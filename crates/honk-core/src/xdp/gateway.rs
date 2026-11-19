pub(crate) mod hold;
pub(crate) mod policy;
pub(crate) mod zones;

pub(crate) use hold::HoldCollector;
pub(crate) use policy::GatewayPolicy;
pub(crate) use zones::ZoneAdmission;

use crate::control::routing_matcher::RoutingPushPlan;
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::{ConntrackKfuncs, GatewayLoad, GatewayMaps, GeneralCapture, OwnedXdpLink, Programs};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use std::{io, net::Ipv4Addr, sync::Arc};

fn reserve_objects<'a>(
    budget: &Arc<MemoryBudget>,
    fds: impl IntoIterator<Item = std::os::fd::BorrowedFd<'a>>,
) -> io::Result<MemoryReservation> {
    let bytes = fds.into_iter().try_fold(0usize, |total, fd| {
        total
            .checked_add(honk_xsk::kernel_memory_bytes(fd)?)
            .ok_or_else(|| io::Error::other("gateway kernel memory overflow"))
    })?;
    budget
        .reserve(bytes)
        .ok_or_else(|| io::Error::other("gateway kernel memory capacity"))
}

pub(crate) struct GatewayReload {
    pub(crate) capture: GeneralCapture,
    pub(crate) queues: u32,
    pub(crate) ipv4_broadcasts: Vec<Ipv4Addr>,
}

struct Member {
    ifindex: u32,
    programs: Arc<Programs>,
    reload: GatewayReload,
}

struct Previous {
    policy: GatewayPolicy,
    programs: Vec<Arc<Programs>>,
    memory: Vec<MemoryReservation>,
}

struct PublisherInner {
    policy: GatewayPolicy,
    members: Vec<Member>,
    memory: Vec<MemoryReservation>,
    previous: Option<Previous>,
}

enum LinkCustody<L> {
    Open(Vec<L>),
    Withdrawing,
    Closed(Result<(), io::ErrorKind>),
}

struct PublisherState<P, L> {
    inner: Mutex<P>,
    // While open, link indices match the members in `inner`.
    links: Mutex<LinkCustody<L>>,
}

impl<P, L> PublisherState<P, L> {
    fn open_links(&self) -> io::Result<MappedMutexGuard<'_, Vec<L>>> {
        Self::require_links(self.links.lock())
    }

    fn try_open_links(&self) -> io::Result<MappedMutexGuard<'_, Vec<L>>> {
        Self::require_links(self.links.try_lock().ok_or_else(publisher_busy)?)
    }

    fn require_links(
        links: MutexGuard<'_, LinkCustody<L>>,
    ) -> io::Result<MappedMutexGuard<'_, Vec<L>>> {
        MutexGuard::try_map(links, |state| match state {
            LinkCustody::Open(links) => Some(links),
            _ => None,
        })
        .map_err(|_| lost_capture())
    }

    fn detach_all(&self, detach: impl Fn(L) -> io::Result<()>) -> io::Result<()> {
        let links = {
            let mut custody = self.links.lock();
            match &mut *custody {
                LinkCustody::Open(links) => {
                    let links = std::mem::take(links);
                    *custody = LinkCustody::Withdrawing;
                    links
                }
                LinkCustody::Withdrawing => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "gateway link withdrawal in progress",
                    ));
                }
                LinkCustody::Closed(result) => return (*result).map_err(io::Error::from),
            }
        };
        let mut error = None;
        for link in links.into_iter().rev() {
            if let Err(failure) = detach(link)
                && error.is_none()
            {
                error = Some(failure);
            }
        }
        *self.links.lock() = LinkCustody::Closed(error.as_ref().map_or(Ok(()), |e| Err(e.kind())));
        error.map_or(Ok(()), Err)
    }
}

fn lost_capture() -> io::Error {
    io::Error::other("gateway publisher lost capture authority")
}

fn publisher_busy() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "gateway publisher is busy")
}

pub(crate) struct GatewayPublisher {
    state: PublisherState<PublisherInner, OwnedXdpLink>,
    maps: Arc<GatewayMaps>,
    conntrack: Arc<ConntrackKfuncs>,
    budget: Arc<MemoryBudget>,
    _initial_memory: MemoryReservation,
}

impl GatewayPublisher {
    pub(crate) fn new(
        policy: GatewayPolicy,
        maps: Arc<GatewayMaps>,
        conntrack: Arc<ConntrackKfuncs>,
        budget: Arc<MemoryBudget>,
    ) -> io::Result<Self> {
        let initial_memory = reserve_objects(&budget, policy.fact_fds())?;
        Ok(Self {
            state: PublisherState {
                inner: Mutex::new(PublisherInner {
                    policy,
                    members: Vec::new(),
                    memory: Vec::new(),
                    previous: None,
                }),
                links: Mutex::new(LinkCustody::Open(Vec::new())),
            },
            maps,
            conntrack,
            budget,
            _initial_memory: initial_memory,
        })
    }

    pub(crate) fn set_mode_flags(&self, flags: u32) -> io::Result<()> {
        drop(self.state.open_links()?);
        self.maps.set_mode_flags(flags)
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.state.inner.lock().policy.fingerprint
    }

    pub(crate) fn register(
        &self,
        ifindex: u32,
        link: OwnedXdpLink,
        programs: Arc<Programs>,
        reload: GatewayReload,
    ) -> io::Result<()> {
        // The startup link is already live. Refuse contention before taking custody.
        let mut inner = self.state.inner.try_lock().ok_or_else(publisher_busy)?;
        let mut links = self.state.open_links()?;
        inner.members.push(Member {
            ifindex,
            programs,
            reload,
        });
        links.push(link);
        Ok(())
    }

    pub(crate) fn publish(&self, plan: &RoutingPushPlan) -> io::Result<()> {
        drop(self.state.open_links()?);
        let policy = GatewayPolicy::prepare(plan)?;
        let mut inner = self.state.inner.lock();
        drop(self.state.open_links()?);
        if inner.previous.is_some() {
            return Err(io::Error::other(
                "gateway publication is awaiting commit or rollback",
            ));
        }
        let mut candidates = Vec::with_capacity(inner.members.len());
        for member in &inner.members {
            if member.reload.capture.authority.ifindex != member.ifindex
                || member.reload.queues == 0
                || member.reload.ipv4_broadcasts.len() > 64
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gateway reload identity mismatch",
                ));
            }
            drop(self.state.open_links()?);
            candidates.push(Arc::new(member.programs.reload_general_gateway(
                GatewayLoad {
                    routing: &policy.bytecode.insns,
                    maps: &self.maps,
                    conntrack: &self.conntrack,
                },
            )?));
        }
        drop(self.state.open_links()?);
        let mut memory = Vec::with_capacity(candidates.len() + 1);
        memory.push(reserve_objects(&self.budget, policy.fact_fds())?);
        for candidate in &candidates {
            memory.push(reserve_objects(
                &self.budget,
                candidate.object_fds().into_iter().skip(2),
            )?);
        }
        for (index, candidate) in candidates.iter().enumerate() {
            let member = &inner.members[index];
            let replaced = self.state.open_links()?[index]
                .replace(member.programs.data_fd(), candidate.data_fd());
            if let Err(error) = replaced {
                let old = self.state.open_links()?[index]
                    .verify(member.programs.data_prog_id())
                    .is_ok();
                let changed = if old {
                    index
                } else if self.state.open_links()?[index]
                    .verify(candidate.data_prog_id())
                    .is_ok()
                {
                    index + 1
                } else {
                    let cleanup = self.detach_all();
                    return Err(io::Error::other(format!(
                        "fatal gateway link identity lost after update: {error}; detach: {cleanup:?}"
                    )));
                };
                for rollback in (0..changed).rev() {
                    let member = &inner.members[rollback];
                    let replaced = self.state.open_links()?[rollback]
                        .replace(candidates[rollback].data_fd(), member.programs.data_fd());
                    if let Err(rollback_error) = replaced {
                        let cleanup = self.detach_all();
                        return Err(io::Error::other(format!(
                            "fatal gateway update rollback failed: {error}; rollback: {rollback_error}; detach: {cleanup:?}"
                        )));
                    }
                }
                return Err(error);
            }
        }
        let _links = self.state.open_links()?;
        for (member, programs) in inner.members.iter_mut().zip(&mut candidates) {
            std::mem::swap(&mut member.programs, programs);
        }
        let previous_policy = std::mem::replace(&mut inner.policy, policy);
        let previous_memory = std::mem::replace(&mut inner.memory, memory);
        inner.previous = Some(Previous {
            policy: previous_policy,
            programs: candidates,
            memory: previous_memory,
        });
        Ok(())
    }

    pub(crate) fn commit(&self) {
        let previous = self.state.inner.lock().previous.take();
        drop(previous);
    }

    pub(crate) fn rollback(&self) -> io::Result<()> {
        drop(self.state.open_links()?);
        let mut inner = self.state.inner.lock();
        drop(self.state.open_links()?);
        let Some(mut previous) = inner.previous.take() else {
            let cleanup = self.detach_all();
            return Err(io::Error::other(format!(
                "fatal gateway rollback has no previous generation; detach: {cleanup:?}"
            )));
        };
        if previous.programs.len() != inner.members.len() {
            let cleanup = self.detach_all();
            return Err(io::Error::other(format!(
                "fatal gateway rollback member mismatch; detach: {cleanup:?}"
            )));
        }
        for index in (0..inner.members.len()).rev() {
            let member = &inner.members[index];
            let replaced = self.state.open_links()?[index].replace(
                member.programs.data_fd(),
                previous.programs[index].data_fd(),
            );
            if let Err(error) = replaced {
                let cleanup = self.detach_all();
                return Err(io::Error::other(format!(
                    "fatal gateway software rollback failed: {error}; detach: {cleanup:?}"
                )));
            }
        }
        let _links = self.state.open_links()?;
        for (member, programs) in inner.members.iter_mut().zip(&mut previous.programs) {
            std::mem::swap(&mut member.programs, programs);
        }
        std::mem::swap(&mut inner.policy, &mut previous.policy);
        std::mem::swap(&mut inner.memory, &mut previous.memory);
        Ok(())
    }

    pub(crate) fn validate_programs<T>(
        &self,
        check: impl FnOnce(&[(u32, u32)]) -> io::Result<T>,
    ) -> io::Result<T> {
        drop(self.state.open_links()?);
        let inner = self.state.inner.lock();
        let programs = inner
            .members
            .iter()
            .enumerate()
            .map(|(index, member)| {
                let id = member.programs.data_prog_id();
                self.state.open_links()?[index].verify(id)?;
                Ok((member.ifindex, id))
            })
            .collect::<io::Result<Vec<_>>>()?;
        drop(self.state.open_links()?);
        let value = check(&programs)?;
        drop(self.state.open_links()?);
        Ok(value)
    }

    pub(super) fn verify_attachments(&self) -> io::Result<()> {
        let inner = self.state.inner.try_lock().ok_or_else(publisher_busy)?;
        drop(self.state.try_open_links()?);
        for (index, member) in inner.members.iter().enumerate() {
            self.state.try_open_links()?[index].verify(member.programs.data_prog_id())?;
        }
        Ok(())
    }

    pub(crate) fn detach_all(&self) -> io::Result<()> {
        self.state.detach_all(OwnedXdpLink::detach)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, os::unix::net::UnixStream, sync::mpsc, thread, time::Duration};

    #[test]
    fn withdrawal_closes_owned_fds_while_policy_is_busy() {
        let (link, mut peer) = UnixStream::pair().unwrap();
        let state = PublisherState {
            inner: Mutex::new(()),
            links: Mutex::new(LinkCustody::Open(vec![link])),
        };
        let (send, recv) = mpsc::channel();
        let policy = state.inner.lock();
        thread::scope(|scope| {
            let state = &state;
            scope.spawn(move || {
                send.send(state.detach_all(|link| {
                    drop(link);
                    Ok(())
                }))
                .unwrap();
            });
            let result = recv.recv_timeout(Duration::from_secs(5));
            drop(policy);
            result
                .expect("withdrawal waited for the policy mutex")
                .unwrap();
        });
        peer.set_nonblocking(true).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert!(state.open_links().is_err());
    }

    #[test]
    fn overlapping_withdrawal_never_reports_success_before_fd_close() {
        let (link, mut peer) = UnixStream::pair().unwrap();
        let state = PublisherState {
            inner: Mutex::new(()),
            links: Mutex::new(LinkCustody::Open(vec![link])),
        };
        let result = state.detach_all(|link| {
            assert_eq!(
                state.detach_all(|_| unreachable!()).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            drop(link);
            Err(io::Error::from(io::ErrorKind::Interrupted))
        });
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(
            state.detach_all(|_| unreachable!()).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }
}
