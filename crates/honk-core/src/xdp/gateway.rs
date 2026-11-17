pub(crate) mod hold;
pub(crate) mod policy;
pub(crate) mod zones;

pub(crate) use hold::HoldCollector;
pub(crate) use policy::GatewayPolicy;
pub(crate) use zones::ZoneAdmission;

use crate::control::routing_matcher::RoutingPushPlan;
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::{ConntrackKfuncs, GatewayLoad, GatewayMaps, GeneralCapture, OwnedXdpLink, Programs};
use parking_lot::Mutex;
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
    link: OwnedXdpLink,
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
    fatal: bool,
    memory: Vec<MemoryReservation>,
    previous: Option<Previous>,
}

pub(crate) struct GatewayPublisher {
    inner: Mutex<PublisherInner>,
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
            inner: Mutex::new(PublisherInner {
                policy,
                members: Vec::new(),
                fatal: false,
                memory: Vec::new(),
                previous: None,
            }),
            maps,
            conntrack,
            budget,
            _initial_memory: initial_memory,
        })
    }

    pub(crate) fn set_mode_flags(&self, flags: u32) -> io::Result<()> {
        self.maps.set_mode_flags(flags)
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.inner.lock().policy.fingerprint
    }

    pub(crate) fn register(
        &self,
        ifindex: u32,
        link: OwnedXdpLink,
        programs: Arc<Programs>,
        reload: GatewayReload,
    ) {
        self.inner.lock().members.push(Member {
            ifindex,
            link,
            programs,
            reload,
        });
    }

    pub(crate) fn publish(&self, plan: &RoutingPushPlan) -> io::Result<()> {
        let policy = GatewayPolicy::prepare(plan)?;
        let mut inner = self.inner.lock();
        if inner.fatal {
            return Err(io::Error::other("gateway publisher lost capture authority"));
        }
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
            candidates.push(Arc::new(member.programs.reload_general_gateway(
                GatewayLoad {
                    routing: &policy.bytecode.insns,
                    maps: &self.maps,
                    conntrack: &self.conntrack,
                },
            )?));
        }
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
            if let Err(error) = member
                .link
                .replace(member.programs.data_fd(), candidate.data_fd())
            {
                let changed = if member.link.verify(member.programs.data_prog_id()).is_ok() {
                    index
                } else if member.link.verify(candidate.data_prog_id()).is_ok() {
                    index + 1
                } else {
                    inner.fatal = true;
                    let cleanup = detach(&mut inner.members);
                    return Err(io::Error::other(format!(
                        "fatal gateway link identity lost after update: {error}; detach: {cleanup:?}"
                    )));
                };
                for rollback in (0..changed).rev() {
                    let member = &inner.members[rollback];
                    if let Err(rollback_error) = member
                        .link
                        .replace(candidates[rollback].data_fd(), member.programs.data_fd())
                    {
                        inner.fatal = true;
                        let cleanup = detach(&mut inner.members);
                        return Err(io::Error::other(format!(
                            "fatal gateway update rollback failed: {error}; rollback: {rollback_error}; detach: {cleanup:?}"
                        )));
                    }
                }
                return Err(error);
            }
        }
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
        let previous = self.inner.lock().previous.take();
        drop(previous);
    }

    pub(crate) fn rollback(&self) -> io::Result<()> {
        let mut inner = self.inner.lock();
        if inner.fatal {
            return Err(io::Error::other("gateway publisher lost capture authority"));
        }
        let Some(mut previous) = inner.previous.take() else {
            inner.fatal = true;
            let cleanup = detach(&mut inner.members);
            return Err(io::Error::other(format!(
                "fatal gateway rollback has no previous generation; detach: {cleanup:?}"
            )));
        };
        if previous.programs.len() != inner.members.len() {
            inner.fatal = true;
            let cleanup = detach(&mut inner.members);
            return Err(io::Error::other(format!(
                "fatal gateway rollback member mismatch; detach: {cleanup:?}"
            )));
        }
        for index in (0..inner.members.len()).rev() {
            let member = &inner.members[index];
            if let Err(error) = member.link.replace(
                member.programs.data_fd(),
                previous.programs[index].data_fd(),
            ) {
                inner.fatal = true;
                let cleanup = detach(&mut inner.members);
                return Err(io::Error::other(format!(
                    "fatal gateway software rollback failed: {error}; detach: {cleanup:?}"
                )));
            }
        }
        for (member, programs) in inner.members.iter_mut().zip(&mut previous.programs) {
            std::mem::swap(&mut member.programs, programs);
        }
        inner.policy = previous.policy;
        inner.memory = previous.memory;
        Ok(())
    }

    pub(crate) fn validate_programs<T>(
        &self,
        check: impl FnOnce(&[(u32, u32)]) -> io::Result<T>,
    ) -> io::Result<T> {
        let inner = self.inner.lock();
        if inner.fatal {
            return Err(io::Error::other("gateway publisher lost capture authority"));
        }
        let programs = inner
            .members
            .iter()
            .map(|member| {
                let id = member.programs.data_prog_id();
                member.link.verify(id)?;
                Ok((member.ifindex, id))
            })
            .collect::<io::Result<Vec<_>>>()?;
        check(&programs)
    }

    pub(crate) fn detach_all(&self) -> io::Result<()> {
        detach(&mut self.inner.lock().members)
    }
}

fn detach(members: &mut Vec<Member>) -> io::Result<()> {
    let mut error = None;
    while let Some(member) = members.pop() {
        if let Err(failure) = member.link.detach()
            && error.is_none()
        {
            error = Some(failure);
        }
    }
    error.map_or(Ok(()), Err)
}
