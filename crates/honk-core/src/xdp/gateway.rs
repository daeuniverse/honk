pub(crate) mod dns;
mod generation;
pub(crate) mod hold;
pub(crate) mod policy;
pub(crate) mod zones;

pub(crate) use hold::HoldCollector;
pub(crate) use policy::GatewayPolicy;
pub(crate) use zones::ZoneAdmission;

use crate::control::routing_matcher::RoutingPushPlan;
use crate::control::{ControlPlane, ShutdownIntent};
use crate::dns::projection::RoutingProjection;
use crate::stats::xdp::{Diagnostics, DnsProjectionState};
use dns::GatewayDnsBank;
use generation::Arbitration;
use honk_datapath::ScopeId;
use honk_ebpf_common::xdp_gateway::GatewayReason;
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::{ConntrackKfuncs, GatewayLoad, GatewayMaps, GeneralCapture, OwnedXdpLink, Programs};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use std::{
    io,
    net::Ipv4Addr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

const NOTRACK_FALLBACK: DnsProjectionState = DnsProjectionState::Fallback("notrack");

pub(super) fn reserve_objects<'a>(
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
        .ok_or_else(|| io::Error::new(io::ErrorKind::OutOfMemory, "gateway kernel memory capacity"))
}

pub(crate) struct GatewayReload {
    pub(crate) capture: GeneralCapture,
    pub(crate) queues: u32,
    pub(crate) ipv4_broadcasts: Vec<Ipv4Addr>,
}

struct Member {
    ifindex: u32,
    programs: Programs,
    reload: GatewayReload,
}

struct Generation {
    policy: GatewayPolicy,
    bank: Option<Arc<GatewayDnsBank>>,
    arbitration: Option<Arc<Arbitration>>,
    status: DnsProjectionState,
    memory: Vec<MemoryReservation>,
}

enum PreparedGeneration {
    KeepStatic(DnsProjectionState),
    Replace(Generation, Vec<Programs>),
}

enum PrepareError {
    Policy(io::Error),
    Candidate(io::Error),
    Authority(io::Error),
}

impl PrepareError {
    fn into_error(self) -> io::Error {
        match self {
            Self::Policy(error) | Self::Candidate(error) | Self::Authority(error) => error,
        }
    }

    fn shadow_failure(self) -> Result<(&'static str, io::Error), io::Error> {
        match self {
            Self::Policy(error) | Self::Candidate(error)
                if error.kind() == io::ErrorKind::OutOfMemory =>
            {
                Ok(("memory_budget", error))
            }
            Self::Policy(error) | Self::Candidate(error)
                if matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) =>
            {
                Ok(("candidate_fds", error))
            }
            Self::Policy(error) => Ok(("policy_prepare", error)),
            Self::Candidate(error) => match honk_xsk::gateway_dns_load_failure(&error) {
                Some(reason) => Ok((reason, error)),
                None => Err(error),
            },
            Self::Authority(error) => Err(error),
        }
    }
}

struct Previous {
    // Kernel programs must release their map references before the charge is refunded.
    programs: Vec<Programs>,
    generation: Generation,
    suspended: Option<(Arc<GatewayDnsBank>, u64)>,
}

struct PublisherInner {
    members: Vec<Member>,
    current: Generation,
    previous: Option<Previous>,
    last_issued: u64,
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

pub(super) struct GatewayShadow {
    projection: Weak<RoutingProjection>,
    diagnostics: Arc<Diagnostics>,
    admission: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    shutdown: Arc<ShutdownIntent>,
    stopped: AtomicBool,
    notrack: AtomicBool,
    realms: Box<[(ScopeId, u32)]>,
    base_status: DnsProjectionState,
    _bindings_memory: Option<MemoryReservation>,
}

impl GatewayShadow {
    pub(super) fn new(
        realms: impl Iterator<Item = (ScopeId, u32)> + Clone,
        plane: &ControlPlane,
        diagnostics: Arc<Diagnostics>,
        admission: Arc<AtomicBool>,
        budget: &Arc<MemoryBudget>,
        notrack_seen: bool,
    ) -> Self {
        let count = realms.clone().count();
        let notrack = count != 0 && notrack_seen;
        let (realms, base_status, memory) = if count == 0 {
            (Box::default(), DnsProjectionState::Disabled, None)
        } else if notrack {
            (Box::default(), NOTRACK_FALLBACK, None)
        } else if let Some(charge) = budget.reserve(count * size_of::<(ScopeId, u32)>()) {
            let mut bound = Vec::with_capacity(count);
            bound.extend(realms);
            (
                bound.into_boxed_slice(),
                DnsProjectionState::NoDomainRules,
                Some(charge),
            )
        } else {
            (
                Box::default(),
                DnsProjectionState::Fallback("memory_budget"),
                None,
            )
        };
        diagnostics.dns_state(base_status);
        Self {
            projection: Arc::downgrade(&plane.packet_routing_projection()),
            diagnostics,
            admission,
            healthy: plane.datapath_health_handle(),
            shutdown: plane.shutdown_intent(),
            stopped: AtomicBool::new(false),
            notrack: AtomicBool::new(notrack),
            realms,
            base_status,
            _bindings_memory: memory,
        }
    }

    fn notrack_latched(&self) -> bool {
        self.notrack.load(Ordering::Acquire)
    }

    fn report_status(&self, status: DnsProjectionState) {
        self.diagnostics.dns_state(if self.notrack_latched() {
            NOTRACK_FALLBACK
        } else {
            status
        });
    }

    fn latch_notrack(&self) {
        if self.base_status == DnsProjectionState::Disabled
            || self.stopped.load(Ordering::Acquire)
            || self.notrack_latched()
        {
            return;
        }
        self.notrack.store(true, Ordering::Release);
        self.suspend();
        self.diagnostics.dns_state(NOTRACK_FALLBACK);
    }

    fn allowed(&self) -> bool {
        !self.stopped.load(Ordering::Acquire)
            && !self.notrack_latched()
            && self.admission.load(Ordering::Acquire)
            && self.healthy.load(Ordering::Acquire)
    }

    fn suspend(&self) -> Option<(Arc<GatewayDnsBank>, u64)> {
        self.projection.upgrade()?.close_gateway_dns()
    }

    fn lock_activation(&self) -> Option<MutexGuard<'_, ()>> {
        let start = self.shutdown.lock_capture_start().ok()?;
        self.allowed().then_some(start)
    }

    fn activate(&self, bank: Arc<GatewayDnsBank>, generation: u64) {
        let Some(_start) = self.lock_activation() else {
            return;
        };
        if let Some(projection) = self.projection.upgrade()
            && projection.activate_gateway_dns(Some(bank), generation, || self.allowed())
        {
            self.report_status(DnsProjectionState::Active);
        }
    }

    fn resume(&self, suspended: Option<(Arc<GatewayDnsBank>, u64)>) {
        if let Some((bank, generation)) = suspended {
            self.activate(bank, generation);
        }
    }
}

pub(crate) struct GatewayPublisher {
    state: PublisherState<PublisherInner, OwnedXdpLink>,
    maps: Arc<GatewayMaps>,
    conntrack: Arc<ConntrackKfuncs>,
    budget: Arc<MemoryBudget>,
    active_plan: Arc<parking_lot::RwLock<Arc<RoutingPushPlan>>>,
    failure: std::sync::OnceLock<Arc<io::Error>>,
    // Link custody orders the notrack latch against DNS activation and status publication.
    shadow: GatewayShadow,
}

impl GatewayPublisher {
    pub(super) fn new(
        initial: (GatewayPolicy, MemoryReservation),
        maps: Arc<GatewayMaps>,
        conntrack: Arc<ConntrackKfuncs>,
        budget: Arc<MemoryBudget>,
        shadow: GatewayShadow,
        active_plan: Arc<parking_lot::RwLock<Arc<RoutingPushPlan>>>,
    ) -> Self {
        let (policy, initial_memory) = initial;
        Self {
            state: PublisherState {
                inner: Mutex::new(PublisherInner {
                    members: Vec::new(),
                    current: Generation {
                        policy,
                        bank: None,
                        arbitration: None,
                        status: shadow.base_status,
                        memory: vec![initial_memory],
                    },
                    previous: None,
                    last_issued: 0,
                }),
                links: Mutex::new(LinkCustody::Open(Vec::new())),
            },
            maps,
            conntrack,
            budget,
            shadow,
            active_plan,
            failure: Default::default(),
        }
    }

    pub(crate) fn set_mode_flags(&self, flags: u32) -> io::Result<()> {
        let _links = self.state.open_links()?;
        self.maps.set_mode_flags(flags)
    }

    #[cfg(all(test, feature = "ebpf"))]
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.state.inner.lock().current.policy.bytecode.fingerprint
    }

    pub(crate) fn register(
        &self,
        ifindex: u32,
        link: OwnedXdpLink,
        programs: (Programs, MemoryReservation),
        reload: GatewayReload,
    ) -> io::Result<()> {
        // The startup link is already live. Refuse contention before taking custody.
        let mut inner = self.state.inner.try_lock().ok_or_else(publisher_busy)?;
        let mut links = self.state.open_links()?;
        let (programs, charge) = programs;
        inner.current.memory.push(charge);
        inner.members.push(Member {
            ifindex,
            programs,
            reload,
        });
        links.push(link);
        Ok(())
    }

    pub(crate) fn prepare_start(&self, plan: &RoutingPushPlan) -> io::Result<()> {
        self.publish_inner(plan, true)
    }

    pub(crate) fn activate_dns(&self, fingerprint: [u8; 32], generation: u64) {
        let inner = self.state.inner.lock();
        let Ok(_links) = self.state.open_links() else {
            return;
        };
        if self.failure.get().is_none()
            && inner.previous.is_none()
            && let Some(bank) = &inner.current.bank
            && bank.fingerprint() == fingerprint
        {
            self.shadow.activate(Arc::clone(bank), generation);
        }
    }

    pub(crate) fn stage_dns_reload(&self) {
        let inner = self.state.inner.lock();
        if let Ok(_links) = self.state.open_links() {
            self.shadow.report_status(inner.current.status);
        }
    }

    pub(crate) fn degrade_dns(&self) {
        let _custody = self.state.links.lock();
        if !self.shadow.realms.is_empty()
            && !self.shadow.stopped.load(Ordering::Acquire)
            && !self.shadow.notrack_latched()
        {
            self.shadow.suspend();
            self.shadow
                .diagnostics
                .dns_state(DnsProjectionState::Fallback("committed_degraded"));
        }
    }

    pub(super) fn latch_notrack(&self) {
        let _custody = self.state.links.lock();
        self.shadow.latch_notrack();
    }

    pub(super) fn maintain_holds(
        &self,
        collector: &mut HoldCollector,
        now_ns: u64,
        retains: &mut dyn FnMut(u32, std::net::IpAddr) -> bool,
    ) -> io::Result<()> {
        let Some(mut inner) = self.state.inner.try_lock() else {
            return Ok(());
        };
        if let Some(error) = self.capture_error() {
            return Err(error);
        }
        if let Some(arb) = &inner.current.arbitration {
            self.shadow.diagnostics.sample_dns_decisions(&self.maps);
            self.check_hold_custody()?;
            collector
                .sweep(&self.maps, now_ns, Some(&arb.kernel), retains)
                .map_err(|error| self.fail_capture(error))?;
            if let Some(bank) = &inner.current.bank
                && !self.shadow.notrack_latched()
            {
                self.shadow.diagnostics.sample_dns(
                    bank,
                    self.maps.reason_count(GatewayReason::WouldPassDns).ok(),
                );
            } else if inner.previous.is_none()
                && (inner.current.bank.is_some() || arb.kernel.pending() == 0)
            {
                self.compact_static(&mut inner)?;
            }
        } else {
            collector.sweep(&self.maps, now_ns, None, retains)?;
        }
        Ok(())
    }

    pub(crate) fn stop_dns(&self) {
        let _custody = self.state.links.lock();
        if !self.shadow.stopped.swap(true, Ordering::AcqRel) {
            self.shadow.suspend();
            self.shadow
                .diagnostics
                .dns_state(DnsProjectionState::Closed);
        }
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

    pub(super) fn verify_link_fds(&self) -> io::Result<()> {
        drop(self.state.open_links()?);
        let inner = self.state.inner.lock();
        for (index, member) in inner.members.iter().enumerate() {
            self.state.open_links()?[index].verify_fd(member.programs.data_prog_id())?;
        }
        // Withdrawal can start between the FD reads without the policy lock.
        let _links = self.state.open_links()?;
        Ok(())
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
        self.stop_dns();
        self.state.detach_all(OwnedXdpLink::detach)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, os::unix::net::UnixStream, sync::mpsc, thread, time::Duration};

    #[test]
    fn optional_candidate_fd_pressure_keeps_authority_error_fatal() {
        for errno in [libc::EMFILE, libc::ENFILE] {
            for stage in [PrepareError::Policy, PrepareError::Candidate] {
                let (reason, error) = stage(io::Error::from_raw_os_error(errno))
                    .shadow_failure()
                    .unwrap();
                assert_eq!(reason, "candidate_fds");
                assert_eq!(error.raw_os_error(), Some(errno));
            }
            let error = PrepareError::Authority(io::Error::from_raw_os_error(errno))
                .shadow_failure()
                .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
        }
    }

    #[test]
    fn notrack_latch_refuses_late_dns_activation() {
        let budget = MemoryBudget::new(4096);
        let shadow = GatewayShadow {
            projection: Weak::new(),
            diagnostics: Diagnostics::new(&budget, 0, std::iter::empty()).unwrap(),
            admission: Arc::new(AtomicBool::new(true)),
            healthy: Arc::new(AtomicBool::new(true)),
            shutdown: Arc::new(ShutdownIntent::default()),
            stopped: AtomicBool::new(false),
            notrack: AtomicBool::new(false),
            realms: Box::new([(ScopeId::allocate().unwrap(), 1)]),
            base_status: DnsProjectionState::NoDomainRules,
            _bindings_memory: None,
        };
        assert!(shadow.lock_activation().is_some());
        shadow.latch_notrack();
        assert!(shadow.lock_activation().is_none());
        shadow.report_status(DnsProjectionState::Staged);
        let status = shadow.diagnostics.json(false);
        assert_eq!(status["dns_projection_state"], "degraded_fallback");
        assert_eq!(status["dns_projection_reason"], "notrack");
    }

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
