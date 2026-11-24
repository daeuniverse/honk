pub(crate) mod dns;
mod generation;
pub(crate) mod hold;
pub(crate) mod policy;
pub(crate) mod zones;

pub(crate) use hold::HoldCollector;
pub(crate) use policy::GatewayPolicy;
pub(crate) use zones::ZoneAdmission;

#[cfg(feature = "ebpf")]
use super::host_identity::HostIdentity;
use crate::control::routing_matcher::RoutingPushPlan;
use crate::control::{ControlPlane, ShutdownIntent};
use crate::dns::projection::RoutingProjection;
use crate::stats::xdp::{Diagnostics, DnsProjectionState};
use dns::GatewayDnsBank;
use generation::Arbitration;
use honk_datapath::ScopeId;
#[cfg(feature = "ebpf")]
use honk_ebpf_common::xdp_gateway::{GATEWAY_REALM_CAPACITY, HostFlowMeta};
use honk_ebpf_common::xdp_gateway::{GatewayKey, GatewayReason};
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::{
    AuxDevicePair, AuxGatewayProgram, AuxReaderGrace, AuxTcxLink, ConntrackKfuncs, GatewayLoad,
    GatewayMaps, GeneralCapture, OwnedXdpLink, Programs, SkbConntrackKfuncs,
};
#[cfg(feature = "ebpf")]
use honk_xsk::{HostConntrack, HostGatewayLoad, topology::AuxLinkInfo};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use std::{
    io,
    net::Ipv4Addr,
    os::fd::AsFd,
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

struct AuxProgram {
    program: AuxGatewayProgram,
    _memory: MemoryReservation,
}

#[derive(Clone, Copy)]
enum AuxDirection {
    LanIngress,
    #[cfg(feature = "ebpf")]
    HostEgress {
        stamp: u64,
        binding: u64,
        is_l2: bool,
    },
}

impl AuxDirection {
    fn matches_dns_scope(self, scope: ScopeId, realm: u32, realms: &[(ScopeId, u32)]) -> bool {
        match self {
            Self::LanIngress => !realms
                .iter()
                .any(|&(s, r)| (s == scope || r == realm) && (s, r) != (scope, realm)),
            #[cfg(feature = "ebpf")]
            Self::HostEgress { .. } => {
                realm != GATEWAY_REALM_CAPACITY
                    && !realms.iter().any(|&(s, r)| s == scope || r == realm)
            }
        }
    }
}

struct AuxMember {
    realm: u32,
    scope: ScopeId,
    direction: AuxDirection,
    pair: Arc<AuxDevicePair>,
    broadcasts: [Ipv4Addr; 64],
    broadcast_count: usize,
    link: Option<(AuxTcxLink, MemoryReservation)>,
    program: Option<AuxProgram>,
    key_bound: bool,
    dns_active: bool,
    #[cfg(feature = "ebpf")]
    host_bound: bool,
    #[cfg(feature = "ebpf")]
    retiring: bool,
}

impl AuxMember {
    fn new(
        realm: u32,
        scope: ScopeId,
        direction: AuxDirection,
        pair: Arc<AuxDevicePair>,
        addresses: &[Ipv4Addr],
    ) -> io::Result<Self> {
        let mut broadcasts = [Ipv4Addr::UNSPECIFIED; 64];
        broadcasts
            .get_mut(..addresses.len())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "auxiliary broadcast capacity exceeded",
                )
            })?
            .copy_from_slice(addresses);
        Ok(Self {
            realm,
            scope,
            direction,
            pair,
            broadcasts,
            broadcast_count: addresses.len(),
            link: None,
            program: None,
            key_bound: false,
            dns_active: false,
            #[cfg(feature = "ebpf")]
            host_bound: false,
            #[cfg(feature = "ebpf")]
            retiring: false,
        })
    }

    fn set_dns_binding(&mut self, projection: &RoutingProjection, active: bool) -> io::Result<()> {
        match self.direction {
            AuxDirection::LanIngress => projection.set_aux_binding(self.scope, active)?,
            #[cfg(feature = "ebpf")]
            AuxDirection::HostEgress { stamp, .. } => {
                projection.set_host_binding(self.scope, stamp, active)?;
            }
        }
        self.dns_active = active;
        Ok(())
    }
}

struct Auxiliary {
    conntrack: Option<SkbConntrackKfuncs>,
    grace: AuxReaderGrace,
    members: Vec<AuxMember>,
    _objects: MemoryReservation,
    _allocation: MemoryReservation,
}

impl Auxiliary {
    fn new(
        budget: &Arc<MemoryBudget>,
        lan_count: usize,
        host_count: usize,
    ) -> io::Result<Box<Self>> {
        // Retired bindings occupy their slots until the owner has joined its work.
        let capacity = lan_count + host_count;
        let allocation = budget
            .reserve(size_of::<Self>() + capacity * size_of::<AuxMember>())
            .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
        let conntrack = (lan_count != 0)
            .then(|| SkbConntrackKfuncs::read_accounted(budget))
            .transpose()?;
        let grace = AuxReaderGrace::new()?;
        let objects = reserve_objects(budget, grace.object_fds())?;
        Ok(Box::new(Self {
            conntrack,
            grace,
            members: Vec::with_capacity(capacity),
            _objects: objects,
            _allocation: allocation,
        }))
    }
}

#[cfg(feature = "ebpf")]
pub(super) struct HostResources {
    identity: HostIdentity,
    bypass_mark: u32,
    conntrack: HostConntrack,
    arbitration: Arc<Arbitration>,
}

#[cfg(feature = "ebpf")]
impl HostResources {
    pub(super) fn prepare(
        identity: HostIdentity,
        bypass_mark: u32,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Self> {
        if bypass_mark == 0 || bypass_mark & 0xc800_0000 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Host gateway bypass mark",
            ));
        }
        Ok(Self {
            identity,
            bypass_mark,
            conntrack: HostConntrack::discover_accounted(budget)?,
            arbitration: Arbitration::new(budget, 0)?,
        })
    }

    pub(super) fn arbitration(&self) -> &honk_xsk::GatewayArbitration {
        &self.arbitration.kernel
    }
}

#[cfg(feature = "ebpf")]
#[derive(Clone)]
pub(crate) struct HostProcessLookup {
    maps: Arc<GatewayMaps>,
    arbitration: Arc<Arbitration>,
}

#[cfg(feature = "ebpf")]
impl HostProcessLookup {
    pub(crate) fn lookup(
        &self,
        key: &GatewayKey,
        binding: u64,
    ) -> io::Result<Option<HostFlowMeta>> {
        self.maps
            .lookup_host_meta(&self.arbitration.kernel, key, binding)
    }
}

struct Candidates {
    physical: Vec<Programs>,
    auxiliary: Vec<(u32, AuxProgram)>,
    _auxiliary_memory: Option<MemoryReservation>,
}

struct Generation {
    policy: GatewayPolicy,
    bank: Option<Arc<GatewayDnsBank>>,
    arbitration: Option<Arc<Arbitration>>,
    status: DnsProjectionState,
    memory: Vec<MemoryReservation>,
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
    programs: Candidates,
    generation: Generation,
    suspended: Option<(Arc<GatewayDnsBank>, u64)>,
}

struct PublisherInner {
    members: Vec<Member>,
    auxiliary: Option<Box<Auxiliary>>,
    final_publication: Option<([u8; 32], u64)>,
    flags_fenced: bool,
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
    // Link indices match `inner.members`. Drop custody before refunding program charges.
    links: Mutex<LinkCustody<L>>,
    inner: Mutex<P>,
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

    fn capture_ready(&self) -> bool {
        !self.stopped.load(Ordering::Acquire)
            && !self.shutdown.requested()
            && self.admission.load(Ordering::Acquire)
            && self.healthy.load(Ordering::Acquire)
    }

    fn allowed(&self) -> bool {
        self.capture_ready() && !self.notrack_latched()
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

    fn resume(&self, inner: &PublisherInner, suspended: Option<(Arc<GatewayDnsBank>, u64)>) {
        if !inner.flags_fenced
            && let Some((bank, generation)) = suspended
            && inner.final_publication == Some((bank.fingerprint(), generation))
        {
            self.activate(bank, generation);
        }
    }
}

pub(crate) struct GatewayPublisher {
    state: PublisherState<PublisherInner, OwnedXdpLink>,
    maps: Arc<GatewayMaps>,
    conntrack: Option<Arc<ConntrackKfuncs>>,
    #[cfg(feature = "ebpf")]
    host: Option<HostResources>,
    budget: Arc<MemoryBudget>,
    active_plan: Arc<parking_lot::RwLock<Arc<RoutingPushPlan>>>,
    failure: std::sync::OnceLock<Arc<io::Error>>,
    #[cfg(all(test, feature = "ebpf"))]
    pub(super) replace_tcx_before_final: AtomicBool,
    // Link custody orders the notrack latch against DNS activation and status publication.
    shadow: GatewayShadow,
}

impl GatewayPublisher {
    pub(super) fn new(
        initial: (GatewayPolicy, MemoryReservation),
        maps: Arc<GatewayMaps>,
        conntrack: Option<Arc<ConntrackKfuncs>>,
        budget: Arc<MemoryBudget>,
        shadow: GatewayShadow,
        active_plan: Arc<parking_lot::RwLock<Arc<RoutingPushPlan>>>,
    ) -> Self {
        let (policy, initial_memory) = initial;
        Self {
            state: PublisherState {
                inner: Mutex::new(PublisherInner {
                    members: Vec::new(),
                    auxiliary: None,
                    final_publication: None,
                    flags_fenced: false,
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
            #[cfg(feature = "ebpf")]
            host: None,
            budget,
            shadow,
            active_plan,
            failure: Default::default(),
            #[cfg(all(test, feature = "ebpf"))]
            replace_tcx_before_final: AtomicBool::new(false),
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

    #[cfg(all(test, feature = "ebpf"))]
    pub(super) fn auxiliary_program(&self, outer: u32) -> io::Result<Option<u32>> {
        let inner = self.state.inner.lock();
        let Some(member) = inner
            .auxiliary
            .as_ref()
            .and_then(|aux| aux.members.iter().find(|m| m.pair.outer_ifindex() == outer))
        else {
            return Ok(None);
        };
        let Some((link, _)) = &member.link else {
            return Ok(None);
        };
        let id = member.program.as_ref().unwrap().program.id();
        link.verify(id)?;
        Ok(Some(id))
    }

    #[cfg(all(test, feature = "ebpf"))]
    pub(super) fn check_unhealthy_auxiliary_retry(&self) -> io::Result<()> {
        let (realm, scope, direction, pair) = {
            let inner = self.state.inner.lock();
            let member = inner
                .auxiliary
                .as_ref()
                .and_then(|aux| aux.members.first())
                .ok_or_else(lost_capture)?;
            (
                member.realm,
                member.scope,
                member.direction,
                Arc::clone(&member.pair),
            )
        };
        let outer = pair.outer_ifindex();
        let was_healthy = {
            let _start = self.shadow.shutdown.lock_capture_start()?;
            self.shadow.healthy.swap(false, Ordering::AcqRel)
        };
        // A legitimate published member would otherwise report AlreadyExists. Busy proves
        // cancellation was observed before the membership check, program load or TCX attach.
        let attempt = self.bind_member(realm, scope, direction, outer, pair, &[]);
        {
            let _start = self.shadow.shutdown.lock_capture_start()?;
            self.shadow.healthy.store(was_healthy, Ordering::Release);
        }
        assert_eq!(attempt.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        Ok(())
    }

    #[cfg(all(test, feature = "ebpf"))]
    pub(super) fn unbound_quota_programs(
        &self,
        ifindex: u32,
        attached_id: u32,
    ) -> anyhow::Result<(Programs, MemoryReservation)> {
        use anyhow::{Context, ensure};

        let inner = self.state.inner.lock();
        ensure!(
            inner.previous.is_none(),
            "gateway generation is uncommitted"
        );
        let (index, member) = inner
            .members
            .iter()
            .enumerate()
            .find(|(_, member)| member.ifindex == ifindex)
            .context("gateway quota member")?;
        let reload = &member.reload;
        ensure!(
            member.programs.data_prog_id() == attached_id
                && reload.capture.authority.ifindex == ifindex
                && reload.capture.vlan_metadata,
            "expected the attached VLAN-metadata LAN program"
        );
        self.state.open_links()?[index].verify(attached_id)?;
        let generation = &inner.current;
        let bank = generation
            .bank
            .as_ref()
            .context("committed gateway DNS bank")?;
        let arb = generation
            .arbitration
            .as_ref()
            .context("committed gateway arbitration")?;
        // TEST_RUN rejects device-bound programs. Keep the real capture authority,
        // policy instructions (including fact-map FDs), and gateway decision maps.
        let mut capture = reload.capture.clone();
        capture.vlan_metadata = false;
        let programs = Programs::load_general_gateway(
            &capture,
            reload.queues,
            &reload.ipv4_broadcasts,
            GatewayLoad {
                routing: &generation.policy.bytecode.insns,
                maps: &self.maps,
                conntrack: self.conntrack.as_deref(),
                dns: Some(bank.maps()),
                arbitration: Some(&arb.kernel),
            },
        )?;
        let charge = reserve_objects(&self.budget, programs.object_fds())?;
        self.state.open_links()?[index].verify(attached_id)?;
        Ok((programs, charge))
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

    pub(super) fn prepare_auxiliary(&mut self, lan_count: usize) -> io::Result<()> {
        let inner = self.state.inner.get_mut();
        if inner.auxiliary.is_some()
            || !(1..=honk_config::datapath::MAX_L3_LANS).contains(&lan_count)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid auxiliary preparation",
            ));
        }
        inner.auxiliary = Some(Auxiliary::new(
            &self.budget,
            lan_count,
            self.maps.host_realms().len(),
        )?);
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn prepare_host(&mut self, host: HostResources) -> io::Result<()> {
        let inner = self.state.inner.get_mut();
        let count = self.maps.host_realms().len();
        if count == 0
            || self.host.is_some()
            || inner.current.policy.host_bytecode.is_none()
            || inner.current.arbitration.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Host gateway preparation",
            ));
        }
        if inner.auxiliary.is_none() {
            inner.auxiliary = Some(Auxiliary::new(&self.budget, 0, count)?);
        }
        self.host = Some(host);
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn maps(&self) -> &GatewayMaps {
        &self.maps
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn host_conntrack(&self) -> io::Result<&HostConntrack> {
        self.host
            .as_ref()
            .map(|host| &host.conntrack)
            .ok_or_else(lost_capture)
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn synchronize_host_input(&self) -> io::Result<()> {
        self.host
            .as_ref()
            .ok_or_else(lost_capture)?
            .arbitration()
            .synchronize_readers()
    }

    #[cfg(feature = "ebpf")]
    pub(crate) fn host_process_lookup(&self) -> io::Result<HostProcessLookup> {
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| io::Error::other("Host gateway was not prepared"))?;
        Ok(HostProcessLookup {
            maps: Arc::clone(&self.maps),
            arbitration: Arc::clone(&host.arbitration),
        })
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn host_pending_drain(&self, realm: u32, binding: u64) -> io::Result<Option<u64>> {
        self.maps.host_pending_drain(realm, binding)
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn host_input_drained(
        &self,
        realm: u32,
        binding: u64,
        cutoff: u64,
    ) -> io::Result<()> {
        self.maps.host_input_drained(realm, binding, cutoff)
    }

    pub(crate) fn pause_auxiliary(&self) {
        let mut inner = self.state.inner.lock();
        let _custody = self.state.links.lock();
        inner.flags_fenced = true;
        self.shadow.suspend();
    }

    pub(crate) fn restore_auxiliary(&self) -> io::Result<()> {
        let mut inner = self.state.inner.lock();
        if let Some(error) = self.capture_error() {
            return Err(error);
        }
        inner.flags_fenced = false;
        if let Some((fingerprint, generation)) = inner.final_publication {
            self.activate_final(&mut inner, fingerprint, generation, false)?;
        }
        Ok(())
    }

    fn gateway_load<'a>(&'a self, generation: &'a Generation) -> GatewayLoad<'a> {
        GatewayLoad {
            routing: &generation.policy.bytecode.insns,
            maps: &self.maps,
            conntrack: self.conntrack.as_deref(),
            dns: generation
                .bank
                .as_ref()
                .filter(|_| generation.arbitration.is_some())
                .map(|bank| bank.maps()),
            arbitration: generation.arbitration.as_ref().map(|arb| &arb.kernel),
        }
    }

    fn load_auxiliary(
        &self,
        member: &AuxMember,
        generation: &Generation,
        lan_ct: Option<&SkbConntrackKfuncs>,
    ) -> io::Result<AuxProgram> {
        let load = GatewayLoad {
            conntrack: None,
            ..self.gateway_load(generation)
        };
        let broadcasts = &member.broadcasts[..member.broadcast_count];
        let program = match member.direction {
            AuxDirection::LanIngress => AuxGatewayProgram::load(
                &member.pair,
                member.realm,
                broadcasts,
                load,
                lan_ct.ok_or_else(lost_capture)?,
            )?,
            #[cfg(feature = "ebpf")]
            AuxDirection::HostEgress { binding, is_l2, .. } => {
                let host = self.host.as_ref().ok_or_else(lost_capture)?;
                let bytecode = generation
                    .policy
                    .host_bytecode
                    .as_ref()
                    .ok_or_else(lost_capture)?;
                AuxGatewayProgram::load_host(
                    &member.pair,
                    member.realm,
                    GatewayLoad {
                        routing: &bytecode.insns,
                        dns: generation.bank.as_ref().map(|bank| bank.maps()),
                        arbitration: Some(host.arbitration()),
                        ..load
                    },
                    HostGatewayLoad {
                        binding,
                        is_l2,
                        bypass_mark: host.bypass_mark,
                        honk_pid: host.identity.self_pid(),
                        identity: host.identity.identity_fd(),
                        decision: host.identity.decision_fd(),
                        dns_realm: GATEWAY_REALM_CAPACITY,
                        ct: &host.conntrack,
                    },
                )?
            }
        };
        let memory = reserve_objects(&self.budget, program.object_fds())?;
        Ok(AuxProgram {
            program,
            _memory: memory,
        })
    }

    pub(crate) fn bind_auxiliary(
        &self,
        realm: u32,
        scope: ScopeId,
        outer: u32,
        pair: Arc<AuxDevicePair>,
        ipv4_broadcasts: &[Ipv4Addr],
    ) -> io::Result<()> {
        self.bind_member(
            realm,
            scope,
            AuxDirection::LanIngress,
            outer,
            pair,
            ipv4_broadcasts,
        )
    }

    #[cfg(feature = "ebpf")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind_host(
        &self,
        realm: u32,
        scope: ScopeId,
        stamp: u64,
        binding: u64,
        outer: AuxLinkInfo,
        pair: Arc<AuxDevicePair>,
        broadcasts: &[Ipv4Addr],
    ) -> io::Result<()> {
        let direction = AuxDirection::HostEgress {
            stamp,
            binding,
            is_l2: outer.is_l2,
        };
        self.bind_member(realm, scope, direction, outer.ifindex, pair, broadcasts)
    }

    fn bind_member(
        &self,
        realm: u32,
        scope: ScopeId,
        direction: AuxDirection,
        outer: u32,
        pair: Arc<AuxDevicePair>,
        broadcasts: &[Ipv4Addr],
    ) -> io::Result<()> {
        let plan = self.active_plan.try_read().ok_or_else(publisher_busy)?;
        let mut inner = self.state.inner.try_lock().ok_or_else(publisher_busy)?;
        drop(self.state.try_open_links()?);
        if let Some(error) = self.capture_error() {
            return Err(error);
        }
        if inner.previous.is_some()
            || !self.shadow.capture_ready()
            || inner.flags_fenced
            || inner
                .final_publication
                .is_none_or(|(fingerprint, _)| fingerprint != plan.fingerprint)
            || inner.current.policy.bytecode.fingerprint != plan.fingerprint
        {
            return Err(publisher_busy());
        }
        let host_realm = self.maps.host_realms().contains(&realm);
        if pair.outer_ifindex() != outer
            || scope == ScopeId::HOST
            || host_realm == matches!(direction, AuxDirection::LanIngress)
            || !direction.matches_dns_scope(scope, realm, &self.shadow.realms)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "auxiliary device or DNS realm mismatch",
            ));
        }
        let aux = inner
            .auxiliary
            .as_ref()
            .ok_or_else(|| io::Error::other("auxiliary capture was not prepared"))?;
        if aux.members.len() == aux.members.capacity()
            || aux.members.iter().any(|existing| {
                existing.realm == realm
                    || existing.scope == scope
                    || (existing.key_bound && existing.pair.outer_ifindex() == outer)
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "gateway auxiliary binding still owned",
            ));
        }
        #[cfg(feature = "ebpf")]
        // Host policy generations retain the same atomic root for the lifetime of the pair.
        let broadcasts = if matches!(direction, AuxDirection::HostEgress { .. }) {
            pair.replace_host_broadcasts(broadcasts)?;
            &[]
        } else {
            broadcasts
        };
        let mut member = AuxMember::new(realm, scope, direction, pair, broadcasts)?;
        member.pair.verify()?;
        let program = self.load_auxiliary(&member, &inner.current, aux.conntrack.as_ref())?;
        let _links = self.state.open_links()?;
        let _start = self.shadow.shutdown.lock_capture_start()?;
        if !self.shadow.capture_ready() {
            return Err(publisher_busy());
        }
        let projection = self.shadow.projection.upgrade().ok_or_else(lost_capture)?;
        if member.pair.unavailable()? {
            member.pair.verify()?;
            return Err(publisher_busy());
        }
        // Keep the neutral-to-data replacement inside the same authority as the gate open.
        let fd = program.program.as_fd();
        let link = match direction {
            AuxDirection::LanIngress => AuxTcxLink::outer(&member.pair, fd, &self.budget)?,
            #[cfg(feature = "ebpf")]
            AuxDirection::HostEgress { .. } => {
                AuxTcxLink::host_egress(&member.pair, fd, &self.budget)?
            }
        };
        member.link = Some(link);
        member.program = Some(program);
        let aux = inner.auxiliary.as_mut().unwrap();
        aux.members.push(member);
        let member = aux.members.last_mut().unwrap();
        let opened = (|| {
            self.maps.bind_aux_realm(&member.pair, realm)?;
            member.key_bound = true;
            #[cfg(feature = "ebpf")]
            if let AuxDirection::HostEgress { binding, .. } = member.direction {
                self.maps.bind_host_realm(realm, binding)?;
                member.host_bound = true;
            }
            member.set_dns_binding(&projection, true)?;
            member.pair.set_open(true)
        })();
        if let Err(error) = opened {
            tracing::debug!(realm, errno = ?error.raw_os_error(), %error, "auxiliary gate activation failed");
            drop(_start);
            drop(_links);
            self.close_member(member, &aux.grace)
                .map_err(|failure| self.fail_capture(failure))?;
            return if error.kind() == io::ErrorKind::WouldBlock {
                Err(io::Error::other(error))
            } else {
                Err(error)
            };
        }
        Ok(())
    }

    fn close_member(&self, member: &mut AuxMember, grace: &AuxReaderGrace) -> io::Result<()> {
        if member.program.is_none() {
            return Ok(());
        }
        self.revoke_member(member).and(grace.synchronize())?;
        member.program.take();
        Ok(())
    }

    fn revoke_member(&self, member: &mut AuxMember) -> io::Result<()> {
        let gate = member.pair.set_open(false);
        let dns = if member.dns_active {
            if let Some(projection) = self.shadow.projection.upgrade() {
                member.set_dns_binding(&projection, false)
            } else {
                member.dns_active = false;
                Ok(())
            }
        } else {
            Ok(())
        };
        let detached = member
            .link
            .as_ref()
            .map_or(Ok(()), |(link, _)| link.detach());
        if detached.is_ok() {
            member.link.take();
        }
        let key = if member.key_bound {
            self.maps
                .unbind_aux_realm(&member.pair, member.realm)
                .map(|()| member.key_bound = false)
        } else {
            Ok(())
        };
        gate.and(dns).and(detached).and(key)
    }

    pub(crate) fn verify_auxiliary(&self, realm: u32, pair: &Arc<AuxDevicePair>) -> io::Result<()> {
        let inner = self.state.inner.lock();
        let missing = || io::Error::from_raw_os_error(libc::ENODEV);
        let member = inner
            .auxiliary
            .as_ref()
            .and_then(|aux| {
                aux.members
                    .iter()
                    .find(|member| member.realm == realm && Arc::ptr_eq(&member.pair, pair))
            })
            .ok_or_else(missing)?;
        let (link, _) = member.link.as_ref().ok_or_else(missing)?;
        let program = member.program.as_ref().ok_or_else(lost_capture)?;
        link.verify(program.program.id())?;
        pair.verify_open()
    }

    pub(crate) fn close_auxiliary(&self, realm: u32) -> io::Result<()> {
        let mut inner = self.state.inner.lock();
        if let Some(aux) = inner.auxiliary.as_mut()
            && let Some(member) = aux.members.iter_mut().find(|m| m.realm == realm)
        {
            #[cfg(feature = "ebpf")]
            if matches!(member.direction, AuxDirection::HostEgress { .. }) {
                if member.program.is_none() {
                    return Ok(());
                }
                self.revoke_member(member)?;
                let pair = Arc::clone(&member.pair);
                drop(inner);
                self.synchronize_host_input()?;
                let mut inner = self.state.inner.lock();
                if let Some(member) = inner.auxiliary.as_mut().and_then(|aux| {
                    aux.members
                        .iter_mut()
                        .find(|m| m.realm == realm && Arc::ptr_eq(&m.pair, &pair))
                }) {
                    member.program.take();
                }
                return Ok(());
            }
            self.close_member(member, &aux.grace)?;
        }
        Ok(())
    }

    /// The scope owner has now closed its old TUN FD and joined every application and output.
    pub(crate) fn unbind_auxiliary(&self, realm: u32) -> io::Result<()> {
        let mut inner = self.state.inner.lock();
        let Some(aux) = inner.auxiliary.as_deref_mut() else {
            return Ok(());
        };
        let Some(index) = aux.members.iter().position(|m| m.realm == realm) else {
            return Ok(());
        };
        let member = &mut aux.members[index];
        if member.key_bound || member.link.is_some() || member.dns_active {
            return Err(io::Error::other(
                "gateway auxiliary binding has not been closed",
            ));
        }
        if member.program.is_some() {
            return Err(io::Error::other(
                "gateway auxiliary readers have not drained",
            ));
        }
        if !member.pair.inner_gone()? {
            return Err(io::Error::other(
                "gateway auxiliary TUN device is still registered",
            ));
        }
        let index = match member.direction {
            AuxDirection::LanIngress => {
                let arbitration = inner.current.arbitration.as_ref().map(|a| &a.kernel);
                self.maps
                    .clear_aux_realm(realm, arbitration, &self.budget)?;
                index
            }
            #[cfg(feature = "ebpf")]
            AuxDirection::HostEgress { binding, .. } if member.host_bound => {
                if member.retiring {
                    return Err(publisher_busy());
                }
                let host = self.host.as_ref().ok_or_else(lost_capture)?;
                // Keep the closed row in the membership table while other realms publish.
                let pair = Arc::clone(&member.pair);
                member.retiring = true;
                drop(inner);
                let result =
                    self.maps
                        .clear_host_binding(realm, binding, host.arbitration(), &self.budget);
                inner = self.state.inner.lock();
                let members = &mut inner.auxiliary.as_mut().ok_or_else(lost_capture)?.members;
                let index = members
                    .iter()
                    .position(|m| m.realm == realm && Arc::ptr_eq(&m.pair, &pair))
                    .ok_or_else(lost_capture)?;
                members[index].retiring = false;
                result?;
                index
            }
            #[cfg(feature = "ebpf")]
            AuxDirection::HostEgress { .. } => index,
        };
        if let Some(previous) = &mut inner.previous {
            previous.programs.auxiliary.retain(|(r, _)| *r != realm);
        }
        let aux = inner.auxiliary.as_mut().unwrap();
        aux.members.swap_remove(index);
        Ok(())
    }

    pub(crate) fn activate_dns(
        &self,
        fingerprint: [u8; 32],
        generation: u64,
        recover: bool,
    ) -> io::Result<()> {
        self.activate_final(
            &mut self.state.inner.lock(),
            fingerprint,
            generation,
            recover,
        )
    }

    pub(crate) fn verify_committed(
        &self,
        fingerprint: [u8; 32],
        generation: u64,
    ) -> io::Result<()> {
        let mut inner = self.state.inner.lock();
        if let Some(error) = self.capture_error() {
            return Err(error);
        }
        if inner.flags_fenced
            || inner.previous.is_some()
            || inner.final_publication != Some((fingerprint, generation))
            || inner.current.policy.bytecode.fingerprint != fingerprint
        {
            return Err(io::Error::other("auxiliary publication has not settled"));
        }
        drop(self.state.open_links()?);
        self.verify_auxiliary_targets(inner.auxiliary.as_deref_mut(), None)
            .map_err(|error| self.fail_capture(error))
    }

    fn activate_final(
        &self,
        inner: &mut PublisherInner,
        fingerprint: [u8; 32],
        generation: u64,
        recover: bool,
    ) -> io::Result<()> {
        if let Some(error) = self.capture_error() {
            return Err(error);
        }
        if inner.previous.is_some() || inner.current.policy.bytecode.fingerprint != fingerprint {
            return Err(io::Error::other(
                "gateway final publication identity mismatch",
            ));
        }
        if inner.flags_fenced {
            // Startup can complete while a reload is still restoring the previous flags.
            inner.final_publication = Some((fingerprint, generation));
            return Ok(());
        }
        #[cfg(all(test, feature = "ebpf"))]
        let replacement = if recover && self.replace_tcx_before_final.swap(false, Ordering::AcqRel)
        {
            Some(tests::replace_final_target(self, inner)?)
        } else {
            None
        };
        let verified = self.verify_auxiliary_targets(inner.auxiliary.as_deref_mut(), None);
        #[cfg(all(test, feature = "ebpf"))]
        if let Some((realm, replacement)) = replacement {
            tests::restore_and_check_withdrawal(self, inner, realm, replacement)?;
        }
        verified.map_err(|error| self.fail_capture(error))?;
        let _links = self.state.open_links()?;
        if recover {
            self.shadow.healthy.store(true, Ordering::Release);
        }
        inner.final_publication = Some((fingerprint, generation));
        if let Some(bank) = &inner.current.bank {
            self.shadow.activate(Arc::clone(bank), generation);
        }
        Ok(())
    }

    pub(crate) fn stage_dns_reload(&self) {
        let mut inner = self.state.inner.lock();
        inner.final_publication = None;
        if let Ok(_links) = self.state.open_links() {
            self.shadow.report_status(inner.current.status);
        }
    }

    pub(crate) fn degrade_dns(&self) {
        let mut inner = self.state.inner.lock();
        inner.final_publication = None;
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
        retains: &mut dyn FnMut(&GatewayKey) -> bool,
    ) -> io::Result<()> {
        let Some(mut inner) = self.state.inner.try_lock() else {
            return Ok(());
        };
        if let Some(error) = self.capture_error() {
            return Err(error);
        }
        #[cfg(feature = "ebpf")]
        let host = self.host.as_ref().map(HostResources::arbitration);
        #[cfg(not(feature = "ebpf"))]
        let host = None;
        let lan = inner.current.arbitration.as_ref().map(|a| &a.kernel);
        if lan.is_some() || host.is_some() {
            self.shadow.diagnostics.sample_dns_decisions(&self.maps);
            self.check_hold_custody()?;
        }
        collector
            .sweep(&self.maps, now_ns, lan, host, &self.budget, retains)
            .map_err(|error| {
                if lan.is_some() || host.is_some() {
                    self.fail_capture(error)
                } else {
                    error
                }
            })?;
        if let Some(bank) = &inner.current.bank
            && !self.shadow.notrack_latched()
        {
            self.shadow.diagnostics.sample_dns(
                bank,
                self.maps.reason_count(GatewayReason::WouldPassDns).ok(),
            );
        } else if inner.previous.is_none()
            && (inner.current.bank.is_some() || lan.is_some_and(|arb| arb.pending() == 0))
        {
            self.compact_static(&mut inner)?;
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

    // The guarded guest changes the actual link target while the publication lock excludes
    // the watcher. Both programs have identical policy, fact maps, DNS and arbitration.
    #[cfg(feature = "ebpf")]
    pub(super) fn replace_final_target(
        publisher: &GatewayPublisher,
        inner: &PublisherInner,
    ) -> io::Result<(u32, AuxProgram)> {
        let aux = inner.auxiliary.as_ref().ok_or_else(lost_capture)?;
        let member = aux
            .members
            .iter()
            .find(|member| member.link.is_some())
            .ok_or_else(lost_capture)?;
        let current = member.program.as_ref().ok_or_else(lost_capture)?;
        let next = publisher.load_auxiliary(member, &inner.current, aux.conntrack.as_ref())?;
        member
            .link
            .as_ref()
            .unwrap()
            .0
            .replace(current.program.as_fd(), next.program.as_fd())?;
        Ok((member.realm, next))
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn restore_and_check_withdrawal(
        publisher: &GatewayPublisher,
        inner: &mut PublisherInner,
        realm: u32,
        replacement: AuxProgram,
    ) -> io::Result<()> {
        let aux = inner.auxiliary.as_mut().ok_or_else(lost_capture)?;
        let member = aux
            .members
            .iter_mut()
            .find(|member| member.realm == realm)
            .ok_or_else(lost_capture)?;
        let (link, _) = member.link.as_ref().ok_or_else(lost_capture)?;
        let original = member.program.as_ref().ok_or_else(lost_capture)?;
        link.replace(replacement.program.as_fd(), original.program.as_fd())?;
        // Force key removal to fail after the actual TCX detach, then restore the key so
        // the real withdrawal can be retried. The charge stays with the still-held program.
        member.pair.set_open(false)?;
        publisher.maps.unbind_aux_realm(&member.pair, realm)?;
        let error = publisher.close_member(member, &aux.grace).unwrap_err();
        assert_eq!(error.to_string(), "foreign auxiliary binding");
        assert!(member.link.is_none() && member.program.is_some());
        publisher.maps.bind_aux_realm(&member.pair, realm)?;
        publisher.close_member(member, &aux.grace)?;
        assert!(member.program.is_none());
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn host_execution_scopes_are_distinct_from_the_shared_dns_scope() {
        let host_scope = ScopeId::allocate().unwrap();
        let first = ScopeId::allocate().unwrap();
        let second = ScopeId::allocate().unwrap();
        let lan = ScopeId::allocate().unwrap();
        let bindings = [(lan, 1), (host_scope, GATEWAY_REALM_CAPACITY)];
        let egress = AuxDirection::HostEgress {
            stamp: 2,
            binding: 1,
            is_l2: true,
        };

        assert!(egress.matches_dns_scope(first, 2, &bindings));
        assert!(egress.matches_dns_scope(second, 3, &bindings));
        assert!(egress.matches_dns_scope(first, 2, &[]));
        assert!(!egress.matches_dns_scope(host_scope, 2, &bindings));
        assert!(!egress.matches_dns_scope(first, GATEWAY_REALM_CAPACITY, &[]));
        assert!(!egress.matches_dns_scope(first, 1, &bindings));
        assert!(!egress.matches_dns_scope(lan, 2, &bindings));
        assert!(AuxDirection::LanIngress.matches_dns_scope(lan, 1, &bindings));
    }

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
