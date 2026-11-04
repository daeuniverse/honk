//! eBPF backend abstraction.

#[cfg(feature = "ebpf")]
pub(crate) mod interface;
pub mod map_snapshot;
pub mod maps;
pub mod mock;
pub mod probe;
mod retirement;
pub use retirement::*;
#[cfg(feature = "ebpf")]
pub mod real;
#[cfg(feature = "ebpf")]
pub use real::TcpKernelPin;
#[cfg(all(test, feature = "ebpf"))]
pub(crate) mod test_support;

/// Resume state for a bounded traversal of one tuple map. A completed traversal
/// resets it, so the next scan starts a new pass. Batch cursors name buckets,
/// not keys that retirement can remove between scans.
#[derive(Clone, Copy, Debug, Default)]
pub struct FlowScanCursor {
    pub(crate) batch: Option<[u8; 4]>,
    pub(crate) next_key: Option<[u8; 40]>,
}

impl FlowScanCursor {
    pub(crate) fn is_start(self) -> bool {
        self.batch.is_none() && self.next_key.is_none()
    }
}

pub type TcpPinErrorSink =
    std::sync::Arc<parking_lot::Mutex<Option<tokio::sync::mpsc::UnboundedSender<anyhow::Error>>>>;

pub struct TcpAdoption {
    pub incarnation: u64,
    pub handoff: Option<RoutingHandoffEntry>,
    pub pin: TcpPin,
}

/// The accepted child has no proof: either sock_ops has not published it yet (it does so after
/// the kernel queued the child, so a running acceptor can win that race by microseconds) or it
/// never will. Callers retry briefly before treating the child as unproven.
#[derive(Debug, thiserror::Error)]
#[error("accepted TCP child is unproven: no proof published")]
pub struct TcpChildProofPending;

pub enum TcpPin {
    Model,
    #[cfg(feature = "ebpf")]
    Kernel(TcpKernelPin),
}

impl TcpPin {
    pub(crate) fn release(self) -> anyhow::Result<()> {
        match self {
            Self::Model => Ok(()),
            #[cfg(feature = "ebpf")]
            Self::Kernel(pin) => pin.release(),
        }
    }
}

use async_trait::async_trait;
use honk_ebpf_common::*;

/// Captured once at admission; `None` is reserved for stateless or model flows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UdpFlowOwner {
    pub token: u32,
    pub incarnation: Option<std::num::NonZeroU64>,
}

impl UdpFlowOwner {
    pub fn new(token: u32, incarnation: Option<u64>) -> anyhow::Result<Self> {
        let incarnation = incarnation
            .map(|incarnation| {
                anyhow::ensure!(
                    incarnation <= honk_ebpf_common::conn::FLOW_INCARNATION_MAX,
                    "UDP flow incarnation exceeds allocator domain"
                );
                std::num::NonZeroU64::new(incarnation)
                    .ok_or_else(|| anyhow::anyhow!("UDP flow incarnation must be nonzero"))
            })
            .transpose()?;
        Ok(Self { token, incarnation })
    }

    pub fn incarnation(self) -> Option<u64> {
        self.incarnation.map(std::num::NonZeroU64::get)
    }

    pub fn is_stateless(self, src_port: u16, dst_port: u16) -> bool {
        self.token == 0 && honk_ebpf_common::conn::is_stateless_udp_ports(src_port, dst_port)
    }
}

pub const UDP_DECISION_SEQUENCE_MAP: &str = "UDP_DECISION_SEQUENCE";
pub const RETIRE_FENCE_MAP: &str = "RETIRE_FENCE";

/// Callback for a bounded janitor scan. Return `false` to stop the scan at a
/// chunk boundary (used to enforce the janitor time budget).
pub type ConnStateChunkVisitor<'a> = dyn FnMut(&[(TuplesKey, ConnState)]) -> bool + 'a;
pub type RedirectTrackChunkVisitor<'a> = dyn FnMut(&[(RedirectTuple, RedirectEntry)]) -> bool + 'a;
pub type RoutingHandoffChunkVisitor<'a> =
    dyn FnMut(&[(TuplesKey, RoutingHandoffEntry)]) -> bool + 'a;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPushPhase {
    DomainRouting,
    DestinationLpm,
    SourceLpm,
    MacLpm,
    Program,
    Attach,
    Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDecisionTransition {
    ArmDirect(u32),
    ActivateDirect(u32),
    ActivateProxy(u8, u32),
    Block,
}

#[derive(Debug, Clone, Copy)]
pub struct UdpDecisionCommit {
    pub key: TuplesKey,
    pub token: u32,
    pub transition: UdpDecisionTransition,
}

pub type UdpCommitApply<'a> = dyn FnMut() -> anyhow::Result<UdpDecisionCommitResult> + 'a;
pub type UdpCommitVisit<'a> = dyn FnMut(usize, &mut UdpCommitApply<'_>) -> anyhow::Result<()> + 'a;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDecisionCommitResult {
    Applied,
    Missing,
    /// A newer kernel incarnation owns the tuple; nothing was removed.
    Superseded,
    TokenMismatch,
    StateMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDecisionSequenceStatus {
    pub next: u32,
    pub generation: u32,
}

impl UdpDecisionSequenceStatus {
    pub fn exhausted(self) -> bool {
        self.next >= honk_ebpf_common::UDP_DECISION_SEQUENCE_MASK
    }
}

pub(crate) fn validate_udp_decision_transition(
    transition: UdpDecisionTransition,
) -> anyhow::Result<()> {
    let mark = match transition {
        UdpDecisionTransition::ArmDirect(mark)
        | UdpDecisionTransition::ActivateDirect(mark)
        | UdpDecisionTransition::ActivateProxy(_, mark) => mark,
        UdpDecisionTransition::Block => return Ok(()),
    };
    anyhow::ensure!(
        !skb_mark_has_reserved_bits(mark),
        "UDP decision rule mark contains reserved skb bits: 0x{mark:08x}"
    );
    Ok(())
}

fn final_udp_meta(previous: RoutingMeta, outbound: u8, mark: u32, offload: bool) -> RoutingMeta {
    const DSCP_MASK: u64 = 0xff << 48;
    let preserved = unsafe { previous.raw } & (DSCP_MASK | ROUTING_META_FLAG_PUBLISHED);
    let flags = if offload {
        ROUTING_META_FLAG_OFFLOAD
    } else {
        0
    };
    RoutingMeta {
        raw: preserved | outbound as u64 | ((mark as u64) << 8) | flags,
    }
}

pub(crate) fn apply_udp_decision_transition(
    state: &mut ConnState,
    transition: UdpDecisionTransition,
) -> Result<(), UdpDecisionCommitResult> {
    let expected = match transition {
        UdpDecisionTransition::ActivateDirect(_) => UdpDecisionState::DirectArmed,
        UdpDecisionTransition::ArmDirect(_)
        | UdpDecisionTransition::ActivateProxy(_, _)
        | UdpDecisionTransition::Block => UdpDecisionState::Pending,
    };
    if state.state != expected as u8 {
        return Err(UdpDecisionCommitResult::StateMismatch);
    }
    if let UdpDecisionTransition::ActivateDirect(mark) = transition {
        let raw = unsafe { state.meta.raw };
        let armed_mark = ((raw >> 8) & 0xffff_ffff) as u32;
        if raw & 0xff != OutboundIndex::Direct as u64
            || armed_mark != mark
            || raw & ROUTING_META_FLAG_OFFLOAD != 0
        {
            return Err(UdpDecisionCommitResult::StateMismatch);
        }
    }
    match transition {
        UdpDecisionTransition::ArmDirect(mark) => {
            state.state = UdpDecisionState::DirectArmed as u8;
            state.meta = final_udp_meta(state.meta, OutboundIndex::Direct as u8, mark, false);
        }
        UdpDecisionTransition::ActivateDirect(mark) => {
            state.state = UdpDecisionState::None as u8;
            state.meta = final_udp_meta(state.meta, OutboundIndex::Direct as u8, mark, true);
        }
        UdpDecisionTransition::ActivateProxy(outbound, mark) => {
            state.state = UdpDecisionState::Proxy as u8;
            state.meta = final_udp_meta(state.meta, outbound, mark, false);
        }
        UdpDecisionTransition::Block => {
            state.state = UdpDecisionState::Block as u8;
            state.meta = final_udp_meta(state.meta, OutboundIndex::Block as u8, 0, false);
        }
    }
    Ok(())
}

pub(crate) fn udp_state_is_userspace_owned(state: u8) -> bool {
    state == UdpDecisionState::Preparing as u8
        || state == UdpDecisionState::Pending as u8
        || state == UdpDecisionState::Aborted as u8
        || state == UdpDecisionState::Proxy as u8
}

/// Unpublished UDP staging that `quiesce_udp_staging` and pending-only
/// retirement reclaim; Proxy and finished states belong to their endpoint.
pub(crate) fn udp_state_is_staged(state: u8) -> bool {
    state == UdpDecisionState::Preparing as u8
        || state == UdpDecisionState::Pending as u8
        || state == UdpDecisionState::Aborted as u8
}

pub(crate) fn udp_state_is_legacy_userspace_owned(state: &ConnState) -> bool {
    if state.decision_token != 0 || state.state != UdpDecisionState::None as u8 {
        return false;
    }
    let raw = unsafe { state.meta.raw };
    if raw & ROUTING_META_FLAG_PUBLISHED == 0 || raw & ROUTING_META_FLAG_OFFLOAD != 0 {
        return false;
    }
    let outbound = (raw & 0xff) as u8;
    let must = ((raw >> 40) & 1) != 0;
    outbound != OutboundIndex::Block as u8
        && (outbound != OutboundIndex::Direct as u8
            || !must
            || raw & ROUTING_META_FLAG_WAN_USERSPACE != 0)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionMapOperation {
    Set,
    Remove,
}

#[derive(Debug, thiserror::Error)]
pub enum DomainRouteWriteError {
    #[error("domain routing map capacity exhausted")]
    MapFull,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl DomainRouteWriteError {
    pub const fn is_map_full(&self) -> bool {
        matches!(self, Self::MapFull)
    }
}

pub const MAX_DATAPATH_PROGRAMS: usize = 64;
pub const MAX_DATAPATH_ATTACHMENTS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatapathKind {
    Real,
    Mock,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatapathCheck {
    Verified,
    Absent,
    Unknown,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatapathObservationError {
    Programs,
    Hooks,
    Routing,
    Admission,
    Maps,
    Limit,
}

#[derive(Debug, Clone)]
pub struct DatapathProgram {
    pub name: String,
    pub id: u32,
}

#[derive(Debug, Clone)]
pub struct DatapathAttachment {
    pub program: String,
    pub interface: String,
    pub egress: bool,
    pub state: DatapathCheck,
}

/// Facts checked during one read of the backend cell, not configuration intent.
/// Unknown occupancy is deliberate: observation never walks a traffic map.
#[derive(Debug, Clone)]
pub struct DatapathObservation {
    pub kind: DatapathKind,
    pub checked_at: std::time::SystemTime,
    pub programs: DatapathCheck,
    pub loaded_programs: Vec<DatapathProgram>,
    pub hooks: DatapathCheck,
    pub routing: DatapathCheck,
    pub routing_generation: Option<u64>,
    pub admission: Option<bool>,
    pub listeners_published: Option<bool>,
    pub attachments: Vec<DatapathAttachment>,
    pub conn_state_capacity: Option<u32>,
    pub errors: Vec<DatapathObservationError>,
}

impl DatapathObservation {
    pub fn unknown(kind: DatapathKind) -> Self {
        Self {
            kind,
            checked_at: std::time::SystemTime::now(),
            programs: DatapathCheck::Unknown,
            loaded_programs: Vec::new(),
            hooks: DatapathCheck::Unknown,
            routing: DatapathCheck::Unknown,
            routing_generation: None,
            admission: None,
            listeners_published: None,
            attachments: Vec::new(),
            conn_state_capacity: None,
            errors: Vec::new(),
        }
    }

    pub fn record_error(&mut self, error: DatapathObservationError) {
        if !self.errors.contains(&error) {
            self.errors.push(error);
        }
    }

    /// Claims hooks only when each of the `required` hooks was checked and found
    /// attached. A required hook that cannot be checked keeps `hooks` unknown.
    pub fn verify_required_hooks(&mut self, required: usize) {
        if required > 0
            && self.attachments.len() == required
            && self
                .attachments
                .iter()
                .all(|attachment| attachment.state == DatapathCheck::Verified)
        {
            self.hooks = DatapathCheck::Verified;
        }
    }
}

#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DatapathFlagsWriteOrigin {
    #[default]
    Other,
    FenceNfqueue,
    SetStatic,
    ReopenNfqueue,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatapathFlagsWriteTrace {
    pub ordinal: usize,
    pub origin: DatapathFlagsWriteOrigin,
    pub flags: u32,
    pub failed: bool,
}

/// How far the datapath can match `pname()` rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PnameSupport {
    #[default]
    Full,
    /// Kernel argv capture is unavailable; rules see the thread name.
    ThreadName,
    /// The cgroup hooks are not attached; `pname()` never matches and
    /// `!pname()` always does.
    Unavailable,
}

/// Lists `pname_routing` while `router` has a `pname()` rule that `backend` reduces.
pub(crate) fn record_pname_routing(
    router: &crate::routing::Router,
    backend: &dyn EbpfBackend,
    degradations: &crate::degradations::Degradations,
) {
    use crate::degradations::{Component, Issue};
    let issue = match backend.pname_support() {
        PnameSupport::Full => None,
        _ if !router.uses_process_name() => None,
        PnameSupport::ThreadName => Some(Issue {
            code: "pname_routing_reduced",
            message: "Kernel argv capture is unavailable; process-name rules match the thread name.",
            reason: "comm_fallback",
        }),
        PnameSupport::Unavailable => Some(Issue {
            code: "pname_routing_disabled",
            message: "cgroup v2 is unavailable; pname() conditions see no process name, so positive ones never match and negated ones always match.",
            reason: "cgroup_unavailable",
        }),
    };
    match issue {
        Some(issue) => degradations.set(Component::PnameRouting, issue),
        None => degradations.clear(Component::PnameRouting),
    }
}

#[async_trait]
pub trait EbpfBackend: Send + Sync {
    /// Bounded readonly kernel/owner facts; never repairs or reopens the datapath.
    fn observe_datapath(&self) -> DatapathObservation {
        DatapathObservation::unknown(DatapathKind::Unknown)
    }

    fn inject_routing_fault(
        &mut self,
        _phase: RoutingPushPhase,
        _times: usize,
    ) -> anyhow::Result<()> {
        anyhow::bail!("routing fault injection is unsupported")
    }
    #[cfg(test)]
    fn inject_projection_fault(
        &mut self,
        _operation: ProjectionMapOperation,
        _times: usize,
        _map_full: bool,
    ) -> anyhow::Result<()> {
        anyhow::bail!("projection fault injection is unsupported")
    }
    /// Fail the next `times` `add_domain_ip_bitmap` writes (the sniffed-
    /// domain writeback path).  Test-only, mirroring
    /// `inject_projection_fault`.
    #[cfg(test)]
    fn inject_domain_bitmap_add_fault(&mut self, _times: usize) -> anyhow::Result<()> {
        anyhow::bail!("domain bitmap add fault injection is unsupported")
    }
    #[cfg(test)]
    fn projection_map_snapshot(&self) -> Vec<([u8; 20], DomainRouting)> {
        Vec::new()
    }
    #[cfg(test)]
    fn projection_write_log(&self) -> Vec<ProjectionMapOperation> {
        Vec::new()
    }
    #[cfg(test)]
    fn clear_projection_write_log(&mut self) {}
    fn detach_hooks(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    fn attach_dae0_programs(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    /// Open or close admission at the TC entry points. Implementations must
    /// publish listener sockets before setting this to `true`.
    fn set_datapath_ready(&mut self, _ready: bool) -> anyhow::Result<()> {
        Ok(())
    }

    /// Write the mode-based direct-offload policy (the
    /// `DATAPATH_FLAG_OFFLOAD_*` bits) into `DATAPATH_FLAGS_MAP`.  The
    /// control plane recomputes and pushes the full word on startup, at the
    /// reload commit point, and on every clash mode switch; `lan_ingress`
    /// reads it once per new flow and caches the decision per flow, so the
    /// write takes effect for new flows only — established flows keep the
    /// decision they were created with.
    fn set_datapath_flags(&mut self, _flags: u32) -> anyhow::Result<()> {
        Ok(())
    }
    #[cfg(test)]
    fn arm_datapath_flags_write_fault(&mut self, _nth: usize) -> anyhow::Result<()> {
        anyhow::bail!("datapath flag fault injection is unsupported")
    }
    #[cfg(test)]
    fn mark_datapath_flags_write_origin(&mut self, _origin: DatapathFlagsWriteOrigin) {}
    #[cfg(test)]
    fn arm_quiesce_fault(&mut self) {}
    #[cfg(test)]
    fn datapath_flags_write_log(&self) -> Vec<u32> {
        Vec::new()
    }
    #[cfg(test)]
    fn datapath_flags_write_trace(&self) -> Vec<DatapathFlagsWriteTrace> {
        Vec::new()
    }
    #[cfg(test)]
    fn clear_datapath_flags_write_log(&mut self) {}

    /// After READY has been cleared, wait for every kernel invocation that
    /// observed the prior fence to finish, then remove all unpublished or
    /// pending staged states. Delayed NFQUEUE deliveries therefore fail
    /// token lookup instead of crossing a runtime-generation boundary.
    fn quiesce_udp_staging(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Attach the dae0peer_ingress TC program after dae0peer has been moved
    /// into the isolated daens namespace.  The attach runs inside a scoped
    /// `with_daens_netns` switch — the process threads always stay in the
    /// host netns — while the dae0peer interface and the TPROXY listener
    /// sockets both live in daens.
    fn attach_dae0peer_ingress(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Attach the sk_lookup program to the isolated daens namespace (also a
    /// scoped switch).  The program overrides socket selection for
    /// proxy-bound packets arriving on dae0peer and delivers them to the
    /// daens-resident TPROXY listener while keeping the original destination
    /// intact.
    fn attach_sk_lookup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Publish transparent listeners after their required address-family proofs
    /// are attached. Missing TCP6 leaves slot 1 empty, never an IPv4 substitute.
    /// Keys: 0 TCP4, 1 TCP6, 2.. IPv4 UDP, 2 + UDP_LISTENER_COUNT.. IPv6 UDP.
    /// UDP descriptors must be in flow-hash slot order.
    fn publish_listener_sockets(
        &mut self,
        _tcp4_fd: std::os::unix::io::RawFd,
        _tcp6_fd: Option<std::os::unix::io::RawFd>,
        _udp4_fds: &[std::os::unix::io::RawFd],
        _udp6_fds: &[std::os::unix::io::RawFd],
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Release all published listener references only after admission is closed
    /// and the caller has joined ingress. Errors never authorize reopening.
    fn clear_listener_sockets(&mut self) -> anyhow::Result<()>;

    async fn cleanup(&mut self) -> anyhow::Result<()>;

    /// Snapshot what this backend owns for the interface reconciler: program
    /// FDs plus dup'd link FDs.
    #[cfg(feature = "ebpf")]
    fn interface_binding_snapshot(&self) -> anyhow::Result<interface::BindingSnapshot>;

    /// Load TC programs not loaded yet (a verifier run each). Blocking; on
    /// error the bindings that need a missing program fail in apply.
    #[cfg(feature = "ebpf")]
    fn load_tc_programs(&mut self, _programs: &[interface::TcProgram]) -> anyhow::Result<()> {
        Ok(())
    }

    /// Apply the commit and return replaced or removed link FDs. The caller
    /// must close them outside any lock: the last close takes the rtnl lock.
    #[cfg(feature = "ebpf")]
    fn commit_interface_bindings(
        &mut self,
        commit: interface::BindingCommit,
    ) -> Vec<std::os::fd::OwnedFd>;

    /// Atomically publish a complete compiled routing plan into an inactive slot.
    /// Implementations stage every generation-owned fact map and program before
    /// committing the stable policy root; errors leave the prior root untouched.
    fn publish_routing_plan(
        &mut self,
        plan: &crate::control::routing_matcher::RoutingPushPlan,
        learned_domains: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()>;
    /// Return the committed compiled-policy generation, not the active slot.
    fn routing_policy_generation(&self) -> u64;
    /// Return the slot currently selected by the stable policy root.
    fn active_routing_slot(&self) -> anyhow::Result<u32> {
        Ok(0)
    }
    /// OR a learned domain bitmap into the active generation-owned map.
    fn add_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()>;
    /// Replace one entry in the active generation-owned domain HASH map.
    /// A present all-zero value is meaningful and must not be removed.
    fn set_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> Result<(), DomainRouteWriteError>;
    fn set_domain_ip_bitmap_batch(
        &mut self,
        entries: &[(LpmKey, DomainRouting)],
    ) -> Result<(), (usize, DomainRouteWriteError)> {
        for (index, (key, bitmap)) in entries.iter().enumerate() {
            self.set_domain_ip_bitmap(key, bitmap)
                .map_err(|error| (index, error))?;
        }
        Ok(())
    }
    /// Remove an entry from the active generation-owned domain HASH map.
    fn remove_domain_ip_bitmap(&mut self, ip_key: &LpmKey) -> Result<(), DomainRouteWriteError>;
    fn remove_domain_ip_bitmap_batch(
        &mut self,
        keys: &[LpmKey],
    ) -> Result<(), (usize, DomainRouteWriteError)> {
        for (index, key) in keys.iter().enumerate() {
            self.remove_domain_ip_bitmap(key)
                .map_err(|error| (index, error))?;
        }
        Ok(())
    }

    /// Locked snapshot of one tuple's conn state, for either protocol.
    fn conn_state_lookup(&self, key: &TuplesKey) -> anyhow::Result<Option<ConnState>>;
    /// Raw fixture writes bypass fencing; production mutation goes through
    /// `commit_udp_decision`, `commit_udp_batch` and `retire_batch`.
    #[cfg(test)]
    fn tcp_conn_state_store(&mut self, _key: &TuplesKey, _state: &ConnState) -> anyhow::Result<()> {
        anyhow::bail!("raw TCP conn-state fixture writes are unsupported")
    }
    #[cfg(test)]
    fn udp_conn_state_store(&mut self, _key: &TuplesKey, _state: &ConnState) -> anyhow::Result<()> {
        anyhow::bail!("raw UDP conn-state fixture writes are unsupported")
    }
    /// Derive ownership from the coherent snapshot already read at admission.
    fn udp_flow_owner(&self, token: u32, state: Option<ConnState>) -> anyhow::Result<UdpFlowOwner>;

    fn verify_udp_admission(
        &self,
        tuples: &TuplesKey,
        owner: UdpFlowOwner,
    ) -> anyhow::Result<Option<RoutingHandoffEntry>> {
        let entry = self.routing_handoff_lookup(tuples)?;
        if !owner.is_stateless(tuples.src_port, tuples.dst_port) {
            let current = self.udp_flow_owner(owner.token, self.conn_state_lookup(tuples)?)?;
            if owner.incarnation.is_some() {
                anyhow::ensure!(
                    owner.incarnation == current.incarnation,
                    "UDP admission conn-state incarnation mismatch"
                );
            } else {
                anyhow::ensure!(
                    owner.token != 0 || current.incarnation.is_none(),
                    "ordinary UDP admission has no captured incarnation"
                );
            }
            if let Some(entry) = entry {
                anyhow::ensure!(
                    entry.result.decision_token == owner.token
                        && entry.incarnation == current.incarnation().unwrap_or(0),
                    "UDP admission handoff ownership mismatch"
                );
            } else {
                anyhow::ensure!(owner.token == 0, "staged UDP flow has no routing handoff");
            }
        } else if let Some(entry) = entry {
            anyhow::ensure!(
                entry.result.decision_token == 0,
                "raw DNS handoff token mismatch"
            );
        }
        Ok(entry)
    }

    /// Publish one token-bound UDP decision transition. The caller holds the
    /// backend write lock; implementations validate the state incarnation and
    /// every auxiliary entry before changing any map.
    fn commit_udp_decision(
        &mut self,
        key: &TuplesKey,
        token: u32,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult>;

    /// Fence a bounded batch of initial UDP decisions once. After grace, visit
    /// each item in order with its exact-owner recheck/mutation. The visitor may
    /// skip an expired item or hold its cell lock across the apply call. Success
    /// includes exact fence release; callers must not acknowledge before return.
    /// ActivateDirect uses `commit_udp_decision`, never this fenced batch.
    fn commit_udp_batch(
        &mut self,
        requests: &[UdpDecisionCommit],
        visit: &mut UdpCommitVisit<'_>,
    ) -> anyhow::Result<()>;

    /// Retire captured owners under one bounded tuple-fence/grace batch.
    fn retire_batch(
        &mut self,
        requests: &[RetireRequest<'_>],
        outcomes: &mut [RetireOutcome],
    ) -> Result<RetireCounts, RetireError>;
    /// Verify native child lineage and retain its incarnation under backendR.
    fn adopt_tcp(
        &self,
        fd: std::os::fd::BorrowedFd<'_>,
        tuples: &TuplesKey,
        errors: TcpPinErrorSink,
    ) -> anyhow::Result<TcpAdoption>;
    #[cfg(test)]
    fn tcp_socket_ownership(
        &self,
        fd: std::os::fd::BorrowedFd<'_>,
    ) -> anyhow::Result<TcpSocketOwnership>;
    fn take_expiry_hints(&mut self) -> Option<tokio::sync::mpsc::Receiver<FlowExpiryHint>>;

    /// Validate the pinned allocator map and its locked value before admission.
    fn verify_udp_decision_sequence(&self) -> anyhow::Result<()>;

    /// Read the persistent allocator under its embedded BPF spin lock.
    fn udp_decision_sequence_status(&self) -> anyhow::Result<UdpDecisionSequenceStatus>;

    /// Reset an exhausted allocator only when no live token is reachable by a
    /// rolled-back legacy monotonic allocator starting at `generation`.
    fn reset_udp_decision_sequence(&mut self, generation: u32) -> anyhow::Result<bool>;

    /// Inspect immutable handoff metadata without consuming newer ownership.
    fn routing_handoff_lookup(
        &self,
        key: &TuplesKey,
    ) -> anyhow::Result<Option<RoutingHandoffEntry>>;

    fn redirect_track_lookup(&self, key: &RedirectTuple) -> anyhow::Result<Option<RedirectEntry>>;
    #[cfg(test)]
    fn redirect_track_store(
        &mut self,
        _key: &RedirectTuple,
        _entry: &RedirectEntry,
    ) -> anyhow::Result<()> {
        anyhow::bail!("raw redirect-track fixture writes are unsupported")
    }

    #[cfg(feature = "native-api")]
    fn bind_kernel_trace_dictionary(
        &mut self,
        _dictionary: crate::observe::flows::kernel::KernelTraceDictionary,
    ) {
    }

    #[cfg(feature = "native-api")]
    fn capture_kernel_route(
        &self,
        _key: &TuplesKey,
        _reference: crate::observe::flows::kernel::KernelRouteReference,
    ) -> Result<crate::observe::flows::kernel::CapturedKernelRoute, &'static str> {
        Err("kernel_trace_unsupported")
    }

    #[cfg(all(feature = "ebpf", feature = "native-api"))]
    fn receive_trace(&mut self) -> Option<std::sync::Arc<real::receive_trace::ReceiveTrace>> {
        None
    }

    fn pname_support(&self) -> PnameSupport {
        PnameSupport::Full
    }

    fn set_outbound_alive(
        &mut self,
        outbound: u8,
        domain: u32,
        ipver: u32,
        alive: bool,
    ) -> anyhow::Result<()>;
    fn get_outbound_alive(&self, outbound: u8, domain: u32, ipver: u32) -> anyhow::Result<bool>;

    fn get_bpf_stats(&self, key: u32) -> anyhow::Result<Option<u64>>;

    // CONN_STATE_MAP is a plain hash. Expired datapath hits emit advisory
    // hints; all physical reclamation belongs to fenced userspace retirement.

    /// Visit CONN_STATE_MAP entries in bounded chunks without accumulating
    /// the whole map (524K entries would otherwise spike memory on every
    /// sweep). The visitor returns `false` to stop at a chunk boundary.
    fn conn_state_for_each_chunk(
        &self,
        chunk_size: usize,
        cursor: &mut FlowScanCursor,
        visit: &mut ConnStateChunkVisitor<'_>,
    ) -> anyhow::Result<()>;

    /// Read the datapath's CONN_STATE_MAP occupancy counters:
    /// `(cumulative_inserts, cumulative_ebpf_deletes)`.  Userspace combines
    /// these with `USERSPACE_CONN_STATE_DELETES` to estimate live
    /// occupancy between sweeps (see `CONN_STATE_OCCUPANCY` in the eBPF
    /// maps).  Backends without the gauge return `(0, 0)`.
    fn conn_state_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        Ok((0, 0))
    }

    /// Live `(redirect, handoff)` element estimates: the datapath's cumulative
    /// inserts minus what userspace retirement removed. Backends without the
    /// gauge return `(0, 0)`.
    fn aux_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        Ok((0, 0))
    }

    /// Publish the janitor's conn-only reverse-UDP admission latch.
    fn set_admission_pressure(&mut self, pressured: bool) -> anyhow::Result<()>;

    /// Stream REDIRECT_TRACK in bounded chunks. The callback can stop at a
    /// chunk boundary so callers can retain a wall-clock budget.
    fn redirect_track_for_each_chunk(
        &self,
        chunk_size: usize,
        cursor: &mut FlowScanCursor,
        visit: &mut RedirectTrackChunkVisitor<'_>,
    ) -> anyhow::Result<()>;

    fn routing_handoff_for_each_chunk(
        &self,
        chunk_size: usize,
        cursor: &mut FlowScanCursor,
        visit: &mut RoutingHandoffChunkVisitor<'_>,
    ) -> anyhow::Result<()>;
}
