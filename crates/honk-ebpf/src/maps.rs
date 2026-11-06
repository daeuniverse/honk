use aya_ebpf::Global;
use aya_ebpf::btf_maps::{
    Array, ArrayOfMaps, HashMap, LruHashMap, LruPerCpuHashMap, PerCpuArray, RingBuf, SkStorage,
    SockMap,
};
use aya_ebpf::macros::btf_map;
use honk_ebpf_common::conn::{
    BpfStatsKey, ConnState, FlowIncarnationSequence, FlowMapValue, FragmentKey, FragmentVerdict,
    MAX_CONN_STATE_NUM, ParseTransportCtx, RetirementFence, UdpDecisionSequence,
};
use honk_ebpf_common::dae_ip::In6Addr;
use honk_ebpf_common::event::DaeEvent;
use honk_ebpf_common::redirect_need::{
    RoutingHandoffEntry, SocketIdentity, TcpSocketBinding, TuplesKey,
};
use honk_ebpf_common::{DaeParam, RedirectEntry, RedirectTuple, RoutingPolicyDescriptor};
#[cfg(feature = "routing-test")]
use honk_ebpf_common::{RoutingInput, RoutingTestResult};

use crate::transport::ParsedPacket;

/// LPM tries are generation-owned by userspace and bound to the generated
/// routing extension; no legacy fact map is present in the static datapath.
pub const MAX_ROUTING_HANDOFF_NUM: usize = 65536;

#[repr(C)]
pub struct UdpDecisionScratch {
    pub redirect_key: RedirectTuple,
    pub redirect_header: u64,
    pub redirect: RedirectEntry,
    pub handoff_header: u64,
    pub handoff: RoutingHandoffEntry,
    pub state: ConnState,
}

#[unsafe(no_mangle)]
pub static PARAM: Global<DaeParam> = Global::new(DaeParam::DEFAULT);

#[unsafe(no_mangle)]
pub static WAN_IFINDEX: Global<u32> = Global::new(0);

/// dae0peer interface ifindex used by the sk_lookup program to identify
/// proxy-bound packets that have entered the isolated dae netns.
#[unsafe(no_mangle)]
pub static DAE0PEER_IFINDEX: Global<u32> = Global::new(0);

#[btf_map]
pub static OUTBOUND_CONNECTIVITY_MAP: Array<u64, 1536, 0> = Array::new();

#[btf_map]
pub static LISTEN_SOCKET_MAP: SockMap<16> = SockMap::new();

#[btf_map]
pub static DATAPATH_STATE_MAP: Array<u32, 1, 0> = Array::new();

#[inline(always)]
pub fn datapath_ready() -> bool {
    DATAPATH_STATE_MAP.get(0).is_some_and(|ready| *ready != 0)
}

/// Runtime offload and NFQUEUE readiness flags written by the sole userspace coordinator.
#[btf_map]
pub static DATAPATH_FLAGS_MAP: Array<u32, 1, 0> = Array::new();

/// Route-time offload policy is cached per flow; UDP staging paths re-read
/// only the enabled/readiness fence before publishing an exact pending mark.
#[inline(always)]
pub fn datapath_flags() -> u32 {
    DATAPATH_FLAGS_MAP.get(0).copied().unwrap_or(0)
}

/// Only conn-state occupancy gates reverse UDP learning; auxiliary pressure
/// must not change the semantics of incoming UDP services.
#[btf_map]
pub static ADMISSION_PRESSURE: Array<u32, 1> = Array::new();

#[inline(always)]
pub fn admission_pressure() -> bool {
    ADMISSION_PRESSURE
        .get(0)
        .is_some_and(|pressure| *pressure != 0)
}

/// Persistent across process reloads so no live held skb can observe token reuse.
#[btf_map]
pub static UDP_DECISION_SEQUENCE: Array<UdpDecisionSequence, 1, 0> = Array::new();

/// Generation-local ownership IDs, independent of the persistent UDP allocator.
#[btf_map]
pub static FLOW_INCARNATION_SEQUENCE: Array<FlowIncarnationSequence, 1> = Array::new();

#[btf_map]
pub static RETIRE_ACTIVE: Array<u32, 1> = Array::new();

#[btf_map]
pub static RETIRE_FENCE: HashMap<TuplesKey, RetirementFence, 65536, 1> = HashMap::new();

/// Private map-in-map publication supplies the synchronous kernel grace period.
#[btf_map]
pub static RETIRE_GRACE_ROOT: ArrayOfMaps<Array<u32, 1>, 1> = ArrayOfMaps::new();

#[btf_map]
pub static TCP_LIVE_PINS: HashMap<u64, u8, 65536, 1> = HashMap::new();

#[btf_map]
pub static TCP_SOCKET_BINDING: SkStorage<TcpSocketBinding> = SkStorage::new();

/// SYN invocation exclusion: zero during classification/cached reuse, a fresh
/// incarnation only for authorized replacement. No userspace mutation or expiry.
#[btf_map]
pub static TCP_PUBLISHING: HashMap<TuplesKey, u64, 65536, 1> = HashMap::new();

#[inline(always)]
pub fn tuple_retiring(key: &TuplesKey) -> bool {
    RETIRE_ACTIVE.get(0).is_none_or(|active| *active != 0)
        && unsafe { RETIRE_FENCE.get(key).is_some() }
}

#[btf_map]
/// Plain hash with BPF_F_NO_PREALLOC: kernel memory scales with live
/// entries instead of locking max_entries up front (~8 MB empty instead of
/// ~8 MB per 64K capacity).  Eviction is owned by the userspace janitor
/// (state-based timeouts), never by silent kernel LRU eviction — an evicted
/// entry here breaks reply rewriting for live flows.
pub static REDIRECT_TRACK: HashMap<RedirectTuple, FlowMapValue<RedirectEntry>, 65536, 1> =
    HashMap::new();

#[btf_map]
/// LAN framing of the client side of a redirected non-DNS UDP flow, keyed by the
/// client address and port alone (destination zeroed, token cleared). A reply
/// from a peer the client never contacted has no exact `REDIRECT_TRACK` entry
/// but must still reach the same client. Kernel LRU eviction is approximate:
/// near capacity, and sooner with many CPUs, it can drop a quiet client before
/// the map is full. That only restores the previous behaviour for that client,
/// unlike the plain hashes above, so no userspace sweep owns it.
pub static CLIENT_REPLY_TRACK: LruHashMap<RedirectTuple, RedirectEntry, 16384> = LruHashMap::new();

/// Fixed one-second window of a source's new-flow budget on one CPU.
#[repr(C)]
pub struct NewFlowWindow {
    pub second: u32,
    pub count: u32,
}

/// New-flow budget per LAN source address. Per-CPU values let each CPU count
/// without atomics, which LRU maps cannot back with a spin lock; the effective
/// limit is the CPU count times `NEW_FLOW_LIMIT_PER_CPU_SECOND`. Eviction only
/// forgets a source's recent count.
#[btf_map]
pub static NEW_FLOW_RATE: LruPerCpuHashMap<In6Addr, NewFlowWindow, 16384> = LruPerCpuHashMap::new();

/// Datagrams whose first fragment was redirected or dropped; later fragments
/// of the same datagram are dropped too. Forgetting an entry only lets later
/// fragments pass as they did before the record existed.
#[btf_map]
pub static FRAG_VERDICT: LruHashMap<FragmentKey, FragmentVerdict, 4096> = LruHashMap::new();

#[btf_map]
/// Plain hash with BPF_F_NO_PREALLOC: swept by the userspace janitor (30 s
/// timeout).
pub static ROUTING_HANDOFF_MAP: HashMap<
    TuplesKey,
    FlowMapValue<RoutingHandoffEntry>,
    MAX_ROUTING_HANDOFF_NUM,
    1,
> = HashMap::new();

#[repr(C)]
pub struct RouteTraceSequence {
    pub lock: aya_ebpf_bindings::bindings::bpf_spin_lock,
    pub next: u32,
}

// Instance-local: unlike the UDP decision allocator, this map is never reused.
#[btf_map]
pub static ROUTE_TRACE_SEQUENCE: Array<RouteTraceSequence, 1> = Array::new();

#[btf_map]
pub static ROUTE_TRACE_MAP: LruHashMap<
    u32,
    honk_ebpf_common::KernelRouteWitness,
    { honk_ebpf_common::ROUTE_TRACE_CAPACITY as usize },
> = LruHashMap::new();

/// Stable one-entry policy root. The backend atomically swaps the immutable
/// descriptor map only after every inactive target slot and its generation-owned
/// fact maps are ready.
#[btf_map]
pub static ROUTING_POLICY_ROOT: ArrayOfMaps<Array<RoutingPolicyDescriptor, 1>, 1> =
    ArrayOfMaps::new();
#[cfg(feature = "routing-test")]
#[btf_map]
pub static ROUTING_TEST_INPUT: Array<RoutingInput, 1> = Array::new();

#[cfg(feature = "routing-test")]
#[btf_map]
pub static ROUTING_TEST_OUTPUT: Array<RoutingTestResult, 1> = Array::new();

#[btf_map]
pub static SOCKET_IDENTITY: SkStorage<SocketIdentity> = SkStorage::new();

// Must be pinned in userspace.
// Plain hash with BPF_F_NO_PREALLOC: kernel memory scales with live entries
// instead of pinning ~84 MB for 512K capacity up front. Expired hits emit
// advisory hints; the userspace retirement worker and janitor reclaim under
// the common tuple fence and kernel grace period. The kernel never evicts.
// Inserts under memory pressure fail closed and increment the overflow counter.
#[btf_map]
pub static CONN_STATE_MAP: HashMap<
    TuplesKey,
    FlowMapValue<ConnState>,
    { MAX_CONN_STATE_NUM as usize },
    1,
> = HashMap::new();

/// Successful insertions remain counted through Aborted; only fenced userspace
/// reclamation removes tuple elements. The second slot is retained, always zero,
/// for the existing occupancy ABI.
#[btf_map]
pub static CONN_STATE_OCCUPANCY: PerCpuArray<u64, 2> = PerCpuArray::new();

/// Successful redirect/handoff insertions; only fenced userspace reclamation
/// removes these elements, so userspace subtracts its own deletes.
#[btf_map]
pub static AUX_OCCUPANCY: PerCpuArray<u64, 2> = PerCpuArray::new();

/// Conn UDP/TCP, redirect/handoff insertion, socket identity capture, TCP child proof
/// storage and non-collision SYN claim failures.
#[btf_map]
pub static BPF_STATS_MAP: Array<u64, { BpfStatsKey::COUNT as usize }> = Array::new();

#[inline(always)]
pub fn increment_bpf_stat(key: BpfStatsKey) {
    if let Some(counter) = BPF_STATS_MAP.get_ptr_mut(key as u32) {
        unsafe {
            *counter += 1;
        }
    }
}

/// Per-outbound traffic counters (per-CPU to avoid cross-CPU contention on
/// the per-packet update path). Each entry packs tx/rx packets and bytes for
/// one of the 256 possible `u8` outbound indices; userspace aggregates the
/// per-CPU values when reading.
#[btf_map]
pub static OUTBOUND_STATS: PerCpuArray<
    honk_ebpf_common::OutboundStatsCounters,
    { honk_ebpf_common::OUTBOUND_STATS_MAP_LEN as usize },
> = PerCpuArray::new();

#[btf_map]
pub static EVENT_RINGBUF: RingBuf<DaeEvent, 262144> = RingBuf::new();

#[repr(C)]
pub struct FlowExpiryHint {
    pub incarnation: u64,
    pub last_hint_ns: u64,
}

/// Advisory hint suppression only. Each CPU retains the last hinted owner of
/// a tuple; LRU eviction may forget it, while the janitor remains lossless.
#[btf_map]
pub static FLOW_EXPIRY_HINT: LruPerCpuHashMap<TuplesKey, FlowExpiryHint, 4096> =
    LruPerCpuHashMap::new();

#[btf_map]
pub static PKT_SCRATCH_KEY: PerCpuArray<ParsedPacket, 1> = PerCpuArray::new();

#[btf_map]
pub static CONNTRACK_ARGS_MAP: PerCpuArray<crate::contrack::ConntrackArgs, 1> = PerCpuArray::new();

#[btf_map]
pub static PARSE_CTX_MAP: PerCpuArray<ParseTransportCtx, 1> = PerCpuArray::new();

#[btf_map]
pub static UDP_DECISION_SCRATCH_MAP: PerCpuArray<UdpDecisionScratch, 1> = PerCpuArray::new();

#[btf_map]
pub static CONNTRACK_SNAPSHOT_MAP: PerCpuArray<ConnState, 1> = PerCpuArray::new();
