use aya_ebpf::Global;
use aya_ebpf::bindings::__be32;
use aya_ebpf::btf_maps::{Array, HashMap, LpmTrie, PerCpuArray, RingBuf, SockMap};
use aya_ebpf::macros::btf_map;
use honk_ebpf_common::conn::{
    BpfStatsKey, ConnState, ConntrackArgs, MAX_CONN_STATE_NUM, ParseTransportCtx,
    UdpDecisionSequence,
};
use honk_ebpf_common::event::DaeEvent;
use honk_ebpf_common::redirect_need::{
    DomainRouting, MAX_MATCH_SET_LEN, PIDName, RoutingHandoffEntry, TuplesKey,
};
use honk_ebpf_common::route::{
    MatchSet, ROUTING_GROUP_META_MAP_LEN, ROUTING_META_MAP_LEN, RoutingGroupMeta,
};
use honk_ebpf_common::{DaeParam, ROUTING_MAP_LEN, RedirectEntry, RedirectTuple};

use crate::route::{RouteCtx, WanEgressRouteScratch};
use crate::transport::ParsedPacket;

/// LPM tries allocate entries on demand; the shared limit preserves large
/// GeoIP sets without reserving their maximum capacity at map creation.
pub const MAX_LPM_SIZE: usize = honk_ebpf_common::MAX_LPM_SIZE as usize;
pub const MAX_ROUTING_HANDOFF_NUM: usize = 65536;
pub const MAX_LPM_NUM: usize = MAX_MATCH_SET_LEN + 8;
pub const MAX_COOKIE_PID_PNAME_MAPPING_NUM: usize = 65536;
pub const MAX_DOMAIN_ROUTING_NUM: usize = 65536;

#[repr(C)]
pub struct UdpDecisionScratch {
    pub redirect_key: RedirectTuple,
    pub redirect: RedirectEntry,
    pub handoff: RoutingHandoffEntry,
    pub state: ConnState,
}

// Global variable: corresponds to the C `const volatile struct dae_param PARAM = {};`.
#[unsafe(no_mangle)]
pub static PARAM: Global<DaeParam> = Global::new(DaeParam {
    tproxy_port: 0,
    control_plane_pid: 0,
    dae0_ifindex: 0,
    dae_netns_id: 0,
    wan_ifindex: 0,
    dae0peer_mac: [0; 6],
    padding_after_mac: [0; 2],
    use_redirect_peer: 0,
    has_bpf_get_current_task: 0,
    padding2: 0,
    dae_socket_mark: 0,
    local_ip: 0,
});

/// WAN interface ifindex used by the egress program to identify locally-
/// generated packets that the bonding driver forwards onto the bond master.
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

/// Persistent across process reloads so no live held skb can observe token reuse.
#[btf_map]
pub static UDP_DECISION_SEQUENCE: Array<UdpDecisionSequence, 1, 0> = Array::new();

/// Active grace-period slot for token-bound decision work. Userspace flips
/// this before waiting on the previous per-CPU slot.
#[btf_map]
pub static UDP_DECISION_EPOCH: Array<u32, 1, 0> = Array::new();

/// Per-CPU readers for the two decision grace-period slots.
#[btf_map]
pub static UDP_DECISION_INFLIGHT: PerCpuArray<u32, 2> = PerCpuArray::new();

/// Tuple fence installed by userspace before token-conditioned retirement.
/// New claims and cached followers fail closed while an entry exists.
#[btf_map]
pub static UDP_DECISION_RETIRE_FENCE: HashMap<TuplesKey, u32, 65536, 1> = HashMap::new();

#[inline(always)]
fn try_begin_udp_decision(slot: u32) -> bool {
    let Some(counter) = UDP_DECISION_INFLIGHT.get_ptr_mut(slot) else {
        return false;
    };
    unsafe {
        *counter = (*counter).wrapping_add(1);
    }
    if UDP_DECISION_EPOCH
        .get(0)
        .is_some_and(|epoch| *epoch & 1 == slot)
    {
        return true;
    }
    unsafe {
        *counter = (*counter).wrapping_sub(1);
    }
    false
}

#[inline(always)]
pub fn begin_udp_decision() -> Option<u32> {
    let first = UDP_DECISION_EPOCH.get(0).map_or(0, |epoch| *epoch & 1);
    if try_begin_udp_decision(first) {
        return Some(first);
    }
    let second = UDP_DECISION_EPOCH.get(0).map_or(0, |epoch| *epoch & 1);
    if try_begin_udp_decision(second) {
        return Some(second);
    }
    None
}

#[inline(always)]
pub fn end_udp_decision(slot: u32) {
    if let Some(counter) = UDP_DECISION_INFLIGHT.get_ptr_mut(slot & 1) {
        unsafe {
            *counter = (*counter).wrapping_sub(1);
        }
    }
}

#[inline(always)]
pub fn udp_decision_retiring(key: &TuplesKey) -> bool {
    unsafe { UDP_DECISION_RETIRE_FENCE.get(key).is_some() }
}

#[btf_map]
/// Plain hash with BPF_F_NO_PREALLOC: kernel memory scales with live
/// entries instead of locking max_entries up front (~8 MB empty instead of
/// ~8 MB per 64K capacity).  Eviction is owned by the userspace janitor
/// (state-based timeouts), never by silent kernel LRU eviction — an evicted
/// entry here breaks reply rewriting for live flows.
pub static REDIRECT_TRACK: HashMap<RedirectTuple, RedirectEntry, 65536, 1> = HashMap::new();

#[btf_map]
/// Plain hash with BPF_F_NO_PREALLOC: swept by the userspace janitor (30 s
/// timeout).
pub static ROUTING_HANDOFF_MAP: HashMap<
    TuplesKey,
    RoutingHandoffEntry,
    MAX_ROUTING_HANDOFF_NUM,
    1,
> = HashMap::new();

#[btf_map]
/// Two physical rule banks. `ROUTING_META_MAP[0]` selects the active bank;
/// the inactive bank is populated before that single-slot switch.
pub static ROUTING_MAP: Array<MatchSet, ROUTING_MAP_LEN, 0> = Array::new();

/// Routing metadata for the two rule banks. Slot 0 is the active generation;
/// each following block contains one generation's count and group bitmaps.
#[btf_map]
pub static ROUTING_META_MAP: Array<u32, ROUTING_META_MAP_LEN, 0> = Array::new();
/// Packed count and bitmap for each (generation, flow-group) pair.
#[btf_map]
pub static ROUTING_GROUP_META_MAP: Array<RoutingGroupMeta, { ROUTING_GROUP_META_MAP_LEN }, 0> =
    Array::new();
#[btf_map]
pub static DOMAIN_ROUTING_MAP: HashMap<[__be32; 4], DomainRouting, MAX_DOMAIN_ROUTING_NUM, 1> =
    HashMap::new();

#[btf_map]
pub static DEST_LPM_ROUTING_MAP: LpmTrie<[__be32; 4], DomainRouting, MAX_LPM_SIZE, 1> =
    LpmTrie::new();

#[btf_map]
pub static SOURCE_LPM_ROUTING_MAP: LpmTrie<[__be32; 4], DomainRouting, MAX_LPM_SIZE, 1> =
    LpmTrie::new();

#[btf_map]
pub static MAC_LPM_ROUTING_MAP: LpmTrie<[__be32; 4], DomainRouting, MAX_LPM_SIZE, 1> =
    LpmTrie::new();

#[btf_map]
pub static COOKIE_PID_MAP: HashMap<u64, PIDName, MAX_COOKIE_PID_PNAME_MAPPING_NUM, 1> =
    HashMap::new();

// Must be pinned in userspace.
// Plain hash with BPF_F_NO_PREALLOC: kernel memory scales with live entries
// instead of pinning ~84 MB for 512K capacity up front.  The datapath
// expires entries lazily on hit and the userspace janitor sweeps with
// state-based timeouts; the kernel never evicts on its own (silent LRU
// eviction could re-route or break live flows mid-flight).  Inserts under
// kernel memory pressure can fail — the overflow counter + fail-closed
// path covers that.
#[btf_map]
pub static CONN_STATE_MAP: HashMap<TuplesKey, ConnState, { MAX_CONN_STATE_NUM as usize }, 1> =
    HashMap::new();

/// Occupancy gauge for CONN_STATE_MAP (per-CPU to keep the insert path
/// contention-free): slot `OCCUPANCY_INSERTS` counts successful inserts,
/// slot `OCCUPANCY_EBPF_DELETES` counts datapath-side deletes.  Userspace
/// combines these with its own janitor-delete accounting to estimate live
/// occupancy between sweeps.
#[btf_map]
pub static CONN_STATE_OCCUPANCY: PerCpuArray<u64, 2> = PerCpuArray::new();

/// Insert failures: conn UDP/TCP, redirect-track, routing-handoff, cookie-PID.
#[btf_map]
pub static BPF_STATS_MAP: Array<u64, 5> = Array::new();

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

#[btf_map]
pub static PKT_SCRATCH_KEY: PerCpuArray<ParsedPacket, 1> = PerCpuArray::new();

#[btf_map]
pub static ROUTE_CTX_SCRATCH_MAP: PerCpuArray<RouteCtx, 1> = PerCpuArray::new();

#[btf_map]
pub static WAN_EGRESS_ROUTE_SCRATCH_MAP: PerCpuArray<WanEgressRouteScratch, 1> = PerCpuArray::new();

#[btf_map]
pub static CONNTRACK_ARGS_MAP: PerCpuArray<ConntrackArgs, 1> = PerCpuArray::new();

#[btf_map]
pub static PARSE_CTX_MAP: PerCpuArray<ParseTransportCtx, 1> = PerCpuArray::new();

#[btf_map]
pub static UDP_DECISION_SCRATCH_MAP: PerCpuArray<UdpDecisionScratch, 1> = PerCpuArray::new();
