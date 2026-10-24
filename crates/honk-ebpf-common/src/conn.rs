use crate::{RoutingMeta, TASK_COMM_LEN};
use network_types::{
    eth::EthHdr,
    icmp::Icmpv6Hdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

/// Stable tuple-map element; payload snapshots and mutations hold the native lock.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowMapValue<T> {
    pub lock: aya_ebpf_bindings::bindings::bpf_spin_lock,
    pub padding: u32,
    pub value: T,
}

impl<T> FlowMapValue<T> {
    pub const fn new(value: T) -> Self {
        Self {
            lock: aya_ebpf_bindings::bindings::bpf_spin_lock { val: 0 },
            padding: 0,
            value,
        }
    }
}

impl<T: Default> Default for FlowMapValue<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl<T: aya::Pod> aya::Pod for FlowMapValue<T> {}

/// Connection-state payload stored inside [`FlowMapValue`] in CONN_STATE_MAP.
/// Used by both eBPF programs (for conntrack/lifecycle) and userspace janitor
/// (for cleanup).  All fields are repr(C) so the binary layout is identical
/// regardless of compiler or target triple.
///
/// Layout (repr(C), total 72 bytes):
///   offset 0:  is_wan_ingress_direction: u8
///   offset 1:  state: u8 (`TcpState` for TCP, `UdpDecisionState` for UDP)
///   offset 2:  tcp_syn_flags: u16 (ORIGINAL_INTERCEPT eligibility)
///   offset 4:  decision_token: u32 (nonzero only for staged UDP flows)
///   offset 8:  last_seen_ns: u64 (monotonic timestamp from bpf_ktime_get_ns)
///   offset 16: meta: RoutingMeta (cached routing decision)
///   offset 24: mac: [u8; 6] (source MAC)
///   offset 30: padding: [u8; 2]
///   offset 32: pname: [u8; TASK_COMM_LEN] (process name)
///   offset 48: pid: u32
///   offset 52: trace_id: u32 (immutable route witness, independent of decision_token)
///   offset 56: incarnation: u64 (generation-owned identity, independent of UDP tokens)
///   offset 64: tcp_syn_isn: u32 (host-order original sequence, including zero)
///   offset 68: reserved: u32 (always zero)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnState {
    pub is_wan_ingress_direction: u8,
    pub state: u8,
    pub tcp_syn_flags: u16,
    pub decision_token: u32,
    pub last_seen_ns: u64,
    pub meta: RoutingMeta,
    pub mac: [u8; 6],
    pub padding: [u8; 2],
    pub pname: [u8; TASK_COMM_LEN],
    pub pid: u32,
    pub trace_id: u32,
    pub incarnation: u64,
    pub tcp_syn_isn: u32,
    pub reserved: u32,
}

const _CONN_STATE_SIZE: () = assert!(core::mem::size_of::<ConnState>() == 72);
const _CONN_STATE_ALIGN: () = assert!(core::mem::align_of::<ConnState>() == 8);
const _CONN_STATE_DIRECTION_OFFSET: () =
    assert!(core::mem::offset_of!(ConnState, is_wan_ingress_direction) == 0);
const _CONN_STATE_STATE_OFFSET: () = assert!(core::mem::offset_of!(ConnState, state) == 1);
const _: () = assert!(core::mem::offset_of!(ConnState, tcp_syn_flags) == 2);
const _CONN_STATE_TOKEN_OFFSET: () = assert!(core::mem::offset_of!(ConnState, decision_token) == 4);
const _CONN_STATE_LAST_SEEN_OFFSET: () =
    assert!(core::mem::offset_of!(ConnState, last_seen_ns) == 8);
const _CONN_STATE_META_OFFSET: () = assert!(core::mem::offset_of!(ConnState, meta) == 16);
const _CONN_STATE_MAC_OFFSET: () = assert!(core::mem::offset_of!(ConnState, mac) == 24);
const _CONN_STATE_PADDING_OFFSET: () = assert!(core::mem::offset_of!(ConnState, padding) == 30);
const _CONN_STATE_PNAME_OFFSET: () = assert!(core::mem::offset_of!(ConnState, pname) == 32);
const _CONN_STATE_PID_OFFSET: () = assert!(core::mem::offset_of!(ConnState, pid) == 48);
const _: () = assert!(core::mem::offset_of!(ConnState, trace_id) == 52);
const _: () = assert!(core::mem::offset_of!(ConnState, incarnation) == 56);
const _: () = assert!(core::mem::offset_of!(ConnState, tcp_syn_isn) == 64);
const _: () = assert!(core::mem::offset_of!(ConnState, reserved) == 68);

/// The original forward SYN committed both handoff and redirect before delivery.
/// Native/direct and failed/incomplete publications never set this eligibility bit.
pub const TCP_SYN_ORIGINAL_INTERCEPT: u16 = 1 << 0;

const _: () = assert!(core::mem::offset_of!(FlowMapValue<ConnState>, lock) == 0);
const _: () = assert!(core::mem::offset_of!(FlowMapValue<ConnState>, value) == 8);
const _: () = assert!(core::mem::size_of::<FlowMapValue<ConnState>>() == 80);
const _: () = assert!(core::mem::size_of::<FlowMapValue<crate::RedirectEntry>>() == 48);
const _: () =
    assert!(core::mem::size_of::<FlowMapValue<crate::redirect_need::RoutingHandoffEntry>>() == 80);

// Matches the C enum bpf_stats_key.
// The C enum's underlying type defaults to int (32-bit); use u32 for compatibility.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfStatsKey {
    UdpConnOverflow = 0,
    TcpConnOverflow = 1,
    RedirectTrackInsertFailure = 2,
    RoutingHandoffInsertFailure = 3,
    SocketIdentityCaptureFailure = 4,
    TcpChildProofStorageFailure = 5,
    TcpPublisherClaimFailure = 6,
    NewFlowRateLimited = 7,
    UdpReverseLearningSuspended = 8,
}

impl BpfStatsKey {
    pub const ALL: [Self; 9] = [
        Self::UdpConnOverflow,
        Self::TcpConnOverflow,
        Self::RedirectTrackInsertFailure,
        Self::RoutingHandoffInsertFailure,
        Self::SocketIdentityCaptureFailure,
        Self::TcpChildProofStorageFailure,
        Self::TcpPublisherClaimFailure,
        Self::NewFlowRateLimited,
        Self::UdpReverseLearningSuspended,
    ];
    pub const COUNT: u32 = Self::ALL.len() as u32;

    pub const fn label(self) -> &'static str {
        match self {
            Self::UdpConnOverflow => "udp_conn_overflow",
            Self::TcpConnOverflow => "tcp_conn_overflow",
            Self::RedirectTrackInsertFailure => "redirect_track_insert_failure",
            Self::RoutingHandoffInsertFailure => "routing_handoff_insert_failure",
            Self::SocketIdentityCaptureFailure => "socket_identity_capture_failure",
            Self::TcpChildProofStorageFailure => "tcp_child_proof_storage_failure",
            Self::TcpPublisherClaimFailure => "tcp_publisher_claim_failure",
            Self::NewFlowRateLimited => "new_flow_rate_limited",
            Self::UdpReverseLearningSuspended => "udp_reverse_learning_suspended",
        }
    }
}

/// New flows (pure SYN, first non-DNS UDP packet, every UDP/53 packet) one LAN
/// source may start per second on each CPU before further attempts are dropped.
pub const NEW_FLOW_LIMIT_PER_CPU_SECOND: u32 = 1024;

/// How long a redirected or blocked first fragment condemns the rest of its datagram.
pub const FRAGMENT_VERDICT_TTL_NS: u64 = 30_000_000_000;

/// Identity of one IP datagram under reassembly; every byte is initialized.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FragmentKey {
    pub src_ip: crate::dae_ip::In6Addr,
    pub dst_ip: crate::dae_ip::In6Addr,
    pub id: u32,
    pub l4proto: u8,
    pub padding: [u8; 3],
}

/// First-fragment outcome that later fragments of the same datagram inherit.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FragmentVerdict {
    pub verdict: u32,
    pub padding: u32,
    pub ktime_ns: u64,
}

const _: () = assert!(core::mem::size_of::<FragmentKey>() == 40);
const _: () = assert!(core::mem::size_of::<FragmentVerdict>() == 16);

/// CONN_STATE_MAP capacity, shared by the eBPF map and userspace pressure gauge.
pub const MAX_CONN_STATE_NUM: u32 = 65536 * 8;

/// Conn-state entry timeouts used by the eBPF datapath and userspace janitor.
/// TCP ACTIVE expiry is a userspace-only backstop for unowned state; the
/// datapath expires only CLOSING state. UDP remains a 120-second backstop.
pub const TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS: u64 = 120_000_000_000; // 120 s
pub const TCP_CONN_STATE_CLOSING_TIMEOUT_NS: u64 = 10_000_000_000; // 10 s
pub const UDP_CONN_STATE_TIMEOUT_NS: u64 = 120_000_000_000; // 120 s backstop

/// Auxiliary tuple-metadata expiry shared by the datapath, retirement and janitor.
pub const ROUTING_HANDOFF_TIMEOUT_NS: u64 = 30_000_000_000;
pub const REDIRECT_TRACK_TIMEOUT_NS: u64 = 120_000_000_000;

/// UDP traffic in either port-53 direction does not own ordinary conn-state.
#[inline(always)]
pub const fn is_stateless_udp_ports(src_port: u16, dst_port: u16) -> bool {
    src_port == 53 || dst_port == 53
}

/// Slots of the `CONN_STATE_OCCUPANCY` per-CPU array: the datapath's
/// cumulative successful inserts / deletes into CONN_STATE_MAP.  Userspace
/// derives the live occupancy estimate as
/// `inserts - ebpf_deletes - janitor_deletes`, recalibrated against the exact
/// count on every janitor sweep.
pub const OCCUPANCY_INSERTS: u32 = 0;
pub const OCCUPANCY_EBPF_DELETES: u32 = 1;

/// Slots of the `AUX_OCCUPANCY` per-CPU array: cumulative successful NOEXIST
/// inserts into REDIRECT_TRACK / ROUTING_HANDOFF_MAP. The datapath never
/// deletes these elements, so userspace derives live occupancy as
/// `inserts - userspace deletes`, including retirement and UDP decision commits.
pub const AUX_OCCUPANCY_REDIRECT_INSERTS: u32 = 0;
pub const AUX_OCCUPANCY_HANDOFF_INSERTS: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub enum TcpState {
    TcpStateActive = 0,
    TcpStateClosing = 1,
}

/// Protocol-specific state stored in [`ConnState::state`] for UDP entries.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpDecisionState {
    None = 0,
    Preparing = 1,
    Pending = 2,
    DirectArmed = 3,
    Proxy = 4,
    Block = 5,
    Aborted = 6,
}

const _UDP_DECISION_STATE_SIZE: () = assert!(core::mem::size_of::<UdpDecisionState>() == 1);
const _UDP_DECISION_STATE_VALUES: () = assert!(
    UdpDecisionState::None as u8 == 0
        && UdpDecisionState::Preparing as u8 == 1
        && UdpDecisionState::Pending as u8 == 2
        && UdpDecisionState::DirectArmed as u8 == 3
        && UdpDecisionState::Proxy as u8 == 4
        && UdpDecisionState::Block as u8 == 5
        && UdpDecisionState::Aborted as u8 == 6
);

/// Persistent allocator value shared by the BPF sequence map and userspace.
/// `next` is the full raw token so older binaries can resume allocation after
/// a rollback; `exhausted` retains their ABI and is set only at the final token.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UdpDecisionSequence {
    pub lock: aya_ebpf_bindings::bindings::bpf_spin_lock,
    pub next: u32,
    pub exhausted: u32,
}

impl Default for UdpDecisionSequence {
    fn default() -> Self {
        Self {
            lock: aya_ebpf_bindings::bindings::bpf_spin_lock { val: 0 },
            next: 0,
            exhausted: 0,
        }
    }
}

const _UDP_DECISION_SEQUENCE_SIZE: () = assert!(core::mem::size_of::<UdpDecisionSequence>() == 12);
const _UDP_DECISION_SEQUENCE_ALIGN: () = assert!(core::mem::align_of::<UdpDecisionSequence>() == 4);
const _UDP_DECISION_SEQUENCE_LOCK_OFFSET: () =
    assert!(core::mem::offset_of!(UdpDecisionSequence, lock) == 0);
const _UDP_DECISION_SEQUENCE_NEXT_OFFSET: () =
    assert!(core::mem::offset_of!(UdpDecisionSequence, next) == 4);
const _UDP_DECISION_SEQUENCE_EXHAUSTED_OFFSET: () =
    assert!(core::mem::offset_of!(UdpDecisionSequence, exhausted) == 8);

/// The SYN skb carrier has 56 bits; never truncate a wider allocation domain.
pub const FLOW_INCARNATION_MAX: u64 = (1 << 56) - 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlowIncarnationSequence {
    pub lock: aya_ebpf_bindings::bindings::bpf_spin_lock,
    pub padding: u32,
    pub next: u64,
}

impl Default for FlowIncarnationSequence {
    fn default() -> Self {
        Self {
            lock: aya_ebpf_bindings::bindings::bpf_spin_lock { val: 0 },
            padding: 0,
            next: 0,
        }
    }
}

const _: () = assert!(core::mem::size_of::<FlowIncarnationSequence>() == 16);
const _: () = assert!(core::mem::align_of::<FlowIncarnationSequence>() == 8);
const _: () = assert!(core::mem::offset_of!(FlowIncarnationSequence, lock) == 0);
const _: () = assert!(core::mem::offset_of!(FlowIncarnationSequence, padding) == 4);
const _: () = assert!(core::mem::offset_of!(FlowIncarnationSequence, next) == 8);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetirementFence {
    pub owner: u64,
    pub decision_token: u32,
    pub padding: u32,
}

const _: () = assert!(core::mem::size_of::<RetirementFence>() == 16);
const _: () = assert!(core::mem::align_of::<RetirementFence>() == 8);
const _: () = assert!(core::mem::offset_of!(RetirementFence, owner) == 0);
const _: () = assert!(core::mem::offset_of!(RetirementFence, decision_token) == 8);
const _: () = assert!(core::mem::offset_of!(RetirementFence, padding) == 12);

#[inline(always)]
pub fn tcp_conn_state_expired(state: &ConnState, elapsed_ns: u64) -> bool {
    state.state == TcpState::TcpStateClosing as u8 && elapsed_ns > TCP_CONN_STATE_CLOSING_TIMEOUT_NS
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ParseTransportCtx {
    pub ethh: EthHdr,         // struct ethhdr
    pub iph: Ipv4Hdr,         // struct ipv4hdr
    pub ipv6h: Ipv6Hdr,       // struct ipv6hdr
    pub icmp6h: Icmpv6Hdr,    // struct icmp6hdr
    pub tcph: TcpHdr,         // struct tcphdr
    pub udph: UdpHdr,         // struct udphdr
    pub ihl: u8,              // IP header length in 4-byte units
    pub l4proto: u8,          // Actual L4 protocol
    pub listener_l4proto: u8, // Listener protocol
    pub is_fragmented: u8,
    pub frag_id: u32, // IPv4 identification or IPv6 fragment identification, host order
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for ConnState {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for UdpDecisionSequence {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FlowIncarnationSequence {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RetirementFence {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FragmentKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for FragmentVerdict {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_active_never_expires() {
        let state = ConnState {
            state: TcpState::TcpStateActive as u8,
            ..Default::default()
        };

        assert!(!tcp_conn_state_expired(&state, u64::MAX));
    }

    #[test]
    fn tcp_closing_uses_strict_timeout() {
        let state = ConnState {
            state: TcpState::TcpStateClosing as u8,
            ..Default::default()
        };

        assert!(!tcp_conn_state_expired(
            &state,
            TCP_CONN_STATE_CLOSING_TIMEOUT_NS
        ));
        assert!(tcp_conn_state_expired(
            &state,
            TCP_CONN_STATE_CLOSING_TIMEOUT_NS + 1
        ));
    }

    #[test]
    fn udp_state_and_token_share_the_conn_state_without_aliasing() {
        let mut state = ConnState {
            state: UdpDecisionState::Pending as u8,
            ..Default::default()
        };
        state.decision_token = 0x7fff_ffff;

        assert_eq!(state.state, UdpDecisionState::Pending as u8);
        assert_eq!(state.decision_token, 0x7fff_ffff);
        assert_eq!(UdpDecisionState::None as u8, TcpState::TcpStateActive as u8);
        assert_eq!(
            UdpDecisionState::Preparing as u8,
            TcpState::TcpStateClosing as u8
        );
    }
}
