use core::mem;

use crate::{RoutingMeta, TASK_COMM_LEN};
use network_types::{
    eth::EthHdr,
    icmp::Icmpv6Hdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

/// Unified connection state stored in CONN_STATE_MAP (hash map).
/// Used by both eBPF programs (for conntrack/lifecycle) and userspace janitor
/// (for cleanup).  All fields are repr(C) so the binary layout is identical
/// regardless of compiler or target triple.
///
/// Layout (repr(C), total 56 bytes):
///   offset 0:  is_wan_ingress_direction: u8
///   offset 1:  state: u8 (`TcpState` for TCP, `UdpDecisionState` for UDP)
///   offset 4:  decision_token: u32 (nonzero only for staged UDP flows)
///   offset 8:  last_seen_ns: u64 (monotonic timestamp from bpf_ktime_get_ns)
///   offset 16: meta: RoutingMeta (cached routing decision)
///   offset 24: mac: [u8; 6] (source MAC)
///   offset 30: padding: [u8; 2]
///   offset 32: pname: [u8; TASK_COMM_LEN] (process name)
///   offset 48: pid: u32
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnState {
    pub is_wan_ingress_direction: u8,
    pub state: u8,
    pub decision_token: u32,
    pub last_seen_ns: u64,
    pub meta: RoutingMeta,
    pub mac: [u8; 6],
    pub padding: [u8; 2],
    pub pname: [u8; TASK_COMM_LEN],
    pub pid: u32,
}

const _CONN_STATE_SIZE: () = assert!(core::mem::size_of::<ConnState>() == 56);
const _CONN_STATE_ALIGN: () = assert!(core::mem::align_of::<ConnState>() == 8);
const _CONN_STATE_DIRECTION_OFFSET: () =
    assert!(core::mem::offset_of!(ConnState, is_wan_ingress_direction) == 0);
const _CONN_STATE_STATE_OFFSET: () = assert!(core::mem::offset_of!(ConnState, state) == 1);
const _CONN_STATE_TOKEN_OFFSET: () = assert!(core::mem::offset_of!(ConnState, decision_token) == 4);
const _CONN_STATE_LAST_SEEN_OFFSET: () =
    assert!(core::mem::offset_of!(ConnState, last_seen_ns) == 8);
const _CONN_STATE_META_OFFSET: () = assert!(core::mem::offset_of!(ConnState, meta) == 16);
const _CONN_STATE_MAC_OFFSET: () = assert!(core::mem::offset_of!(ConnState, mac) == 24);
const _CONN_STATE_PADDING_OFFSET: () = assert!(core::mem::offset_of!(ConnState, padding) == 30);
const _CONN_STATE_PNAME_OFFSET: () = assert!(core::mem::offset_of!(ConnState, pname) == 32);
const _CONN_STATE_PID_OFFSET: () = assert!(core::mem::offset_of!(ConnState, pid) == 48);

// Matches the C enum bpf_stats_key.
// The C enum's underlying type defaults to int (32-bit); use u32 for compatibility.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfStatsKey {
    UdpConnOverflow = 0,
    TcpConnOverflow = 1,
    RedirectTrackInsertFailure = 2,
    RoutingHandoffInsertFailure = 3,
    CookiePidInsertFailure = 4,
}

/// CONN_STATE_MAP capacity, shared by the eBPF map definition and the
/// userspace janitor's pressure gauge.  ~68 MB kernel memory at 524,288
/// entries.
pub const MAX_CONN_STATE_NUM: u32 = 65536 * 8;

/// Conn-state entry timeouts used by the eBPF datapath and userspace janitor.
/// TCP ACTIVE expiry is a userspace-only backstop for unowned state; the
/// datapath expires only CLOSING state. UDP remains a 120-second backstop.
pub const TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS: u64 = 120_000_000_000; // 120 s
pub const TCP_CONN_STATE_CLOSING_TIMEOUT_NS: u64 = 10_000_000_000; // 10 s
pub const UDP_CONN_STATE_TIMEOUT_NS: u64 = 120_000_000_000; // 120 s backstop

/// Slots of the `CONN_STATE_OCCUPANCY` per-CPU array: the datapath's
/// cumulative successful inserts / deletes into CONN_STATE_MAP.  Userspace
/// derives the live occupancy estimate as
/// `inserts - ebpf_deletes - janitor_deletes`, recalibrated against the exact
/// count on every janitor sweep.
pub const OCCUPANCY_INSERTS: u32 = 0;
pub const OCCUPANCY_EBPF_DELETES: u32 = 1;

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
}

const _UDP_DECISION_STATE_SIZE: () = assert!(core::mem::size_of::<UdpDecisionState>() == 1);
const _UDP_DECISION_STATE_VALUES: () = assert!(
    UdpDecisionState::None as u8 == 0
        && UdpDecisionState::Preparing as u8 == 1
        && UdpDecisionState::Pending as u8 == 2
        && UdpDecisionState::DirectArmed as u8 == 3
        && UdpDecisionState::Proxy as u8 == 4
        && UdpDecisionState::Block as u8 == 5
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
    pub pad: u8,              // Alignment padding
}

/// CT_ARGS_HAS_* bit flags.
pub const CT_ARGS_HAS_ROUTING: u8 = 1 << 0;
pub const CT_ARGS_HAS_MAC: u8 = 1 << 1;
pub const CT_ARGS_HAS_PNAME: u8 = 1 << 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConntrackArgs {
    pub flags: u8, // CT_ARGS_HAS_* bit mask
    pub outbound: u8,
    pub must: u8,
    pub dscp: u8,
    pub mark: u32,
    pub pid: u32,
    pub mac: [u8; 6],
    pub padding: [u8; 2],
    pub pname: [u8; TASK_COMM_LEN],
}

impl ConntrackArgs {
    #[inline(always)]
    pub fn has_routing(&self) -> bool {
        (self.flags & CT_ARGS_HAS_ROUTING) != 0
    }

    #[inline(always)]
    pub fn has_mac(&self) -> bool {
        (self.flags & CT_ARGS_HAS_MAC) != 0
    }

    #[inline(always)]
    pub fn has_pname(&self) -> bool {
        (self.flags & CT_ARGS_HAS_PNAME) != 0
    }

    #[inline(always)]
    pub fn set(
        &mut self,
        dscp: u8,
        pid: u32,
        routing: Option<(&u8, &u32, &u8)>,
        mac: Option<&[u8; 6]>,
        pname: Option<&[u8; TASK_COMM_LEN]>,
    ) {
        *self = unsafe { mem::zeroed() };
        self.dscp = dscp;
        self.pid = pid;

        if let Some((outbound, mark, must)) = routing {
            self.flags |= CT_ARGS_HAS_ROUTING;
            self.outbound = *outbound;
            self.mark = *mark;
            self.must = *must;
        }

        if let Some(mac_addr) = mac {
            self.flags |= CT_ARGS_HAS_MAC;
            self.mac.copy_from_slice(mac_addr);
        }

        if let Some(pname_bytes) = pname {
            self.flags |= CT_ARGS_HAS_PNAME;
            self.pname.copy_from_slice(pname_bytes);
        }
    }

    #[inline(always)]
    pub fn pname_or_null(&self) -> Option<&[u8; TASK_COMM_LEN]> {
        if self.has_pname() {
            Some(&self.pname)
        } else {
            None
        }
    }
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for ConnState {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for UdpDecisionSequence {}

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
