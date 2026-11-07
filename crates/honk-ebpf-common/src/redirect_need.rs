use crate::{TASK_COMM_LEN, dae_ip::In6Addr};

pub const ROUTING_BITMAP_WORDS: usize = crate::ROUTING_FACT_CAPACITY / 32;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RoutingResult {
    pub mark: u32,
    pub must: u8,
    pub mac: [u8; 6],
    pub outbound: u8,
    pub pname: [u8; 16],
    pub pid: u32,
    pub dscp: u8,
    pub padding: [u8; 3],
    pub decision_token: u32,
}

const _ROUTING_RESULT_SIZE: () = assert!(core::mem::size_of::<RoutingResult>() == 40);
const _ROUTING_RESULT_ALIGN: () = assert!(core::mem::align_of::<RoutingResult>() == 4);
const _ROUTING_RESULT_MARK_OFFSET: () = assert!(core::mem::offset_of!(RoutingResult, mark) == 0);
const _ROUTING_RESULT_MUST_OFFSET: () = assert!(core::mem::offset_of!(RoutingResult, must) == 4);
const _ROUTING_RESULT_MAC_OFFSET: () = assert!(core::mem::offset_of!(RoutingResult, mac) == 5);
const _ROUTING_RESULT_OUTBOUND_OFFSET: () =
    assert!(core::mem::offset_of!(RoutingResult, outbound) == 11);
const _ROUTING_RESULT_PNAME_OFFSET: () = assert!(core::mem::offset_of!(RoutingResult, pname) == 12);
const _ROUTING_RESULT_PID_OFFSET: () = assert!(core::mem::offset_of!(RoutingResult, pid) == 28);
const _ROUTING_RESULT_DSCP_OFFSET: () = assert!(core::mem::offset_of!(RoutingResult, dscp) == 32);
const _: () = assert!(core::mem::offset_of!(RoutingResult, padding) == 33);
const _ROUTING_RESULT_TOKEN_OFFSET: () =
    assert!(core::mem::offset_of!(RoutingResult, decision_token) == 36);

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct TuplesKey {
    pub src_ip: In6Addr,
    pub dst_ip: In6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub l4proto: u8,
    pub padding: [u8; 3],
}

const _: () = assert!(core::mem::size_of::<TuplesKey>() == 40);
const _: () = assert!(core::mem::offset_of!(TuplesKey, padding) == 37);

/// Key of a published UDP/53 route mark: the datagram's tuple and DNS
/// transaction ID, so queries queued on one tuple keep their own routes.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct DnsRouteKey {
    pub tuple: TuplesKey,
    pub query_id: u16,
    pub padding: [u8; 6],
}

const _: () = assert!(core::mem::size_of::<DnsRouteKey>() == 48);
const _: () = assert!(core::mem::offset_of!(DnsRouteKey, query_id) == 40);

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Tuples {
    pub five: TuplesKey,
    pub dscp: u8,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RoutingHandoffEntry {
    pub last_seen_ns: u64,
    pub result: RoutingResult,
    pub routing_generation: u64,
    pub trace_id: u32,
    pub trace_padding: u32,
    pub incarnation: u64,
}

const _ROUTING_HANDOFF_ENTRY_SIZE: () = assert!(core::mem::size_of::<RoutingHandoffEntry>() == 72);
const _ROUTING_HANDOFF_ENTRY_ALIGN: () = assert!(core::mem::align_of::<RoutingHandoffEntry>() == 8);
const _ROUTING_HANDOFF_LAST_SEEN_OFFSET: () =
    assert!(core::mem::offset_of!(RoutingHandoffEntry, last_seen_ns) == 0);
const _ROUTING_HANDOFF_RESULT_OFFSET: () =
    assert!(core::mem::offset_of!(RoutingHandoffEntry, result) == 8);
const _ROUTING_HANDOFF_GENERATION_OFFSET: () =
    assert!(core::mem::offset_of!(RoutingHandoffEntry, routing_generation) == 48);
const _ROUTING_HANDOFF_TOKEN_OFFSET: () = assert!(
    core::mem::offset_of!(RoutingHandoffEntry, result)
        + core::mem::offset_of!(RoutingResult, decision_token)
        == 44
);
const _: () = assert!(core::mem::offset_of!(RoutingHandoffEntry, trace_id) == 56);
const _: () = assert!(core::mem::offset_of!(RoutingHandoffEntry, trace_padding) == 60);
const _: () = assert!(core::mem::offset_of!(RoutingHandoffEntry, incarnation) == 64);

pub const TCP_BINDING_CHILD: u32 = 2;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct TcpSocketBinding {
    pub tuples: TuplesKey,
    pub handoff: RoutingHandoffEntry,
    pub kind: u32,
    pub syn_isn: u32,
}

const _: () = assert!(core::mem::size_of::<TcpSocketBinding>() == 120);
const _: () = assert!(core::mem::align_of::<TcpSocketBinding>() == 8);
const _: () = assert!(core::mem::offset_of!(TcpSocketBinding, tuples) == 0);
const _: () = assert!(core::mem::offset_of!(TcpSocketBinding, handoff) == 40);
const _: () = assert!(core::mem::offset_of!(TcpSocketBinding, kind) == 112);
const _: () = assert!(core::mem::offset_of!(TcpSocketBinding, syn_isn) == 116);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct DomainRouting {
    pub bitmap: [u32; ROUTING_BITMAP_WORDS],
}
const _: () = assert!(ROUTING_BITMAP_WORDS == crate::ROUTING_FACT_CAPACITY / 32);
const _: () = assert!(core::mem::size_of::<DomainRouting>() == 32);

/// First-captured process identity retained by the socket's own lifetime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct SocketIdentity {
    pub pid: u32,
    pub pname: [u8; TASK_COMM_LEN],
}
const _: () = assert!(core::mem::size_of::<SocketIdentity>() == 20);
const _: () = assert!(core::mem::align_of::<SocketIdentity>() == 4);
const _: () = assert!(core::mem::offset_of!(SocketIdentity, pid) == 0);
const _: () = assert!(core::mem::offset_of!(SocketIdentity, pname) == 4);

// Field-size sums include explicit padding and recursively checked payloads.
// Integer flags/indices are not Rust enums or bools: every bit pattern is valid.
const _: () = {
    use core::mem::size_of;
    assert!(size_of::<RoutingResult>() == 4 + 1 + 6 + 1 + 16 + 4 + 1 + 3 + 4);
    assert!(size_of::<TuplesKey>() == 16 + 16 + 2 + 2 + 1 + 3);
    assert!(size_of::<RoutingHandoffEntry>() == 8 + size_of::<RoutingResult>() + 8 + 4 + 4 + 8);
    assert!(size_of::<DomainRouting>() == size_of::<[u32; ROUTING_BITMAP_WORDS]>());
    assert!(size_of::<SocketIdentity>() == 4 + TASK_COMM_LEN);
    assert!(
        size_of::<TcpSocketBinding>()
            == size_of::<TuplesKey>() + size_of::<RoutingHandoffEntry>() + 4 + 4
    );
};

// SAFETY: All fields admit arbitrary bits; the sums above rule out implicit
// padding, including inside In6Addr and RoutingResult.
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for TuplesKey {}
// SAFETY: TuplesKey has no implicit padding, and the remainder is explicit.
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for DnsRouteKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RoutingHandoffEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for DomainRouting {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for SocketIdentity {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for TcpSocketBinding {}
