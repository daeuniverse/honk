use crate::{TASK_COMM_LEN, dae_ip::In6Addr};

pub const MAX_MATCH_SET_LEN: usize = 128;
pub const ROUTING_BITMAP_WORDS_PER_GENERATION: usize = MAX_MATCH_SET_LEN / 32;
pub const ROUTING_BITMAP_GENERATIONS: usize = 2;
pub const ROUTING_BITMAP_WORDS: usize =
    ROUTING_BITMAP_WORDS_PER_GENERATION * ROUTING_BITMAP_GENERATIONS;

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
}

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
}

const _ROUTING_HANDOFF_ENTRY_SIZE: () = assert!(core::mem::size_of::<RoutingHandoffEntry>() == 48);
const _ROUTING_HANDOFF_ENTRY_ALIGN: () = assert!(core::mem::align_of::<RoutingHandoffEntry>() == 8);
const _ROUTING_HANDOFF_LAST_SEEN_OFFSET: () =
    assert!(core::mem::offset_of!(RoutingHandoffEntry, last_seen_ns) == 0);
const _ROUTING_HANDOFF_RESULT_OFFSET: () =
    assert!(core::mem::offset_of!(RoutingHandoffEntry, result) == 8);
const _ROUTING_HANDOFF_TOKEN_OFFSET: () = assert!(
    core::mem::offset_of!(RoutingHandoffEntry, result)
        + core::mem::offset_of!(RoutingResult, decision_token)
        == 44
);

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct DomainRouting {
    pub bitmap: [u32; ROUTING_BITMAP_WORDS],
}

impl DomainRouting {
    pub fn for_generation(&self, generation: u32) -> Self {
        let mut shifted = Self::default();
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        if offset + ROUTING_BITMAP_WORDS_PER_GENERATION <= shifted.bitmap.len() {
            shifted.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION]
                .copy_from_slice(&self.bitmap[..ROUTING_BITMAP_WORDS_PER_GENERATION]);
        }
        shifted
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PIDName {
    pub last_seen_ns: u64,
    pub pid: u32,
    pub pname: [u8; TASK_COMM_LEN],
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for TuplesKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RoutingHandoffEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for DomainRouting {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for PIDName {}
