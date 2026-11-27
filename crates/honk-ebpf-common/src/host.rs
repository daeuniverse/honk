//! Socket-owned gateway identity and native-endian TUN source facts.

use crate::conn::FlowMapValue;

/// First complete normalized process identity observed on this socket.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostSkIdentity {
    pub pid: u32,
    pub pname_len: u8,
    pub reserved: [u8; 3],
    pub pname: [u8; crate::ROUTING_PROCESS_MAX_LEN],
}

pub const HOST_SK_DIRECT: u32 = 1;
pub const HOST_SK_ENDPOINT: u32 = 2;

/// TCP only. The wire key and kernel disconnect counter identify a connection even
/// when an application reconnects the same socket to the same peer after AF_UNSPEC.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostSkDecision {
    pub key: crate::xdp_gateway::GatewayKey,
    pub binding: u64,
    pub stamp: u64,
    pub disconnects: u32,
    pub isn: u32,
    pub state: u32,
    pub identity_present: u32,
}

// repr(C), fixed-width integers, explicit padding and no invalid bit patterns.
#[cfg(all(not(target_arch = "bpf"), feature = "aya-pod"))]
unsafe impl aya::Pod for HostSkIdentity {}
#[cfg(all(not(target_arch = "bpf"), feature = "aya-pod"))]
unsafe impl aya::Pod for HostSkDecision {}
const _: () = assert!(size_of::<HostSkIdentity>() == 56);
const _: () = assert!(size_of::<HostSkDecision>() == 80);

pub const HOST_SOURCE_LOCAL: u32 = 1;
pub const HOST_PROCESS_PRESENT: u32 = 2;
pub const HOST_SOURCE_FLAGS: u32 = HOST_SOURCE_LOCAL | HOST_PROCESS_PRESENT;
pub const HOST_STAGE_TCX_EGRESS: u16 = 1;
pub const HOST_STAGE_TUN_EGRESS: u16 = 2;
pub const HOST_CAPTURE_HORIZON_NS: u64 = 2_000_000_000;
pub const HOST_ID_MAX: u64 = (1 << 48) - 1;
pub const HOST_SOCKET_BUCKETS: usize = 8192;
pub const HOST_SOCKET_WAYS: usize = 8;
pub const HOST_SOCKET_PROCESS_PRESENT: u32 = 1;
pub const HOST_SOCKET_UNSELECTED: u32 = 0;
pub const HOST_SOCKET_ENDPOINT: u32 = 3;
pub const HOST_SOCKET_BORN_NEW: u32 = 5;
pub const HOST_REPRESENTATION_MATERIALIZED: u32 = 1;
pub const HOST_REPRESENTATION_GSO: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HostSourceFacts {
    pub netns_cookie: u64,
    pub attachment: u64,
    pub socket_cookie: u64,
    pub return_generation: u64,
    pub output_ifindex: u32,
    pub skb_mark: u32,
    pub socket_mark: u32,
    pub pid: u32,
    pub pname: [u8; 16],
    pub flags: u32,
    pub stage: u16,
    pub family: u16,
    /// Frozen socket-executor selection, not a per-connect or per-packet counter.
    pub operation_incarnation: u64,
}

impl HostSourceFacts {
    pub fn is_valid(&self) -> bool {
        self.netns_cookie != 0
            && self.attachment != 0
            && self.socket_cookie != 0
            && self.return_generation != 0
            && self.output_ifindex != 0
            && self.operation_incarnation != 0
            && self.operation_incarnation <= HOST_ID_MAX
            && self.flags & HOST_SOURCE_LOCAL != 0
            && self.flags & !HOST_SOURCE_FLAGS == 0
            && matches!(self.stage, HOST_STAGE_TCX_EGRESS | HOST_STAGE_TUN_EGRESS)
            && matches!(self.family, 2 | 10)
            && (self.flags & HOST_PROCESS_PRESENT != 0 || (self.pid == 0 && self.pname == [0; 16]))
    }
}

/// One stable bucket entry. Socket addresses remain kernel-private cleanup discriminators.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostSocketEntry {
    pub cookie: u64,
    pub socket_address: u64,
    pub pid: u32,
    pub pname: [u8; 16],
    pub flags: u32,
    pub operation_incarnation: u64,
    pub disconnect_generation: u32,
    pub selection: u32,
    pub output_ifindex: u32,
    pub reserved: u32,
}

/// Lock-free mmap payload. Version belongs to the bucket, not any socket occupant.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostSocketPayload {
    pub version: u64,
    pub value: [HostSocketEntry; HOST_SOCKET_WAYS],
}

/// Writer serialization lives outside the filter-readable payload map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostSocketLock {
    pub lock: aya_ebpf_bindings::bindings::bpf_spin_lock,
    pub padding: u32,
}
pub type HostSequence = FlowMapValue<u64>;

// Every shared payload has explicit fields covering its complete C layout.
#[cfg(all(not(target_arch = "bpf"), feature = "aya-pod"))]
unsafe impl aya::Pod for HostSourceFacts {}
#[cfg(all(not(target_arch = "bpf"), feature = "aya-pod"))]
unsafe impl aya::Pod for HostSocketEntry {}
#[cfg(all(not(target_arch = "bpf"), feature = "aya-pod"))]
unsafe impl aya::Pod for HostSocketPayload {}
#[cfg(all(not(target_arch = "bpf"), feature = "aya-pod"))]
unsafe impl aya::Pod for HostSocketLock {}
#[cfg(all(not(target_arch = "bpf"), feature = "aya-pod"))]
unsafe impl aya::Pod for HostSequence {}

const _: () = assert!(core::mem::size_of::<HostSourceFacts>() == 80);
const _: () = assert!(core::mem::offset_of!(HostSourceFacts, pid) == 44);
const _: () = assert!(core::mem::offset_of!(HostSourceFacts, flags) == 64);
const _: () = assert!(core::mem::offset_of!(HostSourceFacts, operation_incarnation) == 72);
const _: () = assert!(core::mem::size_of::<HostSocketEntry>() == 64);
const _: () = assert!(core::mem::size_of::<HostSocketPayload>() == 520);
const _: () = assert!(core::mem::align_of::<HostSocketPayload>() == 8);
const _: () = assert!(core::mem::offset_of!(HostSocketPayload, version) == 0);
const _: () = assert!(core::mem::offset_of!(HostSocketPayload, value) == 8);
const _: () = assert!(core::mem::size_of::<HostSocketLock>() == 8);
const _: () = assert!(core::mem::offset_of!(HostSocketLock, lock) == 0);
const _: () = assert!(core::mem::offset_of!(HostSocketLock, padding) == 4);
const _: () = assert!(core::mem::size_of::<HostSequence>() == 16);
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_facts_require_complete_source_and_process_proof() {
        let mut facts = HostSourceFacts {
            netns_cookie: 11,
            attachment: 12,
            socket_cookie: 13,
            return_generation: 14,
            operation_incarnation: 15,
            output_ifindex: 16,
            flags: HOST_SOURCE_LOCAL,
            stage: HOST_STAGE_TUN_EGRESS,
            family: 2,
            ..Default::default()
        };
        assert!(!HostSourceFacts::default().is_valid());
        assert!(facts.is_valid());
        facts.pid = 42;
        assert!(!facts.is_valid());
        facts.flags |= HOST_PROCESS_PRESENT;
        facts.family = 10;
        assert!(facts.is_valid());
        facts.operation_incarnation = HOST_ID_MAX + 1;
        assert!(!facts.is_valid());
    }
}
