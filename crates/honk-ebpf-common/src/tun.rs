//! Private native little-endian TUN producer/read-completion ABI.

use crate::host::HostSourceFacts;

pub const TUN_ABI_MAGIC: u32 = u32::from_le_bytes(*b"HTN1");
pub const TUN_ABI_VERSION: u16 = 1;
pub const TUN_PACKET_CELLS: u32 = 4096;
pub const TUN_PACKET_EXTENT: usize = 192;
pub const TUN_WINDOW_EXTENT: usize = 512;
pub const TUN_OWNER_EXTENT: usize = 256;
pub const TUN_STAMP_MAGIC: u32 = u32::from_le_bytes(*b"HTS1");
pub const TUN_SOURCE_PLAIN: u32 = 0;
pub const TUN_SOURCE_HOST: u32 = 1;
pub const TUN_PACKET_FREE: u64 = 0;
pub const TUN_PACKET_WRITING: u64 = 1;
pub const TUN_PACKET_LIVE: u64 = 2;
pub const TUN_PACKET_CLAIMED: u64 = 3;
pub const TUN_PACKET_RETIRED: u64 = 4;
pub const TUN_PHASE_IDLE: u64 = 0;
pub const TUN_PHASE_ARMED: u64 = 1;
pub const TUN_PHASE_ENTERED: u64 = 2;
pub const TUN_PHASE_COMPLETE: u64 = 3;
pub const TUN_PHASE_CLOSED: u64 = 4;
pub const TUN_WITNESS_OUTER_ENTRY: u64 = 1;
pub const TUN_WITNESS_COPY_ENTRY: u64 = 2;
pub const TUN_WITNESS_COPY_EXIT: u64 = 4;
pub const TUN_WITNESS_OUTER_EXIT: u64 = 8;
pub const TUN_WITNESS_ALL: u64 = 15;
pub const TUN_STATUS_EMPTY: u32 = 0;
pub const TUN_STATUS_COMPLETE_RECORD: u32 = 1;
pub const TUN_STATUS_NO_RECORD: u32 = 2;
pub const TUN_STATUS_INTEGRITY_FAILURE: u32 = 3;
pub const TUN_FATAL_IDENTITY: u64 = 1;
pub const TUN_FATAL_GEOMETRY: u64 = 2;
pub const TUN_FATAL_OWNERSHIP: u64 = 4;
pub const TUN_FATAL_EXHAUSTED: u64 = 8;
pub const TUN_MMAP_FLAG: u32 = 1 << 10;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TunPacketRecordV1 {
    pub state: u64,
    pub packet_id: u64,
    pub owner_epoch: u64,
    pub original_skb_address: u64,
    pub captured_ns: u64,
    pub expires_ns: u64,
    pub attachment: u64,
    pub netns_cookie: u64,
    pub output_ifindex: u32,
    pub original_record_len: u32,
    pub source_kind: u32,
    pub representation_flags: u32,
    pub source: HostSourceFacts,
    pub original_truesize: u32,
    pub original_ingress_ifindex: u32,
    pub claiming_read_id: u64,
    pub reserved: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TunReadWindowV1 {
    pub magic: u32,
    pub version: u16,
    pub extent: u16,
    pub phase: u64,
    pub fatal: u64,
    pub owner_epoch: u64,
    pub attachment: u64,
    pub netns_cookie: u64,
    pub read_id: u64,
    pub requested_extent: u64,
    pub output_ifindex: u32,
    pub reader_tid: u32,
    pub actual_task_address: u64,
    pub actual_leader_start_boottime: u64,
    pub actual_file_address: u64,
    pub actual_tfile_address: u64,
    pub actual_tun_address: u64,
    pub actual_iocb_address: u64,
    pub actual_iter_address: u64,
    pub outer_entry_count: u64,
    pub copy_entry_count: u64,
    pub copy_exit_count: u64,
    pub outer_exit_count: u64,
    pub packet_id: u64,
    pub original_skb_address: u64,
    pub captured_ns: u64,
    pub expires_ns: u64,
    pub packet_cell: u32,
    pub original_record_len: u32,
    pub source_kind: u32,
    pub representation_flags: u32,
    pub copy_offset: i32,
    pub copy_length: u32,
    pub copy_result: i64,
    pub outer_result: i64,
    pub witnesses: u64,
    pub status: u32,
    pub owner_tgid: u32,
    pub source: HostSourceFacts,
    pub acknowledged_read_id: u64,
    pub actual_task_start_boottime: u64,
    pub reserved: [u8; 168],
}

impl Default for TunReadWindowV1 {
    fn default() -> Self {
        // Every field is an integer, byte array or explicit POD source payload.
        let mut value: Self = unsafe { core::mem::zeroed() };
        value.magic = TUN_ABI_MAGIC;
        value.version = TUN_ABI_VERSION;
        value.extent = TUN_WINDOW_EXTENT as u16;
        value
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TunOwnerV1 {
    pub magic: u32,
    pub version: u16,
    pub extent: u16,
    pub gate: u64,
    pub fatal: u64,
    pub owner_epoch: u64,
    pub attachment: u64,
    pub netns_cookie: u64,
    pub next_packet_id: u64,
    pub bound_file_address: u64,
    pub bound_tfile_address: u64,
    pub bound_tun_address: u64,
    pub bound_dev_address: u64,
    pub close_enter: u64,
    pub close_exit: u64,
    pub close_file_address: u64,
    pub close_tfile_address: u64,
    pub close_tun_address: u64,
    pub output_ifindex: u32,
    pub owner_tgid: u32,
    pub vnet_header_size: u32,
    pub tun_flags: u32,
    pub refusal_count: u64,
    pub accepted_count: u64,
    pub retired_count: u64,
    pub close_task_address: u64,
    pub reserved: [u8; 80],
}

impl Default for TunOwnerV1 {
    fn default() -> Self {
        let mut value: Self = unsafe { core::mem::zeroed() };
        value.magic = TUN_ABI_MAGIC;
        value.version = TUN_ABI_VERSION;
        value.extent = TUN_OWNER_EXTENT as u16;
        value.next_packet_id = 1;
        value.vnet_header_size = 10;
        value
    }
}

const _: () = {
    assert!(core::mem::size_of::<TunPacketRecordV1>() == TUN_PACKET_EXTENT);
    assert!(core::mem::size_of::<TunReadWindowV1>() == TUN_WINDOW_EXTENT);
    assert!(core::mem::size_of::<TunOwnerV1>() == TUN_OWNER_EXTENT);
    assert!(core::mem::offset_of!(TunReadWindowV1, source) == 248);
    assert!(core::mem::offset_of!(TunReadWindowV1, acknowledged_read_id) == 328);
    assert!(core::mem::offset_of!(TunOwnerV1, close_enter) == 88);
};

#[cfg(all(not(target_arch = "bpf"), feature = "aya-pod"))]
unsafe impl aya::Pod for TunPacketRecordV1 {}
#[cfg(all(not(target_arch = "bpf"), feature = "aya-pod"))]
unsafe impl aya::Pod for TunReadWindowV1 {}
#[cfg(all(not(target_arch = "bpf"), feature = "aya-pod"))]
unsafe impl aya::Pod for TunOwnerV1 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_close_layouts_are_explicit() {
        assert_eq!(
            core::mem::offset_of!(TunPacketRecordV1, claiming_read_id),
            168
        );
        assert_eq!(
            core::mem::offset_of!(TunReadWindowV1, actual_task_start_boottime),
            336
        );
        assert_eq!(core::mem::offset_of!(TunOwnerV1, reserved), 176);
        assert_eq!(TunOwnerV1::default().next_packet_id, 1);
        assert_eq!(TunReadWindowV1::default().phase, TUN_PHASE_IDLE);
    }
}
