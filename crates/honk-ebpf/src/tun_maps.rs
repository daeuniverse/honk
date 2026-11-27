//! TUN owns one socket bank and a bounded packet/read arena, never XDP facts.

use aya_ebpf::{
    Global,
    btf_maps::{Array, PerCpuArray, Queue},
    macros::btf_map,
};
use honk_ebpf_common::{
    host::{HOST_SOCKET_BUCKETS, HostSequence, HostSocketLock, HostSocketPayload},
    tun::{TUN_MMAP_FLAG, TUN_PACKET_CELLS, TunOwnerV1, TunPacketRecordV1, TunReadWindowV1},
};

#[unsafe(no_mangle)]
pub static HOST_SOURCE_NETNS_COOKIE: Global<u64> = Global::new(0);
#[unsafe(no_mangle)]
pub static HOST_HAS_BPF_GET_CURRENT_TASK: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
pub static HOST_SOCKET_COOKIE_OFFSET: Global<u32> = Global::new(0);

#[btf_map]
pub static HOST_SOCKETS: Array<
    HostSocketPayload,
    { HOST_SOCKET_BUCKETS as usize },
    { TUN_MMAP_FLAG as usize },
> = Array::new();
#[btf_map]
pub static HOST_SOCKET_LOCKS: Array<HostSocketLock, { HOST_SOCKET_BUCKETS as usize }> =
    Array::new();
#[btf_map]
pub static HOST_GATE: Array<u32, 1> = Array::new();
#[btf_map]
pub static HOST_SEQUENCE: Array<HostSequence, 1> = Array::new();
#[btf_map]
pub static HOST_IDENTITY_STATS: PerCpuArray<u64, 2> = PerCpuArray::new();
#[btf_map]
pub static TUN_PACKETS: Array<TunPacketRecordV1, { TUN_PACKET_CELLS as usize }> = Array::new();
#[btf_map]
pub static TUN_FREE: Queue<u32, { TUN_PACKET_CELLS as usize }> = Queue::new();
#[btf_map]
pub static TUN_OWNER: Array<TunOwnerV1, 1, { TUN_MMAP_FLAG as usize }> = Array::new();
#[btf_map]
pub static TUN_READ_WINDOW: Array<TunReadWindowV1, 1, { TUN_MMAP_FLAG as usize }> = Array::new();

pub const IDENTITY_CAPTURE_FAILURE: u32 = 0;
pub const IDENTITY_CAPACITY_REFUSAL: u32 = 1;

#[inline(always)]
pub(crate) fn identity_stat(index: u32) {
    if let Some(counter) = HOST_IDENTITY_STATS.get_ptr_mut(index) {
        unsafe { counter.write_volatile(counter.read_volatile().wrapping_add(1)) };
    }
}
