//! Fixed Host storage shared by cgroup identity, source TCX and final retirement.

use aya_ebpf::{
    Global,
    btf_maps::{Array, HashMap, PerCpuArray},
    macros::btf_map,
};
use aya_ebpf_bindings::bindings::BPF_F_MMAPABLE;
use honk_ebpf_common::host::{
    HOST_FACT_SLOTS, HOST_SOCKET_BUCKETS, HostFactSlot, HostReturnDevice, HostSequence,
    HostSocketLock, HostSocketPayload,
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
    { BPF_F_MMAPABLE as usize },
> = Array::new();
#[btf_map]
pub static HOST_SOCKET_LOCKS: Array<HostSocketLock, { HOST_SOCKET_BUCKETS as usize }> =
    Array::new();
#[btf_map]
pub static HOST_GATE: Array<u32, 1> = Array::new();
#[btf_map]
pub static HOST_SEQUENCE: Array<HostSequence, 1> = Array::new();
#[btf_map]
pub static HOST_FACTS: Array<HostFactSlot, { HOST_FACT_SLOTS as usize }> = Array::new();
#[btf_map]
pub static HOST_RETURNS: HashMap<u32, HostReturnDevice, 64> = HashMap::new();

pub const IDENTITY_CAPTURE_FAILURE: u32 = 0;
pub const IDENTITY_CAPACITY_REFUSAL: u32 = 1;

#[btf_map]
pub static HOST_IDENTITY_STATS: PerCpuArray<u64, 2> = PerCpuArray::new();

#[inline(always)]
pub(crate) fn identity_stat(index: u32) {
    if let Some(counter) = HOST_IDENTITY_STATS.get_ptr_mut(index) {
        unsafe { counter.write_volatile(counter.read_volatile().wrapping_add(1)) };
    }
}
