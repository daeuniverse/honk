//! Locked TCP pre-connect admission and drained-attempt renewal.
//!
//! The owner admits the complete plain-Ethernet prefix before opening HOST_GATE.
//! No timeout, tuple guess, or per-connect replacement of a Host executor is used.

use aya_ebpf::{EbpfContext, Global, helpers::bpf_probe_read_kernel, programs::SockAddrContext};
use aya_ebpf_bindings::helpers::{
    bpf_get_netns_cookie, bpf_get_socket_cookie, bpf_spin_lock, bpf_spin_unlock,
};
use core::ptr;
use honk_ebpf_common::host::{
    HOST_ID_MAX, HOST_SOCKET_BUCKETS, HOST_SOCKET_CANDIDATE, HOST_SOCKET_ENDPOINT,
    HOST_SOCKET_TRANSITION, HostConnectLayout, HostSocketEntry,
};

use crate::{
    host_identity::{begin_write, copy_entry, end_write, lookup, positions},
    host_kernel::socket_address,
    host_maps::{
        HOST_GATE, HOST_SEQUENCE, HOST_SOCKET_LOCKS, HOST_SOCKETS, HOST_SOURCE_NETNS_COOKIE,
    },
};

#[unsafe(no_mangle)]
pub static HOST_CONNECT_LAYOUT: Global<HostConnectLayout> = Global::new(HostConnectLayout {
    valid: 0,
    state: 0,
    lock_owned: 0,
    wmem_alloc: 0,
    refcnt: 0,
    write_queue_len: 0,
    rtx_root: 0,
    send_head: 0,
    backlog_head: 0,
    disconnect_generation: 0,
    socket_mark: 0,
    reserved: 0,
});

#[unsafe(no_mangle)]
pub static HOST_BYPASS_MARK: Global<u32> = Global::new(0);

#[inline(always)]
fn read_at<T: Copy>(address: u64, offset: u32) -> Option<T> {
    let address = address.checked_add(u64::from(offset))?;
    unsafe { bpf_probe_read_kernel(address as *const T) }.ok()
}

#[inline(always)]
fn ready() -> bool {
    HOST_GATE
        .get(0)
        .is_some_and(|gate| unsafe { ptr::read_volatile(gate) } == 1)
}

#[inline(always)]
fn reserve_selection() -> Option<u64> {
    let sequence = HOST_SEQUENCE.get_ptr_mut(0)?;
    let id = unsafe {
        bpf_spin_lock(&raw mut (*sequence).lock);
        let next = (&raw const (*sequence).value).read_volatile();
        let id = if next != 0 && next <= HOST_ID_MAX {
            (&raw mut (*sequence).value).write_volatile(next + 1);
            next
        } else {
            0
        };
        bpf_spin_unlock(&raw mut (*sequence).lock);
        id
    };
    (id != 0).then_some(id)
}

/// The cgroup caller turns zero into its real EPERM refusal before protocol connect.
#[inline(always)]
pub(crate) fn admit_connect(ctx: &SockAddrContext) -> i32 {
    let raw = ctx.sock_addr;
    // UDP connect is not a TCP drain event. Its actual datagram selector owns admission.
    if unsafe { (*raw).protocol != 6 || (*raw).type_ != 1 } {
        return 1;
    }
    let expected_netns = HOST_SOURCE_NETNS_COOKIE.load();
    let netns = unsafe { bpf_get_netns_cookie(ctx.as_ptr()) };
    if expected_netns == 0 || netns == 0 {
        return 0;
    }
    if netns != expected_netns {
        return 1;
    }
    let socket = unsafe { (*raw).__bindgen_anon_1.sk };
    let Some(address) = socket_address(socket.cast()) else {
        return 0;
    };
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    if cookie == 0 {
        return 0;
    }
    let layout = HOST_CONNECT_LAYOUT.load();
    if layout.valid != 1 || layout.reserved != 0 {
        return 0;
    }
    let Some(mark) = read_at::<u32>(address, layout.socket_mark) else {
        return 0;
    };
    let previous = lookup(cookie, address);
    let bypass = HOST_BYPASS_MARK.load();
    if bypass != 0 && mark == bypass {
        return 1;
    }
    if !ready()
        || read_at::<u8>(address, layout.state) != Some(7) // TCP_CLOSE
        || read_at::<u32>(address, layout.lock_owned) != Some(1)
    {
        return 0;
    }
    if previous.is_some_and(|entry| entry.selection == HOST_SOCKET_ENDPOINT) {
        // Endpoint tails can outlive TCP_CLOSE and retain their original source.
        return 1;
    }
    if previous.is_some_and(|entry| entry.selection == HOST_SOCKET_TRANSITION) {
        return 0;
    }
    // TCP's sk_send_head and tcp_rtx_queue are one union, admitted as the same offset.
    if read_at::<u32>(address, layout.write_queue_len) != Some(0)
        || read_at::<u64>(address, layout.rtx_root) != Some(0)
        || read_at::<u64>(address, layout.backlog_head) != Some(0)
    {
        return 0;
    }
    // Ordering is material: the admitted prefix permits W->R, not R->W before TCX.
    // The checked helper calls must remain outside every BPF value lock.
    if read_at::<u32>(address, layout.wmem_alloc) != Some(1) {
        return 0;
    }
    if read_at::<u32>(address, layout.refcnt) != Some(1) {
        return 0;
    }
    let Some(disconnect_generation) = read_at::<u32>(address, layout.disconnect_generation) else {
        return 0;
    };
    let Some(bucket) = HOST_SOCKETS.get_ptr_mut((cookie & (HOST_SOCKET_BUCKETS as u64 - 1)) as u32)
    else {
        return 0;
    };
    let Some(lock) =
        HOST_SOCKET_LOCKS.get_ptr_mut((cookie & (HOST_SOCKET_BUCKETS as u64 - 1)) as u32)
    else {
        return 0;
    };
    let Some(gate) = HOST_GATE.get_ptr_mut(0) else {
        return 0;
    };
    let Some(incarnation) = reserve_selection() else {
        return 0;
    };
    if !ready() {
        return 0;
    }
    let empty_value = HostSocketEntry {
        cookie,
        socket_address: address,
        ..HostSocketEntry::default()
    };
    let mut exhausted = false;
    unsafe {
        bpf_spin_lock(&raw mut (*lock).lock);
        let (found, empty) = positions(bucket, cookie, address);
        let target = if found.is_null() { empty } else { found };
        let unchanged = if found.is_null() {
            previous.is_none()
        } else {
            match previous {
                Some(old) => {
                    (&raw const (*found).selection).read_volatile() == old.selection
                        && (&raw const (*found).operation_incarnation).read_volatile()
                            == old.operation_incarnation
                }
                None => {
                    (&raw const (*found).selection).read_volatile() == 0
                        && (&raw const (*found).operation_incarnation).read_volatile() == 0
                }
            }
        };
        let mut admitted = !target.is_null() && unchanged && gate.read_volatile() == 1;
        if admitted {
            if let Some(version) = begin_write(bucket) {
                if found.is_null() {
                    copy_entry(target, &raw const empty_value);
                }
                (&raw mut (*target).operation_incarnation).write_volatile(incarnation);
                (&raw mut (*target).disconnect_generation).write_volatile(disconnect_generation);
                (&raw mut (*target).output_ifindex).write_volatile(0);
                (&raw mut (*target).selection).write_volatile(HOST_SOCKET_CANDIDATE);
                end_write(bucket, version);
            } else {
                exhausted = true;
                admitted = false;
            }
        }
        bpf_spin_unlock(&raw mut (*lock).lock);
        if exhausted {
            gate.write_volatile(0);
        }
        i32::from(admitted)
    }
}
