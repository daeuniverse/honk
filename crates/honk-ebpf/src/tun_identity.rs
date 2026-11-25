//! Socket birth and optional first-successful process identity share one fixed bank.

use aya_ebpf::{
    EbpfContext,
    helpers::bpf_probe_read_kernel,
    macros::lsm,
    programs::{LsmContext, SockAddrContext, SockContext},
};
use aya_ebpf_bindings::helpers::{
    bpf_get_netns_cookie, bpf_get_socket_cookie, bpf_spin_lock, bpf_spin_unlock,
};
use core::{
    ptr,
    sync::atomic::{Ordering, compiler_fence},
};
use honk_ebpf_common::host::{
    HOST_SOCKET_BORN_NEW, HOST_SOCKET_BUCKETS, HOST_SOCKET_PROCESS_PRESENT, HOST_SOCKET_UNSELECTED,
    HOST_SOCKET_WAYS, HostSocketEntry, HostSocketLock, HostSocketPayload,
};

use crate::{
    host_kernel::socket_address,
    host_maps::{
        HOST_GATE, HOST_HAS_BPF_GET_CURRENT_TASK, HOST_SOCKET_COOKIE_OFFSET, HOST_SOCKET_LOCKS,
        HOST_SOCKETS, HOST_SOURCE_NETNS_COOKIE, IDENTITY_CAPACITY_REFUSAL,
        IDENTITY_CAPTURE_FAILURE, identity_stat,
    },
    process_name::{MM_ARG_START_OFFSET, TASK_MM_OFFSET},
};

#[inline(always)]
fn eligible(family: u32, socket_type: u32, protocol: u32) -> bool {
    matches!(family, 2 | 10)
        && ((socket_type == 1 && protocol == 6) || (socket_type == 2 && protocol == 17))
}

#[inline(always)]
fn selected_namespace(ctx: *mut core::ffi::c_void) -> bool {
    let expected = HOST_SOURCE_NETNS_COOKIE.load();
    expected != 0 && unsafe { bpf_get_netns_cookie(ctx) } == expected
}

#[inline(always)]
pub(crate) fn capture_sock(ctx: &SockContext, argv0: bool) {
    let socket = ctx.sock;
    if !unsafe { eligible((*socket).family, (*socket).type_, (*socket).protocol) }
        || !selected_namespace(ctx.as_ptr())
    {
        return;
    }
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let Some(address) = socket_address(socket.cast()) else {
        identity_stat(IDENTITY_CAPTURE_FAILURE);
        return;
    };
    register_birth(cookie, address);
    capture(cookie, address, argv0);
}

#[inline(always)]
pub(crate) fn capture_addr(ctx: &SockAddrContext, argv0: bool) {
    let raw = ctx.sock_addr;
    if !unsafe { eligible((*raw).family, (*raw).type_, (*raw).protocol) }
        || !selected_namespace(ctx.as_ptr())
    {
        return;
    }
    let socket = unsafe { (*raw).__bindgen_anon_1.sk };
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let Some(address) = socket_address(socket.cast()) else {
        identity_stat(IDENTITY_CAPTURE_FAILURE);
        return;
    };
    capture(cookie, address, argv0);
}

#[inline(always)]
pub(crate) fn capture_connect_addr(ctx: &SockAddrContext, argv0: bool) -> i32 {
    capture_addr(ctx, argv0);
    crate::host_connect::admit_connect(ctx)
}

#[inline(always)]
fn bucket(cookie: u64) -> Option<(*mut HostSocketPayload, *mut HostSocketLock, *mut u32)> {
    let key = (cookie & (HOST_SOCKET_BUCKETS as u64 - 1)) as u32;
    Some((
        HOST_SOCKETS.get_ptr_mut(key)?,
        HOST_SOCKET_LOCKS.get_ptr_mut(key)?,
        HOST_GATE.get_ptr_mut(0)?,
    ))
}

/// Inlined POD only: x86-64 ordered stores plus compiler barriers publish odd before data.
/// Caller holds the external lock and closes its prelooked-up gate after unlocking on failure.
#[inline(always)]
pub(crate) unsafe fn begin_write(bucket: *mut HostSocketPayload) -> Option<u64> {
    let version = unsafe { (&raw const (*bucket).version).read_volatile() };
    if version & 1 != 0 || version >= u64::MAX - 1 {
        return None;
    }
    unsafe { (&raw mut (*bucket).version).write_volatile(version + 1) };
    compiler_fence(Ordering::SeqCst);
    Some(version + 2)
}

#[inline(always)]
pub(crate) unsafe fn end_write(bucket: *mut HostSocketPayload, version: u64) {
    compiler_fence(Ordering::SeqCst);
    unsafe { (&raw mut (*bucket).version).write_volatile(version) };
}

// Scan past holes: a later full-key winner must precede any empty-cell choice.
#[inline(always)]
pub(crate) unsafe fn positions(
    bucket: *mut HostSocketPayload,
    cookie: u64,
    address: u64,
) -> (*mut HostSocketEntry, *mut HostSocketEntry) {
    let entries = unsafe { (&raw mut (*bucket).value).cast::<HostSocketEntry>() };
    let mut found = ptr::null_mut();
    let mut empty: *mut HostSocketEntry = ptr::null_mut();
    let mut index = 0;
    while index < HOST_SOCKET_WAYS {
        let entry = unsafe { entries.add(index) };
        let current = unsafe { (&raw const (*entry).cookie).read_volatile() };
        if current == cookie
            && unsafe { (&raw const (*entry).socket_address).read_volatile() } == address
        {
            found = entry;
        } else if current == 0 && empty.is_null() {
            empty = entry;
        }
        index += 1;
    }
    (found, empty)
}

#[inline(always)]
pub(crate) unsafe fn copy_entry(dst: *mut HostSocketEntry, src: *const HostSocketEntry) {
    let dst = dst.cast::<u64>();
    let src = src.cast::<u64>();
    let mut index = 0;
    while index < 8 {
        unsafe {
            dst.add(index)
                .write_volatile(src.add(index).read_volatile())
        };
        index += 1;
    }
}

#[inline(always)]
fn register_birth(cookie: u64, address: u64) {
    if cookie == 0 {
        return;
    }
    let Some((bucket, lock, gate)) = bucket(cookie) else {
        return;
    };
    if unsafe { gate.read_volatile() } != 1 {
        return;
    }
    let born = HostSocketEntry {
        cookie,
        socket_address: address,
        selection: HOST_SOCKET_BORN_NEW,
        ..HostSocketEntry::default()
    };
    let mut exhausted = false;
    unsafe {
        bpf_spin_lock(&raw mut (*lock).lock);
        if gate.read_volatile() == 1 {
            let (entry, empty) = positions(bucket, cookie, address);
            let update = !entry.is_null()
                && (&raw const (*entry).selection).read_volatile() == HOST_SOCKET_UNSELECTED;
            if update || (entry.is_null() && !empty.is_null()) {
                if let Some(version) = begin_write(bucket) {
                    if update {
                        (&raw mut (*entry).selection).write_volatile(HOST_SOCKET_BORN_NEW);
                    } else {
                        copy_entry(empty, &born);
                    }
                    end_write(bucket, version);
                } else {
                    exhausted = true;
                }
            }
        }
        bpf_spin_unlock(&raw mut (*lock).lock);
        if exhausted {
            gate.write_volatile(0);
        }
    }
}

#[inline(always)]
fn capture(cookie: u64, address: u64, argv0: bool) {
    if cookie == 0 {
        identity_stat(IDENTITY_CAPTURE_FAILURE);
        return;
    }
    let Some((bucket, lock, gate)) = bucket(cookie) else {
        identity_stat(IDENTITY_CAPACITY_REFUSAL);
        return;
    };
    let (present, capacity) = unsafe {
        bpf_spin_lock(&raw mut (*lock).lock);
        let (entry, empty) = positions(bucket, cookie, address);
        let present = !entry.is_null()
            && (&raw const (*entry).flags).read_volatile() & HOST_SOCKET_PROCESS_PRESENT != 0;
        bpf_spin_unlock(&raw mut (*lock).lock);
        (present, !entry.is_null() || !empty.is_null())
    };
    if present {
        return;
    }
    if !capacity {
        identity_stat(IDENTITY_CAPACITY_REFUSAL);
        return;
    }

    let Some(identity) = crate::process_name::capture(
        argv0,
        HOST_HAS_BPF_GET_CURRENT_TASK.load() != 0,
        TASK_MM_OFFSET.load(),
        MM_ARG_START_OFFSET.load(),
    ) else {
        identity_stat(IDENTITY_CAPTURE_FAILURE);
        return;
    };
    let captured = HostSocketEntry {
        cookie,
        socket_address: address,
        pid: identity.pid,
        pname: identity.pname,
        flags: HOST_SOCKET_PROCESS_PRESENT,
        operation_incarnation: 0,
        disconnect_generation: 0,
        selection: HOST_SOCKET_UNSELECTED,
        output_ifindex: 0,
        reserved: 0,
    };
    let mut exhausted = false;
    let published = unsafe {
        bpf_spin_lock(&raw mut (*lock).lock);
        let (entry, empty) = positions(bucket, cookie, address);
        let present = !entry.is_null()
            && (&raw const (*entry).flags).read_volatile() & HOST_SOCKET_PROCESS_PRESENT != 0;
        let target = if entry.is_null() { empty } else { entry };
        let published = if present {
            true
        } else if !target.is_null() {
            if let Some(version) = begin_write(bucket) {
                if entry.is_null() {
                    copy_entry(target, &captured);
                } else {
                    let flags = (&raw const (*entry).flags).read_volatile();
                    (&raw mut (*entry).pid).write_volatile(captured.pid);
                    let dst = (&raw mut (*entry).pname).cast::<u32>();
                    let src = (&raw const captured.pname).cast::<u32>();
                    let mut index = 0;
                    while index < 4 {
                        dst.add(index)
                            .write_volatile(src.add(index).read_volatile());
                        index += 1;
                    }
                    (&raw mut (*entry).flags).write_volatile(flags | HOST_SOCKET_PROCESS_PRESENT);
                }
                end_write(bucket, version);
                true
            } else {
                exhausted = true;
                false
            }
        } else {
            false
        };
        bpf_spin_unlock(&raw mut (*lock).lock);
        if exhausted {
            gate.write_volatile(0);
        }
        published
    };
    if !published {
        identity_stat(IDENTITY_CAPACITY_REFUSAL);
    }
}

#[lsm(hook = "sk_free_security")]
pub fn honk_host_sk_free_security(ctx: LsmContext) -> i32 {
    let socket: *const u8 = ctx.arg(0);
    let Some(address) = socket_address(socket.cast()) else {
        return 0;
    };
    let Ok(cookie) = (unsafe {
        bpf_probe_read_kernel::<u64>(
            socket
                .wrapping_add(HOST_SOCKET_COOKIE_OFFSET.load() as usize)
                .cast(),
        )
    }) else {
        return 0;
    };
    if cookie == 0 {
        return 0;
    }
    let Some((bucket, lock, gate)) = bucket(cookie) else {
        return 0;
    };
    let mut exhausted = false;
    unsafe {
        bpf_spin_lock(&raw mut (*lock).lock);
        let (entry, _) = positions(bucket, cookie, address);
        if !entry.is_null() {
            if let Some(version) = begin_write(bucket) {
                let words = entry.cast::<u64>();
                let mut index = 0;
                while index < 8 {
                    words.add(index).write_volatile(0);
                    index += 1;
                }
                end_write(bucket, version);
            } else {
                exhausted = true;
            }
        }
        bpf_spin_unlock(&raw mut (*lock).lock);
        if exhausted {
            gate.write_volatile(0);
        }
    }
    0
}
