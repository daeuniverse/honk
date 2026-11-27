//! Immutable first-captured process identity, reclaimed with the socket object.

use crate::ctx::raw_skb;
use aya_ebpf::programs::{SockAddrContext, SockContext, TcContext};
use aya_ebpf_bindings::{bindings::BPF_SK_STORAGE_GET_F_CREATE, helpers::bpf_sk_storage_get};
use core::{ffi::c_void, ptr};
use honk_ebpf_common::{conn::BpfStatsKey, redirect_need::SocketIdentity};

use crate::maps::{PARAM, SOCKET_IDENTITY, increment_bpf_stat};
use crate::process_name::{MM_ARG_START_OFFSET, TASK_MM_OFFSET};

#[inline(always)]
pub(crate) fn capture_sock(ctx: &SockContext, argv0: bool) {
    unsafe { capture(ctx.sock.cast(), argv0) };
}

#[inline(always)]
pub(crate) fn capture_addr(ctx: &SockAddrContext, argv0: bool) {
    unsafe { capture((*ctx.sock_addr).__bindgen_anon_1.sk.cast(), argv0) };
}

#[inline(always)]
pub(crate) fn capture_connect_addr(ctx: &SockAddrContext, argv0: bool) -> i32 {
    capture_addr(ctx, argv0);
    1
}

/// Retain the first complete identity; a failure is counted, never enforced.
///
/// # Safety
/// `socket` must retain its verifier pointer type: the original cgroup sock
/// context, or the `sk` field loaded directly from a cgroup sock_addr context.
#[inline(always)]
pub(crate) unsafe fn capture(socket: *mut c_void, argv0: bool) {
    // Aya's SkStorage wrapper only accepts SockAddrContext. Keep the static map
    // relocation while using the helper's context-specific socket argument.
    let map = (&raw const SOCKET_IDENTITY).cast_mut().cast();
    if !unsafe { bpf_sk_storage_get(map, socket.cast(), ptr::null_mut(), 0) }.is_null() {
        return;
    }

    let Some(mut identity) = crate::process_name::capture(
        argv0,
        PARAM.load().has_bpf_get_current_task != 0,
        TASK_MM_OFFSET.load(),
        MM_ARG_START_OFFSET.load(),
    ) else {
        increment_bpf_stat(BpfStatsKey::SocketIdentityCaptureFailure);
        return;
    };

    // Publish the entire value at once; never write through the returned pointer.
    let captured = unsafe {
        bpf_sk_storage_get(
            map,
            socket.cast(),
            ptr::from_mut(&mut identity).cast(),
            BPF_SK_STORAGE_GET_F_CREATE.into(),
        )
    };
    if !captured.is_null() {
        return;
    }
    // A concurrent creator can win publication while our CREATE returns null.
    if !unsafe { bpf_sk_storage_get(map, socket.cast(), ptr::null_mut(), 0) }.is_null() {
        return;
    }

    increment_bpf_stat(BpfStatsKey::SocketIdentityCaptureFailure);
}

/// Borrow only the identity of the actual skb socket; never allocate in TC.
#[inline(always)]
pub(crate) fn lookup(ctx: &TcContext) -> Option<&SocketIdentity> {
    let socket = unsafe { (*raw_skb(ctx)).__bindgen_anon_2.sk };
    if socket.is_null() {
        return None;
    }
    let identity = unsafe {
        bpf_sk_storage_get(
            (&raw const SOCKET_IDENTITY).cast_mut().cast(),
            socket.cast(),
            ptr::null_mut(),
            0,
        )
    };
    if identity.is_null() {
        None
    } else {
        // Socket storage remains live during this non-sleepable invocation;
        // capture never mutates it and production has no explicit delete path.
        Some(unsafe { &*identity.cast::<SocketIdentity>() })
    }
}
