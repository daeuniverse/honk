//! Immutable first-captured process identity, reclaimed with the socket object.

use crate::ctx::raw_skb;
use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::{
    bindings::BPF_SK_STORAGE_GET_F_CREATE,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_sk_storage_get},
};
use core::{ffi::c_void, ptr};
use honk_ebpf_common::{conn::BpfStatsKey, redirect_need::SocketIdentity};

use crate::maps::{SOCKET_IDENTITY, increment_bpf_stat};

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

    let mut identity = SocketIdentity {
        pid: (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32,
        pname: [0; 16],
    };
    if !argv0 || !crate::process_name::read_argv0_basename(&mut identity.pname) {
        let ret = unsafe {
            bpf_get_current_comm(
                identity.pname.as_mut_ptr().cast(),
                identity.pname.len() as u32,
            )
        };
        if ret != 0 {
            increment_bpf_stat(BpfStatsKey::SocketIdentityCaptureFailure);
            return;
        }
    }

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
