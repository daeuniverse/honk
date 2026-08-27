//! Cgroup programs for cookie-to-pid mapping.
//! Ported from daed/wing/dae-core/control/kern/tproxy.c.

use crate::log_shim::*;
use aya_ebpf::{
    macros::{cgroup_sock, cgroup_sock_addr},
    programs::{SockAddrContext, SockContext},
};
use aya_ebpf_bindings::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_socket_cookie, bpf_ktime_get_ns,
};
use core::mem;
use honk_ebpf_common::{conn::BpfStatsKey, redirect_need::PIDName};

use crate::{
    contrack::AUXILIARY_MAP_REFRESH_INTERVAL_NS,
    maps::{COOKIE_PID_MAP, increment_bpf_stat},
};

/// Cgroup program verdict: allow the operation.
const CGROUP_ALLOW: i32 = 1;

/// Fill the shared process identity with the current TGID and timestamp.
#[inline(always)]
fn init_pid_name(pid_name: &mut PIDName) {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    pid_name.last_seen_ns = unsafe { bpf_ktime_get_ns() };
    pid_name.pid = (pid_tgid >> 32) as u32;
}

#[inline(always)]
fn fill_thread_comm(pid_name: &mut PIDName) {
    let ret = unsafe {
        bpf_get_current_comm(
            pid_name.pname.as_mut_ptr() as *mut aya_ebpf_cty::c_void,
            pid_name.pname.len() as u32,
        )
    };
    if ret != 0 {
        pid_name.pname[0] = 0;
    }
}

#[inline(always)]
fn insert_with_comm_fallback(cookie: u64, value: PIDName) -> i32 {
    match COOKIE_PID_MAP.insert(cookie, value, 0u64) {
        Ok(_) => 0,
        Err(_) => {
            let mut fallback: PIDName = unsafe { mem::zeroed() };
            init_pid_name(&mut fallback);
            fill_thread_comm(&mut fallback);
            if COOKIE_PID_MAP.insert(cookie, fallback, 0u64).is_err() {
                increment_bpf_stat(BpfStatsKey::CookiePidInsertFailure);
            }
            -1
        }
    }
}

/// Capture argv[0] in the kernel, with thread comm as the local fallback.
#[inline(always)]
fn update_map_elem_by_cookie_argv0(cookie: u64) -> i32 {
    if cookie == 0 {
        return 0;
    }
    if let Some(ptr) = COOKIE_PID_MAP.get_ptr_mut(cookie) {
        let now = unsafe { bpf_ktime_get_ns() };
        let entry = unsafe { &mut *ptr };
        if now.wrapping_sub(entry.last_seen_ns) >= AUXILIARY_MAP_REFRESH_INTERVAL_NS {
            entry.last_seen_ns = now;
        }
        return 0;
    }

    let mut value: PIDName = unsafe { mem::zeroed() };
    init_pid_name(&mut value);
    if !crate::process_name::read_argv0_basename(&mut value.pname) {
        fill_thread_comm(&mut value);
    }
    let ret = insert_with_comm_fallback(cookie, value);
    if ret == 0 {
        info!((), target: "honk", "setup_mapping: cookie={} pid={}", cookie, value.pid);
    }
    ret
}

/// Guaranteed last-resort capture when kernel argv access is unavailable.
#[inline(always)]
fn update_map_elem_by_cookie_comm(cookie: u64) -> i32 {
    if cookie == 0 {
        return 0;
    }
    if let Some(ptr) = COOKIE_PID_MAP.get_ptr_mut(cookie) {
        let now = unsafe { bpf_ktime_get_ns() };
        let entry = unsafe { &mut *ptr };
        if now.wrapping_sub(entry.last_seen_ns) >= AUXILIARY_MAP_REFRESH_INTERVAL_NS {
            entry.last_seen_ns = now;
        }
        return 0;
    }

    let mut value: PIDName = unsafe { mem::zeroed() };
    init_pid_name(&mut value);
    fill_thread_comm(&mut value);
    let ret = insert_with_comm_fallback(cookie, value);
    if ret == 0 {
        info!((), target: "honk", "setup_mapping: cookie={} pid={}", cookie, value.pid);
    }
    ret
}

#[cgroup_sock(sock_create)]
pub fn tproxy_wan_cg_sock_create(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie_argv0(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock(sock_create)]
pub fn tproxy_wan_cg_sock_create_comm(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie_comm(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock(sock_release)]
pub fn tproxy_wan_cg_sock_release(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock as *mut aya_ebpf_cty::c_void) };
    if cookie != 0 {
        let _ = COOKIE_PID_MAP.remove(cookie);
    }
    CGROUP_ALLOW
}

#[cgroup_sock_addr(connect4)]
pub fn tproxy_wan_cg_connect4(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie_argv0(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock_addr(connect4)]
pub fn tproxy_wan_cg_connect4_comm(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie_comm(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock_addr(connect6)]
pub fn tproxy_wan_cg_connect6(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie_argv0(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock_addr(connect6)]
pub fn tproxy_wan_cg_connect6_comm(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie_comm(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock_addr(sendmsg4)]
pub fn tproxy_wan_cg_sendmsg4(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie_argv0(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock_addr(sendmsg4)]
pub fn tproxy_wan_cg_sendmsg4_comm(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie_comm(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock_addr(sendmsg6)]
pub fn tproxy_wan_cg_sendmsg6(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie_argv0(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock_addr(sendmsg6)]
pub fn tproxy_wan_cg_sendmsg6_comm(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie_comm(cookie);
    CGROUP_ALLOW
}
