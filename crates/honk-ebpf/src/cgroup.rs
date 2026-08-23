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

/// Populate a `PIDName` with current process name and TGID.
#[inline(always)]
fn get_pid_pname(pid_pname: &mut PIDName) -> i32 {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    pid_pname.last_seen_ns = unsafe { bpf_ktime_get_ns() };
    pid_pname.pid = (pid_tgid >> 32) as u32;

    if !crate::process_name::read_argv0_basename(&mut pid_pname.pname) {
        let ret = unsafe {
            bpf_get_current_comm(
                pid_pname.pname.as_mut_ptr() as *mut aya_ebpf_cty::c_void,
                pid_pname.pname.len() as u32,
            )
        };
        if ret != 0 {
            pid_pname.pname[0] = 0;
        }
    }
    0
}

/// Create or update cookie-to-pid mapping.
#[inline(always)]
fn update_map_elem_by_cookie(cookie: u64) -> i32 {
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

    let mut val: PIDName = unsafe { mem::zeroed() };
    let ret = get_pid_pname(&mut val);

    if ret != 0 {
        return ret;
    }

    match COOKIE_PID_MAP.insert(cookie, val, 0u64) {
        Ok(_) => {
            info!((), target: "honk", "setup_mapping: cookie={} pid={}", cookie, val.pid);
            0
        }
        Err(_) => {
            // Fallback: only write pid to avoid loop due to dae packets
            let mut fallback: PIDName = unsafe { mem::zeroed() };
            fallback.last_seen_ns = unsafe { bpf_ktime_get_ns() };
            fallback.pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;
            if COOKIE_PID_MAP.insert(cookie, fallback, 0u64).is_err() {
                increment_bpf_stat(BpfStatsKey::CookiePidInsertFailure);
            }
            -1
        }
    }
}

#[cgroup_sock(sock_create)]
pub fn tproxy_wan_cg_sock_create(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie(cookie);
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
    update_map_elem_by_cookie(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock_addr(connect6)]
pub fn tproxy_wan_cg_connect6(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock_addr(sendmsg4)]
pub fn tproxy_wan_cg_sendmsg4(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie(cookie);
    CGROUP_ALLOW
}

#[cgroup_sock_addr(sendmsg6)]
pub fn tproxy_wan_cg_sendmsg6(ctx: SockAddrContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut aya_ebpf_cty::c_void) };
    update_map_elem_by_cookie(cookie);
    CGROUP_ALLOW
}
