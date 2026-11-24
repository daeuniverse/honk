//! All hooks publish best effort and leave the application's operation alone.

use aya_ebpf::{
    macros::{cgroup_sock, cgroup_sock_addr},
    programs::{SockAddrContext, SockContext},
};
use aya_ebpf_bindings::{
    bindings::{BPF_SK_STORAGE_GET_F_CREATE, bpf_sock},
    helpers::{bpf_loop, bpf_sk_storage_get},
};
use core::{ffi::c_void, ptr};
use honk_ebpf_common::{ROUTING_PROCESS_MAX_LEN, TASK_COMM_LEN, host::HostSkIdentity, routing_policy::ProcessNameNormalizer};
use crate::host_maps::HOST_SK_IDENTITY;

struct NameScan {
    raw: [u8; TASK_COMM_LEN],
    output: [u8; ROUTING_PROCESS_MAX_LEN],
    state: ProcessNameNormalizer,
}

extern "C" fn normalize_step(_: u32, data: *mut c_void) -> i32 {
    let scan = unsafe { &mut *data.cast::<NameScan>() };
    i32::from(!scan.state.advance(&scan.raw, &mut scan.output))
}

#[inline(never)]
fn normalized(raw: [u8; TASK_COMM_LEN], identity: &mut HostSkIdentity) -> bool {
    let mut scan = NameScan { raw, output: [0; ROUTING_PROCESS_MAX_LEN], state: Default::default() };
    if unsafe { bpf_loop(TASK_COMM_LEN as _, normalize_step as *mut _, ptr::from_mut(&mut scan).cast(), 0) } < 0 {
        return false;
    }
    identity.pname = scan.output;
    identity.pname_len = scan.state.normalized_len() as u8;
    identity.pname_len != 0
}

/// Fills identity from the caller of the cgroup socket hook.
///
/// # Safety
/// A non-null output must point to one writable HostSkIdentity for the call.
/// The loader specializes the two immediates within this named BTF function.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn honk_host_name(out: *mut HostSkIdentity) -> i32 {
    if out.is_null() { return 0; }
    // The loader specializes these two MOV64 immediates from running BTF. A
    // disabled argv0 branch is verifier-dead even on kernels denying its helpers.
    let (task_mm, arg_start): (u64, u64);
    unsafe {
        core::arch::asm!(
            "{task} = 0x484f4e31", "{arg} = 0x484f4e32",
            task = out(reg) task_mm, arg = out(reg) arg_start,
            options(nomem, nostack),
        );
    }
    let argv0 = task_mm != u64::MAX;
    let Some(raw) = crate::process_name::capture(argv0, argv0, task_mm as _, arg_start as _) else { return 0 };
    if raw.pid == 0 { return 0; }
    let identity = unsafe { &mut *out };
    identity.pid = raw.pid;
    if normalized(raw.pname, identity) { return 1; }
    if !argv0 { return 0; }
    let Some(comm) = crate::process_name::capture(false, false, 0, 0) else { return 0 };
    i32::from(normalized(comm.pname, identity))
}

#[inline(never)]
fn capture(sk: *mut bpf_sock) {
    let map = (&raw const HOST_SK_IDENTITY).cast_mut().cast();
    if !unsafe { bpf_sk_storage_get(map, sk.cast(), ptr::null_mut(), 0) }.is_null() { return; }
    let mut identity = HostSkIdentity { pid: 0, pname_len: 0, reserved: [0; 3], pname: [0; ROUTING_PROCESS_MAX_LEN] };
    if unsafe { honk_host_name(&mut identity) } == 0 { return; }
    // CREATE publishes an initialized element atomically. Never overwrite a concurrent winner.
    unsafe { bpf_sk_storage_get(map, sk.cast(), ptr::from_mut(&mut identity).cast(), BPF_SK_STORAGE_GET_F_CREATE.into()) };
}

#[cgroup_sock(sock_create)]
pub fn host_create(ctx: SockContext) -> i32 {
    capture(ctx.sock);
    1
}

#[inline(always)]
fn observe_addr(ctx: SockAddrContext) -> i32 {
    let sk = unsafe { (*ctx.sock_addr).__bindgen_anon_1.sk };
    if !sk.is_null() { capture(sk); }
    1
}

#[cgroup_sock_addr(connect4)]
pub fn host_connect4(ctx: SockAddrContext) -> i32 { observe_addr(ctx) }
#[cgroup_sock_addr(connect6)]
pub fn host_connect6(ctx: SockAddrContext) -> i32 { observe_addr(ctx) }
#[cgroup_sock_addr(sendmsg4)]
pub fn host_sendmsg4(ctx: SockAddrContext) -> i32 { observe_addr(ctx) }
#[cgroup_sock_addr(sendmsg6)]
pub fn host_sendmsg6(ctx: SockAddrContext) -> i32 { observe_addr(ctx) }
