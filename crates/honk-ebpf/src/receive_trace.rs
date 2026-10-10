//! Candidate skb metadata becomes evidence only at successful outer recvmsg exit.

use aya_ebpf::{
    Global,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{fentry, fexit, map},
    maps::HashMap,
    programs::{FEntryContext, FExitContext},
};
use honk_ebpf_common::receive_trace::{
    RECEIVE_TRACE_BATCH_SIZE, RECEIVE_TRACE_SOCKETS, RECEIVE_TRACE_VALID, ReceiveTraceBatch,
};

#[unsafe(no_mangle)]
pub static RECEIVE_SOCK_COOKIE_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
pub static RECEIVE_SKB_PRIORITY_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
pub static RECEIVE_SKB_MARK_OFFSET: Global<u32> = Global::new(0);
#[unsafe(no_mangle)]
pub static RECEIVE_OWNER_TGID: Global<u32> = Global::new(0);

#[map]
pub static RECEIVE_TRACE: HashMap<u64, ReceiveTraceBatch> =
    HashMap::with_max_entries(RECEIVE_TRACE_SOCKETS, 0);

#[inline(always)]
fn state(sk: *const u8) -> Option<*mut ReceiveTraceBatch> {
    // The hooks run for every UDP receive on the host.
    if sk.is_null() || (bpf_get_current_pid_tgid() >> 32) as u32 != RECEIVE_OWNER_TGID.load() {
        return None;
    }
    let cookie = unsafe {
        bpf_probe_read_kernel::<u64>(sk.add(RECEIVE_SOCK_COOKIE_OFFSET.load() as usize).cast())
    }
    .ok()?;
    if cookie == 0 {
        return None;
    }
    let state = RECEIVE_TRACE.get_ptr_mut(&cookie)?;
    (unsafe { (*state).active } != 0).then_some(state)
}

#[inline(always)]
fn enter(sk: *const u8, flags: i32) {
    let Some(ptr) = state(sk) else { return };
    let batch = unsafe { &mut *ptr };
    let owner = bpf_get_current_pid_tgid();
    if batch.depth != 0 {
        batch.lost = 1;
        batch.depth = batch.depth.saturating_add(1);
        return;
    }
    batch.owner = owner;
    batch.depth = 1;
    batch.candidate.valid = 0;
    // PEEK and ERRQUEUE are never data-consumption witnesses.
    if flags & (0x2 | 0x2000) != 0 {
        batch.lost = 1;
    }
}

#[inline(always)]
fn exit(sk: *const u8, result: Result<i32, i32>) {
    let Some(ptr) = state(sk) else { return };
    let batch = unsafe { &mut *ptr };
    if batch.depth == 0 || batch.owner != bpf_get_current_pid_tgid() {
        batch.lost = 1;
        return;
    }
    batch.depth -= 1;
    if batch.depth != 0 {
        return;
    }
    let Ok(length) = result else {
        batch.lost = 1;
        return;
    };
    if length < 0 {
        batch.candidate.valid = 0;
        return;
    }
    let index = batch.count as usize;
    if index >= RECEIVE_TRACE_BATCH_SIZE {
        batch.lost = 1;
        return;
    }
    // Zero bytes is a successfully consumed datagram, not an empty batch.
    batch.candidate.length = length as u32;
    batch.packets[index] = batch.candidate;
    batch.count += 1;
    batch.candidate.valid = 0;
}

#[fentry]
pub fn honk_udp_receive_enter(ctx: FEntryContext) -> u32 {
    enter(ctx.arg(0), ctx.arg(3));
    0
}

#[fentry]
pub fn honk_udp6_receive_enter(ctx: FEntryContext) -> u32 {
    enter(ctx.arg(0), ctx.arg(3));
    0
}

#[fexit]
pub fn honk_udp_receive_exit(ctx: FExitContext) -> u32 {
    exit(ctx.arg(0), ctx.ret());
    0
}

#[fexit]
pub fn honk_udp6_receive_exit(ctx: FExitContext) -> u32 {
    exit(ctx.arg(0), ctx.ret());
    0
}

#[fexit]
pub fn honk_udp_receive_candidate(ctx: FExitContext) -> u32 {
    let Some(ptr) = state(ctx.arg(0)) else {
        return 0;
    };
    let batch = unsafe { &mut *ptr };
    if batch.depth != 1 || batch.owner != bpf_get_current_pid_tgid() {
        batch.lost = 1;
        return 0;
    }
    // A checksum-discarded candidate is overwritten by the next helper return.
    batch.candidate.valid = 0;
    let Ok(skb) = ctx.ret::<*const u8>() else {
        return 0;
    };
    if skb.is_null() || skb as usize >= usize::MAX - 4095 {
        return 0;
    }
    let priority = unsafe {
        bpf_probe_read_kernel::<u32>(skb.add(RECEIVE_SKB_PRIORITY_OFFSET.load() as usize).cast())
    };
    let mark = unsafe {
        bpf_probe_read_kernel::<u32>(skb.add(RECEIVE_SKB_MARK_OFFSET.load() as usize).cast())
    };
    if let (Ok(priority), Ok(mark)) = (priority, mark) {
        batch.candidate.priority = priority;
        batch.candidate.mark = mark;
        batch.candidate.valid = RECEIVE_TRACE_VALID;
    }
    0
}
