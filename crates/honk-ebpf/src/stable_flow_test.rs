//! Deterministic sequential interleaving of lookup -> production publication -> locked snapshot.
//! This is not a claim about live parallel-reader coverage.

use core::num::NonZeroU64;

use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::{
    bindings::__sk_buff,
    helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock},
};
use aya_ebpf_cty::c_long;
use honk_ebpf_common::{RedirectTuple, TuplesKey};
use network_types::tcp::TcpHdr;

use crate::{
    action::{TC_ACT_OK, TC_ACT_SHOT},
    auxiliary::{publish_handoff, publish_redirect},
    contrack::{
        is_new_tcp_connection,
        tcp::{TcpPublisher, mark_tcp_seen},
    },
    flow::{conn_incarnation, conn_snapshot, copy_payload, handoff_snapshot, redirect_snapshot},
    maps::{
        CONN_STATE_MAP, REDIRECT_TRACK, ROUTING_HANDOFF_MAP, UDP_DECISION_SCRATCH_MAP,
        UdpDecisionScratch,
    },
    preparing_claim_test::PREPARING_TEST_KEY,
    transport::{ETH_HLEN, IPPROTO_TCP},
};

#[inline(always)]
unsafe fn same_payload<T>(left: *const T, right: *const T) -> bool {
    const {
        assert!(core::mem::size_of::<T>() % 8 == 0);
    }
    const {
        assert!(core::mem::align_of::<T>() >= 8);
    }
    let left = left.cast::<u64>();
    let right = right.cast::<u64>();
    let mut i = 0;
    while i < core::mem::size_of::<T>() / 8 {
        if unsafe { left.add(i).read_volatile() != right.add(i).read_volatile() } {
            return false;
        }
        i += 1;
    }
    true
}

// The fixture supplies a canonical key and an ordinary L2 IPv4/IPv6 SYN without
// extension headers. Read only the packet fields needed by the real publisher.
// `Option<u64>` returns in R0/R2, but the verifier keeps only R0 across a BPF-to-BPF call.
#[inline(never)]
fn publish_syn(
    ctx: *mut __sk_buff,
    key: &TuplesKey,
    direction: u32,
    scratch: &mut UdpDecisionScratch,
) -> Option<NonZeroU64> {
    let tc = TcContext::new(ctx);
    let prefix = tc.load::<[u8; 2]>(ETH_HLEN as usize).ok()?;
    let (tcp_offset, dscp) = if prefix[0] >> 4 == 4 && key.src_ip.is_v4_mapped() {
        let ihl = usize::from(prefix[0] & 15) * 4;
        if ihl < 20 || tc.load::<u8>(ETH_HLEN as usize + 9).ok()? != IPPROTO_TCP {
            return None;
        }
        (ETH_HLEN as usize + ihl, prefix[1] >> 2)
    } else if prefix[0] >> 4 == 6 && !key.src_ip.is_v4_mapped() {
        if tc.load::<u8>(ETH_HLEN as usize + 6).ok()? != IPPROTO_TCP {
            return None;
        }
        (
            ETH_HLEN as usize + 40,
            ((prefix[0] & 15) << 2) | (prefix[1] >> 6),
        )
    } else {
        return None;
    };
    let tcp = tc.load::<TcpHdr>(tcp_offset).ok()?;
    if key.l4proto != IPPROTO_TCP
        || !is_new_tcp_connection(&tcp)
        || u16::from_be_bytes(tcp.source) != key.src_port
        || u16::from_be_bytes(tcp.dest) != key.dst_port
    {
        return None;
    }
    let mut publisher = TcpPublisher::new(key);
    if !publisher.acquire_fresh() {
        return None;
    }
    let incarnation = publisher.incarnation;
    // No routing evaluator ran: preserve A's real selected route/framing inputs,
    // but explicitly mark its witness unavailable instead of attributing B to A.
    scratch.handoff.result.dscp = dscp;
    scratch.handoff.trace_id = honk_ebpf_common::ROUTE_TRACE_LOST;
    mark_tcp_seen(
        key,
        &tcp,
        Some(&scratch.handoff.result.outbound),
        Some(&scratch.handoff.result.mark),
        Some(&scratch.handoff.result.must),
        Some(&scratch.handoff.result.mac),
        dscp,
        Some(&scratch.handoff.result.pname),
        scratch.handoff.result.pid,
        scratch.handoff.trace_id,
        &publisher,
    )?;
    unsafe { (&raw mut (*ctx).cb[4]).write_volatile(1) };
    let now = unsafe { bpf_ktime_get_ns() };
    scratch.handoff.incarnation = incarnation;
    scratch.handoff.last_seen_ns = now;
    scratch.handoff.result.decision_token = 0;
    publish_handoff(key, scratch, true).ok()?;
    unsafe { (&raw mut (*ctx).cb[4]).write_volatile(3) };
    scratch.redirect_key = RedirectTuple::from_tuples(key);
    scratch.redirect.incarnation = incarnation;
    scratch.redirect.last_seen_ns = now;
    scratch.redirect.decision_token = 0;
    scratch.redirect.from_wan = direction as u8;
    publish_redirect(key, scratch, true).ok()?;
    if !crate::contrack::tcp::commit_tcp_intercept(key, u32::from_be_bytes(tcp.seq), incarnation) {
        return None;
    }
    unsafe { (&raw mut (*ctx).cb[4]).write_volatile(7) };
    drop(publisher);
    NonZeroU64::new(incarnation)
}

// Input cb[0]: 0 LAN framing, 1 WAN framing. The fixture seeds A with real TC
// first, then supplies a same-key fresh SYN B. Output cb[1:3]: B owner; cb[3]:
// bit0 conn, bit1 handoff, bit2 redirect are byte-exact B through saved pointers.
// cb[4] reports real helper completion: conn1, handoff2, redirect4. No addresses.
#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn stable_flow_element_identity_test(ctx: *mut __sk_buff) -> c_long {
    let direction = unsafe { (*ctx).cb[0] };
    unsafe {
        (&raw mut (*ctx).cb[0]).write_volatile(0);
        (&raw mut (*ctx).cb[1]).write_volatile(0);
        (&raw mut (*ctx).cb[2]).write_volatile(0);
        (&raw mut (*ctx).cb[3]).write_volatile(0);
        (&raw mut (*ctx).cb[4]).write_volatile(0);
    }
    if direction > 1 {
        return TC_ACT_SHOT;
    }
    let mut zero = 0u32;
    unsafe { core::ptr::write_volatile(&mut zero, 0) };
    let zero = unsafe { core::ptr::read_volatile(&zero) };
    let Some(key) = PREPARING_TEST_KEY.get(zero) else {
        return TC_ACT_SHOT;
    };
    let Some(scratch) = UDP_DECISION_SCRATCH_MAP.get_ptr_mut(zero) else {
        return TC_ACT_SHOT;
    };
    let scratch = unsafe { &mut *scratch };
    let redirect_key = RedirectTuple::from_tuples(key);
    let Some(previous) = conn_incarnation(key) else {
        return TC_ACT_SHOT;
    };
    // Capture real A inputs before entering the retained lookup-to-lock window.
    let Some(input_handoff) = ROUTING_HANDOFF_MAP.get_ptr_mut(key) else {
        return TC_ACT_SHOT;
    };
    unsafe {
        bpf_spin_lock(&mut (*input_handoff).lock);
        copy_payload(&mut scratch.handoff, &raw const (*input_handoff).value);
        bpf_spin_unlock(&mut (*input_handoff).lock);
    }
    let Some(input_redirect) = REDIRECT_TRACK.get_ptr_mut(&redirect_key) else {
        return TC_ACT_SHOT;
    };
    unsafe {
        bpf_spin_lock(&mut (*input_redirect).lock);
        copy_payload(&mut scratch.redirect, &raw const (*input_redirect).value);
        bpf_spin_unlock(&mut (*input_redirect).lock);
    }
    if previous == 0
        || scratch.handoff.incarnation != previous
        || scratch.redirect.incarnation != previous
        || scratch.handoff.result.decision_token != 0
        || scratch.redirect.decision_token != 0
    {
        return TC_ACT_SHOT;
    }
    // These actual unlocked pointers must survive the real production writers.
    let Some(conn_ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
        return TC_ACT_SHOT;
    };
    let Some(handoff_ptr) = ROUTING_HANDOFF_MAP.get_ptr_mut(key) else {
        return TC_ACT_SHOT;
    };
    let Some(redirect_ptr) = REDIRECT_TRACK.get_ptr_mut(&redirect_key) else {
        return TC_ACT_SHOT;
    };
    let Some(current) = publish_syn(ctx, key, direction, scratch).map(NonZeroU64::get) else {
        return TC_ACT_SHOT;
    };
    unsafe {
        (&raw mut (*ctx).cb[1]).write_volatile(current as u32);
        (&raw mut (*ctx).cb[2]).write_volatile((current >> 32) as u32);
    }
    if current == previous {
        return TC_ACT_OK;
    }
    unsafe {
        bpf_spin_lock(&mut (*conn_ptr).lock);
        copy_payload(&mut scratch.state, &raw const (*conn_ptr).value);
        bpf_spin_unlock(&mut (*conn_ptr).lock);
        bpf_spin_lock(&mut (*handoff_ptr).lock);
        copy_payload(&mut scratch.handoff, &raw const (*handoff_ptr).value);
        bpf_spin_unlock(&mut (*handoff_ptr).lock);
        bpf_spin_lock(&mut (*redirect_ptr).lock);
        copy_payload(&mut scratch.redirect, &raw const (*redirect_ptr).value);
        bpf_spin_unlock(&mut (*redirect_ptr).lock);
    }
    let mut observed = 0;
    if let Some(value) = conn_snapshot(key)
        && value.incarnation == current
        && value.decision_token == 0
        && unsafe { same_payload(&scratch.state, &value) }
    {
        observed |= 1;
    }
    if let Some(value) = handoff_snapshot(key)
        && value.incarnation == current
        && value.result.decision_token == 0
        && unsafe { same_payload(&scratch.handoff, &value) }
    {
        observed |= 2;
    }
    if let Some(value) = redirect_snapshot(&redirect_key)
        && value.incarnation == current
        && value.decision_token == 0
        && unsafe { same_payload(&scratch.redirect, &value) }
    {
        observed |= 4;
    }
    unsafe { (&raw mut (*ctx).cb[3]).write_volatile(observed) };
    TC_ACT_OK
}
