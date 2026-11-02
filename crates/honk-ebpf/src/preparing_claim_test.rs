#![cfg(feature = "routing-test")]

//! Controlled admitted claim -> later fence interleavings, not parallel-reader proof.

use aya_ebpf::btf_maps::Array;
use aya_ebpf::macros::btf_map;
use aya_ebpf_bindings::bindings::{__sk_buff, BPF_NOEXIST};
use aya_ebpf_bindings::helpers::{bpf_spin_lock, bpf_spin_unlock};
use aya_ebpf_cty::c_long;
use honk_ebpf_common::TuplesKey;
use honk_ebpf_common::conn::{FlowMapValue, RetirementFence, UdpDecisionState};

use crate::action::{TC_ACT_OK, TC_ACT_SHOT};
use crate::contrack::{
    allocate_flow_incarnation,
    udp::{abort_udp_preparing, claim_udp_preparing, publish_claimed_udp_state},
};
use crate::maps::{
    CONN_STATE_MAP, REDIRECT_TRACK, RETIRE_ACTIVE, RETIRE_FENCE, ROUTING_HANDOFF_MAP,
    UDP_DECISION_SCRATCH_MAP,
};

#[btf_map]
pub static PREPARING_TEST_KEY: Array<TuplesKey, 1> = Array::new();

// cb[0]: 0 claim only, 1 publish-or-abort, 2 owned abort, 3 foreign token,
// 4 foreign incarnation, 5 newer Preparing owner. cb[1:3] captures the claim.
// Mode1 cb[3] is the exact token-zero owner's terminal state; other modes use
// bit0 exact Aborted token41 owner, bit1 missing handoff, bit2 missing redirect.
// cb[4] is publication success. Auxiliary payloads survive every kernel abort.
#[unsafe(no_mangle)]
#[unsafe(link_section = "classifier")]
pub fn preparing_claim_interleaving_test(ctx: *mut __sk_buff) -> c_long {
    let mode = unsafe { (*ctx).cb[0] };
    let mut zero = 0u32;
    unsafe { core::ptr::write_volatile(&mut zero, 0) };
    let zero = unsafe { core::ptr::read_volatile(&zero) };
    // A merged memset would dereference a modified context pointer.
    unsafe {
        (&raw mut (*ctx).cb[1]).write_volatile(0);
        (&raw mut (*ctx).cb[2]).write_volatile(0);
        (&raw mut (*ctx).cb[3]).write_volatile(0);
        (&raw mut (*ctx).cb[4]).write_volatile(0);
    }
    let Some(key) = PREPARING_TEST_KEY.get(zero) else {
        return TC_ACT_SHOT;
    };
    let Some(incarnation) = claim_udp_preparing(key, &[0x02, 0, 0, 0, 0, 1]) else {
        return TC_ACT_SHOT;
    };
    unsafe {
        (&raw mut (*ctx).cb[1]).write_volatile(incarnation as u32);
        (&raw mut (*ctx).cb[2]).write_volatile((incarnation >> 32) as u32);
    }
    if mode == 0 {
        return TC_ACT_OK;
    }
    let Some(scratch) = UDP_DECISION_SCRATCH_MAP.get_ptr_mut(zero) else {
        return TC_ACT_SHOT;
    };
    let scratch = unsafe { &mut *scratch };
    scratch.state = unsafe { core::mem::zeroed() };
    scratch.state.incarnation = incarnation;
    scratch.state.state = UdpDecisionState::Block as u8;
    scratch.state.last_seen_ns = unsafe { aya_ebpf_bindings::helpers::bpf_ktime_get_ns() };
    if mode >= 2 {
        let aux_incarnation = if mode >= 4 {
            let Some(newer) = allocate_flow_incarnation() else {
                return TC_ACT_SHOT;
            };
            newer
        } else {
            incarnation
        };
        let token = if mode == 3 { 42 } else { 41 };
        scratch.handoff = unsafe { core::mem::zeroed() };
        scratch.handoff.last_seen_ns = 77;
        scratch.handoff.incarnation = aux_incarnation;
        scratch.handoff.result.decision_token = token;
        scratch.redirect = unsafe { core::mem::zeroed() };
        scratch.redirect.last_seen_ns = 99;
        scratch.redirect.incarnation = aux_incarnation;
        scratch.redirect.decision_token = token;
        scratch.redirect_key = honk_ebpf_common::RedirectTuple::from_tuples(key);
        if ROUTING_HANDOFF_MAP
            .insert(key, &FlowMapValue::new(scratch.handoff), BPF_NOEXIST as u64)
            .is_err()
        {
            return TC_ACT_SHOT;
        }
        crate::auxiliary::aux_occupancy_add(honk_ebpf_common::conn::AUX_OCCUPANCY_HANDOFF_INSERTS);
        if REDIRECT_TRACK
            .insert(
                &scratch.redirect_key,
                &FlowMapValue::new(scratch.redirect),
                BPF_NOEXIST as u64,
            )
            .is_err()
        {
            return TC_ACT_SHOT;
        }
        crate::auxiliary::aux_occupancy_add(honk_ebpf_common::conn::AUX_OCCUPANCY_REDIRECT_INSERTS);
        if mode == 5 {
            scratch.state.incarnation = aux_incarnation;
            scratch.state.state = UdpDecisionState::Preparing as u8;
            let Some(ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
                return TC_ACT_SHOT;
            };
            unsafe { bpf_spin_lock(&mut (*ptr).lock) };
            let current = unsafe { &mut (*ptr).value };
            let owned = current.incarnation == incarnation
                && current.state == UdpDecisionState::Preparing as u8
                && current.decision_token == 0;
            if owned {
                unsafe { crate::flow::copy_payload(current, &scratch.state) };
            }
            unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
            if !owned {
                return TC_ACT_SHOT;
            }
            scratch.state.incarnation = incarnation;
            scratch.state.state = UdpDecisionState::Block as u8;
        }
    }
    if RETIRE_FENCE
        .insert(
            key,
            &RetirementFence {
                owner: 901,
                decision_token: 0,
                padding: 0,
            },
            BPF_NOEXIST as u64,
        )
        .is_err()
    {
        return TC_ACT_SHOT;
    }
    let Some(active) = RETIRE_ACTIVE.get_ptr_mut(zero) else {
        return TC_ACT_SHOT;
    };
    unsafe { *active = 1 };
    if mode == 1 || mode == 5 {
        let published = publish_claimed_udp_state(key, &scratch.state);
        unsafe { (*ctx).cb[4] = published as u32 };
        if mode == 1 {
            if !published {
                abort_udp_preparing(key, incarnation, 0);
            }
            if let Some(state) = crate::flow::conn_snapshot(key)
                && state.incarnation == incarnation
                && state.decision_token == 0
            {
                unsafe { (*ctx).cb[3] = state.state as u32 };
            }
        }
    }
    if mode >= 2 {
        abort_udp_preparing(key, incarnation, 41);
        let mut observed = 0;
        if let Some(state) = crate::flow::conn_snapshot(key)
            && state.state == UdpDecisionState::Aborted as u8
            && state.decision_token == 41
            && state.incarnation == incarnation
        {
            observed |= 1;
        }
        if ROUTING_HANDOFF_MAP.get_ptr(key).is_none() {
            observed |= 2;
        }
        if REDIRECT_TRACK.get_ptr(&scratch.redirect_key).is_none() {
            observed |= 4;
        }
        unsafe { (*ctx).cb[3] = observed };
        // Fenced userspace retirement, not this driver, owns physical reclamation.
    }
    TC_ACT_OK
}
