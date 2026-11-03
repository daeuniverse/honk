//! UDP conntrack: Preparing claim, publication and abort, decision tokens, and lifecycle refresh.

use super::{
    ConntrackArgs, allocate_flow_incarnation, build_routing_meta, conntrack_output, occupancy_add,
};
use crate::{
    event::{send_dae_event, send_flow_expired},
    maps::{
        BPF_STATS_MAP, CONN_STATE_MAP, CONNTRACK_ARGS_MAP, UDP_DECISION_SEQUENCE, tuple_retiring,
    },
};
use aya_ebpf_bindings::{
    bindings::BPF_NOEXIST,
    helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock},
};
use honk_ebpf_common::{
    NFQUEUE_TOKEN_MASK, RoutingMeta, UDP_DECISION_SEQUENCE_MASK,
    conn::{
        BpfStatsKey, ConnState, FlowMapValue, OCCUPANCY_INSERTS, UDP_CONN_STATE_TIMEOUT_NS,
        UdpDecisionState,
    },
    redirect_need::TuplesKey,
};

/// Lazy-timestamp update interval: only bump `last_seen_ns` when > 1 s elapsed.
const UDP_CONN_STATE_UPDATE_INTERVAL_NS: u64 = 1_000_000_000;

/// Atomically reserve a fresh UDP tuple for this producer, never replacing a hit.
#[inline(always)]
pub fn claim_udp_preparing(key: &TuplesKey, mac: &[u8; 6]) -> Option<u64> {
    if tuple_retiring(key) {
        return None;
    }
    let incarnation = allocate_flow_incarnation()?;
    let mut state: ConnState = unsafe { core::mem::zeroed() };
    state.state = UdpDecisionState::Preparing as u8;
    state.incarnation = incarnation;
    state.last_seen_ns = unsafe { bpf_ktime_get_ns() };
    state.mac.copy_from_slice(mac);

    if CONN_STATE_MAP
        .insert(key, &FlowMapValue::new(state), BPF_NOEXIST as u64)
        .is_ok()
    {
        occupancy_add(OCCUPANCY_INSERTS);
        return Some(incarnation);
    }

    if CONN_STATE_MAP.get_ptr(key).is_none() {
        let stats_key = BpfStatsKey::UdpConnOverflow as u32;
        if let Some(counter) = BPF_STATS_MAP.get_ptr_mut(stats_key) {
            unsafe {
                *counter += 1;
            }
        }
        send_dae_event(
            honk_ebpf_common::event::DaeEventType::UdpConnOverflow as u32,
            0,
            None,
            0,
            key.l4proto,
            Some(unsafe { &key.src_ip.u6_addr32 }),
            Some(unsafe { &key.dst_ip.u6_addr32 }),
            key.src_port,
            key.dst_port,
        );
    }
    None
}

/// Publish only the captured unpublished claim; followers cannot complete it.
#[inline(always)]
pub fn publish_claimed_udp_state(key: &TuplesKey, state: &ConnState) -> bool {
    if tuple_retiring(key) || state.incarnation == 0 {
        return false;
    }
    let Some(ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
        return false;
    };
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let current = unsafe { &mut (*ptr).value };
    let owned = current.state == UdpDecisionState::Preparing as u8
        && current.decision_token == 0
        && current.incarnation == state.incarnation;
    if owned {
        unsafe { crate::flow::copy_payload(current, state) };
    }
    unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
    owned
}

/// An admitted unpublished producer may cancel through a subsequently installed fence.
#[inline(always)]
pub fn abort_udp_preparing(key: &TuplesKey, incarnation: u64, actual_token: u32) {
    if incarnation == 0 {
        return;
    }
    let Some(ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
        return;
    };
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let current = unsafe { &mut (*ptr).value };
    let owned = current.state == UdpDecisionState::Preparing as u8
        && current.decision_token == 0
        && current.incarnation == incarnation;
    if owned {
        current.decision_token = actual_token;
        current.state = UdpDecisionState::Aborted as u8;
    }
    unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
    if owned {
        send_flow_expired(key, incarnation);
    }
}

#[inline(always)]
pub fn populate_udp_conn_state(
    conn: &mut ConnState,
    meta: RoutingMeta,
    mac: &[u8; 6],
    state: UdpDecisionState,
    decision_token: u32,
    incarnation: u64,
) {
    *conn = unsafe { core::mem::zeroed() };
    conn.state = state as u8;
    conn.decision_token = decision_token;
    conn.incarnation = incarnation;
    conn.last_seen_ns = unsafe { bpf_ktime_get_ns() };
    conn.meta = meta;
    conn.mac.copy_from_slice(mac);
}

/// Allocate each generation-tagged mark token once until userspace rotates it.
#[inline(always)]
pub fn allocate_udp_decision_token(key: &TuplesKey) -> Option<u32> {
    let sequence_ptr = UDP_DECISION_SEQUENCE.get_ptr_mut(0)?;
    let sequence = unsafe { &mut *sequence_ptr };
    unsafe {
        bpf_spin_lock(&mut sequence.lock);
    }

    let mut became_exhausted = false;
    let token = if sequence.exhausted != 0
        || sequence.next & UDP_DECISION_SEQUENCE_MASK >= UDP_DECISION_SEQUENCE_MASK
    {
        0
    } else {
        sequence.next += 1;
        became_exhausted = sequence.next & UDP_DECISION_SEQUENCE_MASK == UDP_DECISION_SEQUENCE_MASK;
        if sequence.next == NFQUEUE_TOKEN_MASK {
            sequence.exhausted = 1;
        }
        sequence.next
    };

    unsafe {
        bpf_spin_unlock(&mut sequence.lock);
    }

    if became_exhausted {
        send_dae_event(
            honk_ebpf_common::event::DaeEventType::UdpDecisionTokenExhausted as u32,
            0,
            None,
            0,
            key.l4proto,
            Some(unsafe { &key.src_ip.u6_addr32 }),
            Some(unsafe { &key.dst_ip.u6_addr32 }),
            key.src_port,
            key.dst_port,
        );
    }

    if token == 0 { None } else { Some(token) }
}

/// Unpublished aborts are immediately eligible; other UDP entries retain the age backstop.
#[inline(always)]
fn udp_conn_state_expired(state: &ConnState, now: u64) -> bool {
    state.state == UdpDecisionState::Aborted as u8
        || now.saturating_sub(state.last_seen_ns) > UDP_CONN_STATE_TIMEOUT_NS
}

#[inline(always)]
fn lookup_udp_seen_at(key: &TuplesKey, now: u64) -> Option<&'static mut ConnState> {
    if tuple_retiring(key) {
        return None;
    }
    let output = conntrack_output()?;
    let ptr = CONN_STATE_MAP.get_ptr_mut(key)?;
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let state = unsafe { &mut (*ptr).value };
    let expired = udp_conn_state_expired(state, now);
    // Staging lasts at most three seconds. Freezing these snapshots makes the
    // backend the sole writer between its locked read and in-place activation.
    if !expired
        && state.state != UdpDecisionState::Preparing as u8
        && state.state != UdpDecisionState::Pending as u8
        && state.state != UdpDecisionState::DirectArmed as u8
        && now.saturating_sub(state.last_seen_ns) > UDP_CONN_STATE_UPDATE_INTERVAL_NS
    {
        state.last_seen_ns = now;
    }
    unsafe {
        crate::flow::copy_payload(output, state);
        bpf_spin_unlock(&mut (*ptr).lock);
    }
    if expired {
        send_flow_expired(key, unsafe { (*output).incarnation });
        return None;
    }
    Some(unsafe { &mut *output })
}

/// Look up an existing live UDP entry and lazily refresh its timestamp.
/// Missing or expired entries are never allocated on this path.
#[inline(always)]
pub fn lookup_udp_seen(key: &TuplesKey) -> Option<&'static mut ConnState> {
    lookup_udp_seen_at(key, unsafe { bpf_ktime_get_ns() })
}

/// A live hit already decided expiry and renewal under one lock. A failed
/// lookup may be a fence/expired hit, never permission to replace that owner.
#[inline(always)]
pub(crate) fn lookup_udp_available(key: &TuplesKey) -> Result<Option<&'static mut ConnState>, ()> {
    match lookup_udp_seen(key) {
        Some(state) if state.state == UdpDecisionState::Preparing as u8 => Err(()),
        Some(state) => Ok(Some(state)),
        None if tuple_retiring(key) || CONN_STATE_MAP.get_ptr(key).is_some() => Err(()),
        None => Ok(None),
    }
}

/// Queued decisions keep a userspace-owned clock until their final state is published.
#[inline(always)]
pub fn renew_udp_reply(
    key: &TuplesKey,
    snapshot: &crate::flow::ConnLifecycle,
    redirect: &honk_ebpf_common::RedirectEntry,
    now: u64,
) {
    if redirect.incarnation == 0
        || snapshot.incarnation != redirect.incarnation
        || (snapshot.state != UdpDecisionState::None as u8
            && snapshot.state != UdpDecisionState::Proxy as u8)
        || now.saturating_sub(snapshot.last_seen_ns) < UDP_CONN_STATE_UPDATE_INTERVAL_NS
        || tuple_retiring(key)
    {
        return;
    }
    let Some(ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
        return;
    };
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let current = unsafe { &mut (*ptr).value };
    if current.incarnation == redirect.incarnation
        && current.decision_token == redirect.decision_token
        && current.state == snapshot.state
        && !udp_conn_state_expired(current, now)
        && now.saturating_sub(current.last_seen_ns) >= UDP_CONN_STATE_UPDATE_INTERVAL_NS
    {
        current.last_seen_ns = now;
    }
    unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
}

/// Returns an invocation-local snapshot after publication, never a map payload pointer.
fn __mark_udp_seen(
    key: *const TuplesKey,
    is_wan_ingress_direction: u8,
    args: *const ConntrackArgs,
    routing_meta_flags: u64,
) -> *mut ConnState {
    let key = unsafe { &*key };
    let args = unsafe { &*args };
    let now = unsafe { bpf_ktime_get_ns() };

    if tuple_retiring(key) {
        return core::ptr::null_mut();
    }
    if let Some(state) = lookup_udp_seen_at(key, now) {
        // A cached lifecycle never inherits a competing producer's new route.
        if args.has_routing() {
            return core::ptr::null_mut();
        }
        return state as *mut ConnState;
    }

    // Build the immutable publication in the existing invocation snapshot, not on
    // the WAN classifier's near-limit stack. No map element is touched before claim.
    let Some(output) = conntrack_output() else {
        return core::ptr::null_mut();
    };
    let mac = if args.has_mac() { args.mac } else { [0; 6] };
    let Some(incarnation) = claim_udp_preparing(key, &mac) else {
        return core::ptr::null_mut();
    };
    let has_rt = args.has_routing();

    unsafe { core::ptr::write_bytes(output, 0, 1) };
    let new_state = unsafe { &mut *output };
    new_state.is_wan_ingress_direction = (is_wan_ingress_direction != 0) as u8;
    new_state.state = UdpDecisionState::None as u8;
    new_state.incarnation = incarnation;
    new_state.last_seen_ns = now;
    new_state.pid = args.pid;
    new_state.trace_id = args.trace_id;

    if has_rt {
        new_state.meta = build_routing_meta(args.outbound, args.mark, args.must, args.dscp);
        unsafe { new_state.meta.raw |= routing_meta_flags };
        if args.has_mac() {
            new_state.mac.copy_from_slice(&args.mac);
        }
        if args.has_pname() {
            new_state.pname.copy_from_slice(&args.pname);
        }
    }

    if !publish_claimed_udp_state(key, new_state) {
        abort_udp_preparing(key, incarnation, 0);
        return core::ptr::null_mut();
    }
    output
}

/// Thin inline wrapper: populates the per-CPU `CONNTRACK_ARGS_MAP` scratch
/// and delegates to [`__mark_udp_seen`].
#[inline(always)]
pub fn mark_udp_seen(
    key: &TuplesKey,
    is_wan_ingress_direction: u8,
    outbound: Option<&u8>,
    mark: Option<&u32>,
    must: Option<&u8>,
    mac: Option<&[u8; 6]>,
    dscp: u8,
    pname: Option<&[u8; 16]>,
    pid: u32,
    trace_id: u32,
    routing_meta_flags: u64,
) -> Option<&'static mut ConnState> {
    let zero: u32 = 0;
    let args = unsafe { CONNTRACK_ARGS_MAP.get_ptr_mut(zero).map(|ptr| &mut *ptr)? };

    // Build routing tuple (all three must be present for routing to be set).
    let routing = match (outbound, mark, must) {
        (Some(o), Some(mk), Some(ms)) => Some((o, mk, ms)),
        _ => None,
    };

    args.set(dscp, pid, routing, mac, pname);
    args.trace_id = trace_id;
    let key_ptr: *const TuplesKey = key;
    let args_ptr: *const ConntrackArgs = args;
    let result = __mark_udp_seen(
        key_ptr,
        is_wan_ingress_direction,
        args_ptr,
        routing_meta_flags,
    );
    if result.is_null() {
        None
    } else {
        Some(unsafe { &mut *result })
    }
}

/// Reverse observations cannot claim new conn capacity while the janitor's
/// conn-only pressure latch is set. Existing forward authority stays untouched.
#[inline(always)]
pub fn observe_reverse_udp(key: &TuplesKey) {
    if super::is_short_lived_udp_traffic(key) {
        return;
    }
    if crate::maps::admission_pressure() {
        if lookup_udp_seen(key).is_none() {
            crate::maps::increment_bpf_stat(BpfStatsKey::UdpReverseLearningSuspended);
        }
    } else {
        let _ = mark_udp_seen(key, 1, None, None, None, None, 0, None, 0, 0, 0);
    }
}

/// Established replies decide availability and renewal in one lock. Only a
/// genuine miss reaches learning, and dae0 replies remain lookup-only.
#[inline(always)]
pub fn reverse_udp_available(key: &TuplesKey, learn: bool) -> bool {
    match lookup_udp_available(key) {
        Err(()) => false,
        Ok(Some(_)) => true,
        Ok(None) => {
            if learn {
                observe_reverse_udp(key);
            }
            !super::tuple_unavailable(key)
        }
    }
}

// Keep reversed tuple storage off the LAN classifier's near-limit stack.
#[inline(never)]
pub fn local_udp_reply_seen(key: &TuplesKey) -> bool {
    if super::is_short_lived_udp_traffic(key) {
        return false;
    }
    let mut reversed = TuplesKey::default();
    super::copy_reversed_tuples(key, &mut reversed);
    lookup_udp_seen(&reversed).is_some_and(|state| state.is_wan_ingress_direction != 0)
}

#[inline(never)]
pub fn observe_local_udp_reply(key: &TuplesKey, reversed: &mut TuplesKey) {
    if super::is_short_lived_udp_traffic(key) || !crate::new_flow_limit::try_acquire(&key.src_ip) {
        return;
    }
    super::copy_reversed_tuples(key, reversed);
    observe_reverse_udp(reversed);
}
