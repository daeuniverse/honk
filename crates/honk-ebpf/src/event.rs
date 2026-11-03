//! Direct ring reservations keep event payloads off the bounded TC call-chain stack.

use crate::maps::{EVENT_RINGBUF, FLOW_EXPIRY_HINT, FlowExpiryHint};
use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;
use honk_ebpf_common::event::DaeEvent;

#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn send_dae_event(
    type_: u32,
    pid: u32,
    pname: Option<&[u8; 16]>,
    outbound: u8,
    l4proto: u8,
    sip: Option<&[u32; 4]>,
    dip: Option<&[u32; 4]>,
    sport: u16,
    dport: u16,
) -> i32 {
    let Some(mut reservation) = EVENT_RINGBUF.reserve(0) else {
        return -1;
    };
    let e: &mut DaeEvent = unsafe {
        reservation.as_mut_ptr().write_bytes(0, 1);
        reservation.assume_init_mut()
    };

    e.timestamp = unsafe { bpf_ktime_get_ns() };
    e.type_ = type_;
    e.pid = pid;
    e.outbound = outbound;
    e.l4proto = l4proto;
    e.sport = sport;
    e.dport = dport;

    if let Some(p) = pname {
        e.pname.copy_from_slice(p);
    }
    if let Some(s) = sip {
        e.sip.copy_from_slice(s);
    }
    if let Some(d) = dip {
        e.dip.copy_from_slice(d);
    }

    reservation.submit(0);
    0
}

/// At most one advisory hint per tuple owner per second on each CPU while
/// cached. Physical reclamation always belongs to fenced userspace retirement.
/// Suppression is recorded only once the ring accepted the hint, so a full ring
/// never silences the tuple for the next second.
#[inline(never)]
pub fn send_flow_expired(key: &honk_ebpf_common::redirect_need::TuplesKey, incarnation: u64) {
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(previous) = FLOW_EXPIRY_HINT.get_ptr(key) {
        let previous = unsafe { &*previous };
        if previous.incarnation == incarnation
            && now.saturating_sub(previous.last_hint_ns) < 1_000_000_000
        {
            return;
        }
    }
    let Some(mut reservation) = EVENT_RINGBUF.reserve(0) else {
        return;
    };
    let event: &mut DaeEvent = unsafe {
        reservation.as_mut_ptr().write_bytes(0, 1);
        reservation.assume_init_mut()
    };
    event.timestamp = now;
    event.type_ = honk_ebpf_common::event::DaeEventType::FlowExpired as u32;
    event.incarnation = incarnation;
    event.l4proto = key.l4proto;
    event.sip = unsafe { key.src_ip.u6_addr32 };
    event.dip = unsafe { key.dst_ip.u6_addr32 };
    event.sport = key.src_port;
    event.dport = key.dst_port;
    reservation.submit(0);
    if let Some(previous) = FLOW_EXPIRY_HINT.get_ptr_mut(key) {
        let previous = unsafe { &mut *previous };
        previous.incarnation = incarnation;
        previous.last_hint_ns = now;
    } else {
        let _ = FLOW_EXPIRY_HINT.insert(
            key,
            &FlowExpiryHint {
                incarnation,
                last_hint_ns: now,
            },
            0,
        );
    }
}
