use crate::maps::EVENT_RINGBUF;
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
    let mut e: DaeEvent = unsafe { core::mem::zeroed() };

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

    EVENT_RINGBUF.output(e, 0).map(|_| 0).unwrap_or(-1)
}
