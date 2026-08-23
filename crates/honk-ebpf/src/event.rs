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

/// Ask userspace to resolve a socket's process name when kernel argv access
/// is unavailable. The request keeps the existing DaeEvent ABI: the 64-bit
/// socket cookie occupies the first two `sip` words for this event kind.
#[inline(always)]
pub fn send_pname_resolve(cookie: u64, pid: u32) -> i32 {
    let mut event: DaeEvent = unsafe { core::mem::zeroed() };
    event.timestamp = unsafe { bpf_ktime_get_ns() };
    event.type_ = honk_ebpf_common::event::DaeEventType::PnameResolve as u32;
    event.pid = pid;
    event.sip[0] = cookie as u32;
    event.sip[1] = (cookie >> 32) as u32;
    let _ = unsafe {
        aya_ebpf_bindings::helpers::bpf_get_current_comm(
            event.pname.as_mut_ptr() as *mut aya_ebpf_cty::c_void,
            event.pname.len() as u32,
        )
    };
    EVENT_RINGBUF.output(event, 0).map(|_| 0).unwrap_or(-1)
}
