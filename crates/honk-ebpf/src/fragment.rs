//! Later fragments inherit the fate of the first one: the first fragment is
//! the only one carrying ports, so only it can be routed.

use crate::{
    action::{TC_ACT_REDIRECT, TC_ACT_SHOT},
    maps::{FRAG_VERDICT, PKT_SCRATCH_KEY},
    transport::{IPPROTO_UDP, ParsedPacket},
};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use core::mem;
use honk_ebpf_common::conn::{FRAGMENT_VERDICT_TTL_NS, FragmentKey, FragmentVerdict};

#[inline(always)]
fn key(pkt: &ParsedPacket) -> FragmentKey {
    let mut key: FragmentKey = unsafe { mem::zeroed() };
    key.src_ip = pkt.tuples.five.src_ip;
    key.dst_ip = pkt.tuples.five.dst_ip;
    key.id = pkt.frag_id;
    // RFC 8200 reassembles on source, destination and identification alone. A
    // later fragment stops at the Fragment header, so after extension headers
    // its parsed protocol differs from the first fragment's.
    if key.src_ip.is_v4_mapped() {
        key.l4proto = pkt.tuples.five.l4proto;
    }
    key
}

/// True for a non-first fragment of a datagram whose first fragment was
/// redirected or dropped within the TTL.
// #[inline(never)]: its own stack frame keeps the 40-byte key out of the callers' chain,
// which already sits near the 512-byte BPF stack limit.
#[inline(never)]
pub fn condemned(pkt: &ParsedPacket) -> bool {
    FRAG_VERDICT.get_ptr(&key(pkt)).is_some_and(|recorded| {
        let age = unsafe { bpf_ktime_get_ns() }.wrapping_sub(unsafe { (*recorded).ktime_ns });
        age <= FRAGMENT_VERDICT_TTL_NS
    })
}

/// Entry-wrapper hook: remember a first fragment's SHOT or REDIRECT, or forget
/// the old outcome when an accepted datagram reuses its identification.
#[inline(never)]
pub fn record(verdict: i32) -> i32 {
    // The caller clears fragmentation before any pre-parse early exit.
    let Some(pkt) = PKT_SCRATCH_KEY.get_ptr_mut(0) else {
        return verdict;
    };
    let pkt = unsafe { &*pkt };
    if pkt.is_fragmented == 0 {
        return verdict;
    }
    if verdict != TC_ACT_SHOT as i32 && verdict != TC_ACT_REDIRECT as i32 {
        let _ = FRAG_VERDICT.remove(&key(pkt));
        return verdict;
    }
    if pkt.tuples.five.l4proto == IPPROTO_UDP
        && crate::contrack::is_short_lived_udp_traffic(&pkt.tuples.five)
    {
        return verdict;
    }
    let value = FragmentVerdict {
        verdict: verdict as u32,
        padding: 0,
        ktime_ns: unsafe { bpf_ktime_get_ns() },
    };
    let _ = FRAG_VERDICT.insert(&key(pkt), &value, 0);
    verdict
}
