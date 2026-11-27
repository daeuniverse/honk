//! Replayable properties for the `fuzz/` targets and `tests/fuzz_replay.rs`.
//!
//! Both drive only the public `Stack` API against a scripted remote, so a finding reproduces from
//! its input alone and a panic is the failure signal. They assert no panic, bounded output per
//! drain, well-formed and in-MTU output, the whole-stack recount in `Stack::check`, and that
//! closing everything returns every pool charge.

mod packet;
mod schedule;
mod transparent;
mod world;

pub use packet::check as packet;
pub use schedule::check as schedule;
pub use transparent::check as transparent;

fn control_transmit(
    stack: &mut crate::Stack,
    now: std::time::Instant,
    out: &mut [u8],
) -> Option<crate::Transmit> {
    use crate::flow::Flow;
    use crate::wire::{self, tcp};

    let before: Vec<_> = stack
        .table
        .slots
        .iter()
        .enumerate()
        .filter_map(|(idx, slot)| {
            let Some(Flow::Tcp(t)) = &slot.flow else {
                return None;
            };
            let id = crate::FlowId {
                idx: idx as u32,
                generation: slot.generation,
            };
            Some((id, t.snd_nxt, t.tx.len(), stack.tcp_stats(id)))
        })
        .collect();
    let tx = stack.poll_control_transmit(now, out);
    let mut emitted = None;
    if let Some(tx) = &tx {
        assert_eq!((tx.gso, tx.csum), (None, crate::TxCsum::Full));
        let packet = &out[..tx.len];
        let ip = wire::parse_ip(packet).expect("control output is a complete IP packet");
        let l4 = &packet[ip.payload];
        if ip.proto == wire::PROTO_TCP {
            assert!(tcp::verify_checksum(ip.src, ip.dst, l4));
            let (h, off) = tcp::parse(l4).expect("control TCP header");
            assert_eq!(off, l4.len(), "control credit emitted TCP payload");
            assert_ne!(h.flags & (tcp::SYN | tcp::FIN), tcp::SYN | tcp::FIN);
            let end = h
                .seq
                .wrapping_add(u32::from(h.flags & (tcp::SYN | tcp::FIN) != 0));
            emitted = Some((tx.flow, end, h.flags));
        } else {
            assert!(matches!(ip.proto, wire::PROTO_ICMP | wire::PROTO_ICMPV6));
            assert!(wire::icmp::parse(ip.src, ip.dst, l4).is_ok());
        }
    }
    for (id, next, queued, stats) in before {
        let slot = &stack.table.slots[id.idx as usize];
        if slot.generation != id.generation {
            continue;
        }
        let Some(Flow::Tcp(t)) = &slot.flow else {
            continue;
        };
        let mut expected = next;
        let mut fin = false;
        if let Some((Some(owner), end, flags)) = emitted
            && owner == id
        {
            if (end.wrapping_sub(next) as i32) > 0 {
                assert_eq!(
                    end,
                    next.wrapping_add(1),
                    "control advanced bulk sequence space"
                );
                expected = end;
            }
            fin = flags & tcp::FIN != 0;
        }
        assert_eq!(
            t.snd_nxt, expected,
            "control pull changed an unsent payload sequence"
        );
        assert_eq!(t.tx.len(), queued, "control pull consumed queued payload");
        if !fin && let (Some(before), Some(after)) = (stats, stack.tcp_stats(id)) {
            assert_eq!(
                after.tlp_probes, before.tlp_probes,
                "control pull consumed a payload TLP"
            );
        }
    }
    stack.check();
    tx
}

/// Seed inputs for each target, as `(target, bytes)`; the corpus generator writes them out.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let packets = packet::seeds().into_iter().map(|s| ("netstack_packet", s));
    let schedules = schedule::seeds()
        .into_iter()
        .map(|s| ("netstack_schedule", s));
    let transparent = transparent::seeds()
        .into_iter()
        .map(|s| ("netstack_transparent", s));
    packets.chain(schedules).chain(transparent).collect()
}
