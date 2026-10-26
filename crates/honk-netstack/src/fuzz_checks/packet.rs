//! Arbitrary bytes into `Stack::receive` on a stack whose flows sit in different states.

use std::net::IpAddr;
use std::time::Duration;

use super::world::{MAX_PEERS, World};
use crate::wire::{
    PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP,
    checksum::{Checksum, checksum},
    tcp,
};

/// `data` is `[mode, advance, packet..]`. Bit 0 of `mode` feeds `packet` verbatim; otherwise the
/// IP lengths and checksums are repaired first so that the mutation reaches the state machine
/// instead of dying at the first checksum. `advance` is how many 4 ms pass before delivery.
pub fn check(data: &[u8]) {
    let [mode, advance, packet @ ..] = data else {
        return;
    };
    if packet.len() > 2048 {
        return;
    }
    let mut w = populated();
    w.advance(Duration::from_millis(u64::from(*advance) * 4));
    w.drain();
    let mut bytes = packet.to_vec();
    if mode & 1 == 0 {
        repair(&mut bytes);
    }
    w.stack.receive(w.now, &bytes);
    w.stack.check();
    w.drain();
    // Delayed ACKs, probes, retransmissions and TIME_WAIT run against whatever the packet did.
    for ms in [50, 500, 5_000, 70_000] {
        w.advance(Duration::from_millis(ms));
        w.drain();
        w.stack.check();
    }
    w.finish();
}

/// The flows the packet lands on: SYN_SENT, idle, data in flight, unread plus out-of-order data,
/// FIN_WAIT_1, CLOSE_WAIT, a compact TIME_WAIT entry and a UDP socket.
pub(super) fn populated() -> World {
    let mut w = World::new();
    const { assert!(MAX_PEERS >= 7) };
    w.connect(false).expect("SYN_SENT flow");

    let idle = w.connect(false).unwrap();
    w.syn_ack(idle, 1400, Some(7), true, true);
    w.drain();

    let flight = w.connect(true).unwrap();
    w.syn_ack(flight, 1360, Some(7), true, true);
    w.drain();
    w.write(flight, 4000);
    w.drain();

    let unread = w.connect(false).unwrap();
    w.syn_ack(unread, 1400, Some(7), true, true);
    w.drain();
    w.send_data(unread, &[7; 1000], false);
    let ahead = w.peers[unread].next.wrapping_add(2000);
    let seg = super::world::Seg {
        seq: ahead,
        ack: w.peers[unread].snd_nxt,
        flags: tcp::ACK,
        window: u16::MAX,
        sack: &[],
        data: &[9; 700],
    };
    w.deliver(unread, &seg);
    w.drain();

    let fin_wait = w.connect(false).unwrap();
    w.syn_ack(fin_wait, 1400, Some(7), true, true);
    w.drain();
    w.shutdown(fin_wait);
    w.drain();

    let close_wait = w.connect(true).unwrap();
    w.syn_ack(close_wait, 1360, None, false, false);
    w.drain();
    w.send_data(close_wait, &[5; 500], true);
    w.drain();

    let time_wait = w.connect(false).unwrap();
    w.syn_ack(time_wait, 1400, Some(7), true, true);
    w.drain();
    w.shutdown(time_wait);
    w.drain();
    w.ack_all(time_wait);
    w.send_data(time_wait, &[], true);
    w.drain();
    let id = w.peers[time_wait].id;
    w.stack.tcp_close(id);
    w.drain();

    w.udp = w.stack.udp_bind(Some(5353)).ok();
    w.stack.check();
    w
}

/// Fixes the IP total length and the IP/transport checksums of a possibly mangled packet.
fn repair(b: &mut [u8]) {
    match b.first().map(|v| v >> 4) {
        Some(4) if b.len() >= 20 => {
            let total = b.len();
            b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            let ihl = usize::from(b[0] & 15) * 4;
            if (20..=total).contains(&ihl) {
                b[10..12].fill(0);
                let sum = checksum(&b[..ihl]);
                b[10..12].copy_from_slice(&sum.to_be_bytes());
                let src = IpAddr::from([b[12], b[13], b[14], b[15]]);
                let dst = IpAddr::from([b[16], b[17], b[18], b[19]]);
                let proto = b[9];
                transport(&mut b[ihl..], src, dst, proto);
            }
        }
        Some(6) if b.len() >= 40 => {
            let payload = (b.len() - 40) as u16;
            b[4..6].copy_from_slice(&payload.to_be_bytes());
            let addr = |at: usize| {
                let mut a = [0u8; 16];
                a.copy_from_slice(&b[at..at + 16]);
                IpAddr::from(a)
            };
            let (src, dst, proto) = (addr(8), addr(24), b[6]);
            transport(&mut b[40..], src, dst, proto);
        }
        _ => {}
    }
}

fn transport(seg: &mut [u8], src: IpAddr, dst: IpAddr, proto: u8) {
    let at = match proto {
        PROTO_TCP => 16,
        PROTO_UDP => 6,
        PROTO_ICMP | PROTO_ICMPV6 => 2,
        _ => return,
    };
    if seg.len() < at + 2 {
        return;
    }
    seg[at..at + 2].fill(0);
    let sum = if proto == PROTO_ICMP {
        checksum(seg)
    } else {
        let mut c = Checksum::pseudo(src, dst, proto, seg.len());
        c.add(seg);
        c.finish()
    };
    seg[at..at + 2].copy_from_slice(&sum.to_be_bytes());
}

/// Valid packets for the populated stack, each in verbatim mode.
pub fn seeds() -> Vec<Vec<u8>> {
    let w = populated();
    let mut out = Vec::new();
    let mut add = |bytes: Vec<u8>, mode: u8| {
        let mut v = vec![mode, 0];
        v.extend_from_slice(&bytes);
        out.push(v);
    };
    let ack = tcp::ACK;
    for i in 0..w.peers.len() {
        let p = &w.peers[i];
        let (next, snd_nxt) = (p.next, p.snd_nxt);
        let sack = [(snd_nxt.wrapping_sub(2800), snd_nxt.wrapping_sub(1400))];
        let segs = [
            // pure ACK of everything, a SACK-bearing duplicate, in-order data, FIN, RST.
            super::world::Seg {
                seq: next,
                ack: snd_nxt,
                flags: ack,
                window: u16::MAX,
                sack: &[],
                data: &[],
            },
            super::world::Seg {
                seq: next,
                ack: snd_nxt.wrapping_sub(4000),
                flags: ack,
                window: 0,
                sack: &sack,
                data: &[],
            },
            super::world::Seg {
                seq: next,
                ack: snd_nxt,
                flags: ack,
                window: 1000,
                sack: &[],
                data: &[1; 600],
            },
            super::world::Seg {
                seq: next.wrapping_add(900),
                ack: snd_nxt,
                flags: ack,
                window: 1000,
                sack: &[],
                data: &[2; 300],
            },
            super::world::Seg {
                seq: next,
                ack: snd_nxt,
                flags: ack | tcp::FIN,
                window: 1000,
                sack: &[],
                data: &[],
            },
            super::world::Seg {
                seq: next,
                ack: snd_nxt,
                flags: tcp::RST | ack,
                window: 0,
                sack: &[],
                data: &[],
            },
            super::world::Seg {
                seq: p.isn(),
                ack: p.iss.wrapping_add(1),
                flags: tcp::SYN | ack,
                window: 100,
                sack: &[],
                data: &[],
            },
        ];
        for s in &segs {
            if let Some(bytes) = w.segment(i, s) {
                add(bytes, 1);
            }
        }
        if !w.peers[i].last_data.is_empty() {
            let mut icmp = vec![0; 256];
            let p = &w.peers[i];
            if let Some(local) = p.local
                && let Some(n) = crate::wire::icmp::emit_packet_too_big(
                    &mut icmp,
                    p.remote.ip(),
                    local.ip(),
                    1280,
                    &p.last_data,
                )
            {
                icmp.truncate(n);
                add(icmp, 1);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TcpState::*;

    #[test]
    fn populated_flows_sit_in_distinct_states() {
        let w = populated();
        let states: Vec<_> = w.peers.iter().map(|p| w.stack.tcp_state(p.id)).collect();
        assert_eq!(
            states,
            [
                Some(SynSent),
                Some(Established),
                Some(Established),
                Some(Established),
                Some(FinWait1),
                Some(CloseWait),
                None, // closed after TIME_WAIT: a compact entry
            ]
        );
        assert_eq!(w.stack.stats().timewait_entries, 1);
        assert!(w.stack.tcp_stats(w.peers[2].id).unwrap().outstanding_bytes > 0);
    }
}
