//! A byte-decoded operation sequence: crafted peer segments with valid checksums, application
//! calls, time, pull budgets and ICMP. After every operation the whole stack is recounted.
//!
//! Every byte string decodes to some sequence; an exhausted input reads as zeros, and an
//! operation naming a flow that does not exist is skipped.

use std::time::Duration;

use super::world::{Seg, World};
use crate::wire::{self, tcp};

const MAX_OPS: usize = 192;

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn u8(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }

    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

/// Opcodes, as `seeds` writes them. Arguments follow in the order listed.
pub(super) mod op {
    /// `[v6]`
    pub const CONNECT: u8 = 0;
    /// `[flow, mss, wscale, bit0 sack | bit1 timestamps]`
    pub const SYN_ACK: u8 = 1;
    /// `[flow, ack, window, n, n * (left, right)]`
    pub const ACK: u8 = 2;
    /// `[flow, offset, length, fin]`
    pub const DATA: u8 = 3;
    /// `[flow, offset]`
    pub const FIN: u8 = 4;
    /// `[flow, seq]`
    pub const RST: u8 = 5;
    /// `[flow, hi, lo]`
    pub const WRITE: u8 = 6;
    /// `[flow, n]`
    pub const READ: u8 = 7;
    /// `[flow]`
    pub const SHUTDOWN: u8 = 8;
    /// `[flow]`
    pub const CLOSE: u8 = 9;
    /// `[flow]`
    pub const ABORT: u8 = 10;
    /// `[exponent]`
    pub const ADVANCE: u8 = 11;
    /// `[budget]`
    pub const PULL: u8 = 12;
    /// `[flow, mtu, seq]`
    pub const PTB: u8 = 13;
    /// `[kind, length]`
    pub const UDP: u8 = 14;
    /// `[length, bytes..]`
    pub const RAW: u8 = 15;
}

pub fn check(data: &[u8]) {
    let mut r = Reader(data);
    let mut w = World::new();
    let mut ops = 0;
    while !r.done() && ops < MAX_OPS {
        ops += 1;
        step(&mut w, &mut r);
        w.stack.check();
    }
    w.finish();
}

fn flow(w: &World, r: &mut Reader) -> Option<usize> {
    let b = usize::from(r.u8());
    (!w.peers.is_empty()).then(|| b % w.peers.len())
}

fn step(w: &mut World, r: &mut Reader) {
    match r.u8() % 16 {
        op::CONNECT => {
            let v6 = r.u8() & 1 != 0;
            w.connect(v6);
        }
        op::SYN_ACK => {
            let (i, mss, wscale, flags) = (flow(w, r), r.u8(), r.u8(), r.u8());
            let Some(i) = i else { return };
            let mss = [1, 48, 536, 1380, 1460, u16::MAX][usize::from(mss) % 6];
            let wscale = [None, Some(0), Some(7), Some(14)][usize::from(wscale) % 4];
            w.syn_ack(i, mss, wscale, flags & 1 != 0, flags & 2 != 0);
            w.drain();
        }
        op::ACK => {
            let (i, ack, window, n) = (flow(w, r), r.u8(), r.u8(), r.u8() % 5);
            let blocks: Vec<(u8, u8)> = (0..n).map(|_| (r.u8(), r.u8())).collect();
            let Some(i) = i else { return };
            let p = &w.peers[i];
            let (acked, snd_nxt) = (p.acked, p.snd_nxt);
            let flight = snd_nxt.wrapping_sub(acked);
            let at =
                |frac: u8| acked.wrapping_add((u64::from(flight) * u64::from(frac) / 255) as u32);
            let ack = match ack % 6 {
                0 => snd_nxt,
                1 => acked,
                2 => at(128),
                3 => acked.wrapping_add(1),
                4 => snd_nxt.wrapping_add(1 + u32::from(ack)),
                _ => acked.wrapping_sub(1000),
            };
            let window = [0, 1, 1000, u16::MAX][usize::from(window) % 4];
            let sack: Vec<(u32, u32)> = blocks
                .iter()
                .map(|&(l, rt)| {
                    // Fractions of the flight; reversed pairs and blocks below the ACK are kept on
                    // purpose (DSACK shapes and garbage).
                    (at(l), at(rt))
                })
                .collect();
            let s = Seg {
                seq: p.next,
                ack,
                flags: tcp::ACK,
                window,
                sack: &sack,
                data: &[],
            };
            w.deliver(i, &s);
            w.drain();
        }
        op::DATA => {
            let (i, off, len, fin) = (flow(w, r), r.u8(), usize::from(r.u8()) * 8, r.u8() & 1 != 0);
            let Some(i) = i else { return };
            let data: Vec<u8> = (0..len).map(|k| k as u8).collect();
            let next = w.peers[i].next;
            let seq = match off % 6 {
                0 => next,
                1 => next.wrapping_add(len as u32),
                2 => next.wrapping_sub(len as u32 / 2),
                3 => next.wrapping_add(100_000),
                4 => next.wrapping_sub(5000),
                _ => next.wrapping_add(u32::from(off)),
            };
            let s = Seg {
                seq,
                ack: w.peers[i].snd_nxt,
                flags: tcp::ACK | if fin { tcp::FIN } else { 0 },
                window: u16::MAX,
                sack: &[],
                data: &data,
            };
            w.deliver(i, &s);
            w.drain();
        }
        op::FIN => {
            let (i, off) = (flow(w, r), r.u8());
            let Some(i) = i else { return };
            let next = w.peers[i].next;
            let s = Seg {
                seq: next.wrapping_add(u32::from(off % 4) * 100),
                ack: w.peers[i].snd_nxt,
                flags: tcp::ACK | tcp::FIN,
                window: u16::MAX,
                sack: &[],
                data: &[],
            };
            w.deliver(i, &s);
            w.drain();
        }
        op::RST => {
            let (i, seq) = (flow(w, r), r.u8());
            let Some(i) = i else { return };
            let next = w.peers[i].next;
            let seq = match seq % 3 {
                0 => next,
                1 => next.wrapping_add(1 + u32::from(seq)),
                _ => u32::from(seq) << 24,
            };
            let s = Seg {
                seq,
                ack: w.peers[i].snd_nxt,
                flags: tcp::RST | tcp::ACK,
                window: 0,
                sack: &[],
                data: &[],
            };
            w.deliver(i, &s);
            w.drain();
        }
        op::WRITE => {
            let (i, hi, lo) = (flow(w, r), r.u8(), r.u8());
            let Some(i) = i else { return };
            w.write(i, (usize::from(hi) << 8 | usize::from(lo)) % 20_000);
            w.drain();
        }
        op::READ => {
            let (i, n) = (flow(w, r), usize::from(r.u8()) * 64);
            let Some(i) = i else { return };
            w.read(i, n);
            w.drain();
        }
        op::SHUTDOWN => {
            if let Some(i) = flow(w, r) {
                w.shutdown(i);
                w.drain();
            }
        }
        op::CLOSE => {
            if let Some(i) = flow(w, r) {
                w.stack.tcp_close(w.peers[i].id);
                w.drain();
            }
        }
        op::ABORT => {
            if let Some(i) = flow(w, r) {
                w.stack.tcp_abort(w.peers[i].id);
                w.drain();
            }
        }
        op::ADVANCE => {
            // 1 ms to about 2 minutes, with a fraction so that timers are not hit exactly.
            let e = r.u8();
            let ms = (1u64 << (e % 18)) + u64::from(e / 18);
            w.advance(Duration::from_millis(ms));
            w.drain();
        }
        op::PULL => {
            // Budgets 0, 1 and N: nothing may be lost by stopping early.
            let n = [0, 1, 2, 8, 64][usize::from(r.u8()) % 5];
            w.pull(n);
        }
        op::PTB => {
            let (i, mtu, seq) = (flow(w, r), r.u8(), r.u8());
            let Some(i) = i else { return };
            let p = &w.peers[i];
            let Some(local) = p.local else { return };
            let mut quote = p.last_data.clone();
            if seq % 4 == 0 && quote.len() > 44 {
                // Corrupt the quoted sequence number: it must not reach the flow.
                quote[24 + usize::from(p.remote.is_ipv6()) * 20] ^= seq;
            }
            let mtu = [0, 68, 576, 1280, 1400, 65_535][usize::from(mtu) % 6];
            let mut out = vec![0; 256];
            if let Some(n) =
                wire::icmp::emit_packet_too_big(&mut out, p.remote.ip(), local.ip(), mtu, &quote)
            {
                w.stack.receive(w.now, &out[..n]);
                w.drain();
            }
        }
        op::UDP => {
            let (kind, len) = (r.u8() % 4, usize::from(r.u8()) * 4);
            udp(w, kind, len);
        }
        _ => {
            let len = usize::from(r.u8() % 64);
            let bytes: Vec<u8> = (0..len).map(|_| r.u8()).collect();
            w.stack.receive(w.now, &bytes);
            w.drain();
        }
    }
}

fn udp(w: &mut World, kind: u8, len: usize) {
    let payload = vec![0xA5; len];
    let dst = World::remote(len % 8 >= 4, 0);
    match kind {
        0 if w.udp.is_none() => w.udp = w.stack.udp_bind(None).ok(),
        1 => {
            if let Some(id) = w.udp {
                let mut out = vec![0; 2048];
                if let Ok(n) = w.stack.udp_send(id, dst, &payload, &mut out) {
                    assert!(n <= 1420);
                    assert!(wire::parse_ip(&out[..n]).is_ok());
                }
            }
        }
        2 => {
            // A datagram from the remote to our bound port.
            if let (Some(id), Some(local)) = (w.udp, w.udp_local()) {
                let mut out = vec![0; len + 64];
                if let Some(n) = wire::udp::emit_packet(&mut out, dst, local, &payload) {
                    let rx = w.stack.receive(w.now, &out[..n]);
                    if let crate::Rx::Datagram {
                        flow,
                        payload: range,
                        ..
                    } = rx
                    {
                        assert_eq!(flow, id);
                        assert_eq!(&out[range], payload.as_slice());
                    }
                }
            }
        }
        3 => {
            if let Some(id) = w.udp.take() {
                w.stack.udp_close(id);
            }
        }
        _ => {}
    }
}

/// Op sequences that walk the main paths; the fuzzer mutates them into the rest.
pub fn seeds() -> Vec<Vec<u8>> {
    use op::*;
    let handshake = |v6: u8| vec![CONNECT, v6, SYN_ACK, 0, 3, 2, 3];
    let mut bulk = handshake(0);
    bulk.extend([
        WRITE, 0, 0x4e, 0x20, PULL, 4, ACK, 0, 2, 0, 0, ADVANCE, 8, PULL, 4,
    ]);
    let mut loss = handshake(0);
    loss.extend([
        WRITE, 0, 0x27, 0x10, PULL, 4, // 10 kB out
        ACK, 0, 1, 3, 3, 30, 60, 90, 120, 150, 180, // three SACK blocks above a hole
        ADVANCE, 9, PULL, 4, ADVANCE, 15, PULL, 4, // reorder timer, RTO
        ACK, 0, 0, 3, 0,
    ]);
    let mut receive = handshake(1);
    receive.extend([
        DATA, 0, 0, 100, 0, DATA, 0, 1, 50, 0, DATA, 0, 0, 30,
        1, // ahead of a hole, then fill, FIN
        READ, 0, 255, PULL, 4, SHUTDOWN, 0, PULL, 4, ACK, 0, 0, 3, 0, CLOSE, 0, ADVANCE, 16,
    ]);
    let mut window = handshake(0);
    window.extend([
        ACK, 0, 1, 0, 0, WRITE, 0, 0x03, 0xe8, PULL, 4, ADVANCE, 9, PULL, 4, ADVANCE, 11, PULL, 4,
        ACK, 0, 1, 2, 0, PULL, 4,
    ]);
    let mut icmp = handshake(0);
    icmp.extend([
        WRITE, 0, 0x03, 0xe8, PULL, 4, PTB, 0, 3, 1, PULL, 4, RST, 0, 0, PULL, 4,
    ]);
    let mut udp = vec![UDP, 0, 0, UDP, 2, 40, UDP, 1, 20, UDP, 3, 0];
    udp.extend([RAW, 8, 0x45, 0, 0, 20, 0, 0, 0x40, 0]);
    vec![
        bulk,
        loss,
        receive,
        window,
        icmp,
        udp,
        vec![CONNECT, 0, CONNECT, 1, ABORT, 0],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds must drive real traffic, or the target would only fuzz the decoder.
    #[test]
    fn loss_seed_reaches_sack_recovery_and_timeout() {
        let seed = &seeds()[1];
        let mut r = Reader(seed);
        let mut w = World::new();
        while !r.done() {
            step(&mut w, &mut r);
            w.stack.check();
        }
        let stats = w.stack.tcp_stats(w.peers[0].id).unwrap();
        assert!(
            stats.sacked_bytes > 0 || stats.retrans_segments > 0,
            "{stats:?}"
        );
        assert!(w.stack.stats().tx_packets > 10);
        w.finish();
    }
}
