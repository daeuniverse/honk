//! Transparent-mode operation sequences: SYNs, retransmitted SYNs, admission (immediate and
//! deferred), refusal, handshake ACKs, data, FIN/RST, keepalive, time and raw/UDP packets.
//! Every byte string decodes to some sequence; after each operation the whole stack is recounted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::wire::{self, tcp};
use crate::{
    AcceptOpts, AcceptWhen, Config, ExcludeSet, FlowId, Keepalive, Mode, Refuse, Rx, Stack,
};

const MAX_OPS: usize = 192;
const CLIENTS: usize = 5;
const DSTS: usize = 3;

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

pub(super) mod op {
    /// `[client, dst, mss]`
    pub const SYN: u8 = 0;
    /// `[slot, when, max_mss, keepalive]`
    pub const ACCEPT: u8 = 1;
    /// `[slot]`
    pub const COMPLETE: u8 = 2;
    /// `[slot, how]`
    pub const REFUSE: u8 = 3;
    /// `[slot]`
    pub const HANDSHAKE_ACK: u8 = 4;
    /// `[slot, len, offset]`
    pub const DATA: u8 = 5;
    /// `[slot]`
    pub const FIN: u8 = 6;
    /// `[slot, how]`
    pub const RST: u8 = 7;
    /// `[slot, kind, n]`: 0 write, 1 read, 2 shutdown, 3 close, 4 abort, 5 ack a probe
    pub const APP: u8 = 8;
    /// `[exponent]`
    pub const ADVANCE: u8 = 9;
    /// `[kind, length]`: UDP to a destination, with or without a source port
    pub const UDP: u8 = 10;
    /// `[length, bytes..]`
    pub const RAW: u8 = 11;
}

/// One (client, destination) tuple the script plays the client of.
struct Slot {
    client: SocketAddr,
    dst: SocketAddr,
    /// The client's initial sequence number and next sequence number.
    isn: u32,
    next: u32,
    /// The stack's sequence number after its SYN-ACK, once seen.
    snd: Option<u32>,
    id: Option<FlowId>,
    syn_sent: bool,
}

struct World {
    stack: Stack,
    base: Instant,
    now: Instant,
    slots: Vec<Slot>,
}

fn client(i: usize) -> SocketAddr {
    if i.is_multiple_of(2) {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2 + i as u8)), 40_000)
    } else {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2 + i as u16)),
            40_000,
        )
    }
}

fn destination(v6: bool, j: usize) -> SocketAddr {
    if v6 {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100 + j as u16)),
            443,
        )
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10 + j as u8)), 443)
    }
}

impl World {
    fn new() -> World {
        let base = Instant::now();
        let mut cfg = Config::new([0x3c; 32]);
        cfg.mode = Mode::Transparent {
            exclude: ExcludeSet::default(),
        };
        cfg.max_flows = 12;
        cfg.half_open_max = 6;
        cfg.half_open_per_source = 3;
        cfg.memory_limit = 2 * 1024 * 1024;
        cfg.shared_budget = Some(crate::MemoryBudget::new(1024 * 1024));
        cfg.tcp_rcv_buf_max = 128 * 1024;
        cfg.tcp_snd_buf_max = 128 * 1024;
        World {
            stack: Stack::new(cfg, base),
            base,
            now: base,
            slots: Vec::new(),
        }
    }

    fn slot(&mut self, r: &mut Reader) -> Option<usize> {
        let b = usize::from(r.u8());
        (!self.slots.is_empty()).then(|| b % self.slots.len())
    }

    fn tsval(&self) -> u32 {
        7_000u32.wrapping_add(self.now.duration_since(self.base).as_millis() as u32)
    }

    fn send(
        &mut self,
        s: usize,
        seq: u32,
        ack: u32,
        flags: u8,
        options: tcp::Options,
        data: &[u8],
    ) {
        let p = &self.slots[s];
        let mut out = vec![0u8; data.len() + 128];
        let hdr = tcp::Header {
            src_port: p.client.port(),
            dst_port: p.dst.port(),
            seq,
            ack,
            flags,
            window: 60_000,
            urgent: 0,
            options,
        };
        if let Some(n) = tcp::emit_packet(&mut out, p.client.ip(), p.dst.ip(), &hdr, [data, &[]]) {
            self.stack.receive(self.now, &out[..n]);
        }
    }

    fn plain(&self) -> tcp::Options {
        tcp::Options {
            timestamps: Some((self.tsval(), 0)),
            ..tcp::Options::default()
        }
    }

    /// Pulls everything the stack will send and learns the stack's sequence numbers from it.
    fn drain(&mut self) {
        let mut buf = vec![0u8; 2048];
        for _ in 0..4096 {
            let Some(n) = self.stack.poll_transmit(self.now, &mut buf) else {
                return;
            };
            let ip = wire::parse_ip(&buf[..n]).expect("well-formed output");
            if ip.proto == wire::PROTO_TCP {
                let seg = &buf[ip.payload.clone()];
                let (h, _) = tcp::parse(seg).expect("well-formed TCP");
                if h.flags & (tcp::SYN | tcp::ACK) == tcp::SYN | tcp::ACK {
                    for p in &mut self.slots {
                        if p.client.ip() == ip.dst
                            && p.dst.ip() == ip.src
                            && p.client.port() == h.dst_port
                            && p.dst.port() == h.src_port
                        {
                            p.snd = Some(h.seq.wrapping_add(1));
                        }
                    }
                }
            }
        }
        panic!("poll_transmit never ran dry");
    }

    fn adopt(&mut self) {
        while let Some(info) = self.stack.poll_accept() {
            let slot = self
                .slots
                .iter_mut()
                .find(|p| p.client == info.client && p.dst == info.original_dst)
                .expect("a reported SYN the script never sent");
            slot.id = Some(info.id);
        }
    }

    fn advance(&mut self, by: Duration) {
        self.now += by;
        self.stack.handle_timeout(self.now);
    }

    fn finish(&mut self) {
        self.adopt();
        for p in &self.slots {
            if let Some(id) = p.id {
                self.stack.tcp_abort(id);
            }
        }
        for _ in 0..96 {
            self.drain();
            self.stack.check();
            let stats = self.stack.stats();
            if stats.flows == 0 && stats.timewait_entries == 0 {
                break;
            }
            self.advance(Duration::from_secs(130));
        }
        // Unfinished reassemblies and rate-limit state age out too.
        self.advance(Duration::from_secs(130));
        self.drain();
        let stats = self.stack.stats();
        assert!(
            stats.flows == 0 && stats.timewait_entries == 0,
            "flows never terminated: {} live, {} TIME_WAIT",
            stats.flows,
            stats.timewait_entries
        );
        self.stack.assert_released();
        while self.stack.poll_event().is_some() {}
        assert!(self.stack.poll_timeout().is_none_or(|t| t > self.now));
    }
}

pub fn check(data: &[u8]) {
    let mut r = Reader(data);
    let mut w = World::new();
    let mut ops = 0;
    while !r.done() && ops < MAX_OPS {
        ops += 1;
        step(&mut w, &mut r);
        w.adopt();
        w.stack.check();
    }
    w.finish();
}

fn step(w: &mut World, r: &mut Reader) {
    match r.u8() % 12 {
        op::SYN => {
            let (c, d, mss) = (usize::from(r.u8()) % CLIENTS, usize::from(r.u8()), r.u8());
            let dst = destination(c % 2 == 1, d % DSTS);
            let client = client(c);
            let s = match w
                .slots
                .iter()
                .position(|p| p.client == client && p.dst == dst)
            {
                Some(s) => s,
                None => {
                    if w.slots.len() >= CLIENTS * DSTS {
                        return;
                    }
                    let isn = 1_000u32.wrapping_mul(w.slots.len() as u32 + 1);
                    w.slots.push(Slot {
                        client,
                        dst,
                        isn,
                        next: isn.wrapping_add(1),
                        snd: None,
                        id: None,
                        syn_sent: false,
                    });
                    w.slots.len() - 1
                }
            };
            let mss = [1, 48, 536, 1380, 1460, u16::MAX][usize::from(mss) % 6];
            let options = tcp::Options {
                mss: Some(mss),
                wscale: Some(7),
                sack_permitted: true,
                timestamps: Some((w.tsval(), 0)),
                ..tcp::Options::default()
            };
            let isn = w.slots[s].isn;
            w.slots[s].syn_sent = true;
            w.send(s, isn, 0, tcp::SYN, options, &[]);
            w.drain();
        }
        op::ACCEPT => {
            let (Some(s), when, max_mss, ka) = (w.slot(r), r.u8(), r.u8(), r.u8()) else {
                return;
            };
            let Some(id) = w.slots[s].id else { return };
            let opts = AcceptOpts {
                when: match when % 3 {
                    0 => AcceptWhen::Now,
                    1 => AcceptWhen::Deferred {
                        deadline: Duration::from_millis(u64::from(when) * 150),
                    },
                    _ => AcceptWhen::Deferred {
                        deadline: Duration::from_secs(600),
                    },
                },
                max_mss: [None, Some(1), Some(536), Some(1200)][usize::from(max_mss) % 4],
                keepalive: (ka % 2 == 1).then_some(Keepalive {
                    idle: Duration::from_millis(500 + u64::from(ka) * 50),
                    interval: Duration::from_millis(200),
                    probes: ka % 4,
                }),
            };
            let _ = w.stack.tcp_accept(id, opts);
            w.drain();
        }
        op::COMPLETE => {
            if let Some(s) = w.slot(r)
                && let Some(id) = w.slots[s].id
            {
                let _ = w.stack.tcp_complete(id);
                w.drain();
            }
        }
        op::REFUSE => {
            let (s, how) = (w.slot(r), r.u8());
            if let Some(s) = s
                && let Some(id) = w.slots[s].id
            {
                let how = [
                    Refuse::Rst,
                    Refuse::Drop,
                    Refuse::IcmpUnreachable,
                    Refuse::IcmpAdminProhibited,
                ][usize::from(how) % 4];
                w.stack.tcp_refuse(id, how);
                w.drain();
            }
        }
        op::HANDSHAKE_ACK => {
            if let Some(s) = w.slot(r)
                && let Some(snd) = w.slots[s].snd
            {
                let (next, options) = (w.slots[s].next, w.plain());
                w.send(s, next, snd, tcp::ACK, options, &[]);
                w.drain();
            }
        }
        op::DATA => {
            let (s, len, off) = (w.slot(r), usize::from(r.u8()) * 8, r.u8());
            let Some(s) = s else { return };
            let Some(snd) = w.slots[s].snd else { return };
            let data: Vec<u8> = (0..len).map(|k| k as u8).collect();
            let next = w.slots[s].next;
            let seq = match off % 4 {
                0 | 1 => next,
                2 => next.wrapping_add(u32::from(off)),
                _ => next.wrapping_sub(u32::from(off)),
            };
            let options = w.plain();
            w.send(s, seq, snd, tcp::ACK, options, &data);
            if seq == next {
                w.slots[s].next = next.wrapping_add(len as u32);
            }
            w.drain();
        }
        op::FIN => {
            if let Some(s) = w.slot(r)
                && let Some(snd) = w.slots[s].snd
            {
                let (next, options) = (w.slots[s].next, w.plain());
                w.send(s, next, snd, tcp::ACK | tcp::FIN, options, &[]);
                w.slots[s].next = next.wrapping_add(1);
                w.drain();
            }
        }
        op::RST => {
            let (s, how) = (w.slot(r), r.u8());
            if let Some(s) = s {
                let (next, snd) = (w.slots[s].next, w.slots[s].snd.unwrap_or(0));
                let seq = match how % 3 {
                    0 => next,
                    1 => next.wrapping_add(1 + u32::from(how)),
                    _ => w.slots[s].isn.wrapping_add(1),
                };
                w.send(
                    s,
                    seq,
                    snd,
                    tcp::RST | tcp::ACK,
                    tcp::Options::default(),
                    &[],
                );
                w.drain();
            }
        }
        op::APP => {
            let (s, kind, n) = (w.slot(r), r.u8() % 6, usize::from(r.u8()));
            let Some(s) = s else { return };
            let Some(id) = w.slots[s].id else { return };
            match kind {
                0 => {
                    let _ = w.stack.tcp_write(id, &vec![0x5a; n * 64]);
                }
                1 => {
                    let _ = w.stack.tcp_read(id, &mut vec![0; n * 64]);
                }
                2 => {
                    let _ = w.stack.tcp_shutdown(id);
                }
                3 => w.stack.tcp_close(id),
                4 => w.stack.tcp_abort(id),
                _ => {
                    // Answer a keepalive probe (or anything) with a bare in-window ACK.
                    if let Some(snd) = w.slots[s].snd {
                        let (next, options) = (w.slots[s].next, w.plain());
                        w.send(s, next, snd, tcp::ACK, options, &[]);
                    }
                }
            }
            while w.stack.poll_event().is_some() {}
            w.drain();
        }
        op::ADVANCE => {
            let e = r.u8();
            let ms = (1u64 << (e % 17)) + u64::from(e / 17);
            w.advance(Duration::from_millis(ms));
            w.drain();
        }
        op::UDP => {
            let (kind, len) = (r.u8(), usize::from(r.u8()) * 4);
            let c = client(usize::from(kind) % CLIENTS);
            let d = destination(c.is_ipv6(), usize::from(kind / 8) % DSTS);
            let payload = vec![0xa5; len];
            let mut out = vec![0; len + 64];
            if let Some(n) = wire::udp::emit_packet(&mut out, c, d, &payload) {
                match w.stack.receive(w.now, &out[..n]) {
                    Rx::Transparent { src, dst, payload } => {
                        assert_eq!((src, dst), (c, d));
                        assert_eq!(out[payload].len(), len);
                    }
                    Rx::Dropped(_) => {}
                    other => panic!("unexpected UDP result {other:?}"),
                }
            }
            let mut reply = vec![0; 2048];
            if let Ok(n) = w.stack.udp_send_from(d, c, &payload, &mut reply) {
                assert!(wire::parse_ip(&reply[..n]).is_ok());
            }
            w.drain();
        }
        _ => {
            let len = usize::from(r.u8() % 64);
            let bytes: Vec<u8> = (0..len).map(|_| r.u8()).collect();
            w.stack.receive(w.now, &bytes);
            w.drain();
        }
    }
}

/// Op sequences that walk the main paths; the fuzzer mutates them into the rest.
#[rustfmt::skip]
pub fn seeds() -> Vec<Vec<u8>> {
    use op::*;
    // SYN from client 0 to destination 0, accept now, SYN-ACK pulled, handshake ACK, data.
    let open = vec![SYN, 0, 0, 3, ACCEPT, 0, 0, 0, 0, HANDSHAKE_ACK, 0];
    let mut bulk = open.clone();
    bulk.extend([DATA, 0, 20, 0, APP, 0, 0, 100, APP, 1, 1, 100, FIN, 0, APP, 3, 0, 0]);
    // Three unanswered probes, then the flow fails.
    let keepalive = vec![
        SYN, 0, 0, 3, ACCEPT, 0, 0, 0, 3, HANDSHAKE_ACK, 0,
        ADVANCE, 11, ADVANCE, 9, ADVANCE, 9, ADVANCE, 9, APP, 0, 5, 0,
    ];
    // Retransmitted SYNs while deferred (600 ms), then complete.
    let deferred = vec![
        SYN, 1, 1, 4, SYN, 1, 1, 4, ACCEPT, 0, 4, 0, 0, ADVANCE, 8, SYN, 1, 1, 4,
        COMPLETE, 0, HANDSHAKE_ACK, 0, APP, 3, 0, 0,
    ];
    let refuse = vec![
        SYN, 0, 1, 3, REFUSE, 0, 0, SYN, 2, 0, 3, REFUSE, 1, 1,
        SYN, 3, 2, 3, REFUSE, 2, 2, SYN, 4, 0, 3, REFUSE, 3, 3,
    ];
    // Active close into TIME_WAIT, then a SYN for the same tuple.
    let mut close = open.clone();
    close.extend([
        APP, 0, 3, 0, ADVANCE, 3, FIN, 0, ADVANCE, 15, SYN, 0, 0, 3, ACCEPT, 0, 0, 0, 0,
    ]);
    let caps = (0..10).flat_map(|i| [SYN, i % 5, i, 3]).collect();
    let udp = vec![UDP, 0, 40, UDP, 9, 255, RAW, 8, 0x45, 0, 0, 20, 0, 0, 0x40, 0];
    vec![bulk, keepalive, deferred, refuse, close, caps, udp]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds must drive real termination, or the target would only fuzz the decoder.
    #[test]
    fn seeds_walk_accept_refusal_keepalive_and_caps() {
        let seeds = seeds();
        let run = |seed: &[u8]| {
            let mut r = Reader(seed);
            let mut w = World::new();
            while !r.done() {
                step(&mut w, &mut r);
                w.adopt();
                w.stack.check();
            }
            let sent = w.stack.stats().tx_packets;
            let drops = w.stack.stats().drops;
            w.finish();
            (sent, drops)
        };
        // bulk: SYN-ACK, data ACKs, our data, FIN handling.
        assert!(run(&seeds[0]).0 >= 4);
        // keepalive: the SYN-ACK, the handshake's answers and three probes.
        assert!(run(&seeds[1]).0 >= 4);
        // deferred: absorbed SYN retransmits, then one SYN-ACK.
        assert!(run(&seeds[2]).0 >= 1);
        // refusals: RST and two ICMP errors.
        assert!(run(&seeds[3]).0 >= 3);
        // caps: ten SYNs against six half-open slots.
        let (_, drops) = run(&seeds[5]);
        assert!(drops[crate::DropReason::HalfOpen as usize] > 0);
    }

    /// A deterministic sweep of biased random op streams; the real fuzzer goes much further.
    #[test]
    fn random_streams_hold_every_invariant() {
        let rounds: u64 = std::env::var("TRANSPARENT_ROUNDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..rounds {
            let mut data = Vec::new();
            for _ in 0..160 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                // Mostly small values so slots, flags and opcodes repeat.
                data.push(if x.is_multiple_of(5) {
                    (x >> 8) as u8
                } else {
                    ((x >> 8) % 12) as u8
                });
            }
            check(&data);
        }
    }
}
