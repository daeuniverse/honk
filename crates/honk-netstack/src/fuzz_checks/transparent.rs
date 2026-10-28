//! Transparent operation sequences: admission, shutdown, keepalive, checksum provenance, TCP
//! GRO/TSO, UDP USO, bounded fragments and raw input. Every byte string decodes to some sequence;
//! after each operation the whole stack is recounted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::wire::{self, tcp};
use crate::{
    AcceptOpts, AcceptWhen, Config, Csum, ExcludeSet, FlowId, GsoKind, GsoRx, Keepalive, Mode,
    Refuse, Rx, RxMeta, Stack, Transmit, TxCaps, TxCsum,
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
    /// `[slot, length * 256, offset, size-index, checksum-flags]`
    pub const TCP_GSO: u8 = 12;
    /// `[kind, length * 256, size-index, checksum-flags]`
    pub const UDP_GSO: u8 = 13;
    /// `[mask]`: low bits TSO4/TSO6/USO4/USO6; 32 tiny-buffer, 64 paused, 128 control-only.
    pub const CAPS: u8 = 14;
    /// `[kind, length, behavior]`: valid UDP fragments, reordered/duplicated/incomplete/corrupt.
    pub const FRAGMENTS: u8 = 15;
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
    caps: TxCaps,
    pull_flags: u8,
    control_packets: usize,
    rx_gso_packets: usize,
    tx_gso_packets: usize,
    reassembled: usize,
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

/// Provenance and segment-size choices, including contradictory driver claims.
fn metadata(flags: u8, size: u8, proto: u8, start: u16) -> (RxMeta, bool) {
    let field = if proto == wire::PROTO_TCP { 16 } else { 6 };
    let csum = match flags & 7 {
        0 | 6 => Csum::Verify,
        1 | 7 => Csum::Valid,
        2 | 5 => Csum::Partial {
            start,
            offset: field,
        },
        3 => Csum::Partial {
            start: start + 4,
            offset: field,
        },
        _ => Csum::Partial {
            start,
            offset: field + 1,
        },
    };
    let tcp = (proto == wire::PROTO_TCP) ^ (flags & 16 != 0);
    let gso = (size & 128 == 0).then_some(GsoRx {
        kind: if tcp { GsoKind::Tcp } else { GsoKind::UdpL4 },
        size: [0, 1, 48, 512, 1368, u16::MAX][usize::from(size) % 6],
    });
    (RxMeta { csum, gso }, flags & 8 != 0)
}

/// Check the bytes and metadata together, including the seed required by CHECKSUM_PARTIAL.
fn check_transmit(tx: &Transmit, packet: &[u8]) {
    assert_eq!(tx.len, packet.len());
    let ip = match wire::parse_ip(packet) {
        Ok(ip) => ip,
        Err(wire::ParseError::Fragment) => {
            assert_eq!(tx.gso, None);
            assert_eq!(tx.csum, TxCsum::Full);
            wire::frag::parse(packet).expect("well-formed output fragment");
            return;
        }
        other => panic!("malformed output: {other:?}"),
    };
    let l4 = &packet[ip.payload.clone()];
    match (tx.gso, tx.csum) {
        (Some(gso), TxCsum::Partial { start, offset }) => {
            assert_eq!(usize::from(start), ip.payload.start);
            assert_ne!(gso.size, 0);
            assert!(tx.len <= usize::from(u16::MAX));
            let (header, field) = match gso.kind {
                GsoKind::Tcp => {
                    assert_eq!(ip.proto, wire::PROTO_TCP);
                    (tcp::parse(l4).expect("well-formed TSO header").1, 16)
                }
                GsoKind::UdpL4 => {
                    assert_eq!(ip.proto, wire::PROTO_UDP);
                    wire::udp::parse(l4).expect("well-formed USO header");
                    (8, 6)
                }
            };
            assert_eq!(offset, field as u16);
            assert_eq!(usize::from(gso.hdr_len), ip.payload.start + header);
            let segments = (l4.len() - header).div_ceil(usize::from(gso.size));
            assert!(segments >= 2);
            if gso.kind == GsoKind::UdpL4 {
                assert!(segments <= crate::offload::MAX_USO_TX);
            }
            let seed = wire::checksum::Checksum::pseudo(ip.src, ip.dst, ip.proto, l4.len()).fold();
            assert_eq!(u16::from_be_bytes([l4[field], l4[field + 1]]), seed);
        }
        (None, TxCsum::Full) => match ip.proto {
            wire::PROTO_TCP => assert!(tcp::verify_checksum(ip.src, ip.dst, l4)),
            wire::PROTO_UDP => assert!(wire::udp::verify_checksum(ip.src, ip.dst, l4)),
            _ => {}
        },
        _ => panic!("segmentation and checksum metadata disagree: {tx:?}"),
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
            caps: TxCaps::NONE,
            pull_flags: 0,
            control_packets: 0,
            rx_gso_packets: 0,
            tx_gso_packets: 0,
            reassembled: 0,
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
        (seq, ack): (u32, u32),
        flags: u8,
        options: tcp::Options,
        data: &[u8],
        metadata: (RxMeta, bool),
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
            self.ingest(&mut out[..n], metadata);
        }
    }

    /// Seeds a partial checksum as a kernel would, optionally damages it, and ingests the packet.
    fn ingest(&mut self, packet: &mut [u8], (meta, corrupt): (RxMeta, bool)) -> Rx {
        let ip = wire::parse_ip(packet).expect("the harness just built a complete packet");
        let offset = if ip.proto == wire::PROTO_TCP { 16 } else { 6 };
        let field = ip.payload.start + offset;
        if matches!(meta.csum, Csum::Partial { .. }) {
            let seed =
                wire::checksum::Checksum::pseudo(ip.src, ip.dst, ip.proto, ip.payload.len()).fold();
            packet[field..field + 2].copy_from_slice(&seed.to_be_bytes());
        }
        if corrupt {
            packet[field] ^= 0x55;
        }
        let rx = self.stack.receive_with(self.now, packet, meta);
        if meta.gso.is_some() && matches!(rx, Rx::Consumed | Rx::TransparentSplit { .. }) {
            self.rx_gso_packets += 1;
        }
        rx
    }

    fn plain(&self) -> tcp::Options {
        tcp::Options {
            timestamps: Some((self.tsval(), 0)),
            ..tcp::Options::default()
        }
    }

    /// Pulls everything the stack will send and learns the stack's sequence numbers from it.
    fn drain(&mut self) {
        if self.pull_flags & 64 != 0 {
            return;
        }
        let mut buf = vec![0u8; 70_000];
        for _ in 0..4096 {
            let limit = if self.pull_flags & 32 != 0 {
                31
            } else {
                buf.len()
            };
            let tx = if self.pull_flags & 128 != 0 {
                super::control_transmit(&mut self.stack, self.now, &mut buf[..limit])
            } else {
                self.stack
                    .poll_transmit_with(self.now, &mut buf[..limit], self.caps)
            };
            let Some(tx) = tx else {
                return;
            };
            self.stack.check();
            if self.pull_flags & 128 != 0 {
                self.control_packets += 1;
            }
            let packet = &buf[..tx.len];
            let ip = match wire::parse_ip(packet) {
                Ok(ip) => ip,
                Err(wire::ParseError::Fragment) => {
                    assert_eq!(tx.gso, None);
                    assert_eq!(tx.csum, TxCsum::Full);
                    wire::frag::parse(packet).expect("well-formed output fragment");
                    continue;
                }
                other => panic!("malformed output: {other:?}"),
            };
            if tx.gso.is_some() {
                self.tx_gso_packets += 1;
            }
            check_transmit(&tx, packet);
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
        self.pull_flags = 0;
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

/// Build actual IPv4/IPv6 fragments, not just random input that the IP parser discards.
fn fragments(w: &mut World, kind: u8, len: u8, how: u8) {
    let src = client(usize::from(kind) % CLIENTS);
    let dst = destination(src.is_ipv6(), usize::from(kind / 8) % DSTS);
    let payload = vec![0x71; (usize::from(len) + 1) * 32];
    let mut whole = vec![0; payload.len() + 64];
    let n = wire::udp::emit_packet(&mut whole, src, dst, &payload).expect("bounded UDP packet");
    let ip = wire::parse_ip(&whole[..n]).expect("harness UDP packet");
    let mut datagram = whole[ip.payload].to_vec();
    if how & 8 != 0 {
        datagram[6] ^= 0x55;
    }
    let chunk = [64, 256, 1200][usize::from(how >> 5) % 3];
    let mut packets = Vec::new();
    let ident = (u32::from(kind) << 16) | u32::from(len);
    for (index, part) in datagram.chunks(chunk).enumerate() {
        let offset = index * chunk;
        let more = offset + part.len() < datagram.len();
        let mut packet = vec![0; part.len() + 48];
        let header = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => wire::ipv4::emit_fragment(
                &mut packet,
                s,
                d,
                wire::PROTO_UDP,
                part.len(),
                (ident as u16, offset, more),
            )
            .expect("bounded IPv4 fragment"),
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let ip = wire::ipv6::emit(&mut packet, s, d, 44, 8 + part.len())
                    .expect("bounded IPv6 fragment");
                let frag = wire::ipv6::emit_fragment_header(
                    &mut packet[ip..],
                    wire::PROTO_UDP,
                    offset,
                    more,
                    ident,
                )
                .expect("fragment header fits");
                ip + frag
            }
            _ => unreachable!(),
        };
        packet[header..header + part.len()].copy_from_slice(part);
        packet.truncate(header + part.len());
        packets.push(packet);
    }
    if how & 1 != 0 {
        packets.reverse();
    }
    let omit = (how & 4 != 0).then_some(packets.len() / 2);
    let meta = RxMeta {
        csum: if how & 16 != 0 {
            Csum::Valid
        } else {
            Csum::Verify
        },
        gso: None,
    };
    for (index, packet) in packets.iter().enumerate() {
        if omit == Some(index) {
            continue;
        }
        let rx = w.stack.receive_with(w.now, packet, meta);
        if let Rx::TransparentOwned {
            src: got_src,
            dst: got_dst,
            dscp,
            packet,
            payload: range,
        } = rx
        {
            assert_eq!(
                how & 8,
                0,
                "a corrupt reassembled checksum must never be trusted"
            );
            assert_eq!((got_src, got_dst), (src, dst));
            assert_eq!(dscp, 0);
            assert_eq!(&packet[range], payload);
            w.reassembled += 1;
        }
        w.stack.check();
        if how & 2 != 0 {
            w.stack.receive_with(w.now, packet, meta);
            w.stack.check();
        }
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
    let opcode = r.u8() % 16;
    match opcode {
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
            w.send(s, (isn, 0), tcp::SYN, options, &[], (RxMeta::VERIFY, false));
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
                w.send(
                    s,
                    (next, snd),
                    tcp::ACK,
                    options,
                    &[],
                    (RxMeta::VERIFY, false),
                );
                w.drain();
            }
        }
        op::DATA | op::TCP_GSO => {
            let (s, len, off) = (w.slot(r), usize::from(r.u8()), r.u8());
            let len = len * if opcode == op::TCP_GSO { 256 } else { 8 };
            let (size, provenance) = if opcode == op::TCP_GSO {
                (r.u8(), r.u8())
            } else {
                (128, 0)
            };
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
            let meta = metadata(
                provenance,
                size,
                wire::PROTO_TCP,
                wire::ip_header_len(w.slots[s].client.is_ipv6()) as u16,
            );
            w.send(s, (seq, snd), tcp::ACK, options, &data, meta);
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
                w.send(
                    s,
                    (next, snd),
                    tcp::ACK | tcp::FIN,
                    options,
                    &[],
                    (RxMeta::VERIFY, false),
                );
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
                    (seq, snd),
                    tcp::RST | tcp::ACK,
                    tcp::Options::default(),
                    &[],
                    (RxMeta::VERIFY, false),
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
                        w.send(
                            s,
                            (next, snd),
                            tcp::ACK,
                            options,
                            &[],
                            (RxMeta::VERIFY, false),
                        );
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
        op::UDP | op::UDP_GSO => {
            let (kind, len) = (r.u8(), usize::from(r.u8()));
            let len = len * if opcode == op::UDP_GSO { 256 } else { 4 };
            let (size, provenance) = if opcode == op::UDP_GSO {
                (r.u8(), r.u8())
            } else {
                (128, 0)
            };
            let c = client(usize::from(kind) % CLIENTS);
            let d = destination(c.is_ipv6(), usize::from(kind / 8) % DSTS);
            let payload = vec![0xa5; len];
            let mut out = vec![0; len + 64];
            if let Some(n) = wire::udp::emit_packet(&mut out, c, d, &payload) {
                let meta = metadata(
                    provenance,
                    size,
                    wire::PROTO_UDP,
                    wire::ip_header_len(c.is_ipv6()) as u16,
                );
                match w.ingest(&mut out[..n], meta) {
                    Rx::Transparent {
                        src,
                        dst,
                        dscp,
                        payload,
                    } => {
                        assert_eq!((src, dst), (c, d));
                        assert_eq!(dscp, 0);
                        assert_eq!(out[payload].len(), len);
                    }
                    Rx::TransparentSplit {
                        src,
                        dst,
                        dscp,
                        payload,
                        size,
                    } => {
                        assert_eq!((src, dst), (c, d));
                        assert_eq!(dscp, 0);
                        assert_eq!(out[payload.clone()].len(), len);
                        for datagram in out[payload].chunks(usize::from(size)) {
                            assert!(datagram.iter().all(|&byte| byte == 0xa5));
                        }
                    }
                    Rx::Dropped(_) => {}
                    other => panic!("unexpected UDP result {other:?}"),
                }
            }
            let mut reply = vec![0; 70_000];
            if opcode == op::UDP_GSO {
                let segment = [0, 1, 48, 512, 1368, u16::MAX][usize::from(size) % 6];
                if let Ok(tx) =
                    w.stack
                        .udp_send_gso_from((d, c), &payload, segment, w.caps, &mut reply)
                {
                    check_transmit(&tx, &reply[..tx.len]);
                    w.tx_gso_packets += usize::from(tx.gso.is_some());
                }
            } else if let Ok(n) = w.stack.udp_send_from(d, c, &payload, &mut reply) {
                assert!(wire::parse_ip(&reply[..n]).is_ok());
            }
            w.drain();
        }
        op::CAPS => {
            let mask = r.u8();
            w.pull_flags = mask;
            w.caps = TxCaps {
                tso4: mask & 1 != 0,
                tso6: mask & 2 != 0,
                uso4: mask & 4 != 0,
                uso6: mask & 8 != 0,
            };
            w.drain();
        }
        op::FRAGMENTS => {
            let (kind, len, how) = (r.u8(), r.u8(), r.u8());
            fragments(w, kind, len, how);
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
    let mut offloads = open.clone();
    offloads.extend([
        CAPS, 15, TCP_GSO, 0, 32, 0, 4, 2, APP, 0, 0, 255,
        UDP_GSO, 0, 30, 3, 2, UDP_GSO, 1, 20, 3, 1,
        FRAGMENTS, 0, 90, 0, FRAGMENTS, 1, 90, 1,
        FRAGMENTS, 0, 90, 20, FRAGMENTS, 1, 90, 24,
        TCP_GSO, 0, 10, 2, 3, 3, UDP_GSO, 0, 20, 0, 0,
        CAPS, 0, APP, 0, 1, 255,
    ]);
    let mut control = open.clone();
    control.extend([
        CAPS, 128, APP, 0, 0, 32, DATA, 0, 3, 0,
        SYN, 2, 1, 3, ACCEPT, 1, 0, 0, 0, HANDSHAKE_ACK, 1,
        APP, 1, 2, 0, FRAGMENTS, 0, 90, 4, ADVANCE, 15,
        CAPS, 160, DATA, 0, 3, 0, CAPS, 128,
        CAPS, 64, APP, 0, 0, 8, CAPS, 0,
    ]);
    vec![bulk, keepalive, deferred, refuse, close, caps, udp, offloads, control]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_seed_reaches_ack_fin_and_fragment_timeout_then_resumes_bulk() {
        let seed = &seeds()[8];
        let mut r = Reader(seed);
        let mut w = World::new();
        while !r.done() {
            step(&mut w, &mut r);
            w.adopt();
            w.stack.check();
            if w.pull_flags & 128 != 0 {
                let id = w.slots[0].id.unwrap();
                assert_eq!(w.stack.tcp_stats(id).unwrap().outstanding_bytes, 0);
            }
        }
        assert!(
            w.control_packets >= 5,
            "SYN-ACK, data ACKs, FIN and reassembly ICMP use control credit"
        );
        let id = w.slots[0].id.unwrap();
        assert!(
            w.stack.tcp_stats(id).unwrap().outstanding_bytes > 0,
            "bulk resumes"
        );
        let mut received = [0; 256];
        assert_eq!(w.stack.tcp_read(id, &mut received), Ok(48));
        let expected: Vec<u8> = (0..24).chain(0..24).collect();
        assert_eq!(&received[..48], expected);
        w.finish();
    }

    #[test]
    fn seed_walks_gro_tso_uso_and_valid_fragment_reassembly() {
        let seeds = seeds();
        let mut r = Reader(&seeds[7]);
        let mut w = World::new();
        while !r.done() {
            step(&mut w, &mut r);
            w.adopt();
            w.stack.check();
        }
        assert!(
            w.rx_gso_packets >= 3,
            "GRO and both USO families reached receive_with"
        );
        assert!(
            w.tx_gso_packets >= 3,
            "TSO and both USO families reached transmit"
        );
        assert!(
            w.reassembled >= 2,
            "both fragment families were fully reassembled"
        );
        w.finish();
    }

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
                    ((x >> 8) % 16) as u8
                });
            }
            check(&data);
        }
    }
}
