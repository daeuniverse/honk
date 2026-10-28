//! Shared helpers of the `offload_*` tests: a scripted client against a transparent stack, an
//! independent model of what a kernel does with TSO/GRO packets, and an independent checksum.

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use honk_netstack::wire::tcp::{self, ACK, FIN, Header, Options, PSH, SYN};
use honk_netstack::wire::{self, PROTO_TCP};
use honk_netstack::{
    AcceptOpts, Config, Csum, ExcludeSet, FlowId, GsoKind, GsoRx, GsoTx, Mode, Rx, RxMeta, Stack,
    TcpState, Transmit, TxCaps, TxCsum,
};

pub const DST: &str = "203.0.113.9:443";
pub const CLIENT: &str = "10.0.0.2:40000";
pub const DST6: &str = "[2001:db8::9]:443";
pub const CLIENT6: &str = "[fd00::2]:40000";

pub fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

pub fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

pub fn transparent() -> Config {
    let mut cfg = Config::new([9; 32]);
    cfg.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    cfg.memory_limit = 256 * 1024 * 1024;
    cfg.max_flows = 64;
    cfg
}

pub fn pattern(n: usize, seed: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(31).wrapping_add(seed) >> 1) as u8)
        .collect()
}

/// RFC 1071 sum of `data`, folded, not complemented, written independently of the crate.
pub fn sum16(data: &[u8], init: u32) -> u16 {
    let mut s = u64::from(init);
    for c in data.chunks(2) {
        s += if c.len() == 2 {
            u64::from(u16::from_be_bytes([c[0], c[1]]))
        } else {
            u64::from(c[0]) << 8
        };
    }
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    s as u16
}

/// The pseudo-header sum a `CHECKSUM_PARTIAL` packet carries: folded, not complemented.
pub fn pseudo_seed(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u16 {
    let mut b = Vec::new();
    for a in [src, dst] {
        match a {
            IpAddr::V4(a) => b.extend_from_slice(&a.octets()),
            IpAddr::V6(a) => b.extend_from_slice(&a.octets()),
        }
    }
    if src.is_ipv4() {
        b.extend_from_slice(&[0, proto]);
        b.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        b.extend_from_slice(&(len as u32).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, proto]);
    }
    sum16(&b, 0)
}

/// What the NIC or kernel does with `CHECKSUM_PARTIAL`: sum from `start`, seeded by the field.
pub fn complete_checksum(packet: &mut [u8], start: usize, offset: usize) {
    let sum = sum16(&packet[start..], 0);
    packet[start + offset..start + offset + 2].copy_from_slice(&(!sum).to_be_bytes());
}

pub fn opts_syn(mss: u16) -> Options {
    Options {
        mss: Some(mss),
        wscale: Some(7),
        sack_permitted: true,
        timestamps: Some((5000, 0)),
        ..Options::default()
    }
}

pub fn build(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    options: Options,
    data: &[u8],
) -> Vec<u8> {
    build_win(src, dst, (seq, ack), flags, options, data, 60000)
}

pub fn build_win(
    src: SocketAddr,
    dst: SocketAddr,
    (seq, ack): (u32, u32),
    flags: u8,
    options: Options,
    data: &[u8],
    window: u16,
) -> Vec<u8> {
    let mut bytes = vec![0u8; data.len() + 120];
    let n = tcp::emit_packet(
        &mut bytes,
        src.ip(),
        dst.ip(),
        &Header {
            src_port: src.port(),
            dst_port: dst.port(),
            seq,
            ack,
            flags,
            window,
            urgent: 0,
            options,
        },
        [data, &[]],
    )
    .unwrap();
    bytes.truncate(n);
    bytes
}

/// A decoded TCP packet; the checksum is not checked here (a TSO packet has only the seed).
#[derive(Clone, Debug)]
pub struct Pkt {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub h: Header,
    pub payload: Vec<u8>,
    pub ip_len: usize,
    pub tcp_len: usize,
    pub raw: Vec<u8>,
}

pub fn decode(bytes: &[u8]) -> Pkt {
    let ip = wire::parse_ip(bytes).unwrap();
    assert_eq!(ip.proto, PROTO_TCP);
    let seg = &bytes[ip.payload.clone()];
    let (h, off) = tcp::parse(seg).unwrap();
    Pkt {
        src: SocketAddr::new(ip.src, h.src_port),
        dst: SocketAddr::new(ip.dst, h.dst_port),
        h,
        payload: seg[off..].to_vec(),
        ip_len: ip.payload.start,
        tcp_len: off,
        raw: bytes.to_vec(),
    }
}

/// Everything a stack has ready, with the descriptor each packet came with.
pub fn drain(stack: &mut Stack, now: Instant, caps: TxCaps) -> Vec<(Transmit, Pkt)> {
    let mut all = Vec::new();
    let mut buf = vec![0u8; 70_000];
    while let Some(t) = stack.poll_transmit_with(now, &mut buf, caps) {
        all.push((t, decode(&buf[..t.len])));
    }
    all
}

/// The packets a kernel's GSO would cut a TSO packet into: complete, checksummed, with PSH/FIN
/// only on the last one.
pub fn tso_segments(t: &Transmit, p: &Pkt) -> Vec<Vec<u8>> {
    let gso: GsoTx = t.gso.expect("a TSO packet");
    assert_eq!(gso.kind, GsoKind::Tcp);
    assert_eq!(usize::from(gso.hdr_len), p.ip_len + p.tcp_len);
    let size = usize::from(gso.size);
    let n = p.payload.len().div_ceil(size);
    let mut out = Vec::new();
    for (i, chunk) in p.payload.chunks(size).enumerate() {
        let mut h = p.h;
        h.seq = p.h.seq.wrapping_add((i * size) as u32);
        if i + 1 != n {
            h.flags &= !(FIN | PSH);
        }
        let mut b = vec![0u8; chunk.len() + 120];
        let len = tcp::emit_packet(&mut b, p.src.ip(), p.dst.ip(), &h, [chunk, &[]]).unwrap();
        b.truncate(len);
        out.push(b);
    }
    out
}

/// What GRO builds from consecutive in-order segments of one flow: one header, the payloads
/// concatenated, the checksum field holding the pseudo-header sum over the new length.
pub fn gro(segments: &[Vec<u8>], size: u16) -> (Vec<u8>, RxMeta) {
    let first = decode(&segments[0]);
    let last = decode(segments.last().unwrap());
    let mut payload = Vec::new();
    for s in segments {
        payload.extend_from_slice(&decode(s).payload);
    }
    let mut h = first.h;
    h.flags = last.h.flags;
    let mut b = build(
        first.src, first.dst, h.seq, h.ack, h.flags, h.options, &payload,
    );
    let start = first.ip_len;
    let len = b.len() - start;
    let seed = pseudo_seed(first.src.ip(), first.dst.ip(), PROTO_TCP, len);
    b[start + 16..start + 18].copy_from_slice(&seed.to_be_bytes());
    (
        b,
        RxMeta {
            csum: Csum::Partial {
                start: start as u16,
                offset: 16,
            },
            gso: Some(GsoRx {
                kind: GsoKind::Tcp,
                size,
            }),
        },
    )
}

/// A scripted client talking to a transparent stack through one accepted flow.
pub struct Conn {
    pub stack: Stack,
    pub id: FlowId,
    pub client: SocketAddr,
    pub dst: SocketAddr,
    pub now: Instant,
    /// The client's next sequence number.
    pub seq: u32,
    pub ts: u32,
    /// The stack's next sequence number as the client knows it (acknowledged by the client).
    pub snd: u32,
    pub tsval: u32,
    pub caps: TxCaps,
    /// The window the client advertises (scaled by 7).
    pub window: u16,
}

impl Conn {
    pub fn new(cfg: Config) -> Conn {
        Conn::with_addrs(cfg, CLIENT, DST)
    }

    pub fn with_addrs(cfg: Config, client: &str, dst: &str) -> Conn {
        Self::with_addrs_opts(cfg, client, dst, AcceptOpts::default())
    }

    pub fn with_opts(cfg: Config, opts: AcceptOpts) -> Conn {
        Self::with_addrs_opts(cfg, CLIENT, DST, opts)
    }

    fn with_addrs_opts(cfg: Config, client: &str, dst: &str, opts: AcceptOpts) -> Conn {
        let t0 = Instant::now();
        let mut stack = Stack::new(cfg, t0);
        let (client, dst) = (addr(client), addr(dst));
        let mss = if client.is_ipv4() { 1460 } else { 1440 };
        let syn = build(client, dst, 1000, 0, SYN, opts_syn(mss), &[]);
        assert_eq!(stack.receive(t0, &syn), Rx::Consumed);
        let info = stack.poll_accept().expect("SynInfo");
        stack.tcp_accept(info.id, opts).unwrap();
        let out = drain(&mut stack, t0, TxCaps::NONE);
        assert_eq!(out.len(), 1);
        let synack = &out[0].1;
        assert_eq!(synack.h.flags, SYN | ACK);
        let mut c = Conn {
            stack,
            id: info.id,
            client,
            dst,
            now: t0 + ms(5),
            seq: 1001,
            ts: 5000,
            snd: synack.h.seq.wrapping_add(1),
            tsval: synack.h.options.timestamps.unwrap().0,
            caps: TxCaps::NONE,
            window: 60000,
        };
        c.client_ack(&[]);
        assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::Established));
        c
    }

    /// Builds a client segment without delivering it.
    pub fn client_pkt(&mut self, flags: u8, data: &[u8], sack: &[(u32, u32)]) -> Vec<u8> {
        self.ts += 1;
        let mut o = Options {
            timestamps: Some((self.ts, self.tsval)),
            ..Options::default()
        };
        for &(l, r) in sack {
            o.sack.push(l, r);
        }
        let b = build_win(
            self.client,
            self.dst,
            (self.seq, self.snd),
            flags,
            o,
            data,
            self.window,
        );
        self.seq = self.seq.wrapping_add(data.len() as u32);
        b
    }

    /// A pure ACK from the client acknowledging everything up to `self.snd`.
    pub fn client_ack(&mut self, sack: &[(u32, u32)]) -> Rx {
        let b = self.client_pkt(ACK, &[], sack);
        self.stack.receive(self.now, &b)
    }

    /// An ACK for `ack` (and SACK blocks), refreshing the timestamp echo.
    pub fn ack_to(&mut self, ack: u32, sack: &[(u32, u32)]) {
        self.snd = ack;
        self.client_ack(sack);
    }

    pub fn drain(&mut self) -> Vec<(Transmit, Pkt)> {
        drain(&mut self.stack, self.now, self.caps)
    }

    /// Updates the echo the client would reflect from the newest packet it saw.
    pub fn echo(&mut self, p: &Pkt) {
        if let Some((v, _)) = p.h.options.timestamps {
            self.tsval = v;
        }
    }
}

/// An ordinary packet's descriptor.
pub fn plain(len: usize, flow: Option<FlowId>) -> Transmit {
    Transmit {
        len,
        gso: None,
        csum: TxCsum::Full,
        flow,
    }
}
