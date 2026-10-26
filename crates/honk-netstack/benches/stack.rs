//! Per-packet cost of the TCP fast paths, driven through the public API against a scripted peer,
//! for an active-open flow (`tcp`) and for a flow the transparent terminator accepted
//! (`transparent_tcp`), plus transparent UDP and passive open. Every case reports
//! `Throughput::Elements` so Criterion prints time per packet.
//!
//! `OFFLOAD` is the one-line switch for transparent TCP GRO/TSO; element throughput still counts
//! wire segments, not super-packets. Endpoint/WireGuard and IP-fragmented UDP stay plain.

use std::hint::black_box;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use honk_netstack::wire::{self, tcp};
use honk_netstack::{
    AcceptOpts, Config, Csum, ExcludeSet, FlowId, GsoKind, GsoRx, Mode, Rx, RxMeta, Stack,
    TcpState, TxCaps,
};

/// Config MTU 1420 minus IPv4 and TCP headers; no timestamps are negotiated.
const MSS: usize = 1380;
const MS: Duration = Duration::from_millis(1);
/// Packets prepared (outside the timed region) per timed batch.
const BATCH: u64 = 256;
const OUTSTANDING: u32 = 1000;
/// Toggle only this line for the transparent TCP GSO comparison.
const OFFLOAD: bool = false;
const GRO_SEGMENTS: usize = 32;

fn remote() -> SocketAddr {
    "198.51.100.2:443".parse().unwrap()
}

fn client() -> SocketAddr {
    "10.0.0.2:40000".parse().unwrap()
}

/// What the client dialed; the terminator answers from it.
fn original_dst() -> SocketAddr {
    "203.0.113.9:443".parse().unwrap()
}

fn transparent() -> Config {
    let mut cfg = Config::new([0x38; 32]);
    cfg.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    cfg
}

fn encode(src: SocketAddr, dst: SocketAddr, h: &tcp::Header, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; payload.len() + 128];
    let n = tcp::emit_packet(&mut buf, src.ip(), dst.ip(), h, [payload, &[]]).unwrap();
    buf.truncate(n);
    buf
}

struct Flow {
    stack: Stack,
    id: FlowId,
    local: SocketAddr,
    /// The other end: `remote()` for an active open, the client for an accepted flow.
    peer: SocketAddr,
    transparent: bool,
    now: Instant,
    /// Next sequence number the stack will send.
    snd_nxt: u32,
    /// Next sequence number the peer will send.
    peer_next: u32,
    out: Vec<u8>,
}

impl Flow {
    /// Handshake with a 10 ms RTT, SACK and a window-scale-7 peer so 1000 segments fit its window.
    fn connect() -> Flow {
        let mut cfg = Config::new([0x37; 32]);
        cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
        let local_ip = IpAddr::V4(cfg.local_v4.unwrap());
        let mut now = Instant::now();
        let mut stack = Stack::new(cfg, now);
        let id = stack.tcp_connect(now, remote()).unwrap();
        let mut out = vec![0u8; 2048];
        let n = stack.poll_transmit(now, &mut out).expect("SYN");
        let ip = wire::parse_ip(&out[..n]).unwrap();
        let (syn, _) = tcp::parse(&out[ip.payload.clone()]).unwrap();
        let mut flow = Flow {
            stack,
            id,
            local: SocketAddr::new(local_ip, syn.src_port),
            peer: remote(),
            transparent: false,
            now,
            snd_nxt: syn.seq.wrapping_add(1),
            peer_next: 0x1020_3041,
            out,
        };
        let mut h = flow.header(flow.snd_nxt);
        h.seq = flow.peer_next.wrapping_sub(1);
        h.flags |= tcp::SYN;
        h.options.mss = Some(MSS as u16);
        h.options.wscale = Some(7);
        h.options.sack_permitted = true;
        now += 10 * MS;
        flow.now = now;
        let packet = flow.encode(&h, &[]);
        assert_eq!(flow.stack.receive(now, &packet), Rx::Consumed);
        assert_eq!(flow.stack.tcp_state(id), Some(TcpState::Established));
        assert!(flow.stack.poll_transmit(now, &mut flow.out).is_some());
        flow
    }

    /// Passive open through a transparent stack: the scripted client dials `original_dst()` with
    /// the same SYN options as `connect`'s peer and the application accepts at once.
    fn accept() -> Flow {
        let mut now = Instant::now();
        let mut stack = Stack::new(transparent(), now);
        let mut syn = tcp::Header {
            src_port: client().port(),
            dst_port: original_dst().port(),
            seq: 0x1020_3040,
            ack: 0,
            flags: tcp::SYN,
            window: u16::MAX,
            urgent: 0,
            options: tcp::Options::default(),
        };
        syn.options.mss = Some(MSS as u16);
        syn.options.wscale = Some(7);
        syn.options.sack_permitted = true;
        let packet = encode(client(), original_dst(), &syn, &[]);
        assert_eq!(stack.receive(now, &packet), Rx::Consumed);
        let info = stack.poll_accept().expect("the SYN is reported");
        stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
        let mut out = vec![0u8; 65535];
        let n = stack.poll_transmit(now, &mut out).expect("SYN-ACK");
        let ip = wire::parse_ip(&out[..n]).unwrap();
        let (synack, _) = tcp::parse(&out[ip.payload.clone()]).unwrap();
        let mut flow = Flow {
            stack,
            id: info.id,
            local: original_dst(),
            peer: client(),
            transparent: true,
            now,
            snd_nxt: synack.seq.wrapping_add(1),
            peer_next: syn.seq.wrapping_add(1),
            out,
        };
        now += 10 * MS;
        flow.now = now;
        let ack = flow.encode(&flow.header(flow.snd_nxt), &[]);
        assert_eq!(flow.stack.receive(now, &ack), Rx::Consumed);
        assert_eq!(flow.stack.tcp_state(info.id), Some(TcpState::Established));
        while flow.stack.poll_transmit(now, &mut flow.out).is_some() {}
        flow
    }

    fn header(&self, ack: u32) -> tcp::Header {
        tcp::Header {
            src_port: self.peer.port(),
            dst_port: self.local.port(),
            seq: self.peer_next,
            ack,
            flags: tcp::ACK,
            window: u16::MAX,
            urgent: 0,
            options: tcp::Options::default(),
        }
    }

    fn encode(&self, h: &tcp::Header, payload: &[u8]) -> Vec<u8> {
        encode(self.peer, self.local, h, payload)
    }

    fn ack_packet(&self, ack: u32, blocks: &[(u32, u32)]) -> Vec<u8> {
        let mut h = self.header(ack);
        for &(l, r) in blocks {
            h.options.sack.push(l, r);
        }
        self.encode(&h, &[])
    }

    /// The next in-order full segment from the peer.
    fn data_packet(&mut self, payload: &[u8]) -> Vec<u8> {
        let packet = self.encode(&self.header(self.snd_nxt), payload);
        self.peer_next = self.peer_next.wrapping_add(payload.len() as u32);
        packet
    }

    /// Pulls exactly `segments` full segments, letting time pass only for pacing gaps.
    fn send(&mut self, segments: usize) {
        let mut sent = 0;
        while sent < segments {
            let caps = if OFFLOAD && self.transparent {
                TxCaps::ALL
            } else {
                TxCaps::NONE
            };
            if let Some(tx) = self.stack.poll_transmit_with(self.now, &mut self.out, caps) {
                let n = (tx.len - 40) / MSS;
                assert!(n > 0 && sent + n <= segments);
                assert_eq!(tx.len, 40 + n * MSS, "whole full-sized wire segments");
                assert_eq!(tx.gso.is_some(), n > 1);
                sent += n;
                continue;
            }
            match self.stack.poll_timeout() {
                Some(at) if at.saturating_duration_since(self.now) <= 5 * MS => {
                    self.now = at.max(self.now);
                    self.stack.handle_timeout(self.now);
                }
                _ => panic!("transmit stalled after {sent} of {segments} segments"),
            }
        }
        self.snd_nxt = self.snd_nxt.wrapping_add((segments * MSS) as u32);
    }

    /// Peer acknowledges everything sent, one RTT after the last transmission.
    fn ack_all(&mut self) {
        self.now += 10 * MS;
        let packet = self.ack_packet(self.snd_nxt, &[]);
        assert_eq!(self.stack.receive(self.now, &packet), Rx::Consumed);
    }

    /// Opens the congestion window to `segments` full segments with healthy slow-start rounds.
    fn grow(&mut self, segments: u32) {
        let data = vec![0xa5u8; segments as usize * MSS];
        while self.stack.tcp_stats(self.id).unwrap().cwnd < segments * MSS as u32 {
            let round = self.stack.tcp_stats(self.id).unwrap().cwnd as usize / MSS;
            assert_eq!(
                self.stack.tcp_write(self.id, &data[..round * MSS]),
                Ok(round * MSS)
            );
            self.send(round);
            self.ack_all();
        }
    }
}

/// The flavours every TCP case runs for: an active-open client and a transparent terminator.
type Make = fn() -> Flow;
const FLAVOURS: [(&str, Make); 2] = [
    ("tcp", Flow::connect),
    (
        if OFFLOAD {
            "transparent_tcp_gso"
        } else {
            "transparent_tcp"
        },
        Flow::accept,
    ),
];

/// Feeds in-order segments to the stack, reading and answering each (the offload seam for RX).
fn deliver(f: &mut Flow, packets: &[Vec<u8>], read: &mut [u8]) {
    for p in packets {
        let meta = if OFFLOAD && f.transparent {
            RxMeta {
                csum: Csum::Verify,
                gso: Some(GsoRx {
                    kind: GsoKind::Tcp,
                    size: MSS as u16,
                }),
            }
        } else {
            RxMeta::VERIFY
        };
        assert_eq!(f.stack.receive_with(f.now, p, meta), Rx::Consumed);
        black_box(f.stack.tcp_read(f.id, read).unwrap());
        while f.stack.poll_transmit(f.now, &mut f.out).is_some() {}
    }
}

fn receive_and_ack(c: &mut Criterion) {
    for (group, make) in FLAVOURS {
        let mut g = c.benchmark_group(group);
        g.throughput(Throughput::Elements(1));
        g.bench_function("receive_in_order_and_ack", |b| {
            b.iter_custom(|iters| {
                let mut f = make();
                let gro = if OFFLOAD && f.transparent {
                    GRO_SEGMENTS
                } else {
                    1
                };
                let payload = vec![0x5au8; gro * MSS];
                let mut read = vec![0u8; 64 * 1024];
                let mut elapsed = Duration::ZERO;
                let mut left = iters;
                while left > 0 {
                    let n = left.min(BATCH);
                    let packets: Vec<Vec<u8>> = (0..n as usize)
                        .step_by(gro)
                        .map(|i| {
                            let count = gro.min(n as usize - i);
                            f.data_packet(&payload[..count * MSS])
                        })
                        .collect();
                    let t = Instant::now();
                    deliver(&mut f, &packets, &mut read);
                    elapsed += t.elapsed();
                    left -= n;
                }
                elapsed
            })
        });
        g.finish();
    }
}

fn transmit_bulk(c: &mut Criterion) {
    for (group, make) in FLAVOURS {
        let mut g = c.benchmark_group(group);
        g.throughput(Throughput::Elements(1));
        g.bench_function("poll_transmit_full_segments", |b| {
            b.iter_custom(|iters| {
                let mut f = make();
                f.grow(2 * BATCH as u32);
                let data = vec![0xa5u8; BATCH as usize * MSS];
                let mut elapsed = Duration::ZERO;
                let mut left = iters;
                while left > 0 {
                    let n = left.min(BATCH) as usize;
                    assert_eq!(f.stack.tcp_write(f.id, &data[..n * MSS]), Ok(n * MSS));
                    let t = Instant::now();
                    f.send(n);
                    elapsed += t.elapsed();
                    f.ack_all();
                    left -= n as u64;
                }
                elapsed
            })
        });
        g.finish();
    }
}

/// SYN to SYN-ACK for `BATCH` fresh clients: classify, create the pending flow, report it,
/// accept it and emit the SYN-ACK.
fn passive_open(c: &mut Criterion) {
    let mut g = c.benchmark_group("transparent_tcp");
    g.throughput(Throughput::Elements(BATCH));
    g.bench_function("syn_accept_synack", |b| {
        b.iter_batched(
            || {
                let syns: Vec<Vec<u8>> = (0..BATCH as u16)
                    .map(|i| {
                        // One address each: the per-source half-open cap is not under test.
                        let ip = std::net::Ipv4Addr::new(10, 0, 1, i as u8);
                        let src = SocketAddr::new(ip.into(), 20_000 + i);
                        let h = tcp::Header {
                            src_port: src.port(),
                            dst_port: original_dst().port(),
                            seq: 0x1000 + u32::from(i),
                            ack: 0,
                            flags: tcp::SYN,
                            window: u16::MAX,
                            urgent: 0,
                            options: tcp::Options {
                                mss: Some(MSS as u16),
                                ..tcp::Options::default()
                            },
                        };
                        encode(src, original_dst(), &h, &[])
                    })
                    .collect();
                (
                    Stack::new(transparent(), Instant::now()),
                    syns,
                    vec![0u8; 2048],
                )
            },
            |(mut stack, syns, mut out)| {
                let now = Instant::now();
                for p in &syns {
                    assert_eq!(stack.receive(now, p), Rx::Consumed);
                    let info = stack.poll_accept().expect("reported");
                    stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
                    black_box(stack.poll_transmit(now, &mut out).expect("SYN-ACK"));
                }
                (stack, syns, out)
            },
            BatchSize::PerIteration,
        )
    });
    g.finish();
}

/// Every packet of a `len`-byte transparent datagram from `original_dst()` to `client()`.
fn datagram_packets(len: usize) -> Vec<Vec<u8>> {
    let mut tx = Stack::new(transparent(), Instant::now());
    let mut out = vec![0u8; 2048];
    let n = tx
        .udp_send_from(original_dst(), client(), &vec![0x33u8; len], &mut out)
        .unwrap();
    let mut packets = vec![out[..n].to_vec()];
    while let Some(n) = tx.poll_transmit(Instant::now(), &mut out) {
        packets.push(out[..n].to_vec());
    }
    packets
}

fn transparent_udp(c: &mut Criterion) {
    let mut g = c.benchmark_group("transparent_udp");
    let now = Instant::now();
    let endpoints = (original_dst(), client());
    for (name, len) in [("1200_byte", 1200usize), ("4000_byte_fragmented", 4000)] {
        let packets = datagram_packets(len);
        let count = packets.len() as u64;
        assert_eq!(count > 1, len > 1400, "{len}");
        g.throughput(Throughput::Elements(count));
        g.bench_function(format!("receive_{name}"), |b| {
            let mut rx = Stack::new(transparent(), now);
            b.iter(|| {
                for (i, p) in packets.iter().enumerate() {
                    let result = rx.receive(now, p);
                    if i + 1 < packets.len() {
                        assert_eq!(result, Rx::Consumed);
                    } else {
                        match result {
                            Rx::Transparent { src, dst, payload }
                            | Rx::TransparentOwned {
                                src, dst, payload, ..
                            } => {
                                assert_eq!((src, dst), endpoints);
                                assert_eq!(payload.len(), len);
                                black_box(payload);
                            }
                            other => panic!("datagram was not delivered: {other:?}"),
                        }
                    }
                }
            })
        });
        g.bench_function(format!("send_from_{name}"), |b| {
            let mut tx = Stack::new(transparent(), now);
            let payload = vec![0x33u8; len];
            let mut out = vec![0u8; 2048];
            b.iter(|| {
                black_box(
                    tx.udp_send_from(endpoints.0, endpoints.1, &payload, &mut out)
                        .unwrap(),
                );
                let mut emitted = 1;
                while let Some(n) = tx.poll_transmit(now, &mut out) {
                    black_box(n);
                    emitted += 1;
                }
                assert_eq!(emitted, count, "every fragment must be emitted");
            })
        });
    }
    g.finish();
}

/// `OUTSTANDING` segments in flight, segment 0 lost (the cumulative ACK never moves) and every
/// ACK carrying SACK blocks over the flight. `blocks(i, una)` builds the options of the i-th ACK.
fn sack_ack_stream(
    c: &mut Criterion,
    name: &str,
    acks: u32,
    blocks: impl Fn(u32, u32) -> Vec<(u32, u32)>,
) {
    let mut g = c.benchmark_group("tcp");
    g.throughput(Throughput::Elements(u64::from(acks)));
    g.bench_function(name, |b| {
        b.iter_batched(
            || {
                let mut f = Flow::connect();
                f.grow(OUTSTANDING + 100);
                let una = f.snd_nxt;
                let data = vec![0xa5u8; OUTSTANDING as usize * MSS];
                assert_eq!(f.stack.tcp_write(f.id, &data), Ok(data.len()));
                f.send(OUTSTANDING as usize);
                f.now += 10 * MS;
                let packets: Vec<Vec<u8>> = (0..acks)
                    .map(|i| f.ack_packet(una, &blocks(i, una)))
                    .collect();
                (f, packets)
            },
            |(mut f, packets)| {
                for p in &packets {
                    black_box(f.stack.receive(f.now, p));
                }
                assert!(f.stack.tcp_stats(f.id).unwrap().sacked_bytes > 0);
                (f, packets)
            },
            BatchSize::PerIteration,
        )
    });
    g.finish();
}

/// Left edge of segment `i` after the cumulative ACK point.
fn seg(una: u32, i: u32) -> u32 {
    una.wrapping_add(i * MSS as u32)
}

fn sack_processing(c: &mut Criterion) {
    // Four wide blocks, repeated unchanged: the scoreboard walk without new information.
    sack_ack_stream(c, "sack_1000_wide_blocks", OUTSTANDING, |_, una| {
        (0..4)
            .map(|j| (seg(una, 250 * j + 1), seg(una, 250 * j + 250)))
            .collect()
    });
    // Four blocks each growing by one segment per ACK until they are 249 segments wide.
    sack_ack_stream(c, "sack_1000_extending_blocks", 996, |i, una| {
        (0..4)
            .filter_map(|j| {
                let width = (i + 4 - j) / 4;
                (width > 0).then(|| (seg(una, 250 * j + 1), seg(una, 250 * j + 1 + width)))
            })
            .collect()
    });
}

criterion_group!(
    benches,
    receive_and_ack,
    transmit_bulk,
    sack_processing,
    passive_open,
    transparent_udp
);
criterion_main!(benches);
