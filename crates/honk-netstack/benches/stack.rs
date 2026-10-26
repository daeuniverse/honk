//! Per-packet cost of the TCP fast paths, driven through the public API against a scripted peer.
//! Every case reports `Throughput::Elements` so Criterion prints time per packet.

use std::hint::black_box;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use honk_netstack::wire::{self, tcp};
use honk_netstack::{Config, FlowId, Rx, Stack, TcpState};

/// Config MTU 1420 minus IPv4 and TCP headers; no timestamps are negotiated.
const MSS: usize = 1380;
const MS: Duration = Duration::from_millis(1);
/// Packets prepared (outside the timed region) per timed batch.
const BATCH: u64 = 256;
const OUTSTANDING: u32 = 1000;

fn remote() -> SocketAddr {
    "198.51.100.2:443".parse().unwrap()
}

struct Flow {
    stack: Stack,
    id: FlowId,
    local: SocketAddr,
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

    fn header(&self, ack: u32) -> tcp::Header {
        tcp::Header {
            src_port: remote().port(),
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
        let mut buf = vec![0u8; payload.len() + 128];
        let n =
            tcp::emit_packet(&mut buf, remote().ip(), self.local.ip(), h, [payload, &[]]).unwrap();
        buf.truncate(n);
        buf
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
            if let Some(n) = self.stack.poll_transmit(self.now, &mut self.out) {
                assert_eq!(n, 40 + MSS, "a full segment");
                sent += 1;
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

fn receive_and_ack(c: &mut Criterion) {
    let mut g = c.benchmark_group("tcp");
    g.throughput(Throughput::Elements(1));
    g.bench_function("receive_in_order_and_ack", |b| {
        b.iter_custom(|iters| {
            let mut f = Flow::connect();
            let payload = vec![0x5au8; MSS];
            let mut read = vec![0u8; 64 * 1024];
            let mut elapsed = Duration::ZERO;
            let mut left = iters;
            while left > 0 {
                let n = left.min(BATCH);
                let packets: Vec<Vec<u8>> = (0..n).map(|_| f.data_packet(&payload)).collect();
                let t = Instant::now();
                for p in &packets {
                    assert_eq!(f.stack.receive(f.now, p), Rx::Consumed);
                    black_box(f.stack.tcp_read(f.id, &mut read).unwrap());
                    while f.stack.poll_transmit(f.now, &mut f.out).is_some() {}
                }
                elapsed += t.elapsed();
                left -= n;
            }
            elapsed
        })
    });
    g.finish();
}

fn transmit_bulk(c: &mut Criterion) {
    let mut g = c.benchmark_group("tcp");
    g.throughput(Throughput::Elements(1));
    g.bench_function("poll_transmit_full_segments", |b| {
        b.iter_custom(|iters| {
            let mut f = Flow::connect();
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

criterion_group!(benches, receive_and_ack, transmit_bulk, sack_processing);
criterion_main!(benches);
