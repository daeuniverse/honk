//! A transparent server sending with TSO into a transparent client receiving GRO super-packets,
//! with and without loss: the TX and RX offload paths against each other (and the stack's own
//! recovery against holes inside super-packets).

mod offload_common;

use std::time::{Duration, Instant};

use honk_netstack::{AcceptOpts, FlowId, Rx, Stack, StreamError, TcpState, TxCaps, TxCsum};
use offload_common::*;

struct Pair {
    server: Stack,
    client: Stack,
    sid: FlowId,
    cid: FlowId,
    now: Instant,
    caps: TxCaps,
    /// Drop segment `n` of the server's data stream when `lose(n)`.
    lose: fn(u64) -> bool,
    seg_index: u64,
    highest_seq: Option<u32>,
    tso_packets: u64,
    tso_retransmits: u64,
    super_packets: u64,
    segments: u64,
}

fn pair(caps: TxCaps, lose: fn(u64) -> bool) -> Pair {
    pair_chunk(caps, lose, None)
}

fn pair_chunk(caps: TxCaps, lose: fn(u64) -> bool, chunk: Option<usize>) -> Pair {
    let t0 = Instant::now();
    let mut scfg = transparent();
    scfg.tcp_chunk = chunk;
    let server = Stack::new(scfg, t0);
    let mut cfg = transparent();
    cfg.tcp_chunk = chunk;
    cfg.local_v4 = Some("10.0.0.2".parse().unwrap());
    cfg.secret = [3; 32];
    let mut client = Stack::new(cfg, t0);
    let cid = client.tcp_connect(t0, addr(DST)).unwrap();
    let mut p = Pair {
        server,
        client,
        sid: cid, // replaced below
        cid,
        now: t0,
        caps,
        lose,
        seg_index: 0,
        highest_seq: None,
        tso_packets: 0,
        tso_retransmits: 0,
        super_packets: 0,
        segments: 0,
    };
    // Handshake.
    for _ in 0..20 {
        p.exchange();
        if let Some(info) = p.server.poll_accept() {
            p.server.tcp_accept(info.id, AcceptOpts::default()).unwrap();
            p.sid = info.id;
        }
        p.now += ms(1);
        if p.client.tcp_state(p.cid) == Some(TcpState::Established) {
            break;
        }
    }
    assert_eq!(p.client.tcp_state(p.cid), Some(TcpState::Established));
    p
}

impl Pair {
    /// One round of packet exchange in both directions at `self.now`.
    fn exchange(&mut self) {
        let mut buf = vec![0u8; 70_000];
        let now = self.now;
        // Client to server: ordinary packets (ACKs, the SYN).
        while let Some(n) = self.client.poll_transmit(now, &mut buf) {
            self.server.receive(now, &buf[..n]);
        }
        // Server to client: TSO packets become segments, losses are applied, and the survivors
        // are coalesced back into super-packets as GRO would.
        while let Some(t) = self.server.poll_transmit_with(now, &mut buf, self.caps) {
            let pkt = decode(&buf[..t.len]);
            if pkt.payload.is_empty() {
                assert_eq!(t.gso, None);
                self.client.receive(now, &pkt.raw);
                continue;
            }
            let segs = if t.gso.is_some() {
                assert!(matches!(t.csum, TxCsum::Partial { .. }));
                self.tso_packets += 1;
                if self
                    .highest_seq
                    .is_some_and(|h| (pkt.h.seq.wrapping_sub(h) as i32) < 0)
                {
                    self.tso_retransmits += 1;
                }
                tso_segments(&t, &pkt)
            } else {
                vec![pkt.raw.clone()]
            };
            let end = pkt.h.seq.wrapping_add(pkt.payload.len() as u32);
            if self
                .highest_seq
                .is_none_or(|h| (end.wrapping_sub(h) as i32) > 0)
            {
                self.highest_seq = Some(end);
            }
            let size = t.gso.map_or(0, |g| g.size);
            let mut run: Vec<Vec<u8>> = Vec::new();
            let flush = |client: &mut Stack, run: &mut Vec<Vec<u8>>, stats: &mut (u64, u64)| {
                if run.is_empty() {
                    return;
                }
                if size != 0 && run.len() > 1 {
                    let (b, meta) = gro(run, size);
                    assert_eq!(client.receive_with(now, &b, meta), Rx::Consumed);
                    stats.0 += 1;
                } else {
                    for s in run.iter() {
                        assert_eq!(client.receive(now, s), Rx::Consumed);
                    }
                }
                stats.1 += run.len() as u64;
                run.clear();
            };
            let mut stats = (0, 0);
            for s in segs {
                let idx = self.seg_index;
                self.seg_index += 1;
                if (self.lose)(idx) {
                    flush(&mut self.client, &mut run, &mut stats);
                    continue;
                }
                run.push(s);
            }
            flush(&mut self.client, &mut run, &mut stats);
            self.super_packets += stats.0;
            self.segments += stats.1;
        }
    }

    /// Moves `total` bytes server to client; returns what the client read.
    fn transfer(&mut self, total: usize, rounds: usize) -> Vec<u8> {
        let data = pattern(total, 17);
        let (mut written, mut got) = (0, Vec::new());
        let mut buf = vec![0u8; 100_000];
        for _ in 0..rounds {
            if written < total {
                match self.server.tcp_write(self.sid, &data[written..]) {
                    Ok(n) => written += n,
                    Err(StreamError::WouldBlock) => {}
                    Err(e) => panic!("{e:?}"),
                }
            }
            self.server.handle_timeout(self.now);
            self.client.handle_timeout(self.now);
            self.exchange();
            loop {
                match self.client.tcp_read(self.cid, &mut buf) {
                    Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            self.exchange();
            if got.len() == total {
                break;
            }
            self.now += Duration::from_micros(500);
        }
        assert_eq!(got.len(), total, "the transfer completes");
        assert!(got == data, "and arrives intact");
        got
    }
}

#[test]
fn bulk_transfer_with_tso_and_gro_is_intact_and_cheap() {
    let mut p = pair(TxCaps::ALL, |_| false);
    p.transfer(16 << 20, 100_000);
    let s = p.server.stats();
    let segments = (16u64 << 20) / 1368;
    assert!(p.tso_packets > 0 && p.super_packets > 0);
    assert!(
        s.tx_packets < segments / 3,
        "{} packets for {segments} segments",
        s.tx_packets
    );
    let t = p.server.tcp_stats(p.sid).unwrap();
    assert_eq!((t.retrans_segments, t.rto_count), (0, 0));
    // Fewer packets reached the client than segments were sent: it saw super-packets.
    assert!(p.client.stats().rx_packets < segments / 3);
}

#[test]
fn the_same_transfer_without_caps_sends_every_segment_alone() {
    let mut p = pair(TxCaps::NONE, |_| false);
    p.transfer(4 << 20, 100_000);
    assert_eq!(p.tso_packets, 0);
    assert!(p.server.stats().tx_packets >= (4u64 << 20) / 1368);
}

#[test]
fn single_holes_inside_super_packets_recover_by_sack() {
    let mut p = pair(TxCaps::ALL, |n| n % 37 == 11);
    p.transfer(8 << 20, 400_000);
    let t = p.server.tcp_stats(p.sid).unwrap();
    assert!(t.retrans_segments > 0, "{t:?}");
    assert!(t.loss_events > 0);
    assert!(p.super_packets > 0);
}

#[test]
fn a_lost_run_inside_the_flight_is_retransmitted_as_a_tso_packet() {
    // Eight consecutive segments vanish now and then, the shape of a congested queue.
    let mut p = pair(TxCaps::ALL, |n| n % 400 >= 300 && n % 400 < 308);
    p.transfer(12 << 20, 800_000);
    let t = p.server.tcp_stats(p.sid).unwrap();
    assert!(t.retrans_segments >= 8, "{t:?}");
    assert!(
        p.tso_retransmits > 0,
        "{} TSO packets, none a retransmission: {t:?}",
        p.tso_packets
    );
}

#[test]
fn a_long_burst_of_loss_recovers_too() {
    let mut p = pair(TxCaps::ALL, |n| n % 3000 >= 2000 && n % 3000 < 2100);
    p.transfer(8 << 20, 800_000);
    let t = p.server.tcp_stats(p.sid).unwrap();
    assert!(t.retrans_segments >= 100, "{t:?}");
}

#[test]
fn throughput_paths_work_at_every_chunk_size() {
    // A TSO packet spans 16 chunks of 4 KiB, one of 64 KiB; the stream must not care.
    for chunk in [4096, 8192, 8193, 16384, 65536] {
        let mut p = pair_chunk(TxCaps::ALL, |n| n % 500 == 123, Some(chunk));
        p.transfer(3 << 20, 400_000);
        assert!(p.tso_packets > 0 && p.super_packets > 0, "chunk {chunk}");
        let s = p.server.stats();
        let c = p.client.stats();
        assert!(s.memory_committed <= 256 << 20 && c.memory_committed <= 256 << 20);
    }
}
