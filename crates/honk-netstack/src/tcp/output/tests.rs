use std::io::ErrorKind::{self, BrokenPipe, WouldBlock};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use crate::tcp::ring::TRANSPARENT_CHUNK;
use crate::tcp::sent::{Acked, FLOOR_SLOTS, RETRANS};
use crate::{Config, FlowId, MemoryBudget, SourceContext};

use super::*;

const MAX_LEN: usize = u16::MAX as usize;
const IDENTITY: Transmit = Transmit {
    len: 0,
    gso: None,
    csum: TxCsum::Full,
    flow: Some(FlowId {
        idx: 3,
        generation: 2,
    }),
    source: Some(SourceContext {
        lineage: NonZeroU64::new(1).unwrap(),
        snapshot: NonZeroU64::new(5).unwrap(),
    }),
};

struct Rig {
    t: Tcb,
    pool: Pool,
    budget: Arc<MemoryBudget>,
    now: Instant,
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    budget: (usize, usize, usize, (u64, u64)),
    sequence: (u32, u32, Option<u32>, usize),
    advertised_right: [u32; 2],
    last_ack_sent: u32,
    ack_due: u8,
    full_segments: u8,
    ooo_acks: u16,
    dsack: Option<(u32, u32)>,
    sent: ([u32; 6], usize, Vec<Descriptor>),
    rack: Option<(usize, Vec<(u32, Instant)>)>,
    tlp: (bool, Option<(u32, bool)>, u32),
    pacer: Pacer,
    deadlines: [Option<Instant>; 4],
    congestion: (u32, u32, bool),
    recovery: (crate::tcp::recovery::State, u32, Option<u32>, u64, u32),
    stamps: (Instant, Instant, Instant, u64),
    control: (bool, bool, bool, Option<Instant>, bool),
}

#[derive(Debug, PartialEq, Eq)]
struct Packet {
    bytes: Vec<u8>,
    parts: usize,
    info: Transmit,
}

impl Packet {
    fn tcp(&self) -> (Header, &[u8]) {
        let ip = wire::parse_ip(&self.bytes).unwrap();
        let segment = &self.bytes[ip.payload];
        if self.info.csum == TxCsum::Full {
            assert!(wire_tcp::verify_checksum(ip.src, ip.dst, segment));
        }
        let (header, len) = wire_tcp::parse(segment).unwrap();
        (header, &segment[len..])
    }
}

impl Rig {
    fn new() -> Self {
        let now = Instant::now();
        let tuple = FourTuple {
            local: "192.0.2.1:40000".parse().unwrap(),
            remote: "198.51.100.1:443".parse().unwrap(),
        };
        let mut cfg = Config::new([1; 32]);
        cfg.tcp_chunk = Some(TRANSPARENT_CHUNK);
        let t = Tcb::new(tuple, &cfg, now, now, 100, 200);
        let budget = MemoryBudget::new(1024 * 1024);
        let mut pool = Pool::new(64)
            .with_chunk(cfg.chunk())
            .with_budget(Some(Arc::clone(&budget)))
            .with_index_accounting();
        assert!(pool.admit_floor());
        Self {
            t,
            pool,
            budget,
            now,
        }
    }

    fn established() -> Self {
        let mut rig = Self::new();
        let t = &mut rig.t;
        t.state = TcpState::Established;
        t.syn_due = false;
        t.syn_sent = Some(rig.now);
        t.snd_una = t.iss + 1;
        t.snd_nxt = t.snd_una;
        t.peer_mss = 1460;
        t.timestamps = true;
        t.rcv_nxt = 9001;
        t.committed_right = t.rcv_nxt + TRANSPARENT_CHUNK as u32;
        t.max_adv_right = t.rcv_nxt;
        t.last_adv_right = t.rcv_nxt;
        rig
    }

    fn snapshot(&self) -> Snapshot {
        let t = &self.t;
        let s = &t.sent;
        let r = &t.recovery;
        Snapshot {
            budget: (
                self.budget.used(),
                self.pool.shared_bytes(),
                self.pool.allocated_bytes(),
                self.pool.release_epochs(),
            ),
            sequence: (t.snd_una, t.snd_nxt, t.fin_seq, t.tx.len()),
            advertised_right: [t.max_adv_right, t.last_adv_right],
            last_ack_sent: t.last_ack_sent,
            ack_due: t.ack_due,
            full_segments: t.full_segments,
            ooo_acks: t.ooo_acks,
            dsack: t.dsack,
            sent: (
                [
                    s.start,
                    s.outstanding,
                    s.sacked,
                    s.lost,
                    s.retrans,
                    s.retrans_cursor,
                ],
                s.queue.capacity(),
                s.queue.iter().cloned().collect(),
            ),
            rack: r
                .rack
                .retransmit_entries()
                .map(|q| (q.capacity(), q.iter().copied().collect())),
            tlp: (
                t.tlp_due,
                r.rack.tlp.map(|p| (p.high_seq, p.retransmit)),
                r.counters.tlp_probes,
            ),
            pacer: t.pacer,
            deadlines: [
                t.rto_deadline,
                t.delack_deadline,
                t.tlp_deadline,
                t.pacing_deadline,
            ],
            congestion: (t.cc.cwnd(), t.cc.ssthresh(), t.cwnd_limited),
            recovery: (
                r.state(),
                r.budget(r.pipe(s, t.sack), t.cc.cwnd()),
                r.retrans_stamp(),
                t.stats.retrans_bytes,
                t.stats.retrans_segments,
            ),
            stamps: (
                t.first_tx_ts,
                t.delivered_ts,
                t.last_data_tx,
                t.app_limited_until,
            ),
            control: (t.syn_due, t.rst_pending, t.probe_due, t.syn_sent, t.persist),
        }
    }

    fn write(&mut self, data: &[u8]) {
        assert_eq!(self.t.write(&mut self.pool, data), Ok(data.len()));
    }

    fn send_contiguous(&mut self) {
        let mut out = [0; 1500];
        assert!(matches!(
            self.t.output(self.now, &mut out, &mut self.pool),
            Output::Sent(_)
        ));
    }

    fn no_emit(&mut self, max_len: usize, caps: TxCaps) -> IovTransmit {
        self.t
            .output_iov::<ErrorKind>(
                self.now,
                max_len,
                &mut self.pool,
                caps,
                true,
                IDENTITY,
                &mut |_, _, _| panic!("maintenance or refusal called the sink"),
            )
            .unwrap()
    }

    fn retry(&mut self, caps: TxCaps, payload_allowed: bool, borrowed: (usize, usize)) -> Packet {
        let before = self.snapshot();
        let expected_parts: Vec<_> = {
            let (slices, n) = self.t.tx.slices(borrowed.0, borrowed.1);
            slices[..n]
                .iter()
                .map(|slice| (slice.as_ptr(), slice.len()))
                .collect()
        };
        let mut expected = None;
        for fault in [Some(WouldBlock), Some(BrokenPipe), None] {
            let mut offered = None;
            let result = self.t.output_iov(
                self.now,
                MAX_LEN,
                &mut self.pool,
                caps,
                payload_allowed,
                IDENTITY,
                &mut |header, parts, info| {
                    assert!(offered.is_none(), "more than one callback per pull");
                    assert_eq!(parts.len(), expected_parts.len());
                    let mut bytes = header.to_vec();
                    for (part, &(ptr, len)) in parts.iter().zip(&expected_parts) {
                        assert_eq!((part.as_ptr(), part.len()), (ptr, len));
                        bytes.extend_from_slice(part);
                    }
                    assert_eq!(bytes.len(), info.len);
                    assert_eq!((info.flow, info.source), (IDENTITY.flow, IDENTITY.source));
                    offered = Some(Packet {
                        bytes,
                        parts: parts.len(),
                        info,
                    });
                    fault.map_or(Ok(()), Err)
                },
            );
            let packet = offered.expect("one packet offered");
            if let Some(expected) = &expected {
                assert_eq!(&packet, expected, "retry changed packet bytes or metadata");
            }
            if let Some(error) = fault {
                assert_eq!(result.unwrap_err(), error);
                assert_eq!(self.snapshot(), before);
            } else {
                assert!(
                    matches!(result.unwrap(), IovTransmit::Packet(info) if info == packet.info)
                );
                assert_eq!(
                    self.snapshot().budget,
                    before.budget,
                    "commit used new credit"
                );
                self.t.check();
                return packet;
            }
            expected = Some(packet);
        }
        unreachable!()
    }
}

#[test]
fn new_data_retries_with_the_same_pacing_and_idle_restart() {
    let mut rig = Rig::established();
    let data = [23; 1001];
    rig.write(&data);
    rig.t.rtt.sample(Duration::from_millis(10));
    rig.now += rig.t.rtt.rto();
    rig.t.ack_due = crate::tcp::DATA;
    rig.t.delack_deadline = Some(rig.now);
    let cwnd = rig.t.cc.cwnd();
    let seq = rig.t.snd_nxt;
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::NONE),
        IovTransmit::Progress
    ));
    let before = rig.snapshot();
    assert!(matches!(
        rig.no_emit(40, TxCaps::NONE),
        IovTransmit::BufferTooSmall
    ));
    assert_eq!(rig.snapshot(), before);
    let packet = rig.retry(TxCaps::NONE, true, (0, data.len()));
    let (hdr, payload) = packet.tcp();
    assert_eq!((hdr.seq, hdr.flags), (seq, ACK | PSH));
    assert_eq!(payload, &data);
    assert_eq!(rig.t.snd_nxt, seq + data.len() as u32);
    assert_eq!(rig.t.sent.queue.len(), 1);
    assert!(rig.t.cc.cwnd() < cwnd);
    assert_ne!(rig.t.pacer, before.pacer);
    assert_eq!(rig.t.ack_due, 0);
    assert_eq!(rig.t.delack_deadline, None);
}

#[test]
fn tso_fin_retries_the_same_ring_slices_and_commits_one_descriptor_per_segment() {
    let mut rig = Rig::established();
    rig.t.peer_mss = 512;
    rig.t.rtt.sample(Duration::from_millis(1));
    let mut rng = wire::testutil::Rng::new(13);
    let data = rng.bytes(8511);
    rig.write(&data);
    rig.t.shutdown().unwrap();
    let seq = rig.t.snd_nxt;
    let unused = rig.budget.used();
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::ALL),
        IovTransmit::Progress
    ));
    assert_eq!(
        rig.budget.used(),
        unused,
        "the descriptor floor was already funded"
    );
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::ALL),
        IovTransmit::Progress
    ));
    assert!(rig.budget.used() > unused);
    assert_eq!(rig.t.snd_nxt, seq);
    assert!(rig.t.sent.queue.is_empty());
    assert_eq!(rig.t.fin_seq, None);

    let packet = rig.retry(TxCaps::ALL, true, (0, data.len()));
    let gso = packet.info.gso.unwrap();
    assert_eq!(
        (packet.parts, gso.kind, gso.size, gso.hdr_len),
        (3, GsoKind::Tcp, 500, 52)
    );
    assert_eq!(
        packet.info.csum,
        TxCsum::Partial {
            start: 20,
            offset: 16
        }
    );
    let (hdr, payload) = packet.tcp();
    assert_eq!((hdr.seq, hdr.flags), (seq, ACK | PSH | FIN));
    assert_eq!(payload, &data);
    let fin = seq + data.len() as u32;
    assert_eq!(rig.t.fin_seq, Some(fin));
    assert_eq!(rig.t.snd_nxt, fin + 1);
    assert_eq!(rig.t.sent.queue.len(), data.len().div_ceil(500));
    assert_eq!(rig.t.sent.queue.back().unwrap().end_seq, fin + 1);
    assert!(rig.t.sent.queue.back().unwrap().flags & SENT_FIN != 0);
}

#[test]
fn refused_descriptor_growth_does_not_spend_credit_or_consume_the_tail_probe() {
    let mut rig = Rig::established();
    rig.t.peer_mss = 13;
    rig.write(&[7; FLOOR_SLOTS]);
    for _ in 0..FLOOR_SLOTS - 1 {
        rig.send_contiguous();
    }
    assert_eq!(rig.t.sent.queue.len(), FLOOR_SLOTS - 1);
    rig.t.sack = true;
    rig.t.sent.sack(
        rig.t.snd_una,
        rig.t.snd_nxt,
        rig.t.snd_nxt,
        &mut Acked::new(rig.now, Duration::ZERO),
    );
    rig.t.tlp_due = true;
    let other = rig.budget.reserve(rig.budget.available()).unwrap();
    let before = rig.snapshot();
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::NONE),
        IovTransmit::Deferred
    ));
    assert_eq!(rig.snapshot(), before);
    drop(other);
    let before = rig.snapshot();
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::NONE),
        IovTransmit::Progress
    ));
    assert_eq!(rig.snapshot().sequence, before.sequence);
    let packet = rig.retry(TxCaps::NONE, true, (FLOOR_SLOTS - 1, 1));
    assert_eq!(packet.tcp().1, &[7]);
    assert_eq!(rig.t.sent.queue.len(), FLOOR_SLOTS);
    assert!(!rig.t.tlp_due);
    assert_eq!(rig.t.recovery.counters.tlp_probes, 1);
}

#[test]
fn split_retransmit_preserves_cursor_and_rack_on_refused_credit_and_sink_errors() {
    let mut rig = Rig::established();
    rig.t.sack = true;
    rig.write(&[1; 40]);
    rig.send_contiguous();
    rig.write(&[7; 1000]);
    rig.send_contiguous();
    rig.t.pmtu(400);
    let mss = rig.t.send_mss();
    let t = &mut rig.t;
    t.recovery.rto(&mut t.sent, &mut t.cc, t.snd_nxt, mss);
    let start = t.snd_una + 40;
    t.sent.sack(
        t.snd_una,
        start,
        t.snd_nxt,
        &mut Acked::new(rig.now, Duration::ZERO),
    );
    t.rtt.sample(Duration::from_millis(10));
    rig.now += Duration::from_millis(10);
    assert!(matches!(
        t.recovery.rack.ensure_room::<true>(&rig.pool, FLOOR_SLOTS),
        Room::Grew
    ));
    for _ in 0..FLOOR_SLOTS {
        t.recovery.rack.on_retransmit(start, rig.now);
    }
    assert_eq!(t.sent.retrans_cursor, t.snd_una);
    let other = rig.budget.reserve(rig.budget.available()).unwrap();
    let before = rig.snapshot();
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::NONE),
        IovTransmit::Deferred
    ));
    assert_eq!(rig.snapshot(), before);
    drop(other);
    let used = rig.budget.used();
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::NONE),
        IovTransmit::Progress
    ));
    assert!(rig.budget.used() > used);
    assert_eq!(rig.t.sent.retrans_cursor, rig.t.snd_una);
    assert_eq!(rig.t.recovery.rack.pending_retransmits(), FLOOR_SLOTS);
    let packet = rig.retry(TxCaps::NONE, true, (40, mss as usize));
    let (hdr, payload) = packet.tcp();
    assert_eq!((hdr.seq, hdr.flags), (start, ACK));
    assert_eq!(payload.len(), mss as usize);
    assert!(payload.iter().all(|&byte| byte == 7));
    assert_eq!(rig.t.sent.queue.len(), 3);
    assert_eq!(rig.t.sent.queue[1].end_seq, start + mss);
    assert_eq!(rig.t.sent.queue[1].flags & RETRANS, RETRANS);
    assert_eq!(rig.t.sent.retrans_cursor, start + mss);
    assert_eq!(
        rig.t.recovery.rack.retransmit_entries().unwrap().back(),
        Some(&(start + mss, rig.now))
    );
    assert_eq!(
        rig.t.recovery.retrans_stamp(),
        Some(rig.t.timestamp(rig.now))
    );
    assert_eq!(rig.t.stats.retrans_segments, 1);
    assert_eq!(rig.t.stats.retrans_bytes, u64::from(mss));
}

#[test]
fn tail_probes_commit_only_after_acceptance_and_survive_control_only_pulls() {
    for retransmit in [false, true] {
        let mut rig = Rig::established();
        rig.t.sack = true;
        rig.t.rtt.sample(Duration::from_millis(300));
        rig.write(&[7; 100]);
        rig.send_contiguous();
        if !retransmit {
            rig.write(&[9; 200]);
        }
        let prev_nxt = rig.t.snd_nxt;
        rig.now = rig.t.tlp_deadline.unwrap();
        rig.t.timer(rig.now);
        assert!(rig.t.tlp_due);
        rig.t.ack_due = crate::tcp::WINDOW_UPDATE;
        let ack = rig.retry(TxCaps::NONE, false, (0, 0));
        assert_eq!(ack.tcp().0.flags, ACK);
        assert!(rig.t.tlp_due);
        assert_eq!(rig.t.snd_nxt, prev_nxt);
        assert!(rig.t.recovery.rack.tlp.is_none());

        if retransmit {
            assert!(matches!(
                rig.no_emit(MAX_LEN, TxCaps::NONE),
                IovTransmit::Progress
            ));
        }
        let (offset, data) = if retransmit {
            (0, vec![7; 100])
        } else {
            (100, vec![9; 200])
        };
        let packet = rig.retry(TxCaps::NONE, true, (offset, data.len()));
        let (hdr, payload) = packet.tcp();
        assert_eq!(hdr.seq, rig.t.snd_una + offset as u32);
        assert_eq!(payload, &data);
        assert_eq!(rig.t.snd_nxt, prev_nxt + if retransmit { 0 } else { 200 });
        assert!(!rig.t.tlp_due);
        let tlp = rig.t.recovery.rack.tlp.unwrap();
        assert_eq!((tlp.high_seq, tlp.retransmit), (rig.t.snd_nxt, retransmit));
        assert_eq!(rig.t.recovery.counters.tlp_probes, 1);
        assert_eq!(rig.t.rto_deadline, Some(rig.now + rig.t.rtt.rto()));
    }
}

#[test]
fn syn_reset_and_persist_control_obligations_survive_sink_errors() {
    let mut rig = Rig::new();
    let packet = rig.retry(TxCaps::NONE, false, (0, 0));
    assert_eq!(packet.tcp().0.flags, SYN);
    assert!(!rig.t.syn_due);
    assert_eq!(rig.t.syn_sent, Some(rig.now));
    assert_eq!(rig.t.snd_nxt, rig.t.iss + 1);

    let mut rig = Rig::established();
    rig.t.abort();
    let packet = rig.retry(TxCaps::NONE, false, (0, 0));
    assert_eq!(packet.tcp().0.flags, RST | ACK);
    assert!(!rig.t.rst_pending);

    let mut rig = Rig::established();
    rig.t.snd_wnd = 0;
    rig.write(b"pending");
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::NONE),
        IovTransmit::Progress
    ));
    assert!(rig.t.persist);
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::NONE),
        IovTransmit::Idle
    ));
    rig.now = rig.t.rto_deadline.unwrap();
    rig.t.timer(rig.now);
    let packet = rig.retry(TxCaps::NONE, false, (0, 0));
    assert_eq!(packet.tcp().0.seq, rig.t.snd_una - 1);
    assert!(!rig.t.probe_due);
    assert_eq!(rig.t.snd_nxt, rig.t.snd_una);
}

#[test]
fn standalone_fin_retries_with_its_sequence_slot_held() {
    let mut rig = Rig::established();
    rig.t.shutdown().unwrap();
    let seq = rig.t.snd_nxt;
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::NONE),
        IovTransmit::Progress
    ));
    let packet = rig.retry(TxCaps::NONE, false, (0, 0));
    let (hdr, payload) = packet.tcp();
    assert_eq!((hdr.seq, hdr.flags), (seq, ACK | FIN));
    assert!(payload.is_empty());
    assert_eq!(rig.t.snd_nxt, seq + 1);
    assert_eq!(rig.t.fin_seq, Some(seq));
    assert_eq!(rig.t.sent.queue[0].flags & SENT_FIN, SENT_FIN);
}

#[test]
fn pacing_maintenance_arms_one_wakeup_and_quiesces_until_it_fires() {
    let mut rig = Rig::established();
    rig.t.peer_mss = 512;
    rig.t.rtt.sample(Duration::from_millis(300));
    let data = [16; 1000];
    rig.write(&data);
    rig.send_contiguous();
    assert_eq!(rig.t.pacer.tokens(), 0);
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::NONE),
        IovTransmit::Progress
    ));
    let when = rig.t.pacing_deadline.unwrap();
    assert!(when > rig.now);
    rig.now += (when - rig.now) / 2;
    let armed = rig.snapshot();
    assert!(matches!(
        rig.no_emit(MAX_LEN, TxCaps::NONE),
        IovTransmit::Idle
    ));
    assert_eq!(rig.snapshot(), armed);
    rig.now = when;
    rig.t.timer(when);
    let packet = rig.retry(TxCaps::NONE, true, (500, 500));
    assert_eq!(packet.tcp().1, &data[500..]);
    assert_eq!(rig.t.snd_nxt, rig.t.snd_una + 1000);
}
