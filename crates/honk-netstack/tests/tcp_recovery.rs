//! Loss-recovery packet scripts: RACK-TLP, PRR, undo, F-RTO, pacing and rate samples, driven only
//! through the public API with a scripted peer.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use honk_netstack::wire::{self, tcp};
use honk_netstack::{Config, FlowId, Rx, Stack, TcpState, TcpStats};

const MSS: u32 = 1000;
const MS: Duration = Duration::from_millis(1);

fn config() -> Config {
    let mut cfg = Config::new([0x37; 32]);
    cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
    cfg
}

fn remote() -> SocketAddr {
    "198.51.100.2:443".parse().unwrap()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

struct Packet {
    h: tcp::Header,
    data: Vec<u8>,
}

impl Packet {
    fn end(&self) -> u32 {
        self.h.seq.wrapping_add(self.data.len() as u32)
    }
}

fn pull(stack: &mut Stack, now: Instant) -> Option<Packet> {
    let mut out = [0u8; 2048];
    let n = stack.poll_transmit(now, &mut out)?;
    let ip = wire::parse_ip(&out[..n]).unwrap();
    let seg = &out[ip.payload.clone()];
    let (h, off) = tcp::parse(seg).unwrap();
    Some(Packet {
        h,
        data: seg[off..].to_vec(),
    })
}

/// Everything the stack will send, letting time pass only for pacing gaps (sub-millisecond here),
/// never for probe or retransmission timers.
fn drain(stack: &mut Stack, now: &mut Instant) -> Vec<Packet> {
    let mut packets = Vec::new();
    loop {
        while let Some(p) = pull(stack, *now) {
            assert!(packets.len() < 512, "transmit never quiesced");
            packets.push(p);
        }
        match stack.poll_timeout() {
            Some(at) if at > *now && at - *now <= 5 * MS => {
                *now = at;
                stack.handle_timeout(at);
            }
            _ => return packets,
        }
    }
}

/// What is sendable right now, with no time passing.
fn pull_all(stack: &mut Stack, now: Instant) -> Vec<Packet> {
    std::iter::from_fn(|| pull(stack, now)).collect()
}

/// Advances to the next deadline and runs it; panics if there is none.
fn tick(stack: &mut Stack, now: &mut Instant) {
    *now = stack.poll_timeout().expect("a pending deadline");
    stack.handle_timeout(*now);
}

/// The next packet the stack produces, running deadlines until one appears within `limit`.
/// Deadlines are lazy: an early one may fire with nothing due yet.
fn next_packet(stack: &mut Stack, now: &mut Instant, limit: Duration) -> Option<Packet> {
    let end = *now + limit;
    loop {
        if let Some(p) = pull(stack, *now) {
            return Some(p);
        }
        match stack.poll_timeout() {
            Some(at) if at <= end => {
                *now = at.max(*now);
                stack.handle_timeout(*now);
            }
            _ => return None,
        }
    }
}

struct Peer {
    id: FlowId,
    local: SocketAddr,
    start: u32,
    next: u32,
    epoch: Instant,
    timestamps: bool,
    echo: u32,
}

impl Peer {
    fn header(&self, now: Instant, ack: u32) -> tcp::Header {
        tcp::Header {
            src_port: remote().port(),
            dst_port: self.local.port(),
            seq: self.next,
            ack,
            flags: tcp::ACK,
            window: u16::MAX,
            urgent: 0,
            options: tcp::Options {
                timestamps: self.timestamps.then_some((
                    100_000u32.wrapping_add(now.duration_since(self.epoch).as_millis() as u32),
                    self.echo,
                )),
                ..tcp::Options::default()
            },
        }
    }

    /// An ACK with SACK blocks (`blocks[0]` may be a DSACK).
    fn ack(&self, stack: &mut Stack, now: Instant, ack: u32, blocks: &[(u32, u32)]) {
        self.ack_window(stack, now, ack, blocks, u16::MAX);
    }

    fn ack_window(
        &self,
        stack: &mut Stack,
        now: Instant,
        ack: u32,
        blocks: &[(u32, u32)],
        window: u16,
    ) {
        let mut h = self.header(now, ack);
        h.window = window;
        for &(l, r) in blocks {
            h.options.sack.push(l, r);
        }
        let mut bytes = vec![0u8; 256];
        let n =
            tcp::emit_packet(&mut bytes, remote().ip(), self.local.ip(), &h, [&[], &[]]).unwrap();
        assert_eq!(stack.receive(now, &bytes[..n]), Rx::Consumed);
    }

    /// A data segment from the peer, acknowledging `ack`.
    fn data(&mut self, stack: &mut Stack, now: Instant, ack: u32, bytes: &[u8]) {
        let h = self.header(now, ack);
        let mut buf = vec![0u8; bytes.len() + 256];
        let n =
            tcp::emit_packet(&mut buf, remote().ip(), self.local.ip(), &h, [bytes, &[]]).unwrap();
        assert_eq!(stack.receive(now, &buf[..n]), Rx::Consumed);
        self.next = self.next.wrapping_add(bytes.len() as u32);
    }
}

/// Connects `stack` to a scripted peer (10 ms handshake RTT, MSS 1000, window scaling off).
/// With `syn_lost` the first SYN is lost, so the handshake yields no RTT sample.
fn connect(sack: bool, timestamps: bool, syn_lost: bool) -> (Stack, Instant, Peer) {
    let mut now = Instant::now();
    let epoch = now;
    let mut stack = Stack::new(config(), now);
    let id = stack.tcp_connect(now, remote()).unwrap();
    let mut syn = pull(&mut stack, now).expect("SYN");
    if syn_lost {
        tick(&mut stack, &mut now);
        syn = pull(&mut stack, now).expect("SYN retransmission");
    }
    let peer = Peer {
        id,
        local: SocketAddr::new(IpAddr::V4(config().local_v4.unwrap()), syn.h.src_port),
        start: syn.h.seq.wrapping_add(1),
        next: 0x1020_3041,
        epoch,
        timestamps,
        echo: syn.h.options.timestamps.unwrap().0,
    };
    let mut h = peer.header(now, syn.h.seq.wrapping_add(1));
    h.seq = peer.next.wrapping_sub(1);
    h.flags |= tcp::SYN;
    h.options.mss = Some(MSS as u16);
    h.options.sack_permitted = sack;
    now += 10 * MS;
    let mut bytes = vec![0u8; 256];
    let n = tcp::emit_packet(&mut bytes, remote().ip(), peer.local.ip(), &h, [&[], &[]]).unwrap();
    assert_eq!(stack.receive(now, &bytes[..n]), Rx::Consumed);
    assert_eq!(stack.tcp_state(id), Some(TcpState::Established));
    let ack = pull(&mut stack, now).expect("handshake ACK");
    assert_eq!(ack.h.flags, tcp::ACK);
    assert!(pull(&mut stack, now).is_none());
    (stack, now, peer)
}

fn stats(stack: &Stack, peer: &Peer) -> TcpStats {
    stack.tcp_stats(peer.id).unwrap()
}

/// Sends `bytes` and acknowledges everything after `rtt`, the way a healthy path would.
fn round(stack: &mut Stack, now: &mut Instant, peer: &mut Peer, bytes: usize) -> Vec<Packet> {
    assert_eq!(stack.tcp_write(peer.id, &pattern(bytes)), Ok(bytes));
    let packets = drain(stack, now);
    *now += 10 * MS;
    let end = packets.last().expect("data").end();
    peer.ack(stack, *now, end, &[]);
    packets
}

/// Opens the congestion window to `segments` full segments by acknowledging slow-start rounds.
fn grow(stack: &mut Stack, now: &mut Instant, peer: &mut Peer, segments: u32) {
    while stats(stack, peer).cwnd < segments * MSS {
        let cwnd = stats(stack, peer).cwnd as usize;
        round(stack, now, peer, cwnd);
    }
}

#[test]
fn tail_loss_probe_fires_at_two_srtt_resends_the_last_segment_and_is_no_loss_event() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(2000)), Ok(2000));
    let packets = drain(&mut stack, &mut now);
    assert_eq!(packets.len(), 2);
    let sent_at = now;
    let before = stats(&stack, &peer);
    assert_eq!(before.srtt, Some(10 * MS));
    assert_eq!(
        stack.poll_timeout(),
        Some(sent_at + 20 * MS),
        "PTO = 2 * SRTT for a flight of two"
    );
    let probe = next_packet(&mut stack, &mut now, 30 * MS).expect("probe");
    assert_eq!(now, sent_at + 20 * MS);
    assert_eq!(
        (probe.h.seq, &probe.data),
        (packets[1].h.seq, &packets[1].data),
        "with nothing new to send the newest segment is probed"
    );
    assert!(pull(&mut stack, now).is_none(), "one probe, not a window");
    let after = stats(&stack, &peer);
    assert_eq!(
        (
            after.tlp_probes,
            after.rto_count,
            after.loss_events,
            after.cwnd
        ),
        (1, 0, 0, before.cwnd),
        "a probe alone neither backs off nor reduces the window"
    );
    // The retransmission timer restarts at the probe and backs it up.
    let probed_at = now;
    assert!(next_packet(&mut stack, &mut now, 190 * MS).is_none());
    assert_eq!(stats(&stack, &peer).rto_count, 0);
    let resent = next_packet(&mut stack, &mut now, 20 * MS).expect("timeout retransmission");
    assert_eq!(resent.h.seq, packets[0].h.seq);
    assert!(now - probed_at >= after.rto);
    assert_eq!(stats(&stack, &peer).rto_count, 1);
}

#[test]
fn single_segment_flight_waits_for_the_peers_delayed_ack_before_probing() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(500)), Ok(500));
    drain(&mut stack, &mut now);
    let rto = stats(&stack, &peer).rto;
    // 2 * SRTT + 200 ms exceeds the 200 ms RTO: the probe timer is clamped to it (RFC 8985 7.2).
    assert_eq!(stack.poll_timeout(), Some(now + rto));
}

#[test]
fn probe_sends_new_data_when_the_window_is_full_but_data_is_waiting() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(12_000)), Ok(12_000));
    let packets = drain(&mut stack, &mut now);
    assert_eq!(packets.len(), 10, "the initial window");
    let probe = next_packet(&mut stack, &mut now, 30 * MS).expect("probe");
    assert_eq!(
        probe.h.seq,
        packets[9].end(),
        "new data beyond cwnd, not a retransmission"
    );
    assert_eq!(stats(&stack, &peer).retrans_segments, 0);
}

#[test]
fn rack_waits_out_the_reorder_window_then_retransmits_only_older_segments() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(6000)), Ok(6000));
    let packets = drain(&mut stack, &mut now);
    assert_eq!(packets.len(), 6);
    now += 10 * MS;
    // Segment 1 arrived, segment 0 did not: one SACKed segment is reordering until proven loss.
    peer.ack(
        &mut stack,
        now,
        peer.start,
        &[(packets[1].h.seq, packets[1].end())],
    );
    let acked_at = now;
    assert!(pull(&mut stack, now).is_none(), "not lost yet");
    assert_eq!(stats(&stack, &peer).loss_events, 0);
    let resent = next_packet(&mut stack, &mut now, 10 * MS)
        .expect("retransmission once min_rtt/4 has passed");
    assert_eq!(resent.h.seq, packets[0].h.seq);
    let waited = now - acked_at;
    assert!(
        waited >= Duration::from_micros(1500) && waited <= 3 * MS,
        "reorder window is min_rtt/4 = 2.5 ms past the segment's age, waited {waited:?}"
    );
    assert!(
        drain(&mut stack, &mut now)
            .iter()
            .all(|p| p.h.seq == packets[0].h.seq),
        "segments sent after the newest delivered one are never presumed lost"
    );
    assert_eq!(stats(&stack, &peer).loss_events, 1);
}

#[test]
fn three_sacked_segments_skip_the_reorder_window() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(6000)), Ok(6000));
    let packets = drain(&mut stack, &mut now);
    now += 10 * MS;
    peer.ack(
        &mut stack,
        now,
        peer.start,
        &[(packets[1].h.seq, packets[2].end())],
    );
    assert!(pull(&mut stack, now).is_none());
    peer.ack(
        &mut stack,
        now,
        peer.start,
        &[(packets[1].h.seq, packets[3].end())],
    );
    let resent = pull(&mut stack, now).expect("DupThresh segments above the hole mean loss");
    assert_eq!(resent.h.seq, packets[0].h.seq);
    assert_eq!(
        stats(&stack, &peer).ssthresh,
        7000,
        "CUBIC beta 0.7 of cwnd"
    );
}

#[test]
fn prr_sends_ssthresh_over_flight_of_what_is_delivered() {
    let (mut stack, mut now, mut peer) = connect(true, false, false);
    grow(&mut stack, &mut now, &mut peer, 40);
    let cwnd = stats(&stack, &peer).cwnd;
    // Enough data that new segments are waiting while the loss is repaired.
    assert_eq!(
        stack.tcp_write(peer.id, &pattern(2 * cwnd as usize)),
        Ok(2 * cwnd as usize)
    );
    let flight = drain(&mut stack, &mut now);
    assert_eq!(flight.len() as u32, cwnd / MSS);
    now += 10 * MS;
    let seg = |i: usize| (flight[i].h.seq, flight[i].end());
    let sack_to = |stack: &mut Stack, now: Instant, last: usize| {
        peer.ack(stack, now, seg(0).0, &[(seg(1).0, seg(last).1)]);
    };
    // Segment 0 is lost; the third SACKed segment starts the recovery and is the first delivery.
    sack_to(&mut stack, now, 2);
    // Two SACKed segments are not loss yet; the room they free is used for new data.
    assert_eq!(pull_all(&mut stack, now).len(), 2);
    let recover_fs = u64::from(stats(&stack, &peer).outstanding_bytes);
    sack_to(&mut stack, now, 3);
    let ssthresh = u64::from(stats(&stack, &peer).ssthresh);
    assert_eq!(ssthresh, u64::from(cwnd / 10 * 7));
    let mut got = Vec::new();
    let mut sent_in_recovery = 0u64;
    let mut expect = Vec::new();
    for delivered in 1..=7u64 {
        if delivered > 1 {
            now += MS;
            sack_to(&mut stack, now, 2 + delivered as usize);
        }
        for p in pull_all(&mut stack, now) {
            sent_in_recovery += p.data.len() as u64;
        }
        got.push(sent_in_recovery / u64::from(MSS));
        // RFC 6937: sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out.
        expect.push((delivered * u64::from(MSS) * ssthresh).div_ceil(recover_fs));
    }
    let expect: Vec<u64> = expect.iter().map(|b| b.div_ceil(u64::from(MSS))).collect();
    assert_eq!(
        got, expect,
        "cumulative segments sent per delivered segment"
    );
    assert_eq!(stats(&stack, &peer).loss_events, 1);
}

#[test]
fn dsack_of_the_retransmission_undoes_the_reduction_and_widens_the_reorder_window() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(10_000)), Ok(10_000));
    let packets = drain(&mut stack, &mut now);
    let before = stats(&stack, &peer);
    now += 10 * MS;
    peer.ack(
        &mut stack,
        now,
        peer.start,
        &[(packets[1].h.seq, packets[3].end())],
    );
    peer.ack(
        &mut stack,
        now,
        peer.start,
        &[(packets[1].h.seq, packets[4].end())],
    );
    let resent = pull(&mut stack, now).expect("fast retransmit");
    assert_eq!(resent.h.seq, packets[0].h.seq);
    assert!(stats(&stack, &peer).cwnd < before.cwnd);
    // The original of segment 0 was only delayed: everything is acknowledged, the copy is DSACKed.
    now += 5 * MS;
    peer.ack(
        &mut stack,
        now,
        packets[9].end(),
        &[(packets[0].h.seq, packets[0].end())],
    );
    let after = stats(&stack, &peer);
    assert_eq!(
        (
            after.loss_events,
            after.spurious_recoveries,
            after.undo_count
        ),
        (1, 1, 1)
    );
    assert_eq!((after.cwnd, after.ssthresh), (before.cwnd, before.ssthresh));
    assert_eq!(
        after.reo_wnd,
        2 * (after.srtt.unwrap().min(10 * MS) / 4),
        "one DSACK step doubles min_rtt/4"
    );
}

#[test]
fn retransmission_that_was_needed_is_not_undone() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(10_000)), Ok(10_000));
    let packets = drain(&mut stack, &mut now);
    now += 10 * MS;
    peer.ack(
        &mut stack,
        now,
        peer.start,
        &[(packets[1].h.seq, packets[3].end())],
    );
    peer.ack(
        &mut stack,
        now,
        peer.start,
        &[(packets[1].h.seq, packets[4].end())],
    );
    pull(&mut stack, now).expect("fast retransmit");
    now += 5 * MS;
    peer.ack(&mut stack, now, packets[9].end(), &[]);
    let after = stats(&stack, &peer);
    assert_eq!((after.loss_events, after.undo_count), (1, 0));
    assert_eq!(after.cwnd, 7000);
}

#[test]
fn timestamp_echo_older_than_the_retransmission_proves_it_spurious_without_dsack() {
    for echo_original in [true, false] {
        let (mut stack, mut now, mut peer) = connect(true, true, false);
        assert_eq!(stack.tcp_write(peer.id, &pattern(5000)), Ok(5000));
        let packets = drain(&mut stack, &mut now);
        let before = stats(&stack, &peer);
        let n = packets.len();
        now += 10 * MS;
        peer.echo = packets[1].h.options.timestamps.unwrap().0;
        peer.ack(
            &mut stack,
            now,
            peer.start,
            &[(packets[1].h.seq, packets[3].end())],
        );
        peer.ack(
            &mut stack,
            now,
            peer.start,
            &[(packets[1].h.seq, packets[4].end())],
        );
        let resent = pull(&mut stack, now).expect("fast retransmit");
        assert_eq!(resent.h.seq, packets[0].h.seq);
        now += 5 * MS;
        // Echoing the original's timestamp (Eifel) or the retransmission's own.
        peer.echo = if echo_original {
            packets[0].h.options.timestamps.unwrap().0
        } else {
            resent.h.options.timestamps.unwrap().0
        };
        peer.ack(&mut stack, now, packets[n - 1].end(), &[]);
        let after = stats(&stack, &peer);
        assert_eq!(
            after.undo_count,
            u32::from(echo_original).into(),
            "echo_original={echo_original}"
        );
        assert_eq!(after.cwnd == before.cwnd, echo_original);
    }
}

#[test]
fn rto_whose_delayed_acks_cover_original_data_is_undone_by_frto() {
    let (mut stack, mut now, peer) = connect(false, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(4000)), Ok(4000));
    let packets = drain(&mut stack, &mut now);
    let before = stats(&stack, &peer);
    tick(&mut stack, &mut now);
    let resent = pull(&mut stack, now).expect("timeout retransmission");
    assert_eq!(resent.h.seq, packets[0].h.seq);
    assert_eq!(
        (stats(&stack, &peer).rto_count, stats(&stack, &peer).cwnd),
        (1, MSS)
    );
    assert!(pull(&mut stack, now).is_none(), "one segment per timeout");
    // The ACKs were merely late: they cover segments that were never retransmitted.
    now += 10 * MS;
    peer.ack(&mut stack, now, packets[3].end(), &[]);
    let after = stats(&stack, &peer);
    assert_eq!((after.spurious_recoveries, after.undo_count), (1, 1));
    assert_eq!((after.cwnd, after.ssthresh), (before.cwnd, before.ssthresh));
    assert_eq!((after.lost_bytes, after.outstanding_bytes), (0, 0));
    assert!(drain(&mut stack, &mut now).is_empty());
}

#[test]
fn frto_sends_new_data_after_the_first_ack_and_a_hole_report_confirms_the_loss() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(12_000)), Ok(12_000));
    let packets = drain(&mut stack, &mut now);
    assert_eq!(packets.len(), 10);
    // The probe goes out first; then the retransmission timer fires.
    let probe = next_packet(&mut stack, &mut now, 30 * MS).expect("probe");
    assert_eq!(probe.h.seq, packets[9].end());
    let resent = next_packet(&mut stack, &mut now, 250 * MS).expect("timeout retransmission");
    assert_eq!(resent.h.seq, packets[0].h.seq);
    assert_eq!(stats(&stack, &peer).rto_count, 1);
    now += 10 * MS;
    // Only the retransmitted segment is acknowledged.
    peer.ack(&mut stack, now, packets[0].end(), &[]);
    let next = drain(&mut stack, &mut now);
    assert!(
        next.iter().all(|p| p.h.seq >= packets[9].end()),
        "RFC 5682 step 2b: new data, not more retransmissions: {:?}",
        next.iter().map(|p| p.h.seq).collect::<Vec<_>>()
    );
    assert!(!next.is_empty());
    // The peer reports a hole in front of the new data: the timeout was genuine.
    now += 10 * MS;
    let fresh = next.last().unwrap();
    peer.ack(
        &mut stack,
        now,
        packets[0].end(),
        &[(fresh.h.seq, fresh.end())],
    );
    let resent = drain(&mut stack, &mut now);
    assert_eq!(resent.first().map(|p| p.h.seq), Some(packets[1].h.seq));
    assert_eq!(stats(&stack, &peer).undo_count, 0);
}

#[test]
fn pacing_releases_a_bounded_burst_then_one_segment_per_gap() {
    let (mut stack, now, peer) = connect(false, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(10_000)), Ok(10_000));
    let mut sent = Vec::new();
    while let Some(p) = pull(&mut stack, now) {
        sent.push(p);
    }
    // 2 * cwnd / SRTT = 2 MB/s in slow start, so 2 ms of bucket is 4 segments (below the 10 cap).
    assert_eq!(sent.len(), 4);
    let gap = stack.poll_timeout().expect("pacing deadline") - now;
    assert_eq!(gap, Duration::from_micros(500), "1000 B at 2 MB/s");
    let mut t = now;
    let stamps: Vec<Duration> = (0..6)
        .map(|_| {
            next_packet(&mut stack, &mut t, 2 * MS).expect("paced packet");
            t - now
        })
        .collect();
    assert_eq!(
        stamps,
        (1..=6)
            .map(|i| Duration::from_micros(500 * i))
            .collect::<Vec<_>>()
    );
    assert!(
        next_packet(&mut stack, &mut t, 2 * MS).is_none(),
        "the window is spent"
    );
}

#[test]
fn pacing_stays_off_until_an_rtt_sample_exists() {
    let (mut stack, mut now, peer) = connect(false, false, true);
    assert_eq!(
        stats(&stack, &peer).srtt,
        None,
        "a retransmitted SYN gives no sample"
    );
    assert_eq!(stack.tcp_write(peer.id, &pattern(10_000)), Ok(10_000));
    assert_eq!(drain(&mut stack, &mut now).len(), 10);
}

#[test]
fn app_limited_samples_cannot_lower_the_delivery_rate() {
    let (mut stack, mut now, mut peer) = connect(false, false, false);
    assert_eq!(stats(&stack, &peer).delivery_rate, 0);
    // A full window: the sample measures the path.
    assert_eq!(stack.tcp_write(peer.id, &pattern(10_000)), Ok(10_000));
    let packets = drain(&mut stack, &mut now);
    now += 50 * MS;
    peer.ack(&mut stack, now, packets.last().unwrap().end(), &[]);
    let measured = stats(&stack, &peer).delivery_rate;
    assert!(measured > 100_000, "10 kB over about 55 ms: {measured}");
    // One segment with the window nearly empty: far slower, but app-limited.
    now += 500 * MS;
    let trickle = round(&mut stack, &mut now, &mut peer, 1000);
    assert_eq!(trickle.len(), 1);
    assert_eq!(stats(&stack, &peer).delivery_rate, measured);
}

#[test]
fn sack_blocks_are_applied_oldest_first_so_the_newest_block_is_not_mistaken_for_reordering() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(10_000)), Ok(10_000));
    let packets = drain(&mut stack, &mut now);
    now += 10 * MS;
    let seg = |i: usize, j: usize| (packets[i].h.seq, packets[j].end());
    // RFC 2018 lists the most recently received block first: [6, 7] before [2, 3]. Applied in
    // that order the second block would look like data arriving late, so the sender would wait
    // out a reorder window instead of retransmitting at once.
    peer.ack(&mut stack, now, peer.start, &[seg(6, 7), seg(2, 3)]);
    let resent = pull(&mut stack, now).expect("four SACKed segments above the holes mean loss");
    assert_eq!(resent.h.seq, packets[0].h.seq);
    assert_eq!(stats(&stack, &peer).reo_wnd, Duration::ZERO);
}

#[test]
fn a_lower_segment_arriving_after_a_higher_one_is_reordering_not_loss() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(8000)), Ok(8000));
    let packets = drain(&mut stack, &mut now);
    now += 10 * MS;
    let seg = |i: usize, j: usize| (packets[i].h.seq, packets[j].end());
    peer.ack(&mut stack, now, peer.start, &[seg(3, 4)]);
    assert!(pull(&mut stack, now).is_none());
    // Segment 1 shows up after segments 3 and 4: the network reorders. Three SACKed segments no
    // longer prove loss, so nothing is retransmitted before the reorder window has passed.
    peer.ack(&mut stack, now, peer.start, &[seg(1, 1), seg(3, 4)]);
    assert!(pull(&mut stack, now).is_none());
    let st = stats(&stack, &peer);
    assert_eq!(
        (st.loss_events, st.reo_wnd),
        (0, Duration::from_micros(2500))
    );
}

#[test]
fn ack_compressed_rate_samples_are_discarded() {
    let (mut stack, mut now, peer) = connect(false, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(10_000)), Ok(10_000));
    let packets = drain(&mut stack, &mut now);
    now += 50 * MS;
    peer.ack(&mut stack, now, packets.last().unwrap().end(), &[]);
    let measured = stats(&stack, &peer).delivery_rate;
    // A window-filling flight "delivered" within a millisecond of its last transmission, far
    // faster than the 10 ms path RTT allows: the ACKs were compressed, the rate is not real.
    let cwnd = stats(&stack, &peer).cwnd as usize;
    assert_eq!(stack.tcp_write(peer.id, &pattern(cwnd)), Ok(cwnd));
    let flight = drain(&mut stack, &mut now);
    now += MS;
    peer.ack(&mut stack, now, flight.last().unwrap().end(), &[]);
    assert_eq!(stats(&stack, &peer).delivery_rate, measured);
}

#[test]
fn frto_without_new_data_retransmits_the_remaining_tail_at_once() {
    let (mut stack, mut now, peer) = connect(false, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(4000)), Ok(4000));
    let packets = drain(&mut stack, &mut now);
    assert_eq!(packets.len(), 4);
    tick(&mut stack, &mut now);
    let resent = pull(&mut stack, now).expect("timeout retransmission");
    assert_eq!(resent.h.seq, packets[0].h.seq);
    now += 10 * MS;
    peer.ack(&mut stack, now, packets[0].end(), &[]);
    // Nothing new to send, so F-RTO cannot wait for new data: the next lost segment must go out
    // now instead of one timeout later.
    let next = drain(&mut stack, &mut now);
    assert_eq!(next.first().map(|p| p.h.seq), Some(packets[1].h.seq));
}

#[test]
fn zero_window_with_a_lost_head_retransmits_it_on_timeout_instead_of_probing() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(10_000)), Ok(10_000));
    let packets = drain(&mut stack, &mut now);
    assert_eq!(packets.len(), 10);
    now += 10 * MS;
    // The peer's buffer filled with the out-of-order data behind a lost head.
    peer.ack_window(
        &mut stack,
        now,
        peer.start,
        &[(packets[1].h.seq, packets[9].end())],
        0,
    );
    let fast = pull(&mut stack, now).expect("fast retransmit");
    assert_eq!(fast.h.seq, packets[0].h.seq); // lost in the network
    let mut resent = None;
    for _ in 0..4 {
        let Some(p) = next_packet(&mut stack, &mut now, 2000 * MS) else {
            break;
        };
        if !p.data.is_empty() {
            resent = Some(p);
            break;
        }
    }
    let resent = resent.expect("the timeout must retransmit the head, not only probe");
    assert_eq!(resent.h.seq, packets[0].h.seq);
}

#[test]
fn zero_window_probes_back_off_even_when_each_probe_is_answered() {
    let (mut stack, mut now, peer) = connect(false, false, false);
    peer.ack_window(&mut stack, now, peer.start, &[], 0);
    assert_eq!(stack.tcp_write(peer.id, &pattern(1000)), Ok(1000));
    assert!(
        pull(&mut stack, now).is_none(),
        "nothing goes into a closed window"
    );
    let mut times = Vec::new();
    for _ in 0..20 {
        let probe = next_packet(&mut stack, &mut now, 130_000 * MS).expect("zero-window probe");
        assert!(probe.data.is_empty());
        assert_eq!(probe.h.seq, peer.start.wrapping_sub(1));
        times.push(now);
        peer.ack_window(&mut stack, now, peer.start, &[], 0);
    }
    let gaps: Vec<_> = times.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(gaps.windows(2).all(|w| w[1] >= w[0]), "{gaps:?}");
    assert!(gaps[6] > 8 * gaps[0], "{gaps:?}");
    assert_eq!(gaps.last(), Some(&Duration::from_secs(120)));
    assert_eq!(stack.tcp_state(peer.id), Some(TcpState::Established));
}

#[test]
fn rto_keeps_sacked_data_and_a_second_loss_of_the_hole_is_not_undone() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(5000)), Ok(5000));
    let packets = drain(&mut stack, &mut now);
    assert_eq!(packets.len(), 5);
    let before = stats(&stack, &peer);
    now += 10 * MS;
    peer.ack(
        &mut stack,
        now,
        peer.start,
        &[(packets[1].h.seq, packets[4].end())],
    );
    let fast = pull(&mut stack, now).expect("fast retransmit");
    assert_eq!(fast.h.seq, packets[0].h.seq); // lost again
    while stats(&stack, &peer).rto_count == 0 {
        tick(&mut stack, &mut now);
    }
    let st = stats(&stack, &peer);
    assert_eq!((st.sacked_bytes, st.lost_bytes), (4 * MSS, MSS));
    let resent = pull(&mut stack, now).expect("timeout retransmission");
    assert_eq!(resent.h.seq, packets[0].h.seq);
    assert!(
        pull(&mut stack, now).is_none(),
        "SACKed segments are not resent"
    );
    now += 10 * MS;
    peer.ack(&mut stack, now, packets[4].end(), &[]);
    let after = stats(&stack, &peer);
    assert_eq!((after.undo_count, after.spurious_recoveries), (0, 0));
    assert!(
        after.cwnd < before.cwnd,
        "{} !< {}",
        after.cwnd,
        before.cwnd
    );
}

#[test]
fn forged_dsack_block_cannot_undo_a_recovery() {
    let (mut stack, mut now, peer) = connect(true, false, false);
    assert_eq!(stack.tcp_write(peer.id, &pattern(10_000)), Ok(10_000));
    let packets = drain(&mut stack, &mut now);
    now += 10 * MS;
    peer.ack(
        &mut stack,
        now,
        peer.start,
        &[(packets[1].h.seq, packets[9].end())],
    );
    let fast = pull(&mut stack, now).expect("fast retransmit");
    assert_eq!(fast.h.seq, packets[0].h.seq);
    let before = stats(&stack, &peer);
    // "Below the cumulative ACK" but reversed: its length wraps to about 2^32 bytes.
    peer.ack(
        &mut stack,
        now,
        peer.start,
        &[(peer.start.wrapping_add(5), peer.start.wrapping_sub(1))],
    );
    let after = stats(&stack, &peer);
    assert_eq!((after.undo_count, after.cwnd), (0, before.cwnd));
}

#[test]
fn syn_retry_backoff_does_not_leak_into_the_first_data_timeout() {
    let (stack, _, peer) = connect(false, false, true);
    assert_eq!(stats(&stack, &peer).rto, Duration::from_secs(1));
}

#[test]
fn a_sub_microsecond_ack_turnaround_without_an_rtt_sample_does_not_divide_by_zero() {
    // The SYN was retransmitted, so no handshake RTT sample exists when the first ACK arrives.
    let (mut stack, mut now, peer) = connect(false, false, true);
    assert_eq!(stack.tcp_write(peer.id, &pattern(1000)), Ok(1000));
    let packets = drain(&mut stack, &mut now);
    peer.ack(
        &mut stack,
        now + Duration::from_nanos(500),
        packets[0].end(),
        &[],
    );
    assert_eq!(stats(&stack, &peer).outstanding_bytes, 0);
}

#[test]
fn acks_do_not_count_as_activity_for_the_idle_restart() {
    let (mut stack, mut now, mut peer) = connect(false, false, false);
    grow(&mut stack, &mut now, &mut peer, 40);
    assert!(stats(&stack, &peer).cwnd >= 40 * MSS);
    let snd_nxt = round(&mut stack, &mut now, &mut peer, MSS as usize)
        .last()
        .unwrap()
        .end();
    // Only the peer sends for a while; our ACKs are the last packets we emit before the next write.
    now += 1900 * MS;
    peer.data(&mut stack, now, snd_nxt, &[7; 100]);
    let ack = pull(&mut stack, now).expect("ACK of the peer's data");
    assert!(ack.data.is_empty());
    now += 100 * MS;
    assert_eq!(
        stack.tcp_write(peer.id, &pattern(40 * MSS as usize)),
        Ok(40 * MSS as usize)
    );
    drain(&mut stack, &mut now);
    assert!(
        stats(&stack, &peer).cwnd <= 10 * MSS,
        "two seconds without data restart the window: {}",
        stats(&stack, &peer).cwnd
    );
}
