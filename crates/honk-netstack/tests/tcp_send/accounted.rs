use super::*;
use honk_netstack::{ExcludeSet, MemoryBudget, Mode};
use std::sync::Arc;

const CHUNK: usize = 4096;

fn connected(mode: Mode, max_flows: usize) -> (Stack, Arc<MemoryBudget>, Instant, Peer) {
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let mut cfg = config();
    cfg.mode = mode;
    cfg.max_flows = u32::try_from(max_flows).unwrap();
    cfg.memory_limit = 512 * 1024;
    cfg.tcp_chunk = Some(CHUNK);
    cfg.tcp_rcv_buf_max = CHUNK;
    cfg.shared_budget = Some(budget.clone());
    let mut now = Instant::now();
    let mut stack = Stack::new_accounted(cfg, now, max_flows).unwrap();
    let peer = open(&mut stack, &mut now, remote(false), false, true);
    (stack, budget, now, peer)
}

fn round(stack: &mut Stack, now: &mut Instant, peer: &Peer, bytes: usize) {
    let payload = pattern(bytes);
    assert_eq!(stack.tcp_write(peer.id, &payload), Ok(bytes));
    let packets = drain_paced(stack, now);
    assert_eq!(
        packets
            .iter()
            .flat_map(|p| p.data().iter().copied())
            .collect::<Vec<_>>(),
        payload
    );
    *now += Duration::from_millis(10);
    peer.ack(stack, *now, packets.last().unwrap().end());
    events(stack, peer.id);
}

#[test]
fn chunk_without_next_index_credit_stays_blocked_until_budget_release_and_wakes_once() {
    let (mut stack, budget, mut now, peer) = connected(Mode::Endpoint, 1);
    round(&mut stack, &mut now, &peer, 10 * usize::from(MSS));
    let payload = pattern(4 * CHUNK);
    assert_eq!(stack.tcp_write(peer.id, &payload), Ok(payload.len()));
    let packets = drain_paced(&mut stack, &mut now);
    let mut delivered = packets
        .iter()
        .flat_map(|p| p.data().iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(delivered, payload);
    let held = budget
        .reserve(budget.limit() - budget.used() - CHUNK - 1)
        .unwrap();
    let last_byte = budget.reserve(1).unwrap();
    assert_eq!(budget.limit() - budget.used(), CHUNK);
    assert_eq!(
        stack.tcp_write(peer.id, b"blocked"),
        Err(StreamError::WouldBlock)
    );
    assert_eq!(budget.limit() - budget.used(), CHUNK);

    now += Duration::from_millis(10);
    peer.ack(&mut stack, now, packets[0].end());
    assert!(
        !events(&mut stack, peer.id).contains(Ready::WRITABLE),
        "a partial ACK does not fund the next chunk's index expansion"
    );
    drop(last_byte);
    assert_eq!(
        stack.tcp_read(peer.id, &mut [0; 1]),
        Err(StreamError::WouldBlock)
    );
    assert!(!events(&mut stack, peer.id).contains(Ready::WRITABLE));
    assert_eq!(budget.limit() - budget.used(), CHUNK + 1);

    drop(held);
    stack.handle_timeout(now);
    let (id, ready) = stack
        .poll_event()
        .expect("released index credit wakes the retained writer");
    assert_eq!(id, peer.id);
    assert!(ready.contains(Ready::WRITABLE));
    assert!(stack.poll_event().is_none());
    stack.handle_timeout(now);
    assert!(
        stack.poll_event().is_none(),
        "one blocked write yields one readiness edge"
    );
    let extra = vec![0xa5; CHUNK];
    let before = budget.used();
    assert_eq!(stack.tcp_write(peer.id, &extra), Ok(extra.len()));
    assert_eq!(
        budget.used() - before,
        CHUNK + 4 * std::mem::size_of::<Box<[u8]>>()
    );
    peer.ack(&mut stack, now, packets.last().unwrap().end());
    let mut next = packets.last().unwrap().end();
    let mut expected = payload;
    expected.extend_from_slice(&extra);
    while delivered.len() < expected.len() {
        let packets = drain_paced(&mut stack, &mut now);
        assert!(!packets.is_empty());
        for packet in &packets {
            assert_eq!(packet.h.seq, next);
            next = packet.end();
            delivered.extend_from_slice(packet.data());
        }
        now += Duration::from_millis(10);
        peer.ack(&mut stack, now, next);
    }
    assert_eq!(delivered, expected);
    assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 0);
    assert!(drain_paced(&mut stack, &mut now).is_empty());
    assert!(!events(&mut stack, peer.id).contains(Ready::WRITABLE));
    drop(stack);
    assert_eq!(budget.used(), 0);
}

#[test]
fn rack_capacity_refusal_preserves_retransmission_until_shared_budget_resumes() {
    let (mut stack, budget, mut now, peer) = connected(Mode::Endpoint, 1);
    while stack.tcp_stats(peer.id).unwrap().cwnd < 60 * u32::from(MSS) {
        let bytes = stack.tcp_stats(peer.id).unwrap().cwnd as usize;
        round(&mut stack, &mut now, &peer, bytes);
    }
    let payload = pattern(60 * usize::from(MSS));
    assert_eq!(stack.tcp_write(peer.id, &payload), Ok(payload.len()));
    let original = drain_paced(&mut stack, &mut now);
    assert_eq!(original.len(), 60);
    let before = budget.used();
    let held = budget.reserve(budget.limit() - before).unwrap();
    now += Duration::from_millis(10);
    let mut header = peer.header(now, original[0].h.seq);
    header
        .options
        .sack
        .push(original[28].h.seq, original.last().unwrap().end());
    assert_eq!(stack.receive(now, &peer.packet(&header, &[])), Rx::Consumed);
    let mut retransmitted = drain_paced(&mut stack, &mut now);
    assert_eq!(
        retransmitted.len(),
        16,
        "the funded RACK FIFO floor still progresses"
    );
    assert_eq!(stack.tcp_stats(peer.id).unwrap().retrans_segments, 16);
    for _ in 0..3 {
        assert!(
            pull(&mut stack, now).is_none(),
            "unfunded FIFO growth must not emit a packet"
        );
    }
    assert_eq!(stack.tcp_stats(peer.id).unwrap().retrans_segments, 16);
    assert_eq!(budget.used(), budget.limit());
    drop(held);
    retransmitted.extend(drain_paced(&mut stack, &mut now));
    assert_eq!(retransmitted.len(), 28);
    assert_eq!(stack.tcp_stats(peer.id).unwrap().retrans_segments, 28);
    assert!(
        budget.used() > before,
        "retained FIFO expansion owns shared credit"
    );
    for (got, expected) in retransmitted.iter().zip(&original[..28]) {
        assert_eq!(got.h.seq, expected.h.seq);
        assert_eq!(got.data(), expected.data());
    }
    assert!(pull(&mut stack, now).is_none());
    now += Duration::from_millis(10);
    peer.ack(&mut stack, now, original.last().unwrap().end());
    assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 0);
    drop(stack);
    assert_eq!(budget.used(), 0);
}

#[test]
fn rack_capacity_deferral_serves_funded_tcp_and_udp_before_retransmission_resumes() {
    let mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    let (mut stack, budget, mut now, peer) = connected(mode, 2);
    let mut other_dst = remote(false);
    other_dst.set_port(444);
    let other = open(&mut stack, &mut now, other_dst, false, true);
    while stack.tcp_stats(peer.id).unwrap().cwnd < 60 * u32::from(MSS) {
        let bytes = stack.tcp_stats(peer.id).unwrap().cwnd as usize;
        round(&mut stack, &mut now, &peer, bytes);
    }
    let payload = pattern(60 * usize::from(MSS));
    assert_eq!(stack.tcp_write(peer.id, &payload), Ok(payload.len()));
    let original = drain_paced(&mut stack, &mut now);
    assert_eq!(original.len(), 60);
    let held = budget.reserve(budget.limit() - budget.used()).unwrap();
    now += Duration::from_millis(10);
    let mut header = peer.header(now, original[0].h.seq);
    header
        .options
        .sack
        .push(original[28].h.seq, original.last().unwrap().end());
    assert_eq!(stack.receive(now, &peer.packet(&header, &[])), Rx::Consumed);
    let mut retransmitted = drain_paced(&mut stack, &mut now);
    assert_eq!(retransmitted.len(), 16);
    let blocked = stack.tcp_stats(peer.id).unwrap();
    assert_eq!(blocked.retrans_segments, 16);

    // A class-0 reply leaves the next ordinary pull starting before ready TCP and queued UDP.
    header.dst_port = 1;
    header.options.sack = Default::default();
    assert_eq!(
        stack.receive(now, &peer.packet(&header, &[])),
        Rx::Dropped(DropReason::NoFlow)
    );
    assert_eq!(pull(&mut stack, now).unwrap().h.flags, tcp::RST);
    drop(held);
    let udp_payload = pattern(6000);
    let mut out = [0; 2048];
    let n = stack
        .udp_send_from(peer.local, peer.remote, &udp_payload, &mut out)
        .unwrap();
    let mut udp = out[20..n].to_vec();
    let held = budget.reserve(budget.limit() - budget.used()).unwrap();
    let funded = pattern(3 * usize::from(MSS));
    assert_eq!(stack.tcp_write(other.id, &funded), Ok(funded.len()));
    let deadline = stack.poll_timeout();
    for _ in 0..3 {
        assert!(stack.poll_control_transmit(now, &mut out).is_none());
        assert!(stack.poll_transmit(now, &mut [0; 1]).is_none());
        assert_eq!(stack.poll_timeout(), deadline);
        assert_eq!(stack.tcp_stats(peer.id).unwrap().retrans_segments, 16);
    }

    let mut received = Vec::new();
    let mut udp_fragments = 0;
    for _ in 0..8 {
        assert_eq!(budget.used(), budget.limit());
        let tx = stack
            .poll_transmit_with(now, &mut out, honk_netstack::TxCaps::NONE)
            .expect("funded TCP and UDP must bypass unfunded RACK growth");
        if out[9] == wire::PROTO_TCP {
            assert_eq!(tx.flow, Some(other.id));
            let packet = Packet::decode(out[..tx.len].to_vec());
            assert_eq!(
                packet.h.seq,
                other.start.wrapping_add(received.len() as u32)
            );
            received.extend_from_slice(packet.data());
        } else {
            assert_eq!(out[9], wire::PROTO_UDP);
            assert_eq!(tx.flow, None);
            assert_eq!(wire::checksum::checksum(&out[..20]), 0);
            let offset = usize::from(u16::from_be_bytes([out[6], out[7]]) & 0x1fff) * 8;
            assert_eq!(offset, udp.len());
            udp.extend_from_slice(&out[20..tx.len]);
            udp_fragments += 1;
        }
        let still_blocked = stack.tcp_stats(peer.id).unwrap();
        assert_eq!(still_blocked.retrans_segments, blocked.retrans_segments);
        assert_eq!(still_blocked.retrans_bytes, blocked.retrans_bytes);
        assert_eq!(still_blocked.lost_bytes, blocked.lost_bytes);
        assert_eq!(still_blocked.tlp_probes, blocked.tlp_probes);
        assert_eq!(still_blocked.rto_count, blocked.rto_count);
        if udp.len() == udp_payload.len() + 8 {
            break;
        }
    }
    assert_eq!(received, funded);
    assert!(udp_fragments >= 3);
    assert_eq!(&udp[8..], udp_payload);
    assert!(wire::udp::verify_checksum(
        peer.local.ip(),
        peer.remote.ip(),
        &udp
    ));
    drop(held);
    retransmitted.extend(drain_paced(&mut stack, &mut now));
    assert_eq!(retransmitted.len(), 28);
    for (got, expected) in retransmitted.iter().zip(&original[..28]) {
        assert_eq!((got.h.seq, got.data()), (expected.h.seq, expected.data()));
    }
    assert_eq!(stack.tcp_stats(peer.id).unwrap().retrans_segments, 28);
    assert!(pull(&mut stack, now).is_none());
    peer.ack(&mut stack, now, original.last().unwrap().end());
    other.ack(
        &mut stack,
        now,
        other.start.wrapping_add(funded.len() as u32),
    );
    assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 0);
    assert_eq!(stack.tcp_stats(other.id).unwrap().outstanding_bytes, 0);
    drop(stack);
    assert_eq!(budget.used(), 0);
}
