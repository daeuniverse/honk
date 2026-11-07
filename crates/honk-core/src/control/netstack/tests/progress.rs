use super::*;

#[test]
fn sustained_control_flood_still_emits_bulk_payload_once() {
    let now = Instant::now();
    let budget = MemoryBudget::new(32 << 20);
    let (scope, _owner) = PacketScope::new(
        config(),
        budget,
        RuntimeLimits {
            control_frames: BATCH,
            ..limits()
        },
        now,
    )
    .unwrap();
    let (mut io, _) = handshake(&scope, now, "10.0.0.2:40000".parse().unwrap(), 100);
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), b"bulk"),
        Poll::Ready(Ok(4))
    ));
    let mut bulk = Vec::new();
    for _ in 0..8 {
        for port in 40001..40001 + BATCH as u16 {
            let peer = SocketAddr::new("10.0.0.2".parse().unwrap(), port);
            scope.receive(&segment(peer, 1, 2, tcp::ACK, &[]), now);
        }
        scope.drive(now);
        for _ in 0..BATCH {
            let Poll::Ready(Some(output)) = scope.poll_output(&mut context()) else {
                break;
            };
            let (_, bytes) = decode(&output);
            if !bytes.is_empty() {
                assert_eq!(output.flow_id(), Some(io.flow_id()));
                bulk.extend_from_slice(&bytes);
            }
            output.release();
        }
    }
    assert_eq!(bulk, b"bulk");
}

#[test]
fn graceful_drain_retains_fragment_timeout_and_its_icmp_output() {
    for (source, destination) in [
        ("10.0.0.2:40000", "203.0.113.9:443"),
        ("[fd00::2]:40000", "[2001:db8::9]:443"),
    ] {
        let now = Instant::now();
        let (source, destination): (SocketAddr, SocketAddr) =
            (source.parse().unwrap(), destination.parse().unwrap());
        let mut cfg = config();
        cfg.fragment_limits.timeout = Duration::from_secs(10);
        let (scope, _owner) =
            PacketScope::new(cfg, MemoryBudget::new(32 << 20), limits(), now).unwrap();
        let mut peer = Stack::new(config(), now);
        let mut first = [0; 1280];
        let length = peer
            .udp_send_from(source, destination, &[7; 4000], &mut first)
            .unwrap();
        assert_eq!(scope.receive(&first[..length], now), Rx::Consumed);
        scope.shutdown(false);
        scope.drive(now);
        assert!(
            !scope.0.inner.lock().finish(),
            "incomplete IP reassembly still owns a timeout"
        );
        scope.drive(now + Duration::from_secs(11));
        let response = output(&scope);
        let ip = wire::parse_ip(response.packet()).unwrap();
        assert_eq!((ip.src, ip.dst), (destination.ip(), source.ip()));
        let message = &response.packet()[ip.payload];
        assert_eq!(
            (message[0], message[1]),
            (if source.is_ipv6() { 3 } else { 11 }, 1)
        );
        assert_eq!(
            &message[8..],
            &first[..if source.is_ipv6() { 56 } else { 28 }]
        );
        assert!(
            !scope.0.inner.lock().finish(),
            "exported ICMP storage is still owned"
        );
        response.release();
        assert!(scope.0.inner.lock().finish());
    }
}

#[tokio::test]
async fn graceful_fragmented_udp_drain_preserves_every_accepted_byte() {
    let now = Instant::now();
    let (scope, owner, _) = runtime(now);
    let source: SocketAddr = "203.0.113.9:53".parse().unwrap();
    let destination: SocketAddr = "10.0.0.2:40000".parse().unwrap();
    let payload: Vec<u8> = (0..4000).map(|value| (value % 251) as u8).collect();
    scope
        .datagram_sender(source)
        .send_to(&payload, destination)
        .await
        .unwrap();
    let mut receiver = Stack::new(config(), now);
    let mut completed = None;
    scope.shutdown(false);
    for _ in 0..8 {
        scope.drive(now);
        while let Poll::Ready(Some(output)) = scope.poll_output(&mut context()) {
            match receiver.receive(now, output.packet()) {
                Rx::Consumed => {}
                Rx::TransparentOwned {
                    packet, payload, ..
                } => {
                    assert!(completed.replace(packet[payload].to_vec()).is_none());
                }
                other => panic!("fragment drain lost its datagram: {other:?}"),
            }
            output.release();
        }
        if scope.0.inner.lock().finish() {
            break;
        }
    }
    assert_eq!(completed.as_deref(), Some(payload.as_slice()));
    assert!(scope.0.inner.lock().finished);
    owner.run().await;
}

#[test]
fn direct_rack_deferral_preserves_deadline_credit_and_original_retransmissions() {
    fn drain(driver: &mut PacketDriver, now: &mut Instant) -> Vec<(tcp::Header, Vec<u8>)> {
        let mut packets = Vec::new();
        let mut frame = [0; 1280];
        for _ in 0..128 {
            driver.begin_turn(*now);
            let before = packets.len();
            for _ in 0..32 {
                let Some(owner) = driver
                    .materialize_into(*now, TxClass::Bulk, &mut frame)
                    .unwrap()
                else {
                    break;
                };
                assert!(owner.packet().is_none());
                packets.push(decode_packet(&frame[..owner.len()]));
                drop(owner);
            }
            driver.finish_turn(&mut context(), *now);
            if packets.len() - before == 32 {
                continue;
            }
            match driver.deadline() {
                Some(due) if due <= *now + Duration::from_millis(5) => *now = due.max(*now),
                _ => return packets,
            }
        }
        panic!("direct packet drain exceeded its bounded pacing turns");
    }

    let mut now = Instant::now();
    let mut cfg = config();
    cfg.tcp_chunk = Some(4096);
    cfg.tcp_snd_buf_max = 256 * 1024;
    let budget = MemoryBudget::new(32 << 20);
    let (scope, owner) = PacketScope::new(cfg, Arc::clone(&budget), limits(), now).unwrap();
    let mut driver = owner.hand_off();
    let client = "10.0.0.2:40000".parse().unwrap();
    let options = tcp::Options {
        mss: Some(1000),
        sack_permitted: true,
        ..tcp::Options::default()
    };
    assert_eq!(
        scope.receive(
            &segment_with_options(client, 100, 0, tcp::SYN, &[], options),
            now
        ),
        Rx::Consumed
    );
    let (_, mut io) = scope.poll_accept().unwrap();
    let id = io.flow_id();
    let mut frame = [0; 1280];
    driver.begin_turn(now);
    let synack = materialized(&mut driver, now, TxClass::Control, &mut frame);
    let server_seq = decode_packet(&frame[..synack.len()]).0.seq.wrapping_add(1);
    drop(synack);
    now += Duration::from_millis(10);
    scope.receive(&segment(client, 101, server_seq, tcp::ACK, &[]), now);
    driver.begin_turn(now);
    driver.finish_turn(&mut context(), now);
    for _ in 0..8 {
        let cwnd = scope
            .0
            .inner
            .lock()
            .stack
            .as_ref()
            .unwrap()
            .tcp_stats(id)
            .unwrap()
            .cwnd;
        if cwnd >= 60_000 {
            break;
        }
        let payload: Vec<_> = (0..cwnd as usize).map(|n| (n % 251) as u8).collect();
        assert!(matches!(
            std::pin::Pin::new(&mut io).poll_write(&mut context(), &payload),
            Poll::Ready(Ok(n)) if n == payload.len()
        ));
        let packets = drain(&mut driver, &mut now);
        assert_eq!(
            packets
                .iter()
                .flat_map(|(_, bytes)| bytes.iter().copied())
                .collect::<Vec<_>>(),
            payload
        );
        let (header, bytes) = packets.last().unwrap();
        now += Duration::from_millis(10);
        scope.receive(
            &segment(
                client,
                101,
                header.seq.wrapping_add(bytes.len() as u32),
                tcp::ACK,
                &[],
            ),
            now,
        );
        driver.begin_turn(now);
        driver.finish_turn(&mut context(), now);
    }
    assert!(
        scope
            .0
            .inner
            .lock()
            .stack
            .as_ref()
            .unwrap()
            .tcp_stats(id)
            .unwrap()
            .cwnd
            >= 60_000
    );
    let payload: Vec<_> = (0..60_000).map(|n| (n % 251) as u8).collect();
    assert!(matches!(
        std::pin::Pin::new(&mut io).poll_write(&mut context(), &payload),
        Poll::Ready(Ok(n)) if n == payload.len()
    ));
    let original = drain(&mut driver, &mut now);
    assert_eq!(original.len(), 60);
    let before = budget.used();
    let held = budget.reserve(budget.limit() - before).unwrap();
    now += Duration::from_millis(10);
    let (last, bytes) = original.last().unwrap();
    let end = last.seq.wrapping_add(bytes.len() as u32);
    let mut options = tcp::Options::default();
    options.sack.push(original[28].0.seq, end);
    assert_eq!(
        scope.receive(
            &segment_with_options(client, 101, original[0].0.seq, tcp::ACK, &[], options),
            now
        ),
        Rx::Consumed
    );
    let mut retransmitted = drain(&mut driver, &mut now);
    assert_eq!(retransmitted.len(), 16);
    let deadline = driver.deadline();
    let blocked = scope
        .0
        .inner
        .lock()
        .stack
        .as_ref()
        .unwrap()
        .tcp_stats(id)
        .unwrap();
    assert_eq!(blocked.retrans_segments, 16);
    for _ in 0..3 {
        driver.begin_turn(now);
        for class in [TxClass::Control, TxClass::Bulk] {
            assert!(
                driver
                    .materialize_into(now, class, &mut frame)
                    .unwrap()
                    .is_none()
            );
        }
        driver.finish_turn(&mut context(), now);
        assert_eq!(driver.deadline(), deadline);
        assert_eq!(
            driver.deadline(),
            scope.0.inner.lock().stack.as_ref().unwrap().poll_timeout()
        );
        let mut inner = scope.0.inner.lock();
        let after = inner.stack.as_ref().unwrap().tcp_stats(id).unwrap();
        assert_eq!(
            (
                after.retrans_segments,
                after.retrans_bytes,
                after.lost_bytes
            ),
            (
                blocked.retrans_segments,
                blocked.retrans_bytes,
                blocked.lost_bytes
            )
        );
        assert_eq!(inner.ledger.outstanding_tx().count(), 0);
        assert!(inner.frames.iter().all(Option::is_some));
        for class in [TxClass::Control, TxClass::Bulk] {
            let lease = inner.ledger.reserve_tx(class).unwrap();
            inner.ledger.cancel_tx(lease).unwrap();
        }
        assert_eq!(budget.used(), budget.limit());
    }
    drop(held);
    retransmitted.extend(drain(&mut driver, &mut now));
    assert_eq!(retransmitted.len(), 28);
    assert!(budget.used() > before);
    for ((header, bytes), (expected, payload)) in retransmitted.iter().zip(&original[..28]) {
        assert_eq!((header.seq, bytes), (expected.seq, payload));
    }
    now += Duration::from_millis(10);
    scope.receive(&segment(client, 101, end, tcp::ACK, &[]), now);
    driver.begin_turn(now);
    driver.finish_turn(&mut context(), now);
    assert_eq!(
        scope
            .0
            .inner
            .lock()
            .stack
            .as_ref()
            .unwrap()
            .tcp_stats(id)
            .unwrap()
            .outstanding_bytes,
        0
    );
    assert_eq!(scope.0.inner.lock().queued, 0);
}
