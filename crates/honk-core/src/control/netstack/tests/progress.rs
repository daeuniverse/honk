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
