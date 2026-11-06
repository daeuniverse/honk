use super::*;

#[tokio::test]
async fn source_receipts_preserve_udp_queue_pressure_and_reject_unowned_scopes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = local_plane().await;
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        let permits: Vec<_> = (0..INGRESS_CAPACITY)
            .map(|_| endpoints.sender.try_reserve().unwrap())
            .collect();
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.9:443".parse().unwrap();
        let expected = ValidatedSource {
            src: source,
            dst: destination,
            protocol: wire::PROTO_UDP,
            tcp_flags: None,
        };
        let mut packet = [0; 128];
        let length =
            wire::udp::emit_packet(&mut packet, source, destination, b"source-before-work")
                .unwrap();
        let now = Instant::now();
        let mut observed = Vec::new();
        let error = endpoints
            .receive_with_source(scope.scope(), &packet[..length], now, false, |source, _| {
                observed.push(source);
                true
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(
            observed,
            vec![expected],
            "a receipt is validity, not UDP queue admission"
        );
        assert_eq!(
            endpoints
                .receive(scope.scope(), &packet[..length], now)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            endpoints
                .receive_with_source(scope.scope(), &packet[..length], now, false, |_, _| false)
                .unwrap(),
            Some(expected)
        );
        assert_eq!(
            endpoints.sender.capacity(),
            0,
            "source refusal must not consume reserved work slots"
        );
        packet[length - 1] ^= 1;
        assert_eq!(
            endpoints
                .receive_with_source(scope.scope(), &packet[..length], now, false, |_, _| panic!(
                    "bad checksum reported a source"
                ))
                .unwrap(),
            None
        );
        let foreign = ScopeId::allocate().unwrap();
        assert_eq!(
            endpoints
                .receive_with_source(foreign, &packet[..length], now, false, |_, _| panic!(
                    "unowned scope reached the parser"
                ))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        endpoints.close();
        drop(permits);
        assert!(
            endpoints.capture_ready().is_err(),
            "capture readiness must not reopen closing admission"
        );
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("source receipt pressure fixture must join");
}

#[cfg(feature = "native-api")]
#[tokio::test]
async fn observed_routing_admission_funds_its_real_route_and_transfers_the_charge() {
    let (mut plane, _health) = local_plane().await;
    let _native = crate::native_api::observation::NativeObservation::attach(&mut plane).await;
    let handle = plane.spawn_handle();
    let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.9:443".parse().unwrap();
    let budget = MemoryBudget::new(1 << 20);
    let plain = handle
        .prepare_packet_routing_snapshot(source, destination, "tcp", 0, false)
        .await
        .unwrap();
    let plain = EndpointAdmission::new(plain, &budget).unwrap();
    let plain_bytes = budget.used();
    drop(plain);
    assert_eq!(budget.used(), 0);
    let observed = handle
        .prepare_packet_routing_snapshot(source, destination, "tcp", 0, true)
        .await
        .unwrap();
    let insufficient = MemoryBudget::new(plain_bytes);
    let error = EndpointAdmission::new(observed, &insufficient).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(insufficient.used(), 0);
    let observed = handle
        .prepare_packet_routing_snapshot(source, destination, "tcp", 0, true)
        .await
        .unwrap();
    let admission = EndpointAdmission::new(observed, &budget).unwrap();
    let charged = budget.used();
    assert!(charged > plain_bytes);
    let snapshot = admission.into_snapshot();
    assert_eq!(budget.used(), charged);
    drop(snapshot);
    assert_eq!(budget.used(), 0);
}
