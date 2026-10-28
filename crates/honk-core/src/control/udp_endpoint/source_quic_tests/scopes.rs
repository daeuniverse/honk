use super::*;

#[tokio::test]
async fn overlapping_scopes_keep_real_associations_replies_and_close_independent() {
    for mode in MODES {
        let scopes = [ScopeId::HOST, ScopeId::allocate().unwrap()];
        let mut f = Fixture::with_scopes(mode, false, &scopes).await;
        let client = f.client();
        let target = f.target(0);
        let lease_a = f.reserve(scopes[0], client, target, b"scope-a");
        let generation_a = lease_a.generation();
        let attachment_a = f
            .prepare(scopes[0], client, target, None, false)
            .await
            .commit(&f.pool)
            .await
            .unwrap();
        let (a, mut driver_a) = f
            .install(lease_a, attachment_a, client, target, target)
            .await;
        driver_a.wait_first_ack().await.unwrap();
        let packet_a = f.packet().await;
        assert_eq!(packet_a.payload, b"scope-a");

        let lease_b = f.reserve(scopes[1], client, target, b"scope-b");
        let attachment_b = f
            .prepare(scopes[1], client, target, None, false)
            .await
            .commit(&f.pool)
            .await
            .unwrap();
        let (b, mut driver_b) = f
            .install(lease_b, attachment_b, client, target, target)
            .await;
        driver_b.wait_first_ack().await.unwrap();
        let packet_b = f.packet().await;
        assert_eq!(packet_b.payload, b"scope-b");
        assert_ne!(
            (packet_a.connection, packet_a.session),
            (packet_b.connection, packet_b.session),
        );

        f.targets[0]
            .send_to(b"reply-a", packet_a.mapping)
            .await
            .unwrap();
        assert_eq!(received(&f.client).await, (b"reply-a".to_vec(), target));
        assert!(a.has_reply());
        assert!(!b.has_reply());
        assert_eq!(a.download.load(Ordering::Relaxed), 7);
        assert_eq!(b.download.load(Ordering::Relaxed), 0);

        let foreign = f.target(1);
        let pending_b = f.reserve(scopes[1], client, foreign, b"not-sent");
        f.targets[1]
            .send_to(b"foreign-a", packet_a.mapping)
            .await
            .unwrap();
        assert_eq!(received(&f.client).await, (b"foreign-a".to_vec(), foreign));
        assert!(pending_b.still_initializing());
        assert!(!f.pool.contains(scopes[0], client, foreign));
        assert_eq!(a.download.load(Ordering::Relaxed), 7);
        assert_eq!(b.download.load(Ordering::Relaxed), 0);
        drop(pending_b);

        assert!(
            f.pool
                .close_exact(scopes[0], client, target, 0, generation_a)
        );
        assert!(
            !f.pool
                .close_exact(scopes[0], client, target, 0, generation_a)
        );
        assert!(f.pool.get(scopes[1], client, target).is_some());
        f.targets[0]
            .send_to(b"late-a", packet_a.mapping)
            .await
            .unwrap();
        no_reply(&f.client).await;
        assert!(matches!(
            f.pool
                .fast_path_enqueue(scopes[1], client, target, b"survivor-b", &f.stats),
            Some(EndpointReservation::Enqueued)
        ));
        let survivor = f.packet().await;
        assert_eq!(survivor.payload, b"survivor-b");
        assert_eq!(
            (survivor.connection, survivor.session),
            (packet_b.connection, packet_b.session),
        );
        f.targets[0]
            .send_to(b"reply-b", survivor.mapping)
            .await
            .unwrap();
        assert_eq!(received(&f.client).await, (b"reply-b".to_vec(), target));
        assert!(b.has_reply());
        assert_eq!(b.download.load(Ordering::Relaxed), 7);
        drop((a, b, driver_a, driver_b));
        f.shutdown().await;
    }
}

#[tokio::test]
async fn source_attachment_cannot_publish_in_another_scope() {
    let f = Fixture::new(QuicUdpMode::Hysteria2, false).await;
    let domain = ScopeId::allocate().unwrap();
    let target = f.target(0);
    let mut lease = f.reserve(domain, f.client(), target, b"not-sent");
    let attachment = f
        .prepare(ScopeId::HOST, f.client(), target, None, false)
        .await
        .commit(&f.pool)
        .await
        .unwrap();
    let endpoint = Arc::new(UdpEndpoint::new_source_scored(
        attachment,
        target,
        None,
        Arc::new(f.pool.create_reply_socket(ScopeId::HOST, target).unwrap()),
        f.stats
            .outbound_tracker(&f.peer.node.name, crate::stats::OutboundKind::Node),
        f.peer.node.id,
        f.family,
        None,
    ));
    assert!(!lease.commit_ready(Arc::clone(&endpoint)));
    assert!(lease.still_initializing());
    assert!(f.pool.get(domain, f.client(), target).is_none());
    assert_eq!(
        f.pool.endpoint_slots.available_permits(),
        TEST_ENDPOINTS - 1
    );
    drop((endpoint, lease));
    f.shutdown().await;
}
