use super::*;

#[tokio::test]
async fn physical_syn_admission_reclaims_completed_udp_task_credit() {
    use crate::control::netstack::{CAPTURE_MEMORY, capture_realm};
    use crate::xdp::{ReturnPath, worker::PeerAuthority};

    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, mut owners) = capture_realm(1280, 1, 16, 1, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap();
    let (plane, _health) = local_plane().await;
    let (endpoints, supervisor) =
        PacketEndpoints::new(plane, vec![(scope.clone(), owners.pop().unwrap())], 1)
            .await
            .unwrap();
    let (done, completed) = tokio::sync::oneshot::channel();
    let payload = [7u8; 65_536];
    assert!(endpoints.shared.udp_pool.spawn_slow_path(async move {
        std::hint::black_box(payload);
        done.send(()).unwrap();
    }));
    completed.await.unwrap();
    assert!(!endpoints.can_batch_tcp());
    let peers =
        PeerAuthority::new(Arc::new(std::sync::atomic::AtomicBool::new(true)), &budget).unwrap();
    let ceiling = budget.reserve(budget.limit() - budget.used()).unwrap();
    let path = ReturnPath {
        realm: 1,
        device: 0,
        mac: [2; 6],
        vlan_tci: [0; 2],
        vlan_proto: [0; 2],
        vlan_count: 0,
    };
    let mut packet = [0; 128];
    let n = syn_packet("203.0.113.9:443".parse().unwrap(), &mut packet);
    let now = Instant::now();
    let report = endpoints
        .receive_on_timed(
            scope,
            &packet[..n],
            now,
            now,
            None,
            false,
            |source, pending| peers.retain(scope.scope(), source, path, now, pending),
        )
        .unwrap();
    assert!(report.taken_over && !report.qualified_rx);
    assert_eq!(scope.stats().unwrap().flows, 1);
    assert!(endpoints.can_batch_tcp());
    drop(ceiling);
    endpoints.shutdown().await.unwrap();
    supervisor.run().await.unwrap();
}

#[tokio::test]
async fn one_logical_realm_drives_two_owners_through_the_shared_udp_pool() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let budget = MemoryBudget::new(super::super::super::netstack::CAPTURE_MEMORY);
        let (realm, owners) =
            super::super::super::netstack::capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
        let clients: [SocketAddr; 2] = std::array::from_fn(|worker| {
            (1..=254)
                .map(|last| SocketAddr::from(([192, 0, 2, last], 41000)))
                .find(|client| realm.worker_for_udp(client.ip()) == worker)
                .unwrap()
        });
        let (plane, _health) = local_plane().await;
        let (endpoints, mut owner, drivers) = PacketEndpoints::start(
            plane,
            vec![(realm.clone(), owners)],
            4,
            false,
            None,
            ScopeId::HOST,
        )
        .await
        .unwrap();
        assert!(drivers.is_empty());
        std::future::poll_fn(|cx| owner.poll_ready(cx))
            .await
            .unwrap();
        assert_eq!(endpoints.shared.realms.len(), 1);
        assert_eq!(endpoints.shared.scopes.len(), 2);
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut bytes = [0; 64];
            for _ in 0..2 {
                let (len, source) = upstream.recv_from(&mut bytes).await.unwrap();
                upstream.send_to(&bytes[..len], source).await.unwrap();
            }
        });
        for (worker, client) in clients.into_iter().enumerate() {
            let mut bytes = [0; 128];
            let len =
                wire::udp::emit_packet(&mut bytes, client, destination, &[worker as u8]).unwrap();
            let (selected, _claim) = endpoints
                .execution_owner(realm.scope(), wire::PacketView::from_slice(&bytes[..len]))
                .unwrap();
            assert!(selected.same_owner(&realm.owners()[worker]));
            endpoints
                .receive(realm.scope(), &bytes[..len], Instant::now())
                .unwrap();
            let reply = realm.owners()[worker].next_output().await.unwrap();
            let ip = wire::parse_ip(reply.packet()).unwrap();
            assert_eq!(ip.dst, client.ip());
            assert_eq!(ip.src, destination.ip());
            assert!(endpoints.retained_transport(
                realm.scope(),
                client,
                destination,
                wire::PROTO_UDP
            ));
            assert!(!realm.owners()[1 - worker].retains_source(client.ip()));
            reply.release();
        }
        echo.await.unwrap();
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("two real endpoint owners and their shared UDP pool must join");
}

#[tokio::test]
async fn realm_start_refuses_swapped_original_owner_capabilities() {
    let budget = MemoryBudget::new(super::super::super::netstack::CAPTURE_MEMORY);
    let (realm, mut owners) =
        super::super::super::netstack::capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
    owners.swap(0, 1);
    let (plane, _health) = local_plane().await;
    let result = PacketEndpoints::start(
        plane,
        vec![(realm.clone(), owners)],
        4,
        false,
        None,
        ScopeId::HOST,
    )
    .await;
    assert!(
        result.is_err(),
        "same logical scope cannot substitute another Stack's owner"
    );
    assert!(
        realm
            .owners()
            .iter()
            .all(PacketScope::is_protocol_quiescent)
    );
}

#[tokio::test]
async fn shared_reply_factory_resolves_each_foreign_client_to_its_actual_owner() {
    let budget = MemoryBudget::new(super::super::super::netstack::CAPTURE_MEMORY);
    let (realm, owners) =
        super::super::super::netstack::capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
    let factory = Replies(Arc::from([realm.clone()]));
    let ReplySocketFd::Packet(sender) = factory
        .create(realm.scope(), "203.0.113.9:53".parse().unwrap(), None)
        .unwrap()
    else {
        panic!("packet realm requires its real packet reply transport");
    };
    for worker in 0..2 {
        let client = (1..=254)
            .map(|last| SocketAddr::from(([192, 0, 2, last], 41000)))
            .find(|client| realm.worker_for_udp(client.ip()) == worker)
            .unwrap();
        sender.send_to(b"foreign", client).await.unwrap();
        let output = realm.owners()[worker].next_output().await.unwrap();
        assert_eq!(
            wire::packet_addresses(output.packet()).unwrap().1,
            client.ip()
        );
        assert!(
            realm.owners()[1 - worker]
                .poll_output(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        );
        output.release();
    }
    for owner in owners {
        owner.shutdown().await;
    }
}

#[tokio::test]
async fn exact_udp_source_refuses_another_worker_and_another_client() {
    let budget = MemoryBudget::new(super::super::super::netstack::CAPTURE_MEMORY);
    let (realm, owners) =
        super::super::super::netstack::capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
    let client = (1..=254)
        .map(|last| SocketAddr::from(([192, 0, 2, last], 41000)))
        .find(|client| realm.worker_for_udp(client.ip()) == 0)
        .unwrap();
    let factory = Replies(Arc::from([realm.clone()]));
    let source = "203.0.113.9:53".parse().unwrap();
    let wrong = realm.owners()[1].hold_source(client.ip()).unwrap();
    assert_eq!(
        factory
            .create(realm.scope(), source, Some(&wrong))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    drop(wrong);
    let work = realm.owners()[0].hold_source(client.ip()).unwrap();
    let ReplySocketFd::Packet(sender) = factory.create(realm.scope(), source, Some(&work)).unwrap()
    else {
        panic!("packet reply transport");
    };
    let other = SocketAddr::from(([198, 51, 100, 1], 41000));
    assert_eq!(
        sender.send_to(b"reply", other).await.unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    drop((work, sender));
    for owner in owners {
        owner.shutdown().await;
    }
}

#[tokio::test]
async fn auxiliary_rebind_forgets_positive_and_negative_quic_decisions() {
    use crate::control::packet_sniffer::{PacketSnifferKey, QuicSniffOutcome};
    use crate::control::quic::test_utils::rfc9001_client_initial;

    let budget = MemoryBudget::new(32 << 20);
    let (scope, owner) = crate::control::netstack::auxiliary_scope(1500, &budget).unwrap();
    let (plane, _health) = local_plane().await;
    let pool = Arc::clone(&plane.sniffer_pool);
    let (endpoints, mut supervisor, mut drivers) =
        PacketEndpoints::start_driven(plane, vec![(scope.clone(), owner)], 2, None, ScopeId::HOST)
            .await
            .unwrap();
    let driver = drivers.first_mut().unwrap();
    std::future::poll_fn(|cx| {
        driver.service(cx, Instant::now());
        supervisor.poll_ready(cx)
    })
    .await
    .unwrap();
    endpoints.resume_auxiliary(driver, 1500).unwrap();
    let work = scope.auxiliary_work().unwrap().unwrap();
    let positive = PacketSnifferKey::new(
        scope.scope(),
        "192.0.2.1:40000".parse().unwrap(),
        "192.0.2.9:443".parse().unwrap(),
        None,
    );
    let negative = PacketSnifferKey {
        src_port: 40001,
        ..positive
    };
    let sibling = PacketSnifferKey {
        scope: ScopeId::HOST,
        ..positive
    };
    let sibling_failure = PacketSnifferKey {
        scope: ScopeId::HOST,
        ..negative
    };
    let hello = rfc9001_client_initial();
    let example = QuicSniffOutcome::Domain("example.com".into());
    {
        let mut pause = std::pin::pin!(endpoints.pause_auxiliary(driver));
        assert!(futures::poll!(&mut pause).is_pending());
        // An initializer already inside sniffing may finish after the pause request.
        for key in [positive, sibling] {
            assert_eq!(pool.feed_quic_initial(key, &hello), example);
        }
        for key in [negative, sibling_failure] {
            pool.mark_dcid_failed_decrypt(key);
        }
        drop(work);
        pause.await.unwrap();
    }
    endpoints.resume_auxiliary(driver, 1280).unwrap();
    assert_eq!(
        pool.feed_quic_initial(positive, b"new data"),
        QuicSniffOutcome::NotQuic
    );
    assert_eq!(pool.feed_quic_initial(negative, &hello), example);
    assert_eq!(pool.feed_quic_initial(sibling, b"unchanged"), example);
    assert!(pool.is_dcid_failed(&sibling_failure));

    endpoints.close();
    let (_, result) = std::future::poll_fn(|cx| {
        driver.service(cx, Instant::now());
        supervisor.poll_join_plane(cx)
    })
    .await
    .unwrap();
    result.unwrap();
}
