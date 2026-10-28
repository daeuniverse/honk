use super::*;

#[tokio::test]
async fn quic_source_reuses_one_association_across_targets() {
    for mode in MODES {
        for ipv6 in [false, true] {
            let mut f = Fixture::new(mode, ipv6).await;
            let (a, b, c) = (f.target(0), f.target(1), f.target(2));
            let lease_a = f.reserve(honk_datapath::ScopeId::HOST, f.client(), a, b"to-a");
            let lease_b = f.reserve(honk_datapath::ScopeId::HOST, f.client(), b, b"to-b");
            let (pa, pb) = tokio::join!(
                f.prepare(ScopeId::HOST, f.client(), a, None, false),
                f.prepare(ScopeId::HOST, f.client(), b, None, false)
            );
            let (aa, ab) = tokio::join!(pa.commit(&f.pool), pb.commit(&f.pool));
            let (ea, mut da) = f.install(lease_a, aa.unwrap(), f.client(), a, a).await;
            let (eb, mut db) = f.install(lease_b, ab.unwrap(), f.client(), b, b).await;
            da.wait_first_ack().await.unwrap();
            db.wait_first_ack().await.unwrap();
            let first = f.packet().await;
            let second = f.packet().await;
            assert_eq!(
                (first.connection, first.session, first.mapping),
                (second.connection, second.session, second.mapping)
            );
            assert_ne!(first.target, second.target);
            assert_eq!(
                received(&f.targets[0]).await,
                (b"to-a".to_vec(), first.mapping)
            );
            assert_eq!(
                received(&f.targets[1]).await,
                (b"to-b".to_vec(), first.mapping)
            );
            // C is the first inbound packet, before either contacted target responds.
            f.targets[2]
                .send_to(b"never-contacted-c", first.mapping)
                .await
                .unwrap();
            assert_eq!(
                received(&f.client).await,
                (b"never-contacted-c".to_vec(), c)
            );
            assert!(!ea.has_reply() && !eb.has_reply());
            assert_eq!(ea.download.load(Ordering::Relaxed), 0);
            assert_eq!(eb.download.load(Ordering::Relaxed), 0);
            assert_eq!(
                f.score
                    .score_verification_for_network("score", SelectionNetwork::Udp)
                    .unwrap()
                    .1
                    .state,
                ScoreVerificationState::Provisional
            );
            assert!(
                !f.pool.endpoints.contains_key(&EndpointKey::new(
                    honk_datapath::ScopeId::HOST,
                    f.client(),
                    c
                )),
                "foreign replies cannot create flow authority"
            );
            for (index, payload) in [(0, b"reply-a".as_slice()), (1, b"reply-b".as_slice())] {
                f.targets[index]
                    .send_to(payload, first.mapping)
                    .await
                    .unwrap();
                assert_eq!(
                    received(&f.client).await,
                    (payload.to_vec(), f.target(index))
                );
            }
            assert!(ea.has_reply() && eb.has_reply());
            assert_eq!(ea.download.load(Ordering::Relaxed), 7);
            assert_eq!(eb.download.load(Ordering::Relaxed), 7);
            drop((ea, eb));
            f.shutdown().await;
        }
    }
}

#[tokio::test]
async fn quic_source_partitions_clients_runtimes_and_rewrites() {
    for mode in MODES {
        let mut f = Fixture::new(mode, false).await;
        let first_endpoint = f.flow(0, b"base").await;
        let first = f.packet().await;
        let second_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = second_client.local_addr().unwrap();
        let target = f.target(0);
        let lease = f.reserve(
            honk_datapath::ScopeId::HOST,
            client,
            target,
            b"other-client",
        );
        let attachment = f
            .prepare(honk_datapath::ScopeId::HOST, client, target, None, false)
            .await
            .commit(&f.pool)
            .await
            .unwrap();
        let (other, mut driver) = f.install(lease, attachment, client, target, target).await;
        driver.wait_first_ack().await.unwrap();
        let second = f.packet().await;
        assert_ne!(
            (first.connection, first.session),
            (second.connection, second.session)
        );
        assert_ne!(first.mapping, second.mapping);
        f.targets[2]
            .send_to(b"only-client-two", second.mapping)
            .await
            .unwrap();
        assert_eq!(
            received(&second_client).await,
            (b"only-client-two".to_vec(), f.target(2))
        );
        no_reply(&f.client).await;

        let replacement =
            Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&f.peer.node)).unwrap());
        let runtime = replacement.get(&f.peer.node.id).unwrap();
        let target_b = f.target(1);
        let lease = f.reserve(
            honk_datapath::ScopeId::HOST,
            f.client(),
            target_b,
            b"other-runtime",
        );
        let attachment = f
            .pool
            .prepare_source(
                honk_datapath::ScopeId::HOST,
                &honk_outbound::proxy::ProxyRegistry::new(),
                Arc::clone(&replacement),
                runtime,
                f.client(),
                f.path,
                None,
                target_b,
                None,
                TEST_TIMEOUT,
                Arc::clone(&f.alive),
                Arc::clone(&f.stats),
                f.family,
                false,
            )
            .await
            .unwrap()
            .commit(&f.pool)
            .await
            .unwrap();
        let (new_runtime, mut driver) = f
            .install(lease, attachment, f.client(), target_b, target_b)
            .await;
        driver.wait_first_ack().await.unwrap();
        let third = f.packet().await;
        assert_ne!(
            (first.connection, first.session),
            (third.connection, third.session)
        );
        assert_ne!(first.mapping, third.mapping);

        let mut rewritten = Vec::new();
        for index in [3, 4] {
            let original = f.target(index);
            let lease = f.reserve(
                honk_datapath::ScopeId::HOST,
                f.client(),
                original,
                b"rewritten",
            );
            let attachment = f
                .prepare(
                    honk_datapath::ScopeId::HOST,
                    f.client(),
                    target,
                    Some(original),
                    false,
                )
                .await
                .commit(&f.pool)
                .await
                .unwrap();
            let (endpoint, mut driver) = f
                .install(lease, attachment, f.client(), target, original)
                .await;
            driver.wait_first_ack().await.unwrap();
            let packet = f.packet().await;
            assert_ne!(
                (first.connection, first.session),
                (packet.connection, packet.session)
            );
            if let Some(previous) = rewritten.last() {
                let previous: &QuicUdpPacket = previous;
                assert_ne!(
                    (previous.connection, previous.session),
                    (packet.connection, packet.session)
                );
            }
            f.targets[2]
                .send_to(b"projected", packet.mapping)
                .await
                .unwrap();
            assert_eq!(received(&f.client).await, (b"projected".to_vec(), original));
            f.pool
                .remove(honk_datapath::ScopeId::HOST, f.client(), original);
            f.targets[2]
                .send_to(b"no-foreign-rewrite", packet.mapping)
                .await
                .unwrap();
            no_reply(&f.client).await;
            rewritten.push(packet);
            drop(endpoint);
        }
        drop((first_endpoint, other, new_runtime));
        assert!(f.pool.shutdown().await.joined);
        replacement.shutdown().await;
        f.shutdown().await;
    }
}

#[tokio::test]
async fn quic_source_foreign_reply_requires_vacant_live_scope() {
    for mode in MODES {
        let mut f = Fixture::new(mode, false).await;
        let a = f.flow(0, b"a").await;
        let packet = f.packet().await;
        let b = f.flow(1, b"b").await;
        f.packet().await;
        let (removed_tx, mut removed_rx) = mpsc::channel(16);
        f.pool.set_remove_sink(removed_tx);
        let initializing = f.reserve(
            honk_datapath::ScopeId::HOST,
            f.client(),
            f.target(2),
            b"initializing",
        );
        f.targets[2]
            .send_to(b"blocked-initializing", packet.mapping)
            .await
            .unwrap();
        no_reply(&f.client).await;
        drop(initializing);
        let replacement =
            Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&f.peer.node)).unwrap());
        let runtime = replacement.get(&f.peer.node.id).unwrap();
        let target = f.target(3);
        let lease = f.reserve(
            honk_datapath::ScopeId::HOST,
            f.client(),
            target,
            b"different-owner",
        );
        let attachment = f
            .pool
            .prepare_source(
                honk_datapath::ScopeId::HOST,
                &honk_outbound::proxy::ProxyRegistry::new(),
                Arc::clone(&replacement),
                runtime,
                f.client(),
                f.path,
                None,
                target,
                None,
                TEST_TIMEOUT,
                Arc::clone(&f.alive),
                Arc::clone(&f.stats),
                f.family,
                false,
            )
            .await
            .unwrap()
            .commit(&f.pool)
            .await
            .unwrap();
        let (other, mut driver) = f
            .install(lease, attachment, f.client(), target, target)
            .await;
        driver.wait_first_ack().await.unwrap();
        let other_packet = f.packet().await;
        f.targets[3]
            .send_to(b"wrong-owner", packet.mapping)
            .await
            .unwrap();
        no_reply(&f.client).await;
        f.targets[3]
            .send_to(b"correct-owner", other_packet.mapping)
            .await
            .unwrap();
        assert_eq!(
            received(&f.client).await,
            (b"correct-owner".to_vec(), target)
        );
        f.peer
            .reply(&packet, "[::1]:32123".parse().unwrap(), b"wrong-family")
            .await
            .unwrap();
        no_reply(&f.client).await;
        f.pool
            .remove(honk_datapath::ScopeId::HOST, f.client(), f.target(0));
        f.targets[0]
            .send_to(b"retiring", packet.mapping)
            .await
            .unwrap();
        no_reply(&f.client).await;
        drop(a);
        loop {
            let removed = tokio::time::timeout(TEST_TIMEOUT, removed_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(f.pool.wait_removal_io(&removed).await);
            assert!(f.pool.complete_removal(
                removed.scope,
                removed.client,
                removed.dst,
                removed.owner,
                removed.generation
            ));
            if removed.dst == f.target(0) {
                break;
            }
        }
        f.targets[0]
            .send_to(b"retired", packet.mapping)
            .await
            .unwrap();
        no_reply(&f.client).await;
        f.targets[1]
            .send_to(b"sibling-lives", packet.mapping)
            .await
            .unwrap();
        assert_eq!(
            received(&f.client).await,
            (b"sibling-lives".to_vec(), f.target(1))
        );
        assert!(b.has_reply());
        drop((b, other));
        let pool = Arc::clone(&f.pool);
        let removals = tokio::spawn(async move {
            while let Some(removed) = removed_rx.recv().await {
                assert!(pool.wait_removal_io(&removed).await);
                assert!(pool.complete_removal(
                    removed.scope,
                    removed.client,
                    removed.dst,
                    removed.owner,
                    removed.generation,
                ));
            }
        });
        assert!(f.pool.shutdown().await.joined);
        removals.await.unwrap();
        replacement.shutdown().await;
        f.generation.shutdown().await;
        f.peer.close().await.unwrap();
    }
}

#[tokio::test]
async fn quic_source_preparation_publishes_only_winner() {
    for mode in MODES {
        let mut f = Fixture::new(mode, false).await;
        let a = f.target(0);
        let b = f.target(1);
        let outer = Arc::new(honk_outbound::runtime::TaskOwner::production());
        let (winner, loser) = {
            let operation = std::pin::pin!(async {
                tokio::join!(
                    f.prepare(ScopeId::HOST, f.client(), a, None, true),
                    f.prepare(ScopeId::HOST, f.client(), b, None, true)
                )
            });
            outer.task_scope().scope(operation).await
        };
        assert!(f.pool.sources.is_empty(), "uncommitted source published");
        assert!(
            tokio::time::timeout(SHORT_WAIT, f.peer.packets.recv())
                .await
                .is_err(),
            "preparation sent application bytes"
        );
        drop(loser);
        let loser_connection = tokio::time::timeout(TEST_TIMEOUT, f.peer.closed.recv())
            .await
            .expect("losing preparation did not close its detached carrier")
            .unwrap();
        let attachment = winner.commit(&f.pool).await.unwrap();
        let lease = f.reserve(honk_datapath::ScopeId::HOST, f.client(), a, b"winner");
        let (endpoint, mut driver) = f.install(lease, attachment, f.client(), a, a).await;
        driver.wait_first_ack().await.unwrap();
        let first = f.packet().await;
        assert_ne!(
            first.connection, loser_connection,
            "winner reused losing carrier"
        );
        assert_eq!(first.payload, b"winner");
        let sibling = f.flow(1, b"reused-winner").await;
        let second = f.packet().await;
        assert_eq!(
            (first.connection, first.session, first.mapping),
            (second.connection, second.session, second.mapping)
        );
        assert!(
            tokio::time::timeout(SHORT_WAIT, f.peer.packets.recv())
                .await
                .is_err(),
            "loser leaked or replayed application bytes"
        );
        f.targets[2]
            .send_to(b"winner-c", first.mapping)
            .await
            .unwrap();
        assert_eq!(
            received(&f.client).await,
            (b"winner-c".to_vec(), f.target(2))
        );
        drop((endpoint, sibling));
        outer.close().await;
        first
            .carrier
            .close(0u32.into(), b"force authoritative reconnect");
        tokio::time::timeout(TEST_TIMEOUT, async {
            while !f.pool.sources.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("closed carrier retained source ownership");
        let reconnected = f.flow(3, b"authoritative-reconnect").await;
        let replacement = f.packet().await;
        assert_ne!(replacement.connection, first.connection);
        assert_eq!(replacement.payload, b"authoritative-reconnect");
        assert_eq!(
            received(&f.targets[3]).await,
            (replacement.payload, replacement.mapping)
        );
        drop(reconnected);
        f.shutdown().await;
    }
}
