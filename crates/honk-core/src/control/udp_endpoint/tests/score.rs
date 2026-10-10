use super::*;
use honk_config::group::{Group, GroupPolicy};
use honk_config::node::Node;
use honk_outbound::group::{
    GroupManager, ScoreEvidenceQuestion, ScoreSelectionContext, ScoreVerificationState,
    SelectionNetwork,
};

#[tokio::test]
async fn accepted_udp_progress_changes_selection_before_endpoint_finishes() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let outbound_addr = outbound.local_addr().unwrap();
    let nodes = [
        Node {
            name: "control".into(),
            id: OTHER_NODE_ID,
            ..Default::default()
        },
        Node {
            name: "live".into(),
            id: TEST_NODE_ID,
            ..Default::default()
        },
    ];
    let manager = GroupManager::new(
        &[Group {
            name: "score".into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        }],
        &nodes,
    );
    let context = ScoreSelectionContext {
        network: SelectionNetwork::Udp,
        probe_domain: honk_outbound::alive::ProbeDomain::DataUdp,
        target_family: Some(honk_outbound::alive::IpVersion::V4),
        health_family: honk_outbound::alive::IpVersion::V4,
        target: Some(target.into()),
    };
    let histories: Vec<Vec<_>> = nodes
        .iter()
        .map(|node| {
            (0..8)
                .map(|_| {
                    let reporter = manager
                        .feedback_for_node(node.id, context.clone())
                        .unwrap()
                        .start();
                    reporter.setup_succeeded();
                    reporter
                })
                .collect()
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(100)).await;
    for history in histories {
        for reporter in history {
            reporter.first_response();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let control = manager
        .feedback_for_node(OTHER_NODE_ID, context.clone())
        .unwrap()
        .start();
    control.setup_succeeded();
    let reporter = manager
        .feedback_for_node(TEST_NODE_ID, context)
        .unwrap()
        .start();
    reporter.setup_succeeded();
    let endpoint = Arc::new(UdpEndpoint::new_scored(
        transport(outbound, target),
        target,
        false,
        TEST_NODE_ID,
        honk_outbound::alive::IpVersion::V4,
        Some(reporter),
    ));
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let payload = vec![0x5a; 32 * 1024];
    let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client_addr, target, &payload, permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("live flow must reserve a fresh endpoint"),
    };
    let mut driver = pool.spawn_driver(
        client_addr,
        target,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        lease.take_queue_receiver().unwrap(),
        test_reply_socket().await,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        stats.outbound_tracker("live", crate::stats::OutboundKind::Node),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    driver.start(lease.take_first().unwrap()).unwrap();
    drop(lease);
    driver.wait_first_ack().await.unwrap();
    let mut buf = vec![0; payload.len()];
    for index in 0..4 {
        if index != 0 {
            let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
            assert!(matches!(
                pool.reserve_or_enqueue(client_addr, target, &payload, permit, &stats),
                EndpointReservation::Enqueued
            ));
        }
        let (len, peer) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer, outbound_addr);
        assert_eq!(&buf[..len], payload);
    }
    server.send_to(b"r", outbound_addr).await.unwrap();
    let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..len], b"r");
    control.first_response();
    control.tx(64 * 1024);
    control.rx(1);

    for window in 0..4 {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        control.tx(1);
        if window == 0 {
            assert_eq!(
                manager.get_score_selection_for_network("score", SelectionNetwork::Udp),
                Some("control".into()),
            );
        }
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(client_addr, target, b"!", permit, &stats),
            EndpointReservation::Enqueued
        ));
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"!");
        if window < 3 {
            control.tx(64 * 1024);
            for _ in 0..4 {
                let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
                assert!(matches!(
                    pool.reserve_or_enqueue(client_addr, target, &payload, permit, &stats),
                    EndpointReservation::Enqueued
                ));
                let (len, _) =
                    tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(&buf[..len], payload);
            }
        }
    }
    assert_eq!(endpoint.upload.load(Ordering::Relaxed), 4 * 128 * 1024 + 4);
    assert_eq!(endpoint.download.load(Ordering::Relaxed), 1);
    assert_eq!(pool.driver_count(), 1);
    assert_eq!(
        manager.get_score_selection_for_network("score", SelectionNetwork::Udp),
        Some("live".into()),
        "accepted upload and delivered reply must publish before terminal settlement",
    );

    endpoint.finish_score(ScoreOutcome::Success);
    endpoint.finish_score(ScoreOutcome::Io(io::ErrorKind::ConnectionReset));
    assert_eq!(
        manager.get_score_selection_for_network("score", SelectionNetwork::Udp),
        Some("live".into()),
    );
    control.finish(ScoreOutcome::Cancelled);
    assert!(pool.shutdown().await.joined);
}

#[tokio::test]
async fn delivered_udp_reply_restores_incumbent_protection_before_endpoint_finishes() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let mut clients = Vec::new();
    let mut endpoints = Vec::new();
    let mut drivers = Vec::new();
    let nodes = [
        Node {
            name: "live".into(),
            id: TEST_NODE_ID,
            ..Default::default()
        },
        Node {
            name: "challenger".into(),
            id: OTHER_NODE_ID,
            ..Default::default()
        },
    ];
    let manager = GroupManager::new(
        &[Group {
            name: "score".into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        }],
        &nodes,
    );
    let context = ScoreSelectionContext {
        network: SelectionNetwork::Udp,
        probe_domain: honk_outbound::alive::ProbeDomain::DataUdp,
        target_family: Some(honk_outbound::alive::IpVersion::V4),
        health_family: honk_outbound::alive::IpVersion::V4,
        target: Some(target.into()),
    };
    for (index, node) in nodes.iter().enumerate() {
        let feedback = manager.feedback_for_node(node.id, context.clone()).unwrap();
        // Two failures stay below the mature switching margin. Response-free
        // histories and fixed probes isolate recovery from scheduler latency.
        for _ in 0..512 {
            let reporter = feedback.start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
        let probe = feedback.with_source(honk_outbound::group::ScoreSource::HealthProbe);
        for _ in 0..8 {
            let reporter = probe.start();
            reporter.probe_latency(Duration::from_millis(100 + index as u64));
            reporter.finish(ScoreOutcome::Success);
        }
    }
    let aggregate = ScoreSelectionContext::aggregate(
        SelectionNetwork::Udp,
        honk_outbound::alive::ProbeDomain::DataUdp,
        honk_outbound::alive::IpVersion::V4,
    );
    assert_eq!(
        manager
            .selection_plan_for_target("score", &aggregate)
            .entries[0]
            .node
            .id,
        TEST_NODE_ID,
    );
    let feedback = manager
        .feedback_for_node(TEST_NODE_ID, context.clone())
        .unwrap();
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let mut half_open = None;
    for flow in 0..4 {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let outbound_addr = outbound.local_addr().unwrap();
        let reporter = half_open.take().unwrap_or_else(|| feedback.start());
        reporter.setup_succeeded();
        let endpoint = Arc::new(UdpEndpoint::new_scored(
            transport(outbound, target),
            target,
            false,
            TEST_NODE_ID,
            honk_outbound::alive::IpVersion::V4,
            Some(reporter),
        ));
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client_addr, target, b"q", permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("each recovery flow must reserve a distinct endpoint"),
        };
        let mut driver = pool.spawn_driver(
            client_addr,
            target,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            lease.take_queue_receiver().unwrap(),
            test_reply_socket().await,
            Arc::clone(&alive),
            Arc::clone(&stats),
            stats.outbound_tracker("live", crate::stats::OutboundKind::Node),
        );
        tokio::time::timeout(Duration::from_secs(1), driver.wait_ready())
            .await
            .unwrap()
            .unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);
        tokio::time::timeout(Duration::from_secs(1), driver.wait_first_ack())
            .await
            .unwrap()
            .unwrap();
        let mut buf = [0; 8];
        let (len, peer) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer, outbound_addr);
        assert_eq!(&buf[..len], b"q");

        if flow == 0 {
            let failed = feedback.start();
            failed.setup_succeeded();
            failed.finish(ScoreOutcome::Timeout);
            assert_eq!(
                manager.get_score_selection_for_network("score", SelectionNetwork::Udp),
                Some("live".into()),
                "a target timeout must not remove aggregate incumbent protection",
            );
            assert_eq!(
                manager.selection_plan_for_target("score", &context).entries[0]
                    .node
                    .id,
                OTHER_NODE_ID,
                "the failed exact target must still escape to the healthy leaf",
            );

            // A node fault, unlike the target timeout, opens an aggregate hard episode.
            let failed = feedback.start();
            failed.setup_succeeded();
            failed.finish(ScoreOutcome::NodeFailure);
            assert_eq!(
                manager.get_score_selection_for_network("score", SelectionNetwork::Udp),
                Some("challenger".into()),
            );
        }

        server.send_to(b"r", outbound_addr).await.unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"r");
        assert_eq!(endpoint.upload.load(Ordering::Relaxed), 1);
        assert_eq!(endpoint.download.load(Ordering::Relaxed), 1);
        assert!(!endpoint.dead.load(Ordering::Acquire));
        if flow < 3 {
            assert_eq!(
                manager.get_score_selection_for_network("score", SelectionNetwork::Udp),
                Some("challenger".into()),
                "fewer than four independent replies must not restore protection",
            );
            let (_, report) = manager
                .score_verification_for_network("score", SelectionNetwork::Udp)
                .unwrap();
            assert_eq!(report.question, ScoreEvidenceQuestion::Recovery);
        }
        if flow == 0 {
            let before = manager.score_budget_counters("score", SelectionNetwork::Udp);
            let plan = manager.selection_plan_for_target("score", &context);
            assert_eq!(plan.entries[0].node.id, TEST_NODE_ID);
            half_open = Some(
                plan.entries[0]
                    .feedback
                    .as_ref()
                    .unwrap()
                    .begin()
                    .unwrap()
                    .start(),
            );
            let after = manager.score_budget_counters("score", SelectionNetwork::Udp);
            assert_eq!(after.trial_starts, before.trial_starts + 1);
            assert_eq!(after.spent, before.spent + 1);
            assert!(
                after.spent + after.reserved
                    <= after.cold_allowance + after.business_starts / after.earning_period
            );
        }
        clients.push(client);
        endpoints.push(endpoint);
        drivers.push(driver);
    }
    let before = manager.score_reason_snapshot()[0].udp;
    assert_eq!(
        manager
            .selection_plan_for_target("score", &aggregate)
            .entries[0]
            .node
            .id,
        TEST_NODE_ID,
        "four delivered replies must restore protection before terminal settlement",
    );
    let recovered = manager.score_reason_snapshot()[0].udp;
    assert_eq!(
        recovered.insufficient_evidence_held,
        before.insufficient_evidence_held + 1,
    );
    assert_eq!(recovered.fresh_failure_bypass, before.fresh_failure_bypass);
    assert_eq!(recovered.incumbent_ineligible, before.incumbent_ineligible);
    assert_eq!(recovered.ordinary_switch, before.ordinary_switch);
    let (_, report) = manager
        .score_verification_for_network("score", SelectionNetwork::Udp)
        .unwrap();
    assert_ne!(report.question, ScoreEvidenceQuestion::Recovery);
    assert_eq!(pool.driver_count(), 4);
    assert!(
        endpoints
            .iter()
            .all(|endpoint| !endpoint.dead.load(Ordering::Acquire))
    );
    assert!(pool.shutdown().await.joined);
}

#[tokio::test]
async fn four_live_udp_drivers_establish_observed_usability_before_retirement() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let node = Node::from_share_link("socks5://127.0.0.1:1080#live").unwrap();
    let manager = GroupManager::new(
        &[Group {
            name: "score".into(),
            policy: GroupPolicy::Score,
            nodes: vec![node.id],
            ..Default::default()
        }],
        std::slice::from_ref(&node),
    );
    let context = ScoreSelectionContext {
        network: SelectionNetwork::Udp,
        probe_domain: honk_outbound::alive::ProbeDomain::DataUdp,
        target_family: Some(honk_outbound::alive::IpVersion::V4),
        health_family: honk_outbound::alive::IpVersion::V4,
        target: Some(target.into()),
    };
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let mut clients = Vec::new();
    let mut endpoints = Vec::new();
    let mut drivers = Vec::new();
    for flow in 0..4 {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let outbound_addr = outbound.local_addr().unwrap();
        let reporter = manager
            .feedback_for_group_node("score", node.id, context.clone())
            .unwrap()
            .start();
        reporter.setup_succeeded();
        let endpoint = Arc::new(UdpEndpoint::new_scored(
            transport(outbound, target),
            target,
            false,
            node.id,
            honk_outbound::alive::IpVersion::V4,
            Some(reporter),
        ));
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client_addr, target, b"q", permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("each client must reserve a distinct scored endpoint"),
        };
        let mut driver = pool.spawn_driver(
            client_addr,
            target,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            lease.take_queue_receiver().unwrap(),
            test_reply_socket().await,
            Arc::clone(&alive),
            Arc::clone(&stats),
            stats.outbound_tracker("live", crate::stats::OutboundKind::Node),
        );
        tokio::time::timeout(Duration::from_secs(1), driver.wait_ready())
            .await
            .unwrap()
            .unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);
        tokio::time::timeout(Duration::from_secs(1), driver.wait_first_ack())
            .await
            .unwrap()
            .unwrap();
        let mut buf = [0; 8];
        for packet in 0..if flow == 0 { 4 } else { 1 } {
            if packet != 0 {
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
                assert!(matches!(
                    pool.reserve_or_enqueue(client_addr, target, b"q", permit, &stats),
                    EndpointReservation::Enqueued
                ));
            }
            let (len, peer) =
                tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(peer, outbound_addr);
            assert_eq!(&buf[..len], b"q");
            server.send_to(b"r", peer).await.unwrap();
            let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..len], b"r");
            if flow < 3 {
                let (_, report) = manager
                    .score_verification_for_network("score", SelectionNetwork::Udp)
                    .unwrap();
                assert_eq!(report.state, ScoreVerificationState::Provisional);
            }
        }
        clients.push(client);
        endpoints.push(endpoint);
        drivers.push(driver);
    }
    let counters = manager.score_verification_counters("score", SelectionNetwork::Udp);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let (_, report) = manager
                .score_verification_for_network("score", SelectionNetwork::Udp)
                .unwrap();
            if report.state == ScoreVerificationState::ObservedUsable {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("four delivered live replies must establish public observed usability");
    assert_eq!(
        manager.score_verification_counters("score", SelectionNetwork::Udp),
        counters
    );
    assert_eq!(pool.driver_count(), 4);
    assert!(
        endpoints
            .iter()
            .all(|endpoint| !endpoint.dead.load(Ordering::Acquire))
    );
    assert!(pool.shutdown().await.joined);
}

#[tokio::test]
async fn quic_stall_terminal_invalidates_aggregate_without_changing_alive_congestion() {
    let target = make_addr("192.0.2.1", 443);
    let nodes = [
        Node {
            name: "stalled".into(),
            id: TEST_NODE_ID,
            ..Default::default()
        },
        Node {
            name: "survivor".into(),
            id: OTHER_NODE_ID,
            ..Default::default()
        },
    ];
    let manager = GroupManager::new(
        &[Group {
            name: "score".into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        }],
        &nodes,
    );
    let context = ScoreSelectionContext {
        network: SelectionNetwork::Udp,
        probe_domain: honk_outbound::alive::ProbeDomain::DataUdp,
        target_family: Some(honk_outbound::alive::IpVersion::V4),
        health_family: honk_outbound::alive::IpVersion::V4,
        target: Some(target.into()),
    };
    for (index, node) in nodes.iter().enumerate() {
        let feedback = manager.feedback_for_node(node.id, context.clone()).unwrap();
        // A single numerical failure cannot outweigh the established probe advantage.
        for _ in 0..512 {
            let reporter = feedback.start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
        let probe = feedback.with_source(honk_outbound::group::ScoreSource::HealthProbe);
        for _ in 0..8 {
            let reporter = probe.start();
            reporter.probe_latency(Duration::from_millis(10 + 90 * index as u64));
            reporter.finish(ScoreOutcome::Success);
        }
    }
    let aggregate = ScoreSelectionContext::aggregate(
        context.network,
        context.probe_domain,
        context.health_family,
    );
    assert_eq!(
        manager
            .selection_plan_for_target("score", &aggregate)
            .entries[0]
            .node
            .id,
        TEST_NODE_ID,
    );
    let reporter = manager
        .feedback_for_node(TEST_NODE_ID, context)
        .unwrap()
        .start();
    reporter.setup_succeeded();
    let transport = Arc::new(ScriptedPacketTransport::new(
        target,
        [DriverSendAction::Congestion],
    ));
    transport.quic_path_stalled.store(true, Ordering::Release);
    let endpoint = Arc::new(UdpEndpoint::new_scored(
        transport,
        target,
        false,
        TEST_NODE_ID,
        honk_outbound::alive::IpVersion::V4,
        Some(reporter),
    ));
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let client = make_addr("127.0.0.1", 12345);
    let (first, queue_rx) = reserve_driver_packets(&pool, &stats, client, target, b"q", &[]);
    let (first_ack, ack) = oneshot::channel();
    let terminal = super::super::run_endpoint_driver(
        UdpDriverContext {
            endpoint: Arc::clone(&endpoint),
            queue_rx,
            reply_socket: Arc::new(ReplySocket::untracked(test_reply_socket().await)),
            reply_socket_factory: Arc::new(SystemUdpReplySocketFactory),
            reply_socket_slots: Arc::new(Semaphore::new(MAX_REPLY_SOCKETS_PER_ENDPOINT)),
            client_addr: client,
            client_dst: target,
            alive_set: Arc::clone(&alive),
            outbound_tracker: stats.outbound_tracker("stalled", crate::stats::OutboundKind::Node),
            stats,
            health_family: honk_outbound::alive::IpVersion::V4,
        },
        UdpDriverStart {
            first,
            followers: Vec::new(),
        },
        first_ack,
    )
    .await;
    endpoint.finish_score(terminal.outcome);
    assert_eq!(
        manager
            .peek_selection_plan_for_domain(
                "score",
                aggregate.probe_domain,
                aggregate.health_family,
            )
            .nodes[0]
            .id,
        OTHER_NODE_ID,
        "a proven shared carrier stall must invalidate the aggregate incumbent",
    );
    assert_eq!(terminal.outcome, ScoreOutcome::NodeFailure);
    assert_eq!(
        terminal.result.unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        ack.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(
        alive
            .get_probe_history(
                TEST_NODE_ID,
                aggregate.probe_domain,
                aggregate.health_family,
            )
            .is_empty()
    );
}
