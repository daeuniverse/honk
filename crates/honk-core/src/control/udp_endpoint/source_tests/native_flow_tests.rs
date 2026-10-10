use super::*;
use crate::control::tests::support::NativeFlowApi;

#[tokio::test]
async fn native_shared_source_idle_keeps_reply_evidence_per_flow_view() {
    let api = NativeFlowApi::new().await;
    let (server, mut events, wire_task) = start_wire_peer().await;
    let node = vless_node(server);
    let generation = Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap());
    let runtime = generation.get(&node.id).unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let raw_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let raw_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let targets = [raw_a.local_addr().unwrap(), raw_b.local_addr().unwrap()];
    let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        2,
        Arc::new(SourceReplySocketFactory::new([raw_a, raw_b])),
    ));
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let (removed_tx, mut removed_rx) = mpsc::channel(2);
    pool.set_remove_sink(removed_tx);
    let mut endpoints = Vec::new();
    let mut ids = Vec::new();
    let mut owner_ids = Vec::new();
    for target in targets {
        let flow = Arc::new(
            api.flows
                .begin(crate::observe::vocab::Network::Udp, client_addr, target)
                .unwrap(),
        );
        ids.push(flow.id().to_owned());
        let mut lease = reserve_source(&pool, &stats, client_addr, target, node.id);
        let attachment = pool
            .prepare_vless_source(
                Arc::clone(&generation),
                Arc::clone(&runtime),
                client_addr,
                VlessUdpPath::Xudp,
                None,
                target,
                None,
                Duration::from_secs(2),
                Arc::clone(&alive),
                Arc::clone(&stats),
                honk_outbound::alive::IpVersion::V4,
            )
            .await
            .unwrap()
            .commit(&pool)
            .await
            .unwrap();
        let mut endpoint = UdpEndpoint::new_source_scored(
            attachment,
            target,
            None,
            Arc::new(pool.create_reply_socket(target).unwrap()),
            stats.outbound_tracker("core-source-vless", crate::stats::OutboundKind::Node),
            node.id,
            honk_outbound::alive::IpVersion::V4,
            None,
        );
        endpoint
            .native
            .set_observer(flow.observer(7, None, "dial_target"));
        endpoint.native.set_flow(Some(flow), &pool, None);
        let endpoint = Arc::new(endpoint);
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        owner_ids.push(endpoint.source_owner_id().unwrap());
        endpoints.push(endpoint);
    }
    assert_eq!(owner_ids[0], owner_ids[1]);
    assert_ne!(ids[0], ids[1]);

    let mut replies = HashMap::new();
    endpoints[0].send_packet(b"first", false).await.unwrap();
    let first = next_data_frame(&mut events, &mut replies).await;
    endpoints[1].send_packet(b"second", false).await.unwrap();
    let second = next_data_frame(&mut events, &mut replies).await;
    endpoints[0].send_packet(b"same-flow", false).await.unwrap();
    let repeated = next_data_frame(&mut events, &mut replies).await;
    assert_eq!(
        (repeated.connection, repeated.session_id),
        (first.connection, first.session_id)
    );
    assert_eq!(
        (first.connection, first.session_id),
        (second.connection, second.session_id)
    );
    replies[&first.connection]
        .send((targets[0], b"reply".to_vec()))
        .unwrap();
    assert_eq!(
        receive_reply(&client).await,
        (b"reply".to_vec(), targets[0])
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while !endpoints[0].has_reply() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;
    tokio::time::pause();
    tokio::time::advance(REPLY_IDLE_TIMEOUT).await;
    let downloaded: Vec<_> = endpoints
        .iter()
        .map(|endpoint| endpoint.byte_counters().1.load(Ordering::Relaxed))
        .collect();
    drop(endpoints);
    for _ in 0..2 {
        let removal = removed_rx.recv().await.unwrap();
        let index = targets
            .iter()
            .position(|target| *target == removal.dst)
            .unwrap();
        let before = api.detail(&ids[index]).await;
        assert!(
            before["ended_at"].is_null(),
            "source retirement is not cleanup acknowledgement"
        );
        assert!(pool.wait_removal_io(&removal).await);
        pool.finish_removal(&removal, true);
    }
    tokio::time::resume();
    assert!(pool.is_empty());
    assert_eq!(downloaded, [5, 0]);

    for (index, state, reason) in [
        (0, "closed", "reply_idle"),
        (1, "failed", "timeout_before_reply"),
    ] {
        let detail = api.detail(&ids[index]).await;
        assert_eq!(detail["state"], state);
        let steps = detail["trace"]["steps"].as_array().unwrap();
        assert_eq!(
            steps
                .iter()
                .filter(|step| step["data"]["milestone"] == "target_request_sent")
                .count(),
            1,
            "each endpoint context records its own first target send, not the shared owner",
        );
        let terminal: Vec<_> = steps
            .iter()
            .filter(|step| step["data"]["milestone"] == "terminal")
            .collect();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0]["data"]["reason"], reason);
        assert_eq!(
            steps
                .iter()
                .filter(|step| step["data"]["milestone"] == "first_reply")
                .count(),
            usize::from(index == 0)
        );
    }
    assert!(pool.shutdown().await.joined);
    wire_task.abort();
    let _ = wire_task.await;
    api.shutdown().await;
}
