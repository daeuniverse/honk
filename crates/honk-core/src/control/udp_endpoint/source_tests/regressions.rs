use super::*;
const OTHER_SCORE_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x5c07e);

fn source_runtime(
    server: SocketAddr,
    capacity: usize,
) -> (
    Node,
    Arc<OutboundRuntimeRegistry>,
    Arc<honk_outbound::runtime::NodeRuntime>,
) {
    let node = vless_node(server);
    let generation = Arc::new(
        OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            std::slice::from_ref(&node),
            capacity,
            capacity,
            capacity,
            None,
        )
        .unwrap()
        .0,
    );
    let runtime = generation.get(&node.id).unwrap();
    (node, generation, runtime)
}

async fn attach_source(
    pool: &Arc<UdpEndpointPool>,
    generation: &Arc<OutboundRuntimeRegistry>,
    runtime: &Arc<honk_outbound::runtime::NodeRuntime>,
    client: SocketAddr,
    target: SocketAddr,
    alive: &Arc<honk_outbound::alive::AliveDialerSet>,
    stats: &Arc<StatsManager>,
) -> SourceAttachment {
    pool.prepare_vless_source(
        Arc::clone(generation),
        Arc::clone(runtime),
        client,
        VlessUdpPath::Xudp,
        None,
        target,
        None,
        Duration::from_secs(2),
        Arc::clone(alive),
        Arc::clone(stats),
        honk_outbound::alive::IpVersion::V4,
    )
    .await
    .unwrap()
    .commit(pool)
    .await
    .unwrap()
}

fn source_endpoint(
    pool: &Arc<UdpEndpointPool>,
    attachment: SourceAttachment,
    target: SocketAddr,
    stats: &Arc<StatsManager>,
    node_id: uuid::Uuid,
    reporter: Option<honk_outbound::group::ScoreReporter>,
) -> Arc<UdpEndpoint> {
    Arc::new(UdpEndpoint::new_source_scored(
        attachment,
        target,
        None,
        Arc::new(pool.create_reply_socket(target).unwrap()),
        stats.outbound_tracker("core-source-vless"),
        node_id,
        honk_outbound::alive::IpVersion::V4,
        reporter,
    ))
}

fn score_context(target: SocketAddr) -> honk_outbound::group::ScoreSelectionContext {
    honk_outbound::group::ScoreSelectionContext {
        network: honk_outbound::group::SelectionNetwork::Udp,
        probe_domain: honk_outbound::alive::ProbeDomain::DataUdp,
        target_family: Some(honk_outbound::alive::IpVersion::V4),
        health_family: honk_outbound::alive::IpVersion::V4,
        target: Some(target.into()),
    }
}

#[tokio::test(start_paused = true, flavor = "current_thread")]
async fn queued_source_view_timeout_is_local_congestion() {
    let (server, mut events, wire_task) = start_wire_peer().await;
    let (node, generation, runtime) = source_runtime(server, 3);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let raw_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let raw_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let raw_c = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target_a = raw_a.local_addr().unwrap();
    let target_b = raw_b.local_addr().unwrap();
    let target_c = raw_c.local_addr().unwrap();
    let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        3,
        Arc::new(SourceReplySocketFactory::new([raw_a, raw_b, raw_c])),
    ));
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());

    let lease_a = reserve_source(&pool, &stats, client_addr, target_a, node.id);
    let lease_b = reserve_source(&pool, &stats, client_addr, target_b, node.id);
    let mut lease_c = reserve_source(&pool, &stats, client_addr, target_c, node.id);
    let attachment_a = attach_source(
        &pool,
        &generation,
        &runtime,
        client_addr,
        target_a,
        &alive,
        &stats,
    )
    .await;
    let attachment_b = attach_source(
        &pool,
        &generation,
        &runtime,
        client_addr,
        target_b,
        &alive,
        &stats,
    )
    .await;
    let attachment_c = attach_source(
        &pool,
        &generation,
        &runtime,
        client_addr,
        target_c,
        &alive,
        &stats,
    )
    .await;
    let owner = attachment_a.owner();
    assert!(Arc::ptr_eq(&owner, &attachment_b.owner()));
    assert!(Arc::ptr_eq(&owner, &attachment_c.owner()));
    let scope = SourceScope::new(&runtime, client_addr, VlessUdpPath::Xudp, None);
    let endpoint_a = install_source(&pool, lease_a, attachment_a, target_a, &stats, node.id);
    let endpoint_b = install_source(&pool, lease_b, attachment_b, target_b, &stats, node.id);
    let endpoint_c = source_endpoint(&pool, attachment_c, target_c, &stats, node.id, None);

    for _ in 0..49 {
        alive.report_unavailable_traffic(
            node.id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            honk_outbound::alive::IpVersion::V4,
        );
    }
    let a_endpoint = Arc::clone(&endpoint_a);
    let mut send_a = Box::pin(async move { a_endpoint.send_packet(b"from-a", true).await });
    assert!(
        poll_fn(|cx| std::task::Poll::Ready(Future::poll(send_a.as_mut(), cx).is_pending())).await,
        "first source send must be waiting for carrier I/O"
    );
    let b_endpoint = Arc::clone(&endpoint_b);
    let mut send_b = Box::pin(async move { b_endpoint.send_packet(b"from-b", true).await });
    assert!(
        poll_fn(|cx| std::task::Poll::Ready(Future::poll(send_b.as_mut(), cx).is_pending())).await,
        "second source view must queue behind the first"
    );

    let queue_rx = lease_c.take_queue_receiver().unwrap();
    let mut driver = pool.spawn_driver(
        client_addr,
        target_c,
        lease_c.generation(),
        lease_c.decision_token(),
        Arc::clone(&endpoint_c),
        queue_rx,
        Arc::clone(endpoint_c.source_reply_socket()),
        Arc::clone(&alive),
        Arc::clone(&stats),
        node.name.clone(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease_c.commit_ready(Arc::clone(&endpoint_c)));
    driver.start(lease_c.take_first().unwrap()).unwrap();
    drop(lease_c);
    tokio::task::yield_now().await;
    tokio::time::advance(TRANSPORT_SEND_TIMEOUT).await;

    let queued_error = driver.wait_first_ack().await.unwrap_err();
    assert_eq!(queued_error.kind(), io::ErrorKind::WouldBlock);
    assert!(alive.is_alive_for(
        node.id,
        honk_outbound::alive::ProbeDomain::DataUdp,
        honk_outbound::alive::IpVersion::V4,
    ));
    assert!(pool.sources.get(&scope).is_some());

    send_a.await.unwrap();
    send_b.await.unwrap();
    let mut replies = HashMap::new();
    let first = next_wire_frame(&mut events, &mut replies).await;
    let second = next_wire_frame(&mut events, &mut replies).await;
    assert_eq!(first.target, Some(target_a));
    assert_eq!(second.target, Some(target_b));
    assert_eq!(first.status, STATUS_NEW);
    assert_eq!(second.status, STATUS_KEEP);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            next_wire_frame(&mut events, &mut replies),
        )
        .await
        .is_err(),
        "pre-gate timeout must emit neither a source NEW nor END"
    );

    for target in [target_a, target_b, target_c] {
        pool.remove(client_addr, target);
    }

    drop(endpoint_a);
    drop(endpoint_b);
    drop(endpoint_c);
    wait_source_removed(&pool, &scope).await;
    assert!(pool.shutdown().await);
    generation.shutdown().await;
    wire_task.abort();
    let _ = wire_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn admitted_source_transport_timeout_still_demotes_health() {
    let (server, _events, wire_task) = start_wire_peer().await;
    let (node, generation, runtime) = source_runtime(server, 1);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = raw.local_addr().unwrap();
    let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        1,
        Arc::new(SourceReplySocketFactory::new([raw])),
    ));
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let mut lease = reserve_source(&pool, &stats, client_addr, target, node.id);
    let attachment = attach_source(
        &pool,
        &generation,
        &runtime,
        client_addr,
        target,
        &alive,
        &stats,
    )
    .await;
    let owner = attachment.owner();
    owner.set_send_timeout_for_test(Duration::from_millis(20));
    let endpoint = source_endpoint(&pool, attachment, target, &stats, node.id, None);
    let queue_rx = lease.take_queue_receiver().unwrap();
    let first = lease.take_first().unwrap();
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    drop(lease);
    for _ in 0..49 {
        alive.report_unavailable_traffic(
            node.id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            honk_outbound::alive::IpVersion::V4,
        );
    }

    // Advance the deadline without running the current-thread carrier writer.
    let timer_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()
        .unwrap();
    let (first_ack_tx, first_ack_rx) = oneshot::channel();
    let mut driver = Box::pin(super::super::run_endpoint_driver(
        UdpDriverContext {
            endpoint: Arc::clone(&endpoint),
            queue_rx,
            reply_socket: Arc::clone(endpoint.source_reply_socket()),
            reply_socket_factory: Arc::new(SystemUdpReplySocketFactory),
            reply_socket_slots: Arc::new(Semaphore::new(MAX_REPLY_SOCKETS_PER_ENDPOINT)),
            client_addr,
            client_dst: target,
            alive_set: Arc::clone(&alive),
            stats: Arc::clone(&stats),
            outbound_tracker: stats.outbound_tracker(&node.name),
            health_family: honk_outbound::alive::IpVersion::V4,
        },
        UdpDriverStart {
            first,
            followers: Vec::new(),
        },
        first_ack_tx,
    ));
    {
        let _timer_context = timer_runtime.enter();
        assert!(
            poll_fn(|cx| std::task::Poll::Ready(Future::poll(driver.as_mut(), cx).is_pending()))
                .await,
            "first poll must enter the real source transport I/O"
        );
    }
    let (elapsed_tx, elapsed_rx) = std::sync::mpsc::sync_channel(1);
    timer_runtime.spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        elapsed_tx.send(()).unwrap();
    });
    elapsed_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let result = poll_fn(|cx| std::task::Poll::Ready(Future::poll(driver.as_mut(), cx))).await;
    timer_runtime.shutdown_background();
    let std::task::Poll::Ready(result) = result else {
        panic!("an admitted transport timeout must terminate the driver");
    };
    assert_eq!(result.result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        first_ack_rx.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(!alive.is_alive_for(
        node.id,
        honk_outbound::alive::ProbeDomain::DataUdp,
        honk_outbound::alive::IpVersion::V4,
    ));

    drop(driver);
    drop(endpoint);
    assert!(pool.shutdown().await);
    generation.shutdown().await;
    wire_task.abort();
    let _ = wire_task.await;
}

#[tokio::test]
async fn retired_source_preparation_is_typed_and_score_neutral() {
    let (server, mut events, wire_task) = start_wire_peer().await;
    let (node, generation, runtime) = source_runtime(server, 2);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let raw_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let raw_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target_a = raw_a.local_addr().unwrap();
    let target_b = raw_b.local_addr().unwrap();
    let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        2,
        Arc::new(SourceReplySocketFactory::new([raw_a, raw_b])),
    ));
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let lease_a = reserve_source(&pool, &stats, client_addr, target_a, node.id);
    let attachment_a = attach_source(
        &pool,
        &generation,
        &runtime,
        client_addr,
        target_a,
        &alive,
        &stats,
    )
    .await;
    let endpoint_a = install_source(&pool, lease_a, attachment_a, target_a, &stats, node.id);
    let stale = pool
        .prepare_vless_source(
            Arc::clone(&generation),
            Arc::clone(&runtime),
            client_addr,
            VlessUdpPath::Xudp,
            None,
            target_b,
            None,
            Duration::from_secs(2),
            Arc::clone(&alive),
            Arc::clone(&stats),
            honk_outbound::alive::IpVersion::V4,
        )
        .await
        .unwrap();
    let scope = SourceScope::new(&runtime, client_addr, VlessUdpPath::Xudp, None);

    assert_ne!(node.id, OTHER_SCORE_NODE_ID);
    let other = Node {
        name: "other-score-node".into(),
        id: OTHER_SCORE_NODE_ID,
        ..Default::default()
    };
    let group = honk_config::group::Group {
        name: "score".into(),
        policy: honk_config::group::GroupPolicy::Score,
        nodes: vec![node.id, other.id],
        ..Default::default()
    };
    let manager = honk_outbound::group::GroupManager::new(&[group], &[node.clone(), other]);
    let context = score_context(target_b);
    let reporter = manager.feedback_for_node(node.id, context).unwrap().start();

    for _ in 0..49 {
        alive.report_unavailable_traffic(
            node.id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            honk_outbound::alive::IpVersion::V4,
        );
    }
    pool.remove(client_addr, target_a);
    drop(endpoint_a);
    wait_source_removed(&pool, &scope).await;
    let Err(error) = stale.commit(&pool).await else {
        panic!("retired source attachment must reject commit");
    };
    assert_eq!(
        honk_outbound::proxy::packet_rejection(&error),
        Some(honk_outbound::proxy::PacketRejection::Cancelled),
    );
    reporter.finish(honk_outbound::group::ScoreOutcome::from_error(&error));
    assert_eq!(
        manager.score_cache_snapshot(),
        honk_outbound::group::ScoreCacheSnapshot::default(),
    );
    assert!(alive.is_alive_for(
        node.id,
        honk_outbound::alive::ProbeDomain::DataUdp,
        honk_outbound::alive::IpVersion::V4,
    ));
    let mut replies = HashMap::new();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            next_wire_frame(&mut events, &mut replies),
        )
        .await
        .is_err(),
        "cancelled preparation must not resurrect a source or emit NEW/END"
    );

    assert!(pool.shutdown().await);
    generation.shutdown().await;
    wire_task.abort();
    let _ = wire_task.await;
}

fn train_score_context(
    manager: &honk_outbound::group::GroupManager,
    preferred: uuid::Uuid,
    other: uuid::Uuid,
    context: &honk_outbound::group::ScoreSelectionContext,
) {
    for _ in 0..8 {
        let preferred_reporter = manager
            .feedback_for_node(preferred, context.clone())
            .unwrap()
            .start();
        preferred_reporter.setup_succeeded();
        preferred_reporter.finish_setup_only();

        let other_reporter = manager
            .feedback_for_node(other, context.clone())
            .unwrap()
            .start();
        std::thread::sleep(Duration::from_millis(1));
        other_reporter.setup_succeeded();
        other_reporter.finish_setup_only();
    }
    assert_eq!(
        manager.selection_plan_for_target("score", context).entries[0]
            .node
            .id,
        preferred,
    );
}

#[tokio::test]
async fn shared_source_failure_finishes_every_flow_before_death_cleanup() {
    let (server, mut events, wire_task) = start_wire_peer().await;
    let (node, generation, runtime) = source_runtime(server, 2);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let raw_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let raw_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target_a = raw_a.local_addr().unwrap();
    let target_b = raw_b.local_addr().unwrap();
    let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        2,
        Arc::new(SourceReplySocketFactory::new([raw_a, raw_b])),
    ));
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());

    assert_ne!(node.id, OTHER_SCORE_NODE_ID);
    let other = Node {
        name: "other-score-node".into(),
        id: OTHER_SCORE_NODE_ID,
        ..Default::default()
    };
    let other_id = other.id;
    let group = honk_config::group::Group {
        name: "score".into(),
        policy: honk_config::group::GroupPolicy::Score,
        nodes: vec![node.id, other_id],
        ..Default::default()
    };
    let manager_a = honk_outbound::group::GroupManager::new(
        std::slice::from_ref(&group),
        &[node.clone(), other.clone()],
    );
    let manager_b = honk_outbound::group::GroupManager::new(&[group], &[node.clone(), other]);
    let context_a = score_context(target_a);
    let context_b = score_context(target_b);
    train_score_context(&manager_a, node.id, other_id, &context_a);
    train_score_context(&manager_b, node.id, other_id, &context_b);
    let reporter_a = manager_a
        .feedback_for_node(node.id, context_a.clone())
        .unwrap()
        .start();
    reporter_a.setup_succeeded();
    let reporter_b = manager_b
        .feedback_for_node(node.id, context_b.clone())
        .unwrap()
        .start();
    reporter_b.setup_succeeded();

    let mut lease_a = reserve_source(&pool, &stats, client_addr, target_a, node.id);
    let mut lease_b = reserve_source(&pool, &stats, client_addr, target_b, node.id);
    let attachment_a = attach_source(
        &pool,
        &generation,
        &runtime,
        client_addr,
        target_a,
        &alive,
        &stats,
    )
    .await;
    let attachment_b = attach_source(
        &pool,
        &generation,
        &runtime,
        client_addr,
        target_b,
        &alive,
        &stats,
    )
    .await;
    let owner = attachment_a.owner();
    let endpoint_a = source_endpoint(
        &pool,
        attachment_a,
        target_a,
        &stats,
        node.id,
        Some(reporter_a),
    );
    let endpoint_b = source_endpoint(
        &pool,
        attachment_b,
        target_b,
        &stats,
        node.id,
        Some(reporter_b),
    );

    let queue_a = lease_a.take_queue_receiver().unwrap();
    let queue_b = lease_b.take_queue_receiver().unwrap();
    let mut driver_a = pool.spawn_driver(
        client_addr,
        target_a,
        lease_a.generation(),
        lease_a.decision_token(),
        Arc::clone(&endpoint_a),
        queue_a,
        Arc::clone(endpoint_a.source_reply_socket()),
        Arc::clone(&alive),
        Arc::clone(&stats),
        node.name.clone(),
    );
    let mut driver_b = pool.spawn_driver(
        client_addr,
        target_b,
        lease_b.generation(),
        lease_b.decision_token(),
        Arc::clone(&endpoint_b),
        queue_b,
        Arc::clone(endpoint_b.source_reply_socket()),
        Arc::clone(&alive),
        Arc::clone(&stats),
        node.name.clone(),
    );
    driver_a.wait_ready().await.unwrap();
    driver_b.wait_ready().await.unwrap();
    assert!(lease_a.commit_ready(Arc::clone(&endpoint_a)));
    assert!(lease_b.commit_ready(Arc::clone(&endpoint_b)));
    driver_a.start(lease_a.take_first().unwrap()).unwrap();
    driver_b.start(lease_b.take_first().unwrap()).unwrap();
    drop(lease_a);
    drop(lease_b);
    driver_a.wait_first_ack().await.unwrap();
    driver_b.wait_first_ack().await.unwrap();

    let mut replies = HashMap::new();
    let first = next_data_frame(&mut events, &mut replies).await;
    let second = next_data_frame(&mut events, &mut replies).await;
    assert!(
        (first.target == Some(target_a) && second.target == Some(target_b))
            || (first.target == Some(target_b) && second.target == Some(target_a))
    );
    assert_eq!(first.connection, second.connection);
    replies[&first.connection]
        .send((target_a, b"only-a-replied".to_vec()))
        .unwrap();
    assert_eq!(
        receive_reply(&client).await,
        (b"only-a-replied".to_vec(), target_a),
    );
    assert!(endpoint_a.first_reply_recorded.load(Ordering::Acquire));
    assert!(!endpoint_b.first_reply_recorded.load(Ordering::Acquire));
    assert_eq!(
        endpoint_a.byte_counters().1.load(Ordering::Relaxed),
        b"only-a-replied".len() as u64,
    );
    assert_eq!(endpoint_b.byte_counters().1.load(Ordering::Relaxed), 0);

    let deaths = Arc::new(AtomicUsize::new(0));
    let callback_pool = Arc::clone(&pool);
    let callback_deaths = Arc::clone(&deaths);
    alive.set_death_callback(Some(Box::new(move |node_id, _| {
        callback_deaths.fetch_add(1, Ordering::Relaxed);
        callback_pool.remove_by_node(node_id);
    })));
    for _ in 0..49 {
        alive.report_unavailable_traffic(
            node.id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            honk_outbound::alive::IpVersion::V4,
        );
    }
    owner.fail(honk_outbound::group::ScoreOutcome::Io(
        io::ErrorKind::ConnectionReset,
    ));
    assert_eq!(deaths.load(Ordering::Relaxed), 1);
    assert_eq!(
        manager_a
            .selection_plan_for_target("score", &context_a)
            .entries[0]
            .node
            .id,
        other_id,
        "a genuine source failure stays I/O-negative even after A replied",
    );
    assert_eq!(
        manager_b
            .selection_plan_for_target("score", &context_b)
            .entries[0]
            .node
            .id,
        other_id,
        "B must be scored before reentrant death cleanup can cancel its driver",
    );

    let scope = SourceScope::new(&runtime, client_addr, VlessUdpPath::Xudp, None);
    drop(endpoint_a);
    drop(endpoint_b);
    drop(owner);
    wait_source_removed(&pool, &scope).await;
    assert!(pool.shutdown().await);
    generation.shutdown().await;
    wire_task.abort();
    let _ = wire_task.await;
}
