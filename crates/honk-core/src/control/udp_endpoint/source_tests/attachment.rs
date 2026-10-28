use super::*;

#[tokio::test]
async fn pending_attachment_survives_last_binding_retirement() {
    let (server, mut events, wire_task) = start_wire_peer().await;
    let node = vless_node(server);
    let generation = Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap());
    let runtime = generation.get(&node.id).unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let raw_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let raw_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target_a = raw_a.local_addr().unwrap();
    let target_b = raw_b.local_addr().unwrap();
    let pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        2,
        Arc::new(SourceReplySocketFactory::new(
            [ScopeId::HOST],
            [raw_a, raw_b],
        )),
    ));
    let stats = Arc::new(StatsManager::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let attach = async |target| {
        pool.prepare_source(
            honk_datapath::ScopeId::HOST,
            &honk_outbound::proxy::ProxyRegistry::new(),
            Arc::clone(&generation),
            Arc::clone(&runtime),
            client_addr,
            SourcePath::Vless(VlessUdpPath::Xudp),
            None,
            target,
            None,
            Duration::from_secs(2),
            Arc::clone(&alive),
            Arc::clone(&stats),
            honk_outbound::alive::IpVersion::V4,
            false,
        )
        .await
        .unwrap()
        .commit(&pool)
        .await
        .unwrap()
    };
    let lease_a = reserve_source(&pool, &stats, client_addr, target_a, node.id);
    let endpoint_a = install_source(
        &pool,
        lease_a,
        attach(target_a).await,
        target_a,
        &stats,
        node.id,
    );
    let lease_b = reserve_source(&pool, &stats, client_addr, target_b, node.id);
    let pending = attach(target_b).await;
    pool.remove(honk_datapath::ScopeId::HOST, client_addr, target_a);
    drop(endpoint_a);
    let endpoint_b = install_source(&pool, lease_b, pending, target_b, &stats, node.id);
    endpoint_b
        .send_packet(b"pending-survived", true)
        .await
        .unwrap();
    let frame = tokio::time::timeout(
        Duration::from_secs(2),
        next_data_frame(&mut events, &mut HashMap::new()),
    )
    .await
    .unwrap();
    assert_eq!(frame.target, Some(target_b));
    assert_eq!(
        frame.payload.as_deref(),
        Some(b"pending-survived".as_slice())
    );

    let cancelled = attach(target_a).await;
    pool.remove(honk_datapath::ScopeId::HOST, client_addr, target_b);
    drop(endpoint_b);
    drop(cancelled);
    let scope = SourceScope::new(
        honk_datapath::ScopeId::HOST,
        &runtime,
        client_addr,
        SourcePath::Vless(VlessUdpPath::Xudp),
        None,
    );
    wait_source_removed(&pool, &scope).await;
    assert!(pool.shutdown().await.joined);
    generation.shutdown().await;
    wire_task.abort();
    let _ = wire_task.await;
}
