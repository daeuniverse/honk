use super::*;

#[tokio::test]
async fn ready_pool_hit_does_not_wait_for_physical_dial_permit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let tcp = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let mut node = Node {
        name: "ready-socks".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        ..Default::default()
    };
    node.id = node.derive_id();
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[node.clone()], 1, None)
            .unwrap()
            .0,
    );
    let _held = generation.acquire_dial_permit().await;
    let pool = ConnectionPool::new();
    let key = ConnectionPool::ready_key(&format!("{}:{}", node.host(), node.port), target, None);
    pool.deposit_ready(
        &key,
        crate::proxy::ProxyStream {
            stream: Box::new(tcp),
            target_addr: target,
            target_domain: None,
        },
    )
    .await;
    let registry = ProxyRegistry::default_resolver().unwrap();

    let (stream, fresh) = tokio::time::timeout(
        Duration::from_millis(100),
        ControlPlaneHandle::dial_pooled(
            &registry,
            &pool,
            &generation,
            &node,
            (target, None),
            Duration::from_secs(1),
            || {},
        ),
    )
    .await
    .expect("ready stream must bypass an exhausted physical-dial gate")
    .unwrap();
    assert!(
        !fresh,
        "a ready-pool acquire performs no network round trip"
    );

    drop(stream);
    server.abort();
}

#[tokio::test]
async fn feedback_does_not_start_while_waiting_for_dial_admission() {
    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let mut node = Node {
        name: "blocked-socks".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: "127.0.0.1".into(),
        port: 9,
        ..Default::default()
    };
    node.id = node.derive_id();
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[node.clone()], 1, None)
            .unwrap()
            .0,
    );
    let _held = generation.acquire_dial_permit().await;
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started_on_dial = Arc::clone(&started);

    let result = tokio::time::timeout(
        Duration::from_millis(20),
        ControlPlaneHandle::dial_pooled(
            &ProxyRegistry::default_resolver().unwrap(),
            &ConnectionPool::new(),
            &generation,
            &node,
            (target, None),
            Duration::from_secs(1),
            move || started_on_dial.store(true, std::sync::atomic::Ordering::Release),
        ),
    )
    .await;

    assert!(result.is_err());
    assert!(!started.load(std::sync::atomic::Ordering::Acquire));
}

#[test]
fn retired_runtime_errors_are_neutral() {
    let generation = honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
        .unwrap()
        .0;
    generation.begin_retirement();

    assert_eq!(
        score_runtime_outcome(&generation, &anyhow::anyhow!("retired")),
        crate::group::ScoreOutcome::Shutdown
    );
}

#[test]
fn retired_generation_dial_failures_do_not_poison_health() {
    let live_generation =
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
            .unwrap()
            .0;
    let retired_generation =
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
            .unwrap()
            .0;
    retired_generation.begin_retirement();
    let live = honk_outbound::alive::AliveDialerSet::new();
    let retired = honk_outbound::alive::AliveDialerSet::new();
    let node_id = uuid::Uuid::new_v4();

    for _ in 0..50 {
        report_dial_failure_if_current(
            &live_generation,
            &live,
            node_id,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        report_dial_failure_if_current(
            &retired_generation,
            &retired,
            node_id,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
    }

    assert!(!live.is_alive_for(node_id, ProbeDomain::DataUdp, IpVersion::V4));
    assert!(retired.is_alive_for(node_id, ProbeDomain::DataUdp, IpVersion::V4));
}
