use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test(start_paused = true)]
async fn cold_urltest_releases_candidates_progressively_and_cancels_waiters() {
    let started = Arc::new(AtomicUsize::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..3 {
        let started = Arc::clone(&started);
        tasks.spawn(async move {
            wait_for_cold_urltest_release(index).await;
            started.fetch_add(1, Ordering::AcqRel);
        });
    }
    tokio::task::yield_now().await;
    assert_eq!(
        started.load(Ordering::Acquire),
        1,
        "only the first candidate is immediate"
    );
    tokio::time::advance(COLD_URLTEST_STAGGER).await;
    tokio::task::yield_now().await;
    assert_eq!(
        started.load(Ordering::Acquire),
        2,
        "the second candidate releases after one delay"
    );
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    tokio::time::advance(COLD_URLTEST_STAGGER * 2).await;
    tokio::task::yield_now().await;
    assert_eq!(
        started.load(Ordering::Acquire),
        2,
        "cancelled unreleased candidate must not start"
    );
}

#[cfg(feature = "rprx")]
#[tokio::test]
async fn tcp_carrier_capacity_is_terminal_without_health_demotion() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let blocked = Node::from_share_link(&format!(
        "vless://00000000-0000-4000-8000-000000000001@{server}?mux=h2mux#capacity"
    ))
    .unwrap();
    let alternate = Node::from_share_link(&format!("socks5://{server}#alternate")).unwrap();
    let nodes = [blocked.clone(), alternate.clone()];
    let config = honk_config::Config {
        nodes: nodes.to_vec(),
        ..Default::default()
    };
    let control = crate::control::tests::support::control_plane(config);
    let handle = control.spawn_handle();
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            &nodes, 1, 4, 0, None,
        )
        .unwrap()
        .0,
    );
    for _ in 0..2 {
        let result = handle
            .race_candidates(
                &[&blocked, &alternate],
                "192.0.2.1:443".parse().unwrap(),
                None,
                "proxy",
                Duration::from_millis(50),
                Duration::from_secs(1),
                Arc::clone(&generation),
                IpVersion::V4,
                &HashMap::new(),
                true,
            )
            .await;
        assert!(
            handle
                .alive_set
                .is_alive_for(blocked.id, ProbeDomain::Tcp, IpVersion::V4)
        );
        let Err(error) = result else {
            panic!("local capacity must not become a retryable dial failure");
        };
        assert_eq!(
            honk_outbound::proxy::packet_rejection(&error),
            Some(honk_outbound::proxy::PacketRejection::Capacity),
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    let target = "192.0.2.1:443".parse().unwrap();
    let tcp = tokio::net::TcpStream::connect(server).await.unwrap();
    let (_peer, _) = listener.accept().await.unwrap();
    let key = ConnectionPool::ready_key(generation.generation(), alternate.id, target, None);
    handle
        .connection_pool
        .deposit_ready(
            generation.generation(),
            &key,
            crate::proxy::ProxyStream {
                stream: Box::new(tcp),
                target_addr: target,
                target_domain: None,
            },
        )
        .await;
    let result = handle
        .race_candidates(
            &[&alternate, &blocked],
            target,
            None,
            "proxy",
            Duration::from_millis(50),
            Duration::from_secs(1),
            Arc::clone(&generation),
            IpVersion::V4,
            &HashMap::new(),
            false,
        )
        .await;
    let Err(error) = result else {
        panic!("completed capacity refusal must veto a provisional ready winner");
    };
    assert_eq!(
        honk_outbound::proxy::packet_rejection(&error),
        Some(honk_outbound::proxy::PacketRejection::Capacity),
    );
    generation.shutdown().await;
}
