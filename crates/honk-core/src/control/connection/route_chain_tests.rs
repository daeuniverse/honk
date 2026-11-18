use super::*;

fn socks5(name: &str, port: u16) -> Node {
    let mut node = Node {
        name: name.into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

/// The route `[leaf, exit]`, dialed as `leaf` behind a group with exit `exit`.
fn route(leaf: &Node, exit: &Node) -> OwnedTarget {
    let route = match honk_config::group_graph::compose(leaf.id, &[leaf.id], [exit.id]) {
        honk_config::group_graph::Composed::Routed(route) => route,
        other => panic!("expected a route, got {other:?}"),
    };
    OwnedTarget {
        node: leaf.clone(),
        route: Some(Box::new(honk_outbound::group::RoutedTarget {
            route,
            hop_names: [leaf.name.clone(), exit.name.clone()].into(),
        })),
    }
}

async fn race(
    handle: &ControlPlaneHandle,
    route: &OwnedTarget,
    generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
) {
    let won = race_to(handle, route, generation, "192.0.2.1:443".parse().unwrap()).await;
    assert!(!won, "the route must fail");
}

/// Whether the route wins; a failed route returns no winner, not an error.
async fn race_to(
    handle: &ControlPlaneHandle,
    route: &OwnedTarget,
    generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    target: std::net::SocketAddr,
) -> bool {
    let result = handle
        .race_candidates(
            &[route],
            target,
            None,
            "proxy",
            crate::stats::OutboundKind::Group,
            None,
            Duration::from_millis(500),
            tokio::time::Instant::now() + Duration::from_secs(5),
            Arc::clone(generation),
            IpVersion::V4,
            &HashMap::new(),
            false,
            #[cfg(feature = "native-api")]
            &HashMap::new(),
            #[cfg(feature = "native-api")]
            &ConnectionObservation::default(),
        )
        .await;
    assert!(result.is_ok(), "a route dial reports no error");
    matches!(result, Ok(Some(_)))
}

fn control(nodes: &[&Node]) -> (crate::control::ControlPlane, ControlPlaneHandle) {
    let control = crate::control::tests::support::control_plane(Config {
        nodes: nodes.iter().map(|node| (*node).clone()).collect(),
        ..Default::default()
    });
    let handle = control.spawn_handle();
    (control, handle)
}

fn demoted(handle: &ControlPlaneHandle, node: &Node) -> bool {
    handle
        .alive_set
        .is_failure_demoted(node.id, ProbeDomain::Tcp, IpVersion::V4)
}

/// A route's failure counts against the hop that failed. A route whose exit
/// is missing from the generation fails before any hop and charges nothing.
#[tokio::test]
async fn a_first_hop_failure_counts_against_the_leaf_only() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let front = socks5("front", port);
    let land = socks5("land", 1);
    let route = route(&front, &land);
    let (_control, handle) = control(&[&front, &land]);

    let without_exit = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&front))
            .unwrap(),
    );
    for _ in 0..2 {
        race(&handle, &route, &without_exit).await;
    }
    assert!(!demoted(&handle, &front) && !demoted(&handle, &land));

    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[front.clone(), land.clone()])
            .unwrap(),
    );
    for _ in 0..2 {
        race(&handle, &route, &generation).await;
    }
    assert!(demoted(&handle, &front));
    assert!(!demoted(&handle, &land));
}

#[tokio::test]
async fn an_exit_failure_counts_against_the_exit_only() {
    let relay = crate::test_support::socks5_relay().await;
    let refusing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let land = socks5("land", refusing.local_addr().unwrap().port());
    tokio::spawn(async move {
        while let Ok((stream, _)) = refusing.accept().await {
            drop(stream);
        }
    });
    let front = socks5("front", relay.addr.port());
    let route = route(&front, &land);
    let (_control, handle) = control(&[&front, &land]);
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[front.clone(), land.clone()])
            .unwrap(),
    );
    for _ in 0..2 {
        race(&handle, &route, &generation).await;
    }
    assert!(demoted(&handle, &land));
    assert!(!demoted(&handle, &front));
}

/// A front that completes its own handshake but cannot reach the exit's
/// server charges the exit, not itself.
#[tokio::test]
async fn a_front_that_cannot_reach_the_exit_charges_the_exit() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let refusing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = socks5("front", refusing.local_addr().unwrap().port());
    tokio::spawn(async move {
        while let Ok((mut client, _)) = refusing.accept().await {
            let mut greeting = [0u8; 2];
            client.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; usize::from(greeting[1])];
            client.read_exact(&mut methods).await.unwrap();
            client.write_all(&[5, 0]).await.unwrap();
            let mut request = [0u8; 10];
            client.read_exact(&mut request).await.unwrap();
            // Connection refused, for an IPv4 bind address.
            client
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        }
    });
    let land = socks5("land", 1);
    let route = route(&front, &land);
    let (_control, handle) = control(&[&front, &land]);
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[front.clone(), land.clone()])
            .unwrap(),
    );
    for _ in 0..2 {
        race(&handle, &route, &generation).await;
    }
    assert!(demoted(&handle, &land));
    assert!(!demoted(&handle, &front));
}

/// A route's success proves every hop, so a leaf used only behind an exit
/// does not keep the dial failures of earlier routes through it.
#[tokio::test]
async fn a_route_success_clears_the_leaf_failure_streak() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    tokio::spawn(async move {
        let mut accepted = Vec::new();
        while let Ok((stream, _)) = target.accept().await {
            accepted.push(stream);
        }
    });
    let front_relay = crate::test_support::socks5_relay().await;
    let land_relay = crate::test_support::socks5_relay().await;
    let front = socks5("front", front_relay.addr.port());
    let land = socks5("land", land_relay.addr.port());
    let route = route(&front, &land);
    let (_control, handle) = control(&[&front, &land]);
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[front.clone(), land.clone()])
            .unwrap(),
    );
    let fail = |node: &Node| {
        super::super::report_dial_failure_if_current(
            &generation,
            &handle.alive_set,
            node.id,
            ProbeDomain::Tcp,
            IpVersion::V4,
        )
    };

    fail(&front);
    fail(&land);
    assert!(race_to(&handle, &route, &generation, target_addr).await);
    fail(&front);
    fail(&land);
    assert!(!demoted(&handle, &front) && !demoted(&handle, &land));
}

/// A chain leaf whose last hop is the group's exit enters the exit once, so
/// the route has no exit hop past the chain's own; its success still proves
/// the chain and charges the exit with the latency.
#[tokio::test]
async fn a_chain_leaf_ending_at_the_exit_reports_its_success() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    tokio::spawn(async move {
        let mut accepted = Vec::new();
        while let Ok((stream, _)) = target.accept().await {
            accepted.push(stream);
        }
    });
    let front_relay = crate::test_support::socks5_relay().await;
    let land_relay = crate::test_support::socks5_relay().await;
    let front = socks5("front", front_relay.addr.port());
    let land = socks5("land", land_relay.addr.port());
    let mut chain = Node {
        name: "chain".into(),
        outbound: honk_config::node::OutboundConfig::Chain {
            hops: vec!["front".into(), "land".into()],
        },
        ..Default::default()
    };
    chain.id = chain.derive_id();
    let route = match honk_config::group_graph::compose(chain.id, &[front.id, land.id], [land.id]) {
        honk_config::group_graph::Composed::Routed(route) => route,
        other => panic!("expected a route, got {other:?}"),
    };
    assert_eq!(
        (route.hops(), route.leaf_hops()),
        (&[front.id, land.id][..], 2)
    );
    let route = OwnedTarget {
        node: chain.clone(),
        route: Some(Box::new(honk_outbound::group::RoutedTarget {
            route,
            hop_names: [front.name.clone(), land.name.clone()].into(),
        })),
    };
    let (_control, handle) = control(&[&front, &land]);
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[front.clone(), land.clone()])
            .unwrap(),
    );
    let fail = |node: &Node| {
        super::super::report_dial_failure_if_current(
            &generation,
            &handle.alive_set,
            node.id,
            ProbeDomain::Tcp,
            IpVersion::V4,
        )
    };

    fail(&chain);
    fail(&land);
    assert!(race_to(&handle, &route, &generation, target_addr).await);
    fail(&chain);
    fail(&land);
    assert!(!demoted(&handle, &chain) && !demoted(&handle, &land));
}

/// A losing route leaves its leaf's pool alone: a stream dialed to the leaf
/// itself would skip the exits.
#[tokio::test]
async fn a_losing_route_deposits_nothing_for_its_leaf() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    tokio::spawn(async move {
        let mut accepted = Vec::new();
        while let Ok((stream, _)) = target.accept().await {
            accepted.push(stream);
        }
    });
    let win_relay = crate::test_support::socks5_relay().await;
    let leaf_relay = crate::test_support::socks5_relay().await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let win = socks5("win", win_relay.addr.port());
    let leaf = socks5("leaf", leaf_relay.addr.port());
    let exit = socks5("exit", closed_port);
    let route = route(&leaf, &exit);
    let (_control, handle) = control(&[&win, &leaf, &exit]);
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[
            win.clone(),
            leaf.clone(),
            exit.clone(),
        ])
        .unwrap(),
    );

    let result = handle
        .race_candidates(
            &[&route, &OwnedTarget::node(win.clone())],
            target_addr,
            None,
            "proxy",
            crate::stats::OutboundKind::Group,
            None,
            Duration::from_millis(500),
            tokio::time::Instant::now() + Duration::from_secs(5),
            Arc::clone(&generation),
            IpVersion::V4,
            &HashMap::new(),
            false,
            #[cfg(feature = "native-api")]
            &HashMap::new(),
            #[cfg(feature = "native-api")]
            &ConnectionObservation::default(),
        )
        .await;
    let Ok(Some(winner)) = result else {
        panic!("the plain node must win");
    };
    assert_eq!(winner.target.node.id, win.id);
    for _ in 0..40 {
        if handle.connection_pool.ready_metrics().entries > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(handle.connection_pool.ready_metrics().entries, 0);
}

/// A route's streams come from its hops, so its relay refills no pool; a
/// plain node's relay refills its own.
#[test]
fn a_route_relay_replenishes_no_pool() {
    let leaf = socks5("leaf", 1);
    let exit = socks5("exit", 2);
    assert!(super::replenishes_pool(
        "proxy",
        &OwnedTarget::node(leaf.clone())
    ));
    assert!(!super::replenishes_pool("proxy", &route(&leaf, &exit)));
}

/// A group its dead exit emptied probes that exit too, or nothing would
/// bring the group back; an exit the alive set does not register is never
/// probed.
#[tokio::test]
async fn an_empty_group_probes_its_registered_exit() {
    let leaf = socks5("leaf", 1);
    let exit = socks5("exit", 2);
    let group = honk_config::group::Group {
        name: "proxy".into(),
        nodes: vec![leaf.id],
        exit: Some("exit".into()),
        ..Default::default()
    };
    let control = crate::control::tests::support::control_plane(Config {
        nodes: vec![leaf.clone(), exit.clone()],
        groups: vec![group],
        ..Default::default()
    });
    let handle = control.spawn_handle();
    let mut probes = handle
        .alive_set
        .take_trigger_rx()
        .expect("trigger receiver");
    let mut probed = || std::iter::from_fn(|| probes.try_recv().ok()).collect::<Vec<_>>();
    handle
        .alive_set
        .register_node(exit.id, exit.name.clone(), exit.address.clone());

    handle.probe_unavailable_group("proxy");
    assert!(probed().contains(&exit.id));

    handle.alive_set.remove_node(exit.id);
    handle.probe_unavailable_group("proxy");
    assert!(probed().is_empty());
}
