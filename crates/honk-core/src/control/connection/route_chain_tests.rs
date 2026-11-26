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
        collapse: crate::group::ExitCollapse::None,
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
    let manager = handle.group_manager.read().clone();
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
            &manager,
            IpVersion::V4,
            manager.route_health_revision("proxy"),
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

fn control(
    nodes: &[&Node],
    members: &[&Node],
    exit: &Node,
) -> (crate::control::ControlPlane, ControlPlaneHandle) {
    let control = crate::control::tests::support::control_plane(Config {
        nodes: nodes.iter().map(|node| (*node).clone()).collect(),
        groups: vec![honk_config::group::Group {
            name: "proxy".into(),
            policy: honk_config::group::GroupPolicy::Fallback,
            nodes: members.iter().map(|node| node.id).collect(),
            exit: Some(exit.name.clone()),
            final_outbound: Some("block".into()),
            ..Default::default()
        }],
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
    let (_control, handle) = control(&[&front, &land], &[&front], &land);

    let without_exit = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&front))
            .unwrap(),
    );
    for _ in 0..2 {
        race(&handle, &route, &without_exit).await;
    }
    assert!(!demoted(&handle, &front) && !demoted(&handle, &land));

    let generation = handle.runtime_registry.read().clone();
    for _ in 0..2 {
        race(&handle, &route, &generation).await;
    }
    assert!(demoted(&handle, &front));
    assert!(!demoted(&handle, &land));
}

#[tokio::test]
async fn a_collapsed_exit_counts_only_its_proxy_socket_refusal() {
    use honk_outbound::group::ExitCollapse;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(10), async {
        let application = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = application.local_addr().unwrap();
        for collapse in [ExitCollapse::Member, ExitCollapse::Direct] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let exit = socks5("exit", listener.local_addr().unwrap().port());
            let member = collapse == ExitCollapse::Member;
            let mut config = Config {
                nodes: vec![exit.clone()],
                groups: vec![Group {
                    name: "proxy".into(),
                    policy: GroupPolicy::Fallback,
                    nodes: if member { vec![exit.id] } else { Vec::new() },
                    exit: Some(exit.name.clone()),
                    final_outbound: Some(if member { "block" } else { "direct" }.into()),
                    ..Default::default()
                }],
                ..Default::default()
            };
            config.ensure_builtin_nodes();
            let plane = crate::control::tests::support::control_plane(config);
            let handle = plane.spawn_handle();
            let manager = handle.group_manager.read().clone();
            let generation = handle.runtime_registry.read().clone();
            let selected = crate::control::reload::resolve_outbound_plan_for_target(
                handle.config.read().await.as_ref(),
                &manager,
                "proxy",
                &tcp_score_context(destination, None, IpVersion::V4),
                crate::control::reload::OutboundConstraint::Any,
            )
            .targets
            .pop()
            .unwrap();
            assert_eq!(selected.collapse, collapse);
            assert_eq!(selected.node.id, exit.id);

            let reject_target = [true, false, true, false];
            let dial = async {
                for _ in reject_target {
                    assert!(!race_to(&handle, &selected, &generation, destination).await);
                }
            };
            let peer = async {
                for reject in reject_target {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut greeting = [0; 3];
                    socket.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    socket.write_all(&[5, 0]).await.unwrap();
                    let mut request = [0; 10];
                    socket.read_exact(&mut request).await.unwrap();
                    assert_eq!(request[..8], [5, 1, 0, 1, 127, 0, 0, 1]);
                    assert_eq!(request[8..], destination.port().to_be_bytes());
                    if reject {
                        socket
                            .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                            .await
                            .unwrap();
                    } else {
                        socket.set_zero_linger().unwrap();
                    }
                }
            };
            tokio::join!(dial, peer);
            assert!(
                !demoted(&handle, &exit),
                "{collapse:?} charged a failure after socket admission"
            );

            drop(listener);
            for _ in 0..2 {
                assert!(!race_to(&handle, &selected, &generation, destination).await);
            }
            assert!(
                demoted(&handle, &exit),
                "{collapse:?} lost a physical connection refusal"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn downstream_eof_without_a_typed_cause_does_not_demote_either_hop() {
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
    let (_control, handle) = control(&[&front, &land], &[&front], &land);
    let generation = handle.runtime_registry.read().clone();
    for _ in 0..2 {
        race(&handle, &route, &generation).await;
    }
    assert!(!demoted(&handle, &land));
    assert!(!demoted(&handle, &front));
}

#[tokio::test]
async fn a_front_refusal_does_not_demote_the_exit_for_another_front() {
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
    let land_relay = crate::test_support::socks5_relay().await;
    let good_relay = crate::test_support::socks5_relay().await;
    let land = socks5("land", land_relay.addr.port());
    let good = socks5("good", good_relay.addr.port());
    let bad_route = route(&front, &land);
    let (_control, handle) = control(&[&front, &good, &land], &[&front, &good], &land);
    let manager = handle.group_manager.read().clone();
    let select = |family| {
        let context = crate::group::ScoreSelectionContext::aggregate(
            crate::group::SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            family,
        );
        manager.selection_plan_for_target("proxy", &context)
    };
    assert_eq!(select(IpVersion::V4).entries[0].node.id, front.id);
    let generation = handle.runtime_registry.read().clone();
    for _ in 0..10 {
        race(&handle, &bad_route, &generation).await;
    }
    assert!(!demoted(&handle, &land));
    assert!(!demoted(&handle, &front));
    // Fallback shares its pin across TCP families: first check IPv6 before IPv4 replaces the pin.
    assert_eq!(select(IpVersion::V6).entries[0].node.id, front.id);
    assert_eq!(select(IpVersion::V4).entries[0].node.id, good.id);
    assert_eq!(select(IpVersion::V6).entries[0].node.id, good.id);
    let entry = select(IpVersion::V4).entries.pop().unwrap();
    let good_route = manager.own_target(crate::group::Target {
        node: entry.node,
        route: entry.route,
    });
    assert_eq!(good_route.node.id, good.id);
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    assert!(race_to(&handle, &good_route, &generation, address).await);
    assert_eq!(*good_relay.requests.lock(), [land_relay.addr]);
    assert_eq!(*land_relay.requests.lock(), [address]);
}

#[tokio::test]
async fn a_staggered_route_cannot_recover_health_after_its_selector_changes() {
    use crate::control::reload::{OutboundConstraint, resolve_outbound_plan_for_target};
    use crate::group::SelectorNetworks;
    use crate::test_support::socks5_relay;

    let front_relay = socks5_relay().await;
    let land_relay = socks5_relay().await;
    let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dst = origin.local_addr().unwrap();
    let first = socks5("slow", stalled.local_addr().unwrap().port());
    let a = socks5("a", front_relay.addr.port());
    let land = socks5("land", land_relay.addr.port());
    let config = Config {
        nodes: vec![first.clone(), a.clone(), land.clone()],
        groups: vec![
            Group {
                name: "proxy".into(),
                policy: GroupPolicy::URLTest,
                nodes: vec![first.id],
                groups: vec!["pin".into()],
                exit: Some(land.name.clone()),
                ..Default::default()
            },
            Group {
                name: "pin".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![a.id, land.id],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let plane = crate::control::tests::support::control_plane(config.clone());
    let handle = plane.spawn_handle();
    let manager = handle.group_manager.read().clone();
    let set_pin = |member| {
        manager
            .set_selector_choice("pin", member, SelectorNetworks::Tcp)
            .unwrap()
    };
    let original_revision = set_pin("a");
    let strike = || {
        handle
            .alive_set
            .record_dial_failure(land.id, ProbeDomain::Tcp, IpVersion::V4);
    };
    strike();
    assert!(!demoted(&handle, &land));

    let context = tcp_score_context(dst, None, IpVersion::V4);
    let plan = resolve_outbound_plan_for_target(
        &config,
        &manager,
        "proxy",
        &context,
        OutboundConstraint::Any,
    );
    let (targets, mode, feedback, _chains, _, family, revision) = unpack_tcp_score_plan(plan);
    assert_eq!(mode, SelectionPlanMode::ColdUrlTest);
    let [immediate, delayed] = targets.as_slice() else {
        panic!("expected two cold candidates");
    };
    assert_eq!(immediate.node.id, first.id);
    assert_eq!(delayed.route().unwrap().hops(), [a.id, land.id]);

    let candidates = [immediate, delayed];
    let generation = handle.runtime_registry.read().clone();
    #[cfg(feature = "native-api")]
    let observation = ConnectionObservation::default();
    tokio::time::pause();
    let race = handle.race_candidates(
        &candidates,
        dst,
        None,
        "proxy",
        crate::stats::OutboundKind::Group,
        None,
        Duration::from_secs(1),
        tokio::time::Instant::now() + Duration::from_secs(5),
        generation,
        &manager,
        family,
        revision,
        &feedback,
        true,
        #[cfg(feature = "native-api")]
        &_chains,
        #[cfg(feature = "native-api")]
        &observation,
    );
    tokio::pin!(race);
    assert!(futures::poll!(race.as_mut()).is_pending());
    assert!(set_pin("land") > original_revision);
    tokio::time::resume();

    let winner = race.await.unwrap().unwrap();
    assert_eq!(winner.target.key(), delayed.key());
    assert!(
        winner
            .route_traffic
            .is_some_and(|traffic| traffic.confirmed)
    );
    assert_eq!(*front_relay.requests.lock(), [land_relay.addr]);
    assert_eq!(*land_relay.requests.lock(), [dst]);
    set_pin("a");
    strike();
    assert!(
        demoted(&handle, &land),
        "stale success erased the prior dial failure"
    );
}

#[tokio::test]
async fn a_write_only_exit_does_not_clear_failure_streaks_at_open() {
    use honk_config::node::{OutboundConfig, TlsOptions, TrojanConfig};
    use tokio::io::AsyncReadExt;

    let front_peer = crate::test_support::socks5_relay().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = socks5("front", front_peer.addr.port());
    let mut exit = socks5("exit", listener.local_addr().unwrap().port());
    exit.outbound = OutboundConfig::Trojan(TrojanConfig {
        password: Some("test".into()),
        tls: TlsOptions {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    });
    exit.id = exit.derive_id();
    let path = route(&front, &exit);
    let (_control, handle) = control(&[&front, &exit], &[&front], &exit);
    let generation = handle.runtime_registry.read().clone();
    let strike = || {
        handle
            .alive_set
            .record_dial_failure(exit.id, ProbeDomain::Tcp, IpVersion::V4)
    };
    strike();
    let addr = "127.0.0.1:443".parse().unwrap();
    assert!(race_to(&handle, &path, &generation, addr).await);
    let (mut peer, _) = listener.accept().await.unwrap();
    let mut request = [0; 68];
    peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request[56..], b"\r\n\x01\x01\x7f\x00\x00\x01\x01\xbb\r\n");
    strike();
    assert!(
        demoted(&handle, &exit),
        "writing a Trojan request is not a response"
    );
}

#[tokio::test]
async fn a_routed_score_deadline_preserves_observed_leaf_availability() {
    use crate::group::{ScoreOutcome, ScoreVerificationState};
    use tokio::io::AsyncReadExt;

    let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = socks5("front", stalled.local_addr().unwrap().port());
    let exit = socks5("exit", 1);
    let path = route(&front, &exit);
    let plane = crate::control::tests::support::control_plane(Config {
        nodes: vec![front.clone(), exit.clone()],
        groups: vec![Group {
            name: "score".into(),
            policy: GroupPolicy::Score,
            nodes: vec![front.id],
            exit: Some(exit.name.clone()),
            ..Default::default()
        }],
        ..Default::default()
    });
    let handle = plane.spawn_handle();
    let manager = handle.group_manager.read().clone();
    let dst = "127.0.0.1:443".parse().unwrap();
    let context = tcp_score_context(dst, None, IpVersion::V4);
    let source = manager
        .feedback_for_node(front.id, context.clone())
        .unwrap();
    for _ in 0..4 {
        let report = source.start();
        report.setup_succeeded();
        report.tx(1);
        report.rx(1);
        report.finish(ScoreOutcome::Cancelled);
    }
    let state = || {
        manager
            .score_verification_for_network("score", SelectionNetwork::Tcp)
            .unwrap()
            .1
            .state
    };
    assert_eq!(state(), ScoreVerificationState::ObservedUsable);
    let before = manager.score_state().root_business_starts();
    let generation = handle.runtime_registry.read().clone();
    let feedback = HashMap::from([(path.key(), source.business())]);
    let paths = [&path];
    #[cfg(feature = "native-api")]
    let (chains, observer) = (HashMap::new(), ConnectionObservation::default());
    let dial = handle.race_candidates(
        &paths,
        dst,
        None,
        "score",
        crate::stats::OutboundKind::Group,
        None,
        Duration::from_secs(10),
        tokio::time::Instant::now() + Duration::from_secs(2),
        generation,
        &manager,
        IpVersion::V4,
        manager.route_health_revision("score"),
        &feedback,
        false,
        #[cfg(feature = "native-api")]
        &chains,
        #[cfg(feature = "native-api")]
        &observer,
    );
    tokio::pin!(dial);
    let mut peer = tokio::select! {
        socket = stalled.accept() => socket.unwrap().0,
        _ = &mut dial => panic!("deadline expired before admission"),
    };
    let mut greeting = [0; 3];
    tokio::select! {
        result = peer.read_exact(&mut greeting) => { result.unwrap(); },
        _ = &mut dial => panic!("deadline expired before proxy setup"),
    }
    assert_eq!(greeting, [5, 1, 0]);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(dial.await.unwrap().is_none());
    assert_eq!(manager.score_state().root_business_starts(), before + 1);
    assert_eq!(state(), ScoreVerificationState::ObservedUsable);
}

#[tokio::test]
async fn a_reset_after_a_routed_reply_does_not_invalidate_the_selected_leaf() -> anyhow::Result<()>
{
    use crate::control::tests::{
        store_active_tcp_flow,
        support::{TestRetirement, test_dns_forwarder},
    };
    use crate::group::ScoreOutcome;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(10), async {
        for reset_client in [false, true] {
            let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let dst = origin.local_addr()?;
            let front_peer = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let land = crate::test_support::socks5_relay().await;
            let front = socks5("front", front_peer.local_addr()?.port());
            let exit = socks5("exit", land.addr.port());
            let mut config = Config {
                nodes: vec![front.clone(), exit.clone()],
                groups: vec![Group {
                    name: "scored".into(),
                    policy: GroupPolicy::Score,
                    nodes: vec![front.id, exit.id],
                    exit: Some(exit.name),
                    ..Default::default()
                }],
                ..Default::default()
            };
            config.ensure_builtin_nodes();
            config.routing.default_outbound = "scored".into();
            config.global.dial_mode = "ip".into();
            let router = Router::from_config(&config.routing)?;
            let plane = ControlPlane::new(
                config,
                Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
                router,
                Arc::new(ProxyRegistry::default_resolver()?),
                DnsResolver::new(&Default::default())?,
                test_dns_forwarder(),
            )?;
            let handle = plane.spawn_handle();
            let retirement = TestRetirement::start(&handle);
            let manager = handle.group_manager.read().clone();
            let context = tcp_score_context(dst, None, IpVersion::V4);
            let feedback = manager
                .feedback_for_node(front.id, context.clone())
                .unwrap();
            for _ in 0..4 {
                let sample = feedback.start();
                sample.setup_succeeded();
                sample.tx(1);
                sample.rx(1);
                sample.finish(ScoreOutcome::Cancelled);
            }
            // Qualify the ordinary choice so the routed front gets a funded trial.
            let seed = manager.feedback_for_node(exit.id, context.clone()).unwrap();
            for _ in 0..5 {
                let sample = seed.start();
                sample.setup_succeeded();
                sample.tx(1);
                sample.rx(1);
                sample.finish(ScoreOutcome::Success);
            }
            let usable_selections = || {
                manager
                    .score_verification_counters("scored", SelectionNetwork::Tcp)
                    .usable_selections
            };
            let usable_before = usable_selections();
            let before = manager.score_state().root_business_starts();
            let mut client = TcpStream::connect(dst).await?;
            let (socket, src) = origin.accept().await?;
            store_active_tcp_flow(&handle, dst, src).await?;
            let serving = {
                let handle = handle.clone();
                tokio::spawn(async move { handle.serve_connection(socket, src).await })
            };
            let (mut socket, _) = front_peer.accept().await?;
            let mut greet = [0; 3];
            socket.read_exact(&mut greet).await?;
            assert_eq!(greet, [5, 1, 0]);
            socket.write_all(&[5, 0]).await?;
            let mut request = [0; 10];
            socket.read_exact(&mut request).await?;
            assert_eq!(&request[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
            assert_eq!(&request[8..], &land.addr.port().to_be_bytes());
            let mut carrier = TcpStream::connect(land.addr).await?;
            socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let (end, stop) = tokio::sync::oneshot::channel::<()>();
            let mut end = Some(end);
            let bridge = tokio::spawn(async move {
                tokio::select! {
                    _ = stop => socket2::SockRef::from(&socket).set_linger(Some(Duration::ZERO)),
                    _ = tokio::io::copy_bidirectional(&mut socket, &mut carrier) => Ok(()),
                }
            });
            let (mut upstream, _) = origin.accept().await?;
            client.write_u8(b'q').await?;
            assert_eq!(upstream.read_u8().await?, b'q');
            upstream.write_u8(b'r').await?;
            assert_eq!(client.read_u8().await?, b'r');
            if reset_client {
                socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO))?;
                drop(client);
            } else {
                end.take().unwrap().send(()).unwrap();
            }
            serving.await??;
            drop(end);
            bridge.await??;
            assert_eq!(*land.requests.lock(), [dst]);
            assert_eq!(manager.score_state().root_business_starts(), before + 1);
            assert_eq!(handle.stats.snapshot()["scored"].errors, 1);
            let budget = manager.score_budget_counters("scored", SelectionNetwork::Tcp);
            assert_eq!(budget.spent, 1, "the routed front must run a funded trial");
            assert_eq!(
                (
                    budget.trial_success,
                    budget.trial_failure,
                    budget.trial_cancelled,
                ),
                (0, u64::from(!reset_client), u64::from(reset_client)),
                "upstream reset fails the business and client reset cancels it"
            );
            assert_eq!(usable_selections(), usable_before + 1);
            let next = manager.selection_plan_for_target("scored", &context);
            assert_eq!(next.entries[0].node.id, front.id);
            assert_eq!(
                usable_selections(),
                usable_before + 2,
                "the routed front retains usable evidence for this target"
            );
            drop(next);
            retirement.join(&handle).await?;
        }
        Ok(())
    })
    .await?
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
    let (_control, handle) = control(&[&front, &land], &[&front], &land);
    let generation = handle.runtime_registry.read().clone();
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
    let chain = Node::chain_from_nodes("chain", &[&front, &land]).unwrap();
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
        collapse: crate::group::ExitCollapse::None,
    };
    let (_control, handle) = control(&[&front, &land, &chain], &[&chain], &land);
    let generation = handle.runtime_registry.read().clone();
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

const SOCKS_CONNECTED: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

async fn accept_socks_connect(
    listener: &TcpListener,
    destination: SocketAddr,
) -> anyhow::Result<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let SocketAddr::V4(destination) = destination else {
        panic!("expected a loopback IPv4 target");
    };
    let (mut peer, _) = listener.accept().await?;
    let mut greeting = [0; 3];
    peer.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [5, 1, 0]);
    peer.write_all(&[5, 0]).await?;
    let mut request = [0; 10];
    peer.read_exact(&mut request).await?;
    assert_eq!(request[..4], [5, 1, 0, 1]);
    assert_eq!(request[4..8], destination.ip().octets());
    assert_eq!(request[8..], destination.port().to_be_bytes());
    Ok(peer)
}

async fn finish_ready_refill(
    listener: &TcpListener,
    destination: SocketAddr,
    tasks_before: usize,
) -> anyhow::Result<Option<TcpStream>> {
    use tokio::io::AsyncWriteExt;

    // A queued task already counts as alive on the current-thread runtime.
    // Finish its real handshake and join its completion before checking the pool.
    let tasks = tokio::runtime::Handle::current().metrics();
    let active = tasks.num_alive_tasks();
    if active == tasks_before {
        return Ok(None);
    }
    assert_eq!(active, tasks_before + 1);
    let mut peer = accept_socks_connect(listener, destination).await?;
    peer.write_all(&SOCKS_CONNECTED).await?;
    while tasks.num_alive_tasks() > tasks_before {
        tokio::task::yield_now().await;
    }
    Ok(Some(peer))
}

/// A losing route leaves its leaf's pool alone: a stream dialed to the leaf
/// itself would skip the exits.
#[tokio::test(flavor = "current_thread")]
async fn a_losing_route_deposits_nothing_for_its_leaf() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(10), async {
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let target_addr = target.local_addr()?;
        let win_peer = TcpListener::bind("127.0.0.1:0").await?;
        let leaf_peer = TcpListener::bind("127.0.0.1:0").await?;
        let exit_peer = TcpListener::bind("127.0.0.1:0").await?;
        let exit_addr = exit_peer.local_addr()?;
        let win = socks5("win", win_peer.local_addr()?.port());
        let leaf = socks5("leaf", leaf_peer.local_addr()?.port());
        let exit = socks5("exit", exit_addr.port());
        let route = route(&leaf, &exit);
        let (_control, handle) = control(&[&win, &leaf, &exit], &[&leaf], &exit);
        let generation = handle.runtime_registry.read().clone();
        let manager = handle.group_manager.read().clone();
        let tasks_before = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();

        let raced = async {
            handle
                .race_candidates(
                    &[&route, &OwnedTarget::node(win.clone())],
                    target_addr,
                    None,
                    "proxy",
                    crate::stats::OutboundKind::Group,
                    None,
                    Duration::from_secs(2),
                    tokio::time::Instant::now() + Duration::from_secs(5),
                    Arc::clone(&generation),
                    &manager,
                    IpVersion::V4,
                    manager.route_health_revision("proxy"),
                    &HashMap::new(),
                    false,
                    #[cfg(feature = "native-api")]
                    &HashMap::new(),
                    #[cfg(feature = "native-api")]
                    &ConnectionObservation::default(),
                )
                .await
        };
        let peers = async {
            let mut loser = accept_socks_connect(&leaf_peer, exit_addr).await?;
            let mut winner = accept_socks_connect(&win_peer, target_addr).await?;
            loser.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            // The refused dial may close with the unused BND.ADDR still queued.
            match loser.read(&mut [0; 1]).await {
                Ok(n) => assert_eq!(n, 0),
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                Err(error) => return Err(error.into()),
            }
            let upstream = TcpStream::connect(target_addr).await?;
            let (origin, _) = target.accept().await?;
            winner.write_all(&SOCKS_CONNECTED).await?;
            Ok((winner, upstream, origin))
        };
        let (winner, _winner_peer) = tokio::try_join!(raced, peers)?;
        let winner = winner.expect("the plain node must win");
        assert_eq!(winner.target.node.id, win.id);
        assert!(winner.target.route.is_none());
        assert_eq!(handle.stats.snapshot()["proxy"].errors, 1);

        let refill = finish_ready_refill(&leaf_peer, target_addr, tasks_before).await?;
        generation.shutdown().await;
        assert!(!generation.tasks_failed());
        assert_eq!(handle.connection_pool.ready_metrics().entries, 0);
        assert!(
            refill.is_none(),
            "the losing route must not dial the bare leaf"
        );
        Ok(())
    })
    .await?
}

/// A route's streams come from its hops, so its relay refills no pool; a
/// plain node's relay refills its own.
#[tokio::test(flavor = "current_thread")]
async fn a_route_relay_replenishes_no_pool() -> anyhow::Result<()> {
    use crate::control::tests::{
        store_active_tcp_flow,
        support::{TestRetirement, test_dns_forwarder},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn forward_to(mut peer: TcpStream, target: SocketAddr) -> anyhow::Result<()> {
        let mut upstream = TcpStream::connect(target).await?;
        peer.write_all(&SOCKS_CONNECTED).await?;
        tokio::io::copy_bidirectional(&mut peer, &mut upstream).await?;
        Ok(())
    }

    tokio::time::timeout(Duration::from_secs(10), async {
        let leaf_peer = TcpListener::bind("127.0.0.1:0").await?;
        let exit_peer = TcpListener::bind("127.0.0.1:0").await?;
        let exit_addr = exit_peer.local_addr()?;
        let leaf = socks5("leaf", leaf_peer.local_addr()?.port());
        let exit = socks5("exit", exit_addr.port());
        let ingress = TcpListener::bind("127.0.0.1:0").await?;
        let destination = ingress.local_addr()?;
        for routed in [false, true] {
            let mut config = Config {
                nodes: vec![leaf.clone(), exit.clone()],
                groups: vec![Group {
                    name: "proxy".into(),
                    policy: GroupPolicy::Fallback,
                    nodes: vec![leaf.id],
                    exit: routed.then(|| exit.name.clone()),
                    ..Default::default()
                }],
                ..Default::default()
            };
            config.ensure_builtin_nodes();
            config.routing.default_outbound = "proxy".into();
            config.global.dial_mode = "ip".into();
            config.global.max_concurrent_dials = 1;
            let router = Router::from_config(&config.routing)?;
            let control = ControlPlane::new(
                config,
                Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
                router,
                Arc::new(ProxyRegistry::default_resolver()?),
                DnsResolver::new(&Default::default())?,
                test_dns_forwarder(),
            )?;
            let handle = control.spawn_handle();
            let retirement = TestRetirement::start(&handle);
            let generation = handle.runtime_registry.read().clone();
            assert_eq!(generation.dial_limit(), 1);
            let pool = &handle.connection_pool;
            let generation_id = generation.generation();
            let key = ConnectionPool::ready_key(generation_id, leaf.id, destination, None);
            // Both paths can fund the same target-bound refill as soon as the relay ends.
            assert!(!pool.note_target(generation_id, &key));

            let mut client = TcpStream::connect(destination).await?;
            let (socket, src) = ingress.accept().await?;
            store_active_tcp_flow(&handle, destination, src).await?;
            let tasks_before = tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks();
            let peers = async {
                let target = if routed { exit_addr } else { destination };
                let mut first = accept_socks_connect(&leaf_peer, target).await?;
                if routed {
                    let mut carrier = TcpStream::connect(exit_addr).await?;
                    first.write_all(&SOCKS_CONNECTED).await?;
                    let exit = async {
                        let peer = accept_socks_connect(&exit_peer, destination).await?;
                        forward_to(peer, destination).await
                    };
                    let forward = async {
                        tokio::io::copy_bidirectional(&mut first, &mut carrier).await?;
                        Ok::<_, anyhow::Error>(())
                    };
                    tokio::try_join!(forward, exit)?;
                } else {
                    forward_to(first, destination).await?;
                }
                Ok::<_, anyhow::Error>(())
            };
            let origin = async {
                let (mut upstream, _) = ingress.accept().await?;
                assert_eq!(upstream.read_u8().await?, b'q');
                upstream.write_u8(b'r').await?;
                assert_eq!(upstream.read(&mut [0; 1]).await?, 0);
                upstream.shutdown().await?;
                Ok::<_, anyhow::Error>(())
            };
            let business = async {
                client.write_u8(b'q').await?;
                assert_eq!(client.read_u8().await?, b'r');
                // Hold the only dial permit across relay retirement, so a queued
                // refill cannot race the observation of its peer and pool entry.
                let permit = generation.acquire_dial_permit().await;
                client.shutdown().await?;
                assert_eq!(client.read(&mut [0; 1]).await?, 0);
                Ok::<_, anyhow::Error>(permit)
            };
            let ((), (), (), permit) = tokio::try_join!(
                handle.serve_connection(socket, src),
                peers,
                origin,
                business
            )?;
            let snapshot = handle.stats.snapshot();
            let flow = &snapshot["proxy"];
            assert_eq!(
                (flow.total_conns, flow.active_conns, flow.errors),
                (1, 0, 0)
            );
            drop(permit);

            let refill = finish_ready_refill(&leaf_peer, destination, tasks_before).await?;
            let result = (refill.is_some(), pool.ready_metrics().entries);
            if let Some(mut peer) = refill {
                let mut pooled = pool
                    .acquire_ready(&key)
                    .await
                    .expect("refill in the leaf's pool");
                peer.write_u8(b'w').await?;
                assert_eq!(pooled.stream.read_u8().await?, b'w');
            }
            generation.shutdown().await;
            assert!(!generation.tasks_failed());
            retirement.join(&handle).await?;
            assert_eq!(result, (!routed, u64::from(!routed)), "routed={routed}");
        }
        Ok(())
    })
    .await?
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
        .register_node(exit.id, exit.name.clone(), Some(exit.address.clone()));

    handle.probe_unavailable_group("proxy");
    assert!(probed().contains(&exit.id));

    handle.alive_set.remove_node(exit.id);
    handle.probe_unavailable_group("proxy");
    assert!(probed().is_empty());
}
