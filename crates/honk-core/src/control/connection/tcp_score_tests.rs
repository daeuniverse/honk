use super::*;

#[tokio::test]
async fn relay_outcome_is_settled_once_even_when_retirement_fails() -> anyhow::Result<()> {
    use crate::control::tests::support::{canonical_socks5, test_dns_forwarder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(10), async {
        for relay_fails in [false, true] {
            for retirement_fails in [false, true] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let destination = listener.local_addr()?;
                let proxies = [
                    tokio::net::TcpListener::bind("127.0.0.1:0").await?,
                    tokio::net::TcpListener::bind("127.0.0.1:0").await?,
                ];
                let nodes = [
                    canonical_socks5("seed", "127.0.0.1", proxies[0].local_addr()?.port(), None),
                    canonical_socks5("relay", "127.0.0.1", proxies[1].local_addr()?.port(), None),
                ];
                let mut config = Config::default();
                config.ensure_builtin_nodes();
                config.nodes.extend(nodes.iter().cloned());
                config.groups = vec![Group {
                    name: "score".into(),
                    policy: GroupPolicy::Score,
                    nodes: nodes.iter().map(|node| node.id).collect(),
                    ..Default::default()
                }];
                config.routing.default_outbound = "score".into();
                config.global.dial_mode = "ip".into();
                let router = Router::from_config(&config.routing)?;
                let plane = ControlPlane::new(
                    config,
                    Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
                    router,
                    Arc::new(ProxyRegistry::default_resolver()?),
                    DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
                    test_dns_forwarder(),
                )?;
                let handle = plane.spawn_handle();
                let (fatal_tx, mut removal_errors) = mpsc::unbounded_channel();
                let removals = spawn_retirement_worker(
                    Arc::clone(&plane.udp_pool),
                    Arc::clone(&handle.ebpf),
                    Arc::clone(&handle.connection_tracker),
                    fatal_tx,
                    Arc::clone(&handle.tcp_flow_pins),
                    Arc::clone(&handle.retirement),
                );
                let manager = handle.group_manager.read().clone();
                let seed = manager
                    .feedback_for_node(
                        nodes[0].id,
                        crate::group::ScoreSelectionContext::aggregate(
                            SelectionNetwork::Tcp,
                            ProbeDomain::Tcp,
                            IpVersion::V4,
                        ),
                    )
                    .unwrap()
                    .start();
                seed.setup_succeeded();
                seed.tx(1);
                seed.rx(1);
                seed.finish(crate::group::ScoreOutcome::Success);
                let mut client = TcpStream::connect(destination).await?;
                let (accepted, source) = listener.accept().await?;
                crate::control::tests::store_active_tcp_flow(&handle, destination, source).await?;
                let worker = handle.clone();
                let serving =
                    tokio::spawn(async move { worker.serve_connection(accepted, source).await });
                let (mut upstream, _) = tokio::select! {
                    accepted = proxies[0].accept() => accepted?,
                    accepted = proxies[1].accept() => accepted?,
                };
                let mut greeting = [0; 3];
                upstream.read_exact(&mut greeting).await?;
                upstream.write_all(&[5, 0]).await?;
                let mut request = [0; 10];
                upstream.read_exact(&mut request).await?;
                upstream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await?;
                client.write_all(b"q").await?;
                assert_eq!(upstream.read_u8().await?, b'q');
                upstream.write_all(b"r").await?;
                assert_eq!(client.read_u8().await?, b'r');
                if retirement_fails {
                    let key = handle.tcp_flow_pins.snapshot().into_iter().next().unwrap();
                    assert_eq!(handle.tcp_flow_pins.release_for_test(key), Some(true));
                }
                if relay_fails {
                    socket2::SockRef::from(&upstream).set_linger(Some(Duration::ZERO))?;
                    drop(upstream);
                } else {
                    upstream.shutdown().await?;
                    client.shutdown().await?;
                }
                let result = serving.await?;
                assert_eq!(result.is_err(), retirement_fails);
                let counters = manager.score_budget_counters("score", SelectionNetwork::Tcp);
                assert_eq!(counters.spent, 1, "fixture must execute a scored trial");
                assert_eq!(
                    (
                        counters.trial_success,
                        counters.trial_failure,
                        counters.trial_cancelled
                    ),
                    (u64::from(!relay_fails), u64::from(relay_fails), 0),
                );
                assert_eq!(
                    handle.stats.snapshot()["score"].errors,
                    u32::from(relay_fails)
                );
                if retirement_fails {
                    assert!(
                        tokio::time::timeout(Duration::from_millis(20), async {
                            tokio::select! {
                                accepted = proxies[0].accept() => accepted,
                                accepted = proxies[1].accept() => accepted,
                            }
                        })
                        .await
                        .is_err(),
                        "failed retirement must not replenish the pool"
                    );
                }
                let runtime = handle.runtime_registry.read().clone();
                runtime.shutdown().await;
                plane.udp_pool.shutdown().await;
                handle.retirement.sink.lock().take();
                removals.await?;
                assert_eq!(removal_errors.try_recv().is_ok(), retirement_fails);
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[test]
fn pending_warm_refill_refunds_trial_without_starting_business() {
    let nodes = [
        Node::from_share_link("socks5://127.0.0.1:1080#a").unwrap(),
        Node::from_share_link("socks5://127.0.0.1:1081#b").unwrap(),
    ];
    let group = honk_config::group::Group {
        name: "score".into(),
        policy: honk_config::group::GroupPolicy::Score,
        nodes: nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    };
    let manager = crate::group::GroupManager::new(&[group], &nodes);
    // Trials only serve challengers trailing the selection's completions.
    let seed = manager
        .feedback_for_node(
            nodes[0].id,
            crate::group::ScoreSelectionContext::aggregate(
                SelectionNetwork::Tcp,
                ProbeDomain::Tcp,
                IpVersion::V4,
            ),
        )
        .unwrap()
        .start();
    seed.setup_succeeded();
    seed.tx(1);
    seed.rx(1);
    seed.finish(crate::group::ScoreOutcome::Success);
    let context = tcp_score_context("192.0.2.1:443".parse().unwrap(), None, IpVersion::V4);
    let mut plan = manager.selection_plan_for_target("score", &context);
    let attempt = plan.entries[0].feedback.take().unwrap();
    drop(plan);
    assert!(attempt.continuation().is_err());
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .reserved,
        1
    );
    let warm = attempt.start_warmup(context.clone());
    warm.setup_succeeded();
    warm.tx(1);
    warm.rx(1);
    warm.finish(crate::group::ScoreOutcome::Success);
    let refill = warm.start_warmup(context);
    refill.setup_succeeded();
    refill.finish_setup_only();
    let counters = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(
        (
            counters.business_starts,
            counters.spent,
            counters.reserved,
            counters.refunded
        ),
        (0, 0, 0, 1)
    );
    assert_eq!(counters.cold_available, counters.cold_allowance);
    assert_eq!(manager.score_state().root_business_starts(), 0);
}

#[tokio::test]
async fn client_reset_preserves_score_availability_but_upstream_reset_revokes_target() {
    use crate::group::{ScoreOutcome, ScoreVerificationState};
    use std::sync::atomic::AtomicU64;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, server) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept(),
        );
        (client.unwrap(), server.unwrap().0)
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        for client_reset in [true, false] {
            let node = Node::from_share_link("socks5://127.0.0.1:1080#relay").unwrap();
            let group = honk_config::group::Group {
                name: "score".into(),
                policy: honk_config::group::GroupPolicy::Score,
                nodes: vec![node.id],
                ..Default::default()
            };
            let manager = crate::group::GroupManager::new(&[group], std::slice::from_ref(&node));
            let address = "127.0.0.1:443".parse().unwrap();
            let context = tcp_score_context(address, None, IpVersion::V4);
            let feedback = manager.feedback_for_node(node.id, context.clone()).unwrap();
            feedback.start().finish(ScoreOutcome::Timeout);
            for _ in 0..4 {
                let seed = feedback.start();
                seed.setup_succeeded();
                seed.tx(1);
                seed.rx(1);
                seed.finish(ScoreOutcome::Cancelled);
            }
            let snapshot = || {
                manager
                    .score_verification_for_network("score", SelectionNetwork::Tcp)
                    .unwrap()
                    .1
            };
            let before = snapshot();
            assert_eq!(before.state, ScoreVerificationState::ObservedUsable);
            drop(manager.selection_plan_for_target("score", &context));
            let before_counts = manager.score_verification_counters("score", SelectionNetwork::Tcp);
            assert_eq!(
                (
                    before_counts.usable_selections,
                    before_counts.provisional_selections
                ),
                (1, 0)
            );
            let reporter = feedback.start();
            reporter.setup_succeeded();
            let progress = relay::RelayProgress {
                upload: Arc::new(AtomicU64::new(0)),
                download: Arc::new(AtomicU64::new(0)),
                outbound_upload: None,
                outbound_download: None,
                first_response: Some(Arc::new({
                    let reporter = reporter.clone();
                    move || reporter.first_response()
                })),
                on_transfer: Some(Arc::new({
                    let reporter = reporter.clone();
                    move |up, down| {
                        reporter.tx(up);
                        reporter.rx(down);
                    }
                })),
            };
            let (mut client, relay_client) = pair().await;
            let (relay_upstream, mut upstream) = pair().await;
            let running = tokio::spawn(relay::splice::relay_auto(
                relay_client,
                relay_upstream,
                address,
                address,
                Some(progress),
            ));
            client.write_all(b"q").await.unwrap();
            assert_eq!(upstream.read_u8().await.unwrap(), b'q');
            upstream.write_all(b"r").await.unwrap();
            assert_eq!(client.read_u8().await.unwrap(), b'r');
            let reset = if client_reset { client } else { upstream };
            socket2::SockRef::from(&reset)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(reset);
            let error = running.await.unwrap().unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::ECONNRESET)
            );
            let outcome = tcp_relay_score_outcome(&error);
            assert_eq!(
                outcome,
                if client_reset {
                    ScoreOutcome::Cancelled
                } else {
                    ScoreOutcome::Io(std::io::ErrorKind::ConnectionReset)
                }
            );
            reporter.finish(outcome);
            let after = snapshot();
            // A target reset cannot erase the node's factual aggregate RX.
            assert_eq!(after.state, ScoreVerificationState::ObservedUsable);
            drop(manager.selection_plan_for_target("score", &context));
            let after_counts = manager.score_verification_counters("score", SelectionNetwork::Tcp);
            assert_eq!(
                (
                    after_counts.usable_selections - before_counts.usable_selections,
                    after_counts.provisional_selections - before_counts.provisional_selections,
                ),
                if client_reset { (1, 0) } else { (0, 1) },
                "only an upstream reset revokes observed usability for the next target flow"
            );
        }
    })
    .await
    .expect("reset must terminate the relay without waiting for idle cleanup");
}

#[tokio::test]
async fn sniff_prefix_reports_accepted_bytes_before_write_failure() {
    use tokio::io::AsyncReadExt;
    let (mut writer, mut reader) = tokio::io::duplex(3);
    let mut accepted = 0;
    let (result, ()) = tokio::join!(
        write_sniff_prefix(&mut writer, b"prefix", |bytes| accepted += bytes),
        async move {
            let mut prefix = [0; 3];
            reader.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"pre");
            drop(reader);
        },
    );
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(accepted, 3);
}

#[test]
fn tcp_score_context_uses_target_family_not_health_family() {
    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let context = tcp_score_context(target, Some("example.com"), IpVersion::V6);

    assert_eq!(context.target_family, Some(IpVersion::V4));
    assert_eq!(context.health_family, IpVersion::V6);
    assert_eq!(
        context.target,
        Some(crate::group::ScoreTarget::domain("example.com", 443))
    );
}

#[test]
fn unpack_tcp_score_plan_deduplicates_shared_leaf_metadata() {
    use crate::control::reload::{OutboundConstraint, resolve_outbound_plan_for_target};
    use honk_outbound::group::{DialKey, ScoreAttribution};

    let node = Node::from_share_link("socks5://127.0.0.1:1080#shared").unwrap();
    let exit = Node::from_share_link("socks5://127.0.0.1:1081#exit").unwrap();
    let mut groups = ["outer", "duplicate", "via"]
        .map(|name| Group {
            name: name.into(),
            policy: GroupPolicy::Score,
            final_outbound: Some("leaf".into()),
            exit: (name == "via").then(|| exit.name.clone()),
            ..Default::default()
        })
        .to_vec();
    groups.push(Group {
        name: "leaf".into(),
        policy: GroupPolicy::Score,
        nodes: vec![node.id],
        ..Default::default()
    });
    let config = Config {
        nodes: vec![node.clone(), exit.clone()],
        groups,
        ..Default::default()
    };
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let context = tcp_score_context("192.0.2.1:443".parse().unwrap(), None, IpVersion::V4);
    let resolve = |name| {
        resolve_outbound_plan_for_target(&config, &manager, name, &context, OutboundConstraint::Any)
    };
    let mut plan = resolve("outer");
    plan.mode = SelectionPlanMode::ColdUrlTest;
    for name in ["via", "duplicate"] {
        let mut extra = resolve(name);
        assert_eq!(extra.targets.len(), 1);
        plan.targets.append(&mut extra.targets);
        plan.feedback.append(&mut extra.feedback);
        plan.selection_chains.append(&mut extra.selection_chains);
        plan.final_owners.append(&mut extra.final_owners);
    }
    assert_eq!(plan.targets.len(), 3);
    let bare = DialKey::Node(node.id);
    assert_eq!(
        plan.targets[2].key(),
        bare,
        "fixture must repeat the bare key"
    );

    let (targets, mode, feedback, selection_chains, final_owners, family, _) =
        unpack_tcp_score_plan(plan);
    assert_eq!(targets.len(), 2);
    assert_eq!(mode, SelectionPlanMode::ColdUrlTest);
    assert_eq!(family, IpVersion::V4);
    assert_eq!(targets[0].key(), bare);
    let via = targets[1].key();
    let DialKey::Route(route) = via else {
        panic!("the same leaf through the exit must keep its own dial key");
    };
    assert_eq!(targets[1].node.id, node.id);
    assert_eq!(route.leaf(), node.id);
    assert_eq!(route.hops(), [node.id, exit.id]);

    assert_eq!(
        (feedback.len(), selection_chains.len(), final_owners.len()),
        (2, 2, 2)
    );
    for (key, root) in [(bare, "outer"), (via, "via")] {
        let attempt = &feedback[&key];
        assert_eq!(attempt.context(), &context);
        assert_eq!(
            attempt.attributions(),
            [root, "leaf"].map(|group| ScoreAttribution {
                group: group.into(),
                node_id: node.id,
            })
        );
        assert_eq!(selection_chains[&key], [root, "leaf", "shared"]);
        assert_eq!(final_owners[&key], [root]);
    }
}

#[test]
fn timeout_helper_finishes_started_reporter_before_abort_drop() {
    let nodes = [
        Node {
            id: uuid::Uuid::new_v4(),
            name: "a".into(),
            ..Default::default()
        },
        Node {
            id: uuid::Uuid::new_v4(),
            name: "b".into(),
            ..Default::default()
        },
    ];
    let group = honk_config::group::Group {
        name: "score".into(),
        policy: honk_config::group::GroupPolicy::Score,
        nodes: nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    };
    let manager = crate::group::GroupManager::new(&[group], &nodes);
    let context = tcp_score_context("192.0.2.1:443".parse().unwrap(), None, IpVersion::V4);
    let feedback = manager
        .feedback_for_node(nodes[0].id, context.clone())
        .unwrap();
    let reporters = parking_lot::Mutex::new(vec![(feedback.start(), false)]);
    timeout_started_score_reporters(&reporters);
    drop(reporters);

    assert_eq!(
        manager.selection_plan_for_target("score", &context).entries[0]
            .node
            .id,
        nodes[1].id
    );
}
