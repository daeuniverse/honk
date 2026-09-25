use super::*;
use anyhow::Context as _;

#[tokio::test]
async fn tcp_authoritative_dial_failure_retries_with_replacement() -> anyhow::Result<()> {
    loopback_recovery(honk_config::group::GroupPolicy::URLTest, false).await
}

#[tokio::test]
async fn tcp_score_recovers_while_failed_leaf_remains_ordinary_winner() -> anyhow::Result<()> {
    loopback_recovery(honk_config::group::GroupPolicy::Score, false).await
}

#[tokio::test]
async fn tcp_score_recovers_inside_previously_selected_nested_final() -> anyhow::Result<()> {
    loopback_recovery(honk_config::group::GroupPolicy::Score, true).await
}

#[tokio::test]
async fn cold_urltest_refunds_unscheduled_score_work_before_relay_closes() -> anyhow::Result<()> {
    use crate::group::SelectionNetwork;
    use honk_config::group::GroupPolicy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let target = listener.local_addr()?;
        let nodes: Vec<_> = (0..8)
            .map(|index| {
                let mut node = udp_test_node();
                node.name = format!("leaf-{index}");
                node.port += index;
                node.id = node.derive_id();
                node
            })
            .collect();
        let mut groups: Vec<_> = nodes
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
            .map(|(index, nodes)| Group {
                name: format!("child-{index}"),
                policy: GroupPolicy::Score,
                nodes: nodes.iter().map(|node| node.id).collect(),
                ..Default::default()
            })
            .collect();
        groups.push(Group {
            name: "cold".into(),
            policy: GroupPolicy::URLTest,
            groups: groups.iter().map(|group| group.name.clone()).collect(),
            ..Default::default()
        });
        let selections: Vec<_> = nodes.iter().step_by(2).map(|node| node.id).collect();
        let mut config = udp_test_config("cold", nodes, groups);
        config.global.dial_mode = "ip".into();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let handle = udp_test_handle(
            config,
            UdpTestMode::TcpHold {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
            1,
        );
        let manager = handle.group_manager.read().clone();
        // Trials only serve challengers trailing the selection's completions, so each child's
        // selection needs one before its sibling can hold cold work.
        for leaf in selections {
            let reporter = manager
                .feedback_for_node(
                    leaf,
                    crate::group::ScoreSelectionContext::aggregate(
                        SelectionNetwork::Tcp,
                        ProbeDomain::Tcp,
                        IpVersion::V4,
                    ),
                )
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(crate::group::ScoreOutcome::Success);
        }
        let counts = |group| manager.score_budget_counters(group, SelectionNetwork::Tcp);
        let mut client = TcpStream::connect(target).await?;
        let (accepted, client_addr) = listener.accept().await?;
        store_active_tcp_flow(&handle, target, client_addr).await?;
        let serving = {
            let handle = handle.clone();
            tokio::spawn(async move { handle.serve_connection(accepted, client_addr).await })
        };
        entered.notified().await;
        let (mut upstream, _) = listener.accept().await?;
        let truncated = counts("child-3");
        assert_eq!((truncated.reserved, truncated.refunded), (0, 1));
        assert_eq!(truncated.cold_available, truncated.cold_allowance);
        for group in ["child-1", "child-2"] {
            assert_eq!(counts(group).reserved, 1);
            assert_eq!(counts(group).business_starts, 0);
        }

        release.notify_one();
        client.write_all(b"q").await?;
        assert_eq!(upstream.read_u8().await?, b'q');
        upstream.write_all(b"r").await?;
        assert_eq!(client.read_u8().await?, b'r');
        assert!(
            !serving.is_finished(),
            "the winning relay must still be open"
        );
        assert_eq!(counts("child-0").business_starts, 1);
        for group in ["child-1", "child-2", "child-3"] {
            let refunded = counts(group);
            assert_eq!((refunded.reserved, refunded.refunded), (0, 1), "{group}");
            assert_eq!(
                (refunded.business_starts, refunded.spent),
                (0, 0),
                "{group}"
            );
            assert_eq!(refunded.cold_available, refunded.cold_allowance, "{group}");
        }
        drop(upstream);
        drop(client);
        serving.await??;
        let generation = handle.runtime_registry.read().clone();
        generation.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("cold URLTest ownership must settle before the live relay closes")?
}

async fn loopback_recovery(
    policy: honk_config::group::GroupPolicy,
    through_final: bool,
) -> anyhow::Result<()> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Echo listener: the FIRST accepted socket is the client flow handed to
    // serve_connection (its local_addr is the flow's original destination);
    // every later socket is the proxy's relayed connection and gets echoed.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?;
    let (flow_tx, flow_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut flow_tx = Some(flow_tx);
        while let Ok((mut stream, peer)) = listener.accept().await {
            if let Some(tx) = flow_tx.take() {
                let _ = tx.send((stream, peer));
                continue;
            }
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    // Minimal relaying SOCKS5 server: no auth, CONNECT to the requested
    // target, then pipe both ways.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let socks_addr = socks_listener.local_addr()?;
    let successful_dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let successful_dials_on_wire = Arc::clone(&successful_dials);
    let alternate_started = Arc::new(tokio::sync::Notify::new());
    let alternate_release = Arc::new(tokio::sync::Notify::new());
    let started_on_wire = Arc::clone(&alternate_started);
    let release_on_wire = Arc::clone(&alternate_release);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = socks_listener.accept().await {
            successful_dials_on_wire.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let started = Arc::clone(&started_on_wire);
            let release = Arc::clone(&release_on_wire);
            tokio::spawn(async move {
                started.notify_one();
                release.notified().await;
                let mut head = [0u8; 2];
                if stream.read_exact(&mut head).await.is_err() || head[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; head[1] as usize];
                if stream.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if stream.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }
                let mut req = [0u8; 4];
                if stream.read_exact(&mut req).await.is_err() || req[1] != 0x01 {
                    return;
                }
                let target = match req[3] {
                    0x01 => {
                        let mut rest = [0u8; 6];
                        if stream.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                        SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3])),
                            u16::from_be_bytes([rest[4], rest[5]]),
                        )
                    }
                    // The test dials only IPv4 literals.
                    _ => return,
                };
                let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {
                    return;
                };
                let _ = stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            });
        }
    });

    let socks_node = |name: &str, port: u16| {
        let mut node = Node {
            name: name.into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(
                honk_config::types::NodeProtocol::Socks5,
            ),
            address: "127.0.0.1".into(),
            port,
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    };
    let refused_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let node_a = socks_node("a", refused_listener.local_addr()?.port());
    let failed_dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let failed_dials_on_wire = Arc::clone(&failed_dials);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = refused_listener.accept().await {
            failed_dials_on_wire.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Refuse CONNECT, not the proxy handshake: the node and its
            // configured-probe evidence remain usable for other targets.
            let mut greeting = [0; 3];
            if stream.read_exact(&mut greeting).await.is_err()
                || stream.write_all(&[0x05, 0x00]).await.is_err()
            {
                continue;
            }
            let mut request = [0; 10];
            if stream.read_exact(&mut request).await.is_err() {
                continue;
            }
            let _ = stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
        }
    });
    let node_b = socks_node("b", socks_addr.port());
    let group = Group {
        name: "proxy".into(),
        policy,
        nodes: vec![node_a.id, node_b.id],
        ..Default::default()
    };
    let mut config = udp_test_config("proxy", vec![node_a.clone(), node_b.clone()], vec![group]);
    if through_final {
        config.groups.extend([
            Group {
                name: "via-final".into(),
                final_outbound: Some("proxy".into()),
                ..Default::default()
            },
            Group {
                name: "outer".into(),
                groups: vec!["via-final".into()],
                ..Default::default()
            },
        ]);
        config.routing.default_outbound = "outer".into();
    }
    config.global.dial_mode = "ip".into();
    config.global.max_concurrent_dials = 1;
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let handle = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap()
    .spawn_handle();

    // Warm URLTest measurements: a (1ms) wins over b (50ms).
    handle.alive_set.record_probe_latency(
        node_a.id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(1),
    );
    handle.alive_set.record_probe_latency(
        node_b.id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(50),
    );
    let gm = handle.group_manager.read().clone();
    if policy == honk_config::group::GroupPolicy::Score {
        train_score_setup(&gm, &node_a, &node_b, target);
    }
    {
        let gm = handle.group_manager.read().clone();
        let plan = gm.selection_plan_for_domain("proxy", ProbeDomain::Tcp, IpVersion::V4);
        assert_eq!(plan.nodes.first().map(|n| n.name.as_str()), Some("a"));
    }

    let mut client = tokio::net::TcpStream::connect(target).await?;
    let (flow_stream, client_addr) = flow_rx.await.expect("listener hands the flow over");
    store_active_tcp_flow(&handle, target, client_addr).await?;
    let serve = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.serve_connection(flow_stream, client_addr).await })
    };

    let payload = b"retry-with-replacement";
    client.write_all(payload).await?;
    tokio::time::timeout(Duration::from_secs(5), alternate_started.notified())
        .await
        .context("replacement did not reach its peer")?;
    if policy == honk_config::group::GroupPolicy::Score {
        assert_eq!(
            gm.get_score_selection_for_network("proxy", crate::group::SelectionNetwork::Tcp),
            Some(node_a.name.clone()),
            "A must remain the ordinary winner after its failed setup"
        );
        let context = crate::group::ScoreSelectionContext {
            target: Some(target.into()),
            target_family: Some(IpVersion::V4),
            ..crate::group::ScoreSelectionContext::aggregate(
                crate::group::SelectionNetwork::Tcp,
                ProbeDomain::Tcp,
                IpVersion::V4,
            )
        };
        let ordinary = gm.selection_plan_for_target("proxy", &context);
        assert_eq!(
            ordinary.entries.first().map(|entry| entry.node.id),
            Some(node_a.id),
            "replacement must exclude A even when ordinary target selection still prefers it"
        );
    }
    alternate_release.notify_one();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
        .await
        .context("replacement did not relay the client payload")??;
    assert_eq!(
        echoed, payload,
        "the flow must succeed through the replacement"
    );
    if policy == honk_config::group::GroupPolicy::Score {
        assert_eq!(failed_dials.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(
            successful_dials.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    } else {
        assert!(
            handle
                .alive_set
                .is_failure_demoted(node_a.id, ProbeDomain::Tcp, IpVersion::V4)
        );
    }
    client.shutdown().await?;
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), serve)
        .await
        .context("replacement flow did not close")???;
    let generation = handle.runtime_registry.read().clone();
    let permit =
        tokio::time::timeout(Duration::from_millis(100), generation.acquire_dial_permit()).await?;
    drop(permit);
    assert!(
        !handle
            .alive_set
            .is_failure_demoted(node_b.id, ProbeDomain::Tcp, IpVersion::V4),
        "the replacement node must stay clean"
    );
    Ok(())
}

fn train_score_setup(
    manager: &honk_outbound::group::GroupManager,
    preferred: &Node,
    alternate: &Node,
    target: SocketAddr,
) {
    use crate::group::{ScoreSelectionContext, ScoreSource, SelectionNetwork};
    let context = ScoreSelectionContext {
        target: Some(target.into()),
        target_family: Some(IpVersion::V4),
        ..ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4)
    };
    // The probe prefers `preferred`; the alternate's unanswered response question would take the
    // first flow as a trial if its completions trailed the selection's.
    for (node, successes, latency) in [(preferred, 1000, 1), (alternate, 1010, 500)] {
        let feedback = manager.feedback_for_node(node.id, context.clone()).unwrap();
        for _ in 0..successes {
            let reporter = feedback.start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(crate::group::ScoreOutcome::Success);
        }
        for _ in 0..4 {
            let reporter = feedback
                .clone()
                .with_source(ScoreSource::HealthProbe)
                .start();
            reporter.probe_latency(Duration::from_millis(latency));
            reporter.finish_setup_only();
        }
    }
}

#[derive(Debug)]
struct HeldSetup {
    attempts: tokio::sync::mpsc::UnboundedSender<uuid::Uuid>,
    release: Arc<tokio::sync::Notify>,
    refusal: Option<honk_outbound::proxy::PacketRejection>,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for HeldSetup {
    async fn dial(
        &self,
        node: &Node,
        _target: SocketAddr,
        _domain: Option<&str>,
        _timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        self.attempts.send(node.id).unwrap();
        if node.name == "a" {
            self.release.notified().await;
            if let Some(refusal) = self.refusal {
                return Err(refusal.into());
            }
            return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into());
        }
        std::future::pending().await
    }
}

fn held_score_handle(
    refusal: Option<honk_outbound::proxy::PacketRejection>,
    constrained: bool,
    urltest: bool,
) -> (
    ControlPlaneHandle,
    Vec<Node>,
    Arc<tokio::sync::Notify>,
    tokio::sync::mpsc::UnboundedReceiver<uuid::Uuid>,
) {
    use honk_config::group::GroupPolicy;
    let nodes: Vec<_> = ["a", "b"]
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            let mut node = udp_test_node();
            node.name = name.into();
            node.port += index as u16;
            node.id = node.derive_id();
            node
        })
        .collect();
    let mut groups = vec![Group {
        name: "proxy".into(),
        policy: GroupPolicy::Score,
        nodes: nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    }];
    if constrained {
        groups[0].nodes = vec![nodes[0].id, nodes[0].id];
        groups[0].groups = vec!["pinned".into()];
        groups[0].final_outbound = Some("direct".into());
        groups.push(Group {
            name: "pinned".into(),
            policy: GroupPolicy::Selector,
            nodes: nodes.iter().map(|node| node.id).collect(),
            default: Some("a".into()),
            ..Default::default()
        });
    }
    let mut config = udp_test_config("proxy", nodes.clone(), groups);
    if urltest {
        config.groups.push(Group {
            name: "alternate".into(),
            policy: GroupPolicy::Score,
            nodes: vec![nodes[1].id],
            ..Default::default()
        });
        config.groups.push(Group {
            name: "outer".into(),
            policy: GroupPolicy::URLTest,
            groups: vec!["proxy".into(), "alternate".into()],
            ..Default::default()
        });
        config.routing.default_outbound = "outer".into();
    }
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.connect_timeout_ms = 4000;
    config.global.max_concurrent_dials = 1;
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let (attempts, receiver) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let mut registry = ProxyRegistry::new();
    let handler = Arc::new(HeldSetup {
        attempts,
        release: Arc::clone(&release),
        refusal,
    });
    registry.register(honk_outbound::proxy::ProtocolEntry::new(
        honk_config::types::NodeProtocol::Socks5,
        handler.clone(),
    ));
    registry.register(honk_outbound::proxy::ProtocolEntry::new(
        honk_config::types::NodeProtocol::Direct,
        handler,
    ));
    let handle = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap()
    .spawn_handle();
    (handle, nodes, release, receiver)
}

async fn start_held_flow(
    handle: &ControlPlaneHandle,
    nodes: &[Node],
) -> anyhow::Result<(TcpStream, tokio::task::JoinHandle<anyhow::Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?;
    let client = TcpStream::connect(target).await?;
    let (accepted, peer) = listener.accept().await?;
    store_active_tcp_flow(handle, target, peer).await?;
    train_score_setup(&handle.group_manager.read(), &nodes[0], &nodes[1], target);
    let handle = handle.clone();
    Ok((
        client,
        tokio::spawn(async move { handle.serve_connection(accepted, peer).await }),
    ))
}

#[tokio::test(start_paused = true)]
async fn tcp_score_alternate_shares_primary_absolute_deadline() -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    let (handle, nodes, release, mut attempts) = held_score_handle(None, false, false);
    let (mut client, mut serve) = start_held_flow(&handle, &nodes).await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), attempts.recv())
            .await
            .context("primary setup did not start")?,
        Some(nodes[0].id)
    );
    tokio::time::advance(Duration::from_secs(8)).await;
    release.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), attempts.recv())
            .await
            .context("alternate setup did not start")?,
        Some(nodes[1].id)
    );
    tokio::time::advance(Duration::from_secs(8)).await;
    tokio::time::timeout(Duration::from_millis(1), &mut serve).await???;
    assert_eq!(client.read(&mut [0; 1]).await?, 0);
    assert!(attempts.try_recv().is_err(), "never admit a third leaf");
    Ok(())
}

#[tokio::test]
async fn tcp_score_refusal_and_retirement_do_not_retry() -> anyhow::Result<()> {
    use honk_outbound::proxy::PacketRejection;
    for refusal in [
        Some(PacketRejection::Policy),
        Some(PacketRejection::Capacity),
        Some(PacketRejection::Cancelled),
        None,
    ] {
        let (handle, nodes, release, mut attempts) = held_score_handle(refusal, false, false);
        let (_client, serve) = start_held_flow(&handle, &nodes).await?;
        assert_eq!(attempts.recv().await, Some(nodes[0].id));
        if refusal.is_none() {
            handle.runtime_registry.read().begin_retirement();
        }
        release.notify_one();
        let error = tokio::time::timeout(Duration::from_secs(1), serve)
            .await??
            .unwrap_err();
        if let Some(refusal) = refusal {
            assert_eq!(
                honk_outbound::proxy::packet_rejection(&error),
                Some(refusal)
            );
        }
        assert!(attempts.try_recv().is_err());
        assert!(
            handle
                .alive_set
                .is_alive_for(nodes[0].id, ProbeDomain::Tcp, IpVersion::V4)
        );
    }
    Ok(())
}

#[tokio::test]
async fn tcp_score_exhaustion_cannot_escape_selector_or_synthesize_final() -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    let (handle, nodes, release, mut attempts) = held_score_handle(None, true, false);
    let (mut client, serve) = start_held_flow(&handle, &nodes).await?;
    assert_eq!(attempts.recv().await, Some(nodes[0].id));
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), serve).await???;
    assert_eq!(client.read(&mut [0; 1]).await?, 0);
    assert!(
        attempts.try_recv().is_err(),
        "duplicate A and unchosen B are not alternates"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn tcp_urltest_retry_after_deadline_preserves_original_business() -> anyhow::Result<()> {
    use crate::group::SelectionNetwork;
    let (handle, nodes, release, mut attempts) = held_score_handle(None, false, true);
    for (index, node) in nodes.iter().enumerate() {
        handle.alive_set.record_probe_latency(
            node.id,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(1 + index as u64 * 50),
        );
    }
    let (_client, serve) = start_held_flow(&handle, &nodes).await?;
    assert_eq!(attempts.recv().await, Some(nodes[0].id));
    let manager = handle.group_manager.read().clone();
    let before = manager.score_budget_counters("proxy", SelectionNetwork::Tcp);
    let root_before = manager.score_state().root_business_starts();
    // Jump past the absolute deadline without polling the earlier per-dial timer.
    tokio::time::advance(Duration::from_secs(17)).await;
    release.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), attempts.recv()).await?,
        Some(nodes[1].id)
    );
    let after = manager.score_budget_counters("proxy", SelectionNetwork::Tcp);
    assert_eq!(manager.score_state().root_business_starts(), root_before);
    assert_eq!(after.business_starts, before.business_starts);
    serve.abort();
    let _ = serve.await;
    Ok(())
}

#[tokio::test]
async fn tcp_urltest_retry_after_score_reload_still_reaches_alternate() -> anyhow::Result<()> {
    use crate::group::SelectionNetwork;
    let (handle, nodes, release, mut attempts) = held_score_handle(None, false, true);
    for (index, node) in nodes.iter().enumerate() {
        handle.alive_set.record_probe_latency(
            node.id,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(1 + index as u64 * 50),
        );
    }
    let (_client, serve) = start_held_flow(&handle, &nodes).await?;
    assert_eq!(attempts.recv().await, Some(nodes[0].id));
    let manager = handle.group_manager.read().clone();
    let replacement = {
        let config = handle.config.read().await;
        GroupManager::with_alive_set_and_score_state(
            &config.groups,
            &config.nodes,
            Some(Arc::clone(&handle.alive_set)),
            manager.score_state(),
        )
    };
    replacement.publish_score_membership();
    let before = replacement.score_budget_counters("proxy", SelectionNetwork::Tcp);
    let root_before = replacement.score_state().root_business_starts();
    release.notify_one();
    let reached = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(node) = attempts.recv().await {
            if node == nodes[1].id {
                return true;
            }
            assert_eq!(node, nodes[0].id);
            release.notify_one();
        }
        false
    })
    .await?;
    assert!(
        reached,
        "Score authority replacement must not cancel an ordinary retry on the admitted generation"
    );
    assert_eq!(
        replacement.score_state().root_business_starts(),
        root_before
    );
    assert_eq!(
        replacement.score_budget_counters("proxy", SelectionNetwork::Tcp),
        before
    );
    serve.abort();
    let _ = serve.await;
    Ok(())
}
