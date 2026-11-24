use super::support::{
    UdpTestHandler, UdpTestMode, canonical_socks5, control_plane, score_reload_config,
};
use crate::control::{
    ControlPlane, drain::DrainTracker, probers::UdpDnsProbeTarget, reload::sync_health_check_nodes,
};
use honk_config::{Config, node::Node, parser::parse_dae_config, types::NodeProtocol};
use honk_outbound::alive::{
    AliveDialerSet, HttpProbeOutcome, HttpProbeResult, HttpProber, IpVersion, ProbeDomain,
    UdpProber,
};
use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry, ProxyStream, TcpOutbound};
use parking_lot::Mutex;
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[cfg(feature = "clash-api")]
mod clash_delay;

#[derive(Debug)]
struct DirectConnectHandler;

#[async_trait::async_trait]
impl TcpOutbound for DirectConnectHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        Ok(ProxyStream {
            stream: Box::new(tokio::time::timeout(timeout, TcpStream::connect(target)).await??),
            target_addr: target,
            target_domain: domain.map(str::to_owned),
        })
    }
}

struct PeriodProbe(tokio::sync::mpsc::UnboundedSender<tokio::time::Instant>);
impl HttpProber for PeriodProbe {
    fn probe_http(
        &self,
        _: uuid::Uuid,
        _: SocketAddr,
        _: &str,
        _: Duration,
        _cancel: honk_outbound::alive::ProbeCancellation,
    ) -> Pin<Box<dyn Future<Output = HttpProbeOutcome> + Send + 'static>> {
        let _ = self.0.send(tokio::time::Instant::now());
        Box::pin(async { HttpProbeResult::WarmSuccess(Duration::from_millis(1)).into() })
    }
}

#[tokio::test]
async fn raw_health_only_skips_virtual_chains() {
    let mut config = Config::from_json_str(
        r#"{
            "global": { "tcp_check_url": [] },
            "nodes": [
                { "name": "front", "protocol": "socks5", "address": "", "host": "127.0.0.1", "port": 1080 },
                { "name": "land", "protocol": "socks5", "address": "", "host": "::1", "port": 1080 }
            ]
        }"#,
    )
    .unwrap();
    let via = Node::chain_from_nodes("via", &[&config.nodes[0], &config.nodes[1]]).unwrap();
    let chain_id = via.id;
    config.nodes.push(via);
    config.validate_assembled().unwrap();
    assert!(config.nodes.iter().all(|node| node.address.is_empty()));

    for check_url in [None, Some("")] {
        let alive = Arc::new(AliveDialerSet::new());
        let (http_attempts, mut probed) = tokio::sync::mpsc::unbounded_channel();
        if let Some(url) = check_url {
            alive
                .set_http_probe(
                    Arc::new(PeriodProbe(http_attempts)),
                    url.into(),
                    "HEAD".into(),
                )
                .await;
        }
        alive.set_resolver(Arc::new(|host, port| {
            assert_eq!((host.as_str(), port), ("", 80));
            // Give the legacy empty-address lookup two local, unusable endpoints.
            Box::pin(async {
                Ok(vec![
                    "127.0.0.1:0".parse().unwrap(),
                    "[::1]:0".parse().unwrap(),
                ])
            })
        }));
        assert_eq!(sync_health_check_nodes(&alive, &config), (3, 0));
        assert_eq!(sync_health_check_nodes(&alive, &config), (0, 0));

        alive
            .run_health_check_cycle_concurrent(Duration::from_secs(1), 1)
            .await;
        assert!(probed.try_recv().is_err());
        for family in [IpVersion::V4, IpVersion::V6] {
            assert!(alive.is_alive_for(chain_id, ProbeDomain::Tcp, family));
            assert!(
                alive
                    .get_probe_history(chain_id, ProbeDomain::Tcp, family)
                    .is_empty()
            );
            for node in &config.nodes[..2] {
                let history = alive.get_probe_history(node.id, ProbeDomain::Tcp, family);
                assert_eq!(history.len(), 1, "{} {family:?} {check_url:?}", node.name);
                assert!(!history[0].success);
            }
        }
    }
}

fn health_config(url: String) -> Config {
    let mut config = score_reload_config(50);
    config.global.nfqueue_enable = false;
    config.global.check_interval_secs = 30;
    config.global.tcp_check_url = vec![url];
    config.global.tcp_check_http_method = "HEAD".into();
    config
}

#[tokio::test(start_paused = true)]
async fn c28_health_reload_retains_old_period_after_rejection() {
    let old = health_config("http://127.0.0.1:18080/".into());
    let cp = control_plane(old.clone());
    let alive = cp.alive_set();
    let (calls, mut observations) = tokio::sync::mpsc::unbounded_channel();
    alive
        .set_http_probe(
            Arc::new(PeriodProbe(calls)),
            old.global.tcp_check_url[0].clone(),
            "HEAD".into(),
        )
        .await;
    // Measure the period alone: without idle suspension, and without the
    // wake-up probes that marking the group active would queue.
    alive.sync_idle_groups(&[]);
    let task = alive.spawn_health_check_loop(Duration::from_secs(30), Duration::from_secs(1));
    let first = observations.recv().await.unwrap();
    // Both registered leaves are probed in each cycle.
    observations.recv().await.unwrap();
    let mut candidate = old.clone();
    candidate.global.check_interval_secs = 60;
    assert!(
        !cp.reload_runtime_config(candidate, Default::default())
            .await
    );
    assert_eq!(
        observations.recv().await.unwrap() - first,
        Duration::from_secs(30)
    );
    assert_eq!(cp.config_handle().read().await.as_ref(), &old);
    alive.shutdown_health_checks().await.unwrap();
    task.await.unwrap();
}

async fn http_fixture() -> (
    ControlPlane,
    Arc<Mutex<Vec<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old = health_config(format!(
        "http://127.0.0.1:{}/old-path?old=1",
        listener.local_addr().unwrap().port()
    ));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let observed = observed.clone();
            tokio::spawn(async move {
                let mut stream = BufReader::new(stream);
                loop {
                    let mut request = String::new();
                    while !request.ends_with("\r\n\r\n") {
                        match stream.read_line(&mut request).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                    observed.lock().push(request);
                    if stream
                        .get_mut()
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    let cp = control_plane(old.clone());
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(
        NodeProtocol::Socks5,
        Arc::new(DirectConnectHandler),
    ));
    let prober = Arc::new(crate::control::probers::http::ProxyHttpProber::new(
        cp.config_handle(),
        Arc::new(registry),
        cp.runtime_registry(),
        "HEAD".into(),
        cp.group_manager(),
    ));
    cp.alive_set()
        .set_http_probe(prober, old.global.tcp_check_url[0].clone(), "HEAD".into())
        .await;
    (cp, requests, task)
}

async fn reject_http_change(change: fn(&mut Config)) {
    let (cp, requests, task) = http_fixture().await;
    let old = cp.config_handle().read().await.clone();
    let mut candidate = old.as_ref().clone();
    change(&mut candidate);
    assert!(
        !cp.reload_runtime_config(candidate, Default::default())
            .await
    );
    cp.alive_set().mark_group_active("score");
    cp.alive_set()
        .run_health_check_cycle(Duration::from_secs(1))
        .await;
    assert_eq!(cp.config_handle().read().await.as_ref(), old.as_ref());
    let requests = requests.lock();
    assert!(!requests.is_empty(), "real HTTP probe made no request");
    assert!(
        requests
            .iter()
            .all(|request| request.starts_with("HEAD /old-path?old=1 HTTP/1.1"))
    );
    task.abort();
}

#[tokio::test]
async fn c28_first_http_url_rejection_retains_installed_request() {
    reject_http_change(|config| {
        config.global.tcp_check_url[0] = "http://127.0.0.1:1/new-path?new=1".into()
    })
    .await;
}

#[tokio::test]
async fn c28_http_method_rejection_retains_installed_request() {
    reject_http_change(|config| config.global.tcp_check_http_method = "GET".into()).await;
}

#[tokio::test]
async fn c28_tls_rejection_retains_consumer_mode() {
    honk_outbound::tls::set_tls_mode("tls");
    reject_http_change(|config| config.global.tls_implementation = "utls".into()).await;
    assert!(!honk_outbound::tls::chrome_mode());
}

#[tokio::test]
async fn c28_effectively_equal_health_inputs_remain_admissible() {
    for change in [
        |config: &mut Config| config.global.tcp_check_http_method.clear(),
        |config: &mut Config| {
            config
                .global
                .tcp_check_url
                .push("http://127.0.0.1:1/later".into())
        },
        |config: &mut Config| config.global.tls_implementation = "TLS".into(),
        |config: &mut Config| config.global.utls_imitate = "firefox".into(),
    ] {
        let old = health_config("http://127.0.0.1:18080/".into());
        let cp = control_plane(old.clone());
        let mut candidate = old;
        change(&mut candidate);
        assert!(
            cp.reload_runtime_config(candidate.clone(), Default::default())
                .await
        );
        assert_eq!(cp.config_handle().read().await.as_ref(), &candidate);
    }
    let mut old = health_config(String::new());
    let cp = control_plane(old.clone());
    old.global.tcp_check_url.clear();
    old.global.tcp_check_http_method = "POST".into();
    assert!(cp.reload_runtime_config(old, Default::default()).await);
}

#[tokio::test]
async fn c28_udp_reload_preserves_the_configured_probe_target() {
    for (old_raw, new_raw, expected_target, should_accept) in [
        (
            "127.0.0.1:5301",
            vec!["127.0.0.1:5302"],
            "127.0.0.1:5301",
            false,
        ),
        (
            "",
            vec!["8.8.8.8:53", "unused.example:5302"],
            "8.8.8.8:53",
            true,
        ),
        (
            "old.example:5301",
            vec!["new.example:5301"],
            "127.0.0.1:5301",
            false,
        ),
        (
            "OLD.example.:5301",
            vec!["old.example:5301"],
            "127.0.0.1:5301",
            true,
        ),
        (
            "127.0.0.1:5301",
            vec!["unused.example", " 127.0.0.1:5301 ", "127.0.0.1:5302"],
            "127.0.0.1:5301",
            true,
        ),
    ] {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&resolver_calls);
        let resolver: crate::outbound::ResolveHook = Arc::new(move |_host, port| {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]) })
        });
        let node = canonical_socks5("c28-udp", "127.0.0.1", 9, None);
        let mut config = Config::default();
        config.global.nfqueue_enable = false;
        config.global.udp_check_dns = Some(vec![old_raw.into()]);
        config.nodes = vec![node.clone()];
        let dns_probe = UdpDnsProbeTarget::new(
            config.global.effective_udp_check_dns().to_vec(),
            Some(resolver.clone()),
        );
        dns_probe.resolve().await.unwrap();
        let cp = control_plane(config.clone());
        cp.alive_set().set_resolver(resolver);
        let calls_before = resolver_calls.load(Ordering::SeqCst);
        let capture = Arc::new(Mutex::new(None));
        let handler = Arc::new(UdpTestHandler {
            mode: UdpTestMode::DnsResponseCaptureTarget(Arc::clone(&capture)),
        });
        let mut registry = ProxyRegistry::new();
        registry.register(
            honk_outbound::proxy::ProtocolEntry::new(node.protocol(), handler.clone())
                .with_packet(handler),
        );
        let prober = crate::control::probers::ProxyUdpProber::new(
            cp.config_handle(),
            Arc::new(registry),
            cp.runtime_registry(),
            cp.stats_handle(),
            dns_probe,
            None,
            cp.group_manager(),
        );
        let generation = cp.runtime_registry().read().generation();
        let mut candidate = config.clone();
        candidate.global.udp_check_dns = Some(new_raw.into_iter().map(str::to_owned).collect());
        let accepted = cp
            .apply_runtime_config(candidate.clone(), Default::default(), &DrainTracker::new())
            .await
            .accepted();
        let outcome =
            UdpProber::probe_udp(&prober, node.id, Duration::from_secs(1), Default::default())
                .await;
        assert!(matches!(outcome.dns, Some(Ok(_))), "{outcome:?}");
        assert_eq!(
            *capture.lock(),
            Some(expected_target.parse::<SocketAddr>().unwrap()),
        );
        assert_eq!(resolver_calls.load(Ordering::SeqCst), calls_before);
        assert_eq!(accepted, should_accept, "configured UDP target: {old_raw}");
        assert_eq!(
            cp.config_handle().read().await.as_ref(),
            if should_accept { &candidate } else { &config },
        );
        if !should_accept {
            assert_eq!(cp.runtime_registry().read().generation(), generation);
        }
    }
}

fn udp_dns_prober(
    cp: &ControlPlane,
    node: &Node,
    dns_probe: UdpDnsProbeTarget,
    mode: UdpTestMode,
) -> Arc<crate::control::probers::ProxyUdpProber> {
    let handler = Arc::new(UdpTestHandler { mode });
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(node.protocol(), handler.clone()).with_packet(handler));
    Arc::new(crate::control::probers::ProxyUdpProber::new(
        cp.config_handle(),
        Arc::new(registry),
        cp.runtime_registry(),
        cp.stats_handle(),
        dns_probe,
        None,
        cp.group_manager(),
    ))
}

#[tokio::test]
async fn udp_dns_target_recovers_after_capacity_refusal_and_pins_success() {
    let node = canonical_socks5("udp-resolver-recovery", "127.0.0.1", 9, None);
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.global.udp_check_dns = Some(vec!["resolver.example:5301".into()]);
    config.nodes = vec![node.clone()];
    let capacity = Arc::new(tokio::sync::Semaphore::new(1));
    let held = capacity.clone().acquire_owned().await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver: crate::outbound::ResolveHook = {
        let capacity = capacity.clone();
        let calls = calls.clone();
        Arc::new(move |host, port| {
            assert_eq!(host, "resolver.example");
            calls.fetch_add(1, Ordering::SeqCst);
            let capacity = capacity.clone();
            Box::pin(async move {
                let _permit = capacity.try_acquire_owned().map_err(|_| {
                    anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                })?;
                Ok(vec![SocketAddr::from(([127, 0, 0, 2], port))])
            })
        })
    };
    let dns_probe = UdpDnsProbeTarget::new(
        config.global.effective_udp_check_dns().to_vec(),
        Some(resolver),
    );
    let startup_error = dns_probe.resolve().await.unwrap_err();
    assert!(honk_outbound::proxy::is_packet_rejection(&startup_error));
    let cp = control_plane(config);
    let capture = Arc::new(Mutex::new(None));
    let prober = udp_dns_prober(
        &cp,
        &node,
        dns_probe,
        UdpTestMode::DnsResponseCaptureTarget(capture.clone()),
    );
    let alive = cp.alive_set();
    alive.register_node(node.id, node.name.clone(), Some("127.0.0.1:9".into()));
    alive.set_udp_probe(prober);

    assert!(!alive.probe_node_udp(node.id, Duration::from_secs(1)).await);
    assert!(
        !alive.has_udp_state(node.id),
        "local refusal is not node evidence"
    );
    assert_eq!(
        *capture.lock(),
        None,
        "refusal must not dial a default target"
    );

    drop(held);
    assert!(alive.probe_node_udp(node.id, Duration::from_secs(1)).await);
    let expected = Some("127.0.0.2:5301".parse::<SocketAddr>().unwrap());
    assert_eq!(*capture.lock(), expected);
    for domain in [ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
        assert!(alive.is_alive_for(node.id, domain, IpVersion::V4));
    }

    let _held_again = capacity.acquire_owned().await.unwrap();
    *capture.lock() = None;
    assert!(alive.probe_node_udp(node.id, Duration::from_secs(1)).await);
    assert_eq!(*capture.lock(), expected);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "successful target stays pinned"
    );
}

#[tokio::test(start_paused = true)]
async fn udp_dns_initialization_timeout_is_neutral_and_retryable() {
    let node = canonical_socks5("udp-resolver-timeout", "127.0.0.1", 9, None);
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.nodes = vec![node.clone()];
    let calls = Arc::new(AtomicUsize::new(0));
    let capacity = Arc::new(tokio::sync::Semaphore::new(1));
    let resolver: crate::outbound::ResolveHook = {
        let calls = calls.clone();
        let capacity = capacity.clone();
        Arc::new(move |_, port| {
            let attempt = calls.fetch_add(1, Ordering::SeqCst);
            let capacity = capacity.clone();
            Box::pin(async move {
                let _permit = capacity.acquire_owned().await.unwrap();
                if attempt == 0 {
                    std::future::pending::<()>().await;
                }
                Ok(vec![SocketAddr::from(([127, 0, 0, 3], port))])
            })
        })
    };
    let cp = control_plane(config);
    let capture = Arc::new(Mutex::new(None));
    let prober = udp_dns_prober(
        &cp,
        &node,
        UdpDnsProbeTarget::new(vec!["resolver.example:5301".into()], Some(resolver)),
        UdpTestMode::DnsResponseCaptureTarget(capture.clone()),
    );
    let alive = cp.alive_set();
    alive.register_node(node.id, node.name.clone(), Some("127.0.0.1:9".into()));
    alive.set_udp_probe(prober);
    assert!(
        !tokio::time::timeout(
            Duration::from_secs(1),
            alive.probe_node_udp(node.id, Duration::from_millis(50)),
        )
        .await
        .expect("DNS initialization must honor the probe deadline")
    );
    assert!(
        !alive.has_udp_state(node.id),
        "local resolution timeout is neutral"
    );
    assert_eq!(*capture.lock(), None);
    assert_eq!(
        capacity.available_permits(),
        1,
        "timed-out resolver was cancelled"
    );

    assert!(
        alive
            .probe_node_udp(node.id, Duration::from_millis(50))
            .await
    );
    assert_eq!(*capture.lock(), Some("127.0.0.3:5301".parse().unwrap()));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn udp_dns_resolution_and_transport_share_one_deadline() {
    let node = canonical_socks5("udp-shared-deadline", "127.0.0.1", 9, None);
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.nodes = vec![node.clone()];
    let resolver: crate::outbound::ResolveHook = Arc::new(|_, port| {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
        })
    });
    let cp = control_plane(config);
    let entered = Arc::new(tokio::sync::Notify::new());
    let prober = udp_dns_prober(
        &cp,
        &node,
        UdpDnsProbeTarget::new(vec!["resolver.example:5301".into()], Some(resolver)),
        UdpTestMode::Hold {
            entered: entered.clone(),
            release: Arc::new(tokio::sync::Notify::new()),
        },
    );
    let start = tokio::time::Instant::now();
    let outcome = prober
        .probe_udp(
            node.id,
            Duration::from_millis(50),
            honk_outbound::alive::ProbeCancellation::default(),
        )
        .await;
    assert!(matches!(outcome.dns, Some(Err(_))), "{outcome:?}");
    assert!(outcome.data_path.is_none());
    assert!(
        start.elapsed() <= Duration::from_millis(51),
        "DNS setup reset the transport budget"
    );
    tokio::time::timeout(Duration::from_millis(1), entered.notified())
        .await
        .expect("transport must start after resolution");
}

fn dae_urltest_config(tolerance_ms: u64) -> Config {
    parse_dae_config(&format!(
        "global {{\n    nfqueue_enable: false\n    check_tolerance: {tolerance_ms}ms\n}}\n\
         node {{\n    a: 'socks5://127.0.0.1:1080'\n    b: 'socks5://127.0.0.1:1081'\n}}\n\
         group {{\n    url {{\n        filter: name('a')\n        filter: name('b')\n        policy: urltest\n    }}\n}}\n"
    ))
    .expect("valid dae URLTest fixture")
}

#[tokio::test]
async fn c28_dae_tolerance_reload_changes_real_urltest_selection() {
    let config = dae_urltest_config(100);
    let a_id = config
        .nodes
        .iter()
        .find(|node| node.name == "a")
        .unwrap()
        .id;
    let b_id = config
        .nodes
        .iter()
        .find(|node| node.name == "b")
        .unwrap()
        .id;
    let cp = control_plane(config);
    let alive = cp.alive_set();
    // Establish the incumbent through the real URLTest policy before the
    // challenger has a measurement.
    alive.record_probe_latency(
        a_id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    assert_eq!(
        cp.group_manager()
            .read()
            .select_node_for_domain("url", ProbeDomain::Tcp, IpVersion::V4)
            .unwrap()
            .name,
        "a"
    );
    // The challenger is now faster, but the old 100ms tolerance retains a.
    alive.record_probe_latency(
        b_id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(60),
    );
    assert_eq!(
        cp.group_manager()
            .read()
            .select_node_for_domain("url", ProbeDomain::Tcp, IpVersion::V4)
            .unwrap()
            .name,
        "a"
    );

    let candidate = dae_urltest_config(10);
    let accepted = cp
        .apply_runtime_config(candidate, Default::default(), &DrainTracker::new())
        .await
        .accepted();
    assert!(accepted, "dae tolerance-only reload must remain admissible");
    assert_eq!(
        cp.group_manager()
            .read()
            .select_node_for_domain("url", ProbeDomain::Tcp, IpVersion::V4)
            .unwrap()
            .name,
        "b",
        "the live URLTest policy must apply the adapted global tolerance"
    );
}

fn loopback_node(name: &str, port: u16, outbound: honk_config::node::OutboundConfig) -> Node {
    let mut node = Node {
        name: name.into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        outbound,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

/// Every failed route gets a fresh carrier. Existing siblings must still deliver
/// through the same framing node after fifty independent truncated responses.
#[tokio::test]
async fn fifty_ambiguous_udp_closures_preserve_sibling_route_and_bare_exit() {
    use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
    use tokio::io::AsyncReadExt;

    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = server.local_addr().unwrap().port();
    let (accepted_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = server.accept().await {
            if accepted_tx.send(stream).is_err() {
                break;
            }
        }
    });
    let relay = crate::test_support::socks5_relay().await;
    let front = loopback_node(
        "front",
        relay.addr.port(),
        honk_config::node::OutboundConfig::Socks5(Default::default()),
    );
    let sibling_relay = crate::test_support::socks5_relay().await;
    let sibling = loopback_node(
        "other-front",
        sibling_relay.addr.port(),
        honk_config::node::OutboundConfig::Socks5(Default::default()),
    );
    let land = loopback_node(
        "land",
        server_port,
        honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            password: Some("secret".into()),
            ..Default::default()
        }),
    );
    let chain = Node::chain_from_nodes("configured", &[&sibling, &land]).unwrap();
    let configured_id = chain.id;
    let mut config = Config {
        nodes: vec![front.clone(), sibling.clone(), land.clone(), chain],
        groups: [
            ("g", front.id, Some(land.name.clone())),
            ("sibling", sibling.id, Some(land.name.clone())),
            ("bare-exit", land.id, None),
            ("via-chain", configured_id, None),
        ]
        .map(|(name, member, exit)| honk_config::group::Group {
            name: name.into(),
            nodes: vec![member],
            exit,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    config.ensure_builtin_nodes();
    config.global.nfqueue_enable = false;
    config.global.dial_mode = "ip".into();
    config.routing.rules = [
        (5101, "sibling"),
        (5102, "bare-exit"),
        (5103, "via-chain"),
        (5104, "via-chain"),
    ]
    .map(|(port, outbound)| RoutingRule {
        name: outbound.into(),
        condition: RoutingCondition {
            port: vec![port.to_string()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple(outbound.into()),
        priority: 0,
        must: true,
        mark: 0,
    })
    .into();
    let config = config.assemble(|_, _, _| {}).unwrap();
    let router = crate::routing::Router::new(&config.routing.rules, "g").unwrap();
    let mut plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        crate::dns::DnsResolver::new(&Default::default()).unwrap(),
        super::support::test_dns_forwarder(),
    )
    .unwrap();
    plane.udp_pool = Arc::new(
        crate::control::udp_endpoint::UdpEndpointPool::with_reply_socket_factory(
            16,
            Arc::new(super::support::UdpTestReplySocketFactory),
        ),
    );
    plane.install_node_death_callback();
    let handle = plane.spawn_handle();
    let retirement = super::support::TestRetirement::start(&handle);
    // Framing faults are counted for an unprobed exit immediately. Startup
    // grace belongs to periodic-probe registrations, not the wire fixture.
    handle.alive_set.remove_node(land.id);
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = client_socket.local_addr().unwrap();
    let retired = super::support::addr("192.0.2.1:5000");
    let land_addr = super::support::addr(&land.address);

    super::support::serve_test_udp_to(&handle, client, retired, b"first")
        .await
        .unwrap();
    assert_eq!(relay.requests.lock()[..], [land_addr]);
    plane.udp_pool.remove_by_node(front.id);
    assert!(plane.udp_pool.get(client, retired).is_some());
    plane.udp_pool.remove_by_node(land.id);
    assert!(plane.udp_pool.get(client, retired).is_none());
    drop(accepted.recv().await.unwrap());

    let protected = [
        super::support::addr("192.0.2.2:5101"),
        super::support::addr("192.0.2.2:5102"),
    ];
    for target in protected {
        super::support::serve_test_udp_to(&handle, client, target, b"alive")
            .await
            .unwrap();
        let mut stream = accepted.recv().await.unwrap();
        tokio::spawn(async move {
            let mut head = [0; 56 + 2 + 1 + 7 + 2];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[58], 3);
            let (mut reader, mut writer) = stream.split();
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
        });
        let mut reply = [0; 8];
        let len = tokio::time::timeout(Duration::from_secs(3), client_socket.recv(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..len], b"alive");
    }
    let original_endpoints = protected.map(|target| plane.udp_pool.get(client, target).unwrap());
    for seq in 0u8..50 {
        let dst = SocketAddr::new(retired.ip(), 6000 + u16::from(seq));
        super::support::serve_test_udp_to(&handle, client, dst, &[seq])
            .await
            .unwrap();
        assert!(plane.udp_pool.get(client, dst).is_some());
        let mut stream = tokio::time::timeout(Duration::from_secs(3), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        let mut wire = [0; 68 + 11 + 1];
        stream.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire[58], 3);
        assert_eq!(wire[79], seq);
        stream.write_all(&[1, 192]).await.unwrap();
        drop(stream);
        tokio::time::timeout(Duration::from_secs(3), async {
            while plane.udp_pool.get(client, dst).is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("truncated response must close exactly its own flow");
    }
    assert_eq!(relay.requests.lock().as_slice(), vec![land_addr; 51]);
    assert_eq!(sibling_relay.requests.lock()[..], [land_addr]);
    for (target, original) in protected.into_iter().zip(original_endpoints) {
        assert!(Arc::ptr_eq(
            &original,
            &plane.udp_pool.get(client, target).unwrap()
        ));
        super::support::serve_test_udp_to(&handle, client, target, b"")
            .await
            .unwrap();
        let mut reply = [0; 1];
        let len = tokio::time::timeout(Duration::from_secs(3), client_socket.recv(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            len, 0,
            "the original sibling must deliver even an empty datagram"
        );
    }
    let shared_dest = [
        super::support::addr("192.0.2.3:5103"),
        super::support::addr("192.0.2.4:5104"),
    ];
    super::support::serve_test_udp_to(&handle, client, shared_dest[0], b"owner")
        .await
        .unwrap();
    let mut shared_wire = accepted.recv().await.unwrap();
    let mut head = [0; 68];
    shared_wire.read_exact(&mut head).await.unwrap();
    let mut frame = [0; 11 + 5];
    shared_wire.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame[11..], b"owner");
    super::support::serve_test_udp_to(&handle, client, shared_dest[1], b"reuse")
        .await
        .unwrap();
    shared_wire.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame[11..], b"reuse");
    assert!(accepted.try_recv().is_err());

    let mixed_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mixed_addr = mixed_client.local_addr().unwrap();
    let creator = super::support::addr("[2001:db8::3]:5103");
    let reused = shared_dest[1];
    super::support::serve_test_udp_to(&handle, mixed_addr, creator, b"v6")
        .await
        .unwrap();
    let mut mixed_wire = accepted.recv().await.unwrap();
    let mut v6_header_and_frame = [0; 80 + 23 + 2];
    mixed_wire
        .read_exact(&mut v6_header_and_frame)
        .await
        .unwrap();
    assert_eq!(&v6_header_and_frame[103..], b"v6");
    // An IPv6 reply for an IPv4 client cannot be delivered. The second view
    // has a matching family; its delivered empty frame still proves the creator.
    mixed_wire
        .write_all(&v6_header_and_frame[80..])
        .await
        .unwrap();
    super::support::serve_test_udp_to(&handle, mixed_addr, reused, b"v4")
        .await
        .unwrap();
    let mut v4_frame = [0; 11 + 2];
    mixed_wire.read_exact(&mut v4_frame).await.unwrap();
    assert_eq!(&v4_frame[11..], b"v4");
    assert!(!handle.alive_set.routed_udp_node_proven(
        configured_id,
        ProbeDomain::DataUdp,
        IpVersion::V6
    ));
    v4_frame[7..9].copy_from_slice(&0u16.to_be_bytes());
    mixed_wire.write_all(&v4_frame[..11]).await.unwrap();
    let mut byte = [0];
    let len = tokio::time::timeout(Duration::from_secs(3), mixed_client.recv(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, 0);
    assert!(handle.alive_set.routed_udp_node_proven(
        configured_id,
        ProbeDomain::DataUdp,
        IpVersion::V6
    ));
    assert!(!handle.alive_set.routed_udp_node_proven(
        configured_id,
        ProbeDomain::DataUdp,
        IpVersion::V4
    ));
    assert!(accepted.try_recv().is_err());

    let manager = handle.group_manager.read().clone();
    let generation = handle.runtime_registry.read().clone();
    let mut bound = Vec::new();
    for (port, family) in [(5201, IpVersion::V4), (5202, IpVersion::V6)] {
        let context = crate::group::ScoreSelectionContext::aggregate(
            crate::group::SelectionNetwork::Udp,
            ProbeDomain::DataUdp,
            family,
        );
        let config = handle.config.read().await;
        let plan = crate::control::reload::resolve_outbound_plan_for_target(
            &config,
            &manager,
            "sibling",
            &context,
            crate::control::reload::OutboundConstraint::Any,
        );
        assert_eq!(plan.health_family, family);
        let evidence = crate::control::udp_endpoint::UdpTrafficEvidence::capture_route(
            &manager,
            &generation,
            &plan.targets[0],
            &plan.selection_chains[0],
            &plan.final_owners[0],
            plan.route_revision,
            family,
        )
        .unwrap();
        let permit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        let dst = SocketAddr::new(retired.ip(), port);
        let crate::control::udp_endpoint::EndpointReservation::Initializing(lease) = plane
            .udp_pool
            .reserve_or_enqueue(client, dst, b"waiting", permit, &handle.stats)
        else {
            panic!("fresh reservation");
        };
        assert!(lease.bind_selected(land.id, Some(Arc::new(evidence))));
        bound.push(lease);
    }

    // A complete invalid address tag identifies E's framing operation.
    for seq in 0u8..49 {
        let dst = SocketAddr::new(retired.ip(), 7000 + u16::from(seq));
        super::support::serve_test_udp_to(&handle, client, dst, &[seq])
            .await
            .unwrap();
        let mut stream = tokio::time::timeout(Duration::from_secs(3), accepted.recv())
            .await
            .unwrap()
            .unwrap();
        let mut wire = [0; 68 + 11 + 1];
        stream.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire[79], seq);
        stream.write_all(&[9]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while plane.udp_pool.get(client, dst).is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("typed bad record must terminate its flow");
        for live in protected.into_iter().chain(shared_dest) {
            assert!(plane.udp_pool.get(client, live).is_some());
        }
    }
    // One receiver settles the fiftieth independent fault for both of its
    // bound views; the death callback also retires other affected owners.
    shared_wire.write_all(&[9]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while plane.udp_pool.get(client, protected[1]).is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the shared receiver must publish its typed framing failure");
    for dead in protected.into_iter().chain(shared_dest) {
        assert!(plane.udp_pool.get(client, dead).is_none());
    }
    assert!(plane.udp_pool.get(mixed_addr, creator).is_some());
    assert!(plane.udp_pool.get(mixed_addr, reused).is_none());
    assert!(!bound[0].still_initializing());
    assert!(bound[1].still_initializing());
    drop(bound);
    assert!(!handle.group_manager.read().is_node_selectable_for_domain(
        land.id,
        ProbeDomain::DataUdp,
        IpVersion::V4
    ));
    assert!(handle.group_manager.read().is_node_selectable_for_domain(
        land.id,
        ProbeDomain::DataUdp,
        IpVersion::V6
    ));
    assert!(
        handle
            .alive_set
            .is_alive_for(land.id, ProbeDomain::Tcp, IpVersion::V4)
    );
    retirement.join(&handle).await.unwrap();
}

#[tokio::test]
async fn control_plane_idle_probe_lifecycle_startup_restore_reload_and_timeout_hot_reload() {
    use crate::state::StateDb;
    use crate::state::cache::Maintenance;
    use honk_config::group::{Group, GroupPolicy};

    let build_config = |sel_nodes: &[&Node], auto_nodes: &[&Node], idle_timeout: Option<u64>| {
        let mut config = Config::default();
        config.global.nfqueue_enable = false;
        config.ensure_builtin_nodes();
        for node in sel_nodes.iter().chain(auto_nodes.iter()) {
            if !config.nodes.iter().any(|existing| existing.id == node.id) {
                config.nodes.push((*node).clone());
            }
        }
        config.groups = vec![
            Group {
                name: "proxy".into(),
                policy: GroupPolicy::Selector,
                nodes: sel_nodes.iter().map(|n| n.id).collect(),
                default: sel_nodes.first().map(|n| n.name.clone()),
                ..Default::default()
            },
            Group {
                name: "auto".into(),
                policy: GroupPolicy::Score,
                nodes: auto_nodes.iter().map(|n| n.id).collect(),
                idle_timeout,
                ..Default::default()
            },
        ];
        config
    };

    let n_sel1 = canonical_socks5("sel1", "127.0.0.1", 2001, None);
    let n_sel2 = canonical_socks5("sel2", "127.0.0.1", 2002, None);
    let n_auto1 = canonical_socks5("auto1", "127.0.0.1", 2003, None);
    let n_new = canonical_socks5("new_idle", "127.0.0.1", 2004, None);

    // Persist a Selector choice (`sel2`) to verify quiet startup cache restore.
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(StateDb::open(dir.path()).unwrap());
    {
        let mut seeded = control_plane(build_config(&[&n_sel1, &n_sel2], &[&n_auto1], Some(1800)));
        seeded.init_cache_db(Some(Arc::clone(&state)), None).await;
        seeded
            .group_manager()
            .read()
            .set_selector_choice(
                "proxy",
                "sel2",
                honk_outbound::group::SelectorNetworks::Both,
            )
            .unwrap();
        seeded
            .cache_db()
            .unwrap()
            .maintain(Maintenance::default())
            .unwrap();
    }

    // Startup + cache restore: default/restored pick is unsuspended without
    // pre-filling trigger_tx, while unselected Selector and idle Score nodes pause.
    let mut plane = control_plane(build_config(&[&n_sel1, &n_sel2], &[&n_auto1], Some(1800)));
    let mut trigger_rx = plane
        .alive_set()
        .take_trigger_rx()
        .expect("trigger receiver");
    assert!(!plane.alive_set().is_probe_suspended(n_sel1.id));
    assert!(plane.alive_set().is_probe_suspended(n_sel2.id));
    assert!(plane.alive_set().is_probe_suspended(n_auto1.id));
    assert!(trigger_rx.try_recv().is_err());

    plane.init_cache_db(Some(state), None).await;
    assert!(plane.alive_set().is_probe_suspended(n_sel1.id));
    assert!(!plane.alive_set().is_probe_suspended(n_sel2.id));
    assert!(
        trigger_rx.try_recv().is_err(),
        "startup cache restore must not pre-fill trigger_tx before health loop stagger"
    );

    // Reload atomicity + idle_timeout hot reload: hold udp_warm_task so reload
    // pauses right after publication locks drop, before warm coordinators run.
    let plane = Arc::new(plane);
    let next = build_config(&[&n_sel1], &[&n_auto1, &n_new], Some(0));
    let warm_guard = plane.udp_warm_task.lock().await;
    let generation = plane.runtime_registry.read().generation();
    let reload_plane = Arc::clone(&plane);
    let reload = tokio::spawn(async move {
        reload_plane
            .reload_runtime_config(next, Default::default())
            .await
    });
    while plane.runtime_registry.read().generation() == generation {
        assert!(!reload.is_finished(), "reload exited before publication");
        tokio::task::yield_now().await;
    }
    // Already published before warm coordinators run: new idle node is suspended,
    // and newly active Selector fallback `sel1` is unsuspended and woken.
    assert!(plane.alive_set().is_probe_suspended(n_new.id));
    assert!(!plane.alive_set().is_probe_suspended(n_sel1.id));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), trigger_rx.recv())
            .await
            .expect("reload must wake newly active Selector pick before warm coordinators"),
        Some(n_sel1.id)
    );
    drop(warm_guard);
    assert!(reload.await.unwrap());

    // Hot-reloaded `idle_timeout: 0` takes effect immediately without storming.
    plane.alive_set().mark_group_active("auto");
    assert!(plane.alive_set().is_group_idle("auto"));
    assert!(trigger_rx.try_recv().is_err());

    // Manager-only rebuild switches Selector membership and wakes the new selection.
    let rebuilt = build_config(&[&n_sel2], &[&n_auto1], Some(1800));
    *plane.config_handle().write().await = Arc::new(rebuilt);
    plane.reload_group_manager().await.unwrap();
    assert!(!plane.alive_set().is_probe_suspended(n_sel2.id));
    assert_eq!(trigger_rx.try_recv(), Ok(n_sel2.id));
}

#[tokio::test]
async fn control_plane_selector_isolates_unselected_members_and_registers_recovery_leaves() {
    use honk_config::group::{Group, GroupPolicy};
    use honk_config::node::{Node, OutboundConfig};
    use honk_outbound::alive::IdleGroupKind;

    let sel_a = canonical_socks5("sel_a", "127.0.0.1", 2101, None);
    let sel_b = canonical_socks5("sel_b", "127.0.0.1", 2102, None);
    let mut hk_tcp_only = Node {
        outbound: OutboundConfig::Vmess(honk_config::node::VmessConfig {
            uuid: Some("11111111-1111-1111-1111-111111111111".into()),
            ..Default::default()
        }),
        ..canonical_socks5("hk_tcp_only", "127.0.0.1", 2103, None)
    };
    hk_tcp_only.id = hk_tcp_only.derive_id();
    let hk_udp = canonical_socks5("hk_udp", "127.0.0.1", 2104, None);
    let jp1 = canonical_socks5("jp1", "127.0.0.1", 2105, None);
    let p_direct = canonical_socks5("p_direct", "127.0.0.1", 2106, None);

    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.ensure_builtin_nodes();
    config.nodes.extend([
        sel_a.clone(),
        sel_b.clone(),
        hk_tcp_only.clone(),
        hk_udp.clone(),
        jp1.clone(),
        p_direct.clone(),
    ]);
    config.groups = vec![
        Group {
            name: "proxy".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![sel_a.id, sel_b.id],
            groups: vec!["auto_hk".into(), "auto_jp".into()],
            default: Some("sel_a".into()),
            ..Default::default()
        },
        Group {
            name: "auto_hk".into(),
            policy: GroupPolicy::Score,
            nodes: vec![hk_tcp_only.id, hk_udp.id],
            final_outbound: Some("direct".into()),
            idle_timeout: Some(0),
            ..Default::default()
        },
        Group {
            name: "auto_jp".into(),
            policy: GroupPolicy::Fallback,
            nodes: vec![jp1.id],
            ..Default::default()
        },
        Group {
            name: "parent_auto".into(),
            policy: GroupPolicy::URLTest,
            nodes: vec![p_direct.id],
            groups: vec!["auto_jp".into()],
            ..Default::default()
        },
    ];

    // Verify idle_group_registrations directly: direct-only members + Selector kind +
    // datapath-parity TCP/UDP recovery sets (builtins & TCP-only excluded appropriately).
    let regs = super::super::reload::idle_group_registrations(&config);
    let by_name = |name: &str| regs.iter().find(|r| r.name == name).unwrap();

    let reg_proxy = by_name("proxy");
    assert_eq!(reg_proxy.kind, IdleGroupKind::Selector);
    assert_eq!(
        reg_proxy
            .members
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>(),
        std::collections::HashSet::from([sel_a.id, sel_b.id])
    );
    assert!(reg_proxy.tcp_recovery_members.is_empty());
    assert!(reg_proxy.udp_recovery_members.is_empty());

    let reg_hk = by_name("auto_hk");
    assert_eq!(reg_hk.kind, IdleGroupKind::Automatic);
    assert_eq!(
        reg_hk
            .tcp_recovery_members
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>(),
        std::collections::HashSet::from([hk_tcp_only.id, hk_udp.id])
    );
    assert_eq!(reg_hk.udp_recovery_members, vec![hk_udp.id]);

    let reg_parent = by_name("parent_auto");
    assert_eq!(reg_parent.members, vec![p_direct.id]);
    assert_eq!(
        reg_parent
            .tcp_recovery_members
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>(),
        std::collections::HashSet::from([p_direct.id, jp1.id])
    );
    assert_eq!(
        reg_parent
            .udp_recovery_members
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>(),
        std::collections::HashSet::from([p_direct.id, jp1.id])
    );

    // Real ControlPlane: selecting through active Selector keeps unselected direct
    // members and unselected automatic subgroups suspended.
    let plane = control_plane(config);
    assert_eq!(
        plane
            .group_manager()
            .read()
            .select_node("proxy")
            .map(|n| n.id),
        Some(sel_a.id)
    );
    assert!(!plane.alive_set().is_probe_suspended(sel_a.id));
    for suspended in [sel_b.id, hk_tcp_only.id, hk_udp.id, jp1.id, p_direct.id] {
        assert!(plane.alive_set().is_probe_suspended(suspended));
    }
    assert!(plane.alive_set().is_group_idle("auto_hk"));
    assert!(plane.alive_set().is_group_idle("auto_jp"));

    // Switching Selector to `auto_jp` wakes only `auto_jp` on traffic.
    plane
        .group_manager()
        .read()
        .set_selector_choice(
            "proxy",
            "auto_jp",
            honk_outbound::group::SelectorNetworks::Both,
        )
        .unwrap();
    assert_eq!(
        plane
            .group_manager()
            .read()
            .select_node("proxy")
            .map(|n| n.id),
        Some(jp1.id)
    );
    assert!(!plane.alive_set().is_group_idle("auto_jp"));
    assert!(!plane.alive_set().is_probe_suspended(jp1.id));
    for suspended in [sel_a.id, sel_b.id, hk_tcp_only.id, hk_udp.id, p_direct.id] {
        assert!(plane.alive_set().is_probe_suspended(suspended));
    }
}

#[tokio::test]
async fn control_plane_custom_url_selection_under_group_manager_read_does_not_deadlock_on_writer() {
    use honk_config::group::{Group, GroupPolicy};

    let n1 = canonical_socks5("n1", "127.0.0.1", 2201, None);
    let n2 = canonical_socks5("n2", "127.0.0.1", 2202, None);
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.ensure_builtin_nodes();
    config.nodes.extend([n1.clone(), n2.clone()]);
    config.groups = vec![
        Group {
            name: "custom_auto".into(),
            policy: GroupPolicy::URLTest,
            nodes: vec![n1.id],
            groups: vec!["sub".into()],
            check_url: Some("http://127.0.0.1/custom".into()),
            ..Default::default()
        },
        Group {
            name: "sub".into(),
            policy: GroupPolicy::Fallback,
            nodes: vec![n2.id],
            ..Default::default()
        },
    ];

    let plane = control_plane(config);
    let gm_cell = plane.group_manager().clone();

    // Hold a read guard while a writer parks on the write-preferring RwLock.
    // Reentering `group_manager.read()` from `mark_group_active` would self-deadlock here.
    let (writer_ready_tx, writer_ready_rx) = std::sync::mpsc::channel();
    let (writer_done_tx, writer_done_rx) = std::sync::mpsc::channel();
    let gm_read = gm_cell.read();
    let writer_cell = Arc::clone(&gm_cell);
    let writer = std::thread::spawn(move || {
        writer_ready_tx.send(()).unwrap();
        let _guard = writer_cell.write();
        let _ = writer_done_tx.send(());
    });
    writer_ready_rx.recv().unwrap();
    std::thread::sleep(Duration::from_millis(20));

    assert!(gm_read.select_node("custom_auto").is_some());
    drop(gm_read);

    writer_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("writer must acquire group_manager lock without deadlock");
    writer.join().unwrap();
    assert!(!plane.alive_set().is_group_idle("custom_auto"));
}

#[tokio::test]
async fn control_plane_noop_reload_clears_override_and_runs_callbacks_after_config_unlock() {
    use honk_config::group::{Group, GroupPolicy};
    use std::sync::atomic::{AtomicBool, Ordering};

    let a1 = canonical_socks5("a1", "127.0.0.1", 2301, None);
    let a2 = canonical_socks5("a2", "127.0.0.1", 2302, None);
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.ensure_builtin_nodes();
    config.nodes.extend([a1.clone(), a2.clone()]);
    config.groups = vec![Group {
        name: "auto".into(),
        policy: GroupPolicy::Score,
        nodes: vec![a1.id, a2.id],
        ..Default::default()
    }];

    let plane = control_plane(config.clone());
    // Establish a reload-compiled DNS forwarder policy_id so the next identical
    // reload enters the NOOP fast path.
    assert!(
        plane
            .reload_runtime_config(config.clone(), Default::default())
            .await
    );
    assert!(plane.alive_set().is_probe_suspended(a1.id));

    plane
        .group_manager()
        .read()
        .publish_override(
            "auto",
            &honk_outbound::group::SelectorMember::Node(a1.id),
            honk_outbound::group::SelectorNetworks::Both,
        )
        .unwrap()
        .run_callbacks();
    assert!(!plane.alive_set().is_probe_suspended(a1.id));
    assert!(
        plane
            .group_manager()
            .read()
            .has_override("auto", honk_outbound::group::SelectionNetwork::Tcp)
    );

    let callback_fired = Arc::new(AtomicBool::new(false));
    let config_unlocked = Arc::new(AtomicBool::new(false));
    let fired_cb = Arc::clone(&callback_fired);
    let unlocked_cb = Arc::clone(&config_unlocked);
    let config_handle = plane.config_handle().clone();
    plane
        .group_manager()
        .read()
        .set_selector_change_callback(Some(Arc::new(move || {
            fired_cb.store(true, Ordering::Release);
            unlocked_cb.store(config_handle.try_read().is_ok(), Ordering::Release);
        })));

    let gen_before = plane.runtime_registry.read().generation();
    let reloaded = plane
        .reload_runtime_config(config, Default::default())
        .await;
    assert!(reloaded, "NOOP reload must succeed");
    assert_eq!(
        plane.runtime_registry.read().generation(),
        gen_before,
        "identical config must take the NOOP reload path without advancing generation"
    );
    assert!(
        !plane
            .group_manager()
            .read()
            .has_override("auto", honk_outbound::group::SelectionNetwork::Tcp)
    );
    assert!(plane.alive_set().is_probe_suspended(a1.id));
    assert!(callback_fired.load(Ordering::Acquire));
    assert!(
        config_unlocked.load(Ordering::Acquire),
        "NOOP reload must release config write guard before running clear_override callbacks"
    );
}
