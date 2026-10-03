use super::support::{
    UdpTestHandler, UdpTestMode, canonical_socks5, control_plane, score_reload_config,
};
use crate::control::{ControlPlane, drain::DrainTracker, probers::UdpDnsProbeTarget};
use honk_config::{Config, node::Node, parser::parse_dae_config, types::NodeProtocol};
use honk_outbound::alive::{
    HttpProbeOutcome, HttpProbeResult, HttpProber, IpVersion, ProbeDomain, UdpProber,
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
    let prober = Arc::new(crate::control::probers::ProxyHttpProber::new(
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
        config.global.udp_check_dns = vec![old_raw.into()];
        config.nodes = vec![node.clone()];
        let dns_probe =
            UdpDnsProbeTarget::new(config.global.udp_check_dns.clone(), Some(resolver.clone()));
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
        candidate.global.udp_check_dns = new_raw.into_iter().map(str::to_owned).collect();
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
    config.global.udp_check_dns = vec!["resolver.example:5301".into()];
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
    let dns_probe = UdpDnsProbeTarget::new(config.global.udp_check_dns.clone(), Some(resolver));
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
    alive.register_node(node.id, node.name.clone(), "127.0.0.1:9".into());
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
    alive.register_node(node.id, node.name.clone(), "127.0.0.1:9".into());
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
