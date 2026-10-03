use super::*;
use crate::control::tests::support::{UdpTestHandler, UdpTestMode, udp_test_node};
use honk_outbound::alive::{HttpProbeResult, HttpProber, UdpProber};
use honk_outbound::proxy::{ProtocolEntry, ProxyStream, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct LoopbackOutbound;

#[async_trait::async_trait]
impl TcpOutbound for LoopbackOutbound {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        Ok(ProxyStream {
            stream: Box::new(tokio::net::TcpStream::connect(target).await?),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

fn test_prober(method: &str) -> (ProxyHttpProber, uuid::Uuid) {
    let mut node = Node {
        name: "http-probe-test".into(),
        address: "127.0.0.1:1".into(),
        host: "127.0.0.1".into(),
        port: 1,
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        ..Node::default()
    };
    node.id = node.derive_id();
    let node_id = node.id;
    let config = Arc::new(RwLock::new(Arc::new(Config {
        nodes: vec![node.clone()],
        ..Config::default()
    })));
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(
        node.protocol(),
        Arc::new(LoopbackOutbound),
    ));
    let runtimes = Arc::new(parking_lot::RwLock::new(Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
            .unwrap(),
    )));
    let groups = Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
        &[],
        std::slice::from_ref(&node),
    ))));
    (
        ProxyHttpProber::new(config, Arc::new(registry), runtimes, method.into(), groups),
        node_id,
    )
}

#[tokio::test]
async fn configured_http_measurements_update_score_quality_baseline() {
    async fn peer(delay: Duration) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for _ in 0..2 {
                read_request_head(&mut stream).await;
                tokio::time::sleep(delay).await;
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        (addr, task)
    }

    let nodes: Vec<_> = ["slow", "fast"]
        .into_iter()
        .map(|name| {
            let mut node = Node {
                name: name.into(),
                address: "127.0.0.1".into(),
                host: "127.0.0.1".into(),
                port: 1,
                outbound: honk_config::node::OutboundConfig::Socks5(
                    honk_config::node::Socks5Config {
                        username: Some(name.into()),
                        ..Default::default()
                    },
                ),
                ..Node::default()
            };
            node.id = node.derive_id();
            node
        })
        .collect();
    let url = "http://quality.example.test/";
    let mut config = Config {
        nodes: nodes.clone(),
        groups: vec![honk_config::group::Group {
            name: "score".into(),
            policy: honk_config::group::GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        }],
        ..Default::default()
    };
    config.global.tcp_check_url = vec![url.into()];
    let manager = Arc::new(GroupManager::new(&config.groups, &nodes));
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(
        NodeProtocol::Socks5,
        Arc::new(LoopbackOutbound),
    ));
    let generation =
        Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&nodes).unwrap());
    let prober = ProxyHttpProber::new(
        Arc::new(RwLock::new(Arc::new(config))),
        Arc::new(registry),
        Arc::new(parking_lot::RwLock::new(generation)),
        "HEAD".into(),
        Arc::new(parking_lot::RwLock::new(Arc::clone(&manager))),
    );
    for (node, delay) in nodes
        .iter()
        .zip([Duration::from_millis(100), Duration::ZERO])
    {
        let (addr, task) = peer(delay).await;
        assert!(matches!(
            prober
                .probe_http(
                    node.id,
                    addr,
                    url,
                    Duration::from_secs(2),
                    Default::default()
                )
                .await
                .result,
            HttpProbeResult::WarmSuccess(_),
        ));
        finish_server(task).await;
    }
    assert_eq!(
        manager.get_score_selection_for_network("score", SelectionNetwork::Tcp),
        Some("fast".into()),
    );
}

async fn read_request_head(stream: &mut tokio::net::TcpStream) -> String {
    let mut request = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            return String::from_utf8(request).unwrap();
        }
    }
}

async fn finish_server<T>(mut server: tokio::task::JoinHandle<T>) -> T {
    match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
        Ok(result) => result.unwrap(),
        Err(_) => {
            server.abort();
            let _ = server.await;
            panic!("HTTP probe fixture did not finish");
        }
    }
}

#[tokio::test]
async fn rejected_first_response_cannot_become_fallback_success() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_request_head(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
    });
    let (prober, node_id) = test_prober("GET");

    let result = prober
        .probe_http(
            node_id,
            addr,
            &format!("http://probe.invalid:{}/health", addr.port()),
            Duration::from_secs(1),
            honk_outbound::alive::ProbeCancellation::default(),
        )
        .await;

    finish_server(server).await;
    assert!(
        matches!(&result.result, HttpProbeResult::ExchangeFailure(_)),
        "503 warm-up followed by close must fail, got {result:?}"
    );
}

#[tokio::test]
async fn c25_health_sends_authority_and_path_query_without_credentials() {
    for (url_host, suffix, path) in [
        ("localhost", "/check?q=1#fragment", "/check?q=1"),
        ("localhost", "?q=1", "/?q=1"),
        ("localhost", "/a/../health?q=1#fragment", "/a/../health?q=1"),
        (
            "localhost",
            "/a/%2e%2e/health?q=1#fragment",
            "/a/%2e%2e/health?q=1",
        ),
        ("[::1]", "/check?q=1#fragment", "/check?q=1"),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected_authority = format!("{url_host}:{}", addr.port());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for _ in 0..2 {
                let request = read_request_head(&mut stream).await;
                assert_eq!(
                    request.split_once("\r\n").unwrap().0,
                    format!("HEAD {path} HTTP/1.1")
                );
                assert!(request.contains(&format!("\r\nHost: {expected_authority}\r\n")));
                assert!(!request.contains("PRIVATE") && !request.contains("Authorization:"));
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let url = format!("http://user:PRIVATE@{url_host}:{}{suffix}", addr.port());
        let (prober, node_id) = test_prober("HEAD");
        let result = prober
            .probe_http(
                node_id,
                addr,
                &url,
                Duration::from_secs(2),
                honk_outbound::alive::ProbeCancellation::default(),
            )
            .await;
        assert!(
            matches!(&result.result, HttpProbeResult::WarmSuccess(_)),
            "{result:?}"
        );
        finish_server(server).await;
    }
}

#[tokio::test]
async fn configured_target_and_method_reach_the_server() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let first = read_request_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let second = read_request_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        [first, second]
    });
    let (prober, node_id) = test_prober("POST");

    let result = prober
        .probe_http(
            node_id,
            addr,
            &format!(
                "probe.invalid:{}/ready/check?region=west,192.0.2.1,2001:db8::1",
                addr.port()
            ),
            Duration::from_secs(1),
            honk_outbound::alive::ProbeCancellation::default(),
        )
        .await;

    let [first, second] = finish_server(server).await;
    assert!(
        matches!(&result.result, HttpProbeResult::WarmSuccess(_)),
        "{result:?}"
    );
    assert_eq!(
        first.lines().next(),
        Some("HEAD /ready/check?region=west HTTP/1.1")
    );
    assert_eq!(
        second.lines().next(),
        Some("POST /ready/check?region=west HTTP/1.1")
    );
    let authority = format!("host: probe.invalid:{}", addr.port());
    for request in [&first, &second] {
        assert!(
            request
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&authority)),
            "configured authority did not reach the server: {request:?}"
        );
    }
}

#[tokio::test]
async fn https_probe_starts_with_tls() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut content_type = [0u8; 1];
        stream.read_exact(&mut content_type).await.unwrap();
        content_type[0]
    });
    let (prober, node_id) = test_prober("HEAD");

    let result = prober
        .probe_http(
            node_id,
            addr,
            &format!("https://localhost:{}/secure", addr.port()),
            Duration::from_secs(1),
            honk_outbound::alive::ProbeCancellation::default(),
        )
        .await;

    let content_type = finish_server(server).await;
    assert!(matches!(
        &result.result,
        HttpProbeResult::ExchangeFailure(_)
    ));
    assert_eq!(content_type, 22, "TLS handshake record expected");
}

fn invalid_probe_nodes() -> Vec<Node> {
    let node = udp_test_node();
    let mut nil = node.clone();
    nil.id = uuid::Uuid::nil();
    let mut stale = node.clone();
    stale.port += 1;
    let mut intrinsic = node;
    intrinsic.port = 0;
    vec![nil, stale, intrinsic]
}

#[tokio::test]
async fn c27_http_rejects_invalid_nodes_before_dial() {
    for node in invalid_probe_nodes() {
        let original = udp_test_node();
        let generation = Arc::new(parking_lot::RwLock::new(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&[original]).unwrap(),
        )));
        let captured = Arc::new(std::sync::Mutex::new(None));
        let mut registry = ProxyRegistry::new();
        registry.register(honk_outbound::proxy::ProtocolEntry::new(
            node.protocol(),
            Arc::new(UdpTestHandler {
                mode: UdpTestMode::TcpCaptureTarget(captured.clone()),
            }),
        ));
        let config = Config {
            nodes: vec![node.clone()],
            ..Config::default()
        };
        let manager = Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
            &[],
            &[],
        ))));
        let prober = ProxyHttpProber::new(
            Arc::new(RwLock::new(Arc::new(config))),
            Arc::new(registry),
            generation,
            "HEAD".into(),
            manager,
        );
        let result = prober
            .probe_http(
                node.id,
                "127.0.0.1:9".parse().unwrap(),
                "http://127.0.0.1:9/",
                Duration::from_millis(50),
                honk_outbound::alive::ProbeCancellation::default(),
            )
            .await;
        assert!(matches!(result.result, HttpProbeResult::SetupFailure(_)));
        assert!(
            captured.lock().unwrap().is_none(),
            "invalid node reached TCP dial"
        );
    }
}

#[tokio::test]
async fn c27_udp_rejects_invalid_nodes_without_data_path() {
    for node in invalid_probe_nodes() {
        let generation = Arc::new(parking_lot::RwLock::new(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&[udp_test_node()]).unwrap(),
        )));
        let captured = Arc::new(std::sync::Mutex::new(None));
        let handler = Arc::new(UdpTestHandler {
            mode: UdpTestMode::UdpCaptureTarget(captured.clone()),
        });
        let mut registry = ProxyRegistry::new();
        registry.register(
            honk_outbound::proxy::ProtocolEntry::new(node.protocol(), handler.clone())
                .with_packet(handler),
        );
        let config = Config {
            nodes: vec![node.clone()],
            ..Config::default()
        };
        let manager = Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
            &[],
            &[],
        ))));
        let target: SocketAddr = "127.0.0.1:5301".parse().unwrap();
        let prober = ProxyUdpProber::new(
            Arc::new(RwLock::new(Arc::new(config))),
            Arc::new(registry),
            generation,
            Arc::new(StatsManager::new()),
            UdpDnsProbeTarget::new(vec![target.to_string()], None),
            None,
            manager,
        );
        let result = prober
            .probe_udp(
                node.id,
                Duration::from_millis(50),
                honk_outbound::alive::ProbeCancellation::default(),
            )
            .await;
        assert!(matches!(result.dns, Some(Err(_))));
        assert!(result.data_path.is_none());
        assert!(
            captured.lock().unwrap().is_none(),
            "invalid node reached UDP dial"
        );
    }
}

#[tokio::test]
async fn udp_capability_and_policy_gates_skip_target_resolution_and_health_feedback() {
    for udp_disabled in [false, true] {
        let mut node = udp_test_node();
        node.name = "vision-vless".into();
        node.outbound = honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some("00000000-0000-4000-8000-000000000001".into()),
            network: udp_disabled.then(|| "tcp".into()),
            flow: Some("xtls-rprx-vision".into()),
            multiplex: honk_config::node::VlessMultiplex::xray(
                -1,
                -1,
                honk_config::node::Udp443Policy::Reject,
            ),
            tls: honk_config::node::TlsOptions {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        });
        node.id = node.derive_id();
        let generation = Arc::new(parking_lot::RwLock::new(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&[udp_test_node()]).unwrap(),
        )));
        let captured = Arc::new(std::sync::Mutex::new(None));
        let handler = Arc::new(UdpTestHandler {
            mode: UdpTestMode::UdpCaptureTarget(captured.clone()),
        });
        let mut registry = ProxyRegistry::new();
        registry.register(
            honk_outbound::proxy::ProtocolEntry::new(node.protocol(), handler.clone())
                .with_packet(handler),
        );
        let config = Config {
            nodes: vec![node.clone()],
            ..Config::default()
        };
        let manager = Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
            &[],
            std::slice::from_ref(&node),
        ))));
        let resolver: crate::outbound::ResolveHook = Arc::new(|_, _| {
            panic!("policy-denied DNS target must not be resolved");
        });
        let prober = ProxyUdpProber::new(
            Arc::new(RwLock::new(Arc::new(config))),
            Arc::new(registry),
            generation,
            Arc::new(StatsManager::new()),
            UdpDnsProbeTarget::new(vec!["denied.example:443".into()], Some(resolver.clone())),
            Some(Arc::new(QuicScoreProbeTarget::new(
                "https://denied.example/".into(),
                Some(resolver),
                Arc::default(),
            ))),
            manager,
        );

        let outcome = prober
            .probe_udp(
                node.id,
                Duration::from_millis(50),
                honk_outbound::alive::ProbeCancellation::default(),
            )
            .await;

        assert!(outcome.dns.is_none());
        assert!(outcome.data_path.is_none());
        assert!(captured.lock().unwrap().is_none());
    }
}

#[tokio::test]
async fn c27_urltest_propagates_admission_before_dial() {
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[udp_test_node()]).unwrap(),
    );
    let captured = Arc::new(std::sync::Mutex::new(None));
    let handler = UdpTestHandler {
        mode: UdpTestMode::TcpCaptureTarget(captured.clone()),
    };
    for node in invalid_probe_nodes() {
        let result = honk_outbound::urltest::urltest_node_in_generation_with_feedback(
            &generation,
            &node,
            &handler,
            None,
            "http://127.0.0.1:9/",
            Duration::from_millis(50),
            &GroupManager::new(&[], &[]),
            Default::default(),
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<honk_outbound::runtime::RuntimeRegistryError>()
                .is_some()
        );
        assert!(captured.lock().unwrap().is_none());
    }
}

#[tokio::test]
async fn quic_target_refusal_is_retried_by_later_udp_probe() {
    use honk_outbound::proxy::PacketRejection;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for rejection in [PacketRejection::Policy, PacketRejection::Capacity] {
        let node = udp_test_node();
        let group = Group {
            name: "score".into(),
            policy: GroupPolicy::Score,
            nodes: vec![node.id],
            ..Default::default()
        };
        let manager = Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
            std::slice::from_ref(&group),
            std::slice::from_ref(&node),
        ))));
        let generation = Arc::new(parking_lot::RwLock::new(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                .unwrap(),
        )));
        let dials = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(UdpTestHandler {
            mode: UdpTestMode::CountDialError {
                dials: dials.clone(),
            },
        });
        let mut registry = ProxyRegistry::new();
        registry
            .register(ProtocolEntry::new(node.protocol(), handler.clone()).with_packet(handler));
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolver: crate::outbound::ResolveHook = {
            let resolutions = resolutions.clone();
            Arc::new(move |_, port| {
                let attempt = resolutions.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    if attempt < 2 {
                        Err(anyhow::Error::new(rejection).context("target resolution refused"))
                    } else {
                        Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
                    }
                })
            })
        };
        let target = QuicScoreProbeTarget::new(
            "https://quic.example:9443/".into(),
            Some(resolver),
            Arc::default(),
        );
        let error = target.resolve().await.err().expect("initial refusal");
        assert!(honk_outbound::proxy::is_packet_rejection(&error));
        let prober = ProxyUdpProber::new(
            Arc::new(RwLock::new(Arc::new(Config {
                nodes: vec![node.clone()],
                groups: vec![group],
                ..Default::default()
            }))),
            Arc::new(registry),
            generation,
            Arc::new(StatsManager::new()),
            UdpDnsProbeTarget::new(vec!["127.0.0.1:53".into()], None),
            Some(Arc::new(target)),
            manager,
        );

        let first = prober
            .probe_udp(
                node.id,
                Duration::from_secs(1),
                honk_outbound::alive::ProbeCancellation::default(),
            )
            .await;
        let error = first
            .data_path
            .expect("refusal must propagate")
            .unwrap_err();
        assert!(honk_outbound::proxy::is_packet_rejection(&error));
        assert_eq!(dials.load(Ordering::SeqCst), 1, "only DNS was dialed");

        let second = prober
            .probe_udp(
                node.id,
                Duration::from_secs(1),
                honk_outbound::alive::ProbeCancellation::default(),
            )
            .await;
        let error = second.data_path.expect("QUIC must be retried").unwrap_err();
        assert!(!honk_outbound::proxy::is_packet_rejection(&error));
        assert_eq!(resolutions.load(Ordering::SeqCst), 3);
        assert_eq!(dials.load(Ordering::SeqCst), 3, "DNS and QUIC were dialed");
    }
}

#[tokio::test]
async fn native_health_distinguishes_connect_and_http_for_duplicate_names() {
    use honk_outbound::alive::{AliveDialerSet, HealthState, HealthWarmth};
    struct NodeEndpoint;
    #[async_trait::async_trait]
    impl TcpOutbound for NodeEndpoint {
        async fn dial(
            &self,
            node: &Node,
            target: SocketAddr,
            _: Option<&str>,
            _: Duration,
        ) -> anyhow::Result<ProxyStream> {
            Ok(ProxyStream {
                stream: Box::new(tokio::net::TcpStream::connect(&node.address).await?),
                target_addr: target,
                target_domain: None,
            })
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let other = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut prober, _) = test_prober("HEAD");
    let mut node = prober.config.read().await.nodes[0].clone();
    node.address = addr.to_string();
    node.port = addr.port();
    node.id = node.derive_id();
    let mut duplicate = node.clone();
    duplicate.port = other.local_addr().unwrap().port();
    duplicate.address = other.local_addr().unwrap().to_string();
    duplicate.id = duplicate.derive_id();
    let nodes = vec![duplicate, node.clone()];
    prober.runtime_registry = Arc::new(parking_lot::RwLock::new(Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&nodes).unwrap(),
    )));
    prober.config = Arc::new(RwLock::new(Arc::new(Config {
        nodes,
        ..Config::default()
    })));
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(node.protocol(), Arc::new(NodeEndpoint)));
    prober.proxy_registry = Arc::new(registry);
    let alive = AliveDialerSet::new();
    alive.enable_health_history();
    alive.register_node(node.id, node.name.clone(), node.address.clone());
    let before = std::time::SystemTime::now();
    assert!(alive.probe_node(node.id, Duration::from_secs(1)).await);
    drop(listener.accept().await.unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for _ in 0..2 {
            read_request_head(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        }
    });
    alive
        .set_http_probe(Arc::new(prober), format!("http://{addr}/"), "HEAD".into())
        .await;
    assert!(alive.probe_node(node.id, Duration::from_secs(1)).await);
    finish_server(server).await;
    let samples = alive.health_observations(node.id);
    assert_eq!(samples.len(), 2);
    for sample in &samples {
        assert_eq!(sample.ip_version, IpVersion::V4);
        assert_eq!(sample.state, HealthState::Healthy);
        assert!(sample.latency.is_some());
        assert!(sample.observed_at >= before);
    }
    assert!(
        samples
            .iter()
            .any(|sample| sample.measurement == HealthMeasurement::TcpConnect
                && sample.warmth == HealthWarmth::Cold)
    );
    assert!(samples.iter().any(
        |sample| sample.measurement == HealthMeasurement::HttpHeaders
            && sample.warmth == HealthWarmth::Unknown
    ));
    assert_eq!(alive.health_observations(node.id), samples);
    assert!(!alive.probe_node(node.id, Duration::from_millis(50)).await);
    let failed = alive
        .health_observations(node.id)
        .into_iter()
        .find(|sample| sample.measurement == HealthMeasurement::HttpHeaders)
        .unwrap();
    assert_eq!(failed.state, HealthState::Unavailable);
    assert_eq!(failed.latency, None);
    assert_eq!(failed.error, Some("probe_failed"));
}

#[tokio::test]
async fn native_udp_dns_records_only_the_actual_target_family() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let mut buf = [0; 512];
        let (len, source) = server.recv_from(&mut buf).await.unwrap();
        buf[2] |= 0x80;
        server.send_to(&buf[..len], source).await.unwrap();
    });
    let node = Config::builtin_direct_node();
    let handler = Arc::new(honk_outbound::proxy::direct::DirectHandler::new());
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(node.protocol(), handler.clone()).with_packet(handler));
    let prober = ProxyUdpProber::new(
        Arc::new(RwLock::new(Arc::new(Config {
            nodes: vec![node.clone()],
            ..Config::default()
        }))),
        Arc::new(registry),
        Arc::new(parking_lot::RwLock::new(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                .unwrap(),
        ))),
        Arc::new(StatsManager::new()),
        UdpDnsProbeTarget::new(vec![target.to_string()], None),
        None,
        Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
            &[],
            std::slice::from_ref(&node),
        )))),
    );
    let before = std::time::SystemTime::now();
    let result = prober
        .probe_udp(
            node.id,
            Duration::from_secs(1),
            honk_outbound::alive::ProbeCancellation::default(),
        )
        .await;
    finish_server(peer).await;
    let sample = result.observations[0].unwrap();
    assert_eq!(sample.measurement, HealthMeasurement::DnsRoundTrip);
    assert_eq!(sample.ip_version, IpVersion::V4);
    assert!(sample.observed_at >= before);
    assert!(sample.latency.unwrap() <= result.dns.unwrap().unwrap());
    assert!(result.observations[1].is_none());
}

#[tokio::test]
async fn health_shutdown_closes_real_http_probe_without_failure_evidence() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (prober, node) = test_prober("HEAD");
        let alive = Arc::new(AliveDialerSet::new());
        alive.enable_health_history();
        alive.register_node(node, "probe".into(), addr.to_string());
        alive
            .set_http_probe(Arc::new(prober), format!("http://{addr}/"), "HEAD".into())
            .await;
        let request = tokio::spawn({
            let alive = Arc::clone(&alive);
            async move { alive.probe_node(node, Duration::from_secs(30)).await }
        });
        let (mut peer, _) = listener.accept().await.unwrap();
        read_request_head(&mut peer).await;
        alive.shutdown_health_checks().await.unwrap();
        assert!(!request.await.unwrap());
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        assert!(alive.health_observations(node).is_empty());
        assert!(
            alive
                .get_probe_history(node, ProbeDomain::Tcp, IpVersion::V4)
                .is_empty()
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn disabled_quic_probes_are_reported_while_a_score_group_needs_them() {
    use crate::degradations::{Component, Degradations};
    let degradations = Arc::new(Degradations::default());
    let reason = || {
        degradations
            .get(Component::QuicProbe)
            .map(|issue| issue.reason)
    };

    let plain = QuicScoreProbeTarget::new(
        "http://quic.example/".into(),
        None,
        Arc::clone(&degradations),
    );
    assert_eq!(reason(), Some("unsupported_url"));
    // A reload that drops the last Score group clears it; one that adds a
    // Score group back reports it again.
    plain.set_needed(false);
    assert_eq!(reason(), None);
    plain.set_needed(true);
    assert_eq!(reason(), Some("unsupported_url"));
    drop(plain);

    let unresolved: crate::outbound::ResolveHook =
        Arc::new(|_, _| Box::pin(async { Err(anyhow::anyhow!("no answer")) }));
    let target = QuicScoreProbeTarget::new(
        "https://quic.example/".into(),
        Some(unresolved),
        Arc::clone(&degradations),
    );
    assert!(target.resolve().await.unwrap().is_none());
    assert_eq!(reason(), Some("resolution_failed"));
    target.set_needed(false);
    assert_eq!(reason(), None);
    assert!(target.resolve().await.unwrap().is_none());
    assert_eq!(reason(), None, "an unneeded target stays unlisted");

    let literal = QuicScoreProbeTarget::new(
        "https://127.0.0.1:9443/".into(),
        None,
        Arc::clone(&degradations),
    );
    assert!(literal.resolve().await.unwrap().is_some());
    assert_eq!(reason(), None);
}
