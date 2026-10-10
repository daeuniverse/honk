mod http2;
#[cfg(feature = "flow-observation")]
mod native;
mod score;

use super::exchange::MAX_HTTP_RESPONSE_HEAD;
use super::*;
use crate::proxy::ProxyStream;
use honk_config::types::NodeProtocol;
use std::net::SocketAddr;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Mock handler: dials the requested target with a plain TcpStream
/// (no proxy protocol, no SO_MARK). Nodes named "bad" always fail.
struct MockHandler;

#[async_trait::async_trait]
impl TcpOutbound for MockHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        if node.name == "bad" {
            return Err(anyhow!("simulated dial failure"));
        }
        let stream = tokio::net::TcpStream::connect(target).await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

struct DelayedDialHandler {
    delay: Duration,
}

#[async_trait::async_trait]
impl TcpOutbound for DelayedDialHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        tokio::time::sleep(self.delay).await;
        let stream = tokio::net::TcpStream::connect(target).await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }
}

fn make_node(name: &str) -> Node {
    let host = format!("{name}.example");
    let mut node = Node {
        name: name.into(),
        address: format!("{host}:443"),
        host,
        port: 443,
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

struct RecordingWarmable {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    fail: bool,
    ephemeral: Arc<std::sync::atomic::AtomicBool>,
}

struct DelayedWarmable {
    delay: Duration,
}

#[async_trait::async_trait]
impl crate::proxy::WarmableOutbound for DelayedWarmable {
    async fn warm(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _connect_timeout: Duration,
        requirement: crate::proxy::WarmRequirement,
    ) -> anyhow::Result<()> {
        assert_eq!(requirement, crate::proxy::WarmRequirement::Session);
        tokio::time::sleep(self.delay).await;
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::proxy::WarmableOutbound for RecordingWarmable {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        _connect_timeout: Duration,
        requirement: crate::proxy::WarmRequirement,
    ) -> anyhow::Result<()> {
        assert_eq!(requirement, crate::proxy::WarmRequirement::Session);
        self.ephemeral
            .store(runtime.is_ephemeral(), std::sync::atomic::Ordering::Relaxed);
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.fail {
            return Err(std::io::Error::other("warm failure").into());
        }
        Ok(())
    }
}

fn reusable_node(name: &str, protocol: NodeProtocol) -> Node {
    let mut node = make_node(name);
    node.outbound = honk_config::node::OutboundConfig::from_protocol(protocol);
    let credential = "00000000-0000-4000-8000-000000000001".to_string();
    match &mut node.outbound {
        honk_config::node::OutboundConfig::Vmess(config) => config.uuid = Some(credential.clone()),
        honk_config::node::OutboundConfig::Vless(config) => {
            config.uuid = Some(credential.clone());
            config.multiplex = honk_config::node::VlessMultiplex::H2 { padding: false };
        }
        honk_config::node::OutboundConfig::Tuic(config) => config.uuid = Some(credential.clone()),
        honk_config::node::OutboundConfig::Juicity(config) => config.uuid = Some(credential),
        _ => {}
    }
    node.id = node.derive_id();
    node
}

#[test]
fn try_probe_runtime_reuses_only_warm_or_stateless_nodes() {
    let anytls = reusable_node("anytls", NodeProtocol::AnyTLS);
    let trojan = reusable_node("trojan", NodeProtocol::Trojan);
    let absent = reusable_node("absent", NodeProtocol::SS);
    let generation =
        crate::runtime::OutboundRuntimeRegistry::build(&[anytls.clone(), trojan.clone()]).unwrap();

    assert!(
        try_probe_runtime(&generation, &anytls, crate::proxy::WarmRequirement::Session)
            .unwrap()
            .1
            .is_some()
    );
    assert!(
        try_probe_runtime(&generation, &absent, crate::proxy::WarmRequirement::Session)
            .unwrap()
            .1
            .is_some()
    );
    let (runtime, guard) =
        try_probe_runtime(&generation, &trojan, crate::proxy::WarmRequirement::Session).unwrap();
    assert!(Arc::ptr_eq(&runtime, &generation.get(&trojan.id).unwrap()));
    assert!(guard.is_none());
}

#[test]
fn vless_probe_runtime_keeps_cold_udp_pool_ephemeral_without_penalizing_tcp() {
    use std::num::NonZeroU16;

    let mut node = reusable_node("vless-udp-probe", NodeProtocol::VLess);
    let honk_config::node::OutboundConfig::Vless(config) = &mut node.outbound else {
        unreachable!()
    };
    config.multiplex = honk_config::node::VlessMultiplex::Xray {
        tcp: None,
        udp: honk_config::node::VlessUdpMux::Separate(NonZeroU16::new(8).unwrap()),
        udp443: honk_config::node::Udp443Policy::Reject,
    };
    node.id = node.derive_id();
    let generation =
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();

    let (tcp, tcp_guard) =
        try_probe_runtime(&generation, &node, crate::proxy::WarmRequirement::Session).unwrap();
    assert!(Arc::ptr_eq(&tcp, &generation.get(&node.id).unwrap()));
    assert!(tcp_guard.is_none());
    let (udp, udp_guard) =
        try_probe_runtime(&generation, &node, crate::proxy::WarmRequirement::Udp).unwrap();
    assert!(!Arc::ptr_eq(&udp, &generation.get(&node.id).unwrap()));
    assert!(udp_guard.is_some());
}

async fn assert_cold_reusable_transport_warms_before_measurement(node: Node) {
    let addr = spawn_mock_http_server().await;
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ephemeral = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let warmable = RecordingWarmable {
        calls: Arc::clone(&calls),
        fail: false,
        ephemeral: Arc::clone(&ephemeral),
    };

    urltest_node_in_generation_impl(
        &generation,
        &node,
        &MockHandler,
        Some(&warmable),
        &format!("http://{addr}/"),
        Duration::from_secs(1),
        None,
        Default::default(),
    )
    .await
    .unwrap();

    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(ephemeral.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn cold_anytls_warms_before_measurement() {
    assert_cold_reusable_transport_warms_before_measurement(reusable_node(
        "anytls",
        NodeProtocol::AnyTLS,
    ))
    .await;
}

#[cfg(feature = "rprx")]
#[tokio::test]
async fn cold_vless_mux_warms_before_measurement() {
    assert_cold_reusable_transport_warms_before_measurement(reusable_node(
        "vless",
        NodeProtocol::VLess,
    ))
    .await;
}

#[tokio::test]
async fn cold_quic_protocols_warm_before_measurement() {
    for (name, protocol) in [
        ("hysteria2", NodeProtocol::Hysteria2),
        ("tuic", NodeProtocol::Tuic),
        ("juicity", NodeProtocol::Juicity),
    ] {
        assert_cold_reusable_transport_warms_before_measurement(reusable_node(name, protocol))
            .await;
    }
}

#[tokio::test]
async fn cold_quic_warm_time_is_not_reported() {
    let addr = spawn_mock_http_server().await;
    for (name, protocol) in [
        ("hysteria2", NodeProtocol::Hysteria2),
        ("tuic", NodeProtocol::Tuic),
        ("juicity", NodeProtocol::Juicity),
    ] {
        let node = reusable_node(name, protocol);
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let elapsed = urltest_node_in_generation_impl(
            &generation,
            &node,
            &MockHandler,
            Some(&DelayedWarmable {
                delay: Duration::from_millis(100),
            }),
            &format!("http://{addr}/"),
            Duration::from_secs(1),
            None,
            Default::default(),
        )
        .await
        .unwrap();

        assert!(elapsed < Duration::from_millis(50), "{name}: {elapsed:?}");
    }
}

#[cfg(feature = "rprx")]
#[tokio::test]
async fn cold_vless_mux_warm_failure_skips_measurement() {
    let node = reusable_node("vless", NodeProtocol::VLess);
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ephemeral = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let warmable = RecordingWarmable {
        calls: Arc::clone(&calls),
        fail: true,
        ephemeral: Arc::clone(&ephemeral),
    };

    let error = urltest_node_in_generation_impl(
        &generation,
        &node,
        &DelayedDialHandler {
            delay: Duration::from_secs(10),
        },
        Some(&warmable),
        "http://localhost/",
        Duration::from_millis(50),
        None,
        Default::default(),
    )
    .await
    .unwrap_err();

    assert!(error.downcast_ref::<std::io::Error>().is_some());
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(ephemeral.load(std::sync::atomic::Ordering::Relaxed));
}

struct RecordingHandler {
    target_domains: Arc<parking_lot::Mutex<Vec<Option<String>>>>,
    client_hellos: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

#[async_trait::async_trait]
impl TcpOutbound for RecordingHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.target_domains
            .lock()
            .push(target_domain.map(str::to_string));
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let client_hellos = self.client_hellos.clone();
        tokio::spawn(async move {
            let mut bytes = vec![0_u8; 16 * 1024];
            let size = server.read(&mut bytes).await.unwrap_or(0);
            bytes.truncate(size);
            let _ = client_hellos.send(bytes);
        });
        Ok(ProxyStream {
            stream: Box::new(client),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }
}

#[tokio::test]
async fn urltest_distinguishes_domain_and_address_targets() {
    let target_domains = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let (client_hellos, mut recorded_hellos) = tokio::sync::mpsc::unbounded_channel();
    let handler = RecordingHandler {
        target_domains: Arc::clone(&target_domains),
        client_hellos,
    };
    let node = make_node("recording");
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let url = "https://localhost/";

    let _ = urltest_node(&runtime, &handler, url, Duration::from_secs(2)).await;
    let domain_hello = tokio::time::timeout(Duration::from_secs(1), recorded_hellos.recv())
        .await
        .unwrap()
        .unwrap();
    let _ = urltest_node_addr(
        &runtime,
        &handler,
        url,
        "127.0.0.1:443".parse().unwrap(),
        Duration::from_secs(2),
    )
    .await;
    let address_hello = tokio::time::timeout(Duration::from_secs(1), recorded_hellos.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        *target_domains.lock(),
        vec![Some("localhost".to_string()), None]
    );
    for hello in [domain_hello, address_hello] {
        assert!(
            hello
                .windows(b"localhost".len())
                .any(|part| part == b"localhost")
        );
    }

    let (mut client, mut server) = tokio::io::duplex(1024);
    let server = tokio::spawn(async move {
        let mut request = [0_u8; 1024];
        let size = server.read(&mut request).await.unwrap();
        assert!(
            request[..size]
                .windows(b"Host: localhost\r\n".len())
                .any(|part| { part == b"Host: localhost\r\n" })
        );
        server
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let request = http_probe_request("http://localhost/", "").unwrap();
    exchange_http1(&mut client, &request, &None, Duration::from_secs(5), false)
        .await
        .unwrap();
    server.await.unwrap();
}

/// Spawn a minimal HTTP server answering every request with 204.
async fn spawn_mock_http_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                // Keep answering until the client closes: the measurement
                // sends a warm-up request before the timed one.
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if sock
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Legacy shape: one response per connection, then close — exercises the
/// single-exchange fallback.
async fn spawn_close_after_response_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    addr
}

async fn read_request_head<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 256];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let size = stream.read(&mut chunk).await.unwrap();
        assert_ne!(size, 0, "request closed before its header completed");
        request.extend_from_slice(&chunk[..size]);
    }
    request
}

#[tokio::test]
async fn http1_uses_configured_method_target_and_authority() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let warm = read_request_head(&mut server).await;
        assert!(warm.starts_with(b"HEAD /health/ready?source=urltest HTTP/1.1\r\n"));
        assert!(
            warm.windows(b"Host: probe.example:8080\r\n".len())
                .any(|part| part == b"Host: probe.example:8080\r\n")
        );
        server
                .write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </ready>\r\n\r\nHTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        let measured = read_request_head(&mut server).await;
        assert!(measured.starts_with(b"GET /health/ready?source=urltest HTTP/1.1\r\n"));
        assert!(
            measured
                .windows(b"Host: probe.example:8080\r\n".len())
                .any(|part| part == b"Host: probe.example:8080\r\n")
        );
        server
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let request = http_probe_request(
        "http://probe.example:8080/health/ready?source=urltest",
        "GET",
    )
    .unwrap();
    exchange_http1(&mut client, &request, &None, Duration::from_secs(1), false)
        .await
        .unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn partial_measured_response_timeout_is_not_a_fallback_success() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let peer = tokio::spawn(async move {
        let _ = read_request_head(&mut server).await;
        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
        let _ = read_request_head(&mut server).await;
        server
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\n")
            .await
            .unwrap();
        std::future::pending::<()>().await;
    });
    let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
    let result = exchange_http1(
        &mut client,
        &request,
        &None,
        Duration::from_millis(50),
        false,
    )
    .await;
    peer.abort();
    let _ = peer.await;
    assert!(
        result.is_err(),
        "partial response cannot become warm success"
    );
}

#[tokio::test]
async fn malformed_truncated_or_oversized_response_is_not_a_fallback_success() {
    for response in [
        b"not an HTTP response\r\n\r\n".to_vec(),
        b"HTTP/1.1 204 No Content\r\nContent-Len".to_vec(),
        format!(
            "HTTP/1.1 204 No Content\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(MAX_HTTP_RESPONSE_HEAD)
        )
        .into_bytes(),
    ] {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let _ = read_request_head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let _ = read_request_head(&mut server).await;
            let _ = server.write_all(&response).await;
        });
        let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
        assert!(
            exchange_http1(&mut client, &request, &None, Duration::from_secs(1), false)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn hysteria2_excludes_pre_write_dial_time() {
    let addr = spawn_mock_http_server().await;
    let node = Node::from_share_link("hysteria2://test@127.0.0.1:443").unwrap();
    let elapsed = urltest_node_addr(
        &crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap(),
        &DelayedDialHandler {
            delay: Duration::from_millis(100),
        },
        "http://localhost/",
        addr,
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    assert!(elapsed < Duration::from_millis(50), "{elapsed:?}");
}
#[test]
fn http_probe_request_preserves_uri_and_validates_inputs() {
    let request = http_probe_request("example.com:8443/ready,check?region=us,west", "GET").unwrap();
    assert_eq!(request.method(), http::Method::GET);
    assert_eq!(
        request.uri().to_string(),
        "https://example.com:8443/ready,check?region=us,west"
    );
    let target = request_target(&request).unwrap();
    assert_eq!(
        (
            target.host(),
            target.authority(),
            target.port(),
            target.is_https()
        ),
        ("example.com", "example.com:8443", 8443, true)
    );

    let ipv6 = http_probe_request("http://[::1]:8080/status?full=1", "").unwrap();
    assert_eq!(ipv6.method(), http::Method::HEAD);
    assert_eq!(ipv6.uri().authority().unwrap().as_str(), "[::1]:8080");
    let target = request_target(&ipv6).unwrap();
    assert_eq!(
        (target.host(), target.port(), target.is_https()),
        ("::1", 8080, false)
    );

    let health = health_http_probe_request("probe.example/ready,1.1.1.1", "").unwrap();
    assert_eq!(health.method(), http::Method::HEAD);
    assert_eq!(health.uri().to_string(), "http://probe.example/ready");

    assert_eq!(
        http_probe_request("", "").unwrap().uri().to_string(),
        DEFAULT_URLTEST_URL
    );
    assert!(http_probe_request("ftp://example.com/", "HEAD").is_err());
    assert!(http_probe_request("https://", "HEAD").is_err());
    assert!(http_probe_request("https://example.com:99999/", "HEAD").is_err());
    assert!(http_probe_request("https://example.com/", "GET\r\nInjected: yes").is_err());
    let error = http_probe_request("https:///u:PRIVATE@example.invalid/", "HEAD").unwrap_err();
    assert!(!format!("{error:#}").contains("PRIVATE"));
}

#[test]
fn c25_urltest_authority_boundaries() {
    for (input, expected) in [
        (
            "http://u:PRIVATE@host:8080/path?q#fragment",
            ("host", "host:8080", 8080, false, "/path?q"),
        ),
        ("https://host?q=1", ("host", "host", 443, true, "/?q=1")),
        (
            "http://[::1]:8080?q=1",
            ("::1", "[::1]:8080", 8080, false, "/?q=1"),
        ),
        (
            "http://host/a/../health?q=1",
            ("host", "host", 80, false, "/a/../health?q=1"),
        ),
    ] {
        let request = http_probe_request(input, "").unwrap();
        let target = request_target(&request).unwrap();
        assert_eq!(
            (
                target.host(),
                target.authority(),
                target.port(),
                target.is_https(),
                target.request_target(),
            ),
            expected
        );
        assert!(!request.uri().authority().unwrap().as_str().contains('@'));
    }
}

/// A server that closes after the first response still yields a sample:
/// the warm-up exchange's own time is reported.
#[tokio::test]
async fn test_exchange_http1_falls_back_when_server_closes() {
    let request = http_probe_request("http://localhost/", "").unwrap();
    let addr = spawn_close_after_response_server().await;
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    exchange_http1(&mut stream, &request, &None, Duration::from_secs(5), false)
        .await
        .expect("single-response server must fall back to the warm sample");
}

/// The reported sample excludes warm-up: a server that stalls only the
/// first response must still measure a fast second round trip.
#[tokio::test]
async fn test_exchange_http1_reports_warm_round_trip() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        for round in 0..2 {
            if sock.read(&mut buf).await.unwrap_or(0) == 0 {
                break;
            }
            if round == 0 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        }
    });
    let request = http_probe_request("http://localhost/", "").unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let measured = exchange_http1(&mut stream, &request, &None, Duration::from_secs(5), false)
        .await
        .unwrap();
    assert!(
        measured.latency < Duration::from_millis(100),
        "warm round trip must exclude the stalled first response: {measured:?}"
    );
}

/// The sample really is the second request, not min(#1, #2): a stall on
/// the second response must show up in the sample.
#[tokio::test]
async fn test_exchange_http1_reports_the_second_round_trip() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        for round in 0..2 {
            if sock.read(&mut buf).await.unwrap_or(0) == 0 {
                break;
            }
            if round == 1 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        }
    });
    let request = http_probe_request("http://localhost/", "").unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let measured = exchange_http1(&mut stream, &request, &None, Duration::from_secs(5), false)
        .await
        .unwrap();
    assert!(
        measured.latency >= Duration::from_millis(150),
        "the sample is the second request: {measured:?}"
    );
}

/// A bad status on the measured request fails the measurement; only a
/// lost connection or a timeout falls back to the warm sample.
#[tokio::test]
async fn test_exchange_http1_bad_status_on_second_request_fails() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        for round in 0..2 {
            if sock.read(&mut buf).await.unwrap_or(0) == 0 {
                break;
            }
            let response = if round == 0 {
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".as_slice()
            } else {
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".as_slice()
            };
            sock.write_all(response).await.unwrap();
        }
    });
    let request = http_probe_request("http://localhost/", "").unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert!(
        exchange_http1(&mut stream, &request, &None, Duration::from_secs(5), false)
            .await
            .is_err()
    );
}

/// A measured request that outlives its own budget falls back to the
/// warm sample instead of failing the whole measurement.
#[tokio::test]
async fn test_exchange_http1_slow_second_request_falls_back() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        for round in 0..2 {
            if sock.read(&mut buf).await.unwrap_or(0) == 0 {
                break;
            }
            if round == 1 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        }
    });
    let request = http_probe_request("http://localhost/", "").unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let measured = exchange_http1(
        &mut stream,
        &request,
        &None,
        Duration::from_millis(100),
        false,
    )
    .await
    .unwrap();
    assert!(
        measured.latency < Duration::from_millis(100),
        "timed-out measured request falls back to the warm sample: {measured:?}"
    );
    assert!(
        SystemTime::now()
            .duration_since(measured.observed_at)
            .unwrap()
            >= Duration::from_millis(90)
    );
}

/// Regression test for the plaintext-over-443 bug: an https URL must
/// run a real TLS handshake, so a plaintext HTTP server fails the
/// measurement instead of answering a cleartext HEAD.
#[tokio::test]
async fn test_urltest_node_https_requires_tls() {
    let addr = spawn_mock_http_server().await;
    let node = make_node("good");
    let handler = MockHandler;
    let url = format!("https://{}:{}/", addr.ip(), addr.port());

    let result = urltest_node(
        &crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap(),
        &handler,
        &url,
        Duration::from_secs(5),
    )
    .await;
    assert!(
        result.is_err(),
        "https measurement against a plaintext server must fail"
    );
}

#[tokio::test]
async fn test_urltest_node_failure() {
    // Nothing listens on 127.0.0.1:1 → dial fails.
    let node = make_node("good");
    let handler = MockHandler;
    let result = urltest_node(
        &crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap(),
        &handler,
        "https://127.0.0.1:1/",
        Duration::from_secs(2),
    )
    .await;
    assert!(result.is_err());

    // A node named "bad" fails inside the handler.
    let bad = make_node("bad");
    let result = urltest_node(
        &crate::runtime::NodeRuntime::try_ephemeral(&bad).unwrap(),
        &handler,
        "https://127.0.0.1:1/",
        Duration::from_secs(2),
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_urltest_group_does_not_penalize_resolver_rejection() {
    let _lock = super::resolver_hook_tests::RESOLVER_LOCK.lock().await;
    let hook: UrltestResolver = Arc::new(|host, port| {
        Box::pin(async move {
            if host == "rejected.invalid" {
                return Err(anyhow::Error::new(crate::proxy::PacketRejection::Policy));
            }
            tokio::net::lookup_host(format!("{host}:{port}"))
                .await
                .map(|addrs| addrs.collect())
                .map_err(anyhow::Error::from)
        })
    });
    let _reset = super::resolver_hook_tests::ResolverReset::install(hook);

    let member = make_node("rejected");
    let mut registry = ProxyRegistry::new();
    registry.register(crate::proxy::ProtocolEntry::new(
        NodeProtocol::Socks5,
        Arc::new(MockHandler),
    ));
    let registry = Arc::new(registry);
    let alive_set = Arc::new(AliveDialerSet::new());
    let runtime = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&member)).unwrap(),
    );

    for _ in 0..2 {
        let results = urltest_group_impl(
            std::slice::from_ref(&member),
            &runtime,
            &registry,
            &alive_set,
            "https://rejected.invalid/",
            Duration::from_millis(50),
            None,
            Default::default(),
        )
        .await;
        assert!(crate::proxy::is_packet_rejection(
            results[0].1.as_ref().expect_err("typed resolver rejection")
        ));
    }

    assert!(!alive_set.is_failure_demoted(member.id, ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(
        alive_set.get_last_latency(member.id, ProbeDomain::Tcp, IpVersion::V4),
        None
    );
}

#[tokio::test]
async fn urltest_group_failures_do_not_advance_real_dial_streaks() {
    let addr = spawn_mock_http_server().await;
    let url = format!("https://{}:{}/", addr.ip(), addr.port());
    let mut registry = ProxyRegistry::new();
    registry.register(crate::proxy::ProtocolEntry::new(
        NodeProtocol::Socks5,
        Arc::new(MockHandler),
    ));
    let registry = Arc::new(registry);
    let alive_set = Arc::new(AliveDialerSet::new());
    let members = vec![make_node("good"), make_node("bad")];
    for member in &members {
        alive_set.record_probe_latency(
            member.id,
            ProbeDomain::Tcp,
            IpVersion::V4,
            Duration::from_millis(999),
        );
    }
    let runtime = Arc::new(crate::runtime::OutboundRuntimeRegistry::build(&members).unwrap());
    for _ in 0..3 {
        let results = urltest_group_impl(
            &members,
            &runtime,
            &registry,
            &alive_set,
            &url,
            Duration::from_secs(5),
            None,
            Default::default(),
        )
        .await;
        assert_eq!(results.len(), members.len());
        assert_eq!(results[0].0, "good");
        assert_eq!(results[1].0, "bad");
        assert!(results.iter().all(|(_, result)| result.is_err()));
    }
    for member in &members {
        assert!(alive_set.is_alive_for(member.id, ProbeDomain::Tcp, IpVersion::V4));
        assert!(!alive_set.is_failure_demoted(member.id, ProbeDomain::Tcp, IpVersion::V4));
        assert_eq!(
            alive_set.get_last_latency(member.id, ProbeDomain::Tcp, IpVersion::V4),
            Some(Duration::from_millis(999)),
        );
        alive_set.record_dial_failure(member.id, ProbeDomain::Tcp, IpVersion::V4);
        assert!(!alive_set.is_failure_demoted(member.id, ProbeDomain::Tcp, IpVersion::V4));
        alive_set.record_dial_failure(member.id, ProbeDomain::Tcp, IpVersion::V4);
        assert!(alive_set.is_failure_demoted(member.id, ProbeDomain::Tcp, IpVersion::V4));
    }
}
