use super::*;
use honk_outbound::alive::{HttpProbeResult, HttpProber};
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

fn test_prober(method: &str) -> (ProxyHttpProber, String) {
    let mut node = Node {
        name: "http-probe-test".into(),
        address: "127.0.0.1:1".into(),
        host: "127.0.0.1".into(),
        port: 1,
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        ..Node::default()
    };
    node.id = node.derive_id();
    let node_name = node.name.clone();
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
        node_name,
    )
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
    let (prober, node_name) = test_prober("GET");

    let result = prober
        .probe_http(
            &node_name,
            addr,
            &format!("http://probe.invalid:{}/health", addr.port()),
            Duration::from_secs(1),
        )
        .await;

    finish_server(server).await;
    assert!(
        matches!(&result, HttpProbeResult::ExchangeFailure(_)),
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
        let (prober, node_name) = test_prober("HEAD");
        let result = prober
            .probe_http(&node_name, addr, &url, Duration::from_secs(2))
            .await;
        assert!(
            matches!(&result, HttpProbeResult::WarmSuccess(_)),
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
    let (prober, node_name) = test_prober("POST");

    let result = prober
        .probe_http(
            &node_name,
            addr,
            &format!(
                "probe.invalid:{}/ready/check?region=west,192.0.2.1,2001:db8::1",
                addr.port()
            ),
            Duration::from_secs(1),
        )
        .await;

    let [first, second] = finish_server(server).await;
    assert!(
        matches!(&result, HttpProbeResult::WarmSuccess(_)),
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
    let (prober, node_name) = test_prober("HEAD");

    let result = prober
        .probe_http(
            &node_name,
            addr,
            &format!("https://localhost:{}/secure", addr.port()),
            Duration::from_secs(1),
        )
        .await;

    let content_type = finish_server(server).await;
    assert!(matches!(&result, HttpProbeResult::ExchangeFailure(_)));
    assert_eq!(content_type, 22, "TLS handshake record expected");
}
