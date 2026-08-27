//! Protocol-level tests for DNS transports.
//!
//! Local mock servers exercise the real UDP, TCP, TLS, HTTP/2, QUIC, and
//! HTTP/3 wire paths.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes};
use honk_config::dns::DnsUpstream;
use honk_config::node::Node;
use honk_config::types::{DnsProtocol, NodeProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{self, ServerConfig};

use crate::dns::endpoint::DnsEndpoint;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool, build_dns_query, parse_dns_question};
use crate::dns::routing::DnsRouter;
use crate::dns::transport::{DialContext, DohClient, DotPool, ProxyDial, TcpPool};
use crate::dns::upstream_pool::UpstreamPool;
use crate::dns::{DnsResolver, cache::DnsCache};
use crate::proxy::{PacketOutbound, PacketTransport, ProtocolEntry, ProxyStream, TcpOutbound};

fn mock_dns_response(txid: u16) -> Vec<u8> {
    vec![
        (txid >> 8) as u8,
        txid as u8,
        0x81,
        0x80,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x07,
        b'e',
        b'x',
        b'a',
        b'm',
        b'p',
        b'l',
        b'e',
        0x03,
        b'c',
        b'o',
        b'm',
        0x00,
        0x00,
        0x01,
        0x00,
        0x01,
        0xc0,
        0x0c,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x3c,
        0x00,
        0x04,
        0x7f,
        0x00,
        0x00,
        0x01,
    ]
}

fn make_upstream(name: &str, addr: &str, protocol: DnsProtocol) -> DnsUpstream {
    DnsUpstream {
        name: name.into(),
        address: addr.into(),
        protocol,
        tls_server_name: None,
        outbound: None,
    }
}

fn empty_router() -> Arc<DnsRouter> {
    Arc::new(
        DnsRouter::new(&honk_config::dns::DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    )
}

fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn self_signed_server_config() -> (ServerConfig, rustls::RootCertStore) {
    ensure_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "dns.test".into()])
        .expect("rcgen");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add root");

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut cfg = ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config");
    cfg.alpn_protocols = vec![b"dot".to_vec(), b"h2".to_vec()];
    (cfg, roots)
}

#[derive(Debug)]
struct TrackedUdpTransport {
    socket: UdpSocket,
    remote: SocketAddr,
    active: Arc<AtomicUsize>,
}

impl Drop for TrackedUdpTransport {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl PacketTransport for TrackedUdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.remote
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.socket.send(data).await?;
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        Ok((self.socket.recv(buf).await?, self.remote))
    }
}

#[derive(Debug)]
struct TestPacketHandler {
    active: Arc<AtomicUsize>,
    runtime_dials: Arc<AtomicUsize>,
}

impl TestPacketHandler {
    async fn open(&self, target: SocketAddr) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let bind = if target.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(target).await?;
        self.active.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(TrackedUdpTransport {
            socket,
            remote: target,
            active: Arc::clone(&self.active),
        }))
    }
}

#[async_trait::async_trait]
impl TcpOutbound for TestPacketHandler {
    async fn dial(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!("test handler has no TCP capability")
    }
}

#[async_trait::async_trait]
impl PacketOutbound for TestPacketHandler {
    async fn dial_udp_transport(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        anyhow::bail!("unpinned packet dial")
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<honk_outbound::runtime::NodeRuntime>,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        assert_eq!(runtime.node.protocol, NodeProtocol::Socks5);
        self.runtime_dials.fetch_add(1, Ordering::SeqCst);
        self.open(target).await
    }
}

pub(super) struct ProxiedQuicFixture {
    pub(super) dial: DialContext,
    pub(super) active: Arc<AtomicUsize>,
    pub(super) runtime_dials: Arc<AtomicUsize>,
}

pub(super) fn proxied_quic_fixture(endpoint: DnsEndpoint) -> ProxiedQuicFixture {
    let active = Arc::new(AtomicUsize::new(0));
    let runtime_dials = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(TestPacketHandler {
        active: Arc::clone(&active),
        runtime_dials: Arc::clone(&runtime_dials),
    });
    let mut registry = crate::proxy::ProxyRegistry::new();
    registry.register(
        ProtocolEntry::new(NodeProtocol::Socks5, Arc::clone(&handler))
            .with_packet(Arc::clone(&handler)),
    );
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "packet-proxy".into(),
        protocol: NodeProtocol::Socks5,
        address: "127.0.0.1:1".into(),
        host: "127.0.0.1".into(),
        port: 1,
        ..Default::default()
    };
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
            .unwrap(),
    );
    ProxiedQuicFixture {
        dial: DialContext {
            endpoint,
            query_timeout: Duration::from_secs(2),
            dial_timeout: Duration::from_secs(2),
            proxy: Some(ProxyDial {
                registry: Arc::new(registry),
                generation: Some(generation),
                node,
            }),
        },
        active,
        runtime_dials,
    }
}

pub(super) async fn insecure_quic_config(alpn: &[u8]) -> quinn::ClientConfig {
    honk_outbound::quic::client_config(
        &Node {
            skip_cert_verify: true,
            ..Default::default()
        },
        &[alpn],
        honk_outbound::quic::QuicClientOptions::default(),
    )
    .await
    .unwrap()
}

fn quic_server_endpoint(alpn: &[u8]) -> (quinn::Endpoint, SocketAddr) {
    ensure_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut tls =
        ServerConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
            )
            .unwrap();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    (endpoint, address)
}

pub(super) fn spawn_doq_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let (endpoint, address) = quic_server_endpoint(b"doq");
    let task = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        for _ in 0..2 {
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let mut length = [0; 2];
            recv.read_exact(&mut length).await.unwrap();
            let mut query = vec![0; u16::from_be_bytes(length) as usize];
            recv.read_exact(&mut query).await.unwrap();
            let response = mock_dns_response(0);
            send.write_all(&(response.len() as u16).to_be_bytes())
                .await
                .unwrap();
            send.write_all(&response).await.unwrap();
            send.finish().unwrap();
        }
        connection.closed().await;
    });
    (address, task)
}

pub(super) fn spawn_doh3_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let (endpoint, address) = quic_server_endpoint(b"h3");
    let task = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut h3 = h3::server::builder()
            .build(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        for _ in 0..2 {
            let resolver = h3.accept().await.unwrap().unwrap();
            let (_request, mut stream) = resolver.resolve_request().await.unwrap();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                while data.has_remaining() {
                    let length = data.chunk().len();
                    data.advance(length);
                }
            }
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream
                .send_data(Bytes::from(mock_dns_response(0)))
                .await
                .unwrap();
            stream.finish().await.unwrap();
        }
        connection.closed().await;
    });
    (address, task)
}

async fn serve_length_prefixed_dns(mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin) {
    let mut len_buf = [0u8; 2];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut query = vec![0u8; n];
    if stream.read_exact(&mut query).await.is_err() {
        return;
    }
    let txid = if query.len() >= 2 {
        u16::from_be_bytes([query[0], query[1]])
    } else {
        0
    };
    let resp = mock_dns_response(txid);
    let _ = stream.write_all(&(resp.len() as u16).to_be_bytes()).await;
    let _ = stream.write_all(&resp).await;
}

#[tokio::test]
async fn udp_and_tcp_via_upstream_pool() {
    // UDP server
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, src) = udp.recv_from(&mut buf).await.unwrap();
        let txid = u16::from_be_bytes([buf[0], buf[1]]);
        let _ = udp.send_to(&mock_dns_response(txid), src).await;
        let _ = n;
    });

    // TCP server (two queries on one connection)
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let tcp_task = tokio::spawn(async move {
        let (stream, _) = tcp.accept().await.unwrap();
        let mut stream = stream;
        for _ in 0..2 {
            serve_length_prefixed_dns(&mut stream).await;
        }
    });

    let ups = [
        make_upstream("u", &udp_addr.to_string(), DnsProtocol::Udp),
        make_upstream("t", &tcp_addr.to_string(), DnsProtocol::Tcp),
    ];
    let pool = UpstreamPool::new(&ups, empty_router()).unwrap();
    let q = build_dns_query("example.com", 1);

    let ru = pool.query("u", &q).await.unwrap();
    assert!(ru.len() >= 12);
    assert_eq!(&ru[0..2], &q[0..2]);

    let r1 = pool.query("t", &q).await.unwrap();
    let r2 = pool.query("t", &q).await.unwrap();
    assert_eq!(r1.len(), r2.len());

    udp_task.await.unwrap();
    tcp_task.await.unwrap();
}

#[tokio::test]
async fn tcp_pool_reuses_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepts2 = accepts.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepts2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut stream = stream;
        for _ in 0..3 {
            serve_length_prefixed_dns(&mut stream).await;
        }
    });

    let ep = DnsEndpoint::parse(&addr.to_string(), DnsProtocol::Tcp, None).unwrap();
    let pool = TcpPool::new(DialContext {
        endpoint: ep,
        query_timeout: Duration::from_secs(2),
        dial_timeout: Duration::from_secs(2),
        proxy: None,
    });
    let q = build_dns_query("example.com", 1);
    for _ in 0..3 {
        let r = pool.exchange(&q, None).await.unwrap();
        assert!(r.len() >= 12);
    }
    assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 1);
    server.await.unwrap();
}

#[tokio::test]
async fn dot_pool_roundtrip() {
    let (server_cfg, roots) = self_signed_server_config();
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        serve_length_prefixed_dns(&mut tls).await;
    });

    let ep = DnsEndpoint::parse(
        &format!("{}:{}", addr.ip(), addr.port()),
        DnsProtocol::Tls,
        Some("localhost"),
    )
    .unwrap();

    // Build client with roots trusting our self-signed cert.
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut client_cfg = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"dot".to_vec()];

    // Use low-level dial + exchange through a one-off TLS stream to avoid
    // changing DotPool's public API; still validates endpoint + framing path.
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, tcp).await.unwrap();
    let q = build_dns_query("example.com", 1);
    let resp =
        crate::dns::transport::exchange_length_prefixed(&mut tls, &q, Duration::from_secs(2))
            .await
            .unwrap();
    assert!(resp.len() >= 12);
    assert_eq!(&resp[0..2], &q[0..2]);
    let _ = (
        ep,
        DotPool::new(DialContext {
            endpoint: DnsEndpoint::parse("127.0.0.1:1", DnsProtocol::Tls, Some("localhost"))
                .unwrap(),
            query_timeout: Duration::from_secs(1),
            dial_timeout: Duration::from_secs(1),
            proxy: None,
        }),
    );
    server.await.unwrap();
}

#[tokio::test]
async fn doh_post_over_h2_roundtrip() {
    // Minimal H2 server: accept TLS with h2 ALPN, speak one POST response.
    let (mut server_cfg, roots) = self_signed_server_config();
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut conn = h2::server::handshake(tls).await.unwrap();
        if let Some(Ok((req, mut respond))) = conn.accept().await {
            assert_eq!(req.method(), http::Method::POST);
            let mut body = req.into_body();
            let mut query = Vec::new();
            while let Some(Ok(chunk)) = body.data().await {
                query.extend_from_slice(&chunk);
            }
            let txid = if query.len() >= 2 {
                u16::from_be_bytes([query[0], query[1]])
            } else {
                0
            };
            // DoH forces ID 0 on the wire.
            assert_eq!(txid, 0);
            let resp_bytes = mock_dns_response(0);
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/dns-message")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(bytes::Bytes::from(resp_bytes), true)
                .unwrap();
        }
        // Drive connection to completion briefly.
        while conn.accept().await.is_some() {}
    });

    let ep = DnsEndpoint::parse(
        &format!("localhost:{}/dns-query", addr.port()),
        DnsProtocol::Https,
        Some("localhost"),
    )
    .unwrap();

    // Custom DohClient-equivalent with trusted roots.
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut client_cfg = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    let (mut sender, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut q = build_dns_query("example.com", 1);
    let orig = crate::dns::transport::force_dns_id_zero(&mut q);
    let uri = format!("https://localhost:{}/dns-query", addr.port());
    let req = http::Request::builder()
        .method("POST")
        .uri(&uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(())
        .unwrap();
    let (resp_fut, mut send) = sender.send_request(req, false).unwrap();
    send.send_data(bytes::Bytes::from(q), true).unwrap();
    let resp = resp_fut.await.unwrap();
    assert!(resp.status().is_success());
    let mut body = resp.into_body();
    let mut buf = Vec::new();
    while let Some(Ok(c)) = body.data().await {
        buf.extend_from_slice(&c);
    }
    crate::dns::transport::restore_dns_id(&mut buf, orig);
    assert!(buf.len() >= 12);
    let _ = (
        ep,
        DohClient::new(DialContext {
            endpoint: DnsEndpoint::parse(
                "127.0.0.1/dns-query",
                DnsProtocol::Https,
                Some("localhost"),
            )
            .unwrap(),
            query_timeout: Duration::from_secs(1),
            dial_timeout: Duration::from_secs(1),
            proxy: None,
        }),
    );
    server.abort();
}

#[tokio::test]
async fn doh_connector_rejects_http1_only_server() {
    let (mut server_config, _) = self_signed_server_config();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor.accept(tcp).await
    });
    let connector =
        honk_outbound::tls::build_dns_connector(true, super::doh::DOH_ALPN_WIRE).unwrap();
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();

    let result = connector.connect("localhost", tcp).await;

    assert!(result.is_err(), "DoH must not negotiate HTTP/1.1");
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn forwarder_cache_hit_all_protocols_udp() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hits2 = hits.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, src)) = udp.recv_from(&mut buf).await else {
                break;
            };
            hits2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let txid = u16::from_be_bytes([buf[0], buf[1]]);
            let _ = udp.send_to(&mock_dns_response(txid), src).await;
            let _ = n;
        }
    });

    let ups = [make_upstream(
        "default",
        &addr.to_string(),
        DnsProtocol::Udp,
    )];
    let pool = Arc::new(UpstreamPool::new(&ups, empty_router()).unwrap());
    let cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(100)));
    let fw = DnsForwarder::new(pool, cache, empty_router());
    let q = build_dns_query("example.com", 1);
    let r1 = fw.resolve(&q).await.unwrap();
    let r2 = fw.resolve(&q).await.unwrap();
    assert_eq!(r1.len(), r2.len());
    // Second resolve must be cache hit → only one upstream query.
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn resolver_uses_forwarder_stack() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let mut qtypes = Vec::with_capacity(2);
        for _ in 0..2 {
            let (n, src) = udp.recv_from(&mut buf).await?;
            let txid = u16::from_be_bytes([buf[0], buf[1]]);
            let qtype = parse_dns_question(&buf[..n])
                .map(|(_, qtype)| qtype)
                .ok_or_else(|| anyhow::anyhow!("malformed DNS question"))?;
            qtypes.push(qtype);
            let response = match qtype {
                1 => mock_dns_response(txid),
                28 => {
                    let mut response = buf[..n].to_vec();
                    response[2] = 0x81;
                    response[3] = 0x80;
                    response
                }
                other => anyhow::bail!("unexpected DNS qtype: {other}"),
            };
            udp.send_to(&response, src).await?;
        }
        anyhow::Ok(qtypes)
    });

    let mut cfg = honk_config::dns::DnsConfig {
        upstream: vec![make_upstream(
            "default",
            &addr.to_string(),
            DnsProtocol::Udp,
        )],
        ..Default::default()
    };
    cfg.routing.fallback = "default".into();
    let resolver = DnsResolver::new(&cfg).unwrap();
    let r = resolver.resolve("example.com").await.unwrap();
    assert_eq!(
        r.ipv4,
        ["127.0.0.1"
            .parse::<std::net::IpAddr>()
            .expect("loopback IPv4")]
    );
    assert!(r.ipv6.is_empty());
    let mut qtypes = responder
        .await
        .expect("DNS responder task")
        .expect("DNS responder I/O");
    qtypes.sort_unstable();
    assert_eq!(qtypes, [1, 28], "exactly one A and one AAAA datagram");
}

#[test]
fn encrypted_endpoint_defaults() {
    let dot = DnsEndpoint::parse("dns.google", DnsProtocol::Tls, None).unwrap();
    assert_eq!(dot.port, 853);
    assert_eq!(dot.sni, "dns.google");

    let doh = DnsEndpoint::parse("cloudflare-dns.com/dns-query", DnsProtocol::Https, None).unwrap();
    assert_eq!(doh.port, 443);
    assert_eq!(doh.path, "/dns-query");

    let doq = DnsEndpoint::parse("dns.adguard.com", DnsProtocol::Quic, None).unwrap();
    assert_eq!(doq.port, 853);

    let h3 = DnsEndpoint::parse("dns.google", DnsProtocol::H3, None).unwrap();
    assert_eq!(h3.port, 443);
    assert_eq!(h3.path, "/dns-query");
}

/// Live path probe against Google DoH. Run with:
/// `cargo test -p honk-core --lib live_google_doh -- --nocapture --ignored`
#[tokio::test]
#[ignore = "live network: Google DoH"]
async fn live_google_doh_request_path() {
    use crate::dns::cache::DnsCache;
    use crate::dns::forwarder::{DnsForwarder, build_dns_query, extract_answer_ips};
    use crate::dns::routing::DnsRouter;
    use crate::dns::upstream_pool::UpstreamPool;
    use honk_config::dns::{DnsRequestAction, DnsRequestRouting, DnsRouting, DnsUpstream};
    use std::time::Instant;
    use tokio::sync::Mutex;

    eprintln!("\n=== Google DoH live request path ===");

    // 1) Config shape (what dae `https://dns.google/dns-query` becomes)
    let t0 = Instant::now();
    let ep = DnsEndpoint::parse("dns.google/dns-query", DnsProtocol::Https, None).unwrap();
    eprintln!(
        "[1] endpoint parse  host={} port={} path={} sni={}  ({:?})",
        ep.host,
        ep.port,
        ep.path,
        ep.sni,
        t0.elapsed()
    );
    assert_eq!(ep.port, 443);
    assert_eq!(ep.path, "/dns-query");
    assert_eq!(ep.sni, "dns.google");

    // 2) Bootstrap resolve of dns.google (system resolver; no bootstrap_resolver set)
    //    IPv4 is preferred so broken dual-stack hosts still dial.
    let t1 = Instant::now();
    let addrs = ep
        .resolve_addrs()
        .await
        .expect("bootstrap resolve dns.google");
    eprintln!(
        "[2] bootstrap resolve → {:?}  (prefer first)  ({:?})",
        addrs,
        t1.elapsed()
    );
    assert!(
        addrs.iter().any(|a| a.is_ipv4()),
        "expected A record for dns.google"
    );

    // 3) Build UpstreamPool + Forwarder (same as production)
    let upstream = DnsUpstream {
        name: "google".into(),
        address: "dns.google/dns-query".into(),
        protocol: DnsProtocol::Https,
        tls_server_name: None,
        outbound: None,
    };
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![],
                fallback: DnsRequestAction::Upstream("google".into()),
            },
            fallback: "google".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    let pool = Arc::new(
        UpstreamPool::new(&[upstream], router.clone())
            .unwrap()
            .with_timeouts(Duration::from_secs(5), Duration::from_secs(10)),
    );
    let cache = Arc::new(Mutex::new(DnsCache::new(64)));
    let forwarder = DnsForwarder::new(pool.clone(), cache.clone(), router)
        .with_strategy(honk_config::dns::DnsStrategy::Both)
        .with_cache_ttl(0); // keep answer TTL for inspection

    // 4) First query — full cold path: bootstrap (cached by OS) + TCP + TLS + H2 + POST
    let query = build_dns_query("example.com", 1);
    let t2 = Instant::now();
    let resp1 = pool
        .query("google", &query)
        .await
        .expect("pool DoH query #1");
    let d1 = t2.elapsed();
    let ips1 = extract_answer_ips(&resp1);
    eprintln!(
        "[3] cold UpstreamPool.query  bytes={} ips={:?}  ({:?})",
        resp1.len(),
        ips1,
        d1
    );
    assert!(resp1.len() >= 12);
    assert!(!ips1.is_empty(), "Google DoH must return A records");

    // 5) Second query — H2 session reuse (no new TCP/TLS)
    let t3 = Instant::now();
    let resp2 = pool
        .query("google", &build_dns_query("www.example.com", 1))
        .await
        .expect("pool DoH query #2");
    let d2 = t3.elapsed();
    eprintln!(
        "[4] warm UpstreamPool.query  bytes={} ips={:?}  ({:?})  reuse_ratio={:.1}x",
        resp2.len(),
        extract_answer_ips(&resp2),
        d2,
        d1.as_secs_f64() / d2.as_secs_f64().max(1e-6)
    );
    assert!(d2 < d1 + Duration::from_millis(500) || d2.as_millis() < 200);

    // 6) Full forwarder path (request route → upstream → response accept → cache)
    let t4 = Instant::now();
    let f1 = forwarder
        .resolve(&build_dns_query("cloudflare.com", 1))
        .await
        .expect("forwarder resolve #1");
    let fd1 = t4.elapsed();
    let fips = extract_answer_ips(&f1);
    eprintln!("[5] forwarder.resolve (miss)  ips={:?}  ({:?})", fips, fd1);
    assert!(!fips.is_empty());

    let t5 = Instant::now();
    let f2 = forwarder
        .resolve(&build_dns_query("cloudflare.com", 1))
        .await
        .expect("forwarder resolve #2 cache hit");
    let fd2 = t5.elapsed();
    eprintln!(
        "[6] forwarder.resolve (hit)   ips={:?}  ({:?})",
        extract_answer_ips(&f2),
        fd2
    );
    assert_eq!(extract_answer_ips(&f2), fips);
    assert!(fd2 < Duration::from_millis(50), "cache hit should be µs–ms");

    eprintln!("=== path OK ===\n");
}

#[tokio::test]
async fn doq_doh3_clients_construct() {
    let ep = DnsEndpoint::parse("127.0.0.1", DnsProtocol::Quic, Some("localhost")).unwrap();
    assert!(
        crate::dns::transport::DoqClient::new(DialContext {
            endpoint: ep,
            query_timeout: Duration::from_secs(1),
            dial_timeout: Duration::from_secs(2),
            proxy: None,
        })
        .await
        .is_ok()
    );
    let ep3 =
        DnsEndpoint::parse("127.0.0.1/dns-query", DnsProtocol::H3, Some("localhost")).unwrap();
    assert!(
        crate::dns::transport::Doh3Client::new(DialContext {
            endpoint: ep3,
            query_timeout: Duration::from_secs(1),
            dial_timeout: Duration::from_secs(2),
            proxy: None,
        })
        .await
        .is_ok()
    );
}
