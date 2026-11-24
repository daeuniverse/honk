//! Protocol-level tests for DNS transports.
//!
//! Local mock servers exercise the real UDP, TCP, TLS, HTTP/2, QUIC, and
//! HTTP/3 wire paths.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

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
use crate::dns::transport::{DialContext, ProxyDial, TcpPool};
use crate::dns::upstream_pool::UpstreamPool;
use crate::dns::{DnsResolver, cache::DnsCache};
use crate::proxy::{PacketOutbound, PacketTransport, ProtocolEntry, ProxyStream, TcpOutbound};

mod quic_lifecycle;

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

pub(super) fn self_signed_server_config() -> (ServerConfig, rustls::RootCertStore) {
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
    fault: Option<Arc<PacketWorkerFault>>,
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
        let _teardown = self.fault.as_ref().and_then(|fault| {
            fault.entered.notify_one();
            assert!(
                !fault.panic.swap(false, Ordering::AcqRel),
                "injected adapter panic"
            );
            fault
                .release
                .lock()
                .take()
                .map(|release| PacketWorkerTeardown {
                    fault: Arc::clone(fault),
                    release,
                })
        });
        Ok((self.socket.recv(buf).await?, self.remote))
    }
}

#[derive(Debug, Default)]
struct PacketWorkerFault {
    entered: tokio::sync::Notify,
    dropping: tokio::sync::Notify,
    release: parking_lot::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    completed: std::sync::atomic::AtomicBool,
    panic: std::sync::atomic::AtomicBool,
}

struct PacketWorkerTeardown {
    fault: Arc<PacketWorkerFault>,
    release: std::sync::mpsc::Receiver<()>,
}

impl Drop for PacketWorkerTeardown {
    fn drop(&mut self) {
        self.fault.dropping.notify_one();
        let _ = self.release.recv_timeout(Duration::from_secs(5));
        self.fault.completed.store(true, Ordering::Release);
    }
}

#[derive(Debug)]
struct TestPacketHandler {
    active: Arc<AtomicUsize>,
    runtime_dials: Arc<AtomicUsize>,
    protocol: NodeProtocol,
    fault: Option<Arc<PacketWorkerFault>>,
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
            fault: self.fault.clone(),
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
        assert_eq!(runtime.node.protocol(), self.protocol);
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
    proxied_quic_fixture_for_protocol(endpoint, NodeProtocol::Socks5, None)
}

fn proxied_quic_fixture_for_protocol(
    endpoint: DnsEndpoint,
    protocol: NodeProtocol,
    fault: Option<Arc<PacketWorkerFault>>,
) -> ProxiedQuicFixture {
    let active = Arc::new(AtomicUsize::new(0));
    let runtime_dials = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(TestPacketHandler {
        active: Arc::clone(&active),
        runtime_dials: Arc::clone(&runtime_dials),
        protocol,
        fault,
    });
    let mut registry = crate::proxy::ProxyRegistry::new();
    registry.register(
        ProtocolEntry::new(protocol, Arc::clone(&handler)).with_packet(Arc::clone(&handler)),
    );
    let mut node = Node {
        name: "packet-proxy".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
        address: "127.0.0.1:1".into(),
        host: "127.0.0.1".into(),
        port: 1,
        ..Default::default()
    };
    node.id = node.derive_id();
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
            .unwrap(),
    );
    ProxiedQuicFixture {
        dial: DialContext {
            endpoint,
            query_timeout: Duration::from_secs(2),
            dial_timeout: Duration::from_secs(2),
            socket_budget: Default::default(),
            proxy: Some(ProxyDial {
                registry: Arc::new(registry),
                generation: Some(generation),
                node,
                route: None,
            }),
        },
        active,
        runtime_dials,
    }
}

pub(super) async fn insecure_quic_config(alpn: &[u8]) -> quinn::ClientConfig {
    honk_outbound::quic::client_config(
        &Node {
            outbound: honk_config::node::OutboundConfig::Hysteria2(
                honk_config::node::Hysteria2Config {
                    quic: honk_config::node::QuicOptions {
                        tls: honk_config::node::TlsOptions {
                            skip_cert_verify: true,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            ..Default::default()
        },
        &[alpn],
        honk_outbound::quic::QuicClientOptions::default(),
    )
    .await
    .unwrap()
}

pub(super) fn quic_server_endpoint(alpn: &[u8]) -> (quinn::Endpoint, SocketAddr) {
    let (endpoint, address, _) = quic_server_with_roots(alpn);
    (endpoint, address)
}

fn quic_server_with_roots(alpn: &[u8]) -> (quinn::Endpoint, SocketAddr, rustls::RootCertStore) {
    let (mut tls, roots) = self_signed_server_config();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    (endpoint, address, roots)
}

pub(super) fn spawn_doq_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let (endpoint, address) = quic_server_endpoint(b"doq");
    let task = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        for _ in 0..2 {
            serve_one_doq_response(&connection).await;
        }
        connection.closed().await;
    });
    (address, task)
}

async fn serve_one_doq_response(connection: &quinn::Connection) -> Vec<u8> {
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    let mut length = [0; 2];
    recv.read_exact(&mut length).await.unwrap();
    let mut query = vec![0; u16::from_be_bytes(length) as usize];
    recv.read_exact(&mut query).await.unwrap();
    let mut response = query.clone();
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    send.write_all(&(response.len() as u16).to_be_bytes())
        .await
        .unwrap();
    send.write_all(&response).await.unwrap();
    send.finish().unwrap();
    query
}

#[tokio::test]
async fn quic_dns_queries_distinguish_exit_refusals_from_packet_dials() {
    use honk_config::Config;
    use honk_config::node::Group;
    use honk_outbound::group::GroupManager;
    use honk_outbound::proxy::{PacketRejection, packet_rejection};
    use honk_outbound::runtime::OutboundRuntimeRegistry;

    for (protocol, alpn) in [
        (DnsProtocol::Quic, &b"doq"[..]),
        (DnsProtocol::H3, &b"h3"[..]),
    ] {
        let (peer, address) = quic_server_endpoint(alpn);
        let target = address.to_string();
        let fixture =
            proxied_quic_fixture(DnsEndpoint::parse(&target, protocol, Some("localhost")).unwrap());
        let proxy = fixture.dial.proxy.unwrap();
        let relay = crate::test_support::socks5_relay().await;
        let exit = Node::from_share_link(&format!("trojan://secret@{}#exit", relay.addr)).unwrap();
        let block = Config::builtin_block_node();
        let group = |name: &str, member, has_exit: bool, final_outbound: Option<&str>| Group {
            name: name.into(),
            nodes: vec![member],
            exit: has_exit.then(|| exit.name.clone()),
            final_outbound: final_outbound.map(str::to_owned),
            ..Default::default()
        };
        let groups = [
            group("through-exit", proxy.node.id, true, None),
            group("block-member", block.id, true, None),
            group("block-final", proxy.node.id, true, Some("block")),
            group("allowed", proxy.node.id, false, None),
            Group {
                name: "fallback".into(),
                policy: honk_config::group::GroupPolicy::Fallback,
                groups: vec!["through-exit".into(), "allowed".into()],
                ..Default::default()
            },
        ];
        let upstreams = groups.each_ref().map(|group| DnsUpstream {
            tls_server_name: Some("localhost".into()),
            outbound: Some(group.name.clone()),
            ..make_upstream(&group.name, &target, protocol)
        });
        let nodes = vec![proxy.node, exit, block];
        let generation = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
        let manager = Arc::new(GroupManager::new(&groups, &nodes));
        let pool = UpstreamPool::new_with_proxy(
            &upstreams,
            empty_router(),
            Some(proxy.registry),
            nodes,
            Vec::from(groups),
        )
        .unwrap()
        .with_group_manager_snapshot(manager)
        .with_socket_budget(super::DnsSocketBudget::new(4))
        .with_timeouts(Duration::from_secs(2), Duration::from_secs(2));
        pool.set_runtime_generation(generation).unwrap();

        let query = build_dns_query("example.com", 1);
        let error = pool.query("through-exit", &query).await.unwrap_err();
        assert_eq!(packet_rejection(&error), None, "{protocol:?}: {error:#}");
        assert!(error.to_string().contains("no available node"), "{error:#}");
        for group in ["block-member", "block-final"] {
            let error = pool.query(group, &query).await.unwrap_err();
            assert_eq!(
                packet_rejection(&error),
                Some(PacketRejection::Policy),
                "{protocol:?}/{group}: {error:#}"
            );
        }
        assert_eq!(pool.lifecycle_stats().init_count, 0);
        assert_eq!(fixture.runtime_dials.load(Ordering::SeqCst), 0);
        assert!(relay.requests.lock().is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), peer.accept())
                .await
                .is_err(),
            "{protocol:?}: an exit refusal reached the QUIC peer"
        );

        let (result, handshakes) = tokio::time::timeout(Duration::from_secs(6), async {
            tokio::join!(pool.query("fallback", &query), async {
                let mut connections = [None, None];
                for slot in &mut connections {
                    let connection = slot.insert(peer.accept().await.unwrap().accept().unwrap());
                    let handshake = connection
                        .handshake_data()
                        .await
                        .unwrap()
                        .downcast::<quinn::crypto::rustls::HandshakeData>()
                        .unwrap();
                    assert_eq!(handshake.protocol.as_deref(), Some(alpn));
                }
                connections
            })
        })
        .await
        .expect("the eligible packet sibling must reach the peer and retry once");
        // TLS unknown_ca (48) from the ordinary production certificate check.
        let unknown_ca = quinn::TransportErrorCode::crypto(48);
        let error = result.expect_err("server certificate must be verified");
        assert!(
            error.chain().any(|cause| matches!(
                cause.downcast_ref::<quinn::ConnectionError>(),
                Some(quinn::ConnectionError::TransportError(error)) if error.code == unknown_ca
            )),
            "{protocol:?}: {error:#}"
        );
        drop(handshakes);
        assert_eq!(fixture.runtime_dials.load(Ordering::SeqCst), 2);
        assert_eq!(pool.lifecycle_stats().init_count, 1);
        pool.close().await;
        assert_eq!(pool.lifecycle_stats().close_count, 1);
        assert_eq!(fixture.active.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn packet_dns_returns_verified_replies_via_selected_sibling_and_native_collapse() {
    use crate::test_support::routed_udp::{PASSWORD, Peer, trojan_quic_peer};
    use honk_config::group::{Group, GroupPolicy};
    use honk_outbound::{group::GroupManager, runtime::OutboundRuntimeRegistry};

    for (protocol, alpn) in [
        (DnsProtocol::Quic, b"doq".as_slice()),
        (DnsProtocol::H3, b"h3".as_slice()),
    ] {
        let (endpoint, address, roots) = quic_server_with_roots(alpn);
        let mut query = build_dns_query("example.com", 1);
        query[..2].copy_from_slice(&[0x12, 0x34]);
        let mut expected = query.clone();
        expected[..2].fill(0);
        let mut answer = expected.clone();
        answer[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let mut h3;
                let received = if protocol == DnsProtocol::Quic {
                    serve_one_doq_response(&conn).await
                } else {
                    h3 = h3::server::builder()
                        .build(h3_quinn::Connection::new(conn.clone()))
                        .await
                        .unwrap();
                    super::doh3::tests::respond_h3(&mut h3, 200, answer.clone()).await
                };
                assert_eq!(received, expected);
                conn.closed().await;
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = listener.local_addr().unwrap();
        let mut exit =
            Node::from_share_link(&format!("trojan://{PASSWORD}@{exit_addr}#land")).unwrap();
        exit.tls_mut().unwrap().enabled = false;
        exit.id = exit.derive_id();
        let peer = Peer::start(listener, move |stream, _| trojan_quic_peer(stream, address));
        let forbidden_entry = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = Node::from_share_link(&format!(
            "socks5://{}#front",
            forbidden_entry.local_addr().unwrap()
        ))
        .unwrap();
        let groups = [
            Group {
                name: "composed".into(),
                nodes: vec![front.id],
                exit: Some(exit.name.clone()),
                ..Default::default()
            },
            Group {
                name: "sibling".into(),
                policy: GroupPolicy::Fallback,
                groups: vec!["composed".into(), "bare".into()],
                ..Default::default()
            },
            Group {
                name: "bare".into(),
                nodes: vec![exit.id],
                ..Default::default()
            },
            Group {
                name: "collapse".into(),
                nodes: vec![exit.id],
                exit: Some(exit.name.clone()),
                ..Default::default()
            },
        ];
        let target = address.to_string();
        let upstreams = ["sibling", "collapse"].map(|name| DnsUpstream {
            outbound: Some(name.into()),
            tls_server_name: Some("localhost".into()),
            ..make_upstream(name, &target, protocol)
        });
        let exit_id = exit.id;
        let nodes = vec![front, exit];
        let generation = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
        let manager = Arc::new(GroupManager::new(&groups, &nodes));
        let pool = UpstreamPool::new_with_proxy(
            &upstreams,
            empty_router(),
            Some(Arc::new(
                crate::proxy::ProxyRegistry::default_resolver().unwrap(),
            )),
            nodes,
            groups.to_vec(),
        )
        .unwrap()
        .with_group_manager_snapshot(manager)
        .with_timeouts(Duration::from_secs(2), Duration::from_secs(2));
        pool.set_runtime_generation(generation).unwrap();

        let mut tls = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![alpn.to_vec()];
        let config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        ));
        for upstream in ["sibling", "collapse"] {
            let dial = pool
                .selected_dial_context_for_test(upstream, address)
                .await
                .unwrap();
            let selected = dial.proxy.as_ref().unwrap();
            assert_eq!(selected.node.id, exit_id, "{protocol:?}/{upstream}");
            assert!(selected.route.is_none());
            let response = if protocol == DnsProtocol::Quic {
                let client = super::DoqClient::with_quic_config(dial, config.clone());
                let result = client.exchange(&query, None).await;
                client.close().await;
                result
            } else {
                let client = super::Doh3Client::with_quic_config(
                    dial,
                    config.clone(),
                    Arc::new(AtomicUsize::new(0)),
                );
                let result = client.exchange(&query, None).await;
                client.close().await;
                result
            }
            .unwrap();
            assert!(super::is_valid_response(&query, &response));
            assert_eq!(&response[..2], &query[..2]);
        }
        pool.close().await;
        peer.finish(2).await;
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), forbidden_entry.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn packet_dns_configured_chain_scores_only_attributed_setup_failures_hard() {
    use crate::test_support::routed_udp::{Peer, front};
    use honk_config::group::{Group, GroupPolicy};
    use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
    use honk_outbound::group::{GroupManager, ScoreSelectionContext, SelectionNetwork};
    use honk_outbound::proxy::{DialFailureScope, dial_failure_scope};
    use honk_outbound::runtime::OutboundRuntimeRegistry;

    for protocol in [DnsProtocol::Quic, DnsProtocol::H3] {
        for expected in [
            DialFailureScope::Unattributed,
            DialFailureScope::Prefix(1),
            DialFailureScope::Hop(0),
        ] {
            let unused_exit = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let exit_addr = unused_exit.local_addr().unwrap();
            let exit = Node::from_share_link(&format!("trojan://secret@{exit_addr}#land")).unwrap();
            let closed = tokio::net::TcpSocket::new_v4().unwrap();
            closed.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let (front_addr, peer) = if expected == DialFailureScope::Hop(0) {
                (closed.local_addr().unwrap(), None)
            } else {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let peer = Peer::start(listener, move |mut stream, _| async move {
                    if expected == DialFailureScope::Prefix(1) {
                        front(stream, exit_addr, true).await;
                    } else {
                        let mut greeting = [0; 3];
                        stream.read_exact(&mut greeting).await.unwrap();
                        assert_eq!(greeting, [5, 1, 0]);
                        stream.shutdown().await.unwrap();
                    }
                });
                (address, Some(peer))
            };
            let entry = Node::from_share_link(&format!("socks5://{front_addr}#front")).unwrap();
            let chain = Node::chain_from_nodes("via", &[&entry, &exit]).unwrap();
            let sibling = Node::from_share_link("socks5://127.0.0.1:9#sibling").unwrap();
            let sibling_id = sibling.id;
            let group = Group {
                name: "score".into(),
                policy: GroupPolicy::Score,
                nodes: vec![chain.id, sibling_id],
                ..Default::default()
            };
            let nodes = vec![entry, exit, chain, sibling];
            let alive = Arc::new(AliveDialerSet::new());
            for domain in [ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
                alive.report_unavailable_forced(sibling_id, domain, IpVersion::V4);
            }
            let groups = [group];
            let manager = Arc::new(GroupManager::with_alive_set(
                &groups,
                &nodes,
                Some(Arc::clone(&alive)),
            ));
            let upstream = DnsUpstream {
                outbound: Some("score".into()),
                ..make_upstream("score", "127.0.0.1:853", protocol)
            };
            let generation = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
            let pool = UpstreamPool::new_with_proxy(
                &[upstream],
                empty_router(),
                Some(Arc::new(
                    crate::proxy::ProxyRegistry::default_resolver().unwrap(),
                )),
                nodes,
                groups.to_vec(),
            )
            .unwrap()
            .with_group_manager_snapshot(Arc::clone(&manager));
            pool.set_runtime_generation(generation).unwrap();
            let query = build_dns_query("example.com", 1);
            for _ in 0..3 {
                let error = pool.query("score", &query).await.unwrap_err();
                assert_eq!(
                    dial_failure_scope(error.as_ref()),
                    expected,
                    "{protocol:?}: {error:#}"
                );
            }
            assert_eq!(
                manager
                    .score_budget_counters("score", SelectionNetwork::Udp)
                    .business_starts,
                3
            );
            alive.report_available_traffic(sibling_id, ProbeDomain::DataUdp, IpVersion::V4);
            let exclusions = || manager.score_reason_snapshot()[0].udp.fail_streak_excluded;
            let before = exclusions();
            let context = ScoreSelectionContext::aggregate(
                SelectionNetwork::Udp,
                ProbeDomain::DataUdp,
                IpVersion::V4,
            );
            drop(manager.selection_plan_for_target("score", &context));
            assert_eq!(
                exclusions() - before,
                u64::from(expected != DialFailureScope::Unattributed),
                "{protocol:?}/{expected:?}"
            );
            pool.close().await;
            if let Some(peer) = peer {
                peer.finish(6).await;
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(30), unused_exit.accept())
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn packet_dns_collapse_scores_exit_refusal_by_selected_member() {
    use honk_config::group::{Group, GroupPolicy};
    use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
    use honk_outbound::group::{GroupManager, ScoreSelectionContext, SelectionNetwork};
    use honk_outbound::runtime::OutboundRuntimeRegistry;

    let closed = tokio::net::TcpSocket::new_v4().unwrap();
    closed.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let exit = Node::from_share_link(&format!(
        "trojan://secret@{}#exit",
        closed.local_addr().unwrap()
    ))
    .unwrap();
    let relay = crate::test_support::socks5_relay().await;
    let prefix = Node::from_share_link(&format!("socks5://{}#prefix", relay.addr)).unwrap();
    let direct = honk_config::Config::builtin_direct_node();
    let group = |name: &str, id| Group {
        name: name.into(),
        policy: GroupPolicy::Score,
        nodes: vec![id, prefix.id],
        exit: Some(exit.name.clone()),
        ..Default::default()
    };
    let groups = [
        group("direct-collapse", direct.id),
        group("member-collapse", exit.id),
    ];
    let nodes = [direct, prefix, exit.clone()];
    for protocol in [DnsProtocol::Quic, DnsProtocol::H3] {
        let alive = Arc::new(AliveDialerSet::new());
        let manager = Arc::new(GroupManager::with_alive_set(
            &groups,
            &nodes,
            Some(Arc::clone(&alive)),
        ));
        manager.publish_route_health();
        let upstreams = groups.each_ref().map(|group| DnsUpstream {
            outbound: Some(group.name.clone()),
            ..make_upstream(&group.name, "127.0.0.1:853", protocol)
        });
        let pool = UpstreamPool::new_with_proxy(
            &upstreams,
            empty_router(),
            Some(Arc::new(
                crate::proxy::ProxyRegistry::default_resolver().unwrap(),
            )),
            nodes.to_vec(),
            groups.to_vec(),
        )
        .unwrap()
        .with_group_manager_snapshot(Arc::clone(&manager));
        pool.set_runtime_generation(Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap()))
            .unwrap();
        let query = build_dns_query("example.test", 1);
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Udp,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        for (group, expected_exclusions) in groups.iter().zip([0, 1]) {
            for _ in 0..3 {
                let error = pool.query(&group.name, &query).await.unwrap_err();
                assert!(
                    error.chain().any(|cause| cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::ConnectionRefused)),
                    "{protocol:?}: {error:#}"
                );
            }
            assert_eq!(
                manager
                    .score_budget_counters(&group.name, SelectionNetwork::Udp)
                    .business_starts,
                3
            );
            let exclusions = || {
                manager
                    .score_reason_snapshot()
                    .into_iter()
                    .find(|row| row.name == group.name)
                    .unwrap()
                    .udp
                    .fail_streak_excluded
            };
            let before = exclusions();
            drop(manager.selection_plan_for_target(&group.name, &context));
            assert_eq!(
                exclusions() - before,
                expected_exclusions,
                "{protocol:?} {}",
                group.name
            );
        }
        assert!(!alive.is_failure_demoted(exit.id, ProbeDomain::Tcp, IpVersion::V4));
        assert!(relay.requests.lock().is_empty());
        pool.close().await;
    }
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
        socket_budget: Default::default(),
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
async fn tls_length_prefixed_framing_roundtrip() {
    let (server_cfg, roots) = self_signed_server_config();
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        serve_length_prefixed_dns(&mut tls).await;
    });

    // Build client with roots trusting our self-signed cert.
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut client_cfg = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"dot".to_vec()];

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
    server.await.unwrap();
}

#[tokio::test]
async fn h2_post_dns_roundtrip() {
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
