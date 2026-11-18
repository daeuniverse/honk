use super::*;
use crate::proxy::{AsyncReadWrite, PacketOutbound, ProtocolEntry, ProxyRegistry, node_failure};
use crate::runtime::OutboundRuntimeRegistry;
use crate::test_support::{
    assert_legacy_bulk_echo, chain, mock_legacy_tcp_server, node, socks5, socks5_relay,
};
use honk_config::node::OutboundConfig;
use honk_config::types::NodeProtocol;
use std::sync::Mutex;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// The Shadowsocks mock skips a 7-byte IPv4 target header.
const TARGET: &str = "93.184.216.34:80";

fn target() -> SocketAddr {
    TARGET.parse().unwrap()
}

fn shadowsocks(name: &str, host: &str, port: u16) -> Node {
    node(
        name,
        host,
        port,
        OutboundConfig::Shadowsocks(honk_config::node::ShadowsocksConfig {
            encryption: Some("aes-128-gcm".into()),
            password: Some("test-password".into()),
            ..Default::default()
        }),
    )
}

async fn shadowsocks_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(mock_legacy_tcp_server(stream));
        }
    });
    addr
}

async fn dial_chain(nodes: &[Node]) -> anyhow::Result<ProxyStream> {
    let generation = Arc::new(OutboundRuntimeRegistry::build(nodes).unwrap());
    ProxyRegistry::default_resolver()
        .unwrap()
        .dial_runtime(
            generation,
            nodes[0].id,
            target(),
            None,
            Duration::from_secs(3),
        )
        .await
}

#[tokio::test]
async fn socks5_front_carries_a_shadowsocks_exit() {
    let relay = socks5_relay(Vec::new(), false).await;
    let server = shadowsocks_server().await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = shadowsocks("land", "127.0.0.1", server.port());
    let mut stream = dial_chain(&[chain(&[&front, &land]), front, land])
        .await
        .unwrap();
    assert_legacy_bulk_echo(&mut stream.stream).await;
    assert_eq!(relay.requests(), [server.to_string()]);
    assert_eq!(stream.target_addr, target());
}

#[tokio::test]
async fn three_hops_leave_each_server_domain_to_the_hop_before() {
    let server = shadowsocks_server().await;
    let inner = socks5_relay(vec![("land.test", server)], false).await;
    let outer = socks5_relay(vec![("mid.test", inner.addr)], false).await;
    let front = socks5("front", "127.0.0.1", outer.addr.port());
    let mid = socks5("mid", "mid.test", inner.addr.port());
    let land = shadowsocks("land", "land.test", server.port());
    let mut stream = dial_chain(&[chain(&[&front, &mid, &land]), front, mid, land])
        .await
        .unwrap();
    assert_legacy_bulk_echo(&mut stream.stream).await;
    assert_eq!(
        outer.requests(),
        [format!("mid.test:{}", inner.addr.port())]
    );
    assert_eq!(inner.requests(), [format!("land.test:{}", server.port())]);
}

#[tokio::test]
async fn an_earlier_hop_target_failure_is_a_chain_failure() {
    let relay = socks5_relay(Vec::new(), true).await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = shadowsocks("land", "127.0.0.1", 9);
    let land_id = land.id;
    let error = dial_chain(&[chain(&[&front, &land]), front, land])
        .await
        .unwrap_err();
    assert!(!target_failure(&error), "{error:#}");
    assert!(node_failure(&error), "{error:#}");
    // The front answered; the hop it could not reach is the one that failed.
    assert_eq!(
        crate::proxy::failed_hop(&error).map(|failure| (failure.hop, failure.node)),
        Some((1, land_id)),
        "{error:#}"
    );
}

#[tokio::test]
async fn the_last_hop_target_failure_stays_a_target_failure() {
    let refusing = socks5_relay(Vec::new(), true).await;
    let relay = socks5_relay(Vec::new(), false).await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = socks5("land", "127.0.0.1", refusing.addr.port());
    let error = dial_chain(&[chain(&[&front, &land]), front, land])
        .await
        .unwrap_err();
    assert!(target_failure(&error), "{error:#}");
    assert_eq!(refusing.requests(), [TARGET]);
}

fn trojan_exit(name: &str, host: &str, port: u16) -> Node {
    node(
        name,
        host,
        port,
        OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            password: Some("secret".into()),
            tls: honk_config::node::TlsOptions {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        }),
    )
}

/// A plaintext Trojan server that answers a UDP associate by echoing its
/// frames, so each reply names the peer its request did.
async fn trojan_udp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                // hex(sha224) | CRLF | UDP ASSOCIATE | IPv4 target | CRLF
                let mut head = [0u8; 56 + 2 + 1 + 7 + 2];
                stream.read_exact(&mut head).await.unwrap();
                assert_eq!(head[58], 0x03);
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    addr
}

async fn dial_chain_udp(
    generation: &OutboundRuntimeRegistry,
    chain: &Node,
) -> anyhow::Result<Arc<dyn PacketTransport>> {
    let registry = ProxyRegistry::default_resolver().unwrap();
    let packet = Arc::clone(
        registry
            .find(NodeProtocol::Chain)
            .unwrap()
            .packet
            .as_ref()
            .unwrap(),
    );
    packet
        .dial_udp_transport_runtime(
            generation.get(&chain.id).unwrap(),
            target(),
            None,
            Duration::from_secs(3),
        )
        .await
}

async fn assert_udp_echo(transport: &dyn PacketTransport) {
    transport.send_packet(b"ping").await.unwrap();
    let mut buf = [0u8; 16];
    let (len, peer) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!((&buf[..len], peer), (&b"ping"[..], target()));
}

#[tokio::test]
async fn socks5_front_carries_a_trojan_udp_exit() {
    let relay = socks5_relay(Vec::new(), false).await;
    let server = trojan_udp_echo().await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = trojan_exit("land", "127.0.0.1", server.port());
    let via = chain(&[&front, &land]);
    let generation = OutboundRuntimeRegistry::build(&[via.clone(), front, land]).unwrap();
    let transport = dial_chain_udp(&generation, &via).await.unwrap();
    assert_udp_echo(transport.as_ref()).await;
    assert_eq!(relay.requests(), [server.to_string()]);
}

#[tokio::test]
async fn three_hops_carry_udp_to_the_exit() {
    let server = trojan_udp_echo().await;
    let inner = socks5_relay(vec![("land.test", server)], false).await;
    let outer = socks5_relay(vec![("mid.test", inner.addr)], false).await;
    let front = socks5("front", "127.0.0.1", outer.addr.port());
    let mid = socks5("mid", "mid.test", inner.addr.port());
    let land = trojan_exit("land", "land.test", server.port());
    let via = chain(&[&front, &mid, &land]);
    let generation = OutboundRuntimeRegistry::build(&[via.clone(), front, mid, land]).unwrap();
    let transport = dial_chain_udp(&generation, &via).await.unwrap();
    assert_udp_echo(transport.as_ref()).await;
    assert_eq!(inner.requests(), [format!("land.test:{}", server.port())]);
}

#[tokio::test]
async fn an_earlier_hop_target_failure_fails_a_udp_chain_at_the_next_hop() {
    let relay = socks5_relay(Vec::new(), true).await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = trojan_exit("land", "127.0.0.1", 9);
    let land_id = land.id;
    let via = chain(&[&front, &land]);
    let generation = OutboundRuntimeRegistry::build(&[via.clone(), front, land]).unwrap();
    let error = dial_chain_udp(&generation, &via).await.unwrap_err();
    assert!(!target_failure(&error), "{error:#}");
    assert!(node_failure(&error), "{error:#}");
    assert_eq!(
        crate::proxy::failed_hop(&error).map(|failure| (failure.hop, failure.node)),
        Some((1, land_id)),
        "{error:#}"
    );
}

#[cfg(feature = "rprx")]
#[tokio::test]
async fn socks5_front_carries_a_vless_native_udp_exit() {
    use tokio::io::AsyncWriteExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // version | uuid | addons | command | port | IPv4 target
        let mut head = [0u8; 26];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[18], 0x02);
        stream.write_all(&[0, 0]).await.unwrap();
        let (mut rd, mut wr) = stream.split();
        let _ = tokio::io::copy(&mut rd, &mut wr).await;
    });
    let relay = socks5_relay(Vec::new(), false).await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let mut land = Node::from_share_link(&format!(
        "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:{}?security=none",
        server.port()
    ))
    .unwrap();
    land.name = "land".into();
    let via = chain(&[&front, &land]);
    let generation = OutboundRuntimeRegistry::build(&[via.clone(), front, land]).unwrap();
    let transport = dial_chain_udp(&generation, &via).await.unwrap();
    assert_udp_echo(transport.as_ref()).await;
}

fn xudp_exit(name: &str) -> Node {
    node(
        name,
        "127.0.0.1",
        443,
        OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some("00000000-0000-4000-8000-000000000001".into()),
            udp_encoding: honk_config::node::VlessUdpEncoding::Xudp,
            ..Default::default()
        }),
    )
}

#[tokio::test]
async fn the_registry_dials_udp_for_a_chain_whose_exit_carries_it() {
    let relay = socks5_relay(Vec::new(), false).await;
    let server = trojan_udp_echo().await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = trojan_exit("land", "127.0.0.1", server.port());
    let via = chain(&[&front, &land]);
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[via.clone(), front, land]).unwrap());
    let transport = ProxyRegistry::default_resolver()
        .unwrap()
        .dial_udp_transport_runtime(generation, via.id, target(), None, Duration::from_secs(3))
        .await
        .unwrap();
    assert_udp_echo(transport.as_ref()).await;
}

/// The registry refuses a chain whose exit cannot carry UDP before dialing,
/// and the chain refuses it with a typed policy rejection when a caller such
/// as a probe skips that gate.
#[tokio::test]
async fn a_chain_whose_exit_cannot_carry_udp_refuses_udp() {
    let front = socks5("front", "127.0.0.1", 9);
    let land = xudp_exit("land");
    let via = chain(&[&front, &land]);
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[via.clone(), front, land]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();
    let error = registry
        .dial_udp_transport_runtime(
            Arc::clone(&generation),
            via.id,
            target(),
            None,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("UDP not supported"), "{error:#}");
    let packet = registry.find(NodeProtocol::Chain).unwrap().packet.clone();
    let error = packet
        .unwrap()
        .dial_udp_transport_runtime(
            generation.get(&via.id).unwrap(),
            target(),
            None,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
    assert_eq!(
        crate::proxy::packet_rejection(&error),
        Some(crate::proxy::PacketRejection::Policy),
        "{error:#}"
    );
}

/// A chain shares a source only through an exit whose protocol registers
/// the tunneled shared slot; the ordinary shared slot is not enough.
#[test]
fn only_registered_tunneled_shared_exits_share_a_source() {
    let front = socks5("front", "127.0.0.1", 9);
    let land = trojan_exit("land", "127.0.0.1", 443);
    let via = chain(&[&front, &land]);
    let generation = OutboundRuntimeRegistry::build(&[via.clone(), front, land]).unwrap();
    let runtime = generation.get(&via.id).unwrap();
    let trojan = Arc::new(crate::proxy::trojan::TrojanHandler::new());
    for tunneled in [false, true] {
        let mut entry = ProtocolEntry::new(NodeProtocol::Trojan, Arc::clone(&trojan))
            .with_packet(Arc::clone(&trojan))
            .with_shared(Arc::clone(&trojan));
        if tunneled {
            entry = entry.with_tunneled_shared(Arc::clone(&trojan));
        }
        let mut registry = ProxyRegistry::new();
        registry.register(entry);
        assert_eq!(registry.has_shared_source_for(&runtime), tunneled);
    }
}

/// A chain runtime built without its hops shares no source, though Chain
/// registers a shared slot.
#[tokio::test]
async fn a_hopless_chain_has_no_shared_source() {
    let via = chain(&[
        &socks5("front", "127.0.0.1", 9),
        &trojan_exit("land", "127.0.0.1", 443),
    ]);
    let registry = ProxyRegistry::default_resolver().unwrap();
    let held = crate::runtime::NodeRuntime::ephemeral_guarded_after_admission(&via);
    assert!(registry.has_shared_source(NodeProtocol::Chain));
    assert!(!registry.has_shared_source_for(&held.runtime()));
}

/// A generation decides a chain's UDP from its exit, for a configured chain
/// and a route through group exits alike.
#[test]
fn a_generation_takes_a_chain_udp_capability_from_its_exit() {
    let front = socks5("front", "127.0.0.1", 9);
    let trojan = trojan_exit("trojan", "127.0.0.1", 443);
    let xudp = xudp_exit("xudp");
    let mut via_trojan = chain(&[&front, &trojan]);
    via_trojan.name = "via-trojan".into();
    let mut via_xudp = chain(&[&front, &xudp]);
    via_xudp.name = "via-xudp".into();
    let generation = OutboundRuntimeRegistry::build(&[
        via_trojan.clone(),
        via_xudp.clone(),
        front.clone(),
        trojan.clone(),
        xudp.clone(),
    ])
    .unwrap();
    for (node, carries) in [(via_trojan, true), (via_xudp, false), (front.clone(), true)] {
        assert_eq!(generation.udp_capable(&node), carries, "{}", node.name);
        assert_eq!(
            generation.get(&node.id).unwrap().udp_capable,
            carries,
            "{}",
            node.name
        );
    }
    for (exit, carries) in [(&trojan, true), (&xudp, false)] {
        let honk_config::group_graph::Composed::Routed(route) =
            honk_config::group_graph::compose(front.id, &[front.id], [exit.id])
        else {
            panic!("expected a route");
        };
        let runtime = generation.route_runtime(&route).unwrap();
        assert_eq!(runtime.udp_capable, carries, "{}", exit.name);
    }
}

#[tokio::test]
async fn a_chain_without_its_generation_refuses_to_dial() {
    let front = socks5("front", "127.0.0.1", 1080);
    let land = shadowsocks("land", "127.0.0.1", 8388);
    let via = chain(&[&front, &land]);
    let handler = ChainHandler::new(Vec::new());
    assert!(
        handler
            .dial(&via, target(), None, Duration::from_secs(1))
            .await
            .is_err()
    );
    let runtime = NodeRuntime::try_ephemeral(&via).unwrap();
    assert!(
        handler
            .dial_runtime(runtime, target(), None, Duration::from_secs(1))
            .await
            .is_err()
    );
}

fn route(leaf: &Node, hops: &[&Node]) -> honk_config::route::Route {
    let ids: Vec<_> = hops.iter().map(|hop| hop.id).collect();
    let (exit, own) = ids.split_last().unwrap();
    match honk_config::group_graph::compose(leaf.id, own, [*exit]) {
        honk_config::group_graph::Composed::Routed(route) => route,
        other => panic!("expected a route, got {other:?}"),
    }
}

async fn dial_route(
    generation: &Arc<OutboundRuntimeRegistry>,
    route: &honk_config::route::Route,
) -> anyhow::Result<ProxyStream> {
    ProxyRegistry::default_resolver()
        .unwrap()
        .dial_ref(
            Arc::clone(generation),
            crate::proxy::DialRef::Route(route),
            target(),
            None,
            Duration::from_secs(3),
        )
        .await
}

#[tokio::test]
async fn a_route_dials_through_the_hop_runtimes_of_its_generation() {
    let relay = socks5_relay(Vec::new(), false).await;
    let server = shadowsocks_server().await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = shadowsocks("land", "127.0.0.1", server.port());
    let generation =
        Arc::new(OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap());
    let mut stream = dial_route(&generation, &route(&front, &[&front, &land]))
        .await
        .unwrap();
    assert_legacy_bulk_echo(&mut stream.stream).await;
    assert_eq!(relay.requests(), [server.to_string()]);
}

#[tokio::test]
async fn a_route_with_a_missing_hop_fails_closed() {
    let relay = socks5_relay(Vec::new(), false).await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = shadowsocks("land", "127.0.0.1", 8388);
    let generation =
        Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(&front)).unwrap());
    let error = dial_route(&generation, &route(&front, &[&front, &land]))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("route is not in runtime generation"),
        "{error:#}"
    );
    generation.begin_retirement();
    let full = Arc::new(OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap());
    full.begin_retirement();
    let error = dial_route(&full, &route(&front, &[&front, &land]))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("generation is shut down"),
        "{error:#}"
    );
    assert!(relay.requests().is_empty());
}

#[tokio::test]
async fn a_full_route_cache_still_dials_uncached() {
    let relay = socks5_relay(Vec::new(), false).await;
    let server = shadowsocks_server().await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = shadowsocks("land", "127.0.0.1", server.port());
    let generation =
        Arc::new(OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap());
    let mut leaf = front.clone();
    for index in 0..crate::runtime::MAX_ROUTE_RUNTIMES {
        leaf.id = uuid::Uuid::from_u128(index as u128 + 1);
        generation
            .route_runtime(&route(&leaf, &[&front, &land]))
            .unwrap();
    }
    let mut stream = dial_route(&generation, &route(&front, &[&front, &land]))
        .await
        .unwrap();
    assert_legacy_bulk_echo(&mut stream.stream).await;
    assert_eq!(relay.requests(), [server.to_string()]);
}

/// A dialed route stream holds its hops' resources, not the route runtime,
/// so it outlives a reload and the generation that cached the route.
#[tokio::test]
async fn a_route_flow_survives_reload_and_cache_drop() {
    let relay = socks5_relay(Vec::new(), false).await;
    let server = shadowsocks_server().await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = shadowsocks("land", "127.0.0.1", server.port());
    let nodes = [front.clone(), land.clone()];
    let old = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
    let route = route(&front, &[&front, &land]);
    let mut stream = dial_route(&old, &route).await.unwrap();
    let cached = Arc::downgrade(&old.route_runtime(&route).unwrap());
    let (new, _) = OutboundRuntimeRegistry::build_reusing(&nodes, 8, Some(&old)).unwrap();
    old.begin_retirement();
    drop(old);
    assert!(cached.upgrade().is_none());
    assert_legacy_bulk_echo(&mut stream.stream).await;
    let mut again = dial_route(&Arc::new(new), &route).await.unwrap();
    assert_legacy_bulk_echo(&mut again.stream).await;
}

/// Records how the chain drives each hop and answers with a pass-through stream.
#[derive(Default)]
struct FakeHop {
    calls: Mutex<Vec<Call>>,
    delay: Duration,
    /// Fail tunneled dials with a REALITY mask certificate while key shares are on.
    masked: bool,
    /// Fail every dial with this error.
    failure: Option<fn() -> anyhow::Error>,
    milestones: bool,
    /// The far ends of the streams runtime dials open, to watch them close.
    peers: Mutex<Vec<tokio::io::DuplexStream>>,
}

#[derive(Clone, Debug, PartialEq)]
struct Call {
    hop: String,
    target: SocketAddr,
    domain: Option<String>,
    timeout: Duration,
    key_shares: Option<bool>,
}

impl FakeHop {
    fn record(&self, runtime: &NodeRuntime, target: SocketAddr, domain: Option<&str>) -> Call {
        Call {
            hop: runtime.node.name.clone(),
            target,
            domain: domain.map(str::to_string),
            timeout: Duration::ZERO,
            key_shares: None,
        }
    }

    async fn act(
        &self,
        mut call: Call,
        stream: Box<dyn AsyncReadWrite>,
    ) -> anyhow::Result<ProxyStream> {
        let masked = self.masked && call.key_shares == Some(true);
        let target = call.target;
        call.hop.push_str(if call.key_shares.is_some() {
            "/over"
        } else {
            "/runtime"
        });
        self.calls.lock().unwrap().push(call);
        tokio::time::sleep(self.delay).await;
        if masked {
            return Err(crate::reality::RealityMaskCertificate.into());
        }
        if let Some(failure) = self.failure {
            return Err(failure());
        }
        if self.milestones {
            use crate::runtime::flow_observation::{Milestone, milestone};
            milestone(Milestone::TransportReady);
            milestone(Milestone::TargetRequestSent);
            milestone(Milestone::TargetConfirmed);
        }
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: None,
        })
    }
}

#[async_trait]
impl TcpOutbound for FakeHop {
    async fn dial(
        &self,
        node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        panic!("hop '{}' must dial through its runtime", node.name)
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let mut call = self.record(&runtime, target, target_domain);
        call.timeout = connect_timeout;
        let (stream, peer) = tokio::io::duplex(64);
        self.peers.lock().unwrap().push(peer);
        self.act(call, Box::new(stream)).await
    }

    async fn dial_over(
        &self,
        runtime: Arc<NodeRuntime>,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<ProxyStream> {
        let mut call = self.record(&runtime, target, target_domain);
        call.timeout = options.connect_timeout;
        call.key_shares = Some(options.reality_key_shares);
        self.act(call, carrier).await
    }
}

/// An exit's carrier held as a packet transport.
#[derive(Debug)]
struct CarrierPacket(#[allow(dead_code)] tokio::sync::Mutex<Box<dyn AsyncReadWrite>>);

#[async_trait]
impl PacketTransport for CarrierPacket {
    fn relay_addr(&self) -> SocketAddr {
        target()
    }

    async fn send_packet(&self, _data: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
}

#[async_trait]
impl PacketOutbound for FakeHop {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        panic!("hop '{}' must dial through the chain", node.name)
    }

    async fn dial_udp_over(
        &self,
        runtime: Arc<NodeRuntime>,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let mut call = self.record(&runtime, target, target_domain);
        call.timeout = options.connect_timeout;
        call.key_shares = Some(options.reality_key_shares);
        let stream = self.act(call, carrier).await?.stream;
        Ok(Arc::new(CarrierPacket(tokio::sync::Mutex::new(stream))))
    }
}

struct Fakes {
    generation: Arc<OutboundRuntimeRegistry>,
    via: Node,
    front: Arc<FakeHop>,
    land: Arc<FakeHop>,
}

impl Fakes {
    /// An AnyTLS front (a session protocol) and a Trojan exit at a domain.
    fn new(front: FakeHop, land: FakeHop) -> Self {
        let anytls = node(
            "front",
            "192.0.2.1",
            443,
            OutboundConfig::AnyTls(honk_config::node::AnyTlsConfig {
                password: Some("secret".into()),
                ..Default::default()
            }),
        );
        let trojan = node(
            "land",
            "land.example",
            443,
            OutboundConfig::Trojan(Default::default()),
        );
        let via = chain(&[&anytls, &trojan]);
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(&[via.clone(), anytls, trojan]).unwrap());
        Self {
            generation,
            via,
            front: Arc::new(front),
            land: Arc::new(land),
        }
    }

    fn handler(&self) -> ChainHandler {
        ChainHandler::new(vec![
            ProtocolEntry::new(NodeProtocol::AnyTLS, self.front.clone()),
            ProtocolEntry::new(NodeProtocol::Trojan, self.land.clone())
                .with_packet(self.land.clone()),
        ])
    }

    /// The chain dial for TCP, or for UDP when `udp` is set.
    async fn dial_on(&self, udp: bool, connect_timeout: Duration) -> anyhow::Result<()> {
        let runtime = self.generation.get(&self.via.id).unwrap();
        let domain = Some("example.com");
        if udp {
            self.handler()
                .dial_udp_transport_runtime(runtime, target(), domain, connect_timeout)
                .await
                .map(drop)
        } else {
            self.handler()
                .dial_runtime(runtime, target(), domain, connect_timeout)
                .await
                .map(drop)
        }
    }

    fn calls(&self) -> Vec<Call> {
        let mut calls = self.front.calls.lock().unwrap().clone();
        calls.extend(self.land.calls.lock().unwrap().iter().cloned());
        calls
    }
}

#[tokio::test]
async fn the_front_dials_its_own_runtime_toward_the_next_server() {
    for udp in [false, true] {
        let fakes = Fakes::new(FakeHop::default(), FakeHop::default());
        fakes.dial_on(udp, Duration::from_secs(1)).await.unwrap();
        let second = Duration::from_secs(1);
        assert_eq!(
            fakes.calls(),
            [
                Call {
                    hop: "front/runtime".into(),
                    target: "0.0.0.0:443".parse().unwrap(),
                    domain: Some("land.example".into()),
                    timeout: second,
                    key_shares: None,
                },
                Call {
                    hop: "land/over".into(),
                    target: target(),
                    domain: Some("example.com".into()),
                    timeout: second,
                    key_shares: Some(true),
                },
            ]
        );
    }
}

#[tokio::test]
async fn a_reality_mask_certificate_redials_the_chain_once_without_key_shares() {
    for udp in [false, true] {
        let fakes = Fakes::new(
            FakeHop::default(),
            FakeHop {
                masked: true,
                ..Default::default()
            },
        );
        fakes.dial_on(udp, Duration::from_secs(1)).await.unwrap();
        let hops: Vec<_> = fakes
            .calls()
            .into_iter()
            .map(|call| (call.hop, call.key_shares))
            .collect();
        assert_eq!(
            hops,
            [
                ("front/runtime".to_string(), None),
                ("front/runtime".to_string(), None),
                ("land/over".to_string(), Some(true)),
                ("land/over".to_string(), Some(false)),
            ]
        );
    }
}

/// The first hop dials its server directly, where a REALITY dial has already
/// retried once, so its mask certificate ends the chain dial.
#[tokio::test]
async fn a_reality_mask_certificate_on_the_first_hop_is_not_redialed() {
    for udp in [false, true] {
        let fakes = Fakes::new(
            FakeHop {
                failure: Some(|| crate::reality::RealityMaskCertificate.into()),
                ..Default::default()
            },
            FakeHop::default(),
        );
        let error = fakes
            .dial_on(udp, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(reality_mask_certificate(&error), "{error:#}");
        let hops: Vec<_> = fakes.calls().into_iter().map(|call| call.hop).collect();
        assert_eq!(hops, ["front/runtime"]);
    }
}

/// A packet policy rejection keeps its class whichever hop raises it.
#[tokio::test]
async fn packet_rejections_pass_through_the_chain_unchanged() {
    for udp in [false, true] {
        let rejection: fn() -> anyhow::Error = || crate::proxy::PacketRejection::Capacity.into();
        for (front, land) in [(Some(rejection), None), (None, Some(rejection))] {
            let fakes = Fakes::new(
                FakeHop {
                    failure: front,
                    ..Default::default()
                },
                FakeHop {
                    failure: land,
                    ..Default::default()
                },
            );
            let error = fakes
                .dial_on(udp, Duration::from_secs(1))
                .await
                .unwrap_err();
            assert_eq!(
                crate::proxy::packet_rejection(&error),
                Some(crate::proxy::PacketRejection::Capacity),
                "{error:#}"
            );
            assert!(!node_failure(&error), "{error:#}");
        }
    }
}

#[tokio::test]
async fn a_chain_failure_names_the_hop_that_failed() {
    for udp in [false, true] {
        let failure: fn() -> anyhow::Error = || anyhow::anyhow!("handshake failed");
        for (hop, front, land) in [(0, Some(failure), None), (1, None, Some(failure))] {
            let fakes = Fakes::new(
                FakeHop {
                    failure: front,
                    ..Default::default()
                },
                FakeHop {
                    failure: land,
                    ..Default::default()
                },
            );
            let error = fakes
                .dial_on(udp, Duration::from_secs(1))
                .await
                .unwrap_err();
            let hops = fakes.generation.get(&fakes.via.id).unwrap();
            assert_eq!(
                crate::proxy::failed_hop(&error).map(|failure| (failure.hop, failure.node)),
                Some((hop, hops.chain_hops()[hop].node.id)),
                "{error:#}"
            );
        }
    }
}

/// Dropping the dial once the front is up closes the front's connection and
/// returns every hop runtime it borrowed. The dial never finishes, so it
/// leaves no transport evidence for the chain or its hops.
#[tokio::test]
async fn dropping_the_dial_after_the_first_hop_releases_everything() {
    for udp in [false, true] {
        let fakes = Fakes::new(
            FakeHop::default(),
            FakeHop {
                delay: Duration::from_secs(3600),
                ..Default::default()
            },
        );
        let runtime = fakes.generation.get(&fakes.via.id).unwrap();
        let held = || {
            runtime
                .chain_hops()
                .iter()
                .map(Arc::strong_count)
                .collect::<Vec<_>>()
        };
        let before = held();
        tokio::time::timeout(Duration::from_secs(5), async {
            let dial = fakes.dial_on(udp, Duration::from_secs(1));
            tokio::pin!(dial);
            while fakes.land.calls.lock().unwrap().is_empty() {
                assert!(futures_util::poll!(&mut dial).is_pending());
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut peer = fakes.front.peers.lock().unwrap().pop().unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(held(), before);
        for hop in std::iter::once(&runtime).chain(runtime.chain_hops()) {
            assert!(
                hop.transport_quality()
                    .snapshot()
                    .iter()
                    .all(Option::is_none),
                "{}",
                hop.node.name
            );
        }
    }
}

/// Selector warm-up and preconnect pass over a chain: it has no session of
/// its own to warm and no bare socket to pool, and asking to warm it leaves
/// its session-protocol front cold.
#[tokio::test]
async fn warming_a_chain_does_not_apply_and_leaves_its_hops_cold() {
    use crate::proxy::{WarmOutcome, WarmRequirement};

    let fakes = Fakes::new(FakeHop::default(), FakeHop::default());
    let descriptor = crate::descriptor::descriptor(NodeProtocol::Chain);
    assert!(!(descriptor.pool_bare_tcp)(&fakes.via));
    assert!(!(descriptor.pool_ready_streams)(&fakes.via));
    assert!(!descriptor.supports_warm(&fakes.via, WarmRequirement::Session));
    let outcome = ProxyRegistry::default_resolver()
        .unwrap()
        .warm_session(
            Arc::clone(&fakes.generation),
            fakes.via.id,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, WarmOutcome::NotApplicable));
    let runtime = fakes.generation.get(&fakes.via.id).unwrap();
    assert!(!runtime.chain_hops()[0].is_warm_or_stateless_for(WarmRequirement::Session));
}

#[tokio::test(start_paused = true)]
async fn later_hops_get_what_remains_of_one_chain_deadline() {
    for udp in [false, true] {
        let fakes = Fakes::new(
            FakeHop {
                delay: Duration::from_millis(250),
                ..Default::default()
            },
            FakeHop::default(),
        );
        fakes
            .dial_on(udp, Duration::from_millis(100))
            .await
            .unwrap();
        let timeouts: Vec<_> = fakes.calls().into_iter().map(|call| call.timeout).collect();
        assert_eq!(
            timeouts,
            [Duration::from_millis(100), Duration::from_millis(50)]
        );
    }
}

#[tokio::test(start_paused = true)]
async fn the_chain_deadline_bounds_every_hop_together() {
    for udp in [false, true] {
        let fakes = Fakes::new(
            FakeHop {
                delay: Duration::from_millis(200),
                ..Default::default()
            },
            FakeHop {
                delay: Duration::from_millis(200),
                ..Default::default()
            },
        );
        let started = Instant::now();
        let error = fakes
            .dial_on(udp, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_millis(300));
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::TimedOut)
        );
    }
}

/// The whole chain runs inside the generation's dial scope. A generation that
/// retires while the front is still dialing gets the chain finished and then
/// dropped, front connection included, instead of handed out.
#[tokio::test(start_paused = true)]
async fn a_generation_shut_down_during_the_dial_publishes_nothing() {
    for udp in [false, true] {
        let fakes = Fakes::new(
            FakeHop {
                delay: Duration::from_millis(50),
                ..Default::default()
            },
            FakeHop::default(),
        );
        let handler = Arc::new(fakes.handler());
        let mut registry = ProxyRegistry::new();
        registry.register(
            ProtocolEntry::new(NodeProtocol::Chain, handler.clone()).with_packet(handler),
        );
        let generation = || Arc::clone(&fakes.generation);
        let dial = async {
            if udp {
                registry
                    .dial_udp_transport_runtime(
                        generation(),
                        fakes.via.id,
                        target(),
                        None,
                        Duration::from_secs(1),
                    )
                    .await
                    .map(drop)
            } else {
                registry
                    .dial_runtime(
                        generation(),
                        fakes.via.id,
                        target(),
                        None,
                        Duration::from_secs(1),
                    )
                    .await
                    .map(drop)
            }
        };
        let shutdown = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            fakes.generation.begin_retirement();
        };
        let (result, ()) = tokio::join!(dial, shutdown);
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("shut down during dial"),
            "{error:#}"
        );
        let hops: Vec<_> = fakes.calls().into_iter().map(|call| call.hop).collect();
        assert_eq!(hops, ["front/runtime", "land/over"]);
        let mut peer = fakes.front.peers.lock().unwrap().pop().unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
}

#[cfg(feature = "flow-observation")]
async fn observed_milestones(
    land_reports: bool,
) -> Vec<crate::runtime::flow_observation::Milestone> {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};

    let fakes = Fakes::new(
        FakeHop {
            milestones: true,
            ..Default::default()
        },
        FakeHop {
            milestones: land_reports,
            ..Default::default()
        },
    );
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&events);
    let observer = FlowObserver::new(
        FlowContext {
            flow_id: uuid::Uuid::nil(),
            generation: 0,
            attempt_id: None,
            lookup_id: None,
            dns_purpose: "",
        },
        Arc::new(move |_, event| {
            if let FlowEvent::Milestone { milestone } = event {
                log.lock().unwrap().push(milestone);
            }
        }),
    );
    observer
        .scope(fakes.dial_on(false, Duration::from_secs(1)))
        .await
        .unwrap();
    events.lock().unwrap().clone()
}

/// The front's transport readiness reaches the flow; its target milestones
/// describe the next hop's server and are dropped.
#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn only_the_last_hop_reports_target_milestones() {
    use crate::runtime::flow_observation::Milestone;

    assert_eq!(
        observed_milestones(false).await,
        [Milestone::TransportReady]
    );
    assert_eq!(
        observed_milestones(true).await,
        [
            Milestone::TransportReady,
            Milestone::TargetRequestSent,
            Milestone::TargetConfirmed,
        ]
    );
}

/// `Node::supports_tunneled_dial` in honk-config decides which hops
/// `validate_assembled` accepts; every registered handler must agree with it.
#[tokio::test]
async fn tunneled_dial_support_matches_the_config_table() {
    const UUID: &str = "00000000-0000-4000-8000-000000000001";
    let link = |link: &str| Node::from_share_link(link).unwrap();
    let rebuilt = |mut node: Node, change: &dyn Fn(&mut Node)| {
        change(&mut node);
        node.normalize_stream_transport().unwrap();
        node.id = node.derive_id();
        node
    };
    let vless = link(&format!(
        "vless://{UUID}@127.0.0.1:443?security=tls&sni=a.example"
    ));
    let mut vmess = socks5("vmess", "127.0.0.1", 443);
    vmess.outbound = OutboundConfig::Vmess(honk_config::node::VmessConfig {
        uuid: Some(UUID.into()),
        ..Default::default()
    });
    let vmess = rebuilt(vmess, &|_| {});
    let xhttp = |node: &mut Node| node.transport_mut().unwrap().transport = "xhttp".into();
    let nodes = [
        link("socks5://127.0.0.1:1080"),
        link("ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388"),
        link("trojan://secret@127.0.0.1:443?security=tls&sni=a.example"),
        link("trojan://secret@127.0.0.1:443?security=tls&sni=a.example&type=ws&path=%2Fws"),
        link("trojan://secret@127.0.0.1:443?security=tls&sni=a.example&type=xhttp&path=%2Fx"),
        vmess.clone(),
        rebuilt(vmess, &xhttp),
        vless.clone(),
        rebuilt(vless.clone(), &xhttp),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().flow = Some("xtls-rprx-vision".into())
        }),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().multiplex =
                honk_config::node::VlessMultiplex::H2 { padding: false }
        }),
        rebuilt(vless, &|node| {
            node.vless_mut().unwrap().encryption = Some("mlkem768x25519plus.native.0rtt.x".into())
        }),
        link("hysteria2://auth@127.0.0.1:443"),
        link(&format!("tuic://{UUID}:pass@127.0.0.1:443")),
        link(&format!("juicity://{UUID}:pass@127.0.0.1:443")),
        link("anytls://secret@127.0.0.1:443"),
    ];
    let registry = ProxyRegistry::default_resolver().unwrap();
    for node in nodes {
        // VLESS and VMess handlers exist only with the rprx feature.
        let Some(entry) = registry.find(node.protocol()) else {
            continue;
        };
        let runtime = NodeRuntime::try_ephemeral(&node).unwrap();
        let (carrier, _server) = tokio::io::duplex(1 << 16);
        let dial = entry.tcp.dial_over(
            runtime,
            Box::new(carrier),
            target(),
            None,
            TunnelDialOptions::new(Duration::from_millis(100)),
        );
        // A supported hop starts its handshake: it succeeds, fails on the
        // silent peer, or waits for it.
        let refused = matches!(
            tokio::time::timeout(Duration::from_millis(200), dial).await,
            Ok(Err(error)) if crate::proxy::tunnel_unsupported(&error)
        );
        assert_eq!(
            !refused,
            node.supports_tunneled_dial(),
            "{} {:?}",
            node.protocol().as_str(),
            node.outbound
        );
    }
}

/// `Node::supports_tunneled_udp` in honk-config decides which exits carry a
/// chain's UDP; every registered packet handler must agree with it.
#[tokio::test]
async fn tunneled_udp_support_matches_the_config_table() {
    use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpEncoding};
    const UUID: &str = "00000000-0000-4000-8000-000000000001";
    let link = |link: &str| Node::from_share_link(link).unwrap();
    let rebuilt = |mut node: Node, change: &dyn Fn(&mut Node)| {
        change(&mut node);
        node.id = node.derive_id();
        node
    };
    let vless = link(&format!(
        "vless://{UUID}@127.0.0.1:443?security=tls&sni=a.example"
    ));
    let trojan = link("trojan://secret@127.0.0.1:443?security=tls&sni=a.example");
    let nodes = [
        link("socks5://127.0.0.1:1080"),
        link("ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388"),
        trojan.clone(),
        rebuilt(trojan, &|node| {
            node.trojan_mut().unwrap().network = Some("tcp".into())
        }),
        link("trojan://secret@127.0.0.1:443?security=tls&sni=a.example&type=xhttp&path=%2Fx"),
        vless.clone(),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().udp_encoding = VlessUdpEncoding::Xudp
        }),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().udp_encoding = VlessUdpEncoding::UotV2
        }),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().multiplex = VlessMultiplex::H2 { padding: false }
        }),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().multiplex = VlessMultiplex::xray(-1, 0, Udp443Policy::Reject)
        }),
        rebuilt(vless, &|node| {
            node.vless_mut().unwrap().flow = Some("xtls-rprx-vision".into())
        }),
        link("hysteria2://auth@127.0.0.1:443"),
        link(&format!("tuic://{UUID}:pass@127.0.0.1:443")),
        link(&format!("juicity://{UUID}:pass@127.0.0.1:443")),
        link("anytls://secret@127.0.0.1:443"),
    ];
    let registry = ProxyRegistry::default_resolver().unwrap();
    for node in nodes {
        // VLESS handlers exist only with the rprx feature.
        let Some(entry) = registry.find(node.protocol()) else {
            continue;
        };
        // Plaintext, so a supported exit completes its handshake with the
        // peer below; TLS plays no part in the table. Vision needs TLS.
        let node = rebuilt(node, &|node| match &mut node.outbound {
            OutboundConfig::Trojan(trojan) => trojan.tls.enabled = false,
            OutboundConfig::Vless(vless) if vless.flow.is_none() => vless.tls.enabled = false,
            _ => {}
        });
        let supported = match &entry.packet {
            None => false,
            Some(packet) => {
                let runtime = NodeRuntime::try_ephemeral(&node).unwrap();
                let (carrier, mut server) = tokio::io::duplex(1 << 16);
                let dial = packet.dial_udp_over(
                    runtime,
                    Box::new(carrier),
                    target(),
                    None,
                    TunnelDialOptions::new(Duration::from_millis(100)),
                );
                match tokio::time::timeout(Duration::from_millis(500), dial).await {
                    Ok(Err(error)) if crate::proxy::tunnel_unsupported(&error) => false,
                    Ok(Ok(transport)) => {
                        transport.send_packet(b"ping").await.unwrap();
                        let wire = read_until_payload(&mut server, b"ping").await;
                        // The request asks the exit for UDP, not a stream.
                        let (offset, command) = match node.protocol() {
                            NodeProtocol::Trojan => (58, 0x03),
                            _ => (18, 0x02),
                        };
                        assert_eq!(wire[offset], command, "{}", node.protocol().as_str());
                        true
                    }
                    other => panic!(
                        "{} {:?}: neither a typed refusal nor a UDP handshake: {:?}",
                        node.protocol().as_str(),
                        node.outbound,
                        other.map(|result| result.map(drop))
                    ),
                }
            }
        };
        assert_eq!(
            supported,
            node.supports_tunneled_udp(),
            "{} {:?}",
            node.protocol().as_str(),
            node.outbound
        );
    }
}

/// What the client wrote to `server` up to and including `payload`.
async fn read_until_payload(server: &mut tokio::io::DuplexStream, payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    let mut buf = [0u8; 512];
    while !wire.ends_with(payload) {
        let read = tokio::time::timeout(Duration::from_secs(1), server.read(&mut buf))
            .await
            .expect("the exit sends the packet")
            .unwrap();
        assert!(read > 0, "the exit closed before sending the packet");
        wire.extend_from_slice(&buf[..read]);
    }
    wire
}
