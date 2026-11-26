use super::*;
use crate::group::ScoreOutcome;
use crate::proxy::{
    DialFailureScope, DialRef, NodeFailure, ProxyRegistry, TargetFailure, dial_failure_scope,
    failed_hop, node_failure, target_failure,
};
use crate::runtime::OutboundRuntimeRegistry;
use crate::test_support::{
    TCP_TARGET as TARGET, TCP_TARGET_HEADER, assert_legacy_bulk_echo, chain,
    mock_legacy_tcp_server, node, socks5, socks5_relay,
};
use honk_config::node::OutboundConfig;
use honk_config::types::NodeProtocol;
use std::sync::Mutex;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

mod failure_provenance;

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
            tokio::spawn(mock_legacy_tcp_server(stream, &TCP_TARGET_HEADER));
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
    let route = route(&front, &[&front, &land]);
    let generation =
        Arc::new(OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap());
    let error = dial_chain(&[chain(&[&front, &land]), front, land])
        .await
        .unwrap_err();
    assert!(!target_failure(&error), "{error:#}");
    assert!(node_failure(&error), "{error:#}");
    assert!(failed_hop(&error).is_none());
    assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::NodeFailure);
    assert!(error.chain().any(|cause| cause.is::<TargetFailure>()));

    let error = dial_route(&generation, &route).await.unwrap_err();
    assert_eq!(
        dial_failure_scope(error.as_ref()),
        DialFailureScope::Prefix(1)
    );
    assert_eq!(
        failed_hop(&error).map(|failure| (failure.hop, failure.node)),
        Some((1, route.exit())),
    );
    assert!(error.chain().any(|cause| cause.is::<TargetFailure>()));
}

#[tokio::test]
async fn internal_refusals_charge_the_configured_chain_but_boundary_refusals_do_not() {
    use crate::group::{OwnedTarget, RoutedTarget};
    use std::sync::atomic::Ordering;

    let ingress = socks5_relay(Vec::new(), true).await;
    let middle = socks5_relay(Vec::new(), true).await;
    let front = socks5("front", "127.0.0.1", ingress.addr.port());
    let mid = socks5("mid", "127.0.0.1", middle.addr.port());
    let exit = socks5("exit", "127.0.0.1", 9);
    let configured = chain(&[&front, &mid]);
    let route = route(&configured, &[&front, &mid, &exit]);
    let standalone = OwnedTarget::node(configured.clone());
    let mut routed = OwnedTarget::node(configured.clone());
    routed.route = Some(Box::new(RoutedTarget {
        route,
        hop_names: [front.name.clone(), mid.name.clone(), exit.name.clone()].into(),
    }));
    let generation =
        Arc::new(OutboundRuntimeRegistry::build(&[configured.clone(), front, mid, exit]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();
    for (owner_target, scope, owner) in [
        (
            &standalone,
            DialFailureScope::Prefix(1),
            Some(configured.id),
        ),
        (&routed, DialFailureScope::Prefix(1), Some(configured.id)),
        (&routed, DialFailureScope::Prefix(2), None),
    ] {
        ingress
            .refuse
            .store(scope == DialFailureScope::Prefix(1), Ordering::SeqCst);
        let error = registry
            .dial_ref(
                Arc::clone(&generation),
                owner_target.dial_ref(),
                target(),
                None,
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert_eq!(dial_failure_scope(error.as_ref()), scope);
        assert_eq!(owner_target.failure_owner(&error), owner);
    }
    assert_eq!(middle.requests(), ["127.0.0.1:9"]);
}

#[tokio::test]
async fn the_last_hop_target_failure_stays_a_target_failure() {
    let refusing = socks5_relay(Vec::new(), true).await;
    let relay = socks5_relay(Vec::new(), false).await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = socks5("land", "127.0.0.1", refusing.addr.port());
    let route = route(&front, &[&front, &land]);
    let generation =
        Arc::new(OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap());
    let error = dial_chain(&[chain(&[&front, &land]), front, land])
        .await
        .unwrap_err();
    assert!(target_failure(&error), "{error:#}");
    assert_eq!(
        ScoreOutcome::from_error(&error),
        ScoreOutcome::TargetFailure
    );
    let error = dial_route(&generation, &route).await.unwrap_err();
    assert_eq!(dial_failure_scope(error.as_ref()), DialFailureScope::Target);
    assert_eq!(failed_hop(&error).unwrap().node, route.exit());
    assert_eq!(refusing.requests(), [TARGET, TARGET]);
}

#[tokio::test]
async fn a_confirmed_socks_route_retains_splice_and_checks_generation() {
    let application = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = application.local_addr().unwrap();
    let ingress = socks5_relay(Vec::new(), false).await;
    let egress = socks5_relay(Vec::new(), false).await;
    let front = socks5("front", "127.0.0.1", ingress.addr.port());
    let exit = socks5("exit", "127.0.0.1", egress.addr.port());
    let route = route(&front, &[&front, &exit]);
    let incomplete = OutboundRuntimeRegistry::build(std::slice::from_ref(&exit)).unwrap();
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[front, exit]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();
    let stream = registry
        .dial_ref(
            Arc::clone(&generation),
            DialRef::Route(&route),
            destination,
            None,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert!(stream.into_tcp_stream().is_ok());
    assert_eq!(egress.requests(), [destination.to_string()]);
    let exit = DialRef::Node(route.exit());
    let dial = DialRef::Route(&route);
    assert!(registry.confirms_target_on_open(&generation, exit));
    assert!(registry.confirms_target_on_open(&generation, dial));
    assert!(!registry.confirms_target_on_open(&incomplete, dial));
    generation.begin_retirement();
    assert!(!registry.confirms_target_on_open(&generation, exit));
    assert!(!registry.confirms_target_on_open(&generation, dial));
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
async fn composed_udp_locates_codec_faults_but_not_partial_replies() {
    use tokio::io::AsyncWriteExt;

    let cases = [
        (NodeProtocol::Trojan, &b"\x09"[..], DialFailureScope::Hop(1)),
        (
            NodeProtocol::Trojan,
            &b"\x01\xc0"[..],
            DialFailureScope::Unattributed,
        ),
        (
            NodeProtocol::Trojan,
            &b"\x01\xc0\x00\x02\x01\x00\x35\x00\x00\rX"[..],
            DialFailureScope::Hop(1),
        ),
        (
            NodeProtocol::Trojan,
            &b"\x01\xc0\x00\x02\x01\x00\x35\x00\x00\r"[..],
            DialFailureScope::Unattributed,
        ),
        // A complete address and frame declaration that exceed this caller's receive buffer.
        (
            NodeProtocol::Trojan,
            &b"\x01\xc0\x00\x02\x01\x00\x35\x00\x20\r\n"[..],
            DialFailureScope::Unattributed,
        ),
        #[cfg(feature = "rprx")]
        (
            NodeProtocol::VLess,
            &b"\x01\x00"[..],
            DialFailureScope::Hop(1),
        ),
        #[cfg(feature = "rprx")]
        (
            NodeProtocol::VLess,
            &b"\x01"[..],
            DialFailureScope::Unattributed,
        ),
    ];
    for (protocol, wire, expected) in cases {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let relay = socks5_relay(Vec::new(), false).await;
            let front = socks5("front", "127.0.0.1", relay.addr.port());
            let (exit, header_len) = match protocol {
                NodeProtocol::Trojan => (trojan_exit("exit", "127.0.0.1", port), 68),
                _ => (
                    Node::from_share_link(&format!(
                        "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:{port}?security=none#exit",
                    ))
                    .unwrap(),
                    26,
                ),
            };
            let via = chain(&[&front, &exit]);
            let generation = OutboundRuntimeRegistry::build(&[via.clone(), front, exit]).unwrap();
            let peer = async {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.read_exact(&mut [0; 68][..header_len]).await.unwrap();
                stream.write_all(wire).await.unwrap();
                stream.shutdown().await.unwrap();
            };
            let (transport, ()) = tokio::join!(dial_chain_udp(&generation, &via), peer);
            let error = transport.unwrap().recv_packet(&mut [0; 16]).await.unwrap_err();
            assert_eq!(
                dial_failure_scope(&error),
                expected,
                "{protocol:?}: {error:#}"
            );
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn socks5_front_carries_a_trojan_udp_exit() {
    let relay = socks5_relay(Vec::new(), false).await;
    let server = trojan_udp_echo().await;
    let front = socks5("front", "127.0.0.1", relay.addr.port());
    let land = trojan_exit("land", "127.0.0.1", server.port());
    let via = chain(&[&front, &land]);
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[via.clone(), front, land]).unwrap());
    let handler = dial_chain_udp(&generation, &via).await.unwrap();
    assert_udp_echo(handler.as_ref()).await;
    let registry = ProxyRegistry::default_resolver().unwrap();
    let transport = registry
        .dial_udp_transport_runtime(generation, via.id, target(), None, Duration::from_secs(3))
        .await
        .unwrap();
    assert_udp_echo(transport.as_ref()).await;
    assert_eq!(relay.requests(), vec![server.to_string(); 2]);
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
async fn four_hop_configured_chain_and_nested_group_route_carry_udp() {
    tokio::time::timeout(Duration::from_secs(5), async {
        use crate::alive::{IpVersion, ProbeDomain};
        use crate::group::{GroupManager, ScoreSelectionContext, SelectionNetwork};
        use honk_config::group::Group;

        let server = trojan_udp_echo().await;
        let inner = socks5_relay(vec![("land.test", server)], false).await;
        let middle = socks5_relay(vec![("inner.test", inner.addr)], false).await;
        let outer = socks5_relay(vec![("middle.test", middle.addr)], false).await;
        let front = socks5("front", "127.0.0.1", outer.addr.port());
        let mid = socks5("middle", "middle.test", middle.addr.port());
        let next = socks5("inner", "inner.test", inner.addr.port());
        let land = trojan_exit("land", "land.test", server.port());
        let via = chain(&[&front, &mid, &next, &land]);
        let groups = [
            Group {
                name: "first".into(),
                nodes: vec![front.id],
                exit: Some(mid.name.clone()),
                ..Default::default()
            },
            Group {
                name: "second".into(),
                groups: vec!["first".into()],
                exit: Some(next.name.clone()),
                ..Default::default()
            },
            Group {
                name: "last".into(),
                groups: vec!["second".into()],
                exit: Some(land.name.clone()),
                ..Default::default()
            },
        ];
        let hops = [front.id, mid.id, next.id, land.id];
        let chain_id = via.id;
        let nodes = [via, front, mid, next, land];
        let manager = GroupManager::new(&groups, &nodes);
        let context = ScoreSelectionContext::aggregate(
            SelectionNetwork::Udp,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        let plan = manager.selection_plan_for_target("last", &context);
        let [entry] = plan.entries.as_slice() else {
            panic!("expected one route")
        };
        let route = entry.route.as_deref().unwrap();
        assert_eq!(route.hops(), hops);
        let generation = Arc::new(OutboundRuntimeRegistry::build(&nodes).unwrap());
        let registry = ProxyRegistry::default_resolver().unwrap();
        for dial in [DialRef::Node(chain_id), DialRef::Route(route)] {
            let timeout = Duration::from_secs(3);
            let transport = match dial {
                DialRef::Node(id) => {
                    registry
                        .dial_udp_transport_runtime(
                            Arc::clone(&generation),
                            id,
                            target(),
                            None,
                            timeout,
                        )
                        .await
                }
                DialRef::Route(route) => {
                    registry
                        .dial_udp_route(Arc::clone(&generation), route, target(), None, timeout)
                        .await
                }
            }
            .unwrap();
            for expected in [b"first".as_slice(), b"", b"second payload"] {
                transport.send_packet(expected).await.unwrap();
                let mut buffer = [0; 32];
                let (len, peer) = transport.recv_packet(&mut buffer).await.unwrap();
                assert_eq!((&buffer[..len], peer), (expected, target()));
            }
        }
        for (relay, host, port) in [
            (&outer, "middle.test", middle.addr.port()),
            (&middle, "inner.test", inner.addr.port()),
            (&inner, "land.test", server.port()),
        ] {
            assert_eq!(relay.requests(), vec![format!("{host}:{port}"); 2]);
        }
        generation.shutdown().await;
    })
    .await
    .expect("four-hop UDP round trip stalled");
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
    assert_eq!(
        crate::proxy::packet_rejection(&error),
        Some(PacketRejection::Policy)
    );
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
        assert_eq!(runtime.udp_capable(), carries, "{}", exit.name);
    }
}

#[tokio::test]
async fn a_chain_without_its_generation_refuses_to_dial() {
    let fakes = Fakes::new(FakeHop::default(), FakeHop::default());
    assert!(
        fakes
            .registry()
            .dial(&fakes.via, target(), None, Duration::from_secs(1))
            .await
            .is_err()
    );
    assert!(fakes.calls().is_empty());
    assert!(matches!(
        NodeRuntime::try_ephemeral(&fakes.via),
        Err(crate::runtime::RuntimeRegistryError::Admission(error))
            if error.diagnostic.code == "invalid-chain-hop-reference"
    ));
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
    for entries in [0, crate::runtime::MAX_ROUTE_RUNTIMES] {
        let relay = socks5_relay(Vec::new(), false).await;
        let server = shadowsocks_server().await;
        let front = socks5("front", "127.0.0.1", relay.addr.port());
        let land = shadowsocks("land", "127.0.0.1", server.port());
        let generation =
            Arc::new(OutboundRuntimeRegistry::build(&[front.clone(), land.clone()]).unwrap());
        let mut leaf = front.clone();
        for index in 0..entries {
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
    calls: Arc<Mutex<Vec<Call>>>,
    delay: Duration,
    /// Fail tunneled dials with a REALITY mask certificate while key shares are on.
    masked: bool,
    failure: Option<fn() -> anyhow::Error>,
    milestones: bool,
    /// The far ends of the streams runtime dials open, to watch them close.
    peers: Mutex<Vec<tokio::io::DuplexStream>>,
}

#[derive(Clone)]
struct Call {
    hop: String,
    runtime: std::sync::Weak<NodeRuntime>,
    target: SocketAddr,
    domain: Option<String>,
    timeout: Duration,
    key_shares: Option<bool>,
}

impl FakeHop {
    fn record(runtime: &Arc<NodeRuntime>, target: SocketAddr, domain: Option<&str>) -> Call {
        Call {
            hop: runtime.node.name.clone(),
            runtime: Arc::downgrade(runtime),
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
        let mut call = Self::record(&runtime, target, target_domain);
        call.timeout = connect_timeout;
        let (stream, peer) = crate::runtime::admit_physical_dial(async {
            Ok::<_, anyhow::Error>(tokio::io::duplex(64))
        })
        .await?;
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
        let mut call = Self::record(&runtime, target, target_domain);
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
        let mut call = Self::record(&runtime, target, target_domain);
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
    fn new(front: FakeHop, land: FakeHop) -> Self {
        Self::with_entry(socks5("front", "192.0.2.1", 443), front, land)
    }

    fn with_entry(entry: Node, front: FakeHop, mut land: FakeHop) -> Self {
        land.calls = Arc::clone(&front.calls);
        let trojan = node(
            "land",
            "land.example",
            443,
            OutboundConfig::Trojan(Default::default()),
        );
        let via = chain(&[&entry, &trojan]);
        let (generation, _) =
            OutboundRuntimeRegistry::build_reusing(&[via.clone(), entry, trojan], 1, None).unwrap();
        Self {
            generation: Arc::new(generation),
            via,
            front: Arc::new(front),
            land: Arc::new(land),
        }
    }

    fn registry(&self) -> ProxyRegistry {
        let mut registry = ProxyRegistry::new();
        registry.register(ProtocolEntry::new(NodeProtocol::Socks5, self.front.clone()));
        registry.register(
            ProtocolEntry::new(NodeProtocol::Trojan, self.land.clone())
                .with_packet(self.land.clone())
                .with_tunneled_packet(self.land.clone()),
        );
        registry.register_chain();
        registry
    }

    fn route(&self) -> honk_config::route::Route {
        let via = self.generation.get(&self.via.id).unwrap();
        let [front, land] = via.chain_hops() else {
            panic!("expected a two-hop chain");
        };
        route(&front.node, &[&front.node, &land.node])
    }

    async fn dial_ref(
        &self,
        dial: DialRef<'_>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.registry()
            .dial_ref(
                Arc::clone(&self.generation),
                dial,
                target(),
                Some("example.com"),
                connect_timeout,
            )
            .await
    }

    async fn dial_on(&self, udp: bool, connect_timeout: Duration) -> anyhow::Result<()> {
        self.dial_transport(DialRef::Node(self.via.id), udp, connect_timeout)
            .await
    }

    async fn dial_transport(
        &self,
        dial: DialRef<'_>,
        udp: bool,
        connect_timeout: Duration,
    ) -> anyhow::Result<()> {
        if !udp {
            return self.dial_ref(dial, connect_timeout).await.map(drop);
        }
        let registry = self.registry();
        let generation = Arc::clone(&self.generation);
        let domain = Some("example.com");
        match dial {
            DialRef::Node(id) => {
                registry
                    .dial_udp_transport_runtime(generation, id, target(), domain, connect_timeout)
                    .await
            }
            DialRef::Route(route) => {
                registry
                    .dial_udp_route(generation, route, target(), domain, connect_timeout)
                    .await
            }
        }
        .map(drop)
    }

    fn calls(&self) -> Vec<Call> {
        self.front.calls.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn ordinary_packet_registration_does_not_open_a_tunneled_udp_prefix() {
    let fakes = Fakes::new(FakeHop::default(), FakeHop::default());
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(
        NodeProtocol::Socks5,
        fakes.front.clone(),
    ));
    registry.register(
        ProtocolEntry::new(NodeProtocol::Trojan, fakes.land.clone())
            .with_packet(fakes.land.clone()),
    );
    registry.register_chain();
    let route = fakes.route();
    let timeout = Duration::from_secs(1);
    for error in [
        registry
            .dial_udp_transport_runtime(
                Arc::clone(&fakes.generation),
                fakes.via.id,
                target(),
                None,
                timeout,
            )
            .await
            .unwrap_err(),
        registry
            .dial_udp_route(
                Arc::clone(&fakes.generation),
                &route,
                target(),
                None,
                timeout,
            )
            .await
            .unwrap_err(),
    ] {
        assert!(crate::proxy::tunnel_unsupported(&error), "{error:#}");
        assert_eq!(
            dial_failure_scope(error.as_ref()),
            DialFailureScope::LocalRejection,
        );
    }
    assert!(fakes.calls().is_empty());
}

#[tokio::test]
async fn a_custom_socks_handler_does_not_get_stock_confirmation() {
    let custom = Arc::new(FakeHop::default());
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(NodeProtocol::Socks5, custom.clone()));
    registry.register(ProtocolEntry::new(
        NodeProtocol::Socks5,
        Arc::new(crate::proxy::socks5::Socks5Handler::new()),
    ));
    registry.register_chain();
    let front = socks5("front", "127.0.0.1", 1);
    let exit = socks5("exit", "127.0.0.1", 2);
    let route = route(&front, &[&front, &exit]);
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[front, exit]).unwrap());
    for dial in [DialRef::Node(route.exit()), DialRef::Route(&route)] {
        registry
            .dial_ref(
                Arc::clone(&generation),
                dial,
                target(),
                None,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert!(!registry.confirms_target_on_open(&generation, dial));
    }
    assert_eq!(custom.calls.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn the_front_dials_its_own_runtime_toward_the_next_server() {
    for udp in [false, true] {
        let fakes = Fakes::new(FakeHop::default(), FakeHop::default());
        let second = Duration::from_secs(1);
        fakes.dial_on(udp, second).await.unwrap();
        let calls = fakes.calls();
        let [front, land] = calls.as_slice() else {
            panic!(
                "expected one entry dial and one exit dial, got {}",
                calls.len()
            );
        };
        let via = fakes.generation.get(&fakes.via.id).unwrap();
        let hops = via.chain_hops();
        assert!(front.runtime.ptr_eq(&Arc::downgrade(&hops[0])));
        assert!(land.runtime.ptr_eq(&Arc::downgrade(&hops[1])));
        assert_eq!(front.hop, "front/runtime");
        assert_eq!(front.domain.as_deref(), Some("land.example"));
        assert_eq!(front.target, "0.0.0.0:443".parse().unwrap());
        assert_eq!((front.timeout, front.key_shares), (second, None));
        assert_eq!(land.hop, "land/over");
        assert_eq!(
            (land.target, land.domain.as_deref()),
            (target(), Some("example.com"))
        );
        assert_eq!((land.timeout, land.key_shares), (second, Some(true)));
    }
}

#[tokio::test]
async fn a_reality_mask_certificate_redials_once_with_fresh_physical_credits() {
    use futures_util::FutureExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for (routed, udp) in [(false, false), (true, false), (false, true), (true, true)] {
        let fakes = Fakes::new(
            FakeHop::default(),
            FakeHop {
                masked: true,
                ..Default::default()
            },
        );
        let route = fakes.route();
        let dial = if routed {
            DialRef::Route(&route)
        } else {
            DialRef::Node(fakes.via.id)
        };
        let starts = Arc::new(AtomicUsize::new(0));
        let scope = fakes.generation.dial_scope({
            let starts = Arc::clone(&starts);
            move || {
                starts.fetch_add(1, Ordering::Relaxed);
            }
        });
        scope
            .scope(fakes.dial_transport(dial, udp, Duration::from_secs(1)))
            .await
            .unwrap();
        let hops: Vec<_> = fakes
            .calls()
            .into_iter()
            .map(|call| (call.hop, call.key_shares))
            .collect();
        assert_eq!(
            hops,
            [
                ("front/runtime".to_string(), None),
                ("land/over".to_string(), Some(true)),
                ("front/runtime".to_string(), None),
                ("land/over".to_string(), Some(false)),
            ]
        );
        assert_eq!(starts.load(Ordering::Relaxed), 1);
        assert!(
            fakes
                .generation
                .acquire_dial_permit()
                .now_or_never()
                .is_some()
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
        if udp {
            assert_eq!(failed_hop(&error).unwrap().hop, 0);
            assert!(reality_mask_certificate(&error), "{error:#}");
        } else {
            assert!(
                error.is::<crate::reality::RealityMaskCertificate>(),
                "{error:#}"
            );
        }
        let hops: Vec<_> = fakes.calls().into_iter().map(|call| call.hop).collect();
        assert_eq!(hops, ["front/runtime"]);

        let fakes = Fakes::new(
            FakeHop {
                failure: Some(|| {
                    TargetFailure(crate::reality::RealityMaskCertificate.into()).into()
                }),
                ..Default::default()
            },
            FakeHop::default(),
        );
        let route = fakes.route();
        let error = fakes
            .dial_transport(DialRef::Route(&route), udp, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(failed_hop(&error).unwrap().hop, 1);
        assert!(reality_mask_certificate(&error));
        assert_eq!(fakes.calls().len(), 1);
    }
}

#[tokio::test]
async fn packet_rejections_pass_through_the_chain_unchanged() {
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
        let route = fakes.route();
        let configured = DialRef::Node(fakes.via.id);
        let routed = DialRef::Route(&route);
        for (dial, udp) in [
            (configured, false),
            (routed, false),
            (configured, true),
            (routed, true),
        ] {
            let error = fakes
                .dial_transport(dial, udp, Duration::from_secs(1))
                .await
                .unwrap_err();
            assert_eq!(
                crate::proxy::packet_rejection(&error),
                Some(crate::proxy::PacketRejection::Capacity),
                "{error:#}"
            );
            assert_eq!(
                dial_failure_scope(error.as_ref()),
                DialFailureScope::LocalRejection
            );
            assert!(!node_failure(&error), "{error:#}");
        }
    }
}

#[tokio::test]
async fn a_composed_failure_distinguishes_a_typed_hop_fault_from_ambiguous_io() {
    fn closed() -> anyhow::Error {
        io::Error::from(io::ErrorKind::UnexpectedEof).into()
    }
    let ambiguous: fn() -> anyhow::Error = closed;
    let carrier_fault: fn() -> anyhow::Error = || NodeFailure(closed()).into();
    let local: fn() -> anyhow::Error = || io::Error::from_raw_os_error(libc::EMFILE).into();
    for (hop, front, land, udp_scope, os_error) in [
        (
            0,
            Some(local),
            None,
            DialFailureScope::Unattributed,
            Some(libc::EMFILE),
        ),
        (
            0,
            Some(ambiguous),
            None,
            DialFailureScope::Unattributed,
            None,
        ),
        (0, Some(carrier_fault), None, DialFailureScope::Hop(0), None),
        (
            1,
            None,
            Some(ambiguous),
            DialFailureScope::Unattributed,
            None,
        ),
        (1, None, Some(carrier_fault), DialFailureScope::Hop(1), None),
    ] {
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
        let route = fakes.route();
        let routed = DialRef::Route(&route);
        for (dial, udp) in [
            (routed, false),
            (routed, true),
            (DialRef::Node(fakes.via.id), true),
        ] {
            let error = fakes
                .dial_transport(dial, udp, Duration::from_secs(1))
                .await
                .unwrap_err();
            assert_eq!(
                failed_hop(&error).map(|failure| (failure.hop, failure.node)),
                Some((hop, route.hops()[hop])),
                "{error:#}"
            );
            let expected = if !udp && hop == 0 {
                DialFailureScope::Hop(0)
            } else {
                udp_scope
            };
            assert_eq!(dial_failure_scope(error.as_ref()), expected, "{error:#}");
            let cause = error.root_cause().downcast_ref::<io::Error>().unwrap();
            assert_eq!(cause.raw_os_error(), os_error);
            if os_error.is_none() {
                assert_eq!(cause.kind(), io::ErrorKind::UnexpectedEof);
            }
        }
    }
}

/// A cancelled dial releases its carrier and leaves no transport evidence.
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
            while fakes.calls().len() < 2 {
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

#[tokio::test]
async fn cancelling_a_socks_chain_releases_its_credit_while_the_parent_scope_is_alive() {
    use futures_util::FutureExt as _;

    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let entry = socks5_relay(Vec::new(), false).await;
        let front = socks5("front", "127.0.0.1", entry.addr.port());
        let exit = socks5("exit", "127.0.0.1", listener.local_addr().unwrap().port());
        let via = chain(&[&front, &exit]);
        let via_id = via.id;
        let (generation, _) = OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            &[via, front, exit],
            1,
            1,
            1,
            false,
            None,
        )
        .unwrap();
        let generation = Arc::new(generation);
        let scope = generation.dial_scope(|| {});
        let dial = tokio::spawn({
            let scope = Arc::clone(&scope);
            let generation = Arc::clone(&generation);
            async move {
                let registry = ProxyRegistry::default_resolver().unwrap();
                scope
                    .scope(registry.dial_runtime(
                        generation,
                        via_id,
                        target(),
                        None,
                        Duration::from_secs(10),
                    ))
                    .await
            }
        });
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        peer.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        assert!(generation.acquire_dial_permit().now_or_never().is_none());

        dial.abort();
        assert!(dial.await.unwrap_err().is_cancelled());
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(generation.acquire_dial_permit().now_or_never().is_some());
        assert_eq!(
            entry.requests(),
            [listener.local_addr().unwrap().to_string()]
        );
        drop(scope);
    })
    .await
    .unwrap();
}

/// Only the individual hops own sessions that can be warmed.
#[tokio::test]
async fn warming_a_chain_does_not_apply_and_leaves_its_hops_cold() {
    use crate::proxy::{WarmOutcome, WarmRequirement};

    let entry = node(
        "front",
        "192.0.2.1",
        443,
        OutboundConfig::AnyTls(honk_config::node::AnyTlsConfig {
            password: Some("secret".into()),
            ..Default::default()
        }),
    );
    let fakes = Fakes::with_entry(entry, FakeHop::default(), FakeHop::default());
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

#[tokio::test(start_paused = true)]
async fn reality_retry_uses_the_original_chain_deadline() {
    for (routed, udp) in [(false, false), (true, false), (false, true), (true, true)] {
        let delay = Duration::from_millis(80);
        let fakes = Fakes::new(
            FakeHop {
                delay,
                ..Default::default()
            },
            FakeHop {
                delay,
                masked: true,
                ..Default::default()
            },
        );
        let route = fakes.route();
        let dial = if routed {
            DialRef::Route(&route)
        } else {
            DialRef::Node(fakes.via.id)
        };
        let started = Instant::now();
        let error = fakes
            .dial_transport(dial, udp, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_millis(300));
        assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::Timeout);
        assert_eq!(
            dial_failure_scope(error.as_ref()),
            DialFailureScope::Unattributed
        );
        assert!(failed_hop(&error).is_none());
        let calls = fakes.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[3].key_shares, Some(false));
        assert_eq!(calls[3].timeout, Duration::from_millis(60));
    }
}

/// The whole chain runs inside the generation's dial scope. A generation that
/// retires while the front is still dialing gets the chain finished and then
/// dropped, front connection included, instead of handed out.
#[tokio::test(start_paused = true)]
async fn a_generation_shut_down_during_the_dial_publishes_nothing() {
    for (routed, udp) in [(false, false), (true, false), (false, true), (true, true)] {
        let fakes = Fakes::new(
            FakeHop {
                delay: Duration::from_millis(50),
                ..Default::default()
            },
            FakeHop::default(),
        );
        let route = fakes.route();
        let dial = if routed {
            DialRef::Route(&route)
        } else {
            DialRef::Node(fakes.via.id)
        };
        let dial = fakes.dial_transport(dial, udp, Duration::from_secs(1));
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

fn unsupported_tunneled_nodes() -> Vec<Node> {
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
    let xhttp = |node: &mut Node| node.transport_mut().unwrap().transport = "xhttp".into();
    vec![
        link("trojan://secret@127.0.0.1:443?security=tls&sni=a.example&type=xhttp&path=%2Fx"),
        link("trojan://secret@127.0.0.1:443?ech=1&type=ws&host=a.example"),
        rebuilt(vmess, &xhttp),
        rebuilt(vless.clone(), &xhttp),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().flow = Some("xtls-rprx-vision".into())
        }),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().multiplex =
                honk_config::node::VlessMultiplex::H2 { padding: false }
        }),
        rebuilt(vless.clone(), &|node| {
            node.vless_mut().unwrap().multiplex = honk_config::node::VlessMultiplex::xray(
                8,
                0,
                honk_config::node::Udp443Policy::Allow,
            );
        }),
        link(&format!(
            "vless://{UUID}@127.0.0.1:443?security=tls&sni=a.example&ech=1"
        )),
        rebuilt(vless, &|node| {
            node.vless_mut().unwrap().encryption = Some("mlkem768x25519plus.native.0rtt.x".into())
        }),
        link("hysteria2://auth@127.0.0.1:443"),
        link(&format!("tuic://{UUID}:pass@127.0.0.1:443")),
        link(&format!("juicity://{UUID}:pass@127.0.0.1:443")),
        link("anytls://secret@127.0.0.1:443"),
    ]
}

#[tokio::test]
async fn composed_udp_refuses_every_non_tunneled_entry_before_dial() {
    for first in unsupported_tunneled_nodes() {
        let terminal = trojan_exit("udp-terminal", "127.0.0.1", 8443);
        let via = chain(&[&first, &terminal]);
        let route = route(&first, &[&first, &terminal]);
        let id = via.id;
        let protocol = first.protocol();
        let generation = Arc::new(OutboundRuntimeRegistry::build(&[via, first, terminal]).unwrap());
        let recorder = Arc::new(FakeHop::default());
        let mut registry = ProxyRegistry::new();
        if protocol != NodeProtocol::Trojan {
            registry.register(ProtocolEntry::new(protocol, recorder.clone()));
        }
        registry.register(
            ProtocolEntry::new(NodeProtocol::Trojan, recorder.clone())
                .with_packet(recorder.clone())
                .with_tunneled_packet(recorder.clone()),
        );
        registry.register_chain();
        let timeout = Duration::from_secs(1);
        for error in [
            registry
                .dial_udp_transport_runtime(Arc::clone(&generation), id, target(), None, timeout)
                .await
                .unwrap_err(),
            registry
                .dial_udp_route(Arc::clone(&generation), &route, target(), None, timeout)
                .await
                .unwrap_err(),
        ] {
            assert_eq!(
                crate::proxy::packet_rejection(&error),
                Some(PacketRejection::Policy)
            );
            assert_eq!(
                dial_failure_scope(error.as_ref()),
                DialFailureScope::LocalRejection
            );
        }
        assert!(recorder.calls.lock().unwrap().is_empty());
    }
}

/// Shapes that require another connection must refuse before touching the carrier.
#[tokio::test]
async fn disallowed_later_hops_refuse_without_writing_to_the_carrier() {
    let registry = ProxyRegistry::default_resolver().unwrap();
    for node in unsupported_tunneled_nodes() {
        assert!(!node.supports_tunneled_dial(), "{:?}", node.outbound);
        let protocol = node.protocol();
        let entry = registry.find(protocol);
        if !cfg!(feature = "rprx") && matches!(protocol, NodeProtocol::VLess | NodeProtocol::VMess)
        {
            assert!(entry.is_none(), "{protocol:?} was registered without rprx");
            continue;
        }
        let entry = entry.expect("missing protocol handler");
        let runtime = NodeRuntime::try_ephemeral(&node).unwrap();
        let (carrier, mut server) = tokio::io::duplex(1024);
        let dial = entry.tcp.dial_over(
            runtime,
            Box::new(carrier),
            target(),
            None,
            TunnelDialOptions::new(Duration::from_millis(100)),
        );
        let error = tokio::time::timeout(Duration::from_secs(1), dial)
            .await
            .unwrap()
            .unwrap_err();
        assert!(
            crate::proxy::tunnel_unsupported(&error),
            "{protocol:?}: {error:#}"
        );
        let mut byte = [0];
        let read = tokio::time::timeout(Duration::from_secs(1), server.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0, "{protocol:?} wrote to the carrier");
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
