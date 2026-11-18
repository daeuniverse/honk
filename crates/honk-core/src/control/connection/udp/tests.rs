use super::dial::source_path as source_path_in;
use super::*;
use crate::control::udp_endpoint::SourcePath;
use honk_config::node::OutboundConfig;
use honk_config::types::NodeProtocol;

fn node(protocol: NodeProtocol) -> Node {
    Node {
        outbound: OutboundConfig::from_protocol(protocol),
        ..Default::default()
    }
}

fn source_path(registry: &ProxyRegistry, node: &Node, port: u16) -> Option<SourcePath> {
    let empty = honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap();
    source_path_in(registry, &empty, node, port)
}

fn production() -> ProxyRegistry {
    ProxyRegistry::default_resolver().unwrap()
}

/// SOCKS5 registered with or without a shared-source slot.
fn socks5_registry(shared: bool) -> ProxyRegistry {
    let handler = Arc::new(honk_outbound::proxy::socks5::Socks5Handler::new());
    let mut entry =
        honk_outbound::proxy::ProtocolEntry::new(NodeProtocol::Socks5, Arc::clone(&handler))
            .with_packet(Arc::clone(&handler));
    if shared {
        entry = entry.with_shared(handler);
    }
    let mut registry = ProxyRegistry::new();
    registry.register(entry);
    registry
}

#[test]
fn source_path_selects_shared_exactly_for_the_registered_slots() {
    let registry = production();
    for (protocol, shared) in [
        (NodeProtocol::SS, true),
        (NodeProtocol::Trojan, true),
        (NodeProtocol::VMess, false),
        (NodeProtocol::Socks5, true),
        (NodeProtocol::Juicity, true),
        (NodeProtocol::AnyTLS, true),
        (NodeProtocol::Direct, false),
        (NodeProtocol::Block, false),
    ] {
        assert_eq!(
            source_path(&registry, &node(protocol), 443),
            shared.then_some(SourcePath::Shared),
            "{protocol:?}"
        );
    }
}

#[test]
fn the_registered_slot_alone_selects_the_shared_path() {
    let socks5 = node(NodeProtocol::Socks5);
    assert_eq!(
        source_path(&socks5_registry(false), &socks5, 443),
        None,
        "a registry without the slot keeps the ordinary path"
    );
    assert_eq!(
        source_path(&socks5_registry(true), &socks5, 443),
        Some(SourcePath::Shared)
    );
    assert_eq!(
        source_path(&ProxyRegistry::new(), &socks5, 443),
        None,
        "an unregistered protocol has no slot"
    );
}

#[cfg(feature = "rprx")]
#[test]
fn vless_shares_explicit_uot_and_h2_but_keeps_xudp_and_native_apart() {
    use honk_config::node::{
        Udp443Policy, VlessConfig, VlessMultiplex, VlessUdpEncoding, VlessUdpPath,
    };
    fn vless(
        udp_encoding: VlessUdpEncoding,
        multiplex: VlessMultiplex,
        network: Option<&str>,
    ) -> Node {
        Node {
            outbound: OutboundConfig::Vless(VlessConfig {
                udp_encoding,
                multiplex,
                network: network.map(Into::into),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
    let registry = production();
    let off = VlessMultiplex::Off;
    for port in [53, 443, 5301] {
        for node in [
            vless(VlessUdpEncoding::UotV2, off, None),
            vless(
                VlessUdpEncoding::Auto,
                VlessMultiplex::H2 { padding: false },
                None,
            ),
        ] {
            assert_eq!(
                source_path(&registry, &node, port),
                Some(SourcePath::Shared),
                "{port}"
            );
        }
    }
    assert_eq!(
        source_path(
            &ProxyRegistry::new(),
            &vless(VlessUdpEncoding::UotV2, off, None),
            5301
        ),
        None,
        "without a registered slot UoT stays on the ordinary path"
    );
    assert_eq!(
        source_path(&registry, &vless(VlessUdpEncoding::Auto, off, None), 53),
        None
    );
    assert_eq!(
        source_path(&registry, &vless(VlessUdpEncoding::Native, off, None), 5301),
        None
    );
    assert_eq!(
        source_path(&registry, &vless(VlessUdpEncoding::Xudp, off, None), 5301),
        Some(SourcePath::Vless(VlessUdpPath::Xudp))
    );
    // Reject and the capability gate keep their terminal meaning.
    let rejecting = vless(
        VlessUdpEncoding::UotV2,
        VlessMultiplex::xray(-1, -1, Udp443Policy::Reject),
        None,
    );
    assert_eq!(source_path(&registry, &rejecting, 443), None);
    assert_eq!(
        source_path(&registry, &rejecting, 5301),
        Some(SourcePath::Shared)
    );
    assert_eq!(
        source_path(
            &registry,
            &vless(VlessUdpEncoding::UotV2, off, Some("tcp")),
            5301
        ),
        None
    );
}

#[test]
fn quic_sources_keep_their_concrete_paths() {
    assert_eq!(
        source_path(&production(), &node(NodeProtocol::Hysteria2), 443),
        Some(SourcePath::Hysteria2)
    );
    assert_eq!(
        source_path(&production(), &node(NodeProtocol::Tuic), 443),
        Some(SourcePath::Tuic)
    );
}

fn chain_node(name: &str, hops: &[&Node]) -> Node {
    let mut node = Node {
        name: name.into(),
        outbound: OutboundConfig::Chain {
            hops: hops.iter().map(|hop| hop.name.clone()).collect(),
        },
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn exit_node(name: &str, port: u16, outbound: OutboundConfig) -> Node {
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

fn trojan_exit(port: u16) -> Node {
    exit_node(
        "trojan",
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

/// Only a configured chain whose exit registers a tunneled shared source,
/// Trojan here, shares a source; a VLESS exit sends native UDP per flow.
#[test]
fn a_chain_shares_a_source_only_when_configured_with_a_shared_exit() {
    let front = exit_node("front", 1080, OutboundConfig::Socks5(Default::default()));
    let trojan = trojan_exit(443);
    let vless = exit_node(
        "vless",
        443,
        OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some("00000000-0000-4000-8000-000000000001".into()),
            ..Default::default()
        }),
    );
    let via_trojan = chain_node("via-trojan", &[&front, &trojan]);
    let via_vless = chain_node("via-vless", &[&front, &vless]);
    let generation = honk_outbound::runtime::OutboundRuntimeRegistry::build(&[
        via_trojan.clone(),
        via_vless.clone(),
        front.clone(),
        trojan.clone(),
        vless,
    ])
    .unwrap();
    let registry = production();
    for (node, path) in [(&via_trojan, Some(SourcePath::Shared)), (&via_vless, None)] {
        assert_eq!(
            source_path_in(&registry, &generation, node, 443),
            path,
            "{}",
            node.name
        );
    }
}

/// Two destinations of one client ride one Trojan associate through the chain.
#[tokio::test]
async fn one_client_shares_one_chain_association_across_destinations() {
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = server.accept().await {
            held.push(stream);
        }
    });
    let relay = crate::test_support::socks5_relay().await;
    let front = exit_node(
        "front",
        relay.addr.port(),
        OutboundConfig::Socks5(Default::default()),
    );
    let trojan = trojan_exit(port);
    let via = chain_node("via", &[&front, &trojan]);
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[via.clone(), front, trojan])
            .unwrap(),
    );
    let registry = production();
    let pool = Arc::new(crate::control::udp_endpoint::UdpEndpointPool::new());
    let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
    let stats = Arc::new(crate::stats::StatsManager::new());
    let client: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let path = source_path_in(&registry, &generation, &via, 53).unwrap();
    let mut attachments = Vec::new();
    for target in ["192.0.2.1:53", "192.0.2.2:53"] {
        let preparation = pool
            .prepare_source(
                &registry,
                Arc::clone(&generation),
                generation.get(&via.id).unwrap(),
                client,
                path,
                None,
                target.parse().unwrap(),
                None,
                Duration::from_secs(3),
                Arc::clone(&alive),
                Arc::clone(&stats),
                IpVersion::V4,
                false,
            )
            .await
            .unwrap();
        attachments.push(preparation.commit(&pool).await.unwrap());
    }
    assert_eq!(relay.requests.lock().len(), 1);
}

fn route_target(leaf: &Node, hops: &[&Node]) -> honk_outbound::group::OwnedTarget {
    let (exit, own) = hops.split_last().unwrap();
    let own: Vec<_> = own.iter().map(|hop| hop.id).collect();
    let (leaf_hops, exits) = own.split_at(1);
    let honk_config::group_graph::Composed::Routed(route) = honk_config::group_graph::compose(
        leaf.id,
        leaf_hops,
        exits.iter().copied().chain([exit.id]),
    ) else {
        panic!("expected a route");
    };
    honk_outbound::group::OwnedTarget {
        node: leaf.clone(),
        route: Some(Box::new(honk_outbound::group::RoutedTarget {
            route,
            hop_names: hops.iter().map(|hop| hop.name.clone()).collect(),
        })),
    }
}

/// Prepare `target` alone, as an authoritative plan, toward `destination`.
async fn prepare_target(
    handle: &ControlPlaneHandle,
    target: &honk_outbound::group::OwnedTarget,
    generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    destination: &str,
) -> anyhow::Result<
    Option<(
        honk_outbound::group::OwnedTarget,
        super::dial::PreparedEndpoint,
    )>,
> {
    let plan = crate::control::reload::ResolvedUdpPlan {
        mode: crate::group::SelectionPlanMode::Authoritative,
        targets: vec![target.clone()],
        ipver: IpVersion::V4,
        feedback: vec![None],
        selection_chains: vec![vec!["g".into(), target.node.name.clone()]],
        #[cfg(feature = "native-api")]
        observation: None,
    };
    handle
        .prepare_udp_candidates(
            plan,
            None,
            "127.0.0.1:40000".parse().unwrap(),
            destination.parse().unwrap(),
            None,
            Duration::from_millis(500),
            tokio::time::Instant::now() + Duration::from_secs(5),
            generation,
            #[cfg(feature = "native-api")]
            &super::super::observation::ConnectionObservation::default(),
        )
        .await
}

/// A route over a working SOCKS5 front to a Trojan exit server that holds
/// every stream, with the control plane and generation serving it.
struct RouteFixture {
    control: ControlPlane,
    generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    nodes: Vec<Node>,
}

impl RouteFixture {
    fn new(nodes: Vec<Node>) -> Self {
        let control = crate::control::tests::support::control_plane(honk_config::Config {
            nodes: nodes.clone(),
            ..Default::default()
        });
        let generation =
            Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&nodes).unwrap());
        Self {
            control,
            generation,
            nodes,
        }
    }

    fn demoted(&self, handle: &ControlPlaneHandle) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|node| {
                handle
                    .alive_set
                    .is_failure_demoted(node.id, ProbeDomain::DataUdp, IpVersion::V4)
            })
            .map(|node| node.name.clone())
            .collect()
    }
}

async fn holding_server() -> u16 {
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = server.accept().await {
            held.push(stream);
        }
    });
    port
}

fn socks5_hop(name: &str, port: u16) -> Node {
    exit_node(name, port, OutboundConfig::Socks5(Default::default()))
}

#[tokio::test]
async fn a_route_udp_failure_at_the_first_hop_counts_against_the_leaf_only() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let front = socks5_hop("front", port);
    let land = trojan_exit(443);
    let route = route_target(&front, &[&front, &land]);
    let fixture = RouteFixture::new(vec![front, land]);
    let handle = fixture.control.spawn_handle();
    for _ in 0..2 {
        let prepared = prepare_target(&handle, &route, &fixture.generation, "192.0.2.1:53").await;
        assert!(!matches!(prepared, Ok(Some(_))));
    }
    assert_eq!(fixture.demoted(&handle), ["front"]);
}

#[tokio::test]
async fn a_route_udp_failure_at_the_exit_counts_against_the_exit_only() {
    let refusing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = refusing.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = refusing.accept().await {
            drop(stream);
        }
    });
    let relay = crate::test_support::socks5_relay().await;
    let front = socks5_hop("front", relay.addr.port());
    // TLS makes the exit's handshake wait for its server, which hangs up.
    let land = exit_node(
        "land",
        port,
        OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            password: Some("secret".into()),
            tls: honk_config::node::TlsOptions {
                enabled: true,
                sni: Some("land.example".into()),
                ..Default::default()
            },
            ..Default::default()
        }),
    );
    let route = route_target(&front, &[&front, &land]);
    let fixture = RouteFixture::new(vec![front, land]);
    let handle = fixture.control.spawn_handle();
    for _ in 0..2 {
        let prepared = prepare_target(&handle, &route, &fixture.generation, "192.0.2.1:53").await;
        assert!(!matches!(prepared, Ok(Some(_))));
    }
    assert_eq!(fixture.demoted(&handle), ["land"]);
}

/// An established route stream proves its leaf and every exit before the
/// last; the last exit's UDP health comes only from the flow it carries.
#[tokio::test]
async fn a_route_udp_setup_success_proves_the_leaf_and_inner_exits() {
    let outer = crate::test_support::socks5_relay().await;
    let inner = crate::test_support::socks5_relay().await;
    let front = socks5_hop("front", outer.addr.port());
    let mid = socks5_hop("mid", inner.addr.port());
    let land = trojan_exit(holding_server().await);
    let route = route_target(&front, &[&front, &mid, &land]);
    let fixture = RouteFixture::new(vec![front, mid, land]);
    let handle = fixture.control.spawn_handle();
    let fail_all = || {
        for node in &fixture.nodes {
            crate::control::report_dial_failure_if_current(
                &fixture.generation,
                &handle.alive_set,
                node.id,
                ProbeDomain::DataUdp,
                IpVersion::V4,
            );
        }
    };
    fail_all();
    let prepared = prepare_target(&handle, &route, &fixture.generation, "192.0.2.1:53").await;
    assert!(matches!(prepared, Ok(Some(_))), "{:?}", prepared.err());
    fail_all();
    assert_eq!(fixture.demoted(&handle), ["trojan"]);
}

/// A route's UDP is a flow of its own even when its leaf could share a
/// source: the source pool keys by the generation's nodes, not by routes.
#[tokio::test]
async fn group_exit_routes_never_get_a_shared_source() {
    let relay = crate::test_support::socks5_relay().await;
    let front = socks5_hop("front", relay.addr.port());
    let land = trojan_exit(holding_server().await);
    let route = route_target(&front, &[&front, &land]);
    let fixture = RouteFixture::new(vec![front.clone(), land]);
    assert!(source_path(&production(), &front, 53).is_some());
    let handle = fixture.control.spawn_handle();
    let (_, prepared) = prepare_target(&handle, &route, &fixture.generation, "192.0.2.1:53")
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        prepared.transport,
        super::dial::PreparedEndpointTransport::Flow(_)
    ));
}

/// The exit frames a route's UDP, so the exit's destination-port policy
/// decides: a leaf that rejects UDP/443 still reaches it through a Trojan
/// exit, and a VLESS exit that can tunnel UDP has no port policy to apply.
#[cfg(feature = "rprx")]
#[tokio::test]
async fn a_route_checks_the_port_policy_of_its_exit() {
    use honk_config::node::{Udp443Policy, VlessConfig, VlessMultiplex};
    let leaf = exit_node(
        "leaf",
        holding_server().await,
        OutboundConfig::Vless(VlessConfig {
            uuid: Some("00000000-0000-4000-8000-000000000001".into()),
            multiplex: VlessMultiplex::xray(8, 0, Udp443Policy::Reject),
            ..Default::default()
        }),
    );
    assert!(!honk_outbound::descriptor::udp_target_allowed(&leaf, 443));
    let land = trojan_exit(holding_server().await);
    let leaf_route = route_target(&leaf, &[&leaf, &land]);
    let fixture = RouteFixture::new(vec![land, leaf]);
    let handle = fixture.control.spawn_handle();
    let prepared = prepare_target(&handle, &leaf_route, &fixture.generation, "192.0.2.1:443").await;
    assert!(matches!(prepared, Ok(Some(_))), "{:?}", prepared.err());
}
