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
