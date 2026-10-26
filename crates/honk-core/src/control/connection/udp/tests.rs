use super::dial::source_path;
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
        (NodeProtocol::WireGuard, true),
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
