//! Per-protocol facts: UDP support, pooling behavior, generation runtime
//! ownership, and share-link schemes.

use honk_config::node::{Node, WireMode};
use honk_config::types::NodeProtocol;

use crate::runtime::GenerationRuntime;

/// Per-protocol facts. Function-typed fields cover per-node conditions:
/// VLESS, Trojan, and AnyTLS gate UDP on `node.network`, while Trojan
/// ready-stream pooling additionally depends on its transport.
pub struct ProtocolDescriptor {
    pub protocol: NodeProtocol,
    pub supports_udp: fn(&Node) -> bool,
    pub pool_ready_streams: fn(&Node) -> bool,
    pub pool_bare_tcp: fn(&Node) -> bool,
    pub generation_runtime: fn(&Node) -> GenerationRuntime,
    pub share_link_schemes: &'static [&'static str],
}

impl ProtocolDescriptor {
    pub fn generation_runtime(&self, node: &Node) -> GenerationRuntime {
        (self.generation_runtime)(node)
    }

    pub fn has_generation_runtime(&self, node: &Node) -> bool {
        self.generation_runtime(node) != GenerationRuntime::None
    }
}

/// The dial-time network gate shared by capability predicates and UDP dial
/// paths: no `network` restriction means UDP is allowed; otherwise the list
/// must contain "udp".
pub(crate) fn network_allows_udp(node: &Node) -> bool {
    node.network().is_none_or(|network| {
        network
            .split(',')
            .any(|entry| entry.trim().eq_ignore_ascii_case("udp"))
    })
}

fn never(_: &Node) -> bool {
    false
}

fn always(_: &Node) -> bool {
    true
}

fn no_runtime(_: &Node) -> GenerationRuntime {
    GenerationRuntime::None
}

fn anytls_runtime(_: &Node) -> GenerationRuntime {
    GenerationRuntime::AnyTls
}

fn quic_runtime(_: &Node) -> GenerationRuntime {
    GenerationRuntime::Quic
}

fn vless_supports_udp(node: &Node) -> bool {
    node.vless().unwrap().mode != WireMode::Legacy && network_allows_udp(node)
}

fn vless_pool_bare_tcp(node: &Node) -> bool {
    matches!(
        node.vless().unwrap().mode,
        WireMode::Legacy | WireMode::UotV2 | WireMode::Xudp
    )
}

fn vless_runtime(node: &Node) -> GenerationRuntime {
    match node.vless().unwrap().mode {
        WireMode::H2mux | WireMode::H2muxPadded => GenerationRuntime::VlessH2Mux,
        WireMode::MuxCool => GenerationRuntime::VlessCoolMux,
        WireMode::Legacy | WireMode::UotV2 | WireMode::Xudp => GenerationRuntime::None,
    }
}

/// Poolable only on the plain TCP transport: `dial()` completes the TLS
/// handshake (if enabled) and writes the one-shot request header; Trojan
/// defines no server handshake reply, so the stream is then a target-bound
/// data channel. WebSocket/gRPC transports add a bridge task / HTTP/2
/// framing state whose idle liveness cannot be probed at the fd level, so
/// they stay on bare-TCP pooling.
fn trojan_pool_ready_streams(node: &Node) -> bool {
    matches!(node.transport().unwrap().transport.as_str(), "" | "tcp")
}

static DESCRIPTORS: &[ProtocolDescriptor] = &[
    ProtocolDescriptor {
        protocol: NodeProtocol::SS,
        supports_udp: always,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: no_runtime,
        share_link_schemes: &["ss"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Trojan,
        supports_udp: network_allows_udp,
        pool_ready_streams: trojan_pool_ready_streams,
        pool_bare_tcp: always,
        generation_runtime: no_runtime,
        share_link_schemes: &["trojan"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::VMess,
        supports_udp: never,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: no_runtime,
        share_link_schemes: &["vmess"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::VLess,
        supports_udp: vless_supports_udp,
        pool_ready_streams: never,
        pool_bare_tcp: vless_pool_bare_tcp,
        generation_runtime: vless_runtime,
        share_link_schemes: &["vless"],
    },
    // After the greeting (+ optional RFC 1929 auth) and a successful CONNECT
    // reply, the connection is a pure data channel bound to the requested
    // target — the server sends nothing of its own first, so a fully-dialed
    // stream is safe to pool and reuse directly.
    ProtocolDescriptor {
        protocol: NodeProtocol::Socks5,
        supports_udp: always,
        pool_ready_streams: always,
        pool_bare_tcp: always,
        generation_runtime: no_runtime,
        share_link_schemes: &["socks5", "socks4", "socks4a"],
    },
    // QUIC-based (hy2/tuic/juicity): a pooled bare TCP is unusable — their
    // `dial_with_tcp` fails — so preconnect warmup must not deposit one (it
    // would poison the first flow).
    ProtocolDescriptor {
        protocol: NodeProtocol::Hysteria2,
        supports_udp: always,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: quic_runtime,
        share_link_schemes: &["hysteria2", "hysteria"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Tuic,
        supports_udp: always,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: quic_runtime,
        share_link_schemes: &["tuic"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Juicity,
        supports_udp: always,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: quic_runtime,
        share_link_schemes: &["juicity"],
    },
    // Multiplexed: the node-owned session pool already keeps reusable
    // connections. Bare-TCP or ready-stream pooling would bypass that owner,
    // creating an untracked TLS/auth session outside its lifecycle.
    ProtocolDescriptor {
        protocol: NodeProtocol::AnyTLS,
        supports_udp: network_allows_udp,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: anytls_runtime,
        share_link_schemes: &["anytls"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Direct,
        supports_udp: always,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: no_runtime,
        share_link_schemes: &[],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Block,
        supports_udp: never,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: no_runtime,
        share_link_schemes: &[],
    },
];

pub fn descriptor(protocol: NodeProtocol) -> &'static ProtocolDescriptor {
    DESCRIPTORS
        .iter()
        .find(|d| d.protocol == protocol)
        .expect("every NodeProtocol has a descriptor")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_protocol_has_a_descriptor() {
        for protocol in [
            NodeProtocol::SS,
            NodeProtocol::Trojan,
            NodeProtocol::VMess,
            NodeProtocol::VLess,
            NodeProtocol::Socks5,
            NodeProtocol::Hysteria2,
            NodeProtocol::Tuic,
            NodeProtocol::Juicity,
            NodeProtocol::AnyTLS,
            NodeProtocol::Direct,
            NodeProtocol::Block,
        ] {
            assert_eq!(descriptor(protocol).protocol, protocol);
        }
    }

    #[test]
    fn generation_runtime_matches_protocol_family() {
        let node = |protocol| Node {
            outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
            ..Default::default()
        };
        for protocol in [
            NodeProtocol::AnyTLS,
            NodeProtocol::Tuic,
            NodeProtocol::Juicity,
            NodeProtocol::Hysteria2,
        ] {
            let node = node(protocol);
            assert!(descriptor(protocol).has_generation_runtime(&node));
        }
        for protocol in [
            NodeProtocol::VLess,
            NodeProtocol::Trojan,
            NodeProtocol::Direct,
        ] {
            let node = node(protocol);
            assert!(!descriptor(protocol).has_generation_runtime(&node));
        }
    }

    #[test]
    fn vless_capabilities_follow_wire_mode() {
        let descriptor = descriptor(NodeProtocol::VLess);
        for (mode, udp, bare, runtime) in [
            (WireMode::Legacy, false, true, GenerationRuntime::None),
            (WireMode::UotV2, true, true, GenerationRuntime::None),
            (WireMode::Xudp, true, true, GenerationRuntime::None),
            (WireMode::H2mux, true, false, GenerationRuntime::VlessH2Mux),
            (
                WireMode::H2muxPadded,
                true,
                false,
                GenerationRuntime::VlessH2Mux,
            ),
            (
                WireMode::MuxCool,
                true,
                false,
                GenerationRuntime::VlessCoolMux,
            ),
        ] {
            let node = Node {
                outbound: honk_config::node::OutboundConfig::Vless(
                    honk_config::node::VlessConfig {
                        mode,
                        ..Default::default()
                    },
                ),
                ..Default::default()
            };
            assert_eq!((descriptor.supports_udp)(&node), udp);
            assert_eq!((descriptor.pool_bare_tcp)(&node), bare);
            assert_eq!(descriptor.generation_runtime(&node), runtime);
        }
    }

    #[test]
    fn udp_capability_follows_the_network_gate() {
        let mut base = Node {
            outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
            ..Default::default()
        };
        let trojan = descriptor(NodeProtocol::Trojan).supports_udp;
        assert!(trojan(&base), "no network restriction allows UDP");
        base.trojan_mut().unwrap().network = Some("ws".to_string());
        assert!(!trojan(&base));
        base.trojan_mut().unwrap().network = Some("tcp, udp".to_string());
        assert!(trojan(&base));

        let anytls = descriptor(NodeProtocol::AnyTLS).supports_udp;
        let ws_only = Node {
            outbound: honk_config::node::OutboundConfig::AnyTls(honk_config::node::AnyTlsConfig {
                network: Some("ws".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!anytls(&ws_only));

        let vless = descriptor(NodeProtocol::VLess).supports_udp;
        let tcp_only = Node {
            outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
                mode: WireMode::H2mux,
                network: Some("tcp".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!vless(&tcp_only));

        let ss = descriptor(NodeProtocol::SS).supports_udp;
        let node = Node::default();
        assert!(ss(&node), "SS UDP is not network-gated");
    }
}
