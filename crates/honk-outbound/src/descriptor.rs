//! Per-protocol facts: UDP support, pooling behavior, generation runtime
//! ownership, and share-link schemes.

use honk_config::node::{Node, VlessTcpPath, VlessUdpPath};
use honk_config::types::NodeProtocol;

use crate::proxy::WarmRequirement;
use crate::runtime::GenerationRuntime;

/// Predicate fields cover per-node conditions:
/// VLESS, Trojan, and AnyTLS gate UDP on `node.network`, while Trojan
/// ready-stream pooling additionally depends on its transport.
pub struct ProtocolDescriptor {
    pub protocol: NodeProtocol,
    pub supports_udp: fn(&Node) -> bool,
    pub pool_ready_streams: fn(&Node) -> bool,
    pub pool_bare_tcp: fn(&Node) -> bool,
    pub generation_runtime: GenerationRuntime,
    pub share_link_schemes: &'static [&'static str],
}

impl ProtocolDescriptor {
    pub fn supports_warm(&self, node: &Node, requirement: WarmRequirement) -> bool {
        if self.protocol == NodeProtocol::VLess {
            let vless = node
                .vless()
                .expect("VLESS descriptor requires VLESS config");
            return match requirement {
                WarmRequirement::Session => {
                    matches!(vless.tcp_path(), VlessTcpPath::H2 | VlessTcpPath::Cool)
                }
                WarmRequirement::Udp => matches!(
                    vless.udp_path(0),
                    Some(VlessUdpPath::H2 | VlessUdpPath::CoolShared | VlessUdpPath::CoolSeparate)
                ),
            };
        }
        self.generation_runtime != GenerationRuntime::None
            && (requirement == WarmRequirement::Session || (self.supports_udp)(node))
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

fn vless_supports_udp(node: &Node) -> bool {
    node.vless().unwrap().udp_enabled()
}

fn vless_pool_bare_tcp(node: &Node) -> bool {
    node.vless().unwrap().tcp_path() == VlessTcpPath::Direct
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
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["ss"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Trojan,
        supports_udp: network_allows_udp,
        pool_ready_streams: trojan_pool_ready_streams,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["trojan"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::VMess,
        supports_udp: never,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["vmess"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::VLess,
        supports_udp: vless_supports_udp,
        pool_ready_streams: never,
        pool_bare_tcp: vless_pool_bare_tcp,
        generation_runtime: GenerationRuntime::Vless,
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
        generation_runtime: GenerationRuntime::None,
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
        generation_runtime: GenerationRuntime::Quic,
        share_link_schemes: &["hysteria2", "hysteria", "hy2"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Tuic,
        supports_udp: always,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: GenerationRuntime::Quic,
        share_link_schemes: &["tuic"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Juicity,
        supports_udp: always,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: GenerationRuntime::Quic,
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
        generation_runtime: GenerationRuntime::AnyTls,
        share_link_schemes: &["anytls"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Direct,
        supports_udp: always,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &[],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Block,
        supports_udp: never,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &[],
    },
];

/// Whether a selected node permits packets to the target port.
pub fn udp_target_allowed(node: &Node, port: u16) -> bool {
    node.vless()
        .is_none_or(|vless| vless.udp_path(port).is_some())
}

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
    fn vless_capabilities_follow_selected_paths() {
        use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpMux};
        use std::num::NonZeroU16;

        let descriptor = descriptor(NodeProtocol::VLess);
        let limit = NonZeroU16::new(8).unwrap();
        for (multiplex, bare, warm_tcp, warm_udp) in [
            (VlessMultiplex::Off, true, false, false),
            (VlessMultiplex::H2 { padding: false }, false, true, true),
            (
                VlessMultiplex::Xray {
                    tcp: Some(limit),
                    udp: VlessUdpMux::SharedTcp,
                    udp443: Udp443Policy::Reject,
                },
                false,
                true,
                true,
            ),
            (
                VlessMultiplex::Xray {
                    tcp: None,
                    udp: VlessUdpMux::Separate(limit),
                    udp443: Udp443Policy::Reject,
                },
                true,
                false,
                true,
            ),
        ] {
            let node = Node {
                outbound: honk_config::node::OutboundConfig::Vless(
                    honk_config::node::VlessConfig {
                        multiplex,
                        ..Default::default()
                    },
                ),
                ..Default::default()
            };
            assert!((descriptor.supports_udp)(&node));
            assert_eq!((descriptor.pool_bare_tcp)(&node), bare);
            assert_eq!(
                descriptor.supports_warm(&node, WarmRequirement::Session),
                warm_tcp
            );
            assert_eq!(
                descriptor.supports_warm(&node, WarmRequirement::Udp),
                warm_udp
            );
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
                multiplex: honk_config::node::VlessMultiplex::H2 { padding: false },
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

    #[test]
    fn vless_udp_443_policy_is_path_scoped() {
        use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpMux};
        use std::num::NonZeroU16;

        let mut node = Node {
            outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
                multiplex: VlessMultiplex::Xray {
                    tcp: Some(NonZeroU16::new(8).unwrap()),
                    udp: VlessUdpMux::SharedTcp,
                    udp443: Udp443Policy::Reject,
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(udp_target_allowed(&node, 53));
        assert!(!udp_target_allowed(&node, 443));

        let VlessMultiplex::Xray { udp443, .. } = &mut node.vless_mut().unwrap().multiplex else {
            unreachable!()
        };
        *udp443 = Udp443Policy::Allow;
        assert!(udp_target_allowed(&node, 443));
        assert!(udp_target_allowed(&Node::default(), 443));
    }
}
