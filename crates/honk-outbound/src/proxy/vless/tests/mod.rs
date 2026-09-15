use super::*;
use tokio::io::AsyncReadExt;

fn vless_node(uuid: &str) -> Node {
    Node {
        outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some(uuid.into()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn configured_vless_node(
    uuid: &str,
    udp_encoding: honk_config::node::VlessUdpEncoding,
    multiplex: honk_config::node::VlessMultiplex,
) -> Node {
    let mut node = vless_node(uuid);
    let vless = node.vless_mut().unwrap();
    vless.udp_encoding = udp_encoding;
    vless.multiplex = multiplex;
    node
}

fn cool_node(name: &str) -> Node {
    let limit = std::num::NonZeroU16::new(8).unwrap();
    let mut node = configured_vless_node(
        "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3",
        honk_config::node::VlessUdpEncoding::Auto,
        honk_config::node::VlessMultiplex::Xray {
            tcp: Some(limit),
            udp: honk_config::node::VlessUdpMux::SharedTcp,
            udp443: honk_config::node::Udp443Policy::Reject,
        },
    );
    node.name = name.into();
    node.address = "127.0.0.1:1".into();
    node.host = "127.0.0.1".into();
    node.port = 1;
    node.id = node.derive_id();
    node
}

mod interop;
mod pools;
mod protocol;
mod stream_tests;
mod udp;
