use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpEncoding};

use super::*;
use crate::subscription::clash::options::parse_vless_external_options;

#[test]
fn clash_preserves_vless_packet_and_multiplex_wrappers() {
    let yaml = r#"
proxies:
  - name: h2-default
    type: vless
    server: h2.example
    port: 443
    uuid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
    smux:
      enabled: true
      padding: false
  - name: h2-padded
    type: vless
    server: padded.example
    port: 443
    uuid: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
    multiplex:
      enabled: true
      protocol: h2mux
      padding: true
  - name: uot-default
    type: vless
    server: uot-default.example
    port: 443
    uuid: cccccccc-cccc-4ccc-8ccc-cccccccccccc
    udp-over-tcp: true
  - name: uot-v2
    type: vless
    server: uot-v2.example
    port: 443
    uuid: dddddddd-dddd-4ddd-8ddd-dddddddddddd
    udp_over_tcp:
      enabled: true
      version: 2
  - name: udp-disabled
    type: vless
    server: disabled.example
    port: 443
    uuid: eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee
    smux:
      enabled: false
  - name: xudp
    type: vless
    server: xudp.example
    port: 443
    uuid: ffffffff-ffff-4fff-8fff-ffffffffffff
    packet-encoding: xudp
    flow: xtls-rprx-vision
    tls: true
"#;

    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes.len(), 6);
    assert_eq!(
        nodes
            .iter()
            .map(|node| {
                let config = node.vless().unwrap();
                (config.udp_encoding, config.multiplex, config.udp_enabled())
            })
            .collect::<Vec<_>>(),
        [
            (
                VlessUdpEncoding::Auto,
                VlessMultiplex::H2 { padding: false },
                true,
            ),
            (
                VlessUdpEncoding::Auto,
                VlessMultiplex::H2 { padding: true },
                true,
            ),
            (VlessUdpEncoding::UotV2, VlessMultiplex::Off, true,),
            (VlessUdpEncoding::UotV2, VlessMultiplex::Off, true,),
            (VlessUdpEncoding::Auto, VlessMultiplex::Off, false,),
            (VlessUdpEncoding::Auto, VlessMultiplex::Off, true,),
        ]
    );
    assert_eq!(
        nodes[5].vless().unwrap().flow.as_deref(),
        Some("xtls-rprx-vision")
    );
}

#[test]
fn external_vless_options_preserve_clash_defaults() {
    for (options, encoding, multiplex, udp_enabled) in [
        ("{}", VlessUdpEncoding::Auto, VlessMultiplex::Off, false),
        (
            "packet-encoding: ''",
            VlessUdpEncoding::Auto,
            VlessMultiplex::Off,
            false,
        ),
        (
            "packet-encoding: none",
            VlessUdpEncoding::Native,
            VlessMultiplex::Off,
            true,
        ),
        (
            "packet-encoding: legacy",
            VlessUdpEncoding::Native,
            VlessMultiplex::Off,
            true,
        ),
        (
            "packet_encoding: xudp",
            VlessUdpEncoding::Xudp,
            VlessMultiplex::Off,
            true,
        ),
        (
            "xudp: true",
            VlessUdpEncoding::Xudp,
            VlessMultiplex::Off,
            true,
        ),
        (
            "xudp: false",
            VlessUdpEncoding::Native,
            VlessMultiplex::Off,
            true,
        ),
        (
            "udp: true",
            VlessUdpEncoding::Xudp,
            VlessMultiplex::Off,
            true,
        ),
        (
            "udp: true\npacket-encoding: ''",
            VlessUdpEncoding::Xudp,
            VlessMultiplex::Off,
            true,
        ),
        (
            "udp: true\npacket-encoding: none",
            VlessUdpEncoding::Native,
            VlessMultiplex::Off,
            true,
        ),
        (
            "udp: false\npacket-encoding: xudp",
            VlessUdpEncoding::Xudp,
            VlessMultiplex::Off,
            false,
        ),
        (
            "udp: false\nmultiplex: { enabled: true, protocol: h2mux }",
            VlessUdpEncoding::Auto,
            VlessMultiplex::H2 { padding: false },
            false,
        ),
        (
            "multiplex: { enabled: true, protocol: '', padding: false }",
            VlessUdpEncoding::Auto,
            VlessMultiplex::H2 { padding: false },
            true,
        ),
        (
            "multiplex: { enabled: true, padding: true }",
            VlessUdpEncoding::Auto,
            VlessMultiplex::H2 { padding: true },
            true,
        ),
        (
            "mux: { enabled: true }",
            VlessUdpEncoding::Auto,
            VlessMultiplex::xray(0, 0, Udp443Policy::Reject),
            true,
        ),
        (
            "mux: { enabled: true, concurrency: -1, xudpConcurrency: 0, xudpProxyUDP443: skip }",
            VlessUdpEncoding::Auto,
            VlessMultiplex::xray(-1, 0, Udp443Policy::Skip),
            true,
        ),
        (
            "packet-encoding: none\nmux: { enabled: true, concurrency: 0, xudpConcurrency: 0, xudpProxyUDP443: skip }",
            VlessUdpEncoding::Native,
            VlessMultiplex::xray(0, 0, Udp443Policy::Skip),
            true,
        ),
    ] {
        let value: serde_yaml::Value = serde_yaml::from_str(options).unwrap();
        assert_eq!(
            parse_vless_external_options(value.as_mapping().unwrap()).unwrap(),
            (encoding, multiplex, udp_enabled),
            "{options}"
        );
    }
}

#[test]
fn clash_projects_xray_mux_controls_into_canonical_config() {
    let yaml = r#"proxies:
  - name: xray-mux
    type: vless
    server: mux.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    mux:
      enabled: true
      concurrency: -1
      xudpConcurrency: 4
      xudpProxyUDP443: allow
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    let config = nodes[0].vless().unwrap();
    assert_eq!(
        config.multiplex,
        VlessMultiplex::xray(-1, 4, Udp443Policy::Allow)
    );
    assert_eq!(config.udp_encoding, VlessUdpEncoding::Auto);
    assert!(config.udp_enabled());
    assert_eq!(nodes[0].id, nodes[0].derive_id());
}

#[test]
fn clash_vless_udp_true_defaults_to_xudp() {
    let yaml = r#"proxies:
  - name: ordinary
    type: vless
    server: vless.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    udp: true
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    let config = nodes[0].vless().unwrap();
    assert_eq!(config.udp_encoding, VlessUdpEncoding::Xudp);
    assert_eq!(config.multiplex, VlessMultiplex::Off);
}

#[test]
fn clash_vless_udp_gate_is_independent_from_selected_carrier() {
    let yaml = r#"proxies:
  - {name: implicit-disabled, type: vless, server: disabled.example, port: 443, uuid: 00000000-0000-4000-8000-000000000041}
  - {name: source-xudp, type: vless, server: default.example, port: 443, uuid: 00000000-0000-4000-8000-000000000042, udp: true}
  - {name: native-enabled, type: vless, server: native.example, port: 443, uuid: 00000000-0000-4000-8000-000000000043, udp: true, packet-encoding: none}
  - {name: disabled-xudp, type: vless, server: xudp.example, port: 443, uuid: 00000000-0000-4000-8000-000000000044, udp: false, packet-encoding: xudp}
  - {name: disabled-h2mux, type: vless, server: mux.example, port: 443, uuid: 00000000-0000-4000-8000-000000000045, udp: false, multiplex: {enabled: true, protocol: h2mux}}
  - {name: native-vision-tcp, type: vless, server: vision.example, port: 443, uuid: 00000000-0000-4000-8000-000000000046, udp: false, packet-encoding: legacy, flow: xtls-rprx-vision, tls: true}
  - {name: wrapper-precedence, type: vless, server: wrapper.example, port: 443, uuid: 00000000-0000-4000-8000-000000000047, packet-encoding: none, udp-over-tcp: true}
  - {name: rejected-native-vision-udp, type: vless, server: bad-vision.example, port: 443, uuid: 00000000-0000-4000-8000-000000000048, udp: true, packet-encoding: none, flow: xtls-rprx-vision, tls: true}
  - {name: rejected-carrier-conflict, type: vless, server: conflict.example, port: 443, uuid: 00000000-0000-4000-8000-000000000049, packet-encoding: xudp, udp-over-tcp: true}
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();

    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        [
            "implicit-disabled",
            "source-xudp",
            "native-enabled",
            "disabled-xudp",
            "disabled-h2mux",
            "native-vision-tcp",
            "wrapper-precedence",
        ]
    );
    assert_eq!(
        nodes
            .iter()
            .map(|node| {
                let config = node.vless().unwrap();
                (config.udp_encoding, config.multiplex, config.udp_enabled())
            })
            .collect::<Vec<_>>(),
        [
            (VlessUdpEncoding::Auto, VlessMultiplex::Off, false),
            (VlessUdpEncoding::Xudp, VlessMultiplex::Off, true),
            (VlessUdpEncoding::Native, VlessMultiplex::Off, true),
            (VlessUdpEncoding::Auto, VlessMultiplex::Off, false),
            (
                VlessUdpEncoding::Auto,
                VlessMultiplex::H2 { padding: false },
                false,
            ),
            (VlessUdpEncoding::Auto, VlessMultiplex::Off, false),
            (VlessUdpEncoding::UotV2, VlessMultiplex::Off, true,),
        ]
    );
    assert!(nodes.iter().all(|node| node.id == node.derive_id()));
}

#[test]
fn rejects_ambiguous_external_vless_options() {
    for options in [
        "smux: { enabled: true }",
        "multiplex: { enabled: true, protocol: '' }",
        "smux: { enabled: true, protocol: smux }",
        "smux: { enabled: true, protocol: yamux }",
        "udp-over-tcp: { enabled: true, version: 1 }",
        "packet-encoding: packetaddr",
        "packet-encoding: mux-cool",
        "packet-encoding: unsupported",
        "packet-addr: true",
        "mux: true",
        "mux: { enabled: true, concurrency: 32768 }",
        "mux: { enabled: true, xudpProxyUDP443: false }",
        "mux: { enabled: true, unknown: true }",
        "mux: { enabled: true }\nsmux: { enabled: true, protocol: h2mux }",
        "mux: { enabled: true }\nudp-over-tcp: true",
        "packet-encoding: xudp\nxudp: true",
        "packet-encoding: xudp\npacket_encoding: xudp",
        "packet-encoding: xudp\nsmux: { enabled: true }",
        "xudp: true\nudp-over-tcp: true",
        "smux: { enabled: true, only-tcp: true }",
        "smux: { enabled: true, brutal: { enabled: true } }",
        "smux: { enabled: true, brutal-opts: { enabled: true, up: 100 Mbps } }",
        "smux: { enabled: true, max-connections: 2 }",
        "smux: { enabled: true, min-streams: 1 }",
        "smux: { enabled: true, max-streams: 128 }",
        "smux: { enabled: true }\nudp-over-tcp: true",
    ] {
        let value: serde_yaml::Value = serde_yaml::from_str(options).unwrap();
        let mapping = value.as_mapping().unwrap();
        assert!(
            parse_vless_external_options(mapping).is_err(),
            "unsupported options must fail: {options}"
        );
    }
}

#[test]
fn clash_import_skips_unsupported_vless_options() {
    let yaml = r#"
proxies:
  - name: unsupported
    type: vless
    server: bad.example
    port: 443
    uuid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
    packet-encoding: packetaddr
  - name: unsupported-flow
    type: vless
    server: flow.example
    port: 443
    uuid: cccccccc-cccc-4ccc-8ccc-cccccccccccc
    flow: xtls-rprx-vision
    tls: true
    smux:
      enabled: true
  - name: unsupported-encryption
    type: vless
    server: encryption.example
    port: 443
    uuid: dddddddd-dddd-4ddd-8ddd-dddddddddddd
    encryption: mlkem768x25519plus.native.1rtt.key
    udp-over-tcp: true
  - name: valid
    type: vless
    server: good.example
    port: 443
    uuid: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
    udp-over-tcp: true
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "valid");
}

#[test]
fn clash_rejects_removed_vless_mode_before_value_loss() {
    let yaml = r#"proxies:
  - {name: null, type: vless, server: null.example, port: 443, uuid: 00000000-0000-4000-8000-000000000061, vless_mode: null}
  - {name: empty, type: vless, server: empty.example, port: 443, uuid: 00000000-0000-4000-8000-000000000062, vless_mode: ''}
  - {name: false, type: vless, server: false.example, port: 443, uuid: 00000000-0000-4000-8000-000000000063, vless_mode: false}
  - {name: old-value, type: vless, server: old.example, port: 443, uuid: 00000000-0000-4000-8000-000000000064, vless_mode: legacy}
  - {name: vmess-unchanged, type: vmess, server: vmess.example, port: 443, uuid: 00000000-0000-4000-8000-000000000065, vless_mode: xudp}
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "vmess-unchanged");
}

#[test]
fn empty_packet_encoding_does_not_shadow_xudp_declaration() {
    for (empty, enabled, expected) in [
        ("", true, VlessUdpEncoding::Xudp),
        ("  ", false, VlessUdpEncoding::Native),
    ] {
        let yaml = format!(
            r#"proxies:
  - name: empty-encoding
    type: vless
    server: example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    packet-encoding: '{empty}'
    xudp: {enabled}
"#
        );
        let nodes = parse_clash_subscription(&yaml, None).unwrap();
        assert_eq!(nodes[0].vless().unwrap().udp_encoding, expected);
    }
}
