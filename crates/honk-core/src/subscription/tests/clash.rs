use super::*;
use crate::subscription::clash::options::parse_vless_external_mode;

#[test]
fn test_parse_clash_subscription() {
    let yaml = r#"
proxies:
  - name: "My SOCKS5"
    type: socks5
    server: 192.168.1.1
    port: 1080
  - name: "My SS"
    type: ss
    server: 10.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].name, "My SOCKS5");
    assert_eq!(nodes[0].protocol(), NodeProtocol::Socks5);
    assert_eq!(nodes[0].host, "192.168.1.1");
    assert_eq!(nodes[0].port, 1080);
    assert_eq!(nodes[1].name, "My SS");
    assert_eq!(nodes[1].protocol(), NodeProtocol::SS);
    assert_eq!(
        nodes[1].shadowsocks().unwrap().encryption,
        Some("aes-256-gcm".to_string())
    );
}

#[test]
fn imported_tls_required_protocols_and_quic_options_are_preserved() {
    let implicit = r#"proxies:
  - name: implicit-trojan
    type: trojan
    server: trojan.example
    port: 443
    password: trojan-secret
"#;
    let node = parse_clash_subscription(implicit, None).unwrap().remove(0);
    assert!(node.trojan().unwrap().tls.enabled);
    assert!(
        parse_clash_subscription(
            &implicit.replace(
                "password: trojan-secret",
                "password: trojan-secret\n    tls: false"
            ),
            None
        )
        .is_err()
    );

    let yaml = r#"proxies:
  - name: hy2
    type: hysteria2
    server: hy2.example
    port: 443
    password: hy2-secret
    obfs: salamander
    obfs-password: obfs-secret
    up: 100 Mbps
    down-speed: 50 Mbps
    ports: ["4000:5000", 6000]
    hop-interval: 7s
    initial-stream-receive-window: 1234
    initial-conn-receive-window: 5678
    disable-mtu-discovery: true
    mtu: 1400
  - name: tuic
    type: tuic
    server: tuic.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    password: tuic-secret
    congestion-controller: bbr
    alpn: [h3, hq-29]
    initial-stream-receive-window: 2345
    initial-conn-receive-window: 6789
    mtu: 1450
  - name: anytls
    type: anytls
    server: anytls.example
    port: 443
    password: anytls-secret
    min-idle-session: 4
    idle-session-check-interval: 30s
    idle-session-timeout: 1m
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    let hy2 = nodes[0].hysteria2().unwrap();
    assert_eq!(hy2.obfs.as_deref(), Some("obfs-secret"));
    assert_eq!(hy2.up_mbps, Some(100));
    assert_eq!(hy2.down_mbps, Some(50));
    assert_eq!(hy2.port_hopping.as_deref(), Some("4000-5000,6000"));
    assert_eq!(hy2.hop_interval, Some(7));
    assert_eq!(hy2.init_stream_recv_window, Some(1234));
    assert_eq!(hy2.init_conn_recv_window, Some(5678));
    assert_eq!(hy2.quic.mtu, Some(1400));
    assert!(hy2.quic.tls.enabled);
    let tuic = nodes[1].tuic().unwrap();
    assert_eq!(tuic.congestion.as_deref(), Some("bbr"));
    assert_eq!(tuic.alpn.as_deref(), Some("h3,hq-29"));
    assert_eq!(tuic.init_stream_recv_window, Some(2345));
    assert_eq!(tuic.init_conn_recv_window, Some(6789));
    assert_eq!(tuic.quic.mtu, Some(1450));
    assert!(tuic.quic.tls.enabled);
    let anytls = nodes[2].anytls().unwrap();
    assert_eq!(anytls.min_idle_session, Some(4));
    assert_eq!(anytls.idle_session_check_interval, Some(30));
    assert_eq!(anytls.idle_session_timeout, Some(60));
    assert!(anytls.tls.enabled);
}

#[test]
fn anytls_alpn_import_preserves_distinct_endpoints() {
    let subscription = Subscription::default();
    let nodes = parse_subscription_content(
        &subscription,
        r#"proxies:
  - {name: issue-173, server: anytls.example, port: 123, type: anytls, client-fingerprint: chrome, idle-session-check-interval: 30, idle-session-timeout: 30, min-idle-session: 0, alpn: [h2], password: secret, sni: tls.example, skip-cert-verify: true, udp: true, tfo: false}
  - {name: other-alpn, server: anytls.example, port: 123, type: anytls, password: secret, sni: tls.example, alpn: [http/1.1]}
  - {name: duplicate, server: anytls.example, port: 123, type: anytls, password: secret, sni: tls.example, alpn: [h2]}
"#,
    )
    .unwrap();

    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["issue-173", "other-alpn"]
    );
    let anytls = nodes[0].anytls().unwrap();
    assert_eq!(anytls.tls.alpn, ["h2"]);
    assert_eq!(nodes[1].tls().unwrap().alpn, ["http/1.1"]);
    assert!(anytls.tls.enabled);
    assert!(anytls.tls.skip_cert_verify);
    assert_eq!(anytls.network.as_deref(), Some("tcp,udp"));
    assert_eq!(anytls.min_idle_session, Some(0));
    assert_eq!(anytls.idle_session_check_interval, Some(30));
    assert_eq!(anytls.idle_session_timeout, Some(30));
}

#[test]
fn clash_alpn_keeps_opaque_members_and_rejects_non_strings() {
    let nodes = parse_clash_subscription(
        r#"proxies:
  - {name: opaque, type: anytls, server: anytls.example, port: 443, password: secret, alpn: ["h2,http/1.1"]}
  - {name: separate, type: anytls, server: anytls.example, port: 443, password: secret, alpn: [h2, http/1.1]}
  - {name: malformed, type: anytls, server: anytls.example, port: 443, password: secret, alpn: [h2, 123]}
"#,
        None,
    )
    .unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["opaque", "separate"]
    );
    assert_eq!(nodes[0].tls().unwrap().alpn, ["h2,http/1.1"]);
    assert_eq!(nodes[1].tls().unwrap().alpn, ["h2", "http/1.1"]);
    assert_ne!(nodes[0].id, nodes[1].id);
}
#[test]
fn test_parse_clash_vless_nested_fields() {
    let subscription_id = uuid::Uuid::new_v4();
    let yaml = r#"
proxies:
  - name: reality-vision
    type: vless
    server: reality.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: legacy-password
    servername: mask.example
    sni: ignored.example
    flow: xtls-rprx-vision
    network: tcp
    client-fingerprint: chrome
    reality-opts:
      public-key: jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc
      short-id: a1b2c3d4
  - name: nested-ws
    type: vless
    server: ws.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    encryption: mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    servername: tls.example
    network: ws
    ws-path: /flat
    ws-host: flat.example
    ws-opts:
      path: /nested
      headers:
        hOsT: websocket.example
  - name: nested-grpc
    type: vless
    server: grpc.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    tls: true
    network: grpc
    grpc-service: flat-service
    grpc-opts:
      grpc-service-name: nested-service
  - name: missing-uuid
    type: vless
    server: plain.example
    port: 80
  - name: incomplete-reality
    type: vless
    server: invalid.example
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    reality-opts:
      short-id: abcd
"#;

    let nodes = parse_clash_subscription(yaml, Some(subscription_id)).unwrap();
    assert_eq!(nodes.len(), 3);

    let reality = &nodes[0];
    assert_eq!(reality.protocol(), NodeProtocol::VLess);
    let reality_config = reality.vless().unwrap();
    assert_eq!(
        reality_config.uuid.as_deref(),
        Some("b831381d-6324-4d53-ad4f-8cda48b30811")
    );
    assert_eq!(reality_config.tls.sni.as_deref(), Some("mask.example"));
    assert_eq!(reality_config.flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(reality_config.transport.transport, "tcp");
    assert!(reality_config.tls.enabled);
    assert_eq!(
        reality_config.tls.reality_public_key.as_deref(),
        Some("jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc")
    );
    assert_eq!(
        reality_config.tls.reality_short_id.as_deref(),
        Some("a1b2c3d4")
    );
    assert_eq!(reality_config.tls.reality_spider_x.as_deref(), Some("/"));

    let ws = nodes[1].vless().unwrap();
    assert_eq!(ws.tls.sni.as_deref(), Some("tls.example"));
    assert_eq!(
        ws.encryption.as_deref(),
        Some("mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    );
    assert_eq!(ws.transport.transport, "ws");
    assert_eq!(ws.transport.ws_path.as_deref(), Some("/nested"));
    assert_eq!(ws.transport.ws_host.as_deref(), Some("websocket.example"));

    let grpc = nodes[2].vless().unwrap();
    assert_eq!(grpc.transport.transport, "grpc");
    assert_eq!(
        grpc.transport.grpc_service.as_deref(),
        Some("nested-service")
    );

    for node in &nodes {
        assert_eq!(node.subscription_id, Some(subscription_id));
    }
}

#[test]
fn test_parse_clash_vless_modes() {
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
  - name: legacy
    type: vless
    server: legacy.example
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
        nodes[0].vless().unwrap().mode,
        honk_config::node::WireMode::H2mux
    );
    assert_eq!(
        nodes[1].vless().unwrap().mode,
        honk_config::node::WireMode::H2muxPadded
    );
    assert_eq!(
        nodes[2].vless().unwrap().mode,
        honk_config::node::WireMode::UotV2
    );
    assert_eq!(
        nodes[3].vless().unwrap().mode,
        honk_config::node::WireMode::UotV2
    );
    assert_eq!(
        nodes[4].vless().unwrap().mode,
        honk_config::node::WireMode::Legacy
    );
    assert_eq!(
        nodes[5].vless().unwrap().mode,
        honk_config::node::WireMode::Xudp
    );
    assert_eq!(
        nodes[5].vless().unwrap().flow.as_deref(),
        Some("xtls-rprx-vision")
    );
}

#[test]
fn test_external_vless_mode_representations() {
    use honk_config::node::WireMode;

    for (options, expected) in [
        ("{}", WireMode::Legacy),
        ("packet-encoding: ''", WireMode::Legacy),
        ("packet_encoding: xudp", WireMode::Xudp),
        ("xudp: true", WireMode::Xudp),
        ("xudp: false", WireMode::Legacy),
        ("udp: true\nxudp: true", WireMode::Xudp),
        ("udp: true", WireMode::Xudp),
        ("udp: true\npacket-encoding: ''", WireMode::Xudp),
        (
            "multiplex: { enabled: true, protocol: '', padding: false }",
            WireMode::H2mux,
        ),
        (
            "multiplex: { enabled: true, padding: true }",
            WireMode::H2muxPadded,
        ),
    ] {
        let value: serde_yaml::Value = serde_yaml::from_str(options).unwrap();
        assert_eq!(
            parse_vless_external_mode(value.as_mapping().unwrap()).unwrap(),
            expected,
            "{options}"
        );
    }
}

#[test]
fn clash_vless_udp_defaults_to_xudp() {
    let yaml = r#"proxies:
  - name: ordinary
    type: vless
    server: vless.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    udp: true
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(
        nodes[0].vless().unwrap().mode,
        honk_config::node::WireMode::Xudp
    );
}

#[test]
fn test_rejects_ambiguous_external_vless_modes() {
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
        "mux: { enabled: true }",
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
        "udp: false\nxudp: true",
    ] {
        let value: serde_yaml::Value = serde_yaml::from_str(options).unwrap();
        let mapping = value.as_mapping().unwrap();
        assert!(
            parse_vless_external_mode(mapping).is_err(),
            "unsupported options must fail: {options}"
        );
    }
}

#[test]
fn test_clash_import_skips_unsupported_vless_mode() {
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
fn test_parse_clash_skips_removed_protocols() {
    // ssr/http/trojan-go support was removed: subscription entries are
    // skipped with a warning instead of failing the whole fetch.
    let yaml = r#"
proxies:
  - name: "SSR node"
    type: ssr
    server: 10.0.0.2
    port: 8388
  - name: "HTTP node"
    type: http
    server: 10.0.0.3
    port: 8080
  - name: "Trojan-Go node"
    type: trojan-go
    server: 10.0.0.4
    port: 443
  - name: "OK"
    type: socks5
    server: 10.0.0.1
    port: 1080
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "OK");
}

#[test]
fn test_parse_clash_no_proxies() {
    let yaml = r#"
port: 7890
not-proxies: []
"#;
    let result = parse_clash_subscription(yaml, None);
    assert!(result.is_err());
}

#[test]
fn clash_imports_intrinsic_udp_nodes_but_rejects_false_restrictions() {
    let yaml = r#"proxies:
  - name: ss-udp
    type: ss
    server: ss.example
    port: 8388
    cipher: aes-128-gcm
    password: secret
    udp: true
  - name: socks-udp
    type: socks5
    server: socks.example
    port: 1080
    udp: true
  - name: hy2-udp
    type: hysteria2
    server: hy2.example
    port: 443
    udp: true
  - name: tuic-udp
    type: tuic
    server: tuic.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    udp: true
  - name: juicity-udp
    type: juicity
    server: juicity.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    password: secret
    udp: true
  - name: false-restriction
    type: socks5
    server: false.example
    port: 1080
    udp: false
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["ss-udp", "socks-udp", "hy2-udp", "tuic-udp", "juicity-udp"]
    );
}

#[test]
fn clash_ignores_disabled_features_but_not_malformed_tls_pins() {
    let yaml = r#"proxies:
  - name: conflicting-aliases
    type: trojan
    server: conflict.example
    port: 443
    password: secret
    skip-cert-verify: true
    skip_cert_verify: false
  - name: tls-disabled
    type: socks5
    server: socks.example
    port: 1080
    tls: false
    flow: 0
    network: null
    encryption: ""
    plugin: null
    plugin-opts: {}
    ws-opts:
      enabled: false
  - name: mux-disabled
    type: trojan
    server: trojan.example
    port: 443
    password: secret
    tls: true
    skip-cert-verify: true
    skip_cert_verify: true
    smux:
      enabled: false
  - name: malformed-pin
    type: socks5
    server: pin.example
    port: 1080
    pin-sha256:
      enabled: false
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].name, "tls-disabled");
    assert_eq!(nodes[1].name, "mux-disabled");
    assert!(nodes[1].trojan().unwrap().tls.skip_cert_verify);
}

#[test]
fn clash_accepts_fixed_h3_alpn_and_tuic_empty_password() {
    let yaml = r#"proxies:
  - name: hy2-h3
    type: hysteria2
    server: hy2.example
    port: 443
    password: secret
    alpn: [h3]
  - name: juicity-h3
    type: juicity
    server: juicity.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    password: secret
    alpn: h3
  - name: tuic-absent-password
    type: tuic
    server: tuic.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
  - name: tuic-empty-password
    type: tuic
    server: tuic-empty.example
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    password: ""
  - name: bad-alpn
    type: hysteria2
    server: bad.example
    port: 443
    alpn: [h3, hq-29]
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        [
            "hy2-h3",
            "juicity-h3",
            "tuic-absent-password",
            "tuic-empty-password"
        ]
    );
    assert_eq!(nodes[2].tuic().unwrap().password, None);
    assert_eq!(nodes[3].tuic().unwrap().password.as_deref(), Some(""));
}

#[test]
fn clash_restores_fallback_names_and_lazy_ws_host_precedence() {
    let yaml = r#"proxies:
  - type: socks5
    server: first.example
    port: 1080
  - name: ""
    type: socks5
    server: second.example
    port: 1081
  - name: nested-host
    type: vless
    server: ws.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    network: ws
    ws-opts:
      headers:
        Host: nested.example
    ws-headers: [ignored-lower-priority-value]
    ws-host:
      ignored: malformed
  - name: ordered-fallback
    type: vless
    server: fallback.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    network: ws
    ws-headers: headers.example
    ws-host: host.example
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes[0].name, "socks5-first.example:1080");
    assert_eq!(nodes[1].name, "socks5-second.example:1081");
    assert_eq!(
        nodes[2].vless().unwrap().transport.ws_host.as_deref(),
        Some("nested.example")
    );
    assert_eq!(
        nodes[3].vless().unwrap().transport.ws_host.as_deref(),
        Some("headers.example")
    );
}

#[test]
fn clash_rejects_legacy_vless_udp_and_nondefault_juicity_windows() {
    let yaml = r#"proxies:
  - name: legacy-udp
    type: vless
    server: legacy.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    udp: true
    xudp: false
  - name: disabled-packet-udp
    type: vless
    server: packet.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    udp: true
    packet-encoding: none
  - name: disabled-mux
    type: vless
    server: mux.example
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    udp: true
    smux:
      enabled: false
  - name: default-window
    type: juicity
    server: juic-good.example
    port: 443
    uuid: 44444444-4444-4444-8444-444444444444
    password: secret
    initial-stream-receive-window: 8388608
    initial-conn-receive-window: "8388608"
    mtu: 1400
  - name: custom-window
    type: juicity
    server: juic-bad.example
    port: 443
    uuid: 55555555-5555-4555-8555-555555555555
    password: secret
    initial-stream-receive-window: 1234
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].name, "disabled-mux");
    assert_eq!(
        nodes[0].vless().unwrap().mode,
        honk_config::node::WireMode::Xudp
    );
    assert_eq!(nodes[1].name, "default-window");
    assert_eq!(nodes[1].juicity().unwrap().quic.mtu, Some(1400));
}
