use super::*;

mod vless;

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
fn clash_vmess_udp_claim_imports_the_tcp_node() {
    let yaml = r#"proxies:
  - {name: udp-claim, type: vmess, server: vmess.example, port: 443, uuid: 11111111-1111-4111-8111-111111111111, cipher: auto, network: ws, ws-opts: {path: /}, udp: true}
  - {name: tcp-only, type: vmess, server: vmess.example, port: 443, uuid: 22222222-2222-4222-8222-222222222222, cipher: auto, udp: false}
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["udp-claim", "tcp-only"]
    );
    assert_eq!(nodes[0].vmess().unwrap().network, None);
    assert_eq!(nodes[1].vmess().unwrap().network.as_deref(), Some("tcp"));
    assert!(!honk_outbound::descriptor::carries_udp(
        honk_outbound::descriptor::UdpPath::Own(&nodes[0])
    ));
}

#[test]
fn tuic_alpn_defaults_follow_the_subscription_dialect() {
    for (alpn, clash_expected, other_expected) in [
        (None, Some("h3"), None),
        (Some("null"), Some("h3"), None),
        (Some("[]"), Some(""), Some("")),
        (Some(r#""""#), Some(""), Some("")),
        (Some(r#""  ""#), Some("  "), Some("  ")),
        (Some(r#"["tuic"]"#), Some("tuic"), Some("tuic")),
        (Some(r#"["h3","tuic"]"#), Some("h3,tuic"), Some("h3,tuic")),
    ] {
        let field = alpn.map_or_else(String::new, |value| format!(r#", "alpn": {value}"#));
        let clash = format!(
            r#"{{"proxies":[{{"name":"tuic","type":"tuic","server":"127.0.0.1","port":443,
                "uuid":"11111111-1111-4111-8111-111111111111","password":"secret"{field}}}]}}"#
        );
        let sing_box = format!(
            r#"{{"outbounds":[{{"tag":"tuic","type":"tuic","server":"127.0.0.1","server_port":443,
                "uuid":"11111111-1111-4111-8111-111111111111","password":"secret",
                "tls":{{"enabled":true{field}}}}}]}}"#
        );
        for (content, expected) in [(clash, clash_expected), (sing_box, other_expected)] {
            let nodes = parse_subscription_content(&Subscription::default(), &content).unwrap();
            assert_eq!(
                nodes[0].tuic().unwrap().alpn.as_deref(),
                expected,
                "{content}"
            );
        }
    }
}

#[test]
fn tuic_source_default_preserves_runtime_reuse_until_alpn_changes() {
    use honk_outbound::runtime::OutboundRuntimeRegistry;
    use std::sync::Arc;

    let parse = |alpn| {
        parse_clash_subscription(
            &format!(
                "proxies:\n  - name: tuic\n    type: tuic\n    server: 127.0.0.1\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    password: secret\n{alpn}"
            ),
            None,
        )
        .unwrap()
        .remove(0)
    };
    let explicit = parse("    alpn: [h3]\n");
    let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&explicit)).unwrap();
    let original = first.get(&explicit.id).unwrap();
    for (alpn, should_reuse) in [
        ("", true),
        ("    alpn: null\n", true),
        ("    alpn: [tuic]\n", false),
    ] {
        let imported = parse(alpn);
        assert_eq!(imported.id, explicit.id);
        let (next, reused) = OutboundRuntimeRegistry::build_reusing(
            std::slice::from_ref(&imported),
            64,
            Some(&first),
        )
        .unwrap();
        assert_eq!(reused.contains(&imported.id), should_reuse);
        assert_eq!(
            Arc::ptr_eq(&original, &next.get(&imported.id).unwrap()),
            should_reuse
        );
    }
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
    sni: mask.example
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
fn clash_imports_fingerprint_as_certificate_pin() {
    const PIN: &str = "84c855b4a09bba0ff518c778c0540da87acb9871dd3ae6dc5e8f78423e7ede05";
    let yaml = format!(
        r#"proxies:
  - {{name: tuic, type: tuic, server: tuic.example, port: 443, uuid: 11111111-1111-4111-8111-111111111111, password: secret, fingerprint: {PIN}}}
  - {{name: trojan, type: trojan, server: trojan.example, port: 443, password: secret, fingerprint: {PIN}}}
  - {{name: conflict, type: hysteria2, server: hy2.example, port: 443, password: secret, pin-sha256: 0000000000000000000000000000000000000000000000000000000000000000, fingerprint: {PIN}}}
  - {{name: socks, type: socks5, server: socks.example, port: 1080, fingerprint: {{enabled: false}}}}
"#
    );
    let nodes = parse_clash_subscription(&yaml, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["tuic", "trojan"]
    );
    assert_eq!(
        nodes[0].tuic().unwrap().quic.tls.pin_sha256.as_deref(),
        Some(PIN)
    );
    assert_eq!(
        nodes[1].trojan().unwrap().tls.pin_sha256.as_deref(),
        Some(PIN)
    );
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
    for protocol in ["vless", "vmess", "trojan"] {
        let credential = if protocol == "trojan" {
            "password: secret"
        } else {
            "uuid: 11111111-1111-4111-8111-111111111111"
        };
        for (headers, expected) in [
            ("{Host: false}", Some("fallback.example")),
            ("{Host: [ignored]}", Some("fallback.example")),
            ("{Host: {ignored: true}}", Some("fallback.example")),
            ("{Host: .nan}", Some("fallback.example")),
            ("{Host: null, host: '  '}", Some("fallback.example")),
            ("{Host: false, host: front.example}", Some("front.example")),
            ("{Host: front.example, host: false}", Some("front.example")),
            (
                "{Host: first.example, host: second.example}",
                Some("first.example"),
            ),
            ("{Host: 5}", Some("5")),
            ("{Host: front.example, X-Bad: false}", None),
        ] {
            let input = format!(
                "proxies: [{{name: host-case, type: {protocol}, server: ws.example, port: 443, {credential}, tls: true, network: ws, ws-opts: {{headers: {headers}}}, ws-headers: fallback.example, ws-host: {{ignored: true}}}}]"
            );
            let result = parse_clash_subscription(&input, None);
            if let Some(expected) = expected {
                let nodes = result.unwrap();
                assert_eq!(nodes[0].name, "host-case");
                assert_eq!(
                    nodes[0].transport().unwrap().ws_host.as_deref(),
                    Some(expected)
                );
            } else {
                assert!(
                    result.is_err(),
                    "{protocol}: invalid non-Host header admitted"
                );
            }
        }
        let invalid_fallback = format!(
            "proxies: [{{type: {protocol}, server: ws.example, port: 443, {credential}, tls: true, network: ws, ws-opts: {{headers: {{Host: false}}}}, ws-headers: false, ws-host: fallback.example}}]"
        );
        assert!(parse_clash_subscription(&invalid_fallback, None).is_err());
    }
}

#[test]
fn clash_accepts_explicit_native_vless_udp_and_rejects_nondefault_juicity_windows() {
    let yaml = r#"proxies:
  - name: native-from-xudp-false
    type: vless
    server: legacy.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    udp: true
    xudp: false
  - name: native-from-none
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
    assert_eq!(nodes.len(), 4);
    assert_eq!(nodes[0].name, "native-from-xudp-false");
    assert_eq!(
        nodes[0].vless().unwrap().udp_encoding,
        honk_config::node::VlessUdpEncoding::Native
    );
    assert_eq!(
        nodes[1].vless().unwrap().udp_encoding,
        honk_config::node::VlessUdpEncoding::Native
    );
    assert_eq!(
        nodes[2].vless().unwrap().udp_encoding,
        honk_config::node::VlessUdpEncoding::Xudp
    );
    assert_eq!(nodes[3].name, "default-window");
    assert_eq!(nodes[3].juicity().unwrap().quic.mtu, Some(1400));
}

const C07_CLASH_SERVERNAME_ALIASES: &str = r#"proxies:
  - name: empty
    type: trojan
    server: empty.example
    port: 443
    password: fixture-password
    servername: ""
    server-name: " \t"
    sni: null
  - name: equal
    type: trojan
    server: equal.example
    port: 443
    password: fixture-password
    servername: tls.example
    server-name: tls.example
    sni: tls.example
  - name: baseline
    type: trojan
    server: equal.example
    port: 443
    password: fixture-password
    sni: tls.example
  - name: conflict
    type: trojan
    server: conflict.example
    port: 443
    password: fixture-password
    servername: first.example
    server-name: second.example
"#;

#[test]
fn c07_clash_tls_name_aliases_normalize_empty_equal_and_conflict() {
    let nodes = parse_clash_subscription(C07_CLASH_SERVERNAME_ALIASES, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["empty", "equal", "baseline"]
    );
    assert_eq!(nodes[0].tls().unwrap().sni, None);
    assert_eq!(nodes[1].tls().unwrap().sni.as_deref(), Some("tls.example"));
    assert_eq!(nodes[1].id, nodes[2].id);
}

const C09_CLASH_NONFINITE_CREDENTIAL: &str = r#"proxies:
  - name: nonfinite-password
    type: hysteria2
    server: nonfinite.example
    port: 443
    auth: usable-auth
    password: .nan
  - name: finite-password
    type: hysteria2
    server: finite.example
    port: 443
    auth: usable-auth
    password: 12345
"#;

#[test]
fn c09_clash_rejects_nonfinite_credential_even_with_valid_alias() {
    let nodes = parse_clash_subscription(C09_CLASH_NONFINITE_CREDENTIAL, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["finite-password"]
    );
    assert_eq!(
        nodes[0].hysteria2().unwrap().auth.as_deref(),
        Some("usable-auth")
    );
}

const C11_CLASH_ANYTLS_NETWORK: &str = r#"proxies:
  - name: anytls-udp-first
    type: anytls
    server: udp-first.example
    port: 443
    password: password
    anytls-network: udp
    network: tcp,udp
    udp: true
  - name: anytls-list-first
    type: anytls
    server: list-first.example
    port: 443
    password: password
    anytls-network: tcp,udp
    network: udp
    udp: true
  - name: anytls-boolean-only
    type: anytls
    server: boolean-only.example
    port: 443
    password: password
    udp: true
  - name: anytls-tcp
    type: anytls
    server: tcp.example
    port: 443
    password: password
    anytls-network: tcp
    udp: false
  - name: anytls-empty
    type: anytls
    server: empty.example
    port: 443
    password: password
    anytls-network: ""
    network: null
  - name: anytls-conflict
    type: anytls
    server: conflict.example
    port: 443
    password: password
    anytls-network: tcp
    udp: true
  - name: anytls-unsupported
    type: anytls
    server: unsupported.example
    port: 443
    password: password
    network: quic
"#;

#[test]
fn c11_clash_anytls_network_aliases_resolve_before_udp() {
    let nodes = parse_clash_subscription(C11_CLASH_ANYTLS_NETWORK, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        [
            "anytls-udp-first",
            "anytls-list-first",
            "anytls-boolean-only",
            "anytls-tcp",
            "anytls-empty"
        ]
    );
    assert_eq!(nodes[0].anytls().unwrap().network.as_deref(), Some("udp"));
    assert_eq!(
        nodes[1].anytls().unwrap().network.as_deref(),
        Some("tcp,udp")
    );
    assert_eq!(
        nodes[2].anytls().unwrap().network.as_deref(),
        Some("tcp,udp")
    );
    assert_eq!(nodes[3].anytls().unwrap().network.as_deref(), Some("tcp"));
    assert_eq!(nodes[4].anytls().unwrap().network, None);
    assert_eq!(
        nodes
            .iter()
            .map(|node| {
                honk_outbound::descriptor::carries_udp(honk_outbound::descriptor::UdpPath::Own(
                    node,
                ))
            })
            .collect::<Vec<_>>(),
        [true, true, true, false, true]
    );
}

#[test]
fn c14_feed_duration_aliases_compare_after_ceiling() {
    const FEED: &str = r#"proxies:
      - {name: hy2, type: hysteria2, server: example.com, port: 443, password: password, hop-interval: 500ms, mhop: 1s}
      - {name: anytls, type: anytls, server: example.com, port: 443, password: password, idle-session-timeout: 1000ms, idle-session-check-interval: 0ms}
    "#;
    let nodes = parse_clash_subscription(FEED, None).unwrap();
    assert_eq!(
        nodes.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
        ["hy2", "anytls"]
    );
    assert_eq!(nodes[0].hysteria2().unwrap().hop_interval, Some(1));
    assert_eq!(nodes[1].anytls().unwrap().idle_session_timeout, Some(1));
    assert_eq!(
        nodes[1].anytls().unwrap().idle_session_check_interval,
        Some(0)
    );
}

#[test]
fn clash_imports_websocket_upgrade_headers() {
    let yaml = r#"proxies:
  - name: ws
    type: vless
    server: ws.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    servername: tls.example
    network: ws
    ws-opts:
      path: /path
      headers:
        Host: front.example
        User-Agent: 'Mozilla/5.0 (X11; Linux x86_64)'
        X-CDN-Token: abc
        Ignored: null
  - name: other-ua
    type: vless
    server: ws.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    servername: tls.example
    network: ws
    ws-opts:
      path: /path
      headers:
        Host: front.example
        User-Agent: curl/8
  - {name: nested, type: vless, server: nested.example, port: 443, uuid: 22222222-2222-4222-8222-222222222222, network: ws, ws-opts: {headers: {X-Nested: {a: b}}}}
  - {name: managed, type: vless, server: managed.example, port: 443, uuid: 33333333-3333-4333-8333-333333333333, network: ws, ws-opts: {headers: {Connection: Upgrade}}}
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes.len(), 2);
    let transport = &nodes[0].vless().unwrap().transport;
    assert_eq!(transport.ws_host.as_deref(), Some("front.example"));
    assert_eq!(
        transport.ws_headers["user-agent"],
        "Mozilla/5.0 (X11; Linux x86_64)"
    );
    assert_eq!(transport.ws_headers["x-cdn-token"], "abc");
    assert_eq!(transport.ws_headers.len(), 2);
    assert_eq!(nodes[0].id, nodes[0].derive_id());
    // The header joins the dial shape, so it changes node identity.
    assert_eq!(
        nodes[1].vless().unwrap().transport.ws_headers["user-agent"],
        "curl/8"
    );
    assert_ne!(nodes[0].id, nodes[1].id);
}

#[test]
fn clash_hysteria2_coalesces_equivalent_port_hopping_aliases() {
    let fixture = r#"proxies:
  - name: hy2-range-both
    type: hysteria2
    server: hy2-1.example
    port: 443
    password: secret
    ports: "35000-39000"
    mport: "35000-39000"
  - name: hy2-mixed-both
    type: hysteria2
    server: hy2-2.example
    port: 443
    password: secret
    ports: "443,5000-5010"
    mport: "443,5000-5010"
  - name: hy2-single-port
    type: hysteria2
    server: hy2-3.example
    port: 443
    password: secret
  - name: vless-control
    type: vless
    server: vless.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
"#;
    let mut diagnostics = Vec::new();
    let nodes = parse_subscription_content_with_diagnostics(
        &Subscription {
            sub_type: SubscriptionType::Clash,
            ..Default::default()
        },
        fixture,
        &mut diagnostics,
    )
    .unwrap();
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        [
            "hy2-range-both",
            "hy2-mixed-both",
            "hy2-single-port",
            "vless-control"
        ]
    );
    assert_eq!(
        nodes[0].hysteria2().unwrap().port_hopping.as_deref(),
        Some("35000-39000")
    );
    assert_eq!(
        nodes[1].hysteria2().unwrap().port_hopping.as_deref(),
        Some("443,5000-5010")
    );
    assert_eq!(nodes[2].hysteria2().unwrap().port_hopping, None);
    assert_eq!(nodes[3].protocol(), NodeProtocol::VLess);

    let equivalent = r#"proxies:
  - name: seq-and-reordered
    type: hysteria2
    server: eq-1.example
    port: 443
    password: secret
    ports: ["4000:5000", 6000]
    mport: "6000, 4000-5000"
  - name: adjacent-merged
    type: hysteria2
    server: eq-2.example
    port: 443
    password: secret
    ports: "5000-5005,5006-5010"
    mport: "5000-5010"
  - name: colon-and-hyphen
    type: hysteria2
    server: eq-3.example
    port: 443
    password: secret
    mport: "4000:5000"
    port-hopping: "4000-5000"
    port_hopping: "4000:5000"
"#;
    let nodes = parse_clash_subscription(equivalent, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| (
                node.name.as_str(),
                node.hysteria2().unwrap().port_hopping.as_deref()
            ))
            .collect::<Vec<_>>(),
        [
            ("seq-and-reordered", Some("4000-5000,6000")),
            ("adjacent-merged", Some("5000-5005,5006-5010")),
            ("colon-and-hyphen", Some("4000-5000")),
        ]
    );
}

#[test]
fn clash_hysteria2_port_hopping_handles_blank_null_conflict_and_invalid_aliases() {
    let valid_absent = r#"proxies:
  - name: blank-mport
    type: hysteria2
    server: absent-1.example
    port: 443
    password: secret
    ports: "35000-39000"
    mport: ""
  - name: null-mport
    type: hysteria2
    server: absent-2.example
    port: 443
    password: secret
    ports: "35000-39000"
    mport: null
    port-hopping: "  "
    port_hopping: []
  - name: standalone-empty-string
    type: hysteria2
    server: absent-3.example
    port: 443
    password: secret
    ports: ""
  - name: standalone-empty-seq
    type: hysteria2
    server: absent-4.example
    port: 443
    password: secret
    ports: []
"#;
    let nodes = parse_clash_subscription(valid_absent, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| (
                node.name.as_str(),
                node.hysteria2().unwrap().port_hopping.as_deref()
            ))
            .collect::<Vec<_>>(),
        [
            ("blank-mport", Some("35000-39000")),
            ("null-mport", Some("35000-39000")),
            ("standalone-empty-string", None),
            ("standalone-empty-seq", None),
        ]
    );

    let rejected = r#"proxies:
  - name: genuine-conflict
    type: hysteria2
    server: conflict.example
    port: 443
    password: secret
    ports: "35000-39000"
    mport: "20000-25000"
  - name: invalid-beside-valid
    type: hysteria2
    server: invalid-1.example
    port: 443
    password: secret
    ports: "35000-39000"
    mport: "bad"
  - name: duplicate-port-beside-valid
    type: hysteria2
    server: invalid-2.example
    port: 443
    password: secret
    ports: "35000-39000"
    mport: "35000-39000,35000"
  - name: comma-only
    type: hysteria2
    server: invalid-3.example
    port: 443
    password: secret
    ports: ","
  - name: spaced-comma-only
    type: hysteria2
    server: invalid-4.example
    port: 443
    password: secret
    ports: " , "
  - name: seq-empty-string
    type: hysteria2
    server: invalid-5.example
    port: 443
    password: secret
    ports: [""]
  - name: seq-null-entry
    type: hysteria2
    server: invalid-6.example
    port: 443
    password: secret
    ports: [null]
  - name: survivor
    type: hysteria2
    server: survivor.example
    port: 443
    password: secret
"#;
    let mut diagnostics = Vec::new();
    let nodes = parse_subscription_content_with_diagnostics(
        &Subscription {
            sub_type: SubscriptionType::Clash,
            ..Default::default()
        },
        rejected,
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["survivor"]
    );
    assert_eq!(diagnostics.len(), 7);
    for (index, diagnostic) in diagnostics.iter().enumerate() {
        assert_eq!(diagnostic.code, "malformed-subscription-entry");
        assert_eq!(diagnostic.entry_index, Some(index + 1));
    }
    assert_eq!(
        diagnostics[0].message,
        "Hysteria2 port hopping aliases conflict"
    );
}

#[test]
fn clash_hysteria2_ports_only_and_ports_with_mport_preserve_identity_and_reuse() {
    use honk_outbound::runtime::OutboundRuntimeRegistry;
    use std::sync::Arc;

    let ports_only = parse_clash_subscription(
        r#"proxies:
  - name: hy2
    type: hysteria2
    server: 127.0.0.1
    port: 443
    password: secret
    ports: ["4000:5000", 6000]
"#,
        None,
    )
    .unwrap()
    .remove(0);
    let with_mport = parse_clash_subscription(
        r#"proxies:
  - name: hy2
    type: hysteria2
    server: 127.0.0.1
    port: 443
    password: secret
    ports: ["4000:5000", 6000]
    mport: "6000,4000-5000"
"#,
        None,
    )
    .unwrap()
    .remove(0);

    assert_eq!(ports_only.id, with_mport.id);
    assert_eq!(
        ports_only.hysteria2().unwrap().port_hopping,
        with_mport.hysteria2().unwrap().port_hopping
    );
    assert_eq!(
        with_mport.hysteria2().unwrap().port_hopping.as_deref(),
        Some("4000-5000,6000")
    );
    assert_eq!(ports_only.outbound, with_mport.outbound);

    let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&ports_only)).unwrap();
    let original = first.get(&ports_only.id).unwrap();
    let (next, reused) =
        OutboundRuntimeRegistry::build_reusing(std::slice::from_ref(&with_mport), 64, Some(&first))
            .unwrap();
    assert!(reused.contains(&with_mport.id));
    assert!(Arc::ptr_eq(&original, &next.get(&with_mport.id).unwrap()));
}

#[test]
fn clash_dialer_proxy_imports_two_to_four_hop_chains_with_canonical_ids() {
    use honk_outbound::runtime::OutboundRuntimeRegistry;

    let mut sub = Subscription {
        name: "feed".into(),
        url: "https://example.com/sub".into(),
        sub_type: SubscriptionType::Clash,
        ..Default::default()
    };
    sub.id = uuid::Uuid::new_v4();

    let yaml = r#"proxies:
  - name: via4
    type: trojan
    server: exit4.example
    port: 443
    password: p4
    sni: exit4.example
    dialer-proxy: via3
  - name: via3
    type: vmess
    server: hop3.example
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    cipher: auto
    network: tcp
    tls: true
    servername: hop3.example
    dialer_proxy: mid
  - name: mid
    type: ss
    server: mid.example
    port: 8388
    cipher: aes-256-gcm
    password: p2
    dialer-proxy: front-alias
  - name: shared-exit-b
    type: trojan
    server: exit4.example
    port: 443
    password: p4
    sni: exit4.example
    dialer-proxy: alt-front
  - name: front
    type: socks5
    server: 127.0.0.1
    port: 1080
    dialer-proxy: ""
  - name: front-alias
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: alt-front
    type: hysteria2
    server: hy2-front.example
    port: 443
    password: hy2p
    dialer_proxy: null
"#;

    let mut diagnostics = Vec::new();
    let nodes = parse_subscription_content_with_diagnostics(&sub, yaml, &mut diagnostics).unwrap();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].code, "duplicate-subscription-entry");
    assert_eq!(diagnostics[0].entry_index, Some(6));
    assert_eq!(diagnostics[0].related_indices, [5]);

    for node in &nodes {
        assert_eq!(node.subscription_id, Some(sub.id));
        assert_eq!(node.id, node.derive_id());
    }

    let hop_nodes: Vec<_> = nodes
        .iter()
        .filter(|node| node.name.starts_with("chain-hop-"))
        .collect();
    assert_eq!(hop_nodes.len(), 3, "{nodes:?}");

    let vmess_hop3 = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(
            r#"{"ps":"hop3","add":"hop3.example","port":443,"id":"33333333-3333-4333-8333-333333333333","scy":"auto","net":"tcp","tls":"tls","sni":"hop3.example"}"#
        )
    );
    let static_dae = honk_config::parser::parse_dae_config(&format!(
        r#"node {{
            front: 'socks5://127.0.0.1:1080'
            alt_front: 'hysteria2://hy2p@hy2-front.example:443'
            mid_hop: 'ss://YWVzLTI1Ni1nY206cDI@mid.example:8388'
            hop3: '{vmess_hop3}'
            exit4: 'trojan://p4@exit4.example:443?sni=exit4.example'
            dae_mid: front -> mid_hop
            dae_via3: front -> mid_hop -> hop3
            dae_via4: front -> mid_hop -> hop3 -> exit4
            dae_shared_b: alt_front -> exit4
        }}"#,
    ))
    .unwrap()
    .assemble(honk_config::parser::resolve_group_filters)
    .unwrap();
    let static_id = |name: &str| {
        static_dae
            .nodes
            .iter()
            .find(|node| node.name == name)
            .unwrap()
            .id
    };

    let by_name = |name: &str| nodes.iter().find(|node| node.name == name).unwrap();
    assert_eq!(by_name("mid").protocol(), NodeProtocol::Chain);
    assert_eq!(by_name("via3").protocol(), NodeProtocol::Chain);
    assert_eq!(by_name("via4").protocol(), NodeProtocol::Chain);
    assert_eq!(by_name("shared-exit-b").protocol(), NodeProtocol::Chain);
    assert_eq!(by_name("mid").id, static_id("dae_mid"));
    assert_eq!(by_name("via3").id, static_id("dae_via3"));
    assert_eq!(by_name("via4").id, static_id("dae_via4"));
    assert_eq!(by_name("shared-exit-b").id, static_id("dae_shared_b"));
    assert_eq!(by_name("via4").chain_hops().unwrap()[0], "front");
    assert_eq!(
        by_name("shared-exit-b").chain_hops().unwrap()[0],
        "alt-front"
    );

    let mut config = honk_config::parser::parse_dae_config(
        "group {\n selectable { filter: subtag(feed) && !name(keyword: 'chain-hop-') }\n chains { filter: name(mid, via3, via4, 'shared-exit-b') }\n}",
    )
    .unwrap();
    config.subscriptions.push(sub);
    config.nodes = nodes;
    let assembled = config
        .assemble(honk_config::parser::resolve_group_filters)
        .unwrap();
    let selectable: Vec<_> = assembled.groups[0]
        .nodes
        .iter()
        .map(|id| {
            assembled
                .nodes
                .iter()
                .find(|n| n.id == *id)
                .unwrap()
                .name
                .as_str()
        })
        .collect();
    assert_eq!(
        selectable,
        ["via4", "via3", "mid", "shared-exit-b", "front", "alt-front"]
    );
    assert_eq!(assembled.groups[1].nodes.len(), 4);
    OutboundRuntimeRegistry::build(&assembled.nodes).unwrap();
}

#[test]
fn clash_dialer_proxy_rejects_cycles_five_hops_groups_builtins_and_capabilities() {
    let yaml = r#"proxy-groups:
  - name: auto-group
    type: url-test
    proxies: [h1]
proxies:
  - {name: h1, type: socks5, server: 127.0.0.1, port: 1081}
  - {name: h2, type: socks5, server: 127.0.0.1, port: 1082, dialer-proxy: h1}
  - {name: h3, type: socks5, server: 127.0.0.1, port: 1083, dialer-proxy: h2}
  - {name: h4, type: socks5, server: 127.0.0.1, port: 1084, dialer-proxy: h3}
  - {name: too-deep, type: socks5, server: 127.0.0.1, port: 1085, dialer-proxy: h4}
  - {name: self-loop, type: socks5, server: 127.0.0.1, port: 1086, dialer-proxy: self-loop}
  - {name: cycle-a, type: socks5, server: 127.0.0.1, port: 1087, dialer-proxy: cycle-b}
  - {name: cycle-b, type: socks5, server: 127.0.0.1, port: 1088, dialer-proxy: cycle-a}
  - {name: into-cycle, type: socks5, server: 127.0.0.1, port: 1089, dialer-proxy: cycle-a}
  - {name: missing-hop, type: socks5, server: 127.0.0.1, port: 1090, dialer-proxy: ghost}
  - {name: dup-hop, type: socks5, server: 127.0.0.1, port: 1091}
  - {name: dup-hop, type: socks5, server: 127.0.0.1, port: 1092}
  - {name: uses-dup, type: socks5, server: 127.0.0.1, port: 1093, dialer-proxy: dup-hop}
  - {name: same-endpoint, type: socks5, server: 127.0.0.1, port: 1081, dialer-proxy: h1}
  - {name: via-group, type: socks5, server: 127.0.0.1, port: 1094, dialer-proxy: auto-group}
  - {name: via-direct, type: socks5, server: 127.0.0.1, port: 1095, dialer-proxy: DIRECT}
  - {name: via-reject, type: socks5, server: 127.0.0.1, port: 1096, dialer-proxy: REJECT}
  - {name: hy2-exit, type: hysteria2, server: hy2.example, port: 443, password: p, dialer-proxy: h1}
  - {name: tuic-exit, type: tuic, server: tuic.example, port: 443, uuid: 11111111-1111-4111-8111-111111111111, password: p, dialer-proxy: h1}
  - {name: juicity-exit, type: juicity, server: juic.example, port: 443, uuid: 22222222-2222-4222-8222-222222222222, password: p, dialer-proxy: h1}
  - {name: anytls-exit, type: anytls, server: any.example, port: 443, password: p, dialer-proxy: h1}
  - {name: xhttp-exit, type: vless, server: xhttp.example, port: 443, uuid: 33333333-3333-4333-8333-333333333333, tls: true, network: xhttp, dialer-proxy: h1}
  - {name: vision-exit, type: vless, server: vision.example, port: 443, uuid: 44444444-4444-4444-8444-444444444444, tls: true, flow: xtls-rprx-vision, dialer-proxy: h1}
  - {name: enc-exit, type: vless, server: enc.example, port: 443, uuid: 55555555-5555-4555-8555-555555555555, encryption: mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, dialer-proxy: h1}
  - {name: mux-exit, type: vless, server: mux.example, port: 443, uuid: 66666666-6666-4666-8666-666666666666, smux: {enabled: true, protocol: h2mux}, dialer-proxy: h1}
  - {name: plugin-hop, type: ss, server: plug.example, port: 8388, cipher: aes-256-gcm, password: p, plugin: obfs-local}
  - {name: via-plugin, type: socks5, server: 127.0.0.1, port: 1097, dialer-proxy: plugin-hop}
  - {name: conflict-detour, type: socks5, server: 127.0.0.1, port: 1098, dialer-proxy: h1, dialer_proxy: h2}
  - {name: bad-detour-type, type: socks5, server: 127.0.0.1, port: 1099, dialer-proxy: [h1]}
"#;

    for sub_type in [SubscriptionType::Clash, SubscriptionType::Simple] {
        let sub = Subscription {
            name: "feed".into(),
            url: "https://example.com/sub".into(),
            sub_type,
            ..Default::default()
        };
        let mut diagnostics = Vec::new();
        let nodes =
            parse_subscription_content_with_diagnostics(&sub, yaml, &mut diagnostics).unwrap();
        let non_backing: Vec<_> = nodes
            .iter()
            .filter(|n| !n.name.starts_with("chain-hop-"))
            .map(|n| (n.name.as_str(), n.protocol()))
            .collect();
        assert_eq!(
            non_backing,
            [
                ("h1", NodeProtocol::Socks5),
                ("h2", NodeProtocol::Chain),
                ("h3", NodeProtocol::Chain),
                ("h4", NodeProtocol::Chain),
                ("dup-hop", NodeProtocol::Socks5),
                ("dup-hop", NodeProtocol::Socks5),
            ]
        );
        let config = honk_config::Config {
            nodes,
            subscriptions: vec![sub],
            ..Default::default()
        };
        config.validate_assembled().unwrap();

        let by_index: std::collections::HashMap<_, _> = diagnostics
            .iter()
            .map(|d| (d.entry_index.unwrap(), (d.code, d.message)))
            .collect();
        for index in [5, 6, 7, 8, 9, 10, 13, 14, 28, 29] {
            assert_eq!(
                by_index.get(&index).map(|&(code, _)| code),
                Some("malformed-subscription-entry"),
                "entry {index}"
            );
        }
        assert_eq!(
            by_index[&5].1,
            "subscription chain exceeds maximum hop count"
        );
        assert_eq!(by_index[&6].1, "subscription chain contains a cycle");
        assert_eq!(by_index[&7].1, "subscription chain contains a cycle");
        assert_eq!(by_index[&9].1, "subscription chain contains a cycle");
        assert_eq!(
            by_index[&14].1,
            "subscription chain repeats a physical hop endpoint"
        );
        for index in [15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27] {
            assert_eq!(
                by_index.get(&index).map(|&(code, _)| code),
                Some("unsupported-subscription-entry"),
                "entry {index}"
            );
        }
    }
}
