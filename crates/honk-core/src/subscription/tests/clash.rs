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
            .map(|node| (honk_outbound::descriptor::descriptor(node.protocol()).supports_udp)(node))
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
