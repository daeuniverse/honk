use super::*;

#[test]
fn test_group_policy_serde_lowercase() {
    assert_eq!(
        serde_json::from_str::<GroupPolicy>("\"selector\"").unwrap(),
        GroupPolicy::Selector
    );
    assert_eq!(
        serde_json::from_str::<GroupPolicy>("\"urltest\"").unwrap(),
        GroupPolicy::URLTest
    );
    assert_eq!(
        serde_json::from_str::<GroupPolicy>("\"loadbalance\"").unwrap(),
        GroupPolicy::LoadBalance
    );
    assert_eq!(
        serde_json::from_str::<GroupPolicy>("\"fallback\"").unwrap(),
        GroupPolicy::Fallback
    );
    // dae-style alias for LoadBalance.
    assert_eq!(
        serde_json::from_str::<GroupPolicy>("\"roundrobin\"").unwrap(),
        GroupPolicy::LoadBalance
    );
    assert_eq!(
        serde_json::to_string(&GroupPolicy::LoadBalance).unwrap(),
        "\"loadbalance\""
    );
    assert_eq!(
        serde_json::to_string(&GroupPolicy::URLTest).unwrap(),
        "\"urltest\""
    );
    assert_eq!(
        serde_json::from_str::<GroupPolicy>("\"score\"").unwrap(),
        GroupPolicy::Score
    );
    assert_eq!(
        serde_json::to_string(&GroupPolicy::Score).unwrap(),
        "\"score\""
    );
}

#[test]
fn test_group_policy_serde_rejects_legacy_honk() {
    assert!(serde_json::from_str::<GroupPolicy>("\"honk\"").is_err());
}

#[test]
fn test_protocol_identity_goldens() {
    let cases = [
        (
            "vless-ws",
            "vless://00000000-0000-4000-8000-000000000001@ws.example:443?type=ws&path=%2Fws#ws",
            "ff344bcb-482a-5b1d-b435-f75734608c61",
        ),
        (
            "ss",
            "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss",
            "e4a92538-53a2-5f83-85cd-b5d11f90361b",
        ),
        (
            "socks5",
            "socks5://user:pass@1.2.3.4:1080#socks5",
            "4257ffb1-f1ac-5838-b020-fe5c08dc99f8",
        ),
        (
            "trojan",
            "trojan://secret@example.com:443#trojan",
            "6b92dad3-62ea-5dcd-a71f-fd67105ccfe1",
        ),
        (
            "vmess",
            "vmess://eyJwcyI6InZtZXNzIiwiYWRkIjoiZXhhbXBsZS5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJzY3kiOiJhdXRvIiwibmV0IjoidGNwIiwidGxzIjoidGxzIn0",
            "263e811a-31e9-572f-bb87-66f1fc63ce98",
        ),
        (
            "hysteria2",
            "hysteria2://secret@example.com:443#hysteria2",
            "f622cf2a-ef2e-5777-abdb-d8c826d11f57",
        ),
        (
            "tuic",
            "tuic://00000000-0000-0000-0000-000000000001:pass@example.com:443#tuic",
            "e8751061-7db8-5d0d-b2e9-04af9ce55d02",
        ),
        (
            "juicity",
            "juicity://00000000-0000-0000-0000-000000000001:pass@example.com:443#juicity",
            "26d8181d-9c09-580d-86bc-1bdc22f1d113",
        ),
        (
            "anytls",
            "anytls://secret@example.com:443#anytls",
            "743d15b1-586a-5095-9e49-58c6f444f738",
        ),
    ];

    for (name, link, expected) in cases {
        let mut node = Node::from_share_link(link).unwrap();
        // Admission changed; the historical identity material and hashes did not.
        match &mut node.outbound {
            OutboundConfig::Tuic(config) => config.uuid = Some("uuid".into()),
            OutboundConfig::Juicity(config) => config.uuid = Some("uuid".into()),
            _ => {}
        }
        assert_eq!(node.derive_id().to_string(), expected, "{name}");
    }
}

#[test]
fn test_identity_credential_split() {
    for p in ["socks5", "ss", "tuic", "juicity"] {
        let base =
            Node::from_share_link(&format!("{p}://00000000-0000-0000-0000-000000000001:c@h"))
                .unwrap();
        let [left, right] = [("a|b", "c"), ("a", "b|c")].map(|(first, second)| {
            let mut node = base.clone();
            let (credential, password) = match &mut node.outbound {
                OutboundConfig::Socks5(config) => (&mut config.username, &mut config.password),
                OutboundConfig::Shadowsocks(config) => {
                    (&mut config.encryption, &mut config.password)
                }
                OutboundConfig::Tuic(config) => (&mut config.uuid, &mut config.password),
                OutboundConfig::Juicity(config) => (&mut config.uuid, &mut config.password),
                _ => unreachable!(),
            };
            *credential = Some(first.into());
            *password = Some(second.into());
            node.derive_id()
        });
        assert_ne!(left, right);
    }
}

#[test]
fn test_identity_vless_credential_arity() {
    let mut left =
        Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.com:443")
            .unwrap();
    let mut right = left.clone();
    left.vless_mut().unwrap().uuid = Some("b".into());
    left.vless_mut().unwrap().encryption = Some("a".into());
    right.vless_mut().unwrap().uuid = Some("a|b".into());
    assert_ne!(left.derive_id(), right.derive_id());
}

#[test]
fn test_identity_dial_shape_split() {
    let mut left = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?type=ws&sni=a%7Cws&path=%2Fp",
    )
    .unwrap();
    let mut right = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?type=ws&sni=a&path=ws%7C%2Fp",
    )
    .unwrap();
    left.vless_mut().unwrap().uuid = Some("uuid".into());
    right.vless_mut().unwrap().uuid = Some("uuid".into());
    assert_ne!(left.derive_id(), right.derive_id());
}

#[test]
fn test_identity_effective_host_split() {
    let mut node = Node::from_share_link("socks5://a:b@h:443").unwrap();
    let plain_id = node.derive_id();
    node.host = "h|1080".into();
    assert!(node.identity_material().contains(r"|h\|1080|"));
    assert_ne!(node.derive_id(), plain_id);
}

#[test]
fn test_identity_vless_layout_control() {
    let mut encrypted = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?sni=tcp",
    )
    .unwrap();
    let mut xudp = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=xudp&sni=b",
    )
    .unwrap();
    encrypted.vless_mut().unwrap().uuid = Some("b".into());
    encrypted.vless_mut().unwrap().encryption = Some("a".into());
    xudp.vless_mut().unwrap().uuid = Some("a".into());
    assert_ne!(encrypted.derive_id(), xudp.derive_id());
}

#[test]
fn test_identity_escape_mutation_check() {
    let left = [r"|\", ""].map(identity_field).join("|");
    let right = [r"\", "|"].map(identity_field).join("|");
    assert_ne!(left, right);
}

#[test]
fn test_vless_identity_uses_canonical_effective_settings() {
    let off = Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.com:443")
        .unwrap();
    let no_pools = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?mux=xray&concurrency=-1&xudpConcurrency=-1&xudpProxyUDP443=allow",
    )
    .unwrap();
    assert_ne!(off.id, no_pools.id);
    let mut spaced_none = off.clone();
    spaced_none.vless_mut().unwrap().encryption = Some(" none ".into());
    assert_eq!(off.id, spaced_none.derive_id());

    let defaults = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?mux=xray",
    )
    .unwrap();
    let explicit = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?mux=xray&concurrency=8&xudpConcurrency=0",
    )
    .unwrap();
    assert_eq!(defaults.id, explicit.id);

    let pooled_auto = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?mux=xray&xudpConcurrency=8&xudpProxyUDP443=allow",
    )
    .unwrap();
    let pooled_unused_encoding = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=uot-v2&mux=xray&xudpConcurrency=8&xudpProxyUDP443=allow",
    )
    .unwrap();
    assert_eq!(pooled_auto.id, pooled_unused_encoding.id);
}

#[test]
fn test_vless_tls_identity_matches_effective_transport() {
    const LINK: &str = "vless://00000000-0000-0000-0000-000000000001@example.com:443";
    let tls = Node::from_share_link(LINK).unwrap();
    let plain = Node::from_share_link(&format!("{LINK}?security=none")).unwrap();
    assert_ne!(tls.id, plain.id);
    for (query, expected) in [("security=tls&tls=1", tls.id), ("tls=0", plain.id)] {
        assert_eq!(
            Node::from_share_link(&format!("{LINK}?{query}"))
                .unwrap()
                .id,
            expected
        );
    }
    crate::Config {
        nodes: vec![tls, plain],
        ..Default::default()
    }
    .validate()
    .unwrap();

    let reality = Node::from_share_link(&format!("{LINK}?security=reality&pbk=AAA")).unwrap();
    let mut equivalent = reality.clone();
    equivalent.tls_mut().unwrap().enabled = false;
    equivalent.validate().unwrap();
    assert_eq!(reality.id, equivalent.derive_id());
}

/// The addressed UoT v2 / H2MUX PacketAddr dial shapes replaced the
/// connected ones on the wire, so their IDs must not alias the native
/// node or each other, and disabling UDP drops the UDP shape from identity.
#[test]
fn test_vless_addressed_udp_shapes_have_their_own_identities() {
    const LINK: &str = "vless://00000000-0000-0000-0000-000000000001@example.com:443";
    let id = |query: &str| {
        Node::from_share_link(&format!("{LINK}?{query}"))
            .unwrap()
            .id
    };
    let (native, uot, h2) = (
        id("packetEncoding=none"),
        id("packetEncoding=uot-v2"),
        id("mux=h2mux"),
    );
    assert_ne!(uot, native);
    assert_ne!(h2, native);
    assert_ne!(uot, h2);
    assert_ne!(id("mux=h2mux&udp=0"), h2);
}

#[test]
fn test_vless_packet_disable_identity_is_effective() {
    let enabled = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=none",
    )
    .unwrap();
    let disabled = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=none&udp=0",
    )
    .unwrap();
    let mut equivalent = disabled.clone();
    equivalent.vless_mut().unwrap().network = Some(" TCP ".into());
    assert_ne!(enabled.id, disabled.id);
    assert_eq!(disabled.id, equivalent.derive_id());
    for network in ["udp", " TCP, UDP "] {
        let mut equivalent = enabled.clone();
        equivalent.vless_mut().unwrap().network = Some(network.into());
        assert_eq!(enabled.id, equivalent.derive_id());
    }

    let disabled_xudp = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=xudp&udp=0",
    )
    .unwrap();
    assert_eq!(disabled.id, disabled_xudp.id);
}

#[test]
fn test_derive_id_is_content_derived() {
    let node = Node::from_share_link("trojan://secret@example.com:443#one").unwrap();
    // Same content, different name → same ID.
    let mut renamed = node.clone();
    renamed.name = "two".into();
    assert_eq!(node.derive_id(), renamed.derive_id());
    assert_eq!(node.id, node.derive_id());

    // Credential or endpoint change → different ID.
    let mut other_pw = node.clone();
    other_pw.trojan_mut().unwrap().password = Some("other".into());
    assert_ne!(node.derive_id(), other_pw.derive_id());
    let mut other_port = node.clone();
    other_port.port = 8443;
    assert_ne!(node.derive_id(), other_port.derive_id());
    // Dial shape participates: same server behind a different SNI or
    // transport is a different endpoint (CDN fronting).
    let mut other_sni = node.clone();
    other_sni.tls_mut().unwrap().sni = Some("cdn.example".into());
    assert_ne!(node.derive_id(), other_sni.derive_id());
    let mut other_transport = node.clone();
    other_transport.transport_mut().unwrap().transport = "ws".into();
    assert_ne!(node.derive_id(), other_transport.derive_id());
    // Validation and tuning knobs do not participate.
    let mut other_insecure = node.clone();
    other_insecure.tls_mut().unwrap().skip_cert_verify = true;
    assert_eq!(node.derive_id(), other_insecure.derive_id());
}

fn ws_candidate(headers: &[(&str, &str)]) -> Node {
    let mut node = Node::from_share_link(
        "vless://00000000-0000-4000-8000-000000000001@ws.example:443?type=ws&path=%2Fws#ws",
    )
    .unwrap();
    let transport = node.transport_mut().unwrap();
    for (name, value) in headers {
        transport.ws_headers.insert((*name).into(), (*value).into());
    }
    node
}

fn ws_normalized(headers: &[(&str, &str)]) -> Node {
    let mut node = ws_candidate(headers);
    node.normalize_stream_transport().unwrap();
    node.validate_protocol().unwrap();
    node
}

#[test]
fn test_ws_headers_participate_in_identity() {
    let plain = ws_normalized(&[]);
    let with_ua = ws_normalized(&[("User-Agent", "Mozilla/5.0")]);
    assert_eq!(
        with_ua.transport().unwrap().ws_headers["user-agent"],
        "Mozilla/5.0"
    );
    assert_ne!(plain.derive_id(), with_ua.derive_id());

    // Names are case-insensitive: equal-value aliases collapse and do not
    // change identity; differing values conflict.
    assert_eq!(
        ws_normalized(&[("user-agent", "Mozilla/5.0"), ("User-Agent", "Mozilla/5.0")]).derive_id(),
        with_ua.derive_id()
    );
    assert_ne!(
        ws_normalized(&[("user-agent", "curl/8")]).derive_id(),
        with_ua.derive_id()
    );
    let mut conflicting = ws_candidate(&[("User-Agent", "one"), ("user-agent", "two")]);
    assert!(conflicting.normalize_stream_transport().is_err());
}

#[test]
fn test_ws_header_admission_bounds_and_reserved_names() {
    for (name, value) in [
        ("host", "cdn.example"),
        ("Connection", "keep-alive"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-extensions", ""),
        ("sec-websocket-accept", ""),
        ("content-length", "0"),
        ("transfer-encoding", "chunked"),
        ("sec-websocket-key", "x"),
        ("sec-websocket-protocol", "v2ray"),
        ("bad name", "x"),
        ("x-test", "\r\n"),
        ("x-test", "\t"),
        ("x-test", "\0"),
        ("x-test", "\u{7f}"),
    ] {
        let mut candidate = ws_candidate(&[(name, value)]);
        assert!(
            candidate.normalize_stream_transport().is_err(),
            "{name} must be rejected"
        );
    }
    for name in ["origin", "cookie", "x-cdn-token"] {
        let mut candidate = ws_candidate(&[(name, "value")]);
        assert!(candidate.normalize_stream_transport().is_ok(), "{name}");
    }

    let mut noncanonical = ws_candidate(&[("User-Agent", "value")]);
    assert!(noncanonical.validate_protocol().is_err());
    noncanonical.normalize_stream_transport().unwrap();
    assert!(noncanonical.validate_protocol().is_ok());
    noncanonical.transport_mut().unwrap().ws_headers = (0..65)
        .map(|index| (format!("x-{index}"), "v".into()))
        .collect();
    assert!(noncanonical.validate_protocol().is_err());

    let mut grpc = ws_candidate(&[("user-agent", "Mozilla/5.0")]);
    let transport = grpc.transport_mut().unwrap();
    transport.transport = "grpc".into();
    transport.grpc_service = Some("service".into());
    assert!(grpc.normalize_stream_transport().is_err());
}

#[test]
fn test_tls_alpn_identity_is_ordered_and_framed() {
    let legacy = Node::from_share_link("anytls://secret@example.com:443#anytls").unwrap();
    assert_eq!(
        legacy.id.to_string(),
        "743d15b1-586a-5095-9e49-58c6f444f738"
    );

    let id_with = |protocols: &[&str]| {
        let mut node = legacy.clone();
        node.tls_mut().unwrap().alpn = protocols.iter().map(|value| (*value).into()).collect();
        node.validate_protocol().unwrap();
        node.derive_id()
    };
    assert_eq!(id_with(&[]), legacy.id);
    let ids = [
        id_with(&["h2"]),
        id_with(&["h2", "http/1.1"]),
        id_with(&["http/1.1", "h2"]),
        id_with(&["a,b", "c"]),
        id_with(&["a", "b,c"]),
    ];
    assert_eq!(
        ids.iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        ids.len()
    );
    assert!(ids.iter().all(|id| *id != legacy.id));

    let mut explicit = legacy.clone();
    explicit.anytls_mut().unwrap().password = Some("p".into());
    explicit.tls_mut().unwrap().alpn = vec!["X||tcp||||||||".into()];
    let mut embedded = legacy;
    embedded.anytls_mut().unwrap().password = Some("p||tcp|||||||||tls-alpn:1:14:X".into());
    assert_ne!(explicit.derive_id(), embedded.derive_id());
}

#[test]
fn test_tls_alpn_validation_boundaries_and_context() {
    for protocol in [String::new(), "x".repeat(256), "é".repeat(128)] {
        let tls = TlsOptions {
            alpn: vec![protocol],
            ..Default::default()
        };
        assert!(tls.validate_alpn().is_err());
    }

    let mut tls = TlsOptions {
        alpn: vec!["x".repeat(255); 255],
        ..Default::default()
    };
    tls.alpn.push("x".repeat(252));
    assert!(tls.validate_alpn().is_ok());
    tls.alpn.push("x".into());
    assert!(tls.validate_alpn().is_err());

    let mut raw = Node::from_share_link("trojan://secret@example.com:443").unwrap();
    raw.transport_mut().unwrap().transport.clear();
    raw.tls_mut().unwrap().alpn = vec!["h2".into()];
    assert!(raw.validate_protocol().is_ok());

    let mut disabled = Node::from_share_link("trojan://secret@example.com:443").unwrap();
    disabled.tls_mut().unwrap().enabled = false;
    disabled.tls_mut().unwrap().alpn = vec!["h2".into()];

    let mut wrapped =
        Node::from_share_link("trojan://secret@example.com:443?type=ws&path=%2Fproxy").unwrap();
    wrapped.tls_mut().unwrap().alpn = vec!["h2".into()];

    let mut reality =
        Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.com:443?security=reality&pbk=public-key")
            .unwrap();
    reality.tls_mut().unwrap().alpn = vec!["h2".into()];

    let mut quic = Node::from_share_link("hysteria2://secret@example.com:443").unwrap();
    quic.tls_mut().unwrap().alpn = vec!["h3".into()];

    for node in [disabled, wrapped, reality, quic] {
        assert!(node.validate_protocol().is_err(), "{}", node.name);
    }
}

#[test]
fn test_validate_redacts_anytls_alpn_context_name() {
    let mut node = Node::from_share_link("anytls://secret@example.com:443#anytls").unwrap();
    assert!(node.validate().is_ok());

    const CANARY: &str = "node-name-canary-anytls";
    node.name = CANARY.into();
    let tls = node.tls_mut().unwrap();
    tls.enabled = false;
    tls.alpn = vec!["h2".into()];

    let error = node.validate().unwrap_err();
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(CANARY), "{rendered}");
}

#[test]
fn test_validate_redacts_vless_path_context_name() {
    let mut node =
        Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.com:443#vless")
            .unwrap();
    assert!(node.validate().is_ok());

    const CANARY: &str = "node-name-canary-vless";
    node.name = CANARY.into();
    let vless = node.vless_mut().unwrap();
    vless.udp_encoding = VlessUdpEncoding::UotV2;
    vless.flow = Some("xtls-rprx-vision".into());
    vless.tls.enabled = true;

    let error = node.validate().unwrap_err();
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(CANARY), "{rendered}");
}
