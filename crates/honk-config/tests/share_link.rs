//! Integration tests for the unified share-link parser and the
//! extension-aware config (de)serialization.

use base64::Engine as _;
use honk_config::Config;
use honk_config::diagnostic::{SafeValue, Severity};
use honk_config::node::{
    Node, Udp443Policy, VlessMultiplex, VlessUdpEncoding, VlessUdpMux, VlessUdpPath,
};
use honk_config::types::NodeProtocol;

/// URL-safe base64 without padding (the encoding used by vmess links).
fn b64(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
}
fn vmess_link(json: &str) -> String {
    format!("vmess://{}", b64(json))
}

fn vmess_transport_fixture(net: Option<&str>) -> String {
    let mut fixture = serde_json::json!({
        "ps": "vmess-transport-fixture",
        "add": "vmess.example.com",
        "port": 443,
        "id": UUID_A,
        "tls": "tls",
    });
    if let Some(net) = net {
        fixture["net"] = serde_json::json!(net);
    }
    serde_json::to_string(&fixture).unwrap()
}

const UUID_A: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const UUID_B: &str = "00000000-0000-0000-0000-000000000001";

fn flat_credential_fixture(protocol: &str) -> serde_json::Value {
    let mut fixture = serde_json::json!({
        "name": "credential-fixture",
        "protocol": protocol,
        "address": "example.com:443",
        "host": "example.com",
        "port": 443,
    });
    let object = fixture.as_object_mut().expect("object fixture");
    match protocol {
        "tuic" => {
            object.insert("tuic_uuid".into(), serde_json::json!(UUID_A));
        }
        "juicity" => {
            object.insert("juicity_uuid".into(), serde_json::json!(UUID_A));
        }
        _ => {}
    }
    fixture
}

fn flat_node_with(
    protocol: &str,
    fields: &[(&str, serde_json::Value)],
) -> Result<Node, serde_json::Error> {
    let mut fixture = flat_credential_fixture(protocol);
    let object = fixture.as_object_mut().expect("object fixture");
    for (field, value) in fields {
        object.insert((*field).to_string(), value.clone());
    }
    serde_json::from_value(fixture)
}

fn assert_flat_credential_alias(
    protocol: &str,
    dedicated: &str,
    generic: &str,
    equal: &str,
    conflict_a: &str,
    conflict_b: &str,
) {
    let both = flat_node_with(
        protocol,
        &[
            (dedicated, serde_json::json!(equal)),
            (generic, serde_json::json!(equal)),
        ],
    )
    .unwrap();
    let dedicated_only =
        flat_node_with(protocol, &[(dedicated, serde_json::json!(equal))]).unwrap();
    assert_eq!(both.outbound, dedicated_only.outbound);

    let conflict = flat_node_with(
        protocol,
        &[
            (dedicated, serde_json::json!(conflict_a)),
            (generic, serde_json::json!(conflict_b)),
        ],
    );
    assert!(conflict.is_err(), "{protocol}: {dedicated}/{generic}");

    let empty_with_nonempty = flat_node_with(
        protocol,
        &[
            (dedicated, serde_json::json!("")),
            (generic, serde_json::json!(equal)),
        ],
    );
    assert!(
        empty_with_nonempty.is_err(),
        "{protocol}: empty {dedicated} must not hide {generic}"
    );
}

fn serialization_golden_node() -> Node {
    Node {
        id: uuid::Uuid::parse_str("11111111-2222-5333-8444-555555555555").unwrap(),
        name: "golden-vless".into(),
        address: "edge.example:443".into(),
        host: "edge.example".into(),
        port: 443,
        outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some("00000000-0000-0000-0000-000000000001".into()),
            encryption: Some("none".into()),
            udp_encoding: VlessUdpEncoding::Xudp,
            multiplex: VlessMultiplex::Off,
            flow: Some("xtls-rprx-vision".into()),
            network: Some("tcp,udp".into()),
            transport: honk_config::node::StreamTransportOptions {
                transport: "ws".into(),
                ws_path: Some("/ws".into()),
                ws_host: Some("cdn.example".into()),
                ..Default::default()
            },
            tls: honk_config::node::TlsOptions {
                enabled: true,
                sni: Some("front.example".into()),
                skip_cert_verify: true,
                ech_enabled: true,
                ech_config: Some("AAECAw==".into()),
                reality_public_key: Some("reality-public-key".into()),
                reality_short_id: Some("0123456789abcdef".into()),
                reality_spider_x: Some("/spider".into()),
                ..Default::default()
            },
        }),
        mark: Some(7),
        tags: vec!["paid".into(), "hk".into()],
        subscription_id: Some(
            uuid::Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap(),
        ),
        group_id: Some(uuid::Uuid::parse_str("12345678-1234-4234-8234-123456789abc").unwrap()),
        created_at: "2026-01-02T03:04:05Z".parse().unwrap(),
        updated_at: "2026-02-03T04:05:06Z".parse().unwrap(),
    }
}

#[test]
fn test_node_serialization_bytes_match_flat_wire_goldens() {
    let node = serialization_golden_node();
    assert_eq!(
        serde_json::to_string_pretty(&node).unwrap().as_bytes(),
        include_bytes!("fixtures/node_flat.json")
    );
    assert_eq!(
        serde_yaml::to_string(&node).unwrap().as_bytes(),
        include_bytes!("fixtures/node_flat.yaml")
    );
    assert_eq!(
        toml::to_string_pretty(&node).unwrap().as_bytes(),
        include_bytes!("fixtures/node_flat.toml")
    );
}

#[test]
fn test_tls_alpn_flat_wire_round_trip_and_legacy_omission() {
    let legacy = Node::from_share_link("anytls://secret@example.com:443#anytls").unwrap();
    assert!(
        serde_json::to_value(&legacy)
            .unwrap()
            .get("tls_alpn")
            .is_none()
    );

    let mut node = legacy;
    node.tls_mut().unwrap().alpn = vec!["h2".into(), "http/1.1".into()];
    node.validate_protocol().unwrap();
    node.id = node.derive_id();
    let value = serde_json::to_value(&node).unwrap();
    assert_eq!(value["tls_alpn"], serde_json::json!(["h2", "http/1.1"]));

    let restored: Node = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(restored.tls().unwrap().alpn, node.tls().unwrap().alpn);
    assert_eq!(restored.id, node.id);

    let mut unsupported = value;
    unsupported["tls"] = false.into();
    assert!(serde_json::from_value::<Node>(unsupported).is_err());
}

#[test]
fn test_legacy_cross_protocol_fields_are_stripped() {
    let json = r#"{
        "name":"dirty-id",
        "protocol":"socks5",
        "address":"proxy.example:1080",
        "host":"proxy.example",
        "port":1080,
        "username":"user",
        "password":"pass",
        "tls":true,
        "hy2_obfs":"cross-protocol-obfs"
    }"#;
    let node = serde_json::from_str::<Node>(json).unwrap();
    let socks5 = node.socks5().unwrap();
    assert_eq!(socks5.username.as_deref(), Some("user"));
    assert_eq!(socks5.password.as_deref(), Some("pass"));
    assert!(node.tls().is_none());
    assert!(node.hysteria2().is_none());
    let flat = serde_json::to_value(&node).unwrap();
    assert_eq!(flat["tls"], false);
    assert!(flat["hy2_obfs"].is_null());
}

#[test]
fn test_unused_username_credential_is_stripped() {
    let node = serde_json::from_str::<Node>(
        r#"{
                "name":"username-only",
                "protocol":"trojan",
                "address":"proxy.example:443",
                "host":"proxy.example",
                "port":443,
                "username":"secret"
            }"#,
    )
    .unwrap();

    assert!(node.trojan().unwrap().password.is_none());
    assert!(serde_json::to_value(&node).unwrap()["username"].is_null());
}

#[test]
fn test_ss_base64_userinfo() {
    // SIP002: base64("aes-256-gcm:pass") as the whole userinfo.
    let node = Node::from_share_link("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss-b64").unwrap();
    assert_eq!(node.protocol(), NodeProtocol::SS);
    assert_eq!(node.name, "ss-b64");
    assert_eq!(node.host, "1.2.3.4");
    assert_eq!(node.port, 8388);
    assert_eq!(
        node.shadowsocks().unwrap().encryption.as_deref(),
        Some("aes-256-gcm")
    );
    assert_eq!(
        node.shadowsocks().unwrap().password.as_deref(),
        Some("pass")
    );
}

#[test]
fn test_ss_base64_userinfo_with_padding_and_plugin_suffix() {
    // Same but padded base64 and the `/?plugin=...` suffix form.
    let node = Node::from_share_link(
        "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388/?plugin=v2ray-plugin%3Btls#ss-pad",
    )
    .unwrap();
    let ss = node.shadowsocks().unwrap();
    assert_eq!(ss.encryption.as_deref(), Some("aes-256-gcm"));
    assert_eq!(ss.password.as_deref(), Some("pass"));
    assert_eq!(ss.plugin.as_deref(), Some("v2ray-plugin"));
    assert_eq!(ss.plugin_opts.as_deref(), Some("tls"));
}

#[test]
fn test_ss_plain_userinfo() {
    let node = Node::from_share_link("ss://aes-256-gcm:mypassword@2.3.4.5:8389#ss-plain").unwrap();
    assert_eq!(node.protocol(), NodeProtocol::SS);
    assert_eq!(
        node.shadowsocks().unwrap().encryption.as_deref(),
        Some("aes-256-gcm")
    );
    assert_eq!(
        node.shadowsocks().unwrap().password.as_deref(),
        Some("mypassword")
    );
}

#[test]
fn test_ss_plain_userinfo_base64_method() {
    // Plain userinfo whose method part is base64("chacha20-ietf-poly1305").
    let node =
        Node::from_share_link("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ:mypassword@2.3.4.5:8389#ss-bm")
            .unwrap();
    assert_eq!(
        node.shadowsocks().unwrap().encryption.as_deref(),
        Some("chacha20-ietf-poly1305")
    );
    assert_eq!(
        node.shadowsocks().unwrap().password.as_deref(),
        Some("mypassword")
    );
}

#[test]
fn test_ss_with_plugin() {
    let node = Node::from_share_link(
        "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#ss-plugin",
    )
    .unwrap();
    assert_eq!(node.protocol(), NodeProtocol::SS);
    let ss = node.shadowsocks().unwrap();
    assert_eq!(ss.encryption.as_deref(), Some("aes-256-gcm"));
    assert_eq!(ss.plugin.as_deref(), Some("obfs-local"));
    assert_eq!(
        ss.plugin_opts.as_deref(),
        Some("obfs=http;obfs-host=example.com")
    );
}

#[test]
fn test_trojan_ws_query() {
    let node = Node::from_share_link(
        "trojan://pw@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&sni=sni.example.com#trojan-ws",
    )
    .unwrap();
    assert_eq!(node.protocol(), NodeProtocol::Trojan);
    assert_eq!(node.name, "trojan-ws");
    assert!(node.tls().unwrap().enabled);
    assert_eq!(node.trojan().unwrap().password.as_deref(), Some("pw"));
    assert_eq!(node.transport().unwrap().transport, "ws");
    assert_eq!(node.transport().unwrap().ws_path.as_deref(), Some("/ws"));
    assert_eq!(
        node.transport().unwrap().ws_host.as_deref(),
        Some("cdn.example.com")
    );
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("sni.example.com"));
}

#[test]
fn test_anytls_pool_query() {
    let node = Node::from_share_link(
        "anytls://uuid-pw@any.example.com:443?insecure=1&sni=any.example.com&idle_session_check_interval=30s&idle_session_timeout=1m&min_idle_session=4#anytls-node",
    )
    .unwrap();
    assert_eq!(node.protocol(), NodeProtocol::AnyTLS);
    assert!(node.tls().unwrap().enabled);
    assert!(node.tls().unwrap().skip_cert_verify);
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("any.example.com"));
    let anytls = node.anytls().unwrap();
    assert_eq!(anytls.password.as_deref(), Some("uuid-pw"));
    assert_eq!(anytls.idle_session_check_interval, Some(30));
    assert_eq!(anytls.idle_session_timeout, Some(60));
    assert_eq!(anytls.min_idle_session, Some(4));
}

#[test]
fn test_vmess_full_fields_ws_tls() {
    // v2rayN-style base64(JSON) with the full WS+TLS field set.
    let json = r#"{
        "v": "2",
        "ps": "vmess-ws-tls",
        "add": "vmess.example.com",
        "port": "443",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/vmess-ws",
        "tls": "tls",
        "sni": "sni.example.com",
        "alpn": "h2,http/1.1"
    }"#;
    let node = Node::from_share_link(&format!("vmess://{}", b64(json))).unwrap();
    assert_eq!(node.protocol(), NodeProtocol::VMess);
    assert_eq!(node.name, "vmess-ws-tls");
    assert_eq!(node.host, "vmess.example.com");
    assert_eq!(node.address, "vmess.example.com:443");
    assert_eq!(node.port, 443);
    assert_eq!(
        node.vmess().unwrap().uuid.as_deref(),
        Some("b831381d-6324-4d53-ad4f-8cda48b30811")
    );
    assert_eq!(node.vmess().unwrap().encryption.as_deref(), Some("auto"));
    assert_eq!(node.network(), None);
    assert_eq!(node.transport().unwrap().transport, "ws");
    assert!(node.tls().unwrap().enabled);
    assert_eq!(
        node.transport().unwrap().ws_host.as_deref(),
        Some("cdn.example.com")
    );
    assert_eq!(
        node.transport().unwrap().ws_path.as_deref(),
        Some("/vmess-ws")
    );
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("sni.example.com"));
}

#[test]
fn test_vmess_standard_base64_and_numeric_port() {
    // STANDARD base64 alphabet with padding and a numeric JSON port.
    let json = r#"{"add":"1.2.3.4","port":8388,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"tcp","tls":"","security":"aes-128-gcm"}"#;
    let encoded = base64::engine::general_purpose::STANDARD.encode(json);
    let node = Node::from_share_link(&format!("vmess://{}", encoded)).unwrap();
    assert_eq!(node.protocol(), NodeProtocol::VMess);
    assert_eq!(node.host, "1.2.3.4");
    assert_eq!(node.port, 8388);
    assert_eq!(node.transport().unwrap().transport, "tcp");
    assert!(!node.tls().unwrap().enabled);
    // `security` is the older cipher key, picked up when `scy` is absent.
    assert_eq!(
        node.vmess().unwrap().encryption.as_deref(),
        Some("aes-128-gcm")
    );
    // No remark: the name falls back to `vmess-<host>` (never the raw link,
    // which would leak the user id).
    assert_eq!(node.name, "vmess-1.2.3.4");
}

#[test]
fn test_vmess_grpc_service_from_path() {
    // On grpc links the JSON `path` carries the gRPC service name and
    // `host` falls back to the TLS SNI.
    let json = r#"{"ps":"vmess-grpc","add":"g.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"grpc","path":"MyService","host":"sni.example.com","tls":"tls"}"#;
    let node = Node::from_share_link(&format!("vmess://{}", b64(json))).unwrap();
    assert_eq!(node.transport().unwrap().transport, "grpc");
    assert_eq!(
        node.transport().unwrap().grpc_service.as_deref(),
        Some("MyService")
    );
    assert!(node.transport().unwrap().ws_path.is_none());
    assert!(node.transport().unwrap().ws_host.is_none());
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("sni.example.com"));
    assert!(node.tls().unwrap().enabled);
}

#[test]
fn test_share_link_tls_name_aliases_resolve_before_loss() {
    let canonical = Node::from_share_link("trojan://pw@example.com:443?sni=edge.example").unwrap();
    let empty_sni =
        Node::from_share_link("trojan://pw@example.com:443?sni=&peer=edge.example").unwrap();
    let equal_aliases =
        Node::from_share_link("trojan://pw@example.com:443?sni=edge.example&peer=edge.example")
            .unwrap();
    let repeated_equal =
        Node::from_share_link("trojan://pw@example.com:443?sni=edge.example&sni=edge.example")
            .unwrap();
    for equivalent in [empty_sni, equal_aliases, repeated_equal] {
        assert_eq!(
            equivalent.tls().unwrap().sni.as_deref(),
            Some("edge.example")
        );
        assert_eq!(equivalent.derive_id(), canonical.derive_id());
    }

    for link in [
        "trojan://pw@example.com:443?sni=one.example&peer=two.example",
        "trojan://pw@example.com:443?sni=one.example&sni=two.example",
    ] {
        assert!(Node::from_share_link(link).is_err(), "{link}");
    }

    let raw_tcp =
        Node::from_share_link("trojan://pw@example.com:443?host=fallback.example").unwrap();
    assert_eq!(
        raw_tcp.tls().unwrap().sni.as_deref(),
        Some("fallback.example")
    );
    assert!(raw_tcp.transport().unwrap().ws_host.is_none());
    let ws =
        Node::from_share_link("trojan://pw@example.com:443?type=ws&host=header.example").unwrap();
    assert_eq!(
        ws.transport().unwrap().ws_host.as_deref(),
        Some("header.example")
    );
    assert!(ws.tls().unwrap().sni.is_none());
    let raw_tcp = Node::from_share_link(&vmess_link(
        r#"{"add":"vmess.example","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"tcp","host":"fallback.example","sni":" \t ","tls":"tls"}"#,
    ))
    .unwrap();
    assert_eq!(
        raw_tcp.tls().unwrap().sni.as_deref(),
        Some("fallback.example")
    );

    let ws = Node::from_share_link(&vmess_link(
        r#"{"add":"vmess.example","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"ws","host":"header.example","sni":" \t ","tls":"tls"}"#,
    ))
    .unwrap();
    assert_eq!(
        ws.transport().unwrap().ws_host.as_deref(),
        Some("header.example")
    );
    assert!(ws.tls().unwrap().sni.is_none());
}

#[test]
fn test_flat_optional_sni_and_flow_normalize_like_url_inputs() {
    let flat: Node = serde_json::from_value(serde_json::json!({
        "name": "flat",
        "protocol": "vless",
        "address": "example.com:443",
        "host": "example.com",
        "port": 443,
        "password": "b831381d-6324-4d53-ad4f-8cda48b30811",
        "tls": true,
        "sni": " \t ",
        "flow": "\n ",
    }))
    .unwrap();
    let url = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&flow=",
    )
    .unwrap();

    assert!(flat.tls().unwrap().sni.is_none());
    assert!(flat.vless().unwrap().flow.is_none());
    assert_eq!(flat.tls().unwrap().sni, url.tls().unwrap().sni);
    assert_eq!(flat.vless().unwrap().flow, url.vless().unwrap().flow);
    assert_eq!(flat.derive_id(), url.derive_id());
}

#[test]
fn test_share_link_flow_empty_is_absent_and_invalid_is_rejected() {
    let empty = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&flow=",
    )
    .unwrap();
    assert!(empty.vless().unwrap().flow.is_none());
    assert!(
        Node::from_share_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&flow=invalid"
        )
        .is_err()
    );
}

#[test]
fn test_vmess_invalid_links_rejected() {
    assert!(Node::from_share_link("vmess://!!!not-base64!!!").is_err());
    // Valid base64 but not JSON.
    assert!(Node::from_share_link(&format!("vmess://{}", b64("not json"))).is_err());
    // JSON without a server address.
    assert!(
        Node::from_share_link(&format!("vmess://{}", b64(r#"{"port":443,"id":"x"}"#))).is_err()
    );
}

#[test]
fn test_removed_protocol_links_rejected() {
    // ssr/trojan-go/http(s) support was removed; the links now fail as
    // unknown protocols (hard error in config files, skipped with a
    // warning in subscriptions).
    let ssr_link = format!("ssr://{}", b64("example.com:443:origin:none:plain:cHc"));
    for link in [
        ssr_link.as_str(),
        "trojan-go://pw@example.com:443",
        "http://proxy.example.com:8080",
        "https://user:pass@proxy.example.com:8443",
    ] {
        let err = Node::from_share_link(link).unwrap_err();
        assert!(matches!(err, honk_config::ConfigError::UnknownProtocol(_)));
    }
}

#[test]
fn test_unknown_scheme_rejected() {
    let err = Node::from_share_link("unknown://host:1234").unwrap_err();
    assert!(matches!(err, honk_config::ConfigError::UnknownProtocol(_)));
}

/// Build a config holding an experimental section and three fully populated
/// nodes (ss, trojan+ws, anytls) for serialization round-trip tests.
fn sample_config() -> Config {
    let mut config = Config::default();
    config.experimental.clash_api.external_controller = "0.0.0.0:9999".to_string();
    config.experimental.clash_api.external_ui = "yacd".to_string();
    config.experimental.clash_api.external_ui_download_url =
        "https://example.com/ui.zip".to_string();
    config.experimental.clash_api.external_ui_download_detour = "proxy".to_string();
    config.experimental.clash_api.secret = "s3cret".to_string();
    config.experimental.cache_file.enabled = true;
    config.experimental.cache_file.path = "cache.db".to_string();
    config.experimental.cache_file.cache_id = "router1".to_string();
    config.experimental.cache_file.store_fakeip = true;

    config.nodes.push(
        Node::from_share_link(
            "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp#ss-node",
        )
        .unwrap(),
    );
    config.nodes.push(
        Node::from_share_link(
            "trojan://pw@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&sni=sni.example.com#trojan-node",
        )
        .unwrap(),
    );
    let mut anytls = Node::from_share_link(
        "anytls://uuid-pw@any.example.com:443?insecure=1&idle_session_timeout=1m&min_idle_session=4#anytls-node",
    )
    .unwrap();
    anytls.tls_mut().unwrap().alpn = vec!["h2".into()];
    anytls.validate_protocol().unwrap();
    anytls.id = anytls.derive_id();
    config.nodes.push(anytls);
    config
}

#[test]
fn test_config_json_round_trip() {
    let config = sample_config();
    let json = config.to_json_string().unwrap();
    let parsed = Config::from_json_str(&json).unwrap();
    assert_eq!(parsed.to_json_string().unwrap(), json);
}

#[test]
fn test_config_vless_flat_fields_and_removed_key_rejection() {
    let node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?packetEncoding=xudp&mux=xray&xudpConcurrency=4&xudpProxyUDP443=allow#vless",
    )
    .unwrap();
    let value = serde_json::to_value(&node).unwrap();
    assert!(value.get("vless_mode").is_none());
    assert_eq!(value["packet_encoding"], serde_json::json!("auto"));
    assert_eq!(value["multiplex"]["protocol"], serde_json::json!("xray"));
    let parsed: Node = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(parsed.outbound, node.outbound);

    for removed in [serde_json::json!("legacy"), serde_json::Value::Null] {
        let mut rejected = value.clone();
        rejected["vless_mode"] = removed;
        assert!(serde_json::from_value::<Node>(rejected).is_err());
    }
    for multiplex in [
        serde_json::json!({ "protocol": "off", "padding": true }),
        serde_json::json!({ "protocol": "h2", "tcp": 8 }),
        serde_json::json!({ "protocol": "xray", "padding": true }),
    ] {
        let mut rejected = value.clone();
        rejected["multiplex"] = multiplex;
        assert!(serde_json::from_value::<Node>(rejected).is_err());
    }
    let yaml = serde_yaml::to_string(&node).unwrap();
    assert_eq!(
        serde_yaml::from_str::<Node>(&yaml).unwrap().outbound,
        node.outbound
    );
    assert!(serde_yaml::from_str::<Node>(&format!("{yaml}vless_mode: null\n")).is_err());
    let encoded_toml = toml::to_string(&node).unwrap();
    assert_eq!(
        toml::from_str::<Node>(&encoded_toml).unwrap().outbound,
        node.outbound
    );
    let toml = r#"name = "vless"
protocol = "vless"
address = "example.com:443"
host = "example.com"
port = 443
password = "b831381d-6324-4d53-ad4f-8cda48b30811"
vless_mode = "legacy"
"#;
    assert!(toml::from_str::<Node>(toml).is_err());

    let anytls = Node::from_share_link("anytls://password@example.com:443").unwrap();
    let mut neutral = serde_json::to_value(&anytls).unwrap();
    assert_eq!(neutral["vless_mode"], serde_json::json!("legacy"));
    assert!(neutral.get("packet_encoding").is_none());
    assert!(neutral.get("multiplex").is_none());
    neutral["vless_mode"] = serde_json::Value::Null;
    serde_json::from_value::<Node>(neutral).unwrap();
}

#[test]
fn test_config_toml_round_trip() {
    let config = sample_config();
    let toml_str = toml::to_string_pretty(&config).unwrap();
    let parsed: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(
        parsed.to_json_string().unwrap(),
        config.to_json_string().unwrap()
    );
}

#[test]
fn test_config_yaml_round_trip() {
    let config = sample_config();
    let yaml_str = serde_yaml::to_string(&config).unwrap();
    let parsed: Config = serde_yaml::from_str(&yaml_str).unwrap();
    assert_eq!(
        parsed.to_json_string().unwrap(),
        config.to_json_string().unwrap()
    );
}

#[test]
fn test_from_file_json_extension() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let config = sample_config();
    std::fs::write(&path, config.to_json_string().unwrap()).unwrap();

    let loaded = Config::from_file(path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.nodes.len(), 3);
    assert_eq!(
        loaded.nodes[0].shadowsocks().unwrap().encryption.as_deref(),
        Some("aes-256-gcm")
    );
    assert_eq!(loaded.nodes[1].transport().unwrap().transport, "ws");
    assert_eq!(loaded.nodes[2].anytls().unwrap().min_idle_session, Some(4));
    assert_eq!(
        loaded.experimental.clash_api.external_controller,
        "0.0.0.0:9999"
    );
    assert_eq!(
        loaded.to_json_string().unwrap(),
        config.to_json_string().unwrap()
    );
}

#[test]
fn test_to_file_and_from_file_by_extension() {
    let dir = tempfile::tempdir().unwrap();
    let config = sample_config();

    for ext in ["json", "toml", "yaml", "yml"] {
        let path = dir.path().join(format!("config.{}", ext));
        config.to_file(path.to_str().unwrap()).unwrap();
        let loaded = Config::from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(
            loaded.to_json_string().unwrap(),
            config.to_json_string().unwrap(),
            "round trip failed for extension .{}",
            ext
        );
    }
}

#[test]
fn test_from_file_dae_fallback_chain() {
    // Extension-less and unknown-extension files keep the dae-first chain.
    let dir = tempfile::tempdir().unwrap();
    let dae = "global {\n    tproxy_port: 12346\n}\n";
    for name in ["config", "config.dae"] {
        let path = dir.path().join(name);
        std::fs::write(&path, dae).unwrap();
        let loaded = Config::from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.global.tproxy_port, 12346);
    }
}

#[test]
fn test_fragment_name_is_utf8_decoded() {
    // Regression: percent-encoded bytes must be decoded as UTF-8, not as
    // per-byte chars (which produced mojibake for Chinese/emoji names).
    let node = Node::from_share_link(
        "trojan://pw@hk.example.com:443/#%E9%A6%99%E6%B8%AF%20%E8%8A%82%E7%82%B9",
    )
    .unwrap();
    assert_eq!(node.name, "香港 节点");

    let node = Node::from_share_link(
        "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:443/#%F0%9F%87%AD%F0%9F%87%B0%20HK",
    )
    .unwrap();
    assert_eq!(node.name, "🇭🇰 HK");
    assert_eq!(
        node.shadowsocks().unwrap().encryption.as_deref(),
        Some("aes-256-gcm")
    );
    assert_eq!(node.shadowsocks().unwrap().password.as_deref(), Some("pw"));
}

#[test]
fn test_ss_full_base64_authority_with_fragment() {
    // SIP002 full-base64 form: ss://base64(method:password@host:port)#name
    let inner = b64("aes-128-gcm:secret-pw@sg.example.com:8388");
    let link = format!("ss://{}#%E6%96%B0%E5%8A%A0%E5%9D%A1", inner);
    let node = Node::from_share_link(&link).unwrap();
    assert_eq!(node.protocol(), NodeProtocol::SS);
    assert_eq!(node.host, "sg.example.com");
    assert_eq!(node.port, 8388);
    assert_eq!(
        node.shadowsocks().unwrap().encryption.as_deref(),
        Some("aes-128-gcm")
    );
    assert_eq!(
        node.shadowsocks().unwrap().password.as_deref(),
        Some("secret-pw")
    );
    assert_eq!(node.name, "新加坡");
}

#[test]
fn test_ss_legacy_literal_percent_password() {
    let link = format!("ss://{}", b64("aes-256-gcm:a%20b@1.2.3.4:8388"));
    let node = Node::from_share_link(&link).unwrap();
    assert_eq!(
        node.shadowsocks().unwrap().password.as_deref(),
        Some("a%20b")
    );
}

#[test]
fn test_ss_legacy_standard_base64_slash() {
    let payload = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:ab?@1.2.3.4:8388");
    let node = Node::from_share_link(&format!("ss://{payload}")).unwrap();
    assert_eq!(node.host, "1.2.3.4");
    assert_eq!(node.port, 8388);
    assert_eq!(
        node.shadowsocks().unwrap().encryption.as_deref(),
        Some("aes-256-gcm")
    );
    assert_eq!(node.shadowsocks().unwrap().password.as_deref(), Some("ab?"));
}

#[test]
fn test_ss_legacy_literal_slash_password() {
    let link = format!("ss://{}", b64("aes-256-gcm:a/b@1.2.3.4:8388"));
    let node = Node::from_share_link(&link).unwrap();
    assert_eq!(node.shadowsocks().unwrap().password.as_deref(), Some("a/b"));
}

#[test]
fn test_ss_legacy_literal_hash_password() {
    let link = format!("ss://{}", b64("aes-256-gcm:p#x@1.2.3.4:8388"));
    let node = Node::from_share_link(&link).unwrap();
    assert_eq!(node.shadowsocks().unwrap().password.as_deref(), Some("p#x"));
}

#[test]
fn test_ss_legacy_rejects_missing_credentials() {
    let link = format!("ss://{}", b64("1.2.3.4:8388"));
    let error = Node::from_share_link(&link).unwrap_err();
    assert!(matches!(error, honk_config::ConfigError::Parse(_)));
}

#[test]
fn test_ss_legacy_rejects_missing_method_separator() {
    let link = format!("ss://{}", b64("password@1.2.3.4:8388"));
    let error = Node::from_share_link(&link).unwrap_err();
    assert!(matches!(error, honk_config::ConfigError::Parse(_)));
}

#[test]
fn test_ss_legacy_plain_matches_userinfo_form() {
    let link = format!("ss://{}", b64("aes-256-gcm:plain@1.2.3.4:8388"));
    let node = Node::from_share_link(&link).unwrap();
    let canonical = Node::from_share_link("ss://aes-256-gcm:plain@1.2.3.4:8388").unwrap();
    assert_eq!(node.id, canonical.id);
    assert_eq!(
        node.shadowsocks().unwrap().password.as_deref(),
        Some("plain")
    );
}

#[test]
fn test_ss_legacy_colon_password() {
    let link = format!("ss://{}", b64("aes-256-gcm:a:b@1.2.3.4:8388"));
    let node = Node::from_share_link(&link).unwrap();
    assert_eq!(node.shadowsocks().unwrap().password.as_deref(), Some("a:b"));
}

#[test]
fn test_ss_legacy_last_at_separates_endpoint() {
    let link = format!("ss://{}", b64("aes-256-gcm:a@b@1.2.3.4:8388"));
    let node = Node::from_share_link(&link).unwrap();
    assert_eq!(node.host, "1.2.3.4");
    assert_eq!(node.shadowsocks().unwrap().password.as_deref(), Some("a@b"));
}

#[test]
fn test_ss_legacy_encoded_method() {
    let link = format!(
        "ss://{}",
        b64("Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ:pw@1.2.3.4:8388")
    );
    let node = Node::from_share_link(&link).unwrap();
    assert_eq!(
        node.shadowsocks().unwrap().encryption.as_deref(),
        Some("chacha20-ietf-poly1305")
    );
}

#[test]
fn test_ss_legacy_ipv6_matches_userinfo_form() {
    let link = format!("ss://{}", b64("aes-256-gcm:plain@[2001:db8::1]:8388"));
    let node = Node::from_share_link(&link).unwrap();
    let canonical = Node::from_share_link("ss://aes-256-gcm:plain@[2001:db8::1]:8388").unwrap();
    assert_eq!(node.host, "[2001:db8::1]");
    assert_eq!(node.id, canonical.id);
}

#[test]
fn test_ss_legacy_padded_plugin_suffix() {
    let payload =
        base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:plain@1.2.3.4:8388");
    let node = Node::from_share_link(&format!(
        "ss://{payload}/?plugin=v2ray-plugin%3Btls&remark=query#name"
    ))
    .unwrap();
    assert_eq!(
        node.shadowsocks().unwrap().plugin.as_deref(),
        Some("v2ray-plugin")
    );
    assert_eq!(
        node.shadowsocks().unwrap().plugin_opts.as_deref(),
        Some("tls")
    );
    assert_eq!(node.name, "name");
}

#[test]
fn test_ss_legacy_unpadded_plugin_delimiter() {
    let payload = b64("aes-256-gcm:abcdefghijklmnop@1.2.3.4:8388");
    let node =
        Node::from_share_link(&format!("ss://{payload}/?plugin=v2ray-plugin%3Btls#name")).unwrap();
    assert_eq!(node.port, 8388);
    assert_eq!(
        node.shadowsocks().unwrap().plugin.as_deref(),
        Some("v2ray-plugin")
    );
    assert_eq!(
        node.shadowsocks().unwrap().plugin_opts.as_deref(),
        Some("tls")
    );
    assert_eq!(node.name, "name");
}

#[test]
fn test_ss_legacy_remark_suffix() {
    let link = format!(
        "ss://{}/?remark=name",
        b64("aes-256-gcm:plain@1.2.3.4:8388")
    );
    let node = Node::from_share_link(&link).unwrap();
    assert_eq!(node.name, "name");
}

#[test]
fn test_ss_url_userinfo_still_percent_decodes() {
    let link = "ss://aes-256-gcm:a%20b@1.2.3.4:8388";
    let node = Node::from_share_link(link).unwrap();
    assert_eq!(node.shadowsocks().unwrap().password.as_deref(), Some("a b"));
}

#[test]
fn test_ss_compat_nested_base64_userinfo() {
    let link = format!(
        "ss://{}",
        b64(&format!("{}@1.2.3.4:8388", b64("aes-256-gcm:pw")))
    );
    let node = Node::from_share_link(&link).unwrap();
    let ss = node.shadowsocks().unwrap();
    assert_eq!(ss.encryption.as_deref(), Some("aes-256-gcm"));
    assert_eq!(ss.password.as_deref(), Some("pw"));
}

#[test]
fn test_ss_compat_empty_base64_run() {
    let link = "ss://[2001:db8::1]:8388#nm";
    let node = Node::from_share_link(link).unwrap();
    assert_eq!(node.host, "[2001:db8::1]");
    assert_eq!(node.port, 8388);
    assert_eq!(node.name, "nm");
}

#[test]
fn test_ss_compat_legacy_path_suffix() {
    let link = format!("ss://{}/path#name", b64("aes-256-gcm:plain@1.2.3.4:8388"));
    let node = Node::from_share_link(&link).unwrap();
    assert_eq!(node.host, "1.2.3.4");
    assert_eq!(node.port, 8388);
    assert_eq!(
        node.shadowsocks().unwrap().password.as_deref(),
        Some("plain")
    );
    assert_eq!(node.name, "name");
}

#[test]
fn test_ss_compat_bare_hostname() {
    let link = "ss://host:8388";
    let node = Node::from_share_link(link).unwrap();
    assert_eq!(node.host, "host");
    assert_eq!(node.port, 8388);
}

#[test]
fn test_name_fallback_never_contains_credentials() {
    // Links without #name get a `scheme-host` fallback; the raw URI (with
    // the password) must never end up in the display name.
    let node = Node::from_share_link("trojan://super-secret@us.example.com:443").unwrap();
    assert_eq!(node.name, "trojan-us.example.com");
    assert!(!node.name.contains("super-secret"));

    let node = Node::from_share_link("socks5://user:pass@10.0.0.1:1080").unwrap();
    assert_eq!(node.name, "socks5-10.0.0.1");
    assert!(!node.name.contains("pass"));
}

#[test]
fn test_percent_encoded_userinfo_is_decoded() {
    // Regression: encoded UUIDs in userinfo must be decoded, otherwise
    // AnyTLS/Trojan auth computes over the wrong string.
    let node = Node::from_share_link(
        "anytls://00000000%2D0000%2D0000%2D0000%2D000000000000@example.com:443/?sni=example.com#test-node",
    )
    .unwrap();
    assert_eq!(
        node.anytls().unwrap().password.as_deref(),
        Some("00000000-0000-0000-0000-000000000000")
    );
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("example.com"));

    let node = Node::from_share_link("trojan://pass%40word%3Ax@h.example.com:443").unwrap();
    assert_eq!(
        node.trojan().unwrap().password.as_deref(),
        Some("pass@word:x")
    );
}

#[test]
fn test_hysteria2_auth_and_obfs_params() {
    let node =
        Node::from_share_link("hysteria2://pass@example.com:443/?sni=example.com&insecure=1")
            .unwrap();
    assert_eq!(node.protocol(), NodeProtocol::Hysteria2);
    assert_eq!(node.hysteria2().unwrap().auth.as_deref(), Some("pass"));
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("example.com"));
    assert!(node.tls().unwrap().skip_cert_verify);
    assert!(node.hysteria2().unwrap().obfs.is_none());

    // Percent-encoded secrets are decoded; salamander obfs password lands in
    // `hy2_obfs`; the fragment names the node.
    let node = Node::from_share_link(
        "hysteria2://p%40ss%3Aword@example.com:443/?obfs=salamander&obfs-password=obfspw#my-hy2",
    )
    .unwrap();
    assert_eq!(node.hysteria2().unwrap().auth.as_deref(), Some("p@ss:word"));
    assert_eq!(node.hysteria2().unwrap().obfs.as_deref(), Some("obfspw"));
    assert_eq!(node.name, "my-hy2");

    // obfs without a password leaves obfuscation off.
    let node = Node::from_share_link("hysteria2://pass@example.com:443/?obfs=salamander").unwrap();
    assert!(node.hysteria2().unwrap().obfs.is_none());

    // Brutal bandwidth hints.
    let node =
        Node::from_share_link("hysteria2://pass@example.com:443/?upmbps=50&downmbps=200").unwrap();
    assert_eq!(node.hysteria2().unwrap().up_mbps, Some(50));
    assert_eq!(node.hysteria2().unwrap().down_mbps, Some(200));

    // Port hopping and certificate pin.
    let node = Node::from_share_link(
        "hysteria2://pass@example.com:443/?mport=20000-20010,30000&mhop=15&pinSHA256=aabbcc",
    )
    .unwrap();
    assert_eq!(
        node.hysteria2().unwrap().port_hopping.as_deref(),
        Some("20000-20010,30000")
    );
    assert_eq!(node.hysteria2().unwrap().hop_interval, Some(15));
    assert_eq!(node.tls().unwrap().pin_sha256.as_deref(), Some("aabbcc"));
}

#[test]
fn shadowrocket_hysteria2_peer_preserves_sni_and_identity() {
    let canonical = Node::from_share_link(
        "hysteria2://secret@example.com:8443?sni=tls.example&insecure=1#edge",
    )
    .unwrap();
    for query in ["peer=tls.example", "peer=tls.example&sni=tls.example"] {
        let node = Node::from_share_link(&format!(
            "hysteria2://secret@example.com:8443?{query}&insecure=1#edge"
        ))
        .unwrap();
        assert_eq!(node.outbound, canonical.outbound);
        assert_eq!(node.id, canonical.id);
    }
}

#[test]
fn test_hysteria2_embedded_hop_ports() {
    // Official client style: the hop set lives in the authority; the first
    // entry becomes the nominal port.
    let node = Node::from_share_link(
        "hysteria2://letmein@example.com:123,5000-6000/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=deadbeef&sni=real.example.com#cool-server",
    )
    .unwrap();
    assert_eq!(node.port, 123);
    assert_eq!(node.address, "example.com:123");
    assert_eq!(
        node.hysteria2().unwrap().port_hopping.as_deref(),
        Some("123,5000-6000")
    );
    assert_eq!(node.name, "cool-server");
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("real.example.com"));
    assert!(node.tls().unwrap().skip_cert_verify);
    assert_eq!(node.hysteria2().unwrap().obfs.as_deref(), Some("gawrgura"));

    // Range-only form; the `hysteria` alias scheme works too.
    let node = Node::from_share_link("hysteria://pass@example.com:5000-6000/").unwrap();
    assert_eq!(node.port, 5000);
    assert_eq!(
        node.hysteria2().unwrap().port_hopping.as_deref(),
        Some("5000-6000")
    );

    // Both spellings of the same hop set derive the same node identity.
    let embedded =
        Node::from_share_link("hysteria2://pass@example.com:123,5000-6000/?insecure=1").unwrap();
    let query_form =
        Node::from_share_link("hysteria2://pass@example.com:123/?mport=123,5000-6000&insecure=1")
            .unwrap();
    assert_eq!(embedded.id, query_form.id);

    // Specifying hop ports twice is ambiguous and rejected.
    assert!(Node::from_share_link("hysteria2://pass@example.com:443,6000/?mport=7000").is_err());

    // Structurally invalid lists fail at parse time.
    for link in [
        "hysteria2://pass@example.com:0,6000/",
        "hysteria2://pass@example.com:6000-5000/",
        "hysteria2://pass@example.com:abc,6000/",
        "hysteria2://pass@example.com:443,/",
        "hysteria2://pass@example.com:70000-70001/",
    ] {
        assert!(Node::from_share_link(link).is_err(), "{link}");
    }

    // A plain single port and IPv6 bracket hosts are untouched.
    let node = Node::from_share_link("hysteria2://pass@example.com:443/").unwrap();
    assert!(node.hysteria2().unwrap().port_hopping.is_none());
    let node = Node::from_share_link("hysteria2://pass@[2001:db8::1]:443,6000/").unwrap();
    assert_eq!(node.port, 443);
    assert_eq!(
        node.hysteria2().unwrap().port_hopping.as_deref(),
        Some("443,6000")
    );

    // No path/query/fragment suffix; whitespace-only lists are invalid.
    let node = Node::from_share_link("hysteria2://pass@example.com:443,6000").unwrap();
    assert_eq!(
        node.hysteria2().unwrap().port_hopping.as_deref(),
        Some("443,6000")
    );
    assert!(Node::from_share_link("hysteria2://pass@example.com: ,6000/").is_err());

    // An empty mport value is absent, not a conflict with the address form.
    let node = Node::from_share_link("hysteria2://pass@example.com:443,6000/?mport=").unwrap();
    assert_eq!(
        node.hysteria2().unwrap().port_hopping.as_deref(),
        Some("443,6000")
    );
}

#[test]
fn test_ech_query_params() {
    // ech_config=<base64url ECHConfigList> enables ECH and carries the config.
    let node = Node::from_share_link(
        "hysteria2://pass@example.com:443/?sni=example.com&ech_config=QUJDMTIz",
    )
    .unwrap();
    assert!(node.tls().unwrap().ech_enabled);
    assert_eq!(node.tls().unwrap().ech_config.as_deref(), Some("QUJDMTIz"));

    // Bare ech=1 toggles ECH without keys.
    let node = Node::from_share_link(
        "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:p@example.com:443/?ech=1",
    )
    .unwrap();
    assert!(node.tls().unwrap().ech_enabled);
    assert!(node.tls().unwrap().ech_config.is_none());
}

#[test]
fn test_tuic_window_params() {
    let node = Node::from_share_link(
        "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:p@example.com:443/?initStreamReceiveWindow=4194304&initConnReceiveWindow=16777216",
    )
    .unwrap();
    assert_eq!(node.tuic().unwrap().init_stream_recv_window, Some(4194304));
    assert_eq!(node.tuic().unwrap().init_conn_recv_window, Some(16777216));
    // Unset by default.
    let node =
        Node::from_share_link("tuic://b831381d-6324-4d53-ad4f-8cda48b30811:p@example.com:443")
            .unwrap();
    assert_eq!(node.tuic().unwrap().init_stream_recv_window, None);

    // No ECH params: disabled.
    let node = Node::from_share_link("trojan://pass@example.com:443").unwrap();
    assert!(!node.tls().unwrap().ech_enabled);
    assert!(node.tls().unwrap().ech_config.is_none());
}

#[test]
fn test_tuic_alpn_and_congestion_params() {
    let node = Node::from_share_link(
        "tuic://d4d633d1-e9db-44dc-a458-fc6fe81beba4:d4d633d1-e9db-44dc-a458-fc6fe81beba4@[2a03:4000:37:a0f:48d0:aff:fe96:e75b]:37618/?congestion_control=bbr&alpn=h3&insecure=1",
    )
    .unwrap();
    assert_eq!(node.tuic().unwrap().alpn.as_deref(), Some("h3"));
    assert_eq!(node.tuic().unwrap().congestion.as_deref(), Some("bbr"));

    // Comma-separated ALPN list is preserved verbatim.
    let node = Node::from_share_link(
        "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:p@example.com:443/?alpn=h3,h3-29",
    )
    .unwrap();
    assert_eq!(node.tuic().unwrap().alpn.as_deref(), Some("h3,h3-29"));

    // Unset by default.
    let node =
        Node::from_share_link("tuic://b831381d-6324-4d53-ad4f-8cda48b30811:p@example.com:443")
            .unwrap();
    assert_eq!(node.tuic().unwrap().alpn, None);
    assert_eq!(node.tuic().unwrap().congestion, None);
}

#[test]
fn test_vless_packet_encoding_query() {
    for (query, expected) in [
        ("", VlessUdpEncoding::Auto),
        ("packetEncoding=auto", VlessUdpEncoding::Auto),
        ("packetEncoding=none", VlessUdpEncoding::Native),
        ("packetEncoding=xudp", VlessUdpEncoding::Xudp),
        ("packetEncoding=uot-v2", VlessUdpEncoding::UotV2),
    ] {
        let node = Node::from_share_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?{query}#node"
        ))
        .unwrap();
        assert_eq!(node.vless().unwrap().udp_encoding, expected);
    }
}

#[test]
fn test_vless_mux_query() {
    let h2 = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?mux=h2mux&padding=true#node",
    )
    .unwrap();
    assert_eq!(
        h2.vless().unwrap().multiplex,
        VlessMultiplex::H2 { padding: true }
    );

    let xray = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?mux=xray&concurrency=-1&xudpConcurrency=7&xudpProxyUDP443=allow#node",
    )
    .unwrap();
    assert_eq!(
        xray.vless().unwrap().multiplex,
        VlessMultiplex::Xray {
            tcp: None,
            udp: VlessUdpMux::Separate(std::num::NonZeroU16::new(7).unwrap()),
            udp443: Udp443Policy::Allow,
        }
    );
}

#[test]
fn test_vless_canonical_query_rejections_keep_safe_fields() {
    for (query, field, code) in [
        ("vless_mode=", "vless_mode", "removed-vless-mode"),
        (
            "packet-encoding=PRIVATE_VALUE",
            "packet_encoding",
            "unsupported-vless-parameter",
        ),
        (
            "packetEncoding=xudp&packetEncoding=xudp",
            "packet_encoding",
            "duplicate-vless-parameter",
        ),
        (
            "mux=off&padding=false",
            "multiplex.padding",
            "invalid-config-value",
        ),
        (
            "mux=h2mux&concurrency=8",
            "multiplex.tcp",
            "invalid-config-value",
        ),
        (
            "mux=xray&padding=false",
            "multiplex.padding",
            "invalid-config-value",
        ),
        (
            "mux=xray&concurrency=32769",
            "multiplex.tcp",
            "invalid-config-value",
        ),
        (
            "mux=xray&xudpConcurrency=PRIVATE_VALUE",
            "multiplex.udp",
            "invalid-config-value",
        ),
        (
            "mux=xray&xudpProxyUDP443=PRIVATE_VALUE",
            "multiplex.udp443",
            "invalid-config-value",
        ),
        (
            "packetEncoding=PRIVATE_VALUE",
            "packet_encoding",
            "invalid-config-value",
        ),
        ("mux=PRIVATE_VALUE", "multiplex", "invalid-config-value"),
        (
            "mux=h2mux&padding=PRIVATE_VALUE",
            "multiplex.padding",
            "invalid-config-value",
        ),
        ("udp=PRIVATE_VALUE", "network", "invalid-config-value"),
        ("xtls=PRIVATE_VALUE", "flow", "invalid-config-value"),
    ] {
        let link = format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@private.example:443?pbk=PRIVATE_KEY&{query}#PRIVATE_NAME"
        );
        let mut diagnostics = Vec::new();
        let error =
            Node::from_share_link_with_detailed_diagnostics(&link, &mut diagnostics).unwrap_err();
        assert_eq!(error.category, honk_config::error::ErrorCategory::Parse);
        assert_eq!(error.diagnostic.code, code, "{query}");
        assert_eq!(
            error.diagnostic.setting.to_string(),
            format!("nodes.{field}"),
            "{query}"
        );
        assert_eq!(error.diagnostic.severity, Severity::Error);
        assert!(error.diagnostic.terminal);
        assert_eq!(error.diagnostic.value, SafeValue::Redacted);
        assert_eq!(diagnostics, [*error.diagnostic.clone()]);
        let rendered = format!(
            "{error:?} {error} {diagnostics:?} {:?}",
            error.diagnostic.to_legacy()
        );
        for secret in [
            "PRIVATE_",
            "private.example",
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "32769",
        ] {
            assert!(!rendered.contains(secret), "{query}: {rendered}");
        }
    }
}

#[test]
fn test_vless_udp_query_coalesces_equal_claims_and_rejects_bad_values() {
    for query in ["", "udp=1", "udp=TRUE", "udp=true&udp=1"] {
        let node = Node::from_share_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?{query}"
        ))
        .unwrap();
        assert!(node.vless().unwrap().udp_enabled(), "{query}");
        assert_eq!(node.vless().unwrap().network, None, "{query}");
    }
    for query in ["udp=0", "udp=FALSE", "udp=false&udp=0"] {
        let node = Node::from_share_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?{query}"
        ))
        .unwrap();
        assert!(!node.vless().unwrap().udp_enabled(), "{query}");
        assert_eq!(node.vless().unwrap().network.as_deref(), Some("tcp"));
    }
    for query in ["udp=", "udp=yes", "udp=true&udp=0"] {
        assert!(
            Node::from_share_link(&format!(
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?{query}"
            ))
            .is_err(),
            "{query}"
        );
    }
}

#[test]
fn test_rejects_vless_mode_on_other_protocols() {
    for query in ["vless_mode=h2mux", "packetEncoding=xudp"] {
        assert!(
            Node::from_share_link(&format!("trojan://password@example.com:443?{query}#node"))
                .is_err()
        );
    }
}

#[test]
fn test_packet_encoding_none_is_a_noop_on_other_protocols() {
    // Converters append packetEncoding=none to anytls/trojan links; it spells
    // the default behavior and must not reject the node.
    let node = Node::from_share_link(
        "anytls://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&packetEncoding=none&udp=1#node",
    )
    .unwrap();
    assert_eq!(node.protocol(), honk_config::types::NodeProtocol::AnyTLS);
}

#[test]
fn test_vless_share_link_rejects_external_mux_fields() {
    for parameter in [
        "smux=h2mux",
        "udp-over-tcp=1",
        "packet-encoding=xudp",
        "only-tcp=1",
        "brutal=1",
        "packet-addr=1",
        "xudp=1",
        "brutal-opts=1",
        "max-connections=2",
    ] {
        assert!(
            Node::from_share_link(&format!(
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?{parameter}#node"
            ))
            .is_err()
        );
    }

    assert!(
        Node::from_share_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?packetEncoding=packetaddr#node")
            .is_err()
    );
}

#[test]
fn test_vless_reality_full() {
    let node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@reality.example.com:443?security=reality&pbk=jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc&sid=a1b2c3d4e5f60718&spx=%2F&fp=chrome&flow=xtls-rprx-vision#reality-node",
    )
    .unwrap();
    assert_eq!(node.protocol(), NodeProtocol::VLess);
    assert_eq!(node.name, "reality-node");
    // The userinfo UUID is the protocol credential.
    assert_eq!(
        node.vless().unwrap().uuid.as_deref(),
        Some("b831381d-6324-4d53-ad4f-8cda48b30811")
    );
    assert!(node.tls().unwrap().enabled);
    assert_eq!(
        node.tls().unwrap().reality_public_key.as_deref(),
        Some("jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc")
    );
    assert_eq!(
        node.tls().unwrap().reality_short_id.as_deref(),
        Some("a1b2c3d4e5f60718")
    );
    assert_eq!(node.tls().unwrap().reality_spider_x.as_deref(), Some("/"));
    assert_eq!(
        node.vless().unwrap().flow.as_deref(),
        Some("xtls-rprx-vision")
    );

    // A valid REALITY+flow node passes config validation.
    let mut config = Config::default();
    config.nodes.push(node);
    config.validate().unwrap();
}

#[test]
fn test_vless_reality_spx_default() {
    // A missing `spx` falls back to the share-link default `/`.
    let node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&pbk=jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc#n",
    )
    .unwrap();
    assert!(node.tls().unwrap().enabled);
    assert_eq!(node.tls().unwrap().reality_spider_x.as_deref(), Some("/"));
    assert!(node.tls().unwrap().reality_short_id.is_none());
}

#[test]
fn test_vless_security_none() {
    let node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=none#n",
    )
    .unwrap();
    assert!(!node.tls().unwrap().enabled);
    assert!(node.tls().unwrap().reality_public_key.is_none());
}

#[test]
fn test_vless_no_security_keeps_tls_default() {
    // Existing links without a `security` parameter keep the historical
    // TLS-on default.
    let node =
        Node::from_share_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443#n")
            .unwrap();
    assert!(node.tls().unwrap().enabled);
    assert!(node.tls().unwrap().reality_public_key.is_none());
}

#[test]
fn shadowrocket_vless_reality_matches_canonical_link() {
    let authority = "auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:8443";
    let canonical = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:8443?security=reality&sni=tls.example&pbk=jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc&sid=0123456789abcdef&flow=xtls-rprx-vision#Hong%20Kong",
    )
    .unwrap();
    for encoded in [
        base64::engine::general_purpose::STANDARD.encode(authority),
        b64(authority),
    ] {
        let node = Node::from_share_link(&format!(
            "vless://{encoded}?tls=1&xtls=2&peer=tls.example&sni=tls.example&pbk=jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc&sid=0123456789abcdef&remark=Hong%20Kong"
        ))
        .unwrap();
        assert_eq!(node.host, canonical.host);
        assert_eq!(node.port, canonical.port);
        assert_eq!(node.name, canonical.name);
        assert_eq!(node.outbound, canonical.outbound);
        assert_eq!(node.id, canonical.id);
    }
}

#[test]
fn shadowrocket_vless_plaintext_and_display_name() {
    let authority = b64("b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:8443");
    let canonical = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:8443?security=none#fragment",
    )
    .unwrap();
    let node =
        Node::from_share_link(&format!("vless://{authority}?remark=ignored#fragment")).unwrap();
    assert_eq!(node.host, canonical.host);
    assert_eq!(node.port, canonical.port);
    assert_eq!(node.name, canonical.name);
    assert_eq!(node.outbound, canonical.outbound);
    assert_eq!(node.id, canonical.id);
    let unnamed = Node::from_share_link(&format!("vless://{authority}")).unwrap();
    assert_eq!(unnamed.name, format!("vless-{}", canonical.host));
}

#[test]
fn shadowrocket_vless_rejects_invalid_authorities_and_security() {
    for payload in [
        "auto:credential-sentinel@example.com:443",
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        "auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com",
        "auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:0",
        "auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:65536",
        "auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=none",
    ] {
        let error = Node::from_share_link(&format!("vless://{}", b64(payload))).unwrap_err();
        assert!(!error.to_string().contains("credential-sentinel"));
    }
    assert!(Node::from_share_link("vless://!!!").is_err());
    let authority = b64("auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443");
    for query in [
        "tls=2",
        "tls=1&xtls=1",
        "tls=1&xtls=unknown",
        "tls=0&xtls=2",
        "tls=1&security=none",
        "tls=0&pbk=AAA",
        "tls=1&pbk=",
        "tls=1&sid=",
        "tls=1&pbk=AAA&security=tls",
        "tls=1&xtls=0&flow=xtls-rprx-vision",
        "tls=1&xtls=2&flow=xtls-rprx-direct",
        "tls=1&obfs=http",
    ] {
        assert!(
            Node::from_share_link(&format!("vless://{authority}?{query}")).is_err(),
            "{query}"
        );
    }
}

#[test]
fn shadowrocket_vless_stream_transports_match_canonical_links() {
    let authority = b64("auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443");
    for (alias, canonical) in [
        (
            "obfs=websocket&obfsParam=cdn.example&path=%2Fws",
            "type=ws&host=cdn.example&path=%2Fws",
        ),
        ("obfs=grpc&path=service", "type=grpc&serviceName=service"),
    ] {
        let node = Node::from_share_link(&format!(
            "vless://{authority}?tls=1&xtls=0&peer=tls.example&{alias}#edge"
        ))
        .unwrap();
        let canonical = Node::from_share_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&sni=tls.example&{canonical}#edge"
        ))
        .unwrap();
        assert_eq!(node.outbound, canonical.outbound);
        assert_eq!(node.id, canonical.id);
    }
}

#[test]
fn test_vless_encryption_param_and_identity() {
    let plain =
        Node::from_share_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443#plain")
            .unwrap();
    let encryption = "mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let encrypted = Node::from_share_link(&format!(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption={encryption}#encrypted"
    ))
    .unwrap();
    assert_eq!(
        encrypted.vless().unwrap().encryption.as_deref(),
        Some(encryption)
    );
    assert_ne!(plain.id, encrypted.id);

    for query in ["packetEncoding=none", "packetEncoding=xudp", "mux=xray"] {
        Node::from_share_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?{query}&encryption={encryption}"
        ))
        .unwrap();
    }
    for query in ["packetEncoding=uot-v2", "mux=h2mux"] {
        assert!(
            Node::from_share_link(&format!(
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?{query}&encryption={encryption}"
            ))
            .is_err(),
            "{query}"
        );
    }
}

#[test]
fn test_vless_encryption_with_vision_uses_supported_paths() {
    let encryption = "mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for options in [
        "",
        "&type=ws&path=%2Fvision&host=cdn.example",
        "&type=grpc&serviceName=vision",
        "&mux=xray&concurrency=-1&xudpConcurrency=4",
    ] {
        Node::from_share_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&flow=xtls-rprx-vision&encryption={encryption}{options}#encrypted-flow"
        ))
        .unwrap();
    }
    Node::from_share_link(&format!(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?flow=xtls-rprx-vision&encryption={encryption}#encrypted-flow"
    ))
    .unwrap();
    assert!(Node::from_share_link(&format!(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&flow=xtls-rprx-vision&encryption={encryption}&mux=xray"
    )).is_err());
}

#[test]
fn test_reality_without_public_key_is_rejected_on_every_load_path() {
    // Share links are validated as they are parsed.
    for link in [
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality#no-pbk",
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&pbk=#empty-pbk",
    ] {
        assert!(Node::from_share_link(link).is_err());
    }

    // A structured node reaches the same invariant through Config::validate.
    let node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&pbk=AAA#ok",
    )
    .unwrap();
    let mut config = Config::default();
    config.nodes.push(node.clone());
    config.validate().unwrap();

    // Either an auxiliary REALITY field or the key itself signals the intent; an empty key is
    // still the intent, and only a node with none of the three is an ordinary TLS node.
    for (key, short_id) in [
        (None, Some("0123456789abcdef".to_string())),
        // An empty short id is documented as valid, so it still signals REALITY.
        (None, Some(String::new())),
        (Some(String::new()), None),
        (Some("  ".to_string()), None),
    ] {
        let mut node = node.clone();
        let tls = node.tls_mut().unwrap();
        tls.reality_public_key = key;
        tls.reality_short_id = short_id;
        tls.reality_spider_x = None;
        let mut config = Config::default();
        config.nodes.push(node);
        assert!(config.validate().is_err());
    }
}

#[test]
fn test_vless_derive_id_differs_by_reality_public_key() {
    let a = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&pbk=AAA#a",
    )
    .unwrap();
    let b = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&pbk=BBB#b",
    )
    .unwrap();
    assert_ne!(a.derive_id(), b.derive_id());
    assert_ne!(a.id, b.id);
}

#[test]
fn test_validate_flow_requires_tls_or_reality() {
    let mut node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=none#flow-no-tls",
    )
    .unwrap();
    node.vless_mut().unwrap().flow = Some("xtls-rprx-vision".into());
    let mut config = Config::default();
    config.nodes.push(node);
    assert!(config.validate().is_err());
}

#[test]
fn test_validate_flow_rejects_unknown_value() {
    let mut node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443#flow-bad-value",
    )
    .unwrap();
    node.vless_mut().unwrap().flow = Some("xtls-rprx-vision-udp444".into());
    let mut config = Config::default();
    config.nodes.push(node);
    assert!(config.validate().is_err());
}

#[test]
fn test_vless_vision_udp443_and_unreachable_native_fallback() {
    let opted_in = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&flow=xtls-rprx-vision-udp443",
    )
    .unwrap();
    let vless = opted_in.vless().unwrap();
    assert_eq!(vless.flow.as_deref(), Some("xtls-rprx-vision-udp443"));
    assert_eq!(vless.wire_flow(), Some("xtls-rprx-vision"));
    assert!(vless.is_vision());
    assert_eq!(vless.udp_path(443), Some(VlessUdpPath::Xudp));

    let base = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&flow=xtls-rprx-vision",
    )
    .unwrap();
    assert_eq!(base.vless().unwrap().udp_path(443), None);

    let tcp_only = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&packetEncoding=none&udp=false&flow=xtls-rprx-vision",
    )
    .unwrap();
    assert!(!tcp_only.vless().unwrap().udp_enabled());

    assert!(
        Node::from_share_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&packetEncoding=none&flow=xtls-rprx-vision"
        )
        .is_err()
    );
}

#[test]
fn test_vless_ws_transport_params() {
    let node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=ws&path=%2Fvless-ws&host=cdn.example&sni=cdn.example#n",
    )
    .unwrap();
    assert_eq!(node.protocol(), NodeProtocol::VLess);
    assert!(node.tls().unwrap().enabled);
    assert_eq!(node.transport().unwrap().transport, "ws");
    assert_eq!(
        node.transport().unwrap().ws_path.as_deref(),
        Some("/vless-ws")
    );
    // `host` on a ws link is the WS Host header, not the SNI.
    assert_eq!(
        node.transport().unwrap().ws_host.as_deref(),
        Some("cdn.example")
    );
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("cdn.example"));
    assert_eq!(
        node.vless().unwrap().uuid.as_deref(),
        Some("b831381d-6324-4d53-ad4f-8cda48b30811")
    );
}

#[test]
fn test_vless_grpc_transport_params() {
    let node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=none&type=grpc&serviceName=vless-grpc#n",
    )
    .unwrap();
    assert!(!node.tls().unwrap().enabled);
    assert_eq!(node.transport().unwrap().transport, "grpc");
    assert_eq!(
        node.transport().unwrap().grpc_service.as_deref(),
        Some("vless-grpc")
    );
}

#[test]
fn test_vless_ws_host_falls_back_to_sni_without_ws() {
    // `host` on a non-ws link keeps its SNI meaning.
    let node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&host=cdn.example#n",
    )
    .unwrap();
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("cdn.example"));
    assert!(node.transport().unwrap().ws_host.is_none());
}

#[test]
fn hy2_alias_preserves_userpass_and_hopping_identity() {
    let canonical = Node::from_share_link(
        "hysteria2://user:password@example.com:123,5000-6000/?insecure=1#hy2",
    )
    .unwrap();
    for link in [
        "hy2://user:password@example.com:123,5000-6000/?insecure=1#hy2",
        "HY2://user:password@example.com:123,5000-6000/?insecure=1#hy2",
        "hysteria2://user%3Apassword@example.com:123,5000-6000/?insecure=1#hy2",
    ] {
        let node = Node::from_share_link(link).unwrap();
        assert_eq!(
            node.hysteria2().unwrap().auth.as_deref(),
            Some("user:password")
        );
        assert_eq!(
            node.hysteria2().unwrap().port_hopping.as_deref(),
            Some("123,5000-6000")
        );
        assert_eq!(node.outbound, canonical.outbound);
        assert_eq!(node.id, canonical.id);
    }
}

#[test]
fn shadowrocket_vmess_ws_and_grpc_match_v2rayn_json() {
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let authority = b64(&format!("auto:{uuid}@vmess.example.com:443"));
    let ws_json = r#"{"ps":"vmess-ws","add":"vmess.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","scy":"auto","net":"ws","host":"cdn.example.com","path":"/vmess-ws","tls":"tls","sni":"sni.example.com"}"#;
    let canonical_ws = Node::from_share_link(&format!("vmess://{}", b64(ws_json))).unwrap();
    let shadowrocket_ws = Node::from_share_link(&format!(
        "vmess://{authority}?tfo=1&remark=vmess-ws&alterId=0&tls=1&peer=sni.example.com&obfs=websocket&path=%2Fvmess-ws&obfsParam=cdn.example.com"
    ))
    .unwrap();
    assert_eq!(shadowrocket_ws.outbound, canonical_ws.outbound);
    assert_eq!(shadowrocket_ws.id, canonical_ws.id);
    let standard_authority = base64::engine::general_purpose::STANDARD
        .encode(format!("auto:{uuid}@vmess.example.com:443"));
    let standard_ws = Node::from_share_link(&format!(
        "vmess://{standard_authority}?tls=1&peer=sni.example.com&obfs=websocket&path=%2Fvmess-ws&obfsParam=cdn.example.com&tls=1"
    ))
    .unwrap();
    assert_eq!(standard_ws.outbound, canonical_ws.outbound);
    assert_eq!(standard_ws.id, canonical_ws.id);

    let grpc_json = r#"{"ps":"vmess-grpc","add":"vmess.example.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","scy":"auto","net":"grpc","path":"vmess-grpc","host":"sni.example.com","tls":"tls"}"#;
    let canonical_grpc = Node::from_share_link(&format!("vmess://{}", b64(grpc_json))).unwrap();
    let shadowrocket_grpc = Node::from_share_link(&format!(
        "vmess://{authority}?tfo=0&remark=vmess-grpc&alterId=0&tls=1&peer=sni.example.com&obfs=grpc&path=vmess-grpc&host=sni.example.com"
    ))
    .unwrap();
    assert_eq!(shadowrocket_grpc.outbound, canonical_grpc.outbound);
    assert_eq!(shadowrocket_grpc.id, canonical_grpc.id);
}

#[test]
fn shadowrocket_vmess_rejects_bad_authorities_and_conflicts() {
    let valid = "auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443";
    for payload in [
        "auto:credential-sentinel@example.com:443",
        "auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com",
        "auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:0",
        "auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:65536",
        "auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443/path",
    ] {
        let error = Node::from_share_link(&format!("vmess://{}", b64(payload))).unwrap_err();
        assert!(!error.to_string().contains("credential-sentinel"));
    }
    for query in [
        "tls=2",
        "alterId=1",
        "obfs=http",
        "obfs=websocket&type=grpc",
        "allowInsecure=maybe",
        "security=reality",
        "security=reality&encryption=auto",
        "tls=1&pbk=active-reality-key",
        "encryption=chacha20-poly1305",
        "scy=none",
    ] {
        assert!(
            Node::from_share_link(&format!("vmess://{}?{query}", b64(valid))).is_err(),
            "{query}"
        );
    }
    assert!(Node::from_share_link("vmess://!!!").is_err());
}

#[test]
fn test_credential_bytes_are_not_replaced() {
    // RFC 1929 makes the SOCKS5 password a byte string. A lossy decode would
    // turn 0xFF into U+FFFD and authenticate with three bytes the operator
    // never wrote, failing at dial time with nothing pointing back here.
    for link in [
        "socks5://user:p%FFss@1.2.3.4:1080#n",
        "socks5://u%FFser:pass@1.2.3.4:1080#n",
        "trojan://%FF%FE@1.2.3.4:443#t",
        "ss://aes-256-gcm:p%FFss@1.2.3.4:8388#s",
    ] {
        assert!(
            Node::from_share_link(link).is_err(),
            "{link} must be refused rather than silently re-encoded"
        );
    }

    // A component the protocol discards must not decide whether the link loads:
    // Trojan, VLESS and AnyTLS all take `password.or(username)`.
    let node = Node::from_share_link("trojan://%FF:correct-password@1.2.3.4:443#t").unwrap();
    assert_eq!(
        node.trojan().unwrap().password.as_deref(),
        Some("correct-password")
    );
    let node = Node::from_share_link("anytls://%FF:correct-password@1.2.3.4:443#a").unwrap();
    assert_eq!(
        node.anytls().unwrap().password.as_deref(),
        Some("correct-password")
    );

    // Multibyte UTF-8 survives byte for byte.
    let node = Node::from_share_link("socks5://user:p%C3%A4ss@1.2.3.4:1080#n").unwrap();
    assert_eq!(node.socks5().unwrap().password.as_deref(), Some("päss"));

    let node = Node::from_share_link("socks5://user:p%40ss@1.2.3.4:1080#n").unwrap();
    let socks5 = node.socks5().unwrap();
    assert_eq!(socks5.password.as_deref(), Some("p@ss"));

    // A name is cosmetic, so an undecodable fragment must not lose the node.
    let node = Node::from_share_link("socks5://user:pass@1.2.3.4:1080#n%FFm").unwrap();
    assert!(node.name.contains('\u{FFFD}'), "{}", node.name);
}

#[test]
fn empty_share_link_sni_uses_the_host_fallback() {
    for alias in ["sni", "peer"] {
        let node = Node::from_share_link(&format!("trojan://pw@example.com:443?{alias}=")).unwrap();
        assert_eq!(node.tls().unwrap().sni, None);
        let node = Node::from_share_link(&format!(
            "trojan://pw@example.com:443?{alias}=&host=cdn.example"
        ))
        .unwrap();
        assert_eq!(node.tls().unwrap().sni.as_deref(), Some("cdn.example"));
    }
}

#[test]
fn empty_share_link_host_alias_leaves_sni_absent() {
    for query in ["host=", "sni=&host="] {
        let node = Node::from_share_link(&format!("trojan://pw@example.com:443?{query}")).unwrap();
        assert_eq!(node.tls().unwrap().sni, None, "{query}");
        assert_eq!(node.host(), "example.com");
    }
}

#[test]
fn empty_share_link_sni_does_not_mask_peer() {
    let node = Node::from_share_link("trojan://pw@example.com:443?sni=&peer=cdn.example").unwrap();
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("cdn.example"));
}

#[test]
fn empty_share_link_flow_is_absent_and_valid() {
    let node =
        Node::from_share_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?flow=")
            .unwrap();
    assert_eq!(node.vless().unwrap().flow, None);
    let mut config = Config::default();
    config.nodes.push(node);
    config.validate().unwrap();
}

#[test]
fn empty_share_link_flow_allows_xtls_vision() {
    let node = Node::from_share_link(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?flow=&xtls=2",
    )
    .unwrap();
    assert_eq!(
        node.vless().unwrap().flow.as_deref(),
        Some("xtls-rprx-vision")
    );
}

#[test]
fn empty_share_link_reality_key_still_conflicts_with_plaintext() {
    assert!(
        Node::from_share_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=none&pbk=",
        )
        .is_err()
    );
}

#[test]
fn c08_share_link_verification_yes_on_warn_and_enable() {
    for spelling in ["yes", "on"] {
        let mut diagnostics = Vec::new();
        let node = Node::from_share_link_with_detailed_diagnostics(
            &format!("trojan://secret-password@secret.example:443?insecure={spelling}"),
            &mut diagnostics,
        )
        .unwrap();
        assert!(node.tls().unwrap().skip_cert_verify);
        assert_eq!(diagnostics.len(), 1, "{spelling}: {diagnostics:?}");
        let warning = &diagnostics[0];
        assert_eq!(warning.code, "legacy-config-warning");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.setting.to_string(), "nodes.skip_cert_verify");
        assert_eq!(warning.value, SafeValue::Redacted);
        assert!(!format!("{warning:?}").contains("secret-password"));
        assert!(!format!("{warning:?}").contains("secret.example"));
    }

    let dae = "node {\n    edge: 'trojan://secret-password@secret.example:443?insecure=yes'\n}\nrouting {\n    fallback: direct\n}";
    let mut diagnostics = Vec::new();
    let config =
        honk_config::parser::parse_dae_config_with_detailed_diagnostics(dae, &mut diagnostics)
            .unwrap();
    assert_eq!(config.nodes.len(), 1);
    let warning = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "legacy-config-warning")
        .expect("dae share-link warning");
    assert_eq!(warning.setting.to_string(), "nodes[1].skip_cert_verify");
    assert_eq!(warning.entry_index, Some(1));
    assert_eq!(warning.line, Some(2));
    assert_eq!(warning.value, SafeValue::Redacted);
    assert!(!format!("{diagnostics:?}").contains("secret-password"));
    assert!(!format!("{diagnostics:?}").contains("secret.example"));
}

#[test]
fn c08_share_link_verification_aliases_resolve_and_reject_invalid() {
    let equal = Node::from_share_link(
        "trojan://pw@example.com:443?allowInsecure=true&allow_insecure=1&insecure=true",
    )
    .unwrap();
    assert!(equal.tls().unwrap().skip_cert_verify);
    let authority = b64("auto:b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443");
    let encoded = Node::from_share_link(&format!(
        "vmess://{authority}?tls=1&allowInsecure=true&allowInsecure=1"
    ))
    .unwrap();
    assert!(encoded.tls().unwrap().skip_cert_verify);

    for link in [
        "trojan://pw@example.com:443?allowInsecure=true&insecure=false",
        "trojan://pw@example.com:443?insecure=unknown",
        "trojan://pw@example.com:443?insecure=",
    ] {
        assert!(Node::from_share_link(link).is_err(), "{link}");
    }
    for spelling in ["t", "y"] {
        let node =
            Node::from_share_link(&format!("trojan://pw@example.com:443?insecure={spelling}"))
                .unwrap();
        assert!(!node.tls().unwrap().skip_cert_verify, "{spelling}");
    }

    let typed: Node = serde_json::from_value(serde_json::json!({
        "name": "typed",
        "protocol": "trojan",
        "address": "example.com:443",
        "host": "example.com",
        "port": 443,
        "password": "password",
        "tls": true,
        "skip_cert_verify": false,
    }))
    .unwrap();
    assert!(!typed.tls().unwrap().skip_cert_verify);
}

#[test]
fn c09_flat_credential_aliases_preserve_equal_conflicts_and_empty() {
    assert_flat_credential_alias(
        "hysteria2",
        "hy2_auth",
        "password",
        "same",
        "dedicated",
        "generic",
    );
    assert_flat_credential_alias("tuic", "tuic_uuid", "username", UUID_A, UUID_A, UUID_B);
    assert_flat_credential_alias(
        "tuic",
        "tuic_password",
        "password",
        "same",
        "dedicated",
        "generic",
    );
    assert_flat_credential_alias(
        "juicity",
        "juicity_uuid",
        "username",
        UUID_A,
        UUID_A,
        UUID_B,
    );
    assert_flat_credential_alias(
        "juicity",
        "juicity_password",
        "password",
        "same",
        "dedicated",
        "generic",
    );
    assert_flat_credential_alias(
        "anytls",
        "anytls_password",
        "password",
        "same",
        "dedicated",
        "generic",
    );

    let empty_tuic = flat_node_with("tuic", &[("tuic_password", serde_json::json!(""))]).unwrap();
    assert_eq!(empty_tuic.tuic().unwrap().password.as_deref(), Some(""));

    let numeric = flat_node_with("anytls", &[("password", serde_json::json!(123))]);
    assert!(
        numeric.is_err(),
        "flat typed credentials must not coerce numbers"
    );
}

#[test]
fn c10_vmess_json_net_maps_only_to_stream_transport() {
    for (net, expected_transport) in [
        (Some("tcp"), "tcp"),
        (Some("ws"), "ws"),
        (Some("grpc"), "grpc"),
        (None, ""),
    ] {
        let node = Node::from_share_link(&vmess_link(&vmess_transport_fixture(net))).unwrap();
        assert_eq!(
            node.transport().unwrap().transport,
            expected_transport,
            "{net:?}"
        );
        assert_eq!(
            node.network(),
            None,
            "{net:?} must not become packet network"
        );
    }
    assert!(
        Node::from_share_link(&vmess_link(&vmess_transport_fixture(Some("h2")))).is_err(),
        "unsupported VMess stream transport"
    );
}

#[test]
fn c10_share_link_stream_transport_aliases_resolve_before_storage() {
    for (query, expected_transport) in [
        ("type=ws", "ws"),
        ("type=ws&type=ws", "ws"),
        ("type=ws&network=ws&obfs=websocket", "ws"),
        ("type=tcp&obfs=", "tcp"),
        ("type=&network=tcp", ""),
        ("network=tcp&type=", ""),
        ("network=grpc&obfs=grpc", "grpc"),
    ] {
        let node = Node::from_share_link(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?{query}"
        ))
        .unwrap();
        assert_eq!(
            node.transport().unwrap().transport,
            expected_transport,
            "{query}"
        );
    }

    let authority = b64(&format!("auto:{UUID_A}@example.com:443"));
    let encoded = Node::from_share_link(&format!(
        "vmess://{authority}?tls=1&type=&network=tcp&network=tcp"
    ))
    .unwrap();
    assert_eq!(encoded.transport().unwrap().transport, "");
    assert_eq!(encoded.network(), None);

    for query in [
        "type=ws&network=grpc",
        "type=ws&type=grpc",
        "type=tcp&obfs=websocket",
        "type=h2",
        "obfs=h2",
    ] {
        assert!(
            Node::from_share_link(&format!(
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?{query}"
            ))
            .is_err(),
            "{query}"
        );
    }
}

#[test]
fn c11_flat_packet_network_validates_and_preserves_spelling() {
    for protocol in ["trojan", "anytls"] {
        for network in ["tcp", "udp", "tcp,udp"] {
            let node = flat_node_with(
                protocol,
                &[
                    ("password", serde_json::json!("packet-password")),
                    ("tls", serde_json::json!(true)),
                    ("network", serde_json::json!(network)),
                ],
            )
            .unwrap();
            assert_eq!(node.network(), Some(network), "{protocol}:{network}");
        }

        let omitted = flat_node_with(
            protocol,
            &[
                ("password", serde_json::json!("packet-password")),
                ("tls", serde_json::json!(true)),
            ],
        )
        .unwrap();
        for empty in ["", " \t "] {
            let node = flat_node_with(
                protocol,
                &[
                    ("password", serde_json::json!("packet-password")),
                    ("tls", serde_json::json!(true)),
                    ("network", serde_json::json!(empty)),
                ],
            )
            .unwrap();
            assert_eq!(node.outbound, omitted.outbound, "{protocol}:{empty:?}");
        }

        for invalid in ["quic", "tcp,quic", "tcp,"] {
            let result = flat_node_with(
                protocol,
                &[
                    ("password", serde_json::json!("packet-password")),
                    ("tls", serde_json::json!(true)),
                    ("network", serde_json::json!(invalid)),
                ],
            );
            assert!(result.is_err(), "{protocol}:{invalid}");
        }
    }
}

#[test]
fn c12_vmess_cipher_claims_resolve_before_assignment() {
    for (scy, security, expected) in [
        ("", "auto", Some("auto")),
        ("AUTO", "auto", Some("auto")),
        ("aes-128-gcm", "AES-128-GCM", Some("aes-128-gcm")),
        ("", "", None),
    ] {
        let mut fixture: serde_json::Value =
            serde_json::from_str(&vmess_transport_fixture(None)).unwrap();
        fixture["scy"] = scy.into();
        fixture["security"] = security.into();
        let node = Node::from_share_link(&vmess_link(&fixture.to_string())).unwrap();
        assert_eq!(node.vmess().unwrap().encryption.as_deref(), expected);
    }
    for (scy, security) in [("none", "auto"), ("auto", "aes-128-gcm")] {
        let mut fixture: serde_json::Value =
            serde_json::from_str(&vmess_transport_fixture(None)).unwrap();
        fixture["scy"] = scy.into();
        fixture["security"] = security.into();
        assert!(Node::from_share_link(&vmess_link(&fixture.to_string())).is_err());
    }
}

#[test]
fn c12_shadowrocket_cipher_aliases_keep_security_tls_meaning() {
    let authority = b64(&format!("auto:{UUID_A}@example.com:443"));
    for security in ["none", "tls"] {
        let node = Node::from_share_link(&format!(
            "vmess://{authority}?security={security}&scy=AUTO&encryption=auto"
        ))
        .unwrap();
        assert_eq!(node.vmess().unwrap().encryption.as_deref(), Some("auto"));
        assert_eq!(node.tls().unwrap().enabled, security == "tls");
    }
    let canonical = Node::from_share_link(&format!("vmess://{authority}?security=auto")).unwrap();
    let repeated =
        Node::from_share_link(&format!("vmess://{authority}?security=AUTO&security=auto")).unwrap();
    assert_eq!(repeated.outbound, canonical.outbound);
    assert_eq!(repeated.id, canonical.id);
    for query in [
        "scy=auto&encryption=aes-128-gcm",
        "scy=bogus&encryption=auto",
        "security=none&security=tls",
    ] {
        assert!(Node::from_share_link(&format!("vmess://{authority}?{query}")).is_err());
    }
}

#[test]
fn c13_tuic_relay_claims_cannot_be_discarded() {
    let link = format!("tuic://{UUID_A}:password@example.com:443");
    let control = Node::from_share_link(&link).unwrap();
    for query in [
        "udp-relay-mode=",
        "udp_relay_mode=native",
        "udp-relay-mode=&udp_relay_mode=native",
    ] {
        assert_eq!(
            Node::from_share_link(&format!("{link}?{query}"))
                .unwrap()
                .outbound,
            control.outbound
        );
    }
    for query in [
        "udp-relay-mode=quic",
        "udp_relay_mode=unknown",
        "udp-relay-mode=quic&udp-relay-mode=native",
    ] {
        assert!(Node::from_share_link(&format!("{link}?{query}")).is_err());
    }
}

#[test]
fn c13_hy2_obfs_claims_preserve_exact_source_grammar() {
    const LINK: &str = "hy2://password@example.com:443";
    for query in ["obfs=", "obfs=salamander", "obfs=salamander&obfs-password="] {
        assert_eq!(
            Node::from_share_link(&format!("{LINK}?{query}"))
                .unwrap()
                .hysteria2()
                .unwrap()
                .obfs,
            None
        );
    }
    for query in [
        "obfs=SALAMANDER",
        "obfs=unknown",
        "obfs=unknown&obfs=salamander",
        "obfs=salamander&obfs-password=a&obfs_password=b",
    ] {
        assert!(Node::from_share_link(&format!("{LINK}?{query}")).is_err());
    }
}

#[test]
fn c15_hopping_sets_reject_duplicates_and_keep_valid_spelling() {
    for spec in ["443,443", "443-445,445-446"] {
        for link in [
            format!("hy2://password@example.com:443?mport={spec}"),
            format!("hy2://password@example.com:{spec}"),
        ] {
            assert!(Node::from_share_link(&link).is_err());
        }
    }
    for spec in ["443", "443, 500-501"] {
        let node =
            Node::from_share_link(&format!("hy2://password@example.com:443?mport={spec}")).unwrap();
        assert_eq!(
            node.hysteria2().unwrap().port_hopping.as_deref(),
            Some(spec)
        );
    }
}

#[test]
fn c16_all_share_link_completions_reject_intrinsic_errors() {
    for link in [
        "tuic://invalid:password@example.com:443",
        "juicity://invalid:password@example.com:443",
        "socks5://example.com:0",
    ] {
        assert!(Node::from_share_link(link).is_err(), "{link}");
    }
    let mut fixture: serde_json::Value =
        serde_json::from_str(&vmess_transport_fixture(None)).unwrap();
    fixture["id"] = "invalid".into();
    assert!(Node::from_share_link(&vmess_link(&fixture.to_string())).is_err());
}

#[test]
fn c16_flat_completion_rejects_invalid_nodes_without_alpn() {
    for (field, value) in [
        ("host", serde_json::json!(" ")),
        ("port", serde_json::json!(0)),
    ] {
        assert!(flat_node_with("socks5", &[(field, value)]).is_err());
    }
    assert!(flat_node_with("vmess", &[("password", serde_json::json!("invalid"))]).is_err());
    assert!(
        flat_node_with(
            "vless",
            &[
                ("password", serde_json::json!(UUID_A)),
                ("flow", serde_json::json!("xtls-rprx-vision")),
                ("tls", false.into())
            ]
        )
        .is_err()
    );
    let fallback = flat_node_with("socks5", &[("host", "".into())]).unwrap();
    assert_eq!(fallback.host(), "example.com");
    assert!(
        flat_node_with(
            "socks5",
            &[("host", "".into()), ("address", "[::1]:443".into())]
        )
        .is_err()
    );
}

#[test]
fn c16_constructed_config_cannot_bypass_canonical_node_checks() {
    let base = Node::from_share_link("anytls://password@example.com:443").unwrap();
    for field in ["port", "sni", "network"] {
        let mut node = base.clone();
        match field {
            "port" => node.port = 0,
            "sni" => node.tls_mut().unwrap().sni = Some(" ".into()),
            _ => node.anytls_mut().unwrap().network = Some("quic".into()),
        }
        let mut config = Config::default();
        config.nodes.push(node);
        assert!(config.validate().is_err(), "{field}");
    }
}

#[test]
fn detailed_share_link_validation_preserves_intrinsic_cause() {
    let mut diagnostics = Vec::new();
    let error = Node::from_share_link_with_detailed_diagnostics(
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=none&flow=xtls-rprx-vision",
        &mut diagnostics,
    )
    .expect_err("flow without TLS must fail intrinsic validation");
    assert_eq!(error.diagnostic.code, "invalid-config-value");
    assert_eq!(error.diagnostic.setting.to_string(), "nodes.flow");
    assert!(
        error
            .to_string()
            .contains("VLESS flow requires TLS or REALITY")
    );
}
