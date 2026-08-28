//! Integration tests for the unified share-link parser and the
//! extension-aware config (de)serialization.

use base64::Engine as _;
use honk_config::Config;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;

/// URL-safe base64 without padding (the encoding used by vmess links).
fn b64(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
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
            mode: honk_config::node::WireMode::Xudp,
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
fn test_legacy_cross_protocol_fields_are_rejected() {
    let json = r#"{
        "name":"dirty-id",
        "protocol":"socks5",
        "address":"proxy.example:1080",
        "host":"proxy.example",
        "port":1080,
        "username":"user",
        "password":"pass",
        "hy2_obfs":"cross-protocol-obfs"
    }"#;
    let error = serde_json::from_str::<Node>(json).unwrap_err();
    assert!(error.to_string().contains("hy2_obfs"), "{error}");
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
    assert_eq!(node.transport().unwrap().transport, "ws");
    assert_eq!(node.network(), Some("ws"));
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
        assert!(
            err.to_string().contains("Unknown node protocol"),
            "'{link}' must be rejected: {err}"
        );
    }
}

#[test]
fn test_unknown_scheme_rejected() {
    let err = Node::from_share_link("unknown://host:1234").unwrap_err();
    assert!(err.to_string().contains("Unknown node protocol"));
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
    config.nodes.push(
        Node::from_share_link(
            "anytls://uuid-pw@any.example.com:443?insecure=1&idle_session_timeout=1m&min_idle_session=4#anytls-node",
        )
        .unwrap(),
    );
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
fn test_config_json_vless_mode_and_default() {
    let mut config = Config::default();
    config.nodes.push(
        Node::from_share_link("vless://uuid@example.com:443?vless_mode=mux-cool#vless").unwrap(),
    );
    let json = config.to_json_string().unwrap();
    let parsed = Config::from_json_str(&json).unwrap();
    assert_eq!(
        parsed.nodes[0].vless().unwrap().mode,
        honk_config::node::WireMode::MuxCool
    );

    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    value["nodes"][0]
        .as_object_mut()
        .unwrap()
        .remove("vless_mode");
    let parsed = Config::from_json_str(&value.to_string()).unwrap();
    assert_eq!(
        parsed.nodes[0].vless().unwrap().mode,
        honk_config::node::WireMode::Legacy
    );
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
fn test_ech_query_params() {
    // ech_config=<base64url ECHConfigList> enables ECH and carries the config.
    let node = Node::from_share_link(
        "hysteria2://pass@example.com:443/?sni=example.com&ech_config=QUJDMTIz",
    )
    .unwrap();
    assert!(node.tls().unwrap().ech_enabled);
    assert_eq!(node.tls().unwrap().ech_config.as_deref(), Some("QUJDMTIz"));

    // Bare ech=1 toggles ECH without keys.
    let node = Node::from_share_link("tuic://u:p@example.com:443/?ech=1").unwrap();
    assert!(node.tls().unwrap().ech_enabled);
    assert!(node.tls().unwrap().ech_config.is_none());
}

#[test]
fn test_tuic_window_params() {
    let node = Node::from_share_link(
        "tuic://u:p@example.com:443/?initStreamReceiveWindow=4194304&initConnReceiveWindow=16777216",
    )
    .unwrap();
    assert_eq!(node.tuic().unwrap().init_stream_recv_window, Some(4194304));
    assert_eq!(node.tuic().unwrap().init_conn_recv_window, Some(16777216));
    // Unset by default.
    let node = Node::from_share_link("tuic://u:p@example.com:443").unwrap();
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
    let node = Node::from_share_link("tuic://u:p@example.com:443/?alpn=h3,h3-29").unwrap();
    assert_eq!(node.tuic().unwrap().alpn.as_deref(), Some("h3,h3-29"));

    // Unset by default.
    let node = Node::from_share_link("tuic://u:p@example.com:443").unwrap();
    assert_eq!(node.tuic().unwrap().alpn, None);
    assert_eq!(node.tuic().unwrap().congestion, None);
}

#[test]
fn test_vless_mode_query() {
    for (value, expected) in [
        ("legacy", honk_config::node::WireMode::Legacy),
        ("uot-v2", honk_config::node::WireMode::UotV2),
        ("h2mux", honk_config::node::WireMode::H2mux),
        ("h2mux-padded", honk_config::node::WireMode::H2muxPadded),
        ("xudp", honk_config::node::WireMode::Xudp),
        ("mux-cool", honk_config::node::WireMode::MuxCool),
    ] {
        let node = Node::from_share_link(&format!(
            "vless://uuid@example.com:443?vless_mode={value}#node"
        ))
        .unwrap();
        assert_eq!(node.vless().unwrap().mode, expected);
    }
    let xudp =
        Node::from_share_link("vless://uuid@example.com:443?packetEncoding=xudp#node").unwrap();
    assert_eq!(
        xudp.vless().unwrap().mode,
        honk_config::node::WireMode::Xudp
    );

    let legacy =
        Node::from_share_link("vless://uuid@example.com:443?packetEncoding=none#node").unwrap();
    assert_eq!(
        legacy.vless().unwrap().mode,
        honk_config::node::WireMode::Legacy
    );

    let error =
        Node::from_share_link("vless://uuid@example.com:443?vless_mode=smux#node").unwrap_err();
    assert!(error.to_string().contains("unsupported wire mode"));
}

#[test]
fn test_vless_mode_query_rejects_duplicates() {
    let error = Node::from_share_link(
        "vless://uuid@example.com:443?vless_mode=xudp&vless_mode=legacy#node",
    )
    .unwrap_err();
    assert!(error.to_string().contains("duplicate"));
    let error = Node::from_share_link(
        "vless://uuid@example.com:443?vless_mode=xudp&packetEncoding=xudp#node",
    )
    .unwrap_err();
    assert!(error.to_string().contains("duplicate"));
}

#[test]
fn test_rejects_vless_mode_on_other_protocols() {
    for query in ["vless_mode=h2mux", "packetEncoding=xudp"] {
        let error =
            Node::from_share_link(&format!("trojan://password@example.com:443?{query}#node"))
                .unwrap_err();
        assert!(
            error.to_string().contains("only for VLESS"),
            "{query}: {error}"
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
        let error =
            Node::from_share_link(&format!("vless://uuid@example.com:443?{parameter}#node"))
                .unwrap_err();
        assert!(
            error.to_string().contains("use vless_mode"),
            "{parameter}: {error}"
        );
    }

    let error =
        Node::from_share_link("vless://uuid@example.com:443?packetEncoding=packetaddr#node")
            .unwrap_err();
    assert!(error.to_string().contains("expected xudp or none"));
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
        "vless://uuid@example.com:443?security=reality&pbk=jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc#n",
    )
    .unwrap();
    assert!(node.tls().unwrap().enabled);
    assert_eq!(node.tls().unwrap().reality_spider_x.as_deref(), Some("/"));
    assert!(node.tls().unwrap().reality_short_id.is_none());
}

#[test]
fn test_vless_security_none() {
    let node = Node::from_share_link("vless://uuid@example.com:443?security=none#n").unwrap();
    assert!(!node.tls().unwrap().enabled);
    assert!(node.tls().unwrap().reality_public_key.is_none());
}

#[test]
fn test_vless_no_security_keeps_tls_default() {
    // Existing links without a `security` parameter keep the historical
    // TLS-on default.
    let node = Node::from_share_link("vless://uuid@example.com:443#n").unwrap();
    assert!(node.tls().unwrap().enabled);
    assert!(node.tls().unwrap().reality_public_key.is_none());
}

#[test]
fn test_vless_encryption_param_and_identity() {
    let plain = Node::from_share_link("vless://uuid@example.com:443#plain").unwrap();
    let encryption = "mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let encrypted = Node::from_share_link(&format!(
        "vless://uuid@example.com:443?encryption={encryption}#encrypted"
    ))
    .unwrap();
    assert_eq!(
        encrypted.vless().unwrap().encryption.as_deref(),
        Some(encryption)
    );
    assert_ne!(plain.id, encrypted.id);
}

#[test]
fn test_validate_rejects_vless_encryption_with_flow() {
    let encryption = "mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let node = Node::from_share_link(&format!(
        "vless://uuid@example.com:443?security=tls&flow=xtls-rprx-vision&encryption={encryption}#encrypted-flow"
    ))
    .unwrap();
    let mut config = Config::default();
    config.nodes.push(node);
    let error = config.validate().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("combines VLESS Encryption with flow")
    );
}

#[test]
fn test_vless_derive_id_differs_by_reality_public_key() {
    let a =
        Node::from_share_link("vless://uuid@example.com:443?security=reality&pbk=AAA#a").unwrap();
    let b =
        Node::from_share_link("vless://uuid@example.com:443?security=reality&pbk=BBB#b").unwrap();
    assert_ne!(a.derive_id(), b.derive_id());
    assert_ne!(a.id, b.id);
}

#[test]
fn test_validate_flow_requires_tls_or_reality() {
    let node = Node::from_share_link(
        "vless://uuid@example.com:443?security=none&flow=xtls-rprx-vision#flow-no-tls",
    )
    .unwrap();
    let mut config = Config::default();
    config.nodes.push(node);
    assert!(config.validate().is_err());
}

#[test]
fn test_validate_flow_rejects_unknown_value() {
    let node = Node::from_share_link(
        "vless://uuid@example.com:443?flow=xtls-rprx-vision-udp443#flow-bad-value",
    )
    .unwrap();
    let mut config = Config::default();
    config.nodes.push(node);
    assert!(config.validate().is_err());
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
