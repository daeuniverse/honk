use base64::Engine as _;
use honk_config::node::{Node, XhttpMode, XhttpOptions, XhttpRange};
use serde_json::{Value, json};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn link(query: &str) -> Node {
    Node::from_share_link(&format!("vless://{UUID}@example.com:443?{query}#xhttp")).unwrap()
}

fn extra_uri(extra: Value) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("extra", &extra.to_string())
        .finish()
}

fn flat(options: Value) -> Result<Node, serde_json::Error> {
    serde_json::from_value(json!({
        "name":"xhttp", "protocol":"vless", "host":"example.com", "address":"example.com:443",
        "port":443, "password":UUID, "tls":true, "transport":"splithttp", "xhttp":options,
    }))
}

#[test]
fn literal_path_admission_keeps_raw_query_validation() {
    for path in ["/a b/", "/<>/", "/雪/", "/a%2Fb/?raw=a%2Fb&keep=1"] {
        let node = flat(json!({"path":path})).unwrap();
        assert_eq!(node.transport().unwrap().xhttp.as_ref().unwrap().path, path);
        let query = url::form_urlencoded::Serializer::new(String::from("type=xhttp&"))
            .append_pair("path", path).finish();
        assert_eq!(node.derive_id(), link(&query).id);
    }
    for path in ["/a\t/", "/a\u{7f}/", "/a\0/", "/a#fragment/", "/a/?q=a b", "/a/?q=<>"] {
        assert!(flat(json!({"path":path})).is_err(), "{path:?}");
    }
}

#[test]
fn extra_request_fields_fill_only_absent_top_level_claims() {
    let extra = json!({"host":"front.example", "path":"api", "mode":"stream-up"});
    let canonical = link("type=xhttp&host=front.example&path=api&mode=stream-up");
    let from_extra = link(&format!("type=xhttp&{}", extra_uri(extra.clone())));
    assert_eq!(from_extra.outbound, canonical.outbound);
    assert_eq!(from_extra.id, canonical.id);
    let defaults = link(&format!("type=xhttp&host=&path=&mode=&{}", extra_uri(extra.clone())));
    assert_eq!(defaults.id, link("type=xhttp").id);
    let overriding = link(&format!("type=xhttp&host=front.example&path=api&mode=stream-up&{}&{}", extra_uri(extra.clone()), extra_uri(json!({"host":"other.example", "path":"other", "mode":"auto"}))));
    assert_eq!(overriding.id, canonical.id);
    for top_level in [false, true] {
        let mut fixture = json!({"add":"example.com", "port":443, "id":UUID, "net":"xhttp", "tls":"tls", "extra":extra});
        if top_level {
            fixture["host"] = json!("");
            fixture["path"] = json!("");
            fixture["mode"] = json!("");
        }
        let node = Node::from_share_link(&format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(fixture.to_string()))).unwrap();
        fixture.as_object_mut().unwrap().remove("extra");
        if !top_level {
            fixture["host"] = json!("front.example");
            fixture["path"] = json!("api");
            fixture["mode"] = json!("stream-up");
        }
        let canonical = Node::from_share_link(&format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(fixture.to_string()))).unwrap();
        assert_eq!(node.outbound, canonical.outbound);
        assert_eq!(node.id, canonical.id);
    }
    for extra in [json!({"mode":"gun"}), json!({"path":"/bad#fragment"}), json!({"host":"bad host"}), json!({"host":null})] {
        assert!(Node::from_share_link(&format!("vless://{UUID}@example.com:443?type=xhttp&{}", extra_uri(extra))).is_err());
    }
}

#[test]
fn vmess_exported_xhttp_mode_and_empty_alpn_are_canonical() {
    let parse = |fixture: Value| Node::from_share_link(&format!("vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(fixture.to_string())));
    for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
        let base = json!({"add":"example.com", "port":443, "id":UUID, "net":"xhttp", "tls":"tls", "mode":mode});
        let canonical = parse(base.clone()).unwrap();
        let mut exported = base;
        exported.as_object_mut().unwrap().remove("mode");
        exported["type"] = json!(mode);
        exported["fp"] = json!("chrome");
        exported["insecure"] = json!(false);
        for alpn in ["", " , ", " h2, ,h2 "] {
            exported["alpn"] = json!(alpn);
            let node = parse(exported.clone()).unwrap();
            assert_eq!(node.outbound, canonical.outbound);
            assert_eq!(node.id, canonical.id);
        }
        exported["insecure"] = json!(true);
        assert!(parse(exported.clone()).unwrap().tls().unwrap().skip_cert_verify);
        exported["mode"] = json!(if mode == "auto" { "stream-one" } else { "auto" });
        assert!(parse(exported).is_err());
    }
    for alpn in ["", " , ", " h2, ,h2 "] {
        let query = url::form_urlencoded::Serializer::new(String::from("type=xhttp&"))
            .append_pair("alpn", alpn).finish();
        assert_eq!(link(&query).id, link("type=xhttp").id);
    }
}

#[test]
fn xhttp_uri_exporter_metadata_preserves_tls_and_request_options() {
    for scheme in ["trojan", "vless"] {
        let base = format!("{scheme}://{UUID}@example.com:443?type=xhttp&security=reality&pbk=key&sid=&spx=/&sni=tls.example&alpn=h2&host=front.example&path=/api&mode=auto&allowInsecure=1&insecure=1");
        let canonical = Node::from_share_link(&base).unwrap();
        let exported = Node::from_share_link(&format!("{base}&fp=chrome&headerType=none&flow=&encryption=none&extra=%7B%7D")).unwrap();
        assert_eq!(exported.transport(), canonical.transport());
        assert_eq!(exported.tls(), canonical.tls());
        assert!(exported.tls().unwrap().skip_cert_verify);
    }
    assert!(Node::from_share_link(&format!("vless://{UUID}@example.com:443?type=xhttp&headerType=http")).is_err());
}

#[test]
fn legacy_transports_ignore_unrelated_mode_and_extra() {
    for transport in ["tcp", "ws", "grpc"] {
        for scheme in ["vless", "trojan"] {
            let base = format!("{scheme}://{UUID}@example.com:443?type={transport}&path=/svc&serviceName=svc");
            let canonical = Node::from_share_link(&base).unwrap();
            for suffix in ["&mode=gun", "&mode=multi&extra=", "&extra=not-json"] {
                let node = Node::from_share_link(&format!("{base}{suffix}")).unwrap();
                assert_eq!(node.outbound, canonical.outbound);
                assert_eq!(node.id, canonical.id);
            }
        }
        let fixture = json!({"add":"example.com", "port":443, "id":UUID, "net":transport,
            "mode":"gun", "extra":{"unrelated":null}});
        let node = Node::from_share_link(&format!("vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(fixture.to_string()))).unwrap();
        assert_eq!(node.transport().unwrap().transport, transport);
    }
}

#[test]
fn aliases_defaults_and_normalized_paths_share_identity() {
    let canonical = link("type=xhttp");
    assert_eq!(
        canonical.transport().unwrap().xhttp,
        Some(XhttpOptions::default())
    );
    assert_eq!(canonical.tls().unwrap().alpn, ["h2"]);
    for query in [
        "type=splithttp",
        "type=splithttp&type=xhttp&network=splithttp",
        "type=xhttp&path=&host=&mode=&alpn=h2",
        "type=xhttp&path=/&mode=auto&alpn=h2,h2",
        "type=xhttp&alpn=h2&alpn=h2,h2",
    ] {
        let alias = link(query);
        assert_eq!(alias.outbound, canonical.outbound, "{query}");
        assert_eq!(alias.id, canonical.id, "{query}");
    }
    let defaults =
        extra_uri(json!({"xPaddingBytes":"", "scMaxEachPostBytes":"", "scMinPostsIntervalMs":""}));
    assert_eq!(link(&format!("type=xhttp&{defaults}")).id, canonical.id);
    assert_eq!(flat(json!({"path":"", "host":"", "mode":"", "x_padding_bytes":"", "sc_max_each_post_bytes":"", "sc_min_posts_interval_ms":""})).unwrap().derive_id(), canonical.id);
    assert_eq!(
        link("type=xhttp&path=api%3Fraw%3D%252F").id,
        link("type=xhttp&path=/api/%3Fraw%3D%252F").id
    );
    assert_ne!(
        link("type=xhttp&path=/a/../b").id,
        link("type=xhttp&path=/b").id
    );
    assert_ne!(
        link("type=xhttp&path=/%2561").id,
        link("type=xhttp&path=/a").id
    );
}

#[test]
fn accepted_extra_reaches_canonical_node_without_parameter_loss() {
    let extra = json!({"headers":{"X-Test":"keep", "User-Agent":"test"}, "xPaddingBytes":"123-456",
        "noGRPCHeader":true, "scMaxEachPostBytes":4096, "scMinPostsIntervalMs":"0-50"});
    let node = link(&format!(
        "type=splithttp&path=api%3Fx%3D1&host=front.example&mode=stream-up&{}",
        extra_uri(extra)
    ));
    let options = node.transport().unwrap().xhttp.as_ref().unwrap();
    assert_eq!(options.path, "/api/?x=1");
    assert_eq!(options.host.as_deref(), Some("front.example"));
    assert_eq!(options.mode, XhttpMode::StreamUp);
    assert_eq!(
        options.headers.get("x-test").map(String::as_str),
        Some("keep")
    );
    assert_eq!(options.x_padding_bytes, XhttpRange { min: 123, max: 456 });
    assert!(options.no_grpc_header);
    assert_eq!(
        options.sc_max_each_post_bytes,
        XhttpRange {
            min: 4096,
            max: 4096
        }
    );
    assert_eq!(
        options.sc_min_posts_interval_ms,
        XhttpRange { min: 0, max: 50 }
    );
    assert!(
        node.tls().unwrap().sni.is_none(),
        "HTTP host must not be silently moved into TLS SNI"
    );
    for restored in [
        serde_json::from_str::<Node>(&serde_json::to_string(&node).unwrap()).unwrap(),
        serde_yaml::from_str::<Node>(&serde_yaml::to_string(&node).unwrap()).unwrap(),
        toml::from_str::<Node>(&toml::to_string(&node).unwrap()).unwrap(),
    ] {
        assert_eq!(restored.outbound, node.outbound);
        assert_eq!(restored.derive_id(), node.id);
    }
}

#[test]
fn all_xhttp_option_differences_change_reload_identity() {
    let default = flat(json!({})).unwrap();
    for options in [
        json!({"path":"/changed"}),
        json!({"host":"front.example"}),
        json!({"mode":"packet-up"}),
        json!({"mode":"stream-up"}),
        json!({"mode":"stream-one"}),
        json!({"headers":{"x-test":"a"}}),
        json!({"x_padding_bytes":"101-1000"}),
        json!({"no_grpc_header":true}),
        json!({"sc_max_each_post_bytes":4096}),
        json!({"sc_min_posts_interval_ms":31}),
    ] {
        let changed = flat(options.clone()).unwrap();
        assert_ne!(changed.derive_id(), default.derive_id(), "{options}");
        let restored: Node =
            serde_json::from_value(serde_json::to_value(&changed).unwrap()).unwrap();
        assert_eq!(restored.derive_id(), changed.derive_id());
    }
    let first =
        flat(json!({"headers":{"X-A":"a","x-b":"b"},"x_padding_bytes":"100-1000"})).unwrap();
    let second =
        flat(json!({"x_padding_bytes":{"min":100,"max":1000},"headers":{"X-B":"b","x-a":"a"}}))
            .unwrap();
    assert_eq!(first.outbound, second.outbound);
    assert_eq!(first.derive_id(), second.derive_id());
    assert!(
        serde_json::to_value(link("type=tcp"))
            .unwrap()
            .get("xhttp")
            .is_none()
    );
}

#[test]
fn raw_unsupported_options_ranges_and_headers_fail_closed() {
    for field in [
        "downloadSettings",
        "xmux",
        "reuseSettings",
        "sessionPlacement",
        "seqPlacement",
        "uplinkDataPlacement",
        "uplinkHTTPMethod",
        "xPaddingObfsMode",
        "unknown",
    ] {
        for value in [Value::Null, json!(""), json!({}), json!(false)] {
            let mut extra = serde_json::Map::new();
            extra.insert(field.into(), value);
            assert!(
                Node::from_share_link(&format!(
                    "vless://{UUID}@example.com:443?type=xhttp&{}",
                    extra_uri(Value::Object(extra))
                ))
                .is_err(),
                "{field}"
            );
        }
    }
    for options in [
        Value::Null,
        json!({"download_settings":null}),
        json!({"x_padding_bytes":0}),
        json!({"x_padding_bytes":8193}),
        json!({"sc_max_each_post_bytes":0}),
        json!({"sc_max_each_post_bytes":16777217}),
        json!({"sc_min_posts_interval_ms":60001}),
        json!({"x_padding_bytes":"500-100"}),
        json!({"sc_max_each_post_bytes":"-1"}),
        json!({"headers":{"x-test":"value\r\ninjected: yes"}}),
        json!({"headers":{":authority":"host"}}),
        json!({"headers":{"referer":"custom"}}),
        json!({"headers":{"Content-Type":"custom"}}),
        json!({"headers":{"Connection":"close"}}),
        json!({"headers":{"Host":"other.example"}}),
        json!({"headers":{"X-A":"one","x-a":"two"}}),
        json!({"path":"/bad#fragment"}),
        json!({"host":"user@front.example"}),
    ] {
        assert!(flat(options.clone()).is_err(), "{options}");
    }
    let mut other = serde_json::to_value(link("type=tcp")).unwrap();
    other["xhttp"] = json!({});
    assert!(serde_json::from_value::<Node>(other).is_err());
    for query in [
        "type=xhttp&downloadSettings=",
        "type=xhttp&unknown=",
        "type=xhttp&mode=invalid",
        "type=xhttp&path=/a&path=/b",
        "type=xhttp&host=a&host=b",
        "type=xhttp&mode=auto&mode=stream-one",
        "type=xhttp&alpn=http/1.1",
        "type=xhttp&alpn=h3",
        "type=xhttp&alpn=h2,http/1.1",
        "type=xhttp&extra=null",
    ] {
        assert!(
            Node::from_share_link(&format!("vless://{UUID}@example.com:443?{query}")).is_err(),
            "{query}"
        );
    }
}

#[test]
fn equal_extra_claims_normalize_before_comparison_and_conflicts_reject() {
    let a = extra_uri(json!({"headers":{"X-A":"a","x-b":"b"},"xPaddingBytes":"100-1000"}));
    let b =
        extra_uri(json!({"xPaddingBytes":{"min":100,"max":1000},"headers":{"X-B":"b","x-a":"a"}}));
    assert_eq!(
        link(&format!("type=xhttp&{a}&{b}")).id,
        link(&format!("type=xhttp&{a}")).id
    );
    let different = extra_uri(json!({"xPaddingBytes":500}));
    assert!(
        Node::from_share_link(&format!(
            "vless://{UUID}@example.com:443?type=xhttp&{a}&{different}"
        ))
        .is_err()
    );
}

#[test]
fn xhttp_h2_validation_preserves_plain_tls_reality_and_vless_path_policy() {
    for security in [
        "security=none",
        "security=tls",
        "security=reality&pbk=test-key",
    ] {
        let node = link(&format!("type=xhttp&alpn=h2&{security}"));
        node.validate().unwrap();
    }
    for query in [
        "type=xhttp&mux=xray&concurrency=8",
        "type=xhttp&flow=xtls-rprx-vision",
    ] {
        assert!(Node::from_share_link(&format!("vless://{UUID}@example.com:443?{query}")).is_err());
    }
    link("type=xhttp&mux=xray&concurrency=-1&xudpConcurrency=4")
        .validate()
        .unwrap();
    link("type=xhttp&flow=xtls-rprx-vision&encryption=mlkem768x25519plus.test")
        .validate()
        .unwrap();
    for transport in ["tcp", "ws", "grpc"] {
        let mut node = link(&format!("type={transport}"));
        node.tls_mut().unwrap().alpn = vec!["h2".into()];
        assert_eq!(node.validate_protocol().is_ok(), transport == "tcp");
    }
}

#[test]
fn vmess_json_preserves_xhttp_top_fields_and_supported_extra() {
    let mut fixture = json!({"v":"2","ps":"vmess","add":"example.com","port":443,"id":UUID,
        "net":"splithttp","tls":"tls","host":"front.example","sni":"tls.example","path":"api",
        "mode":"stream-one","alpn":"h2", "extra":{"xPaddingBytes":"123-456","noGRPCHeader":true}});
    let parse = |fixture: &Value| {
        Node::from_share_link(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(fixture.to_string())
        ))
    };
    let node = parse(&fixture).unwrap();
    let options = node.transport().unwrap().xhttp.as_ref().unwrap();
    assert_eq!(options.path, "/api/");
    assert_eq!(options.host.as_deref(), Some("front.example"));
    assert_eq!(options.mode, XhttpMode::StreamOne);
    assert!(options.no_grpc_header);
    assert_eq!(options.x_padding_bytes, XhttpRange { min: 123, max: 456 });
    assert_eq!(node.tls().unwrap().sni.as_deref(), Some("tls.example"));
    fixture["extra"]["downloadSettings"] = Value::Null;
    assert!(parse(&fixture).is_err());
    fixture["extra"] = json!({});
    fixture["alpn"] = json!("http/1.1");
    assert!(parse(&fixture).is_err());
    fixture["alpn"] = json!("h2");
    fixture["extra"] = json!("{\"noGRPCHeader\":true}");
    assert!(
        parse(&fixture)
            .unwrap()
            .transport()
            .unwrap()
            .xhttp
            .as_ref()
            .unwrap()
            .no_grpc_header
    );
    for extra in [
        Value::Null,
        json!(""),
        json!({"unknown":null}),
        json!({"headers":null}),
        json!({"noGRPCHeader":null}),
    ] {
        fixture["extra"] = extra;
        assert!(parse(&fixture).is_err());
    }
    let duplicate = format!(
        r#"{{"ps":"vmess","add":"example.com","port":443,"id":"{UUID}","net":"xhttp","extra":{{"downloadSettings":null}},"extra":{{}}}}"#
    );
    assert!(
        Node::from_share_link(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(duplicate)
        ))
        .is_err()
    );
}

#[test]
fn duplicate_json_claims_cannot_hide_invalid_xhttp_inputs() {
    for extra in [
        r#"{"noGRPCHeader":null,"noGRPCHeader":false}"#,
        r#"{"host":"front.example","host":"front.example"}"#,
        r#"{"path":"api","path":"/api/"}"#,
        r#"{"mode":"auto","mode":"auto"}"#,
        r#"{"headers":{"x-a":"one","x-a":"two"}}"#,
        r#"{"headers":{"x-a":"one","x-a":"one"}}"#,
        r#"[{},100,false,1000000,30]"#,
        r#"{"xPaddingBytes":{"min":0,"min":100,"max":1000}}"#,
    ] {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("extra", extra)
            .finish();
        assert!(
            Node::from_share_link(&format!(
                "vless://{UUID}@example.com:443?type=xhttp&{query}"
            ))
            .is_err()
        );
        for encoded in [false, true] {
            let extra = if encoded {
                serde_json::to_string(extra).unwrap()
            } else {
                extra.into()
            };
            let payload = format!(
                r#"{{"ps":"duplicate","add":"example.com","port":443,"id":"{UUID}","net":"xhttp","extra":{extra}}}"#
            );
            assert!(
                Node::from_share_link(&format!(
                    "vmess://{}",
                    base64::engine::general_purpose::STANDARD.encode(payload)
                ))
                .is_err()
            );
        }
    }
    for headers in [
        r#"{"x-a":"one","x-a":"two"}"#,
        r#"{"x-a":null,"x-a":"two"}"#,
    ] {
        let input = format!(
            r#"{{"name":"flat","protocol":"vless","address":"example.com:443","host":"example.com","port":443,"password":"{UUID}","transport":"xhttp","xhttp":{{"headers":{headers}}}}}"#
        );
        assert!(serde_json::from_str::<Node>(&input).is_err());
    }
    for options in [
        r#"{"x_padding_bytes":{"min":0,"min":100,"max":1000}}"#,
        r#"{"x_padding_bytes":100,"x-padding-bytes":100}"#,
    ] {
        let input = format!(
            r#"{{"name":"flat","protocol":"vless","address":"example.com:443","host":"example.com","port":443,"password":"{UUID}","transport":"xhttp","xhttp":{options}}}"#
        );
        assert!(serde_json::from_str::<Node>(&input).is_err());
    }
}

#[test]
fn direct_alias_must_normalize_before_config_admission() {
    let mut node = link("type=xhttp");
    node.transport_mut().unwrap().transport = "splithttp".into();
    assert!(node.validate_protocol().is_err());
    assert!(
        honk_config::Config {
            nodes: vec![node.clone()],
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    node.normalize_stream_transport().unwrap();
    node.id = node.derive_id();
    honk_config::Config {
        nodes: vec![node],
        ..Default::default()
    }
    .validate()
    .unwrap();
}

#[test]
fn direct_alpn_must_normalize_before_config_admission() {
    let canonical = link("type=xhttp");
    for alpn in [vec![], vec!["h2".into(), "h2".into()]] {
        let mut node = canonical.clone();
        node.tls_mut().unwrap().alpn = alpn;
        node.id = node.derive_id();
        assert!(node.validate_protocol().is_err());
        assert!(
            honk_config::Config {
                nodes: vec![node.clone()],
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        node.normalize_stream_transport().unwrap();
        assert_eq!(node.tls().unwrap().alpn, ["h2"]);
        node.id = node.derive_id();
        assert_eq!(node.id, canonical.id);
        honk_config::Config {
            nodes: vec![node],
            ..Default::default()
        }
        .validate()
        .unwrap();
    }
    for alpn in [
        vec!["http/1.1".into()],
        vec!["h2".into(), "http/1.1".into()],
    ] {
        let mut node = canonical.clone();
        node.tls_mut().unwrap().alpn = alpn;
        assert!(node.validate_protocol().is_err());
        assert_eq!(
            node.normalize_stream_transport(),
            Err("XHTTP requires H2-only ALPN")
        );
    }
}

#[test]
fn direct_options_must_normalize_before_config_admission() {
    for options in [
        XhttpOptions {
            path: "/api?token=a%2Fb".into(),
            ..Default::default()
        },
        XhttpOptions {
            headers: [("X-A".into(), "one".into())].into(),
            ..Default::default()
        },
    ] {
        let mut node = link("type=xhttp");
        node.transport_mut().unwrap().xhttp = Some(options);
        node.id = node.derive_id();
        assert!(
            honk_config::Config {
                nodes: vec![node.clone()],
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        node.normalize_stream_transport().unwrap();
        node.id = node.derive_id();
        honk_config::Config {
            nodes: vec![node],
            ..Default::default()
        }
        .validate()
        .unwrap();
    }
    let mut node = link("type=xhttp");
    node.transport_mut()
        .unwrap()
        .xhttp
        .as_mut()
        .unwrap()
        .headers = [("X-A".into(), "one".into()), ("x-a".into(), "two".into())].into();
    node.id = node.derive_id();
    assert!(node.validate_protocol().is_err());
    assert!(node.normalize_stream_transport().is_err());
}

#[test]
fn vmess_xhttp_tls_posture_has_distinct_reload_identity() {
    let mut fixture =
        json!({"ps":"posture","add":"example.com","port":443,"id":UUID,"net":"xhttp"});
    let parse = |fixture: &Value| {
        Node::from_share_link(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(fixture.to_string())
        ))
        .unwrap()
    };
    let plain = parse(&fixture);
    fixture["tls"] = json!("tls");
    let tls = parse(&fixture);
    assert_ne!(plain.id, tls.id);
    assert_ne!(plain.derive_id(), tls.derive_id());
    let config = honk_config::Config {
        nodes: vec![plain, tls],
        ..Default::default()
    };
    config.validate().unwrap();
}

#[test]
fn nonstream_uri_protocols_reject_xhttp_claims_instead_of_discarding_them() {
    for base in [
        "socks5://user:password@example.com:1080",
        "ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388",
        "anytls://password@example.com:443",
        "hysteria2://password@example.com:443",
        "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:password@example.com:443",
        "juicity://b831381d-6324-4d53-ad4f-8cda48b30811:password@example.com:443",
    ] {
        Node::from_share_link(base).unwrap();
        for query in [
            "type=xhttp",
            "network=splithttp",
            "type=xhttp&extra=%7B%7D",
        ] {
            let mut diagnostics = Vec::new();
            let error = Node::from_share_link_with_detailed_diagnostics(
                &format!("{base}?{query}"),
                &mut diagnostics,
            )
            .unwrap_err();
            assert_eq!(error.diagnostic.setting.to_string(), "nodes.xhttp");
            assert_eq!(error.diagnostic.code, "invalid-config-value");
        }
    }
}
