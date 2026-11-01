use honk_config::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SafeValue, SettingPath, finish_attempt,
};
use honk_config::error::{DetailedConfigError, ErrorCategory};

#[test]
fn failure_preserves_prefix_and_has_one_safe_terminal() {
    let first = DiagnosticSources::new(None);
    let second = DiagnosticSources::new(None);
    let prefix = DetailedDiagnostic::warning(
        "invalid-scalar",
        first.root(),
        SettingPath::new("global").field("check_tolerance"),
        SafeValue::Redacted,
        "invalid duration; keeping the default",
    );
    let mut diagnostics = vec![prefix.clone()];
    let error = DetailedConfigError::new(
        ErrorCategory::Parse,
        "invalid-value",
        second.root(),
        SettingPath::new("dns").field("client_subnet"),
        "invalid value",
    );
    let result: Result<(), _> = finish_attempt(Err(error), &mut diagnostics);
    let error = result.unwrap_err();
    assert_eq!(diagnostics[0], prefix);
    assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
    assert!(!diagnostics[0].source.same_source(&diagnostics[1].source));
    assert!(matches!(
        error.into_legacy(),
        honk_config::ConfigError::Parse(_)
    ));
    assert_eq!(diagnostics[0].to_legacy().value, "<redacted>");
}

#[test]
fn legacy_fallbacks_name_the_field_and_expected_form_but_not_the_value() {
    let sources = DiagnosticSources::new(None);
    let validation = |text: &str| honk_config::ConfigError::Validation(text.into());
    for (original, setting, message) in [
        (
            validation("global.dial_mode PRIVATE"),
            "global.dial_mode",
            "expected ip, domain, domain+, or domain++",
        ),
        (
            validation("global.data_dir PRIVATE"),
            "global.data_dir",
            "expected a non-empty absolute path",
        ),
        (
            validation("global.check_interval PRIVATE"),
            "global.check_interval",
            "expected a positive duration",
        ),
        (
            validation("global.tproxy_mark PRIVATE"),
            "global.tproxy_mark",
            "expected the compiled datapath mark",
        ),
        (
            validation("global.so_mark_from_dae PRIVATE"),
            "global.so_mark_from_dae",
            "expected a mark clear of datapath-reserved and TPROXY bits",
        ),
        (
            validation("invalid dns.bind \"PRIVATE\": invalid host"),
            "dns.bind",
            "expected IP:port or a udp://, tcp:// or tcp+udp:// host:port",
        ),
        (
            honk_config::ConfigError::UnknownProtocol("PRIVATE".into()),
            "nodes.protocol",
            "unknown node protocol; expected ss, trojan, vmess, vless, socks5, hysteria2, tuic, juicity, anytls, direct or block",
        ),
        (
            honk_config::ConfigError::UnsupportedPolicy("PRIVATE".into()),
            "groups.policy",
            "unsupported group policy; expected selector, urltest, loadbalance, fallback or score",
        ),
        (
            honk_config::ConfigError::Parse("PRIVATE".into()),
            "config",
            "invalid configuration",
        ),
    ] {
        let error = DetailedConfigError::from_legacy(original, sources.root());
        assert_eq!(
            (
                error.diagnostic.setting.to_string().as_str(),
                error.diagnostic.message
            ),
            (setting, message)
        );
        assert!(!format!("{error:?} {error}").contains("PRIVATE"));
    }
}

#[test]
fn parser_errors_name_the_entry_being_read() {
    for (input, code, setting) in [
        (
            "group {\n PRIVATE_GROUP {\n  policy: honk\n }\n}\n",
            "unsupported-policy",
            "groups[1].policy",
        ),
        (
            "group {\n first {\n  policy: selector\n }\n PRIVATE_GROUP {\n  icon: PRIVATE\n }\n}\n",
            "invalid-config-value",
            "groups[2].icon",
        ),
        (
            "node {\n first: 'socks5://192.0.2.1:1080'\n PRIVATE: 'ssr://PRIVATE@192.0.2.2:1'\n}\n",
            "unknown-protocol",
            "nodes[2].protocol",
        ),
        ("routing {\n PRIVATE)\n}\n", "config-parse", "routing"),
    ] {
        let error =
            honk_config::parser::parse_dae_config_with_detailed_diagnostics(input, &mut Vec::new())
                .unwrap_err();
        assert_eq!(
            (error.diagnostic.code, error.diagnostic.setting.to_string()),
            (code, setting.to_owned()),
            "{input}"
        );
        assert!(!format!("{error:?}").contains("PRIVATE"));
    }
}

#[test]
fn ignored_blocks_and_dns_keys_list_the_valid_names() {
    let mut diagnostics = Vec::new();
    honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        "PRIVATE_BLOCK {\n}\ndns {\n PRIVATE_KEY: 1\n PRIVATE_STATEMENT\n}\n",
        &mut diagnostics,
    )
    .unwrap();
    let message = |code: &str| {
        diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("{code}: {diagnostics:?}"))
            .message
    };
    let block = message("unknown-block");
    for root in honk_config::parser::cursor::Root::ALL {
        assert!(block.contains(root.name()), "{block}");
    }
    assert!(message("unknown-key").contains("max_cache_size"));
    assert!(message("unknown-statement").contains("fixed_domain_ttl"));
    assert!(!format!("{diagnostics:?}").contains("PRIVATE"));
}

#[test]
fn source_metadata_retains_include_ancestry_without_input() {
    let sources = DiagnosticSources::new(Some("entry.dae".into()));
    let child = sources.add(Some("child.dae".into()), Some(0));
    let decoded = sources.add(None, Some(child.index()));
    assert_eq!(decoded.index(), 2);
    assert_eq!(sources.metadata()[2].parent, Some(1));
    assert_eq!(
        sources.metadata()[1].path.as_deref(),
        Some(std::path::Path::new("child.dae"))
    );
    assert!(sources.root().same_table(&decoded));
}

#[test]
fn legacy_error_projection_preserves_every_category_without_payload() {
    let sources = DiagnosticSources::new(None);
    let errors = [
        honk_config::ConfigError::Io(std::io::Error::other("secret")),
        honk_config::ConfigError::Parse("secret".into()),
        honk_config::ConfigError::Parse("unsupported VLESS share-link parameter 'secret'".into()),
        honk_config::ConfigError::Parse("duplicate VLESS share-link parameter 'secret'".into()),
        honk_config::ConfigError::Parse("VLESS parameter 'secret' is inactive with mux=off".into()),
        honk_config::ConfigError::Parse("VLESS parameter 'secret' requires mux=xray".into()),
        honk_config::ConfigError::Parse("duplicate VLESS share-link parameter 'mux' secret".into()),
        honk_config::ConfigError::Include("secret".into()),
        honk_config::ConfigError::Validation("secret".into()),
        honk_config::ConfigError::Serialization("secret".into()),
        honk_config::ConfigError::UnknownProtocol("secret".into()),
        honk_config::ConfigError::UnsupportedPolicy("secret".into()),
    ];
    for original in errors {
        let category = ErrorCategory::of(&original);
        let detailed = DetailedConfigError::from_legacy(original, sources.root());
        if category == ErrorCategory::Parse {
            assert_eq!(detailed.diagnostic.code, "config-parse");
            assert_eq!(detailed.diagnostic.setting.to_string(), "config");
        }
        assert!(!format!("{detailed:?} {detailed}").contains("secret"));
        let legacy = detailed.into_legacy();
        assert_eq!(ErrorCategory::of(&legacy), category);
        assert!(!format!("{legacy:?} {legacy}").contains("secret"));
    }
}

#[test]
fn collection_admission_preserves_the_intrinsic_field_and_cause() {
    let mut node = honk_config::node::Node::from_share_link(
    "vless://00000000-0000-0000-0000-000000000001@example.invalid:443?security=tls&flow=xtls-rprx-vision",
)
.unwrap();
    node.vless_mut().unwrap().tls.enabled = false;
    node.id = node.derive_id();
    let config = honk_config::Config {
        nodes: vec![node],
        ..Default::default()
    };
    let error = config.validate_detailed().unwrap_err();
    assert_eq!(error.diagnostic.setting.to_string(), "nodes[1].flow");
    assert_eq!(error.diagnostic.code, "invalid-config-value");
    assert_eq!(error.diagnostic.entry_index, Some(1));
}

#[test]
fn routing_admission_identifies_the_invalid_target_without_echoing_it() {
    let mut config = honk_config::Config::default();
    config.routing.default_outbound = "PRIVATE_TARGET".into();
    let error = config.validate_detailed().unwrap_err();
    assert_eq!(error.diagnostic.setting.to_string(), "routing.fallback");
    assert_eq!(error.diagnostic.code, "unknown-routing-target");
    assert!(!format!("{error:?}{error}").contains("PRIVATE_TARGET"));
}

#[test]
fn included_semantic_error_retains_the_winning_field_source() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.dae");
    let child = dir.path().join("child.dae");
    std::fs::write(
        &root,
        "global {\n tproxy_port: 12345\n}\ninclude {\n child.dae\n}\n",
    )
    .unwrap();
    std::fs::write(&child, "global {\n nfqueue_enable: PRIVATE_INVALID\n}\n").unwrap();
    let mut diagnostics = Vec::new();
    let error = honk_config::Config::from_file_with_detailed_diagnostics(
        root.to_str().unwrap(),
        &mut diagnostics,
    )
    .unwrap_err();
    assert_eq!(
        error.diagnostic.setting.to_string(),
        "global.nfqueue_enable"
    );
    assert_eq!(error.diagnostic.line, Some(2));
    let source = &error.diagnostic.source;
    assert_eq!(
        source.sources().metadata()[source.index()].path.as_ref(),
        Some(&child)
    );
    assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
    assert!(!format!("{diagnostics:?}{error}").contains("PRIVATE_INVALID"));
}

#[test]
fn structured_node_failure_retains_its_semantic_field() {
    let node = honk_config::node::Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.invalid:443?security=tls",
    )
    .unwrap();
    let mut value = serde_json::to_value(node).unwrap();
    let mut invalid_transport = value.clone();
    invalid_transport["transport"] = serde_json::json!("PRIVATE_INVALID");
    let mut invalid_headers = value.clone();
    invalid_headers["transport"] = serde_json::json!("ws");
    invalid_headers["ws_headers"] = serde_json::json!({"Host": "PRIVATE_INVALID"});
    let mut conflicting_headers = value.clone();
    conflicting_headers["transport"] = serde_json::json!("ws");
    conflicting_headers["ws_headers"] =
        serde_json::json!({"X-Test": "PRIVATE_INVALID", "x-test": "different"});
    let mut xhttp_headers = value.clone();
    xhttp_headers["transport"] = serde_json::json!("xhttp");
    xhttp_headers["xhttp"] = serde_json::json!({"headers": {"Host": "PRIVATE_INVALID"}});
    let mut null_headers = value.clone();
    null_headers["transport"] = serde_json::json!("ws");
    null_headers["ws_headers"] = serde_json::Value::Null;
    let mut typed_headers = value.clone();
    typed_headers["transport"] = serde_json::json!("ws");
    typed_headers["ws_headers"] = serde_json::json!({"PRIVATE_INVALID": false});
    value["flow"] = serde_json::json!("PRIVATE_INVALID");
    let alias_conflict = serde_json::json!({
        "name": "tuic",
        "protocol": "tuic",
        "address": "example.invalid:443",
        "host": "example.invalid",
        "port": 443,
        "tuic_uuid": "00000000-0000-0000-0000-000000000001",
        "username": "PRIVATE_INVALID",
        "tuic_password": "secret",
    });
    for (node, setting) in [
        (value, "nodes[1].flow"),
        (alias_conflict, "nodes[1].tuic_uuid"),
        (invalid_transport, "nodes[1].transport"),
        (invalid_headers, "nodes[1].ws_headers"),
        (conflicting_headers, "nodes[1].ws_headers"),
        (xhttp_headers, "nodes[1].xhttp"),
        (null_headers, "nodes[1].ws_headers"),
        (typed_headers, "nodes[1].ws_headers"),
    ] {
        let body = serde_json::json!({"nodes": [node]}).to_string();
        let mut diagnostics = Vec::new();
        let error =
            honk_config::Config::from_json_str_with_detailed_diagnostics(&body, &mut diagnostics)
                .unwrap_err();
        assert_eq!(error.diagnostic.setting.to_string(), setting);
        assert_eq!(error.diagnostic.entry_index, Some(1));
        assert!(error.diagnostic.line.is_some());
        assert!(!format!("{diagnostics:?}{error}").contains("PRIVATE_INVALID"));
    }
}

#[test]
fn node_entry_diagnostics_keep_coordinates_before_intrinsic_validation() {
    let first = " skip_cert_verify: 'socks5://127.0.0.1:1080'\n";
    let remaining = concat!(
        " warning: 'trojan://PRIVATE@example.invalid:443?insecure=yes'\n",
        " bad: 'ssr://PRIVATE@example.invalid:443'\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.dae");
    let child = dir.path().join("child.dae");
    std::fs::write(
        &root,
        format!("node {{\n{first}}}\ninclude {{\n child.dae\n}}\n"),
    )
    .unwrap();
    std::fs::write(&child, format!("node {{\n{remaining}}}\n")).unwrap();

    for included in [false, true] {
        let mut diagnostics = Vec::new();
        let error = if included {
            honk_config::Config::from_file_with_detailed_diagnostics(
                root.to_str().unwrap(),
                &mut diagnostics,
            )
        } else {
            honk_config::parser::parse_dae_config_with_detailed_diagnostics(
                &format!("node {{\n{first}{remaining}}}\n"),
                &mut diagnostics,
            )
        }
        .unwrap_err();
        assert_eq!(error.diagnostic.code, "unknown-protocol");
        assert_eq!(error.diagnostic.line, Some(if included { 3 } else { 4 }));
        assert_eq!(error.diagnostic.entry_index, Some(3));
        assert_eq!(error.diagnostic.setting.to_string(), "nodes[3].protocol");
        let source_text = if included {
            format!("node {{\n{remaining}}}\n")
        } else {
            format!("node {{\n{first}{remaining}}}\n")
        };
        assert_eq!(
            &source_text[error.diagnostic.span.clone().unwrap()],
            "bad: 'ssr://PRIVATE@example.invalid:443'"
        );
        let warning = diagnostics
            .iter()
            .find(|d| d.code == "legacy-config-warning")
            .unwrap();
        assert_eq!(warning.line, Some(if included { 2 } else { 3 }));
        assert_eq!(warning.entry_index, Some(2));
        assert_eq!(warning.setting.to_string(), "nodes[2].skip_cert_verify");
        assert_eq!(
            &source_text[warning.span.clone().unwrap()],
            "warning: 'trojan://PRIVATE@example.invalid:443?insecure=yes'"
        );
        for diagnostic in [warning, error.diagnostic.as_ref()] {
            assert_eq!(diagnostic.byte_column, Some(2));
            let source = &diagnostic.source;
            assert_eq!(
                source.sources().metadata()[source.index()].path.as_ref(),
                included.then_some(&child),
            );
        }
        assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
        assert!(!format!("{diagnostics:?}{error}").contains("PRIVATE"));
    }
}
