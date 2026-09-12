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
        honk_config::ConfigError::Include("secret".into()),
        honk_config::ConfigError::Validation("secret".into()),
        honk_config::ConfigError::Serialization("secret".into()),
        honk_config::ConfigError::UnknownProtocol("secret".into()),
        honk_config::ConfigError::UnsupportedPolicy("secret".into()),
    ];
    for original in errors {
        let category = ErrorCategory::of(&original);
        let detailed = DetailedConfigError::from_legacy(original, sources.root());
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
        assert_eq!(error.diagnostic.setting.to_string(), "nodes[3]");
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
