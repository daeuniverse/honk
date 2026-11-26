use honk_config::{Config, parser::parse_dae_config};

#[test]
fn defaults_and_both_address_families_survive_serialization() {
    let defaults = Config::default();
    assert!(!defaults.global.syslog_dns_enabled);
    assert!(!defaults.global.syslog_cee_enabled);
    assert!(defaults.global.syslog_addr.is_empty());
    assert!(defaults.global.syslog_hostname.is_empty());
    assert_eq!(defaults.global.syslog_app_name, "honk");
    for address in ["192.0.2.1:514", "[2001:db8::1]:514"] {
        let config = parse_dae_config(&format!(
            "global {{ syslog_dns_enabled: true\n syslog_addr: '{address}' }}"
        ))
        .unwrap();
        config.validate().unwrap();
        assert!(config.global.syslog_dns_enabled);
        assert_eq!(config.global.syslog_addr, address);
        let value = serde_json::to_value(&config).unwrap();
        let restored: Config = serde_json::from_value(value).unwrap();
        assert_eq!(restored.global, config.global);
    }
}

#[test]
fn enabled_requires_a_numeric_unicast_address_and_boolean() {
    for address in [
        "",
        "dns.example:514",
        "192.0.2.1",
        "192.0.2.1:0",
        "[::]:514",
        "224.0.0.1:514",
        "255.255.255.255:514",
        "[::ffff:224.0.0.1]:514",
    ] {
        let mut config = Config::default();
        config.global.syslog_dns_enabled = true;
        config.global.syslog_addr = address.into();
        assert!(config.validate().is_err(), "{address}");
    }
    assert!(parse_dae_config("global { syslog_dns_enabled: perhaps }").is_err());
}

#[test]
fn identity_fields_parse_and_validate_without_header_injection() {
    let config = parse_dae_config(
        "global { syslog_hostname: 'router.example'\n syslog_app_name: 'dns-audit' }",
    )
    .unwrap();
    config.validate().unwrap();
    assert_eq!(config.global.syslog_hostname, "router.example");
    assert_eq!(config.global.syslog_app_name, "dns-audit");
    let decoded: Config = serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
    assert_eq!(decoded.global, config.global);
    for (host, app) in [
        ("h".repeat(255), "a".repeat(48)),
        (String::new(), "honk".into()),
    ] {
        let mut config = Config::default();
        config.global.syslog_hostname = host;
        config.global.syslog_app_name = app;
        config.validate().unwrap();
    }
    for invalid in [
        "with space",
        " leading",
        "trailing ",
        "a\nb",
        "a\rb",
        "a\tb",
        "a\0b",
        "\u{7f}",
        "路由器",
    ] {
        for host_field in [true, false] {
            let mut config = Config::default();
            let field = if host_field {
                &mut config.global.syslog_hostname
            } else {
                &mut config.global.syslog_app_name
            };
            *field = invalid.into();
            assert!(config.validate().is_err(), "{invalid:?}");
        }
    }
    for (host, app) in [
        ("h".repeat(256), "honk".into()),
        (String::new(), "a".repeat(49)),
        (String::new(), String::new()),
    ] {
        let mut config = Config::default();
        config.global.syslog_hostname = host;
        config.global.syslog_app_name = app;
        assert!(config.validate().is_err());
    }
    assert!(
        parse_dae_config("global { syslog_app_name: 'two apps' }")
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn cee_setting_is_a_boolean_and_defaults_to_plain_json() {
    let defaults = serde_json::to_value(Config::default()).unwrap();
    assert_eq!(defaults["global"]["syslog_cee_enabled"], false);
    for (raw, expected) in [
        ("false", false),
        ("true", true),
        ("off", false),
        ("on", true),
    ] {
        let config = parse_dae_config(&format!("global {{ syslog_cee_enabled: {raw} }}")).unwrap();
        config.validate().unwrap();
        let encoded = serde_json::to_value(&config).unwrap();
        assert_eq!(encoded["global"]["syslog_cee_enabled"], expected);
        let restored: Config = serde_json::from_value(encoded).unwrap();
        assert_eq!(restored.global, config.global);
    }
    for raw in ["perhaps", "null", "''"] {
        assert!(parse_dae_config(&format!("global {{ syslog_cee_enabled: {raw} }}")).is_err());
    }
    for value in [
        serde_json::json!("false"),
        serde_json::json!(0),
        serde_json::Value::Null,
    ] {
        assert!(
            serde_json::from_value::<Config>(
                serde_json::json!({"global":{"syslog_cee_enabled":value}})
            )
            .is_err()
        );
    }
}

#[test]
fn removed_dns_syslog_format_settings_are_rejected_by_presence() {
    let keys = ["syslog_dns_template", "syslog_dns_json"];
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("removed-syslog.json");
    let encoded = serde_json::to_value(Config::default()).unwrap();
    for key in keys {
        assert!(encoded["global"].get(key).is_none());
        for value in ["'private-template-value'", "''", "false", "null"] {
            let error = parse_dae_config(&format!("global {{ {key}: {value} }}"))
                .unwrap_err()
                .to_string();
            assert!(error.contains("fixed JSON schema"), "{key}: {error}");
            assert!(!error.contains("private-template-value"));
        }
        for value in [
            serde_json::json!("private-template-value"),
            serde_json::json!(""),
            serde_json::json!(false),
            serde_json::Value::Null,
        ] {
            let mut global = serde_json::json!({});
            global[key] = value;
            let error = serde_json::from_value::<honk_config::config::GlobalConfig>(global.clone())
                .unwrap_err()
                .to_string();
            assert!(error.contains("fixed JSON schema"), "{key}: {error}");
            assert!(!error.contains("private-template-value"));
            let input = serde_json::json!({"global": global});
            assert!(serde_json::from_value::<Config>(input.clone()).is_err());
            let input = input.to_string();
            assert!(Config::from_json_str(&input).is_err());
            std::fs::write(&file, input).unwrap();
            assert!(Config::from_file(file.to_str().unwrap()).is_err());
        }
    }
}
