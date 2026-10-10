mod parser_warnings {
    use honk_config::parser::parse_dae_config_with_diagnostics;

    #[test]
    fn parser_returns_node_skip_and_legacy_nfqueue_warnings_as_safe_data() {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_diagnostics(
            include_str!("fixtures/diagnostic_warnings.dae"),
            &mut diagnostics,
        )
        .unwrap();
        assert!(config.nodes.is_empty());
        assert!(!config.global.nfqueue_enable);
        assert_eq!(config.global.check_tolerance_ms, 50);
        assert_eq!(diagnostics.len(), 3, "{diagnostics:?}");
        assert!(!format!("{diagnostics:?}").contains("secret"));
    }
    #[test]
    fn dns_unsupported_conditions_are_safe_data_on_success() {
        let input = include_str!("fixtures/dns_unsupported_condition.dae");

        let mut detailed = Vec::new();
        let config =
            honk_config::parser::parse_dae_config_with_detailed_diagnostics(input, &mut detailed)
                .unwrap();
        assert_eq!(config.dns.routing.request.rules.len(), 1);
        assert_eq!(config.dns.routing.response.rules.len(), 1);

        let warnings = detailed
            .iter()
            .filter(|diagnostic| diagnostic.code == "unsupported-dns-condition")
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 2, "{detailed:?}");
        assert_eq!(
            warnings[0].setting.to_string(),
            "dns.routing.request.rules[1]"
        );
        assert_eq!(warnings[0].entry_index, Some(1));
        assert_eq!(warnings[0].line, Some(4));
        assert_eq!(
            warnings[1].setting.to_string(),
            "dns.routing.response.rules[1]"
        );
        assert_eq!(warnings[1].entry_index, Some(1));
        assert_eq!(warnings[1].line, Some(8));
        assert!(!format!("{detailed:?}").contains("PRIVATE_"));

        let mut legacy = Vec::new();
        honk_config::parser::parse_dae_config_with_diagnostics(input, &mut legacy).unwrap();
        assert_eq!(legacy.len(), 2, "{legacy:?}");
        assert!(legacy.iter().all(|diagnostic| {
            diagnostic.setting.ends_with(".rules[1]")
                && diagnostic.value == "1"
                && !diagnostic.message.contains("PRIVATE_")
        }));
        assert!(!format!("{legacy:?}").contains("PRIVATE_"));
    }

    #[test]
    fn dns_unsupported_conditions_are_retained_before_failure() {
        let input = include_str!("fixtures/dns_unsupported_condition_failure.dae");

        let mut detailed = Vec::new();
        let error =
            honk_config::parser::parse_dae_config_with_detailed_diagnostics(input, &mut detailed)
                .unwrap_err();
        assert!(detailed.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-dns-condition"
                && diagnostic.setting.to_string() == "dns.routing.request.rules[1]"
        }));
        assert!(detailed.iter().any(|diagnostic| {
            diagnostic.code == "unsupported-dns-condition"
                && diagnostic.setting.to_string() == "dns.routing.response.rules[1]"
        }));
        assert!(detailed.iter().any(|diagnostic| diagnostic.terminal));
        assert!(!format!("{detailed:?}").contains("PRIVATE_"));
        assert!(!format!("{error:?}").contains("PRIVATE_"));

        let mut legacy = Vec::new();
        let error =
            honk_config::parser::parse_dae_config_with_diagnostics(input, &mut legacy).unwrap_err();
        assert_eq!(
            legacy
                .iter()
                .filter(|diagnostic| diagnostic.setting.ends_with(".rules[1]"))
                .count(),
            2
        );
        assert!(!format!("{legacy:?}").contains("PRIVATE_"));
        assert!(!format!("{error:?}").contains("PRIVATE_"));
    }

    #[test]
    fn misplaced_experimental_keys_are_named_by_schema_name_only() {
        let native = "native API setting belongs inside native_api { }";
        let unknown = "unknown experimental setting";
        let nfqueue = "unknown NFQUEUE setting; only enabled is supported";
        for (input, code, setting, message) in [
            (
                "experimental {\n config_write: true\n}\n",
                "unknown-experimental-setting",
                "experimental.config_write",
                native,
            ),
            (
                "experimental {\n record_logs: false\n}\n",
                "unknown-experimental-setting",
                "experimental.record_logs",
                native,
            ),
            (
                "experimental {\n external_ui: PRIVATE_UI\n}\n",
                "unknown-experimental-setting",
                "experimental.external_ui",
                "clash API setting belongs inside clash_api { }",
            ),
            (
                "experimental {\n store_dns: true\n}\n",
                "unknown-experimental-setting",
                "experimental.store_dns",
                "cache file setting belongs inside cache_file { }",
            ),
            (
                "experimental {\n secret: PRIVATE_SECRET\n}\n",
                "unknown-experimental-setting",
                "experimental.secret",
                unknown,
            ),
            (
                "experimental {\n enabled: true\n}\n",
                "unknown-experimental-setting",
                "experimental.enabled",
                unknown,
            ),
            (
                "experimental {\n nfqueue_enable: true\n}\n",
                "unknown-experimental-setting",
                "experimental.nfqueue_enable",
                unknown,
            ),
            (
                "experimental {\n PRIVATE_KEY: true\n}\n",
                "unknown-experimental-setting",
                "experimental",
                unknown,
            ),
            (
                "experimental {\n PRIVATE_BLOCK {\n }\n}\n",
                "unknown-experimental-setting",
                "experimental",
                unknown,
            ),
            (
                "experimental {\n native_api {\n external_ui: PRIVATE_UI\n }\n}\n",
                "unknown-native-api-setting",
                "experimental.native_api.external_ui",
                "unknown native API setting",
            ),
            (
                "experimental {\n native_api {\n PRIVATE_KEY: true\n }\n}\n",
                "unknown-native-api-setting",
                "experimental.native_api",
                "unknown native API setting",
            ),
            (
                "experimental {\n udp_nfqueue {\n nfqueue_enable: true\n }\n}\n",
                "unknown-nfqueue-setting",
                "experimental.udp_nfqueue.nfqueue_enable",
                nfqueue,
            ),
            (
                "experimental {\n udp_nfqueue {\n PRIVATE_KEY: true\n }\n}\n",
                "unknown-nfqueue-setting",
                "experimental.udp_nfqueue",
                nfqueue,
            ),
        ] {
            let mut detailed = Vec::new();
            let error = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
                input,
                &mut detailed,
            )
            .unwrap_err();
            assert_eq!(
                (
                    error.diagnostic.code,
                    error.diagnostic.setting.to_string().as_str(),
                    error.diagnostic.message,
                ),
                (code, setting, message),
                "{input}"
            );
            assert!(!format!("{error:?} {detailed:?}").contains("PRIVATE_"));
        }
    }

    #[test]
    fn removed_settings_retain_safe_migration_causes() {
        for (input, path, code, replacement) in [
            (
                include_str!("fixtures/removed_node_mux.dae"),
                "nodes.mux",
                "unsupported-node-mux",
                "mux",
            ),
            (
                include_str!("fixtures/removed_dns_hosts_file.dae"),
                "dns.hosts_file",
                "removed-dns-hosts-file",
                "use_host",
            ),
        ] {
            let mut diagnostics = Vec::new();
            let error = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
                input,
                &mut diagnostics,
            )
            .unwrap_err();
            assert_eq!(error.diagnostic.code, code);
            assert_eq!(error.diagnostic.setting.to_string(), path);
            assert!(error.diagnostic.message.contains(replacement));
            assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
            assert!(error.into_legacy().to_string().contains(replacement));
        }
    }
    #[test]
    fn removed_vless_mode_is_terminal_at_the_dae_entry() {
        let input = "node {\n edge: 'vless://b831381d-6324-4d53-ad4f-8cda48b30811@private.example:443?vless_mode=#PRIVATE'\n}";
        let mut diagnostics = Vec::new();
        let error = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
            input,
            &mut diagnostics,
        )
        .unwrap_err();
        assert_eq!(error.diagnostic.code, "removed-vless-mode");
        assert_eq!(error.diagnostic.setting.to_string(), "nodes[1].vless_mode");
        assert_eq!(error.diagnostic.entry_index, Some(1));
        assert!(!format!("{error:?} {diagnostics:?}").contains("PRIVATE"));
    }

    #[test]
    fn recoverable_vless_rejections_keep_reasons_and_entry_sources() {
        use honk_config::diagnostic::{SafeValue, Severity};

        let uri =
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@private.example:443?pbk=PRIVATE_KEY";
        let input = format!(
            "node {{\n keep: 'socks5://127.0.0.1:1080'\n PRIVATE_ALIAS: '{uri}&allowInsecure=yes&packet-encoding=PRIVATE_VALUE#PRIVATE_NAME'\n PRIVATE_TUNING: '{uri}&mux=xray&concurrency=PRIVATE_VALUE'\n PRIVATE_VISION: '{uri}&flow=xtls-rprx-vision&mux=h2mux'\n PRIVATE_DUPLICATE: '{uri}&mux=off&mux=off'\n malformed: 'PRIVATE_SYNTAX'\n}}\n"
        );
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root.dae");
        let child = dir.path().join("child.dae");
        std::fs::write(&root, "include { child.dae }\n").unwrap();
        std::fs::write(&child, &input).unwrap();

        for included in [false, true] {
            let mut diagnostics = Vec::new();
            let config = if included {
                honk_config::Config::from_file_with_detailed_diagnostics(
                    root.to_str().unwrap(),
                    &mut diagnostics,
                )
            } else {
                honk_config::parser::parse_dae_config_with_detailed_diagnostics(
                    &input,
                    &mut diagnostics,
                )
            }
            .unwrap();
            assert_eq!(
                config
                    .nodes
                    .iter()
                    .map(|node| node.name.as_str())
                    .collect::<Vec<_>>(),
                ["keep"]
            );
            assert_eq!(diagnostics.len(), 6, "{diagnostics:?}");
            for (diagnostic, (code, field, ordinal, reason)) in diagnostics.iter().zip([
                (
                    "legacy-config-warning",
                    "nodes[2].skip_cert_verify",
                    2,
                    "verification",
                ),
                (
                    "unsupported-vless-parameter",
                    "nodes[2].packet_encoding",
                    2,
                    "packetEncoding",
                ),
                (
                    "invalid-config-value",
                    "nodes[3].multiplex.tcp",
                    3,
                    "integer",
                ),
                ("invalid-config-value", "nodes[4].flow", 4, "path"),
                ("duplicate-vless-parameter", "nodes[5].multiplex", 5, "once"),
                ("invalid-node-entry", "nodes[6]", 6, "ignored"),
            ]) {
                assert_eq!(diagnostic.code, code);
                assert_eq!(diagnostic.setting.to_string(), field);
                assert!(diagnostic.message.contains(reason), "{diagnostic:?}");
                assert_eq!(diagnostic.entry_index, Some(ordinal));
                assert_eq!(diagnostic.line, Some(ordinal + 1));
                assert_eq!(diagnostic.byte_column, Some(2));
                assert_eq!(diagnostic.severity, Severity::Warning);
                assert!(!diagnostic.terminal);
                assert_eq!(diagnostic.value, SafeValue::Redacted);
                assert_eq!(
                    &input[diagnostic.span.clone().unwrap()],
                    input.lines().nth(ordinal).unwrap().trim(),
                );
                let source = &diagnostic.source;
                assert_eq!(
                    source.sources().metadata()[source.index()].path.as_ref(),
                    included.then_some(&child),
                );
                assert!(source.same_source(&diagnostics[0].source));
                let rendered = format!("{diagnostic:?} {:?}", diagnostic.to_legacy());
                for secret in [
                    "PRIVATE_",
                    "private.example",
                    "b831381d-6324-4d53-ad4f-8cda48b30811",
                ] {
                    assert!(!rendered.contains(secret));
                }
            }
        }
    }
}

mod config_loaders {
    use honk_config::diagnostic::SafeValue;
    use honk_config::{Config, ConfigDiagnostic};

    fn node_fixture() -> serde_json::Value {
        let mut node: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/node_incompatible.json")).unwrap();
        node.as_object_mut().unwrap().remove("tls_alpn");
        node
    }

    #[test]
    fn structured_loaders_preserve_prefix_and_return_node_warnings() {
        let root = serde_json::json!({"nodes": [node_fixture()]});
        let formats = [
            ("json", serde_json::to_string(&root).unwrap()),
            ("yaml", serde_yaml::to_string(&root).unwrap()),
            ("toml", toml::to_string(&root).unwrap()),
            ("dae", serde_json::to_string(&root).unwrap()),
        ];
        for (extension, text) in formats {
            let file = tempfile::Builder::new()
                .suffix(&format!(".{extension}"))
                .tempfile()
                .unwrap();
            std::fs::write(file.path(), text).unwrap();
            let prefix = ConfigDiagnostic {
                setting: "caller".into(),
                value: "prefix".into(),
                message: "keep".into(),
            };
            let mut diagnostics = vec![prefix.clone()];
            let config =
                Config::from_file_with_diagnostics(file.path().to_str().unwrap(), &mut diagnostics)
                    .unwrap();
            assert_eq!(config.nodes[0].host, "secret-endpoint");
            assert_eq!(diagnostics[0], prefix);
            assert_eq!(diagnostics.len(), 2, "{extension}: {diagnostics:?}");
            assert!(!format!("{:?}", &diagnostics[1..]).contains("secret"));
        }
    }

    #[test]
    fn structured_loaders_ignore_removed_native_destination_keys_with_warnings() {
        let root = serde_json::json!({"experimental": {"native_api": {
            "record_flows": false,
            "probe_allowed_cidrs": {"PRIVATE": false},
            "probe_allowed_ports": [0, 65536, "PRIVATE"]
        }}});
        for (extension, text) in [
            ("json", serde_json::to_string(&root).unwrap()),
            ("yaml", serde_yaml::to_string(&root).unwrap()),
            ("toml", toml::to_string(&root).unwrap()),
            ("dae", serde_json::to_string(&root).unwrap()),
        ] {
            let file = tempfile::Builder::new()
                .suffix(&format!(".{extension}"))
                .tempfile()
                .unwrap();
            std::fs::write(file.path(), text).unwrap();
            let mut diagnostics = Vec::new();
            let config = Config::from_file_with_detailed_diagnostics(
                file.path().to_str().unwrap(),
                &mut diagnostics,
            )
            .unwrap();
            assert!(!config.experimental.native_api.record_flows);
            assert_eq!(diagnostics.len(), 2, "{extension}: {diagnostics:?}");
            for key in ["probe_allowed_cidrs", "probe_allowed_ports"] {
                let notice = diagnostics
                    .iter()
                    .find(|notice| {
                        notice.setting.to_string() == format!("experimental.native_api.{key}")
                    })
                    .unwrap();
                assert_eq!(notice.code, "legacy-config-warning");
                assert_eq!(notice.severity, honk_config::diagnostic::Severity::Warning);
                assert!(
                    notice.message.contains("removed") && notice.message.contains("can be deleted")
                );
                assert!(!serde_json::to_string(&config).unwrap().contains(key));
            }
            assert!(!format!("{diagnostics:?}").contains("PRIVATE"));
        }
        let invalid = r#"{"experimental":{"native_api":{"record_flows":"PRIVATE"}}}"#;
        let error =
            Config::from_json_str_with_detailed_diagnostics(invalid, &mut Vec::new()).unwrap_err();
        assert_eq!(error.diagnostic.setting.to_string(), "experimental");
        let input = r#"{"experimental":{"native_api":{"probe_allowed_cidrs":null,"probe_allowed_ports":null}}}"#;
        let mut diagnostics = Vec::new();
        Config::from_json_str_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        assert_eq!(diagnostics.len(), 2);
        assert!(
            Config::from_json_str(r#"{"experimental":{"native_api":{"probe_allowed_port":[]}}}"#)
                .is_err()
        );
    }

    #[test]
    fn legacy_cache_file_keys_warn_in_dae_and_structured_input() {
        let dae = "experimental { cache_file { enabled: true\n path: 'cache.db' }\n cache_file { cache_id: 'gw' } }\n";
        let mut diagnostics = Vec::new();
        honk_config::parser::parse_dae_config_with_detailed_diagnostics(dae, &mut diagnostics)
            .unwrap();
        let warned = |diagnostics: &[honk_config::diagnostic::DetailedDiagnostic]| {
            diagnostics
                .iter()
                .filter(|d| d.code == "legacy-cache-file")
                .map(|d| d.setting.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            warned(&diagnostics),
            [
                "experimental.cache_file.path",
                "experimental.cache_file.cache_id"
            ]
        );

        let file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::fs::write(
            file.path(),
            "[experimental.cache_file]\nenabled = true\npath = \"cache.db\"\ncache_id = \"gw\"\n",
        )
        .unwrap();
        let mut diagnostics = Vec::new();
        let config = Config::from_file_with_detailed_diagnostics(
            file.path().to_str().unwrap(),
            &mut diagnostics,
        )
        .unwrap();
        assert_eq!(
            warned(&diagnostics),
            [
                "experimental.cache_file.path",
                "experimental.cache_file.cache_id"
            ]
        );
        assert_eq!(
            config.experimental.cache_file.legacy_cache_file(),
            (Some("cache.db"), Some("gw"))
        );
        let serialized = serde_json::to_value(&config.experimental.cache_file).unwrap();
        assert_eq!(
            serialized,
            serde_json::json!({"enabled": true, "store_dns": false})
        );
    }

    #[test]
    fn failed_fallback_retains_attempts_and_only_one_terminal() {
        let file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        std::fs::write(
            file.path(),
            include_str!("fixtures/config_failed_second_port.json"),
        )
        .unwrap();
        let mut diagnostics = Vec::new();
        Config::from_file_with_detailed_diagnostics(
            file.path().to_str().unwrap(),
            &mut diagnostics,
        )
        .unwrap_err();
        assert_eq!(
            diagnostics.iter().map(|d| d.code).collect::<Vec<_>>(),
            [
                "incompatible-node-fields",
                "invalid-structured-config",
                "invalid-structured-config",
                "incompatible-node-fields",
                "invalid-structured-config",
            ]
        );
        assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
        assert!(diagnostics.last().unwrap().terminal);
        let terminal = diagnostics.last().unwrap();
        assert_eq!(terminal.setting.to_string(), "nodes[2].port");
        assert_eq!(terminal.entry_index, Some(2));
        assert!(terminal.line.is_some());
        assert!(terminal.byte_column.is_some());
        assert_eq!(terminal.value, SafeValue::Redacted);
        assert!(diagnostics[0].source.same_table(&diagnostics[1].source));
        assert!(!diagnostics[1].source.same_table(&diagnostics[2].source));
        assert!(!format!("{diagnostics:?}").contains("private-port"));
    }

    #[test]
    fn failed_fallback_keeps_the_indexed_cause_over_later_syntax_errors() {
        let root: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/config_failed_second_port.json")).unwrap();
        for (extension, text) in [
            ("yaml", serde_yaml::to_string(&root).unwrap()),
            ("toml", toml::to_string(&root).unwrap()),
        ] {
            let file = tempfile::Builder::new()
                .suffix(&format!(".{extension}"))
                .tempfile()
                .unwrap();
            std::fs::write(file.path(), text).unwrap();
            let mut diagnostics = Vec::new();
            let error = Config::from_file_with_detailed_diagnostics(
                file.path().to_str().unwrap(),
                &mut diagnostics,
            )
            .unwrap_err();
            assert_eq!(error.diagnostic.setting.to_string(), "nodes[2].port");
            assert_eq!(error.diagnostic.entry_index, Some(2));
            assert!(error.diagnostic.line.is_some());
            let causes = diagnostics
                .iter()
                .filter(|d| d.code == "invalid-structured-config")
                .collect::<Vec<_>>();
            assert_eq!(causes.len(), 3, "{extension}: {diagnostics:?}");
            for (index, cause) in causes.iter().enumerate() {
                assert!(
                    causes[..index]
                        .iter()
                        .all(|earlier| !earlier.source.same_table(&cause.source)),
                    "{extension}: each attempted format must contribute one cause"
                );
            }
            assert_eq!(causes.iter().filter(|cause| cause.terminal).count(), 1);
            let terminal = causes
                .iter()
                .find(|diagnostic| diagnostic.terminal)
                .expect("selected format cause is terminal");
            assert_eq!(
                causes
                    .iter()
                    .filter(|diagnostic| diagnostic.setting == terminal.setting)
                    .count(),
                1,
                "{extension}: selected terminal cause must render once"
            );
            assert!(!format!("{diagnostics:?}").contains("private-port"));
        }
    }

    #[test]
    fn structured_group_failure_retains_original_index_in_map_and_sequence_forms() {
        let input = include_str!("fixtures/config_failed_group.json");
        let mut sequence = serde_json::to_value(Config::default()).unwrap();
        sequence["groups"] =
            serde_json::from_str::<serde_json::Value>(input).unwrap()["groups"].clone();
        let sequence = [
            "global",
            "dns",
            "routing",
            "nodes",
            "groups",
            "subscriptions",
            "experimental",
        ]
        .map(|field| sequence[field].take());
        for text in [input.to_owned(), serde_json::to_string(&sequence).unwrap()] {
            let mut diagnostics = Vec::new();
            let error = Config::from_json_str_with_detailed_diagnostics(&text, &mut diagnostics)
                .unwrap_err();
            assert_eq!(error.diagnostic.setting.to_string(), "groups[1]");
            assert_eq!(error.diagnostic.entry_index, Some(1));
            assert!(error.diagnostic.line.is_some());
            assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
            assert!(!format!("{error:?} {diagnostics:?}").contains("PRIVATE_GROUP_VALUE"));
        }
    }
    #[test]
    fn removed_vless_mode_preserves_indexed_safe_diagnostics() {
        for removed in [serde_json::json!("legacy"), serde_json::Value::Null] {
            let input = serde_json::json!({
                "nodes": [{
                    "name": "vless",
                    "protocol": "vless",
                    "address": "private.example:443",
                    "host": "private.example",
                    "port": 443,
                    "password": "b831381d-6324-4d53-ad4f-8cda48b30811",
                    "vless_mode": removed,
                }]
            });
            let mut diagnostics = Vec::new();
            let error = Config::from_json_str_with_detailed_diagnostics(
                &input.to_string(),
                &mut diagnostics,
            )
            .unwrap_err();
            assert_eq!(error.diagnostic.setting.to_string(), "nodes[1].vless_mode");
            assert_eq!(error.diagnostic.entry_index, Some(1));
            assert_eq!(error.diagnostic.value, SafeValue::Redacted);
            assert!(!format!("{error:?} {diagnostics:?}").contains("private.example"));
        }
    }
}

mod failure_recognition {
    use honk_config::Config;

    #[test]
    fn tolerated_prefixes_do_not_hide_dae_semantic_failures() {
        for prefix in ["", "ignored_top_level_statement\n", "}\n"] {
            for extension in ["", ".dae"] {
                let file = tempfile::Builder::new()
                    .suffix(extension)
                    .tempfile()
                    .unwrap();
                std::fs::write(
                    file.path(),
                    format!("{prefix}global {{\n nfqueue_enable: invalid\n}}\n"),
                )
                .unwrap();
                let mut diagnostics = Vec::new();
                Config::from_file_with_detailed_diagnostics(
                    file.path().to_str().unwrap(),
                    &mut diagnostics,
                )
                .unwrap_err();
                assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
                assert!(
                    !diagnostics
                        .iter()
                        .any(|d| d.code == "invalid-structured-config")
                );
            }
        }
    }

    #[test]
    fn inline_dae_semantic_failure_is_not_a_yaml_mapping() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            include_str!("fixtures/invalid_nfqueue_inline.dae"),
        )
        .unwrap();
        let mut diagnostics = Vec::new();
        Config::from_file_with_detailed_diagnostics(
            file.path().to_str().unwrap(),
            &mut diagnostics,
        )
        .unwrap_err();
        assert_eq!(diagnostics.len(), 1);
    }

    #[test]
    fn quoted_scalar_keeps_structured_fallback() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), include_str!("fixtures/quoted_dae_scalar.yaml")).unwrap();
        let mut diagnostics = Vec::new();
        let config = Config::from_file_with_detailed_diagnostics(
            file.path().to_str().unwrap(),
            &mut diagnostics,
        )
        .unwrap();
        assert_eq!(config.global.check_tolerance_ms, 75);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn flow_sequence_scalar_keeps_structured_fallback_and_caller_prefix() {
        let mut prefix = Vec::new();
        honk_config::parser::parse_dae_config_with_diagnostics(
            "global {\n sniffing_timeout: 2h\n}",
            &mut prefix,
        )
        .unwrap();
        let mut configs = Vec::new();
        for extension in [".yaml", ".dae"] {
            let file = tempfile::Builder::new()
                .suffix(extension)
                .tempfile()
                .unwrap();
            std::fs::write(
                file.path(),
                include_str!("fixtures/flow_sequence_dae_scalar.yaml"),
            )
            .unwrap();
            let mut diagnostics = prefix.clone();
            let config =
                Config::from_file_with_diagnostics(file.path().to_str().unwrap(), &mut diagnostics)
                    .unwrap();
            assert_eq!(config.global.check_tolerance_ms, 75);
            assert_eq!(diagnostics, prefix);
            configs.push(config);
        }
        assert_eq!(configs[0], configs[1]);
    }
}

mod detailed_diagnostics {
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
            let error = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
                input,
                &mut Vec::new(),
            )
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
            honk_config::ConfigError::Parse(
                "unsupported VLESS share-link parameter 'secret'".into(),
            ),
            honk_config::ConfigError::Parse("duplicate VLESS share-link parameter 'secret'".into()),
            honk_config::ConfigError::Parse(
                "VLESS parameter 'secret' is inactive with mux=off".into(),
            ),
            honk_config::ConfigError::Parse("VLESS parameter 'secret' requires mux=xray".into()),
            honk_config::ConfigError::Parse(
                "duplicate VLESS share-link parameter 'mux' secret".into(),
            ),
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
            let error = honk_config::Config::from_json_str_with_detailed_diagnostics(
                &body,
                &mut diagnostics,
            )
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
}

mod structured_warnings {
    use honk_config::{
        Config,
        config::ConfigSeed,
        diagnostic::{DiagnosticSources, SafeValue},
    };
    use serde::de::DeserializeSeed;

    #[test]
    fn api_exposure_warning_covers_custom_binds_without_values() {
        for (bind, secret, expected) in [
            ("", "", false),
            ("127.0.0.1:9090", "", false),
            ("[::1]:9090", "", false),
            (":9090", "", true),
            ("192.0.2.221:9090", "", true),
            ("[2001:db8::221]:9090", "", true),
            ("0.0.0.0:9090", "PRIVATE_SECRET", false),
        ] {
            let body = serde_json::json!({"experimental": {"clash_api": {"external_controller": bind, "secret": secret}}}).to_string();
            let mut diagnostics = Vec::new();
            ConfigSeed {
                diagnostics: &mut diagnostics,
                source: DiagnosticSources::new(None).root(),
            }
            .deserialize(&mut serde_json::Deserializer::from_str(&body))
            .unwrap();
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|d| d.code == "unsafe-api-bind")
                    .count(),
                usize::from(expected)
            );
            if expected {
                assert_eq!(
                    diagnostics[0].setting.to_string(),
                    "experimental.clash_api.external_controller"
                );
            }
            let text = format!("{diagnostics:?}");
            assert!(
                !text.contains("PRIVATE_SECRET")
                    && !text.contains("9090")
                    && !text.contains("192.0.2")
                    && !text.contains("2001:db8")
            );
        }
    }

    #[test]
    fn included_api_warning_keeps_the_winning_field_source() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root.dae");
        let child = dir.path().join("api.dae");
        std::fs::write(
            &root,
            "include {\n api.dae\n}\nexperimental {\n cache_file {\n enabled: false\n }\n}\n",
        )
        .unwrap();
        std::fs::write(
            &child,
            "experimental {\n clash_api {\n external_controller: '192.0.2.221:9090'\n }\n}\n",
        )
        .unwrap();
        let mut diagnostics = Vec::new();
        Config::from_file_with_detailed_diagnostics(root.to_str().unwrap(), &mut diagnostics)
            .unwrap();
        let warning = diagnostics
            .iter()
            .find(|d| d.code == "unsafe-api-bind")
            .unwrap();

        let sources = warning.source.sources().metadata();
        assert_eq!(sources[warning.source.index()].path.as_ref(), Some(&child));
        assert_eq!(warning.line, Some(3));
    }

    fn assert_warning_precedes_terminal(
        diagnostics: &[honk_config::diagnostic::DetailedDiagnostic],
        code: &str,
    ) {
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.terminal)
                .count(),
            1
        );
        assert_eq!(diagnostics[0].code, code);
        assert!(!diagnostics[0].terminal);
        assert!(matches!(&diagnostics[0].value, SafeValue::Redacted));
        assert!(diagnostics[1].terminal);
    }

    #[test]
    fn api_warning_survives_later_structured_node_failure() {
        let input = r#"{
        "experimental": {
            "clash_api": {
                "external_controller": "0.0.0.0:9090"
            }
        },
        "nodes": [{}]
    }"#;
        let mut diagnostics = Vec::new();
        assert!(Config::from_json_str_with_detailed_diagnostics(input, &mut diagnostics).is_err());
        assert_warning_precedes_terminal(&diagnostics, "unsafe-api-bind");
        assert_eq!(
            diagnostics[0].setting.to_string(),
            "experimental.clash_api.external_controller"
        );
        let rendered = format!("{diagnostics:?}");
        assert!(!rendered.contains("0.0.0.0:9090"));
    }
}
