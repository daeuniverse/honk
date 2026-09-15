mod traffic_and_dns_rules {
    use honk_config::{Config, parser::parse_dae_config_with_detailed_diagnostics};

    #[test]
    fn unsafe_traffic_terms_reject_at_file_boundary() {
        for (matcher, code) in [
            ("unknown(PRIVATE)", "unknown-traffic-predicate"),
            ("!unknown(PRIVATE)", "unknown-traffic-predicate"),
            ("dport (443)", "unknown-traffic-predicate"),
            ("dport(443)junk", "trailing-matcher-text"),
            ("dport(443) domain(PRIVATE)", "unknown-traffic-predicate"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("input.dae");
            std::fs::write(
                &path,
                format!("routing {{\n dport(80) && {matcher} -> direct\n}}\n"),
            )
            .unwrap();
            let mut diagnostics = Vec::new();
            let error = Config::from_file_with_detailed_diagnostics(
                path.to_str().unwrap(),
                &mut diagnostics,
            )
            .unwrap_err();
            assert_eq!(error.diagnostic.code, code);
            assert_eq!(error.diagnostic.setting.to_string(), "routing.rules[1]");
            assert_eq!(error.diagnostic.line, Some(2));
            assert!(!format!("{diagnostics:?}{error:?}").contains("PRIVATE"));
        }
    }

    #[test]
    fn invalid_dns_conjunct_omits_whole_rule() {
        for (matcher, code) in [
            ("", "invalid-dns-rule"),
            ("unknown(PRIVATE)", "invalid-dns-rule"),
            ("!sub(PRIVATE)", "unsupported-dns-condition"),
            ("qname (PRIVATE)", "invalid-dns-rule"),
            ("qname(PRIVATE)junk", "trailing-matcher-text"),
            ("qtype(A,TYPO)", "invalid-qtype"),
            ("!qtype(TYPO)", "invalid-qtype"),
        ] {
            let mut diagnostics = Vec::new();
            let config = parse_dae_config_with_detailed_diagnostics(&format!("dns {{\n routing {{\n request {{\n qname(PRIVATE) && {matcher} -> reject\n qtype('a,aaaa') -> reject\n qtype() -> reject\n }}\n }}\n}}"), &mut diagnostics).unwrap();
            assert_eq!(config.dns.routing.request.rules.len(), 2, "{matcher}");
            assert!(
                matches!(&config.dns.routing.request.rules[0].conditions[0], honk_config::dns::DnsCond::Qtype { types, .. } if types == &[1,28])
            );
            assert!(
                matches!(&config.dns.routing.request.rules[1].conditions[0], honk_config::dns::DnsCond::Qtype { types, .. } if types.is_empty())
            );
            let warning = diagnostics.iter().find(|d| d.code == code).unwrap();
            assert_eq!(warning.setting.to_string(), "dns.routing.request.rules[1]");
            assert_eq!(warning.line, Some(4));
            assert!(!format!("{diagnostics:?}").contains("PRIVATE"));
        }
    }

    #[test]
    fn regex_character_class_is_not_a_nested_predicate() {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(
            "dns {\n routing {\n request {\n qname(regex:[(]) && qtype(a) -> reject\n }\n }\n}",
            &mut diagnostics,
        )
        .unwrap();
        assert_eq!(config.dns.routing.request.rules.len(), 1);
        let rule = &config.dns.routing.request.rules[0];
        assert_eq!(rule.conditions.len(), 2);
        assert!(!diagnostics.iter().any(|d| d.code == "invalid-dns-rule"));
    }
}

mod dns_networks {
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    #[test]
    fn dns_network_admission_rejects_whole_rule_and_reports_host_bits() {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics("dns {\n routing {\n response {\n ip(192.0.2.1, PRIVATE_INVALID) -> reject\n ip(192.0.2.17/24, 2001:db8::1, 192.0.2.1) -> reject\n }\n }\n}", &mut diagnostics).unwrap();
        assert_eq!(config.dns.routing.response.rules.len(), 1);
        assert!(diagnostics.iter().any(|d| d.code == "invalid-dns-network"
            && d.line == Some(4)
            && d.setting.to_string() == "dns.routing.response.rules[1]"));
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code == "dns-network-host-bits" && d.line == Some(5))
        );
        assert!(!format!("{diagnostics:?}").contains("PRIVATE_INVALID"));
    }
}

mod empty_subgroups {
    use honk_config::{
        Config,
        parser::{parse_dae_config_with_detailed_diagnostics, resolve_group_filters},
    };

    #[test]
    fn explicit_empty_contributions_survive_roundtrip_and_refresh() {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics("node {\n edge: 'socks5://127.0.0.1:1080'\n}\nsubscription {\n paid: 'https://example.test/sub'\n}\ngroup {\n empty { filter: group() }\n blank { filter: }\n nested { filter: group(empty) }\n late { filter: subtag(paid) }\n sibling {\n filter: group()\n filter: name(edge)\n final: direct\n }\n}", &mut diagnostics).unwrap();
        assert!(config.groups[..4].iter().all(|g| g.nodes.is_empty()));
        assert_eq!(config.groups[4].nodes, [config.nodes[0].id]);
        assert_eq!(config.groups[4].final_outbound.as_deref(), Some("direct"));
        assert_eq!(
            diagnostics
                .iter()
                .filter(|d| d.code == "empty-subgroup")
                .count(),
            2
        );
        assert_eq!(config.groups[0].filters, ["group()"]);
        for mut restored in [
            serde_json::from_str::<Config>(&serde_json::to_string(&config).unwrap()).unwrap(),
            serde_yaml::from_str::<Config>(&serde_yaml::to_string(&config).unwrap()).unwrap(),
            toml::from_str::<Config>(&toml::to_string(&config).unwrap()).unwrap(),
        ] {
            restored.nodes[0].subscription_id = Some(restored.subscriptions[0].id);
            resolve_group_filters(
                &mut restored.groups,
                &restored.nodes,
                &restored.subscriptions,
            );
            assert!(restored.groups[..3].iter().all(|g| g.nodes.is_empty()));
            assert_eq!(restored.groups[2].groups, ["empty"]);
            assert_eq!(restored.groups[3].nodes, [restored.nodes[0].id]);
            restored.nodes[0].subscription_id = None;
            resolve_group_filters(
                &mut restored.groups,
                &restored.nodes,
                &restored.subscriptions,
            );
            assert!(restored.groups[..4].iter().all(|g| g.nodes.is_empty()));
            assert_eq!(restored.groups[4].nodes, [restored.nodes[0].id]);
        }
    }
}

mod check_targets {
    use honk_config::{Config, parser::parse_dae_config_with_detailed_diagnostics};

    #[test]
    fn malformed_udp_dns_targets_fail_located_admission() {
        for value in [
            "[::1",
            "[::1]junk",
            "resolver.test:PRIVATE",
            "resolver.test:0",
            "resolver.test:65536",
            ":53",
            "resolver.test:",
        ] {
            let mut config = Config::default();
            config.global.udp_check_dns = vec![value.into()];
            assert!(config.validate().is_err(), "{value}");
            let mut diagnostics = Vec::new();
            let error = parse_dae_config_with_detailed_diagnostics(
                &format!("global {{\n udp_check_dns: {value}\n}}"),
                &mut diagnostics,
            )
            .unwrap_err();
            assert_eq!(error.diagnostic.code, "invalid-dns-check-target");
            assert_eq!(
                error.diagnostic.setting.to_string(),
                "global.udp_check_dns[1]"
            );
            assert_eq!(error.diagnostic.line, Some(2));
            assert!(!format!("{diagnostics:?}{error:?}").contains("PRIVATE"));
        }
    }

    #[test]
    fn http_targets_preserve_caller_defaults_and_authority_boundaries() {
        use honk_config::check::{decode_health_http_target, decode_http_check_target};
        for (input, host, port, path) in [
            ("http://host,1.1.1.1,::1", "host", 80, "/"),
            ("host/generate_204", "host", 80, "/generate_204"),
            (
                "host/path?next=https://other/",
                "host",
                80,
                "/path?next=https://other/",
            ),
            (
                "http://u:PRIVATE@host:8080/path?q#fragment",
                "host",
                8080,
                "/path?q",
            ),
            ("https://host?q=1", "host", 443, "/?q=1"),
            (
                "http://host/a/../health?q=1",
                "host",
                80,
                "/a/../health?q=1",
            ),
            (
                "http://host/a/%2e%2e/health?q=1",
                "host",
                80,
                "/a/%2e%2e/health?q=1",
            ),
            ("[::1]:8080/path", "::1", 8080, "/path"),
            ("https://[::1]/", "::1", 443, "/"),
        ] {
            let target = decode_health_http_target(input).unwrap();
            assert_eq!(
                (target.host(), target.port(), target.request_target()),
                (host, port, path)
            );
        }
        for (input, expected) in [
            ("http://host", "host"),
            ("http://host:80", "host"),
            ("http://host:8080", "host:8080"),
            ("https://host:443", "host"),
            ("https://host:8443", "host:8443"),
            ("http://[::1]", "[::1]"),
            ("http://[::1]:8080", "[::1]:8080"),
        ] {
            assert_eq!(
                decode_health_http_target(input).unwrap().authority(),
                expected,
                "{input}"
            );
        }
        assert_eq!(
            decode_http_check_target("host/check", true).unwrap().port(),
            443
        );
        for input in ["", "https://", "http://[::1", "http://host:bad/"] {
            assert!(decode_health_http_target(input).is_err());
        }
    }

    #[test]
    fn http_targets_reject_ambiguous_authorities_before_exposing_userinfo() {
        use honk_config::check::decode_http_check_target;
        for input in [
            "http:///user:PRIVATE@example.invalid/health",
            "https:////user:PRIVATE@example.invalid/health",
            r"http://\user:PRIVATE@example.invalid/health",
            "http://example.invalid/health\r\nX-Private: secret",
        ] {
            assert!(decode_http_check_target(input, false).is_err(), "{input:?}");
        }
    }
}

mod node_collection_admission {
    use honk_config::{
        Config,
        diagnostic::SafeValue,
        error::ErrorCategory,
        node::{Node, OutboundConfig},
    };

    fn canonical_socks5_node() -> Node {
        let mut node = Node {
            name: "endpoint".into(),
            address: "192.0.2.10:1080".into(),
            host: "192.0.2.10".into(),
            port: 1080,
            outbound: OutboundConfig::Socks5(Default::default()),
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    }

    fn config_with_node(node: Node) -> Config {
        Config {
            nodes: vec![node],
            ..Default::default()
        }
    }

    #[test]
    fn incompatible_vless_fields_report_once_without_changing_node_identity() {
        use honk_config::diagnostic::{DiagnosticSources, SettingPath};
        use honk_config::node::NodeSeed;
        use serde::de::DeserializeSeed as _;
        use serde_json::json;

        let canonical = canonical_socks5_node();
        let base = serde_json::to_value(&canonical).unwrap();
        for (fields, expected) in [
            (json!({}), vec![]),
            (json!({"packet_encoding": null, "multiplex": null}), vec![]),
            (
                json!({"packet_encoding": "auto", "multiplex": {"protocol": "off"}}),
                vec![],
            ),
            (
                json!({"packet_encoding": "xudp", "multiplex": {"protocol": "xray", "tcp": 8}, "tls": true}),
                vec!["multiplex", "packet_encoding", "tls"],
            ),
        ] {
            let mut input = base.clone();
            input
                .as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            let mut diagnostics = Vec::new();
            let node = NodeSeed {
                diagnostics: &mut diagnostics,
                source: DiagnosticSources::new(None).root(),
                setting: SettingPath::new("nodes").index(1),
            }
            .deserialize(input)
            .unwrap();
            assert_eq!(node.id, canonical.id);
            assert_eq!(node.outbound, canonical.outbound);
            if expected.is_empty() {
                assert!(diagnostics.is_empty(), "{diagnostics:?}");
            } else {
                assert_eq!(diagnostics.len(), 1);
                let diagnostic = &diagnostics[0];
                assert_eq!(diagnostic.code, "incompatible-node-fields");
                assert_eq!(diagnostic.setting.to_string(), "nodes[1]");
                assert!(!diagnostic.terminal);
                let SafeValue::Fields(mut fields) = diagnostic.value.clone() else {
                    panic!("discarded fields must be safe schema names");
                };
                fields.sort_unstable();
                assert_eq!(fields, expected);
            }
        }
    }

    #[test]
    fn c20_config_admission_preserves_canonical_identity() {
        let canonical = canonical_socks5_node();
        let config = Config {
            nodes: vec![
                canonical.clone(),
                Config::builtin_direct_node(),
                Config::builtin_block_node(),
            ],
            ..Default::default()
        };
        config.validate().unwrap();

        let mut stale = canonical.clone();
        stale.host = "192.0.2.11".into();
        stale.address = "192.0.2.11:1080".into();
        let mut nil = canonical.clone();
        nil.id = uuid::Uuid::nil();
        let mut second_id = canonical.clone();
        second_id.id = uuid::Uuid::new_v4();
        let mut wrong_builtin = Config::builtin_direct_node();
        wrong_builtin.id = uuid::Uuid::new_v4();
        for nodes in [
            vec![stale],
            vec![nil],
            vec![canonical.clone(), second_id],
            vec![canonical.clone(), canonical],
            vec![wrong_builtin],
        ] {
            assert!(
                Config {
                    nodes,
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn test_config_validation_empty_node_name() {
        let mut node = canonical_socks5_node();
        node.name.clear();
        let error = config_with_node(node).validate_detailed().unwrap_err();
        assert_eq!(error.category, ErrorCategory::Validation);
        assert_eq!(error.diagnostic.code, "invalid-config-value");
        assert_eq!(error.diagnostic.setting.to_string(), "nodes[1].name");
        assert_eq!(error.diagnostic.entry_index, Some(1));
        assert_eq!(error.diagnostic.value, SafeValue::Ordinal(1));
    }

    #[test]
    fn test_config_validation_no_address() {
        let mut node = canonical_socks5_node();
        node.address.clear();
        node.host.clear();
        node.id = node.derive_id();
        let error = config_with_node(node).validate_detailed().unwrap_err();
        assert_eq!(error.category, ErrorCategory::Validation);
        assert_eq!(error.diagnostic.code, "invalid-config-value");
        assert_eq!(error.diagnostic.setting.to_string(), "nodes[1]");
        assert_eq!(error.diagnostic.entry_index, Some(1));
        assert_eq!(error.diagnostic.value, SafeValue::Ordinal(1));
    }
}
