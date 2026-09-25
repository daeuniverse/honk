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
    fn structured_vless_mux_rejects_invalid_limits_and_missing_shared_tcp() {
        use honk_config::diagnostic::Severity;
        use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpMux};
        use std::num::NonZeroU16;

        let base = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls",
        )
        .unwrap();
        for (tcp, udp) in [
            (NonZeroU16::new(129), VlessUdpMux::Protocol),
            (None, VlessUdpMux::Separate(NonZeroU16::new(129).unwrap())),
            (None, VlessUdpMux::SharedTcp),
        ] {
            for network in [None, Some("tcp")] {
                let mut node = base.clone();
                let vless = node.vless_mut().unwrap();
                vless.multiplex = VlessMultiplex::Xray {
                    tcp,
                    udp,
                    udp443: Udp443Policy::Allow,
                };
                vless.network = network.map(str::to_owned);
                assert!(node.validate().is_err(), "{tcp:?}, {udp:?}, {network:?}");
                for rejected in [
                    serde_json::from_str::<Node>(&serde_json::to_string(&node).unwrap()).is_err(),
                    serde_yaml::from_str::<Node>(&serde_yaml::to_string(&node).unwrap()).is_err(),
                    toml::from_str::<Node>(&toml::to_string(&node).unwrap()).is_err(),
                ] {
                    assert!(rejected, "{tcp:?}, {udp:?}, {network:?}");
                }

                let config = config_with_node(node);
                let error = config.validate_detailed().unwrap_err();
                assert_eq!(error.diagnostic.setting.to_string(), "nodes[1].multiplex");
                for (extension, text) in [
                    ("json", serde_json::to_string(&config).unwrap()),
                    ("yaml", serde_yaml::to_string(&config).unwrap()),
                    ("toml", toml::to_string(&config).unwrap()),
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
                    assert_eq!(error.diagnostic.code, "invalid-config-value");
                    assert_eq!(error.diagnostic.setting.to_string(), "nodes[1].multiplex");
                    assert_eq!(error.diagnostic.entry_index, Some(1));
                    assert_eq!(error.diagnostic.severity, Severity::Error);
                    assert!(error.diagnostic.terminal);
                    assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
                    assert!(diagnostics.iter().all(|d| d.severity == Severity::Error));
                }
            }
        }
    }

    #[test]
    fn structured_reality_intent_requires_nonblank_key() {
        use serde_json::json;

        for protocol in ["trojan", "vmess"] {
            for enabled in [false, true] {
                let base: Node = serde_json::from_value(json!({
                    "name": "endpoint",
                    "protocol": protocol,
                    "address": "192.0.2.10:443",
                    "host": "192.0.2.10",
                    "port": 443,
                    "password": "00000000-0000-0000-0000-000000000001",
                    "tls": enabled,
                }))
                .unwrap();
                for (key, short_id, spider_x, valid) in [
                    (None, None, None, true),
                    (Some(""), None, None, false),
                    (Some(" \t"), None, None, false),
                    (None, Some("a1b2"), None, false),
                    (None, Some(""), None, false),
                    (None, None, Some("/"), false),
                    (None, None, Some(""), false),
                    (Some("AAA"), None, None, true),
                    (Some("AAA"), Some(""), None, true),
                ] {
                    let mut node = base.clone();
                    let tls = node.tls_mut().unwrap();
                    tls.reality_public_key = key.map(str::to_owned);
                    tls.reality_short_id = short_id.map(str::to_owned);
                    tls.reality_spider_x = spider_x.map(str::to_owned);
                    node.id = node.derive_id();
                    let config = config_with_node(node);
                    let mut diagnostics = Vec::new();
                    let loaded = Config::from_json_str_with_detailed_diagnostics(
                        &serde_json::to_string(&config).unwrap(),
                        &mut diagnostics,
                    );
                    if valid {
                        config.validate().unwrap();
                        loaded.unwrap().validate().unwrap();
                    } else {
                        for error in [config.validate_detailed().unwrap_err(), loaded.unwrap_err()]
                        {
                            assert_eq!(error.category, ErrorCategory::Validation);
                            assert_eq!(error.diagnostic.code, "invalid-config-value");
                            assert_eq!(
                                error.diagnostic.setting.to_string(),
                                "nodes[1].reality_public_key"
                            );
                            assert_eq!(error.diagnostic.entry_index, Some(1));
                            assert!(error.diagnostic.terminal);
                        }
                    }
                }
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

mod share_link_security {
    use base64::Engine as _;
    use honk_config::node::Node;

    const AUTHORITY: &str = "00000000-0000-0000-0000-000000000001@example.com:443";
    const PUBLIC_KEY: &str = "jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc";

    #[test]
    fn trojan_reality_preserves_authentication_intent() {
        let node = Node::from_share_link(&format!(
            "trojan://pw@example.com:443?security=reality&pbk={PUBLIC_KEY}&sid=ab&spx=%2Fmask&sni=mask.example"
        ))
        .unwrap();
        let tls = node.tls().unwrap();
        assert_eq!(tls.effective_reality_public_key(), Ok(Some(PUBLIC_KEY)));
        assert_eq!(tls.reality_short_id.as_deref(), Some("ab"));
        assert_eq!(tls.reality_spider_x.as_deref(), Some("/mask"));
        assert_eq!(tls.sni.as_deref(), Some("mask.example"));

        let implicit = Node::from_share_link(&format!(
            "trojan://pw@example.com:443?pbk={PUBLIC_KEY}&tls=1"
        ))
        .unwrap();
        assert_eq!(
            implicit.tls().unwrap().effective_reality_public_key(),
            Ok(Some(PUBLIC_KEY))
        );
        assert_eq!(
            implicit.tls().unwrap().reality_spider_x.as_deref(),
            Some("/")
        );
        for query in [
            "security=reality",
            "security=reality&pbk=",
            "sid=ab",
            "tls=0",
        ] {
            assert!(
                Node::from_share_link(&format!("trojan://pw@example.com:443?{query}")).is_err()
            );
        }
        for query in ["security=reality", "pbk=AAA"] {
            assert!(
                Node::from_share_link(&format!("anytls://pw@example.com:443?{query}")).is_err()
            );
        }
        let default = Node::from_share_link("trojan://pw@example.com:443").unwrap();
        let ignored_tls = Node::from_share_link("trojan://pw@example.com:443?tls=true").unwrap();
        assert_eq!(default.outbound, ignored_tls.outbound);
        assert_eq!(default.id, ignored_tls.id);
    }

    #[test]
    fn repeated_tls_claims_are_order_independent() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(AUTHORITY);
        for authority in [AUTHORITY, encoded.as_str()] {
            for query in [
                "security=tls&security=none",
                "security=none&security=tls",
                "tls=1&tls=0",
                "tls=0&tls=1",
                "security=none&tls=1",
                "tls=0&security=tls",
            ] {
                let mut diagnostics = Vec::new();
                let error = Node::from_share_link_with_detailed_diagnostics(
                    &format!("vless://{authority}?{query}"),
                    &mut diagnostics,
                )
                .unwrap_err();
                assert_eq!(error.diagnostic.setting.to_string(), "nodes.tls");
            }
            for (query, enabled) in [
                ("security=tls&security=tls&tls=1&tls=1", true),
                ("security=none&tls=0&security=none&tls=0", false),
            ] {
                let node = Node::from_share_link(&format!("vless://{authority}?{query}")).unwrap();
                assert_eq!(node.tls().unwrap().enabled, enabled);
            }
        }
        let canonical = Node::from_share_link(&format!("vless://{AUTHORITY}")).unwrap();
        let shadowrocket = Node::from_share_link(&format!("vless://{encoded}")).unwrap();
        assert!(canonical.tls().unwrap().enabled);
        assert!(!shadowrocket.tls().unwrap().enabled);
    }
}

mod routing_marks {
    use honk_config::{Config, parser::parse_dae_config_with_detailed_diagnostics};

    #[test]
    fn invalid_direct_marks_cannot_escape_file_loader_admission() {
        let dir = tempfile::tempdir().unwrap();
        for statement in [
            "dport(443) -> direct(mark: 4294967296)",
            "dport(443) -> direct(mark: 0x40000000)",
            "fallback: direct(mark: PRIVATE)",
        ] {
            let path = dir.path().join("config.dae");
            std::fs::write(&path, format!("routing {{\n {statement}\n}}")).unwrap();
            let mut diagnostics = Vec::new();
            let error = Config::from_file_with_detailed_diagnostics(
                path.to_str().unwrap(),
                &mut diagnostics,
            )
            .unwrap_err();
            assert_eq!(error.diagnostic.code, "invalid-routing-mark");
            assert!(!format!("{error:?}{diagnostics:?}").contains("PRIVATE"));
        }
    }

    #[test]
    fn reserved_marks_remain_invalid_after_structured_loading() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = parse_dae_config_with_detailed_diagnostics(
            "routing { dport(443) -> direct(mark: 512) }",
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(config.routing.rules[0].mark, 512);
        for reserved in [0x4000_0000, 0x8000_0000, 0xc000_0000] {
            for setting in [
                "routing.rules[1].mark",
                "global.so_mark_from_dae",
                "routing.fallback",
            ] {
                let value = |owner: &str| if setting == owner { reserved } else { 0 };
                config.routing.rules[0].mark = value("routing.rules[1].mark");
                config.global.so_mark_from_dae = value("global.so_mark_from_dae");
                config.routing.default_mark = value("routing.fallback");
                for (extension, body) in [
                    ("json", serde_json::to_string(&config).unwrap()),
                    ("yaml", serde_yaml::to_string(&config).unwrap()),
                    ("toml", toml::to_string(&config).unwrap()),
                ] {
                    let path = dir.path().join(format!("config.{extension}"));
                    std::fs::write(&path, body).unwrap();
                    let restored = Config::from_file(path.to_str().unwrap()).unwrap();
                    let error = restored.validate_detailed().unwrap_err();
                    assert_eq!(error.diagnostic.setting.to_string(), setting);
                    assert_eq!(error.diagnostic.code, "invalid-config-value");
                }
            }
        }
    }

    #[test]
    fn global_marks_keep_hex_first_lexing_and_zero_effective_default() {
        for (value, raw, effective) in [
            ("0", 0, 0x100),
            ("10", 16, 16),
            ("0x200", 512, 512),
            ("zz", 0, 0x100),
        ] {
            let config = parse_dae_config_with_detailed_diagnostics(
                &format!("global {{ so_mark_from_dae: {value} }}"),
                &mut Vec::new(),
            )
            .unwrap();
            assert_eq!(config.global.so_mark_from_dae, raw);
            assert_eq!(config.global.effective_so_mark(), effective);
        }
    }
}
