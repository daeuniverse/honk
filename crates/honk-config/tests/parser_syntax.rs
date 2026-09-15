mod scalar_syntax {
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    #[test]
    fn glued_hash_is_scalar_data_with_legacy_notice() {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(
            include_str!("fixtures/parser/scalars/k01-glued-hash.dae"),
            &mut diagnostics,
        )
        .unwrap();

        assert_eq!(config.global.log_file, "/tmp/a#b");
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "legacy-glued-hash" && diagnostic.line == Some(2)
        }));
    }

    #[test]
    fn lists_unquote_items_and_retain_check_target_aggregate_compatibility() {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(
            include_str!("fixtures/parser/scalars/k14-lists.dae"),
            &mut diagnostics,
        )
        .unwrap();

        assert_eq!(config.global.lan_interface, ["eth0", "eth1"]);
        assert_eq!(
            config.global.tcp_check_url,
            ["https://one.example/a", "https://two.example/b"]
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "legacy-list-quoting")
                .count(),
            1
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "legacy-quoted-list")
                .count(),
            1
        );
    }

    #[test]
    fn scalar_remainder_does_not_enter_subscription_ua_logic() {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(
            include_str!("fixtures/parser/scalars/k22-c-scalar.dae"),
            &mut diagnostics,
        )
        .unwrap();

        assert_eq!(config.global.log_file, "/tmp/x 'piece'(part)tail");
        assert_eq!(config.routing.default_outbound, "direct");
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "legacy-ua-boundary")
        );
    }

    #[test]
    fn bare_apostrophe_remains_literal_scalar_data() {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(
            include_str!("fixtures/parser/scalars/k05-bare-apostrophe.dae"),
            &mut diagnostics,
        )
        .unwrap();

        assert_eq!(config.global.log_file, "/tmp/don't");
    }

    #[test]
    fn token_head_unterminated_quote_fails_with_lexical_error() {
        let mut diagnostics = Vec::new();
        let error = parse_dae_config_with_detailed_diagnostics(
            include_str!("fixtures/parser/scalars/k05-unterminated.dae"),
            &mut diagnostics,
        )
        .unwrap_err();

        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "unterminated-quote")
        );
        assert!(error.diagnostic.code == "unterminated-quote");
    }

    #[test]
    fn shorthand_booleans_keep_false_and_mark_the_migration() {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(
            include_str!("fixtures/parser/scalars/scalar-controls.dae"),
            &mut diagnostics,
        )
        .unwrap();

        assert!(!config.global.disable_waiting_network);
        assert!(!config.global.auto_config_kernel_parameter);
        assert!(!config.global.store_subscribe);
        assert!(!config.global.allow_insecure);
        assert!(!config.global.tls_fragment);
        assert!(!config.global.mptcp);
        assert_eq!(config.global.so_mark_from_dae, 0x0800_0000);
        assert_eq!(config.global.check_interval_secs, 2);
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "legacy-bool-shorthand")
                .count(),
            6
        );
    }

    #[test]
    fn nfqueue_boolean_remains_strict() {
        let mut diagnostics = Vec::new();
        let result = parse_dae_config_with_detailed_diagnostics(
            "global {\n nfqueue_enable: t\n}\n",
            &mut diagnostics,
        );
        assert!(result.is_err());
    }
}

mod routing_syntax {
    use honk_config::diagnostic::{DetailedDiagnostic, Severity};
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    #[test]
    fn spaced_must_is_an_outbound_name() {
        let config = parse_dae_config_with_detailed_diagnostics(
            "routing {\n domain(x) -> proxy( must )\n domain(y) -> proxy(must)\n}",
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            config.routing.rules[0].outbound,
            honk_config::routing::RoutingOutbound::Simple("proxy( must )".into())
        );
        assert!(!config.routing.rules[0].must);
        assert!(config.routing.rules[1].must);
    }

    fn input(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/parser/routing/{name}.dae",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn glued_hash_target_is_literal_and_warns_at_the_boundary() {
        let source = input("k02-glued-hash-target");
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap();
        assert_eq!(
            config.routing.rules[0].outbound,
            honk_config::routing::RoutingOutbound::Simple("proxy#c".into())
        );
        let warnings: Vec<&DetailedDiagnostic> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "legacy-glued-hash")
            .collect();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].severity, Severity::Warning);
        assert_eq!(warnings[0].line, Some(2));
        assert_eq!(
            warnings[0].span.as_ref().unwrap().start,
            source.find('#').unwrap()
        );
    }

    #[test]
    fn complete_matcher_with_junk_has_a_located_terminal_error() {
        let source = input("k36-trailing-matcher-text");
        let mut diagnostics = Vec::new();
        let error =
            parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap_err();
        assert_eq!(error.diagnostic.code, "trailing-matcher-text");
        assert_eq!(error.diagnostic.line, Some(2));
        assert!(error.diagnostic.span.is_some());
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.terminal)
                .count(),
            1
        );
    }

    #[test]
    fn traffic_quotes_fail_lexically_at_both_quote_boundaries() {
        for name in ["k05-argument-quote", "k05-head-quote"] {
            let source = input(name);
            let mut diagnostics = Vec::new();
            let error =
                parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap_err();
            assert_eq!(error.diagnostic.code, "unterminated-quote", "{name}");
            assert_eq!(error.diagnostic.line, Some(2));
            assert!(error.diagnostic.span.is_some());
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "unterminated-quote")
                    .count(),
                1
            );
        }
    }

    #[test]
    fn quoted_arguments_preserve_spaces_hashes_and_braces() {
        let source = input("k05-quoted-arguments");
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap();
        let condition = &config.routing.rules[0].condition;
        assert_eq!(condition.domain_suffix, [" a # b ", "a } b"]);
        assert_eq!(condition.process_name, ["agent # build"]);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != "legacy-glued-hash")
        );
    }

    #[test]
    fn unfinished_traffic_calls_do_not_cross_include_sources() {
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path().join("entry.dae");
        std::fs::write(
            &entry,
            format!(
                "# {}\ninclude {{ child.dae }}\nrouting {{ domain( }}\n",
                "source offset padding ".repeat(8)
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("child.dae"),
            "routing { example.com) -> direct }\n",
        )
        .unwrap();
        assert!(honk_config::Config::from_file(entry.to_str().unwrap()).is_err());
    }

    #[test]
    fn nested_parentheses_do_not_hide_trailing_matcher_text() {
        let source = "routing { domain(regex:(foo)) -> direct }";
        assert!(parse_dae_config_with_detailed_diagnostics(source, &mut Vec::new()).is_err());
    }

    #[test]
    fn compact_tokens_inside_matcher_arguments_remain_data() {
        for source in [
            "routing { pname(agent {} worker) -> direct }",
            "routing {\n pname(\n agent {} worker\n ) -> direct\n}",
            "routing { pname( }\nrouting {\n agent {} worker\n ) -> direct\n}",
        ] {
            let mut diagnostics = Vec::new();
            let config =
                parse_dae_config_with_detailed_diagnostics(source, &mut diagnostics).unwrap();
            assert_eq!(
                config.routing.rules[0].condition.process_name,
                ["agent {} worker"]
            );
            assert!(diagnostics.is_empty(), "{diagnostics:?}");
        }
    }

    #[test]
    fn ignored_statements_cannot_change_expression_continuation() {
        let source = "routing {\n pname(\n /* ) */\n agent {} worker\n ) -> direct\n}";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(source, &mut diagnostics).unwrap();
        assert_eq!(
            config.routing.rules[0].condition.process_name,
            ["agent {} worker"]
        );
        assert_eq!(
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code)
                .collect::<Vec<_>>(),
            ["unsupported-comment"],
        );
    }
}

mod section_syntax {
    use honk_config::Config;
    use honk_config::diagnostic::{DetailedDiagnostic, Severity};
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    #[test]
    fn unknown_subtrees_cannot_override_settings_or_leak_rules() {
        let input = r#"global {
 log_level: warn
 wrapper { nested { log_level: debug } }
 tproxy_port: 23456
}
group { g {
 policy: selector
 wrapper { policy: score }
 final: direct
} }
experimental {
 clash_api {
  secret: retained
  wrapper { secret: leaked }
 }
 cache_file {
  enabled: false
  wrapper { enabled: true }
 }
}
dns {
 max_cache_size: 321
 wrapper { max_cache_size: 999 }
 upstream {
  wrapper { hidden: 'udp://127.0.0.2:53' }
  visible: 'udp://127.0.0.1:53'
 }
 fixed_domain_ttl {
  wrapper { hidden: 99 }
  visible: 42
 }
 routing {
  wrapper { request { qname(hidden) -> reject } }
  request {
   wrapper { qname(hidden) -> reject }
   qname(visible) -> reject
  }
  response { wrapper { qname(hidden) -> reject } }
 }
}
routing {
 wrapper { domain(hidden) -> block }
 domain(visible) -> direct
 fallback: direct
}
"#;
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        assert_eq!(config.global.log_level, "warn");
        assert_eq!(config.global.tproxy_port, 23456);
        assert_eq!(
            config.groups[0].policy,
            honk_config::group::GroupPolicy::Selector
        );
        assert_eq!(config.groups[0].final_outbound.as_deref(), Some("direct"));
        assert_eq!(config.experimental.clash_api.secret, "retained");
        assert!(!config.experimental.cache_file.enabled);
        assert_eq!(config.dns.cache.max_size, 321);
        assert_eq!(config.dns.upstream.len(), 1);
        assert_eq!(config.dns.upstream[0].name, "visible");
        assert_eq!(config.dns.fixed_domain_ttl, [("visible".into(), 42)].into());
        assert_eq!(config.dns.routing.request.rules.len(), 1);
        assert!(config.dns.routing.response.rules.is_empty());
        assert_eq!(config.routing.rules.len(), 1);
        assert_eq!(
            config.routing.rules[0].outbound,
            honk_config::routing::RoutingOutbound::Simple("direct".into())
        );
        let skipped: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.code == "unknown-block")
            .collect();
        assert_eq!(skipped.len(), 11);
        assert!(
            skipped
                .iter()
                .all(|d| d.severity == Severity::Warning && d.span.is_some())
        );
    }

    #[test]
    fn strict_nfqueue_rejects_nested_content_but_optional_children_ignore_unknown_keys() {
        let mut diagnostics: Vec<DetailedDiagnostic> = Vec::new();
        let error = parse_dae_config_with_detailed_diagnostics(
            "experimental { udp_nfqueue { wrapper { enabled: true } } }",
            &mut diagnostics,
        )
        .unwrap_err();
        assert_eq!(error.category, honk_config::error::ErrorCategory::Parse);
        assert!(error.diagnostic.terminal);
        assert_eq!(error.diagnostic.line, Some(1));
        assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);

        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(
        "experimental {\n clash_api { future: sensitive-value\n secret: kept }\n cache_file { future: sensitive-value\n enabled: true }\n}",
        &mut diagnostics,
    ).unwrap();
        assert_eq!(config.experimental.clash_api.secret, "kept");
        assert!(config.experimental.cache_file.enabled);
        assert_eq!(
            diagnostics
                .iter()
                .filter(|d| d.code == "unknown-key")
                .count(),
            2
        );
        assert!(!format!("{diagnostics:?}").contains("sensitive-value"));
        assert_eq!(config.global, Config::default().global);
    }

    #[test]
    fn comment_brace_notice_survives_early_failure_inside_an_open_root() {
        for statement in ["{", "log_level: 'unterminated", "wrapper{"] {
            let input = format!("global {{\n  # }}\n  {statement}\n  # }}\n");
            let mut diagnostics = Vec::new();
            parse_dae_config_with_detailed_diagnostics(&input, &mut diagnostics).unwrap_err();
            let comments: Vec<_> = diagnostics
                .iter()
                .filter(|d| d.code == "legacy-comment-brace")
                .collect();
            assert_eq!(comments.len(), 1, "{statement}: {diagnostics:?}");
            assert_eq!(comments[0].line, Some(2));
            assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
        }
    }

    #[test]
    fn sibling_notices_belong_to_the_enclosing_section() {
        let input = "node {\n first: 'socks5://127.0.0.1:1080'\n wrapper {\n second: 'socks5://127.0.0.1:1081'\n }\n}\nsubscription {\n first: 'https://example.com/one'\n wrapper {\n second: 'https://example.com/two'\n }\n}\ngroup {\n a { }\n stray\n b { }\n}";
        let mut diagnostics = Vec::new();
        parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        let notices = diagnostics
            .iter()
            .filter(|diagnostic| matches!(diagnostic.code, "legacy-wrapper" | "unknown-statement"))
            .map(|diagnostic| {
                (
                    diagnostic.code,
                    diagnostic.setting.to_string(),
                    diagnostic.entry_index,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            notices,
            [
                ("legacy-wrapper", "nodes".to_owned(), None),
                ("legacy-wrapper", "subscriptions".to_owned(), None),
                ("unknown-statement", "groups".to_owned(), None),
            ],
        );
    }

    #[test]
    fn compact_blocks_preserve_mixed_section_siblings_and_rule_values() {
        let input = "dns { upstream {} routing { request { fallback: reject } } }\nexperimental { cache_file {} clash_api { secret: kept } }\nrouting { domain(example.test) -> direct {} literal }";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        assert_eq!(
            config.dns.routing.request.fallback,
            honk_config::dns::DnsRequestAction::Reject
        );
        assert_eq!(config.experimental.clash_api.secret, "kept");
        assert_eq!(
            config.routing.rules[0].outbound,
            honk_config::routing::RoutingOutbound::Simple("direct {} literal".to_owned()),
        );
    }

    #[test]
    fn compact_header_does_not_detach_an_indexed_subtree() {
        let input = "node { edge: 'socks5://127.0.0.1:1080' }\nglobal {\n log_level: warn\n wrapper {} {\n log_level: debug\n }\n}\ngroup { g {\n policy: selector\n wrapper {} {\n policy: score\n filter: name(missing)\n }\n} }";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        assert_eq!(config.global.log_level, "warn");
        assert_eq!(
            config.groups[0].policy,
            honk_config::group::GroupPolicy::Selector
        );
        assert_eq!(config.groups[0].nodes, [config.nodes[0].id]);
    }

    #[test]
    fn ignored_statement_suffixes_cannot_install_settings_or_rules() {
        let input = "global {\n log_level: warn\n /* ignored {} log_level: debug\n}\nrouting {\n /* ignored {} pname(agent) -> direct\n}";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        assert_eq!(config.global.log_level, "warn");
        assert!(config.routing.rules.is_empty());
        assert_eq!(
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code)
                .collect::<Vec<_>>(),
            ["unsupported-comment", "unsupported-comment"],
        );
    }
}
