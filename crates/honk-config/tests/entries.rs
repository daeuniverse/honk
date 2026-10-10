mod subscription_syntax {
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    fn parse(
        input: &str,
    ) -> (
        honk_config::Config,
        Vec<honk_config::diagnostic::DetailedDiagnostic>,
    ) {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        (config, diagnostics)
    }

    fn count_code(
        diagnostics: &[honk_config::diagnostic::DetailedDiagnostic],
        code: &str,
    ) -> usize {
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == code)
            .count()
    }

    #[test]
    fn quoted_subscription_tag_and_user_agent_keep_exact_bytes() {
        let (config, diagnostics) = parse(include_str!(
            "fixtures/parser/subscriptions/ctl-sub-quoted-spaced-hash.dae"
        ));
        assert_eq!(config.subscriptions.len(), 1);
        let subscription = &config.subscriptions[0];
        assert_eq!(subscription.name, "paid # east");
        assert_eq!(subscription.url, "https://example.com/sub#token #data");
        assert_eq!(subscription.user_agent.as_deref(), Some("agent # build"));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn quoted_embedded_tag_is_split_with_one_compatibility_warning() {
        let (config, diagnostics) = parse(include_str!(
            "fixtures/parser/subscriptions/cls-sub-quoted-tag-inside.dae"
        ));
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "paid");
        assert_eq!(config.subscriptions[0].url, "https://example.com/sub");
        assert_eq!(count_code(&diagnostics, "legacy-embedded-tag"), 1);
    }

    #[test]
    fn quoted_embedded_tag_is_normalized_after_user_agent_and_glued_comment_parsing() {
        let input = "subscription {\n 'paid:http://q/path#token #data'('agent # build')# note\n}\nrouting {\n fallback: direct\n}\n";
        let (config, diagnostics) = parse(input);
        assert_eq!(config.subscriptions.len(), 1);
        let subscription = &config.subscriptions[0];
        assert_eq!(subscription.name, "paid");
        assert_eq!(subscription.url, "http://q/path#token #data");
        assert_eq!(subscription.user_agent.as_deref(), Some("agent # build"));
        assert_eq!(count_code(&diagnostics, "legacy-embedded-tag"), 1);
        assert_eq!(count_code(&diagnostics, "legacy-glued-hash"), 1);
    }

    #[test]
    fn quoted_subscription_user_agent_colons_are_data() {
        let (config, _) = parse(
            "subscription {\n 'https://example.com/sub'(agent:1)\n 'explicit:tag': 'https://example.com/explicit'(agent:2)\n}",
        );
        assert_eq!(config.subscriptions[0].name, "example.com");
        assert_eq!(config.subscriptions[0].url, "https://example.com/sub");
        assert_eq!(
            config.subscriptions[0].user_agent.as_deref(),
            Some("agent:1")
        );
        assert_eq!(config.subscriptions[1].name, "explicit:tag");
        assert_eq!(config.subscriptions[1].url, "https://example.com/explicit");
        assert_eq!(
            config.subscriptions[1].user_agent.as_deref(),
            Some("agent:2")
        );
    }

    #[test]
    fn quoted_entry_comment_colons_do_not_create_tags() {
        let (config, diagnostics) = parse(
            "node {\n 'socks5://127.0.0.1:1080#edge'#note: detail\n}\nsubscription {\n 'paid:https://example.com/sub'#note: detail\n}",
        );
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].name, "edge");
        assert_eq!(config.subscriptions[0].name, "paid");
        assert_eq!(config.subscriptions[0].url, "https://example.com/sub");
        assert_eq!(count_code(&diagnostics, "legacy-glued-hash"), 2);
    }

    #[test]
    fn glued_user_agent_hash_comments_retain_entries_and_warn_at_hash() {
        let input = include_str!("fixtures/parser/subscriptions/cls-sub-ua-glued-hash.dae");
        let (config, diagnostics) = parse(input);
        assert_eq!(
            config
                .subscriptions
                .iter()
                .map(|subscription| (
                    subscription.name.as_str(),
                    subscription.url.as_str(),
                    subscription.user_agent.as_deref()
                ))
                .collect::<Vec<_>>(),
            [
                ("sub", "http://sub", Some("honk/1.0 like")),
                ("other", "http://other", Some("agent")),
            ]
        );
        assert_eq!(diagnostics.len(), 2);
        for (diagnostic, hash) in diagnostics.iter().zip(["#xxxx", "# note"]) {
            assert_eq!(diagnostic.code, "legacy-glued-hash");
            assert_eq!(
                diagnostic.severity,
                honk_config::diagnostic::Severity::Warning
            );
            let offset = input.find(hash).unwrap();
            assert_eq!(diagnostic.span, Some(offset..offset + 1));
        }
    }

    #[test]
    fn incomplete_user_agent_hash_head_skips_entry_with_a_precise_diagnostic() {
        let input = include_str!("fixtures/parser/subscriptions/cls-sub-ua-with-hash.dae");
        let (config, diagnostics) = parse(input);
        assert!(config.subscriptions.is_empty());
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.code, "trailing-entry-text");
        assert_eq!(
            diagnostic.severity,
            honk_config::diagnostic::Severity::Warning
        );
        let suffix = input.find("(agent").unwrap();
        let hash = input.find("# build").unwrap();
        assert_eq!(diagnostic.span, Some(suffix..hash - 1));
    }

    #[test]
    fn spaced_entry_tags_are_documented_admitted_and_normalized_for_nodes_and_subscriptions() {
        // Whitespace around an entry tag colon is admitted and normalized.
        let (config, diagnostics) = parse(include_str!(
            "fixtures/parser/subscriptions/ctl-node-spaced-tag.dae"
        ));
        assert_eq!(
            config
                .nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["edge", "edge west"]
        );
        assert_eq!(count_code(&diagnostics, "entry-tag-normalized"), 1);

        let (config, diagnostics) = parse(include_str!(
            "fixtures/parser/subscriptions/ctl-sub-spaced-tag.dae"
        ));
        assert_eq!(
            config
                .subscriptions
                .iter()
                .map(|sub| sub.name.as_str())
                .collect::<Vec<_>>(),
            ["paid", "paid plan"]
        );
        assert_eq!(count_code(&diagnostics, "entry-tag-normalized"), 1);
    }

    #[test]
    fn subscription_blocks_preserve_values_and_duration_conversion() {
        let (config, diagnostics) = parse(include_str!(
            "fixtures/parser/subscriptions/equiv-subscription-block-nested-close.dae"
        ));
        assert_eq!(config.subscriptions.len(), 2);
        assert_eq!(config.subscriptions[0].name, "detailed");
        assert_eq!(
            config.subscriptions[0].url,
            "http://example.test/subscription"
        );
        assert_eq!(
            config.subscriptions[0].user_agent.as_deref(),
            Some("provider/2.0")
        );
        assert_eq!(config.subscriptions[0].update_interval, 10_000);
        assert_eq!(
            config.subscriptions[1].user_agent.as_deref(),
            Some("honk/1.0 like")
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn nested_wrappers_traverse_entries_and_warn_once_per_wrapper() {
        let (config, diagnostics) = parse(include_str!(
            "fixtures/parser/subscriptions/ctl-node-nested-wrapper.dae"
        ));
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].name, "a");
        assert_eq!(count_code(&diagnostics, "legacy-wrapper"), 1);

        let (config, diagnostics) = parse(include_str!(
            "fixtures/parser/subscriptions/ctl-subscription-nested-wrapper.dae"
        ));
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "a");
        assert_eq!(count_code(&diagnostics, "legacy-wrapper"), 1);
    }

    #[test]
    fn tagless_subscription_names_and_quoted_ua_are_derived_without_boundary_errors() {
        let (config, diagnostics) = parse(include_str!(
            "fixtures/parser/subscriptions/cls-sub-tagless-ua.dae"
        ));
        assert_eq!(config.subscriptions[0].name, "example.org");
        assert_eq!(config.subscriptions[0].url, "https://example.org/sub");
        assert_eq!(
            config.subscriptions[0].user_agent.as_deref(),
            Some("provider/2.0")
        );
        assert_eq!(count_code(&diagnostics, "legacy-ua-boundary"), 0);

        let (config, diagnostics) = parse(include_str!(
            "fixtures/parser/subscriptions/cls-sub-tagless-quoted.dae"
        ));
        assert_eq!(config.subscriptions[0].name, "example.org");
        assert_eq!(config.subscriptions[0].url, "https://example.org/sub");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn glued_hash_after_a_quoted_node_link_retains_both_nodes_and_warns_once() {
        let input =
            include_str!("fixtures/parser/subscriptions/ctl-node-glued-hash-after-quote.dae");
        let (config, diagnostics) = parse(input);
        assert_eq!(config.nodes.len(), 2);
        assert_eq!(config.nodes[0].name, "hk1");
        assert_eq!(config.nodes[0].address, "1.2.3.4:8388");
        assert_eq!(config.nodes[1].name, "hk2#note");
        assert_eq!(config.nodes[1].address, "1.2.3.4:8389");
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.code, "legacy-glued-hash");
        assert_eq!(
            diagnostic.severity,
            honk_config::diagnostic::Severity::Warning
        );
        let hash = input.find("#note").unwrap();
        assert_eq!(diagnostic.span, Some(hash..hash + 1));
        let input = "node {\n 'socks5://127.0.0.1:1080'junk\n}\nrouting {\n fallback: direct\n}\n";
        let (config, diagnostics) = parse(input);
        assert!(config.nodes.is_empty());
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.code, "trailing-entry-text");
        assert_eq!(
            diagnostic.severity,
            honk_config::diagnostic::Severity::Warning
        );
        let junk = input.find("junk").unwrap();
        assert_eq!(diagnostic.span, Some(junk..junk + 4));
    }

    #[test]
    fn k22_a_retains_commented_subscription_and_preserves_structural_order() {
        let input = include_str!("fixtures/cursor/k22-a.dae");
        let (config, diagnostics) = parse(input);
        assert_eq!(
            config
                .subscriptions
                .iter()
                .map(|subscription| (
                    subscription.name.as_str(),
                    subscription.url.as_str(),
                    subscription.user_agent.as_deref()
                ))
                .collect::<Vec<_>>(),
            [("sub", "http://sub", Some("ua"))]
        );
        let codes = diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>();
        // K22-A keeps the quoted entry; separated braces remain lexer-owned.
        assert_eq!(
            codes,
            ["legacy-glued-hash", "unknown-statement", "unmatched-close"]
        );
        assert_eq!(
            diagnostics[0].severity,
            honk_config::diagnostic::Severity::Warning
        );
        let hash = input.find("# }").unwrap();
        assert_eq!(diagnostics[0].span, Some(hash..hash + 1));
    }

    #[test]
    fn bare_subscription_uri_hash_tail_remains_data() {
        let (config, diagnostics) = parse(include_str!("fixtures/cursor/k22-b.dae"));
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(
            config.subscriptions[0].url,
            "https://example.com/sub?filter='hk'#token"
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn a_second_complete_user_agent_suffix_is_not_part_of_the_first() {
        let input =
            "subscription {\n sub: 'http://sub'(one)(two)\n}\nrouting {\n fallback: direct\n}\n";
        let (config, diagnostics) = parse(input);
        assert!(config.subscriptions.is_empty());
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.code, "legacy-ua-boundary");
        assert_eq!(
            diagnostic.severity,
            honk_config::diagnostic::Severity::Error
        );
        assert_eq!(
            diagnostic.span,
            Some(input.find("(two)").unwrap()..input.find("(two)").unwrap() + 1)
        );
    }

    #[test]
    fn subscription_wrappers_retain_inline_header_entries_in_order() {
        let (config, diagnostics) = parse(include_str!(
            "fixtures/parser/subscriptions/ctl-subscription-double-colon-header.dae"
        ));
        assert_eq!(
            config
                .subscriptions
                .iter()
                .map(|subscription| (subscription.name.as_str(), subscription.url.as_str()))
                .collect::<Vec<_>>(),
            [("a", "b: {"), ("url", "http://example.test/sub")],
        );
        assert_eq!(count_code(&diagnostics, "legacy-wrapper"), 1);
    }

    #[test]
    fn subscription_blocks_advance_following_inline_diagnostic_ordinals() {
        let input = "subscription {\n stable: {\n  url: 'http://stable'\n }\n 'http://bad'junk\n}\nrouting {\n fallback: direct\n}\n";
        let (config, diagnostics) = parse(input);
        assert_eq!(config.subscriptions.len(), 1);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "trailing-entry-text")
            .unwrap();
        assert_eq!(diagnostic.setting.to_string(), "subscriptions[2]");
        assert_eq!(diagnostic.entry_index, Some(2));
    }

    #[test]
    fn skipped_inline_subscriptions_advance_following_block_warning_ordinals() {
        let input = "subscription {\n 'http://skipped'junk\n timed: {\n  url: 'http://timed'\n  interval: never\n }\n}\nrouting {\n fallback: direct\n}\n";
        let (config, diagnostics) = parse(input);
        assert_eq!(config.subscriptions.len(), 1);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "legacy-config-warning")
            .unwrap();
        assert_eq!(diagnostic.setting.to_string(), "subscriptions[2].interval");
        assert_eq!(diagnostic.entry_index, Some(2));
    }

    #[test]
    fn invalid_subscription_cache_reports_the_cache_field() {
        let input = "subscription {\n paid: {\n  url: 'http://paid'\n  cache: maybe\n }\n}\nrouting {\n fallback: direct\n}\n";
        let (config, diagnostics) = parse(input);
        assert!(config.subscriptions[0].cache);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "legacy-config-warning")
            .unwrap();
        assert_eq!(diagnostic.setting.to_string(), "subscriptions[1].cache");
        assert_eq!(
            diagnostic.message,
            "value is not a boolean; using fallback true"
        );
        assert_eq!(&input[diagnostic.span.clone().unwrap()], "maybe");
    }

    #[test]
    fn compact_tokens_inside_user_agents_remain_data() {
        let (config, diagnostics) =
            parse("subscription { paid: 'https://example.com/sub'(agent {} worker) }");
        assert_eq!(
            config
                .subscriptions
                .iter()
                .map(|subscription| (
                    subscription.name.as_str(),
                    subscription.url.as_str(),
                    subscription.user_agent.as_deref(),
                ))
                .collect::<Vec<_>>(),
            [("paid", "https://example.com/sub", Some("agent {} worker"))],
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn compact_subscription_field_headers_keep_raw_values() {
        let input = "subscription {\n paid: {\n url: https://example.com/sub\n ua: agent {}\n interval: 30s {}\n }\n}";
        let (config, diagnostics) = parse(input);
        assert_eq!(
            config.subscriptions[0].user_agent.as_deref(),
            Some("agent {}")
        );
        assert_eq!(config.subscriptions[0].update_interval, 0);
        let warning = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "legacy-config-warning")
            .unwrap();
        assert_eq!(warning.setting.to_string(), "subscriptions[1].interval");
        assert_eq!(&input[warning.span.clone().unwrap()], "30s {}");
    }

    #[test]
    fn populated_bare_entries_keep_interior_compact_tokens() {
        let (config, _) = parse(
            "node { socks5://127.0.0.1:1080#edge {} west }\nsubscription { sub: https://example.com/path {} suffix }",
        );
        assert_eq!(
            config
                .nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["edge {} west"],
        );
        assert_eq!(
            config
                .subscriptions
                .iter()
                .map(|subscription| (subscription.name.as_str(), subscription.url.as_str(),))
                .collect::<Vec<_>>(),
            [("sub", "https://example.com/path {} suffix")],
        );
    }

    #[test]
    fn quoted_entry_hash_tails_cannot_supply_compact_siblings() {
        let (config, _) = parse(
            "node { 'socks5://127.0.0.1:1080#edge'# {} socks5://127.0.0.1:1081#other }\nsubscription { 'https://example.com/sub'# {} https://other.invalid/sub }",
        );
        assert_eq!(
            config
                .nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["edge"],
        );
        assert_eq!(
            config
                .subscriptions
                .iter()
                .map(|subscription| subscription.url.as_str())
                .collect::<Vec<_>>(),
            ["https://example.com/sub"],
        );
    }
}

mod group_syntax {
    use honk_config::Config;
    use honk_config::diagnostic::DetailedDiagnostic;
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    fn fixture(name: &str) -> (Config, Vec<DetailedDiagnostic>) {
        let input = std::fs::read_to_string(format!(
            "{}/tests/fixtures/parser/groups/{name}.dae",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(&input, &mut diagnostics).unwrap();
        (config, diagnostics)
    }

    #[test]
    fn quoted_brace_name_matches_and_suffix_junk_is_false() {
        let (config, _) = fixture("k06-braced-name");
        assert_eq!(config.groups[0].nodes, [config.nodes[0].id]);

        let (config, diagnostics) = fixture("k36-suffix-junk");
        assert!(config.groups[0].nodes.is_empty());
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| {
                    diagnostic.code == "legacy-config-warning"
                        && diagnostic.setting.to_string() == "groups[1].filter"
                        && diagnostic.entry_index == Some(1)
                })
                .count(),
            1
        );
    }

    #[test]
    fn quoted_subgroup_lists_and_explicit_empty_contributions_keep_boundaries() {
        let (config, diagnostics) = fixture("k40-quoted-subgroups");
        assert_eq!(config.groups[0].groups, ["alpha", "beta", "gamma"]);
        assert_eq!(config.groups[0].filters, Vec::<String>::new());
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "legacy-quoted-list")
                .count(),
            1
        );

        let (config, diagnostics) = fixture("k41-empty-subgroup");
        assert!(config.groups[0].nodes.is_empty());
        assert_eq!(config.groups[1].nodes, [config.nodes[0].id]);
        assert_eq!(config.groups[1].final_outbound.as_deref(), Some("direct"));
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "empty-subgroup")
                .count(),
            2
        );
    }

    #[test]
    fn malformed_argument_and_head_quotes_recover_only_with_surviving_closers() {
        for (name, raw) in [
            ("k05-argument-recovery", "name('unterminated)"),
            ("k05-head-recovery", "'unterminated"),
        ] {
            let (config, diagnostics) = fixture(name);
            assert!(config.groups[0].nodes.is_empty(), "{name}");
            assert_eq!(config.groups[0].filters, [raw]);
            assert_eq!(
                config.groups[0].policy,
                honk_config::group::GroupPolicy::Score
            );
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "unterminated-quote")
                    .count(),
                1,
                "{name}: {diagnostics:?}"
            );
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "legacy-config-warning")
                    .count(),
                0,
                "lexical failures must not receive a duplicate reader warning: {name}"
            );
        }
    }

    #[test]
    fn quote_failure_still_fails_when_a_required_closer_is_hidden() {
        for name in [
            "k05-same-line-failure",
            "k05-head-failure",
            "k05-multiline-missing-closer",
        ] {
            let input = std::fs::read_to_string(format!(
                "{}/tests/fixtures/parser/groups/{name}.dae",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            let mut diagnostics = Vec::new();
            assert!(
                parse_dae_config_with_detailed_diagnostics(&input, &mut diagnostics).is_err(),
                "{name}"
            );
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "unterminated-quote"),
                "{name}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn frozen_balanced_incomplete_calls_keep_reader_diagnostics_and_policy() {
        for (name, group_name, policy) in [
            (
                "cls-unterminated-quoted-paren-subgroup",
                "g",
                honk_config::group::GroupPolicy::Selector,
            ),
            (
                "ctl-unterminated-filter-then-policy",
                "proxy",
                honk_config::group::GroupPolicy::Score,
            ),
        ] {
            let (config, diagnostics) = fixture(name);
            assert_eq!(config.groups[0].name, group_name);
            assert_eq!(config.groups[0].policy, policy);
            assert!(config.groups[0].nodes.is_empty());
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|diagnostic| {
                        diagnostic.code == "legacy-config-warning"
                            && diagnostic.setting.to_string() == "groups[1].filter"
                            && diagnostic.entry_index == Some(1)
                    })
                    .count(),
                1,
                "{name}: {diagnostics:?}"
            );
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "unterminated-quote")
                    .count(),
                0,
                "{name}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn annotation_is_an_invalid_whole_contribution() {
        let (config, diagnostics) = fixture("k04-annotation-filter");
        assert!(config.groups[0].nodes.is_empty());
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| {
                    diagnostic.code == "legacy-config-warning"
                        && diagnostic.setting.to_string() == "groups[1].filter"
                        && diagnostic.entry_index == Some(1)
                })
                .count(),
            1
        );
    }

    #[test]
    fn glued_hash_in_a_filter_argument_is_data_and_warns_once() {
        // K01 inside a call argument: `group(hk#suffix)` used to be cut at the hash
        // and left a truncated `group(hk` filter; now the subgroup name is the whole
        // argument and the formerly cut boundary gets the same warning as a scalar.
        let (config, diagnostics) = fixture("k01-glued-hash-filter");
        assert_eq!(config.groups[0].groups, ["hk#suffix"]);
        assert!(config.groups[0].nodes.is_empty());
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "legacy-glued-hash")
                .map(|diagnostic| (diagnostic.line, diagnostic.setting.to_string()))
                .collect::<Vec<_>>(),
            vec![(Some(7), "groups[1].filter".to_string())],
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn compact_child_blocks_preserve_siblings_and_scalar_data() {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(
        "global {\n log_file: /tmp/keep {} literal\n}\ngroup { a:b {} a {} b {} }\nsubscription { first: {} wrapper { second: {} third: {} } }",
        &mut diagnostics,
    )
    .unwrap();
        assert_eq!(config.global.log_file, "/tmp/keep {} literal");
        assert_eq!(
            config
                .groups
                .iter()
                .map(|group| group.name.as_str())
                .collect::<Vec<_>>(),
            ["a:b", "a", "b"],
        );
        assert_eq!(
            config
                .subscriptions
                .iter()
                .map(|subscription| subscription.name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second", "third"],
        );
    }

    #[test]
    fn filter_quote_without_a_space_is_the_same_unterminated_quote() {
        // `filter:'x` and `filter: 'x` are one entry in dae's grammar; an
        // unterminated quote is the located lexer error in both spellings.
        for input in [
            "node {\n edge: 'socks5://127.0.0.1:1080'\n}\ngroup {\n proxy {\n filter:'unterminated\n }\n}",
            "node {\n edge: 'socks5://127.0.0.1:1080'\n}\ngroup {\n proxy {\n filter: 'unterminated\n }\n}",
        ] {
            let mut diagnostics = Vec::new();
            let config =
                parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
            assert!(config.groups[0].nodes.is_empty());
            assert_eq!(
                diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.code)
                    .collect::<Vec<_>>(),
                ["unterminated-quote"],
            );
            let diagnostic = &diagnostics[0];
            assert!(!diagnostic.terminal);
            assert_eq!(&input[diagnostic.span.clone().unwrap()], "'unterminated");
        }
    }
}
