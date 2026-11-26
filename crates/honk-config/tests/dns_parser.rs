mod scalar_syntax {
    use honk_config::error::ErrorCategory;
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    fn input(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/parser/dns/{name}.dae",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn dns_hosts_keep_glued_hash_data_and_source_order() {
        let source = input("k01-ordered-hosts");
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap();
        assert_eq!(
            config.dns.hosts,
            ["/etc/hosts", "/tmp/a#b", "agent # build", "/tmp/don't"]
        );
        let warnings: Vec<_> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "legacy-glued-hash")
            .collect();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].line, Some(3));
        assert_eq!(
            warnings[0].span.as_ref().unwrap().start,
            source.find('#').unwrap()
        );
    }

    #[test]
    fn dns_scalar_unterminated_quote_is_a_terminal_lexical_error() {
        let source = input("k05-scalar-quote");
        let mut diagnostics = Vec::new();
        parse_dae_config_with_detailed_diagnostics("dns {\n unknown: value\n}", &mut diagnostics)
            .unwrap();
        let prefix = diagnostics.clone();
        let error =
            parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap_err();
        let quote = source.find('\'').unwrap();
        let line_end = quote + source[quote..].find('\n').unwrap();
        assert_eq!(error.category, ErrorCategory::Parse);
        assert_eq!(error.diagnostic.code, "unterminated-quote");
        assert_eq!(error.diagnostic.line, Some(2));
        assert_eq!(error.diagnostic.span, Some(quote..line_end));
        assert_eq!(&diagnostics[..prefix.len()], prefix.as_slice());
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "unterminated-quote")
                .count(),
            1
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.terminal)
                .count(),
            1
        );
        let terminal = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.terminal)
            .unwrap();
        assert!(terminal.source.same_source(&error.diagnostic.source));
        assert!(!prefix[0].source.same_source(&error.diagnostic.source));
    }

    #[test]
    fn dns_scalar_quotes_remove_only_the_enclosing_pair() {
        let source = input("k14-scalar-quote-pair");
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap();
        assert_eq!(config.dns.hosts, ["\"hosts\""]);
    }

    #[test]
    fn bare_apostrophes_cannot_pair_across_a_comment_or_hide_the_closer() {
        let source = input("k05-bare-apostrophe-before-comment");
        let config = parse_dae_config_with_detailed_diagnostics(&source, &mut Vec::new()).unwrap();
        assert_eq!(config.dns.hosts, ["/tmp/don't"]);
    }
}

mod upstream_syntax {
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    #[test]
    fn upstream_comments_end_before_uri_and_detour_conversion() {
        let source = "dns {\n upstream {\n  plain: 'udp://8.8.8.8:53' # note\n  via: 'tls://1.1.1.1:853?tls_server_name=dns.example' -> proxy\t# note\n }\n}";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(source, &mut diagnostics).unwrap();
        let upstreams = &config.dns.upstream;
        assert_eq!(upstreams[0].address, "8.8.8.8:53");
        assert_eq!(upstreams[1].address, "1.1.1.1:853");
        assert_eq!(upstreams[1].outbound.as_deref(), Some("proxy"));
        assert_eq!(upstreams[1].tls_server_name.as_deref(), Some("dns.example"));
        let warnings: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.code == "legacy-upstream-comment")
            .collect();
        assert_eq!(
            warnings.iter().map(|d| d.line).collect::<Vec<_>>(),
            [Some(3), Some(4)]
        );
        for warning in warnings {
            assert_eq!(&source[warning.span.clone().unwrap()], "#");
        }
    }

    #[test]
    fn quoted_uri_separators_cannot_select_a_detour() {
        let source = "dns {\n upstream {\n  literal: 'https://dns.example/q?x=outbound:proxy#frag'\n  arrow: 'https://dns.example/q?x=->proxy' outbound: real\n  control: 'https://dns.example/q?x=outbound:data' -> real\n }\n}";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(source, &mut diagnostics).unwrap();
        assert_eq!(
            config.dns.upstream[0].address,
            "dns.example/q?x=outbound:proxy#frag"
        );
        assert_eq!(config.dns.upstream[0].outbound, None);
        assert_eq!(config.dns.upstream[1].address, "dns.example/q?x=->proxy");
        assert_eq!(config.dns.upstream[1].outbound.as_deref(), Some("real"));
        assert_eq!(
            config.dns.upstream[2].address,
            "dns.example/q?x=outbound:data"
        );
        assert_eq!(config.dns.upstream[2].outbound.as_deref(), Some("real"));
        assert_eq!(
            diagnostics
                .iter()
                .filter(|d| d.code == "legacy-upstream-separator")
                .map(|d| d.line)
                .collect::<Vec<_>>(),
            [Some(3), Some(4)]
        );
    }
}

mod ttl_syntax {
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    #[test]
    fn fixed_ttl_requires_one_decimal_scalar_after_unquoting() {
        let source = "dns {\n fixed_domain_ttl {\n  quoted: '60'\n  zero: 0\n  max: 4294967295\n  glued: 60#note\n  extra: 60 ignored\n  overflow: 4294967296\n  empty:\n  commented: 60 # note\n }\n}";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(source, &mut diagnostics).unwrap();
        let mut ttl: Vec<_> = config.dns.fixed_domain_ttl.into_iter().collect();
        ttl.sort();
        assert_eq!(
            ttl,
            [
                ("commented".into(), 60),
                ("max".into(), u32::MAX),
                ("quoted".into(), 60),
                ("zero".into(), 0)
            ]
        );
        assert_eq!(
            diagnostics
                .iter()
                .map(|d| (d.code, d.line))
                .collect::<Vec<_>>(),
            [
                ("legacy-ttl-quoting", Some(3)),
                ("invalid-ttl", Some(6)),
                ("trailing-value", Some(7)),
                ("invalid-ttl", Some(8)),
                ("invalid-ttl", Some(9)),
            ]
        );
        for diagnostic in diagnostics {
            assert!(diagnostic.span.is_some());
            assert!(diagnostic.byte_column.is_some());
        }
    }
}

mod routing_syntax {
    use honk_config::Config;
    use honk_config::diagnostic::DetailedDiagnostic;
    use honk_config::dns::{DnsCond, DnsDomainMatcher, DnsRequestAction, DnsResponseAction};
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    fn parse(source: &str) -> (Config, Vec<DetailedDiagnostic>) {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(source, &mut diagnostics).unwrap();
        (config, diagnostics)
    }

    fn assert_suffix(condition: &DnsCond, expected: &str) {
        let DnsCond::Qname { matchers, .. } = condition else {
            panic!("expected qname condition, got {condition:?}");
        };
        assert_eq!(matchers, &[DnsDomainMatcher::Suffix(expected.to_string())]);
    }

    #[test]
    fn frozen_request_and_response_hash_suffixes_keep_projected_bytes() {
        let (config, diagnostics) = parse(include_str!("fixtures/lexer/cls-dns-hash-in-quote.dae"));
        assert!(diagnostics.is_empty());
        let rule = &config.dns.routing.request.rules[0];
        assert_suffix(&rule.conditions[0], "a # b");
        assert_eq!(rule.action, DnsRequestAction::AsIs);

        let (config, diagnostics) = parse(include_str!(
            "fixtures/lexer/cls-dns-response-quoted-hash.dae"
        ));
        assert!(diagnostics.is_empty());
        let rule = &config.dns.routing.response.rules[0];
        assert_suffix(&rule.conditions[0], "a # b");
        assert_eq!(rule.action, DnsResponseAction::Accept);
    }

    #[test]
    fn glued_hash_then_tab_or_space_comment_preserves_rule_and_precedence() {
        let source = "dns {\n routing {\n  request {\n   qname(a#b) -> reject\t# tab comment\n   qname(c#d) -> reject # space comment // not a second comment\n  }\n }\n}";
        let (config, diagnostics) = parse(source);
        let rules = &config.dns.routing.request.rules;
        assert_eq!(rules.len(), 2);
        assert_suffix(&rules[0].conditions[0], "a#b");
        assert_suffix(&rules[1].conditions[0], "c#d");
        assert!(
            rules
                .iter()
                .all(|rule| rule.action == DnsRequestAction::Reject)
        );
        let hashes = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "legacy-dns-hash")
            .collect::<Vec<_>>();
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes
                .iter()
                .map(|diagnostic| diagnostic.line)
                .collect::<Vec<_>>(),
            [Some(4), Some(5)]
        );
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "legacy-slash-comment")
        );
    }

    #[test]
    fn slash_comment_is_not_silently_removed_from_dns_rule() {
        let source =
            "dns {\n routing {\n  request {\n   qname(a) -> asis // legacy comment\n  }\n }\n}";
        let (config, diagnostics) = parse(source);
        assert!(config.dns.routing.request.rules.is_empty());
        let warning = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "legacy-slash-comment")
            .expect("slash comment warning");
        assert_eq!(warning.line, Some(4));
        assert!(warning.span.is_some());
    }

    #[test]
    fn split_qname_call_emits_two_located_incomplete_warnings() {
        let source =
            "dns {\n routing {\n  request {\n   qname(\n   a.example) -> reject\n  }\n }\n}";
        let (config, diagnostics) = parse(source);
        assert!(config.dns.routing.request.rules.is_empty());
        let incomplete = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "incomplete-dns-rule")
            .collect::<Vec<_>>();
        assert_eq!(incomplete.len(), 2);
        assert_eq!(
            incomplete
                .iter()
                .map(|diagnostic| diagnostic.line)
                .collect::<Vec<_>>(),
            [Some(4), Some(5)]
        );
        assert!(
            incomplete
                .iter()
                .all(|diagnostic| diagnostic.span.is_some())
        );
    }

    #[test]
    fn trailing_call_suffix_rejects_the_whole_dns_rule() {
        let source = "dns {\n routing {\n  request {\n   qname(a)junk -> reject\n  }\n }\n}";
        let (config, diagnostics) = parse(source);
        assert!(config.dns.routing.request.rules.is_empty());
        let warning = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "trailing-matcher-text")
            .expect("trailing matcher warning");
        assert_eq!(warning.line, Some(4));
        assert!(warning.span.is_some());
    }

    #[test]
    fn dns_quote_shapes_match_lexical_recovery_contract() {
        for source in [
            include_str!("fixtures/cursor/k05-c-argument-multiline.dae"),
            include_str!("fixtures/cursor/k05-c-head-multiline.dae"),
            include_str!("fixtures/cursor/k05-c-argument-multiline-response.dae"),
            include_str!("fixtures/cursor/k05-c-head-multiline-response.dae"),
        ] {
            let (config, diagnostics) = parse(source);
            assert!(config.dns.routing.request.rules.is_empty());
            assert!(config.dns.routing.response.rules.is_empty());
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "unterminated-quote")
                    .count(),
                1
            );
            assert!(
                !diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "incomplete-dns-rule")
            );
            let unclosed = source.replacen("\n}\nrouting", "\nrouting", 1);
            let mut diagnostics = Vec::new();
            let error = parse_dae_config_with_detailed_diagnostics(&unclosed, &mut diagnostics)
                .unwrap_err();
            assert_eq!(error.diagnostic.code, "unterminated-quote");
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|d| d.code == "unterminated-quote")
                    .count(),
                1
            );
            assert!(!diagnostics.iter().any(|d| d.code == "incomplete-dns-rule"));
        }

        for source in [
            include_str!("fixtures/cursor/k05-c.dae"),
            include_str!("fixtures/cursor/k05-c-head.dae"),
            include_str!("fixtures/cursor/k05-c-response.dae"),
            include_str!("fixtures/cursor/k05-c-head-response.dae"),
        ] {
            let mut diagnostics = Vec::new();
            let error =
                parse_dae_config_with_detailed_diagnostics(source, &mut diagnostics).unwrap_err();
            assert_eq!(error.diagnostic.code, "unterminated-quote");
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "unterminated-quote")
                    .count(),
                1
            );
            assert!(
                !diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "incomplete-dns-rule")
            );
        }
    }

    #[test]
    fn literal_slash_arguments_are_not_action_comments() {
        let (config, _) = parse(
            "dns { routing { request {\n qname( //literal) -> reject\n } response {\n qname( //literal) -> accept\n } } }",
        );
        assert_eq!(config.dns.routing.request.rules.len(), 1);
        assert_eq!(config.dns.routing.response.rules.len(), 1);
        assert_suffix(
            &config.dns.routing.request.rules[0].conditions[0],
            "//literal",
        );
        assert_suffix(
            &config.dns.routing.response.rules[0].conditions[0],
            "//literal",
        );
    }

    #[test]
    fn comment_only_braces_do_not_report_a_changed_closer() {
        let (config, diagnostics) =
            parse("dns {\n # fixed_domain_ttl {\n # }\n max_cache_size: 123\n}");
        assert_eq!(config.dns.cache.max_size, 123);
        assert!(!diagnostics.iter().any(|d| d.code == "legacy-comment-brace"));
    }

    #[test]
    fn quoted_slashes_in_hash_comments_do_not_report_a_changed_rule() {
        let (config, diagnostics) =
            parse("dns { routing { request {\n qname(a) -> asis # '//'\n } } }");
        assert_eq!(
            config.dns.routing.request.rules[0].action,
            DnsRequestAction::AsIs
        );
        assert!(!diagnostics.iter().any(|d| d.code == "legacy-dns-hash"));
    }

    #[test]
    fn completed_quote_before_unquoted_slash_in_hash_comment_reports_changed_rule() {
        let source = "dns { routing { request {\n qname(a) -> asis # 'note' // tail\n } } }";
        let (config, diagnostics) = parse(source);
        assert_eq!(
            config.dns.routing.request.rules[0].action,
            DnsRequestAction::AsIs
        );
        let warning = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "legacy-dns-hash")
            .expect("legacy DNS hash warning");
        assert_eq!(&source[warning.span.clone().unwrap()], "#");
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "legacy-slash-comment")
        );
    }

    #[test]
    fn unicode_comment_gaps_keep_located_migration_notices() {
        let (config, diagnostics) = parse(
            "dns {\n upstream { v: 'udp://8.8.8.8:53'\u{a0}# comment\n }\n routing { request {\n qname(a#b) -> reject\u{a0}# comment\n } }\n}",
        );
        assert_eq!(config.dns.upstream[0].address, "8.8.8.8:53");
        assert_eq!(
            config.dns.routing.request.rules[0].action,
            DnsRequestAction::Reject
        );
        assert_eq!(
            diagnostics
                .iter()
                .map(|d| (d.code, d.line))
                .collect::<Vec<_>>(),
            [
                ("legacy-upstream-comment", Some(2)),
                ("legacy-dns-hash", Some(5))
            ]
        );
    }

    #[test]
    fn unknown_wrapper_headers_cannot_enable_dns_listeners() {
        for source in [
            "dns { bind: 127.0.0.1:53 { } }",
            "dns { bind: 127.0.0.1:53 {} }",
        ] {
            let (config, diagnostics) = parse(source);
            assert!(
                config.dns.bind.is_empty(),
                "unknown wrapper became a scalar binding: {source}"
            );
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|d| d.code == "unknown-block")
                    .count(),
                1
            );
        }
    }

    #[test]
    fn test_parse_dns_upstream_race_groups() {
        use honk_config::dns::DnsUpstreamGroup;

        let (config, diagnostics) = parse(
            r#"
dns {
    upstream {
        alidns: 'udp://223.5.5.5:53'
        dnspod: 'https://doh.pub/dns-query'
        fast: race(alidns, dnspod)
        'overseas fast': race("alidns", 'dnspod')
        literal_uri: 'race(alidns, dnspod)'
    }
    upstream {
        fast: race(dnspod, alidns)
        u1: '192.0.2.1:53'
        u2: '192.0.2.2:53'
        u3: '192.0.2.3:53'
        u4: '192.0.2.4:53'
        u5: '192.0.2.5:53'
        u6: '192.0.2.6:53'
        u7: '192.0.2.7:53'
        u8: '192.0.2.8:53'
        eight: race(u1, u2, u3, u4, u5, u6, u7, u8)
    }
}
"#,
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert!(
            config.dns.upstream.iter().all(|u| u.name != "default"),
            "explicit upstream block must clear default upstream"
        );
        assert!(
            config
                .dns
                .upstream
                .iter()
                .any(|u| u.name == "literal_uri" && u.address == "race(alidns, dnspod)"),
            "quoted race(...) must remain a literal URI"
        );
        assert_eq!(
            config.dns.upstream_groups,
            vec![
                DnsUpstreamGroup {
                    name: "fast".into(),
                    upstreams: vec!["dnspod".into(), "alidns".into()],
                },
                DnsUpstreamGroup {
                    name: "overseas fast".into(),
                    upstreams: vec!["alidns".into(), "dnspod".into()],
                },
                DnsUpstreamGroup {
                    name: "eight".into(),
                    upstreams: (1..=8).map(|i| format!("u{i}")).collect(),
                },
            ]
        );
    }

    #[test]
    fn test_parse_dns_upstream_race_rejects_malformed_declarations() {
        for bad in [
            "dns {\n upstream {\n  fast: race()\n }\n}",
            "dns {\n upstream {\n  fast: race(alidns)\n }\n}",
            "dns {\n upstream {\n  fast: race(u1, u2, u3, u4, u5, u6, u7, u8, u9)\n }\n}",
            "dns {\n upstream {\n  fast: race(alidns, )\n }\n}",
            "dns {\n upstream {\n  fast: race(, dnspod)\n }\n}",
            "dns {\n upstream {\n  fast: race(alidns, '')\n }\n}",
            "dns {\n upstream {\n  '': race(alidns, dnspod)\n }\n}",
            "dns {\n upstream {\n  fast: race(fast, alidns)\n }\n}",
            "dns {\n upstream {\n  fast: race(alidns, 'alidns')\n }\n}",
            "dns {\n upstream {\n  fast: race(alidns dnspod, cf)\n }\n}",
            "dns {\n upstream {\n  fast: race('alidns' extra, cf)\n }\n}",
            "dns {\n upstream {\n  fast: race(alidns, dnspod\n }\n}",
            "dns {\n upstream {\n  fast: race(alidns, dnspod) -> proxy\n }\n}",
            "dns {\n upstream {\n  fast: race(alidns, dnspod) outbound: proxy\n }\n}",
            "dns {\n upstream {\n  fast: race(alidns, dnspod) extra\n }\n}",
        ] {
            let mut diagnostics = Vec::new();
            let error = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
                bad,
                &mut diagnostics,
            )
            .expect_err(bad);
            assert_eq!(error.diagnostic.code, "invalid-dns-race", "{bad}");
            assert_eq!(error.diagnostic.line, Some(3), "{bad}");
        }
    }
}
