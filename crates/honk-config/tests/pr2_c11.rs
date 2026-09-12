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
    let source = "dns {\n routing {\n  request {\n   qname(\n   a.example) -> reject\n  }\n }\n}";
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
        let error =
            parse_dae_config_with_detailed_diagnostics(&unclosed, &mut diagnostics).unwrap_err();
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
