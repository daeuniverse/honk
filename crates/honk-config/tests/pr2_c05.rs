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

fn count_code(diagnostics: &[honk_config::diagnostic::DetailedDiagnostic], code: &str) -> usize {
    diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == code)
        .count()
}

#[test]
fn quoted_subscription_tag_and_user_agent_keep_exact_bytes() {
    let (config, diagnostics) = parse(include_str!(
        "fixtures/pr2/c05/ctl-sub-quoted-spaced-hash.dae"
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
        "fixtures/pr2/c05/cls-sub-quoted-tag-inside.dae"
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
    let input = include_str!("fixtures/pr2/c05/cls-sub-ua-glued-hash.dae");
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
    let input = include_str!("fixtures/pr2/c05/cls-sub-ua-with-hash.dae");
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
    let (config, diagnostics) = parse(include_str!("fixtures/pr2/c05/ctl-node-spaced-tag.dae"));
    assert_eq!(
        config
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["edge", "edge west"]
    );
    assert_eq!(count_code(&diagnostics, "entry-tag-normalized"), 1);

    let (config, diagnostics) = parse(include_str!("fixtures/pr2/c05/ctl-sub-spaced-tag.dae"));
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
        "fixtures/pr2/c05/equiv-subscription-block-nested-close.dae"
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
    let (config, diagnostics) = parse(include_str!("fixtures/pr2/c05/ctl-node-nested-wrapper.dae"));
    assert_eq!(config.nodes.len(), 1);
    assert_eq!(config.nodes[0].name, "a");
    assert_eq!(count_code(&diagnostics, "legacy-wrapper"), 1);

    let (config, diagnostics) = parse(include_str!(
        "fixtures/pr2/c05/ctl-subscription-nested-wrapper.dae"
    ));
    assert_eq!(config.subscriptions.len(), 1);
    assert_eq!(config.subscriptions[0].name, "a");
    assert_eq!(count_code(&diagnostics, "legacy-wrapper"), 1);
}

#[test]
fn tagless_subscription_names_and_quoted_ua_are_derived_without_boundary_errors() {
    let (config, diagnostics) = parse(include_str!("fixtures/pr2/c05/cls-sub-tagless-ua.dae"));
    assert_eq!(config.subscriptions[0].name, "example.org");
    assert_eq!(config.subscriptions[0].url, "https://example.org/sub");
    assert_eq!(
        config.subscriptions[0].user_agent.as_deref(),
        Some("provider/2.0")
    );
    assert_eq!(count_code(&diagnostics, "legacy-ua-boundary"), 0);

    let (config, diagnostics) = parse(include_str!("fixtures/pr2/c05/cls-sub-tagless-quoted.dae"));
    assert_eq!(config.subscriptions[0].name, "example.org");
    assert_eq!(config.subscriptions[0].url, "https://example.org/sub");
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
}

#[test]
fn glued_hash_after_a_quoted_node_link_retains_both_nodes_and_warns_once() {
    let input = include_str!("fixtures/pr2/c05/ctl-node-glued-hash-after-quote.dae");
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
        "fixtures/pr2/c05/ctl-subscription-double-colon-header.dae"
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
