use super::*;
use crate::parser::{SourceLimits, parse_dae_sources};
use std::{path::PathBuf, sync::Arc};

fn managed_source(content: &str) -> super::super::LoadedConfig {
    parse_dae_sources(
        &[(PathBuf::from("main.dae"), Arc::from(content))],
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap()
}

#[test]
fn managed_appends_use_last_roots_and_preserve_literal_names_and_crlf() {
    let text = "include { 'child.dae' }\r\nnode {} # first\r\nsubscription {} # first\r\nnode {} # last\r\nsubscription {} # last\r\n# untouched\r\n";
    let loaded = managed_source(text);
    let name = "east's # }: node {";
    let edited = append_node_source(
        &loaded.sources[0],
        name,
        "socks5://127.0.0.1:1080#link-name",
    )
    .unwrap();
    assert_eq!(
        edited,
        text.replace(
            "node {} # last",
            "node {\r\n    \"east's # }: node {\": 'socks5://127.0.0.1:1080#link-name'\r\n} # last"
        )
    );
    let loaded = managed_source(&edited);
    assert_eq!(loaded.config.nodes[0].name, name);
    let edited = append_subscription_source(
        &loaded.sources[0],
        "paid # east",
        "https://example.test/sub?q=%2F#token",
        &SubscriptionOptions::default(),
    )
    .unwrap();
    assert_eq!(edited, loaded.sources[0].content.replace("subscription {} # last", "subscription {\r\n    'paid # east': 'https://example.test/sub?q=%2F#token'\r\n} # last"));
    let config = managed_source(&edited).config;
    assert_eq!(config.nodes.len(), 1);
    assert_eq!(config.subscriptions.len(), 1);
    assert_eq!(config.subscriptions[0].name, "paid # east");
    assert_eq!(
        config.subscriptions[0].url,
        "https://example.test/sub?q=%2F#token"
    );
}

#[test]
fn managed_appends_create_sections_after_unterminated_comments() {
    let loaded = managed_source("# preserved EOF comment");
    let edited = append_node_source(&loaded.sources[0], "node", "socks5://127.0.0.1:1080").unwrap();
    assert_eq!(
        edited,
        "# preserved EOF comment\nnode {\n    node: 'socks5://127.0.0.1:1080'\n}\n"
    );
    let loaded = managed_source(&edited);
    let edited = append_subscription_source(
        &loaded.sources[0],
        "provider",
        "https://example.test/sub",
        &SubscriptionOptions::default(),
    )
    .unwrap();
    let config = managed_source(&edited).config;
    assert_eq!(config.nodes[0].name, "node");
    assert_eq!(config.subscriptions[0].name, "provider");
    let loaded = managed_source(&edited);
    let edited = append_node_source(&loaded.sources[0], "mux", "socks5://127.0.0.1:1081").unwrap();
    assert!(edited.contains("    'mux': 'socks5://127.0.0.1:1081'\n"));
    assert_eq!(managed_source(&edited).config.nodes[1].name, "mux");
}

#[test]
fn managed_entries_write_bare_keys_and_delete_whole_lines() {
    for newline in ["\n", "\r\n"] {
        let text = format!(
            "node {{{newline}    a: 'socks5://127.0.0.1:1080'{newline}}}{newline}subscription {{{newline}    a: 'https://example.test/a'{newline}}}{newline}"
        );
        let loaded = managed_source(&text);
        let edited =
            append_node_source(&loaded.sources[0], "lab-1.b", "socks5://127.0.0.1:1081").unwrap();
        let loaded = managed_source(&edited);
        let edited = append_subscription_source(
            &loaded.sources[0],
            "lab_2",
            "https://example.test/b",
            &SubscriptionOptions::default(),
        )
        .unwrap();
        assert_eq!(
            edited,
            text.replace(
                "1080'",
                &format!("1080'{newline}    lab-1.b: 'socks5://127.0.0.1:1081'")
            )
            .replace(
                "test/a'",
                &format!("test/a'{newline}    lab_2: 'https://example.test/b'")
            )
        );
        let loaded = managed_source(&edited);
        let edited = remove_node_source(&loaded.sources[0], loaded.config.nodes[1].id)
            .unwrap()
            .unwrap();
        let loaded = managed_source(&edited);
        let edited = remove_subscription_source(
            &loaded.sources[0],
            &loaded.config.subscriptions[1],
            &loaded.config.assets,
        )
        .unwrap()
        .unwrap();
        assert_eq!(edited, text);
    }
}

#[test]
fn managed_appends_reject_injection_parse_skips_and_duplicate_identities() {
    let loaded = managed_source(
        "node { old: 'socks5://127.0.0.1:1080' }\nsubscription { old: 'https://example.test/old' }\n",
    );
    let source = &loaded.sources[0];
    for name in [
        "",
        " \t",
        "two'quotes\"",
        "trailing\\",
        "new\n}\nrouting { fallback: block }",
    ] {
        assert!(append_node_source(source, name, "socks5://127.0.0.1:1081").is_err());
        assert!(
            append_subscription_source(
                source,
                name,
                "https://example.test/new",
                &SubscriptionOptions::default()
            )
            .is_err()
        );
    }
    for link in [
        "unsupported://PRIVATE",
        "socks5://127.0.0.1:badport",
        "socks5://127.0.0.1:1081\nPRIVATE",
    ] {
        let error = append_node_source(source, "new", link).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("PRIVATE"));
    }
    for url in [
        "file:///PRIVATE",
        "https://",
        "https://example.test/PRIVATE\n}",
        "https://example.test/two'quotes\"",
    ] {
        assert!(
            append_subscription_source(source, "new", url, &SubscriptionOptions::default())
                .is_err()
        );
    }
    assert!(append_node_source(source, "old", "socks5://127.0.0.1:1081").is_err());
    assert!(append_node_source(source, "new", "socks5://127.0.0.1:1080#different-name").is_err());
    assert!(
        append_subscription_source(
            source,
            "old",
            "https://example.test/new",
            &SubscriptionOptions::default()
        )
        .is_err()
    );
}

#[test]
fn managed_node_deletion_uses_normalized_identity_and_keeps_nested_siblings() {
    let declaration = "'display # name': 'vless://00000000-0000-0000-0000-000000000001@example.test:443?security=tls&flow=xtls-rprx-vision-udp443'";
    let text = format!(
        "include {{ 'child.dae' }}\r\nnode {{\r\n wrapper {{\r\n  {declaration}# keep this comment\r\n  other: 'socks5://127.0.0.1:1080' # sibling\r\n }}\r\n}}\r\n"
    );
    let loaded = managed_source(&text);
    let id = crate::node::Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.test:443?security=tls&flow=xtls-rprx-vision#different-name").unwrap().id;
    assert_eq!(loaded.config.nodes[0].id, id);
    let edited = remove_node_source(&loaded.sources[0], id).unwrap().unwrap();
    assert_eq!(edited, text.replace(declaration, ""));
    let loaded = managed_source(&edited);
    assert_eq!(loaded.config.nodes.len(), 1);
    assert_eq!(loaded.config.nodes[0].name, "other");
    assert!(
        remove_node_source(&loaded.sources[0], id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn managed_subscription_options_write_a_block_that_reads_back_and_deletes_whole() {
    for newline in ["\n", "\r\n"] {
        let text =
            format!("subscription {{{newline}    a: 'https://example.test/a'{newline}}}{newline}");
        let loaded = managed_source(&text);
        let options = SubscriptionOptions {
            update_interval: Some(3600),
            user_agent: Some("east's agent/1.0"),
            cache: Some(false),
        };
        let edited =
            append_subscription_source(&loaded.sources[0], "b", "https://example.test/b", &options)
                .unwrap();
        assert_eq!(
            edited,
            text.replace(
                "a'",
                &format!(
                    "a'{newline}    b: 'https://example.test/b' {{{newline}        ua: \"east's agent/1.0\"{newline}        interval: 3600s{newline}        cache: false{newline}    }}"
                )
            )
        );
        let loaded = managed_source(&edited);
        let [first, added] = loaded.config.subscriptions.as_slice() else {
            panic!("two subscriptions");
        };
        assert!(first.cache);
        assert_eq!(first.update_interval, 86400);
        assert_eq!(added.name, "b");
        assert_eq!(added.url, "https://example.test/b");
        assert_eq!(added.user_agent.as_deref(), Some("east's agent/1.0"));
        assert_eq!(added.update_interval, 3600);
        assert!(!added.cache);
        let removed = remove_subscription_source(&loaded.sources[0], added, &loaded.config.assets)
            .unwrap()
            .unwrap();
        assert_eq!(removed, text);
        let manual = SubscriptionOptions {
            update_interval: Some(0),
            ..Default::default()
        };
        let edited =
            append_subscription_source(&loaded.sources[0], "c", "https://example.test/c", &manual)
                .unwrap();
        let config = managed_source(&edited).config;
        assert_eq!(config.subscriptions[2].update_interval, 0);
        assert!(config.subscriptions[2].cache);
        assert!(config.subscriptions[2].user_agent.is_none());
    }
    let loaded = managed_source("");
    let control = SubscriptionOptions {
        user_agent: Some("agent\r\nX-Injected: 1"),
        ..Default::default()
    };
    assert!(
        append_subscription_source(&loaded.sources[0], "d", "https://example.test/d", &control)
            .is_err()
    );
}

#[test]
fn managed_subscription_options_equal_to_built_in_defaults_override_assets() {
    let text = "subscription {\n    a: 'https://example.test/a'\n}\nassets {\n    subscription {\n        ua: 'clash.meta'\n        interval: 3600s\n        cache: false\n    }\n}\n";
    let loaded = managed_source(text);
    let options = SubscriptionOptions {
        update_interval: Some(86400),
        user_agent: None,
        cache: Some(true),
    };
    let edited =
        append_subscription_source(&loaded.sources[0], "b", "https://example.test/b", &options)
            .unwrap();
    assert!(
        edited.contains(
            "    b: 'https://example.test/b' {\n        interval: 86400s\n        cache: true\n    }"
        ),
        "{edited}"
    );
    let config = managed_source(&edited).config;
    let [first, added] = config.subscriptions.as_slice() else {
        panic!("two subscriptions");
    };
    assert_eq!(first.update_interval, 3600);
    assert!(!first.cache);
    assert_eq!(added.update_interval, 86400);
    assert!(added.cache);
    assert_eq!(added.user_agent.as_deref(), Some("clash.meta"));
}

#[test]
fn managed_subscription_deletion_matches_fetch_identity_not_parser_uuid() {
    let declaration = "'same # name': 'https://example.test/sub'('agent:A')";
    let text = format!(
        "subscription {{\r\n wrapper {{\r\n  {declaration}# keep\r\n  'same # name': 'https://example.test/sub'('agent:B') # sibling\r\n }}\r\n}}\r\n"
    );
    let loaded = managed_source(&text);
    let mut subscription = loaded.config.subscriptions[0].clone();
    subscription.id = uuid::Uuid::nil();
    subscription.node_count = 100;
    subscription.update_interval = 17;
    let edited =
        remove_subscription_source(&loaded.sources[0], &subscription, &loaded.config.assets)
            .unwrap()
            .unwrap();
    assert_eq!(edited, text.replace(declaration, ""));
    let remaining = managed_source(&edited);
    assert_eq!(remaining.config.subscriptions.len(), 1);
    assert_eq!(
        remaining.config.subscriptions[0].user_agent.as_deref(),
        Some("agent:B")
    );
    assert!(
        remove_subscription_source(
            &remaining.sources[0],
            &subscription,
            &remaining.config.assets
        )
        .unwrap()
        .is_none()
    );
    subscription.user_agent = Some("agent:B".into());
    subscription
        .headers
        .push(crate::subscription::SubscriptionHeader {
            key: "X-Fetch".into(),
            value: "different".into(),
        });
    assert!(
        remove_subscription_source(
            &remaining.sources[0],
            &subscription,
            &remaining.config.assets
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn managed_subscription_deletion_owns_blocks_but_not_legacy_wrapper_headers() {
    let declaration =
        "'paid # tag': {\n wrapper { url: 'https://example.test/sub' }\n interval: 30s\n}";
    let text = format!(
        "subscription {{\n {declaration} # keep\n empty: {{}} sibling: {{ url: 'https://example.test/other' }}\n}}\n"
    );
    let loaded = managed_source(&text);
    let mut subscription = loaded.config.subscriptions[0].clone();
    subscription.user_agent = Some(String::new());
    let edited =
        remove_subscription_source(&loaded.sources[0], &subscription, &loaded.config.assets)
            .unwrap()
            .unwrap();
    assert_eq!(edited, text.replace(declaration, ""));
    let loaded = managed_source(&edited);
    assert_eq!(
        loaded
            .config
            .subscriptions
            .iter()
            .map(|sub| sub.name.as_str())
            .collect::<Vec<_>>(),
        ["empty", "sibling"]
    );
    let edited = remove_subscription_source(
        &loaded.sources[0],
        &loaded.config.subscriptions[0],
        &loaded.config.assets,
    )
    .unwrap()
    .unwrap();
    assert_eq!(edited, loaded.sources[0].content.replace("empty: {}", ""));
    assert_eq!(
        managed_source(&edited).config.subscriptions[0].name,
        "sibling"
    );
    let legacy =
        managed_source("subscription {\n a: b: {\n url: 'https://example.test/sub'\n }\n}\n");
    assert!(
        remove_subscription_source(
            &legacy.sources[0],
            &legacy.config.subscriptions[0],
            &legacy.config.assets
        )
        .is_err()
    );
}

#[test]
fn managed_deletion_rejects_duplicate_declarations_and_never_edits_includes() {
    let text = "node {\n one: 'socks5://127.0.0.1:1080'\n two: 'socks5://127.0.0.1:1080'\n}\nsubscription {\n same: 'https://example.test/sub'\n same: 'https://example.test/sub'\n}\n";
    let loaded = managed_source(text);
    assert!(remove_node_source(&loaded.sources[0], loaded.config.nodes[0].id).is_err());
    assert!(
        remove_subscription_source(
            &loaded.sources[0],
            &loaded.config.subscriptions[0],
            &loaded.config.assets
        )
        .is_err()
    );
    let sources = parse_dae_sources(
        &[
            (
                PathBuf::from("main.dae"),
                Arc::from("include { 'child.dae' }"),
            ),
            (PathBuf::from("child.dae"), Arc::from(text)),
        ],
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    assert!(
        remove_node_source(&sources.sources[0], sources.config.nodes[0].id)
            .unwrap()
            .is_none()
    );
    assert!(
        remove_subscription_source(
            &sources.sources[0],
            &sources.config.subscriptions[0],
            &sources.config.assets
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn managed_subscription_deletion_inherits_assets_declared_in_an_include() {
    let sources = parse_dae_sources(
        &[
            (
                PathBuf::from("main.dae"),
                Arc::from(
                    "include { 'assets.dae' }\nsubscription {\n feed: 'https://example.test/sub'\n}\n",
                ),
            ),
            (
                PathBuf::from("assets.dae"),
                Arc::from("assets {\n subscription {\n ua: 'agent:A'\n }\n}\n"),
            ),
        ],
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    let subscription = &sources.config.subscriptions[0];
    assert_eq!(subscription.user_agent.as_deref(), Some("agent:A"));
    let edited =
        remove_subscription_source(&sources.sources[0], subscription, &sources.config.assets)
            .unwrap()
            .unwrap();
    assert!(!edited.contains("feed:"));
}

#[test]
fn exact_group_edit_preserves_crlf_comments_includes_and_last_winners() {
    let main = "include { 'child.dae' }\r\ngroup { G { policy: fallback } }\r\n";
    let child = "# untouched\r\ngroup {\r\n  G {\r\n    policy: 'fallback' # old\r\n    policy: \"urltest\" # winner\r\n    tolerance: 4\r\n    tolerance: 9 # repeated\r\n  }\r\n}\r\n";
    let loaded = parse_dae_sources(
        &[
            (PathBuf::from("main.dae"), Arc::from(main)),
            (PathBuf::from("child.dae"), Arc::from(child)),
        ],
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(source_indices(&loaded.sources).unwrap().0["G"], 1);
    let edited = edit_group_source(
        &loaded.sources[1],
        "G",
        &[
            (GroupField::Policy, Some("selector".into())),
            (GroupField::Tolerance, None),
            (GroupField::Final, Some("block".into())),
        ],
    )
    .unwrap();
    assert_eq!(
        edited,
        child
            .replace("\"urltest\"", "\"selector\"")
            .replace("    tolerance: 4\r\n", "")
            .replace("tolerance: 9", "")
            .replace("  }\r\n}", "      final: 'block'\r\n  }\r\n}")
    );
    let config = crate::parser::parse_dae_config(&edited).unwrap();
    assert_eq!(config.groups[0].policy, crate::node::GroupPolicy::Selector);
    assert_eq!(loaded.sources[0].content.as_ref(), main);
    let empty = parse_dae_sources(
        &[(PathBuf::from("empty.dae"), Arc::from("group { G {} }"))],
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    let added = edit_group_source(
        &empty.sources[0],
        "G",
        &[(GroupField::Final, Some("block".into()))],
    )
    .unwrap();
    assert_eq!(
        crate::parser::parse_dae_config(&added).unwrap().groups[0]
            .final_outbound
            .as_deref(),
        Some("block")
    );
}

#[test]
fn group_check_url_edits_add_replace_and_remove_quoted_values() {
    let parse = |text: &str| {
        parse_dae_sources(
            &[(PathBuf::from("main.dae"), Arc::from(text))],
            SourceLimits::default(),
            &mut Vec::new(),
        )
        .unwrap()
    };
    let check_url = |text: &str| {
        crate::parser::parse_dae_config(text).unwrap().groups[0]
            .check_url
            .clone()
    };
    let url = "https://example.test/generate_204?a=1#x";
    let empty = "group {\n  G {\n    policy: urltest\n  }\n}\n";
    let added = edit_group_source(
        &parse(empty).sources[0],
        "G",
        &[(GroupField::CheckUrl, Some(url.into()))],
    )
    .unwrap();
    assert_eq!(
        added,
        empty.replace("  }\n}", &format!("      check_url: '{url}'\n  }}\n}}"))
    );
    assert_eq!(check_url(&added).as_deref(), Some(url));
    let quoted =
        "group {\n  G {\n    policy: urltest\n    check_url: \"http://old.test/\" # kept\n  }\n}\n";
    let apostrophe = "http://example.test/it's";
    let replaced = edit_group_source(
        &parse(quoted).sources[0],
        "G",
        &[(GroupField::CheckUrl, Some(apostrophe.into()))],
    )
    .unwrap();
    assert_eq!(replaced, quoted.replace("http://old.test/", apostrophe));
    assert_eq!(check_url(&replaced).as_deref(), Some(apostrophe));
    let removed = edit_group_source(
        &parse(quoted).sources[0],
        "G",
        &[(GroupField::CheckUrl, None)],
    )
    .unwrap();
    assert_eq!(
        removed,
        quoted.replace("check_url: \"http://old.test/\"", "")
    );
    assert_eq!(check_url(&removed), None);
}

#[test]
fn group_scalars_keep_inheritance_and_icons_keep_exact_values() {
    for icon in [
        "https://example.test/icon.svg?q=%2F",
        "data:image/svg+xml,%3Csvg/%3E",
    ] {
        let config = crate::parser::parse_dae_config(&format!("group {{\n inherited {{ policy: urltest }}\n explicit {{\n policy: urltest\n tolerance: 7\n idle_timeout: 0\n interrupt_connections: true\n icon: '{icon}'\n }}\n}}\nglobal {{ check_tolerance: 123ms }}")).unwrap();
        assert_eq!(config.groups[0].tolerance, 123);
        assert_eq!(config.groups[1].tolerance, 7);
        assert_eq!(config.groups[1].idle_timeout, Some(0));
        assert!(config.groups[1].interrupt_connections);
        assert_eq!(config.groups[1].icon.as_deref(), Some(icon));
        config.validate_detailed().unwrap();
    }
    for icon in [
        "javascript:PRIVATE",
        "https://PRIVATE@example.test/icon",
        "/PRIVATE/icon",
        "data:PRIVATE",
        &format!("https://example.test/{}", "x".repeat(2048)),
    ] {
        let error = crate::parser::parse_dae_config_with_detailed_diagnostics(
            &format!("group {{ G {{ icon: '{icon}' }} }}"),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(!format!("{error:?}").contains("PRIVATE"));
        let config = crate::Config {
            groups: vec![crate::node::Group {
                name: "G".into(),
                icon: Some(icon.into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(config.validate_detailed().is_err());
        assert!(config.validate_assembled().is_err());
    }
    for (setting, path) in [
        ("tolerance: -1", "groups[2].tolerance"),
        ("idle_timeout: 1.5", "groups[2].idle_timeout"),
        (
            "interrupt_connections: maybe",
            "groups[2].interrupt_connections",
        ),
        ("icon { ignored: value }", "groups[2].icon"),
        ("icon: 'data:x'", "groups[2].icon"),
    ] {
        let error = crate::parser::parse_dae_config_with_detailed_diagnostics(
            &format!("group {{ F {{}} G {{ {setting} }} }}"),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.diagnostic.setting.to_string(), path, "{setting}");
    }
}

#[test]
fn listener_secrets_strip_and_restore_by_span() {
    let main = "include { 'child.dae' }\nglobal { log_level: info }\nexperimental {\n    native_api {\n        enabled: true\n        secret: 'first-native-token'\n        secret: \"override-native-token\" # kept comment\n    }\n    clash_api {\n        external_controller: '127.0.0.1:9090'\n        secret: \"clash token with spaces\"\n    }\n}\n";
    let child = "experimental { native_api { secret: final-native-token } }";
    let inputs = |main: &str, child: &str| {
        parse_dae_sources(
            &[
                (PathBuf::from("main.dae"), Arc::from(main)),
                (PathBuf::from("child.dae"), Arc::from(child)),
            ],
            SourceLimits::default(),
            &mut Vec::new(),
        )
        .unwrap()
    };
    let original = inputs(main, child);
    let native = original.config.experimental.native_api.secret.clone();
    let clash = original.config.experimental.clash_api.secret.clone();
    assert_eq!(
        (native.as_str(), clash.as_str()),
        ("final-native-token", "clash token with spaces")
    );

    let stripped_main = strip_listener_secrets(main).unwrap();
    let stripped_child = strip_listener_secrets(child).unwrap();
    for text in [&stripped_main, &stripped_child] {
        assert!(!text.contains("token"));
    }
    assert!(stripped_main.contains("# kept comment"));
    let stripped = inputs(&stripped_main, &stripped_child);
    assert!(
        stripped
            .sources
            .iter()
            .all(|source| !source.contains_api_secret)
    );
    let mut resupplied = stripped.config.clone();
    resupplied.experimental.native_api.secret = native.clone();
    resupplied.experimental.clash_api.secret = clash.clone();
    assert_eq!(resupplied, original.config);

    let inlined = inline_sources(&original.sources).unwrap();
    assert!(!inlined.contains("include"));
    assert_eq!(
        crate::parser::parse_dae_config(&inlined).unwrap(),
        original.config
    );

    let restored =
        restore_listener_secrets(&inline_sources(&stripped.sources).unwrap(), &native, &clash)
            .unwrap();
    assert_eq!(
        crate::parser::parse_dae_config(&restored).unwrap(),
        original.config
    );
    assert!(restore_listener_secrets(main, &native, &clash).is_err());
}

#[test]
fn restored_listener_secrets_preserve_quotes_and_backslashes() {
    for secret in [
        r#"abc'def"ghi"#,
        r"trailing\",
        r"trailing\\",
        r#"abc\'def\"ghi"#,
        r#"abc'def"ghi#suffix"#,
    ] {
        let original = format!(
            "global {{ log_level: debug }}\nexperimental {{\n native_api {{\n  enabled: true\n  secret: {secret}\n }}\n clash_api {{\n  secret: {secret}\n }}\n}}\n"
        );
        let expected = crate::parser::parse_dae_config(&original).unwrap();
        expected.validate_detailed().unwrap();
        assert_eq!(expected.experimental.native_api.secret, secret);
        assert_eq!(expected.experimental.clash_api.secret, secret);
        let restored =
            restore_listener_secrets(&strip_listener_secrets(&original).unwrap(), secret, secret)
                .unwrap();
        assert_eq!(
            crate::parser::parse_dae_config(&restored).unwrap(),
            expected
        );
    }
    let content = "experimental { native_api {} clash_api {} }\n";
    for secret in [
        "abc'def\"ghi\nrecord_flows: false",
        "abc'def\"ghi\r}",
        "abc'def\"ghi\0",
        r#"abc'def"ghi } } global { log_level: error }"#,
        r#"abc'def"ghi {}"#,
        r#"abc'def"ghi # truncated"#,
        r#"abc'def"ghi "#,
    ] {
        assert!(restore_listener_secrets(content, secret, "").is_err());
        assert!(restore_listener_secrets(content, "", secret).is_err());
    }
}

#[test]
fn restored_secret_in_a_compact_block_parses() {
    let restored = restore_listener_secrets(
        "experimental { native_api { enabled: true } }\n",
        "compact-native-token",
        "",
    )
    .unwrap();
    let config = crate::parser::parse_dae_config(&restored).unwrap();
    assert!(config.experimental.native_api.enabled);
    assert_eq!(
        config.experimental.native_api.secret,
        "compact-native-token"
    );
}

#[test]
fn routing_positions_follow_parser_ordinals_across_includes() {
    let first = "routing {\r\n # not a rule\r\n domain(\r\n 'example.test'\r\n ) -> direct\r\n fallback: direct\r\n}\r\n";
    let second = "routing {\n ignored\n dport(443) -> block\n fallback: block\n}\n";
    let loaded = parse_dae_sources(
        &[
            (PathBuf::from("main.dae"), Arc::from(first)),
            (PathBuf::from("child.dae"), Arc::from(second)),
        ],
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    let index = source_indices(&loaded.sources).unwrap().1;
    assert_eq!(index.rules.len(), loaded.config.routing.rules.len());
    assert_eq!((index.rules[0].source_index, index.rules[0].line), (0, 3));
    assert_eq!(
        &first[index.rules[0].bytes.clone()],
        "domain(\r\n 'example.test'\r\n ) -> direct"
    );
    assert_eq!((index.rules[1].source_index, index.rules[1].line), (1, 3));
    let fallback = index.fallback.unwrap();
    assert_eq!(fallback.source_index, 1);
    assert_eq!(fallback.expression, "fallback: block");
}
