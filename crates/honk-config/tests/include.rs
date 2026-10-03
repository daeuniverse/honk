use std::fs;

use honk_config::{Config, ConfigError};

fn write(path: &std::path::Path, content: &str) {
    fs::write(path, content)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
}

#[test]
fn include_loads_nested_globs_and_merges_sections() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("config files")).unwrap();
    fs::create_dir_all(root.join("config.d")).unwrap();
    fs::create_dir_all(root.join("fragments")).unwrap();

    let absolute = root.join("absolute.dae");
    write(
        &root.join("config files/base config.dae"),
        r#"
include {
    fragments/nested.dae
}

global {
    log_level: info
}

node {
    base: 'socks5://127.0.0.1:1080'
}
"#,
    );
    write(
        &root.join("fragments/nested.dae"),
        r#"
group {
    proxy {
        filter: name('base')
        policy: select
    }
}
"#,
    );
    write(
        &absolute,
        r#"
node {
    absolute: 'socks5://127.0.0.1:1081'
}
"#,
    );
    write(
        &root.join("config.d/10-dns.dae"),
        r#"
dns {
    ipversion_prefer: 4
    upstream {
        first: 'udp://1.1.1.1:53'
    }
    routing {
        request {
            qtype(a) -> first
            fallback: first
        }
    }
}
"#,
    );
    write(
        &root.join("config.d/20-routes.dae"),
        r#"
global {
    log_level: debug
}

node {
    extra: 'socks5://127.0.0.1:1082'
}

routing {
    dport(443) -> proxy
    fallback: proxy
}

dns {
    upstream {
        second: 'udp://8.8.8.8:53'
    }
    routing {
        request {
            qtype(aaaa) -> second
            fallback: second
        }
    }
    ipversion_prefer: 6
}
"#,
    );
    write(&root.join("ignored.txt"), "this is not dae syntax");

    write(
        &root.join("config.dae"),
        &format!(
            r#"
include {{ 'config files/base config.dae' '{}' config.d/*.dae missing/*.dae ignored.txt }}

global {{
    tproxy_port: 32123
    log_level: warn
}}

routing {{
    dport(80) -> direct
}}
"#,
            absolute.display()
        ),
    );

    let config = Config::from_file(root.join("config.dae").to_str().unwrap()).unwrap();

    // The root is merged first, then each include in declaration and glob
    // order.  A later scalar changes only that key, rather than resetting the
    // rest of global.
    assert_eq!(config.global.tproxy_port, 32123);
    assert_eq!(config.global.log_level, "debug");
    assert_eq!(
        config
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        vec!["base", "absolute", "extra"]
    );

    let group = config
        .groups
        .iter()
        .find(|group| group.name == "proxy")
        .unwrap();
    let base = config
        .nodes
        .iter()
        .find(|node| node.name == "base")
        .unwrap();
    assert_eq!(group.nodes, vec![base.id]);

    assert_eq!(
        config
            .routing
            .rules
            .iter()
            .map(|rule| rule.outbound.as_str())
            .collect::<Vec<_>>(),
        vec!["direct", "proxy"]
    );
    assert_eq!(config.routing.default_outbound, "proxy");
    assert_eq!(
        config
            .dns
            .upstream
            .iter()
            .map(|upstream| upstream.name.as_str())
            .collect::<Vec<_>>(),
        vec!["first", "second"]
    );
    assert_eq!(config.dns.routing.request.rules.len(), 2);
    assert_eq!(config.dns.routing.fallback, "second");
    assert!(matches!(
        config.dns.strategy,
        honk_config::dns::DnsStrategy::PreferIpv6
    ));
}

#[test]
fn marked_fallback_follows_all_included_rules_and_last_fallback_wins() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        &root.join("config.dae"),
        "include { child.dae }\nrouting {\n fallback: direct(mark: 0x100, must)\n dport(80) -> block\n}",
    );
    for (child_fallback, expected_mark, expected_must) in [
        ("", 0x100, true),
        ("fallback: direct(mark: 512)", 512, false),
        ("default: direct(must, mark: 0x300)", 0x300, true),
        ("fallback: direct", 0, false),
    ] {
        write(
            &root.join("child.dae"),
            &format!("routing {{\n dport(443) -> direct\n {child_fallback}\n}}"),
        );
        let config = Config::from_file(root.join("config.dae").to_str().unwrap()).unwrap();
        assert_eq!(config.routing.rules.len(), 2);
        assert_eq!(config.routing.rules[0].condition.port, ["80"]);
        assert_eq!(config.routing.rules[0].outbound.as_str(), "block");
        assert_eq!(config.routing.rules[1].condition.port, ["443"]);
        assert_eq!(config.routing.rules[1].outbound.as_str(), "direct");
        assert_eq!(
            (
                config.routing.default_outbound.as_str(),
                config.routing.default_mark,
                config.routing.default_must
            ),
            ("direct", expected_mark, expected_must)
        );
    }
}

#[test]
fn include_rejects_cycles_and_paths_outside_the_entry_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir_all(&root).unwrap();

    write(
        &dir.path().join("outside.dae"),
        "global {\n    log_level: info\n}\n",
    );
    write(
        &root.join("escape.dae"),
        "include { ../outside.dae }\nglobal {\n}\n",
    );
    let err = Config::from_file(root.join("escape.dae").to_str().unwrap()).unwrap_err();
    assert!(matches!(err, ConfigError::Include(_)));

    write(
        &root.join("config.dae"),
        "include { child.dae }\nglobal {\n}\n",
    );
    write(
        &root.join("child.dae"),
        "include { config.dae }\nnode {\n}\n",
    );
    let err = Config::from_file(root.join("config.dae").to_str().unwrap()).unwrap_err();
    assert!(matches!(err, ConfigError::Include(_)));
}

#[test]
fn include_preserves_renamed_honk_policy_error() {
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir.path().join("config.dae"),
        "include { child.dae }\nglobal {\n}\n",
    );
    write(
        &dir.path().join("child.dae"),
        "group {\n proxy {\n policy: honk\n }\n}\n",
    );

    let error = Config::from_file(dir.path().join("config.dae").to_str().unwrap()).unwrap_err();
    assert!(matches!(error, ConfigError::UnsupportedPolicy(_)));
}

#[cfg(unix)]
#[test]
fn include_rejects_symlinks_that_escape_the_entry_directory() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir_all(&root).unwrap();
    let outside = dir.path().join("outside.dae");
    write(&outside, "global {\n    log_level: info\n}\n");
    symlink(&outside, root.join("linked.dae")).unwrap();
    write(
        &root.join("config.dae"),
        "include { linked.dae }\nglobal {\n}\n",
    );

    let err = Config::from_file(root.join("config.dae").to_str().unwrap()).unwrap_err();
    assert!(matches!(err, ConfigError::Include(_)));
}

#[test]
fn include_glued_hash_is_literal_in_file_and_string_modes() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("config.dae");
    write(
        &dir.path().join("cut.dae"),
        "node { cut: 'socks5://127.0.0.1:1080' }",
    );
    write(
        &dir.path().join("literal#name.dae"),
        "global { log_level: debug }",
    );
    write(
        &dir.path().join("quoted # name.dae"),
        "global { tproxy_port: 32123 }",
    );
    let input = "include {\n cut.dae#note\n literal#name.dae # ignored }\n 'quoted # name.dae'\n}\nglobal { log_level: warn }";
    write(&entry, input);

    let mut diagnostics = Vec::new();
    let config =
        Config::from_file_with_detailed_diagnostics(entry.to_str().unwrap(), &mut diagnostics)
            .unwrap();
    assert_eq!(config.global.log_level, "debug");
    assert_eq!(config.global.tproxy_port, 32123);
    assert!(
        config.nodes.is_empty(),
        "a glued hash must not open the truncated path"
    );
    let hashes = diagnostics
        .iter()
        .filter(|d| d.code == "legacy-include-hash")
        .map(|d| (d.line, d.byte_column))
        .collect::<Vec<_>>();
    assert_eq!(hashes, [(Some(2), Some(9)), (Some(3), Some(9))]);
    assert_eq!(diagnostics.len(), hashes.len());

    let mut diagnostics = Vec::new();
    let config =
        honk_config::parser::parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics)
            .unwrap();
    assert_eq!(config.global.log_level, "warn");
    assert_eq!(
        diagnostics
            .iter()
            .filter(|d| d.code == "legacy-include-hash")
            .count(),
        2
    );
    assert_eq!(diagnostics.len(), 2);
}

#[test]
fn include_split_opener_keeps_bounded_file_capture() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("config.dae");
    write(
        &dir.path().join("first.dae"),
        "global { tproxy_port: 32123 }",
    );
    write(
        &dir.path().join("second.dae"),
        "global { log_level: debug }",
    );
    let input = "include # header\r\n# between\r\n{\r\n 'first.dae''second.dae' # }\r\n}\r\nglobal { log_level: warn }";
    write(&entry, input);
    let mut diagnostics = Vec::new();
    let config =
        Config::from_file_with_detailed_diagnostics(entry.to_str().unwrap(), &mut diagnostics)
            .unwrap();
    assert_eq!(config.global.tproxy_port, 32123);
    assert_eq!(config.global.log_level, "debug");
    let opener = diagnostics
        .iter()
        .find(|d| d.code == "legacy-include-opener")
        .unwrap();
    assert_eq!((opener.line, opener.byte_column), (Some(3), Some(1)));

    write(&entry, "include\n{}\nglobal { log_level: warn }");
    let mut diagnostics = Vec::new();
    let config =
        Config::from_file_with_detailed_diagnostics(entry.to_str().unwrap(), &mut diagnostics)
            .unwrap();
    assert_eq!(config.global.log_level, "warn");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].code, "legacy-include-opener");
    assert_eq!(diagnostics[0].line, Some(2));

    write(
        &entry,
        "include#note\n{\n first.dae\n}\nglobal { log_level: warn }",
    );
    assert!(Config::from_file(entry.to_str().unwrap()).is_err());

    write(
        &entry,
        "include { 'unterminated.dae\n}\nglobal { log_level: warn }",
    );
    let mut diagnostics = Vec::new();
    let error =
        Config::from_file_with_detailed_diagnostics(entry.to_str().unwrap(), &mut diagnostics)
            .unwrap_err();
    assert_eq!(error.category, honk_config::error::ErrorCategory::Include);
    assert_eq!(
        diagnostics
            .iter()
            .filter(|d| d.code == "unterminated-quote")
            .count(),
        1
    );
}

#[test]
fn adjacent_include_quotes_protect_filename_punctuation_without_leaking() {
    for name in [
        "quoted # name.dae",
        "quoted { name.dae",
        "quoted } name.dae",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path().join("config.dae");
        write(
            &dir.path().join("first.dae"),
            "global { tproxy_port: 32123 }",
        );
        write(&dir.path().join(name), "global { check_tolerance: 75ms }");
        write(
            &entry,
            &format!(
                "include {{\n 'first.dae''{name}' # {{ }}\n}}\nglobal {{\n log_file: 'one''two # comment\n}}\n"
            ),
        );
        let mut diagnostics = Vec::new();
        let config =
            Config::from_file_with_detailed_diagnostics(entry.to_str().unwrap(), &mut diagnostics)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(config.global.tproxy_port, 32123);
        assert_eq!(config.global.check_tolerance_ms, 75);
        assert_eq!(config.global.log_file, "'one''two");
        assert!(diagnostics.is_empty(), "{name}: {diagnostics:?}");
    }
}

#[test]
fn adjacent_include_quote_errors_are_structural_in_string_mode() {
    let input = "include {\n 'first.dae''unterminated\n}\n";
    let mut diagnostics = Vec::new();
    let error =
        honk_config::parser::parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics)
            .unwrap_err();
    assert_eq!(error.diagnostic.code, "unterminated-quote");
    assert_eq!(error.diagnostic.line, Some(2));
    assert_eq!(
        error.diagnostic.span.as_ref().unwrap().start,
        input.find("''").unwrap() + 1
    );
    assert_eq!(
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.terminal)
            .count(),
        1
    );
}

#[test]
fn include_adjacent_quotes_stop_at_bare_path_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("config.dae");
    write(
        &dir.path().join("first.dae"),
        "global { tproxy_port: 32123 }",
    );
    write(
        &dir.path().join("a('x''y.dae"),
        "global { log_level: debug }",
    );
    write(&entry, "include { 'first.dae'a('x''y.dae }");
    let config = Config::from_file(entry.to_str().unwrap()).unwrap();
    assert_eq!(config.global.tproxy_port, 32123);
    assert_eq!(config.global.log_level, "debug");
}

#[test]
fn empty_included_files_contribute_no_sections() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("config.dae");
    write(&dir.path().join("empty.dae"), "");
    write(&dir.path().join("comment.dae"), "# optional fragment { }\n");
    write(
        &entry,
        "include { empty.dae comment.dae }\nglobal { tproxy_port: 34567 }",
    );
    let mut diagnostics = Vec::new();
    let config =
        Config::from_file_with_detailed_diagnostics(entry.to_str().unwrap(), &mut diagnostics)
            .unwrap();
    assert_eq!(config.global.tproxy_port, 34567);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
}

#[test]
fn fragment_format_recognition_stays_at_the_entry_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("config.dae");
    let fragment = dir.path().join("fragment.dae");
    write(&fragment, "future_statement\n");
    write(
        &entry,
        "include { fragment.dae }\nglobal { tproxy_port: 34567 }",
    );
    let mut diagnostics = Vec::new();
    let config =
        Config::from_file_with_detailed_diagnostics(entry.to_str().unwrap(), &mut diagnostics)
            .unwrap();
    assert_eq!(config.global.tproxy_port, 34567);
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>(),
        ["unknown-statement"]
    );
    let standalone = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        "future_statement",
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(standalone.diagnostic.code, "not-dae-config");

    write(&fragment, "global {\n");
    let error =
        Config::from_file_with_detailed_diagnostics(entry.to_str().unwrap(), &mut Vec::new())
            .unwrap_err();
    assert_eq!(error.category, honk_config::error::ErrorCategory::Include);
    assert_eq!(error.diagnostic.code, "unclosed-block");

    write(&entry, "include { fragment.dae {} }");
    write(&fragment, "global {}");
    assert_eq!(
        Config::from_file_with_detailed_diagnostics(entry.to_str().unwrap(), &mut Vec::new())
            .unwrap_err()
            .category,
        honk_config::error::ErrorCategory::Include,
    );
}

#[test]
fn source_capture_preserves_preorder_bytes_and_physical_diagnostics() {
    use honk_config::parser::{SourceLimits, load_dae_sources};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::create_dir(root.join("parts")).unwrap();
    let entry = root.join("config.dae");
    let main = "# unchanged UTF-8: 雪\r\ninclude { parts/*.dae }\r\nglobal { log_level: warn }\r\n";
    let first = "include { sibling.dae }\nglobal { log_level: info }\n";
    let sibling = "global {\n check_tolerance: invalid\n}\n";
    let last = "global { log_level: debug }\n";
    write(&entry, main);
    write(&root.join("parts/10.dae"), first);
    write(&root.join("sibling.dae"), sibling);
    write(&root.join("parts/20.dae"), last);
    let before = std::time::SystemTime::now();
    let mut diagnostics = Vec::new();
    let loaded = load_dae_sources(
        &entry,
        &Default::default(),
        SourceLimits::default(),
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(loaded.config.global.log_level, "debug");
    assert_eq!(
        loaded
            .sources
            .iter()
            .map(|source| source.content.as_ref())
            .collect::<Vec<_>>(),
        [main, first, sibling, last]
    );
    assert_eq!(
        loaded
            .sources
            .iter()
            .map(|source| source.parent)
            .collect::<Vec<_>>(),
        [None, Some(0), Some(1), Some(0)]
    );
    assert_eq!(
        loaded
            .sources
            .iter()
            .map(|source| source.path.clone())
            .collect::<Vec<_>>(),
        [
            entry.clone(),
            root.join("parts/10.dae"),
            root.join("sibling.dae"),
            root.join("parts/20.dae")
        ]
    );
    let warning = diagnostics
        .iter()
        .find(|d| {
            d.setting
                == honk_config::diagnostic::SettingPath::new("global").field("check_tolerance")
        })
        .unwrap();
    assert!(warning.source.same_source(&loaded.sources[2].source));
    assert_eq!(warning.line, Some(2));
    assert_eq!(
        warning.source.sources().metadata()[warning.source.index()].path,
        Some(root.join("sibling.dae"))
    );
    assert!(loaded.sources.iter().all(
        |source| source.loaded_at >= before && source.loaded_at <= std::time::SystemTime::now()
    ));
    write(&entry, "global { log_level: error }");
    assert_eq!(loaded.sources[0].content.as_bytes(), main.as_bytes());
    assert_eq!(loaded.config.global.log_level, "debug");
}

#[test]
fn source_overlay_resolves_siblings_and_virtual_globs_without_writing() {
    use honk_config::parser::{SourceLimits, load_dae_sources};
    use std::collections::HashMap;
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::create_dir(root.join("parts")).unwrap();
    let entry = root.join("config.dae");
    let first = root.join("parts/10.dae");
    let sibling = root.join("sibling.dae");
    let virtual_source = root.join("parts/20.dae");
    write(
        &entry,
        "include { parts/*.dae }\nglobal { log_level: warn }",
    );
    write(&first, "include { sibling.dae }");
    write(&sibling, "global { log_level: info }");
    let overlay: HashMap<_, Arc<str>> = HashMap::from([
        (sibling.clone(), Arc::from("global { tproxy_port: 30000 }")),
        (
            virtual_source.clone(),
            Arc::from("global { log_level: debug }"),
        ),
    ]);
    let loaded =
        load_dae_sources(&entry, &overlay, SourceLimits::default(), &mut Vec::new()).unwrap();
    assert_eq!(loaded.config.global.tproxy_port, 30000);
    assert_eq!(loaded.config.global.log_level, "debug");
    assert_eq!(
        loaded
            .sources
            .iter()
            .map(|source| &source.path)
            .collect::<Vec<_>>(),
        [&entry, &first, &sibling, &virtual_source]
    );
    assert!(Arc::ptr_eq(&loaded.sources[2].content, &overlay[&sibling]));
    assert!(!virtual_source.exists());
    assert_eq!(
        fs::read_to_string(&sibling).unwrap(),
        "global { log_level: info }"
    );
    write(&root.join("parts/30.dae"), "global { log_level: error }");
    let changed =
        load_dae_sources(&entry, &overlay, SourceLimits::default(), &mut Vec::new()).unwrap();
    assert_eq!(
        changed.sources.last().unwrap().path,
        root.join("parts/30.dae")
    );
    assert_eq!(changed.config.global.log_level, "error");
}

#[test]
fn memory_sources_expand_includes_without_reading_the_disk() {
    use honk_config::parser::SourceLimits;
    use std::collections::HashMap;
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::create_dir(root.join("conf.d")).unwrap();
    let entry = root.join("config.dae");
    let included = root.join("conf.d/a.dae");
    write(&entry, "global { log_level: error }");
    write(&root.join("conf.d/x.dae"), "global { tproxy_port: 30001 }");
    let sources: HashMap<_, Arc<str>> = HashMap::from([
        (
            entry.clone(),
            Arc::from("include { conf.d/*.dae }\nglobal { log_level: warn }"),
        ),
        (included.clone(), Arc::from("global { tproxy_port: 30000 }")),
    ]);
    let loaded = Config::from_dae_sources_in_memory(
        &entry,
        &sources,
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        loaded
            .sources
            .iter()
            .map(|source| &source.path)
            .collect::<Vec<_>>(),
        [&entry, &included]
    );
    assert_eq!(loaded.config.global.log_level, "warn");
    assert_eq!(loaded.config.global.tproxy_port, 30000);

    let gone = root.join("missing");
    let moved: HashMap<_, Arc<str>> = sources
        .iter()
        .map(|(path, content)| {
            (
                gone.join(path.strip_prefix(&root).unwrap()),
                content.clone(),
            )
        })
        .collect();
    let relocated = Config::from_dae_sources_in_memory(
        &gone.join("config.dae"),
        &moved,
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(relocated.config, loaded.config);

    let orphan = HashMap::from([(included, Arc::from("global {}"))]);
    let error = Config::from_dae_sources_in_memory(
        &entry,
        &orphan,
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(error.diagnostic.code, "missing-config-source");
}

#[test]
fn source_limits_cover_entry_and_dependency_bytes_and_counts() {
    use honk_config::parser::{SourceLimits, load_dae_sources, parse_dae_sources};
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("config.dae");
    let main = "include { child.dae }";
    let child = "global { log_level: debug }";
    write(&entry, main);
    write(&dir.path().join("child.dae"), child);
    let exact = SourceLimits {
        max_bytes: main.len() + child.len(),
        max_sources: 2,
    };
    let accepted = load_dae_sources(&entry, &Default::default(), exact, &mut Vec::new()).unwrap();
    assert_eq!(accepted.config.global.log_level, "debug");
    for (limits, code) in [
        (
            SourceLimits {
                max_bytes: exact.max_bytes - 1,
                ..exact
            },
            "config-byte-limit",
        ),
        (
            SourceLimits {
                max_sources: 1,
                ..exact
            },
            "config-source-limit",
        ),
        (
            SourceLimits {
                max_bytes: main.len() - 1,
                ..exact
            },
            "config-byte-limit",
        ),
    ] {
        let mut diagnostics = Vec::new();
        let error =
            load_dae_sources(&entry, &Default::default(), limits, &mut diagnostics).unwrap_err();
        assert_eq!(error.diagnostic.code, code);
        assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
    }
    let inputs = vec![
        (entry.clone(), std::sync::Arc::from(main)),
        (dir.path().join("child.dae"), std::sync::Arc::from(child)),
    ];
    assert_eq!(
        parse_dae_sources(
            &inputs,
            SourceLimits {
                max_bytes: exact.max_bytes - 1,
                ..exact
            },
            &mut Vec::new()
        )
        .unwrap_err()
        .diagnostic
        .code,
        "config-byte-limit"
    );
    assert_eq!(
        parse_dae_sources(
            &inputs,
            SourceLimits {
                max_sources: 1,
                ..exact
            },
            &mut Vec::new()
        )
        .unwrap_err()
        .diagnostic
        .code,
        "config-source-limit"
    );
}

#[test]
fn submitted_sources_are_ordered_syntax_only_and_reject_nested_includes() {
    use honk_config::parser::{SourceLimits, parse_dae_sources};
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let inputs = vec![
        (missing.join("main.dae"), std::sync::Arc::from("")),
        (
            missing.join("second.dae"),
            std::sync::Arc::from(
                "include { /unreadable/private/*.dae }\nglobal { log_level: debug }",
            ),
        ),
    ];
    let loaded = parse_dae_sources(&inputs, SourceLimits::default(), &mut Vec::new()).unwrap();
    assert_eq!(loaded.config.global.log_level, "debug");
    assert_eq!(loaded.sources[0].path, inputs[0].0);
    assert_eq!(loaded.sources[1].path, inputs[1].0);
    assert!(!missing.exists());
    for body in [
        "include { file.dae {} }",
        "experimental { native_api { secret { value } } }",
    ] {
        let invalid = vec![(missing.join("main.dae"), std::sync::Arc::from(body))];
        assert!(parse_dae_sources(&invalid, SourceLimits::default(), &mut Vec::new()).is_err());
    }
    let duplicated = vec![inputs[0].clone(), inputs[0].clone()];
    assert_eq!(
        parse_dae_sources(&duplicated, SourceLimits::default(), &mut Vec::new())
            .unwrap_err()
            .diagnostic
            .code,
        "duplicate-config-source"
    );
    write(&dir.path().join("empty.dae"), "");
    assert!(
        honk_config::parser::load_dae_sources(
            &dir.path().join("empty.dae"),
            &Default::default(),
            SourceLimits::default(),
            &mut Vec::new()
        )
        .is_err()
    );
}

#[test]
fn source_secret_marker_keeps_overridden_native_and_clash_credentials_private() {
    use honk_config::parser::{SourceLimits, parse_dae_sources};
    let inputs = vec![
        (
            "native.dae".into(),
            std::sync::Arc::from(
                "experimental { native_api {\n secret: 'old-native-token'\n secret: ''\n} }",
            ),
        ),
        (
            "clash.dae".into(),
            std::sync::Arc::from(
                "experimental { clash_api {\n secret: 'old-clash-token'\n secret: ''\n} }",
            ),
        ),
        (
            "ordinary.dae".into(),
            std::sync::Arc::from("# secret: comment-only\nglobal { log_level: debug }"),
        ),
    ];
    let loaded = parse_dae_sources(&inputs, SourceLimits::default(), &mut Vec::new()).unwrap();
    assert_eq!(
        loaded
            .sources
            .iter()
            .map(|source| source.contains_api_secret)
            .collect::<Vec<_>>(),
        [true, true, false]
    );
    assert!(loaded.config.experimental.native_api.secret.is_empty());
    assert!(loaded.config.experimental.clash_api.secret.is_empty());
    let rendered = format!("{loaded:?}");
    assert!(!rendered.contains("old-native-token"));
    assert!(!rendered.contains("old-clash-token"));
    assert!(!rendered.contains("native.dae"));
}

#[cfg(unix)]
#[test]
fn source_overlay_rejects_escaping_and_duplicate_physical_sources() {
    use honk_config::parser::{SourceLimits, load_dae_sources};
    use std::collections::HashMap;
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap().join("root");
    fs::create_dir(&root).unwrap();
    let entry = root.join("config.dae");
    write(&entry, "global {}");
    let outside = root.parent().unwrap().join("outside.dae");
    let overlay: HashMap<_, Arc<str>> = HashMap::from([(outside.clone(), Arc::from("global {}"))]);
    let error =
        load_dae_sources(&entry, &overlay, SourceLimits::default(), &mut Vec::new()).unwrap_err();
    assert_eq!(error.diagnostic.code, "invalid-config-overlay");
    assert!(!error.to_string().contains(outside.to_str().unwrap()));
    write(&outside, "global {}");
    std::os::unix::fs::symlink(&outside, root.join("escape.dae")).unwrap();
    write(&entry, "include { escape.dae }");
    assert_eq!(
        load_dae_sources(
            &entry,
            &Default::default(),
            SourceLimits::default(),
            &mut Vec::new()
        )
        .unwrap_err()
        .diagnostic
        .code,
        "config-include-escape"
    );
    write(&root.join("child.dae"), "global {}");
    std::os::unix::fs::symlink(root.join("child.dae"), root.join("alias.dae")).unwrap();
    write(&entry, "include { child.dae alias.dae }");
    assert_eq!(
        load_dae_sources(
            &entry,
            &Default::default(),
            SourceLimits::default(),
            &mut Vec::new()
        )
        .unwrap_err()
        .diagnostic
        .code,
        "duplicate-config-source"
    );
}

#[cfg(unix)]
#[test]
fn virtual_includes_follow_existing_directory_aliases_and_parent_components() {
    use honk_config::parser::{SourceLimits, load_dae_sources};
    use std::collections::HashMap;
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::create_dir(root.join("parts")).unwrap();
    std::os::unix::fs::symlink(root.join("parts"), root.join("alias")).unwrap();
    let entry = root.join("config.dae");
    let virtual_source = root.join("parts/child.dae");
    let overlay: HashMap<_, Arc<str>> = HashMap::from([(
        virtual_source.clone(),
        Arc::from("global { tproxy_port: 31000 }"),
    )]);
    for pattern in ["./parts/*.dae", "alias/*.dae", "parts/../parts/*.dae"] {
        write(&entry, &format!("include {{ {pattern} }}"));
        let loaded =
            load_dae_sources(&entry, &overlay, SourceLimits::default(), &mut Vec::new()).unwrap();
        assert_eq!(loaded.config.global.tproxy_port, 31000, "{pattern}");
        assert_eq!(loaded.sources[1].path, virtual_source);
    }
    assert!(!virtual_source.exists());
    write(&entry, "include { parts/C*.dae }");
    let unmatched =
        load_dae_sources(&entry, &overlay, SourceLimits::default(), &mut Vec::new()).unwrap();
    assert_eq!(
        unmatched
            .sources
            .iter()
            .map(|source| &source.path)
            .collect::<Vec<_>>(),
        [&entry]
    );
    write(&entry, "include { parts/*.dae alias/*.dae }");
    assert_eq!(
        load_dae_sources(&entry, &overlay, SourceLimits::default(), &mut Vec::new())
            .unwrap_err()
            .diagnostic
            .code,
        "duplicate-config-source"
    );
}

#[test]
fn structural_source_check_rejects_recovered_lexical_errors() {
    let path = std::path::Path::new("unused.dae");
    let error = honk_config::parser::check_dae_source(path, "dns {\n use_host: 'unterminated\n}\n")
        .unwrap_err();
    assert_eq!(error.diagnostic.code, "unterminated-quote");
    assert_eq!(error.diagnostic.line, Some(2));
    assert!(error.diagnostic.terminal);
}
