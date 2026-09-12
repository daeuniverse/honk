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
