use honk_config::diagnostic::{DetailedDiagnostic, Severity};
use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

fn input(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/pr2/c07/{name}.dae",
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
    let error = parse_dae_config_with_detailed_diagnostics(&source, &mut diagnostics).unwrap_err();
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
