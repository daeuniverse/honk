use honk_config::Config;
use honk_config::diagnostic::DetailedDiagnostic;
use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

fn fixture(name: &str) -> (Config, Vec<DetailedDiagnostic>) {
    let input = std::fs::read_to_string(format!(
        "{}/tests/fixtures/pr2/c06/{name}.dae",
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
            "{}/tests/fixtures/pr2/c06/{name}.dae",
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
