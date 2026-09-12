use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

#[test]
fn glued_hash_is_scalar_data_with_legacy_notice() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics(
        include_str!("fixtures/pr2/c04/k01-glued-hash.dae"),
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
        include_str!("fixtures/pr2/c04/k14-lists.dae"),
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
        include_str!("fixtures/pr2/c04/k22-c-scalar.dae"),
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
        include_str!("fixtures/pr2/c04/k05-bare-apostrophe.dae"),
        &mut diagnostics,
    )
    .unwrap();

    assert_eq!(config.global.log_file, "/tmp/don't");
}

#[test]
fn token_head_unterminated_quote_fails_with_lexical_error() {
    let mut diagnostics = Vec::new();
    let error = parse_dae_config_with_detailed_diagnostics(
        include_str!("fixtures/pr2/c04/k05-unterminated.dae"),
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
        include_str!("fixtures/pr2/c04/scalar-controls.dae"),
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
