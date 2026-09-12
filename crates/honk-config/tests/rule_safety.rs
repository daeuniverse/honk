use honk_config::{Config, parser::parse_dae_config_with_detailed_diagnostics};

#[test]
fn unsafe_traffic_terms_reject_at_file_boundary() {
    for (matcher, code) in [
        ("unknown(PRIVATE)", "unknown-traffic-predicate"),
        ("!unknown(PRIVATE)", "unknown-traffic-predicate"),
        ("dport (443)", "unknown-traffic-predicate"),
        ("dport(443)junk", "trailing-matcher-text"),
        ("dport(443) domain(PRIVATE)", "unknown-traffic-predicate"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.dae");
        std::fs::write(
            &path,
            format!("routing {{\n dport(80) && {matcher} -> direct\n}}\n"),
        )
        .unwrap();
        let mut diagnostics = Vec::new();
        let error =
            Config::from_file_with_detailed_diagnostics(path.to_str().unwrap(), &mut diagnostics)
                .unwrap_err();
        assert_eq!(error.diagnostic.code, code);
        assert_eq!(error.diagnostic.setting.to_string(), "routing.rules[1]");
        assert_eq!(error.diagnostic.line, Some(2));
        assert!(!format!("{diagnostics:?}{error:?}").contains("PRIVATE"));
    }
}

#[test]
fn invalid_dns_conjunct_omits_whole_rule() {
    for (matcher, code) in [
        ("", "invalid-dns-rule"),
        ("unknown(PRIVATE)", "invalid-dns-rule"),
        ("!sub(PRIVATE)", "unsupported-dns-condition"),
        ("qname (PRIVATE)", "invalid-dns-rule"),
        ("qname(PRIVATE)junk", "trailing-matcher-text"),
        ("qtype(A,TYPO)", "invalid-qtype"),
        ("!qtype(TYPO)", "invalid-qtype"),
    ] {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(&format!("dns {{\n routing {{\n request {{\n qname(PRIVATE) && {matcher} -> reject\n qtype('a,aaaa') -> reject\n qtype() -> reject\n }}\n }}\n}}"), &mut diagnostics).unwrap();
        assert_eq!(config.dns.routing.request.rules.len(), 2, "{matcher}");
        assert!(
            matches!(&config.dns.routing.request.rules[0].conditions[0], honk_config::dns::DnsCond::Qtype { types, .. } if types == &[1,28])
        );
        assert!(
            matches!(&config.dns.routing.request.rules[1].conditions[0], honk_config::dns::DnsCond::Qtype { types, .. } if types.is_empty())
        );
        let warning = diagnostics.iter().find(|d| d.code == code).unwrap();
        assert_eq!(warning.setting.to_string(), "dns.routing.request.rules[1]");
        assert_eq!(warning.line, Some(4));
        assert!(!format!("{diagnostics:?}").contains("PRIVATE"));
    }
}

#[test]
fn regex_character_class_is_not_a_nested_predicate() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics(
        "dns {\n routing {\n request {\n qname(regex:[(]) && qtype(a) -> reject\n }\n }\n}",
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 1);
    let rule = &config.dns.routing.request.rules[0];
    assert_eq!(rule.conditions.len(), 2);
    assert!(!diagnostics.iter().any(|d| d.code == "invalid-dns-rule"));
}
