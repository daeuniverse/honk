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
