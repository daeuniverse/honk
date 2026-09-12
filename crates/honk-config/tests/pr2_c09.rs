use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

#[test]
fn upstream_comments_end_before_uri_and_detour_conversion() {
    let source = "dns {\n upstream {\n  plain: 'udp://8.8.8.8:53' # note\n  via: 'tls://1.1.1.1:853?tls_server_name=dns.example' -> proxy\t# note\n }\n}";
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics(source, &mut diagnostics).unwrap();
    let upstreams = &config.dns.upstream;
    assert_eq!(upstreams[0].address, "8.8.8.8:53");
    assert_eq!(upstreams[1].address, "1.1.1.1:853");
    assert_eq!(upstreams[1].outbound.as_deref(), Some("proxy"));
    assert_eq!(upstreams[1].tls_server_name.as_deref(), Some("dns.example"));
    let warnings: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.code == "legacy-upstream-comment")
        .collect();
    assert_eq!(
        warnings.iter().map(|d| d.line).collect::<Vec<_>>(),
        [Some(3), Some(4)]
    );
    for warning in warnings {
        assert_eq!(&source[warning.span.clone().unwrap()], "#");
    }
}

#[test]
fn quoted_uri_separators_cannot_select_a_detour() {
    let source = "dns {\n upstream {\n  literal: 'https://dns.example/q?x=outbound:proxy#frag'\n  arrow: 'https://dns.example/q?x=->proxy' outbound: real\n  control: 'https://dns.example/q?x=outbound:data' -> real\n }\n}";
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics(source, &mut diagnostics).unwrap();
    assert_eq!(
        config.dns.upstream[0].address,
        "dns.example/q?x=outbound:proxy#frag"
    );
    assert_eq!(config.dns.upstream[0].outbound, None);
    assert_eq!(config.dns.upstream[1].address, "dns.example/q?x=->proxy");
    assert_eq!(config.dns.upstream[1].outbound.as_deref(), Some("real"));
    assert_eq!(
        config.dns.upstream[2].address,
        "dns.example/q?x=outbound:data"
    );
    assert_eq!(config.dns.upstream[2].outbound.as_deref(), Some("real"));
    assert_eq!(
        diagnostics
            .iter()
            .filter(|d| d.code == "legacy-upstream-separator")
            .map(|d| d.line)
            .collect::<Vec<_>>(),
        [Some(3), Some(4)]
    );
}
