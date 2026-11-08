use honk_config::Config;

fn dns_validation_fixture(name: &str) -> Config {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/dns-validation")
        .join(name);
    let source = std::fs::read_to_string(&path).unwrap();
    if name.ends_with(".json") {
        Config::from_json_str(&source).unwrap()
    } else if name.ends_with(".toml") {
        Config::from_file(path.to_str().unwrap()).unwrap()
    } else {
        honk_config::parser::parse_dae_config(&source).unwrap()
    }
}

fn assert_missing_dns_upstream(config: &Config, location: &str, target: &str) {
    let error = config
        .validate_detailed()
        .expect_err("undeclared DNS target must fail");
    assert_eq!(
        error.category,
        honk_config::error::ErrorCategory::Validation
    );
    assert_eq!(error.diagnostic.code, "unknown-dns-upstream");
    assert_eq!(error.diagnostic.setting.to_string(), location);
    let mut corrected = config.clone();
    let mut declaration = corrected.dns.upstream[0].clone();
    declaration.name = target.into();
    corrected.dns.upstream.push(declaration);
    corrected.validate().unwrap();
}

fn assert_missing_legacy_fallback(config: &Config, expected_code: &str) {
    let error = config
        .validate_detailed()
        .expect_err("legacy fallback without a declaration must fail");
    assert_eq!(
        error.category,
        honk_config::error::ErrorCategory::Validation
    );
    assert_eq!(error.diagnostic.code, expected_code);
    assert_eq!(error.diagnostic.setting.to_string(), "dns.routing.fallback");
    let mut corrected = config.clone();
    corrected.dns.routing.fallback = "default".into();
    corrected.validate().unwrap();
}

#[test]
fn test_validate_rejects_dns_request_rule_target() {
    let config = dns_validation_fixture("request-rule-missing.dae");
    assert_missing_dns_upstream(&config, "dns.routing.request.rules[1].action", "missing");
}

#[test]
fn test_validate_rejects_dns_request_fallback_target() {
    let config = dns_validation_fixture("request-fallback-missing.dae");
    assert_missing_dns_upstream(&config, "dns.routing.request.fallback", "missing");
}

#[test]
fn test_validate_rejects_dns_implicit_fallback_after_catch_all() {
    let config = dns_validation_fixture("explicit-only-alidns-catchall.dae");
    assert_missing_dns_upstream(&config, "dns.routing.request.fallback", "default");
}

#[test]
fn test_validate_rejects_dns_implicit_fallback_without_request_routing() {
    let config = dns_validation_fixture("explicit-only-alidns.dae");
    assert_missing_dns_upstream(&config, "dns.routing.request.fallback", "default");
}

#[test]
fn test_validate_rejects_dns_response_rule_target() {
    let config = dns_validation_fixture("response-rule-missing.dae");
    assert_missing_dns_upstream(&config, "dns.routing.response.rules[1].action", "missing");
}

#[test]
fn test_validate_rejects_dns_response_fallback_target() {
    let config = dns_validation_fixture("response-fallback-missing.dae");
    assert_missing_dns_upstream(&config, "dns.routing.response.fallback", "missing");
}

#[test]
fn test_validate_rejects_dae_uppercase_declaration_mismatch() {
    let config = dns_validation_fixture("dae-uppercase-request-mismatch.dae");
    assert_missing_dns_upstream(&config, "dns.routing.request.rules[1].action", "alidns");

    let config = dns_validation_fixture("dae-uppercase-response-mismatch.dae");
    assert_missing_dns_upstream(&config, "dns.routing.response.rules[1].action", "alidns");
    dns_validation_fixture("dae-lowercase-declaration.dae")
        .validate()
        .unwrap();
}

#[test]
fn test_validate_accepts_dns_empty_upstreams_with_terminal_fallback() {
    dns_validation_fixture("empty-terminal-fallback.dae")
        .validate()
        .unwrap();
    let config = dns_validation_fixture("empty-asis-fallback.dae");
    config.validate().unwrap();
}

#[test]
fn test_validate_accepts_named_dns_response_fallback() {
    let config = dns_validation_fixture("response-named-fallback.dae");
    config.validate().unwrap();
}

#[test]
fn test_validate_rejects_effective_legacy_dns_rule_target() {
    let config = dns_validation_fixture("legacy-rule-missing.json");
    assert_missing_dns_upstream(&config, "dns.routing.rules[1].upstream", "missing");
}

#[test]
fn test_validate_rejects_omitted_legacy_dns_fallback() {
    let config = dns_validation_fixture("legacy-fallback-omitted.json");
    assert_missing_legacy_fallback(&config, "missing-dns-fallback");
}

#[test]
fn test_validate_rejects_empty_legacy_dns_fallback() {
    let config = dns_validation_fixture("legacy-fallback-empty.toml");
    assert_missing_legacy_fallback(&config, "empty-dns-fallback");
    let mut declared_empty = config.clone();
    let mut upstream = declared_empty.dns.upstream[0].clone();
    upstream.name.clear();
    declared_empty.dns.upstream.push(upstream);
    declared_empty.validate().unwrap();
}

#[test]
fn test_validate_rejects_effective_legacy_dns_fallback_target() {
    let config = dns_validation_fixture("legacy-fallback-missing.json");
    assert_missing_legacy_fallback(&config, "unknown-dns-upstream");
}

#[test]
fn test_validate_rejects_promoted_legacy_dns_fallback_target() {
    let config = dns_validation_fixture("legacy-promotion-missing.json");
    assert_missing_legacy_fallback(&config, "unknown-dns-upstream");
}

#[test]
fn test_validate_accepts_legacy_dns_exact_case() {
    let config = dns_validation_fixture("legacy-exact-case.json");
    config.validate().unwrap();
}

#[test]
fn test_validate_rejects_last_legacy_dns_rule_target() {
    let mut config = dns_validation_fixture("legacy-exact-case.json");
    let mut last_rule = config.dns.routing.rules[0].clone();
    last_rule.domain = "last.example".into();
    last_rule.upstream = "missing".into();
    config.dns.routing.rules.push(last_rule);
    assert_missing_dns_upstream(&config, "dns.routing.rules[2].upstream", "missing");
}

#[test]
fn test_validate_accepts_legacy_dns_upstream_sentinel_without_rules() {
    let config = dns_validation_fixture("legacy-sentinel-upstream.json");
    config.validate().unwrap();
    let mut config = dns_validation_fixture("legacy-sentinel-upstream.json");
    config.dns.routing.fallback.clear();
    config.validate().unwrap();

    let config = dns_validation_fixture("legacy-sentinel-rules.json");
    assert_missing_legacy_fallback(&config, "missing-dns-fallback");
    let mut declared_sentinel = config.clone();
    let mut upstream = declared_sentinel.dns.upstream[0].clone();
    upstream.name = "upstream".into();
    declared_sentinel.dns.upstream.push(upstream);
    declared_sentinel.validate().unwrap();
}

#[test]
fn test_validate_typed_api_new_request_rules_ignore_legacy_fields() {
    let mut config = dns_validation_fixture("dae-lowercase-declaration.dae");
    config.dns.routing.rules.push(honk_config::dns::DnsRule {
        domain: "ignored.example".into(),
        upstream: "missing".into(),
    });
    config.dns.routing.fallback = "missing".into();
    config.validate().unwrap();
    assert_eq!(
        config.dns.routing.effective_request().as_ref(),
        &config.dns.routing.request,
    );
}

#[test]
fn test_validate_typed_api_legacy_rules_precede_new_request_fallback() {
    let mut config = dns_validation_fixture("dae-lowercase-declaration.dae");
    config.dns.routing.request.rules.clear();
    let legacy = dns_validation_fixture("legacy-exact-case.json");
    config.dns.upstream = legacy.dns.upstream;
    config.dns.routing.rules = legacy.dns.routing.rules;
    config.dns.routing.fallback = legacy.dns.routing.fallback;
    config.dns.routing.response = legacy.dns.routing.response;
    config.dns.routing.request.fallback =
        honk_config::dns::DnsRequestAction::Upstream("missing".into());
    config.validate().unwrap();
    assert_eq!(
        config.dns.routing.effective_request().as_ref(),
        &config.dns.routing.convert_legacy_rules(),
    );
}

fn quoted_upstream_config(declared: &str, target: &str) -> Config {
    let source = format!(
        "dns {{
    upstream {{
        {declared}: 'udp://192.0.2.1:53'
    }}
    routing {{
        request {{
            qname(full: quoted.example) -> {target}
            fallback: {target}
        }}
        response {{
            upstream({target}) && ip(192.0.2.0/24) -> {target}
            fallback: {target}
        }}
    }}
}}
"
    );
    honk_config::parser::parse_dae_config(&source).unwrap()
}

#[test]
fn test_validate_resolves_dns_upstream_names_across_quote_styles() {
    use honk_config::dns::{DnsCond, DnsRequestAction, DnsResponseAction};
    for (declared, target, name) in [
        ("'my dns'", "'my dns'", "my dns"),
        ("\"my dns\"", "\"my dns\"", "my dns"),
        ("'my dns'", "\"my dns\"", "my dns"),
        ("\"my dns\"", "'my dns'", "my dns"),
        ("alidns", "'alidns'", "alidns"),
        ("'alidns'", "alidns", "alidns"),
    ] {
        let config = quoted_upstream_config(declared, target);
        config
            .validate()
            .unwrap_or_else(|error| panic!("{declared} -> {target}: {error:?}"));
        let dns = &config.dns;
        assert_eq!(dns.upstream[0].name, name);
        let upstream = DnsRequestAction::Upstream(name.into());
        assert_eq!(dns.routing.request.rules[0].action, upstream);
        assert_eq!(dns.routing.request.fallback, upstream);
        assert_eq!(dns.routing.fallback, name);
        let requery = DnsResponseAction::Upstream(name.into());
        assert_eq!(dns.routing.response.rules[0].action, requery);
        assert_eq!(dns.routing.response.fallback, requery);
        assert_eq!(
            dns.routing.response.rules[0].conditions[0],
            DnsCond::Upstream {
                not: false,
                names: vec![name.into()],
            },
        );
    }
}

#[test]
fn test_validate_rejects_unknown_quoted_dns_upstream_name() {
    let mut config = quoted_upstream_config("'my dns'", "'my dns'");
    config.dns.routing.request.rules[0].action =
        honk_config::dns::DnsRequestAction::Upstream("'my dns'".into());
    assert_missing_dns_upstream(&config, "dns.routing.request.rules[1].action", "'my dns'");

    let config = quoted_upstream_config("'my dns'", "\"other dns\"");
    assert_missing_dns_upstream(&config, "dns.routing.request.rules[1].action", "other dns");
}

#[test]
fn subtag_rules_need_a_direct_upstream_and_only_qname() {
    let config = |upstream: &str, rule: &str| {
        honk_config::parser::parse_dae_config(&format!(
            "dns {{\n upstream {{\n  providerdoh: 'https://203.0.113.1/dns-query'{upstream}\n }}\n routing {{\n  request {{\n   {rule}\n   fallback: providerdoh\n  }}\n }}\n}}\n"
        ))
        .unwrap()
    };
    let accepted = "subtag(MyAirport) && qname(suffix: private.example) -> providerdoh";
    config(" -> direct", accepted).validate().unwrap();
    for (upstream, rule, code, setting) in [
        (
            "",
            accepted,
            "subtag-dns-upstream-route",
            "dns.routing.request.rules[1].action",
        ),
        (
            " -> proxy",
            accepted,
            "subtag-dns-upstream-route",
            "dns.routing.request.rules[1].action",
        ),
        (
            " -> direct\n  providerdoh: 'https://203.0.113.2/dns-query' -> proxy",
            accepted,
            "subtag-dns-upstream-route",
            "dns.routing.request.rules[1].action",
        ),
        (
            " -> proxy\n  providerdoh: 'https://203.0.113.2/dns-query' -> direct",
            accepted,
            "subtag-dns-upstream-route",
            "dns.routing.request.rules[1].action",
        ),
        (
            " -> direct",
            "subtag(MyAirport) -> asis",
            "subtag-dns-action",
            "dns.routing.request.rules[1].action",
        ),
        (
            " -> direct",
            "subtag(MyAirport) && qtype(aaaa) -> providerdoh",
            "subtag-dns-condition",
            "dns.routing.request.rules[1].conditions",
        ),
    ] {
        let error = config(upstream, rule)
            .validate_detailed()
            .expect_err("unsafe subtag rule must fail");
        assert_eq!(error.diagnostic.code, code, "{upstream:?} {rule:?}");
        assert_eq!(error.diagnostic.setting.to_string(), setting);
    }
}
