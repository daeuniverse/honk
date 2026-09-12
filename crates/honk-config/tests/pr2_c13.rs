use honk_config::Config;
use honk_config::diagnostic::{DetailedDiagnostic, Severity};
use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

#[test]
fn unknown_subtrees_cannot_override_settings_or_leak_rules() {
    let input = r#"global {
 log_level: warn
 wrapper { nested { log_level: debug } }
 tproxy_port: 23456
}
group { g {
 policy: selector
 wrapper { policy: score }
 final: direct
} }
experimental {
 clash_api {
  secret: retained
  wrapper { secret: leaked }
 }
 cache_file {
  enabled: false
  wrapper { enabled: true }
 }
}
dns {
 max_cache_size: 321
 wrapper { max_cache_size: 999 }
 upstream {
  wrapper { hidden: 'udp://127.0.0.2:53' }
  visible: 'udp://127.0.0.1:53'
 }
 fixed_domain_ttl {
  wrapper { hidden: 99 }
  visible: 42
 }
 routing {
  wrapper { request { qname(hidden) -> reject } }
  request {
   wrapper { qname(hidden) -> reject }
   qname(visible) -> reject
  }
  response { wrapper { qname(hidden) -> reject } }
 }
}
routing {
 wrapper { domain(hidden) -> block }
 domain(visible) -> direct
 fallback: direct
}
"#;
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
    assert_eq!(config.global.log_level, "warn");
    assert_eq!(config.global.tproxy_port, 23456);
    assert_eq!(
        config.groups[0].policy,
        honk_config::group::GroupPolicy::Selector
    );
    assert_eq!(config.groups[0].final_outbound.as_deref(), Some("direct"));
    assert_eq!(config.experimental.clash_api.secret, "retained");
    assert!(!config.experimental.cache_file.enabled);
    assert_eq!(config.dns.cache.max_size, 321);
    assert_eq!(config.dns.upstream.len(), 1);
    assert_eq!(config.dns.upstream[0].name, "visible");
    assert_eq!(config.dns.fixed_domain_ttl, [("visible".into(), 42)].into());
    assert_eq!(config.dns.routing.request.rules.len(), 1);
    assert!(config.dns.routing.response.rules.is_empty());
    assert_eq!(config.routing.rules.len(), 1);
    assert_eq!(
        config.routing.rules[0].outbound,
        honk_config::routing::RoutingOutbound::Simple("direct".into())
    );
    let skipped: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.code == "unknown-block")
        .collect();
    assert_eq!(skipped.len(), 11);
    assert!(
        skipped
            .iter()
            .all(|d| d.severity == Severity::Warning && d.span.is_some())
    );
}

#[test]
fn strict_nfqueue_rejects_nested_content_but_optional_children_ignore_unknown_keys() {
    let mut diagnostics: Vec<DetailedDiagnostic> = Vec::new();
    let error = parse_dae_config_with_detailed_diagnostics(
        "experimental { udp_nfqueue { wrapper { enabled: true } } }",
        &mut diagnostics,
    )
    .unwrap_err();
    assert_eq!(error.category, honk_config::error::ErrorCategory::Parse);
    assert!(error.diagnostic.terminal);
    assert_eq!(error.diagnostic.line, Some(1));
    assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);

    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics(
        "experimental {\n clash_api { future: sensitive-value\n secret: kept }\n cache_file { future: sensitive-value\n enabled: true }\n}",
        &mut diagnostics,
    ).unwrap();
    assert_eq!(config.experimental.clash_api.secret, "kept");
    assert!(config.experimental.cache_file.enabled);
    assert_eq!(
        diagnostics
            .iter()
            .filter(|d| d.code == "unknown-key")
            .count(),
        2
    );
    assert!(!format!("{diagnostics:?}").contains("sensitive-value"));
    assert_eq!(config.global, Config::default().global);
}

#[test]
fn comment_brace_notice_survives_early_failure_inside_an_open_root() {
    for statement in ["{", "log_level: 'unterminated", "wrapper{"] {
        let input = format!("global {{\n  # }}\n  {statement}\n  # }}\n");
        let mut diagnostics = Vec::new();
        parse_dae_config_with_detailed_diagnostics(&input, &mut diagnostics).unwrap_err();
        let comments: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.code == "legacy-comment-brace")
            .collect();
        assert_eq!(comments.len(), 1, "{statement}: {diagnostics:?}");
        assert_eq!(comments[0].line, Some(2));
        assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
    }
}
