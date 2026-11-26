use crate::dns::routing::{DnsRequestDecision, DnsRouter};
use honk_config::dns::{
    DnsCond, DnsConfig, DnsDomainMatcher, DnsRequestAction, DnsRequestRule, DnsResponseAction,
    DnsResponseRule,
};
use honk_config::types::DnsProtocol;

use super::*;

fn representative_config() -> DnsConfig {
    let mut config = DnsConfig::default();
    config.upstream[0].address = "DNS.Google".into();
    config.upstream[0].tls_server_name = Some("DNS.Google.".into());
    config.routing.request.rules = vec![DnsRequestRule {
        conditions: vec![
            DnsCond::Qname {
                not: false,
                matchers: vec![DnsDomainMatcher::Suffix(".Example.COM.".into())],
            },
            DnsCond::Qtype {
                not: false,
                types: vec![1, 28],
            },
        ],
        action: DnsRequestAction::Upstream("DEFAULT".into()),
    }];
    config.fixed_domain_ttl.insert("Example.COM.".into(), 42);
    config
}

#[test]
fn dns_v2_persistence_cache_identity_matches_external_golden_contract() {
    // Given
    // This externally versioned `dns:v2` byte vector is persisted and used as
    // cache identity; it intentionally does not derive expectations from the
    // encoder implementation under test.
    let first = representative_config();
    let second = representative_config();

    // When
    let first_id = PolicyId::from_config(&first).expect("valid policy");
    let second_id = PolicyId::from_config(&second).expect("valid policy");

    // Then
    assert_eq!(first_id, second_id);
    assert_eq!(
        first_id.digest_hex(),
        "28a5f74cae8c9867b3de9f69057a14b967e8d5679257f292f2b271006d5fc483"
    );
    assert_eq!(
        hex(first_id.canonical_bytes()),
        "020000000000000001000000000000000764656661756c7400000000000000000a646e732e676f6f676c6500350000000000000000000000000000000a646e732e676f6f676c6500000000000000000100000000000000020000000000000000000101000000000000000c6578616d706c652e636f6d2e010000000000000000020001001c02000000000000000744454641554c5402000000000000000764656661756c74000000000000000000040000000000000001000000000000000c4578616d706c652e434f4d2e0000002a01000000000000025800000000000027100000000000000e100000001e"
    );
}

#[test]
fn stale_reply_ttl_changes_policy_identity() {
    let default = representative_config();
    let mut changed = default.clone();
    changed.cache.stale_reply_ttl = 31;

    assert_ne!(
        PolicyId::from_config(&default).expect("default policy"),
        PolicyId::from_config(&changed).expect("changed stale TTL policy"),
    );
}

#[test]
fn effective_client_subnet_partitions_policy_identity() {
    let disabled = representative_config();
    let mut unresolved = representative_config();
    unresolved.client_subnet = "auto(9.9.9.9)".into();
    assert_eq!(
        PolicyId::from_config(&disabled).unwrap(),
        PolicyId::from_config(&unresolved).unwrap()
    );

    let mut first = unresolved.clone();
    first.resolved_client_subnet = Some("198.51.100.0/24".parse().unwrap());
    let mut same = first.clone();
    same.client_subnet = "auto(1.1.1.1)".into();
    let mut second = same.clone();
    second.resolved_client_subnet = Some("203.0.113.0/24".parse().unwrap());

    assert_eq!(
        PolicyId::from_config(&first).unwrap(),
        PolicyId::from_config(&same).unwrap()
    );
    assert_ne!(
        PolicyId::from_config(&disabled).unwrap(),
        PolicyId::from_config(&first).unwrap()
    );
    assert_ne!(
        PolicyId::from_config(&first).unwrap(),
        PolicyId::from_config(&second).unwrap()
    );
}

#[test]
fn upstream_groups_partition_policy_identity_and_preserve_v2_when_empty() {
    use honk_config::dns::DnsUpstreamGroup;

    let base = representative_config();
    let base_id = PolicyId::from_config(&base).unwrap();
    assert_eq!(base_id.canonical_bytes()[0], 2);

    let mut raced_ab = representative_config();
    raced_ab.upstream.push(honk_config::dns::DnsUpstream {
        name: "backup".into(),
        address: "1.1.1.1:53".into(),
        protocol: DnsProtocol::Udp,
        tls_server_name: None,
        outbound: None,
    });
    let no_group_id = PolicyId::from_config(&raced_ab).unwrap();
    raced_ab.upstream_groups.push(DnsUpstreamGroup {
        name: "fast".into(),
        upstreams: vec!["default".into(), "backup".into()],
    });
    let ab_id = PolicyId::from_config(&raced_ab).unwrap();
    assert_ne!(no_group_id, ab_id);
    assert_eq!(ab_id.canonical_bytes()[0], 4);

    let mut raced_ba = raced_ab.clone();
    raced_ba.upstream_groups[0].upstreams = vec!["backup".into(), "default".into()];
    assert_ne!(ab_id, PolicyId::from_config(&raced_ba).unwrap());

    let mut renamed = raced_ab.clone();
    renamed.upstream_groups[0].name = "faster".into();
    assert_ne!(ab_id, PolicyId::from_config(&renamed).unwrap());

    let mut with_ecs = raced_ab.clone();
    with_ecs.client_subnet = "auto".into();
    with_ecs.resolved_client_subnet = Some("198.51.100.0/24".parse().unwrap());
    assert_ne!(ab_id, PolicyId::from_config(&with_ecs).unwrap());
}

#[test]
fn canonical_policy_normalizes_equivalent_endpoint_spellings() {
    // Given
    let first = representative_config();
    let mut second = representative_config();
    second.upstream[0].address = "dns.google:53".into();
    second.upstream[0].tls_server_name = Some("dns.google".into());

    // When
    let first_id = PolicyId::from_config(&first).expect("valid policy");
    let second_id = PolicyId::from_config(&second).expect("valid policy");

    // Then
    assert_eq!(first_id, second_id);
}

#[test]
fn sip_policy_identity_normalizes_addresses_and_preserves_semantics() {
    fn config(cidrs: &[&str], not: bool, action: DnsRequestAction) -> DnsConfig {
        let mut config = DnsConfig::default();
        config.routing.request.rules = vec![DnsRequestRule {
            conditions: vec![DnsCond::Sip {
                not,
                cidrs: cidrs.iter().map(|cidr| (*cidr).to_owned()).collect(),
            }],
            action,
        }];
        config
    }

    let id = |config: &DnsConfig| PolicyId::from_config(config).expect("valid policy");
    assert_eq!(
        id(&config(
            &["192.0.2.10", "2001:db8::10", "2001:db8:0:0::/64"],
            false,
            DnsRequestAction::Reject,
        )),
        id(&config(
            &["192.0.2.10/32", "2001:db8::10/128", "2001:db8::/64"],
            false,
            DnsRequestAction::Reject,
        )),
    );
    assert!(PolicyId::from_config(&config(&[], false, DnsRequestAction::Reject)).is_err());
    assert!(
        PolicyId::from_config(&config(&["not-an-ip"], false, DnsRequestAction::Reject,)).is_err()
    );

    let base = id(&config(
        &["192.0.2.10", "198.51.100.0/24"],
        false,
        DnsRequestAction::Reject,
    ));
    assert_ne!(
        base,
        id(&config(
            &["198.51.100.0/24", "192.0.2.10"],
            false,
            DnsRequestAction::Reject,
        )),
    );
    assert_ne!(
        base,
        id(&config(
            &["192.0.2.10", "198.51.100.0/24"],
            true,
            DnsRequestAction::Reject,
        )),
    );
    assert_ne!(
        base,
        id(&config(
            &["192.0.2.10", "198.51.100.0/24"],
            false,
            DnsRequestAction::AsIs,
        )),
    );
}

#[test]
fn semantic_policy_fields_change_identity() {
    // Given
    let base = representative_config();
    let base_id = PolicyId::from_config(&base).expect("valid policy");
    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.cache.enabled = false;
    variants.push(changed);
    let mut changed = base.clone();
    changed.cache.ttl += 1;
    variants.push(changed);
    let mut changed = base.clone();
    changed.cache.max_size += 1;
    variants.push(changed);
    let mut changed = base.clone();
    changed.strategy = honk_config::dns::DnsStrategy::Ipv4Only;
    variants.push(changed);
    let mut changed = base.clone();
    changed.routing.request.rules[0].action = DnsRequestAction::Reject;
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream[0].outbound = Some("proxy".into());
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream[0].address = "1.1.1.1".into();
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream[0].protocol = DnsProtocol::Tcp;
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream[0].tls_server_name = Some("other.test".into());
    variants.push(changed);
    let mut changed = base.clone();
    changed.routing.response.fallback = DnsResponseAction::Reject;
    variants.push(changed);
    let mut changed = base.clone();
    changed.fixed_domain_ttl.insert("other.test".into(), 7);
    variants.push(changed);

    // When
    let ids = variants
        .iter()
        .map(PolicyId::from_config)
        .collect::<Result<Vec<_>, _>>()
        .expect("valid variants");

    // Then
    assert!(ids.iter().all(|id| id != &base_id));
}

#[test]
fn listener_bind_does_not_change_resolution_policy_identity() {
    let base = representative_config();
    let mut bound = base.clone();
    bound.bind = "tcp+udp://127.0.0.1:53".into();

    assert_eq!(
        PolicyId::from_config(&base).expect("base policy"),
        PolicyId::from_config(&bound).expect("bound policy"),
    );
}

#[test]
fn hosts_lookup_does_not_change_upstream_cache_identity() {
    let base = representative_config();
    let mut with_hosts = base.clone();
    with_hosts.hosts.push("/etc/hosts".into());

    // Hosts answers bypass the cache before routing; non-host upstream policy is unchanged.
    assert_eq!(
        PolicyId::from_config(&base).expect("base policy"),
        PolicyId::from_config(&with_hosts).expect("hosts policy"),
    );
}

#[test]
fn request_and_response_rule_order_change_identity() {
    // Given
    let mut base = representative_config();
    base.routing.request.rules.push(DnsRequestRule {
        conditions: vec![],
        action: DnsRequestAction::Reject,
    });
    base.routing.response.rules = vec![
        DnsResponseRule {
            conditions: vec![],
            action: DnsResponseAction::Accept,
        },
        DnsResponseRule {
            conditions: vec![],
            action: DnsResponseAction::Reject,
        },
    ];
    let mut request_swapped = base.clone();
    request_swapped.routing.request.rules.swap(0, 1);
    let mut response_swapped = base.clone();
    response_swapped.routing.response.rules.swap(0, 1);

    // When
    let base_id = PolicyId::from_config(&base).expect("base");
    let request_id = PolicyId::from_config(&request_swapped).expect("request");
    let response_id = PolicyId::from_config(&response_swapped).expect("response");

    // Then
    assert_ne!(base_id, request_id);
    assert_ne!(base_id, response_id);
}

#[test]
fn malformed_endpoint_is_rejected() {
    // Given
    let mut config = representative_config();
    config.upstream[0].address = "[invalid".into();

    // When
    let result = PolicyId::from_config(&config);

    // Then
    assert!(matches!(result, Err(PolicyError::InvalidEndpoint { .. })));
}

#[test]
fn malformed_cidr_is_rejected() {
    // Given
    let mut config = representative_config();
    config.routing.request.rules[0]
        .conditions
        .push(DnsCond::Ip {
            not: false,
            cidrs: vec!["invalid".into()],
            geoip: vec![],
        });

    // When
    let result = PolicyId::from_config(&config);

    // Then
    assert!(matches!(result, Err(PolicyError::InvalidCidr { .. })));
}

#[test]
fn malformed_regex_is_rejected() {
    // Given
    let mut config = representative_config();
    config.routing.request.rules[0]
        .conditions
        .push(DnsCond::Qname {
            not: false,
            matchers: vec![DnsDomainMatcher::Regex("(".into())],
        });

    // When
    let result = PolicyId::from_config(&config);

    // Then
    assert!(matches!(result, Err(PolicyError::InvalidRegex { .. })));
}

#[test]
fn empty_fixed_ttl_domain_is_rejected() {
    // Given
    let mut config = representative_config();
    config.fixed_domain_ttl.insert(String::new(), 7);

    // When
    let result = PolicyId::from_config(&config);

    // Then
    assert!(matches!(result, Err(PolicyError::EmptyName { .. })));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
#[test]
fn fixed_ttl_case_and_trailing_dot_follow_exact_runtime_keys() {
    // Given
    let lower = fixed_ttl_config("example.com");
    let upper = fixed_ttl_config("EXAMPLE.COM");
    let dotted = fixed_ttl_config("example.com.");

    // When
    let lower_id = PolicyId::from_config(&lower).expect("lower policy");
    let upper_id = PolicyId::from_config(&upper).expect("upper policy");
    let dotted_id = PolicyId::from_config(&dotted).expect("dotted policy");
    let lower_router = DnsRouter::new_from_dns_config(&lower).expect("lower router");
    let upper_router = DnsRouter::new_from_dns_config(&upper).expect("upper router");
    let dotted_router = DnsRouter::new_from_dns_config(&dotted).expect("dotted router");

    // Then
    assert_ne!(lower_id, upper_id);
    assert_ne!(lower_id, dotted_id);
    assert_eq!(lower_router.fixed_ttl("example.com"), Some(42));
    assert_eq!(upper_router.fixed_ttl("example.com"), None);
    assert_eq!(dotted_router.fixed_ttl("example.com"), None);
}

#[test]
fn exact_runtime_tags_and_targets_do_not_share_policy_identity() {
    // Given
    let base = exact_material_config();
    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.upstream[0].name = "dnsmain".into();
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream[0].outbound = Some("proxy".into());
    variants.push(changed);
    let mut changed = base.clone();
    changed.routing.request.fallback = DnsRequestAction::Upstream("dnsmain".into());
    variants.push(changed);
    let mut changed = base.clone();
    changed.routing.response.rules[0].conditions = vec![DnsCond::Upstream {
        not: false,
        names: vec!["dnsmain".into()],
    }];
    variants.push(changed);
    let mut changed = base.clone();
    changed.routing.response.rules[0].action = DnsResponseAction::Upstream("secondary".into());
    variants.push(changed);

    // When
    let base_id = PolicyId::from_config(&base).expect("base policy");
    let variant_ids = variants
        .iter()
        .map(PolicyId::from_config)
        .collect::<Result<Vec<_>, _>>()
        .expect("variant policies");

    // Then
    assert!(variant_ids.iter().all(|id| id != &base_id));
}

#[test]
fn full_matcher_only_normalizes_case_that_router_also_normalizes() {
    // Given
    let lower = full_matcher_config("example.com");
    let upper = full_matcher_config("EXAMPLE.COM");

    // When
    let lower_id = PolicyId::from_config(&lower).expect("lower policy");
    let upper_id = PolicyId::from_config(&upper).expect("upper policy");
    let lower_decision = DnsRouter::new_from_dns_config(&lower)
        .expect("lower router")
        .select_request("example.com", 1);
    let upper_decision = DnsRouter::new_from_dns_config(&upper)
        .expect("upper router")
        .select_request("example.com", 1);

    // Then
    assert_eq!(lower_id, upper_id);
    assert_eq!(lower_decision, DnsRequestDecision::Reject);
    assert_eq!(upper_decision, DnsRequestDecision::Reject);
}

#[test]
fn full_matcher_trailing_dot_changes_runtime_and_identity() {
    // Given
    let plain = full_matcher_config("example.com");
    let dotted = full_matcher_config("example.com.");

    // When
    let plain_id = PolicyId::from_config(&plain).expect("plain policy");
    let dotted_id = PolicyId::from_config(&dotted).expect("dotted policy");
    let plain_decision = DnsRouter::new_from_dns_config(&plain)
        .expect("plain router")
        .select_request("example.com", 1);
    let dotted_decision = DnsRouter::new_from_dns_config(&dotted)
        .expect("dotted router")
        .select_request("example.com", 1);

    // Then
    assert_ne!(plain_id, dotted_id);
    assert_eq!(plain_decision, DnsRequestDecision::Reject);
    assert_eq!(dotted_decision, DnsRequestDecision::AsIs);
}

#[test]
fn keyword_matcher_case_remains_exact_like_router_material() {
    // Given
    let lower = keyword_matcher_config("ads");
    let upper = keyword_matcher_config("ADS");

    // When
    let lower_id = PolicyId::from_config(&lower).expect("lower policy");
    let upper_id = PolicyId::from_config(&upper).expect("upper policy");
    let lower_decision = DnsRouter::new_from_dns_config(&lower)
        .expect("lower router")
        .select_request("ads.example", 1);
    let upper_decision = DnsRouter::new_from_dns_config(&upper)
        .expect("upper router")
        .select_request("ads.example", 1);

    // Then
    assert_ne!(lower_id, upper_id);
    assert_eq!(lower_decision, DnsRequestDecision::Reject);
    assert_eq!(upper_decision, DnsRequestDecision::AsIs);
}

fn fixed_ttl_config(key: &str) -> DnsConfig {
    let mut config = DnsConfig::default();
    config.fixed_domain_ttl.insert(key.into(), 42);
    config
}

fn exact_material_config() -> DnsConfig {
    let mut config = DnsConfig::default();
    config.upstream[0].name = "DNSMain".into();
    config.upstream[0].outbound = Some("Proxy".into());
    config.routing.request.fallback = DnsRequestAction::Upstream("DNSMain".into());
    config.routing.response.rules = vec![DnsResponseRule {
        conditions: vec![DnsCond::Upstream {
            not: false,
            names: vec!["DNSMain".into()],
        }],
        action: DnsResponseAction::Upstream("Secondary".into()),
    }];
    config
}

fn full_matcher_config(value: &str) -> DnsConfig {
    matcher_config(DnsDomainMatcher::Full(value.into()))
}

fn keyword_matcher_config(value: &str) -> DnsConfig {
    matcher_config(DnsDomainMatcher::Keyword(value.into()))
}

fn matcher_config(matcher: DnsDomainMatcher) -> DnsConfig {
    let mut config = DnsConfig::default();
    config.routing.request.rules = vec![DnsRequestRule {
        conditions: vec![DnsCond::Qname {
            not: false,
            matchers: vec![matcher],
        }],
        action: DnsRequestAction::Reject,
    }];
    config.routing.request.fallback = DnsRequestAction::AsIs;
    config
}
