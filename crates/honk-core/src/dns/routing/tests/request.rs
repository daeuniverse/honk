use std::net::IpAddr;

use honk_config::dns::{
    DnsCond, DnsDomainMatcher, DnsLegacyRule, DnsRequestAction, DnsRequestRouting, DnsRequestRule,
    DnsRouting, DnsTagMatcher,
};

use super::{DnsRouter, router_from_request};
use crate::dns::routing::DnsRequestDecision;

fn rule(condition: DnsCond, action: DnsRequestAction) -> DnsRequestRule {
    DnsRequestRule {
        conditions: vec![condition],
        action,
    }
}

fn request(rules: Vec<DnsRequestRule>) -> DnsRequestRouting {
    DnsRequestRouting {
        rules,
        fallback: DnsRequestAction::Upstream("default".to_owned()),
    }
}

#[test]
fn legacy_rules_are_converted() {
    let router = DnsRouter::new(&DnsRouting {
        rules: vec![DnsLegacyRule {
            domain: "suffix:.cn".into(),
            upstream: "alidns".into(),
        }],
        fallback: "default".into(),
        ..Default::default()
    })
    .expect("legacy routing must compile");
    assert_eq!(router.rule_count(), 1);
    assert_eq!(router.select_upstream("baidu.cn"), "alidns");
    assert_eq!(router.select_upstream("google.com"), "default");
}

#[test]
fn qname_matchers_preserve_semantics() {
    let cases = [
        (
            DnsDomainMatcher::Suffix("cn".into()),
            "www.baidu.cn",
            "google.com",
        ),
        (
            DnsDomainMatcher::Full("example.com".into()),
            "example.com",
            "sub.example.com",
        ),
        (
            DnsDomainMatcher::Keyword("ads".into()),
            "ads.google.com",
            "normal.com",
        ),
        (
            DnsDomainMatcher::Regex(r"^.*\.example\.com$".into()),
            "sub.example.com",
            "other.com",
        ),
    ];
    for (matcher, matching, other) in cases {
        let router = router_from_request(request(vec![rule(
            DnsCond::Qname {
                not: false,
                matchers: vec![matcher],
            },
            DnsRequestAction::Upstream("custom".into()),
        )]));
        assert_eq!(
            router.select_request(matching, 1),
            DnsRequestDecision::Upstream("custom".into())
        );
        assert_eq!(
            router.select_request(other, 1),
            DnsRequestDecision::Upstream("default".into())
        );
    }
}

#[test]
fn qtype_and_combined_conditions_preserve_semantics() {
    let router = router_from_request(request(vec![DnsRequestRule {
        conditions: vec![
            DnsCond::Qname {
                not: false,
                matchers: vec![DnsDomainMatcher::Suffix("cn".into())],
            },
            DnsCond::Qtype {
                not: false,
                types: vec![1, 28],
            },
        ],
        action: DnsRequestAction::Upstream("alidns".into()),
    }]));
    assert_eq!(
        router.select_request("baidu.cn", 1),
        DnsRequestDecision::Upstream("alidns".into())
    );
    assert_eq!(
        router.select_request("baidu.cn", 28),
        DnsRequestDecision::Upstream("alidns".into())
    );
    assert_eq!(
        router.select_request("baidu.cn", 65),
        DnsRequestDecision::Upstream("default".into())
    );
    assert_eq!(
        router.select_request("google.com", 1),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn qtype_only_condition_preserves_semantics() {
    let router = router_from_request(request(vec![rule(
        DnsCond::Qtype {
            not: false,
            types: vec![65],
        },
        DnsRequestAction::Reject,
    )]));
    assert_eq!(
        router.select_request("test.com", 65),
        DnsRequestDecision::Reject
    );
    assert_eq!(
        router.select_request("test.com", 1),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn negation_preserves_semantics() {
    let router = router_from_request(request(vec![rule(
        DnsCond::Qname {
            not: true,
            matchers: vec![DnsDomainMatcher::Suffix("cn".into())],
        },
        DnsRequestAction::Upstream("googledns".into()),
    )]));
    assert_eq!(
        router.select_request("google.com", 1),
        DnsRequestDecision::Upstream("googledns".into())
    );
    assert_eq!(
        router.select_request("baidu.cn", 1),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn request_rules_remain_first_match() {
    let router = router_from_request(request(vec![
        rule(
            DnsCond::Qtype {
                not: false,
                types: vec![1],
            },
            DnsRequestAction::Upstream("first".into()),
        ),
        rule(
            DnsCond::Qtype {
                not: false,
                types: vec![1],
            },
            DnsRequestAction::Upstream("second".into()),
        ),
    ]));
    assert_eq!(
        router.select_request("example.com", 1),
        DnsRequestDecision::Upstream("first".into())
    );
}

#[test]
fn request_actions_and_fallback_preserve_semantics() {
    let reject = router_from_request(request(vec![rule(
        DnsCond::Qname {
            not: false,
            matchers: vec![DnsDomainMatcher::Keyword("blocked".into())],
        },
        DnsRequestAction::Reject,
    )]));
    assert_eq!(
        reject.select_request("blocked-site.com", 1),
        DnsRequestDecision::Reject
    );
    let asis = router_from_request(request(vec![rule(
        DnsCond::Qname {
            not: false,
            matchers: vec![DnsDomainMatcher::Full("local.test".into())],
        },
        DnsRequestAction::AsIs,
    )]));
    assert_eq!(
        asis.select_request("local.test", 1),
        DnsRequestDecision::AsIs
    );
    let fallback = router_from_request(DnsRequestRouting {
        rules: vec![],
        fallback: DnsRequestAction::Upstream("fallback_upstream".into()),
    });
    assert_eq!(
        fallback.select_request("anything.com", 1),
        DnsRequestDecision::Upstream("fallback_upstream".into())
    );
}

#[test]
fn negated_qname_matches_complement() {
    let router = router_from_request(request(vec![rule(
        DnsCond::Qname {
            not: true,
            matchers: vec![DnsDomainMatcher::Suffix("cn".into())],
        },
        DnsRequestAction::Upstream("googledns".into()),
    )]));
    assert_eq!(
        router.select_request("google.com", 1),
        DnsRequestDecision::Upstream("googledns".into())
    );
    assert_eq!(
        router.select_request("baidu.cn", 1),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn negated_qtype_matches_complement() {
    let router = router_from_request(request(vec![rule(
        DnsCond::Qtype {
            not: true,
            types: vec![65],
        },
        DnsRequestAction::Upstream("googledns".into()),
    )]));
    assert_eq!(
        router.select_request("example.com", 1),
        DnsRequestDecision::Upstream("googledns".into())
    );
    assert_eq!(
        router.select_request("example.com", 65),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn negated_and_positive_conditions_are_anded() {
    let router = router_from_request(request(vec![DnsRequestRule {
        conditions: vec![
            DnsCond::Qname {
                not: false,
                matchers: vec![DnsDomainMatcher::Suffix("example.com".into())],
            },
            DnsCond::Qtype {
                not: true,
                types: vec![28],
            },
        ],
        action: DnsRequestAction::Upstream("alidns".into()),
    }]));
    assert_eq!(
        router.select_request("www.example.com", 1),
        DnsRequestDecision::Upstream("alidns".into())
    );
    assert_eq!(
        router.select_request("www.example.com", 28),
        DnsRequestDecision::Upstream("default".into())
    );
    assert_eq!(
        router.select_request("other.org", 1),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn sip_matches_hosts_and_mixed_family_cidrs() {
    let router = router_from_request(request(vec![rule(
        DnsCond::Sip {
            not: false,
            cidrs: vec![
                "192.168.50.1".into(),
                "100.64.0.0/10".into(),
                "2001:db8::/32".into(),
            ],
        },
        DnsRequestAction::Upstream("source".into()),
    )]));

    for source in ["192.168.50.1", "100.127.255.254", "2001:db8::1"] {
        assert_eq!(
            router.select_request_normalized("example.test", 1, Some(source.parse().unwrap())),
            DnsRequestDecision::Upstream("source".into())
        );
    }
    assert_eq!(
        router.select_request_normalized("example.test", 1, Some("192.168.50.2".parse().unwrap())),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn unknown_source_never_matches_positive_or_negated_sip() {
    for not in [false, true] {
        let router = router_from_request(request(vec![rule(
            DnsCond::Sip {
                not,
                cidrs: vec!["192.0.2.0/24".into()],
            },
            DnsRequestAction::Upstream("source".into()),
        )]));
        assert_eq!(
            router.select_request_normalized("example.test", 1, None),
            DnsRequestDecision::Upstream("default".into())
        );
    }
}

#[test]
fn negated_sip_matches_only_known_addresses_outside_its_networks() {
    let router = router_from_request(request(vec![rule(
        DnsCond::Sip {
            not: true,
            cidrs: vec!["192.0.2.0/24".into()],
        },
        DnsRequestAction::Upstream("outside".into()),
    )]));

    assert_eq!(
        router.select_request_normalized(
            "example.test",
            1,
            Some("198.51.100.1".parse::<IpAddr>().unwrap())
        ),
        DnsRequestDecision::Upstream("outside".into())
    );
    assert_eq!(
        router.select_request_normalized(
            "example.test",
            1,
            Some("192.0.2.1".parse::<IpAddr>().unwrap())
        ),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn invalid_sip_conditions_fail_router_construction() {
    for cidrs in [Vec::new(), vec!["not-an-ip".into()]] {
        let routing = DnsRouting {
            request: request(vec![rule(
                DnsCond::Sip { not: false, cidrs },
                DnsRequestAction::Reject,
            )]),
            ..DnsRouting::default()
        };
        assert!(DnsRouter::new(&routing).is_err());
    }
}

#[test]
fn subtag_rules_claim_only_node_hosts_of_matching_subscriptions() {
    let subtag = |not, tag: DnsTagMatcher| DnsCond::Subtag {
        not,
        tags: vec![tag],
    };
    let suffix = |value: &str| DnsCond::Qname {
        not: false,
        matchers: vec![DnsDomainMatcher::Suffix(value.into())],
    };
    let upstream = |name: &str| DnsRequestAction::Upstream(name.into());
    let router = router_from_request(request(vec![
        DnsRequestRule {
            conditions: vec![
                subtag(false, DnsTagMatcher::Keyword("Airport".into())),
                suffix("private.example"),
            ],
            action: upstream("providerdoh"),
        },
        rule(
            subtag(true, DnsTagMatcher::Exact("Other".into())),
            upstream("negated"),
        ),
        rule(suffix("example"), upstream("ordinary")),
    ]));
    let node = |host, tag: &str| {
        router
            .select_node_upstream(host, &[tag.to_owned()])
            .map(str::to_owned)
    };

    assert_eq!(
        node("a.private.example", "MyAirport").as_deref(),
        Some("providerdoh")
    );
    assert_eq!(
        node("a.public.example", "MyAirport").as_deref(),
        Some("negated")
    );
    // Ordinary rules and the fallback never claim a node host.
    assert_eq!(node("a.private.example", "Other"), None);
    // Client queries carry no subscription, so even !subtag() stays false.
    assert_eq!(
        router.select_request("a.private.example", 1),
        DnsRequestDecision::Upstream("ordinary".into())
    );
}

#[test]
fn subtag_exact_tags_are_anchored_literals_and_regex_tags_are_patterns() {
    let router = router_from_request(request(vec![rule(
        DnsCond::Subtag {
            not: false,
            tags: vec![
                DnsTagMatcher::Exact("Air.port".into()),
                DnsTagMatcher::Regex("^Paid-[0-9]+$".into()),
            ],
        },
        DnsRequestAction::Upstream("providerdoh".into()),
    )]));
    let claims = |tag: &str| {
        router
            .select_node_upstream("node.example", &[tag.to_owned()])
            .is_some()
    };
    for (tag, claimed) in [
        ("Air.port", true),
        ("AirXport", false),
        ("MyAir.port", false),
        ("Air.port2", false),
        ("air.port", false),
        ("Paid-12", true),
        ("Paid-x", false),
    ] {
        assert_eq!(claims(tag), claimed, "{tag}");
    }
}
