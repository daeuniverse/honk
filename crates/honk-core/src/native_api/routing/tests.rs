use super::*;
use honk_config::routing::{
    RoutingCondition, RoutingNotCondition, RoutingOutbound, RoutingRule as ConfigRule,
};

fn rule(condition: RoutingCondition, outbound: &str, priority: u32) -> ConfigRule {
    ConfigRule {
        name: "private-config-label".into(),
        condition,
        outbound: RoutingOutbound::Simple(outbound.into()),
        priority,
        must: false,
        mark: 0,
    }
}

fn input(value: Value) -> TraceInput {
    serde_json::from_value(value).unwrap()
}
fn destination() -> TraceInput {
    input(json!({"network":"tcp","dst_ip":"198.51.100.20","dst_port":443}))
}
fn trace(router: &Router, input: &TraceInput) -> RoutingEvaluation {
    evaluate(
        router,
        "instance",
        7,
        input,
        Instant::now() + TIMEOUT,
        &RequestId("test".into()),
    )
    .unwrap()
}
fn rules(router: &Router) -> RuleList {
    dictionary(
        router,
        "instance",
        7,
        Instant::now() + TIMEOUT,
        &RequestId("test".into()),
    )
    .unwrap()
}
fn process(name: &str) -> RoutingCondition {
    RoutingCondition {
        process_name: vec![name.into()],
        ..Default::default()
    }
}
fn ip() -> RoutingCondition {
    RoutingCondition {
        ip: vec!["198.51.100.0/24".into()],
        ..Default::default()
    }
}

#[test]
fn earlier_unknown_is_not_a_miss_and_negation_preserves_it() {
    let router = Router::new(
        &[
            rule(
                RoutingCondition {
                    not: RoutingNotCondition {
                        process_name: vec!["curl".into()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                "direct",
                0,
            ),
            rule(ip(), "proxy", 1),
        ],
        "block",
    )
    .unwrap();
    let result = trace(&router, &destination());
    assert_eq!(result.decision, "indeterminate");
    assert_eq!(result.outbound, None);
    assert_eq!(result.missing_inputs, ["pname"]);
    assert_eq!(
        result
            .rules
            .iter()
            .map(|rule| rule.result)
            .collect::<Vec<_>>(),
        ["indeterminate", "matched", "skipped"]
    );
    assert_eq!(result.rules[0].conditions[0].result, "indeterminate");
    assert_eq!(result.rules[0].conditions[0].missing_inputs, ["pname"]);

    let mut known = destination();
    known.pname = Some("curl".into());
    assert_eq!(trace(&router, &known).outbound.as_deref(), Some("proxy"));
    known.pname = Some("wget".into());
    let result = trace(&router, &known);
    assert_eq!(result.outbound.as_deref(), Some("direct"));
    assert_eq!(result.rules[1].conditions[0].result, "skipped");
}

#[test]
fn unknown_paths_that_agree_and_irrelevant_unknowns_are_determinate() {
    let router = Router::new(
        &[rule(process("curl"), "proxy", 0), rule(ip(), "proxy", 1)],
        "block",
    )
    .unwrap();
    assert_eq!(
        trace(&router, &destination()).outbound.as_deref(),
        Some("proxy")
    );

    let router = Router::new(
        &[rule(
            RoutingCondition {
                domain: vec!["private.invalid".into()],
                port: vec!["53".into()],
                process_name: vec!["curl".into()],
                ..Default::default()
            },
            "proxy",
            0,
        )],
        "direct",
    )
    .unwrap();
    let result = trace(&router, &destination());
    assert_eq!(result.outbound.as_deref(), Some("direct"));
    assert!(result.missing_inputs.is_empty());
    assert_eq!(result.rules[0].result, "not_matched");
    assert_eq!(
        result.rules[0]
            .conditions
            .iter()
            .map(|condition| condition.result)
            .collect::<Vec<_>>(),
        ["indeterminate", "not_matched", "skipped"]
    );
    assert_eq!(result.rules[0].conditions[0].missing_inputs, ["domain"]);
    assert!(result.rules[0].missing_inputs.is_empty());
}

#[test]
fn missing_metadata_and_name_only_addresses_remain_unknown() {
    let router = Router::new(
        &[rule(
            RoutingCondition {
                source_ip: vec!["192.0.2.0/24".into()],
                source_port: vec!["50000".into()],
                ip_version: vec!["6".into()],
                dscp: vec!["12".into()],
                mac: vec!["aa:bb:cc:dd:ee:ff".into()],
                ..Default::default()
            },
            "proxy",
            0,
        )],
        "direct",
    )
    .unwrap();
    let result = trace(
        &router,
        &input(json!({"network":"udp","domain":"example.test","dst_port":53})),
    );
    assert_eq!(result.dst_ip, None);
    assert_eq!(result.outbound, None);
    let mut missing = result.missing_inputs;
    missing.sort_unstable();
    assert_eq!(missing, ["dscp", "dst_ip", "src_ip", "src_mac", "src_port"]);
    assert_eq!(result.rules[1].result, "matched");
}

#[test]
fn known_inputs_agree_with_real_router_and_do_not_change_its_policy() {
    let router = Router::new(
        &[
            rule(
                RoutingCondition {
                    domain_suffix: vec!["example.test".into()],
                    protocol: vec!["tcp".into(), "udp".into()],
                    port: vec!["443".into()],
                    not: RoutingNotCondition {
                        process_name: vec!["curl".into()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                "proxy",
                0,
            ),
            rule(
                RoutingCondition {
                    ip: vec!["2001:db8::/32".into()],
                    ..Default::default()
                },
                "v6",
                1,
            ),
        ],
        "direct",
    )
    .unwrap();
    let before = router.policy_fingerprint();
    let bitmap = router.domain_bitmap("www.example.test").unwrap().bitmap;
    for (domain, address, port, pname, expected) in [
        ("www.example.test", "198.51.100.20", 443, "wget", "proxy"),
        ("www.example.test", "198.51.100.20", 443, "curl", "direct"),
        ("other.test", "2001:db8::1", 80, "wget", "v6"),
        ("other.test", "198.51.100.20", 80, "wget", "direct"),
    ] {
        let supplied = input(json!({"network":"tcp","domain":domain,"dst_ip":address,
            "dst_port":port,"src_ip":"192.0.2.10","src_port":50000,"pname":pname,"dscp":0}));
        let connection = crate::routing::ConnectionInfo {
            domain: supplied.domain.clone(),
            dst_ip: supplied.dst_ip.unwrap(),
            dst_port: supplied.dst_port,
            src_ip: supplied.src_ip.unwrap(),
            src_port: supplied.src_port.unwrap(),
            protocol: "tcp",
            process_name: supplied.pname.clone(),
            mac: None,
            dscp: supplied.dscp,
        };
        assert_eq!(router.route(&connection), expected);
        let result = trace(&router, &supplied);
        assert_eq!(result.outbound.as_deref(), Some(expected));
        let winning = result
            .rules
            .iter()
            .find(|rule| rule.result == "matched")
            .unwrap();
        assert_eq!(
            winning.rule_id,
            rule_id(
                "instance",
                7,
                router.route_full(&connection).map(|route| route.rule_id)
            )
        );
    }
    assert_eq!(router.policy_fingerprint(), before);
    assert_eq!(
        router.domain_bitmap("www.example.test").unwrap().bitmap,
        bitmap
    );
}

#[test]
fn dictionary_and_trace_share_complete_priority_order_and_redacted_ids() {
    let mut first = rule(
        RoutingCondition {
            domain_regex: vec!["credential-secret.example".into()],
            process_name: vec!["/private/token".into()],
            ..Default::default()
        },
        "proxy",
        1,
    );
    first.must = true;
    let router = Router::new(
        &[
            rule(ip(), "direct", 2),
            first,
            rule(process("curl"), "block", 1),
        ],
        "fallback-group",
    )
    .unwrap();
    let dictionary = rules(&router);
    assert_eq!(
        dictionary
            .rules
            .iter()
            .map(|rule| (rule.index, rule.outbound.as_str(), rule.kind))
            .collect::<Vec<_>>(),
        [
            (0, "proxy", "rule"),
            (1, "block", "rule"),
            (2, "direct", "rule"),
            (3, "fallback-group", "fallback")
        ]
    );
    assert!(dictionary.rules[0].must);
    assert!(dictionary.rules.iter().all(|rule| rule.source.is_none()));
    assert_eq!(dictionary.fallback.outbound, dictionary.rules[3].outbound);
    assert_eq!(
        dictionary
            .rules
            .iter()
            .map(|rule| &rule.rule_id)
            .collect::<Vec<_>>(),
        trace(&router, &destination())
            .rules
            .iter()
            .map(|rule| &rule.rule_id)
            .collect::<Vec<_>>()
    );
    let json = serde_json::to_string(&dictionary).unwrap();
    for value in ["credential-secret", "/private", "token"] {
        assert!(json.contains(value));
    }
    assert!(!json.contains("private-config-label"));
    assert_ne!(
        rule_id("instance", 7, Some(0)),
        rule_id("instance", 8, Some(0))
    );
    assert_ne!(
        rule_id("instance", 7, Some(0)),
        rule_id("other-instance", 7, Some(0))
    );
    assert_ne!(
        rule_id("instance", 7, Some(0)),
        rule_id("instance", 7, None)
    );
}

#[test]
fn held_router_keeps_old_dictionary_and_fallback_after_replacement() {
    let mut router = Router::new(&[rule(ip(), "old", 0)], "old-fallback").unwrap();
    let pinned = router.clone();
    router = Router::new(&[rule(process("curl"), "new", 0)], "new-fallback").unwrap();
    assert_eq!(
        trace(&pinned, &destination()).outbound.as_deref(),
        Some("old")
    );
    assert_eq!(rules(&pinned).fallback.outbound, "old-fallback");
    assert_eq!(rules(&router).fallback.outbound, "new-fallback");
    let empty = Router::new(&[], "direct").unwrap();
    assert_eq!(
        trace(&empty, &destination()).rules[0].rule_id,
        rules(&empty).rules[0].rule_id
    );
    assert_eq!(
        trace(&empty, &destination()).outbound.as_deref(),
        Some("direct")
    );
}

#[test]
fn rule_and_condition_evidence_bounds_reject_without_truncation() {
    let id = RequestId("test".into());
    let policy = vec![rule(ip(), "proxy", 0); 128];
    let router = Router::new(&policy[..127], "direct").unwrap();
    assert_eq!(trace(&router, &destination()).rules.len(), 128);
    let router = Router::new(&policy, "direct").unwrap();
    assert_eq!(
        evaluate(
            &router,
            "instance",
            7,
            &destination(),
            Instant::now() + TIMEOUT,
            &id
        )
        .unwrap_err()
        .into_response()
        .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let policy = vec![rule(ip(), "proxy", 0); MAX_RULES];
    let router = Router::new(&policy[..MAX_RULES - 1], "direct").unwrap();
    assert_eq!(rules(&router).rules.len(), MAX_RULES);
    let router = Router::new(&policy, "direct").unwrap();
    assert_eq!(
        dictionary(&router, "instance", 7, Instant::now() + TIMEOUT, &id)
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let router = Router::new(&[], "direct").unwrap();
    assert_eq!(
        evaluate(&router, "instance", 7, &destination(), Instant::now(), &id)
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn trace_input_rejects_unknown_fields_and_invalid_metadata() {
    let id = RequestId("test".into());
    for value in [
        json!({"network":"tcp","dst_port":443}),
        json!({"network":"tcp","dst_ip":"192.0.2.1","dst_port":0}),
        json!({"network":"tcp","dst_ip":"192.0.2.1","dst_port":443,"src_port":0}),
        json!({"network":"tcp","dst_ip":"192.0.2.1","dst_port":443,"dscp":64}),
        json!({"network":"tcp","domain":"empty..label","dst_port":443}),
    ] {
        assert!(input(value).validate(&id).is_err());
    }
    for value in [
        json!({"network":"sctp","dst_ip":"192.0.2.1","dst_port":443}),
        json!({"network":"tcp","dst_ip":"192.0.2.1:443","dst_port":443}),
        json!({"network":"tcp","dst_ip":"192.0.2.1","dst_port":443,"mac":"aa:bb:cc:dd:ee:ff"}),
        json!({"network":"tcp","dst_ip":"192.0.2.1","dst_port":443,"mark":4294967296u64}),
    ] {
        assert!(serde_json::from_value::<TraceInput>(value).is_err());
    }
}

fn connection() -> crate::routing::ConnectionInfo {
    crate::routing::ConnectionInfo {
        domain: None,
        dst_ip: "198.51.100.20".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.0.2.10".parse().unwrap(),
        src_port: 50000,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    }
}

#[test]
fn observed_route_retains_real_priority_and_short_circuit_outcomes() {
    let router = Router::new(
        &[
            rule(ip(), "later", 20),
            rule(
                RoutingCondition {
                    domain: vec!["absent.test".into()],
                    ..ip()
                },
                "miss",
                0,
            ),
            rule(ip(), "winner", 10),
        ],
        "fallback",
    )
    .unwrap();
    let observed = router.route_full_observed(&connection(), None, 64);
    assert!(!observed.truncated);
    assert_eq!(observed.matched.unwrap().outbound_name, "winner");
    let evaluated = observed_rule_evaluations("instance", 7, &router, &observed.rules);
    assert_eq!(
        evaluated.iter().map(|rule| rule.result).collect::<Vec<_>>(),
        ["not_matched", "matched", "skipped", "skipped"]
    );
    assert_eq!(
        evaluated[0]
            .conditions
            .iter()
            .map(|condition| condition.result)
            .collect::<Vec<_>>(),
        ["not_matched", "skipped"]
    );
    assert_eq!(evaluated[1].rule_id, rule_id("instance", 7, Some(1)));
    assert_eq!(evaluated[1].conditions[0].result, "matched");
    assert_eq!(evaluated[2].conditions[0].result, "skipped");
    assert_eq!(evaluated[3].rule_id, rule_id("instance", 7, None));
}

#[test]
fn observed_route_preserves_empty_rule_miss_and_fallback() {
    let router = Router::new(
        &[
            rule(RoutingCondition::default(), "empty", 0),
            rule(process("curl"), "process", 1),
        ],
        "fallback",
    )
    .unwrap();
    let observed = router.route_full_observed(&connection(), None, 4);
    assert!(observed.matched.is_none());
    assert!(!observed.truncated);
    assert_eq!(
        observed
            .rules
            .iter()
            .map(|rule| rule.result)
            .collect::<Vec<_>>(),
        [
            MatchResult::NotMatched,
            MatchResult::NotMatched,
            MatchResult::Matched
        ]
    );
    assert!(observed.rules[0].conditions.is_empty());
    let evaluated = observed_rule_evaluations("instance", 7, &router, &observed.rules);
    assert_eq!(evaluated[2].rule_id, rule_id("instance", 7, None));
    assert_eq!(evaluated[2].expression, "fallback");
    let empty = Router::new(&[], "direct").unwrap();
    let observed = empty.route_full_observed(&connection(), None, 1);
    assert!(observed.matched.is_none());
    assert!(!observed.truncated);
    assert_eq!(observed.rules[0].result, MatchResult::Matched);
}

#[test]
fn observed_route_uses_production_absence_before_negation_not_simulation_unknowns() {
    let router = Router::new(
        &[
            rule(
                RoutingCondition {
                    domain: vec!["example.test".into()],
                    process_name: vec!["curl".into()],
                    mac: vec!["aa:bb:cc:dd:ee:ff".into()],
                    dscp: vec!["8".into()],
                    ..Default::default()
                },
                "present",
                0,
            ),
            rule(
                RoutingCondition {
                    not: RoutingNotCondition {
                        domain: vec!["example.test".into()],
                        process_name: vec!["curl".into()],
                        mac: vec!["aa:bb:cc:dd:ee:ff".into()],
                        dscp: vec!["8".into()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                "absent",
                1,
            ),
        ],
        "fallback",
    )
    .unwrap();
    let observed = router.route_full_observed(&connection(), None, 64);
    assert_eq!(observed.matched.unwrap().outbound_name, "absent");
    assert_eq!(
        observed.rules[0].conditions,
        [
            MatchResult::NotMatched,
            MatchResult::Skipped,
            MatchResult::Skipped,
            MatchResult::Skipped
        ]
    );
    assert_eq!(observed.rules[1].conditions, [MatchResult::Matched; 4]);
    let evaluated = observed_rule_evaluations("instance", 7, &router, &observed.rules);
    assert!(evaluated.iter().all(|rule| {
        rule.missing_inputs.is_empty()
            && rule
                .conditions
                .iter()
                .all(|condition| condition.missing_inputs.is_empty())
    }));
    assert_eq!(trace(&router, &destination()).decision, "indeterminate");
}

#[test]
fn observed_route_uses_authoritative_domain_bitmap_and_preserves_action() {
    let positive = rule(
        RoutingCondition {
            domain: vec!["example.test".into()],
            ..Default::default()
        },
        "proxy",
        0,
    );
    let mut negative = rule(
        RoutingCondition {
            not: RoutingNotCondition {
                domain: vec!["example.test".into()],
                ..Default::default()
            },
            ..Default::default()
        },
        "direct",
        1,
    );
    negative.must = true;
    negative.mark = 42;
    let router = Router::new(&[positive, negative], "fallback").unwrap();
    let mut conn = connection();
    conn.domain = Some("example.test".into());
    let zero = router.domain_bitmap("other.test").unwrap();
    let observed = router.route_full_observed(&conn, Some(&zero), 64);
    let matched = observed.matched.unwrap();
    assert_eq!(
        (matched.outbound_name, matched.must, matched.mark),
        ("direct", true, 42)
    );
    assert_eq!(observed.rules[0].conditions, [MatchResult::NotMatched]);
    assert_eq!(observed.rules[1].conditions, [MatchResult::Matched]);
    conn.domain = None;
    let positive = router.domain_bitmap("example.test").unwrap();
    let observed = router.route_full_observed(&conn, Some(&positive), 64);
    assert_eq!(observed.matched.unwrap().outbound_name, "proxy");
    assert_eq!(observed.rules[0].conditions, [MatchResult::Matched]);
    assert_eq!(observed.rules[1].conditions, [MatchResult::Skipped]);
}

#[test]
fn observed_route_budget_only_truncates_evidence_never_decisions() {
    let mut winner = rule(ip(), "winner", 1);
    winner.mark = 42;
    winner.must = true;
    let router = Router::new(
        &[
            rule(
                RoutingCondition {
                    domain: vec!["absent.test".into()],
                    ..ip()
                },
                "miss",
                0,
            ),
            winner,
            rule(ip(), "later", 2),
        ],
        "fallback",
    )
    .unwrap();
    let complete = router.route_full_observed(&connection(), None, 64);
    let required: usize = complete
        .rules
        .iter()
        .map(|rule| 1 + rule.conditions.len())
        .sum();
    for budget in 0..=required {
        let observed = router.route_full_observed(&connection(), None, budget);
        let matched = observed.matched.unwrap();
        assert_eq!(
            (matched.outbound_name, matched.must, matched.mark),
            ("winner", true, 42)
        );
        assert_eq!(observed.truncated, budget < required, "budget={budget}");
        assert_eq!(
            observed
                .rules
                .iter()
                .map(|rule| 1 + rule.conditions.len())
                .sum::<usize>(),
            budget
        );
        for (captured, full) in observed.rules.iter().zip(&complete.rules) {
            assert_eq!(captured.result, full.result);
            assert_eq!(
                captured.conditions,
                full.conditions[..captured.conditions.len()]
            );
        }
    }
    let mut miss = connection();
    miss.dst_ip = "203.0.113.10".parse().unwrap();
    let observed = router.route_full_observed(&miss, None, 0);
    assert!(observed.matched.is_none());
    assert!(observed.rules.is_empty());
    assert!(observed.truncated);
    assert_eq!(router.route(&miss), "fallback");
}
