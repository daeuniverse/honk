use super::*;

#[test]
fn completeness_tracks_captured_frontier_and_sticky_loss_not_lifecycle_or_population() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Tcp);
    flow.transition(
        crate::observe::vocab::ConnectionState::Active,
        "transport_ready",
        crate::observe::vocab::ConnectionMilestone::TransportReady,
        None,
    );
    let page = store.page(filters("tcp", "all", true, 100), None).unwrap();
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["trace_status"], "complete");
    assert_eq!(detail["trace"]["status"], "complete");
    assert_eq!(detail["trace"]["missing"], json!([]));
    assert_eq!(page["coverage"]["kernel_direct"], "none");
    assert_eq!(page["flows"][0]["trace_status"], "complete");
    assert!(detail["ended_at"].is_null());

    flow.mark_gap(honk_outbound::runtime::flow_observation::GapReason::NotInstrumented);
    flow.step(Some(7), dial_mode());
    flow.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    let changed = store.get(flow.id()).unwrap();
    let next = store.page(filters("tcp", "all", false, 100), None).unwrap();
    assert_eq!(changed["state"], "closed");
    assert_eq!(changed["trace"]["status"], "partial");
    assert_eq!(changed["trace_status"], "partial");
    assert_eq!(next["flows"][0]["trace_status"], "partial");
    assert_eq!(changed["trace"]["missing"], json!(["not_instrumented"]));
    assert_eq!(page["flows"][0]["trace_status"], "complete");
}

#[test]
fn rejected_source_writes_never_authorize_causal_references() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Udp);
    assert!(store.record_step(flow.id(), Some(1), dial_mode()));
    assert!(!store.record_step("foreign-flow", Some(1), dial_mode()));
    for _ in 0..MAX_STEPS {
        flow.step(None, dial_mode());
    }
    assert!(!store.record_step(flow.id(), Some(1), dial_mode()));
    flow.finish(
        crate::observe::vocab::ConnectionState::Failed,
        "capture_lost",
    );
    assert!(!store.record_step(flow.id(), Some(1), dial_mode()));
    let detail = store.get(flow.id()).unwrap();
    assert!(
        detail["trace"]["missing"]
            .as_array()
            .unwrap()
            .contains(&json!("buffer_overflow"))
    );
}

#[test]
fn geoip_source_conditions_do_not_expand_into_false_trace_overflow() {
    use crate::routing::{ConnectionInfo, GeoSourceSet, Router};
    use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};

    // GeoIPList with one category and 128 IPv4 CIDRs, independent of host assets.
    let mut category = b"\x0a\x04test".to_vec();
    for subnet in 0..128 {
        category.extend_from_slice(&[0x12, 8, 0x0a, 4, 198, 51, subnet, 0, 0x10, 24]);
    }
    let mut geoip = vec![
        0x0a,
        (category.len() as u8 & 0x7f) | 0x80,
        (category.len() >> 7) as u8,
    ];
    geoip.extend(category);
    let mut routing = honk_config::routing::RoutingConfig::default();
    routing.default_outbound = "block".into();
    routing.rules = vec![RoutingRule {
        condition: RoutingCondition {
            geo_ip: vec!["test".into()],
            port: vec!["443".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("direct".into()),
        name: String::new(),
        priority: 0,
        must: false,
        mark: 0,
    }];
    let router = Router::from_config_with_geo_sources(
        &routing,
        &GeoSourceSet::from_bytes(Vec::new(), geoip),
    )
    .unwrap();
    let connection = ConnectionInfo {
        src_ip: "192.0.2.1".parse().unwrap(),
        src_port: 31000,
        dst_ip: "198.51.100.20".parse().unwrap(),
        dst_port: 443,
        protocol: "tcp",
        domain: None,
        process_name: None,
        mac: None,
        dscp: None,
        user: None,
    };
    let observed = router.route_full_observed(&connection, None, MAX_RULE_VALUES);
    assert_eq!(observed.matched.unwrap().action.outbound, "direct");
    let rules =
        crate::observe::rules::observed_rule_evaluations("instance", 7, &router, &observed.rules);
    assert_eq!(rules[0].conditions[0].expression, "dip(geoip: test)");
    assert_eq!(rules[0].conditions[0].result, "matched");
    assert_eq!(rules[0].conditions[1].expression, "dport(443)");

    let store = store();
    let flow = store
        .begin(
            crate::observe::vocab::Network::Tcp,
            (connection.src_ip, connection.src_port).into(),
            (connection.dst_ip, connection.dst_port).into(),
        )
        .unwrap();
    flow.step(
        Some(7),
        StepData::Route {
            evaluation_id: Uuid::new_v4().to_string(),
            chain: "traffic",
            plane: crate::observe::vocab::Plane::Userspace,
            rule_id: Some(rules[0].rule_id.clone()),
            outbound: Some("direct".into()),
            must: Some(false),
            mark: Some(0),
            input: Some(record::EvaluationInput::Traffic(record::RouteInput {
                network: "tcp",
                src_ip: connection.src_ip,
                src_port: connection.src_port,
                dst_ip: connection.dst_ip,
                dst_port: connection.dst_port,
                domain: None,
                pname: None,
                src_mac: None,
                dscp: None,
                mark: (),
                ingress: None,
                domain_rule_ids: None,
                domain_fact_bitmap: None,
                domain_fact_state: None,
            })),
            rules,
            dns_action: None,
        },
    );
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["trace_status"], "complete");
    assert_eq!(detail["trace"]["missing"], json!([]));
}

#[test]
fn reply_evidence_survives_later_send_bookkeeping_and_terminal_publication() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Udp);
    assert!(flow.first_reply());
    flow.transition(
        crate::observe::vocab::ConnectionState::Active,
        "reply_received",
        crate::observe::vocab::ConnectionMilestone::FirstReply,
        Some(true),
    );
    flow.transition(
        crate::observe::vocab::ConnectionState::Active,
        "send_completed",
        crate::observe::vocab::ConnectionMilestone::TargetRequestSent,
        Some(false),
    );
    flow.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "idle_after_reply",
    );
    let detail = store.get(flow.id()).unwrap();
    for step in detail["trace"]["steps"].as_array().unwrap().iter().skip(1) {
        assert_eq!(step["data"]["reply_received"], true);
    }
}

#[test]
fn observer_identity_cannot_be_rebound_to_another_retained_flow() {
    use honk_outbound::runtime::flow_observation::FlowEvent;
    let store = store();
    let first = Arc::new(begin(&store, crate::observe::vocab::Network::Tcp));
    let second = begin(&store, crate::observe::vocab::Network::Tcp);
    let before_first = store.get(first.id()).unwrap();
    let before_second = store.get(second.id()).unwrap();
    let observer = first.observer(1, None, "dial_target").unwrap();
    let mut context = observer.context();
    context.flow_id = second.id().parse().unwrap();
    observer.with_context(context).publish(FlowEvent::Gap(
        honk_outbound::runtime::flow_observation::GapReason::NotInstrumented,
    ));
    assert_eq!(store.get(first.id()).unwrap(), before_first);
    assert_eq!(store.get(second.id()).unwrap(), before_second);
}

#[test]
fn physical_dns_attempt_without_its_lookup_cannot_claim_complete_evidence() {
    use honk_outbound::runtime::flow_observation::FlowEvent;
    let store = store();
    let flow = Arc::new(begin(&store, crate::observe::vocab::Network::Tcp));
    let observer = flow.observer(1, None, "proxy_server").unwrap();
    let mut context = observer.context();
    context.lookup_id = Some(Uuid::new_v4());
    observer
        .with_context(context)
        .publish(FlowEvent::Transport {
            attempt_id: Uuid::new_v4(),
            server_addr: Some("127.0.0.1:53".parse().unwrap()),
            status: honk_outbound::runtime::flow_observation::TransportStatus::Started,
            resolution_location:
                honk_outbound::runtime::flow_observation::ResolutionLocation::Unknown,
            error: None,
        });
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["trace"]["status"], "partial");
    assert_eq!(detail["trace"]["missing"], json!(["not_instrumented"]));
}

#[test]
fn a_userspace_evaluation_is_recomputed_evidence_on_the_wire() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Tcp);
    flow.routed(
        "group",
        Some("gen:0:rule:0"),
        Some("dip(<redacted>)"),
        crate::observe::vocab::RoutingSource::Evaluation,
    );
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["rule_id"], "gen:0:rule:0");
    assert_eq!(detail["rule_source"], "recomputed");
    // No traffic-route step carries this rule, so its generation is unknown.
    assert_eq!(detail.get("rule_generation_id"), Some(&Value::Null));
    flow.routed(
        "group",
        None,
        None,
        crate::observe::vocab::RoutingSource::Forced,
    );
    assert_eq!(store.get(flow.id()).unwrap()["rule_source"], "unknown");
}

#[test]
fn trace_bounds_keep_terminal_state_and_explicit_loss_without_private_errors() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Tcp);
    let mut unsafe_data = dial_mode();
    if let StepData::DialMode { domain, .. } = &mut unsafe_data {
        *domain = Some("https://operator:credential@example.test".into());
    }
    flow.step(Some(1), unsafe_data);
    for _ in 0..MAX_STEPS + 10 {
        flow.step(Some(1), dial_mode());
    }
    flow.finish(
        crate::observe::vocab::ConnectionState::Failed,
        "dial_failed",
    );
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["state"], "failed");
    assert!(detail["ended_at"].is_string());
    assert_eq!(
        detail["trace"]["steps"].as_array().unwrap().len(),
        MAX_STEPS
    );
    assert_eq!(detail["trace"]["missing"], json!(["buffer_overflow"]));
    assert!(
        detail
            .to_string()
            .contains("https://operator:credential@example.test")
    );
}

#[test]
fn unsafe_causal_identity_drops_step_without_losing_the_terminal_outcome() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Udp);
    flow.step(
        None,
        StepData::Connection {
            state: crate::observe::vocab::ConnectionState::Dialing,
            reason: "transport_failed",
            milestone: crate::observe::vocab::ConnectionMilestone::Unknown,
            attempt_id: Some("https://operator:credential@example.test/private".into()),
            reply_received: None,
            error: Some(FlowError::UdpPrepareFailed),
            selections: Vec::new(),
            lookup_id: None,
            server_addr: None,
        },
    );
    flow.finish(
        crate::observe::vocab::ConnectionState::Failed,
        "transport_failed",
    );
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 2);
    assert_eq!(detail["state"], "failed");
    assert_eq!(
        detail["trace"]["steps"][1]["data"]["reason"],
        "transport_failed"
    );
    assert_eq!(detail["trace"]["missing"], json!(["redacted"]));
    assert!(!detail.to_string().contains("credential"));
}

#[test]
fn fixed_error_codes_and_safe_addresses_do_not_invent_input_provenance() {
    let store = store();
    let flow = store
        .begin(
            crate::observe::vocab::Network::Udp,
            "[::1]:31000".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        )
        .unwrap();
    flow.update_input(None, None, Some("client"), Some(42), None, Some(0), Some(0));
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 1);
    assert_eq!(detail["input"]["pid"], 42);
    flow.update_input(
        Some("secret.example.test"),
        Some(crate::observe::vocab::DomainSource::QuicSni),
        Some("client"),
        Some(42),
        None,
        Some(0),
        Some(0),
    );
    flow.step(
        None,
        StepData::Connection {
            state: crate::observe::vocab::ConnectionState::Dialing,
            reason: "transport_failed",
            milestone: crate::observe::vocab::ConnectionMilestone::Unknown,
            attempt_id: Some("attempt-1".into()),
            reply_received: None,
            error: Some(FlowError::UdpPrepareFailed),
            selections: Vec::new(),
            lookup_id: None,
            server_addr: None,
        },
    );
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["input"]["domain"], "secret.example.test");
    assert_eq!(detail["trace"]["steps"][1]["data"]["source"], "sniffer");
    assert_eq!(
        detail["trace"]["steps"][1]["data"]["values"]["src"],
        "[::1]:31000"
    );
    assert_eq!(
        detail["trace"]["steps"][1]["data"]["values"]["dst"],
        "[2001:db8::1]:443"
    );
    assert_eq!(
        detail["trace"]["steps"][2]["data"]["error"],
        "udp_prepare_failed"
    );
    assert_eq!(detail["trace"]["missing"], json!(["not_instrumented"]));
}

#[test]
fn optional_display_redaction_preserves_attempt_transitions_and_selection_ids() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Tcp);
    for status in [
        honk_outbound::runtime::flow_observation::TransportStatus::Started,
        honk_outbound::runtime::flow_observation::TransportStatus::Succeeded,
    ] {
        flow.step(
            Some(1),
            StepData::Outbound {
                attempt_id: "attempt-1".into(),
                status,
                error: None,
                attempt: OutboundAttempt {
                    parent_attempt_id: None,
                    lookup_id: None,
                    kind: "leaf",
                    evaluation_id: Some("evaluation-1".into()),
                    routing_source: crate::observe::vocab::RoutingSource::Evaluation,
                    routed_outbound: Some("Group/Proxy".into()),
                    effective_outbound: Some("Group/Proxy".into()),
                    mode_override: "none",
                    selection_path: vec![Selection {
                        group_id: "group-1".into(),
                        member_id: Some("node-1".into()),
                        member_name: Some("HK/Trojan".into()),
                        policy: "urltest",
                        reason: "selected",
                        selection: None,
                        health_family: None,
                        applied: None,
                    }],
                    leaf_node_id: Some("node-1".into()),
                    leaf_node_name: Some("HK/Trojan".into()),
                    target: Some("127.0.0.2:443".into()),
                    target_kind: "ip",
                    dial_ip: Some("127.0.0.2".parse().unwrap()),
                    server_addr: None,
                    resolution_location:
                        honk_outbound::runtime::flow_observation::ResolutionLocation::OriginalIp,
                },
            },
        );
    }
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 3);
    for (index, status) in [(1, "started"), (2, "succeeded")] {
        let data = &detail["trace"]["steps"][index]["data"];
        assert_eq!(data["attempt_id"], "attempt-1");
        assert_eq!(data["status"], status);
        assert_eq!(data["leaf_node_id"], "node-1");
        assert_eq!(data["selection_path"][0]["group_id"], "group-1");
        assert_eq!(data["selection_path"][0]["member_id"], "node-1");
        assert_eq!(data["selection_path"][0]["member_name"], "HK/Trojan");
        assert_eq!(data["routed_outbound"], "Group/Proxy");
        assert_eq!(data["x-honk"]["mode_override"], "none");
        assert!(data.get("mode_override").is_none());
    }
    assert_eq!(detail["trace"]["missing"], json!(["not_instrumented"]));
}

#[test]
fn captured_url_rule_values_survive_summary_updates_and_new_router_generations() {
    use crate::observe::rules::{RuleCondition, RuleEvaluation};
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Tcp);
    let expression = r#"pname("/usr/bin/user@host") && domain(regex: "https://example.test/path")"#;
    let id = "instance:7:rule:0";
    flow.step(
        Some(7),
        StepData::Route {
            evaluation_id: "evaluation-7".into(),
            chain: "traffic",
            plane: crate::observe::vocab::Plane::Userspace,
            rule_id: Some(id.into()),
            outbound: Some("group/name@host".into()),
            must: None,
            mark: None,
            input: Some(record::EvaluationInput::Traffic(record::RouteInput {
                network: "tcp",
                src_ip: "127.0.0.1".parse().unwrap(),
                src_port: 31000,
                dst_ip: "127.0.0.2".parse().unwrap(),
                dst_port: 443,
                domain: None,
                pname: Some("/usr/bin/user@host".into()),
                src_mac: None,
                dscp: None,
                mark: (),
                ingress: None,
                domain_rule_ids: None,
                domain_fact_bitmap: None,
                domain_fact_state: None,
            })),
            rules: vec![RuleEvaluation {
                rule_id: id.into(),
                expression: expression.into(),
                result: "matched",
                missing_inputs: vec![],
                conditions: vec![RuleCondition {
                    id: format!("{id}/condition:0"),
                    expression: expression.into(),
                    result: "matched",
                    missing_inputs: vec![],
                }],
            }],
            dns_action: None,
        },
    );
    flow.routed(
        "group/name@host",
        Some(id),
        Some("domain(<redacted>)"),
        crate::observe::vocab::RoutingSource::Evaluation,
    );
    let before = store.get(flow.id()).unwrap();
    assert_eq!(before["rule_expression"], expression);
    assert_eq!(
        before["rule_generation_id"],
        format!("{}:7", store.instance_id)
    );
    let later = begin(&store, crate::observe::vocab::Network::Tcp);
    later.routed(
        "new",
        Some("instance:8:rule:0"),
        Some("pname(\"new\")"),
        crate::observe::vocab::RoutingSource::Evaluation,
    );
    assert_eq!(store.get(flow.id()).unwrap(), before);
    assert_eq!(
        before["trace"]["steps"][1]["generation_id"],
        format!("{}:7", store.instance_id)
    );
    assert_eq!(before["trace"]["missing"], json!([]));
}

#[test]
fn oversized_utf8_display_is_explicit_capture_loss() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Tcp);
    let oversized = "界".repeat(MAX_TEXT / 3 + 1);
    let mut data = dial_mode();
    if let StepData::DialMode { domain, .. } = &mut data {
        *domain = Some(oversized.clone());
    }
    flow.step(Some(1), data);
    flow.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["trace_status"], "partial");
    assert!(
        detail["trace"]["missing"]
            .as_array()
            .unwrap()
            .contains(&json!("buffer_overflow"))
    );
    assert!(!detail.to_string().contains(&oversized));
    assert_eq!(detail["state"], "closed");
}

#[test]
fn rendered_rule_text_is_not_interpreted_as_an_internal_placeholder() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Tcp);
    let expression = "pname(unavailable without matcher)";
    flow.routed(
        "direct",
        Some("instance:1:rule:0"),
        Some(expression),
        crate::observe::vocab::RoutingSource::Evaluation,
    );
    assert_eq!(store.get(flow.id()).unwrap()["rule_expression"], expression);
}
