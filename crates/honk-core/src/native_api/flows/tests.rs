use super::record::{FlowError, OutboundAttempt, Selection};
use super::*;
use honk_config::types::DialMode;

fn store() -> Arc<FlowStore> {
    let instance = Uuid::new_v4().to_string();
    Arc::new(FlowStore::new(
        instance.clone(),
        Arc::new(EventHub::new(instance)),
    ))
}

fn begin(store: &Arc<FlowStore>, network: &'static str) -> FlowGuard {
    store.begin(
        network,
        "127.0.0.1:31000".parse().unwrap(),
        "127.0.0.2:443".parse().unwrap(),
    )
}

fn request_id() -> RequestId {
    RequestId("flow-test".to_owned())
}

fn filters(network: &str, state: &str, full: bool, limit: usize) -> Filters {
    Filters {
        network: network.to_owned(),
        state: state.to_owned(),
        connection_id: None,
        full,
        limit,
    }
}

fn error_code(error: ApiError, status: StatusCode, code: &str) {
    assert_eq!(serde_json::to_value(&error).unwrap()["error"]["code"], code);
    assert_eq!(error.into_response().status(), status);
}

fn dial_mode() -> StepData {
    StepData::DialMode {
        configured: DialMode::Ip,
        effective_target: "ip",
        domain: None,
        domain_source: None,
        verification: "not_required",
        reason: "original_destination",
    }
}

#[test]
fn completeness_tracks_captured_frontier_and_sticky_loss_not_lifecycle_or_population() {
    let store = store();
    let flow = begin(&store, "tcp");
    flow.transition("active", "transport_ready", "transport_ready", None);
    let page = store
        .page(filters("tcp", "all", true, 100), None, &request_id())
        .unwrap();
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["trace_status"], "complete");
    assert_eq!(detail["trace"]["status"], "complete");
    assert_eq!(detail["trace"]["missing"], json!([]));
    assert_eq!(page["coverage"]["kernel_direct"], "none");
    assert_eq!(page["flows"][0]["trace_status"], "complete");
    assert!(detail["ended_at"].is_null());

    flow.mark_gap("not_instrumented");
    flow.step(Some(7), dial_mode());
    flow.finish("closed", "relay_finished");
    let changed = store.get(flow.id(), &request_id()).unwrap();
    let next = store
        .page(filters("tcp", "all", false, 100), None, &request_id())
        .unwrap();
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
    let flow = begin(&store, "udp");
    assert!(store.record_step(flow.id(), Some(1), dial_mode()));
    assert!(!store.record_step("foreign-flow", Some(1), dial_mode()));
    for _ in 0..MAX_STEPS {
        flow.step(None, dial_mode());
    }
    assert!(!store.record_step(flow.id(), Some(1), dial_mode()));
    flow.finish("failed", "capture_lost");
    assert!(!store.record_step(flow.id(), Some(1), dial_mode()));
    let detail = store.get(flow.id(), &request_id()).unwrap();
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
    let router = Router::new_with_geo_sources(
        &[RoutingRule {
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
        }],
        "block",
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
    };
    let observed = router.route_full_observed(&connection, None, MAX_RULE_VALUES);
    assert_eq!(observed.matched.unwrap().outbound_name, "direct");
    let rules =
        super::super::routing::observed_rule_evaluations("instance", 7, &router, &observed.rules);
    assert_eq!(rules[0].conditions[0].expression, "dip(geoip: test)");
    assert_eq!(rules[0].conditions[0].result, "matched");
    assert_eq!(rules[0].conditions[1].expression, "dport(443)");

    let store = store();
    let flow = store.begin(
        "tcp",
        (connection.src_ip, connection.src_port).into(),
        (connection.dst_ip, connection.dst_port).into(),
    );
    flow.step(
        Some(7),
        StepData::Route {
            evaluation_id: Uuid::new_v4().to_string(),
            chain: "traffic",
            plane: "userspace",
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
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["trace_status"], "complete");
    assert_eq!(detail["trace"]["missing"], json!([]));
}

#[test]
fn reply_evidence_survives_later_send_bookkeeping_and_terminal_publication() {
    let store = store();
    let flow = begin(&store, "udp");
    assert!(flow.first_reply());
    flow.transition("active", "reply_received", "first_reply", Some(true));
    flow.transition(
        "active",
        "send_completed",
        "target_request_sent",
        Some(false),
    );
    flow.finish("closed", "idle_after_reply");
    let detail = store.get(flow.id(), &request_id()).unwrap();
    for step in detail["trace"]["steps"].as_array().unwrap().iter().skip(1) {
        assert_eq!(step["data"]["reply_received"], true);
    }
}

#[test]
fn observer_identity_cannot_be_rebound_to_another_retained_flow() {
    use honk_outbound::runtime::flow_observation::FlowEvent;
    let store = store();
    let first = Arc::new(begin(&store, "tcp"));
    let second = begin(&store, "tcp");
    let before_first = store.get(first.id(), &request_id()).unwrap();
    let before_second = store.get(second.id(), &request_id()).unwrap();
    let observer = first.observer(1, None, "dial_target").unwrap();
    let mut context = observer.context();
    context.flow_id = second.id().parse().unwrap();
    observer
        .with_context(context)
        .publish(FlowEvent::Gap("not_instrumented"));
    assert_eq!(store.get(first.id(), &request_id()).unwrap(), before_first);
    assert_eq!(
        store.get(second.id(), &request_id()).unwrap(),
        before_second
    );
}

#[test]
fn physical_dns_attempt_without_its_lookup_cannot_claim_complete_evidence() {
    use honk_outbound::runtime::flow_observation::FlowEvent;
    let store = store();
    let flow = Arc::new(begin(&store, "tcp"));
    let observer = flow.observer(1, None, "proxy_server").unwrap();
    let mut context = observer.context();
    context.lookup_id = Some(Uuid::new_v4());
    observer
        .with_context(context)
        .publish(FlowEvent::Transport {
            attempt_id: Uuid::new_v4(),
            server_addr: Some("127.0.0.1:53".parse().unwrap()),
            status: "started",
            resolution_location: "unknown",
            error: None,
        });
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["trace"]["status"], "partial");
    assert_eq!(detail["trace"]["missing"], json!(["not_instrumented"]));
}

#[test]
fn tuple_reincarnation_keeps_history_and_exact_connection_identity() {
    let store = store();
    let first = begin(&store, "tcp");
    first.attach_connection("connection-old");
    first.routed("original-group", None, None, "unknown");
    first.selected(vec![
        "original-group-id".to_owned(),
        "original-node-id".to_owned(),
    ]);
    first.step(Some(7), dial_mode());
    first.finish("closed", "relay_finished");
    let second = begin(&store, "tcp");
    second.attach_connection("connection-new");
    second.routed("replacement-group", None, None, "unknown");
    second.selected(vec![
        "replacement-group-id".to_owned(),
        "replacement-node-id".to_owned(),
    ]);
    assert_ne!(first.id(), second.id());
    let evidence = store.connection_evidence(first.id()).unwrap();
    assert_eq!(evidence.chain, ["original-group-id", "original-node-id"]);
    let detail = store.get(first.id(), &request_id()).unwrap();
    assert_eq!(detail["outbound"], "original-group");
    assert_eq!(
        detail["trace"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["stage"] == "dial_mode")
            .unwrap()["generation_id"],
        format!("{}:7", store.instance_id)
    );
    let mut query = filters("all", "all", true, 100);
    query.connection_id = Some("connection-old".to_owned());
    let page = store.page(query, None, &request_id()).unwrap();
    assert_eq!(page["flows"].as_array().unwrap().len(), 1);
    assert_eq!(page["flows"][0]["id"], first.id());
    assert_eq!(page["flows"][0]["input"]["src"], "127.0.0.1:31000");
}

#[test]
fn guards_finalize_once_and_do_not_fabricate_kernel_connection_close() {
    let store = store();
    let flow = begin(&store, "udp");
    assert!(flow.first_reply());
    assert!(!flow.first_reply());
    flow.finish("closed", "idle_after_reply");
    let id = flow.id().to_owned();
    let terminal = store.get(&id, &request_id()).unwrap();
    flow.finish("failed", "late_error");
    flow.routed("late-outbound", None, None, "unknown");
    drop(flow);
    assert_eq!(store.get(&id, &request_id()).unwrap(), terminal);
    assert_eq!(
        terminal["trace"]["steps"][1]["data"]["reply_received"],
        true
    );

    let cancelled = begin(&store, "tcp");
    let id = cancelled.id().to_owned();
    drop(cancelled);
    let detail = store.get(&id, &request_id()).unwrap();
    assert_eq!(detail["state"], "failed");
    assert_eq!(detail["trace"]["steps"][1]["data"]["reason"], "cancelled");

    let handoff = begin(&store, "udp");
    handoff.finish("unknown", "kernel_handoff");
    let detail = store.get(handoff.id(), &request_id()).unwrap();
    assert_eq!(detail["state"], "unknown");
    assert!(detail["ended_at"].is_string());
}

#[test]
fn pinned_pages_survive_mutation_and_bind_all_filters() {
    let store = store();
    let old = begin(&store, "tcp");
    old.transition("active", "ready", "transport_ready", None);
    let ignored = begin(&store, "udp");
    ignored.transition("active", "ready", "transport_ready", None);
    let recent = begin(&store, "tcp");
    recent.transition("active", "ready", "transport_ready", None);
    let query = filters("tcp", "active", true, 1);
    let first = store.page(query.clone(), None, &request_id()).unwrap();
    assert_eq!(first["flows"][0]["id"], recent.id());
    let cursor = first["next_cursor"].as_str().unwrap();
    old.finish("closed", "relay_finished");
    let newcomer = begin(&store, "tcp");
    newcomer.transition("active", "ready", "transport_ready", None);
    let second = store
        .page(query.clone(), Some(cursor), &request_id())
        .unwrap();
    assert_eq!(second["observed_at"], first["observed_at"]);
    assert_eq!(second["flows"][0]["id"], old.id());
    assert_eq!(second["flows"][0]["state"], "active");
    assert!(second["next_cursor"].is_null());
    for changed in [
        filters("udp", "active", true, 1),
        filters("tcp", "closed", true, 1),
        filters("tcp", "active", false, 1),
    ] {
        error_code(
            store
                .page(changed, Some(cursor), &request_id())
                .unwrap_err(),
            StatusCode::GONE,
            "snapshot_expired",
        );
    }
    let other_instance = super::tests::store();
    error_code(
        other_instance
            .page(query.clone(), Some(cursor), &request_id())
            .unwrap_err(),
        StatusCode::GONE,
        "snapshot_expired",
    );
    store.inner.lock().snapshots[0].created = Instant::now() - SNAPSHOT_TTL;
    error_code(
        store.page(query, Some(cursor), &request_id()).unwrap_err(),
        StatusCode::GONE,
        "snapshot_expired",
    );
}

#[test]
fn snapshot_capacity_is_explicit_and_recording_disable_releases_every_owner() {
    let store = store();
    store.set_limits(64, 1);
    let first = begin(&store, "tcp");
    let _second = begin(&store, "tcp");
    let query = filters("all", "all", true, 1);
    let mut cursor = String::new();
    let mut oldest = String::new();
    for round in 0..MAX_SNAPSHOTS {
        let page = store.page(query.clone(), None, &request_id()).unwrap();
        cursor = page["next_cursor"].as_str().unwrap().to_owned();
        if round == 0 {
            oldest = cursor.clone();
        }
    }
    // A full table makes room by dropping its oldest snapshot; only that
    // reader starts over, the newest cursors stay valid.
    let page = store.page(query.clone(), None, &request_id()).unwrap();
    assert!(page["next_cursor"].is_string());
    assert_eq!(store.inner.lock().snapshots.len(), MAX_SNAPSHOTS);
    error_code(
        store
            .page(query.clone(), Some(&oldest), &request_id())
            .unwrap_err(),
        StatusCode::GONE,
        "snapshot_expired",
    );
    store
        .page(query.clone(), Some(&cursor), &request_id())
        .unwrap();
    store.set_recording(false);
    let inert = begin(&store, "tcp");
    assert!(inert.id().is_empty());
    assert!(!inert.first_reply());
    first.finish("closed", "late_finish");
    error_code(
        store
            .page(query.clone(), Some(&cursor), &request_id())
            .unwrap_err(),
        StatusCode::GONE,
        "snapshot_expired",
    );
    let page = store.page(query, None, &request_id()).unwrap();
    assert_eq!(page["flows"], json!([]));
    assert_eq!(page["coverage"]["userspace_tcp"], "none");
    let inner = store.inner.lock();
    assert_eq!(inner.records.capacity(), 0);
    assert_eq!(inner.snapshots.capacity(), 0);
    assert_eq!(inner.tombstones.capacity(), 0);
    assert_eq!(inner.record_bytes + inner.snapshot_bytes, 0);
    drop(inner);
    store.set_recording(true);
    assert_eq!(store.inner.lock().max_records, 64);
    assert_eq!(store.inner.lock().retention, Duration::from_secs(1));
    first.finish("closed", "late_finish_after_restart");
    assert!(store.inner.lock().records.is_empty());
    let restarted = begin(&store, "tcp");
    assert_ne!(restarted.id(), first.id());
    assert!(!restarted.id().is_empty());
}

#[test]
fn aged_out_records_report_one_gap_per_interval_with_the_running_count() {
    let store = store();
    let gaps = || {
        store
            .events
            .buffered_kinds()
            .into_iter()
            .filter(|kind| *kind == "flow.gap")
            .count()
    };
    for _ in 0..5 {
        begin(&store, "tcp").finish("closed", "relay_finished");
    }
    assert_eq!(gaps(), 0);
    let later = Instant::now() + TERMINAL_TTL;
    store.prune(&mut store.inner.lock(), later);
    assert_eq!(gaps(), 1);
    let inner = store.inner.lock();
    assert_eq!(inner.dropped, 5);
    assert!(inner.records.is_empty());
    drop(inner);
    // Within the interval a further eviction only advances the count; after
    // it the next eviction is reported again.
    begin(&store, "tcp").finish("closed", "relay_finished");
    store.prune(&mut store.inner.lock(), later + Duration::from_secs(1));
    assert_eq!((gaps(), store.inner.lock().dropped), (1, 6));
    begin(&store, "tcp").finish("closed", "relay_finished");
    store.prune(&mut store.inner.lock(), later + EVICTED_GAP_INTERVAL);
    assert_eq!((gaps(), store.inner.lock().dropped), (2, 7));
}

#[test]
fn room_making_overflow_is_reported_per_interval_but_lost_history_per_record() {
    let store = store();
    let gaps = || {
        store
            .events
            .buffered_kinds()
            .into_iter()
            .filter(|kind| *kind == "flow.gap")
            .count()
    };
    // Keep going until twenty records had to make room for newer ones.
    while store.inner.lock().dropped < 20 {
        begin(&store, "tcp").finish("closed", "relay_finished");
    }
    assert_eq!(gaps(), 1);
    // A record that overflowed its own step budget is still named on its own.
    let flow = begin(&store, "tcp");
    for _ in 0..MAX_STEPS + 1 {
        flow.step(Some(1), dial_mode());
    }
    assert_eq!(gaps(), 2);
}

#[test]
fn a_userspace_evaluation_is_recomputed_evidence_on_the_wire() {
    let store = store();
    let flow = begin(&store, "tcp");
    flow.routed(
        "group",
        Some("gen:0:rule:0"),
        Some("dip(<redacted>)"),
        "evaluation",
    );
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["rule_id"], "gen:0:rule:0");
    assert_eq!(detail["rule_source"], "recomputed");
    flow.routed("group", None, None, "forced");
    assert_eq!(
        store.get(flow.id(), &request_id()).unwrap()["rule_source"],
        "unknown"
    );
}

#[test]
fn retention_distinguishes_expired_unknown_and_active_records() {
    let store = store();
    let terminal = begin(&store, "tcp");
    terminal.finish("failed", "dial_failed");
    let active = begin(&store, "udp");
    let future = Instant::now() + TERMINAL_TTL;
    store.prune(&mut store.inner.lock(), future);
    error_code(
        store.get(terminal.id(), &request_id()).unwrap_err(),
        StatusCode::GONE,
        "flow_expired",
    );
    error_code(
        store.get("not-a-recorded-id", &request_id()).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    );
    assert_eq!(
        store.get(active.id(), &request_id()).unwrap()["state"],
        "observed"
    );
    store.prune(&mut store.inner.lock(), future + TERMINAL_TTL);
    error_code(
        store.get(terminal.id(), &request_id()).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    );
}

#[test]
fn trace_bounds_keep_terminal_state_and_explicit_loss_without_private_errors() {
    let store = store();
    let flow = begin(&store, "tcp");
    let mut unsafe_data = dial_mode();
    if let StepData::DialMode { domain, .. } = &mut unsafe_data {
        *domain = Some("https://operator:credential@example.test".into());
    }
    flow.step(Some(1), unsafe_data);
    for _ in 0..MAX_STEPS + 10 {
        flow.step(Some(1), dial_mode());
    }
    flow.finish("failed", "dial_failed");
    let detail = store.get(flow.id(), &request_id()).unwrap();
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
    let flow = begin(&store, "udp");
    flow.step(
        None,
        StepData::Connection {
            state: "dialing",
            reason: "transport_failed",
            milestone: "unknown",
            attempt_id: Some("https://operator:credential@example.test/private".into()),
            reply_received: None,
            error: Some(FlowError::UdpPrepareFailed),
            selections: Vec::new(),
            lookup_id: None,
            server_addr: None,
        },
    );
    flow.finish("failed", "transport_failed");
    let detail = store.get(flow.id(), &request_id()).unwrap();
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
    let flow = store.begin(
        "udp",
        "[::1]:31000".parse().unwrap(),
        "[2001:db8::1]:443".parse().unwrap(),
    );
    flow.update_input(None, None, Some("client"), Some(42), None, Some(0), Some(0));
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 1);
    assert_eq!(detail["input"]["pid"], 42);
    flow.update_input(
        Some("secret.example.test"),
        Some("quic_sni"),
        Some("client"),
        Some(42),
        None,
        Some(0),
        Some(0),
    );
    flow.step(
        None,
        StepData::Connection {
            state: "dialing",
            reason: "transport_failed",
            milestone: "unknown",
            attempt_id: Some("attempt-1".into()),
            reply_received: None,
            error: Some(FlowError::UdpPrepareFailed),
            selections: Vec::new(),
            lookup_id: None,
            server_addr: None,
        },
    );
    let detail = store.get(flow.id(), &request_id()).unwrap();
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
    let flow = begin(&store, "tcp");
    for status in ["started", "succeeded"] {
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
                    routing_source: "evaluation",
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
                    resolution_location: "original_ip",
                },
            },
        );
    }
    let detail = store.get(flow.id(), &request_id()).unwrap();
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
    }
    assert_eq!(detail["trace"]["missing"], json!(["not_instrumented"]));
}

#[test]
fn recorder_and_snapshots_share_the_byte_budget_and_tombstones_are_bounded() {
    let store = store();
    let original = begin(&store, "tcp");
    let original_id = original.id().to_owned();
    for _ in 0..MAX_RECORDS * 2 {
        let flow = begin(&store, "tcp");
        flow.step(Some(1), dial_mode());
        flow.finish("closed", "relay_finished");
    }
    let inner = store.inner.lock();
    assert!(inner.bytes() <= MAX_BYTES);
    assert!(inner.records.len() <= MAX_RECORDS);
    assert!(inner.tombstones.len() <= MAX_RECORDS);
    assert!(inner.dropped > 0);
    assert!(
        inner
            .records
            .iter()
            .all(|record| record.id() != original_id)
    );
    drop(inner);
    // The ring at its own limit still leaves the listing its reserved share:
    // a walk over every record starts, and the whole store stays in budget.
    let page = store
        .page(filters("all", "all", true, 1), None, &request_id())
        .unwrap();
    assert!(page["next_cursor"].is_string());
    let inner = store.inner.lock();
    assert!(inner.snapshot_bytes > 0);
    assert!(inner.bytes() <= MAX_BYTES);
    drop(inner);
    // A result that fits in one page keeps nothing.
    let before = store.inner.lock().snapshot_bytes;
    store
        .page(
            filters("all", "all", true, MAX_RECORDS),
            None,
            &request_id(),
        )
        .unwrap();
    assert_eq!(store.inner.lock().snapshot_bytes, before);
}

#[test]
fn step_capacity_not_only_string_length_counts_toward_retention() {
    let store = store();
    let flow = begin(&store, "tcp");
    let mut evaluation_id = String::with_capacity(MAX_STEP_BYTES + 1);
    evaluation_id.push_str("evaluation-1");
    flow.step(
        None,
        StepData::Reroute {
            performed: false,
            reason: "not_required",
            from_evaluation_id: Some(evaluation_id),
            to_evaluation_id: None,
        },
    );
    flow.finish("closed", "relay_finished");
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 2);
    assert_eq!(detail["trace"]["missing"], json!(["buffer_overflow"]));
    assert_eq!(detail["state"], "closed");
}

#[test]
fn room_making_prunes_expired_records_before_evicting_live_ones() {
    let store = store();
    store.set_limits(2, 0);
    let live = begin(&store, "tcp");
    begin(&store, "tcp").finish("closed", "relay_finished");
    let newcomer = begin(&store, "tcp");
    assert!(store.get(live.id(), &request_id()).is_ok());
    assert!(store.get(newcomer.id(), &request_id()).is_ok());
    assert_eq!(store.inner.lock().records.len(), 2);
}

#[test]
fn detached_begin_is_empty_without_locking_or_allocating_a_record() {
    let owner = super::super::observation::NativeObservation::new(&honk_config::Config::default());
    assert!(!owner.flows.recording.load(Ordering::Acquire));
    let inner = owner.flows.inner.lock();
    let guard = begin(&owner.flows, "tcp");
    assert!(guard.id().is_empty());
    assert_eq!(guard.id.capacity(), 0);
    assert!(guard.store.upgrade().is_none());
    assert!(inner.records.is_empty());
    assert_eq!(inner.records.capacity(), 0);
    assert_eq!(inner.record_bytes, 0);
}

#[test]
fn captured_url_rule_values_survive_summary_updates_and_new_router_generations() {
    use crate::native_api::routing::{RuleCondition, RuleEvaluation};
    let store = store();
    let flow = begin(&store, "tcp");
    let expression = r#"pname("/usr/bin/user@host") && domain(regex: "https://example.test/path")"#;
    let id = "instance:7:rule:0";
    flow.step(
        Some(7),
        StepData::Route {
            evaluation_id: "evaluation-7".into(),
            chain: "traffic",
            plane: "userspace",
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
        "evaluation",
    );
    let before = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(before["rule_expression"], expression);
    let later = begin(&store, "tcp");
    later.routed(
        "new",
        Some("instance:8:rule:0"),
        Some("pname(\"new\")"),
        "evaluation",
    );
    assert_eq!(store.get(flow.id(), &request_id()).unwrap(), before);
    assert_eq!(
        before["trace"]["steps"][1]["generation_id"],
        format!("{}:7", store.instance_id)
    );
    assert_eq!(before["trace"]["missing"], json!([]));
}

#[test]
fn oversized_utf8_display_is_explicit_capture_loss() {
    let store = store();
    let flow = begin(&store, "tcp");
    let oversized = "界".repeat(MAX_TEXT / 3 + 1);
    let mut data = dial_mode();
    if let StepData::DialMode { domain, .. } = &mut data {
        *domain = Some(oversized.clone());
    }
    flow.step(Some(1), data);
    flow.finish("closed", "relay_finished");
    let detail = store.get(flow.id(), &request_id()).unwrap();
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
    let flow = begin(&store, "tcp");
    let expression = "pname(unavailable without matcher)";
    flow.routed(
        "direct",
        Some("instance:1:rule:0"),
        Some(expression),
        "evaluation",
    );
    assert_eq!(
        store.get(flow.id(), &request_id()).unwrap()["rule_expression"],
        expression
    );
}
