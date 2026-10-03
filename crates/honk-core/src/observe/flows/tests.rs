use super::record::{FlowError, OutboundAttempt, Selection};
use super::*;
use crate::native_api::events::EventHub;
use honk_config::types::DialMode;

fn store() -> Arc<FlowStore> {
    store_with_hub().0
}

fn store_with_hub() -> (Arc<FlowStore>, Arc<EventHub>) {
    let instance = Uuid::new_v4().to_string();
    let hub = Arc::new(EventHub::new(instance.clone()));
    let store = Arc::new(FlowStore::new(
        instance,
        Arc::clone(&hub) as Arc<dyn Events>,
    ));
    (store, hub)
}

fn begin(store: &Arc<FlowStore>, network: Network) -> FlowGuard {
    try_begin(store, network).expect("recording flow")
}

fn try_begin(store: &Arc<FlowStore>, network: Network) -> Option<FlowGuard> {
    store.begin(
        network,
        "127.0.0.1:31000".parse().unwrap(),
        "127.0.0.2:443".parse().unwrap(),
    )
}

fn filters(network: &str, state: &str, full: bool, limit: usize) -> Filters {
    Filters::new(network.to_owned(), state.to_owned(), None, full, limit)
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
fn tuple_reincarnation_keeps_history_and_exact_connection_identity() {
    let store = store();
    let first = begin(&store, crate::observe::vocab::Network::Tcp);
    first.attach_connection("connection-old");
    first.routed(
        "original-group",
        None,
        None,
        crate::observe::vocab::RoutingSource::Unknown,
    );
    first.selected(vec![
        "original-group-id".to_owned(),
        "original-node-id".to_owned(),
    ]);
    first.step(Some(7), dial_mode());
    first.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    let second = begin(&store, crate::observe::vocab::Network::Tcp);
    second.attach_connection("connection-new");
    second.routed(
        "replacement-group",
        None,
        None,
        crate::observe::vocab::RoutingSource::Unknown,
    );
    second.selected(vec![
        "replacement-group-id".to_owned(),
        "replacement-node-id".to_owned(),
    ]);
    assert_ne!(first.id(), second.id());
    let evidence = store.connection_evidence(first.id()).unwrap();
    assert_eq!(evidence.chain, ["original-group-id", "original-node-id"]);
    let detail = store.get(first.id()).unwrap();
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
    let page = store.page(query, None).unwrap();
    assert_eq!(page["flows"].as_array().unwrap().len(), 1);
    assert_eq!(page["flows"][0]["id"], first.id());
    assert_eq!(page["flows"][0]["input"]["src"], "127.0.0.1:31000");
}

#[test]
fn guards_finalize_once_and_do_not_fabricate_kernel_connection_close() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Udp);
    assert!(flow.first_reply());
    assert!(!flow.first_reply());
    flow.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "idle_after_reply",
    );
    let id = flow.id().to_owned();
    let terminal = store.get(&id).unwrap();
    flow.finish(crate::observe::vocab::ConnectionState::Failed, "late_error");
    flow.routed(
        "late-outbound",
        None,
        None,
        crate::observe::vocab::RoutingSource::Unknown,
    );
    drop(flow);
    assert_eq!(store.get(&id).unwrap(), terminal);
    assert_eq!(
        terminal["trace"]["steps"][1]["data"]["reply_received"],
        true
    );

    let cancelled = begin(&store, crate::observe::vocab::Network::Tcp);
    let id = cancelled.id().to_owned();
    drop(cancelled);
    let detail = store.get(&id).unwrap();
    assert_eq!(detail["state"], "failed");
    assert_eq!(detail["trace"]["steps"][1]["data"]["reason"], "cancelled");

    let handoff = begin(&store, crate::observe::vocab::Network::Udp);
    handoff.finish(
        crate::observe::vocab::ConnectionState::Unknown,
        "kernel_handoff",
    );
    let detail = store.get(handoff.id()).unwrap();
    assert_eq!(detail["state"], "unknown");
    assert!(detail["ended_at"].is_string());
}

#[test]
fn pinned_pages_survive_mutation_and_bind_all_filters() {
    let store = store();
    let old = begin(&store, crate::observe::vocab::Network::Tcp);
    old.transition(
        crate::observe::vocab::ConnectionState::Active,
        "ready",
        crate::observe::vocab::ConnectionMilestone::TransportReady,
        None,
    );
    let ignored = begin(&store, crate::observe::vocab::Network::Udp);
    ignored.transition(
        crate::observe::vocab::ConnectionState::Active,
        "ready",
        crate::observe::vocab::ConnectionMilestone::TransportReady,
        None,
    );
    let recent = begin(&store, crate::observe::vocab::Network::Tcp);
    recent.transition(
        crate::observe::vocab::ConnectionState::Active,
        "ready",
        crate::observe::vocab::ConnectionMilestone::TransportReady,
        None,
    );
    let query = filters("tcp", "active", true, 1);
    let first = store.page(query.clone(), None).unwrap();
    assert_eq!(first["flows"][0]["id"], recent.id());
    let cursor = first["next_cursor"].as_str().unwrap();
    old.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    let newcomer = begin(&store, crate::observe::vocab::Network::Tcp);
    newcomer.transition(
        crate::observe::vocab::ConnectionState::Active,
        "ready",
        crate::observe::vocab::ConnectionMilestone::TransportReady,
        None,
    );
    let second = store.page(query.clone(), Some(cursor)).unwrap();
    assert_eq!(second["observed_at"], first["observed_at"]);
    assert_eq!(second["flows"][0]["id"], old.id());
    assert_eq!(second["flows"][0]["state"], "active");
    assert!(second["next_cursor"].is_null());
    for changed in [
        filters("udp", "active", true, 1),
        filters("tcp", "closed", true, 1),
        filters("tcp", "active", false, 1),
        filters("tcp", "active", true, 2),
    ] {
        assert_eq!(
            store.page(changed, Some(cursor)).unwrap_err(),
            PageRefusal::Mismatch
        );
    }
    let other_instance = super::tests::store();
    assert_eq!(
        other_instance
            .page(query.clone(), Some(cursor))
            .unwrap_err(),
        PageRefusal::Expired
    );
    store.inner.lock().snapshots[0].created = Instant::now() - SNAPSHOT_TTL;
    assert_eq!(
        store.page(query, Some(cursor)).unwrap_err(),
        PageRefusal::Expired
    );
}

#[test]
fn snapshot_capacity_is_explicit_and_recording_disable_releases_every_owner() {
    let store = store();
    store.set_limits(64, 1);
    let first = begin(&store, crate::observe::vocab::Network::Tcp);
    let _second = begin(&store, crate::observe::vocab::Network::Tcp);
    let query = filters("all", "all", true, 1);
    let mut cursor = String::new();
    let mut oldest = String::new();
    for round in 0..MAX_SNAPSHOTS {
        let page = store.page(query.clone(), None).unwrap();
        cursor = page["next_cursor"].as_str().unwrap().to_owned();
        if round == 0 {
            oldest = cursor.clone();
        }
    }
    // A full table makes room by dropping its oldest snapshot; only that
    // reader starts over, the newest cursors stay valid.
    let page = store.page(query.clone(), None).unwrap();
    assert!(page["next_cursor"].is_string());
    assert_eq!(store.inner.lock().snapshots.len(), MAX_SNAPSHOTS);
    assert_eq!(
        store.page(query.clone(), Some(&oldest)).unwrap_err(),
        PageRefusal::Expired
    );
    store.page(query.clone(), Some(&cursor)).unwrap();
    store.set_recording(false);
    assert!(try_begin(&store, crate::observe::vocab::Network::Tcp).is_none());
    first.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "late_finish",
    );
    assert_eq!(
        store.page(query.clone(), Some(&cursor)).unwrap_err(),
        PageRefusal::Expired
    );
    let page = store.page(query, None).unwrap();
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
    first.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "late_finish_after_restart",
    );
    assert!(store.inner.lock().records.is_empty());
    let restarted = begin(&store, crate::observe::vocab::Network::Tcp);
    assert_ne!(restarted.id(), first.id());
    assert!(!restarted.id().is_empty());
}

#[test]
fn aged_out_records_report_one_gap_per_interval_with_the_running_count() {
    let (store, hub) = store_with_hub();
    let gaps = || {
        hub.buffered_kinds()
            .into_iter()
            .filter(|kind| *kind == "flow.gap")
            .count()
    };
    for _ in 0..5 {
        begin(&store, crate::observe::vocab::Network::Tcp).finish(
            crate::observe::vocab::ConnectionState::Closed,
            "relay_finished",
        );
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
    begin(&store, crate::observe::vocab::Network::Tcp).finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    store.prune(&mut store.inner.lock(), later + Duration::from_secs(1));
    assert_eq!((gaps(), store.inner.lock().dropped), (1, 6));
    begin(&store, crate::observe::vocab::Network::Tcp).finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    store.prune(&mut store.inner.lock(), later + EVICTED_GAP_INTERVAL);
    assert_eq!((gaps(), store.inner.lock().dropped), (2, 7));
}

fn count(hub: &EventHub, kind: &str) -> usize {
    hub.buffered_kinds()
        .into_iter()
        .filter(|buffered| *buffered == kind)
        .count()
}

#[test]
fn room_making_eviction_is_reported_once_per_interval() {
    let (store, hub) = store_with_hub();
    // Keep going until twenty records had to make room for newer ones.
    while store.inner.lock().dropped < 20 {
        begin(&store, crate::observe::vocab::Network::Tcp).finish(
            crate::observe::vocab::ConnectionState::Closed,
            "relay_finished",
        );
    }
    assert_eq!(count(&hub, "flow.gap"), 1);
}

#[test]
fn step_overflow_updates_the_record_without_a_gap() {
    let (store, hub) = store_with_hub();
    let flow = begin(&store, crate::observe::vocab::Network::Tcp);
    while store.inner.lock().records[0].steps.len() < MAX_STEPS {
        flow.step(Some(1), dial_mode());
    }
    let updates = count(&hub, "flow.updated");
    let revision = store.inner.lock().records[0].summary.revision;
    flow.step(Some(1), dial_mode());
    let inner = store.inner.lock();
    assert!(inner.records[0].overflow);
    assert_eq!(inner.records[0].summary.revision, revision + 1);
    drop(inner);
    assert_eq!(count(&hub, "flow.updated"), updates + 1);
    assert_eq!(count(&hub, "flow.gap"), 0);
    // Later steps find the record already truncated and publish nothing.
    flow.step(Some(1), dial_mode());
    assert_eq!(count(&hub, "flow.updated"), updates + 1);
    assert_eq!(count(&hub, "flow.gap"), 0);
}

#[test]
fn revision_exhaustion_joins_the_interval_notice() {
    let (store, hub) = store_with_hub();
    for _ in 0..2 {
        let flow = begin(&store, crate::observe::vocab::Network::Tcp);
        store
            .inner
            .lock()
            .records
            .back_mut()
            .unwrap()
            .summary
            .revision = MAX_SAFE_UINT;
        flow.step(Some(1), dial_mode());
    }
    let inner = store.inner.lock();
    assert!(inner.records.is_empty());
    assert_eq!(inner.dropped, 2);
    drop(inner);
    assert_eq!(count(&hub, "flow.gap"), 1);
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
fn retention_distinguishes_expired_unknown_and_active_records() {
    let store = store();
    let terminal = begin(&store, crate::observe::vocab::Network::Tcp);
    terminal.finish(
        crate::observe::vocab::ConnectionState::Failed,
        "dial_failed",
    );
    let active = begin(&store, crate::observe::vocab::Network::Udp);
    let future = Instant::now() + TERMINAL_TTL;
    store.prune(&mut store.inner.lock(), future);
    assert_eq!(store.get(terminal.id()).unwrap_err(), FlowMissing::Expired);
    assert_eq!(
        store.get("not-a-recorded-id").unwrap_err(),
        FlowMissing::NotFound
    );
    assert_eq!(store.get(active.id()).unwrap()["state"], "observed");
    store.prune(&mut store.inner.lock(), future + TERMINAL_TTL);
    assert_eq!(store.get(terminal.id()).unwrap_err(), FlowMissing::NotFound);
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
fn recorder_and_snapshots_share_the_byte_budget_and_tombstones_are_bounded() {
    let store = store();
    let original = begin(&store, crate::observe::vocab::Network::Tcp);
    let original_id = original.id().to_owned();
    for _ in 0..MAX_RECORDS * 2 {
        let flow = begin(&store, crate::observe::vocab::Network::Tcp);
        flow.step(Some(1), dial_mode());
        flow.finish(
            crate::observe::vocab::ConnectionState::Closed,
            "relay_finished",
        );
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
            .any(|record| record.id() == original_id)
    );
    drop(inner);
    // The ring at its own limit still leaves the listing its reserved share:
    // a walk over every record starts, and the whole store stays in budget.
    let page = store.page(filters("all", "all", true, 1), None).unwrap();
    assert!(page["next_cursor"].is_string());
    let inner = store.inner.lock();
    assert!(inner.snapshot_bytes > 0);
    assert!(inner.bytes() <= MAX_BYTES);
    drop(inner);
    // A result that fits in one page keeps nothing.
    let before = store.inner.lock().snapshot_bytes;
    store
        .page(filters("all", "all", true, MAX_RECORDS), None)
        .unwrap();
    assert_eq!(store.inner.lock().snapshot_bytes, before);
}

#[test]
fn step_capacity_not_only_string_length_counts_toward_retention() {
    let store = store();
    let flow = begin(&store, crate::observe::vocab::Network::Tcp);
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
    flow.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    let detail = store.get(flow.id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 2);
    assert_eq!(detail["trace"]["missing"], json!(["buffer_overflow"]));
    assert_eq!(detail["state"], "closed");
}

#[test]
fn room_making_prunes_expired_records_before_evicting_live_ones() {
    let store = store();
    store.set_limits(2, 0);
    let live = begin(&store, crate::observe::vocab::Network::Tcp);
    begin(&store, crate::observe::vocab::Network::Tcp).finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    let newcomer = begin(&store, crate::observe::vocab::Network::Tcp);
    assert!(store.get(live.id()).is_ok());
    assert!(store.get(newcomer.id()).is_ok());
    assert_eq!(store.inner.lock().records.len(), 2);
}

#[test]
fn a_step_survives_pruning_an_expired_record_behind_it() {
    let store = store();
    store.set_limits(64, 0);
    let live = begin(&store, crate::observe::vocab::Network::Tcp);
    begin(&store, crate::observe::vocab::Network::Tcp).finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    store.inner.lock().max_records = 1;
    assert!(store.record_step(live.id(), Some(1), dial_mode()));
    assert_eq!(store.inner.lock().records.len(), 1);
}

#[test]
fn room_making_evicts_ended_records_before_the_oldest_live_one() {
    let store = store();
    store.set_limits(3, 3600);
    let live = begin(&store, crate::observe::vocab::Network::Tcp);
    let ended: Vec<String> = (0..3)
        .map(|_| {
            let flow = begin(&store, crate::observe::vocab::Network::Tcp);
            flow.finish(
                crate::observe::vocab::ConnectionState::Closed,
                "relay_finished",
            );
            flow.id().to_owned()
        })
        .collect();
    let newcomer = begin(&store, crate::observe::vocab::Network::Tcp);
    assert!(store.get(live.id()).is_ok());
    let inner = store.inner.lock();
    let retained: Vec<&str> = inner.records.iter().map(|record| record.id()).collect();
    assert_eq!(retained, [live.id(), ended[2].as_str(), newcomer.id()]);
}

#[test]
fn detached_begin_records_nothing_without_locking() {
    let owner =
        crate::native_api::observation::NativeObservation::new(&honk_config::Config::default());
    assert!(!owner.core.flows.recording.load(Ordering::Acquire));
    let inner = owner.core.flows.inner.lock();
    assert!(try_begin(&owner.core.flows, Network::Tcp).is_none());
    assert!(inner.records.is_empty());
    assert_eq!(inner.records.capacity(), 0);
    assert_eq!(inner.record_bytes, 0);
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
