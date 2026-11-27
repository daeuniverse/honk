use super::*;

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
    assert_eq!(inner.records.overhead(), 0);
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
    while store.inner.lock().records.at(0).steps.len() < MAX_STEPS {
        flow.step(Some(1), dial_mode());
    }
    let updates = count(&hub, "flow.updated");
    let revision = store.inner.lock().records.at(0).summary.revision;
    flow.step(Some(1), dial_mode());
    let inner = store.inner.lock();
    assert!(inner.records.at(0).overflow);
    assert_eq!(inner.records.at(0).summary.revision, revision + 1);
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
            .get_mut(&flow.key)
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
fn retention_distinguishes_expired_unknown_and_active_records() {
    let store = store();
    let terminal = begin(&store, crate::observe::vocab::Network::Tcp);
    terminal.finish(
        crate::observe::vocab::ConnectionState::Failed,
        "dial_failed",
    );
    let active = begin(&store, crate::observe::vocab::Network::Udp);
    store.set_limits(MAX_RECORDS, 1);
    let reduced_deadline = Instant::now() + Duration::from_secs(1);
    store.prune(&mut store.inner.lock(), reduced_deadline);
    assert_eq!(store.get(terminal.id()).unwrap_err(), FlowMissing::Expired);
    assert_eq!(
        store.get("not-a-recorded-id").unwrap_err(),
        FlowMissing::NotFound
    );
    assert_eq!(store.get(active.id()).unwrap()["state"], "observed");

    let extended = begin(&store, crate::observe::vocab::Network::Tcp);
    extended.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    store.set_limits(MAX_RECORDS, TERMINAL_TTL.as_secs());
    store.prune(
        &mut store.inner.lock(),
        Instant::now() + Duration::from_secs(1),
    );
    assert!(store.get(extended.id()).is_ok());
    let extended_deadline = Instant::now() + TERMINAL_TTL;
    store.prune(&mut store.inner.lock(), extended_deadline);
    assert_eq!(store.get(extended.id()).unwrap_err(), FlowMissing::Expired);

    store.prune(&mut store.inner.lock(), extended_deadline + TERMINAL_TTL);
    assert_eq!(store.get(terminal.id()).unwrap_err(), FlowMissing::NotFound);
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

    let display_flow = begin(&store, crate::observe::vocab::Network::Tcp);
    let mut domain = String::with_capacity(MAX_STEP_BYTES + 1);
    domain.push_str("cdn.example.test");
    display_flow.step(
        None,
        StepData::DialMode {
            configured: DialMode::Domain,
            effective_target: "domain",
            domain: Some(domain),
            domain_source: Some(DomainSource::DnsMapping),
            verification: "matched",
            reason: "configured",
        },
    );
    display_flow.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "relay_finished",
    );
    let detail = store.get(display_flow.id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 3);
    assert_eq!(
        detail["trace"]["steps"][1]["data"]["domain"],
        "cdn.example.test"
    );
    assert_eq!(detail["trace"]["missing"], json!([]));
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
    assert!(store.record_step(&live.key, Some(1), dial_mode()));
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
fn index_storage_can_evict_a_live_record_at_the_shared_byte_limit() {
    const N: usize = 256;
    let store = store();
    let flows: Vec<_> = (0..N).map(|_| begin(&store, Network::Tcp)).collect();
    // Leave room for all occupied slots and the order, but only half the
    // UUID index. The old record-only budget would still admit the oldest flow.
    let target = MAX_BYTES
        - SNAPSHOT_BYTES
        - OWNER_BYTES
        - N * (size_of::<Option<Record>>() - size_of::<Record>()
            + size_of::<usize>()
            + size_of::<(Uuid, usize)>() / 2);
    for flow in flows.iter().skip(1) {
        let inner = store.inner.lock();
        if inner.dropped != 0 || inner.record_bytes >= target {
            break;
        }
        let capacity = (target - inner.record_bytes).min(MAX_STEP_BYTES / 2);
        drop(inner);
        let mut evaluation = String::with_capacity(capacity);
        evaluation.push('a');
        flow.step(
            None,
            StepData::Reroute {
                performed: false,
                reason: "not_required",
                from_evaluation_id: Some(evaluation),
                to_evaluation_id: None,
            },
        );
    }
    assert_eq!(store.get(flows[0].id()), Err(FlowMissing::Expired));
    assert!(store.get(flows.last().unwrap().id()).is_ok());
    let page = store.page(filters("all", "all", true, 1), None).unwrap();
    assert!(page["next_cursor"].is_string());
    assert!(store.inner.lock().bytes() <= MAX_BYTES);
}

#[test]
fn reused_middle_slot_preserves_live_ids_page_order_and_accounted_storage() {
    let store = store();
    store.set_limits(3, 3600);
    let first = begin(&store, Network::Tcp);
    let middle = begin(&store, Network::Tcp);
    let last = begin(&store, Network::Tcp);
    middle.finish(ConnectionState::Closed, "relay_finished");
    let fourth = begin(&store, Network::Udp);
    first.finish(ConnectionState::Closed, "relay_finished");
    let fifth = begin(&store, Network::Udp);
    assert_eq!(store.get(middle.id()), Err(FlowMissing::Expired));
    assert!(!store.record_step(&middle.key, Some(1), dial_mode()));
    assert!(store.record_step(&last.key, Some(1), dial_mode()));
    let page = store.page(filters("all", "all", true, 10), None).unwrap();
    let ids: Vec<_> = page["flows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [fifth.id(), fourth.id(), last.id()]);
    let inner = store.inner.lock();
    for r in inner.records.iter() {
        assert_eq!(
            r.step_bytes,
            r.steps.iter().map(Step::heap_bytes).sum::<usize>()
        );
    }
    assert!(inner.records.overhead() > 0);
    assert_eq!(
        inner.bytes(),
        OWNER_BYTES + inner.record_bytes + inner.records.overhead() + inner.snapshot_bytes
    );
    assert!(inner.bytes() <= MAX_BYTES);
    drop(inner);
    store.set_recording(false);
    assert_eq!(store.inner.lock().records.overhead(), 0);
}

#[test]
fn detached_begin_records_nothing_without_locking() {
    let owner =
        crate::native_api::observation::NativeObservation::new(&honk_config::Config::default());
    assert!(!owner.core.flows.recording.load(Ordering::Acquire));
    let inner = owner.core.flows.inner.lock();
    assert!(try_begin(&owner.core.flows, Network::Tcp).is_none());
    assert!(inner.records.is_empty());
    assert_eq!(inner.records.overhead(), 0);
    assert_eq!(inner.record_bytes, 0);
}
