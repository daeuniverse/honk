use super::*;
use futures::{FutureExt, StreamExt};

fn hub() -> Arc<EventHub> {
    Arc::new(EventHub::new("instance-a".into()))
}

fn all() -> Filter {
    Filter::new(63, None)
}

fn request_id() -> RequestId {
    RequestId("test-request".into())
}

fn subscribe(hub: &Arc<EventHub>, filter: Filter, cursor: Option<&str>) -> Subscription {
    hub.subscribe(filter, cursor, &request_id()).unwrap()
}

fn publish_flow(hub: &EventHub, id: &str, revision: u64) {
    hub.flow_updated(id, revision);
}

async fn next(stream: &mut Subscription) -> String {
    String::from_utf8(stream.next().await.unwrap().unwrap().to_vec()).unwrap()
}

fn cursor(frame: &str) -> &str {
    frame
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .unwrap()
}

fn data(frame: &str) -> Value {
    serde_json::from_str(
        frame
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap()
}

fn assert_expired(hub: &Arc<EventHub>, filter: Filter, cursor: &str) {
    let response = match hub.subscribe(filter, Some(cursor), &request_id()) {
        Ok(_) => panic!("expired cursor opened a stream"),
        Err(error) => error.into_response(),
    };
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn ready_precedes_replay_and_live_on_fresh_and_resumed_streams() {
    let hub = hub();
    let filter = Filter::new(1 << 2, Some("flow-a".into()));
    let mut fresh = subscribe(&hub, filter.clone(), None);
    publish_flow(&hub, "flow-a", 1);
    let ready = next(&mut fresh).await;
    assert!(ready.starts_with("event: stream.ready\n"));
    let original = next(&mut fresh).await;
    assert_eq!(data(&original)["revision"], 1);
    publish_flow(&hub, "flow-b", 1);
    publish_flow(&hub, "flow-a", 2);
    drop(fresh);

    let mut resumed = subscribe(&hub, filter.clone(), Some(cursor(&ready)));
    publish_flow(&hub, "flow-a", 3);
    let resumed_ready = next(&mut resumed).await;
    assert!(resumed_ready.starts_with("event: stream.ready\n"));
    assert_eq!(cursor(&resumed_ready), cursor(&ready));
    let replay_one = next(&mut resumed).await;
    assert_eq!(replay_one, original);
    assert_eq!(data(&replay_one)["revision"], 1);
    assert_eq!(data(&next(&mut resumed).await)["revision"], 2);
    assert_eq!(data(&next(&mut resumed).await)["revision"], 3);
    drop(resumed);

    // Disconnecting right after ready must not skip the pending replay.
    let mut after_ready = subscribe(&hub, filter, Some(cursor(&resumed_ready)));
    assert!(
        next(&mut after_ready)
            .await
            .starts_with("event: stream.ready\n")
    );
    for revision in 1..=3 {
        assert_eq!(data(&next(&mut after_ready).await)["revision"], revision);
    }
}

#[tokio::test]
async fn live_flow_updates_coalesce_at_the_tail_without_rewriting_replay() {
    let hub = hub();
    let mut live = subscribe(&hub, all(), None);
    let ready = next(&mut live).await;
    publish_flow(&hub, "flow-a", 1);
    publish_flow(&hub, "flow-b", 1);
    hub.publish(
        "flow.gap",
        json!({"resource_id":"flow-a","reason":"buffer_overflow","dropped_records":"1"}),
        Some("flow-a"),
    );
    hub.publish("runtime.updated", json!({}), None);
    publish_flow(&hub, "flow-a", 2);

    assert_eq!(data(&next(&mut live).await)["resource_id"], "flow-b");
    assert!(next(&mut live).await.starts_with("event: flow.gap\n"));
    let runtime = next(&mut live).await;
    assert!(runtime.starts_with("event: runtime.updated\n"));
    let latest = next(&mut live).await;
    assert_eq!(data(&latest)["revision"], 2);
    assert!(live.next().now_or_never().is_none());
    drop(live);

    let mut resumed = subscribe(&hub, all(), Some(cursor(&ready)));
    publish_flow(&hub, "flow-a", 3);
    publish_flow(&hub, "flow-a", 4);
    assert!(
        next(&mut resumed)
            .await
            .starts_with("event: stream.ready\n")
    );
    assert_eq!(data(&next(&mut resumed).await)["revision"], 1);
    assert_eq!(data(&next(&mut resumed).await)["resource_id"], "flow-b");
    assert!(next(&mut resumed).await.starts_with("event: flow.gap\n"));
    assert_eq!(next(&mut resumed).await, runtime);
    assert_eq!(next(&mut resumed).await, latest);
    let last = next(&mut resumed).await;
    assert_eq!(data(&last)["revision"], 4);
    assert!(resumed.next().now_or_never().is_none());
    drop(resumed);

    publish_flow(&hub, "flow-a", 5);
    let mut replay = subscribe(&hub, all(), Some(cursor(&last)));
    assert!(next(&mut replay).await.starts_with("event: stream.ready\n"));
    assert_eq!(data(&next(&mut replay).await)["revision"], 5);
}

#[tokio::test]
async fn queued_flow_replacement_preserves_capacity_for_latest_revision() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    for index in 0..CLIENT_QUEUE {
        publish_flow(&hub, &format!("flow-{index}"), 1);
    }
    for revision in 2..=100 {
        publish_flow(&hub, "flow-0", revision);
    }
    for index in 1..CLIENT_QUEUE {
        assert_eq!(
            data(&next(&mut stream).await)["resource_id"],
            format!("flow-{index}")
        );
    }
    assert_eq!(data(&next(&mut stream).await)["revision"], 100);
    assert!(stream.next().now_or_never().is_none());
}

#[tokio::test]
async fn cursors_reject_changed_filters_instance_and_forgery() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    let ready = next(&mut stream).await;
    let mut same = subscribe(&hub, all(), None);
    let same_ready = next(&mut same).await;
    assert_ne!(cursor(&ready), cursor(&same_ready));
    let other_filter = Filter::new(1 << 2, Some("flow-a".into()));
    let mut other = subscribe(&hub, other_filter.clone(), None);
    let other_ready = next(&mut other).await;
    publish_flow(&hub, "flow-a", 1);
    let original = next(&mut stream).await;
    assert_eq!(next(&mut same).await, original);
    let different = next(&mut other).await;
    assert_eq!(data(&different), data(&original));
    assert_ne!(cursor(&different), cursor(&original));
    let saved = cursor(&original);
    assert_expired(&hub, Filter::new(1 << 2, None), saved);
    assert_expired(&hub, Filter::new(63, Some("flow-a".into())), saved);
    assert_expired(&hub, other_filter.clone(), saved);
    assert_expired(&hub, all(), cursor(&different));
    assert_expired(&Arc::new(EventHub::new("instance-b".into())), all(), saved);
    assert_expired(&Arc::new(EventHub::new("instance-a".into())), all(), saved);
    assert_expired(&hub, all(), "unknown");
    let mut tampered = URL_SAFE_NO_PAD.decode(saved).unwrap();
    tampered[0] ^= 0x80;
    assert_expired(&hub, all(), &URL_SAFE_NO_PAD.encode(tampered));
    let mut replay = subscribe(&hub, all(), Some(cursor(&ready)));
    next(&mut replay).await;
    assert_eq!(next(&mut replay).await, original);
    let mut different_replay = subscribe(&hub, other_filter, Some(cursor(&other_ready)));
    next(&mut different_replay).await;
    assert_eq!(next(&mut different_replay).await, different);
    publish_flow(&hub, "flow-a", 2);
    assert_eq!(data(&next(&mut different_replay).await)["revision"], 2);
}

#[tokio::test(start_paused = true)]
async fn time_and_count_pressure_expire_before_stream_creation() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    let ready = next(&mut stream).await;
    drop(stream);
    tokio::time::advance(RETENTION).await;
    assert_expired(&hub, all(), cursor(&ready));

    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    publish_flow(&hub, "flow-a", 1);
    let first = next(&mut stream).await;
    drop(stream);
    for revision in 2..=MAX_EVENTS as u64 + 1 {
        publish_flow(&hub, "flow-a", revision);
    }
    assert_expired(&hub, all(), cursor(&first));
}

#[tokio::test(start_paused = true)]
async fn fresh_checkpoint_after_history_expires_resumes_replay_and_live() {
    for kind in [StreamKind::Events, StreamKind::Logs] {
        let hub = Arc::new(EventHub::with_kind("instance-a".into(), kind));
        let filter = match kind {
            StreamKind::Events => all(),
            StreamKind::Logs => Filter::logs(5, None),
        };
        let publish = |revision| match kind {
            StreamKind::Events => publish_flow(&hub, "flow-a", revision),
            StreamKind::Logs => hub.publish_log(
                3,
                "honk_core",
                Bytes::from(serde_json::to_vec(&json!({"fields": {"nodes": revision}})).unwrap()),
                hub.capture_epoch(),
            ),
        };
        let revision = |frame: &str| match kind {
            StreamKind::Events => data(frame)["revision"].as_u64().unwrap(),
            StreamKind::Logs => data(frame)["fields"]["nodes"].as_u64().unwrap(),
        };
        let mut original = subscribe(&hub, filter.clone(), None);
        let old_ready = next(&mut original).await;
        publish(1);
        let old_record = next(&mut original).await;
        drop(original);
        tokio::time::advance(RETENTION).await;
        assert_expired(&hub, filter.clone(), cursor(&old_ready));
        assert_expired(&hub, filter.clone(), cursor(&old_record));

        let mut fresh = subscribe(&hub, filter.clone(), None);
        let checkpoint = next(&mut fresh).await;
        drop(fresh);
        let mut immediate = subscribe(&hub, filter.clone(), Some(cursor(&checkpoint)));
        let ready = next(&mut immediate).await;
        assert!(ready.starts_with("event: stream.ready\n"));
        assert_eq!(cursor(&ready), cursor(&checkpoint));
        publish(2);
        assert_eq!(revision(&next(&mut immediate).await), 2);
        drop(immediate);

        publish(3);
        let mut replay = subscribe(&hub, filter.clone(), Some(cursor(&checkpoint)));
        assert_eq!(cursor(&next(&mut replay).await), cursor(&checkpoint));
        assert_eq!(revision(&next(&mut replay).await), 2);
        let last_replayed = next(&mut replay).await;
        assert_eq!(revision(&last_replayed), 3);
        publish(4);
        assert_eq!(revision(&next(&mut replay).await), 4);
        drop(replay);

        // A checkpoint cannot skip newer records that were subsequently evicted.
        hub.set_limit(1);
        assert_expired(&hub, filter.clone(), cursor(&checkpoint));
        assert_expired(&hub, filter, cursor(&last_replayed));
    }
}

#[tokio::test]
async fn queue_overflow_discards_buffered_frames_and_wakes_receiver() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    assert!(stream.next().now_or_never().is_none());
    for index in 0..=CLIENT_QUEUE {
        publish_flow(&hub, &format!("flow-{index}"), 1);
    }
    assert_eq!(
        stream.next().await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(stream.next().await.is_none());

    let mut before_ready = subscribe(&hub, all(), None);
    for index in 0..=CLIENT_QUEUE {
        publish_flow(&hub, &format!("flow-{index}"), 1);
    }
    assert!(before_ready.next().await.unwrap().is_err());
}

#[tokio::test]
async fn body_drop_releases_client_capacity_even_before_polling() {
    let hub = hub();
    let mut bodies: Vec<_> = (0..MAX_CLIENTS)
        .map(|_| Body::from_stream(subscribe(&hub, all(), None)))
        .collect();
    let error = hub.subscribe(all(), None, &request_id()).err().unwrap();
    assert_eq!(
        error.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    bodies.pop();
    let replacement = Body::from_stream(subscribe(&hub, all(), None));
    for index in 0..=CLIENT_QUEUE {
        publish_flow(&hub, &format!("flow-{index}"), 1);
    }
    assert_eq!(
        hub.subscribe(all(), None, &request_id())
            .err()
            .unwrap()
            .into_response()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE,
    );
    drop(replacement);
    let mut fresh = subscribe(&hub, all(), None);
    assert!(next(&mut fresh).await.starts_with("event: stream.ready\n"));
}

#[tokio::test]
async fn replay_eviction_terminates_instead_of_skipping_to_ready() {
    let hub = hub();
    let filter = Filter::new(1 << 2, None);
    let mut fresh = subscribe(&hub, filter.clone(), None);
    let ready = next(&mut fresh).await;
    drop(fresh);
    publish_flow(&hub, "flow-a", 1);
    let mut resumed = subscribe(&hub, filter, Some(cursor(&ready)));
    for _ in 0..MAX_EVENTS {
        hub.publish("runtime.updated", json!({}), None);
    }
    assert!(resumed.next().await.unwrap().is_err());
    assert!(resumed.next().await.is_none());
}

#[tokio::test]
async fn ready_churn_does_not_evict_event_history() {
    let hub = hub();
    let mut first = subscribe(&hub, all(), None);
    next(&mut first).await;
    publish_flow(&hub, "flow-a", 1);
    let event = next(&mut first).await;
    drop(first);
    for _ in 0..MAX_EVENTS + 1 {
        let mut stream = subscribe(&hub, all(), None);
        assert!(next(&mut stream).await.starts_with("event: stream.ready\n"));
    }
    publish_flow(&hub, "flow-a", 2);
    let mut resumed = subscribe(&hub, all(), Some(cursor(&event)));
    assert!(
        next(&mut resumed)
            .await
            .starts_with("event: stream.ready\n")
    );
    assert_eq!(data(&next(&mut resumed).await)["revision"], 2);
}

#[tokio::test(start_paused = true)]
async fn heartbeat_has_no_cursor_and_shutdown_ends_pending_clients() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    tokio::time::advance(HEARTBEAT - Duration::from_secs(1)).await;
    assert!(stream.next().now_or_never().is_none());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(next(&mut stream).await, ": heartbeat\n\n");
    assert!(stream.next().now_or_never().is_none());
    hub.shutdown();
    assert!(stream.next().await.unwrap().is_err());
    assert_eq!(
        hub.subscribe(all(), None, &request_id())
            .err()
            .unwrap()
            .into_response()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE,
    );
}

#[tokio::test]
async fn payloads_enforce_identifier_and_integer_contracts() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    let ready = next(&mut stream).await;
    publish_flow(&hub, "flow-a", MAX_SAFE_UINT);
    let event = data(&next(&mut stream).await);
    assert_eq!(event["revision"], MAX_SAFE_UINT);
    assert_eq!(event["href"], "/api/v1/flows/flow-a");
    hub.publish("flow.gap", json!({
        "resource_id": null, "reason": "buffer_overflow", "dropped_records": u64::MAX.to_string(),
    }), None);
    assert_eq!(
        data(&next(&mut stream).await)["dropped_records"],
        u64::MAX.to_string()
    );
    publish_flow(&hub, "flow-a", MAX_SAFE_UINT + 1);
    assert!(stream.next().await.unwrap().is_err());
    assert_expired(&hub, all(), cursor(&ready));

    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    hub.publish("flow.gap", json!({
        "resource_id": null, "reason": "buffer_overflow", "dropped_records": "18446744073709551616",
    }), None);
    assert!(stream.next().await.unwrap().is_err());

    for (flow_id, revision) in [
        ("", 1),
        ("https://user:password@private.invalid", 1),
        ("flow-a", 0),
    ] {
        let mut stream = subscribe(&hub, all(), None);
        let ready = next(&mut stream).await;
        publish_flow(&hub, flow_id, revision);
        assert!(stream.next().await.unwrap().is_err());
        assert_expired(&hub, all(), cursor(&ready));
    }
}

#[tokio::test]
async fn flow_filter_keeps_global_events_but_excludes_other_flows() {
    let hub = hub();
    let filter = Filter::new(63, Some("flow-a".into()));
    let mut stream = subscribe(&hub, filter.clone(), None);
    let ready = next(&mut stream).await;
    publish_flow(&hub, "flow-b", 1);
    hub.publish("runtime.updated", json!({}), None);
    assert!(
        next(&mut stream)
            .await
            .starts_with("event: runtime.updated\n")
    );
    assert!(stream.next().now_or_never().is_none());
    hub.publish(
        "flow.gap",
        json!({"resource_id":"flow-b","reason":"buffer_overflow","dropped_records":"1"}),
        Some("flow-b"),
    );
    hub.publish(
        "flow.gap",
        json!({"resource_id":null,"reason":"buffer_overflow","dropped_records":"2"}),
        None,
    );
    let live = tokio::time::timeout(Duration::from_secs(1), next(&mut stream))
        .await
        .unwrap();
    assert_eq!(data(&live)["dropped_records"], "2");
    let mut resumed = subscribe(&hub, filter, Some(cursor(&ready)));
    assert!(
        next(&mut resumed)
            .await
            .starts_with("event: stream.ready\n")
    );
    assert!(
        next(&mut resumed)
            .await
            .starts_with("event: runtime.updated\n")
    );
    assert_eq!(cursor(&next(&mut resumed).await), cursor(&live));
}

#[test]
fn request_validation_rejects_ambiguous_filters_headers_and_accept() {
    for uri in [
        "/api/v1/events?unknown=1",
        "/api/v1/events?kinds=flow.updated&kinds=flow.gap",
        "/api/v1/events?kinds=flow.updated,flow.updated",
        "/api/v1/events?kinds=flow.updated,unknown",
        "/api/v1/events?kinds=",
        "/api/v1/events?flow_id=",
    ] {
        let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        assert_eq!(
            request_options(&request, &request_id())
                .err()
                .unwrap()
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for accept in [
        "application/json",
        "text/event-stream;q=0, */*;q=1",
        "invalid",
        "text/event-stream;q=NaN",
        "text/event-stream;q=1e0",
        "text/event-stream;q=0.0001",
        "text/event-stream;q=1.001",
        "text/event-stream;q=1;q=0",
        "te xt/event-stream",
    ] {
        let request = Request::builder()
            .header(header::ACCEPT, accept)
            .body(Body::empty())
            .unwrap();
        assert!(request_options(&request, &request_id()).is_err());
    }
    for accept in [
        "text/event-stream",
        "*/*",
        "application/json, text/event-stream;q=0.5",
        "text/event-stream;charset=utf-8",
        "text/event-stream;charset=\"utf-8\";q=1.000",
    ] {
        let request = Request::builder()
            .header(header::ACCEPT, accept)
            .body(Body::empty())
            .unwrap();
        assert!(request_options(&request, &request_id()).is_ok());
    }
    let request = Request::builder()
        .header("last-event-id", "first")
        .header("last-event-id", "second")
        .body(Body::empty())
        .unwrap();
    assert!(request_options(&request, &request_id()).is_err());
    let first = Request::builder()
        .uri("/api/v1/events?kinds=flow.updated,flow.gap")
        .body(Body::empty())
        .unwrap();
    let second = Request::builder()
        .uri("/api/v1/events?kinds=flow.gap,flow.updated")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        request_options(&first, &request_id()).unwrap().0.binding,
        request_options(&second, &request_id()).unwrap().0.binding
    );
}

#[tokio::test]
async fn notification_live_queue_survives_unrelated_history_eviction() {
    let hub = hub();
    let mut stream = subscribe(&hub, Filter::new(1 << 2, None), None);
    next(&mut stream).await;
    publish_flow(&hub, "flow-a", 1);
    for _ in 0..MAX_EVENTS {
        hub.publish("runtime.updated", json!({}), None);
    }
    assert_eq!(data(&next(&mut stream).await)["revision"], 1);
}

#[tokio::test]
async fn log_stream_binding_and_rejected_payload_invalidate_cursors() {
    let events = hub();
    let logs = Arc::new(EventHub::logs("instance-a".into()));
    let mut event_stream = subscribe(&events, all(), None);
    let event_ready = next(&mut event_stream).await;
    let filter = Filter::logs(5, None);
    assert_expired(&logs, filter.clone(), cursor(&event_ready));
    let mut stream = subscribe(&logs, filter.clone(), None);
    let ready = next(&mut stream).await;
    assert_expired(&events, all(), cursor(&ready));
    assert_expired(&logs, all(), cursor(&ready));
    let mut queued = subscribe(&logs, filter.clone(), None);
    next(&mut queued).await;
    logs.publish_log(
        3,
        "honk_core",
        Bytes::from_static(b"{\"fields\":{\"nodes\":1}}"),
        logs.capture_epoch(),
    );
    let recorded = next(&mut stream).await;
    logs.publish_log(
        3,
        "honk_core",
        Bytes::from(vec![b'x'; MAX_PAYLOAD_BYTES + 1]),
        logs.capture_epoch(),
    );
    assert!(stream.next().await.unwrap().is_err());
    assert!(queued.next().await.unwrap().is_err());
    assert_expired(&logs, filter.clone(), cursor(&ready));
    assert_expired(&logs, filter.clone(), cursor(&recorded));
    let mut fresh = subscribe(&logs, filter.clone(), None);
    next(&mut fresh).await;
    logs.publish_log(
        3,
        "honk_core",
        Bytes::from_static(b"{\"fields\":{\"nodes\":2}}"),
        logs.capture_epoch(),
    );
    let new_record = next(&mut fresh).await;
    assert_eq!(data(&new_record)["fields"]["nodes"], 2);
    let mut resumed = subscribe(&logs, filter, Some(cursor(&new_record)));
    assert_eq!(cursor(&next(&mut resumed).await), cursor(&new_record));
}

#[tokio::test]
async fn log_byte_pressure_closes_queued_consumers_and_expires_replay() {
    let hub = Arc::new(EventHub::logs("instance-a".into()));
    let filter = Filter::logs(5, None);
    let mut live = subscribe(&hub, filter.clone(), None);
    let baseline = next(&mut live).await;
    let mut different = subscribe(&hub, Filter::logs(4, None), None);
    next(&mut different).await;
    let mut slow = subscribe(&hub, Filter::logs(5, Some("honk_old".into())), None);
    next(&mut slow).await;
    let publish = |target, nodes| {
        let mut payload = serde_json::to_vec(&json!({"fields": {"nodes": nodes}})).unwrap();
        payload.resize(MAX_PAYLOAD_BYTES, b' ');
        hub.publish_log(3, target, Bytes::from(payload), hub.capture_epoch());
    };
    publish("honk_old", 0);
    let oldest = next(&mut live).await;
    assert_eq!(data(&next(&mut different).await), data(&oldest));
    let mut penultimate = oldest.clone();
    let mut latest = oldest.clone();
    for nodes in 1..=MAX_EVENTS / 2 + 1 {
        publish("honk_new", nodes);
        penultimate = latest;
        latest = next(&mut live).await;
        let other = next(&mut different).await;
        assert_eq!(data(&latest)["fields"]["nodes"], nodes);
        assert_eq!(data(&other), data(&latest));
        assert_ne!(cursor(&other), cursor(&latest));
    }
    assert_expired(&hub, filter.clone(), cursor(&baseline));
    assert_expired(&hub, filter.clone(), cursor(&oldest));
    assert_eq!(
        slow.next().await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(slow.next().await.is_none());
    hub.set_limit(1);
    assert_expired(&hub, filter.clone(), cursor(&penultimate));
    let mut resumed = subscribe(&hub, filter, Some(cursor(&latest)));
    assert_eq!(cursor(&next(&mut resumed).await), cursor(&latest));
    publish("honk_new", 999);
    assert_eq!(data(&next(&mut resumed).await)["fields"]["nodes"], 999);
}

#[tokio::test]
async fn idle_admission_and_old_capture_epochs_preserve_boundaries() {
    let hub = hub();
    let mut old = subscribe(&hub, all(), None);
    let ready = next(&mut old).await;
    let mut consumer = subscribe(&hub, all(), None);
    next(&mut consumer).await;
    hub.publish("runtime.updated", json!({}), None);
    let recorded = next(&mut consumer).await;
    let epoch = hub.capture_epoch();
    hub.set_recording(false);
    assert!(old.next().await.unwrap().is_err());
    assert!(consumer.next().await.unwrap().is_err());
    assert_expired(&hub, all(), cursor(&ready));
    assert_expired(&hub, all(), cursor(&recorded));
    let _idle = subscribe(&hub, all(), None);
    hub.publish("runtime.updated", json!({}), None);
    assert!(hub.buffered_kinds().is_empty());
    hub.set_recording(true);
    let payload = hub.payload("runtime.updated", &json!({}), None);
    hub.publish_record(payload, None, None, epoch);
    assert!(hub.buffered_kinds().is_empty());
    hub.publish("runtime.updated", json!({}), None);
    assert_eq!(hub.buffered_kinds(), vec!["runtime.updated"]);
    let mut fresh = subscribe(&hub, all(), None);
    next(&mut fresh).await;
    hub.publish("runtime.updated", json!({}), None);
    let new_record = next(&mut fresh).await;
    assert_ne!(cursor(&new_record), cursor(&recorded));
    let mut resumed = subscribe(&hub, all(), Some(cursor(&new_record)));
    assert_eq!(cursor(&next(&mut resumed).await), cursor(&new_record));
}

#[tokio::test]
async fn provider_urls_share_links_and_passwords_never_enter_sse_payloads() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    let subscription = honk_config::subscription::Subscription {
        name: "sentinel-provider".into(),
        url: "https://example.test/private-source?token=provider-url-sentinel".into(),
        ..Default::default()
    };
    let config = honk_config::Config {
        subscriptions: vec![subscription.clone()],
        ..Default::default()
    };
    let provider =
        crate::native_api::providers::provider_value(&config, None, subscription.id, None, |_| {
            None
        })
        .unwrap();
    assert_eq!(provider["url_redacted"], subscription.url);
    hub.publish(
        "operation.updated",
        json!({
            "resource_id":"operation-a", "status":"succeeded", "result":provider,
            "link":"socks5://user:password-sentinel@127.0.0.1:1080", "password":"password-sentinel"
        }),
        None,
    );
    let frame = next(&mut stream).await;
    assert_eq!(data(&frame)["status"], "succeeded");
    for withheld in [
        "provider-url-sentinel",
        "private-source",
        "sentinel-provider",
        "socks5://",
        "password-sentinel",
    ] {
        assert!(!frame.contains(withheld));
    }
}
