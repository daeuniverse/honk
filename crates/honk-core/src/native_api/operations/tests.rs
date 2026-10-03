use super::*;
use axum::body::{Body, to_bytes};
use futures::{FutureExt, StreamExt};
use tokio::sync::Barrier;

fn store() -> Arc<OperationStore> {
    Arc::new(OperationStore::new(
        "instance-a".into(),
        Arc::new(EventHub::new("instance-a".into())),
    ))
}

fn reserve(store: &Arc<OperationStore>, key: &str) -> Reservation {
    store
        .reserve(
            "owner",
            "POST",
            "/api/v1/operations/reload",
            Some(key),
            b"{}",
            crate::native_api::operations::OperationKind::Reload,
        )
        .unwrap()
}

async fn body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}

async fn assert_error(error: ApiError, status: StatusCode, code: &str) -> Value {
    let response = error.into_response();
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    if status == StatusCode::SERVICE_UNAVAILABLE {
        assert_eq!(response.headers()["retry-after"], "1");
    }
    let value = body(response).await;
    assert_eq!(value["error"]["code"], code);
    value
}

#[tokio::test]
async fn concurrent_retries_share_pending_admission_and_the_original_operation() {
    let store = store();
    let barrier = Arc::new(Barrier::new(9));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            barrier.wait().await;
            reserve(&store, "same-key")
        });
    }
    barrier.wait().await;
    let mut reservations = Vec::new();
    while let Some(reservation) = tasks.join_next().await {
        reservations.push(reservation.unwrap());
    }
    assert_eq!(
        reservations
            .iter()
            .filter(|reservation| reservation.fresh)
            .count(),
        1
    );
    let id = reservations[0].id.clone();
    for reservation in &reservations {
        assert_eq!(reservation.id, id);
        assert!(reservation.admission().now_or_never().is_none());
    }
    assert_error(
        store.get(&id).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    assert!(store.accept(&id));
    assert!(!store.accept(&id));
    for reservation in reservations {
        let accepted = reservation.admission().await.unwrap();
        assert_eq!(accepted.operation_id, id);
        let response = accepted.into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response.headers()["location"],
            format!("/api/v1/operations/{id}")
        );
        assert_eq!(response.headers()["retry-after"], "1");
        assert_eq!(body(response).await["status"], "queued");
    }
    let queued = store.get(&id).unwrap();
    assert_eq!(queued.headers()["retry-after"], "1");
    let queued = body(queued).await;
    assert_eq!(queued["status"], "queued");
    for field in ["started_at", "finished_at", "result", "error"] {
        assert_eq!(queued.get(field), Some(&Value::Null));
    }
    assert!(store.running(&id));
    assert!(!store.running(&id));
    assert!(store.succeed(
        &id,
        OperationResult::Reload {
            active_generation_id: Some("instance-a:7".into()),
            datapath_generation_id: None
        }
    ));
    assert!(!store.fail(&id, "reload_failed", "Reload failed.", None));
    let replay = reserve(&store, "same-key");
    assert!(!replay.fresh);
    assert_eq!(replay.admission().await.unwrap().operation_id, id);
    let terminal = store.get(&id).unwrap();
    assert!(!terminal.headers().contains_key("retry-after"));
    let terminal = body(terminal).await;
    assert_eq!(terminal["status"], "succeeded");
    assert_eq!(
        terminal["result"],
        json!({
            "active_generation_id": "instance-a:7", "datapath_generation_id": null,
        })
    );
    assert_eq!(terminal["error"], Value::Null);
    for field in ["created_at", "started_at", "finished_at"] {
        chrono::DateTime::parse_from_rfc3339(terminal[field].as_str().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn keys_are_scoped_and_different_bodies_conflict_before_capacity_checks() {
    let store = store();
    let original = reserve(&store, "key");
    let conflict = store
        .reserve(
            "owner",
            "POST",
            "/api/v1/operations/reload",
            Some("key"),
            b"{ }",
            crate::native_api::operations::OperationKind::Reload,
        )
        .err()
        .unwrap();
    assert_error(conflict, StatusCode::CONFLICT, "idempotency_conflict").await;
    let mut owners = vec![original];
    for (principal, method, path, key) in [
        ("other", "POST", "/api/v1/operations/reload", Some("key")),
        ("owner", "PUT", "/api/v1/operations/reload", Some("key")),
        ("owner", "POST", "/api/v1/config/sources/main", Some("key")),
        (
            "owner",
            "POST",
            "/api/v1/operations/reload",
            Some("other-key"),
        ),
        ("owner", "POST", "/api/v1/operations/reload", None),
        ("owner", "POST", "/api/v1/operations/reload", None),
    ] {
        let reservation = store
            .reserve(
                principal,
                method,
                path,
                key,
                b"{}",
                crate::native_api::operations::OperationKind::Reload,
            )
            .unwrap();
        assert!(reservation.fresh);
        assert!(owners.iter().all(|old| old.id != reservation.id));
        owners.push(reservation);
    }
    let invalid = store
        .reserve(
            "owner",
            "POST",
            "/reload",
            Some(""),
            b"{}",
            crate::native_api::operations::OperationKind::Reload,
        )
        .err()
        .unwrap();
    assert_error(invalid, StatusCode::BAD_REQUEST, "invalid_request").await;
}

#[tokio::test]
async fn rejection_and_owner_cancellation_wake_waiters_without_publishing_operations() {
    let store = store();
    let fresh = reserve(&store, "rejected");
    let duplicate = reserve(&store, "rejected");
    let error = ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::InvalidRequest,
        "The candidate configuration is invalid.",
        None,
    )
    .with_details(json!({"valid": false}));
    assert!(store.reject(&fresh.id, error));
    let original = assert_error(
        fresh.admission().await.unwrap_err(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_request",
    )
    .await;
    let replay = assert_error(
        duplicate.admission().await.unwrap_err(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_request",
    )
    .await;
    assert_eq!(original, replay);
    assert_eq!(original["error"]["details"], json!({"valid": false}));
    assert_error(
        store.get(&fresh.id).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    let retry = reserve(&store, "rejected");
    assert!(retry.fresh);
    assert_ne!(retry.id, fresh.id);
    drop(fresh);
    assert!(retry.admission().now_or_never().is_none());

    let abandoned = reserve(&store, "abandoned");
    let waiter = reserve(&store, "abandoned");
    let pending = abandoned.admission();
    drop(abandoned);
    assert_error(
        pending.await.unwrap_err(),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    assert_error(
        waiter.admission().await.unwrap_err(),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;

    let pending = retry.admission();
    drop(store);
    assert_error(
        pending.await.unwrap_err(),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn full_store_evicts_oldest_terminal_operation_before_refusing_unfinished_ones() {
    let store = store();
    let mut owners = Vec::new();
    for number in 0..MAX_OPERATIONS {
        let reservation = reserve(&store, &number.to_string());
        if number != 0 {
            assert!(store.accept(&reservation.id));
            assert!(store.running(&reservation.id));
        }
        owners.push(reservation);
    }
    let reserve_new = |key: &str| {
        store.reserve(
            "owner",
            "POST",
            "/api/v1/operations/reload",
            Some(key),
            b"{}",
            crate::native_api::operations::OperationKind::Reload,
        )
    };
    // Every slot is preparing or running, so nothing can be evicted.
    assert_error(
        reserve_new("new-0").err().unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    for owner in owners.iter().skip(2).rev() {
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(store.fail(&owner.id, "reload_failed", "Reload failed.", None));
    }

    let first = reserve_new("new-1").unwrap();
    assert!(first.fresh);
    let oldest = owners.last().unwrap();
    assert_error(
        store.get(&oldest.id).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    assert_eq!(
        body(store.get(&owners[2].id).unwrap()).await["status"],
        "failed"
    );
    let second = reserve_new("new-2").unwrap();
    assert!(second.fresh);
    assert_error(
        store.get(&owners[MAX_OPERATIONS - 2].id).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;

    // Unfinished operations keep their slot and their idempotent replay.
    let pending = reserve(&store, "0");
    assert!(!pending.fresh);
    assert!(pending.admission().now_or_never().is_none());
    let running = reserve(&store, "1");
    assert_eq!(
        running.admission().await.unwrap().operation_id,
        owners[1].id
    );
    assert!(store.accept(&owners[0].id));
    assert_eq!(
        pending.admission().await.unwrap().operation_id,
        owners[0].id
    );

    // A terminal operation that is not evicted stays for the full retention window.
    tokio::time::advance(RETENTION - Duration::from_secs(1)).await;
    assert_eq!(
        body(store.get(&owners[2].id).unwrap()).await["status"],
        "failed"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_error(
        store.get(&owners[2].id).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
}

#[tokio::test]
async fn operation_reads_reject_unknown_ids_and_never_echo_sensitive_admission_inputs() {
    let store = store();
    let reservation = store
        .reserve(
            "private-bearer",
            "PUT",
            "/private/source",
            Some("private-key"),
            b"secret-config-text",
            crate::native_api::operations::OperationKind::Reload,
        )
        .unwrap();
    assert!(store.accept(&reservation.id));
    assert!(store.fail(
        &reservation.id,
        "reload_rejected",
        "Reload was rejected.",
        Some(json!({"disk_changed": true}))
    ));
    assert_error(
        store.get("unknown").unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    let owner = body(store.get(&reservation.id).unwrap()).await;
    assert_eq!(owner["status"], "failed");
    assert_eq!(owner["result"], Value::Null);
    assert_eq!(owner["started_at"], Value::Null);
    assert_eq!(
        owner["error"],
        json!({"code": "reload_rejected", "message": "Reload was rejected.", "details": {"disk_changed": true}})
    );
    for secret in [
        "private-bearer",
        "/private/source",
        "private-key",
        "secret-config-text",
    ] {
        assert!(!owner.to_string().contains(secret));
    }
    for details in [
        json!("raw engine output"),
        json!({"oversized": "x".repeat(MAX_ERROR_DETAILS)}),
    ] {
        let reservation = store
            .reserve(
                "owner",
                "POST",
                "/reload",
                None,
                b"{}",
                crate::native_api::operations::OperationKind::Reload,
            )
            .unwrap();
        store.accept(&reservation.id);
        store.fail(
            &reservation.id,
            "reload_failed",
            "Reload failed.",
            Some(details),
        );
        let value = body(store.get(&reservation.id).unwrap()).await;
        assert_eq!(value["error"]["details"], Value::Null);
    }
}

#[tokio::test]
async fn events_describe_only_accepted_transitions_in_order() {
    use crate::native_api::{NativeState, events, types::RequestId};

    let mut config = honk_config::Config::default();
    config.global.nfqueue_enable = false;
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.allow_anonymous_loopback = true;
    config.ensure_builtin_nodes();
    let resolver = crate::dns::DnsResolver::new(&config.dns).unwrap();
    let forwarder = resolver.forwarder();
    let mut control = crate::control::ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        crate::routing::Router::new(&[], "direct").unwrap(),
        Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
        resolver,
        forwarder,
    )
    .unwrap();
    let state = NativeState::new(
        &mut control,
        "127.0.0.1:9527".parse().unwrap(),
        SystemTime::now(),
        std::time::Instant::now(),
    )
    .await
    .unwrap();
    let store = Arc::new(OperationStore::new(
        state.instance_id.clone(),
        Arc::clone(&state.observation.events),
    ));
    let request = axum::http::Request::builder()
        .uri("/api/v1/events?kinds=operation.updated")
        .header("accept", "text/event-stream")
        .body(Body::empty())
        .unwrap();
    let response = events::serve(&state, request, &RequestId("test".into()))
        .await
        .unwrap();
    let mut stream = response.into_body().into_data_stream();
    let ready = stream.next().await.unwrap().unwrap();
    assert!(
        std::str::from_utf8(&ready)
            .unwrap()
            .starts_with("event: stream.ready\n")
    );

    let rejected = reserve(&store, "rejected");
    store.reject(&rejected.id, unavailable());
    let abandoned = reserve(&store, "abandoned");
    drop(abandoned);
    let accepted = reserve(&store, "accepted");
    assert!(stream.next().now_or_never().is_none());
    assert!(!store.running(&accepted.id));
    assert!(!store.succeed(
        &accepted.id,
        OperationResult::Reload {
            active_generation_id: None,
            datapath_generation_id: None
        }
    ));
    store.accept(&accepted.id);
    assert!(!store.reject(&accepted.id, unavailable()));
    assert!(!store.succeed(
        &accepted.id,
        OperationResult::Reload {
            active_generation_id: None,
            datapath_generation_id: None
        }
    ));
    store.running(&accepted.id);
    store.succeed(
        &accepted.id,
        crate::native_api::operations::OperationResult::Reload {
            active_generation_id: Some("instance:4".into()),
            datapath_generation_id: Some("9".into()),
        },
    );
    assert!(!store.fail(&accepted.id, "reload_failed", "Reload failed.", None));
    let replay = reserve(&store, "accepted");
    assert!(!replay.fresh);
    for status in ["queued", "running", "succeeded"] {
        let frame = stream.next().await.unwrap().unwrap();
        let frame = std::str::from_utf8(&frame).unwrap();
        assert!(frame.starts_with("event: operation.updated\n"));
        let data: Value = serde_json::from_str(
            frame
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(data["resource_id"], accepted.id);
        assert_eq!(data["status"], status);
        assert_eq!(data["href"], format!("/api/v1/operations/{}", accepted.id));
        assert!(!data.to_string().contains("rejected"));
    }
    assert!(stream.next().now_or_never().is_none());
    let failed = reserve(&store, "failed");
    store.accept(&failed.id);
    store.fail(&failed.id, "reload_rejected", "Reload was rejected.", None);
    for status in ["queued", "failed"] {
        let frame = stream.next().await.unwrap().unwrap();
        let frame = std::str::from_utf8(&frame).unwrap();
        let data: Value = serde_json::from_str(
            frame
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(data["resource_id"], failed.id);
        assert_eq!(data["status"], status);
    }
    assert!(stream.next().now_or_never().is_none());
}

#[tokio::test]
async fn geodata_replay_precedes_exclusivity_and_capacity() {
    let store = store();
    let geodata = |key| {
        store.reserve(
            "owner",
            "POST",
            "/api/v1/geodata/update",
            Some(key),
            b"",
            OperationKind::GeodataUpdate,
        )
    };
    let first = geodata("first").unwrap();
    let replay = geodata("first").unwrap();
    assert_eq!(first.id, replay.id);
    assert!(!replay.fresh);
    let error = geodata("other").err().unwrap();
    assert_error(error, StatusCode::CONFLICT, "state_conflict").await;
    store.accept(&first.id);
    store.running(&first.id);
    let mut retained = Vec::new();
    for index in 1..MAX_OPERATIONS {
        retained.push(reserve(&store, &format!("reload-{index}")));
    }
    assert_eq!(geodata("first").unwrap().id, first.id);
    assert_error(
        geodata("other").err().unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    store.fail(&first.id, "download_failed", "Download failed", None);
    assert_eq!(geodata("first").unwrap().id, first.id);
    let other = geodata("other").unwrap();
    assert!(other.fresh);
    assert_error(
        store.get(&first.id).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    assert_eq!(geodata("first").unwrap().id, first.id);
    assert_error(
        store
            .reserve(
                "owner",
                "POST",
                "/api/v1/operations/reload",
                Some("full"),
                b"{}",
                OperationKind::Reload,
            )
            .err()
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
}

fn finish_failed(store: &Arc<OperationStore>, key: &str) -> String {
    let reservation = reserve(store, key);
    assert!(store.accept(&reservation.id));
    assert!(store.running(&reservation.id));
    assert!(store.fail(&reservation.id, "reload_failed", "Reload failed.", None));
    reservation.id.clone()
}

#[tokio::test(start_paused = true)]
async fn evicted_keyed_operation_replays_until_retention_after_it_finished() {
    let store = store();
    let original = reserve(&store, "kept");
    assert!(store.accept(&original.id));
    let envelope = serde_json::to_value(original.admission().await.unwrap()).unwrap();
    assert!(store.running(&original.id));
    assert!(store.fail(&original.id, "reload_failed", "Reload failed.", None));
    tokio::time::advance(Duration::from_secs(100)).await;
    let fillers: Vec<_> = (0..MAX_OPERATIONS)
        .map(|number| reserve(&store, &format!("filler-{number}")))
        .collect();
    assert!(fillers.iter().all(|filler| filler.fresh));
    drop(fillers);
    // The original owner may outlive eviction; dropping it must not touch the kept key.
    drop(original);
    let id = envelope["operation_id"].as_str().unwrap().to_owned();
    assert_error(
        store.get(&id).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;

    let replay = reserve(&store, "kept");
    assert!(!replay.fresh);
    assert_eq!(replay.id, id);
    let accepted = replay.admission().await.unwrap();
    assert_eq!(serde_json::to_value(&accepted).unwrap(), envelope);
    let response = accepted.into_response();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response.headers()["location"],
        format!("/api/v1/operations/{id}")
    );
    let conflict = store
        .reserve(
            "owner",
            "POST",
            "/api/v1/operations/reload",
            Some("kept"),
            b"{ }",
            OperationKind::Reload,
        )
        .err()
        .unwrap();
    assert_error(conflict, StatusCode::CONFLICT, "idempotency_conflict").await;

    // An evicted operation takes no further transitions.
    assert!(!store.accept(&id));
    assert!(!store.reject(&id, unavailable()));
    assert!(!store.running(&id));
    assert!(!store.fail(&id, "reload_failed", "Reload failed.", None));
    assert!(!store.succeed(
        &id,
        OperationResult::Reload {
            active_generation_id: None,
            datapath_generation_id: None
        }
    ));
    assert_error(
        store.get(&id).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;

    // Expiry counts from the original finish; a late replay does not extend it.
    tokio::time::advance(RETENTION - Duration::from_secs(101)).await;
    let late = reserve(&store, "kept");
    assert!(!late.fresh);
    assert_eq!(late.id, id);
    tokio::time::advance(Duration::from_secs(1)).await;
    let expired = reserve(&store, "kept");
    assert!(expired.fresh);
    assert_ne!(expired.id, id);
}

#[tokio::test(start_paused = true)]
async fn evicted_keys_never_refuse_admission_and_drop_the_oldest_past_their_cap() {
    let store = store();
    let ids: Vec<_> = (0..MAX_OPERATIONS + MAX_TOMBSTONES + 1)
        .map(|number| finish_failed(&store, &number.to_string()))
        .collect();
    let kept = reserve(&store, "1");
    assert!(!kept.fresh);
    assert_eq!(kept.id, ids[1]);
    let forgotten = reserve(&store, "0");
    assert!(forgotten.fresh);
    assert_ne!(forgotten.id, ids[0]);
}
