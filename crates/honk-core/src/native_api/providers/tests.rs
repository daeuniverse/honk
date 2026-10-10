use super::*;
use crate::{
    control::{ControlCommand, ControlPlane},
    dns::DnsResolver,
    ebpf::mock::MockEbpfBackend,
    native_api::NativeServer,
    routing::Router,
    subscription::{SubscriptionStore, SubscriptionSupervisor},
};
use honk_config::{Config, node::Node};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);
const OLD: &str = "socks5://127.0.0.1:11080#old";
const NEW: &str = "socks5://127.0.0.1:11081#new";

mod support;
use support::{Fixture, Origin, respond};

#[tokio::test]
async fn provider_get_is_safe_pure_and_counts_accepted_provenance_not_display_names() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut disabled = subscription.clone();
    disabled.id = Uuid::new_v4();
    disabled.enabled = false;
    let config = Config {
        subscriptions: vec![subscription.clone(), disabled.clone()],
        ..Default::default()
    };
    let fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    for _ in 0..3 {
        let list = fixture.get("/api/v1/providers").await;
        let detail = fixture
            .get(&format!("/api/v1/providers/{}", subscription.id))
            .await;
        assert_eq!(detail["node_count"], 1);
        assert_eq!(detail["status"], "ok");
        assert!(detail["updated_at"].is_string());
        assert_eq!(detail["url_redacted"], subscription.url);
        assert_eq!(detail["name"], subscription.name);
        assert!(detail["traffic"].is_null() && detail["expires_at"].is_null());
        assert_eq!(
            list["providers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == detail["id"])
                .unwrap(),
            &detail
        );
        let disabled = fixture
            .get(&format!("/api/v1/providers/{}", disabled.id))
            .await;
        assert_eq!(disabled["node_count"], 0);
        assert_eq!(disabled["status"], "stale");
        assert!(disabled["updated_at"].is_null() && disabled["last_error"].is_null());
    }
    assert_eq!(
        origin.count.load(Ordering::SeqCst),
        1,
        "GET must never fetch"
    );
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn refresh_replays_before_busy_and_success_waits_for_real_runtime_publication() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let accepted = fixture.refresh(subscription.id, "same").await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let accepted: Value = accepted.json().await.unwrap();
    let socket = origin.next().await;
    let invalid = fixture
        .client
        .post(fixture.url(&format!("/api/v1/providers/{}/refresh", subscription.id)))
        .header("idempotency-key", "same")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid.json::<Value>().await.unwrap()["error"]["code"],
        "invalid_request"
    );
    let replay: Value = fixture
        .refresh(subscription.id, "same")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(replay["operation_id"], accepted["operation_id"]);
    assert_eq!(
        fixture.refresh(subscription.id, "different").await.status(),
        StatusCode::CONFLICT
    );
    // Keep all 32 operation slots occupied; malformed or missing resources still win.
    let operations = &fixture.state.observation.operations;
    let held: Vec<_> = (0..31)
        .map(|index| {
            operations
                .reserve(
                    fixture.state.principal(),
                    "POST",
                    &format!("/capacity/{index}"),
                    None,
                    b"",
                    OperationKind::ProviderRefresh,
                )
                .unwrap()
        })
        .collect();
    for provider in ["not-a-uuid".to_owned(), Uuid::new_v4().to_string()] {
        let response = fixture
            .client
            .post(fixture.url(&format!("/api/v1/providers/{provider}/refresh")))
            .header("idempotency-key", "missing")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"]["code"],
            "resource_not_found"
        );
    }
    assert_eq!(
        fixture
            .refresh(subscription.id, "new-at-capacity")
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let invalid = fixture
        .client
        .post(fixture.url(&format!("/api/v1/providers/{}/refresh", subscription.id)))
        .header("idempotency-key", "invalid-at-capacity")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid.json::<Value>().await.unwrap()["error"]["code"],
        "invalid_request"
    );
    let replay: Value = fixture
        .refresh(subscription.id, "same")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(replay["operation_id"], accepted["operation_id"]);
    drop(held);
    respond(socket, NEW).await;
    let command = timeout(WAIT, fixture.merges.recv()).await.unwrap().unwrap();
    assert_eq!(
        fixture.get(accepted["href"].as_str().unwrap()).await["status"],
        "running"
    );
    assert!(
        fixture
            .state
            .config
            .read()
            .await
            .nodes
            .iter()
            .any(|node| node.name == "old")
    );
    fixture.commands.send(command).await.unwrap();
    let terminal = fixture.terminal(&accepted).await;
    assert_eq!(terminal["status"], "succeeded");
    assert_eq!(terminal["result"]["node_count"], 1);
    assert_eq!(terminal["result"]["url_redacted"], subscription.url);
    assert_eq!(terminal["result"]["name"], subscription.name);
    assert!(
        fixture
            .state
            .config
            .read()
            .await
            .nodes
            .iter()
            .any(|node| node.name == "new")
    );
    assert_eq!(origin.count.load(Ordering::SeqCst), 2);
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn failed_fetch_and_failed_merge_preserve_previously_accepted_nodes() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    config.nodes.push(Node::from_share_link(NEW).unwrap());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let accepted: Value = fixture
        .refresh(subscription.id, "bad-body")
        .await
        .json()
        .await
        .unwrap();
    respond(origin.next().await, "not a subscription").await;
    assert_eq!(fixture.terminal(&accepted).await["status"], "failed");
    let after_fetch = fixture
        .get(&format!("/api/v1/providers/{}", subscription.id))
        .await;
    assert_eq!(after_fetch["status"], "stale");
    assert_eq!(after_fetch["node_count"], 1);
    let accepted: Value = fixture
        .refresh(subscription.id, "bad-merge")
        .await
        .json()
        .await
        .unwrap();
    respond(origin.next().await, NEW).await;
    fixture.publish().await;
    let operation = fixture.terminal(&accepted).await;
    assert_eq!(operation["status"], "failed");
    assert_eq!(operation["error"]["code"], "publication_rejected");
    assert_eq!(
        operation["error"]["details"]["diagnostic_code"],
        "duplicate-node-id"
    );
    assert!(
        fixture
            .state
            .config
            .read()
            .await
            .nodes
            .iter()
            .any(|node| node.name == "old" && node.subscription_id == Some(subscription.id))
    );
    let provider = fixture
        .get(&format!("/api/v1/providers/{}", subscription.id))
        .await;
    assert_eq!(provider["updated_at"], after_fetch["updated_at"]);
    assert_eq!(provider["last_error"]["code"], "publication_rejected");
    assert_eq!(
        provider["last_error"]["details"],
        json!({"diagnostic_code": "duplicate-node-id"})
    );
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn cache_load_is_stale_until_ack_and_startup_or_periodic_fetch_shares_api_gate() {
    let mut origin = Origin::new().await;
    let mut subscription = origin.subscription();
    subscription.update_interval = 1;
    let directory = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(directory.path());
    store
        .store_content(&subscription, OLD.into())
        .await
        .unwrap();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, Some(store), None, &mut origin).await;
    let socket = origin.next().await;
    let cached = fixture
        .get(&format!("/api/v1/providers/{}", subscription.id))
        .await;
    assert_eq!(cached["status"], "stale");
    assert_eq!(cached["node_count"], 1);
    assert!(cached["updated_at"].is_string());
    assert_eq!(
        fixture
            .refresh(subscription.id, "startup-busy")
            .await
            .status(),
        StatusCode::CONFLICT
    );
    respond(socket, NEW).await;
    fixture.publish().await;
    timeout(WAIT, async {
        loop {
            if fixture
                .get(&format!("/api/v1/providers/{}", subscription.id))
                .await["status"]
                == "ok"
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut periodic = origin.next().await;
    assert_eq!(
        fixture
            .refresh(subscription.id, "periodic-busy")
            .await
            .status(),
        StatusCode::CONFLICT
    );
    fixture.stop().await;
    assert_eq!(
        timeout(WAIT, periodic.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0,
        "shutdown must close the actual fetching socket"
    );
    origin.stop().await;
}

#[tokio::test]
async fn removed_provider_late_fetch_is_rejected_and_retained_replay_remains_available() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let accepted: Value = fixture
        .refresh(subscription.id, "removed")
        .await
        .json()
        .await
        .unwrap();
    let socket = origin.next().await;
    let mut replacement = fixture.state.config.read().await.as_ref().clone();
    replacement.subscriptions.clear();
    fixture.reload(replacement).await;
    respond(socket, NEW).await;
    fixture.publish().await;
    assert_eq!(fixture.terminal(&accepted).await["status"], "failed");
    assert!(
        fixture
            .state
            .config
            .read()
            .await
            .nodes
            .iter()
            .all(|node| node.subscription_id != Some(subscription.id))
    );
    let replay = fixture.refresh(subscription.id, "removed").await;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(
        replay.json::<Value>().await.unwrap()["operation_id"],
        accepted["operation_id"]
    );
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn disconnected_refresh_keeps_daemon_owned_fetch_and_merge_until_completion() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let mut caller = TcpStream::connect(fixture.address).await.unwrap();
    caller.write_all(format!("POST /api/v1/providers/{}/refresh HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer provider-admin-token\r\nIdempotency-Key: lost-response\r\nContent-Length: 0\r\n\r\n", subscription.id, fixture.address).as_bytes()).await.unwrap();
    let socket = origin.next().await;
    drop(caller);
    respond(socket, NEW).await;
    fixture.publish().await;
    let replay: Value = fixture
        .refresh(subscription.id, "lost-response")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(fixture.terminal(&replay).await["status"], "succeeded");
    assert_eq!(origin.count.load(Ordering::SeqCst), 2);
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn failed_initial_fetch_is_error_without_fabricated_success_time() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let fixture = Fixture::start(config, None, Some("invalid body"), &mut origin).await;
    let provider = fixture
        .get(&format!("/api/v1/providers/{}", subscription.id))
        .await;
    assert_eq!(provider["status"], "error");
    assert_eq!(provider["node_count"], 0);
    assert!(provider["updated_at"].is_null());
    assert_eq!(provider["last_error"]["code"], "fetch_failed");
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn same_uuid_replacement_cannot_publish_old_fetch_or_borrow_new_authorization() {
    let mut origin = Origin::new().await;
    let mut replacement_origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let accepted: Value = fixture
        .refresh(subscription.id, "old-incarnation")
        .await
        .json()
        .await
        .unwrap();
    let socket = origin.next().await;
    let mut replacement = fixture.state.config.read().await.as_ref().clone();
    replacement.subscriptions[0].url = replacement_origin.subscription().url;
    fixture.reload(replacement).await;
    respond(socket, NEW).await;
    fixture.publish().await;
    assert_eq!(fixture.terminal(&accepted).await["status"], "failed");
    assert!(
        fixture
            .state
            .config
            .read()
            .await
            .nodes
            .iter()
            .all(|node| node.name != "new")
    );
    respond(
        replacement_origin.next().await,
        "socks5://127.0.0.1:11082#replacement",
    )
    .await;
    fixture.publish().await;
    timeout(WAIT, async {
        loop {
            if fixture
                .state
                .config
                .read()
                .await
                .nodes
                .iter()
                .any(|node| node.name == "replacement")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.stop().await;
    origin.stop().await;
    replacement_origin.stop().await;
}

#[tokio::test]
async fn provider_snapshot_is_immutable_and_unknown_cursor_is_expired() {
    let mut origin = Origin::new().await;
    let mut config = Config::default();
    for _ in 0..3 {
        let mut provider = origin.subscription();
        provider.enabled = false;
        config.subscriptions.push(provider);
    }
    let fixture = Fixture::start(config, None, None, &mut origin).await;
    let first = fixture.get("/api/v1/providers?limit=1").await;
    assert_eq!(first["providers"][0]["id"], "inline");
    let cursor = first["next_cursor"].as_str().unwrap();
    let wider = fixture.get("/api/v1/providers?limit=2").await;
    let all = fixture.get("/api/v1/providers").await;
    let wider_cursor = wider["next_cursor"].as_str().unwrap();
    let (snapshot, _) = wider_cursor.split_once(':').unwrap();
    for (cursor, limit, status) in [
        (format!("{snapshot}:1"), 2, StatusCode::GONE),
        (format!("{snapshot}:02"), 2, StatusCode::GONE),
        (format!("{snapshot}:+2"), 2, StatusCode::GONE),
        (
            format!("{}:2", snapshot.replace('-', "")),
            2,
            StatusCode::GONE,
        ),
        (format!("{snapshot}:1"), 1, StatusCode::BAD_REQUEST),
        (format!("{snapshot}:4"), 1, StatusCode::GONE),
    ] {
        let mut url = reqwest::Url::parse(&fixture.url("/api/v1/providers")).unwrap();
        url.query_pairs_mut()
            .extend_pairs([("limit", limit.to_string()), ("cursor", cursor)]);
        let response = fixture.client.get(url).send().await.unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"]["code"],
            if status == StatusCode::GONE {
                "snapshot_expired"
            } else {
                "invalid_request"
            }
        );
    }
    let resumed = fixture
        .get(&format!("/api/v1/providers?limit=2&cursor={wider_cursor}"))
        .await;
    assert_eq!(
        resumed["providers"],
        json!(&all["providers"].as_array().unwrap()[2..])
    );
    let mut changed = fixture.state.config.read().await.as_ref().clone();
    changed.subscriptions.clear();
    *fixture.state.config.write().await = Arc::new(changed);
    let mut rest = Vec::new();
    let mut next = cursor.to_owned();
    loop {
        let page = fixture
            .get(&format!("/api/v1/providers?limit=1&cursor={next}"))
            .await;
        rest.extend(page["providers"].as_array().unwrap().iter().cloned());
        match page["next_cursor"].as_str() {
            Some(cursor) => next = cursor.to_owned(),
            None => break,
        }
    }
    assert_eq!(rest.len(), 3);
    assert!(
        rest.iter()
            .all(|row| row["id"] != first["providers"][0]["id"])
    );
    assert_eq!(origin.count.load(Ordering::SeqCst), 0);
    for (query, status) in [
        (format!("limit=2&cursor={cursor}"), StatusCode::BAD_REQUEST),
        (format!("cursor={}:1", Uuid::new_v4()), StatusCode::GONE),
        ("cursor=bad".to_owned(), StatusCode::GONE),
    ] {
        let response = fixture
            .client
            .get(fixture.url(&format!("/api/v1/providers?{query}")))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
    }
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn provider_snapshot_over_budget_is_retryable_snapshot_unavailable() {
    let api = ProviderApi::new();
    let snapshot = Snapshot {
        instance: "instance".into(),
        rows: vec![Provider::inline(0), Provider::inline(0)],
        bytes: MAX_SNAPSHOT_BYTES + 1,
    };
    let id = RequestId("request-providers".into());
    let response = api
        .snapshots
        .first(snapshot, 1, &id)
        .unwrap_err()
        .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "1");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "snapshot_unavailable");
    assert_eq!(body["request_id"], "request-providers");
}

#[test]
fn provider_debug_omits_full_url() {
    let subscription = Subscription {
        name: "configured-provider".into(),
        url: format!(
            "https://example.test/{}?token=url-sentinel",
            "p".repeat(4096)
        ),
        ..Default::default()
    };
    let row = Provider::observed(&subscription, ProviderLoad::default(), 0);
    assert_eq!(row.url_redacted.as_deref(), Some(subscription.url.as_str()));
    assert!(!format!("{row:?}").contains("url-sentinel"));
}

#[test]
fn provider_projection_masks_only_listener_values_in_names_and_urls() {
    let mut config = Config::default();
    config.experimental.native_api.secret = "native-listener-token".into();
    config.experimental.clash_api.secret = "clash-listener-token".into();
    let subscription = Subscription {
        name: "provider-native-listener-token".into(),
        url: "https://user:password@example.test/path?token=clash-listener-token#fragment".into(),
        ..Default::default()
    };
    let id = subscription.id;
    config.subscriptions.push(subscription);
    let value = provider_value(&config, None, id, None, |_| None).unwrap();
    assert_eq!(value["name"], "provider-<redacted>");
    assert_eq!(
        value["url_redacted"],
        "https://user:password@example.test/path?token=<redacted>#fragment"
    );
}

#[test]
fn provider_rows_report_the_download_route_like_geodata() {
    let mut config = Config::default();
    for (name, detour) in [
        ("routed", ""),
        ("direct", "direct"),
        ("grouped", "proxy"),
        ("gone", "removed"),
    ] {
        config.subscriptions.push(Subscription {
            name: name.into(),
            url: "https://example.test/sub".into(),
            download_detour: detour.into(),
            ..Default::default()
        });
    }
    let group_id = |name: &str| (name == "proxy").then(|| "group-proxy".to_owned());
    let routes: Vec<_> = config
        .subscriptions
        .iter()
        .map(|subscription| {
            provider_value(&config, None, subscription.id, None, group_id).unwrap()["download"]
                .clone()
        })
        .collect();
    assert_eq!(
        routes,
        [
            json!({"route": "routing", "group_id": null}),
            json!({"route": "direct", "group_id": null}),
            json!({"route": "group", "group_id": "group-proxy"}),
            json!({"route": "group", "group_id": null}),
        ]
    );
    assert_eq!(
        serde_json::to_value(Provider::inline(0)).unwrap()["download"],
        Value::Null
    );
}

#[tokio::test]
async fn refresh_results_keep_full_urls_except_listener_values() {
    let mut origin = Origin::new().await;
    let mut subscription = origin.subscription();
    subscription.name.push_str("-provider-admin-token");
    let mut config = Config::default();
    config.experimental.clash_api.secret = "private-query".into();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let expected_url = subscription.url.replace("private-query", "<redacted>");
    let expected_name = subscription
        .name
        .replace("provider-admin-token", "<redacted>");
    let before = fixture
        .get(&format!("/api/v1/providers/{}", subscription.id))
        .await;
    assert_eq!(before["url_redacted"], expected_url);
    assert_eq!(before["name"], expected_name);
    let accepted: Value = fixture
        .refresh(subscription.id, "masked-refresh")
        .await
        .json()
        .await
        .unwrap();
    respond(origin.next().await, NEW).await;
    fixture.publish().await;
    let terminal = fixture.terminal(&accepted).await;
    assert_eq!(terminal["status"], "succeeded");
    assert_eq!(terminal["result"]["id"], subscription.id.to_string());
    assert_eq!(terminal["result"]["url_redacted"], expected_url);
    assert_eq!(terminal["result"]["name"], expected_name);
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn refresh_without_subscription_owner_is_unsupported_not_retryable() {
    let state = crate::native_api::tests::state().await;
    let subscription = Subscription {
        url: "http://127.0.0.1:9/provider".into(),
        ..Default::default()
    };
    Arc::make_mut(&mut *state.config.write().await)
        .subscriptions
        .push(subscription.clone());
    let request = Request::post(format!("/api/v1/providers/{}/refresh", subscription.id))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = refresh(
        &state,
        &subscription.id.to_string(),
        request,
        &RequestId("test".into()),
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response.headers().get("retry-after").is_none());
}

#[tokio::test]
async fn degraded_refresh_reports_userspace_commit_without_a_kernel_generation() {
    let state = crate::native_api::tests::state().await;
    let operations = Arc::clone(&state.observation.operations);
    let subscription = Subscription::default();
    let reservation = operations
        .reserve(
            state.principal(),
            "POST",
            "/api/v1/providers/test/refresh",
            None,
            b"",
            OperationKind::ProviderRefresh,
        )
        .unwrap();
    let id = reservation.id.clone();
    let operation = Box::new(RefreshOperation {
        reservation,
        operations: Arc::clone(&operations),
        instance: state.instance_id.clone(),
        display_name: "provider".into(),
        display_url: "https://example.test/sub".into(),
        display_download: None,
    });
    operation.accept();
    operation.running();
    operation.finish(
        &subscription,
        ProviderLoad::default(),
        Ok(SubscriptionMergeReply {
            outcome: ReloadOutcome::CommittedDegraded { generation: 7 },
            node_count: 1,
            authorized: Vec::new(),
            rejection: None,
        }),
    );
    let response = operations.get(&id).unwrap();
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["status"], "failed");
    assert_eq!(body["error"]["code"], "publication_degraded");
    assert_eq!(
        body["error"]["details"],
        json!({
            "committed": true,
            "active_generation_id": format!("{}:7", state.instance_id),
            "datapath_generation_id": null,
        })
    );
}

#[tokio::test]
async fn refresh_publishes_configured_xhttp_transport_in_node_catalog() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let config = Config {
        subscriptions: vec![subscription.clone()],
        ..Default::default()
    };
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let accepted: Value = fixture
        .refresh(subscription.id, "xhttp")
        .await
        .json()
        .await
        .unwrap();
    respond(origin.next().await,
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:443?type=splithttp&security=tls&path=%2Fprivate-path#refreshed",
    ).await;
    let command = timeout(WAIT, fixture.merges.recv()).await.unwrap().unwrap();
    let before = fixture.get("/api/v1/nodes").await;
    let old = before["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "old")
        .unwrap();
    assert_eq!(old.get("stream_transport"), Some(&Value::Null));
    fixture.commands.send(command).await.unwrap();
    assert_eq!(fixture.terminal(&accepted).await["status"], "succeeded");
    let after = fixture.get("/api/v1/nodes").await;
    let row = after["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "refreshed")
        .unwrap();
    assert_eq!(row["protocol"], "vless");
    assert_eq!(row["stream_transport"], "xhttp");
    assert_eq!(row["provider_id"], subscription.id.to_string());
    assert!(
        !after["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == old["id"])
    );
    assert!(!row.to_string().contains("private-path"));
    fixture.stop().await;
    origin.stop().await;
}
