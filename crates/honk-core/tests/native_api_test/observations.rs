use super::*;

#[tokio::test]
async fn connections_filter_before_combined_limit_and_preserve_full_width_live_bytes() {
    let app = TestApp::new(|_| {}).await;
    let tracker = app.control.connection_tracker();
    let now = Instant::now();
    for row in [
        entry("old", "tcp", "192.0.2.1:4000", now - Duration::from_secs(1)),
        entry("a", "udp", "[::ffff:192.0.2.1]:4001", now),
        entry("b", "tcp", "192.0.2.1:4002", now),
        entry("c", "tcp", "192.0.2.1:4003", now),
        entry(
            "other-source",
            "tcp",
            "192.0.2.2:4000",
            now + Duration::from_secs(1),
        ),
    ] {
        tracker.register(row);
    }
    let big = u64::from(u32::MAX) + 123;
    tracker.update_bytes("a", big, u64::MAX);
    let summary = response_json(
        app.get("/api/v1/connections?src=192.0.2.1&limit=1")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (summary["total_tcp"].as_u64(), summary["total_udp"].as_u64()),
        (Some(3), Some(1))
    );
    assert_eq!(summary["tcp"], json!([]));
    assert_eq!(summary["udp"][0]["id"], "a");
    assert_eq!(summary["truncated"], true);
    assert_eq!(summary["visibility"], "partial");
    let row = &summary["udp"][0];
    assert_eq!(row["upload_bytes"], big.to_string());
    assert_eq!(row["download_bytes"], u64::MAX.to_string());
    for key in ["src", "dst", "domain"] {
        assert!(row.get(key).is_none());
    }
    for key in [
        "flow_id",
        "pname",
        "rule_id",
        "rule_expression",
        "ingress",
        "domain_source",
        "started_at",
        "upload_bytes_per_second",
        "download_bytes_per_second",
    ] {
        assert_eq!(row.get(key), Some(&Value::Null), "{key}");
    }
    assert_eq!(row["outbound"], "routed-group");
    assert_eq!(row["chain"], json!([]));
    assert_eq!(row["chain_source"], "unknown");
    assert_eq!(row["rule_source"], "unknown");
    assert!(!summary.to_string().contains("private-"));
    assert!(!summary.to_string().contains("current-leaf"));
    let full = response_json(
        app.get("/api/v1/connections?src=%3A%3Affff%3A192.0.2.1&limit=3&detail=full")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        full["tcp"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["b", "c"]
    );
    assert_eq!(full["udp"][0]["id"], "a");
    assert_eq!(full["udp"][0]["src"], "[::ffff:192.0.2.1]:4001");
    assert_eq!(full["udp"][0]["dst"], "198.51.100.10:443");
    assert_eq!(full["udp"][0].get("domain"), Some(&Value::Null));
    let tcp = response_json(
        app.get("/api/v1/connections?type=tcp&src=192.0.2.1&limit=1000")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(tcp["total_udp"], 0);
    assert_eq!(tcp["udp"], json!([]));
    assert_eq!(tcp["truncated"], false);
    assert_eq!(
        tcp["tcp"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["b", "c", "old"]
    );
    let latest = response_json(app.get("/api/v1/connections?limit=1").send().await.unwrap()).await;
    assert_eq!(latest["tcp"][0]["id"], "other-source");
    tracker.remove("a");
    let removed = response_json(
        app.get("/api/v1/connections?type=udp")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(removed["total_udp"], 0);
    assert_eq!(removed["udp"], json!([]));
    app.shutdown().await;
}

/// Reads the next named event and checks its data against the contract.
pub(super) async fn next_event(
    response: &mut Response,
    pending: &mut String,
) -> (String, String, Value) {
    loop {
        if let Some(end) = pending.find("\n\n") {
            let frame = pending[..end].to_owned();
            pending.drain(..end + 2);
            let field = |key: &str| {
                frame
                    .lines()
                    .find_map(|line| line.strip_prefix(key))
                    .map(str::trim)
                    .unwrap_or("")
                    .to_owned()
            };
            let kind = field("event:");
            if kind.is_empty() {
                continue;
            }
            let data = serde_json::from_str(&field("data:")).unwrap();
            contract::check_event(response.url(), &kind, &data);
            return (kind, field("id:"), data);
        }
        let chunk = timeout(IO_TIMEOUT, response.chunk())
            .await
            .unwrap()
            .unwrap()
            .expect("event stream ended");
        pending.push_str(std::str::from_utf8(&chunk).unwrap());
        assert!(pending.len() < 65536);
    }
}

#[tokio::test]
async fn native_events_replay_actual_commits_after_ready_and_reject_changed_filters() {
    let app = TestApp::new(|_| {}).await;
    let path = "/api/v1/events?kinds=generation.changed";
    let mut fresh = app
        .get(path)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status(), StatusCode::OK);
    assert!(
        fresh.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    api_headers(&fresh);
    let mut pending = String::new();
    let (kind, cursor, initial) = next_event(&mut fresh, &mut pending).await;
    assert_eq!(kind, "stream.ready");
    let mut config = app.control.config_handle().read().await.as_ref().clone();
    config.routing.default_outbound = "block".into();
    assert!(
        app.control
            .reload_runtime_config(config.clone(), Default::default())
            .await
    );
    let (kind, committed_cursor, committed) = next_event(&mut fresh, &mut pending).await;
    assert_eq!(kind, "generation.changed");
    assert_eq!(committed["instance_id"], initial["instance_id"]);
    assert_ne!(
        committed["previous_generation_id"],
        committed["generation_id"]
    );
    drop(fresh);
    let mut resumed = app
        .get(path)
        .header("accept", "text/event-stream")
        .header("last-event-id", &cursor)
        .send()
        .await
        .unwrap();
    let mut pending = String::new();
    let ready = next_event(&mut resumed, &mut pending).await;
    assert_eq!(ready.0, "stream.ready");
    assert_eq!(ready.1, cursor);
    let replay = next_event(&mut resumed, &mut pending).await;
    assert_eq!(replay.0, "generation.changed");
    assert_eq!(replay.1, committed_cursor);
    assert_eq!(replay.2, committed);
    drop(resumed);
    error_response(
        app.get("/api/v1/events?kinds=flow.updated")
            .header("accept", "text/event-stream")
            .header("last-event-id", cursor)
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "event_cursor_expired",
    )
    .await;
    let runtime = response_json(app.get("/api/v1/runtime").send().await.unwrap()).await;
    config.experimental.native_api.secret = "rejected".into();
    assert!(
        !app.control
            .reload_runtime_config(config, Default::default())
            .await
    );
    let after = response_json(app.get("/api/v1/runtime").send().await.unwrap()).await;
    assert_eq!(
        after["generation"]["active_id"],
        runtime["generation"]["active_id"]
    );
    app.shutdown().await;
}

#[tokio::test]
async fn native_catalog_capabilities_and_recording_disable_are_honest() {
    let app = TestApp::new(|config| config.experimental.native_api.record_flows = false).await;
    let capabilities = response_json(app.get("/api/v1/capabilities").send().await.unwrap()).await;
    assert_eq!(capabilities["resources"]["flows"]["recording"], "off");
    let flows = response_json(app.get("/api/v1/flows?detail=full").send().await.unwrap()).await;
    assert_eq!(flows["flows"], serde_json::json!([]));
    assert_eq!(flows["coverage"]["userspace_tcp"], "none");
    let settings = response_json(app.get("/api/v1/runtime/settings").send().await.unwrap()).await;
    assert_eq!(settings["recording"]["flows"]["active"], false);
    let nodes = response_json(app.get("/api/v1/nodes?limit=1").send().await.unwrap()).await;
    assert_eq!(nodes["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(nodes["nodes"][0]["health"], serde_json::json!([]));
    let groups = response_json(app.get("/api/v1/groups").send().await.unwrap()).await;
    assert!(groups.is_array());
    error_response(
        app.get("/api/v1/flows/unknown").send().await.unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    app.shutdown().await;
}

#[tokio::test]
async fn native_catalog_masks_listener_secrets_without_changing_membership_or_cursors() {
    use honk_config::{group::Group, node::Node, subscription::Subscription};
    use honk_core::stats::OutboundKind;

    const CLASH_SECRET: &str = "clash-observation-secret";
    let display = format!("{SECRET}-{CLASH_SECRET}");
    let subscription = Subscription {
        name: format!("provider-{display}"),
        url: "https://example.invalid/nodes".into(),
        ..Default::default()
    };
    let mut nodes: Vec<_> = (1080..1083)
        .map(|port| Node::from_share_link(&format!("socks5://127.0.0.1:{port}")).unwrap())
        .collect();
    nodes.sort_unstable_by_key(|node| node.id);
    for (index, node) in nodes.iter_mut().enumerate() {
        node.name = if index == 2 {
            "ordinary-node".into()
        } else {
            format!("node-{index}-{display}")
        };
        node.subscription_id = Some(subscription.id);
    }
    let parent_name = format!("parent-{display}");
    let child_name = format!("child-{display}");
    let app = TestApp::new(|config| {
        config.experimental.clash_api.secret = CLASH_SECRET.into();
        config.subscriptions.push(subscription.clone());
        config.nodes.extend(nodes.clone());
        config.groups = vec![
            Group {
                name: parent_name.clone(),
                groups: vec![child_name.clone()],
                default: Some(child_name.clone()),
                ..Default::default()
            },
            Group {
                name: child_name.clone(),
                nodes: nodes.iter().map(|node| node.id).collect(),
                default: Some(nodes[1].name.clone()),
                icon: Some(format!("https://example.invalid/{display}.svg")),
                check_url: Some(format!("https://example.invalid/{display}/check")),
                final_outbound: Some(nodes[0].name.clone()),
                ..Default::default()
            },
        ];
    })
    .await;
    let stats = app.control.stats_handle();
    let _named = stats.track_connection(&nodes[0].name, OutboundKind::Node);
    stats.record_bytes(&nodes[0].name, OutboundKind::Node, 17, 29);
    let _ordinary = stats.track_connection("ordinary-node", OutboundKind::Node);
    let clean = |value: &Value| {
        let body = value.to_string();
        assert!(!body.contains(SECRET), "{body}");
        assert!(!body.contains(CLASH_SECRET), "{body}");
    };

    let groups = response_json(app.get("/api/v1/groups").send().await.unwrap()).await;
    clean(&groups);
    let rows = groups.as_array().unwrap();
    let parent = rows
        .iter()
        .find(|row| row["name"] == "parent-<redacted>-<redacted>")
        .unwrap();
    let child = rows
        .iter()
        .find(|row| row["name"] == "child-<redacted>-<redacted>")
        .unwrap();
    let child_id = child["id"].as_str().unwrap();
    assert_eq!(parent["selection"]["tcp_member_id"], child["id"]);
    assert_eq!(child["selection"]["tcp_member_id"], nodes[1].id.to_string());
    assert_eq!(child["member_count"], 3);
    assert_eq!(
        child["icon"],
        "https://example.invalid/<redacted>-<redacted>.svg"
    );

    let first = response_json(
        app.get(&format!("/api/v1/nodes?group_id={child_id}&limit=1"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    clean(&first);
    assert_eq!(first["nodes"][0]["id"], nodes[0].id.to_string());
    assert_eq!(first["nodes"][0]["name"], "node-0-<redacted>-<redacted>");
    assert_eq!(
        first["nodes"][0]["subscription_tag"],
        "provider-<redacted>-<redacted>"
    );
    assert_eq!(
        first["nodes"][0]["provider_id"],
        subscription.id.to_string()
    );
    assert_eq!(first["nodes"][0]["group_ids"], json!([child_id]));
    let cursor = first["next_cursor"].as_str().unwrap();
    let resume = |cursor: String| {
        let request = app.get(&format!(
            "/api/v1/nodes?group_id={child_id}&limit=1&cursor={cursor}"
        ));
        async move { response_json(request.send().await.unwrap()).await }
    };
    let resumed = resume(cursor.to_owned()).await;
    clean(&resumed);
    assert_eq!(resumed["observed_at"], first["observed_at"]);
    assert_eq!(resumed["nodes"][0]["id"], nodes[1].id.to_string());
    assert_eq!(resumed["nodes"][0]["name"], "node-1-<redacted>-<redacted>");
    let last = resume(resumed["next_cursor"].as_str().unwrap().to_owned()).await;
    assert_eq!(last["nodes"][0]["id"], nodes[2].id.to_string());
    assert_eq!(last["nodes"][0]["name"], "ordinary-node");
    assert!(last["next_cursor"].is_null());
    for (query, status, code) in [
        (
            format!("group_id={child_id}&limit=100&cursor={cursor}"),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            format!("limit=1&cursor={cursor}"),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            format!(
                "group_id={child_id}&limit=1&cursor={}:1",
                uuid::Uuid::new_v4()
            ),
            StatusCode::GONE,
            "snapshot_expired",
        ),
        (
            "cursor=bad".to_owned(),
            StatusCode::GONE,
            "snapshot_expired",
        ),
    ] {
        error_response(
            app.get(&format!("/api/v1/nodes?{query}"))
                .send()
                .await
                .unwrap(),
            status,
            code,
        )
        .await;
    }

    let single = response_json(
        app.get(&format!("/api/v1/nodes/{}", nodes[0].id))
            .send()
            .await
            .unwrap(),
    )
    .await;
    clean(&single);
    assert_eq!(single, first["nodes"][0]);
    for unknown in ["00000000-0000-4000-8000-000000000000", "not-a-node"] {
        error_response(
            app.get(&format!("/api/v1/nodes/{unknown}"))
                .send()
                .await
                .unwrap(),
            StatusCode::NOT_FOUND,
            "resource_not_found",
        )
        .await;
    }

    for summary in [parent, child] {
        let path = format!("/api/v1/groups/{}", summary["id"].as_str().unwrap());
        let response = app.get(&path).send().await.unwrap();
        assert!(response.headers().get("etag").is_none());
        let detail = response_json(response).await;
        clean(&detail);
        let response = app.get(&format!("{path}/config")).send().await.unwrap();
        assert_eq!(
            response.headers()["etag"].to_str().unwrap(),
            format!("\"{}\"", summary["config_revision"].as_str().unwrap())
        );
        let document = response_json(response).await;
        clean(&document);
        assert_eq!(document["config"], detail["config"]);
        assert_eq!(detail["id"], summary["id"]);
        assert_eq!(detail["config_revision"], summary["config_revision"]);
        assert_eq!(
            detail["config"]["default_member_id"],
            summary["selection"]["tcp_member_id"]
        );
        assert_eq!(
            detail["runtime"]["selection"]["tcp"]["member_id"],
            summary["selection"]["tcp_member_id"]
        );
        assert_eq!(
            detail["runtime"]["selection"]["tcp"]["resolved_leaf_node_id"],
            nodes[1].id.to_string()
        );
        if summary["id"] == child["id"] {
            assert_eq!(detail["members"][0]["id"], nodes[0].id.to_string());
            assert_eq!(detail["members"][0]["name"], "node-0-<redacted>-<redacted>");
            assert_eq!(detail["members"][2]["name"], "ordinary-node");
            assert_eq!(
                detail["config"]["final_outbound"],
                "node-0-<redacted>-<redacted>"
            );
            assert_eq!(
                detail["config"]["check_url"],
                "https://example.invalid/<redacted>-<redacted>/check"
            );
        } else {
            assert_eq!(detail["members"][0]["id"], child["id"]);
            assert_eq!(detail["members"][0]["name"], child["name"]);
        }
    }
    let outbounds = response_json(app.get("/api/v1/runtime/outbounds").send().await.unwrap()).await;
    clean(&outbounds);
    let counters = outbounds["outbounds"].as_array().unwrap();
    let masked = counters
        .iter()
        .find(|row| row["name"] == "node-0-<redacted>-<redacted>")
        .unwrap();
    assert_eq!(masked["active_connections"], 1);
    assert_eq!(masked["total_connections"], "1");
    assert_eq!(masked["upload_bytes"], "17");
    assert_eq!(masked["download_bytes"], "29");
    assert!(counters.iter().any(|row| row["name"] == "ordinary-node"));
    app.shutdown().await;
}

#[tokio::test]
async fn native_head_disposes_event_stream_without_consuming_client_capacity() {
    let app = TestApp::new(|_| {}).await;
    let path = "/api/v1/events?kinds=generation.changed";
    for _ in 0..17 {
        let response = app
            .client
            .head(app.url(path))
            .bearer_auth(SECRET)
            .header("accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert!(response.bytes().await.unwrap().is_empty());
        let settings =
            response_json(app.get("/api/v1/runtime/settings").send().await.unwrap()).await;
        assert_eq!(settings["recording"]["events"]["active"], false);
    }
    let mut response = app
        .get(path)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        next_event(&mut response, &mut String::new()).await.0,
        "stream.ready"
    );
    drop(response);
    app.shutdown().await;
}

#[tokio::test]
async fn native_sse_heartbeat_survives_connection_lifetime_and_shutdown_releases_state() {
    let app = TestApp::new(|_| {}).await;
    let client = contract::ContractClient(Client::builder().no_proxy().build().unwrap());
    let mut response = client
        .get(app.url("/api/v1/events?kinds=generation.changed"))
        .bearer_auth(SECRET)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    let mut pending = String::new();
    assert_eq!(
        next_event(&mut response, &mut pending).await.0,
        "stream.ready"
    );
    for _ in 0..3 {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(16)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();
        let chunk = timeout(IO_TIMEOUT, response.chunk())
            .await
            .unwrap()
            .unwrap()
            .expect("healthy SSE closed");
        assert!(std::str::from_utf8(&chunk).unwrap().contains(": heartbeat"));
    }
    let weak = app.state.clone();
    app.shutdown().await;
    let ended = timeout(IO_TIMEOUT, response.chunk()).await.unwrap();
    assert!(matches!(ended, Ok(None) | Err(_)));
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn native_recorder_modes_reject_forbidden_mixed_patches_atomically() {
    let app = TestApp::new(|config| config.experimental.native_api.record_logs = false).await;
    let path = "/api/v1/runtime/settings";
    let initial = response_json(app.get(path).send().await.unwrap()).await;
    assert_eq!(initial["recording"]["logs"]["allowed"], false);
    for (mode, active) in [("on", Some(true)), ("off", Some(false)), ("auto", None)] {
        let response = app
            .client
            .patch(app.url(path))
            .bearer_auth(SECRET)
            .json(&json!({"record_flows": mode}))
            .send()
            .await
            .unwrap();
        let value = response_json(response).await;
        assert_eq!(value["recording"]["flows"]["mode"], mode);
        if let Some(active) = active {
            assert_eq!(value["recording"]["flows"]["active"], active);
        }
        let capabilities =
            response_json(app.get("/api/v1/capabilities").send().await.unwrap()).await;
        assert_eq!(capabilities["resources"]["flows"]["recording"], mode);
    }
    let before = response_json(app.get(path).send().await.unwrap()).await;
    for patch in [
        json!({"record_flows": "on", "record_logs": "on"}),
        json!({"log": {"level": "debug"}}),
    ] {
        error_response(
            app.client
                .patch(app.url(path))
                .bearer_auth(SECRET)
                .json(&patch)
                .send()
                .await
                .unwrap(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_value",
        )
        .await;
        let after = response_json(app.get(path).send().await.unwrap()).await;
        assert_eq!(after["recording"], before["recording"]);
    }
    for (patch, details) in [
        (
            json!({"record_logs": "on", "dns_log": {"max_records": 1}}),
            Value::Null,
        ),
        (json!({"record_flows": null}), Value::Null),
        (
            json!({"record_flows": true}),
            json!({"field":"record_flows","kind":"invalid_value"}),
        ),
        (
            json!({"recording": {"events": {"active": true}}}),
            json!({"field":"body","kind":"unknown_field"}),
        ),
    ] {
        error_response_details(
            app.client
                .patch(app.url(path))
                .bearer_auth(SECRET)
                .json(&patch)
                .send()
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
            details,
        )
        .await;
        let after = response_json(app.get(path).send().await.unwrap()).await;
        assert_eq!(after["recording"], before["recording"]);
    }
    app.shutdown().await;
}

#[tokio::test]
async fn native_only_successful_observation_gets_attach() {
    for poll in ["/api/v1/flows", "/api/v1/dns/log"] {
        let app = TestApp::new(|_| {}).await;
        for (method, path, status) in [
            (Method::GET, "/api/v1/runtime/settings", StatusCode::OK),
            (Method::GET, "/api/v1/capabilities", StatusCode::OK),
            (Method::HEAD, "/api/v1/flows", StatusCode::OK),
            (Method::HEAD, "/api/v1/dns/log", StatusCode::OK),
            (Method::HEAD, "/api/v1/logs", StatusCode::OK),
            (
                Method::HEAD,
                "/api/v1/events?kinds=flow.updated",
                StatusCode::OK,
            ),
            (Method::GET, "/api/v1/runtime", StatusCode::OK),
            (
                Method::GET,
                "/api/v1/flows?limit=0",
                StatusCode::BAD_REQUEST,
            ),
            (Method::GET, "/api/v1/flows?cursor=bad", StatusCode::GONE),
            (Method::GET, "/api/v1/flows/unknown", StatusCode::NOT_FOUND),
            (Method::GET, "/api/v1/dns/log?cursor=bad", StatusCode::GONE),
            (
                Method::GET,
                "/api/v1/events?kinds=invalid",
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "/api/v1/logs?level=invalid",
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = app
                .client
                .request(method, app.url(path))
                .bearer_auth(SECRET)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), status, "{path}");
            drop(response);
            let settings =
                response_json(app.get("/api/v1/runtime/settings").send().await.unwrap()).await;
            for recorder in ["flows", "logs", "dns_log", "events"] {
                assert_eq!(
                    settings["recording"][recorder]["active"], false,
                    "{path}: {recorder}"
                );
            }
        }
        let preflight = app
            .client
            .request(Method::OPTIONS, app.url(poll))
            .header("origin", app.url(""))
            .header("access-control-request-method", "GET")
            .send()
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            app.client.get(app.url(poll)).send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let settings =
            response_json(app.get("/api/v1/runtime/settings").send().await.unwrap()).await;
        assert_eq!(settings["recording"]["events"]["active"], false);
        assert_eq!(app.get(poll).send().await.unwrap().status(), StatusCode::OK);
        let settings =
            response_json(app.get("/api/v1/runtime/settings").send().await.unwrap()).await;
        for recorder in ["flows", "logs", "dns_log", "events"] {
            assert_eq!(
                settings["recording"][recorder]["active"],
                recorder == "events"
                    || (recorder == "flows" && poll == "/api/v1/flows")
                    || (recorder == "dns_log" && poll == "/api/v1/dns/log"),
                "{poll}: {recorder}"
            );
        }
        assert!(
            settings["recording"]["grace_remaining_seconds"]
                .as_u64()
                .unwrap()
                > 0
        );
        app.shutdown().await;
    }
}

#[tokio::test]
async fn native_sse_recorders_require_their_own_diagnostics() {
    for (path, flow_demand) in [
        ("/api/v1/events", false),
        (
            "/api/v1/events?kinds=runtime.updated,operation.updated,generation.changed",
            false,
        ),
        ("/api/v1/events?flow_id=%20", false),
        (
            "/api/v1/events?kinds=runtime.updated&flow_id=example",
            false,
        ),
        ("/api/v1/logs", false),
        ("/api/v1/events?kinds=flow.updated", true),
        ("/api/v1/events?kinds=flow.gap", true),
        ("/api/v1/events?flow_id=example", true),
    ] {
        let app = TestApp::new(|_| {}).await;
        let mut stream = app
            .get(path)
            .header("accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        assert_eq!(stream.status(), StatusCode::OK, "{path}");
        assert_eq!(
            next_event(&mut stream, &mut String::new()).await.0,
            "stream.ready"
        );
        let settings =
            response_json(app.get("/api/v1/runtime/settings").send().await.unwrap()).await;
        assert_eq!(
            settings["recording"]["flows"]["active"], flow_demand,
            "{path}"
        );
        assert_eq!(
            settings["recording"]["logs"]["active"],
            path == "/api/v1/logs",
            "{path}"
        );
        assert_eq!(settings["recording"]["dns_log"]["active"], false, "{path}");
        assert_eq!(settings["recording"]["events"]["active"], true, "{path}");
        // The response precedes this GET's renewal, so it observes the SSE demand.
        let flows = response_json(app.get("/api/v1/flows").send().await.unwrap()).await;
        assert_eq!(
            flows["coverage"]["userspace_tcp"],
            if flow_demand { "partial" } else { "none" },
            "{path}"
        );
        let enabled = response_json(app.get("/api/v1/flows").send().await.unwrap()).await;
        assert_eq!(enabled["coverage"]["userspace_tcp"], "partial");
        let settings =
            response_json(app.get("/api/v1/runtime/settings").send().await.unwrap()).await;
        assert_eq!(
            settings["recording"]["logs"]["active"],
            path == "/api/v1/logs",
            "{path}"
        );
        assert_eq!(settings["recording"]["dns_log"]["active"], false, "{path}");
        drop(stream);
        app.shutdown().await;
    }
}

#[tokio::test]
async fn native_rejected_flow_streams_cannot_activate_capture() {
    let app = TestApp::new(|_| {}).await;
    let path = "/api/v1/events?kinds=flow.updated";
    for (header, value, status) in [
        ("accept", "application/json", StatusCode::BAD_REQUEST),
        ("last-event-id", "bad", StatusCode::CONFLICT),
    ] {
        assert_eq!(
            app.get(path)
                .header(header, value)
                .send()
                .await
                .unwrap()
                .status(),
            status
        );
        let settings =
            response_json(app.get("/api/v1/runtime/settings").send().await.unwrap()).await;
        assert_eq!(settings["recording"]["flows"]["active"], false);
        assert_eq!(settings["recording"]["events"]["active"], false);
    }
    let mut streams = Vec::new();
    for _ in 0..16 {
        let mut stream = app
            .get("/api/v1/events?kinds=runtime.updated")
            .header("accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        assert_eq!(stream.status(), StatusCode::OK);
        next_event(&mut stream, &mut String::new()).await;
        streams.push(stream);
    }
    let full = app.get(path).send().await.unwrap();
    assert!(full.headers().contains_key("retry-after"));
    error_response(
        full,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    let settings = response_json(app.get("/api/v1/runtime/settings").send().await.unwrap()).await;
    assert_eq!(settings["recording"]["flows"]["active"], false);
    assert_eq!(settings["recording"]["events"]["active"], true);
    drop(streams);
    app.shutdown().await;
}

#[tokio::test]
async fn native_admitted_anonymous_loopback_get_attaches() {
    let app = TestApp::new(|config| {
        config.experimental.native_api.secret.clear();
        config.experimental.native_api.allow_anonymous_loopback = true;
    })
    .await;
    assert_eq!(
        app.client
            .get(app.url("/api/v1/flows"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let settings = response_json(
        app.client
            .get(app.url("/api/v1/runtime/settings"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(settings["recording"]["flows"]["active"], true);
    app.shutdown().await;
}
