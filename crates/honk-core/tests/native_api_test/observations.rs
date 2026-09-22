use super::*;

async fn next_event(response: &mut Response, pending: &mut String) -> (String, String, Value) {
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
            return (
                kind,
                field("id:"),
                serde_json::from_str(&field("data:")).unwrap(),
            );
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
async fn native_events_replay_actual_commits_before_ready_and_reject_changed_filters() {
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
    let replay = next_event(&mut resumed, &mut pending).await;
    assert_eq!(replay.0, "generation.changed");
    assert_eq!(replay.1, committed_cursor);
    assert_eq!(replay.2, committed);
    assert_eq!(
        next_event(&mut resumed, &mut pending).await.0,
        "stream.ready"
    );
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
    let client = Client::builder().no_proxy().build().unwrap();
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
    for mode in [json!(true), json!(false), json!("auto")] {
        let response = app
            .client
            .patch(app.url(path))
            .bearer_auth(SECRET)
            .json(&json!({"record_flows": mode}))
            .send()
            .await
            .unwrap();
        let value = response_json(response).await;
        let expected = match mode.as_bool() {
            Some(true) => "on",
            Some(false) => "off",
            None => "auto",
        };
        assert_eq!(value["recording"]["flows"]["mode"], expected);
        if let Some(active) = mode.as_bool() {
            assert_eq!(value["recording"]["flows"]["active"], active);
        }
    }
    let before = response_json(app.get(path).send().await.unwrap()).await;
    for patch in [
        json!({"record_flows": true, "record_logs": true}),
        json!({"record_flows": null}),
        json!({"record_flows": "on"}),
        json!({"recording": {"events": {"active": true}}}),
    ] {
        error_response(
            app.client
                .patch(app.url(path))
                .bearer_auth(SECRET)
                .json(&patch)
                .send()
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
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
                Method::GET,
                "/api/v1/flows?limit=0",
                StatusCode::BAD_REQUEST,
            ),
            (Method::GET, "/api/v1/flows?cursor=bad", StatusCode::GONE),
            (Method::GET, "/api/v1/flows/unknown", StatusCode::NOT_FOUND),
            (
                Method::GET,
                "/api/v1/dns/log?cursor=bad",
                StatusCode::BAD_REQUEST,
            ),
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
                recorder != "flows" || poll == "/api/v1/flows",
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
async fn native_sse_flow_demand_requires_explicit_diagnostics() {
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
        for recorder in ["logs", "dns_log", "events"] {
            assert_eq!(settings["recording"][recorder]["active"], true, "{path}");
        }
        // The response precedes this GET's renewal, so it observes the SSE demand.
        let flows = response_json(app.get("/api/v1/flows").send().await.unwrap()).await;
        assert_eq!(
            flows["coverage"]["userspace_tcp"],
            if flow_demand { "partial" } else { "none" },
            "{path}"
        );
        let enabled = response_json(app.get("/api/v1/flows").send().await.unwrap()).await;
        assert_eq!(enabled["coverage"]["userspace_tcp"], "partial");
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
    assert_eq!(
        app.get(path).send().await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
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
