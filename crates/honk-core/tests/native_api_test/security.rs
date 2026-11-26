use super::*;

#[tokio::test]
async fn authentication_precedes_capability_and_query_validation() {
    let app = TestApp::new(|config| {
        config.experimental.native_api.allow_anonymous_loopback = true;
    })
    .await;
    // Discovery tells a client how to authenticate, so it answers without a credential.
    let discovery = app.client.get(app.url("/api")).send().await.unwrap();
    assert_eq!(discovery.status(), StatusCode::OK);
    for (method, path) in [
        (Method::GET, "/api/v1/version"),
        (Method::GET, "/api/v1/capabilities"),
        (Method::GET, "/api/v1/config"),
        (Method::GET, "/api/v1/missing"),
        (Method::GET, "/api/v1/runtime?unknown=x"),
        (Method::GET, "/api/v1/x-honk/runtime/mode?unknown=x"),
        (Method::GET, "/api/v1/x-honk/geodata/query?action=list"),
        (Method::POST, "/api/v1/runtime"),
    ] {
        error_response(
            app.client
                .request(method, app.url(path))
                .send()
                .await
                .unwrap(),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    for authorization in [
        "Bearer wrong",
        "Basic native-test-only-secret",
        "Bearer",
        "Bearer ",
        "Bearer native-test-only-secret,other",
    ] {
        error_response(
            app.client
                .get(app.url("/api"))
                .header("authorization", authorization)
                .send()
                .await
                .unwrap(),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    error_response(
        app.get("/api")
            .header("authorization", "Bearer wrong")
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    for query in [
        "token=native-test-only-secret",
        "%74oken=native-test-only-secret",
        "access_token=native-test-only-secret",
    ] {
        error_response(
            app.get(&format!("/api?{query}")).send().await.unwrap(),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    response_json(app.get("/api").send().await.unwrap()).await;
    app.shutdown().await;
}

#[tokio::test]
async fn discovery_withholds_detail_from_callers_without_a_credential() {
    let app = TestApp::new(|_| {}).await;
    // Without a credential a caller learns only how to sign in.
    let public = response_json(app.client.get(app.url("/api")).send().await.unwrap()).await;
    assert_eq!(
        public,
        serde_json::json!({
            "name": "daeuniverse/native",
            "api_major": 1,
            "links": {"auth_setup": null, "auth_login": null},
            "auth": {"mode": "token", "setup_required": false},
        })
    );
    // The contract serves discovery at one path only.
    let alias = app.get("/api/v1/discovery").send().await.unwrap();
    assert_eq!(alias.status(), StatusCode::NOT_FOUND);
    let full = response_json(app.get("/api").send().await.unwrap()).await;
    assert_eq!(full["name"], "daeuniverse/native");
    assert_eq!(full["status"], "draft");
    assert_eq!(
        full["links"]["x-honk"],
        serde_json::json!({
            "config_export": "/api/v1/x-honk/config/export",
            "config_import": "/api/v1/x-honk/config/import",
            "config_revisions": "/api/v1/x-honk/config/revisions",
            "geodata_query": "/api/v1/x-honk/geodata/query",
        })
    );
    assert!(full["links"].get("config_export").is_none());
    let resources =
        response_json(app.get("/api/v1/capabilities").send().await.unwrap()).await["resources"]
            .take();
    for key in [
        "config_export",
        "config_import",
        "config_revisions",
        "geodata_query",
        "runtime_mode",
    ] {
        assert!(resources.get(key).is_none(), "{key}");
        assert!(resources["x-honk"][key]["available"].is_boolean(), "{key}");
    }
    assert_eq!(resources["x-honk"]["geodata_query"]["available"], false);
    error_response(
        app.get("/api/v1/x-honk/geodata/query?action=list")
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    assert!(resources["config"].get("store").is_none());
    assert_eq!(resources["config"]["x-honk"]["store"], "file");
    let version = response_json(app.get("/api/v1/version").send().await.unwrap()).await;
    assert_eq!(version["api"]["name"], "daeuniverse/native");
    assert_eq!(version["engine"]["name"], "honk");
    assert_eq!(full["links"]["version"], "/api/v1/version");
    assert_eq!(
        full["links"]["operations"],
        "/api/v1/operations/{operation_id}"
    );
    assert_eq!(full["auth"]["anonymous_loopback"], false);
    app.shutdown().await;
}

#[tokio::test]
async fn anonymous_loopback_does_not_forgive_credentials_or_cross_site_requests() {
    let app = TestApp::new(|config| {
        config.experimental.native_api.secret.clear();
        config.experimental.native_api.allow_anonymous_loopback = true;
    })
    .await;
    // A secretless loopback listener admits the caller, so it gets the full view.
    let full = response_json(app.client.get(app.url("/api")).send().await.unwrap()).await;
    assert_eq!(full["links"]["version"], "/api/v1/version");
    assert_eq!(full["auth"]["anonymous_loopback"], true);
    for authorization in ["Bearer wrong", "Basic value", "Bearer"] {
        error_response(
            app.client
                .get(app.url("/api"))
                .header("authorization", authorization)
                .send()
                .await
                .unwrap(),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    error_response(
        app.client
            .get(app.url("/api?token=ignored"))
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    error_response(
        app.client
            .get(app.url("/api"))
            .header("sec-fetch-site", "cross-site")
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    app.shutdown().await;
}

#[tokio::test]
async fn host_origin_and_proxy_authorities_are_not_inferred_from_forwarded_headers() {
    let app = TestApp::new(|config| {
        config.experimental.native_api.allowed_hosts =
            vec!["Panel.Example".into(), "panel.example:443".into()];
        config.experimental.native_api.allow_origins = vec!["https://panel.example".into()];
    })
    .await;
    for host in [
        format!("LOCALHOST:{}", app.addr.port()),
        format!("[::1]:{}", app.addr.port()),
        "PANEL.EXAMPLE".into(),
        "panel.example:80".into(),
        "panel.example:443".into(),
    ] {
        let response = app
            .get("/api")
            .header("host", host)
            .header("origin", "https://PANEL.EXAMPLE:443")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://PANEL.EXAMPLE:443"
        );
        response_json(response).await;
    }
    response_json(
        app.get("/api")
            .header("origin", format!("http://localhost:{}", app.addr.port()))
            .send()
            .await
            .unwrap(),
    )
    .await;
    for host in [
        "attacker.example",
        "panel.example:81",
        "user@panel.example",
        "::1",
    ] {
        error_response(
            app.get("/api")
                .header("host", host)
                .header("x-forwarded-host", app.addr.to_string())
                .send()
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
    }
    for origin in [
        "null",
        "http://panel.example",
        "https://panel.example:444",
        "https://panel.example/path",
        "https://user@panel.example",
        "https://attacker.example",
    ] {
        error_response(
            app.get("/api")
                .header("host", "panel.example")
                .header("origin", origin)
                .header("x-forwarded-proto", "https")
                .send()
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
    }
    raw_error(
        raw_request(
            &app,
            "/api",
            &format!("Authorization: Bearer {SECRET}\r\nHost: attacker.example\r\n"),
            b"",
        )
        .await,
        403,
        "permission_denied",
    );
    raw_error_details(
        raw_request(
            &app,
            &app.url("/api"),
            &format!("Authorization: Bearer {SECRET}\r\n"),
            b"",
        )
        .await,
        400,
        "invalid_request",
        json!({"field":"target","kind":"not_origin_form"}),
    );
    app.shutdown().await;
}

#[tokio::test]
async fn wildcard_bind_accepts_its_own_ip_literal_authorities_but_no_names() {
    let app = TestApp::bound("0.0.0.0:0", |_| {}).await;
    let port = app.addr.port();
    for host in [
        format!("127.0.0.1:{port}"),
        format!("192.0.2.7:{port}"),
        format!("[2001:db8::7]:{port}"),
        format!("localhost:{port}"),
    ] {
        response_json(app.get("/api").header("host", &host).send().await.unwrap()).await;
        // The listener's own plain-HTTP origin follows its Host; the UI it hosts posts with it.
        let response = app
            .get("/api")
            .header("host", &host)
            .header("origin", format!("http://{host}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            format!("http://{host}")
        );
        response_json(response).await;
    }
    for host in [
        format!("192.0.2.7:{}", port.wrapping_add(1)),
        "192.0.2.7".to_string(),
        format!("panel.example:{port}"),
    ] {
        error_response(
            app.get("/api").header("host", &host).send().await.unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
    }
    // Only plain HTTP is the listener's own scheme; a TLS proxy still declares its origin.
    // A page on another address at the same port is another site, not the listener.
    for (host, origin) in [
        (
            format!("192.0.2.7:{port}"),
            format!("https://192.0.2.7:{port}"),
        ),
        (
            format!("192.0.2.7:{port}"),
            format!("http://198.51.100.10:{port}"),
        ),
        (
            format!("127.0.0.1:{port}"),
            format!("http://localhost:{port}"),
        ),
    ] {
        error_response(
            app.get("/api")
                .header("host", host)
                .header("origin", origin)
                .send()
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
    }
    app.shutdown().await;
}

#[tokio::test]
async fn preflight_uses_route_methods_but_never_grants_authorization() {
    let app = TestApp::new(|_| {}).await;
    let origin = format!("http://localhost:{}", app.addr.port());
    let preflight = |path: &str, method: &str| {
        app.client
            .request(Method::OPTIONS, app.url(path))
            .header("origin", &origin)
            .header("access-control-request-method", method)
            .header(
                "access-control-request-headers",
                "authorization, Content-Type",
            )
    };
    for (path, method) in [
        ("/api", "GET"),
        ("/api", "HEAD"),
        ("/api/v1/connections", "DELETE"),
        ("/api/v1/providers/raw%2Fid/refresh", "POST"),
        ("/api/v1/dns/cache/flush", "POST"),
        ("/api/v1/x-honk/geodata/query", "GET"),
        ("/api/v1/x-honk/runtime/mode", "PUT"),
    ] {
        let response = preflight(path, method).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        api_headers(&response);
        assert_eq!(response.headers()["access-control-allow-origin"], origin);
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-credentials")
        );
        assert!(
            response.headers()["access-control-allow-methods"]
                .to_str()
                .unwrap()
                .split(", ")
                .any(|value| value == method)
        );
    }
    // A permitted preflight still grants nothing: the protected request after it needs its bearer.
    error_response(
        app.client
            .get(app.url("/api/v1/version"))
            .header("origin", &origin)
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    for (path, method) in [
        ("/api", "PUT"),
        ("/api/v1/missing", "GET"),
        ("/api/v1/dns/cache/flush", "DELETE"),
        ("/api/v1/dns/cache/%66lush", "POST"),
    ] {
        error_response(
            preflight(path, method).send().await.unwrap(),
            StatusCode::NOT_FOUND,
            "resource_not_found",
        )
        .await;
    }
    error_response(
        preflight("/api", "GET")
            .header("access-control-request-headers", "x-not-allowed")
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    error_response(
        preflight("/api", "GET")
            .header("origin", "https://attacker.example")
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    let options = || app.client.request(Method::OPTIONS, app.url("/api"));
    for (request, details) in [
        (
            options().header("access-control-request-method", "GET"),
            json!({"header":"origin","kind":"missing"}),
        ),
        (
            options().header("origin", &origin),
            json!({"header":"access-control-request-method","kind":"missing"}),
        ),
        (
            preflight("/api", "GET").header("access-control-request-method", "POST"),
            json!({"header":"access-control-request-method","kind":"duplicate"}),
        ),
        (
            options().header("origin", &origin).header(
                "access-control-request-method",
                reqwest::header::HeaderValue::from_bytes(b"PRIVATE\xff").unwrap(),
            ),
            json!({"header":"access-control-request-method","kind":"not_text"}),
        ),
        (
            preflight("/api", "GET")
                .header("access-control-request-headers", "authorization,,PRIVATE"),
            json!({"header":"access-control-request-headers","kind":"empty_name"}),
        ),
    ] {
        error_response_details(
            request.send().await.unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
            details,
        )
        .await;
    }
    app.shutdown().await;
}

#[cfg(feature = "clash-api")]
#[tokio::test]
async fn native_and_clash_tokens_do_not_cross_authorize() {
    use honk_core::clash_api::{self, ClashState};
    use honk_core::mode::ModeState;

    let mut app = TestApp::new(|config| {
        config.experimental.clash_api.secret = "clash-test-only-secret".into();
    })
    .await;
    let mode = Arc::new(parking_lot::RwLock::new(ModeState::new("Rule", "direct")));
    app.control.set_mode_state(mode.clone());
    app.control.start_datapath_flags_coordinator().unwrap();
    let state = Arc::new(ClashState {
        config: app.control.config_handle(),
        diagnostics: app.control.diagnostics_handle(),
        stats: app.control.stats_handle(),
        alive_set: app.control.alive_set(),
        group_manager: app.control.group_manager(),
        cache_db: None,
        connection_tracker: app.control.connection_tracker(),
        proxy_registry: app.control.proxy_registry(),
        runtime_registry: app.control.runtime_registry(),
        mode_state: mode,
        datapath_flags: app.control.datapath_flags_handle().unwrap(),
        control: Some(app.control.control_client()),
        ui_download: app.control.ui_download_handle(),
        secret: "clash-test-only-secret".into(),
        connection_pool: app.control.connection_pool(),
        external_ui: String::new(),
        router: app.control.traffic_router(),
        log_handle: clash_api::logs::layer::<tracing_subscriber::Registry>().1,
        dns_service: app.control.dns_service(),
        stream_samplers: Arc::new(clash_api::StreamSamplers::new()),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let clash_url = format!("http://{}/version", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, clash_api::router(state))
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    assert_eq!(
        app.client
            .get(&clash_url)
            .bearer_auth("clash-test-only-secret")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.client
            .get(&clash_url)
            .bearer_auth(SECRET)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    error_response(
        app.client
            .get(app.url("/api"))
            .bearer_auth("clash-test-only-secret")
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    response_json(app.get("/api").send().await.unwrap()).await;
    stop.send(()).unwrap();
    timeout(IO_TIMEOUT, server).await.unwrap().unwrap();
    app.shutdown().await;
}
