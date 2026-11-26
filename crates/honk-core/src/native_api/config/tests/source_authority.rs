use super::*;

#[tokio::test]
async fn metadata_defaults_and_anonymous_never_grant_source_authority() {
    for access in [Access::Metadata, Access::Anonymous] {
        let fixture = Fixture::new(access, false).await;
        let capabilities = fixture.get("/api/v1/capabilities").await;
        assert!(capabilities["resources"]["config"].get("content").is_none());
        assert_eq!(capabilities["resources"]["config"]["writable"], false);
        assert_eq!(capabilities["resources"]["config"]["create"], false);
        assert!(
            capabilities["resources"]["config"]["max_bytes"]
                .as_u64()
                .unwrap()
                < capabilities["limits"]["max_json_body_bytes"]
                    .as_u64()
                    .unwrap()
        );
        assert_eq!(
            capabilities["resources"]["operations"]["max_replay_keys"],
            1024
        );
        assert_eq!(
            capabilities["resources"]["providers"]["create_unfetched"],
            true
        );
        // Full validation also counts dependencies read from disk, not only the request body.
        assert_eq!(
            capabilities["resources"]["config_validate"]["max_bytes"],
            crate::configuration::MAX_SOURCE_BYTES
        );
        assert_eq!(capabilities["resources"]["groups"]["config_patch"], false);
        for resource in [
            "providers",
            "geodata",
            "rules",
            "routing_trace",
            "flows",
            "connections",
        ] {
            assert_eq!(capabilities["resources"][resource]["available"], true);
        }
        for path in [
            "/api/v1/providers",
            "/api/v1/providers/inline",
            "/api/v1/geodata",
            "/api/v1/connections",
            "/api/v1/rules",
            "/api/v1/flows",
        ] {
            fixture.get(path).await;
        }
        let config = fixture.get(CONFIG).await;
        assert_eq!(config["secrets_redacted"], fixture.authenticated);
        assert!(
            config["sources"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["content"].is_string()
                    && row["writable"] == false
                    && row["read_only_reason"] == "writes_disabled")
        );
        assert!(!config.to_string().contains(SECRET));
        let main = source(&config, &fixture.originals["main.dae"]);
        assert_eq!(fixture.get(&source_path(main)).await, source_content(main));
        let before = disk(fixture.directory.path());
        let refused = error(
            fixture
                .replace(main, "routing { fallback: block }")
                .send()
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
        assert_eq!(
            refused["error"]["details"],
            json!({"reason":"writes_disabled"})
        );
        assert_eq!(disk(fixture.directory.path()), before);
        assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn admin_reads_exact_accepted_bytes_but_never_auth_source_or_unapproved_writes() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let config = fixture.get(CONFIG).await;
    assert_eq!(config["sources"].as_array().unwrap().len(), 4);
    for (name, original) in &fixture.originals {
        let row = source(&config, original);
        assert_eq!(row["path"], *name);
        assert_eq!(row["bytes"], original.len());
        assert_eq!(row["line_count"], original.lines().count());
        assert_eq!(
            row["kind"],
            if *name == "main.dae" {
                "main"
            } else {
                "include"
            }
        );
        chrono::DateTime::parse_from_rfc3339(row["loaded_at"].as_str().unwrap()).unwrap();
        let id = row["id"].as_str().unwrap();
        assert!(!id.is_empty() && !id.contains(name));
        assert_eq!(row["writable"], *name != "auth.dae");
        assert_eq!(
            row.get("read_only_reason").cloned(),
            (*name == "auth.dae").then(|| json!("listener_secret_source"))
        );
        assert_eq!(row["absolute_path"], fixture.path(name).to_str().unwrap());
        if *name == "auth.dae" {
            assert!(row["content"].as_str().unwrap().contains("enabled: true"));
            assert!(!row["content"].as_str().unwrap().contains(SECRET));
        } else {
            assert_eq!(row["content"], *original);
            assert_eq!(
                sha256(row["content"].as_str().unwrap()),
                row["content_sha256"]
            );
        }
        let response = fixture
            .request(Method::GET, &source_path(row))
            .send()
            .await
            .unwrap();
        // The auth source masks a listener secret, so its body is not what PUT replaces.
        assert_eq!(
            response
                .headers()
                .get("etag")
                .map(|value| value.to_str().unwrap().to_owned()),
            (*name != "auth.dae").then(|| etag(row)),
        );
        assert_eq!(ok(response).await, source_content(row));
    }
    assert!(!config.to_string().contains(SECRET));
    let before = disk(fixture.directory.path());
    let refused = error(
        fixture
            .replace(
                source(&config, &fixture.originals["auth.dae"]),
                "# not authorized\n",
            )
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    assert_eq!(
        refused["error"]["details"],
        json!({"reason":"listener_secret_source"})
    );
    let without_auth = fixture.originals["main.dae"].replace(" 'auth.dae'\n", "");
    let refused = error(
        fixture
            .replace(
                source(&config, &fixture.originals["main.dae"]),
                &without_auth,
            )
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    assert_eq!(
        refused["error"]["details"],
        json!({"reason":"credential_sources_changed"})
    );
    error(
        fixture
            .request(Method::GET, "/api/v1/config/sources/unknown")
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    error(
        fixture
            .request(Method::PUT, "/api/v1/config/sources/unknown")
            .header("if-match", etag(&config["sources"][0]))
            .json(&json!({"content":"# unknown\n"}))
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), before);
    std::fs::write(
        fixture.path("editable.dae"),
        "# External edit, not accepted.\n",
    )
    .unwrap();
    assert_eq!(fixture.get(CONFIG).await, config);
    assert_eq!(
        fixture
            .get(&source_path(source(
                &config,
                &fixture.originals["editable.dae"]
            )))
            .await,
        source_content(source(&config, &fixture.originals["editable.dae"]))
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn refused_source_writes_name_the_listener_secret_reason() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, files| {
        files
            .get_mut("locked.dae")
            .unwrap()
            .push_str(&format!("# {SECRET}\n"));
    })
    .await;
    let config = fixture.get(CONFIG).await;
    let row = |name: &str| {
        config["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == name)
            .unwrap()
            .clone()
    };
    let (locked, editable) = (row("locked.dae"), row("editable.dae"));
    assert_eq!(locked["read_only_reason"], "listener_secret_in_content");
    assert!(editable.get("read_only_reason").is_none());
    let before = disk(fixture.directory.path());
    let reason = |response: Response| async move {
        error(response, StatusCode::FORBIDDEN, "permission_denied").await["error"]["details"]
            ["reason"]
            .clone()
    };
    let refused = fixture
        .replace(&locked, "# replaced\n")
        .send()
        .await
        .unwrap();
    assert_eq!(reason(refused).await, "listener_secret_in_content");
    let copied = format!("# {SECRET}\n");
    let refused = fixture.replace(&editable, &copied).send().await.unwrap();
    assert_eq!(reason(refused).await, "listener_secret_in_content");
    // The same declaration again changes no listener setting, and it still carries the secret.
    let declared = &fixture.originals["auth.dae"];
    let refused = fixture.replace(&editable, declared).send().await.unwrap();
    assert_eq!(reason(refused).await, "listener_secret_source");
    assert_eq!(disk(fixture.directory.path()), before);
    let mut auth = fixture.originals["auth.dae"].clone();
    auth.push_str("# Edited on disk since the last reload.\n");
    std::fs::write(fixture.path("auth.dae"), auth).unwrap();
    let refused = fixture.replace(&editable, "# edit\n").send().await.unwrap();
    assert_eq!(reason(refused).await, "credential_sources_changed");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn writes_after_the_coordinator_stopped_are_unavailable() {
    let mut fixture = Fixture::new(Access::Admin, false).await;
    let config = fixture.get(CONFIG).await;
    let editable = source(&config, &fixture.originals["editable.dae"]).clone();
    fixture.coordinator.take().unwrap().shutdown().await;
    let refused = error(
        fixture.replace(&editable, "# edit\n").send().await.unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    assert_eq!(
        refused["error"]["details"],
        json!({"reason":"configuration_unavailable"})
    );
    fixture.shutdown().await;
}

type LogLine = (tracing::Level, HashMap<String, String>);

/// Log lines with one message, as level and field text, from the test thread's own dispatcher.
#[derive(Clone)]
struct LogLines(&'static str, Arc<parking_lot::Mutex<Vec<LogLine>>>);

impl LogLines {
    fn new(message: &'static str) -> Self {
        Self(message, Arc::default())
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogLines {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Fields(HashMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().into(), value.into());
            }
        }
        let mut fields = Fields(HashMap::new());
        event.record(&mut fields);
        if fields.0.get("message").map(String::as_str) == Some(self.0) {
            self.1.lock().push((*event.metadata().level(), fields.0));
        }
    }
}

#[tokio::test]
async fn a_refused_write_logs_its_reason_on_the_request_line() {
    use tracing_subscriber::layer::SubscriberExt as _;
    // Callsite interest is process-wide; other tests' dispatchers would race this one.
    if crate::native_api::logs::tests::run_isolated(
        "native_api::config::tests::source_authority::a_refused_write_logs_its_reason_on_the_request_line",
    ) {
        return;
    }
    let lines = LogLines::new("native HTTP request");
    let _dispatch =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(lines.clone()));
    let fixture = Fixture::new(Access::Metadata, false).await;
    let config = fixture.get(CONFIG).await;
    let main = source(&config, &fixture.originals["main.dae"]);
    error(
        fixture.replace(main, "# edit\n").send().await.unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    error(
        fixture
            .request(Method::GET, "/api/v1/config/sources/unknown")
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    fixture.shutdown().await;
    let lines = lines.1.lock();
    let refused: Vec<_> = lines
        .iter()
        .filter(|(_, fields)| fields["method"] == "PUT")
        .collect();
    assert_eq!(refused.len(), 1, "{lines:?}");
    let (level, fields) = refused[0];
    assert_eq!(*level, tracing::Level::INFO);
    assert_eq!(fields["reason"], "writes_disabled");
    assert_eq!(fields["status"], "403");
    assert!(!fields.values().any(|value| value.contains("main.dae")));
    let (level, fields) = lines
        .iter()
        .find(|(_, fields)| fields["status"] == "404")
        .unwrap();
    assert_eq!(*level, tracing::Level::DEBUG);
    assert!(!fields.contains_key("reason"));
}

#[tokio::test]
async fn a_listener_secret_in_source_text_warns_once_per_accepted_reload() {
    use tracing_subscriber::layer::SubscriberExt as _;
    if crate::native_api::logs::tests::run_isolated(
        "native_api::config::tests::source_authority::a_listener_secret_in_source_text_warns_once_per_accepted_reload",
    ) {
        return;
    }
    let lines = LogLines::new(
        "configuration source is read-only because its text contains a listener secret value",
    );
    let _dispatch =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(lines.clone()));
    // A glob loads the file so that only its own text and path hold the Clash secret.
    let fixture = Fixture::new_custom(Access::Admin, false, |directory, files| {
        std::fs::create_dir(directory.join("extra")).unwrap();
        files
            .get_mut("auth.dae")
            .unwrap()
            .push_str("experimental { clash_api { secret: 'clash-listener-token' } }\n");
        files
            .get_mut("main.dae")
            .unwrap()
            .push_str("include { 'extra/*.dae' }\n");
        files.insert(
            "extra/clash-listener-token.dae",
            "# clash-listener-token copied here\n".into(),
        );
    })
    .await;
    let config = fixture.get(CONFIG).await;
    let collided = source(
        &config,
        &fixture.originals["extra/clash-listener-token.dae"],
    );
    assert_eq!(collided["read_only_reason"], "listener_secret_in_content");
    let auth = source(&config, &fixture.originals["auth.dae"]);
    let expected = vec![
        (
            auth["id"].as_str().unwrap().to_owned(),
            "auth.dae".to_owned(),
        ),
        (
            collided["id"].as_str().unwrap().to_owned(),
            "extra/<redacted>.dae".to_owned(),
        ),
    ];
    let warnings = || {
        lines
            .1
            .lock()
            .iter()
            .map(|(level, fields)| {
                assert_eq!(*level, tracing::Level::WARN);
                (fields["source_id"].clone(), fields["path"].clone())
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(warnings(), expected);
    // A reload whose sources lost the acceptance race reports the snapshot already reported.
    fixture.service.warn_secret_collisions();
    assert_eq!(warnings().len(), 2);
    let reload = || async {
        let operation = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
        fixture.terminal(&operation).await
    };
    // An unchanged configuration is accepted again as a no-op.
    assert_eq!(reload().await["status"], "succeeded");
    assert_eq!(warnings().len(), 4);
    fixture
        .reject_reloads
        .store(ReloadBehavior::Reject as u8, Ordering::SeqCst);
    assert_eq!(reload().await["error"]["code"], "reload_rejected");
    assert_eq!(warnings().len(), 4);
    fixture
        .reject_reloads
        .store(ReloadBehavior::Degraded as u8, Ordering::SeqCst);
    let edited = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    std::fs::write(fixture.path("main.dae"), edited).unwrap();
    assert_eq!(reload().await["error"]["code"], "reload_degraded");
    assert_eq!(warnings(), vec![expected; 3].concat());
    fixture.shutdown().await;
}

#[tokio::test]
async fn mixed_listener_secrets_mask_values_and_keep_ordinary_content() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, files| {
        let auth = files.get_mut("auth.dae").unwrap();
        *auth = auth.replace(&format!("secret: '{SECRET}'"),
            &format!("secret: 'overridden-listener-token'\n secret: '{SECRET}'"));
        auth.push_str("experimental { clash_api { secret: 'old-clash-token'\n secret: 'clash-listener-token' } }\n# old-clash-token copied here\n");
        files.get_mut("main.dae").unwrap().push_str("include { 'clash-listener-token.dae' }\n");
        files.insert("clash-listener-token.dae", "# Ordinary included content.\n".into());
        files.get_mut("locked.dae").unwrap().push_str(
            "# overridden-listener-token copied across sources\nnode { ordinary: 'socks5://user:ordinary-password@192.0.2.1:1080' }\n");
    }).await;
    let config = fixture.get(CONFIG).await;
    assert_eq!(config["secrets_redacted"], true);
    let encoded = config.to_string();
    for secret in [
        SECRET,
        "overridden-listener-token",
        "old-clash-token",
        "clash-listener-token",
    ] {
        assert!(!encoded.contains(secret), "listener value leaked");
    }
    let export = fixture
        .request(Method::GET, "/api/v1/x-honk/config/export")
        .send()
        .await
        .unwrap();
    assert_eq!(export.status(), StatusCode::OK);
    let export = export.text().await.unwrap();
    assert!(export.contains("# <redacted> copied across sources"));
    for secret in [
        SECRET,
        "overridden-listener-token",
        "old-clash-token",
        "clash-listener-token",
    ] {
        assert!(!export.contains(secret), "listener value exported");
    }
    let path_only = source(&config, &fixture.originals["clash-listener-token.dae"]);
    assert_eq!(path_only["content"], "# Ordinary included content.\n");
    assert_eq!(path_only["path"], "<redacted>.dae");
    let auth = source(&config, &fixture.originals["auth.dae"]);
    assert_eq!(auth["writable"], false);
    assert_eq!(
        auth["content"].as_str().unwrap().lines().count(),
        fixture.originals["auth.dae"].lines().count()
    );
    let mixed = source(&config, &fixture.originals["locked.dae"]);
    assert!(
        mixed["content"]
            .as_str()
            .unwrap()
            .contains("socks5://user:ordinary-password@192.0.2.1:1080")
    );
    assert_eq!(mixed["writable"], false);
    fixture.shutdown().await;
}

#[tokio::test]
async fn redaction_flag_is_unknown_in_config_write_bodies() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let config = fixture.get(CONFIG).await;
    let row = source(&config, &fixture.originals["locked.dae"]);
    assert_eq!(row["content"], fixture.originals["locked.dae"]);
    assert_eq!(row["writable"], true);
    let candidate = "# accepted include without an allowlist\n";
    error(
        fixture
            .replace(row, candidate)
            .json(&json!({"content": candidate, "secrets_redacted": false}))
            .send()
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    error(
        fixture
            .replace(row, &"#".repeat(super::super::MAX_CONTENT_BYTES + 1))
            .send()
            .await
            .unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_too_large",
    )
    .await;
    let admission = accepted(fixture.replace(row, candidate).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&admission).await["status"], "succeeded");
    for body in [
        json!({"mode":"syntax", "secrets_redacted":true,
            "sources":[{"content":"routing { fallback: direct }"}]}),
        json!({"mode":"syntax",
            "sources":[{"content":"routing { fallback: direct }", "secrets_redacted":false}]}),
    ] {
        let response = fixture
            .request(Method::POST, "/api/v1/config/validate")
            .json(&body)
            .send()
            .await
            .unwrap();
        error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
    }
    fixture.shutdown().await;
}

#[tokio::test]
async fn connection_projection_masks_listener_values_without_losing_flow_references() {
    use crate::connection_tracker::ConnectionEntry;
    use std::sync::atomic::AtomicU64;

    let fixture = Fixture::new(Access::Metadata, false).await;
    let state = fixture.state.upgrade().unwrap();
    state.observation.attach_for_test();
    let flow = state
        .observation
        .core
        .flows
        .begin(
            crate::observe::vocab::Network::Tcp,
            "192.0.2.1:31000".parse().unwrap(),
            "198.51.100.1:443".parse().unwrap(),
        )
        .unwrap();
    let rule_id = format!("{}:1:rule:0", state.instance_id);
    flow.routed(
        "group/name@host",
        Some(&rule_id),
        Some(&format!("pname(\"/usr/bin/{SECRET}\")")),
        crate::observe::vocab::RoutingSource::Evaluation,
    );
    state.tracker.register(ConnectionEntry {
        id: uuid::uuid!("00000000-0000-0000-0000-000000000013"),
        source: "192.0.2.1:31000".parse().unwrap(),
        destination: "198.51.100.1:443".parse().unwrap(),
        proxy: "leaf".into(),
        routed_outbound: Some("group/name@host".into()),
        native_flow_id: Some(flow.id().into()),
        rule: String::new(),
        rule_payload: String::new(),
        chains: vec![],
        upload: Arc::new(AtomicU64::new(0)),
        download: Arc::new(AtomicU64::new(0)),
        start_time: Instant::now(),
        domain: None,
        network: "tcp",
        process: Some("/usr/bin/user@host".into()),
        process_path: None,
    });
    let value = fixture.get("/api/v1/connections?detail=full").await;
    let row = &value["tcp"][0];
    assert_eq!(row["id"], "00000000-0000-0000-0000-000000000013");
    assert_eq!(row["flow_id"], flow.id());
    assert_eq!(row["rule_id"], rule_id);
    assert_eq!(row["outbound"], "group/name@host");
    assert_eq!(row["pname"], "/usr/bin/user@host");
    assert_eq!(row["rule_expression"], "pname(\"/usr/bin/<redacted>\")");
    assert!(!value.to_string().contains(SECRET));
    drop(state);
    fixture.shutdown().await;
}

#[test]
fn every_secret_bearing_accepted_source_warns_even_when_writes_are_disabled() {
    use tracing_subscriber::layer::SubscriberExt as _;
    if crate::native_api::logs::tests::run_isolated(
        "native_api::config::tests::source_authority::every_secret_bearing_accepted_source_warns_even_when_writes_are_disabled",
    ) {
        return;
    }
    let lines = LogLines::new(
        "configuration source is read-only because its text contains a listener secret value",
    );
    let _dispatch =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(lines.clone()));
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("extra")).unwrap();
    let entry = directory.path().join("main.dae");
    std::fs::write(&entry, "include { 'auth.dae'\n 'extra/*.dae' }\n").unwrap();
    std::fs::write(
        directory.path().join("auth.dae"),
        format!("experimental {{ native_api {{ secret: '{SECRET}' }} }}\n"),
    )
    .unwrap();
    std::fs::write(
        directory.path().join(format!("extra/{SECRET}.dae")),
        format!("# {SECRET}\n"),
    )
    .unwrap();
    let loaded = Config::from_dae_file_with_sources(
        &entry,
        &HashMap::new(),
        SourceLimits::DEFAULT,
        &mut Vec::new(),
    )
    .unwrap();
    let owner = crate::native_api::observation::NativeObservation::new(&loaded.config);
    let service = &owner.configuration;
    let update = SourceUpdate {
        sources: loaded.sources,
        dependencies: vec![],
        geo_sources: None,
    };
    service
        .sources
        .accept(service.sources.prepare_accept(&update), 1);
    service.warn_secret_collisions();
    service.warn_secret_collisions();
    let accepted = service.sources.accepted.read().clone().unwrap();
    let expected = [
        (
            accepted.ids[&directory.path().join("auth.dae")].clone(),
            "auth.dae",
        ),
        (
            accepted.ids[&directory.path().join(format!("extra/{SECRET}.dae"))].clone(),
            "extra/<redacted>.dae",
        ),
    ];
    {
        let captured = lines.1.lock();
        assert_eq!(captured.len(), 2);
        for ((level, fields), (id, path)) in captured.iter().zip(&expected) {
            assert_eq!(*level, tracing::Level::WARN);
            assert_eq!(&fields["source_id"], id);
            assert_eq!(&fields["path"], path);
            assert!(!fields.values().any(|value| value.contains(SECRET)));
        }
    }
    service.sources.generation_committed("next-generation", 2);
    service.warn_secret_collisions();
    service.warn_secret_collisions();
    assert_eq!(lines.1.lock().len(), 4);
}
