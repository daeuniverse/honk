//! `--store db`: writes are recorded as revisions and never need the imported tree.

use super::*;

/// `(number, parent, principal, origin)` of every revision, oldest first.
fn revisions(fixture: &Fixture) -> Vec<(i64, Option<i64>, String, String)> {
    let path = fixture.path("state/state/honk.db");
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = connection
        .prepare("SELECT number, parent, principal, origin FROM revision ORDER BY number")
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[tokio::test]
async fn main_source_write_records_a_revision_after_the_tree_is_deleted() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    let parsed = Config::from_dae_file_with_sources(
        &fixture.path("etc/main.dae"),
        &HashMap::new(),
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap()
    .config;
    std::fs::remove_dir_all(fixture.path("etc")).unwrap();
    assert_eq!(
        store.head(),
        Ok(Some(1)),
        "startup import records revision 1"
    );
    let stored = store.load(&HashMap::new(), &mut Vec::new()).unwrap();
    assert_eq!(stored.config, parsed);

    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let operation = accepted(fixture.replace(main, &candidate).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(store.head(), Ok(Some(2)));
    assert_eq!(
        revisions(&fixture),
        [
            (1, None, "startup".into(), "import".into()),
            (2, Some(1), "control".into(), "write".into()),
        ]
    );
    let after = fixture.get(CONFIG).await;
    assert_eq!(source(&after, &candidate)["id"], main["id"]);
    assert!(!fixture.path("etc").exists());
    fixture.shutdown().await;
}

#[tokio::test]
async fn rejected_reload_leaves_the_db_head_alone() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    fixture
        .reject_reloads
        .store(ReloadBehavior::Reject as u8, Ordering::SeqCst);
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    assert_eq!(main["writable"], true);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let operation = accepted(fixture.replace(main, &candidate).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(terminal["error"]["code"], "reload_rejected");
    assert_eq!(terminal["error"]["details"]["written"], false);
    assert_eq!(store.head(), Ok(Some(1)));
    assert_eq!(revisions(&fixture).len(), 1);
    let after = fixture.get(CONFIG).await;
    assert_eq!(after["revision"], before["revision"]);
    assert_eq!(after["x-honk"]["store"]["recorded"], true);
    fixture.shutdown().await;
}

#[tokio::test]
async fn restart_only_changes_are_refused_before_recording() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate =
        fixture.originals["main.dae"].replace("dial_mode: ip", "dial_mode: ip\n log_level: debug");
    let failure = error(
        fixture.replace(main, &candidate).send().await.unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    let rows = failure["error"]["details"]["diagnostics"]
        .as_array()
        .unwrap();
    assert!(rows.iter().any(|row| row["code"] == "restart-required"
        && row["level"] == "error"
        && row["source_id"] == main["id"]
        && row["message"] == "Changing global.log_level requires restarting honk"));

    std::fs::write(fixture.path("etc/main.dae"), &candidate).unwrap();
    let response = fixture
        .request(Method::POST, "/api/v1/x-honk/config/import")
        .header("idempotency-key", "restart")
        .json(&json!({"replace":true}))
        .send()
        .await
        .unwrap();
    let failure = error(
        response,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    assert!(
        failure["error"]["details"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["code"] == "restart-required")
    );
    assert_eq!(store.head(), Ok(Some(1)));
    assert_eq!(revisions(&fixture).len(), 1);
    assert_eq!(fixture.get(CONFIG).await["revision"], before["revision"]);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn listener_settings_data_dir_and_secrets_stay_read_only() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    let config = fixture.get(CONFIG).await;
    let main = source(&config, &fixture.originals["main.dae"]);
    let auth = config["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["path"] == "auth.dae")
        .unwrap();
    let stored_auth = store
        .load(&HashMap::new(), &mut Vec::new())
        .unwrap()
        .sources
        .into_iter()
        .find(|source| source.path.ends_with("auth.dae"))
        .unwrap()
        .content;
    assert!(!stored_auth.contains(SECRET));
    let moved = fixture.originals["main.dae"].replace("/state'", "/moved'");
    assert_ne!(moved, fixture.originals["main.dae"]);
    for (target, content) in [
        (main, moved),
        (
            auth,
            stored_auth.replace("enabled: true", "enabled: true\n record_logs: false"),
        ),
        (
            auth,
            stored_auth.replace("enabled: true", "enabled: true\n secret: 'another-token'"),
        ),
    ] {
        let response = fixture.replace(target, &content).send().await.unwrap();
        error(response, StatusCode::FORBIDDEN, "permission_denied").await;
    }
    assert_eq!(store.head(), Ok(Some(1)));
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn import_from_another_entry_than_the_recorded_tree_is_refused() {
    let fixture = Fixture::new_db_custom(Access::Admin, |root, files| {
        let old = root.join("old");
        std::fs::create_dir_all(&old).unwrap();
        for (name, text) in files.iter() {
            let path = old.join(name);
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let state = root.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let entry = old.join("main.dae").canonicalize().unwrap();
        DatabaseStartup::open(&entry, &state, &mut Vec::new())
            .unwrap()
            .record()
            .unwrap();
    })
    .await;
    let response = fixture
        .request(Method::POST, "/api/v1/x-honk/config/import")
        .header("idempotency-key", "moved")
        .json(&json!({"replace":true}))
        .send()
        .await
        .unwrap();
    let refused = error(response, StatusCode::FORBIDDEN, "permission_denied").await;
    assert_eq!(
        refused["error"]["details"],
        json!({"reason":"import_entry_changed"})
    );
    fixture.shutdown().await;
}

async fn operation(fixture: &Fixture, path: &str, key: &str, body: Value) -> Value {
    let response = fixture
        .request(Method::POST, path)
        .header("idempotency-key", key)
        .json(&body)
        .send()
        .await
        .unwrap();
    let operation = accepted(response).await;
    fixture.terminal(&operation).await
}

#[tokio::test]
async fn file_mode_has_export_but_no_import_or_revisions() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let response = fixture
        .request(Method::POST, "/api/v1/x-honk/config/import")
        .header("idempotency-key", "import")
        .json(&json!({"replace":true}))
        .send()
        .await
        .unwrap();
    error(response, StatusCode::NOT_FOUND, "capability_not_supported").await;
    let response = fixture
        .request(Method::GET, "/api/v1/x-honk/config/revisions")
        .send()
        .await
        .unwrap();
    error(response, StatusCode::NOT_FOUND, "capability_not_supported").await;
    let response = fixture
        .request(Method::POST, "/api/v1/x-honk/config/revisions/1/activate")
        .send()
        .await
        .unwrap();
    error(response, StatusCode::NOT_FOUND, "capability_not_supported").await;
    let response = fixture
        .request(Method::GET, "/api/v1/x-honk/config/export")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"honk.dae\""
    );
    let body = response.text().await.unwrap();
    assert!(body.starts_with("# listener secrets omitted\n"));
    assert!(!body.contains(SECRET));
    let config = fixture.get(CONFIG).await;
    assert_eq!(config["x-honk"]["store"]["kind"], "file");
    assert!(config["sources"][0]["absolute_path"].is_string());
    let capabilities = fixture.get("/api/v1/capabilities").await;
    assert_eq!(
        capabilities["resources"]["config"]["x-honk"]["store"],
        "file"
    );
    assert_eq!(
        capabilities["resources"]["x-honk"]["config_import"]["available"],
        false
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn import_preserves_subscription_declarations() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let edited = format!(
        "{}\nsubscription {{ feed: 'http://127.0.0.1:9/feed' }}\n",
        fixture.originals["main.dae"]
    );
    std::fs::write(fixture.path("etc/main.dae"), &edited).unwrap();
    let terminal = operation(
        &fixture,
        "/api/v1/x-honk/config/import",
        "subscription-import",
        json!({"replace":true}),
    )
    .await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(fixture.database.as_ref().unwrap().head(), Ok(Some(2)));
    source(&fixture.get(CONFIG).await, &edited);
    fixture.shutdown().await;
}

#[tokio::test]
async fn import_export_and_activate_record_revisions() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    let config = fixture.get(CONFIG).await;
    assert_eq!(
        config["x-honk"]["store"],
        json!({"kind":"db","revision":1,"parent":null,"recorded":true})
    );
    assert!(
        config["sources"]
            .as_array()
            .unwrap()
            .iter()
            .all(|source| source.get("absolute_path").is_none())
    );
    let main = fixture
        .get(&format!(
            "{CONFIG}/sources/{}",
            config["sources"][0]["id"].as_str().unwrap()
        ))
        .await;
    assert!(main.get("absolute_path").is_none());
    let capabilities = fixture.get("/api/v1/capabilities").await;
    assert_eq!(capabilities["resources"]["config"]["x-honk"]["store"], "db");
    assert_eq!(
        capabilities["resources"]["x-honk"]["config_revisions"],
        json!({"available":true,"can_activate":true,"max_revisions":50})
    );

    let response = fixture
        .request(Method::POST, "/api/v1/x-honk/config/import")
        .header("idempotency-key", "first")
        .json(&json!({"replace":false}))
        .send()
        .await
        .unwrap();
    error(response, StatusCode::CONFLICT, "state_conflict").await;

    let edited = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    std::fs::write(fixture.path("etc/main.dae"), &edited).unwrap();
    let terminal = operation(
        &fixture,
        "/api/v1/x-honk/config/import",
        "replace",
        json!({"replace":true}),
    )
    .await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(store.head(), Ok(Some(2)));
    let config = fixture.get(CONFIG).await;
    source(&config, &edited);

    let response = fixture
        .request(Method::GET, "/api/v1/x-honk/config/export")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"honk-r2.dae\""
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    let etag = response.headers()["etag"].to_str().unwrap().to_owned();
    let body = response.text().await.unwrap();
    assert_eq!(etag, format!("\"{}\"", sha256(&body)));
    assert!(body.starts_with("# listener secrets omitted\n"));
    assert!(!body.contains(SECRET) && !body.contains("include {"));
    let stored = store.load(&HashMap::new(), &mut Vec::new()).unwrap();
    let documents: Vec<_> = stored
        .sources
        .iter()
        .map(|source| (source.path.clone(), source.content.clone()))
        .collect();
    let expected = honk_config::parser::parse_dae_sources(
        &documents,
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap()
    .config;
    assert_eq!(
        honk_config::parser::parse_dae_config(&body).unwrap(),
        expected
    );

    let terminal = operation(
        &fixture,
        "/api/v1/x-honk/config/revisions/1/activate",
        "rollback",
        json!({}),
    )
    .await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(store.head(), Ok(Some(3)));
    let config = fixture.get(CONFIG).await;
    source(&config, &fixture.originals["main.dae"]);
    let response = fixture
        .request(Method::POST, "/api/v1/x-honk/config/revisions/9/activate")
        .send()
        .await
        .unwrap();
    error(response, StatusCode::NOT_FOUND, "resource_not_found").await;

    let list = fixture.get("/api/v1/x-honk/config/revisions").await;
    assert_eq!(list["active"], 3);
    assert_eq!(list["max_revisions"], 50);
    let rows: Vec<_> = list["revisions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["revision"].as_i64().unwrap(),
                row["parent"].as_i64(),
                row["origin"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (3, Some(2), "activate".to_owned()),
            (2, Some(1), "import".to_owned()),
            (1, None, "import".to_owned()),
        ]
    );
    assert!(list["revisions"][0]["sources"][0]["path"] == "main.dae");
    assert!(!list.to_string().contains("origin_sha256") && !list.to_string().contains("content\""));
    fixture.shutdown().await;
}

fn main_edit(fixture: &Fixture) -> String {
    fixture.originals["main.dae"].replace("fallback: direct", "fallback: block")
}

async fn hold_database(
    fixture: &Fixture,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<bool>) {
    let state = fixture.database.as_ref().unwrap().state();
    let (entered, wait) = oneshot::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let _connection = state.strict();
        entered.send(()).unwrap();
        resume.recv_timeout(WAIT).is_ok()
    });
    timeout(WAIT, wait).await.unwrap().unwrap();
    (release, thread)
}

async fn changed_config(fixture: &Fixture, before: &Value) -> Value {
    timeout(WAIT, async {
        loop {
            let current = fixture.get(CONFIG).await;
            if current["revision"] != before["revision"] {
                return current;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("source activation did not publish")
}

#[tokio::test]
async fn pending_record_keeps_http_responsive_and_serializes_the_next_work() {
    let mut fixture = Fixture::build(Access::Admin, true, |_, _| {}, true, false).await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = main_edit(&fixture);
    let admitted = accepted(fixture.replace(main, &candidate).send().await.unwrap()).await;
    let activation = fixture.next_reload().await;
    assert_eq!(
        fixture.get(CONFIG).await["x-honk"]["store"]["recorded"],
        true
    );
    let (release, locked) = hold_database(&fixture).await;
    activation.send(()).unwrap();

    let active = changed_config(&fixture, &before).await;
    assert_eq!(source(&active, &candidate)["id"], main["id"]);
    assert_eq!(
        active["x-honk"]["store"],
        json!({"kind":"db","revision":1,"parent":null,"recorded":false})
    );
    let export = fixture
        .request(Method::GET, "/api/v1/x-honk/config/export")
        .send()
        .await
        .unwrap();
    assert_eq!(
        export.headers()["content-disposition"],
        "attachment; filename=\"honk.dae\""
    );
    assert!(export.text().await.unwrap().contains("fallback: block"));
    assert_eq!(
        fixture.get(admitted["href"].as_str().unwrap()).await["status"],
        "running"
    );

    let request = fixture.validate("syntax", "routing { fallback: direct }");
    let mut queued = tokio::spawn(request.send());
    assert!(
        timeout(Duration::from_millis(50), &mut queued)
            .await
            .is_err()
    );
    release.send(()).unwrap();
    assert!(
        locked.join().unwrap(),
        "record blocked the async runtime until the lock expired"
    );
    assert_eq!(ok(queued.await.unwrap().unwrap()).await["valid"], true);
    assert_eq!(fixture.terminal(&admitted).await["status"], "succeeded");
    assert_eq!(
        fixture.get(CONFIG).await["x-honk"]["store"],
        json!({"kind":"db","revision":2,"parent":1,"recorded":true})
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn disconnected_management_and_shutdown_retain_pending_record() {
    let mut fixture = Fixture::build(Access::Admin, true, |_, _| {}, true, false).await;
    let before = fixture.get(CONFIG).await;
    let request = fixture
        .request(Method::POST, "/api/v1/nodes")
        .json(&json!({"name":"managed","link":"socks5://127.0.0.1:11080"}));
    let client = tokio::spawn(request.send());
    let activation = fixture.next_reload().await;
    let (release, locked) = hold_database(&fixture).await;
    activation.send(()).unwrap();
    let active = changed_config(&fixture, &before).await;
    assert_eq!(active["x-honk"]["store"]["recorded"], false);
    assert!(
        active["sources"][0]["content"]
            .as_str()
            .unwrap()
            .contains("managed")
    );
    assert!(
        !client.is_finished(),
        "management replied before its revision was durable"
    );
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());

    let coordinator = fixture.coordinator.take().unwrap();
    let mut shutdown = tokio::spawn(coordinator.shutdown());
    assert!(
        timeout(Duration::from_millis(50), &mut shutdown)
            .await
            .is_err()
    );
    release.send(()).unwrap();
    assert!(
        locked.join().unwrap(),
        "record blocked the async runtime until the lock expired"
    );
    timeout(WAIT, shutdown).await.unwrap().unwrap();
    assert_eq!(
        fixture.get(CONFIG).await["x-honk"]["store"],
        json!({"kind":"db","revision":2,"parent":1,"recorded":true})
    );
    assert_eq!(revisions(&fixture).len(), 2);
    fixture.shutdown().await;
}

#[tokio::test]
async fn activation_replay_outlives_the_pruned_revision() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    let edited = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    std::fs::write(fixture.path("etc/main.dae"), &edited).unwrap();
    let terminal = operation(
        &fixture,
        "/api/v1/x-honk/config/import",
        "replace",
        json!({"replace":true}),
    )
    .await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    let activate = || {
        fixture
            .request(Method::POST, "/api/v1/x-honk/config/revisions/1/activate")
            .header("idempotency-key", "rollback")
            .json(&json!({}))
            .send()
    };
    let first = accepted(activate().await.unwrap()).await;
    assert_eq!(fixture.terminal(&first).await["status"], "succeeded");
    // Retention pruned the source revision before the client retried.
    store
        .state()
        .strict()
        .execute("DELETE FROM revision WHERE number = 1", [])
        .unwrap();
    let replay = accepted(activate().await.unwrap()).await;
    assert_eq!(replay["operation_id"], first["operation_id"]);
    fixture.shutdown().await;
}

#[tokio::test]
async fn failed_record_blocks_writes_until_head_is_activated_again() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    store.fail_promote.store(true, Ordering::SeqCst);
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = main_edit(&fixture);
    let admitted = accepted(fixture.replace(main, &candidate).send().await.unwrap()).await;
    let terminal = fixture.terminal(&admitted).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(terminal["error"]["code"], "store_unavailable");
    let details = &terminal["error"]["details"];
    assert_eq!(details["committed"], true);
    assert_eq!(details["written"], false);
    assert!(details["active_generation_id"].is_string(), "{details}");
    assert!(details.get("stage").is_none());
    assert_eq!(store.head(), Ok(Some(1)));
    let config = fixture.get(CONFIG).await;
    assert_eq!(
        config["x-honk"]["store"],
        json!({"kind":"db","revision":1,"parent":null,"recorded":false})
    );
    let capabilities = fixture.get("/api/v1/capabilities").await;
    assert_eq!(capabilities["resources"]["config"]["writable"], false);
    assert_eq!(capabilities["resources"]["config"]["create"], false);
    let response = fixture
        .request(Method::POST, "/api/v1/config/sources")
        .json(&json!({"path":"config.d/new.dae","content":""}))
        .send()
        .await
        .unwrap();
    error(response, StatusCode::NOT_FOUND, "capability_not_supported").await;
    assert_eq!(
        capabilities["resources"]["x-honk"]["config_revisions"]["can_activate"],
        true
    );
    let response = fixture
        .request(Method::GET, "/api/v1/x-honk/config/export")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"honk.dae\""
    );
    let running = source(&config, &candidate);
    assert_eq!(running["writable"], false);
    assert!(
        config["sources"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["read_only_reason"] == "store_blocked")
    );
    let again = candidate.replace("fallback: block", "fallback: direct");
    let response = fixture.replace(running, &again).send().await.unwrap();
    let body = error(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    assert_eq!(body["error"]["details"]["stage"], "store");

    store.fail_promote.store(false, Ordering::SeqCst);
    let reloads = fixture.reloads.load(Ordering::SeqCst);
    let terminal = operation(
        &fixture,
        "/api/v1/x-honk/config/revisions/1/activate",
        "resync",
        json!({}),
    )
    .await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), reloads + 1);
    assert_eq!(store.head(), Ok(Some(1)));
    assert_eq!(revisions(&fixture).len(), 1);
    let config = fixture.get(CONFIG).await;
    assert_eq!(config["x-honk"]["store"]["recorded"], true);
    assert!(
        config["sources"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row.get("read_only_reason").is_none())
    );
    source(&config, &fixture.originals["main.dae"]);
    let capabilities = fixture.get("/api/v1/capabilities").await;
    assert_eq!(capabilities["resources"]["config"]["writable"], true);
    fixture.shutdown().await;
}

#[tokio::test]
async fn unconfirmed_activation_blocks_writes() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    fixture
        .reject_reloads
        .store(ReloadBehavior::Drop as u8, Ordering::SeqCst);
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let operation = accepted(
        fixture
            .replace(main, &main_edit(&fixture))
            .send()
            .await
            .unwrap(),
    )
    .await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(terminal["error"]["code"], "activation_unconfirmed");
    assert_eq!(
        terminal["error"]["details"],
        json!({"committed":null,"written":false})
    );
    assert_eq!(store.head(), Ok(Some(1)));
    assert_eq!(
        fixture.get(CONFIG).await["x-honk"]["store"]["recorded"],
        false
    );
    fixture
        .reject_reloads
        .store(ReloadBehavior::Apply as u8, Ordering::SeqCst);
    fixture.shutdown().await;
}

const CLASH: &str = "clash-listener-token";

#[tokio::test]
async fn db_mode_never_returns_or_keeps_listener_secret_values() {
    let fixture = Fixture::new_db_custom(Access::Admin, |_, files| {
        let auth = files.get_mut("auth.dae").unwrap();
        *auth = auth.replace(
            &format!("secret: '{SECRET}'"),
            &format!("secret: 'overridden-listener-token'\n secret: '{SECRET}'"),
        );
        auth.push_str(&format!(
            "experimental {{ clash_api {{ secret: '{CLASH}' }} }}\n"
        ));
    })
    .await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    let leaked = |text: &str| {
        [SECRET, CLASH, "overridden-listener-token"]
            .iter()
            .any(|secret| text.contains(secret))
    };
    let stored = store.load(&HashMap::new(), &mut Vec::new()).unwrap();
    assert_eq!(stored.config.experimental.clash_api.secret, CLASH);
    assert!(stored.sources.iter().all(|source| !leaked(&source.content)));
    assert!(!leaked(&fixture.get(CONFIG).await.to_string()));
    assert!(!leaked(
        &fixture
            .get("/api/v1/x-honk/config/revisions")
            .await
            .to_string()
    ));
    let bare = fixture.path("bare.dae");
    crate::native_api::store::db::export_to(&fixture.path("state"), &bare, false).unwrap();
    assert!(!leaked(&std::fs::read_to_string(&bare).unwrap()));

    // A copy survives stripping, so import refuses rather than store it.
    let copied = format!(
        "{}# old {CLASH} copied here\n",
        fixture.originals["main.dae"]
    );
    std::fs::write(fixture.path("etc/main.dae"), &copied).unwrap();
    let response = fixture
        .request(Method::POST, "/api/v1/x-honk/config/import")
        .header("idempotency-key", "copy")
        .json(&json!({"replace":true}))
        .send()
        .await
        .unwrap();
    error(
        response,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    assert_eq!(store.head(), Ok(Some(1)));
    fixture.shutdown().await;
}
