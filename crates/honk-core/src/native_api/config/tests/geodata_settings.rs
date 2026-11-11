use super::*;

/// Serves fixed responses by request path; any other path is a 404.
struct Mirror {
    address: SocketAddr,
    requests: Arc<parking_lot::Mutex<Vec<String>>>,
    tasks: JoinSet<()>,
}

impl Mirror {
    async fn new(routes: Vec<(&'static str, &'static str, Vec<u8>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.unwrap());
                }
                let head = String::from_utf8(head).unwrap();
                let path = head.split(' ').nth(1).unwrap().to_owned();
                seen.lock().push(path.clone());
                let (status, body) = routes
                    .iter()
                    .find(|(route, _, _)| *route == path)
                    .map_or(("404 Not Found", &[][..]), |(_, status, body)| {
                        (*status, body)
                    });
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            address,
            requests,
            tasks,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    async fn close(mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}

fn checksum(bytes: &[u8]) -> Vec<u8> {
    format!("{}  file.dat\n", crate::configuration::digest(bytes)).into_bytes()
}

#[tokio::test]
async fn custom_port_override_verifies_and_activates_after_failed_mirrors() {
    let site = geosite("new.example");
    let ip = geoip(203);
    const OK: &str = "200 OK";
    let mirror = Mirror::new(vec![
        ("/tampered/geosite.dat", OK, site.clone()),
        ("/tampered/geosite.dat.sha256sum", OK, checksum(b"other")),
        ("/moved/geosite.dat", OK, site.clone()),
        ("/moved/geosite.dat.sha256sum", "302 Found", Vec::new()),
        ("/token/abc123/geosite.dat?sig=abc", OK, site.clone()),
        (
            "/token/abc123/geosite.dat.sha256sum?sig=abc",
            OK,
            checksum(&site),
        ),
        ("/good/geoip.dat", OK, ip.clone()),
    ])
    .await;
    let fixture = Fixture::new_with_state(Access::Admin, |root, files| {
        setup_rules(root, files);
    })
    .await;
    let geosite_urls = [
        mirror.url("/missing/key/abc123/geosite.dat?token=abc"),
        mirror.url("/tampered/geosite.dat"),
        mirror.url("/moved/geosite.dat"),
        mirror.url("/token/abc123/geosite.dat?sig=abc"),
    ];
    let settings = ok(patch_settings(
        &fixture,
        json!({"geodata": {"geosite": {"urls": geosite_urls},
            "geoip": {"urls": [mirror.url("/good/geoip.dat")]}}}),
    )
    .await)
    .await;
    assert_eq!(settings["geodata"]["source"], "override");
    assert_eq!(settings["geodata"]["geosite"]["urls"], json!(geosite_urls));
    assert_eq!(settings["source"], "config");
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        site
    );
    assert_eq!(std::fs::read(fixture.path("state/geoip.dat")).unwrap(), ip);
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "block");
    let data = fixture.get(GEO).await;
    assert_eq!(data["assets"], terminal["result"]["assets"]);
    let assets = &data["assets"];
    assert_eq!(
        assets[0]["source_redacted"],
        mirror.url("/missing/key/[redacted]/geosite.dat")
    );
    assert_eq!(
        assets[0]["fetched_url_redacted"],
        mirror.url("/token/[redacted]/geosite.dat")
    );
    assert_eq!(assets[0]["verified"], true);
    assert_eq!(
        assets[1]["fetched_url_redacted"],
        mirror.url("/good/geoip.dat")
    );
    assert_eq!(assets[1]["verified"], false);
    for asset in assets.as_array().unwrap() {
        assert_eq!(
            asset["download_route"],
            json!({"route": "routing", "group_id": null})
        );
    }
    assert!(data["last_checked_at"].is_string());
    assert!(data["last_updated_at"].is_string());
    assert!(data["next_check_at"].is_string());
    assert_eq!(data["last_error"], Value::Null);
    assert_eq!(
        data["required_codes"],
        json!({"geosite": ["test"], "geoip": ["test"]})
    );
    assert_eq!(
        *mirror.requests.lock(),
        [
            "/missing/key/abc123/geosite.dat?token=abc",
            "/tampered/geosite.dat",
            "/tampered/geosite.dat.sha256sum",
            "/moved/geosite.dat",
            "/moved/geosite.dat.sha256sum",
            "/token/abc123/geosite.dat?sig=abc",
            "/token/abc123/geosite.dat.sha256sum?sig=abc",
            "/good/geoip.dat",
            "/good/geoip.dat.sha256sum",
        ]
    );
    fixture.shutdown().await;
    mirror.close().await;
}

#[tokio::test]
async fn a_failed_download_names_its_asset_and_the_rejected_status() {
    let site = geosite("new.example");
    let mirror = Mirror::new(vec![
        ("/geosite.dat", "200 OK", site),
        ("/geoip.dat", "200 OK", geoip(203)),
        ("/geoip.dat.sha256sum", "403 Forbidden", Vec::new()),
    ])
    .await;
    let fixture = Fixture::new_with_state(Access::Admin, |root, files| {
        setup_rules(root, files);
    })
    .await;
    ok(patch_settings(
        &fixture,
        json!({"geodata": {"geosite": {"urls": [mirror.url("/geosite.dat")]},
            "geoip": {"urls": [mirror.url("/geoip.dat")]}}}),
    )
    .await)
    .await;
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    let details = &terminal["error"]["details"];
    assert_eq!(details["stage"], "checksum_unavailable");
    assert_eq!(details["asset"], "geoip");
    assert_eq!(details["http_status"], 403);
    assert_eq!(details["committed"], false);
    fixture.shutdown().await;
    mirror.close().await;
}

#[tokio::test]
async fn a_missing_file_keeps_its_404_in_the_failure() {
    let mirror = Mirror::new(vec![("/geosite.dat", "200 OK", geosite("new.example"))]).await;
    let fixture = Fixture::new_with_state(Access::Admin, |root, files| {
        setup_rules(root, files);
    })
    .await;
    ok(patch_settings(
        &fixture,
        json!({"geodata": {"geosite": {"urls": [mirror.url("/geosite.dat")]},
            "geoip": {"urls": [mirror.url("/geoip.dat")]}}}),
    )
    .await)
    .await;
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    let details = &terminal["error"]["details"];
    assert_eq!(details["stage"], "http_not_found");
    assert_eq!(details["asset"], "geoip");
    assert_eq!(details["http_status"], 404);
    fixture.shutdown().await;
    mirror.close().await;
}

#[tokio::test]
async fn update_refuses_a_file_without_a_used_category_and_keeps_the_old_one() {
    let server = AssetServer::new(geosite_code(b"other", "new.example"), geoip(203), false).await;
    let fixture = fixture(server.address, false).await;
    let old = fixture.get(GEO).await;
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed");
    assert_eq!(
        terminal["error"]["details"]["stage"],
        "asset_validation_failed"
    );
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("old.example")
    );
    assert_eq!(fixture.get(GEO).await["assets"], old["assets"]);
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "block");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn url_patches_are_accepted_while_the_configuration_names_urls() {
    let address: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let fixture =
        Fixture::new_with_state(Access::Admin, |root, files| setup(root, files, address)).await;
    let before = fixture.get(SETTINGS).await;
    assert_eq!(
        before["geodata"],
        json!({"source": "config",
            "geosite": {"urls": [format!("http://{address}/geosite/PRIVATE?token=PRIVATE")]},
            "geoip": {"urls": [format!("http://{address}/geoip")]},
            "auto_update": {"enabled": true, "interval_hours": 24, "cron": "0 3 * * *"},
            "download": {"route": "routing", "group_id": null},
            "verify_checksum": true})
    );
    let patched = ok(patch_settings(
        &fixture,
        json!({"geodata": {"geoip": {"urls": ["https://mirror.example/geoip.dat"]}},
            "log": {"level": "debug"}}),
    )
    .await)
    .await;
    assert_eq!(patched["geodata"]["source"], "override");
    assert_eq!(patched["geodata"]["geosite"], before["geodata"]["geosite"]);
    assert_eq!(
        patched["geodata"]["geoip"]["urls"],
        json!(["https://mirror.example/geoip.dat"])
    );
    assert_eq!(patched["log"]["level"], "debug");
    assert_eq!(fixture.get(SETTINGS).await["geodata"], patched["geodata"]);
    let capabilities = fixture.get("/api/v1/capabilities").await;
    let geodata = &capabilities["resources"]["geodata"];
    assert_eq!(geodata["configurable_sources"], true);
    assert_eq!(geodata["max_urls"], 4);
    assert_eq!(
        geodata["interval_hours"],
        json!({"min": 6, "max": 168, "default": 24})
    );
    assert_eq!(geodata["checksum"], "sha256sum");
    assert_eq!(
        geodata["lifecycle"],
        json!({"file_values": "start", "overrides_persist": true})
    );
    assert!(
        capabilities["resources"]["runtime_settings"]["fields"]
            .as_array()
            .unwrap()
            .contains(&json!("geodata"))
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn an_unrelated_activation_keeps_patched_urls() {
    let address: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let fixture =
        Fixture::new_with_state(Access::Admin, |root, files| setup(root, files, address)).await;
    let patched = ok(patch_settings(
        &fixture,
        json!({"geodata": {"geosite": {"urls": ["https://mirror.example/geosite.dat"]}}}),
    )
    .await)
    .await["geodata"]
        .clone();
    let main = fixture.originals["main.dae"].replace(
        "domain(geosite: test) -> block",
        "domain(geosite: test) -> direct",
    );
    assert_ne!(main, fixture.originals["main.dae"]);
    std::fs::write(fixture.path("main.dae"), main).unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "direct");
    assert_eq!(fixture.get(SETTINGS).await["geodata"], patched);
    fixture.shutdown().await;
}

#[tokio::test]
async fn auto_update_stays_settable_while_the_configuration_names_urls() {
    let address: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let fixture =
        Fixture::new_with_state(Access::Admin, |root, files| setup(root, files, address)).await;
    assert!(fixture.get(GEO).await["next_check_at"].is_string());
    let settings = ok(patch_settings(
        &fixture,
        json!({"geodata": {"auto_update": {"enabled": false, "interval_hours": 48}}}),
    )
    .await)
    .await;
    assert_eq!(settings["geodata"]["source"], "config");
    assert_eq!(
        settings["geodata"]["auto_update"],
        json!({"enabled": false, "interval_hours": 48, "cron": null})
    );
    assert_eq!(settings["source"], "config");
    assert_eq!(fixture.get(SETTINGS).await["geodata"], settings["geodata"]);
    assert_eq!(fixture.get(GEO).await["next_check_at"], Value::Null);
    let settings = ok(patch_settings(
        &fixture,
        json!({"geodata": {"auto_update": {"cron": "30 4 * * 1-5"}}}),
    )
    .await)
    .await;
    assert_eq!(
        settings["geodata"]["auto_update"],
        json!({"enabled": false, "interval_hours": 24, "cron": "30 4 * * 1-5"})
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn checksum_verification_is_on_by_default_and_settable() {
    let address: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let fixture =
        Fixture::new_with_state(Access::Admin, |root, files| setup(root, files, address)).await;
    assert_eq!(
        fixture.get(SETTINGS).await["geodata"]["verify_checksum"],
        true
    );
    let settings =
        ok(patch_settings(&fixture, json!({"geodata": {"verify_checksum": false}})).await).await;
    assert_eq!(settings["geodata"]["verify_checksum"], false);
    assert_eq!(fixture.get(SETTINGS).await["geodata"], settings["geodata"]);
    fixture.shutdown().await;
}

#[tokio::test]
async fn anonymous_callers_cannot_change_sources_and_read_urls_as_written() {
    const CLASH: &str = "clash{listener}secret";
    let fixture = Fixture::new_with_state(Access::Anonymous, |root, files| {
        setup_rules(root, files);
        let auth = files.get_mut("auth.dae").unwrap();
        *auth = auth.replace(
            " native_api {",
            &format!(" clash_api {{\n secret: '{CLASH}'\n }}\n native_api {{"),
        );
        *auth = auth.replace(
            " allow_anonymous_loopback: true",
            &format!(" allow_anonymous_loopback: true\n geosite_download_url: 'https://mirror.example/{CLASH}/geosite.dat?key=query-secret'"),
        );
    })
    .await;
    let before = fixture.get(SETTINGS).await;
    let urls = before["geodata"]["geosite"]["urls"].as_array().unwrap();
    assert_eq!(urls.len(), 1);
    assert_eq!(
        urls[0],
        "https://mirror.example/<redacted>/geosite.dat?key=query-secret"
    );
    let shown = &fixture.get(GEO).await["assets"][0]["source_redacted"];
    assert!(!shown.to_string().contains("listener"), "{shown}");
    for body in [
        json!({"geodata": {"auto_update": {"enabled": false}}}),
        json!({"geodata": null}),
    ] {
        error(
            patch_settings(&fixture, body).await,
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
    }
    assert_eq!(fixture.get(SETTINGS).await["geodata"], before["geodata"]);
    fixture.shutdown().await;
}

#[tokio::test]
async fn settings_mask_an_overridden_listener_secret_in_urls() {
    const OVERRIDDEN: &str = "overridden-listener-token";
    let fixture = Fixture::new_with_state(Access::Admin, |root, files| {
        setup_rules(root, files);
        let auth = files.get_mut("auth.dae").unwrap();
        *auth = auth.replace(
            &format!("secret: '{SECRET}'"),
            &format!("secret: '{OVERRIDDEN}'\n secret: '{SECRET}'\n geosite_download_url: 'https://mirror.example/{OVERRIDDEN}/geosite.dat'"),
        );
    })
    .await;
    let settings = fixture.get(SETTINGS).await;
    assert_eq!(
        settings["geodata"]["geosite"]["urls"],
        json!(["https://mirror.example/<redacted>/geosite.dat"])
    );
    assert!(!settings.to_string().contains(OVERRIDDEN));
    assert!(!fixture.get(GEO).await.to_string().contains(OVERRIDDEN));
    fixture.shutdown().await;
}

#[tokio::test]
async fn null_returns_to_the_built_in_sources() {
    let fixture = Fixture::new_with_state(Access::Admin, setup_rules).await;
    let defaults = fixture.get(SETTINGS).await["geodata"].clone();
    assert_eq!(defaults["source"], "default");
    assert_eq!(
        defaults["auto_update"],
        json!({"enabled": true, "interval_hours": 24, "cron": "0 3 * * *"})
    );
    let stored = ok(patch_settings(
        &fixture,
        json!({"geodata": {"geoip": {"urls": ["https://mirror.example/geoip.dat"]},
            "auto_update": {"enabled": false}}}),
    )
    .await)
    .await;
    assert_eq!(stored["geodata"]["source"], "override");
    assert_eq!(stored["geodata"]["geosite"], defaults["geosite"]);
    assert_eq!(
        stored["geodata"]["geoip"]["urls"],
        json!(["https://mirror.example/geoip.dat"])
    );
    let reset = ok(patch_settings(&fixture, json!({"geodata": null})).await).await;
    assert_eq!(reset["geodata"], defaults);
    assert_eq!(fixture.get(SETTINGS).await["geodata"], defaults);
    assert!(fixture.get(GEO).await["next_check_at"].is_string());
    fixture.shutdown().await;
}

/// Holds the state db's writer from an OS thread until released, or for 5 s.
fn hold_state_writer(
    fixture: &Fixture,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let db = fixture
        .state
        .upgrade()
        .unwrap()
        .geodata
        .as_ref()
        .unwrap()
        .db();
    let (held, holding) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _connection = db.strict();
        held.send(()).unwrap();
        let _ = released.recv_timeout(Duration::from_secs(5));
    });
    holding.recv().unwrap();
    (release, holder)
}

const MIXED: &str = r#"{"record_flows":"on","geodata":{"auto_update":{"enabled":false}}}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_blocked_geodata_commit_does_not_stall_settings_or_the_runtime() {
    let fixture = Fixture::new_with_state(Access::Admin, setup_rules).await;
    let (release, holder) = hold_state_writer(&fixture);
    let pending = tokio::spawn(
        fixture
            .request(Method::PATCH, SETTINGS)
            .header("content-type", "application/json")
            .body(MIXED)
            .send(),
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = std::time::Instant::now();
    let during = fixture.get(SETTINGS).await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(during["recording"]["flows"]["mode"], "auto");
    assert_eq!(during["geodata"]["auto_update"]["enabled"], true);
    assert!(!pending.is_finished());
    release.send(()).unwrap();
    let landed = ok(pending.await.unwrap().unwrap()).await;
    holder.join().unwrap();
    assert_eq!(landed["recording"]["flows"]["mode"], "on");
    assert_eq!(landed["geodata"]["auto_update"]["enabled"], false);
    assert_eq!(
        fixture.get(SETTINGS).await["recording"]["flows"]["mode"],
        "on"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_dropped_request_still_lands_its_geodata_commit_and_settings() {
    let fixture = Fixture::new_with_state(Access::Admin, setup_rules).await;
    let (release, holder) = hold_state_writer(&fixture);
    let pending = tokio::spawn(
        fixture
            .request(Method::PATCH, SETTINGS)
            .header("content-type", "application/json")
            .body(MIXED)
            .send(),
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    pending.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;
    release.send(()).unwrap();
    holder.join().unwrap();
    let mut landed = Value::Null;
    for _ in 0..50 {
        landed = fixture.get(SETTINGS).await;
        if landed["recording"]["flows"]["mode"] == "on" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(landed["recording"]["flows"]["mode"], "on");
    assert_eq!(landed["geodata"]["auto_update"]["enabled"], false);
    fixture.shutdown().await;
}

const GEODATA_ONLY: &str = r#"{"geodata":{"auto_update":{"enabled":false}}}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_blocked_geodata_commit_does_not_hold_the_config_lock() {
    let fixture = Fixture::new_with_state(Access::Admin, setup_rules).await;
    let (release, holder) = hold_state_writer(&fixture);
    let pending = tokio::spawn(
        fixture
            .request(Method::PATCH, SETTINGS)
            .header("content-type", "application/json")
            .body(GEODATA_ONLY)
            .send(),
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let state = fixture.state.upgrade().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), state.config.write())
            .await
            .is_ok(),
        "a reload writer queued behind the commit"
    );
    assert!(!pending.is_finished());
    release.send(()).unwrap();
    let landed = ok(pending.await.unwrap().unwrap()).await;
    holder.join().unwrap();
    assert_eq!(landed["geodata"]["auto_update"]["enabled"], false);
    drop(state);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn shutdown_during_a_commit_answers_unavailable_after_the_geodata_is_stored() {
    let fixture = Fixture::new_with_state(Access::Admin, setup_rules).await;
    let (release, holder) = hold_state_writer(&fixture);
    let pending = tokio::spawn(
        fixture
            .request(Method::PATCH, SETTINGS)
            .header("content-type", "application/json")
            .body(MIXED)
            .send(),
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let state = fixture.state.upgrade().unwrap();
    state.observation.settings.shutdown(&state.observation);
    drop(state);
    release.send(()).unwrap();
    let response = pending.await.unwrap().unwrap();
    holder.join().unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let error: Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "temporarily_unavailable");
    assert_eq!(error["error"]["details"]["geodata_stored"], true);
    assert_eq!(
        fixture.get(SETTINGS).await["geodata"]["auto_update"]["enabled"],
        false
    );
    fixture.shutdown().await;
}
