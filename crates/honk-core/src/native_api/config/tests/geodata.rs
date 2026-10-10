use super::*;
use crate::native_api::geodata::download_direct;
use tokio::io::AsyncReadExt;

const GEO: &str = "/api/v1/geodata";
const UPDATE: &str = "/api/v1/geodata/update";

fn delimited(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    let mut result = vec![tag << 3 | 2, value.len() as u8];
    result.extend_from_slice(value);
    result
}

fn geosite(domain: &str) -> Vec<u8> {
    geosite_code(b"test", domain)
}

fn geosite_code(code: &[u8], domain: &str) -> Vec<u8> {
    let mut entry = delimited(1, code);
    let mut rule = vec![8, 3];
    rule.extend(delimited(2, domain.as_bytes()));
    entry.extend(delimited(2, &rule));
    delimited(1, &entry)
}

fn geoip(first: u8) -> Vec<u8> {
    let mut entry = delimited(1, b"test");
    let mut cidr = delimited(1, &[first, 0, 0, 0]);
    cidr.extend([16, 8]);
    entry.extend(delimited(2, &cidr));
    delimited(1, &entry)
}

#[tokio::test]
async fn trace_displays_configured_values_in_compiled_condition_order() {
    let fixture = Fixture::new_custom(Access::Metadata, false, |root, files| {
        let directory = root.join("state");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("geosite.dat"), geosite("old.example")).unwrap();
        std::fs::write(directory.join("geoip.dat"), geoip(198)).unwrap();
        files.insert("locked.dae", "routing {\n pname(curl) && !dport(53) && dip(192.0.2.0/24, geoip: test) && domain(keyword: example, geosite: test) -> block\n !domain(geosite: test) && !dip(geoip: test) -> direct\n}\n".into());
    }).await;
    let dictionary = fixture.get("/api/v1/rules").await;
    let trace = |domain| {
        fixture.request(Method::POST, "/api/v1/routing/trace").json(&json!({
        "input":{"network":"tcp","domain":domain,"dst_ip":"192.0.2.1","dst_port":443,"pname":"curl"},
        "resolve":"none"
    }))
    };
    let matched = ok(trace("old.example").send().await.unwrap()).await;
    let evaluation = &matched["evaluations"][0];
    assert_eq!(matched["generation_id"], dictionary["generation_id"]);
    assert_eq!(evaluation["outbound"], "block");
    assert_eq!(
        evaluation["rules"][0]["rule_id"],
        dictionary["rules"][0]["rule_id"]
    );
    assert_eq!(
        evaluation["rules"][0]["expression"],
        dictionary["rules"][0]["expression"]
    );
    let conditions = evaluation["rules"][0]["conditions"].as_array().unwrap();
    assert_eq!(
        conditions
            .iter()
            .map(|row| row["expression"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            r#"domain(keyword: example, geosite: test)"#,
            r#"dip(192.0.2.0/24, geoip: test)"#,
            r#"pname(curl)"#,
            r#"!dport(53)"#,
        ]
    );
    assert!(conditions.iter().all(|row| row["result"] == "matched"));
    let not_matched = ok(trace("other.org").send().await.unwrap()).await;
    let evaluation = &not_matched["evaluations"][0];
    assert_eq!(evaluation["outbound"], "direct");
    assert_eq!(
        evaluation["rules"][0]["conditions"][0]["result"],
        "not_matched"
    );
    assert_eq!(evaluation["rules"][0]["conditions"][1]["result"], "skipped");
    assert_eq!(
        evaluation["rules"][1]["conditions"][0]["expression"],
        r#"!domain(geosite: test)"#
    );
    assert_eq!(
        evaluation["rules"][1]["conditions"][1]["expression"],
        r#"!dip(geoip: test)"#
    );
    assert_eq!(evaluation["rules"][1]["result"], "matched");
    fixture.shutdown().await;
}

struct AssetServer {
    address: SocketAddr,
    assets: Arc<parking_lot::Mutex<(Vec<u8>, Vec<u8>)>>,
    requests: Arc<AtomicUsize>,
    entered: oneshot::Receiver<()>,
    release: Option<oneshot::Sender<()>>,
    tasks: JoinSet<()>,
}

impl AssetServer {
    async fn new(site: Vec<u8>, ip: Vec<u8>, gated: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let assets = Arc::new(parking_lot::Mutex::new((site, ip)));
        let served = Arc::clone(&assets);
        let (entered, wait) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut entered = Some(entered);
            let mut resume = Some(resume);
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                loop {
                    let byte = stream.read_u8().await.unwrap();
                    head.push(byte);
                    assert!(head.len() <= 4096);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                // No checksum is published beside these assets.
                if head.split(|byte| *byte == b' ').nth(1).and_then(|target| target.split(|byte| *byte == b'?').next())
                    .is_some_and(|path| path.ends_with(b".sha256sum")) {
                    stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                    stream.shutdown().await.unwrap();
                    continue;
                }
                counted.fetch_add(1, Ordering::SeqCst);
                if let Some(entered) = entered.take() {
                    let _ = entered.send(());
                    if gated {
                        resume.take().unwrap().await.unwrap();
                    }
                }
                let bytes = {
                    let assets = served.lock();
                    if head.starts_with(b"GET /geosite") {
                        assets.0.clone()
                    } else {
                        assets.1.clone()
                    }
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            address,
            assets,
            requests,
            entered: wait,
            release: Some(release),
            tasks,
        }
    }

    fn serve_geosite(&self, site: Vec<u8>) {
        self.assets.lock().0 = site;
    }

    async fn close(mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}

fn setup(root: &Path, files: &mut HashMap<&'static str, String>, address: SocketAddr) {
    setup_rules(root, files);
    let auth = files.get_mut("auth.dae").unwrap();
    *auth = auth.replace(" enabled: true", &format!(
        " geosite_download_url: 'http://{address}/geosite/PRIVATE?token=PRIVATE'\n geoip_download_url: 'http://{address}/geoip'\n enabled: true",
    ));
}

fn setup_rules(root: &Path, files: &mut HashMap<&'static str, String>) {
    let directory = root.join("state");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("geosite.dat"), geosite("old.example")).unwrap();
    std::fs::write(directory.join("geoip.dat"), geoip(198)).unwrap();
    let main = files.get_mut("main.dae").unwrap();
    *main = main.replace(
        " fallback: direct",
        " domain(geosite: test) -> block\n dip(geoip: test) -> block\n fallback: direct",
    );
}

async fn fixture(address: SocketAddr, gated_reload: bool) -> Fixture {
    Fixture::new_custom(Access::Admin, gated_reload, |root, files| {
        setup(root, files, address)
    })
    .await
}

async fn route(fixture: &Fixture, domain: &str, ip: &str) -> String {
    fixture
        .state
        .upgrade()
        .unwrap()
        .traffic_router
        .read()
        .await
        .route(&crate::routing::ConnectionInfo {
            domain: Some(domain.into()),
            dst_ip: ip.parse().unwrap(),
            dst_port: 443,
            src_ip: "192.0.2.1".parse().unwrap(),
            src_port: 12345,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        })
        .to_owned()
}

#[tokio::test]
async fn source_write_rejects_swapped_geo_readers_before_rename() {
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        setup(root, files, "127.0.0.1:9".parse().unwrap());
        for (name, target) in [("geosite.dat", "site.body"), ("geoip.dat", "ip.body")] {
            let path = root.join("state").join(name);
            let target = root.join("state").join(target);
            std::fs::rename(&path, &target).unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
        }
    })
    .await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let (entered, resume) = fixture.pause_before_replace();
    let request = fixture.replace(main, &candidate);
    let mut requests = JoinSet::new();
    requests.spawn(async move { request.send().await });
    timeout(WAIT, entered).await.unwrap().unwrap();
    for (name, target) in [("geosite.dat", "ip.body"), ("geoip.dat", "site.body")] {
        let path = fixture.path(&format!("state/{name}"));
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(fixture.path(&format!("state/{target}")), path).unwrap();
    }
    resume.send(()).unwrap();
    error(
        timeout(WAIT, requests.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(fixture.path("main.dae")).unwrap(),
        fixture.originals["main.dae"]
    );
    assert_eq!(fixture.get(CONFIG).await, before);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn updates_verified_bytes_and_keeps_loaded_metadata_after_disk_edits() {
    let server = AssetServer::new(geosite("new.example"), geoip(203), false).await;
    let fixture = fixture(server.address, false).await;
    let old = fixture.get(GEO).await;
    assert_eq!(
        old["assets"][0]["sha256"],
        crate::configuration::digest(&geosite("old.example"))
    );
    assert!(
        old["assets"][0]["source_redacted"]
            .as_str()
            .unwrap()
            .starts_with(&format!("http://{}/", server.address))
    );
    assert_eq!(
        old["assets"][0]["source_redacted"],
        format!("http://{}/geosite/PRIVATE", server.address)
    );
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "block");
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "direct");
    let operation = accepted(
        fixture
            .request(Method::POST, UPDATE)
            .header("idempotency-key", "update")
            .send()
            .await
            .unwrap(),
    )
    .await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(terminal["kind"], "geodata_update");
    assert_eq!(
        terminal["result"]["assets"][0]["source_redacted"],
        old["assets"][0]["source_redacted"]
    );
    assert_eq!(
        terminal["result"]["assets"][0]["sha256"],
        crate::configuration::digest(&geosite("new.example"))
    );
    assert_eq!(
        terminal["result"]["assets"][1]["sha256"],
        crate::configuration::digest(&geoip(203))
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 1);
    fixture.assert_last_reload(&terminal).await;
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "direct");
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "block");
    assert_eq!(route(&fixture, "other.example", "203.1.2.3").await, "block");
    let loaded = fixture.get(GEO).await;
    std::fs::write(fixture.path("state/geosite.dat"), b"external-editor").unwrap();
    assert_eq!(fixture.get(GEO).await["assets"], loaded["assets"]);
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "block");
    let replay = accepted(
        fixture
            .request(Method::POST, UPDATE)
            .header("idempotency-key", "update")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(replay, operation);
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn invalid_later_asset_never_replaces_either_file() {
    let mut malformed = geoip(203);
    let mut unused = delimited(1, b"unused");
    unused.extend(delimited(2, &[255]));
    malformed.extend(delimited(1, &unused));
    let server = AssetServer::new(geosite("new.example"), malformed, false).await;
    let fixture = fixture(server.address, false).await;
    let old = fixture.get(GEO).await;
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed");
    assert_eq!(terminal["error"]["details"]["committed"], false);
    for asset in terminal["error"]["details"]["assets"].as_array().unwrap() {
        assert_eq!(asset["written"], false);
    }
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("old.example")
    );
    assert_eq!(
        std::fs::read(fixture.path("state/geoip.dat")).unwrap(),
        geoip(198)
    );
    assert_eq!(fixture.get(GEO).await["assets"], old["assets"]);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read_dir(fixture.path("state")).unwrap().count(), 2);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn disconnect_and_replay_keep_one_inflight_owner() {
    let mut server = AssetServer::new(geosite("new.example"), geoip(203), true).await;
    let fixture = fixture(server.address, false).await;
    let mut stream = TcpStream::connect(fixture.addr).await.unwrap();
    stream.write_all(format!("POST {UPDATE} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {SECRET}\r\nIdempotency-Key: disconnect\r\nContent-Length: 0\r\n\r\n", fixture.addr).as_bytes()).await.unwrap();
    timeout(WAIT, &mut server.entered).await.unwrap().unwrap();
    drop(stream);
    let replay = accepted(
        fixture
            .request(Method::POST, UPDATE)
            .header("idempotency-key", "disconnect")
            .send()
            .await
            .unwrap(),
    )
    .await;
    error(
        fixture
            .request(Method::POST, UPDATE)
            .header("idempotency-key", "different")
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    error(
        fixture
            .request(Method::POST, UPDATE)
            .body("{}")
            .send()
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    server.release.take().unwrap().send(()).unwrap();
    let terminal = fixture.terminal(&replay).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn shutdown_abandons_an_inflight_download() {
    let mut server = AssetServer::new(geosite("new.example"), geoip(203), true).await;
    let mut fixture = fixture(server.address, false).await;
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    timeout(WAIT, &mut server.entered).await.unwrap().unwrap();
    let coordinator = fixture.coordinator.take().unwrap();
    timeout(WAIT, coordinator.shutdown())
        .await
        .expect("shutdown waited for the download");
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(terminal["error"]["details"]["stage"], "coordinator_stopped");
    assert_eq!(terminal["error"]["details"]["committed"], false);
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("old.example")
    );
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn failure_after_first_rename_reports_partial_write_without_activation() {
    let server = AssetServer::new(geosite("new.example"), geoip(203), false).await;
    let fixture = fixture(server.address, false).await;
    let old = fixture.get(GEO).await;
    let service = Arc::clone(&fixture.service);
    let second = fixture.path("state/geoip.dat");
    *fixture.service.before_replace.lock() = Some(Box::new(move || {
        *service.before_replace.lock() = Some(Box::new(move || {
            std::fs::write(second, b"concurrent-editor").unwrap();
        }));
    }));
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed");
    let details = &terminal["error"]["details"];
    assert_eq!(details["assets"][0]["written"], true);
    assert_eq!(details["assets"][0]["durability_confirmed"], true);
    assert_eq!(details["assets"][1]["written"], false);
    assert_eq!(details["committed"], false);
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("new.example")
    );
    assert_eq!(
        std::fs::read(fixture.path("state/geoip.dat")).unwrap(),
        b"concurrent-editor"
    );
    assert_eq!(fixture.get(GEO).await["assets"], old["assets"]);
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "block");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.get("/api/v1/runtime").await["last_reload"],
        Value::Null
    );
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn download_bounds_actual_chunked_bytes_and_joins_timed_out_connection() {
    for (response, expected) in [
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n".as_slice(), "asset_too_large"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n".as_slice(), "download_timeout"),
        (b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: 0\r\n\r\n".as_slice(), "http_status_rejected"),
        (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n".as_slice(), "content_encoding_rejected"),
        (b"HTTP/1.1 302 Found\r\nContent-Length: 1\r\n\r\n".as_slice(), "http_status_rejected"),
        (b"HTTP/1.1 302 Found\r\nContent-Length: 5\r\n\r\n12345".as_slice(), "http_status_rejected"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/data", listener.local_addr().unwrap());
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") { head.push(stream.read_u8().await.unwrap()); }
            stream.write_all(response).await.unwrap();
            let mut remaining = Vec::new();
            let read = timeout(WAIT, stream.read_to_end(&mut remaining)).await.unwrap();
            assert!(read.is_ok() || read.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
        });
        let result = download_direct(&url, "", (tokio::time::Instant::now() + Duration::from_millis(100)).into(), 4).await;
        assert_eq!(result.unwrap_err().code, expected);
        tasks.join_next().await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn loaded_snapshot_waits_for_router_without_holding_config() {
    use futures::FutureExt as _;
    let fixture = Fixture::new(Access::Admin, false).await;
    let state = fixture.state.upgrade().unwrap();
    {
        let router = state.traffic_router.write().await;
        let capture = crate::native_api::geodata::capture(&state);
        tokio::pin!(capture);
        assert!(capture.as_mut().now_or_never().is_none());
        let config = state
            .config
            .try_write()
            .expect("snapshot must follow reload's router-before-config order");
        drop(config);
        drop(router);
        capture.await.unwrap();
    }
    drop(state);
    fixture.shutdown().await;
}

#[tokio::test]
async fn repeated_update_with_hosts_and_split_dns_assets_retains_available_metadata() {
    let server = AssetServer::new(geosite("old.example"), geoip(203), false).await;
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        setup(root, files, server.address);
        let hosts = root.join("state/hosts.rules");
        std::fs::write(&hosts, "full:host.example 192.0.2.9\n").unwrap();
        let main = files.get_mut("main.dae").unwrap();
        *main = main.replace(" dip(geoip: test) -> block\n", "");
        *main = main.replace(
            root.join("state").to_str().unwrap(),
            root.join("state/../state").to_str().unwrap(),
        );
        main.push_str(&format!(
            "dns {{\n use_host: '{}'\n routing {{\n request {{\n qname(geosite: test) -> reject\n fallback: asis\n }}\n response {{\n ip(geoip: test) -> reject\n fallback: accept\n }}\n }}\n}}\n", hosts.display(),
        ));
    }).await;
    for _ in 0..2 {
        let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
        let terminal = fixture.terminal(&operation).await;
        assert_eq!(terminal["status"], "succeeded", "{terminal}");
        assert_eq!(
            terminal["result"]["assets"][0]["sha256"],
            crate::configuration::digest(&geosite("old.example"))
        );
        assert_eq!(
            terminal["result"]["assets"][1]["sha256"],
            crate::configuration::digest(&geoip(203))
        );
        let capabilities = fixture.get("/api/v1/capabilities").await;
        assert_eq!(capabilities["resources"]["geodata"]["available"], true);
        assert_eq!(capabilities["resources"]["geodata"]["can_update"], true);
        assert_eq!(
            fixture.get(GEO).await["assets"][0]["sha256"],
            crate::configuration::digest(&geosite("old.example"))
        );
    }
    assert_eq!(server.requests.load(Ordering::SeqCst), 4);
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "block");
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn cached_subscription_rows_are_fenced_without_filesystem_guards() {
    let server = AssetServer::new(geosite("new.example"), geoip(203), false).await;
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        setup(root, files, server.address);
        files
            .get_mut("main.dae")
            .unwrap()
            .push_str("\nsubscription {\n cached: 'http://127.0.0.1:9/cached'\n}\n");
    })
    .await;
    let state = fixture.state.upgrade().unwrap();
    let subscription = state.config.read().await.subscriptions[0].clone();
    drop(state);
    let store = crate::subscription::SubscriptionStore::in_dir(&fixture.path("state"));

    for port in [17771, 17772] {
        let domain = format!("{port}.example");
        server.serve_geosite(geosite(&domain));
        store
            .store_content(&subscription, format!("socks5://127.0.0.1:{port}#cached"))
            .await
            .unwrap();
        let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
        let terminal = fixture.terminal(&operation).await;
        assert_eq!(terminal["status"], "succeeded", "{terminal}");
        assert_eq!(route(&fixture, &domain, "192.0.2.5").await, "block");
    }
    server.serve_geosite(geosite("final.example"));

    let before = fixture.get(GEO).await;
    let (entered, resume) = fixture.pause_before_replace();
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    timeout(WAIT, entered).await.unwrap().unwrap();
    store
        .store_content(&subscription, "socks5://127.0.0.1:17773#changed".into())
        .await
        .unwrap();
    resume.send(()).unwrap();
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(terminal["error"]["details"]["stage"], "replacement_failed");
    assert!(
        terminal["error"]["details"]["assets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|asset| asset["written"] == false)
    );
    assert_eq!(fixture.get(GEO).await["assets"], before["assets"]);
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("17772.example")
    );
    drop(store);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn concurrent_geodata_rejections_share_the_original_admission_error() {
    use axum::response::IntoResponse as _;
    let fixture = Fixture::new(Access::Metadata, false).await;
    let state = fixture.state.upgrade().unwrap();
    let id = crate::native_api::types::RequestId("geodata-admission".into());
    {
        let request = || {
            axum::extract::Request::builder()
                .method("POST")
                .uri(UPDATE)
                .header("idempotency-key", "unavailable-update")
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let router = state.traffic_router.write().await;
        let first = crate::native_api::geodata::update(&state, request(), &id);
        tokio::pin!(first);
        assert!(futures::poll!(first.as_mut()).is_pending());
        let second = crate::native_api::geodata::update(&state, request(), &id);
        tokio::pin!(second);
        assert!(futures::poll!(second.as_mut()).is_pending());
        drop(router);
        assert_eq!(
            first.await.unwrap_err().into_response().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            second.await.unwrap_err().into_response().status(),
            StatusCode::NOT_FOUND
        );
    }
    drop(state);
    fixture.shutdown().await;
}

const SETTINGS: &str = "/api/v1/runtime/settings";

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

async fn patch_settings(fixture: &Fixture, body: Value) -> Response {
    fixture
        .request(Method::PATCH, SETTINGS)
        .json(&body)
        .send()
        .await
        .unwrap()
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
            "auto_update": {"enabled": true, "interval_hours": 24},
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
        json!({"enabled": false, "interval_hours": 48})
    );
    assert_eq!(settings["source"], "config");
    assert_eq!(fixture.get(SETTINGS).await["geodata"], settings["geodata"]);
    assert_eq!(fixture.get(GEO).await["next_check_at"], Value::Null);
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
        json!({"enabled": true, "interval_hours": 24})
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

/// Group `proxy` exists in the configuration; the file routes downloads through it.
fn setup_group(root: &Path, files: &mut HashMap<&'static str, String>) {
    setup_rules(root, files);
    files
        .get_mut("editable.dae")
        .unwrap()
        .push_str("group {\n proxy { policy: fallback }\n}\n");
    let auth = files.get_mut("auth.dae").unwrap();
    *auth = auth.replace(
        " enabled: true",
        " geodata_download_detour: 'proxy'\n enabled: true",
    );
}

#[tokio::test]
async fn the_download_route_names_a_current_group_by_id() {
    let fixture = Fixture::new_with_state(Access::Admin, setup_group).await;
    let groups = fixture.get("/api/v1/groups").await;
    let proxy = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["name"] == "proxy")
        .unwrap()["id"]
        .clone();
    let seeded = fixture.get(SETTINGS).await["geodata"].clone();
    assert_eq!(
        seeded["download"],
        json!({"route": "group", "group_id": proxy})
    );
    let before = fixture.get(SETTINGS).await;
    error(
        patch_settings(
            &fixture,
            json!({"geodata": {"download": {"route": "group", "group_id": "missing"}}}),
        )
        .await,
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    error(
        patch_settings(
            &fixture,
            json!({"geodata": {"download": {"route": "group", "group_id": "missing"}},
                "log": {"buffered_records": 1}}),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    assert_eq!(fixture.get(SETTINGS).await["geodata"], before["geodata"]);
    let routed = ok(patch_settings(
        &fixture,
        json!({"geodata": {"download": {"route": "routing"}}}),
    )
    .await)
    .await;
    assert_eq!(
        routed["geodata"]["download"],
        json!({"route": "routing", "group_id": null})
    );
    assert_eq!(routed["geodata"]["source"], "default");
    let grouped = ok(patch_settings(
        &fixture,
        json!({"geodata": {"download": {"route": "group", "group_id": proxy}}}),
    )
    .await)
    .await;
    assert_eq!(
        grouped["geodata"]["download"],
        json!({"route": "group", "group_id": proxy})
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn rejected_activation_records_failed_last_reload() {
    let server = AssetServer::new(geosite("new.example"), geoip(203), false).await;
    let fixture = fixture(server.address, false).await;
    fixture
        .reject_reloads
        .store(ReloadBehavior::Reject as u8, Ordering::SeqCst);
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(terminal["error"]["details"]["stage"], "reload_rejected");
    fixture.assert_last_reload(&terminal).await;
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn identical_bytes_keep_the_loaded_files_and_generation() {
    let server = AssetServer::new(geosite("old.example"), geoip(198), false).await;
    let fixture = fixture(server.address, false).await;
    let old = fixture.get(GEO).await;
    let inode = |name: &str| std::fs::metadata(fixture.path(name)).unwrap().ino();
    let before = [inode("state/geosite.dat"), inode("state/geoip.dat")];
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(terminal["result"]["assets"], old["assets"]);
    assert_eq!(
        [inode("state/geosite.dat"), inode("state/geoip.dat")],
        before
    );
    assert_eq!(std::fs::read_dir(fixture.path("state")).unwrap().count(), 2);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.get("/api/v1/runtime").await["last_reload"],
        Value::Null
    );
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn identical_bytes_over_a_changed_loaded_file_are_not_a_success() {
    let server = AssetServer::new(geosite("old.example"), geoip(198), false).await;
    let fixture = fixture(server.address, false).await;
    std::fs::write(fixture.path("state/geosite.dat"), geosite("edited.example")).unwrap();
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(
        terminal["error"]["details"]["stage"], "asset_conflict",
        "{terminal}"
    );
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("edited.example")
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
    server.close().await;
}

/// A reload keeps a router whose asset bytes are unchanged, so it can go on
/// naming a packaged file after an identical copy starts shadowing it.
#[tokio::test]
async fn an_update_replaces_the_resolved_copy_of_an_unchanged_loaded_file() {
    let server = AssetServer::new(geosite("new.example"), geoip(198), false).await;
    let fixture = fixture(server.address, false).await;
    let packaged = fixture.path("packaged");
    std::fs::create_dir_all(&packaged).unwrap();
    for name in ["geosite.dat", "geoip.dat"] {
        std::fs::copy(fixture.path(&format!("state/{name}")), packaged.join(name)).unwrap();
    }
    {
        let state = fixture.state.upgrade().unwrap();
        let config = state.config.read().await.clone();
        let requirements = crate::routing::GeoRequirements::for_traffic(&config.routing.rules)
            .union(&DnsRouter::geo_requirements(&config.dns));
        let geo = crate::routing::GeoSourceSet::load_captured(&requirements, &packaged, |path| {
            std::fs::read(path).map(Arc::from)
        })
        .unwrap();
        *state.traffic_router.write().await =
            Router::from_config_with_geo_sources(&config.routing, &geo).unwrap();
    }
    let geoip_inode = std::fs::metadata(fixture.path("state/geoip.dat"))
        .unwrap()
        .ino();
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(
        terminal["result"]["assets"][0]["sha256"],
        crate::configuration::digest(&geosite("new.example"))
    );
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("new.example")
    );
    assert_eq!(
        std::fs::read(packaged.join("geosite.dat")).unwrap(),
        geosite("old.example")
    );
    assert_eq!(
        std::fs::metadata(fixture.path("state/geoip.dat"))
            .unwrap()
            .ino(),
        geoip_inode
    );
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "block");
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "direct");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 1);
    let again = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&again).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 1);
    fixture.shutdown().await;
    server.close().await;
}

/// OpenWrt's default data directory `/var/lib/honk` sits under `/var -> tmp`.
#[tokio::test]
async fn an_update_writes_through_a_linked_data_directory_prefix() {
    let server = AssetServer::new(geosite("new.example"), geoip(198), false).await;
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        std::os::unix::fs::symlink("tmp", root.join("state")).unwrap();
        setup(root, files, server.address)
    })
    .await;
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(
        std::fs::read(fixture.path("tmp/geosite.dat")).unwrap(),
        geosite("new.example")
    );
    assert!(
        std::fs::symlink_metadata(fixture.path("state"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "block");
    fixture.shutdown().await;
    server.close().await;
}
