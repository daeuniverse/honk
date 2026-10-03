use super::*;
use tokio::io::AsyncReadExt;

const NODES: &str = "/api/v1/nodes";
const PROVIDERS: &str = "/api/v1/providers";
const LINK: &str = "socks5://127.0.0.1:11080#discarded-link-name";

fn create_node(fixture: &Fixture, name: &str, link: &str) -> reqwest::RequestBuilder {
    fixture
        .request(Method::POST, NODES)
        .json(&json!({"name":name,"link":link}))
}

async fn created(response: Response, collection: &str) -> Value {
    assert_eq!(response.status(), StatusCode::CREATED);
    headers(&response);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    let value: Value = response.json().await.unwrap();
    assert_eq!(
        location,
        format!("/api/v1/{collection}/{}", value["id"].as_str().unwrap())
    );
    value
}

/// The rejected resource and fields, without the shared management failure state.
fn rejected(body: &Value) -> Value {
    let mut details = body["error"]["details"].clone();
    let details_map = details.as_object_mut().unwrap();
    for key in ["stage", "written", "durability_confirmed", "committed"] {
        details_map.remove(key);
    }
    details
}

async fn reload(fixture: &Fixture) {
    let operation = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
}

#[tokio::test]
async fn node_management_commits_disk_catalog_and_generation_before_success() {
    let fixture = Fixture::new(Access::Admin, false).await;
    std::fs::write(
        fixture.path("editable.dae"),
        "group { managed { filter: name(keyword:managed) } }\n",
    )
    .unwrap();
    reload(&fixture).await;
    let before = fixture.get(CONFIG).await;
    let capabilities = fixture.get("/api/v1/capabilities").await;
    assert_eq!(capabilities["resources"]["nodes"]["can_manage"], true);
    assert_eq!(capabilities["resources"]["providers"]["can_manage"], true);
    let node = created(
        create_node(&fixture, "managed-node", LINK)
            .send()
            .await
            .unwrap(),
        "nodes",
    )
    .await;
    let after = fixture.get(CONFIG).await;
    assert_ne!(after["revision"], before["revision"]);
    assert_ne!(after["generation_id"], before["generation_id"]);
    let text = std::fs::read_to_string(fixture.path("main.dae")).unwrap();
    assert!(text.starts_with(&fixture.originals["main.dae"]));
    assert!(text.contains(LINK));
    assert_eq!(node["name"], "managed-node");
    assert_eq!(node["protocol"], "socks5");
    assert!(node["subscription_tag"].is_null());
    assert_eq!(node["provider_id"], "inline");
    let inline = fixture.get(&format!("{PROVIDERS}/inline")).await;
    assert_eq!(inline["kind"], "inline");
    assert_eq!(inline["node_count"], 1);
    assert!(
        fixture.get(PROVIDERS).await["providers"]
            .as_array()
            .unwrap()
            .contains(&inline)
    );
    error(
        fixture
            .request(Method::POST, &format!("{PROVIDERS}/inline/refresh"))
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    error(
        fixture
            .request(Method::DELETE, &format!("{PROVIDERS}/inline"))
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    let catalog = fixture.get(NODES).await;
    assert!(catalog["nodes"].as_array().unwrap().contains(&node));
    assert!(
        catalog["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|node| matches!(node["protocol"].as_str(), Some("direct" | "block")))
            .all(|node| node["provider_id"].is_null())
    );
    let groups = fixture.get("/api/v1/groups").await;
    assert_eq!(node["group_ids"], json!([groups[0]["id"]]));
    let path = format!("{NODES}/{}", node["id"].as_str().unwrap());
    assert_eq!(
        ok(fixture.request(Method::DELETE, &path).send().await.unwrap()).await,
        json!({"deleted":1})
    );
    let removed = fixture.get(CONFIG).await;
    assert_ne!(removed["generation_id"], after["generation_id"]);
    assert!(
        !std::fs::read_to_string(fixture.path("main.dae"))
            .unwrap()
            .contains(LINK)
    );
    assert!(
        !fixture.get(NODES).await["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == node["id"])
    );
    assert_eq!(
        ok(fixture.request(Method::DELETE, &path).send().await.unwrap()).await,
        json!({"deleted":0})
    );
    assert_eq!(fixture.get(CONFIG).await, removed);
    assert_eq!(
        fixture.get(&format!("{PROVIDERS}/inline")).await["node_count"],
        0
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn queued_delete_cannot_change_committed_creation_response() {
    use crate::native_api::management::{Mutation, NodeCreate};

    let fixture = Fixture::new_custom(Access::Admin, false, |_, originals| {
        originals.insert(
            "editable.dae",
            "group { managed { filter: name(keyword:managed) } }\n".into(),
        );
    })
    .await;
    let group_id = fixture.get("/api/v1/groups").await[0]["id"].clone();
    let node_id = honk_config::node::Node::from_share_link(LINK).unwrap().id;
    {
        let state = fixture.state.upgrade().unwrap();
        let enqueue = |mutation| {
            let (response, wait) = oneshot::channel();
            fixture
                .service
                .enqueue(super::super::Work::Manage {
                    mutation,
                    catalog: Arc::clone(&state.observation.core.catalog),
                    group_manager: Arc::clone(&state.group_manager),
                    alive_set: Arc::clone(&state.alive_set),
                    response,
                })
                .unwrap();
            wait
        };
        let creation = enqueue(Mutation::CreateNode(NodeCreate {
            name: "managed-node".into(),
            link: LINK.into(),
        }));
        let deletion = enqueue(Mutation::DeleteNode(node_id.to_string()));

        // Leave the create receipt unread until the next mutation has committed.
        let deleted = timeout(WAIT, deletion)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .response();
        assert_eq!(deleted.status(), StatusCode::OK);
        let deleted = axum::body::to_bytes(deleted.into_body(), 65536)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&deleted).unwrap(),
            json!({"deleted":1})
        );
        assert!(
            !fixture.get(NODES).await["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == node_id.to_string())
        );

        let created = timeout(WAIT, creation)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .response();
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(created.headers()["location"], format!("{NODES}/{node_id}"));
        let created = axum::body::to_bytes(created.into_body(), 65536)
            .await
            .unwrap();
        let created: Value = serde_json::from_slice(&created).unwrap();
        assert_eq!(created["id"], node_id.to_string());
        assert_eq!(created["name"], "managed-node");
        assert_eq!(created["protocol"], "socks5");
        assert_eq!(created["group_ids"], json!([group_id]));
        assert_eq!(created["provider_id"], "inline");
        assert!(created["subscription_tag"].is_null());
    }
    fixture.shutdown().await;
}

#[tokio::test]
async fn management_rejects_duplicate_invalid_and_foreign_source_entries_without_writing() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let included = "node { included: 'socks5://127.0.0.1:11081' }\n";
    std::fs::write(fixture.path("editable.dae"), included).unwrap();
    reload(&fixture).await;
    let node = created(
        create_node(&fixture, "managed", LINK).send().await.unwrap(),
        "nodes",
    )
    .await;
    std::fs::write(
        fixture.path("editable.dae"),
        format!("{included}group {{ pinned {{ final: managed }} }}\n"),
    )
    .unwrap();
    reload(&fixture).await;
    let before = fixture.get(CONFIG).await;
    let original = disk(fixture.directory.path());
    let referenced = error(
        fixture
            .request(
                Method::DELETE,
                &format!("{NODES}/{}", node["id"].as_str().unwrap()),
            )
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    let pinned = fixture.get("/api/v1/groups").await;
    let pinned = pinned
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["name"] == "pinned")
        .unwrap();
    assert_eq!(
        referenced["error"]["details"]["groups"],
        json!([pinned["id"]])
    );
    assert_eq!(referenced["error"]["details"]["written"], false);
    error(
        create_node(&fixture, "managed", "socks5://127.0.0.1:11082")
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    error(
        create_node(&fixture, "other-name", LINK)
            .send()
            .await
            .unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    for body in [
        json!({"name":"","link":LINK}),
        json!({"name":"n".repeat(65),"link":LINK}),
        json!({"name":"bounded","link":""}),
        json!({"name":"bounded","link":"x".repeat(8193)}),
    ] {
        error(
            fixture
                .request(Method::POST, NODES)
                .json(&body)
                .send()
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }
    for body in [
        json!({"name":"unsafe\nnode { injected: x }","link":LINK}),
        json!({"name":"unsupported","link":"private-unknown://secret-password@host"}),
        json!({"name":"managed","link":LINK,"unknown":true}),
    ] {
        let status = if body.get("unknown").is_some() {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        };
        let response = fixture
            .request(Method::POST, NODES)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        let text = response.text().await.unwrap();
        assert!(!text.contains("secret-password") && !text.contains("injected"));
    }
    error(
        fixture
            .request(Method::POST, NODES)
            .header("content-type", "application/json")
            .body(" ".repeat(65537))
            .send()
            .await
            .unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_too_large",
    )
    .await;
    let rows = fixture.get(NODES).await;
    for name in ["included", "direct", "block"] {
        let row = rows["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap();
        error(
            fixture
                .request(
                    Method::DELETE,
                    &format!("{NODES}/{}", row["id"].as_str().unwrap()),
                )
                .send()
                .await
                .unwrap(),
            StatusCode::NOT_FOUND,
            "capability_not_supported",
        )
        .await;
    }
    error(
        fixture
            .request(Method::DELETE, "/api/v1/providers/inline")
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), original);
    assert_eq!(fixture.get(CONFIG).await, before);
    assert!(
        rows["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == node["id"])
    );
    fixture.shutdown().await;
    let fixture = Fixture::new(Access::Metadata, false).await;
    assert_eq!(
        fixture.get("/api/v1/capabilities").await["resources"]["nodes"]["can_manage"],
        false
    );
    let refused = error(
        create_node(&fixture, "denied", LINK).send().await.unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    assert_eq!(refused["error"]["details"]["reason"], "writes_disabled");
    fixture.shutdown().await;
    let mut fixture = Fixture::new(Access::Admin, false).await;
    fixture.coordinator.take().unwrap().shutdown().await;
    let refused = error(
        create_node(&fixture, "stopped", LINK).send().await.unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    assert_eq!(
        refused["error"]["details"]["reason"],
        "configuration_unavailable"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn delete_request_errors_and_source_drift_are_not_retryable() {
    let fixture = Fixture::new(Access::Admin, false).await;
    for path in [format!("{NODES}/unknown"), format!("{PROVIDERS}/unknown")] {
        for (request, status, code) in [
            (
                fixture.request(Method::DELETE, &format!("{path}?x=1")),
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                fixture.request(Method::DELETE, &path).body("{}"),
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                fixture
                    .request(Method::DELETE, &path)
                    .body(" ".repeat(65537)),
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
            ),
        ] {
            let response = request.send().await.unwrap();
            assert!(response.headers().get("retry-after").is_none());
            error(response, status, code).await;
        }
    }
    let node = created(
        create_node(&fixture, "drifted", LINK).send().await.unwrap(),
        "nodes",
    )
    .await;
    let path = format!("{NODES}/{}", node["id"].as_str().unwrap());
    let (entered, release) = fixture.pause_before_replace();
    let request = fixture.request(Method::DELETE, &path).send();
    let drift = async {
        entered.await.unwrap();
        let main = fixture.path("main.dae");
        let text = std::fs::read_to_string(&main).unwrap();
        std::fs::write(&main, format!("{text}\n")).unwrap();
        release.send(()).unwrap();
    };
    let (response, ()) = tokio::join!(request, drift);
    let response = response.unwrap();
    assert!(response.headers().get("retry-after").is_none());
    error(response, StatusCode::CONFLICT, "state_conflict").await;
    reload(&fixture).await;

    let (entered, release) = fixture.pause_before_replace();
    let request = fixture.request(Method::DELETE, &path).send();
    let full = async {
        entered.await.unwrap();
        let state = fixture.state.upgrade().unwrap();
        let mut queued = Vec::new();
        loop {
            let (response, wait) = oneshot::channel();
            let work = super::super::Work::Manage {
                mutation: crate::native_api::management::Mutation::DeleteNode("unknown".into()),
                catalog: Arc::clone(&state.observation.core.catalog),
                group_manager: Arc::clone(&state.group_manager),
                alive_set: Arc::clone(&state.alive_set),
                response,
            };
            if fixture.service.enqueue(work).is_err() {
                break;
            }
            queued.push(wait);
        }
        let response = fixture.request(Method::DELETE, &path).send().await.unwrap();
        assert!(response.headers().get("retry-after").is_some());
        error(
            response,
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
        )
        .await;
        release.send(()).unwrap();
        queued
    };
    let (response, _queued) = tokio::join!(request, full);
    assert_eq!(ok(response.unwrap()).await, json!({"deleted":1}));
    fixture.shutdown().await;
}

#[tokio::test]
async fn management_waits_for_activation_and_survives_http_disconnect() {
    let mut fixture = Fixture::new(Access::Admin, true).await;
    let before = fixture.get(CONFIG).await;
    let request = create_node(&fixture, "waited", LINK);
    let mut requests = JoinSet::new();
    requests.spawn(async move { request.send().await.unwrap() });
    let release = fixture.next_reload().await;
    assert!(
        requests.try_join_next().is_none(),
        "success escaped before actual reload"
    );
    assert_eq!(fixture.get(CONFIG).await, before);
    assert!(
        std::fs::read_to_string(fixture.path("main.dae"))
            .unwrap()
            .contains(LINK)
    );
    release.send(()).unwrap();
    created(
        timeout(WAIT, requests.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        "nodes",
    )
    .await;
    let (entered, resume) = fixture.pause_before_replace();
    let body = json!({"name":"disconnected","link":"socks5://127.0.0.1:11082"}).to_string();
    let mut socket = TcpStream::connect(fixture.addr).await.unwrap();
    socket.write_all(format!("POST {NODES} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", fixture.addr, body.len()).as_bytes()).await.unwrap();
    timeout(WAIT, entered).await.unwrap().unwrap();
    socket.shutdown().await.unwrap();
    drop(socket);
    resume.send(()).unwrap();
    fixture.next_reload().await.send(()).unwrap();
    fixture.barrier().await;
    assert!(
        fixture.get(NODES).await["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["name"] == "disconnected")
    );
    assert!(
        std::fs::read_to_string(fixture.path("main.dae"))
            .unwrap()
            .contains("disconnected")
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
}

#[tokio::test]
async fn management_fences_disk_and_activation_and_reports_written_state() {
    let mut fixture = Fixture::new(Access::Admin, true).await;
    let before = fixture.get(CONFIG).await;
    let external = format!("{}# external editor\n", fixture.originals["main.dae"]);
    std::fs::write(fixture.path("main.dae"), &external).unwrap();
    let response = error(
        create_node(&fixture, "conflicting", LINK)
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    assert_eq!(response["error"]["details"]["written"], false);
    assert_eq!(
        std::fs::read_to_string(fixture.path("main.dae")).unwrap(),
        external
    );
    std::fs::write(fixture.path("main.dae"), &fixture.originals["main.dae"]).unwrap();
    let request = create_node(&fixture, "not-activated", LINK);
    let mut requests = JoinSet::new();
    requests.spawn(async move { request.send().await.unwrap() });
    let release = fixture.next_reload().await;
    // Model loss of source authority after durable replacement, before the real reload fence.
    fixture.service.sources.invalidate();
    release.send(()).unwrap();
    let failure = error(
        timeout(WAIT, requests.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    let details = &failure["error"]["details"];
    assert_eq!(details["written"], true);
    assert_eq!(details["durability_confirmed"], true);
    assert_eq!(details["committed"], false);
    assert_eq!(details["stage"], "reload_rejected");
    assert!(
        std::fs::read_to_string(fixture.path("main.dae"))
            .unwrap()
            .contains(LINK)
    );
    assert!(
        !fixture.get(NODES).await["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["name"] == "not-activated")
    );
    assert_eq!(
        fixture.get("/api/v1/runtime").await["generation"]["active_id"],
        before["generation_id"]
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn management_write_and_phase_failures_do_not_mutate_sources() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let before = fixture.get(CONFIG).await;
    let saved = fixture.path("saved.dae");
    std::fs::rename(fixture.path("main.dae"), &saved).unwrap();
    std::os::unix::fs::symlink(&saved, fixture.path("main.dae")).unwrap();
    let failure = error(
        create_node(&fixture, "unsafe-target", LINK)
            .send()
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    assert_eq!(failure["error"]["details"]["written"], false);
    assert_eq!(failure["error"]["details"]["stage"], "write");
    assert_eq!(failure["error"]["details"]["reason"], "unsafe_path");
    std::fs::remove_file(fixture.path("main.dae")).unwrap();
    std::fs::rename(saved, fixture.path("main.dae")).unwrap();
    let (_phase, receiver) = tokio::sync::watch::channel(crate::control::EnginePhase::Draining);
    fixture.service.attach_phase(receiver);
    let failure = error(
        fixture
            .request(Method::DELETE, "/api/v1/nodes/unknown")
            .send()
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    assert_eq!(failure["error"]["details"]["committed"], false);
    assert_eq!(
        std::fs::read_to_string(fixture.path("main.dae")).unwrap(),
        fixture.originals["main.dae"]
    );
    assert_eq!(fixture.get(CONFIG).await, before);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn managed_provider_stays_unfetched_until_explicit_refresh_and_deletes_its_nodes() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    std::fs::write(
        fixture.path("editable.dae"),
        "group { provider-only { filter: subtag(managed-provider) } }\n",
    )
    .unwrap();
    reload(&fixture).await;
    let url = format!(
        "http://{}/private-path?token=private-provider-token",
        origin.local_addr().unwrap()
    );
    std::fs::create_dir_all(fixture.path("state")).unwrap();
    let store = crate::subscription::SubscriptionStore::in_dir(&fixture.path("state"));
    let cached = honk_config::subscription::Subscription {
        url: url.clone(),
        ..Default::default()
    };
    store
        .store_content(&cached, "socks5://127.0.0.1:11084#cached-old-node".into())
        .await
        .unwrap();
    let input = json!({"name":"managed-provider","kind":"subscription","url":url});
    let before = fixture.get(CONFIG).await;
    let provider = created(
        fixture
            .request(Method::POST, PROVIDERS)
            .json(&input)
            .send()
            .await
            .unwrap(),
        "providers",
    )
    .await;
    let id = provider["id"].as_str().unwrap();
    let path = format!("{PROVIDERS}/{id}");
    assert_eq!(provider["node_count"], 0);
    assert_eq!(provider["status"], "stale");
    assert!(provider["updated_at"].is_null());
    assert_eq!(provider["url_redacted"], url);
    assert_eq!(provider["name"], "managed-provider");
    assert_eq!(fixture.get(&path).await, provider);
    let after = fixture.get(CONFIG).await;
    assert_ne!(after["revision"], before["revision"]);
    assert_ne!(after["generation_id"], before["generation_id"]);
    assert!(
        std::fs::read_to_string(fixture.path("main.dae"))
            .unwrap()
            .contains(&url)
    );
    assert!(
        timeout(Duration::from_millis(100), origin.accept())
            .await
            .is_err()
    );
    error(
        fixture
            .request(Method::POST, PROVIDERS)
            .json(&input)
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    let file_url = error(
        fixture
            .request(Method::POST, PROVIDERS)
            .json(&json!({"name":"bad","kind":"subscription","url":"file:///private"}))
            .send()
            .await
            .unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    assert_eq!(
        rejected(&file_url),
        json!({"resource":"/providers","field":"url"})
    );
    assert!(!file_url.to_string().contains("private"));
    created(
        create_node(&fixture, "unrelated", "socks5://127.0.0.1:11085")
            .send()
            .await
            .unwrap(),
        "nodes",
    )
    .await;
    assert_eq!(
        fixture.get(&path).await,
        provider,
        "an unrelated node write must not restore the deferred provider cache"
    );
    let snapshot = fixture.get(CONFIG).await;
    let main = snapshot["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["kind"] == "main")
        .unwrap();
    let text = format!(
        "{}# unrelated source edit\n",
        main["content"].as_str().unwrap()
    );
    let operation = accepted(fixture.replace(main, &text).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
    assert_eq!(
        fixture.get(&path).await,
        provider,
        "raw source writes must preserve owner-backed initial deferral"
    );
    reload(&fixture).await;
    assert!(
        timeout(Duration::from_millis(100), origin.accept())
            .await
            .is_err()
    );
    assert_eq!(fixture.get(&path).await, provider);
    let operation = accepted(
        fixture
            .request(Method::POST, &format!("{path}/refresh"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    let (mut socket, _) = timeout(WAIT, origin.accept()).await.unwrap().unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(socket.read_u8().await.unwrap());
    }
    let body = "socks5://127.0.0.1:11083#provider-node";
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    drop(socket);
    let refreshed = fixture.terminal(&operation).await;
    assert_eq!(refreshed["status"], "succeeded");
    assert_eq!(refreshed["result"]["node_count"], 1);
    assert_eq!(fixture.get(&path).await["status"], "ok");
    let rows = fixture.get(NODES).await;
    let node = rows["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["provider_id"] == id)
        .unwrap();
    assert_eq!(fixture.get("/api/v1/groups").await[0]["member_count"], 1);
    error(
        fixture
            .request(
                Method::DELETE,
                &format!("{NODES}/{}", node["id"].as_str().unwrap()),
            )
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    assert_eq!(
        ok(fixture.request(Method::DELETE, &path).send().await.unwrap()).await,
        json!({"deleted":1})
    );
    assert_eq!(fixture.get("/api/v1/groups").await[0]["member_count"], 0);
    assert!(
        !std::fs::read_to_string(fixture.path("main.dae"))
            .unwrap()
            .contains(&url)
    );
    assert!(
        !fixture.get(NODES).await["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["provider_id"] == id)
    );
    assert_eq!(
        ok(fixture.request(Method::DELETE, &path).send().await.unwrap()).await,
        json!({"deleted":0})
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn managed_provider_aliases_cannot_transfer_existing_runtime_identity() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/same-fetch", origin.local_addr().unwrap());
    let first = created(
        fixture
            .request(Method::POST, PROVIDERS)
            .json(&json!({"name":"first","kind":"subscription","url":url}))
            .send()
            .await
            .unwrap(),
        "providers",
    )
    .await;
    std::fs::write(
        fixture.path("locked.dae"),
        format!("subscription {{ included: '{url}' }}\n"),
    )
    .unwrap();
    reload(&fixture).await;
    let before = fixture.get(CONFIG).await;
    let files = disk(fixture.directory.path());
    let reloads = fixture.reloads.load(Ordering::SeqCst);
    error(
        fixture
            .request(Method::POST, PROVIDERS)
            .json(&json!({"name":"third","kind":"subscription","url":url}))
            .send()
            .await
            .unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    error(
        fixture
            .request(
                Method::DELETE,
                &format!("{PROVIDERS}/{}", first["id"].as_str().unwrap()),
            )
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), files);
    assert_eq!(fixture.get(CONFIG).await, before);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), reloads);
    let providers = fixture.get(PROVIDERS).await;
    assert!(
        providers["providers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == first["id"])
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn db_store_rejected_management_reports_nothing_written() {
    let fixture = Fixture::new_db(Access::Admin).await;
    fixture
        .reject_reloads
        .store(ReloadBehavior::Reject as u8, Ordering::SeqCst);
    let failure = error(
        create_node(&fixture, "not-recorded", LINK)
            .send()
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    let details = &failure["error"]["details"];
    assert_eq!(details["stage"], "reload_rejected");
    assert_eq!(details["written"], false);
    assert!(details.get("durability_confirmed").is_none());
    assert_eq!(details["committed"], false);
    assert_eq!(
        fixture.database.as_ref().unwrap().head(),
        Ok(Some(1)),
        "a rejected activation records no revision"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn db_store_degraded_management_reports_recorded_write() {
    let fixture = Fixture::new_db(Access::Admin).await;
    fixture
        .reject_reloads
        .store(ReloadBehavior::Degraded as u8, Ordering::SeqCst);
    let failure = error(
        create_node(&fixture, "degraded", LINK)
            .send()
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
    )
    .await;
    let details = &failure["error"]["details"];
    assert_eq!(details["stage"], "reload_degraded");
    assert_eq!(details["written"], true);
    assert_eq!(details["durability_confirmed"], true);
    assert_eq!(details["committed"], true);
    assert!(details["active_generation_id"].is_string(), "{details}");
    assert_eq!(fixture.database.as_ref().unwrap().head(), Ok(Some(2)));
    fixture.shutdown().await;
}

#[tokio::test]
async fn managed_provider_options_are_advertised_validated_and_written() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let capabilities = fixture.get("/api/v1/capabilities").await;
    // The fixture turns store_subscribe off, so cache is not offered.
    assert_eq!(
        capabilities["resources"]["providers"]["create_options"],
        json!({"update_interval": 86400, "user_agent": format!("honk/{}", env!("CARGO_PKG_VERSION"))})
    );
    for invalid in [
        json!({"kind":"other"}),
        json!({"name":""}),
        json!({"name":"n".repeat(65)}),
        json!({"name":"invalid tag"}),
        json!({"url":""}),
        json!({"url":format!("https://example.test/{}", "x".repeat(4096))}),
        json!({"update_interval": 31_536_001}),
        json!({"update_interval": -1}),
        json!({"user_agent": ""}),
        json!({"user_agent": "agent\r\nX-Injected: 1"}),
        json!({"user_agent": "é"}),
        json!({"user_agent": "a".repeat(257)}),
        json!({"cache": false}),
    ] {
        let mut input =
            json!({"name":"optioned","kind":"subscription","url":"https://example.test/sub"});
        input
            .as_object_mut()
            .unwrap()
            .extend(invalid.as_object().unwrap().clone());
        let response = fixture
            .request(Method::POST, PROVIDERS)
            .json(&input)
            .send()
            .await
            .unwrap();
        let (status, code) = if invalid.get("cache").is_some() {
            (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_value")
        } else {
            (StatusCode::BAD_REQUEST, "invalid_request")
        };
        error(response, status, code).await;
    }
    // Printable ASCII passes validation, but no dae quote can hold both quote characters.
    let unquotable = fixture
        .request(Method::POST, PROVIDERS)
        .json(&json!({
            "name": "optioned",
            "kind": "subscription",
            "url": "https://example.test/sub",
            "user_agent": "PRIVATE'\"agent"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unquotable.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: Value = unquotable.json().await.unwrap();
    assert_eq!(
        rejected(&body),
        json!({"resource":"/providers","fields":["name","url","user_agent"]})
    );
    assert!(!body.to_string().contains("PRIVATE"), "{body}");
    assert!(
        !std::fs::read_to_string(fixture.path("main.dae"))
            .unwrap()
            .contains("optioned")
    );
    created(
        fixture
            .request(Method::POST, PROVIDERS)
            .json(&json!({
                "name": "optioned",
                "kind": "subscription",
                "url": "https://example.test/sub",
                "update_interval": 3600,
                "user_agent": "clash.meta"
            }))
            .send()
            .await
            .unwrap(),
        "providers",
    )
    .await;
    let main = std::fs::read_to_string(fixture.path("main.dae")).unwrap();
    assert!(
        main.contains(
            "    optioned: 'https://example.test/sub' {\n        ua: 'clash.meta'\n        interval: 3600s\n    }\n"
        ),
        "{main}"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn managed_provider_options_follow_assets_subscription_defaults() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, originals| {
        originals.get_mut("main.dae").unwrap().push_str(
            "assets {\n subscription {\n  ua: 'clash.meta'\n  interval: 3600s\n  cache: false\n }\n}\n",
        );
    })
    .await;
    let capabilities = fixture.get("/api/v1/capabilities").await;
    assert_eq!(
        capabilities["resources"]["providers"]["create_options"],
        json!({"update_interval": 3600, "user_agent": "clash.meta"})
    );
    // The built-in default differs from the assets one, so it is written.
    created(
        fixture
            .request(Method::POST, PROVIDERS)
            .json(&json!({
                "name": "daily",
                "kind": "subscription",
                "url": "https://example.test/sub",
                "update_interval": 86400
            }))
            .send()
            .await
            .unwrap(),
        "providers",
    )
    .await;
    let main = std::fs::read_to_string(fixture.path("main.dae")).unwrap();
    assert!(
        main.contains("    daily: 'https://example.test/sub' {\n        interval: 86400s\n    }\n"),
        "{main}"
    );
    fixture.shutdown().await;
}
