use super::*;

#[tokio::test]
async fn created_nodes_list_only_canonical_configured_stream_transport() {
    let fixture = Fixture::new(Access::Admin, false).await;
    for (name, link, protocol, transport) in [
        (
            "ws",
            "trojan://private-password@127.0.0.1:443?type=ws&path=%2Fprivate-path",
            "trojan",
            Some("ws"),
        ),
        (
            "grpc",
            "vmess://eyJ2IjoiMiIsInBzIjoiZ3JwYyIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOiI0NDMiLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsImFpZCI6IjAiLCJuZXQiOiJncnBjIiwicGF0aCI6InByaXZhdGUtc2VydmljZSIsInRscyI6InRscyJ9",
            "vmess",
            Some("grpc"),
        ),
        (
            "tcp",
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:443?type=tcp",
            "vless",
            Some("tcp"),
        ),
        ("plain", LINK, "socks5", None),
        (
            "xhttp",
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:443?type=xhttp&security=tls&path=%2Fprivate-path&extra=%7B%22noGRPCHeader%22%3Atrue%7D",
            "vless",
            Some("xhttp"),
        ),
        (
            "split",
            "trojan://private-password@127.0.0.1:443?type=splithttp&path=%2Fsplit-path",
            "trojan",
            Some("xhttp"),
        ),
    ] {
        let response = create_node(&fixture, name, link).send().await.unwrap();
        let status = response.status();
        assert_eq!(
            status,
            StatusCode::CREATED,
            "creating node {name}: {}",
            response.text().await.unwrap()
        );
        let node = created(response, "nodes").await;
        assert_eq!(node["protocol"], protocol);
        assert_eq!(node.get("stream_transport"), Some(&json!(transport)));
        assert!(
            fixture.get(NODES).await["nodes"]
                .as_array()
                .unwrap()
                .contains(&node)
        );
        for field in ["password", "host", "path", "extra", "link", "transport"] {
            assert!(node.get(field).is_none(), "{field}");
        }
        let encoded = node.to_string();
        for private in [
            "private-password",
            "private-path",
            "private-service",
            "split-path",
            "noGRPCHeader",
            "127.0.0.1",
            "b831381d-6324-4d53-ad4f-8cda48b30811",
        ] {
            assert!(!encoded.contains(private), "{private}");
        }
    }
    fixture.shutdown().await;
}

#[tokio::test]
async fn rejected_node_links_report_the_static_parser_reason() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let before = std::fs::read_to_string(fixture.path("main.dae")).unwrap();
    let link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:443?type=xhttp&security=tls&extra=%7B%22xPaddingBytes%22%3A%220-10%22%2C%22headers%22%3A%7B%22X-Secret%22%3A%22private-value%22%7D%7D";
    let response = create_node(&fixture, "bad-xhttp", link)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let text = response.text().await.unwrap();
    assert!(!text.contains("private-value"), "{text}");
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["error"]["code"], "unsupported_value");
    assert_eq!(
        body["error"]["message"],
        "XHTTP xPaddingBytes must stay within 1-8192"
    );
    assert_eq!(body["error"]["details"]["written"], false);
    assert_eq!(
        std::fs::read_to_string(fixture.path("main.dae")).unwrap(),
        before
    );
    fixture.shutdown().await;
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
async fn deleting_a_bound_chain_keeps_the_managed_source_unchanged() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, originals| {
        originals.get_mut("main.dae").unwrap().push_str(
            "node {\n via: front -> land\n front: 'socks5://127.0.0.1:1080'\n land: 'socks5://127.0.0.1:1081'\n}\ngroup { pool { filter: name(via) } }\n",
        );
    })
    .await;
    let before = fixture.get(CONFIG).await;
    let catalog = fixture.get(NODES).await;
    let node = catalog["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["name"] == "via")
        .unwrap();
    let id = node["id"].as_str().unwrap();
    let id_value = uuid::Uuid::parse_str(id).unwrap();
    {
        let active = fixture.active.read().await;
        let via = active
            .nodes
            .iter()
            .find(|node| node.id == id_value)
            .unwrap();
        assert!(!id_value.is_nil());
        assert_eq!(via.derive_id(), id_value);
        assert!(via.resolved_chain_hops().is_some());
    }
    error(
        fixture
            .request(Method::DELETE, &format!("{NODES}/{id}"))
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(fixture.path("main.dae")).unwrap(),
        fixture.originals["main.dae"]
    );
    let after = fixture.get(CONFIG).await;
    assert_eq!(after["revision"], before["revision"]);
    assert_eq!(after["generation_id"], before["generation_id"]);
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
async fn deleting_a_chain_from_the_main_source_is_refused_without_writing() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, originals| {
        originals.get_mut("main.dae").unwrap().push_str(
            "node {\n front: 'socks5://127.0.0.1:11081'\n land: 'socks5://127.0.0.1:11082'\n via: front -> land\n}\n",
        );
    })
    .await;
    let original = disk(fixture.directory.path());
    let rows = fixture.get(NODES).await;
    let chain = rows["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "via")
        .unwrap();
    error(
        fixture
            .request(
                Method::DELETE,
                &format!("{NODES}/{}", chain["id"].as_str().unwrap()),
            )
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), original);
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
