use super::*;

/// The rejected resource and fields, without the shared management failure state.
fn rejected(body: &Value) -> Value {
    let mut details = body["error"]["details"].clone();
    let details_map = details.as_object_mut().unwrap();
    for key in ["stage", "written", "durability_confirmed", "committed"] {
        details_map.remove(key);
    }
    details
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
        json!({"name":"机".repeat(65)}),
        json!({"name":"bad\ttag"}),
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
        let body = error(response, status, code).await;
        if invalid.get("name").is_some() {
            assert_eq!(
                rejected(&body),
                json!({"resource":"/providers","field":"name"})
            );
        }
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
async fn managed_provider_names_outside_bare_tags_are_written_quoted() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let longest = "机".repeat(64);
    for (name, url) in [
        ("机场", "https://example.test/airport"),
        (longest.as_str(), "https://example.test/longest"),
    ] {
        let provider = created(
            fixture
                .request(Method::POST, PROVIDERS)
                .json(&json!({"name":name,"kind":"subscription","url":url}))
                .send()
                .await
                .unwrap(),
            "providers",
        )
        .await;
        assert_eq!(provider["name"], name);
        let main = std::fs::read_to_string(fixture.path("main.dae")).unwrap();
        assert!(main.contains(&format!("    '{name}': '{url}'\n")), "{main}");
        let path = format!("{PROVIDERS}/{}", provider["id"].as_str().unwrap());
        assert_eq!(fixture.get(&path).await["name"], name);
        reload(&fixture).await;
        assert_eq!(fixture.get(&path).await["name"], name);
    }
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
