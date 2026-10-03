use super::*;

fn patch(
    fixture: &Fixture,
    group: &Value,
    revision: &str,
    body: &Value,
) -> reqwest::RequestBuilder {
    patch_if_match(fixture, group, &format!("\"{revision}\""), body)
}

fn patch_if_match(
    fixture: &Fixture,
    group: &Value,
    condition: &str,
    body: &Value,
) -> reqwest::RequestBuilder {
    fixture
        .request(
            Method::PATCH,
            &format!("/api/v1/groups/{}/config", group["id"].as_str().unwrap()),
        )
        .header("if-match", condition)
        .header("content-type", "application/json-patch+json")
        .body(body.to_string())
}

#[tokio::test]
async fn group_patch_keeps_source_bytes_and_separates_group_revision_from_disk_hash() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let source_text = "# Explicitly writable include.\r\ngroup {\r\n G { policy: fallback }\r\n G {\r\n  policy: 'fallback' # earlier\r\n  policy: \"selector\" # winner\r\n  final: direct\r\n }\r\n}\r\n";
    std::fs::write(fixture.path("editable.dae"), source_text).unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let groups = fixture.get("/api/v1/groups").await;
    let group = &groups[0];
    let before = fixture.get(CONFIG).await;
    let revision = before["revision"].as_str().unwrap();
    let source = source(&before, source_text);
    let body = json!([{ "op":"replace", "path":"/policy", "value":{"kind":"fallback","native":"fallback"} }]);
    let original = disk(fixture.directory.path());
    error(
        patch(
            &fixture,
            group,
            source["content_sha256"].as_str().unwrap(),
            &body,
        )
        .send()
        .await
        .unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "stale_revision",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), original);
    let failed = json!([{ "op":"replace", "path":"/config/tolerance", "value":100 }, {"op":"test","path":"/config/final_outbound","value":"block"}]);
    error(
        patch(&fixture, group, revision, &failed)
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), original);
    let unsupported =
        json!([{"op":"replace","path":"/config/check_url","value":"ftp://127.0.0.1/"}]);
    error(
        patch(&fixture, group, revision, &unsupported)
            .send()
            .await
            .unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    let excessive = json!(vec![
        json!({"op":"test","path":"/config/final_outbound","value":"direct"});
        33
    ]);
    error(
        patch(&fixture, group, revision, &excessive)
            .send()
            .await
            .unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_too_large",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), original);
    let external = format!("{source_text}# external editor\r\n");
    std::fs::write(fixture.path("editable.dae"), &external).unwrap();
    // The configuration revision still matches `If-Match`, so the moved source is a conflict.
    error(
        patch(&fixture, group, revision, &body)
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(fixture.path("editable.dae")).unwrap(),
        external
    );
    std::fs::write(fixture.path("editable.dae"), source_text).unwrap();
    let operation = accepted(
        patch(&fixture, group, revision, &body)
            .header("idempotency-key", "group-patch")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(operation["kind"], "group_update");
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded");
    let expected = source_text.replace("\"selector\"", "\"fallback\"");
    let written = disk(fixture.directory.path());
    assert_eq!(
        std::fs::read_to_string(fixture.path("editable.dae")).unwrap(),
        expected
    );
    for name in ["main.dae", "auth.dae", "locked.dae"] {
        assert_eq!(
            std::fs::read_to_string(fixture.path(name)).unwrap(),
            fixture.originals[name]
        );
    }
    let after = fixture.get(CONFIG).await;
    assert_eq!(terminal["result"]["group_id"], group["id"]);
    assert_eq!(terminal["result"]["config_revision"], after["revision"]);
    assert_ne!(after["revision"], before["revision"]);
    let replay = accepted(
        patch(&fixture, group, revision, &body)
            .header("idempotency-key", "group-patch")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(replay["operation_id"], operation["operation_id"]);
    assert_eq!(disk(fixture.directory.path()), written);
    error(
        patch(&fixture, group, revision, &body)
            .send()
            .await
            .unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "stale_revision",
    )
    .await;
    let current_group = fixture
        .get(&format!("/api/v1/groups/{}", group["id"].as_str().unwrap()))
        .await;
    assert_eq!(current_group["policy"]["kind"], "fallback");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
}

#[tokio::test]
async fn group_config_document_carries_the_etag_that_patch_compares() {
    let fixture = Fixture::new(Access::Admin, false).await;
    std::fs::write(
        fixture.path("editable.dae"),
        "group {\n G {\n  policy: selector\n  final: direct\n }\n}\n",
    )
    .unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let group = &fixture.get("/api/v1/groups").await[0];
    let path = format!("/api/v1/groups/{}", group["id"].as_str().unwrap());
    let detail = fixture.request(Method::GET, &path).send().await.unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    assert!(detail.headers().get("etag").is_none());
    let detail: Value = detail.json().await.unwrap();
    let revision = detail["config_revision"].as_str().unwrap();
    let document = fixture
        .request(Method::GET, &format!("{path}/config"))
        .send()
        .await
        .unwrap();
    assert_eq!(document.status(), StatusCode::OK);
    assert_eq!(
        document.headers()["etag"],
        format!("\"{revision}\"").as_str()
    );
    let document: Value = document.json().await.unwrap();
    assert_eq!(
        document,
        json!({"policy": detail["policy"], "config": detail["config"]})
    );
    let body = json!([{"op":"replace","path":"/config/final_outbound","value":"block"}]);
    let legacy = fixture
        .request(Method::PATCH, &path)
        .header("if-match", format!("\"{revision}\""))
        .header("content-type", "application/json-patch+json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert!(legacy.status().is_client_error());
    let operation = accepted(
        patch(&fixture, group, revision, &body)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
    let document = fixture
        .request(Method::GET, &format!("{path}/config"))
        .send()
        .await
        .unwrap();
    assert_ne!(
        document.headers()["etag"],
        format!("\"{revision}\"").as_str()
    );
    let document: Value = document.json().await.unwrap();
    assert_eq!(document["config"]["final_outbound"], "block");
    fixture.shutdown().await;
}

#[tokio::test]
async fn group_patch_body_errors_precede_the_stale_revision() {
    let fixture = Fixture::new(Access::Admin, false).await;
    std::fs::write(
        fixture.path("editable.dae"),
        "group {\n G {\n  policy: selector\n  final: direct\n }\n}\n",
    )
    .unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let group = &fixture.get("/api/v1/groups").await[0];
    let test = json!({"op":"test","path":"/config/final_outbound","value":"direct"});
    for (body, status, code) in [
        (json!([]), StatusCode::BAD_REQUEST, "invalid_request"),
        (json!({}), StatusCode::BAD_REQUEST, "invalid_request"),
        (
            json!([test, {"op":"merge","path":"/policy","value":null}]),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!([{"op":"replace","path":"/config/tolerance"}]),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!([{"op":"move","path":"/config/tolerance"}]),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!([{"op":"remove","path":"/config/members"}]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_value",
        ),
        (
            json!(vec![test.clone(); 33]),
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
        ),
    ] {
        error(
            patch(&fixture, group, "stale", &body).send().await.unwrap(),
            status,
            code,
        )
        .await;
    }
    error(
        patch(&fixture, group, "stale", &json!([test]))
            .send()
            .await
            .unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "stale_revision",
    )
    .await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn group_patch_evaluates_a_malformed_or_wildcard_if_match() {
    let fixture = Fixture::new(Access::Admin, false).await;
    std::fs::write(
        fixture.path("editable.dae"),
        "group {\n G {\n  policy: selector\n  final: direct\n }\n}\n",
    )
    .unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let group = &fixture.get("/api/v1/groups").await[0];
    let original = disk(fixture.directory.path());
    let change =
        json!([{"op":"replace","path":"/policy","value":{"kind":"fallback","native":"fallback"}}]);
    for condition in ["\"PRIVATE", "W/", "\"a\" \"b\""] {
        let malformed = error(
            patch_if_match(&fixture, group, condition, &change)
                .send()
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
        assert_eq!(
            malformed["error"]["details"],
            json!({"header":"if-match","kind":"malformed"})
        );
        assert!(!malformed.to_string().contains("PRIVATE"), "{malformed}");
    }
    assert_eq!(disk(fixture.directory.path()), original);
    // `*` holds for any revision, so a failed `test` is a conflict where a stale tag is a 412.
    let failed = json!([{"op":"test","path":"/config/final_outbound","value":"block"}]);
    error(
        patch(&fixture, group, "stale", &failed)
            .send()
            .await
            .unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "stale_revision",
    )
    .await;
    error(
        patch_if_match(&fixture, group, "*", &failed)
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), original);
    let operation = accepted(
        patch_if_match(&fixture, group, "*", &change)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
    assert_ne!(disk(fixture.directory.path()), original);
    fixture.shutdown().await;
}

#[tokio::test]
async fn group_patch_without_writable_source_is_unsupported() {
    let fixture = Fixture::new(Access::Metadata, false).await;
    let refused = error(
        patch(
            &fixture,
            &json!({"id":"any-group"}),
            "revision",
            &json!([{"op":"replace","path":"/config/tolerance","value":100}]),
        )
        .send()
        .await
        .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    assert_eq!(
        refused["error"]["details"],
        json!({"reason":"writes_disabled"})
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn group_patch_in_credential_source_is_unsupported() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, files| {
        files
            .get_mut("auth.dae")
            .unwrap()
            .push_str("group {\n L {\n  policy: selector\n  final: direct\n }\n}\n");
    })
    .await;
    let group = &fixture.get("/api/v1/groups").await[0];
    let detail = fixture
        .get(&format!("/api/v1/groups/{}", group["id"].as_str().unwrap()))
        .await;
    assert_eq!(detail["capabilities"]["mutable_config"], json!([]));
    let refused = error(
        patch(
            &fixture,
            group,
            detail["config_revision"].as_str().unwrap(),
            &json!([{"op":"replace","path":"/config/tolerance","value":100}]),
        )
        .send()
        .await
        .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    assert_eq!(
        refused["error"]["details"],
        json!({"reason":"listener_secret_source"})
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn group_patch_check_url_rewrites_the_source_and_reregisters_the_probe() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let source_text = "# Explicitly writable include.\ngroup {\n G {\n  policy: fallback\n  check_url: 'http://old.test/' # replaced\n }\n}\n";
    std::fs::write(fixture.path("editable.dae"), source_text).unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let group = &fixture.get("/api/v1/groups").await[0];
    let path = format!("/api/v1/groups/{}", group["id"].as_str().unwrap());
    let detail = fixture.get(&path).await;
    assert!(
        detail["capabilities"]["mutable_config"]
            .as_array()
            .unwrap()
            .contains(&json!("check_url"))
    );
    assert_eq!(detail["config"]["check_url"], "http://old.test/");
    let revision = detail["config_revision"].as_str().unwrap();
    let invalid =
        json!([{"op":"replace","path":"/config/check_url","value":"https://user@new.test/"}]);
    error(
        patch(&fixture, group, revision, &invalid)
            .send()
            .await
            .unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    // PATCH writes the normalized form, so the source, GET, `test` and the probe agree.
    let mut previous = "http://old.test/";
    for (url, written) in [
        ("http://example.test", "http://example.test/"),
        ("https://example.test/p#frag", "https://example.test/p"),
        ("http://Example.Test:80/x", "http://example.test/x"),
    ] {
        let revision = fixture.get(&path).await["config_revision"]
            .as_str()
            .unwrap()
            .to_owned();
        let body = json!([
            {"op":"test","path":"/config/check_url","value":previous},
            {"op":"replace","path":"/config/check_url","value":url}
        ]);
        let operation = accepted(
            patch(&fixture, group, &revision, &body)
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
        assert_eq!(
            std::fs::read_to_string(fixture.path("editable.dae")).unwrap(),
            source_text.replace("http://old.test/", written)
        );
        assert_eq!(fixture.get(&path).await["config"]["check_url"], written);
        let state = fixture.state.upgrade().unwrap();
        assert_eq!(
            state.alive_set.group_check_urls(),
            vec![("G".to_owned(), written.to_owned())]
        );
        previous = url;
    }
}

#[tokio::test]
async fn score_group_reports_and_accepts_no_tolerance() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let source_text = "# Explicitly writable include.\ngroup {\n S {\n  policy: score\n }\n}\n";
    std::fs::write(fixture.path("editable.dae"), source_text).unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let group = &fixture.get("/api/v1/groups").await[0];
    let detail = fixture
        .get(&format!("/api/v1/groups/{}", group["id"].as_str().unwrap()))
        .await;
    assert_eq!(detail["policy"]["kind"], "score");
    assert_eq!(detail["config"]["tolerance"], Value::Null);
    let mutable = detail["capabilities"]["mutable_config"].as_array().unwrap();
    assert!(mutable.contains(&json!("policy")));
    assert!(!mutable.contains(&json!("tolerance")));
    let original = disk(fixture.directory.path());
    error(
        patch(
            &fixture,
            group,
            detail["config_revision"].as_str().unwrap(),
            &json!([{"op":"replace","path":"/config/tolerance","value":100}]),
        )
        .send()
        .await
        .unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), original);
    fixture.shutdown().await;
}

#[tokio::test]
async fn automatic_group_pin_is_reported_and_cleared_per_network() {
    let fixture = Fixture::new_custom(Access::Metadata, false, |_, files| {
        files.insert(
            "editable.dae",
            "node {\n a: 'socks5://127.0.0.1:1081'\n b: 'socks5://127.0.0.1:1082'\n}\ngroup {\n auto {\n  filter: name(a, b)\n  policy: fallback\n }\n manual {\n  filter: name(a, b)\n  policy: select\n }\n}\n"
                .into(),
        );
    })
    .await;
    let groups = fixture.get("/api/v1/groups").await;
    let id = |name: &str| {
        groups
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["name"] == name)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (auto, manual) = (id("auto"), id("manual"));
    let group = fixture.get(&format!("/api/v1/groups/{auto}")).await;
    assert_eq!(group["capabilities"]["can_override"], true);
    let member = group["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["name"] == "b")
        .unwrap()["id"]
        .clone();
    let selection = format!("/api/v1/groups/{auto}/selection");
    let pinned = ok(fixture
        .request(Method::PUT, &selection)
        .header("content-type", "application/json")
        .body(json!({ "member_id": member, "network": "both" }).to_string())
        .send()
        .await
        .unwrap())
    .await;
    assert_eq!(pinned["source"], "override");
    let group = fixture.get(&format!("/api/v1/groups/{auto}")).await;
    for network in ["tcp", "udp"] {
        let current = &group["runtime"]["selection"][network];
        assert_eq!(current["member_id"], member);
        assert_eq!(current["source"], "override");
    }

    let clear = |query: &'static str, path: &str| {
        fixture.request(Method::DELETE, &format!("{path}{query}"))
    };
    let cleared = ok(clear("?network=tcp", &selection).send().await.unwrap()).await;
    assert_eq!(cleared["network"], "tcp");
    assert_ne!(cleared["selection"]["tcp"]["source"], "override");
    assert_eq!(cleared["selection"]["udp"]["member_id"], member);
    assert_eq!(cleared["selection"]["udp"]["source"], "override");
    assert_ne!(cleared["selection_revision"], pinned["selection_revision"]);
    let again = ok(clear("?network=tcp", &selection).send().await.unwrap()).await;
    assert_eq!(again["selection"], cleared["selection"]);
    assert_eq!(again["selection_revision"], cleared["selection_revision"]);

    let manual = fixture.get(&format!("/api/v1/groups/{manual}")).await;
    assert_eq!(manual["capabilities"]["can_override"], false);
    error(
        clear(
            "",
            &format!(
                "/api/v1/groups/{}/selection",
                manual["id"].as_str().unwrap()
            ),
        )
        .send()
        .await
        .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;

    // The UDP pin still stands; an activation drops it.
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let group = fixture.get(&format!("/api/v1/groups/{auto}")).await;
    for network in ["tcp", "udp"] {
        assert_ne!(group["runtime"]["selection"][network]["source"], "override");
    }
    fixture.shutdown().await;
}

#[tokio::test]
async fn group_config_reports_unset_options_as_null_and_null_clears_them() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let source_text = "# Explicitly writable include.\ngroup {\n U {\n  policy: urltest\n }\n}\n";
    std::fs::write(fixture.path("editable.dae"), source_text).unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let group = &fixture.get("/api/v1/groups").await[0];
    let path = format!("/api/v1/groups/{}", group["id"].as_str().unwrap());
    let edit = |body: Value| {
        let (fixture, group, path) = (&fixture, group, &path);
        async move {
            let revision = fixture.get(path).await["config_revision"]
                .as_str()
                .unwrap()
                .to_owned();
            let operation = accepted(
                patch(fixture, group, &revision, &body)
                    .send()
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
            fixture.get(path).await["config"].take()
        }
    };
    // Honk still applies its defaults; the group itself sets neither option.
    let mut detail = fixture.get(&path).await;
    let mutable = detail["capabilities"]["mutable_config"].as_array().unwrap();
    assert!(mutable.contains(&json!("tolerance")));
    let config = detail["config"].take();
    assert_eq!(config["tolerance"], Value::Null);
    assert_eq!(config["interrupt_connections"], Value::Null);
    let config = edit(json!([
        {"op":"test","path":"/config/interrupt_connections","value":null},
        {"op":"replace","path":"/config/interrupt_connections","value":false},
        {"op":"test","path":"/config/tolerance","value":null},
        {"op":"replace","path":"/config/tolerance","value":50}
    ]))
    .await;
    assert_eq!(config["interrupt_connections"], false);
    assert_eq!(config["tolerance"], 50);
    let config = edit(json!([
        {"op":"replace","path":"/config/interrupt_connections","value":null},
        {"op":"copy","from":"/config/interrupt_connections","path":"/config/tolerance"}
    ]))
    .await;
    assert_eq!(config["interrupt_connections"], Value::Null);
    assert_eq!(config["tolerance"], Value::Null);
    assert_eq!(
        std::fs::read_to_string(fixture.path("editable.dae")).unwrap(),
        source_text
    );
}

#[tokio::test]
async fn groups_list_in_declaration_order() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let source_text = "group {\n zeta { policy: fallback }\n alpha { policy: fallback }\n mid { policy: fallback }\n alpha { policy: fallback }\n}\n";
    std::fs::write(fixture.path("editable.dae"), source_text).unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let groups = fixture.get("/api/v1/groups").await;
    let names: Vec<_> = groups
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["zeta", "mid", "alpha"]);
}
