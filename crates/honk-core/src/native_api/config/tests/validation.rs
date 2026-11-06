use super::*;

#[tokio::test]
async fn validation_is_offline_readonly_and_distinguishes_syntax_from_full_admission() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let candidate = format!(
        "{}subscription {{ private: 'http://{}/private-candidate-token' }}\n",
        fixture.originals["main.dae"],
        listener.local_addr().unwrap()
    );
    let before = fixture.get(CONFIG).await;
    let before_disk = disk(fixture.directory.path());
    for (mode, content, valid) in [
        ("syntax", candidate.as_str(), true),
        // Full admission of a subscription that was never fetched passes with a
        // warning and, above all, without fetching it.
        ("full", candidate.as_str(), true),
        ("full", fixture.originals["main.dae"].as_str(), true),
        ("syntax", "routing {\n", false),
    ] {
        let result = ok(fixture.validate(mode, content).send().await.unwrap()).await;
        assert_eq!(result["valid"], valid);
        assert_eq!(result["generation_id"], before["generation_id"]);
        chrono::DateTime::parse_from_rfc3339(result["validated_at"].as_str().unwrap()).unwrap();
        if !valid {
            diagnostics(
                &result["diagnostics"],
                "candidate",
                "private-candidate-token",
            );
        } else if mode == "full" && content == candidate.as_str() {
            let rows = result["diagnostics"].as_array().unwrap();
            let notice = rows
                .iter()
                .find(|row| row["code"] == "subscription-not-fetched")
                .unwrap();
            assert_eq!(notice["level"], "warning");
            assert!(!result.to_string().contains("private-candidate-token"));
        }
        assert_eq!(disk(fixture.directory.path()), before_disk);
        assert_eq!(fixture.get(CONFIG).await, before);
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(!fixture.path("state").exists());
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn full_validation_applies_include_overrides_before_semantic_admission() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, sources| {
        sources.insert("editable.dae", "global { nfqueue_enable: false }\n".into());
    })
    .await;
    let candidate =
        fixture.originals["main.dae"].replace("nfqueue_enable: false", "nfqueue_enable: invalid");
    let syntax = ok(fixture.validate("syntax", &candidate).send().await.unwrap()).await;
    assert_eq!(syntax["valid"], false);
    let full = ok(fixture.validate("full", &candidate).send().await.unwrap()).await;
    assert_eq!(full["valid"], true, "{full}");
    assert!(
        !full["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["level"] == "error")
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn full_validation_checks_unused_structure_without_applying_unused_settings() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let baseline = ok(fixture
        .validate("full", &fixture.originals["main.dae"])
        .send()
        .await
        .unwrap())
    .await;
    let request = |content| {
        fixture.request(Method::POST, VALIDATE).json(&json!({
            "mode":"full","sources":[
                {"id":"main","path":"main.dae","content":fixture.originals["main.dae"]},
                {"id":"unused","path":"unused.dae","content":content}
            ]
        }))
    };
    let unused =
        "global { nfqueue_enable: invalid }\nunknown {}\ninclude { '/not-opened/private.dae' }\n";
    let valid = ok(request(unused).send().await.unwrap()).await;
    assert_eq!(valid["valid"], true, "{valid}");
    assert_eq!(valid["diagnostics"], baseline["diagnostics"]);
    for malformed in [
        "global {",
        "include { nested.dae {} }",
        "dns {\n use_host: 'unterminated\n}\n",
    ] {
        let invalid = ok(request(malformed).send().await.unwrap()).await;
        assert_eq!(invalid["valid"], false);
        diagnostics(&invalid["diagnostics"], "unused", "nested.dae");
    }
    fixture.shutdown().await;
}

#[tokio::test]
async fn full_validation_counts_unused_sources_with_every_host_materialization() {
    let fixture = Fixture::new(Access::Admin, false).await;
    std::fs::write(fixture.path("hosts.rules"), "full:alias.test 192.0.2.1\n").unwrap();
    let candidate = |count| {
        let hosts = (0..count)
            .map(|index| {
                format!(
                    " use_host: '{}/{}hosts.rules'\n",
                    fixture.directory.path().display(),
                    "./".repeat(index)
                )
            })
            .collect::<String>();
        format!(
            "global {{ nfqueue_enable: false }}\nrouting {{ fallback: direct }}\ndns {{\n{hosts}}}\n"
        )
    };
    let full = candidate(31);
    let without_unused = ok(fixture.validate("full", &full).send().await.unwrap()).await;
    assert_eq!(without_unused["valid"], true, "{without_unused}");
    let request = |content| {
        fixture.request(Method::POST, VALIDATE).json(&json!({
            "mode":"full","sources":[
                {"id":"main","path":"main.dae","content":content},
                {"id":"unused","path":"unused.dae","content":"# unused\n"}
            ]
        }))
    };
    let at_limit = ok(request(candidate(30)).send().await.unwrap()).await;
    assert_eq!(at_limit["valid"], true, "{at_limit}");
    error(
        request(full).send().await.unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_too_large",
    )
    .await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn validation_ids_and_display_paths_cannot_expand_file_authority() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let before = fixture.get(CONFIG).await;
    let before_disk = disk(fixture.directory.path());
    for sources in [
        json!([{"id":"same","content":""},{"id":"same","content":""}]),
        json!([{"id":"a","path":"main.dae","content":""},{"id":"b","path":"main.dae","content":""}]),
        json!([{"id":"../private","content":""}]),
    ] {
        error(
            fixture
                .request(Method::POST, VALIDATE)
                .json(&json!({"mode":"syntax","sources":sources}))
                .send()
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }
    for (entry, path) in [
        ("main.dae", "../outside.dae"),
        ("main.dae", "/tmp/outside.dae"),
        ("main.dae", "notes.txt"),
        ("editable.dae", "locked.dae"),
    ] {
        error(
            fixture
                .request(Method::POST, VALIDATE)
                .json(&json!({
                    "mode":"full","sources":[
                        {"id":"main","path":entry,"content":fixture.originals["main.dae"]},
                        {"id":"outside","path":path,"content":"# no authority\n"}
                    ]
                }))
                .send()
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }
    let syntax = ok(fixture.request(Method::POST, VALIDATE).json(&json!({
        "mode":"syntax","sources":[{"id":"label","path":"../not-opened.dae","content":"routing { fallback: direct }"}]
    })).send().await.unwrap()).await;
    assert_eq!(syntax["valid"], true);
    // Returned entry-relative paths can be echoed without expanding file authority.
    let echoed_sources: Vec<_> = before["sources"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["content"].is_string())
        .map(|row| json!({"id":row["id"],"path":row["path"],"content":row["content"]}))
        .collect();
    assert!(echoed_sources.len() > 1);
    let echoed = ok(fixture
        .request(Method::POST, VALIDATE)
        .json(&json!({
            "mode":"full","sources":echoed_sources
        }))
        .send()
        .await
        .unwrap())
    .await;
    assert_eq!(echoed["valid"], true);
    let outside = tempfile::tempdir().unwrap();
    let outside_path = outside.path().join("outside.dae");
    std::fs::write(&outside_path, "routing { fallback: block }").unwrap();
    let escaping = fixture.originals["main.dae"]
        .replace("'locked.dae'", &format!("'{}'", outside_path.display()));
    let result = ok(fixture.validate("full", &escaping).send().await.unwrap()).await;
    assert_eq!(result["valid"], false);
    diagnostics(
        &result["diagnostics"],
        "candidate",
        outside_path.to_str().unwrap(),
    );
    assert_eq!(disk(fixture.directory.path()), before_disk);
    assert_eq!(fixture.get(CONFIG).await, before);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn request_bodies_name_the_failing_field_without_echoing_values() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let before_disk = disk(fixture.directory.path());
    for (method, path, body, details) in [
        (
            Method::POST,
            VALIDATE,
            json!({"mode":"syntax","sources":[{"content":["PRIVATE"]}]}),
            json!({"field":"sources[0].content","kind":"wrong_type"}),
        ),
        (
            Method::POST,
            "/api/v1/nodes",
            json!({"name":"PRIVATE"}),
            json!({
                "field":"link","kind":"missing","stage":"admission",
                "written":false,"committed":false
            }),
        ),
        (
            Method::PUT,
            "/api/v1/groups/PRIVATE/selection",
            json!({"member_id":"PRIVATE","network":"PRIVATE"}),
            json!({"field":"network","kind":"invalid_value"}),
        ),
    ] {
        let response = fixture
            .request(method, path)
            .json(&body)
            .send()
            .await
            .unwrap();
        let body = error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
        assert_eq!(body["error"]["details"], details, "{path}");
        assert!(!body.to_string().contains("PRIVATE"), "{body}");
    }
    assert_eq!(disk(fixture.directory.path()), before_disk);
    fixture.shutdown().await;
}

#[tokio::test]
async fn failed_reload_reports_the_diagnostics_of_the_file_on_disk() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let before = fixture.get(CONFIG).await;
    std::fs::write(
        fixture.path("locked.dae"),
        "group {\n  broken {\n    policy: honk\n  }\n}\n",
    )
    .unwrap();
    let operation = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed");
    let error = &terminal["error"];
    assert_eq!(error["code"], "unsupported_value");
    assert_eq!(error["message"], "Configuration validation failed");
    let rows = error["details"]["diagnostics"].as_array().unwrap();
    let row = rows.iter().find(|row| row["level"] == "error").unwrap();
    assert_eq!(row["code"], "unsupported-policy", "{row}");
    assert_eq!(row["line"], 3, "{row}");
    assert_eq!(
        row["source_id"],
        source(&before, &fixture.originals["locked.dae"])["id"],
        "{row}"
    );
    assert!(!error.to_string().contains(SECRET));
    fixture.assert_last_reload(&terminal).await;
    assert_eq!(fixture.get(CONFIG).await, before);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn failed_reload_keeps_the_error_rows_when_warnings_overflow_details() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let ignored: String = (0..20)
        .map(|index| format!("ignored{index} {{\n}}\n"))
        .collect();
    std::fs::write(
        fixture.path("locked.dae"),
        format!("{ignored}group {{\n  broken {{\n    policy: honk\n  }}\n}}\n"),
    )
    .unwrap();
    let operation = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    let rows = terminal["error"]["details"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("{terminal}"));
    assert!(rows.iter().all(|row| row["level"] == "error"), "{rows:?}");
    assert!(rows.iter().any(|row| row["code"] == "unsupported-policy"));
    fixture.assert_last_reload(&terminal).await;
    fixture.shutdown().await;
}

#[cfg(target_os = "linux")]
const XDP: &str = "\ndatapath {\n backend: xdp\n direct: core\n interface {\n eth0: lan\n }\n}\n";

#[cfg(target_os = "linux")]
async fn xdp_fixture(database: bool) -> Fixture {
    let setup = |_: &Path, sources: &mut HashMap<&'static str, String>| {
        sources.get_mut("main.dae").unwrap().push_str(XDP);
    };
    if database {
        Fixture::new_db_custom(Access::Admin, setup).await
    } else {
        Fixture::new_custom(Access::Admin, false, setup).await
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn xdp_policy_rejection_preserves_files_database_and_runtime() {
    for database in [false, true] {
        let fixture = xdp_fixture(database).await;
        let original = &fixture.originals["main.dae"];
        let before = fixture.get(CONFIG).await;
        let main = source(&before, original);
        let tree = fixture.path(if database { "etc" } else { "" });
        let before_disk = disk(&tree);
        let before_rules = fixture.get("/api/v1/rules").await;
        let before_revisions = if database {
            Some(fixture.get("/api/v1/x-honk/config/revisions").await)
        } else {
            None
        };
        let mut candidates: Vec<_> = [
            "dport(443) -> direct(mark: 512)",
            "pname(browser) -> direct",
            "!pname(browser) -> direct",
            "mac(02:00:00:00:00:01) -> direct",
            "!mac(02:00:00:00:00:01) -> direct",
            "domain(example.com) -> direct",
            "!domain(example.com) -> direct",
        ]
        .into_iter()
        .map(|rule| original.replace("fallback: direct", &format!("{rule}\n fallback: direct")))
        .collect();
        candidates.extend([
            original.replace("fallback: direct", "fallback: direct(mark: 512)"),
            original.replace("dial_mode: ip", "dial_mode: domain"),
            original.replace("nfqueue_enable: false", "nfqueue_enable: true"),
            original.replace("dial_mode: ip", "dial_mode: ip\n lan_interface: eth9"),
            original.replace("dial_mode: ip", "dial_mode: ip\n wan_interface: eth9"),
        ]);
        for (index, candidate) in candidates.iter().enumerate() {
            let syntax = ok(fixture.validate("syntax", candidate).send().await.unwrap()).await;
            assert_eq!(syntax["valid"], true, "{syntax}");
            let full = ok(fixture.validate("full", candidate).send().await.unwrap()).await;
            assert_eq!(full["valid"], false, "{full}");
            assert!(full["diagnostics"].as_array().unwrap().iter().any(|row| {
                row["code"] == "invalid-datapath-config" && row["source_id"] == "candidate"
            }));
            let failure = error(
                fixture.replace(main, candidate).send().await.unwrap(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported_value",
            )
            .await;
            assert!(
                failure["error"]["details"]["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| {
                        row["code"] == "invalid-datapath-config" && row["source_id"] == main["id"]
                    })
            );
            assert_eq!(disk(&tree), before_disk);
            assert_eq!(fixture.get(CONFIG).await, before);
            assert_eq!(fixture.get("/api/v1/rules").await, before_rules);
            if let Some(revisions) = &before_revisions {
                assert_eq!(
                    fixture.get("/api/v1/x-honk/config/revisions").await,
                    *revisions
                );
                std::fs::write(tree.join("main.dae"), candidate).unwrap();
                let import_disk = disk(&tree);
                error(
                    fixture
                        .request(Method::POST, "/api/v1/x-honk/config/import")
                        .header("idempotency-key", format!("xdp-policy-{index}"))
                        .json(&json!({"replace":true}))
                        .send()
                        .await
                        .unwrap(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "unsupported_value",
                )
                .await;
                assert_eq!(disk(&tree), import_disk);
                assert_eq!(
                    fixture.get("/api/v1/x-honk/config/revisions").await,
                    *revisions
                );
                assert_eq!(fixture.database.as_ref().unwrap().head(), Ok(Some(1)));
                assert_eq!(fixture.get(CONFIG).await, before);
                assert_eq!(fixture.get("/api/v1/rules").await, before_rules);
                std::fs::write(tree.join("main.dae"), original).unwrap();
            }
            assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
        }
        let endpoint = original
            .replace("direct: core", "direct: endpoint")
            .replace("dial_mode: ip", "dial_mode: domain")
            .replace(
                "fallback: direct",
                "domain(example.com) -> direct\n fallback: direct",
            );
        let full = ok(fixture.validate("full", &endpoint).send().await.unwrap()).await;
        assert_eq!(full["valid"], true, "{full}");
        assert_eq!(fixture.get(CONFIG).await, before);
        assert_eq!(disk(&tree), before_disk);
        assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
        fixture.shutdown().await;
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn xdp_device_changes_reject_before_persistence_but_effective_copy_and_policy_commit() {
    for database in [false, true] {
        let fixture = xdp_fixture(database).await;
        let original = &fixture.originals["main.dae"];
        let before = fixture.get(CONFIG).await;
        let main = source(&before, original);
        let tree = fixture.path(if database { "etc" } else { "" });
        let before_disk = disk(&tree);
        let before_rules = fixture.get("/api/v1/rules").await;
        for candidate in [
            original.replace(XDP, ""),
            original.replace("direct: core", "direct: endpoint"),
            original.replace("eth0: lan", "eth1: lan"),
            original.replace("eth0: lan", "eth0: wan"),
            original.replace("direct: core", "direct: core\n xsk_mode: zerocopy"),
        ] {
            let full = ok(fixture.validate("full", &candidate).send().await.unwrap()).await;
            assert_eq!(full["valid"], true, "{full}");
            assert!(full["diagnostics"].as_array().unwrap().iter().any(|row| {
                row["code"] == "restart-required"
                    && row["level"] == "warning"
                    && row["source_id"] == "candidate"
            }));
            let failure = error(
                fixture.replace(main, &candidate).send().await.unwrap(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported_value",
            )
            .await;
            assert!(
                failure["error"]["details"]["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| {
                        row["code"] == "restart-required"
                            && row["level"] == "error"
                            && row["source_id"] == main["id"]
                    })
            );
            assert_eq!(disk(&tree), before_disk);
            assert_eq!(fixture.get(CONFIG).await, before);
            assert_eq!(fixture.get("/api/v1/rules").await, before_rules);
            assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
            if let Some(store) = &fixture.database {
                assert_eq!(store.head(), Ok(Some(1)));
                assert_eq!(
                    fixture.get("/api/v1/x-honk/config/revisions").await["revisions"]
                        .as_array()
                        .unwrap()
                        .len(),
                    1
                );
            }
        }
        let copy = original.replace("direct: core", "direct: core\n xsk_mode: copy");
        let policy = copy.replace("\n xsk_mode: copy", "\n firewall {\n original {\n default: allow\n }\n forward {\n default: drop\n }\n }")
            .replace("fallback: direct", "fallback: block");
        for (index, candidate) in [copy, policy].iter().enumerate() {
            let full = ok(fixture.validate("full", candidate).send().await.unwrap()).await;
            assert_eq!(full["valid"], true, "{full}");
            assert!(
                !full["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["code"] == "restart-required")
            );
            let current = fixture.get(CONFIG).await;
            let current_main = current["sources"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == main["id"])
                .unwrap();
            let operation = accepted(
                fixture
                    .replace(current_main, candidate)
                    .send()
                    .await
                    .unwrap(),
            )
            .await;
            let terminal = fixture.terminal(&operation).await;
            assert_eq!(terminal["status"], "succeeded", "{terminal}");
            let after = fixture.get(CONFIG).await;
            assert_ne!(after["revision"], current["revision"]);
            assert_eq!(source(&after, candidate)["id"], main["id"]);
            if let Some(store) = &fixture.database {
                assert_eq!(store.head(), Ok(Some(index as i64 + 2)));
                assert_eq!(
                    std::fs::read_to_string(tree.join("main.dae")).unwrap(),
                    *original
                );
            } else {
                assert_eq!(
                    std::fs::read_to_string(tree.join("main.dae")).unwrap(),
                    *candidate
                );
            }
        }
        let trace = ok(fixture
            .request(Method::POST, "/api/v1/routing/trace")
            .json(&json!({"input":{"network":"tcp","dst_ip":"198.51.100.20","dst_port":443}}))
            .send()
            .await
            .unwrap())
        .await;
        assert_eq!(trace["evaluations"][0]["outbound"], "block");
        assert_eq!(fixture.reloads.load(Ordering::SeqCst), 2);
        fixture.shutdown().await;
    }
}
