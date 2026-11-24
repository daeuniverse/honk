use super::*;

#[tokio::test]
async fn refusals_name_the_request_field_or_setting_but_not_the_target() {
    let mut proxy = Node::from_share_link("socks5://127.0.0.1:1080").unwrap();
    proxy.name = "front".into();
    let proxy_id = proxy.id.to_string();
    let mut land = Node::from_share_link("socks5://127.0.0.1:1081").unwrap();
    land.name = "land".into();
    let chain = Node::chain_from_nodes("via", &[&proxy, &land]).unwrap();
    let chain_id = chain.id.to_string();
    let mut config = Config::default();
    config.nodes.extend([proxy, land, chain]);
    config.global.tcp_check_url = vec!["http://127.0.0.1:8080/PRIVATE".into()];
    config.global.udp_check_dns = Some(Vec::new());
    let state = state(config).await;
    let direct = state
        .config
        .read()
        .await
        .nodes
        .iter()
        .find(|node| node.protocol() == honk_config::types::NodeProtocol::Direct)
        .unwrap()
        .id
        .to_string();
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let node = |id: &str| json!({"type":"node","node_id":id});
    for (index, (input, message, details)) in [
        (
            request(node(&direct), "tcp_connect", json!(["tcp"]), "ipv4"),
            "TCP connect probes do not apply to direct or block nodes",
            json!({"field":"kind","allowed":["http","dns"]}),
        ),
        (
            request(node(&chain_id), "tcp_connect", json!(["tcp"]), "ipv4"),
            "TCP connect probes need a node address, which chain nodes do not have",
            json!({"field":"kind","allowed":["http","dns"]}),
        ),
        (
            request(node(&proxy_id), "dns", json!(["tcp"]), "ipv4"),
            "No usable DNS check target is configured",
            json!({"field":"kind","settings":["udp_check_dns"]}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let error = refusal(&state, &input, index).await;
        assert_eq!(error["error"]["code"], "unsupported_value", "{error}");
        assert_eq!(error["error"]["message"], message);
        assert_eq!(error["error"]["details"], details);
        for private in ["PRIVATE", "10.9.8.7", "8080", "127.0.0.1"] {
            assert!(!error.to_string().contains(private), "{error}");
        }
    }
    stop.send(true).unwrap();
    worker.await.unwrap();
}

#[tokio::test]
async fn malformed_requests_name_the_field_but_not_the_value() {
    let state = state(Config::default()).await;
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let input = request(json!({"type":"node"}), "http", json!(["tcp"]), "ipv4");
    let key = "malformed".to_owned();
    let error = create(&state, http_request(&input, &key), &RequestId(key))
        .await
        .unwrap_err();
    let body = serde_json::to_value(&error).unwrap();
    assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(
        body["error"]["details"],
        json!({"field":"target.node_id","kind":"missing"})
    );
    let legal = request(
        json!({"type":"node","node_id":"retained"}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let retained = state
        .observation
        .operations
        .reserve(
            state.principal(),
            "POST",
            "/api/v1/probes",
            Some("conflict"),
            legal.to_string().as_bytes(),
            OperationKind::Probe,
        )
        .unwrap();
    let mut empty_transport = legal.clone();
    empty_transport["transport"] = json!([]);
    let malformed_requests = [input, empty_transport];
    for malformed in &malformed_requests {
        let error = create(
            &state,
            http_request(malformed, "conflict"),
            &RequestId("conflict".into()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    }
    let mut reservations = vec![retained];
    loop {
        match state.observation.operations.reserve(
            state.principal(),
            "POST",
            "/api/v1/probes",
            None,
            legal.to_string().as_bytes(),
            OperationKind::Probe,
        ) {
            Ok(reservation) => reservations.push(reservation),
            Err(error) => {
                assert_eq!(
                    error.into_response().status(),
                    StatusCode::SERVICE_UNAVAILABLE
                );
                break;
            }
        }
    }
    for malformed in &malformed_requests {
        let error = create(
            &state,
            http_request(malformed, "fresh"),
            &RequestId("fresh".into()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    }
    drop(reservations);
    stop.send(true).unwrap();
    worker.await.unwrap();
}

#[tokio::test]
async fn unsupported_kind_pairings_name_the_field() {
    let state = state(Config::default()).await;
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let node = json!({"type":"node","node_id":"node"});
    for (index, (input, field)) in [(
        request(node, "tcp_connect", json!(["udp"]), "ipv4"),
        "transport",
    )]
    .into_iter()
    .enumerate()
    {
        let key = format!("pairing-{index}");
        let error = create(&state, http_request(&input, &key), &RequestId(key))
            .await
            .unwrap_err();
        let body = serde_json::to_value(&error).unwrap();
        assert_eq!(
            error.into_response().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(body["error"]["code"], "unsupported_value", "{body}");
        assert_eq!(body["error"]["details"]["field"], field, "{body}");
    }
    stop.send(true).unwrap();
    worker.await.unwrap();
}

/// The admission error, or the operation's terminal error when planning passed.
async fn refusal(state: &Arc<NativeState>, input: &Value, index: usize) -> Value {
    let key = format!("refusal-{index}");
    match create(state, http_request(input, &key), &RequestId(key)).await {
        Ok(accepted) => {
            let accepted = body(accepted).await;
            terminal(state, accepted["operation_id"].as_str().unwrap()).await
        }
        Err(error) => serde_json::to_value(error).unwrap(),
    }
}

#[tokio::test]
async fn http_check_refusals_separate_a_missing_url_a_bad_url_and_a_bad_method() {
    let proxy = Node::from_share_link("socks5://127.0.0.1:1080").unwrap();
    let proxy_id = proxy.id.to_string();
    let urls = json!({"field":"kind","settings":["check_url","tcp_check_url"]});
    for (index, (url, method, message, details)) in [
        (
            None,
            "HEAD",
            "No HTTP check URL is configured",
            urls.clone(),
        ),
        (
            Some("ftp://PRIVATE.example/"),
            "HEAD",
            "The configured HTTP check URL is not usable",
            urls,
        ),
        (
            Some("http://example.test/"),
            "PRIVATE METHOD",
            "The configured HTTP check method is not usable",
            json!({"field":"kind","settings":["tcp_check_http_method"]}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut config = Config::default();
        config.nodes.push(proxy.clone());
        config.global.tcp_check_url = url.into_iter().map(String::from).collect();
        config.global.tcp_check_http_method = method.into();
        let state = state(config).await;
        let (stop, receiver) = watch::channel(false);
        let worker = state.observation.probes.start(Arc::clone(&state), receiver);
        let input = request(
            json!({"type":"node","node_id":proxy_id}),
            "http",
            json!(["tcp"]),
            "ipv4",
        );
        let error = refusal(&state, &input, index).await;
        assert_eq!(error["error"]["code"], "unsupported_value", "{error}");
        assert_eq!(error["error"]["message"], message);
        assert_eq!(error["error"]["details"], details);
        assert!(!error.to_string().contains("PRIVATE"), "{error}");
        stop.send(true).unwrap();
        worker.await.unwrap();
    }
}

#[test]
fn probe_request_rejects_explicit_null_members_and_caller_urls() {
    let input = request(
        json!({"type":"node","node_id":"node"}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let mut null_members = input.clone();
    null_members["members"] = Value::Null;
    assert!(serde_json::from_value::<ProbeRequest>(null_members).is_err());
    let mut arbitrary_url = input;
    arbitrary_url["url"] = json!("http://169.254.169.254/");
    assert!(serde_json::from_value::<ProbeRequest>(arbitrary_url).is_err());
}

#[tokio::test]
async fn probe_request_has_no_purpose_because_the_kind_fixes_it() {
    let state = state(Config::default()).await;
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let mut input = request(
        json!({"type":"node","node_id":"node"}),
        "dns",
        json!(["udp"]),
        "ipv4",
    );
    input["purpose"] = json!("dns");
    let key = "purpose".to_owned();
    let error = create(&state, http_request(&input, &key), &RequestId(key))
        .await
        .unwrap_err();
    let body = serde_json::to_value(&error).unwrap();
    assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(
        body["error"]["details"],
        json!({"field":"body","kind":"unknown_field"})
    );
    assert!(state.observation.probes.capability()["purposes"].is_null());
    stop.send(true).unwrap();
    worker.await.unwrap();
}
