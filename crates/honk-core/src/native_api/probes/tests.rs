use super::*;
use axum::body::{Body, to_bytes};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod lifecycle;
mod preparation;

async fn state(mut config: Config) -> Arc<NativeState> {
    config.global.nfqueue_enable = false;
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.allow_anonymous_loopback = true;

    config.ensure_builtin_nodes();
    let resolver = crate::dns::DnsResolver::new(&config.dns).unwrap();
    let forwarder = resolver.forwarder();
    let mut control = crate::control::ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        crate::routing::Router::new(&[], "direct").unwrap(),
        Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
        resolver,
        forwarder,
    )
    .unwrap();
    let state = NativeState::new(
        &mut control,
        "127.0.0.1:9527".parse().unwrap(),
        SystemTime::now(),
        std::time::Instant::now(),
    )
    .await
    .unwrap();
    control.publish_phase(crate::control::EnginePhase::Running);
    Arc::new(state)
}
fn request(target: Value, kind: &str, transport: Value, family: &str) -> Value {
    json!({"target":target,"kind":kind,"transport":transport,"ip_version":family,"warmth":"cold"})
}
fn http_request(value: &Value, key: &str) -> Request {
    Request::builder()
        .method("POST")
        .uri("/api/v1/probes")
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(Body::from(value.to_string()))
        .unwrap()
}
async fn body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 262144).await.unwrap()).unwrap()
}
async fn terminal(state: &NativeState, operation: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let value = body(state.observation.operations.get(operation).unwrap()).await;
            if matches!(value["status"].as_str(), Some("succeeded" | "failed")) {
                break value;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}
fn node(address: SocketAddr) -> Node {
    Node::from_share_link(&format!("socks5://{address}")).unwrap()
}
async fn receive_headers(socket: &mut tokio::net::TcpStream) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(socket.read_u8().await.unwrap());
    }
}

#[tokio::test]
async fn raw_probe_keeps_family_and_typed_health_out_of_http_ranking() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node = node(listener.local_addr().unwrap());
    let id = node.id;
    let mut config = Config::default();
    config.nodes.push(node);
    let state = state(config).await;
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut byte = [0];
        assert_eq!(
            socket.read(&mut byte).await.unwrap(),
            0,
            "raw TCP must not send proxy or HTTP bytes"
        );
    });
    let input = request(
        json!({"type":"node","node_id":id.to_string()}),
        "tcp_connect",
        json!(["tcp"]),
        "any",
    );
    let accepted = body(
        create(
            &state,
            http_request(&input, "raw"),
            &RequestId("raw".into()),
        )
        .await
        .unwrap(),
    )
    .await;
    let result = terminal(&state, accepted["operation_id"].as_str().unwrap()).await;
    assert_eq!(result["status"], "succeeded");
    assert_eq!(result["result"]["results"][0]["state"], "healthy");
    assert_eq!(result["result"]["results"][0]["warmth"], "cold");
    assert_eq!(result["result"]["results"][1]["state"], "unknown");
    assert_eq!(result["result"]["results"][1]["health_updated"], false);
    let samples = state.alive_set.health_observations(id);
    assert!(
        samples
            .iter()
            .any(|sample| sample.measurement == HealthMeasurement::TcpConnect
                && sample.ip_version == IpVersion::V4)
    );
    assert!(!samples.iter().any(
        |sample| sample.measurement == HealthMeasurement::HttpHeaders
            || sample.ip_version == IpVersion::V6
    ));
    peer.await.unwrap();
    stop.send(true).unwrap();
    worker.await.unwrap();
}

#[tokio::test]
async fn configured_nondefault_http_port_survives_request_drop_and_replay() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut config = Config::default();
    config.global.tcp_check_url = vec![format!("http://{address}/check")];

    let state = state(config).await;
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, wait_release) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut query = Vec::new();
        while !query.ends_with(b"\r\n\r\n") {
            query.push(socket.read_u8().await.unwrap());
        }
        entered.send(()).unwrap();
        wait_release.await.unwrap();
        socket
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
    });
    let input = request(
        json!({"type":"node","node_id":honk_config::config::DIRECT_NODE_ID.to_string()}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let accepted = body(
        create(
            &state,
            http_request(&input, "same"),
            &RequestId("first".into()),
        )
        .await
        .unwrap(),
    )
    .await;
    waiting.await.unwrap();
    // Removing today's catalog target cannot invalidate retained idempotent replay.
    let mut config = (**state.config.read().await).clone();
    config.nodes.clear();
    *state.config.write().await = Arc::new(config);
    let replay = body(
        create(
            &state,
            http_request(&input, "same"),
            &RequestId("replay".into()),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(accepted["operation_id"], replay["operation_id"]);
    release.send(()).unwrap();
    let result = terminal(&state, accepted["operation_id"].as_str().unwrap()).await;
    assert_eq!(result["result"]["results"][0]["state"], "healthy");
    assert!(result["result"]["results"][0]["latency_ms"].is_number());
    peer.await.unwrap();
    stop.send(true).unwrap();
    worker.await.unwrap();
}

#[tokio::test]
async fn duplicate_group_members_share_execution_but_keep_both_associations() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let leaf = node(listener.local_addr().unwrap());
    let mut config = Config::default();
    config.nodes.push(leaf.clone());
    for name in ["left", "right"] {
        config
            .groups
            .push(serde_json::from_value(json!({"name":name,"nodes":[leaf.id]})).unwrap());
    }
    config
        .groups
        .push(serde_json::from_value(json!({"name":"root","groups":["left","right"]})).unwrap());
    let state = state(config).await;
    let identity = state.observation.core.catalog.snapshot();
    let input = request(
        json!({"type":"group","group_id":identity.groups["root"]}),
        "tcp_connect",
        json!(["tcp"]),
        "ipv4",
    );
    let plan = capture(&state, serde_json::from_value(input).unwrap())
        .await
        .unwrap();
    let mut plan = prepare(plan).await.unwrap();
    let (_stop, receiver) = watch::channel(false);
    execute(
        &state,
        &mut plan,
        Instant::now() + Duration::from_secs(2),
        receiver,
    )
    .await
    .unwrap();
    assert_eq!(plan.result.results.len(), 2);
    assert_ne!(
        plan.result.results[0].member_id,
        plan.result.results[1].member_id
    );
    assert!(plan.result.results.iter().all(
        |row| row.state == "healthy" && row.resolved_leaf_node_id == Some(leaf.id.to_string())
    ));
    let _connection = listener.accept().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err(),
        "deduplicated leaf must execute only once"
    );
}

#[tokio::test]
async fn a_large_group_is_probed_by_member_subset_and_a_child_group_by_its_selected_leaf() {
    let nodes: Vec<Node> = (1..=300u16)
        .map(|port| node(SocketAddr::from(([127, 0, 0, 1], port))))
        .collect();
    let ids: Vec<_> = nodes.iter().map(|node| node.id.to_string()).collect();
    let mut config = Config::default();
    config.nodes.extend(nodes);
    for group in [
        json!({"name":"big","nodes":ids}),
        json!({"name":"c1","nodes":&ids[..100]}),
        json!({"name":"c2","nodes":&ids[100..200]}),
        json!({"name":"c3","nodes":&ids[200..]}),
        json!({"name":"parent","groups":["c1","c2","c3"]}),
    ] {
        config.groups.push(serde_json::from_value(group).unwrap());
    }
    let state = state(config).await;
    let plan = |group: &str, members: Value| {
        let group_id = state.observation.core.catalog.snapshot().groups[group].clone();
        let mut input = request(
            json!({"type":"group","group_id":group_id}),
            "tcp_connect",
            json!(["tcp"]),
            "ipv4",
        );
        input["members"] = members;
        capture(&state, serde_json::from_value(input).unwrap())
    };

    let subset = plan("big", json!(&ids[..3])).await.unwrap();
    assert_eq!(subset.result.results.len(), 3);
    let parent = plan("parent", json!("direct")).await.unwrap();
    let leaves: Vec<_> = parent
        .result
        .results
        .iter()
        .map(|row| row.resolved_leaf_node_id.as_deref())
        .collect();
    assert_eq!(
        leaves,
        [&ids[0], &ids[100], &ids[200]].map(|id| Some(id.as_str()))
    );
    for (group, members) in [
        ("big", json!("direct")),
        ("big", json!("leaves")),
        ("big", json!(&ids[..65])),
        ("parent", json!("leaves")),
    ] {
        let error = plan(group, members).await.err().unwrap();
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
    }
}

#[tokio::test]
async fn group_probe_health_keeps_inherited_targets_and_expanded_leaf_scope() {
    let leaf = honk_config::config::DIRECT_NODE_ID;
    for custom_url in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/check");
        let mut config = Config::default();
        config.global.tcp_check_url = vec![url.clone()];

        for name in ["left", "right"] {
            config
                .groups
                .push(serde_json::from_value(json!({"name":name,"nodes":[leaf]})).unwrap());
        }
        config.groups.push(
            serde_json::from_value(json!({
                "name":"root", "groups":["left","right"],
                "check_url":custom_url.then_some(url)
            }))
            .unwrap(),
        );
        let state = state(config).await;
        let identity = state.observation.core.catalog.snapshot();
        let peer = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                receive_headers(&mut socket).await;
                socket
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let id = RequestId("group-health".into());
        let uri = "/api/v1/groups/root".parse().unwrap();
        let mut expected = Vec::new();
        for scope in ["direct", "leaves"] {
            let mut input = request(
                json!({"type":"group","group_id":identity.groups["root"]}),
                "http",
                json!(["tcp"]),
                "ipv4",
            );
            input["members"] = json!(scope);
            let plan = capture(&state, serde_json::from_value(input).unwrap())
                .await
                .unwrap();
            let mut plan = prepare(plan).await.unwrap();
            let (_stop, receiver) = watch::channel(false);
            execute(
                &state,
                &mut plan,
                Instant::now() + Duration::from_secs(2),
                receiver,
            )
            .await
            .unwrap();
            let members = if scope == "direct" {
                vec![
                    identity.groups["left"].clone(),
                    identity.groups["right"].clone(),
                ]
            } else {
                vec![leaf.to_string()]
            };
            assert_eq!(
                plan.result
                    .results
                    .iter()
                    .map(|row| row.member_id.clone())
                    .collect::<Vec<_>>(),
                members
            );
            for row in plan.result.results {
                assert!(row.health_updated);
                assert_eq!(row.state, "healthy");
                assert!(row.latency_ms.is_some());
                expected.push(json!({
                    "member_id":row.member_id, "resolved_leaf_node_id":leaf.to_string(),
                    "transport":"tcp", "purpose":"data", "measurement":"http_headers",
                    "ip_version":"ipv4", "warmth":"cold", "sample_source":"probe",
                    "state":"healthy", "latency_ms":row.latency_ms, "observed_at":row.observed_at,
                    "moving_avg_ms":null, "avg10_ms":null, "error":null,
                    "sorting_latency_ms":null, "ranking":null
                }));
            }
            let group = body(
                super::super::catalog::group(&state, &identity.groups["root"], &uri, &id)
                    .await
                    .unwrap(),
            )
            .await;
            for (actual, expected) in group["runtime"]["health"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&mut expected)
            {
                assert!(
                    (actual["latency_ms"].as_f64().unwrap()
                        - expected["latency_ms"].as_f64().unwrap())
                    .abs()
                        < 0.000001
                );
                expected["latency_ms"] = actual["latency_ms"].clone();
            }
            assert_eq!(group["runtime"]["health"], json!(expected));
            for name in ["left", "right"] {
                let unrelated = body(
                    super::super::catalog::group(&state, &identity.groups[name], &uri, &id)
                        .await
                        .unwrap(),
                )
                .await;
                assert_eq!(unrelated["runtime"]["health"], json!([]));
            }
            let nodes = body(
                super::super::catalog::nodes(&state, &"/api/v1/nodes".parse().unwrap(), &id)
                    .await
                    .unwrap(),
            )
            .await;
            assert!(
                nodes["nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|node| node["health"] == json!([]))
            );
        }
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn queue_and_target_refusals_wake_all_same_body_waiters_with_exact_error() {
    let state = state(Config::default()).await;
    let service = &state.observation.probes;
    service.gate.lock().state = WorkerState::Running;
    for index in 0..MAX_QUEUED {
        let input = request(
            json!({"type":"node","node_id":honk_config::config::DIRECT_NODE_ID.to_string()}),
            "http",
            json!(["tcp"]),
            "ipv4",
        );
        let mut plan = capture(&state, serde_json::from_value(input).unwrap())
            .await
            .unwrap();
        plan.context.spec.target = Target::Node {
            node_id: index.to_string(),
        };
        let reservation = service
            .operations
            .reserve(
                "anonymous",
                "POST",
                "/api/v1/probes",
                Some(&index.to_string()),
                b"{}",
                OperationKind::Probe,
            )
            .unwrap();
        service
            .enqueue(Job {
                reservation,
                plan,
                deadline: Instant::now() + DEADLINE,
            })
            .unwrap();
    }
    for (target, status) in [
        ("0", StatusCode::TOO_MANY_REQUESTS),
        ("overflow", StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let input = request(
            json!({"type":"node","node_id":honk_config::config::DIRECT_NODE_ID.to_string()}),
            "http",
            json!(["tcp"]),
            "ipv4",
        );
        let mut plan = capture(&state, serde_json::from_value(input).unwrap())
            .await
            .unwrap();
        plan.context.spec.target = Target::Node {
            node_id: target.into(),
        };
        let key = format!("refused-{target}");
        let reservation = service
            .operations
            .reserve(
                "anonymous",
                "POST",
                "/api/v1/probes",
                Some(&key),
                b"{}",
                OperationKind::Probe,
            )
            .unwrap();
        let waiter = service
            .operations
            .reserve(
                "anonymous",
                "POST",
                "/api/v1/probes",
                Some(&key),
                b"{}",
                OperationKind::Probe,
            )
            .unwrap();
        let error = service
            .enqueue(Job {
                reservation,
                plan,
                deadline: Instant::now() + DEADLINE,
            })
            .unwrap_err();
        assert_eq!(error.into_response().status(), status);
        assert_eq!(
            waiter
                .admission()
                .await
                .unwrap_err()
                .into_response()
                .status(),
            status
        );
    }
    service.gate.lock().state = WorkerState::Stopped;
}

#[tokio::test]
async fn deadline_drains_started_socket_and_keeps_unstarted_rows_neutral() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut config = Config::default();
    config.global.tcp_check_url = vec![format!("http://{address}/check")];

    let state = state(config).await;
    let input = request(
        json!({"type":"node","node_id":honk_config::config::DIRECT_NODE_ID.to_string()}),
        "http",
        json!(["tcp"]),
        "any",
    );
    let plan = capture(&state, serde_json::from_value(input).unwrap())
        .await
        .unwrap();
    let mut plan = prepare(plan).await.unwrap();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.starts_with(b"HEAD /check HTTP/1.1\r\n"));
    });
    let (_stop, receiver) = watch::channel(false);
    execute(
        &state,
        &mut plan,
        Instant::now() + Duration::from_millis(50),
        receiver,
    )
    .await
    .unwrap();
    assert_eq!(plan.result.results[0].error, Some("deadline"));
    assert!(
        plan.result
            .results
            .iter()
            .all(|row| row.state == "unknown" && !row.health_updated && row.latency_ms.is_none())
    );
    tokio::time::timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
    assert!(
        state
            .alive_set
            .health_observations(honk_config::config::DIRECT_NODE_ID)
            .is_empty()
    );
}

#[tokio::test]
async fn four_active_jobs_bound_wire_work_and_fifth_request_is_answered_as_queued() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut config = Config::default();
    config.global.tcp_check_url = vec![format!("http://{address}/check")];

    for index in 0..5 {
        config.groups.push(serde_json::from_value(json!({"name":format!("group-{index}"),"nodes":[honk_config::config::DIRECT_NODE_ID]})).unwrap());
    }
    let state = state(config).await;
    let identity = state.observation.core.catalog.snapshot();
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let mut held = Vec::new();
    for index in 0..4 {
        let input = request(
            json!({"type":"group","group_id":identity.groups[&format!("group-{index}")]}),
            "http",
            json!(["tcp"]),
            "ipv4",
        );
        create(
            &state,
            http_request(&input, &format!("active-{index}")),
            &RequestId("active".into()),
        )
        .await
        .unwrap();
        let (mut socket, _) = listener.accept().await.unwrap();
        receive_headers(&mut socket).await;
        held.push(socket);
    }
    let input = request(
        json!({"type":"group","group_id":identity.groups["group-4"]}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    // The fifth job waits for a worker, but its request is answered at once.
    let queued = body(
        tokio::time::timeout(
            Duration::from_secs(1),
            create(
                &state,
                http_request(&input, "queued"),
                &RequestId("queued".into()),
            ),
        )
        .await
        .expect("queued probe must not hold the request")
        .unwrap(),
    )
    .await;
    assert_eq!(queued["status"], "queued");
    let operation = queued["operation_id"].as_str().unwrap();
    assert_eq!(
        body(state.observation.operations.get(operation).unwrap()).await["status"],
        "queued"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    for mut socket in held {
        socket
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
    }
    let (mut fifth, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    receive_headers(&mut fifth).await;
    fifth
        .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
        .await
        .unwrap();
    let replay = body(
        create(
            &state,
            http_request(&input, "queued"),
            &RequestId("replay".into()),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(replay["operation_id"], operation);
    let result = terminal(&state, operation).await;
    assert_eq!(result["result"]["results"][0]["state"], "healthy");
    stop.send(true).unwrap();
    worker.await.unwrap();
}

#[tokio::test]
async fn dns_tcp_and_udp_through_runtime_publish_separate_dns_purpose_samples() {
    for (bind, host, family) in [
        ("127.0.0.1:0", "127.0.0.1", "ipv4"),
        ("[::1]:0", "[::1]", "ipv6"),
        ("127.0.0.1:0", "[::ffff:127.0.0.1]", "ipv4"),
    ] {
        measure_dns_exchange(bind, host, family).await;
    }
}

async fn measure_dns_exchange(bind: &str, host: &str, family: &str) {
    let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
    let address = listener.local_addr().unwrap();
    let udp = tokio::net::UdpSocket::bind(address).await.unwrap();
    let tcp_peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let length = socket.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(length)];
        socket.read_exact(&mut query).await.unwrap();
        query[2] |= 0x80;
        socket.write_u16(length).await.unwrap();
        socket.write_all(&query).await.unwrap();
    });
    let udp_peer = tokio::spawn(async move {
        let mut query = [0; 512];
        let (length, peer) = udp.recv_from(&mut query).await.unwrap();
        query[2] |= 0x80;
        udp.send_to(&query[..length], peer).await.unwrap();
    });
    let mut config = Config::default();
    config.global.udp_check_dns = vec![format!("{host}:{}", address.port())];
    let state = state(config).await;
    let input = request(
        json!({"type":"node","node_id":honk_config::config::DIRECT_NODE_ID.to_string()}),
        "dns",
        json!(["tcp", "udp"]),
        family,
    );
    let plan = capture(&state, serde_json::from_value(input).unwrap())
        .await
        .unwrap();
    let mut plan = prepare(plan).await.unwrap();
    let (_stop, receiver) = watch::channel(false);
    execute(
        &state,
        &mut plan,
        Instant::now() + Duration::from_secs(2),
        receiver,
    )
    .await
    .unwrap();
    assert_eq!(plan.result.results.len(), 2);
    assert!(
        plan.result
            .results
            .iter()
            .all(|row| row.state == "healthy" && row.health_updated && row.latency_ms.is_some())
    );
    let samples = state
        .alive_set
        .health_observations(honk_config::config::DIRECT_NODE_ID);
    for transport in [HealthTransport::Tcp, HealthTransport::Udp] {
        assert!(samples.iter().any(|sample| sample.transport == transport
            && sample.purpose == HealthPurpose::Dns
            && sample.measurement == HealthMeasurement::DnsRoundTrip));
    }
    tcp_peer.await.unwrap();
    udp_peer.await.unwrap();
}

#[tokio::test]
async fn group_http_probe_measures_loopback_node_and_custom_check_port() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node = Node::from_share_link(&format!(
        "socks5://relay.example:{}",
        listener.local_addr().unwrap().port()
    ))
    .unwrap();
    let id = node.id;
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        assert_eq!(socket.read_u8().await.unwrap(), 5);
        let methods = socket.read_u8().await.unwrap();
        let mut offered = vec![0; usize::from(methods)];
        socket.read_exact(&mut offered).await.unwrap();
        assert!(offered.contains(&0));
        socket.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 4];
        socket.read_exact(&mut header).await.unwrap();
        assert_eq!(
            header,
            [5, 1, 0, 1],
            "the SOCKS peer must not resolve a hostname"
        );
        let mut destination = [0; 6];
        socket.read_exact(&mut destination).await.unwrap();
        assert_eq!(destination, [1, 1, 1, 1, 0x20, 0xfb]);
        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
                .to_ascii_lowercase()
                .contains("host: authority.example:8443\r\n")
        );
        socket
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
    });
    let mut config = Config::default();
    let hosts = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        hosts.path(),
        "relay.example 127.0.0.1\nauthority.example 1.1.1.1\n",
    )
    .unwrap();
    config.dns.hosts = vec![hosts.path().to_string_lossy().into_owned()];
    config.nodes.push(node);
    config
        .groups
        .push(serde_json::from_value(json!({"name":"lan-relay","nodes":[id]})).unwrap());
    config.global.tcp_check_url = vec!["http://authority.example:8443/check".into()];
    let state = state(config).await;
    let identity = state.observation.core.catalog.snapshot();
    let input = request(
        json!({"type":"group","group_id":identity.groups["lan-relay"]}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let (stop, receiver) = watch::channel(false);
    let worker = state.observation.probes.start(Arc::clone(&state), receiver);
    let accepted = body(
        create(
            &state,
            http_request(&input, "lan"),
            &RequestId("lan".into()),
        )
        .await
        .unwrap(),
    )
    .await;
    let result = terminal(&state, accepted["operation_id"].as_str().unwrap()).await;
    assert_eq!(result["status"], "succeeded", "{result}");
    assert_eq!(
        result["result"]["results"][0]["resolved_leaf_node_id"],
        id.to_string()
    );
    assert_eq!(result["result"]["results"][0]["state"], "healthy");
    assert!(
        result["result"]["results"][0]["latency_ms"]
            .as_f64()
            .is_some()
    );
    peer.await.unwrap();
    stop.send(true).unwrap();
    worker.await.unwrap();
}

#[tokio::test]
async fn refusals_name_the_request_field_or_setting_but_not_the_target() {
    let proxy = Node::from_share_link("socks5://127.0.0.1:1080").unwrap();
    let proxy_id = proxy.id.to_string();
    let mut config = Config::default();
    config.nodes.push(proxy);
    config.global.tcp_check_url = vec!["http://127.0.0.1:8080/PRIVATE".into()];
    config.global.udp_check_dns = Vec::new();
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

#[tokio::test]
async fn ipv6_raw_probe_dials_the_requested_family_without_ipv4_fallback() {
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let node = node(listener.local_addr().unwrap());
    let id = node.id;
    let mut config = Config::default();
    config.nodes.push(node);
    let state = state(config).await;
    let input = request(
        json!({"type":"node","node_id":id.to_string()}),
        "tcp_connect",
        json!(["tcp"]),
        "ipv6",
    );
    let plan = capture(&state, serde_json::from_value(input).unwrap())
        .await
        .unwrap();
    let mut plan = prepare(plan).await.unwrap();
    let (_stop, receiver) = watch::channel(false);
    execute(
        &state,
        &mut plan,
        Instant::now() + Duration::from_secs(2),
        receiver,
    )
    .await
    .unwrap();
    let (_socket, peer) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(peer.is_ipv6());
    assert_eq!(plan.result.results[0].state, "healthy");
    assert_eq!(plan.result.results[0].ip_version, Family::Ipv6);
    assert!(
        state
            .alive_set
            .health_observations(id)
            .iter()
            .all(|sample| sample.ip_version == IpVersion::V6)
    );
}
