use super::*;

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

async fn socks_member(slow: bool) -> Node {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node = node(listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            if slow {
                held.push(socket);
                continue;
            }
            tokio::spawn(async move {
                let mut greeting = [0; 3];
                socket.read_exact(&mut greeting).await.unwrap();
                socket.write_all(&[5, 0]).await.unwrap();
                let mut connect = [0; 10];
                socket.read_exact(&mut connect).await.unwrap();
                socket
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                    .await
                    .unwrap();
                receive_headers(&mut socket).await;
                socket
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap();
            });
        }
    });
    node
}

async fn group_plan(members: &[Node]) -> (Arc<NativeState>, PreparedPlan) {
    let mut config = Config::default();
    let hosts = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(hosts.path(), "authority.example 1.1.1.1\n").unwrap();
    config.dns.hosts = vec![hosts.path().to_string_lossy().into_owned()];
    config.nodes.extend(members.iter().cloned());
    let ids: Vec<_> = members.iter().map(|node| node.id).collect();
    config
        .groups
        .push(serde_json::from_value(json!({"name":"members","nodes":ids})).unwrap());
    config.global.tcp_check_url = vec!["http://authority.example:8443/check".into()];
    let state = state(config).await;
    let identity = state.observation.core.catalog.snapshot();
    let input = request(
        json!({"type":"group","group_id":identity.groups["members"]}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let plan = capture(&state, serde_json::from_value(input).unwrap())
        .await
        .unwrap();
    let plan = prepare(plan).await.unwrap();
    (state, plan)
}

#[tokio::test]
async fn a_slow_member_does_not_starve_later_members_of_the_deadline() {
    let mut members = vec![socks_member(true).await];
    for _ in 0..3 {
        members.push(socks_member(false).await);
    }
    let (state, mut plan) = group_plan(&members).await;
    let (_stop, receiver) = watch::channel(false);
    execute(
        &state,
        &mut plan,
        Instant::now() + Duration::from_secs(1),
        receiver,
    )
    .await
    .unwrap();
    let rows: HashMap<_, _> = plan
        .result
        .results
        .iter()
        .map(|row| (row.resolved_leaf_node_id.clone().unwrap(), row))
        .collect();
    let slow = rows[&members[0].id.to_string()];
    assert_eq!((slow.state, slow.error), ("unknown", Some("deadline")));
    for member in &members[1..] {
        let row = rows[&member.id.to_string()];
        assert_eq!((row.state, row.error), ("healthy", None));
    }
}

#[tokio::test]
async fn members_beyond_the_concurrency_bound_still_report_deadline_or_cancelled() {
    let mut members = Vec::new();
    for _ in 0..honk_outbound::urltest::URLTEST_MAX_CONCURRENT {
        members.push(socks_member(true).await);
    }
    members.push(socks_member(false).await);

    let (state, mut plan) = group_plan(&members).await;
    let (_stop, receiver) = watch::channel(false);
    execute(
        &state,
        &mut plan,
        Instant::now() + Duration::from_millis(300),
        receiver,
    )
    .await
    .unwrap();
    assert_eq!(plan.result.results.len(), members.len());
    assert!(
        plan.result
            .results
            .iter()
            .all(|row| row.state == "unknown" && row.error == Some("deadline"))
    );

    let (state, mut plan) = group_plan(&members).await;
    let (stop, receiver) = watch::channel(false);
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.send(true).unwrap();
        stop
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        execute(
            &state,
            &mut plan,
            Instant::now() + Duration::from_secs(10),
            receiver,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        plan.result
            .results
            .iter()
            .all(|row| row.state == "unknown" && row.error == Some("cancelled"))
    );
    canceller.await.unwrap();
}
