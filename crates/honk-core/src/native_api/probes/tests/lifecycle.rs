use super::*;

struct PrivateChildProbe {
    panic: bool,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for PrivateChildProbe {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        Ok(honk_outbound::proxy::ProxyStream {
            stream: Box::new(tokio::net::TcpStream::connect(target).await?),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<honk_outbound::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        let scope = honk_outbound::runtime::TaskScope::capture();
        let panic = self.panic;
        let child = scope
            .spawn(async move {
                if panic {
                    panic!("private protocol child failed");
                }
                std::future::pending::<()>().await;
            })
            .unwrap();
        if panic {
            while !child.is_finished() {
                tokio::task::yield_now().await;
            }
            // Registration reaps the panic before the guard closes.
            scope.spawn(std::future::pending()).unwrap();
        }
        self.dial(&runtime.node, target, target_domain, timeout)
            .await
    }
}

#[tokio::test]
async fn private_child_panic_fails_operation_and_pause_without_negating_measurement() {
    for panic in [true, false] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            receive_headers(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
            assert_eq!(socket.read(&mut [0; 1]).await.unwrap(), 0);
        });
        let mut config = Config::default();
        config.global.tcp_check_url = vec![format!("http://{address}/check")];

        let mut state = state(config).await;
        let mut registry = honk_outbound::proxy::ProxyRegistry::new();
        registry.register(honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Direct,
            Arc::new(PrivateChildProbe { panic }),
        ));
        Arc::get_mut(&mut state).unwrap().proxy_registry = Arc::new(registry);
        let service = &state.observation.probes;
        let (stop, receiver) = watch::channel(false);
        let worker = service.start(Arc::clone(&state), receiver);
        let input = request(
            json!({"type":"node","node_id":honk_config::config::DIRECT_NODE_ID.to_string()}),
            "http",
            json!(["tcp"]),
            "ipv4",
        );
        let accepted = body(
            create(
                &state,
                http_request(&input, "private-child"),
                &RequestId("private-child".into()),
            )
            .await
            .unwrap(),
        )
        .await;
        let operation = terminal(&state, accepted["operation_id"].as_str().unwrap()).await;
        assert_eq!(
            operation["status"],
            if panic { "failed" } else { "succeeded" }
        );
        // A failed operation keeps result null; completed measurements move to error.details.
        let measured = if panic {
            assert_eq!(operation["result"], Value::Null);
            &operation["error"]["details"]
        } else {
            &operation["result"]
        };
        assert_eq!(measured["results"][0]["state"], "healthy");
        assert_eq!(measured["results"][0]["health_updated"], true);
        assert_eq!(measured["results"][0]["error"], Value::Null);
        assert_eq!(
            state
                .alive_set
                .health_observations(honk_config::config::DIRECT_NODE_ID)
                .iter()
                .map(|observation| observation.state)
                .collect::<Vec<_>>(),
            [HealthState::Healthy]
        );
        if panic {
            assert_eq!(operation["error"]["code"], "probe_cleanup_failed");
            assert_eq!(
                service.pause().await,
                Err(ProbeLifecycleError::CleanupFailed)
            );
        } else {
            service.pause().await.unwrap();
        }
        stop.send(true).unwrap();
        worker.await.unwrap();
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn pause_drains_started_and_disconnected_queued_jobs() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut config = Config::default();
    config.global.tcp_check_url = vec![format!("http://{address}/check")];

    for index in 0..=MAX_ACTIVE {
        config.groups.push(serde_json::from_value(json!({"name":format!("pause-{index}"),"nodes":[honk_config::config::DIRECT_NODE_ID]})).unwrap());
    }
    let state = state(config).await;
    let service = &state.observation.probes;
    assert_eq!(service.pause().await, Err(ProbeLifecycleError::Unavailable));
    let identity = state.observation.core.catalog.snapshot();
    let (stop, receiver) = watch::channel(false);
    let worker = service.start(Arc::clone(&state), receiver);
    let mut held = Vec::new();
    let mut accepted = Vec::new();
    for index in 0..MAX_ACTIVE {
        let input = request(
            json!({"type":"group","group_id":identity.groups[&format!("pause-{index}")]}),
            "http",
            json!(["tcp"]),
            "ipv4",
        );
        accepted.push(
            body(
                create(
                    &state,
                    http_request(&input, &format!("active-{index}")),
                    &RequestId("active".into()),
                )
                .await
                .unwrap(),
            )
            .await,
        );
        let (mut socket, _) = listener.accept().await.unwrap();
        receive_headers(&mut socket).await;
        held.push(socket);
    }
    let input = request(
        json!({"type":"group","group_id":identity.groups[&format!("pause-{MAX_ACTIVE}")]}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let caller = tokio::spawn({
        let state = Arc::clone(&state);
        let input = input.clone();
        async move {
            create(
                &state,
                http_request(&input, "queued"),
                &RequestId("queued".into()),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while service.sender.capacity() == MAX_QUEUED {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let waiter = service
        .operations
        .reserve(
            "anonymous",
            "POST",
            "/api/v1/probes",
            Some("queued"),
            input.to_string().as_bytes(),
            OperationKind::Probe,
        )
        .unwrap();
    assert!(!waiter.fresh);
    caller.abort();
    let _ = caller.await;
    tokio::time::timeout(Duration::from_secs(2), service.pause())
        .await
        .unwrap()
        .unwrap();
    assert!(!service.running());
    assert_eq!(service.capability()["available"], false);
    let queued = waiter.admission().await.unwrap().operation_id;
    let cancelled = terminal(&state, &queued).await;
    assert_eq!(cancelled["status"], "failed");
    assert_eq!(cancelled["error"]["code"], "probe_cancelled");
    for mut socket in held {
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), socket.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    for operation in &accepted {
        let result = terminal(&state, operation["operation_id"].as_str().unwrap()).await;
        assert_eq!(result["result"]["results"][0]["state"], "unknown");
        assert_eq!(result["result"]["results"][0]["error"], "cancelled");
        assert_eq!(result["result"]["results"][0]["health_updated"], false);
    }
    let old = request(
        json!({"type":"group","group_id":identity.groups["pause-0"]}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let replay = body(
        create(
            &state,
            http_request(&old, "active-0"),
            &RequestId("replay".into()),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(replay["operation_id"], accepted[0]["operation_id"]);
    let stopped = create(
        &state,
        http_request(&input, "fresh-stopped"),
        &RequestId("fresh".into()),
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(stopped.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(stopped.headers().contains_key("retry-after"));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    assert!(
        state
            .alive_set
            .health_observations(honk_config::config::DIRECT_NODE_ID)
            .is_empty()
    );
    assert_eq!(service.pause().await, Err(ProbeLifecycleError::Unavailable));
    stop.send(true).unwrap();
    worker.await.unwrap();
    assert_eq!(service.pause().await, Err(ProbeLifecycleError::Unavailable));
}

#[tokio::test]
async fn pause_cancels_reserved_capture_without_late_enqueue() {
    let state = state(Config::default()).await;
    let service = &state.observation.probes;
    let (stop, receiver) = watch::channel(false);
    let worker = service.start(Arc::clone(&state), receiver);
    let router = state.traffic_router.write().await;
    let input = request(
        json!({"type":"node","node_id":honk_config::config::DIRECT_NODE_ID.to_string()}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let capture = tokio::spawn({
        let state = Arc::clone(&state);
        let input = input.clone();
        async move {
            create(
                &state,
                http_request(&input, "capture"),
                &RequestId("capture".into()),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while service.gate.lock().requests != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let waiter = service
        .operations
        .reserve(
            "anonymous",
            "POST",
            "/api/v1/probes",
            Some("capture"),
            input.to_string().as_bytes(),
            OperationKind::Probe,
        )
        .unwrap();
    assert!(!waiter.fresh);
    tokio::time::timeout(Duration::from_secs(1), service.pause())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        capture.await.unwrap().unwrap_err().into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        waiter
            .admission()
            .await
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(router);
    assert!(
        state
            .alive_set
            .health_observations(honk_config::config::DIRECT_NODE_ID)
            .is_empty()
    );
    stop.send(true).unwrap();
    worker.await.unwrap();
}
