use super::*;

#[tokio::test]
async fn native_log_records_bound_udp_success_and_header_only_refusal() {
    let (controller, _) = controller([192, 0, 2, 10]);
    let api = Arc::new(crate::native_api::dns::DnsApi::new(
        "bound-log".into(),
        true,
        std::sync::Weak::new(),
    ));
    controller
        .dns_service()
        .attach_observer(Arc::downgrade(&api.recorder));
    let (mut listener, address, drain) =
        start_listener("udp://127.0.0.1:0", Arc::clone(&controller));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = client.local_addr().unwrap();
    let mut bytes = [0; 512];
    client
        .send_to(&query("accepted.example", 1), address)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes[3] & 15, 0);
    stop_listener(&mut listener, &drain).await;
    let (saturated, _) =
        controller_with_config([192, 0, 2, 10], &honk_config::dns::DnsConfig::default(), 0);
    saturated
        .dns_service()
        .attach_observer(Arc::downgrade(&api.recorder));
    let (mut listener, address, drain) = start_listener("udp://127.0.0.1:0", saturated);
    client
        .send_to(&query("refused.example", 2), address)
        .await
        .unwrap();
    let length = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(length, 12);
    assert_eq!(bytes[3] & 15, 5);
    stop_listener(&mut listener, &drain).await;
    let page = api.log_page_for_test();
    let body = axum::body::to_bytes(page.into_body(), 262144)
        .await
        .unwrap();
    let log: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(log["total"], 2);
    assert_eq!(log["records"][0]["status"], "REFUSED");
    assert_eq!(log["records"][0]["question"]["name"], "refused.example.");
    assert_eq!(log["records"][0]["src"], source.to_string());
    assert_eq!(log["records"][1]["answers"][0]["data"], "192.0.2.10");
}

#[tokio::test]
async fn native_bound_dns_records_each_udp_query_and_tcp_frame_without_dns_log() {
    let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    let mut config = honk_config::Config::default();
    config.global.nfqueue_enable = false;
    config.global.store_subscribe = false;
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.record_dns_log = false;
    config.experimental.native_api.listen = api_addr.to_string();
    config.experimental.native_api.secret = "bound-flow-test".into();
    config.ensure_builtin_nodes();
    let mut plane = crate::control::tests::support::control_plane(config);
    plane.diagnostics.write().generation = 17;
    let state = Arc::new(
        crate::native_api::NativeState::new(
            &mut plane,
            api_addr,
            std::time::SystemTime::now(),
            std::time::Instant::now(),
        )
        .await
        .unwrap(),
    );
    let native = Arc::clone(&state.observation);
    let api_server = crate::native_api::NativeServer::start(api_listener, state);
    native.attach_for_test();
    let (controller, calls) = controller([192, 0, 2, 10]);
    controller
        .dns_service()
        .attach_observer(Arc::downgrade(&native.dns.recorder));
    let bound = BoundDnsListener::bind(
        &DnsBindEndpoint::parse("tcp+udp://127.0.0.1:0").unwrap(),
        None,
    )
    .unwrap();
    let address = bound.local_addr();
    let drain = Arc::new(DrainTracker::new());
    let mut listener = bound
        .spawn(
            controller,
            Arc::new(Semaphore::new(16)),
            Arc::new(StatsManager::new()),
            Arc::clone(&drain),
            Some(Arc::clone(&native.core)),
            plane.diagnostics.clone(),
            ScopeId::HOST,
        )
        .unwrap();
    let response = udp_exchange(address, &query("udp.flow.test", 1)).await;
    assert_eq!(response[3] & 15, 0);
    let mut tcp = TcpStream::connect(address).await.unwrap();
    for (domain, txid) in [("first.flow.test", 2), ("second.flow.test", 3)] {
        crate::dns::transport::write_length_prefixed(&mut tcp, &query(domain, txid))
            .await
            .unwrap();
        assert_eq!(read_tcp_frame(&mut tcp).await[3] & 15, 0);
    }
    drop(tcp);
    stop_listener(&mut listener, &drain).await;
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let (saturated, rejected_calls) =
        controller_with_config([192, 0, 2, 10], &honk_config::dns::DnsConfig::default(), 0);
    saturated
        .dns_service()
        .attach_observer(Arc::downgrade(&native.dns.recorder));
    let bound = BoundDnsListener::bind(&DnsBindEndpoint::parse("udp://127.0.0.1:0").unwrap(), None)
        .unwrap();
    let address = bound.local_addr();
    let drain = Arc::new(DrainTracker::new());
    let mut listener = bound
        .spawn(
            saturated,
            Arc::new(Semaphore::new(16)),
            Arc::new(StatsManager::new()),
            Arc::clone(&drain),
            Some(Arc::clone(&native.core)),
            plane.diagnostics.clone(),
            ScopeId::HOST,
        )
        .unwrap();
    let refused = udp_exchange(address, &query("refused.flow.test", 4)).await;
    assert_eq!(refused[3] & 15, 5);
    stop_listener(&mut listener, &drain).await;
    assert_eq!(rejected_calls.load(Ordering::SeqCst), 0);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let page: serde_json::Value = client
        .get(format!("http://{api_addr}/api/v1/flows"))
        .bearer_auth("bound-flow-test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let flows = page["flows"].as_array().unwrap();
    assert_eq!(flows.len(), 3);
    let mut rejected = 0;
    for flow in flows {
        let id = flow["id"].as_str().unwrap();
        let detail: serde_json::Value = client
            .get(format!("http://{api_addr}/api/v1/flows/{id}"))
            .bearer_auth("bound-flow-test")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let steps = detail["trace"]["steps"].as_array().unwrap();
        let delivered: Vec<_> = steps
            .iter()
            .filter(|step| {
                step["stage"] == "dns"
                    && step["data"]["status"] == "delivered"
                    && step["data"]["parent_lookup_id"].is_null()
            })
            .collect();
        assert_eq!(
            delivered.len(),
            if flow["network"] == "tcp" { 2 } else { 1 }
        );
        let ids: std::collections::HashSet<_> = delivered
            .iter()
            .map(|step| step["data"]["lookup_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), delivered.len());
        rejected += usize::from(steps.iter().any(|step| {
            step["stage"] == "dns"
                && step["data"]["status"] == "rejected"
                && step["data"]["error"] == "admission_refused"
        }));
        assert!(detail["ended_at"].is_string());
        assert!(
            !steps
                .iter()
                .any(|step| step["data"]["milestone"] == "target_confirmed")
        );
    }
    assert_eq!(rejected, 1);
    api_server.shutdown().await;
}
