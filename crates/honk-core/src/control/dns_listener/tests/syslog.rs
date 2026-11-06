use super::*;

fn audited_controller(
    audit: crate::audit::DnsAudit,
    limit: usize,
    cached: bool,
) -> (Arc<DnsController>, Arc<AtomicUsize>) {
    let (mut forwarder, calls) = forwarder([192, 0, 2, 10]);
    Arc::get_mut(&mut forwarder).unwrap().cache_enabled = cached;
    let backend: Arc<tokio::sync::RwLock<Box<dyn crate::ebpf::EbpfBackend>>> = Arc::new(
        tokio::sync::RwLock::new(Box::new(crate::ebpf::mock::MockEbpfBackend::new())),
    );
    let base = DnsController::new(
        forwarder,
        Arc::clone(&backend),
        Arc::new(tokio::sync::RwLock::new(
            Router::new(&[], "direct").unwrap(),
        )),
        limit,
    );
    let mut service = base.dns_service().clone();
    service.audit = audit;
    (
        Arc::new(DnsController::new_with_service(service, backend, limit)),
        calls,
    )
}

#[tokio::test]
async fn udp_dns_records_each_client_query_including_cache_over_tcp_syslog() {
    let (audit, mut worker, mut receiver) = crate::audit::tests::receiver().await;
    let (controller, calls) = audited_controller(audit, 16, true);
    let (mut listener, address, drain) = start_listener("udp://127.0.0.1:0", controller);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buffer = [0; 512];
    let mut ids = Vec::new();
    for txid in [1, 2] {
        client
            .send_to(&query("cached.example", txid), address)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let value = crate::audit::tests::receive(&mut receiver).await;
        assert_eq!(value["client_ip"], "127.0.0.1");
        assert_eq!(value["client_port"], client.local_addr().unwrap().port());
        assert_eq!(value["domain"], "cached.example.");
        assert_eq!(value["transport"], "udp");
        assert_eq!(value["rcode"], "NOERROR");
        assert_eq!(value["answers"][0]["data"], "192.0.2.10");
        assert_eq!(
            value["upstream"],
            if txid == 1 { "default" } else { "cache" }
        );
        assert!(value["duration_ms"].as_f64().unwrap() >= 0.0);
        ids.push(value["event_id"].clone());
    }
    assert_ne!(ids[0], ids[1]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop_listener(&mut listener, &drain).await;
    worker.shutdown().await;
}

#[tokio::test]
async fn udp_dns_refusal_is_exported_over_tcp_syslog() {
    let (audit, mut worker, mut receiver) = crate::audit::tests::receiver().await;
    let (controller, calls) = audited_controller(audit, 0, false);
    let (mut listener, address, drain) = start_listener("udp://127.0.0.1:0", controller);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&query("refused.example", 1), address)
        .await
        .unwrap();
    let mut buffer = [0; 512];
    let length = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(length, 12);
    let value = crate::audit::tests::receive(&mut receiver).await;
    assert_eq!(value["domain"], "refused.example.");
    assert_eq!(value["rcode"], "REFUSED");
    assert_eq!(value["answers"], serde_json::json!([]));
    assert!(value["upstream"].is_null());
    assert!(value["duration_ms"].as_f64().unwrap() >= 0.0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop_listener(&mut listener, &drain).await;
    worker.shutdown().await;
}

#[tokio::test]
async fn tcp_dns_records_each_frame_with_socket_peer_over_tcp_syslog() {
    let (audit, mut worker, mut receiver) = crate::audit::tests::receiver().await;
    let (controller, _) = audited_controller(audit, 16, false);
    let (mut listener, address, drain) = start_listener("tcp://127.0.0.1:0", controller);
    let mut client = TcpStream::connect(address).await.unwrap();
    let source = client.local_addr().unwrap();
    for (name, txid) in [("one.example", 1), ("two.example", 2)] {
        crate::dns::transport::write_length_prefixed(&mut client, &query(name, txid))
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            crate::dns::transport::read_length_prefixed_into(&mut client, &mut response, None),
        )
        .await
        .unwrap()
        .unwrap();
        let value = crate::audit::tests::receive(&mut receiver).await;
        assert_eq!(value["client_port"], source.port());
        assert_eq!(value["transport"], "tcp");
        assert_eq!(value["domain"], format!("{name}."));
        assert_eq!(value["upstream"], "default");
        assert!(value["duration_ms"].as_f64().unwrap() >= 0.0);
    }
    drop(client);
    stop_listener(&mut listener, &drain).await;
    worker.shutdown().await;
}
