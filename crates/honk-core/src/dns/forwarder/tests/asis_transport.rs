fn asis_test_forwarder() -> DnsForwarder {
    use honk_config::dns::{DnsRequestAction, DnsRequestRouting};

    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: Vec::new(),
                fallback: DnsRequestAction::AsIs,
            },
            ..Default::default()
        })
        .expect("asis router"),
    );
    DnsForwarder::new(Arc::new(FailUpstream), test_cache(), router).with_timeouts(
        Duration::from_millis(250),
        Duration::from_millis(250),
    )
}

async fn answer_one_tcp_query(
    listener: tokio::net::TcpListener,
    answer_ip: [u8; 4],
) -> Vec<u8> {
    let (mut stream, _) = listener.accept().await.expect("accept asis TCP query");
    let mut query = Vec::new();
    crate::dns::transport::read_length_prefixed_into(
        &mut stream,
        &mut query,
        Some(Duration::from_secs(1)),
    )
    .await
    .expect("read asis TCP query");
    let mut response = make_a_response(answer_ip, 60);
    response[..2].copy_from_slice(&query[..2]);
    crate::dns::transport::write_length_prefixed(&mut stream, &response)
        .await
        .expect("write asis TCP response");
    query
}

async fn answer_one_udp_query(socket: tokio::net::UdpSocket, answer_ip: [u8; 4]) -> Vec<u8> {
    let mut query = vec![0u8; 512];
    let (received, peer) = socket.recv_from(&mut query).await.expect("receive asis query");
    query.truncate(received);
    let mut response = make_a_response(answer_ip, 60);
    response[..2].copy_from_slice(&query[..2]);
    socket
        .send_to(&response, peer)
        .await
        .expect("send asis response");
    query
}

#[tokio::test]
async fn tcp_asis_reaches_tcp_only_original_destination() {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind TCP-only DNS endpoint");
    let original_dst = listener.local_addr().expect("TCP endpoint address");
    let responder = tokio::spawn(answer_one_tcp_query(listener, [203, 0, 113, 10]));
    let query = make_a_query();

    let response = asis_test_forwarder()
        .resolve_with_context_and_profile(
            &query,
            DnsRequestMeta::new(None, Some(original_dst)),
            IngressProfile::Tcp,
        )
        .await
        .expect("TCP asis response");
    let received_query = tokio::time::timeout(Duration::from_millis(250), responder)
        .await
        .expect("TCP responder must receive the asis query")
        .expect("TCP responder");

    assert_eq!(received_query, query);
    assert_eq!(&response[response.len() - 4..], &[203, 0, 113, 10]);
}

#[tokio::test]
async fn udp_asis_truncation_retries_tcp_on_the_same_endpoint() {
    let tcp = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind fallback TCP endpoint");
    let original_dst = tcp.local_addr().expect("fallback endpoint address");
    let udp = tokio::net::UdpSocket::bind(original_dst)
        .await
        .expect("bind UDP endpoint on TCP port");
    let tcp_responder = tokio::spawn(answer_one_tcp_query(tcp, [203, 0, 113, 11]));
    let udp_responder = tokio::spawn(async move {
        let mut query = vec![0u8; 512];
        let (received, peer) = udp.recv_from(&mut query).await.expect("receive asis UDP query");
        query.truncate(received);
        let mut truncated = query.clone();
        truncated[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
        udp.send_to(&truncated, peer)
            .await
            .expect("send truncated UDP response");
        query
    });
    let query = make_a_query();

    let response = asis_test_forwarder()
        .resolve_with_context_and_profile(
            &query,
            DnsRequestMeta::new(None, Some(original_dst)),
            IngressProfile::Udp {
                advertised_size: 1232,
            },
        )
        .await
        .expect("UDP asis fallback response");
    let udp_query = udp_responder.await.expect("UDP responder");
    let tcp_query = tokio::time::timeout(Duration::from_millis(250), tcp_responder)
        .await
        .expect("TC response must trigger the TCP responder")
        .expect("TCP responder");

    assert_eq!(udp_query, query);
    assert_eq!(tcp_query, query);
    assert_eq!(&response[response.len() - 4..], &[203, 0, 113, 11]);
}

#[tokio::test]
async fn udp_asis_wrong_id_tc_does_not_trigger_tcp_fallback() {
    let tcp = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind fallback TCP endpoint");
    let original_dst = tcp.local_addr().expect("fallback endpoint address");
    let udp = tokio::net::UdpSocket::bind(original_dst)
        .await
        .expect("bind UDP endpoint on TCP port");
    let udp_responder = tokio::spawn(async move {
        let mut query = vec![0u8; 512];
        let (received, peer) = udp.recv_from(&mut query).await.expect("receive asis UDP query");
        query.truncate(received);
        query[..2].copy_from_slice(&0xdeadu16.to_be_bytes());
        query[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
        udp.send_to(&query, peer)
            .await
            .expect("send wrong-ID truncated UDP response");
    });
    let query = make_a_query();

    let error = asis_test_forwarder()
        .resolve_with_context_and_profile(
            &query,
            DnsRequestMeta::new(None, Some(original_dst)),
            IngressProfile::Udp {
                advertised_size: 1232,
            },
        )
        .await
        .expect_err("wrong transaction ID must be rejected");
    udp_responder.await.expect("UDP responder");
    assert!(error.to_string().contains("transaction ID"));
    assert!(tokio::time::timeout(Duration::from_millis(100), tcp.accept())
        .await
        .is_err());
}

struct WrongIdUpstream {
    response: Vec<u8>,
    call_count: AtomicUsize,
}

#[async_trait]
impl DnsUpstreamPool for WrongIdUpstream {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(self.response.clone())
    }
}

#[tokio::test]
async fn named_wrong_id_response_is_rejected_before_cache() {
    let mut query = make_a_query();
    query[..2].copy_from_slice(&0x1234u16.to_be_bytes());
    let mut response = make_a_response([192, 0, 2, 42], 60);
    response[..2].copy_from_slice(&0xdeadu16.to_be_bytes());
    let upstream = Arc::new(WrongIdUpstream {
        response,
        call_count: AtomicUsize::new(0),
    });
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), test_router());

    for _ in 0..2 {
        assert!(forwarder.resolve_outcome(&query).await.is_err());
    }
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn udp_asis_cache_is_partitioned_by_original_destination() {
    let first = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind first endpoint");
    let first_addr = first.local_addr().expect("first endpoint");
    let second = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind second endpoint");
    let second_addr = second.local_addr().expect("second endpoint");
    let first_responder = tokio::spawn(answer_one_udp_query(first, [192, 0, 2, 1]));
    let second_responder = tokio::spawn(answer_one_udp_query(second, [198, 51, 100, 1]));
    let query = make_a_query();
    let forwarder = asis_test_forwarder();
    let ingress = IngressProfile::Udp {
        advertised_size: 1232,
    };

    let first_response = forwarder
        .resolve_with_context_and_profile(
            &query,
            DnsRequestMeta::new(None, Some(first_addr)),
            ingress,
        )
        .await
        .expect("first asis response");
    let second_response = forwarder
        .resolve_with_context_and_profile(
            &query,
            DnsRequestMeta::new(None, Some(second_addr)),
            ingress,
        )
        .await
        .expect("second asis response");
    first_responder.await.expect("first responder");
    second_responder.await.expect("second responder");

    assert_eq!(&first_response[first_response.len() - 4..], &[192, 0, 2, 1]);
    assert_eq!(
        &second_response[second_response.len() - 4..],
        &[198, 51, 100, 1]
    );
    for (destination, expected) in [
        (first_addr, [192, 0, 2, 1]),
        (second_addr, [198, 51, 100, 1]),
    ] {
        let cached = forwarder
            .resolve_with_context_and_profile(
                &query,
                DnsRequestMeta::new(None, Some(destination)),
                ingress,
            )
            .await
            .expect("cached asis response");
        assert_eq!(&cached[cached.len() - 4..], &expected);
    }
}

#[tokio::test]
async fn udp_asis_receives_valid_datagrams_larger_than_4096_bytes() {
    let socket = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind large UDP responder");
    let original_dst = socket.local_addr().expect("large UDP endpoint address");
    let mut query = make_a_query();
    query[10..12].copy_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[
        0x00, 0x00, 0x29, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let ingress = crate::dns::query::udp_ingress_profile(&query);
    let responder = tokio::spawn(async move {
        let mut query = vec![0u8; 512];
        let (received, peer) = socket
            .recv_from(&mut query)
            .await
            .expect("receive large-response query");
        query.truncate(received);
        let question_end = crate::dns::query::QueryContext::parse(&query)
            .expect("large-response query")
            .question_offsets()
            .expect("large-response question")
            .end();
        let opt = query[question_end..].to_vec();
        let mut response = query[..question_end].to_vec();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[
            0xc0, 0x0c, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
        ]);
        response.extend_from_slice(&5000u16.to_be_bytes());
        response.resize(response.len() + 5000, 0x5a);
        response.extend_from_slice(&opt);
        socket
            .send_to(&response, peer)
            .await
            .expect("send large UDP response");
        response
    });

    let response = asis_test_forwarder()
        .resolve_with_context_and_profile(
            &query,
            DnsRequestMeta::new(None, Some(original_dst)),
            ingress,
        )
        .await
        .expect("large UDP asis response");
    let sent = tokio::time::timeout(Duration::from_millis(250), responder)
        .await
        .expect("large UDP responder must receive the asis query")
        .expect("large UDP responder");

    assert!(sent.len() > 4096);
    assert!(response.len() <= 1232);
    assert_eq!(&response[0..2], &query[0..2]);
    assert_ne!(u16::from_be_bytes([response[2], response[3]]) & 0x0200, 0);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
}

#[tokio::test]
async fn udp_asis_honors_configured_query_timeout() {
    let socket = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind silent UDP responder");
    let original_dst = socket.local_addr().expect("silent UDP endpoint address");
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let responder = tokio::spawn(async move {
        let mut query = vec![0u8; 512];
        socket
            .recv_from(&mut query)
            .await
            .expect("receive timeout probe");
        let _ = received_tx.send(());
        let _ = release_rx.await;
    });
    let query = make_a_query();
    let forwarder = asis_test_forwarder().with_timeouts(
        Duration::from_millis(37),
        Duration::from_secs(10),
    );
    let started = tokio::time::Instant::now();
    let mut running = tokio::spawn(async move {
        forwarder
            .resolve_with_context_and_profile(
                &query,
                DnsRequestMeta::new(None, Some(original_dst)),
                IngressProfile::Udp {
                    advertised_size: 1232,
                },
            )
            .await
    });
    received_rx.await.expect("timeout probe reached endpoint");

    let completed = tokio::time::timeout(Duration::from_millis(250), &mut running).await;
    let elapsed = started.elapsed();
    if completed.is_err() {
        running.abort();
    }
    let _ = release_tx.send(());
    responder.await.expect("silent UDP responder");
    let error = completed
        .expect("configured timeout must finish promptly")
        .expect("timeout query task")
        .expect_err("silent endpoint must time out");

    assert!(elapsed >= Duration::from_millis(30));
    assert!(error.to_string().contains("timeout"));
}

struct RecordingNodataUpstream {
    queries: std::sync::Mutex<Vec<Vec<u8>>>,
}

#[async_trait]
impl DnsUpstreamPool for RecordingNodataUpstream {
    async fn query(&self, _: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.queries.lock().unwrap().push(raw_query.to_vec());
        let mut response = raw_query.to_vec();
        response[2] |= 0x80;
        response[3] |= 0x80;
        Ok(response)
    }
}

#[tokio::test]
async fn prefer_sibling_changes_only_original_question_qtype() {
    let mut query = build_dns_query("example.com", 28);
    query[..2].copy_from_slice(&0x1234u16.to_be_bytes());
    query[2..4].copy_from_slice(&0x0120u16.to_be_bytes());
    let qclass_start = query.len() - 2;
    query[qclass_start..].copy_from_slice(&3u16.to_be_bytes());
    query[10..12].copy_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00, 0x07, 0xfd, 0xe9, 0x00,
        0x03, 0xaa, 0xbb, 0xcc,
    ]);
    let parsed = crate::dns::query::QueryContext::parse_with_profile(
        &query,
        IngressProfile::Internal,
    )
    .expect("profile-rich query");
    let qtype_start = parsed.question_offsets().expect("question offsets").end() - 4;
    let upstream = Arc::new(RecordingNodataUpstream {
        queries: std::sync::Mutex::new(Vec::new()),
    });
    let forwarder = DnsForwarder::new(
        upstream.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::PreferIpv4);

    forwarder
        .resolve(&query)
        .await
        .expect("prefer-family response");
    let recorded = upstream.queries.lock().unwrap();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0], query);
    let mut expected_sibling = query.clone();
    expected_sibling[qtype_start..qtype_start + 2].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(recorded[1], expected_sibling);
    assert_eq!(&recorded[1][qclass_start..qclass_start + 2], &3u16.to_be_bytes());
    assert_eq!(&recorded[1][qclass_start + 2..], &query[qclass_start + 2..]);
}
