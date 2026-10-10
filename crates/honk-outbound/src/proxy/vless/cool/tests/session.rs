use super::*;

#[tokio::test]
async fn fragmented_and_coalesced_responses_are_demultiplexed() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let mut stream = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "93.184.216.34:443".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("TCP stream must open"));
    assert_eq!(read_wire_frame(&mut wire).await.id, 1);

    let first = response_frame(1, STATUS_KEEP, OPTION_DATA, None, Some(b"ab"));
    for &byte in first.iter() {
        wire.write_all(&[byte]).await.unwrap();
    }
    let mut joined = BytesMut::new();
    joined.extend_from_slice(&response_frame(
        1,
        STATUS_KEEP,
        OPTION_DATA,
        None,
        Some(b"cd"),
    ));
    joined.extend_from_slice(&response_frame(0xbeef, STATUS_KEEPALIVE, 0, None, None));
    wire.write_all(&joined).await.unwrap();
    let mut output = [0; 4];
    stream.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, b"abcd");
    session.close();
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn shared_xudp_records_each_business_target_once_without_carrying_opener_context() {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};
    let events = Arc::new(Mutex::new(Vec::new()));
    let observe = |flow_id| {
        let events = Arc::clone(&events);
        FlowObserver::new(
            FlowContext {
                flow_id,
                generation: 1,
                attempt_id: None,
                lookup_id: None,
                dns_purpose: "proxy_server",
            },
            Arc::new(move |context, event| {
                if let FlowEvent::Milestone { milestone } = event {
                    events.lock().push((context.flow_id, milestone.as_str()));
                }
            }),
        )
    };
    let first = observe(uuid::Uuid::new_v4());
    let second = observe(uuid::Uuid::new_v4());
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let transport = first
        .scope(open_xudp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            udp_target(),
            None,
            [1; 8],
        ))
        .await
        .unwrap_or_else(|_| panic!("shared child failed to open"));
    assert!(
        events.lock().is_empty(),
        "opening a deferred child sends no target"
    );
    for observer in [&first, &first, &second] {
        observer
            .scope(transport.send_to(udp_target(), None, b"dns", None))
            .await
            .unwrap();
        assert_eq!(
            read_wire_frame(&mut wire).await.payload.unwrap(),
            Bytes::from_static(b"dns")
        );
    }
    assert_eq!(
        &*events.lock(),
        &[
            (first.context().flow_id, "target_request_sent"),
            (second.context().flow_id, "target_request_sent"),
        ]
    );
    drop(transport);
    session.close();
}

#[tokio::test]
async fn tcp_receive_budget_waits_for_transient_reader_backpressure() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let mut stream = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "93.184.216.34:443".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("TCP stream must open"));
    assert_eq!(read_wire_frame(&mut wire).await.id, 1);

    let held = Arc::clone(&session.receive_budget)
        .acquire_many_owned(RECEIVE_BYTE_BUDGET as u32)
        .await
        .unwrap();
    let dispatch = {
        let session = Arc::clone(&session);
        tokio::spawn(async move {
            session
                .dispatch(IncomingFrame {
                    metadata: base_metadata(1, STATUS_KEEP, OPTION_DATA).freeze(),
                    id: 1,
                    status: STATUS_KEEP,
                    options: OPTION_DATA,
                    payload: Some(Bytes::from_static(b"ready")),
                })
                .await
        })
    };
    tokio::task::yield_now().await;
    assert!(!dispatch.is_finished());

    drop(held);
    tokio::time::timeout(Duration::from_secs(1), dispatch)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut output = [0; 5];
    stream.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, b"ready");
    session.close();
}

#[tokio::test]
async fn unread_tcp_child_does_not_block_siblings() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let _blocked = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "93.184.216.34:443".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("blocked TCP stream must open"));
    let blocked_id = read_wire_frame(&mut wire).await.id;
    let mut sibling = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "93.184.216.35:443".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("sibling TCP stream must open"));
    let sibling_id = read_wire_frame(&mut wire).await.id;

    for _ in 0..=TCP_QUEUE_CAPACITY {
        wire.write_all(&response_frame(
            blocked_id,
            STATUS_KEEP,
            OPTION_DATA,
            None,
            Some(b"x"),
        ))
        .await
        .unwrap();
    }
    wire.write_all(&response_frame(
        sibling_id,
        STATUS_KEEP,
        OPTION_DATA,
        None,
        Some(b"ok"),
    ))
    .await
    .unwrap();

    let mut output = [0; 2];
    tokio::time::timeout(Duration::from_secs(1), sibling.read_exact(&mut output))
        .await
        .expect("unread child blocked the physical carrier")
        .unwrap();
    assert_eq!(&output, b"ok");
    assert_eq!(session.state(), SessionState::Active);
    session.close();
}

#[tokio::test]
async fn source_reply_fallback_uses_first_sender_not_preparation_or_latest() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let unused_preparation_domain = "x".repeat(256);
    let udp = open_xudp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        udp_target(),
        Some(&unused_preparation_domain),
        [1, 2, 3, 4, 5, 6, 7, 8],
    )
    .await
    .unwrap_or_else(|_| panic!("UDP transport must open"));
    let empty_error = udp
        .send_to(
            "192.0.2.1:5353".parse().unwrap(),
            Some("empty.example"),
            b"",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(empty_error.kind(), io::ErrorKind::InvalidInput);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read_frame(&mut wire))
            .await
            .is_err(),
        "source preparation must not send an eager NEW frame"
    );
    let committed_target = "1.1.1.1:5353".parse().unwrap();
    udp.send_to(committed_target, Some("first.example"), b"query", None)
        .await
        .unwrap();
    let request = read_wire_frame(&mut wire).await;
    let first_peer = "5.6.7.8:1000".parse().unwrap();
    let second_peer = "9.10.11.12:2000".parse().unwrap();
    wire.write_all(&response_frame(
        request.id,
        STATUS_KEEP,
        OPTION_DATA,
        Some(first_peer),
        Some(b"answer"),
    ))
    .await
    .unwrap();
    assert_eq!(
        udp.recv_packet(&mut [0; 2]).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let mut output = [0; 16];
    assert_eq!(udp.recv_packet(&mut output).await.unwrap(), (6, first_peer));
    assert_eq!(&output[..6], b"answer");

    wire.write_all(&response_frame(
        request.id,
        STATUS_KEEP,
        OPTION_DATA,
        Some(second_peer),
        Some(b"next"),
    ))
    .await
    .unwrap();
    assert_eq!(
        udp.recv_packet(&mut output).await.unwrap(),
        (4, second_peer)
    );
    assert_eq!(&output[..4], b"next");
    let later_target = "2.2.2.2:5354".parse().unwrap();
    udp.send_to(later_target, Some("later.example"), b"later", None)
        .await
        .unwrap();
    let keep = read_wire_frame(&mut wire).await;
    assert_eq!(keep.status, STATUS_KEEP);
    wire.write_all(&response_frame(
        request.id,
        STATUS_KEEP,
        OPTION_DATA,
        None,
        Some(b"fixed"),
    ))
    .await
    .unwrap();
    assert_eq!(
        udp.recv_packet(&mut output).await.unwrap(),
        (5, committed_target)
    );
    assert_eq!(&output[..5], b"fixed");
    let mut domain_response = base_metadata(request.id, STATUS_KEEP, OPTION_DATA);
    domain_response.extend_from_slice(&[NETWORK_UDP]);
    encode_address(&mut domain_response, udp_target(), Some("first.example")).unwrap();
    wire.write_all(&metadata_frame(domain_response, Some(b"domain")).unwrap())
        .await
        .unwrap();
    assert_eq!(
        udp.recv_packet(&mut output).await.unwrap(),
        (6, "1.1.1.1:53".parse().unwrap())
    );
    assert_eq!(&output[..6], b"domain");
    wire.write_all(&response_frame(request.id, STATUS_END, 0, None, None))
        .await
        .unwrap();
    assert_eq!(
        udp.recv_packet(&mut output).await.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(
        udp.send_packet_confirmed(b"late").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    session.close();
}

#[test]
fn keep_domain_preserves_wire_port_and_validates_identity() {
    let mut metadata = base_metadata(1, STATUS_KEEP, OPTION_DATA);
    metadata.extend_from_slice(&[NETWORK_UDP]);
    encode_address(
        &mut metadata,
        "9.9.9.9:5353".parse().unwrap(),
        Some("DNS.Example"),
    )
    .unwrap();
    assert_eq!(
        parse_keep_peer(
            &metadata,
            "1.2.3.4:53".parse().unwrap(),
            Some("dns.example")
        )
        .unwrap(),
        "1.2.3.4:5353".parse().unwrap()
    );
    assert!(
        parse_keep_peer(
            &metadata,
            "1.2.3.4:53".parse().unwrap(),
            Some("other.example")
        )
        .is_err()
    );
}

#[tokio::test]
async fn udp_receive_byte_budget_drops_excess_datagrams() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    Arc::clone(&session.receive_budget)
        .acquire_many_owned((RECEIVE_BYTE_BUDGET - 4) as u32)
        .await
        .unwrap()
        .forget();
    let udp = open_udp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        udp_target(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("UDP transport must open"));
    udp.send_packet_confirmed(b"query").await.unwrap();
    let request = read_wire_frame(&mut wire).await;
    wire.write_all(&response_frame(
        request.id,
        STATUS_KEEP,
        OPTION_DATA,
        None,
        Some(b"large"),
    ))
    .await
    .unwrap();
    wire.write_all(&response_frame(
        request.id,
        STATUS_KEEP,
        OPTION_DATA,
        None,
        Some(b"fits"),
    ))
    .await
    .unwrap();

    let mut output = [0; 8];
    assert_eq!(udp.recv_packet(&mut output).await.unwrap().0, 4);
    assert_eq!(&output[..4], b"fits");
    assert_eq!(session.receive_budget.available_permits(), 4);
    session.close();
}

/// A KEEP frame with unreadable UDP metadata fails only the child it names;
/// the carrier and its other logical connections keep working.
#[tokio::test]
async fn malformed_xudp_keep_metadata_fails_only_its_child() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let first = open_udp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        udp_target(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("first UDP transport must open"));
    let second = open_udp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "5.6.7.8:53".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("second UDP transport must open"));
    first.send_packet_confirmed(b"one").await.unwrap();
    let first_request = read_wire_frame(&mut wire).await;
    second.send_packet_confirmed(b"two").await.unwrap();
    let second_request = read_wire_frame(&mut wire).await;

    // Eight metadata bytes whose network byte is TCP: not a UDP endpoint.
    let mut metadata = base_metadata(first_request.id, STATUS_KEEP, OPTION_DATA);
    metadata.extend_from_slice(&[codec::NETWORK_TCP, 0, 53, codec::ATYP_IPV4]);
    wire.write_all(&metadata_frame(metadata, Some(b"bad")).unwrap())
        .await
        .unwrap();
    wire.write_all(&response_frame(
        second_request.id,
        STATUS_KEEP,
        OPTION_DATA,
        None,
        Some(b"reply"),
    ))
    .await
    .unwrap();

    let mut output = [0; 8];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), second.recv_packet(&mut output))
        .await
        .expect("the carrier must survive another child's malformed KEEP")
        .unwrap();
    assert_eq!(&output[..n], b"reply");
    let failed = tokio::time::timeout(Duration::from_secs(2), first.recv_packet(&mut output))
        .await
        .expect("the named child must observe its failure")
        .unwrap_err();
    assert_eq!(failed.kind(), io::ErrorKind::InvalidData);
    // The carrier still answers a new logical connection.
    let third = open_udp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        udp_target(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("the carrier must still open children"));
    third.send_packet_confirmed(b"three").await.unwrap();
    // The failed child's END goes out first; the new child's NEW follows.
    let ended = read_wire_frame(&mut wire).await;
    assert_eq!((ended.id, ended.status), (first_request.id, STATUS_END));
    assert_eq!(read_wire_frame(&mut wire).await.status, STATUS_NEW);
    session.close();
}

#[tokio::test]
async fn new_tcp_is_flushed_for_target_speaks_first() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        let request = read_wire_frame(&mut wire).await;
        assert_eq!(request.status, STATUS_NEW);
        assert!(request.payload.is_none());
        wire.write_all(&response_frame(
            request.id,
            STATUS_KEEP,
            OPTION_DATA,
            None,
            Some(b""),
        ))
        .await
        .unwrap();
        wire.write_all(&response_frame(
            request.id,
            STATUS_KEEP,
            OPTION_DATA,
            None,
            Some(b"hello"),
        ))
        .await
        .unwrap();
    });
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let mut stream = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "93.184.216.34:443".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("TCP stream must open"));
    let mut greeting = [0; 5];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hello");
    session.close();
    server.await.unwrap();
}

#[tokio::test]
async fn ready_tcp_consumer_survives_a_large_carrier_burst() {
    const FRAMES: usize = 2048;
    let (client, mut wire) = tokio::io::duplex(20 << 20);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let mut stream = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "93.184.216.34:443".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("TCP stream must open"));
    let request = read_wire_frame(&mut wire).await;
    let payload = vec![0xA5; MAX_TCP_CHUNK];
    let response = response_frame(request.id, STATUS_KEEP, OPTION_DATA, None, Some(&payload));
    for _ in 0..FRAMES {
        wire.write_all(&response).await.unwrap();
    }

    let mut output = vec![0; FRAMES * payload.len()];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut output))
        .await
        .expect("ready TCP consumer was starved by the carrier reader")
        .unwrap();
    assert!(output.iter().all(|byte| *byte == 0xA5));
    session.close();
}

#[tokio::test]
async fn concurrent_tcp_and_udp_share_one_atomic_writer() {
    let (client, mut wire) = tokio::io::duplex(1 << 20);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let mut tcp = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "93.184.216.34:443".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("TCP stream must open"));
    let tcp_new = read_wire_frame(&mut wire).await;
    assert_eq!(tcp_new.id, 1);
    let udp = open_udp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        udp_target(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("UDP transport must open"));
    let (tcp_result, udp_result) = tokio::join!(
        tcp.write_all(b"tcp-data"),
        udp.send_packet_confirmed(b"udp-first")
    );
    tcp_result.unwrap();
    udp_result.unwrap();
    let mut frames = [
        read_wire_frame(&mut wire).await,
        read_wire_frame(&mut wire).await,
    ];
    frames.sort_by_key(|frame| frame.id);
    assert_eq!(frames[0].id, 1);
    assert_eq!(frames[0].status, STATUS_KEEP);
    assert_eq!(frames[0].payload.as_deref(), Some(&b"tcp-data"[..]));
    assert_eq!(frames[1].id, 2);
    assert_eq!(frames[1].status, STATUS_NEW);
    assert_eq!(frames[1].payload.as_deref(), Some(&b"udp-first"[..]));
    session.close();
}

#[tokio::test]
async fn session_ids_are_never_reused_and_carrier_drains_at_128() {
    let (client, mut wire) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(async move {
        let mut ids = Vec::new();
        for _ in 0..MAX_STREAMS_PER_SESSION {
            let new = read_wire_frame(&mut wire).await;
            ids.push(new.id);
            let end = read_wire_frame(&mut wire).await;
            assert_eq!(end.id, new.id);
            assert_eq!(end.status, STATUS_END);
        }
        ids
    });
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    for _ in 0..MAX_STREAMS_PER_SESSION {
        let permit = session.try_reserve().unwrap();
        let mut stream = open_tcp(
            Arc::clone(&session),
            permit,
            "127.0.0.1:80".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("ID within lifetime cap must open"));
        stream.shutdown().await.unwrap();
        drop(stream);
    }
    let ids = server.await.unwrap();
    assert_eq!(
        ids,
        (1..=MAX_STREAMS_PER_SESSION as u16).collect::<Vec<_>>()
    );
    assert!(session.is_closed());
    assert!(session.try_reserve().is_none());
}

#[tokio::test]
async fn end_error_and_physical_eof_fail_children() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let mut first = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "127.0.0.1:80".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("first stream must open"));
    let first_id = read_wire_frame(&mut wire).await.id;
    let mut second = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "127.0.0.1:81".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("second stream must open"));
    let second_id = read_wire_frame(&mut wire).await.id;
    wire.write_all(&response_frame(first_id, STATUS_END, 0, None, None))
        .await
        .unwrap();
    wire.write_all(&response_frame(
        second_id,
        STATUS_END,
        OPTION_ERROR,
        None,
        None,
    ))
    .await
    .unwrap();
    let mut eof = [0; 1];
    assert_eq!(first.read(&mut eof).await.unwrap(), 0);
    assert_eq!(
        first.write_all(b"late").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    let refused = second.read_u8().await.unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(
        crate::group::ScoreOutcome::from_io_error(&refused),
        crate::group::ScoreOutcome::TargetFailure
    );

    let udp = open_xudp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        udp_target(),
        None,
        [1; 8],
    )
    .await
    .unwrap_or_else(|_| panic!("TCP refusal must leave the carrier usable"));
    udp.send_packet_confirmed(b"query").await.unwrap();
    let udp_id = read_wire_frame(&mut wire).await.id;
    let other_target = "5.6.7.8:53".parse().unwrap();
    udp.send_to(other_target, None, b"other query", None)
        .await
        .unwrap();
    assert_eq!(read_wire_frame(&mut wire).await.id, udp_id);
    let sibling_udp = open_xudp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        udp_target(),
        None,
        [2; 8],
    )
    .await
    .unwrap_or_else(|_| panic!("another UDP source must open"));
    sibling_udp
        .send_packet_confirmed(b"sibling query")
        .await
        .unwrap();
    let sibling_udp_id = read_wire_frame(&mut wire).await.id;
    assert_ne!(sibling_udp_id, udp_id);
    wire.write_all(&response_frame(
        udp_id,
        STATUS_END,
        OPTION_ERROR,
        None,
        None,
    ))
    .await
    .unwrap();
    let udp_error = udp.recv_packet(&mut [0; 1]).await.unwrap_err();
    let source_failure = crate::group::ScoreOutcome::from_io_error(&udp_error);
    assert!(matches!(
        source_failure,
        crate::group::ScoreOutcome::SharedNodeFailure(_)
    ));
    for target in [udp_target(), other_target] {
        let error = udp.send_to(target, None, b"late", None).await.unwrap_err();
        assert_eq!(
            crate::group::ScoreOutcome::from_io_error(&error),
            source_failure,
            "late sends repeat the source's one END|ERROR event"
        );
    }
    wire.write_all(&response_frame(
        sibling_udp_id,
        STATUS_KEEP,
        OPTION_DATA,
        Some(udp_target()),
        Some(b"answer"),
    ))
    .await
    .unwrap();
    let mut answer = [0; 6];
    assert_eq!(
        sibling_udp.recv_packet(&mut answer).await.unwrap(),
        (6, udp_target())
    );
    assert_eq!(&answer, b"answer");
    assert!(!session.is_closed());

    let mut third = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "127.0.0.1:82".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("third stream must open"));
    let mut fourth = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "127.0.0.1:83".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("fourth stream must open"));
    let _ = read_wire_frame(&mut wire).await;
    let _ = read_wire_frame(&mut wire).await;
    drop(wire);
    let physical = crate::group::ScoreOutcome::from_io_error(&third.read_u8().await.unwrap_err());
    assert!(matches!(
        physical,
        crate::group::ScoreOutcome::SharedNodeFailure(_)
    ));
    assert_ne!(physical, source_failure);
    assert_eq!(
        crate::group::ScoreOutcome::from_io_error(&fourth.read_u8().await.unwrap_err()),
        physical,
        "one carrier failure is one episode"
    );
    assert!(session.is_closed());
}

#[tokio::test]
async fn zero_global_id_is_omitted_without_a_source_identity() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let first = open_udp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        udp_target(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("first UDP transport must open"));
    let second = open_udp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "5.6.7.8:53".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("second UDP transport must open"));
    first.send_packet_confirmed(b"one").await.unwrap();
    first.send_packet_confirmed(b"two").await.unwrap();
    second.send_packet_confirmed(b"three").await.unwrap();
    let new_first = read_wire_frame(&mut wire).await;
    let keep_first = read_wire_frame(&mut wire).await;
    let new_second = read_wire_frame(&mut wire).await;
    assert_eq!(new_first.metadata.len(), 12);
    assert_eq!(keep_first.status, STATUS_KEEP);
    assert_eq!(new_second.metadata.len(), 12);
    session.close();
}
