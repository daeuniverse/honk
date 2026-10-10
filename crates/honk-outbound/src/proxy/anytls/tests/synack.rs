use super::*;
/// 3B-3: a SYNACK carrying a dial error surfaces as a stream error
/// (not a clean EOF) and the session stays healthy.
#[tokio::test]
async fn test_synack_with_data_surfaces_open_error() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    let permit = session.try_reserve().unwrap();
    let mut stream = session
        .open_stream_direct(vec![0x01, 1, 2, 3, 4, 0, 80], permit)
        .await
        .unwrap();
    let (cmd, sid, _) = read_frame(&mut server).await.unwrap();
    assert_eq!(cmd, CMD_SYN);
    let (cmd, _, _) = read_frame(&mut server).await.unwrap();
    assert_eq!(cmd, CMD_PSH);
    write_frame(&mut server, CMD_SYNACK, sid, b"refused: banned")
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let err = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("read settles")
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(err.to_string().contains("refused"));
    assert_eq!(
        crate::group::ScoreOutcome::from_io_error(&err),
        crate::group::ScoreOutcome::TargetFailure
    );
    assert!(!session.is_closed(), "target refusal keeps the session");
    assert!(!session.streams.lock().unwrap().contains_key(&stream.sid));
}

#[tokio::test(start_paused = true)]
async fn reused_v2_session_requires_synack_within_deadline() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert!(session.peer_supports_synack.load(Ordering::Acquire));

    let first = session
        .open_stream_direct(
            vec![0x01, 1, 1, 1, 1, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_SYN);
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_PSH);

    let second = session
        .open_stream_direct(
            vec![0x01, 2, 2, 2, 2, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_SYN);
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_PSH);
    write_frame(&mut server, CMD_SYNACK, second.sid, &[])
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert!(session.synack_pending.lock().sids.is_empty());
    tokio::time::advance(SYNACK_TIMEOUT + Duration::from_millis(1)).await;
    assert!(
        !session.is_closed(),
        "a received SYNACK keeps the session live"
    );

    let mut third = session
        .open_stream_direct(
            vec![0x01, 3, 3, 3, 3, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_SYN);
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_PSH);
    tokio::task::yield_now().await;
    tokio::time::advance(SYNACK_TIMEOUT + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;

    assert!(
        !session.is_closed(),
        "one silent window must not kill the carrier's other streams"
    );
    assert_eq!(
        crate::session::ManagedSession::state(&*session),
        crate::session::SessionState::Draining,
        "a silent carrier takes no new streams"
    );
    let error = third.read_u8().await.unwrap_err();
    assert!(crate::group::ScoreOutcome::from_io_error(&error).is_node_failure());

    tokio::time::advance(SILENT_SESSION_GRACE).await;
    tokio::task::yield_now().await;
    assert!(
        session.is_closed(),
        "a carrier that stays silent through the grace period is retired"
    );
    drop((first, second));
}

/// Regression for the PR review repro: a SYNACK for one stream must not
/// cancel the deadline of a concurrent, still-unacknowledged open.
#[tokio::test(start_paused = true)]
async fn synack_deadline_is_tracked_per_stream() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;

    let _first = session
        .open_stream_direct(
            vec![0x01, 1, 1, 1, 1, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    let second = session
        .open_stream_direct(
            vec![0x01, 2, 2, 2, 2, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    let _third = session
        .open_stream_direct(
            vec![0x01, 3, 3, 3, 3, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    for _ in 0..6 {
        read_frame(&mut server).await.unwrap();
    }
    tokio::task::yield_now().await;

    // A late SYNACK for the second stream leaves the third one pending.
    write_frame(&mut server, CMD_SYNACK, second.sid, &[])
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert!(!session.synack_pending.lock().sids.is_empty());

    tokio::time::advance(SYNACK_TIMEOUT + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    // The third stream's own deadline still fires, but the session was
    // receiving frames through the window, so only the stream is reset.
    assert!(
        !session.is_closed(),
        "an active session must survive one unanswered open"
    );
    assert!(
        session.streams.lock().unwrap().contains_key(&second.sid),
        "the acknowledged sibling stream is untouched"
    );
}

/// Each reused open gets its own full deadline: acknowledging one stream must
/// neither reset it nor shorten a later stream's deadline.
#[tokio::test(start_paused = true)]
async fn synack_deadlines_do_not_share_elapsed_time() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert!(session.peer_supports_synack.load(Ordering::Acquire));

    let _first = session
        .open_stream_direct(
            vec![0x01, 1, 1, 1, 1, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    for _ in 0..2 {
        read_frame(&mut server).await.unwrap();
    }

    let mut acknowledged = session
        .open_stream_direct(
            vec![0x01, 2, 2, 2, 2, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    for _ in 0..2 {
        read_frame(&mut server).await.unwrap();
    }
    assert!(acknowledged.sid >= 2);

    tokio::time::advance(Duration::from_secs(1)).await;
    let mut unanswered = session
        .open_stream_direct(
            vec![0x01, 3, 3, 3, 3, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    assert!(unanswered.sid >= 2);
    for _ in 0..2 {
        read_frame(&mut server).await.unwrap();
    }

    tokio::time::advance(Duration::from_millis(500)).await;
    write_frame(&mut server, CMD_SYNACK, acknowledged.sid, &[])
        .await
        .unwrap();
    write_frame(&mut server, CMD_PSH, acknowledged.sid, b"acknowledged")
        .await
        .unwrap();
    let mut reply = [0; 12];
    acknowledged.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"acknowledged");

    tokio::time::advance(Duration::from_millis(1600)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(1), unanswered.read(&mut [0; 1]))
            .await
            .is_err(),
        "the later open keeps its own full deadline"
    );

    tokio::time::advance(Duration::from_millis(1000)).await;
    tokio::task::yield_now().await;
    let error = tokio::time::timeout(Duration::from_millis(100), unanswered.read(&mut [0; 1]))
        .await
        .expect("acknowledging another stream must not reset this deadline")
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(!session.is_closed());
}

/// A live session that never acknowledges one open (the server's own target
/// dial stalled) must reset only that stream, not die with its siblings.
/// Killed 13 healthy streams per burst on the production gateway before this.
#[tokio::test(start_paused = true)]
async fn synack_timeout_on_active_session_resets_only_the_stream() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;

    let mut first = session
        .open_stream_direct(
            vec![0x01, 1, 1, 1, 1, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    let mut second = session
        .open_stream_direct(
            vec![0x01, 2, 2, 2, 2, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    let uot = Arc::clone(&session)
        .open_packet(
            session.try_reserve().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("UoT service stream must open"));
    for _ in 0..6 {
        read_frame(&mut server).await.unwrap();
    }
    tokio::task::yield_now().await;

    // The sibling keeps receiving data while the second open stays unanswered.
    write_frame(&mut server, CMD_PSH, first.sid, b"ok")
        .await
        .unwrap();
    tokio::task::yield_now().await;

    tokio::time::advance(SYNACK_TIMEOUT + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;

    assert!(
        !session.is_closed(),
        "a session with inbound activity must not die for one unanswered open"
    );
    let mut buf = [0u8; 16];
    let err = second.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    assert_eq!(
        crate::group::ScoreOutcome::from_io_error(&err),
        crate::group::ScoreOutcome::TargetFailure
    );
    let service_error = uot.recv_packet(&mut buf).await.unwrap_err();
    assert!(crate::group::ScoreOutcome::from_io_error(&service_error).is_node_failure());
    let n = first.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ok", "the sibling stream keeps its data");
    let (cmd, sid, _) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, sid), (CMD_FIN, second.sid));
    first.write_all(b"still live").await.unwrap();
    let (cmd, sid, payload) = read_frame(&mut server).await.unwrap();
    assert_eq!(
        (cmd, sid, payload.as_slice()),
        (CMD_PSH, first.sid, b"still live".as_slice())
    );
    session.close();
}

/// A loss burst silences every stream at once. Only the unanswered open may
/// fail; the siblings must survive and the carrier must live on once frames
/// flow again (it used to be retired, resetting every stream on it).
#[tokio::test(start_paused = true)]
async fn silent_window_resets_only_the_open_and_a_recovering_carrier_survives() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;

    let mut first = session
        .open_stream_direct(
            vec![0x01, 1, 1, 1, 1, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    let second = session
        .open_stream_direct(
            vec![0x01, 2, 2, 2, 2, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    for _ in 0..4 {
        read_frame(&mut server).await.unwrap();
    }
    write_frame(&mut server, CMD_SYNACK, second.sid, &[])
        .await
        .unwrap();
    tokio::task::yield_now().await;
    let mut third = session
        .open_stream_direct(
            vec![0x01, 3, 3, 3, 3, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    for _ in 0..2 {
        read_frame(&mut server).await.unwrap();
    }
    tokio::task::yield_now().await;

    tokio::time::advance(SYNACK_TIMEOUT + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    let error = third.read_u8().await.unwrap_err();
    assert!(crate::group::ScoreOutcome::from_io_error(&error).is_node_failure());
    assert!(!session.is_closed());
    assert!(session.streams.lock().unwrap().contains_key(&first.sid));
    assert!(session.streams.lock().unwrap().contains_key(&second.sid));

    tokio::time::advance(Duration::from_secs(5)).await;
    write_frame(&mut server, CMD_PSH, first.sid, b"late")
        .await
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(SILENT_SESSION_GRACE).await;
    tokio::task::yield_now().await;
    assert!(
        !session.is_closed(),
        "frames arrived after the silent window, so the carrier is alive"
    );
    let mut buf = [0u8; 4];
    first.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"late");
    session.close();
}

/// Dropping a stream whose open was never answered must settle its pending
/// entry: an orphaned deadline would otherwise fire later and fail a healthy
/// session.
#[tokio::test(start_paused = true)]
async fn dropped_unanswered_stream_cancels_its_synack_deadline() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;

    let _first = session
        .open_stream_direct(
            vec![0x01, 1, 1, 1, 1, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    let second = session
        .open_stream_direct(
            vec![0x01, 2, 2, 2, 2, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    for _ in 0..4 {
        read_frame(&mut server).await.unwrap();
    }
    tokio::task::yield_now().await;
    assert!(session.synack_pending.lock().sids.contains_key(&second.sid));

    drop(second);
    assert!(
        session.synack_pending.lock().sids.is_empty(),
        "dropping the stream settles its pending entry"
    );

    tokio::time::advance(SYNACK_TIMEOUT + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert!(
        !session.is_closed(),
        "an orphaned deadline must not fail the session"
    );
}

/// A SYNACK received while a reused stream's SYN is physically queued settles
/// that open before the writer later arms its deadline.
#[tokio::test(start_paused = true)]
async fn synack_before_wire_write_settles_the_open() {
    let (session, mut server) = establish_test_session_with_capacity("127.0.0.1:443", 64).await;
    expect_handshake(&mut server).await;
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert!(session.peer_supports_synack.load(Ordering::Acquire));

    let mut first = session
        .open_stream_direct(
            vec![0x01, 1, 1, 1, 1, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    for _ in 0..2 {
        read_frame(&mut server).await.unwrap();
    }
    first.write_all(&vec![0x5a; 1024]).await.unwrap();
    tokio::task::yield_now().await;

    let mut reused = session
        .open_stream_direct(
            vec![0x01, 2, 2, 2, 2, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    assert!(reused.sid >= 2);
    write_frame(&mut server, CMD_SYNACK, reused.sid, &[])
        .await
        .unwrap();
    tokio::task::yield_now().await;

    let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, sid, data.len()), (CMD_PSH, first.sid, 1024));
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_SYN);
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_PSH);

    tokio::time::advance(SYNACK_TIMEOUT + Duration::from_millis(1)).await;
    write_frame(&mut server, CMD_PSH, reused.sid, b"open")
        .await
        .unwrap();
    let mut reply = [0; 4];
    reused.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"open");
    assert!(!session.is_closed());
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn target_evidence_is_scoped_to_sid_and_uot_ack_is_not_target_confirmation() {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};
    let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
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
    let udp = observe(uuid::Uuid::new_v4());
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    let mut first_stream = first
        .scope(
            session.open_stream_direct(vec![1, 1, 1, 1, 1, 0, 80], session.try_reserve().unwrap()),
        )
        .await
        .unwrap();
    let mut second_stream = second
        .scope(
            session.open_stream_direct(vec![1, 2, 2, 2, 2, 0, 80], session.try_reserve().unwrap()),
        )
        .await
        .unwrap();
    for _ in 0..4 {
        read_frame(&mut server).await.unwrap();
    }
    write_frame(&mut server, CMD_SYNACK, second_stream.sid, b"refused")
        .await
        .unwrap();
    assert!(second_stream.read_u8().await.is_err());
    let (command, sid, _) = read_frame(&mut server).await.unwrap();
    assert_eq!((command, sid), (CMD_FIN, second_stream.sid));
    write_frame(&mut server, CMD_SYNACK, first_stream.sid, &[])
        .await
        .unwrap();
    write_frame(&mut server, CMD_PSH, first_stream.sid, b"x")
        .await
        .unwrap();
    assert_eq!(first_stream.read_u8().await.unwrap(), b'x');

    let transport = udp
        .scope(Arc::clone(&session).open_packet(
            session.try_reserve().unwrap(),
            "8.8.8.8:53".parse().unwrap(),
            None,
        ))
        .await
        .unwrap_or_else(|_| panic!("UoT open failed"));
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_SYN);
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_PSH);
    write_frame(&mut server, CMD_SYNACK, transport.sid, &[])
        .await
        .unwrap();
    assert!(
        !events
            .lock()
            .iter()
            .any(|(id, _)| *id == udp.context().flow_id)
    );
    let (sent, frame) = tokio::join!(
        transport.send_packet_confirmed(b"dns"),
        read_frame(&mut server),
    );
    sent.unwrap();
    assert_eq!(frame.unwrap().0, CMD_PSH);
    let events = events.lock();
    assert_eq!(
        events
            .iter()
            .filter_map(|(id, event)| { (*id == first.context().flow_id).then_some(*event) })
            .collect::<Vec<_>>(),
        ["target_request_sent", "target_confirmed"]
    );
    assert_eq!(
        events
            .iter()
            .filter_map(|(id, event)| { (*id == second.context().flow_id).then_some(*event) })
            .collect::<Vec<_>>(),
        ["target_request_sent"]
    );
    assert_eq!(
        events
            .iter()
            .filter_map(|(id, event)| { (*id == udp.context().flow_id).then_some(*event) })
            .collect::<Vec<_>>(),
        ["target_request_sent"]
    );
    drop(events);
    drop((transport, first_stream, second_stream));
    session.close();
}
