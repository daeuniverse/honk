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

    let _third = session
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
        session.is_closed(),
        "a missing SYNACK retires the reused session"
    );
    assert!(
        session
            .terminal_error
            .get()
            .is_some_and(|error| error.to_string().contains("SYNACK timed out"))
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

/// Each open gets its own full deadline: acknowledging an earlier stream
/// must not leave a later stream on the earlier one's clock.
#[tokio::test(start_paused = true)]
async fn synack_deadlines_do_not_share_elapsed_time() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;

    let second = session
        .open_stream_direct(
            vec![0x01, 2, 2, 2, 2, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    read_frame(&mut server).await.unwrap();
    read_frame(&mut server).await.unwrap();
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(1)).await;
    let _third = session
        .open_stream_direct(
            vec![0x01, 3, 3, 3, 3, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    let third_sid = _third.sid;
    read_frame(&mut server).await.unwrap();
    read_frame(&mut server).await.unwrap();
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_millis(500)).await;
    write_frame(&mut server, CMD_SYNACK, second.sid, &[])
        .await
        .unwrap();
    tokio::task::yield_now().await;

    // 1.6s past the second stream's deadline, but only 2.1s into the third's.
    tokio::time::advance(Duration::from_millis(1600)).await;
    tokio::task::yield_now().await;
    assert!(
        !session.is_closed(),
        "the third stream keeps its own full deadline"
    );

    tokio::time::advance(SYNACK_TIMEOUT).await;
    tokio::task::yield_now().await;
    // The third stream's own deadline fires; the session kept receiving
    // frames (the second stream's SYNACK), so only the stream is reset.
    assert!(
        !session.is_closed(),
        "an active session survives a single unanswered open"
    );
    assert!(
        !session.synack_pending.lock().sids.contains_key(&third_sid),
        "the third stream's deadline entry is consumed"
    );
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
    for _ in 0..4 {
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
    assert!(err.to_string().contains("not acknowledged"), "{err}");
    let n = first.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ok", "the sibling stream keeps its data");
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

/// A SYNACK that arrives while the SYN is still queued must settle the open:
/// registering at queue time means the wire-time arm finds nothing to do.
#[tokio::test(start_paused = true)]
async fn synack_before_wire_write_settles_the_open() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;

    let second = session
        .open_stream_direct(
            vec![0x01, 2, 2, 2, 2, 0, 80],
            session.try_reserve().unwrap(),
        )
        .await
        .unwrap();
    // ACK before the writer has written the SYN.
    write_frame(&mut server, CMD_SYNACK, second.sid, &[])
        .await
        .unwrap();
    tokio::task::yield_now().await;
    // Now let the writer put the SYN on the wire.
    read_frame(&mut server).await.unwrap();
    read_frame(&mut server).await.unwrap();
    tokio::task::yield_now().await;

    tokio::time::advance(SYNACK_TIMEOUT + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert!(
        !session.is_closed(),
        "an early SYNACK must not strand a never-armed deadline"
    );
}
