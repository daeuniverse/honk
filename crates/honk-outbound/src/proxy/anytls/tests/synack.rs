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
