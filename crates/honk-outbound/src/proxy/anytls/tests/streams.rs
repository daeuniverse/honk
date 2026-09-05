use super::*;
#[tokio::test]
async fn settings_wait_for_the_first_stream_open() {
    let (client, mut server) = tokio::io::duplex(1 << 20);
    let (read, write) = tokio::io::split(client);
    let session = AnyTlsSession::establish(
        "deferred-settings",
        Box::new(read),
        Box::new(write),
        TEST_AUTH,
        bytes::Bytes::from_static(TEST_SETTINGS),
        test_padding(),
        test_inbound_payload_budget(),
    )
    .await
    .unwrap();

    let mut auth = vec![0; TEST_AUTH.len()];
    server.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, TEST_AUTH);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read_frame(&mut server))
            .await
            .is_err()
    );

    let stream = session
        .open_stream_direct(b"target".to_vec(), session.try_reserve().unwrap())
        .await
        .unwrap();
    assert_eq!(
        read_frame(&mut server).await.unwrap(),
        (CMD_SETTINGS, 0, TEST_SETTINGS.to_vec())
    );
    assert_eq!(
        read_frame(&mut server).await.unwrap(),
        (CMD_SYN, stream.sid, Vec::new())
    );
    assert_eq!(
        read_frame(&mut server).await.unwrap(),
        (CMD_PSH, stream.sid, b"target".to_vec())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn concurrent_first_open_keeps_settings_ahead_of_syn() {
    let (client, mut server) = tokio::io::duplex(1 << 20);
    let (read, write) = tokio::io::split(client);
    let session = AnyTlsSession::establish(
        "concurrent-first-open",
        Box::new(read),
        Box::new(write),
        TEST_AUTH,
        bytes::Bytes::from_static(TEST_SETTINGS),
        test_padding(),
        test_inbound_payload_budget(),
    )
    .await
    .unwrap();

    let mut auth = vec![0; TEST_AUTH.len()];
    server.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, TEST_AUTH);

    let writer_guard = session.writer_q.queue.lock();
    let first = tokio::spawn({
        let session = Arc::clone(&session);
        let permit = session.try_reserve().unwrap();
        async move { session.open_stream_direct(b"first".to_vec(), permit).await }
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(settings) = session.initial_settings.try_lock() {
            assert!(
                settings.is_some(),
                "first opener released SETTINGS before committing its queue order"
            );
            drop(settings);
            assert!(Instant::now() < deadline, "first opener did not start");
            std::thread::yield_now();
            continue;
        }
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            session.initial_settings.try_lock().is_none(),
            "first opener released SETTINGS while waiting for the writer queue"
        );
        break;
    }

    let second = tokio::spawn({
        let session = Arc::clone(&session);
        let permit = session.try_reserve().unwrap();
        async move { session.open_stream_direct(b"second".to_vec(), permit).await }
    });
    drop(writer_guard);

    let first = first.await.unwrap().unwrap();
    let second = second.await.unwrap().unwrap();
    assert_eq!(
        read_frame(&mut server).await.unwrap(),
        (CMD_SETTINGS, 0, TEST_SETTINGS.to_vec())
    );
    assert_eq!(
        read_frame(&mut server).await.unwrap(),
        (CMD_SYN, first.sid, Vec::new())
    );
    assert_eq!(
        read_frame(&mut server).await.unwrap(),
        (CMD_PSH, first.sid, b"first".to_vec())
    );
    assert_eq!(
        read_frame(&mut server).await.unwrap(),
        (CMD_SYN, second.sid, Vec::new())
    );
    assert_eq!(
        read_frame(&mut server).await.unwrap(),
        (CMD_PSH, second.sid, b"second".to_vec())
    );
}

#[tokio::test]
async fn empty_control_frames_do_not_close_the_session() {
    let (session, mut server) = establish_test_session("empty-controls").await;
    expect_handshake(&mut server).await;
    let mut stream = session
        .open_stream_direct(b"target".to_vec(), session.try_reserve().unwrap())
        .await
        .unwrap();
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_SYN);
    assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_PSH);
    let padding_md5 = session.padding_state.snapshot().md5.clone();

    write_frame(&mut server, CMD_ALERT, 0, &[]).await.unwrap();
    write_frame(&mut server, CMD_UPDATE_PADDING_SCHEME, 0, &[])
        .await
        .unwrap();
    write_frame(&mut server, CMD_PSH, stream.sid, &[])
        .await
        .unwrap();
    write_frame(&mut server, CMD_PSH, stream.sid, b"alive")
        .await
        .unwrap();
    let mut response = [0; 5];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"alive");
    assert!(!session.is_closed());
    assert_eq!(session.padding_state.snapshot().md5, padding_md5);

    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !session.peer_supports_synack.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=1\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while session.peer_supports_synack.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn padding_update_applies_to_an_active_session_before_stop() {
    let padding_state = Arc::new(PaddingState {
        current: parking_lot::RwLock::new(Arc::new(PaddingScheme::parse(b"stop=8").unwrap())),
    });
    let (client, mut server) = tokio::io::duplex(1 << 20);
    let (read, write) = tokio::io::split(client);
    let session = AnyTlsSession::establish(
        "padding-update",
        Box::new(read),
        Box::new(write),
        TEST_AUTH,
        bytes::Bytes::from_static(TEST_SETTINGS),
        Arc::clone(&padding_state),
        test_inbound_payload_budget(),
    )
    .await
    .unwrap();
    session.flush_initial_settings_for_test().unwrap();
    expect_handshake(&mut server).await;

    let update = b"stop=4\n2=30-30";
    let updated_md5 = PaddingScheme::parse(update).unwrap().md5;
    write_frame(&mut server, CMD_UPDATE_PADDING_SCHEME, 0, update)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while padding_state.snapshot().md5 != updated_md5 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let stream = session
        .open_stream_direct(b"target".to_vec(), session.try_reserve().unwrap())
        .await
        .unwrap();
    assert_eq!(
        read_frame(&mut server).await.unwrap(),
        (CMD_SYN, stream.sid, Vec::new())
    );
    let (cmd, sid, padding) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, sid, padding.len()), (CMD_WASTE, 0, 16));
    assert!(padding.iter().all(|byte| *byte == 0));
    assert_eq!(
        read_frame(&mut server).await.unwrap(),
        (CMD_PSH, stream.sid, b"target".to_vec())
    );
}

/// A fake AnyTLS server: consumes each SYN and its address PSH (the
/// address is forwarded to `addr_tx`), echoes payload PSHs back to the
/// same sid, and answers FIN with FIN.
pub(super) fn spawn_echo_server(
    mut server: tokio::io::DuplexStream,
) -> mpsc::UnboundedReceiver<(u32, Vec<u8>)> {
    let (addr_tx, addr_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut pending_addr: HashSet<u32> = HashSet::new();
        let mut known: HashSet<u32> = HashSet::new();
        loop {
            let Ok((cmd, sid, data)) = read_frame(&mut server).await else {
                break;
            };
            match cmd {
                CMD_SYN => {
                    known.insert(sid);
                    pending_addr.insert(sid);
                }
                CMD_PSH if pending_addr.remove(&sid) => {
                    addr_tx.send((sid, data)).unwrap();
                }
                CMD_PSH if known.contains(&sid) => {
                    write_frame(&mut server, CMD_PSH, sid, &data).await.unwrap();
                }
                CMD_FIN if known.contains(&sid) => {
                    known.remove(&sid);
                    write_frame(&mut server, CMD_FIN, sid, &[]).await.unwrap();
                }
                _ => {}
            }
        }
    });
    addr_rx
}

/// poll_write cancel safety: a cancelled write neither loses the
/// payload nor enqueues it twice; a retry reuses the stored slot.
#[tokio::test]
async fn test_poll_write_cancel_safety() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    let mut addr_rx = spawn_echo_server(server);
    let target = vec![0x01, 127, 0, 0, 1, 0x01, 0xbb];
    let permit = session.try_reserve().unwrap();
    let mut stream = session.open_stream_direct(target, permit).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
        .await
        .unwrap();

    let sem = Arc::clone(&session.writer_q.data_permits);
    let mut hog = Vec::new();
    while let Ok(p) = Arc::clone(&sem).try_acquire_owned() {
        hog.push(p);
    }
    assert!(!hog.is_empty());

    let one = b"payload-one".to_vec();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), stream.write(&one))
            .await
            .is_err()
    );

    drop(hog.pop());
    tokio::time::timeout(Duration::from_secs(2), stream.write(&one))
        .await
        .unwrap()
        .unwrap();

    let two = b"payload-two".to_vec();
    drop(hog);
    tokio::time::timeout(Duration::from_secs(2), stream.write(&two))
        .await
        .unwrap()
        .unwrap();

    let mut echoed = vec![0u8; one.len() + two.len()];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    let mut want = one.clone();
    want.extend_from_slice(&two);
    assert_eq!(echoed, want);
}

#[tokio::test]
async fn test_pool_offer_reuses_and_invalidates() {
    let pool = crate::session::SessionPool::new(crate::session::SessionPoolConfig::default());
    let addr = "127.0.0.1:1234";
    let (session, mut server) = establish_test_session(addr).await;
    expect_handshake(&mut server).await;
    pool.insert(&session);

    let offered = pool
        .offer(|| async { anyhow::bail!("must not dial") })
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&session, &offered));

    pool.invalidate(&session);
    assert!(session.is_closed());
    assert!(
        pool.offer(|| async { anyhow::bail!("no server") })
            .await
            .is_err()
    );
}

/// Write `payload` on `stream` and assert it echoes back intact.
async fn echo<S>(stream: &mut S, payload: &[u8]) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(payload).await?;
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")?;
    assert_eq!(buf, payload);
    Ok(())
}

/// Regression (113666e): Data+Fin enqueued before the first poll must
/// deliver the data first and a zero-byte EOF next — the batched drain
/// must not eat the Fin and hang the relay.
#[tokio::test]
async fn test_data_fin_same_batch_delivers_data_then_eof() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 7u32;
    let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let permit = session.try_reserve().unwrap();
    let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);

    let sink = session.streams.lock().unwrap().get(&sid).cloned().unwrap();
    sink.send_data(b"hello".to_vec()).await;
    sink.send_fin().await;

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");

    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("EOF never delivered — Fin was eaten")
        .unwrap();
    assert_eq!(n, 0);

    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);
}

/// Same-batch variant with multiple data frames before the Fin.
#[tokio::test]
async fn test_multi_data_fin_same_batch() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 9u32;
    let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let permit = session.try_reserve().unwrap();
    let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);

    let sink = session.streams.lock().unwrap().get(&sid).cloned().unwrap();
    sink.send_data(b"aa".to_vec()).await;
    sink.send_data(b"bbb".to_vec()).await;
    sink.send_fin().await;

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"aabbb", "both frames batch into one read");
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);
}

/// 0.5.2/v2: an uncommitted registration cleans the sid and releases
/// the capacity slot on drop.
#[tokio::test]
async fn test_registration_guard_drop_cleans_uncommitted() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 11u32;
    let (tx, _rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let permit = session.try_reserve().unwrap();
    assert_eq!(session.active_streams(), 1);
    {
        let _guard = StreamRegistration {
            session: Arc::clone(&session),
            sid,
            frame_started: false,
            committed: false,
            permit: Some(permit),
        };
    }
    assert!(session.streams.lock().unwrap().get(&sid).is_none());
    assert_eq!(session.active_streams(), 0, "the slot is released");
    assert!(
        !session.is_closed(),
        "no frame was started: session must survive"
    );
}

/// v2 writer queue: an abandoned mid-open registration cleans up
/// with a FIN (the queue makes partial frames impossible) — the
/// session survives.
#[tokio::test]
async fn test_registration_guard_partial_frame_sends_fin() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    let sid = 13u32;
    let (tx, _rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let permit = session.try_reserve().unwrap();
    {
        let _guard = StreamRegistration {
            session: Arc::clone(&session),
            sid,
            frame_started: true,
            committed: false,
            permit: Some(permit),
        };
    }
    assert!(
        !session.is_closed(),
        "no partial frames with the writer queue: session survives"
    );
    assert!(session.streams.lock().unwrap().get(&sid).is_none());

    expect_handshake(&mut server).await;
    let (cmd, got_sid, _) = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut server))
        .await
        .expect("FIN frame")
        .unwrap();
    assert_eq!(cmd, CMD_FIN);
    assert_eq!(got_sid, sid);
}

/// v2: commit moves the capacity slot to the caller; end_stream only
/// unregisters — the semaphore is the count.
#[tokio::test]
async fn test_registration_commit_moves_permit() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 17u32;
    let (tx, _rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let guard = StreamRegistration {
        session: Arc::clone(&session),
        sid,
        frame_started: false,
        committed: false,
        permit: Some(session.try_reserve().unwrap()),
    };
    let permit = guard.commit();
    assert_eq!(session.active_streams(), 1);
    session.end_stream(sid, false);
    assert_eq!(
        session.active_streams(),
        1,
        "end_stream only unregisters; the permit is the count"
    );
    drop(permit);
    assert_eq!(session.active_streams(), 0);
}

/// v2: a draining session takes no new permits, even after slots free.
#[tokio::test]
async fn test_try_reserve_rejects_draining() {
    use crate::session::{ManagedSession as _, SessionState};
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let permit = session.try_reserve().unwrap();
    session.begin_drain();
    assert!(session.try_reserve().is_none(), "draining takes no permits");
    drop(permit);
    assert!(
        session.try_reserve().is_none(),
        "still draining after slots free"
    );
    session.close();
    assert_eq!(session.state(), SessionState::Closed);
}

/// Ad-hoc bulk-transfer check for the writer-queue path (50MB echo).
#[tokio::test]
async fn test_bulk_50mb() {
    let addr = "127.0.0.1:443";
    let (session, mut server) = establish_test_session(addr).await;
    expect_handshake(&mut server).await;
    let mut addr_rx = spawn_echo_server(server);

    let target = vec![0x01, 127, 0, 0, 1, 0x01, 0xbb];
    let permit = session.try_reserve().unwrap();
    let stream = session
        .open_stream_direct(target.clone(), permit)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
        .await
        .unwrap();

    let payload: Vec<u8> = (0..50_000_000u32).map(|i| (i % 251) as u8).collect();
    let t0 = std::time::Instant::now();
    let (mut rd, mut wr) = tokio::io::split(stream);

    let writer = {
        let payload = payload.clone();
        tokio::spawn(async move {
            for chunk in payload.chunks(65536) {
                wr.write_all(chunk).await.unwrap();
            }
        })
    };
    let reader = tokio::spawn(async move {
        let mut received = vec![0u8; 50_000_000];
        rd.read_exact(&mut received).await.unwrap();
        received
    });
    let (w, r) = tokio::join!(writer, reader);
    w.unwrap();
    let received = r.unwrap();
    assert_eq!(received.len(), 50_000_000);
    assert!(
        received
            .iter()
            .enumerate()
            .all(|(i, &b)| b == (i as u32 % 251) as u8)
    );
    eprintln!("50MB echoed in {:?}", t0.elapsed());
}

/// Direct-path stream: multi-frame bulk write echoes back intact, and a
/// server FIN surfaces as read EOF.
#[tokio::test]
async fn test_direct_stream_roundtrip_and_fin() {
    let addr = "127.0.0.1:443";
    let (session, mut server) = establish_test_session(addr).await;
    expect_handshake(&mut server).await;
    let mut addr_rx = spawn_echo_server(server);

    let target = vec![0x01, 127, 0, 0, 1, 0x01, 0xbb];
    let permit = session.try_reserve().unwrap();
    let mut stream = session
        .open_stream_direct(target.clone(), permit)
        .await
        .unwrap();

    let (got_sid, got_addr) = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
        .await
        .expect("address frame")
        .unwrap();
    assert_eq!(got_sid, stream.sid);
    assert_eq!(got_addr, target);

    let payload: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload[..70000]).await.unwrap();
    stream.write_all(&payload[70000..140000]).await.unwrap();
    stream.write_all(&payload[140000..]).await.unwrap();

    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(received, payload);

    stream.shutdown().await.unwrap();
    let mut b = [0u8; 1];
    let early = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut b)).await;
    assert!(early.is_err(), "shutdown must not FIN the stream");
    drop(stream);

    let permit = session.try_reserve().unwrap();
    let mut stream2 = session
        .open_stream_direct(target.clone(), permit)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
        .await
        .expect("second stream address frame")
        .unwrap();
    stream2.write_all(b"ping").await.unwrap();
    let mut four = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(2), stream2.read_exact(&mut four))
        .await
        .expect("second stream echo")
        .unwrap();
    assert_eq!(&four, b"ping");
}

/// Three concurrent streams multiplexed on one session, echoing in
/// parallel (sing-anytls semantics).
#[tokio::test]
async fn test_concurrent_streams_on_one_session() {
    let addr = "127.0.0.1:443";
    let (session, mut server) = establish_test_session(addr).await;
    expect_handshake(&mut server).await;
    let mut addr_rx = spawn_echo_server(server);

    let target = |b: u8| vec![0x01, 127, 0, 0, b, 0x01, 0xbb];
    let (s1, s2, s3) = tokio::join!(
        session.open_stream_direct(target(1), session.try_reserve().unwrap()),
        session.open_stream_direct(target(2), session.try_reserve().unwrap()),
        session.open_stream_direct(target(3), session.try_reserve().unwrap()),
    );
    let (mut s1, mut s2, mut s3) = (s1.unwrap(), s2.unwrap(), s3.unwrap());
    assert_eq!(session.active_streams(), 3);

    let mut addrs = Vec::new();
    for _ in 0..3 {
        let (sid, a) = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
            .await
            .expect("address frame")
            .unwrap();
        addrs.push((sid, a));
    }
    addrs.sort_by_key(|(sid, _)| *sid);
    assert_eq!(addrs[0].1, target(1));
    assert_eq!(addrs[1].1, target(2));
    assert_eq!(addrs[2].1, target(3));

    tokio::try_join!(
        echo(&mut s1, b"one"),
        echo(&mut s2, b"two"),
        echo(&mut s3, b"three")
    )
    .unwrap();
    drop(s1);
    drop(s2);
    drop(s3);
    tokio::time::timeout(Duration::from_secs(2), async {
        while session.active_streams() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("streams drain");
    assert!(!session.is_closed());

    let mut s4 = session
        .open_stream_direct(target(4), session.try_reserve().unwrap())
        .await
        .unwrap();
    let (sid, a) = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
        .await
        .expect("address frame")
        .unwrap();
    assert_eq!(sid, 4);
    assert_eq!(a, target(4));
    echo(&mut s4, b"again").await.unwrap();
}

/// A server-side FIN closes only that stream; sibling streams and the
/// session itself are unaffected.
#[tokio::test]
async fn test_server_fin_closes_only_that_stream() {
    let addr = "127.0.0.1:1443";
    let (session, mut server) = establish_test_session(addr).await;
    expect_handshake(&mut server).await;

    let target = vec![0x01, 127, 0, 0, 1, 0x00, 0x50];
    let mut s1 = session
        .open_stream_direct(target.clone(), session.try_reserve().unwrap())
        .await
        .unwrap();
    let mut s2 = session
        .open_stream_direct(target, session.try_reserve().unwrap())
        .await
        .unwrap();

    for expected_sid in 1..=2u32 {
        let (cmd, sid, _) = read_frame(&mut server).await.unwrap();
        assert_eq!((cmd, sid), (CMD_SYN, expected_sid));
        let (cmd, psid, _) = read_frame(&mut server).await.unwrap();
        assert_eq!((cmd, psid), (CMD_PSH, expected_sid));
    }
    write_frame(&mut server, CMD_FIN, 1, &[]).await.unwrap();

    let mut b = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), s1.read(&mut b))
        .await
        .expect("s1 EOF")
        .unwrap();
    assert_eq!(n, 0);

    s2.write_all(b"still-here").await.unwrap();
    let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, sid), (CMD_PSH, 2));
    assert_eq!(data, b"still-here");
    write_frame(&mut server, CMD_PSH, 2, &data).await.unwrap();
    let mut buf = vec![0u8; 10];
    tokio::time::timeout(Duration::from_secs(2), s2.read_exact(&mut buf))
        .await
        .expect("s2 echo")
        .unwrap();
    assert_eq!(buf, b"still-here");

    assert!(!session.is_closed());
    assert_eq!(session.active_streams(), 1);
}

#[tokio::test]
async fn stream_drop_unregisters_before_returning() {
    let (session, mut server) = establish_test_session("127.0.0.1:1443").await;
    expect_handshake(&mut server).await;
    let sid = 44;
    let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let stream = AnyTlsStream::new(
        Arc::clone(&session),
        sid,
        rx,
        session.try_reserve().unwrap(),
    );

    drop(stream);
    assert!(!session.streams.lock().unwrap().contains_key(&sid));
    let (cmd, got_sid, _) = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut server))
        .await
        .expect("drop FIN")
        .unwrap();
    assert_eq!((cmd, got_sid), (CMD_FIN, sid));
    session.close();
}

#[tokio::test]
async fn remote_fin_drop_does_not_enqueue_a_second_fin() {
    let (session, mut server) = establish_test_session("127.0.0.1:1443").await;
    expect_handshake(&mut server).await;

    let target = vec![0x01, 127, 0, 0, 1, 0x00, 0x50];
    let stream = session
        .open_stream_direct(target, session.try_reserve().unwrap())
        .await
        .unwrap();
    let sid = stream.sid;
    let (cmd, got_sid, _) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, got_sid), (CMD_SYN, sid));
    let (cmd, got_sid, _) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, got_sid), (CMD_PSH, sid));

    session.dispatch_fin(sid).await;
    assert!(session.remote_fin.lock().contains(&sid));
    drop(stream);

    assert!(!session.streams.lock().unwrap().contains_key(&sid));
    assert!(!session.remote_fin.lock().contains(&sid));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), read_frame(&mut server))
            .await
            .is_err(),
        "dropping a remotely closed stream must not send a duplicate FIN"
    );
    session.close();
}
