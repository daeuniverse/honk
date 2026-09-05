use super::*;
#[tokio::test]
async fn inbound_payload_budget_is_held_until_consumed_or_dropped() {
    const BUDGET: usize = 8;
    let budget = InboundPayloadBudget::new(BUDGET);
    let (draining, mut draining_server) =
        establish_test_session_with_budget("draining", Arc::clone(&budget)).await;
    let (sibling, mut sibling_server) =
        establish_test_session_with_budget("sibling", Arc::clone(&budget)).await;
    expect_handshake(&mut draining_server).await;
    expect_handshake(&mut sibling_server).await;

    let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
    draining
        .streams
        .lock()
        .unwrap()
        .insert(101, StreamSink::Tcp(tx));
    let permit = draining.try_reserve().unwrap();
    let mut stream = AnyTlsStream::new(Arc::clone(&draining), 101, rx, permit);
    let (sibling_tx, sibling_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    sibling
        .streams
        .lock()
        .unwrap()
        .insert(202, StreamSink::Tcp(sibling_tx));
    let sibling_permit = sibling.try_reserve().unwrap();
    let mut sibling_stream =
        AnyTlsStream::new(Arc::clone(&sibling), 202, sibling_rx, sibling_permit);

    write_frame(&mut draining_server, CMD_PSH, 101, b"abcd")
        .await
        .unwrap();
    write_frame(&mut draining_server, CMD_PSH, 101, b"efgh")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while budget.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("two queued payloads fill the shared budget");
    crate::session::ManagedSession::begin_drain(draining.as_ref());

    write_frame(&mut sibling_server, CMD_PSH, 202, b"ijkl")
        .await
        .unwrap();
    let mut sibling_bytes = [0; 4];
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            sibling_stream.read_exact(&mut sibling_bytes)
        )
        .await
        .is_err(),
        "a sibling session must backpressure at the pool-wide cap"
    );

    let mut partial = [0; 3];
    stream.read_exact(&mut partial).await.unwrap();
    assert_eq!(&partial, b"abc");
    assert_eq!(budget.available_permits(), 0);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            sibling_stream.read_exact(&mut sibling_bytes)
        )
        .await
        .is_err(),
        "a partial read must retain the whole payload credit"
    );

    let mut final_byte = [0; 1];
    stream.read_exact(&mut final_byte).await.unwrap();
    assert_eq!(&final_byte, b"d");
    tokio::time::timeout(
        Duration::from_secs(1),
        sibling_stream.read_exact(&mut sibling_bytes),
    )
    .await
    .expect("exact final-byte consumption releases credit")
    .expect("sibling stream remains registered");
    assert_eq!(&sibling_bytes, b"ijkl");

    draining.close();
    sibling.close();
    drop(sibling_stream);
    drop(stream);
    assert_eq!(budget.available_permits(), BUDGET);
}

#[tokio::test]
async fn saturated_uot_budget_does_not_block_tcp_delivery() {
    const BUDGET: usize = 8;
    let budget = InboundPayloadBudget::new(BUDGET);
    let (session, mut server) =
        establish_test_session_with_budget("class-isolation", Arc::clone(&budget)).await;
    expect_handshake(&mut server).await;

    let (uot_tx, uot_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(301, StreamSink::Uot(uot_tx));

    let (tcp_tx, tcp_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(302, StreamSink::Tcp(tcp_tx));
    let tcp_permit = session.try_reserve().unwrap();
    let mut tcp_stream = AnyTlsStream::new(Arc::clone(&session), 302, tcp_rx, tcp_permit);
    write_frame(&mut server, CMD_PSH, 301, &[1; BUDGET])
        .await
        .unwrap();
    write_frame(&mut server, CMD_PSH, 301, &[3]).await.unwrap();
    write_frame(&mut server, CMD_PSH, 302, &[2; BUDGET])
        .await
        .unwrap();

    let mut delivered = [0; BUDGET];
    tokio::time::timeout(
        Duration::from_secs(1),
        tcp_stream.read_exact(&mut delivered),
    )
    .await
    .expect("UoT saturation must not block TCP")
    .unwrap();
    assert_eq!(delivered, [2; BUDGET]);
    assert!(!session.streams.lock().unwrap().contains_key(&301));
    drop(uot_rx);
    let (replacement_tx, mut replacement_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(303, StreamSink::Uot(replacement_tx));
    write_frame(&mut server, CMD_PSH, 303, &[4; BUDGET])
        .await
        .unwrap();
    let replacement = tokio::time::timeout(Duration::from_secs(1), replacement_rx.recv())
        .await
        .expect("retired UoT transport retained its payload budget")
        .expect("replacement UoT stream closed");
    match replacement {
        StreamEvent::Data(data) => assert_eq!(data, vec![4; BUDGET]),
        StreamEvent::Fin | StreamEvent::Error(_) => panic!("replacement UoT stream terminated"),
    }
    assert!(!session.is_closed());
}

#[tokio::test]
async fn retired_tcp_frame_does_not_fail_its_session() {
    let budget = InboundPayloadBudget::new(8);
    let (session, mut server) = establish_test_session_with_budget("retired-frame", budget).await;
    expect_handshake(&mut server).await;

    let (retired_tx, _retired_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(351, StreamSink::Tcp(retired_tx));
    let (sibling_tx, sibling_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(352, StreamSink::Tcp(sibling_tx));
    let sibling_permit = session.try_reserve().unwrap();
    let mut sibling_stream =
        AnyTlsStream::new(Arc::clone(&session), 352, sibling_rx, sibling_permit);

    write_frame(&mut server, CMD_PSH, 351, &[1; 4])
        .await
        .unwrap();
    write_frame(&mut server, CMD_PSH, 352, &[2; 4])
        .await
        .unwrap();
    let mut delivered = [0; 4];
    tokio::time::timeout(
        Duration::from_secs(1),
        sibling_stream.read_exact(&mut delivered),
    )
    .await
    .expect("retired TCP frame failed the physical session")
    .unwrap();
    assert_eq!(delivered, [2; 4]);
    assert!(!session.is_closed());
}

#[tokio::test]
async fn terminal_event_releases_later_payload_credit() {
    const BUDGET: usize = 8;
    let budget = InboundPayloadBudget::new(BUDGET);
    let (session, mut server) =
        establish_test_session_with_budget("terminal-credit", Arc::clone(&budget)).await;
    expect_handshake(&mut server).await;

    let (failed_tx, failed_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(401, StreamSink::Tcp(failed_tx.clone()));
    let failed_permit = session.try_reserve().unwrap();
    let mut failed_stream = AnyTlsStream::new(Arc::clone(&session), 401, failed_rx, failed_permit);
    let inbound = session.tcp_inbound.lock().get(&401).unwrap().clone();
    let (credit, _wait) = budget.acquire(&session, 401, BUDGET).await.unwrap();
    let credit = credit.unwrap();
    failed_tx
        .send(StreamEvent::Error(Arc::from("target refused")))
        .await
        .unwrap();
    failed_tx
        .send(StreamEvent::Data(InboundPayload::for_tcp(
            vec![1; BUDGET],
            credit,
            inbound,
        )))
        .await
        .unwrap();

    let mut byte = [0; 1];
    let error = failed_stream.read_exact(&mut byte).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);

    let (sibling_tx, sibling_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(402, StreamSink::Tcp(sibling_tx));
    let sibling_permit = session.try_reserve().unwrap();
    let mut sibling_stream =
        AnyTlsStream::new(Arc::clone(&session), 402, sibling_rx, sibling_permit);
    write_frame(&mut server, CMD_PSH, 402, &[2; BUDGET])
        .await
        .unwrap();
    let mut delivered = [0; BUDGET];
    tokio::time::timeout(
        Duration::from_secs(1),
        sibling_stream.read_exact(&mut delivered),
    )
    .await
    .expect("terminal stream retained sibling payload budget")
    .unwrap();
    assert_eq!(delivered, [2; BUDGET]);
}

#[tokio::test(start_paused = true)]
async fn canceled_budget_waiter_does_not_stall_or_desync_demux() {
    const BUDGET: usize = 8;
    let budget = InboundPayloadBudget::new(BUDGET);
    let (blocker, mut blocker_server) =
        establish_test_session_with_budget("wait-blocker", Arc::clone(&budget)).await;
    let (waiting, mut waiting_server) =
        establish_test_session_with_budget("wait-cancel", Arc::clone(&budget)).await;
    expect_handshake(&mut blocker_server).await;
    expect_handshake(&mut waiting_server).await;

    let (blocker_tx, blocker_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    blocker
        .streams
        .lock()
        .unwrap()
        .insert(601, StreamSink::Tcp(blocker_tx));
    let blocker_permit = blocker.try_reserve().unwrap();
    let mut blocker_stream =
        AnyTlsStream::new(Arc::clone(&blocker), 601, blocker_rx, blocker_permit);
    let (canceled_tx, canceled_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    waiting
        .streams
        .lock()
        .unwrap()
        .insert(602, StreamSink::Tcp(canceled_tx));
    let canceled_permit = waiting.try_reserve().unwrap();
    let canceled_stream =
        AnyTlsStream::new(Arc::clone(&waiting), 602, canceled_rx, canceled_permit);
    let (survivor_tx, survivor_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    waiting
        .streams
        .lock()
        .unwrap()
        .insert(603, StreamSink::Tcp(survivor_tx));
    let survivor_permit = waiting.try_reserve().unwrap();
    let mut survivor_stream =
        AnyTlsStream::new(Arc::clone(&waiting), 603, survivor_rx, survivor_permit);

    write_frame(&mut blocker_server, CMD_PSH, 601, &[1; BUDGET])
        .await
        .unwrap();
    for _ in 0..100 {
        if budget.available_permits() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(budget.available_permits(), 0);
    write_frame(&mut waiting_server, CMD_PSH, 602, &[2; 4])
        .await
        .unwrap();
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    write_frame(&mut waiting_server, CMD_PSH, 603, &[3; 4])
        .await
        .unwrap();
    drop(canceled_stream);
    tokio::time::advance(OVERFLOW_EMERGENCY_WAIT + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;

    let mut blocker_payload = [0; BUDGET];
    blocker_stream
        .read_exact(&mut blocker_payload)
        .await
        .unwrap();
    let mut survivor_payload = [0; 4];
    tokio::time::timeout(
        Duration::from_secs(1),
        survivor_stream.read_exact(&mut survivor_payload),
    )
    .await
    .expect("canceled frame left the session demux stalled or misaligned")
    .unwrap();
    assert_eq!(survivor_payload, [3; 4]);
    assert!(!waiting.is_closed());
}

#[tokio::test(start_paused = true)]
async fn stalled_primary_queue_releases_pool_budget_for_sibling_session() {
    const BUDGET: usize = 8;
    let budget = InboundPayloadBudget::new(BUDGET);
    let (slow, mut slow_server) =
        establish_test_session_with_budget("slow", Arc::clone(&budget)).await;
    let (sibling, mut sibling_server) =
        establish_test_session_with_budget("sibling", Arc::clone(&budget)).await;
    expect_handshake(&mut slow_server).await;
    expect_handshake(&mut sibling_server).await;

    let (slow_tx, slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    slow.streams
        .lock()
        .unwrap()
        .insert(301, StreamSink::Tcp(slow_tx));
    let slow_permit = slow.try_reserve().unwrap();
    let mut slow_stream = AnyTlsStream::new(Arc::clone(&slow), 301, slow_rx, slow_permit);
    let (sibling_tx, sibling_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    sibling
        .streams
        .lock()
        .unwrap()
        .insert(302, StreamSink::Tcp(sibling_tx));
    let sibling_permit = sibling.try_reserve().unwrap();
    let mut sibling_stream =
        AnyTlsStream::new(Arc::clone(&sibling), 302, sibling_rx, sibling_permit);

    write_frame(&mut slow_server, CMD_PSH, 301, &[1; BUDGET])
        .await
        .unwrap();
    for _ in 0..100 {
        if budget.available_permits() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(budget.available_permits(), 0);
    write_frame(&mut sibling_server, CMD_PSH, 302, &[2; 4])
        .await
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(OVERFLOW_STALL_GRACE - OVERFLOW_EMERGENCY_WAIT).await;
    let mut progress = [0; 1];
    slow_stream.read_exact(&mut progress).await.unwrap();
    assert_eq!(progress, [1]);
    tokio::time::advance(OVERFLOW_EMERGENCY_WAIT + OVERFLOW_EMERGENCY_WAIT).await;
    tokio::task::yield_now().await;
    assert!(slow.streams.lock().unwrap().contains_key(&301));
    assert_eq!(budget.available_permits(), 0);
    tokio::time::advance(OVERFLOW_STALL_GRACE).await;

    let mut delivered = [0; 4];
    sibling_stream.read_exact(&mut delivered).await.unwrap();
    assert_eq!(delivered, [2; 4]);
    let mut byte = [0; 1];
    let error = slow_stream.read_exact(&mut byte).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(!slow.is_closed());
    assert!(!sibling.is_closed());
    assert_eq!(budget.available_permits(), BUDGET);
}

#[tokio::test(start_paused = true)]
async fn closed_session_budget_reap_reports_reset() {
    const BUDGET: usize = 8;
    let budget = InboundPayloadBudget::new(BUDGET);
    let (slow, mut slow_server) =
        establish_test_session_with_budget("closed-slow", Arc::clone(&budget)).await;
    let (sibling, mut sibling_server) =
        establish_test_session_with_budget("closed-sibling", Arc::clone(&budget)).await;
    expect_handshake(&mut slow_server).await;
    expect_handshake(&mut sibling_server).await;

    let (slow_tx, slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    slow.streams
        .lock()
        .unwrap()
        .insert(501, StreamSink::Tcp(slow_tx));
    let slow_permit = slow.try_reserve().unwrap();
    let mut slow_stream = AnyTlsStream::new(Arc::clone(&slow), 501, slow_rx, slow_permit);
    let (sibling_tx, sibling_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    sibling
        .streams
        .lock()
        .unwrap()
        .insert(502, StreamSink::Tcp(sibling_tx));
    let sibling_permit = sibling.try_reserve().unwrap();
    let mut sibling_stream =
        AnyTlsStream::new(Arc::clone(&sibling), 502, sibling_rx, sibling_permit);

    write_frame(&mut slow_server, CMD_PSH, 501, &[1; BUDGET])
        .await
        .unwrap();
    for _ in 0..100 {
        if budget.available_permits() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(budget.available_permits(), 0);
    slow.close();
    write_frame(&mut sibling_server, CMD_PSH, 502, &[2; 4])
        .await
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(OVERFLOW_STALL_GRACE + OVERFLOW_EMERGENCY_WAIT + OVERFLOW_EMERGENCY_WAIT)
        .await;

    let mut delivered = [0; 4];
    sibling_stream.read_exact(&mut delivered).await.unwrap();
    assert_eq!(delivered, [2; 4]);
    let mut byte = [0; 1];
    let error = slow_stream.read_exact(&mut byte).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(!sibling.is_closed());
}
/// A locally blocked frame stays observable across permit acquisition and
/// body dispatch. Once admitted without that wait, a partial body is still
/// peer silence and lets the SYNACK watchdog retire the physical session.
#[tokio::test(start_paused = true)]
async fn budget_wait_to_body_handoff_is_atomic_for_synack_liveness() {
    const BUDGET: usize = 8;
    let budget = InboundPayloadBudget::new(BUDGET);
    let (blocker, mut blocker_server) =
        establish_test_session_with_budget("synack-blocker", Arc::clone(&budget)).await;
    let (session, mut server) =
        establish_test_session_with_budget("synack-active", Arc::clone(&budget)).await;
    expect_handshake(&mut blocker_server).await;
    expect_handshake(&mut server).await;
    write_frame(&mut server, CMD_SERVER_SETTINGS, 0, b"v=2\n")
        .await
        .unwrap();
    tokio::task::yield_now().await;

    let (blocker_tx, blocker_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    blocker
        .streams
        .lock()
        .unwrap()
        .insert(7, StreamSink::Tcp(blocker_tx));
    let blocker_permit = blocker.try_reserve().unwrap();
    let blocker_stream = AnyTlsStream::new(Arc::clone(&blocker), 7, blocker_rx, blocker_permit);
    write_frame(&mut blocker_server, CMD_PSH, 7, &[1; BUDGET])
        .await
        .unwrap();
    for _ in 0..100 {
        if budget.available_permits() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(budget.available_permits(), 0);

    let (active_tx, active_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(9, StreamSink::Tcp(active_tx));
    let active_permit = session.try_reserve().unwrap();
    let mut active_stream = AnyTlsStream::new(Arc::clone(&session), 9, active_rx, active_permit);
    session.register_synack(9);
    let marker = session.rx_frame_seq.load(Ordering::Relaxed);
    session.start_synack_deadline(9, marker);
    let mut delayed = Vec::new();
    write_frame(&mut delayed, CMD_PSH, 9, b"xy").await.unwrap();
    server
        .write_all(&delayed[..FRAME_HEADER_LEN + 1])
        .await
        .unwrap();
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    tokio::time::advance(SYNACK_TIMEOUT - Duration::from_millis(1)).await;
    drop(blocker_stream);
    for _ in 0..100 {
        if budget.available_permits() == BUDGET - 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(budget.available_permits(), BUDGET - 2);
    assert_eq!(session.inbound_budget_epoch.load(Ordering::SeqCst) & 1, 1);

    tokio::time::advance(Duration::from_millis(2)).await;
    tokio::task::yield_now().await;
    assert!(
        !session.is_closed(),
        "permit acquisition must not create a false-silence window"
    );
    server
        .write_all(&delayed[FRAME_HEADER_LEN + 1..])
        .await
        .unwrap();
    for _ in 0..100 {
        if session.rx_frame_seq.load(Ordering::Relaxed) > marker {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(session.rx_frame_seq.load(Ordering::Relaxed) > marker);
    let error = active_stream.read(&mut [0; 1]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert_eq!(budget.available_permits(), BUDGET);

    let (stalled_tx, stalled_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(10, StreamSink::Tcp(stalled_tx));
    let stalled_permit = session.try_reserve().unwrap();
    let _stalled_stream = AnyTlsStream::new(Arc::clone(&session), 10, stalled_rx, stalled_permit);
    session.register_synack(10);
    let marker = session.rx_frame_seq.load(Ordering::Relaxed);
    session.start_synack_deadline(10, marker);
    let mut partial = Vec::new();
    write_frame(&mut partial, CMD_PSH, 10, b"yz").await.unwrap();
    server
        .write_all(&partial[..FRAME_HEADER_LEN + 1])
        .await
        .unwrap();
    tokio::task::yield_now().await;

    tokio::time::advance(SYNACK_TIMEOUT + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert!(
        session.is_closed(),
        "a peer-stalled frame body must not count as completed activity"
    );
}
