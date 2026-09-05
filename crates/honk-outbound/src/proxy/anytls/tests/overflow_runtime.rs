use super::*;
#[tokio::test]
async fn overflow_accounting_clears_on_lifecycle_exits() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;

    let (end_tx, _end_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(31, StreamSink::Tcp(end_tx));
    session
        .overflow
        .lock()
        .push_back(31, StreamEvent::Data(InboundPayload::for_test(vec![1; 17])));
    session.end_stream(31, false);
    assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());

    let (drop_tx, _drop_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(32, StreamSink::Tcp(drop_tx));
    let registration = StreamRegistration {
        session: Arc::clone(&session),
        sid: 32,
        frame_started: false,
        committed: false,
        permit: Some(session.try_reserve().unwrap()),
    };
    session
        .overflow
        .lock()
        .push_back(32, StreamEvent::Data(InboundPayload::for_test(vec![2; 19])));
    drop(registration);
    assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());

    let (close_tx, _close_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(34, StreamSink::Tcp(close_tx));
    session
        .overflow
        .lock()
        .push_back(34, StreamEvent::Data(InboundPayload::for_test(vec![5; 29])));
    session.close();
    assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
}

/// Below the hard caps parking never kills, however stale the stream:
/// only the stall watchdog reaps it, strictly after a full grace
/// without flush progress.
#[tokio::test(start_paused = true)]
async fn stream_byte_cap_reaps_via_watchdog_only_after_stall_grace() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 41;
    let (tx, _rx) = mpsc::channel(STREAM_QUEUE_CAP);
    for _ in 0..STREAM_QUEUE_CAP {
        tx.try_send(StreamEvent::Data(InboundPayload::for_test(vec![0])))
            .unwrap();
    }
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    session.overflow.lock().push_back(
        sid,
        StreamEvent::Data(InboundPayload::for_test(vec![0; STREAM_OVERFLOW_BYTES_CAP])),
    );

    session
        .park_overflow(sid, StreamEvent::Data(InboundPayload::for_test(vec![1])))
        .await;
    tokio::time::advance(OVERFLOW_STALL_GRACE - OVERFLOW_WATCHDOG_TICK).await;
    tokio::task::yield_now().await;
    assert!(session.streams.lock().unwrap().contains_key(&sid));
    assert!(!session.killed_streams.lock().unwrap().contains(&sid));
    assert_eq!(
        session.overflow.lock().stream_usage(sid).bytes,
        STREAM_OVERFLOW_BYTES_CAP + 1
    );

    tokio::time::advance(OVERFLOW_WATCHDOG_TICK * 2).await;
    tokio::task::yield_now().await;
    assert!(!session.streams.lock().unwrap().contains_key(&sid));
    assert!(session.killed_streams.lock().unwrap().contains(&sid));
    assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
    assert!(!session.is_closed());
    session.close();
}

/// Fast-peer burst regression: a peer can park past the session byte
/// soft cap in the milliseconds before the reader is first scheduled —
/// parking never waits and never kills inside the grace, the late
/// reader drains, and every byte arrives in order.
#[tokio::test]
async fn overflow_burst_within_grace_survives_and_delivers() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 42;
    let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let permit = session.try_reserve().unwrap();
    let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);

    const FRAME: usize = 32 * 1024;

    let frames = STREAM_QUEUE_CAP + SESSION_OVERFLOW_BYTES_CAP / FRAME + 8;
    let dispatcher = tokio::spawn({
        let session = Arc::clone(&session);
        async move {
            for i in 0..frames {
                session
                    .dispatch_data(sid, vec![(i % 251) as u8; FRAME])
                    .await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(session.streams.lock().unwrap().contains_key(&sid));
    assert!(!session.killed_streams.lock().unwrap().contains(&sid));

    let mut got = vec![0u8; frames * FRAME];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got))
        .await
        .expect("burst drains")
        .unwrap();
    dispatcher.await.unwrap();
    for (i, frame) in got.as_chunks::<FRAME>().0.iter().enumerate() {
        assert!(
            frame.iter().all(|&b| b == (i % 251) as u8),
            "frame {i} corrupted"
        );
    }
    assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
    assert!(session.streams.lock().unwrap().contains_key(&sid));
    session.close();
}

/// At the hard frame cap with stalled streams past the grace, parking
/// reaps on the spot (never waits): the most-stalled parked stream —
/// 51, oldest progress (ties to the lowest sid) — dies and the new
/// frame parks on the freed space, then flushes into its empty
/// channel.
#[tokio::test(start_paused = true)]
async fn session_hard_cap_kills_stream_that_outwaits_the_stall_grace() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let (slow_tx, _slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    let (other_tx, _other_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    let (waiting_tx, _waiting_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    {
        let mut streams = session.streams.lock().unwrap();
        streams.insert(51, StreamSink::Tcp(slow_tx));
        streams.insert(52, StreamSink::Tcp(other_tx));
        streams.insert(53, StreamSink::Tcp(waiting_tx));
    }
    {
        let mut overflow = session.overflow.lock();
        for _ in 0..400 {
            overflow.push_back(51, StreamEvent::Data(InboundPayload::for_test(vec![1; 8])));
        }
        for _ in 0..368 {
            overflow.push_back(52, StreamEvent::Data(InboundPayload::for_test(vec![2; 8])));
        }
        assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_HARD_CAP);
    }
    tokio::time::advance(OVERFLOW_STALL_GRACE).await;

    session
        .park_overflow(
            53,
            StreamEvent::Data(InboundPayload::for_test(vec![9, 8, 7])),
        )
        .await;

    assert!(session.killed_streams.lock().unwrap().contains(&51));
    assert!(!session.streams.lock().unwrap().contains_key(&51));
    assert!(session.streams.lock().unwrap().contains_key(&52));
    assert!(session.streams.lock().unwrap().contains_key(&53));
    assert!(!session.overflow.lock().has(51));
    assert!(!session.overflow.lock().has(53));
    assert_eq!(
        session.overflow.lock().usage(),
        OverflowUsage {
            frames: 368,
            bytes: 368 * 8,
        }
    );

    session.park_overflow(52, StreamEvent::Fin).await;
    assert!(session.streams.lock().unwrap().contains_key(&52));
    assert_eq!(
        session.overflow.lock().usage().frames,
        368 - STREAM_QUEUE_CAP
    );
    assert!(!session.is_closed());
    session.close();
}

/// Hard cap with every stalled stream inside the grace: the demux
/// waits bounded rounds instead of killing; reader progress on the
/// stalled stream frees space, wakes the waiter, and the frame parks
/// — nobody dies.
#[tokio::test]
async fn session_hard_cap_waits_for_progress_and_spares_everyone() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let slow_sid = 64;
    let waiting_sid = 65;
    let (slow_tx, _slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    let (waiting_tx, mut waiting_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    for _ in 0..STREAM_QUEUE_CAP {
        waiting_tx
            .try_send(StreamEvent::Data(InboundPayload::for_test(vec![7])))
            .unwrap();
    }
    {
        let mut streams = session.streams.lock().unwrap();
        streams.insert(slow_sid, StreamSink::Tcp(slow_tx));
        streams.insert(waiting_sid, StreamSink::Tcp(waiting_tx));
    }
    {
        let mut overflow = session.overflow.lock();
        for _ in 0..SESSION_OVERFLOW_HARD_CAP {
            overflow.push_back(
                slow_sid,
                StreamEvent::Data(InboundPayload::for_test(vec![1; 8])),
            );
        }
    }

    let parker = tokio::spawn({
        let session = Arc::clone(&session);
        async move {
            session
                .park_overflow(
                    waiting_sid,
                    StreamEvent::Data(InboundPayload::for_test(vec![9, 8, 7])),
                )
                .await;
        }
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    assert!(
        !session.overflow.lock().has(waiting_sid),
        "the frame waits at the hard cap inside the grace"
    );
    assert!(!parker.is_finished());
    assert!(session.killed_streams.lock().unwrap().is_empty());

    session.flush_overflow(slow_sid);
    tokio::time::timeout(Duration::from_secs(2), parker)
        .await
        .expect("parker wakes after the flush")
        .unwrap();
    assert_eq!(session.overflow.lock().stream_usage(waiting_sid).frames, 1);
    assert!(session.killed_streams.lock().unwrap().is_empty());

    for _ in 0..STREAM_QUEUE_CAP {
        match waiting_rx.recv().await.unwrap() {
            StreamEvent::Data(data) => assert_eq!(data, vec![7]),
            StreamEvent::Fin | StreamEvent::Error(_) => {
                panic!("waiting stream was terminated")
            }
        }
        session.flush_overflow(waiting_sid);
    }
    match waiting_rx.recv().await.unwrap() {
        StreamEvent::Data(data) => assert_eq!(data, vec![9, 8, 7]),
        StreamEvent::Fin | StreamEvent::Error(_) => panic!("waiting stream was terminated"),
    }
    assert!(!session.is_closed());
    session.close();
}

/// Hard cap with zero reader progress anywhere: the bounded wait
/// rounds accrue until the most-stalled stream crosses the full
/// grace — only then is it reaped (paused time walks the rounds).
#[tokio::test(start_paused = true)]
async fn session_hard_cap_kills_only_after_full_grace_of_waits() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let (slow_tx, _slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    let (waiting_tx, _waiting_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    {
        let mut streams = session.streams.lock().unwrap();
        streams.insert(71, StreamSink::Tcp(slow_tx));
        streams.insert(72, StreamSink::Tcp(waiting_tx));
    }
    {
        let mut overflow = session.overflow.lock();
        for _ in 0..SESSION_OVERFLOW_HARD_CAP {
            overflow.push_back(71, StreamEvent::Data(InboundPayload::for_test(vec![1; 8])));
        }
    }

    session
        .park_overflow(72, StreamEvent::Data(InboundPayload::for_test(vec![9])))
        .await;

    assert!(session.killed_streams.lock().unwrap().contains(&71));
    assert!(!session.streams.lock().unwrap().contains_key(&71));
    assert!(!session.overflow.lock().has(71));
    assert!(!session.overflow.lock().has(72));
    assert!(!session.is_closed());
    session.close();
}

/// At the session soft cap parking is immediate — the demux never
/// waits: a sibling with no parked frames dispatches normally, and
/// reader progress flushes the parked frame into the freed slot.
#[tokio::test]
async fn session_soft_cap_parks_immediately_and_flushes_on_progress() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let slow_sid = 61;
    let fast_sid = 62;
    let waiting_sid = 63;
    let (slow_tx, _slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    let (fast_tx, fast_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    let (waiting_tx, mut waiting_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    for _ in 0..STREAM_QUEUE_CAP {
        waiting_tx
            .try_send(StreamEvent::Data(InboundPayload::for_test(vec![7])))
            .unwrap();
    }
    {
        let mut streams = session.streams.lock().unwrap();
        streams.insert(slow_sid, StreamSink::Tcp(slow_tx));
        streams.insert(fast_sid, StreamSink::Tcp(fast_tx));
        streams.insert(waiting_sid, StreamSink::Tcp(waiting_tx));
    }
    let fast_permit = session.try_reserve().unwrap();
    let mut fast_stream = AnyTlsStream::new(Arc::clone(&session), fast_sid, fast_rx, fast_permit);
    {
        let mut overflow = session.overflow.lock();
        for _ in 0..SESSION_OVERFLOW_CAP {
            overflow.push_back(
                slow_sid,
                StreamEvent::Data(InboundPayload::for_test(vec![1; 8])),
            );
        }
    }

    session
        .park_overflow(
            waiting_sid,
            StreamEvent::Data(InboundPayload::for_test(vec![9, 8, 7])),
        )
        .await;
    assert!(
        !session
            .killed_streams
            .lock()
            .unwrap()
            .contains(&waiting_sid)
    );
    assert_eq!(session.overflow.lock().stream_usage(waiting_sid).frames, 1);

    session.dispatch_data(fast_sid, vec![7]).await;
    let mut fast_byte = [0; 1];
    fast_stream.read_exact(&mut fast_byte).await.unwrap();
    assert_eq!(fast_byte, [7]);

    match waiting_rx.recv().await.unwrap() {
        StreamEvent::Data(data) => assert_eq!(data, vec![7]),
        StreamEvent::Fin | StreamEvent::Error(_) => panic!("waiting stream was terminated"),
    }
    session.flush_overflow(waiting_sid);
    for _ in 1..STREAM_QUEUE_CAP {
        match waiting_rx.recv().await.unwrap() {
            StreamEvent::Data(data) => assert_eq!(data, vec![7]),
            StreamEvent::Fin | StreamEvent::Error(_) => {
                panic!("waiting stream was terminated")
            }
        }
    }
    match waiting_rx.recv().await.unwrap() {
        StreamEvent::Data(data) => assert_eq!(data, vec![9, 8, 7]),
        StreamEvent::Fin | StreamEvent::Error(_) => panic!("waiting stream was terminated"),
    }
    assert_eq!(session.overflow.lock().usage().frames, SESSION_OVERFLOW_CAP);
    assert!(!session.is_closed());
    session.close();
}

#[tokio::test]
async fn overflow_transition_self_kicks_an_emptied_queue() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 70;
    let (tx, mut rx) = mpsc::channel(1);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));

    session
        .park_overflow(
            sid,
            StreamEvent::Data(InboundPayload::for_test(vec![7, 8, 9])),
        )
        .await;

    assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
    match rx.recv().await.unwrap() {
        StreamEvent::Data(data) => assert_eq!(data, vec![7, 8, 9]),
        _ => panic!("overflow transition delivered a terminal event"),
    }
    session.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_overflow_flush_preserves_stream_order() {
    const EVENTS: usize = 256;
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 70;
    let (tx, mut rx) = mpsc::channel(1);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    for index in 0..EVENTS {
        session.overflow.lock().push_back(
            sid,
            StreamEvent::Data(InboundPayload::for_test(
                u16::try_from(index).unwrap().to_be_bytes().to_vec(),
            )),
        );
    }

    let done = Arc::new(AtomicBool::new(false));
    let kickers: Vec<_> = (0..8)
        .map(|_| {
            let session = Arc::clone(&session);
            let done = Arc::clone(&done);
            tokio::spawn(async move {
                while !done.load(Ordering::Acquire) {
                    session.flush_overflow(sid);
                    tokio::task::yield_now().await;
                }
            })
        })
        .collect();

    let mut observed = Vec::with_capacity(EVENTS);
    while observed.len() != EVENTS {
        session.flush_overflow(sid);
        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("ordered overflow event timed out")
            .expect("ordered overflow channel closed");
        match event {
            StreamEvent::Data(data) => {
                observed.push(u16::from_be_bytes(data[..].try_into().unwrap()) as usize);
            }
            StreamEvent::Fin | StreamEvent::Error(_) => {
                panic!("unexpected terminal event")
            }
        }
    }
    done.store(true, Ordering::Release);
    for kicker in kickers {
        kicker.await.unwrap();
    }

    assert_eq!(observed, (0..EVENTS).collect::<Vec<_>>());
    let overflow = session.overflow.lock();
    assert_eq!(overflow.usage(), OverflowUsage::default());
    assert!(!overflow.flushing.contains(&sid));
    assert!(!overflow.flush_requested.contains(&sid));
    drop(overflow);
    session.close();
}

#[tokio::test]
async fn overflow_preserves_data_before_fin() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 81;
    let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let permit = session.try_reserve().unwrap();
    let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);
    for _ in 0..STREAM_QUEUE_CAP {
        session.dispatch_data(sid, vec![1]).await;
    }
    session.dispatch_data(sid, vec![9]).await;
    session.dispatch_fin(sid).await;

    let mut payload = vec![0; STREAM_QUEUE_CAP + 1];
    stream.read_exact(&mut payload).await.unwrap();
    assert!(payload[..STREAM_QUEUE_CAP].iter().all(|byte| *byte == 1));
    assert_eq!(payload[STREAM_QUEUE_CAP], 9);
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
}

/// A FIN delivered through a sender cloned before watchdog retirement must
/// preserve the stream reset instead of turning the retirement into EOF.
#[tokio::test]
async fn stale_remote_fin_after_overflow_kill_is_reset() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 82;
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(StreamEvent::Data(InboundPayload::for_test(vec![1])))
        .unwrap();
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let permit = session.try_reserve().unwrap();
    let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);

    let stale_tx = match session.streams.lock().unwrap().get(&sid).cloned() {
        Some(StreamSink::Tcp(tx)) => tx,
        _ => panic!("registered TCP stream"),
    };
    session.dispatch_data(sid, vec![2]).await;
    session.dispatch_fin(sid).await;
    assert!(session.remote_fin.lock().contains(&sid));

    let victim = session
        .overflow
        .lock()
        .take_victim(sid, OverflowLimit::StallGrace);
    session.kill_overflow_victim(victim);
    assert!(session.killed_streams.lock().unwrap().contains(&sid));

    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, [1]);
    stale_tx.try_send(StreamEvent::Fin).unwrap();

    let error = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
        .await
        .expect("stale FIN read")
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(!session.killed_streams.lock().unwrap().contains(&sid));
    session.close();
}

#[tokio::test]
async fn killed_stream_tombstone_follows_stream_owner() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;

    let sid = 83;
    let (tx, rx) = mpsc::channel(1);
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
    session
        .overflow
        .lock()
        .push_back(sid, StreamEvent::Data(InboundPayload::for_test(vec![1])));
    let victim = session
        .overflow
        .lock()
        .take_victim(sid, OverflowLimit::StallGrace);
    session.kill_overflow_victim(victim);
    assert!(session.killed_streams.lock().unwrap().contains(&sid));
    drop(stream);
    assert!(!session.killed_streams.lock().unwrap().contains(&sid));

    let sid = 84;
    let (tx, rx) = mpsc::channel(1);
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
    session
        .overflow
        .lock()
        .push_back(sid, StreamEvent::Data(InboundPayload::for_test(vec![1])));
    let victim = session
        .overflow
        .lock()
        .take_victim(sid, OverflowLimit::StallGrace);
    drop(stream);
    session.kill_overflow_victim(victim);
    assert!(!session.killed_streams.lock().unwrap().contains(&sid));
    session.close();
}

#[tokio::test]
async fn session_close_preserves_killed_reset_until_owner_reads() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 85;
    let (tx, rx) = mpsc::channel(1);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let mut stream = AnyTlsStream::new(
        Arc::clone(&session),
        sid,
        rx,
        session.try_reserve().unwrap(),
    );
    session
        .overflow
        .lock()
        .push_back(sid, StreamEvent::Data(InboundPayload::for_test(vec![1])));
    let victim = session
        .overflow
        .lock()
        .take_victim(sid, OverflowLimit::StallGrace);
    session.kill_overflow_victim(victim);
    session.close();
    assert!(session.killed_streams.lock().unwrap().contains(&sid));

    let error = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut [0; 1]))
        .await
        .expect("killed stream read")
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(!session.killed_streams.lock().unwrap().contains(&sid));
}

/// 3B-2: a stalled stream is first parked in the session overflow
/// (non-blocking); parking past the session soft cap still does not
/// kill, but past the stall grace the watchdog reaps just that
/// stream — queued data still drains, then the reader sees a reset
/// (never a clean EOF), and the session survives.
#[tokio::test(start_paused = true)]
async fn test_hol_slow_consumer_reset_after_queue_drains() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 21u32;
    let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    let permit = session.try_reserve().unwrap();
    let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);
    let sink = session.streams.lock().unwrap().get(&sid).cloned().unwrap();
    for _ in 0..STREAM_QUEUE_CAP {
        sink.send_data(vec![1u8; 8]).await;
    }
    drop(sink); // the test's clone must not keep the channel alive

    session.dispatch_data(sid, vec![2u8; 8]).await;
    assert!(
        session.streams.lock().unwrap().get(&sid).is_some(),
        "overflow parking must not kill the stream"
    );

    for _ in 0..SESSION_OVERFLOW_CAP {
        session.dispatch_data(sid, vec![2u8; 8]).await;
    }
    assert!(session.streams.lock().unwrap().get(&sid).is_some());

    tokio::time::advance(OVERFLOW_STALL_GRACE + OVERFLOW_WATCHDOG_TICK).await;
    tokio::task::yield_now().await;
    assert!(session.streams.lock().unwrap().get(&sid).is_none());
    let mut buf = vec![0u8; STREAM_QUEUE_CAP * 8];
    stream.read_exact(&mut buf).await.unwrap();
    assert!(buf.iter().all(|&b| b == 1), "queued data drains first");
    let err = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut [0u8; 1]))
        .await
        .expect("read settles")
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(
        !session.is_closed(),
        "a killed stream must not kill the session"
    );
}

/// 3B-3: a stalled stream never blocks the demux — a healthy stream on
/// the same session keeps receiving while the stalled one parks in
/// the session overflow, and the parked frames flush (in order) once
/// the stalled reader progresses.
#[tokio::test]
async fn test_hol_stall_does_not_block_other_streams() {
    use tokio::io::AsyncReadExt as _;

    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let (slow_tx, slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    let (fast_tx, fast_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(1, StreamSink::Tcp(slow_tx));
    session
        .streams
        .lock()
        .unwrap()
        .insert(2, StreamSink::Tcp(fast_tx));
    let fast_permit = session.try_reserve().unwrap();
    let mut fast_stream = AnyTlsStream::new(Arc::clone(&session), 2, fast_rx, fast_permit);
    let permit = session.try_reserve().unwrap();
    let mut slow_stream = AnyTlsStream::new(Arc::clone(&session), 1, slow_rx, permit);

    let parked = 64usize;
    for i in 0..STREAM_QUEUE_CAP + parked {
        session.dispatch_data(1, vec![(i % 251) as u8; 4]).await;
    }

    for i in 0..10u8 {
        session.dispatch_data(2, vec![i; 4]).await;
        let mut delivered = [0; 4];
        tokio::time::timeout(
            Duration::from_secs(2),
            fast_stream.read_exact(&mut delivered),
        )
        .await
        .expect("stream 2 must not be blocked by stream 1")
        .unwrap();
        assert_eq!(delivered, [i; 4]);
    }

    let total = STREAM_QUEUE_CAP + parked;
    let mut got = vec![0u8; total * 4];
    tokio::time::timeout(Duration::from_secs(5), slow_stream.read_exact(&mut got))
        .await
        .expect("slow stream must drain")
        .unwrap();
    for (i, b) in got.as_chunks::<4>().0.iter().enumerate() {
        assert_eq!(b, &[(i % 251) as u8; 4], "frame {i} out of order");
    }
}

/// Regression: tripping the session overflow cap must never stall the
/// demux. Driven through the real receive loop over the duplex: a slow
/// stream parked to the session soft cap, one more frame for it, then
/// a frame for a fast sibling — the sibling must receive within a
/// bounded delay (the old demux waited ~500ms per cap trip here).
#[tokio::test]
async fn demux_overflow_cap_never_blocks_sibling_streams() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    let slow_sid = 91;
    let fast_sid = 92;
    let (slow_tx, slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    let (fast_tx, fast_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    {
        let mut streams = session.streams.lock().unwrap();
        streams.insert(slow_sid, StreamSink::Tcp(slow_tx));
        streams.insert(fast_sid, StreamSink::Tcp(fast_tx));
    }
    let slow_permit = session.try_reserve().unwrap();
    let _slow_stream = AnyTlsStream::new(Arc::clone(&session), slow_sid, slow_rx, slow_permit);
    let fast_permit = session.try_reserve().unwrap();
    let mut fast_stream = AnyTlsStream::new(Arc::clone(&session), fast_sid, fast_rx, fast_permit);

    for _ in 0..STREAM_QUEUE_CAP + SESSION_OVERFLOW_CAP {
        write_frame(&mut server, CMD_PSH, slow_sid, &[1u8; 8])
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while session.overflow.lock().usage().frames != SESSION_OVERFLOW_CAP {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("demux parks up to the session soft cap");

    write_frame(&mut server, CMD_PSH, slow_sid, &[2u8; 8])
        .await
        .unwrap();
    write_frame(&mut server, CMD_PSH, fast_sid, &[7u8; 4])
        .await
        .unwrap();
    let mut data = [0; 4];
    tokio::time::timeout(
        Duration::from_millis(100),
        fast_stream.read_exact(&mut data),
    )
    .await
    .expect("fast sibling must not wait behind the overflow cap")
    .expect("fast sibling remains open");
    assert_eq!(data, [7u8; 4]);
    assert!(session.streams.lock().unwrap().contains_key(&slow_sid));
    assert!(!session.killed_streams.lock().unwrap().contains(&slow_sid));
    session.close();
}

/// Flush progress pushes the reap deadline out: a stream that keeps
/// draining is spared; once progress stops, the full grace applies.
#[tokio::test(start_paused = true)]
async fn overflow_watchdog_spares_streams_with_flush_progress() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 44;
    let (tx, mut rx) = mpsc::channel(STREAM_QUEUE_CAP);
    for _ in 0..STREAM_QUEUE_CAP {
        tx.try_send(StreamEvent::Data(InboundPayload::for_test(vec![0])))
            .unwrap();
    }
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    session
        .park_overflow(sid, StreamEvent::Data(InboundPayload::for_test(vec![1; 8])))
        .await;
    session
        .park_overflow(sid, StreamEvent::Data(InboundPayload::for_test(vec![2; 8])))
        .await;

    tokio::time::advance(Duration::from_secs(2)).await;
    match rx.recv().await {
        Some(StreamEvent::Data(_)) => {}
        _ => panic!("queued data must drain"),
    }
    session.flush_overflow(sid);
    assert_eq!(session.overflow.lock().stream_usage(sid).frames, 1);

    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert!(session.streams.lock().unwrap().contains_key(&sid));
    assert!(!session.killed_streams.lock().unwrap().contains(&sid));

    tokio::time::advance(OVERFLOW_STALL_GRACE + OVERFLOW_WATCHDOG_TICK).await;
    tokio::task::yield_now().await;
    assert!(!session.streams.lock().unwrap().contains_key(&sid));
    assert!(session.killed_streams.lock().unwrap().contains(&sid));
    session.close();
}

/// The watchdog retires once the overflow drains; the next park
/// respawns it.
#[tokio::test(start_paused = true)]
async fn overflow_watchdog_retires_when_the_overflow_drains() {
    let (session, _server) = establish_test_session("127.0.0.1:443").await;
    let sid = 45;
    let (tx, mut rx) = mpsc::channel(STREAM_QUEUE_CAP);
    for _ in 0..STREAM_QUEUE_CAP {
        tx.try_send(StreamEvent::Data(InboundPayload::for_test(vec![0])))
            .unwrap();
    }
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    session
        .park_overflow(sid, StreamEvent::Data(InboundPayload::for_test(vec![1; 8])))
        .await;
    assert!(session.watchdog.lock().unwrap().is_some());

    while rx.try_recv().is_ok() {}
    session.flush_overflow(sid);
    while rx.try_recv().is_ok() {}
    assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
    tokio::time::advance(OVERFLOW_WATCHDOG_TICK * 2).await;
    tokio::task::yield_now().await;
    assert!(session.watchdog.lock().unwrap().is_none());
    session.close();
}

/// UoT saturation retires only the affected sid and never parks bytes in
/// the session-wide TCP overflow.
#[tokio::test]
async fn uot_sink_saturation_retires_only_stream() {
    let (session, mut server) = establish_test_session("127.0.0.1:443").await;
    expect_handshake(&mut server).await;
    let (tx, _rx) = mpsc::channel(1);
    tx.try_send(StreamEvent::Data(InboundPayload::for_test(vec![0])))
        .unwrap();
    session
        .streams
        .lock()
        .unwrap()
        .insert(77, StreamSink::Uot(tx));
    session.dispatch_data(77, vec![1; 16]).await;
    assert!(!session.streams.lock().unwrap().contains_key(&77));
    assert!(!session.is_closed());
    assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
    assert!(session.watchdog.lock().unwrap().is_none());
    let (cmd, sid, _) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, sid), (CMD_FIN, 77));
    session.close();
}
