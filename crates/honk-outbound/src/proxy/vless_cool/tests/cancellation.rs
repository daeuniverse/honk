use super::*;

#[derive(Debug, Default)]
struct FlushGate {
    open: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl FlushGate {
    fn open(&self) {
        self.open.store(true, Ordering::Release);
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    fn close(&self) {
        self.open.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
struct GatedFlushIo<S> {
    inner: S,
    gate: Arc<FlushGate>,
}

impl<S: AsyncRead + Unpin> AsyncRead for GatedFlushIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GatedFlushIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.gate.open.load(Ordering::Acquire) {
            Pin::new(&mut self.inner).poll_flush(cx)
        } else {
            *self.gate.waker.lock() = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_carrier_writer_times_out() {
    let (client, _wire) = tokio::io::duplex(1 << 16);
    let gate = Arc::new(FlushGate::default());
    let (tx, rx) = mpsc::channel(1);
    let writer = CarrierWriter { tx };
    let driver = tokio::spawn(run_writer(
        GatedFlushIo {
            inner: client,
            gate,
        },
        rx,
        std::sync::Weak::new(),
    ));
    let send = tokio::spawn(async move { writer.send(Bytes::from_static(b"blocked"), true).await });
    tokio::task::yield_now().await;
    tokio::time::advance(WRITER_IO_TIMEOUT + Duration::from_millis(1)).await;
    assert_eq!(
        send.await.unwrap().unwrap_err().failure.kind,
        io::ErrorKind::TimedOut
    );
    driver.await.unwrap();
}

#[tokio::test]
async fn saturated_writer_still_delivers_required_end() {
    let (client, mut wire) = tokio::io::duplex(1 << 20);
    let gate = Arc::new(FlushGate::default());
    let session = connect(
        Box::new(GatedFlushIo {
            inner: client,
            gate: Arc::clone(&gate),
        }),
        MAX_STREAMS_PER_SESSION,
    );
    let blocker = {
        let writer = session.writer.clone();
        tokio::spawn(async move { writer.flush().await })
    };
    tokio::task::yield_now().await;
    let queued = (1..=WRITER_QUEUE_CAPACITY as u16)
        .map(|id| {
            let writer = session.writer.clone();
            tokio::spawn(async move { writer.send(end_frame(id), false).await })
        })
        .collect::<Vec<_>>();
    tokio::task::yield_now().await;
    assert!(
        session
            .dispatch(IncomingFrame {
                metadata: base_metadata(128, STATUS_KEEP, OPTION_DATA).freeze(),
                id: 128,
                status: STATUS_KEEP,
                options: OPTION_DATA,
                payload: Some(Bytes::from_static(b"forged")),
            })
            .await
            .is_err()
    );
    assert!(!session.ending_ids.lock().contains(&128));
    session.next_id.store(129, Ordering::Release);
    session
        .dispatch(IncomingFrame {
            metadata: base_metadata(128, STATUS_KEEP, OPTION_DATA).freeze(),
            id: 128,
            status: STATUS_KEEP,
            options: OPTION_DATA,
            payload: Some(Bytes::from_static(b"orphan")),
        })
        .await
        .unwrap();
    gate.open();
    blocker.await.unwrap().unwrap();
    for send in queued {
        send.await.unwrap().unwrap();
    }
    let mut found = false;
    for _ in 0..=WRITER_QUEUE_CAPACITY {
        let frame = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut wire))
            .await
            .expect("required END was dropped")
            .unwrap();
        found |= frame.id == 128 && frame.status == STATUS_END;
    }
    assert!(found);
    session.close();
}

#[tokio::test]
async fn pre_admission_cancel_keeps_an_active_shared_xudp_sid_usable() {
    let (client, mut wire) = tokio::io::duplex(1 << 20);
    let gate = Arc::new(FlushGate::default());
    gate.open();
    let session = connect(
        Box::new(GatedFlushIo {
            inner: client,
            gate: Arc::clone(&gate),
        }),
        MAX_STREAMS_PER_SESSION,
    );
    let udp = open_xudp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        udp_target(),
        None,
        [1; 8],
    )
    .await
    .unwrap_or_else(|_| panic!("XUDP child must open"));
    udp.send_to("1.1.1.1:53".parse().unwrap(), None, b"first", None)
        .await
        .unwrap();
    assert_eq!(read_wire_frame(&mut wire).await.status, STATUS_NEW);

    gate.close();
    let blocker = {
        let writer = session.writer.clone();
        tokio::spawn(async move { writer.flush().await })
    };
    tokio::task::yield_now().await;
    let queued = (0..WRITER_QUEUE_CAPACITY as u16)
        .map(|index| {
            let writer = session.writer.clone();
            tokio::spawn(async move { writer.send(end_frame(1000 + index), false).await })
        })
        .collect::<Vec<_>>();
    while session.writer.tx.capacity() != 0 {
        tokio::task::yield_now().await;
    }
    let admitted = Arc::new(AtomicBool::new(false));
    let sender = tokio::spawn({
        let udp = Arc::clone(&udp);
        let admitted = Arc::clone(&admitted);
        async move {
            udp.send_to(
                "9.9.9.9:53".parse().unwrap(),
                None,
                b"cancelled",
                Some(&admitted),
            )
            .await
        }
    });
    tokio::task::yield_now().await;
    assert!(!sender.is_finished());
    assert!(
        udp.write.try_lock().is_err(),
        "cancelled send did not reach the full writer queue"
    );
    assert!(!admitted.load(Ordering::Acquire));
    sender.abort();
    let _ = sender.await;
    assert!(!admitted.load(Ordering::Acquire));
    assert!(udp.source_send_usable().await);

    gate.open();
    blocker.await.unwrap().unwrap();
    for send in queued {
        send.await.unwrap().unwrap();
    }
    for _ in 0..WRITER_QUEUE_CAPACITY {
        assert_ne!(read_wire_frame(&mut wire).await.id, udp.id);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read_frame(&mut wire))
            .await
            .is_err(),
        "pre-admission cancellation emitted a frame for the shared SID"
    );
    udp.send_to(
        "8.8.8.8:53".parse().unwrap(),
        None,
        b"after",
        Some(&admitted),
    )
    .await
    .expect("one retired view must not poison the shared SID");
    assert!(admitted.load(Ordering::Acquire));
    let after = read_wire_frame(&mut wire).await;
    assert_eq!(after.id, udp.id);
    assert_eq!(after.status, STATUS_KEEP);
    assert_eq!(after.payload.as_deref(), Some(&b"after"[..]));
    session.close();
}

#[tokio::test]
async fn cancelled_tcp_write_does_not_send_or_replay_bytes() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let gate = Arc::new(FlushGate::default());
    gate.open();
    let session = connect(
        Box::new(GatedFlushIo {
            inner: client,
            gate: Arc::clone(&gate),
        }),
        MAX_STREAMS_PER_SESSION,
    );
    let mut stream = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "127.0.0.1:80".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("TCP stream must open"));
    let _ = read_wire_frame(&mut wire).await;
    gate.close();
    let blocker = {
        let writer = session.writer.clone();
        tokio::spawn(async move { writer.flush().await })
    };
    tokio::task::yield_now().await;
    assert!(gate.waker.lock().is_some());
    for id in 2..=WRITER_QUEUE_CAPACITY as u16 + 1 {
        let (done, _wait) = oneshot::channel();
        assert!(
            session
                .writer
                .tx
                .try_send(WriterCommand {
                    frame: end_frame(id),
                    flush: false,
                    done,
                })
                .is_ok()
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), stream.write(b"old"))
            .await
            .is_err()
    );
    gate.open();
    blocker.await.unwrap().unwrap();
    stream.write_all(b"new").await.unwrap();
    stream.flush().await.unwrap();

    let mut saw_new = 0;
    for _ in 0..=WRITER_QUEUE_CAPACITY {
        let frame = read_wire_frame(&mut wire).await;
        assert_ne!(frame.payload.as_deref(), Some(&b"old"[..]));
        saw_new += usize::from(frame.payload.as_deref() == Some(&b"new"[..]));
    }
    assert_eq!(saw_new, 1);
    session.close();
}

#[tokio::test]
async fn dropping_a_pending_shutdown_still_sends_end() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let session = connect(Box::new(client), MAX_STREAMS_PER_SESSION);
    let mut stream = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "127.0.0.1:80".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("TCP stream must open"));
    let id = read_wire_frame(&mut wire).await.id;
    stream.operation = Some(StreamOperation::Shutdown(Box::pin(std::future::pending())));
    drop(stream);
    let end = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut wire))
        .await
        .expect("pending shutdown suppressed END")
        .unwrap();
    assert_eq!((end.id, end.status), (id, STATUS_END));
    session.close();
}

#[tokio::test]
async fn cancelled_pending_flush_then_shutdown_sends_end() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let gate = Arc::new(FlushGate::default());
    gate.open();
    let session = connect(
        Box::new(GatedFlushIo {
            inner: client,
            gate: Arc::clone(&gate),
        }),
        MAX_STREAMS_PER_SESSION,
    );
    let mut stream = open_tcp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        "127.0.0.1:80".parse().unwrap(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("TCP stream must open"));
    let id = read_wire_frame(&mut wire).await.id;

    gate.close();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), stream.flush())
            .await
            .is_err()
    );
    assert!(matches!(stream.operation, Some(StreamOperation::Flush(_))));

    gate.open();
    stream.shutdown().await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut wire))
        .await
        .expect("shutdown completed without delivering END")
        .unwrap();
    assert_eq!((end.id, end.status), (id, STATUS_END));
    assert_eq!(
        stream
            .write_all(b"after shutdown")
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    session.close();
}

#[tokio::test]
async fn first_send_waits_for_flush_and_cancellation_never_replays() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let gate = Arc::new(FlushGate::default());
    let session = connect(
        Box::new(GatedFlushIo {
            inner: client,
            gate: Arc::clone(&gate),
        }),
        MAX_STREAMS_PER_SESSION,
    );
    let udp = open_udp(
        Arc::clone(&session),
        session.try_reserve().unwrap(),
        udp_target(),
        None,
    )
    .await
    .unwrap_or_else(|_| panic!("UDP transport must open"));
    let sender = tokio::spawn({
        let udp = Arc::clone(&udp);
        async move { udp.send_packet_confirmed(b"first").await }
    });
    let first = read_wire_frame(&mut wire).await;
    assert_eq!(first.status, STATUS_NEW);
    assert_eq!(first.payload.as_deref(), Some(&b"first"[..]));
    assert!(!sender.is_finished(), "confirmation must wait for flush");
    sender.abort();
    let _ = sender.await;
    gate.open();
    tokio::task::yield_now().await;
    assert!(!udp.source_send_usable().await);
    let terminal = udp.recv_packet(&mut [0; 1]).await.unwrap_err();
    assert!(is_vless_source_post_admission_cancel(&terminal));
    assert_eq!(
        udp.send_packet_confirmed(b"second")
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    let end = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(end.status, STATUS_END);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read_frame(&mut wire))
            .await
            .is_err(),
        "cancelled first send must not be replayed"
    );
    session.close();
}

#[tokio::test]
async fn single_xudp_uses_session_id_zero() {
    let (client, mut wire) = tokio::io::duplex(1 << 16);
    let udp = connect_single_xudp(Box::new(client), udp_target(), None, [0; 8])
        .await
        .unwrap();
    udp.send_packet_confirmed(b"single").await.unwrap();
    let frame = read_wire_frame(&mut wire).await;
    assert_eq!(frame.id, 0);
    assert_eq!(frame.status, STATUS_NEW);
    assert_eq!(frame.payload.as_deref(), Some(&b"single"[..]));
    udp.session.close();
}
