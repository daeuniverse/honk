use super::*;

#[test]
fn test_settings_payload_format() {
    let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
    assert_eq!(scheme.md5, "75cff2ad89aadf5e257059ee571ebe11");
    assert_eq!(
        scheme.settings_payload().as_ref(),
        b"v=2\nclient=honk/0.0.1-alpha\npadding-md5=75cff2ad89aadf5e257059ee571ebe11\n"
    );
}

#[test]
fn padding_scheme_matches_upstream_map_boundaries() {
    assert!(PaddingScheme::parse(b"0=30-30").is_none());

    let scheme =
        PaddingScheme::parse(b"stop=bad\nstop=3\n01=900-900\n1=20-10,c\nignored=\xff").unwrap();
    assert_eq!(scheme.stop, 3);
    assert!(!scheme.packets.contains_key(&0));
    let packet_one = scheme.packets.get(&1).unwrap();
    assert!(matches!(packet_one[0], PaddingInstruction::Range(10, 20)));
    assert!(matches!(packet_one[1], PaddingInstruction::Check));

    assert!(PaddingScheme::parse(b"stop=1\n0=c,30-30").is_none());
}

#[test]
fn authentication_packet_covers_padding_length_boundaries() {
    let scheme = PaddingScheme::parse(b"stop=1\n0=30-30").unwrap();
    let auth = authentication_payload("secret", &scheme);
    assert_eq!(auth.len(), 64);
    assert_eq!(&auth[..32], &Sha256::digest(b"secret")[..]);
    assert_eq!(&auth[32..34], &30u16.to_be_bytes());
    assert!(auth[34..].iter().all(|byte| *byte == 0));

    let too_large = PaddingScheme::parse(b"stop=1\n0=65536-65536").unwrap();
    assert_eq!(authentication_payload("secret", &too_large).len(), 34);
}

#[test]
fn server_settings_use_the_final_version_value() {
    assert_eq!(server_synack_setting(b"v=2\n"), Some(true));
    assert_eq!(server_synack_setting(b"v=2\nv=1\n"), Some(false));
    assert_eq!(server_synack_setting(b"v=-1\n"), Some(true));
    assert_eq!(server_synack_setting(b"v=256\n"), Some(false));
    assert_eq!(server_synack_setting(b"v=invalid\n"), None);
    assert_eq!(server_synack_setting(b"client=anytls\n"), None);
}

#[tokio::test]
async fn padding_writer_honors_check_and_frame_size_boundaries() {
    let scheme = PaddingScheme::parse(b"stop=3\n1=20-20,c,30-30").unwrap();

    let mut short = Vec::new();
    write_padded(&mut short, b"hello", &scheme, 1)
        .await
        .unwrap();
    assert_eq!(short.len(), 20);
    assert_eq!(&short[..5], b"hello");
    assert_eq!(short[5], CMD_WASTE);
    assert_eq!(&short[10..12], &8u16.to_be_bytes());

    let payload = [7u8; 25];
    let mut long = Vec::new();
    write_padded(&mut long, &payload, &scheme, 1).await.unwrap();
    assert_eq!(&long[..25], &payload);
    assert_eq!(long.len(), 50);
    assert_eq!(long[25], CMD_WASTE);
    assert_eq!(&long[30..32], &18u16.to_be_bytes());

    let mut frame = Vec::new();
    write_frame(&mut frame, CMD_PSH, 1, &vec![0; u16::MAX as usize])
        .await
        .unwrap();
    assert_eq!(frame.len(), FRAME_HEADER_LEN + u16::MAX as usize);
    let error = write_frame(&mut Vec::new(), CMD_PSH, 1, &vec![0; u16::MAX as usize + 1])
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn overflow_state_enforces_frame_and_byte_caps_independently() {
    let mut frames = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_CAP {
        frames.push_back(1, StreamEvent::Data(vec![1]));
    }
    assert_eq!(frames.usage().bytes, SESSION_OVERFLOW_CAP);
    assert_eq!(
        frames.limit_for(2, &StreamEvent::Data(vec![1])),
        Some(OverflowLimit::SessionFrames)
    );

    let mut stream_bytes = OverflowState::default();
    stream_bytes.push_back(1, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));
    assert_eq!(
        stream_bytes.limit_for(1, &StreamEvent::Data(vec![1])),
        Some(OverflowLimit::StreamBytes)
    );

    let mut session_bytes = OverflowState::default();
    for sid in 1..=4 {
        session_bytes.push_back(sid, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));
    }
    assert_eq!(session_bytes.usage().bytes, SESSION_OVERFLOW_BYTES_CAP);
    assert_eq!(
        session_bytes.limit_for(5, &StreamEvent::Data(vec![1])),
        Some(OverflowLimit::SessionBytes)
    );
    assert_eq!(session_bytes.limit_for(5, &StreamEvent::Fin), None);

    let mut competing_limits = OverflowState::default();
    competing_limits.push_back(9, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));
    for _ in 1..SESSION_OVERFLOW_CAP {
        competing_limits.push_back(10, StreamEvent::Data(vec![2]));
    }
    assert_eq!(
        competing_limits.limit_for(9, &StreamEvent::Data(vec![1])),
        Some(OverflowLimit::SessionFrames)
    );

    let mut competing_session_limits = OverflowState::default();
    for sid in 1..=4 {
        competing_session_limits
            .push_back(sid, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));
    }
    for _ in 4..SESSION_OVERFLOW_CAP {
        competing_session_limits.push_back(10, StreamEvent::Data(vec![3]));
    }
    assert_eq!(
        competing_session_limits.limit_for(11, &StreamEvent::Data(vec![1])),
        Some(OverflowLimit::SessionBytes)
    );

    let mut errors = OverflowState::default();
    errors.push_back(1, StreamEvent::Error(Arc::from("remote error")));
    errors.push_back(1, StreamEvent::Fin);
    assert_eq!(errors.usage(), OverflowUsage::default());
    assert_eq!(errors.stream_usage(1).frames, 0);
}

#[test]
fn overflow_terminal_events_cap_per_stream() {
    let mut overflow = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_CAP {
        overflow.push_back(1, StreamEvent::Data(vec![1]));
    }

    assert!(matches!(
        overflow.admit(1, StreamEvent::Fin),
        OverflowAction::Parked
    ));
    assert!(matches!(
        overflow.admit(1, StreamEvent::Error(Arc::from("x"))),
        OverflowAction::Parked
    ));

    assert!(matches!(
        overflow.admit(1, StreamEvent::Fin),
        OverflowAction::Dropped
    ));
    assert!(matches!(
        overflow.admit(2, StreamEvent::Fin),
        OverflowAction::Parked
    ));
    assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_CAP);
    assert_eq!(overflow.stream_usage(1).frames, SESSION_OVERFLOW_CAP);
}

#[test]
fn overflow_state_accounting_tracks_every_queue_operation() {
    let mut overflow = OverflowState::default();
    overflow.push_back(1, StreamEvent::Data(vec![1, 2, 3]));
    overflow.push_back(1, StreamEvent::Fin);
    overflow.push_back(2, StreamEvent::Data(vec![0; 5]));
    assert_eq!(
        overflow.usage(),
        OverflowUsage {
            frames: 2,
            bytes: 8
        }
    );

    let event = overflow.pop_front(1).unwrap();
    assert_eq!(
        overflow.usage(),
        OverflowUsage {
            frames: 1,
            bytes: 5
        }
    );
    overflow.push_front(1, event);
    assert_eq!(
        overflow.usage(),
        OverflowUsage {
            frames: 2,
            bytes: 8
        }
    );

    assert_eq!(
        overflow.remove_stream(1),
        OverflowUsage {
            frames: 1,
            bytes: 3
        }
    );
    assert_eq!(
        overflow.usage(),
        OverflowUsage {
            frames: 1,
            bytes: 5
        }
    );
    assert_eq!(
        overflow.clear(),
        OverflowUsage {
            frames: 1,
            bytes: 5
        }
    );
    assert_eq!(overflow.usage(), OverflowUsage::default());
}

#[tokio::test(start_paused = true)]
async fn overflow_full_requeue_preserves_stall_age() {
    let mut overflow = OverflowState::default();
    overflow.push_back(1, StreamEvent::Data(vec![1]));
    tokio::time::advance(Duration::from_secs(2)).await;

    let progress = overflow.last_progress_at(1);
    let event = overflow.pop_front(1).unwrap();
    overflow.push_front(1, event);
    overflow.restore_last_progress_at(1, progress);

    assert_eq!(overflow.stalled_for(1), Duration::from_secs(2));
}

#[tokio::test(start_paused = true)]
async fn overflow_flush_progress_resets_stall_age() {
    let mut overflow = OverflowState::default();
    overflow.push_back(1, StreamEvent::Data(vec![1]));
    tokio::time::advance(Duration::from_secs(2)).await;
    overflow.note_progress(1);
    tokio::time::advance(Duration::from_secs(2)).await;

    assert_eq!(overflow.stalled_for(1), Duration::from_secs(2));
}

/// Soft caps never kill, no matter how stale the stream: only the
/// watchdog reaps on stall age, only the hard caps reap in admit.
#[tokio::test(start_paused = true)]
async fn overflow_admit_below_hard_caps_never_kills() {
    let mut overflow = OverflowState::default();
    overflow.push_back(1, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));
    tokio::time::advance(OVERFLOW_STALL_GRACE * 4).await;
    assert!(matches!(
        overflow.admit(1, StreamEvent::Data(vec![1])),
        OverflowAction::Parked
    ));
    assert_eq!(
        overflow.stream_usage(1).bytes,
        STREAM_OVERFLOW_BYTES_CAP + 1
    );

    let mut session_soft = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_CAP {
        session_soft.push_back(1, StreamEvent::Data(vec![1]));
    }
    tokio::time::advance(OVERFLOW_STALL_GRACE * 4).await;
    assert!(matches!(
        session_soft.admit(2, StreamEvent::Data(vec![2])),
        OverflowAction::Parked
    ));
    assert_eq!(session_soft.usage().frames, SESSION_OVERFLOW_CAP + 1);
}

/// Hard cap with a past-grace stream: the admit reaps the
/// most-stalled stream immediately and hands the event back; the
/// retry parks on the freed space.
#[tokio::test(start_paused = true)]
async fn overflow_admit_hard_cap_reaps_past_grace_stream() {
    let mut overflow = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_HARD_CAP {
        overflow.push_back(1, StreamEvent::Data(vec![1; 8]));
    }
    tokio::time::advance(OVERFLOW_STALL_GRACE).await;

    let OverflowAction::Kill(victim, event) = overflow.admit(2, StreamEvent::Data(vec![9])) else {
        panic!("past-grace stream at the hard cap must be reaped")
    };
    assert_eq!(victim.sid, 1);
    assert_eq!(victim.limit, OverflowLimit::SessionFrames);
    assert!(victim.stalled_for >= OVERFLOW_STALL_GRACE);
    assert!(!overflow.has(1));

    assert!(matches!(overflow.admit(2, event), OverflowAction::Parked));
    assert_eq!(overflow.usage().frames, 1);
}

/// Hard cap with every stream inside the grace: the admit asks the
/// caller to wait a bounded round instead of killing or parking past
/// the cap; once a stalled stream crosses the grace, the same admit
/// reaps it.
#[tokio::test(start_paused = true)]
async fn overflow_admit_hard_cap_waits_inside_the_grace() {
    let mut overflow = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_HARD_CAP {
        overflow.push_back(1, StreamEvent::Data(vec![1; 8]));
    }
    let wait = match overflow.admit(2, StreamEvent::Data(vec![9])) {
        OverflowAction::Wait(_, wait) => wait,
        _ => panic!("hard cap inside the grace must wait, not kill"),
    };
    assert!(wait <= OVERFLOW_EMERGENCY_WAIT);
    assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_HARD_CAP);
    assert!(overflow.has(1));

    tokio::time::advance(OVERFLOW_STALL_GRACE).await;
    let OverflowAction::Kill(victim, event) = overflow.admit(2, StreamEvent::Data(vec![9])) else {
        panic!("hard cap past the grace must reap")
    };
    assert_eq!(victim.sid, 1);
    assert!(victim.stalled_for >= OVERFLOW_STALL_GRACE);
    assert!(matches!(overflow.admit(2, event), OverflowAction::Parked));
}

/// The byte hard cap follows the same wait-then-reap path as the
/// frame cap.
#[tokio::test(start_paused = true)]
async fn overflow_admit_hard_byte_cap_waits_inside_the_grace() {
    let mut overflow = OverflowState::default();
    overflow.push_back(
        1,
        StreamEvent::Data(vec![0; SESSION_OVERFLOW_HARD_BYTES_CAP]),
    );
    assert!(matches!(
        overflow.admit(2, StreamEvent::Data(vec![1])),
        OverflowAction::Wait(..)
    ));
    tokio::time::advance(OVERFLOW_STALL_GRACE).await;
    assert!(matches!(
        overflow.admit(2, StreamEvent::Data(vec![1])),
        OverflowAction::Kill(..)
    ));
    assert!(!overflow.has(1));
}

fn anytls_node(name: &str) -> Node {
    Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        outbound: honk_config::node::OutboundConfig::AnyTls(Default::default()),
        ..Default::default()
    }
}

fn zero_idle_anytls_node(name: &str) -> Node {
    let mut node = anytls_node(name);
    node.anytls_mut().unwrap().min_idle_session = Some(0);
    node
}

#[test]
fn test_resolve_password() {
    let mut node = anytls_node("test");
    assert_eq!(AnyTlsHandler::resolve_password(&node), "");

    node.anytls_mut().unwrap().password = Some("anytls-secret".into());
    assert_eq!(AnyTlsHandler::resolve_password(&node), "anytls-secret");
}

#[tokio::test]
async fn stalled_tls_session_dial_respects_its_own_deadline() {
    // Given: the proxy accepts TCP but never sends a TLS ServerHello.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket_addr = listener.local_addr().unwrap();
    let address = socket_addr.to_string();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let node = Node {
        address: address.clone(),
        host: socket_addr.ip().to_string(),
        port: socket_addr.port(),
        outbound: honk_config::node::OutboundConfig::AnyTls(honk_config::node::AnyTlsConfig {
            tls: honk_config::node::TlsOptions {
                sni: Some("localhost".into()),
                skip_cert_verify: true,
                ..Default::default()
            },
            ..Default::default()
        }),
        ..anytls_node("stalled-tls")
    };

    // When: a pool-owned physical AnyTLS session dial reaches that server.
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        dial_session(
            &node,
            &address,
            Duration::from_millis(50),
            None,
            Arc::new(PaddingState::default()),
        ),
    )
    .await;
    server.abort();

    // Then: the handshake expires instead of relying on caller cancellation.
    let outcome = result.expect("the AnyTLS dial must enforce an internal deadline");
    let error = outcome.err().expect("the stalled TLS dial must fail");
    assert!(
        error.to_string().contains("AnyTLS TLS handshake timed out"),
        "unexpected error: {error:#}"
    );
}

#[tokio::test]
async fn test_writer_batch_encoding_matches_sequential_frames() {
    let q = WriterQueue::new();
    let sem = Arc::new(tokio::sync::Semaphore::new(2));
    let p1 = sem.clone().acquire_owned().await.unwrap();
    let p2 = sem.clone().acquire_owned().await.unwrap();
    assert!(
        q.push_batch([
            FrameCommand::Control {
                cmd: CMD_SYN,
                sid: 1,
                payload: bytes::Bytes::from_static(b"addr"),
            },
            FrameCommand::Data {
                sid: 1,
                payload: bytes::Bytes::from_static(b"hello"),
                _permit: p1,
                completion: None,
            },
            FrameCommand::Data {
                sid: 2,
                payload: bytes::Bytes::from_static(b"world"),
                _permit: p2,
                completion: None,
            },
            FrameCommand::Control {
                cmd: CMD_FIN,
                sid: 2,
                payload: bytes::Bytes::new(),
            },
        ])
        .is_ok()
    );
    let mut batch = vec![q.pop().await.unwrap()];
    q.drain_available(
        &mut batch,
        WRITER_BATCH_MAX_FRAMES - 1,
        WRITER_BATCH_MAX_BYTES,
    );
    assert_eq!(batch.len(), 4);
    let mut buf = bytes::BytesMut::new();
    for cmd in &batch {
        cmd.encode_into(&mut buf);
    }

    let mut reference: Vec<u8> = Vec::new();
    write_frame(&mut reference, CMD_SYN, 1, b"addr")
        .await
        .unwrap();
    write_frame(&mut reference, CMD_PSH, 1, b"hello")
        .await
        .unwrap();
    write_frame(&mut reference, CMD_PSH, 2, b"world")
        .await
        .unwrap();
    write_frame(&mut reference, CMD_FIN, 2, b"").await.unwrap();
    assert_eq!(&buf[..], &reference[..]);
}

#[tokio::test]
async fn test_writer_batch_caps() {
    let q = WriterQueue::new();
    let payload = bytes::Bytes::from(vec![7u8; 100]);
    for sid in 0..5u32 {
        assert!(
            q.push_batch([FrameCommand::Control {
                cmd: CMD_WASTE,
                sid,
                payload: payload.clone(),
            }])
            .is_ok()
        );
    }

    let mut batch = Vec::new();
    q.drain_available(&mut batch, 2, usize::MAX);
    assert_eq!(batch.len(), 2);

    let mut batch = Vec::new();
    q.drain_available(&mut batch, usize::MAX, 300);
    assert_eq!(batch.len(), 2);

    let mut batch = Vec::new();
    q.drain_available(&mut batch, usize::MAX, usize::MAX);
    assert_eq!(batch.len(), 1);
    assert!(q.queue.lock().is_empty());
}

#[test]
fn writer_queue_bounds_control_pressure_and_rejects_after_close() {
    let q = WriterQueue::new();
    for sid in 0..WRITER_QUEUE_CAP {
        assert!(
            q.push_batch([FrameCommand::Control {
                cmd: CMD_HEART_RESPONSE,
                sid: sid as u32,
                payload: bytes::Bytes::new(),
            }])
            .is_ok()
        );
    }
    assert!(
        q.push_batch([FrameCommand::Control {
            cmd: CMD_HEART_RESPONSE,
            sid: u32::MAX,
            payload: bytes::Bytes::new(),
        }])
        .is_err()
    );

    q.close();
    assert!(q.queue.lock().is_empty());
    assert!(
        q.push_batch([FrameCommand::Control {
            cmd: CMD_FIN,
            sid: 1,
            payload: bytes::Bytes::new(),
        }])
        .is_err()
    );
}

const TEST_AUTH: &[u8] = b"test-auth";
const TEST_SETTINGS: &[u8] = b"test-settings";

fn test_padding() -> Arc<PaddingState> {
    Arc::new(PaddingState {
        current: parking_lot::RwLock::new(Arc::new(PaddingScheme::parse(b"stop=0").unwrap())),
    })
}

/// Establish a session over an in-memory duplex; returns the session
/// and the server end of the transport.
async fn establish_test_session(addr: &str) -> (Arc<AnyTlsSession>, tokio::io::DuplexStream) {
    let (client_end, server_end) = tokio::io::duplex(1 << 20);
    let (read, write) = tokio::io::split(client_end);
    let padding_state = test_padding();
    let session = AnyTlsSession::establish(
        addr,
        Box::new(read),
        Box::new(write),
        TEST_AUTH,
        bytes::Bytes::from_static(TEST_SETTINGS),
        padding_state,
    )
    .await
    .unwrap();
    session.flush_initial_settings_for_test().unwrap();
    (session, server_end)
}

/// Assert the session opened with the auth blob + settings frame.
async fn expect_handshake(server: &mut tokio::io::DuplexStream) {
    let mut auth = vec![0u8; TEST_AUTH.len()];
    server.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, TEST_AUTH);
    let (cmd, sid, data) = read_frame(server).await.unwrap();
    assert_eq!(cmd, CMD_SETTINGS);
    assert_eq!(sid, 0);
    assert_eq!(data, TEST_SETTINGS);
}

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

#[tokio::test]
async fn runtime_udp_pool_hit_does_not_build_connector() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "runtime-udp-hit".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = match &runtime.runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("expected AnyTLS runtime"),
    };
    let (session, mut server) = establish_test_session("runtime-udp-hit").await;
    expect_handshake(&mut server).await;
    pool.insert(&session);
    assert!(!runtime.tls_connector_loaded());

    let handler = AnyTlsHandler::new();
    let transport = handler
        .dial_udp_transport_runtime(
            Arc::clone(&runtime),
            "127.0.0.1:53".parse().unwrap(),
            None,
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    assert!(!runtime.tls_connector_loaded());
    drop(transport);
    generation.shutdown().await;
}

/// A cold-node health probe dials through an ephemeral runtime; closing
/// it must deterministically release the session, its demux task, and
/// the underlying connection (the 797 ESTABLISHED leak: throwaway pools
/// had no owner running any close/idle reaping).
/// A probe future dropped mid-flight (outer timeout / task abort) never
/// runs the explicit close; the guard's Drop must still release the
/// session and its connection.
#[tokio::test]
async fn ephemeral_guard_releases_session_when_probe_is_aborted() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "guard-abort".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let (session, mut server) = establish_test_session("guard-abort").await;
    expect_handshake(&mut server).await;
    let probe_session = Arc::clone(&session);
    let probe = tokio::spawn(async move {
        let guard = crate::runtime::NodeRuntime::ephemeral_guarded(&node);
        let runtime = guard.runtime();
        let crate::runtime::ProtocolRuntime::AnyTls(anytls) = &runtime.runtime else {
            panic!("expected AnyTLS runtime")
        };
        anytls.pool.insert(&probe_session);
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    probe.abort();
    let _ = probe.await;

    assert!(
        session.is_closed(),
        "dropping the guard on abort must close the session"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while read_frame(&mut server).await.is_ok() {}
    })
    .await
    .expect("the connection must close on abort");
}

#[tokio::test]
async fn ephemeral_runtime_close_releases_session_and_connection() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "ephemeral-probe".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let runtime = crate::runtime::NodeRuntime::ephemeral(&node);
    assert!(runtime.is_ephemeral());
    let pool = match &runtime.runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("expected AnyTLS runtime"),
    };
    let (session, mut server) = establish_test_session("ephemeral-probe").await;
    expect_handshake(&mut server).await;
    pool.insert(&session);

    let handler = AnyTlsHandler::new();
    let stream = handler
        .dial_runtime(
            Arc::clone(&runtime),
            "8.8.8.8:53".parse().unwrap(),
            None,
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .stream;
    let (cmd, _sid, _) = read_frame(&mut server).await.unwrap();
    assert_eq!(cmd, CMD_SYN);
    let (cmd, _, _) = read_frame(&mut server).await.unwrap();
    assert_eq!(cmd, CMD_PSH);
    drop(stream);

    runtime.close().await;
    assert!(session.is_closed());
    assert_eq!(pool.live_session_count(), 0);

    tokio::time::timeout(Duration::from_secs(5), async {
        while read_frame(&mut server).await.is_ok() {}
    })
    .await
    .expect("closing the ephemeral runtime must close the connection");
}

#[tokio::test]
async fn warm_resources_flip_with_pool_session() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "warm-resources".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let generation =
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let runtime = generation.get(&node.id).unwrap();
    assert!(!runtime.is_warm_or_stateless());

    let crate::runtime::ProtocolRuntime::AnyTls(anytls) = &runtime.runtime else {
        panic!("expected AnyTLS runtime")
    };
    let (session, mut server) = establish_test_session("warm-resources").await;
    expect_handshake(&mut server).await;
    anytls.pool.insert(&session);
    assert!(runtime.is_warm_or_stateless());
    assert_eq!(runtime.warm_counts().sessions, 1);

    session.close();
    assert!(
        !runtime.is_warm_or_stateless(),
        "a closed session no longer counts as warm"
    );
    assert_eq!(runtime.warm_counts().sessions, 0);
}

#[tokio::test]
async fn runtime_dial_stays_on_captured_pool_after_registry_swap() {
    let old_node = Node {
        id: uuid::Uuid::new_v4(),
        name: "generation-node".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        address: "127.0.0.1:9".into(),
        ..Default::default()
    };
    let old_generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&old_node)).unwrap(),
    );
    let old_runtime = old_generation.get(&old_node.id).unwrap();
    let old_pool = match &old_runtime.runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("expected AnyTLS runtime"),
    };
    let (session, mut server) = establish_test_session("captured-generation").await;
    expect_handshake(&mut server).await;
    let _addresses = spawn_echo_server(server);
    old_pool.insert(&session);

    let mut replacement_node = old_node.clone();
    replacement_node.address = "127.0.0.1:10".into();
    let replacement = crate::runtime::OutboundRuntimeRegistry::build(&[replacement_node]).unwrap();
    let replacement_pool = match &replacement.get(&old_node.id).unwrap().runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("expected AnyTLS runtime"),
    };
    let handler = AnyTlsHandler::new();

    let mut stream = handler
        .dial_runtime(
            old_runtime,
            "8.8.8.8:53".parse().unwrap(),
            None,
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .stream;
    stream.write_all(b"old-generation").await.unwrap();
    let mut echoed = vec![0; b"old-generation".len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"old-generation");
    assert!(old_pool.has_usable_session());
    assert!(!replacement_pool.has_usable_session());
    session.close();
}

#[tokio::test(start_paused = true)]
async fn runtime_retirement_drains_live_session_without_cutting_it() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "retiring-anytls".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
        ..Default::default()
    };
    let generation =
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    let pool = match &generation.get(&node.id).unwrap().runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("expected AnyTLS runtime"),
    };
    let (session, mut server) = establish_test_session("retiring-anytls").await;
    expect_handshake(&mut server).await;
    pool.insert(&session);
    let permit = session.try_reserve().expect("live stream permit");

    generation.begin_retirement();
    assert!(
        !session.is_closed(),
        "publication must not cut live streams"
    );
    generation.drain_session_pools();
    assert_eq!(session.state(), crate::session::SessionState::Draining);
    assert!(
        !session.is_closed(),
        "pool drain must preserve live streams"
    );

    drop(permit);
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    assert!(session.is_closed(), "last stream release must finish drain");
}

#[tokio::test]
async fn uot_setup_fallback_waits_for_capacity_and_cancellation_does_not_enqueue() {
    let (session, mut server) = establish_test_session("uot-setup-capacity").await;
    expect_handshake(&mut server).await;
    let capacity = (WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED) as u32;
    let held = Arc::clone(&session.writer_q.data_permits)
        .acquire_many_owned(capacity)
        .await
        .unwrap();

    let setup = session.enqueue_confirmed_data(7, bytes::Bytes::from_static(b"setup"));
    tokio::pin!(setup);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut setup)
            .await
            .is_err(),
        "oversized first datagrams must not drop their fallback setup"
    );
    drop(held);
    tokio::time::timeout(Duration::from_secs(1), setup)
        .await
        .unwrap()
        .unwrap();
    let (cmd, sid, payload) = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut server))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (cmd, sid, payload.as_slice()),
        (CMD_PSH, 7, b"setup".as_slice())
    );

    let held = Arc::clone(&session.writer_q.data_permits)
        .acquire_many_owned(capacity)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            session.enqueue_confirmed_data(7, bytes::Bytes::from_static(b"cancelled")),
        )
        .await
        .is_err()
    );
    drop(held);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), read_frame(&mut server))
            .await
            .is_err(),
        "cancelling before capacity is acquired must not enqueue setup"
    );
    session.close();
}

/// A fake AnyTLS server: consumes each SYN and its address PSH (the
/// address is forwarded to `addr_tx`), echoes payload PSHs back to the
/// same sid, and answers FIN with FIN.
fn spawn_echo_server(
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
    assert!(
        session.is_closed(),
        "an unrelated SYNACK must not clear another stream's deadline"
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
    assert!(session.is_closed(), "the third stream's own deadline fires");
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
        .push_back(31, StreamEvent::Data(vec![1; 17]));
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
        .push_back(32, StreamEvent::Data(vec![2; 19]));
    drop(registration);
    assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());

    let (closed_tx, closed_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session
        .streams
        .lock()
        .unwrap()
        .insert(33, StreamSink::Tcp(closed_tx));
    session
        .overflow
        .lock()
        .push_back(33, StreamEvent::Data(vec![3; 23]));
    drop(closed_rx);
    session.dispatch_data(33, vec![4]).await;
    assert!(!session.streams.lock().unwrap().contains_key(&33));
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
        .push_back(34, StreamEvent::Data(vec![5; 29]));
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
        tx.try_send(StreamEvent::Data(vec![0])).unwrap();
    }
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    session
        .overflow
        .lock()
        .push_back(sid, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));

    session.park_overflow(sid, StreamEvent::Data(vec![1])).await;
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
            overflow.push_back(51, StreamEvent::Data(vec![1; 8]));
        }
        for _ in 0..368 {
            overflow.push_back(52, StreamEvent::Data(vec![2; 8]));
        }
        assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_HARD_CAP);
    }
    tokio::time::advance(OVERFLOW_STALL_GRACE).await;

    session
        .park_overflow(53, StreamEvent::Data(vec![9, 8, 7]))
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
        waiting_tx.try_send(StreamEvent::Data(vec![7])).unwrap();
    }
    {
        let mut streams = session.streams.lock().unwrap();
        streams.insert(slow_sid, StreamSink::Tcp(slow_tx));
        streams.insert(waiting_sid, StreamSink::Tcp(waiting_tx));
    }
    {
        let mut overflow = session.overflow.lock();
        for _ in 0..SESSION_OVERFLOW_HARD_CAP {
            overflow.push_back(slow_sid, StreamEvent::Data(vec![1; 8]));
        }
    }

    let parker = tokio::spawn({
        let session = Arc::clone(&session);
        async move {
            session
                .park_overflow(waiting_sid, StreamEvent::Data(vec![9, 8, 7]))
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
            overflow.push_back(71, StreamEvent::Data(vec![1; 8]));
        }
    }

    session.park_overflow(72, StreamEvent::Data(vec![9])).await;

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
    let (fast_tx, mut fast_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    let (waiting_tx, mut waiting_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    for _ in 0..STREAM_QUEUE_CAP {
        waiting_tx.try_send(StreamEvent::Data(vec![7])).unwrap();
    }
    {
        let mut streams = session.streams.lock().unwrap();
        streams.insert(slow_sid, StreamSink::Tcp(slow_tx));
        streams.insert(fast_sid, StreamSink::Tcp(fast_tx));
        streams.insert(waiting_sid, StreamSink::Tcp(waiting_tx));
    }
    {
        let mut overflow = session.overflow.lock();
        for _ in 0..SESSION_OVERFLOW_CAP {
            overflow.push_back(slow_sid, StreamEvent::Data(vec![1; 8]));
        }
    }

    session
        .park_overflow(waiting_sid, StreamEvent::Data(vec![9, 8, 7]))
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
    match fast_rx.recv().await.unwrap() {
        StreamEvent::Data(data) => assert_eq!(data, vec![7]),
        StreamEvent::Fin | StreamEvent::Error(_) => panic!("fast sibling was terminated"),
    }

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
        .park_overflow(sid, StreamEvent::Data(vec![7, 8, 9]))
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
            StreamEvent::Data(u16::try_from(index).unwrap().to_be_bytes().to_vec()),
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
                observed.push(u16::from_be_bytes(data.try_into().unwrap()) as usize);
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
    tx.try_send(StreamEvent::Data(vec![1])).unwrap();
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
        .push_back(sid, StreamEvent::Data(vec![1]));
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
        .push_back(sid, StreamEvent::Data(vec![1]));
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
        .push_back(sid, StreamEvent::Data(vec![1]));
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
    let (fast_tx, mut fast_rx) = mpsc::channel(STREAM_QUEUE_CAP);
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
    let permit = session.try_reserve().unwrap();
    let mut slow_stream = AnyTlsStream::new(Arc::clone(&session), 1, slow_rx, permit);

    let parked = 64usize;
    for i in 0..STREAM_QUEUE_CAP + parked {
        session.dispatch_data(1, vec![(i % 251) as u8; 4]).await;
    }

    for i in 0..10u8 {
        session.dispatch_data(2, vec![i; 4]).await;
        let ev = tokio::time::timeout(Duration::from_secs(2), fast_rx.recv())
            .await
            .expect("stream 2 must not be blocked by stream 1")
            .expect("stream 2 channel open");
        match ev {
            StreamEvent::Data(d) => assert_eq!(d, vec![i; 4]),
            _ => panic!("stream 2 got non-data event"),
        }
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
    let (slow_tx, _slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    let (fast_tx, mut fast_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    {
        let mut streams = session.streams.lock().unwrap();
        streams.insert(slow_sid, StreamSink::Tcp(slow_tx));
        streams.insert(fast_sid, StreamSink::Tcp(fast_tx));
    }

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
    let event = tokio::time::timeout(Duration::from_millis(100), fast_rx.recv())
        .await
        .expect("fast sibling must not wait behind the overflow cap")
        .expect("fast sibling channel open");
    match event {
        StreamEvent::Data(data) => assert_eq!(data, vec![7u8; 4]),
        StreamEvent::Fin | StreamEvent::Error(_) => panic!("fast sibling was terminated"),
    }
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
        tx.try_send(StreamEvent::Data(vec![0])).unwrap();
    }
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    session
        .park_overflow(sid, StreamEvent::Data(vec![1; 8]))
        .await;
    session
        .park_overflow(sid, StreamEvent::Data(vec![2; 8]))
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
        tx.try_send(StreamEvent::Data(vec![0])).unwrap();
    }
    session
        .streams
        .lock()
        .unwrap()
        .insert(sid, StreamSink::Tcp(tx));
    session
        .park_overflow(sid, StreamEvent::Data(vec![1; 8]))
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
    tx.try_send(StreamEvent::Data(vec![0])).unwrap();
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

#[tokio::test]
async fn warm_uses_only_its_generation_owned_runtime_pool() {
    let node = zero_idle_anytls_node("warm-anytls");
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = match &runtime.runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("AnyTLS node needs its own runtime"),
    };
    let (session, mut server) = establish_test_session("warm-anytls").await;
    expect_handshake(&mut server).await;

    AnyTlsHandler::warm_pool_with(Arc::clone(&runtime), move || async move { Ok(session) })
        .await
        .unwrap();
    assert!(pool.has_usable_session());

    let handler = AnyTlsHandler::new();
    handler
        .warm(
            Arc::clone(&runtime),
            Duration::from_secs(1),
            WarmRequirement::Session,
        )
        .await
        .unwrap();
    drop(server);
}

#[tokio::test]
async fn warm_shutdown_cancels_a_notify_blocked_dial_and_keeps_pool_terminal() {
    let node = zero_idle_anytls_node("shutdown-warm-anytls");
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = match &runtime.runtime {
        crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
        _ => panic!("AnyTLS node needs its own runtime"),
    };
    let dial_started = Arc::new(tokio::sync::Notify::new());
    let dial_blocked = Arc::new(tokio::sync::Notify::new());
    let warm = tokio::spawn({
        let runtime = Arc::clone(&runtime);
        let dial_started = Arc::clone(&dial_started);
        let dial_blocked = Arc::clone(&dial_blocked);
        async move {
            AnyTlsHandler::warm_pool_with(runtime, move || {
                let dial_started = Arc::clone(&dial_started);
                let dial_blocked = Arc::clone(&dial_blocked);
                async move {
                    dial_started.notify_one();
                    dial_blocked.notified().await;
                    unreachable!("the blocked warm dial must be cancelled by shutdown")
                }
            })
            .await
        }
    });

    tokio::time::timeout(Duration::from_secs(1), dial_started.notified())
        .await
        .expect("warm dial must start before its generation is shut down");
    generation.shutdown().await;
    let result = tokio::time::timeout(Duration::from_secs(1), warm)
        .await
        .expect("shutdown must unblock the warm future")
        .expect("warm task must not panic");
    assert!(result.is_err(), "terminal pool shutdown rejects the warm");
    assert!(
        !pool.has_usable_session(),
        "a cancelled dial must not leave a usable session in the pool"
    );
    assert!(
        AnyTlsHandler::warm_pool_with(Arc::clone(&runtime), || async {
            unreachable!("a terminal pool must reject before invoking a new dial")
        })
        .await
        .is_err(),
        "subsequent warm attempts must be rejected after generation shutdown"
    );
}

#[tokio::test]
async fn speculative_shared_loser_unregisters_uot_sid_synchronously() {
    let handler = AnyTlsHandler::new();
    let node = zero_idle_anytls_node("speculative-shared");
    let pool: Arc<AnyTlsPool> = Arc::new(AnyTlsPool::new());
    let (session, _server) = establish_test_session("speculative-shared").await;
    pool.insert(&session);
    let prepared = handler
        .dial_udp_transport_speculative_with(
            &node,
            Arc::clone(&pool),
            "8.8.8.8:53".parse().unwrap(),
            None,
            || async { unreachable!("a shared checkout cannot dial") },
        )
        .await
        .unwrap();
    assert_eq!(session.streams.lock().unwrap().len(), 1);

    drop(prepared);

    assert!(
        session.streams.lock().unwrap().is_empty(),
        "loser Drop must synchronously unregister its UoT stream"
    );
    assert!(
        !session.is_closed(),
        "dropping a shared speculative transport must not retire its pooled session"
    );
}

#[tokio::test]
async fn speculative_detached_winner_commits_into_captured_pool_once() {
    let handler = AnyTlsHandler::new();
    let node = zero_idle_anytls_node("speculative-detached-commit");
    let pool: Arc<AnyTlsPool> = Arc::new(AnyTlsPool::new());
    let (session, _server) = establish_test_session("speculative-detached-commit").await;
    let prepared = handler
        .dial_udp_transport_speculative_with(
            &node,
            Arc::clone(&pool),
            "8.8.8.8:53".parse().unwrap(),
            None,
            {
                let session = Arc::clone(&session);
                move || async move { Ok(session) }
            },
        )
        .await
        .unwrap();
    assert_eq!(pool.metrics().sessions, 0);
    assert_eq!(session.streams.lock().unwrap().len(), 1);

    let transport = prepared.commit().await.unwrap();
    assert_eq!(pool.metrics().sessions, 1);
    assert!(pool.has_usable_session());
    drop(transport);
    assert!(session.streams.lock().unwrap().is_empty());
    pool.shutdown();
}

#[tokio::test]
async fn speculative_commit_binds_initial_generation_admission() {
    let mut node = zero_idle_anytls_node("speculative-initial-admission");
    node.address = "127.0.0.1:443".into();
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing(
            std::slice::from_ref(&node),
            1,
            None,
        )
        .unwrap()
        .0,
    );
    let runtime = generation.get(&node.id).unwrap();
    let pool = runtime.anytls_pool().unwrap();
    assert!(!pool.dial_scope_matches(&generation));
    let (session, _server) = establish_test_session("speculative-initial-admission").await;
    let prepared = generation
        .scope_dials(AnyTlsHandler::dial_udp_transport_speculative_for_pool_with(
            &node,
            Arc::clone(&pool),
            "8.8.8.8:53".parse().unwrap(),
            None,
            Some(runtime),
            {
                let session = Arc::clone(&session);
                move || async move { Ok(session) }
            },
        ))
        .await
        .unwrap();
    assert!(!pool.dial_scope_matches(&generation));

    let transport = prepared.commit().await.unwrap();

    assert!(pool.dial_scope_matches(&generation));
    drop(transport);
    pool.shutdown();
}

#[tokio::test]
async fn speculative_detached_commit_fails_closed_after_generation_shutdown() {
    let handler = AnyTlsHandler::new();
    let node = zero_idle_anytls_node("speculative-detached-shutdown");
    let pool: Arc<AnyTlsPool> = Arc::new(AnyTlsPool::new());
    let (session, _server) = establish_test_session("speculative-detached-shutdown").await;
    let prepared = handler
        .dial_udp_transport_speculative_with(
            &node,
            Arc::clone(&pool),
            "8.8.8.8:53".parse().unwrap(),
            None,
            {
                let session = Arc::clone(&session);
                move || async move { Ok(session) }
            },
        )
        .await
        .unwrap();

    pool.shutdown();
    assert!(prepared.commit().await.is_err());
    assert!(session.is_closed());
    assert!(session.streams.lock().unwrap().is_empty());
    assert_eq!(pool.metrics().sessions, 0);
}

struct CancelledDial(Arc<AtomicBool>);

impl Drop for CancelledDial {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[tokio::test]
async fn speculative_udp_abort_cancels_injected_dial_without_pooling() {
    let handler = Arc::new(AnyTlsHandler::new());
    let node = zero_idle_anytls_node("speculative-abort");
    let pool: Arc<AnyTlsPool> = Arc::new(AnyTlsPool::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let cancelled = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn({
        let handler = Arc::clone(&handler);
        let node = node.clone();
        let pool = Arc::clone(&pool);
        let started = Arc::clone(&started);
        let cancelled = Arc::clone(&cancelled);
        async move {
            let _ = handler
                .dial_udp_transport_speculative_with(
                    &node,
                    pool,
                    "8.8.8.8:53".parse().unwrap(),
                    None,
                    move || async move {
                        let _cancelled = CancelledDial(cancelled);
                        started.notify_one();
                        futures_util::future::pending::<anyhow::Result<Arc<AnyTlsSession>>>().await
                    },
                )
                .await;
        }
    });
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("the injected speculative dial must start");

    task.abort();
    let _ = task.await;
    assert!(
        cancelled.load(Ordering::Acquire),
        "aborting the speculative caller must drop the physical dial future"
    );
    assert_eq!(pool.metrics().sessions, 0);
    let first = pool.checkout_speculative().await.unwrap();
    let second = tokio::time::timeout(Duration::from_millis(100), pool.checkout_speculative())
        .await
        .expect("cancelled speculative work must not leave a provisional slot")
        .unwrap();
    assert!(matches!(
        first,
        crate::session::SpeculativeCheckout::Detached(_)
    ));
    assert!(matches!(
        second,
        crate::session::SpeculativeCheckout::Detached(_)
    ));
}

#[tokio::test]
async fn speculative_udp_generation_shutdown_cancels_injected_dial() {
    let handler = Arc::new(AnyTlsHandler::new());
    let node = zero_idle_anytls_node("speculative-shutdown");
    let pool: Arc<AnyTlsPool> = Arc::new(AnyTlsPool::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let cancelled = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn({
        let handler = Arc::clone(&handler);
        let node = node.clone();
        let pool = Arc::clone(&pool);
        let started = Arc::clone(&started);
        let cancelled = Arc::clone(&cancelled);
        async move {
            handler
                .dial_udp_transport_speculative_with(
                    &node,
                    pool,
                    "8.8.8.8:53".parse().unwrap(),
                    None,
                    move || async move {
                        let _cancelled = CancelledDial(cancelled);
                        started.notify_one();
                        futures_util::future::pending::<anyhow::Result<Arc<AnyTlsSession>>>().await
                    },
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("the detached generation-owned dial must start");

    pool.shutdown();
    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("pool shutdown must cancel the detached dial")
        .expect("speculative task must not panic");
    assert!(result.is_err());
    assert!(cancelled.load(Ordering::Acquire));
    assert_eq!(pool.metrics().sessions, 0);
}
