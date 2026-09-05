use super::*;
mod overflow_runtime;
mod overflow_state;
mod payload_budget;
mod runtime;
mod streams;
mod synack;

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
            InboundPayloadBudget::new(INBOUND_PAYLOAD_BUDGET),
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

fn test_inbound_payload_budget() -> Arc<InboundPayloadBudget> {
    InboundPayloadBudget::new(INBOUND_PAYLOAD_BUDGET)
}

/// Establish a session over an in-memory duplex; returns the session
/// and the server end of the transport.
async fn establish_test_session(addr: &str) -> (Arc<AnyTlsSession>, tokio::io::DuplexStream) {
    establish_test_session_with_budget(addr, test_inbound_payload_budget()).await
}

async fn establish_test_session_with_budget(
    addr: &str,
    inbound_payload_budget: Arc<InboundPayloadBudget>,
) -> (Arc<AnyTlsSession>, tokio::io::DuplexStream) {
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
        inbound_payload_budget,
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
