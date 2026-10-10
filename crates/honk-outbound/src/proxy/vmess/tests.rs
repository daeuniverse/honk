use super::*;
use std::io;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Byte-level regression vectors produced by running the actual
// Xray-core/sing-vmess Go code (aead/kdf.go, aead/authid.go,
// aead/encrypt.go, encoding/auth.go semantics) with these fixed inputs.
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const CMD_KEY: &str = "b50d916ac0cec067981af8e5f38a758f";
const AUTH_ID_KEY: &str = "1415ba74ca8b3d041a8f583fb4116315";
const AUTH_ID: &str = "7997d3314952dc37e0b284331b6bb2e7"; // ts=1700000000, rand=deadbeef
const HEADER_PLAIN: &str = "0122222222222222222222222222222222111111111111111111111111111111115a053300010050015db8d822aabbcc15eba2f4";
const HEADER_WIRE: &str = "7997d3314952dc37e0b284331b6bb2e71a963074b6c9f5cd7c0825ace93c69df311f0102030405060708301fcaedd9021cf0eaab9deb25afab08b13d78f0b0ff69acfc123dd0ba0d9b6c24d5edbfbcd20d23d7fd0a9f3d59a64835ccd0253af09feb22cc2affb2942c159c5acdc2";
const CHUNK0: &str = "cce0f4cf6e664ef12db2501e5fc2333f0d54118144ce186c4913a9a33a";
const CHUNK1: &str = "821e7f5df60be7f0159bdf89de3bda5c55c920d471fda4d17d24ddb5fd";
const CHUNK_TERM: &str = "f25f875b48011300760c657294fca053c869";
const RESP_KEY: &str = "b8f12ea8c9a95d4b4641b03d9fa5a71a";
const RESP_IV: &str = "3dc30fbac8417f76943e9c10e15eeacb";
const RESP_HEADER_WIRE: &str =
    "1ed5e218e618e8c5350363b980c93de5efa06015b5dc7a63f67ab72353ff9aa4f47a9ee044da";
const RCHUNK0: &str = "a519478d162a2f176b9d3e71216983fc910451176407bbc97aa4daccb61c4740c0";
const RCHUNK1: &str = "7baab45ea2ec0a90ad19bc5cacb263341906c9224a32ff3ce1dd65f2c0f7817120";

fn fixed_session() -> Session {
    Session {
        req_key: [0x11; 16],
        req_iv: [0x22; 16],
        resp_key: hex(RESP_KEY).try_into().unwrap(),
        resp_iv: hex(RESP_IV).try_into().unwrap(),
        resp_header: 0x5a,
    }
}

fn fixed_cmd_key() -> [u8; 16] {
    hex(CMD_KEY).try_into().unwrap()
}

#[test]
fn test_derive_cmd_key_vector() {
    let uuid = uuid::Uuid::parse_str(UUID).unwrap();
    assert_eq!(
        VmessHandler::derive_cmd_key(uuid.as_bytes()),
        fixed_cmd_key()
    );
}

#[test]
fn test_kdf_auth_id_key_vector() {
    assert_eq!(
        kdf16(&fixed_cmd_key(), KDF_SALT_AUTH_ID, &[]).to_vec(),
        hex(AUTH_ID_KEY)
    );
}

#[test]
fn test_auth_id_vector() {
    let auth_id =
        VmessHandler::create_auth_id(&fixed_cmd_key(), 1_700_000_000, [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(auth_id.to_vec(), hex(AUTH_ID));
}

#[test]
fn test_request_header_plain_vector() {
    let session = fixed_session();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let plain =
        VmessHandler::build_header_plain(&session, 3, &[0xaa, 0xbb, 0xcc], target, None).unwrap();
    assert_eq!(plain, hex(HEADER_PLAIN));
}

#[test]
fn test_request_header_wire_vector() {
    let session = fixed_session();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let plain =
        VmessHandler::build_header_plain(&session, 3, &[0xaa, 0xbb, 0xcc], target, None).unwrap();
    let wire = VmessHandler::seal_request_header(
        &fixed_cmd_key(),
        &hex(AUTH_ID).try_into().unwrap(),
        &[1, 2, 3, 4, 5, 6, 7, 8],
        &plain,
    );
    assert_eq!(wire, hex(HEADER_WIRE));
}

#[test]
fn test_body_chunk_vectors() {
    let session = fixed_session();
    let mut body = BodyChunks::new(&session.req_key, &session.req_iv).unwrap();
    let c0 = body.seal_chunk(b"hello vmess");
    let c1 = body.seal_chunk(b"hello vmess");
    let term = body.seal_chunk(b"");
    assert_eq!(c0, hex(CHUNK0));
    assert_eq!(c1, hex(CHUNK1));
    assert_eq!(term, hex(CHUNK_TERM));
}

/// Feed the exact bytes a Go (Xray-semantics) server would send and
/// check the response header + body chunk decode end to end.
#[tokio::test]
async fn test_response_decode_vectors() {
    let session = fixed_session();
    let mut wire = hex(RESP_HEADER_WIRE);
    wire.extend_from_slice(&hex(RCHUNK0));
    wire.extend_from_slice(&hex(RCHUNK1));

    let mut cursor: &[u8] = &wire;
    read_response_header(&mut cursor, &session).await.unwrap();

    let mut body = BodyChunks::new(&session.resp_key, &session.resp_iv).unwrap();
    let mut out = Vec::new();
    for _ in 0..2 {
        let mut len_buf = [0u8; 2];
        cursor.read_exact(&mut len_buf).await.unwrap();
        let chunk_len = body.decode_len(len_buf) as usize;
        let mut ct = vec![0u8; chunk_len];
        cursor.read_exact(&mut ct).await.unwrap();
        let n = body.open_chunk(&mut ct).unwrap();
        out.extend_from_slice(&ct[..n]);
    }
    assert_eq!(out, b"HTTP/1.1 200 OKHTTP/1.1 200 OK");
    assert!(cursor.is_empty());
}

/// The same wire bytes with a tampered response-header byte must fail
/// the response-header equality check, not silently relay.
#[tokio::test]
async fn test_response_header_mismatch_fails() {
    let session = Session {
        resp_header: 0x5b,
        ..fixed_session()
    };
    let wire = hex(RESP_HEADER_WIRE);
    let mut cursor: &[u8] = &wire;
    assert!(read_response_header(&mut cursor, &session).await.is_err());
}

#[test]
fn test_crc32_ieee() {
    // crc32.ChecksumIEEE("123456789") = 0xCBF43926 (classic vector).
    assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
}

#[test]
fn test_fnv1a32() {
    // fnv.New32a("hello") = 0x4f9f2cab.
    assert_eq!(fnv1a32(b"hello"), 0x4F9F_2CAB);
}

#[test]
fn test_chunk_nonce_layout() {
    let iv = [0x22; 16];
    let nonce = chunk_nonce(&iv, 0x0102);
    assert_eq!(nonce[..2], [0x01, 0x02]);
    assert_eq!(nonce[2..], [0x22; 10]);
}

#[test]
fn test_body_chunk_roundtrip() {
    let session = fixed_session();
    let mut tx = BodyChunks::new(&session.req_key, &session.req_iv).unwrap();
    let mut rx = BodyChunks::new(&session.req_key, &session.req_iv).unwrap();
    for payload in [&b"hello vmess aead"[..], &vec![0xAB; CHUNK_MAX_LEN][..]] {
        let wire = tx.seal_chunk(payload);
        let len = rx.decode_len([wire[0], wire[1]]) as usize;
        assert_eq!(len, payload.len() + GCM_TAG_LEN);
        let mut ct = wire[2..].to_vec();
        let n = rx.open_chunk(&mut ct).unwrap();
        assert_eq!(&ct[..n], payload);
    }
}

#[tokio::test]
async fn dropping_vmess_stream_closes_physical_transport() {
    let (physical, mut peer) = tokio::io::duplex(4096);
    let uuid = uuid::Uuid::parse_str(UUID).unwrap();
    let target = "93.184.216.34:53".parse().unwrap();
    let stream =
        VmessHandler::perform_handshake(uuid.as_bytes(), Box::new(physical), target, None).unwrap();

    let mut first = [0];
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        peer.read_exact(&mut first),
    )
    .await
    .expect("VMess relay must write its request header")
    .unwrap();
    drop(stream);

    let mut rest = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        peer.read_to_end(&mut rest),
    )
    .await
    .expect("dropping the VMess stream must close its physical transport")
    .unwrap();
}

#[derive(Debug, Default)]
struct RecordedUpload {
    wire: Vec<u8>,
    delivered: usize,
    flushes: usize,
}

#[derive(Debug)]
struct RecordingTransport(
    Arc<parking_lot::Mutex<RecordedUpload>>,
    Arc<tokio::sync::Notify>,
);

impl AsyncRead for RecordingTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for RecordingTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().wire.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut recording = self.0.lock();
        recording.delivered = recording.wire.len();
        recording.flushes += 1;
        self.1.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[tokio::test]
async fn upload_batches_a_queued_burst_and_flushes_when_input_goes_idle() {
    const WRITES: usize = 64;
    const WRITE_SIZE: usize = 8192;
    let payload = vec![0xa5; WRITES * WRITE_SIZE];
    let (mut client, mut relay_client) = tokio::io::duplex(payload.len());
    for write in payload.as_chunks::<WRITE_SIZE>().0 {
        client.write_all(write).await.unwrap();
    }
    let recording = Arc::new(parking_lot::Mutex::new(RecordedUpload::default()));
    let changed = Arc::new(tokio::sync::Notify::new());
    let transport = RecordingTransport(recording.clone(), changed.clone());
    let header = b"request-header";
    let relay = tokio::spawn(async move {
        vmess_relay(
            Box::new(transport),
            &mut relay_client,
            header.to_vec(),
            fixed_session(),
        )
        .await
    });
    let wire_length =
        header.len() + payload.len() + payload.len().div_ceil(CHUNK_MAX_LEN) * (2 + GCM_TAG_LEN);
    let wait_for_delivery = |length| {
        let recording = recording.clone();
        let changed = changed.clone();
        async move {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    let notified = changed.notified();
                    if recording.lock().delivered >= length {
                        break;
                    }
                    notified.await;
                }
            })
            .await
            .expect("idle VMess producer did not flush its upload");
        }
    };
    wait_for_delivery(wire_length).await;
    let idle_flushes = {
        let recording = recording.lock();
        assert!(
            recording.flushes < WRITES / 4,
            "queued burst flushed {} times",
            recording.flushes
        );
        assert_eq!(&recording.wire[..header.len()], header);
        let mut body = BodyChunks::new(&fixed_session().req_key, &fixed_session().req_iv).unwrap();
        let mut wire = &recording.wire[header.len()..recording.delivered];
        let mut decoded = Vec::new();
        while !wire.is_empty() {
            let length = body.decode_len(wire[..2].try_into().unwrap()) as usize;
            let mut chunk = wire[2..2 + length].to_vec();
            let length = body.open_chunk(&mut chunk).unwrap();
            decoded.extend_from_slice(&chunk[..length]);
            wire = &wire[2 + chunk.len()..];
        }
        assert_eq!(decoded, payload);
        recording.flushes
    };
    client.shutdown().await.unwrap();
    wait_for_delivery(wire_length + 2 + GCM_TAG_LEN).await;
    assert!(
        recording.lock().flushes > idle_flushes,
        "upload terminator was not flushed"
    );
    relay.abort();
    assert!(relay.await.unwrap_err().is_cancelled());
}

#[cfg(feature = "owned-tasks")]
#[tokio::test]
async fn runtime_shutdown_joins_vmess_relay_with_live_stream() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = listener.local_addr()?;
    let physical = TcpStream::connect(endpoint).await?;
    let (mut peer, _) = listener.accept().await?;
    let mut node = Node {
        name: "owned-vmess".into(),
        address: endpoint.to_string(),
        host: endpoint.ip().to_string(),
        port: endpoint.port(),
        outbound: honk_config::node::OutboundConfig::Vmess(honk_config::node::VmessConfig {
            uuid: Some(UUID.into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    let (registry, _) = crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        std::slice::from_ref(&node),
        1,
        1,
        1,
        true,
        None,
    )?;
    let runtime = registry.get(&node.id).unwrap();
    let uuid = uuid::Uuid::parse_str(UUID)?;
    let target = "192.0.2.1:80".parse()?;
    let stream = runtime
        .scope_tasks(async {
            VmessHandler::perform_handshake(uuid.as_bytes(), Box::new(physical), target, None)
        })
        .await?;
    let mut first = [0];
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        peer.read_exact(&mut first),
    )
    .await??;
    tokio::time::timeout(std::time::Duration::from_secs(1), registry.shutdown()).await?;
    let mut remaining_header = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        peer.read_to_end(&mut remaining_header),
    )
    .await??;
    drop(stream);
    Ok(())
}

/// End-to-end over the WebSocket transport: a mock server parses the
/// real AEAD wire format — auth ID, sealed header length, sealed header
/// (version/option/security/address) — exactly like a sing-box/Xray
/// inbound would.
#[tokio::test]
async fn test_vmess_dial_over_ws_handshake() {
    use futures_util::StreamExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

        let uuid = uuid::Uuid::parse_str(uuid_str).unwrap();
        let cmd_key = VmessHandler::derive_cmd_key(uuid.as_bytes());

        // auth_id(16) | enc_len(18) | conn_nonce(8) | enc_header(N+16);
        // the bridge may coalesce or split writes across messages.
        let mut data = Vec::new();
        let header_plain = loop {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
                .await
                .expect("message within timeout")
                .expect("stream open")
                .expect("message ok");
            data.extend_from_slice(&msg.into_data());

            if data.len() < 16 + 18 + 8 + 4 + GCM_TAG_LEN {
                continue;
            }
            let auth_id: [u8; 16] = data[..16].try_into().unwrap();
            let conn_nonce: [u8; 8] = data[34..42].try_into().unwrap();
            let extra: [&[u8]; 2] = [&auth_id, &conn_nonce];
            let len_key = kdf16(&cmd_key, KDF_SALT_HEADER_LEN_KEY, &extra);
            let len_nonce = kdf12(&cmd_key, KDF_SALT_HEADER_LEN_IV, &extra);
            let Ok(len_plain) =
                VmessHandler::open_aad(&len_key, &len_nonce, &data[16..34], &auth_id)
            else {
                continue;
            };
            let hdr_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
            if data.len() < 42 + hdr_len + GCM_TAG_LEN {
                continue;
            }
            let hdr_key = kdf16(&cmd_key, KDF_SALT_HEADER_KEY, &extra);
            let hdr_nonce = kdf12(&cmd_key, KDF_SALT_HEADER_IV, &extra);
            let plain = VmessHandler::open_aad(
                &hdr_key,
                &hdr_nonce,
                &data[42..42 + hdr_len + GCM_TAG_LEN],
                &auth_id,
            )
            .expect("header decrypts");
            break plain;
        };

        assert_eq!(header_plain[0], VMESS_VERSION);
        assert_eq!(header_plain[34], REQUEST_OPTION);
        assert_eq!(header_plain[35] & 0x0f, SECURITY_AES128_GCM);
        assert_eq!(header_plain[37], CMD_TCP);
        // port first, then ATYP + address (V2Ray WriteAddressPort).
        assert_eq!(&header_plain[38..40], &[0x00, 0x50]);
        assert_eq!(header_plain[40], addr::ATYP_VMESS.ipv4);
        assert_eq!(&header_plain[41..45], &[93, 184, 216, 34]);
        // fnv1a checksum over everything before it.
        let payload_end = header_plain.len() - 4;
        let sum = u32::from_be_bytes(header_plain[payload_end..].try_into().unwrap());
        assert_eq!(sum, fnv1a32(&header_plain[..payload_end]));
    });

    let node = Node {
        name: "vmess-ws".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        outbound: honk_config::node::OutboundConfig::Vmess(honk_config::node::VmessConfig {
            uuid: Some(uuid_str.into()),
            transport: honk_config::node::StreamTransportOptions {
                transport: "ws".into(),
                ws_path: Some("/vmess".into()),
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let _ps = VmessHandler::new()
        .dial(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// A peer that answers the request with bytes that are not a sealed
/// response header is a rejected dial: the stream must report the
/// failure, not the EOF the dropped relay half would otherwise mean.
#[tokio::test]
async fn rejected_response_header_surfaces_as_stream_error() {
    let (physical, mut peer) = tokio::io::duplex(4096);
    let uuid = uuid::Uuid::parse_str(UUID).unwrap();
    let target = "93.184.216.34:53".parse().unwrap();
    let mut stream =
        VmessHandler::perform_handshake(uuid.as_bytes(), Box::new(physical), target, None).unwrap();

    let mut first = [0];
    peer.read_exact(&mut first).await.unwrap();
    // 18 bytes: a full sealed length that does not authenticate.
    peer.write_all(&[0x5a; 18]).await.unwrap();
    drop(peer);

    let mut out = Vec::new();
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        stream.stream.read_to_end(&mut out),
    )
    .await
    .expect("the stream must settle once the relay fails")
    .expect_err("a rejected response header must not read as EOF");
    assert!(out.is_empty());
    assert!(crate::group::ScoreOutcome::from_io_error(&error).is_node_failure());
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[derive(Debug)]
struct ErrorOnEof(tokio::io::DuplexStream, io::ErrorKind);

impl AsyncRead for ErrorOnEof {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.0).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() != 0 => {
                Poll::Ready(Err(if self.1 == io::ErrorKind::ConnectionReset {
                    io::Error::from_raw_os_error(libc::ECONNRESET)
                } else {
                    self.1.into()
                }))
            }
            result => result,
        }
    }
}

impl AsyncWrite for ErrorOnEof {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn response_header_eof_and_transport_failures_keep_scope_and_cause() {
    for (prefix_len, failure) in [
        (0, None),
        (3, None),
        (0, Some(io::ErrorKind::ConnectionReset)),
        (3, Some(io::ErrorKind::ConnectionReset)),
        (0, Some(io::ErrorKind::UnexpectedEof)),
    ] {
        let kind = failure.unwrap_or(io::ErrorKind::UnexpectedEof);
        let (physical, mut peer) = tokio::io::duplex(4096);
        let physical: Box<dyn AsyncReadWrite> = if let Some(kind) = failure {
            Box::new(ErrorOnEof(physical, kind))
        } else {
            Box::new(physical)
        };
        let uuid = uuid::Uuid::parse_str(UUID).unwrap();
        let target = "93.184.216.34:53".parse().unwrap();
        let mut stream =
            VmessHandler::perform_handshake(uuid.as_bytes(), physical, target, None).unwrap();

        peer.read_exact(&mut [0]).await.unwrap();
        peer.write_all(&[0x5a; 3][..prefix_len]).await.unwrap();
        // Leave the request side open so only the response read can fail.
        peer.shutdown().await.unwrap();

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.stream.read(&mut [0; 1]),
        )
        .await
        .expect("header transport failure must settle the returned stream")
        .expect_err("an absent or partial response header must not read as clean EOF");
        assert_eq!(error.kind(), kind);
        let outcome = crate::group::ScoreOutcome::from_io_error(&error);
        if prefix_len == 0 && failure.is_none() {
            assert_eq!(outcome, crate::group::ScoreOutcome::Io(kind));
        } else {
            assert!(outcome.is_node_failure(), "{outcome:?}");
        }
        let error = anyhow::Error::new(error);
        let cause = error.root_cause().downcast_ref::<io::Error>().unwrap();
        assert_eq!(cause.kind(), kind);
        if kind == io::ErrorKind::ConnectionReset {
            assert_eq!(cause.raw_os_error(), Some(libc::ECONNRESET));
        }
    }
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn deferred_request_observation_follows_relay_write_not_stream_construction() {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};
    let events = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let captured = std::sync::Arc::clone(&events);
    let observer = FlowObserver::new(
        FlowContext {
            flow_id: uuid::Uuid::new_v4(),
            generation: 11,
            attempt_id: Some(uuid::Uuid::new_v4()),
            lookup_id: None,
            dns_purpose: "proxy_server",
        },
        std::sync::Arc::new(move |_, event| captured.lock().push(event)),
    );
    let (physical, mut peer) = tokio::io::duplex(4096);
    let uuid = uuid::Uuid::parse_str(UUID).unwrap();
    let stream = observer
        .scope(async {
            VmessHandler::perform_handshake(
                uuid.as_bytes(),
                Box::new(physical),
                "127.0.0.1:80".parse().unwrap(),
                None,
            )
            .unwrap()
        })
        .await;
    assert!(
        events.lock().is_empty(),
        "constructing a deferred relay has sent nothing"
    );
    let mut first = [0];
    peer.read_exact(&mut first).await.unwrap();
    assert!(matches!(
        events.lock().as_slice(),
        [FlowEvent::Milestone {
            milestone: crate::runtime::flow_observation::Milestone::TargetRequestSent
        }]
    ));
    drop(stream);
    let mut remaining = Vec::new();
    peer.read_to_end(&mut remaining).await.unwrap();
}
