use super::test_support::{HEADER_WIRE, fixed_session, hex};
use super::*;
use std::io;

// Byte-level regression vectors produced by running the actual
// Xray-core/sing-vmess Go code (aead/kdf.go, aead/authid.go,
// aead/encrypt.go, encoding/auth.go semantics) with these fixed inputs.
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const CMD_KEY: &str = "b50d916ac0cec067981af8e5f38a758f";
const AUTH_ID_KEY: &str = "1415ba74ca8b3d041a8f583fb4116315";
const AUTH_ID: &str = "7997d3314952dc37e0b284331b6bb2e7"; // ts=1700000000, rand=deadbeef
const HEADER_PLAIN: &str = "0122222222222222222222222222222222111111111111111111111111111111115a053300010050015db8d822aabbcc15eba2f4";
const CHUNK0: &str = "cce0f4cf6e664ef12db2501e5fc2333f0d54118144ce186c4913a9a33a";
const CHUNK1: &str = "821e7f5df60be7f0159bdf89de3bda5c55c920d471fda4d17d24ddb5fd";
const CHUNK_TERM: &str = "f25f875b48011300760c657294fca053c869";
const RESP_HEADER_WIRE: &str =
    "1ed5e218e618e8c5350363b980c93de5efa06015b5dc7a63f67ab72353ff9aa4f47a9ee044da";
const RCHUNK0: &str = "a519478d162a2f176b9d3e71216983fc910451176407bbc97aa4daccb61c4740c0";
const RCHUNK1: &str = "7baab45ea2ec0a90ad19bc5cacb263341906c9224a32ff3ce1dd65f2c0f7817120";

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

#[tokio::test]
async fn a_truncated_vmess_response_does_not_identify_a_tunneled_group_hop() {
    let complete = hex(RESP_HEADER_WIRE);
    for routed_carrier in [false, true] {
        let session = Session {
            ambiguous_header_io: routed_carrier,
            ..fixed_session()
        };
        for end in [1, complete.len() - 1] {
            let mut partial = &complete[..end];
            let error = read_response_header(&mut partial, &session)
                .await
                .unwrap_err();
            let cause = error.root_cause().downcast_ref::<io::Error>().unwrap();
            assert_eq!(cause.kind(), io::ErrorKind::UnexpectedEof);
            assert_eq!(crate::proxy::node_failure(&error), !routed_carrier);
        }
    }
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
        VmessHandler::perform_handshake(uuid.as_bytes(), Box::new(physical), target, None, false)
            .unwrap();

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
            &super::super::transport::relay_upload::pipe().1,
            &mut None,
            &mut Vec::new(),
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
            VmessHandler::perform_handshake(
                uuid.as_bytes(),
                Box::new(physical),
                target,
                None,
                false,
            )
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
        VmessHandler::perform_handshake(uuid.as_bytes(), Box::new(physical), target, None, false)
            .unwrap();

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
struct ErrorOnEof(tokio::io::DuplexStream, Option<io::Error>);

impl AsyncRead for ErrorOnEof {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.0).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() != 0 => {
                Poll::Ready(self.1.take().map_or(Ok(()), Err))
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
        let failure = failure.map(|kind| {
            if kind == io::ErrorKind::ConnectionReset {
                io::Error::from_raw_os_error(libc::ECONNRESET)
            } else {
                kind.into()
            }
        });
        let clean_eof = failure.is_none();
        let physical = Box::new(ErrorOnEof(physical, failure));
        let uuid = uuid::Uuid::parse_str(UUID).unwrap();
        let target = "93.184.216.34:53".parse().unwrap();
        let mut stream =
            VmessHandler::perform_handshake(uuid.as_bytes(), physical, target, None, false)
                .unwrap();

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
        if prefix_len == 0 && clean_eof {
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

#[tokio::test]
async fn response_chunk_length_preserves_typed_carrier_failures_after_payload() {
    use crate::group::ScoreOutcome;
    use crate::proxy::error::IntermediateTargetFailure;
    use crate::proxy::{NodeFailure, PacketRejection, TargetFailure};

    let lower_refusal = crate::SharedError::fanout(
        TargetFailure(io::Error::from(io::ErrorKind::ConnectionRefused).into()).into(),
    );
    let episode = lower_refusal.episode().unwrap();
    let intermediate = IntermediateTargetFailure::io(
        2,
        io::Error::new(io::ErrorKind::ConnectionRefused, lower_refusal.clone()),
    );
    let target = io::Error::new(io::ErrorKind::ConnectionRefused, lower_refusal);
    let node_failure = || {
        io::Error::new(
            io::ErrorKind::ConnectionReset,
            NodeFailure(io::Error::from_raw_os_error(libc::ECONNRESET).into()),
        )
    };

    for (failure, expected, length_prefix, terminal_chunk) in [
        (
            Some(intermediate),
            Some(ScoreOutcome::SharedNodeFailure(episode)),
            false,
            false,
        ),
        (Some(target), Some(ScoreOutcome::TargetFailure), true, false),
        (
            Some(node_failure()),
            Some(ScoreOutcome::NodeFailure),
            true,
            false,
        ),
        (
            Some(PacketRejection::Cancelled.into()),
            Some(ScoreOutcome::Cancelled),
            false,
            false,
        ),
        (None, None, false, false),
        (
            None,
            Some(ScoreOutcome::Io(io::ErrorKind::UnexpectedEof)),
            true,
            false,
        ),
        (
            Some(io::Error::from_raw_os_error(libc::ECONNRESET)),
            Some(ScoreOutcome::Io(io::ErrorKind::ConnectionReset)),
            false,
            false,
        ),
        (Some(node_failure()), None, false, true),
    ] {
        let kind = failure.as_ref().map(io::Error::kind);
        let (physical, mut peer) = tokio::io::duplex(4096);
        let mut stream = VmessStream::start(
            Box::new(ErrorOnEof(physical, failure)),
            hex(HEADER_WIRE),
            fixed_session(),
        )
        .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            peer.write_all(&hex(RESP_HEADER_WIRE)).await.unwrap();
            let session = fixed_session();
            let mut body = BodyChunks::new(&session.resp_key, &session.resp_iv).unwrap();
            let payload = b"HTTP/1.1 200 OK";
            peer.write_all(&body.seal_chunk(payload)).await.unwrap();
            let mut received = [0; b"HTTP/1.1 200 OK".len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, payload);

            if terminal_chunk {
                peer.write_all(&body.seal_chunk(b"")).await.unwrap();
            } else if length_prefix {
                peer.write_all(&body.seal_chunk(b"next")[..1])
                    .await
                    .unwrap();
            }
            // Keep the request side open so the lower read determines the result.
            peer.shutdown().await.unwrap();

            let result = stream.read(&mut [0; 1]).await;
            if let Some(expected) = expected {
                let error = result.expect_err("response length failure became EOF");
                assert_eq!(error.kind(), kind.unwrap_or(io::ErrorKind::UnexpectedEof));
                assert_eq!(ScoreOutcome::from_io_error(&error), expected);
            } else {
                assert_eq!(result.unwrap(), 0);
                stream.shutdown().await.unwrap();
                let mut expected = hex(HEADER_WIRE);
                let mut upload = BodyChunks::new(&session.req_key, &session.req_iv).unwrap();
                expected.extend(upload.seal_chunk(&[]));
                let mut sent = Vec::new();
                peer.read_to_end(&mut sent).await.unwrap();
                assert_eq!(sent, expected);
            }
        })
        .await
        .expect("VMess payload and terminal read must settle");
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
                false,
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

async fn read_request_header(wire: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let cmd_key = VmessHandler::derive_cmd_key(uuid::Uuid::parse_str(UUID).unwrap().as_bytes());
    let mut prefix = [0u8; 16 + 18 + 8];
    wire.read_exact(&mut prefix).await.unwrap();
    let auth_id: [u8; 16] = prefix[..16].try_into().unwrap();
    let conn_nonce: [u8; 8] = prefix[34..].try_into().unwrap();
    let extra: [&[u8]; 2] = [&auth_id, &conn_nonce];
    let len_plain = VmessHandler::open_aad(
        &kdf16(&cmd_key, KDF_SALT_HEADER_LEN_KEY, &extra),
        &kdf12(&cmd_key, KDF_SALT_HEADER_LEN_IV, &extra),
        &prefix[16..34],
        &auth_id,
    )
    .unwrap();
    let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    let mut sealed = vec![0u8; header_len + GCM_TAG_LEN];
    wire.read_exact(&mut sealed).await.unwrap();
    VmessHandler::open_aad(
        &kdf16(&cmd_key, KDF_SALT_HEADER_KEY, &extra),
        &kdf12(&cmd_key, KDF_SALT_HEADER_IV, &extra),
        &sealed,
        &auth_id,
    )
    .unwrap()
}

async fn read_first_chunk(wire: &mut (impl AsyncRead + Unpin), header: &[u8]) -> Vec<u8> {
    let mut upload = BodyChunks::new(
        header[17..33].try_into().unwrap(),
        header[1..17].try_into().unwrap(),
    )
    .unwrap();
    let mut len = [0u8; 2];
    wire.read_exact(&mut len).await.unwrap();
    let mut chunk = vec![0u8; upload.decode_len(len) as usize];
    wire.read_exact(&mut chunk).await.unwrap();
    let size = upload.open_chunk(&mut chunk).unwrap();
    chunk.truncate(size);
    chunk
}

/// A minimal AEAD server on the far end of a tunneled carrier: it opens the
/// sealed request and one body chunk, then answers with a response header
/// and one body chunk.
#[tokio::test]
async fn dial_over_relays_through_the_carrier() {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let header = read_request_header(&mut server).await;
        assert_eq!(
            &header[37..45],
            &[CMD_TCP, 0x00, 0x50, addr::ATYP_VMESS.ipv4, 93, 184, 216, 34]
        );
        let req_iv: [u8; 16] = header[1..17].try_into().unwrap();
        let req_key: [u8; 16] = header[17..33].try_into().unwrap();
        let resp_key: [u8; 16] = Sha256::digest(req_key)[..16].try_into().unwrap();
        let resp_iv: [u8; 16] = Sha256::digest(req_iv)[..16].try_into().unwrap();

        assert_eq!(read_first_chunk(&mut server, &header).await, *b"ping");

        let response = [header[33], 0, 0, 0];
        let mut reply = VmessHandler::seal_aad(
            &kdf16(&resp_key, KDF_SALT_RESP_LEN_KEY, &[]),
            &kdf12(&resp_iv, KDF_SALT_RESP_LEN_IV, &[]),
            &(response.len() as u16).to_be_bytes(),
            &[],
        );
        reply.extend(VmessHandler::seal_aad(
            &kdf16(&resp_key, KDF_SALT_RESP_KEY, &[]),
            &kdf12(&resp_iv, KDF_SALT_RESP_IV, &[]),
            &response,
            &[],
        ));
        reply.extend(
            BodyChunks::new(&resp_key, &resp_iv)
                .unwrap()
                .seal_chunk(b"pong"),
        );
        server.write_all(&reply).await.unwrap();
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).await.ok();
    });

    let mut node = Node {
        name: "vmess-tunnel".into(),
        address: "198.51.100.1:443".into(),
        host: "must-not-resolve.invalid".into(),
        port: 443,
        outbound: honk_config::node::OutboundConfig::Vmess(honk_config::node::VmessConfig {
            uuid: Some(UUID.into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let mut stream = VmessHandler::new()
        .dial_over(
            runtime,
            Box::new(client),
            "93.184.216.34:80".parse().unwrap(),
            None,
            TunnelDialOptions::new(std::time::Duration::from_secs(3)),
        )
        .await
        .unwrap();
    stream.stream.write_all(b"ping").await.unwrap();
    stream.stream.flush().await.unwrap();
    let mut reply = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.stream.read_exact(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&reply, b"pong");
    drop(stream);
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

fn chain_vmess_node() -> Node {
    crate::test_support::node(
        "vmess",
        "192.0.2.1",
        1080,
        honk_config::node::OutboundConfig::Vmess(honk_config::node::VmessConfig {
            uuid: Some(UUID.into()),
            ..Default::default()
        }),
    )
}

async fn accept_socks_for_vmess(listener: &tokio::net::TcpListener) -> TcpStream {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await.unwrap();
    let mut request = [0; 10];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request, [5, 1, 0, 1, 192, 0, 2, 1, 4, 56]);
    stream
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    stream
}

#[tokio::test]
async fn vmess_header_reset_after_open_respects_configured_chain_ownership() {
    use crate::group::{OwnedTarget, RoutedTarget, ScoreOutcome};
    use crate::proxy::{DialFailureScope, ProxyRegistry, dial_failure_scope};
    use crate::runtime::OutboundRuntimeRegistry;
    use crate::test_support::{assert_score_failure_scope, chain, socks5};
    use honk_config::group_graph::{Composed, compose};
    use std::time::Duration;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = socks5("front", "127.0.0.1", listener.local_addr().unwrap().port());
    let vmess = chain_vmess_node();
    let configured = chain(&[&front, &vmess]);
    let Composed::Routed(route) = compose(configured.id, &[front.id, vmess.id], [vmess.id]) else {
        panic!("expected a route with the same physical hops as the chain");
    };
    let standalone = OwnedTarget::node(configured.clone());
    let mut routed = OwnedTarget::node(configured.clone());
    routed.route = Some(Box::new(RoutedTarget {
        route,
        hop_names: [front.name.clone(), vmess.name.clone()].into(),
    }));
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[configured, front, vmess]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();

    for (owned, expected, projected, hard_failures) in [
        (
            &standalone,
            ScoreOutcome::NodeFailure,
            ScoreOutcome::NodeFailure,
            1,
        ),
        (
            &routed,
            ScoreOutcome::Io(io::ErrorKind::ConnectionReset),
            ScoreOutcome::RouteFailure,
            0,
        ),
    ] {
        let client = async {
            let mut stream = registry
                .dial_ref(
                    Arc::clone(&generation),
                    owned.dial_ref(),
                    "127.0.0.1:8080".parse().unwrap(),
                    None,
                    Duration::from_secs(2),
                )
                .await
                .unwrap();
            stream.stream.write_all(b"ping").await.unwrap();
            stream.stream.read(&mut [0]).await.unwrap_err()
        };
        let peer = async {
            let mut stream = accept_socks_for_vmess(&listener).await;
            let header = read_request_header(&mut stream).await;
            assert_eq!(
                &header[37..45],
                &[CMD_TCP, 31, 144, addr::ATYP_VMESS.ipv4, 127, 0, 0, 1]
            );
            assert_eq!(read_first_chunk(&mut stream, &header).await, *b"ping");
            stream.set_zero_linger().unwrap();
        };
        let (error, ()) =
            tokio::time::timeout(Duration::from_secs(8), async { tokio::join!(client, peer) })
                .await
                .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(dial_failure_scope(&error), DialFailureScope::Unattributed);
        let outcome = ScoreOutcome::from_io_error(&error);
        assert_eq!(outcome, expected);
        let score = owned.score_failure(outcome, &error);
        assert_eq!(score, projected);
        assert_score_failure_scope(&owned.node, &[score], true, hard_failures, hard_failures);
        let error = anyhow::Error::new(error);
        let cause = error.root_cause().downcast_ref::<io::Error>().unwrap();
        assert_eq!(cause.raw_os_error(), Some(libc::ECONNRESET));
    }
    generation.shutdown().await;
}

#[tokio::test]
async fn three_hop_vmess_attributes_a_bad_header_but_not_a_socks_carrier_reset() {
    use crate::group::{OwnedTarget, RoutedTarget, ScoreOutcome};
    use crate::proxy::{DialFailureScope, ProxyRegistry, dial_failure_scope, failed_hop};
    use crate::runtime::OutboundRuntimeRegistry;
    use crate::test_support::{TCP_TARGET, socks5};
    use honk_config::group_graph::{Composed, compose};
    use std::time::Duration;
    use tokio::net::TcpListener;

    for corrupt in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = socks5("front", "127.0.0.1", listener.local_addr().unwrap().port());
        let mid = chain_vmess_node();
        let exit = socks5("exit", "192.0.2.2", 1081);
        let Composed::Routed(route) = compose(front.id, &[front.id], [mid.id, exit.id]) else {
            panic!("expected three hops");
        };
        let mut owned = OwnedTarget::node(front.clone());
        owned.route = Some(Box::new(RoutedTarget {
            route,
            hop_names: [front.name.clone(), mid.name.clone(), exit.name.clone()].into(),
        }));
        let middle_id = mid.id;
        let generation = Arc::new(OutboundRuntimeRegistry::build(&[front, mid, exit]).unwrap());
        let registry = ProxyRegistry::default_resolver().unwrap();
        let server = async {
            let mut stream = accept_socks_for_vmess(&listener).await;

            let header = read_request_header(&mut stream).await;
            assert_eq!(
                &header[37..45],
                &[CMD_TCP, 4, 57, addr::ATYP_VMESS.ipv4, 192, 0, 2, 2]
            );
            // The final SOCKS handler is awaiting its greeting reply, not writing.
            assert_eq!(read_first_chunk(&mut stream, &header).await, [5, 1, 0]);
            if corrupt {
                let resp_key = Sha256::digest(&header[17..33]);
                let resp_iv = Sha256::digest(&header[1..17]);
                let mut len = VmessHandler::seal_aad(
                    &kdf16(&resp_key[..16], KDF_SALT_RESP_LEN_KEY, &[]),
                    &kdf12(&resp_iv[..16], KDF_SALT_RESP_LEN_IV, &[]),
                    &4u16.to_be_bytes(),
                    &[],
                );
                len[2] ^= 1;
                stream.write_all(&len).await.unwrap();
            } else {
                stream.set_zero_linger().unwrap();
            }
        };
        let dial = registry.dial_ref(
            Arc::clone(&generation),
            owned.dial_ref(),
            TCP_TARGET.parse().unwrap(),
            None,
            Duration::from_secs(2),
        );
        let (result, ()) =
            tokio::time::timeout(Duration::from_secs(8), async { tokio::join!(dial, server) })
                .await
                .unwrap();
        let error = result.unwrap_err();
        if corrupt {
            assert_eq!(dial_failure_scope(error.as_ref()), DialFailureScope::Hop(1));
            let located = failed_hop(&error).unwrap();
            assert_eq!((located.hop, located.node), (1, middle_id));
            assert_eq!(owned.failure_owner(&error), Some(middle_id));
            assert!(ScoreOutcome::from_error(&error).is_node_failure());
        } else {
            assert_eq!(
                dial_failure_scope(error.as_ref()),
                DialFailureScope::Unattributed
            );
            assert_eq!(owned.failure_owner(&error), None);
            let cause = error.root_cause().downcast_ref::<io::Error>().unwrap();
            assert_eq!(cause.raw_os_error(), Some(libc::ECONNRESET));
            assert!(!ScoreOutcome::from_error(&error).is_node_failure());
        }
        generation.shutdown().await;
    }
}

mod websocket;
