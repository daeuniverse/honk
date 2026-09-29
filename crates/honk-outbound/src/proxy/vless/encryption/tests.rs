use super::*;

struct DirectReader<'a>(&'a mut EncryptedStream);

impl AsyncRead for DirectReader<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().0.poll_direct_read(cx, buf)
    }
}

#[test]
fn raw_context_derive_matches_blake3_for_utf8_context() {
    let context = b"VLESS";
    let material = b"shared secret";
    assert_eq!(
        derive_key(context, material),
        blake3::derive_key(std::str::from_utf8(context).unwrap(), material)
    );
}

#[test]
fn parses_x25519_config_and_padding() {
    let key = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let config = ClientConfig::parse(&format!(
        "mlkem768x25519plus.xorpub.0rtt.100-111-1111.75-0-111.50-0-3333.{key}"
    ))
    .unwrap();
    assert_eq!(config.auth_keys.len(), 1);
    assert_eq!(config.mode, XorMode::XorPub);
    assert!(config.allow_0rtt);
    assert_eq!(
        config.padding_lengths,
        vec![
            PaddingSpec {
                probability: 100,
                min: 111,
                max: 1111
            },
            PaddingSpec {
                probability: 50,
                min: 0,
                max: 3333
            }
        ]
    );
    assert_eq!(
        config.padding_gaps,
        vec![PaddingSpec {
            probability: 75,
            min: 0,
            max: 111
        }]
    );
}

#[test]
fn rejects_missing_or_malformed_keys_and_padding() {
    assert!(ClientConfig::parse("mlkem768x25519plus.native.1rtt").is_err());
    assert!(ClientConfig::parse("mlkem768x25519plus.native.1rtt.not-a-key").is_err());
    let key = URL_SAFE_NO_PAD.encode([7u8; 32]);
    assert!(ClientConfig::parse(&format!("mlkem768x25519plus.native.1rtt.50-1-2.{key}")).is_err());
}

#[test]
fn xor_stream_round_trips_across_segments() {
    let material = [9u8; 96];
    let iv = [4u8; 16];
    let mut encrypted = [1u8; 97];
    let original = encrypted;
    let mut sender = AesCtr::new(&material, &iv);
    sender.apply(&mut encrypted[..31]);
    sender.apply(&mut encrypted[31..]);
    let mut receiver = AesCtr::new(&material, &iv);
    receiver.apply(&mut encrypted);
    assert_eq!(encrypted, original);
}

#[tokio::test]
async fn frame_codec_round_trips_large_payload() {
    let key = vec![11u8; 96];
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut client = EncryptedStream::new(
        Box::new(client_io),
        key.clone(),
        true,
        StreamAead::new(b"client", &key, true).unwrap(),
        Some(StreamAead::new(b"server", &key, true).unwrap()),
        None,
        None,
        None,
        PeerInit::Ready,
        None,
        false,
    );
    let mut server = EncryptedStream::new(
        Box::new(server_io),
        key.clone(),
        true,
        StreamAead::new(b"server", &key, true).unwrap(),
        Some(StreamAead::new(b"client", &key, true).unwrap()),
        None,
        None,
        None,
        PeerInit::Ready,
        None,
        false,
    );
    let payload = vec![0x5a; MAX_FRAME_PLAINTEXT * 2 + 321];
    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let mut received = vec![0; expected.len()];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        server.write_all(b"reply").await.unwrap();
        server.shutdown().await.unwrap();
    });
    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"reply");
    server_task.await.unwrap();
}

#[tokio::test]
async fn direct_drains_authenticated_plaintext_and_keeps_encrypted_writes() {
    let key = vec![13_u8; 96];
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let mut server_recv = StreamAead::new(b"client", &key, true).unwrap();
    let mut stream = EncryptedStream::new(
        Box::new(client_io),
        key.clone(),
        true,
        StreamAead::new(b"client", &key, true).unwrap(),
        Some(StreamAead::new(b"server", &key, true).unwrap()),
        None,
        None,
        None,
        PeerInit::Ready,
        None,
        false,
    );
    stream.read_plaintext = b"authenticated-".to_vec();
    server_io.write_all(b"outer").await.unwrap();
    server_io.shutdown().await.unwrap();

    let mut plaintext = Vec::new();
    DirectReader(&mut stream)
        .read_to_end(&mut plaintext)
        .await
        .unwrap();
    assert_eq!(plaintext, b"authenticated-outer");

    stream.write_all(b"uplink").await.unwrap();
    let mut header = [0_u8; FRAME_HEADER_LEN];
    server_io.read_exact(&mut header).await.unwrap();
    assert_eq!(header, [23, 3, 3, 0, 22]);
    let mut body = vec![0_u8; 22];
    server_io.read_exact(&mut body).await.unwrap();
    let length = server_recv.open(&mut body, &header).unwrap();
    assert_eq!(&body[..length], b"uplink");
}

#[tokio::test]
async fn direct_random_xor_continues_across_partial_headers() {
    let key = vec![17_u8; 96];
    let iv = [19_u8; IV_LEN];
    let mut sender = AesCtr::new(&key, &iv);
    let mut receiver = AesCtr::new(&key, &iv);

    let prior_plain = [23, 3, 3, 0, 17];
    let mut prior_wire = prior_plain;
    sender.apply(&mut prior_wire);
    receiver.apply(&mut prior_wire);
    assert_eq!(prior_wire, prior_plain);

    let mut plaintext = Vec::new();
    let mut wire = Vec::new();
    for body in [b"a".repeat(17), b"b".repeat(19)] {
        let mut header = [23, 3, 3, 0, body.len() as u8];
        plaintext.extend_from_slice(&header);
        plaintext.extend_from_slice(&body);
        sender.apply(&mut header);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&body);
    }

    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let mut stream = EncryptedStream::new(
        Box::new(client_io),
        key.clone(),
        true,
        StreamAead::new(b"client", &key, true).unwrap(),
        Some(StreamAead::new(b"server", &key, true).unwrap()),
        None,
        Some(receiver),
        None,
        PeerInit::Ready,
        None,
        true,
    );
    server_io.write_all(&wire).await.unwrap();
    server_io.shutdown().await.unwrap();

    let mut output = Vec::new();
    let mut reader = DirectReader(&mut stream);
    loop {
        let mut byte = [0_u8; 1];
        if reader.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        output.push(byte[0]);
    }

    assert_eq!(output, plaintext);
}

struct DirectWriter<'a>(&'a mut EncryptedStream);

impl AsyncWrite for DirectWriter<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().0.poll_direct_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_shutdown(cx)
    }
}

fn ready_stream(inner: tokio::io::DuplexStream, send_xor: Option<AesCtr>) -> EncryptedStream {
    let key = vec![23_u8; 96];
    EncryptedStream::new(
        Box::new(inner),
        key.clone(),
        true,
        StreamAead::new(b"client", &key, true).unwrap(),
        Some(StreamAead::new(b"server", &key, true).unwrap()),
        send_xor,
        None,
        None,
        PeerInit::Ready,
        None,
        false,
    )
}

#[tokio::test]
async fn native_direct_write_passes_bytes_through_unframed() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    let mut stream = ready_stream(client_io, None);
    DirectWriter(&mut stream)
        .write_all(b"raw-inner-tls")
        .await
        .unwrap();
    DirectWriter(&mut stream).shutdown().await.unwrap();
    let mut received = Vec::new();
    server_io.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"raw-inner-tls");
    assert_eq!(stream.direct_wire.capacity(), 0);
}

/// Xray `XorConn.Write` skips any body whose plaintext header starts
/// 23,3,3 — even an invalid length — and skips nothing after other types.
#[tokio::test]
async fn random_direct_write_xors_headers_exactly_once_across_partial_writes() {
    let key = vec![17_u8; 96];
    let iv = [29_u8; IV_LEN];
    let mut plaintext = vec![23, 3, 3, 0, 5];
    plaintext.extend_from_slice(b"short");
    plaintext.extend_from_slice(&[23, 3, 3, 0, 17]);
    plaintext.extend_from_slice(&[0x42; 17]);
    plaintext.extend_from_slice(&[22, 3, 3, 0, 3]);
    plaintext.extend_from_slice(&[23, 3, 3, 0, 0]);
    let mut expected = plaintext.clone();
    let mut oracle = AesCtr::new(&key, &iv);
    for range in [0..5, 10..15, 32..37, 37..42] {
        oracle.apply(&mut expected[range]);
    }

    // A 3-byte pipe makes the outer writer accept short writes and return
    // Pending, so every caller retry goes through the pending-wire resend.
    let (client_io, mut server_io) = tokio::io::duplex(3);
    let mut stream = ready_stream(client_io, Some(AesCtr::new(&key, &iv)));
    let write = async {
        for chunk in plaintext.chunks(7) {
            DirectWriter(&mut stream).write_all(chunk).await.unwrap();
        }
        DirectWriter(&mut stream).shutdown().await.unwrap();
    };
    let mut received = Vec::new();
    let read = server_io.read_to_end(&mut received);
    let ((), read) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(write, read)
    })
    .await
    .expect("Direct write must finish every resend");
    read.unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn random_direct_large_write_keeps_bounded_chunks_and_xor_state() {
    let key = vec![17_u8; 96];
    let iv = [29_u8; IV_LEN];
    let mut plaintext = vec![23, 3, 3, 0x23, 0x28];
    plaintext.extend_from_slice(&[0x42; 9000]);
    plaintext.extend_from_slice(&[23, 3, 3, 0x23, 0x28]);
    plaintext.extend_from_slice(&[0x43; 9000]);
    let mut expected = plaintext.clone();
    let mut oracle = AesCtr::new(&key, &iv);
    oracle.apply(&mut expected[..5]);
    oracle.apply(&mut expected[9005..9010]);

    let (client_io, mut server_io) = tokio::io::duplex(7);
    let mut stream = ready_stream(client_io, Some(AesCtr::new(&key, &iv)));
    let write = async {
        let mut offset = 0;
        while offset < plaintext.len() {
            let written = DirectWriter(&mut stream)
                .write(&plaintext[offset..])
                .await
                .unwrap();
            assert!((1..=MAX_FRAME_PLAINTEXT).contains(&written));
            offset += written;
        }
        DirectWriter(&mut stream).shutdown().await.unwrap();
    };
    let mut received = Vec::new();
    let read = server_io.read_to_end(&mut received);
    let ((), read) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(write, read)
    })
    .await
    .expect("large Direct write did not finish");
    read.unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn direct_write_refuses_before_the_first_frame() {
    let (client_io, _server_io) = tokio::io::duplex(4096);
    let mut stream = ready_stream(client_io, None);
    stream.prewrite = Some(b"0-rtt-prologue".to_vec());
    let error = DirectWriter(&mut stream)
        .write_all(b"raw")
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
#[ignore = "requires HONK_VLESS_ENCRYPTION_SERVER and an Xray VLESS Encryption server"]
async fn xray_interop_covers_1rtt_then_0rtt() {
    use honk_config::node::Node;

    use crate::proxy::TcpOutbound as _;

    let server: std::net::SocketAddr = std::env::var("HONK_VLESS_ENCRYPTION_SERVER")
        .expect("HONK_VLESS_ENCRYPTION_SERVER")
        .parse()
        .unwrap();
    let target: std::net::SocketAddr = std::env::var("HONK_VLESS_ENCRYPTION_TARGET")
        .expect("HONK_VLESS_ENCRYPTION_TARGET")
        .parse()
        .unwrap();
    let encryption =
        std::env::var("HONK_VLESS_ENCRYPTION_CONFIG").expect("HONK_VLESS_ENCRYPTION_CONFIG");
    let node = Node {
        name: "xray-vless-encryption".into(),
        address: server.to_string(),
        host: server.ip().to_string(),
        port: server.port(),
        outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3".into()),
            encryption: Some(encryption),
            ..Default::default()
        }),
        ..Default::default()
    };
    let handler = crate::proxy::vless::VLessHandler::new();
    for payload in [b"first-1rtt".as_slice(), b"second-0rtt".as_slice()] {
        let mut stream = tokio::time::timeout(
            Duration::from_secs(10),
            handler.dial(&node, target, None, Duration::from_secs(3)),
        )
        .await
        .expect("VLESS Encryption dial timed out")
        .unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(10), async {
            stream.stream.write_all(payload).await?;
            stream.stream.flush().await?;
            let mut echoed = vec![0; payload.len()];
            stream.stream.read_exact(&mut echoed).await?;
            Ok::<_, io::Error>(echoed)
        })
        .await
        .expect("VLESS Encryption relay timed out")
        .unwrap();
        assert_eq!(echoed, payload);
    }
}
