use tokio::io::AsyncRead as _;

use super::*;

/// AsyncRead yielding at most `chunk` bytes per poll, to force frame
/// headers and UUID detection across read boundaries.
struct ChunkedReader {
    data: std::collections::VecDeque<u8>,
    chunk: usize,
}

impl tokio::io::AsyncRead for ChunkedReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let n = self.chunk.min(buf.remaining()).min(self.data.len());
        let (front, _) = self.data.as_slices();
        buf.put_slice(&front[..n]);
        self.data.drain(..n);
        std::task::Poll::Ready(Ok(()))
    }
}

impl DirectIo for ChunkedReader {}

struct SegmentedReader {
    segments: std::collections::VecDeque<std::collections::VecDeque<u8>>,
}

impl tokio::io::AsyncRead for SegmentedReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        while self
            .segments
            .front()
            .is_some_and(|segment| segment.is_empty())
        {
            self.segments.pop_front();
        }
        let Some(segment) = self.segments.front_mut() else {
            return std::task::Poll::Ready(Ok(()));
        };
        let count = segment.len().min(buf.remaining());
        let (front, _) = segment.as_slices();
        buf.put_slice(&front[..count]);
        segment.drain(..count);
        std::task::Poll::Ready(Ok(()))
    }
}

impl DirectIo for SegmentedReader {}

struct DirectSwitchIo {
    prefix: std::collections::VecDeque<u8>,
    raw: TcpStream,
    outer_writes: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncRead for DirectSwitchIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.prefix.is_empty() {
            return std::pin::Pin::new(&mut self.raw).poll_read(cx, buf);
        }
        let count = self.prefix.len().min(buf.remaining());
        let (front, _) = self.prefix.as_slices();
        buf.put_slice(&front[..count]);
        self.prefix.drain(..count);
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for DirectSwitchIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.outer_writes.lock().extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl DirectIo for DirectSwitchIo {
    fn poll_direct_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Option<std::task::Poll<std::io::Result<()>>> {
        Some(std::pin::Pin::new(&mut self.get_mut().raw).poll_read(cx, buf))
    }
}

fn vision_frame(command: u8, content: &[u8], padding: usize) -> Vec<u8> {
    let mut frame = vec![
        command,
        (content.len() >> 8) as u8,
        content.len() as u8,
        (padding >> 8) as u8,
        padding as u8,
    ];
    frame.extend_from_slice(content);
    frame.extend(std::iter::repeat_n(0u8, padding));
    frame
}

async fn unpad_all(uuid: [u8; 16], data: &[u8], chunk: usize) -> Vec<u8> {
    let reader = ChunkedReader {
        data: data.iter().copied().collect(),
        chunk,
    };
    let mut stream = VisionStream::new(reader, uuid);
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn vision_unpad_frames_then_raw_tail() {
    let uuid = [7u8; 16];
    let mut data = uuid.to_vec();
    data.extend(vision_frame(0, b"hello", 3));
    data.extend(vision_frame(0, b"world", 0));
    data.extend(vision_frame(VISION_COMMAND_END, b"!", 2));
    data.extend_from_slice(b"RAW-TAIL");
    for chunk in [1usize, 3, 7, 1024] {
        assert_eq!(
            unpad_all(uuid, &data, chunk).await,
            b"helloworld!RAW-TAIL",
            "chunk={chunk}"
        );
    }
}

#[tokio::test]
async fn vision_unpad_direct_command_switches_to_raw() {
    let uuid = [9u8; 16];
    let mut data = uuid.to_vec();
    data.extend(vision_frame(VISION_COMMAND_DIRECT, b"abc", 1));
    data.extend_from_slice(b"rest-is-raw");
    for chunk in [2usize, 1024] {
        assert_eq!(
            unpad_all(uuid, &data, chunk).await,
            b"abcrest-is-raw",
            "chunk={chunk}"
        );
    }
}

#[tokio::test]
async fn vision_one_byte_destination_buffers_preserve_payload() {
    let uuid = [3_u8; 16];
    let mut data = uuid.to_vec();
    data.extend(vision_frame(0, b"first", 4));
    data.extend(vision_frame(0, b"", 0));
    data.extend(vision_frame(VISION_COMMAND_END, b"second", 2));
    data.extend_from_slice(b"-raw");
    let reader = ChunkedReader {
        data: data.into(),
        chunk: 8192,
    };
    let mut stream = VisionStream::new(reader, uuid);
    let mut output = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let size = stream.read(&mut byte).await.unwrap();
        if size == 0 {
            break;
        }
        assert_eq!(size, 1);
        output.push(byte[0]);
    }
    assert_eq!(output, b"firstsecond-raw");
}

#[tokio::test]
async fn vision_accepts_every_source_frame_boundary() {
    let uuid = [4_u8; 16];
    let mut data = uuid.to_vec();
    data.extend(vision_frame(0, b"alpha", 3));
    data.extend(vision_frame(0, b"", 2));
    data.extend(vision_frame(VISION_COMMAND_END, b"omega", 0));
    data.extend_from_slice(b"-tail");

    for boundary in 0..=data.len() {
        let reader = SegmentedReader {
            segments: vec![
                data[..boundary].iter().copied().collect(),
                data[boundary..].iter().copied().collect(),
            ]
            .into(),
        };
        let mut stream = VisionStream::new(reader, uuid);
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"alphaomega-tail", "boundary={boundary}");
    }
}

#[tokio::test]
async fn vision_truncated_detected_frame_ends_cleanly() {
    let uuid = [5_u8; 16];
    let mut truncated_content = uuid.to_vec();
    truncated_content.extend_from_slice(&[0, 0, 5, 0, 0]);
    truncated_content.extend_from_slice(b"ab");
    assert_eq!(unpad_all(uuid, &truncated_content, 2).await, b"ab");

    let mut truncated_padding = uuid.to_vec();
    truncated_padding.extend_from_slice(&[0, 0, 3, 0, 5]);
    truncated_padding.extend_from_slice(b"abc\0\0");
    assert_eq!(unpad_all(uuid, &truncated_padding, 3).await, b"abc");
}

#[tokio::test]
async fn vision_sub_probe_size_streams_pass_through_raw() {
    let uuid = [6_u8; 16];
    let mut source = uuid.to_vec();
    source.extend_from_slice(&[0, 0, 0, 0]);
    for length in 0..21 {
        assert_eq!(
            unpad_all(uuid, &source[..length], 1).await,
            source[..length],
            "length={length}"
        );
    }
}

#[tokio::test]
async fn vision_downstream_direct_keeps_uplink_framing_on_outer_writer() {
    let uuid = [8_u8; 16];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"raw-tail").await.unwrap();
    });
    let raw = TcpStream::connect(address).await.unwrap();
    let mut prefix = uuid.to_vec();
    prefix.extend(vision_frame(VISION_COMMAND_DIRECT, b"framed-", 1));
    prefix.extend_from_slice(b"buffered-");
    let outer_writes = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let io = DirectSwitchIo {
        prefix: prefix.into(),
        raw,
        outer_writes: std::sync::Arc::clone(&outer_writes),
    };
    let mut stream = VisionStream::new(io, uuid);
    let mut output = Vec::new();
    stream.read_to_end(&mut output).await.unwrap();
    assert_eq!(output, b"framed-buffered-raw-tail");

    // Downstream Direct never switches the uplink: non-TLS payload ends its
    // padding with End and then stays on the outer writer.
    stream.write_all(b"outer-uplink").await.unwrap();
    stream.write_all(b"-plain").await.unwrap();
    let writes = std::mem::take(&mut *outer_writes.lock());
    assert_eq!(writes[..3], [VISION_COMMAND_END, 0, 12]);
    let padding = u16::from_be_bytes([writes[3], writes[4]]) as usize;
    assert!(padding < 256);
    assert_eq!(&writes[5..17], b"outer-uplink");
    assert!(writes[17..17 + padding].iter().all(|byte| *byte == 0));
    assert_eq!(&writes[17 + padding..], b"-plain");
    server.await.unwrap();
}

#[derive(Debug)]
struct TlsRecordCapture {
    tcp: std::net::TcpStream,
    received: Vec<u8>,
}

impl std::io::Read for TlsRecordCapture {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = buf.len().min(3);
        let count = std::io::Read::read(&mut self.tcp, &mut buf[..count])?;
        self.received.extend_from_slice(&buf[..count]);
        Ok(count)
    }
}

impl std::io::Write for TlsRecordCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.tcp, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.tcp)
    }
}

/// Reads one uplink Vision frame through the outer session and checks that
/// it, together with `prefix`, arrived as exactly one TLS record.
fn read_uplink_frame(
    tls: &mut boring::ssl::SslStream<TlsRecordCapture>,
    prefix: &[u8],
) -> (u8, Vec<u8>, usize) {
    use std::io::Read as _;

    let mut head = vec![0; prefix.len() + 5];
    tls.read_exact(&mut head).unwrap();
    assert_eq!(&head[..prefix.len()], prefix);
    let head = &head[prefix.len()..];
    let content_len = usize::from(u16::from_be_bytes([head[1], head[2]]));
    let padding = usize::from(u16::from_be_bytes([head[3], head[4]]));
    let mut body = vec![0; content_len + padding];
    tls.read_exact(&mut body).unwrap();
    assert!(body[content_len..].iter().all(|byte| *byte == 0));
    let wire = &tls.get_ref().received;
    assert_eq!(wire.get(..3), Some([23, 3, 3].as_slice()));
    let length = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    assert_eq!(wire.len(), 5 + length, "one frame must be one TLS record");
    assert_eq!(length, prefix.len() + 5 + content_len + padding + 1 + 16);
    tls.get_mut().received.clear();
    body.truncate(content_len);
    (head[0], body, padding)
}

fn tls_record(record_type: u8, content: &[u8]) -> Vec<u8> {
    let mut record = vec![record_type, 3, 3];
    record.extend_from_slice(&(content.len() as u16).to_be_bytes());
    record.extend_from_slice(content);
    record
}

/// A TLS 1.3 ServerHello selecting TLS_AES_128_GCM_SHA256.
fn tls13_server_hello() -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&[0x13, 0x01, 0]);
    body.extend_from_slice(&[0, 6, 0x00, 0x2b, 0x00, 0x02, 3, 4]);
    let mut message = vec![2, 0, 0, body.len() as u8];
    message.extend_from_slice(&body);
    tls_record(22, &message)
}

/// A real rustls TLS 1.3 ClientHello, the first record an inner client sends.
fn inner_client_hello() -> Vec<u8> {
    use tokio_rustls::rustls;

    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    assert_eq!((hello[0], hello[5]), (22, 1));
    hello
}

/// Accepts one outer TLS 1.3 session on loopback and runs `script` on it in
/// its own thread; the script's panics surface through the returned handle.
fn spawn_outer_tls_server(
    script: impl FnOnce(boring::ssl::SslStream<TlsRecordCapture>) + Send + 'static,
) -> (u16, std::thread::JoinHandle<()>) {
    use boring::pkey::PKey;
    use boring::ssl::{SslAcceptor, SslMethod, SslVersion};
    use boring::x509::X509;

    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor
            .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
            .unwrap();
        acceptor
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        let acceptor = acceptor.build();
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut tls = acceptor
            .accept(TlsRecordCapture {
                tcp,
                received: Vec::new(),
            })
            .unwrap();
        tls.get_mut().received.clear();
        script(tls);
    });
    (port, server)
}

/// A Vision node dialing the loopback port of [`spawn_outer_tls_server`].
fn vision_node(uuid: &str, port: u16) -> Node {
    let mut node = vless_node(uuid);
    node.address = format!("127.0.0.1:{port}");
    node.host = "127.0.0.1".into();
    node.port = port;
    node.vless_mut().unwrap().flow = Some("xtls-rprx-vision".into());
    let tls = node.tls_mut().unwrap();
    tls.enabled = true;
    tls.skip_cert_verify = true;
    tls.sni = Some("localhost".into());
    node
}

/// Reads the dial's VLESS request and the empty long-padded frame that
/// shares its record.
fn read_vision_request(tls: &mut boring::ssl::SslStream<TlsRecordCapture>, uuid: [u8; 16]) {
    let mut request = vec![0];
    request.extend_from_slice(&uuid);
    request.extend_from_slice(b"\x12\x0a\x10xtls-rprx-vision\x01\x01\xbb\x01\x7f\x00\x00\x01");
    request.extend_from_slice(&uuid);
    let (command, content, padding) = read_uplink_frame(tls, &request);
    assert_eq!((command, content.len()), (0, 0));
    assert!((900..1400).contains(&padding));
}

/// Takes the first Vision frame off `wire`: `(command, content, padding, rest)`.
fn take_vision_frame(wire: &[u8]) -> (u8, &[u8], usize, &[u8]) {
    assert!(wire.len() >= 5, "truncated Vision frame header");
    let content = usize::from(u16::from_be_bytes([wire[1], wire[2]]));
    let padding = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    let end = 5 + content + padding;
    assert!(wire.len() >= end, "truncated Vision frame");
    assert!(wire[5 + content..end].iter().all(|byte| *byte == 0));
    (wire[0], &wire[5..5 + content], padding, &wire[end..])
}

/// The whole uplink contract against a real outer TLS 1.3 server: the
/// request shares a record with an empty long-padded frame, the inner
/// ClientHello is padded, the first application record carries Direct, and
/// afterwards the raw socket carries exactly the payload — no KeyUpdate
/// acknowledgement, alert or close_notify from the dormant outer session.
#[tokio::test]
async fn vision_uplink_pads_tls_then_switches_to_raw_tcp() {
    use foreign_types::ForeignTypeRef as _;

    let uuid = [5u8; 16];
    let inner_hello = inner_client_hello();
    let app_record = tls_record(23, &[0x33; 64]);
    let server_hello = tls13_server_hello();

    let expected_hello = inner_hello.clone();
    let expected_app = app_record.clone();
    let downlink_hello = server_hello.clone();
    let (port, server) = spawn_outer_tls_server(move |mut tls| {
        use std::io::{Read, Write};

        read_vision_request(&mut tls, uuid);

        let (command, content, padding) = read_uplink_frame(&mut tls, &[]);
        assert_eq!((command, &content), (0, &expected_hello));
        assert!(content.len() < 900);
        assert!((900..1400).contains(&(content.len() + padding)));

        let mut downlink = vec![0, 0];
        downlink.extend_from_slice(&uuid);
        downlink.extend(vision_frame(0, &downlink_hello, 3));
        tls.write_all(&downlink).unwrap();
        tls.flush().unwrap();

        let (command, content, _) = read_uplink_frame(&mut tls, &[]);
        assert_eq!((command, &content), (VISION_COMMAND_DIRECT, &expected_app));

        // The downlink is still TLS: request a KeyUpdate the client must
        // acknowledge on a write half it no longer uses.
        unsafe {
            assert_eq!(
                boring_sys::SSL_key_update(
                    tls.ssl().as_ptr(),
                    boring_sys::SSL_KEY_UPDATE_REQUESTED
                ),
                1
            );
        }
        tls.write_all(&vision_frame(0, b"after-key-update", 1))
            .unwrap();
        tls.flush().unwrap();
        let mut raw = [0; 10];
        tls.get_mut().tcp.read_exact(&mut raw).unwrap();
        assert_eq!(&raw, b"raw-uplink");

        // A record the client cannot authenticate makes BoringSSL raise a
        // fatal alert, which must not reach the raw uplink either.
        let mut forged = vec![23, 3, 3, 0, 32];
        forged.extend_from_slice(&[0xaa; 32]);
        tls.get_mut().tcp.write_all(&forged).unwrap();
        let mut rest = Vec::new();
        tls.get_mut().tcp.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"after-alert");
    });

    let node = vision_node("05050505-0505-0505-0505-050505050505", port);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut proxy = VLessHandler::new()
            .dial(
                &node,
                "127.0.0.1:443".parse().unwrap(),
                None,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap()
            .stream;
        proxy.write_all(&inner_hello).await.unwrap();
        proxy.flush().await.unwrap();
        let mut hello = vec![0; server_hello.len()];
        proxy.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, server_hello);

        proxy.write_all(&app_record).await.unwrap();
        proxy.flush().await.unwrap();
        let mut after = [0; 16];
        proxy.read_exact(&mut after).await.unwrap();
        assert_eq!(&after, b"after-key-update");
        proxy.write_all(b"raw-uplink").await.unwrap();
        proxy.flush().await.unwrap();

        assert!(proxy.read(&mut [0; 64]).await.is_err());
        proxy.write_all(b"after-alert").await.unwrap();
        proxy.shutdown().await.unwrap();
    })
    .await
    .unwrap();
    server.join().unwrap();
}

/// Vision over the real Encryption codec: the uplink's Direct command travels
/// in an AEAD frame and every later byte is a raw record. In random mode only
/// record headers are XORed, on the keystream the framed headers advanced.
#[tokio::test]
async fn encrypted_vision_uplink_direct_sends_raw_records_after_the_command() {
    use crate::proxy::vless::encryption::testutil::scripted_pair;

    let uuid = [9_u8; 16];
    let hello = inner_client_hello();
    let server_hello = tls13_server_hello();
    let app_record = tls_record(23, &[0x44; 64]);
    let raw = [tls_record(23, &[0x55; 40]), tls_record(23, &[0x66; 12])];
    for xor_iv in [None, Some([0x77; 16])] {
        let (client, mut server) = scripted_pair(xor_iv);
        let mut vision = VisionStream::new(ResponseHeaderStrip::new(client), uuid);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            vision.write_all(&hello).await.unwrap();
            vision.flush().await.unwrap();
            let frame = server.read_frame().await;
            let (command, content, _, rest) = take_vision_frame(&frame);
            assert_eq!((command, content), (0, hello.as_slice()), "{xor_iv:?}");
            assert!(rest.is_empty());

            // Direct is only offered after the inner ServerHello went down.
            let mut downlink = vec![0, 0];
            downlink.extend_from_slice(&uuid);
            downlink.extend(vision_frame(0, &server_hello, 3));
            server.write_frame(&downlink).await;
            let mut echoed = vec![0; server_hello.len()];
            vision.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, server_hello);

            vision.write_all(&app_record).await.unwrap();
            vision.flush().await.unwrap();
            let frame = server.read_frame().await;
            let (command, content, _, rest) = take_vision_frame(&frame);
            assert_eq!(
                (command, content),
                (VISION_COMMAND_DIRECT, app_record.as_slice()),
                "{xor_iv:?}"
            );
            assert!(rest.is_empty());

            for record in &raw {
                vision.write_all(record).await.unwrap();
            }
            vision.flush().await.unwrap();
            let (wire, decoded) = server.read_direct_records(raw.len()).await;
            assert_eq!(decoded, raw.concat(), "{xor_iv:?}");
            if xor_iv.is_some() {
                for start in [0, raw[0].len()] {
                    assert_ne!(wire[start..start + 5], decoded[start..start + 5]);
                    assert_eq!(wire[start + 5..][..8], decoded[start + 5..][..8]);
                }
                assert_eq!(wire[5..raw[0].len()], decoded[5..raw[0].len()]);
            } else {
                assert_eq!(wire, decoded);
            }
        })
        .await
        .expect("uplink Direct script stalled");
    }
}

#[derive(Default)]
struct StallLog {
    wire: Vec<u8>,
    direct: Vec<u8>,
    /// `wire.len()` when the last Ready flush completed.
    flushed: usize,
    /// `(wire.len(), flushed)` at the moment the outer writer was sealed.
    sealed: Option<(usize, usize)>,
}

/// An outer stream whose writes alternate Pending and one accepted byte and
/// whose flushes alternate Pending and Ready, so every place Vision must
/// resume a queued frame is exercised. Reads replay a canned downlink.
struct StallingOuter {
    downlink: std::io::Cursor<Vec<u8>>,
    log: Arc<parking_lot::Mutex<StallLog>>,
    stall_write: bool,
    stall_flush: bool,
}

impl tokio::io::AsyncRead for StallingOuter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.downlink).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for StallingOuter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let stalled = self.stall_write;
        self.stall_write = !stalled;
        if stalled {
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        self.log.lock().wire.push(buf[0]);
        std::task::Poll::Ready(Ok(1))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let stalled = self.stall_flush;
        self.stall_flush = !stalled;
        if stalled {
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        let mut log = self.log.lock();
        log.flushed = log.wire.len();
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl DirectIo for StallingOuter {
    const DIRECT_WRITE: bool = true;

    fn poll_direct_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.log.lock().direct.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_direct_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn seal_outer_write(&mut self) {
        let mut log = self.log.lock();
        log.sealed = Some((log.wire.len(), log.flushed));
    }
}

/// A Pending outer writer must neither lose nor repeat queued frame bytes,
/// and the uplink may only go Direct once the Direct frame has been flushed
/// out of the outer codec — the peer reads raw bytes right after it.
#[tokio::test]
async fn vision_uplink_resumes_stalled_outer_writes_and_flushes_before_direct() {
    let uuid = [11_u8; 16];
    let hello = inner_client_hello();
    let server_hello = tls13_server_hello();
    let app_record = tls_record(23, &[0x44; 64]);
    let mut downlink = uuid.to_vec();
    downlink.extend(vision_frame(0, &server_hello, 0));
    let log = Arc::new(parking_lot::Mutex::new(StallLog::default()));
    let mut vision = VisionStream::new(
        StallingOuter {
            downlink: std::io::Cursor::new(downlink),
            log: Arc::clone(&log),
            stall_write: true,
            stall_flush: true,
        },
        uuid,
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        // Direct is only offered after the inner ServerHello went down.
        let mut echoed = vec![0; server_hello.len()];
        vision.read_exact(&mut echoed).await.unwrap();
        vision.write_all(&hello).await.unwrap();
        // Each accepted frame may still be queued when the next write starts.
        vision.write_all(&app_record).await.unwrap();
        vision.write_all(b"raw-after-direct").await.unwrap();
        vision.flush().await.unwrap();
    })
    .await
    .expect("stalled writer never resumed");

    let log = log.lock();
    let (command, content, padding, rest) = take_vision_frame(&log.wire);
    assert_eq!((command, content), (0, hello.as_slice()));
    assert!((900..1400).contains(&(content.len() + padding)));
    let (command, content, _, rest) = take_vision_frame(rest);
    assert_eq!(
        (command, content),
        (VISION_COMMAND_DIRECT, app_record.as_slice())
    );
    assert!(rest.is_empty());
    assert_eq!(log.sealed, Some((log.wire.len(), log.wire.len())));
    assert_eq!(log.direct, b"raw-after-direct");
}

/// A TLS record larger than Vision's 8 KiB inbox read leaves decoded
/// plaintext inside the outer session: the bytes after the downlink Direct
/// frame must reach the caller before the raw socket is read or lent.
#[tokio::test]
async fn vision_downlink_direct_drains_buffered_tls_plaintext_before_the_raw_socket() {
    use std::sync::atomic::Ordering::Relaxed;

    let uuid = [6_u8; 16];
    let inner_hello = inner_client_hello();
    let app_record = tls_record(23, &[0x33; 64]);
    let server_hello = tls13_server_hello();
    let direct_content = [0xd1_u8; 64];
    let trailing: Vec<u8> = (0..10_000)
        .map(|index: usize| (index % 251) as u8)
        .collect();
    let raw = b"raw-after-direct";
    let mut record = vision_frame(VISION_COMMAND_DIRECT, &direct_content, 0);
    record.extend_from_slice(&trailing);

    let (port, server) = spawn_outer_tls_server({
        let server_hello = server_hello.clone();
        move |mut tls| {
            use std::io::Write as _;

            read_vision_request(&mut tls, uuid);
            read_uplink_frame(&mut tls, &[]);
            let mut downlink = vec![0, 0];
            downlink.extend_from_slice(&uuid);
            downlink.extend(vision_frame(0, &server_hello, 0));
            tls.write_all(&downlink).unwrap();
            tls.flush().unwrap();
            let (command, _, _) = read_uplink_frame(&mut tls, &[]);
            assert_eq!(command, VISION_COMMAND_DIRECT);
            // One outer record, so BoringSSL decrypts all of it at once.
            tls.write_all(&record).unwrap();
            tls.flush().unwrap();
            // After Direct the server writes to the socket, not through TLS.
            tls.get_mut().tcp.write_all(raw).unwrap();
        }
    });

    let node = vision_node("06060606-0606-0606-0606-060606060606", port);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut vision = VLessHandler::new()
            .dial(
                &node,
                "127.0.0.1:443".parse().unwrap(),
                None,
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap()
            .into_vision_splice()
            .unwrap();
        let ready = vision.ready_signal();
        vision.write_all(&inner_hello).await.unwrap();
        vision.flush().await.unwrap();
        let mut hello = vec![0; server_hello.len()];
        vision.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, server_hello);
        vision.write_all(&app_record).await.unwrap();
        vision.flush().await.unwrap();

        // Vision's first read takes 8192 plaintext bytes of the record: the
        // frame header, the Direct content and the head of what follows.
        let head_len = 8192 - 5;
        let taken = head_len - direct_content.len();
        let mut head = vec![0; head_len];
        vision.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..direct_content.len()], &direct_content[..]);
        assert_eq!(&head[direct_content.len()..], &trailing[..taken]);
        // Both directions are Direct and Vision holds nothing, yet the rest
        // of the record is still inside the outer session.
        assert!(
            !ready.load(Relaxed),
            "lent the socket over buffered plaintext"
        );
        assert!(vision.raw_parts().is_none());

        let mut rest = vec![0; trailing.len() - taken];
        vision.read_exact(&mut rest).await.unwrap();
        assert_eq!(rest, &trailing[taken..]);
        assert!(ready.load(Relaxed));
        let (socket, _) = vision
            .raw_parts()
            .expect("drained carrier lends its socket");
        let mut received = vec![0; raw.len()];
        let mut filled = 0;
        while filled < received.len() {
            socket.readable().await.unwrap();
            match socket.try_read(&mut received[filled..]) {
                Ok(0) => panic!("socket closed before the raw bytes arrived"),
                Ok(count) => filled += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
        }
        assert_eq!(received, raw);
    })
    .await
    .expect("Direct drain script stalled");
    server.join().unwrap();
}

#[tokio::test]
async fn vision_passthrough_without_uuid_prefix() {
    let uuid = [7u8; 16];
    let data = b"plain stream, not vision framed".to_vec();
    for chunk in [4usize, 1024] {
        assert_eq!(unpad_all(uuid, &data, chunk).await, data, "chunk={chunk}");
    }
}

#[tokio::test]
async fn vision_unpad_lab_frame_sequence() {
    // Mirrored from a live sing-box vision downlink trace: big content
    // frames with long padding, then a Direct switch to raw.
    let uuid = [7u8; 16];
    let mk = |command: u8, content: usize, padding: usize, fill: u8| {
        let mut frame = vec![
            command,
            (content >> 8) as u8,
            content as u8,
            (padding >> 8) as u8,
            padding as u8,
        ];
        frame.extend(std::iter::repeat_n(fill, content));
        frame.extend(std::iter::repeat_n(0u8, padding));
        frame
    };
    let mut data = uuid.to_vec();
    data.extend(mk(0, 146, 135, b'a'));
    data.extend(mk(0, 5219, 180, b'b'));
    data.extend(mk(VISION_COMMAND_DIRECT, 647, 262, b'c'));
    data.extend_from_slice(b"RAW-TAIL");

    let mut expected = Vec::new();
    expected.extend(std::iter::repeat_n(b'a', 146));
    expected.extend(std::iter::repeat_n(b'b', 5219));
    expected.extend(std::iter::repeat_n(b'c', 647));
    expected.extend_from_slice(b"RAW-TAIL");

    for chunk in [7usize, 1400, 8192, 65536] {
        assert_eq!(
            unpad_all(uuid, &data, chunk).await,
            expected,
            "chunk={chunk}"
        );
    }
}

#[tokio::test]
async fn vision_unknown_command_fails() {
    let uuid = [7u8; 16];
    let mut data = uuid.to_vec();
    data.extend(vision_frame(0x42, b"x", 0));
    let reader = ChunkedReader {
        data: data.into(),
        chunk: 1024,
    };
    let mut stream = VisionStream::new(reader, uuid);
    let mut out = Vec::new();
    let err = stream.read_to_end(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn response_strip_header_and_addon() {
    let mut data = vec![0x00, 0x03, 0xaa, 0xbb, 0xcc];
    data.extend_from_slice(b"payload-bytes");
    for chunk in [1usize, 2, 5, 1024] {
        let reader = ChunkedReader {
            data: data.iter().copied().collect(),
            chunk,
        };
        let mut stream = ResponseHeaderStrip::new(reader);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"payload-bytes", "chunk={chunk}");
    }
}

#[tokio::test]
async fn response_strip_rejects_nonzero_version() {
    let data = vec![0x01, 0x00, 0xff];
    let reader = ChunkedReader {
        data: data.into(),
        chunk: 1024,
    };
    let mut stream = ResponseHeaderStrip::new(reader);
    let mut out = Vec::new();
    let err = stream.read_to_end(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        crate::group::ScoreOutcome::from_io_error(&err),
        crate::group::ScoreOutcome::NodeFailure
    );
}
