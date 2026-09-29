use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use std::time::Duration;

use boring::ssl::{SslAcceptor, SslMethod, SslVersion};
use honk_config::node::{Node, OutboundConfig, VlessConfig};
use honk_outbound::TcpOutbound as _;
use honk_outbound::proxy::vless::VLessHandler;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::relay::splice::test_hook::{self, StateGuard, TEST_LOCK};
use crate::relay::{copy_phase, relay_proxy};

const UUID: &str = "05050505-0505-0505-0505-050505050505";

fn record(record_type: u8, content: &[u8]) -> Vec<u8> {
    let mut record = vec![record_type, 3, 3];
    record.extend_from_slice(&(content.len() as u16).to_be_bytes());
    record.extend_from_slice(content);
    record
}

fn client_hello() -> Vec<u8> {
    record(22, &[1, 0, 0, 4, 9, 9, 9, 9])
}

/// A TLS 1.3 ServerHello selecting TLS_AES_128_GCM_SHA256.
fn server_hello() -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&[0x13, 0x01, 0]);
    body.extend_from_slice(&[0, 6, 0x00, 0x2b, 0x00, 0x02, 3, 4]);
    let mut message = vec![2, 0, 0, body.len() as u8];
    message.extend_from_slice(&body);
    record(22, &message)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Inner TLS application records carrying `len` payload bytes.
fn application_records(len: usize) -> Vec<u8> {
    pattern(len, 7)
        .chunks(16_384)
        .flat_map(|chunk| record(23, chunk))
        .collect()
}

fn vision_frame(command: u8, content: &[u8]) -> Vec<u8> {
    let mut frame = vec![command];
    frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
    frame.extend_from_slice(&3_u16.to_be_bytes());
    frame.extend_from_slice(content);
    frame.extend_from_slice(&[0; 3]);
    frame
}

/// What the scripted peer sends and expects in each phase.
#[derive(Clone)]
struct Script {
    upload: Vec<u8>,
    download: Vec<u8>,
    late_upload: Vec<u8>,
    late_download: Vec<u8>,
}

impl Script {
    fn new(upload: usize, download: usize) -> Self {
        let mut early = client_hello();
        early.extend(application_records(upload));
        Self {
            upload: early,
            download: pattern(download, 3),
            late_upload: pattern(64 * 1024, 5),
            late_download: pattern(96 * 1024, 11),
        }
    }
}

async fn read_frame(tls: &mut tokio_boring::SslStream<TcpStream>) -> (u8, Vec<u8>) {
    let mut head = [0; 5];
    tls.read_exact(&mut head).await.unwrap();
    let content = usize::from(u16::from_be_bytes([head[1], head[2]]));
    let padding = usize::from(u16::from_be_bytes([head[3], head[4]]));
    let mut body = vec![0; content + padding];
    tls.read_exact(&mut body).await.unwrap();
    body.truncate(content);
    (head[0], body)
}

/// Accepts the VLESS request, answers the ClientHello with a ServerHello and
/// reads uplink frames until the uplink switched to Direct.
async fn accept_until_uplink_direct(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> (tokio_boring::SslStream<TcpStream>, Vec<u8>) {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = tokio_boring::accept(acceptor, tcp).await.unwrap();
    let mut request = [0; 18];
    tls.read_exact(&mut request).await.unwrap();
    let mut rest = vec![0; usize::from(request[17]) + 1 + 2 + 1 + 4];
    tls.read_exact(&mut rest).await.unwrap();
    let mut uuid = [0; 16];
    tls.read_exact(&mut uuid).await.unwrap();

    let hello = client_hello();
    let mut upload = Vec::new();
    loop {
        let (command, content) = read_frame(&mut tls).await;
        upload.extend(content);
        if upload == hello {
            let mut downlink = vec![0, 0];
            downlink.extend_from_slice(&uuid);
            downlink.extend(vision_frame(0, &server_hello()));
            tls.write_all(&downlink).await.unwrap();
            tls.flush().await.unwrap();
        }
        if command == 2 {
            break;
        }
        assert_eq!(command, 0);
    }
    (tls, upload)
}

/// An Xray-style Vision inbound that echoes nothing and follows `script`:
/// it answers the ClientHello with a ServerHello, switches the downlink to
/// Direct after the uplink did, then trades raw bytes until EOF.
async fn vision_peer(listener: TcpListener, acceptor: Arc<SslAcceptor>, script: Script) {
    let (mut tls, mut upload) = accept_until_uplink_direct(&listener, &acceptor).await;
    let mut raw = vec![0; script.upload.len() - upload.len()];
    tls.get_mut().read_exact(&mut raw).await.unwrap();
    upload.extend(raw);
    assert!(upload == script.upload, "uplink before splice differs");

    let (direct, rest) = script.download.split_at(1000);
    tls.write_all(&vision_frame(2, direct)).await.unwrap();
    tls.flush().await.unwrap();
    let raw = tls.get_mut();
    raw.write_all(rest).await.unwrap();
    let mut late = vec![0; script.late_upload.len()];
    raw.read_exact(&mut late).await.unwrap();
    assert!(late == script.late_upload, "late uplink differs");
    raw.write_all(&script.late_download).await.unwrap();
    let mut tail = Vec::new();
    raw.read_to_end(&mut tail).await.unwrap();
    assert!(tail.is_empty());
    raw.shutdown().await.unwrap();
}

fn acceptor() -> Arc<SslAcceptor> {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&boring::x509::X509::from_pem(cert.pem().as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(
            &boring::pkey::PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    Arc::new(acceptor.build())
}

fn vision_node(port: u16) -> Node {
    let mut node = Node {
        outbound: OutboundConfig::Vless(VlessConfig {
            uuid: Some(UUID.into()),
            flow: Some("xtls-rprx-vision".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    node.address = format!("127.0.0.1:{port}");
    node.host = "127.0.0.1".into();
    node.port = port;
    let tls = node.tls_mut().unwrap();
    tls.enabled = true;
    tls.skip_cert_verify = true;
    tls.sni = Some("localhost".into());
    node
}

struct Outcome {
    stats: RelayStats,
    upload: u64,
    download: u64,
    accepted: (u64, u64),
    responses: usize,
}

/// Relay counters, which the scripted peer may read while the relay runs.
#[derive(Clone)]
struct Tally {
    progress: RelayProgress,
    accepted: Arc<(AtomicU64, AtomicU64)>,
    responses: Arc<AtomicUsize>,
}

impl Tally {
    fn new() -> Self {
        let accepted = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
        let responses = Arc::new(AtomicUsize::new(0));
        let progress = RelayProgress {
            upload: Arc::default(),
            download: Arc::default(),
            first_response: Some(Arc::new({
                let responses = responses.clone();
                move || {
                    responses.fetch_add(1, Ordering::Relaxed);
                }
            })),
            on_transfer: Some(Arc::new({
                let accepted = accepted.clone();
                move |up, down| {
                    accepted.0.fetch_add(up, Ordering::Relaxed);
                    accepted.1.fetch_add(down, Ordering::Relaxed);
                }
            })),
        };
        Self {
            progress,
            accepted,
            responses,
        }
    }

    fn outcome(&self, stats: RelayStats) -> Outcome {
        Outcome {
            stats,
            upload: self.progress.upload.load(Ordering::Relaxed),
            download: self.progress.download.load(Ordering::Relaxed),
            accepted: (
                self.accepted.0.load(Ordering::Relaxed),
                self.accepted.1.load(Ordering::Relaxed),
            ),
            responses: self.responses.load(Ordering::Relaxed),
        }
    }
}

/// Accepts one client and relays it through `relay_proxy` to a real Vision
/// dial of `port`.
async fn spawn_relay(
    port: u16,
    progress: RelayProgress,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<RelayStats>>,
) {
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();
    let relay = tokio::spawn(async move {
        let (mut client, client_addr) = front.accept().await.unwrap();
        let target = "127.0.0.1:443".parse().unwrap();
        let proxy = VLessHandler::new()
            .dial(&vision_node(port), target, None, Duration::from_secs(5))
            .await
            .unwrap();
        relay_proxy(&mut client, proxy, client_addr, target, progress).await
    });
    (front_addr, relay)
}

/// Runs one accepted client through `relay_proxy` to a real Vision dial.
async fn relay_script(script: Script) -> Outcome {
    let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = peer.local_addr().unwrap().port();
    let server = tokio::spawn(vision_peer(peer, acceptor(), script.clone()));
    let tally = Tally::new();
    let (front_addr, relay) = spawn_relay(port, tally.progress.clone()).await;

    let mut app = TcpStream::connect(front_addr).await.unwrap();
    let hello = client_hello();
    app.write_all(&hello).await.unwrap();
    let mut answer = vec![0; server_hello().len()];
    app.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer, server_hello());
    app.write_all(&script.upload[hello.len()..]).await.unwrap();
    let mut download = vec![0; script.download.len()];
    app.read_exact(&mut download).await.unwrap();
    assert!(download == script.download, "downlink differs");
    app.write_all(&script.late_upload).await.unwrap();
    let mut late = vec![0; script.late_download.len()];
    app.read_exact(&mut late).await.unwrap();
    assert!(late == script.late_download, "late downlink differs");
    app.shutdown().await.unwrap();
    let mut tail = Vec::new();
    app.read_to_end(&mut tail).await.unwrap();
    assert!(tail.is_empty());

    server.await.unwrap();
    let stats = relay.await.unwrap().unwrap();
    tally.outcome(stats)
}

/// The uplink copy read a chunk the carrier has not accepted: nobody reads
/// the uplink, so that `write_all` cannot finish.
async fn uplink_write_stuck(tally: &Tally) {
    let mut last = (0, 0);
    let mut steady = 0;
    while steady < 1000 {
        tokio::task::yield_now().await;
        let now = (
            tally.progress.upload.load(Ordering::Relaxed),
            tally.accepted.0.load(Ordering::Relaxed),
        );
        // A copy the runtime paused for its budget lags briefly too, but
        // then moves on; only a gap that outlasts many turns is a stuck write.
        steady = if now.0 > now.1 && now == last {
            steady + 1
        } else {
            0
        };
        last = now;
    }
}

/// A Vision inbound that switches the downlink to Direct and serves the whole
/// download while it leaves the uplink unread, then drains the uplink.
async fn duplex_peer(
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
    script: Script,
    tally: Tally,
    downloaded: tokio::sync::oneshot::Receiver<()>,
) {
    let (mut tls, mut upload) = accept_until_uplink_direct(&listener, &acceptor).await;
    tokio::time::timeout(Duration::from_secs(10), uplink_write_stuck(&tally))
        .await
        .expect("the uplink never backed up");

    let (direct, rest) = script.download.split_at(1000);
    tls.write_all(&vision_frame(2, direct)).await.unwrap();
    tls.flush().await.unwrap();
    let raw = tls.get_mut();
    raw.write_all(rest).await.unwrap();
    downloaded.await.unwrap();

    let mut remainder = vec![0; script.upload.len() - upload.len()];
    raw.read_exact(&mut remainder).await.unwrap();
    upload.extend(remainder);
    assert!(upload == script.upload, "uplink differs");
    raw.write_all(&script.late_download).await.unwrap();
    let mut tail = Vec::new();
    raw.read_to_end(&mut tail).await.unwrap();
    assert!(tail.is_empty());
    raw.shutdown().await.unwrap();
}

/// Uploads without pause while the downlink switches to Direct and the
/// download completes.
async fn relay_duplex(script: Script) -> Outcome {
    let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // A small receive window keeps kernel buffers from hiding the backed-up uplink.
    socket2::SockRef::from(&peer)
        .set_recv_buffer_size(4096)
        .unwrap();
    let port = peer.local_addr().unwrap().port();
    let tally = Tally::new();
    let (downloaded_tx, downloaded_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(duplex_peer(
        peer,
        acceptor(),
        script.clone(),
        tally.clone(),
        downloaded_rx,
    ));
    let (front_addr, relay) = spawn_relay(port, tally.progress.clone()).await;

    let mut app = TcpStream::connect(front_addr).await.unwrap();
    let hello = client_hello();
    app.write_all(&hello).await.unwrap();
    let mut answer = vec![0; server_hello().len()];
    app.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer, server_hello());
    let (mut down, mut up) = app.into_split();
    let rest = script.upload[hello.len()..].to_vec();
    let upload = tokio::spawn(async move {
        up.write_all(&rest).await.unwrap();
        up.shutdown().await.unwrap();
    });
    let mut download = vec![0; script.download.len()];
    down.read_exact(&mut download).await.unwrap();
    assert!(download == script.download, "downlink differs");
    downloaded_tx.send(()).unwrap();
    let mut late = vec![0; script.late_download.len()];
    down.read_exact(&mut late).await.unwrap();
    assert!(late == script.late_download, "late downlink differs");
    let mut tail = Vec::new();
    down.read_to_end(&mut tail).await.unwrap();
    assert!(tail.is_empty());

    upload.await.unwrap();
    server.await.unwrap();
    let stats = relay.await.unwrap().unwrap();
    tally.outcome(stats)
}

fn assert_whole_connection(outcome: &Outcome, script: &Script) {
    let upload = (script.upload.len() + script.late_upload.len()) as u64;
    let download =
        (server_hello().len() + script.download.len() + script.late_download.len()) as u64;
    assert_eq!(outcome.stats.client_to_proxy, upload);
    assert_eq!(outcome.stats.proxy_to_client, download);
    assert_eq!((outcome.upload, outcome.download), (upload, download));
    assert_eq!(outcome.accepted, (upload, download));
    assert_eq!(outcome.responses, 1);
}

async fn run_case(script: Script, prepare: impl FnOnce()) -> Outcome {
    prepare();
    let outcome = tokio::time::timeout(Duration::from_secs(20), relay_script(script.clone()))
        .await
        .expect("Vision relay did not finish");
    assert_whole_connection(&outcome, &script);
    outcome
}

#[tokio::test]
async fn bulk_vision_flow_hands_its_socket_to_splice() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    run_case(Script::new(1024 * 1024, 512 * 1024), || {}).await;
    assert_eq!(test_hook::probe_calls(), 2, "both splice directions ran");
    assert!(splice::splice_available());
}

#[tokio::test]
async fn short_vision_flow_stays_on_the_copy_relay() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    run_case(Script::new(16 * 1024, 8 * 1024), || {}).await;
    assert_eq!(test_hook::probe_calls(), 0);
}

#[tokio::test]
async fn unsupported_splice_resumes_the_same_vision_stream() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    run_case(Script::new(1024 * 1024, 512 * 1024), || {
        test_hook::set_forced_errno(libc::EPERM, -1);
    })
    .await;
    assert_eq!(test_hook::probe_calls(), 1);
    assert!(!splice::splice_available());
}

#[tokio::test]
async fn missing_pipes_resume_copy_without_disabling_splice() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    run_case(Script::new(1024 * 1024, 512 * 1024), test_hook::fail_pipes).await;
    assert_eq!(test_hook::probe_calls(), 0);
    assert!(splice::splice_available());
}

#[tokio::test]
async fn upload_in_flight_at_the_downlink_switch_survives_the_handover() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    let mut script = Script::new(16 * 1024 * 1024, 512 * 1024);
    // One unbroken upload rather than the early/late phases.
    script.late_upload.clear();
    let outcome = tokio::time::timeout(Duration::from_secs(20), relay_duplex(script.clone()))
        .await
        .expect("Vision relay did not finish");
    assert_whole_connection(&outcome, &script);
    assert_eq!(test_hook::probe_calls(), 2, "both splice directions ran");
}

/// A direction waiting in a read still owes the bytes its writer buffered:
/// the connection may be handed over only after that flush finished.
#[tokio::test]
async fn park_waits_for_the_other_direction_to_flush() {
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    #[derive(Default)]
    struct Gate {
        open: AtomicBool,
        stuck: AtomicUsize,
        waker: parking_lot::Mutex<Option<Waker>>,
    }

    /// Accepts writes into a buffer that leaves only on a flush the gate allows.
    struct Carrier {
        reads: tokio::io::DuplexStream,
        buffered: Vec<u8>,
        sent: Arc<parking_lot::Mutex<Vec<u8>>>,
        gate: Arc<Gate>,
    }

    impl AsyncRead for Carrier {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.reads).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Carrier {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.buffered.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            if self.buffered.is_empty() {
                return Poll::Ready(Ok(()));
            }
            if !self.gate.open.load(Ordering::Relaxed) {
                self.gate.stuck.fetch_add(1, Ordering::Relaxed);
                *self.gate.waker.lock() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let buffered = std::mem::take(&mut self.buffered);
            self.sent.lock().extend(buffered);
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        // The stream's own handover condition is off until both sides are set up.
        let ready = AtomicBool::new(false);
        let gate = || ready.load(Ordering::Relaxed);
        let park = Park::new(&gate);
        let (mut app, mut client) = tokio::io::duplex(64);
        let (mut peer, reads) = tokio::io::duplex(64);
        let gate = Arc::new(Gate::default());
        let sent = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut carrier = Carrier {
            reads,
            buffered: Vec::new(),
            sent: sent.clone(),
            gate: gate.clone(),
        };
        let phase = copy_phase(&mut client, &mut carrier, Some(&park));
        tokio::pin!(phase);

        let unflushed = async {
            app.write_all(b"up").await.unwrap();
            while gate.stuck.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
            ready.store(true, Ordering::Relaxed);
            peer.write_all(b"down").await.unwrap();
            // The downlink copy tries the handover right after this write.
            let mut down = [0; 4];
            app.read_exact(&mut down).await.unwrap();
            assert_eq!(&down, b"down");
        };
        tokio::select! {
            result = &mut phase => panic!("handed over with unflushed uplink bytes: {result:?}"),
            () = unflushed => {}
        }
        assert!(!park.taken());

        gate.open.store(true, Ordering::Relaxed);
        gate.waker.lock().take().unwrap().wake();
        let (result, ()) = tokio::join!(phase, async {
            while sent.lock().is_empty() {
                tokio::task::yield_now().await;
            }
            peer.write_all(b"more").await.unwrap();
        });
        result.unwrap();
        assert!(park.taken());
        assert_eq!(*sent.lock(), b"up");
    })
    .await
    .expect("flush-gated handover stalled");
}
