use super::*;
use std::io::IoSliceMut;
use std::sync::atomic::AtomicUsize;

use futures_util::task::AtomicWaker;
use parking_lot::Mutex;
use quinn::{AsyncUdpSocket, Connection, Endpoint, UdpPoller, udp};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;

use crate::proxy::request_observation_support::{Events, milestones, observed};
use crate::proxy::trojan::TrojanHandler;
use crate::proxy::{AsyncReadWrite, UdpSocketTransport};
use crate::quic::{self, QuicBiStream};
use crate::runtime::flow_observation::{self, Milestone, observe_chain_request};

const TROJAN: &[u8] = b"95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12\r\n\x01\x01\xc0\x00\x02\x01\x01\xbb\r\n";

#[derive(Debug, PartialEq)]
enum Permit {
    Open,
    Armed,
    Held,
    One(bool),
}

// One connection driver per fixture. Ordinary ACK, DATAGRAM and STREAM transmits bypass the gate.
#[derive(Debug)]
struct Gate {
    socket: Arc<dyn AsyncUdpSocket>,
    permit: Mutex<Permit>,
    ready: AtomicWaker,
    blocked: Notify,
    strict: AtomicUsize,
    pause_recv: AtomicBool,
    recv_waker: AtomicWaker,
}

impl Gate {
    fn hold(&self) {
        *self.permit.lock() = Permit::Armed;
    }

    async fn held(&self) {
        while *self.permit.lock() != Permit::Held {
            self.blocked.notified().await;
        }
    }

    fn release(&self, one: Option<bool>) {
        *self.permit.lock() = one.map_or(Permit::Open, Permit::One);
        self.ready.wake();
    }
}

impl AsyncUdpSocket for Gate {
    fn try_send(&self, tx: &udp::Transmit<'_>) -> io::Result<()> {
        if self.pause_recv.load(Relaxed) {
            // During the no-ACK checkpoint verify the suffix's syscall even if sticky failure
            // already canceled its receipt. Do not expose this extra fact to the Quinn driver.
            assert!(self.socket.try_send_with_status(tx)?);
            return Ok(());
        }
        self.socket.try_send(tx)
    }

    fn try_send_with_status(&self, tx: &udp::Transmit<'_>) -> io::Result<bool> {
        let mut permit = self.permit.lock();
        let confirm = match *permit {
            Permit::Armed | Permit::Held => {
                *permit = Permit::Held;
                self.blocked.notify_one();
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Permit::Open => true,
            Permit::One(confirm) => confirm,
        };
        assert!(self.socket.try_send_with_status(tx)?);
        self.strict.fetch_add(1, Relaxed);
        if matches!(*permit, Permit::One(_)) {
            *permit = Permit::Armed;
        }
        Ok(confirm)
    }

    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller(self.socket.clone().create_io_poller(), self))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.recv_waker.register(cx.waker());
        if self.pause_recv.load(Relaxed) {
            return Poll::Pending;
        }
        self.socket.poll_recv(cx, bufs, meta)
    }

    fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }
}

#[derive(Debug)]
struct Poller(Pin<Box<dyn UdpPoller>>, Arc<Gate>);

impl UdpPoller for Poller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.1.ready.register(cx.waker());
        if *self.1.permit.lock() == Permit::Held {
            Poll::Pending
        } else {
            self.0.as_mut().poll_writable(cx)
        }
    }
}

async fn establish(client: &Endpoint, server: &Endpoint) -> (Connection, Connection) {
    let config = quic::client_config(&tls_node(skip_verify_tls()), &[b"h3"], Default::default())
        .await
        .unwrap();
    let connecting = client
        .connect_with(config, server.local_addr().unwrap(), "localhost")
        .unwrap();
    let (client, server) = tokio::join!(connecting, async { server.accept().await.unwrap().await });
    (client.unwrap(), server.unwrap())
}

async fn connected() -> (Connection, Connection, Arc<Gate>) {
    let (_, client, server, gate) = connected_with_endpoint().await;
    (client, server, gate)
}

async fn connected_with_endpoint() -> (Endpoint, Connection, Connection, Arc<Gate>) {
    let runtime = quinn::default_runtime().unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let gate = Arc::new(Gate {
        socket: runtime.wrap_udp_socket(socket).unwrap(),
        permit: Mutex::new(Permit::Armed),
        ready: AtomicWaker::new(),
        blocked: Notify::new(),
        strict: AtomicUsize::new(0),
        pause_recv: AtomicBool::new(false),
        recv_waker: AtomicWaker::new(),
    });
    let endpoint =
        Endpoint::new_with_abstract_socket(Default::default(), None, gate.clone(), runtime)
            .unwrap();
    let (server, _) = quic::testutil::server_endpoint(&[b"h3"], true).unwrap();
    let (client, server) = establish(&endpoint, &server).await;
    (endpoint, client, server, gate)
}

async fn stream(client: &Connection) -> QuicBiStream {
    let (tx, rx) = client.open_bi().await.unwrap();
    QuicBiStream::new(tx, rx)
}

async fn trojan(carrier: impl AsyncReadWrite + 'static) -> anyhow::Result<ProxyStream> {
    let mut node = tls_node(TlsOptions {
        enabled: false,
        ..Default::default()
    });
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node)?;
    TrojanHandler
        .dial_over(
            runtime,
            Box::new(carrier),
            "192.0.2.1:443".parse().unwrap(),
            None,
            TunnelDialOptions::new(TIMEOUT),
        )
        .await
}

fn sent(events: &Events) -> usize {
    milestones(&events.lock(), Milestone::TargetRequestSent)
}

async fn wait_sent(events: &Events) {
    while sent(events) == 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(sent(events), 1);
}

// Hold the suffix of a staged carrier write without changing the accepted prefix.
#[derive(Debug)]
struct SplitWrite<T> {
    io: T,
    before_pause: usize,
    resume: Option<oneshot::Receiver<()>>,
}

impl<T> SplitWrite<T> {
    fn new(io: T, before_pause: usize) -> (Self, oneshot::Sender<()>) {
        let (resume, receiver) = oneshot::channel();
        (
            Self {
                io,
                before_pause,
                resume: Some(receiver),
            },
            resume,
        )
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SplitWrite<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.before_pause == 0
            && let Some(resume) = &mut self.resume
        {
            std::task::ready!(Pin::new(resume).poll(cx)).unwrap();
            self.resume = None;
        }
        let len = if self.resume.is_some() {
            self.before_pause.min(bytes.len())
        } else {
            bytes.len()
        };
        let written = std::task::ready!(Pin::new(&mut self.io).poll_write(cx, &bytes[..len]))?;
        self.before_pause = self.before_pause.saturating_sub(written);
        Poll::Ready(Ok(written))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SplitWrite<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

#[tokio::test]
async fn quic_chain_request_waits_for_every_accepted_prefix() {
    for prefix_confirmed in [true, false] {
        timeout(TIMEOUT, async {
            let (client, server, gate) = connected().await;
            let mut other = client.open_uni().await.unwrap();
            client
                .send_datagram(bytes::Bytes::from_static(b"datagram"))
                .unwrap();
            let (n, unrelated) = other.write_with_receipt(b"other").await.unwrap();
            assert_eq!(n, 5);
            gate.held().await;
            let (send, recv) = client.open_bi().await.unwrap();
            let id = send.id();
            let acked = send.stopped();
            let (carrier, resume) = SplitWrite::new(QuicBiStream::new(send, recv), 17);
            let (observer, events) = observed();
            let mut dial = Box::pin(observer.scope(observe_chain_request(trojan(carrier))));
            assert!(futures_util::poll!(dial.as_mut()).is_pending());
            gate.release(Some(true));
            unrelated.await.unwrap();
            assert_eq!(&server.read_datagram().await.unwrap()[..], b"datagram");
            let mut other_rx = server.accept_uni().await.unwrap();
            assert_eq!(other_rx.id(), other.id());
            let mut other_bytes = [0; 5];
            other_rx.read_exact(&mut other_bytes).await.unwrap();
            assert_eq!(&other_bytes, b"other");
            gate.held().await;
            assert_eq!(sent(&events), 0);
            resume.send(()).unwrap();
            let mut tunnel = dial.await.unwrap();
            assert_eq!(sent(&events), 0, "local acceptance is not submission");
            server
                .send_datagram(bytes::Bytes::from_static(b"after seal"))
                .unwrap();
            assert_eq!(&client.read_datagram().await.unwrap()[..], b"after seal");
            assert_eq!(sent(&events), 0, "unrelated traffic after seal");

            gate.pause_recv.store(true, Relaxed);
            gate.release(Some(prefix_confirmed));
            let (_tx, mut rx) = server.accept_bi().await.unwrap();
            assert_eq!(rx.id(), id);
            let mut header = [0; 68];
            rx.read_exact(&mut header[..17]).await.unwrap();
            assert_eq!(&header[..17], &TROJAN[..17]);
            if prefix_confirmed {
                gate.held().await;
            }
            assert_eq!(sent(&events), 0, "confirmed prefix is insufficient");
            gate.release(None);
            rx.read_exact(&mut header[17..]).await.unwrap();
            assert_eq!(&header, TROJAN);
            if prefix_confirmed {
                wait_sent(&events).await;
            }
            gate.pause_recv.store(false, Relaxed);
            gate.recv_waker.wake();
            let count = gate.strict.load(Relaxed);
            gate.hold();
            observer
                .scope(tunnel.stream.write_all(b"after"))
                .await
                .unwrap();
            tunnel.stream.shutdown().await.unwrap();
            assert_eq!(rx.read_to_end(5).await.unwrap(), b"after");
            assert_eq!(
                acked.await.unwrap(),
                None,
                "peer must ACK every byte and the FIN"
            );
            assert_eq!(
                gate.strict.load(Relaxed),
                count,
                "business payload sought a receipt"
            );
            assert_eq!(sent(&events), usize::from(prefix_confirmed));
            assert_eq!(milestones(&events.lock(), Milestone::TargetConfirmed), 0);
        })
        .await
        .expect("timed out stepping the final Trojan request");
    }
}

// Only entry establishment is substituted. ChainHandler selects the real final protocol and
// scopes the request exactly as it does for a production QUIC entry.
struct QuinnEntry(Mutex<Option<Box<dyn AsyncReadWrite>>>);

#[async_trait::async_trait]
impl TcpOutbound for QuinnEntry {
    async fn dial(
        &self,
        _: &Node,
        target_addr: SocketAddr,
        _: Option<&str>,
        _: Duration,
    ) -> anyhow::Result<ProxyStream> {
        Ok(ProxyStream {
            stream: self.0.lock().take().expect("one entry stream per attempt"),
            target_addr,
            target_domain: None,
        })
    }
}

#[derive(Clone, Debug)]
struct Retained(Arc<Mutex<QuicBiStream>>);

impl AsyncRead for Retained {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_read(cx, buf)
    }
}

impl AsyncWrite for Retained {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.lock()).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_shutdown(cx)
    }
}

async fn dispatch_trojan(
    carrier: impl AsyncReadWrite + 'static,
    generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
    dial: crate::proxy::DialRef<'_>,
) -> anyhow::Result<ProxyStream> {
    use crate::proxy::{ProtocolEntry, ProxyRegistry};
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(
        NodeProtocol::Hysteria2,
        Arc::new(QuinnEntry(Mutex::new(Some(Box::new(carrier))))),
    ));
    registry.register(ProtocolEntry::new(
        NodeProtocol::Trojan,
        Arc::new(TrojanHandler),
    ));
    registry.register_chain();
    registry
        .dial_ref(
            Arc::clone(generation),
            dial,
            "192.0.2.1:443".parse().unwrap(),
            None,
            TIMEOUT,
        )
        .await
}

#[tokio::test]
async fn cancelled_chain_receipts_do_not_publish_into_live_sibling() {
    use crate::proxy::DialRef;
    use honk_config::group_graph::{Composed, compose};

    timeout(TIMEOUT, async {
        let (client, server, gate) = connected().await;
        let entry = crate::test_support::node(
            "entry",
            "127.0.0.1",
            443,
            OutboundConfig::Hysteria2(Default::default()),
        );
        let mut exit = tls_node(Default::default());
        exit.id = exit.derive_id();
        let chain = crate::test_support::chain(&[&entry, &exit]);
        let id = chain.id;
        let Composed::Routed(route) = compose(entry.id, &[entry.id], [exit.id]) else {
            panic!("expected a QUIC-entry route");
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(&[chain, entry, exit]).unwrap(),
        );
        for (dial_ref, accepted) in [DialRef::Node(id), DialRef::Route(&route)]
            .into_iter()
            .flat_map(|dial| [0, 17, TROJAN.len()].map(|accepted| (dial, accepted)))
        {
            let mut winner = stream(&client).await;
            winner.write_all(b"W").await.unwrap();
            let (_send, mut winner_rx) = server.accept_bi().await.unwrap();
            let mut marker = [0];
            winner_rx.read_exact(&mut marker).await.unwrap();
            assert_eq!(&marker, b"W");
            gate.hold();
            let (send, recv) = client.open_bi().await.unwrap();
            let loser_id = send.id();
            let mut retained = Retained(Arc::new(Mutex::new(QuicBiStream::new(send, recv))));
            let (carrier, _resume) = SplitWrite::new(retained.clone(), accepted);
            let loser_ctx = flow_observation::FlowContext {
                flow_id: uuid::Uuid::new_v4(),
                generation: 1,
                attempt_id: Some(uuid::Uuid::new_v4()),
                lookup_id: Some(uuid::Uuid::new_v4()),
                dns_purpose: "proxy_server",
            };
            let win_ctx = flow_observation::FlowContext {
                attempt_id: Some(uuid::Uuid::new_v4()),
                lookup_id: Some(uuid::Uuid::new_v4()),
                ..loser_ctx
            };
            let contexts = Arc::new(Mutex::new(Vec::new()));
            let captured = contexts.clone();
            let loser = flow_observation::FlowObserver::new(
                loser_ctx,
                Arc::new(move |ctx, event| {
                    if matches!(
                        event,
                        flow_observation::FlowEvent::Milestone {
                            milestone: Milestone::TargetRequestSent
                        }
                    ) {
                        captured.lock().push(ctx);
                    }
                }),
            );
            let win = loser.with_context(win_ctx);
            let mut dial = Box::pin(loser.scope(dispatch_trojan(carrier, &generation, dial_ref)));
            if accepted == TROJAN.len() {
                let returned = dial.await.unwrap();
                gate.held().await;
                drop(returned);
            } else {
                assert!(futures_util::poll!(dial.as_mut()).is_pending());
                if accepted != 0 {
                    gate.held().await;
                }
                drop(dial);
            }
            assert!(contexts.lock().is_empty());
            gate.release(None);
            let mut tunnel = win
                .scope(dispatch_trojan(winner, &generation, dial_ref))
                .await
                .unwrap();
            while contexts.lock().is_empty() {
                tokio::task::yield_now().await;
            }
            tunnel.stream.shutdown().await.unwrap();
            assert_eq!(winner_rx.read_to_end(TROJAN.len()).await.unwrap(), TROJAN);
            retained.write_all(b"!").await.unwrap();
            retained.shutdown().await.unwrap();
            let (_send, mut loser_rx) = server.accept_bi().await.unwrap();
            assert_eq!(loser_rx.id(), loser_id);
            let bytes = loser_rx.read_to_end(accepted + 1).await.unwrap();
            assert_eq!(bytes.split_last(), Some((&b'!', &TROJAN[..accepted])));
            assert_eq!(
                contexts.lock().as_slice(),
                &[win_ctx],
                "wrong or late event after cancellation at {accepted}"
            );
        }
    })
    .await
    .expect("cancelled loser blocked sibling delivery");
}

#[tokio::test]
async fn unobserved_and_masked_requests_use_ordinary_quinn_writes() {
    timeout(TIMEOUT, async {
        let (client, server, gate) = connected().await;
        let (observer, events) = observed();
        for mode in 0..3 {
            let dial = observe_chain_request(trojan(stream(&client).await));
            let mut tunnel = match mode {
                0 => dial.await,
                1 => observer.scope(flow_observation::without(dial)).await,
                _ => {
                    observer
                        .scope(flow_observation::without_target_milestones(dial))
                        .await
                }
            }
            .unwrap();
            tunnel.stream.shutdown().await.unwrap();
            let (_tx, mut rx) = server.accept_bi().await.unwrap();
            assert_eq!(rx.read_to_end(TROJAN.len()).await.unwrap(), TROJAN);
            assert_eq!(gate.strict.load(Relaxed), 0);
            assert_eq!(sent(&events), 0);
        }
    })
    .await
    .expect("ordinary bytes waited on the strict socket");
}

#[tokio::test]
async fn queue_backed_legacy_socket_delivers_without_submission_evidence() {
    timeout(TIMEOUT, async {
        let (server, remote) = quic::testutil::server_endpoint(&[b"h3"], true).unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = Arc::new(UdpSocketTransport::new(Arc::new(socket), remote));
        let endpoint = quic::packet_transport_endpoint(transport, remote).unwrap();
        let (client, peer) = establish(endpoint.endpoint(), &server).await;
        let (observer, events) = observed();
        let mut tunnel = observer
            .scope(observe_chain_request(trojan(stream(&client).await)))
            .await
            .unwrap();
        tunnel.stream.write_all(b"!").await.unwrap();
        tunnel.stream.shutdown().await.unwrap();
        let (mut tx, mut rx) = peer.accept_bi().await.unwrap();
        let bytes = rx.read_to_end(TROJAN.len() + 1).await.unwrap();
        assert_eq!(bytes.split_last(), Some((&b'!', TROJAN)));
        tx.write_all(b"ok").await.unwrap();
        let mut reply = [0; 2];
        tunnel.stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");
        assert_eq!(
            sent(&events),
            0,
            "peer delivery/response cannot pay for an unconfirmed queue handoff"
        );
        assert!(endpoint.close(Duration::from_millis(50)).await);
    })
    .await
    .expect("queue-backed QUIC delivery timed out");
}

#[tokio::test]
async fn outer_request_survives_target_mask_but_not_full_suppression() {
    timeout(TIMEOUT, async {
        let (client, server, gate) = connected().await;
        let mut carrier = stream(&client).await;
        let (observer, events) = observed();
        let mut peer = None;
        let dial = async {
            let write = async {
                assert_eq!(carrier.write(&[]).await?, 0);
                let mut empty = [bytes::Bytes::new(), bytes::Bytes::new()];
                assert_eq!(
                    std::future::poll_fn(|cx| carrier.poll_write_chunks(cx, &mut empty, 0)).await?,
                    0
                );
                flow_observation::without(carrier.write_all(b"plain")).await?;
                let (_tx, mut rx) = server.accept_bi().await.unwrap();
                let mut marker = [0; 5];
                rx.read_exact(&mut marker).await.unwrap();
                assert_eq!(&marker, b"plain");
                assert_eq!(gate.strict.load(Relaxed), 0);
                let mut chunks = [
                    bytes::Bytes::from_static(b"fin"),
                    bytes::Bytes::from_static(b"al"),
                ];
                let write =
                    std::future::poll_fn(|cx| carrier.poll_write_chunks(cx, &mut chunks, 0));
                assert_eq!(flow_observation::without_target_milestones(write).await?, 5);
                assert!(chunks.iter().all(bytes::Bytes::is_empty));
                Ok::<_, io::Error>(rx)
            };
            peer = Some(flow_observation::request_write(std::pin::pin!(write)).await?);
            Ok(ProxyStream {
                stream: Box::new(carrier),
                target_addr: server.remote_address(),
                target_domain: None,
            })
        };
        let mut tunnel = observer.scope(observe_chain_request(dial)).await.unwrap();
        gate.held().await;
        assert_eq!(sent(&events), 0);
        gate.release(None);
        wait_sent(&events).await;
        tunnel.stream.shutdown().await.unwrap();
        assert_eq!(peer.unwrap().read_to_end(5).await.unwrap(), b"final");
    })
    .await
    .expect("target masking or suppression lost the physical request boundary");
}

#[tokio::test]
async fn stopped_final_stream_preserves_ordinary_write_error() {
    timeout(TIMEOUT, async {
        let (client, server, gate) = connected().await;
        for (scatter, expected) in [
            (false, io::ErrorKind::ConnectionReset),
            (true, io::ErrorKind::Other),
        ] {
            for observed_attempt in [false, true] {
                let (mut tx, rx) = client.open_bi().await.unwrap();
                tx.write_all(b"open").await.unwrap();
                let (_reply, mut stop) = server.accept_bi().await.unwrap();
                let code = quinn::VarInt::from_u32(19);
                stop.stop(code).unwrap();
                assert_eq!(tx.stopped().await.unwrap(), Some(code));
                let (observer, events) = observed();
                let mut carrier = QuicBiStream::new(tx, rx);
                let dial = observe_chain_request(async {
                    if scatter {
                        let mut chunks = [bytes::Bytes::from_static(b"unchanged")];
                        let write = std::future::poll_fn(|cx| {
                            carrier.poll_write_chunks(cx, &mut chunks, 0)
                        });
                        let result = flow_observation::request_write(std::pin::pin!(write)).await;
                        assert_eq!(chunks[0].as_ref(), b"unchanged");
                        result?;
                        panic!("stopped scatter write succeeded");
                    }
                    trojan(carrier).await
                });
                let error = if observed_attempt {
                    observer.scope(dial).await
                } else {
                    dial.await
                }
                .unwrap_err();
                assert_eq!(error.downcast_ref::<io::Error>().unwrap().kind(), expected);
                assert!(!crate::proxy::node_failure(&error));
                assert_eq!(gate.strict.load(Relaxed), 0);
                assert_eq!(sent(&events), 0);
            }
        }
    })
    .await
    .expect("peer STOP did not reach the final write");
}

#[test]
fn socks_refusal_reaps_settled_submission_before_returning() {
    let runtime = || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    };
    let io = runtime();
    let receipts = runtime();
    io.block_on(async {
        timeout(TIMEOUT, async {
            for (reply, confirmed) in [(0x01, false), (0x01, true), (0x05, false), (0x05, true)] {
                let (client, server, gate) = connected().await;
                let carrier = stream(&client).await;
                let (observer, events) = observed();
                let node = crate::test_support::socks5("socks", "127.0.0.1", 1080);
                let dial = crate::proxy::socks5::Socks5Handler.dial_over(
                    crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap(),
                    Box::new(carrier),
                    "192.0.2.1:443".parse().unwrap(),
                    None,
                    TunnelDialOptions::new(TIMEOUT),
                );
                let mut dial = std::pin::pin!(observer.scope(observe_chain_request(dial)));
                // Only Quinn and the peer run. The dial gets polled but its spawned receipt
                // monitor cannot run: a synchronous reap must preserve the actual socket verdict.
                let foreground = std::future::poll_fn(|cx| {
                    let _scope = receipts.enter();
                    dial.as_mut().poll(cx)
                });
                let peer = async {
                    let (mut tx, mut rx) = server.accept_bi().await.unwrap();
                    let mut greeting = [0; 3];
                    rx.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    tx.write_all(&[5, 0]).await.unwrap();
                    gate.held().await;
                    gate.release(Some(confirmed));
                    let mut connect = [0; 10];
                    rx.read_exact(&mut connect).await.unwrap();
                    assert_eq!(connect, [5, 1, 0, 1, 192, 0, 2, 1, 1, 187]);
                    assert_eq!(sent(&events), 0);
                    tx.write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    tx.finish().unwrap();
                };
                let (result, ()) = tokio::join!(foreground, peer);
                let error = result.unwrap_err();
                assert!(
                    error.to_string().contains(&format!("(0x{reply:02x})")),
                    "{error}"
                );
                assert_eq!(crate::proxy::target_failure(&error), reply == 0x05);
                assert_eq!(sent(&events), usize::from(confirmed));
                assert_eq!(milestones(&events.lock(), Milestone::TargetConfirmed), 0);
            }
        })
        .await
        .expect("SOCKS refusal did not settle");
    });
}

#[tokio::test]
async fn graceful_final_websocket_close_keeps_the_attempts_pending_receipt() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    timeout(TIMEOUT, async {
        for (confirmed, cancelled) in [(true, false), (false, false), (true, true)] {
            let (client, server, gate) = connected().await;
            let dropped = Arc::new(Notify::new());
            let notify = dropped.clone();
            let carrier = stream(&client)
                .await
                .with_on_drop(move || notify.notify_one());
            let mut node = tls_node(Default::default());
            node.transport_mut().unwrap().transport = "ws".into();
            node.id = node.derive_id();
            let (observer, events) = observed();
            let dial = TrojanHandler.dial_over(
                crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap(),
                Box::new(carrier),
                "192.0.2.1:443".parse().unwrap(),
                None,
                TunnelDialOptions::new(TIMEOUT),
            );
            let (tunnel, mut peer) =
                tokio::join!(observer.scope(observe_chain_request(dial)), async {
                    let (tx, rx) = server.accept_bi().await.unwrap();
                    tokio_tungstenite::accept_async(QuicBiStream::new(tx, rx))
                        .await
                        .unwrap()
                });
            let mut tunnel = Some(tunnel.unwrap());
            gate.held().await;
            tunnel.as_mut().unwrap().stream.shutdown().await.unwrap();
            dropped.notified().await;
            assert_eq!(sent(&events), 0, "close is not a submission receipt");
            if cancelled {
                drop(tunnel.take());
            }
            gate.release(Some(confirmed));
            assert_eq!(
                peer.next().await.unwrap().unwrap(),
                Message::Binary(TROJAN.into())
            );
            assert!(matches!(peer.next().await, Some(Ok(Message::Close(_)))));
            if confirmed && !cancelled {
                wait_sent(&events).await;
            }
            assert_eq!(sent(&events), usize::from(confirmed && !cancelled));
            drop(tunnel);
        }
    })
    .await
    .expect("graceful close lost pending physical evidence or the payload");
}

#[cfg(feature = "owned-tasks")]
#[tokio::test]
async fn full_task_owner_survives_observed_final_quic_write() {
    timeout(TIMEOUT, async {
        let (client, server, gate) = connected().await;
        let owner = Arc::new(crate::runtime::TaskOwner::default());
        let scope = owner.task_scope();
        let (wake, woke) = oneshot::channel();
        let (alive, witness) = oneshot::channel();
        scope
            .spawn(async {
                woke.await.unwrap();
                alive.send(()).unwrap();
            })
            .unwrap();
        for _ in 1..256 {
            scope.spawn(std::future::pending()).unwrap();
        }
        for observed_attempt in [false, true] {
            let (observer, events) = observed();
            gate.hold();
            let mut other = client.open_uni().await.unwrap();
            let (_, unrelated) = other.write_with_receipt(b"other").await.unwrap();
            other.finish().unwrap();
            gate.held().await;
            let dial = observe_chain_request(trojan(stream(&client).await));
            let mut tunnel = if observed_attempt {
                owner.scope(observer.scope(dial)).await
            } else {
                owner.scope(dial).await
            }
            .unwrap();
            gate.release(Some(true));
            unrelated.await.unwrap();
            let mut sibling = server.accept_uni().await.unwrap();
            assert_eq!(sibling.id(), other.id());
            let mut bytes = [0; 5];
            sibling.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"other");
            assert_eq!(
                sent(&events),
                0,
                "another stream submitted after seal owes no request bytes"
            );
            if observed_attempt {
                gate.held().await;
                gate.release(None);
                wait_sent(&events).await;
            }
            tunnel.stream.shutdown().await.unwrap();
            let (_, mut rx) = server.accept_bi().await.unwrap();
            assert_eq!(rx.read_to_end(TROJAN.len()).await.unwrap(), TROJAN);
            assert_eq!(sent(&events), usize::from(observed_attempt));
        }
        wake.send(()).unwrap();
        witness
            .await
            .expect("receipt monitoring aborted an admitted sibling");
        owner.close().await;
    })
    .await
    .expect("full owner lost a normal dial or the receipt worker");
}

mod grpc;
mod pending_error;
#[cfg(feature = "rprx")]
mod vmess;
