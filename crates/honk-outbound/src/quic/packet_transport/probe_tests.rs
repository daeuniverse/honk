use super::super::{QuicClientOptions, client_config, testutil};
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn packet_rejection_survives_transport_error_storage() {
    let stored = TransportIoError::new(io::Error::from(PacketRejection::InvalidSize));
    assert_eq!(
        packet_error_class(&stored.to_io_error()),
        PacketErrorClass::Rejected
    );
}

#[derive(Debug)]
struct SendFailedPacketTransport(Option<PacketRejection>);

#[async_trait::async_trait]
impl PacketTransport for SendFailedPacketTransport {
    fn relay_addr(&self) -> SocketAddr {
        "127.0.0.1:443".parse().unwrap()
    }

    async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
        Err(match self.0 {
            Some(rejection) => rejection.into(),
            None => io::Error::new(
                io::ErrorKind::ConnectionReset,
                crate::proxy::NodeFailure(io::Error::from_raw_os_error(libc::ECONNRESET).into()),
            ),
        })
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
}

#[derive(Debug)]
struct ReceiveFailedPacketTransport;

#[async_trait::async_trait]
impl PacketTransport for ReceiveFailedPacketTransport {
    fn relay_addr(&self) -> SocketAddr {
        "127.0.0.1:443".parse().unwrap()
    }

    async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
        Ok(())
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::from(io::ErrorKind::ConnectionReset))
    }
}

#[derive(Debug)]
struct AdmissionPacketTransport {
    confirmed: AtomicUsize,
    ordinary: AtomicUsize,
    ordinary_sent: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl PacketTransport for AdmissionPacketTransport {
    fn relay_addr(&self) -> SocketAddr {
        "127.0.0.1:443".parse().unwrap()
    }

    async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
        self.ordinary.fetch_add(1, Ordering::SeqCst);
        self.ordinary_sent.notify_one();
        Ok(())
    }

    async fn send_packet_confirmed(&self, _data: &[u8]) -> io::Result<()> {
        self.confirmed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
}

#[derive(Debug)]
struct CongestedPacketTransport {
    sends: AtomicUsize,
    sent_after_congestion: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl PacketTransport for CongestedPacketTransport {
    fn relay_addr(&self) -> SocketAddr {
        "127.0.0.1:443".parse().unwrap()
    }

    fn send_timeout_is_congestion(&self) -> bool {
        true
    }

    async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
        if self.sends.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(io::Error::from(io::ErrorKind::TimedOut))
        } else {
            self.sent_after_congestion.notify_one();
            Ok(())
        }
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
}

#[derive(Debug)]
struct SequencePacketTransport {
    remote: SocketAddr,
    packets: Mutex<std::collections::VecDeque<(Vec<u8>, SocketAddr)>>,
    full_cone: bool,
}

#[async_trait::async_trait]
impl PacketTransport for SequencePacketTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.remote
    }

    fn allows_full_cone_replies(&self) -> bool {
        self.full_cone
    }

    async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Some((packet, source)) = self.packets.lock().await.pop_front() else {
            return std::future::pending().await;
        };
        let len = packet.len().min(buf.len());
        buf[..len].copy_from_slice(&packet[..len]);
        Ok((len, source))
    }
}

#[derive(Debug)]
struct UdpPacketTransport {
    socket: tokio::net::UdpSocket,
    remote: SocketAddr,
}

#[async_trait::async_trait]
impl PacketTransport for UdpPacketTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.remote
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.socket.send(data).await?;
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Ok((self.socket.recv(buf).await?, self.remote))
    }
}

#[tokio::test]
async fn packet_transport_failures_surface() {
    let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let transmit = quinn::udp::Transmit {
        destination: remote,
        ecn: None,
        contents: b"initial",
        segment_size: None,
        src_ip: None,
    };
    let send_socket = TransportQuinnSocket::new(Arc::new(SendFailedPacketTransport(None)), remote);
    quinn::AsyncUdpSocket::try_send(&*send_socket, &transmit).unwrap();

    let mut data = [0; 64];
    let mut meta = [quinn::udp::RecvMeta::default()];
    let send_error = tokio::time::timeout(
        Duration::from_secs(1),
        std::future::poll_fn(|cx| {
            let mut bufs = [std::io::IoSliceMut::new(&mut data)];
            quinn::AsyncUdpSocket::poll_recv(&*send_socket, cx, &mut bufs, &mut meta)
        }),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(send_error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(
        quinn::AsyncUdpSocket::try_send(&*send_socket, &transmit)
            .unwrap_err()
            .kind(),
        io::ErrorKind::ConnectionAborted
    );

    let recv_socket = TransportQuinnSocket::new(Arc::new(ReceiveFailedPacketTransport), remote);
    let recv_error = tokio::time::timeout(
        Duration::from_secs(1),
        std::future::poll_fn(|cx| {
            let mut bufs = [std::io::IoSliceMut::new(&mut data)];
            quinn::AsyncUdpSocket::poll_recv(&*recv_socket, cx, &mut bufs, &mut meta)
        }),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(recv_error.kind(), io::ErrorKind::ConnectionAborted);
}

#[tokio::test]
async fn endpoint_retains_worker_cause_and_rejection() {
    use crate::group::ScoreOutcome;
    let remote = "127.0.0.1:443".parse().unwrap();
    for rejection in [None, Some(PacketRejection::Capacity)] {
        let endpoint =
            packet_transport_endpoint(Arc::new(SendFailedPacketTransport(rejection)), remote)
                .unwrap();
        quinn::AsyncUdpSocket::try_send(
            &*endpoint.socket,
            &quinn::udp::Transmit {
                destination: remote,
                ecn: None,
                contents: b"initial",
                segment_size: None,
                src_ip: None,
            },
        )
        .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(error) = endpoint.terminal_error() {
                    break error;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        if rejection.is_some() {
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert_eq!(packet_error_class(&error), PacketErrorClass::Rejected);
            assert_eq!(ScoreOutcome::from_io_error(&error), ScoreOutcome::Rejected);
        } else {
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            assert!(ScoreOutcome::from_io_error(&error).is_node_failure());
            assert_eq!(
                anyhow::Error::new(error)
                    .root_cause()
                    .downcast_ref::<io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::ECONNRESET)
            );
        }
        endpoint.close(Duration::ZERO).await;
    }
}

#[tokio::test]
async fn zero_timeout_close_does_not_surface_adapter_error() {
    let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let endpoint = packet_transport_endpoint(
        Arc::new(AdmissionPacketTransport {
            confirmed: AtomicUsize::new(0),
            ordinary: AtomicUsize::new(0),
            ordinary_sent: tokio::sync::Notify::new(),
        }),
        remote,
    )
    .unwrap();

    endpoint.close(Duration::ZERO).await;
    tokio::task::yield_now().await;

    let mut data = [0; 1];
    let mut meta = [quinn::udp::RecvMeta::default()];
    let receive = tokio::time::timeout(
        Duration::from_millis(10),
        std::future::poll_fn(|cx| {
            let mut bufs = [std::io::IoSliceMut::new(&mut data)];
            quinn::AsyncUdpSocket::poll_recv(&*endpoint.socket, cx, &mut bufs, &mut meta)
        }),
    )
    .await;
    assert!(
        receive.is_err(),
        "graceful close surfaced an adapter I/O error"
    );
}

#[tokio::test]
async fn packet_transport_congestion_drops_only_one_datagram() {
    let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let transport = Arc::new(CongestedPacketTransport {
        sends: AtomicUsize::new(0),
        sent_after_congestion: tokio::sync::Notify::new(),
    });
    let socket = TransportQuinnSocket::new(transport.clone(), remote);
    for contents in [b"dropped".as_slice(), b"forwarded".as_slice()] {
        quinn::AsyncUdpSocket::try_send(
            &*socket,
            &quinn::udp::Transmit {
                destination: remote,
                ecn: None,
                contents,
                segment_size: None,
                src_ip: None,
            },
        )
        .unwrap();
    }

    tokio::time::timeout(
        Duration::from_secs(1),
        transport.sent_after_congestion.notified(),
    )
    .await
    .unwrap();
    assert_eq!(transport.sends.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn packet_transport_confirms_only_the_first_datagram() {
    let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let transport = Arc::new(AdmissionPacketTransport {
        confirmed: AtomicUsize::new(0),
        ordinary: AtomicUsize::new(0),
        ordinary_sent: tokio::sync::Notify::new(),
    });
    let socket = TransportQuinnSocket::new(transport.clone(), remote);
    for contents in [b"first".as_slice(), b"second".as_slice()] {
        quinn::AsyncUdpSocket::try_send(
            &*socket,
            &quinn::udp::Transmit {
                destination: remote,
                ecn: None,
                contents,
                segment_size: None,
                src_ip: None,
            },
        )
        .unwrap();
    }

    tokio::time::timeout(Duration::from_secs(1), transport.ordinary_sent.notified())
        .await
        .unwrap();
    assert_eq!(transport.confirmed.load(Ordering::SeqCst), 1);
    assert_eq!(transport.ordinary.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn packet_transport_socket_is_peer_pinned_and_family_matched() {
    let remote: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
    let wrong: SocketAddr = "[2001:db8::3]:443".parse().unwrap();
    let socket = TransportQuinnSocket::new(
        Arc::new(SequencePacketTransport {
            remote,
            full_cone: false,
            packets: Mutex::new(std::collections::VecDeque::from([
                (b"wrong".to_vec(), wrong),
                (vec![0x5a; 65], remote),
            ])),
        }),
        remote,
    );
    assert!(
        quinn::AsyncUdpSocket::local_addr(&*socket)
            .unwrap()
            .is_ipv6()
    );

    let error = quinn::AsyncUdpSocket::try_send(
        &*socket,
        &quinn::udp::Transmit {
            destination: wrong,
            ecn: None,
            contents: b"wrong peer",
            segment_size: None,
            src_ip: None,
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

    let mut data = [0u8; 64];
    let mut meta = [quinn::udp::RecvMeta::default()];
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        std::future::poll_fn(|cx| {
            let mut bufs = [std::io::IoSliceMut::new(&mut data)];
            quinn::AsyncUdpSocket::poll_recv(&*socket, cx, &mut bufs, &mut meta)
        }),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn packet_transport_socket_accepts_full_cone_reply_metadata() {
    let remote: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
    let reply_source: SocketAddr = "[2001:db8::3]:443".parse().unwrap();
    let socket = TransportQuinnSocket::new(
        Arc::new(SequencePacketTransport {
            remote,
            packets: Mutex::new(std::collections::VecDeque::from([(
                b"accepted".to_vec(),
                reply_source,
            )])),
            full_cone: true,
        }),
        remote,
    );
    let mut data = [0; 64];
    let mut meta = [quinn::udp::RecvMeta::default()];

    let received = tokio::time::timeout(
        Duration::from_secs(1),
        std::future::poll_fn(|cx| {
            let mut bufs = [std::io::IoSliceMut::new(&mut data)];
            quinn::AsyncUdpSocket::poll_recv(&*socket, cx, &mut bufs, &mut meta)
        }),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(received, 1);
    assert_eq!(&data[..meta[0].len], b"accepted");
    assert_eq!(meta[0].addr, remote);
}

#[tokio::test]
async fn handshake_crosses_packet_transport_adapter() {
    let (server, remote) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let server_task = tokio::spawn(async move {
        server.accept().await.unwrap().await.unwrap();
    });
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(remote).await.unwrap();
    let mut node = honk_config::node::Node {
        outbound: honk_config::node::OutboundConfig::Hysteria2(Default::default()),
        ..Default::default()
    };
    let tls = node.tls_mut().unwrap();
    tls.sni = Some("localhost".into());
    tls.skip_cert_verify = true;
    let config = client_config(&node, &[b"h3"], QuicClientOptions::default())
        .await
        .unwrap();

    quic_handshake_probe(
        Arc::new(UdpPacketTransport { socket, remote }),
        remote,
        "localhost",
        &config,
        Duration::from_secs(5),
        crate::alive::ProbeCancellation::default(),
    )
    .await
    .unwrap();
    server_task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn silent_handshake_timeout_does_not_retire_health_owner() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = peer.local_addr().unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(remote).await.unwrap();
        let transport = Arc::new(UdpPacketTransport { socket, remote });
        let retained = Arc::downgrade(&transport);
        let node = honk_config::node::Node {
            outbound: honk_config::node::OutboundConfig::Hysteria2(Default::default()),
            ..Default::default()
        };
        let mut config = client_config(&node, &[b"h3"], QuicClientOptions::default())
            .await
            .unwrap();
        let mut timing = quinn::TransportConfig::default();
        timing.initial_rtt(Duration::from_secs(1));
        config.transport_config(Arc::new(timing));
        let owner = Arc::new(crate::alive::AliveDialerSet::new());
        let request = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move {
                owner
                    .run_external_probe(move |cancel| async move {
                        quic_handshake_probe(
                            transport,
                            remote,
                            "localhost",
                            &config,
                            Duration::from_millis(10),
                            cancel,
                        )
                        .await
                    })
                    .await
            }
        });
        let mut initial = [0; 1500];
        let (received, _) = peer.recv_from(&mut initial).await.unwrap();
        assert!(
            received >= 1200,
            "a real QUIC Initial reached the silent peer"
        );
        let error = request.await.unwrap().unwrap().unwrap_err();
        assert!(error.to_string().contains("QUIC handshake timeout"));
        assert!(
            retained.upgrade().is_none(),
            "measurement completion must join the transport workers"
        );
        assert_eq!(owner.run_external_probe(|_| async { 42 }).await, Ok(42));
        owner.shutdown_health_checks().await.unwrap();
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct PanicReceiveTransport {
    inner: UdpPacketTransport,
    panicked: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl PacketTransport for PanicReceiveTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.inner.remote
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.inner.send_packet(data).await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_packet(buf).await?;
        self.panicked.notify_one();
        panic!("injected packet receiver panic");
    }
}

#[tokio::test]
async fn endpoint_close_keeps_worker_panic_failure_after_first_join() {
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = peer.local_addr().unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(remote).await.unwrap();
    peer.send_to(b"panic", socket.local_addr().unwrap())
        .await
        .unwrap();
    let panicked = Arc::new(tokio::sync::Notify::new());
    let endpoint = packet_transport_endpoint(
        Arc::new(PanicReceiveTransport {
            inner: UdpPacketTransport { socket, remote },
            panicked: Arc::clone(&panicked),
        }),
        remote,
    )
    .unwrap();
    panicked.notified().await;
    assert!(!endpoint.close(Duration::from_secs(1)).await);
    assert!(!endpoint.close(Duration::from_secs(1)).await);
}

#[derive(Debug)]
struct PanicDriverRuntime {
    inner: Arc<dyn quinn::Runtime>,
    panicked: Arc<tokio::sync::Notify>,
}

impl quinn::Runtime for PanicDriverRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        self.inner.new_timer(deadline)
    }

    fn spawn(&self, mut future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let panicked = Arc::clone(&self.panicked);
        self.inner.spawn(Box::pin(async move {
            std::future::poll_fn(|cx| {
                let _ = future.as_mut().poll(cx);
                Poll::Ready(())
            })
            .await;
            // Inject outside Quinn's mutexes, which intentionally poison on panic.
            drop(future);
            panicked.notify_one();
            panic!("injected Quinn driver-task panic");
        }));
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        self.inner.wrap_udp_socket(socket)
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }
}

#[tokio::test]
async fn endpoint_close_retains_quinn_driver_panic_in_both_owners() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = peer.local_addr().unwrap();
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.connect(remote).await.unwrap();
        let parent = Arc::new(crate::runtime::TaskOwner::production());
        let drivers = Arc::new(crate::runtime::TaskOwner::production());
        let panicked = Arc::new(tokio::sync::Notify::new());
        let runtime = Arc::new(PanicDriverRuntime {
            inner: Arc::new(PacketTransportRuntime {
                inner: quinn::default_runtime().unwrap(),
                tasks: Arc::downgrade(&drivers),
                parent: Some(Arc::downgrade(&parent)),
            }),
            panicked: Arc::clone(&panicked),
        });
        let (socket, sender, receiver) = TransportQuinnSocket::prepare(
            Arc::new(UdpPacketTransport {
                socket: udp,
                remote,
            }),
            remote,
            false,
        );
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config_with_mtu(1252).unwrap(),
            None,
            socket.clone(),
            runtime,
        )
        .unwrap();
        socket
            .start_workers(Some(&parent), sender, receiver)
            .unwrap();
        let endpoint = PacketTransportEndpoint {
            endpoint,
            socket,
            drivers,
        };
        panicked.notified().await;
        assert!(!endpoint.close(Duration::from_millis(1)).await);
        assert!(!endpoint.close(Duration::from_millis(1)).await);
        parent.close().await;
        assert!(
            parent.has_failed(),
            "parent teardown must retain driver failure"
        );
    })
    .await
    .unwrap();
}
