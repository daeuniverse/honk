use super::*;

use anyhow::Context as _;

use crate::proxy::{PacketErrorClass, PacketTransport, QuicSendAttempt, packet_error_class};

/// quinn [`AsyncUdpSocket`] over a framed [`PacketTransport`]: outbound
/// datagrams ride a bounded channel drained by a forwarder task (the
/// transport's async send cannot run in a poll context), while inbound
/// datagrams are accepted only from the configured QUIC peer.
const TRANSPORT_QUEUE_CAP: usize = 64;
/// A queued QUIC datagram must not wait behind a full adapter queue longer
/// than the longest per-packet send deadline.
const TRANSPORT_PACKET_MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct QueuedTransportPacket {
    data: Vec<u8>,
    enqueued_at: Instant,
}

#[derive(Debug)]
struct TransportIoError {
    kind: io::ErrorKind,
    message: String,
}

impl TransportIoError {
    fn new(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn fatal(error: io::Error) -> Self {
        let mut error = Self::new(error);
        // Quinn deliberately ignores UDP ECONNRESET on its receive path, but
        // every worker error exposed here has already terminated the adapter.
        if error.kind == io::ErrorKind::ConnectionReset {
            error.kind = io::ErrorKind::ConnectionAborted;
        }
        error
    }

    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

type SharedRecvWaker = Arc<SyncMutex<Option<Waker>>>;

fn wake_recv(waker: &SharedRecvWaker) {
    let waker = waker.lock().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}
type SharedTransportError = Arc<SyncMutex<Option<TransportIoError>>>;

#[derive(Debug)]
struct TransportQuinnSocket {
    remote: SocketAddr,
    outbound: tokio::sync::mpsc::Sender<QueuedTransportPacket>,
    inbound: SyncMutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    send_error: SharedTransportError,
    recv_error: SharedTransportError,
    recv_waker: SharedRecvWaker,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    metrics_enabled: bool,
}

impl TransportQuinnSocket {
    fn new(transport: Arc<dyn PacketTransport>, remote: SocketAddr) -> Arc<Self> {
        Self::new_with_metrics(transport, remote, false)
    }

    fn new_with_metrics(
        transport: Arc<dyn PacketTransport>,
        remote: SocketAddr,
        metrics_enabled: bool,
    ) -> Arc<Self> {
        let (outbound_tx, mut outbound_rx) =
            tokio::sync::mpsc::channel::<QueuedTransportPacket>(TRANSPORT_QUEUE_CAP);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(TRANSPORT_QUEUE_CAP);
        let send_error = Arc::new(SyncMutex::new(None));
        let recv_error = Arc::new(SyncMutex::new(None));
        let recv_waker = Arc::new(SyncMutex::new(None));
        let sender = tokio::spawn({
            let transport = Arc::clone(&transport);
            let send_error = Arc::clone(&send_error);
            let recv_waker = Arc::clone(&recv_waker);
            async move {
                let mut first_datagram = true;
                while let Some(queued) = outbound_rx.recv().await {
                    if queued.enqueued_at.elapsed() >= TRANSPORT_PACKET_MAX_AGE {
                        if metrics_enabled {
                            record_transport_tx_drop();
                        }
                        continue;
                    }
                    let first = first_datagram;
                    let data = queued.data;
                    let timeout = transport.send_timeout().max(Duration::from_millis(1));
                    let attempt = QuicSendAttempt::new(transport.as_ref());
                    let result = tokio::time::timeout(timeout, async {
                        if first {
                            transport.send_packet_confirmed(&data).await
                        } else {
                            transport.send_packet(&data).await
                        }
                    })
                    .await;
                    let timed_out = match &result {
                        Err(_) => true,
                        Ok(Err(error)) => error.kind() == io::ErrorKind::TimedOut,
                        Ok(Ok(())) => false,
                    };
                    let result = match result {
                        Ok(result) => result,
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "QUIC PacketTransport send deadline exceeded",
                        )),
                    };
                    match result {
                        Ok(()) => {
                            first_datagram = false;
                            attempt.success();
                        }
                        Err(error) => {
                            if timed_out {
                                attempt.timeout();
                            } else {
                                attempt.failure();
                            }
                            let congestion = packet_error_class(&error)
                                == PacketErrorClass::Congestion
                                || (error.kind() == io::ErrorKind::TimedOut
                                    && transport.send_timeout_is_congestion());
                            if congestion {
                                if metrics_enabled {
                                    record_transport_tx_drop();
                                }
                                continue;
                            }
                            *send_error.lock() = Some(TransportIoError::fatal(error));
                            wake_recv(&recv_waker);
                            outbound_rx.close();
                            return;
                        }
                    }
                }
            }
        });
        let allows_full_cone_replies = transport.allows_full_cone_replies();
        let receiver = tokio::spawn({
            let recv_error = Arc::clone(&recv_error);
            let recv_waker = Arc::clone(&recv_waker);
            async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let (n, source) = match transport.recv_packet(&mut buf).await {
                        Ok(packet) => packet,
                        Err(error) => {
                            *recv_error.lock() = Some(TransportIoError::fatal(error));
                            wake_recv(&recv_waker);
                            return;
                        }
                    };
                    if n == 0 {
                        continue;
                    }
                    if source != remote && !allows_full_cone_replies {
                        continue;
                    }
                    if n > buf.len() {
                        *recv_error.lock() = Some(TransportIoError::fatal(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "PacketTransport returned a datagram larger than its receive buffer",
                        )));
                        wake_recv(&recv_waker);
                        return;
                    }
                    // A full queue drops the datagram (UDP semantics); the
                    // transport read must never backpressure or allocate for a drop.
                    match inbound_tx.try_reserve() {
                        Ok(permit) => permit.send(buf[..n].to_vec()),
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            if metrics_enabled {
                                record_transport_rx_drop();
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            *recv_error.lock() = Some(TransportIoError::fatal(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "QUIC adapter receive queue closed",
                            )));
                            wake_recv(&recv_waker);
                            return;
                        }
                    }
                }
            }
        });
        Arc::new(Self {
            remote,
            outbound: outbound_tx,
            inbound: SyncMutex::new(inbound_rx),
            send_error,
            recv_error,
            recv_waker,
            tasks: Mutex::new(vec![sender, receiver]),
            metrics_enabled,
        })
    }

    fn send_error(&self) -> Option<io::Error> {
        self.send_error
            .lock()
            .as_ref()
            .map(TransportIoError::to_io_error)
    }

    fn recv_error(&self) -> Option<io::Error> {
        self.recv_error
            .lock()
            .as_ref()
            .map(TransportIoError::to_io_error)
    }

    fn terminal_error(&self) -> Option<io::Error> {
        self.recv_error().or_else(|| self.send_error())
    }

    async fn close_tasks(&self) {
        let mut tasks = self.tasks.lock().await;
        for task in tasks.iter() {
            task.abort();
        }
        for task in tasks.iter_mut() {
            let _ = task.await;
        }
        tasks.clear();
    }
}

impl Drop for TransportQuinnSocket {
    fn drop(&mut self) {
        for task in self.tasks.get_mut().drain(..) {
            task.abort();
        }
    }
}

type TransportSendPermit = Result<
    tokio::sync::mpsc::OwnedPermit<QueuedTransportPacket>,
    tokio::sync::mpsc::error::SendError<()>,
>;

struct TransportUdpPoller {
    socket: Arc<TransportQuinnSocket>,
    writable: SyncMutex<Option<Pin<Box<dyn Future<Output = TransportSendPermit> + Send>>>>,
}

impl std::fmt::Debug for TransportUdpPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportUdpPoller").finish_non_exhaustive()
    }
}

impl quinn::UdpPoller for TransportUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.socket.send_error() {
            *this.writable.lock() = None;
            return Poll::Ready(Err(error));
        }

        let mut writable = this.writable.lock();
        if writable.is_none() {
            *writable = Some(Box::pin(this.socket.outbound.clone().reserve_owned()));
        }
        match writable.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(permit)) => {
                drop(permit);
                *writable = None;
                Poll::Ready(this.socket.send_error().map_or(Ok(()), Err))
            }
            Poll::Ready(Err(_)) => {
                *writable = None;
                Poll::Ready(Err(this
                    .socket
                    .send_error()
                    .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))))
            }
        }
    }
}
impl quinn::AsyncUdpSocket for TransportQuinnSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(TransportUdpPoller {
            socket: self,
            writable: SyncMutex::new(None),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        if transmit.destination != self.remote {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PacketTransport QUIC destination does not match its peer",
            ));
        }
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PacketTransport QUIC does not support segmented transmits",
            ));
        }
        if let Some(error) = self.send_error() {
            return Err(error);
        }

        match self.outbound.try_reserve() {
            Ok(permit) => {
                permit.send(QueuedTransportPacket {
                    data: transmit.contents.to_vec(),
                    enqueued_at: Instant::now(),
                });
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                if self.metrics_enabled {
                    record_transport_tx_would_block();
                }
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(self
                .send_error()
                .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))),
        }
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.terminal_error() {
            return Poll::Ready(Err(error));
        }
        *self.recv_waker.lock() = Some(cx.waker().clone());
        if let Some(error) = self.terminal_error() {
            return Poll::Ready(Err(error));
        }

        let mut inbound = self.inbound.lock();
        let mut count = 0;
        for (buf, meta_slot) in bufs.iter_mut().zip(meta.iter_mut()) {
            match inbound.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    // The endpoint advertises a 1252-byte receive buffer. Never hand Quinn a
                    // truncated packet: a partial QUIC packet is indistinguishable from wire
                    // corruption. Fail the adapter so the caller can redial with a safe path.
                    if data.len() > buf.len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "PacketTransport returned a datagram larger than the QUIC receive buffer",
                        )));
                    }
                    let len = data.len();
                    buf[..len].copy_from_slice(&data);
                    *meta_slot = quinn::udp::RecvMeta {
                        addr: self.remote,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    count += 1;
                }
                Poll::Ready(None) => {
                    return if count == 0 {
                        Poll::Ready(Err(self
                            .terminal_error()
                            .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))))
                    } else {
                        Poll::Ready(Ok(count))
                    };
                }
                Poll::Pending => {
                    if count != 0 {
                        return Poll::Ready(Ok(count));
                    }
                    drop(inbound);
                    return if let Some(error) = self.terminal_error() {
                        Poll::Ready(Err(error))
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // There is no kernel socket; quinn uses this only to validate the
        // endpoint's address family.
        let ip: std::net::IpAddr = match self.remote {
            SocketAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
            SocketAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
        };
        Ok(SocketAddr::new(ip, 0))
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

/// Owns a client-only quinn endpoint and the bounded [`PacketTransport`]
/// adapter workers that drive it.
#[derive(Debug)]
pub struct PacketTransportEndpoint {
    endpoint: Endpoint,
    socket: Arc<TransportQuinnSocket>,
}

impl PacketTransportEndpoint {
    /// Borrow the Quinn endpoint. Keep this owner alive as long as any
    /// connection opened from it can still perform I/O.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Close the Quinn endpoint and wait up to `timeout` for it to drain.
    /// A zero timeout leaves the adapter workers alive until Quinn releases
    /// the socket; other closes abort and join them.
    pub async fn close(&self, timeout: Duration) {
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
        if timeout.is_zero() {
            return;
        }
        let _ = tokio::time::timeout(timeout, self.endpoint.wait_idle()).await;
        self.socket.close_tasks().await;
    }
}

/// Create a [`PacketTransportEndpoint`] pinned to `remote` with the safe
/// 1252-byte UDP payload cap. Metrics are disabled because this constructor is
/// also used by temporary health probes.
pub fn packet_transport_endpoint(
    transport: Arc<dyn PacketTransport>,
    remote: SocketAddr,
) -> io::Result<PacketTransportEndpoint> {
    packet_transport_endpoint_with_metrics(transport, remote, false)
}

/// Create a packet-backed endpoint whose adapter pressure counters belong to a
/// persistent pooled DNS connection.
pub fn packet_transport_endpoint_with_metrics(
    transport: Arc<dyn PacketTransport>,
    remote: SocketAddr,
    metrics_enabled: bool,
) -> io::Result<PacketTransportEndpoint> {
    if transport.relay_addr() != remote {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PacketTransport relay address does not match the QUIC peer",
        ));
    }
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
    let socket = if metrics_enabled {
        TransportQuinnSocket::new_with_metrics(transport, remote, true)
    } else {
        TransportQuinnSocket::new(transport, remote)
    };
    let endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config_with_mtu(1252)?,
        None,
        socket.clone(),
        runtime,
    )?;
    Ok(PacketTransportEndpoint { endpoint, socket })
}

/// Establish a QUIC connection through a proxied UDP tunnel and time the
/// handshake.  This is the real QUIC liveness probe: unlike a bare
/// Version-Negotiation trigger (which many frontends ignore), it proves
/// TLS-in-QUIC reachability through the node's UDP path.  `config` comes from
/// [`client_config`] — pass a node with `skip_cert_verify` for pure liveness
/// probing.
pub async fn quic_handshake_probe(
    transport: Arc<dyn PacketTransport>,
    target: SocketAddr,
    server_name: &str,
    config: &ClientConfig,
    timeout: Duration,
) -> anyhow::Result<Duration> {
    let endpoint = packet_transport_endpoint(transport, target)?;

    let start = Instant::now();
    let connecting = endpoint
        .endpoint()
        .connect_with(config.clone(), target, server_name)
        .context("create QUIC connecting")?;
    let conn = tokio::time::timeout(timeout, connecting)
        .await
        .context("QUIC handshake timeout")??;
    let elapsed = start.elapsed();
    conn.close(quinn::VarInt::from_u32(0), b"probe");
    drop(conn);
    endpoint.close(Duration::ZERO).await;
    Ok(elapsed)
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    #[derive(Debug)]
    struct SendFailedPacketTransport;

    #[async_trait::async_trait]
    impl PacketTransport for SendFailedPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            "127.0.0.1:443".parse().unwrap()
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
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
        let send_socket = TransportQuinnSocket::new(Arc::new(SendFailedPacketTransport), remote);
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
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }
}
