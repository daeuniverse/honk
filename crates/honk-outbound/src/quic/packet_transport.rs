use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use parking_lot::Mutex as SyncMutex;
use quinn::{ClientConfig, Endpoint, VarInt};
#[cfg(test)]
use tokio::sync::Mutex;

use super::endpoint::endpoint_config_with_mtu;
use super::metrics::{
    record_transport_rx_drop, record_transport_tx_drop, record_transport_tx_would_block,
};

use crate::proxy::{
    PacketErrorClass, PacketRejection, PacketTransport, QuicSendAttempt, io_packet_rejection,
    packet_error_class,
};

/// quinn [`AsyncUdpSocket`] over a framed [`PacketTransport`]: outbound
/// datagrams ride a bounded channel drained by a forwarder task (the
/// transport's async send cannot run in a poll context), while inbound
/// datagrams are accepted only from the configured QUIC peer.
const TRANSPORT_QUEUE_CAP: usize = 64;
/// A queued QUIC datagram must not wait behind a full adapter queue longer
/// than the longest per-packet send deadline.
const TRANSPORT_PACKET_MAX_AGE: Duration = Duration::from_secs(5);
/// The receive worker yields after this many transport reads: a transport that
/// never returns `Pending` would otherwise overflow the 64-packet queue and
/// drop the rest of a burst before the endpoint driver can run.
const RECV_YIELD_EVERY: u32 = 32;

#[derive(Debug)]
struct QueuedTransportPacket {
    data: Vec<u8>,
    enqueued_at: Instant,
}

#[derive(Debug)]
struct TransportIoError {
    kind: io::ErrorKind,
    cause: crate::SharedError,
    rejection: Option<PacketRejection>,
}

impl TransportIoError {
    fn new(error: io::Error) -> Self {
        let rejection = io_packet_rejection(&error);
        Self {
            kind: error.kind(),
            cause: crate::SharedError::fanout(error.into()),
            rejection,
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
        self.rejection.map_or_else(
            || io::Error::new(self.kind, self.cause.clone()),
            io::Error::from,
        )
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
    tasks: std::sync::OnceLock<[crate::runtime::SharedTask; 2]>,
    metrics_enabled: bool,
}

impl TransportQuinnSocket {
    #[cfg(test)]
    fn new(transport: Arc<dyn PacketTransport>, remote: SocketAddr) -> Arc<Self> {
        let (socket, sender, receiver) = Self::prepare(transport, remote, false);
        socket.start_workers(None, sender, receiver).unwrap();
        socket
    }

    fn prepare(
        transport: Arc<dyn PacketTransport>,
        remote: SocketAddr,
        metrics_enabled: bool,
    ) -> (
        Arc<Self>,
        impl Future<Output = ()> + Send + 'static,
        impl Future<Output = ()> + Send + 'static,
    ) {
        let (outbound_tx, mut outbound_rx) =
            tokio::sync::mpsc::channel::<QueuedTransportPacket>(TRANSPORT_QUEUE_CAP);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(TRANSPORT_QUEUE_CAP);
        let send_error = Arc::new(SyncMutex::new(None));
        let recv_error = Arc::new(SyncMutex::new(None));
        let recv_waker = Arc::new(SyncMutex::new(None));
        let sender = {
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
        };
        let allows_full_cone_replies = transport.allows_full_cone_replies();
        let receiver = {
            let recv_error = Arc::clone(&recv_error);
            let recv_waker = Arc::clone(&recv_waker);
            async move {
                let mut buf = vec![0u8; 65536];
                let mut since_yield = 0;
                loop {
                    if since_yield == RECV_YIELD_EVERY {
                        since_yield = 0;
                        tokio::task::yield_now().await;
                    }
                    let (n, source) = match transport.recv_packet(&mut buf).await {
                        Ok(packet) => packet,
                        Err(error) => {
                            *recv_error.lock() = Some(TransportIoError::fatal(error));
                            wake_recv(&recv_waker);
                            return;
                        }
                    };
                    since_yield += 1;
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
        };
        let socket = Arc::new(Self {
            remote,
            outbound: outbound_tx,
            inbound: SyncMutex::new(inbound_rx),
            send_error,
            recv_error,
            recv_waker,
            tasks: std::sync::OnceLock::new(),
            metrics_enabled,
        });
        (socket, sender, receiver)
    }

    fn start_workers(
        &self,
        owner: Option<&Arc<crate::runtime::TaskOwner>>,
        sender: impl Future<Output = ()> + Send + 'static,
        receiver: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<()> {
        let sender = crate::runtime::spawn_joinable(owner, sender)?;
        let receiver = match crate::runtime::spawn_joinable(owner, receiver) {
            Ok(receiver) => receiver,
            Err(error) => {
                sender.abort();
                return Err(error);
            }
        };
        self.tasks
            .set([sender, receiver])
            .expect("workers start once");
        Ok(())
    }

    fn send_error(&self) -> Option<io::Error> {
        self.send_error
            .lock()
            .as_ref()
            .map(TransportIoError::to_io_error)
    }

    /// The send queue is closed: the stored cause, else a broken pipe.
    fn closed_send_error(&self) -> io::Error {
        self.send_error()
            .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    /// A reserved slot means writable only while no fatal send error is stored.
    fn writable_unless_failed(&self) -> io::Result<()> {
        self.send_error().map_or(Ok(()), Err)
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

    async fn close_tasks(&self) -> bool {
        let mut joined = true;
        for task in self.tasks.get().into_iter().flatten() {
            task.abort();
        }
        for task in self.tasks.get().into_iter().flatten() {
            joined &= task.join().await;
        }
        joined
    }
}

impl Drop for TransportQuinnSocket {
    fn drop(&mut self) {
        for task in self.tasks.get().into_iter().flatten() {
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
            // Spare capacity is the common case: admit it without building a
            // reservation future, but keep charging Tokio's cooperative budget
            // so a driver that polls readiness in a loop still yields.
            let coop = std::task::ready!(tokio::task::coop::poll_proceed(cx));
            match this.socket.outbound.try_reserve() {
                // Dropping `coop` refunds the charge; the future charges its own polls.
                Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {}
                reserved => {
                    coop.made_progress();
                    return Poll::Ready(match reserved {
                        Ok(_) => this.socket.writable_unless_failed(),
                        Err(_) => Err(this.socket.closed_send_error()),
                    });
                }
            }
            *writable = Some(Box::pin(this.socket.outbound.clone().reserve_owned()));
        }
        match writable.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(permit)) => {
                drop(permit);
                *writable = None;
                Poll::Ready(this.socket.writable_unless_failed())
            }
            Poll::Ready(Err(_)) => {
                *writable = None;
                Poll::Ready(Err(this.socket.closed_send_error()))
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
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(self.closed_send_error()),
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

#[derive(Debug)]
struct PacketTransportRuntime {
    inner: Arc<dyn quinn::Runtime>,
    tasks: std::sync::Weak<crate::runtime::TaskOwner>,
    parent: Option<std::sync::Weak<crate::runtime::TaskOwner>>,
}

impl quinn::Runtime for PacketTransportRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        self.inner.new_timer(deadline)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let Some(tasks) = self.tasks.upgrade() else {
            return;
        };
        let (start, started) = tokio::sync::oneshot::channel();
        let Ok(task) = crate::runtime::spawn_joinable(Some(&tasks), async move {
            if started.await.is_ok() {
                future.await;
            }
        }) else {
            return;
        };
        if self.parent.as_ref().is_some_and(|parent| {
            parent
                .upgrade()
                .is_none_or(|parent| !parent.retain_joinable(task.clone()))
        }) {
            task.abort();
            return;
        }
        let _ = start.send(());
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

/// Owns a client-only quinn endpoint, its drivers, and the bounded
/// [`PacketTransport`] adapter workers that drive it.
#[derive(Debug)]
pub struct PacketTransportEndpoint {
    endpoint: Endpoint,
    socket: Arc<TransportQuinnSocket>,
    drivers: Arc<crate::runtime::TaskOwner>,
}

impl PacketTransportEndpoint {
    /// Borrow the Quinn endpoint. Keep this owner alive as long as any
    /// connection opened from it can still perform I/O.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Recover an already-recorded packet-carrier failure when Quinn reports
    /// only endpoint loss. This does not probe or close the transport.
    pub fn terminal_error(&self) -> Option<io::Error> {
        self.socket.terminal_error()
    }

    /// Request closure, allow `timeout` for peer notification, then stop and join
    /// adapter workers and Quinn drivers. Returns false only for a worker panic.
    /// Zero only requests closure; retained owners still own all jobs.
    pub async fn close(&self, timeout: Duration) -> bool {
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
        if timeout.is_zero() {
            return true;
        }
        // Quinn's normal close linger is three PTOs and may exceed the grace.
        // Expiry ends peer notification, not successful owned teardown.
        let _ = tokio::time::timeout(timeout, self.endpoint.wait_idle()).await;
        let joined = self.socket.close_tasks().await;
        self.drivers.close().await;
        joined && !self.drivers.has_failed()
    }
}

/// Create a [`PacketTransportEndpoint`] pinned to `remote` with the safe
/// 1252-byte UDP payload cap. Metrics are disabled because this constructor is
/// also used by temporary health probes.
pub fn packet_transport_endpoint(
    transport: Arc<dyn PacketTransport>,
    remote: SocketAddr,
) -> io::Result<PacketTransportEndpoint> {
    packet_transport_endpoint_with_metrics(transport, remote, false, None)
}

/// Create a packet-backed endpoint whose adapter pressure counters belong to a
/// persistent pooled DNS connection.
/// `owner` retains unpublished worker joins even without a native runtime scope.
pub fn packet_transport_endpoint_with_metrics(
    transport: Arc<dyn PacketTransport>,
    remote: SocketAddr,
    metrics_enabled: bool,
    owner: Option<&Arc<crate::runtime::TaskOwner>>,
) -> io::Result<PacketTransportEndpoint> {
    if transport.relay_addr() != remote {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PacketTransport relay address does not match the QUIC peer",
        ));
    }
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
    let drivers = Arc::new(crate::runtime::TaskOwner::production());
    let runtime = Arc::new(PacketTransportRuntime {
        inner: runtime,
        tasks: Arc::downgrade(&drivers),
        parent: owner.map(Arc::downgrade),
    });
    let config = endpoint_config_with_mtu(1252)?;
    let (socket, sender, receiver) =
        TransportQuinnSocket::prepare(transport, remote, metrics_enabled);
    let endpoint = Endpoint::new_with_abstract_socket(config, None, socket.clone(), runtime)?;
    socket.start_workers(owner, sender, receiver)?;
    Ok(PacketTransportEndpoint {
        endpoint,
        socket,
        drivers,
    })
}

/// Establish a QUIC connection through a proxied UDP tunnel and time the
/// handshake.  This is the real QUIC liveness probe: unlike a bare
/// Version-Negotiation trigger (which many frontends ignore), it proves
/// TLS-in-QUIC reachability through the node's UDP path.  `config` comes from
/// [`super::client_config`] — pass a node with `skip_cert_verify` for pure liveness
/// probing.
pub async fn quic_handshake_probe(
    transport: Arc<dyn PacketTransport>,
    target: SocketAddr,
    server_name: &str,
    config: &ClientConfig,
    timeout: Duration,
    cancel: crate::alive::ProbeCancellation,
) -> anyhow::Result<crate::alive::ProbeMeasurement> {
    if cancel.is_cancelled() {
        return Err(crate::alive::HealthCheckError::Stopped.into());
    }
    let tasks = Arc::new(crate::runtime::TaskOwner::production());
    let endpoint =
        match packet_transport_endpoint_with_metrics(transport, target, false, Some(&tasks)) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                tasks.close().await;
                if tasks.has_failed() {
                    cancel.report_cleanup_failure();
                }
                return Err(error.into());
            }
        };
    let result = async {
        let start = Instant::now();
        let connecting = endpoint
            .endpoint()
            .connect_with(config.clone(), target, server_name)
            .context("create QUIC connecting")?;
        let conn = cancel
            .run(tokio::time::timeout(timeout, connecting))
            .await
            .ok_or(crate::alive::HealthCheckError::Stopped)?
            .context("QUIC handshake timeout")
            .and_then(|result| result.map_err(anyhow::Error::from))
            .map_err(|error| endpoint.terminal_error().map_or(error, anyhow::Error::from))?;
        let measured = crate::alive::ProbeMeasurement {
            latency: start.elapsed(),
            observed_at: std::time::SystemTime::now(),
        };
        conn.close(quinn::VarInt::from_u32(0), b"probe");
        Ok(measured)
    }
    .await;
    let joined = endpoint.close(Duration::from_secs(2)).await;
    tasks.close().await;
    if !joined || tasks.has_failed() {
        cancel.report_cleanup_failure();
        return result.and_then(|_| Err(crate::alive::HealthCheckError::WorkerFailed.into()));
    }
    result
}

#[cfg(test)]
mod probe_tests;

#[cfg(test)]
mod poller_tests;
