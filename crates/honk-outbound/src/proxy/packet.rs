use async_trait::async_trait;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use super::AsyncReadWrite;

/// Snapshot identifying one asynchronous QUIC packet send.
///
/// The token binds completion to the ACK epoch and packet counts observed
/// before the send. A cancelled send is completed as a failure by
/// [`QuicSendAttempt`] so it cannot leave a phantom path wait.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuicSendToken {
    pub(crate) ack_epoch: u64,
    pub(crate) ack_baseline: u64,
    pub(crate) sent_baseline: u64,
    pub(crate) started_at: u64,
}

impl QuicSendToken {
    pub(crate) const INACTIVE: Self = Self {
        ack_epoch: 0,
        ack_baseline: 0,
        sent_baseline: 0,
        started_at: 0,
    };

    pub(crate) fn new(
        ack_epoch: u64,
        ack_baseline: u64,
        sent_baseline: u64,
        started_at: u64,
    ) -> Self {
        Self {
            ack_epoch,
            ack_baseline,
            sent_baseline,
            started_at,
        }
    }

    pub(crate) fn is_active(self) -> bool {
        self.started_at != 0
    }
}

/// Completes one asynchronous QUIC packet send exactly once.
#[must_use]
pub struct QuicSendAttempt<'a> {
    transport: &'a dyn PacketTransport,
    token: QuicSendToken,
    completed: bool,
}

impl<'a> QuicSendAttempt<'a> {
    pub fn new(transport: &'a dyn PacketTransport) -> Self {
        Self {
            token: transport.record_quic_send_started(),
            transport,
            completed: false,
        }
    }

    pub fn success(mut self) {
        self.completed = true;
        self.transport.record_quic_send_success(self.token);
    }

    pub fn timeout(mut self) {
        self.completed = true;
        self.transport.record_quic_send_timeout(self.token);
    }

    pub fn failure(mut self) {
        self.completed = true;
        self.transport.record_quic_send_failure(self.token);
    }
}

impl Drop for QuicSendAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed && self.token.is_active() {
            self.transport.record_quic_send_failure(self.token);
        }
    }
}

/// Framed UDP packet transport — the production UDP contract. Native UDP
/// protocols wrap a real `UdpSocket`; tunnel protocols implement their
/// framing directly on the tunnel instead of bouncing datagrams through a
/// loopback socket pair (extra FD + 1–2 copies per packet).
#[async_trait]
pub trait PacketTransport: Send + Sync + Debug {
    /// The relay target a flow reports as its destination.
    fn relay_addr(&self) -> SocketAddr;
    /// Whether server-carried metadata may authoritatively name a logical
    /// reply source before the endpoint has observed its first response.
    fn allows_full_cone_replies(&self) -> bool {
        false
    }
    /// Per-packet send deadline. QUIC transports derive this from SRTT;
    /// non-QUIC transports retain the five-second driver default.
    fn send_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }
    /// Capture the ACK baseline before an asynchronous QUIC send begins.
    fn record_quic_send_started(&self) -> QuicSendToken {
        QuicSendToken::INACTIVE
    }
    /// Record a packet accepted by the QUIC transport; the path watchdog
    /// waits for its ACK before declaring a black hole.
    fn record_quic_send_success(&self, _token: QuicSendToken) {}
    /// Record a QUIC packet wait that reached its deadline.
    fn record_quic_send_timeout(&self, _token: QuicSendToken) {}
    /// Record a non-timeout send failure so a failed send cannot arm a path wait.
    fn record_quic_send_failure(&self, _token: QuicSendToken) {}
    /// Whether this transport's shared QUIC path was retired by the watchdog.
    fn quic_path_stalled(&self) -> bool {
        false
    }
    /// Whether a driver send deadline is packet-local congestion rather than
    /// evidence that the tunnel died. Stream-framed transports keep the safe
    /// default of `false`; atomic datagram/QUIC waits opt in.
    fn send_timeout_is_congestion(&self) -> bool {
        false
    }
    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()>;
    /// Stronger admission for a flow's first datagram. Queue-backed tunnels
    /// override this to complete only after their writer flushes the packet.
    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_packet(data).await
    }
    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

pub(crate) trait MuxSession: crate::session::ManagedSession + Sized + 'static {
    type Stream: AsyncReadWrite + 'static;
    type Packet: PacketTransport + 'static;
    #[cfg(any(feature = "rprx", test))]
    fn check_ready(
        self: Arc<Self>,
    ) -> impl Future<Output = Result<(), crate::session::OpenError>> + Send {
        std::future::ready(match self.state() {
            crate::session::SessionState::Active => Ok(()),
            crate::session::SessionState::Draining => Err(crate::session::OpenError::Draining(
                anyhow::anyhow!("mux carrier is draining"),
            )),
            crate::session::SessionState::Closed => Err(crate::session::OpenError::Session(
                anyhow::anyhow!("mux carrier is closed"),
            )),
        })
    }

    fn open_stream(
        self: Arc<Self>,
        permit: crate::session::SessionPermit<Self>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> impl Future<Output = Result<Self::Stream, crate::session::OpenError>> + Send;

    fn open_packet(
        self: Arc<Self>,
        permit: crate::session::SessionPermit<Self>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> impl Future<Output = Result<Arc<Self::Packet>, crate::session::OpenError>> + Send;
}

struct RuntimeOwnedPacketTransport<T> {
    inner: Arc<dyn PacketTransport>,
    _owner: T,
}

impl<T> std::fmt::Debug for RuntimeOwnedPacketTransport<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeOwnedPacketTransport")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<T: Send + Sync> PacketTransport for RuntimeOwnedPacketTransport<T> {
    fn relay_addr(&self) -> SocketAddr {
        self.inner.relay_addr()
    }
    fn allows_full_cone_replies(&self) -> bool {
        self.inner.allows_full_cone_replies()
    }
    fn send_timeout(&self) -> std::time::Duration {
        self.inner.send_timeout()
    }
    fn record_quic_send_started(&self) -> QuicSendToken {
        self.inner.record_quic_send_started()
    }
    fn record_quic_send_success(&self, token: QuicSendToken) {
        self.inner.record_quic_send_success(token);
    }
    fn record_quic_send_timeout(&self, token: QuicSendToken) {
        self.inner.record_quic_send_timeout(token);
    }
    fn record_quic_send_failure(&self, token: QuicSendToken) {
        self.inner.record_quic_send_failure(token);
    }
    fn quic_path_stalled(&self) -> bool {
        self.inner.quic_path_stalled()
    }
    fn send_timeout_is_congestion(&self) -> bool {
        self.inner.send_timeout_is_congestion()
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.inner.send_packet(data).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.inner.send_packet_confirmed(data).await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.inner.recv_packet(buf).await
    }
}

pub(crate) fn packet_transport_with_owner<T>(
    transport: Arc<dyn PacketTransport>,
    owner: T,
) -> Arc<dyn PacketTransport>
where
    T: Send + Sync + 'static,
{
    Arc::new(RuntimeOwnedPacketTransport {
        inner: transport,
        _owner: owner,
    })
}

/// A prepared UDP transport that is usable only after its final side effects
/// have been committed. Dropping it without [`Self::commit`] abandons the
/// preparation; protocol-specific resources then clean themselves up via
/// normal RAII. Commit failure drops the transport and returns no value.
pub struct PreparedUdpTransport<T: ?Sized = dyn PacketTransport> {
    commit: std::pin::Pin<Box<dyn Future<Output = anyhow::Result<Arc<T>>> + Send>>,
}

impl<T: ?Sized> std::fmt::Debug for PreparedUdpTransport<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedUdpTransport")
            .finish_non_exhaustive()
    }
}

impl<T: ?Sized + Send + Sync + 'static> PreparedUdpTransport<T> {
    pub fn new<Fut>(commit: Fut) -> Self
    where
        Fut: Future<Output = anyhow::Result<Arc<T>>> + Send + 'static,
    {
        Self {
            commit: Box::pin(commit),
        }
    }
    /// Wrap an already-authoritative ordinary transport. This deliberately
    /// preserves `dial_udp_transport` semantics for protocols with no
    /// speculative ownership to promote.
    pub fn ready(transport: Arc<T>) -> Self {
        Self::new(async move { Ok(transport) })
    }

    /// Consume the preparation, run its one-shot promotion, then expose the
    /// transport. A failed promotion is fail-closed: the transport is dropped
    /// and cannot be sent on by a caller.
    pub async fn commit(self) -> anyhow::Result<Arc<T>> {
        self.commit.await
    }
}
pub(super) async fn prepare_detached_quic_transport<T, F, Fut>(
    runtime: Arc<crate::runtime::NodeRuntime>,
    client: Arc<T>,
    prepare: F,
) -> anyhow::Result<PreparedUdpTransport>
where
    T: crate::runtime::QuicRuntimeClient,
    F: FnOnce(Arc<T>) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Arc<dyn PacketTransport>>>,
{
    if !matches!(runtime.runtime, crate::runtime::ProtocolRuntime::Quic(_)) {
        anyhow::bail!("node '{}' has no QUIC runtime", runtime.node.name);
    }
    let transport = prepare(Arc::clone(&client)).await?;
    Ok(PreparedUdpTransport::new(async move {
        let crate::runtime::ProtocolRuntime::Quic(quic) = &runtime.runtime else {
            anyhow::bail!("node '{}' lost its QUIC runtime", runtime.node.name);
        };
        quic.publish_client(client).await?;
        Ok(transport)
    }))
}

/// Adapter presenting a raw `UdpSocket` (e.g. the direct handler's
/// bypass-marked socket) as a [`PacketTransport`].
#[derive(Debug)]
pub struct UdpSocketTransport {
    socket: Arc<tokio::net::UdpSocket>,
    relay_addr: SocketAddr,
}

impl UdpSocketTransport {
    pub fn new(socket: Arc<tokio::net::UdpSocket>, relay_addr: SocketAddr) -> Self {
        Self { socket, relay_addr }
    }
}

#[async_trait]
impl PacketTransport for UdpSocketTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }
    fn send_timeout_is_congestion(&self) -> bool {
        true
    }
    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.socket.send_to(data, self.relay_addr).await?;
        Ok(())
    }
    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }
}

#[cfg(all(test, target_os = "linux"))]
mod socket_mark_tests;
