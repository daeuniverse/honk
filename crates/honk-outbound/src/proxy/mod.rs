//! Registry-based outbound dispatch: a static protocol descriptor plus
//! per-capability trait objects (`TcpOutbound`, `PacketOutbound`,
//! `WarmableOutbound`, `ProbeableOutbound`).

pub(crate) mod addr;
pub mod anytls;
pub mod block;
pub mod direct;
pub mod hysteria2;
pub mod juicity;
pub mod shadowsocks;
pub(crate) mod shadowsocks_2022;
pub mod socks5;
pub(crate) mod ss_stream;
pub(crate) mod transport;
pub mod trojan;
pub mod tuic;
pub(crate) mod uot;
#[cfg(feature = "rprx")]
pub mod vless;
pub(crate) mod vless_cool;
#[cfg(feature = "rprx")]
mod vless_encryption;
pub(crate) mod vless_mux;
#[cfg(feature = "rprx")]
pub mod vmess;

use anytls::AnyTlsHandler;
use async_trait::async_trait;
use block::BlockHandler;
use direct::DirectHandler;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use hysteria2::Hysteria2Handler;
use juicity::JuicityHandler;
use shadowsocks::ShadowsocksHandler;
use socks5::Socks5Handler;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use trojan::TrojanHandler;
use tuic::TuicHandler;
#[cfg(feature = "rprx")]
use vless::VLessHandler;
#[cfg(feature = "rprx")]
use vmess::VmessHandler;

/// Trait object-compatible combination of async I/O traits used for proxy streams.
///
/// This allows a `ProxyStream` to hold either a plain `TcpStream` or a
/// TLS-wrapped stream (e.g. `tokio_boring::SslStream<TcpStream>`)
/// without exposing the concrete type to downstream relay code.
///
/// The `as_any`/`into_any` accessors let the relay layer downcast back to a
/// concrete `TcpStream` so direct (unwrapped) connections can use the
/// zero-copy `splice(2)` datapath.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin + Debug {
    /// Borrow this stream as `Any` for type checks.
    fn as_any(&self) -> &dyn std::any::Any;
    /// Consume this boxed stream as `Any` for owned downcasts.
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;
}

impl<T> AsyncReadWrite for T
where
    T: AsyncRead + AsyncWrite + Send + Unpin + Debug + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

struct RuntimeOwnedIo<T> {
    inner: Box<dyn AsyncReadWrite>,
    _owner: T,
}

impl<T> std::fmt::Debug for RuntimeOwnedIo<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeOwnedIo").finish_non_exhaustive()
    }
}

impl<T: Unpin> AsyncRead for RuntimeOwnedIo<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(self.inner.as_mut()).poll_read(cx, buf)
    }
}

impl<T: Unpin> AsyncWrite for RuntimeOwnedIo<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(self.inner.as_mut()).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(self.inner.as_mut()).poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub struct ProxyStream {
    /// Boxed so it can hold either a plain TCP or TLS-wrapped stream.
    pub stream: Box<dyn AsyncReadWrite>,
    pub target_addr: SocketAddr,
    /// Domain-based routing support.
    pub target_domain: Option<String>,
}

impl ProxyStream {
    /// If the dialled stream is a plain `TcpStream` (direct/bypass
    /// connections), return it as an owned socket so the relay can use the
    /// zero-copy `splice(2)` path. Returns `self` unchanged for wrapped
    /// (TLS/protocol) streams.
    pub fn into_tcp_stream(self) -> Result<tokio::net::TcpStream, Self> {
        // NOTE: `(*stream).as_any()` dispatches through the trait
        // object's vtable. `self.stream.as_any()` would instead resolve to
        // the blanket `impl<T> AsyncReadWrite for T` with T = `Box<dyn
        // AsyncReadWrite>` (tokio implements AsyncRead/AsyncWrite for
        // Box<T>, so the Box itself satisfies the blanket bound), and the
        // returned `Any` would wrap the Box — every downcast would fail.
        if !(*self.stream).as_any().is::<tokio::net::TcpStream>() {
            return Err(self);
        }
        let Self { stream, .. } = self;
        match stream.into_any().downcast::<tokio::net::TcpStream>() {
            Ok(stream) => Ok(*stream),
            // The type was checked immediately above.
            Err(_) => unreachable!("AsyncReadWrite type changed between checks"),
        }
    }

    /// Raw file descriptor of the underlying TCP socket, if reachable.
    ///
    /// Used by the connection pool's `MSG_PEEK` liveness probe for pooled
    /// ready streams. Returns `None` when no socket is directly reachable
    /// (e.g. a WebSocket duplex bridge); callers must treat `None` as
    /// "cannot probe" and decide conservatively.
    pub fn raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        // Vtable dispatch required — see into_tcp_stream.
        let any = (*self.stream).as_any();
        if let Some(tcp) = any.downcast_ref::<tokio::net::TcpStream>() {
            return Some(tcp.as_raw_fd());
        }
        if let Some(tls) = any.downcast_ref::<tokio_boring::SslStream<tokio::net::TcpStream>>() {
            return Some(tls.get_ref().as_raw_fd());
        }
        None
    }
    pub(crate) fn with_owner<T>(mut self, owner: T) -> Self
    where
        T: Send + Unpin + 'static,
    {
        self.stream = Box::new(RuntimeOwnedIo {
            inner: self.stream,
            _owner: owner,
        });
        self
    }
}

/// Coarse classification for packet-send failures shared with the control plane.
///
/// Congestion is deliberately separate from a dead tunnel: dropping one UDP
/// packet under backpressure must not demote an otherwise live outbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketErrorClass {
    Congestion,
    ConnectionDead,
    Other,
}

/// Classify an error returned by a [`PacketTransport`] operation.
pub fn packet_error_class(error: &std::io::Error) -> PacketErrorClass {
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    ) || error.raw_os_error() == Some(libc::ENOBUFS)
    {
        return PacketErrorClass::Congestion;
    }

    let mut source = error
        .get_ref()
        .map(|source| source as &(dyn std::error::Error + 'static));
    while let Some(current) = source {
        if let Some(quic_error) = current.downcast_ref::<quinn::SendDatagramError>() {
            return match quic_error {
                quinn::SendDatagramError::ConnectionLost(_) => PacketErrorClass::ConnectionDead,
                quinn::SendDatagramError::TooLarge => PacketErrorClass::Congestion,
                quinn::SendDatagramError::UnsupportedByPeer
                | quinn::SendDatagramError::Disabled => PacketErrorClass::Other,
            };
        }
        source = current.source();
    }

    if matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable
    ) {
        PacketErrorClass::ConnectionDead
    } else {
        PacketErrorClass::Other
    }
}

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
    #[cfg_attr(
        not(any(feature = "rprx", test)),
        allow(
            dead_code,
            reason = "only VLESS H2MUX performs a carrier readiness probe"
        )
    )]
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

type PreparedUdpCommitFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>;
type PreparedUdpCommit = Box<dyn FnOnce() -> PreparedUdpCommitFuture + Send>;

/// A prepared UDP transport that is usable only after its final side effects
/// have been committed. Dropping it without [`Self::commit`] abandons the
/// preparation; protocol-specific resources then clean themselves up via
/// normal RAII. Commit failure drops the transport and returns no value.
pub struct PreparedUdpTransport {
    transport: Arc<dyn PacketTransport>,
    commit: PreparedUdpCommit,
}

impl std::fmt::Debug for PreparedUdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedUdpTransport")
            .finish_non_exhaustive()
    }
}

impl PreparedUdpTransport {
    pub fn new<F, Fut>(transport: Arc<dyn PacketTransport>, commit: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        Self {
            transport,
            commit: Box::new(move || Box::pin(commit())),
        }
    }
    /// Wrap an already-authoritative ordinary transport. This deliberately
    /// preserves `dial_udp_transport` semantics for protocols with no
    /// speculative ownership to promote.
    pub fn ready(transport: Arc<dyn PacketTransport>) -> Self {
        Self::new(transport, || async { Ok(()) })
    }

    /// Consume the preparation, run its one-shot promotion, then expose the
    /// transport. A failed promotion is fail-closed: the transport is dropped
    /// and cannot be sent on by a caller.
    pub async fn commit(self) -> anyhow::Result<Arc<dyn PacketTransport>> {
        (self.commit)().await?;
        Ok(self.transport)
    }
}
async fn prepare_detached_quic_transport<T, F, Fut>(
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
    Ok(PreparedUdpTransport::new(transport, move || async move {
        let crate::runtime::ProtocolRuntime::Quic(quic) = &runtime.runtime else {
            anyhow::bail!("node '{}' lost its QUIC runtime", runtime.node.name);
        };
        quic.publish_client(client).await
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

/// Result of requesting reusable protocol state. `Ready` means the state is
/// usable after the call; `NotApplicable` means the protocol owns no
/// generation-scoped session or client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmOutcome {
    Ready,
    NotApplicable,
}

/// TCP flow dialing. Every protocol implements this.
#[async_trait]
pub trait TcpOutbound: Send + Sync {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream>;

    /// The provided `tcp` stream is already connected to the proxy
    /// server. Handlers that support connection pooling override this to
    /// skip `TcpStream::connect()`; the default ignores `tcp` and delegates
    /// to [`Self::dial`].
    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: tokio::net::TcpStream,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let _ = tcp;
        self.dial(node, target, target_domain, connect_timeout)
            .await
    }

    /// Dial through an explicitly captured runtime generation. Stateless
    /// handlers delegate to [`Self::dial`]; session-owning handlers override
    /// this to avoid consulting the mutable current-generation registry.
    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dial(
            runtime.node.as_ref(),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }
}

/// Framed UDP transports — only protocols with UDP capability (see
/// [`crate::descriptor::ProtocolDescriptor::supports_udp`]).
#[async_trait]
pub trait PacketOutbound: Send + Sync {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>>;

    /// Open a framed UDP transport using an explicitly captured runtime
    /// generation. Session-owning handlers override this so an authoritative
    /// flow reuses the same warmed generation-local client.
    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_udp_transport(
            runtime.node.as_ref(),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    /// Generation-pinned speculative preparation. The default wraps the
    /// authoritative runtime transport; session handlers override this when
    /// loser cancellation must avoid publishing reusable state.
    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        self.dial_udp_transport_runtime(runtime, target, target_domain, connect_timeout)
            .await
            .map(PreparedUdpTransport::ready)
    }
}

/// Which property a warm request must establish. Selector ownership needs
/// the shared session; UDP top-N ownership additionally validates that the
/// server admitted UDP on protocols where that is negotiated separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmRequirement {
    Session,
    Udp,
}

#[async_trait]
pub trait WarmableOutbound: Send + Sync {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: Duration,
        requirement: WarmRequirement,
    ) -> anyhow::Result<()>;
}

/// Raw server reachability checks.
#[async_trait]
pub trait ProbeableOutbound: Send + Sync {
    async fn test_connectivity(&self, node: &Node) -> bool {
        let addr = format!("{}:{}", node.host(), node.port);
        match crate::util::connect_outbound(&addr, std::time::Duration::from_secs(3)).await {
            Ok(_stream) => true,
            Err(e) => {
                tracing::debug!(
                    "{} connectivity test failed for {}: {}",
                    node.protocol().as_str(),
                    node.name,
                    e
                );
                false
            }
        }
    }
}

/// One registered protocol: its descriptor plus the capability objects it
/// implements. A `None` slot means the implementation lacks that capability;
/// the descriptor decides whether a present slot applies to a particular node.
pub struct ProtocolEntry {
    pub descriptor: &'static crate::descriptor::ProtocolDescriptor,
    pub tcp: Arc<dyn TcpOutbound>,
    pub packet: Option<Arc<dyn PacketOutbound>>,
    pub warmable: Option<Arc<dyn WarmableOutbound>>,
    pub probeable: Option<Arc<dyn ProbeableOutbound>>,
}

impl ProtocolEntry {
    pub fn new<T: TcpOutbound + 'static>(protocol: NodeProtocol, handler: Arc<T>) -> Self {
        Self {
            descriptor: crate::descriptor::descriptor(protocol),
            tcp: handler,
            packet: None,
            warmable: None,
            probeable: None,
        }
    }

    pub fn with_packet<T: PacketOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.packet = Some(handler);
        self
    }

    pub fn with_warmable<T: WarmableOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.warmable = Some(handler);
        self
    }

    pub fn with_probeable<T: ProbeableOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.probeable = Some(handler);
        self
    }

    /// Every capability enabled by the descriptor's default node must have an
    /// implementation slot. Node-dependent descriptors may keep an extra slot;
    /// dispatch checks the concrete node before calling it.
    fn validate_consistency(&self) {
        let protocol = self.descriptor.protocol;
        let default_node = Node {
            outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
            ..Default::default()
        };
        if (self.descriptor.supports_udp)(&default_node) && self.packet.is_none() {
            panic!(
                "protocol {} declares UDP without a packet handler",
                protocol.as_str()
            );
        }
        if self.descriptor.generation_runtime(&default_node)
            != crate::runtime::GenerationRuntime::None
            && self.warmable.is_none()
        {
            panic!(
                "protocol {} declares a generation runtime without a warm handler",
                protocol.as_str()
            );
        }
    }
}

pub struct ProxyRegistry {
    entries: Vec<ProtocolEntry>,
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn default_resolver() -> anyhow::Result<Self> {
        let mut registry = Self::new();

        let socks5 = Arc::new(Socks5Handler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Socks5, socks5.clone())
                .with_packet(socks5.clone())
                .with_probeable(socks5),
        );
        let direct = Arc::new(DirectHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Direct, direct.clone())
                .with_packet(direct.clone())
                .with_probeable(direct),
        );
        let block = Arc::new(BlockHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Block, block.clone())
                .with_packet(block.clone())
                .with_probeable(block),
        );
        let trojan = Arc::new(TrojanHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Trojan, trojan.clone())
                .with_packet(trojan.clone())
                .with_probeable(trojan),
        );
        let hysteria2 = Arc::new(Hysteria2Handler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Hysteria2, hysteria2.clone())
                .with_packet(hysteria2.clone())
                .with_warmable(hysteria2.clone())
                .with_probeable(hysteria2),
        );
        let shadowsocks = Arc::new(ShadowsocksHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::SS, shadowsocks.clone())
                .with_packet(shadowsocks.clone())
                .with_probeable(shadowsocks),
        );
        #[cfg(feature = "rprx")]
        {
            let vless = Arc::new(VLessHandler::new());
            registry.register(
                ProtocolEntry::new(NodeProtocol::VLess, vless.clone())
                    .with_packet(vless.clone())
                    .with_warmable(vless.clone())
                    .with_probeable(vless),
            );
            let vmess = Arc::new(VmessHandler::new());
            registry.register(
                ProtocolEntry::new(NodeProtocol::VMess, vmess.clone()).with_probeable(vmess),
            );
        }
        let anytls = Arc::new(AnyTlsHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::AnyTLS, anytls.clone())
                .with_packet(anytls.clone())
                .with_warmable(anytls.clone())
                .with_probeable(anytls),
        );
        let tuic = Arc::new(TuicHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Tuic, tuic.clone())
                .with_packet(tuic.clone())
                .with_warmable(tuic.clone())
                .with_probeable(tuic),
        );
        let juicity = Arc::new(JuicityHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Juicity, juicity.clone())
                .with_packet(juicity.clone())
                .with_warmable(juicity.clone())
                .with_probeable(juicity),
        );
        for entry in &registry.entries {
            entry.validate_consistency();
        }
        Ok(registry)
    }

    pub fn register(&mut self, entry: ProtocolEntry) {
        self.entries.push(entry);
    }

    pub fn find(&self, protocol: NodeProtocol) -> Option<&ProtocolEntry> {
        self.entries
            .iter()
            .find(|entry| entry.descriptor.protocol == protocol)
    }

    pub async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let protocol = node.protocol();
        let entry = self
            .find(protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;

        tracing::debug!(
            "Dialing {}:{} via {} ({})",
            target,
            protocol.as_str(),
            node.name,
            node.host()
        );

        entry
            .tcp
            .dial(node, target, target_domain, connect_timeout)
            .await
    }

    /// Dial through a generation-pinned node runtime. The generation's
    /// terminal flag is checked before and after the dial so a reload or
    /// shutdown racing the handshake fails closed instead of publishing a
    /// stream into a retired generation.
    pub async fn dial_runtime(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let protocol = runtime.node.protocol();
        let entry = self
            .find(protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;
        let stream = generation
            .scope_dials(
                entry
                    .tcp
                    .dial_runtime(runtime, target, target_domain, connect_timeout),
            )
            .await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during dial");
        }
        Ok(stream)
    }

    async fn warm_retained(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        connect_timeout: Duration,
        reason: crate::runtime::WarmRetention,
    ) -> anyhow::Result<WarmOutcome> {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let protocol = runtime.node.protocol();
        let entry = self
            .find(protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;
        if entry.descriptor.generation_runtime(&runtime.node)
            == crate::runtime::GenerationRuntime::None
        {
            return Ok(WarmOutcome::NotApplicable);
        }
        let Some(warmable) = entry.warmable.as_ref() else {
            return Ok(WarmOutcome::NotApplicable);
        };
        if reason == crate::runtime::WarmRetention::Udp && !runtime.udp_capable {
            return Ok(WarmOutcome::NotApplicable);
        }
        let requirement = match reason {
            crate::runtime::WarmRetention::Selector => WarmRequirement::Session,
            crate::runtime::WarmRetention::Udp => WarmRequirement::Udp,
        };
        let attempt = runtime.retain_warm(reason).await;
        if let Err(error) = generation
            .scope_dials(warmable.warm(Arc::clone(&runtime), connect_timeout, requirement))
            .await
        {
            attempt.rollback().await;
            return Err(error);
        }
        if generation.is_shutdown() {
            attempt.rollback().await;
            anyhow::bail!("outbound runtime generation shut down during warm-up");
        }
        attempt.commit();
        Ok(WarmOutcome::Ready)
    }

    /// Warm a selected node's reusable session in the captured generation.
    pub async fn warm_session(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        connect_timeout: Duration,
    ) -> anyhow::Result<WarmOutcome> {
        self.warm_retained(
            generation,
            node_id,
            connect_timeout,
            crate::runtime::WarmRetention::Selector,
        )
        .await
    }

    /// Warm a UDP-capable node in the explicitly supplied runtime generation.
    pub async fn warm_udp(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        connect_timeout: Duration,
    ) -> anyhow::Result<WarmOutcome> {
        self.warm_retained(
            generation,
            node_id,
            connect_timeout,
            crate::runtime::WarmRetention::Udp,
        )
        .await
    }

    /// Framed UDP transport for a flow, dispatching to the node's packet
    /// capability (see [`PacketOutbound::dial_udp_transport`]).
    pub async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let protocol = node.protocol();
        let entry = self
            .find(protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;
        if protocol != NodeProtocol::Block && !(entry.descriptor.supports_udp)(node) {
            anyhow::bail!("UDP not supported for protocol {}", protocol.as_str());
        }
        let packet = entry.packet.as_ref().ok_or_else(|| {
            anyhow::anyhow!("UDP not supported for protocol {}", protocol.as_str())
        })?;
        packet
            .dial_udp_transport(node, target, target_domain, connect_timeout)
            .await
    }

    /// Generation-pinned framed UDP transport for an authoritative flow.
    /// This complements speculative preparation: both paths must retain the
    /// runtime captured when the flow was admitted, not re-resolve a handler
    /// cache after reload.
    pub async fn dial_udp_transport_runtime(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let (runtime, packet) = self.packet_runtime(&generation, node_id)?;
        let transport = generation
            .scope_dials(packet.dial_udp_transport_runtime(
                runtime,
                target,
                target_domain,
                connect_timeout,
            ))
            .await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during UDP dial");
        }
        Ok(transport)
    }

    /// Speculatively prepare a framed UDP transport for a Cold URLTest
    /// candidate. Ordinary dial behavior remains available through
    /// [`Self::dial_udp_transport`] for authoritative paths.
    pub async fn dial_udp_transport_speculative(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let (runtime, packet) = self.packet_runtime(&generation, node_id)?;
        let prepared = generation
            .scope_dials(packet.dial_udp_transport_speculative_runtime(
                runtime,
                target,
                target_domain,
                connect_timeout,
            ))
            .await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during UDP preparation");
        }
        Ok(prepared)
    }

    fn packet_runtime(
        &self,
        generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
    ) -> anyhow::Result<(Arc<crate::runtime::NodeRuntime>, &Arc<dyn PacketOutbound>)> {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let protocol = runtime.node.protocol();
        if protocol != NodeProtocol::Block && !runtime.udp_capable {
            anyhow::bail!("UDP not supported for protocol {}", protocol.as_str());
        }
        let entry = self
            .find(protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;
        let packet = entry.packet.as_ref().ok_or_else(|| {
            anyhow::anyhow!("UDP not supported for protocol {}", protocol.as_str())
        })?;
        Ok((runtime, packet))
    }

    pub fn handler_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for ProxyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_default_handlers() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        assert!(registry.handler_count() >= 4);
        assert!(registry.find(NodeProtocol::Socks5).is_some());
        assert!(registry.find(NodeProtocol::Direct).is_some());
        assert!(registry.find(NodeProtocol::Block).is_some());
        assert!(registry.find(NodeProtocol::Trojan).is_some());
        assert!(registry.find(NodeProtocol::SS).is_some());
        assert!(registry.find(NodeProtocol::AnyTLS).is_some());
        assert!(registry.find(NodeProtocol::Hysteria2).is_some());
        #[cfg(feature = "rprx")]
        assert!(registry.find(NodeProtocol::VMess).is_some());
        assert!(registry.find(NodeProtocol::Tuic).is_some());
        assert!(registry.find(NodeProtocol::Juicity).is_some());
    }
    #[test]
    fn packet_error_class_separates_backpressure_from_dead_tunnel() {
        for kind in [
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::Interrupted,
        ] {
            assert_eq!(
                packet_error_class(&std::io::Error::new(kind, "backpressure")),
                PacketErrorClass::Congestion
            );
        }
        assert_eq!(
            packet_error_class(&std::io::Error::from_raw_os_error(libc::ENOBUFS)),
            PacketErrorClass::Congestion
        );
        assert_eq!(
            packet_error_class(&std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            )),
            PacketErrorClass::ConnectionDead
        );
        assert_eq!(
            packet_error_class(&std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "operation timeout",
            )),
            PacketErrorClass::Other
        );
        let quic_error = std::io::Error::other(quinn::SendDatagramError::ConnectionLost(
            quinn::ConnectionError::Reset,
        ));
        assert_eq!(
            packet_error_class(&quic_error),
            PacketErrorClass::ConnectionDead
        );
        let too_large = std::io::Error::other(quinn::SendDatagramError::TooLarge);
        assert_eq!(packet_error_class(&too_large), PacketErrorClass::Congestion);
    }

    /// Without the `rprx` feature a parsed VLESS/VMess node must hit the
    /// ordinary no-handler refusal, never a panic.
    #[cfg(not(feature = "rprx"))]
    #[tokio::test]
    async fn rprx_off_refuses_vless_vmess_without_handler() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        for protocol in [NodeProtocol::VLess, NodeProtocol::VMess] {
            assert!(registry.find(protocol).is_none());
            let node = Node {
                outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
                ..Default::default()
            };
            let err = registry
                .dial(
                    &node,
                    "93.184.216.34:443".parse().unwrap(),
                    None,
                    Duration::from_secs(1),
                )
                .await
                .expect_err("no handler registered without rprx");
            assert!(err.to_string().contains("No handler for protocol"));
        }
    }

    #[test]
    #[should_panic(expected = "declares UDP without a packet handler")]
    fn consistency_rejects_missing_packet_implementation() {
        let direct = Arc::new(DirectHandler::new());
        ProtocolEntry::new(NodeProtocol::Direct, direct).validate_consistency();
    }

    #[test]
    #[should_panic(expected = "generation runtime without a warm handler")]
    fn consistency_rejects_missing_warm_implementation() {
        let anytls = Arc::new(AnyTlsHandler::new());
        ProtocolEntry::new(NodeProtocol::AnyTLS, anytls.clone())
            .with_packet(anytls)
            .validate_consistency();
    }

    #[cfg(feature = "rprx")]
    #[tokio::test]
    async fn vless_capabilities_follow_the_concrete_node() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        let entry = registry.find(NodeProtocol::VLess).unwrap();
        assert!(entry.packet.is_some());
        assert!(entry.warmable.is_some());

        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "legacy-vless".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::VLess),
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        assert_eq!(
            registry
                .warm_session(Arc::clone(&generation), node.id, Duration::from_millis(10),)
                .await
                .unwrap(),
            WarmOutcome::NotApplicable
        );
        let error = registry
            .dial_udp_transport_runtime(
                generation,
                node.id,
                "8.8.8.8:53".parse().unwrap(),
                None,
                Duration::from_millis(10),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("UDP not supported"));
    }

    /// The built-in block node carries NodeProtocol::Block; the registry must
    /// dispatch it to BlockHandler (regression: block rules silently dialed
    /// direct when block shared direct's protocol marker).
    #[tokio::test]
    async fn test_block_node_dispatches_to_block_handler() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "block".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Block),
            ..Default::default()
        };
        let target: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let err = registry
            .dial(&node, target, None, Duration::from_secs(1))
            .await
            .expect_err("block node must not dial");
        assert!(err.to_string().contains("blocked"));
        let err = registry
            .dial_udp_transport(&node, target, None, Duration::from_secs(1))
            .await
            .expect_err("block node must not dial UDP");
        assert!(err.to_string().contains("blocked"));
    }

    /// Regression test for the `Box<dyn AsyncReadWrite>` method-resolution
    /// trap: `as_any`/`into_any` must see the inner stream, not the Box.
    #[tokio::test]
    async fn test_into_tcp_stream_plain_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ps = ProxyStream {
            stream: Box::new(tcp),
            target_addr: addr,
            target_domain: None,
        };
        assert!(
            ps.into_tcp_stream().is_ok(),
            "plain TcpStream must downcast"
        );
    }

    #[tokio::test]
    async fn test_raw_fd_plain_tcp() {
        use std::os::unix::io::AsRawFd;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let expected = tcp.as_raw_fd();
        let ps = ProxyStream {
            stream: Box::new(tcp),
            target_addr: addr,
            target_domain: None,
        };
        assert_eq!(ps.raw_fd(), Some(expected));
    }

    #[tokio::test]
    async fn test_raw_fd_none_for_non_tcp() {
        // A stream without a reachable socket (duplex bridge, as used by
        // the WebSocket transport) must report "cannot probe".
        let (client, _server) = tokio::io::duplex(64);
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ps = ProxyStream {
            stream: Box::new(client),
            target_addr: addr,
            target_domain: None,
        };
        assert_eq!(ps.raw_fd(), None);
    }

    #[tokio::test]
    async fn warm_udp_is_not_applicable_without_reusable_udp_state() {
        let mut nodes = Vec::new();
        for (name, protocol) in [
            ("direct", NodeProtocol::Direct),
            ("socks", NodeProtocol::Socks5),
            ("ss", NodeProtocol::SS),
            ("trojan", NodeProtocol::Trojan),
        ] {
            nodes.push(Node {
                id: uuid::Uuid::new_v4(),
                name: name.into(),
                outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
                ..Default::default()
            });
        }
        nodes.push(Node {
            id: uuid::Uuid::new_v4(),
            name: "tcp-only-anytls".into(),
            outbound: honk_config::node::OutboundConfig::AnyTls(honk_config::node::AnyTlsConfig {
                network: Some("tcp".into()),
                ..Default::default()
            }),
            ..Default::default()
        });
        let generation = Arc::new(crate::runtime::OutboundRuntimeRegistry::build(&nodes).unwrap());
        let registry = ProxyRegistry::default_resolver().unwrap();

        for node in &nodes {
            assert_eq!(
                registry
                    .warm_udp(Arc::clone(&generation), node.id, Duration::from_secs(1))
                    .await
                    .unwrap(),
                WarmOutcome::NotApplicable,
                "{} must not masquerade as a warmable UDP session",
                node.name
            );
        }
    }
    struct RejectingWarmable;

    #[async_trait]
    impl WarmableOutbound for RejectingWarmable {
        async fn warm(
            &self,
            _runtime: Arc<crate::runtime::NodeRuntime>,
            _connect_timeout: Duration,
            _requirement: WarmRequirement,
        ) -> anyhow::Result<()> {
            anyhow::bail!("warm rejected")
        }
    }

    struct PendingWarmable {
        started: tokio::sync::mpsc::UnboundedSender<()>,
    }

    #[async_trait]
    impl WarmableOutbound for PendingWarmable {
        async fn warm(
            &self,
            _runtime: Arc<crate::runtime::NodeRuntime>,
            _connect_timeout: Duration,
            _requirement: WarmRequirement,
        ) -> anyhow::Result<()> {
            self.started.send(()).unwrap();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancelled_warm_releases_only_its_inserted_retention() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "cancelled-anytls".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let runtime = generation.get(&node.id).unwrap();
        let pool = runtime.anytls_pool().unwrap();
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut registry = ProxyRegistry::default_resolver().unwrap();
        registry
            .entries
            .iter_mut()
            .find(|entry| entry.descriptor.protocol == NodeProtocol::AnyTLS)
            .unwrap()
            .warmable = Some(Arc::new(PendingWarmable {
            started: started_tx,
        }));
        let registry = Arc::new(registry);

        let task = tokio::spawn({
            let registry = Arc::clone(&registry);
            let generation = Arc::clone(&generation);
            async move {
                registry
                    .warm_session(generation, node.id, Duration::from_secs(1))
                    .await
            }
        });
        started_rx.recv().await.unwrap();
        assert!(pool.is_warm_retained());
        task.abort();
        let _ = task.await;
        assert!(!pool.is_warm_retained());

        runtime
            .retain_warm(crate::runtime::WarmRetention::Selector)
            .await
            .commit();
        let task = tokio::spawn({
            let registry = Arc::clone(&registry);
            async move {
                registry
                    .warm_session(generation, node.id, Duration::from_secs(1))
                    .await
            }
        });
        started_rx.recv().await.unwrap();
        task.abort();
        let _ = task.await;
        assert!(pool.is_warm_retained());
        runtime
            .release_warm(crate::runtime::WarmRetention::Selector)
            .await;
    }

    #[tokio::test]
    async fn failed_warm_releases_its_policy_retention() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "failing-anytls".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let runtime = generation.get(&node.id).unwrap();
        let pool = runtime.anytls_pool().unwrap();
        let mut registry = ProxyRegistry::default_resolver().unwrap();
        registry
            .entries
            .iter_mut()
            .find(|entry| entry.descriptor.protocol == NodeProtocol::AnyTLS)
            .unwrap()
            .warmable = Some(Arc::new(RejectingWarmable));

        let error = registry
            .warm_session(Arc::clone(&generation), node.id, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("warm rejected"));
        assert!(!pool.is_warm_retained());

        runtime
            .retain_warm(crate::runtime::WarmRetention::Selector)
            .await
            .commit();
        assert!(pool.is_warm_retained());
        registry
            .warm_session(generation, node.id, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(pool.is_warm_retained());
        runtime
            .release_warm(crate::runtime::WarmRetention::Selector)
            .await;
        assert!(!pool.is_warm_retained());
    }

    #[tokio::test]
    async fn warm_udp_rejects_a_shutdown_generation_before_dispatch() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "old-anytls".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        generation.shutdown().await;

        assert!(
            ProxyRegistry::default_resolver()
                .unwrap()
                .warm_udp(generation, node.id, Duration::from_secs(1))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn speculative_udp_rejects_a_shutdown_generation_before_dispatch() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "direct".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Direct),
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        generation.shutdown().await;

        assert!(
            ProxyRegistry::default_resolver()
                .unwrap()
                .dial_udp_transport_speculative(
                    generation,
                    node.id,
                    "127.0.0.1:53".parse().unwrap(),
                    None,
                    Duration::from_secs(1),
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn prepared_udp_transport_defers_transport_exposure_until_commit() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = socket.local_addr().unwrap();
        let transport: Arc<dyn PacketTransport> =
            Arc::new(UdpSocketTransport::new(Arc::clone(&socket), relay_addr));
        let commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let prepared = PreparedUdpTransport::new(Arc::clone(&transport), {
            let commits = Arc::clone(&commits);
            move || async move {
                commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
        });
        assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);

        let committed = prepared.commit().await.unwrap();

        assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(Arc::ptr_eq(&transport, &committed));
    }
}
