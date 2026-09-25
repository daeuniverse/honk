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
pub mod socks5;
pub(crate) mod transport;
pub mod trojan;
pub mod tuic;
pub(crate) mod uot;
#[cfg(any(feature = "rprx", test))]
pub mod vless;
#[cfg(feature = "rprx")]
pub mod vmess;

mod error;
mod outbound;
mod packet;
mod registry;

pub use direct::DirectMark;
pub use error::{
    NodeFailure, PacketErrorClass, PacketRejection, TargetFailure, is_packet_rejection,
    node_failure, packet_error_class, packet_rejection, target_failure,
};
pub(crate) use error::{
    io_packet_rejection, io_target_failure, node_failure_episode, quic_carrier_error,
    quic_carrier_io_error,
};
pub use outbound::{
    PacketOutbound, ProbeableOutbound, TcpOutbound, WarmOutcome, WarmRequirement, WarmableOutbound,
};
use packet::prepare_detached_quic_transport;
pub(crate) use packet::{MuxSession, packet_transport_with_owner};
pub use packet::{
    PacketTransport, PreparedUdpTransport, QuicSendAttempt, QuicSendToken, UdpSocketTransport,
};
pub use registry::{ProtocolEntry, ProxyRegistry};

#[cfg(test)]
use anytls::AnyTlsHandler;
#[cfg(test)]
use async_trait::async_trait;
#[cfg(test)]
use direct::DirectHandler;
#[cfg(test)]
use honk_config::node::Node;
#[cfg(test)]
use honk_config::types::NodeProtocol;
use std::fmt::Debug;
use std::net::SocketAddr;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

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
        if let Some(tcp) = any.downcast_ref::<crate::transport_quality::tcp::ObservedTcp>() {
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

#[cfg(test)]
mod tests;
