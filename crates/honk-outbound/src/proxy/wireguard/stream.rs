//! TCP flows: `FlowIo` adapts a stack flow to `AsyncRead + AsyncWrite`, and `dial` opens one.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use honk_netstack::{ConnectError, FlowId, StreamError, TcpState};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tunnel::{Gone, Slot, Tunnel};
use crate::proxy::{PacketRejection, TargetFailure};

pub(crate) struct FlowIo {
    tunnel: Tunnel,
    id: FlowId,
}

impl fmt::Debug for FlowIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardTcpStream").finish_non_exhaustive()
    }
}

impl Drop for FlowIo {
    fn drop(&mut self) {
        let id = self.id;
        self.tunnel.0.with(|inner| {
            // Unread data turns into an RST, as on Linux; an unconnected flow just disappears.
            inner.stack.tcp_close(id);
            inner.flows.remove(&id);
            self.tunnel.0.retire_if_unused(inner);
        });
        self.tunnel.0.wake_owner();
    }
}

fn stream_error(error: StreamError) -> io::Error {
    let kind = match error {
        StreamError::WouldBlock => io::ErrorKind::WouldBlock,
        StreamError::Closed => io::ErrorKind::BrokenPipe,
        StreamError::Reset => io::ErrorKind::ConnectionReset,
        StreamError::TimedOut => io::ErrorKind::TimedOut,
        StreamError::Unreachable => io::ErrorKind::HostUnreachable,
        StreamError::Stale => io::ErrorKind::NotConnected,
    };
    io::Error::new(kind, error)
}

impl AsyncRead for FlowIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let id = self.id;
        self.tunnel.0.with(|inner| {
            if let Some(error) = inner.forced(id) {
                return Poll::Ready(Err(error));
            }
            match inner.stack.tcp_read(id, buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    Poll::Ready(Ok(()))
                }
                Err(StreamError::WouldBlock) => {
                    if let Some(slot) = inner.flows.get_mut(&id) {
                        slot.rx = Some(cx.waker().clone());
                    }
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(stream_error(error))),
            }
        })
    }
}

impl AsyncWrite for FlowIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let id = self.id;
        self.tunnel.0.with(|inner| {
            if let Some(error) = inner.forced(id) {
                return Poll::Ready(Err(error));
            }
            match inner.stack.tcp_write(id, data) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(StreamError::WouldBlock) => {
                    if let Some(slot) = inner.flows.get_mut(&id) {
                        slot.tx = Some(cx.waker().clone());
                    }
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(stream_error(error))),
            }
        })
    }

    /// Accepted bytes belong to the stack until acknowledged; there is nothing further to flush.
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let id = self.id;
        self.tunnel.0.with(|inner| {
            if let Some(error) = inner.forced(id) {
                return Poll::Ready(Err(error));
            }
            Poll::Ready(inner.stack.tcp_shutdown(id).map_err(stream_error))
        })
    }
}

pub(super) fn refusal(kind: io::ErrorKind, message: &str) -> anyhow::Error {
    io::Error::new(kind, TargetFailure(anyhow::anyhow!("{message}"))).into()
}

impl Tunnel {
    /// Open a TCP flow to `target` through the tunnel and wait for the inner handshake.
    ///
    /// An inner RST or ICMP unreachable is the target's refusal. A SYN that stays unanswered is
    /// the target's only when the peer sent other inner packets meanwhile; otherwise the tunnel
    /// itself may be blackholed, so the timeout stays untyped (node-conservative).
    pub(crate) async fn dial_tcp(
        &self,
        scope: u64,
        target: SocketAddr,
        deadline: Instant,
    ) -> Result<anyhow::Result<FlowIo>, Gone> {
        let target = SocketAddr::new(target.ip().to_canonical(), target.port());
        let attached = self.0.with(|inner| {
            if inner.dead() {
                return Err(None);
            }
            let before = inner.inner_rx;
            match inner.stack.tcp_connect(Instant::now(), target) {
                Ok(id) => {
                    inner.flows.insert(id, Slot::new(scope, false));
                    Ok((id, before))
                }
                Err(error) => Err(Some(error)),
            }
        });
        let (id, inner_rx_before) = match attached {
            Ok(attached) => attached,
            Err(None) => return Err(self.gone()),
            Err(Some(ConnectError::NoLocalAddress)) => {
                return Ok(Err(refusal(
                    io::ErrorKind::HostUnreachable,
                    "no WireGuard tunnel address in the target's family",
                )));
            }
            // Local exhaustion says nothing about the node or the target.
            Err(Some(ConnectError::FlowLimit | ConnectError::Memory | ConnectError::AddrInUse)) => {
                return Ok(Err(PacketRejection::Capacity.into()));
            }
        };
        let flow = FlowIo {
            tunnel: self.clone(),
            id,
        };
        let connected = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            std::future::poll_fn(|cx| {
                self.0.with(|inner| {
                    if let Some(error) = inner.forced(id) {
                        return Poll::Ready(Connect::Forced(error));
                    }
                    match inner.stack.tcp_state(id) {
                        Some(TcpState::SynSent | TcpState::SynReceived) => {
                            if let Some(slot) = inner.flows.get_mut(&id) {
                                slot.tx = Some(cx.waker().clone());
                            }
                            Poll::Pending
                        }
                        // Closed on a connecting flow means a sticky error is waiting.
                        Some(TcpState::Closed) | None => Poll::Ready(Connect::Failed(
                            inner
                                .stack
                                .tcp_write(id, &[])
                                .err()
                                .unwrap_or(StreamError::Reset),
                        )),
                        Some(_) => Poll::Ready(Connect::Open),
                    }
                })
            }),
        )
        .await;
        let peer_answered = || self.0.with(|inner| inner.inner_rx > inner_rx_before);
        Ok(match connected {
            Ok(Connect::Open) => Ok(flow),
            // Tunnel failure or runtime close: the carrier's own error.
            Ok(Connect::Forced(error)) => Err(error.into()),
            Ok(Connect::Failed(StreamError::Reset)) => Err(refusal(
                io::ErrorKind::ConnectionRefused,
                "WireGuard target refused the connection",
            )),
            Ok(Connect::Failed(StreamError::Unreachable)) => Err(refusal(
                io::ErrorKind::HostUnreachable,
                "WireGuard target is unreachable",
            )),
            Ok(Connect::Failed(StreamError::TimedOut)) | Err(_) => {
                if peer_answered() {
                    Err(refusal(
                        io::ErrorKind::TimedOut,
                        "WireGuard target did not answer the connection attempt",
                    ))
                } else {
                    Err(io::Error::from(io::ErrorKind::TimedOut).into())
                }
            }
            Ok(Connect::Failed(error)) => Err(stream_error(error).into()),
        })
    }

    pub(crate) fn gone(&self) -> Gone {
        match &*self.0.state.borrow() {
            super::tunnel::State::Failed(error) => Gone::Failed(error.clone()),
            super::tunnel::State::Closed => Gone::Closed,
            _ => Gone::Idle,
        }
    }
}

enum Connect {
    Open,
    Forced(io::Error),
    Failed(StreamError),
}
