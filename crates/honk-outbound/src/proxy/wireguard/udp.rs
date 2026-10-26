//! UDP associations: one stack socket per prepared source, addressing any allowed destination.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use async_trait::async_trait;
use honk_netstack::{BindError, FlowId};

use super::tunnel::{Gone, Slot, Tunnel};
use crate::proxy::{MultiTargetTransport, PacketRejection, PacketTransport};

pub(crate) struct WgUdpTransport {
    tunnel: Tunnel,
    id: FlowId,
    target: SocketAddr,
}

impl fmt::Debug for WgUdpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgUdpTransport")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Drop for WgUdpTransport {
    fn drop(&mut self) {
        let id = self.id;
        self.tunnel.0.with(|inner| {
            inner.stack.udp_close(id);
            inner.flows.remove(&id);
            self.tunnel.0.retire_if_unused(inner);
        });
        self.tunnel.0.wake_owner();
    }
}

impl Tunnel {
    pub(crate) fn bind_udp(
        &self,
        scope: u64,
        target: SocketAddr,
    ) -> Result<anyhow::Result<WgUdpTransport>, Gone> {
        let bound = self.0.with(|inner| {
            if inner.dead() {
                return None;
            }
            let bound = inner.stack.udp_bind(None);
            if let Ok(id) = bound {
                inner.flows.insert(id, Slot::new(scope, true));
            }
            Some(bound)
        });
        let Some(bound) = bound else {
            return Err(self.gone());
        };
        Ok(match bound {
            Ok(id) => Ok(WgUdpTransport {
                tunnel: self.clone(),
                id,
                target: SocketAddr::new(target.ip().to_canonical(), target.port()),
            }),
            Err(BindError::NoLocalAddress) => Err(PacketRejection::Policy.into()),
            Err(BindError::AddrInUse | BindError::FlowLimit) => {
                Err(PacketRejection::Capacity.into())
            }
        })
    }
}

impl WgUdpTransport {
    /// The one send path behind `send_packet` and `send_to`, unboxed.
    async fn send(
        &self,
        target: SocketAddr,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> io::Result<()> {
        if !self.tunnel.0.allowed.contains(target.ip()) {
            return Err(PacketRejection::Policy.into());
        }
        let dst = SocketAddr::new(target.ip().to_canonical(), target.port());
        let id = self.id;
        let seq = self.tunnel.0.with(|inner| inner.udp_send(id, dst, data))?;
        self.tunnel.0.wake_owner();
        if confirmed {
            // Queue acceptance is not wire admission: the first datagram waits for the socket.
            self.tunnel.flushed(seq).await;
            if let Some(error) = self.tunnel.0.with(|inner| inner.forced(id)) {
                return Err(error);
            }
        }
        if let Some(admitted) = admitted {
            admitted.store(true, Ordering::Release);
        }
        Ok(())
    }
}

#[async_trait]
impl PacketTransport for WgUdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    /// Cancelling a send wait cannot damage the association: the datagram is already queued.
    fn send_timeout_is_congestion(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.send(self.target, data, false, None).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> io::Result<()> {
        self.send(self.target, data, true, None).await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let id = self.id;
        std::future::poll_fn(|cx| {
            self.tunnel.0.with(|inner| {
                if let Some(error) = inner.forced(id) {
                    return Poll::Ready(Err(error));
                }
                let Some(slot) = inner.flows.get_mut(&id) else {
                    return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
                };
                if let Some(received) = slot.udp.as_mut().and_then(|queue| queue.pop(buf)) {
                    return Poll::Ready(Ok(received));
                }
                slot.rx = Some(cx.waker().clone());
                Poll::Pending
            })
        })
        .await
    }
}

#[async_trait]
impl MultiTargetTransport for WgUdpTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        _domain: Option<&str>,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> io::Result<()> {
        self.send(target, data, confirmed, admitted).await
    }

    fn carrier_addr(&self) -> Option<SocketAddr> {
        Some(self.tunnel.endpoint())
    }
}
