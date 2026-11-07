use super::*;
use crate::control::netstack::{FlowIo, FlowRetirement};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) enum TcpInput {
    Kernel(TcpStream),
    Packet(FlowIo),
}

pub(super) enum TcpFlow {
    Kernel(super::super::handoff::TcpFlowGuard),
    Packet(PacketFlow),
}

pub(super) struct PacketFlow {
    retirement: FlowRetirement,
    stream: FlowIo,
    tracker: Arc<ConnectionTracker>,
    tracker_id: Option<uuid::Uuid>,
    completion_installed: bool,
}

impl TcpFlow {
    pub(super) fn packet(stream: FlowIo, tracker: Arc<ConnectionTracker>) -> Self {
        Self::Packet(PacketFlow {
            retirement: stream.retirement(),
            stream,
            tracker,
            tracker_id: None,
            completion_installed: false,
        })
    }

    pub(super) fn is_kernel(&self) -> bool {
        matches!(self, Self::Kernel(_))
    }

    pub(super) fn mark_packet_rx_admitted(&self) {
        if let Self::Packet(flow) = self {
            flow.stream.mark_rx_admitted();
        }
    }

    pub(super) async fn serve_dns(
        &mut self,
        controller: &crate::control::dns_control::DnsController,
        client: SocketAddr,
        destination: SocketAddr,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Kernel(flow) => {
                controller
                    .handle_tcp_dns(flow.stream_mut(), client, destination)
                    .await
            }
            Self::Packet(flow) => {
                let scope = flow.stream.scope();
                controller
                    .handle_packet_tcp_dns(&mut flow.stream, client, destination, scope)
                    .await
            }
        }
    }

    pub(super) fn hold_packet_completion(
        &mut self,
        close: &mut Option<CloseCompletion>,
        outbound: &mut Option<crate::stats::ActiveConnectionGuard>,
    ) -> std::io::Result<()> {
        let Self::Packet(flow) = self else {
            return Ok(());
        };
        let identity_memory = if flow.tracker.is_enabled() {
            Some(flow.stream.reserve_memory(uuid::fmt::Hyphenated::LENGTH)?)
        } else {
            None
        };
        let tracker_id = identity_memory.as_ref().map(|_| uuid::Uuid::new_v4());
        let retired_id = tracker_id.map(|id| id.to_string());
        let tracker = Arc::clone(&flow.tracker);
        let ack = RetireAck {
            close: close.take(),
            outbound: outbound.take(),
        };
        flow.stream.set_retirement_callback(move || {
            if let Some(id) = retired_id {
                tracker.remove(&id);
            }
            drop(ack.outbound);
            if let Some(close) = ack.close {
                close.0.finish(true);
            }
            drop(identity_memory);
        })?;
        flow.tracker_id = tracker_id;
        flow.completion_installed = true;
        Ok(())
    }

    pub(super) fn track_if_enabled(
        &mut self,
        make_entry: impl FnOnce(String) -> crate::connection_tracker::ConnectionEntry,
        owner: ConnectionOwner,
    ) -> Option<String> {
        match self {
            Self::Kernel(flow) => {
                flow.track_if_enabled(|| make_entry(uuid::Uuid::new_v4().to_string()), owner)
            }
            Self::Packet(flow) => {
                if !flow.tracker.is_enabled() {
                    return None;
                }
                let id = flow.tracker_id?;
                Some(
                    flow.tracker
                        .register_owned(make_entry(id.to_string()), owner),
                )
            }
        }
    }

    pub(super) async fn relay(
        &mut self,
        proxy: honk_outbound::ProxyStream,
        client: SocketAddr,
        destination: SocketAddr,
        progress: relay::RelayProgress,
    ) -> anyhow::Result<relay::RelayStats> {
        match self {
            Self::Kernel(flow) => {
                relay::relay_proxy(flow.stream_mut(), proxy, client, destination, progress).await
            }
            Self::Packet(flow) => {
                relay::splice::relay_auto(
                    &mut flow.stream,
                    proxy.stream,
                    client,
                    destination,
                    Some(progress),
                )
                .await
            }
        }
    }

    pub(super) async fn retire(self, ack: RetireAck) -> bool {
        match self {
            Self::Kernel(flow) => flow.retire(ack).await,
            Self::Packet(mut flow) => {
                if !flow.completion_installed
                    && let Err(error) = flow.stream.set_retirement_callback(move || {
                        drop(ack.outbound);
                        if let Some(close) = ack.close {
                            close.0.finish(true);
                        }
                    })
                {
                    error!(%error, "packet TCP completion reservation failed");
                    return false;
                }
                if let Err(error) = flow.stream.retire().await {
                    error!(%error, "packet TCP application retirement failed");
                    return false;
                }
                if let Err(error) = flow.retirement.wait().await {
                    error!(%error, "packet TCP exact retirement failed");
                    return false;
                }
                true
            }
        }
    }
}

impl AsyncRead for TcpFlow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Kernel(flow) => Pin::new(flow.stream_mut()).poll_read(cx, buffer),
            Self::Packet(flow) => Pin::new(&mut flow.stream).poll_read(cx, buffer),
        }
    }
}

impl AsyncWrite for TcpFlow {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Kernel(flow) => Pin::new(flow.stream_mut()).poll_write(cx, buffer),
            Self::Packet(flow) => Pin::new(&mut flow.stream).poll_write(cx, buffer),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Kernel(flow) => Pin::new(flow.stream_mut()).poll_flush(cx),
            Self::Packet(flow) => Pin::new(&mut flow.stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Kernel(flow) => Pin::new(flow.stream_mut()).poll_shutdown(cx),
            Self::Packet(flow) => Pin::new(&mut flow.stream).poll_shutdown(cx),
        }
    }
}
