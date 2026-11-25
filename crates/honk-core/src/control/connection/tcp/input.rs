use super::*;
use crate::control::netstack::{DirectRelayOwner, FlowIo, FlowRetirement};
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_outbound::ProxyStream;
#[cfg(feature = "native-api")]
use honk_outbound::runtime::flow_observation::{self, FlowObserver};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// Boxing the packet stream would allocate for each packet-backed TCP flow.
#[allow(clippy::large_enum_variant)]
pub(super) enum TcpInput {
    Kernel(TcpStream),
    Packet(FlowIo),
}

// Bound what each shared connection future carries, including non-Host connections.
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
const _: () = assert!(size_of::<TcpFlow>() <= 448);

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

struct PacketCompletion {
    tracked: Option<(Arc<ConnectionTracker>, uuid::Uuid)>,
    ack: RetireAck,
}

impl PacketCompletion {
    fn finish(self) {
        if let Some((tracker, id)) = self.tracked {
            tracker.remove(
                id.as_hyphenated()
                    .encode_lower(&mut uuid::Uuid::encode_buffer()),
            );
        }
        finish_packet_ack(self.ack);
    }
}

fn finish_packet_ack(ack: RetireAck) {
    drop(ack.outbound);
    if let Some(close) = ack.close {
        close.0.finish(true);
    }
}

impl DirectRelayOwner {
    pub(in crate::control) fn with_completion_credit(
        &self,
        budget: &Arc<MemoryBudget>,
    ) -> Option<(Self, MemoryReservation)> {
        // The optional parent must not spend the bytes its original flow needs to retire.
        let credit = budget.reserve(size_of::<PacketCompletion>())?;
        Some((self.clone(), credit))
    }
}

impl PacketFlow {
    fn install_completion(
        &mut self,
        ack: RetireAck,
        id: Option<uuid::Uuid>,
        credit: Option<MemoryReservation>,
    ) -> std::io::Result<()> {
        if credit.is_none() && id.is_none() {
            return self
                .stream
                .set_retirement_callback(move || finish_packet_ack(ack));
        }
        let completion = PacketCompletion {
            tracked: id.map(|id| (Arc::clone(&self.tracker), id)),
            ack,
        };
        self.stream
            .set_retirement_callback_with_credit(credit, move || completion.finish())
    }
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

    pub(super) fn packet_source(&self) -> Option<&crate::control::netstack::SourceWork> {
        match self {
            Self::Kernel(_) => None,
            Self::Packet(flow) => flow.stream.packet_source(),
        }
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
        credit: Option<MemoryReservation>,
    ) -> std::io::Result<()> {
        let Self::Packet(flow) = self else {
            return Ok(());
        };
        let tracker_id = flow.tracker.is_enabled().then(uuid::Uuid::new_v4);
        let ack = RetireAck {
            close: close.take(),
            outbound: outbound.take(),
        };
        flow.install_completion(ack, tracker_id, credit)?;
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

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn relay_owned(
        mut self,
        direct: Option<&mut DirectRelay<'_>>,
        mut proxy: ProxyStream,
        client: SocketAddr,
        destination: SocketAddr,
        progress: relay::RelayProgress,
        prefix: SniffPrefix,
        close: Option<&Arc<CloseSignal>>,
        #[cfg(feature = "native-api")] observer: Option<&FlowObserver>,
    ) -> Option<(Self, RelayCompletion)> {
        let on_owner = move |mut flow: PacketFlow, proxy: ProxyStream, progress, prefix| {
            let stream = proxy.stream;
            let close = close.cloned();
            #[cfg(feature = "native-api")]
            let observer = observer.cloned().or_else(flow_observation::current);
            async move {
                let operation = async {
                    let socket = match stream.into_any().downcast::<TcpStream>() {
                        Ok(socket) => *socket,
                        Err(_) => unreachable!("relay admission proved a raw TCP socket"),
                    };
                    // into_std deregisters through the socket's original registration.
                    let mut upstream = match socket.into_std().and_then(TcpStream::from_std) {
                        Ok(upstream) => upstream,
                        Err(error) => return RelayCompletion::LocalError(error),
                    };
                    if let Err(early) =
                        write_prefix(&mut upstream, &prefix, &progress, close.as_ref()).await
                    {
                        return early;
                    }
                    drop(prefix);
                    // Each copy turn consumes Tokio's socket budget on upstream reads or writes.
                    relay_until_close(
                        close.as_ref(),
                        relay::splice::relay_auto(
                            &mut flow.stream,
                            upstream,
                            client,
                            destination,
                            Some(progress),
                        ),
                    )
                    .await
                };
                #[cfg(feature = "native-api")]
                let operation = observe_relay(observer.as_ref(), operation);
                let result = operation.await;
                (Self::Packet(flow), result)
            }
        };

        if let Some(direct) = direct
            && let Self::Packet(flow) = &self
            && let Some((memory, join_lease)) =
                direct.reserve(&flow.stream, &proxy, &prefix, &on_owner)
        {
            let Self::Packet(flow) = self else {
                unreachable!("only a packet flow can transfer its relay");
            };
            return direct
                .run(memory, join_lease, on_owner(flow, proxy, progress, prefix))
                .await;
        }

        let operation = async {
            if let Err(early) = write_prefix(&mut *proxy.stream, &prefix, &progress, close).await {
                return early;
            }
            drop(prefix);
            relay_until_close(close, self.relay(proxy, client, destination, progress)).await
        };
        #[cfg(feature = "native-api")]
        let operation = observe_relay(observer, operation);
        let result = operation.await;
        Some((self, result))
    }

    async fn relay(
        &mut self,
        proxy: ProxyStream,
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

    pub(super) async fn retire(self, ack: RetireAck, credit: Option<MemoryReservation>) -> bool {
        match self {
            Self::Kernel(flow) => flow.retire(ack).await,
            Self::Packet(mut flow) => {
                if !flow.completion_installed
                    && let Err(error) = flow.install_completion(ack, None, credit)
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

async fn relay_until_close(
    close: Option<&Arc<CloseSignal>>,
    relay: impl Future<Output = anyhow::Result<relay::RelayStats>>,
) -> RelayCompletion {
    tokio::select! {
        biased;
        _ = wait_for_close(close) => RelayCompletion::Closed,
        result = relay => RelayCompletion::Relayed(result),
    }
}

#[cfg(feature = "native-api")]
async fn observe_relay<T>(
    observer: Option<&FlowObserver>,
    operation: impl Future<Output = T>,
) -> T {
    match observer {
        Some(observer) => observer.scope(operation).await,
        None => operation.await,
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
