//! Proxy chain nodes: the first hop dials its server as usual, and every later
//! hop runs its handshake over the stream the hops before it opened.

use async_trait::async_trait;
#[cfg(feature = "rprx")]
use futures_util::future::Either;
use honk_config::node::{MAX_CHAIN_HOPS, Node};
use honk_config::types::NodeProtocol;
use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use super::error::{
    HopIoFailure, IntermediateTargetFailure, UdpEntrySetupFailure, hop_io_failure,
    intermediate_target_hop,
};
use super::{
    AsyncReadWrite, ChainHopFailure, MissingProtocolHandler, MultiTargetTransport, PacketOutbound,
    PacketRejection, PacketTransport, PreparedUdpTransport, ProtocolEntry, ProxyStream,
    SharedSourceOutbound, TcpOutbound, TunnelDialOptions, TunnelUnsupported,
};
use crate::runtime::flow_observation::{observe_chain_request, without_target_milestones};
use crate::runtime::{NodeRuntime, RouteRuntime};

#[derive(Clone, Copy, PartialEq, Eq)]
enum DialPurpose {
    ConfiguredTcp,
    RoutedTcp,
    Udp,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct UdpExit {
    pub(super) index: usize,
    pub(super) tls_handoff: bool,
}

impl UdpExit {
    fn from_hops(hops: &[Arc<NodeRuntime>]) -> Self {
        // Walk through pass-through writers to the first layer that takes custody.
        let tls_handoff = hops
            .iter()
            .rev()
            .find_map(|hop| udp_writer_handoff(&hop.node));
        Self {
            index: hops.len() - 1,
            tls_handoff: tls_handoff.unwrap_or(false),
        }
    }
}

fn udp_writer_handoff(node: &Node) -> Option<bool> {
    if matches!(node.protocol(), NodeProtocol::SS | NodeProtocol::VMess)
        || node
            .transport()
            .is_some_and(|transport| matches!(transport.transport.as_str(), "grpc" | "ws"))
    {
        return Some(false);
    }
    node.tls().filter(|tls| tls.is_secure()).map(|_| true)
}

pub(super) fn native_udp_writer_handoff(node: &Node) -> Option<bool> {
    // These extra writer layers are outside the collapsed UDP route shapes.
    if node.is_xhttp()
        || node
            .vless()
            .is_some_and(|vless| vless.is_encrypted() || vless.is_vision())
    {
        return None;
    }
    Some(udp_writer_handoff(node).unwrap_or(false))
}

tokio::task_local! {
    pub(super) static UDP_EXIT_HOP: UdpExit;
}

#[cfg(feature = "rprx")]
pub(super) fn locate_udp_exit_stream(stream: Box<dyn AsyncReadWrite>) -> Box<dyn AsyncReadWrite> {
    match UDP_EXIT_HOP.try_with(|exit| exit.index) {
        Ok(index) => hop_carrier(index, stream, true, false),
        Err(_) => stream,
    }
}

/// Dials a chain through the hop runtimes of its own generation, using the
/// same handler instances the registry dispatches to.
pub(super) struct ChainHandler {
    handlers: Vec<HopHandler>,
}

struct HopHandler {
    protocol: NodeProtocol,
    tcp: Arc<dyn TcpOutbound>,
    tunneled_tcp: Option<Arc<dyn TcpOutbound>>,
    tunneled_packet: Option<Arc<dyn PacketOutbound>>,
    tunneled_shared: Option<Arc<dyn SharedSourceOutbound>>,
}

impl ChainHandler {
    pub(super) fn new(entries: &[ProtocolEntry]) -> Self {
        let handlers = entries
            .iter()
            .map(|entry| HopHandler {
                protocol: entry.descriptor.protocol,
                tcp: Arc::clone(&entry.tcp),
                tunneled_tcp: entry.tunneled_tcp.clone(),
                tunneled_packet: entry.tunneled_packet.clone(),
                tunneled_shared: entry.tunneled_shared.clone(),
            })
            .collect();
        Self { handlers }
    }

    fn hop_handler(&self, protocol: NodeProtocol) -> Result<&HopHandler, MissingProtocolHandler> {
        self.handlers
            .iter()
            .find(|handler| handler.protocol == protocol)
            .ok_or(MissingProtocolHandler(protocol))
    }

    pub(super) fn handler(&self, protocol: NodeProtocol) -> Option<&dyn TcpOutbound> {
        self.hop_handler(protocol)
            .ok()
            .map(|handler| handler.tcp.as_ref())
    }

    /// On failure, also returns the index of the executing hop.
    async fn dial_hops<'a, T, Fut>(
        handlers: &[&'a dyn TcpOutbound; MAX_CHAIN_HOPS],
        hops: &[Arc<NodeRuntime>],
        options: TunnelDialOptions,
        deadline: Instant,
        purpose: DialPurpose,
        exit: &impl Fn(
            &'a dyn TcpOutbound,
            Arc<NodeRuntime>,
            Box<dyn AsyncReadWrite>,
            TunnelDialOptions,
        ) -> Fut,
    ) -> Result<T, (usize, anyhow::Error)>
    where
        Fut: Future<Output = anyhow::Result<T>>,
    {
        let budget = || {
            options
                .connect_timeout
                .min(deadline.saturating_duration_since(Instant::now()))
        };
        let (first, rest) = hops.split_first().expect("a chain has at least two hops");
        let (server, server_domain) = server_target(&rest[0].node);
        let dial = handlers[0].dial_runtime(Arc::clone(first), server, server_domain, budget());
        let entry = hop_scope(first, without_target_milestones(dial)).await;
        let located = purpose != DialPurpose::ConfiguredTcp;
        let mut carrier = intermediate_carrier(0, entry, located)?;
        for (index, (hop, handler)) in rest.iter().zip(&handlers[1..]).enumerate() {
            let options = TunnelDialOptions {
                connect_timeout: budget(),
                ..options
            };
            let Some(next) = rest.get(index + 1) else {
                let dial = exit(*handler, Arc::clone(hop), carrier, options);
                return hop_scope(hop, dial)
                    .await
                    .map_err(|error| (index + 1, error));
            };
            let (server, server_domain) = server_target(&next.node);
            let dial = dial_tcp_over(
                *handler,
                Arc::clone(hop),
                carrier,
                server,
                server_domain,
                options,
                located,
            );
            let result = hop_scope(hop, without_target_milestones(dial)).await;
            carrier = intermediate_carrier(index + 1, result, located)?;
        }
        unreachable!("the last hop returns from the loop")
    }
}

fn dial_tcp_over<'a>(
    handler: &'a dyn TcpOutbound,
    hop: Arc<NodeRuntime>,
    carrier: Box<dyn AsyncReadWrite>,
    target: SocketAddr,
    target_domain: Option<&'a str>,
    options: TunnelDialOptions,
    located: bool,
) -> impl Future<Output = anyhow::Result<ProxyStream>> + 'a {
    #[cfg(feature = "rprx")]
    let is_routed_vmess = located && hop.node.protocol() == NodeProtocol::VMess;
    #[cfg(not(feature = "rprx"))]
    let _ = located;
    let dial = handler.dial_over(hop, carrier, target, target_domain, options);
    #[cfg(feature = "rprx")]
    let dial = if is_routed_vmess {
        Either::Left(super::vmess::ROUTED_CARRIER.scope((), dial))
    } else {
        Either::Right(dial)
    };
    dial
}

/// Each hop owns its tasks and transport evidence, leaving the chain's
/// `TransportQuality` empty. The entry inherits the chain's dial admission scope.
fn hop_scope<T>(
    hop: &Arc<NodeRuntime>,
    dial: impl Future<Output = anyhow::Result<T>>,
) -> impl Future<Output = anyhow::Result<T>> {
    hop.scope_tasks(hop.transport_quality().scope(dial))
}

/// The next hop's server as a dial target. A domain stays unresolved for the
/// hop before it to resolve, as a proxied target domain always is.
fn server_target(node: &Node) -> (SocketAddr, Option<&str>) {
    let host = node.host();
    match host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        Ok(ip) => (SocketAddr::new(ip, node.port), None),
        Err(_) => (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), node.port),
            Some(host),
        ),
    }
}

fn intermediate_carrier(
    index: usize,
    result: anyhow::Result<ProxyStream>,
    routed: bool,
) -> Result<Box<dyn AsyncReadWrite>, (usize, anyhow::Error)> {
    let ProxyStream { stream, .. } =
        result.map_err(|error| (index, IntermediateTargetFailure::dial(index + 1, error)))?;
    Ok(hop_carrier(index, stream, routed, true))
}

fn hop_carrier(
    index: usize,
    stream: Box<dyn AsyncReadWrite>,
    routed: bool,
    targets_next_hop: bool,
) -> Box<dyn AsyncReadWrite> {
    // A pass-through hop adds no codec to blame. In particular, a plain
    // SOCKS5 chain still returns the original socket for splice.
    let concrete = (*stream).as_any();
    if concrete.is::<tokio::net::TcpStream>() || concrete.is::<HopCarrier>() {
        return stream;
    }
    // Stock tunneled handlers do not return Vision. A custom handler can
    // nevertheless return a native spliceable stream instead of a new codec.
    #[cfg(feature = "rprx")]
    if !targets_next_hop && ProxyStream::is_vision_splice_stream(concrete) {
        return stream;
    }
    Box::new(HopCarrier {
        index,
        routed,
        targets_next_hop,
        stream,
    })
}

#[derive(Debug)]
struct HopCarrier {
    index: usize,
    routed: bool,
    targets_next_hop: bool,
    stream: Box<dyn AsyncReadWrite>,
}

impl HopCarrier {
    fn map_error(&self, error: io::Error) -> io::Error {
        if self.routed {
            HopIoFailure::io(self.index, error, self.targets_next_hop)
        } else {
            IntermediateTargetFailure::io(self.index + 1, error)
        }
    }
}

impl AsyncRead for HopCarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream)
            .poll_read(cx, buf)
            .map_err(|error| self.map_error(error))
    }
}

impl AsyncWrite for HopCarrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream)
            .poll_write(cx, buf)
            .map_err(|error| self.map_error(error))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream)
            .poll_write_vectored(cx, bufs)
            .map_err(|error| self.map_error(error))
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream)
            .poll_flush(cx)
            .map_err(|error| self.map_error(error))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream)
            .poll_shutdown(cx)
            .map_err(|error| self.map_error(error))
    }
}

fn reality_mask_certificate(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<crate::reality::RealityMaskCertificate>())
}

#[async_trait]
impl TcpOutbound for ChainHandler {
    async fn dial(
        &self,
        node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!(
            "chain node '{}' dials only through a runtime generation",
            node.name
        )
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dial_tcp(
            &runtime.node.name,
            runtime.chain_hops(),
            target,
            target_domain,
            connect_timeout,
            false,
        )
        .await
    }
}

impl ChainHandler {
    /// Dial a route through group exits over its generation's hop runtimes.
    pub(super) fn dial_route_tcp<'a>(
        &'a self,
        route: &'a RouteRuntime,
        target: SocketAddr,
        target_domain: Option<&'a str>,
        connect_timeout: Duration,
    ) -> impl Future<Output = anyhow::Result<ProxyStream>> + 'a {
        self.dial_tcp(
            "group exit route",
            route.hops(),
            target,
            target_domain,
            connect_timeout,
            true,
        )
    }

    async fn dial_tcp(
        &self,
        label: &str,
        hops: &[Arc<NodeRuntime>],
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        routed: bool,
    ) -> anyhow::Result<ProxyStream> {
        let quic_entry = hops.first().is_some_and(|hop| {
            matches!(
                hop.node.protocol(),
                NodeProtocol::Hysteria2 | NodeProtocol::Tuic | NodeProtocol::Juicity
            )
        });
        let mut result = self
            .dial_chain(
                label,
                hops,
                connect_timeout,
                if routed {
                    DialPurpose::RoutedTcp
                } else {
                    DialPurpose::ConfiguredTcp
                },
                |handler, hop, carrier, options| async move {
                    let dial = dial_tcp_over(
                        handler,
                        hop,
                        carrier,
                        target,
                        target_domain,
                        options,
                        routed,
                    );
                    if quic_entry {
                        observe_chain_request(dial).await
                    } else {
                        dial.await
                    }
                },
            )
            .await?;
        if routed {
            result.stream = hop_carrier(hops.len() - 1, result.stream, true, false);
        }
        Ok(result)
    }

    /// UDP through a route's exit over its generation's hop runtimes.
    pub(super) async fn dial_route_udp(
        &self,
        route: &RouteRuntime,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_udp_via(
            route.hops(),
            route.udp_capable(),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    async fn dial_udp_via(
        &self,
        hops: &[Arc<NodeRuntime>],
        udp_capable: bool,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let (exit, packet) = self.udp_packet_exit(hops, udp_capable)?;
        if !crate::descriptor::udp_target_allowed(exit, target.port()) {
            return Err(PacketRejection::Policy.into());
        }
        self.dial_chain(
            "UDP",
            hops,
            connect_timeout,
            DialPurpose::Udp,
            |_, hop, carrier, options| {
                UDP_EXIT_HOP.scope(
                    UdpExit::from_hops(hops),
                    packet.dial_udp_over(hop, carrier, target, target_domain, options),
                )
            },
        )
        .await
    }

    pub(super) fn udp_terminal<'a>(
        &self,
        hops: &'a [Arc<NodeRuntime>],
        udp_capable: bool,
    ) -> anyhow::Result<&'a Node> {
        let (exit, _) = self.udp_packet_exit(hops, udp_capable)?;
        self.tcp_handlers(hops, DialPurpose::Udp)?;
        Ok(exit)
    }

    fn udp_packet_exit<'a>(
        &self,
        hops: &'a [Arc<NodeRuntime>],
        udp_capable: bool,
    ) -> anyhow::Result<(&'a Node, &dyn PacketOutbound)> {
        let (exit, terminal) = self.udp_exit(hops, udp_capable)?;
        let packet = terminal
            .tunneled_packet
            .as_deref()
            .ok_or(TunnelUnsupported(terminal.protocol.as_str()))?;
        Ok((exit, packet))
    }

    fn udp_exit<'a>(
        &self,
        hops: &'a [Arc<NodeRuntime>],
        udp_capable: bool,
    ) -> anyhow::Result<(&'a Node, &HopHandler)> {
        let exit = hops
            .last()
            .filter(|_| udp_capable)
            .ok_or(PacketRejection::Policy)?;
        Ok((&exit.node, self.hop_handler(exit.node.protocol())?))
    }

    fn tcp_handlers(
        &self,
        hops: &[Arc<NodeRuntime>],
        purpose: DialPurpose,
    ) -> anyhow::Result<[&dyn TcpOutbound; MAX_CHAIN_HOPS]> {
        let handler = |hop: &Arc<NodeRuntime>| {
            let protocol = hop.node.protocol();
            self.handler(protocol)
                .ok_or(MissingProtocolHandler(protocol))
        };
        let mut handlers = [handler(&hops[0])?; MAX_CHAIN_HOPS];
        for (index, (slot, hop)) in handlers[1..].iter_mut().zip(&hops[1..]).enumerate() {
            let protocol = hop.node.protocol();
            *slot = if purpose == DialPurpose::Udp && index + 2 < hops.len() {
                let entry = self.hop_handler(protocol)?;
                entry
                    .tunneled_tcp
                    .as_deref()
                    .ok_or(TunnelUnsupported(protocol.as_str()))?
            } else {
                handler(hop)?
            };
        }
        Ok(handlers)
    }

    /// One deadline covers the whole chain, the caller's per-candidate bound;
    /// each hop gets what remains of it, capped at `connect_timeout`. A REALITY
    /// mask certificate on a tunneled hop redials the chain once without
    /// hybrid key shares, as a direct REALITY dial retries once. The first hop
    /// dials directly and has already had that retry, so its failure stands.
    /// Routed TCP and composed UDP attach their locator after the retry decision.
    /// The deadline belongs to no hop.
    async fn dial_chain<'a, T, Fut>(
        &'a self,
        label: &str,
        hops: &[Arc<NodeRuntime>],
        connect_timeout: Duration,
        purpose: DialPurpose,
        exit: impl Fn(
            &'a dyn TcpOutbound,
            Arc<NodeRuntime>,
            Box<dyn AsyncReadWrite>,
            TunnelDialOptions,
        ) -> Fut,
    ) -> anyhow::Result<T>
    where
        Fut: Future<Output = anyhow::Result<T>>,
    {
        if hops.len() < 2 {
            anyhow::bail!("chain node '{label}' has no hops in this runtime");
        }
        let deadline = Instant::now() + connect_timeout * 3;
        // A missing backend is knowable before any prefix traffic. Use the
        // same frozen handlers for both attempts; no allocation is needed.
        let handlers = self.tcp_handlers(hops, purpose)?;
        let scope = crate::runtime::capture_dial_scope();
        let attempt = |reality_key_shares| {
            // Retain physical dial credits through this attempt's handshakes.
            // A serial retry drops the failed carrier and owns fresh credits.
            scope.physical_setup().scope(Self::dial_hops(
                &handlers,
                hops,
                TunnelDialOptions {
                    connect_timeout,
                    reality_key_shares,
                },
                deadline,
                purpose,
                &exit,
            ))
        };
        let dial = async {
            let first = attempt(true).await;
            match first {
                Err((hop, error)) if hop > 0 && reality_mask_certificate(&error) => {
                    attempt(false).await
                }
                result => result,
            }
            .map_err(|(index, error)| {
                if purpose == DialPurpose::ConfiguredTcp {
                    return error;
                }
                let source = error.as_ref();
                let hop = intermediate_target_hop(source)
                    .or_else(|| hop_io_failure(source))
                    .unwrap_or(index);
                let failure = ChainHopFailure {
                    hop,
                    node: hops[hop].node.id,
                    error,
                };
                if purpose == DialPurpose::Udp && hop == 0 {
                    UdpEntrySetupFailure(failure).into()
                } else {
                    failure.into()
                }
            })
        };
        tokio::time::timeout_at(deadline, dial).await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "proxy chain setup timeout")
        })?
    }
}

#[async_trait]
impl PacketOutbound for ChainHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        anyhow::bail!(
            "chain node '{}' dials only through a runtime generation",
            node.name
        )
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_udp_via(
            runtime.chain_hops(),
            runtime.udp_capable,
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }
}

/// One association through the chain for a whole client source, over the
/// exit's tunneled shared slot.
#[async_trait]
impl SharedSourceOutbound for ChainHandler {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        _speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        let hops = runtime.chain_hops();
        let (exit, terminal) = self.udp_exit(hops, runtime.udp_capable)?;
        if !crate::descriptor::udp_target_allowed(exit, target.port()) {
            return Err(PacketRejection::Policy.into());
        }
        let shared = terminal
            .tunneled_shared
            .as_deref()
            .ok_or(TunnelUnsupported(terminal.protocol.as_str()))?;
        self.dial_chain(
            &runtime.node.name,
            hops,
            connect_timeout,
            DialPurpose::Udp,
            |_, hop, carrier, options| {
                UDP_EXIT_HOP.scope(
                    UdpExit::from_hops(hops),
                    shared.prepare_shared_source_over(hop, carrier, target, target_domain, options),
                )
            },
        )
        .await
        .map(PreparedUdpTransport::ready)
    }
}

#[cfg(test)]
mod tests;
