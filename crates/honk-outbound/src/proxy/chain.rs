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
    HopIoFailure, IntermediateTargetFailure, hop_io_failure, intermediate_target_hop,
};
use super::{
    AsyncReadWrite, ChainHopFailure, MissingProtocolHandler, ProtocolEntry, ProxyStream,
    TcpOutbound, TunnelDialOptions,
};
use crate::runtime::flow_observation::without_target_milestones;
use crate::runtime::{NodeRuntime, RouteRuntime};

/// Dials a chain through the hop runtimes of its own generation, using the
/// same handler instances the registry dispatches to.
pub(super) struct ChainHandler {
    handlers: Vec<(NodeProtocol, Arc<dyn TcpOutbound>)>,
}

impl ChainHandler {
    pub(super) fn new(entries: &[ProtocolEntry]) -> Self {
        let handlers = entries
            .iter()
            .map(|entry| (entry.descriptor.protocol, Arc::clone(&entry.tcp)))
            .collect();
        Self { handlers }
    }

    pub(super) fn handler(&self, protocol: NodeProtocol) -> Option<&dyn TcpOutbound> {
        self.handlers
            .iter()
            .find(|(registered, _)| *registered == protocol)
            .map(|(_, handler)| handler.as_ref())
    }

    /// On failure, also returns the index of the executing hop.
    async fn dial_hops(
        handlers: &[&dyn TcpOutbound; MAX_CHAIN_HOPS],
        hops: &[Arc<NodeRuntime>],
        target: SocketAddr,
        target_domain: Option<&str>,
        options: TunnelDialOptions,
        deadline: Instant,
        routed: bool,
    ) -> Result<ProxyStream, (usize, anyhow::Error)> {
        let budget = || {
            options
                .connect_timeout
                .min(deadline.saturating_duration_since(Instant::now()))
        };
        let at = |hop: usize| move |error| (hop, error);
        let (first, rest) = hops.split_first().expect("a chain has at least two hops");
        let (server, server_domain) = server_target(&rest[0].node);
        let entry = hop_scope(
            first,
            without_target_milestones(handlers[0].dial_runtime(
                Arc::clone(first),
                server,
                server_domain,
                budget(),
            )),
        )
        .await;
        let mut carrier = intermediate_carrier(0, entry, routed)?;
        for (index, (hop, handler)) in rest.iter().zip(&handlers[1..]).enumerate() {
            let options = TunnelDialOptions {
                connect_timeout: budget(),
                ..options
            };
            let next = rest.get(index + 1);
            let (target, target_domain) =
                next.map_or((target, target_domain), |next| server_target(&next.node));
            let dial = handler.dial_over(Arc::clone(hop), carrier, target, target_domain, options);
            #[cfg(feature = "rprx")]
            let dial = if routed && hop.node.protocol() == NodeProtocol::VMess {
                Either::Left(super::vmess::ROUTED_CARRIER.scope((), dial))
            } else {
                Either::Right(dial)
            };
            if next.is_none() {
                let mut result = if matches!(
                    first.node.protocol(),
                    NodeProtocol::Hysteria2 | NodeProtocol::Tuic | NodeProtocol::Juicity
                ) {
                    hop_scope(
                        hop,
                        crate::runtime::flow_observation::observe_chain_request(dial),
                    )
                    .await
                } else {
                    hop_scope(hop, dial).await
                }
                .map_err(at(index + 1))?;
                if routed {
                    result.stream = hop_carrier(index + 1, result.stream, true, false);
                }
                return Ok(result);
            }
            let result = hop_scope(hop, without_target_milestones(dial)).await;
            carrier = intermediate_carrier(index + 1, result, routed)?;
        }
        unreachable!("the last hop returns from the loop")
    }
}

/// Each hop owns its tasks and transport evidence, leaving the chain's
/// `TransportQuality` empty. The entry inherits the chain's dial admission scope.
fn hop_scope(
    hop: &Arc<NodeRuntime>,
    dial: impl Future<Output = anyhow::Result<ProxyStream>>,
) -> impl Future<Output = anyhow::Result<ProxyStream>> {
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
        self.dial_chain(
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
    pub(super) async fn dial_route_tcp(
        &self,
        route: &RouteRuntime,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dial_chain(
            "group exit route",
            route.hops(),
            target,
            target_domain,
            connect_timeout,
            true,
        )
        .await
    }

    /// One deadline covers the whole chain, the caller's per-candidate bound;
    /// each hop gets what remains of it, capped at `connect_timeout`. A REALITY
    /// mask certificate on a tunneled hop redials the chain once without
    /// hybrid key shares, as a direct REALITY dial retries once. The first hop
    /// dials directly and has already had that retry, so its failure stands.
    /// Routed dials attach their locator after the retry decision. The
    /// deadline belongs to no hop.
    async fn dial_chain(
        &self,
        label: &str,
        hops: &[Arc<NodeRuntime>],
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        routed: bool,
    ) -> anyhow::Result<ProxyStream> {
        if hops.len() < 2 {
            anyhow::bail!("chain node '{label}' has no hops in this runtime");
        }
        let deadline = Instant::now() + connect_timeout * 3;
        // A missing backend is knowable before any prefix traffic. Use the
        // same frozen handlers for both attempts; no allocation is needed.
        let handler = |hop: &Arc<NodeRuntime>| {
            let protocol = hop.node.protocol();
            self.handler(protocol)
                .ok_or(MissingProtocolHandler(protocol))
        };
        let mut handlers = [handler(&hops[0])?; MAX_CHAIN_HOPS];
        for (slot, hop) in handlers[1..].iter_mut().zip(&hops[1..]) {
            *slot = handler(hop)?;
        }
        let scope = crate::runtime::capture_dial_scope();
        let attempt = |reality_key_shares| {
            // Retain physical dial credits through this attempt's handshakes.
            // A serial retry drops the failed carrier and owns fresh credits.
            scope.physical_setup().scope(Self::dial_hops(
                &handlers,
                hops,
                target,
                target_domain,
                TunnelDialOptions {
                    connect_timeout,
                    reality_key_shares,
                },
                deadline,
                routed,
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
                if !routed {
                    return error;
                }
                let source = error.as_ref();
                let hop = intermediate_target_hop(source)
                    .or_else(|| hop_io_failure(source))
                    .unwrap_or(index);
                ChainHopFailure {
                    hop,
                    node: hops[hop].node.id,
                    error,
                }
                .into()
            })
        };
        tokio::time::timeout_at(deadline, dial).await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "proxy chain setup timeout")
        })?
    }
}

#[cfg(test)]
mod tests;
