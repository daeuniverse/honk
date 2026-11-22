//! Proxy chain nodes: the first hop dials its server as usual, and every later
//! hop runs its handshake over the stream the hops before it opened.

use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use super::error::IntermediateTargetFailure;
use super::{AsyncReadWrite, ProtocolEntry, ProxyStream, TcpOutbound, TunnelDialOptions};
use crate::runtime::NodeRuntime;
use crate::runtime::flow_observation::without_target_milestones;

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

    fn handler(&self, node: &Node) -> anyhow::Result<&Arc<dyn TcpOutbound>> {
        self.handlers
            .iter()
            .find(|(protocol, _)| *protocol == node.protocol())
            .map(|(_, handler)| handler)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", node.protocol()))
    }

    /// On failure, also returns the index of the hop that failed.
    async fn dial_hops(
        &self,
        hops: &[Arc<NodeRuntime>],
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        deadline: Instant,
        reality_key_shares: bool,
    ) -> Result<ProxyStream, (usize, anyhow::Error)> {
        let budget = || connect_timeout.min(deadline.saturating_duration_since(Instant::now()));
        let at = |hop: usize| move |error| (hop, error);
        let (first, rest) = hops.split_first().expect("a chain has at least two hops");
        let (server, server_domain) = server_target(&rest[0].node);
        let handler = self.handler(&first.node).map_err(at(0))?;
        let entry = hop_scope(
            first,
            without_target_milestones(handler.dial_runtime(
                Arc::clone(first),
                server,
                server_domain,
                budget(),
            )),
        )
        .await;
        let mut carrier = intermediate_carrier(0, entry)?;
        for (index, hop) in rest.iter().enumerate() {
            let handler = self.handler(&hop.node).map_err(at(index + 1))?;
            let options = TunnelDialOptions {
                connect_timeout: budget(),
                reality_key_shares,
            };
            let Some(next) = rest.get(index + 1) else {
                let dial =
                    handler.dial_over(Arc::clone(hop), carrier, target, target_domain, options);
                return if matches!(
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
                .map_err(at(index + 1));
            };
            let (server, server_domain) = server_target(&next.node);
            let result = hop_scope(
                hop,
                without_target_milestones(handler.dial_over(
                    Arc::clone(hop),
                    carrier,
                    server,
                    server_domain,
                    options,
                )),
            )
            .await;
            carrier = intermediate_carrier(index + 1, result)?;
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
) -> Result<Box<dyn AsyncReadWrite>, (usize, anyhow::Error)> {
    let hop = index + 1;
    let ProxyStream { stream, .. } =
        result.map_err(|error| (index, IntermediateTargetFailure::dial(hop, error)))?;
    // Bare sockets can still use splice. Pass-through hops can reuse the wrapper.
    let concrete = (*stream).as_any();
    if concrete.is::<tokio::net::TcpStream>() || concrete.is::<IntermediateCarrier>() {
        return Ok(stream);
    }
    Ok(Box::new(IntermediateCarrier { hop, stream }))
}

#[derive(Debug)]
struct IntermediateCarrier {
    hop: usize,
    stream: Box<dyn AsyncReadWrite>,
}

impl AsyncRead for IntermediateCarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream)
            .poll_read(cx, buf)
            .map_err(|error| IntermediateTargetFailure::io(self.hop, error))
    }
}

impl AsyncWrite for IntermediateCarrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream)
            .poll_write(cx, buf)
            .map_err(|error| IntermediateTargetFailure::io(self.hop, error))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream)
            .poll_write_vectored(cx, bufs)
            .map_err(|error| IntermediateTargetFailure::io(self.hop, error))
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream)
            .poll_flush(cx)
            .map_err(|error| IntermediateTargetFailure::io(self.hop, error))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream)
            .poll_shutdown(cx)
            .map_err(|error| IntermediateTargetFailure::io(self.hop, error))
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

    /// Each hop gets the remaining chain deadline, capped at `connect_timeout`.
    /// A tunneled REALITY mask certificate redials the chain once without hybrid
    /// key shares. The direct entry's own dial already handles that retry.
    async fn dial_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let hops = runtime.chain_hops();
        if hops.len() < 2 {
            anyhow::bail!(
                "chain node '{}' has no hops in this runtime",
                runtime.node.name
            );
        }
        let deadline = Instant::now() + connect_timeout * 3;
        let scope = crate::runtime::capture_dial_scope();
        let attempt = |reality_key_shares| {
            // Retain physical dial credits through this attempt's handshakes.
            // A serial retry drops the failed carrier and owns fresh credits.
            scope.physical_setup().scope(self.dial_hops(
                hops,
                target,
                target_domain,
                connect_timeout,
                deadline,
                reality_key_shares,
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
            .map_err(|(_, error)| error)
        };
        tokio::time::timeout_at(deadline, dial).await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "proxy chain setup timeout")
        })?
    }
}

#[cfg(test)]
mod tests;
