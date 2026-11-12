//! Proxy chain nodes: the first hop dials its server as usual, and every later
//! hop runs its handshake over the stream the hops before it opened.

use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use super::{
    NodeFailure, ProxyStream, TcpOutbound, TunnelDialOptions, is_packet_rejection, target_failure,
};
use crate::runtime::NodeRuntime;
use crate::runtime::flow_observation::without_target_milestones;

/// Dials a chain through the hop runtimes of its own generation, using the
/// same handler instances the registry dispatches to.
pub struct ChainHandler {
    handlers: Vec<(NodeProtocol, Arc<dyn TcpOutbound>)>,
}

impl ChainHandler {
    pub fn new(handlers: Vec<(NodeProtocol, Arc<dyn TcpOutbound>)>) -> Self {
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
        let mut carrier = hop_scope(
            first,
            without_target_milestones(handler.dial_runtime(
                Arc::clone(first),
                server,
                server_domain,
                budget(),
            )),
        )
        .await
        .map_err(|error| (0, earlier_hop_error(error)))?
        .stream;
        for (index, hop) in rest.iter().enumerate() {
            let handler = self.handler(&hop.node).map_err(at(index + 1))?;
            let options = TunnelDialOptions {
                connect_timeout: budget(),
                reality_key_shares,
            };
            let Some(next) = rest.get(index + 1) else {
                return hop_scope(
                    hop,
                    handler.dial_over(Arc::clone(hop), carrier, target, target_domain, options),
                )
                .await
                .map_err(at(index + 1));
            };
            let (server, server_domain) = server_target(&next.node);
            carrier = hop_scope(
                hop,
                without_target_milestones(handler.dial_over(
                    Arc::clone(hop),
                    carrier,
                    server,
                    server_domain,
                    options,
                )),
            )
            .await
            .map_err(|error| (index + 1, earlier_hop_error(error)))?
            .stream;
        }
        unreachable!("the last hop returns from the loop")
    }
}

/// A hop's background tasks and transport evidence belong to its own runtime,
/// as for a direct dial through the registry. Carrier pressure from chain
/// traffic therefore lands on the hops, the entry's node included, and the
/// chain runtime's own `TransportQuality` stays empty. The first hop's
/// physical connection inherits the chain's dial admission scope.
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

/// An earlier hop's target is the next hop's server, so its target failure is
/// a failure of the chain itself. Packet policy rejections keep their class.
fn earlier_hop_error(error: anyhow::Error) -> anyhow::Error {
    if is_packet_rejection(&error) || !target_failure(&error) {
        return error;
    }
    NodeFailure(anyhow::anyhow!("{error:#}")).into()
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

    /// One deadline covers the whole chain, the caller's per-candidate bound;
    /// each hop gets what remains of it, capped at `connect_timeout`. A REALITY
    /// mask certificate on a tunneled hop redials the chain once without
    /// hybrid key shares, as a direct REALITY dial retries once. The first hop
    /// dials directly and has already had that retry, so its failure stands.
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
        let dial = async {
            match self
                .dial_hops(hops, target, target_domain, connect_timeout, deadline, true)
                .await
            {
                Err((hop, error)) if hop > 0 && reality_mask_certificate(&error) => {
                    self.dial_hops(
                        hops,
                        target,
                        target_domain,
                        connect_timeout,
                        deadline,
                        false,
                    )
                    .await
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
