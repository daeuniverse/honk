//! Proxy chain nodes: the first hop dials its server as usual, and every later
//! hop runs its handshake over the stream the hops before it opened.

use async_trait::async_trait;
use honk_config::node::Node;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use super::{
    AsyncReadWrite, ChainHopFailure, MultiTargetTransport, NodeFailure, PacketOutbound,
    PacketRejection, PacketTransport, PreparedUdpTransport, ProtocolEntry, ProxyStream,
    SharedSourceOutbound, TcpOutbound, TunnelDialOptions, TunnelUnsupported, is_packet_rejection,
    target_failure,
};
use crate::runtime::flow_observation::without_target_milestones;
use crate::runtime::{NodeRuntime, RouteRuntime};

/// Dials a chain through the hop runtimes of its own generation, using the
/// same handler instances the registry dispatches to.
pub struct ChainHandler {
    handlers: Vec<ProtocolEntry>,
}

impl ChainHandler {
    pub fn new(handlers: Vec<ProtocolEntry>) -> Self {
        Self { handlers }
    }

    fn handler(&self, node: &Node) -> anyhow::Result<&ProtocolEntry> {
        self.handlers
            .iter()
            .find(|entry| entry.descriptor.protocol == node.protocol())
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", node.protocol()))
    }

    /// On failure, also returns the index of the hop that failed.
    async fn dial_hops<T, Fut>(
        &self,
        hops: &[Arc<NodeRuntime>],
        connect_timeout: Duration,
        deadline: Instant,
        reality_key_shares: bool,
        exit: &impl Fn(
            &ProtocolEntry,
            Arc<NodeRuntime>,
            Box<dyn AsyncReadWrite>,
            TunnelDialOptions,
        ) -> Fut,
    ) -> Result<T, (usize, anyhow::Error)>
    where
        Fut: Future<Output = anyhow::Result<T>>,
    {
        let budget = || connect_timeout.min(deadline.saturating_duration_since(Instant::now()));
        let at = |hop: usize| move |error| (hop, error);
        let (first, rest) = hops.split_first().expect("a chain has at least two hops");
        let (server, server_domain) = server_target(&rest[0].node);
        let handler = &self.handler(&first.node).map_err(at(0))?.tcp;
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
        .map_err(|error| earlier_hop_error(0, error))?
        .stream;
        for (index, hop) in rest.iter().enumerate() {
            let handler = self.handler(&hop.node).map_err(at(index + 1))?;
            let options = TunnelDialOptions {
                connect_timeout: budget(),
                reality_key_shares,
            };
            let Some(next) = rest.get(index + 1) else {
                return hop_scope(hop, exit(handler, Arc::clone(hop), carrier, options))
                    .await
                    .map_err(at(index + 1));
            };
            let (server, server_domain) = server_target(&next.node);
            carrier = hop_scope(
                hop,
                without_target_milestones(handler.tcp.dial_over(
                    Arc::clone(hop),
                    carrier,
                    server,
                    server_domain,
                    options,
                )),
            )
            .await
            .map_err(|error| earlier_hop_error(index + 1, error))?
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
/// a failure of the chain itself, and the failed hop is the next one: `hop`
/// completed its own handshake and reported that it could not reach that
/// server. Fronts that send no such reply (Shadowsocks, Trojan, VMess)
/// surface the same outage as the next hop's handshake failure. Packet
/// policy rejections keep their class and their hop.
fn earlier_hop_error(hop: usize, error: anyhow::Error) -> (usize, anyhow::Error) {
    if is_packet_rejection(&error) || !target_failure(&error) {
        return (hop, error);
    }
    (hop + 1, NodeFailure(anyhow::anyhow!("{error:#}")).into())
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
            connect_timeout,
            |exit, hop, carrier, options| {
                let tcp = Arc::clone(&exit.tcp);
                async move {
                    tcp.dial_over(hop, carrier, target, target_domain, options)
                        .await
                }
            },
        )
        .await
    }
}

impl ChainHandler {
    /// Dial a route through group exits over its generation's hop runtimes.
    pub async fn dial_route_tcp(
        &self,
        route: &RouteRuntime,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dial_chain(
            "group exit route",
            route.hops(),
            connect_timeout,
            |exit, hop, carrier, options| {
                let tcp = Arc::clone(&exit.tcp);
                async move {
                    tcp.dial_over(hop, carrier, target, target_domain, options)
                        .await
                }
            },
        )
        .await
    }

    /// One deadline covers the whole chain, the caller's per-candidate bound;
    /// each hop gets what remains of it, capped at `connect_timeout`. A REALITY
    /// mask certificate on a tunneled hop redials the chain once without
    /// hybrid key shares, as a direct REALITY dial retries once. The first hop
    /// dials directly and has already had that retry, so its failure stands.
    /// A failure names its hop through [`ChainHopFailure`]; the deadline
    /// belongs to no hop. `exit` runs the last hop's handshake over the
    /// carrier to its server.
    async fn dial_chain<T, Fut>(
        &self,
        label: &str,
        hops: &[Arc<NodeRuntime>],
        connect_timeout: Duration,
        exit: impl Fn(
            &ProtocolEntry,
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
        let dial = async {
            match self
                .dial_hops(hops, connect_timeout, deadline, true, &exit)
                .await
            {
                Err((hop, error)) if hop > 0 && reality_mask_certificate(&error) => {
                    self.dial_hops(hops, connect_timeout, deadline, false, &exit)
                        .await
                }
                result => result,
            }
            .map_err(|(hop, error)| {
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
        // Probes reach this without the registry's capability gate; a typed
        // refusal keeps a chain that cannot carry UDP out of their failures.
        if !runtime.udp_capable {
            return Err(PacketRejection::Policy.into());
        }
        self.dial_chain(
            &runtime.node.name,
            runtime.chain_hops(),
            connect_timeout,
            |exit, hop, carrier, options| {
                let packet = exit.packet.clone();
                async move {
                    let protocol = hop.node.protocol().as_str();
                    packet
                        .ok_or(TunnelUnsupported(protocol))?
                        .dial_udp_over(hop, carrier, target, target_domain, options)
                        .await
                }
            },
        )
        .await
    }
}

/// One association through the chain for a whole client source, over the
/// exit's tunneled shared slot. The exit's handshake runs on a carrier the
/// chain owns, so a speculative preparation has nothing to hold back until
/// commit.
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
        if !runtime.udp_capable {
            return Err(PacketRejection::Policy.into());
        }
        self.dial_chain(
            &runtime.node.name,
            runtime.chain_hops(),
            connect_timeout,
            |exit, hop, carrier, options| {
                let shared = exit.tunneled_shared.clone();
                async move {
                    let protocol = hop.node.protocol().as_str();
                    shared
                        .ok_or(TunnelUnsupported(protocol))?
                        .prepare_shared_source_over(hop, carrier, target, target_domain, options)
                        .await
                }
            },
        )
        .await
        .map(PreparedUdpTransport::ready)
    }
}

#[cfg(test)]
mod tests;
