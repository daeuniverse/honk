//! WireGuard outbound over a userspace tunnel: boringtun for the Noise transport and
//! `honk-netstack` for the inner TCP/UDP, driven by one owner task per tunnel.
//!
//! Layout: `registry` owns the one-tunnel-per-(keys, endpoint) rule and the memory share, `tunnel`
//! the shared state and owner task, `socket` the marked outer UDP socket with GRO/GSO batching,
//! `stream`/`udp` the flow adapters. This file is the handler: dial, warm and probe entry points.
//!
//! Deviations from the other protocols, all consequences of sharing:
//! - A tunnel is shared by every runtime of one control plane with an identical config, including
//!   DNS-fork runtimes and reload successors (which otherwise own fresh protocol state): two
//!   sessions with the same keys to the same peer would invalidate each other's handshakes. Two
//!   planes in one process never share a tunnel; node-only dials (no runtime) share a
//!   process-wide registry of their own.
//! - The owner task belongs to its plane's registry, not a node's task owner;
//!   `OutboundRuntimeRegistry::shutdown_wireguard_tunnels` joins it at teardown. It ends on
//!   failure, replacement by a different config for the same key pair and endpoint, when the last
//!   runtime using it closes with nothing left to serve, or after 120 s with no flow and no warm
//!   retention. A runtime closing fails only the flows it opened.
//! - The inner network is layer 3: targets are dialed by address and must fall inside the peer's
//!   allowed IPs; target domains are metadata and never resolved remotely.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use honk_config::node::Node;

use crate::proxy::{
    MultiTargetTransport, PacketOutbound, PacketTransport, PreparedUdpTransport, ProbeableOutbound,
    ProxyStream, SharedSourceOutbound, TcpOutbound, WarmRequirement, WarmableOutbound,
};
use crate::runtime::NodeRuntime;

mod registry;
mod socket;
mod stream;
#[cfg(test)]
mod tests;
mod tunnel;
mod udp;

pub use registry::init_memory_share;
pub(crate) use registry::{Registry as TunnelRegistry, TunnelConfig};
use stream::refusal;
pub use tunnel::RuntimeClosed;
pub(crate) use tunnel::{Gone, Tunnel, WarmHold};
pub(crate) use udp::WgUdpTransport;

/// Where a dial gets its tunnel: the process-wide standalone registry, a runtime's cached slot, or
/// its plane's registry on behalf of a runtime whose slot a speculative preparation must not
/// touch yet.
enum Source<'a> {
    Standalone(&'a Node),
    Installed(&'a Arc<NodeRuntime>),
    Detached(&'a Arc<NodeRuntime>),
}

impl Source<'_> {
    fn node(&self) -> &Node {
        match self {
            Source::Standalone(node) => node,
            Source::Installed(runtime) | Source::Detached(runtime) => &runtime.node,
        }
    }

    async fn tunnel(&self) -> anyhow::Result<(Tunnel, u64)> {
        match self {
            Source::Standalone(node) => Ok((
                TunnelRegistry::standalone()
                    .acquire(TunnelConfig::from_node(node)?)
                    .await?,
                0,
            )),
            Source::Installed(runtime) => {
                let wireguard = runtime.wireguard()?;
                Ok((wireguard.tunnel(&runtime.node).await?, wireguard.scope()))
            }
            Source::Detached(runtime) => {
                let wireguard = runtime.wireguard()?;
                let tunnel = wireguard
                    .registry()
                    .acquire(TunnelConfig::from_node(&runtime.node)?)
                    .await?;
                Ok((tunnel, wireguard.scope()))
            }
        }
    }
}

/// A cold probe's handshake budget.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A tunnel with a live session. One that retires between lookup and use is replaced once.
async fn ready_tunnel(source: &Source<'_>, deadline: Instant) -> anyhow::Result<(Tunnel, u64)> {
    for _ in 0..2 {
        let (tunnel, scope) = source.tunnel().await?;
        match tunnel
            .ready(deadline.saturating_duration_since(Instant::now()))
            .await
        {
            Ok(()) => return Ok((tunnel, scope)),
            Err(Gone::Idle) => {}
            Err(gone) => return Err(gone.into_error()),
        }
    }
    anyhow::bail!("WireGuard tunnel kept closing while connecting")
}

/// Refuses, before any handshake, a target this tunnel cannot carry. That is the node's wrong fit
/// for the target, which Score can act on, not a failure of the node.
fn reachable(config: &TunnelConfig, target: SocketAddr) -> anyhow::Result<()> {
    if !config.allows(target.ip()) {
        return Err(refusal(
            std::io::ErrorKind::HostUnreachable,
            "target is outside the WireGuard peer's allowed IPs",
        ));
    }
    if !config.has_local_for(target.ip()) {
        return Err(refusal(
            std::io::ErrorKind::HostUnreachable,
            "no WireGuard tunnel address in the target's family",
        ));
    }
    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct WireGuardHandler;

impl WireGuardHandler {
    pub fn new() -> Self {
        Self
    }

    async fn dial(
        &self,
        source: Source<'_>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        reachable(&TunnelConfig::from_node(source.node())?, target)?;
        let deadline = Instant::now() + connect_timeout;
        // A tunnel can retire between lookup and use; the second attempt gets a fresh one.
        for _ in 0..2 {
            let (tunnel, scope) = ready_tunnel(&source, deadline).await?;
            match tunnel.dial_tcp(scope, target, deadline).await {
                Ok(flow) => {
                    return Ok(ProxyStream {
                        stream: Box::new(flow?),
                        target_addr: target,
                        target_domain: target_domain.map(str::to_string),
                    });
                }
                Err(Gone::Idle) => continue,
                Err(gone) => return Err(gone.into_error()),
            }
        }
        anyhow::bail!("WireGuard tunnel kept closing while connecting")
    }

    /// Bind one inner UDP socket on a ready tunnel. Returns the tunnel too so a speculative
    /// preparation can publish it into its runtime on commit.
    async fn open_udp(
        &self,
        source: &Source<'_>,
        target: SocketAddr,
        connect_timeout: Duration,
    ) -> anyhow::Result<(Arc<WgUdpTransport>, Tunnel)> {
        reachable(&TunnelConfig::from_node(source.node())?, target)?;
        let deadline = Instant::now() + connect_timeout;
        for _ in 0..2 {
            let (tunnel, scope) = ready_tunnel(source, deadline).await?;
            match tunnel.bind_udp(scope, target) {
                Ok(transport) => return Ok((Arc::new(transport?), tunnel)),
                Err(Gone::Idle) => continue,
                Err(gone) => return Err(gone.into_error()),
            }
        }
        anyhow::bail!("WireGuard tunnel kept closing while binding UDP")
    }

    /// Prepare an association whose runtime slot is only touched by the commit.
    async fn prepare<T: ?Sized + Send + Sync + 'static>(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        connect_timeout: Duration,
        speculative: bool,
        upcast: fn(Arc<WgUdpTransport>) -> Arc<T>,
    ) -> anyhow::Result<PreparedUdpTransport<T>> {
        if !speculative {
            let (transport, _) = self
                .open_udp(&Source::Installed(&runtime), target, connect_timeout)
                .await?;
            return Ok(PreparedUdpTransport::ready(upcast(transport)));
        }
        let (transport, tunnel) = self
            .open_udp(&Source::Detached(&runtime), target, connect_timeout)
            .await?;
        Ok(PreparedUdpTransport::new(async move {
            runtime.wireguard()?.install(tunnel)?;
            Ok(upcast(transport))
        }))
    }
}

#[async_trait]
impl TcpOutbound for WireGuardHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dial(
            Source::Standalone(node),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dial(
            Source::Installed(&runtime),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    async fn dial_with_tcp(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _tcp: tokio::net::TcpStream,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!("WireGuard runs over UDP; a bare TCP connection cannot be reused")
    }
}

#[async_trait]
impl PacketOutbound for WireGuardHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let (transport, _) = self
            .open_udp(&Source::Standalone(node), target, connect_timeout)
            .await?;
        Ok(transport)
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        _target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let (transport, _) = self
            .open_udp(&Source::Installed(&runtime), target, connect_timeout)
            .await?;
        Ok(transport)
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        _target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        self.prepare(runtime, target, connect_timeout, true, |transport| {
            transport as Arc<dyn PacketTransport>
        })
        .await
    }
}

#[async_trait]
impl SharedSourceOutbound for WireGuardHandler {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        _target_domain: Option<&str>,
        connect_timeout: Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        self.prepare(runtime, target, connect_timeout, speculative, |transport| {
            transport as Arc<dyn MultiTargetTransport>
        })
        .await
    }
}

#[async_trait]
impl WarmableOutbound for WireGuardHandler {
    /// Completing the handshake is the whole warm-up, for both requirements.
    async fn warm(
        &self,
        runtime: Arc<NodeRuntime>,
        connect_timeout: Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        let source = Source::Installed(&runtime);
        let warm = ready_tunnel(&source, Instant::now() + connect_timeout);
        crate::runtime::flow_observation::without(async { warm.await.map(|_| ()) }).await
    }
}

#[async_trait]
impl ProbeableOutbound for WireGuardHandler {
    /// A real handshake with the peer; the endpoint answering TCP says nothing about a UDP tunnel.
    async fn test_connectivity(&self, node: &Node) -> bool {
        let source = Source::Standalone(node);
        match ready_tunnel(&source, Instant::now() + PROBE_TIMEOUT).await {
            Ok(_) => true,
            Err(error) => {
                tracing::debug!(
                    "WireGuard connectivity test failed for {}: {error}",
                    node.name
                );
                false
            }
        }
    }
}
