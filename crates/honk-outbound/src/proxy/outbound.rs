use async_trait::async_trait;
use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::{
    AsyncReadWrite, DirectMark, MultiTargetTransport, PacketTransport, PreparedUdpTransport,
    ProxyStream, TunnelUnsupported,
};

/// Result of requesting reusable protocol state. `Ready` means the state is
/// usable after the call; `NotApplicable` means the protocol owns no
/// generation-scoped session or client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmOutcome {
    Ready,
    NotApplicable,
}

/// Settings for a hop dialed over a stream tunneled through earlier hops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelDialOptions {
    /// Base of the REALITY handshake budget (three times this value). Other
    /// handshakes are bounded by the caller's deadline for the whole chain.
    pub connect_timeout: Duration,
    /// Offer hybrid post-quantum key shares in a REALITY ClientHello. A
    /// caller redials with `false` after a REALITY mask certificate.
    pub reality_key_shares: bool,
}

impl TunnelDialOptions {
    pub fn new(connect_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            reality_key_shares: true,
        }
    }
}

/// TCP flow dialing. Every protocol implements this.
#[async_trait]
pub trait TcpOutbound: Send + Sync {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream>;

    /// Whether a successful TCP open always includes a proxy reply confirming the target.
    fn confirms_target_on_open(&self) -> bool {
        false
    }

    /// The provided `tcp` stream is already connected to the proxy
    /// server. Handlers that support connection pooling override this to
    /// skip `TcpStream::connect()`; the default ignores `tcp` and delegates
    /// to [`Self::dial`].
    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: tokio::net::TcpStream,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let _ = tcp;
        self.dial(node, target, target_domain, connect_timeout)
            .await
    }

    /// Dial through an explicitly captured runtime generation. Stateless
    /// handlers delegate to [`Self::dial`]; session-owning handlers override
    /// this to avoid consulting the mutable current-generation registry.
    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dial(
            runtime.node.as_ref(),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    /// Dial a routed direct flow with a nonzero mark. Outbounds that do not
    /// own the flow's socket cannot apply it and refuse the dial.
    async fn dial_runtime_marked(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
        mark: DirectMark,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!("outbound cannot carry direct mark {:#x}", mark.get())
    }

    /// Run this node's handshake over `carrier`, a stream already connected
    /// to its server through earlier hops. The carrier's physical connection
    /// owns dial admission and transport observation (`TransportAttached`,
    /// `TransportReady`). This hop still emits its target milestones as a
    /// direct dial does: `TargetRequestSent` once the carriers below have
    /// delivered the request, and `TargetConfirmed` once a protocol reply
    /// confirms the target. Relay tasks of earlier hops (WS bridge, VMess)
    /// and a gRPC connection driver defer delivery to their physical write;
    /// a first hop that hands writes to its own session writer (AnyTLS,
    /// VLESS mux, XHTTP) may report delivery once that writer accepts them.
    /// A caller chaining several hops suppresses them on every hop but the
    /// last.
    /// Protocols that cannot run over a tunneled stream keep the default, a
    /// [`TunnelUnsupported`] error.
    async fn dial_over(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        _carrier: Box<dyn AsyncReadWrite>,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _options: TunnelDialOptions,
    ) -> anyhow::Result<ProxyStream> {
        Err(TunnelUnsupported(runtime.node.protocol().as_str()).into())
    }
}

/// Framed UDP transports — only protocols with UDP capability (see
/// [`crate::descriptor::ProtocolDescriptor::supports_udp`]).
#[async_trait]
pub trait PacketOutbound: Send + Sync {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>>;

    /// Open a framed UDP transport using an explicitly captured runtime
    /// generation. Session-owning handlers override this so an authoritative
    /// flow reuses the same warmed generation-local client.
    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_udp_transport(
            runtime.node.as_ref(),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    /// UDP counterpart of [`TcpOutbound::dial_runtime_marked`].
    async fn dial_udp_transport_runtime_marked(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
        mark: DirectMark,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        anyhow::bail!("outbound cannot carry direct mark {:#x}", mark.get())
    }

    /// Generation-pinned speculative preparation. The default wraps the
    /// authoritative runtime transport; session handlers override this when
    /// loser cancellation must avoid publishing reusable state.
    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        self.dial_udp_transport_runtime(runtime, target, target_domain, connect_timeout)
            .await
            .map(PreparedUdpTransport::ready)
    }

    /// UDP counterpart of [`TcpOutbound::dial_over`]. The returned transport
    /// owns the supplied carrier. Exits without tunneled UDP return
    /// [`TunnelUnsupported`].
    async fn dial_udp_over(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        _carrier: Box<dyn AsyncReadWrite>,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _options: TunnelDialOptions,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Err(TunnelUnsupported(runtime.node.protocol().as_str()).into())
    }
}

/// One association carrying every destination of a client source (the core
/// `Shared` source transport). Registered only by protocols whose
/// [`PacketOutbound`] slot also exists; `speculative` preparations must not
/// publish carrier state until committed.
#[async_trait]
pub trait SharedSourceOutbound: Send + Sync {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>>;

    /// Shared-source counterpart of [`PacketOutbound::dial_udp_over`].
    async fn prepare_shared_source_over(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        _carrier: Box<dyn AsyncReadWrite>,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _options: TunnelDialOptions,
    ) -> anyhow::Result<Arc<dyn MultiTargetTransport>> {
        Err(TunnelUnsupported(runtime.node.protocol().as_str()).into())
    }
}

/// Which property a warm request must establish. Selector ownership needs
/// the shared session; UDP top-N ownership additionally validates that the
/// server admitted UDP on protocols where that is negotiated separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmRequirement {
    Session,
    Udp,
}

#[async_trait]
pub trait WarmableOutbound: Send + Sync {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: Duration,
        requirement: WarmRequirement,
    ) -> anyhow::Result<()>;
}

/// Raw server reachability checks.
#[async_trait]
pub trait ProbeableOutbound: Send + Sync {
    async fn test_connectivity(&self, node: &Node) -> bool {
        let addr = format!("{}:{}", node.host(), node.port);
        match crate::util::connect_outbound(&addr, std::time::Duration::from_secs(3)).await {
            Ok(_stream) => true,
            Err(e) => {
                tracing::debug!(
                    "{} connectivity test failed for {}: {}",
                    node.protocol().as_str(),
                    node.name,
                    e
                );
                false
            }
        }
    }
}
