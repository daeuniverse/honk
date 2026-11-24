use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::anytls::AnyTlsHandler;
use super::block::BlockHandler;
use super::chain::ChainHandler;
use super::direct::DirectHandler;
use super::hysteria2::Hysteria2Handler;
use super::juicity::JuicityHandler;
use super::shadowsocks::ShadowsocksHandler;
use super::socks5::Socks5Handler;
use super::trojan::TrojanHandler;
use super::tuic::TuicHandler;
#[cfg(feature = "rprx")]
use super::vless::VLessHandler;
#[cfg(feature = "rprx")]
use super::vmess::VmessHandler;
use super::{
    DirectMark, MissingProtocolHandler, MultiTargetTransport, PacketOutbound, PacketRejection,
    PacketTransport, PreparedUdpTransport, ProbeableOutbound, ProxyStream, SharedSourceOutbound,
    TcpOutbound, WarmOutcome, WarmRequirement, WarmableOutbound,
};

macro_rules! rprx_handlers {
    ($emit:ident $(, $registry:ident)?) => {
        $emit! {
            $($registry;)?
            VLess, VLessHandler, [with_tunneled_tcp, with_packet, with_tunneled_packet, with_shared, with_warmable];
            VMess, VmessHandler, [with_tunneled_tcp, with_warmable];
        }
    };
}

/// One registered protocol: its descriptor plus the capability objects it
/// implements. A `None` slot means the implementation lacks that capability;
/// the descriptor decides whether a present slot applies to a particular node.
pub struct ProtocolEntry {
    pub descriptor: &'static crate::descriptor::ProtocolDescriptor,
    pub tcp: Arc<dyn TcpOutbound>,
    /// Handshakes with an intermediate hop on a supplied UDP carrier stream.
    pub(super) tunneled_tcp: Option<Arc<dyn TcpOutbound>>,
    pub packet: Option<Arc<dyn PacketOutbound>>,
    /// Frames packets on a stream already opened by the preceding hop.
    pub(super) tunneled_packet: Option<Arc<dyn PacketOutbound>>,
    pub warmable: Option<Arc<dyn WarmableOutbound>>,
    pub probeable: Option<Arc<dyn ProbeableOutbound>>,
    pub shared: Option<Arc<dyn SharedSourceOutbound>>,
    /// Shares one association per client source when this protocol is a
    /// chain's exit; only a handler implementing
    /// [`SharedSourceOutbound::prepare_shared_source_over`] registers it.
    pub tunneled_shared: Option<Arc<dyn SharedSourceOutbound>>,
}

impl ProtocolEntry {
    pub fn new<T: TcpOutbound + 'static>(protocol: NodeProtocol, handler: Arc<T>) -> Self {
        Self {
            descriptor: crate::descriptor::descriptor(protocol),
            tcp: handler,
            tunneled_tcp: None,
            packet: None,
            tunneled_packet: None,
            warmable: None,
            probeable: None,
            shared: None,
            tunneled_shared: None,
        }
    }

    pub fn with_packet<T: PacketOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.packet = Some(handler);
        self
    }

    pub(super) fn with_tunneled_tcp<T: TcpOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.tunneled_tcp = Some(handler);
        self
    }

    pub(super) fn with_tunneled_packet<T: PacketOutbound + 'static>(
        mut self,
        handler: Arc<T>,
    ) -> Self {
        self.tunneled_packet = Some(handler);
        self
    }

    pub fn with_warmable<T: WarmableOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.warmable = Some(handler);
        self
    }

    pub fn with_probeable<T: ProbeableOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.probeable = Some(handler);
        self
    }

    pub fn with_shared<T: SharedSourceOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.shared = Some(handler);
        self
    }

    pub fn with_tunneled_shared<T: SharedSourceOutbound + 'static>(
        mut self,
        handler: Arc<T>,
    ) -> Self {
        self.tunneled_shared = Some(handler);
        self
    }

    /// Every capability enabled by the descriptor's default node must have an
    /// implementation slot. Node-dependent descriptors may keep an extra slot;
    /// dispatch checks the concrete node before calling it.
    pub(super) fn validate_consistency(&self) {
        let protocol = self.descriptor.protocol;
        let default_node = Node {
            outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
            ..Default::default()
        };
        if crate::descriptor::carries_udp(crate::descriptor::UdpPath::Own(&default_node))
            && self.packet.is_none()
        {
            panic!(
                "protocol {} declares UDP without a packet handler",
                protocol.as_str()
            );
        }
        if (self.shared.is_some() || self.tunneled_shared.is_some()) && self.packet.is_none() {
            panic!(
                "protocol {} declares a shared source without a packet handler",
                protocol.as_str()
            );
        }
        if crate::descriptor::carries_udp(crate::descriptor::UdpPath::Tunneled {
            exit: &default_node,
        }) {
            assert!(
                self.tunneled_packet.is_some() && self.packet.is_some(),
                "protocol {} declares tunneled UDP without a packet handler",
                protocol.as_str(),
            );
        }
        if default_node.supports_tunneled_dial() {
            assert!(
                self.tunneled_tcp.is_some(),
                "protocol {} declares tunneled TCP without a handler",
                protocol.as_str(),
            );
        }
        if self.descriptor.generation_runtime != crate::runtime::GenerationRuntime::None
            && self.warmable.is_none()
        {
            panic!(
                "protocol {} declares a generation runtime without a warm handler",
                protocol.as_str()
            );
        }
    }
}

pub struct ProxyRegistry {
    pub(super) entries: Vec<ProtocolEntry>,
    /// The chain handler, also registered for `NodeProtocol::Chain`, for
    /// routes through group exits, which have no protocol entry of their own.
    chain: Option<Arc<ChainHandler>>,
}

/// What a runtime-pinned dial goes through: a node of the generation, or a
/// route over the generation's hop runtimes.
#[derive(Clone, Copy, Debug)]
pub enum DialRef<'a> {
    Node(uuid::Uuid),
    Route(&'a honk_config::route::Route),
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            chain: None,
        }
    }

    pub(crate) const fn builtin_protocol_available(protocol: NodeProtocol) -> bool {
        macro_rules! available {
            ($( $name:ident, $handler:ident, [$($slot:ident),*]; )*) => {
                match protocol {
                    $(NodeProtocol::$name)|* => cfg!(feature = "rprx"),
                    _ => true,
                }
            };
        }
        rprx_handlers!(available)
    }

    pub fn default_resolver() -> anyhow::Result<Self> {
        let mut registry = Self::new();

        let socks5 = Arc::new(Socks5Handler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Socks5, socks5.clone())
                .with_tunneled_tcp(socks5.clone())
                .with_packet(socks5.clone())
                .with_shared(socks5.clone())
                .with_probeable(socks5),
        );
        let direct = Arc::new(DirectHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Direct, direct.clone())
                .with_packet(direct.clone())
                .with_probeable(direct),
        );
        let block = Arc::new(BlockHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Block, block.clone())
                .with_packet(block.clone())
                .with_probeable(block),
        );
        let trojan = Arc::new(TrojanHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Trojan, trojan.clone())
                .with_tunneled_tcp(trojan.clone())
                .with_packet(trojan.clone())
                .with_tunneled_packet(trojan.clone())
                .with_shared(trojan.clone())
                .with_tunneled_shared(trojan.clone())
                .with_warmable(trojan.clone())
                .with_probeable(trojan),
        );
        let hysteria2 = Arc::new(Hysteria2Handler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Hysteria2, hysteria2.clone())
                .with_packet(hysteria2.clone())
                .with_warmable(hysteria2.clone())
                .with_probeable(hysteria2),
        );
        let shadowsocks = Arc::new(ShadowsocksHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::SS, shadowsocks.clone())
                .with_tunneled_tcp(shadowsocks.clone())
                .with_packet(shadowsocks.clone())
                .with_shared(shadowsocks.clone())
                .with_probeable(shadowsocks),
        );
        #[cfg(feature = "rprx")]
        {
            macro_rules! register {
                ($registry:ident; $( $name:ident, $handler:ident, [$($slot:ident),*]; )*) => {{
                    $(
                        let handler = Arc::new($handler::new());
                        $registry.register(
                            ProtocolEntry::new(NodeProtocol::$name, Arc::clone(&handler))
                                $(.$slot(Arc::clone(&handler)))*
                                .with_probeable(handler),
                        );
                    )*
                }};
            }
            rprx_handlers!(register, registry);
        }
        let anytls = Arc::new(AnyTlsHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::AnyTLS, anytls.clone())
                .with_packet(anytls.clone())
                .with_shared(anytls.clone())
                .with_warmable(anytls.clone())
                .with_probeable(anytls),
        );
        let tuic = Arc::new(TuicHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Tuic, tuic.clone())
                .with_packet(tuic.clone())
                .with_warmable(tuic.clone())
                .with_probeable(tuic),
        );
        let juicity = Arc::new(JuicityHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Juicity, juicity.clone())
                .with_packet(juicity.clone())
                .with_shared(juicity.clone())
                .with_warmable(juicity.clone())
                .with_probeable(juicity),
        );
        registry.register_chain();
        for entry in &registry.entries {
            entry.validate_consistency();
        }
        Ok(registry)
    }

    pub fn register(&mut self, entry: ProtocolEntry) {
        self.entries.push(entry);
    }

    pub(super) fn register_chain(&mut self) {
        let chain = Arc::new(ChainHandler::new(&self.entries));
        self.register(
            ProtocolEntry::new(NodeProtocol::Chain, Arc::clone(&chain))
                .with_packet(Arc::clone(&chain))
                .with_shared(Arc::clone(&chain)),
        );
        self.chain = Some(chain);
    }

    pub fn find(&self, protocol: NodeProtocol) -> Option<&ProtocolEntry> {
        self.entries
            .iter()
            .find(|entry| entry.descriptor.protocol == protocol)
    }

    /// Preflight the leaf against the installed handlers and return its
    /// packet handler and the node that owns destination-port policy.
    pub fn udp_probe_target<'a>(
        &self,
        generation: &'a crate::runtime::OutboundRuntimeRegistry,
        node: &'a Node,
    ) -> anyhow::Result<(&dyn PacketOutbound, &'a Node)> {
        let protocol = node.protocol();
        let packet = self
            .find(protocol)
            .and_then(|entry| entry.packet.as_deref())
            .ok_or(MissingProtocolHandler(protocol))?;
        if protocol == NodeProtocol::Chain {
            let runtime = generation.admitted_chain_runtime_ref(node)?;
            let terminal = self
                .chain
                .as_ref()
                .ok_or(MissingProtocolHandler(protocol))?
                .udp_terminal(runtime.chain_hops(), runtime.udp_capable)?;
            return Ok((packet, terminal));
        }
        if !generation.udp_capable(node) {
            return Err(PacketRejection::Policy.into());
        }
        Ok((packet, node))
    }

    /// Resolve the actual framing node and its required handlers before resolving a probe target.
    pub fn udp_framing_node<'a>(
        &self,
        generation: &'a crate::runtime::OutboundRuntimeRegistry,
        target: DialRef<'_>,
    ) -> anyhow::Result<&'a Node> {
        match target {
            DialRef::Node(id) => {
                let runtime = generation.get_ref(&id).ok_or(PacketRejection::Cancelled)?;
                self.udp_probe_target(generation, &runtime.node)
                    .map(|(_, terminal)| terminal)
            }
            DialRef::Route(route) => {
                let runtime = generation
                    .route_runtime(route)
                    .ok_or(PacketRejection::Cancelled)?;
                let terminal = self
                    .chain
                    .as_ref()
                    .ok_or(MissingProtocolHandler(NodeProtocol::Chain))?
                    .udp_terminal(runtime.hops(), runtime.udp_capable())?;
                Ok(&generation
                    .get_ref(&terminal.id)
                    .ok_or(PacketRejection::Cancelled)?
                    .node)
            }
        }
    }

    pub async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let protocol = node.protocol();
        let entry = self
            .find(protocol)
            .ok_or(MissingProtocolHandler(protocol))?;

        tracing::debug!(
            "Dialing {}:{} via {} ({})",
            target,
            protocol.as_str(),
            node.name,
            node.host()
        );

        entry
            .tcp
            .dial(node, target, target_domain, connect_timeout)
            .await
    }

    /// Dial through a generation-pinned node runtime, refusing a stream from a
    /// generation retired during the dial.
    pub async fn dial_runtime(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dial_generation(generation, node_id, |runtime, entry| {
            let tcp = Arc::clone(&entry.tcp);
            Ok(async move {
                tcp.dial_runtime(runtime, target, target_domain, connect_timeout)
                    .await
            })
        })
        .await
    }

    /// Dial a node or a route through the captured generation.
    pub async fn dial_ref(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        dial: DialRef<'_>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        match dial {
            DialRef::Node(node_id) => {
                self.dial_runtime(generation, node_id, target, target_domain, connect_timeout)
                    .await
            }
            DialRef::Route(route) => {
                self.dial_route(generation, route, target, target_domain, connect_timeout)
                    .await
            }
        }
    }

    /// After a fresh successful dial, whether its actual handler confirmed the target at open.
    pub fn confirms_target_on_open(
        &self,
        generation: &crate::runtime::OutboundRuntimeRegistry,
        target: DialRef<'_>,
    ) -> bool {
        if generation.is_shutdown() {
            return false;
        }
        match target {
            DialRef::Node(id) => generation
                .get_ref(&id)
                .and_then(|runtime| self.find(runtime.node.protocol()))
                .is_some_and(|entry| entry.tcp.confirms_target_on_open()),
            DialRef::Route(route) => {
                let Some(chain) = &self.chain else {
                    return false;
                };
                let mut handlers = route
                    .hops()
                    .iter()
                    .map(|id| chain.handler(generation.get_ref(id)?.node.protocol()));
                handlers
                    .next_back()
                    .flatten()
                    .is_some_and(|handler| handler.confirms_target_on_open())
                    && handlers.all(|handler| handler.is_some())
            }
        }
    }

    /// Dial a route over the captured generation's hop runtimes. The dial's
    /// tasks have no owner of their own; each hop scopes its own to its
    /// runtime, as for a configured chain.
    async fn dial_route(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        route: &honk_config::route::Route,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let chain = self
            .chain
            .as_ref()
            .ok_or(MissingProtocolHandler(NodeProtocol::Chain))?;
        let runtime = generation
            .route_runtime(route)
            .ok_or_else(|| anyhow::anyhow!("route is not in runtime generation"))?;
        // The two task scopes borrow one dial; nesting its state by value grows every dial_ref.
        let dial =
            std::pin::pin!(chain.dial_route_tcp(&runtime, target, target_domain, connect_timeout));
        let result = generation
            .scope_dials(crate::runtime::scope_unowned(dial))
            .await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during dial");
        }
        Ok(result)
    }

    /// Dial a direct flow with a nonzero mark in the captured generation.
    pub async fn dial_runtime_marked(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        mark: DirectMark,
    ) -> anyhow::Result<ProxyStream> {
        self.dial_generation(generation, node_id, |runtime, entry| {
            let tcp = Arc::clone(&entry.tcp);
            Ok(async move {
                tcp.dial_runtime_marked(runtime, target, target_domain, connect_timeout, mark)
                    .await
            })
        })
        .await
    }

    /// Shared admission for every runtime-pinned dial: `dial` validates the
    /// handler before the dial scope opens, and a generation retired while
    /// dialing never publishes its result.
    async fn dial_generation<T, Fut>(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        dial: impl FnOnce(Arc<crate::runtime::NodeRuntime>, &ProtocolEntry) -> anyhow::Result<Fut>,
    ) -> anyhow::Result<T>
    where
        Fut: Future<Output = anyhow::Result<T>>,
    {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let protocol = runtime.node.protocol();
        let entry = self
            .find(protocol)
            .ok_or(MissingProtocolHandler(protocol))?;
        let quality = runtime.transport_quality();
        let dial = dial(Arc::clone(&runtime), entry)?;
        let result = generation
            .scope_dials(runtime.scope_tasks(quality.scope(dial)))
            .await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during dial");
        }
        Ok(result)
    }

    async fn warm_retained(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        connect_timeout: Duration,
        reason: crate::runtime::WarmRetention,
    ) -> anyhow::Result<WarmOutcome> {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let protocol = runtime.node.protocol();
        let entry = self
            .find(protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;
        let Some(warmable) = entry.warmable.as_ref() else {
            return Ok(WarmOutcome::NotApplicable);
        };
        let requirement = match reason {
            crate::runtime::WarmRetention::Selector => WarmRequirement::Session,
            crate::runtime::WarmRetention::Udp => WarmRequirement::Udp,
        };
        if !entry.descriptor.supports_warm(&runtime.node, requirement) {
            return Ok(WarmOutcome::NotApplicable);
        }
        let attempt = runtime.retain_warm(reason).await;
        if let Err(error) = generation
            .scope_dials(runtime.scope_tasks(warmable.warm(
                Arc::clone(&runtime),
                connect_timeout,
                requirement,
            )))
            .await
        {
            attempt.rollback().await;
            return Err(error);
        }
        if generation.is_shutdown() {
            attempt.rollback().await;
            anyhow::bail!("outbound runtime generation shut down during warm-up");
        }
        attempt.commit();
        Ok(WarmOutcome::Ready)
    }

    /// Warm a selected node's reusable session in the captured generation.
    pub async fn warm_session(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        connect_timeout: Duration,
    ) -> anyhow::Result<WarmOutcome> {
        self.warm_retained(
            generation,
            node_id,
            connect_timeout,
            crate::runtime::WarmRetention::Selector,
        )
        .await
    }

    /// Warm a UDP-capable node in the explicitly supplied runtime generation.
    pub async fn warm_udp(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        connect_timeout: Duration,
    ) -> anyhow::Result<WarmOutcome> {
        self.warm_retained(
            generation,
            node_id,
            connect_timeout,
            crate::runtime::WarmRetention::Udp,
        )
        .await
    }

    /// Framed UDP transport for a flow, dispatching to the node's packet
    /// capability (see [`PacketOutbound::dial_udp_transport`]).
    pub async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let protocol = node.protocol();
        let entry = self
            .find(protocol)
            .ok_or(MissingProtocolHandler(protocol))?;
        if protocol != NodeProtocol::Block
            && !crate::descriptor::udp_target_allowed(node, target.port())
        {
            return Err(PacketRejection::Policy.into());
        }
        if protocol != NodeProtocol::Block
            && !crate::descriptor::carries_udp(crate::descriptor::UdpPath::Own(node))
        {
            anyhow::bail!("UDP not supported for protocol {}", protocol.as_str());
        }
        let packet = entry.packet.as_ref().ok_or_else(|| {
            anyhow::anyhow!("UDP not supported for protocol {}", protocol.as_str())
        })?;
        packet
            .dial_udp_transport(node, target, target_domain, connect_timeout)
            .await
    }

    /// Generation-pinned UDP over a route through group exits: its exit
    /// tunnels UDP over the stream the earlier hops open. The exit answers
    /// the destination-port policy, as the node that frames the UDP. A route
    /// never shares a source: its runtime is not a node of the generation.
    pub async fn dial_udp_route(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        route: &honk_config::route::Route,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let chain = self
            .chain
            .as_ref()
            .ok_or(MissingProtocolHandler(NodeProtocol::Chain))?;
        let runtime = generation
            .route_runtime(route)
            .ok_or_else(|| anyhow::anyhow!("route is not in runtime generation"))?;
        let dial =
            std::pin::pin!(chain.dial_route_udp(&runtime, target, target_domain, connect_timeout));
        let result = generation
            .scope_dials(crate::runtime::scope_unowned(dial))
            .await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during dial");
        }
        Ok(result)
    }

    /// Generation-pinned framed UDP transport for an authoritative flow.
    pub async fn dial_udp_transport_runtime(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_generation(generation, node_id, |runtime, entry| {
            let packet = Arc::clone(Self::packet_for_runtime(&runtime, entry, target.port())?);
            Ok(async move {
                packet
                    .dial_udp_transport_runtime(runtime, target, target_domain, connect_timeout)
                    .await
            })
        })
        .await
    }

    /// Generation-pinned direct UDP flow with a nonzero rule mark.
    pub async fn dial_udp_transport_runtime_marked(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        mark: DirectMark,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_generation(generation, node_id, |runtime, entry| {
            let packet = Arc::clone(Self::packet_for_runtime(&runtime, entry, target.port())?);
            Ok(async move {
                packet
                    .dial_udp_transport_runtime_marked(
                        runtime,
                        target,
                        target_domain,
                        connect_timeout,
                        mark,
                    )
                    .await
            })
        })
        .await
    }

    /// Speculatively prepare a framed UDP transport for a Cold URLTest
    /// candidate. Ordinary dial behavior remains available through
    /// [`Self::dial_udp_transport`] for authoritative paths.
    pub async fn dial_udp_transport_speculative(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let (runtime, packet) = self.packet_runtime(&generation, node_id, target.port())?;
        let prepared = generation
            .scope_dials(runtime.scope_tasks(runtime.transport_quality().scope(
                packet.dial_udp_transport_speculative_runtime(
                    Arc::clone(&runtime),
                    target,
                    target_domain,
                    connect_timeout,
                ),
            )))
            .await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during UDP preparation");
        }
        Ok(prepared)
    }

    /// Whether `protocol`'s registered entry serves the core `Shared` source
    /// transport, so one association carries every destination of a source.
    pub fn has_shared_source(&self, protocol: NodeProtocol) -> bool {
        self.find(protocol)
            .is_some_and(|entry| entry.shared.is_some())
    }

    /// [`Self::has_shared_source`] for a captured runtime. A chain shares
    /// one association only through an exit registered as a tunneled shared
    /// source; a chain without hops in its generation shares nothing.
    pub fn has_shared_source_for(&self, runtime: &crate::runtime::NodeRuntime) -> bool {
        let protocol = runtime.node.protocol();
        if protocol != NodeProtocol::Chain {
            return self.has_shared_source(protocol);
        }
        runtime.udp_capable
            && runtime.chain_hops().last().is_some_and(|exit| {
                self.find(exit.node.protocol())
                    .is_some_and(|entry| entry.tunneled_shared.is_some())
            })
    }

    /// Shared-source association for a captured runtime. The caller owns the
    /// generation dial scope (see `dial_udp_transport_speculative`); this
    /// applies the packet capability and policy checks of ordinary UDP dials.
    pub async fn prepare_shared_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        let protocol = runtime.node.protocol();
        let entry = self
            .find(protocol)
            .ok_or(MissingProtocolHandler(protocol))?;
        Self::packet_for_runtime(&runtime, entry, target.port())?;
        let shared = entry.shared.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "shared UDP source not supported for protocol {}",
                protocol.as_str()
            )
        })?;
        shared
            .prepare_shared_source(runtime, target, target_domain, connect_timeout, speculative)
            .await
    }

    fn packet_runtime(
        &self,
        generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target_port: u16,
    ) -> anyhow::Result<(Arc<crate::runtime::NodeRuntime>, &Arc<dyn PacketOutbound>)> {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let protocol = runtime.node.protocol();
        let entry = self
            .find(protocol)
            .ok_or(MissingProtocolHandler(protocol))?;
        let packet = Self::packet_for_runtime(&runtime, entry, target_port)?;
        Ok((runtime, packet))
    }

    fn packet_for_runtime<'a>(
        runtime: &crate::runtime::NodeRuntime,
        entry: &'a ProtocolEntry,
        target_port: u16,
    ) -> anyhow::Result<&'a Arc<dyn PacketOutbound>> {
        let protocol = runtime.node.protocol();
        if protocol != NodeProtocol::Block
            && !crate::descriptor::udp_target_allowed(&runtime.node, target_port)
        {
            return Err(PacketRejection::Policy.into());
        }
        if protocol != NodeProtocol::Block && !runtime.udp_capable {
            if protocol == NodeProtocol::Chain {
                return Err(PacketRejection::Policy.into());
            }
            anyhow::bail!("UDP not supported for protocol {}", protocol.as_str());
        }
        entry
            .packet
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("UDP not supported for protocol {}", protocol.as_str()))
    }

    pub fn handler_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for ProxyRegistry {
    fn default() -> Self {
        Self::new()
    }
}
