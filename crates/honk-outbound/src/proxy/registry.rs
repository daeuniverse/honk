use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::anytls::AnyTlsHandler;
use super::block::BlockHandler;
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
    DirectMark, PacketOutbound, PacketRejection, PacketTransport, PreparedUdpTransport,
    ProbeableOutbound, ProxyStream, TcpOutbound, WarmOutcome, WarmRequirement, WarmableOutbound,
};

/// One registered protocol: its descriptor plus the capability objects it
/// implements. A `None` slot means the implementation lacks that capability;
/// the descriptor decides whether a present slot applies to a particular node.
pub struct ProtocolEntry {
    pub descriptor: &'static crate::descriptor::ProtocolDescriptor,
    pub tcp: Arc<dyn TcpOutbound>,
    pub packet: Option<Arc<dyn PacketOutbound>>,
    pub warmable: Option<Arc<dyn WarmableOutbound>>,
    pub probeable: Option<Arc<dyn ProbeableOutbound>>,
}

impl ProtocolEntry {
    pub fn new<T: TcpOutbound + 'static>(protocol: NodeProtocol, handler: Arc<T>) -> Self {
        Self {
            descriptor: crate::descriptor::descriptor(protocol),
            tcp: handler,
            packet: None,
            warmable: None,
            probeable: None,
        }
    }

    pub fn with_packet<T: PacketOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.packet = Some(handler);
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

    /// Every capability enabled by the descriptor's default node must have an
    /// implementation slot. Node-dependent descriptors may keep an extra slot;
    /// dispatch checks the concrete node before calling it.
    pub(super) fn validate_consistency(&self) {
        let protocol = self.descriptor.protocol;
        let default_node = Node {
            outbound: honk_config::node::OutboundConfig::from_protocol(protocol),
            ..Default::default()
        };
        if (self.descriptor.supports_udp)(&default_node) && self.packet.is_none() {
            panic!(
                "protocol {} declares UDP without a packet handler",
                protocol.as_str()
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
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn default_resolver() -> anyhow::Result<Self> {
        let mut registry = Self::new();

        let socks5 = Arc::new(Socks5Handler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Socks5, socks5.clone())
                .with_packet(socks5.clone())
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
                .with_packet(trojan.clone())
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
                .with_packet(shadowsocks.clone())
                .with_probeable(shadowsocks),
        );
        #[cfg(feature = "rprx")]
        {
            let vless = Arc::new(VLessHandler::new());
            registry.register(
                ProtocolEntry::new(NodeProtocol::VLess, vless.clone())
                    .with_packet(vless.clone())
                    .with_warmable(vless.clone())
                    .with_probeable(vless),
            );
            let vmess = Arc::new(VmessHandler::new());
            registry.register(
                ProtocolEntry::new(NodeProtocol::VMess, vmess.clone()).with_probeable(vmess),
            );
        }
        let anytls = Arc::new(AnyTlsHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::AnyTLS, anytls.clone())
                .with_packet(anytls.clone())
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
                .with_warmable(juicity.clone())
                .with_probeable(juicity),
        );
        for entry in &registry.entries {
            entry.validate_consistency();
        }
        Ok(registry)
    }

    pub fn register(&mut self, entry: ProtocolEntry) {
        self.entries.push(entry);
    }

    pub fn find(&self, protocol: NodeProtocol) -> Option<&ProtocolEntry> {
        self.entries
            .iter()
            .find(|entry| entry.descriptor.protocol == protocol)
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
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;

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
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;
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
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;
        if protocol != NodeProtocol::Block
            && !crate::descriptor::udp_target_allowed(node, target.port())
        {
            return Err(PacketRejection::Policy.into());
        }
        if protocol != NodeProtocol::Block && !(entry.descriptor.supports_udp)(node) {
            anyhow::bail!("UDP not supported for protocol {}", protocol.as_str());
        }
        let packet = entry.packet.as_ref().ok_or_else(|| {
            anyhow::anyhow!("UDP not supported for protocol {}", protocol.as_str())
        })?;
        packet
            .dial_udp_transport(node, target, target_domain, connect_timeout)
            .await
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
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;
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
