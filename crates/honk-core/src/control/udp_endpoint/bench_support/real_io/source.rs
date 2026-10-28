//! Source and real-backend constructors. A shared source is the production
//! `prepare_source` -> `new_source_scored` -> driver sequence (one carrier per
//! client, one endpoint and driver per destination); an ordinary backend flow
//! is the registry's `dial_udp_transport_runtime` -> `install_flow`. Both
//! drive the same production handler, so a pair differs only in the core path.

use super::IoHarness;
use crate::control::udp_endpoint::source::PreparedSourceTransport;
use crate::control::udp_endpoint::{SourcePath, SourcePreparation, SourceScope, UdpEndpoint};
use honk_config::node::{
    Node, OutboundConfig, ShadowsocksConfig, Socks5Config, TlsOptions, TrojanConfig,
};
use honk_outbound::alive::IpVersion;
use honk_outbound::proxy::{MultiTargetTransport, PreparedUdpTransport, ProxyRegistry};
use honk_outbound::runtime::{NodeRuntime, OutboundRuntimeRegistry};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const DIAL_TIMEOUT: Duration = Duration::from_secs(2);

/// Handler under test, configured against the bench's loopback peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Shadowsocks,
    Socks5,
    /// Plain-TCP Trojan (TLS disabled), UDP associate.
    Trojan,
    /// In-memory transport handed to `install_mock_source`; never dialed.
    Mock,
    #[cfg(feature = "rprx")]
    VlessXudp,
}

impl Backend {
    pub const SS_METHOD: &'static str = "aes-128-gcm";
    pub const PASSWORD: &'static str = "udp-io-bench";

    fn outbound(self) -> OutboundConfig {
        match self {
            Self::Shadowsocks => OutboundConfig::Shadowsocks(ShadowsocksConfig {
                password: Some(Self::PASSWORD.into()),
                encryption: Some(Self::SS_METHOD.into()),
                ..Default::default()
            }),
            Self::Socks5 | Self::Mock => OutboundConfig::Socks5(Socks5Config::default()),
            Self::Trojan => OutboundConfig::Trojan(TrojanConfig {
                password: Some(Self::PASSWORD.into()),
                tls: TlsOptions {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            }),
            #[cfg(feature = "rprx")]
            Self::VlessXudp => OutboundConfig::Vless(honk_config::node::VlessConfig {
                uuid: Some("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3".into()),
                udp_encoding: honk_config::node::VlessUdpEncoding::Xudp,
                ..Default::default()
            }),
        }
    }

    fn path(self) -> SourcePath {
        match self {
            #[cfg(feature = "rprx")]
            Self::VlessXudp => SourcePath::Vless(honk_config::node::VlessUdpPath::Xudp),
            _ => SourcePath::Shared,
        }
    }
}

pub(super) struct SourceRuntime {
    node: Node,
    generation: Arc<OutboundRuntimeRegistry>,
    runtime: Arc<NodeRuntime>,
    registry: ProxyRegistry,
}

impl SourceRuntime {
    fn new(backend: Backend, server: SocketAddr) -> io::Result<Self> {
        let mut node = Node {
            name: "udp-io-bench".into(),
            address: server.to_string(),
            host: server.ip().to_string(),
            port: server.port(),
            outbound: backend.outbound(),
            ..Default::default()
        };
        node.id = node.derive_id();
        let generation = Arc::new(
            OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
                std::slice::from_ref(&node),
                8,
                8,
                8,
                false,
                None,
            )
            .map_err(io::Error::other)?
            .0,
        );
        let runtime = generation
            .get(&node.id)
            .ok_or_else(|| io::Error::other("node runtime missing"))?;
        Ok(Self {
            node,
            generation,
            runtime,
            registry: ProxyRegistry::default_resolver().map_err(io::Error::other)?,
        })
    }
}

impl IoHarness {
    fn source_runtime(&mut self, backend: Backend, server: SocketAddr) -> io::Result<()> {
        if self.source.is_none() {
            self.source = Some(SourceRuntime::new(backend, server)?);
        }
        Ok(())
    }

    /// Ordinary per-flow endpoint over the real handler: one association per
    /// destination, dialed through the registry as the listener does.
    pub async fn install_backend_flow(
        &mut self,
        destination: usize,
        backend: Backend,
        server: SocketAddr,
    ) -> io::Result<()> {
        self.source_runtime(backend, server)?;
        let source = self.source.as_ref().expect("source runtime just created");
        let transport = source
            .registry
            .dial_udp_transport_runtime(
                Arc::clone(&source.generation),
                source.node.id,
                self.targets[destination],
                None,
                DIAL_TIMEOUT,
            )
            .await
            .map_err(io::Error::other)?;
        self.install_flow(destination, transport).await
    }

    /// Adds one destination to the client's source against the wire peer at
    /// `server`. The first call creates the carrier; later calls (same
    /// `server`) attach to it. The first datagram is echoed and drained
    /// before returning.
    pub async fn install_backend_source(
        &mut self,
        destination: usize,
        backend: Backend,
        server: SocketAddr,
    ) -> io::Result<()> {
        self.source_runtime(backend, server)?;
        let target = self.targets[destination];
        let source = self.source.as_ref().expect("source runtime just created");
        let preparation = self
            .pool
            .prepare_source(
                honk_datapath::ScopeId::HOST,
                &source.registry,
                Arc::clone(&source.generation),
                Arc::clone(&source.runtime),
                self.client_addr,
                backend.path(),
                None,
                target,
                None,
                DIAL_TIMEOUT,
                Arc::clone(&self.alive),
                Arc::clone(&self.stats),
                IpVersion::V4,
                false,
            )
            .await
            .map_err(io::Error::other)?;
        self.install_source(destination, preparation).await
    }

    /// Shared source over an injected in-memory transport. The first call
    /// publishes `transport` as the client's association; later calls attach
    /// to it (their `transport` is unused), like `source_shared_tests`.
    pub async fn install_mock_source(
        &mut self,
        destination: usize,
        transport: Arc<dyn MultiTargetTransport>,
    ) -> io::Result<()> {
        // The mock node is never dialed; any address names it.
        self.source_runtime(Backend::Mock, ([127, 0, 0, 1], 1).into())?;
        let target = self.targets[destination];
        let source = self.source.as_ref().expect("source runtime just created");
        let scope = SourceScope::new(
            honk_datapath::ScopeId::HOST,
            &source.runtime,
            self.client_addr,
            SourcePath::Shared,
            None,
        );
        let preparation = if self.pool.sources.contains_key(&scope) {
            self.pool
                .prepare_source(
                    honk_datapath::ScopeId::HOST,
                    &source.registry,
                    Arc::clone(&source.generation),
                    Arc::clone(&source.runtime),
                    self.client_addr,
                    SourcePath::Shared,
                    None,
                    target,
                    None,
                    DIAL_TIMEOUT,
                    Arc::clone(&self.alive),
                    Arc::clone(&self.stats),
                    IpVersion::V4,
                    false,
                )
                .await
                .map_err(io::Error::other)?
        } else {
            SourcePreparation::Fresh {
                scope,
                prepared: PreparedSourceTransport::Shared(PreparedUdpTransport::ready(transport)),
                source_permit: self
                    .pool
                    .source_slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(io::Error::other)?,
                runtime: Arc::clone(&source.runtime),
                alive_set: Arc::clone(&self.alive),
                stats: Arc::clone(&self.stats),
                node_id: source.node.id,
                node_name: source.node.name.clone(),
                health_family: IpVersion::V4,
            }
        };
        self.install_source(destination, preparation).await
    }

    async fn install_source(
        &self,
        destination: usize,
        preparation: SourcePreparation,
    ) -> io::Result<()> {
        let source = self.source.as_ref().expect("source runtime exists");
        let target = self.targets[destination];
        let lease = self.reserve(target, source.node.id)?;
        let attachment = preparation
            .commit(&self.pool)
            .await
            .map_err(io::Error::other)?;
        let reply = Arc::new(self.pool.create_reply_socket(lease.scope(), target)?);
        let endpoint = Arc::new(UdpEndpoint::new_source_scored(
            attachment,
            target,
            None,
            reply,
            self.stats
                .outbound_tracker("udp-io-bench", crate::stats::OutboundKind::Node),
            source.node.id,
            IpVersion::V4,
            None,
        ));
        let reply = Arc::clone(endpoint.source_reply_socket());
        self.start(lease, endpoint, target, reply).await
    }
}
