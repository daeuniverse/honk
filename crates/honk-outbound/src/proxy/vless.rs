//! VLESS proxy handler.
//!
//! The base VLESS request is unencrypted. `node.encryption` optionally adds
//! Xray VLESS Encryption inside the selected transport; otherwise deployments
//! normally use TLS or REALITY, although cleartext is explicitly configurable.
//! The handshake is one request header followed by a two-byte response prefix
//! and optional addons.
//!
//! Protocol flow:
//! 1. Connect to the server via the shared transport layer
//!    (`super::transport`): TCP, optionally TLS-wrapped (`node.tls`),
//!    optionally carried over WebSocket (`node.transport = "ws"`) or
//!    gRPC (`"grpc"`).
//! 2. When configured, complete the VLESS Encryption key exchange, then send the VLESS request header:
//!    ```text
//!    ver(1) | uuid(16) | addon_len(1) | [addon(addon_len)] | cmd(1) | port(2) | atyp(1) | addr(var)
//!    ```
//!    - `ver`: 0x00
//!    - `uuid`: 16 raw bytes parsed from `node.password` (UUID string)
//!    - `addon_len` / `addon`: Xray `encoding.Addons` protobuf carrying
//!      the flow (`node.flow`, e.g. `xtls-rprx-vision`); empty otherwise
//!    - `cmd`: 0x01 TCP or 0x02 UDP
//!    - `port`: big-endian u16
//!    - `atyp`: 0x01 IPv4, 0x02 Domain, 0x03 IPv6
//!    - `addr`: 4 bytes (IPv4) / 1+len bytes (Domain) / 16 bytes (IPv6)
//! 3. The response prefix (`ver(1) | addon_len(1) | [addon]`) is stripped
//!    lazily on the first read. Real servers emit it with the target's first
//!    downstream bytes; awaiting it during dial deadlocks when target output
//!    depends on client bytes, including the target TLS handshake.
//! 4. The stream is then transparently connected to the target (with XTLS
//!    Vision unpadding on the read path when `flow = xtls-rprx-vision`).
//!
//! Reference: <https://xtls.github.io/en/development/protocols/vless.html>

mod carrier;
mod packet;
mod stream;

#[cfg(test)]
use super::RuntimeOwnedIo;
use packet::VlessConnectedTransport;

pub use super::vless_cool::{VlessXudpTransport, is_vless_source_post_admission_cancel};
#[cfg(test)]
use super::{
    PacketRejection, ProxyRegistry, WarmOutcome, is_packet_rejection, uot, vless_cool, vless_mux,
};
#[cfg(test)]
use stream::{DirectRead, VISION_COMMAND_DIRECT, VISION_COMMAND_END};
use stream::{ResponseHeaderStrip, VisionStream};

use async_trait::async_trait;
use honk_config::node::{Node, VlessTcpPath, VlessUdpPath};
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{
    AsyncReadWrite, MuxSession, PacketOutbound, PacketTransport, PreparedUdpTransport,
    ProbeableOutbound, ProxyStream, TcpOutbound, WarmRequirement, WarmableOutbound,
};
use crate::session::{OpenError, SpeculativeCheckout};

const VLESS_VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
// Xray bounds command-UDP frames to 8192 bytes including the u16 length.
const MAX_NATIVE_PACKET_SIZE: usize = 8190;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

#[derive(Debug, Default)]
pub struct VLessHandler {
    // Short-lived source-carrier handlers stay allocation-free when unencrypted;
    // encryption ticket reuse exists only while a registry handler retains this cache.
    encryption_configs:
        OnceLock<RwLock<lru::LruCache<uuid::Uuid, Arc<super::vless_encryption::ClientConfig>>>>,
}

impl VLessHandler {
    pub fn new() -> Self {
        Self::default()
    }

    fn encryption_config(
        &self,
        node: &Node,
    ) -> anyhow::Result<Option<Arc<super::vless_encryption::ClientConfig>>> {
        let vless = node.vless().unwrap();
        let Some(value) = vless
            .encryption
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty() && *value != "none")
        else {
            return Ok(None);
        };
        let cache_key = if node.id.is_nil() {
            node.derive_id()
        } else {
            node.id
        };
        let configs = self.encryption_configs.get_or_init(|| {
            RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1024).expect("non-zero VLESS config cache capacity"),
            ))
        });
        if let Some(config) = configs.read().peek(&cache_key).cloned() {
            return Ok(Some(config));
        }
        let parsed = super::vless_encryption::ClientConfig::parse(value)?;
        let mut configs = configs.write();
        if let Some(config) = configs.peek(&cache_key).cloned() {
            return Ok(Some(config));
        }
        configs.put(cache_key, parsed.clone());
        Ok(Some(parsed))
    }

    fn parse_uuid(uuid_str: &str) -> anyhow::Result<[u8; 16]> {
        let uuid = uuid::Uuid::parse_str(uuid_str)?;
        Ok(*uuid.as_bytes())
    }

    fn build_request_header(
        uuid_bytes: &[u8; 16],
        command: u8,
        target: Option<SocketAddr>,
        target_domain: Option<&str>,
        flow: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let flow = match flow.filter(|flow| !flow.is_empty()) {
            None => None,
            Some("xtls-rprx-vision") => Some("xtls-rprx-vision"),
            Some(_) => anyhow::bail!("VLESS: unsupported flow"),
        };
        anyhow::ensure!(
            matches!(
                (command, target),
                (CMD_TCP, Some(_))
                    | (CMD_UDP, Some(_))
                    | (super::vless_cool::VLESS_MUX_COMMAND, None)
            ),
            "VLESS: invalid command target"
        );
        anyhow::ensure!(
            target.is_some() || target_domain.is_none(),
            "VLESS: command-Mux carries no target"
        );
        let addon_len = flow.map_or(0, |flow| 2 + flow.len());
        let encoded_address_len = match (target, target_domain) {
            (None, _) => 0,
            (Some(_), Some(domain)) => {
                anyhow::ensure!(
                    domain.len() <= u8::MAX as usize,
                    "VLESS: target domain exceeds 255 bytes"
                );
                1 + 1 + domain.len()
            }
            (Some(target), None) if target.is_ipv6() => 1 + 16,
            (Some(_), None) => 1 + 4,
        };
        let mut buf = Vec::with_capacity(1 + 16 + 1 + addon_len + 1 + 2 + encoded_address_len);

        buf.push(VLESS_VERSION);
        buf.extend_from_slice(uuid_bytes);
        buf.push(addon_len as u8);
        if let Some(flow) = flow {
            buf.push(0x0a);
            buf.push(flow.len() as u8);
            buf.extend_from_slice(flow.as_bytes());
        }
        buf.push(command);
        let Some(target) = target else {
            return Ok(buf);
        };
        buf.extend_from_slice(&target.port().to_be_bytes());
        if let Some(domain) = target_domain {
            buf.push(ATYP_DOMAIN);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        } else {
            match target {
                SocketAddr::V4(address) => {
                    buf.push(ATYP_IPV4);
                    buf.extend_from_slice(&address.ip().octets());
                }
                SocketAddr::V6(address) => {
                    buf.push(ATYP_IPV6);
                    buf.extend_from_slice(&address.ip().octets());
                }
            }
        }
        Ok(buf)
    }
}

impl VLessHandler {
    fn udp_path(node: &Node, port: u16) -> anyhow::Result<VlessUdpPath> {
        node.vless()
            .and_then(|vless| vless.udp_path(port))
            .ok_or_else(|| super::PacketRejection::Policy.into())
    }

    async fn open_udp(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        path: VlessUdpPath,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        match path {
            VlessUdpPath::H2 => {
                Self::open_h2_udp(runtime, target, target_domain, connect_timeout).await
            }
            VlessUdpPath::CoolShared => {
                Self::open_cool_udp(runtime, false, target, target_domain, connect_timeout).await
            }
            VlessUdpPath::CoolSeparate => {
                Self::open_cool_udp(runtime, true, target, target_domain, connect_timeout).await
            }
            VlessUdpPath::Native => {
                let vless = runtime.node.vless().unwrap();
                let uuid = Self::parse_uuid(vless.uuid.as_deref().unwrap_or(""))?;
                let header = Self::build_request_header(
                    &uuid,
                    CMD_UDP,
                    Some(target),
                    target_domain,
                    vless.wire_flow(),
                )?;
                let stream = self
                    .dial_retained_carrier(&runtime, uuid, header, connect_timeout)
                    .await?;
                Ok(Arc::new(VlessConnectedTransport::new(stream, target, None)))
            }
            VlessUdpPath::UotV2 => {
                let setup = super::uot::connect_request(target, target_domain)?;
                let magic_target = SocketAddr::from(([0, 0, 0, 0], 0));
                let stream = self
                    .dial_retained_base(
                        &runtime,
                        magic_target,
                        Some(super::uot::MAGIC_ADDRESS),
                        connect_timeout,
                    )
                    .await?
                    .stream;
                Ok(Arc::new(VlessConnectedTransport::new(
                    stream,
                    target,
                    Some(setup),
                )))
            }
            VlessUdpPath::Xudp => {
                let stream = self
                    .dial_retained_mux_carrier(&runtime, connect_timeout)
                    .await?;
                Ok(
                    super::vless_cool::connect_single_xudp(stream, target, target_domain, [0; 8])
                        .await?,
                )
            }
        }
    }

    fn cool_limit(node: &Node, separate: bool) -> anyhow::Result<usize> {
        let honk_config::node::VlessMultiplex::Xray { tcp, udp, .. } =
            &node.vless().unwrap().multiplex
        else {
            anyhow::bail!("VLESS Cool path has no Xray multiplex settings");
        };
        if separate {
            let honk_config::node::VlessUdpMux::Separate(limit) = udp else {
                anyhow::bail!("VLESS separate Cool path has no concurrency");
            };
            Ok(limit.get() as usize)
        } else {
            Ok(tcp
                .ok_or_else(|| anyhow::anyhow!("VLESS shared Cool path has no concurrency"))?
                .get() as usize)
        }
    }

    async fn dial_h2_session(
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<super::vless_mux::VlessMuxSession>> {
        let (target, domain) = super::vless_mux::physical_target();
        let honk_config::node::VlessMultiplex::H2 { padding } =
            &runtime.node.vless().unwrap().multiplex
        else {
            anyhow::bail!("VLESS H2 path has no H2 multiplex settings");
        };
        let stream = Self::new()
            .dial_retained_base(&runtime, target, Some(domain), connect_timeout)
            .await?
            .stream;
        super::vless_mux::connect(stream, *padding).await
    }

    async fn open_h2_tcp(
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let pool = runtime.vless_h2_pool()?;
        let dial_runtime = Arc::clone(&runtime);
        let domain = target_domain.map(str::to_string);
        let stream = pool
            .open_with(
                move || Self::dial_h2_session(dial_runtime, connect_timeout),
                move |session, permit| {
                    let domain = domain.clone();
                    async move { session.open_stream(permit, target, domain.as_deref()).await }
                },
            )
            .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }

    async fn open_h2_udp(
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let pool = runtime.vless_h2_pool()?;
        let dial_runtime = Arc::clone(&runtime);
        let domain = target_domain.map(str::to_string);
        let transport = pool
            .open_with(
                move || Self::dial_h2_session(dial_runtime, connect_timeout),
                move |session, permit| {
                    let domain = domain.clone();
                    async move { session.open_packet(permit, target, domain.as_deref()).await }
                },
            )
            .await?;
        Ok(transport)
    }

    async fn dial_cool_session(
        runtime: Arc<crate::runtime::NodeRuntime>,
        active_limit: usize,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<super::vless_cool::VlessCoolSession>> {
        let stream = Self::new()
            .dial_retained_mux_carrier(&runtime, connect_timeout)
            .await?;
        Ok(super::vless_cool::connect(stream, active_limit))
    }

    async fn open_cool_tcp(
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let pool = runtime.vless_shared_cool_pool()?;
        let active_limit = Self::cool_limit(&runtime.node, false)?;
        let dial_runtime = Arc::clone(&runtime);
        let domain = target_domain.map(str::to_string);
        let stream = pool
            .open_with(
                move || Self::dial_cool_session(dial_runtime, active_limit, connect_timeout),
                move |session, permit| {
                    let domain = domain.clone();
                    async move { session.open_stream(permit, target, domain.as_deref()).await }
                },
            )
            .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }

    async fn open_cool_udp(
        runtime: Arc<crate::runtime::NodeRuntime>,
        separate: bool,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let pool = if separate {
            runtime.vless_separate_cool_pool()?
        } else {
            runtime.vless_shared_cool_pool()?
        };
        let active_limit = Self::cool_limit(&runtime.node, separate)?;
        let dial_runtime = Arc::clone(&runtime);
        let domain = target_domain.map(str::to_string);
        let transport = pool
            .open_with(
                move || Self::dial_cool_session(dial_runtime, active_limit, connect_timeout),
                move |session, permit| {
                    let domain = domain.clone();
                    async move { session.open_packet(permit, target, domain.as_deref()).await }
                },
            )
            .await?;
        Ok(transport)
    }

    async fn prepare_mux_udp<S, T, Dial, DialFuture, Open, OpenFuture>(
        pool: Arc<crate::session::SessionPool<S>>,
        dial: Dial,
        open: Open,
        retired_error: &'static str,
    ) -> anyhow::Result<PreparedUdpTransport<T>>
    where
        S: super::MuxSession,
        T: PacketTransport + ?Sized + 'static,
        Dial: FnOnce() -> DialFuture + Send,
        DialFuture: Future<Output = anyhow::Result<Arc<S>>> + Send,
        Open: Fn(Arc<S>, crate::session::SessionPermit<S>) -> OpenFuture + Send,
        OpenFuture: Future<Output = Result<Arc<T>, OpenError>> + Send,
    {
        let mut dial = Some(dial);
        let mut last_error = None;
        for _ in 0..2 {
            match pool.checkout_speculative().await? {
                SpeculativeCheckout::Shared { session, permit } => {
                    match open(Arc::clone(&session), permit).await {
                        Ok(transport) => return Ok(PreparedUdpTransport::ready(transport)),
                        Err(OpenError::Refused(error)) => return Err(error),
                        Err(OpenError::Draining(error)) => {
                            crate::session::ManagedSession::begin_drain(session.as_ref());
                            last_error = Some(error);
                        }
                        Err(OpenError::Session(error)) => {
                            pool.invalidate(&session);
                            last_error = Some(error);
                        }
                    }
                }
                SpeculativeCheckout::Detached(mut reservation) => {
                    let dial = dial.take().expect("speculative dial runs at most once");
                    let session = tokio::select! {
                        result = dial() => result?,
                        _ = reservation.cancelled() => anyhow::bail!(retired_error),
                    };
                    reservation.attach(&session)?;
                    let permit = session
                        .try_reserve()
                        .ok_or_else(|| anyhow::anyhow!("new VLESS mux session has no capacity"))?;
                    let transport = open(session, permit).await.map_err(Self::open_error)?;
                    return Ok(PreparedUdpTransport::new(async move {
                        reservation.commit()?;
                        Ok(transport)
                    }));
                }
            }
        }
        Err(last_error.expect("shared mux open attempts record an error"))
    }

    /// Prepare a concrete source-scoped XUDP child without sending NEW; commit
    /// promotes only a detached physical carrier after the caller wins admission.
    pub async fn prepare_source_udp(
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
        global_id: [u8; 8],
    ) -> anyhow::Result<PreparedUdpTransport<VlessXudpTransport>> {
        match Self::udp_path(&runtime.node, target.port())? {
            VlessUdpPath::Xudp => {
                let stream = Self::new()
                    .dial_retained_mux_carrier(&runtime, timeout)
                    .await?;
                let transport =
                    super::vless_cool::connect_single_xudp(stream, target, domain, global_id)
                        .await?;
                Ok(PreparedUdpTransport::ready(transport))
            }
            path @ (VlessUdpPath::CoolShared | VlessUdpPath::CoolSeparate) => {
                let separate = path == VlessUdpPath::CoolSeparate;
                let pool = if separate {
                    runtime.vless_separate_cool_pool()?
                } else {
                    runtime.vless_shared_cool_pool()?
                };
                let active_limit = Self::cool_limit(&runtime.node, separate)?;
                let dial_runtime = Arc::clone(&runtime);
                Self::prepare_mux_udp(
                    pool,
                    move || Self::dial_cool_session(dial_runtime, active_limit, timeout),
                    move |session, permit| {
                        super::vless_cool::open_xudp(session, permit, target, domain, global_id)
                    },
                    if separate {
                        "VLESS separate Cool pool retired during source preparation"
                    } else {
                        "VLESS shared Cool pool retired during source preparation"
                    },
                )
                .await
            }
            VlessUdpPath::Native | VlessUdpPath::UotV2 | VlessUdpPath::H2 => {
                Err(super::PacketRejection::Policy.into())
            }
        }
    }

    async fn warm_mux_pool<S, Dial, DialFuture>(
        pool: Arc<crate::session::SessionPool<S>>,
        dial: Dial,
        retired_error: &'static str,
    ) -> anyhow::Result<()>
    where
        S: super::MuxSession,
        Dial: FnOnce() -> DialFuture + Send,
        DialFuture: Future<Output = anyhow::Result<Arc<S>>> + Send,
    {
        let mut last_error = None;
        for _ in 0..2 {
            match pool.checkout_speculative().await? {
                SpeculativeCheckout::Shared { session, .. } => {
                    match session.clone().check_ready().await {
                        Ok(()) => return Ok(()),
                        Err(OpenError::Refused(error)) => return Err(error),
                        Err(OpenError::Draining(error)) => {
                            crate::session::ManagedSession::begin_drain(session.as_ref());
                            last_error = Some(error);
                        }
                        Err(OpenError::Session(error)) => {
                            pool.invalidate(&session);
                            last_error = Some(error);
                        }
                    }
                }
                SpeculativeCheckout::Detached(mut reservation) => {
                    let session = tokio::select! {
                        result = dial() => result?,
                        _ = reservation.cancelled() => anyhow::bail!(retired_error),
                    };
                    reservation.attach(&session)?;
                    session
                        .clone()
                        .check_ready()
                        .await
                        .map_err(Self::open_error)?;
                    reservation.commit()?;
                    return Ok(());
                }
            }
        }
        Err(last_error.expect("shared mux readiness attempts record an error"))
    }

    fn open_error(error: OpenError) -> anyhow::Error {
        match error {
            OpenError::Session(error) | OpenError::Draining(error) | OpenError::Refused(error) => {
                error
            }
        }
    }
}

#[async_trait]
impl TcpOutbound for VLessHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        match node.vless().unwrap().tcp_path() {
            VlessTcpPath::Direct => {
                self.dial_base(node, target, target_domain, None, connect_timeout)
                    .await
            }
            VlessTcpPath::H2 => {
                let owner = crate::runtime::NodeRuntime::try_ephemeral_guarded(node)?;
                let stream =
                    Self::open_h2_tcp(owner.runtime(), target, target_domain, connect_timeout)
                        .await?;
                Ok(stream.with_owner(owner))
            }
            VlessTcpPath::Cool => {
                let owner = crate::runtime::NodeRuntime::try_ephemeral_guarded(node)?;
                let stream =
                    Self::open_cool_tcp(owner.runtime(), target, target_domain, connect_timeout)
                        .await?;
                Ok(stream.with_owner(owner))
            }
        }
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::ensure!(
            node.vless().unwrap().tcp_path() == VlessTcpPath::Direct,
            "VLESS multiplexed TCP cannot use a bare pooled connection"
        );
        self.dial_base(node, target, target_domain, Some(tcp), connect_timeout)
            .await
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        match runtime.node.vless().unwrap().tcp_path() {
            VlessTcpPath::Direct => {
                self.dial_base(&runtime.node, target, target_domain, None, connect_timeout)
                    .await
            }
            VlessTcpPath::H2 => {
                Self::open_h2_tcp(runtime, target, target_domain, connect_timeout).await
            }
            VlessTcpPath::Cool => {
                Self::open_cool_tcp(runtime, target, target_domain, connect_timeout).await
            }
        }
    }
}

#[async_trait]
impl PacketOutbound for VLessHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let path = Self::udp_path(node, target.port())?;
        let owner = crate::runtime::NodeRuntime::try_ephemeral_guarded(node)?;
        let transport = self
            .open_udp(
                owner.runtime(),
                path,
                target,
                target_domain,
                connect_timeout,
            )
            .await?;
        Ok(super::packet_transport_with_owner(transport, owner))
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let path = Self::udp_path(&runtime.node, target.port())?;
        self.open_udp(runtime, path, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let path = Self::udp_path(&runtime.node, target.port())?;
        match path {
            VlessUdpPath::H2 => {
                let pool = runtime.vless_h2_pool()?;
                let dial_runtime = Arc::clone(&runtime);
                Self::prepare_mux_udp(
                    pool,
                    move || Self::dial_h2_session(dial_runtime, connect_timeout),
                    move |session, permit| async move {
                        let transport: Arc<dyn PacketTransport> =
                            session.open_packet(permit, target, target_domain).await?;
                        Ok(transport)
                    },
                    "VLESS H2 pool retired during speculative dial",
                )
                .await
            }
            path @ (VlessUdpPath::CoolShared | VlessUdpPath::CoolSeparate) => {
                let separate = path == VlessUdpPath::CoolSeparate;
                let pool = if separate {
                    runtime.vless_separate_cool_pool()?
                } else {
                    runtime.vless_shared_cool_pool()?
                };
                let active_limit = Self::cool_limit(&runtime.node, separate)?;
                let dial_runtime = Arc::clone(&runtime);
                Self::prepare_mux_udp(
                    pool,
                    move || Self::dial_cool_session(dial_runtime, active_limit, connect_timeout),
                    move |session, permit| async move {
                        let transport: Arc<dyn PacketTransport> =
                            session.open_packet(permit, target, target_domain).await?;
                        Ok(transport)
                    },
                    if separate {
                        "VLESS separate Cool pool retired during speculative dial"
                    } else {
                        "VLESS shared Cool pool retired during speculative dial"
                    },
                )
                .await
            }
            VlessUdpPath::Native | VlessUdpPath::Xudp | VlessUdpPath::UotV2 => self
                .open_udp(runtime, path, target, target_domain, connect_timeout)
                .await
                .map(PreparedUdpTransport::ready),
        }
    }
}

#[async_trait]
impl WarmableOutbound for VLessHandler {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: std::time::Duration,
        requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        enum WarmPath {
            H2,
            Cool(bool),
        }
        let path = match requirement {
            WarmRequirement::Session => match runtime.node.vless().unwrap().tcp_path() {
                VlessTcpPath::H2 => WarmPath::H2,
                VlessTcpPath::Cool => WarmPath::Cool(false),
                VlessTcpPath::Direct => anyhow::bail!("VLESS TCP path is not warmable"),
            },
            WarmRequirement::Udp => match runtime.node.vless().unwrap().udp_path(0) {
                Some(VlessUdpPath::H2) => WarmPath::H2,
                Some(VlessUdpPath::CoolShared) => WarmPath::Cool(false),
                Some(VlessUdpPath::CoolSeparate) => WarmPath::Cool(true),
                Some(VlessUdpPath::Native | VlessUdpPath::Xudp | VlessUdpPath::UotV2) | None => {
                    anyhow::bail!("VLESS UDP path is not warmable")
                }
            },
        };
        match path {
            WarmPath::H2 => {
                let pool = runtime.vless_h2_pool()?;
                let dial_runtime = Arc::clone(&runtime);
                Self::warm_mux_pool(
                    pool,
                    move || Self::dial_h2_session(dial_runtime, connect_timeout),
                    "VLESS H2 pool retired during warm-up",
                )
                .await
            }
            WarmPath::Cool(separate) => {
                let pool = if separate {
                    runtime.vless_separate_cool_pool()?
                } else {
                    runtime.vless_shared_cool_pool()?
                };
                let active_limit = Self::cool_limit(&runtime.node, separate)?;
                let dial_runtime = Arc::clone(&runtime);
                Self::warm_mux_pool(
                    pool,
                    move || Self::dial_cool_session(dial_runtime, active_limit, connect_timeout),
                    if separate {
                        "VLESS separate Cool pool retired during warm-up"
                    } else {
                        "VLESS shared Cool pool retired during warm-up"
                    },
                )
                .await
            }
        }
    }
}

#[async_trait]
impl ProbeableOutbound for VLessHandler {}

#[cfg(test)]
mod tests;
