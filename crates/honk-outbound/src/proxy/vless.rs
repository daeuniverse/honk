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
//!    - `cmd`: 0x01 TCP
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

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use honk_config::node::{Node, WireMode};
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{
    AsyncReadWrite, MuxSession as _, PacketOutbound, PacketTransport, PreparedUdpTransport,
    ProbeableOutbound, ProxyStream, TcpOutbound, WarmRequirement, WarmableOutbound,
};
use crate::session::{OpenError, SpeculativeCheckout};

const VLESS_VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

#[derive(Debug)]
pub struct VLessHandler {
    encryption_configs:
        RwLock<lru::LruCache<uuid::Uuid, Arc<super::vless_encryption::ClientConfig>>>,
}

impl Default for VLessHandler {
    fn default() -> Self {
        Self {
            encryption_configs: RwLock::new(lru::LruCache::new(
                NonZeroUsize::new(1024).expect("non-zero VLESS config cache capacity"),
            )),
        }
    }
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
        anyhow::ensure!(
            vless.flow.as_deref().is_none_or(str::is_empty),
            "VLESS Encryption cannot be combined with XTLS flow"
        );
        let cache_key = if node.id.is_nil() {
            node.derive_id()
        } else {
            node.id
        };
        if let Some(config) = self.encryption_configs.read().peek(&cache_key).cloned() {
            return Ok(Some(config));
        }
        let parsed = super::vless_encryption::ClientConfig::parse(value)?;
        let mut configs = self.encryption_configs.write();
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
                (CMD_TCP, Some(_)) | (super::vless_cool::VLESS_MUX_COMMAND, None)
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
    /// Build the post-connect stream for a dial. VLESS Encryption wraps and
    /// erases the selected transport. Vision over raw TCP/TLS instead keeps
    /// the concrete stream type so the direct-copy read switch can reach the
    /// socket; every other case uses the ordinary erased transport.
    async fn dial_stream(
        &self,
        node: &Node,
        uuid: [u8; 16],
        tcp: TcpStream,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let vless = node.vless().unwrap();
        if let Some(config) = self.encryption_config(node)? {
            let stream = super::transport::wrap_transport(node, tcp).await?;
            let encrypted = config.connect(stream).await?;
            return Ok(Self::wrap_response_stream(node, uuid, Box::new(encrypted)));
        }
        if vless.flow.as_deref() == Some("xtls-rprx-vision")
            && matches!(vless.transport.transport.as_str(), "" | "tcp")
        {
            let stream: Box<dyn AsyncReadWrite> =
                match super::transport::maybe_tls_wrap_concrete(node, tcp).await? {
                    super::transport::MaybeTls::Tls(tls) => {
                        Box::new(VisionStream::new(ResponseHeaderStrip::new(tls), uuid))
                    }
                    super::transport::MaybeTls::Plain(tcp) => {
                        Box::new(VisionStream::new(ResponseHeaderStrip::new(tcp), uuid))
                    }
                };
            return Ok(stream);
        }
        let stream = super::transport::wrap_transport(node, tcp).await?;
        Ok(Self::wrap_response_stream(node, uuid, stream))
    }

    fn wrap_response_stream(
        node: &Node,
        uuid: [u8; 16],
        stream: Box<dyn AsyncReadWrite>,
    ) -> Box<dyn AsyncReadWrite> {
        let stripped = ResponseHeaderStrip::new(stream);
        if node.vless().unwrap().flow.as_deref() == Some("xtls-rprx-vision") {
            Box::new(VisionStream::new(stripped, uuid))
        } else {
            Box::new(stripped)
        }
    }
    async fn dial_carrier(
        &self,
        node: &Node,
        uuid: [u8; 16],
        header: Vec<u8>,
        tcp: Option<TcpStream>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let tcp = match tcp {
            Some(tcp) => tcp,
            None => {
                let address = format!("{}:{}", node.host(), node.port);
                crate::util::connect_outbound(&address, connect_timeout).await?
            }
        };
        let mut stream = self.dial_stream(node, uuid, tcp).await?;
        stream.write_all(&header).await?;
        stream.flush().await?;
        Ok(stream)
    }

    async fn dial_base(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: Option<TcpStream>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let vless = node.vless().unwrap();
        let uuid_bytes = Self::parse_uuid(vless.uuid.as_deref().unwrap_or(""))?;
        let header = Self::build_request_header(
            &uuid_bytes,
            CMD_TCP,
            Some(target),
            target_domain,
            vless.flow.as_deref(),
        )?;
        let stream = self
            .dial_carrier(node, uuid_bytes, header, tcp, connect_timeout)
            .await?;
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }

    async fn dial_mux_carrier(
        &self,
        node: &Node,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let vless = node.vless().unwrap();
        let uuid = Self::parse_uuid(vless.uuid.as_deref().unwrap_or(""))?;
        let header = Self::build_request_header(
            &uuid,
            super::vless_cool::VLESS_MUX_COMMAND,
            None,
            None,
            vless.flow.as_deref(),
        )?;
        self.dial_carrier(node, uuid, header, None, connect_timeout)
            .await
    }

    fn uses_mux_runtime(node: &Node) -> bool {
        matches!(
            node.vless().unwrap().mode,
            WireMode::H2mux | WireMode::H2muxPadded | WireMode::MuxCool
        )
    }

    async fn dial_h2_session(
        node: Arc<Node>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<super::vless_mux::VlessMuxSession>> {
        let (target, domain) = super::vless_mux::physical_target();
        let padded = node.vless().unwrap().mode == WireMode::H2muxPadded;
        let stream = Self::new()
            .dial_base(&node, target, Some(domain), None, connect_timeout)
            .await?
            .stream;
        super::vless_mux::connect(stream, padded).await
    }

    async fn open_h2_tcp(
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let pool = runtime.vless_h2_pool()?;
        let dial_node = Arc::clone(&runtime.node);
        let domain = target_domain.map(str::to_string);
        let stream = pool
            .open_with(
                move || {
                    let node = Arc::clone(&dial_node);
                    async move { Self::dial_h2_session(node, connect_timeout).await }
                },
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
        let dial_node = Arc::clone(&runtime.node);
        let domain = target_domain.map(str::to_string);
        let transport = pool
            .open_with(
                move || {
                    let node = Arc::clone(&dial_node);
                    async move { Self::dial_h2_session(node, connect_timeout).await }
                },
                move |session, permit| {
                    let domain = domain.clone();
                    async move { session.open_packet(permit, target, domain.as_deref()).await }
                },
            )
            .await?;
        Ok(transport)
    }

    async fn dial_cool_session(
        node: Arc<Node>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<super::vless_cool::VlessCoolSession>> {
        let stream = Self::new().dial_mux_carrier(&node, connect_timeout).await?;
        super::vless_cool::connect(stream).await
    }

    async fn open_cool_tcp(
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let pool = runtime.vless_cool_pool()?;
        let dial_node = Arc::clone(&runtime.node);
        let domain = target_domain.map(str::to_string);
        let stream = pool
            .open_with(
                move || {
                    let node = Arc::clone(&dial_node);
                    async move { Self::dial_cool_session(node, connect_timeout).await }
                },
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
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let pool = runtime.vless_cool_pool()?;
        let dial_node = Arc::clone(&runtime.node);
        let domain = target_domain.map(str::to_string);
        let transport = pool
            .open_with(
                move || {
                    let node = Arc::clone(&dial_node);
                    async move { Self::dial_cool_session(node, connect_timeout).await }
                },
                move |session, permit| {
                    let domain = domain.clone();
                    async move { session.open_packet(permit, target, domain.as_deref()).await }
                },
            )
            .await?;
        Ok(transport)
    }

    async fn prepare_mux_udp<S, Dial, DialFuture>(
        pool: Arc<crate::session::SessionPool<S>>,
        dial: Dial,
        target: SocketAddr,
        target_domain: Option<&str>,
        retired_error: &'static str,
    ) -> anyhow::Result<PreparedUdpTransport>
    where
        S: super::MuxSession,
        Dial: FnOnce() -> DialFuture + Send,
        DialFuture: std::future::Future<Output = anyhow::Result<Arc<S>>> + Send,
    {
        let domain = target_domain.map(str::to_string);
        let mut dial = Some(dial);
        let mut last_error = None;
        for _ in 0..2 {
            match pool.checkout_speculative().await? {
                SpeculativeCheckout::Shared { session, permit } => {
                    match session
                        .clone()
                        .open_packet(permit, target, domain.as_deref())
                        .await
                    {
                        Ok(transport) => {
                            let transport: Arc<dyn PacketTransport> = transport;
                            return Ok(PreparedUdpTransport::ready(transport));
                        }
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
                    let transport = session
                        .open_packet(permit, target, domain.as_deref())
                        .await
                        .map_err(Self::open_error)?;
                    let transport: Arc<dyn PacketTransport> = transport;
                    return Ok(PreparedUdpTransport::new(transport, move || async move {
                        reservation.commit()?;
                        Ok(())
                    }));
                }
            }
        }
        Err(last_error.expect("shared mux open attempts record an error"))
    }

    async fn warm_mux_pool<S, Dial, DialFuture>(
        pool: Arc<crate::session::SessionPool<S>>,
        dial: Dial,
        retired_error: &'static str,
    ) -> anyhow::Result<()>
    where
        S: super::MuxSession,
        Dial: FnOnce() -> DialFuture + Send,
        DialFuture: std::future::Future<Output = anyhow::Result<Arc<S>>> + Send,
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

/// Real servers do not send the two-byte `[version][addon_len]` prefix and
/// optional addons on request acceptance. They emit them with the target's
/// first downstream data (sing-vmess `serverConn.Write`, Xray alike). Reading
/// eagerly during dial deadlocks when the target needs client bytes before it
/// responds, so the prefix is consumed on the first read. A non-zero version
/// surfaces as a read error rather than a dial error.
#[derive(Debug)]
struct ResponseHeaderStrip<S> {
    inner: S,
    state: StripState,
}

#[derive(Debug)]
enum StripState {
    /// Accumulating the 2-byte `[version][addon_len]` header.
    Header {
        filled: usize,
        buf: [u8; 2],
    },
    /// Discarding `remaining` addon bytes.
    Addon {
        remaining: usize,
    },
    Body,
}

impl<S: AsyncRead + Unpin> ResponseHeaderStrip<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            state: StripState::Header {
                filled: 0,
                buf: [0; 2],
            },
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ResponseHeaderStrip<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let Self { inner, state, .. } = &mut *self;
        loop {
            match state {
                StripState::Header { filled, buf: hdr } => {
                    while *filled < 2 {
                        let mut rb = tokio::io::ReadBuf::new(&mut hdr[*filled..]);
                        match std::pin::Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                            std::task::Poll::Pending => return std::task::Poll::Pending,
                            std::task::Poll::Ready(Err(e)) => {
                                return std::task::Poll::Ready(Err(e));
                            }
                            std::task::Poll::Ready(Ok(())) => {
                                if rb.filled().is_empty() {
                                    return std::task::Poll::Ready(Ok(())); // EOF before header
                                }
                                *filled += rb.filled().len();
                            }
                        }
                    }
                    let [version, addon_len] = *hdr;
                    if version != 0 {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("VLESS: server rejected request (code 0x{version:02x})"),
                        )));
                    }
                    *state = if addon_len > 0 {
                        StripState::Addon {
                            remaining: addon_len as usize,
                        }
                    } else {
                        StripState::Body
                    };
                }
                StripState::Addon { remaining } => {
                    let mut scratch = [0u8; 256];
                    let n = (*remaining).min(scratch.len());
                    let mut rb = tokio::io::ReadBuf::new(&mut scratch[..n]);
                    match std::pin::Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                        std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                        std::task::Poll::Ready(Ok(())) => {
                            if rb.filled().is_empty() {
                                return std::task::Poll::Ready(Ok(())); // EOF in addon
                            }
                            *remaining -= rb.filled().len();
                            if *remaining == 0 {
                                *state = StripState::Body;
                            }
                        }
                    }
                }
                StripState::Body => {
                    return std::pin::Pin::new(&mut *inner).poll_read(cx, buf);
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ResponseHeaderStrip<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// XTLS Vision response-side unpadding (flow `xtls-rprx-vision`).
///
/// The vision server frames the response body as a 16-byte user UUID
/// followed by `[command u8][content_len u16][padding_len u16][content]
/// [padding]` blocks (Xray-core proxy/vless encoding semantics, mirrored
/// from sing-vmess vision.go whose frame layout the lab emits). `command`
/// 1 (End) stops framing but keeps the outer TLS session; `command` 2
/// (Direct) is the XTLS direct copy: the server abandons the outer TLS
/// session and exchanges plaintext inner-TLS records on the raw socket
/// (sing-vmess `directWrite`/`netConn`, Xray `WriterSwitchToDirectCopy`),
/// so the read side must switch to the raw TCP conn or the next record
/// dies in the abandoned TLS session (observed as BAD_DECRYPT). The write
/// side stays on the outer stream: both servers only switch their uplink
/// to raw when the client pads its upload with a Direct command, and a
/// raw (unpadded) upload keeps the server reading the TLS uplink.
///
/// The upload direction needs no padding: the server passes raw upload
/// through unless it begins with the user UUID itself, and padding is
/// traffic shaping, not framing.
#[derive(Debug)]
struct VisionStream<S> {
    inner: S,
    uuid: [u8; 16],
    inbox: BytesMut,
    state: VisionState,
    inner_eof: bool,
}

/// Reach the raw TCP socket for the Vision direct-copy read switch. WS/gRPC
/// streams cannot unwrap and fall back to outer-stream raw passthrough.
pub(crate) trait RawTcp {
    fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
        None
    }
}

impl RawTcp for TcpStream {
    fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
        Some(self)
    }
}

impl RawTcp for tokio_boring::SslStream<TcpStream> {
    fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
        Some(self.get_mut())
    }
}

impl RawTcp for Box<dyn AsyncReadWrite> {}

impl<T: RawTcp + ?Sized> RawTcp for Box<T> {
    fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
        (**self).raw_tcp()
    }
}

impl<S: RawTcp> RawTcp for ResponseHeaderStrip<S> {
    fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
        self.inner.raw_tcp()
    }
}

#[derive(Debug)]
enum VisionState {
    /// The server's first write is at least uuid(16) + header(5) bytes;
    /// fewer cannot prove framed vs raw, so keep buffering.
    Detect,
    Framed {
        content_remaining: usize,
        padding_remaining: usize,
        command: u8,
    },
    /// Outer-session passthrough (after End, or never framed).
    Raw,
    /// Raw-socket read after the Direct command (write side unaffected).
    DirectRaw,
    Failed,
}

const VISION_COMMAND_END: u8 = 1;
const VISION_COMMAND_DIRECT: u8 = 2;

impl<S> VisionStream<S> {
    fn new(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            inbox: BytesMut::new(),
            state: VisionState::Detect,
            inner_eof: false,
        }
    }
}

impl<S: AsyncRead + RawTcp + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        let initial_filled = buf.filled().len();

        loop {
            let needs_inner_read = {
                let this = &mut *self;
                let state = std::mem::replace(&mut this.state, VisionState::Failed);
                match state {
                    VisionState::Detect => {
                        if this.inbox.len() < 21 {
                            if this.inner_eof {
                                this.state = VisionState::Raw;
                                continue;
                            }
                            this.state = VisionState::Detect;
                            true
                        } else if this.inbox[..16] == this.uuid {
                            this.inbox.advance(16);
                            this.state = VisionState::Framed {
                                content_remaining: 0,
                                padding_remaining: 0,
                                command: 0,
                            };
                            continue;
                        } else {
                            this.state = VisionState::Raw;
                            continue;
                        }
                    }
                    VisionState::Framed {
                        mut content_remaining,
                        mut padding_remaining,
                        command,
                    } => {
                        if content_remaining > 0 {
                            let count =
                                content_remaining.min(this.inbox.len()).min(buf.remaining());
                            if count > 0 {
                                buf.put_slice(&this.inbox[..count]);
                                this.inbox.advance(count);
                                content_remaining -= count;
                            }
                            this.state = VisionState::Framed {
                                content_remaining,
                                padding_remaining,
                                command,
                            };
                            if buf.remaining() == 0 {
                                return std::task::Poll::Ready(Ok(()));
                            }
                            if content_remaining == 0 {
                                continue;
                            }
                            if this.inner_eof || buf.filled().len() > initial_filled {
                                return std::task::Poll::Ready(Ok(()));
                            }
                            true
                        } else if padding_remaining > 0 {
                            let count = padding_remaining.min(this.inbox.len());
                            this.inbox.advance(count);
                            padding_remaining -= count;
                            this.state = VisionState::Framed {
                                content_remaining,
                                padding_remaining,
                                command,
                            };
                            if padding_remaining == 0 {
                                continue;
                            }
                            if this.inner_eof || buf.filled().len() > initial_filled {
                                return std::task::Poll::Ready(Ok(()));
                            }
                            true
                        } else {
                            match command {
                                VISION_COMMAND_END => {
                                    this.state = VisionState::Raw;
                                    continue;
                                }
                                VISION_COMMAND_DIRECT => {
                                    // Drain bytes already read through the outer TLS stream
                                    // before switching the read side to the raw socket.
                                    this.state = if this.inner.raw_tcp().is_some() {
                                        VisionState::DirectRaw
                                    } else {
                                        VisionState::Raw
                                    };
                                    continue;
                                }
                                0 => {
                                    if this.inbox.len() < 5 {
                                        this.state = VisionState::Framed {
                                            content_remaining,
                                            padding_remaining,
                                            command,
                                        };
                                        if this.inner_eof || buf.filled().len() > initial_filled {
                                            return std::task::Poll::Ready(Ok(()));
                                        }
                                        true
                                    } else {
                                        let command = this.inbox[0];
                                        let content_remaining =
                                            u16::from_be_bytes([this.inbox[1], this.inbox[2]])
                                                as usize;
                                        let padding_remaining =
                                            u16::from_be_bytes([this.inbox[3], this.inbox[4]])
                                                as usize;
                                        this.inbox.advance(5);
                                        this.state = VisionState::Framed {
                                            content_remaining,
                                            padding_remaining,
                                            command,
                                        };
                                        continue;
                                    }
                                }
                                _ => {
                                    this.state = VisionState::Failed;
                                    if buf.filled().len() > initial_filled {
                                        return std::task::Poll::Ready(Ok(()));
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    VisionState::Raw => {
                        this.state = VisionState::Raw;
                        if !this.inbox.is_empty() {
                            let count = this.inbox.len().min(buf.remaining());
                            buf.put_slice(&this.inbox[..count]);
                            this.inbox.advance(count);
                            return std::task::Poll::Ready(Ok(()));
                        }
                        if buf.filled().len() > initial_filled {
                            return std::task::Poll::Ready(Ok(()));
                        }
                        return std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
                    }
                    VisionState::DirectRaw => {
                        this.state = VisionState::DirectRaw;
                        if !this.inbox.is_empty() {
                            let count = this.inbox.len().min(buf.remaining());
                            buf.put_slice(&this.inbox[..count]);
                            this.inbox.advance(count);
                            return std::task::Poll::Ready(Ok(()));
                        }
                        if buf.filled().len() > initial_filled {
                            return std::task::Poll::Ready(Ok(()));
                        }
                        let tcp = this.inner.raw_tcp().expect("checked at transition");
                        return std::pin::Pin::new(tcp).poll_read(cx, buf);
                    }
                    VisionState::Failed => {
                        this.state = VisionState::Failed;
                        if buf.filled().len() > initial_filled {
                            return std::task::Poll::Ready(Ok(()));
                        }
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "vision: unknown padding command",
                        )));
                    }
                }
            };

            debug_assert!(needs_inner_read);
            let this = &mut *self;
            let old_len = this.inbox.len();
            this.inbox.resize(old_len + 8192, 0);
            let (poll, filled) = {
                let mut read_buf = tokio::io::ReadBuf::new(&mut this.inbox[old_len..]);
                let poll = std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf);
                let filled = read_buf.filled().len();
                (poll, filled)
            };
            match poll {
                std::task::Poll::Pending => {
                    this.inbox.truncate(old_len);
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(Err(error)) => {
                    this.inbox.truncate(old_len);
                    return std::task::Poll::Ready(Err(error));
                }
                std::task::Poll::Ready(Ok(())) => {
                    this.inbox.truncate(old_len + filled);
                    if filled == 0 {
                        this.inner_eof = true;
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct VlessUotReader {
    stream: tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>,
    decoder: super::uot::Decoder,
}

struct VlessUotWriter {
    stream: tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>,
    setup: Option<bytes::Bytes>,
    pending: bool,
}

struct VlessUotTransport {
    reader: tokio::sync::Mutex<VlessUotReader>,
    writer: tokio::sync::Mutex<VlessUotWriter>,
    target: SocketAddr,
}

impl VlessUotTransport {
    fn new(stream: Box<dyn AsyncReadWrite>, target: SocketAddr, setup: bytes::Bytes) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: tokio::sync::Mutex::new(VlessUotReader {
                stream: reader,
                decoder: super::uot::Decoder::default(),
            }),
            writer: tokio::sync::Mutex::new(VlessUotWriter {
                stream: writer,
                setup: Some(setup),
                pending: false,
            }),
            target,
        }
    }

    async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        let packet = super::uot::encode_packet(data, super::uot::MAX_PACKET_SIZE)?;
        let mut writer = self.writer.lock().await;
        if writer.pending {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "VLESS UoT write was interrupted",
            ));
        }
        let frame = if let Some(setup) = writer.setup.as_ref() {
            let mut frame = bytes::BytesMut::with_capacity(setup.len() + packet.len());
            frame.extend_from_slice(setup);
            frame.extend_from_slice(&packet);
            frame.freeze()
        } else {
            packet
        };
        writer.pending = true;
        writer.stream.write_all(&frame).await?;
        writer.stream.flush().await?;
        writer.setup = None;
        writer.pending = false;
        Ok(())
    }
}

impl std::fmt::Debug for VlessUotTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessUotTransport")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PacketTransport for VlessUotTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send(data).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.send(data).await
    }

    async fn recv_packet(&self, output: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        loop {
            if let Some(size) = reader.decoder.next_packet(output)? {
                return Ok((size, self.target));
            }
            let mut chunk = [0; 16 * 1024];
            let size = reader.stream.read(&mut chunk).await?;
            if size == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "VLESS UoT stream closed",
                ));
            }
            reader.decoder.push(&chunk[..size])?;
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
        match node.vless().unwrap().mode {
            WireMode::H2mux | WireMode::H2muxPadded => {
                let owner = crate::runtime::NodeRuntime::ephemeral_guarded(node);
                let stream =
                    Self::open_h2_tcp(owner.runtime(), target, target_domain, connect_timeout)
                        .await?;
                Ok(stream.with_owner(owner))
            }
            WireMode::MuxCool => {
                let owner = crate::runtime::NodeRuntime::ephemeral_guarded(node);
                let stream =
                    Self::open_cool_tcp(owner.runtime(), target, target_domain, connect_timeout)
                        .await?;
                Ok(stream.with_owner(owner))
            }
            WireMode::Legacy | WireMode::UotV2 | WireMode::Xudp => {
                self.dial_base(node, target, target_domain, None, connect_timeout)
                    .await
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
        if Self::uses_mux_runtime(node) {
            anyhow::bail!("VLESS mux cannot use a bare pooled TCP connection");
        }
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
        match runtime.node.vless().unwrap().mode {
            WireMode::H2mux | WireMode::H2muxPadded => {
                Self::open_h2_tcp(runtime, target, target_domain, connect_timeout).await
            }
            WireMode::MuxCool => {
                Self::open_cool_tcp(runtime, target, target_domain, connect_timeout).await
            }
            WireMode::Legacy | WireMode::UotV2 | WireMode::Xudp => {
                self.dial_base(&runtime.node, target, target_domain, None, connect_timeout)
                    .await
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
        if !crate::descriptor::network_allows_udp(node) {
            anyhow::bail!("VLESS node '{}' disables UDP", node.name);
        }
        match node.vless().unwrap().mode {
            WireMode::Legacy => anyhow::bail!(
                "VLESS UDP requires uot-v2, xudp, h2mux, h2mux-padded, or mux-cool mode"
            ),
            WireMode::UotV2 => {
                let setup = super::uot::connect_request(target, target_domain)?;
                let magic_target = SocketAddr::from(([0, 0, 0, 0], 0));
                let stream = self
                    .dial_base(
                        node,
                        magic_target,
                        Some(super::uot::MAGIC_ADDRESS),
                        None,
                        connect_timeout,
                    )
                    .await?
                    .stream;
                Ok(Arc::new(VlessUotTransport::new(stream, target, setup)))
            }
            WireMode::Xudp => {
                let stream = self.dial_mux_carrier(node, connect_timeout).await?;
                Ok(super::vless_cool::connect_single_xudp(stream, target, target_domain).await?)
            }
            WireMode::H2mux | WireMode::H2muxPadded => {
                let owner = crate::runtime::NodeRuntime::ephemeral_guarded(node);
                let transport =
                    Self::open_h2_udp(owner.runtime(), target, target_domain, connect_timeout)
                        .await?;
                Ok(super::packet_transport_with_owner(transport, owner))
            }
            WireMode::MuxCool => {
                let owner = crate::runtime::NodeRuntime::ephemeral_guarded(node);
                let transport =
                    Self::open_cool_udp(owner.runtime(), target, target_domain, connect_timeout)
                        .await?;
                Ok(super::packet_transport_with_owner(transport, owner))
            }
        }
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        match runtime.node.vless().unwrap().mode {
            WireMode::H2mux | WireMode::H2muxPadded => {
                Self::open_h2_udp(runtime, target, target_domain, connect_timeout).await
            }
            WireMode::MuxCool => {
                Self::open_cool_udp(runtime, target, target_domain, connect_timeout).await
            }
            WireMode::Legacy | WireMode::UotV2 | WireMode::Xudp => {
                self.dial_udp_transport(&runtime.node, target, target_domain, connect_timeout)
                    .await
            }
        }
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        match runtime.node.vless().unwrap().mode {
            WireMode::H2mux | WireMode::H2muxPadded => {
                let pool = runtime.vless_h2_pool()?;
                let node = Arc::clone(&runtime.node);
                Self::prepare_mux_udp(
                    pool,
                    move || Self::dial_h2_session(node, connect_timeout),
                    target,
                    target_domain,
                    "VLESS H2MUX pool retired during speculative dial",
                )
                .await
            }
            WireMode::MuxCool => {
                let pool = runtime.vless_cool_pool()?;
                let node = Arc::clone(&runtime.node);
                Self::prepare_mux_udp(
                    pool,
                    move || Self::dial_cool_session(node, connect_timeout),
                    target,
                    target_domain,
                    "VLESS Mux.Cool pool retired during speculative dial",
                )
                .await
            }
            WireMode::Legacy | WireMode::UotV2 | WireMode::Xudp => self
                .dial_udp_transport_runtime(runtime, target, target_domain, connect_timeout)
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
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        match runtime.node.vless().unwrap().mode {
            WireMode::H2mux | WireMode::H2muxPadded => {
                let pool = runtime.vless_h2_pool()?;
                let node = Arc::clone(&runtime.node);
                Self::warm_mux_pool(
                    pool,
                    move || Self::dial_h2_session(node, connect_timeout),
                    "VLESS H2MUX pool retired during warm-up",
                )
                .await?;
            }
            WireMode::MuxCool => {
                let pool = runtime.vless_cool_pool()?;
                let node = Arc::clone(&runtime.node);
                Self::warm_mux_pool(
                    pool,
                    move || Self::dial_cool_session(node, connect_timeout),
                    "VLESS Mux.Cool pool retired during warm-up",
                )
                .await?;
            }
            WireMode::Legacy | WireMode::UotV2 | WireMode::Xudp => {
                anyhow::bail!("VLESS mode has no warmable runtime")
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ProbeableOutbound for VLessHandler {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn vless_node(uuid: &str, mode: WireMode) -> Node {
        Node {
            outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
                uuid: Some(uuid.into()),
                mode,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// AsyncRead yielding at most `chunk` bytes per poll, to force frame
    /// headers and UUID detection across read boundaries.
    struct ChunkedReader {
        data: std::collections::VecDeque<u8>,
        chunk: usize,
    }

    impl tokio::io::AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let n = self.chunk.min(buf.remaining()).min(self.data.len());
            let (front, _) = self.data.as_slices();
            buf.put_slice(&front[..n]);
            self.data.drain(..n);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl RawTcp for ChunkedReader {}

    struct SegmentedReader {
        segments: std::collections::VecDeque<std::collections::VecDeque<u8>>,
    }

    impl tokio::io::AsyncRead for SegmentedReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            while self
                .segments
                .front()
                .is_some_and(|segment| segment.is_empty())
            {
                self.segments.pop_front();
            }
            let Some(segment) = self.segments.front_mut() else {
                return std::task::Poll::Ready(Ok(()));
            };
            let count = segment.len().min(buf.remaining());
            let (front, _) = segment.as_slices();
            buf.put_slice(&front[..count]);
            segment.drain(..count);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl RawTcp for SegmentedReader {}

    struct DirectSwitchIo {
        prefix: std::collections::VecDeque<u8>,
        raw: TcpStream,
        outer_writes: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
    }

    impl tokio::io::AsyncRead for DirectSwitchIo {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.prefix.is_empty() {
                return std::pin::Pin::new(&mut self.raw).poll_read(cx, buf);
            }
            let count = self.prefix.len().min(buf.remaining());
            let (front, _) = self.prefix.as_slices();
            buf.put_slice(&front[..count]);
            self.prefix.drain(..count);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for DirectSwitchIo {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.outer_writes.lock().extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl RawTcp for DirectSwitchIo {
        fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
            Some(&mut self.raw)
        }
    }

    fn vision_frame(command: u8, content: &[u8], padding: usize) -> Vec<u8> {
        let mut frame = vec![
            command,
            (content.len() >> 8) as u8,
            content.len() as u8,
            (padding >> 8) as u8,
            padding as u8,
        ];
        frame.extend_from_slice(content);
        frame.extend(std::iter::repeat_n(0u8, padding));
        frame
    }

    async fn unpad_all(uuid: [u8; 16], data: &[u8], chunk: usize) -> Vec<u8> {
        let reader = ChunkedReader {
            data: data.iter().copied().collect(),
            chunk,
        };
        let mut stream = VisionStream::new(reader, uuid);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn vision_unpad_frames_then_raw_tail() {
        let uuid = [7u8; 16];
        let mut data = uuid.to_vec();
        data.extend(vision_frame(0, b"hello", 3));
        data.extend(vision_frame(0, b"world", 0));
        data.extend(vision_frame(VISION_COMMAND_END, b"!", 2));
        data.extend_from_slice(b"RAW-TAIL");
        for chunk in [1usize, 3, 7, 1024] {
            assert_eq!(
                unpad_all(uuid, &data, chunk).await,
                b"helloworld!RAW-TAIL",
                "chunk={chunk}"
            );
        }
    }

    #[tokio::test]
    async fn vision_unpad_direct_command_switches_to_raw() {
        let uuid = [9u8; 16];
        let mut data = uuid.to_vec();
        data.extend(vision_frame(VISION_COMMAND_DIRECT, b"abc", 1));
        data.extend_from_slice(b"rest-is-raw");
        for chunk in [2usize, 1024] {
            assert_eq!(
                unpad_all(uuid, &data, chunk).await,
                b"abcrest-is-raw",
                "chunk={chunk}"
            );
        }
    }

    #[tokio::test]
    async fn vision_one_byte_destination_buffers_preserve_payload() {
        let uuid = [3_u8; 16];
        let mut data = uuid.to_vec();
        data.extend(vision_frame(0, b"first", 4));
        data.extend(vision_frame(0, b"", 0));
        data.extend(vision_frame(VISION_COMMAND_END, b"second", 2));
        data.extend_from_slice(b"-raw");
        let reader = ChunkedReader {
            data: data.into(),
            chunk: 8192,
        };
        let mut stream = VisionStream::new(reader, uuid);
        let mut output = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            let size = stream.read(&mut byte).await.unwrap();
            if size == 0 {
                break;
            }
            assert_eq!(size, 1);
            output.push(byte[0]);
        }
        assert_eq!(output, b"firstsecond-raw");
    }

    #[tokio::test]
    async fn vision_accepts_every_source_frame_boundary() {
        let uuid = [4_u8; 16];
        let mut data = uuid.to_vec();
        data.extend(vision_frame(0, b"alpha", 3));
        data.extend(vision_frame(0, b"", 2));
        data.extend(vision_frame(VISION_COMMAND_END, b"omega", 0));
        data.extend_from_slice(b"-tail");

        for boundary in 0..=data.len() {
            let reader = SegmentedReader {
                segments: vec![
                    data[..boundary].iter().copied().collect(),
                    data[boundary..].iter().copied().collect(),
                ]
                .into(),
            };
            let mut stream = VisionStream::new(reader, uuid);
            let mut output = Vec::new();
            stream.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, b"alphaomega-tail", "boundary={boundary}");
        }
    }

    #[tokio::test]
    async fn vision_truncated_detected_frame_ends_cleanly() {
        let uuid = [5_u8; 16];
        let mut truncated_content = uuid.to_vec();
        truncated_content.extend_from_slice(&[0, 0, 5, 0, 0]);
        truncated_content.extend_from_slice(b"ab");
        assert_eq!(unpad_all(uuid, &truncated_content, 2).await, b"ab");

        let mut truncated_padding = uuid.to_vec();
        truncated_padding.extend_from_slice(&[0, 0, 3, 0, 5]);
        truncated_padding.extend_from_slice(b"abc\0\0");
        assert_eq!(unpad_all(uuid, &truncated_padding, 3).await, b"abc");
    }

    #[tokio::test]
    async fn vision_sub_probe_size_streams_pass_through_raw() {
        let uuid = [6_u8; 16];
        let mut source = uuid.to_vec();
        source.extend_from_slice(&[0, 0, 0, 0]);
        for length in 0..21 {
            assert_eq!(
                unpad_all(uuid, &source[..length], 1).await,
                source[..length],
                "length={length}"
            );
        }
    }

    #[tokio::test]
    async fn vision_direct_drains_buffered_tail_and_keeps_outer_writes() {
        let uuid = [8_u8; 16];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"raw-tail").await.unwrap();
        });
        let raw = TcpStream::connect(address).await.unwrap();
        let mut prefix = uuid.to_vec();
        prefix.extend(vision_frame(VISION_COMMAND_DIRECT, b"framed-", 1));
        prefix.extend_from_slice(b"buffered-");
        let outer_writes = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let io = DirectSwitchIo {
            prefix: prefix.into(),
            raw,
            outer_writes: std::sync::Arc::clone(&outer_writes),
        };
        let mut stream = VisionStream::new(io, uuid);
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"framed-buffered-raw-tail");

        stream.write_all(b"outer-uplink").await.unwrap();
        assert_eq!(&*outer_writes.lock(), b"outer-uplink");
        server.await.unwrap();
    }

    /// After a Direct command the server abandons the outer TLS session
    /// and writes plaintext on the raw socket: a loopback TLS server sends
    /// vision frames over TLS, then switches to raw TCP writes; the client
    /// must deliver both phases (write side stays on TLS).
    #[tokio::test]
    async fn vision_direct_raw_read_switch_over_tls() {
        use boring::pkey::PKey;
        use boring::ssl::{SslAcceptor, SslMethod};
        use boring::x509::X509;

        let uuid = [5u8; 16];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            use std::io::Write;
            let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            acceptor
                .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
                .unwrap();
            acceptor
                .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
                .unwrap();
            let acceptor = acceptor.build();
            let (stream, _) = listener.accept().unwrap();
            let mut tls = acceptor.accept(stream).unwrap();
            let mut frame = uuid.to_vec();
            frame.extend(vision_frame(0, b"hel", 2));
            frame.extend(vision_frame(VISION_COMMAND_DIRECT, b"lo", 0));
            tls.write_all(&frame).unwrap();
            tls.flush().unwrap();
            // Direct: abandon TLS, write plaintext on the raw transport.
            let mut raw = tls.into_inner();
            raw.write_all(b" world").unwrap();
            raw.shutdown(std::net::Shutdown::Both).ok();
        });

        let mut node = vless_node("", WireMode::Legacy);
        node.tls_mut().unwrap().skip_cert_verify = true;
        let connector = crate::tls::build_connector(&node).unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut tls = connector.connect("localhost", tcp).await.unwrap();
        assert!(
            RawTcp::raw_tcp(&mut tls).is_some(),
            "TLS stream must unwrap"
        );
        let mut stream = VisionStream::new(tls, uuid);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn vision_passthrough_without_uuid_prefix() {
        let uuid = [7u8; 16];
        let data = b"plain stream, not vision framed".to_vec();
        for chunk in [4usize, 1024] {
            assert_eq!(unpad_all(uuid, &data, chunk).await, data, "chunk={chunk}");
        }
    }

    #[tokio::test]
    async fn vision_detect_short_stream_below_probe_size() {
        // Fewer than uuid(16)+header(5) bytes can never prove framing;
        // even a UUID-looking prefix passes through raw at EOF.
        let uuid = [7u8; 16];
        let data = uuid[..10].to_vec();
        assert_eq!(unpad_all(uuid, &data, 2).await, data);
    }

    #[tokio::test]
    async fn vision_unpad_lab_frame_sequence() {
        // Mirrored from a live sing-box vision downlink trace: big content
        // frames with long padding, then a Direct switch to raw.
        let uuid = [7u8; 16];
        let mk = |command: u8, content: usize, padding: usize, fill: u8| {
            let mut frame = vec![
                command,
                (content >> 8) as u8,
                content as u8,
                (padding >> 8) as u8,
                padding as u8,
            ];
            frame.extend(std::iter::repeat_n(fill, content));
            frame.extend(std::iter::repeat_n(0u8, padding));
            frame
        };
        let mut data = uuid.to_vec();
        data.extend(mk(0, 146, 135, b'a'));
        data.extend(mk(0, 5219, 180, b'b'));
        data.extend(mk(VISION_COMMAND_DIRECT, 647, 262, b'c'));
        data.extend_from_slice(b"RAW-TAIL");

        let mut expected = Vec::new();
        expected.extend(std::iter::repeat_n(b'a', 146));
        expected.extend(std::iter::repeat_n(b'b', 5219));
        expected.extend(std::iter::repeat_n(b'c', 647));
        expected.extend_from_slice(b"RAW-TAIL");

        for chunk in [7usize, 1400, 8192, 65536] {
            assert_eq!(
                unpad_all(uuid, &data, chunk).await,
                expected,
                "chunk={chunk}"
            );
        }
    }

    #[tokio::test]
    async fn vision_unknown_command_fails() {
        let uuid = [7u8; 16];
        let mut data = uuid.to_vec();
        data.extend(vision_frame(0x42, b"x", 0));
        let reader = ChunkedReader {
            data: data.into(),
            chunk: 1024,
        };
        let mut stream = VisionStream::new(reader, uuid);
        let mut out = Vec::new();
        let err = stream.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn response_strip_header_and_addon() {
        let mut data = vec![0x00, 0x03, 0xaa, 0xbb, 0xcc];
        data.extend_from_slice(b"payload-bytes");
        for chunk in [1usize, 2, 5, 1024] {
            let reader = ChunkedReader {
                data: data.iter().copied().collect(),
                chunk,
            };
            let mut stream = ResponseHeaderStrip::new(reader);
            let mut out = Vec::new();
            stream.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"payload-bytes", "chunk={chunk}");
        }
    }

    #[tokio::test]
    async fn response_strip_rejects_nonzero_version() {
        let data = vec![0x01, 0x00, 0xff];
        let reader = ChunkedReader {
            data: data.into(),
            chunk: 1024,
        };
        let mut stream = ResponseHeaderStrip::new(reader);
        let mut out = Vec::new();
        let err = stream.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Real servers piggyback the response header on the target's first
    /// downstream bytes: dial must return without it, and the header must
    /// not leak into the relayed stream.
    #[tokio::test]
    async fn test_vless_dial_lazy_response_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 19];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[18], CMD_TCP);
            let mut addr = [0u8; 7];
            stream.read_exact(&mut addr).await.unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            // Response header only after the client spoke first.
            stream.write_all(b"\x00\x00pong").await.unwrap();
        });

        let node = Node {
            name: "vless-lazy".into(),
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            ..vless_node(uuid_str, WireMode::Legacy)
        };
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let mut ps = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            VLessHandler::new().dial(&node, target, None, std::time::Duration::from_secs(3)),
        )
        .await
        .expect("dial must not wait for the response header")
        .unwrap();
        ps.stream.write_all(b"ping").await.unwrap();
        ps.stream.flush().await.unwrap();
        let mut out = [0u8; 4];
        ps.stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn direct_uot_is_lazy_and_preserves_datagrams() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (lazy_tx, lazy_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0; 23];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[18], CMD_TCP);
            assert_eq!(&head[19..21], &[0, 0]);
            assert_eq!(head[21], ATYP_DOMAIN);
            assert_eq!(head[22] as usize, super::super::uot::MAGIC_ADDRESS.len());
            let mut magic = vec![0; head[22] as usize];
            stream.read_exact(&mut magic).await.unwrap();
            assert_eq!(magic, super::super::uot::MAGIC_ADDRESS.as_bytes());
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(20), stream.read_u8())
                    .await
                    .is_err(),
                "UoT setup must wait for the first datagram"
            );
            lazy_tx.send(()).unwrap();

            let mut request = [0; 8];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [1, ATYP_IPV4, 8, 8, 8, 8, 0, 53]);
            let mut packet = [0; 5];
            stream.read_exact(&mut packet).await.unwrap();
            assert_eq!(&packet, b"\0\x03dns");

            let mut response = vec![0, 0];
            response.extend_from_slice(
                &super::super::uot::encode_packet(b"first", super::super::uot::MAX_PACKET_SIZE)
                    .unwrap(),
            );
            response.extend_from_slice(
                &super::super::uot::encode_packet(b"second", super::super::uot::MAX_PACKET_SIZE)
                    .unwrap(),
            );
            stream.write_all(&response).await.unwrap();
        });

        let node = Node {
            name: "vless-uot".into(),
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            ..vless_node("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3", WireMode::UotV2)
        };
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let transport = VLessHandler::new()
            .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        lazy_rx.await.unwrap();
        assert_eq!(transport.relay_addr(), target);
        transport.send_packet_confirmed(b"dns").await.unwrap();

        let error = transport.recv_packet(&mut [0; 1]).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let mut output = [0; 8];
        assert_eq!(
            transport.recv_packet(&mut output).await.unwrap(),
            (5, target)
        );
        assert_eq!(&output[..5], b"first");
        assert_eq!(
            transport.recv_packet(&mut output).await.unwrap(),
            (6, target)
        );
        assert_eq!(&output[..6], b"second");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_mux_warm_dial_does_not_outlive_its_caller() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let node = Arc::new(Node {
            name: "vless-h2mux-cancel".into(),
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            ..vless_node("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3", WireMode::H2mux)
        });
        let pool = Arc::new(crate::session::SessionPool::new(
            super::super::vless_mux::session_pool_config(),
        ));
        let warming = {
            let pool = Arc::clone(&pool);
            tokio::spawn(VLessHandler::warm_mux_pool(
                pool,
                move || VLessHandler::dial_h2_session(node, std::time::Duration::from_secs(3)),
                "retired",
            ))
        };
        let (accepted, _) = listener.accept().await.unwrap();
        warming.abort();
        assert!(warming.await.unwrap_err().is_cancelled());

        let checkout = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            pool.checkout_speculative(),
        )
        .await
        .expect("cancelled warm dial retained the pool reservation")
        .unwrap();
        assert!(matches!(checkout, SpeculativeCheckout::Detached(_)));
        drop(accepted);
        pool.shutdown();
    }

    #[tokio::test]
    async fn h2mux_tcp_and_udp_share_one_vless_carrier() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0; 23];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[18], CMD_TCP);
            assert_eq!(&head[19..21], &444u16.to_be_bytes());
            assert_eq!(head[21], ATYP_DOMAIN);
            let mut domain = vec![0; head[22] as usize];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"sp.mux.sing-box.arpa");
            stream.write_all(&[0, 0]).await.unwrap();
            let mut mux = [0; 2];
            stream.read_exact(&mut mux).await.unwrap();
            assert_eq!(mux, [0, 2]);

            let mut connection = h2::server::handshake(stream).await.unwrap();
            let mut handlers = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                handlers.spawn(async move {
                    assert_eq!(request.method(), http::Method::CONNECT);
                    assert_eq!(request.uri().authority().unwrap().as_str(), "localhost");
                    let mut send = respond
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    let mut recv = request.into_body();
                    let mut body = bytes::BytesMut::new();
                    while body.len() < 9 {
                        let data = recv.data().await.unwrap().unwrap();
                        let size = data.len();
                        body.extend_from_slice(&data);
                        recv.flow_control().release_capacity(size).unwrap();
                    }
                    match u16::from_be_bytes([body[0], body[1]]) {
                        0 => {
                            assert_eq!(&body[2..9], &[1, 93, 184, 216, 34, 1, 187]);
                            send.send_data(bytes::Bytes::from_static(b"\0hello"), false)
                                .unwrap();
                            while body.len() < 13 {
                                let data = recv.data().await.unwrap().unwrap();
                                let size = data.len();
                                body.extend_from_slice(&data);
                                recv.flow_control().release_capacity(size).unwrap();
                            }
                            assert_eq!(&body[9..13], b"ping");
                            send.send_data(bytes::Bytes::from_static(b"pong"), true)
                                .unwrap();
                        }
                        1 => {
                            assert_eq!(&body[2..9], &[1, 8, 8, 8, 8, 0, 53]);
                            while body.len() < 14 {
                                let data = recv.data().await.unwrap().unwrap();
                                let size = data.len();
                                body.extend_from_slice(&data);
                                recv.flow_control().release_capacity(size).unwrap();
                            }
                            assert_eq!(&body[9..14], b"\0\x03dns");
                            let packet = super::super::uot::encode_packet(
                                b"answer",
                                super::super::uot::MAX_PACKET_SIZE,
                            )
                            .unwrap();
                            let mut response = bytes::BytesMut::with_capacity(1 + packet.len());
                            response.extend_from_slice(&[0]);
                            response.extend_from_slice(&packet);
                            send.send_data(response.freeze(), true).unwrap();
                        }
                        flags => panic!("unexpected mux flags {flags}"),
                    }
                });
            }
            while !handlers.is_empty() {
                tokio::select! {
                    result = handlers.join_next() => result.unwrap().unwrap(),
                    stream = connection.accept() => assert!(stream.is_none()),
                }
            }
            while connection.accept().await.is_some() {}
        });

        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "vless-h2mux".into(),
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            ..vless_node("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3", WireMode::H2mux)
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let registry = super::super::ProxyRegistry::default_resolver().unwrap();
        assert_eq!(
            registry
                .warm_session(
                    Arc::clone(&generation),
                    node.id,
                    std::time::Duration::from_secs(3),
                )
                .await
                .unwrap(),
            super::super::WarmOutcome::Ready
        );
        assert_eq!(
            registry
                .warm_udp(
                    Arc::clone(&generation),
                    node.id,
                    std::time::Duration::from_secs(3),
                )
                .await
                .unwrap(),
            super::super::WarmOutcome::Ready
        );
        let runtime = generation.get(&node.id).unwrap();
        let pool = runtime.vless_h2_pool().unwrap();
        assert_eq!(pool.live_session_count(), 1);
        let (replacement, moved) = crate::runtime::OutboundRuntimeRegistry::build_reusing(
            std::slice::from_ref(&node),
            8,
            Some(&generation),
        )
        .unwrap();
        assert!(moved.contains(&node.id));
        let replacement = Arc::new(replacement);
        generation.mark_moved_out(moved);
        generation.retire_reusable_state().await;
        generation.shutdown().await;
        assert_eq!(pool.live_session_count(), 1);
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut tcp = registry
            .dial_runtime(
                Arc::clone(&replacement),
                node.id,
                target,
                None,
                std::time::Duration::from_secs(3),
            )
            .await
            .unwrap();
        let mut greeting = [0; 5];
        tcp.stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"hello");
        tcp.stream.write_all(b"ping").await.unwrap();
        let mut pong = [0; 4];
        tcp.stream.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");

        let udp_target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let udp = registry
            .dial_udp_transport_runtime(
                Arc::clone(&replacement),
                node.id,
                udp_target,
                None,
                std::time::Duration::from_secs(3),
            )
            .await
            .unwrap();
        udp.send_packet_confirmed(b"dns").await.unwrap();
        let mut answer = [0; 16];
        assert_eq!(udp.recv_packet(&mut answer).await.unwrap(), (6, udp_target));
        assert_eq!(&answer[..6], b"answer");
        assert_eq!(pool.live_session_count(), 1);

        drop(udp);
        drop(tcp);
        runtime
            .release_warm(crate::runtime::WarmRetention::Selector)
            .await;
        assert!(pool.is_warm_retained());
        runtime
            .release_warm(crate::runtime::WarmRetention::Udp)
            .await;
        assert!(!pool.is_warm_retained());
        assert_eq!(pool.live_session_count(), 0);
        replacement.shutdown().await;
        server.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires the official sing-box and Xray executables"]
    async fn official_sing_box_and_xray_mux_interop() {
        async fn unused_port() -> u16 {
            tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        }

        async fn exercise(
            registry: &super::super::ProxyRegistry,
            mut node: Node,
            tcp_target: SocketAddr,
            udp_target: SocketAddr,
        ) {
            eprintln!("testing {}", node.name);
            node.id = node.derive_id();
            let generation = Arc::new(
                crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                    .unwrap(),
            );
            let timeout = std::time::Duration::from_secs(5);
            let mut tcp = registry
                .dial_runtime(Arc::clone(&generation), node.id, tcp_target, None, timeout)
                .await
                .unwrap();
            tcp.stream.write_all(node.name.as_bytes()).await.unwrap();
            let mut echoed = vec![0; node.name.len()];
            tcp.stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, node.name.as_bytes());

            let udp = registry
                .dial_udp_transport_runtime(
                    Arc::clone(&generation),
                    node.id,
                    udp_target,
                    None,
                    timeout,
                )
                .await
                .unwrap();
            udp.send_packet_confirmed(node.name.as_bytes())
                .await
                .unwrap();
            let mut echoed = [0; 64];
            let (size, peer) = udp.recv_packet(&mut echoed).await.unwrap();
            assert_eq!(peer, udp_target);
            assert_eq!(&echoed[..size], node.name.as_bytes());
            drop(udp);
            drop(tcp);
            generation.shutdown().await;
        }

        let tcp_echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_target = tcp_echo.local_addr().unwrap();
        let tcp_echo_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = tcp_echo.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buffer = [0; 1024];
                    loop {
                        let size = stream.read(&mut buffer).await.unwrap();
                        if size == 0 {
                            break;
                        }
                        stream.write_all(&buffer[..size]).await.unwrap();
                    }
                });
            }
        });
        let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_target = udp_echo.local_addr().unwrap();
        let udp_echo_task = tokio::spawn(async move {
            let mut buffer = [0; 65535];
            loop {
                let (size, peer) = udp_echo.recv_from(&mut buffer).await.unwrap();
                udp_echo.send_to(&buffer[..size], peer).await.unwrap();
            }
        });

        let plain_port = unused_port().await;
        let tls_port = unused_port().await;
        let reality_port = unused_port().await;
        let xray_port = unused_port().await;
        let xray_vision_port = unused_port().await;
        let directory = std::env::temp_dir().join(format!(
            "honk-vless-sing-box-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_path = directory.join("cert.pem");
        let key_path = directory.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        let config_path = directory.join("config.json");
        std::fs::write(
            &config_path,
            format!(
                r#"{{
  "log": {{ "level": "warn" }},
  "inbounds": [
    {{ "type": "vless", "tag": "plain", "listen": "127.0.0.1", "listen_port": {plain_port}, "users": [{{ "uuid": "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3" }}], "multiplex": {{ "enabled": true }} }},
    {{ "type": "vless", "tag": "tls", "listen": "127.0.0.1", "listen_port": {tls_port}, "users": [{{ "uuid": "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3" }}], "multiplex": {{ "enabled": true }}, "tls": {{ "enabled": true, "server_name": "localhost", "certificate_path": "{}", "key_path": "{}" }} }},
    {{ "type": "vless", "tag": "reality", "listen": "127.0.0.1", "listen_port": {reality_port}, "users": [{{ "uuid": "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3" }}], "multiplex": {{ "enabled": true }}, "tls": {{ "enabled": true, "server_name": "www.cloudflare.com", "reality": {{ "enabled": true, "handshake": {{ "server": "www.cloudflare.com", "server_port": 443 }}, "private_key": "GCrdIerhJnsv8UEGgVcP6Gpf_d13pziIcua09rRDqEA", "short_id": ["0123456789abcdef"] }} }} }}
  ],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
                cert_path.display(),
                key_path.display()
            ),
        )
        .unwrap();
        let xray_config_path = directory.join("xray.json");
        std::fs::write(
            &xray_config_path,
            format!(
                r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "tag": "vless",
    "listen": "127.0.0.1",
    "port": {xray_port},
    "protocol": "vless",
    "settings": {{ "clients": [{{ "id": "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3" }}], "decryption": "none" }},
    "streamSettings": {{ "network": "tcp", "security": "none" }}
  }}, {{
    "tag": "vless-vision",
    "listen": "127.0.0.1",
    "port": {xray_vision_port},
    "protocol": "vless",
    "settings": {{ "clients": [{{ "id": "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3", "flow": "xtls-rprx-vision" }}], "decryption": "none" }},
    "streamSettings": {{ "network": "tcp", "security": "tls", "tlsSettings": {{ "certificates": [{{ "certificateFile": "{}", "keyFile": "{}" }}] }} }}
  }}],
  "outbounds": [{{ "tag": "direct", "protocol": "freedom" }}]
}}"#,
                cert_path.display(),
                key_path.display()
            ),
        )
        .unwrap();
        let mut sing_box = tokio::process::Command::new("sing-box")
            .args(["run", "--disable-color", "-c"])
            .arg(&config_path)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut ready = false;
        for _ in 0..100 {
            assert!(sing_box.try_wait().unwrap().is_none(), "sing-box exited");
            if tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, plain_port))
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(ready, "sing-box did not bind its VLESS listeners");

        let registry = super::super::ProxyRegistry::default_resolver().unwrap();
        let mut base = vless_node("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3", WireMode::Legacy);
        base.host = "127.0.0.1".into();
        for (name, mode) in [
            ("uot-v2", WireMode::UotV2),
            ("xudp", WireMode::Xudp),
            ("h2mux", WireMode::H2mux),
            ("h2mux-padded", WireMode::H2muxPadded),
            ("mux-cool", WireMode::MuxCool),
        ] {
            let mut node = base.clone();
            node.name = name.into();
            node.address = format!("127.0.0.1:{plain_port}");
            node.port = plain_port;
            node.vless_mut().unwrap().mode = mode;
            exercise(&registry, node, tcp_target, udp_target).await;
        }

        let mut node = base.clone();
        node.name = "h2mux-tls".into();
        node.address = format!("127.0.0.1:{tls_port}");
        node.port = tls_port;
        node.vless_mut().unwrap().mode = WireMode::H2mux;
        let tls = node.tls_mut().unwrap();
        tls.enabled = true;
        tls.skip_cert_verify = true;
        tls.sni = Some("localhost".into());
        exercise(&registry, node, tcp_target, udp_target).await;

        let mut node = base.clone();
        node.name = "h2mux-reality".into();
        node.address = format!("127.0.0.1:{reality_port}");
        node.port = reality_port;
        node.vless_mut().unwrap().mode = WireMode::H2muxPadded;
        let tls = node.tls_mut().unwrap();
        tls.enabled = true;
        tls.sni = Some("www.cloudflare.com".into());
        tls.reality_public_key = Some("pYbbKZZ-9WsXODEENCcbisSN6ol6sx5GoVisiyN1oyo".into());
        tls.reality_short_id = Some("0123456789abcdef".into());
        tls.reality_spider_x = Some("/".into());
        exercise(&registry, node, tcp_target, udp_target).await;

        let xray_bin = std::env::var_os("HONK_XRAY_BIN").unwrap_or_else(|| "xray".into());
        let mut xray = tokio::process::Command::new(xray_bin)
            .args(["run", "-c"])
            .arg(&xray_config_path)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut ready = false;
        for _ in 0..100 {
            assert!(xray.try_wait().unwrap().is_none(), "Xray exited");
            if tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, xray_port))
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(ready, "Xray did not bind its VLESS listener");
        for (name, mode) in [
            ("xray-xudp", WireMode::Xudp),
            ("xray-mux-cool", WireMode::MuxCool),
        ] {
            let mut node = base.clone();
            node.name = name.into();
            node.address = format!("127.0.0.1:{xray_port}");
            node.port = xray_port;
            node.vless_mut().unwrap().mode = mode;
            exercise(&registry, node, tcp_target, udp_target).await;
        }

        let mut node = base.clone();
        node.name = "xray-xudp-vision".into();
        node.address = format!("127.0.0.1:{xray_vision_port}");
        node.port = xray_vision_port;
        let vless = node.vless_mut().unwrap();
        vless.mode = WireMode::Xudp;
        vless.flow = Some("xtls-rprx-vision".into());
        let tls = node.tls_mut().unwrap();
        tls.enabled = true;
        tls.skip_cert_verify = true;
        tls.sni = Some("localhost".into());
        exercise(&registry, node, tcp_target, udp_target).await;

        xray.start_kill().unwrap();
        xray.wait().await.unwrap();

        sing_box.start_kill().unwrap();
        sing_box.wait().await.unwrap();
        tcp_echo_task.abort();
        udp_echo_task.abort();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_vless_header_ipv4() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let header =
            VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, Some(target), None, None)
                .unwrap();

        // ver(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + atyp(1) + addr(4)
        assert_eq!(header.len(), 1 + 16 + 1 + 1 + 2 + 1 + 4);
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(&header[1..17], &uuid_bytes);
        assert_eq!(header[17], 0x00); // addon_len
        assert_eq!(header[18], CMD_TCP);
        assert_eq!(&header[19..21], &[0x00, 0x50]); // port 80
        assert_eq!(header[21], ATYP_IPV4);
        assert_eq!(&header[22..26], &[93, 184, 216, 34]);
    }

    #[test]
    fn test_vless_header_domain() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let domain = "example.com";

        let header = VLessHandler::build_request_header(
            &uuid_bytes,
            CMD_TCP,
            Some(target),
            Some(domain),
            None,
        )
        .unwrap();

        // ver(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + atyp(1) + domain_len(1) + domain(11)
        assert_eq!(header.len(), 1 + 16 + 1 + 1 + 2 + 1 + 1 + domain.len());
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(&header[1..17], &uuid_bytes);
        assert_eq!(header[17], 0x00); // addon_len
        assert_eq!(header[18], CMD_TCP);
        assert_eq!(&header[19..21], &[0x01, 0xbb]); // port 443
        assert_eq!(header[21], ATYP_DOMAIN);
        assert_eq!(header[22], domain.len() as u8);
        assert_eq!(&header[23..34], domain.as_bytes());
    }

    #[test]
    fn test_vless_header_ipv6() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "[::1]:1080".parse().unwrap();

        let header =
            VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, Some(target), None, None)
                .unwrap();

        // ver(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + atyp(1) + addr(16)
        assert_eq!(header.len(), 1 + 16 + 1 + 1 + 2 + 1 + 16);
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(&header[1..17], &uuid_bytes);
        assert_eq!(header[17], 0x00); // addon_len
        assert_eq!(header[18], CMD_TCP);
        assert_eq!(&header[19..21], &[0x04, 0x38]); // port 1080
        assert_eq!(header[21], ATYP_IPV6);
        // IPv6 ::1 = 15 bytes of 0x00 then 0x01
        assert_eq!(&header[22..37], &[0u8; 15]);
        assert_eq!(header[37], 0x01);
    }

    #[test]
    fn vless_mux_command_carries_no_target() {
        let uuid = VLessHandler::parse_uuid("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3").unwrap();
        let header = VLessHandler::build_request_header(
            &uuid,
            super::super::vless_cool::VLESS_MUX_COMMAND,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(header.len(), 19);
        assert_eq!(header[18], super::super::vless_cool::VLESS_MUX_COMMAND);

        let target = Some("127.0.0.1:9527".parse().unwrap());
        assert!(
            VLessHandler::build_request_header(
                &uuid,
                super::super::vless_cool::VLESS_MUX_COMMAND,
                target,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn test_vless_header_vision_flow() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let header = VLessHandler::build_request_header(
            &uuid_bytes,
            CMD_TCP,
            Some(target),
            None,
            Some("xtls-rprx-vision"),
        )
        .unwrap();

        // ver(1) + uuid(16) + addon_len(1) + addon(18) + cmd(1) + port(2) + atyp(1) + addr(4)
        assert_eq!(header.len(), 1 + 16 + 1 + 18 + 1 + 2 + 1 + 4);
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(&header[1..17], &uuid_bytes);
        assert_eq!(header[17], 18); // addon_len: 0x0A + len + 16-byte flow
        // Xray encoding.Addons protobuf: field 1 (Flow) = tag 0x0A, length 0x10
        assert_eq!(&header[18..36], b"\x0a\x10xtls-rprx-vision");
        assert_eq!(header[36], CMD_TCP);
        assert_eq!(&header[37..39], &[0x01, 0xbb]); // port 443
        assert_eq!(header[39], ATYP_IPV4);
        assert_eq!(&header[40..44], &[93, 184, 216, 34]);
    }

    #[test]
    fn test_vless_header_rejects_unsupported_flow_and_long_domain() {
        let uuid_bytes = VLessHandler::parse_uuid("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3").unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let flow_error = VLessHandler::build_request_header(
            &uuid_bytes,
            CMD_TCP,
            Some(target),
            None,
            Some("unsupported"),
        )
        .unwrap_err();
        assert_eq!(flow_error.to_string(), "VLESS: unsupported flow");

        let long_domain = "a".repeat(256);
        let domain_error = VLessHandler::build_request_header(
            &uuid_bytes,
            CMD_TCP,
            Some(target),
            Some(&long_domain),
            None,
        )
        .unwrap_err();
        assert_eq!(
            domain_error.to_string(),
            "VLESS: target domain exceeds 255 bytes"
        );

        let empty_flow =
            VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, Some(target), None, Some(""))
                .unwrap();
        assert_eq!(empty_flow[17], 0);
    }

    #[test]
    fn test_parse_uuid_valid() {
        let result = VLessHandler::parse_uuid("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_parse_uuid_invalid() {
        let result = VLessHandler::parse_uuid("not-a-uuid");
        assert!(result.is_err());
    }

    /// End-to-end over the WebSocket transport: a mock WS server receives
    /// the VLESS request header as the first binary message, replies with
    /// the 1-byte acceptance, and then sees relayed payload.
    #[tokio::test]
    async fn test_vless_dial_over_ws() {
        use futures_util::{SinkExt, StreamExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            // First binary message carries the VLESS request header,
            // possibly coalesced with the first payload bytes (nothing
            // forces a read between the two writes anymore).
            let msg = ws.next().await.unwrap().unwrap();
            let data = msg.into_data();
            assert_eq!(data[0], VLESS_VERSION);
            let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
            assert_eq!(&data[1..17], &uuid_bytes);
            assert_eq!(data[18], CMD_TCP);

            // Accept with the 2-byte response header (version + addon_len=0),
            // then expect relayed payload.
            ws.send(tokio_tungstenite::tungstenite::Message::Binary(
                vec![0x00, 0x00].into(),
            ))
            .await
            .unwrap();
            const HEADER_LEN: usize = 1 + 16 + 1 + 1 + 2 + 1 + 4;
            if data.len() > HEADER_LEN {
                assert_eq!(&data[HEADER_LEN..], b"ping");
            } else {
                let msg = ws.next().await.unwrap().unwrap();
                assert_eq!(&msg.into_data()[..], b"ping");
            }
        });

        let node = Node {
            name: "vless-ws".into(),
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
                uuid: Some(uuid_str.into()),
                transport: honk_config::node::StreamTransportOptions {
                    transport: "ws".into(),
                    ws_path: Some("/vless".into()),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let mut ps = VLessHandler::new()
            .dial(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        ps.stream.write_all(b"ping").await.unwrap();
        ps.stream.flush().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    /// Bare VLESS over raw TCP (`security=none`): `node.tls` false and an
    /// empty transport must not be TLS-wrapped. The lazy response stripper
    /// still wraps the stream (bare servers piggyback the response header
    /// too), so it no longer downcasts to a plain TcpStream.
    #[tokio::test]
    async fn test_vless_dial_bare_tcp() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 19];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], VLESS_VERSION);
            let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
            assert_eq!(&head[1..17], &uuid_bytes);
            assert_eq!(head[17], 0x00); // addon_len
            assert_eq!(head[18], CMD_TCP);
            // Skip port(2) + atyp(1) + ipv4(4), accept, expect payload.
            let mut addr = [0u8; 7];
            stream.read_exact(&mut addr).await.unwrap();
            stream.write_all(&[0x00, 0x00]).await.unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
        });

        let node = Node {
            name: "vless-bare".into(),
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            ..vless_node(uuid_str, WireMode::Legacy)
        };
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let mut ps = VLessHandler::new()
            .dial(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        ps.stream.write_all(b"ping").await.unwrap();
        ps.stream.flush().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    /// xtls-rprx-vision over raw TCP: the mock server asserts the full
    /// request header including the protobuf flow addon.
    #[tokio::test]
    async fn test_vless_dial_vision_flow() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // ver(1) + uuid(16) + addon_len(1) + addon(18) + cmd(1)
            let mut head = [0u8; 37];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], VLESS_VERSION);
            let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
            assert_eq!(&head[1..17], &uuid_bytes);
            assert_eq!(head[17], 18);
            assert_eq!(&head[18..36], b"\x0a\x10xtls-rprx-vision");
            assert_eq!(head[36], CMD_TCP);
            let mut addr = [0u8; 7];
            stream.read_exact(&mut addr).await.unwrap();
            stream.write_all(&[0x00, 0x00]).await.unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
        });

        let node = Node {
            name: "vless-vision".into(),
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
                uuid: Some(uuid_str.into()),
                flow: Some("xtls-rprx-vision".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let mut ps = VLessHandler::new()
            .dial(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        ps.stream.write_all(b"ping").await.unwrap();
        ps.stream.flush().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}
