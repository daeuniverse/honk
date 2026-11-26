use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::proxy::chain::native_udp_writer_handoff;
use crate::proxy::uot::{AddrDecoder, AddrFraming, Decoder, MAX_PACKET_SIZE};
use crate::proxy::vless::cool;
use crate::proxy::{AsyncReadWrite, FramePoison, MultiTargetTransport, PacketTransport};

type Reader = tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>;

struct VlessPacketWriter {
    stream: tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>,
    /// UoT request, sent in front of the first datagram.
    setup: Option<bytes::Bytes>,
}

impl VlessPacketWriter {
    /// A partially written frame cannot be resumed, so an interrupted write
    /// poisons the stream. `observed` publishes the sending flow's first
    /// request milestone once the frame is delivered; `admitted` is set when
    /// the frame starts onto the wire.
    async fn write_frame(
        &mut self,
        poison: &FramePoison,
        frame: &[u8],
        observed: bool,
        admitted: Option<&AtomicBool>,
    ) -> std::io::Result<()> {
        let write = poison.begin(admitted)?;
        let stream = &mut self.stream;
        let write_all = async {
            stream.write_all(frame).await?;
            stream.flush().await
        };
        if observed {
            crate::runtime::flow_observation::request_write(std::pin::pin!(write_all)).await?;
        } else {
            write_all.await?;
        }
        self.setup = None;
        write.complete();
        Ok(())
    }
}

async fn read_chunk(stream: &mut Reader, chunk: &mut [u8]) -> std::io::Result<usize> {
    let size = stream.read(chunk).await?;
    if size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "VLESS packet stream closed",
        ));
    }
    Ok(size)
}

/// Native command-UDP: one fixed target, bare `[u16 length][payload]` frames.
pub(super) struct VlessConnectedTransport {
    reader: tokio::sync::Mutex<(Reader, Decoder)>,
    writer: tokio::sync::Mutex<VlessPacketWriter>,
    poison: FramePoison,
    target: SocketAddr,
    tls_handoff: Option<bool>,
}

impl VlessConnectedTransport {
    pub(super) fn new(
        stream: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        tls_handoff: Option<bool>,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: tokio::sync::Mutex::new((reader, Decoder::default())),
            writer: tokio::sync::Mutex::new(VlessPacketWriter {
                stream: writer,
                setup: None,
            }),
            poison: FramePoison::default(),
            target,
            tls_handoff,
        }
    }

    async fn send(
        &self,
        data: &[u8],
        current: Option<&(dyn Fn() -> bool + Send + Sync)>,
    ) -> std::io::Result<()> {
        if data.is_empty() || data.len() > MAX_NATIVE_PACKET_SIZE {
            return Err(crate::proxy::PacketRejection::InvalidSize.into());
        }
        let packet = crate::proxy::uot::encode_packet(data, MAX_PACKET_SIZE)?;
        let mut writer = self.writer.lock().await;
        if let Some(current) = current {
            let tls_handoff = self
                .tls_handoff
                .ok_or(crate::proxy::PacketRejection::Policy)?;
            return self
                .poison
                .write_checked(&mut writer.stream, &packet, None, tls_handoff, current)
                .await;
        }
        writer.write_frame(&self.poison, &packet, false, None).await
    }
}

impl std::fmt::Debug for VlessConnectedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessConnectedTransport")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PacketTransport for VlessConnectedTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send(data, None).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.send(data, None).await
    }

    async fn send_packet_checked(
        &self,
        data: &[u8],
        current: &(dyn Fn() -> bool + Send + Sync),
    ) -> std::io::Result<()> {
        self.send(data, Some(current)).await
    }

    async fn recv_packet(&self, output: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        let (stream, decoder) = &mut *reader;
        loop {
            if let Some(size) = decoder.next_packet(output)? {
                return Ok((size, self.target));
            }
            let mut chunk = [0; 16 * 1024];
            let size = read_chunk(stream, &mut chunk).await?;
            decoder.push(&chunk[..size])?;
        }
    }
}

/// Non-connect UoT v2 over a VLESS TCP command stream: the request names the
/// first destination, then every datagram in both directions carries its own
/// address, so one stream serves all destinations of a client source and
/// replies keep their real source. The request and first datagram share one
/// write; the open-time target is the default for ordinary sends and the only
/// domain a reply source may project back to.
pub(crate) struct VlessUotTransport {
    reader: tokio::sync::Mutex<(Reader, AddrDecoder)>,
    writer: tokio::sync::Mutex<VlessPacketWriter>,
    poison: FramePoison,
    target: SocketAddr,
    target_domain: Option<Box<str>>,
    tls_handoff: Option<bool>,
}

impl VlessUotTransport {
    pub(super) fn new(
        stream: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        request: bytes::Bytes,
        tls_handoff: Option<bool>,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: tokio::sync::Mutex::new((reader, AddrDecoder::new(AddrFraming::UOT_V1))),
            writer: tokio::sync::Mutex::new(VlessPacketWriter {
                stream: writer,
                setup: Some(request),
            }),
            poison: FramePoison::default(),
            target,
            target_domain: target_domain.map(Box::from),
            tls_handoff,
        }
    }

    /// All sends serialize here so a withdrawn first send leaves setup for the next view.
    async fn send_inner(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
        current: Option<&(dyn Fn() -> bool + Send + Sync)>,
    ) -> std::io::Result<()> {
        let mut writer = self.writer.lock().await;
        let frame = AddrFraming::UOT_V1.encode(
            writer.setup.as_deref().unwrap_or_default(),
            target,
            domain,
            data,
            MAX_PACKET_SIZE,
        )?;
        if let Some(current) = current {
            let tls_handoff = self
                .tls_handoff
                .ok_or(crate::proxy::PacketRejection::Policy)?;
            let write = self.poison.write_checked(
                &mut writer.stream,
                &frame,
                admitted,
                tls_handoff,
                current,
            );
            crate::runtime::flow_observation::request_write(std::pin::pin!(write)).await?;
            writer.setup = None;
            return Ok(());
        }
        writer
            .write_frame(&self.poison, &frame, confirmed, admitted)
            .await
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

    fn allows_full_cone_replies(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_inner(
            self.target,
            self.target_domain.as_deref(),
            data,
            false,
            None,
            None,
        )
        .await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_inner(
            self.target,
            self.target_domain.as_deref(),
            data,
            true,
            None,
            None,
        )
        .await
    }

    async fn recv_packet(&self, output: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        let (stream, decoder) = &mut *reader;
        loop {
            if let Some(frame) =
                decoder.next_packet(output, self.target, self.target_domain.as_deref())?
            {
                match frame.packet {
                    Some(packet) => return Ok(packet),
                    None => continue,
                }
            }
            let mut chunk = [0; 16 * 1024];
            let size = read_chunk(stream, &mut chunk).await?;
            decoder.push(&chunk[..size])?;
        }
    }
}

#[async_trait]
impl MultiTargetTransport for VlessUotTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> std::io::Result<()> {
        let domain = crate::proxy::addr::dialed_name(self.target_domain.as_deref(), domain);
        self.send_inner(target, domain, data, confirmed, admitted, None)
            .await
    }

    async fn send_to_checked(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        admitted: Option<&AtomicBool>,
        current: &(dyn Fn() -> bool + Send + Sync),
    ) -> std::io::Result<()> {
        let domain = crate::proxy::addr::dialed_name(self.target_domain.as_deref(), domain);
        self.send_inner(target, domain, data, true, admitted, Some(current))
            .await
    }

    fn frame_stream_torn(&self) -> bool {
        self.poison.is_set()
    }
}

impl VLessHandler {
    /// Non-connect UoT v2 over the retained carrier. Nothing is published
    /// until the returned preparation commits.
    pub(super) async fn prepare_uot_transport(
        &self,
        runtime: &Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(
        Arc<VlessUotTransport>,
        crate::proxy::transport::TransportPreparation,
    )> {
        let vless = runtime.node.vless().unwrap();
        let uuid = Self::parse_uuid(vless.uuid.as_deref().unwrap_or(""))?;
        let header = Self::build_request_header(
            &uuid,
            CMD_TCP,
            Some(SocketAddr::from(([0, 0, 0, 0], 0))),
            Some(crate::proxy::uot::MAGIC_ADDRESS),
            vless.wire_flow(),
        )?;
        let request = crate::proxy::uot::request(false, target, domain)?;
        let (stream, preparation) = self
            .prepare_retained_carrier(runtime, uuid, header, timeout)
            .await?;
        Ok((
            Arc::new(VlessUotTransport::new(
                stream,
                target,
                domain,
                request,
                native_udp_writer_handoff(&runtime.node),
            )),
            preparation,
        ))
    }

    pub(super) async fn prepare_protocol_udp(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        path: VlessUdpPath,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let vless = runtime.node.vless().unwrap();
        let uuid = Self::parse_uuid(vless.uuid.as_deref().unwrap_or(""))?;
        let (command, header_target, header_domain) = match path {
            VlessUdpPath::Native => (CMD_UDP, Some(target), domain),
            VlessUdpPath::Xudp => (cool::VLESS_MUX_COMMAND, None, None),
            _ => unreachable!("protocol UDP preparation excludes UoT and pooled mux paths"),
        };
        let header = Self::build_request_header(
            &uuid,
            command,
            header_target,
            header_domain,
            vless.wire_flow(),
        )?;
        let operation = self.prepare_retained_carrier(&runtime, uuid, header, timeout);
        let (stream, preparation) = if path == VlessUdpPath::Native {
            crate::runtime::flow_observation::request_write(std::pin::pin!(operation)).await?
        } else {
            operation.await?
        };
        let transport: Arc<dyn PacketTransport> = if path == VlessUdpPath::Xudp {
            cool::connect_single_xudp(stream, target, domain, [0; 8]).await?
        } else {
            Arc::new(VlessConnectedTransport::new(
                stream,
                target,
                native_udp_writer_handoff(&runtime.node),
            ))
        };
        Ok(publish_on_commit(transport, preparation))
    }

    async fn prepare_mux_udp<S, T, Dial, DialFuture, Open, OpenFuture>(
        pool: Arc<crate::session::SessionPool<S>>,
        dial: Dial,
        open: Open,
        retired_error: &'static str,
    ) -> anyhow::Result<PreparedUdpTransport<T>>
    where
        S: MuxSession,
        T: PacketTransport + ?Sized + 'static,
        Dial: FnOnce() -> DialFuture + Send,
        DialFuture: Future<Output = anyhow::Result<(Arc<S>, crate::proxy::transport::TransportPreparation)>>
            + Send,
        Open: Fn(Arc<S>, crate::session::SessionPermit<S>) -> OpenFuture + Send,
        OpenFuture: Future<Output = Result<Arc<T>, OpenError>> + Send,
    {
        let mut dial = Some(dial);
        let mut last_error = None;
        for _ in 0..2 {
            match pool.checkout_speculative().await? {
                SpeculativeCheckout::Shared { session, permit } => {
                    let observation = crate::session::ObservedSessionOpen::start();
                    let result = open(Arc::clone(&session), permit).await;
                    observation.finish_open(&result);
                    match result {
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
                    let (session, preparation) = tokio::select! {
                        result = dial() => result?,
                        _ = reservation.cancelled() => anyhow::bail!(retired_error),
                    };
                    let permit = reservation.attach(&session)?;
                    let observation = crate::session::ObservedSessionOpen::start();
                    let result = open(session, permit).await;
                    observation.finish_open(&result);
                    let transport = result.map_err(Self::open_error)?;
                    return Ok(PreparedUdpTransport::new(async move {
                        preparation.commit()?;
                        // Mux rejection may leave valid warm carriers in the capped XHTTP pool.
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
        // This large cold handshake must not inflate each task-scope poll frame.
        runtime
            .scope_tasks(Box::pin(async {
                match Self::udp_path(&runtime.node, target.port())? {
                    VlessUdpPath::Xudp => {
                        let (stream, preparation) = Self::new()
                            .prepare_retained_mux_carrier(&runtime, timeout)
                            .await?;
                        let transport =
                            cool::connect_single_xudp(stream, target, domain, global_id).await?;
                        Ok(publish_on_commit(transport, preparation))
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
                            move || Self::prepare_cool_session(dial_runtime, active_limit, timeout),
                            move |session, permit| {
                                cool::open_xudp(session, permit, target, domain, global_id)
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
                        Err(crate::proxy::PacketRejection::Policy.into())
                    }
                }
            }))
            .await
    }

    /// Prepare the one UoT v2 / H2MUX PacketAddr association of a client
    /// source scope. Retained carriers and pooled H2 sessions follow the same
    /// commit-only publication as [`Self::prepare_source_udp`]; the explicit
    /// paths carry no VLESS-only empty-first or poisoned-child rules.
    pub async fn prepare_shared_udp(
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        runtime
            .scope_tasks(Box::pin(async {
                match Self::udp_path(&runtime.node, target.port())? {
                    VlessUdpPath::UotV2 => {
                        let (transport, preparation) = Self::new()
                            .prepare_uot_transport(&runtime, target, domain, timeout)
                            .await?;
                        Ok(publish_on_commit(
                            transport as Arc<dyn MultiTargetTransport>,
                            preparation,
                        ))
                    }
                    VlessUdpPath::H2 => {
                        let pool = runtime.vless_h2_pool()?;
                        let dial_runtime = Arc::clone(&runtime);
                        Self::prepare_mux_udp(
                            pool,
                            move || Self::prepare_h2_session(dial_runtime, timeout),
                            move |session, permit| async move {
                                let transport: Arc<dyn MultiTargetTransport> =
                                    session.open_packet(permit, target, domain).await?;
                                Ok(transport)
                            },
                            "VLESS H2 pool retired during source preparation",
                        )
                        .await
                    }
                    VlessUdpPath::Native
                    | VlessUdpPath::Xudp
                    | VlessUdpPath::CoolShared
                    | VlessUdpPath::CoolSeparate => {
                        Err(crate::proxy::PacketRejection::Policy.into())
                    }
                }
            }))
            .await
    }
}

#[async_trait]
impl SharedSourceOutbound for VLessHandler {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        let _ = speculative;
        Self::prepare_shared_udp(runtime, target, target_domain, connect_timeout).await
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
        Ok(crate::proxy::packet_transport_with_owner(transport, owner))
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

    /// Native UDP only: XUDP and the multiplexed paths need sessions owned
    /// by this node's runtime, which a tunneled hop does not dial.
    async fn dial_udp_over(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        options: crate::proxy::TunnelDialOptions,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        if !runtime.node.supports_tunneled_udp() {
            return Err(crate::proxy::TunnelUnsupported("vless udp").into());
        }
        let stream = Self::start_tunneled(
            &runtime.node,
            carrier,
            CMD_UDP,
            target,
            target_domain,
            options,
        )
        .await?;
        let stream = crate::proxy::chain::locate_udp_exit_stream(stream);
        let tls_handoff = crate::proxy::chain::UDP_EXIT_HOP
            .try_with(|exit| exit.tls_handoff)
            .ok();
        Ok(Arc::new(VlessConnectedTransport::new(
            stream,
            target,
            tls_handoff,
        )))
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
                    move || Self::prepare_h2_session(dial_runtime, connect_timeout),
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
                    move || Self::prepare_cool_session(dial_runtime, active_limit, connect_timeout),
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
            VlessUdpPath::UotV2 => {
                let (transport, preparation) = self
                    .prepare_uot_transport(&runtime, target, target_domain, connect_timeout)
                    .await?;
                Ok(publish_on_commit(
                    transport as Arc<dyn PacketTransport>,
                    preparation,
                ))
            }
            VlessUdpPath::Native | VlessUdpPath::Xudp => {
                self.prepare_protocol_udp(runtime, path, target, target_domain, connect_timeout)
                    .await
            }
        }
    }
}
