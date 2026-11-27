use super::{Session, VmessHandler, VmessStream, uuid};
use crate::proxy::uot::{self, StreamUotTransport};
use crate::proxy::{
    AsyncReadWrite, MultiTargetTransport, PacketOutbound, PacketRejection, PacketTransport,
    PreparedUdpTransport, SharedSourceOutbound, TunnelDialOptions, TunnelUnsupported, chain,
    transport,
};
use crate::runtime::NodeRuntime;
use async_trait::async_trait;
use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

impl VmessStream {
    pub(super) fn start_uot(
        stream: Box<dyn AsyncReadWrite>,
        request: (Vec<u8>, Session),
        gate: Option<oneshot::Receiver<()>>,
    ) -> anyhow::Result<Self> {
        Self::spawn(stream, request, Some(Box::default()), gate)
    }

    pub(super) fn commit_uot(
        carrier: Box<dyn AsyncReadWrite>,
        header: (Vec<u8>, Session),
        publish: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        let (start, gate) = oneshot::channel();
        let stream = Self::start_uot(carrier, header, Some(gate))?;
        if start.is_closed() {
            return Err(PacketRejection::Cancelled.into());
        }
        publish()?;
        start.send(()).map_err(|_| PacketRejection::Cancelled)?;
        Ok(stream)
    }
}

impl VmessHandler {
    fn uot_header(node: &Node, ambiguous_header_io: bool) -> anyhow::Result<(Vec<u8>, Session)> {
        Self::request_header(
            uuid(node)?.as_bytes(),
            SocketAddr::from(([0; 4], 0)),
            Some(uot::MAGIC_ADDRESS),
            ambiguous_header_io,
        )
    }

    async fn prepare_uot_stream<T: ?Sized + Send + Sync + 'static>(
        node: &Node,
        runtime: Option<&Arc<NodeRuntime>>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: Duration,
        project: fn(Arc<StreamUotTransport>) -> Arc<T>,
    ) -> anyhow::Result<PreparedUdpTransport<T>> {
        anyhow::ensure!(
            node.vmess().unwrap().udp_enabled(),
            "UDP not supported for this VMess node"
        );
        let header = Self::uot_header(node, false)?;
        let request = uot::request(false, target, domain)?;
        let (carrier, preparation) =
            transport::prepare_transport(node, runtime, None, timeout).await?;
        let handoff = chain::native_udp_writer_handoff(node);
        let domain = domain.map(Box::<str>::from);
        Ok(PreparedUdpTransport::new(async move {
            let stream = VmessStream::commit_uot(carrier, header, || preparation.commit())?;
            Ok(project(Arc::new(StreamUotTransport::new(
                Box::new(stream),
                target,
                domain,
                request,
                handoff,
                None,
            ))))
        }))
    }

    async fn open_uot_over(
        node: &Node,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<Arc<StreamUotTransport>> {
        if !node.supports_tunneled_udp() {
            return Err(TunnelUnsupported("vmess udp").into());
        }
        let header = Self::uot_header(node, true)?;
        let request = uot::request(false, target, domain)?;
        let carrier = transport::wrap_tunnel(node, carrier, options).await?;
        let exit = chain::UDP_EXIT_HOP.try_with(|exit| *exit).ok();
        let stream = VmessStream::start_uot(carrier, header, None)?;
        let stream = chain::locate_udp_exit_stream(Box::new(stream));
        Ok(Arc::new(StreamUotTransport::new(
            stream,
            target,
            domain.map(Box::from),
            request,
            None,
            exit,
        )))
    }
}

#[async_trait]
impl PacketOutbound for VmessHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::prepare_uot_stream(node, None, target, domain, timeout, |t| {
            t as Arc<dyn PacketTransport>
        })
        .await?
        .commit()
        .await
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_udp_transport_speculative_runtime(runtime, target, domain, timeout)
            .await?
            .commit()
            .await
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        Self::prepare_uot_stream(
            &runtime.node,
            Some(&runtime),
            target,
            domain,
            timeout,
            |t| t as Arc<dyn PacketTransport>,
        )
        .await
    }

    async fn dial_udp_over(
        &self,
        runtime: Arc<NodeRuntime>,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Ok(Self::open_uot_over(&runtime.node, carrier, target, domain, options).await?)
    }
}

#[async_trait]
impl SharedSourceOutbound for VmessHandler {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: Duration,
        _speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        Self::prepare_uot_stream(
            &runtime.node,
            Some(&runtime),
            target,
            domain,
            timeout,
            |t| t as Arc<dyn MultiTargetTransport>,
        )
        .await
    }

    async fn prepare_shared_source_over(
        &self,
        runtime: Arc<NodeRuntime>,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<Arc<dyn MultiTargetTransport>> {
        Ok(Self::open_uot_over(&runtime.node, carrier, target, domain, options).await?)
    }
}
