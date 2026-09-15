use crate::control::udp_endpoint::UdpEndpointPool;
use crate::control::{ControlPlane, ControlPlaneHandle};
use crate::dns::{self, DnsResolver};
use crate::ebpf::mock::MockEbpfBackend;
use crate::proxy::ProxyRegistry;
use crate::routing::Router;
use crate::stats::StatsManager;
use honk_config::Config;
use honk_config::node::{Group, GroupPolicy, Node, OutboundConfig};
use honk_config::types::NodeProtocol;
#[cfg(feature = "ebpf")]
use honk_ebpf_common::DAE_BYPASS_MARK;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

/// A minimal DNS query payload for "a.com" (A record).
pub(in crate::control) fn dns_query_payload() -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q.extend_from_slice(&[
        0x01, b'a', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]);
    q
}

pub(in crate::control) fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: the returned slice borrows `value` and has its exact layout size.
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}
pub(in crate::control) type CapturedTcpTarget =
    Arc<std::sync::Mutex<Option<(SocketAddr, Option<String>)>>>;

#[derive(Debug, Clone)]
pub(in crate::control) enum UdpTestMode {
    #[cfg(feature = "ebpf")]
    TcpConnect,
    DialError,
    SendError,
    /// Records real application-send attempts made by the production
    /// PacketTransport call path.
    CountSends(Arc<std::sync::atomic::AtomicUsize>),
    /// Counts dial and send attempts while making the first application send
    /// ambiguous. A later candidate must never be tried after that send.
    CountFirstSendError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    CountDialAndSend {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    CountDialError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    PreparedCommitError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        commits: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    PreparedCommitHold {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        commits: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    Success,
    DnsResponse {
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    DnsResponseCaptureTarget(Arc<parking_lot::Mutex<Option<SocketAddr>>>),
    #[cfg(feature = "ebpf")]
    KernelSocket(Arc<UdpSocket>),
    TcpHold {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    TcpCaptureTarget(CapturedTcpTarget),
    UdpCaptureTarget(CapturedTcpTarget),
    Hold {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    HoldAndCount {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    HoldAndCountDialAndSend {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
}

#[derive(Debug)]
struct UdpTestTransport {
    mode: UdpTestMode,
    relay: SocketAddr,
    replied: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketTransport for UdpTestTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    async fn send_packet(&self, _data: &[u8]) -> std::io::Result<()> {
        match &self.mode {
            UdpTestMode::SendError => Err(std::io::Error::other("first UDP send failed")),
            UdpTestMode::CountSends(sends) => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            UdpTestMode::CountFirstSendError { sends, .. } => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(std::io::Error::other("ambiguous first UDP send failure"))
            }
            UdpTestMode::CountDialAndSend { sends, .. }
            | UdpTestMode::HoldAndCountDialAndSend { sends, .. }
            | UdpTestMode::PreparedCommitError { sends, .. }
            | UdpTestMode::PreparedCommitHold { sends, .. } => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            #[cfg(feature = "ebpf")]
            UdpTestMode::KernelSocket(socket) => {
                socket.send_to(_data, self.relay).await?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        #[cfg(feature = "ebpf")]
        if let UdpTestMode::KernelSocket(socket) = &self.mode {
            let (size, _) = socket.recv_from(buf).await?;
            return Ok((size, self.relay));
        }
        if matches!(
            self.mode,
            UdpTestMode::DnsResponse { .. } | UdpTestMode::DnsResponseCaptureTarget(_)
        ) && !self
            .replied
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            let response = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
            buf[..response.len()].copy_from_slice(&response);
            return Ok((response.len(), self.relay));
        }
        if matches!(
            self.mode,
            UdpTestMode::DnsResponse { .. } | UdpTestMode::DnsResponseCaptureTarget(_)
        ) {
            return std::future::pending().await;
        }
        Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    }
}

#[derive(Debug)]
pub(in crate::control) struct UdpTestReplySocketFactory;

impl crate::control::udp_endpoint::UdpReplySocketFactory for UdpTestReplySocketFactory {
    fn create(&self, _original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }
}

#[cfg(feature = "ebpf")]
#[derive(Debug)]
pub(super) struct KernelUdpReplySocketFactory;

#[cfg(feature = "ebpf")]
impl crate::control::udp_endpoint::UdpReplySocketFactory for KernelUdpReplySocketFactory {
    fn create(&self, original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        let domain = if original_dst.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        if original_dst.is_ipv4() {
            socket.set_ip_transparent_v4(true)?;
        } else {
            socket.set_ip_transparent_v6(true)?;
        }
        socket.set_mark(DAE_BYPASS_MARK)?;
        socket.bind(&original_dst.into())?;
        UdpSocket::from_std(socket.into())
    }
}

#[derive(Debug)]
pub(super) struct FailingUdpTestReplySocketFactory;

impl crate::control::udp_endpoint::UdpReplySocketFactory for FailingUdpTestReplySocketFactory {
    fn create(&self, _original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        Err(std::io::Error::other("scripted anyfrom setup failure"))
    }
}

#[derive(Debug)]
pub(in crate::control) struct UdpTestHandler {
    pub(in crate::control) mode: UdpTestMode,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for UdpTestHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        match &self.mode {
            #[cfg(feature = "ebpf")]
            UdpTestMode::TcpConnect => {}
            UdpTestMode::TcpHold { entered, release } => {
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::TcpCaptureTarget(captured) => {
                *captured.lock().expect("dial target") =
                    Some((target, target_domain.map(str::to_owned)));
            }
            _ => anyhow::bail!("TCP dial is not used by the UDP lifecycle tests"),
        }
        let stream = TcpStream::connect(target).await?;
        Ok(honk_outbound::proxy::ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketOutbound for UdpTestHandler {
    async fn dial_udp_transport(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn honk_outbound::proxy::PacketTransport>> {
        if let UdpTestMode::DnsResponseCaptureTarget(captured) = &self.mode {
            *captured.lock() = Some(target);
        }
        if let UdpTestMode::UdpCaptureTarget(captured) = &self.mode {
            *captured.lock().expect("UDP dial target") =
                Some((target, target_domain.map(str::to_owned)));
        }
        match &self.mode {
            UdpTestMode::Hold { entered, release } => {
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::HoldAndCount {
                entered,
                release,
                dials,
            } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::CountFirstSendError { dials, .. }
            | UdpTestMode::CountDialAndSend { dials, .. }
            | UdpTestMode::CountDialError { dials }
            | UdpTestMode::PreparedCommitError { dials, .. }
            | UdpTestMode::PreparedCommitHold { dials, .. } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            UdpTestMode::HoldAndCountDialAndSend {
                entered,
                release,
                dials,
                ..
            } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::DnsResponse { dials } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
        match &self.mode {
            UdpTestMode::DialError | UdpTestMode::CountDialError { .. } => {
                Err(anyhow::anyhow!("UDP dial failed"))
            }
            _ => Ok(Arc::new(UdpTestTransport {
                mode: self.mode.clone(),
                relay: target,
                replied: std::sync::atomic::AtomicBool::new(false),
            })),
        }
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<honk_outbound::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::PreparedUdpTransport> {
        let transport = self
            .dial_udp_transport(
                runtime.node.as_ref(),
                target,
                target_domain,
                connect_timeout,
            )
            .await?;
        if let UdpTestMode::PreparedCommitError { commits, .. } = &self.mode {
            let commits = Arc::clone(commits);
            return Ok(honk_outbound::proxy::PreparedUdpTransport::new(
                async move {
                    let _transport = transport;
                    commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Err(anyhow::anyhow!(
                        "scripted prepared transport commit failure"
                    ))
                },
            ));
        }
        if let UdpTestMode::PreparedCommitHold {
            commits,
            entered,
            release,
            ..
        } = &self.mode
        {
            let commits = Arc::clone(commits);
            let entered = Arc::clone(entered);
            let release = Arc::clone(release);
            return Ok(honk_outbound::proxy::PreparedUdpTransport::new(
                async move {
                    entered.notify_one();
                    release.notified().await;
                    commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(transport)
                },
            ));
        }
        Ok(honk_outbound::proxy::PreparedUdpTransport::ready(transport))
    }
}

pub(in crate::control) fn udp_test_forwarder() -> Arc<crate::dns::forwarder::DnsForwarder> {
    let router = Arc::new(
        crate::dns::routing::DnsRouter::new(&honk_config::dns::DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    Arc::new(
        crate::dns::forwarder::DnsForwarder::new(
            Arc::new(crate::dns::upstream_pool::UpstreamPool::new(&[], router.clone()).unwrap()),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(1))),
            router,
        )
        .with_cache_enabled(false),
    )
}
pub(super) fn udp_test_config(
    default_outbound: &str,
    nodes: Vec<Node>,
    groups: Vec<Group>,
) -> Config {
    let mut config = Config {
        nodes,
        groups,
        ..Default::default()
    };
    config.routing.default_outbound = if let Some(node) = config
        .nodes
        .iter()
        .find(|node| node.name == default_outbound)
        && !matches!(default_outbound, "direct" | "block")
    {
        let name = format!("{default_outbound}-route");
        config.groups.push(Group {
            name: name.clone(),
            nodes: vec![node.id],
            ..Default::default()
        });
        name
    } else {
        default_outbound.into()
    };
    config
}

pub(in crate::control) fn udp_test_node() -> Node {
    let mut node = Node {
        name: "udp-test".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        address: "127.0.0.1".into(),
        port: 9,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

pub(super) fn udp_test_handle(
    config: Config,
    mode: UdpTestMode,
    capacity: usize,
) -> ControlPlaneHandle {
    udp_test_handle_with_reply_factory(config, mode, capacity, Arc::new(UdpTestReplySocketFactory))
}

/// Uses ControlPlane's production endpoint pool unchanged. The blocked-dial
/// death test needs this so the callback installed during ControlPlane::new
/// owns the same pool that contains the real Initializing reservation.
pub(super) fn udp_test_handle_with_default_pool(
    config: Config,
    mode: UdpTestMode,
) -> ControlPlaneHandle {
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = Arc::new(UdpTestHandler { mode });
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler.clone(),
        )
        .with_packet(handler),
    );
    ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap()
    .spawn_handle()
}

pub(super) fn udp_test_handle_with_reply_factory(
    config: Config,
    mode: UdpTestMode,
    capacity: usize,
    reply_socket_factory: Arc<dyn crate::control::udp_endpoint::UdpReplySocketFactory>,
) -> ControlPlaneHandle {
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = Arc::new(UdpTestHandler { mode });
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler.clone(),
        )
        .with_packet(handler),
    );
    let mut control_plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();
    control_plane.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        capacity,
        reply_socket_factory,
    ));
    control_plane.spawn_handle()
}

pub(in crate::control) fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

pub(super) async fn serve_test_udp(handle: &ControlPlaneHandle) -> anyhow::Result<()> {
    serve_test_udp_to(
        handle,
        addr("10.0.0.2:53000"),
        addr("203.0.113.2:443"),
        b"UDP test packet",
    )
    .await
}

pub(super) async fn serve_test_udp_to(
    handle: &ControlPlaneHandle,
    client: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> anyhow::Result<()> {
    let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("test slow permit");
    let reservation =
        handle
            .udp_pool
            .reserve_or_enqueue(client, dst, payload, slow_permit, &handle.stats);
    match reservation {
        crate::control::udp_endpoint::EndpointReservation::Initializing(lease) => {
            handle.serve_udp_connection(lease).await
        }
        crate::control::udp_endpoint::EndpointReservation::Enqueued
        | crate::control::udp_endpoint::EndpointReservation::CapacityRejected
        | crate::control::udp_endpoint::EndpointReservation::QueueFull
        | crate::control::udp_endpoint::EndpointReservation::QueueClosed
        | crate::control::udp_endpoint::EndpointReservation::IdentityMismatch => Ok(()),
    }
}

pub(super) fn assert_udp_outbound(
    stats: &Arc<StatsManager>,
    outbound: &str,
    total_connections: u32,
    active_connections: u32,
    errors: u32,
) {
    let snapshot = stats.snapshot();
    let actual = snapshot
        .get(outbound)
        .unwrap_or_else(|| panic!("missing outbound stats for {outbound}"));
    assert_eq!(actual.total_conns, total_connections);
    assert_eq!(actual.active_conns, active_connections);
    assert_eq!(actual.errors, errors);
}

pub(in crate::control) fn canonical_socks5(
    name: &str,
    address: &str,
    port: u16,
    subscription_id: Option<uuid::Uuid>,
) -> Node {
    let mut node = Node {
        name: name.to_owned(),
        address: address.to_owned(),
        port,
        outbound: OutboundConfig::from_protocol(NodeProtocol::Socks5),
        subscription_id,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

pub(in crate::control) fn control_plane(config: Config) -> ControlPlane {
    ControlPlane::new(
        config,
        Box::new(MockEbpfBackend::new()),
        Router::new(&[], "direct").expect("test router"),
        Arc::new(ProxyRegistry::default_resolver().expect("test proxy registry")),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).expect("test DNS resolver"),
        test_dns_forwarder(),
    )
    .expect("test control plane")
}

pub(in crate::control) fn test_dns_forwarder() -> Arc<dns::forwarder::DnsForwarder> {
    let cache = Arc::new(tokio::sync::Mutex::new(dns::cache::DnsCache::new(100)));
    let router = Arc::new(
        dns::routing::DnsRouter::new(&honk_config::dns::DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    let upstream_pool = Arc::new(
        dns::upstream_pool::UpstreamPool::new(
            &[honk_config::dns::DnsUpstream {
                name: "default".into(),
                address: "8.8.8.8:53".into(),
                protocol: honk_config::types::DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            }],
            router.clone(),
        )
        .unwrap(),
    );
    dns::forwarder::DnsForwarder::new(upstream_pool, cache, router)
        .with_cache_enabled(false)
        .into()
}

pub(in crate::control) fn changed_routing_config() -> Config {
    let mut config = Config::default();
    config
        .routing
        .rules
        .push(honk_config::routing::RoutingRule {
            name: "reload-change".into(),
            condition: honk_config::routing::RoutingCondition {
                domain: vec!["reload.example".into()],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        });
    config
}

pub(in crate::control) fn score_reload_config(revision: u64) -> Config {
    let nodes = [("score-a", 9), ("score-b", 10)].map(|(name, port)| {
        let mut node = Node {
            name: name.into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    });
    let mut config = Config::default();
    config
        .routing
        .rules
        .push(honk_config::routing::RoutingRule {
            name: format!("score-reload-{revision}"),
            condition: honk_config::routing::RoutingCondition {
                domain: vec![format!("score-{revision}.example")],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        });
    config.nodes = nodes.to_vec();
    config.groups = vec![Group {
        name: "score".into(),
        policy: GroupPolicy::Score,
        nodes: nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    }];
    config
}
