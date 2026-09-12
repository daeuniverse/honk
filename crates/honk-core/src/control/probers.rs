use super::*;
use honk_outbound::group::{
    ScoreFeedback, ScoreOutcome, ScoreReporter, ScoreSelectionContext, ScoreTarget,
    SelectionNetwork,
};

type ProbeReporter = Option<ScoreReporter>;

fn probe_feedback(
    manager: &SharedGroupManager,
    node_id: uuid::Uuid,
    context: ScoreSelectionContext,
) -> Option<ScoreFeedback> {
    manager
        .read()
        .feedback_for_node(node_id, context)
        .map(ScoreFeedback::streak_neutral)
}

fn start_probe_feedback(
    manager: &SharedGroupManager,
    node_id: uuid::Uuid,
    context: ScoreSelectionContext,
) -> ProbeReporter {
    probe_feedback(manager, node_id, context).map(|feedback| feedback.start())
}

fn probe_setup(reporter: &ProbeReporter) {
    if let Some(reporter) = reporter {
        reporter.setup_succeeded();
    }
}

fn probe_first_response(reporter: &ProbeReporter) {
    if let Some(reporter) = reporter {
        reporter.first_response();
    }
}

fn probe_tx(reporter: &ProbeReporter, bytes: usize) {
    if let Some(reporter) = reporter {
        reporter.tx(bytes as u64);
    }
}

fn probe_rx(reporter: &ProbeReporter, bytes: usize) {
    if let Some(reporter) = reporter {
        reporter.rx(bytes as u64);
    }
}

fn probe_finish(reporter: &ProbeReporter, outcome: ScoreOutcome) {
    if let Some(reporter) = reporter {
        reporter.finish(outcome);
    }
}

fn target_family(addr: SocketAddr) -> IpVersion {
    if addr.is_ipv6() {
        IpVersion::V6
    } else {
        IpVersion::V4
    }
}

fn http_probe_context(request: &http::Request<()>, addr: SocketAddr) -> ScoreSelectionContext {
    let family = target_family(addr);
    let host = request
        .uri()
        .host()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    let port = request.uri().port_u16().unwrap_or_else(|| {
        if request.uri().scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });
    let target = host
        .parse::<std::net::IpAddr>()
        .map_or_else(|_| ScoreTarget::domain(host, port), |_| addr.into());
    ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(family),
        health_family: family,
        target: Some(target),
    }
}

/// Adapts health configuration, generation ownership, and Score feedback
/// to the shared outbound HTTP measurement.
pub(super) struct ProxyHttpProber {
    config: Arc<RwLock<Arc<Config>>>,
    proxy_registry: Arc<ProxyRegistry>,
    runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    check_method: String,
    group_manager: SharedGroupManager,
}

impl ProxyHttpProber {
    pub(super) fn new(
        config: Arc<RwLock<Arc<Config>>>,
        proxy_registry: Arc<ProxyRegistry>,
        runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
        check_method: String,
        group_manager: SharedGroupManager,
    ) -> Self {
        Self {
            config,
            proxy_registry,
            runtime_registry,
            check_method,
            group_manager,
        }
    }

    /// Find a node by name in the current config.
    fn find_node(&self, node_name: &str) -> Option<Node> {
        self.config
            .try_read()
            .ok()?
            .nodes
            .iter()
            .find(|n| n.name == node_name)
            .cloned()
    }
}

impl honk_outbound::alive::HttpProber for ProxyHttpProber {
    fn probe_http(
        &self,
        node_name: &str,
        addr: SocketAddr,
        url: &str,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = honk_outbound::alive::HttpProbeResult> + Send + 'static>,
    > {
        let node = self.find_node(node_name);
        let node_name = node_name.to_string();
        let registry = self.proxy_registry.clone();
        let generation = self.runtime_registry.read().clone();
        let check_url = url.to_string();
        let check_method = self.check_method.clone();
        let config = self.config.clone();
        let group_manager = self.group_manager.clone();

        Box::pin(async move {
            let Some(node) = node else {
                return honk_outbound::alive::HttpProbeResult::SetupFailure(format!(
                    "node '{node_name}' not found"
                ));
            };
            let protocol = node.protocol();
            let Some(entry) = registry.find(protocol) else {
                return honk_outbound::alive::HttpProbeResult::SetupFailure(format!(
                    "no handler for protocol {:?}",
                    protocol
                ));
            };
            let connect_timeout = match config.try_read() {
                Ok(config) => Duration::from_millis(config.global.connect_timeout_ms),
                Err(_) => {
                    return honk_outbound::alive::HttpProbeResult::SetupFailure(
                        "config lock busy".to_string(),
                    );
                }
            };

            let request = match honk_outbound::urltest::health_http_probe_request(
                &check_url,
                &check_method,
            ) {
                Ok(request) => request,
                Err(error) => {
                    return honk_outbound::alive::HttpProbeResult::SetupFailure(format!(
                        "invalid HTTP probe request: {error:#}"
                    ));
                }
            };
            let host = request
                .uri()
                .host()
                .unwrap_or_default()
                .trim_matches(['[', ']']);
            let target_domain =
                if protocol == NodeProtocol::Direct || host.parse::<std::net::IpAddr>().is_ok() {
                    None
                } else {
                    Some(host.to_string())
                };
            let (runtime, ephemeral) =
                match honk_outbound::urltest::try_probe_runtime(&generation, &node) {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        return honk_outbound::alive::HttpProbeResult::SetupFailure(
                            "invalid node for health probe".into(),
                        );
                    }
                };
            let warm_feedback = if runtime.is_warm_or_stateless() {
                None
            } else {
                probe_feedback(
                    &group_manager,
                    node.id,
                    ScoreSelectionContext::aggregate(
                        SelectionNetwork::Tcp,
                        ProbeDomain::Tcp,
                        target_family(addr),
                    ),
                )
            };
            if let Err(error) = generation
                .scope_dials(honk_outbound::urltest::warm_http_probe(
                    &runtime,
                    entry.warmable.as_deref(),
                    connect_timeout,
                    timeout,
                    warm_feedback,
                ))
                .await
            {
                close_ephemeral(ephemeral).await;
                return honk_outbound::alive::HttpProbeResult::SetupFailure(format!(
                    "warm failed: {error:#}"
                ));
            }

            let feedback =
                probe_feedback(&group_manager, node.id, http_probe_context(&request, addr));
            let result = generation
                .scope_dials(honk_outbound::urltest::measure_http_probe(
                    &runtime,
                    entry.tcp.as_ref(),
                    &request,
                    addr,
                    target_domain.as_deref(),
                    connect_timeout,
                    timeout,
                    feedback,
                ))
                .await;
            close_ephemeral(ephemeral).await;
            match result {
                Ok(elapsed) => honk_outbound::alive::HttpProbeResult::WarmSuccess(elapsed),
                Err(error) => {
                    honk_outbound::alive::HttpProbeResult::ExchangeFailure(format!("{error:#}"))
                }
            }
        })
    }
}

async fn close_ephemeral(guard: Option<honk_outbound::runtime::EphemeralRuntimeGuard>) {
    if let Some(guard) = guard {
        guard.close().await;
    }
}

/// Default DNS target for UDP health checks when `udp_check_dns` is unset
/// or unresolvable (dae semantics: plain `8.8.8.8:53`).
pub(super) const DEFAULT_UDP_CHECK_DNS: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::new(8, 8, 8, 8),
    53,
));

#[derive(Clone)]
pub(super) struct QuicScoreTarget {
    addr: SocketAddr,
    host: String,
    identity: ScoreTarget,
    config: quinn::ClientConfig,
}

/// UDP health check prober that routes a minimal DNS query through the
/// proxy node's UDP data path.
///
/// Implements `UdpProber` for `AliveDialerSet` (Go: `Dialer.UdpCheck`):
/// resolves the node, opens its UDP channel via the handler's
/// `dial_udp_transport` (real UDP, UoT, QUIC datagrams — whatever the
/// protocol provides), sends one DNS query to the configured check DNS
/// server, and awaits the answer. Nodes whose server or protocol cannot
/// carry UDP (e.g. an AnyTLS server without UoT support) fail here even
/// while their TCP probe succeeds — exactly the signal the UDP alive
/// domains need.
pub(super) struct ProxyUdpProber {
    config: Arc<RwLock<Arc<Config>>>,
    proxy_registry: Arc<ProxyRegistry>,
    runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    stats: Arc<StatsManager>,
    dns_target: SocketAddr,
    group_manager: SharedGroupManager,
    dns_identity: ScoreTarget,
    quic_score_target: Option<QuicScoreTarget>,
}

impl ProxyUdpProber {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        config: Arc<RwLock<Arc<Config>>>,
        proxy_registry: Arc<ProxyRegistry>,
        runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
        stats: Arc<StatsManager>,
        dns_target: SocketAddr,
        dns_identity: ScoreTarget,
        quic_score_target: Option<QuicScoreTarget>,
        group_manager: SharedGroupManager,
    ) -> Self {
        Self {
            config,
            proxy_registry,
            runtime_registry,
            stats,
            dns_target,
            group_manager,
            dns_identity,
            quic_score_target,
        }
    }

    /// Find a node by name in the current config.
    fn find_node(&self, node_name: &str) -> Option<Node> {
        self.config
            .try_read()
            .ok()?
            .nodes
            .iter()
            .find(|n| n.name == node_name)
            .cloned()
    }
}

impl honk_outbound::alive::UdpProber for ProxyUdpProber {
    fn probe_udp(
        &self,
        node_name: &str,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = honk_outbound::alive::UdpProbeOutcome>
                + Send
                + 'static,
        >,
    > {
        let node = self.find_node(node_name);
        let node_name_owned = node_name.to_string();
        let registry = self.proxy_registry.clone();
        let generation = self.runtime_registry.read().clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        let dns_target = self.dns_target;
        let group_manager = self.group_manager.clone();
        let dns_identity = self.dns_identity.clone();
        let quic_score_target = self.quic_score_target.clone();

        Box::pin(async move {
            let dns_only = |error: String| honk_outbound::alive::UdpProbeOutcome {
                dns: Err(error),
                data_path: None,
            };
            let Some(node) = node else {
                return dns_only(format!("node '{}' not found", node_name_owned));
            };
            let protocol = node.protocol();
            let Some(entry) = registry.find(protocol) else {
                return dns_only(format!("no handler for protocol {:?}", protocol));
            };
            let Some(packet) = entry.packet.clone() else {
                return dns_only(format!("protocol {:?} has no UDP capability", protocol));
            };
            let connect_timeout = {
                let config = config
                    .try_read()
                    .map_err(|_| "config lock busy".to_string());
                match config {
                    Ok(config) => {
                        std::time::Duration::from_millis(config.global.connect_timeout_ms)
                    }
                    Err(error) => return dns_only(error),
                }
            };
            let (runtime, ephemeral) =
                match honk_outbound::urltest::try_probe_runtime(&generation, &node) {
                    Ok(runtime) => runtime,
                    Err(_) => return dns_only("invalid node for health probe".into()),
                };
            let reporter = start_probe_feedback(
                &group_manager,
                node.id,
                ScoreSelectionContext {
                    network: SelectionNetwork::Udp,
                    probe_domain: ProbeDomain::DnsUdp,
                    target_family: Some(target_family(dns_target)),
                    health_family: target_family(dns_target),
                    target: Some(dns_identity),
                },
            );
            let start = std::time::Instant::now();
            let attempt = async {
                let transport = generation
                    .scope_dials(packet.dial_udp_transport_runtime(
                        Arc::clone(&runtime),
                        dns_target,
                        None,
                        connect_timeout,
                    ))
                    .await?;
                probe_setup(&reporter);
                udp_probe_exchange(&transport, &reporter, timeout)
                    .await
                    .map_err(anyhow::Error::msg)?;
                drop(transport);
                Ok::<(), anyhow::Error>(())
            };
            let result = tokio::time::timeout(timeout, attempt).await;
            let dns = match result {
                Ok(Ok(())) => {
                    probe_finish(&reporter, ScoreOutcome::Success);
                    Ok(start.elapsed())
                }
                Ok(Err(error)) => {
                    probe_finish(&reporter, ScoreOutcome::from_error(&error));
                    Err(format!("UDP probe failed: {error}"))
                }
                Err(_) => {
                    probe_finish(&reporter, ScoreOutcome::Timeout);
                    Err("UDP probe timeout".to_string())
                }
            };
            // The DNS check target may be blocked through an otherwise
            // healthy UDP path (relay anti-amplification rules); the Score
            // handshake runs regardless so its success can attest the data
            // path. It is still skipped for nodes outside Score groups
            // (start_probe_feedback returns no reporter there).
            let data_path = match quic_score_target.as_ref() {
                Some(target) => {
                    score_quic_probe(
                        &packet,
                        &generation,
                        Arc::clone(&runtime),
                        &node,
                        target,
                        &group_manager,
                        connect_timeout,
                        timeout,
                    )
                    .await
                }
                None => None,
            };
            if ephemeral.is_none() {
                stats.mark_warm(node.id, crate::stats::WarmReason::Health);
            }
            close_ephemeral(ephemeral).await;
            honk_outbound::alive::UdpProbeOutcome { dns, data_path }
        })
    }
}

/// Send the minimal DNS probe query and await a well-formed answer.
async fn udp_probe_exchange(
    transport: &Arc<dyn honk_outbound::proxy::PacketTransport>,
    reporter: &ProbeReporter,
    timeout: Duration,
) -> Result<(), String> {
    let query = build_dns_probe_query();
    transport
        .send_packet(&query)
        .await
        .map_err(|error| format!("UDP probe send failed: {error}"))?;
    probe_tx(reporter, query.len());
    let mut buf = [0u8; 512];
    let (n, _src) = tokio::time::timeout(timeout, transport.recv_packet(&mut buf))
        .await
        .map_err(|_| "UDP probe recv timeout".to_string())?
        .map_err(|error| format!("UDP probe recv failed: {error}"))?;
    probe_first_response(reporter);
    probe_rx(reporter, n);
    if n < 12 || buf[0] != query[0] || buf[1] != query[1] || buf[2] & 0x80 == 0 {
        return Err("malformed DNS probe response".to_string());
    }
    Ok(())
}

pub(super) fn quic_probe_context(target: &QuicScoreTarget) -> ScoreSelectionContext {
    let family = target_family(target.addr);
    ScoreSelectionContext {
        network: SelectionNetwork::Udp,
        probe_domain: ProbeDomain::DataUdp,
        target_family: Some(family),
        health_family: family,
        target: Some(target.identity.clone()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn score_quic_probe(
    packet: &Arc<dyn honk_outbound::proxy::PacketOutbound>,
    generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    runtime: Arc<honk_outbound::runtime::NodeRuntime>,
    node: &Node,
    target: &QuicScoreTarget,
    group_manager: &SharedGroupManager,
    connect_timeout: Duration,
    timeout: Duration,
) -> Option<Result<Duration, String>> {
    // Nodes outside Score groups create no reporter and are not probed.
    let reporter = start_probe_feedback(group_manager, node.id, quic_probe_context(target))?;
    let reporter = Some(reporter);
    let target_domain = match &target.identity {
        ScoreTarget::Domain { .. } => Some(target.host.as_str()),
        ScoreTarget::Socket(_) => None,
    };
    let start = std::time::Instant::now();
    let attempt = async {
        let transport = generation
            .scope_dials(packet.dial_udp_transport_runtime(
                runtime,
                target.addr,
                target_domain,
                connect_timeout,
            ))
            .await?;
        probe_setup(&reporter);
        honk_outbound::quic::quic_handshake_probe(
            transport,
            target.addr,
            &target.host,
            &target.config,
            timeout,
        )
        .await
    };
    Some(match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(_)) => {
            probe_first_response(&reporter);
            // The handshake probe exposes no wire counters. Record only the
            // bidirectional fact so it contributes reliability, not volume.
            probe_tx(&reporter, 1);
            probe_rx(&reporter, 1);
            probe_finish(&reporter, ScoreOutcome::Success);
            Ok(start.elapsed())
        }
        Ok(Err(error)) => {
            let message = format!("{error}");
            probe_finish(&reporter, ScoreOutcome::from_error(&error));
            Err(message)
        }
        Err(_) => {
            probe_finish(&reporter, ScoreOutcome::Timeout);
            Err("Score QUIC probe timeout".to_string())
        }
    })
}

/// Build the minimal DNS query used by the UDP health probe: a single
/// A-record question for google.com with a fixed id (0x1234). The id is
/// echoed back by the resolver and validated in the response.
pub(super) fn build_dns_probe_query() -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(&[
        6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ]);
    q
}

/// Resolve the UDP health check target from `global.udp_check_dns`
/// (dae semantics: `host[:port]` list, default port 53).
///
/// IP literals in the list are preferred over domain entries: the system
/// resolver can return DNS-poisoned answers for popular check domains
/// (e.g. dns.google), which would send every probe to a black hole.
/// Falls back to [`DEFAULT_UDP_CHECK_DNS`] when the list is empty or no
/// entry resolves.
pub(super) async fn resolve_udp_check_target(
    raws: &[String],
    resolver: Option<crate::outbound::ResolveHook>,
) -> SocketAddr {
    if let Ok(Some(target)) = honk_config::check::select_dns_check_target(raws) {
        let (host, port) = match target {
            honk_config::check::DnsCheckTarget::Literal(address) => return address,
            honk_config::check::DnsCheckTarget::Domain { host, port } => (host, port),
        };
        let addrs = match resolver {
            Some(resolve) => resolve(host.to_string(), port).await,
            None => tokio::net::lookup_host((host, port))
                .await
                .map(|it| it.collect())
                .unwrap_or_default(),
        };
        if let Some(addr) = addrs.into_iter().next() {
            return addr;
        }
        warn!("Failed to resolve UDP DNS check target; using the default");
    }
    DEFAULT_UDP_CHECK_DNS
}

pub(super) fn udp_probe_identity(raws: &[String], resolved: SocketAddr) -> ScoreTarget {
    match honk_config::check::select_dns_check_target(raws) {
        Ok(Some(honk_config::check::DnsCheckTarget::Literal(address))) => address.into(),
        Ok(Some(honk_config::check::DnsCheckTarget::Domain { host, port })) => {
            ScoreTarget::domain(host, port)
        }
        Ok(None) | Err(_) => resolved.into(),
    }
}

pub(super) async fn resolve_quic_score_target(
    url: &str,
    resolver: Option<crate::outbound::ResolveHook>,
) -> Option<QuicScoreTarget> {
    if !url.trim().starts_with("https://") {
        warn!("Score QUIC probe disabled: tcp_check_url is not HTTPS");
        return None;
    }
    let target = match honk_config::check::decode_health_http_target(url) {
        Ok(target) => target,
        Err(_) => {
            warn!("Score QUIC probe disabled: invalid tcp_check_url");
            return None;
        }
    };
    let host = target.host().to_owned();
    let port = target.port();
    let addrs = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        match resolver {
            Some(resolve) => resolve(host.clone(), port).await,
            None => tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|addrs| addrs.collect())
                .unwrap_or_default(),
        }
    };
    let addr = match addrs.into_iter().next() {
        Some(addr) => addr,
        None => {
            warn!("Score QUIC probe disabled: tcp_check_url host did not resolve");
            return None;
        }
    };
    let identity = host
        .parse::<std::net::IpAddr>()
        .map_or_else(|_| ScoreTarget::domain(&host, port), |_| addr.into());
    let tls_node = Node {
        outbound: honk_config::node::OutboundConfig::Hysteria2(
            honk_config::node::Hysteria2Config {
                quic: honk_config::node::QuicOptions {
                    tls: honk_config::node::TlsOptions {
                        sni: Some(host.clone()),
                        skip_cert_verify: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        ..Node::default()
    };
    let config = match honk_outbound::quic::client_config(
        &tls_node,
        &[b"h3"],
        honk_outbound::quic::QuicClientOptions::default(),
    )
    .await
    {
        Ok(config) => config,
        Err(error) => {
            warn!("Score QUIC probe disabled: failed to build QUIC client: {error:#}");
            return None;
        }
    };
    debug!(host, %addr, "Score QUIC probe enabled");
    Some(QuicScoreTarget {
        addr,
        host,
        identity,
        config,
    })
}

/// Returns true if `ip` belongs to honk's own dae0 link subnets.
///
/// The subnet constants (`crate::DAE0_IPV6_PREFIX_HI`, `crate::DAE0_IPV4_NET`)
/// live in the crate root next to the `DAENS_*` address strings used by the
/// netns setup, so this datapath check and the interface configuration
/// cannot drift apart.
pub(super) fn is_honk_internal_addr(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V6(v6) => {
            let octets = v6.octets();
            let hi = u64::from_be_bytes(octets[..8].try_into().unwrap());
            hi == crate::DAE0_IPV6_PREFIX_HI // fd00:686f:6e6b::/64
        }
        std::net::IpAddr::V4(v4) => {
            let addr: u32 = u32::from(*v4);
            (addr & 0xFFFF0000) == crate::DAE0_IPV4_NET // 169.254.0.0/16
        }
    }
}

/// Returns true for broadcast/multicast addresses that should not be
/// proxied (mDNS, SSDP, LLMNR local discovery traffic).
pub(super) fn is_broadcast_or_multicast(ip: &std::net::IpAddr) -> bool {
    if ip.is_multicast() {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets == [255, 255, 255, 255] || octets[3] == 255
        }
        std::net::IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
#[path = "probers_tests.rs"]
mod http_probe_tests;
