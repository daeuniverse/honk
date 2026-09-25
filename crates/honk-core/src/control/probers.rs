use super::*;
use anyhow::Context as _;
use honk_outbound::group::{
    ScoreFeedback, ScoreOutcome, ScoreReporter, ScoreSelectionContext, ScoreSource, ScoreTarget,
    SelectionNetwork,
};

type ProbeReporter = Option<ScoreReporter>;

fn probe_feedback(
    manager: &SharedGroupManager,
    node_id: uuid::Uuid,
    context: ScoreSelectionContext,
    interval: Duration,
) -> Option<ScoreFeedback> {
    manager
        .read()
        .feedback_for_node(node_id, context)
        .map(|feedback| {
            feedback
                .with_source(ScoreSource::HealthProbe)
                .with_probe_interval(interval)
        })
}

fn start_probe_feedback(
    manager: &SharedGroupManager,
    node_id: uuid::Uuid,
    context: ScoreSelectionContext,
    interval: Duration,
) -> ProbeReporter {
    probe_feedback(manager, node_id, context, interval).map(|feedback| feedback.start())
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
            let (connect_timeout, default_probe_url, probe_interval) = match config.try_read() {
                Ok(config) => (
                    Duration::from_millis(config.global.connect_timeout_ms),
                    config
                        .global
                        .tcp_check_url
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                    Duration::from_secs(config.global.check_interval_secs),
                ),
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
            let (runtime, ephemeral) = match honk_outbound::urltest::try_probe_runtime(
                &generation,
                &node,
                honk_outbound::proxy::WarmRequirement::Session,
            ) {
                Ok(runtime) => runtime,
                Err(_) => {
                    return honk_outbound::alive::HttpProbeResult::SetupFailure(
                        "invalid node for health probe".into(),
                    );
                }
            };
            let warm_feedback = if runtime
                .is_warm_or_stateless_for(honk_outbound::proxy::WarmRequirement::Session)
            {
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
                    probe_interval,
                )
                .map(|feedback| feedback.with_source(ScoreSource::Warmup))
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
                if let Some(rejection) = honk_outbound::proxy::packet_rejection(&error) {
                    return honk_outbound::alive::HttpProbeResult::LocalRefusal(rejection);
                }
                return honk_outbound::alive::HttpProbeResult::SetupFailure(format!(
                    "warm failed: {error:#}"
                ));
            }

            let feedback = group_manager
                .read()
                .feedback_for_http_probe(
                    node.id,
                    http_probe_context(&request, addr),
                    &check_url,
                    &default_probe_url,
                )
                .map(|feedback| feedback.with_probe_interval(probe_interval));
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
                    if let Some(rejection) = honk_outbound::proxy::packet_rejection(&error) {
                        return honk_outbound::alive::HttpProbeResult::LocalRefusal(rejection);
                    }
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

pub(super) struct QuicScoreProbeTarget {
    url: String,
    port: Option<u16>,
    resolver: Option<crate::outbound::ResolveHook>,
    resolved: tokio::sync::OnceCell<Option<QuicScoreTarget>>,
}

impl QuicScoreProbeTarget {
    pub(super) fn new(url: String, resolver: Option<crate::outbound::ResolveHook>) -> Self {
        let port = honk_config::check::decode_health_http_target(&url)
            .ok()
            .filter(|_| url.trim().starts_with("https://"))
            .map(|target| target.port());
        Self {
            url,
            port,
            resolver,
            resolved: tokio::sync::OnceCell::new(),
        }
    }

    pub(super) async fn resolve(&self) -> anyhow::Result<&Option<QuicScoreTarget>> {
        self.resolved
            .get_or_try_init(|| resolve_quic_score_target(&self.url, self.resolver.clone()))
            .await
    }
}

pub(super) struct UdpDnsProbeTarget {
    raws: Vec<String>,
    resolver: Option<crate::outbound::ResolveHook>,
    resolved: tokio::sync::OnceCell<(SocketAddr, ScoreTarget)>,
}

impl UdpDnsProbeTarget {
    pub(super) fn new(raws: Vec<String>, resolver: Option<crate::outbound::ResolveHook>) -> Self {
        let resolved = match honk_config::check::select_dns_check_target(&raws) {
            Ok(Some(honk_config::check::DnsCheckTarget::Literal(target))) => {
                Some((target, target.into()))
            }
            Ok(Some(honk_config::check::DnsCheckTarget::Domain { .. })) => None,
            Ok(None) | Err(_) => Some((DEFAULT_UDP_CHECK_DNS, DEFAULT_UDP_CHECK_DNS.into())),
        };
        Self {
            raws,
            resolver,
            resolved: tokio::sync::OnceCell::new_with(resolved),
        }
    }

    fn port(&self) -> u16 {
        if let Some((target, _)) = self.resolved.get() {
            return target.port();
        }
        match honk_config::check::select_dns_check_target(&self.raws) {
            Ok(Some(honk_config::check::DnsCheckTarget::Domain { port, .. })) => port,
            _ => DEFAULT_UDP_CHECK_DNS.port(),
        }
    }

    pub(super) async fn resolve(&self) -> anyhow::Result<&(SocketAddr, ScoreTarget)> {
        // Only successful initialization is pinned; refusal or cancellation permits
        // a later health cycle to retry the same configured target.
        self.resolved
            .get_or_try_init(|| async {
                let target = resolve_udp_check_target(&self.raws, self.resolver.clone()).await?;
                Ok((target, udp_probe_identity(&self.raws, target)))
            })
            .await
    }
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
    dns_probe: Arc<UdpDnsProbeTarget>,
    group_manager: SharedGroupManager,
    quic_score_target: Option<Arc<QuicScoreProbeTarget>>,
}

impl ProxyUdpProber {
    pub(super) fn new(
        config: Arc<RwLock<Arc<Config>>>,
        proxy_registry: Arc<ProxyRegistry>,
        runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
        stats: Arc<StatsManager>,
        dns_probe: UdpDnsProbeTarget,
        quic_score_target: Option<QuicScoreProbeTarget>,
        group_manager: SharedGroupManager,
    ) -> Self {
        Self {
            config,
            proxy_registry,
            runtime_registry,
            stats,
            dns_probe: Arc::new(dns_probe),
            group_manager,
            quic_score_target: quic_score_target.map(Arc::new),
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
        let dns_probe = self.dns_probe.clone();
        let group_manager = self.group_manager.clone();
        let quic_score_target = self.quic_score_target.clone();

        Box::pin(async move {
            let Some(node) = node else {
                return honk_outbound::alive::UdpProbeOutcome {
                    dns: Some(Err(anyhow::anyhow!("node '{}' not found", node_name_owned))),
                    data_path: None,
                };
            };
            let udp_capable =
                (honk_outbound::descriptor::descriptor(node.protocol()).supports_udp)(&node);
            let dns_allowed = udp_capable
                && honk_outbound::descriptor::udp_target_allowed(&node, dns_probe.port());
            let data_allowed = udp_capable
                && quic_score_target.as_ref().is_some_and(|target| {
                    target.port.is_some_and(|port| {
                        honk_outbound::descriptor::udp_target_allowed(&node, port)
                    })
                });
            let failed = |error: String| honk_outbound::alive::UdpProbeOutcome {
                dns: dns_allowed.then(|| Err(anyhow::Error::msg(error.clone()))),
                data_path: (!dns_allowed && data_allowed).then_some(Err(anyhow::Error::msg(error))),
            };
            if !dns_allowed && !data_allowed {
                return honk_outbound::alive::UdpProbeOutcome {
                    dns: None,
                    data_path: None,
                };
            }
            let protocol = node.protocol();
            let Some(entry) = registry.find(protocol) else {
                return failed(format!("no handler for protocol {:?}", protocol));
            };
            let Some(packet) = entry.packet.clone() else {
                return failed(format!("protocol {:?} has no UDP capability", protocol));
            };
            let (connect_timeout, probe_interval) = {
                let config = config
                    .try_read()
                    .map_err(|_| "config lock busy".to_string());
                match config {
                    Ok(config) => (
                        Duration::from_millis(config.global.connect_timeout_ms),
                        Duration::from_secs(config.global.check_interval_secs),
                    ),
                    Err(error) => return failed(error),
                }
            };
            let (runtime, ephemeral) = match honk_outbound::urltest::try_probe_runtime(
                &generation,
                &node,
                honk_outbound::proxy::WarmRequirement::Udp,
            ) {
                Ok(runtime) => runtime,
                Err(_) => return failed("invalid node for health probe".into()),
            };
            let dns_deadline = tokio::time::Instant::now() + timeout;
            let dns_target = if dns_allowed {
                // Resolving the shared check target is local setup, not node evidence.
                tokio::time::timeout_at(dns_deadline, dns_probe.resolve())
                    .await
                    .ok()
                    .and_then(Result::ok)
            } else {
                None
            };
            let dns = if let Some((dns_target, dns_identity)) = dns_target.filter(|(target, _)| {
                tokio::time::Instant::now() < dns_deadline
                    && honk_outbound::descriptor::udp_target_allowed(&node, target.port())
            }) {
                let reporter = start_probe_feedback(
                    &group_manager,
                    node.id,
                    ScoreSelectionContext {
                        network: SelectionNetwork::Udp,
                        probe_domain: ProbeDomain::DnsUdp,
                        target_family: Some(target_family(*dns_target)),
                        health_family: target_family(*dns_target),
                        target: Some(dns_identity.clone()),
                    },
                    probe_interval,
                );
                let start = std::time::Instant::now();
                let attempt = async {
                    let transport = generation
                        .scope_dials(packet.dial_udp_transport_runtime(
                            Arc::clone(&runtime),
                            *dns_target,
                            None,
                            connect_timeout,
                        ))
                        .await?;
                    udp_probe_exchange(&transport, timeout).await?;
                    drop(transport);
                    Ok::<(), anyhow::Error>(())
                };
                Some(match tokio::time::timeout_at(dns_deadline, attempt).await {
                    Ok(Ok(())) => {
                        let elapsed = start.elapsed();
                        if let Some(reporter) = &reporter {
                            reporter.probe_latency(elapsed);
                        }
                        probe_finish(&reporter, ScoreOutcome::Success);
                        Ok(elapsed)
                    }
                    Ok(Err(error)) => {
                        probe_finish(&reporter, ScoreOutcome::from_error(&error));
                        Err(error.context("UDP probe failed"))
                    }
                    Err(_) => {
                        probe_finish(&reporter, ScoreOutcome::Timeout);
                        Err(anyhow::anyhow!("UDP probe timeout"))
                    }
                })
            } else {
                None
            };
            let mut data_attempted = false;
            let data_path = match quic_score_target.as_ref() {
                Some(target) if data_allowed => {
                    let deadline = tokio::time::Instant::now() + timeout;
                    match tokio::time::timeout_at(deadline, target.resolve()).await {
                        Ok(Ok(Some(target))) if tokio::time::Instant::now() < deadline => {
                            data_attempted = true;
                            score_quic_probe(
                                &packet,
                                &generation,
                                Arc::clone(&runtime),
                                &node,
                                target,
                                &group_manager,
                                probe_interval,
                                connect_timeout,
                                deadline.saturating_duration_since(tokio::time::Instant::now()),
                            )
                            .await
                        }
                        Ok(Err(error)) => Some(Err(error)),
                        Ok(Ok(_)) | Err(_) => None,
                    }
                }
                Some(_) | None => None,
            };
            if ephemeral.is_none() && (dns.is_some() || (data_attempted && data_path.is_some())) {
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
    timeout: Duration,
) -> anyhow::Result<()> {
    let query = build_dns_probe_query();
    transport
        .send_packet(&query)
        .await
        .context("UDP probe send failed")?;
    let mut buf = [0u8; 512];
    let (n, _src) = tokio::time::timeout(timeout, transport.recv_packet(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("UDP probe recv timeout"))?
        .context("UDP probe recv failed")?;
    anyhow::ensure!(
        n >= 12 && buf[0] == query[0] && buf[1] == query[1] && buf[2] & 0x80 != 0,
        "malformed DNS probe response"
    );
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
    probe_interval: Duration,
    connect_timeout: Duration,
    timeout: Duration,
) -> Option<anyhow::Result<Duration>> {
    if !honk_outbound::descriptor::udp_target_allowed(node, target.addr.port()) {
        return None;
    }
    // Nodes outside Score groups create no reporter and are not probed.
    let reporter = start_probe_feedback(
        group_manager,
        node.id,
        quic_probe_context(target),
        probe_interval,
    )?;
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
            let elapsed = start.elapsed();
            if let Some(reporter) = &reporter {
                reporter.probe_latency(elapsed);
            }
            probe_finish(&reporter, ScoreOutcome::Success);
            Ok(elapsed)
        }
        Ok(Err(error)) => {
            probe_finish(&reporter, ScoreOutcome::from_error(&error));
            Err(error)
        }
        Err(_) => {
            probe_finish(&reporter, ScoreOutcome::Timeout);
            Err(anyhow::anyhow!("Score QUIC probe timeout"))
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
/// Falls back to [`DEFAULT_UDP_CHECK_DNS`] when the list is empty, no entry
/// resolves, or ordinary resolution fails. Typed local refusal is returned.
pub(super) async fn resolve_udp_check_target(
    raws: &[String],
    resolver: Option<crate::outbound::ResolveHook>,
) -> anyhow::Result<SocketAddr> {
    if let Ok(Some(target)) = honk_config::check::select_dns_check_target(raws) {
        let (host, port) = match target {
            honk_config::check::DnsCheckTarget::Literal(address) => return Ok(address),
            honk_config::check::DnsCheckTarget::Domain { host, port } => (host, port),
        };
        let addrs = match resolver {
            Some(resolve) => match resolve(host.to_string(), port).await {
                Ok(addrs) => addrs,
                Err(error) if honk_outbound::proxy::is_packet_rejection(&error) => {
                    return Err(error);
                }
                Err(_) => Vec::new(),
            },
            None => honk_outbound::bootstrap::resolve(host)
                .await
                .map(|ips| {
                    ips.into_iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect()
                })
                .unwrap_or_default(),
        };
        if let Some(addr) = addrs.into_iter().next() {
            return Ok(addr);
        }
        warn!("Failed to resolve UDP DNS check target; using the default");
    }
    Ok(DEFAULT_UDP_CHECK_DNS)
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
) -> anyhow::Result<Option<QuicScoreTarget>> {
    if !url.trim().starts_with("https://") {
        warn!("Score QUIC probe disabled: tcp_check_url is not HTTPS");
        return Ok(None);
    }
    let target = match honk_config::check::decode_health_http_target(url) {
        Ok(target) => target,
        Err(_) => {
            warn!("Score QUIC probe disabled: invalid tcp_check_url");
            return Ok(None);
        }
    };
    let host = target.host().to_owned();
    let port = target.port();
    let addrs = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        match resolver {
            Some(resolve) => match resolve(host.clone(), port).await {
                Ok(addrs) => addrs,
                Err(error) if honk_outbound::proxy::is_packet_rejection(&error) => {
                    return Err(error);
                }
                Err(_) => {
                    warn!("Score QUIC probe disabled: tcp_check_url host resolution failed");
                    return Ok(None);
                }
            },
            None => honk_outbound::bootstrap::resolve(&host)
                .await
                .map(|ips| {
                    ips.into_iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect()
                })
                .unwrap_or_default(),
        }
    };
    let addr = match addrs.into_iter().next() {
        Some(addr) => addr,
        None => {
            warn!("Score QUIC probe disabled: tcp_check_url host did not resolve");
            return Ok(None);
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
            return Ok(None);
        }
    };
    debug!(host, %addr, "Score QUIC probe enabled");
    Ok(Some(QuicScoreTarget {
        addr,
        host,
        identity,
        config,
    }))
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
mod tests;
