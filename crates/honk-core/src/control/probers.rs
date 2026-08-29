use super::*;
use honk_outbound::group::{
    ScoreOutcome, ScoreReporter, ScoreSelectionContext, ScoreTarget, SelectionNetwork,
};

type ProbeReporter = Option<ScoreReporter>;
#[cfg(test)]
fn empty_probe_reporter() -> ProbeReporter {
    None
}

fn start_probe_feedback(
    manager: &SharedGroupManager,
    node_id: uuid::Uuid,
    context: ScoreSelectionContext,
) -> ProbeReporter {
    manager
        .read()
        .feedback_for_node(node_id, context)
        .map(|feedback| feedback.start())
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

fn url_port(url: &str) -> u16 {
    let (default, rest) = if let Some(rest) = url.trim().strip_prefix("https://") {
        (443, rest)
    } else if let Some(rest) = url.trim().strip_prefix("http://") {
        (80, rest)
    } else {
        (80, url.trim())
    };
    let authority = rest
        .split(',')
        .next()
        .unwrap_or(rest)
        .split('/')
        .next()
        .unwrap_or(rest);
    if let Some(rest) = authority.strip_prefix('[') {
        return rest
            .split(']')
            .nth(1)
            .and_then(|tail| tail.strip_prefix(':'))
            .and_then(|port| port.parse().ok())
            .unwrap_or(default);
    }
    authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or(default)
}

fn http_probe_context(url: &str, addr: SocketAddr) -> ScoreSelectionContext {
    let family = target_family(addr);
    let (host, _) = extract_url_host_path(url).unwrap_or(("", "/"));
    let target = host.parse::<std::net::IpAddr>().map_or_else(
        |_| ScoreTarget::domain(host, url_port(url)),
        |_| addr.into(),
    );
    ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(family),
        health_family: family,
        target: Some(target),
    }
}

/// HTTP-based health check prober that routes requests through proxy nodes.
///
/// Implements `HttpProber` for `AliveDialerSet`, matching Go's `Dialer.HttpCheck`.
/// Resolves the check URL's hostname, dials through the proxy node via the
/// `ProxyRegistry`, sends a raw HTTP request, and validates the status code.
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
            let domain = if protocol == NodeProtocol::Direct {
                None
            } else {
                url_host(&check_url)
            };
            let (runtime, ephemeral) = honk_outbound::urltest::probe_runtime(&generation, &node);
            if !runtime.is_warm_or_stateless() {
                let warm_reporter = start_probe_feedback(
                    &group_manager,
                    node.id,
                    ScoreSelectionContext::aggregate(
                        SelectionNetwork::Tcp,
                        ProbeDomain::Tcp,
                        target_family(addr),
                    ),
                );
                let warmed = match entry.warmable.as_ref() {
                    Some(warmable) => {
                        tokio::time::timeout(
                            timeout,
                            generation.scope_dials(warmable.warm(
                                Arc::clone(&runtime),
                                connect_timeout,
                                honk_outbound::proxy::WarmRequirement::Session,
                            )),
                        )
                        .await
                    }
                    None => Ok(Err(anyhow::anyhow!(
                        "no warm handler for node '{}'",
                        node.name
                    ))),
                };
                match warmed {
                    Ok(Ok(())) => {
                        probe_setup(&warm_reporter);
                        probe_finish(&warm_reporter, ScoreOutcome::Success);
                    }
                    Ok(Err(error)) => {
                        probe_finish(&warm_reporter, ScoreOutcome::from_error(&error));
                        close_ephemeral(ephemeral).await;
                        return honk_outbound::alive::HttpProbeResult::SetupFailure(format!(
                            "warm failed: {error}"
                        ));
                    }
                    Err(_) => {
                        probe_finish(&warm_reporter, ScoreOutcome::Timeout);
                        close_ephemeral(ephemeral).await;
                        return honk_outbound::alive::HttpProbeResult::SetupFailure(
                            "warm timeout".into(),
                        );
                    }
                }
            }

            let reporter = start_probe_feedback(
                &group_manager,
                node.id,
                http_probe_context(&check_url, addr),
            );
            let start = std::time::Instant::now();
            let attempt = async {
                let proxy = generation
                    .scope_dials(entry.tcp.dial_runtime(
                        runtime,
                        addr,
                        domain.as_deref(),
                        connect_timeout,
                    ))
                    .await?;
                probe_setup(&reporter);
                Self::http_check(proxy.stream, &check_url, &check_method, &reporter, timeout)
                    .await
                    .map_err(anyhow::Error::msg)
            };
            let result = tokio::time::timeout(timeout, attempt).await;
            close_ephemeral(ephemeral).await;
            match result {
                Ok(Ok(())) => {
                    probe_finish(&reporter, ScoreOutcome::Success);
                    honk_outbound::alive::HttpProbeResult::WarmSuccess(start.elapsed())
                }
                Ok(Err(error)) => {
                    probe_finish(&reporter, ScoreOutcome::from_error(&error));
                    honk_outbound::alive::HttpProbeResult::ExchangeFailure(error.to_string())
                }
                Err(_) => {
                    probe_finish(&reporter, ScoreOutcome::Timeout);
                    honk_outbound::alive::HttpProbeResult::ExchangeFailure(
                        "HTTP probe timeout".into(),
                    )
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

/// Bare host part of a check URL (`http://host[:port]/path` → `host`).
fn url_host(url: &str) -> Option<String> {
    let (host, _) = extract_url_host_path(url)?;
    if host.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(host.to_string())
    }
}

impl ProxyHttpProber {
    /// Perform an HTTP health check over an already-established connection.
    /// HTTPS targets get a verified TLS layer before the HTTP/1.1 exchange;
    /// status codes 200-499 are considered healthy.
    async fn http_check(
        stream: Box<dyn crate::proxy::AsyncReadWrite>,
        url: &str,
        method: &str,
        reporter: &ProbeReporter,
        timeout: Duration,
    ) -> Result<(), String> {
        let (host, path) =
            extract_url_host_path(url).ok_or_else(|| format!("invalid check URL: {url}"))?;
        let method = if method.is_empty() { "GET" } else { method };
        if url.trim().starts_with("https://") {
            let connector = health_https_connector()?;
            let mut tls = tokio::time::timeout(timeout, connector.connect(host, stream))
                .await
                .map_err(|_| "HTTPS handshake timeout".to_string())?
                .map_err(|error| format!("HTTPS handshake failed: {error}"))?;
            Self::http1_exchange(&mut tls, host, path, method, reporter, timeout).await
        } else {
            let mut stream = stream;
            Self::http1_exchange(stream.as_mut(), host, path, method, reporter, timeout).await
        }
    }

    async fn http1_exchange<S>(
        stream: &mut S,
        host: &str,
        path: &str,
        method: &str,
        reporter: &ProbeReporter,
        timeout: Duration,
    ) -> Result<(), String>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: honk-health/1.0\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| format!("HTTP write failed: {error}"))?;
        probe_tx(reporter, request.len());
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|_| "HTTP read timeout".to_string())?
            .map_err(|error| format!("HTTP read failed: {error}"))?;
        if n == 0 {
            return Err("empty HTTP response".to_string());
        }
        probe_first_response(reporter);
        probe_rx(reporter, n);
        let response = String::from_utf8_lossy(&buf[..n]);
        let status_line = response.lines().next().unwrap_or("");
        let mut parts = status_line.split_whitespace();
        let _version = parts
            .next()
            .ok_or_else(|| format!("malformed HTTP status: {status_line}"))?;
        let status_code = parts
            .next()
            .ok_or_else(|| format!("malformed HTTP status: {status_line}"))?
            .parse::<u16>()
            .map_err(|error| format!("invalid HTTP status '{status_line}': {error}"))?;
        if !(200..500).contains(&status_code) {
            return Err(format!("bad status code: {status_code}"));
        }
        Ok(())
    }
}

fn health_https_connector() -> Result<honk_outbound::tls::TlsConnector, String> {
    static CONNECTOR: std::sync::LazyLock<Result<honk_outbound::tls::TlsConnector, String>> =
        std::sync::LazyLock::new(|| {
            honk_outbound::tls::build_dns_connector(false, b"\x08http/1.1")
                .map_err(|error| format!("failed to build health-check TLS connector: {error:#}"))
        });
    CONNECTOR.clone()
}

/// Default DNS target for UDP health checks when `udp_check_dns` is unset
/// or unresolvable (dae semantics: plain `8.8.8.8:53`).
const DEFAULT_UDP_CHECK_DNS: &str = "8.8.8.8:53";

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
        Box<dyn std::future::Future<Output = Result<std::time::Duration, String>> + Send + 'static>,
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
            let node = node.ok_or_else(|| format!("node '{}' not found", node_name_owned))?;
            let protocol = node.protocol();
            let entry = registry
                .find(protocol)
                .ok_or_else(|| format!("no handler for protocol {:?}", protocol))?;
            let packet = entry
                .packet
                .clone()
                .ok_or_else(|| format!("protocol {:?} has no UDP capability", protocol))?;
            let connect_timeout = {
                let config = config
                    .try_read()
                    .map_err(|_| "config lock busy".to_string())?;
                std::time::Duration::from_millis(config.global.connect_timeout_ms)
            };
            let (runtime, ephemeral) = honk_outbound::urltest::probe_runtime(&generation, &node);
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
            let health_result = match result {
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
            if let Some(target) = quic_score_target.as_ref() {
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
                .await;
            }
            if ephemeral.is_none() {
                stats.mark_warm(node.id, crate::stats::WarmReason::Health);
            }
            close_ephemeral(ephemeral).await;
            health_result
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
) {
    let Some(reporter) = start_probe_feedback(group_manager, node.id, quic_probe_context(target))
    else {
        return;
    };
    let reporter = Some(reporter);
    let target_domain = match &target.identity {
        ScoreTarget::Domain { .. } => Some(target.host.as_str()),
        ScoreTarget::Socket(_) => None,
    };
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
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(_)) => {
            probe_first_response(&reporter);
            // The handshake probe exposes no wire counters. Record only the
            // bidirectional fact so it contributes reliability, not volume.
            probe_tx(&reporter, 1);
            probe_rx(&reporter, 1);
            probe_finish(&reporter, ScoreOutcome::Success);
        }
        Ok(Err(error)) => probe_finish(&reporter, ScoreOutcome::from_error(&error)),
        Err(_) => probe_finish(&reporter, ScoreOutcome::Timeout),
    }
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
    let fallback: SocketAddr = DEFAULT_UDP_CHECK_DNS
        .parse()
        .expect("hardcoded default UDP check DNS address");
    let entries: Vec<&str> = raws
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    // First pass: literal IPs (full socket addr or bare IP with default port).
    for raw in &entries {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            return addr;
        }
        if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
            return SocketAddr::new(ip, 53);
        }
    }
    // Second pass: first domain entry, resolved through the internal DNS
    // resolver when installed (system lookup otherwise).
    if let Some(raw) = entries.first() {
        let (host, port) = match raw.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => (h, port),
                Err(_) => (*raw, 53),
            },
            None => (*raw, 53),
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
        warn!(
            "Failed to resolve udp_check_dns '{}'; using {}",
            raw, fallback
        );
    }
    fallback
}

pub(super) fn udp_probe_identity(raws: &[String], resolved: SocketAddr) -> ScoreTarget {
    let entries: Vec<&str> = raws
        .iter()
        .map(|raw| raw.trim())
        .filter(|raw| !raw.is_empty())
        .collect();
    for raw in &entries {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            return addr.into();
        }
        if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
            return SocketAddr::new(ip, 53).into();
        }
    }
    if let Some(raw) = entries.first() {
        let (host, port) = raw
            .rsplit_once(':')
            .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
            .unwrap_or((raw, 53));
        return ScoreTarget::domain(host, port);
    }
    resolved.into()
}

pub(super) async fn resolve_quic_score_target(
    url: &str,
    resolver: Option<crate::outbound::ResolveHook>,
) -> Option<QuicScoreTarget> {
    if !url.trim().starts_with("https://") {
        warn!("Score QUIC probe disabled: tcp_check_url is not HTTPS");
        return None;
    }
    let (host, _) = match extract_url_host_path(url) {
        Some(parts) => parts,
        None => {
            warn!("Score QUIC probe disabled: invalid tcp_check_url");
            return None;
        }
    };
    let host = host.to_string();
    let port = url_port(url);
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

/// Extract hostname from a URL like "http://cp.cloudflare.com".
/// Extract `(host, request_path)` from a health-check URL.
///
/// The scheme is optional; with dae's comma-separated fallback list
/// (`http://host,ip4,ip6`) only the first segment contributes. The path
/// defaults to `/` when the URL has none. The port is stripped (bracketed
/// IPv6 literals are kept intact).
pub(super) fn extract_url_host_path(url: &str) -> Option<(&str, &str)> {
    let s = url.trim();
    let s = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(s);
    let s = s.split(',').next().unwrap_or(s).trim();
    let (authority, path) = match s.find('/') {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, "/"),
    };
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or(authority)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        None
    } else {
        Some((host, path))
    }
}
#[cfg(test)]
mod http_probe_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn https_health_check_starts_with_tls_client_hello() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut content_type = [0u8; 1];
            stream.read_exact(&mut content_type).await.unwrap();
            content_type[0]
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let reporter = empty_probe_reporter();
        let result = ProxyHttpProber::http_check(
            Box::new(stream),
            "https://localhost/generate_204",
            "HEAD",
            &reporter,
            Duration::from_secs(5),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(peer.await.unwrap(), 22, "TLS handshake record expected");
    }
}
