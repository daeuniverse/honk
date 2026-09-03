//! `honk-tool sub` — subscription availability check.
//!
//! Fetches a subscription (or reads a local file), then probes every node:
//! server address families, proxied connectivity to a test host over IPv4
//! and IPv6 (a full protocol dial through the node), and a proxied latency
//! measurement (`urltest_node`).

use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use clap::{Args, ValueEnum};
use honk_config::Config;
use honk_config::node::{Node, WireMode};
use honk_config::subscription::Subscription;
use honk_config::types::{NodeProtocol, SubscriptionType};
use honk_core::proxy::ProxyRegistry;
use honk_core::subscription::SubscriptionManager;
use honk_outbound::reality::parse_reality_config;
use honk_outbound::urltest::urltest_node;
use url::Url;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum TlsImplementation {
    Tls,
    Utls,
}

impl TlsImplementation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Utls => "utls",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeEligibility {
    Supported,
    InvalidConfig(&'static str),
    ExpectedUnsupported(&'static str),
}

impl ProbeEligibility {
    fn code(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::InvalidConfig(reason) | Self::ExpectedUnsupported(reason) => reason,
        }
    }

    fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeFailureKind {
    Resolve,
    Timeout,
    Exchange,
    Handler,
}

impl ProbeFailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Timeout => "timeout",
            Self::Exchange => "exchange",
            Self::Handler => "handler",
        }
    }
}

#[derive(Args)]
pub struct SubArgs {
    /// Subscription URL (http/https) or a local file with one share link per line.
    pub source: String,
    /// Test target for proxied connectivity/latency (host:port).
    #[arg(long, default_value = "cp.cloudflare.com:443")]
    pub target: String,
    /// Latency-test URL (defaults to https://www.gstatic.com/generate_204).
    #[arg(long)]
    pub url: Option<String>,
    /// Per-probe timeout in seconds.
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,
    /// Maximum concurrent probes.
    #[arg(long, default_value_t = 10)]
    pub concurrency: usize,
    /// Probe only the first N nodes (0 = all).
    #[arg(long, default_value_t = 0)]
    pub limit: usize,
    /// User-Agent for the subscription fetch.
    #[arg(long)]
    pub ua: Option<String>,
    /// TLS ClientHello implementation used by subscription probes.
    #[arg(long, value_enum, default_value = "tls")]
    pub tls_implementation: TlsImplementation,
    /// Chrome fingerprint profile used when --tls-implementation=utls.
    #[arg(long, default_value = "chrome_auto")]
    pub utls_imitate: String,
    /// Explicit IPv4 target for the v4 probe (dae-style, e.g. 1.1.1.1:80).
    /// Overrides DNS resolution for that family.
    #[arg(long, default_value = "1.1.1.1:443")]
    pub v4_target: Option<SocketAddr>,
    /// Explicit IPv6 target for the v6 probe (dae-style, e.g.
    /// [2606:4700:4700::1111]:80).  Use when the resolver gives no AAAA
    /// (e.g. ipversion_prefer: 4 DNS) or the host has none.
    #[arg(long, default_value = "[2606:4700:4700::1111]:443")]
    pub v6_target: Option<SocketAddr>,
}

struct ProbeOutcome {
    node_name: String,
    shape: String,
    eligibility: ProbeEligibility,
    server_v4: bool,
    server_v6: bool,
    v4: Option<Result<Duration, ProbeFailureKind>>,
    v6: Option<Result<Duration, ProbeFailureKind>>,
    urltest: Option<Result<Duration, ProbeFailureKind>>,
    udp_dns: Option<Result<Duration, ProbeFailureKind>>,
    udp_quic: Option<Result<Duration, ProbeFailureKind>>,
}

pub async fn run(args: SubArgs) -> anyhow::Result<()> {
    configure_tls(&args)?;
    let mut nodes = load_nodes(&args).await?;
    if args.limit > 0 {
        nodes.truncate(args.limit);
    }
    print_summary_header(&nodes);

    let registry = Arc::new(ProxyRegistry::default_resolver()?);
    let (url_host, url_port) = split_host_port(&args.target)?;
    let timeout = Duration::from_secs(args.timeout);

    let mut set = tokio::task::JoinSet::new();
    let mut pending = nodes.into_iter();
    let mut running = 0usize;
    let mut outcomes = Vec::new();

    loop {
        while running < args.concurrency
            && let Some(node) = pending.next()
        {
            let registry = Arc::clone(&registry);
            let targets = Arc::new(ProbeTargets {
                host: url_host.to_string(),
                port: url_port,
                url: args.url.clone(),
                timeout,
                v4: args.v4_target,
                v6: args.v6_target,
            });
            set.spawn(async move { probe_node(&registry, node, &targets).await });
            running += 1;
        }
        match set.join_next().await {
            Some(Ok(outcome)) => {
                running -= 1;
                print_outcome(&outcome);
                outcomes.push(outcome);
            }
            Some(Err(_)) => {
                running -= 1;
                eprintln!("probe task failed");
            }
            None => break,
        }
    }

    let alive_v4 = outcomes
        .iter()
        .filter(|o| matches!(&o.v4, Some(Ok(_))))
        .count();
    let alive_v6 = outcomes
        .iter()
        .filter(|o| matches!(&o.v6, Some(Ok(_))))
        .count();
    let alive_udp = outcomes
        .iter()
        .filter(|o| matches!(&o.udp_dns, Some(Ok(_))))
        .count();
    let alive_quic = outcomes
        .iter()
        .filter(|o| matches!(&o.udp_quic, Some(Ok(_))))
        .count();
    let mut latencies: Vec<u128> = outcomes
        .iter()
        .filter_map(|o| {
            o.urltest
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .map(Duration::as_millis)
        })
        .collect();
    latencies.sort_unstable();
    let median = latencies
        .get(latencies.len() / 2)
        .map(|v| format!("{v}ms"))
        .unwrap_or_else(|| "n/a".into());
    println!(
        "\n== {} node(s): v4-proxied {alive_v4}, v6-proxied {alive_v6}, udp-dns {alive_udp}, udp-quic {alive_quic}, urltest-ok {}, median latency {median}",
        outcomes.len(),
        latencies.len()
    );
    Ok(())
}
fn configure_tls(args: &SubArgs) -> anyhow::Result<()> {
    let imitate = args.utls_imitate.trim();
    anyhow::ensure!(
        imitate.starts_with("chrome"),
        "--utls-imitate must use a chrome* profile"
    );
    honk_outbound::tls::set_tls_mode(args.tls_implementation.as_str());
    honk_outbound::tls::set_utls_imitate(imitate);
    Ok(())
}

fn parse_subscription_url_from_stdin(input: &str) -> anyhow::Result<String> {
    let value = input.trim();
    let parsed = Url::parse(value).ok();
    let valid = !value.is_empty()
        && !value.contains(['\n', '\r'])
        && parsed
            .as_ref()
            .is_some_and(|url| matches!(url.scheme(), "http" | "https") && url.has_host());
    if !valid {
        anyhow::bail!("invalid subscription URL from stdin");
    }
    Ok(value.to_string())
}

/// Load nodes from a subscription URL or a local share-link file.
async fn load_nodes(args: &SubArgs) -> anyhow::Result<Vec<Node>> {
    let source = if args.source == "-" {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|_| anyhow::anyhow!("failed to read subscription URL from stdin"))?;
        parse_subscription_url_from_stdin(&input)?
    } else {
        args.source.clone()
    };

    if args.source != "-" && std::path::Path::new(&source).exists() {
        let content =
            std::fs::read_to_string(&source).with_context(|| format!("read '{}'", args.source))?;
        return parse_lines(&content);
    }

    let sub = Subscription {
        name: "sub".into(),
        url: source,
        sub_type: SubscriptionType::Custom,
        user_agent: args.ua.clone(),
        ..Default::default()
    };
    let manager = SubscriptionManager::new()?;
    let started = Instant::now();
    let nodes = manager.fetch(&sub).await.context("fetch subscription")?;
    println!("fetched {} node(s) in {:?}", nodes.len(), started.elapsed());
    Ok(nodes)
}

/// Parse a local file of share links (one per line, `#` comments allowed).
fn parse_lines(content: &str) -> anyhow::Result<Vec<Node>> {
    let mut nodes = Vec::new();
    let mut skipped = 0usize;
    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match Node::from_share_link(line) {
            Ok(node) => nodes.push(node),
            Err(_) => skipped += 1,
        }
    }
    if nodes.is_empty() {
        anyhow::bail!("no valid share links in file");
    }
    if skipped > 0 {
        println!("parsed {} node(s), {skipped} line(s) skipped", nodes.len());
    } else {
        println!("parsed {} node(s)", nodes.len());
    }
    Ok(nodes)
}

fn print_summary_header(nodes: &[Node]) {
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for n in nodes {
        *counts.entry(n.protocol().as_str().to_string()).or_default() += 1;
    }
    let breakdown = counts
        .iter()
        .map(|(p, c)| format!("{p}×{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    println!("protocols: {breakdown}\n");
}
fn classify_vless_node(node: &Node) -> ProbeEligibility {
    let vless = node.vless().unwrap();
    let Some(password) = vless.uuid.as_deref().filter(|value| !value.is_empty()) else {
        return ProbeEligibility::InvalidConfig("invalid-uuid");
    };
    if Uuid::parse_str(password).is_err() {
        return ProbeEligibility::InvalidConfig("invalid-uuid");
    }

    let reality_fields_present = vless.tls.reality_public_key.is_some()
        || vless.tls.reality_short_id.is_some()
        || vless.tls.reality_spider_x.is_some();
    let reality = if reality_fields_present {
        match parse_reality_config(node) {
            Ok(Some(_)) => true,
            Ok(None) | Err(_) => return ProbeEligibility::InvalidConfig("invalid-reality"),
        }
    } else {
        false
    };

    if !matches!(
        vless.transport.transport.as_str(),
        "" | "tcp" | "ws" | "grpc"
    ) {
        return ProbeEligibility::ExpectedUnsupported("unsupported-transport");
    }

    let flow = vless.flow.as_deref().filter(|flow| !flow.is_empty());
    if flow.is_some_and(|flow| flow != "xtls-rprx-vision") {
        return ProbeEligibility::ExpectedUnsupported("unsupported-flow");
    }
    let vision = flow == Some("xtls-rprx-vision");
    if vision && !vless.tls.enabled && !reality {
        return ProbeEligibility::InvalidConfig("vision-without-tls");
    }
    if vision && matches!(vless.transport.transport.as_str(), "ws" | "grpc") {
        return ProbeEligibility::ExpectedUnsupported("vision-non-tcp");
    }

    let mut candidate = node.clone();
    candidate.vless_mut().unwrap().flow = flow.map(str::to_string);
    let config = Config {
        nodes: vec![candidate],
        ..Config::default()
    };
    if config.validate().is_err() {
        return ProbeEligibility::InvalidConfig("invalid-config");
    }
    ProbeEligibility::Supported
}

fn vless_shape(node: &Node) -> String {
    let vless = node.vless().unwrap();
    let carrier = if vless.tls.reality_public_key.is_some()
        || vless.tls.reality_short_id.is_some()
        || vless.tls.reality_spider_x.is_some()
    {
        "reality"
    } else if vless.tls.enabled {
        "tls"
    } else {
        "plain"
    };
    let transport = match vless.transport.transport.as_str() {
        "" | "tcp" => "tcp",
        "ws" => "ws",
        "grpc" => "grpc",
        _ => "unsupported",
    };
    let vision = if vless.flow.as_deref() == Some("xtls-rprx-vision") {
        "/vision"
    } else {
        ""
    };
    let wire = match vless.mode {
        WireMode::Legacy => "",
        WireMode::UotV2 => "/uot-v2",
        WireMode::H2mux => "/h2mux",
        WireMode::H2muxPadded => "/h2mux-padded",
        WireMode::Xudp => "/xudp",
        WireMode::MuxCool => "/mux-cool",
    };
    format!("vless/{carrier}/{transport}{vision}{wire}")
}

/// Everything a probe run needs to reach the test target.
struct ProbeTargets {
    host: String,
    port: u16,
    url: Option<String>,
    timeout: Duration,
    v4: Option<SocketAddr>,
    v6: Option<SocketAddr>,
}

async fn probe_node(registry: &ProxyRegistry, node: Node, targets: &ProbeTargets) -> ProbeOutcome {
    let eligibility = if node.protocol() == NodeProtocol::VLess {
        classify_vless_node(&node)
    } else {
        ProbeEligibility::Supported
    };
    if !eligibility.is_supported() {
        return ProbeOutcome::skipped(&node, eligibility);
    }

    let deadline = targets.timeout.saturating_add(Duration::from_secs(1));
    match tokio::time::timeout(deadline, probe_supported_node(registry, &node, targets)).await {
        Ok(outcome) => outcome,
        Err(_) => ProbeOutcome::timed_out(registry, &node),
    }
}

async fn probe_supported_node(
    registry: &ProxyRegistry,
    node: &Node,
    targets: &ProbeTargets,
) -> ProbeOutcome {
    let server_families = server_families(node).await;
    let (v4, v6, udp_dns, udp_quic, urltest) = tokio::join!(
        probe_family(
            registry,
            node,
            &targets.host,
            targets.port,
            false,
            targets.timeout,
            targets.v4,
        ),
        probe_family(
            registry,
            node,
            &targets.host,
            targets.port,
            true,
            targets.timeout,
            targets.v6,
        ),
        probe_udp_dns(registry, node, targets.timeout),
        probe_udp_quic(registry, node, &targets.host, 443, targets.timeout),
        probe_urltest(
            registry,
            node,
            targets.url.as_deref().unwrap_or_default(),
            targets.timeout,
        ),
    );

    ProbeOutcome {
        node_name: node.name.clone(),
        shape: probe_shape(node),
        eligibility: ProbeEligibility::Supported,
        server_v4: server_families.0,
        server_v6: server_families.1,
        v4,
        v6,
        urltest,
        udp_dns,
        udp_quic,
    }
}

async fn probe_urltest(
    registry: &ProxyRegistry,
    node: &Node,
    url: &str,
    timeout: Duration,
) -> Option<Result<Duration, ProbeFailureKind>> {
    let Some(entry) = registry.find(node.protocol()) else {
        return Some(Err(ProbeFailureKind::Handler));
    };
    let guard = honk_outbound::runtime::NodeRuntime::ephemeral_guarded(node);
    let measured = urltest_node(&guard.runtime(), entry.tcp.as_ref(), url, timeout).await;
    guard.close().await;
    Some(measured.map_err(|_| ProbeFailureKind::Exchange))
}

impl ProbeOutcome {
    fn skipped(node: &Node, eligibility: ProbeEligibility) -> Self {
        Self {
            node_name: node.name.clone(),
            shape: probe_shape(node),
            eligibility,
            server_v4: false,
            server_v6: false,
            v4: None,
            v6: None,
            urltest: None,
            udp_dns: None,
            udp_quic: None,
        }
    }

    fn timed_out(registry: &ProxyRegistry, node: &Node) -> Self {
        let packet_result = registry
            .find(node.protocol())
            .filter(|entry| (entry.descriptor.supports_udp)(node))
            .and_then(|entry| entry.packet.as_ref())
            .map(|_| Err(ProbeFailureKind::Timeout));
        Self {
            node_name: node.name.clone(),
            shape: probe_shape(node),
            eligibility: ProbeEligibility::Supported,
            server_v4: false,
            server_v6: false,
            v4: Some(Err(ProbeFailureKind::Timeout)),
            v6: Some(Err(ProbeFailureKind::Timeout)),
            urltest: Some(Err(ProbeFailureKind::Timeout)),
            udp_dns: packet_result,
            udp_quic: packet_result,
        }
    }
}

fn probe_shape(node: &Node) -> String {
    if node.protocol() == NodeProtocol::VLess {
        vless_shape(node)
    } else {
        node.protocol().as_str().to_string()
    }
}

/// Resolve the node server address and report which IP families it has.
async fn server_families(node: &Node) -> (bool, bool) {
    let lookup = format!("{}:0", node.host());
    match tokio::net::lookup_host(lookup).await {
        Ok(addrs) => {
            let mut v4 = false;
            let mut v6 = false;
            for a in addrs {
                if a.is_ipv4() {
                    v4 = true;
                } else {
                    v6 = true;
                }
            }
            (v4, v6)
        }
        Err(_) => (false, false),
    }
}

/// Probe one address family end-to-end: dial the family-specific target
/// through the node and complete a real HTTP HEAD round trip (so a bare
/// dial() return, which is free for session-multiplexed protocols, proves
/// nothing). The reported value follows urltest's warm-path convention —
/// one round trip over the established connection, setup excluded.
async fn probe_family(
    registry: &ProxyRegistry,
    node: &Node,
    url_host: &str,
    url_port: u16,
    v6: bool,
    timeout: Duration,
    explicit: Option<SocketAddr>,
) -> Option<Result<Duration, ProbeFailureKind>> {
    let addr = match explicit {
        Some(addr) => addr,
        None => match tokio::net::lookup_host((url_host, url_port)).await {
            Ok(mut addrs) => addrs.find(|addr| addr.is_ipv6() == v6)?,
            Err(_) => return Some(Err(ProbeFailureKind::Resolve)),
        },
    };
    let Some(entry) = registry.find(node.protocol()) else {
        return Some(Err(ProbeFailureKind::Handler));
    };
    let url = format!("https://{url_host}/");
    let guard = honk_outbound::runtime::NodeRuntime::ephemeral_guarded(node);
    let measured = honk_outbound::urltest::urltest_node_addr(
        &guard.runtime(),
        entry.tcp.as_ref(),
        &url,
        addr,
        timeout,
    )
    .await;
    guard.close().await;
    Some(measured.map_err(|_| ProbeFailureKind::Exchange))
}

fn print_outcome(outcome: &ProbeOutcome) {
    println!("{}", render_outcome(outcome));
}

fn render_outcome(outcome: &ProbeOutcome) -> String {
    let families = match (outcome.server_v4, outcome.server_v6) {
        (true, true) => "v4+v6",
        (true, false) => "v4",
        (false, true) => "v6",
        (false, false) => "-",
    };
    format!(
        "{:<40} {:<32} {:<6} status: {:<22} v4: {:<14} v6: {:<14} urltest: {:<14} dns: {:<14} quic: {}",
        truncate(&outcome.node_name, 40),
        outcome.shape,
        families,
        outcome.eligibility.code(),
        render_probe_result(&outcome.v4, "n/a"),
        render_probe_result(&outcome.v6, "n/a"),
        render_probe_result(&outcome.urltest, "n/a"),
        render_probe_result(&outcome.udp_dns, "n/a"),
        render_probe_result(&outcome.udp_quic, "n/a"),
    )
}

fn render_probe_result(
    result: &Option<Result<Duration, ProbeFailureKind>>,
    unavailable: &str,
) -> String {
    match result {
        None => unavailable.to_string(),
        Some(Ok(duration)) => format!("{}ms", duration.as_millis()),
        Some(Err(error)) => format!("FAIL({})", error.as_str()),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

fn split_host_port(s: &str) -> anyhow::Result<(&str, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .with_context(|| format!("target '{s}' must be host:port"))?;
    Ok((host, port.parse()?))
}

/// Tiny xorshift PRNG seeded from the clock (avoids a rand dependency for the
/// two probe packet builders).
fn next_rand(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn rand_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64 | 1)
        .unwrap_or(0x9e3779b97f4a7c15)
}

/// UDP probe: one minimal DNS A query through the node's UDP transport.
/// Proves the node's UDP relay path end to end (mirrors the engine's
/// `probe_node_udp` health check).
async fn probe_udp_dns(
    registry: &ProxyRegistry,
    node: &Node,
    timeout: Duration,
) -> Option<Result<Duration, ProbeFailureKind>> {
    let Some(entry) = registry.find(node.protocol()) else {
        return Some(Err(ProbeFailureKind::Handler));
    };
    if !(entry.descriptor.supports_udp)(node) {
        return None;
    }
    let packet = entry.packet.as_ref()?;
    let dns_server = SocketAddr::from(([8, 8, 8, 8], 53));
    let transport = match packet
        .dial_udp_transport(node, dns_server, None, timeout)
        .await
    {
        Ok(transport) => transport,
        Err(_) => return Some(Err(ProbeFailureKind::Exchange)),
    };

    let mut rng = rand_seed();
    let id = next_rand(&mut rng) as u16;
    let mut query = vec![
        (id >> 8) as u8,
        id as u8,
        0x01,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    for label in ["google", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);

    let start = Instant::now();
    if transport.send_packet(&query).await.is_err() {
        return Some(Err(ProbeFailureKind::Exchange));
    }
    let mut buf = [0u8; 512];
    match tokio::time::timeout(timeout, transport.recv_packet(&mut buf)).await {
        Ok(Ok((n, _))) if n >= 2 && buf[0] == query[0] && buf[1] == query[1] => {
            Some(Ok(start.elapsed()))
        }
        Ok(Ok(_)) | Ok(Err(_)) => Some(Err(ProbeFailureKind::Exchange)),
        Err(_) => Some(Err(ProbeFailureKind::Timeout)),
    }
}

/// UDP probe for QUIC: run a real QUIC handshake through the node's UDP
/// transport and time it.  Unlike a bare Version-Negotiation trigger (which
/// most frontends silently drop), this proves TLS-in-QUIC reachability
/// through the node's UDP path.
async fn probe_udp_quic(
    registry: &ProxyRegistry,
    node: &Node,
    url_host: &str,
    url_port: u16,
    timeout: Duration,
) -> Option<Result<Duration, ProbeFailureKind>> {
    let Some(entry) = registry.find(node.protocol()) else {
        return Some(Err(ProbeFailureKind::Handler));
    };
    if !(entry.descriptor.supports_udp)(node) {
        return None;
    }
    let packet = entry.packet.as_ref()?;
    let addr = match tokio::net::lookup_host((url_host, url_port)).await {
        Ok(mut addrs) => addrs.find(SocketAddr::is_ipv4)?,
        Err(_) => return Some(Err(ProbeFailureKind::Resolve)),
    };
    let transport = match packet.dial_udp_transport(node, addr, None, timeout).await {
        Ok(transport) => transport,
        Err(_) => return Some(Err(ProbeFailureKind::Exchange)),
    };

    let probe_node = Node {
        outbound: honk_config::node::OutboundConfig::Hysteria2(
            honk_config::node::Hysteria2Config {
                quic: honk_config::node::QuicOptions {
                    tls: honk_config::node::TlsOptions {
                        skip_cert_verify: true,
                        sni: Some(url_host.to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let config = match honk_outbound::quic::client_config(
        &probe_node,
        &[b"h3"],
        honk_outbound::quic::QuicClientOptions::default(),
    )
    .await
    {
        Ok(config) => config,
        Err(_) => return Some(Err(ProbeFailureKind::Exchange)),
    };

    Some(
        honk_outbound::quic::quic_handshake_probe(transport, addr, url_host, &config, timeout)
            .await
            .map_err(|_| ProbeFailureKind::Exchange),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vless_node() -> Node {
        Node {
            name: "vless-test".into(),
            address: "192.0.2.1:443".into(),
            host: "192.0.2.1".into(),
            port: 443,
            outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
                uuid: Some("b831381d-6324-4d53-ad4f-8cda48b30811".into()),
                tls: honk_config::node::TlsOptions {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn registry_contains_node_dependent_vless_udp() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        let entry = registry.find(NodeProtocol::VLess).unwrap();
        assert_eq!(entry.descriptor.protocol, NodeProtocol::VLess);
        assert!(entry.probeable.is_some());
        assert!(entry.packet.is_some());
        let mut node = vless_node();
        assert!(!(entry.descriptor.supports_udp)(&node));
        node.vless_mut().unwrap().mode = WireMode::UotV2;
        assert!((entry.descriptor.supports_udp)(&node));
    }

    #[test]
    fn stdin_subscription_url_rules() {
        assert_eq!(
            parse_subscription_url_from_stdin("  https://example.com/feed?token=value\n").unwrap(),
            "https://example.com/feed?token=value"
        );
        assert_eq!(
            parse_subscription_url_from_stdin("http://127.0.0.1/sub").unwrap(),
            "http://127.0.0.1/sub"
        );
        for invalid in [
            "",
            "   \n",
            "not a URL",
            "ftp://example.com/sub",
            "https:///",
            "https://one.example/sub\nhttps://two.example/sub",
        ] {
            assert_eq!(
                parse_subscription_url_from_stdin(invalid)
                    .unwrap_err()
                    .to_string(),
                "invalid subscription URL from stdin"
            );
        }
    }

    #[test]
    fn vless_probe_eligibility_precedence_and_reasons() {
        assert_eq!(
            classify_vless_node(&vless_node()),
            ProbeEligibility::Supported
        );

        let mut node = vless_node();
        let vless = node.vless_mut().unwrap();
        vless.uuid = None;
        vless.tls.reality_short_id = Some("abc".into());
        assert_eq!(
            classify_vless_node(&node),
            ProbeEligibility::InvalidConfig("invalid-uuid")
        );

        let mut node = vless_node();
        let vless = node.vless_mut().unwrap();
        vless.tls.reality_short_id = Some("abc".into());
        vless.transport.transport = "kcp".into();
        assert_eq!(
            classify_vless_node(&node),
            ProbeEligibility::InvalidConfig("invalid-reality")
        );

        let mut node = vless_node();
        node.vless_mut().unwrap().transport.transport = "kcp".into();
        assert_eq!(
            classify_vless_node(&node),
            ProbeEligibility::ExpectedUnsupported("unsupported-transport")
        );

        let mut node = vless_node();
        node.vless_mut().unwrap().flow = Some("unsupported-flow-value".into());
        assert_eq!(
            classify_vless_node(&node),
            ProbeEligibility::ExpectedUnsupported("unsupported-flow")
        );

        let mut node = vless_node();
        let vless = node.vless_mut().unwrap();
        vless.tls.enabled = false;
        vless.flow = Some("xtls-rprx-vision".into());
        assert_eq!(
            classify_vless_node(&node),
            ProbeEligibility::InvalidConfig("vision-without-tls")
        );

        let mut node = vless_node();
        let vless = node.vless_mut().unwrap();
        vless.transport.transport = "ws".into();
        vless.flow = Some("xtls-rprx-vision".into());
        assert_eq!(
            classify_vless_node(&node),
            ProbeEligibility::ExpectedUnsupported("vision-non-tcp")
        );

        let mut node = vless_node();
        node.name.clear();
        assert_eq!(
            classify_vless_node(&node),
            ProbeEligibility::InvalidConfig("invalid-config")
        );
    }

    #[test]
    fn vless_shapes_are_fixed_and_non_identifying() {
        let mut node = vless_node();
        let vless = node.vless_mut().unwrap();
        vless.tls.enabled = false;
        vless.transport.transport.clear();
        assert_eq!(vless_shape(&node), "vless/plain/tcp");

        node.vless_mut().unwrap().mode = WireMode::Xudp;
        assert_eq!(vless_shape(&node), "vless/plain/tcp/xudp");
        node.vless_mut().unwrap().mode = WireMode::MuxCool;
        assert_eq!(vless_shape(&node), "vless/plain/tcp/mux-cool");
        node.vless_mut().unwrap().mode = WireMode::Legacy;

        let vless = node.vless_mut().unwrap();
        vless.tls.enabled = true;
        vless.transport.transport = "ws".into();
        assert_eq!(vless_shape(&node), "vless/tls/ws");

        let vless = node.vless_mut().unwrap();
        vless.tls.reality_public_key = Some("private-key-material".into());
        vless.transport.transport = "grpc".into();
        vless.flow = Some("xtls-rprx-vision".into());
        assert_eq!(vless_shape(&node), "vless/reality/grpc/vision");

        let vless = node.vless_mut().unwrap();
        vless.transport.transport = "kcp-secret".into();
        vless.flow = Some("provider-flow-secret".into());
        assert_eq!(vless_shape(&node), "vless/reality/unsupported");
    }

    #[test]
    fn vless_udp_is_rendered_as_not_applicable() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        let outcome = ProbeOutcome::timed_out(&registry, &vless_node());
        assert_eq!(outcome.udp_dns, None);
        assert_eq!(outcome.udp_quic, None);
        let rendered = render_outcome(&outcome);
        assert!(rendered.contains("dns: n/a"));
        assert!(rendered.contains("quic: n/a"));
    }

    #[test]
    fn vless_udp_mode_is_rendered_as_probeable() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        let mut node = vless_node();
        node.vless_mut().unwrap().mode = WireMode::H2mux;
        let outcome = ProbeOutcome::timed_out(&registry, &node);
        assert!(matches!(
            outcome.udp_dns,
            Some(Err(ProbeFailureKind::Timeout))
        ));
        assert!(render_outcome(&outcome).contains("dns: FAIL(timeout)"));
        assert_eq!(outcome.shape, "vless/tls/tcp/h2mux");
    }

    #[test]
    fn rendered_failures_exclude_connection_identifiers() {
        let mut node = vless_node();
        node.host = "sentinel-host.invalid".into();
        node.address = "sentinel-host.invalid:443".into();
        let vless = node.vless_mut().unwrap();
        vless.uuid = Some("sentinel-uuid".into());
        vless.tls.sni = Some("sentinel-sni.invalid".into());
        vless.tls.reality_public_key = Some("sentinel-reality-key".into());
        let outcome = ProbeOutcome::skipped(&node, classify_vless_node(&node));
        let rendered = render_outcome(&outcome);
        for sentinel in [
            "https://sentinel-url.invalid/private?token=secret",
            "sentinel-host.invalid",
            "sentinel-uuid",
            "sentinel-sni.invalid",
            "sentinel-reality-key",
        ] {
            assert!(!rendered.contains(sentinel));
        }

        for (kind, expected) in [
            (ProbeFailureKind::Resolve, "FAIL(resolve)"),
            (ProbeFailureKind::Timeout, "FAIL(timeout)"),
            (ProbeFailureKind::Exchange, "FAIL(exchange)"),
            (ProbeFailureKind::Handler, "FAIL(handler)"),
        ] {
            assert_eq!(render_probe_result(&Some(Err(kind)), "n/a"), expected);
        }
    }
}
