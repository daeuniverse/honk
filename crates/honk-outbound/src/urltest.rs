//! On-demand URLTest latency measurement (sing-box `urltest` semantics).
//!
//! Dials a liveness URL through a proxy node and times the exchange up to
//! the response headers: HTTP/1.1 `HEAD /` or a real HTTP/2 request when the
//! server negotiates h2 via ALPN (dispatched per connection — the probe
//! offers `h2,http/1.1` and speaks whichever the server picks, Go-client
//! style). Successful measurements feed the node's latency history in
//! [`AliveDialerSet`]. A lone failure leaves history unchanged; a second
//! consecutive failure adds a synthetic penalty and demotes the node.
//!
//! Used by the clash API delay endpoints; the periodic health check loop in
//! `alive` is unaffected by these ad-hoc measurements.

use crate::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use crate::group::{
    GroupManager, ScoreFeedback, ScoreOutcome, ScoreReporter, ScoreSelectionContext, ScoreTarget,
    SelectionNetwork,
};
use crate::proxy::{ProxyRegistry, TcpOutbound};
use anyhow::{Context, anyhow};
use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(test)]
fn no_feedback() -> Option<ScoreReporter> {
    None
}

fn start_feedback(feedback: Option<ScoreFeedback>) -> Option<ScoreReporter> {
    feedback.map(|feedback| feedback.start())
}

fn reporter_setup(reporter: &Option<ScoreReporter>) {
    if let Some(reporter) = reporter {
        reporter.setup_succeeded();
    }
}

fn reporter_first_response(reporter: &Option<ScoreReporter>) {
    if let Some(reporter) = reporter {
        reporter.first_response();
    }
}

fn reporter_tx(reporter: &Option<ScoreReporter>, bytes: usize) {
    if let Some(reporter) = reporter {
        reporter.tx(bytes as u64);
    }
}

fn reporter_rx(reporter: &Option<ScoreReporter>, bytes: usize) {
    if let Some(reporter) = reporter {
        reporter.rx(bytes as u64);
    }
}

fn reporter_error(reporter: &Option<ScoreReporter>, error: &anyhow::Error) {
    if let Some(reporter) = reporter {
        reporter.finish(ScoreOutcome::from_error(error));
    }
}

fn reporter_timeout(reporter: &Option<ScoreReporter>) {
    if let Some(reporter) = reporter {
        reporter.finish(ScoreOutcome::Timeout);
    }
}

fn reporter_success(reporter: &Option<ScoreReporter>) {
    if let Some(reporter) = reporter {
        reporter.finish(ScoreOutcome::Success);
    }
}

/// Default liveness URL (sing-box / clash convention).
pub const DEFAULT_URLTEST_URL: &str = "https://www.gstatic.com/generate_204";

/// Default per-node measurement timeout.
pub const DEFAULT_URLTEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Optional resolver for check-URL hosts: `(host, port) → addr`.
/// honk-core installs the DNS-forwarder-backed resolver so delay
/// measurements share the internal DNS stack; unset means the raw system
/// resolver (tests, tools).
pub type UrltestResolver = std::sync::Arc<
    dyn Fn(
            String,
            u16,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<SocketAddr>> + Send>>
        + Send
        + Sync,
>;

static URLTEST_RESOLVER: std::sync::LazyLock<parking_lot::RwLock<Option<UrltestResolver>>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(None));

/// Install the resolver used for subsequent [`urltest_node`] measurements.
pub fn set_urltest_resolver(hook: UrltestResolver) {
    *URLTEST_RESOLVER.write() = Some(hook);
}

pub const URLTEST_MAX_CONCURRENT: usize = 10;

pub async fn urltest_node(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    handler: &dyn TcpOutbound,
    url: &str,
    timeout: Duration,
) -> anyhow::Result<Duration> {
    urltest_node_impl(runtime, handler, url, timeout, None).await
}

async fn urltest_node_impl(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    handler: &dyn TcpOutbound,
    url: &str,
    timeout: Duration,
    group_manager: Option<&GroupManager>,
) -> anyhow::Result<Duration> {
    let node = runtime.node.as_ref();
    let url = normalize_url(url);
    let timeout = if timeout.is_zero() {
        DEFAULT_URLTEST_TIMEOUT
    } else {
        timeout
    };
    if node.protocol == honk_config::types::NodeProtocol::Direct {
        let (host, port, is_https) = parse_url_host_port(url)?;
        let addr = {
            let hook = URLTEST_RESOLVER.read().clone();
            match hook {
                Some(hook) => hook(host.clone(), port)
                    .await
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"))?,
                None => crate::bootstrap::resolve(&host)
                    .await
                    .with_context(|| format!("failed to resolve '{host}:{port}'"))?
                    .into_iter()
                    .next()
                    .map(|ip| SocketAddr::new(ip, port))
                    .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"))?,
            }
        };
        let feedback = group_manager.and_then(|manager| {
            let family = if addr.is_ipv6() {
                IpVersion::V6
            } else {
                IpVersion::V4
            };
            let target = host
                .parse::<std::net::IpAddr>()
                .map_or_else(|_| ScoreTarget::domain(&host, port), |_| addr.into());
            manager.feedback_for_node(
                node.id,
                ScoreSelectionContext {
                    network: SelectionNetwork::Tcp,
                    probe_domain: ProbeDomain::Tcp,
                    target_family: Some(family),
                    health_family: family,
                    target: Some(target),
                },
            )
        });
        return measure_head_exchange(
            runtime,
            handler,
            &host,
            Some(&host),
            is_https,
            addr,
            timeout,
            feedback,
        )
        .await;
    }
    let (host, port, is_https) = parse_url_host_port(url)?;
    let addr = {
        let hook = URLTEST_RESOLVER.read().clone();
        match hook {
            Some(hook) => hook(host.clone(), port)
                .await
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"))?,
            None => tokio::net::lookup_host(format!("{host}:{port}"))
                .await
                .with_context(|| format!("failed to resolve '{host}:{port}'"))?
                .next()
                .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"))?,
        }
    };
    let feedback = group_manager.and_then(|manager| {
        let family = if addr.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let target = host
            .parse::<std::net::IpAddr>()
            .map_or_else(|_| ScoreTarget::domain(&host, port), |_| addr.into());
        manager.feedback_for_node(
            node.id,
            ScoreSelectionContext {
                network: SelectionNetwork::Tcp,
                probe_domain: ProbeDomain::Tcp,
                target_family: Some(family),
                health_family: family,
                target: Some(target),
            },
        )
    });
    measure_head_exchange(
        runtime,
        handler,
        &host,
        Some(&host),
        is_https,
        addr,
        timeout,
        feedback,
    )
    .await
}
/// Reuse an already-warm generation runtime; otherwise create a throwaway
/// runtime whose guard closes any session or client established for probing.
pub fn probe_runtime(
    generation: &crate::runtime::OutboundRuntimeRegistry,
    node: &Node,
) -> (
    Arc<crate::runtime::NodeRuntime>,
    Option<crate::runtime::EphemeralRuntimeGuard>,
) {
    match generation
        .get(&node.id)
        .filter(|runtime| runtime.is_warm_or_stateless())
    {
        Some(runtime) => (runtime, None),
        None => {
            let guard = crate::runtime::NodeRuntime::ephemeral_guarded(node);
            (guard.runtime(), Some(guard))
        }
    }
}

/// Reuse an already-warm generation runtime. Cold reusable transports warm a
/// throwaway runtime before measurement so a group scan retains no new state.
pub async fn urltest_node_in_generation_with_feedback(
    generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
    node: &Node,
    handler: &dyn TcpOutbound,
    warmable: Option<&dyn crate::proxy::WarmableOutbound>,
    url: &str,
    timeout: Duration,
    group_manager: &GroupManager,
) -> anyhow::Result<Duration> {
    urltest_node_in_generation_impl(
        generation,
        node,
        handler,
        warmable,
        url,
        timeout,
        Some(group_manager),
    )
    .await
}

async fn urltest_node_in_generation_impl(
    generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
    node: &Node,
    handler: &dyn TcpOutbound,
    warmable: Option<&dyn crate::proxy::WarmableOutbound>,
    url: &str,
    timeout: Duration,
    group_manager: Option<&GroupManager>,
) -> anyhow::Result<Duration> {
    let timeout = if timeout.is_zero() {
        DEFAULT_URLTEST_TIMEOUT
    } else {
        timeout
    };
    let (runtime, guard) = probe_runtime(generation, node);
    let result = generation
        .scope_dials(async {
            if !runtime.is_warm_or_stateless() {
                let warm_reporter = start_feedback(group_manager.and_then(|manager| {
                    manager.feedback_for_node(
                        node.id,
                        ScoreSelectionContext::aggregate(
                            SelectionNetwork::Tcp,
                            ProbeDomain::Tcp,
                            IpVersion::V4,
                        ),
                    )
                }));
                let warmed = match warmable {
                    Some(warmable) => {
                        crate::runtime::capture_dial_admission()
                            .scope(warmable.warm(
                                Arc::clone(&runtime),
                                timeout,
                                crate::proxy::WarmRequirement::Session,
                            ))
                            .await
                    }
                    None => Err(anyhow!("no warm handler for node '{}'", node.name)),
                };
                match warmed {
                    Ok(()) => {
                        reporter_setup(&warm_reporter);
                        reporter_success(&warm_reporter);
                    }
                    Err(error) => {
                        reporter_error(&warm_reporter, &error);
                        return Err(error);
                    }
                }
            }
            urltest_node_impl(&runtime, handler, url, timeout, group_manager).await
        })
        .await;
    if let Some(guard) = guard {
        guard.close().await;
    }
    result
}

/// [`urltest_node`] with a caller-chosen destination address (e.g. an
/// explicit v4/v6 target) — TLS SNI/Host still come from `url`.
pub async fn urltest_node_addr(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    handler: &dyn TcpOutbound,
    url: &str,
    addr: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<Duration> {
    let url = normalize_url(url);
    let (host, _, is_https) = parse_url_host_port(url)?;
    measure_head_exchange(runtime, handler, &host, None, is_https, addr, timeout, None).await
}

/// Dial `addr` through the node and time the full exchange up to the first
/// response bytes (TLS handshake + HEAD for https, plain HEAD for http).
#[allow(clippy::too_many_arguments)]
async fn measure_head_exchange(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    handler: &dyn TcpOutbound,
    host: &str,
    target_domain: Option<&str>,
    is_https: bool,
    addr: SocketAddr,
    timeout: Duration,
    feedback: Option<ScoreFeedback>,
) -> anyhow::Result<Duration> {
    let node = runtime.node.as_ref();
    let reporter = start_feedback(feedback);
    let timed = async {
        let mut start = Instant::now();
        let proxy = match crate::runtime::capture_dial_admission()
            .scope(handler.dial_runtime(Arc::clone(runtime), addr, target_domain, timeout))
            .await
        {
            Ok(proxy) => proxy,
            Err(error) => {
                reporter_error(&reporter, &error);
                return Err(error);
            }
        };
        reporter_setup(&reporter);
        tracing::debug!(node = %node.name, %addr, "urltest: dial established");
        if matches!(node.protocol, honk_config::types::NodeProtocol::Hysteria2) {
            start = Instant::now();
        }
        let stream = proxy.stream;
        let result = async {
            if is_https {
                let connector = https_connector()?;
                let tls = connector.connect(host, stream).await.context("TLS handshake failed")?;
                tracing::debug!(
                    node = %node.name,
                    alpn = ?tls.ssl().selected_alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
                    "urltest: TLS established"
                );
                match tls.ssl().selected_alpn_protocol() {
                    Some(b"h2") => exchange_head_h2(tls, host, &reporter).await,
                    _ => { let mut tls = tls; exchange_head(&mut tls, host, &reporter).await }
                }
            } else {
                let mut stream = stream;
                exchange_head(&mut stream, host, &reporter).await
            }
        }.await;
        match result {
            Ok(()) => {
                reporter_success(&reporter);
                Ok(start.elapsed())
            }
            Err(error) => {
                reporter_error(&reporter, &error);
                Err(error)
            }
        }
    };
    match tokio::time::timeout(timeout, timed).await {
        Ok(result) => result,
        Err(_) => {
            reporter_timeout(&reporter);
            Err(anyhow!("urltest timed out after {:?}", timeout))
        }
    }
}

/// BoringSSL connector with webpki root verification for urltest.
/// Built once and reused across measurements (it never changes at runtime).
/// Offers `h2,http/1.1`; the exchange dispatches on the negotiated ALPN.
fn https_connector() -> anyhow::Result<crate::tls::TlsConnector> {
    static CONNECTOR: std::sync::OnceLock<anyhow::Result<crate::tls::TlsConnector>> =
        std::sync::OnceLock::new();
    let connector = CONNECTOR.get_or_init(|| crate::tls::build_http_probe_connector(false));
    match connector {
        Ok(c) => Ok(c.clone()),
        Err(e) => Err(anyhow!("failed to build urltest TLS connector: {e:#}")),
    }
}

/// HTTP/2 variant of [`exchange_head`]: one HEAD request over a fresh H2
/// session (same layer as the DoH transport), resolved when the response
/// HEADERS arrive — the same measurement point as the HTTP/1.1 path.
async fn exchange_head_h2<S>(
    stream: S,
    host: &str,
    reporter: &Option<ScoreReporter>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = h2::client::handshake(stream)
        .await
        .map_err(|e| anyhow!("HTTP/2 handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = http::Request::builder()
        .method("HEAD")
        .uri(format!("https://{host}/"))
        .header("user-agent", "honk-urltest/1.0")
        .body(())
        .map_err(|e| anyhow!("h2 request build: {e}"))?;
    let (response_fut, _send_stream) = sender
        .send_request(req, true)
        .map_err(|e| anyhow!("h2 send_request: {e}"))?;
    reporter_tx(reporter, host.len().saturating_add(1));
    let response = response_fut
        .await
        .map_err(|e| anyhow!("h2 response: {e}"))?;
    reporter_first_response(reporter);
    reporter_rx(reporter, 1);
    let code = response.status().as_u16();
    if !(200..500).contains(&code) {
        return Err(anyhow!("bad status code: {}", code));
    }
    Ok(())
}

/// Send a minimal HTTP/1.1 HEAD request and wait for the response
/// headers, validating the status line (200–499 counts as reachable).
async fn exchange_head<S>(
    stream: &mut S,
    host: &str,
    reporter: &Option<ScoreReporter>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: honk-urltest/1.0\r\nConnection: close\r\n\r\n",
        host
    );
    stream.write_all(request.as_bytes()).await?;
    reporter_tx(reporter, request.len());
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.is_empty() {
            reporter_first_response(reporter);
        }
        reporter_rx(reporter, n);
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 16 * 1024 {
            break;
        }
    }
    validate_status(&buf)
}

/// Measure every member of a group concurrently (at most
/// [`URLTEST_MAX_CONCURRENT`] at a time) and fold the results into the
/// alive set: successes record the measured TCP latency; only a second
/// consecutive failure adds a synthetic penalty and demotes the node.
///
/// Returns one `(node_name, result)` entry per member, in member order.
pub async fn urltest_group_with_feedback(
    members: &[Node],
    generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
    registry: &Arc<ProxyRegistry>,
    alive_set: &Arc<AliveDialerSet>,
    url: &str,
    timeout: Duration,
    group_manager: Arc<GroupManager>,
) -> Vec<(String, anyhow::Result<Duration>)> {
    urltest_group_impl(
        members,
        generation,
        registry,
        alive_set,
        url,
        timeout,
        Some(group_manager),
    )
    .await
}

async fn urltest_group_impl(
    members: &[Node],
    generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
    registry: &Arc<ProxyRegistry>,
    alive_set: &Arc<AliveDialerSet>,
    url: &str,
    timeout: Duration,
    group_manager: Option<Arc<GroupManager>>,
) -> Vec<(String, anyhow::Result<Duration>)> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(URLTEST_MAX_CONCURRENT));
    let url = normalize_url(url).to_string();
    let mut join_set = tokio::task::JoinSet::new();
    for node in members {
        let node = node.clone();
        let generation = Arc::clone(generation);
        let registry = registry.clone();
        let alive_set = alive_set.clone();
        let url = url.clone();
        let permit = semaphore.clone();
        let group_manager = group_manager.clone();
        join_set.spawn(async move {
            let _permit = permit.acquire_owned().await;
            let result = match registry.find(node.protocol) {
                Some(entry) => {
                    urltest_node_in_generation_impl(
                        &generation,
                        &node,
                        entry.tcp.as_ref(),
                        entry.warmable.as_deref(),
                        &url,
                        timeout,
                        group_manager.as_deref(),
                    )
                    .await
                }
                None => Err(anyhow!("no handler for protocol {:?}", node.protocol)),
            };
            match &result {
                Ok(latency) => alive_set.record_probe_latency(
                    node.id,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                    *latency,
                ),
                Err(_) => alive_set.record_dial_failure(node.id, ProbeDomain::Tcp, IpVersion::V4),
            }
            (node.name.clone(), result)
        });
    }
    let mut results = Vec::with_capacity(members.len());
    while let Some(res) = join_set.join_next().await {
        if let Ok(pair) = res {
            results.push(pair);
        }
    }
    let order: std::collections::HashMap<&str, usize> = members
        .iter()
        .enumerate()
        .map(|(i, n)| (n.name.as_str(), i))
        .collect();
    results.sort_by_key(|(name, _)| order.get(name.as_str()).copied().unwrap_or(usize::MAX));
    results
}

/// Empty URLs fall back to the default HTTPS liveness URL; an explicit
/// URL (http or https) is always honored as given.
fn normalize_url(url: &str) -> &str {
    let url = url.trim();
    if url.is_empty() {
        DEFAULT_URLTEST_URL
    } else {
        url
    }
}

fn parse_url_host_port(url: &str) -> anyhow::Result<(String, u16, bool)> {
    let (default_port, rest, is_https) = if let Some(r) = url.strip_prefix("https://") {
        (443u16, r, true)
    } else if let Some(r) = url.strip_prefix("http://") {
        (80u16, r, false)
    } else {
        (443u16, url, true)
    };
    let authority = rest.split('/').next().unwrap_or(rest).trim();
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid bracketed host in URL '{}'", url))?;
        if host.is_empty() {
            return Err(anyhow!("empty host in URL '{}'", url));
        }
        let port = match tail {
            "" => default_port,
            tail => tail
                .strip_prefix(':')
                .ok_or_else(|| anyhow!("invalid bracketed host in URL '{}'", url))?
                .parse::<u16>()
                .with_context(|| format!("invalid port in URL '{}'", url))?,
        };
        return Ok((host.to_string(), port, is_https));
    }
    if let Some((host, port)) = authority.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        if host.is_empty() {
            return Err(anyhow!("empty host in URL '{}'", url));
        }
        return Ok((host.to_string(), port, is_https));
    }
    if authority.is_empty() {
        return Err(anyhow!("empty host in URL '{}'", url));
    }
    Ok((authority.to_string(), default_port, is_https))
}

fn validate_status(buf: &[u8]) -> anyhow::Result<()> {
    let line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let status_line = String::from_utf8_lossy(&buf[..line_end]);
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(anyhow!("malformed HTTP response: '{}'", status_line.trim()));
    }
    let code: u16 = parts
        .next()
        .ok_or_else(|| anyhow!("missing status code in '{}'", status_line.trim()))?
        .parse()
        .context("invalid status code")?;
    if !(200..500).contains(&code) {
        return Err(anyhow!("bad status code: {}", code));
    }
    Ok(())
}

#[cfg(test)]
mod resolver_hook_tests {
    use super::*;

    /// The installed hook is consulted before the system resolver.
    #[tokio::test]
    async fn hook_supplies_urltest_addresses() {
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called2 = called.clone();
        set_urltest_resolver(std::sync::Arc::new(move |host, port| {
            let called2 = called2.clone();
            Box::pin(async move {
                // Other urltest tests run concurrently against this global
                // hook — answer only our host, pass foreigners through to
                // the system resolver instead of breaking their dials.
                if host == "example.invalid" && port == 443 {
                    called2.store(true, std::sync::atomic::Ordering::Relaxed);
                    vec!["127.0.0.1:443".parse().unwrap()]
                } else {
                    tokio::net::lookup_host(format!("{host}:{port}"))
                        .await
                        .map(|addrs| addrs.collect())
                        .unwrap_or_default()
                }
            })
        }));
        let node = Node::default();
        // The dial itself fails (nothing on 127.0.0.1:443) but the hook
        // must have been consulted first.
        let handler = crate::proxy::direct::DirectHandler::new();
        let _ = urltest_node(
            &crate::runtime::NodeRuntime::ephemeral(&node),
            &handler,
            "https://example.invalid/",
            Duration::from_millis(50),
        )
        .await;
        assert!(called.load(std::sync::atomic::Ordering::Relaxed));
        *URLTEST_RESOLVER.write() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ProxyStream;
    use honk_config::types::NodeProtocol;
    use std::net::SocketAddr;

    /// Mock handler: dials the requested target with a plain TcpStream
    /// (no proxy protocol, no SO_MARK). Nodes named "bad" always fail.
    struct MockHandler;

    #[async_trait::async_trait]
    impl TcpOutbound for MockHandler {
        async fn dial(
            &self,
            node: &Node,
            target: SocketAddr,
            target_domain: Option<&str>,
            _connect_timeout: Duration,
        ) -> anyhow::Result<ProxyStream> {
            if node.name == "bad" {
                return Err(anyhow!("simulated dial failure"));
            }
            let stream = tokio::net::TcpStream::connect(target).await?;
            Ok(ProxyStream {
                stream: Box::new(stream),
                target_addr: target,
                target_domain: target_domain.map(|s| s.to_string()),
            })
        }
    }

    struct DelayedDialHandler {
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl TcpOutbound for DelayedDialHandler {
        async fn dial(
            &self,
            _node: &Node,
            target: SocketAddr,
            target_domain: Option<&str>,
            _connect_timeout: Duration,
        ) -> anyhow::Result<ProxyStream> {
            tokio::time::sleep(self.delay).await;
            let stream = tokio::net::TcpStream::connect(target).await?;
            Ok(ProxyStream {
                stream: Box::new(stream),
                target_addr: target,
                target_domain: target_domain.map(str::to_string),
            })
        }
    }

    fn make_node(name: &str) -> Node {
        Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            protocol: NodeProtocol::Socks5,
            ..Default::default()
        }
    }

    struct RecordingWarmable {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        fail: bool,
        ephemeral: Arc<std::sync::atomic::AtomicBool>,
    }

    struct DelayedWarmable {
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl crate::proxy::WarmableOutbound for DelayedWarmable {
        async fn warm(
            &self,
            _runtime: Arc<crate::runtime::NodeRuntime>,
            _connect_timeout: Duration,
            requirement: crate::proxy::WarmRequirement,
        ) -> anyhow::Result<()> {
            assert_eq!(requirement, crate::proxy::WarmRequirement::Session);
            tokio::time::sleep(self.delay).await;
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl crate::proxy::WarmableOutbound for RecordingWarmable {
        async fn warm(
            &self,
            runtime: Arc<crate::runtime::NodeRuntime>,
            _connect_timeout: Duration,
            requirement: crate::proxy::WarmRequirement,
        ) -> anyhow::Result<()> {
            assert_eq!(requirement, crate::proxy::WarmRequirement::Session);
            self.ephemeral
                .store(runtime.is_ephemeral(), std::sync::atomic::Ordering::Relaxed);
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.fail {
                anyhow::bail!("simulated warm failure");
            }
            Ok(())
        }
    }

    fn reusable_node(name: &str, protocol: NodeProtocol) -> Node {
        let mut node = make_node(name);
        node.protocol = protocol;
        if protocol == NodeProtocol::VLess {
            node.vless_mode = honk_config::node::WireMode::H2mux;
        }
        node
    }

    #[test]
    fn probe_runtime_reuses_only_warm_or_stateless_nodes() {
        let anytls = reusable_node("anytls", NodeProtocol::AnyTLS);
        let trojan = reusable_node("trojan", NodeProtocol::Trojan);
        let absent = reusable_node("absent", NodeProtocol::SS);
        let generation =
            crate::runtime::OutboundRuntimeRegistry::build(&[anytls.clone(), trojan.clone()])
                .unwrap();

        assert!(probe_runtime(&generation, &anytls).1.is_some());
        assert!(probe_runtime(&generation, &absent).1.is_some());
        let (runtime, guard) = probe_runtime(&generation, &trojan);
        assert!(Arc::ptr_eq(&runtime, &generation.get(&trojan.id).unwrap()));
        assert!(guard.is_none());
    }

    async fn assert_cold_reusable_transport_warms_before_measurement(node: Node) {
        let addr = spawn_mock_http_server().await;
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ephemeral = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let warmable = RecordingWarmable {
            calls: Arc::clone(&calls),
            fail: false,
            ephemeral: Arc::clone(&ephemeral),
        };

        urltest_node_in_generation_impl(
            &generation,
            &node,
            &MockHandler,
            Some(&warmable),
            &format!("http://{addr}/"),
            Duration::from_secs(1),
            None,
        )
        .await
        .unwrap();

        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(ephemeral.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn cold_anytls_warms_before_measurement() {
        assert_cold_reusable_transport_warms_before_measurement(reusable_node(
            "anytls",
            NodeProtocol::AnyTLS,
        ))
        .await;
    }

    #[cfg(feature = "rprx")]
    #[tokio::test]
    async fn cold_vless_mux_warms_before_measurement() {
        assert_cold_reusable_transport_warms_before_measurement(reusable_node(
            "vless",
            NodeProtocol::VLess,
        ))
        .await;
    }

    #[tokio::test]
    async fn cold_quic_protocols_warm_before_measurement() {
        for (name, protocol) in [
            ("hysteria2", NodeProtocol::Hysteria2),
            ("tuic", NodeProtocol::Tuic),
            ("juicity", NodeProtocol::Juicity),
        ] {
            assert_cold_reusable_transport_warms_before_measurement(reusable_node(name, protocol))
                .await;
        }
    }

    #[tokio::test]
    async fn cold_quic_warm_time_is_not_reported() {
        let addr = spawn_mock_http_server().await;
        for (name, protocol) in [
            ("hysteria2", NodeProtocol::Hysteria2),
            ("tuic", NodeProtocol::Tuic),
            ("juicity", NodeProtocol::Juicity),
        ] {
            let node = reusable_node(name, protocol);
            let generation = Arc::new(
                crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                    .unwrap(),
            );
            let elapsed = urltest_node_in_generation_impl(
                &generation,
                &node,
                &MockHandler,
                Some(&DelayedWarmable {
                    delay: Duration::from_millis(100),
                }),
                &format!("http://{addr}/"),
                Duration::from_secs(1),
                None,
            )
            .await
            .unwrap();

            assert!(elapsed < Duration::from_millis(50), "{name}: {elapsed:?}");
        }
    }

    #[cfg(feature = "rprx")]
    #[tokio::test]
    async fn cold_vless_mux_warm_failure_skips_measurement() {
        let node = reusable_node("vless", NodeProtocol::VLess);
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ephemeral = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let warmable = RecordingWarmable {
            calls: Arc::clone(&calls),
            fail: true,
            ephemeral: Arc::clone(&ephemeral),
        };

        let error = urltest_node_in_generation_impl(
            &generation,
            &node,
            &DelayedDialHandler {
                delay: Duration::from_secs(10),
            },
            Some(&warmable),
            "http://localhost/",
            Duration::from_millis(50),
            None,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("simulated warm failure"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(ephemeral.load(std::sync::atomic::Ordering::Relaxed));
    }

    struct RecordingHandler {
        target_domains: Arc<parking_lot::Mutex<Vec<Option<String>>>>,
        client_hellos: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl TcpOutbound for RecordingHandler {
        async fn dial(
            &self,
            _node: &Node,
            target: SocketAddr,
            target_domain: Option<&str>,
            _connect_timeout: Duration,
        ) -> anyhow::Result<ProxyStream> {
            self.target_domains
                .lock()
                .push(target_domain.map(str::to_string));
            let (client, mut server) = tokio::io::duplex(16 * 1024);
            let client_hellos = self.client_hellos.clone();
            tokio::spawn(async move {
                let mut bytes = vec![0_u8; 16 * 1024];
                let size = server.read(&mut bytes).await.unwrap_or(0);
                bytes.truncate(size);
                let _ = client_hellos.send(bytes);
            });
            Ok(ProxyStream {
                stream: Box::new(client),
                target_addr: target,
                target_domain: target_domain.map(str::to_string),
            })
        }
    }

    #[tokio::test]
    async fn urltest_distinguishes_domain_and_address_targets() {
        let target_domains = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let (client_hellos, mut recorded_hellos) = tokio::sync::mpsc::unbounded_channel();
        let handler = RecordingHandler {
            target_domains: Arc::clone(&target_domains),
            client_hellos,
        };
        let node = make_node("recording");
        let runtime = crate::runtime::NodeRuntime::ephemeral(&node);
        let url = "https://localhost/";

        let _ = urltest_node(&runtime, &handler, url, Duration::from_secs(2)).await;
        let domain_hello = tokio::time::timeout(Duration::from_secs(1), recorded_hellos.recv())
            .await
            .unwrap()
            .unwrap();
        let _ = urltest_node_addr(
            &runtime,
            &handler,
            url,
            "127.0.0.1:443".parse().unwrap(),
            Duration::from_secs(2),
        )
        .await;
        let address_hello = tokio::time::timeout(Duration::from_secs(1), recorded_hellos.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            *target_domains.lock(),
            vec![Some("localhost".to_string()), None]
        );
        for hello in [domain_hello, address_hello] {
            assert!(
                hello
                    .windows(b"localhost".len())
                    .any(|part| part == b"localhost")
            );
        }

        let (mut client, mut server) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut request = [0_u8; 1024];
            let size = server.read(&mut request).await.unwrap();
            assert!(
                request[..size]
                    .windows(b"Host: localhost\r\n".len())
                    .any(|part| { part == b"Host: localhost\r\n" })
            );
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        exchange_head(&mut client, "localhost", &no_feedback())
            .await
            .unwrap();
        server.await.unwrap();
    }

    /// Spawn a minimal HTTP server answering every request with 204.
    async fn spawn_mock_http_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        addr
    }

    /// Spawn a minimal HTTP/2 server answering every request with 204.
    async fn spawn_h2_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(sock).await.unwrap();
                    while let Some(result) = conn.accept().await {
                        let (_request, mut respond) = result.unwrap();
                        let response = http::Response::builder().status(204).body(()).unwrap();
                        respond.send_response(response, true).unwrap();
                    }
                });
            }
        });
        addr
    }

    /// The h2 probe path completes against an h2-only server — this is the
    /// gstatic case that used to fail with "malformed HTTP response".
    #[tokio::test]
    async fn test_exchange_head_h2() {
        let addr = spawn_h2_server().await;
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        exchange_head_h2(stream, "localhost", &no_feedback())
            .await
            .expect("h2 HEAD exchange must succeed");

        // A non-2xx..4xx status is a measurement failure.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(sock).await.unwrap();
            let (_req, mut respond) = conn.accept().await.unwrap().unwrap();
            let response = http::Response::builder().status(500).body(()).unwrap();
            respond.send_response(response, true).unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            exchange_head_h2(stream, "localhost", &no_feedback())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn hysteria2_excludes_pre_write_dial_time() {
        let addr = spawn_mock_http_server().await;
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "hysteria2".into(),
            protocol: NodeProtocol::Hysteria2,
            ..Default::default()
        };
        let elapsed = urltest_node_addr(
            &crate::runtime::NodeRuntime::ephemeral(&node),
            &DelayedDialHandler {
                delay: Duration::from_millis(100),
            },
            "http://localhost/",
            addr,
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        assert!(elapsed < Duration::from_millis(50), "{elapsed:?}");
    }
    #[test]
    fn test_normalize_and_parse_url() {
        assert_eq!(normalize_url(""), DEFAULT_URLTEST_URL);

        assert_eq!(
            normalize_url("http://www.gstatic.com/generate_204"),
            "http://www.gstatic.com/generate_204"
        );
        assert_eq!(
            normalize_url("https://example.com/x"),
            "https://example.com/x"
        );

        assert_eq!(
            parse_url_host_port(DEFAULT_URLTEST_URL).unwrap(),
            ("www.gstatic.com".to_string(), 443, true)
        );
        assert_eq!(
            parse_url_host_port("https://127.0.0.1:8080/").unwrap(),
            ("127.0.0.1".to_string(), 8080, true)
        );
        assert_eq!(
            parse_url_host_port("https://[::1]/").unwrap(),
            ("::1".to_string(), 443, true)
        );
        assert_eq!(
            parse_url_host_port("http://[::1]:8080/").unwrap(),
            ("::1".to_string(), 8080, false)
        );
        // Schemeless URLs are treated as https on port 443.
        assert_eq!(
            parse_url_host_port("example.com/204").unwrap(),
            ("example.com".to_string(), 443, true)
        );
        assert!(parse_url_host_port("https://").is_err());
    }

    /// The HEAD exchange itself is protocol-agnostic; exercise it over a
    /// plain stream against a local HTTP server.
    #[tokio::test]
    async fn test_exchange_head_plain_http() {
        let addr = spawn_mock_http_server().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        exchange_head(&mut stream, "localhost", &no_feedback())
            .await
            .expect("HEAD exchange against local HTTP server should succeed");
    }

    /// Regression test for the plaintext-over-443 bug: an https URL must
    /// run a real TLS handshake, so a plaintext HTTP server fails the
    /// measurement instead of answering a cleartext HEAD.
    #[tokio::test]
    async fn test_urltest_node_https_requires_tls() {
        let addr = spawn_mock_http_server().await;
        let node = make_node("good");
        let handler = MockHandler;
        let url = format!("https://{}:{}/", addr.ip(), addr.port());

        let result = urltest_node(
            &crate::runtime::NodeRuntime::ephemeral(&node),
            &handler,
            &url,
            Duration::from_secs(5),
        )
        .await;
        assert!(
            result.is_err(),
            "https measurement against a plaintext server must fail"
        );
    }

    #[tokio::test]
    async fn test_urltest_node_failure() {
        // Nothing listens on 127.0.0.1:1 → dial fails.
        let node = make_node("good");
        let handler = MockHandler;
        let result = urltest_node(
            &crate::runtime::NodeRuntime::ephemeral(&node),
            &handler,
            "https://127.0.0.1:1/",
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_err());

        // A node named "bad" fails inside the handler.
        let bad = make_node("bad");
        let result = urltest_node(
            &crate::runtime::NodeRuntime::ephemeral(&bad),
            &handler,
            "https://127.0.0.1:1/",
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_urltest_group_marks_failure_with_synthetic_sample() {
        // Plaintext HTTP server: every https measurement fails the TLS
        // handshake, so two consecutive failing group runs must append a
        // synthetic penalty sample for both the dial-failing and the
        // handshake-failing member (a lone transient failure strikes
        // nothing).
        let addr = spawn_mock_http_server().await;
        let url = format!("https://{}:{}/", addr.ip(), addr.port());

        let mut registry = ProxyRegistry::new();
        registry.register(crate::proxy::ProtocolEntry::new(
            NodeProtocol::Socks5,
            Arc::new(MockHandler),
        ));
        let registry = Arc::new(registry);
        let alive_set = Arc::new(AliveDialerSet::new());

        let members = vec![make_node("good"), make_node("bad")];
        for m in &members {
            alive_set.record_probe_latency(
                m.id,
                ProbeDomain::Tcp,
                IpVersion::V4,
                Duration::from_millis(999),
            );
        }

        let runtime = Arc::new(crate::runtime::OutboundRuntimeRegistry::build(&members).unwrap());
        let results = urltest_group_impl(
            &members,
            &runtime,
            &registry,
            &alive_set,
            &url,
            Duration::from_secs(5),
            None,
        )
        .await;
        assert_eq!(results.len(), 2);
        // Member order preserved.
        assert_eq!(results[0].0, "good");
        assert_eq!(results[1].0, "bad");
        assert!(results[0].1.is_err());
        assert!(results[1].1.is_err());

        // One failed run leaves no selection state.
        for m in &members {
            assert!(!alive_set.is_failure_demoted(m.id, ProbeDomain::Tcp, IpVersion::V4));
        }

        let results = urltest_group_impl(
            &members,
            &runtime,
            &registry,
            &alive_set,
            &url,
            Duration::from_secs(5),
            None,
        )
        .await;
        assert!(results.iter().all(|(_, r)| r.is_err()));

        // The second consecutive failure → synthetic penalty sample on top
        // of the retained history: the latest sample is the 10s placeholder
        // (display-only) and a failure strike demotes the node, while the
        // real 999ms moving average survives unpoisoned.
        for m in &members {
            assert_eq!(
                alive_set.get_last_latency(m.id, ProbeDomain::Tcp, IpVersion::V4),
                Some(Duration::from_secs(10))
            );
            assert!(alive_set.is_failure_demoted(m.id, ProbeDomain::Tcp, IpVersion::V4));
            assert_eq!(
                alive_set.get_moving_average(m.id, ProbeDomain::Tcp, IpVersion::V4),
                Some(Duration::from_millis(999))
            );
        }
    }
}

#[cfg(test)]
mod direct_urltest_tests {
    use super::*;

    #[tokio::test]
    async fn direct_urltest_measures_requested_url() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let n = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..n]).starts_with("HEAD / HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let node = Node {
            name: honk_config::Config::BUILTIN_DIRECT_NODE.to_string(),
            protocol: honk_config::types::NodeProtocol::Direct,
            ..Default::default()
        };
        let handler = crate::proxy::direct::DirectHandler::new();
        let latency = urltest_node(
            &crate::runtime::NodeRuntime::ephemeral(&node),
            &handler,
            &format!("http://{addr}/requested"),
            Duration::from_secs(2),
        )
        .await
        .expect("direct urltest must exchange with the requested URL");
        assert!(latency < Duration::from_secs(2));
    }
}
