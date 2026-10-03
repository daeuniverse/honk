//! On-demand URLTest latency measurement.
//!
//! Dials a liveness URL through a proxy node and reports one **warm-path
//! round trip**: the proxy dial, target TLS handshake, and a first throwaway
//! request are all untimed; only the second configured request is measured.
//! Every protocol therefore reports the same "already-warm node" latency —
//! the number real traffic pays through the connection pool. A second request
//! whose transport fails or times out falls back to the first exchange's time;
//! rejected response heads and bad decoded status codes never do. Successful measurements
//! feed the node's latency history in [`AliveDialerSet`].
//! An arbitrary measurement failure does not alter real dial failure streaks
//! or establish a node-wide outage; configured health probes own liveness.
//!
//! Shared by clash delay measurements and periodic HTTP health checks; their
//! wrappers remain responsible for alive-state updates.
//!
//! Native probes use a caller-owned absolute deadline and cancellation signal;
//! cold probes include connection setup and do not publish legacy health/Score feedback.

use crate::alive::{AliveDialerSet, IpVersion, ProbeCancellation, ProbeDomain, ProbeMeasurement};
use crate::group::{
    GroupManager, ScoreFeedback, ScoreOutcome, ScoreReporter, ScoreSelectionContext, ScoreSource,
    SelectionNetwork,
};
use crate::proxy::{ProxyRegistry, TcpOutbound};
use anyhow::{Context, anyhow};
use honk_config::check::{HttpCheckTarget, decode_health_http_target, decode_http_check_target};
use honk_config::node::Node;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod exchange;
use exchange::{exchange_http1, exchange_http2};

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

fn reporter_success(reporter: &Option<ScoreReporter>) {
    if let Some(reporter) = reporter {
        reporter.finish(ScoreOutcome::Success);
    }
}

/// Default liveness URL (sing-box / clash convention).
pub const DEFAULT_URLTEST_URL: &str = "https://www.gstatic.com/generate_204";

/// Default per-node measurement timeout.
pub const DEFAULT_URLTEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Build a request from one of the canonical HTTP check target decoders.
///
/// The target owns the credential-free authority and raw request target, so
/// URL serialization cannot normalize dot segments or leak user information.
fn build_http_probe_request(
    target: &HttpCheckTarget,
    method: http::Method,
) -> anyhow::Result<http::Request<()>> {
    let scheme = if target.is_https() { "https" } else { "http" };
    let uri = format!(
        "{scheme}://{}{}",
        target.authority(),
        target.request_target()
    );
    http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::USER_AGENT, "honk-http-probe/1.0")
        .body(())
        .context("failed to build HTTP probe request")
}

/// The configured probe method; empty means HEAD.
pub fn probe_method(method: &str) -> anyhow::Result<http::Method> {
    if method.is_empty() {
        return Ok(http::Method::HEAD);
    }
    http::Method::from_bytes(method.as_bytes()).context("invalid HTTP probe method")
}

fn decode_probe_url(url: &str, default_https: bool) -> anyhow::Result<HttpCheckTarget> {
    decode_http_check_target(url, default_https).map_err(|_| anyhow!("invalid HTTP probe URL"))
}

/// Build the URLTest request using HTTPS for schemeless targets.
pub fn http_probe_request(url: &str, method: &str) -> anyhow::Result<http::Request<()>> {
    let target = decode_probe_url(normalize_url(url), true)?;
    build_http_probe_request(&target, probe_method(method)?)
}

/// Build the health-check request using HTTP for schemeless targets and dae's
/// comma-separated literal fallback convention.
pub fn health_http_probe_request(url: &str, method: &str) -> anyhow::Result<http::Request<()>> {
    let target = decode_health_http_target(url).map_err(|_| anyhow!("invalid HTTP probe URL"))?;
    build_http_probe_request(&target, probe_method(method)?)
}

fn request_target(request: &http::Request<()>) -> anyhow::Result<HttpCheckTarget> {
    let uri = request.uri().to_string();
    decode_probe_url(&uri, true)
}

fn normalize_url(url: &str) -> &str {
    let url = url.trim();
    if url.is_empty() {
        DEFAULT_URLTEST_URL
    } else {
        url
    }
}

fn urltest_timeout(timeout: Duration) -> Duration {
    if timeout.is_zero() {
        DEFAULT_URLTEST_TIMEOUT
    } else {
        timeout
    }
}

fn validate_runtime(runtime: &Arc<crate::runtime::NodeRuntime>) -> anyhow::Result<()> {
    crate::runtime::NodeRuntime::validate_for_ephemeral(runtime.node.as_ref())
        .map_err(anyhow::Error::new)
}

/// Optional resolver for check-URL hosts: `(host, port) → Result<addrs>`.
/// honk-core installs the DNS-forwarder-backed resolver so delay
/// measurements share the internal DNS stack; unset means the raw system
/// resolver (tests, tools).
pub type UrltestResolver = Arc<
    dyn Fn(String, u16) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<SocketAddr>>> + Send>>
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
    let timeout = urltest_timeout(timeout);
    let request = http_probe_request(url, "")?;
    urltest_request_impl(
        runtime,
        handler,
        &request,
        timeout,
        &ProbeCancellation::default(),
    )
    .await
}

async fn urltest_request_impl(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    handler: &dyn TcpOutbound,
    request: &http::Request<()>,
    timeout: Duration,
    cancel: &ProbeCancellation,
) -> anyhow::Result<Duration> {
    validate_runtime(runtime)?;
    let target = request_target(request)?;
    let host = target.host();
    let port = target.port();
    let addr = cancel
        .scope_resolution(resolve_urltest_address(host, port))
        .await?;
    measure_http_probe(
        runtime,
        handler,
        request,
        addr,
        Some(host),
        timeout,
        timeout,
        None,
    )
    .await
    .map(|measurement| measurement.latency)
}

async fn resolve_urltest_address(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let hook = URLTEST_RESOLVER.read().clone();
    if let Some(hook) = hook {
        return hook(host.to_string(), port)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"));
    }
    crate::bootstrap::resolve(host)
        .await
        .with_context(|| format!("failed to resolve '{host}:{port}'"))?
        .into_iter()
        .next()
        .map(|ip| SocketAddr::new(ip, port))
        .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"))
}

/// Reuse an already-warm generation runtime; otherwise create a throwaway
/// runtime whose guard closes any session or client established for probing.
pub fn try_probe_runtime(
    generation: &crate::runtime::OutboundRuntimeRegistry,
    node: &Node,
    requirement: crate::proxy::WarmRequirement,
) -> Result<
    (
        Arc<crate::runtime::NodeRuntime>,
        Option<crate::runtime::EphemeralRuntimeGuard>,
    ),
    crate::runtime::RuntimeRegistryError,
> {
    // Validate before looking up a warm runtime: a stale ID must not buy a
    // warm-path shortcut or cause feedback/resources to be initialized.
    crate::runtime::NodeRuntime::validate_for_ephemeral(node)?;
    match generation
        .get(&node.id)
        .filter(|runtime| runtime.is_warm_or_stateless_for(requirement))
    {
        Some(runtime) => Ok((runtime, None)),
        None => {
            let guard = generation.ephemeral_guarded_after_admission(node);
            Ok((guard.runtime(), Some(guard)))
        }
    }
}

/// Prepare a cold reusable transport for one HTTP probe attempt.
///
/// The caller owns generation dial scoping and any ephemeral runtime guard.
pub async fn warm_http_probe(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    warmable: Option<&dyn crate::proxy::WarmableOutbound>,
    connect_timeout: Duration,
    timeout: Duration,
    feedback: Option<ScoreFeedback>,
) -> anyhow::Result<()> {
    validate_runtime(runtime)?;
    if runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session)
        || !crate::descriptor::descriptor(runtime.node.protocol())
            .supports_warm(&runtime.node, crate::proxy::WarmRequirement::Session)
    {
        return Ok(());
    }
    let reporter = start_feedback(feedback);
    let result = match warmable {
        Some(warmable) => {
            let warm = crate::runtime::capture_dial_admission().scope(warmable.warm(
                Arc::clone(runtime),
                connect_timeout,
                crate::proxy::WarmRequirement::Session,
            ));
            match tokio::time::timeout(timeout, warm).await {
                Ok(result) => result,
                Err(_) => Err(phase_timeout("HTTP probe warm-up timed out")),
            }
        }
        None => Err(anyhow!("no warm handler for node '{}'", runtime.node.name)),
    };
    match result {
        Ok(()) => {
            reporter_setup(&reporter);
            if let Some(reporter) = &reporter {
                reporter.finish_setup_only();
            }
            Ok(())
        }
        Err(error) => {
            reporter_error(&reporter, &error);
            Err(error)
        }
    }
}

/// Reuse an already-warm generation runtime. Cold reusable transports warm a
/// throwaway runtime before measurement so a group scan retains no new state.
#[allow(clippy::too_many_arguments)]
pub async fn urltest_node_in_generation_with_feedback(
    generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
    node: &Node,
    handler: &dyn TcpOutbound,
    warmable: Option<&dyn crate::proxy::WarmableOutbound>,
    url: &str,
    timeout: Duration,
    group_manager: &GroupManager,
    cancel: ProbeCancellation,
) -> anyhow::Result<Duration> {
    urltest_node_in_generation_impl(
        generation,
        node,
        handler,
        warmable,
        url,
        timeout,
        Some(group_manager),
        cancel,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn urltest_node_in_generation_impl(
    generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
    node: &Node,
    handler: &dyn TcpOutbound,
    warmable: Option<&dyn crate::proxy::WarmableOutbound>,
    url: &str,
    timeout: Duration,
    group_manager: Option<&GroupManager>,
    cancel: ProbeCancellation,
) -> anyhow::Result<Duration> {
    if cancel.is_cancelled() {
        return Err(crate::proxy::PacketRejection::Cancelled.into());
    }
    let timeout = urltest_timeout(timeout);
    let request = http_probe_request(url, "")?;
    let (runtime, guard) =
        try_probe_runtime(generation, node, crate::proxy::WarmRequirement::Session)?;
    let warm_feedback = if runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session)
    {
        None
    } else {
        group_manager.and_then(|manager| {
            manager
                .feedback_for_node(
                    node.id,
                    ScoreSelectionContext::aggregate(
                        SelectionNetwork::Tcp,
                        ProbeDomain::Tcp,
                        IpVersion::V4,
                    ),
                )
                .map(|feedback| feedback.with_source(ScoreSource::Warmup))
        })
    };
    let result = cancel
        .run(runtime.scope_tasks(generation.scope_dials(Box::pin(async {
            warm_http_probe(&runtime, warmable, timeout, timeout, warm_feedback).await?;
            urltest_request_impl(&runtime, handler, &request, timeout, &cancel).await
        }))))
        .await
        .unwrap_or_else(|| Err(crate::proxy::PacketRejection::Cancelled.into()));
    if let Some(mut guard) = guard
        && guard.close().await.is_err()
    {
        cancel.report_cleanup_failure();
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
    let timeout = urltest_timeout(timeout);
    let request = http_probe_request(url, "")?;
    measure_http_probe(
        runtime, handler, &request, addr, None, timeout, timeout, None,
    )
    .await
    .map(|measurement| measurement.latency)
}

fn phase_timeout(message: &'static str) -> anyhow::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, message).into()
}

/// Dial and perform two bounded HTTP exchanges, returning the warm-path RTT.
/// Uses the request's URI and method; probe headers and the empty body are fixed.
#[allow(clippy::too_many_arguments)]
pub async fn measure_http_probe(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    handler: &dyn TcpOutbound,
    request: &http::Request<()>,
    addr: SocketAddr,
    target_domain: Option<&str>,
    connect_timeout: Duration,
    timeout: Duration,
    feedback: Option<ScoreFeedback>,
) -> anyhow::Result<ProbeMeasurement> {
    measure_http_probe_mode(
        runtime,
        handler,
        request,
        addr,
        target_domain,
        connect_timeout,
        timeout,
        feedback,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn measure_http_probe_mode(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    handler: &dyn TcpOutbound,
    request: &http::Request<()>,
    addr: SocketAddr,
    target_domain: Option<&str>,
    connect_timeout: Duration,
    timeout: Duration,
    feedback: Option<ScoreFeedback>,
    cold: bool,
) -> anyhow::Result<ProbeMeasurement> {
    validate_runtime(runtime)?;
    let target = request_target(request)?;
    let normalized_request = build_http_probe_request(&target, request.method().clone())?;
    let request = &normalized_request;
    let host = target.host();
    let is_https = target.is_https();
    let node = runtime.node.as_ref();
    let reporter = start_feedback(feedback.map(|feedback| {
        feedback.with_probe_identity(&request.uri().to_string(), request.method().as_str())
    }));
    let start = cold.then(Instant::now);
    let result = async {
        // Legacy callers renew each phase budget; native callers also bound
        // this entire future by their absolute deadline.
        let dial = crate::runtime::capture_dial_admission().scope(handler.dial_runtime(
            Arc::clone(runtime),
            addr,
            target_domain,
            connect_timeout,
        ));
        let proxy = tokio::time::timeout(timeout, dial)
            .await
            .map_err(|_| phase_timeout("HTTP probe dial timed out"))??;
        reporter_setup(&reporter);
        tracing::debug!(node = %node.name, %addr, "HTTP probe dial established");
        let stream = proxy.stream;
        if is_https {
            let connector = https_connector()?;
            let tls = tokio::time::timeout(timeout, connector.connect(host, stream))
                .await
                .map_err(|_| phase_timeout("HTTP probe TLS handshake timed out"))?
                .context("HTTP probe TLS handshake failed")?;
            tracing::debug!(
                node = %node.name,
                alpn = ?tls.ssl().selected_alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
                "HTTP probe TLS established"
            );
            match tls.ssl().selected_alpn_protocol() {
                Some(b"h2") => exchange_http2(tls, request, &reporter, timeout, cold).await,
                _ => {
                    let mut tls = tls;
                    exchange_http1(&mut tls, request, &reporter, timeout, cold).await
                }
            }
        } else {
            let mut stream = stream;
            exchange_http1(&mut stream, request, &reporter, timeout, cold).await
        }
    }
    .await;
    match result {
        Ok(mut elapsed) => {
            if let Some(start) = start {
                elapsed.latency = start.elapsed();
            }
            reporter_success(&reporter);
            Ok(elapsed)
        }
        Err(error) => {
            reporter_error(&reporter, &error);
            Err(error)
        }
    }
}

/// Probe one pinned address without resolving or forwarding the request hostname.
///
/// Cold probes time dial, TLS and one configured request; warm probes time the
/// configured request after a validated HEAD. Host/SNI come from the request URI.
/// `timeout` bounds each phase; the caller owns any absolute deadline,
/// cancellation and runtime teardown. HTTP/2 is driven inline, so dropping this
/// future releases its connection without a detached driver task.
#[cfg(feature = "flow-observation")]
pub async fn measure_pinned_http_probe(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    handler: &dyn TcpOutbound,
    request: &http::Request<()>,
    addr: SocketAddr,
    cold: bool,
    timeout: Duration,
) -> anyhow::Result<ProbeMeasurement> {
    measure_http_probe_mode(
        runtime, handler, request, addr, None, timeout, timeout, None, cold,
    )
    .await
}

/// BoringSSL connector with webpki root verification for HTTP probes.
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

/// Measure every member of a group concurrently (at most
/// [`URLTEST_MAX_CONCURRENT`] at a time) and fold the results into the
/// alive set: successes record measured TCP latency. An arbitrary measurement
/// target failing does not establish a real dial failure or node-wide outage.
///
/// Returns one `(node_name, result)` entry per member, in member order.
#[allow(clippy::too_many_arguments)]
pub async fn urltest_group_with_feedback(
    members: &[Node],
    generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
    registry: &Arc<ProxyRegistry>,
    alive_set: &Arc<AliveDialerSet>,
    url: &str,
    timeout: Duration,
    group_manager: Arc<GroupManager>,
    cancel: ProbeCancellation,
) -> Vec<(String, anyhow::Result<Duration>)> {
    urltest_group_impl(
        members,
        generation,
        registry,
        alive_set,
        url,
        timeout,
        Some(group_manager),
        cancel,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn urltest_group_impl(
    members: &[Node],
    generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
    registry: &Arc<ProxyRegistry>,
    alive_set: &Arc<AliveDialerSet>,
    url: &str,
    timeout: Duration,
    group_manager: Option<Arc<GroupManager>>,
    cancel: ProbeCancellation,
) -> Vec<(String, anyhow::Result<Duration>)> {
    let timeout = urltest_timeout(timeout);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(URLTEST_MAX_CONCURRENT));
    let url = url.to_string();
    let mut join_set = tokio::task::JoinSet::new();
    for node in members {
        let node = node.clone();
        let generation = Arc::clone(generation);
        let registry = registry.clone();
        let alive_set = alive_set.clone();
        let url = url.clone();
        let permit = semaphore.clone();
        let group_manager = group_manager.clone();
        let cancel = cancel.clone();
        join_set.spawn(async move {
            let Some(_permit) = cancel.run(permit.acquire_owned()).await else {
                return (
                    node.name.clone(),
                    Err(crate::proxy::PacketRejection::Cancelled.into()),
                );
            };
            let result = match registry.find(node.protocol()) {
                Some(entry) => {
                    urltest_node_in_generation_impl(
                        &generation,
                        &node,
                        entry.tcp.as_ref(),
                        entry.warmable.as_deref(),
                        &url,
                        timeout,
                        group_manager.as_deref(),
                        cancel,
                    )
                    .await
                }
                None => Err(anyhow!("no handler for protocol {:?}", node.protocol())),
            };
            if let Ok(latency) = &result {
                alive_set.record_probe_latency(node.id, ProbeDomain::Tcp, IpVersion::V4, *latency);
            }
            (node.name.clone(), result)
        });
    }
    let mut results = Vec::with_capacity(members.len());
    while let Some(res) = join_set.join_next().await {
        if let Ok(pair) = res {
            results.push(pair);
        } else {
            cancel.report_cleanup_failure();
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

#[cfg(test)]
mod resolver_hook_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod direct_urltest_tests;

#[cfg(test)]
mod fallible_probe_tests;
