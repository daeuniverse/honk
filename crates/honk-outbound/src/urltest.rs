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
//! A lone failure leaves history unchanged; a second consecutive failure adds
//! a synthetic penalty and demotes the node.
//!
//! Shared by clash delay measurements and periodic HTTP health checks; their
//! wrappers remain responsible for alive-state updates.

use crate::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use crate::group::{
    GroupManager, ScoreFeedback, ScoreOutcome, ScoreReporter, ScoreSelectionContext, ScoreTarget,
    SelectionNetwork,
};
use crate::proxy::{ProxyRegistry, TcpOutbound};
use anyhow::{Context, anyhow};
use honk_config::check::{HttpCheckTarget, decode_health_http_target, decode_http_check_target};
use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
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

fn probe_method(method: &str) -> anyhow::Result<http::Method> {
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
    validate_runtime(runtime)?;
    let timeout = urltest_timeout(timeout);
    let request = http_probe_request(url, "")?;
    urltest_request_impl(runtime, handler, &request, timeout, group_manager).await
}

async fn urltest_request_impl(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    handler: &dyn TcpOutbound,
    request: &http::Request<()>,
    timeout: Duration,
    group_manager: Option<&GroupManager>,
) -> anyhow::Result<Duration> {
    validate_runtime(runtime)?;
    let node = runtime.node.as_ref();
    let target = request_target(request)?;
    let host = target.host();
    let port = target.port();
    let direct = node.protocol() == honk_config::types::NodeProtocol::Direct;
    let addr = resolve_urltest_address(host, port, direct).await?;
    let feedback = group_manager.and_then(|manager| {
        let family = if addr.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let target = host
            .parse::<std::net::IpAddr>()
            .map_or_else(|_| ScoreTarget::domain(host, port), |_| addr.into());
        manager
            .feedback_for_node(
                node.id,
                ScoreSelectionContext {
                    network: SelectionNetwork::Tcp,
                    probe_domain: ProbeDomain::Tcp,
                    target_family: Some(family),
                    health_family: family,
                    target: Some(target),
                },
            )
            .map(|feedback| feedback.streak_neutral())
    });
    measure_http_probe(
        runtime,
        handler,
        request,
        addr,
        Some(host),
        timeout,
        timeout,
        feedback,
    )
    .await
}

async fn resolve_urltest_address(
    host: &str,
    port: u16,
    direct: bool,
) -> anyhow::Result<SocketAddr> {
    let hook = URLTEST_RESOLVER.read().clone();
    if let Some(hook) = hook {
        return hook(host.to_string(), port)
            .await
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"));
    }
    if direct {
        return crate::bootstrap::resolve(host)
            .await
            .with_context(|| format!("failed to resolve '{host}:{port}'"))?
            .into_iter()
            .next()
            .map(|ip| SocketAddr::new(ip, port))
            .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"));
    }
    tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve '{host}:{port}'"))?
        .next()
        .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"))
}

/// Reuse an already-warm generation runtime; otherwise create a throwaway
/// runtime whose guard closes any session or client established for probing.
pub fn try_probe_runtime(
    generation: &crate::runtime::OutboundRuntimeRegistry,
    node: &Node,
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
        .filter(|runtime| runtime.is_warm_or_stateless())
    {
        Some(runtime) => Ok((runtime, None)),
        None => {
            let guard = crate::runtime::NodeRuntime::ephemeral_guarded_after_admission(node);
            Ok((guard.runtime(), Some(guard)))
        }
    }
}

/// Compatibility wrapper for [`try_probe_runtime`]; panics on invalid input.
pub fn probe_runtime(
    generation: &crate::runtime::OutboundRuntimeRegistry,
    node: &Node,
) -> (
    Arc<crate::runtime::NodeRuntime>,
    Option<crate::runtime::EphemeralRuntimeGuard>,
) {
    try_probe_runtime(generation, node)
        .unwrap_or_else(|_| panic!("invalid node passed to URLTest runtime probe"))
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
    if runtime.is_warm_or_stateless() {
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
    let timeout = urltest_timeout(timeout);
    let request = http_probe_request(url, "")?;
    let (runtime, guard) = try_probe_runtime(generation, node)?;
    let warm_feedback = if runtime.is_warm_or_stateless() {
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
                .map(|feedback| feedback.streak_neutral())
        })
    };
    let result = generation
        .scope_dials(async {
            warm_http_probe(&runtime, warmable, timeout, timeout, warm_feedback).await?;
            urltest_request_impl(&runtime, handler, &request, timeout, group_manager).await
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
    let timeout = urltest_timeout(timeout);
    let request = http_probe_request(url, "")?;
    measure_http_probe(
        runtime, handler, &request, addr, None, timeout, timeout, None,
    )
    .await
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
) -> anyhow::Result<Duration> {
    validate_runtime(runtime)?;
    let target = request_target(request)?;
    let normalized_request = build_http_probe_request(&target, request.method().clone())?;
    let request = &normalized_request;
    let host = target.host();
    let is_https = target.is_https();
    let node = runtime.node.as_ref();
    let reporter = start_feedback(feedback);
    let result = async {
        // Dial, target TLS, HTTP/2 startup, and both exchanges each receive
        // their own phase budget rather than sharing one outer clock.
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
                Some(b"h2") => exchange_http2(tls, request, &reporter, timeout).await,
                _ => {
                    let mut tls = tls;
                    exchange_http1(&mut tls, request, &reporter, timeout).await
                }
            }
        } else {
            let mut stream = stream;
            exchange_http1(&mut stream, request, &reporter, timeout).await
        }
    }
    .await;
    match result {
        Ok(elapsed) => {
            reporter_success(&reporter);
            Ok(elapsed)
        }
        Err(error) => {
            reporter_error(&reporter, &error);
            Err(error)
        }
    }
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

enum RoundError {
    Transport(anyhow::Error),
    Invalid(anyhow::Error),
}

impl RoundError {
    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Transport(error) | Self::Invalid(error) => error,
        }
    }
}

struct H2Driver(Option<tokio::task::JoinHandle<()>>);

impl H2Driver {
    async fn stop(mut self) {
        if let Some(driver) = self.0.take() {
            driver.abort();
            let _ = driver.await;
        }
    }
}

impl Drop for H2Driver {
    fn drop(&mut self) {
        if let Some(driver) = self.0.take() {
            driver.abort();
        }
    }
}

fn h2_round_error(error: h2::Error, context: &'static str) -> RoundError {
    // A remote REFUSED_STREAM means the request was not processed (RFC 9113
    // §8.7), so it says nothing about the response; the local refusal h2
    // raises for an oversized header list is not remote and stays invalid.
    let refused =
        error.is_reset() && error.is_remote() && error.reason() == Some(h2::Reason::REFUSED_STREAM);
    let transport = error.is_io()
        || (error.is_go_away() && error.reason() == Some(h2::Reason::NO_ERROR))
        || refused;
    let error = anyhow::Error::new(error).context(context);
    if transport {
        RoundError::Transport(error)
    } else {
        RoundError::Invalid(error)
    }
}

fn request_with_method(
    request: &http::Request<()>,
    method: http::Method,
) -> anyhow::Result<http::Request<()>> {
    let target = request_target(request)?;
    build_http_probe_request(&target, method)
}

async fn h2_round(
    sender: &mut h2::client::SendRequest<bytes::Bytes>,
    request: &http::Request<()>,
    method: http::Method,
    reporter: &Option<ScoreReporter>,
    first_response: bool,
) -> Result<(Duration, http::StatusCode), RoundError> {
    std::future::poll_fn(|context| sender.poll_ready(context))
        .await
        .map_err(|error| h2_round_error(error, "HTTP/2 request readiness failed"))?;
    let outgoing = request_with_method(request, method.clone()).map_err(RoundError::Invalid)?;
    let start = Instant::now();
    let (response, _) = sender
        .send_request(outgoing, true)
        .map_err(|error| h2_round_error(error, "HTTP/2 request send failed"))?;
    let uri_bytes = request
        .uri()
        .authority()
        .map_or(0, |authority| authority.as_str().len())
        .saturating_add(
            request
                .uri()
                .path_and_query()
                .map_or(1, |target| target.as_str().len()),
        );
    reporter_tx(reporter, method.as_str().len().saturating_add(uri_bytes));
    let response = response
        .await
        .map_err(|error| h2_round_error(error, "HTTP/2 response failed"))?;
    if first_response {
        reporter_first_response(reporter);
    }
    reporter_rx(reporter, 1);
    // ponytail: h2 defaults missing :status to 200; await hyperium/h2#958 rather than fork locally.
    Ok((start.elapsed(), response.status()))
}

/// Two requests over a fresh HTTP/2 connection. The connection driver is
/// owned by this future and aborted on both ordinary return and cancellation.
async fn exchange_http2<S>(
    stream: S,
    request: &http::Request<()>,
    reporter: &Option<ScoreReporter>,
    timeout: Duration,
) -> anyhow::Result<Duration>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = tokio::time::timeout(
        timeout,
        h2::client::Builder::new()
            .enable_push(false)
            .max_header_list_size(MAX_HTTP_RESPONSE_HEAD as u32)
            .handshake(stream),
    )
    .await
    .map_err(|_| phase_timeout("HTTP/2 probe startup timed out"))?
    .map_err(|error| anyhow::Error::new(error).context("HTTP/2 probe startup failed"))?;
    let driver = H2Driver(Some(tokio::spawn(async move {
        let _ = connection.await;
    })));
    let result = async {
        let (warm, status) = match tokio::time::timeout(
            timeout,
            h2_round(&mut sender, request, http::Method::HEAD, reporter, true),
        )
        .await
        {
            Ok(result) => result.map_err(RoundError::into_error)?,
            Err(_) => return Err(phase_timeout("HTTP probe warm-up request timed out")),
        };
        validate_status_code(status)?;
        match tokio::time::timeout(
            timeout,
            h2_round(
                &mut sender,
                request,
                request.method().clone(),
                reporter,
                false,
            ),
        )
        .await
        {
            Ok(Ok((measured, status))) => {
                validate_status_code(status)?;
                Ok(measured)
            }
            Ok(Err(RoundError::Transport(_))) | Err(_) => Ok(warm),
            Ok(Err(RoundError::Invalid(error))) => Err(error),
        }
    }
    .await;
    driver.stop().await;
    result
}

fn http1_wire_request(
    request: &http::Request<()>,
    method: &http::Method,
    close: bool,
) -> anyhow::Result<String> {
    let target = request_target(request)?;
    Ok(format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: honk-http-probe/1.0\r\n{}\r\n",
        method,
        target.request_target(),
        target.authority(),
        if close { "Connection: close\r\n" } else { "" }
    ))
}

const MAX_HTTP_RESPONSE_HEAD: usize = 16 * 1024;

async fn read_response_head<S>(
    stream: &mut S,
    reporter: &Option<ScoreReporter>,
    first_response: bool,
    response_started: &mut bool,
) -> Result<http::StatusCode, RoundError>
where
    S: AsyncBufRead + Unpin,
{
    let mut head = Vec::with_capacity(1024);
    let mut total = 0;
    loop {
        if total == MAX_HTTP_RESPONSE_HEAD {
            return Err(RoundError::Invalid(anyhow!(
                "HTTP response heads exceed {MAX_HTTP_RESPONSE_HEAD} bytes"
            )));
        }
        let first_bytes = !*response_started;
        let (consumed, complete) = {
            let available = match stream.fill_buf().await {
                Ok(available) => available,
                Err(error) if !*response_started => {
                    return Err(RoundError::Transport(
                        anyhow::Error::new(error).context("HTTP probe read failed"),
                    ));
                }
                Err(error) => {
                    return Err(RoundError::Invalid(
                        anyhow::Error::new(error).context("truncated HTTP response head"),
                    ));
                }
            };
            if available.is_empty() {
                return if !*response_started {
                    Err(RoundError::Transport(anyhow!(
                        "connection closed without an HTTP response"
                    )))
                } else {
                    Err(RoundError::Invalid(anyhow!("truncated HTTP response head")))
                };
            }
            *response_started = true;
            let take = available.len().min(MAX_HTTP_RESPONSE_HEAD - total);
            let old_len = head.len();
            head.extend_from_slice(&available[..take]);
            let scan_from = old_len.saturating_sub(3);
            let complete = head[scan_from..]
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|offset| scan_from + offset + 4);
            let consumed = complete.map_or(take, |end| end - old_len);
            (consumed, complete)
        };
        stream.consume(consumed);
        total += consumed;
        if first_response && first_bytes {
            reporter_first_response(reporter);
        }
        reporter_rx(reporter, consumed);
        if let Some(end) = complete {
            head.truncate(end);
            let status = validate_response_head(&head).map_err(RoundError::Invalid)?;
            if !status.is_informational() || status == http::StatusCode::SWITCHING_PROTOCOLS {
                return Ok(status);
            }
            head.clear();
        }
    }
}

async fn http1_round<S>(
    stream: &mut S,
    request: &http::Request<()>,
    method: &http::Method,
    close: bool,
    reporter: &Option<ScoreReporter>,
    first_response: bool,
    timeout: Duration,
) -> Result<(Duration, http::StatusCode), RoundError>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let wire = http1_wire_request(request, method, close).map_err(RoundError::Invalid)?;
    let mut response_started = false;
    let round = async {
        let start = Instant::now();
        stream.write_all(wire.as_bytes()).await.map_err(|error| {
            RoundError::Transport(anyhow::Error::new(error).context("HTTP probe write failed"))
        })?;
        reporter_tx(reporter, wire.len());
        let status =
            read_response_head(stream, reporter, first_response, &mut response_started).await?;
        Ok((start.elapsed(), status))
    };
    match tokio::time::timeout(timeout, round).await {
        Ok(result) => result,
        Err(_) => {
            let error = phase_timeout("HTTP probe request timed out");
            if response_started {
                Err(RoundError::Invalid(
                    error.context("incomplete HTTP response head"),
                ))
            } else {
                Err(RoundError::Transport(error))
            }
        }
    }
}

/// Two HTTP/1.x requests on one connection. Only measured-round transport
/// failure may fall back to the validated warm response.
async fn exchange_http1<S>(
    stream: &mut S,
    request: &http::Request<()>,
    reporter: &Option<ScoreReporter>,
    timeout: Duration,
) -> anyhow::Result<Duration>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);
    let (warm, status) = http1_round(
        &mut stream,
        request,
        &http::Method::HEAD,
        false,
        reporter,
        true,
        timeout,
    )
    .await
    .map_err(RoundError::into_error)?;
    validate_status_code(status)?;
    match http1_round(
        &mut stream,
        request,
        request.method(),
        true,
        reporter,
        false,
        timeout,
    )
    .await
    {
        Ok((measured, status)) => {
            validate_status_code(status)?;
            Ok(measured)
        }
        Err(RoundError::Transport(_)) => Ok(warm),
        Err(RoundError::Invalid(error)) => Err(error),
    }
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
        join_set.spawn(async move {
            let _permit = permit.acquire_owned().await;
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
                    )
                    .await
                }
                None => Err(anyhow!("no handler for protocol {:?}", node.protocol())),
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

fn validate_status_code(status: http::StatusCode) -> anyhow::Result<()> {
    if (200..500).contains(&status.as_u16()) {
        Ok(())
    } else {
        Err(anyhow!("bad status code: {status}"))
    }
}

fn validate_response_head(head: &[u8]) -> anyhow::Result<http::StatusCode> {
    if head.len() > MAX_HTTP_RESPONSE_HEAD || !head.ends_with(b"\r\n\r\n") {
        return Err(anyhow!("incomplete HTTP response head"));
    }
    let mut lines = head[..head.len() - 2].split(|byte| *byte == b'\n');
    let status = lines
        .next()
        .and_then(|line| line.strip_suffix(b"\r"))
        .ok_or_else(|| anyhow!("malformed HTTP status line"))?;
    let separator = status
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or_else(|| anyhow!("malformed HTTP status line"))?;
    let version = &status[..separator];
    if version != b"HTTP/1.0" && version != b"HTTP/1.1" {
        return Err(anyhow!("unsupported HTTP response version"));
    }
    let remainder = &status[separator + 1..];
    let code_end = remainder
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(remainder.len());
    let code = &remainder[..code_end];
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return Err(anyhow!("malformed HTTP status code"));
    }
    if remainder[code_end..]
        .iter()
        .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(anyhow!("malformed HTTP reason phrase"));
    }
    let status = http::StatusCode::from_bytes(code).context("invalid HTTP status code")?;

    for raw_line in lines {
        if raw_line.is_empty() {
            continue;
        }
        let line = raw_line
            .strip_suffix(b"\r")
            .ok_or_else(|| anyhow!("malformed HTTP header line ending"))?;
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| anyhow!("malformed HTTP response header"))?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().copied().all(is_header_name_byte) {
            return Err(anyhow!("malformed HTTP response header name"));
        }
        if line[colon + 1..]
            .iter()
            .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
        {
            return Err(anyhow!("malformed HTTP response header value"));
        }
    }
    Ok(status)
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
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
        let node = honk_config::Config::builtin_direct_node();
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        let host = format!("{name}.example");
        let mut node = Node {
            name: name.into(),
            address: format!("{host}:443"),
            host,
            port: 443,
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
            ..Default::default()
        };
        node.id = node.derive_id();
        node
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
        node.outbound = honk_config::node::OutboundConfig::from_protocol(protocol);
        let credential = "00000000-0000-4000-8000-000000000001".to_string();
        match &mut node.outbound {
            honk_config::node::OutboundConfig::Vmess(config) => {
                config.uuid = Some(credential.clone())
            }
            honk_config::node::OutboundConfig::Vless(config) => {
                config.uuid = Some(credential.clone());
                config.mode = honk_config::node::WireMode::H2mux;
            }
            honk_config::node::OutboundConfig::Tuic(config) => {
                config.uuid = Some(credential.clone())
            }
            honk_config::node::OutboundConfig::Juicity(config) => config.uuid = Some(credential),
            _ => {}
        }
        node.id = node.derive_id();
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
        let request = http_probe_request("http://localhost/", "").unwrap();
        exchange_http1(
            &mut client,
            &request,
            &no_feedback(),
            Duration::from_secs(5),
        )
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
                    // Keep answering until the client closes: the measurement
                    // sends a warm-up request before the timed one.
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if sock
                            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    /// Legacy shape: one response per connection, then close — exercises the
    /// single-exchange fallback.
    async fn spawn_close_after_response_server() -> SocketAddr {
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

    async fn read_request_head<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 256];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let size = stream.read(&mut chunk).await.unwrap();
            assert_ne!(size, 0, "request closed before its header completed");
            request.extend_from_slice(&chunk[..size]);
        }
        request
    }

    #[tokio::test]
    async fn http1_uses_configured_method_target_and_authority() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let warm = read_request_head(&mut server).await;
            assert!(warm.starts_with(b"HEAD /health/ready?source=urltest HTTP/1.1\r\n"));
            assert!(
                warm.windows(b"Host: probe.example:8080\r\n".len())
                    .any(|part| part == b"Host: probe.example:8080\r\n")
            );
            server
                .write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </ready>\r\n\r\nHTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let measured = read_request_head(&mut server).await;
            assert!(measured.starts_with(b"GET /health/ready?source=urltest HTTP/1.1\r\n"));
            assert!(
                measured
                    .windows(b"Host: probe.example:8080\r\n".len())
                    .any(|part| part == b"Host: probe.example:8080\r\n")
            );
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let request = http_probe_request(
            "http://probe.example:8080/health/ready?source=urltest",
            "GET",
        )
        .unwrap();
        exchange_http1(
            &mut client,
            &request,
            &no_feedback(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn partial_measured_response_timeout_is_not_a_fallback_success() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let peer = tokio::spawn(async move {
            let _ = read_request_head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
            let _ = read_request_head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\n")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
        let result = exchange_http1(
            &mut client,
            &request,
            &no_feedback(),
            Duration::from_millis(50),
        )
        .await;
        peer.abort();
        let _ = peer.await;
        assert!(
            result.is_err(),
            "partial response cannot become warm success"
        );
    }

    #[tokio::test]
    async fn malformed_truncated_or_oversized_response_is_not_a_fallback_success() {
        for response in [
            b"not an HTTP response\r\n\r\n".to_vec(),
            b"HTTP/1.1 204 No Content\r\nContent-Len".to_vec(),
            format!(
                "HTTP/1.1 204 No Content\r\nX-Pad: {}\r\n\r\n",
                "a".repeat(MAX_HTTP_RESPONSE_HEAD)
            )
            .into_bytes(),
        ] {
            let (mut client, mut server) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _ = read_request_head(&mut server).await;
                server
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                let _ = read_request_head(&mut server).await;
                let _ = server.write_all(&response).await;
            });
            let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
            assert!(
                exchange_http1(
                    &mut client,
                    &request,
                    &no_feedback(),
                    Duration::from_secs(1)
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn h2_uses_configured_method_target_and_authority() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (observed, mut requests) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(sock).await.unwrap();
            while let Some(result) = connection.accept().await {
                let (request, mut respond) = result.unwrap();
                let push = http::Request::builder()
                    .uri("http://probe.example/pushed")
                    .body(())
                    .unwrap();
                assert!(
                    respond.push_request(push).is_err(),
                    "probes must refuse server push"
                );
                observed
                    .send((request.method().clone(), request.uri().clone()))
                    .unwrap();
                let response = http::Response::builder().status(204).body(()).unwrap();
                respond.send_response(response, true).unwrap();
            }
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request =
            http_probe_request("http://probe.example:8080?source=urltest", "GET").unwrap();
        exchange_http2(stream, &request, &no_feedback(), Duration::from_secs(5))
            .await
            .expect("HTTP/2 exchange must succeed");

        let first = requests.recv().await.unwrap();
        let second = requests.recv().await.unwrap();
        assert_eq!(first.0, http::Method::HEAD);
        assert_eq!(second.0, http::Method::GET);
        for (_, uri) in [first, second] {
            assert_eq!(uri.authority().unwrap().as_str(), "probe.example:8080");
            assert_eq!(uri.path_and_query().unwrap().as_str(), "/?source=urltest");
        }
    }

    #[tokio::test]
    async fn h2_rejects_bad_warm_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(sock).await.unwrap();
            let mut first = true;
            while let Some(request) = connection.accept().await {
                let (_request, mut respond) = request.unwrap();
                let status = if first { 500 } else { 204 };
                first = false;
                respond
                    .send_response(
                        http::Response::builder().status(status).body(()).unwrap(),
                        true,
                    )
                    .unwrap();
            }
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
        assert!(
            exchange_http2(stream, &request, &no_feedback(), Duration::from_secs(1))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn h2_falls_back_only_for_remote_refused_stream() {
        for (reason, healthy) in [
            (h2::Reason::REFUSED_STREAM, true),
            (h2::Reason::INTERNAL_ERROR, false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let (sock, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(sock).await.unwrap();
                let mut first = true;
                while let Some(request) = connection.accept().await {
                    let (_request, mut respond) = request.unwrap();
                    if first {
                        first = false;
                        respond
                            .send_response(
                                http::Response::builder().status(204).body(()).unwrap(),
                                true,
                            )
                            .unwrap();
                    } else {
                        respond.send_reset(reason);
                    }
                }
            });
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
            let result =
                exchange_http2(stream, &request, &no_feedback(), Duration::from_secs(1)).await;
            peer.abort();
            let _ = peer.await;
            assert_eq!(result.is_ok(), healthy, "RST_STREAM({reason}): {result:?}");
        }
    }

    #[tokio::test]
    async fn h2_falls_back_only_for_graceful_goaway() {
        for (reason, healthy) in [(0_u32, true), (1, false)] {
            let (client, mut server) = tokio::io::duplex(4096);
            let peer = tokio::spawn(async move {
                let mut preface = [0; 24];
                server.read_exact(&mut preface).await.unwrap();
                server
                    .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                loop {
                    let mut header = [0; 9];
                    server.read_exact(&mut header).await.unwrap();
                    let length = ((header[0] as usize) << 16)
                        | ((header[1] as usize) << 8)
                        | header[2] as usize;
                    let mut payload = vec![0; length];
                    server.read_exact(&mut payload).await.unwrap();
                    if header[3] == 4 && header[4] == 0 {
                        server
                            .write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0])
                            .await
                            .unwrap();
                    }
                    if header[3] == 1 {
                        // Deliver :status 204 and GOAWAY together, before stream 3 can open.
                        let mut frames = vec![
                            0, 0, 1, 1, 5, 0, 0, 0, 1, 0x89, 0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                        ];
                        frames.extend_from_slice(&reason.to_be_bytes());
                        server.write_all(&frames).await.unwrap();
                        std::future::pending::<()>().await;
                    }
                }
            });
            let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
            let result =
                exchange_http2(client, &request, &no_feedback(), Duration::from_secs(1)).await;
            peer.abort();
            let _ = peer.await;
            assert_eq!(result.is_ok(), healthy, "GOAWAY({reason}): {result:?}");
        }
    }

    struct DropWatch<S> {
        stream: S,
        dropped: Arc<std::sync::atomic::AtomicBool>,
        block_writes: Arc<std::sync::atomic::AtomicBool>,
    }

    impl<S> Drop for DropWatch<S> {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for DropWatch<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for DropWatch<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.block_writes.load(std::sync::atomic::Ordering::Acquire) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.get_mut().stream).poll_write(context, buffer)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.block_writes.load(std::sync::atomic::Ordering::Acquire) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(context)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.block_writes.load(std::sync::atomic::Ordering::Acquire) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
        }
    }

    #[tokio::test]
    async fn cancelling_stalled_h2_probe_drops_its_driver_stream() {
        let (client, server) = tokio::io::duplex(4096);
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let block_writes = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watched = DropWatch {
            stream: client,
            dropped: Arc::clone(&dropped),
            block_writes: Arc::clone(&block_writes),
        };
        let (accepted, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (_request, _respond) = connection.accept().await.unwrap().unwrap();
            let _ = accepted.send(());
            let _held = (connection, _request, _respond);
            std::future::pending::<()>().await;
        });
        let probe = tokio::spawn(async move {
            let request = http_probe_request("http://probe.example/stall", "HEAD").unwrap();
            exchange_http2(watched, &request, &no_feedback(), Duration::from_secs(5)).await
        });
        tokio::time::timeout(Duration::from_secs(1), accepted_rx)
            .await
            .unwrap()
            .unwrap();
        block_writes.store(true, std::sync::atomic::Ordering::Release);
        probe.abort();
        let _ = probe.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled HTTP/2 driver must release its stream");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn hysteria2_excludes_pre_write_dial_time() {
        let addr = spawn_mock_http_server().await;
        let node = Node::from_share_link("hysteria2://test@127.0.0.1:443").unwrap();
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
    fn http_probe_request_preserves_uri_and_validates_inputs() {
        let request =
            http_probe_request("example.com:8443/ready,check?region=us,west", "GET").unwrap();
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(
            request.uri().to_string(),
            "https://example.com:8443/ready,check?region=us,west"
        );
        let target = request_target(&request).unwrap();
        assert_eq!(
            (
                target.host(),
                target.authority(),
                target.port(),
                target.is_https()
            ),
            ("example.com", "example.com:8443", 8443, true)
        );

        let ipv6 = http_probe_request("http://[::1]:8080/status?full=1", "").unwrap();
        assert_eq!(ipv6.method(), http::Method::HEAD);
        assert_eq!(ipv6.uri().authority().unwrap().as_str(), "[::1]:8080");
        let target = request_target(&ipv6).unwrap();
        assert_eq!(
            (target.host(), target.port(), target.is_https()),
            ("::1", 8080, false)
        );

        let health = health_http_probe_request("probe.example/ready,1.1.1.1", "").unwrap();
        assert_eq!(health.method(), http::Method::HEAD);
        assert_eq!(health.uri().to_string(), "http://probe.example/ready");

        assert_eq!(
            http_probe_request("", "").unwrap().uri().to_string(),
            DEFAULT_URLTEST_URL
        );
        assert!(http_probe_request("ftp://example.com/", "HEAD").is_err());
        assert!(http_probe_request("https://", "HEAD").is_err());
        assert!(http_probe_request("https://example.com:99999/", "HEAD").is_err());
        assert!(http_probe_request("https://example.com/", "GET\r\nInjected: yes").is_err());
        let error = http_probe_request("https:///u:PRIVATE@example.invalid/", "HEAD").unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE"));
    }

    #[test]
    fn c25_urltest_authority_boundaries() {
        for (input, expected) in [
            (
                "http://u:PRIVATE@host:8080/path?q#fragment",
                ("host", "host:8080", 8080, false, "/path?q"),
            ),
            ("https://host?q=1", ("host", "host", 443, true, "/?q=1")),
            (
                "http://[::1]:8080?q=1",
                ("::1", "[::1]:8080", 8080, false, "/?q=1"),
            ),
            (
                "http://host/a/../health?q=1",
                ("host", "host", 80, false, "/a/../health?q=1"),
            ),
        ] {
            let request = http_probe_request(input, "").unwrap();
            let target = request_target(&request).unwrap();
            assert_eq!(
                (
                    target.host(),
                    target.authority(),
                    target.port(),
                    target.is_https(),
                    target.request_target(),
                ),
                expected
            );
            assert!(!request.uri().authority().unwrap().as_str().contains('@'));
        }
    }
    /// The HEAD exchange itself is protocol-agnostic; exercise it over a
    /// plain stream against a local HTTP server.
    #[tokio::test]
    async fn test_exchange_http1_plain_http() {
        let request = http_probe_request("http://localhost/", "").unwrap();
        let addr = spawn_mock_http_server().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        exchange_http1(
            &mut stream,
            &request,
            &no_feedback(),
            Duration::from_secs(5),
        )
        .await
        .expect("HEAD exchange against local HTTP server should succeed");
    }

    /// A server that closes after the first response still yields a sample:
    /// the warm-up exchange's own time is reported.
    #[tokio::test]
    async fn test_exchange_http1_falls_back_when_server_closes() {
        let request = http_probe_request("http://localhost/", "").unwrap();
        let addr = spawn_close_after_response_server().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        exchange_http1(
            &mut stream,
            &request,
            &no_feedback(),
            Duration::from_secs(5),
        )
        .await
        .expect("single-response server must fall back to the warm sample");
    }

    /// The reported sample excludes warm-up: a server that stalls only the
    /// first response must still measure a fast second round trip.
    #[tokio::test]
    async fn test_exchange_http1_reports_warm_round_trip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            for round in 0..2 {
                if sock.read(&mut buf).await.unwrap_or(0) == 0 {
                    break;
                }
                if round == 0 {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let request = http_probe_request("http://localhost/", "").unwrap();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let measured = exchange_http1(
            &mut stream,
            &request,
            &no_feedback(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(
            measured < Duration::from_millis(100),
            "warm round trip must exclude the stalled first response: {measured:?}"
        );
    }

    /// The sample really is the second request, not min(#1, #2): a stall on
    /// the second response must show up in the sample.
    #[tokio::test]
    async fn test_exchange_http1_reports_the_second_round_trip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            for round in 0..2 {
                if sock.read(&mut buf).await.unwrap_or(0) == 0 {
                    break;
                }
                if round == 1 {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let request = http_probe_request("http://localhost/", "").unwrap();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let measured = exchange_http1(
            &mut stream,
            &request,
            &no_feedback(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(
            measured >= Duration::from_millis(150),
            "the sample is the second request: {measured:?}"
        );
    }

    /// A bad status on the measured request fails the measurement; only a
    /// lost connection or a timeout falls back to the warm sample.
    #[tokio::test]
    async fn test_exchange_http1_bad_status_on_second_request_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            for round in 0..2 {
                if sock.read(&mut buf).await.unwrap_or(0) == 0 {
                    break;
                }
                let response = if round == 0 {
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".as_slice()
                } else {
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".as_slice()
                };
                sock.write_all(response).await.unwrap();
            }
        });
        let request = http_probe_request("http://localhost/", "").unwrap();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            exchange_http1(
                &mut stream,
                &request,
                &no_feedback(),
                Duration::from_secs(5)
            )
            .await
            .is_err()
        );
    }

    /// A measured request that outlives its own budget falls back to the
    /// warm sample instead of failing the whole measurement.
    #[tokio::test]
    async fn test_exchange_http1_slow_second_request_falls_back() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            for round in 0..2 {
                if sock.read(&mut buf).await.unwrap_or(0) == 0 {
                    break;
                }
                if round == 1 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let request = http_probe_request("http://localhost/", "").unwrap();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let measured = exchange_http1(
            &mut stream,
            &request,
            &no_feedback(),
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert!(
            measured < Duration::from_millis(100),
            "timed-out measured request falls back to the warm sample: {measured:?}"
        );
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn read_head(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut head = Vec::new();
        let mut chunk = [0_u8; 256];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let size = stream.read(&mut chunk).await.unwrap();
            assert_ne!(size, 0);
            head.extend_from_slice(&chunk[..size]);
        }
        head
    }

    #[tokio::test]
    async fn direct_urltest_routes_the_full_requested_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut wrong, _) = listener.accept().await.unwrap();
            let request = read_head(&mut wrong).await;
            assert!(request.starts_with(b"HEAD /wrong?probe=1 HTTP/1.1\r\n"));
            wrong
                .write_all(b"HTTP/1.1 500 Wrong Target\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();

            let (mut correct, _) = listener.accept().await.unwrap();
            let expected_host = format!("Host: {addr}\r\n");
            for _ in 0..2 {
                let request = read_head(&mut correct).await;
                assert!(request.starts_with(b"HEAD /requested?probe=1 HTTP/1.1\r\n"));
                assert!(
                    request
                        .windows(expected_host.len())
                        .any(|part| part == expected_host.as_bytes())
                );
                correct
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let node = honk_config::Config::builtin_direct_node();
        let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
        let handler = crate::proxy::direct::DirectHandler::new();
        assert!(
            urltest_node(
                &runtime,
                &handler,
                &format!("http://{addr}/wrong?probe=1"),
                Duration::from_secs(2),
            )
            .await
            .is_err()
        );
        urltest_node(
            &runtime,
            &handler,
            &format!("http://{addr}/requested?probe=1"),
            Duration::from_secs(2),
        )
        .await
        .expect("direct URLTest must route the requested path, query, and authority");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn native_request_normalizes_query_only_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for _ in 0..2 {
                let head = read_head(&mut stream).await;
                assert!(
                    !head
                        .windows(b"PRIVATE".len())
                        .any(|part| part == b"PRIVATE")
                );
                let response = if head.starts_with(b"HEAD /?check=1 HTTP/1.1\r\n") {
                    b"HTTP/1.1 204 No Content\r\n\r\n".as_slice()
                } else {
                    b"HTTP/1.1 503 Wrong Target\r\n\r\n".as_slice()
                };
                if stream.write_all(response).await.is_err() {
                    break;
                }
            }
        });
        let node = honk_config::Config::builtin_direct_node();
        let guard = crate::runtime::NodeRuntime::try_ephemeral_guarded(&node).unwrap();
        let request = http::Request::builder()
            .method("HEAD")
            .uri(format!("http://u:PRIVATE@{addr}?check=1"))
            .body(())
            .unwrap();
        let result = measure_http_probe(
            &guard.runtime(),
            &crate::proxy::direct::DirectHandler::new(),
            &request,
            addr,
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            None,
        )
        .await;
        guard.close().await;
        peer.abort();
        let _ = peer.await;
        assert!(result.is_ok(), "native request target rejected: {result:?}");
    }
}

#[cfg(test)]
mod fallible_probe_tests {
    use super::*;

    #[test]
    fn try_probe_runtime_rejects_stale_id_before_warm_lookup() {
        let mut node = Node::from_share_link("socks5://127.0.0.1:1080").unwrap();
        let generation =
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        node.port += 1;
        let error = try_probe_runtime(&generation, &node).unwrap_err();
        let crate::runtime::RuntimeRegistryError::Admission(error) = error else {
            panic!("expected node admission error");
        };
        assert_eq!(error.diagnostic.code, "noncanonical-node-id");
    }
}
