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

use crate::alive::{AliveDialerSet, IpVersion, ProbeDomain};
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
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

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
    urltest_request_impl(runtime, handler, &request, timeout).await
}

async fn urltest_request_impl(
    runtime: &Arc<crate::runtime::NodeRuntime>,
    handler: &dyn TcpOutbound,
    request: &http::Request<()>,
    timeout: Duration,
) -> anyhow::Result<Duration> {
    validate_runtime(runtime)?;
    let target = request_target(request)?;
    let host = target.host();
    let port = target.port();
    let addr = resolve_urltest_address(host, port).await?;
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
    let result = generation
        .scope_dials(async {
            warm_http_probe(&runtime, warmable, timeout, timeout, warm_feedback).await?;
            urltest_request_impl(&runtime, handler, &request, timeout).await
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
    let reporter = start_feedback(feedback.map(|feedback| {
        feedback.with_probe_identity(&request.uri().to_string(), request.method().as_str())
    }));
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
    // A remote REFUSED_STREAM means the request was not processed (RFC 9113 §8.7).
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
    // ponytail: locked h2 0.4.19 defaults missing :status; await a release containing hyperium/h2#959.
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
            // Fail this disposable connection on its first local protocol rejection,
            // before a remote reset can overwrite the error.
            .max_local_error_reset_streams(Some(0))
            // Cover both request budgets so late warm-stream frames stay ignorable.
            .reset_stream_duration(timeout.saturating_mul(2))
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
                if let Some(reporter) = reporter {
                    reporter.probe_latency(measured);
                }
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
            if let Some(reporter) = reporter {
                reporter.probe_latency(measured);
            }
            Ok(measured)
        }
        Err(RoundError::Transport(_)) => Ok(warm),
        Err(RoundError::Invalid(error)) => Err(error),
    }
}

/// Measure every member of a group concurrently (at most
/// [`URLTEST_MAX_CONCURRENT`] at a time) and fold the results into the
/// alive set: successes record measured TCP latency. An arbitrary measurement
/// target failing does not establish a real dial failure or node-wide outage.
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
mod resolver_hook_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod direct_urltest_tests;

#[cfg(test)]
mod fallible_probe_tests;
