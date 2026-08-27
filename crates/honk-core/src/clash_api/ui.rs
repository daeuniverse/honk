//! External UI auto-download for the clash API (sing-box
//! `experimental/clashapi/server_resources.go` equivalent).
//!
//! When `experimental.clash_api.external_ui` points at a missing or empty
//! directory, a background task downloads the zashboard dashboard zip from
//! GitHub and extracts it into that directory, stripping the single
//! top-level archive directory. The download never blocks startup and
//! failures only log a warning — `ServeDir` keeps returning 404 until the
//! files land.
//!
//! A non-empty `external_ui_download_detour` forces every request and
//! redirect through that node or group. Otherwise each URL host follows the
//! normal traffic routing decision: `direct` uses reqwest, `block` aborts,
//! and other results use the selected node's tunnel.
//!
//! The download URL defaults to [`DEFAULT_UI_DOWNLOAD_URL`].
//! `external_ui_download_url` configures it, while `HONK_UI_DOWNLOAD_URL`
//! remains the highest-precedence override.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use honk_config::Config;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use honk_outbound::alive::{IpVersion, ProbeDomain};
use honk_outbound::group::{
    ScoreFeedback, ScoreOutcome, ScoreReporter, ScoreSelectionContext, ScoreTarget,
    SelectionNetwork, SharedGroupManager,
};
use honk_outbound::proxy::{AsyncReadWrite, ProxyRegistry};
use honk_outbound::runtime::SharedRuntimeRegistry;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::info;

use crate::routing::{ConnectionInfo, Router};

/// Default dashboard archive (zashboard release `dist.zip`, latest).
pub const DEFAULT_UI_DOWNLOAD_URL: &str =
    "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip";

/// Environment variable overriding [`DEFAULT_UI_DOWNLOAD_URL`].
pub const UI_DOWNLOAD_URL_ENV: &str = "HONK_UI_DOWNLOAD_URL";

/// HTTP timeout for the archive download.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// The dashboard zip is a few MB; anything beyond this ceiling is a broken
/// or hostile endpoint, not a dashboard.
const MAX_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;

/// Redirects followed per proxied fetch (each hop is re-routed: the
/// Location target is usually a different host).
const MAX_REDIRECTS: u32 = 5;

/// HTTP/1.1-only ALPN wire: the proxied fetch has no h2 client.
const HTTP11_ALPN_WIRE: &[u8] = b"\x08http/1.1";

/// Response-header ceiling; GitHub sends a few KB.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Everything the download needs to route the fetch like user traffic.
pub struct UiDownloadContext {
    pub external_ui: String,
    pub router: Arc<RwLock<Router>>,
    pub config: Arc<RwLock<Config>>,
    pub group_manager: SharedGroupManager,
    pub proxy_registry: Arc<ProxyRegistry>,
    pub runtime_registry: SharedRuntimeRegistry,
}

/// Spawn a background task that downloads the dashboard when the configured
/// directory is missing or empty. Fire-and-forget: outcomes are only logged.
pub fn spawn_ui_download_if_needed(ctx: UiDownloadContext) {
    let dir = ctx.external_ui.clone();
    tokio::spawn(async move {
        match ensure_external_ui(&ctx).await {
            Ok(true) => tracing::info!("external UI downloaded into {}", dir),
            Ok(false) => {}
            Err(e) => tracing::warn!("download external ui error: {:#}", e),
        }
    });
}

/// Ensure the configured directory exists and holds the dashboard,
/// downloading it when the directory is missing or empty. Returns
/// `Ok(true)` when a download was performed, `Ok(false)` when the directory
/// was already populated.
pub async fn ensure_external_ui(ctx: &UiDownloadContext) -> anyhow::Result<bool> {
    let dir = &ctx.external_ui;
    if dir.is_empty() {
        return Ok(false);
    }
    let path = Path::new(dir);
    match std::fs::read_dir(path) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Ok(false);
            }
        }
        Err(_) => std::fs::create_dir_all(path)?,
    }
    let configured_url = {
        let config = ctx.config.read().await;
        config
            .experimental
            .clash_api
            .external_ui_download_url
            .clone()
    };
    download_external_ui(ctx, &download_url(&configured_url)).await?;
    Ok(true)
}

/// The environment override wins over the configured URL, then the default.
fn download_url(configured: &str) -> String {
    std::env::var(UI_DOWNLOAD_URL_ENV).unwrap_or_else(|_| {
        if configured.is_empty() {
            DEFAULT_UI_DOWNLOAD_URL.to_string()
        } else {
            configured.to_string()
        }
    })
}

/// Where the routing decision sends the download.
enum UiRoute {
    Direct {
        feedback: Option<ScoreFeedback>,
    },
    Block,
    Proxy {
        node: Box<Node>,
        feedback: Option<ScoreFeedback>,
    },
}

/// Run the download target through the same routing pipeline as user
/// traffic: `Router::route_with_must` for the outbound name, then the
/// authoritative group/leaf resolution for the node to dial.
async fn decide_route(ctx: &UiDownloadContext, host: &str, port: u16) -> anyhow::Result<UiRoute> {
    let host_ip = parse_host_ip(host);
    let resolved_ip = if let Some(ip) = host_ip {
        Some(ip)
    } else {
        honk_outbound::bootstrap::resolve(host)
            .await
            .ok()
            .and_then(|addresses| addresses.into_iter().next())
    };
    let (dst_ip, domain) = match host_ip {
        Some(ip) => (
            ip,
            (!host.parse::<std::net::IpAddr>().is_ok()).then(|| host.to_string()),
        ),
        None => (
            resolved_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            Some(host.to_string()),
        ),
    };
    let info = ConnectionInfo {
        domain: domain.clone(),
        dst_ip,
        dst_port: port,
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        src_port: 0,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };
    let configured_detour = {
        let config = ctx.config.read().await;
        config
            .experimental
            .clash_api
            .external_ui_download_detour
            .clone()
    };
    let (outbound, rule) = if configured_detour.is_empty() {
        let router = ctx.router.read().await;
        let (outbound, _must) = router.route_with_must(&info);
        let rule = router
            .route_full(&info)
            .map(|m| format!("{}:{}", m.rule_type, m.rule_payload));
        (outbound.to_string(), rule)
    } else {
        (
            configured_detour,
            Some("experimental.clash_api.external_ui_download_detour".to_string()),
        )
    };
    let target_ipver = if matches!(dst_ip, std::net::IpAddr::V6(_)) {
        IpVersion::V6
    } else {
        IpVersion::V4
    };
    let score_ipver = resolved_ip.map(|ip| {
        if ip.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        }
    });
    let (nodes, feedback) = {
        let config = ctx.config.read().await;
        let group_manager = ctx.group_manager.read().clone();
        if config.groups.iter().any(|group| group.name == outbound) {
            let context = ScoreSelectionContext {
                network: SelectionNetwork::Tcp,
                probe_domain: ProbeDomain::Tcp,
                target_family: score_ipver,
                health_family: score_ipver.unwrap_or(target_ipver),
                target: Some(if domain.is_some() {
                    ScoreTarget::domain(host, port)
                } else {
                    std::net::SocketAddr::new(dst_ip, port).into()
                }),
            };
            let plan =
                group_manager.selection_plan_for_target_with_health_fallback(&outbound, &context);
            let mut entries = plan.entries.into_iter();
            match entries.next() {
                Some(entry) => (vec![entry.node.clone()], entry.feedback),
                None => (Vec::new(), None),
            }
        } else {
            (
                crate::control::reload::resolve_outbound_nodes(
                    &config,
                    &group_manager,
                    &outbound,
                    ProbeDomain::Tcp,
                    target_ipver,
                ),
                None,
            )
        }
    };
    let Some(node) = nodes.into_iter().next() else {
        anyhow::bail!("external UI download: outbound '{outbound}' has no available node");
    };
    let route = match node.protocol {
        NodeProtocol::Direct => UiRoute::Direct { feedback },
        NodeProtocol::Block => UiRoute::Block,
        _ => UiRoute::Proxy {
            node: Box::new(node),
            feedback,
        },
    };
    info!(
        outbound = %outbound,
        rule = rule.as_deref().unwrap_or("fallback"),
        via = match &route {
            UiRoute::Direct { .. } => "direct",
            UiRoute::Block => "block",
            UiRoute::Proxy { node, .. } => node.name.as_str(),
        },
        "external UI download routed"
    );
    Ok(route)
}

/// Download the archive at `url` and extract it into the configured
/// directory. On extraction failure the (possibly partial) directory
/// contents are removed again, matching sing-box's cleanup so the next
/// start retries the download.
pub async fn download_external_ui(ctx: &UiDownloadContext, url: &str) -> anyhow::Result<()> {
    info!("downloading external ui from {}", url);
    let bytes = fetch_routed(ctx, url).await?;
    let dir = ctx.external_ui.clone();
    let result = tokio::task::spawn_blocking(move || extract_ui_zip(&bytes, Path::new(&dir))).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            remove_all_in_directory(Path::new(&ctx.external_ui));
            Err(e)
        }
        Err(join_err) => {
            remove_all_in_directory(Path::new(&ctx.external_ui));
            Err(anyhow::anyhow!(
                "external ui extraction task failed: {}",
                join_err
            ))
        }
    }
}

/// Fetch `url` following the traffic routing decision; proxied redirects
/// re-enter the router because the Location host usually differs.
async fn fetch_routed(ctx: &UiDownloadContext, url: &str) -> anyhow::Result<Vec<u8>> {
    let mut url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let (host, port, path, is_https) = parse_download_url(&url)?;
        let response = match decide_route(ctx, &host, port).await? {
            UiRoute::Direct { feedback } => fetch_direct(&url, feedback).await?,
            UiRoute::Block => {
                anyhow::bail!("routing sends the external UI download to 'block'");
            }
            UiRoute::Proxy { node, feedback } => {
                fetch_proxied(ctx, &node, feedback, &host, port, &path, is_https).await?
            }
        };
        match response {
            ProxiedFetch::Body(bytes) => return Ok(bytes),
            ProxiedFetch::Redirect(location) => {
                url = reqwest::Url::parse(&url)?.join(&location)?.to_string();
                info!(url = %url, "external UI download following redirect");
            }
        }
    }
    anyhow::bail!("external UI download: too many redirects")
}

/// Direct fetch: plain reqwest (the control-plane PID bypass keeps the
/// gateway's own traffic out of the datapath), streaming with the archive
/// size cap.
async fn fetch_direct(url: &str, feedback: Option<ScoreFeedback>) -> anyhow::Result<ProxiedFetch> {
    let reporter = feedback.as_ref().map(ScoreFeedback::start);
    let result = async {
        let client = reqwest::Client::builder()
            .timeout(DOWNLOAD_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let mut response = client.get(url).send().await?;
        if let Some(reporter) = &reporter {
            reporter.setup_succeeded();
            reporter.first_response();
            reporter.tx(url.len() as u64);
        }
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .ok_or_else(|| anyhow::anyhow!("redirect {} without Location", response.status()))?
                .to_str()?
                .to_string();
            if let Some(reporter) = &reporter {
                reporter.rx(location.len() as u64);
            }
            return Ok(ProxiedFetch::Redirect(location));
        }
        if !response.status().is_success() {
            anyhow::bail!("download external ui failed: {}", response.status());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > MAX_ARCHIVE_BYTES {
                anyhow::bail!("external UI archive exceeds {} bytes", MAX_ARCHIVE_BYTES);
            }
            if let Some(reporter) = &reporter {
                reporter.rx(chunk.len() as u64);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(ProxiedFetch::Body(bytes))
    }
    .await;
    if let Some(reporter) = &reporter {
        reporter.finish(match &result {
            Ok(_) => ScoreOutcome::Success,
            Err(error) => ScoreOutcome::from_error(error),
        });
    }
    result
}

enum ProxiedFetch {
    Body(Vec<u8>),
    Redirect(String),
}

/// One proxied GET through `node`'s tunnel: dial by domain (the node's
/// egress resolves it, sidestepping local DNS poisoning), TLS for https,
/// then a minimal HTTP/1.1 exchange.
async fn fetch_proxied(
    ctx: &UiDownloadContext,
    node: &Node,
    feedback: Option<ScoreFeedback>,
    host: &str,
    port: u16,
    path: &str,
    is_https: bool,
) -> anyhow::Result<ProxiedFetch> {
    let entry = ctx
        .proxy_registry
        .find(node.protocol)
        .ok_or_else(|| anyhow::anyhow!("no handler for protocol {:?}", node.protocol))?;
    let connect_timeout = Duration::from_millis(ctx.config.read().await.global.connect_timeout_ms);
    // Tunnel handlers dial by domain; the address is only a fallback for
    // handlers that need a numeric target.
    let host_ip = parse_host_ip(host);
    let (domain, addr) = match host_ip {
        Some(ip) => (None, std::net::SocketAddr::new(ip, port)),
        None => (Some(host), std::net::SocketAddr::from(([0, 0, 0, 0], port))),
    };
    let generation = ctx.runtime_registry.read().clone();
    let (runtime, guard) = match generation
        .get(&node.id)
        .filter(|runtime| runtime.is_warm_or_stateless())
    {
        Some(runtime) => (runtime, None),
        None => {
            let guard = honk_outbound::runtime::NodeRuntime::ephemeral_guarded(node);
            (guard.runtime(), Some(guard))
        }
    };
    let reporter = feedback.as_ref().map(ScoreFeedback::start);
    let result = match entry
        .tcp
        .dial_runtime(runtime, addr, domain, connect_timeout)
        .await
    {
        Ok(proxy) => match tokio::time::timeout(
            DOWNLOAD_TIMEOUT,
            proxied_get(proxy.stream, host, path, is_https, &reporter),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "external UI download timed out",
            ))),
        },
        Err(e) => Err(e.context("external UI download dial failed")),
    };
    if let Some(reporter) = &reporter {
        reporter.finish(match &result {
            Ok(_) => ScoreOutcome::Success,
            Err(error) => ScoreOutcome::from_error(error),
        });
    }
    if let Some(guard) = guard {
        guard.close().await;
    }
    result
}

/// TLS-wrap when https, then run the HTTP/1.1 GET.
async fn proxied_get(
    stream: Box<dyn AsyncReadWrite>,
    host: &str,
    path: &str,
    is_https: bool,
    reporter: &Option<ScoreReporter>,
) -> anyhow::Result<ProxiedFetch> {
    if is_https {
        let connector = honk_outbound::tls::build_dns_connector(false, HTTP11_ALPN_WIRE)?;
        let mut tls = connector.connect(host, stream).await?;
        if let Some(reporter) = reporter {
            reporter.setup_succeeded();
        }
        http_get(&mut tls, host, path, reporter).await
    } else {
        let mut stream = stream;
        if let Some(reporter) = reporter {
            reporter.setup_succeeded();
        }
        http_get(&mut stream, host, path, reporter).await
    }
}

/// Minimal HTTP/1.1 GET: request, header parse, capped body read. Only
/// identity bodies are supported (Content-Length or read-to-close); GitHub
/// release assets always carry a length.
async fn http_get<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    reporter: &Option<ScoreReporter>,
) -> anyhow::Result<ProxiedFetch>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: honk-ui-download/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    if let Some(reporter) = reporter {
        reporter.tx(request.len() as u64);
    }

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("connection closed before response headers");
        }
        if let Some(reporter) = reporter {
            reporter.first_response();
            reporter.rx(n as u64);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEADER_BYTES {
            anyhow::bail!("response headers exceed {} bytes", MAX_HEADER_BYTES);
        }
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]);
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP status line"))?;
    let mut content_length = None;
    let mut location = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => content_length = value.trim().parse::<usize>().ok(),
            "location" => location = Some(value.trim().to_string()),
            "transfer-encoding" if !value.trim().eq_ignore_ascii_case("identity") => {
                anyhow::bail!("unsupported transfer-encoding: {}", value.trim());
            }
            _ => {}
        }
    }

    if matches!(status, 301 | 302 | 303 | 307 | 308) {
        let location =
            location.ok_or_else(|| anyhow::anyhow!("redirect {status} without Location"))?;
        return Ok(ProxiedFetch::Redirect(location));
    }
    if !(200..300).contains(&status) {
        anyhow::bail!("download external ui failed: {status}");
    }

    let mut body = buf.split_off(head_end);
    match content_length {
        Some(len) => {
            if len > MAX_ARCHIVE_BYTES {
                anyhow::bail!("external UI archive exceeds {} bytes", MAX_ARCHIVE_BYTES);
            }
            body.reserve(len.saturating_sub(body.len()));
            while body.len() < len {
                let n = stream.read(&mut chunk).await?;
                if let Some(reporter) = reporter {
                    reporter.rx(n as u64);
                }
                if n == 0 {
                    anyhow::bail!("truncated archive: {} of {} bytes", body.len(), len);
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(len);
        }
        None => loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            if let Some(reporter) = reporter {
                reporter.rx(n as u64);
            }
            if body.len() + n > MAX_ARCHIVE_BYTES {
                anyhow::bail!("external UI archive exceeds {} bytes", MAX_ARCHIVE_BYTES);
            }
            body.extend_from_slice(&chunk[..n]);
        },
    }
    Ok(ProxiedFetch::Body(body))
}

fn parse_host_ip(host: &str) -> Option<std::net::IpAddr> {
    host.parse()
        .ok()
        .or_else(|| host.strip_prefix('[')?.strip_suffix(']')?.parse().ok())
}

/// Split a download URL into (host, port, path, is_https); the scheme is
/// required and must be http or https.
fn parse_download_url(url: &str) -> anyhow::Result<(String, u16, String, bool)> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| anyhow::anyhow!("invalid external UI URL '{url}': {e}"))?;

    let is_https = match parsed.scheme() {
        "https" => true,
        "http" => false,
        _ => anyhow::bail!("unsupported scheme in external UI URL '{url}'"),
    };

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("empty host in external UI URL '{url}'"))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("missing port in external UI URL '{url}'"))?;

    let mut path = parsed.path().to_string();
    if let Some(q) = parsed.query() {
        path.push('?');
        path.push_str(q);
    }

    Ok((host.to_string(), port, path, is_https))
}

/// Extract a zip archive into `output`, stripping the single top-level
/// directory when every entry shares one (GitHub archives always do).
/// Entries with path-traversal components are skipped.
pub fn extract_ui_zip(bytes: &[u8], output: &Path) -> anyhow::Result<()> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    let names: Vec<String> = archive.file_names().map(str::to_string).collect();
    let trim_top = single_top_directory(&names);

    std::fs::create_dir_all(output)?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }
        let mut components: Vec<&str> = file.name().split('/').collect();
        if trim_top {
            components.remove(0);
        }
        // Reject traversal and empty components (zip-slip guard).
        if components
            .iter()
            .any(|c| c.is_empty() || *c == "." || *c == ".." || c.contains('\\'))
        {
            continue;
        }
        if components.is_empty() {
            continue;
        }
        let mut save_path = PathBuf::from(output);
        for component in components {
            save_path.push(component);
        }
        if let Some(parent) = save_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out_file = std::fs::File::create(&save_path)?;
        std::io::copy(&mut file as &mut dyn Read, &mut out_file)?;
    }
    Ok(())
}

/// `true` when every entry in the archive lives under the same top-level
/// directory (sing-box `zipIsInSingleDirectory`).
fn single_top_directory(names: &[String]) -> bool {
    let mut top: Option<&str> = None;
    for name in names {
        let mut parts = name.split('/');
        let Some(first) = parts.next() else {
            return false;
        };
        // An entry without a path separator sits at the archive root.
        if parts.next().is_none() {
            return false;
        }
        match top {
            None => top = Some(first),
            Some(t) if t != first => return false,
            _ => {}
        }
    }
    top.is_some()
}

/// Remove everything inside `directory` (best-effort).
fn remove_all_in_directory(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let _ = std::fs::remove_dir_all(entry.path());
        let _ = std::fs::remove_file(entry.path());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::group::{Group, GroupPolicy};
    use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
    use honk_outbound::group::GroupManager;
    use honk_outbound::proxy::{ProtocolEntry, ProxyStream, TcpOutbound};

    /// Build an in-memory zip with the given (path, contents) entries.
    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, contents) in entries {
            writer.start_file(*name, options).unwrap();
            std::io::Write::write_all(&mut writer, contents).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn test_ctx(dir: &Path, rules: &[RoutingRule]) -> UiDownloadContext {
        test_ctx_with_registry(
            dir,
            rules,
            Arc::new(ProxyRegistry::default_resolver().unwrap()),
        )
    }

    fn test_ctx_with_registry(
        dir: &Path,
        rules: &[RoutingRule],
        proxy_registry: Arc<ProxyRegistry>,
    ) -> UiDownloadContext {
        let config = Config::default();
        UiDownloadContext {
            external_ui: dir.to_string_lossy().into_owned(),
            router: Arc::new(RwLock::new(Router::new(rules, "direct").unwrap())),
            group_manager: Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
                &config.groups,
                &config.nodes,
            )))),
            config: Arc::new(RwLock::new(config)),
            proxy_registry,
            runtime_registry: Arc::new(parking_lot::RwLock::new(Arc::new(
                honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap(),
            ))),
        }
    }

    #[test]
    fn extract_strips_single_top_directory() {
        let zip_bytes = make_zip(&[
            ("dist/index.html", b"<html>zashboard</html>".as_slice()),
            ("dist/assets/app.js", b"console.log(1)".as_slice()),
        ]);
        let dir = tempfile::tempdir().unwrap();
        extract_ui_zip(&zip_bytes, dir.path()).unwrap();

        assert_eq!(
            std::fs::read(dir.path().join("index.html")).unwrap(),
            b"<html>zashboard</html>"
        );
        assert_eq!(
            std::fs::read(dir.path().join("assets/app.js")).unwrap(),
            b"console.log(1)"
        );
        // The top-level archive directory must not appear.
        assert!(!dir.path().join("dist").exists());
    }

    #[test]
    fn extract_keeps_layout_without_single_top_directory() {
        let zip_bytes = make_zip(&[
            ("index.html", b"root".as_slice()),
            ("sub/page.js", b"sub".as_slice()),
        ]);
        let dir = tempfile::tempdir().unwrap();
        extract_ui_zip(&zip_bytes, dir.path()).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("index.html")).unwrap(),
            b"root"
        );
        assert_eq!(
            std::fs::read(dir.path().join("sub/page.js")).unwrap(),
            b"sub"
        );
    }

    #[test]
    fn extract_skips_traversal_entries() {
        let zip_bytes = make_zip(&[
            ("top/../evil.txt", b"evil".as_slice()),
            ("top/ok.txt", b"ok".as_slice()),
        ]);
        let dir = tempfile::tempdir().unwrap();
        extract_ui_zip(&zip_bytes, dir.path()).unwrap();
        assert!(!dir.path().join("evil.txt").exists());
        assert!(!dir.path().join("../evil.txt").exists());
        assert_eq!(std::fs::read(dir.path().join("ok.txt")).unwrap(), b"ok");
    }

    /// Raw TCP HTTP server serving `body` once per connection.
    async fn spawn_zip_server(body: Vec<u8>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn configured_url_and_detour_download_into_empty_directory() {
        let zip_bytes = make_zip(&[("dist/index.html", b"<html>y</html>".as_slice())]);
        let addr = spawn_zip_server(zip_bytes).await;
        let dir = tempfile::tempdir().unwrap();
        let ui_dir = dir.path().join("ui");
        let rules = vec![RoutingRule {
            name: "block-ui".into(),
            condition: RoutingCondition {
                ip: vec!["127.0.0.1/32".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("block".into()),
            priority: 0,
            must: false,
            mark: 0,
        }];
        let ctx = test_ctx(&ui_dir, &rules);
        {
            let mut config = ctx.config.write().await;
            config.experimental.clash_api.external_ui_download_url =
                format!("http://{addr}/ui.zip");
            config.experimental.clash_api.external_ui_download_detour = "direct".into();
        }

        assert!(ensure_external_ui(&ctx).await.unwrap());
        assert_eq!(
            std::fs::read(ui_dir.join("index.html")).unwrap(),
            b"<html>y</html>"
        );
    }

    #[tokio::test]
    async fn ensure_skips_populated_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "existing").unwrap();
        // A bogus URL proves no download is attempted for populated dirs.
        let downloaded = ensure_external_ui(&test_ctx(dir.path(), &[]))
            .await
            .unwrap();
        assert!(!downloaded);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("index.html")).unwrap(),
            "existing"
        );
    }

    #[tokio::test]
    async fn failed_download_cleans_partial_directory() {
        let zip_bytes = make_zip(&[("top/ok.txt", b"ok".as_slice())]);
        // Corrupt the archive so extraction fails after a successful GET.
        let garbage = zip_bytes[..zip_bytes.len() / 2].to_vec();
        let addr = spawn_zip_server(garbage).await;
        let dir = tempfile::tempdir().unwrap();
        let result = download_external_ui(
            &test_ctx(dir.path(), &[]),
            &format!("http://{}/bad.zip", addr),
        )
        .await;
        assert!(result.is_err());
        // Partial contents are removed so the next start retries.
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[tokio::test]
    async fn blocked_route_aborts_download_before_any_fetch() {
        let rules = vec![RoutingRule {
            name: "block-ui".into(),
            condition: RoutingCondition {
                domain_suffix: vec!["blocked.test".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("block".into()),
            priority: 0,
            must: false,
            mark: 0,
        }];
        let dir = tempfile::tempdir().unwrap();
        let result =
            download_external_ui(&test_ctx(dir.path(), &rules), "http://blocked.test/ui.zip").await;
        assert!(result.is_err(), "a block routing decision must fail closed");
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[tokio::test]
    async fn direct_redirect_reenters_routing_without_local_dns() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://blocked.test/ui.zip\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let rules = vec![RoutingRule {
            name: "block-redirect".into(),
            condition: RoutingCondition {
                domain_suffix: vec!["blocked.test".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("block".into()),
            priority: 0,
            must: false,
            mark: 0,
        }];
        let dir = tempfile::tempdir().unwrap();

        let error = fetch_routed(
            &test_ctx(dir.path(), &rules),
            &format!("http://{addr}/redirect"),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("routing sends"), "{error:#}");
    }

    /// Mock tunnel handler: dials the target with a plain TcpStream, so the
    /// proxied fetch path runs end-to-end against a loopback server.
    struct LoopbackHandler;

    #[async_trait::async_trait]
    impl TcpOutbound for LoopbackHandler {
        async fn dial(
            &self,
            _node: &Node,
            target: std::net::SocketAddr,
            target_domain: Option<&str>,
            _connect_timeout: Duration,
        ) -> anyhow::Result<ProxyStream> {
            let stream = tokio::net::TcpStream::connect(target).await?;
            Ok(ProxyStream {
                stream: Box::new(stream),
                target_addr: target,
                target_domain: target_domain.map(|s| s.to_string()),
            })
        }
    }

    #[tokio::test]
    async fn proxied_route_fetches_through_node_handler() {
        let zip_bytes = make_zip(&[("dist/index.html", b"<html>p</html>".as_slice())]);
        let addr = spawn_zip_server(zip_bytes).await;

        let mut node = Node {
            name: "mock".into(),
            protocol: NodeProtocol::Socks5,
            address: "127.0.0.1".into(),
            port: 1,
            ..Default::default()
        };
        node.id = node.derive_id();
        let mut registry = ProxyRegistry::new();
        registry.register(ProtocolEntry::new(
            NodeProtocol::Socks5,
            Arc::new(LoopbackHandler),
        ));

        let rules = vec![RoutingRule {
            name: "proxy-ui".into(),
            condition: RoutingCondition {
                ip: vec!["127.0.0.1/32".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("mock".into()),
            priority: 0,
            must: false,
            mark: 0,
        }];
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx_with_registry(dir.path(), &rules, Arc::new(registry));
        ctx.config.write().await.nodes.push(node);
        download_external_ui(&ctx, &format!("http://{addr}/ui.zip"))
            .await
            .expect("proxied download must succeed");
        assert_eq!(
            std::fs::read(dir.path().join("index.html")).unwrap(),
            b"<html>p</html>"
        );
    }
    #[tokio::test]
    async fn score_route_attributes_target_and_rewards_useful_body_exchange() {
        let body = b"dashboard bytes".to_vec();
        let addr = spawn_zip_server(body.clone()).await;
        let nodes = ["a", "b"].map(|name| {
            let mut node = Node {
                name: name.into(),
                protocol: NodeProtocol::Socks5,
                address: "127.0.0.1".into(),
                port: 1,
                ..Default::default()
            };
            node.id = node.derive_id();
            node
        });
        let child = Group {
            name: "ui-child".into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        };
        let parent = Group {
            name: "ui-parent".into(),
            policy: GroupPolicy::Score,
            groups: vec![child.name.clone()],
            ..Default::default()
        };
        let config = Config {
            nodes: nodes.to_vec(),
            groups: vec![child, parent],
            ..Default::default()
        };
        let rules = vec![RoutingRule {
            name: "score-ui".into(),
            condition: RoutingCondition {
                ip: vec!["127.0.0.1/32".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("ui-parent".into()),
            priority: 0,
            must: false,
            mark: 0,
        }];
        let mut registry = ProxyRegistry::new();
        registry.register(ProtocolEntry::new(
            NodeProtocol::Socks5,
            Arc::new(LoopbackHandler),
        ));
        let dir = tempfile::tempdir().unwrap();
        let ctx = UiDownloadContext {
            external_ui: dir.path().to_string_lossy().into_owned(),
            router: Arc::new(RwLock::new(Router::new(&rules, "direct").unwrap())),
            group_manager: Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
                &config.groups,
                &config.nodes,
            )))),
            config: Arc::new(RwLock::new(config)),
            proxy_registry: Arc::new(registry),
            runtime_registry: Arc::new(parking_lot::RwLock::new(Arc::new(
                honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap(),
            ))),
        };

        let UiRoute::Proxy { node, feedback } =
            decide_route(&ctx, "127.0.0.1", addr.port()).await.unwrap()
        else {
            panic!("Score group must resolve to a proxy leaf");
        };
        assert_eq!(node.id, nodes[0].id);
        let feedback = feedback.expect("Score route must carry feedback");
        assert_eq!(
            feedback
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["ui-parent", "ui-child"]
        );
        let fetched = fetch_proxied(
            &ctx,
            &node,
            Some(feedback),
            "127.0.0.1",
            addr.port(),
            "/ui.zip",
            false,
        )
        .await
        .unwrap();
        assert!(matches!(fetched, ProxiedFetch::Body(bytes) if bytes == body));

        let UiRoute::Proxy { node, feedback } =
            decide_route(&ctx, "127.0.0.1", addr.port()).await.unwrap()
        else {
            panic!("Score group must resolve to a proxy leaf");
        };
        assert_eq!(node.id, nodes[1].id);
        let reporter = feedback.unwrap().start();
        reporter.setup_succeeded();
        reporter.finish(ScoreOutcome::Success);

        let UiRoute::Proxy { node, .. } =
            decide_route(&ctx, "127.0.0.1", addr.port()).await.unwrap()
        else {
            panic!("Score group must resolve to a proxy leaf");
        };
        assert_eq!(node.id, nodes[0].id);
    }

    #[tokio::test]
    async fn direct_score_ui_route_reports_target_exchange() {
        let body = b"direct dashboard".to_vec();
        let addr = spawn_zip_server(body.clone()).await;
        let direct = Config::builtin_direct_node();
        let group = Group {
            name: "ui-direct".into(),
            policy: GroupPolicy::Score,
            nodes: vec![direct.id],
            ..Default::default()
        };
        let config = Config {
            nodes: vec![direct],
            groups: vec![group],
            ..Default::default()
        };
        let rules = vec![RoutingRule {
            name: "score-ui-direct".into(),
            condition: RoutingCondition {
                ip: vec!["127.0.0.1/32".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("ui-direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        }];
        let dir = tempfile::tempdir().unwrap();
        let ctx = UiDownloadContext {
            external_ui: dir.path().to_string_lossy().into_owned(),
            router: Arc::new(RwLock::new(Router::new(&rules, "direct").unwrap())),
            group_manager: Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
                &config.groups,
                &config.nodes,
            )))),
            config: Arc::new(RwLock::new(config)),
            proxy_registry: Arc::new(ProxyRegistry::default_resolver().unwrap()),
            runtime_registry: Arc::new(parking_lot::RwLock::new(Arc::new(
                honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap(),
            ))),
        };
        let UiRoute::Direct { feedback } =
            decide_route(&ctx, "127.0.0.1", addr.port()).await.unwrap()
        else {
            panic!("Score group must resolve to direct");
        };
        assert_eq!(
            feedback
                .as_ref()
                .unwrap()
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["ui-direct"]
        );
        let fetched = fetch_direct(&format!("http://{addr}/ui.zip"), feedback)
            .await
            .unwrap();
        assert!(matches!(fetched, ProxiedFetch::Body(bytes) if bytes == body));
        let UiRoute::Direct { feedback } =
            decide_route(&ctx, "127.0.0.1", addr.port()).await.unwrap()
        else {
            panic!("Score group must still resolve to direct");
        };
        feedback
            .unwrap()
            .start()
            .setup_failed(ScoreOutcome::Timeout);
    }
}
