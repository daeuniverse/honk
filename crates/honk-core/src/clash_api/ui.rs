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
//! normal traffic routing decision: `direct` uses a bypass-marked socket,
//! `block` aborts, and other results use the selected node's tunnel.
//!
//! The download URL defaults to [`DEFAULT_UI_DOWNLOAD_URL`].
//! `external_ui_download_url` configures it, while `HONK_UI_DOWNLOAD_URL`
//! remains the highest-precedence override.

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use honk_config::Config;
use honk_config::node::Node;
use honk_outbound::group::{
    ScoreAttempt, ScoreBusinessGuard, ScoreContinuation, ScoreOutcome, ScoreReporter,
    SharedGroupManager,
};
use honk_outbound::proxy::{AsyncReadWrite, ProxyRegistry};
use honk_outbound::runtime::SharedRuntimeRegistry;
use tokio::io::AsyncWriteExt;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;
use tracing::info;

use crate::download_route::{Outbounds, Route as UiRoute};
use crate::routing::Router;

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
/// Extraction bounds: a small archive must not unpack into an unbounded tree.
const EXTRACT_LIMITS: ExtractLimits = ExtractLimits {
    bytes: 128 * 1024 * 1024,
    entries: 10_000,
};

#[derive(Debug, Clone, Copy)]
struct ExtractLimits {
    bytes: u64,
    entries: usize,
}

/// Redirects followed per proxied fetch (each hop is re-routed: the
/// Location target is usually a different host).
const MAX_REDIRECTS: u32 = 5;

/// Everything the download needs to route the fetch like user traffic.
pub struct UiDownloadContext {
    pub external_ui: String,
    pub router: Arc<RwLock<Router>>,
    pub config: Arc<RwLock<Arc<Config>>>,
    pub group_manager: SharedGroupManager,
    pub proxy_registry: Arc<ProxyRegistry>,
    pub runtime_registry: SharedRuntimeRegistry,
}

/// Owns the one startup download; stopping never schedules a retry.
#[must_use = "retain the UI download owner and call stop_and_join before teardown"]
pub struct UiDownloadTask {
    stop: watch::Sender<bool>,
    handle: Option<JoinHandle<()>>,
}

impl UiDownloadTask {
    pub(crate) async fn stop_and_join(&mut self) -> anyhow::Result<()> {
        self.stop.send_replace(true);
        if let Some(handle) = self.handle.as_mut() {
            // Await in place: a caller's deadline must not lose the extraction join.
            let result = handle.await;
            self.handle = None;
            result.map_err(|error| anyhow::anyhow!("external UI download task failed: {error}"))?;
        }
        Ok(())
    }
}

impl Drop for UiDownloadTask {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if self.handle.is_some() {
            tracing::error!("external UI download owner dropped without stop_and_join");
        }
    }
}

impl UiDownloadContext {
    fn outbounds(&self) -> Outbounds<'_> {
        Outbounds {
            router: &self.router,
            config: &self.config,
            group_manager: &self.group_manager,
            proxy_registry: &self.proxy_registry,
            runtime_registry: &self.runtime_registry,
        }
    }
}

/// Spawn an owned download when the configured directory is missing or empty.
pub(crate) fn spawn_ui_download_if_needed(ctx: UiDownloadContext) -> UiDownloadTask {
    let (stop, stop_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        match ensure_external_ui_with_stop(&ctx, &mut Some(stop_rx)).await {
            Ok(true) => tracing::info!("external UI downloaded into {}", ctx.external_ui),
            Ok(false) => {}
            Err(e) => tracing::warn!("download external ui error: {:#}", e),
        }
    });
    UiDownloadTask {
        stop,
        handle: Some(handle),
    }
}

async fn download_stopped(stop: &mut Option<watch::Receiver<bool>>) {
    match stop {
        Some(stop) => {
            let _ = stop.wait_for(|stopped| *stopped).await;
        }
        None => std::future::pending().await,
    }
}

/// Ensure the configured directory exists and holds the dashboard,
/// downloading it when the directory is missing or empty. Returns
/// `Ok(true)` when a download was performed, `Ok(false)` when the directory
/// was already populated.
pub async fn ensure_external_ui(ctx: &UiDownloadContext) -> anyhow::Result<bool> {
    ensure_external_ui_with_stop(ctx, &mut None).await
}

async fn ensure_external_ui_with_stop(
    ctx: &UiDownloadContext,
    stop: &mut Option<watch::Receiver<bool>>,
) -> anyhow::Result<bool> {
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
    let configured_url = tokio::select! {
        biased;
        _ = download_stopped(stop) => return Ok(false),
        config = ctx.config.read() => config
            .experimental
            .clash_api
            .external_ui_download_url
            .clone(),
    };
    download_external_ui_with_stop(ctx, &download_url(&configured_url), stop).await
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

/// Run the download target through the configured detour, or through the
/// same routing pipeline as user traffic when none is set.
async fn decide_route(
    ctx: &UiDownloadContext,
    host: &str,
    port: u16,
    original: Option<&ScoreContinuation>,
) -> anyhow::Result<UiRoute> {
    let detour = ctx
        .config
        .read()
        .await
        .experimental
        .clash_api
        .external_ui_download_detour
        .clone();
    ctx.outbounds()
        .decide(
            (!detour.is_empty()).then_some(detour.as_str()),
            "experimental.clash_api.external_ui_download_detour",
            "external UI download",
            (host, port),
            original,
        )
        .await
        .map(|decision| decision.route)
}

/// Download the archive at `url` and extract it into the configured
/// directory. On extraction failure the (possibly partial) directory
/// contents are removed again, matching sing-box's cleanup so the next
/// start retries the download.
pub async fn download_external_ui(ctx: &UiDownloadContext, url: &str) -> anyhow::Result<()> {
    download_external_ui_with_stop(ctx, url, &mut None)
        .await
        .map(|_| ())
}

async fn download_external_ui_with_stop(
    ctx: &UiDownloadContext,
    url: &str,
    stop: &mut Option<watch::Receiver<bool>>,
) -> anyhow::Result<bool> {
    info!("downloading external ui from {}", url);
    let mut archive = ArchiveFile::create(Path::new(&ctx.external_ui))?;
    if !fetch_routed(ctx, url, &mut archive, stop).await? {
        return Ok(false);
    }
    if stop.as_ref().is_some_and(|stop| *stop.borrow()) {
        return Ok(false);
    }
    let file = archive.finish().await?;
    let dir = ctx.external_ui.clone();
    // Once accepted, blocking filesystem work must finish even if stop arrives.
    let result = tokio::task::spawn_blocking(move || {
        extract_ui_zip(std::io::BufReader::new(file), Path::new(&dir))
    })
    .await;
    match result {
        Ok(Ok(())) => Ok(true),
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

/// Fetch `url` into `archive` following the traffic routing decision; proxied
/// redirects re-enter the router because the Location host usually differs.
/// `Ok(false)` when stopped.
async fn fetch_routed(
    ctx: &UiDownloadContext,
    url: &str,
    archive: &mut ArchiveFile,
    stop: &mut Option<watch::Receiver<bool>>,
) -> anyhow::Result<bool> {
    let mut url = url.to_string();
    let mut original_business: Option<ScoreContinuation> = None;
    for _ in 0..=MAX_REDIRECTS {
        let (parsed, host, port) = parse_download_url(&url)?;
        let route = tokio::select! {
            biased;
            _ = download_stopped(stop) => return Ok(false),
            route = decide_route(ctx, &host, port, original_business.as_ref()) => route?,
        };
        let original_attempt = match &route {
            UiRoute::Direct { feedback } | UiRoute::Proxy { feedback, .. }
                if original_business.is_none() =>
            {
                feedback.clone()
            }
            _ => None,
        };
        let response = match route {
            UiRoute::Direct { feedback } => fetch_direct(&url, feedback, archive, stop).await?,
            UiRoute::Block => {
                anyhow::bail!("routing sends the external UI download to 'block'");
            }
            UiRoute::Proxy { node, feedback } => {
                let target = (&parsed, host.as_str(), port);
                fetch_proxied(ctx, &node, feedback, target, archive, stop).await?
            }
        };
        match response {
            ProxiedFetch::Body => return Ok(true),
            ProxiedFetch::Stopped => return Ok(false),
            ProxiedFetch::Redirect(location) => {
                if let Some(original) = original_attempt {
                    original_business = Some(original.continuation()?);
                }
                url = parsed.join(&location)?.to_string();
                info!(url = %url, "external UI download following redirect");
            }
        }
    }
    anyhow::bail!("external UI download: too many redirects")
}

/// Direct fetch on a bypass-marked socket, streaming with the archive size cap.
async fn fetch_direct(
    url: &str,
    feedback: Option<ScoreAttempt>,
    archive: &mut ArchiveFile,
    stop: &mut Option<watch::Receiver<bool>>,
) -> anyhow::Result<ProxiedFetch> {
    let reporter = feedback
        .as_ref()
        .map(ScoreAttempt::begin)
        .transpose()?
        .map(ScoreBusinessGuard::start);
    let result = tokio::select! {
        biased;
        _ = download_stopped(stop) => Ok(ProxiedFetch::Stopped),
        result = tokio::time::timeout(DOWNLOAD_TIMEOUT, async {
        let prepared = crate::marked_http::Client::new()?
            .prepare(
                &reqwest::Url::parse(url)?,
                &http::HeaderMap::new(),
                DOWNLOAD_TIMEOUT,
            )
            .await?;
        if let Some(reporter) = &reporter {
            reporter.setup_succeeded();
        }
        let response = crate::marked_http::send(prepared).await?;
        receive(response, url, archive, &reporter).await
        }) => result
            .map_err(|_| timed_out())
            .and_then(|result| result),
    };
    if let Some(reporter) = &reporter {
        reporter.finish(match &result {
            Ok(ProxiedFetch::Stopped) => ScoreOutcome::Cancelled,
            Ok(_) => ScoreOutcome::Success,
            Err(error) => ScoreOutcome::from_error(error),
        });
    }
    result
}

enum ProxiedFetch {
    /// The body is in the archive file.
    Body,
    Redirect(String),
    Stopped,
}

/// One proxied GET of `url` through `node`'s tunnel to `host:port`.
async fn fetch_proxied(
    ctx: &UiDownloadContext,
    node: &Node,
    feedback: Option<ScoreAttempt>,
    (url, host, port): (&reqwest::Url, &str, u16),
    archive: &mut ArchiveFile,
    stop: &mut Option<watch::Receiver<bool>>,
) -> anyhow::Result<ProxiedFetch> {
    let outbounds = ctx.outbounds();
    let tunnel = tokio::select! {
        biased;
        _ = download_stopped(stop) => return Ok(ProxiedFetch::Stopped),
        tunnel = outbounds.tunnel(node, (host, port)) => tunnel?,
    };
    let mut reporter = None;
    let result = tokio::select! {
        biased;
        _ = download_stopped(stop) => Ok(ProxiedFetch::Stopped),
        result = async {
        reporter = feedback
            .as_ref()
            .map(ScoreAttempt::begin)
            .transpose()?
            .map(ScoreBusinessGuard::start);
        match tunnel.dial().await {
        Ok(stream) => match tokio::time::timeout(
            DOWNLOAD_TIMEOUT,
            async {
                let by = tokio::time::Instant::now() + DOWNLOAD_TIMEOUT;
                proxied_get(&crate::marked_http::Client::new()?, stream, url, archive, &reporter, by).await
            },
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(timed_out()),
        },
        Err(e) => Err(e.context("external UI download dial failed")),
        } } => result,
    };
    if let Some(reporter) = &reporter {
        reporter.finish(match &result {
            Ok(ProxiedFetch::Stopped) => ScoreOutcome::Cancelled,
            Ok(_) => ScoreOutcome::Success,
            Err(error) => ScoreOutcome::from_error(error),
        });
    }
    tunnel.close().await?;
    result
}

/// The GET over the tunnel's stream, answered like the direct one.
async fn proxied_get(
    client: &crate::marked_http::Client,
    stream: Box<dyn AsyncReadWrite>,
    url: &reqwest::Url,
    archive: &mut ArchiveFile,
    reporter: &Option<ScoreReporter>,
    by: tokio::time::Instant,
) -> anyhow::Result<ProxiedFetch> {
    let prepared = client
        .prepare_over(stream, url, &http::HeaderMap::new(), by)
        .await?;
    if let Some(reporter) = reporter {
        reporter.setup_succeeded();
    }
    let response = crate::marked_http::send(prepared).await?;
    receive(response, url.as_str(), archive, reporter).await
}

/// Scored as a timeout, not as another failure.
fn timed_out() -> anyhow::Error {
    anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "external UI download timed out",
    ))
}

/// A redirect's Location, a failure, or the body streamed into `archive`.
async fn receive(
    mut response: crate::marked_http::Response,
    url: &str,
    archive: &mut ArchiveFile,
    reporter: &Option<ScoreReporter>,
) -> anyhow::Result<ProxiedFetch> {
    if let Some(reporter) = reporter {
        reporter.first_response();
        reporter.tx(url.len() as u64);
    }
    if crate::marked_http::followed_redirect(response.status()) {
        let location = response
            .headers()
            .get(http::header::LOCATION)
            .ok_or_else(|| anyhow::anyhow!("redirect {} without Location", response.status()))?
            .to_str()?
            .to_string();
        if let Some(reporter) = reporter {
            reporter.rx(location.len() as u64);
        }
        return Ok(ProxiedFetch::Redirect(location));
    }
    if !response.status().is_success() {
        anyhow::bail!("download external ui failed: {}", response.status());
    }
    while let Some(chunk) = response.body_mut().chunk().await? {
        if let Some(reporter) = reporter {
            reporter.rx(chunk.len() as u64);
        }
        archive.append(&chunk).await?;
    }
    Ok(ProxiedFetch::Body)
}

/// The archive being downloaded: an unlinked private file beside the target
/// directory, so the download is not held in memory, stays on the target's
/// filesystem and leaves nothing behind on any path.
struct ArchiveFile {
    file: tokio::fs::File,
    len: usize,
    limit: usize,
}

impl ArchiveFile {
    fn create(target: &Path) -> std::io::Result<Self> {
        let parent = match target.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        Ok(Self {
            file: tokio::fs::File::from_std(unlinked_file(parent)?),
            len: 0,
            limit: MAX_ARCHIVE_BYTES,
        })
    }

    async fn append(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        if self.len + bytes.len() > self.limit {
            anyhow::bail!("external UI archive exceeds {} bytes", self.limit);
        }
        self.file.write_all(bytes).await?;
        self.len += bytes.len();
        Ok(())
    }

    /// The written file, positioned at its start.
    async fn finish(mut self) -> std::io::Result<std::fs::File> {
        self.file.flush().await?;
        let mut file = self.file.into_std().await;
        file.rewind()?;
        Ok(file)
    }
}

/// A 0600 file in `directory` with no name: `O_TMPFILE`, or where the
/// filesystem lacks it, a new name unlinked as soon as it is open.
fn unlinked_file(directory: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).mode(0o600);
    match options
        .clone()
        .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
        .open(directory)
    {
        Ok(file) => return Ok(file),
        Err(error) if matches!(error.raw_os_error(), Some(libc::EOPNOTSUPP | libc::EISDIR)) => {}
        Err(error) => return Err(error),
    }
    named_then_unlinked(directory, options)
}

fn named_then_unlinked(
    directory: &Path,
    mut options: std::fs::OpenOptions,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    options
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    for attempt in 0..16 {
        let path = directory.join(format!(".honk-ui-{}-{attempt}.zip", std::process::id()));
        match options.open(&path) {
            Ok(file) => {
                std::fs::remove_file(&path)?;
                return Ok(file);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(std::io::ErrorKind::AlreadyExists.into())
}

/// Parse a download URL with its host and port; the scheme is required and
/// must be http or https.
fn parse_download_url(url: &str) -> anyhow::Result<(reqwest::Url, String, u16)> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| anyhow::anyhow!("invalid external UI URL '{url}': {e}"))?;

    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("unsupported scheme in external UI URL '{url}'");
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("empty host in external UI URL '{url}'"))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("missing port in external UI URL '{url}'"))?;

    Ok((parsed, host, port))
}

/// Extract a zip archive into `output`, stripping the single top-level
/// directory when every entry shares one (GitHub archives always do).
/// Entries with path-traversal components are skipped. An archive with more
/// than 10,000 entries or 128 MiB of content is refused; the caller removes
/// what was written.
pub fn extract_ui_zip(archive: impl Read + Seek, output: &Path) -> anyhow::Result<()> {
    extract_ui_zip_bounded(archive, output, EXTRACT_LIMITS)
}

fn extract_ui_zip_bounded(
    archive: impl Read + Seek,
    output: &Path,
    limits: ExtractLimits,
) -> anyhow::Result<()> {
    let mut archive = zip::ZipArchive::new(archive)?;
    if archive.len() > limits.entries {
        anyhow::bail!(
            "external UI archive has more than {} entries",
            limits.entries
        );
    }
    let mut remaining = limits.bytes;
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
        // Counted as written: the declared size of an entry is not trusted.
        let written = std::io::copy(
            &mut (&mut file as &mut dyn Read).take(remaining + 1),
            &mut out_file,
        )?;
        remaining = remaining.checked_sub(written).ok_or_else(|| {
            anyhow::anyhow!("external UI archive expands past {} bytes", limits.bytes)
        })?;
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
    use honk_config::types::NodeProtocol;
    use honk_outbound::alive::{IpVersion, ProbeDomain};
    use honk_outbound::group::{GroupManager, ScoreSelectionContext, SelectionNetwork};
    use honk_outbound::proxy::{ProtocolEntry, ProxyStream, TcpOutbound};
    use tokio::io::AsyncReadExt;

    mod attribution;

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
            config: Arc::new(RwLock::new(Arc::new(config))),
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
        extract_ui_zip(std::io::Cursor::new(&zip_bytes), dir.path()).unwrap();

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
    fn extract_refuses_an_archive_that_expands_past_its_bounds() {
        let limits = ExtractLimits {
            bytes: 1024 * 1024,
            entries: 4,
        };
        let bomb = make_zip(&[("dist/zeros.bin", vec![0; 2 * 1024 * 1024].as_slice())]);
        assert!(bomb.len() < 64 * 1024, "the fixture compresses well");
        let dir = tempfile::tempdir().unwrap();
        let error =
            extract_ui_zip_bounded(std::io::Cursor::new(&bomb), dir.path(), limits).unwrap_err();
        assert!(error.to_string().contains("expands past"), "{error}");

        let many: Vec<(String, Vec<u8>)> = (0..5)
            .map(|index| (format!("dist/{index}.js"), vec![1]))
            .collect();
        let entries: Vec<(&str, &[u8])> = many
            .iter()
            .map(|(name, body)| (name.as_str(), body.as_slice()))
            .collect();
        let error =
            extract_ui_zip_bounded(std::io::Cursor::new(make_zip(&entries)), dir.path(), limits)
                .unwrap_err();
        assert!(error.to_string().contains("entries"), "{error}");
        assert!(
            extract_ui_zip_bounded(
                std::io::Cursor::new(make_zip(&entries[..4])),
                dir.path(),
                limits
            )
            .is_ok()
        );
    }

    #[test]
    fn extract_keeps_layout_without_single_top_directory() {
        let zip_bytes = make_zip(&[
            ("index.html", b"root".as_slice()),
            ("sub/page.js", b"sub".as_slice()),
        ]);
        let dir = tempfile::tempdir().unwrap();
        extract_ui_zip(std::io::Cursor::new(&zip_bytes), dir.path()).unwrap();
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
        extract_ui_zip(std::io::Cursor::new(&zip_bytes), dir.path()).unwrap();
        assert!(!dir.path().join("evil.txt").exists());
        assert!(!dir.path().join("../evil.txt").exists());
        assert_eq!(std::fs::read(dir.path().join("ok.txt")).unwrap(), b"ok");
    }

    async fn archive_bytes(archive: ArchiveFile) -> Vec<u8> {
        let mut bytes = Vec::new();
        archive
            .finish()
            .await
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        bytes
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

    async fn read_test_request(socket: &mut tokio::net::TcpStream) {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
            assert!(request.len() < 64 * 1024);
        }
    }

    async fn assert_stop_closes_stalled_body(ctx: UiDownloadContext) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let mut config = ctx.config.write().await;
            Arc::make_mut(&mut config)
                .experimental
                .clash_api
                .external_ui_download_url = format!("http://{addr}/ui.zip");
        }
        let (headers_tx, headers_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_test_request(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nx")
                .await
                .unwrap();
            headers_tx.send(()).unwrap();
            let mut byte = [0];
            let closed = socket.read(&mut byte).await;
            assert!(
                matches!(&closed, Ok(0))
                    || matches!(&closed, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
                "stopping the download must close the peer connection: {closed:?}"
            );
        });
        let directory = ctx.external_ui.clone();
        let mut task = spawn_ui_download_if_needed(ctx);
        tokio::time::timeout(Duration::from_secs(2), headers_rx)
            .await
            .expect("the request must reach the loopback server")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), task.stop_and_join())
            .await
            .expect("stop must cancel the body, not wait for the 30-second download timeout")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("the peer must observe the canceled connection")
            .unwrap();
        assert!(std::fs::read_dir(directory).unwrap().next().is_none());
        task.stop_and_join().await.unwrap();
    }

    #[tokio::test]
    async fn stop_cancels_stalled_direct_body_and_joins() {
        let dir = tempfile::tempdir().unwrap();
        assert_stop_closes_stalled_body(test_ctx(dir.path(), &[])).await;
    }

    #[tokio::test]
    async fn stop_cancels_stalled_proxy_body_and_joins() {
        let mut registry = ProxyRegistry::new();
        registry.register(ProtocolEntry::new(
            NodeProtocol::Socks5,
            Arc::new(LoopbackHandler),
        ));
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx_with_registry(dir.path(), &[], Arc::new(registry));
        let mut node = Node {
            name: "ui-proxy".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
            address: "127.0.0.1".into(),
            port: 1,
            ..Default::default()
        };
        node.id = node.derive_id();
        {
            let mut config = ctx.config.write().await;
            let config = Arc::make_mut(&mut config);
            config.experimental.clash_api.external_ui_download_detour = node.name.clone();
            config.nodes.push(node);
        }
        assert_stop_closes_stalled_body(ctx).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_retains_started_extraction_across_canceled_join() {
        use std::os::unix::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().unwrap();
        let fifo_path = dir.path().join("barrier");
        let started_path = dir.path().join("started");
        let index_path = dir.path().join("index.html");
        let zip_bytes = make_zip(&[
            ("dist/started", b"started".as_slice()),
            ("dist/barrier", b"release".as_slice()),
            ("dist/index.html", b"complete".as_slice()),
        ]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        let (body_tx, body_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_test_request(&mut socket).await;
            request_tx.send(()).unwrap();
            body_rx.await.unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                zip_bytes.len()
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            socket.write_all(&zip_bytes).await.unwrap();
        });
        let ctx = test_ctx(dir.path(), &[]);
        {
            let mut config = ctx.config.write().await;
            Arc::make_mut(&mut config)
                .experimental
                .clash_api
                .external_ui_download_url = format!("http://{addr}/ui.zip");
        }
        let mut task = spawn_ui_download_if_needed(ctx);
        tokio::time::timeout(Duration::from_secs(2), request_rx)
            .await
            .unwrap()
            .unwrap();
        // Create the barrier after the empty-directory check, before delivering the ZIP.
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        body_tx.send(()).unwrap();
        let started = tokio::time::timeout(Duration::from_secs(2), async {
            while !started_path.exists() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
        let first_stop =
            tokio::time::timeout(Duration::from_millis(20), task.stop_and_join()).await;

        // Release blocking extraction before asserting, including on a broken early-ack path.
        let _reader = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo_path)
            .unwrap();
        let joined = tokio::time::timeout(Duration::from_secs(2), task.stop_and_join()).await;
        let completed = tokio::time::timeout(Duration::from_secs(2), async {
            while !index_path.exists() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
        server.await.unwrap();
        assert!(
            started.is_ok(),
            "the real extractor must reach the filesystem barrier"
        );
        assert!(
            first_stop.is_err(),
            "stop must not acknowledge unfinished extraction"
        );
        joined
            .expect("a canceled stop wait must retain the task join")
            .unwrap();
        completed.expect("already-started extraction must finish after stop");
        assert_eq!(std::fs::read(index_path).unwrap(), b"complete");
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
            let config = Arc::make_mut(&mut config);
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
    async fn unknown_configured_detour_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path(), &[]);
        let mut config = ctx.config.write().await;
        Arc::make_mut(&mut config)
            .experimental
            .clash_api
            .external_ui_download_detour = "missing".into();
        drop(config);

        let error = decide_route(&ctx, "127.0.0.1", 80, None)
            .await
            .err()
            .expect("an unknown explicit detour must fail");
        assert!(
            error
                .to_string()
                .contains("detour outbound 'missing' not found"),
            "{error:#}"
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
        let ui = dir.path().join("ui");
        std::fs::create_dir(&ui).unwrap();
        let result =
            download_external_ui(&test_ctx(&ui, &[]), &format!("http://{}/bad.zip", addr)).await;
        assert!(result.is_err());
        // Partial contents are removed so the next start retries, and the
        // archive left no file beside the directory.
        assert!(std::fs::read_dir(&ui).unwrap().next().is_none());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn the_archive_is_an_unlinked_private_file_bounded_while_it_streams() {
        use std::os::unix::fs::MetadataExt as _;

        let addr = spawn_zip_server(vec![7; 64]).await;
        let dir = tempfile::tempdir().unwrap();
        let ui = dir.path().join("ui");
        let fetch = |limit| {
            let url = format!("http://{addr}/ui.zip");
            let mut archive = ArchiveFile::create(&ui).unwrap();
            archive.limit = limit;
            async move {
                let direct = fetch_direct(&url, None, &mut archive, &mut None).await;
                (direct, archive)
            }
        };

        let (refused, _) = fetch(63).await;
        let error = refused.err().expect("a body past the limit is refused");
        assert!(error.to_string().contains("exceeds 63 bytes"), "{error:#}");
        let (fetched, archive) = fetch(64).await;
        assert!(matches!(fetched.unwrap(), ProxiedFetch::Body));
        let metadata = archive.file.metadata().await.unwrap();
        assert_eq!((metadata.nlink(), metadata.mode() & 0o777), (0, 0o600));
        assert_eq!(metadata.dev(), std::fs::metadata(dir.path()).unwrap().dev());
        assert_eq!(archive_bytes(archive).await, vec![7; 64]);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        // Without O_TMPFILE the file is named only until it is open.
        let mut options = std::fs::OpenOptions::new();
        std::os::unix::fs::OpenOptionsExt::mode(options.read(true).write(true), 0o600);
        let file = named_then_unlinked(dir.path(), options).unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!((metadata.nlink(), metadata.mode() & 0o777), (0, 0o600));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
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
            &mut ArchiveFile::create(&dir.path().join("ui")).unwrap(),
            &mut None,
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
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
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
        let mut config = ctx.config.write().await;
        Arc::make_mut(&mut config).nodes.push(node);
        drop(config);
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
                outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
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
            config: Arc::new(RwLock::new(Arc::new(config))),
            proxy_registry: Arc::new(registry),
            runtime_registry: Arc::new(parking_lot::RwLock::new(Arc::new(
                honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap(),
            ))),
        };

        let UiRoute::Proxy { node, feedback } = decide_route(&ctx, "127.0.0.1", addr.port(), None)
            .await
            .unwrap()
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
        let mut archive = ArchiveFile::create(&dir.path().join("ui")).unwrap();
        let url = reqwest::Url::parse(&format!("http://{addr}/ui.zip")).unwrap();
        let fetched = fetch_proxied(
            &ctx,
            &node,
            Some(feedback),
            (&url, "127.0.0.1", addr.port()),
            &mut archive,
            &mut None,
        )
        .await
        .unwrap();
        assert!(matches!(fetched, ProxiedFetch::Body));
        assert_eq!(archive_bytes(archive).await, body);

        let UiRoute::Proxy { node, feedback } = decide_route(&ctx, "127.0.0.1", addr.port(), None)
            .await
            .unwrap()
        else {
            panic!("Score group must resolve to a proxy leaf");
        };
        assert_eq!(node.id, nodes[1].id);
        let reporter = feedback.unwrap().begin().unwrap().start();
        reporter.setup_succeeded();
        reporter.finish(ScoreOutcome::Success);

        let UiRoute::Proxy { node, .. } = decide_route(&ctx, "127.0.0.1", addr.port(), None)
            .await
            .unwrap()
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
            config: Arc::new(RwLock::new(Arc::new(config))),
            proxy_registry: Arc::new(ProxyRegistry::default_resolver().unwrap()),
            runtime_registry: Arc::new(parking_lot::RwLock::new(Arc::new(
                honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap(),
            ))),
        };
        let UiRoute::Direct { feedback } = decide_route(&ctx, "127.0.0.1", addr.port(), None)
            .await
            .unwrap()
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
        let mut archive = ArchiveFile::create(&dir.path().join("ui")).unwrap();
        let fetched = fetch_direct(
            &format!("http://{addr}/ui.zip"),
            feedback,
            &mut archive,
            &mut None,
        )
        .await
        .unwrap();
        assert!(matches!(fetched, ProxiedFetch::Body));
        assert_eq!(archive_bytes(archive).await, body);
        let UiRoute::Direct { feedback } = decide_route(&ctx, "127.0.0.1", addr.port(), None)
            .await
            .unwrap()
        else {
            panic!("Score group must still resolve to direct");
        };
        feedback
            .unwrap()
            .begin()
            .unwrap()
            .start()
            .setup_failed(ScoreOutcome::Timeout);
    }

    /// The rustls default provider is process-global, so only a child may break it.
    #[test]
    fn direct_fetch_reports_tls_setup_failure() {
        const CHILD: &str = "HONK_UI_TLS_SETUP_FAILURE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "clash_api::ui::tests::direct_fetch_reports_tls_setup_failure",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env_remove("HTTP_PROXY")
                .env_remove("HTTPS_PROXY")
                .env_remove("ALL_PROXY")
                .env_remove("http_proxy")
                .env_remove("https_proxy")
                .env_remove("all_proxy")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        use tokio_rustls::rustls::{
            self,
            crypto::{CryptoProvider, aws_lc_rs},
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    loop {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        let mut request = Vec::new();
                        let mut byte = [0];
                        while !request.ends_with(b"\r\n\r\n") {
                            stream.read_exact(&mut byte).await.unwrap();
                            request.push(byte[0]);
                        }
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone").await.unwrap();
                    }
                });
                let url = format!("http://{address}/ui.zip");
                let dir = tempfile::tempdir().unwrap();
                let mut archive = ArchiveFile::create(&dir.path().join("ui")).unwrap();
                let healthy = fetch_direct(&url, None, &mut archive, &mut None)
                    .await
                    .unwrap();
                assert!(matches!(healthy, ProxiedFetch::Body));
                assert_eq!(archive_bytes(archive).await, b"done");
                CryptoProvider {
                    cipher_suites: Vec::new(),
                    ..aws_lc_rs::default_provider()
                }
                .install_default()
                .unwrap();
                let mut archive = ArchiveFile::create(&dir.path().join("ui")).unwrap();
                let error = fetch_direct(&url, None, &mut archive, &mut None)
                    .await
                    .err()
                    .expect("invalid TLS provider must fail even for a reachable HTTP endpoint");
                assert!(error.downcast_ref::<rustls::Error>().is_some(), "{error:?}");
                server.abort();
                assert!(server.await.unwrap_err().is_cancelled());
            });
    }

    #[tokio::test]
    async fn score_redirects_keep_optional_credit_and_one_original_business() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for hop in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 1024];
                let mut used = 0;
                while !request[..used].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    assert!(
                        used < request.len(),
                        "loopback request headers exceed fixture limit"
                    );
                    let received = socket.read(&mut request[used..]).await.unwrap();
                    assert_ne!(received, 0, "loopback request closed before its headers");
                    used += received;
                }
                let response = if hop == 3 {
                    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone"
                        .to_string()
                } else {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: /hop{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        hop + 1
                    )
                };
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let nodes: Vec<_> = (1..=3)
            .map(|port| {
                let mut node = Node {
                    name: format!("proxy-{port}"),
                    outbound: honk_config::node::OutboundConfig::from_protocol(
                        NodeProtocol::Socks5,
                    ),
                    address: "127.0.0.1".into(),
                    port,
                    ..Default::default()
                };
                node.id = node.derive_id();
                node
            })
            .collect();
        let group = Group {
            name: "ui-score".into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        };
        let manager = Arc::new(GroupManager::new(std::slice::from_ref(&group), &nodes));
        // Trials only serve challengers trailing the selection's completions.
        let seed = manager
            .feedback_for_node(
                nodes[0].id,
                ScoreSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .unwrap()
            .start();
        seed.setup_succeeded();
        seed.tx(1);
        seed.rx(1);
        seed.finish(ScoreOutcome::Success);
        let mut registry = ProxyRegistry::new();
        registry.register(ProtocolEntry::new(
            NodeProtocol::Socks5,
            Arc::new(LoopbackHandler),
        ));
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx_with_registry(dir.path(), &[], Arc::new(registry));
        {
            let mut config = ctx.config.write().await;
            let config = Arc::make_mut(&mut config);
            config.nodes = nodes;
            config.groups = vec![group];
            config.experimental.clash_api.external_ui_download_detour = "ui-score".into();
        }
        *ctx.group_manager.write() = Arc::clone(&manager);
        let mut archive = ArchiveFile::create(&dir.path().join("ui")).unwrap();
        assert!(
            fetch_routed(
                &ctx,
                &format!("http://{address}/start"),
                &mut archive,
                &mut None,
            )
            .await
            .unwrap()
        );
        assert_eq!(archive_bytes(archive).await, b"done");
        server.await.unwrap();
        let cost = manager.score_budget_counters("ui-score", SelectionNetwork::Tcp);
        assert_eq!(
            (
                cost.business_starts,
                cost.trial_starts,
                cost.recovery_starts,
                cost.spent,
                cost.cold_available,
                cost.refunded
            ),
            (1, 1, 3, 1, 2, 0)
        );
        assert_eq!(manager.score_state().root_business_starts(), 1);
    }
}
