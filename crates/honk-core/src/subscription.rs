//! Subscription manager for fetching and parsing proxy subscription URLs.
//!
//! Downloaded bodies, persisted bodies and local tool inputs share format
//! detection. Foreign JSON and client records normalize through the Clash node
//! builder; URI lists use [`Node::from_share_link`] from honk-config.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use honk_config::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SafeValue, SettingPath, Severity, finish_attempt,
    report_detailed_diagnostics,
};
use honk_config::error::{DetailedConfigError, ErrorCategory};
use honk_config::node::Node;
use honk_config::subscription::Subscription;
use honk_config::types::SubscriptionType;
use sha2::{Digest as _, Sha256};

mod clash;
mod json;
mod records;
mod supervisor;

pub(crate) use supervisor::{
    AuthorizedSubscription, SubscriptionAuthorizations, SubscriptionSupervisor,
    SubscriptionSupervisorHandle, same_subscription_worker_set, validate_subscription_ids,
};

/// Bounds what a hostile or broken origin can make honk buffer before parsing.
const MAX_SUBSCRIPTION_BYTES: usize = 8 * 1024 * 1024;

const MAX_SUBSCRIPTION_REDIRECTS: usize = 5;

/// One source entry retained only until the common admission pass consumes it.
#[derive(Debug)]
struct IndexedOutcome {
    ordinal: usize,
    line: Option<usize>,
    path: &'static str,
    kind: IndexedOutcomeKind,
}

// Consumed synchronously, never queued: boxing would allocate once per imported node.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum IndexedOutcomeKind {
    Node(Node),
    Malformed(&'static str),
    Unsupported(&'static str),
    Profile(&'static str),
    Diagnostic(DetailedDiagnostic),
}

impl IndexedOutcome {
    fn node(ordinal: usize, path: &'static str, node: Node) -> Self {
        Self {
            ordinal,
            line: None,
            path,
            kind: IndexedOutcomeKind::Node(node),
        }
    }

    fn malformed(ordinal: usize, path: &'static str, reason: &'static str) -> Self {
        Self {
            ordinal,
            line: None,
            path,
            kind: IndexedOutcomeKind::Malformed(reason),
        }
    }

    fn unsupported(ordinal: usize, path: &'static str, reason: &'static str) -> Self {
        Self {
            ordinal,
            line: None,
            path,
            kind: IndexedOutcomeKind::Unsupported(reason),
        }
    }

    fn profile(ordinal: usize, path: &'static str, reason: &'static str) -> Self {
        Self {
            ordinal,
            line: None,
            path,
            kind: IndexedOutcomeKind::Profile(reason),
        }
    }
}

const MAX_SUBSCRIPTION_DIAGNOSTICS: usize = 128;

struct AdmissionOwner<'a> {
    source: honk_config::diagnostic::SourceRef,
    diagnostics: &'a mut Vec<DetailedDiagnostic>,
    nodes: Vec<Node>,
    seen: std::collections::HashMap<uuid::Uuid, usize>,
    retained: usize,
    omitted: usize,
}

impl<'a> AdmissionOwner<'a> {
    fn new(
        source: &honk_config::diagnostic::SourceRef,
        diagnostics: &'a mut Vec<DetailedDiagnostic>,
    ) -> Self {
        Self {
            source: source.clone(),
            diagnostics,
            nodes: Vec::new(),
            seen: std::collections::HashMap::new(),
            retained: 0,
            omitted: 0,
        }
    }

    fn emit(&mut self, outcome: IndexedOutcome) {
        let IndexedOutcome {
            ordinal,
            line,
            path,
            kind,
        } = outcome;
        match kind {
            IndexedOutcomeKind::Node(node) => {
                if node.shadowsocks().is_some_and(|config| {
                    config
                        .plugin
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                        || config
                            .plugin_opts
                            .as_deref()
                            .is_some_and(|value| !value.trim().is_empty())
                }) {
                    self.emit_indexed(
                        "unsupported-subscription-entry",
                        Severity::Warning,
                        ordinal,
                        line,
                        path,
                        "subscription node uses an unsupported proxy plugin; ignored",
                    );
                } else if let Some(first) = self.seen.get(&node.id).copied() {
                    if self.reserve() {
                        let mut diagnostic = indexed_diagnostic(
                            "duplicate-subscription-entry",
                            Severity::Warning,
                            &self.source,
                            ordinal,
                            line,
                            path,
                            "duplicate endpoint identity; retaining the first usable entry",
                        );
                        diagnostic.related_indices.push(first);
                        self.diagnostics.push(diagnostic);
                    }
                } else {
                    self.seen.insert(node.id, ordinal);
                    self.nodes.push(node);
                }
            }
            IndexedOutcomeKind::Malformed(reason) => self.emit_indexed(
                "malformed-subscription-entry",
                Severity::Warning,
                ordinal,
                line,
                path,
                reason,
            ),
            IndexedOutcomeKind::Unsupported(reason) => self.emit_indexed(
                "unsupported-subscription-entry",
                Severity::Warning,
                ordinal,
                line,
                path,
                reason,
            ),
            IndexedOutcomeKind::Profile(reason) => self.emit_indexed(
                "subscription-profile-entry",
                Severity::Info,
                ordinal,
                line,
                path,
                reason,
            ),
            IndexedOutcomeKind::Diagnostic(mut diagnostic) => {
                diagnostic.terminal = false;
                if self.reserve() {
                    diagnostic.source = self.source.clone();
                    diagnostic.setting = SettingPath::new(path).index(ordinal);
                    diagnostic.entry_index = Some(ordinal);
                    diagnostic.line = line;
                    diagnostic.span = None;
                    diagnostic.byte_column = None;
                    self.diagnostics.push(diagnostic);
                }
            }
        }
    }

    fn emit_indexed(
        &mut self,
        code: &'static str,
        severity: Severity,
        ordinal: usize,
        line: Option<usize>,
        path: &'static str,
        message: &'static str,
    ) {
        if self.reserve() {
            self.diagnostics.push(indexed_diagnostic(
                code,
                severity,
                &self.source,
                ordinal,
                line,
                path,
                message,
            ));
        }
    }

    fn reserve(&mut self) -> bool {
        if self.retained < MAX_SUBSCRIPTION_DIAGNOSTICS {
            self.retained += 1;
            true
        } else {
            self.omitted += 1;
            false
        }
    }

    fn finish_diagnostics(&mut self) {
        if self.omitted != 0 {
            self.diagnostics.push(DetailedDiagnostic::warning(
                "subscription-diagnostics-truncated",
                self.source.clone(),
                SettingPath::new("subscription").field("entries"),
                SafeValue::Ordinal(self.omitted),
                "subscription diagnostics were truncated; valid entries were retained",
            ));
        }
    }

    fn finish(mut self) -> Result<Vec<Node>, DetailedConfigError> {
        self.finish_diagnostics();
        if self.nodes.is_empty() {
            return Err(subscription_error(self.source, "empty-subscription-body"));
        }
        Ok(self.nodes)
    }
}

/// A hostname that resolves to a private address is not detected here; this
/// only refuses a destination the redirect states outright.
fn has_private_literal_host(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    // Canonicalized first: an IPv4-mapped literal such as `::ffff:127.0.0.1`
    // otherwise takes the IPv6 branch, where it is neither loopback nor local.
    match host.parse::<std::net::IpAddr>().map(|ip| ip.to_canonical()) {
        Ok(std::net::IpAddr::V4(address)) => {
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(address)) => {
            address.is_loopback()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_unspecified()
        }
        Err(_) => false,
    }
}

/// reqwest's default follows ten hops, allows an https-to-http downgrade, and
/// does not restrict the destination, so a subscription origin could move the
/// fetch onto plaintext or onto an address the operator never published it to.
fn subscription_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let origin_https = attempt
            .previous()
            .first()
            .is_some_and(|url| url.scheme() == "https");
        let origin_private = attempt
            .previous()
            .first()
            .is_some_and(has_private_literal_host);
        let refusal = if attempt.previous().len() > MAX_SUBSCRIPTION_REDIRECTS {
            Some("redirected too many times")
        } else if origin_https && attempt.url().scheme() != "https" {
            Some("redirected from https to plaintext")
        } else if has_private_literal_host(attempt.url()) && !origin_private {
            Some("redirected to a private address")
        } else {
            None
        };
        match refusal {
            Some(reason) => attempt.error(anyhow::anyhow!("subscription {reason}")),
            None => attempt.follow(),
        }
    })
}

/// reqwest DNS resolver backed by honk's bootstrap resolver
/// (bypass-marked UDP/TCP), so subscription fetches do not depend on the
/// system resolver — which on a polluted network can hand back poisoned
/// answers and kill the subscription download.
struct BootstrapDnsResolve;

impl reqwest::dns::Resolve for BootstrapDnsResolve {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = honk_outbound::bootstrap::resolve(&host).await?;
            let addrs: Vec<std::net::SocketAddr> = ips
                .into_iter()
                .map(|ip| std::net::SocketAddr::new(ip, 0))
                .collect();
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

const SUBSCRIPTION_STORE_DIR: &str = ".sub";
const DEFAULT_SUBSCRIPTION_USER_AGENT: &str = concat!("honk/", env!("CARGO_PKG_VERSION"));

fn effective_subscription_user_agent(sub: &Subscription) -> &str {
    sub.user_agent
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_SUBSCRIPTION_USER_AGENT)
}

/// Durable raw subscription bodies keyed by their fetch identity.
#[derive(Clone, Debug)]
pub struct SubscriptionStore {
    root: Arc<PathBuf>,
}

impl SubscriptionStore {
    /// Open the subscription store below `global.data_dir`, retaining an
    /// existing old data-directory or `./.sub` store during upgrades.
    pub fn in_data_dir() -> anyhow::Result<Self> {
        Self::open_with_legacy(
            honk_config::paths::resolve_artifact_path(SUBSCRIPTION_STORE_DIR),
            [
                Path::new(honk_config::paths::LEGACY_DATA_DIR).join(SUBSCRIPTION_STORE_DIR),
                PathBuf::from(SUBSCRIPTION_STORE_DIR),
            ],
        )
    }

    fn open_with_legacy(preferred: PathBuf, legacy_roots: [PathBuf; 2]) -> anyhow::Result<Self> {
        if preferred.exists() {
            return Self::open(preferred);
        }
        for root in legacy_roots {
            if !root.exists() {
                continue;
            }
            match Self::open(root.clone()) {
                Ok(store) => {
                    tracing::warn!(
                        legacy = %root.display(),
                        preferred = %preferred.display(),
                        "using legacy subscription store; move it to the runtime data directory"
                    );
                    return Ok(store);
                }
                Err(error) => {
                    tracing::warn!(
                        legacy = %root.display(),
                        %error,
                        "legacy subscription store is unusable; trying the next location"
                    );
                }
            }
        }
        Self::open(preferred)
    }

    fn open(root: PathBuf) -> anyhow::Result<Self> {
        ensure_store_directory(&root)?;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    pub fn root(&self) -> &Path {
        self.root.as_path()
    }

    pub async fn load_nodes(&self, sub: &Subscription) -> anyhow::Result<Option<Vec<Node>>> {
        let mut diagnostics = Vec::new();
        let result = self
            .load_nodes_with_diagnostics(sub, &mut diagnostics)
            .await;
        report_detailed_diagnostics(&diagnostics);
        result
    }

    pub async fn load_nodes_with_diagnostics(
        &self,
        sub: &Subscription,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> anyhow::Result<Option<Vec<Node>>> {
        let path = self.path_for(sub);
        let content = match tokio::task::spawn_blocking(move || read_store_file(&path)).await? {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        parse_subscription_content_with_diagnostics(sub, &content, diagnostics)
            .map(Some)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    async fn store_content(&self, sub: &Subscription, content: String) -> anyhow::Result<()> {
        let root = Arc::clone(&self.root);
        let destination = self.path_for(sub);
        tokio::task::spawn_blocking(move || {
            write_store_file(&root, &destination, content.as_bytes())
        })
        .await??;
        Ok(())
    }

    fn path_for(&self, sub: &Subscription) -> PathBuf {
        self.root.join(subscription_filename(sub))
    }
}

fn subscription_cache_user_agent(sub: &Subscription) -> &str {
    // The request UA may change with the binary; the cache identity must not.
    sub.user_agent.as_deref().unwrap_or_default()
}

/// Full fetch identity, matching the cache filename key: URL plus configured
/// UA plus headers. URL-only reload matching can swap identities between
/// same-URL subscriptions with different fetch options.
pub(crate) fn same_subscription_fetch_identity(a: &Subscription, b: &Subscription) -> bool {
    a.url == b.url
        && subscription_cache_user_agent(a) == subscription_cache_user_agent(b)
        && a.headers == b.headers
}

fn subscription_filename(sub: &Subscription) -> String {
    fn add_part(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    let mut hasher = Sha256::new();
    add_part(&mut hasher, sub.url.as_bytes());
    add_part(&mut hasher, subscription_cache_user_agent(sub).as_bytes());
    for header in &sub.headers {
        add_part(&mut hasher, header.key.as_bytes());
        add_part(&mut hasher, header.value.as_bytes());
    }
    use base64::Engine as _;
    format!(
        "{}.sub",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
    )
}

fn ensure_store_directory(root: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "subscription store is not a directory: {}",
                root.display()
            );
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.recursive(true).mode(0o700).create(root)?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn read_store_file(path: &Path) -> std::io::Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "subscription cache is not a regular file",
        ));
    }
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

fn write_store_file(root: &Path, destination: &Path, content: &[u8]) -> anyhow::Result<()> {
    ensure_store_directory(root)?;
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid subscription cache filename")?;
    let temporary = root.join(format!(
        ".{destination_name}.{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temporary, destination)?;
        File::open(root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// `Response::text` buffers the whole body before anything can check its size.
async fn read_capped_body(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)?
    {
        if body.len() + chunk.len() > MAX_SUBSCRIPTION_BYTES {
            anyhow::bail!("subscription body exceeds {MAX_SUBSCRIPTION_BYTES} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Manager for fetching and parsing proxy subscriptions.
pub struct SubscriptionManager {
    client: reqwest::Client,
}

impl SubscriptionManager {
    pub fn new() -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .dns_resolver(std::sync::Arc::new(BootstrapDnsResolve))
            .redirect(subscription_redirect_policy())
            .build()?;
        Ok(Self { client })
    }

    /// Fetch a subscription URL and parse its contents into a list of nodes.
    pub async fn fetch(&self, sub: &Subscription) -> anyhow::Result<Vec<Node>> {
        self.fetch_and_store(sub, None).await
    }
    pub async fn fetch_and_store(
        &self,
        sub: &Subscription,
        store: Option<&SubscriptionStore>,
    ) -> anyhow::Result<Vec<Node>> {
        let mut diagnostics = Vec::new();
        let result = self
            .fetch_and_store_with_diagnostics(sub, store, &mut diagnostics)
            .await;
        report_detailed_diagnostics(&diagnostics);
        result
    }

    /// Body acceptance and persistence precede, and are independent of, runtime publication.
    pub async fn fetch_and_store_with_diagnostics(
        &self,
        sub: &Subscription,
        store: Option<&SubscriptionStore>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> anyhow::Result<Vec<Node>> {
        let mut request = self
            .client
            .get(&sub.url)
            .header("User-Agent", effective_subscription_user_agent(sub));

        for header in &sub.headers {
            request = request.header(&header.key, &header.value);
        }

        let response = request.send().await.map_err(reqwest::Error::without_url)?;
        let response = response
            .error_for_status()
            .map_err(reqwest::Error::without_url)?;
        let body = read_capped_body(response).await?;
        let content = finish_attempt(
            String::from_utf8(body).map_err(|_| {
                subscription_error(
                    DiagnosticSources::new(None).root(),
                    "invalid-subscription-encoding",
                )
            }),
            diagnostics,
        )?;
        let start = diagnostics.len();
        let nodes = parse_subscription_content_with_diagnostics(sub, &content, diagnostics)?;
        if let Some(store) = store
            && store.store_content(sub, content).await.is_err()
        {
            let source = diagnostics.get(start).map_or_else(
                || DiagnosticSources::new(None).root(),
                |diagnostic| diagnostic.source.sources().root(),
            );
            diagnostics.push(DetailedDiagnostic::warning(
                "subscription-store-write-failed",
                source,
                SettingPath::new("subscription").field("store"),
                SafeValue::Redacted,
                "subscription body accepted but could not be persisted",
            ));
        }
        Ok(nodes)
    }
}

/// Parse a fetched or locally supplied subscription body using its shape.
pub fn parse_subscription_content(sub: &Subscription, content: &str) -> anyhow::Result<Vec<Node>> {
    let mut diagnostics = Vec::new();
    let result = parse_subscription_content_with_diagnostics(sub, content, &mut diagnostics);
    report_detailed_diagnostics(&diagnostics);
    result.map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Parse a subscription body while retaining redacted, indexed entry outcomes.
pub fn parse_subscription_content_with_diagnostics(
    sub: &Subscription,
    content: &str,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Vec<Node>, DetailedConfigError> {
    let source = DiagnosticSources::new(None).root();
    let result = parse_subscription_content_attempt(sub, content, &source, diagnostics);
    finish_attempt(result, diagnostics)
}

fn parse_subscription_content_attempt(
    sub: &Subscription,
    content: &str,
    source: &honk_config::diagnostic::SourceRef,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Vec<Node>, DetailedConfigError> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let decoded = if matches!(
        sub.sub_type,
        SubscriptionType::Simple | SubscriptionType::Custom
    ) {
        decode_base64_flexible(content).ok()
    } else {
        None
    };
    let source = if decoded.is_some() {
        source.sources().add(None, Some(source.index()))
    } else {
        source.clone()
    };
    let content = match decoded.as_deref() {
        Some(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| subscription_error(source.clone(), "invalid-subscription-encoding"))?,
        None => content,
    };
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut owner = AdmissionOwner::new(&source, diagnostics);
    let result = match sub.sub_type {
        SubscriptionType::Sip008 => {
            parse_sip008_subscription(content, Some(sub.id), |outcome| owner.emit(outcome))
        }
        SubscriptionType::Clash => {
            parse_clash_subscription(content, Some(sub.id), |outcome| owner.emit(outcome))
        }
        SubscriptionType::Simple | SubscriptionType::Custom => {
            parse_auto_subscription(content, Some(sub.id), |outcome| owner.emit(outcome))
        }
    };
    if result.is_err() {
        owner.finish_diagnostics();
        return Err(subscription_error(source, "invalid-subscription-body"));
    }
    owner.finish()
}

fn subscription_error(
    source: honk_config::diagnostic::SourceRef,
    code: &'static str,
) -> DetailedConfigError {
    DetailedConfigError::new(
        ErrorCategory::Parse,
        code,
        source,
        SettingPath::new("subscription"),
        "subscription body could not be accepted",
    )
}

fn indexed_diagnostic(
    code: &'static str,
    severity: Severity,
    source: &honk_config::diagnostic::SourceRef,
    ordinal: usize,
    line: Option<usize>,
    path: &'static str,
    message: &'static str,
) -> DetailedDiagnostic {
    let mut diagnostic = DetailedDiagnostic::warning(
        code,
        source.clone(),
        SettingPath::new(path).index(ordinal),
        SafeValue::Ordinal(ordinal),
        message,
    );
    diagnostic.severity = severity;
    diagnostic.entry_index = Some(ordinal);
    diagnostic.line = line;
    diagnostic
}
fn parse_sip008_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
    emit: impl FnMut(IndexedOutcome),
) -> anyhow::Result<()> {
    let value = parse_structured_value(content)?;
    match &value {
        serde_yaml::Value::Sequence(_) => {
            json::emit_json_subscription(value, subscription_id, emit)
        }
        serde_yaml::Value::Mapping(root)
            if yaml_value(root, "servers").is_some()
                && yaml_value(root, "outbounds").is_none()
                && yaml_value(root, "proxies").is_none() =>
        {
            json::emit_json_subscription(value, subscription_id, emit)
        }
        _ => anyhow::bail!("invalid SIP008 subscription shape"),
    }
}

fn parse_structured_value(content: &str) -> Result<serde_yaml::Value, serde_yaml::Error> {
    let content = content.trim_start().trim_start_matches('\u{feff}');
    // YAML's quoted-scalar decoder does not accept JSON UTF-16 surrogate pairs.
    serde_json::from_str(content).or_else(|_| serde_yaml::from_str(content))
}

fn parse_auto_subscription(
    text: &str,
    subscription_id: Option<uuid::Uuid>,
    mut emit: impl FnMut(IndexedOutcome),
) -> anyhow::Result<()> {
    if text.trim().is_empty() {
        anyhow::bail!("empty subscription body");
    }
    if parse_structured_subscription(text, subscription_id, &mut emit)? {
        return Ok(());
    }
    let has_uri = text.lines().map(str::trim).any(|line| {
        line.split_once("://").is_some_and(|(scheme, _)| {
            !scheme.is_empty()
                && scheme
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        })
    });
    if has_uri {
        parse_uri_subscription(text, subscription_id, emit)
    } else {
        records::parse_record_subscription(text, subscription_id, emit)
    }
}

fn parse_structured_subscription(
    text: &str,
    subscription_id: Option<uuid::Uuid>,
    emit: &mut impl FnMut(IndexedOutcome),
) -> anyhow::Result<bool> {
    let Ok(value) = parse_structured_value(text) else {
        let first = text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with(';'))
            .unwrap_or_default();
        let ini_header = first
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
            .is_some_and(|name| {
                !name.is_empty()
                    && name.chars().all(|ch| {
                        ch.is_ascii_alphanumeric()
                            || ch.is_ascii_whitespace()
                            || matches!(ch, '_' | '-')
                    })
            });
        if first.starts_with('{')
            || (first.starts_with('[') && !ini_header)
            || ["proxies:", "outbounds:", "servers:"]
                .iter()
                .any(|key| first.starts_with(key))
        {
            anyhow::bail!("malformed structured subscription");
        }
        return Ok(false);
    };
    if let serde_yaml::Value::Mapping(root) = &value
        && let Some(proxies) = yaml_value(root, "proxies").and_then(serde_yaml::Value::as_sequence)
    {
        emit_clash_proxies(proxies, subscription_id, &mut *emit);
        return Ok(true);
    }
    match value {
        serde_yaml::Value::Mapping(_) | serde_yaml::Value::Sequence(_) => {
            json::emit_json_subscription(value, subscription_id, &mut *emit)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}
fn parse_uri_subscription(
    text: &str,
    subscription_id: Option<uuid::Uuid>,
    mut emit: impl FnMut(IndexedOutcome),
) -> anyhow::Result<()> {
    for (index, uri) in text.lines().enumerate() {
        let uri = uri.trim();
        if uri.is_empty()
            || ["#", ";", "//"]
                .iter()
                .any(|prefix| uri.starts_with(prefix))
        {
            continue;
        }
        let ordinal = index + 1;
        if ["REMARKS=", "STATUS="]
            .iter()
            .any(|prefix| uri.starts_with(prefix))
        {
            let mut outcome =
                IndexedOutcome::profile(ordinal, "entries", "subscription profile metadata");
            outcome.line = Some(ordinal);
            emit(outcome);
            continue;
        }
        let result = Node::from_share_link_with_detailed_diagnostics_emit(uri, &mut |diagnostic| {
            emit(IndexedOutcome {
                ordinal,
                line: Some(ordinal),
                path: "entries",
                kind: IndexedOutcomeKind::Diagnostic(diagnostic),
            });
        });
        match result {
            Ok(mut node) => {
                node.subscription_id = subscription_id;
                let mut outcome = IndexedOutcome::node(ordinal, "entries", node);
                outcome.line = Some(ordinal);
                emit(outcome);
            }
            Err(error) => {
                let mut diagnostic = *error.diagnostic;
                diagnostic.code = if error.category == ErrorCategory::UnknownProtocol {
                    "unsupported-subscription-entry"
                } else {
                    "malformed-subscription-entry"
                };
                diagnostic.terminal = false;
                diagnostic.severity = Severity::Warning;
                emit(IndexedOutcome {
                    ordinal,
                    line: Some(ordinal),
                    path: "entries",
                    kind: IndexedOutcomeKind::Diagnostic(diagnostic),
                });
            }
        }
    }
    Ok(())
}

fn decode_base64_flexible(input: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    use std::borrow::Cow;

    let input = input.trim();
    if input.bytes().any(|byte| {
        !byte.is_ascii_alphanumeric()
            && !byte.is_ascii_whitespace()
            && !matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
    }) {
        anyhow::bail!("invalid base64 subscription body");
    }
    let compact: Cow<'_, str> = if input.bytes().any(|byte| byte.is_ascii_whitespace()) {
        Cow::Owned(
            input
                .chars()
                .filter(|ch| !ch.is_ascii_whitespace())
                .collect(),
        )
    } else {
        Cow::Borrowed(input)
    };
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(data) = engine.decode(compact.as_bytes()) {
            return Ok(data);
        }
    }
    anyhow::bail!("invalid base64 subscription body")
}

fn yaml_value<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> Option<&'a serde_yaml::Value> {
    mapping.get(serde_yaml::Value::String(key.to_string()))
}

#[cfg(test)]
fn parse_clash_proxies(
    proxies: &[serde_yaml::Value],
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let mut nodes = Vec::new();
    emit_clash_proxies(proxies, subscription_id, |outcome| {
        if let IndexedOutcomeKind::Node(node) = outcome.kind {
            nodes.push(node);
        }
    });
    if nodes.is_empty() {
        anyhow::bail!("no supported proxies found in Clash subscription");
    }
    Ok(nodes)
}

fn emit_clash_proxies(
    proxies: &[serde_yaml::Value],
    subscription_id: Option<uuid::Uuid>,
    mut emit: impl FnMut(IndexedOutcome),
) {
    for (index, proxy) in proxies.iter().enumerate() {
        let ordinal = index + 1;
        let outcome = match proxy.as_mapping() {
            None => {
                IndexedOutcome::malformed(ordinal, "proxies", "Clash proxy entry must be an object")
            }
            Some(mapping) => match clash::parse_clash_proxy(mapping, subscription_id) {
                Ok(node) => IndexedOutcome::node(ordinal, "proxies", node),
                Err(reason) if reason.contains("unsupported") => {
                    IndexedOutcome::unsupported(ordinal, "proxies", reason)
                }
                Err(reason) => IndexedOutcome::malformed(ordinal, "proxies", reason),
            },
        };
        emit(outcome);
    }
}

fn parse_clash_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
    emit: impl FnMut(IndexedOutcome),
) -> anyhow::Result<()> {
    let yaml = parse_structured_value(content)?;
    let proxies = yaml
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| anyhow::anyhow!("no 'proxies' array found in Clash YAML"))?;
    emit_clash_proxies(proxies, subscription_id, emit);
    Ok(())
}

#[cfg(test)]
mod tests;
