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
        let path = self.path_for(sub);
        let content = match tokio::task::spawn_blocking(move || read_store_file(&path)).await? {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        parse_subscription_content(sub, &content)
            .with_context(|| format!("invalid stored subscription '{}'", sub.name))
            .map(Some)
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
/// Lossy conversion keeps the previous behaviour: a body with invalid bytes
/// still parses its valid lines.
async fn read_capped_body(mut response: reqwest::Response) -> anyhow::Result<String> {
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
    Ok(String::from_utf8_lossy(&body).into_owned())
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
        let content = read_capped_body(response).await?;
        let nodes = parse_subscription_content(sub, &content)?;
        if let Some(store) = store
            && let Err(error) = store.store_content(sub, content).await
        {
            tracing::warn!(
                subscription = %sub.name,
                %error,
                "failed to persist subscription"
            );
        }
        Ok(nodes)
    }
}

/// Parse a fetched or locally supplied subscription body using its shape.
pub fn parse_subscription_content(sub: &Subscription, content: &str) -> anyhow::Result<Vec<Node>> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let nodes = match sub.sub_type {
        SubscriptionType::Sip008 => parse_sip008_subscription(content, Some(sub.id)),
        SubscriptionType::Clash => parse_clash_subscription(content, Some(sub.id)),
        SubscriptionType::Simple | SubscriptionType::Custom => {
            parse_auto_subscription(content, Some(sub.id), &sub.name)
        }
    }?;

    let mut seen = std::collections::HashSet::new();
    let nodes = nodes
        .into_iter()
        .filter(|node| {
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
                tracing::warn!(
                    node = %node.name,
                    "skipping subscription node with unsupported proxy plugin"
                );
                return false;
            }
            if seen.insert(node.id) {
                true
            } else {
                tracing::warn!(
                    node = %node.name,
                    "skipping subscription node with a duplicate endpoint identity"
                );
                false
            }
        })
        .collect::<Vec<_>>();
    if nodes.is_empty() {
        anyhow::bail!("no usable nodes found in subscription");
    }
    Ok(nodes)
}

fn parse_structured_value(content: &str) -> Result<serde_yaml::Value, serde_yaml::Error> {
    let content = content.trim_start().trim_start_matches('\u{feff}');
    // YAML's quoted-scalar decoder does not accept JSON UTF-16 surrogate pairs.
    serde_json::from_str(content).or_else(|_| serde_yaml::from_str(content))
}

fn parse_sip008_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let value = parse_structured_value(content)?;
    match &value {
        serde_yaml::Value::Sequence(_) => json::parse_json_subscription(value, subscription_id),
        serde_yaml::Value::Mapping(root)
            if yaml_value(root, "servers").is_some()
                && yaml_value(root, "outbounds").is_none()
                && yaml_value(root, "proxies").is_none() =>
        {
            json::parse_json_subscription(value, subscription_id)
        }
        _ => anyhow::bail!("invalid SIP008 subscription shape"),
    }
}

fn parse_auto_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
    subscription_tag: &str,
) -> anyhow::Result<Vec<Node>> {
    let content = content.trim().trim_start_matches('\u{feff}');
    if content.is_empty() {
        anyhow::bail!("empty subscription body");
    }
    let decoded = decode_base64_flexible(content)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let text = decoded
        .as_deref()
        .unwrap_or(content)
        .trim()
        .trim_start_matches('\u{feff}');
    if let Some(nodes) = parse_structured_subscription(text, subscription_id)? {
        return Ok(nodes);
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
        parse_uri_subscription(text, subscription_id, subscription_tag)
    } else {
        records::parse_records_subscription(text, subscription_id)
    }
}

fn parse_structured_subscription(
    text: &str,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Option<Vec<Node>>> {
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
        return Ok(None);
    };
    if let serde_yaml::Value::Mapping(root) = &value
        && let Some(proxies) = yaml_value(root, "proxies").and_then(serde_yaml::Value::as_sequence)
    {
        return Ok(Some(parse_clash_proxies(proxies, subscription_id)?));
    }
    match value {
        serde_yaml::Value::Mapping(_) | serde_yaml::Value::Sequence(_) => {
            json::parse_json_subscription(value, subscription_id).map(Some)
        }
        _ => Ok(None),
    }
}

fn parse_uri_subscription(
    text: &str,
    subscription_id: Option<uuid::Uuid>,
    subscription_tag: &str,
) -> anyhow::Result<Vec<Node>> {
    let mut nodes = Vec::new();
    for uri in text.lines().map(str::trim).filter(|line| {
        !line.is_empty()
            && !["#", ";", "//", "REMARKS=", "STATUS="]
                .iter()
                .any(|prefix| line.starts_with(prefix))
    }) {
        match Node::from_share_link(uri) {
            Ok(mut node) => {
                node.subscription_id = subscription_id;
                nodes.push(node);
            }
            Err(_) => tracing::warn!(
                subscription = subscription_tag,
                category = "unsupported-node-uri",
                "skipping subscription node"
            ),
        }
    }
    if nodes.is_empty() {
        anyhow::bail!("no supported nodes found in subscription");
    }
    Ok(nodes)
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

fn parse_clash_proxies(
    proxies: &[serde_yaml::Value],
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let mut nodes = Vec::new();
    for proxy in proxies {
        let Some(mapping) = proxy.as_mapping() else {
            continue;
        };
        match clash::parse_clash_proxy(mapping, subscription_id) {
            Ok(node) => nodes.push(node),
            Err(_) => {
                tracing::warn!("skipping unsupported or malformed subscription proxy");
            }
        }
    }
    if nodes.is_empty() {
        anyhow::bail!("no supported proxies found in Clash subscription");
    }
    Ok(nodes)
}

fn parse_clash_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let yaml = parse_structured_value(content)?;
    let proxies = yaml
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| anyhow::anyhow!("no 'proxies' array found in Clash YAML"))?;
    parse_clash_proxies(proxies, subscription_id)
}

#[cfg(test)]
mod tests;
