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
use honk_config::node::{Node, OutboundConfig};
use honk_config::subscription::Subscription;
use honk_config::types::{NodeProtocol, SubscriptionType};
use sha2::{Digest as _, Sha256};

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

fn structured_subscription(value: serde_yaml::Value) -> anyhow::Result<Option<serde_yaml::Value>> {
    let recognized = match &value {
        serde_yaml::Value::Mapping(mapping) => ["proxies", "outbounds", "servers"]
            .into_iter()
            .any(|key| yaml_value(mapping, key).is_some()),
        serde_yaml::Value::Sequence(items) => items.iter().any(|item| {
            item.as_mapping().is_some_and(|mapping| {
                yaml_value(mapping, "server").is_some()
                    && (yaml_value(mapping, "server_port").is_some()
                        || yaml_value(mapping, "port").is_some())
            })
        }),
        _ => false,
    };
    if recognized {
        Ok(Some(value))
    } else if matches!(
        value,
        serde_yaml::Value::Mapping(_) | serde_yaml::Value::Sequence(_)
    ) {
        anyhow::bail!("unsupported structured subscription format")
    } else {
        Ok(None)
    }
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
    let trimmed = content.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty subscription body");
    }
    let parse_structured = |text: &str| -> anyhow::Result<Option<Vec<Node>>> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
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
        let Some(value) = structured_subscription(value)? else {
            return Ok(None);
        };
        if let serde_yaml::Value::Mapping(root) = &value
            && let Some(proxies) =
                yaml_value(root, "proxies").and_then(serde_yaml::Value::as_sequence)
        {
            return Ok(Some(parse_clash_proxies(proxies, subscription_id)?));
        }
        Ok(Some(json::parse_json_subscription(value, subscription_id)?))
    };

    if let Some(nodes) = parse_structured(trimmed)? {
        return Ok(nodes);
    }

    let decoded = if looks_like_raw_text(trimmed) {
        None
    } else {
        decode_base64_flexible(trimmed)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    };
    if let Some(decoded) = decoded.as_deref()
        && let Some(nodes) = parse_structured(decoded)?
    {
        return Ok(nodes);
    }

    parse_base64_subscription(
        decoded.as_deref().unwrap_or(trimmed),
        subscription_id,
        subscription_tag,
    )
    .or_else(|_| {
        let text = decoded.as_deref().unwrap_or(trimmed);
        records::parse_records_subscription(
            text.strip_prefix('\u{feff}').unwrap_or(text),
            subscription_id,
        )
    })
}

fn looks_like_raw_text(text: &str) -> bool {
    const RECORD_TYPES: &[&str] = &[
        "ss",
        "shadowsocks",
        "socks5",
        "vmess",
        "vless",
        "trojan",
        "hysteria2",
        "hy2",
        "tuic",
        "juicity",
        "anytls",
    ];
    text.lines().map(str::trim).any(|line| {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            return false;
        }
        if line.starts_with('[')
            || line.contains("://")
            || line.starts_with("REMARKS=")
            || line.starts_with("STATUS=")
            || (line.contains('=') && !line.ends_with('='))
        {
            return true;
        }
        let Some((left, right)) = line.split_once('=') else {
            return false;
        };
        let left = left.trim().to_ascii_lowercase();
        let right = right
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        RECORD_TYPES.contains(&left.as_str()) || RECORD_TYPES.contains(&right.as_str())
    })
}

fn parse_base64_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
    subscription_tag: &str,
) -> anyhow::Result<Vec<Node>> {
    const SKIP_PREFIXES: &[&str] = &["REMARKS=", "STATUS="];

    let trimmed = content.trim();
    let decoded = if trimmed.lines().map(str::trim).any(|line| {
        line.contains("://") || SKIP_PREFIXES.iter().any(|prefix| line.starts_with(prefix))
    }) {
        None
    } else {
        decode_base64_flexible(trimmed).ok()
    };
    let decoded_text = decoded
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok());
    let text = decoded_text
        .unwrap_or(trimmed)
        .strip_prefix('\u{feff}')
        .unwrap_or(decoded_text.unwrap_or(trimmed));
    let uris: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| !SKIP_PREFIXES.iter().any(|prefix| line.starts_with(*prefix)))
        .collect();

    if uris.is_empty() {
        anyhow::bail!("no valid node URIs found in subscription");
    }

    let mut nodes = Vec::new();
    for uri in uris {
        match parse_node_uri(uri) {
            Ok(mut node) => {
                node.subscription_id = subscription_id;
                nodes.push(node);
            }
            Err(_) => {
                tracing::warn!(
                    subscription = subscription_tag,
                    category = "unsupported-node-uri",
                    "skipping subscription node"
                );
            }
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

fn yaml_values_equal(a: &serde_yaml::Value, b: &serde_yaml::Value) -> bool {
    if a == b {
        return true;
    }
    match (a, b) {
        (
            serde_yaml::Value::Number(_) | serde_yaml::Value::String(_),
            serde_yaml::Value::Number(_) | serde_yaml::Value::String(_),
        ) => matches!(
            (yaml_u64(a, "").ok(), yaml_u64(b, "").ok()),
            (Some(a), Some(b)) if a == b
        ),
        _ => false,
    }
}

fn yaml_alias<'a>(
    mapping: &'a serde_yaml::Mapping,
    keys: &[&str],
) -> Result<Option<&'a serde_yaml::Value>, String> {
    let mut found = None;
    for key in keys {
        let Some(value) = yaml_value(mapping, key) else {
            continue;
        };
        match found {
            None => found = Some(value),
            Some(_) if matches!(value, serde_yaml::Value::Null) => {}
            Some(previous) if matches!(previous, serde_yaml::Value::Null) => found = Some(value),
            Some(previous) if yaml_values_equal(previous, value) => {}
            Some(_) => return Err(format!("conflicting aliases '{}'", keys.join("/"))),
        }
    }
    Ok(found)
}

fn parse_vless_external_mode(
    mapping: &serde_yaml::Mapping,
) -> Result<honk_config::node::WireMode, String> {
    use honk_config::node::WireMode;
    let udp = yaml_value(mapping, "udp")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| "VLESS udp must be boolean".to_string())
        })
        .transpose()?;
    if yaml_value(mapping, "packet-encoding")
        .is_some_and(|value| !matches!(value, serde_yaml::Value::Null))
        && yaml_value(mapping, "packet_encoding")
            .is_some_and(|value| !matches!(value, serde_yaml::Value::Null))
    {
        return Err("duplicate VLESS XUDP representations".into());
    }

    let packet_encoding = yaml_alias(mapping, &["packet-encoding", "packet_encoding"])?
        .filter(|value| yaml_active(value));
    let xudp = yaml_value(mapping, "xudp").filter(|value| match value {
        serde_yaml::Value::Null => false,
        serde_yaml::Value::String(value) => !value.trim().is_empty(),
        _ => true,
    });
    let packet_encoding_disabled = packet_encoding.is_some_and(|value| {
        value
            .as_str()
            .is_some_and(|encoding| matches!(encoding.trim(), "none" | "legacy"))
    });
    let xudp_enabled = match (packet_encoding, xudp) {
        (Some(value), None) => {
            let encoding = value
                .as_str()
                .ok_or_else(|| "VLESS packet encoding must be a string".to_string())?
                .trim();
            match encoding {
                "" | "none" | "legacy" => false,
                "xudp" => true,
                _ => return Err(format!("unsupported VLESS packet encoding '{encoding}'")),
            }
        }
        (None, Some(value)) => value
            .as_bool()
            .ok_or_else(|| "VLESS xudp must be boolean".to_string())?,
        (None, None) => false,
        (Some(_), Some(_)) => return Err("duplicate VLESS XUDP representations".into()),
    };
    let xudp_disabled =
        packet_encoding_disabled || xudp.is_some_and(|value| value.as_bool() == Some(false));
    if let Some(value) =
        yaml_alias(mapping, &["packet-addr", "packet_addr"])?.filter(|value| yaml_active(value))
    {
        let enabled = value
            .as_bool()
            .ok_or_else(|| "VLESS packet-addr must be boolean".to_string())?;
        if enabled {
            return Err("unsupported VLESS packet-addr mode".into());
        }
    }
    if let Some(value) = yaml_value(mapping, "mux").filter(|value| yaml_active(value)) {
        let enabled = match value {
            serde_yaml::Value::Bool(enabled) => *enabled,
            serde_yaml::Value::Mapping(options) => match yaml_value(options, "enabled") {
                Some(value) => value
                    .as_bool()
                    .ok_or_else(|| "VLESS mux.enabled must be boolean".to_string())?,
                None => false,
            },
            _ => return Err("VLESS mux must be boolean or a mapping".into()),
        };
        if enabled {
            return Err("top-level VLESS mux is unsupported".into());
        }
    }

    let mut mux_mode = None;
    if let Some(value) =
        yaml_alias(mapping, &["smux", "multiplex"])?.filter(|value| yaml_active(value))
    {
        let options = value
            .as_mapping()
            .ok_or_else(|| "VLESS multiplex settings must be a mapping".to_string())?;
        let enabled = match yaml_value(options, "enabled") {
            Some(value) => value
                .as_bool()
                .ok_or_else(|| "VLESS multiplex.enabled must be boolean".to_string())?,
            None => false,
        };
        if enabled {
            let protocol = match yaml_value(options, "protocol") {
                Some(value) => {
                    let protocol = value
                        .as_str()
                        .ok_or_else(|| "VLESS multiplex.protocol must be a string".to_string())?;
                    let protocol = protocol.trim();
                    (!protocol.is_empty()).then_some(protocol)
                }
                None => None,
            };
            if protocol.is_some_and(|protocol| protocol != "h2mux") {
                return Err(format!(
                    "unsupported VLESS multiplex protocol '{}'",
                    protocol.unwrap_or_default()
                ));
            }
            if let Some(value) = yaml_alias(options, &["only-tcp", "only_tcp"])? {
                let only_tcp = value
                    .as_bool()
                    .ok_or_else(|| "VLESS multiplex.only-tcp must be boolean".to_string())?;
                if only_tcp {
                    return Err("VLESS multiplex.only-tcp is unsupported".into());
                }
            }
            if let Some(value) = yaml_alias(options, &["brutal", "brutal-opts", "brutal_opts"])? {
                let disabled = match value {
                    serde_yaml::Value::Null | serde_yaml::Value::Bool(false) => true,
                    serde_yaml::Value::Mapping(brutal) if brutal.is_empty() => true,
                    serde_yaml::Value::Mapping(brutal) => match yaml_value(brutal, "enabled") {
                        Some(value) => !value.as_bool().ok_or_else(|| {
                            "VLESS multiplex Brutal enabled must be boolean".to_string()
                        })?,
                        None => false,
                    },
                    _ => false,
                };
                if !disabled {
                    return Err("VLESS multiplex Brutal is unsupported".into());
                }
            }
            for keys in [
                ["max-connections", "max_connections"],
                ["min-streams", "min_streams"],
                ["max-streams", "max_streams"],
            ] {
                if let Some(value) = yaml_alias(options, &keys)? {
                    let limit = value
                        .as_u64()
                        .ok_or_else(|| format!("VLESS multiplex.{} must be an integer", keys[0]))?;
                    if limit != 0 {
                        return Err(format!("VLESS multiplex.{} tuning is unsupported", keys[0]));
                    }
                }
            }
            let padding = yaml_value(options, "padding")
                .map(|value| {
                    value
                        .as_bool()
                        .ok_or_else(|| "VLESS multiplex.padding must be boolean".to_string())
                })
                .transpose()?;
            if protocol.is_none() && padding.is_none() {
                return Err(
                    "enabled VLESS multiplex requires an explicit protocol or padding setting"
                        .into(),
                );
            }
            mux_mode = Some(if padding.unwrap_or(false) {
                WireMode::H2muxPadded
            } else {
                WireMode::H2mux
            });
        }
    }

    let mut uot_enabled = false;
    if let Some(value) =
        yaml_alias(mapping, &["udp-over-tcp", "udp_over_tcp"])?.filter(|value| yaml_active(value))
    {
        match value {
            serde_yaml::Value::Bool(enabled) => uot_enabled = *enabled,
            serde_yaml::Value::Mapping(options) => {
                uot_enabled = match yaml_value(options, "enabled") {
                    Some(value) => value
                        .as_bool()
                        .ok_or_else(|| "VLESS udp-over-tcp.enabled must be boolean".to_string())?,
                    None => false,
                };
                if uot_enabled {
                    let version = match yaml_value(options, "version") {
                        Some(value) => value.as_u64().ok_or_else(|| {
                            "VLESS udp-over-tcp.version must be an integer".to_string()
                        })?,
                        None => 0,
                    };
                    if !matches!(version, 0 | 2) {
                        return Err(format!(
                            "unsupported VLESS udp-over-tcp version '{version}'"
                        ));
                    }
                }
            }
            _ => return Err("VLESS udp-over-tcp must be boolean or a mapping".to_string()),
        }
    }

    if xudp_enabled && (mux_mode.is_some() || uot_enabled) {
        return Err("VLESS XUDP cannot be combined with multiplex or udp-over-tcp".into());
    }
    if mux_mode.is_some() && uot_enabled {
        return Err("VLESS multiplex and udp-over-tcp cannot both be enabled".into());
    }
    let mut mode = if xudp_enabled {
        WireMode::Xudp
    } else if let Some(mode) = mux_mode {
        mode
    } else if uot_enabled {
        WireMode::UotV2
    } else {
        WireMode::Legacy
    };
    if udp == Some(true) && mode == WireMode::Legacy {
        if xudp_disabled {
            return Err("VLESS udp=true requires an enabled packet mode".into());
        }
        mode = WireMode::Xudp;
    }
    match (udp, mode) {
        (Some(false), mode) if mode != WireMode::Legacy => Err(format!(
            "VLESS mode '{}' enables UDP but udp is false",
            mode.as_str()
        )),
        _ => Ok(mode),
    }
}

fn yaml_text(value: &serde_yaml::Value, label: &str) -> Result<Option<String>, String> {
    match value {
        serde_yaml::Value::Null => Ok(None),
        serde_yaml::Value::String(value) => Ok(Some(value.clone())),
        serde_yaml::Value::Number(value) => Ok(Some(value.to_string())),
        _ => Err(format!("{label} must be a scalar")),
    }
}

fn yaml_text_alias(mapping: &serde_yaml::Mapping, keys: &[&str]) -> Result<Option<String>, String> {
    yaml_alias(mapping, keys)?
        .map(|value| yaml_text(value, keys[0]))
        .transpose()
        .map(|value| value.flatten())
}

fn yaml_bool_alias(mapping: &serde_yaml::Mapping, keys: &[&str]) -> Result<Option<bool>, String> {
    yaml_alias(mapping, keys)?
        .map(|value| match value {
            serde_yaml::Value::Null => Ok(None),
            serde_yaml::Value::Bool(value) => Ok(Some(*value)),
            _ => Err(format!("{} must be boolean", keys[0])),
        })
        .transpose()
        .map(|value| value.flatten())
}

fn yaml_u64(value: &serde_yaml::Value, label: &str) -> Result<u64, String> {
    match value {
        serde_yaml::Value::Number(value) => value
            .as_u64()
            .ok_or_else(|| format!("{label} must be a non-negative integer")),
        serde_yaml::Value::String(value) => value
            .trim()
            .parse()
            .map_err(|_| format!("{label} must be a non-negative integer")),
        _ => Err(format!("{label} must be a non-negative integer")),
    }
}

fn yaml_u64_alias(mapping: &serde_yaml::Mapping, keys: &[&str]) -> Result<Option<u64>, String> {
    yaml_alias(mapping, keys)?
        .map(|value| match value {
            serde_yaml::Value::Null => Ok(None),
            value => yaml_u64(value, keys[0]).map(Some),
        })
        .transpose()
        .map(|value| value.flatten())
}

fn yaml_duration_secs(value: &serde_yaml::Value, label: &str) -> Result<u64, String> {
    match value {
        serde_yaml::Value::Number(_) => yaml_u64(value, label),
        serde_yaml::Value::String(raw) => {
            let raw = raw.trim();
            let (number, multiplier) = if let Some(value) = raw.strip_suffix("ms") {
                (value, 0)
            } else if let Some(value) = raw.strip_suffix('s') {
                (value, 1)
            } else if let Some(value) = raw.strip_suffix('m') {
                (value, 60)
            } else if let Some(value) = raw.strip_suffix('h') {
                (value, 3600)
            } else {
                (raw, 1)
            };
            let number: u64 = number
                .trim()
                .parse()
                .map_err(|_| format!("{label} must be a duration"))?;
            if multiplier == 0 {
                Ok(number / 1000)
            } else {
                number
                    .checked_mul(multiplier)
                    .ok_or_else(|| format!("{label} duration is too large"))
            }
        }
        _ => Err(format!("{label} must be a duration")),
    }
}

fn yaml_duration_alias(
    mapping: &serde_yaml::Mapping,
    keys: &[&str],
) -> Result<Option<u64>, String> {
    yaml_alias(mapping, keys)?
        .map(|value| match value {
            serde_yaml::Value::Null => Ok(None),
            value => yaml_duration_secs(value, keys[0]).map(Some),
        })
        .transpose()
        .map(|value| value.flatten())
}

fn yaml_rate_mbps(value: &serde_yaml::Value, label: &str) -> Result<u32, String> {
    let raw = yaml_text(value, label)?.ok_or_else(|| format!("{label} is empty"))?;
    let raw = raw.trim();
    let raw = raw
        .strip_suffix("Mbps")
        .or_else(|| raw.strip_suffix("mbps"))
        .or_else(|| raw.strip_suffix("Mb/s"))
        .unwrap_or(raw)
        .trim();
    raw.parse().map_err(|_| format!("{label} must be Mbps"))
}

fn yaml_rate_alias(mapping: &serde_yaml::Mapping, keys: &[&str]) -> Result<Option<u32>, String> {
    yaml_alias(mapping, keys)?
        .map(|value| match value {
            serde_yaml::Value::Null => Ok(None),
            value => yaml_rate_mbps(value, keys[0]).map(Some),
        })
        .transpose()
        .map(|value| value.flatten())
}

fn yaml_list_text(value: &serde_yaml::Value, label: &str) -> Result<Option<String>, String> {
    match value {
        serde_yaml::Value::Null => Ok(None),
        serde_yaml::Value::Sequence(values) => values
            .iter()
            .map(|value| yaml_text(value, label).map(|value| value.unwrap_or_default()))
            .collect::<Result<Vec<_>, _>>()
            .map(|values| Some(values.join(","))),
        value => yaml_text(value, label),
    }
}

fn yaml_list_alias(mapping: &serde_yaml::Mapping, keys: &[&str]) -> Result<Option<String>, String> {
    yaml_alias(mapping, keys)?
        .map(|value| yaml_list_text(value, keys[0]))
        .transpose()
        .map(|value| value.flatten())
}

fn yaml_ports(value: &serde_yaml::Value, label: &str) -> Result<Option<String>, String> {
    let Some(value) = yaml_list_text(value, label)? else {
        return Ok(None);
    };
    let value = value
        .split(',')
        .map(|part| part.trim().replace(':', "-"))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    if value.is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(Some(value))
}

fn validate_imported_node(node: &Node) -> Result<(), String> {
    fn nonempty<'a>(value: Option<&'a String>, label: &str) -> Result<&'a String, String> {
        value
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("{label} is missing"))
    }
    match &node.outbound {
        OutboundConfig::Shadowsocks(config) => {
            nonempty(config.password.as_ref(), "Shadowsocks password")?;
            nonempty(config.encryption.as_ref(), "Shadowsocks cipher")?;
        }
        OutboundConfig::Trojan(config) => {
            nonempty(config.password.as_ref(), "Trojan password")?;
        }
        OutboundConfig::Vmess(config) => {
            let uuid = nonempty(config.uuid.as_ref(), "VMess UUID")?;
            uuid::Uuid::parse_str(uuid).map_err(|_| "VMess UUID is invalid")?;
            let cipher = config.encryption.as_deref().unwrap_or("auto").trim();
            if !cipher.eq_ignore_ascii_case("auto") && !cipher.eq_ignore_ascii_case("aes-128-gcm") {
                return Err("VMess cipher is unsupported".into());
            }
        }
        OutboundConfig::Vless(config) => {
            let uuid = nonempty(config.uuid.as_ref(), "VLESS UUID")?;
            uuid::Uuid::parse_str(uuid).map_err(|_| "VLESS UUID is invalid")?;
            if config
                .flow
                .as_deref()
                .is_some_and(|flow| !flow.trim().is_empty() && flow != "xtls-rprx-vision")
            {
                return Err("VLESS flow is unsupported".into());
            }
            if config.encryption.as_deref().is_some_and(|encryption| {
                let encryption = encryption.trim();
                !encryption.is_empty()
                    && encryption != "none"
                    && !encryption.starts_with("mlkem768x25519plus.")
            }) {
                return Err("VLESS encryption is unsupported".into());
            }
        }
        OutboundConfig::Socks5(_) => {}
        OutboundConfig::Hysteria2(_) => {}
        OutboundConfig::Tuic(config) => {
            let uuid = nonempty(config.uuid.as_ref(), "TUIC UUID")?;
            uuid::Uuid::parse_str(uuid).map_err(|_| "TUIC UUID is invalid")?;
        }
        OutboundConfig::Juicity(config) => {
            let uuid = nonempty(config.uuid.as_ref(), "Juicity UUID")?;
            uuid::Uuid::parse_str(uuid).map_err(|_| "Juicity UUID is invalid")?;
            nonempty(config.password.as_ref(), "Juicity password")?;
        }
        OutboundConfig::AnyTls(config) => {
            nonempty(config.password.as_ref(), "AnyTLS password")?;
        }
        OutboundConfig::Direct | OutboundConfig::Block => unreachable!(),
    }
    Ok(())
}

fn yaml_active(value: &serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::Null => false,
        serde_yaml::Value::Bool(value) => *value,
        serde_yaml::Value::Number(value) => {
            value.as_i64() != Some(0) && value.as_u64() != Some(0) && value.as_f64() != Some(0.0)
        }
        serde_yaml::Value::String(value) => !value.trim().is_empty(),
        serde_yaml::Value::Sequence(value) => !value.is_empty(),
        serde_yaml::Value::Mapping(value) => {
            !value.is_empty()
                && yaml_value(value, "enabled").is_none_or(|enabled| {
                    !matches!(
                        enabled,
                        serde_yaml::Value::Null | serde_yaml::Value::Bool(false)
                    )
                })
        }
        serde_yaml::Value::Tagged(_) => true,
    }
}

fn yaml_active_for_key(key: &str, value: &serde_yaml::Value) -> bool {
    if matches!(key, "pin-sha256" | "pin_sha256") {
        return !matches!(value, serde_yaml::Value::Null);
    }
    if matches!(key, "packet-encoding" | "packet_encoding") {
        return match value {
            serde_yaml::Value::Null => false,
            serde_yaml::Value::String(value) => !matches!(value.trim(), "" | "none" | "legacy"),
            _ => yaml_active(value),
        };
    }
    yaml_active(value)
}

fn apply_reality(
    mapping: &serde_yaml::Mapping,
    node: &mut Node,
    protocol: NodeProtocol,
    tls_explicit: Option<bool>,
) -> Result<(), String> {
    let Some(value) = yaml_value(mapping, "reality-opts") else {
        return Ok(());
    };
    if !yaml_active(value) {
        return Ok(());
    }
    if !matches!(
        protocol,
        NodeProtocol::Trojan | NodeProtocol::VMess | NodeProtocol::VLess
    ) {
        return Err("REALITY is unsupported for this protocol".into());
    }
    if tls_explicit == Some(false) {
        return Err("REALITY conflicts with tls=false".into());
    }
    let reality = value
        .as_mapping()
        .ok_or_else(|| "reality-opts must be a mapping".to_string())?;
    let public_key = yaml_text_alias(reality, &["public-key", "public_key"])?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "REALITY public key is missing".to_string())?;
    let short_id = yaml_text_alias(reality, &["short-id", "short_id"])?;
    let spider_x = yaml_text_alias(reality, &["spider-x", "spider_x"])?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/".to_string());
    let tls = node
        .tls_mut()
        .ok_or_else(|| "REALITY requires TLS".to_string())?;
    tls.enabled = true;
    tls.reality_public_key = Some(public_key);
    tls.reality_short_id = short_id;
    tls.reality_spider_x = Some(spider_x);
    Ok(())
}

fn parse_clash_proxy(
    mapping: &serde_yaml::Mapping,
    subscription_id: Option<uuid::Uuid>,
) -> Result<Option<Node>, String> {
    let Some(proxy_type) = yaml_text_alias(mapping, &["type"])? else {
        return Ok(None);
    };
    let protocol = match proxy_type.to_ascii_lowercase().as_str() {
        "socks5" => NodeProtocol::Socks5,
        "ss" | "shadowsocks" => NodeProtocol::SS,
        "trojan" => NodeProtocol::Trojan,
        "vmess" => NodeProtocol::VMess,
        "vless" => NodeProtocol::VLess,
        "hysteria2" | "hysteria" => NodeProtocol::Hysteria2,
        "tuic" => NodeProtocol::Tuic,
        "juicity" => NodeProtocol::Juicity,
        "anytls" => NodeProtocol::AnyTLS,
        _ => return Ok(None),
    };
    if ["plugin", "plugin-opts", "plugin_opts"]
        .into_iter()
        .any(|key| yaml_value(mapping, key).is_some_and(yaml_active))
    {
        return Err("proxy plugins are unsupported".into());
    }
    let tls_capable = matches!(
        protocol,
        NodeProtocol::Trojan
            | NodeProtocol::VMess
            | NodeProtocol::VLess
            | NodeProtocol::Hysteria2
            | NodeProtocol::Tuic
            | NodeProtocol::Juicity
            | NodeProtocol::AnyTLS
    );
    if !tls_capable
        && [
            "tls",
            "servername",
            "server-name",
            "sni",
            "skip-cert-verify",
            "skip_cert_verify",
            "insecure",
            "pin-sha256",
            "pin_sha256",
            "reality-opts",
        ]
        .into_iter()
        .any(|key| yaml_value(mapping, key).is_some_and(|value| yaml_active_for_key(key, value)))
    {
        return Err("TLS settings are unsupported for this protocol".into());
    }
    if !matches!(
        protocol,
        NodeProtocol::Trojan | NodeProtocol::VMess | NodeProtocol::VLess
    ) && [
        "ws-opts",
        "ws-path",
        "ws-host",
        "ws-headers",
        "grpc-opts",
        "grpc-service",
    ]
    .into_iter()
    .any(|key| yaml_value(mapping, key).is_some_and(yaml_active))
    {
        return Err("stream transport settings are unsupported for this protocol".into());
    }
    if !matches!(
        protocol,
        NodeProtocol::Trojan | NodeProtocol::VMess | NodeProtocol::VLess | NodeProtocol::AnyTLS
    ) && yaml_value(mapping, "network").is_some_and(yaml_active)
    {
        return Err("network settings are unsupported for this protocol".into());
    }
    if !matches!(
        protocol,
        NodeProtocol::Trojan | NodeProtocol::VMess | NodeProtocol::VLess
    ) && yaml_value(mapping, "flow").is_some_and(yaml_active)
    {
        return Err("VLESS flow is unsupported for this protocol".into());
    }
    if !matches!(
        protocol,
        NodeProtocol::SS | NodeProtocol::VMess | NodeProtocol::VLess
    ) && ["cipher", "encryption"]
        .into_iter()
        .any(|key| yaml_value(mapping, key).is_some_and(yaml_active))
    {
        return Err("encryption settings are unsupported for this protocol".into());
    }
    if !matches!(protocol, NodeProtocol::VLess)
        && [
            "packet-encoding",
            "packet_encoding",
            "packet-addr",
            "packet_addr",
            "xudp",
            "mux",
            "smux",
            "multiplex",
            "udp-over-tcp",
            "udp_over_tcp",
        ]
        .into_iter()
        .any(|key| yaml_value(mapping, key).is_some_and(|value| yaml_active_for_key(key, value)))
    {
        return Err("VLESS packet wrappers are unsupported for this protocol".into());
    }
    let udp = yaml_bool_alias(mapping, &["udp"])?;
    let udp_capable = matches!(
        protocol,
        NodeProtocol::SS
            | NodeProtocol::Trojan
            | NodeProtocol::VLess
            | NodeProtocol::Socks5
            | NodeProtocol::Hysteria2
            | NodeProtocol::Tuic
            | NodeProtocol::Juicity
            | NodeProtocol::AnyTLS
    );
    let udp_restrictable = matches!(
        protocol,
        NodeProtocol::Trojan | NodeProtocol::VMess | NodeProtocol::VLess | NodeProtocol::AnyTLS
    );
    if udp == Some(true) && !udp_capable {
        return Err("UDP capability is unsupported for this protocol".into());
    }
    if udp == Some(false) && !udp_restrictable {
        return Err("UDP restriction is unsupported for this protocol".into());
    }
    if !matches!(protocol, NodeProtocol::Hysteria2)
        && [
            "obfs",
            "obfs-password",
            "obfs_password",
            "ports",
            "mport",
            "port-hopping",
            "port_hopping",
            "up",
            "down",
            "upload-bandwidth",
            "download-bandwidth",
            "up-speed",
            "down-speed",
            "up_mbps",
            "down_mbps",
            "hop-interval",
            "hop_interval",
            "mhop",
        ]
        .into_iter()
        .any(|key| yaml_value(mapping, key).is_some_and(yaml_active))
    {
        return Err("Hysteria2 options are unsupported for this protocol".into());
    }
    if !matches!(protocol, NodeProtocol::Hysteria2)
        && [
            "disable-mtu-discovery",
            "disable-path-mtu-discovery",
            "disablePathMTUDiscovery",
        ]
        .into_iter()
        .any(|key| yaml_value(mapping, key).is_some_and(yaml_active))
    {
        return Err("Hysteria2 MTU discovery options are unsupported".into());
    }
    if !matches!(
        protocol,
        NodeProtocol::Hysteria2 | NodeProtocol::Tuic | NodeProtocol::Juicity
    ) && [
        "mtu",
        "quic-mtu",
        "quic_mtu",
        "initial-stream-receive-window",
        "initial-conn-receive-window",
        "initial_stream_receive_window",
        "initial_conn_receive_window",
        "init-stream-receive-window",
        "init-conn-receive-window",
        "init_stream_receive_window",
        "init_conn_receive_window",
        "initStreamReceiveWindow",
        "initConnReceiveWindow",
    ]
    .into_iter()
    .any(|key| yaml_value(mapping, key).is_some_and(yaml_active))
    {
        return Err("QUIC options are unsupported for this protocol".into());
    }
    if protocol == NodeProtocol::Juicity {
        for keys in [
            [
                "initial-stream-receive-window",
                "initial_stream_receive_window",
                "init-stream-receive-window",
                "init_stream_receive_window",
                "initStreamReceiveWindow",
            ],
            [
                "initial-conn-receive-window",
                "initial_conn_receive_window",
                "init-conn-receive-window",
                "init_conn_receive_window",
                "initConnReceiveWindow",
            ],
        ] {
            if keys
                .iter()
                .any(|key| yaml_value(mapping, key).is_some_and(yaml_active))
                && let Some(window) = yaml_u64_alias(mapping, &keys)?
                && !matches!(window, 0 | 8_388_608)
            {
                return Err("Juicity receive-window override is unsupported".into());
            }
        }
    }
    if yaml_value(mapping, "alpn").is_some_and(yaml_active) {
        match protocol {
            NodeProtocol::Tuic => {}
            NodeProtocol::Hysteria2 | NodeProtocol::Juicity => {
                let alpn = yaml_list_alias(mapping, &["alpn"])?.unwrap_or_default();
                if !alpn.split(',').all(|value| value.trim() == "h3") {
                    return Err("unsupported fixed QUIC ALPN".into());
                }
            }
            _ => return Err("TUIC ALPN is unsupported for this protocol".into()),
        }
    }
    if yaml_bool_alias(mapping, &["disable-sni", "disable_sni"])? == Some(true) {
        return Err("disable-sni is unsupported".into());
    }
    if let Some(mode) = yaml_text_alias(mapping, &["udp-relay-mode", "udp_relay_mode"])?
        && (!matches!(protocol, NodeProtocol::Tuic) || !matches!(mode.trim(), "" | "native"))
    {
        return Err("unsupported TUIC UDP relay mode".into());
    }
    let server = yaml_text_alias(mapping, &["server"])?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "proxy server is missing".to_string())?;
    let port = yaml_u64_alias(mapping, &["port"])?
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| "proxy port is invalid".to_string())?;
    let name = yaml_text_alias(mapping, &["name"])?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("{proxy_type}-{server}:{port}"));
    let tls_explicit = yaml_bool_alias(mapping, &["tls"])?;
    let mandatory_tls = matches!(
        protocol,
        NodeProtocol::Trojan
            | NodeProtocol::Hysteria2
            | NodeProtocol::Tuic
            | NodeProtocol::Juicity
            | NodeProtocol::AnyTLS
    );
    let tls_enabled = tls_explicit.unwrap_or(mandatory_tls);
    if mandatory_tls && !tls_enabled {
        return Err("this imported protocol requires TLS".into());
    }
    let vless_mode = if protocol == NodeProtocol::VLess {
        parse_vless_external_mode(mapping)?
    } else {
        honk_config::node::WireMode::Legacy
    };
    let mut node = Node {
        name,
        address: format!("{server}:{port}"),
        host: server,
        port,
        outbound: OutboundConfig::from_protocol(protocol),
        subscription_id,
        ..Default::default()
    };
    let username = yaml_text_alias(mapping, &["username"])?;
    let password = yaml_text_alias(mapping, &["password"])?;
    let cipher = yaml_text_alias(mapping, &["cipher"])?;
    match &mut node.outbound {
        OutboundConfig::Shadowsocks(config) => {
            config.password = password;
            config.encryption = cipher;
        }
        OutboundConfig::Socks5(config) => {
            config.username = username;
            config.password = password;
        }
        OutboundConfig::Trojan(config) => {
            config.password = password;
        }
        OutboundConfig::Vmess(config) => {
            config.uuid = yaml_text_alias(mapping, &["uuid"])?.or(password);
            config.encryption = yaml_text_alias(mapping, &["encryption"])?.or(cipher);
        }
        OutboundConfig::Vless(config) => {
            config.uuid = yaml_text_alias(mapping, &["uuid"])?.or(password);
            config.encryption = yaml_text_alias(mapping, &["encryption"])?.or(cipher);
            config.flow =
                yaml_text_alias(mapping, &["flow"])?.filter(|flow| !flow.trim().is_empty());
            config.mode = vless_mode;
        }
        OutboundConfig::Hysteria2(config) => {
            config.auth = yaml_text_alias(mapping, &["auth"])?.or(password);
            let obfs = yaml_text_alias(mapping, &["obfs"])?;
            if let Some(obfs) = obfs {
                if !obfs.eq_ignore_ascii_case("salamander") {
                    return Err("unsupported Hysteria2 obfuscation algorithm".into());
                }
                config.obfs = yaml_text_alias(mapping, &["obfs-password", "obfs_password"])?
                    .filter(|password| !password.trim().is_empty())
                    .ok_or_else(|| "Hysteria2 salamander password is missing".to_string())
                    .map(Some)?;
            } else if yaml_value(mapping, "obfs-password").is_some()
                || yaml_value(mapping, "obfs_password").is_some()
            {
                return Err("Hysteria2 obfs-password requires salamander".into());
            }
            config.up_mbps =
                yaml_rate_alias(mapping, &["up", "upload-bandwidth", "up-speed", "up_mbps"])?;
            config.down_mbps = yaml_rate_alias(
                mapping,
                &["down", "download-bandwidth", "down-speed", "down_mbps"],
            )?;
            let ports = yaml_alias(mapping, &["ports"])?
                .map(|value| yaml_ports(value, "ports"))
                .transpose()?
                .flatten();
            let mport = yaml_text_alias(mapping, &["mport", "port-hopping", "port_hopping"])?
                .map(|value| value.replace(':', "-"));
            if ports.is_some() && mport.is_some() {
                return Err("Hysteria2 port hopping aliases conflict".into());
            }
            config.port_hopping = ports.or(mport);
            config.hop_interval =
                yaml_duration_alias(mapping, &["hop-interval", "hop_interval", "mhop"])?;
            config.init_stream_recv_window = yaml_u64_alias(
                mapping,
                &[
                    "initial-stream-receive-window",
                    "initial_stream_receive_window",
                    "init-stream-receive-window",
                    "init_stream_receive_window",
                    "initStreamReceiveWindow",
                ],
            )?;
            config.init_conn_recv_window = yaml_u64_alias(
                mapping,
                &[
                    "initial-conn-receive-window",
                    "initial_conn_receive_window",
                    "init-conn-receive-window",
                    "init_conn_receive_window",
                    "initConnReceiveWindow",
                ],
            )?;
            config.disable_mtu_discovery = yaml_bool_alias(
                mapping,
                &[
                    "disable-mtu-discovery",
                    "disable-path-mtu-discovery",
                    "disablePathMTUDiscovery",
                ],
            )?;
        }
        OutboundConfig::Tuic(config) => {
            config.uuid = yaml_text_alias(mapping, &["uuid"])?.or(username);
            config.password = password;
            config.congestion = yaml_text_alias(
                mapping,
                &[
                    "congestion-controller",
                    "congestion-control",
                    "congestion_control",
                    "congestion",
                ],
            )?;
            config.alpn = yaml_list_alias(mapping, &["alpn"])?;
            config.init_stream_recv_window = yaml_u64_alias(
                mapping,
                &[
                    "initial-stream-receive-window",
                    "initial_stream_receive_window",
                    "init-stream-receive-window",
                    "init_stream_receive_window",
                    "initStreamReceiveWindow",
                ],
            )?;
            config.init_conn_recv_window = yaml_u64_alias(
                mapping,
                &[
                    "initial-conn-receive-window",
                    "initial_conn_receive_window",
                    "init-conn-receive-window",
                    "init_conn_receive_window",
                    "initConnReceiveWindow",
                ],
            )?;
        }
        OutboundConfig::Juicity(config) => {
            config.uuid = yaml_text_alias(mapping, &["uuid"])?.or(username);
            config.password = password;
        }
        OutboundConfig::AnyTls(config) => {
            config.password = password;
            config.network = yaml_text_alias(mapping, &["anytls-network"])?;
            config.min_idle_session =
                yaml_u64_alias(mapping, &["min-idle-session", "min_idle_session"])?
                    .map(|value| {
                        usize::try_from(value).map_err(|_| "AnyTLS session count is too large")
                    })
                    .transpose()?;
            config.idle_session_check_interval = yaml_duration_alias(
                mapping,
                &["idle-session-check-interval", "idle_session_check_interval"],
            )?;
            config.idle_session_timeout =
                yaml_duration_alias(mapping, &["idle-session-timeout", "idle_session_timeout"])?;
        }
        OutboundConfig::Direct | OutboundConfig::Block => unreachable!(),
    }
    if let Some(network) =
        yaml_text_alias(mapping, &["network"])?.filter(|network| !network.trim().is_empty())
    {
        if let Some(transport) = node.transport_mut() {
            if !matches!(network.as_str(), "tcp" | "ws" | "grpc") {
                return Err("unsupported stream transport".into());
            }
            transport.transport = network;
        } else if let Some(config) = node.anytls_mut() {
            if !matches!(network.as_str(), "tcp" | "udp") {
                return Err("unsupported AnyTLS network".into());
            }
            config.network = Some(network);
        }
    }
    if let Some(udp) = udp {
        let network = if udp { "tcp,udp" } else { "tcp" }.to_string();
        match &mut node.outbound {
            OutboundConfig::Trojan(config) => config.network = Some(network),
            OutboundConfig::Vmess(config) => config.network = Some(network),
            OutboundConfig::Vless(config) => config.network = Some(network),
            OutboundConfig::AnyTls(config) => config.network = Some(network),
            _ => {}
        }
    }
    if let Some(transport) = node.transport() {
        if transport.transport != "ws"
            && ["ws-opts", "ws-path", "ws-host", "ws-headers"]
                .into_iter()
                .any(|key| yaml_value(mapping, key).is_some_and(yaml_active))
        {
            return Err("websocket options require websocket transport".into());
        }
        if transport.transport != "grpc"
            && ["grpc-opts", "grpc-service", "grpc_service"]
                .into_iter()
                .any(|key| yaml_value(mapping, key).is_some_and(yaml_active))
        {
            return Err("gRPC options require gRPC transport".into());
        }
    }
    if let Some(transport) = node.transport_mut() {
        if let Some(options) = yaml_value(mapping, "ws-opts").filter(|value| yaml_active(value)) {
            let options = options
                .as_mapping()
                .ok_or_else(|| "ws-opts must be a mapping".to_string())?;
            if transport.transport != "ws" && !options.is_empty() {
                return Err("ws-opts require websocket transport".into());
            }
            transport.ws_path = yaml_text_alias(options, &["path"])?;
            if let Some(headers) = yaml_value(options, "headers") {
                let headers = headers
                    .as_mapping()
                    .ok_or_else(|| "ws-opts.headers must be a mapping".to_string())?;
                for (key, value) in headers {
                    let key = key
                        .as_str()
                        .ok_or_else(|| "websocket header name is invalid".to_string())?;
                    if !key.eq_ignore_ascii_case("host")
                        && !matches!(value, serde_yaml::Value::Null)
                    {
                        return Err("unsupported websocket header".into());
                    }
                }
                transport.ws_host = headers.iter().find_map(|(key, value)| {
                    key.as_str()
                        .filter(|key| key.eq_ignore_ascii_case("host"))
                        .and_then(|_| yaml_text(value, "websocket host").ok().flatten())
                        .filter(|value| !value.trim().is_empty())
                });
            }
        }
        transport.ws_path = transport
            .ws_path
            .take()
            .or(yaml_text_alias(mapping, &["ws-path"])?.filter(|value| !value.trim().is_empty()));
        if transport.ws_host.is_none() {
            transport.ws_host =
                yaml_text_alias(mapping, &["ws-headers"])?.filter(|value| !value.trim().is_empty());
        }
        if transport.ws_host.is_none() {
            transport.ws_host =
                yaml_text_alias(mapping, &["ws-host"])?.filter(|value| !value.trim().is_empty());
        }
        if let Some(options) = yaml_value(mapping, "grpc-opts").filter(|value| yaml_active(value)) {
            let options = options
                .as_mapping()
                .ok_or_else(|| "grpc-opts must be a mapping".to_string())?;
            if transport.transport != "grpc" && !options.is_empty() {
                return Err("grpc-opts require gRPC transport".into());
            }
            transport.grpc_service =
                yaml_text_alias(options, &["grpc-service-name", "grpc_service_name"])?;
        }
        transport.grpc_service = transport
            .grpc_service
            .take()
            .or(yaml_text_alias(mapping, &["grpc-service", "grpc_service"])?);
    }

    if let Some(tls) = node.tls_mut() {
        tls.enabled = tls_enabled;
        tls.sni = yaml_text_alias(mapping, &["servername", "server-name"])?
            .or(yaml_text_alias(mapping, &["sni"])?);
        tls.skip_cert_verify = yaml_bool_alias(
            mapping,
            &["skip-cert-verify", "skip_cert_verify", "insecure"],
        )?
        .unwrap_or(false);
        tls.pin_sha256 = yaml_text_alias(mapping, &["pin-sha256", "pin_sha256"])?;
    }
    apply_reality(mapping, &mut node, protocol, tls_explicit)?;
    if let Some(mtu) = yaml_u64_alias(mapping, &["mtu", "quic-mtu", "quic_mtu"])? {
        let mtu = u16::try_from(mtu).map_err(|_| "QUIC MTU is invalid")?;
        if !(1200..=65527).contains(&mtu) {
            return Err("QUIC MTU is invalid".into());
        }
        match &mut node.outbound {
            OutboundConfig::Hysteria2(config) => config.quic.mtu = Some(mtu),
            OutboundConfig::Tuic(config) => config.quic.mtu = Some(mtu),
            OutboundConfig::Juicity(config) => config.quic.mtu = Some(mtu),
            _ => {}
        }
    }
    validate_imported_node(&node)?;
    if let Err(_error) = node.validate_protocol() {
        return Err("invalid imported node protocol settings".into());
    }
    node.id = node.derive_id();
    Ok(Some(node))
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
        match parse_clash_proxy(mapping, subscription_id) {
            Ok(Some(node)) => nodes.push(node),
            Ok(None) | Err(_) => {
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

/// Parse a single node share link via the unified parser in honk-config.
fn parse_node_uri(uri: &str) -> anyhow::Result<Node> {
    Node::from_share_link(uri).map_err(anyhow::Error::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[tokio::test]
    async fn body_reader_refuses_one_byte_past_the_cap() {
        let at_cap = http::Response::new(vec![b'a'; MAX_SUBSCRIPTION_BYTES]);
        assert_eq!(
            read_capped_body(at_cap.into()).await.unwrap().len(),
            MAX_SUBSCRIPTION_BYTES
        );
        let over_cap = http::Response::new(vec![b'a'; MAX_SUBSCRIPTION_BYTES + 1]);
        assert!(read_capped_body(over_cap.into()).await.is_err());
    }

    #[test]
    fn private_literal_hosts_are_recognized_by_address_not_name() {
        for url in [
            "http://127.0.0.1/sub",
            "http://10.203.0.1:8080/sub",
            "http://192.168.1.1/sub",
            "http://169.254.1.1/sub",
            "http://[::1]/sub",
            "http://[fd00::1]/sub",
            "http://[fe80::1]/sub",
            "http://[::ffff:127.0.0.1]/sub",
            "http://0.0.0.0/sub",
            "http://[::]/sub",
        ] {
            let url = reqwest::Url::parse(url).unwrap();
            assert!(has_private_literal_host(&url), "{url} should be private");
        }
        for url in [
            "https://example.com/sub",
            "http://93.184.216.34/sub",
            "http://[2001:db8::1]/sub",
            // Resolution is out of scope: only a stated literal is refused.
            "http://internal.example/sub",
        ] {
            let url = reqwest::Url::parse(url).unwrap();
            assert!(
                !has_private_literal_host(&url),
                "{url} should not be private"
            );
        }
    }

    #[test]
    fn test_parse_socks5_uri() {
        let node = parse_node_uri("socks5://192.168.1.1:1080").unwrap();
        assert_eq!(node.protocol(), NodeProtocol::Socks5);
        assert_eq!(node.host, "192.168.1.1");
        assert_eq!(node.port, 1080);
        assert_eq!(node.address, "192.168.1.1:1080");
        assert!(node.name.contains("socks5"));
    }

    #[test]
    fn test_parse_socks5_uri_with_fragment() {
        let node = parse_node_uri("socks5://10.0.0.1:1080#MySocks5").unwrap();
        assert_eq!(node.protocol(), NodeProtocol::Socks5);
        assert_eq!(node.host, "10.0.0.1");
        assert_eq!(node.port, 1080);
        assert_eq!(node.name, "MySocks5");
    }

    #[test]
    fn test_parse_unsupported_protocol() {
        let result = parse_node_uri("unknown://host:1234");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unknown node protocol"));
    }

    #[test]
    fn test_parse_socks5_uri_with_auth() {
        let node = parse_node_uri("socks5://user:pass@10.0.0.1:1080").unwrap();
        assert_eq!(node.protocol(), NodeProtocol::Socks5);
        assert_eq!(node.host, "10.0.0.1");
        assert_eq!(node.port, 1080);
        let socks = node.socks5().unwrap();
        assert_eq!(socks.username, Some("user".to_string()));
        assert_eq!(socks.password, Some("pass".to_string()));
    }

    #[test]
    fn test_parse_base64_subscription() {
        let uris = [
            "socks5://192.168.1.1:1080#Node1",
            "socks5://10.0.0.1:2080#Node2",
        ];
        let joined = uris.join("\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
        let nodes = parse_base64_subscription(&encoded, None, "test").unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "Node1");
        assert_eq!(nodes[1].name, "Node2");
        assert_eq!(nodes[0].protocol(), NodeProtocol::Socks5);
        assert_eq!(nodes[1].protocol(), NodeProtocol::Socks5);
    }

    #[test]
    fn test_parse_base64_without_padding() {
        let uris = "socks5://10.0.0.1:1080#NoPad";
        let encoded = base64::engine::general_purpose::STANDARD.encode(uris.as_bytes());
        let no_pad = encoded.trim_end_matches('=');
        let nodes = parse_base64_subscription(no_pad, None, "test").unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "NoPad");
    }

    #[test]
    fn test_parse_base64_skips_unsupported() {
        let uris = ["socks5://192.168.1.1:1080#Valid", "unknown://host:1234"];
        let joined = uris.join("\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
        let nodes = parse_base64_subscription(&encoded, None, "test").unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Valid");
    }

    #[test]
    fn test_parse_base64_empty_result() {
        let uris = "unknown://host:1234\nanother-unsupported://x:1";
        let encoded = base64::engine::general_purpose::STANDARD.encode(uris.as_bytes());
        let result = parse_base64_subscription(&encoded, None, "test");
        assert!(result.is_err());
    }

    #[test]
    fn subscription_normalizes_bom_and_urlsafe_wrapped_base64() {
        let sub = Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        };
        let uri = "socks5://127.0.0.1:1080#wrapped";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(uri);
        let wrapped = encoded
            .as_bytes()
            .chunks(7)
            .map(std::str::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join(" \n");
        let nodes = parse_subscription_content(&sub, &format!("\u{feff}{wrapped}")).unwrap();
        assert_eq!(nodes[0].name, "wrapped");
    }

    #[test]
    fn simple_and_custom_detect_structured_bodies_without_fallback() {
        let yaml =
            "proxies:\n  - type: socks5\n    server: 127.0.0.1\n    port: 1080\n    name: yaml\n";
        let simple = Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        };
        assert_eq!(
            parse_subscription_content(&simple, yaml).unwrap()[0].name,
            "yaml"
        );

        let custom = Subscription {
            sub_type: SubscriptionType::Custom,
            ..Default::default()
        };
        let json = r#"{"outbounds":[{"type":"socks","tag":"json","server":"127.0.0.1","server_port":1081}]}"#;
        assert_eq!(
            parse_subscription_content(&custom, json).unwrap()[0].name,
            "json"
        );
        assert!(parse_subscription_content(&simple, r#"{"unknown":"wrapper"}"#).is_err());
        assert!(
            parse_subscription_content(
                &simple,
                "{\"outbounds\":[\ntrojan://secret@example.com:443#not-json",
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_sip008_uses_server_schema_not_uri_parser() {
        let sub = Subscription {
            sub_type: SubscriptionType::Sip008,
            ..Default::default()
        };
        let body = r#"{"servers":[{"server":"ss.example","server_port":8388,"method":"aes-128-gcm","password":"secret","remarks":"sip"}]}"#;
        let nodes = parse_subscription_content(&sub, body).unwrap();
        assert_eq!(nodes[0].name, "sip");
        assert_eq!(nodes[0].protocol(), NodeProtocol::SS);
    }

    #[test]
    fn json_subscription_names_accept_utf16_surrogate_pairs() {
        for (sub_type, body) in [
            (
                SubscriptionType::Simple,
                r#"{"outbounds":[{"type":"socks","tag":"node-\ud83d\ude00","server":"127.0.0.1","server_port":1080}]}"#,
            ),
            (
                SubscriptionType::Clash,
                r#"{"proxies":[{"type":"socks5","name":"node-\ud83d\ude00","server":"127.0.0.1","port":1080}]}"#,
            ),
            (
                SubscriptionType::Sip008,
                r#"{"servers":[{"remarks":"node-\ud83d\ude00","server":"127.0.0.1","server_port":8388,"method":"aes-128-gcm","password":"fixture"}]}"#,
            ),
        ] {
            let sub = Subscription {
                sub_type,
                ..Default::default()
            };
            let nodes = parse_subscription_content(&sub, body).unwrap();
            assert_eq!(nodes[0].name, "node-\u{1f600}");
        }
    }

    #[test]
    fn test_parse_subscription_keeps_unique_nodes_with_duplicates() {
        let sub = Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        };
        let content = concat!(
            "socks5://127.0.0.1:1080#same\n",
            "socks5://127.0.0.1:1080#same-again"
        );
        let nodes = parse_subscription_content(&sub, content).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "same");
    }

    #[test]
    fn test_parse_subscription_skips_proxy_plugins() {
        let clash = Subscription {
            sub_type: SubscriptionType::Clash,
            ..Default::default()
        };
        let clash_nodes = parse_subscription_content(
            &clash,
            r#"proxies:
  - name: obfs
    type: ss
    server: ss.example
    port: 8388
    cipher: aes-128-gcm
    password: secret
    plugin: obfs
    plugin-opts:
      mode: http
      host: mask.example
  - name: plain
    type: socks5
    server: 127.0.0.1
    port: 1080
"#,
        )
        .unwrap();
        assert_eq!(clash_nodes.len(), 1);
        assert_eq!(clash_nodes[0].name, "plain");

        let simple = Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        };
        let simple_nodes = parse_subscription_content(
            &simple,
            concat!(
                "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp#obfs\n",
                "socks5://127.0.0.1:1080#plain"
            ),
        )
        .unwrap();
        assert_eq!(simple_nodes.len(), 1);
        assert_eq!(simple_nodes[0].name, "plain");
    }

    #[test]
    fn test_parse_clash_subscription() {
        let yaml = r#"
proxies:
  - name: "My SOCKS5"
    type: socks5
    server: 192.168.1.1
    port: 1080
  - name: "My SS"
    type: ss
    server: 10.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "My SOCKS5");
        assert_eq!(nodes[0].protocol(), NodeProtocol::Socks5);
        assert_eq!(nodes[0].host, "192.168.1.1");
        assert_eq!(nodes[0].port, 1080);
        assert_eq!(nodes[1].name, "My SS");
        assert_eq!(nodes[1].protocol(), NodeProtocol::SS);
        assert_eq!(
            nodes[1].shadowsocks().unwrap().encryption,
            Some("aes-256-gcm".to_string())
        );
    }

    #[test]
    fn imported_tls_required_protocols_and_quic_options_are_preserved() {
        let implicit = r#"proxies:
  - name: implicit-trojan
    type: trojan
    server: trojan.example
    port: 443
    password: trojan-secret
"#;
        let node = parse_clash_subscription(implicit, None).unwrap().remove(0);
        assert!(node.trojan().unwrap().tls.enabled);
        assert!(
            parse_clash_subscription(
                &implicit.replace(
                    "password: trojan-secret",
                    "password: trojan-secret\n    tls: false"
                ),
                None
            )
            .is_err()
        );

        let yaml = r#"proxies:
  - name: hy2
    type: hysteria2
    server: hy2.example
    port: 443
    password: hy2-secret
    obfs: salamander
    obfs-password: obfs-secret
    up: 100 Mbps
    down-speed: 50 Mbps
    ports: ["4000:5000", 6000]
    hop-interval: 7s
    initial-stream-receive-window: 1234
    initial-conn-receive-window: 5678
    disable-mtu-discovery: true
    mtu: 1400
  - name: tuic
    type: tuic
    server: tuic.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    password: tuic-secret
    congestion-controller: bbr
    alpn: [h3, hq-29]
    initial-stream-receive-window: 2345
    initial-conn-receive-window: 6789
    mtu: 1450
  - name: anytls
    type: anytls
    server: anytls.example
    port: 443
    password: anytls-secret
    min-idle-session: 4
    idle-session-check-interval: 30s
    idle-session-timeout: 1m
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        let hy2 = nodes[0].hysteria2().unwrap();
        assert_eq!(hy2.obfs.as_deref(), Some("obfs-secret"));
        assert_eq!(hy2.up_mbps, Some(100));
        assert_eq!(hy2.down_mbps, Some(50));
        assert_eq!(hy2.port_hopping.as_deref(), Some("4000-5000,6000"));
        assert_eq!(hy2.hop_interval, Some(7));
        assert_eq!(hy2.init_stream_recv_window, Some(1234));
        assert_eq!(hy2.init_conn_recv_window, Some(5678));
        assert_eq!(hy2.quic.mtu, Some(1400));
        assert!(hy2.quic.tls.enabled);
        let tuic = nodes[1].tuic().unwrap();
        assert_eq!(tuic.congestion.as_deref(), Some("bbr"));
        assert_eq!(tuic.alpn.as_deref(), Some("h3,hq-29"));
        assert_eq!(tuic.init_stream_recv_window, Some(2345));
        assert_eq!(tuic.init_conn_recv_window, Some(6789));
        assert_eq!(tuic.quic.mtu, Some(1450));
        assert!(tuic.quic.tls.enabled);
        let anytls = nodes[2].anytls().unwrap();
        assert_eq!(anytls.min_idle_session, Some(4));
        assert_eq!(anytls.idle_session_check_interval, Some(30));
        assert_eq!(anytls.idle_session_timeout, Some(60));
        assert!(anytls.tls.enabled);
    }
    #[test]
    fn test_parse_clash_vless_nested_fields() {
        let subscription_id = uuid::Uuid::new_v4();
        let yaml = r#"
proxies:
  - name: reality-vision
    type: vless
    server: reality.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: legacy-password
    servername: mask.example
    sni: ignored.example
    flow: xtls-rprx-vision
    network: tcp
    client-fingerprint: chrome
    reality-opts:
      public-key: jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc
      short-id: a1b2c3d4
  - name: nested-ws
    type: vless
    server: ws.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    encryption: mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    servername: tls.example
    network: ws
    ws-path: /flat
    ws-host: flat.example
    ws-opts:
      path: /nested
      headers:
        hOsT: websocket.example
  - name: nested-grpc
    type: vless
    server: grpc.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    tls: true
    network: grpc
    grpc-service: flat-service
    grpc-opts:
      grpc-service-name: nested-service
  - name: missing-uuid
    type: vless
    server: plain.example
    port: 80
  - name: incomplete-reality
    type: vless
    server: invalid.example
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    reality-opts:
      short-id: abcd
"#;

        let nodes = parse_clash_subscription(yaml, Some(subscription_id)).unwrap();
        assert_eq!(nodes.len(), 3);

        let reality = &nodes[0];
        assert_eq!(reality.protocol(), NodeProtocol::VLess);
        let reality_config = reality.vless().unwrap();
        assert_eq!(
            reality_config.uuid.as_deref(),
            Some("b831381d-6324-4d53-ad4f-8cda48b30811")
        );
        assert_eq!(reality_config.tls.sni.as_deref(), Some("mask.example"));
        assert_eq!(reality_config.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(reality_config.transport.transport, "tcp");
        assert!(reality_config.tls.enabled);
        assert_eq!(
            reality_config.tls.reality_public_key.as_deref(),
            Some("jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc")
        );
        assert_eq!(
            reality_config.tls.reality_short_id.as_deref(),
            Some("a1b2c3d4")
        );
        assert_eq!(reality_config.tls.reality_spider_x.as_deref(), Some("/"));

        let ws = nodes[1].vless().unwrap();
        assert_eq!(ws.tls.sni.as_deref(), Some("tls.example"));
        assert_eq!(
            ws.encryption.as_deref(),
            Some("mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
        assert_eq!(ws.transport.transport, "ws");
        assert_eq!(ws.transport.ws_path.as_deref(), Some("/nested"));
        assert_eq!(ws.transport.ws_host.as_deref(), Some("websocket.example"));

        let grpc = nodes[2].vless().unwrap();
        assert_eq!(grpc.transport.transport, "grpc");
        assert_eq!(
            grpc.transport.grpc_service.as_deref(),
            Some("nested-service")
        );

        for node in &nodes {
            assert_eq!(node.subscription_id, Some(subscription_id));
            assert_eq!(node.id, node.derive_id());
        }
    }

    #[test]
    fn test_parse_clash_vless_modes() {
        let yaml = r#"
proxies:
  - name: h2-default
    type: vless
    server: h2.example
    port: 443
    uuid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
    smux:
      enabled: true
      padding: false
  - name: h2-padded
    type: vless
    server: padded.example
    port: 443
    uuid: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
    multiplex:
      enabled: true
      protocol: h2mux
      padding: true
  - name: uot-default
    type: vless
    server: uot-default.example
    port: 443
    uuid: cccccccc-cccc-4ccc-8ccc-cccccccccccc
    udp-over-tcp: true
  - name: uot-v2
    type: vless
    server: uot-v2.example
    port: 443
    uuid: dddddddd-dddd-4ddd-8ddd-dddddddddddd
    udp_over_tcp:
      enabled: true
      version: 2
  - name: legacy
    type: vless
    server: legacy.example
    port: 443
    uuid: eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee
    smux:
      enabled: false
  - name: xudp
    type: vless
    server: xudp.example
    port: 443
    uuid: ffffffff-ffff-4fff-8fff-ffffffffffff
    packet-encoding: xudp
    flow: xtls-rprx-vision
    tls: true
"#;

        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(nodes.len(), 6);
        assert_eq!(
            nodes[0].vless().unwrap().mode,
            honk_config::node::WireMode::H2mux
        );
        assert_eq!(
            nodes[1].vless().unwrap().mode,
            honk_config::node::WireMode::H2muxPadded
        );
        assert_eq!(
            nodes[2].vless().unwrap().mode,
            honk_config::node::WireMode::UotV2
        );
        assert_eq!(
            nodes[3].vless().unwrap().mode,
            honk_config::node::WireMode::UotV2
        );
        assert_eq!(
            nodes[4].vless().unwrap().mode,
            honk_config::node::WireMode::Legacy
        );
        assert_eq!(
            nodes[5].vless().unwrap().mode,
            honk_config::node::WireMode::Xudp
        );
        assert_eq!(
            nodes[5].vless().unwrap().flow.as_deref(),
            Some("xtls-rprx-vision")
        );
    }

    #[test]
    fn test_external_vless_mode_representations() {
        use honk_config::node::WireMode;

        for (options, expected) in [
            ("{}", WireMode::Legacy),
            ("packet-encoding: ''", WireMode::Legacy),
            ("packet_encoding: xudp", WireMode::Xudp),
            ("xudp: true", WireMode::Xudp),
            ("xudp: false", WireMode::Legacy),
            ("udp: true\nxudp: true", WireMode::Xudp),
            ("udp: true", WireMode::Xudp),
            ("udp: true\npacket-encoding: ''", WireMode::Xudp),
            (
                "multiplex: { enabled: true, protocol: '', padding: false }",
                WireMode::H2mux,
            ),
            (
                "multiplex: { enabled: true, padding: true }",
                WireMode::H2muxPadded,
            ),
        ] {
            let value: serde_yaml::Value = serde_yaml::from_str(options).unwrap();
            assert_eq!(
                parse_vless_external_mode(value.as_mapping().unwrap()).unwrap(),
                expected,
                "{options}"
            );
        }
    }

    #[test]
    fn clash_vless_udp_defaults_to_xudp() {
        let yaml = r#"proxies:
  - name: ordinary
    type: vless
    server: vless.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    udp: true
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(
            nodes[0].vless().unwrap().mode,
            honk_config::node::WireMode::Xudp
        );
    }

    #[test]
    fn test_rejects_ambiguous_external_vless_modes() {
        for options in [
            "smux: { enabled: true }",
            "multiplex: { enabled: true, protocol: '' }",
            "smux: { enabled: true, protocol: smux }",
            "smux: { enabled: true, protocol: yamux }",
            "udp-over-tcp: { enabled: true, version: 1 }",
            "packet-encoding: packetaddr",
            "packet-encoding: mux-cool",
            "packet-encoding: unsupported",
            "packet-addr: true",
            "mux: true",
            "mux: { enabled: true }",
            "packet-encoding: xudp\nxudp: true",
            "packet-encoding: xudp\npacket_encoding: xudp",
            "packet-encoding: xudp\nsmux: { enabled: true }",
            "xudp: true\nudp-over-tcp: true",
            "smux: { enabled: true, only-tcp: true }",
            "smux: { enabled: true, brutal: { enabled: true } }",
            "smux: { enabled: true, brutal-opts: { enabled: true, up: 100 Mbps } }",
            "smux: { enabled: true, max-connections: 2 }",
            "smux: { enabled: true, min-streams: 1 }",
            "smux: { enabled: true, max-streams: 128 }",
            "smux: { enabled: true }\nudp-over-tcp: true",
            "udp: false\nxudp: true",
        ] {
            let value: serde_yaml::Value = serde_yaml::from_str(options).unwrap();
            let mapping = value.as_mapping().unwrap();
            assert!(
                parse_vless_external_mode(mapping).is_err(),
                "unsupported options must fail: {options}"
            );
        }
    }

    #[test]
    fn test_clash_import_skips_unsupported_vless_mode() {
        let yaml = r#"
proxies:
  - name: unsupported
    type: vless
    server: bad.example
    port: 443
    uuid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
    packet-encoding: packetaddr
  - name: unsupported-flow
    type: vless
    server: flow.example
    port: 443
    uuid: cccccccc-cccc-4ccc-8ccc-cccccccccccc
    flow: xtls-rprx-vision
    tls: true
    smux:
      enabled: true
  - name: unsupported-encryption
    type: vless
    server: encryption.example
    port: 443
    uuid: dddddddd-dddd-4ddd-8ddd-dddddddddddd
    encryption: mlkem768x25519plus.native.1rtt.key
    udp-over-tcp: true
  - name: valid
    type: vless
    server: good.example
    port: 443
    uuid: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
    udp-over-tcp: true
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "valid");
    }

    #[test]
    fn test_parse_clash_skips_removed_protocols() {
        // ssr/http/trojan-go support was removed: subscription entries are
        // skipped with a warning instead of failing the whole fetch.
        let yaml = r#"
proxies:
  - name: "SSR node"
    type: ssr
    server: 10.0.0.2
    port: 8388
  - name: "HTTP node"
    type: http
    server: 10.0.0.3
    port: 8080
  - name: "Trojan-Go node"
    type: trojan-go
    server: 10.0.0.4
    port: 443
  - name: "OK"
    type: socks5
    server: 10.0.0.1
    port: 1080
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "OK");
    }

    #[test]
    fn test_parse_clash_no_proxies() {
        let yaml = r#"
port: 7890
not-proxies: []
"#;
        let result = parse_clash_subscription(yaml, None);
        assert!(result.is_err());
    }
    #[test]
    fn subscription_user_agent_defaults_and_allows_override() {
        let mut sub = Subscription::default();
        assert_eq!(
            effective_subscription_user_agent(&sub),
            DEFAULT_SUBSCRIPTION_USER_AGENT
        );

        sub.user_agent = Some("provider/1.0".into());
        assert_eq!(effective_subscription_user_agent(&sub), "provider/1.0");

        sub.user_agent = Some(String::new());
        assert_eq!(
            effective_subscription_user_agent(&sub),
            DEFAULT_SUBSCRIPTION_USER_AGENT
        );
    }

    #[tokio::test]
    async fn configured_subscription_user_agent_reaches_fetch_request() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 256];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let size = stream.read(&mut chunk).await.unwrap();
                assert!(size > 0);
                request.extend_from_slice(&chunk[..size]);
            }
            assert!(String::from_utf8_lossy(&request).lines().any(|line| {
                line.trim_end_matches('\r')
                    .eq_ignore_ascii_case("user-agent: provider/2.0")
            }));
            let body = "socks5://127.0.0.1:1080#node";
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let config = honk_config::parser::parse_dae_config(&format!(
            "subscription {{\nprovider: {{\nurl: 'http://{address}/sub'\nua: 'provider/2.0'\ninterval: 0\n}}\n}}"
        ))
        .unwrap();

        let nodes = SubscriptionManager::new()
            .unwrap()
            .fetch(&config.subscriptions[0])
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn subscription_cache_identity_is_stable_with_default_user_agent() {
        let mut sub = Subscription {
            url: "https://example.test/subscription".into(),
            ..Subscription::default()
        };
        let unset = subscription_filename(&sub);
        sub.user_agent = Some(String::new());
        assert_eq!(subscription_filename(&sub), unset);
        sub.user_agent = Some("provider/1.0".into());
        assert_ne!(subscription_filename(&sub), unset);
    }

    #[tokio::test]
    async fn subscription_store_loads_pre_default_user_agent_key() {
        fn pre_default_filename(sub: &Subscription) -> String {
            fn add_part(hasher: &mut Sha256, value: &[u8]) {
                hasher.update((value.len() as u64).to_be_bytes());
                hasher.update(value);
            }

            let mut hasher = Sha256::new();
            add_part(&mut hasher, sub.url.as_bytes());
            add_part(&mut hasher, b"");
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

        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::open(temp.path().join(SUBSCRIPTION_STORE_DIR)).unwrap();
        let sub = Subscription {
            name: "provider".into(),
            url: "https://example.test/subscription".into(),
            ..Subscription::default()
        };
        let content = "socks5://127.0.0.1:1080#stored";
        let old_path = store.root().join(pre_default_filename(&sub));
        write_store_file(store.root(), &old_path, content.as_bytes()).unwrap();

        let restored = store.load_nodes(&sub).await.unwrap().unwrap();
        assert_eq!(restored[0].name, "stored");

        let mut explicit_empty = sub.clone();
        explicit_empty.user_agent = Some(String::new());
        assert!(store.load_nodes(&explicit_empty).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn subscription_cache_identity_isolates_explicit_default_user_agent() {
        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::open(temp.path().join(SUBSCRIPTION_STORE_DIR)).unwrap();
        let default_sub = Subscription {
            name: "provider".into(),
            url: "https://example.test/subscription".into(),
            ..Subscription::default()
        };
        let mut explicit_default = default_sub.clone();
        explicit_default.user_agent = Some(DEFAULT_SUBSCRIPTION_USER_AGENT.into());
        assert_ne!(
            store.path_for(&default_sub),
            store.path_for(&explicit_default)
        );

        let mut with_header = default_sub.clone();
        with_header
            .headers
            .push(honk_config::subscription::SubscriptionHeader {
                key: "X-Test".into(),
                value: "1".into(),
            });
        assert_ne!(store.path_for(&default_sub), store.path_for(&with_header));

        write_store_file(
            store.root(),
            &store.path_for(&explicit_default),
            b"socks5://127.0.0.1:1080#explicit",
        )
        .unwrap();
        assert!(store.load_nodes(&default_sub).await.unwrap().is_none());
        assert!(store.load_nodes(&explicit_default).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn fetch_error_chain_redacts_subscription_url() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const SENTINEL: &str = "subscription-secret-sentinel";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::with_capacity(1024);
            let mut chunk = [0_u8; 256];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let size = stream.read(&mut chunk).await.unwrap();
                assert!(size > 0, "HTTP request ended before its headers");
                request.extend_from_slice(&chunk[..size]);
                assert!(request.len() <= 16 * 1024, "HTTP request headers too large");
            }
            let request = String::from_utf8_lossy(&request);
            let expected = format!("user-agent: {DEFAULT_SUBSCRIPTION_USER_AGENT}");
            assert!(
                request
                    .lines()
                    .any(|line| { line.trim_end_matches('\r').eq_ignore_ascii_case(&expected) })
            );
            stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let subscription = Subscription {
            name: "provider".into(),
            url: format!("http://{address}/{SENTINEL}?token={SENTINEL}"),
            ..Subscription::default()
        };

        let error = SubscriptionManager::new()
            .unwrap()
            .fetch(&subscription)
            .await
            .unwrap_err();
        server.await.unwrap();
        let chain = error
            .chain()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!chain.contains(SENTINEL));
        assert!(!format!("{error:?}").contains(SENTINEL));
    }

    #[tokio::test]
    async fn subscription_store_recovers_last_valid_fetch() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::open(temp.path().join(SUBSCRIPTION_STORE_DIR)).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let valid = "socks5://127.0.0.1:1080#stored";
        let server = tokio::spawn(async move {
            for body in [valid, "not a subscription"] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).await.unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let mut sub = Subscription {
            name: "provider".into(),
            url: format!("http://{address}/subscription"),
            ..Subscription::default()
        };
        let path = store.path_for(&sub);
        let original_id = sub.id;
        let manager = SubscriptionManager::new().unwrap();
        let fetched = manager.fetch_and_store(&sub, Some(&store)).await.unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].subscription_id, Some(original_id));
        assert!(manager.fetch_and_store(&sub, Some(&store)).await.is_err());
        server.await.unwrap();

        sub.id = uuid::Uuid::new_v4();
        sub.name = "renamed-provider".into();
        assert_eq!(store.path_for(&sub), path);
        let restored = store.load_nodes(&sub).await.unwrap().unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].name, "stored");
        assert_eq!(restored[0].subscription_id, Some(sub.id));

        let directory_mode = fs::metadata(store.root()).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        assert_eq!(fs::read_dir(store.root()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn subscription_store_skips_rejected_legacy_candidates() {
        let temp = tempfile::tempdir().unwrap();
        let preferred = temp.path().join("preferred");
        let old = temp.path().join("old");
        let cwd = temp.path().join("cwd");
        let sub = Subscription {
            url: "https://example.invalid/subscription".into(),
            ..Subscription::default()
        };
        let retained = SubscriptionStore::open(cwd.clone()).unwrap();
        retained
            .store_content(&sub, "socks5://127.0.0.1:1080#retained".into())
            .await
            .unwrap();
        fs::write(&old, "not a directory").unwrap();

        for symlink in [false, true] {
            if symlink {
                fs::remove_file(&old).unwrap();
                let target = temp.path().join("symlink-target");
                fs::create_dir(&target).unwrap();
                std::os::unix::fs::symlink(target, &old).unwrap();
            }
            let store =
                SubscriptionStore::open_with_legacy(preferred.clone(), [old.clone(), cwd.clone()])
                    .unwrap();
            let nodes = store.load_nodes(&sub).await.unwrap().unwrap();
            assert_eq!(nodes[0].name, "retained");
            assert!(!preferred.exists());
        }
    }

    #[test]
    fn subscription_store_rejects_symlink_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join(SUBSCRIPTION_STORE_DIR);
        symlink(target, &link).unwrap();
        assert!(SubscriptionStore::open(link).is_err());
    }
    #[test]
    fn clash_imports_intrinsic_udp_nodes_but_rejects_false_restrictions() {
        let yaml = r#"proxies:
  - name: ss-udp
    type: ss
    server: ss.example
    port: 8388
    cipher: aes-128-gcm
    password: secret
    udp: true
  - name: socks-udp
    type: socks5
    server: socks.example
    port: 1080
    udp: true
  - name: hy2-udp
    type: hysteria2
    server: hy2.example
    port: 443
    udp: true
  - name: tuic-udp
    type: tuic
    server: tuic.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    udp: true
  - name: juicity-udp
    type: juicity
    server: juicity.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    password: secret
    udp: true
  - name: false-restriction
    type: socks5
    server: false.example
    port: 1080
    udp: false
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(
            nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["ss-udp", "socks-udp", "hy2-udp", "tuic-udp", "juicity-udp"]
        );
    }

    #[test]
    fn clash_ignores_disabled_features_but_not_malformed_tls_pins() {
        let yaml = r#"proxies:
  - name: conflicting-aliases
    type: trojan
    server: conflict.example
    port: 443
    password: secret
    skip-cert-verify: true
    skip_cert_verify: false
  - name: tls-disabled
    type: socks5
    server: socks.example
    port: 1080
    tls: false
    flow: 0
    network: null
    encryption: ""
    plugin: null
    plugin-opts: {}
    ws-opts:
      enabled: false
  - name: mux-disabled
    type: trojan
    server: trojan.example
    port: 443
    password: secret
    tls: true
    skip-cert-verify: true
    skip_cert_verify: true
    smux:
      enabled: false
  - name: malformed-pin
    type: socks5
    server: pin.example
    port: 1080
    pin-sha256:
      enabled: false
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "tls-disabled");
        assert_eq!(nodes[1].name, "mux-disabled");
        assert!(nodes[1].trojan().unwrap().tls.skip_cert_verify);
    }

    #[test]
    fn clash_accepts_fixed_h3_alpn_and_tuic_empty_password() {
        let yaml = r#"proxies:
  - name: hy2-h3
    type: hysteria2
    server: hy2.example
    port: 443
    password: secret
    alpn: [h3]
  - name: juicity-h3
    type: juicity
    server: juicity.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    password: secret
    alpn: h3
  - name: tuic-absent-password
    type: tuic
    server: tuic.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
  - name: tuic-empty-password
    type: tuic
    server: tuic-empty.example
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    password: ""
  - name: bad-alpn
    type: hysteria2
    server: bad.example
    port: 443
    alpn: [h3, hq-29]
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(
            nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            [
                "hy2-h3",
                "juicity-h3",
                "tuic-absent-password",
                "tuic-empty-password"
            ]
        );
        assert_eq!(nodes[2].tuic().unwrap().password, None);
        assert_eq!(nodes[3].tuic().unwrap().password.as_deref(), Some(""));
    }

    #[test]
    fn clash_restores_fallback_names_and_lazy_ws_host_precedence() {
        let yaml = r#"proxies:
  - type: socks5
    server: first.example
    port: 1080
  - name: ""
    type: socks5
    server: second.example
    port: 1081
  - name: nested-host
    type: vless
    server: ws.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    network: ws
    ws-opts:
      headers:
        Host: nested.example
    ws-headers: [ignored-lower-priority-value]
    ws-host:
      ignored: malformed
  - name: ordered-fallback
    type: vless
    server: fallback.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    network: ws
    ws-headers: headers.example
    ws-host: host.example
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(nodes[0].name, "socks5-first.example:1080");
        assert_eq!(nodes[1].name, "socks5-second.example:1081");
        assert_eq!(
            nodes[2].vless().unwrap().transport.ws_host.as_deref(),
            Some("nested.example")
        );
        assert_eq!(
            nodes[3].vless().unwrap().transport.ws_host.as_deref(),
            Some("headers.example")
        );
    }

    #[test]
    fn clash_rejects_legacy_vless_udp_and_nondefault_juicity_windows() {
        let yaml = r#"proxies:
  - name: legacy-udp
    type: vless
    server: legacy.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    udp: true
    xudp: false
  - name: disabled-packet-udp
    type: vless
    server: packet.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    udp: true
    packet-encoding: none
  - name: disabled-mux
    type: vless
    server: mux.example
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    udp: true
    smux:
      enabled: false
  - name: default-window
    type: juicity
    server: juic-good.example
    port: 443
    uuid: 44444444-4444-4444-8444-444444444444
    password: secret
    initial-stream-receive-window: 8388608
    initial-conn-receive-window: "8388608"
    mtu: 1400
  - name: custom-window
    type: juicity
    server: juic-bad.example
    port: 443
    uuid: 55555555-5555-4555-8555-555555555555
    password: secret
    initial-stream-receive-window: 1234
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "disabled-mux");
        assert_eq!(
            nodes[0].vless().unwrap().mode,
            honk_config::node::WireMode::Xudp
        );
        assert_eq!(nodes[1].name, "default-window");
        assert_eq!(nodes[1].juicity().unwrap().quic.mtu, Some(1400));
    }
}
