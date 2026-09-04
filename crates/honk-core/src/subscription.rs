//! Subscription manager for fetching and parsing proxy subscription URLs.
//!
//! Supports base64-encoded node lists (Simple format) and Clash-compatible
//! YAML subscriptions. Individual share links are parsed with the unified
//! [`Node::from_share_link`] parser from honk-config.

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

mod supervisor;

pub(crate) use supervisor::{
    SubscriptionAuthorizations, SubscriptionSupervisor, validate_subscription_ids,
};

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

fn default_store_root() -> PathBuf {
    honk_config::paths::resolve_artifact_path_with_legacy(
        SUBSCRIPTION_STORE_DIR,
        Some(Path::new(SUBSCRIPTION_STORE_DIR)),
    )
}

/// Durable raw subscription bodies keyed by their fetch identity.
#[derive(Clone, Debug)]
pub struct SubscriptionStore {
    root: Arc<PathBuf>,
}

impl SubscriptionStore {
    /// Open the subscription store below `global.data_dir`, retaining an
    /// existing legacy `./.sub` store during the data-directory cutover.
    pub fn in_data_dir() -> anyhow::Result<Self> {
        let root = default_store_root();
        let preferred = honk_config::paths::resolve_artifact_path(SUBSCRIPTION_STORE_DIR);
        if root == preferred {
            return Self::open(root);
        }
        match Self::open(root.clone()) {
            Ok(store) => {
                tracing::warn!(
                    legacy = %root.display(),
                    preferred = %preferred.display(),
                    "using legacy subscription store; move it to the runtime data directory"
                );
                Ok(store)
            }
            Err(error) => {
                tracing::warn!(
                    legacy = %root.display(),
                    preferred = %preferred.display(),
                    %error,
                    "legacy subscription store is unusable; starting a data-directory store"
                );
                Self::open(preferred)
            }
        }
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

/// Manager for fetching and parsing proxy subscriptions.
pub struct SubscriptionManager {
    client: reqwest::Client,
}

impl SubscriptionManager {
    pub fn new() -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .dns_resolver(std::sync::Arc::new(BootstrapDnsResolve))
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
        let content = response.text().await.map_err(reqwest::Error::without_url)?;
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

fn parse_subscription_content(sub: &Subscription, content: &str) -> anyhow::Result<Vec<Node>> {
    let nodes = match sub.sub_type {
        SubscriptionType::Simple | SubscriptionType::Sip008 => {
            parse_base64_subscription(content, Some(sub.id), &sub.name)
        }
        SubscriptionType::Clash => parse_clash_subscription(content, Some(sub.id)),
        SubscriptionType::Custom => parse_base64_subscription(content, Some(sub.id), &sub.name)
            .or_else(|_| parse_clash_subscription(content, Some(sub.id))),
    }?;

    let mut seen = std::collections::HashSet::new();
    let mut had_duplicate = false;
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
                had_duplicate = true;
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
    if had_duplicate && nodes.len() == 1 {
        anyhow::bail!("subscription contains only duplicate endpoint identities");
    }
    Ok(nodes)
}

fn parse_base64_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
    subscription_tag: &str,
) -> anyhow::Result<Vec<Node>> {
    let trimmed = content.trim();

    // Many providers return a raw list of node URIs even when the subscription
    // is labelled "simple". Try base64 first, then fall back to raw lines.
    let text = match decode_base64_flexible(trimmed) {
        Ok(decoded) => String::from_utf8(decoded)?,
        Err(_) => {
            tracing::debug!(
                subscription = subscription_tag,
                category = "raw-node-list",
                "subscription content is not base64"
            );
            trimmed.to_string()
        }
    };

    let uris: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
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

    let input = input.trim();

    if let Ok(data) = base64::engine::general_purpose::STANDARD.decode(input) {
        return Ok(data);
    }

    let padded = if !input.len().is_multiple_of(4) {
        let padding = 4 - (input.len() % 4);
        let mut s = input.to_string();
        for _ in 0..padding {
            s.push('=');
        }
        s
    } else {
        input.to_string()
    };

    let data = base64::engine::general_purpose::STANDARD.decode(&padded)?;
    Ok(data)
}

fn yaml_value<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> Option<&'a serde_yaml::Value> {
    mapping.get(serde_yaml::Value::String(key.to_string()))
}

fn yaml_alias<'a>(
    mapping: &'a serde_yaml::Mapping,
    keys: &[&str],
) -> Result<Option<&'a serde_yaml::Value>, String> {
    let mut found = None;
    for key in keys {
        if let Some(value) = yaml_value(mapping, key) {
            if found.is_some() {
                return Err(format!("conflicting aliases '{}'", keys.join("/")));
            }
            found = Some(value);
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

    let packet_encoding = yaml_alias(mapping, &["packet-encoding", "packet_encoding"])?;
    let xudp = yaml_value(mapping, "xudp");
    let xudp_enabled = match (packet_encoding, xudp) {
        (Some(value), None) => {
            let encoding = value
                .as_str()
                .ok_or_else(|| "VLESS packet encoding must be a string".to_string())?
                .trim();
            match encoding {
                "" => false,
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
    if let Some(value) = yaml_alias(mapping, &["packet-addr", "packet_addr"])? {
        let enabled = value
            .as_bool()
            .ok_or_else(|| "VLESS packet-addr must be boolean".to_string())?;
        if enabled {
            return Err("unsupported VLESS packet-addr mode".into());
        }
    }
    if let Some(value) = yaml_value(mapping, "mux") {
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
    if let Some(value) = yaml_alias(mapping, &["smux", "multiplex"])? {
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
    if let Some(value) = yaml_alias(mapping, &["udp-over-tcp", "udp_over_tcp"])? {
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
    let mode = if xudp_enabled {
        WireMode::Xudp
    } else if let Some(mode) = mux_mode {
        mode
    } else if uot_enabled {
        WireMode::UotV2
    } else {
        WireMode::Legacy
    };
    match (udp, mode) {
        (Some(true), WireMode::Legacy) => {
            Err("native VLESS UDP is unsupported; specify an explicit packet mode".into())
        }
        (Some(false), mode) if mode != WireMode::Legacy => Err(format!(
            "VLESS mode '{}' enables UDP but udp is false",
            mode.as_str()
        )),
        _ => Ok(mode),
    }
}

fn parse_clash_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(content)?;
    let proxies = yaml
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| anyhow::anyhow!("no 'proxies' array found in Clash YAML"))?;
    let mut nodes = Vec::new();

    for proxy in proxies {
        let Some(mapping) = proxy.as_mapping() else {
            continue;
        };
        let get_value = |key: &str| mapping.get(serde_yaml::Value::String(key.to_string()));
        let get_str = |key: &str| {
            get_value(key)
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_string)
        };
        let get_u16 = |key: &str| {
            get_value(key)
                .and_then(serde_yaml::Value::as_u64)
                .and_then(|number| u16::try_from(number).ok())
        };
        let get_nested_str = |section: &str, key: &str| {
            get_value(section)
                .and_then(serde_yaml::Value::as_mapping)
                .and_then(|nested| nested.get(serde_yaml::Value::String(key.to_string())))
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_string)
        };

        let Some(proxy_type) = get_str("type") else {
            continue;
        };
        let protocol = match proxy_type.to_lowercase().as_str() {
            "socks5" => NodeProtocol::Socks5,
            "ss" | "shadowsocks" => NodeProtocol::SS,
            "trojan" => NodeProtocol::Trojan,
            "vmess" => NodeProtocol::VMess,
            "vless" => NodeProtocol::VLess,
            "hysteria2" | "hysteria" => NodeProtocol::Hysteria2,
            "tuic" => NodeProtocol::Tuic,
            "juicity" => NodeProtocol::Juicity,
            "anytls" => NodeProtocol::AnyTLS,
            _ => {
                tracing::warn!("skipping unsupported Clash proxy type: {}", proxy_type);
                continue;
            }
        };
        let Some(server) = get_str("server") else {
            continue;
        };
        let Some(port) = get_u16("port") else {
            continue;
        };
        let name = get_str("name").unwrap_or_else(|| format!("{proxy_type}-{server}:{port}"));
        let plugin_configured = ["plugin", "plugin-opts"].into_iter().any(|key| {
            get_value(key).is_some_and(|value| match value {
                serde_yaml::Value::Null => false,
                serde_yaml::Value::String(value) => !value.trim().is_empty(),
                serde_yaml::Value::Sequence(value) => !value.is_empty(),
                serde_yaml::Value::Mapping(value) => !value.is_empty(),
                _ => true,
            })
        });
        if plugin_configured {
            tracing::warn!(
                node = %name,
                "skipping Clash node with unsupported proxy plugin"
            );
            continue;
        }
        let address = format!("{server}:{port}");
        let vless_mode = if protocol == NodeProtocol::VLess {
            match parse_vless_external_mode(mapping) {
                Ok(mode) => mode,
                Err(error) => {
                    tracing::warn!(node = %name, reason = %error, "skipping unsupported VLESS node");
                    continue;
                }
            }
        } else {
            honk_config::node::WireMode::Legacy
        };
        let mut node = Node {
            name,
            address,
            host: server,
            port,
            outbound: OutboundConfig::from_protocol(protocol),
            ..Default::default()
        };

        let username = get_str("username");
        let password = get_str("password");
        let cipher = get_str("cipher");
        match &mut node.outbound {
            OutboundConfig::Shadowsocks(config) => {
                config.password = password;
                config.encryption = cipher;
            }
            OutboundConfig::Socks5(config) => {
                config.username = username;
                config.password = password;
            }
            OutboundConfig::Trojan(config) => config.password = password,
            OutboundConfig::Vmess(config) => {
                config.uuid = get_str("uuid").or(password);
                config.encryption = cipher;
            }
            OutboundConfig::Vless(config) => {
                config.uuid = get_str("uuid").or(password);
                config.encryption = get_str("encryption").or(cipher);
                config.flow = get_str("flow").filter(|flow| !flow.is_empty());
                config.mode = vless_mode;
            }
            OutboundConfig::Hysteria2(config) => {
                config.auth = get_str("auth").or(password);
            }
            OutboundConfig::Tuic(config) => {
                config.uuid = get_str("uuid").or(username);
                config.password = password;
            }
            OutboundConfig::Juicity(config) => {
                config.uuid = get_str("uuid").or(username);
                config.password = password;
            }
            OutboundConfig::AnyTls(config) => config.password = password,
            OutboundConfig::Direct | OutboundConfig::Block => unreachable!(),
        }

        if let Some(network) = get_str("network")
            && let Some(transport) = node.transport_mut()
        {
            transport.transport = network;
        }
        if let Some(transport) = node.transport_mut() {
            transport.ws_path = get_nested_str("ws-opts", "path").or_else(|| get_str("ws-path"));
            transport.ws_host = get_value("ws-opts")
                .and_then(serde_yaml::Value::as_mapping)
                .and_then(|options| {
                    options
                        .get(serde_yaml::Value::String("headers".to_string()))
                        .and_then(serde_yaml::Value::as_mapping)
                })
                .and_then(|headers| {
                    headers.iter().find_map(|(key, value)| {
                        key.as_str()
                            .filter(|key| key.eq_ignore_ascii_case("host"))
                            .and_then(|_| value.as_str())
                            .map(str::to_string)
                    })
                })
                .or_else(|| get_str("ws-headers"))
                .or_else(|| get_str("ws-host"));
            transport.grpc_service = get_nested_str("grpc-opts", "grpc-service-name")
                .or_else(|| get_str("grpc-service"));
        }

        if let Some(tls_options) = node.tls_mut() {
            if let Some(enabled) = get_value("tls").and_then(serde_yaml::Value::as_bool) {
                tls_options.enabled = enabled;
            }
            tls_options.sni = get_str("servername").or_else(|| get_str("sni"));
            if let Some(skip) = get_value("skip-cert-verify").and_then(serde_yaml::Value::as_bool) {
                tls_options.skip_cert_verify = skip;
            }
        }

        if protocol == NodeProtocol::VLess
            && let Some(reality_value) = get_value("reality-opts")
        {
            let Some(reality) = reality_value.as_mapping() else {
                tracing::warn!("skipping VLESS Clash node with incomplete reality-opts");
                continue;
            };
            let nested = |key: &str| {
                reality
                    .get(serde_yaml::Value::String(key.to_string()))
                    .and_then(serde_yaml::Value::as_str)
                    .map(str::to_string)
            };
            let Some(public_key) = nested("public-key").filter(|value| !value.trim().is_empty())
            else {
                tracing::warn!("skipping VLESS Clash node with incomplete reality-opts");
                continue;
            };
            let tls = &mut node.vless_mut().unwrap().tls;
            tls.reality_public_key = Some(public_key);
            tls.reality_short_id = nested("short-id");
            tls.reality_spider_x = Some(
                nested("spider-x")
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "/".to_string()),
            );
            tls.enabled = true;
        }
        if let Err(error) = node.validate_protocol() {
            tracing::warn!(node = %node.name, reason = %error, "skipping unsupported VLESS node");
            continue;
        }

        node.subscription_id = subscription_id;
        node.id = node.derive_id();
        nodes.push(node);
    }

    if nodes.is_empty() {
        anyhow::bail!("no supported proxies found in Clash subscription");
    }
    Ok(nodes)
}

/// Parse a single node share link via the unified parser in honk-config.
fn parse_node_uri(uri: &str) -> anyhow::Result<Node> {
    Node::from_share_link(uri).map_err(anyhow::Error::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

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
    fn test_parse_subscription_rejects_duplicate_only_simple_payload() {
        let sub = Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        };
        let uri = "socks5://127.0.0.1:1080#same";
        let content = format!("{uri}\n{uri}");
        let error = parse_subscription_content(&sub, &content).unwrap_err();
        assert!(error.to_string().contains("duplicate endpoint identities"));
    }

    #[test]
    fn test_parse_subscription_keeps_unique_nodes_with_duplicates() {
        let sub = Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        };
        let content = concat!(
            "socks5://127.0.0.1:1080#same\n",
            "socks5://127.0.0.1:1080#same-again\n",
            "socks5://127.0.0.1:1081#unique"
        );
        let nodes = parse_subscription_content(&sub, content).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "same");
        assert_eq!(nodes[1].name, "unique");
    }

    #[test]
    fn test_parse_subscription_rejects_duplicate_only_clash_payload() {
        let sub = Subscription {
            sub_type: SubscriptionType::Clash,
            ..Default::default()
        };
        let yaml = r#"proxies:
  - name: first
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: second
    type: socks5
    server: 127.0.0.1
    port: 1080
"#;
        let error = parse_subscription_content(&sub, yaml).unwrap_err();
        assert!(error.to_string().contains("duplicate endpoint identities"));
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
        assert_eq!(nodes.len(), 4);

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

        assert_eq!(nodes[3].vless().unwrap().uuid, None);
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
            ("udp: false", WireMode::Legacy),
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
            "udp: true",
            "udp: true\npacket-encoding: ''",
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
}
