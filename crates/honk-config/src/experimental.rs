use serde::{Deserialize, Serialize};

/// Clash-compatible REST API server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClashApiConfig {
    /// Listen address for the REST API (e.g. "0.0.0.0:9999").
    /// API is disabled when empty.
    #[serde(default)]
    pub external_controller: String,
    /// Path to external UI static files (e.g. "zashboard").
    #[serde(default)]
    pub external_ui: String,
    /// ZIP download URL used when the external UI directory is empty.
    /// An empty value uses the built-in zashboard URL.
    #[serde(default)]
    pub external_ui_download_url: String,
    /// Node or group tag used to download the external UI.
    /// An empty value follows the normal traffic routing decision.
    #[serde(default)]
    pub external_ui_download_detour: String,
    /// Bearer token secret for API authentication.
    /// If empty, authentication is bypassed.
    #[serde(default)]
    pub secret: String,
    /// Default clash mode: "Rule", "Global", "Direct".
    #[serde(default = "default_clash_mode")]
    pub default_mode: String,
}

fn default_clash_mode() -> String {
    "Rule".to_string()
}

impl Default for ClashApiConfig {
    fn default() -> Self {
        Self {
            external_controller: String::new(),
            external_ui: String::new(),
            external_ui_download_url: String::new(),
            external_ui_download_detour: String::new(),
            secret: String::new(),
            default_mode: "Rule".to_string(),
        }
    }
}

/// Persistence of runtime state (mode/selection, delays, DNS cache) in the
/// state database.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheFileConfig {
    /// Unset keeps Selector choices and delay samples; `true` also keeps the
    /// Clash mode, the Clash GLOBAL selection and, with `store_dns`, DNS
    /// answers; `false` keeps nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Store DNS cache answers across restarts.
    #[serde(default)]
    pub store_dns: bool,
    /// Removed from the active schema; read once to find a legacy `cache.db`.
    #[serde(rename = "path", default, skip_serializing)]
    pub(crate) legacy_path: Option<String>,
    /// Removed from the active schema; read once to select the imported key prefix.
    #[serde(rename = "cache_id", default, skip_serializing)]
    pub(crate) legacy_cache_id: Option<String>,
    /// Removed from the active schema; it never had an effect.
    #[serde(rename = "store_fakeip", default, skip_serializing)]
    pub(crate) legacy_store_fakeip: Option<bool>,
}

impl CacheFileConfig {
    /// Selector choices and delay samples, kept unless `enabled: false`, as
    /// mihomo's `store-selected` defaults on.
    pub fn stores_selections(&self) -> bool {
        self.enabled != Some(false)
    }

    /// The Clash mode and GLOBAL selection stay opt-in, as sing-box's
    /// `cache_file` defaults off: a cached mode would override `default_mode`.
    pub fn stores_mode(&self) -> bool {
        self.enabled == Some(true)
    }

    pub fn stores_dns(&self) -> bool {
        self.enabled == Some(true) && self.store_dns
    }

    /// `(path, cache_id)` as written, for the one-time `cache.db` import.
    pub fn legacy_cache_file(&self) -> (Option<&str>, Option<&str>) {
        (self.legacy_path.as_deref(), self.legacy_cache_id.as_deref())
    }

    pub(crate) fn legacy_keys(&self) -> impl Iterator<Item = &'static str> {
        [
            ("path", self.legacy_path.is_some()),
            ("cache_id", self.legacy_cache_id.is_some()),
            ("store_fakeip", self.legacy_store_fakeip.is_some()),
        ]
        .into_iter()
        .filter_map(|(key, present)| present.then_some(key))
    }
}

/// Independent, opt-in native HTTP API. All settings require a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NativeApiConfig {
    pub enabled: bool,
    pub listen: String,
    pub secret: String,
    /// Administrator login with a username and password instead of a bearer secret; restart-required.
    pub password_auth: bool,
    pub allow_anonymous_loopback: bool,
    pub allow_origins: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub ui: String,
    pub record_flows: bool,
    pub record_traffic: bool,
    pub record_memory: bool,
    pub record_logs: bool,
    pub record_dns_log: bool,
    pub config_write: bool,
    pub geosite_download_url: String,
    pub geoip_download_url: String,
    /// How geodata downloads leave: `direct`, `routing` or a group name.
    /// Empty follows routing, like `external_ui_download_detour`, unless a
    /// route is stored.
    pub geodata_download_detour: String,
}

impl Default for NativeApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:9527".into(),
            secret: String::new(),
            password_auth: false,
            allow_anonymous_loopback: false,
            allow_origins: Vec::new(),
            allowed_hosts: Vec::new(),
            ui: String::new(),
            record_flows: true,
            record_traffic: true,
            record_memory: true,
            record_logs: true,
            record_dns_log: true,
            config_write: false,
            geosite_download_url: String::new(),
            geoip_download_url: String::new(),
            geodata_download_detour: String::new(),
        }
    }
}

impl NativeApiConfig {
    /// A bearer secret or password login protects the listener: administration may be enabled.
    pub fn credentialed(&self) -> bool {
        !self.secret.is_empty() || self.password_auth
    }

    pub(crate) fn validate_detailed(
        &self,
        source: &crate::diagnostic::SourceRef,
    ) -> Result<(), crate::error::DetailedConfigError> {
        let invalid = |field, message| {
            crate::error::DetailedConfigError::new(
                crate::error::ErrorCategory::Validation,
                "invalid-config-value",
                source.clone(),
                crate::diagnostic::SettingPath::new("experimental")
                    .field("native_api")
                    .field(field),
                message,
            )
        };
        if !self.secret.is_empty() && !valid_native_bearer_token(&self.secret) {
            return Err(invalid(
                "secret",
                "native API secret must be visible ASCII without commas or whitespace",
            ));
        }
        if self.config_write && !self.credentialed() {
            return Err(invalid(
                "secret",
                "configuration administration requires a bearer secret or password login",
            ));
        }
        if self.password_auth && !self.secret.is_empty() {
            return Err(invalid(
                "password_auth",
                "password login requires an empty secret; a configured secret selects token mode",
            ));
        }
        if self.password_auth && self.allow_anonymous_loopback {
            return Err(invalid(
                "password_auth",
                "password login cannot be combined with anonymous loopback",
            ));
        }
        for (field, value) in [
            ("geosite_download_url", &self.geosite_download_url),
            ("geoip_download_url", &self.geoip_download_url),
        ] {
            if !value.is_empty() && parse_geodata_url(value).is_none() {
                return Err(invalid(
                    field,
                    "geodata source requires a credential-free HTTP(S) URL without a fragment",
                ));
            }
            if value.len() > MAX_GEODATA_URL_BYTES {
                return Err(invalid(
                    field,
                    "geodata source URL must not exceed 4096 bytes",
                ));
            }
        }
        if self.enabled {
            let listen = self
                .listen
                .parse::<std::net::SocketAddr>()
                .ok()
                .filter(|addr| addr.port() != 0)
                .ok_or_else(|| {
                    invalid(
                        "listen",
                        "native API requires a numeric IP and nonzero port",
                    )
                })?;
            if !self.credentialed() && !(self.allow_anonymous_loopback && listen.ip().is_loopback())
            {
                return Err(invalid(
                    "secret",
                    "native API requires a secret, password login, or explicitly anonymous loopback",
                ));
            }
        }
        if self
            .allowed_hosts
            .iter()
            .any(|value| parse_native_authority(value, 80).is_none())
        {
            return Err(invalid(
                "allowed_hosts",
                "expected explicit host authorities without URLs or wildcards",
            ));
        }
        if self
            .allow_origins
            .iter()
            .any(|value| parse_native_origin(value).is_none())
        {
            return Err(invalid(
                "allow_origins",
                "expected explicit HTTP origins without paths or credentials",
            ));
        }
        Ok(())
    }
}

/// The longest geodata source URL the configuration or the state db accepts.
pub const MAX_GEODATA_URL_BYTES: usize = 4096;

/// Parse an administrator-configured direct geodata source without credentials.
pub fn parse_geodata_url(value: &str) -> Option<url::Url> {
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains('\\')
    {
        return None;
    }
    let (scheme, rest) = value.split_once("://")?;
    if !matches!(scheme, "http" | "https") || rest.split(['/', '?', '#']).next()?.contains('@') {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    (url.has_host()
        && url.port_or_known_default()? != 0
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

/// Credential syntax shared by configuration admission and HTTP authentication.
pub fn valid_native_bearer_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b',')
}

/// Normalize an explicit HTTP authority without DNS resolution or URL rewriting.
pub fn parse_native_authority(value: &str, default_port: u16) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        let ip = host.parse::<std::net::Ipv6Addr>().ok()?;
        let port = if suffix.is_empty() {
            default_port
        } else {
            native_port(suffix.strip_prefix(':')?)?
        };
        return Some((ip.to_string(), port));
    } else if let Some((host, port)) = value.split_once(':') {
        (host, native_port(port)?)
    } else {
        (value, default_port)
    };
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Some((ip.to_string(), port));
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

fn native_port(value: &str) -> Option<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok().filter(|port| *port != 0)
}

/// Normalize a serialized HTTP origin; paths, credentials and opaque origins are invalid.
pub fn parse_native_origin(value: &str) -> Option<(String, String, u16)> {
    let (scheme, authority) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let (host, port) = parse_native_authority(authority, default_port)?;
    Some((scheme, host, port))
}

/// Compatibility-only NFQUEUE settings accepted while old configurations migrate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyUdpNfqueueConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
}

/// Experimental features configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalConfig {
    #[serde(default)]
    pub clash_api: ClashApiConfig,
    #[serde(default)]
    pub cache_file: CacheFileConfig,
    #[serde(default)]
    pub native_api: NativeApiConfig,
    /// Removed from the active schema; accepted only as a migration input.
    #[serde(rename = "udp_nfqueue", default, skip_serializing)]
    pub(crate) legacy_udp_nfqueue: Option<LegacyUdpNfqueueConfig>,
}
