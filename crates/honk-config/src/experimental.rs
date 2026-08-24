use serde::{Deserialize, Serialize};

/// Clash-compatible REST API server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashApiConfig {
    /// Listen address for the REST API (e.g. "0.0.0.0:9999").
    /// API is disabled when empty.
    #[serde(default)]
    pub external_controller: String,
    /// Path to external UI static files (e.g. "zashboard").
    #[serde(default)]
    pub external_ui: String,
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
            secret: String::new(),
            default_mode: "Rule".to_string(),
        }
    }
}

/// Cache file for persistent state (FakeIP, DNS cache, mode/selection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheFileConfig {
    /// Enable cache file persistence.
    #[serde(default)]
    pub enabled: bool,
    /// Cache database path. New relative paths resolve below `global.data_dir`;
    /// an existing legacy config-directory path is retained.
    #[serde(default = "default_cache_path")]
    pub path: String,
    /// Unique identifier for this router instance.
    #[serde(default)]
    pub cache_id: String,
    /// Store FakeIP mappings across restarts.
    #[serde(default)]
    pub store_fakeip: bool,
    /// Store DNS cache answers across restarts.
    #[serde(default)]
    pub store_dns: bool,
}

fn default_cache_path() -> String {
    "cache.db".to_string()
}

impl Default for CacheFileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "cache.db".to_string(),
            cache_id: String::new(),
            store_fakeip: false,
            store_dns: false,
        }
    }
}

/// Compatibility-only NFQUEUE settings accepted while old configurations migrate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyUdpNfqueueConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
}

/// Experimental features configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalConfig {
    #[serde(default)]
    pub clash_api: ClashApiConfig,
    #[serde(default)]
    pub cache_file: CacheFileConfig,
    /// Removed from the active schema; accepted only as a migration input.
    #[serde(rename = "udp_nfqueue", default, skip_serializing)]
    pub(crate) legacy_udp_nfqueue: Option<LegacyUdpNfqueueConfig>,
}
