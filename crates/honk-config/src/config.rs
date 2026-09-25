mod diagnostics;
mod seed;
pub(crate) use seed::CONFIG_FIELDS;
pub use seed::ConfigSeed;
use seed::RawConfigSeed;

use std::ops::Range;

use crate::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SettingPath, SourceRef, finish_attempt,
    report_detailed_diagnostics,
};
use crate::error::{DetailedConfigError, ErrorCategory};
use serde::de::DeserializeSeed;
use serde::{Deserialize, Serialize};
use serde_path_to_error::{Deserializer as PathDeserializer, Segment, Track};

use crate::ConfigDiagnostic;
use crate::dns::DnsConfig;
use crate::experimental::ExperimentalConfig;
use crate::group::Group;
use crate::node::Node;
use crate::routing::RoutingConfig;
use crate::subscription::Subscription;
use crate::types::DialMode;

/// Stable identity of the built-in `direct` node across reloads and restarts.
pub const DIRECT_NODE_ID: uuid::Uuid =
    uuid::Uuid::from_u128(0x00000000_0000_4000_8000_00000000d1ec);
/// Stable identity of the built-in `block` node across reloads and restarts.
pub const BLOCK_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x00000000_0000_4000_8000_00000000b10c);

/// `preconnect_node_count` sentinel for the dae `'auto'` value: preconnect
/// `min(nodes, 8)` nodes. Kept as a `usize` sentinel so the serde formats
/// stay plain integers; `0` means disabled.
pub const PRECONNECT_NODE_COUNT_AUTO: usize = usize::MAX;

/// Main honk configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub experimental: ExperimentalConfig,
}

/// Global configuration matching dae `global { ... }` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_tproxy_port")]
    pub tproxy_port: u16,
    #[serde(default = "default_tproxy_mark")]
    pub tproxy_mark: u32,
    #[serde(default = "crate::types::default_true")]
    pub tproxy_port_protect: bool,
    #[serde(default)]
    pub pprof_port: u16,
    #[serde(default)]
    pub so_mark_from_dae: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Optional append-only operational log file. Relative paths resolve below
    /// [`GlobalConfig::data_dir`]; empty keeps file logging disabled.
    #[serde(default)]
    pub log_file: String,
    #[serde(default)]
    pub disable_waiting_network: bool,
    #[serde(default)]
    pub lan_interface: Vec<String>,
    #[serde(default)]
    pub wan_interface: Vec<String>,
    #[serde(default)]
    pub auto_config_kernel_parameter: bool,
    /// Enable held-first-packet NFQUEUE staging for ambiguous LAN-forwarded UDP.
    /// This process-scoped setting requires the real eBPF backend and a restart.
    #[serde(default = "crate::types::default_true")]
    pub nfqueue_enable: bool,
    /// Root for generated state and relative runtime-supplied assets.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// Persist successfully fetched subscription bodies below the configured
    /// runtime data directory so startup can recover without the network.
    #[serde(default = "default_store_subscribe")]
    pub store_subscribe: bool,
    #[serde(default = "default_tcp_check_urls")]
    pub tcp_check_url: Vec<String>,
    #[serde(default = "default_tcp_check_http_method")]
    pub tcp_check_http_method: String,
    #[serde(default = "default_udp_check_dns")]
    pub udp_check_dns: Vec<String>,
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,
    #[serde(default = "default_check_tolerance_ms")]
    pub check_tolerance_ms: u64,
    #[serde(default = "default_dial_mode")]
    pub dial_mode: String,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default = "default_sniffing_timeout_ms")]
    pub sniffing_timeout_ms: u64,
    #[serde(default = "default_tls_impl")]
    pub tls_implementation: String,
    #[serde(default = "default_utls_imitate")]
    pub utls_imitate: String,
    #[serde(default)]
    pub tls_fragment: bool,
    #[serde(default)]
    pub tls_fragment_length: String,
    #[serde(default)]
    pub tls_fragment_interval: String,
    #[serde(default)]
    pub mptcp: bool,
    #[serde(default)]
    pub bootstrap_resolver: String,
    #[serde(default = "default_fallback_resolver")]
    pub fallback_resolver: String,
    #[serde(default)]
    pub bandwidth_max_tx: String,
    #[serde(default)]
    pub bandwidth_max_rx: String,
    #[serde(default = "default_udphop_interval_secs")]
    pub udphop_interval_secs: u64,
    /// Timeout for TCP connect (SYN/SYN-ACK) in milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Timeout for DNS resolution in the control plane in milliseconds
    /// (used when resolving target domains for non-domain-capable proxies).
    #[serde(default = "default_dns_resolve_timeout_ms")]
    pub dns_resolve_timeout_ms: u64,
    /// Relay idle timeout: if no data flows in either direction for this
    /// many seconds, the relay is terminated. 0 disables the timeout.
    #[serde(default = "default_relay_idle_timeout_secs")]
    pub relay_idle_timeout_secs: u64,
    /// Number of proxy nodes to preconnect on startup. `0` disables the
    /// warm-up entirely; [`PRECONNECT_NODE_COUNT_AUTO`] (dae `'auto'`) picks
    /// `min(nodes, 8)`.
    #[serde(default = "default_preconnect_node_count")]
    pub preconnect_node_count: usize,
    /// Number of selected UDP nodes to warm on startup/reload. Zero strictly
    /// disables this independent warm-up path.
    #[serde(default = "default_udp_warm_node_count")]
    pub udp_warm_node_count: usize,
    /// Process-wide cap on physical proxied connects and protocol handshakes.
    /// Ready-pool hits, logical streams on warm generation transports, and
    /// built-in direct/block dials are exempt.
    #[serde(default = "default_max_concurrent_dials")]
    pub max_concurrent_dials: usize,
}

impl GlobalConfig {
    /// Process socket mark; zero retains the historical bypass mark.
    pub fn effective_so_mark(&self) -> u32 {
        if self.so_mark_from_dae == 0 {
            0x100
        } else {
            self.so_mark_from_dae
        }
    }
}

fn default_tproxy_port() -> u16 {
    12345
}

/// Host CIDRs (`addr/32`, `addr/128`) for every global-scoped address on
/// `iface`. The literal `auto` resolves through the lowest-metric IPv4
/// default route. Missing or unresolved interfaces yield an empty list.
fn interface_host_cidrs(iface: &str) -> Vec<String> {
    let iface = iface.trim();
    let owned;
    let iface = if iface.eq_ignore_ascii_case("auto") {
        owned = default_route_interface().unwrap_or_default();
        if owned.is_empty() {
            return Vec::new();
        }
        owned.as_str()
    } else {
        iface
    };
    // getifaddrs(3) — no `ip` subprocess needed. Link-local addresses
    // (v4 169.254/16, v6 fe80::/10) are excluded, matching the old
    // "not scope link" filter.
    let mut cidrs = Vec::new();
    // SAFETY: getifaddrs allocates a linked list freed by freeifaddrs;
    // all pointers are checked before dereference.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return cidrs;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
            if name == iface && !ifa.ifa_addr.is_null() {
                let family = (*ifa.ifa_addr).sa_family as i32;
                if family == libc::AF_INET {
                    // s_addr is network byte order in memory — read it in
                    // native order to get the wire bytes as-is.
                    let a = (*(ifa.ifa_addr as *const libc::sockaddr_in))
                        .sin_addr
                        .s_addr
                        .to_ne_bytes();
                    if !(a[0] == 169 && a[1] == 254) {
                        cidrs.push(format!("{}.{}.{}.{}/32", a[0], a[1], a[2], a[3]));
                    }
                } else if family == libc::AF_INET6 {
                    let a = (*(ifa.ifa_addr as *const libc::sockaddr_in6))
                        .sin6_addr
                        .s6_addr;
                    if !(a[0] == 0xfe && (a[1] & 0xc0) == 0x80) {
                        cidrs.push(format!("{}/128", std::net::Ipv6Addr::from(a)));
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    cidrs
}

/// Interface owning the lowest-metric IPv4 default route.
pub fn default_route_interface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    default_route_interface_from(&text)
}

/// Parse `/proc/net/route` and select a real destination/mask-zero route.
pub fn default_route_interface_from(text: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None;
    for line in text.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(interface) = fields.next() else {
            continue;
        };
        let Some(destination) = fields.next() else {
            continue;
        };
        let Some(metric) = fields.nth(4) else {
            continue;
        };
        let Some(mask) = fields.next() else {
            continue;
        };
        if destination != "00000000" || mask != "00000000" {
            continue;
        }
        let metric = metric.parse::<u32>().unwrap_or(u32::MAX);
        if best.as_ref().is_none_or(|(current, _)| metric < *current) {
            best = Some((metric, interface.to_string()));
        }
    }
    best.map(|(_, interface)| interface)
}

fn default_tproxy_mark() -> u32 {
    DEFAULT_TPROXY_MARK
}

/// The only valid `global.tproxy_mark`: the eBPF datapath has the mark
/// compiled in, so userspace cannot honor any other value. honk-core pins
/// this against `honk_ebpf_common::TPROXY_MARK` with a unit test.
pub const DEFAULT_TPROXY_MARK: u32 = 0x0800_0000;
fn default_log_level() -> String {
    "info".into()
}
fn default_tcp_check_urls() -> Vec<String> {
    vec!["https://www.gstatic.com/generate_204".into()]
}
fn default_tcp_check_http_method() -> String {
    "HEAD".into()
}
fn default_udp_check_dns() -> Vec<String> {
    vec![
        "dns.google:53".into(),
        "8.8.8.8".into(),
        "2001:4860:4860::8888".into(),
    ]
}
fn default_check_interval_secs() -> u64 {
    30
}
fn default_check_tolerance_ms() -> u64 {
    50
}
fn default_dial_mode() -> String {
    "domain".into()
}
fn default_sniffing_timeout_ms() -> u64 {
    30
}
fn default_tls_impl() -> String {
    "tls".into()
}
fn default_utls_imitate() -> String {
    "chrome_auto".into()
}
fn default_fallback_resolver() -> String {
    "8.8.8.8:53".into()
}
fn default_udphop_interval_secs() -> u64 {
    30
}
fn default_connect_timeout_ms() -> u64 {
    3000
}
fn default_dns_resolve_timeout_ms() -> u64 {
    2000
}
fn default_relay_idle_timeout_secs() -> u64 {
    300
}
fn default_preconnect_node_count() -> usize {
    PRECONNECT_NODE_COUNT_AUTO
}
fn default_udp_warm_node_count() -> usize {
    0
}
fn default_data_dir() -> String {
    crate::paths::DEFAULT_DATA_DIR.to_string()
}
fn default_store_subscribe() -> bool {
    true
}
fn default_max_concurrent_dials() -> usize {
    64
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            tproxy_port: default_tproxy_port(),
            tproxy_mark: default_tproxy_mark(),
            tproxy_port_protect: true,
            pprof_port: 0,
            so_mark_from_dae: 0,
            log_level: default_log_level(),
            log_file: String::new(),
            disable_waiting_network: false,
            lan_interface: vec![],
            wan_interface: vec![],
            auto_config_kernel_parameter: false,
            nfqueue_enable: true,
            data_dir: default_data_dir(),
            store_subscribe: default_store_subscribe(),
            tcp_check_url: default_tcp_check_urls(),
            tcp_check_http_method: default_tcp_check_http_method(),
            udp_check_dns: default_udp_check_dns(),
            check_interval_secs: default_check_interval_secs(),
            check_tolerance_ms: default_check_tolerance_ms(),
            dial_mode: default_dial_mode(),
            allow_insecure: false,
            sniffing_timeout_ms: default_sniffing_timeout_ms(),
            tls_implementation: default_tls_impl(),
            utls_imitate: default_utls_imitate(),
            tls_fragment: false,
            tls_fragment_length: String::new(),
            tls_fragment_interval: String::new(),
            mptcp: false,
            bootstrap_resolver: String::new(),
            fallback_resolver: default_fallback_resolver(),
            bandwidth_max_tx: String::new(),
            bandwidth_max_rx: String::new(),
            udphop_interval_secs: default_udphop_interval_secs(),
            connect_timeout_ms: default_connect_timeout_ms(),
            dns_resolve_timeout_ms: default_dns_resolve_timeout_ms(),
            relay_idle_timeout_secs: default_relay_idle_timeout_secs(),
            preconnect_node_count: default_preconnect_node_count(),
            udp_warm_node_count: default_udp_warm_node_count(),
            max_concurrent_dials: default_max_concurrent_dials(),
        }
    }
}

fn config_validation_error(
    source: &SourceRef,
    setting: SettingPath,
    code: &'static str,
    message: &'static str,
) -> DetailedConfigError {
    DetailedConfigError::new(
        ErrorCategory::Validation,
        code,
        source.clone(),
        setting,
        message,
    )
}

impl Config {
    /// The built-in `direct` node name (usable as a group member without
    /// being declared in the config).
    pub const BUILTIN_DIRECT_NODE: &'static str = "direct";
    /// The built-in `block` node name.
    pub const BUILTIN_BLOCK_NODE: &'static str = "block";

    /// Inject the built-in `direct`/`block` nodes unless the config already
    /// defines nodes with those names. Idempotent.
    ///
    /// This makes both built-ins first-class group members (Selector/urltest
    /// candidates, delay-test targets) without declaring them in the config
    /// file; their address fields are unused.
    pub fn ensure_builtin_nodes(&mut self) {
        for builtin in [Self::builtin_direct_node(), Self::builtin_block_node()] {
            if !self.nodes.iter().any(|n| n.name == builtin.name) {
                self.nodes.push(builtin);
            }
        }
    }

    /// The built-in node registered under `name`, falling back to a fresh
    /// built-in definition when [`Self::ensure_builtin_nodes`] has not run.
    /// `None` for any non-built-in name.
    pub fn builtin_node(&self, name: &str) -> Option<crate::node::Node> {
        let fresh = match name {
            Self::BUILTIN_DIRECT_NODE => Self::builtin_direct_node(),
            Self::BUILTIN_BLOCK_NODE => Self::builtin_block_node(),
            _ => return None,
        };
        Some(
            self.nodes
                .iter()
                .find(|n| n.name == name)
                .cloned()
                .unwrap_or(fresh),
        )
    }

    /// A fresh built-in `direct` node definition.
    pub fn builtin_direct_node() -> crate::node::Node {
        crate::node::Node {
            id: DIRECT_NODE_ID,
            name: Self::BUILTIN_DIRECT_NODE.to_string(),
            outbound: crate::node::OutboundConfig::Direct,
            ..Default::default()
        }
    }

    /// A fresh built-in `block` node definition.
    pub fn builtin_block_node() -> crate::node::Node {
        crate::node::Node {
            id: BLOCK_NODE_ID,
            name: Self::BUILTIN_BLOCK_NODE.to_string(),
            outbound: crate::node::OutboundConfig::Block,
            ..Default::default()
        }
    }

    /// Current host CIDRs on configured LAN/WAN interfaces, used to detect
    /// address changes rather than synthesize routing rules. Missing
    /// interfaces and an unresolved `auto` entry are omitted.
    pub fn local_direct_cidrs(&self) -> Vec<String> {
        let mut cidrs = Vec::new();
        for iface in &self.global.lan_interface {
            cidrs.extend(interface_host_cidrs(iface));
        }
        for iface in &self.global.wan_interface {
            cidrs.extend(interface_host_cidrs(iface));
        }
        cidrs.sort();
        cidrs.dedup();
        cidrs
    }

    /// Apply the removed experimental NFQUEUE setting without retaining it in
    /// the active configuration schema.
    pub(crate) fn apply_legacy_nfqueue(&mut self, canonical_present: bool) {
        let Some(legacy) = self.experimental.legacy_udp_nfqueue.take() else {
            return;
        };
        if !canonical_present {
            self.global.nfqueue_enable = legacy.enabled;
        }
    }

    pub fn from_file(path: &str) -> Result<Self, crate::ConfigError> {
        let mut diagnostics = Vec::new();
        let result = Self::from_file_with_detailed_diagnostics(path, &mut diagnostics);
        report_detailed_diagnostics(&diagnostics);
        result.map_err(DetailedConfigError::into_legacy)
    }

    /// Compatibility projection of the detailed data API; never logs.
    pub fn from_file_with_diagnostics(
        path: &str,
        diagnostics: &mut Vec<ConfigDiagnostic>,
    ) -> Result<Self, crate::ConfigError> {
        let mut detailed = Vec::new();
        let result = Self::from_file_with_detailed_diagnostics(path, &mut detailed);
        diagnostics.extend(detailed.iter().map(DetailedDiagnostic::to_legacy));
        result.map_err(DetailedConfigError::into_legacy)
    }

    /// Load with failure-preserving diagnostics. Each format owns a separate source table.
    pub fn from_file_with_detailed_diagnostics(
        path: &str,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Self, DetailedConfigError> {
        let result = Self::load_file_attempt(path, diagnostics);
        finish_attempt(result, diagnostics)
    }

    fn load_file_attempt(
        path: &str,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Self, DetailedConfigError> {
        let source = DiagnosticSources::new(Some(path.into())).root();
        let content = std::fs::read_to_string(path)
            .map_err(|error| DetailedConfigError::from_legacy(error.into(), source.clone()))?;
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase);
        let start = diagnostics.len();
        let formats: &[ConfigFormat] = match ext.as_deref() {
            Some("json") => &[ConfigFormat::Json, ConfigFormat::Toml, ConfigFormat::Yaml],
            Some("yaml" | "yml") => &[ConfigFormat::Yaml, ConfigFormat::Toml, ConfigFormat::Json],
            Some("toml") => &[ConfigFormat::Toml, ConfigFormat::Yaml, ConfigFormat::Json],
            _ => {
                let mut semantic = false;
                let result =
                    crate::parser::parse_dae_config_file_attempt(path, diagnostics, &mut semantic);
                match result {
                    Ok(mut config) => {
                        config.derive_node_ids();
                        return Ok(config);
                    }
                    Err(error) => {
                        let stop = matches!(
                            error.category,
                            ErrorCategory::Include | ErrorCategory::UnsupportedPolicy
                        );
                        let mut error = error;
                        // File-mode legacy callers historically received the last Parse error.
                        if !stop && semantic {
                            error.category = ErrorCategory::Parse;
                        }
                        if stop || semantic {
                            return Err(error);
                        }
                        let mut diagnostic = *error.diagnostic;
                        diagnostic.terminal = false;
                        diagnostics.push(diagnostic);
                    }
                }
                &[ConfigFormat::Toml, ConfigFormat::Yaml, ConfigFormat::Json]
            }
        };
        for (index, format) in formats.iter().enumerate() {
            let attempt_start = diagnostics.len();
            let source = DiagnosticSources::new(Some(path.into())).root();
            match parse_structured(&content, *format, diagnostics, source) {
                Ok(mut config) => {
                    diagnostics.drain(start..attempt_start);
                    config.derive_node_ids();
                    return Ok(config);
                }
                Err(error) => {
                    if index + 1 == formats.len() {
                        if error.diagnostic.entry_index.is_none()
                            && let Some(cause_index) =
                                diagnostics[start..].iter().position(|diagnostic| {
                                    diagnostic.severity == crate::diagnostic::Severity::Error
                                        && diagnostic.entry_index.is_some()
                                })
                        {
                            let mut cause = diagnostics.remove(start + cause_index);
                            cause.terminal = true;
                            let mut last_attempt = *error.diagnostic;
                            last_attempt.terminal = false;
                            diagnostics.push(last_attempt);
                            return Err(DetailedConfigError {
                                category: error.category,
                                diagnostic: Box::new(cause),
                            });
                        }
                        return Err(error);
                    }
                    let mut diagnostic = *error.diagnostic;
                    diagnostic.terminal = false;
                    diagnostics.push(diagnostic);
                }
            }
        }
        unreachable!("format list is nonempty")
    }

    pub fn to_file(&self, path: &str) -> Result<(), crate::ConfigError> {
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);

        let content = match ext.as_deref() {
            Some("dae") => {
                return Err(crate::ConfigError::Serialization(
                    "refusing to rewrite .dae configuration: source formatting, comments, and includes cannot be preserved; edit the dae source directly or use .toml/.yaml/.json"
                        .into(),
                ));
            }
            Some("json") => self.to_json_string()?,
            Some("yaml") | Some("yml") => serde_yaml::to_string(self)
                .map_err(|e| crate::ConfigError::Serialization(e.to_string()))?,
            _ => toml::to_string_pretty(self)
                .map_err(|e| crate::ConfigError::Serialization(e.to_string()))?,
        };
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Serialize the configuration to a pretty-printed JSON string.
    pub fn to_json_string(&self) -> Result<String, crate::ConfigError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::ConfigError::Serialization(e.to_string()))
    }

    /// Parse a configuration from a JSON string.
    pub fn from_json_str(s: &str) -> Result<Self, crate::ConfigError> {
        let mut diagnostics = Vec::new();
        let result = Self::from_json_str_with_detailed_diagnostics(s, &mut diagnostics);
        report_detailed_diagnostics(&diagnostics);
        result.map_err(DetailedConfigError::into_legacy)
    }

    pub fn from_json_str_with_detailed_diagnostics(
        s: &str,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Self, DetailedConfigError> {
        let result = parse_structured(
            s,
            ConfigFormat::Json,
            diagnostics,
            DiagnosticSources::new(None).root(),
        )
        .map(|mut config| {
            config.derive_node_ids();
            config
        });
        finish_attempt(result, diagnostics)
    }

    /// Re-derive every node's content-based ID ([`Node::derive_id`]) after
    /// load. Stored/serde-default IDs are discarded so identity always
    /// reflects the current content; the built-in direct/block nodes keep
    /// their fixed IDs.
    fn derive_node_ids(&mut self) {
        for node in &mut self.nodes {
            if matches!(
                node.outbound,
                crate::node::OutboundConfig::Direct | crate::node::OutboundConfig::Block
            ) {
                continue;
            }
            node.id = node.derive_id();
        }
    }

    fn validate_globals_detailed(&self, source: &SourceRef) -> Result<(), DetailedConfigError> {
        if let Err(mut error) = crate::check::validate_dns_check_targets(&self.global.udp_check_dns)
        {
            error.diagnostic.source = source.clone();
            return Err(error);
        }
        if self.global.dial_mode.parse::<DialMode>().is_err() {
            return Err(config_validation_error(
                source,
                SettingPath::new("global").field("dial_mode"),
                "invalid-config-value",
                "dial_mode must be ip, domain, domain+, or domain++",
            ));
        }
        if self.global.data_dir.is_empty()
            || !std::path::Path::new(&self.global.data_dir).is_absolute()
        {
            return Err(config_validation_error(
                source,
                SettingPath::new("global").field("data_dir"),
                "invalid-config-value",
                "data_dir must be a non-empty absolute path",
            ));
        }
        if self.dns.bind_endpoint().is_err() {
            return Err(config_validation_error(
                source,
                SettingPath::new("dns").field("bind"),
                "invalid-config-value",
                "dns.bind must be a supported endpoint",
            ));
        }
        if self.dns.client_subnet_mode().is_err() {
            return Err(config_validation_error(
                source,
                SettingPath::new("dns").field("client_subnet"),
                "invalid-config-value",
                "client_subnet must be empty, auto, auto(IPv4), IPv4, or IPv4/prefix",
            ));
        }
        self.dns.validate_upstream_references_detailed(source)?;
        if self.global.check_interval_secs == 0 {
            return Err(config_validation_error(
                source,
                SettingPath::new("global").field("check_interval"),
                "invalid-config-value",
                "check_interval must be a positive duration",
            ));
        }
        if self.global.tproxy_mark != default_tproxy_mark() {
            return Err(config_validation_error(
                source,
                SettingPath::new("global").field("tproxy_mark"),
                "invalid-config-value",
                "tproxy_mark does not match the compiled datapath mark",
            ));
        }
        let reserved = crate::routing::DATAPATH_RESERVED_MARK_MASK;
        // Transparent listeners carry the global mark; daens routes the TPROXY bit to local delivery.
        if self.global.so_mark_from_dae & (reserved | DEFAULT_TPROXY_MARK) != 0 {
            return Err(config_validation_error(
                source,
                SettingPath::new("global").field("so_mark_from_dae"),
                "invalid-config-value",
                "so_mark_from_dae overlaps datapath-reserved or TPROXY mark bits",
            ));
        }
        for (index, rule) in self.routing.rules.iter().enumerate() {
            if rule.mark & reserved != 0 {
                return Err(config_validation_error(
                    source,
                    SettingPath::new("routing")
                        .field("rules")
                        .index(index + 1)
                        .field("mark"),
                    "invalid-config-value",
                    "routing mark overlaps datapath-reserved mark bits",
                ));
            }
        }
        if self.routing.default_mark & reserved != 0 {
            return Err(config_validation_error(
                source,
                SettingPath::new("routing").field("fallback"),
                "invalid-config-value",
                "routing mark overlaps datapath-reserved mark bits",
            ));
        }
        Ok(())
    }

    fn validate_reserved_names_detailed(
        &self,
        source: &SourceRef,
    ) -> Result<(), DetailedConfigError> {
        for (index, node) in self.nodes.iter().enumerate() {
            if matches!(
                node.protocol(),
                crate::types::NodeProtocol::Direct | crate::types::NodeProtocol::Block
            ) {
                continue;
            }
            if matches!(
                node.name.as_str(),
                Self::BUILTIN_DIRECT_NODE | Self::BUILTIN_BLOCK_NODE
            ) {
                return Err(config_validation_error(
                    source,
                    SettingPath::new("nodes").index(index + 1).field("name"),
                    "invalid-config-value",
                    "node name is reserved for a builtin direct/block node",
                ));
            }
        }
        Ok(())
    }

    fn validate_references_detailed(&self, source: &SourceRef) -> Result<(), DetailedConfigError> {
        const MAX_USER_GROUPS: usize = 0xFC - 2;
        if self.groups.len() > MAX_USER_GROUPS {
            return Err(config_validation_error(
                source,
                SettingPath::new("groups"),
                "invalid-config-value",
                "too many outbound groups",
            ));
        }
        for (index, group) in self.groups.iter().enumerate() {
            if group.name.is_empty() {
                return Err(config_validation_error(
                    source,
                    SettingPath::new("groups").index(index + 1).field("name"),
                    "invalid-config-value",
                    "group name must not be empty",
                ));
            }
            if self.nodes.iter().any(|node| {
                node.id != DIRECT_NODE_ID && node.id != BLOCK_NODE_ID && node.name == group.name
            }) {
                return Err(config_validation_error(
                    source,
                    SettingPath::new("groups").index(index + 1).field("name"),
                    "invalid-config-value",
                    "group name must not duplicate a node name",
                ));
            }
        }
        let is_config_node = |name: &str| {
            self.nodes.iter().any(|node| {
                node.id != DIRECT_NODE_ID && node.id != BLOCK_NODE_ID && node.name == name
            })
        };
        let check_outbound = |target: &str, index: Option<usize>| {
            if matches!(target, Self::BUILTIN_DIRECT_NODE | Self::BUILTIN_BLOCK_NODE)
                || self.groups.iter().any(|group| group.name == target)
            {
                return Ok(());
            }
            let message = if is_config_node(target) {
                "routing target names a node; use a group"
            } else {
                "routing target is not a declared group or builtin"
            };
            let setting = match index {
                Some(index) => SettingPath::new("routing")
                    .field("rules")
                    .index(index + 1)
                    .field("outbound"),
                None => SettingPath::new("routing").field("fallback"),
            };
            Err(config_validation_error(
                source,
                setting,
                "unknown-routing-target",
                message,
            ))
        };
        for (index, rule) in self.routing.rules.iter().enumerate() {
            check_outbound(rule.outbound.as_str(), Some(index))?;
        }
        check_outbound(&self.routing.default_outbound, None)?;
        for (index, subscription) in self.subscriptions.iter().enumerate() {
            if subscription.name.is_empty() {
                return Err(config_validation_error(
                    source,
                    SettingPath::new("subscriptions")
                        .index(index + 1)
                        .field("name"),
                    "invalid-config-value",
                    "subscription name must not be empty",
                ));
            }
            if subscription.url.is_empty() {
                return Err(config_validation_error(
                    source,
                    SettingPath::new("subscriptions")
                        .index(index + 1)
                        .field("url"),
                    "invalid-config-value",
                    "subscription URL must not be empty",
                ));
            }
            if !subscription.url.starts_with("http://") && !subscription.url.starts_with("https://")
            {
                return Err(config_validation_error(
                    source,
                    SettingPath::new("subscriptions")
                        .index(index + 1)
                        .field("url"),
                    "invalid-config-value",
                    "subscription URL must use http:// or https://",
                ));
            }
        }
        Ok(())
    }

    /// Validate operator configuration through the legacy error API.
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        self.validate_detailed()
            .map_err(DetailedConfigError::into_legacy)
    }

    /// Validate operator configuration while retaining typed diagnostics.
    pub fn validate_detailed(&self) -> Result<(), DetailedConfigError> {
        let source = DiagnosticSources::new(None).root();
        self.validate_globals_detailed(&source)?;
        crate::node::validate_node_collection(&self.nodes)?;
        self.validate_reserved_names_detailed(&source)?;
        self.validate_references_detailed(&source)
    }
    /// Validate a fully assembled runtime snapshot.
    ///
    /// This retains the operator validator's global, DNS, routing, and
    /// subscription checks, then verifies references materialized by runtime
    /// providers. The latter must run after membership rebuilding so a failed
    /// refresh cannot publish dangling direct or nested-group members.
    pub fn validate_assembled(&self) -> Result<(), DetailedConfigError> {
        let source = DiagnosticSources::new(None).root();
        self.validate_globals_detailed(&source)?;
        crate::node::validate_node_collection(&self.nodes)?;
        // Provider display names are not operator declarations of reserved builtins.
        self.validate_references_detailed(&source)?;

        let node_ids: std::collections::HashSet<_> =
            self.nodes.iter().map(|node| node.id).collect();
        let group_names: std::collections::HashSet<_> = self
            .groups
            .iter()
            .map(|group| group.name.as_str())
            .collect();
        let target_exists = |target: &str| {
            matches!(target, Self::BUILTIN_DIRECT_NODE | Self::BUILTIN_BLOCK_NODE)
                || self.nodes.iter().any(|node| node.name == target)
                || group_names.contains(target)
        };
        let error = |setting, code, message, ordinal| {
            let mut error = DetailedConfigError::new(
                ErrorCategory::Validation,
                code,
                source.clone(),
                setting,
                message,
            );
            error.diagnostic.value = crate::diagnostic::SafeValue::Ordinal(ordinal);
            error.diagnostic.entry_index = Some(ordinal);
            error
        };

        for (group_index, group) in self.groups.iter().enumerate() {
            for (member_index, node_id) in group.nodes.iter().enumerate() {
                if !node_ids.contains(node_id) {
                    return Err(error(
                        SettingPath::new("groups")
                            .index(group_index + 1)
                            .field("nodes")
                            .index(member_index + 1),
                        "invalid-group-node-reference",
                        "group references a node outside the assembled collection",
                        group_index + 1,
                    ));
                }
            }
            for (nested_index, nested_name) in group.groups.iter().enumerate() {
                if !group_names.contains(nested_name.as_str()) {
                    return Err(error(
                        SettingPath::new("groups")
                            .index(group_index + 1)
                            .field("groups")
                            .index(nested_index + 1),
                        "invalid-nested-group-reference",
                        "group references an unknown nested group",
                        group_index + 1,
                    ));
                }
            }
            if let Some(final_outbound) = group.final_outbound.as_deref()
                && !target_exists(final_outbound)
            {
                return Err(error(
                    SettingPath::new("groups")
                        .index(group_index + 1)
                        .field("final"),
                    "invalid-group-final-target",
                    "group final target is not an assembled node, group, or builtin",
                    group_index + 1,
                ));
            }
        }
        for (upstream_index, upstream) in self.dns.upstream.iter().enumerate() {
            if let Some(outbound) = upstream.outbound.as_deref()
                && !target_exists(outbound)
            {
                return Err(error(
                    SettingPath::new("dns")
                        .field("upstream")
                        .index(upstream_index + 1)
                        .field("outbound"),
                    "invalid-dns-detour-target",
                    "DNS detour target is not an assembled node, group, or builtin",
                    upstream_index + 1,
                ));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum ConfigFormat {
    Json,
    Yaml,
    Toml,
}

#[derive(Default)]
struct DecodeLocation {
    span: Option<Range<usize>>,
    line: Option<usize>,
    byte_column: Option<usize>,
    reason: Option<&'static str>,
}

fn parse_structured(
    content: &str,
    format: ConfigFormat,
    diagnostics: &mut Vec<DetailedDiagnostic>,
    source: SourceRef,
) -> Result<Config, DetailedConfigError> {
    let diagnostic_start = diagnostics.len();
    let mut track = Track::new();
    let seed = RawConfigSeed {
        diagnostics,
        source: source.clone(),
    };
    let result = match format {
        ConfigFormat::Json => {
            let mut decoder = serde_json::Deserializer::from_str(content);
            seed.deserialize(PathDeserializer::new(&mut decoder, &mut track))
                .and_then(|config| decoder.end().map(|_| config))
                .map_err(|error| DecodeLocation {
                    line: (error.line() != 0).then_some(error.line()),
                    byte_column: (error.column() != 0).then_some(error.column()),
                    span: None,
                    reason: Some(safe_json_reason(&error)),
                })
        }
        ConfigFormat::Yaml => seed
            .deserialize(PathDeserializer::new(
                serde_yaml::Deserializer::from_str(content),
                &mut track,
            ))
            .map_err(|error| {
                let location = error.location();
                DecodeLocation {
                    line: location.as_ref().map(|location| location.line()),
                    byte_column: location.as_ref().and_then(|location| {
                        let line = content.lines().nth(location.line().checked_sub(1)?)?;
                        let column = location.column().checked_sub(1)?;
                        Some(
                            line.char_indices()
                                .nth(column)
                                .map_or(line.len(), |(i, _)| i)
                                + 1,
                        )
                    }),
                    span: None,
                    reason: None,
                }
            }),
        ConfigFormat::Toml => toml::de::Deserializer::parse(content)
            .and_then(|decoder| seed.deserialize(PathDeserializer::new(decoder, &mut track)))
            .map_err(|error| toml_location(content, &error)),
    };
    let mut config = match result {
        Ok(config) => config,
        Err(location) => {
            if let Some(index) = diagnostics[diagnostic_start..]
                .iter()
                .position(|diagnostic| {
                    diagnostic.terminal && diagnostic.severity == crate::diagnostic::Severity::Error
                })
            {
                let mut diagnostic = diagnostics.remove(diagnostic_start + index);
                diagnostic.span = location.span;
                diagnostic.line = location.line;
                diagnostic.byte_column = location.byte_column;
                return Err(DetailedConfigError {
                    category: ErrorCategory::Validation,
                    diagnostic: Box::new(diagnostic),
                });
            }
            return Err(structured_decode_error(source, track.path(), location));
        }
    };
    let canonical_present = match format {
        ConfigFormat::Json => json_has_global_nfqueue_enable(content),
        ConfigFormat::Yaml => yaml_has_global_nfqueue_enable(content),
        ConfigFormat::Toml => toml_has_global_nfqueue_enable(content),
    };
    config.apply_legacy_nfqueue(canonical_present);
    Ok(config)
}

fn safe_json_reason(error: &serde_json::Error) -> &'static str {
    // Decoder prose is transient. Only these schema-defined reasons may escape.
    let text = error.to_string();
    let reason = text
        .rsplit_once(" at line ")
        .map_or(text.as_str(), |(reason, _)| reason);
    if reason == "expected value" {
        "expected a JSON value"
    } else if reason == "expected ident" {
        "invalid JSON literal"
    } else if reason.starts_with("unknown field `") && reason.ends_with("expected `enabled`") {
        "unknown field; expected enabled"
    } else if reason.starts_with("invalid type:") {
        if reason.ends_with("expected struct Group") {
            "expected a group object"
        } else if reason.ends_with("expected a sequence") {
            "expected a sequence"
        } else {
            "incorrect value type for configuration field"
        }
    } else {
        match error.classify() {
            serde_json::error::Category::Io => "configuration IO failed",
            serde_json::error::Category::Syntax => "invalid JSON syntax",
            serde_json::error::Category::Eof => "incomplete JSON input",
            serde_json::error::Category::Data => "invalid configuration fields",
        }
    }
}

fn toml_location(content: &str, error: &toml::de::Error) -> DecodeLocation {
    let Some(span) = error.span() else {
        return DecodeLocation::default();
    };
    let start = span.start.min(content.len());
    let prefix = &content.as_bytes()[..start];
    let line = prefix.iter().filter(|&&byte| byte == b'\n').count() + 1;
    let byte_column = prefix
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(start + 1, |newline| start - newline);
    DecodeLocation {
        span: Some(span),
        line: Some(line),
        byte_column: Some(byte_column),
        reason: None,
    }
}

fn structured_decode_error(
    source: SourceRef,
    path: serde_path_to_error::Path,
    location: DecodeLocation,
) -> DetailedConfigError {
    let (setting, entry_index) = setting_from_decode_path(&path);
    let mut error = DetailedConfigError::new(
        ErrorCategory::Parse,
        "invalid-structured-config",
        source,
        setting,
        location.reason.unwrap_or("invalid configuration fields"),
    );
    error.diagnostic.entry_index = entry_index;
    error.diagnostic.span = location.span;
    error.diagnostic.line = location.line;
    error.diagnostic.byte_column = location.byte_column;
    error
}

fn setting_from_decode_path(path: &serde_path_to_error::Path) -> (SettingPath, Option<usize>) {
    let mut segments = path.iter();
    let root = match segments.next() {
        Some(Segment::Map { key }) => seed::CONFIG_FIELDS
            .iter()
            .copied()
            .find(|&field| field == key),
        Some(Segment::Seq { index }) => seed::CONFIG_FIELDS.get(*index).copied(),
        _ => None,
    };
    let Some(root) = root else {
        return (SettingPath::new("config"), None);
    };
    let mut setting = SettingPath::new(root);
    let mut entry_index = None;
    let mut field_seen = false;
    for segment in segments {
        match segment {
            Segment::Seq { index } if matches!(root, "nodes" | "groups" | "subscriptions") => {
                let index = index + 1;
                setting = setting.index(index);
                entry_index.get_or_insert(index);
            }
            Segment::Map { key } if !field_seen => {
                let field = match root {
                    "nodes" if entry_index.is_some() => node_schema_field(key),
                    "groups" if entry_index.is_some() => [
                        "id",
                        "name",
                        "policy",
                        "nodes",
                        "filters",
                        "groups",
                        "default",
                        "final_outbound",
                        "check_url",
                        "check_interval",
                        "tolerance",
                        "idle_timeout",
                        "interrupt_connections",
                        "created_at",
                    ]
                    .into_iter()
                    .find(|field| field == key),
                    "subscriptions" if entry_index.is_some() => [
                        "id",
                        "name",
                        "url",
                        "sub_type",
                        "update_interval",
                        "user_agent",
                        "headers",
                        "enabled",
                        "last_updated",
                        "node_count",
                        "created_at",
                    ]
                    .into_iter()
                    .find(|field| field == key),
                    _ => None,
                };
                let Some(field) = field else {
                    break;
                };
                setting = setting.field(field);
                field_seen = true;
            }
            _ => break,
        }
    }
    (setting, entry_index)
}

fn node_schema_field(field: &str) -> Option<&'static str> {
    Some(match field {
        "id" => "id",
        "name" => "name",
        "address" => "address",
        "host" => "host",
        "port" => "port",
        "protocol" => "protocol",
        "username" => "username",
        "password" => "password",
        "encryption" => "encryption",
        "vless_mode" => "vless_mode",
        "packet_encoding" => "packet_encoding",
        "multiplex" => "multiplex",
        "plugin" => "plugin",
        "plugin_opts" => "plugin_opts",
        "transport" => "transport",
        "tls" => "tls",
        "sni" => "sni",
        "tls_alpn" => "tls_alpn",
        "skip_cert_verify" => "skip_cert_verify",
        "ech_enabled" => "ech_enabled",
        "ech_config" => "ech_config",
        "ech_config_path" => "ech_config_path",
        "reality_public_key" => "reality_public_key",
        "reality_short_id" => "reality_short_id",
        "reality_spider_x" => "reality_spider_x",
        "flow" => "flow",
        "network" => "network",
        "ws_path" => "ws_path",
        "ws_host" => "ws_host",
        "grpc_service" => "grpc_service",
        "hy2_auth" => "hy2_auth",
        "hy2_obfs" => "hy2_obfs",
        "hy2_up_mbps" => "hy2_up_mbps",
        "hy2_down_mbps" => "hy2_down_mbps",
        "hy2_port_hopping" => "hy2_port_hopping",
        "hy2_hop_interval" => "hy2_hop_interval",
        "tls_pin_sha256" => "tls_pin_sha256",
        "hy2_init_stream_recv_window" => "hy2_init_stream_recv_window",
        "hy2_init_conn_recv_window" => "hy2_init_conn_recv_window",
        "hy2_disable_mtu_discovery" => "hy2_disable_mtu_discovery",
        "quic_mtu" => "quic_mtu",
        "tuic_uuid" => "tuic_uuid",
        "tuic_password" => "tuic_password",
        "tuic_congestion" => "tuic_congestion",
        "tuic_alpn" => "tuic_alpn",
        "tuic_init_stream_recv_window" => "tuic_init_stream_recv_window",
        "tuic_init_conn_recv_window" => "tuic_init_conn_recv_window",
        "juicity_uuid" => "juicity_uuid",
        "juicity_password" => "juicity_password",
        "anytls_password" => "anytls_password",
        "anytls_min_idle_session" => "anytls_min_idle_session",
        "anytls_idle_session_check_interval" => "anytls_idle_session_check_interval",
        "anytls_idle_session_timeout" => "anytls_idle_session_timeout",
        "mark" => "mark",
        "tags" => "tags",
        "subscription_id" => "subscription_id",
        "group_id" => "group_id",
        "created_at" => "created_at",
        "updated_at" => "updated_at",
        _ => return None,
    })
}

fn json_has_global_nfqueue_enable(content: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(content)
        .ok()
        .and_then(|root| root.get("global").cloned())
        .and_then(|global| global.as_object().cloned())
        .is_some_and(|global| global.contains_key("nfqueue_enable"))
}

fn toml_has_global_nfqueue_enable(content: &str) -> bool {
    toml::from_str::<toml::Value>(content)
        .ok()
        .and_then(|root| root.get("global").cloned())
        .and_then(|global| global.as_table().cloned())
        .is_some_and(|global| global.contains_key("nfqueue_enable"))
}

fn yaml_has_global_nfqueue_enable(content: &str) -> bool {
    serde_yaml::from_str::<serde_yaml::Value>(content)
        .ok()
        .and_then(|root| root.get("global").cloned())
        .and_then(|global| global.as_mapping().cloned())
        .is_some_and(|global| {
            global.contains_key(serde_yaml::Value::String("nfqueue_enable".into()))
        })
}

#[cfg(test)]
mod builtin_nodes_tests {
    use super::*;

    #[test]
    fn test_validate_accepts_supported_dns_bind() {
        let mut config = Config::default();
        config.dns.bind = "tcp+udp://localhost:0".into();
        config.validate().unwrap();
    }

    #[test]
    fn test_validate_rejects_invalid_subscriptions() {
        let valid = crate::subscription::Subscription {
            name: "sub".into(),
            url: "https://example.test/feed".into(),
            ..Default::default()
        };
        let mut config = Config::default();
        config.subscriptions.push(valid.clone());
        config.validate().unwrap();

        for (name, url) in [
            ("", "https://example.test/feed"),
            ("sub", ""),
            ("sub", "ftp://example.test/feed"),
        ] {
            let mut config = Config::default();
            let mut sub = valid.clone();
            sub.name = name.into();
            sub.url = url.into();
            config.subscriptions.push(sub);
            assert!(
                config.validate().is_err(),
                "name={name:?} url={url:?} must fail validation"
            );
        }
    }

    #[test]
    fn test_validate_rejects_zero_check_interval() {
        let mut config = Config::default();
        config.global.check_interval_secs = 0;
        let error = config.validate().unwrap_err();
        assert!(
            error.to_string().contains("global.check_interval"),
            "validation error must identify global.check_interval: {error}"
        );
    }

    #[test]
    fn test_validate_rejects_unknown_dial_mode() {
        let mut config = Config::default();
        config.global.dial_mode = "domain???".into();
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("global.dial_mode"));
    }

    #[test]
    fn test_validate_rejects_invalid_structured_dns_bind_clearly() {
        let config = Config::from_json_str(r#"{"dns":{"bind":"udp://localhost"}}"#).unwrap();
        let error = config.validate().unwrap_err();
        assert!(matches!(error, crate::ConfigError::Validation(_)));
        assert!(
            error.to_string().contains("dns.bind"),
            "validation error must identify dns.bind: {error}"
        );
    }

    #[test]
    fn test_from_json_accepts_legacy_null_dns_routing_fields() {
        let config =
            Config::from_json_str(r#"{"dns":{"routing":{"request":null,"response":null}}}"#)
                .unwrap();

        assert!(config.dns.routing.request.rules.is_empty());
        assert!(config.dns.routing.response.rules.is_empty());
    }

    #[test]
    fn test_from_file_preserves_renamed_honk_policy_error() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "group {\n proxy {\n policy: honk\n }\n}").unwrap();
        let error = Config::from_file(file.path().to_str().unwrap()).unwrap_err();
        assert!(matches!(error, crate::ConfigError::UnsupportedPolicy(_)));
    }

    #[test]
    fn test_validate_rejects_invalid_structured_dns_client_subnet() {
        let config =
            Config::from_json_str(r#"{"dns":{"client_subnet":"auto(dns.google)"}}"#).unwrap();
        let error = config.validate().unwrap_err();
        assert!(matches!(error, crate::ConfigError::Validation(_)));
        assert!(error.to_string().contains("dns.client_subnet"));
    }

    #[test]
    fn test_validate_requires_absolute_data_dir() {
        let mut config = Config::default();
        assert_eq!(config.global.data_dir, crate::paths::DEFAULT_DATA_DIR);
        config.validate().unwrap();

        for invalid in ["", "relative/data"] {
            config.global.data_dir = invalid.into();
            let error = config.validate().unwrap_err();
            assert!(error.to_string().contains("global.data_dir"));
        }
    }

    #[test]
    fn test_validate_rejects_datapath_reserved_routing_marks() {
        let mut config = Config::default();
        config.routing.rules.push(crate::routing::RoutingRule {
            name: "reserved-mark".into(),
            condition: crate::routing::RoutingCondition::default(),
            outbound: crate::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        });

        for reserved_bit in [0x4000_0000, 0x8000_0000] {
            config.routing.rules[0].mark = reserved_bit;
            let error = config
                .validate_detailed()
                .expect_err("reserved routing mark must fail");
            assert_eq!(error.diagnostic.code, "invalid-config-value");
            assert_eq!(
                error.diagnostic.setting.to_string(),
                "routing.rules[1].mark"
            );
        }

        // Direct rule marks may use the TPROXY bit; the global listener mark may not.
        config.routing.rules[0].mark = 0x3fff_ffff;
        for global in [
            0x8000_0000,
            DEFAULT_TPROXY_MARK,
            DEFAULT_TPROXY_MARK | 0x100,
        ] {
            config.global.so_mark_from_dae = global;
            let error = config.validate_detailed().unwrap_err();
            assert_eq!(
                error.diagnostic.setting.to_string(),
                "global.so_mark_from_dae"
            );
        }
        config.global.so_mark_from_dae = 0x37ff_ffff;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_reserved_group_ordinal_overflow() {
        let mut config = Config::default();
        for index in 0..=250 {
            config.groups.push(crate::group::Group {
                name: format!("group-{index}"),
                ..Default::default()
            });
        }
        let error = config
            .validate()
            .expect_err("reserved user-group ordinal must fail validation");
        assert!(error.to_string().contains("too many outbound groups"));

        config.groups.pop();
        assert!(
            config.validate().is_ok(),
            "the last valid group ordinal must pass"
        );
    }

    #[test]
    fn test_validate_rejects_unknown_transport() {
        let mut config = Config::default();
        config
            .nodes
            .push(crate::node::Node::from_share_link("trojan://secret@1.2.3.4:443#bad").unwrap());
        config.nodes[0].transport_mut().unwrap().transport = "kcp".into();
        config.nodes[0].id = config.nodes[0].derive_id();
        assert!(config.validate().is_err());
        for ok in ["", "tcp", "ws", "grpc"] {
            config.nodes[0].transport_mut().unwrap().transport = ok.into();
            config.nodes[0].id = config.nodes[0].derive_id();
            assert!(config.validate().is_ok(), "transport '{ok}' must pass");
        }
    }

    #[test]
    fn test_validate_rejects_incompatible_vless_selected_paths() {
        use crate::node::{Udp443Policy, VlessMultiplex, VlessUdpEncoding};

        let base = crate::node::Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443#vless",
        )
        .unwrap();
        let mut config = Config::default();
        config.nodes.push(base.clone());

        for configure in [
            |vless: &mut crate::node::VlessConfig| {
                vless.udp_encoding = VlessUdpEncoding::UotV2;
            },
            |vless: &mut crate::node::VlessConfig| {
                vless.multiplex = VlessMultiplex::H2 { padding: false };
            },
            |vless: &mut crate::node::VlessConfig| {
                vless.multiplex = VlessMultiplex::xray(8, 0, Udp443Policy::Allow);
            },
        ] {
            config.nodes[0] = base.clone();
            let vless = config.nodes[0].vless_mut().unwrap();
            vless.flow = Some("xtls-rprx-vision".into());
            configure(vless);
            config.nodes[0].id = config.nodes[0].derive_id();
            assert!(config.validate().is_err());
        }

        config.nodes[0] = base;
        let vless = config.nodes[0].vless_mut().unwrap();
        vless.flow = Some("xtls-rprx-vision".into());
        vless.multiplex = VlessMultiplex::xray(-1, 8, Udp443Policy::Allow);
        config.nodes[0].id = config.nodes[0].derive_id();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_reserved_builtin_names_and_protocols() {
        for (name, protocol) in [
            ("direct", crate::types::NodeProtocol::Socks5),
            ("block", crate::types::NodeProtocol::Socks5),
            ("web-proxy", crate::types::NodeProtocol::Direct),
            ("web-proxy", crate::types::NodeProtocol::Block),
        ] {
            let outbound = match protocol {
                crate::types::NodeProtocol::Socks5 => {
                    crate::node::OutboundConfig::Socks5(Default::default())
                }
                crate::types::NodeProtocol::Direct => crate::node::OutboundConfig::Direct,
                crate::types::NodeProtocol::Block => crate::node::OutboundConfig::Block,
                _ => unreachable!(),
            };
            let mut config = Config::default();
            let mut node =
                crate::node::Node::from_share_link("socks5://1.2.3.4:8080#web-proxy").unwrap();
            node.name = name.into();
            node.outbound = outbound;
            config.nodes.push(node);
            assert!(config.validate().is_err(), "{name}/{protocol:?}");
        }
    }

    #[test]
    fn test_ensure_builtin_nodes_injects_direct_and_block_once() {
        let mut config = Config::default();
        assert!(!config.nodes.iter().any(|n| n.name == "direct"));
        config.ensure_builtin_nodes();
        assert_eq!(config.nodes.len(), 2);
        assert_eq!(config.nodes[0].name, "direct");
        assert_eq!(config.nodes[0].id, DIRECT_NODE_ID);
        assert_eq!(
            config.nodes[0].protocol(),
            crate::types::NodeProtocol::Direct
        );
        assert_eq!(config.nodes[1].name, "block");
        assert_eq!(config.nodes[1].id, BLOCK_NODE_ID);
        assert_eq!(
            config.nodes[1].protocol(),
            crate::types::NodeProtocol::Block
        );
        config.ensure_builtin_nodes();
        assert_eq!(config.nodes.len(), 2);
        assert!(config.validate().is_ok(), "built-ins stay valid");
    }

    #[test]
    fn test_builtin_node_resolves_registered_or_fresh() {
        let mut config = Config::default();
        let fresh = config.builtin_node("direct").unwrap();
        assert_eq!(fresh.id, DIRECT_NODE_ID);
        assert!(config.builtin_node("proxy").is_none());
        let mut registered = Config::builtin_block_node();
        registered.subscription_id = Some(uuid::Uuid::new_v4());
        config.nodes.push(registered.clone());
        assert_eq!(
            config.builtin_node("block").unwrap().subscription_id,
            registered.subscription_id,
            "a registered built-in wins over the fresh definition"
        );
    }

    fn test_node(name: &str) -> crate::node::Node {
        let mut node =
            crate::node::Node::from_share_link("trojan://secret@example.com:443").unwrap();
        node.name = name.into();
        node
    }

    fn rule_to(outbound: &str) -> crate::routing::RoutingRule {
        crate::routing::RoutingRule {
            name: String::new(),
            condition: crate::routing::RoutingCondition::default(),
            outbound: crate::routing::RoutingOutbound::Simple(outbound.into()),
            priority: 0,
            must: false,
            mark: 0,
        }
    }

    #[test]
    fn test_validate_rejects_bare_node_outbounds() {
        let mut config = Config::default();
        config.nodes.push(test_node("vn"));

        config.routing.rules.push(rule_to("vn"));
        let error = config.validate_detailed().unwrap_err();
        assert_eq!(error.diagnostic.code, "unknown-routing-target");
        assert_eq!(
            error.diagnostic.setting.to_string(),
            "routing.rules[1].outbound"
        );

        config.routing.rules.clear();
        config.routing.default_outbound = "vn".into();
        let error = config.validate_detailed().unwrap_err();
        assert_eq!(error.diagnostic.code, "unknown-routing-target");
        assert_eq!(error.diagnostic.setting.to_string(), "routing.fallback");
    }

    #[test]
    fn test_validate_accepts_group_and_builtin_outbounds() {
        let mut config = Config::default();
        config.nodes.push(test_node("vn"));
        config.groups.push(crate::group::Group {
            name: "proxy".into(),
            ..Default::default()
        });
        for outbound in ["proxy", "direct", "block"] {
            config.routing.rules = vec![rule_to(outbound)];
            config.routing.default_outbound = outbound.into();
            assert!(config.validate().is_ok(), "outbound '{outbound}' must pass");
        }
    }

    #[test]
    fn test_validate_rejects_unknown_outbounds() {
        let mut config = Config::default();
        config.routing.rules.push(rule_to("missing"));
        let error = config.validate_detailed().unwrap_err();
        assert_eq!(error.diagnostic.code, "unknown-routing-target");
        assert_eq!(
            error.diagnostic.setting.to_string(),
            "routing.rules[1].outbound"
        );

        config.routing.rules.clear();
        config.routing.default_outbound = "missing".into();
        let error = config.validate_detailed().unwrap_err();
        assert_eq!(error.diagnostic.code, "unknown-routing-target");
        assert_eq!(error.diagnostic.setting.to_string(), "routing.fallback");
    }

    #[test]
    fn test_validate_rejects_node_group_name_collision() {
        let mut config = Config::default();
        config.nodes.push(test_node("dup"));
        config.groups.push(crate::group::Group {
            name: "dup".into(),
            ..Default::default()
        });
        let error = config.validate_detailed().unwrap_err();
        assert_eq!(error.diagnostic.code, "invalid-config-value");
        assert_eq!(error.diagnostic.setting.to_string(), "groups[1].name");
    }
}
