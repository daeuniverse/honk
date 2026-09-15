use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Include error: {0}")]
    Include(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Unknown node protocol: {0}")]
    UnknownProtocol(String),

    #[error("Unsupported policy: {0}")]
    UnsupportedPolicy(String),
}

/// The legacy exhaustive matching surface, without an input-bearing payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Io(std::io::ErrorKind),
    Parse,
    Include,
    Validation,
    Serialization,
    UnknownProtocol,
    UnsupportedPolicy,
}

impl ErrorCategory {
    pub fn of(error: &ConfigError) -> Self {
        match error {
            ConfigError::Io(error) => Self::Io(error.kind()),
            ConfigError::Parse(_) => Self::Parse,
            ConfigError::Include(_) => Self::Include,
            ConfigError::Validation(_) => Self::Validation,
            ConfigError::Serialization(_) => Self::Serialization,
            ConfigError::UnknownProtocol(_) => Self::UnknownProtocol,
            ConfigError::UnsupportedPolicy(_) => Self::UnsupportedPolicy,
        }
    }
}

#[derive(Debug, Clone, Error)]
#[error("{setting}: {message}", setting = .diagnostic.setting, message = .diagnostic.message)]
pub struct DetailedConfigError {
    pub category: ErrorCategory,
    pub diagnostic: Box<crate::diagnostic::DetailedDiagnostic>,
}

impl DetailedConfigError {
    pub fn new(
        category: ErrorCategory,
        code: &'static str,
        source: crate::diagnostic::SourceRef,
        setting: crate::diagnostic::SettingPath,
        message: &'static str,
    ) -> Self {
        let mut diagnostic = crate::diagnostic::DetailedDiagnostic::warning(
            code,
            source,
            setting,
            crate::diagnostic::SafeValue::Redacted,
            message,
        );
        diagnostic.severity = crate::diagnostic::Severity::Error;
        diagnostic.terminal = true;
        Self {
            category,
            diagnostic: Box::new(diagnostic),
        }
    }

    /// Unknown legacy prose is deliberately withheld, including serde/IO sources.
    pub fn from_legacy(error: ConfigError, source: crate::diagnostic::SourceRef) -> Self {
        use crate::diagnostic::SettingPath;
        let category = ErrorCategory::of(&error);
        if matches!(&error, ConfigError::UnsupportedPolicy(message)
            if message == "group policy 'honk' was renamed to 'score'")
        {
            return Self::new(
                category,
                "unsupported-policy",
                source,
                SettingPath::new("groups").field("policy"),
                "group policy 'honk' was renamed to 'score'",
            );
        }
        let text = match &error {
            ConfigError::Parse(text) | ConfigError::Validation(text) => Some(text.as_str()),
            _ => None,
        };
        if let Some(text) = text {
            if let Some(index) = text
                .strip_prefix("global.udp_check_dns[")
                .and_then(|text| text.strip_suffix("]: invalid DNS check target"))
                .and_then(|text| text.parse::<usize>().ok())
            {
                let mut error = Self::new(
                    category,
                    "invalid-dns-check-target",
                    source,
                    SettingPath::new("global")
                        .field("udp_check_dns")
                        .index(index),
                    "DNS check target requires a host and a valid nonzero port; omitted port is 53",
                );
                error.diagnostic.entry_index = Some(index);
                return error;
            }
            let reason = match text {
                "unknown traffic predicate" => Some((
                    "unknown-traffic-predicate",
                    SettingPath::new("routing").field("rules"),
                    "unknown or malformed traffic predicate; correct the matcher syntax",
                )),
                "invalid hysteria2 hop port list" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("hy2_port_hopping"),
                    "hopping ports must be nonzero, valid ranges, and nonrepeating",
                )),
                "unsupported TUIC UDP relay mode" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("udp_relay_mode"),
                    "TUIC supports only native UDP relay",
                )),
                "unsupported Hysteria2 obfuscation"
                | "conflicting Hysteria2 obfuscation passwords" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("hy2_obfs"),
                    "Hysteria2 obfuscation must use the supported algorithm and agreeing password claims",
                )),
                "unsupported VMess cipher" | "conflicting VMess cipher aliases" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("encryption"),
                    "VMess cipher must be auto or aes-128-gcm; aliases must agree",
                )),
                "unsupported stream transport"
                | "conflicting stream transport aliases"
                | "unsupported VMess obfs transport" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("transport"),
                    "stream transport must be tcp, ws, or grpc; aliases must agree",
                )),
                "invalid certificate verification boolean"
                | "conflicting certificate verification aliases" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("skip_cert_verify"),
                    "certificate verification aliases must be valid agreeing booleans",
                )),
                "conflicting TLS server name parameters" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("sni"),
                    "conflicting TLS server name aliases",
                )),
                "dns.hosts_file was removed; use one or more use_host paths" => Some((
                    "removed-dns-hosts-file",
                    SettingPath::new("dns").field("hosts_file"),
                    "hosts_file was removed; use one or more use_host paths",
                )),
                "not a dae config file" => Some((
                    "not-dae-config",
                    SettingPath::new("config"),
                    "not a dae config file",
                )),
                _ if text.starts_with("unclosed block `") => Some((
                    "unclosed-block",
                    SettingPath::new("config"),
                    "unclosed configuration block",
                )),
                _ if text.starts_with("unexpected `{` at line ") => Some((
                    "unexpected-opener",
                    SettingPath::new("config"),
                    "unexpected opening brace",
                )),
                _ if text.starts_with("unknown experimental.udp_nfqueue setting: ") => Some((
                    "unknown-nfqueue-setting",
                    SettingPath::new("experimental").field("udp_nfqueue"),
                    "unknown NFQUEUE setting; only enabled is supported",
                )),
                _ if text.starts_with("unknown experimental setting: ") => Some((
                    "unknown-experimental-setting",
                    SettingPath::new("experimental"),
                    "unknown experimental setting",
                )),
                _ => None,
            };
            if let Some((code, setting, message)) = reason {
                return Self::new(category, code, source, setting, message);
            }
            for (prefix, root, field) in [
                ("global.dial_mode", "global", "dial_mode"),
                ("global.data_dir", "global", "data_dir"),
                ("global.check_interval", "global", "check_interval"),
                ("global.tproxy_mark", "global", "tproxy_mark"),
                ("global.so_mark_from_dae", "global", "so_mark_from_dae"),
                (
                    "invalid udp_warm_node_count",
                    "global",
                    "udp_warm_node_count",
                ),
                (
                    "invalid preconnect_node_count",
                    "global",
                    "preconnect_node_count",
                ),
                (
                    "invalid max_concurrent_dials",
                    "global",
                    "max_concurrent_dials",
                ),
                (
                    "invalid boolean for global.nfqueue_enable",
                    "global",
                    "nfqueue_enable",
                ),
                ("invalid dns.bind", "dns", "bind"),
                ("invalid dns.client_subnet", "dns", "client_subnet"),
                (
                    "invalid boolean for experimental.udp_nfqueue.enabled",
                    "experimental",
                    "udp_nfqueue",
                ),
            ] {
                if text.starts_with(prefix) {
                    return Self::new(
                        category,
                        "invalid-config-value",
                        source,
                        SettingPath::new(root).field(field),
                        match field {
                            "preconnect_node_count" => "expected a nonnegative integer or auto",
                            "max_concurrent_dials" | "udp_warm_node_count" => {
                                "expected a nonnegative integer"
                            }
                            "nfqueue_enable" | "udp_nfqueue" => {
                                "expected true/false, yes/no, 1/0 or on/off"
                            }
                            "client_subnet" => {
                                "expected empty, auto, auto(IPv4), IPv4, or IPv4/prefix"
                            }
                            _ => "invalid configuration value",
                        },
                    );
                }
            }
        }
        let (code, message) = match category {
            ErrorCategory::Io(_) => ("config-io", "configuration IO failed"),
            ErrorCategory::Parse => ("config-parse", "invalid configuration"),
            ErrorCategory::Include => ("config-include", "invalid configuration include"),
            ErrorCategory::Validation => ("config-validation", "configuration validation failed"),
            ErrorCategory::Serialization => {
                ("config-serialization", "configuration serialization failed")
            }
            ErrorCategory::UnknownProtocol => ("unknown-protocol", "unknown node protocol"),
            ErrorCategory::UnsupportedPolicy => ("unsupported-policy", "unsupported group policy"),
        };
        Self::new(category, code, source, SettingPath::new("config"), message)
    }

    pub fn into_legacy(self) -> ConfigError {
        let message = self.to_string();
        match self.category {
            ErrorCategory::Io(kind) => ConfigError::Io(std::io::Error::new(kind, message)),
            ErrorCategory::Parse => ConfigError::Parse(message),
            ErrorCategory::Include => ConfigError::Include(message),
            ErrorCategory::Validation => ConfigError::Validation(message),
            ErrorCategory::Serialization => ConfigError::Serialization(message),
            ErrorCategory::UnknownProtocol => ConfigError::UnknownProtocol(message),
            ErrorCategory::UnsupportedPolicy => ConfigError::UnsupportedPolicy(message),
        }
    }
}
