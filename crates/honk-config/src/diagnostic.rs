use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;

use tracing::warn;

/// One-release projection of detailed diagnostics. Data entrypoints never log.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigDiagnostic {
    pub setting: String,
    /// Arbitrary values are redacted; filters retain ordinals and policies are withheld.
    pub value: String,
    pub message: String,
}

/// Log each diagnostic as a structured warning. The plain entry points call this
/// at parse time; the daemon calls it once its subscriber is installed.
pub fn report_diagnostics(diagnostics: &[ConfigDiagnostic]) {
    for d in diagnostics {
        warn!(setting = %d.setting, value = %d.value, "{}", d.message);
    }
}

/// Metadata only: diagnostic ownership must never keep input buffers alive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticSource {
    pub path: Option<PathBuf>,
    pub parent: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct DiagnosticSources(Arc<RwLock<Vec<DiagnosticSource>>>);

impl DiagnosticSources {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self(Arc::new(RwLock::new(vec![DiagnosticSource {
            path,
            parent: None,
        }])))
    }

    pub fn root(&self) -> SourceRef {
        SourceRef {
            table: self.clone(),
            index: 0,
        }
    }

    pub fn add(&self, path: Option<PathBuf>, parent: Option<usize>) -> SourceRef {
        let mut sources = self.0.write();
        let index = sources.len();
        assert!(parent.is_none_or(|parent| parent < index));
        sources.push(DiagnosticSource { path, parent });
        SourceRef {
            table: self.clone(),
            index,
        }
    }

    pub fn metadata(&self) -> Vec<DiagnosticSource> {
        self.0.read().clone()
    }
}

/// A local index is meaningful only together with its owning attempt's table.
#[derive(Debug, Clone)]
pub struct SourceRef {
    table: DiagnosticSources,
    index: usize,
}

impl SourceRef {
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn sources(&self) -> &DiagnosticSources {
        &self.table
    }
    pub fn same_table(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.table.0, &other.table.0)
    }
    pub fn same_source(&self, other: &Self) -> bool {
        self.index == other.index && self.same_table(other)
    }
}

impl PartialEq for SourceRef {
    fn eq(&self, other: &Self) -> bool {
        self.same_source(other)
    }
}
impl Eq for SourceRef {}

impl std::hash::Hash for SourceRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&Arc::as_ptr(&self.table.0), state);
        std::hash::Hash::hash(&self.index, state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingSegment {
    Field(&'static str),
    Index(usize),
}

/// Schema names and original one-based ordinals, never operator-supplied names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingPath(pub Vec<SettingSegment>);

impl SettingPath {
    pub fn new(field: &'static str) -> Self {
        Self(vec![SettingSegment::Field(field)])
    }
    pub fn field(mut self, field: &'static str) -> Self {
        self.0.push(SettingSegment::Field(field));
        self
    }
    pub fn index(mut self, index: usize) -> Self {
        self.0.push(SettingSegment::Index(index));
        self
    }
}

impl std::fmt::Display for SettingPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, segment) in self.0.iter().enumerate() {
            match segment {
                SettingSegment::Field(field) => {
                    if index != 0 {
                        f.write_str(".")?;
                    }
                    f.write_str(field)?;
                }
                SettingSegment::Index(index) => write!(f, "[{index}]")?,
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeValue {
    Redacted,
    Empty,
    Ordinal(usize),
    Fields(Vec<&'static str>),
}

impl std::fmt::Display for SafeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redacted => f.write_str("<redacted>"),
            Self::Empty => Ok(()),
            Self::Ordinal(index) => write!(f, "{index}"),
            Self::Fields(fields) => {
                for (index, field) in fields.iter().enumerate() {
                    if index != 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(field)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedDiagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub source: SourceRef,
    pub span: Option<std::ops::Range<usize>>,
    pub line: Option<usize>,
    pub byte_column: Option<usize>,
    pub setting: SettingPath,
    pub value: SafeValue,
    pub message: &'static str,
    pub entry_index: Option<usize>,
    pub related_indices: Vec<usize>,
    pub terminal: bool,
}

impl DetailedDiagnostic {
    pub fn warning(
        code: &'static str,
        source: SourceRef,
        setting: SettingPath,
        value: SafeValue,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            severity: Severity::Warning,
            source,
            span: None,
            line: None,
            byte_column: None,
            setting,
            value,
            message,
            entry_index: None,
            related_indices: Vec::new(),
            terminal: false,
        }
    }

    pub fn to_legacy(&self) -> ConfigDiagnostic {
        ConfigDiagnostic {
            setting: self.setting.to_string(),
            value: self.value.to_string(),
            message: self.message.to_owned(),
        }
    }
}

// Legacy diagnostic producers cross the redaction boundary here.
pub(crate) fn project_legacy(d: ConfigDiagnostic, source: SourceRef) -> DetailedDiagnostic {
    let setting = [
        "global.tproxy_port",
        "global.tproxy_port_protect",
        "global.pprof_port",
        "global.so_mark_from_dae",
        "global.disable_waiting_network",
        "global.auto_config_kernel_parameter",
        "global.store_subscribe",
        "global.check_interval",
        "global.check_tolerance",
        "global.allow_insecure",
        "global.sniffing_timeout",
        "global.tls_fragment",
        "global.mptcp",
        "dns.ipversion_prefer",
        "dns.optimistic_cache",
        "dns.optimistic_cache_ttl",
        "dns.optimistic_stale_reply_ttl",
        "dns.max_cache_size",
        "experimental.clash_api.enabled",
        "experimental.cache_file.enabled",
        "experimental.cache_file.store_fakeip",
        "experimental.cache_file.store_rdrc",
        "experimental.cache_file.store_dns",
    ]
    .into_iter()
    .find(|setting| *setting == d.setting);
    let path = if let Some(setting) = setting {
        SettingPath(setting.split('.').map(SettingSegment::Field).collect())
    } else if d.setting.starts_with("group.") && d.setting.ends_with(".policy") {
        SettingPath::new("groups").field("policy")
    } else if d.setting.starts_with("group.") && d.setting.ends_with(".filter") {
        SettingPath::new("groups").field("filter")
    } else if d.setting.starts_with("subscription.") {
        SettingPath::new("subscriptions").field("interval")
    } else if d.setting.starts_with("dns.fixed_domain_ttl.") {
        SettingPath::new("dns").field("fixed_domain_ttl")
    } else {
        SettingPath::new("config")
    };
    let value = if d.setting.ends_with(".policy") {
        SafeValue::Empty
    } else if d.setting.ends_with(".filter") || d.setting.is_empty() {
        d.value
            .parse()
            .map(SafeValue::Ordinal)
            .unwrap_or(SafeValue::Redacted)
    } else {
        SafeValue::Redacted
    };
    macro_rules! message {
        ($($message:literal),* $(,)?) => {
            match d.message.as_str() {
                $($message => $message,)*
                _ => "invalid configuration value; keeping the default",
            }
        };
    }
    let message = message!(
        "unmatched `}` ignored",
        "group(...) is unterminated; ignored",
        "group(...) must be the whole filter line; ignored",
        "honk could not parse this filter; ignored",
        "policy is not recognised; using fallback selector",
        "duration is unsupported by honk; using fallback 0s",
        "duration is not milliseconds, `ms` or `s`; keeping the default (50ms)",
        "duration is not milliseconds, `ms` or `s`; keeping the default (100ms)",
        "duration is not milliseconds, `ms` or `s`; keeping the default (30ms)",
        "value is not a boolean spelling honk recognises; using fallback false",
        "honk could not parse this port as a decimal in 0-65535; using fallback 12345",
        "honk could not parse this port as a decimal in 0-65535; using fallback 0",
        "honk could not parse this mark as a u32; using fallback 0",
        "honk could not parse the preference as decimal 0, 4 or 6; using fallback: no preference",
        "honk could not parse this value as an unsigned decimal integer in range; using fallback 60",
        "honk could not parse this value as an unsigned decimal integer in range; using fallback 30",
        "honk could not parse this value as an unsigned decimal integer in range; using fallback 10000",
        "honk could not parse this TTL as an unsigned 32-bit decimal integer; entry ignored",
    );
    let mut diagnostic =
        DetailedDiagnostic::warning("legacy-config-warning", source, path, value, message);
    if d.setting.is_empty() {
        diagnostic.line = d.value.parse().ok();
    }
    diagnostic
}

pub(crate) fn legacy_nfqueue_warning(source: SourceRef) -> DetailedDiagnostic {
    DetailedDiagnostic::warning(
        "legacy-nfqueue",
        source,
        SettingPath::new("experimental")
            .field("udp_nfqueue")
            .field("enabled"),
        SafeValue::Redacted,
        "experimental.udp_nfqueue.enabled is deprecated; migrate to global.nfqueue_enable",
    )
}

/// Called by the outer attempt owner, not by nested readers or format probes.
pub fn finish_attempt<T>(
    result: Result<T, crate::error::DetailedConfigError>,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<T, crate::error::DetailedConfigError> {
    if let Err(error) = &result {
        diagnostics.push((*error.diagnostic).clone());
    }
    result
}

/// Terminal causes are rendered by the error return path, never replayed here.
pub fn report_detailed_diagnostics(diagnostics: &[DetailedDiagnostic]) {
    for d in diagnostics.iter().filter(|d| !d.terminal) {
        match d.severity {
            Severity::Info => {
                tracing::info!(code = d.code, setting = %d.setting, value = %d.value, "{}", d.message)
            }
            Severity::Warning => {
                tracing::warn!(code = d.code, setting = %d.setting, value = %d.value, "{}", d.message)
            }
            Severity::Error => {
                tracing::error!(code = d.code, setting = %d.setting, value = %d.value, "{}", d.message)
            }
        }
    }
}
