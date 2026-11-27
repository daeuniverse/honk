use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::Config;
use crate::datapath::{
    DatapathConfig, DatapathInput, REMOVED_HOST_XSK_MODE_CODE, REMOVED_HOST_XSK_MODE_MESSAGE,
    removed_host_xsk_mode_setting,
};
use crate::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SettingPath, SourceRef, report_detailed_diagnostics,
};
use crate::error::{DetailedConfigError, ErrorCategory};
use crate::node::{Node, RawNodeSeed};

pub(crate) const CONFIG_FIELDS: &[&str] = &[
    "global",
    "dns",
    "routing",
    "nodes",
    "groups",
    "subscriptions",
    "experimental",
    "assets",
    "datapath",
];

/// Public data-only adapter. Its serde errors are always redacted.
pub struct ConfigSeed<'a> {
    pub diagnostics: &'a mut Vec<DetailedDiagnostic>,
    pub source: SourceRef,
}

/// Internal adapter used by format-specific loaders before they project errors.
pub(super) struct RawConfigSeed<'a> {
    pub(super) diagnostics: &'a mut Vec<DetailedDiagnostic>,
    pub(super) source: SourceRef,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum Field {
    Global,
    Dns,
    Routing,
    Nodes,
    Groups,
    Subscriptions,
    Experimental,
    Assets,
    Datapath,
    #[serde(other)]
    Ignore,
}

impl<'de> DeserializeSeed<'de> for ConfigSeed<'_> {
    type Value = Config;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Config, D::Error> {
        let start = self.diagnostics.len();
        let result = RawConfigSeed {
            diagnostics: self.diagnostics,
            source: self.source,
        }
        .deserialize(deserializer);
        result.map_err(|_| {
            let reason = if self.diagnostics[start..]
                .iter()
                .any(|diagnostic| diagnostic.code == REMOVED_HOST_XSK_MODE_CODE)
            {
                REMOVED_HOST_XSK_MODE_MESSAGE
            } else {
                "invalid configuration fields"
            };
            D::Error::custom(reason)
        })
    }
}

impl<'de> DeserializeSeed<'de> for RawConfigSeed<'_> {
    type Value = Config;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Config, D::Error> {
        deserializer.deserialize_struct("Config", CONFIG_FIELDS, self)
    }
}

impl RawConfigSeed<'_> {
    fn datapath<E: serde::de::Error>(
        &mut self,
        input: Option<DatapathInput>,
    ) -> Result<Option<DatapathConfig>, E> {
        input
            .map(|input| {
                input.into_config(|| {
                    let error = DetailedConfigError::new(
                        ErrorCategory::Parse,
                        REMOVED_HOST_XSK_MODE_CODE,
                        self.source.clone(),
                        removed_host_xsk_mode_setting(),
                        REMOVED_HOST_XSK_MODE_MESSAGE,
                    );
                    self.diagnostics.push(*error.diagnostic);
                })
            })
            .transpose()
    }
}

impl<'de> Visitor<'de> for RawConfigSeed<'_> {
    type Value = Config;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a configuration")
    }
    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<Config, A::Error> {
        let mut config = Config::default();
        let mut seen = 0u16;
        while let Some(field) = map.next_key::<Field>()? {
            if matches!(field, Field::Ignore) {
                map.next_value::<serde::de::IgnoredAny>()?;
                continue;
            }
            let bit = 1 << field as u8;
            if seen & bit != 0 {
                return Err(A::Error::custom("duplicate configuration field"));
            }
            seen |= bit;
            match field {
                Field::Global => config.global = map.next_value()?,
                Field::Dns => config.dns = map.next_value()?,
                Field::Routing => config.routing = map.next_value()?,
                Field::Nodes => {
                    config.nodes = map.next_value_seed(RawNodesSeed {
                        diagnostics: self.diagnostics,
                        source: self.source.clone(),
                    })?
                }
                Field::Groups => {
                    config.groups = map.next_value()?;
                }
                Field::Subscriptions => config.subscriptions = map.next_value()?,
                Field::Experimental => {
                    let input: ExperimentalInput = map.next_value()?;
                    config.experimental = input.into_config(self.diagnostics, &self.source);
                    if config.experimental.legacy_udp_nfqueue.is_some() {
                        self.diagnostics
                            .push(crate::diagnostic::legacy_nfqueue_warning(
                                self.source.clone(),
                            ));
                    }
                    for key in config.experimental.cache_file.legacy_keys() {
                        self.diagnostics
                            .push(crate::diagnostic::legacy_cache_file_warning(
                                self.source.clone(),
                                key,
                            ));
                    }
                    if let Some(diagnostic) = config
                        .experimental
                        .clash_api
                        .exposure_diagnostic(self.source.clone())
                    {
                        self.diagnostics.push(diagnostic);
                    }
                }
                Field::Assets => config.assets = map.next_value()?,
                Field::Datapath => config.datapath = self.datapath(map.next_value()?)?,
                Field::Ignore => unreachable!(),
            }
        }
        Ok(config)
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Config, A::Error> {
        // Derived Config serde also accepts sequences in declaration order.
        let global = seq.next_element()?.unwrap_or_default();
        let dns = seq.next_element()?.unwrap_or_default();
        let routing = seq.next_element()?.unwrap_or_default();
        let nodes = seq
            .next_element_seed(RawNodesSeed {
                diagnostics: self.diagnostics,
                source: self.source.clone(),
            })?
            .unwrap_or_default();
        let groups: Vec<crate::node::Group> = seq.next_element()?.unwrap_or_default();
        let subscriptions = seq.next_element()?.unwrap_or_default();
        let input: ExperimentalInput = seq.next_element()?.unwrap_or_default();
        let experimental = input.into_config(self.diagnostics, &self.source);
        let assets = seq.next_element()?.unwrap_or_default();
        let datapath = self.datapath(seq.next_element()?.unwrap_or_default())?;
        if experimental.legacy_udp_nfqueue.is_some() {
            self.diagnostics
                .push(crate::diagnostic::legacy_nfqueue_warning(
                    self.source.clone(),
                ));
        }
        for key in experimental.cache_file.legacy_keys() {
            self.diagnostics
                .push(crate::diagnostic::legacy_cache_file_warning(
                    self.source.clone(),
                    key,
                ));
        }
        if let Some(diagnostic) = experimental
            .clash_api
            .exposure_diagnostic(self.source.clone())
        {
            self.diagnostics.push(diagnostic);
        }
        Ok(Config {
            global,
            dns,
            routing,
            nodes,
            groups,
            subscriptions,
            experimental,
            assets,
            datapath,
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ExperimentalInput {
    clash_api: crate::experimental::ClashApiConfig,
    cache_file: crate::experimental::CacheFileConfig,
    native_api: NativeApiInput,
    udp_nfqueue: Option<crate::experimental::LegacyUdpNfqueueConfig>,
}

impl ExperimentalInput {
    fn into_config(
        self,
        diagnostics: &mut Vec<DetailedDiagnostic>,
        source: &SourceRef,
    ) -> crate::experimental::ExperimentalConfig {
        for (key, present) in [
            ("probe_allowed_cidrs", self.native_api.probe_allowed_cidrs),
            ("probe_allowed_ports", self.native_api.probe_allowed_ports),
        ] {
            if present {
                diagnostics.push(DetailedDiagnostic::warning(
                    "legacy-config-warning",
                    source.clone(),
                    SettingPath::new("experimental")
                        .field("native_api")
                        .field(key),
                    crate::diagnostic::SafeValue::Redacted,
                    "setting was removed and can be deleted; its value is ignored",
                ));
            }
        }
        crate::experimental::ExperimentalConfig {
            clash_api: self.clash_api,
            cache_file: self.cache_file,
            native_api: self.native_api.config,
            legacy_udp_nfqueue: self.udp_nfqueue,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeApiInput {
    #[serde(flatten)]
    config: crate::experimental::NativeApiConfig,
    #[serde(default, deserialize_with = "removed_setting")]
    probe_allowed_cidrs: bool,
    #[serde(default, deserialize_with = "removed_setting")]
    probe_allowed_ports: bool,
}

fn removed_setting<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(deserializer).map(|_| true)
}

struct RawNodesSeed<'a> {
    diagnostics: &'a mut Vec<DetailedDiagnostic>,
    source: SourceRef,
}
impl<'de> DeserializeSeed<'de> for RawNodesSeed<'_> {
    type Value = Vec<Node>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for RawNodesSeed<'_> {
    type Value = Vec<Node>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a node sequence")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut nodes = Vec::new();
        while let Some(node) = seq.next_element_seed(RawNodeSeed {
            diagnostics: self.diagnostics,
            source: self.source.clone(),
            setting: SettingPath::new("nodes").index(nodes.len() + 1),
            record_semantic: true,
        })? {
            nodes.push(node);
        }
        Ok(nodes)
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut diagnostics = Vec::new();
        let result = ConfigSeed {
            diagnostics: &mut diagnostics,
            source: DiagnosticSources::new(None).root(),
        }
        .deserialize(deserializer);
        report_detailed_diagnostics(&diagnostics);
        result
    }
}
