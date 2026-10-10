use std::collections::HashMap;

use super::cursor::Segment;
use super::diagnostics::ParserDiagnostics;
use super::read::{self, Text};
use crate::config::GlobalConfig;
use crate::diagnostic::{SettingPath, SettingSegment, Severity};
use crate::experimental::ExperimentalConfig;

const LEGACY_LIST_MESSAGE: &str =
    "list quoting is deprecated; quote list items individually or use bare items";
const LEGACY_BOOL_MESSAGE: &str = "boolean shorthand is deprecated; use true or false";

fn scalar_path(setting: &'static str) -> SettingPath {
    SettingPath(setting.split('.').map(SettingSegment::Field).collect())
}

pub(super) fn strict_bool(value: &str) -> Option<bool> {
    if ["true", "yes", "1", "on"]
        .iter()
        .any(|spelling| value.eq_ignore_ascii_case(spelling))
    {
        Some(true)
    } else if ["false", "no", "0", "off"]
        .iter()
        .any(|spelling| value.eq_ignore_ascii_case(spelling))
    {
        Some(false)
    } else {
        None
    }
}

fn scalar_warning(
    text: Text<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
    setting: &'static str,
    message: &'static str,
) {
    let mut diagnostic = text.source.diagnostic(
        text.span,
        Severity::Warning,
        "legacy-config-warning",
        message,
    );
    diagnostic.setting = scalar_path(setting);
    diagnostics.emit(diagnostic);
}

fn scalar_error(
    text: Text<'_, '_>,
    code: &'static str,
    setting: &'static str,
    message: &'static str,
) -> crate::error::DetailedConfigError {
    let mut error = crate::error::DetailedConfigError::new(
        crate::error::ErrorCategory::Parse,
        code,
        text.source.reference(),
        scalar_path(setting),
        message,
    );
    let (line, column) = text.source.location(text.span.start);
    error.diagnostic.line = Some(line);
    error.diagnostic.span = Some(text.span.start..text.span.end);
    error.diagnostic.byte_column = Some(column);
    error
}

const GLOBAL_KEYS: &[&str] = &[
    "tproxy_port",
    "tproxy_port_protect",
    "pprof_port",
    "so_mark_from_dae",
    "log_level",
    "log_file",
    "disable_waiting_network",
    "lan_interface",
    "wan_interface",
    "auto_config_kernel_parameter",
    "data_dir",
    "store_subscribe",
    "tcp_check_url",
    "tcp_check_http_method",
    "udp_check_dns",
    "check_interval",
    "check_tolerance",
    "dial_mode",
    "nfqueue_enable",
    "allow_insecure",
    "sniffing_timeout",
    "tls_implementation",
    "utls_imitate",
    "tls_fragment",
    "tls_fragment_length",
    "tls_fragment_interval",
    "mptcp",
    "bootstrap_resolver",
    "fallback_resolver",
    "bandwidth_max_tx",
    "bandwidth_max_rx",
    "udp_warm_node_count",
    "preconnect_node_count",
    "max_concurrent_dials",
];

fn raw_fields<'d, 'a>(
    section: &[Segment<'d, 'a>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> HashMap<&'d str, Text<'d, 'a>> {
    let mut raw = HashMap::new();
    for line in read::statements(section, diagnostics, super::cursor::BodySyntax::Statements) {
        let Some((key, value)) = line.kv() else {
            line.notice(
                diagnostics,
                Severity::Warning,
                "unknown-statement",
                "unknown scalar statement ignored",
            );
            continue;
        };
        if !GLOBAL_KEYS.contains(&key.raw()) {
            key.notice(
                diagnostics,
                Severity::Warning,
                "unknown-key",
                "unknown scalar key ignored",
            );
            continue;
        }
        diagnostics.register_field(key.raw(), value);
        value.warn_glued_hash(diagnostics);
        raw.insert(key.raw(), value);
    }
    raw
}

pub(super) fn bool_value(
    settings: &HashMap<&str, Text<'_, '_>>,
    key: &str,
    setting: &'static str,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> bool {
    let Some(text) = settings.get(key) else {
        return false;
    };
    let value = text.unquote().raw();
    let shorthand = value.len() == 1
        && matches!(
            value.as_bytes()[0].to_ascii_lowercase(),
            b'f' | b'n' | b't' | b'y'
        );
    let parsed = match strict_bool(value) {
        Some(parsed) => parsed,
        None if shorthand => false,
        None => {
            scalar_warning(
                *text,
                diagnostics,
                setting,
                "value is not a boolean spelling honk recognises; using fallback false",
            );
            false
        }
    };
    if shorthand {
        text.notice(
            diagnostics,
            Severity::Warning,
            "legacy-bool-shorthand",
            LEGACY_BOOL_MESSAGE,
        );
    }
    parsed
}

#[derive(Clone, Copy)]
struct ListOptions {
    aggregate_compat: bool,
    legacy_unquote_items: bool,
    filter_empty: bool,
    legacy_notice: bool,
}

impl ListOptions {
    const INTERFACES: Self = Self {
        aggregate_compat: false,
        legacy_unquote_items: false,
        filter_empty: true,
        legacy_notice: true,
    };
    const CHECK_TARGETS: Self = Self {
        aggregate_compat: true,
        legacy_unquote_items: true,
        filter_empty: false,
        legacy_notice: true,
    };
    /// A setting that never existed before the item-wise parser: there is no legacy
    /// reading to compare against, so quoting differences are not migration notices.
    const NEW: Self = Self {
        aggregate_compat: false,
        legacy_unquote_items: false,
        filter_empty: false,
        legacy_notice: false,
    };
}

fn list_value(
    value: Text<'_, '_>,
    options: ListOptions,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Vec<String> {
    let ListOptions {
        aggregate_compat,
        legacy_unquote_items,
        filter_empty,
        legacy_notice,
    } = options;
    let trimmed = value.trim();
    let whole_quoted = trimmed
        .quoted_prefix()
        .is_some_and(|quoted| quoted.span == trimmed.span);
    let aggregate = aggregate_compat && whole_quoted && trimmed.unquote().raw().contains(',');
    let source = if aggregate {
        trimmed.unquote()
    } else {
        trimmed
    };
    let parsed: Vec<String> = source
        .split(",")
        .map(|item| item.unquote().raw().to_owned())
        .filter(|item| !filter_empty || !item.is_empty())
        .collect();

    let legacy_source = trimmed.raw().trim_matches('\'').trim_matches('"');
    let legacy = legacy_source
        .split(',')
        .map(str::trim)
        .map(|item| {
            if legacy_unquote_items {
                item.trim_matches('\'')
            } else {
                item
            }
        })
        .filter(|item| !filter_empty || !item.is_empty());
    if aggregate || (legacy_notice && !parsed.iter().map(String::as_str).eq(legacy)) {
        trimmed.notice(
            diagnostics,
            Severity::Warning,
            if aggregate {
                "legacy-quoted-list"
            } else {
                "legacy-list-quoting"
            },
            LEGACY_LIST_MESSAGE,
        );
    }
    parsed
}

pub(super) fn parse_global_section(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<GlobalConfig, super::ParseFailure> {
    let settings = raw_fields(section, diagnostics);
    let mut cfg = GlobalConfig::default();

    if let Some(text) = settings.get("tproxy_port") {
        let value = text.unquote().raw();
        cfg.tproxy_port = match value.parse() {
            Ok(value) => value,
            Err(_) => {
                scalar_warning(
                    *text,
                    diagnostics,
                    "global.tproxy_port",
                    "honk could not parse this port as a decimal in 0-65535; using fallback 12345",
                );
                12345
            }
        };
    }
    if settings.contains_key("tproxy_port_protect") {
        cfg.tproxy_port_protect = bool_value(
            &settings,
            "tproxy_port_protect",
            "global.tproxy_port_protect",
            diagnostics,
        );
    }
    if let Some(text) = settings.get("pprof_port") {
        let value = text.unquote().raw();
        cfg.pprof_port = match value.parse() {
            Ok(value) => value,
            Err(_) => {
                scalar_warning(
                    *text,
                    diagnostics,
                    "global.pprof_port",
                    "honk could not parse this port as a decimal in 0-65535; using fallback 0",
                );
                0
            }
        };
    }
    if let Some(text) = settings.get("so_mark_from_dae") {
        let value = text.unquote().raw();
        cfg.so_mark_from_dae = match super::parse_hex_or_dec(value) {
            Some(value) => value,
            None => {
                scalar_warning(
                    *text,
                    diagnostics,
                    "global.so_mark_from_dae",
                    "honk could not parse this mark as a u32; using fallback 0",
                );
                0
            }
        };
    }
    if let Some(value) = settings.get("log_level").map(|text| text.unquote().raw()) {
        cfg.log_level = value.to_owned();
    }
    if let Some(value) = settings.get("log_file").map(|text| text.unquote().raw()) {
        cfg.log_file = value.to_owned();
    }
    if settings.contains_key("disable_waiting_network") {
        cfg.disable_waiting_network = bool_value(
            &settings,
            "disable_waiting_network",
            "global.disable_waiting_network",
            diagnostics,
        );
    }
    if let Some(value) = settings.get("lan_interface") {
        cfg.lan_interface = list_value(*value, ListOptions::INTERFACES, diagnostics);
    }
    if let Some(value) = settings.get("wan_interface") {
        cfg.wan_interface = list_value(*value, ListOptions::INTERFACES, diagnostics);
    }
    if settings.contains_key("auto_config_kernel_parameter") {
        cfg.auto_config_kernel_parameter = bool_value(
            &settings,
            "auto_config_kernel_parameter",
            "global.auto_config_kernel_parameter",
            diagnostics,
        );
    }
    if let Some(value) = settings.get("data_dir").map(|text| text.unquote().raw()) {
        cfg.data_dir = value.to_owned();
    }
    if settings.contains_key("store_subscribe") {
        cfg.store_subscribe = bool_value(
            &settings,
            "store_subscribe",
            "global.store_subscribe",
            diagnostics,
        );
    }
    if let Some(value) = settings.get("tcp_check_url") {
        cfg.tcp_check_url = list_value(*value, ListOptions::CHECK_TARGETS, diagnostics);
    }
    if let Some(value) = settings
        .get("tcp_check_http_method")
        .map(|text| text.unquote().raw())
    {
        cfg.tcp_check_http_method = value.to_owned();
    }
    if let Some(value) = settings.get("udp_check_dns") {
        cfg.udp_check_dns = list_value(*value, ListOptions::CHECK_TARGETS, diagnostics);
    }
    if let Some(text) = settings.get("check_interval") {
        let value = text.unquote().raw();
        cfg.check_interval_secs = match crate::types::parse_duration_secs(value) {
            Some(value) => value,
            None => {
                scalar_warning(
                    *text,
                    diagnostics,
                    "global.check_interval",
                    "duration is unsupported by honk; using fallback 0s",
                );
                0
            }
        };
    }
    if let Some(text) = settings.get("check_tolerance") {
        let value = text.unquote().raw();
        cfg.check_tolerance_ms = match crate::types::parse_duration_ms(value) {
            Some(value) => value,
            None => {
                scalar_warning(
                    *text,
                    diagnostics,
                    "global.check_tolerance",
                    "duration is not milliseconds, `ms` or `s`; keeping the default (50ms)",
                );
                cfg.check_tolerance_ms
            }
        };
    }
    if let Some(value) = settings.get("dial_mode").map(|text| text.unquote().raw()) {
        cfg.dial_mode = value.to_owned();
    }
    if let Some(value) = settings.get("nfqueue_enable") {
        cfg.nfqueue_enable = strict_bool(value.unquote().raw()).ok_or_else(|| {
            scalar_error(
                *value,
                "invalid-config-value",
                "global.nfqueue_enable",
                "expected true/false, yes/no, 1/0 or on/off",
            )
        })?;
    }
    if settings.contains_key("allow_insecure") {
        cfg.allow_insecure = bool_value(
            &settings,
            "allow_insecure",
            "global.allow_insecure",
            diagnostics,
        );
    }
    if let Some(text) = settings.get("sniffing_timeout") {
        let value = text.unquote().raw();
        cfg.sniffing_timeout_ms = match crate::types::parse_duration_ms(value) {
            Some(value) => value,
            None => {
                scalar_warning(
                    *text,
                    diagnostics,
                    "global.sniffing_timeout",
                    "duration is not milliseconds, `ms` or `s`; keeping the default (30ms)",
                );
                cfg.sniffing_timeout_ms
            }
        };
    }
    if let Some(value) = settings
        .get("tls_implementation")
        .map(|text| text.unquote().raw())
    {
        cfg.tls_implementation = value.to_owned();
    }
    if let Some(value) = settings
        .get("utls_imitate")
        .map(|text| text.unquote().raw())
    {
        cfg.utls_imitate = value.to_owned();
    }
    if settings.contains_key("tls_fragment") {
        cfg.tls_fragment = bool_value(
            &settings,
            "tls_fragment",
            "global.tls_fragment",
            diagnostics,
        );
    }
    if let Some(value) = settings
        .get("tls_fragment_length")
        .map(|text| text.unquote().raw())
    {
        cfg.tls_fragment_length = value.to_owned();
    }
    if let Some(value) = settings
        .get("tls_fragment_interval")
        .map(|text| text.unquote().raw())
    {
        cfg.tls_fragment_interval = value.to_owned();
    }
    if settings.contains_key("mptcp") {
        cfg.mptcp = bool_value(&settings, "mptcp", "global.mptcp", diagnostics);
    }
    if let Some(value) = settings
        .get("bootstrap_resolver")
        .map(|text| text.unquote().raw())
    {
        cfg.bootstrap_resolver = value.to_owned();
    }
    if let Some(value) = settings
        .get("fallback_resolver")
        .map(|text| text.unquote().raw())
    {
        cfg.fallback_resolver = value.to_owned();
    }
    if let Some(value) = settings
        .get("bandwidth_max_tx")
        .map(|text| text.unquote().raw())
    {
        cfg.bandwidth_max_tx = value.to_owned();
    }
    if let Some(value) = settings
        .get("bandwidth_max_rx")
        .map(|text| text.unquote().raw())
    {
        cfg.bandwidth_max_rx = value.to_owned();
    }
    if let Some(text) = settings.get("udp_warm_node_count") {
        let value = text.unquote().raw();
        cfg.udp_warm_node_count = value.parse().map_err(|_| {
            scalar_error(
                *text,
                "invalid-config-value",
                "global.udp_warm_node_count",
                "expected a nonnegative integer",
            )
        })?;
    }
    if let Some(text) = settings.get("preconnect_node_count") {
        let value = text.unquote().raw();
        cfg.preconnect_node_count = if value.eq_ignore_ascii_case("auto") {
            crate::config::PRECONNECT_NODE_COUNT_AUTO
        } else {
            value.parse().map_err(|_| {
                scalar_error(
                    *text,
                    "invalid-config-value",
                    "global.preconnect_node_count",
                    "expected a nonnegative integer or auto",
                )
            })?
        };
    }
    if let Some(text) = settings.get("max_concurrent_dials") {
        let value = text.unquote().raw();
        cfg.max_concurrent_dials = value.parse().map_err(|_| {
            scalar_error(
                *text,
                "invalid-config-value",
                "global.max_concurrent_dials",
                "expected a nonnegative integer",
            )
        })?;
    }

    crate::check::validate_dns_check_targets(&cfg.udp_check_dns).map_err(|mut error| {
        if let Some(value) = settings.get("udp_check_dns") {
            let (line, column) = value.source.location(value.span.start);
            error.diagnostic.source = value.source.reference();
            error.diagnostic.line = Some(line);
            error.diagnostic.span = Some(value.span.start..value.span.end);
            error.diagnostic.byte_column = Some(column);
        } else {
            error.diagnostic.source = diagnostics.source();
        }
        super::ParseFailure::Detailed(error)
    })?;
    Ok(cfg)
}

pub(super) fn nfqueue_present(section: &[Segment<'_, '_>]) -> bool {
    section.iter().any(|segment| {
        let Some(body) = segment.body() else {
            return false;
        };
        for child in body {
            if read::block_header(&child).is_none()
                && Text::segment(&child)
                    .kv()
                    .is_some_and(|(key, _)| key.raw() == "nfqueue_enable")
            {
                return true;
            }
        }
        false
    })
}

const CLASH_API_KEYS: &[&str] = &[
    "external_controller",
    "external_ui",
    "external_ui_download_url",
    "external_ui_download_detour",
    "secret",
    "default_mode",
];
const CACHE_FILE_KEYS: &[&str] = &["enabled", "path", "cache_id", "store_fakeip", "store_dns"];
const UDP_NFQUEUE_KEYS: &[&str] = &["enabled"];
const NATIVE_API_KEYS: &[&str] = &[
    "enabled",
    "listen",
    "secret",
    "password_auth",
    "allow_anonymous_loopback",
    "allow_origins",
    "allowed_hosts",
    "ui",
    "record_flows",
    "record_traffic",
    "record_memory",
    "record_logs",
    "record_dns_log",
    "config_write",
    "geosite_download_url",
    "geoip_download_url",
    "geodata_download_detour",
];

/// Experimental blocks, their keys, and the hint for a key only that block owns.
const EXPERIMENTAL_BLOCKS: [(&str, &[&str], &str); 4] = [
    (
        "clash_api",
        CLASH_API_KEYS,
        "clash API setting belongs inside clash_api { }",
    ),
    (
        "cache_file",
        CACHE_FILE_KEYS,
        "cache file setting belongs inside cache_file { }",
    ),
    (
        "udp_nfqueue",
        UDP_NFQUEUE_KEYS,
        "NFQUEUE setting belongs inside udp_nfqueue { }",
    ),
    (
        "native_api",
        NATIVE_API_KEYS,
        "native API setting belongs inside native_api { }",
    ),
];

/// Diagnostics carry schema names only, so an unknown key is named back only
/// when honk knows it from another section.
fn schema_key(key: &str) -> Option<&'static str> {
    EXPERIMENTAL_BLOCKS
        .iter()
        .map(|(_, keys, _)| *keys)
        .chain([GLOBAL_KEYS])
        .flatten()
        .copied()
        .find(|known| *known == key)
}

fn unknown_experimental_setting(
    text: Text<'_, '_>,
    key: &str,
) -> crate::error::DetailedConfigError {
    let mut error = scalar_error(
        text,
        "unknown-experimental-setting",
        "experimental",
        "unknown experimental setting",
    );
    if let Some(key) = schema_key(key) {
        error.diagnostic.setting.0.push(SettingSegment::Field(key));
        let mut owners = EXPERIMENTAL_BLOCKS
            .iter()
            .filter(|(_, keys, _)| keys.contains(&key));
        // A key several blocks share (`enabled`, `secret`) has no single home.
        if let (Some((_, _, hint)), None) = (owners.next(), owners.next()) {
            error.diagnostic.message = hint;
        }
    }
    error
}

pub(super) fn parse_experimental_section(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<ExperimentalConfig, super::ParseFailure> {
    let mut config = ExperimentalConfig::default();
    let mut api_location = None;
    for root in section {
        let Some(body) = root.body() else {
            continue;
        };
        for segment in body {
            diagnostics.at_text(Text::segment(&segment));
            let Some(header) = read::block_header(&segment) else {
                let text = Text::segment(&segment);
                let key = text.kv().map_or(text, |(key, _)| key).raw();
                return Err(unknown_experimental_setting(text, key).into());
            };
            let name = header.raw();
            let mut values = HashMap::new();
            let Some(&(_, known_keys, _)) = EXPERIMENTAL_BLOCKS
                .iter()
                .find(|(block, _, _)| *block == name)
            else {
                return Err(unknown_experimental_setting(header, name).into());
            };
            let strict_section = matches!(name, "udp_nfqueue" | "native_api");
            let strict_error = |text, key: &str| {
                let mut error = if name == "native_api" {
                    scalar_error(
                        text,
                        "unknown-native-api-setting",
                        "experimental.native_api",
                        "unknown native API setting",
                    )
                } else {
                    scalar_error(
                        text,
                        "unknown-nfqueue-setting",
                        "experimental.udp_nfqueue",
                        "unknown NFQUEUE setting; only enabled is supported",
                    )
                };
                if let Some(key) = schema_key(key) {
                    error.diagnostic.setting.0.push(SettingSegment::Field(key));
                }
                error
            };
            let lines = if strict_section {
                let mut lines = Vec::new();
                if let Some(body) = segment.body() {
                    for child in body {
                        let text = Text::segment(&child);
                        diagnostics.at_text(text);
                        if let Some(header) = read::block_header(&child) {
                            return Err(strict_error(text, header.raw()).into());
                        }
                        lines.push(text);
                    }
                }
                lines
            } else {
                read::child_statements(&segment, diagnostics, super::cursor::BodySyntax::Statements)
            };
            for line in lines {
                diagnostics.at_text(line);
                let Some((key, value)) = line.kv() else {
                    if strict_section {
                        return Err(strict_error(line, line.raw()).into());
                    }
                    line.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-statement",
                        "unknown scalar statement ignored",
                    );
                    continue;
                };
                if name == "native_api"
                    && matches!(key.raw(), "probe_allowed_cidrs" | "probe_allowed_ports")
                {
                    scalar_warning(
                        key,
                        diagnostics,
                        if key.raw() == "probe_allowed_cidrs" {
                            "experimental.native_api.probe_allowed_cidrs"
                        } else {
                            "experimental.native_api.probe_allowed_ports"
                        },
                        "setting was removed and can be deleted; its value is ignored",
                    );
                    continue;
                }
                if !known_keys.contains(&key.raw()) {
                    if strict_section {
                        return Err(strict_error(line, key.raw()).into());
                    }
                    key.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-key",
                        "unknown scalar key ignored",
                    );
                    continue;
                }
                diagnostics.register_field(key.raw(), value);
                if let Some(&(block, key, message)) = crate::diagnostic::LEGACY_ASSETS_KEYS
                    .iter()
                    .find(|(block, legacy, _)| *block == name && *legacy == key.raw())
                {
                    diagnostics.emit(crate::diagnostic::legacy_assets_warning(
                        diagnostics.source(),
                        block,
                        key,
                        message,
                    ));
                }
                if name == "clash_api" && key.raw() == "external_controller" {
                    api_location = Some(diagnostics.field_location("external_controller"));
                }
                value.warn_glued_hash(diagnostics);
                values.insert(key.raw(), value);
            }
            match name {
                "clash_api" => {
                    if let Some(value) = values
                        .get("external_controller")
                        .map(|text| text.unquote().raw())
                    {
                        config.clash_api.external_controller = value.to_owned();
                    }
                    if let Some(value) = values.get("external_ui").map(|text| text.unquote().raw())
                    {
                        config.clash_api.external_ui = value.to_owned();
                    }
                    if let Some(value) = values
                        .get("external_ui_download_url")
                        .map(|text| text.unquote().raw())
                    {
                        config.clash_api.external_ui_download_url = value.to_owned();
                    }
                    if let Some(value) = values
                        .get("external_ui_download_detour")
                        .map(|text| text.unquote().raw())
                    {
                        config.clash_api.external_ui_download_detour = value.to_owned();
                    }
                    if let Some(value) = values.get("secret").map(|text| text.unquote().raw()) {
                        config.clash_api.secret = value.to_owned();
                    }
                    if let Some(value) = values.get("default_mode").map(|text| text.unquote().raw())
                    {
                        config.clash_api.default_mode = value.to_owned();
                    }
                }
                "cache_file" => {
                    if values.contains_key("enabled") {
                        config.cache_file.enabled = Some(bool_value(
                            &values,
                            "enabled",
                            "experimental.cache_file.enabled",
                            diagnostics,
                        ));
                    }
                    if let Some(value) = values.get("path").map(|text| text.unquote().raw()) {
                        config.cache_file.legacy_path = Some(value.to_owned());
                    }
                    if let Some(value) = values.get("cache_id").map(|text| text.unquote().raw()) {
                        config.cache_file.legacy_cache_id = Some(value.to_owned());
                    }
                    if let Some(value) = values.get("store_fakeip") {
                        config.cache_file.legacy_store_fakeip =
                            Some(strict_bool(value.unquote().raw()).unwrap_or(false));
                    }
                    for key in config
                        .cache_file
                        .legacy_keys()
                        .filter(|key| values.contains_key(key))
                    {
                        diagnostics.emit(crate::diagnostic::legacy_cache_file_warning(
                            diagnostics.source(),
                            key,
                        ));
                    }
                    if values.contains_key("store_dns") {
                        config.cache_file.store_dns = bool_value(
                            &values,
                            "store_dns",
                            "experimental.cache_file.store_dns",
                            diagnostics,
                        );
                    }
                }
                "native_api" => {
                    for (key, setting, target) in [
                        (
                            "enabled",
                            "experimental.native_api.enabled",
                            &mut config.native_api.enabled,
                        ),
                        (
                            "record_flows",
                            "experimental.native_api.record_flows",
                            &mut config.native_api.record_flows,
                        ),
                        (
                            "record_traffic",
                            "experimental.native_api.record_traffic",
                            &mut config.native_api.record_traffic,
                        ),
                        (
                            "record_memory",
                            "experimental.native_api.record_memory",
                            &mut config.native_api.record_memory,
                        ),
                        (
                            "record_logs",
                            "experimental.native_api.record_logs",
                            &mut config.native_api.record_logs,
                        ),
                        (
                            "record_dns_log",
                            "experimental.native_api.record_dns_log",
                            &mut config.native_api.record_dns_log,
                        ),
                        (
                            "config_write",
                            "experimental.native_api.config_write",
                            &mut config.native_api.config_write,
                        ),
                        (
                            "allow_anonymous_loopback",
                            "experimental.native_api.allow_anonymous_loopback",
                            &mut config.native_api.allow_anonymous_loopback,
                        ),
                        (
                            "password_auth",
                            "experimental.native_api.password_auth",
                            &mut config.native_api.password_auth,
                        ),
                    ] {
                        if let Some(text) = values.get(key) {
                            *target = strict_bool(text.unquote().raw()).ok_or_else(|| {
                                scalar_error(
                                    *text,
                                    "invalid-config-value",
                                    setting,
                                    "expected true/false, yes/no, 1/0 or on/off",
                                )
                            })?;
                        }
                    }
                    for (key, target) in [
                        ("listen", &mut config.native_api.listen),
                        ("secret", &mut config.native_api.secret),
                        ("ui", &mut config.native_api.ui),
                        (
                            "geosite_download_url",
                            &mut config.native_api.geosite_download_url,
                        ),
                        (
                            "geoip_download_url",
                            &mut config.native_api.geoip_download_url,
                        ),
                        (
                            "geodata_download_detour",
                            &mut config.native_api.geodata_download_detour,
                        ),
                    ] {
                        if let Some(text) = values.get(key) {
                            *target = text.unquote().raw().to_owned();
                        }
                    }
                    for (key, setting, target) in [
                        (
                            "allowed_hosts",
                            "experimental.native_api.allowed_hosts",
                            &mut config.native_api.allowed_hosts,
                        ),
                        (
                            "allow_origins",
                            "experimental.native_api.allow_origins",
                            &mut config.native_api.allow_origins,
                        ),
                    ] {
                        if let Some(text) = values.get(key) {
                            let items = list_value(*text, ListOptions::NEW, diagnostics);
                            let invalid = items.iter().any(|value| {
                                if key == "allowed_hosts" {
                                    crate::experimental::parse_native_authority(value, 80).is_none()
                                } else {
                                    crate::experimental::parse_native_origin(value).is_none()
                                }
                            });
                            if invalid {
                                return Err(scalar_error(
                                    *text,
                                    "invalid-config-value",
                                    setting,
                                    "expected individually quoted nonempty authorities or origins",
                                )
                                .into());
                            }
                            *target = items;
                        }
                    }
                }
                "udp_nfqueue" => {
                    let enabled = values
                        .get("enabled")
                        .map(|text| {
                            strict_bool(text.unquote().raw()).ok_or_else(|| {
                                scalar_error(
                                    *text,
                                    "invalid-config-value",
                                    "experimental.udp_nfqueue",
                                    "expected true/false, yes/no, 1/0 or on/off",
                                )
                            })
                        })
                        .transpose()?;
                    config.legacy_udp_nfqueue = Some(crate::experimental::LegacyUdpNfqueueConfig {
                        enabled: enabled.unwrap_or(false),
                    });
                    diagnostics.emit(crate::diagnostic::legacy_nfqueue_warning(
                        diagnostics.source(),
                    ));
                }
                _ => {
                    return Err(scalar_error(
                        header,
                        "unknown-experimental-setting",
                        "experimental",
                        "unknown experimental setting",
                    )
                    .into());
                }
            }
        }
    }
    if let Some((source, line)) = api_location
        && let Some(mut diagnostic) = config.clash_api.exposure_diagnostic(source)
    {
        diagnostic.line = line;
        diagnostics.output.push(diagnostic);
    }
    Ok(config)
}
