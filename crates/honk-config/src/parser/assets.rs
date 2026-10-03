//! `assets { route, geodata { … }, ui { … }, subscription { … } }`.

use super::cursor::Segment;
use super::diagnostics::ParserDiagnostics;
use super::read::{self, Text};
use crate::Config;
use crate::assets::AssetsConfig;
use crate::diagnostic::{ConfigDiagnostic, SafeValue, SettingPath, Severity};
use crate::error::{DetailedConfigError, ErrorCategory};

/// The block as written; geodata and UI values stay separate until
/// [`apply`] checks them against the old `experimental` keys.
#[derive(Default)]
pub(super) struct ParsedAssets<'d, 'a> {
    pub(super) config: AssetsConfig,
    geosite: Option<Text<'d, 'a>>,
    geoip: Option<Text<'d, 'a>>,
    geodata_route: Option<Text<'d, 'a>>,
    ui_url: Option<Text<'d, 'a>>,
    ui_route: Option<Text<'d, 'a>>,
}

const SUB_BLOCKS: [(&str, &[&str]); 3] = [
    ("geodata", &["geosite", "geoip", "route"]),
    ("ui", &["url", "route"]),
    ("subscription", &["ua", "interval", "cache"]),
];

pub(super) fn parse_section<'d, 'a>(
    section: &[Segment<'d, 'a>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> ParsedAssets<'d, 'a> {
    let mut parsed = ParsedAssets::default();
    for root in section {
        let Some(body) = root.body() else {
            continue;
        };
        for child in body {
            let text = Text::segment(&child);
            diagnostics.at_text(text);
            if let Some(header) = read::block_header(&child) {
                let Some(&(name, keys)) =
                    SUB_BLOCKS.iter().find(|(block, _)| *block == header.raw())
                else {
                    header.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-block",
                        "unknown assets block ignored; expected geodata, ui or subscription",
                    );
                    continue;
                };
                for line in read::child_statements(
                    &child,
                    diagnostics,
                    super::cursor::BodySyntax::Statements,
                ) {
                    diagnostics.at_text(line);
                    match line.kv() {
                        Some((key, value)) if keys.contains(&key.raw()) => {
                            diagnostics.register_field(key.raw(), value);
                            parsed.set(name, key.raw(), value.unquote(), diagnostics);
                        }
                        Some((key, _)) => key.notice(
                            diagnostics,
                            Severity::Warning,
                            "unknown-key",
                            "unknown scalar key ignored",
                        ),
                        None => line.notice(
                            diagnostics,
                            Severity::Warning,
                            "unknown-statement",
                            "unknown scalar statement ignored",
                        ),
                    }
                }
                continue;
            }
            match text.trim().kv() {
                Some((key, value)) if key.raw() == "route" => {
                    diagnostics.register_field("route", value);
                    parsed.config.route = value.unquote().raw().to_owned();
                }
                Some((key, _)) => key.notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-key",
                    "unknown scalar key ignored",
                ),
                None => text.notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-statement",
                    "unknown scalar statement ignored",
                ),
            }
        }
    }
    parsed
}

impl<'d, 'a> ParsedAssets<'d, 'a> {
    fn set(
        &mut self,
        block: &str,
        key: &str,
        value: Text<'d, 'a>,
        diagnostics: &mut ParserDiagnostics<'_>,
    ) {
        let defaults = &mut self.config.subscription;
        match (block, key) {
            ("geodata", "geosite") => self.geosite = Some(value),
            ("geodata", "geoip") => self.geoip = Some(value),
            ("geodata", "route") => self.geodata_route = Some(value),
            ("ui", "url") => self.ui_url = Some(value),
            ("ui", "route") => self.ui_route = Some(value),
            ("subscription", "ua") => defaults.ua = Some(value.raw().to_owned()),
            ("subscription", "interval") => {
                let raw = value.raw();
                defaults.interval = Some(super::lenient(
                    crate::types::parse_duration_secs(raw),
                    0,
                    diagnostics,
                    || ConfigDiagnostic {
                        setting: "assets.subscription.interval".to_owned(),
                        value: raw.to_owned(),
                        message: "duration is unsupported by honk; using fallback 0s".to_owned(),
                    },
                ));
            }
            ("subscription", "cache") => {
                let raw = value.raw();
                defaults.cache = Some(super::lenient(
                    super::scalars::strict_bool(raw),
                    true,
                    diagnostics,
                    || ConfigDiagnostic {
                        setting: "assets.subscription.cache".to_owned(),
                        value: raw.to_owned(),
                        message: "value is not a boolean; using fallback true".to_owned(),
                    },
                ));
            }
            // `SUB_BLOCKS` admits only the keys matched above.
            _ => unreachable!("assets.{block}.{key} is not in SUB_BLOCKS"),
        }
    }
}

/// Moves the geodata and UI values into the fields consumers read and fills
/// every route still empty from `assets.route`. Subscriptions took their
/// defaults from [`AssetsConfig::subscription_base`] while they were parsed.
pub(super) fn apply(
    parsed: ParsedAssets<'_, '_>,
    config: &mut Config,
) -> Result<(), super::ParseFailure> {
    let native = &mut config.experimental.native_api;
    let clash = &mut config.experimental.clash_api;
    for (value, target, (block, key), field, message) in [
        (
            parsed.geosite,
            &mut native.geosite_download_url,
            ("geodata", "geosite"),
            "geosite_download_url",
            "assets.geodata.geosite and experimental.native_api.geosite_download_url are both set; keep assets.geodata.geosite",
        ),
        (
            parsed.geoip,
            &mut native.geoip_download_url,
            ("geodata", "geoip"),
            "geoip_download_url",
            "assets.geodata.geoip and experimental.native_api.geoip_download_url are both set; keep assets.geodata.geoip",
        ),
        (
            parsed.geodata_route,
            &mut native.geodata_download_detour,
            ("geodata", "route"),
            "geodata_download_detour",
            "assets.geodata.route and experimental.native_api.geodata_download_detour are both set; keep assets.geodata.route",
        ),
        (
            parsed.ui_url,
            &mut clash.external_ui_download_url,
            ("ui", "url"),
            "external_ui_download_url",
            "assets.ui.url and experimental.clash_api.external_ui_download_url are both set; keep assets.ui.url",
        ),
        (
            parsed.ui_route,
            &mut clash.external_ui_download_detour,
            ("ui", "route"),
            "external_ui_download_detour",
            "assets.ui.route and experimental.clash_api.external_ui_download_detour are both set; keep assets.ui.route",
        ),
    ] {
        let Some(value) = value else {
            continue;
        };
        if !target.is_empty() {
            return Err(conflict(value, block, key, field, message).into());
        }
        *target = value.raw().to_owned();
    }
    let route = parsed.config.route.as_str();
    if native.geodata_download_detour.is_empty() {
        native.geodata_download_detour = route.to_owned();
    }
    if clash.external_ui_download_detour.is_empty() {
        clash.external_ui_download_detour = route.to_owned();
    }
    // The UI detour names an outbound; `routing` is its empty default.
    if clash.external_ui_download_detour == "routing" {
        clash.external_ui_download_detour.clear();
    }
    config.assets = parsed.config;
    Ok(())
}

fn conflict(
    value: Text<'_, '_>,
    block: &'static str,
    key: &'static str,
    field: &'static str,
    message: &'static str,
) -> DetailedConfigError {
    let (line, column) = value.source.location(value.span.start);
    let mut error = DetailedConfigError::new(
        ErrorCategory::Parse,
        "conflicting-assets-setting",
        value.source.reference(),
        SettingPath::new("assets").field(block).field(key),
        message,
    );
    error.diagnostic.value = SafeValue::Fields(vec![key, field]);
    error.diagnostic.line = Some(line);
    error.diagnostic.span = Some(value.span.start..value.span.end);
    error.diagnostic.byte_column = Some(column);
    error
}
