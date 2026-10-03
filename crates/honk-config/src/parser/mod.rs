mod assets;
#[cfg(feature = "conformance")]
pub mod conformance;
pub mod cursor;
mod diagnostics;
mod dns;
mod entries;
mod groups;
pub mod lexer;
mod routing;

mod read;
mod scalars;
pub mod source_edit;
mod sources;
use entries::{parse_node_section, parse_subscription_section};
use groups::{parse_group_section, resolve_group_filters_inner};
use scalars::{parse_experimental_section, parse_global_section};
pub use sources::{
    LoadedConfig, SourceLimits, SourceSnapshot, check_dae_source, load_dae_sources,
    load_dae_sources_in_memory, parse_dae_sources,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod lexer_tests;

#[cfg(test)]
mod cursor_tests;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use self::diagnostics::ParserDiagnostics;
use crate::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, finish_attempt, report_detailed_diagnostics,
};
use crate::error::DetailedConfigError;
use crate::group::Group;
use crate::node::Node;
use crate::subscription::Subscription;
use crate::{Config, ConfigDiagnostic};
use cursor::{Document, Root, Segment};
use lexer::quoted_end;
enum ParseFailure {
    Legacy(crate::ConfigError),
    Detailed(crate::error::DetailedConfigError),
}

impl From<crate::ConfigError> for ParseFailure {
    fn from(error: crate::ConfigError) -> Self {
        Self::Legacy(error)
    }
}

impl From<crate::error::DetailedConfigError> for ParseFailure {
    fn from(error: crate::error::DetailedConfigError) -> Self {
        Self::Detailed(error)
    }
}

/// Load a dae configuration file, resolving its top-level `include` blocks.
///
/// Include paths are relative to the entry configuration's directory, even
/// when they occur in a nested included file.  Included files must remain
/// below that directory after symlink resolution.
pub fn parse_dae_config_file(path: impl AsRef<Path>) -> Result<Config, crate::ConfigError> {
    let mut diagnostics = Vec::new();
    let result = parse_dae_config_file_with_detailed_diagnostics(path, &mut diagnostics);
    report_detailed_diagnostics(&diagnostics);
    result.map_err(DetailedConfigError::into_legacy)
}

/// One-release data projection; the caller's existing prefix is preserved.
pub fn parse_dae_config_file_with_diagnostics(
    path: impl AsRef<Path>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Result<Config, crate::ConfigError> {
    let mut detailed = Vec::new();
    let result = parse_dae_config_file_with_detailed_diagnostics(path, &mut detailed);
    diagnostics.extend(detailed.iter().map(DetailedDiagnostic::to_legacy));
    result.map_err(DetailedConfigError::into_legacy)
}

pub fn parse_dae_config_file_with_detailed_diagnostics(
    path: impl AsRef<Path>,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Config, DetailedConfigError> {
    let result = parse_dae_config_file_attempt(path, None, diagnostics, &mut false);
    finish_attempt(result, diagnostics)
}

pub(crate) fn parse_dae_config_file_attempt(
    path: impl AsRef<Path>,
    entry_input: Option<Arc<str>>,
    diagnostics: &mut Vec<DetailedDiagnostic>,
    semantic: &mut bool,
) -> Result<Config, DetailedConfigError> {
    sources::load_attempt(
        path.as_ref(),
        &HashMap::new(),
        SourceLimits::UNLIMITED,
        entry_input,
        true,
        diagnostics,
        semantic,
    )
    .map(|loaded| loaded.config)
}

fn parse_dae_file_inner(
    path: &Path,
    overlay: &HashMap<PathBuf, Arc<str>>,
    limits: SourceLimits,
    entry_input: Option<Arc<str>>,
    disk: bool,
    diagnostics: &mut ParserDiagnostics<'_>,
    semantic: &mut bool,
) -> Result<LoadedConfig, ParseFailure> {
    let entry = if !disk {
        sources::lexical_source_path(path)
    } else if overlay.contains_key(path) {
        sources::canonical_overlay_path(path)
    } else {
        std::fs::canonicalize(path)
    }
    .map_err(|error| ParseFailure::Legacy(error.into()))?;
    diagnostics.set_source(DiagnosticSources::new(Some(entry.clone())).root());
    let entry_dir = entry.parent().map(Path::to_path_buf).ok_or_else(|| {
        sources::source_error(
            diagnostics.source(),
            "invalid-config-path",
            "configuration entry requires a parent directory",
        )
    })?;
    for path in overlay.keys() {
        let canonical = if disk {
            sources::canonical_overlay_path(path)
        } else {
            sources::lexical_source_path(path)
        };
        if !path.starts_with(&entry_dir)
            || !canonical.is_ok_and(|canonical| canonical == *path)
            || disk && std::fs::metadata(path).is_ok_and(|metadata| !metadata.is_file())
        {
            return Err(sources::source_error(
                diagnostics.source(),
                "invalid-config-overlay",
                "configuration overlay paths must be canonical and confined to the entry directory",
            )
            .into());
        }
    }
    let mut loader = IncludeLoader {
        entry_dir,
        loaded: HashSet::new(),
        stack: Vec::new(),
        saw_include: false,
        entry_input: Arc::from(""),
        supplied_entry: entry_input,
        overlay,
        disk,
        limits,
        bytes: 0,
        sources: Vec::new(),
    };
    let documents = match loader.expand_file(&entry, None, diagnostics) {
        Ok(documents) => documents,
        Err(error) => {
            if loader.saw_include {
                let mut error = match error {
                    ParseFailure::Legacy(error) => diagnostics.error(error),
                    ParseFailure::Detailed(error) => error,
                };
                if error.category != crate::error::ErrorCategory::UnsupportedPolicy {
                    error.category = crate::error::ErrorCategory::Include;
                }
                return Err(ParseFailure::Detailed(error));
            }
            return Err(error);
        }
    };
    match parse_documents(&documents, diagnostics) {
        Ok(config) => Ok(LoadedConfig {
            config,
            sources: loader.sources,
        }),
        Err(err) => {
            *semantic = loader.saw_include || !is_structured_document(&loader.entry_input);
            match err {
                ParseFailure::Detailed(mut error) if loader.saw_include => {
                    if error.category != crate::error::ErrorCategory::UnsupportedPolicy {
                        error.category = crate::error::ErrorCategory::Include;
                    }
                    Err(ParseFailure::Detailed(error))
                }
                err @ ParseFailure::Detailed(_) => Err(err),
                ParseFailure::Legacy(error) if loader.saw_include => {
                    let mut error = diagnostics.error(error);
                    if error.category != crate::error::ErrorCategory::UnsupportedPolicy {
                        error.category = crate::error::ErrorCategory::Include;
                    }
                    Err(ParseFailure::Detailed(error))
                }
                err => Err(err),
            }
        }
    }
}

fn is_structured_document(input: &str) -> bool {
    // A dae semantic failure is final unless the complete document decodes as
    // a YAML, TOML or JSON mapping containing at least one known Config root.
    use crate::config::CONFIG_FIELDS;

    serde_yaml::from_str::<serde_yaml::Value>(input).is_ok_and(|value| {
        value.as_mapping().is_some_and(|mapping| {
            mapping
                .keys()
                .any(|key| key.as_str().is_some_and(|key| CONFIG_FIELDS.contains(&key)))
        })
    }) || toml::from_str::<toml::Value>(input).is_ok_and(|value| {
        value.as_table().is_some_and(|mapping| {
            mapping
                .keys()
                .any(|key| CONFIG_FIELDS.contains(&key.as_str()))
        })
    }) || serde_json::from_str::<serde_json::Value>(input).is_ok_and(|value| {
        value.as_object().is_some_and(|mapping| {
            mapping
                .keys()
                .any(|key| CONFIG_FIELDS.contains(&key.as_str()))
        })
    })
}

struct IncludeLoader<'a> {
    entry_dir: PathBuf,
    // Canonical paths prevent symlink aliases from bypassing duplicate detection.
    loaded: HashSet<PathBuf>,
    stack: Vec<PathBuf>,
    saw_include: bool,
    entry_input: Arc<str>,
    supplied_entry: Option<Arc<str>>,
    overlay: &'a HashMap<PathBuf, Arc<str>>,
    /// When false the overlay is the whole source set and no path is resolved on disk.
    disk: bool,
    limits: SourceLimits,
    bytes: usize,
    sources: Vec<SourceSnapshot>,
}

impl IncludeLoader<'_> {
    fn expand_file(
        &mut self,
        path: &Path,
        parent_index: Option<usize>,
        diagnostics: &mut ParserDiagnostics<'_>,
    ) -> Result<Vec<Document<'static>>, ParseFailure> {
        if !self.loaded.insert(path.to_path_buf()) {
            return Err(sources::source_error(
                diagnostics.source(),
                "duplicate-config-source",
                "circular or duplicate include is not allowed",
            )
            .into());
        }
        let parent = diagnostics.source();
        let source = if self.stack.is_empty() {
            parent
        } else {
            parent
                .sources()
                .add(Some(path.to_path_buf()), Some(parent.index()))
        };
        diagnostics.set_source(source.clone());
        sources::check_budget(self.limits, self.sources.len(), self.bytes, 0, &source)?;
        self.stack.push(path.to_path_buf());
        let result = (|| {
            let supplied_entry = if self.stack.len() == 1 {
                self.supplied_entry.take()
            } else {
                None
            };
            let input = if let Some(input) = self.overlay.get(path) {
                input.clone()
            } else if let Some(input) = supplied_entry {
                input
            } else if !self.disk {
                return Err(sources::source_error(
                    source.clone(),
                    "missing-config-source",
                    "configuration source is not in the supplied set",
                )
                .into());
            } else {
                sources::read_source(
                    path,
                    self.limits.max_bytes.saturating_sub(self.bytes),
                    &source,
                )?
            };
            let loaded_at = std::time::SystemTime::now();
            sources::check_budget(
                self.limits,
                self.sources.len(),
                self.bytes,
                input.len(),
                &source,
            )?;
            self.bytes += input.len();
            if self.stack.len() == 1 {
                self.entry_input = input.clone();
            }
            let source_text = lexer::Source::shared(input.clone(), source.clone());
            let document =
                Document::parse_attempt(source_text, diagnostics.output, self.stack.len() == 1)
                    .map_err(|error| {
                        self.saw_include |= error.saw_include;
                        ParseFailure::Detailed(error.error)
                    })?;
            let source_index = self.sources.len();
            self.sources.push(SourceSnapshot {
                path: path.to_path_buf(),
                content: input,
                parent: parent_index,
                source: source.clone(),
                contains_api_secret: sources::contains_api_secret(&document),
                loaded_at,
            });
            let mut patterns = Vec::new();
            for segment in document
                .sections()
                .filter(|segment| segment.header() == "include")
            {
                self.saw_include = true;
                warn_include_hash(&segment, diagnostics);
                patterns.extend(parse_include_body(segment, path)?);
            }
            let mut documents = vec![document];
            // dae merges own sections before descendants, in declaration/glob order.
            for pattern in patterns {
                diagnostics.set_source(source.clone());
                for child in self.expand_pattern(&pattern, &source)? {
                    diagnostics.set_source(source.clone());
                    documents.extend(self.expand_file(&child, Some(source_index), diagnostics)?);
                }
            }
            Ok(documents)
        })();
        self.stack.pop();
        result
    }

    fn expand_pattern(
        &self,
        pattern: &str,
        source: &crate::diagnostic::SourceRef,
    ) -> Result<Vec<PathBuf>, ParseFailure> {
        let pattern_path = Path::new(pattern);
        let pattern = if pattern_path.is_absolute() {
            pattern_path.to_path_buf()
        } else {
            self.entry_dir.join(pattern_path)
        };
        // dae treats `**` as an ordinary same-component wildcard.
        let mut pattern = normalize_dae_glob_pattern(&pattern);
        if !self.disk {
            pattern = sources::lexical_normalize(&pattern);
        }
        let pattern_display = pattern.to_string_lossy();
        let expansion_error = || {
            sources::source_error(
                source.clone(),
                "invalid-config-include",
                "configuration include pattern cannot be expanded",
            )
        };
        let mut matches = Vec::new();
        let disk_matches = if self.disk {
            Some(glob::glob(&pattern_display).map_err(|_| expansion_error())?)
        } else {
            None
        };
        for path in disk_matches.into_iter().flatten() {
            let path = path.map_err(|_| expansion_error())?;
            if path.extension().and_then(|ext| ext.to_str()) != Some("dae") {
                continue;
            }
            let metadata = std::fs::metadata(&path).map_err(|_| expansion_error())?;
            if metadata.is_dir() {
                continue;
            }
            sources::check_budget(
                self.limits,
                self.sources.len().saturating_add(matches.len()),
                self.bytes,
                0,
                source,
            )?;
            matches.push(path);
        }
        if !self.overlay.is_empty() {
            let normalized: PathBuf = pattern.components().collect();
            let matcher =
                glob::Pattern::new(&normalized.to_string_lossy()).map_err(|_| expansion_error())?;
            let options = glob::MatchOptions {
                require_literal_separator: true,
                ..glob::MatchOptions::new()
            };
            let mut add_virtual = |path: PathBuf| -> Result<(), DetailedConfigError> {
                if !matches.contains(&path) {
                    sources::check_budget(
                        self.limits,
                        self.sources.len().saturating_add(matches.len()),
                        self.bytes,
                        0,
                        source,
                    )?;
                    matches.push(path);
                }
                Ok(())
            };
            for path in self.overlay.keys() {
                if path.extension().and_then(|ext| ext.to_str()) == Some("dae")
                    && matcher.matches_path_with(path, options)
                {
                    add_virtual(path.clone())?;
                }
            }
            // Existing directory aliases and `..` must also find a virtual leaf.
            if self.disk
                && let (Some(parent), Some(name)) = (pattern.parent(), pattern.file_name())
            {
                let leaf =
                    glob::Pattern::new(&name.to_string_lossy()).map_err(|_| expansion_error())?;
                for directory in
                    glob::glob(&parent.to_string_lossy()).map_err(|_| expansion_error())?
                {
                    let directory = directory.map_err(|_| expansion_error())?;
                    if !directory.is_dir() {
                        continue;
                    }
                    let canonical =
                        std::fs::canonicalize(&directory).map_err(|_| expansion_error())?;
                    if directory == canonical {
                        continue;
                    }
                    for path in self.overlay.keys() {
                        if path.parent() == Some(canonical.as_path())
                            && path.extension().and_then(|ext| ext.to_str()) == Some("dae")
                            && let Some(name) = path.file_name()
                            && leaf.matches_with(&name.to_string_lossy(), options)
                        {
                            add_virtual(directory.join(name))?;
                        }
                    }
                }
            }
        }
        matches.sort();
        let mut files = Vec::with_capacity(matches.len());
        for path in matches {
            let path = if !self.disk {
                Ok(path)
            } else if self.overlay.contains_key(&path) {
                sources::canonical_overlay_path(&path)
            } else {
                std::fs::canonicalize(&path).or_else(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound
                        && let (Some(parent), Some(name)) = (path.parent(), path.file_name())
                        && let Ok(parent) = std::fs::canonicalize(parent)
                        && self.overlay.contains_key(&parent.join(name))
                    {
                        return Ok(parent.join(name));
                    }
                    Err(error)
                })
            }
            .map_err(|_| expansion_error())?;
            if !path.starts_with(&self.entry_dir) {
                return Err(sources::source_error(
                    source.clone(),
                    "config-include-escape",
                    "included configuration must remain inside the entry directory",
                )
                .into());
            }
            files.push(path);
        }
        Ok(files)
    }
}

fn normalize_dae_glob_pattern(pattern: &Path) -> PathBuf {
    // honk runs on Linux, where `/` is both the dae and native separator.
    let normalized = pattern
        .to_string_lossy()
        .split('/')
        .map(|component| if component == "**" { "*" } else { component })
        .collect::<Vec<_>>()
        .join("/");
    PathBuf::from(normalized)
}

fn warn_include_hash(segment: &Segment<'_, '_>, diagnostics: &mut ParserDiagnostics<'_>) {
    if let Some(body) = segment.body() {
        for token in body.flat_map(|entry| entry.tokens()) {
            let text = read::Text {
                source: segment.source(),
                tokens: std::slice::from_ref(token),
                span: token.span,
                comment: None,
            };
            if let Some(offset) = text.find("#") {
                text.sub(offset, offset + 1).notice(
                    diagnostics,
                    crate::diagnostic::Severity::Warning,
                    "legacy-include-hash",
                    "glued `#` is data; separate include comments with whitespace",
                );
            }
        }
    }
}

fn parse_include_body(
    segment: cursor::Segment<'_, '_>,
    source: &Path,
) -> Result<Vec<String>, crate::ConfigError> {
    let mut patterns = Vec::new();
    let Some(body) = segment.body() else {
        return Ok(patterns);
    };
    for entry in body {
        if entry.is_block() {
            return Err(crate::ConfigError::Include(format!(
                "include section in '{}' accepts only file patterns",
                source.display()
            )));
        }
        let raw = entry.source().raw(entry.header_span());
        let bytes = raw.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index == bytes.len() {
                break;
            }
            if matches!(bytes[index], b'{' | b'}') {
                return Err(crate::ConfigError::Include(format!(
                    "include section in '{}' accepts only file patterns",
                    source.display()
                )));
            }
            // Adjacent quoted paths share a lexer token.
            let value = if matches!(bytes[index], b'\'' | b'"') {
                let start = index + 1;
                let end = quoted_end(bytes, index).ok_or_else(|| {
                    crate::ConfigError::Include(format!(
                        "unterminated quoted include path in '{}'",
                        source.display()
                    ))
                })?;
                index = end;
                &raw[start..end - 1]
            } else {
                let start = index;
                while index < bytes.len()
                    && !bytes[index].is_ascii_whitespace()
                    && !matches!(bytes[index], b'{' | b'}')
                {
                    index += 1;
                }
                &raw[start..index]
            };
            if value.is_empty() {
                return Err(crate::ConfigError::Include(format!(
                    "empty include path in '{}'",
                    source.display()
                )));
            }
            patterns.push(value.to_owned());
        }
    }
    Ok(patterns)
}

pub fn parse_dae_config(input: &str) -> Result<Config, crate::ConfigError> {
    let mut diagnostics = Vec::new();
    let result = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics);
    report_detailed_diagnostics(&diagnostics);
    result.map_err(DetailedConfigError::into_legacy)
}

/// One-release data projection; never logs or exposes arbitrary input values.
pub fn parse_dae_config_with_diagnostics(
    input: &str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Result<Config, crate::ConfigError> {
    let mut detailed = Vec::new();
    let result = parse_dae_config_with_detailed_diagnostics(input, &mut detailed);
    diagnostics.extend(detailed.iter().map(DetailedDiagnostic::to_legacy));
    result.map_err(DetailedConfigError::into_legacy)
}

pub fn parse_dae_config_with_detailed_diagnostics(
    input: &str,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Config, DetailedConfigError> {
    let source = DiagnosticSources::new(None).root();
    let mut sink = ParserDiagnostics::new(diagnostics, source.clone());
    let result: Result<Config, ParseFailure> = (|| {
        let document =
            Document::parse_attempt(lexer::Source::new(input, source), sink.output, true)
                .map_err(|error| ParseFailure::Detailed(error.error))?;
        for segment in document
            .sections()
            .filter(|segment| segment.header() == "include")
        {
            warn_include_hash(&segment, &mut sink);
        }
        parse_documents(&[document], &mut sink)
    })();
    let result = result.map_err(|error| match error {
        ParseFailure::Detailed(error) => error,
        ParseFailure::Legacy(error) => sink.error(error),
    });
    sink.finish();
    finish_attempt(result, sink.output)
}

fn parse_documents(
    documents: &[Document<'_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Config, ParseFailure> {
    let mut sections: Vec<(&str, Vec<Segment<'_, '_>>)> = Vec::new();
    for document in documents {
        for segment in document.sections() {
            let name = segment.header();
            if Root::parse(name) == Some(Root::Include) {
                continue;
            }
            if let Some((_, segments)) = sections.iter_mut().find(|(key, _)| *key == name) {
                segments.push(segment);
            } else {
                sections.push((name, vec![segment]));
            }
        }
    }

    let canonical_nfqueue_present = sections
        .iter()
        .filter(|(name, _)| *name == "global")
        .any(|(_, segments)| scalars::nfqueue_present(segments));
    let mut config = Config::default();
    // Subscriptions start from these defaults, whichever block comes first.
    let assets = sections
        .iter()
        .find(|(name, _)| Root::parse(name) == Some(Root::Assets))
        .map(|(name, segments)| {
            diagnostics.at_section(name, read::Text::segment(&segments[0]));
            assets::parse_section(segments, diagnostics)
        })
        .unwrap_or_default();
    for (name, segments) in &sections {
        diagnostics.at_section(name, read::Text::segment(&segments[0]));
        match Root::parse(name) {
            Some(Root::Global) => config.global = parse_global_section(segments, diagnostics)?,
            Some(Root::Dns) => config.dns = dns::parse_section(segments, diagnostics)?,
            Some(Root::Routing) => config.routing = routing::parse_section(segments, diagnostics)?,
            Some(Root::Node) => config.nodes = parse_node_section(segments, diagnostics)?,
            Some(Root::Group) => {}
            Some(Root::Subscription) => {
                config.subscriptions =
                    parse_subscription_section(segments, &assets.config, diagnostics)?
            }
            Some(Root::Experimental) => {
                config.experimental = parse_experimental_section(segments, diagnostics)?;
            }
            // Includes were spliced before dispatch; an unknown root never gets here
            // because the document only indexes known roots (K43 notices are emitted
            // there), so the last arm is a compile-time completeness check, not a guard.
            Some(Root::Include | Root::Assets) | None => {}
        }
    }
    assets::apply(assets, &mut config)?;
    config.apply_legacy_nfqueue(canonical_nfqueue_present);

    if let Some((_, segments)) = sections.iter().find(|(name, _)| *name == "group") {
        config.groups =
            parse_group_section(segments, diagnostics, config.global.check_tolerance_ms)?;
    }

    resolve_group_filters_inner(
        &mut config.groups,
        &config.nodes,
        &config.subscriptions,
        Some(diagnostics),
    );

    Ok(config)
}

/// Resolve group filters into concrete node UUIDs.
///
/// Each `filter:` line is OR-ed. Predicates joined by `&&` within one line
/// are AND-ed and may be negated with `!`. Supported predicates are
/// `name(...)` and dae-compatible `subtag(...)`; both accept exact values,
/// `keyword:`, and `regex:` arguments.
///
/// `group('tag')` entries are not node filters — the dae parser routes them
/// into `Group.groups` at parse time.
pub fn resolve_group_filters(groups: &mut [Group], nodes: &[Node], subscriptions: &[Subscription]) {
    // Runtime re-resolution: the filters were reported when the config was parsed.
    resolve_group_filters_inner(groups, nodes, subscriptions, None);
}

/// Normalize a geosite list name.
fn normalize_geosite_code(code: &str) -> String {
    // Keep the code verbatim: `@attr` is an attribute filter applied at
    // expansion time (honk-core routing/geo.rs), not part of the category
    // name — remapping it to `-` silently mismatched into a nonexistent
    // category.
    code.trim().to_string()
}

/// Keep `fallback` when `parsed` is `None` and record why. For settings whose
/// unparseable value does not justify rejecting the configuration.
fn lenient<T>(
    parsed: Option<T>,
    fallback: T,
    diagnostics: &mut ParserDiagnostics<'_>,
    diagnostic: impl FnOnce() -> ConfigDiagnostic,
) -> T {
    match parsed {
        Some(value) => value,
        None => {
            diagnostics.push(diagnostic());
            fallback
        }
    }
}

fn parse_hex_or_dec(s: &str) -> Option<u32> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).ok().or_else(|| s.parse().ok())
}

fn parse_ip_prefer(s: &str) -> Option<crate::dns::DnsStrategy> {
    use crate::dns::DnsStrategy;
    // dae `ipversion_prefer` is a *preference*, not an only-mode: 4/6 map to
    // the prefer variants (other family still answered when it alone exists),
    // and 0 is dae's "no preference", the same as omitting the setting.
    match s.parse::<i32>() {
        Ok(0) => Some(DnsStrategy::Both),
        Ok(4) => Some(DnsStrategy::PreferIpv4),
        Ok(6) => Some(DnsStrategy::PreferIpv6),
        _ => None,
    }
}
