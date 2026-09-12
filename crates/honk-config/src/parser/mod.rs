pub mod cursor;
mod diagnostics;
mod dns;
mod entries;
mod groups;
pub mod lexer;
mod routing;

mod read;
mod scalars;
use entries::{parse_node_section, parse_subscription_section};
use groups::{parse_group_section, resolve_group_filters_inner};
use scalars::{parse_experimental_section, parse_global_section};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod lexer_tests;

#[cfg(test)]
mod cursor_tests;

use std::collections::HashSet;
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
    let result = parse_dae_config_file_attempt(path, diagnostics, &mut false);
    finish_attempt(result, diagnostics)
}

pub(crate) fn parse_dae_config_file_attempt(
    path: impl AsRef<Path>,
    diagnostics: &mut Vec<DetailedDiagnostic>,
    semantic: &mut bool,
) -> Result<Config, DetailedConfigError> {
    let source = DiagnosticSources::new(Some(path.as_ref().to_path_buf())).root();
    let mut sink = ParserDiagnostics::new(diagnostics, source);
    let result = match parse_dae_file_inner(path, &mut sink, semantic) {
        Ok(config) => Ok(config),
        Err(ParseFailure::Detailed(error)) => Err(error),
        Err(ParseFailure::Legacy(error)) => Err(sink.error(error)),
    };
    sink.finish();
    result
}

fn parse_dae_file_inner(
    path: impl AsRef<Path>,
    diagnostics: &mut ParserDiagnostics<'_>,
    semantic: &mut bool,
) -> Result<Config, ParseFailure> {
    let entry =
        std::fs::canonicalize(path.as_ref()).map_err(|error| ParseFailure::Legacy(error.into()))?;
    let entry_dir = entry.parent().map(Path::to_path_buf).ok_or_else(|| {
        ParseFailure::Legacy(crate::ConfigError::Include(format!(
            "entry configuration '{}' has no parent directory",
            entry.display()
        )))
    })?;
    let mut loader = IncludeLoader {
        entry_dir,
        loaded: HashSet::new(),
        stack: Vec::new(),
        saw_include: false,
        entry_input: Arc::from(""),
    };
    let documents = match loader.expand_file(&entry, diagnostics) {
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
        Ok(config) => Ok(config),
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

struct IncludeLoader {
    entry_dir: PathBuf,
    // dae treats a repeated include as a circular include too.  Keep that
    // behavior, but canonical paths also prevent symlink aliases escaping it.
    loaded: HashSet<PathBuf>,
    stack: Vec<PathBuf>,
    saw_include: bool,
    entry_input: Arc<str>,
}

impl IncludeLoader {
    fn expand_file(
        &mut self,
        path: &Path,
        diagnostics: &mut ParserDiagnostics<'_>,
    ) -> Result<Vec<Document<'static>>, ParseFailure> {
        if !self.loaded.insert(path.to_path_buf()) {
            let mut chain = self
                .stack
                .iter()
                .map(|entry| entry.display().to_string())
                .collect::<Vec<_>>();
            chain.push(path.display().to_string());
            return Err(crate::ConfigError::Include(format!(
                "circular or duplicate include is not allowed: {}",
                chain.join(" -> ")
            ))
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
        self.stack.push(path.to_path_buf());
        let result = (|| {
            let input = std::fs::read_to_string(path).map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to read configuration '{}': {err}",
                    path.display()
                ))
            })?;
            let input: Arc<str> = input.into();
            if self.stack.len() == 1 {
                self.entry_input = input.clone();
            }
            let source_text = lexer::Source::shared(input, source.clone());
            let document =
                Document::parse_attempt(source_text, diagnostics.output).map_err(|error| {
                    self.saw_include |= error.saw_include;
                    ParseFailure::Detailed(error.error)
                })?;
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

            // dae merges an entry's own sections before the sections of its
            // included descendants, regardless of where `include` occurs in
            // that entry.  Appending recursively gives that preorder.
            for pattern in patterns {
                diagnostics.set_source(source.clone());
                for child in self.expand_pattern(&pattern, path)? {
                    diagnostics.set_source(source.clone());
                    documents.extend(self.expand_file(&child, diagnostics)?);
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
        source: &Path,
    ) -> Result<Vec<PathBuf>, crate::ConfigError> {
        let pattern_path = Path::new(pattern);
        let pattern = if pattern_path.is_absolute() {
            pattern_path.to_path_buf()
        } else {
            self.entry_dir.join(pattern_path)
        };
        // `glob` gives `**` recursive semantics while dae's filepath.Glob
        // treats it as an ordinary same-component wildcard.  Normalize the
        // one divergent form before matching.
        let pattern = normalize_dae_glob_pattern(&pattern);
        let pattern_display = pattern.display().to_string();
        let mut matches = glob::glob(&pattern_display)
            .map_err(|err| {
                crate::ConfigError::Include(format!(
                    "invalid include pattern '{}' in '{}': {err}",
                    pattern_display,
                    source.display()
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to expand include pattern '{}' in '{}': {err}",
                    pattern_display,
                    source.display()
                ))
            })?;
        matches.sort();

        let mut files = Vec::new();
        for path in matches {
            if path.extension().and_then(|ext| ext.to_str()) != Some("dae") {
                continue;
            }
            let metadata = std::fs::metadata(&path).map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to inspect included path '{}': {err}",
                    path.display()
                ))
            })?;
            if metadata.is_dir() {
                continue;
            }

            let path = std::fs::canonicalize(&path).map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to resolve included path '{}': {err}",
                    path.display()
                ))
            })?;
            if !path.starts_with(&self.entry_dir) {
                return Err(crate::ConfigError::Include(format!(
                    "included path '{}' is outside entry configuration directory '{}'",
                    path.display(),
                    self.entry_dir.display()
                )));
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
        if entry.body().is_some() {
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
        let document = Document::parse_attempt(lexer::Source::new(input, source), sink.output)
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
    for (name, segments) in &sections {
        diagnostics.at_section(name, read::Text::segment(&segments[0]));
        match Root::parse(name) {
            Some(Root::Global) => config.global = parse_global_section(segments, diagnostics)?,
            Some(Root::Dns) => config.dns = dns::parse_section(segments, diagnostics)?,
            Some(Root::Routing) => config.routing = routing::parse_section(segments, diagnostics)?,
            Some(Root::Node) => config.nodes = parse_node_section(segments, diagnostics)?,
            Some(Root::Group) => config.groups = parse_group_section(segments, diagnostics)?,
            Some(Root::Subscription) => {
                config.subscriptions = parse_subscription_section(segments, diagnostics)?
            }
            Some(Root::Experimental) => {
                config.experimental = parse_experimental_section(segments, diagnostics)?;
            }
            // Includes were spliced before dispatch; an unknown root never gets here
            // because the document only indexes known roots (K43 notices are emitted
            // there), so the last arm is a compile-time completeness check, not a guard.
            Some(Root::Include) | None => {}
        }
    }
    config.apply_legacy_nfqueue(canonical_nfqueue_present);

    for group in &mut config.groups {
        if group.policy == crate::node::GroupPolicy::URLTest {
            group.tolerance = config.global.check_tolerance_ms;
        }
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
