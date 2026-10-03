use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use super::{Document, ParseFailure, ParserDiagnostics, lexer, parse_documents};
use crate::Config;
use crate::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SettingPath, Severity, SourceRef, finish_attempt,
};
use crate::error::{DetailedConfigError, ErrorCategory};

/// Raw input retained separately from metadata-only diagnostic ownership.
/// Paths and content are private engine data, never an HTTP serialization shape.
#[derive(Clone)]
pub struct SourceSnapshot {
    pub path: PathBuf,
    pub content: Arc<str>,
    /// Index in the loaded snapshot's preorder source list.
    pub parent: Option<usize>,
    pub source: SourceRef,
    pub contains_api_secret: bool,
    pub loaded_at: SystemTime,
}

impl std::fmt::Debug for SourceSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceSnapshot")
            .field("bytes", &self.content.len())
            .field("parent", &self.parent)
            .field("contains_api_secret", &self.contains_api_secret)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub sources: Vec<SourceSnapshot>,
}

impl std::fmt::Debug for LoadedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedConfig")
            .field("sources", &self.sources)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SourceLimits {
    pub max_bytes: usize,
    pub max_sources: usize,
}

impl Default for SourceLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl SourceLimits {
    pub const DEFAULT: Self = Self {
        max_bytes: 8 * 1024 * 1024,
        max_sources: 32,
    };

    pub(super) const UNLIMITED: Self = Self {
        max_bytes: usize::MAX,
        max_sources: usize::MAX,
    };
}

/// Capture exactly the bytes consumed by the normal dae/include parser.
///
/// Overlay keys must be caller-authorized, absolute canonical paths inside the
/// entry directory. Missing paths are allowed only when supplied by the overlay;
/// their existing ancestors must resolve to the same path. This is a read-only
/// candidate loader, not authorization to create or write a file.
pub fn load_dae_sources(
    path: &Path,
    overlay: &HashMap<PathBuf, Arc<str>>,
    limits: SourceLimits,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<LoadedConfig, DetailedConfigError> {
    let result = load_attempt(path, overlay, limits, None, true, diagnostics, &mut false);
    finish_attempt(result, diagnostics)
}

/// Load the dae tree rooted at `path` from `sources` alone, as the file loader
/// would with every source in its overlay, but without touching the disk.
///
/// Keys are absolute, lexically normal labels inside the entry directory; they
/// are never opened. Includes expand only against keys, and a missing key is
/// `missing-config-source` rather than a disk read.
pub fn load_dae_sources_in_memory(
    path: &Path,
    sources: &HashMap<PathBuf, Arc<str>>,
    limits: SourceLimits,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<LoadedConfig, DetailedConfigError> {
    let result = load_attempt(path, sources, limits, None, false, diagnostics, &mut false);
    finish_attempt(result, diagnostics)
}

pub(super) fn load_attempt(
    path: &Path,
    overlay: &HashMap<PathBuf, Arc<str>>,
    limits: SourceLimits,
    entry_input: Option<Arc<str>>,
    disk: bool,
    diagnostics: &mut Vec<DetailedDiagnostic>,
    semantic: &mut bool,
) -> Result<LoadedConfig, DetailedConfigError> {
    let source = DiagnosticSources::new(Some(path.to_path_buf())).root();
    let mut sink = ParserDiagnostics::new(diagnostics, source);
    let result = super::parse_dae_file_inner(
        path,
        overlay,
        limits,
        entry_input,
        disk,
        &mut sink,
        semantic,
    )
    .map_err(|error| match error {
        ParseFailure::Detailed(error) => error,
        ParseFailure::Legacy(error) => sink.error(error),
    });
    sink.finish();
    result
}

/// Parse submitted documents in their supplied order, without filesystem access.
///
/// Paths are caller-provided source labels, not file access authority.
/// Include bodies are syntax-checked but never expanded. Empty documents are
/// permitted here; full admission must use the file/overlay loader and validators.
pub fn parse_dae_sources(
    inputs: &[(PathBuf, Arc<str>)],
    limits: SourceLimits,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<LoadedConfig, DetailedConfigError> {
    let table = DiagnosticSources::new(inputs.first().map(|(path, _)| path.clone()));
    let mut sink = ParserDiagnostics::new(diagnostics, table.root());
    let result: Result<LoadedConfig, ParseFailure> = (|| {
        if inputs.is_empty() {
            return Err(source_error(
                table.root(),
                "missing-config-source",
                "at least one configuration source is required",
            )
            .into());
        }
        let mut documents = Vec::new();
        let mut sources = Vec::new();
        let mut seen = HashSet::new();
        let mut bytes = 0;
        for (index, (path, content)) in inputs.iter().enumerate() {
            let source = if index == 0 {
                table.root()
            } else {
                table.add(Some(path.clone()), None)
            };
            sink.set_source(source.clone());
            if !seen.insert(path) {
                return Err(source_error(
                    source,
                    "duplicate-config-source",
                    "configuration sources must be distinct",
                )
                .into());
            }
            check_budget(limits, index, bytes, content.len(), &source)?;
            bytes += content.len();
            let loaded_at = SystemTime::now();
            let document = source_document(
                lexer::Source::shared(content.clone(), source.clone()),
                path,
                &mut sink,
            )?;
            sources.push(SourceSnapshot {
                path: path.clone(),
                content: content.clone(),
                parent: None,
                source,
                contains_api_secret: contains_api_secret(&document),
                loaded_at,
            });
            documents.push(document);
        }
        Ok(LoadedConfig {
            config: parse_documents(&documents, &mut sink)?,
            sources,
        })
    })();
    let result = result.map_err(|error| match error {
        ParseFailure::Detailed(error) => error,
        ParseFailure::Legacy(error) => sink.error(error),
    });
    sink.finish();
    finish_attempt(result, sink.output)
}

/// Check one submitted fragment's structure and include syntax without decoding
/// settings, resolving includes or publishing warnings for an unused document.
pub fn check_dae_source(path: &Path, content: &str) -> Result<(), DetailedConfigError> {
    let source = DiagnosticSources::new(Some(path.to_path_buf())).root();
    let mut diagnostics = Vec::new();
    let mut sink = ParserDiagnostics::new(&mut diagnostics, source.clone());
    source_document(lexer::Source::new(content, source), path, &mut sink)
        .map(|_| ())
        .map_err(|error| match error {
            ParseFailure::Detailed(error) => error,
            ParseFailure::Legacy(error) => sink.error(error),
        })?;
    if let Some(mut diagnostic) = diagnostics
        .into_iter()
        .find(|diagnostic| diagnostic.severity == Severity::Error)
    {
        diagnostic.terminal = true;
        return Err(DetailedConfigError {
            category: ErrorCategory::Parse,
            diagnostic: Box::new(diagnostic),
        });
    }
    Ok(())
}

fn source_document<'a>(
    source: lexer::Source<'a>,
    path: &Path,
    sink: &mut ParserDiagnostics<'_>,
) -> Result<Document<'a>, ParseFailure> {
    let document = Document::parse_attempt(source, sink.output, false)
        .map_err(|error| ParseFailure::Detailed(error.error))?;
    for segment in document
        .sections()
        .filter(|segment| segment.header() == "include")
    {
        super::warn_include_hash(&segment, sink);
        super::parse_include_body(segment, path)?;
    }
    Ok(document)
}

pub(super) fn source_error(
    source: SourceRef,
    code: &'static str,
    message: &'static str,
) -> DetailedConfigError {
    DetailedConfigError::new(
        ErrorCategory::Include,
        code,
        source,
        SettingPath::new("config"),
        message,
    )
}

pub(super) fn check_budget(
    limits: SourceLimits,
    count: usize,
    bytes: usize,
    additional: usize,
    source: &SourceRef,
) -> Result<(), DetailedConfigError> {
    if count >= limits.max_sources {
        return Err(source_error(
            source.clone(),
            "config-source-limit",
            "configuration source count exceeds the limit",
        ));
    }
    if additional > limits.max_bytes.saturating_sub(bytes) {
        return Err(source_error(
            source.clone(),
            "config-byte-limit",
            "configuration source bytes exceed the limit",
        ));
    }
    Ok(())
}

pub(super) fn read_source(
    path: &Path,
    remaining: usize,
    source: &SourceRef,
) -> Result<Arc<str>, DetailedConfigError> {
    let io_error =
        |error: std::io::Error| DetailedConfigError::from_legacy(error.into(), source.clone());
    if !std::fs::metadata(path).map_err(io_error)?.is_file() {
        return Err(source_error(
            source.clone(),
            "invalid-config-source",
            "configuration source must be a regular file",
        ));
    }
    let file = std::fs::File::open(path).map_err(io_error)?;
    let mut content = Vec::new();
    file.take((remaining as u64).saturating_add(1))
        .read_to_end(&mut content)
        .map_err(io_error)?;
    if content.len() > remaining {
        return Err(source_error(
            source.clone(),
            "config-byte-limit",
            "configuration source bytes exceed the limit",
        ));
    }
    String::from_utf8(content).map(Arc::from).map_err(|_| {
        source_error(
            source.clone(),
            "invalid-config-encoding",
            "configuration source must be UTF-8",
        )
    })
}

pub(super) fn canonical_overlay_path(path: &Path) -> std::io::Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    let mut ancestor = path;
    let mut missing = Vec::new();
    let mut resolved = loop {
        match std::fs::canonicalize(ancestor) {
            Ok(resolved) => break resolved,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A dangling symlink is not a new virtual path.
                if std::fs::symlink_metadata(ancestor)
                    .is_ok_and(|meta| meta.file_type().is_symlink())
                {
                    return Err(error);
                }
                missing.push(ancestor.file_name().ok_or(error)?);
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
            }
            Err(error) => return Err(error),
        }
    };
    for part in missing.into_iter().rev() {
        resolved.push(part);
    }
    Ok(resolved)
}

pub(super) fn lexical_source_path(path: &Path) -> std::io::Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    Ok(path.components().collect())
}

pub(super) fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            part => normalized.push(part),
        }
    }
    normalized
}

pub(super) fn contains_api_secret(document: &Document<'_>) -> bool {
    document
        .sections()
        .filter(|root| root.header() == "experimental")
        .filter_map(|root| root.body())
        .flatten()
        .filter(|section| {
            super::read::block_header(section)
                .is_some_and(|header| matches!(header.raw(), "native_api" | "clash_api"))
        })
        .filter_map(|section| section.body())
        .flatten()
        .any(|field| {
            field.is_block()
                || super::read::Text::segment(&field)
                    .kv()
                    .is_some_and(|(key, _)| key.raw() == "secret")
        })
}
