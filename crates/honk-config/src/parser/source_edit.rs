//! Exact source edits use the same structural cursor and scalar spans as admission.

use std::collections::HashMap;
use std::ops::Range;

use super::cursor::{BodySyntax, Document};
use super::lexer::Source;
use super::read::{self, Text};
use super::sources::SourceSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupField {
    Policy,
    Default,
    Final,
    Tolerance,
    IdleTimeout,
    InterruptConnections,
    CheckUrl,
}

impl GroupField {
    fn key(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Default => "default",
            Self::Final => "final",
            Self::Tolerance => "tolerance",
            Self::IdleTimeout => "idle_timeout",
            Self::InterruptConnections => "interrupt_connections",
            Self::CheckUrl => "check_url",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("source cannot represent the requested edit")]
pub struct SourceEditError;

fn group_source_indices(documents: &[Document<'_>]) -> HashMap<String, usize> {
    let mut result = HashMap::new();
    for (index, document) in documents.iter().enumerate() {
        for root in document.sections().filter(|root| root.header() == "group") {
            if let Some(body) = root.body_with(BodySyntax::Declarations) {
                for group in body {
                    if let Some(name) = read::block_header(&group) {
                        result.insert(name.raw().to_owned(), index);
                    }
                }
            }
        }
    }
    result
}

/// `None` removes every occurrence of a scalar in the winning declaration,
/// preventing an earlier repeated scalar from becoming effective again.
pub fn edit_group_source(
    source: &SourceSnapshot,
    name: &str,
    changes: &[(GroupField, Option<String>)],
) -> Result<String, SourceEditError> {
    let document = Document::parse_attempt(
        Source::new(&source.content, source.source.clone()),
        &mut Vec::new(),
        false,
    )
    .map_err(|_| SourceEditError)?;
    let group = document
        .sections()
        .filter(|root| root.header() == "group")
        .filter_map(|root| root.body_with(BodySyntax::Declarations))
        .flatten()
        .filter(|group| read::block_header(group).is_some_and(|header| header.raw() == name))
        .last()
        .ok_or(SourceEditError)?;
    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    let mut additions = String::new();
    let newline = if source.content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let line_start = source.content[..group.header_span().start]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    let prefix = &source.content[line_start..group.header_span().start];
    let indent = if prefix
        .chars()
        .all(|character| character == ' ' || character == '\t')
    {
        prefix
    } else {
        ""
    };
    for (index, (field, replacement)) in changes.iter().enumerate() {
        if changes[..index]
            .iter()
            .any(|(previous, _)| previous == field)
        {
            return Err(SourceEditError);
        }
        let fields: Vec<_> = group
            .body()
            .into_iter()
            .flatten()
            .filter(|statement| !statement.is_block() && !statement.is_ignored())
            .filter_map(|statement| {
                let text = Text::segment(&statement);
                let (key, value) = text.kv()?;
                (key.raw().trim() == field.key()).then_some((text, value.trim()))
            })
            .collect();
        match replacement {
            Some(value) => {
                let preferred = fields
                    .last()
                    .and_then(|(_, text)| text.raw().chars().next())
                    .filter(|quote| matches!(quote, '\'' | '"'));
                let encoded = quote_scalar(value, preferred)?;
                if let Some((_, value)) = fields.last() {
                    edits.push((value.span.start..value.span.end, encoded));
                } else {
                    if !additions.is_empty() {
                        additions.push_str(newline);
                    }
                    additions.push_str(indent);
                    additions.push_str("    ");
                    additions.push_str(field.key());
                    additions.push_str(": ");
                    additions.push_str(&encoded);
                }
            }
            None => {
                for (text, _) in fields {
                    edits.push((
                        line_of(&source.content, text.span.start..text.span.end),
                        String::new(),
                    ));
                }
            }
        }
    }
    if !additions.is_empty() {
        let close = group.span().end - 1;
        match own_line_start(&source.content, close) {
            Some(line_start) => edits.push((line_start..line_start, additions + newline)),
            None => edits.push((
                close..close,
                format!("{newline}{additions}{newline}{indent}"),
            )),
        }
    }
    edits.sort_unstable_by_key(|(range, _)| range.start);
    if edits.windows(2).any(|pair| pair[0].0.end > pair[1].0.start) {
        return Err(SourceEditError);
    }
    let mut output = source.content.to_string();
    for (range, text) in edits.into_iter().rev() {
        output.replace_range(range, &text);
    }
    Ok(output)
}

fn quote_scalar(value: &str, preferred: Option<char>) -> Result<String, SourceEditError> {
    if value.chars().any(char::is_control) {
        return Err(SourceEditError);
    }
    for quote in preferred.into_iter().chain(['\'', '"']) {
        let candidate = format!("{quote}{value}{quote}");
        if super::lexer::quoted_end(candidate.as_bytes(), 0) == Some(candidate.len()) {
            return Ok(candidate);
        }
    }
    Err(SourceEditError)
}

/// Append one validated, explicitly named node without expanding includes.
/// Duplicate names or derived node identities in this source are rejected.
pub fn append_node_source(
    source: &SourceSnapshot,
    name: &str,
    link: &str,
) -> Result<String, SourceEditError> {
    let (entry, config) = managed_entry("node", name, link, &[])?;
    let [node] = config.nodes.as_slice() else {
        return Err(SourceEditError);
    };
    if node.name != name {
        return Err(SourceEditError);
    }
    let document = managed_document(source)?;
    let sections = document
        .sections()
        .filter(|root| root.header() == "node")
        .collect::<Vec<_>>();
    let mut notices = Vec::new();
    let mut diagnostics =
        super::diagnostics::ParserDiagnostics::new(&mut notices, source.source.clone());
    let nodes = super::entries::parse_node_section(&sections, &mut diagnostics)
        .map_err(|_| SourceEditError)?;
    if nodes
        .iter()
        .any(|existing| existing.name == name || existing.id == node.id)
    {
        return Err(SourceEditError);
    }
    Ok(append_entry(&document, "node", &entry))
}

/// Remove the unique declaration with this parser-derived node identity.
/// `None` means this source owns no matching declaration; includes are untouched.
pub fn remove_node_source(
    source: &SourceSnapshot,
    id: uuid::Uuid,
) -> Result<Option<String>, SourceEditError> {
    let document = managed_document(source)?;
    let sections = document
        .sections()
        .filter(|root| root.header() == "node")
        .collect::<Vec<_>>();
    let mut notices = Vec::new();
    let mut diagnostics =
        super::diagnostics::ParserDiagnostics::new(&mut notices, source.source.clone());
    let mut target = None;
    let mut duplicate = false;
    super::entries::parse_node_section_indexed(&sections, &mut diagnostics, |node, span| {
        if node.id == id {
            duplicate |= target.replace(span.start..span.end).is_some();
        }
    })
    .map_err(|_| SourceEditError)?;
    if duplicate {
        return Err(SourceEditError);
    }
    Ok(target.map(|range| {
        let mut output = source.content.to_string();
        output.replace_range(line_of(&source.content, range), "");
        output
    }))
}

/// Per-subscription settings for a new entry; `None` keeps the default.
#[derive(Debug, Default, Clone, Copy)]
pub struct SubscriptionOptions<'a> {
    pub update_interval: Option<u64>,
    pub user_agent: Option<&'a str>,
    pub cache: Option<bool>,
}

/// Append an unfetched HTTP(S) subscription, rejecting duplicate source names.
/// Fetching and whole-candidate admission remain the coordinator's responsibility.
pub fn append_subscription_source(
    source: &SourceSnapshot,
    name: &str,
    url: &str,
    options: &SubscriptionOptions<'_>,
) -> Result<String, SourceEditError> {
    let quote = |value: &str| quote_scalar(value, None);
    let mut fields = Vec::new();
    if let Some(user_agent) = options.user_agent {
        fields.push(format!("ua: {}", quote(user_agent)?));
    }
    if let Some(seconds) = options.update_interval {
        fields.push(format!("interval: {seconds}s"));
    }
    if let Some(cache) = options.cache {
        fields.push(format!("cache: {cache}"));
    }
    let (entry, config) = managed_entry("subscription", name, url, &fields)?;
    let [subscription] = config.subscriptions.as_slice() else {
        return Err(SourceEditError);
    };
    let defaults = crate::subscription::Subscription::default();
    if subscription.name != name
        || subscription.url != url
        || subscription.user_agent.as_deref() != options.user_agent
        || subscription.update_interval
            != options.update_interval.unwrap_or(defaults.update_interval)
        || subscription.cache != options.cache.unwrap_or(defaults.cache)
        || url::Url::parse(url)
            .ok()
            .is_none_or(|url| url.host_str().is_none())
    {
        return Err(SourceEditError);
    }
    let document = managed_document(source)?;
    let sections = document
        .sections()
        .filter(|root| root.header() == "subscription")
        .collect::<Vec<_>>();
    let mut notices = Vec::new();
    let mut diagnostics =
        super::diagnostics::ParserDiagnostics::new(&mut notices, source.source.clone());
    // Only names are compared, and they do not depend on `assets` defaults.
    let subscriptions = super::entries::parse_subscription_section(
        &sections,
        &crate::assets::AssetsConfig::default(),
        &mut diagnostics,
    )
    .map_err(|_| SourceEditError)?;
    if subscriptions.iter().any(|existing| existing.name == name) {
        return Err(SourceEditError);
    }
    Ok(append_entry(&document, "subscription", &entry))
}

/// Match by name and fetch identity (URL, configured UA, headers), never the
/// parser's random subscription UUID or mutable refresh metadata. Ambiguous
/// duplicate declarations and legacy headers owning child entries are rejected.
/// `assets` is the loaded configuration's block, which any source may declare,
/// so an entry's effective UA matches the live subscription's.
pub fn remove_subscription_source(
    source: &SourceSnapshot,
    subscription: &crate::subscription::Subscription,
    assets: &crate::assets::AssetsConfig,
) -> Result<Option<String>, SourceEditError> {
    let document = managed_document(source)?;
    let sections = document
        .sections()
        .filter(|root| root.header() == "subscription")
        .collect::<Vec<_>>();
    let mut notices = Vec::new();
    let mut diagnostics =
        super::diagnostics::ParserDiagnostics::new(&mut notices, source.source.clone());
    let mut target = None;
    let mut ambiguous = false;
    super::entries::parse_subscription_section_indexed(
        &sections,
        assets,
        &mut diagnostics,
        |existing, span| {
            if existing.name == subscription.name
                && existing.url == subscription.url
                && existing.user_agent.as_deref().unwrap_or_default()
                    == subscription.user_agent.as_deref().unwrap_or_default()
                && existing.headers == subscription.headers
            {
                if let Some(span) = span {
                    ambiguous |= target.replace(span.start..span.end).is_some();
                } else {
                    ambiguous = true;
                }
            }
        },
    )
    .map_err(|_| SourceEditError)?;
    if ambiguous {
        return Err(SourceEditError);
    }
    Ok(target.map(|range| {
        let mut output = source.content.to_string();
        output.replace_range(line_of(&source.content, range), "");
        output
    }))
}

fn is_blank(byte: &u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

/// The whole line, newline included, when nothing but blanks shares it with
/// the declaration; deleting that range leaves no empty line behind.
fn line_of(content: &str, declaration: Range<usize>) -> Range<usize> {
    let bytes = content.as_bytes();
    let Some(line_start) = own_line_start(content, declaration.start) else {
        return declaration;
    };
    let mut line_end = declaration.end;
    while bytes.get(line_end).is_some_and(is_blank) {
        line_end += 1;
    }
    match &bytes[line_end..] {
        rest if rest.starts_with(b"\r\n") => line_start..line_end + 2,
        rest if rest.starts_with(b"\n") => line_start..line_end + 1,
        [] => line_start..line_end,
        _ => declaration,
    }
}

/// Start of the line when nothing but blanks precedes `offset` on it.
fn own_line_start(content: &str, offset: usize) -> Option<usize> {
    let line_start = content[..offset].rfind('\n').map_or(0, |end| end + 1);
    content[line_start..offset]
        .bytes()
        .all(|byte| is_blank(&byte))
        .then_some(line_start)
}

fn managed_document(source: &SourceSnapshot) -> Result<Document<'_>, SourceEditError> {
    Document::parse_attempt(
        Source::new(&source.content, source.source.clone()),
        &mut Vec::new(),
        false,
    )
    .map_err(|_| SourceEditError)
}

/// A scalar `name: value` entry, or with `fields` a block whose `url` is `value`.
fn managed_entry(
    section: &str,
    name: &str,
    value: &str,
    fields: &[String],
) -> Result<(String, crate::Config), SourceEditError> {
    if name.trim().is_empty() {
        return Err(SourceEditError);
    }
    let value = quote_scalar(value, None)?;
    let quoted = quote_scalar(name, None).map_err(|_| SourceEditError)?;
    let bare = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        .then(|| name.to_owned());
    // A bare key that the section reads back differently (`mux`) keeps its quotes.
    for key in bare.into_iter().chain([quoted]) {
        let entry = if fields.is_empty() {
            format!("{key}: {value}")
        } else {
            let mut entry = format!("{key}: {value} {{");
            for field in fields {
                entry.push_str(&format!("\n        {field}"));
            }
            entry + "\n    }"
        };
        let Ok(config) = super::parse_dae_config_with_detailed_diagnostics(
            &format!("{section} {{\n    {entry}\n}}"),
            &mut Vec::new(),
        ) else {
            continue;
        };
        let names: Vec<&str> = match section {
            "node" => config.nodes.iter().map(|node| node.name.as_str()).collect(),
            _ => config
                .subscriptions
                .iter()
                .map(|subscription| subscription.name.as_str())
                .collect(),
        };
        if names == [name] && config.validate().is_ok() {
            return Ok((entry, config));
        }
    }
    Err(SourceEditError)
}

fn append_entry(document: &Document<'_>, section: &str, entry: &str) -> String {
    let content = document.source().text();
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let entry = entry.replace('\n', newline);
    let mut output = content.to_owned();
    if let Some(root) = document.sections().rfind(|root| root.header() == section) {
        let close = root.span().end - 1;
        match own_line_start(content, close) {
            Some(line_start) => output.insert_str(line_start, &format!("    {entry}{newline}")),
            None => output.insert_str(close, &format!("{newline}    {entry}{newline}")),
        }
    } else {
        if !content.is_empty() && !content.ends_with('\n') {
            output.push_str(newline);
        }
        output.push_str(&format!(
            "{section} {{{newline}    {entry}{newline}}}{newline}"
        ));
    }
    output
}

/// Encode `value` as a dae scalar that reads back unchanged.
fn quote_dae_scalar(value: &str) -> Result<String, SourceEditError> {
    if let Ok(quoted) = quote_scalar(value, None) {
        return Ok(quoted);
    }
    if value.chars().any(char::is_control) {
        return Err(SourceEditError);
    }
    // dae preserves backslashes, so adding quote escapes would change the value.
    // Only use bare text when the canonical reader sees exactly one scalar.
    let candidate = format!("global {{\nvalue: {value}\n}}\n");
    let document = plain_document(&candidate)?;
    let mut roots = document.sections();
    let root = roots.next().ok_or(SourceEditError)?;
    let mut fields = root.body().ok_or(SourceEditError)?;
    let field = fields.next().ok_or(SourceEditError)?;
    if roots.next().is_some()
        || fields.next().is_some()
        || field.is_block()
        || field.is_ignored()
        || !Text::segment(&field)
            .kv()
            .is_some_and(|(key, parsed)| key.raw() == "value" && parsed.unquote().raw() == value)
    {
        return Err(SourceEditError);
    }
    Ok(value.to_owned())
}

/// Remove every `secret:` of `experimental.native_api` and `.clash_api`,
/// duplicates and overridden ones included.
pub fn strip_listener_secrets(content: &str) -> Result<String, SourceEditError> {
    let document = plain_document(content)?;
    let mut ranges = Vec::new();
    for block in listener_blocks(&document) {
        for field in block.1.body().into_iter().flatten() {
            let text = Text::segment(&field);
            if text.kv().is_some_and(|(key, _)| key.raw() == "secret") {
                ranges.push(line_of(content, text.span.start..text.span.end));
            }
        }
    }
    let mut output = content.to_owned();
    for range in ranges.into_iter().rev() {
        output.replace_range(range, "");
    }
    if super::sources::contains_api_secret(&plain_document(&output)?) {
        return Err(SourceEditError);
    }
    Ok(output)
}

/// Put listener secrets back into content without any; an empty value is not
/// written. Each goes into the last block of its API.
pub fn restore_listener_secrets(
    content: &str,
    native_api: &str,
    clash_api: &str,
) -> Result<String, SourceEditError> {
    let document = plain_document(content)?;
    if super::sources::contains_api_secret(&document) {
        return Err(SourceEditError);
    }
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let blocks = listener_blocks(&document);
    let mut edits = Vec::new();
    for (api, value) in [("native_api", native_api), ("clash_api", clash_api)] {
        if value.is_empty() {
            continue;
        }
        let (_, block) = blocks
            .iter()
            .rfind(|(name, _)| *name == api)
            .ok_or(SourceEditError)?;
        let entry = format!("secret: {}", quote_dae_scalar(value)?);
        let close = block.span().end - 1;
        let edit = match own_line_start(content, close) {
            Some(line_start) => {
                let indent = &content[line_start..close];
                (line_start, format!("{indent}    {entry}{newline}"))
            }
            // Fields are line-separated, so a compact block gets its own lines.
            None => (close, format!("{newline}{entry}{newline}")),
        };
        edits.push(edit);
    }
    edits.sort_unstable_by_key(|(offset, _)| *offset);
    let mut output = content.to_owned();
    for (offset, text) in edits.into_iter().rev() {
        output.insert_str(offset, &text);
    }
    Ok(output)
}

/// Join preorder sources into one document without their `include` roots,
/// which parses to the same `Config` as the tree.
pub fn inline_sources(sources: &[SourceSnapshot]) -> Result<String, SourceEditError> {
    let mut output = String::new();
    for source in sources {
        let document = managed_document(source)?;
        let mut content = source.content.to_string();
        let includes: Vec<_> = document
            .sections()
            .filter(|root| root.header() == "include")
            .map(|root| line_of(&source.content, root.span().start..root.span().end))
            .collect();
        for range in includes.into_iter().rev() {
            content.replace_range(range, "");
        }
        output.push_str(&content);
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
    }
    Ok(output)
}

fn plain_document(content: &str) -> Result<Document<'_>, SourceEditError> {
    let source = crate::diagnostic::DiagnosticSources::new(None).root();
    Document::parse_attempt(Source::new(content, source), &mut Vec::new(), false)
        .map_err(|_| SourceEditError)
}

fn listener_blocks<'d, 'a>(
    document: &'d Document<'a>,
) -> Vec<(&'d str, super::cursor::Segment<'d, 'a>)> {
    document
        .sections()
        .filter(|root| root.header() == "experimental")
        .filter_map(|root| root.body())
        .flatten()
        .filter_map(|block| {
            let name = read::block_header(&block)?.raw();
            matches!(name, "native_api" | "clash_api").then_some((name, block))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSourceLocation {
    pub source_index: usize,
    pub bytes: Range<usize>,
    pub line: usize,
    pub column: usize,
    /// Comment-free condition display, or the whole fallback statement.
    pub expression: String,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSourceIndex {
    pub rules: Vec<RuleSourceLocation>,
    pub fallback: Option<RuleSourceLocation>,
    pub dns_request: DnsRuleSources,
    pub dns_response: DnsRuleSources,
}

/// One DNS rule list; `expression` holds the whole statement as written,
/// including its action.
#[derive(Debug, Clone, Default)]
pub struct DnsRuleSources {
    pub rules: Vec<RuleSourceLocation>,
    pub fallback: Option<RuleSourceLocation>,
}

/// Index the runtime's last group declarations and the real rule parser's
/// ordinals from accepted source bytes, never display strings or file labels.
pub fn source_indices(
    sources: &[SourceSnapshot],
) -> Result<(HashMap<String, usize>, RuleSourceIndex), SourceEditError> {
    let mut notices = Vec::new();
    let documents = sources
        .iter()
        .map(|source| {
            Document::parse_attempt(
                Source::new(&source.content, source.source.clone()),
                &mut notices,
                false,
            )
            .map_err(|_| SourceEditError)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let groups = group_source_indices(&documents);
    let sections = documents
        .iter()
        .flat_map(Document::sections)
        .filter(|section| section.header() == "routing")
        .collect::<Vec<_>>();
    let mut result = RuleSourceIndex::default();
    let Some(source) = sources.first() else {
        return Ok((groups, result));
    };
    let mut diagnostics =
        super::diagnostics::ParserDiagnostics::new(&mut notices, source.source.clone());
    super::routing::parse_section_indexed(&sections, &mut diagnostics, |ordinal, statement| {
        let span = statement.span;
        if let Some(index) = sources
            .iter()
            .position(|source| source.source.index() == span.source)
        {
            let (line, column) = documents[index].source().location(span.start);
            let location = RuleSourceLocation {
                source_index: index,
                bytes: span.start..span.end,
                line,
                column,
                expression: match ordinal {
                    Some(_) => statement.sub(span.start, statement.find("->").unwrap()),
                    None => statement,
                }
                .trim()
                .display(),
            };
            if ordinal.is_some() {
                result.rules.push(location);
            } else {
                result.fallback = Some(location);
            }
        }
    })
    .map_err(|_| SourceEditError)?;
    let dns = documents
        .iter()
        .flat_map(Document::sections)
        .filter(|section| section.header() == "dns")
        .collect::<Vec<_>>();
    super::dns::parse_routing_indexed(&dns, &mut diagnostics, |response, index, line| {
        let Some(source_index) = sources
            .iter()
            .position(|source| source.source.index() == line.span.source)
        else {
            return;
        };
        let (line_number, column) = documents[source_index].source().location(line.span.start);
        let location = RuleSourceLocation {
            source_index,
            bytes: line.span.start..line.span.end,
            line: line_number,
            column,
            expression: line.trim().raw().to_owned(),
        };
        let list = if response {
            &mut result.dns_response
        } else {
            &mut result.dns_request
        };
        match index {
            Some(_) => list.rules.push(location),
            None => list.fallback = Some(location),
        }
    });
    Ok((groups, result))
}

#[cfg(test)]
mod tests;
