//! Structural indexing and independent Caddy-style dispensers; no setting decoding.

use std::ops::Range;

use super::lexer::{Lexer, Source, Span, Token, TokenKind};
use crate::diagnostic::{DetailedDiagnostic, SettingPath, Severity};
use crate::error::{DetailedConfigError, ErrorCategory};

/// The root sections a document can carry. One list, matched exhaustively by
/// the reader dispatch, so a root cannot be indexed here and forgotten there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    Include,
    Global,
    Node,
    Group,
    Subscription,
    Routing,
    Dns,
    Experimental,
}

impl Root {
    pub const ALL: [Root; 8] = [
        Root::Include,
        Root::Global,
        Root::Node,
        Root::Group,
        Root::Subscription,
        Root::Routing,
        Root::Dns,
        Root::Experimental,
    ];

    pub fn parse(name: &str) -> Option<Root> {
        Root::ALL.into_iter().find(|root| root.name() == name)
    }

    /// Sections whose readers turn a statement with an unterminated quote into a
    /// skipped contribution once every open block still closes (K05). Elsewhere
    /// the document fails at the quote.
    pub fn recovers_from_quote_errors(self) -> bool {
        matches!(self, Root::Group | Root::Node | Root::Dns)
    }

    pub fn name(self) -> &'static str {
        match self {
            Root::Include => "include",
            Root::Global => "global",
            Root::Node => "node",
            Root::Group => "group",
            Root::Subscription => "subscription",
            Root::Routing => "routing",
            Root::Dns => "dns",
            Root::Experimental => "experimental",
        }
    }
}

/// Related opener coordinates stay local until the diagnostic model supports related spans.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct StructureError {
    pub error: DetailedConfigError,
    pub unclosed: Option<Span>,
    /// Whether a root-level `include` opener was successfully indexed before failure.
    pub saw_include: bool,
}

#[derive(Debug)]
pub struct Document<'a> {
    source: Source<'a>,
    tokens: Vec<Token>,
    comments: Vec<Token>,
    closes: Vec<usize>,
    sections: Vec<Range<usize>>,
}

struct Frame {
    start: usize,
    open: usize,
    header: Span,
    quote: Option<usize>,
}

#[derive(Clone, Copy)]
struct PendingHeader {
    start: usize,
    has_unquoted_colon: bool,
}

impl<'a> Document<'a> {
    /// Standalone structural attempt: appends diagnostics, including one terminal cause.
    /// Recoverable error tokens remain visible to the owning section reader.
    pub fn parse(
        source: Source<'a>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Self, StructureError> {
        let result = Self::parse_attempt(source, diagnostics);
        if let Err(error) = &result {
            diagnostics.push((*error.error.diagnostic).clone());
        }
        result
    }

    pub(super) fn parse_attempt(
        source: Source<'a>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Self, StructureError> {
        let mut doc = Self {
            closes: Vec::new(),
            source,
            tokens: Vec::new(),
            comments: Vec::new(),
            sections: Vec::new(),
        };
        let mut lexer = Lexer::default();
        let mut frames: Vec<Frame> = Vec::new();
        let mut root_ranges = Vec::new();
        let mut pending: Option<PendingHeader> = None;
        let mut saw_open = false;
        let mut saw_include = false;
        let attempt_start = diagnostics.len();
        loop {
            let include_paths = frames
                .first()
                .is_some_and(|frame| doc.source.raw(frame.header) == "include");
            let Some(token) = lexer.next_token(&doc.source, include_paths) else {
                break;
            };
            match token.kind {
                TokenKind::Comment => {
                    doc.comments.push(token);
                    continue;
                }
                kind if kind.is_trivia() => continue,
                _ => {}
            }
            let index = doc.tokens.len();
            doc.tokens.push(token);
            doc.closes.push(usize::MAX);
            let token = &doc.tokens[index];
            let split_include = pending.is_some_and(|header| {
                let start = header.start;
                frames.is_empty()
                    && index == start + 1
                    && token.kind == TokenKind::OpenBrace
                    && doc.source.raw(doc.tokens[start].span) == "include"
            });
            let compact_empty = pending.is_some_and(|header| {
                let start = header.start;
                frames.is_empty()
                    && token.kind == TokenKind::Word
                    && doc.source.raw(token.span) == "{}"
                    && !header.has_unquoted_colon
                    && (token.line == doc.tokens[start].line
                        || (index == start + 1
                            && doc.source.raw(doc.tokens[start].span) == "include"))
            });
            if compact_empty {
                let start = pending.take().unwrap().start;
                let header = doc.range_span(start..index);
                let name = doc.source.raw(header);
                if token.line != doc.tokens[start].line {
                    diagnostics.push(doc.source.diagnostic(
                        token.span,
                        Severity::Warning,
                        "legacy-include-opener",
                        "put the include opener on its header line",
                    ));
                }
                if Root::parse(name).is_none() {
                    diagnostics.push(doc.source.diagnostic(
                        token.span,
                        Severity::Warning,
                        "unknown-block",
                        "unknown top-level block ignored",
                    ));
                } else if name == "include" {
                    saw_include = true;
                }
                if Root::parse(name).is_some() {
                    doc.sections.push(start..index + 1);
                }
                root_ranges.push((doc.range_span(start..index + 1), header));
                saw_open = true;
                continue;
            }
            if let Some(header) = pending
                && index > 0
                && token.line != doc.tokens[index - 1].line
                && !split_include
            {
                if frames.is_empty() {
                    doc.warn_statement(header.start..index, diagnostics);
                }
                pending = None;
            }
            match token.kind {
                TokenKind::OpenBrace => {
                    let Some(pending_header) = pending.take() else {
                        doc.warn_comment_braces(
                            &root_ranges,
                            frames.first(),
                            token.span.start,
                            diagnostics,
                        );
                        return Err(reject(
                            doc.source.diagnostic(
                                token.span,
                                Severity::Error,
                                "unexpected-open-brace",
                                "block opener requires a header on the same line",
                            ),
                            None,
                            None,
                            saw_include,
                            diagnostics,
                        ));
                    };
                    let start = pending_header.start;
                    let header = doc.range_span(start..index);
                    let root = frames.is_empty();
                    let name = doc.source.raw(header);
                    if token.line != doc.tokens[start].line {
                        diagnostics.push(doc.source.diagnostic(
                            token.span,
                            Severity::Warning,
                            "legacy-include-opener",
                            "put the include opener on its header line",
                        ));
                    }
                    if root && name == "include" {
                        saw_include = true;
                    }
                    if root && Root::parse(name).is_none() {
                        diagnostics.push(doc.source.diagnostic(
                            token.span,
                            Severity::Warning,
                            "unknown-block",
                            "unknown top-level block ignored",
                        ));
                    }
                    frames.push(Frame {
                        start,
                        open: index,
                        header,
                        quote: None,
                    });
                    saw_open = true;
                }
                TokenKind::CloseBrace => {
                    if frames.is_empty() {
                        if let Some(header) = pending {
                            doc.warn_statement(header.start..index, diagnostics);
                        }
                        diagnostics.push(doc.source.diagnostic(
                            token.span,
                            Severity::Warning,
                            "unmatched-close",
                            "unmatched closing brace ignored",
                        ));
                    } else {
                        let frame = frames.pop().unwrap();
                        doc.closes[frame.open] = index;
                        if frames.is_empty() {
                            root_ranges
                                .push((doc.range_span(frame.start..index + 1), frame.header));
                            if Root::parse(doc.source.raw(frame.header)).is_some() {
                                doc.sections.push(frame.start..index + 1);
                            }
                        }
                    }
                    pending = None;
                }
                TokenKind::Error { opener } => {
                    let diagnostic = doc.source.quote_error(opener, token.span.end);
                    let position = diagnostics.len();
                    let recoverable = frames.first().is_some_and(|frame| {
                        Root::parse(doc.source.raw(frame.header))
                            .is_some_and(Root::recovers_from_quote_errors)
                    });
                    if !recoverable {
                        doc.warn_comment_braces(
                            &root_ranges,
                            frames.first(),
                            token.span.start,
                            diagnostics,
                        );
                        return Err(reject(diagnostic, None, None, saw_include, diagnostics));
                    }
                    diagnostics.push(diagnostic);
                    for frame in frames.iter_mut().rev() {
                        if frame.quote.is_some() {
                            break;
                        }
                        frame.quote = Some(position);
                    }
                    pending.get_or_insert(PendingHeader {
                        start: index,
                        has_unquoted_colon: false,
                    });
                }
                TokenKind::Word => {
                    let header = pending.get_or_insert(PendingHeader {
                        start: index,
                        has_unquoted_colon: false,
                    });
                    if frames.is_empty() && !header.has_unquoted_colon {
                        header.has_unquoted_colon = doc.unquoted_contains(token, b':');
                    }
                    let raw = doc.source.raw(token.span);
                    let glued_empty_root =
                        frames.is_empty() && raw.len() > 2 && raw.ends_with("{}");
                    if (raw.ends_with('{') || glued_empty_root)
                        && !token.quoted.iter().any(|span| span.end == token.span.end)
                    {
                        doc.warn_comment_braces(
                            &root_ranges,
                            frames.first(),
                            token.span.start,
                            diagnostics,
                        );
                        let start = token.span.end - if glued_empty_root { 2 } else { 1 };
                        let brace = doc.source.span(start, start + 1);
                        return Err(reject(
                            doc.source.diagnostic(
                                brace,
                                Severity::Error,
                                "block-delimiter-spacing",
                                "separate block braces from the header with whitespace",
                            ),
                            None,
                            None,
                            saw_include,
                            diagnostics,
                        ));
                    }
                }
                _ => unreachable!("trivia was removed"),
            }
        }
        doc.warn_comment_braces(
            &root_ranges,
            frames.first(),
            doc.source.text().len(),
            diagnostics,
        );
        if let Some(frame) = frames
            .iter()
            .rev()
            .find(|frame| frame.quote.is_some())
            .or_else(|| frames.last())
        {
            let (mut diagnostic, existing) = if let Some(position) = frame.quote {
                (diagnostics[position].clone(), Some(position))
            } else {
                (
                    doc.source.diagnostic(
                        frame.header,
                        Severity::Error,
                        "unclosed-block",
                        "block has no surviving closing brace",
                    ),
                    None,
                )
            };
            let root = doc.source.raw(frames[0].header);
            if let Some(name) = Root::parse(root).map(Root::name) {
                diagnostic.setting = SettingPath::new(name);
            }
            return Err(reject(
                diagnostic,
                Some(frame.header),
                existing,
                saw_include,
                diagnostics,
            ));
        }
        if !saw_open {
            diagnostics.truncate(attempt_start);
            let eof = doc
                .source
                .span(doc.source.text().len(), doc.source.text().len());
            return Err(reject(
                doc.source.diagnostic(
                    eof,
                    Severity::Error,
                    "not-dae-config",
                    "document contains no block",
                ),
                None,
                None,
                saw_include,
                diagnostics,
            ));
        }
        if let Some(header) = pending {
            doc.warn_statement(header.start..doc.tokens.len(), diagnostics);
        }
        Ok(doc)
    }

    pub fn source(&self) -> &Source<'a> {
        &self.source
    }
    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    pub fn sections(&self) -> impl DoubleEndedIterator<Item = Segment<'_, 'a>> {
        self.sections.iter().map(|range| {
            let mut segment = self.segment(range.clone());
            if segment.open.is_none() {
                segment.header = self.range_span(range.start..range.end - 1);
            }
            segment
        })
    }

    pub(super) fn segment(&self, range: Range<usize>) -> Segment<'_, 'a> {
        let open = range
            .clone()
            .find(|&i| self.tokens[i].kind == TokenKind::OpenBrace);
        Segment {
            doc: self,
            range: range.clone(),
            open,
            header: self.range_span(range.start..open.unwrap_or(range.end)),
        }
    }

    /// Whether `byte` occurs in the token outside its quoted spans; punctuation
    /// inside quotes is data and never a structural signal.
    fn unquoted_contains(&self, token: &Token, byte: u8) -> bool {
        let bytes = self.source.raw(token.span).as_bytes();
        let mut start = 0;
        for quote in &token.quoted {
            let end = quote.start - token.span.start;
            if bytes[start..end].contains(&byte) {
                return true;
            }
            start = quote.end - token.span.start;
        }
        bytes[start..].contains(&byte)
    }

    fn range_span(&self, range: Range<usize>) -> Span {
        self.source.span(
            self.tokens[range.start].span.start,
            self.tokens[range.end - 1].span.end,
        )
    }

    fn warn_comment_braces(
        &self,
        roots: &[(Span, Span)],
        active_root: Option<&Frame>,
        end: usize,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) {
        let active_root = active_root.map(|frame| {
            (
                self.source.span(self.tokens[frame.start].span.start, end),
                frame.header,
            )
        });
        for comment in &self.comments {
            if !self.source.raw(comment.span).contains(['{', '}']) {
                continue;
            }
            let position = roots.partition_point(|(span, _)| span.end <= comment.span.start);
            let Some(&(_, header)) =
                roots
                    .get(position)
                    .or(active_root.as_ref())
                    .filter(|(span, _)| {
                        span.start <= comment.span.start && comment.span.start < span.end
                    })
            else {
                continue;
            };
            let root = self.source.raw(header);
            if root == "include" {
                continue;
            }
            let previous = self
                .tokens
                .partition_point(|token| token.span.end <= comment.span.start);
            if root == "dns" && (previous == 0 || self.tokens[previous - 1].line != comment.line) {
                continue;
            }
            diagnostics.push(self.source.diagnostic(
                comment.span,
                Severity::Warning,
                "legacy-comment-brace",
                "comments do not close blocks; put the closer outside the comment",
            ));
        }
    }

    fn warn_statement(&self, range: Range<usize>, diagnostics: &mut Vec<DetailedDiagnostic>) {
        let span = self.range_span(range);
        let code = if self.source.raw(span).starts_with("/*") {
            "unsupported-comment"
        } else {
            "unknown-statement"
        };
        diagnostics.push(self.source.diagnostic(
            span,
            Severity::Warning,
            code,
            "unknown top-level statement ignored",
        ));
    }
}

fn reject(
    mut diagnostic: DetailedDiagnostic,
    unclosed: Option<Span>,
    existing: Option<usize>,
    saw_include: bool,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> StructureError {
    diagnostic.terminal = true;
    if let Some(index) = existing {
        diagnostics.remove(index);
    }
    StructureError {
        error: DetailedConfigError {
            category: ErrorCategory::Parse,
            diagnostic: Box::new(diagnostic),
        },
        unclosed,
        saw_include,
    }
}

#[derive(Debug)]
pub struct Segment<'d, 'a> {
    doc: &'d Document<'a>,
    range: Range<usize>,
    open: Option<usize>,
    header: Span,
}

impl<'d, 'a> Segment<'d, 'a> {
    pub fn span(&self) -> Span {
        self.doc.range_span(self.range.clone())
    }
    pub fn header_span(&self) -> Span {
        self.header
    }

    pub fn header(&self) -> &'d str {
        self.doc.source.raw(self.header_span())
    }
    pub fn body(&self) -> Option<Dispenser<'d, 'a>> {
        self.open
            .map(|open| Dispenser::new(self.doc, open + 1..self.doc.closes[open]))
    }
    pub(super) fn source(&self) -> &'d Source<'a> {
        &self.doc.source
    }

    /// Return the comment token that follows this segment's header or statement
    /// on its physical line.
    pub(super) fn comment(&self) -> Option<&'d Token> {
        let end = self.open.unwrap_or(self.range.end - 1);
        let last = self.doc.tokens.get(end)?;
        let position = self
            .doc
            .comments
            .partition_point(|comment| comment.span.start < last.span.end);
        self.doc.comments.get(position).filter(|comment| {
            comment.line == last.line
                && self
                    .doc
                    .tokens
                    .get(end + 1)
                    .is_none_or(|next| next.span.start > comment.span.start)
        })
    }
    pub(super) fn tokens(&self) -> &'d [Token] {
        &self.doc.tokens[self.range.clone()]
    }
}

#[derive(Debug, Clone)]
pub struct Dispenser<'d, 'a> {
    doc: &'d Document<'a>,
    range: Range<usize>,
}

impl<'d, 'a> Dispenser<'d, 'a> {
    fn new(doc: &'d Document<'a>, range: Range<usize>) -> Self {
        Self { doc, range }
    }
}

impl<'d, 'a> Iterator for Dispenser<'d, 'a> {
    type Item = Segment<'d, 'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.is_empty() {
            return None;
        }
        let start = self.range.start;
        let mut end = start + 1;
        while end < self.range.end
            && (same_physical_line(&self.doc.tokens[start], &self.doc.tokens[end])
                || self.doc.tokens[end].kind == TokenKind::OpenBrace)
        {
            match self.doc.tokens[end].kind {
                TokenKind::OpenBrace => {
                    end = self.doc.closes[end] + 1;
                    break;
                }
                TokenKind::CloseBrace => break,
                _ => end += 1,
            }
        }
        self.range.start = end;
        Some(self.doc.segment(start..end))
    }
}

pub fn same_physical_line(left: &Token, right: &Token) -> bool {
    left.span.source == right.span.source && left.line == right.line
}

pub fn adjacent(left: Span, right: Span) -> bool {
    left.source == right.source && left.end == right.start
}
