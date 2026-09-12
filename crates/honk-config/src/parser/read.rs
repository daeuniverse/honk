//! Reader punctuation over lexical spans; quotes and comments remain lexer-owned.

use super::cursor::Segment;
use super::diagnostics::ParserDiagnostics;
use super::lexer::{Source, Span, Token, TokenKind};
use crate::diagnostic::Severity;

#[derive(Clone, Copy)]
pub(super) struct Text<'d, 'a> {
    pub source: &'d Source<'a>,
    pub tokens: &'d [Token],
    pub span: Span,
    pub comment: Option<&'d Token>,
}

impl<'d, 'a> Text<'d, 'a> {
    pub fn segment(segment: &Segment<'d, 'a>) -> Self {
        Self {
            source: segment.source(),
            tokens: segment.tokens(),
            span: segment.header_span(),
            comment: segment.comment(),
        }
    }

    pub fn raw(self) -> &'d str {
        self.source.raw(self.span)
    }

    pub fn sub(self, start: usize, end: usize) -> Self {
        let span = self
            .source
            .span(self.span.start + start, self.span.start + end);
        let first = self
            .tokens
            .partition_point(|token| token.span.end <= span.start);
        let last = if span.start == span.end {
            first
        } else {
            self.tokens
                .partition_point(|token| token.span.start < span.end)
        };
        Self {
            tokens: &self.tokens[first..last],
            span,
            ..self
        }
    }

    pub fn trim(self) -> Self {
        let raw = self.raw();
        let start = raw.len() - raw.trim_start().len();
        self.sub(start, start + raw.trim().len())
    }

    fn quotes(self) -> impl Iterator<Item = Span> + 'd {
        let bounds = self.span;
        self.tokens.iter().flat_map(move |token| {
            let first = token
                .quoted
                .partition_point(|quote| quote.start < bounds.start);
            let quoted = &token.quoted[first..];
            let last = quoted.partition_point(|quote| quote.end <= bounds.end);
            quoted[..last].iter().copied().filter(move |quote| {
                quote.source == bounds.source
                    && bounds.start <= quote.start
                    && quote.end <= bounds.end
            })
        })
    }

    pub fn quoted_prefix(self) -> Option<Self> {
        let text = self.trim();
        text.quotes()
            .find(|span| span.start == text.span.start)
            .map(|span| text.sub(0, span.end - text.span.start))
    }

    pub fn unquote(self) -> Self {
        let text = self.trim();
        if let Some(quoted) = text
            .quoted_prefix()
            .filter(|quoted| quoted.span == text.span)
        {
            Self {
                span: quoted.span.interior(),
                ..text
            }
        } else {
            text
        }
    }

    pub(super) fn delimiter_positions<'s>(
        self,
        delimiter: &'s str,
    ) -> impl Iterator<Item = usize> + 's
    where
        'd: 's,
    {
        assert!(!delimiter.is_empty(), "delimiter must not be empty");
        let raw = self.raw();
        let mut quotes = self.quotes().peekable();
        let mut offset = 0;
        std::iter::from_fn(move || {
            loop {
                if offset + delimiter.len() > raw.len() {
                    return None;
                }
                let position = self.span.start + offset;
                while quotes.peek().is_some_and(|quote| quote.end <= position) {
                    quotes.next();
                }
                if let Some(quote) = quotes.peek().filter(|quote| quote.start <= position) {
                    offset = quote.end - self.span.start;
                    quotes.next();
                    continue;
                }
                if raw[offset..].starts_with(delimiter) {
                    offset += delimiter.len();
                    return Some(position);
                }
                offset += raw[offset..].chars().next()?.len_utf8();
            }
        })
    }

    pub fn find(self, delimiter: &str) -> Option<usize> {
        self.delimiter_positions(delimiter)
            .next()
            .map(|position| position - self.span.start)
    }

    pub fn split<'s>(self, delimiter: &'s str) -> impl Iterator<Item = Self> + 's
    where
        'd: 's,
    {
        let mut delimiters = self.delimiter_positions(delimiter);
        let mut start = self.span.start;
        let mut done = false;
        std::iter::from_fn(move || {
            if done {
                return None;
            }
            if let Some(end) = delimiters.next() {
                let part = self.sub(start - self.span.start, end - self.span.start);
                start = end + delimiter.len();
                Some(part)
            } else {
                done = true;
                Some(self.sub(start - self.span.start, self.span.end - self.span.start))
            }
        })
    }

    pub(super) fn parentheses(self) -> impl Iterator<Item = (usize, u8)> + 'd {
        let raw = self.raw().as_bytes();
        let mut quotes = self.quotes().peekable();
        let mut offset = 0;
        std::iter::from_fn(move || {
            loop {
                let &byte = raw.get(offset)?;
                let position = self.span.start + offset;
                while quotes.peek().is_some_and(|quote| quote.end <= position) {
                    quotes.next();
                }
                if let Some(quote) = quotes.peek().filter(|quote| quote.start <= position) {
                    offset = quote.end - self.span.start;
                    quotes.next();
                    continue;
                }
                offset += 1;
                if matches!(byte, b'(' | b')') {
                    return Some((position, byte));
                }
            }
        })
    }

    /// Return the leading parenthesized body and its untouched trailing span.
    pub fn parenthesized(self) -> Option<(Self, Self)> {
        if !self.raw().starts_with('(') {
            return None;
        }
        let mut depth = 0;
        for (position, byte) in self.parentheses() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        let end = position - self.span.start;
                        return Some((self.sub(1, end), self.sub(end + 1, self.raw().len())));
                    }
                }
                _ => unreachable!(),
            }
        }
        None
    }

    pub fn kv(self) -> Option<(Self, Self)> {
        let colon = self.find(":")?;
        Some((
            self.sub(0, colon).trim(),
            self.sub(colon + 1, self.raw().len()).trim(),
        ))
    }

    pub fn has_error(self) -> bool {
        self.tokens.iter().any(|token| {
            matches!(token.kind, TokenKind::Error { .. })
                && token.span.start < self.span.end
                && self.span.start < token.span.end
        })
    }
    /// The `#` that starts a comment after this text on its source line, if any.
    /// The lexer owns comment boundaries; this view only narrows the token span
    /// to the hash byte used by existing diagnostics.
    pub fn trailing_comment(self) -> Option<Self> {
        let comment = self.comment?;
        (comment.span.start >= self.span.end).then(|| Self {
            span: self.source.span(comment.span.start, comment.span.start + 1),
            ..self
        })
    }

    /// K01: warn once where the old parser truncated a glued hash.
    pub fn warn_glued_hash(self, diagnostics: &mut ParserDiagnostics<'_>) {
        let raw = self.raw();
        for position in self.delimiter_positions("#") {
            let offset = position - self.span.start;
            if offset == 0 || raw.as_bytes()[offset - 1].is_ascii_whitespace() {
                continue;
            }
            self.sub(offset, offset + 1).notice(
                diagnostics,
                Severity::Warning,
                "legacy-glued-hash",
                "glued `#` is data; separate comments with whitespace",
            );
            break;
        }
    }

    pub fn notice(
        self,
        sink: &mut ParserDiagnostics<'_>,
        severity: Severity,
        code: &'static str,
        message: &'static str,
    ) {
        sink.notice(self.source.diagnostic(self.span, severity, code, message));
    }
}

/// Compact empty blocks are a frozen compatibility form, not brace tokens in values.
pub(super) fn block_header<'d, 'a>(segment: &Segment<'d, 'a>) -> Option<Text<'d, 'a>> {
    let header = Text::segment(segment).trim();
    if segment.body().is_some() {
        return Some(header);
    }
    let last = segment.tokens().last()?;
    (last.kind == TokenKind::Word
        && header.source.raw(last.span) == "{}"
        && last.span.start > header.span.start)
        .then(|| header.sub(0, last.span.start - header.span.start).trim())
}

pub(super) fn child_statements<'d, 'a>(
    segment: &Segment<'d, 'a>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Vec<Text<'d, 'a>> {
    let mut output = Vec::new();
    if let Some(body) = segment.body() {
        for child in body {
            if let Some(header) = block_header(&child) {
                header.notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-block",
                    "unknown nested block ignored; move settings to their documented level",
                );
            } else {
                let text = Text::segment(&child);
                if text.raw().starts_with("/*") {
                    text.notice(
                        diagnostics,
                        Severity::Warning,
                        "unsupported-comment",
                        "use `#` on each intended comment line",
                    );
                } else {
                    output.push(text);
                }
            }
        }
    }
    output
}

pub(super) fn statements<'d, 'a>(
    section: &[Segment<'d, 'a>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Vec<Text<'d, 'a>> {
    section
        .iter()
        .flat_map(|segment| child_statements(segment, diagnostics))
        .collect()
}
