//! Lossless physical-line tokens. Semantic punctuation belongs to section readers.

use crate::diagnostic::{DetailedDiagnostic, SafeValue, SettingPath, Severity, SourceRef};
use std::sync::Arc;

/// Half-open UTF-8 byte coordinates in the source's attempt-local table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub source: usize,
    pub start: usize,
    pub end: usize,
}

impl Span {
    /// Interior of a matched quote span; escapes remain source bytes.
    pub fn interior(self) -> Self {
        assert!(self.end >= self.start + 2);
        Self {
            start: self.start + 1,
            end: self.end - 1,
            ..self
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Word,
    Whitespace,
    Newline,
    Comment,
    OpenBrace,
    CloseBrace,
    Error { opener: usize },
}

impl TokenKind {
    pub fn is_trivia(self) -> bool {
        matches!(self, Self::Whitespace | Self::Newline | Self::Comment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub span: Span,
    /// Matched spans including both quote delimiters, in source order.
    pub quoted: Vec<Span>,
    pub kind: TokenKind,
    pub line: usize,
}

/// Borrows input once; diagnostics retain only `reference` metadata.
#[derive(Debug, Clone)]
pub struct Source<'a> {
    text: SourceText<'a>,
    reference: SourceRef,
    line_starts: Arc<[usize]>,
}

#[derive(Debug, Clone)]
enum SourceText<'a> {
    Borrowed(&'a str),
    Shared(Arc<str>),
}

impl<'a> Source<'a> {
    pub fn new(text: &'a str, reference: SourceRef) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(
            text.bytes()
                .enumerate()
                .filter_map(|(i, b)| (b == b'\n').then_some(i + 1)),
        );
        Self {
            text: SourceText::Borrowed(text),
            reference,
            line_starts: line_starts.into(),
        }
    }

    pub(super) fn shared(text: Arc<str>, reference: SourceRef) -> Source<'static> {
        let line_starts: Arc<[usize]> = std::iter::once(0)
            .chain(
                text.bytes()
                    .enumerate()
                    .filter_map(|(i, b)| (b == b'\n').then_some(i + 1)),
            )
            .collect();
        Source {
            text: SourceText::Shared(text),
            reference,
            line_starts,
        }
    }

    pub fn text(&self) -> &str {
        match &self.text {
            SourceText::Borrowed(text) => text,
            SourceText::Shared(text) => text,
        }
    }

    pub(super) fn reference(&self) -> SourceRef {
        self.reference.clone()
    }

    pub fn span(&self, start: usize, end: usize) -> Span {
        Span {
            source: self.reference.index(),
            start,
            end,
        }
    }

    pub fn raw(&self, span: Span) -> &str {
        assert_eq!(span.source, self.reference.index());
        &self.text()[span.start..span.end]
    }

    pub fn location(&self, offset: usize) -> (usize, usize) {
        assert!(offset <= self.text().len());
        let line = self.line_starts.partition_point(|&start| start <= offset);
        (line, offset - self.line_starts[line - 1] + 1)
    }

    pub fn diagnostic(
        &self,
        span: Span,
        severity: Severity,
        code: &'static str,
        message: &'static str,
    ) -> DetailedDiagnostic {
        let mut diagnostic = DetailedDiagnostic::warning(
            code,
            self.reference.clone(),
            SettingPath::new("config"),
            SafeValue::Redacted,
            message,
        );
        let (line, column) = self.location(span.start);
        diagnostic.span = Some(span.start..span.end);
        diagnostic.line = Some(line);
        diagnostic.byte_column = Some(column);
        diagnostic.severity = severity;
        diagnostic
    }

    /// Includes trivia, so concatenating raw token spans recovers the entire input.
    /// Quote errors append once and remain nonterminal until the reader decides recovery.
    pub fn tokenize(&self, diagnostics: &mut Vec<DetailedDiagnostic>) -> Vec<Token> {
        let mut lexer = Lexer::default();
        let mut tokens = Vec::new();
        while let Some(token) = lexer.next_token(self, false) {
            if let TokenKind::Error { opener } = token.kind {
                diagnostics.push(self.quote_error(opener, token.span.end));
            }
            tokens.push(token);
        }
        tokens
    }

    pub(super) fn quote_error(&self, opener: usize, end: usize) -> DetailedDiagnostic {
        self.diagnostic(
            self.span(opener, end),
            Severity::Error,
            "unterminated-quote",
            "quote must close on the same physical line",
        )
    }

    fn whitespace_width(&self, index: usize) -> usize {
        let byte = self.text().as_bytes()[index];
        if byte.is_ascii() {
            usize::from(byte.is_ascii_whitespace())
        } else {
            let ch = self.text()[index..].chars().next().unwrap();
            if ch.is_whitespace() { ch.len_utf8() } else { 0 }
        }
    }
}

#[derive(Default)]
pub(super) struct Lexer {
    offset: usize,
    line: usize,
}

impl Lexer {
    pub(super) fn next_token(
        &mut self,
        source: &Source<'_>,
        adjacent_quotes: bool,
    ) -> Option<Token> {
        let bytes = source.text().as_bytes();
        let start = self.offset;
        if start >= bytes.len() {
            return None;
        }
        let next_line = source
            .line_starts
            .get(self.line + 1)
            .copied()
            .unwrap_or(bytes.len());
        let mut end = next_line;
        if end > start && bytes[end - 1] == b'\n' {
            end -= 1;
            if end > start && bytes[end - 1] == b'\r' {
                end -= 1;
            }
        }
        let line = self.line + 1;
        if start >= end {
            self.offset = next_line;
            self.line += 1;
            return Some(Token {
                span: source.span(start, next_line),
                quoted: Vec::new(),
                kind: TokenKind::Newline,
                line,
            });
        }
        let mut index = start;
        let mut quoted: Vec<Span> = Vec::new();
        let kind;
        if source.whitespace_width(index) != 0 {
            while index < end {
                let width = source.whitespace_width(index);
                if width == 0 {
                    break;
                }
                index += width;
            }
            kind = TokenKind::Whitespace;
        } else if bytes[index] == b'#' {
            index = end;
            kind = TokenKind::Comment;
        } else {
            let mut error = None;
            let mut path_quotes = adjacent_quotes;
            while index < end && source.whitespace_width(index) == 0 {
                let boundary =
                    index == start || matches!(bytes[index - 1], b'(' | b',') || path_quotes;
                if boundary && matches!(bytes[index], b'\'' | b'"') {
                    if let Some(close) = quoted_end(&bytes[..end], index) {
                        quoted.push(source.span(index, close));
                        index = close;
                        continue;
                    }
                    error = Some(index);
                    index = end;
                    break;
                }
                path_quotes = false;
                index += source.text()[index..].chars().next().unwrap().len_utf8();
            }
            kind = if let Some(opener) = error {
                TokenKind::Error { opener }
            } else if quoted.is_empty() && index == start + 1 {
                match bytes[start] {
                    b'{' => TokenKind::OpenBrace,
                    b'}' => TokenKind::CloseBrace,
                    _ => TokenKind::Word,
                }
            } else {
                TokenKind::Word
            };
        }
        self.offset = index;
        Some(Token {
            span: source.span(start, index),
            quoted,
            kind,
            line,
        })
    }
}

/// Return the byte index immediately after the matching quote. A backslash
/// skips the next byte without decoding it.
pub(super) fn quoted_end(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == quote => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}
