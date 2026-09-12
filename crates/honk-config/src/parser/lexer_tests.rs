use super::lexer::{Source, Span, Token, TokenKind};
use crate::diagnostic::{DetailedDiagnostic, DiagnosticSources, Severity};

fn source(text: &str) -> Source<'_> {
    Source::new(text, DiagnosticSources::new(None).root())
}

fn significant(tokens: &[Token]) -> Vec<&Token> {
    tokens
        .iter()
        .filter(|token| !token.kind.is_trivia())
        .collect()
}

fn word(text: &str, quoted: &[(usize, usize)]) {
    let source = source(text);
    let mut diagnostics = Vec::new();
    let tokens = source.tokenize(&mut diagnostics);
    assert!(diagnostics.is_empty());
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].kind, TokenKind::Word);
    assert_eq!(source.raw(tokens[0].span), text);
    assert_eq!(
        tokens[0]
            .quoted
            .iter()
            .map(|s| (s.start, s.end))
            .collect::<Vec<_>>(),
        quoted
    );
}

#[test]
fn argument_position_quotes_are_opaque() {
    word("name('a } b')", &[(5, 12)]);
    word("call(a,'b # c')", &[(7, 14)]);
}

#[test]
fn glued_tokens_continue_after_quotes() {
    word("'piece'(part)tail", &[(0, 7)]);
    word("filter='hk'#token", &[]);
    word("/tmp/don't", &[]);
    word("/tmp/a#b", &[]);
    word("(hk)#token", &[]);
}

#[test]
fn head_hash_owns_the_remaining_line() {
    let source = source("x # comment } 'unterminated\ny");
    let mut diagnostics = Vec::new();
    let tokens = source.tokenize(&mut diagnostics);
    assert!(diagnostics.is_empty());
    assert_eq!(
        significant(&tokens)
            .iter()
            .map(|t| source.raw(t.span))
            .collect::<Vec<_>>(),
        ["x", "y"]
    );
    let comment = tokens
        .iter()
        .find(|t| t.kind == TokenKind::Comment)
        .unwrap();
    assert_eq!(source.raw(comment.span), "# comment } 'unterminated");
}

#[test]
fn only_standalone_unquoted_braces_are_structural() {
    let source = source("global{ '{' \"}\" a{b} { }");
    let tokens = source.tokenize(&mut Vec::new());
    assert_eq!(
        significant(&tokens)
            .iter()
            .map(|t| t.kind)
            .collect::<Vec<_>>(),
        [
            TokenKind::Word,
            TokenKind::Word,
            TokenKind::Word,
            TokenKind::Word,
            TokenKind::OpenBrace,
            TokenKind::CloseBrace
        ]
    );
}

#[test]
fn unterminated_quotes_are_one_located_eol_error() {
    for text in [
        "'unterminated } # hidden\n}",
        "name('unterminated) } # hidden\n}",
    ] {
        let source = source(text);
        let mut diagnostics = Vec::new();
        let tokens = source.tokenize(&mut diagnostics);
        let tokens = significant(&tokens);
        let opener = text.find('\'').unwrap();
        let end = text.find('\n').unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].kind, TokenKind::Error { opener });
        assert_eq!(source.raw(tokens[0].span), &text[..end]);
        assert_eq!(tokens[1].kind, TokenKind::CloseBrace);
        assert_eq!(tokens[1].line, 2);
        assert_eq!(diagnostics.len(), 1);
        let d = &diagnostics[0];
        assert_eq!(
            (d.code, d.severity, d.span.clone(), d.line, d.byte_column),
            (
                "unterminated-quote",
                Severity::Error,
                Some(opener..end),
                Some(1),
                Some(opener + 1)
            )
        );
        assert!(!d.terminal);
    }
}

#[test]
fn escapes_preserve_bytes_and_do_not_escape_physical_newlines() {
    word(r#"'a\'b\\c'"#, &[(0, 9)]);
    let source = source("'a\\\r\nnext");
    let mut diagnostics = Vec::new();
    let tokens = source.tokenize(&mut diagnostics);
    assert_eq!(tokens[0].kind, TokenKind::Error { opener: 0 });
    assert_eq!(source.raw(tokens[1].span), "\r\n");
    assert_eq!(tokens[2].line, 2);
    assert_eq!(diagnostics[0].span, Some(0..3));
}

#[test]
fn lossless_trivia_and_utf8_byte_locations() {
    let source = source("香港\u{2003}x\r\n  'bad\nlast");
    let mut diagnostics = Vec::new();
    let tokens = source.tokenize(&mut diagnostics);
    let mut end = 0;
    for token in &tokens {
        assert_eq!(token.span.start, end);
        end = token.span.end;
    }
    assert_eq!(end, source.text().len());
    assert_eq!(source.location(9), (1, 10));
    assert_eq!(source.location(12), (2, 1));
    assert_eq!(diagnostics[0].byte_column, Some(3));
    assert_eq!(source.raw(tokens.last().unwrap().span), "last");
    let other = DiagnosticSources::new(None);
    let reference = other.add(None, Some(0));
    let input = Source::new("x", reference.clone());
    assert_eq!(input.tokenize(&mut Vec::new())[0].span.source, 1);
    let d: DetailedDiagnostic = input.diagnostic(
        Span {
            source: 1,
            start: 0,
            end: 1,
        },
        Severity::Warning,
        "test",
        "test",
    );
    assert!(d.source.same_source(&reference));
}

#[test]
fn frozen_dns_quotes_retain_exact_token_and_quote_spans() {
    for (text, start) in [
        (
            include_str!("../../tests/fixtures/lexer/cls-dns-hash-in-quote.dae"),
            38,
        ),
        (
            include_str!("../../tests/fixtures/lexer/cls-dns-response-quoted-hash.dae"),
            39,
        ),
    ] {
        let source = source(text);
        let mut diagnostics = Vec::new();
        let tokens = source.tokenize(&mut diagnostics);
        let call = tokens.iter().find(|t| t.span.start == start).unwrap();
        assert_eq!(call.kind, TokenKind::Word);
        assert_eq!(
            call.span,
            Span {
                source: 0,
                start,
                end: start + 14
            }
        );
        assert_eq!(
            call.quoted,
            [Span {
                source: 0,
                start: start + 6,
                end: start + 13
            }]
        );
        assert_eq!(call.line, 4);
        assert_eq!(source.raw(call.span), "qname('a # b')");
        assert!(diagnostics.is_empty());
    }
}

#[test]
fn frozen_subscription_quotes_retain_exact_token_and_quote_spans() {
    let source = source(include_str!(
        "../../tests/fixtures/lexer/ctl-sub-quoted-spaced-hash.dae"
    ));
    let mut diagnostics = Vec::new();
    let tokens = source.tokenize(&mut diagnostics);
    let line = significant(&tokens)
        .into_iter()
        .filter(|t| t.line == 2)
        .collect::<Vec<_>>();
    assert_eq!(line.len(), 2);
    assert_eq!(
        line[0].span,
        Span {
            source: 0,
            start: 19,
            end: 33
        }
    );
    assert_eq!(
        line[0].quoted,
        [Span {
            source: 0,
            start: 19,
            end: 32
        }]
    );
    assert_eq!(
        line[1].span,
        Span {
            source: 0,
            start: 34,
            end: 88
        }
    );
    assert_eq!(
        line[1].quoted,
        [
            Span {
                source: 0,
                start: 34,
                end: 71
            },
            Span {
                source: 0,
                start: 72,
                end: 87
            }
        ]
    );
    assert_eq!(source.raw(line[1].quoted[1].interior()), "agent # build");
    assert!(diagnostics.is_empty());
}
