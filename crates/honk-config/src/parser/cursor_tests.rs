use super::cursor::{Document, StructureError, adjacent, same_physical_line};
use super::lexer::{Source, TokenKind};
use crate::diagnostic::{DetailedDiagnostic, DiagnosticSources, Severity};

fn parse<'a>(
    text: &'a str,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Document<'a>, StructureError> {
    Document::parse(
        Source::new(text, DiagnosticSources::new(None).root()),
        diagnostics,
    )
}

#[test]
fn segments_preserve_dynamic_headers_and_independent_positions() {
    let doc = parse("group {\n123 { policy: score }\n香港 { policy: selector }\nHong Kong { filter: name(x) }\n}", &mut Vec::new()).unwrap();
    let groups = doc.sections().next().unwrap().body().unwrap();
    let mut names = Vec::new();
    for segment in groups {
        names.push(segment.header());
        let mut left = segment.body().unwrap();
        let mut right = segment.body().unwrap();
        assert_eq!(left.next().unwrap().span(), right.next().unwrap().span());
    }
    assert_eq!(names, ["123", "香港", "Hong Kong"]);
}

#[test]
fn structural_segments_never_reclassify_quoted_or_commented_braces() {
    let text = "group {\ng { filter: name('a } b') } # } {\nh { filter: '}' }\n}\nglobal { path: /tmp/{x}.log }";
    let mut diagnostics = Vec::new();
    let doc = parse(text, &mut diagnostics).unwrap();
    let mut group = doc.sections().next().unwrap().body().unwrap();
    assert_eq!(group.next().unwrap().header(), "g");
    assert_eq!(group.next().unwrap().header(), "h");
    assert!(group.next().is_none());
    assert_eq!(doc.sections().count(), 2);
}

#[test]
fn glued_header_braces_report_the_actual_byte() {
    for text in [
        "global{\n x: y\n}",
        "global{ x: y }",
        "global{}",
        "group {\nHong Kong{\n}\n}",
    ] {
        let mut diagnostics = Vec::new();
        let error = parse(text, &mut diagnostics).unwrap_err();
        let start = if text.starts_with("group") {
            text.find("Kong{").unwrap() + 4
        } else {
            6
        };
        assert_eq!(error.error.diagnostic.code, "block-delimiter-spacing");
        assert_eq!(error.error.diagnostic.span, Some(start..start + 1));
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].terminal);
    }
}

#[test]
fn quoted_colon_headers_require_a_separate_opener() {
    let text = "group {\n'Asia: East'{\n}\n}";
    let mut diagnostics = Vec::new();
    let error = parse(text, &mut diagnostics).unwrap_err();
    assert_eq!(error.error.diagnostic.code, "block-delimiter-spacing");
    assert_eq!(error.error.diagnostic.span, Some(20..21));
    assert_eq!(diagnostics, [*error.error.diagnostic]);

    let doc = parse("group {\n'Asia: East' {\n}\n}", &mut Vec::new()).unwrap();
    let mut body = doc.sections().next().unwrap().body().unwrap();
    assert_eq!(body.next().unwrap().header(), "'Asia: East'");
}

#[test]
fn only_root_include_accepts_a_split_opener() {
    let mut diagnostics = Vec::new();
    let doc = parse(
        "include\n# comment\n{ '*.dae' }\nglobal { x: y }",
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(doc.sections().next().unwrap().header(), "include");
    assert_eq!(
        (diagnostics[0].code, diagnostics[0].line),
        ("legacy-include-opener", Some(3))
    );
    let section = doc.sections().next().unwrap();
    let mut cursor = section.body().unwrap();
    assert_eq!(cursor.next().unwrap().header(), "'*.dae'");
    assert!(cursor.next().is_none());
    for text in ["global\n{ x: y }", "group { include\n{ x } }"] {
        assert_eq!(
            parse(text, &mut Vec::new())
                .unwrap_err()
                .error
                .diagnostic
                .code,
            "unexpected-open-brace"
        );
    }
}

#[test]
fn compact_include_keeps_empty_root_and_split_warning() {
    let mut diagnostics = Vec::new();
    let doc = parse("include\n{}\nglobal {}", &mut diagnostics).unwrap();
    let sections = doc.sections().collect::<Vec<_>>();
    assert_eq!(
        sections
            .iter()
            .map(|section| section.header())
            .collect::<Vec<_>>(),
        ["include", "global"]
    );
    assert!(sections.iter().all(|section| section.body().is_none()));
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.line))
            .collect::<Vec<_>>(),
        [("legacy-include-opener", Some(2))]
    );
}

#[test]
fn segment_comment_uses_lexed_token_with_unicode_gap_and_crlf() {
    let doc = parse(
        "global {\r\n key: value\u{2003}# note\r\n}\r\n",
        &mut Vec::new(),
    )
    .unwrap();
    let section = doc.sections().next().unwrap();
    let mut body = section.body().unwrap();
    let statement = body.next().unwrap();
    let text = super::read::Text::segment(&statement);
    let comment = text.trailing_comment().unwrap();
    assert_eq!(doc.source().raw(comment.span), "#");
}

#[test]
fn unmatched_close_warns() {
    let mut diagnostics = Vec::new();
    let doc = parse(
        "global { }\n}\nrouting { fallback: direct }",
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(doc.sections().count(), 2);
    assert_eq!(
        (
            diagnostics[0].code,
            diagnostics[0].line,
            diagnostics[0].severity
        ),
        ("unmatched-close", Some(2), Severity::Warning)
    );
}

#[test]
fn markerless_input_fails_without_provisional_warnings() {
    for text in ["", "# comment", "plain text", "one\ntwo\nthree", "}\n}"] {
        let mut diagnostics = Vec::new();
        assert_eq!(
            parse(text, &mut diagnostics)
                .unwrap_err()
                .error
                .diagnostic
                .code,
            "not-dae-config"
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].terminal);
    }
}

fn assert_fatal_preserves_diagnostics(text: &str, code: &'static str) {
    let source = Source::new(text, DiagnosticSources::new(None).root());
    let prefix_source = Source::new("prefix", DiagnosticSources::new(None).root());
    let prefix = prefix_source.diagnostic(
        prefix_source.span(0, 6),
        Severity::Warning,
        "caller-prefix",
        "caller warning",
    );
    let warning = source.diagnostic(
        source.span(0, 1),
        Severity::Warning,
        "unmatched-close",
        "unmatched closing brace ignored",
    );
    let mut diagnostics = vec![prefix.clone()];
    let error = Document::parse(source, &mut diagnostics).unwrap_err();
    assert_eq!(error.error.diagnostic.code, code);
    assert_eq!(diagnostics, [prefix, warning, *error.error.diagnostic]);
    assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
}

#[test]
fn fatal_glued_opener_preserves_prior_diagnostics() {
    assert_fatal_preserves_diagnostics("}\nglobal{\n}", "block-delimiter-spacing");
}

#[test]
fn fatal_anonymous_opener_preserves_prior_diagnostics() {
    assert_fatal_preserves_diagnostics("}\n{", "unexpected-open-brace");
}

#[test]
fn fatal_quote_preserves_prior_diagnostics() {
    assert_fatal_preserves_diagnostics("}\n'unterminated", "unterminated-quote");
}

#[test]
fn k22_a_closes_before_unknown_root_and_unmatched_close() {
    let mut diagnostics = Vec::new();
    let doc = parse(
        include_str!("../../tests/fixtures/cursor/k22-a.dae"),
        &mut diagnostics,
    )
    .unwrap();
    let sections = doc.sections().collect::<Vec<_>>();
    assert_eq!(
        sections.iter().map(|s| s.header()).collect::<Vec<_>>(),
        ["subscription", "routing"]
    );
    assert_eq!(doc.source().location(sections[0].span().end - 1).0, 2);
    assert_eq!(
        diagnostics
            .iter()
            .map(|d| (d.code, d.line))
            .collect::<Vec<_>>(),
        [("unknown-statement", Some(3)), ("unmatched-close", Some(4))]
    );
    let mut entry = sections[0].body().unwrap();
    assert_eq!(entry.next().unwrap().header(), "sub: 'http://sub'(ua)#");
}

#[test]
fn k22_controls_keep_raw_scalar_and_entry_ownership() {
    for (text, expected) in [
        (
            include_str!("../../tests/fixtures/cursor/k22-c.dae"),
            "log_file: /tmp/x 'piece'(part)tail",
        ),
        (
            include_str!("../../tests/fixtures/cursor/k22-b.dae"),
            "sub: https://example.com/sub?filter='hk'#token",
        ),
    ] {
        let mut diagnostics = Vec::new();
        let doc = parse(text, &mut diagnostics).unwrap();
        let mut body = doc.sections().next().unwrap().body().unwrap();
        assert_eq!(body.next().unwrap().header(), expected);
        assert!(diagnostics.is_empty());
    }
    for text in [
        include_str!("../../tests/fixtures/cursor/k22-a-glued-no-brace.dae"),
        include_str!("../../tests/fixtures/cursor/k22-a-separated-comment.dae"),
    ] {
        let doc = parse(text, &mut Vec::new()).unwrap();
        let section = doc.sections().next().unwrap();
        assert_eq!(doc.source().location(section.span().end - 1).0, 4);
        let mut body = section.body().unwrap();
        body.next().unwrap();
        assert!(body.next().unwrap().header().starts_with("other:"));
    }
}

#[test]
fn hidden_closers_fail_with_one_quote_error_and_related_opener() {
    for text in [
        include_str!("../../tests/fixtures/cursor/k05-a.dae"),
        include_str!("../../tests/fixtures/cursor/k05-a-head.dae"),
        include_str!("../../tests/fixtures/cursor/k05-c.dae"),
        include_str!("../../tests/fixtures/cursor/k05-c-head.dae"),
        include_str!("../../tests/fixtures/cursor/k05-c-response.dae"),
        include_str!("../../tests/fixtures/cursor/k05-c-head-response.dae"),
    ] {
        let mut diagnostics = Vec::new();
        let error = parse(text, &mut diagnostics).unwrap_err();
        assert_eq!(error.error.diagnostic.code, "unterminated-quote");
        let opener = error.unclosed.unwrap();
        assert_eq!(
            &text[opener.start..opener.end],
            if text.starts_with("group") {
                "group"
            } else {
                "dns"
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].terminal);
        assert_eq!(
            diagnostics[0].span.as_ref().unwrap().start,
            text.find('\'').unwrap()
        );
    }
}

#[test]
fn surviving_closers_recover_without_rescanning_error_tokens() {
    for text in [
        include_str!("../../tests/fixtures/cursor/k05-b.dae"),
        include_str!("../../tests/fixtures/cursor/k05-b-head.dae"),
        include_str!("../../tests/fixtures/cursor/k05-c-argument-multiline.dae"),
        include_str!("../../tests/fixtures/cursor/k05-c-head-multiline.dae"),
        include_str!("../../tests/fixtures/cursor/k05-c-argument-multiline-response.dae"),
        include_str!("../../tests/fixtures/cursor/k05-c-head-multiline-response.dae"),
    ] {
        let mut diagnostics = Vec::new();
        let doc = parse(text, &mut diagnostics).unwrap();
        assert_eq!(doc.sections().last().unwrap().header(), "routing");
        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].terminal);
        assert_eq!(
            doc.tokens()
                .iter()
                .filter(|t| matches!(t.kind, TokenKind::Error { .. }))
                .count(),
            1
        );
        let removed = text.replacen("\n}", "", 1);
        assert_eq!(
            parse(&removed, &mut Vec::new())
                .unwrap_err()
                .error
                .diagnostic
                .code,
            "unterminated-quote"
        );
    }
}

#[test]
fn later_open_frames_cannot_replace_an_outstanding_quote_error() {
    for value in ["'unterminated }", "name('unterminated) }"] {
        let text = format!("group {{\ng {{ filter: {value}\nh {{\n");
        let mut diagnostics = Vec::new();
        let error = parse(&text, &mut diagnostics).unwrap_err();
        assert_eq!(error.error.diagnostic.code, "unterminated-quote");
        let quote = text.find('\'').unwrap();
        let end = text[quote..].find('\n').unwrap() + quote;
        assert_eq!(error.error.diagnostic.span, Some(quote..end));
        let header = error.unclosed.unwrap();
        assert_eq!((header.start, header.end), (8, 9));
        assert_eq!(diagnostics, [*error.error.diagnostic]);
        assert!(diagnostics[0].terminal);
    }
}

#[test]
fn closed_quote_obligations_do_not_mask_later_unclosed_blocks() {
    let text = "group {\ng { filter: 'unterminated }\n}\n}\nglobal {";
    let mut diagnostics = Vec::new();
    let error = parse(text, &mut diagnostics).unwrap_err();
    assert_eq!(
        diagnostics
            .iter()
            .map(|d| (d.code, d.line, d.terminal))
            .collect::<Vec<_>>(),
        [
            ("unterminated-quote", Some(2), false),
            ("unclosed-block", Some(5), true),
        ]
    );
    let header = error.unclosed.unwrap();
    assert_eq!(&text[header.start..header.end], "global");
    assert_eq!(error.error.diagnostic.span, Some(header.start..header.end));
    assert_eq!(diagnostics[1], *error.error.diagnostic);
}

#[test]
fn frozen_quoted_values_remain_inside_their_sections() {
    for (text, children, expected) in [
        (
            include_str!("../../tests/fixtures/lexer/cls-dns-hash-in-quote.dae"),
            &["routing", "request"][..],
            "qname('a # b') -> asis",
        ),
        (
            include_str!("../../tests/fixtures/lexer/cls-dns-response-quoted-hash.dae"),
            &["routing", "response"][..],
            "qname('a # b') -> accept",
        ),
        (
            include_str!("../../tests/fixtures/lexer/ctl-sub-quoted-spaced-hash.dae"),
            &[][..],
            "'paid # east': 'https://example.com/sub#token #data'('agent # build')",
        ),
    ] {
        let mut diagnostics = Vec::new();
        let doc = parse(text, &mut diagnostics).unwrap();
        let mut section = doc.sections().next().unwrap();
        for &name in children {
            let mut body = section.body().unwrap();
            section = body.next().unwrap();
            assert_eq!(section.header(), name);
        }
        let mut body = section.body().unwrap();
        assert_eq!(body.next().unwrap().header(), expected);
        assert!(diagnostics.is_empty());
    }
}

#[test]
fn coordinate_predicates_distinguish_glued_and_separated_source() {
    let source = Source::new("'a'('b') x\nnext", DiagnosticSources::new(None).root());
    let tokens = source.tokenize(&mut Vec::new());
    let words = tokens
        .iter()
        .filter(|t| t.kind == TokenKind::Word)
        .collect::<Vec<_>>();
    assert!(same_physical_line(words[0], words[1]));
    assert!(!same_physical_line(words[1], words[2]));
    assert!(!adjacent(words[0].span, words[1].span));
    assert!(adjacent(words[0].quoted[0], source.span(3, 4)));
    assert!(!adjacent(words[0].quoted[0], words[0].quoted[1]));
}

#[test]
fn quoted_colon_in_a_root_header_still_opens_a_compact_empty_block() {
    // A colon inside quotes is data; `'a: b' {}` is an (unknown) empty root block,
    // not a `key: {}` statement.
    let input = "'a: b' {}\nglobal {}\n";
    let mut diagnostics = Vec::new();
    let source = Source::new(input, DiagnosticSources::new(None).root());
    let document = Document::parse(source, &mut diagnostics).expect("document");
    assert_eq!(
        document.sections().count(),
        1,
        "only `global` is a known root"
    );
    let codes: Vec<&str> = diagnostics.iter().map(|d| d.code).collect();
    assert_eq!(codes, ["unknown-block"], "{diagnostics:#?}");
}
