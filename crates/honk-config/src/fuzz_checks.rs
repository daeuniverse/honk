//! Shared assertions for libFuzzer targets and stable saved-input replay.

use crate::diagnostic::{DetailedDiagnostic, DiagnosticSources};
use crate::node::Node;
use crate::parser::{lexer::Source, parse_dae_config_with_detailed_diagnostics};

fn spans(input: &str, diagnostics: &[DetailedDiagnostic]) {
    for diagnostic in diagnostics {
        if let Some(span) = &diagnostic.span {
            assert!(span.start <= span.end && span.end <= input.len());
            assert!(input.is_char_boundary(span.start) && input.is_char_boundary(span.end));
        }
    }
}

/// Parse a UTF-8 document and check diagnostic bounds and validation termination.
pub fn document(data: &[u8]) {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let mut diagnostics = Vec::new();
    let parsed = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics);
    spans(input, &diagnostics);
    if let Ok(config) = parsed {
        let _ = config.validate_detailed();
    }
}

/// Check that every accepted UTF-8 share link has a deterministic, non-nil identity.
pub fn share_link(data: &[u8]) {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let mut diagnostics = Vec::new();
    if let Ok(node) = Node::from_share_link_with_detailed_diagnostics(input, &mut diagnostics) {
        assert!(!node.id.is_nil());
        assert_eq!(node.id, node.derive_id());
    }
}

/// Check that UTF-8 tokens form an ordered, contiguous partition of the input.
pub fn lexer(data: &[u8]) {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let source = Source::new(input, DiagnosticSources::new(None).root());
    let mut diagnostics = Vec::new();
    let mut end = 0;
    for token in source.tokenize(&mut diagnostics) {
        assert_eq!(token.span.start, end);
        assert!(token.span.end > token.span.start && token.span.end <= input.len());
        assert_eq!(source.raw(token.span), &input[end..token.span.end]);
        end = token.span.end;
    }
    assert_eq!(end, input.len());
    spans(input, &diagnostics);
}
