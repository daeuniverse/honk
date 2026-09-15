//! Test-only decoded syntax projection. Quote ownership stays with production readers.

use serde::Serialize;
use serde_json::{Value, json};

use super::cursor::{BodySyntax, Document, Segment};
use super::diagnostics::ParserDiagnostics;
use super::lexer::Source;
use super::read::{self, Text};
use super::routing::Expression;
use crate::diagnostic::DiagnosticSources;

#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub code: &'static str,
    pub setting: String,
    pub message: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Projection {
    pub accepted: bool,
    pub diagnostics: Vec<Diagnostic>,
    pub document: Option<Value>,
    pub error: Option<String>,
    /// Opening-token byte ranges, not reconstructed names or bodies.
    pub unknown_positions: Vec<std::ops::Range<usize>>,
}

/// Project syntax and separately observe semantic acceptance and diagnostics.
/// This is not a configuration loader: includes never access the filesystem.
/// Values are unredacted; use only public test inputs, not operator secrets.
pub fn project(input: &str) -> Projection {
    let mut diagnostics = Vec::new();
    let result = super::parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics);
    let source = DiagnosticSources::new(None).root();
    let mut structural = Vec::new();
    let parsed = Document::parse_attempt(Source::new(input, source.clone()), &mut structural, true);
    let unknown_positions: Vec<_> = structural
        .iter()
        .filter(|d| d.code == "unknown-block")
        .filter_map(|d| d.span.clone())
        .collect();
    let document = parsed.ok().map(|document| {
        let mut ignored = Vec::new();
        let mut sink = ParserDiagnostics::new(&mut ignored, source);
        let sections: Vec<_> = document
            .sections()
            .map(|section| section_value(&section, section.header(), &mut sink))
            .collect();
        json!({"sections": sections, "unknown_sections": unknown_positions.len()})
    });
    Projection {
        accepted: result.is_ok(),
        error: result.err().map(|e| e.to_string()),
        diagnostics: diagnostics
            .into_iter()
            .map(|d| Diagnostic {
                code: d.code,
                setting: d.setting.to_string(),
                message: d.message,
            })
            .collect(),
        document,
        unknown_positions,
    }
}

fn section_value(
    section: &Segment<'_, '_>,
    context: &str,
    sink: &mut ParserDiagnostics<'_>,
) -> Value {
    let mut items = Vec::new();
    if context == "routing" {
        let lines = read::child_statements(section, sink, BodySyntax::Expressions);
        let mut start = 0;
        let mut depth = 0usize;
        for (end, line) in lines.iter().enumerate() {
            for (_, byte) in line.parentheses() {
                depth = if byte == b'(' {
                    depth + 1
                } else {
                    depth.saturating_sub(1)
                };
            }
            if depth == 0 {
                if let Some(item) = statement(Expression::new(&lines[start..=end]), true) {
                    items.push(item);
                }
                start = end + 1;
            }
        }
    } else {
        let syntax = match context {
            "group" => BodySyntax::Declarations,
            "node" | "subscription" => BodySyntax::Entries,
            _ => BodySyntax::Statements,
        };
        if let Some(body) = section.body_with(syntax) {
            for child in body {
                if child.is_ignored() {
                    continue;
                }
                if child.is_block() {
                    let name = child.header();
                    let next = match (context, name) {
                        ("group", _) => Some("group-fields"),
                        ("node" | "subscription", _) => Some(context),
                        ("dns", "upstream") => Some("upstream"),
                        ("dns", "routing") => Some("dns-routing"),
                        ("dns", "fixed_domain_ttl") => Some("ttl"),
                        ("dns-routing", "request" | "response") => Some("dns-rules"),
                        ("experimental", "clash_api" | "cache_file" | "udp_nfqueue") => {
                            Some("settings")
                        }
                        _ => None,
                    };
                    if let Some(next) = next {
                        items.push(json!({"section": section_value(&child, next, sink)}));
                    }
                } else {
                    let pieces = [Text::segment(&child)];
                    if let Some(item) = statement(Expression::new(&pieces), context == "dns-rules")
                    {
                        items.push(item);
                    }
                }
            }
        }
    }
    json!({"name": section.header(), "items": items})
}

fn statement(text: Expression<'_, '_, '_>, rules: bool) -> Option<Value> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if rules && let Some(arrow) = text.find("->") {
        let left = text.sub(text.span.start, arrow).trim();
        let right = without_annotation(text.sub(arrow + 2, text.span.end).trim()).0;
        let functions: Option<Vec<_>> = left.split("&&").map(function).collect();
        return Some(json!({"rule": {"and_functions": functions?, "outbound": outbound(right)}}));
    }
    if rules && !text.starts_with("fallback:") && !text.starts_with("default:") {
        return None;
    }
    let (key, value) = key_value(text);
    let (value, annotation) = without_annotation(value);
    let functions: Option<Vec<_>> = value.split("&&").map(function).collect();
    let (val, functions) = if let Some(functions) = functions {
        (String::new(), functions)
    } else {
        (
            value
                .split(",")
                .map(|v| v.unquote().value().into_owned())
                .collect::<Vec<_>>()
                .join(","),
            Vec::new(),
        )
    };
    Some(
        json!({"param": {"key": key, "val": val, "and_functions": functions, "annotation": annotation}}),
    )
}

fn key_value<'p, 'd, 'a>(text: Expression<'p, 'd, 'a>) -> (String, Expression<'p, 'd, 'a>) {
    if let Some(colon) = text.find(":") {
        // Bare URI entries have no tag; their scheme colon belongs to the value.
        if !text.sub(colon, text.span.end).starts_with("://") {
            return (
                text.sub(text.span.start, colon)
                    .unquote()
                    .value()
                    .into_owned(),
                text.sub(colon + 1, text.span.end).trim(),
            );
        }
    }
    (String::new(), text.trim())
}

fn parameters(text: Expression<'_, '_, '_>) -> Vec<Value> {
    text.split(",")
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (key, val) = key_value(p);
            json!({"key": key, "val": val.unquote().value()})
        })
        .collect()
}

fn without_annotation<'p, 'd, 'a>(
    text: Expression<'p, 'd, 'a>,
) -> (Expression<'p, 'd, 'a>, Vec<Value>) {
    if let Some(open) = text.find("[")
        && let Some(close) = text.find("]")
        && close > open
        && text.sub(close + 1, text.span.end).trim().is_empty()
    {
        return (
            text.sub(text.span.start, open).trim(),
            parameters(text.sub(open + 1, close)),
        );
    }
    (text, Vec::new())
}

fn function(text: Expression<'_, '_, '_>) -> Option<Value> {
    let text = text.trim();
    let not = text.starts_with("!");
    let text = if not {
        text.sub(text.span.start + 1, text.span.end).trim()
    } else {
        text
    };
    let open = text.find("(")?;
    let close = text.find(")")?;
    if close < open || !text.sub(close + 1, text.span.end).trim().is_empty() {
        return None;
    }
    Some(
        json!({"name": text.sub(text.span.start, open).trim().value(), "not": not, "params": parameters(text.sub(open + 1, close))}),
    )
}

fn outbound(text: Expression<'_, '_, '_>) -> Value {
    function(text)
        .unwrap_or_else(|| json!({"name": text.unquote().value(), "not": false, "params": []}))
}
