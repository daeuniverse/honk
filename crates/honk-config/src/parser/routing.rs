use super::cursor::Segment;
use super::lexer::Span;
use super::read::Text;
use super::{ParserDiagnostics, normalize_geosite_code, read};
use crate::diagnostic::{SettingPath, Severity};
use crate::error::{DetailedConfigError, ErrorCategory};
use crate::routing::{RoutingCondition, RoutingConfig, RoutingRule};

/// A window over physical source pieces, including gaps owned by comments.
#[derive(Clone, Copy)]
struct Expression<'p, 'd, 'a> {
    pieces: &'p [Text<'d, 'a>],
    span: Span,
}

impl<'p, 'd, 'a> Expression<'p, 'd, 'a> {
    fn new(pieces: &'p [Text<'d, 'a>]) -> Self {
        Self {
            pieces,
            span: Span {
                end: pieces.last().unwrap().span.end,
                ..pieces[0].span
            },
        }
    }

    fn sub(self, start: usize, end: usize) -> Self {
        let first = self.pieces.partition_point(|piece| piece.span.end <= start);
        let last = if start == end {
            first
        } else {
            self.pieces.partition_point(|piece| piece.span.start < end)
        };
        Self {
            pieces: &self.pieces[first..last],
            span: Span {
                start,
                end,
                ..self.span
            },
        }
    }

    fn parts(self) -> impl DoubleEndedIterator<Item = Text<'d, 'a>> + 'p {
        self.pieces.iter().filter_map(move |piece| {
            let start = piece.span.start.max(self.span.start);
            let end = piece.span.end.min(self.span.end);
            (start < end).then(|| piece.sub(start - piece.span.start, end - piece.span.start))
        })
    }

    fn trim(self) -> Self {
        let mut parts = self
            .parts()
            .map(Text::trim)
            .filter(|part| !part.raw().is_empty());
        if let Some(first) = parts.next() {
            let end = parts.next_back().unwrap_or(first).span.end;
            self.sub(first.span.start, end)
        } else {
            self.sub(self.span.start, self.span.start)
        }
    }

    fn is_empty(self) -> bool {
        self.span.start == self.span.end
    }

    fn starts_with(self, prefix: &str) -> bool {
        self.parts()
            .next()
            .is_some_and(|part| part.raw().starts_with(prefix))
    }

    fn find(self, delimiter: &str) -> Option<usize> {
        self.parts()
            .find_map(|part| part.find(delimiter).map(|offset| part.span.start + offset))
    }

    fn split<'s>(self, delimiter: &'s str) -> impl Iterator<Item = Self> + 's
    where
        'p: 's,
        'd: 's,
    {
        let mut delimiters = self
            .parts()
            .flat_map(move |part| part.delimiter_positions(delimiter));
        let mut start = self.span.start;
        let mut done = false;
        std::iter::from_fn(move || {
            if done {
                return None;
            }
            if let Some(end) = delimiters.next() {
                let part = self.sub(start, end).trim();
                start = end + delimiter.len();
                Some(part)
            } else {
                done = true;
                Some(self.sub(start, self.span.end).trim())
            }
        })
    }

    fn parentheses(self) -> impl Iterator<Item = (usize, u8)> + 'p
    where
        'd: 'p,
    {
        self.parts().flat_map(Text::parentheses)
    }

    fn display(self) -> String {
        let mut output = String::new();
        for part in self
            .parts()
            .map(Text::trim)
            .filter(|part| !part.raw().is_empty())
        {
            let raw = part.raw();
            // Preserve the existing complex-rule display across continuation lines.
            if !output.is_empty() && !raw.starts_with([')', ',']) {
                output.push(' ');
            }
            output.push_str(raw);
        }
        output
    }

    fn unquote(self) -> Self {
        let text = self.trim();
        let mut parts = text.parts();
        match (parts.next(), parts.next()) {
            (Some(part), None) => {
                let part = part.unquote();
                text.sub(part.span.start, part.span.end)
            }
            _ => text,
        }
    }

    fn value(self) -> std::borrow::Cow<'d, str> {
        let mut parts = self.parts();
        match (parts.next(), parts.next()) {
            (Some(part), None) => std::borrow::Cow::Borrowed(part.raw()),
            _ => std::borrow::Cow::Owned(self.display()),
        }
    }

    fn warn_glued_hash(self, diagnostics: &mut ParserDiagnostics<'_>) {
        for part in self.parts() {
            part.warn_glued_hash(diagnostics);
        }
    }

    fn error(self, code: &'static str, message: &'static str, index: usize) -> DetailedConfigError {
        let mut diagnostic =
            self.pieces[0]
                .source
                .diagnostic(self.span, Severity::Error, code, message);
        diagnostic.setting = SettingPath::new("routing").field("rules").index(index);
        diagnostic.entry_index = Some(index);
        diagnostic.terminal = true;
        DetailedConfigError {
            category: ErrorCategory::Parse,
            diagnostic: Box::new(diagnostic),
        }
    }
}

pub(super) fn parse_section(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<RoutingConfig, super::ParseFailure> {
    let mut config = RoutingConfig::default();
    let lines = read::statements(section, diagnostics);
    let mut start = 0;
    let mut depth = 0usize;
    let mut ordinal = 0;
    for end in 0..lines.len() {
        if start < end && lines[start].span.source != lines[end].span.source {
            return Err(crate::ConfigError::Parse(
                "routing: unterminated parenthesized rule at source boundary".into(),
            )
            .into());
        }
        for (_, byte) in Expression::new(&lines[end..=end]).parentheses() {
            if byte == b'(' {
                depth += 1;
            } else {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    crate::ConfigError::Parse("routing: unmatched closing parenthesis".into())
                })?;
            }
        }
        if depth != 0 {
            continue;
        }
        ordinal += 1;
        let statement = Expression::new(&lines[start..=end]).trim();
        start = end + 1;
        diagnostics.entry_text(statement.parts().next().unwrap(), ordinal);
        if let Some(prefix) = ["fallback:", "default:"]
            .into_iter()
            .find(|prefix| statement.starts_with(prefix))
        {
            let value = statement
                .sub(statement.span.start + prefix.len(), statement.span.end)
                .trim();
            value.warn_glued_hash(diagnostics);
            config.default_outbound = value.display();
        } else {
            match parse_routing_rule(statement, config.rules.len(), ordinal, diagnostics) {
                Ok(Some((rule, source))) => {
                    if let Some(source) = source {
                        config.record_complex_rule_source(rule.name.clone(), source);
                    }
                    config.rules.push(rule);
                }
                Ok(None) => statement.parts().next().unwrap().notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-statement",
                    "traffic statement without an arrow ignored",
                ),
                Err(error) => return Err(error.into()),
            }
        }
    }
    if depth != 0 {
        return Err(
            crate::ConfigError::Parse("routing: unterminated parenthesized rule".into()).into(),
        );
    }
    Ok(config)
}

fn parse_routing_rule(
    statement: Expression<'_, '_, '_>,
    index: usize,
    ordinal: usize,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Option<(RoutingRule, Option<String>)>, DetailedConfigError> {
    let Some(arrow) = statement.find("->") else {
        return Ok(None);
    };
    let left = statement.sub(statement.span.start, arrow).trim();
    let right = statement.sub(arrow + 2, statement.span.end).trim();
    left.warn_glued_hash(diagnostics);
    right.warn_glued_hash(diagnostics);
    if let Some(offset) = right.find("->") {
        right
            .sub(offset, offset + 2)
            .parts()
            .next()
            .unwrap()
            .notice(
                diagnostics,
                Severity::Warning,
                "legacy-arrow-target",
                "additional arrows remain literal outbound data",
            );
    }
    let mut outbound = right.display();
    let must = outbound.ends_with("(must)");
    if must {
        outbound.truncate(outbound.len() - "(must)".len());
        outbound.truncate(outbound.trim_end().len());
    }
    let mut condition = RoutingCondition::default();
    for matcher in left.split("&&").filter(|matcher| !matcher.is_empty()) {
        parse_route_matcher(&mut condition, matcher, ordinal)?;
    }
    let complex = must || left.find("&&").is_some() || condition.needs_complex_display();
    let rule = RoutingRule {
        name: format!("rule-{index}"),
        condition,
        outbound: crate::routing::RoutingOutbound::Simple(outbound),
        priority: index as u32,
        must,
        mark: 0,
    };
    Ok(Some((rule, complex.then(|| statement.display()))))
}

fn parse_route_matcher(
    condition: &mut RoutingCondition,
    matcher: Expression<'_, '_, '_>,
    ordinal: usize,
) -> Result<(), DetailedConfigError> {
    let negated = matcher.starts_with("!");
    let matcher = if negated {
        matcher.sub(matcher.span.start + 1, matcher.span.end).trim()
    } else {
        matcher
    };
    if matcher.is_empty() {
        return Ok(());
    }
    let mut target = if negated {
        condition.not.fields_mut()
    } else {
        condition.fields_mut()
    };
    for name in [
        "pname",
        "dip",
        "sip",
        "domain",
        "dport",
        "sport",
        "l4proto",
        "ipversion",
        "mac",
        "dscp",
    ] {
        if let Some(args) = parse_call(matcher, name, ordinal)? {
            match name {
                "dip" => parse_ip_args(&args, &mut target),
                "domain" => parse_domain_args(&args, &mut target),
                _ => {
                    let field = match name {
                        "pname" => target.process_name,
                        "sip" => target.source_ip,
                        "dport" => target.port,
                        "sport" => target.source_port,
                        "l4proto" => target.protocol,
                        "ipversion" => target.ip_version,
                        "mac" => target.mac,
                        "dscp" => target.dscp,
                        _ => unreachable!(),
                    };
                    field.extend(
                        args.into_iter()
                            .map(|argument| argument.value().into_owned()),
                    );
                }
            }
            return Ok(());
        }
    }
    for prefix in [
        "geosite:", "geoip:", "domain:", "suffix:", "keyword:", "full:", "regex:",
    ] {
        if matcher.starts_with(prefix) {
            let value = matcher
                .sub(matcher.span.start + prefix.len(), matcher.span.end)
                .unquote()
                .value();
            match prefix {
                "geosite:" => target.geosite.push(normalize_geosite_code(&value)),
                "geoip:" => target.geo_ip.push(normalize_geosite_code(&value)),
                "domain:" | "suffix:" => target.domain_suffix.push(value.into_owned()),
                "keyword:" => target.domain_keyword.push(value.into_owned()),
                "full:" => target.domain.push(value.into_owned()),
                "regex:" => target.domain_regex.push(value.into_owned()),
                _ => unreachable!(),
            }
            return Ok(());
        }
    }
    Err(matcher.error(
        "unknown-traffic-predicate",
        "unknown traffic predicate",
        ordinal,
    ))
}

fn parse_call<'p, 'd, 'a>(
    matcher: Expression<'p, 'd, 'a>,
    name: &str,
    ordinal: usize,
) -> Result<Option<Vec<Expression<'p, 'd, 'a>>>, DetailedConfigError> {
    if !matcher.parts().next().is_some_and(|part| {
        part.raw()
            .strip_prefix(name)
            .is_some_and(|rest| rest.starts_with('('))
    }) {
        return Ok(None);
    }
    let call = matcher.sub(matcher.span.start + name.len(), matcher.span.end);
    let Some((position, _)) = call.parentheses().find(|(_, byte)| *byte == b')') else {
        return Ok(None);
    };
    let trailing = call.sub(position + 1, call.span.end);
    if !trailing.trim().is_empty() {
        if trailing.span.start == trailing.trim().span.start {
            return Err(trailing.trim().error(
                "trailing-matcher-text",
                "matcher call has trailing text",
                ordinal,
            ));
        }
        return Ok(None);
    }
    Ok(Some(
        call.sub(call.span.start + 1, position)
            .split(",")
            .map(Expression::unquote)
            .filter(|value| !value.is_empty())
            .collect(),
    ))
}

fn parse_domain_args(
    args: &[Expression<'_, '_, '_>],
    cond: &mut crate::routing::ConditionFields<'_>,
) {
    for a in args {
        let prefix = ["geosite:", "keyword:", "full:", "regex:", "suffix:"]
            .into_iter()
            .find(|prefix| a.starts_with(prefix));
        if let Some(prefix) = prefix {
            let value = a
                .sub(a.span.start + prefix.len(), a.span.end)
                .unquote()
                .value();
            match prefix {
                "geosite:" => cond.geosite.push(normalize_geosite_code(&value)),
                "keyword:" => cond.domain_keyword.push(value.into_owned()),
                "full:" => cond.domain.push(value.into_owned()),
                "regex:" => cond.domain_regex.push(value.into_owned()),
                "suffix:" => cond.domain_suffix.push(value.into_owned()),
                _ => unreachable!(),
            }
        } else {
            cond.domain_suffix.push(a.value().into_owned());
        }
    }
}

fn parse_ip_args(args: &[Expression<'_, '_, '_>], cond: &mut crate::routing::ConditionFields<'_>) {
    for a in args {
        if a.starts_with("geoip:") {
            let value = a
                .sub(a.span.start + "geoip:".len(), a.span.end)
                .unquote()
                .value();
            cond.geo_ip.push(normalize_geosite_code(&value));
        } else {
            cond.ip.push(a.value().into_owned());
        }
    }
}
