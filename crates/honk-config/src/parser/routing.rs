use super::{Section, extract_fn_args, normalize_geosite_code, strip_tag_arg};
use crate::routing::RoutingConfig;

fn split_routing_statements(body: &str) -> Result<Vec<String>, crate::ConfigError> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut parenthesis_depth = 0usize;

    for (line_index, line) in body.lines().enumerate() {
        let mut chunk = String::new();
        let mut quote = None;
        let mut escaped = false;

        for ch in line.chars() {
            if let Some(delimiter) = quote {
                chunk.push(ch);
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == delimiter {
                    quote = None;
                }
                continue;
            }

            match ch {
                '#' => break,
                '\'' | '"' => {
                    quote = Some(ch);
                    chunk.push(ch);
                }
                '(' => {
                    parenthesis_depth += 1;
                    chunk.push(ch);
                }
                ')' => {
                    if parenthesis_depth == 0 {
                        return Err(crate::ConfigError::Parse(format!(
                            "routing line {}: unmatched ')'",
                            line_index + 1
                        )));
                    }
                    parenthesis_depth -= 1;
                    chunk.push(ch);
                }
                _ => chunk.push(ch),
            }
        }

        if quote.is_some() {
            return Err(crate::ConfigError::Parse(format!(
                "routing line {}: unterminated quote",
                line_index + 1
            )));
        }

        let chunk = chunk.trim();
        if !chunk.is_empty() {
            if !current.is_empty() && !chunk.starts_with([')', ',']) {
                current.push(' ');
            }
            current.push_str(chunk);
        }

        if parenthesis_depth == 0 && !current.is_empty() {
            statements.push(std::mem::take(&mut current));
        }
    }

    if parenthesis_depth != 0 {
        return Err(crate::ConfigError::Parse(
            "routing section: unterminated parenthesized rule".into(),
        ));
    }

    Ok(statements)
}

fn parse_default_outbound(statement: &str) -> Option<String> {
    ["fallback:", "default:"]
        .into_iter()
        .find_map(|prefix| statement.strip_prefix(prefix))
        .map(str::trim)
        .map(str::to_owned)
}

fn parse_routing_rule(
    statement: String,
    index: usize,
) -> Option<(crate::routing::RoutingRule, Option<String>)> {
    let (left, right) = statement.split_once("->")?;
    let left = left.trim();
    let right = right.trim();
    let (outbound, must) = right.strip_suffix("(must)").map_or_else(
        || (right.to_owned(), false),
        |name| (name.trim().to_owned(), true),
    );
    let condition = parse_route_condition(left);
    let is_complex = must || left.split("&&").nth(1).is_some() || condition.needs_complex_display();
    let rule = crate::routing::RoutingRule {
        name: format!("rule-{index}"),
        condition,
        outbound: crate::routing::RoutingOutbound::Simple(outbound),
        priority: index as u32,
        must,
        mark: 0,
    };

    Some((rule, is_complex.then_some(statement)))
}

pub(super) fn parse_section(section: &Section) -> Result<RoutingConfig, crate::ConfigError> {
    split_routing_statements(&section.body).map(|statements| {
        statements
            .into_iter()
            .fold(RoutingConfig::default(), |mut config, statement| {
                if let Some(outbound) = parse_default_outbound(&statement) {
                    config.default_outbound = outbound;
                } else if let Some((rule, complex_source)) =
                    parse_routing_rule(statement, config.rules.len())
                {
                    if let Some(source) = complex_source {
                        config.record_complex_rule_source(rule.name.clone(), source);
                    }
                    config.rules.push(rule);
                }
                config
            })
    })
}

fn parse_route_matcher(condition: &mut crate::routing::RoutingCondition, matcher: &str) {
    let (negated, matcher) = matcher
        .strip_prefix('!')
        .map_or((false, matcher), |rest| (true, rest.trim()));
    if matcher.is_empty() {
        return;
    }

    let mut target = if negated {
        condition.not.fields_mut()
    } else {
        condition.fields_mut()
    };
    if let Some(args) = extract_fn_args(matcher, "pname") {
        target.process_name.extend(args);
    } else if let Some(args) = extract_fn_args(matcher, "dip") {
        parse_ip_args(&args, &mut target);
    } else if let Some(args) = extract_fn_args(matcher, "sip") {
        target.source_ip.extend(args);
    } else if let Some(args) = extract_fn_args(matcher, "domain") {
        parse_domain_args(&args, &mut target);
    } else if let Some(args) = extract_fn_args(matcher, "dport") {
        target.port.extend(args);
    } else if let Some(args) = extract_fn_args(matcher, "sport") {
        target.source_port.extend(args);
    } else if let Some(args) = extract_fn_args(matcher, "l4proto") {
        target.protocol.extend(args);
    } else if let Some(args) = extract_fn_args(matcher, "ipversion") {
        target.ip_version.extend(args);
    } else if let Some(args) = extract_fn_args(matcher, "mac") {
        target.mac.extend(args);
    } else if let Some(args) = extract_fn_args(matcher, "dscp") {
        target.dscp.extend(args);
    } else if let Some(value) = strip_tag_arg(matcher, "geosite:") {
        target.geosite.push(normalize_geosite_code(&value));
    } else if let Some(value) = strip_tag_arg(matcher, "geoip:") {
        target.geo_ip.push(normalize_geosite_code(&value));
    } else if let Some(value) = strip_tag_arg(matcher, "domain:") {
        target.domain_suffix.push(value);
    } else if let Some(value) = strip_tag_arg(matcher, "suffix:") {
        target.domain_suffix.push(value);
    } else if let Some(value) = strip_tag_arg(matcher, "keyword:") {
        target.domain_keyword.push(value);
    } else if let Some(value) = strip_tag_arg(matcher, "full:") {
        target.domain.push(value);
    } else if let Some(value) = strip_tag_arg(matcher, "regex:") {
        target.domain_regex.push(value);
    }
}

fn parse_route_condition(expr: &str) -> crate::routing::RoutingCondition {
    expr.split("&&")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .fold(
            crate::routing::RoutingCondition::default(),
            |mut condition, matcher| {
                parse_route_matcher(&mut condition, matcher);
                condition
            },
        )
}

/// Dispatch `domain(...)` arguments to the correct condition fields.
/// Supports `suffix:`, `keyword:`, `full:`, `regex:`, and `geosite:`.
fn parse_domain_args(args: &[String], cond: &mut crate::routing::ConditionFields<'_>) {
    for a in args {
        if let Some(v) = strip_tag_arg(a, "geosite:") {
            cond.geosite.push(normalize_geosite_code(&v));
        } else if let Some(v) = strip_tag_arg(a, "keyword:") {
            cond.domain_keyword.push(v);
        } else if let Some(v) = strip_tag_arg(a, "full:") {
            cond.domain.push(v);
        } else if let Some(v) = strip_tag_arg(a, "regex:") {
            cond.domain_regex.push(v);
        } else if let Some(v) = strip_tag_arg(a, "suffix:") {
            cond.domain_suffix.push(v);
        } else {
            // Bare domain argument defaults to suffix matching, mirroring dae.
            cond.domain_suffix.push(a.trim().to_string());
        }
    }
}

/// Dispatch `dip(...)` arguments to the correct condition fields.
/// Supports `geoip:` and plain CIDRs.
fn parse_ip_args(args: &[String], cond: &mut crate::routing::ConditionFields<'_>) {
    for a in args {
        if let Some(v) = strip_tag_arg(a, "geoip:") {
            cond.geo_ip.push(normalize_geosite_code(&v));
        } else {
            cond.ip.push(a.trim().to_string());
        }
    }
}
