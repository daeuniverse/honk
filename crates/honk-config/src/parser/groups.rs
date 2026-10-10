use std::collections::HashMap;

use regex::Regex;

use super::cursor::Segment;
use super::diagnostics::ParserDiagnostics;
use super::lexer::{Source, TokenKind};
use super::read::{self, Text};
use crate::diagnostic::{DiagnosticSources, Severity};
use crate::group::{Group, GroupPolicy};
use crate::node::Node;
use crate::subscription::Subscription;
use crate::{ConfigDiagnostic, ConfigError};

pub(super) fn parse_group_section(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
    tolerance: u64,
) -> Result<Vec<Group>, super::ParseFailure> {
    let mut groups = Vec::new();

    for root in section {
        let Some(body) = root.body_with(super::cursor::BodySyntax::Declarations) else {
            continue;
        };
        for segment in body {
            diagnostics.at_section("group", Text::segment(&segment));
            let Some(group_text) = read::block_header(&segment) else {
                Text::segment(&segment).notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-statement",
                    "group declaration requires a block",
                );
                continue;
            };
            let index = groups.len() + 1;
            diagnostics.begin_group_text(group_text, index);

            let mut group = Group {
                name: group_text.raw().to_owned(),
                ..Default::default()
            };
            for child in segment.body().into_iter().flatten() {
                if let Some(header) = read::block_header(&child)
                    && let Some(field) =
                        ["icon", "tolerance", "idle_timeout", "interrupt_connections"]
                            .into_iter()
                            .find(|field| header.raw().trim_end_matches(':').trim() == *field)
                {
                    return Err(group_scalar_error(
                        header,
                        index,
                        field,
                        "group scalar does not accept a nested block",
                    )
                    .into());
                }
            }
            let mut fields: HashMap<&str, Text<'_, '_>> = HashMap::new();
            for statement in
                read::child_statements(&segment, diagnostics, super::cursor::BodySyntax::Statements)
            {
                let Some((key, value)) = statement.kv() else {
                    statement.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-statement",
                        "unknown group statement ignored",
                    );
                    continue;
                };
                if ![
                    "filter",
                    "policy",
                    "final",
                    "default",
                    "check_url",
                    "icon",
                    "tolerance",
                    "idle_timeout",
                    "interrupt_connections",
                ]
                .contains(&key.raw())
                {
                    key.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-key",
                        "unknown scalar key ignored",
                    );
                    continue;
                }
                let key = key.raw().trim();
                if key == "filter" {
                    append_filter(&mut group, value.trim(), diagnostics);
                } else {
                    diagnostics.register_field(key, value);
                    fields.insert(key, value.unquote());
                }
            }

            if let Some(policy) = fields.get("policy").copied() {
                group.policy = parse_group_policy(policy, &group.name, diagnostics)?;
            }
            if group.policy == GroupPolicy::URLTest {
                group.tolerance = tolerance;
            }
            if let Some(value) = fields.get("final").copied() {
                group.final_outbound = Some(value.raw().to_owned());
            }
            if let Some(value) = fields.get("default").copied() {
                group.default = Some(value.raw().to_owned());
            }
            if let Some(value) = fields.get("check_url").copied() {
                group.check_url = Some(value.raw().to_owned());
            }
            if let Some(value) = fields.get("icon").copied() {
                if !Group::valid_icon(value.raw()) {
                    return Err(
                        group_scalar_error(value, index, "icon", Group::INVALID_ICON).into(),
                    );
                }
                group.icon = Some(value.raw().to_owned());
            }
            if let Some(value) = fields.get("tolerance").copied() {
                group.own.tolerance = true;
                group.tolerance = value.raw().parse::<u64>().map_err(|_| {
                    group_scalar_error(
                        value,
                        index,
                        "tolerance",
                        "tolerance must be a nonnegative integer in milliseconds",
                    )
                })?;
            }
            if let Some(value) = fields.get("idle_timeout").copied() {
                group.idle_timeout = Some(value.raw().parse::<u64>().map_err(|_| {
                    group_scalar_error(
                        value,
                        index,
                        "idle_timeout",
                        "idle timeout must be a nonnegative integer in seconds",
                    )
                })?);
            }
            if let Some(value) = fields.get("interrupt_connections").copied() {
                group.own.interrupt_connections = true;
                group.interrupt_connections =
                    super::scalars::strict_bool(value.raw()).ok_or_else(|| {
                        group_scalar_error(
                            value,
                            index,
                            "interrupt_connections",
                            "interrupt_connections must be a boolean",
                        )
                    })?;
            }

            groups.push(group);
        }
    }

    Ok(groups)
}

fn group_scalar_error(
    value: Text<'_, '_>,
    index: usize,
    field: &'static str,
    message: &'static str,
) -> crate::error::DetailedConfigError {
    let mut error = crate::error::DetailedConfigError::new(
        crate::error::ErrorCategory::Validation,
        "invalid-config-value",
        value.source.reference(),
        crate::diagnostic::SettingPath::new("groups")
            .index(index)
            .field(field),
        message,
    );
    error.diagnostic.line = Some(value.source.location(value.span.start).0);
    error
}

fn append_filter(group: &mut Group, filter: Text<'_, '_>, diagnostics: &mut ParserDiagnostics<'_>) {
    let filter = filter.trim();
    filter.warn_glued_hash(diagnostics);
    if let Some(arguments) = standalone_group_reference(filter) {
        let mut has_tag = false;
        for argument in arguments {
            let argument = argument.trim();
            let quoted_aggregate = argument
                .quoted_prefix()
                .is_some_and(|quoted| quoted.span == argument.span)
                && argument.unquote().raw().contains(['|', ',']);
            if quoted_aggregate {
                argument.notice(
                    diagnostics,
                    Severity::Warning,
                    "legacy-quoted-list",
                    "quoted subgroup lists are retained for compatibility",
                );
            }
            for tag in argument
                .unquote()
                .raw()
                .split(['|', ','])
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
            {
                has_tag = true;
                if !group.groups.iter().any(|existing| existing == tag) {
                    group.groups.push(tag.to_owned());
                }
            }
        }
        if has_tag {
            return;
        }

        diagnostics.remember_filter_text(filter);
        group.filters.push(filter.raw().to_owned());
        filter.notice(
            diagnostics,
            Severity::Warning,
            "empty-subgroup",
            "empty subgroup contribution selects no nodes; remove the filter to select all nodes",
        );
        return;
    }

    diagnostics.remember_filter_text(filter);
    group.filters.push(filter.raw().to_owned());
}

fn standalone_group_reference<'d, 'a>(text: Text<'d, 'a>) -> Option<Vec<Text<'d, 'a>>> {
    let text = text.trim();
    if text.has_error() || !text.raw().starts_with("group(") {
        return None;
    }
    let body = text.sub("group(".len(), text.raw().len());
    let end = body.find(")")?;
    if !body.sub(end + 1, body.raw().len()).trim().raw().is_empty() {
        return None;
    }
    let args = body.sub(0, end);
    if args.find("(").is_some() {
        return None;
    }
    Some(args.split(",").collect())
}

fn parse_group_policy(
    policy: Text<'_, '_>,
    group_name: &str,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<GroupPolicy, ConfigError> {
    let policy = policy.trim();
    let raw = policy.raw();
    let base = policy
        .find("(")
        .map(|offset| policy.sub(0, offset).raw())
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    match base.as_str() {
        "select" | "selector" | "fixed" => Ok(GroupPolicy::Selector),
        "urltest" | "min_moving_avg" | "min_avg10" | "min_last_delay" => Ok(GroupPolicy::URLTest),
        "roundrobin" | "round_robin" | "loadbalance" | "balance" => Ok(GroupPolicy::LoadBalance),
        "fallback" => Ok(GroupPolicy::Fallback),
        "score" => Ok(GroupPolicy::Score),
        "honk" => Err(ConfigError::UnsupportedPolicy(
            "group policy 'honk' was renamed to 'score'".into(),
        )),
        _ => {
            diagnostics.at_text(policy);
            diagnostics.push(ConfigDiagnostic {
                setting: format!("group.{group_name}.policy"),
                value: String::new(),
                message: "policy is not recognised; using fallback selector".to_string(),
            });
            Ok(GroupPolicy::Selector)
        }
    }
}

/// Resolve source-preserved group filters into concrete node UUIDs.
///
/// Each filter line is OR-ed; terms separated by `&&` are AND-ed. Subgroup
/// references are graph edges collected during parsing and never interpreted as
/// node predicates here.
pub(super) fn resolve_group_filters_inner(
    groups: &mut [Group],
    nodes: &[Node],
    subscriptions: &[Subscription],
    mut diagnostics: Option<&mut ParserDiagnostics<'_>>,
) {
    let mut subscription_tags: HashMap<uuid::Uuid, Vec<&str>> = HashMap::new();
    for subscription in subscriptions {
        subscription_tags
            .entry(subscription.id)
            .or_default()
            .push(subscription.name.as_str());
    }

    for (group_index, group) in groups.iter_mut().enumerate() {
        if let Some(sink) = diagnostics.as_deref_mut() {
            sink.select_group(group_index + 1);
        }

        let mut has_node_filter = false;
        let mut parsed_filters = Vec::new();
        for (filter_index, filter) in group.filters.iter().enumerate() {
            let (parsed, subgroup_has_members, message) = parse_runtime_filter(filter);
            if subgroup_has_members == Some(true) {
                continue;
            }
            has_node_filter = true;
            if let Some(parsed) = parsed {
                parsed_filters.push(parsed);
            } else if subgroup_has_members.is_none()
                && let Some(sink) = diagnostics.as_deref_mut()
                && !sink.filter_has_error(filter_index + 1)
            {
                sink.push(ConfigDiagnostic {
                    setting: format!("group.{}.filter", group.name),
                    value: (filter_index + 1).to_string(),
                    message: message.to_string(),
                });
            }
        }

        // The injected `direct` and `block` are outbounds, not part of the
        // node pool a group draws from: an unfiltered group and every
        // pattern skip them, and only a filter line that spells the name
        // literally (`name(direct)`) admits one.
        if !has_node_filter {
            if group.groups.is_empty() {
                for node in nodes.iter().filter(|node| !is_builtin(node)) {
                    if !group.nodes.contains(&node.id) {
                        group.nodes.push(node.id);
                    }
                }
            }
            continue;
        }
        group.nodes.clear();

        for node in nodes {
            let admitted = parsed_filters.iter().any(|filter| {
                (!is_builtin(node) || filter.iter().any(|term| term.names_literally(&node.name)))
                    && filter
                        .iter()
                        .all(|term| term.matches(node, &subscription_tags))
            });
            if admitted && !group.nodes.contains(&node.id) {
                group.nodes.push(node.id);
            }
        }
    }
}

fn is_builtin(node: &Node) -> bool {
    matches!(
        node.outbound,
        crate::node::OutboundConfig::Direct | crate::node::OutboundConfig::Block
    )
}

struct GroupFilterTerm {
    matcher: GroupFilterMatcher,
    negated: bool,
}

enum GroupFilterMatcher {
    /// The compiled pattern and the names the filter spelled out exactly.
    Name(Regex, Vec<String>),
    SubscriptionTag(Regex),
}

impl GroupFilterTerm {
    /// A positive `name(...)` term that lists `name` as an exact argument.
    fn names_literally(&self, name: &str) -> bool {
        match &self.matcher {
            GroupFilterMatcher::Name(_, exact) => {
                !self.negated && exact.iter().any(|literal| literal == name)
            }
            GroupFilterMatcher::SubscriptionTag(_) => false,
        }
    }

    fn matches(&self, node: &Node, subscription_tags: &HashMap<uuid::Uuid, Vec<&str>>) -> bool {
        let matched = match &self.matcher {
            GroupFilterMatcher::Name(pattern, _) => pattern.is_match(&node.name),
            GroupFilterMatcher::SubscriptionTag(pattern) => node
                .subscription_id
                .and_then(|id| subscription_tags.get(&id))
                .is_some_and(|tags| tags.iter().any(|tag| pattern.is_match(tag))),
        };
        if self.negated { !matched } else { matched }
    }
}

fn parse_runtime_filter(
    filter: &str,
) -> (Option<Vec<GroupFilterTerm>>, Option<bool>, &'static str) {
    let source_ref = DiagnosticSources::new(None).root();
    let source = Source::new(filter, source_ref);
    let tokens = source.tokenize(&mut Vec::new());
    let end = tokens
        .iter()
        .find(|token| token.kind == TokenKind::Comment)
        .map_or(filter.len(), |token| token.span.start);
    let text = Text {
        source: &source,
        tokens: &tokens,
        span: source.span(0, end),
        comment: None,
    };
    let text = text.trim();
    let subgroup_has_members = standalone_group_reference(text).map(|arguments| {
        arguments.into_iter().any(|argument| {
            argument
                .unquote()
                .raw()
                .split(['|', ','])
                .any(|tag| !tag.trim().is_empty())
        })
    });
    let message = if text.raw().starts_with("group(") {
        let body = text.sub("group(".len(), text.raw().len());
        if body.find(")").is_none() {
            "group(...) is unterminated; ignored"
        } else {
            "group(...) must be the whole filter line; ignored"
        }
    } else {
        "honk could not parse this filter; ignored"
    };
    (
        parse_group_filter_expression(text),
        subgroup_has_members,
        message,
    )
}

fn parse_group_filter_expression(text: Text<'_, '_>) -> Option<Vec<GroupFilterTerm>> {
    let text = text.trim();
    if text.has_error() {
        return None;
    }
    let mut terms = Vec::new();
    for raw_term in text.split("&&") {
        let raw_term = raw_term.trim();
        let (negated, predicate) = if raw_term.raw().starts_with('!') {
            (true, raw_term.sub(1, raw_term.raw().len()).trim())
        } else {
            (false, raw_term)
        };
        let matcher = if predicate.raw().starts_with("name(") {
            let (pattern, exact) = parse_text_filter(predicate, "name")?;
            GroupFilterMatcher::Name(pattern, exact)
        } else if predicate.raw().starts_with("subtag(") {
            GroupFilterMatcher::SubscriptionTag(parse_text_filter(predicate, "subtag")?.0)
        } else {
            return None;
        };
        terms.push(GroupFilterTerm { matcher, negated });
    }
    (!terms.is_empty()).then_some(terms)
}

/// The compiled alternation and, separately, the arguments given as exact
/// names (neither `keyword:` nor `regex:`).
fn parse_text_filter(text: Text<'_, '_>, function: &str) -> Option<(Regex, Vec<String>)> {
    let text = text.trim();
    let raw = text.raw();
    let body = raw.strip_prefix(function)?;
    if !body.starts_with('(') || !body.ends_with(')') {
        return None;
    }
    // Parentheses inside a regex remain pattern data, including escaped literals.
    let args = text.sub(function.len() + 1, raw.len() - 1);
    let mut patterns = Vec::new();
    let mut exact = Vec::new();
    for argument in args.split(",") {
        let argument = argument.trim();
        let raw = argument.raw();
        let pattern = if raw.strip_prefix("keyword:").is_some() {
            let value = argument
                .sub("keyword:".len(), raw.len())
                .trim()
                .unquote()
                .raw();
            if value.is_empty() {
                continue;
            }
            regex::escape(value)
        } else if raw.strip_prefix("regex:").is_some() {
            let value = argument
                .sub("regex:".len(), raw.len())
                .trim()
                .unquote()
                .raw();
            if value.is_empty() {
                continue;
            }
            format!("(?:{value})")
        } else {
            let value = argument.unquote().raw();
            if value.is_empty() {
                continue;
            }
            exact.push(value.to_string());
            format!("^(?:{})$", regex::escape(value))
        };
        patterns.push(pattern);
    }
    if patterns.is_empty() {
        return None;
    }
    Some((Regex::new(&patterns.join("|")).ok()?, exact))
}
