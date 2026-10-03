//! Read-only DNS routing rules of the running generation.

use std::time::{Duration, Instant};

use axum::{
    Json,
    http::Uri,
    response::{IntoResponse, Response},
};
use honk_config::dns::{
    DnsCond, DnsDomainMatcher, DnsRequestAction, DnsResponseAction, DnsRouting,
};
use serde::Serialize;
use serde_json::{Value, json};

use super::super::{
    ApiError, NativeState,
    catalog::snapshot_unavailable,
    parse_query,
    routing::{MAX_RULES, RuleSource},
    types::RequestId,
};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Never below either running list, so both are always served whole.
pub(crate) fn capability(routing: &DnsRouting) -> Value {
    let size = routing
        .effective_request()
        .rules
        .len()
        .max(routing.response.rules.len())
        + 1;
    json!({"available":true,"max_rules":MAX_RULES.max(size)})
}

#[derive(Debug, Serialize)]
struct DnsRule {
    rule_id: String,
    index: usize,
    expression: String,
    action: &'static str,
    upstream: Option<String>,
    source: Option<RuleSource>,
    kind: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct DnsRuleList {
    generation_id: String,
    request: Vec<DnsRule>,
    response: Vec<DnsRule>,
}

/// A wire `action` and its `upstream`.
type Action = (&'static str, Option<String>);

pub(in crate::native_api) async fn serve(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let result = snapshot(state, Instant::now() + TIMEOUT, id).await?;
    Ok(Json(super::super::config::administrative_projection(
        state,
        json!(result),
    )?)
    .into_response())
}

pub(super) async fn snapshot(
    state: &NativeState,
    deadline: Instant,
    id: &RequestId,
) -> Result<DnsRuleList, ApiError> {
    tokio::time::timeout_at(deadline.into(), async {
        // Reload publishes the config, its generation and the accepted
        // sources under the config write lock, so this read pins all three.
        let config = state.config.read().await;
        let generation = state.diagnostics.read().generation;
        list(state, &config.dns.routing, generation)
    })
    .await
    .map_err(|_| snapshot_unavailable(id))
}

fn list(state: &NativeState, routing: &DnsRouting, generation: u64) -> DnsRuleList {
    let request = routing.effective_request();
    let response = &routing.response;
    DnsRuleList {
        generation_id: format!("{}:{generation}", state.instance_id),
        request: entries(
            state,
            generation,
            false,
            request
                .rules
                .iter()
                .map(|rule| (rule.conditions.as_slice(), request_action(&rule.action))),
            request_action(&request.fallback),
        ),
        response: entries(
            state,
            generation,
            true,
            response
                .rules
                .iter()
                .map(|rule| (rule.conditions.as_slice(), response_action(&rule.action))),
            response_action(&response.fallback),
        ),
    }
}

fn entries<'c>(
    state: &NativeState,
    generation: u64,
    response: bool,
    parsed: impl ExactSizeIterator<Item = (&'c [DnsCond], Action)>,
    fallback: Action,
) -> Vec<DnsRule> {
    let list = if response {
        "dns_response"
    } else {
        "dns_request"
    };
    let located = |index| {
        state
            .observation
            .configuration
            .dns_rule_source(response, index)
            .map(super::super::routing::located)
    };
    let count = parsed.len();
    let entry = |index: Option<usize>, (action, upstream): Action| {
        let (source, expression) = located(index).unzip();
        let instance = &state.instance_id;
        DnsRule {
            // Mirrors `/rules` ids with the list name in front of the ordinal.
            rule_id: match index {
                Some(index) => format!("{instance}:{generation}:{list}:rule:{index}"),
                None => format!("{instance}:{generation}:{list}:fallback"),
            },
            index: index.unwrap_or(count),
            expression: expression.unwrap_or_default(),
            action,
            upstream,
            source,
            kind: if index.is_some() { "rule" } else { "fallback" },
        }
    };
    let mut rules = Vec::with_capacity(count + 1);
    for (index, (conditions, action)) in parsed.enumerate() {
        let mut rule = entry(Some(index), action);
        if rule.expression.is_empty() {
            rule.expression = format!("{} -> {}", display(conditions), target(&rule));
        }
        rules.push(rule);
    }
    let mut fallback = entry(None, fallback);
    if fallback.expression.is_empty() {
        fallback.expression = format!("fallback: {}", target(&fallback));
    }
    rules.push(fallback);
    rules
}

fn request_action(action: &DnsRequestAction) -> Action {
    match action {
        DnsRequestAction::Upstream(name) => ("upstream", Some(name.clone())),
        DnsRequestAction::AsIs => ("asis", None),
        DnsRequestAction::Reject => ("reject", None),
    }
}

fn response_action(action: &DnsResponseAction) -> Action {
    match action {
        DnsResponseAction::Upstream(name) => ("requery", Some(name.clone())),
        DnsResponseAction::Accept => ("accept", None),
        DnsResponseAction::Reject => ("reject", None),
    }
}

/// The configuration spelling of an action: the upstream name, or the keyword.
fn target(rule: &DnsRule) -> &str {
    rule.upstream.as_deref().unwrap_or(rule.action)
}

/// A readable form of parsed conditions, used only when the accepted sources
/// cannot place the rule, so there is no source text to show.
fn display(conditions: &[DnsCond]) -> String {
    let render = |name: &str, not: bool, args: Vec<String>| {
        format!("{}{name}({})", if not { "!" } else { "" }, args.join(", "))
    };
    conditions
        .iter()
        .map(|condition| match condition {
            DnsCond::Qname { not, matchers } => render(
                "qname",
                *not,
                matchers
                    .iter()
                    .map(|matcher| match matcher {
                        DnsDomainMatcher::Full(value) => format!("full: {value}"),
                        DnsDomainMatcher::Suffix(value) => format!("suffix: {value}"),
                        DnsDomainMatcher::Keyword(value) => format!("keyword: {value}"),
                        DnsDomainMatcher::Regex(value) => format!("regex: {value}"),
                        DnsDomainMatcher::Geosite(value) => format!("geosite: {value}"),
                    })
                    .collect(),
            ),
            DnsCond::Qtype { not, types } => {
                render("qtype", *not, types.iter().map(u16::to_string).collect())
            }
            DnsCond::Sip { not, cidrs } => render("sip", *not, cidrs.clone()),
            DnsCond::Upstream { not, names } => render("upstream", *not, names.clone()),
            DnsCond::Ip { not, cidrs, geoip } => render(
                "ip",
                *not,
                cidrs
                    .iter()
                    .cloned()
                    .chain(geoip.iter().map(|code| format!("geoip: {code}")))
                    .collect(),
            ),
        })
        .collect::<Vec<_>>()
        .join(" && ")
}
