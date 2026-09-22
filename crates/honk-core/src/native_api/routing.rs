//! Generation-pinned, non-publishing routing inspection.

use std::{
    net::IpAddr,
    time::{Duration, Instant, SystemTime},
};

use axum::{
    Json,
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::routing::{
    PredicateInput, Router,
    native::{self, EvaluatedRule, MatchResult, TraceError},
};

use super::{
    ApiError, ErrorCode, NativeState, error, parse_query, security::RequestRate, timestamp,
    types::RequestId,
};

const MAX_RULES: usize = 4096;
const MAX_STEPS: usize = 256;
const TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct TraceState {
    rate: RequestRate,
}

impl TraceState {
    pub(crate) fn new() -> Self {
        Self {
            rate: RequestRate::new(),
        }
    }

    pub(crate) fn capability(&self) -> Value {
        json!({"available":true,"resolve_modes":["none"],"max_addresses":1,
            "max_rule_steps":MAX_STEPS,"timeout_ms":TIMEOUT.as_millis(),
            "per_principal_requests_per_minute":30,"global_requests_per_minute":30})
    }
}

pub(crate) fn rules_capability() -> Value {
    json!({"available":true,"max_rules":MAX_RULES})
}

/// `None` identifies an evaluated fallback, never unknown kernel provenance.
pub(crate) fn rule_id(instance: &str, generation: u64, compiled_id: Option<u32>) -> String {
    match compiled_id {
        Some(id) => format!("{instance}:{generation}:rule:{id}"),
        None => format!("{instance}:{generation}:fallback"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TraceRequest {
    input: TraceInput,
    #[serde(default)]
    resolve: Resolve,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Resolve {
    #[default]
    None,
    Live,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Network {
    Tcp,
    Udp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TraceInput {
    network: Network,
    domain: Option<String>,
    dst_ip: Option<IpAddr>,
    dst_port: u16,
    src_ip: Option<IpAddr>,
    src_port: Option<u16>,
    pname: Option<String>,
    dscp: Option<u8>,
    #[serde(rename = "mark")]
    _mark: Option<u32>,
}

impl TraceInput {
    fn validate(&self, id: &RequestId) -> Result<(), ApiError> {
        if self.dst_port == 0
            || self.src_port == Some(0)
            || self.dscp.is_some_and(|v| v > 63)
            || self
                .domain
                .as_deref()
                .is_some_and(|name| !super::dns::validate_name(name))
            || (self.domain.is_none() && self.dst_ip.is_none())
        {
            return Err(invalid(id));
        }
        Ok(())
    }

    fn predicates(&self) -> PredicateInput<'_> {
        PredicateInput {
            domain: self.domain.as_deref(),
            dst_ip: self.dst_ip,
            dst_port: Some(self.dst_port),
            src_ip: self.src_ip,
            src_port: self.src_port,
            protocol: match self.network {
                Network::Tcp => "tcp",
                Network::Udp => "udp",
            },
            process_name: self.pname.as_deref(),
            mac: None,
            dscp: self.dscp,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RuleSource {
    file: String,
    source_id: String,
    line: usize,
    column: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct RoutingRule {
    pub(crate) rule_id: String,
    pub(crate) index: usize,
    pub(crate) expression: String,
    pub(crate) outbound: String,
    pub(crate) must: bool,
    pub(crate) source: Option<RuleSource>,
    pub(crate) kind: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct RuleFallback {
    pub(crate) outbound: String,
    pub(crate) source: Option<RuleSource>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RuleList {
    pub(crate) generation_id: String,
    pub(crate) rules: Vec<RoutingRule>,
    pub(crate) fallback: RuleFallback,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RuleCondition {
    pub(crate) id: String,
    pub(crate) expression: String,
    pub(crate) result: &'static str,
    pub(crate) missing_inputs: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RuleEvaluation {
    pub(crate) rule_id: String,
    pub(crate) expression: String,
    pub(crate) result: &'static str,
    pub(crate) missing_inputs: Vec<&'static str>,
    pub(crate) conditions: Vec<RuleCondition>,
}

impl RuleEvaluation {
    pub(crate) fn heap_bytes(&self) -> usize {
        self.rule_id.capacity()
            + self.expression.capacity()
            + self.missing_inputs.capacity() * size_of::<&str>()
            + self.conditions.capacity() * size_of::<RuleCondition>()
            + self
                .conditions
                .iter()
                .map(|condition| {
                    condition.id.capacity()
                        + condition.expression.capacity()
                        + condition.missing_inputs.capacity() * size_of::<&str>()
                })
                .sum::<usize>()
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct RoutingEvaluation {
    pub(crate) dst_ip: Option<IpAddr>,
    pub(crate) decision: &'static str,
    pub(crate) outbound: Option<String>,
    pub(crate) missing_inputs: Vec<&'static str>,
    pub(crate) rules: Vec<RuleEvaluation>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RoutingTraceResponse {
    pub(crate) mode: &'static str,
    pub(crate) instance_id: String,
    pub(crate) generation_id: String,
    pub(crate) observed_at: String,
    pub(crate) evaluations: Vec<RoutingEvaluation>,
    pub(crate) dns: Vec<Value>,
}

async fn evaluate_current(
    state: &NativeState,
    input: &TraceInput,
    deadline: Instant,
    id: &RequestId,
) -> Result<(RoutingEvaluation, u64), ApiError> {
    tokio::time::timeout_at(deadline.into(), async {
        let router = state.traffic_router.read().await;
        let config = state.config.read().await;
        let generation = state.diagnostics.read().generation;
        let mut evaluation =
            evaluate(&router, &state.instance_id, generation, input, deadline, id)?;
        let mut order: Vec<_> = config.routing.rules.iter().enumerate().collect();
        order.sort_by_key(|(_, rule)| rule.priority);
        for ((evaluated, compiled), (source_index, configured)) in evaluation
            .rules
            .iter_mut()
            .zip(router.compiled_routes())
            .zip(order)
        {
            check_deadline(deadline, id)?;
            evaluated.expression = state
                .observation
                .configuration
                .rule_source(Some(source_index))
                .map(|(_, _, source)| source.expression)
                .filter(|expression| !expression.is_empty())
                .unwrap_or_else(|| {
                    router.configured_rule_expression(&compiled.conditions, &configured.condition)
                });
            for (condition, compiled) in evaluated.conditions.iter_mut().zip(&compiled.conditions) {
                check_deadline(deadline, id)?;
                condition.expression = router.condition_display(compiled, &configured.condition);
            }
        }
        check_deadline(deadline, id)?;
        Ok((evaluation, generation))
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::CONFLICT,
            ErrorCode::SnapshotUnavailable,
            "Routing snapshot is unavailable",
            id,
        )
    })?
}

pub(super) async fn trace(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let deadline = Instant::now() + TIMEOUT;
    parse_query(request.uri(), &[], id)?;
    state.observation.trace.rate.admit(id)?;
    let mut content_types = request.headers().get_all("content-type").iter();
    let content_type = content_types.next().and_then(|v| v.to_str().ok());
    if content_types.next().is_some() {
        return Err(invalid(id));
    }
    if !content_type
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "Expected application/json",
            id,
        ));
    }
    let bytes = tokio::time::timeout_at(
        deadline.into(),
        axum::body::to_bytes(request.into_body(), 65536),
    )
    .await
    .map_err(|_| unavailable(id))?
    .map_err(|_| too_large(id))?;
    let request: TraceRequest = serde_json::from_slice(&bytes).map_err(|_| invalid(id))?;
    request.input.validate(id)?;
    if !matches!(request.resolve, Resolve::None) {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::UnsupportedValue,
            "Live routing resolution is not supported",
            id,
        ));
    }
    let (evaluation, generation) = evaluate_current(state, &request.input, deadline, id).await?;
    let response = RoutingTraceResponse {
        mode: "simulation",
        instance_id: state.instance_id.clone(),
        generation_id: format!("{}:{generation}", state.instance_id),
        observed_at: timestamp(SystemTime::now()),
        evaluations: vec![evaluation],
        dns: Vec::new(),
    };
    Ok(Json(super::config::administrative_projection(
        state,
        json!(response),
    )?)
    .into_response())
}

pub(super) async fn rules(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let deadline = Instant::now() + TIMEOUT;
    let result = tokio::time::timeout_at(deadline.into(), async {
        let router = state.traffic_router.read().await;
        let config = state.config.read().await;
        let generation = state.diagnostics.read().generation;
        let mut result = dictionary(&router, &state.instance_id, generation, deadline, id)?;
        let source =
            |index| {
                state.observation.configuration.rule_source(index).map(
                    |(source_id, file, location)| {
                        (
                            RuleSource {
                                file,
                                source_id,
                                line: location.line,
                                column: location.column,
                            },
                            location.expression,
                        )
                    },
                )
            };
        let mut order: Vec<_> = config.routing.rules.iter().enumerate().collect();
        order.sort_by_key(|(_, rule)| rule.priority);
        for (rule, (source_index, configured)) in result
            .rules
            .iter_mut()
            .filter(|rule| rule.kind == "rule")
            .zip(order)
        {
            if let Some(compiled) = router.compiled_routes().get(rule.index) {
                rule.expression =
                    router.configured_rule_expression(&compiled.conditions, &configured.condition);
            }
            if let Some((source, expression)) = source(Some(source_index)) {
                rule.source = Some(source);
                if !expression.is_empty() {
                    rule.expression = expression;
                }
            }
        }
        result.fallback.source = source(None).map(|(source, _)| source);
        if let Some(fallback) = result.rules.last_mut() {
            fallback.source = result.fallback.source.clone();
        }
        Ok::<_, ApiError>(result)
    })
    .await
    .map_err(|_| unavailable(id))??;
    Ok(Json(super::config::administrative_projection(
        state,
        json!(result),
    )?)
    .into_response())
}

fn dictionary(
    router: &Router,
    instance: &str,
    generation: u64,
    deadline: Instant,
    id: &RequestId,
) -> Result<RuleList, ApiError> {
    if router.route_count() >= MAX_RULES {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::TemporarilyUnavailable,
            "The complete rule dictionary exceeds its limit",
            id,
        )
        .with_retry_after(1));
    }
    let mut rules = Vec::with_capacity(router.route_count() + 1);
    for (index, rule) in router.compiled_routes().iter().enumerate() {
        check_deadline(deadline, id)?;
        rules.push(RoutingRule {
            rule_id: rule_id(instance, generation, Some(rule.id)),
            index,
            expression: rule.expression.clone(),
            outbound: rule.outbound.clone(),
            must: rule.must,
            source: None,
            kind: "rule",
        });
    }
    rules.push(RoutingRule {
        rule_id: rule_id(instance, generation, None),
        index: rules.len(),
        expression: "fallback".into(),
        outbound: router.default_outbound().into(),
        must: false,
        source: None,
        kind: "fallback",
    });
    check_deadline(deadline, id)?;
    Ok(RuleList {
        generation_id: format!("{instance}:{generation}"),
        rules,
        fallback: RuleFallback {
            outbound: router.default_outbound().into(),
            source: None,
        },
    })
}

fn evaluate(
    router: &Router,
    instance: &str,
    generation: u64,
    input: &TraceInput,
    deadline: Instant,
    id: &RequestId,
) -> Result<RoutingEvaluation, ApiError> {
    let evaluation = router
        .simulate(input.predicates(), MAX_STEPS, deadline)
        .map_err(|e| match e {
            TraceError::Steps => too_large(id),
            TraceError::Deadline => unavailable(id),
        })?;
    let mut missing_inputs = Vec::new();
    let mut rules = Vec::with_capacity(evaluation.rules.len());
    for (index, evaluated) in evaluation.rules.iter().enumerate() {
        check_deadline(deadline, id)?;
        let rule = rule_evaluation(instance, generation, router, index, evaluated);
        for name in &rule.missing_inputs {
            if !missing_inputs.contains(name) {
                missing_inputs.push(*name);
            }
        }
        rules.push(rule);
    }
    check_deadline(deadline, id)?;
    Ok(RoutingEvaluation {
        dst_ip: input.dst_ip,
        decision: if evaluation.outbound.is_some() {
            "determinate"
        } else {
            "indeterminate"
        },
        outbound: evaluation.outbound.map(str::to_owned),
        missing_inputs,
        rules,
    })
}

pub(crate) fn observed_rule_evaluations(
    instance: &str,
    generation: u64,
    router: &Router,
    evaluated: &[EvaluatedRule],
) -> Vec<RuleEvaluation> {
    evaluated
        .iter()
        .enumerate()
        .map(|(index, evaluated)| rule_evaluation(instance, generation, router, index, evaluated))
        .collect()
}

fn rule_evaluation(
    instance: &str,
    generation: u64,
    router: &Router,
    index: usize,
    evaluated: &EvaluatedRule,
) -> RuleEvaluation {
    let compiled = router.compiled_routes().get(index);
    let rule_id = rule_id(instance, generation, compiled.map(|rule| rule.id));
    let mut missing = Vec::new();
    let conditions = compiled
        .map(|rule| {
            rule.conditions
                .iter()
                .zip(&evaluated.conditions)
                .enumerate()
                .map(|(index, (condition, &result))| {
                    let condition_missing = if result == MatchResult::Indeterminate {
                        let name = native::missing_input(&condition.predicate);
                        if !missing.contains(&name) {
                            missing.push(name);
                        }
                        vec![name]
                    } else {
                        Vec::new()
                    };
                    RuleCondition {
                        id: format!("{rule_id}/condition:{index}"),
                        expression: rule.condition_expressions[index].clone(),
                        result: result_name(result),
                        missing_inputs: condition_missing,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    if evaluated.result != MatchResult::Indeterminate {
        missing.clear();
    }
    RuleEvaluation {
        rule_id,
        expression: compiled
            .map(|rule| rule.expression.clone())
            .unwrap_or_else(|| "fallback".into()),
        result: result_name(evaluated.result),
        missing_inputs: missing,
        conditions,
    }
}

fn result_name(result: MatchResult) -> &'static str {
    match result {
        MatchResult::Matched => "matched",
        MatchResult::NotMatched => "not_matched",
        MatchResult::Indeterminate => "indeterminate",
        MatchResult::Skipped => "skipped",
    }
}

fn check_deadline(deadline: Instant, id: &RequestId) -> Result<(), ApiError> {
    native::check_deadline(deadline).map_err(|_| unavailable(id))
}
fn invalid(id: &RequestId) -> ApiError {
    error(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid routing trace input",
        id,
    )
}
fn too_large(id: &RequestId) -> ApiError {
    error(
        StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::RequestTooLarge,
        "Routing trace exceeds its step limit",
        id,
    )
}
fn unavailable(id: &RequestId) -> ApiError {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Routing inspection timed out",
        id,
    )
    .with_retry_after(1)
}

#[cfg(test)]
mod tests;
