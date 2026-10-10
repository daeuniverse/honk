//! Captured flow evidence; only these fields can cross the recorder boundary.

use std::{
    mem::size_of,
    net::{IpAddr, SocketAddr},
    time::SystemTime,
};

use honk_config::types::DialMode;
use honk_outbound::runtime::flow_observation::DnsLookup;
use serde::Serialize;

use super::{MAX_RULE_VALUES, MAX_STEPS, display_text, safe_text};
use crate::observe::rules::RuleEvaluation;
use crate::observe::vocab::{
    ConnectionMilestone, ConnectionState, DomainSource, Network, Plane, RoutingSource, RuleSource,
};
use honk_outbound::runtime::flow_observation::{ResolutionLocation, TransportStatus};

/// Wire shape of a DNS lookup step; outbound captures the facts, the
/// recorder owns how they serialize.
// Serde only reads the remote type's fields; this mirror is never built.
#[allow(dead_code)]
#[derive(Serialize)]
#[serde(remote = "DnsLookup")]
struct DnsLookupWire {
    lookup_id: uuid::Uuid,
    parent_lookup_id: Option<uuid::Uuid>,
    attempt_id: Option<uuid::Uuid>,
    purpose: &'static str,
    name: String,
    qtype: String,
    source: &'static str,
    upstream_transport: Option<&'static str>,
    carrier_transport: Option<&'static str>,
    cache: &'static str,
    cache_entry_id: Option<String>,
    upstream: Option<String>,
    route_evaluation_ids: Vec<String>,
    status: &'static str,
    addresses: Vec<IpAddr>,
    selected_ip: Option<IpAddr>,
    error: Option<&'static str>,
}

#[derive(Clone, Serialize)]
pub(super) struct Summary {
    pub id: String,
    pub instance_id: String,
    pub revision: u64,
    pub network: Network,
    pub state: ConnectionState,
    pub pname: Option<String>,
    pub connection_id: Option<String>,
    pub outbound: Option<String>,
    pub chain: Vec<String>,
    pub chain_source: &'static str,
    pub rule_id: Option<String>,
    pub rule_generation_id: Option<String>,
    pub rule_expression: Option<String>,
    pub rule_source: RuleSource,
    pub ingress: (),
    pub domain_source: Option<DomainSource>,
    pub observed_by: &'static str,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub trace_status: &'static str,
}

impl Summary {
    pub(super) fn heap_bytes(&self) -> usize {
        self.id.capacity()
            + self.instance_id.capacity()
            + self.started_at.capacity()
            + optional_bytes([
                &self.pname,
                &self.connection_id,
                &self.outbound,
                &self.rule_id,
                &self.rule_generation_id,
                &self.rule_expression,
                &self.ended_at,
            ])
            + self.chain.capacity() * size_of::<String>()
            + self.chain.iter().map(String::capacity).sum::<usize>()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Input {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub domain: Option<String>,
    pub domain_source: Option<DomainSource>,
    pub pid: Option<u32>,
    pub process_path: (),
    pub src_mac: Option<String>,
    pub ingress: (),
    pub domain_rule_ids: (),
    pub dscp: Option<u8>,
    pub mark: Option<u32>,
}

impl Input {
    pub(super) fn heap_bytes(&self) -> usize {
        optional_bytes([&self.domain, &self.src_mac])
    }

    fn redact(&mut self, redacted: &mut bool, overflow: &mut bool) {
        redact_display(&mut self.domain, redacted, overflow);
        redact_display(&mut self.src_mac, redacted, overflow);
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct InputValues {
    #[serde(flatten)]
    pub input: Input,
    pub pname: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RouteInput {
    pub network: &'static str,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub domain: Option<String>,
    pub pname: Option<String>,
    pub src_mac: Option<String>,
    pub dscp: Option<u8>,
    pub mark: (),
    pub ingress: Option<&'static str>,
    pub domain_rule_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_fact_bitmap: Option<[u32; 8]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_fact_state: Option<u32>,
}

impl RouteInput {
    fn heap_bytes(&self) -> usize {
        optional_bytes([&self.domain, &self.pname, &self.src_mac])
            + self.domain_rule_ids.as_ref().map_or(0, |ids| {
                ids.capacity() * size_of::<String>()
                    + ids.iter().map(String::capacity).sum::<usize>()
            })
    }
}

impl From<&crate::routing::ConnectionInfo> for RouteInput {
    fn from(input: &crate::routing::ConnectionInfo) -> Self {
        Self {
            network: input.protocol,
            src_ip: input.src_ip,
            src_port: input.src_port,
            dst_ip: input.dst_ip,
            dst_port: input.dst_port,
            domain: input.domain.clone(),
            pname: input.process_name.clone(),
            src_mac: input.mac.clone(),
            dscp: input.dscp,
            mark: (),
            ingress: None,
            domain_rule_ids: None,
            domain_fact_bitmap: None,
            domain_fact_state: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DnsRequestInput {
    pub(crate) name: String,
    pub(crate) qtype: String,
    pub(crate) source_ip: Option<IpAddr>,
    pub(crate) original_dst: Option<SocketAddr>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DnsResponseInput {
    pub(crate) name: String,
    pub(crate) qtype: String,
    pub(crate) answer_ips: Vec<IpAddr>,
    pub(crate) from_upstream: String,
}

impl DnsRequestInput {
    pub(crate) fn heap_bytes(&self) -> usize {
        self.name.capacity() + self.qtype.capacity()
    }
}
impl DnsResponseInput {
    pub(crate) fn heap_bytes(&self) -> usize {
        self.name.capacity()
            + self.qtype.capacity()
            + self.from_upstream.capacity()
            + self.answer_ips.capacity() * size_of::<IpAddr>()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum EvaluationInput {
    Traffic(RouteInput),
    DnsRequest(DnsRequestInput),
    DnsResponse(DnsResponseInput),
}

impl EvaluationInput {
    fn heap_bytes(&self) -> usize {
        match self {
            Self::Traffic(input) => input.heap_bytes(),
            Self::DnsRequest(input) => input.heap_bytes(),
            Self::DnsResponse(input) => input.heap_bytes(),
        }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct Selection {
    pub group_id: String,
    pub member_id: Option<String>,
    pub member_name: Option<String>,
    pub policy: &'static str,
    pub reason: &'static str,
    pub selection: Option<SelectionDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_family: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<bool>,
}

#[derive(Clone, Serialize)]
pub(crate) struct SelectionDecision {
    pub previous_member_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_leaf_node_id: Option<String>,
    pub metric: Option<&'static str>,
    pub tolerance_ms: Option<f64>,
    pub candidates: Vec<SelectionCandidate>,
}

#[derive(Clone, Serialize)]
pub(crate) struct SelectionCandidate {
    pub member_id: String,
    pub member_name: Option<String>,
    pub leaf_node_id: Option<String>,
    pub leaf_node_name: Option<String>,
    pub eligible: Option<bool>,
    pub sorting_latency_ms: Option<f64>,
    pub score: Option<f64>,
    pub selected: bool,
    pub reason: &'static str,
}

impl Selection {
    fn heap_bytes(&self) -> usize {
        self.group_id.capacity()
            + optional_bytes([&self.member_id, &self.member_name])
            + self.selection.as_ref().map_or(0, |selection| {
                optional_bytes([
                    &selection.previous_member_id,
                    &selection.previous_leaf_node_id,
                ]) + selection.candidates.capacity() * size_of::<SelectionCandidate>()
                    + selection
                        .candidates
                        .iter()
                        .map(|candidate| {
                            candidate.member_id.capacity()
                                + optional_bytes([
                                    &candidate.member_name,
                                    &candidate.leaf_node_id,
                                    &candidate.leaf_node_name,
                                ])
                        })
                        .sum::<usize>()
            })
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct OutboundAttempt {
    pub parent_attempt_id: Option<String>,
    pub kind: &'static str,
    pub evaluation_id: Option<String>,
    pub routing_source: RoutingSource,
    pub routed_outbound: Option<String>,
    pub effective_outbound: Option<String>,
    #[serde(rename = "x-honk", serialize_with = "x_honk_mode_override")]
    pub mode_override: &'static str,
    pub selection_path: Vec<Selection>,
    pub leaf_node_id: Option<String>,
    pub leaf_node_name: Option<String>,
    pub target: Option<String>,
    pub target_kind: &'static str,
    pub dial_ip: Option<IpAddr>,
    pub server_addr: Option<SocketAddr>,
    pub resolution_location: ResolutionLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookup_id: Option<String>,
}

impl OutboundAttempt {
    fn heap_bytes(&self) -> usize {
        optional_bytes([
            &self.parent_attempt_id,
            &self.evaluation_id,
            &self.lookup_id,
            &self.routed_outbound,
            &self.effective_outbound,
            &self.leaf_node_id,
            &self.leaf_node_name,
            &self.target,
        ]) + self.selection_path.capacity() * size_of::<Selection>()
            + self
                .selection_path
                .iter()
                .map(Selection::heap_bytes)
                .sum::<usize>()
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FlowError {
    PolicyBlock,
    DialFailed,
    DialTimeout,
    LocalRefusal,
    UdpPrepareFailed,
    Cancelled,
    #[serde(untagged)]
    Code(&'static str),
}

#[derive(Serialize)]
#[serde(tag = "stage", content = "data", rename_all = "snake_case")]
pub(crate) enum StepData {
    Input {
        values: InputValues,
        source: &'static str,
    },
    Route {
        evaluation_id: String,
        chain: &'static str,
        plane: Plane,
        rule_id: Option<String>,
        rules: Vec<RuleEvaluation>,
        outbound: Option<String>,
        must: Option<bool>,
        mark: Option<u32>,
        input: Option<EvaluationInput>,
        dns_action: Option<&'static str>,
    },
    Dns(#[serde(with = "DnsLookupWire")] DnsLookup),
    Datapath {
        plane: Plane,
        action: &'static str,
        reason: &'static str,
        error: Option<FlowError>,
    },
    DialMode {
        configured: DialMode,
        effective_target: &'static str,
        domain: Option<String>,
        domain_source: Option<DomainSource>,
        verification: &'static str,
        reason: &'static str,
    },
    Reroute {
        performed: bool,
        reason: &'static str,
        from_evaluation_id: Option<String>,
        to_evaluation_id: Option<String>,
    },
    Outbound {
        attempt_id: String,
        #[serde(flatten)]
        attempt: OutboundAttempt,
        status: TransportStatus,
        error: Option<FlowError>,
    },
    Connection {
        state: ConnectionState,
        reason: &'static str,
        milestone: ConnectionMilestone,
        attempt_id: Option<String>,
        reply_received: Option<bool>,
        error: Option<FlowError>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        selections: Vec<Selection>,
        #[serde(skip_serializing_if = "Option::is_none")]
        lookup_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        server_addr: Option<SocketAddr>,
    },
}

#[derive(Serialize)]
pub(super) struct Step {
    pub seq: usize,
    #[serde(serialize_with = "rfc3339")]
    pub observed_at: SystemTime,
    pub elapsed_us: Option<u64>,
    pub generation_id: Option<String>,
    pub evidence: &'static str,
    #[serde(flatten)]
    pub data: StepData,
}

#[derive(Serialize)]
pub(super) struct SnapshotRow {
    #[serde(flatten)]
    pub summary: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<Input>,
}

impl SnapshotRow {
    pub(super) fn heap_bytes(&self) -> usize {
        self.summary.heap_bytes() + self.input.as_ref().map_or(0, Input::heap_bytes)
    }
}

impl Step {
    pub(super) fn heap_bytes(&self) -> usize {
        optional_bytes([&self.generation_id]) + self.data.heap_bytes()
    }
}

impl StepData {
    pub(super) fn heap_bytes(&self) -> usize {
        match self {
            Self::Input { values, .. } => {
                values.input.heap_bytes() + optional_bytes([&values.pname])
            }
            Self::Route {
                evaluation_id,
                rule_id,
                outbound,
                input,
                rules,
                ..
            } => {
                evaluation_id.capacity()
                    + optional_bytes([rule_id, outbound])
                    + input.as_ref().map_or(0, EvaluationInput::heap_bytes)
                    + rules.capacity() * size_of::<RuleEvaluation>()
                    + rules.iter().map(RuleEvaluation::heap_bytes).sum::<usize>()
            }
            Self::Dns(data) => {
                data.name.capacity()
                    + data.qtype.capacity()
                    + optional_bytes([&data.cache_entry_id, &data.upstream])
                    + data.route_evaluation_ids.capacity() * size_of::<String>()
                    + data
                        .route_evaluation_ids
                        .iter()
                        .map(String::capacity)
                        .sum::<usize>()
                    + data.addresses.capacity() * size_of::<IpAddr>()
            }
            Self::Datapath { .. } => 0,
            Self::DialMode { domain, .. } => optional_bytes([domain]),
            Self::Reroute {
                from_evaluation_id,
                to_evaluation_id,
                ..
            } => optional_bytes([from_evaluation_id, to_evaluation_id]),
            Self::Outbound {
                attempt_id,
                attempt,
                ..
            } => attempt_id.capacity() + attempt.heap_bytes(),
            Self::Connection {
                attempt_id,
                selections,
                lookup_id,
                ..
            } => {
                optional_bytes([attempt_id, lookup_id])
                    + selections.capacity() * size_of::<Selection>()
                    + selections.iter().map(Selection::heap_bytes).sum::<usize>()
            }
        }
    }

    pub(super) fn sanitize(&mut self, redacted: &mut bool, overflow: &mut bool) -> bool {
        match self {
            Self::Input { values, source } => {
                values.input.redact(redacted, overflow);
                redact_display(&mut values.pname, redacted, overflow);
                safe_text(source)
            }
            Self::Route {
                evaluation_id,
                chain,
                rule_id,
                outbound,
                input,
                rules,
                dns_action,
                ..
            } => {
                redact_display(outbound, redacted, overflow);
                if !sanitize_rules(rules, redacted, overflow) {
                    return false;
                }
                if let Some(input) = input {
                    match input {
                        EvaluationInput::Traffic(input) => {
                            redact_display(&mut input.domain, redacted, overflow);
                            redact_display(&mut input.pname, redacted, overflow);
                            redact_display(&mut input.src_mac, redacted, overflow);
                            if !safe_text(input.network) {
                                return false;
                            }
                            if let Some(ids) = &input.domain_rule_ids {
                                if ids.len() > MAX_RULE_VALUES {
                                    *overflow = true;
                                    return false;
                                }
                                if ids.iter().any(|id| !safe_reference(id)) {
                                    return false;
                                }
                            }
                        }
                        EvaluationInput::DnsRequest(input) => {
                            input.name = super::bounded_display(&input.name, redacted, overflow)
                                .unwrap_or_default();
                            if !display_text(&input.name) || !safe_text(&input.qtype) {
                                return false;
                            }
                        }
                        EvaluationInput::DnsResponse(input) => {
                            input.name = super::bounded_display(&input.name, redacted, overflow)
                                .unwrap_or_default();
                            input.from_upstream =
                                super::bounded_display(&input.from_upstream, redacted, overflow)
                                    .unwrap_or_default();
                            if input.answer_ips.len() > MAX_RULE_VALUES {
                                *overflow = true;
                                return false;
                            }
                            if !display_text(&input.name)
                                || !safe_text(&input.qtype)
                                || !display_text(&input.from_upstream)
                            {
                                return false;
                            }
                        }
                    }
                }
                [evaluation_id.as_str(), *chain].into_iter().all(safe_text)
                    && rule_id.as_deref().is_none_or(safe_text)
                    && dns_action.is_none_or(|action| {
                        matches!(
                            action,
                            "upstream" | "asis" | "accept" | "reject" | "requery"
                        )
                    })
            }
            Self::Dns(data) => {
                if data.addresses.len() > MAX_RULE_VALUES
                    || data.route_evaluation_ids.len() > MAX_RULE_VALUES
                {
                    *overflow = true;
                    return false;
                }
                redact_display(&mut data.upstream, redacted, overflow);
                data.name =
                    super::bounded_display(&data.name, redacted, overflow).unwrap_or_default();
                if data
                    .cache_entry_id
                    .as_deref()
                    .is_some_and(|value| !safe_text(value))
                {
                    data.cache_entry_id = None;
                    *redacted = true;
                }
                [
                    &data.qtype,
                    data.purpose,
                    data.source,
                    data.cache,
                    data.status,
                ]
                .into_iter()
                .all(safe_text)
                    && display_text(&data.name)
                    && data.route_evaluation_ids.iter().all(|id| safe_text(id))
                    && data.upstream_transport.is_none_or(safe_text)
                    && data.carrier_transport.is_none_or(safe_text)
                    && data.error.is_none_or(safe_text)
            }
            Self::Datapath {
                action,
                reason,
                error,
                ..
            } => [*action, *reason].into_iter().all(safe_text) && safe_error(error),
            Self::DialMode {
                effective_target,
                domain,
                verification,
                reason,
                ..
            } => {
                redact_display(domain, redacted, overflow);
                [*effective_target, *verification, *reason]
                    .into_iter()
                    .all(safe_text)
            }
            Self::Reroute {
                reason,
                from_evaluation_id,
                to_evaluation_id,
                ..
            } => {
                safe_text(reason)
                    && from_evaluation_id.as_deref().is_none_or(safe_text)
                    && to_evaluation_id.as_deref().is_none_or(safe_text)
            }
            Self::Outbound {
                attempt_id,
                attempt,
                error,
                ..
            } => {
                for display in [
                    &mut attempt.routed_outbound,
                    &mut attempt.effective_outbound,
                    &mut attempt.leaf_node_name,
                    &mut attempt.target,
                ] {
                    redact_display(display, redacted, overflow);
                }
                sanitize_selections(&mut attempt.selection_path, redacted, overflow)
                    && [
                        attempt_id.as_str(),
                        attempt.kind,
                        attempt.mode_override,
                        attempt.target_kind,
                    ]
                    .into_iter()
                    .all(safe_text)
                    && attempt.leaf_node_id.as_deref().is_none_or(safe_text)
                    && attempt.parent_attempt_id.as_deref().is_none_or(safe_text)
                    && attempt.evaluation_id.as_deref().is_none_or(safe_text)
                    && attempt.lookup_id.as_deref().is_none_or(safe_text)
                    && safe_error(error)
            }
            Self::Connection {
                reason,
                attempt_id,
                selections,
                error,
                lookup_id,
                ..
            } => {
                safe_text(reason)
                    && attempt_id.as_deref().is_none_or(safe_text)
                    && lookup_id.as_deref().is_none_or(safe_text)
                    && sanitize_selections(selections, redacted, overflow)
                    && safe_error(error)
            }
        }
    }
}

fn safe_error(error: &Option<FlowError>) -> bool {
    !matches!(error, Some(FlowError::Code(code)) if !safe_text(code))
}

fn safe_reference(value: &str) -> bool {
    safe_text(value)
        || value
            .rsplit_once("/condition:")
            .is_some_and(|(rule, condition)| safe_text(rule) && condition.parse::<u32>().is_ok())
}

pub(super) fn safe_expression(value: &str) -> bool {
    display_text(value)
}

fn sanitize_rules(rules: &mut [RuleEvaluation], redacted: &mut bool, overflow: &mut bool) -> bool {
    let count = rules.iter().fold(0usize, |count, rule| {
        count
            .saturating_add(1)
            .saturating_add(rule.conditions.len())
    });
    if count > MAX_RULE_VALUES {
        *overflow = true;
        return false;
    }
    for rule in rules {
        if !safe_text(&rule.rule_id)
            || !safe_rule_result(rule.result)
            || rule.missing_inputs.iter().any(|input| !safe_text(input))
        {
            return false;
        }
        rule.expression =
            super::bounded_display(&rule.expression, redacted, overflow).unwrap_or_default();
        for condition in &mut rule.conditions {
            if !safe_reference(&condition.id)
                || !safe_rule_result(condition.result)
                || condition
                    .missing_inputs
                    .iter()
                    .any(|input| !safe_text(input))
            {
                return false;
            }
            condition.expression =
                super::bounded_display(&condition.expression, redacted, overflow)
                    .unwrap_or_default();
        }
    }
    true
}

fn safe_rule_result(result: &str) -> bool {
    matches!(
        result,
        "matched" | "not_matched" | "skipped" | "indeterminate"
    )
}

fn sanitize_selections(
    selections: &mut [Selection],
    redacted: &mut bool,
    overflow: &mut bool,
) -> bool {
    let candidates = selections.iter().fold(0usize, |count, row| {
        count.saturating_add(
            row.selection
                .as_ref()
                .map_or(0, |selection| selection.candidates.len()),
        )
    });
    if selections.len() > MAX_STEPS || candidates > MAX_RULE_VALUES {
        *overflow = true;
        return false;
    }
    for row in selections {
        redact_display(&mut row.member_name, redacted, overflow);
        if ![row.group_id.as_str(), row.policy, row.reason]
            .into_iter()
            .all(safe_text)
            || !row.member_id.as_deref().is_none_or(safe_text)
            || !row.health_family.is_none_or(safe_text)
        {
            return false;
        }
        if let Some(selection) = &mut row.selection {
            if !selection
                .previous_member_id
                .as_deref()
                .is_none_or(safe_text)
                || !selection
                    .previous_leaf_node_id
                    .as_deref()
                    .is_none_or(safe_text)
                || !selection.metric.is_none_or(safe_text)
                || !selection.tolerance_ms.is_none_or(f64::is_finite)
            {
                return false;
            }
            for candidate in &mut selection.candidates {
                redact_display(&mut candidate.member_name, redacted, overflow);
                redact_display(&mut candidate.leaf_node_name, redacted, overflow);
                if !safe_text(&candidate.member_id)
                    || !safe_text(candidate.reason)
                    || !candidate.leaf_node_id.as_deref().is_none_or(safe_text)
                    || !candidate.sorting_latency_ms.is_none_or(f64::is_finite)
                    || !candidate.score.is_none_or(f64::is_finite)
                {
                    return false;
                }
            }
        }
    }
    true
}

fn optional_bytes<const N: usize>(values: [&Option<String>; N]) -> usize {
    values.into_iter().flatten().map(String::capacity).sum()
}

fn redact_display(value: &mut Option<String>, redacted: &mut bool, overflow: &mut bool) {
    if value
        .as_ref()
        .is_some_and(|text| display_text(text) && text.capacity() == text.len())
    {
        return;
    }
    if let Some(text) = value {
        *value = super::bounded_display(text, redacted, overflow);
    }
}

fn x_honk_mode_override<S: serde::Serializer>(
    mode_override: &&'static str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry("mode_override", mode_override)?;
    map.end()
}

fn rfc3339<S: serde::Serializer>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&crate::observe::timestamp(*time))
}
