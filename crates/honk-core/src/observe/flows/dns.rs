//! DNS evidence captured inside the operation that consumed the policy.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Weak},
};

use honk_outbound::runtime::flow_observation::{
    self, DnsLookup, FlowEvent, FlowObserver, GapReason, SessionEvent, TransportStatus,
};
use parking_lot::Mutex;
use uuid::Uuid;

use super::{
    MAX_RULE_VALUES, MAX_TEXT,
    producer::{bounded, captured_selection, map_selection_observation},
    record::{DnsRequestInput, DnsResponseInput, EvaluationInput, StepData},
};
use crate::dns::{
    forwarder::DnsForwardError,
    outcome::{DnsOutcome, OutcomeStatus, Provenance, ResponseClass},
    query::{DnsRequestMeta, IngressProfile, QueryContext},
};
use crate::observe::vocab::{ConnectionMilestone, ConnectionState, Plane, RoutingSource};
use crate::observe::{
    DnsRecorder,
    catalog::CatalogIdentity,
    rules::{RuleCondition, RuleEvaluation},
};

const MAX_ADDRESSES: usize = 256;

tokio::task_local! {
    static DNS_API: Weak<DnsRecorder>;
    static LOOKUP: LookupState;
    static CATALOG: Option<Arc<CatalogIdentity>>;
}

pub(crate) fn scope_api<F: Future>(
    api: Weak<DnsRecorder>,
    future: F,
) -> impl Future<Output = F::Output> {
    DNS_API.scope(api, future)
}

pub(crate) fn scope_catalog<F: Future>(
    catalog: Option<Arc<CatalogIdentity>>,
    future: F,
) -> impl Future<Output = F::Output> {
    CATALOG.scope(catalog, future)
}

/// Changes only the reason for child lookups; lineage remains owned by the caller.
pub(crate) async fn scope_purpose<F: Future>(
    purpose: &'static str,
    future: std::pin::Pin<&mut F>,
) -> F::Output {
    if let Some(observer) = flow_observation::current() {
        let mut context = observer.context();
        context.dns_purpose = purpose;
        observer.with_context(context).scope(future).await
    } else {
        future.await
    }
}

pub(crate) async fn outbound_dial_scope<F: Future>(
    node: &honk_config::node::Node,
    future: F,
) -> F::Output {
    use honk_config::types::NodeProtocol;
    let future = std::pin::pin!(future);

    if matches!(node.protocol(), NodeProtocol::Direct | NodeProtocol::Block) {
        future.await
    } else {
        scope_purpose("proxy_server", future).await
    }
}

#[derive(Clone)]
struct LookupState {
    observer: FlowObserver,
    data: Arc<Mutex<DnsLookup>>,
    metadata: DnsRequestMeta,
}

pub(crate) struct LookupGuard {
    state: LookupState,
    finished: bool,
}

impl LookupGuard {
    pub(crate) fn start(
        raw: &[u8],
        ingress: IngressProfile,
        metadata: DnsRequestMeta,
    ) -> Option<Self> {
        let observer = flow_observation::current()?;
        let query = match QueryContext::parse_with_profile(raw, ingress) {
            Ok(query) => query,
            Err(_) => {
                observer.publish(FlowEvent::Gap(GapReason::NotInstrumented));
                return None;
            }
        };
        let name = query.qname().and_then(|name| name.to_domain_name());
        let Some((name, query_type)) = name.zip(query.qtype()) else {
            observer.publish(FlowEvent::Gap(GapReason::NotInstrumented));
            return None;
        };
        let parent = observer.context();
        let lookup_id = Uuid::new_v4();
        let mut context = parent;
        context.lookup_id = Some(lookup_id);
        let state = LookupState {
            observer: observer.with_context(context),
            data: Arc::new(Mutex::new(DnsLookup {
                lookup_id,
                parent_lookup_id: parent.lookup_id,
                attempt_id: parent.attempt_id,
                purpose: parent.dns_purpose,
                name,
                qtype: qtype(query_type.get()),
                source: "unknown",
                upstream_transport: None,
                carrier_transport: None,
                cache: "unknown",
                cache_entry_id: None,
                upstream: None,
                route_evaluation_ids: Vec::new(),
                status: "started",
                addresses: Vec::new(),
                selected_ip: None,
                error: None,
            })),
            metadata,
        };
        let guard = Self {
            state,
            finished: false,
        };
        guard.publish();
        Some(guard)
    }

    pub(crate) fn scope<F: Future>(&self, future: F) -> impl Future<Output = F::Output> {
        self.state
            .observer
            .scope(LOOKUP.scope(self.state.clone(), future))
    }

    fn publish(&self) {
        let data = self.state.data.lock().clone();
        self.state.observer.publish(FlowEvent::Dns(data));
    }

    pub(crate) fn finish(&mut self, status: &'static str, error: Option<&'static str>) {
        if self.finished {
            return;
        }
        self.finished = true;
        {
            let mut data = self.state.data.lock();
            data.status = status;
            data.error = error;
        }
        self.publish();
    }

    pub(crate) fn outcome(&mut self, result: &Result<DnsOutcome, DnsForwardError>) {
        match result {
            Ok(outcome) => {
                let mut data = self.state.data.lock();
                match outcome.provenance() {
                    Provenance::Cache => {
                        data.cache = "hit";
                        if data.source != "coalesced" {
                            data.source = "cache";
                        }
                    }
                    Provenance::Stale => {
                        data.cache = "stale";
                        if data.source != "coalesced" {
                            data.source = "cache";
                        }
                    }
                    Provenance::Upstream => {
                        if data.source != "coalesced" {
                            data.source = "upstream";
                        }
                    }
                    Provenance::Fresh => {}
                }
                data.cache_entry_id = outcome.cache_entry_id().map(bounded);
                if data.source != "coalesced" {
                    data.upstream = outcome.final_upstream().map(bounded);
                }
                data.addresses = addresses(outcome.answer_ips(), &self.state.observer);
                drop(data);
                let status = match (outcome.status(), outcome.response_class()) {
                    (OutcomeStatus::Rejected, _) => "rejected",
                    (_, ResponseClass::Positive) => "succeeded",
                    (_, ResponseClass::Nodata) => "nodata",
                    (_, ResponseClass::Nxdomain) => "nxdomain",
                    (_, ResponseClass::Servfail) => "failed",
                };
                self.finish(status, (status == "failed").then_some("servfail"));
            }
            Err(error) => {
                if let DnsForwardError::Exchange { source, .. } | DnsForwardError::Internal(source) =
                    error.unshared()
                    && cancelled(source)
                {
                    self.finish("cancelled", Some("cancelled"));
                    return;
                }
                let code = match error.unshared() {
                    DnsForwardError::Engine(_) => "query_or_policy_failed",
                    DnsForwardError::Exchange { .. } => "upstream_failed",
                    DnsForwardError::Response(_) => "invalid_response",
                    DnsForwardError::Overloaded => "overloaded",
                    DnsForwardError::Internal(_) | DnsForwardError::RejectedPlanEscaped => {
                        "resolution_failed"
                    }
                    DnsForwardError::Shared(_) => unreachable!("unwrapped shared failure"),
                };
                self.finish("failed", Some(code));
            }
        }
    }
}

impl Drop for LookupGuard {
    fn drop(&mut self) {
        self.finish("cancelled", Some("cancelled"));
    }
}

pub(crate) fn source(source: &'static str, cache: Option<&'static str>) {
    let _ = with_lookup(|lookup| {
        let mut data = lookup.data.lock();
        data.source = source;
        if let Some(cache) = cache {
            data.cache = cache;
        }
        if source == "coalesced" {
            data.status = "joined";
            let event = data.clone();
            drop(data);
            lookup.observer.publish(FlowEvent::Dns(event));
        }
    });
}

pub(crate) fn cache_state(cache: &'static str) {
    let _ = with_lookup(|lookup| {
        let mut data = lookup.data.lock();
        data.cache = cache;
        if matches!(cache, "hit" | "stale") && data.source != "coalesced" {
            data.source = "cache";
        }
    });
}

pub(crate) fn cache_entry(id: Option<&str>) {
    let _ = with_lookup(|lookup| {
        lookup.data.lock().cache_entry_id = id.map(bounded);
    });
}

pub(crate) fn transport(upstream: &'static str, carrier: &'static str) {
    let _ = with_lookup(|lookup| {
        let mut data = lookup.data.lock();
        data.upstream_transport = Some(upstream);
        data.carrier_transport = Some(carrier);
    });
}

pub(crate) fn tcp_fallback() {
    if let Some(observer) = flow_observation::current() {
        observer.publish(FlowEvent::Session(
            SessionEvent::DnsResponseTruncatedTcpFallback,
        ));
    }
}

pub(crate) fn upstream(name: &str) {
    let _ = with_lookup(|lookup| {
        lookup.data.lock().upstream = Some(bounded(name));
    });
}

pub(crate) fn delivery(status: &'static str, error: Option<&'static str>) {
    let _ = with_lookup(|lookup| {
        let mut data = lookup.data.lock();
        data.status = status;
        data.error = error;
    });
}

/// Records how a reply guarded by runtime retirement left: delivered when the
/// send finished and `complete` accepts what it reports, else `failure`.
pub(crate) fn reply_delivery<T, E, C>(
    result: &Result<Result<T, E>, C>,
    complete: impl FnOnce(&T) -> bool,
    failure: &'static str,
) {
    let (status, error) = match result {
        Ok(Ok(sent)) if complete(sent) => ("delivered", None),
        Ok(_) => ("delivery_failed", Some(failure)),
        Err(_) => ("cancelled", Some("runtime_retired")),
    };
    delivery(status, error);
}

pub(crate) fn decision(status: &'static str, error: Option<&'static str>) {
    delivery(status, error);
    let _ = with_lookup(|lookup| {
        let data = lookup.data.lock().clone();
        lookup.observer.publish(FlowEvent::Dns(data));
    });
}

pub(crate) fn qtype(value: u16) -> String {
    crate::dns::response::native::record_type(value)
}

fn addresses(values: &[IpAddr], observer: &FlowObserver) -> Vec<IpAddr> {
    if values.len() > MAX_ADDRESSES {
        observer.publish(FlowEvent::Gap(GapReason::BufferOverflow));
    }
    let mut result = Vec::with_capacity(values.len().min(MAX_ADDRESSES));
    for value in values.iter().take(MAX_ADDRESSES) {
        if !result.contains(value) {
            result.push(*value);
        }
    }
    result
}

pub(crate) struct RuleCapture {
    observer: FlowObserver,
    api: Arc<DnsRecorder>,
    chain: &'static str,
    input: EvaluationInput,
    rules: Vec<RuleEvaluation>,
    remaining: usize,
    overflow: bool,
    recording_rule: bool,
}

impl RuleCapture {
    pub(crate) fn request(name: &str, query_type: u16, source_ip: Option<IpAddr>) -> Option<Self> {
        let (observer, api) = authority()?;
        let original_dst = with_lookup(|lookup| lookup.metadata.original_dst()).flatten();
        Some(Self::new(
            observer,
            api,
            "dns_request",
            EvaluationInput::DnsRequest(DnsRequestInput {
                name: bounded(name),
                qtype: qtype(query_type),
                source_ip,
                original_dst,
            }),
        ))
    }

    pub(crate) fn response(
        name: &str,
        query_type: u16,
        ips: &[IpAddr],
        from: &str,
    ) -> Option<Self> {
        let (observer, api) = authority()?;
        let input = EvaluationInput::DnsResponse(DnsResponseInput {
            name: bounded(name),
            qtype: qtype(query_type),
            answer_ips: addresses(ips, &observer),
            from_upstream: bounded(from),
        });
        Some(Self::new(observer, api, "dns_response", input))
    }

    fn new(
        observer: FlowObserver,
        api: Arc<DnsRecorder>,
        chain: &'static str,
        input: EvaluationInput,
    ) -> Self {
        Self {
            observer,
            api,
            chain,
            input,
            rules: Vec::new(),
            remaining: MAX_RULE_VALUES,
            overflow: false,
            recording_rule: false,
        }
    }

    pub(crate) fn begin_rule(
        &mut self,
        index: Option<usize>,
        conditions: &[honk_config::dns::DnsCond],
    ) {
        self.recording_rule = self.remaining != 0;
        if self.remaining == 0 {
            self.overflow = true;
            return;
        }
        self.remaining -= 1;
        let context = self.observer.context();
        let suffix = index.map_or_else(|| "fallback".into(), |index| index.to_string());
        let id = format!(
            "{}:{}:{}:{}",
            self.api.instance(),
            context.generation,
            self.chain,
            suffix
        );
        let count = conditions.len().min(self.remaining);
        self.remaining -= count;
        self.overflow |= count != conditions.len();
        let conditions: Vec<_> = conditions
            .iter()
            .take(count)
            .enumerate()
            .map(|(index, expression)| {
                let (expression, truncated) = condition_expression(expression);
                self.overflow |= truncated;
                RuleCondition {
                    id: format!("{id}/condition:{index}"),
                    expression,
                    result: "skipped",
                    missing_inputs: Vec::new(),
                }
            })
            .collect();
        let expression = if index.is_none() {
            "fallback".into()
        } else if conditions.is_empty() {
            "true".into()
        } else {
            let mut expression = String::new();
            for condition in &conditions {
                if !expression.is_empty() {
                    expression.push_str(" && ");
                }
                let remaining = MAX_TEXT.saturating_sub(expression.len());
                if condition.expression.len() > remaining {
                    self.overflow = true;
                    break;
                }
                expression.push_str(&condition.expression);
            }
            expression
        };
        self.rules.push(RuleEvaluation {
            rule_id: id,
            expression,
            result: "skipped",
            missing_inputs: Vec::new(),
            conditions,
        });
    }

    pub(crate) fn condition(&mut self, index: usize, matched: bool) {
        if !self.recording_rule {
            return;
        }
        if let Some(condition) = self
            .rules
            .last_mut()
            .and_then(|rule| rule.conditions.get_mut(index))
        {
            condition.result = if matched { "matched" } else { "not_matched" };
        }
    }

    pub(crate) fn rule_result(&mut self, matched: bool) {
        if !self.recording_rule {
            return;
        }
        if let Some(rule) = self.rules.last_mut() {
            rule.result = if matched { "matched" } else { "not_matched" };
        }
    }

    pub(crate) fn finish(self, action: &'static str, outbound: Option<&str>) {
        let context = self.observer.context();
        if self.overflow {
            self.observer
                .publish(FlowEvent::Gap(GapReason::BufferOverflow));
        }
        let evaluation_id = Uuid::new_v4().to_string();
        let rule_id = self
            .rules
            .iter()
            .find(|rule| rule.result == "matched")
            .map(|rule| rule.rule_id.clone());
        let accepted = self.api.record_flow(
            context,
            StepData::Route {
                evaluation_id: evaluation_id.clone(),
                chain: self.chain,
                plane: Plane::Userspace,
                rule_id,
                rules: self.rules,
                outbound: outbound.map(bounded),
                must: None,
                mark: None,
                input: Some(self.input),
                dns_action: Some(action),
            },
        );
        if !accepted {
            self.observer
                .publish(FlowEvent::Gap(GapReason::NotInstrumented));
            return;
        }
        let _ = with_lookup(|lookup| {
            let mut data = lookup.data.lock();
            if data.route_evaluation_ids.len() < MAX_RULE_VALUES {
                data.route_evaluation_ids.push(evaluation_id);
            } else {
                drop(data);
                self.observer
                    .publish(FlowEvent::Gap(GapReason::BufferOverflow));
            }
        });
    }
}

fn with_lookup<T>(capture: impl FnOnce(&LookupState) -> T) -> Option<T> {
    let context = flow_observation::current()?.context();
    LOOKUP
        .try_with(|lookup| {
            let owner = lookup.observer.context();
            (owner.flow_id == context.flow_id && owner.lookup_id == context.lookup_id)
                .then(|| capture(lookup))
        })
        .ok()
        .flatten()
}

fn authority() -> Option<(FlowObserver, Arc<DnsRecorder>)> {
    let observer = flow_observation::current()?;
    let Some(api) = DNS_API.try_with(Weak::upgrade).ok().flatten() else {
        observer.publish(FlowEvent::Gap(GapReason::NotInstrumented));
        return None;
    };
    Some((observer, api))
}

fn condition_expression(condition: &honk_config::dns::DnsCond) -> (String, bool) {
    use std::fmt::Write;
    struct Bounded(String);
    impl std::fmt::Write for Bounded {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            if self.0.len().saturating_add(text.len()) > MAX_TEXT {
                return Err(std::fmt::Error);
            }
            self.0.push_str(text);
            Ok(())
        }
    }
    let mut output = Bounded(String::new());
    let truncated = write!(&mut output, "{condition:?}").is_err();
    (output.0, truncated)
}

/// One client query, including its actual reply operation. Persistent TCP callers
/// invoke this once per frame, never once for the entire connection.
pub(crate) async fn client_scope<F: Future>(
    raw: &[u8],
    ingress: IngressProfile,
    metadata: DnsRequestMeta,
    future: std::pin::Pin<&mut F>,
) -> F::Output {
    // Borrow the caller's pinned operation; copying its state here bloats every DNS flow.
    scope_purpose(
        "intercepted_query",
        std::pin::pin!(async {
            let Some(mut guard) = LookupGuard::start(raw, ingress, metadata) else {
                return future.await;
            };
            let result = guard.scope(future).await;
            let (status, error) = {
                let data = guard.state.data.lock();
                if data.status == "started" {
                    ("failed", Some("delivery_not_observed"))
                } else {
                    (data.status, data.error)
                }
            };
            guard.finish(status, error);
            result
        }),
    )
    .await
}

pub(crate) async fn exchange_scope<F: Future<Output = anyhow::Result<Vec<u8>>>>(
    raw: &[u8],
    upstream_name: &str,
    future: std::pin::Pin<&mut F>,
) -> anyhow::Result<Vec<u8>> {
    let Some(guard) = LookupGuard::start(raw, IngressProfile::Internal, DnsRequestMeta::EMPTY)
    else {
        return future.await;
    };
    observed_exchange(raw, guard, async {
        source("upstream", Some("bypass"));
        upstream(upstream_name);
        future.await
    })
    .await
}

pub(crate) async fn transport_exchange_scope<F: Future<Output = anyhow::Result<Vec<u8>>>>(
    raw: &[u8],
    future: std::pin::Pin<&mut F>,
) -> anyhow::Result<Vec<u8>> {
    let Some(guard) = LookupGuard::start(raw, IngressProfile::Internal, DnsRequestMeta::EMPTY)
    else {
        return future.await;
    };
    {
        let mut data = guard.state.data.lock();
        data.source = "upstream";
        data.cache = "bypass";
        with_lookup(|lookup| {
            let parent = lookup.data.lock();
            data.upstream = parent.upstream.clone();
            data.upstream_transport = parent.upstream_transport;
            data.carrier_transport = parent.carrier_transport;
        });
    }
    observed_exchange(raw, guard, future).await
}

async fn observed_exchange<F: Future<Output = anyhow::Result<Vec<u8>>>>(
    raw: &[u8],
    mut guard: LookupGuard,
    future: F,
) -> anyhow::Result<Vec<u8>> {
    let future = std::pin::pin!(future);
    let result = guard.scope(future).await;
    match &result {
        Ok(wire) => {
            // A UDP wire response may validly require fallback before final-answer admission.
            let ingress = if guard.state.data.lock().upstream_transport == Some("udp") {
                IngressProfile::Udp {
                    advertised_size: 512,
                }
            } else {
                IngressProfile::Internal
            };
            if let Some(query) = QueryContext::parse_with_profile(raw, ingress).ok()
                && crate::dns::response::ResponseTemplate::check(&query, wire).is_ok()
            {
                let ips: Vec<_> =
                    crate::dns::wire::extract_ips_with_ttl_bounded(wire, MAX_ADDRESSES + 1)
                        .into_iter()
                        .map(|(ip, _)| ip)
                        .collect();
                guard.state.data.lock().addresses = addresses(&ips, &guard.state.observer);
                guard.finish("succeeded", None);
            } else {
                guard.finish("failed", Some("invalid_response"));
            }
        }
        Err(error) => {
            let code = guard.state.data.lock().error.unwrap_or_else(|| {
                if honk_outbound::proxy::is_packet_rejection(error) {
                    "local_refusal"
                } else {
                    "upstream_failed"
                }
            });
            let was_cancelled = cancelled(error);
            guard.finish(
                if was_cancelled { "cancelled" } else { "failed" },
                Some(if was_cancelled { "cancelled" } else { code }),
            );
        }
    }
    result
}

pub(crate) fn route_upstream(
    router: &crate::routing::Router,
    input: &crate::routing::ConnectionInfo,
) -> (String, Option<String>) {
    let Some((observer, api)) = authority() else {
        return (router.route(input).to_owned(), None);
    };
    let observed = router.route_full_observed(input, None, MAX_RULE_VALUES);
    let action = observed
        .matched
        .as_ref()
        .map_or(router.fallback(), |matched| matched.action);
    let outbound = action.outbound.as_str();
    let context = observer.context();
    if observed.truncated {
        observer.publish(FlowEvent::Gap(GapReason::BufferOverflow));
    }
    let evaluation_id = Uuid::new_v4().to_string();
    let rule_id = crate::observe::rules::rule_id(
        api.instance(),
        context.generation,
        observed.matched.as_ref().map(|matched| matched.rule_id),
    );
    let rules = crate::observe::rules::observed_rule_evaluations(
        api.instance(),
        context.generation,
        router,
        &observed.rules,
    );
    let accepted = api.record_flow(
        context,
        StepData::Route {
            evaluation_id: evaluation_id.clone(),
            chain: "dns_upstream",
            plane: Plane::Userspace,
            rule_id: Some(rule_id),
            rules,
            outbound: Some(bounded(outbound)),
            must: Some(action.must),
            mark: Some(action.mark.map_or(0, honk_outbound::proxy::DirectMark::get)),
            input: Some(EvaluationInput::Traffic({
                let mut traffic = super::record::RouteInput::from(input);
                for text in [
                    &mut traffic.domain,
                    &mut traffic.pname,
                    &mut traffic.src_mac,
                ]
                .into_iter()
                .flatten()
                {
                    *text = bounded(text);
                }
                traffic
            })),
            dns_action: None,
        },
    );
    if !accepted {
        observer.publish(FlowEvent::Gap(GapReason::NotInstrumented));
        return (outbound.to_owned(), None);
    }
    let _ = with_lookup(|lookup| {
        let mut data = lookup.data.lock();
        if data.route_evaluation_ids.len() < MAX_RULE_VALUES {
            data.route_evaluation_ids.push(evaluation_id.clone());
        } else {
            drop(data);
            observer.publish(FlowEvent::Gap(GapReason::BufferOverflow));
        }
    });
    (outbound.to_owned(), Some(evaluation_id))
}

/// The group selections a DNS dial took on its way to the leaf.
pub(crate) type SelectionPath = Vec<super::record::Selection>;

pub(crate) fn selection_evaluated(
    observation: Option<&honk_outbound::group::observation::SelectionObservation>,
) -> SelectionPath {
    let Some((observer, api)) = authority() else {
        return Vec::new();
    };
    let Some(observation) = observation else {
        observer.publish(FlowEvent::Gap(GapReason::NotInstrumented));
        return Vec::new();
    };
    let Some(catalog) = CATALOG.try_with(Clone::clone).ok().flatten() else {
        observer.publish(FlowEvent::Gap(GapReason::NotInstrumented));
        return Vec::new();
    };
    let selections = map_selection_observation(observation, &catalog, &observer);
    let context = observer.context();
    if !api.record_flow(
        context,
        StepData::Connection {
            state: ConnectionState::Observed,
            reason: "selection_evaluated",
            milestone: ConnectionMilestone::Unknown,
            attempt_id: context.attempt_id.map(|id| id.to_string()),
            reply_received: None,
            error: None,
            lookup_id: context.lookup_id.map(|id| id.to_string()),
            server_addr: None,
            selections: selections.clone(),
        },
    ) {
        observer.publish(FlowEvent::Gap(GapReason::NotInstrumented));
        return Vec::new();
    }
    selections
}

pub(crate) fn selection_path(
    selections: &[super::record::Selection],
    chain: &[String],
    node: &honk_config::node::Node,
    family: honk_outbound::alive::IpVersion,
) -> SelectionPath {
    let Some(observer) = flow_observation::current() else {
        return Vec::new();
    };
    let Some(catalog) = CATALOG.try_with(Clone::clone).ok().flatten() else {
        observer.publish(FlowEvent::Gap(GapReason::NotInstrumented));
        return Vec::new();
    };
    let family = Some(super::producer::ip_family(family));
    if chain.len() > MAX_RULE_VALUES {
        observer.publish(FlowEvent::Gap(GapReason::BufferOverflow));
    }
    chain
        .iter()
        .take(MAX_RULE_VALUES)
        .enumerate()
        .filter_map(|(index, name)| {
            let group_id = catalog.groups.get(name)?;
            let (member_id, member_name) = chain
                .get(index + 1)
                .and_then(|name| {
                    catalog
                        .groups
                        .get(name)
                        .map(|id| (id.clone(), bounded(name)))
                })
                .unwrap_or_else(|| (node.id.to_string(), bounded(&node.name)));
            let Some(captured) = captured_selection(selections, group_id, family, &member_id)
            else {
                observer.publish(FlowEvent::Gap(GapReason::NotInstrumented));
                return None;
            };
            let mut captured = captured.clone();
            if captured.member_id.is_none() {
                captured.member_id = Some(member_id);
                captured.member_name = Some(member_name);
                captured.reason = "plan_candidate";
            }
            Some(captured)
        })
        .collect()
}

pub(crate) fn outbound_evidence(
    outbound: &str,
    routing_source: RoutingSource,
    evaluation_id: Option<String>,
    node: Option<&honk_config::node::Node>,
    target: SocketAddr,
    selection_path: SelectionPath,
) -> Option<super::record::OutboundAttempt> {
    let observer = flow_observation::current()?;
    Some(super::record::OutboundAttempt {
        parent_attempt_id: observer.context().attempt_id.map(|id| id.to_string()),
        kind: "leaf",
        evaluation_id,
        lookup_id: observer.context().lookup_id.map(|id| id.to_string()),
        routing_source,
        routed_outbound: Some(bounded(outbound)),
        effective_outbound: Some(bounded(outbound)),
        mode_override: "none",
        selection_path,
        leaf_node_id: Some(
            node.map_or(honk_config::config::DIRECT_NODE_ID, |node| node.id)
                .to_string(),
        ),
        leaf_node_name: Some(node.map_or_else(|| "direct".to_owned(), |node| bounded(&node.name))),
        target: Some(target.to_string()),
        target_kind: "ip",
        dial_ip: Some(target.ip()),
        server_addr: node
            .is_none_or(|node| node.protocol() == honk_config::types::NodeProtocol::Direct)
            .then_some(target),
        resolution_location: honk_outbound::runtime::flow_observation::ResolutionLocation::Unknown,
    })
}

struct OutboundGuard {
    observer: FlowObserver,
    api: Arc<DnsRecorder>,
    attempt_id: Uuid,
    attempt: super::record::OutboundAttempt,
    finished: bool,
}

impl OutboundGuard {
    fn start(attempt: &super::record::OutboundAttempt) -> Option<Self> {
        let (observer, api) = authority()?;
        let attempt_id = Uuid::new_v4();
        let mut context = observer.context();
        context.attempt_id = Some(attempt_id);
        let guard = Self {
            observer: observer.with_context(context),
            api,
            attempt_id,
            attempt: attempt.clone(),
            finished: false,
        };
        if !guard.publish(TransportStatus::Started, None) {
            return None;
        }
        Some(guard)
    }
    fn publish(&self, status: TransportStatus, error: Option<super::record::FlowError>) -> bool {
        self.api.record_flow(
            self.observer.context(),
            StepData::Outbound {
                attempt_id: self.attempt_id.to_string(),
                attempt: self.attempt.clone(),
                status,
                error,
            },
        )
    }
    fn finish(&mut self, status: TransportStatus, error: Option<super::record::FlowError>) {
        if !self.finished {
            self.finished = true;
            self.publish(status, error);
        }
    }
}
impl Drop for OutboundGuard {
    fn drop(&mut self) {
        self.finish(
            TransportStatus::Cancelled,
            Some(super::record::FlowError::Cancelled),
        );
    }
}

pub(crate) async fn outbound_scope<T, F: Future<Output = anyhow::Result<T>>>(
    attempt: Option<&super::record::OutboundAttempt>,
    future: std::pin::Pin<&mut F>,
) -> anyhow::Result<T> {
    let Some(mut guard) = attempt.and_then(OutboundGuard::start) else {
        return future.await;
    };
    let result = guard.observer.scope(future).await;
    let was_cancelled = result.as_ref().err().is_some_and(cancelled);
    guard.finish(
        if result.is_ok() {
            TransportStatus::Succeeded
        } else if was_cancelled {
            TransportStatus::Cancelled
        } else {
            TransportStatus::Failed
        },
        result.as_ref().err().map(|error| {
            if was_cancelled {
                super::record::FlowError::Cancelled
            } else if honk_outbound::proxy::is_packet_rejection(error) {
                super::record::FlowError::LocalRefusal
            } else {
                super::record::FlowError::DialFailed
            }
        }),
    );
    result
}

fn cancelled(error: &anyhow::Error) -> bool {
    honk_outbound::proxy::packet_rejection(error)
        == Some(honk_outbound::proxy::PacketRejection::Cancelled)
}

#[cfg(test)]
mod tests;
