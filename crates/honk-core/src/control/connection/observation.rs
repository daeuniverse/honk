use std::{net::SocketAddr, sync::Arc};

use honk_config::{
    Config,
    node::Node,
    types::{DialMode, NodeProtocol},
};
use honk_outbound::{
    alive::IpVersion,
    runtime::flow_observation::{FlowObserver, GapReason, ResolutionLocation, TransportStatus},
};

use super::{handoff::HandoffResult, routing::RoutingDecision};
use crate::{
    observe::{
        Observation,
        catalog::CatalogIdentity,
        flows::{
            FlowGuard,
            record::{
                EvaluationInput, FlowError, Input, InputValues, OutboundAttempt, RouteInput,
                Selection, StepData,
            },
        },
        rules::{RuleEvaluation, rule_id},
        vocab::{
            ConnectionMilestone, ConnectionState, DomainSource, Network, Plane, RoutingSource,
        },
    },
    routing::{ConnectionInfo, RouteMatch, Router},
};

#[derive(Debug, Clone)]
pub(super) struct RouteObservation {
    generation: Option<u64>,
    rule_id: Option<String>,
    rule_expression: Option<String>,
    evaluation_id: String,
    plane: Plane,
    input: Option<RouteInput>,
    rules: Vec<RuleEvaluation>,
    truncated: bool,
}

impl RouteObservation {
    pub(super) fn kernel() -> Self {
        Self {
            generation: None,
            rule_id: None,
            rule_expression: None,
            evaluation_id: String::new(),
            plane: Plane::Kernel,
            input: None,
            rules: Vec::new(),
            truncated: false,
        }
    }

    pub(super) fn userspace(
        instance: &str,
        generation: u64,
        input: &ConnectionInfo,
        router: &Router,
        matched: Option<&RouteMatch<'_>>,
        rules: Vec<RuleEvaluation>,
        truncated: bool,
    ) -> Self {
        Self {
            generation: Some(generation),
            rule_id: Some(rule_id(
                instance,
                generation,
                matched.map(|route| route.rule_id),
            )),
            rule_expression: Some(match matched {
                Some(route) => router
                    .compiled_routes()
                    .iter()
                    .find(|compiled| compiled.id == route.rule_id)
                    .map(|compiled| compiled.expression.clone())
                    .expect("matched compiled rule"),
                None => "fallback".to_owned(),
            }),
            evaluation_id: uuid::Uuid::new_v4().to_string(),
            plane: Plane::Userspace,
            input: Some(RouteInput::from(input)),
            rules,
            truncated,
        }
    }
}

#[derive(Clone, Default)]
pub(in crate::control) struct ConnectionObservation {
    recorded: Option<RecordedConnection>,
}

#[derive(Clone)]
struct RecordedConnection {
    flow: Arc<FlowGuard>,
    network: Network,
    source: SocketAddr,
    destination: SocketAddr,
    kernel_evaluation: Option<String>,
    kernel_route: Option<RouteObservation>,
    evaluation: Option<String>,
    route: Option<RouteObservation>,
    routed_outbound: Option<String>,
    effective_outbound: Option<String>,
    dial_mode_generation: Option<u64>,
    selection: Option<SelectionGeneration>,
}

#[derive(Clone)]
struct SelectionGeneration {
    generation: u64,
    catalog: Arc<CatalogIdentity>,
    config: Arc<Config>,
    decisions: Arc<[Selection]>,
    health_family: Option<&'static str>,
}

impl ConnectionObservation {
    pub(in crate::control) fn begin(
        native: Option<&Observation>,
        network: Network,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Self {
        Self {
            recorded: native
                .and_then(|native| native.flows.begin(network, source, destination))
                .map(|flow| RecordedConnection {
                    flow: Arc::new(flow),
                    network,
                    source,
                    destination,
                    kernel_evaluation: None,
                    kernel_route: None,
                    evaluation: None,
                    route: None,
                    routed_outbound: None,
                    effective_outbound: None,
                    dial_mode_generation: None,
                    selection: None,
                }),
        }
    }

    pub(super) fn is_recording(&self) -> bool {
        self.recorded.is_some()
    }

    pub(in crate::control) fn flow(&self) -> Option<&Arc<FlowGuard>> {
        self.recorded.as_ref().map(|record| &record.flow)
    }

    /// Reads `generation` only for a recorded connection.
    pub(in crate::control) fn observer(
        &self,
        generation: impl FnOnce() -> u64,
        purpose: &'static str,
    ) -> Option<FlowObserver> {
        self.flow()?.observer(generation(), None, purpose)
    }

    pub(super) fn routing_started(&self) {
        if let Some(flow) = self.flow() {
            flow.transition(
                ConnectionState::Routing,
                "routing_started",
                ConnectionMilestone::Unknown,
                None,
            );
        }
    }

    pub(super) fn selection_observed(
        &mut self,
        observation: Option<&Arc<honk_outbound::group::observation::SelectionObservation>>,
        family: IpVersion,
    ) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        let Some(selection) = &mut record.selection else {
            record.flow.mark_gap(GapReason::NotInstrumented);
            return;
        };
        selection.health_family = Some(crate::observe::flows::producer::ip_family(family));
        let Some(observation) = observation else {
            return;
        };
        let Some(observer) = record
            .flow
            .observer(selection.generation, None, "dial_target")
        else {
            return;
        };
        let decisions = crate::observe::flows::producer::map_selection_observation(
            observation,
            &selection.catalog,
            &observer,
        );
        record
            .flow
            .observe_selection(selection.generation, decisions.clone());
        selection.decisions = decisions.into();
    }

    pub(super) fn take_flow(&mut self) -> Option<Arc<FlowGuard>> {
        self.recorded.take().map(|record| record.flow)
    }

    pub(super) fn shared(&self) -> Option<Arc<Self>> {
        self.is_recording().then(|| Arc::new(self.clone()))
    }

    pub(super) fn handoff(&mut self, handoff: Option<&HandoffResult>, expected: bool) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        let Some(handoff) = handoff else {
            if expected {
                record.flow.mark_gap(GapReason::NotInstrumented);
            }
            return;
        };
        if handoff.capture_gap == Some("kernel_handoff_ambiguous") {
            record.flow.mark_gap(GapReason::NotInstrumented);
            return;
        }
        if record.network == Network::Tcp {
            update_input(&record.flow, None, None, Some(handoff));
        }
        record.flow.step(
            None,
            StepData::Input {
                source: "kernel",
                values: InputValues {
                    input: Input {
                        src: record.source,
                        dst: record.destination,
                        domain: None,
                        domain_source: None,
                        pid: (handoff.pid != 0).then_some(handoff.pid),
                        process_path: (),
                        src_mac: handoff.mac_address(),
                        ingress: (),
                        domain_rule_ids: (),
                        dscp: (record.network == Network::Udp || handoff.dscp <= 63)
                            .then_some(handoff.dscp),
                        mark: Some(handoff.mark),
                    },
                    pname: handoff.process_name(),
                },
            },
        );
        if let Some(capture) = &handoff.capture {
            Self::record_kernel(record, capture.clone());
        } else {
            // Capture diagnostics stay specific; the record keeps only the missing flag.
            record.flow.mark_gap(GapReason::NotInstrumented);
        }
    }

    pub(in crate::control) fn packet_route(
        &mut self,
        capture: Result<crate::observe::flows::kernel::CapturedKernelRoute, &'static str>,
    ) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        match capture {
            Ok(capture) => Self::record_kernel(record, capture),
            Err(_) => record.flow.mark_gap(GapReason::NotInstrumented),
        }
    }

    fn record_kernel(
        record: &mut RecordedConnection,
        capture: crate::observe::flows::kernel::CapturedKernelRoute,
    ) {
        if capture.truncated {
            record.flow.mark_overflow();
        }
        if capture.ambiguous {
            record.flow.mark_gap(GapReason::StartedLate);
        }
        if capture.gap.is_some() {
            record.flow.mark_gap(GapReason::NotInstrumented);
        }
        let rule_expression = capture.rule_id.as_ref().and_then(|id| {
            capture
                .rules
                .iter()
                .find(|rule| &rule.rule_id == id)
                .map(|rule| rule.expression.clone())
        });
        record.kernel_evaluation = Some(capture.evaluation_id.clone());
        record.kernel_route = Some(RouteObservation {
            generation: Some(capture.generation),
            rule_id: capture.rule_id.clone(),
            rule_expression,
            evaluation_id: capture.evaluation_id.clone(),
            plane: Plane::Kernel,
            input: None,
            rules: Vec::new(),
            truncated: false,
        });
        let mut input = capture.input;
        input.domain_fact_bitmap = Some(capture.domain_bitmap);
        input.domain_fact_state = Some(capture.fact_state);
        record.route = record.kernel_route.clone();
        record.evaluation = record.kernel_evaluation.clone();
        record.routed_outbound = capture
            .effective_outbound
            .clone()
            .or_else(|| capture.outbound.clone());
        record.flow.step(
            Some(capture.generation),
            StepData::Route {
                evaluation_id: capture.evaluation_id,
                chain: "traffic",
                plane: Plane::Kernel,
                rule_id: capture.rule_id,
                rules: capture.rules,
                outbound: capture.outbound,
                must: Some(capture.must),
                mark: Some(capture.mark),
                input: Some(EvaluationInput::Traffic(input)),
                dns_action: None,
            },
        );
    }

    pub(super) fn tcp_sniffed(
        &self,
        sniff: &crate::sniffing::SniffResult,
        handoff: Option<&HandoffResult>,
    ) {
        self.sniffed(sniff.domain.as_deref(), tcp_domain_source(sniff), handoff);
    }

    pub(super) fn udp_sniffed(&self, domain: Option<&str>, handoff: Option<&HandoffResult>) {
        self.sniffed(domain, domain.map(|_| DomainSource::QuicSni), handoff);
    }

    fn sniffed(
        &self,
        domain: Option<&str>,
        source: Option<DomainSource>,
        handoff: Option<&HandoffResult>,
    ) {
        if let Some(flow) = self.flow() {
            update_input(flow, domain, source, handoff);
        }
    }

    pub(super) fn routed(&mut self, decision: &mut RoutingDecision) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        let mut route = decision.native_route.take();
        if route
            .as_ref()
            .is_some_and(|route| route.plane == Plane::Kernel)
        {
            route = record.kernel_route.clone().or(route);
        }
        record.routed_outbound = Some(decision.outbound.clone());
        record.evaluation = route
            .as_ref()
            .filter(|route| route.plane == Plane::Userspace)
            .map(|route| route.evaluation_id.clone())
            .or_else(|| record.kernel_evaluation.clone());
        if let Some(capture) = &mut route
            && capture.plane == Plane::Userspace
        {
            if capture.truncated {
                record.flow.mark_overflow();
            }
            record.flow.step(
                capture.generation,
                StepData::Route {
                    evaluation_id: capture.evaluation_id.clone(),
                    chain: "traffic",
                    plane: capture.plane,
                    rule_id: capture.rule_id.clone(),
                    rules: std::mem::take(&mut capture.rules),
                    outbound: Some(decision.outbound.clone()),
                    must: Some(decision.must),
                    mark: Some(
                        decision
                            .mark
                            .map_or(0, honk_outbound::proxy::DirectMark::get),
                    ),
                    input: capture.input.take().map(EvaluationInput::Traffic),
                    dns_action: None,
                },
            );
        }
        let performed = decision.reroute_by_sniffed_domain;
        record.flow.step(
            route.as_ref().and_then(|route| route.generation),
            StepData::Reroute {
                performed,
                reason: if record.network == Network::Udp {
                    "sniff_routing_decision"
                } else if performed {
                    "sniffed_domain"
                } else {
                    "not_required"
                },
                from_evaluation_id: record.kernel_evaluation.clone(),
                to_evaluation_id: (record.network == Network::Tcp || performed)
                    .then(|| record.evaluation.clone())
                    .flatten(),
            },
        );
        record.route = route;
    }

    pub(super) fn mode_applied(&mut self, outbound: &str) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        record.effective_outbound = Some(outbound.to_owned());
        let rule = record.route.as_ref();
        record.flow.routed(
            outbound,
            rule.and_then(|route| route.rule_id.as_deref()),
            rule.and_then(|route| route.rule_expression.as_deref()),
            if rule.is_some_and(|route| route.plane == Plane::Kernel) {
                RoutingSource::Kernel
            } else if rule.is_some_and(|route| route.rule_id.is_some()) {
                RoutingSource::Evaluation
            } else if record.routed_outbound.is_none() {
                RoutingSource::Forced
            } else {
                RoutingSource::Unknown
            },
        );
    }

    pub(super) fn pin_dial_mode(&mut self, generation: Option<u64>) {
        if let Some(record) = &mut self.recorded {
            record.dial_mode_generation = generation;
        }
    }

    pub(super) fn pin_selection(
        &mut self,
        generation: u64,
        catalog: &Arc<CatalogIdentity>,
        config: &Arc<Config>,
    ) {
        if let Some(record) = &mut self.recorded {
            record.selection = Some(SelectionGeneration {
                generation,
                catalog: Arc::clone(catalog),
                config: Arc::clone(config),
                decisions: Arc::from([]),
                health_family: None,
            });
        }
    }

    pub(super) fn release_selection(&mut self) {
        if let Some(record) = &mut self.recorded {
            record.selection = None;
        }
    }

    pub(super) fn tcp_dial_mode(
        &self,
        configured: DialMode,
        sniff: &crate::sniffing::SniffResult,
        verification: &'static str,
        candidates: &[Node],
        domain: Option<&str>,
    ) {
        let Some(record) = &self.recorded else { return };
        let Some(first) = candidates.first() else {
            record.flow.step(
                record.dial_mode_generation,
                StepData::DialMode {
                    configured,
                    effective_target: "none",
                    domain: sniff.domain.clone(),
                    domain_source: tcp_domain_source(sniff),
                    verification,
                    reason: "no_eligible_candidates",
                },
            );
            return;
        };
        let target = target_kind(first, domain);
        let target = if candidates
            .iter()
            .all(|node| target_kind(node, domain) == target)
        {
            target
        } else {
            "unknown"
        };
        record.flow.step(
            record.dial_mode_generation,
            StepData::DialMode {
                configured,
                effective_target: target,
                domain: sniff.domain.clone(),
                domain_source: tcp_domain_source(sniff),
                verification,
                reason: match target {
                    "none" => "policy_block",
                    "domain" => "sniffed_domain",
                    "ip" => "original_destination",
                    _ => "candidate_dependent",
                },
            },
        );
    }

    pub(super) fn udp_dial_mode(
        &self,
        configured: DialMode,
        domain: Option<&str>,
        verification: &'static str,
        selected: Option<(&Node, Option<&str>)>,
    ) {
        let Some(record) = &self.recorded else { return };
        let (generation, target, reason) = match selected {
            Some((node, target)) => (
                record
                    .selection
                    .as_ref()
                    .map(|selection| selection.generation),
                target_kind(node, target),
                "leaf_target_selected",
            ),
            None => (
                record.route.as_ref().and_then(|route| route.generation),
                match record.effective_outbound.as_deref() {
                    Some("block") => "none",
                    Some("direct") => "ip",
                    _ => "unknown",
                },
                "dial_mode_applied",
            ),
        };
        record.flow.step(
            generation,
            StepData::DialMode {
                configured,
                effective_target: target,
                domain: domain.map(str::to_owned),
                domain_source: domain.map(|_| DomainSource::QuicSni),
                verification,
                reason,
            },
        );
    }

    pub(super) fn selected(&self, chain: &[String], node: &Node) {
        let Some(record) = &self.recorded else { return };
        if matches!(node.protocol(), NodeProtocol::Direct | NodeProtocol::Block) {
            record.flow.selected(Vec::new());
            return;
        }
        let Some(selection) = &record.selection else {
            return;
        };
        let count = chain
            .len()
            .saturating_sub(usize::from(chain.last() == Some(&node.name)));
        let groups: Option<Vec<_>> = chain
            .iter()
            .take(count)
            .map(|name| selection.catalog.groups.get(name).cloned())
            .collect();
        if let Some(mut chain) = groups {
            chain.push(node.id.to_string());
            record.flow.selected(chain);
        }
    }

    pub(super) fn attempt(
        &self,
        chain: &[String],
        node: &Node,
        domain: Option<&str>,
    ) -> Option<ConnectionAttempt> {
        let record = self.recorded.as_ref()?;
        let selection = record
            .selection
            .as_ref()
            .expect("captured selection generation");
        let target_kind = target_kind(node, domain);
        let data = OutboundAttempt {
            parent_attempt_id: None,
            lookup_id: None,
            kind: "leaf",
            evaluation_id: record.evaluation.clone(),
            routing_source: if record.evaluation.is_some() {
                RoutingSource::Evaluation
            } else if record.routed_outbound.is_none() {
                RoutingSource::Forced
            } else {
                RoutingSource::Unknown
            },
            routed_outbound: record.routed_outbound.clone(),
            effective_outbound: record.effective_outbound.clone(),
            mode_override: if record.routed_outbound == record.effective_outbound {
                "none"
            } else if record.effective_outbound.as_deref() == Some("direct") {
                "direct"
            } else {
                "global"
            },
            selection_path: selection_path(selection, chain, node),
            leaf_node_id: Some(node.id.to_string()),
            leaf_node_name: Some(node.name.clone()),
            target: match target_kind {
                "none" => None,
                "domain" => domain.map(|domain| format!("{domain}:{}", record.destination.port())),
                _ => Some(record.destination.to_string()),
            },
            target_kind,
            dial_ip: (record.network == Network::Udp && node.protocol() == NodeProtocol::Direct)
                .then(|| record.destination.ip()),
            server_addr: None,
            resolution_location: if target_kind == "none" {
                ResolutionLocation::NotApplicable
            } else if node.protocol() == NodeProtocol::Direct
                || (record.network == Network::Tcp && target_kind == "ip")
            {
                ResolutionLocation::OriginalIp
            } else {
                ResolutionLocation::Unknown
            },
        };
        Some(ConnectionAttempt::new(
            Arc::clone(&record.flow),
            selection.generation,
            data,
            if node.protocol() == NodeProtocol::Direct {
                "dial_target"
            } else {
                "proxy_server"
            },
        ))
    }

    pub(in crate::control) fn finish(&self, state: ConnectionState, reason: &'static str) {
        if let Some(flow) = self.flow() {
            flow.finish(state, reason);
        }
    }

    pub(super) fn tcp_connected(&self, chain: &[String], node: &Node) {
        self.selected(chain, node);
        if let Some(flow) = self.flow() {
            flow.transition(
                ConnectionState::Active,
                "dial_succeeded",
                ConnectionMilestone::TransportReady,
                None,
            );
        }
    }

    pub(super) fn tcp_deadline(&self) {
        let Some(record) = &self.recorded else { return };
        let generation = record
            .selection
            .as_ref()
            .map(|selection| selection.generation)
            .or(record.dial_mode_generation);
        record.flow.step(
            generation,
            StepData::Connection {
                state: ConnectionState::Dialing,
                reason: "dial_deadline_exceeded",
                milestone: ConnectionMilestone::Unknown,
                attempt_id: None,
                reply_received: None,
                error: Some(FlowError::DialTimeout),
                selections: Vec::new(),
                lookup_id: None,
                server_addr: None,
            },
        );
    }

    pub(super) fn first_response(
        &self,
        previous: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Option<Arc<dyn Fn() + Send + Sync>> {
        let Some(flow) = self.flow() else {
            return previous;
        };
        let flow = Arc::clone(flow);
        Some(Arc::new(move || {
            if let Some(callback) = &previous {
                callback();
            }
            if flow.first_reply() {
                flow.transition(
                    ConnectionState::Active,
                    "response_received",
                    ConnectionMilestone::FirstReply,
                    Some(true),
                );
            }
        }))
    }

    pub(super) fn udp_preparing(&self) {
        if let Some(flow) = self.flow() {
            flow.transition(
                ConnectionState::Dialing,
                "udp_prepare_started",
                ConnectionMilestone::Unknown,
                Some(false),
            );
        }
    }
}

fn update_input(
    flow: &FlowGuard,
    domain: Option<&str>,
    source: Option<DomainSource>,
    handoff: Option<&HandoffResult>,
) {
    flow.update_input(
        domain,
        source,
        handoff
            .and_then(|handoff| handoff.process_name())
            .as_deref(),
        handoff.and_then(|handoff| (handoff.pid != 0).then_some(handoff.pid)),
        handoff.and_then(|handoff| handoff.mac_address()),
        handoff.map(|handoff| handoff.dscp),
        handoff.map(|handoff| handoff.mark),
    );
}

fn tcp_domain_source(sniff: &crate::sniffing::SniffResult) -> Option<DomainSource> {
    match &sniff.traffic_type {
        crate::sniffing::TrafficType::Tls => Some(DomainSource::TlsSni),
        crate::sniffing::TrafficType::Http => Some(DomainSource::HttpHost),
        _ => None,
    }
}

fn target_kind(node: &Node, domain: Option<&str>) -> &'static str {
    match node.protocol() {
        NodeProtocol::Block => "none",
        NodeProtocol::Direct => "ip",
        _ if domain.is_some() => "domain",
        _ => "ip",
    }
}

pub(super) struct ConnectionAttempt {
    flow: Arc<FlowGuard>,
    generation: u64,
    attempt_id: uuid::Uuid,
    data: Option<OutboundAttempt>,
    dns_purpose: &'static str,
}

impl ConnectionAttempt {
    fn new(
        flow: Arc<FlowGuard>,
        generation: u64,
        data: OutboundAttempt,
        dns_purpose: &'static str,
    ) -> Self {
        let attempt_id = uuid::Uuid::new_v4();
        flow.step(
            Some(generation),
            StepData::Outbound {
                attempt_id: attempt_id.to_string(),
                attempt: data.clone(),
                status: TransportStatus::Started,
                error: None,
            },
        );
        Self {
            flow,
            generation,
            attempt_id,
            data: Some(data),
            dns_purpose,
        }
    }

    pub(super) fn finish(&mut self, status: TransportStatus, error: Option<FlowError>) {
        let Some(attempt) = self.data.take() else {
            return;
        };
        self.flow.step(
            Some(self.generation),
            StepData::Outbound {
                attempt_id: self.attempt_id.to_string(),
                attempt,
                status,
                error,
            },
        );
    }

    pub(super) fn id(&self) -> uuid::Uuid {
        self.attempt_id
    }

    pub(super) fn observer(&self) -> Option<FlowObserver> {
        self.flow
            .observer(self.generation, Some(self.attempt_id), self.dns_purpose)
    }

    pub(super) fn udp_prepared(&self) {
        self.flow.step(
            Some(self.generation),
            StepData::Connection {
                state: ConnectionState::Dialing,
                reason: "udp_prepared",
                milestone: ConnectionMilestone::Unknown,
                attempt_id: Some(self.attempt_id.to_string()),
                reply_received: None,
                error: None,
                selections: Vec::new(),
                lookup_id: None,
                server_addr: None,
            },
        );
    }

    pub(super) fn tcp_finished(&mut self, error: Option<&anyhow::Error>, node: &Node) {
        let Some(error) = error else {
            self.finish(TransportStatus::Succeeded, None);
            return;
        };
        let code = if node.protocol() == NodeProtocol::Block {
            FlowError::PolicyBlock
        } else if honk_outbound::proxy::is_packet_rejection(error) {
            FlowError::LocalRefusal
        } else if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        {
            FlowError::DialTimeout
        } else {
            FlowError::DialFailed
        };
        self.finish(TransportStatus::Failed, Some(code));
    }

    pub(super) fn udp_finished(&mut self, succeeded: bool) {
        if succeeded {
            self.finish(TransportStatus::Succeeded, None);
        } else {
            self.finish(TransportStatus::Failed, Some(FlowError::UdpPrepareFailed));
        }
    }
}

impl Drop for ConnectionAttempt {
    fn drop(&mut self) {
        self.finish(TransportStatus::Cancelled, Some(FlowError::Cancelled));
    }
}

fn selection_path(
    selection: &SelectionGeneration,
    chain: &[String],
    node: &Node,
) -> Vec<Selection> {
    let catalog = &selection.catalog;
    chain
        .iter()
        .enumerate()
        .filter_map(|(index, name)| {
            let group_id = catalog.groups.get(name)?;
            let next = chain
                .get(index + 1)
                .and_then(|name| {
                    catalog
                        .groups
                        .get(name)
                        .map(|id| (id.clone(), name.clone()))
                })
                .unwrap_or_else(|| (node.id.to_string(), node.name.clone()));
            if let Some(captured) = crate::observe::flows::producer::captured_selection(
                &selection.decisions,
                group_id,
                selection.health_family,
                &next.0,
            ) {
                let mut captured = captured.clone();
                captured.member_id = Some(next.0);
                captured.member_name = Some(next.1);
                return Some(captured);
            }
            let group = selection
                .config
                .groups
                .iter()
                .rev()
                .find(|group| &group.name == name)?;
            let policy = group.policy.as_str();
            Some(Selection {
                group_id: group_id.clone(),
                member_id: Some(next.0),
                member_name: Some(next.1),
                policy,
                reason: "captured_plan",
                selection: None,
                health_family: selection.health_family,
                applied: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_connection_begin_has_no_recorded_guard() {
        let native = crate::native_api::observation::NativeObservation::new(&Config::default());
        let observation = ConnectionObservation::begin(
            Some(&native.core),
            Network::Tcp,
            "127.0.0.1:31000".parse().unwrap(),
            "127.0.0.2:443".parse().unwrap(),
        );
        assert!(!observation.is_recording());
        assert!(observation.flow().is_none());
    }
}
