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
use crate::control::netstack::ProcessMeta;
use crate::{
    observe::{
        Observation,
        catalog::CatalogIdentity,
        flows::{
            FlowGuard,
            kernel::CapturedKernelRoute,
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

#[derive(Debug)]
pub(in crate::control) struct PacketRouteSlot {
    pub(super) capture: Option<Box<CapturedKernelRoute>>,
    pub(super) capture_gap: Option<&'static str>,
}

const _: () = assert!(size_of::<PacketRouteSlot>() <= 3 * size_of::<usize>());

impl PacketRouteSlot {
    pub(in crate::control) const ABSENT: Self = Self {
        capture: None,
        capture_gap: None,
    };

    pub(super) const fn failed(reason: &'static str) -> Self {
        Self {
            capture: None,
            capture_gap: Some(reason),
        }
    }

    pub(in crate::control) fn from_capture(
        capture: Result<CapturedKernelRoute, &'static str>,
    ) -> Self {
        match capture {
            Ok(mut route) => Self {
                capture_gap: route.gap.take(),
                capture: Some(Box::new(route)),
            },
            Err(reason) => Self::failed(reason),
        }
    }
}

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
    fn retained_bytes(&self) -> usize {
        self.rule_id.as_ref().map_or(0, String::capacity)
            + self.rule_expression.as_ref().map_or(0, String::capacity)
            + self.evaluation_id.capacity()
            + self.input.as_ref().map_or(0, RouteInput::heap_bytes)
            + self.rules.capacity() * size_of::<RuleEvaluation>()
            + self
                .rules
                .iter()
                .map(RuleEvaluation::heap_bytes)
                .sum::<usize>()
    }
}

#[derive(Debug, Default)]
pub(super) struct RouteTraceSlot(Option<Box<RouteObservation>>);

const _: () = assert!(size_of::<RouteTraceSlot>() == size_of::<usize>());

impl RouteTraceSlot {
    pub(super) fn kernel(enabled: bool) -> Self {
        Self(enabled.then(|| {
            Box::new(RouteObservation {
                generation: None,
                rule_id: None,
                rule_expression: None,
                evaluation_id: String::new(),
                plane: Plane::Kernel,
                input: None,
                rules: Vec::new(),
                truncated: false,
            })
        }))
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
        Self(Some(Box::new(RouteObservation {
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
        })))
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub(super) fn retained_bytes(&self) -> usize {
        self.0.as_ref().map_or(0, |route| {
            size_of::<RouteObservation>() + route.retained_bytes()
        })
    }

    // The connection keeps the payload inline, releasing the snapshot's box.
    fn take(&mut self) -> Option<RouteObservation> {
        self.0.take().map(|route| *route)
    }
}

#[derive(Default)]
pub(in crate::control) struct ConnectionObservation {
    recorded: Option<Box<RecordedConnection>>,
}

const _: () = assert!(size_of::<ConnectionObservation>() == size_of::<usize>());

pub(super) struct RecordedConnection {
    facts: ConnectionFacts,
    _memory: Option<honk_netstack::MemoryReservation>,
}

#[derive(Clone)]
struct ConnectionFacts {
    flow: Arc<FlowGuard>,
    network: Network,
    source: SocketAddr,
    destination: SocketAddr,
    packet_facts: Option<(ProcessMeta, u8, Option<u32>)>,
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
        Self::begin_in(native, network, source, destination, None).expect("unaccounted observation")
    }

    pub(in crate::control) fn begin_in(
        native: Option<&Observation>,
        network: Network,
        source: SocketAddr,
        destination: SocketAddr,
        budget: Option<&Arc<honk_netstack::MemoryBudget>>,
    ) -> std::io::Result<Self> {
        let Some(flow) = native.and_then(|native| native.flows.begin(network, source, destination))
        else {
            return Ok(Self::default());
        };
        let memory = reserve_record(budget, size_of::<RecordedConnection>()).inspect_err(|_| {
            flow.finish(ConnectionState::Failed, "packet_memory_capacity");
        })?;
        Ok(Self {
            recorded: Some(Box::new(RecordedConnection {
                facts: ConnectionFacts {
                    flow: Arc::new(flow),
                    network,
                    source,
                    destination,
                    packet_facts: None,
                    kernel_evaluation: None,
                    kernel_route: None,
                    evaluation: None,
                    route: None,
                    routed_outbound: None,
                    effective_outbound: None,
                    dial_mode_generation: None,
                    selection: None,
                },
                _memory: memory,
            })),
        })
    }

    fn record(&self) -> Option<&ConnectionFacts> {
        self.recorded.as_ref().map(|record| &record.facts)
    }

    fn record_mut(&mut self) -> Option<&mut ConnectionFacts> {
        self.recorded.as_mut().map(|record| &mut record.facts)
    }

    pub(in crate::control) fn is_recording(&self) -> bool {
        self.recorded.is_some()
    }

    pub(in crate::control) fn flow(&self) -> Option<&Arc<FlowGuard>> {
        self.record().map(|record| &record.flow)
    }

    /// Reads `generation` only for a recorded connection.
    pub(in crate::control) fn observer(
        &self,
        generation: impl FnOnce() -> u64,
        purpose: &'static str,
    ) -> Option<FlowObserver> {
        self.flow()?.observer(generation(), None, purpose)
    }

    pub(super) fn selection_observer(&self) -> Option<FlowObserver> {
        let generation = self.record()?.selection.as_ref()?.generation;
        self.observer(|| generation, "dial_target")
    }

    pub(super) fn observe_tcp_plan(
        &mut self,
        observer: Option<&FlowObserver>,
        build: impl FnOnce() -> crate::control::reload::ResolvedScorePlan,
    ) -> crate::control::reload::ResolvedScorePlan {
        let plan = match observer {
            Some(observer) => observer.sync_scope(build),
            None => build(),
        };
        self.selection_observed(plan.observation.as_ref(), plan.health_family);
        plan
    }

    pub(in crate::control) fn routing_started(&self) {
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
        let Some(record) = self.record_mut() else {
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
        self.recorded.take().map(|record| record.facts.flow)
    }

    pub(super) fn shared(
        &self,
        budget: Option<&Arc<honk_netstack::MemoryBudget>>,
    ) -> std::io::Result<Option<Arc<RecordedConnection>>> {
        self.record()
            .map(|facts| {
                let bytes = size_of::<RecordedConnection>() + 2 * size_of::<usize>();
                let memory = reserve_record(budget, bytes)?;
                Ok(Arc::new(RecordedConnection {
                    facts: facts.clone(),
                    _memory: memory,
                }))
            })
            .transpose()
    }

    pub(in crate::control) fn packet_facts(
        &mut self,
        process: ProcessMeta,
        dscp: u8,
        mark: Option<u32>,
    ) {
        let Some(record) = self.record_mut() else {
            return;
        };
        record.packet_facts = Some((process, dscp, mark));
        let pname = process.name();
        let pid = (process.pid != 0).then_some(process.pid);
        record
            .flow
            .update_input(None, None, pname.as_deref(), pid, None, Some(dscp), mark);
        record.flow.step(
            None,
            StepData::Input {
                source: "packet",
                values: InputValues {
                    input: Input {
                        src: record.source,
                        dst: record.destination,
                        domain: None,
                        domain_source: None,
                        pid,
                        process_path: (),
                        src_mac: None,
                        ingress: (),
                        domain_rule_ids: (),
                        dscp: Some(dscp),
                        mark,
                    },
                    pname,
                },
            },
        );
    }

    pub(super) fn handoff(&mut self, handoff: Option<&mut HandoffResult>, expected: bool) {
        let Some(record) = self.record_mut() else {
            return;
        };
        let Some(handoff) = handoff else {
            if expected {
                record.flow.mark_gap(GapReason::NotInstrumented);
            }
            return;
        };
        if handoff.packet_route.capture_gap == Some("kernel_handoff_ambiguous") {
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
                        src_mac: handoff.mac_address().map(crate::routing::mac_string),
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
        if let Some(capture) = handoff.packet_route.capture.take() {
            Self::record_kernel(record, *capture, handoff.packet_route.capture_gap);
        } else {
            // Capture diagnostics stay specific; the record keeps only the missing flag.
            record.flow.mark_gap(GapReason::NotInstrumented);
        }
    }

    pub(in crate::control) fn packet_route(&mut self, slot: PacketRouteSlot) {
        let Some(record) = self.record_mut() else {
            return;
        };
        if let Some(capture) = slot.capture {
            Self::record_kernel(record, *capture, slot.capture_gap);
        } else if slot.capture_gap.is_some() {
            record.flow.mark_gap(GapReason::NotInstrumented);
        }
    }

    fn record_kernel(
        record: &mut ConnectionFacts,
        capture: CapturedKernelRoute,
        gap: Option<&'static str>,
    ) {
        if capture.truncated {
            record.flow.mark_overflow();
        }
        if capture.ambiguous {
            record.flow.mark_gap(GapReason::StartedLate);
        }
        if gap.is_some() {
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
                mark_kind: Some(capture.mark_kind),
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
        if let Some(record) = self.record() {
            if let Some((process, dscp, mark)) = record.packet_facts {
                let pname = process.name();
                let pid = (process.pid != 0).then_some(process.pid);
                record.flow.update_input(
                    domain,
                    source,
                    pname.as_deref(),
                    pid,
                    None,
                    Some(dscp),
                    mark,
                );
            } else {
                update_input(&record.flow, domain, source, handoff);
            }
        }
    }

    pub(in crate::control) fn routed(&mut self, decision: &mut RoutingDecision) {
        let Some(record) = self.record_mut() else {
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
                    mark_kind: Some(if decision.mark.is_some() {
                        honk_ebpf_common::ROUTING_MARK_SET
                    } else {
                        honk_ebpf_common::ROUTING_MARK_KEEP
                    }),
                    mark: Some(decision.mark.unwrap_or(0)),
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
        let Some(record) = self.record_mut() else {
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
        if let Some(record) = self.record_mut() {
            record.dial_mode_generation = generation;
        }
    }

    pub(super) fn pin_selection(
        &mut self,
        generation: u64,
        catalog: &Arc<CatalogIdentity>,
        config: &Arc<Config>,
    ) {
        if let Some(record) = self.record_mut() {
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
        if let Some(record) = self.record_mut() {
            record.selection = None;
        }
    }

    pub(super) fn tcp_dial_mode(
        &self,
        configured: DialMode,
        sniff: &crate::sniffing::SniffResult,
        verification: &'static str,
        candidates: &[honk_outbound::group::OwnedTarget],
        domain: Option<&str>,
    ) {
        let Some(record) = self.record() else { return };
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
            .all(|candidate| target_kind(candidate, domain) == target)
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
        selected: Option<(&honk_outbound::group::OwnedTarget, Option<&str>)>,
    ) {
        let Some(record) = self.record() else { return };
        let (generation, target, reason) = match selected {
            Some((outbound, target)) => (
                record
                    .selection
                    .as_ref()
                    .map(|selection| selection.generation),
                target_kind(outbound, target),
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

    pub(super) fn selected<'a>(&self, chain: &[String], dialed: impl Into<Dialed<'a>>) {
        let Some(record) = self.record() else { return };
        let dialed = dialed.into();
        if matches!(
            dialed.protocol(),
            NodeProtocol::Direct | NodeProtocol::Block
        ) {
            record.flow.selected(Vec::new());
            return;
        }
        let Some(selection) = &record.selection else {
            return;
        };
        let (member_id, _) = dialed.selected_member();
        let count = chain.len().saturating_sub(1);
        let groups: Option<Vec<_>> = chain
            .iter()
            .take(count)
            .map(|name| selection.catalog.groups.get(name).cloned())
            .collect();
        if let Some(mut chain) = groups {
            chain.push(member_id.to_string());
            record.flow.selected(chain);
        }
    }

    pub(super) fn attempt<'a>(
        &self,
        chain: &[String],
        dialed: impl Into<Dialed<'a>>,
        domain: Option<&str>,
    ) -> Option<ConnectionAttempt> {
        self.recorded
            .as_ref()
            .map(|record| record.attempt(chain, dialed, domain))
    }

    pub(in crate::control) fn finish(&self, state: ConnectionState, reason: &'static str) {
        if let Some(flow) = self.flow() {
            flow.finish(state, reason);
        }
    }

    pub(super) fn tcp_connected(
        &self,
        chain: &[String],
        target: &honk_outbound::group::OwnedTarget,
    ) {
        self.selected(chain, target);
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
        let Some(record) = self.record() else { return };
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

fn reserve_record(
    budget: Option<&Arc<honk_netstack::MemoryBudget>>,
    bytes: usize,
) -> std::io::Result<Option<honk_netstack::MemoryReservation>> {
    budget
        .map(|budget| {
            budget
                .reserve(bytes)
                .ok_or_else(crate::control::task_registry::capacity_error)
        })
        .transpose()
}

impl RecordedConnection {
    pub(super) fn attempt<'a>(
        &self,
        chain: &[String],
        dialed: impl Into<Dialed<'a>>,
        domain: Option<&str>,
    ) -> ConnectionAttempt {
        let record = &self.facts;
        let dialed = dialed.into();
        let node = dialed.node;
        let selection = record
            .selection
            .as_ref()
            .expect("captured selection generation");
        let target_kind = target_kind(dialed, domain);
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
            selection_path: selection_path(selection, chain, dialed),
            leaf_node_id: Some(node.id.to_string()),
            leaf_node_name: Some(node.name.clone()),
            target: match target_kind {
                "none" => None,
                "domain" => domain.map(|domain| format!("{domain}:{}", record.destination.port())),
                _ => Some(record.destination.to_string()),
            },
            target_kind,
            dial_ip: (record.network == Network::Udp && dialed.protocol() == NodeProtocol::Direct)
                .then(|| record.destination.ip()),
            server_addr: None,
            resolution_location: if target_kind == "none" {
                ResolutionLocation::NotApplicable
            } else if dialed.protocol() == NodeProtocol::Direct
                || (record.network == Network::Tcp && target_kind == "ip")
            {
                ResolutionLocation::OriginalIp
            } else {
                ResolutionLocation::Unknown
            },
        };
        ConnectionAttempt::new(
            Arc::clone(&record.flow),
            selection.generation,
            data,
            if dialed.protocol() == NodeProtocol::Direct {
                "dial_target"
            } else {
                "proxy_server"
            },
        )
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
        handoff
            .and_then(HandoffResult::mac_address)
            .map(crate::routing::mac_string),
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

/// What an attempt dials: a configured node, or a route whose leaf is
/// `node`. A route dials a proxy whatever its leaf's protocol.
#[derive(Clone, Copy)]
pub(super) struct Dialed<'a> {
    node: &'a Node,
    target: Option<&'a honk_outbound::group::OwnedTarget>,
}

impl Dialed<'_> {
    fn protocol(&self) -> NodeProtocol {
        match self.target.is_some_and(|target| target.route.is_some()) {
            true => NodeProtocol::Chain,
            false => self.node.protocol(),
        }
    }

    fn selected_member(&self) -> (uuid::Uuid, &str) {
        self.target
            .map_or((self.node.id, self.node.name.as_str()), |target| {
                target.selected_member()
            })
    }
}

impl<'a> From<&'a Node> for Dialed<'a> {
    fn from(node: &'a Node) -> Self {
        Self { node, target: None }
    }
}

impl<'a> From<&'a honk_outbound::group::OwnedTarget> for Dialed<'a> {
    fn from(target: &'a honk_outbound::group::OwnedTarget) -> Self {
        Self {
            node: &target.node,
            target: Some(target),
        }
    }
}

fn target_kind<'a>(dialed: impl Into<Dialed<'a>>, domain: Option<&str>) -> &'static str {
    match dialed.into().protocol() {
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
    dialed: Dialed<'_>,
) -> Vec<Selection> {
    let catalog = &selection.catalog;
    let (member_id, member_name) = dialed.selected_member();
    let Some((_, groups)) = chain.split_last() else {
        return Vec::new();
    };
    groups
        .iter()
        .enumerate()
        .filter_map(|(index, name)| {
            let group_id = catalog.groups.get(name)?;
            let next = match groups.get(index + 1) {
                Some(group) => (catalog.groups.get(group)?.clone(), group.clone()),
                None => (member_id.to_string(), member_name.to_owned()),
            };
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
    fn absent_and_failed_packet_routes_project_different_evidence() {
        let native = crate::native_api::observation::NativeObservation::new(&Config::default());
        native.core.flows.set_recording(true);
        let failure = PacketRouteSlot::from_capture(Err("receive_metadata_unavailable"));
        assert_eq!(failure.capture_gap, Some("receive_metadata_unavailable"));
        for (slot, missing) in [
            (PacketRouteSlot::ABSENT, serde_json::json!([])),
            (failure, serde_json::json!(["not_instrumented"])),
        ] {
            let mut observation = ConnectionObservation::begin(
                Some(&native.core),
                Network::Udp,
                "192.0.2.1:53000".parse().unwrap(),
                "198.51.100.1:53".parse().unwrap(),
            );
            observation.packet_route(slot);
            let detail = native
                .core
                .flows
                .test_detail(observation.flow().unwrap().id());
            assert_eq!(detail["trace"]["missing"], missing);
            assert!(
                !detail["trace"]["steps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|step| step["stage"] == "route")
            );
        }
    }

    #[test]
    fn captured_packet_and_handoff_routes_keep_partial_evidence() {
        let native = crate::native_api::observation::NativeObservation::new(&Config::default());
        native.core.flows.set_recording(true);
        let source = "192.0.2.1:53000".parse().unwrap();
        let destination = "198.51.100.1:53".parse().unwrap();
        let input =
            super::super::routing::build_connection_info(None, destination, source, "udp", None);
        let gap = Some("kernel_trace_conn_incarnation_mismatch");
        for from_handoff in [false, true] {
            let mut observation =
                ConnectionObservation::begin(Some(&native.core), Network::Udp, source, destination);
            let capture = CapturedKernelRoute {
                generation: 9,
                evaluation_id: "kernel-evaluation".into(),
                input: RouteInput::from(&input),
                rules: vec![RuleEvaluation {
                    rule_id: "rule-1".into(),
                    expression: "fallback".into(),
                    result: "matched",
                    missing_inputs: Vec::new(),
                    conditions: Vec::new(),
                }],
                rule_id: Some("rule-1".into()),
                outbound: Some("direct".into()),
                effective_outbound: None,
                must: true,
                mark_kind: honk_ebpf_common::ROUTING_MARK_SET,
                mark: 42,
                truncated: false,
                ambiguous: true,
                gap,
                fact_state: 0,
                domain_bitmap: [0; 8],
            };
            if from_handoff {
                let mut handoff = HandoffResult::from(honk_ebpf_common::RoutingHandoffEntry {
                    trace_id: 31,
                    ..Default::default()
                });
                handoff.packet_route = PacketRouteSlot::from_capture(Ok(capture));
                observation.handoff(Some(&mut handoff), true);
                assert!(handoff.packet_route.capture.is_none());
                assert_eq!(handoff.packet_route.capture_gap, gap);
                assert_eq!(handoff.trace_id, 31);
            } else {
                observation.packet_route(PacketRouteSlot::from_capture(Ok(capture)));
            }
            let detail = native
                .core
                .flows
                .test_detail(observation.flow().unwrap().id());
            assert_eq!(
                detail["trace"]["missing"],
                serde_json::json!(["not_instrumented", "started_late"])
            );
            let route = detail["trace"]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .find(|step| step["stage"] == "route")
                .unwrap();
            assert_eq!(route["data"]["mark"], 42);
            assert_eq!(route["data"]["outbound"], "direct");
        }
    }

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

    #[test]
    fn packet_recording_funds_only_admitted_payloads_and_their_shared_owner() {
        let native = crate::native_api::observation::NativeObservation::new(&Config::default());
        let begin = |budget| {
            ConnectionObservation::begin_in(
                Some(&native.core),
                Network::Udp,
                "192.0.2.1:41000".parse().unwrap(),
                "198.51.100.9:53".parse().unwrap(),
                Some(budget),
            )
        };
        let bytes = size_of::<RecordedConnection>();
        let short = honk_netstack::MemoryBudget::new(bytes - 1);
        let unrecorded = begin(&short).unwrap();
        assert!(!unrecorded.is_recording());
        assert!(unrecorded.shared(Some(&short)).unwrap().is_none());
        assert_eq!(short.used(), 0);
        native.core.flows.set_recording(true);
        assert!(begin(&short).is_err());
        assert_eq!(short.used(), 0);
        let budget = honk_netstack::MemoryBudget::new(bytes);
        let record = begin(&budget).unwrap();
        assert_eq!(budget.used(), bytes);
        assert!(record.shared(Some(&budget)).is_err());
        let shared_bytes = bytes + 2 * size_of::<usize>();
        let shared_budget = honk_netstack::MemoryBudget::new(shared_bytes);
        let shared = record.shared(Some(&shared_budget)).unwrap().unwrap();
        drop(record);
        assert_eq!(budget.used(), 0);
        assert_eq!(shared_budget.used(), shared_bytes);
        drop(shared);
        assert_eq!(shared_budget.used(), 0);
    }

    #[test]
    fn captured_kernel_decision_charges_the_box_even_without_dynamic_rule_data() {
        let trace = RouteTraceSlot::kernel(true);
        assert_eq!(trace.retained_bytes(), size_of::<RouteObservation>());
        assert_eq!(RouteTraceSlot::kernel(false).retained_bytes(), 0);
    }

    #[test]
    fn gateway_process_survives_sniff_without_socket_mark_or_path() {
        let native = crate::native_api::observation::NativeObservation::new(&Config::default());
        native.core.flows.set_recording(true);
        for (network, domain_source, name) in [
            (Network::Tcp, DomainSource::HttpHost, "abcdefghijkl�猫"),
            (Network::Udp, DomainSource::QuicSni, ""),
        ] {
            let mut observation = ConnectionObservation::begin(
                Some(&native.core),
                network,
                "192.0.2.1:41000".parse().unwrap(),
                "198.51.100.7:53".parse().unwrap(),
            );
            observation.packet_facts(ProcessMeta::test_gateway(417, name), 12, None);
            observation.sniffed(Some("example.test"), Some(domain_source), None);
            let detail = native
                .core
                .flows
                .test_detail(observation.flow().unwrap().id());
            assert_eq!(detail["input"]["pid"], 417);
            assert_eq!(detail["pname"].as_str(), (!name.is_empty()).then_some(name));
            assert!(detail["input"]["mark"].is_null());
            assert!(detail["input"]["process_path"].is_null());
        }
    }

    #[test]
    fn userspace_route_evidence_distinguishes_keep_zero_and_full_marks() {
        let native = crate::native_api::observation::NativeObservation::new(&Config::default());
        native.core.flows.set_recording(true);
        let source = "192.0.2.1:53000".parse().unwrap();
        let destination = "198.51.100.1:443".parse().unwrap();
        let input =
            super::super::routing::build_connection_info(None, destination, source, "tcp", None);
        for mark in [None, Some(0), Some(u32::MAX)] {
            let mut observation =
                ConnectionObservation::begin(Some(&native.core), Network::Tcp, source, destination);
            let flow = Arc::clone(observation.flow().unwrap());
            let mut routing = honk_config::routing::RoutingConfig::default();
            routing.default_outbound = "direct".into();
            routing.default_mark = mark;
            let router = Router::from_config(&routing).unwrap();
            let mut decision =
                RoutingDecision::from_router(&router, &input, None, Some((&native.core, 1)));
            observation.routed(&mut decision);
            let detail = native.core.flows.test_detail(flow.id());
            let route = detail["trace"]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .find(|step| step["stage"] == "route")
                .unwrap();
            assert_eq!(
                route["data"]["mark_kind"],
                if mark.is_some() {
                    honk_ebpf_common::ROUTING_MARK_SET
                } else {
                    honk_ebpf_common::ROUTING_MARK_KEEP
                }
            );
            assert_eq!(route["data"]["mark"], mark.unwrap_or(0));
        }
    }
}
