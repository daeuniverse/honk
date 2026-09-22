use super::*;
use crate::ebpf::{EbpfBackend, RoutingPushPhase, mock::MockEbpfBackend};
use honk_config::types::DialMode;
use std::collections::HashMap;

fn fixture() -> (
    MockEbpfBackend,
    RoutingPushPlan,
    Router,
    honk_config::Config,
) {
    let config = honk_config::Config::default();
    let router = Router::new(&[], "direct").unwrap();
    let mut plan = RoutingPushPlan::compile(
        &router,
        &HashMap::from([("direct".into(), 0), ("block".into(), 1)]),
        "direct",
        DialMode::Ip,
    )
    .unwrap();
    plan.enable_trace(true);
    let mut backend = MockEbpfBackend::new();
    backend.publish_routing_plan(&plan, &[]).unwrap();
    backend.bind_kernel_trace_dictionary(
        KernelTraceDictionary::prepare("instance", 17, &router, &config, &plan).unwrap(),
    );
    (backend, plan, router, config)
}

fn captured(backend: &mut MockEbpfBackend, token: u32) -> (TuplesKey, u32, u64) {
    let mut key: TuplesKey = unsafe { std::mem::zeroed() };
    key.src_ip = honk_ebpf_common::dae_ip::In6Addr::from_ipv4_bytes([192, 0, 2, 7]);
    key.dst_ip = honk_ebpf_common::dae_ip::In6Addr::from_ipv4_bytes([198, 51, 100, 9]);
    key.src_port = 40000;
    key.dst_port = 443;
    key.l4proto = 17;
    let descriptor = backend.routing_snapshot().descriptor;
    let mut witness = KernelRouteWitness {
        tuple: key,
        decision_token: token,
        ..Default::default()
    };
    witness.output.flags = ROUTE_TRACE_VERSION | ROUTE_TRACE_ENABLED | ROUTE_TRACE_COMPLETE;
    witness.output.policy_id = descriptor.trace_policy;
    witness.output.generation = descriptor.generation;
    witness.output.decision = RoutingDecision {
        outbound: 0,
        domain_final: 1,
        ..Default::default()
    };
    witness.output.input.src_ip = *key.src_ip.as_bytes();
    witness.output.input.dst_ip = *key.dst_ip.as_bytes();
    witness.output.input.src_port = u32::from(key.src_port);
    witness.output.input.dst_port = u32::from(key.dst_port);
    witness.output.input.l4proto = 2;
    witness.output.outcomes[0] = ROUTE_TRACE_MATCHED;
    let id = backend.capture_route_witness(witness);
    (key, id, descriptor.generation)
}

#[test]
fn old_witness_keeps_accepted_generation_across_fences_and_failed_publication() {
    let (mut backend, plan, router, config) = fixture();
    let (key, id, generation) = captured(&mut backend, 0);
    let owner = backend.routing_snapshot().descriptor.trace_policy;
    backend.quiesce_udp_staging().unwrap();
    assert_ne!(backend.routing_policy_generation(), generation);
    assert_eq!(backend.routing_snapshot().descriptor.trace_policy, owner);
    backend.bind_kernel_trace_dictionary(
        KernelTraceDictionary::prepare("instance", 99, &router, &config, &plan).unwrap(),
    );
    backend.fail_next_routing_phase(RoutingPushPhase::Root);
    assert!(backend.publish_routing_plan(&plan, &[]).is_err());
    assert_eq!(backend.routing_snapshot().descriptor.trace_policy, owner);
    let result = backend
        .capture_kernel_route(
            &key,
            KernelRouteReference {
                trace_id: id,
                decision_token: 0,
                routing_generation: generation,
                effective_outbound: 0,
                mark: Some(0),
                must: Some(0),
            },
        )
        .unwrap();
    assert_eq!(result.generation, 17);
    assert_eq!(result.rule_id.as_deref(), Some("instance:17:fallback"));
    assert_eq!(result.rules[0].result, "matched");
    assert_eq!(result.gap, None);
    assert_eq!(
        backend
            .capture_kernel_route(
                &key,
                KernelRouteReference {
                    trace_id: id,
                    decision_token: 1,
                    routing_generation: generation,
                    effective_outbound: 0,
                    mark: None,
                    must: None
                }
            )
            .unwrap_err(),
        "kernel_trace_identity_mismatch"
    );
    assert_eq!(
        backend
            .capture_kernel_route(
                &key,
                KernelRouteReference {
                    trace_id: id,
                    decision_token: 0,
                    routing_generation: generation + 1,
                    effective_outbound: 0,
                    mark: None,
                    must: None
                }
            )
            .unwrap_err(),
        "kernel_trace_identity_mismatch"
    );
}

#[test]
fn exact_token_witness_rejects_rebound_handoff_and_preserves_tcp_ambiguity() {
    let (mut backend, _, _, _) = fixture();
    let (key, id, generation) = captured(&mut backend, 73);
    assert!(
        backend
            .capture_kernel_route(
                &key,
                KernelRouteReference {
                    trace_id: id,
                    decision_token: 73,
                    routing_generation: generation,
                    effective_outbound: 0,
                    mark: Some(0),
                    must: Some(0)
                }
            )
            .is_ok()
    );
    assert_eq!(
        backend
            .capture_kernel_route(
                &key,
                KernelRouteReference {
                    trace_id: id,
                    decision_token: 74,
                    routing_generation: generation,
                    effective_outbound: 0,
                    mark: None,
                    must: None
                }
            )
            .unwrap_err(),
        "kernel_trace_identity_mismatch"
    );
    assert_eq!(
        backend
            .capture_kernel_route(
                &key,
                KernelRouteReference {
                    trace_id: id,
                    decision_token: 73,
                    routing_generation: generation,
                    effective_outbound: 2,
                    mark: None,
                    must: None
                }
            )
            .unwrap_err(),
        "kernel_trace_action_mismatch"
    );
    backend.route_witnesses.get_mut(&id).unwrap().output.flags |= ROUTE_TRACE_AMBIGUOUS;
    let result = backend
        .capture_kernel_route(
            &key,
            KernelRouteReference {
                trace_id: id,
                decision_token: 73,
                routing_generation: generation,
                effective_outbound: 0,
                mark: None,
                must: None,
            },
        )
        .unwrap();
    assert!(result.ambiguous);
    assert_eq!(result.gap, Some("kernel_tcp_history_ambiguous"));
}

#[test]
fn witness_and_dictionary_pressure_never_relabel_or_reuse_evicted_identity() {
    let (mut backend, plan, router, config) = fixture();
    let (key, old_id, generation) = captured(&mut backend, 0);
    for _ in 0..ROUTE_TRACE_CAPACITY {
        captured(&mut backend, 0);
    }
    assert_eq!(backend.route_witnesses.len(), ROUTE_TRACE_CAPACITY as usize);
    assert_eq!(
        backend
            .capture_kernel_route(
                &key,
                KernelRouteReference {
                    trace_id: old_id,
                    decision_token: 0,
                    routing_generation: generation,
                    effective_outbound: 0,
                    mark: None,
                    must: None
                }
            )
            .unwrap_err(),
        "kernel_trace_sidecar_missing"
    );
    let (_, retained_id, retained_generation) = captured(&mut backend, 0);
    assert!(retained_id > old_id);
    for accepted in 18..=34 {
        backend.publish_routing_plan(&plan, &[]).unwrap();
        backend.bind_kernel_trace_dictionary(
            KernelTraceDictionary::prepare("instance", accepted, &router, &config, &plan).unwrap(),
        );
    }
    assert_eq!(
        backend
            .capture_kernel_route(
                &key,
                KernelRouteReference {
                    trace_id: retained_id,
                    decision_token: 0,
                    routing_generation: retained_generation,
                    effective_outbound: 0,
                    mark: None,
                    must: None
                }
            )
            .unwrap_err(),
        "kernel_trace_dictionary_missing"
    );
    let mut store = KernelTraceDictionaries::default();
    for policy in 1..=17 {
        store.bind(
            policy,
            plan.fingerprint,
            KernelTraceDictionary::prepare("instance", u64::from(policy), &router, &config, &plan)
                .unwrap(),
        );
    }
    store.bind(
        1,
        plan.fingerprint,
        KernelTraceDictionary::prepare("instance", 999, &router, &config, &plan).unwrap(),
    );
    assert!(!store.owners.iter().any(|(id, _)| *id == 1));
    assert!(store.bytes <= MAX_RETAINED_BYTES);
}

#[test]
fn dns_rewrite_is_validated_without_replacing_original_output() {
    let (mut backend, _, _, _) = fixture();
    let (mut key, id, generation) = captured(&mut backend, 0);
    key.dst_port = 53;
    let witness = backend.route_witnesses.get_mut(&id).unwrap();
    witness.tuple = key;
    witness.output.input.dst_port = 53;
    witness.output.decision.outbound = 1;
    witness.output.flags |= ROUTE_TRACE_DNS_OVERRIDE;
    let result = backend
        .capture_kernel_route(
            &key,
            KernelRouteReference {
                trace_id: id,
                decision_token: 0,
                routing_generation: generation,
                effective_outbound: 0xfd,
                mark: None,
                must: None,
            },
        )
        .unwrap();
    assert_eq!(result.outbound.as_deref(), Some("block"));
    assert_eq!(
        result.effective_outbound.as_deref(),
        Some("control_plane_routing")
    );
    assert_eq!(
        backend
            .capture_kernel_route(
                &key,
                KernelRouteReference {
                    trace_id: id,
                    decision_token: 0,
                    routing_generation: generation,
                    effective_outbound: 1,
                    mark: None,
                    must: None
                }
            )
            .unwrap_err(),
        "kernel_trace_action_mismatch"
    );
}

#[test]
fn oversized_dictionary_reports_only_executed_evidence_loss() {
    let mut source = String::from("routing {\n");
    // Three conditions amortize retained row capacity without raising the dictionary budget.
    for port in 1000..1065 {
        source.push_str(&format!(
            "dport({port}) && sport(40000) && l4proto(udp) -> direct(must)\n"
        ));
    }
    source.push_str("fallback: block\n}\n");
    let config = honk_config::parser::parse_dae_config(&source).unwrap();
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut plan = RoutingPushPlan::compile(
        &router,
        &HashMap::from([("direct".into(), 0), ("block".into(), 1)]),
        "block",
        DialMode::Ip,
    )
    .unwrap();
    plan.enable_trace(true);
    let dictionary =
        KernelTraceDictionary::prepare("instance", 17, &router, &config, &plan).unwrap();
    assert!(dictionary.bytes <= MAX_DICTIONARY_BYTES);
    assert_eq!(dictionary.layout.total_values, 261);
    assert_eq!(dictionary.layout.slots.len(), ROUTE_TRACE_VALUES);

    let mut witness = KernelRouteWitness::default();
    witness.output.flags = ROUTE_TRACE_VERSION | ROUTE_TRACE_ENABLED | ROUTE_TRACE_COMPLETE;
    witness.tuple.l4proto = 17;
    witness.output.input.src_port = 40000;
    witness.output.input.dst_port = 1000;
    witness.output.input.l4proto = 2;
    witness.output.decision = RoutingDecision {
        outbound: 0,
        must: 1,
        rule_id: 0,
        ..Default::default()
    };
    witness.output.outcomes[0] = 0x55;
    let early = dictionary.decode(&witness, 0);
    assert!(!early.truncated);
    assert_eq!(early.gap, None);
    assert_eq!(early.rules[0].result, "matched");
    assert!(
        early.rules[0]
            .conditions
            .iter()
            .all(|condition| condition.result == "matched")
    );
    assert!(early.rules[1..].iter().all(|rule| {
        rule.result == "skipped"
            && rule
                .conditions
                .iter()
                .all(|condition| condition.result == "skipped")
    }));

    witness.output.flags |= ROUTE_TRACE_OVERFLOW;
    witness.output.input.dst_port = 1064;
    witness.output.decision.rule_id = 64;
    witness.output.outcomes.fill(0x0a0a_0a0a);
    let late = dictionary.decode(&witness, 0);
    assert!(late.truncated);
    assert_eq!(late.gap, Some("kernel_trace_truncated"));
    assert_eq!(late.rule_id.as_deref(), Some("instance:17:rule:64"));
    assert_eq!(late.outbound.as_deref(), Some("direct"));
    assert!(late.rules.iter().all(|rule| {
        rule.result == "not_matched"
            && rule.conditions[0].result == "not_matched"
            && rule.conditions[1..]
                .iter()
                .all(|condition| condition.result == "skipped")
    }));
}

#[test]
fn cached_unicode_source_truncation_remains_a_visible_flow_gap() {
    use crate::native_api::{
        events::EventHub,
        flows::{
            FlowStore,
            record::{EvaluationInput, StepData},
        },
    };
    use std::sync::Arc;

    let name = format!("{}\u{1f600}", "x".repeat(503));
    let config = honk_config::parser::parse_dae_config(&format!(
        "routing {{\n pname('{name}') -> block\n fallback: direct\n}}\n"
    ))
    .unwrap();
    let router = Router::new(&config.routing.rules, "direct").unwrap();
    let mut plan = RoutingPushPlan::compile(
        &router,
        &HashMap::from([("direct".into(), 0), ("block".into(), 1)]),
        "direct",
        DialMode::Ip,
    )
    .unwrap();
    plan.enable_trace(true);
    let dictionary =
        KernelTraceDictionary::prepare("instance", 17, &router, &config, &plan).unwrap();
    let mut witness = KernelRouteWitness::default();
    witness.output.flags = ROUTE_TRACE_VERSION | ROUTE_TRACE_ENABLED | ROUTE_TRACE_COMPLETE;
    witness.tuple.l4proto = 6;
    witness.output.input.l4proto = 1;
    witness.output.input.src_port = 31000;
    witness.output.input.dst_port = 443;
    witness.output.decision.rule_id = u32::MAX;
    witness.output.outcomes[0] = 2 | (2 << 2) | (1 << 4);
    let capture = dictionary.decode(&witness, 0);
    assert_eq!(capture.gap, None);
    let store = Arc::new(FlowStore::new(
        "instance".into(),
        Arc::new(EventHub::new("instance".into())),
    ));
    let flow = store.begin(
        "tcp",
        (capture.input.src_ip, capture.input.src_port).into(),
        (capture.input.dst_ip, capture.input.dst_port).into(),
    );
    flow.step(
        Some(17),
        StepData::Route {
            evaluation_id: capture.evaluation_id,
            chain: "traffic",
            plane: "kernel",
            rule_id: capture.rule_id,
            outbound: capture.outbound,
            must: Some(capture.must),
            mark: Some(capture.mark),
            input: Some(EvaluationInput::Traffic(capture.input)),
            rules: capture.rules,
            dns_action: None,
        },
    );
    let detail = store.test_detail(flow.id());
    assert_eq!(detail["trace_status"], "partial");
    assert_eq!(
        detail["trace"]["missing"],
        serde_json::json!(["buffer_overflow"])
    );
}
