use super::{decision, input, object, outbound_ids};
use crate::control::routing_matcher::{KernelTraceDisposition, RoutingPushPlan};
use crate::ebpf::EbpfBackend;
use crate::ebpf::real::RealEbpfBackend;
use crate::routing::{Router, golden};
use honk_config::types::DialMode;
use honk_ebpf_common::{
    DATAPATH_FLAG_TRACE_ENABLED, DaeParam, DomainRouting, KernelRouteOutput, ROUTE_FACT_DOMAIN,
    ROUTE_FACT_PRESENT_SHIFT, ROUTE_FACT_SOURCE, ROUTE_TRACE_COMPLETE, ROUTE_TRACE_ENABLED,
    ROUTE_TRACE_OVERFLOW, ROUTE_TRACE_VALUES, ROUTE_TRACE_VERSION,
};

fn compile(source: &str) -> (Router, RoutingPushPlan) {
    let config = honk_config::parser::parse_dae_config(source).unwrap();
    let router = Router::from_config(&config.routing).unwrap();
    let mut plan = RoutingPushPlan::compile(&router, &outbound_ids(), DialMode::Domain).unwrap();
    plan.enable_trace(true);
    (router, plan)
}

fn outcomes(trace: &KernelRouteOutput, expected: &[u32]) {
    assert_eq!(
        trace.flags,
        ROUTE_TRACE_VERSION | ROUTE_TRACE_ENABLED | ROUTE_TRACE_COMPLETE
    );
    assert_ne!(trace.policy_id, 0);
    assert_ne!(trace.generation, 0);
    for slot in 0..ROUTE_TRACE_VALUES {
        assert_eq!(
            trace.outcome(slot),
            Some(expected.get(slot).copied().unwrap_or(0)),
            "slot {slot}"
        );
    }
    assert_eq!(trace.outcome(ROUTE_TRACE_VALUES), None);
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn branch_witness_keeps_port_order_missing_negation_and_consumed_domain_facts() {
    let (router, mut plan) = compile(
        r#"
        routing {
            dip(203.0.113.0/24) && dport(80) -> block(must)
            sip(198.51.100.0/24) && dport(443) -> block(must)
            domain(full:hit.test) && dport(443) && !sip(198.51.100.0/24) -> proxy(must)
            !domain(full:hit.test) && dport(443) && !sip(198.51.100.0/24) -> direct(must)
            fallback: block
        }
        "#,
    );
    let layout = plan.trace_layout().unwrap();
    assert_eq!(layout.total_values, 15);
    assert!(!layout.truncated());
    assert_eq!(layout.slots[1].condition_ordinal, Some(1));
    assert_eq!(layout.slots[1].evaluation_rank, Some(0));
    assert_eq!(layout.slots[2].condition_ordinal, Some(0));
    assert_eq!(layout.slots[2].evaluation_rank, Some(1));

    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
    let mut connection = golden::connection();
    connection.src_ip = "192.0.2.10".parse().unwrap();
    connection.dst_ip = "203.0.113.10".parse().unwrap();
    connection.dst_port = 443;
    let packet = input(&connection);
    let key = crate::ebpf::maps::ip_addr_to_lpm_key(connection.dst_ip);
    let miss = [2, 2, 0, 2, 1, 2, 2, 1, 2, 0, 1, 1, 1, 1, 0];
    let hit = [2, 2, 0, 2, 1, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0];
    let mut retained = None;
    for (compiled, capture) in [(true, false), (true, true), (false, true), (true, true)] {
        plan.enable_trace(compiled);
        backend.publish_routing_plan(&plan, &[]).unwrap();
        backend
            .set_datapath_flags(if capture {
                DATAPATH_FLAG_TRACE_ENABLED
            } else {
                0
            })
            .unwrap();
        for state in 0..4 {
            let bitmap = match state {
                0 | 3 => {
                    backend.remove_domain_ip_bitmap(&key).unwrap();
                    DomainRouting::default()
                }
                1 => {
                    let zero = DomainRouting::default();
                    backend.set_domain_ip_bitmap(&key, &zero).unwrap();
                    zero
                }
                _ => {
                    let bitmap = router.domain_bitmap("hit.test").unwrap();
                    backend.set_domain_ip_bitmap(&key, &bitmap).unwrap();
                    bitmap
                }
            };
            let present = state == 1 || state == 2;
            let selected = state == 2;
            let expected = decision(
                if selected { 2 } else { 0 },
                0,
                true,
                present as u32,
                if selected { 2 } else { 3 },
            );
            let actual = backend.run_routing_test(&packet).unwrap();
            assert_eq!(actual.status, 0);
            assert_eq!(actual.decision, expected);
            if compiled && capture {
                assert_eq!(actual.trace.decision, expected);
                assert_eq!(actual.trace.input, packet);
                assert_eq!(actual.trace.domain_bitmap, bitmap);
                assert_eq!(
                    actual.trace.fact_state,
                    ROUTE_FACT_DOMAIN
                        | ROUTE_FACT_SOURCE
                        | if present {
                            ROUTE_FACT_DOMAIN << ROUTE_FACT_PRESENT_SHIFT
                        } else {
                            0
                        }
                );
                outcomes(&actual.trace, if selected { &hit } else { &miss });
                if selected {
                    retained = Some(actual.trace);
                }
            } else {
                assert_eq!(actual.trace.flags & ROUTE_TRACE_ENABLED, 0);
            }
        }
    }
    // Removing/replacing the map never relabels the already returned invocation.
    let retained = retained.unwrap();
    outcomes(&retained, &hit);
    assert_eq!(retained.domain_bitmap.bitmap[0], 1);
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn folded_and_unreachable_conditions_have_no_invented_runtime_outcomes() {
    use KernelTraceDisposition::{FoldedFalse, FoldedTrue, Runtime, Unreachable};
    let (_, plan) = compile(
        r#"
        routing {
            l4proto(icmp) -> block
            !ipversion(9) && dport(8443) -> proxy(must)
            dport(443) -> block
            !dscp(invalid) -> direct(must)
            dport(80) -> block
            fallback: block
        }
        "#,
    );
    let layout = plan.trace_layout().unwrap();
    assert_eq!(
        layout
            .slots
            .iter()
            .map(|slot| slot.disposition)
            .collect::<Vec<_>>(),
        [
            FoldedFalse,
            FoldedFalse,
            Runtime,
            Runtime,
            FoldedTrue,
            Runtime,
            Runtime,
            Runtime,
            FoldedTrue,
            Unreachable,
            Unreachable,
            Unreachable
        ]
    );
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
    backend.publish_routing_plan(&plan, &[]).unwrap();
    backend
        .set_datapath_flags(DATAPATH_FLAG_TRACE_ENABLED)
        .unwrap();
    let mut connection = golden::connection();
    connection.dst_port = 80;
    let actual = backend.run_routing_test(&input(&connection)).unwrap();
    assert_eq!(actual.status, 0);
    assert_eq!(actual.decision, decision(0, 0, true, 1, 3));
    outcomes(&actual.trace, &[0, 0, 2, 2, 0, 2, 2, 1, 0, 0, 0, 0]);
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn evidence_budget_stops_only_evidence_and_disabled_invocations_do_not_leak() {
    let mut source = String::from("routing {\n");
    for port in 1000..1129 {
        source.push_str(&format!("dport({port}) -> proxy(must)\n"));
    }
    source.push_str("fallback: block\n}\n");
    let (_router, plan) = compile(&source);
    let layout = plan.trace_layout().unwrap();
    assert_eq!(layout.slots.len(), 256);
    assert_eq!(layout.total_values, 259);
    assert!(layout.truncated());
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
    backend.publish_routing_plan(&plan, &[]).unwrap();
    #[cfg(feature = "native-api")]
    let dictionaries = {
        use crate::observe::flows::kernel::{KernelTraceDictionaries, KernelTraceDictionary};
        let mut config = honk_config::parser::parse_dae_config(&source).unwrap();
        config.groups.push(honk_config::group::Group {
            name: "proxy".into(),
            ..Default::default()
        });
        // The compiler's slot budget is independent of retained dictionary capacity.
        assert!(KernelTraceDictionary::prepare("instance", 17, &_router, &config, &plan).is_none());
        KernelTraceDictionaries::default()
    };
    for capture in [true, false, true] {
        backend
            .set_datapath_flags(if capture {
                DATAPATH_FLAG_TRACE_ENABLED
            } else {
                0
            })
            .unwrap();
        for (port, rule_id, overflow) in [
            (1000, 0, false),
            (1127, 127, false),
            (1128, 128, true),
            (999, u32::MAX, true),
        ] {
            let mut connection = golden::connection();
            connection.dst_port = port;
            let actual = backend.run_routing_test(&input(&connection)).unwrap();
            let matched = rule_id != u32::MAX;
            assert_eq!(actual.status, 0);
            assert_eq!(
                actual.decision,
                decision(if matched { 2 } else { 1 }, 0, matched, 1, rule_id)
            );
            if !capture {
                assert_eq!(actual.trace.flags & ROUTE_TRACE_ENABLED, 0);
                continue;
            }
            assert_eq!(actual.trace.decision, actual.decision);
            assert_eq!(
                actual.trace.flags,
                ROUTE_TRACE_VERSION
                    | ROUTE_TRACE_ENABLED
                    | ROUTE_TRACE_COMPLETE
                    | if overflow { ROUTE_TRACE_OVERFLOW } else { 0 }
            );
            for slot in 0..256 {
                let expected = if rule_id == 0 {
                    u32::from(slot < 2)
                } else if rule_id == 127 && slot >= 254 {
                    1
                } else {
                    2
                };
                assert_eq!(
                    actual.trace.outcome(slot),
                    Some(expected),
                    "port {port}, slot {slot}"
                );
            }
            #[cfg(feature = "native-api")]
            {
                use crate::observe::flows::kernel::KernelRouteReference;
                let addr = |ip: std::net::IpAddr| match ip {
                    std::net::IpAddr::V4(ip) => {
                        honk_ebpf_common::dae_ip::In6Addr::from_ipv4_bytes(ip.octets())
                    }
                    std::net::IpAddr::V6(ip) => {
                        honk_ebpf_common::dae_ip::In6Addr::from_ipv6_addr(ip)
                    }
                };
                let mut key: honk_ebpf_common::TuplesKey = unsafe { std::mem::zeroed() };
                key.src_ip = addr(connection.src_ip);
                key.dst_ip = addr(connection.dst_ip);
                key.src_port = connection.src_port;
                key.dst_port = connection.dst_port;
                key.l4proto = if actual.trace.input.l4proto == 1 {
                    6
                } else {
                    17
                };
                let witness = honk_ebpf_common::KernelRouteWitness {
                    output: actual.trace,
                    tuple: key,
                    capture_id: 1,
                    ..Default::default()
                };
                let gap = dictionaries
                    .capture(
                        &witness,
                        &key,
                        KernelRouteReference {
                            trace_id: 1,
                            decision_token: 0,
                            routing_generation: actual.trace.generation,
                            effective_outbound: actual.decision.handoff_outbound(),
                            mark: Some(actual.decision.mark),
                            must: Some(actual.decision.must as u8),
                        },
                    )
                    .unwrap_err();
                assert_eq!(gap, "kernel_trace_dictionary_missing");
            }
        }
    }
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn capture_preserves_every_golden_decision_before_and_after_dns_override() {
    let (router, cases) = golden::fixtures();
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
    for mode in [
        DialMode::Ip,
        DialMode::Domain,
        DialMode::DomainPlus,
        DialMode::DomainPlusPlus,
    ] {
        let mut plan = RoutingPushPlan::compile(&router, &outbound_ids(), mode).unwrap();
        for (compiled, capture) in [(false, false), (false, true), (true, false), (true, true)] {
            plan.enable_trace(compiled);
            backend.publish_routing_plan(&plan, &[]).unwrap();
            backend
                .set_datapath_flags(if capture {
                    DATAPATH_FLAG_TRACE_ENABLED
                } else {
                    0
                })
                .unwrap();
            for case in &cases {
                let packet = input(&case.connection);
                let key = crate::ebpf::maps::ip_addr_to_lpm_key(case.connection.dst_ip);
                let bitmap = case
                    .connection
                    .domain
                    .as_deref()
                    .and_then(|domain| router.domain_bitmap(domain));
                if let Some(bitmap) = bitmap {
                    backend.set_domain_ip_bitmap(&key, &bitmap).unwrap();
                } else {
                    backend.remove_domain_ip_bitmap(&key).unwrap();
                }
                let mut generated = case.decision;
                generated.domain_final =
                    (!matches!(mode, DialMode::Domain | DialMode::DomainPlusPlus)
                        || bitmap.is_some()) as u32;
                if mode == DialMode::DomainPlusPlus && case.generic_port_punt {
                    generated.outbound =
                        honk_ebpf_common::OutboundIndex::ControlPlaneRouting as u32;
                }
                let mut final_decision = generated;
                if packet.dst_port == 53 && generated.must == 0 {
                    final_decision.outbound =
                        honk_ebpf_common::OutboundIndex::ControlPlaneRouting as u32;
                }
                let actual = backend.run_routing_test(&packet).unwrap();
                assert_eq!(actual.status, 0, "{mode:?}/{}", case.label);
                assert_eq!(actual.decision, final_decision, "{mode:?}/{}", case.label);
                if compiled && capture {
                    assert_eq!(actual.trace.decision, generated, "{mode:?}/{}", case.label);
                    assert_eq!(
                        actual.trace.flags & (ROUTE_TRACE_ENABLED | ROUTE_TRACE_COMPLETE),
                        ROUTE_TRACE_ENABLED | ROUTE_TRACE_COMPLETE
                    );
                    if final_decision != generated {
                        assert_ne!(
                            actual.trace.flags & honk_ebpf_common::ROUTE_TRACE_DNS_OVERRIDE,
                            0
                        );
                    }
                } else {
                    assert_eq!(actual.trace.flags & ROUTE_TRACE_ENABLED, 0);
                }
            }
        }
    }
}
