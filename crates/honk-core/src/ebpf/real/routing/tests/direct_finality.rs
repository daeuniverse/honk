use super::*;

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn direct_prefix_finality_preserves_domain_order_and_terminal_contracts() {
    use honk_ebpf_common::{
        DATAPATH_FLAG_OFFLOAD_RULE_DIRECT, DATAPATH_FLAG_TRACE_ENABLED,
        ROUTING_INPUT_ALLOW_DIRECT_FINALITY,
    };

    let independent = r#"
        routing {
            domain(full:folded.test) && l4proto(icmp) -> block
            dip(203.0.113.0/24) -> block
            dip(192.0.2.0/24) -> direct(mark: 0x281)
            domain(full:late.test) -> proxy
            fallback: block
        }
    "#;
    let negated = r#"
        routing {
            !domain(full:late.test) && dip(192.0.2.0/24) -> direct(mark: 0x285)
            fallback: block
        }
    "#;
    let cases = [
        (
            independent,
            true,
            false,
            8443,
            decision(0, 0x281, false, 1, 2),
        ),
        (
            independent,
            false,
            false,
            8443,
            decision(0, 0x281, false, 0, 2),
        ),
        (
            independent,
            true,
            false,
            53,
            decision(0xfd, 0x281, false, 1, 2),
        ),
        (
            r#"
            routing {
                domain(full:late.test) -> proxy
                dip(192.0.2.0/24) -> direct(mark: 0x285)
                fallback: block
            }
            "#,
            true,
            false,
            8443,
            decision(0, 0x285, false, 0, 1),
        ),
        (negated, true, false, 8443, decision(0, 0x285, false, 0, 0)),
        (negated, true, true, 8443, decision(0, 0x285, false, 1, 0)),
        (
            r#"
            routing {
                domain(full:late.test) && l4proto(icmp) -> block
                fallback: direct(mark: 0x28f)
            }
            "#,
            true,
            false,
            8443,
            decision(0, 0x28f, false, 1, u32::MAX),
        ),
    ];
    let mut connection = golden::connection();
    connection.dst_ip = "192.0.2.9".parse().unwrap();
    let key = crate::ebpf::maps::ip_addr_to_lpm_key(connection.dst_ip);
    let mut packet = input(&connection);
    packet.flags |= ROUTING_INPUT_ALLOW_DIRECT_FINALITY;
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();

    for (mode, trace) in [(DialMode::Domain, false), (DialMode::DomainPlusPlus, true)] {
        for (source, rule_mode, known_empty, port, expected) in cases {
            let config = honk_config::parser::parse_dae_config(source).unwrap();
            let router = Router::from_config(&config.routing).unwrap();
            let mut plan = RoutingPushPlan::compile(&router, &outbound_ids(), mode).unwrap();
            plan.enable_trace(trace);
            backend.publish_routing_plan(&plan, &[]).unwrap();
            let mut flags = if rule_mode {
                DATAPATH_FLAG_OFFLOAD_RULE_DIRECT
            } else {
                0
            };
            if trace {
                flags |= DATAPATH_FLAG_TRACE_ENABLED;
            }
            backend.set_datapath_flags(flags).unwrap();
            if known_empty {
                backend
                    .set_domain_ip_bitmap(&key, &DomainRouting::default())
                    .unwrap();
            } else {
                backend.remove_domain_ip_bitmap(&key).unwrap();
            }
            packet.dst_port = port;
            let actual = backend.run_routing_test(&packet).unwrap();
            assert_eq!(actual.status, 0, "{mode:?}/{source}");
            assert_eq!(actual.decision, expected, "{mode:?}/{source}");
            if trace && port == 53 {
                assert_eq!(actual.trace.decision, decision(0, 0x281, false, 1, 2));
            }
        }
    }
}
