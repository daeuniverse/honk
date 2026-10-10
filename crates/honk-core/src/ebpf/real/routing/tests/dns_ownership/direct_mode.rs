use super::*;

/// Clash `direct` mode normalizes a non-`must` proxy rule to direct in every
/// hook: no dead-proxy health gate, no handoff, and no proxy-rule mark in
/// policy routing. A `must` proxy rule keeps its routed outbound and its gate.
#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn direct_mode_normalizes_nonmust_proxy_in_lan_and_wan_tcp_udp() {
    isolated(|| {
        let destinations: [(IpAddr, bool); 4] = [
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 80)), false),
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 81)), true),
            ("2001:db8::80".parse().unwrap(), false),
            ("2001:db8::81".parse().unwrap(), true),
        ];
        let rules = destinations
            .iter()
            .enumerate()
            .map(|(index, (destination, must))| {
                rule(
                    &format!("proxy-{index}"),
                    RoutingCondition {
                        ip: vec![destination.to_string()],
                        ..Default::default()
                    },
                    "proxy",
                    0x400,
                    *must,
                )
            })
            .collect::<Vec<_>>();
        let (mut backend, _, _listeners) = publish(&rules);
        backend
            .set_datapath_flags(DATAPATH_FLAG_OFFLOAD_ALL)
            .unwrap();
        // Every leaf of the proxy group is dead.
        for key in 2 * 6..3 * 6 {
            set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", key, 0u64);
        }

        for (wan, side) in [(true, "wan_egress_l2"), (false, "lan_ingress_l2")] {
            for (index, (destination, must)) in destinations.iter().copied().enumerate() {
                let source = match destination {
                    IpAddr::V4(_) => {
                        IpAddr::V4(Ipv4Addr::new(10 + wan as u8, 0, 0, index as u8 + 2))
                    }
                    IpAddr::V6(_) => format!("2001:db9:{:x}::{:x}", wan as u8, index + 2)
                        .parse()
                        .unwrap(),
                };
                let (expected_verdict, expected_mark) = match (must, wan) {
                    (true, _) => (TC_ACT_SHOT, None),
                    (false, false) => (TC_ACT_OK, Some(CLASSIFIED_MARK)),
                    (false, true) => (TC_ACT_OK, Some(0)),
                };
                let before_handoff =
                    hash_count::<TuplesKey, RoutingHandoffEntry>(&backend, "ROUTING_HANDOFF_MAP");
                let source_port = 42000 + index as u16;
                for (label, packet) in [
                    (
                        "UDP",
                        packet(source, destination, IPPROTO_UDP, source_port, 443, 0, 0),
                    ),
                    (
                        "UDP following",
                        packet(source, destination, IPPROTO_UDP, source_port, 443, 0, 0),
                    ),
                    (
                        "TCP SYN",
                        packet(source, destination, IPPROTO_TCP, source_port, 443, 0, 0x02),
                    ),
                    (
                        "TCP following",
                        packet(source, destination, IPPROTO_TCP, source_port, 443, 0, 0x10),
                    ),
                ] {
                    let result = run(&backend, side, &packet, SkbInput::default());
                    let context = format!("{side} {label} {destination} must={must}");
                    assert_eq!(result.verdict, expected_verdict, "{context}");
                    if let Some(mark) = expected_mark {
                        assert_eq!(result.mark, mark, "{context}");
                    }
                }
                assert_eq!(
                    hash_count::<TuplesKey, RoutingHandoffEntry>(&backend, "ROUTING_HANDOFF_MAP"),
                    before_handoff,
                    "{side} {destination} must={must}: no userspace handoff"
                );
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn rule_direct_prefix_offload_preserves_global_handoffs() {
    isolated(|| {
        let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 80));
        let rules = [
            rule(
                "early-direct",
                RoutingCondition {
                    ip: vec![destination.to_string()],
                    ..Default::default()
                },
                "direct",
                0,
                false,
            ),
            rule(
                "later-domain",
                RoutingCondition {
                    domain: vec!["late.test".into()],
                    ..Default::default()
                },
                "proxy",
                0,
                false,
            ),
        ];
        let (mut backend, _, _listeners) = publish(&rules);
        let router = Router::new(&rules, "direct").unwrap();
        let plan =
            RoutingPushPlan::compile(&router, &outbound_ids(), DialMode::DomainPlusPlus).unwrap();
        backend.publish_routing_plan(&plan, &[]).unwrap();
        for (flags, base_port) in [(0, 43000), (DATAPATH_FLAG_OFFLOAD_RULE_DIRECT, 43010)] {
            backend.set_datapath_flags(flags).unwrap();
            for (wan, side) in [(false, "lan_ingress_l2"), (true, "wan_egress_l2")] {
                let source = IpAddr::V4(Ipv4Addr::new(10 + wan as u8, 0, 0, 2));
                for protocol in [IPPROTO_TCP, IPPROTO_UDP] {
                    let source_port = base_port + protocol as u16;
                    let before_handoff = hash_count::<TuplesKey, RoutingHandoffEntry>(
                        &backend,
                        "ROUTING_HANDOFF_MAP",
                    );
                    for tcp_flags in if protocol == IPPROTO_TCP {
                        [0x02, 0x10]
                    } else {
                        [0, 0]
                    } {
                        let packet = packet(
                            source,
                            destination,
                            protocol,
                            source_port,
                            443,
                            0,
                            tcp_flags,
                        );
                        let result = run(&backend, side, &packet, SkbInput::default());
                        let context =
                            format!("{side} protocol={protocol} flags={flags} tcp={tcp_flags}");
                        if flags == 0 {
                            assert_eq!(result.verdict, TC_ACT_REDIRECT, "{context}");
                            let key = tuple(source, destination, source_port, 443, protocol);
                            assert_eq!(
                                handoff(&backend, &key).result.outbound,
                                OutboundIndex::ControlPlaneRouting as u8,
                                "{context}"
                            );
                        } else {
                            assert_eq!(result.verdict, TC_ACT_OK, "{context}");
                            assert_eq!(
                                result.mark,
                                if wan { 0 } else { CLASSIFIED_MARK },
                                "{context}"
                            );
                            assert_eq!(
                                hash_count::<TuplesKey, RoutingHandoffEntry>(
                                    &backend,
                                    "ROUTING_HANDOFF_MAP"
                                ),
                                before_handoff,
                                "{context}"
                            );
                        }
                    }
                }
            }
        }
    });
}
