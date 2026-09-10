use super::*;
mod readiness;
use crate::control::routing_matcher::RoutingPushPlan;
use crate::routing::{ConnectionInfo, Router, golden};
use honk_config::types::DialMode;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
fn input(connection: &ConnectionInfo) -> RoutingInput {
    fn bytes(ip: IpAddr) -> [u8; 16] {
        match ip {
            IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
            IpAddr::V6(ip) => ip.octets(),
        }
    }
    let mut input = RoutingInput {
        src_ip: bytes(connection.src_ip),
        dst_ip: bytes(connection.dst_ip),
        src_port: connection.src_port as u32,
        dst_port: connection.dst_port as u32,
        l4proto: if connection.protocol == "tcp" { 1 } else { 2 },
        ip_version: if connection.dst_ip.is_ipv4() { 1 } else { 2 },
        dscp: connection.dscp.map_or(u32::MAX, u32::from),
        is_wan: connection.process_name.is_some() as u32,
        ..Default::default()
    };
    if let Some(name) = &connection.process_name {
        assert!(name.len() <= input.pname.len());
        input.pname[..name.len()].copy_from_slice(name.as_bytes());
        input.pname_len = name.len() as u32;
    }
    if let Some(mac) = &connection.mac {
        for (index, byte) in mac.split(':').enumerate() {
            input.mac[10 + index] = u8::from_str_radix(byte, 16).unwrap();
        }
        input.mac_present = 1;
    }
    input
}

fn object() -> Vec<u8> {
    let path = std::env::var_os("HONK_ROUTING_TEST_OBJECT")
        .expect("build honk-ebpf --features routing-test and set HONK_ROUTING_TEST_OBJECT");
    std::fs::read(path).expect("read routing-test object")
}

fn outbound_ids() -> HashMap<String, u8> {
    HashMap::from([
        ("direct".into(), 0),
        ("block".into(), 1),
        ("proxy".into(), 2),
    ])
}

fn rule(
    name: &str,
    condition: honk_config::routing::RoutingCondition,
    outbound: &str,
    mark: u32,
    must: bool,
) -> honk_config::routing::RoutingRule {
    honk_config::routing::RoutingRule {
        name: name.into(),
        condition,
        outbound: honk_config::routing::RoutingOutbound::Simple(outbound.into()),
        priority: 0,
        must,
        mark,
    }
}

fn decision(
    outbound: u32,
    mark: u32,
    must: bool,
    domain_final: u32,
    rule_id: u32,
) -> RoutingDecision {
    RoutingDecision {
        outbound,
        mark,
        must: must as u32,
        domain_final,
        rule_id,
    }
}

fn assert_route(
    backend: &mut RealEbpfBackend,
    label: &str,
    input: &RoutingInput,
    expected: RoutingDecision,
) {
    let actual = backend.run_routing_test(input).unwrap();
    assert_eq!(actual.status, 0, "{label}: program status");
    assert_eq!(actual.decision, expected, "{label}: complete decision");
}

fn domain_entry(
    router: &Router,
    connection: &ConnectionInfo,
    domain: &str,
) -> (LpmKey, DomainRouting) {
    (
        crate::ebpf::maps::ip_addr_to_lpm_key(connection.dst_ip),
        router.domain_bitmap(domain).unwrap(),
    )
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn lazy_fact_cache_short_circuit_reuse_and_alternating_inputs() {
    use honk_config::routing::{RoutingCondition, RoutingNotCondition};

    let rules = vec![
        rule(
            "domain-short-circuits-first-facts",
            RoutingCondition {
                domain: vec!["never.test".into()],
                ip: vec!["192.0.2.10".into()],
                source_ip: vec!["198.51.100.10".into()],
                mac: vec!["02:00:00:00:00:0a".into()],
                ..Default::default()
            },
            "block",
            0x801,
            false,
        ),
        rule(
            "destination-used-before-port-failure",
            RoutingCondition {
                ip: vec!["192.0.2.10".into()],
                port: vec!["1".into()],
                ..Default::default()
            },
            "block",
            0x802,
            false,
        ),
        rule(
            "source-used-before-port-failure",
            RoutingCondition {
                source_ip: vec!["198.51.100.10".into()],
                port: vec!["1".into()],
                ..Default::default()
            },
            "block",
            0x803,
            false,
        ),
        rule(
            "mac-used-before-version-failure",
            RoutingCondition {
                mac: vec!["02:00:00:00:00:0a".into()],
                ip_version: vec!["6".into()],
                ..Default::default()
            },
            "block",
            0x804,
            false,
        ),
        rule(
            "mixed-positive-and-negative-reuse",
            RoutingCondition {
                domain: vec!["a.test".into()],
                ip: vec!["192.0.2.10".into()],
                source_ip: vec!["198.51.100.10".into()],
                port: vec!["8443".into()],
                source_port: vec!["40000".into()],
                protocol: vec!["tcp".into()],
                mac: vec!["02:00:00:00:00:0a".into()],
                ip_version: vec!["4".into()],
                dscp: vec!["0".into()],
                not: RoutingNotCondition {
                    domain: vec!["b.test".into()],
                    ip: vec!["192.0.2.20".into()],
                    source_ip: vec!["198.51.100.20".into()],
                    port: vec!["1".into()],
                    source_port: vec!["1".into()],
                    protocol: vec!["udp".into()],
                    process_name: vec!["forbidden".into()],
                    mac: vec!["02:00:00:00:00:14".into()],
                    ip_version: vec!["6".into()],
                    dscp: vec!["46".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            "proxy",
            0x805,
            true,
        ),
        rule(
            "alternating-b",
            RoutingCondition {
                domain: vec!["b.test".into()],
                ip: vec!["192.0.2.20".into()],
                source_ip: vec!["198.51.100.20".into()],
                mac: vec!["02:00:00:00:00:14".into()],
                ..Default::default()
            },
            "block",
            0x806,
            false,
        ),
    ];
    let router = Router::new(&rules, "direct").unwrap();
    let plan =
        RoutingPushPlan::compile(&router, &outbound_ids(), "direct", DialMode::Domain).unwrap();
    let mut a = golden::connection();
    a.domain = Some("a.test".into());
    a.dst_ip = "192.0.2.10".parse().unwrap();
    a.src_ip = "198.51.100.10".parse().unwrap();
    a.mac = Some("02:00:00:00:00:0a".into());
    let mut b = a.clone();
    b.domain = Some("b.test".into());
    b.dst_ip = "192.0.2.20".parse().unwrap();
    b.src_ip = "198.51.100.20".parse().unwrap();
    b.mac = Some("02:00:00:00:00:14".into());
    let learned = [
        domain_entry(&router, &a, "a.test"),
        domain_entry(&router, &b, "b.test"),
    ];
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    backend.publish_routing_plan(&plan, &learned).unwrap();

    for (round, connection, expected) in [
        ("A1", &a, decision(2, 0x805, true, 1, 4)),
        ("B1", &b, decision(1, 0x806, false, 1, 5)),
        ("A2", &a, decision(2, 0x805, true, 1, 4)),
        ("B2", &b, decision(1, 0x806, false, 1, 5)),
    ] {
        assert_route(&mut backend, round, &input(connection), expected);
    }

    let changed_rules = vec![
        rule(
            "changed-generation-positive",
            RoutingCondition {
                ip: vec!["192.0.2.99".into()],
                source_ip: vec!["198.51.100.99".into()],
                mac: vec!["02:00:00:00:00:63".into()],
                ..Default::default()
            },
            "proxy",
            0x807,
            false,
        ),
        rule(
            "changed-generation-negative",
            RoutingCondition {
                not: RoutingNotCondition {
                    ip: vec!["192.0.2.99".into()],
                    source_ip: vec!["198.51.100.99".into()],
                    mac: vec!["02:00:00:00:00:63".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            "block",
            0x808,
            false,
        ),
    ];
    let changed_router = Router::new(&changed_rules, "direct").unwrap();
    let changed =
        RoutingPushPlan::compile(&changed_router, &outbound_ids(), "direct", DialMode::Domain)
            .unwrap();
    backend.publish_routing_plan(&changed, &[]).unwrap();
    assert_route(
        &mut backend,
        "generation changed all facts and removed domain",
        &input(&a),
        decision(1, 0x808, false, 1, 1),
    );
    backend.publish_routing_plan(&plan, &[]).unwrap();
    assert_route(
        &mut backend,
        "domain generation absent after no-domain generation",
        &input(&a),
        decision(0, 0, false, 0, u32::MAX),
    );
    backend.publish_routing_plan(&plan, &learned).unwrap();
    assert_route(
        &mut backend,
        "domain and original facts restored in later generation",
        &input(&a),
        decision(2, 0x805, true, 1, 4),
    );
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn lazy_fact_cache_ipv6_host_overlap_and_default_prefix() {
    use honk_config::routing::RoutingCondition;

    let rules = vec![
        rule(
            "host-prefix-then-port-failure",
            RoutingCondition {
                ip: vec!["2001:db8:1::42/128".into()],
                source_ip: vec!["2001:db8:2::7/128".into()],
                port: vec!["1".into()],
                ..Default::default()
            },
            "direct",
            0x811,
            false,
        ),
        rule(
            "parent-prefix-reuses-host-result",
            RoutingCondition {
                ip: vec!["2001:db8:1::/48".into()],
                source_ip: vec!["2001:db8:2::/48".into()],
                mac: vec!["02:00:00:00:00:66".into()],
                ip_version: vec!["6".into()],
                ..Default::default()
            },
            "proxy",
            0x812,
            true,
        ),
        rule(
            "ipv6-default-prefix",
            RoutingCondition {
                ip: vec!["::/0".into()],
                source_ip: vec!["::/0".into()],
                mac: vec!["02:00:00:00:00:66".into()],
                ..Default::default()
            },
            "block",
            0x813,
            false,
        ),
    ];
    let router = Router::new(&rules, "direct").unwrap();
    let plan = RoutingPushPlan::compile(&router, &outbound_ids(), "direct", DialMode::Ip).unwrap();
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    backend.publish_routing_plan(&plan, &[]).unwrap();

    let mut host = golden::connection();
    host.dst_ip = "2001:db8:1::42".parse().unwrap();
    host.src_ip = "2001:db8:2::7".parse().unwrap();
    host.mac = Some("02:00:00:00:00:66".into());
    assert_route(
        &mut backend,
        "IPv6 /128 lookup reused by overlapping /48",
        &input(&host),
        decision(2, 0x812, true, 1, 1),
    );

    let mut outside = host;
    outside.dst_ip = "2001:db9::42".parse().unwrap();
    outside.src_ip = "2001:dba::7".parse().unwrap();
    assert_route(
        &mut backend,
        "IPv6 /0 after specific destination short circuits source",
        &input(&outside),
        decision(1, 0x813, false, 1, 2),
    );
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn lazy_fact_cache_null_zero_mac_presence_and_invalid_family() {
    use honk_config::routing::{RoutingCondition, RoutingNotCondition};

    let facts = vec![
        rule(
            "positive-facts",
            RoutingCondition {
                ip: vec!["192.0.2.30".into()],
                source_ip: vec!["198.51.100.30".into()],
                mac: vec!["02:00:00:00:00:1e".into()],
                ..Default::default()
            },
            "proxy",
            0x821,
            false,
        ),
        rule(
            "negated-facts",
            RoutingCondition {
                not: RoutingNotCondition {
                    ip: vec!["192.0.2.30".into()],
                    source_ip: vec!["198.51.100.30".into()],
                    mac: vec!["02:00:00:00:00:1e".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            "block",
            0x822,
            true,
        ),
    ];
    let router = Router::new(&facts, "direct").unwrap();
    let mut zero_plan =
        RoutingPushPlan::compile(&router, &outbound_ids(), "direct", DialMode::Ip).unwrap();
    for entries in [
        &mut zero_plan.facts.destination_v4,
        &mut zero_plan.facts.destination_v6,
        &mut zero_plan.facts.source_v4,
        &mut zero_plan.facts.source_v6,
        &mut zero_plan.facts.mac,
    ] {
        for (_, bitmap) in entries {
            *bitmap = DomainRouting::default();
        }
    }
    let mut null_plan = zero_plan.clone();
    null_plan.facts = Default::default();
    let mut connection = golden::connection();
    connection.dst_ip = "192.0.2.30".parse().unwrap();
    connection.src_ip = "198.51.100.30".parse().unwrap();
    connection.mac = Some("02:00:00:00:00:1e".into());
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    for (label, plan) in [
        ("present zero bitmap", &zero_plan),
        ("NULL map miss", &null_plan),
    ] {
        backend.publish_routing_plan(plan, &[]).unwrap();
        assert_route(
            &mut backend,
            label,
            &input(&connection),
            decision(1, 0x822, true, 1, 1),
        );
    }

    let mac_rules = vec![
        rule(
            "present-all-zero-mac",
            RoutingCondition {
                mac: vec!["00:00:00:00:00:00".into()],
                ..Default::default()
            },
            "proxy",
            0x823,
            false,
        ),
        rule(
            "absent-or-different-mac",
            RoutingCondition {
                not: RoutingNotCondition {
                    mac: vec!["00:00:00:00:00:00".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            "block",
            0x824,
            false,
        ),
    ];
    let mac_router = Router::new(&mac_rules, "direct").unwrap();
    let mac_plan =
        RoutingPushPlan::compile(&mac_router, &outbound_ids(), "direct", DialMode::Ip).unwrap();
    backend.publish_routing_plan(&mac_plan, &[]).unwrap();
    let mut zero_mac = golden::connection();
    zero_mac.mac = Some("00:00:00:00:00:00".into());
    let absent_mac = golden::connection();
    for (label, connection, expected) in [
        (
            "present all-zero MAC",
            &zero_mac,
            decision(2, 0x823, false, 1, 0),
        ),
        ("absent MAC", &absent_mac, decision(1, 0x824, false, 1, 1)),
        (
            "present all-zero MAC again",
            &zero_mac,
            decision(2, 0x823, false, 1, 0),
        ),
    ] {
        assert_route(&mut backend, label, &input(connection), expected);
    }

    let family_rules = vec![
        rule(
            "valid-family",
            RoutingCondition {
                ip: vec!["192.0.2.30".into()],
                source_ip: vec!["198.51.100.30".into()],
                ..Default::default()
            },
            "proxy",
            0x825,
            false,
        ),
        rule(
            "invalid-family-negation",
            RoutingCondition {
                not: RoutingNotCondition {
                    ip: vec!["192.0.2.30".into()],
                    source_ip: vec!["198.51.100.30".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            "block",
            0x826,
            false,
        ),
    ];
    let family_router = Router::new(&family_rules, "direct").unwrap();
    let family_plan =
        RoutingPushPlan::compile(&family_router, &outbound_ids(), "direct", DialMode::Ip).unwrap();
    backend.publish_routing_plan(&family_plan, &[]).unwrap();
    let valid = input(&connection);
    assert_route(
        &mut backend,
        "valid IPv4 family",
        &valid,
        decision(2, 0x825, false, 1, 0),
    );
    for family in [0, 3] {
        let mut invalid = valid;
        invalid.ip_version = family;
        assert_route(
            &mut backend,
            &format!("invalid family {family}"),
            &invalid,
            decision(1, 0x826, false, 1, 1),
        );
    }
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn four_mode_golden_policies() {
    let (router, cases) = golden::fixtures();
    let ids = outbound_ids();
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    let mut comparisons = 0;
    for mode in [
        DialMode::Ip,
        DialMode::Domain,
        DialMode::DomainPlus,
        DialMode::DomainPlusPlus,
    ] {
        let plan = RoutingPushPlan::compile(&router, &ids, "direct", mode).unwrap();
        backend.publish_routing_plan(&plan, &[]).unwrap();
        let mut present = HashSet::new();
        for case in &cases {
            let input = input(&case.connection);
            let key = LpmKey {
                prefix_len: 128,
                data: std::array::from_fn(|index| {
                    u32::from_ne_bytes(input.dst_ip[index * 4..index * 4 + 4].try_into().unwrap())
                }),
            };
            let bitmap = case
                .connection
                .domain
                .as_deref()
                .and_then(|domain| router.domain_bitmap(domain));
            if let Some(bitmap) = bitmap {
                backend.set_domain_ip_bitmap(&key, &bitmap).unwrap();
                present.insert(key.data);
            } else if present.remove(&key.data) {
                backend.remove_domain_ip_bitmap(&key).unwrap();
            }
            let mut expected = case.decision;
            expected.domain_final = (!matches!(mode, DialMode::Domain | DialMode::DomainPlusPlus)
                || bitmap.is_some()) as u32;
            if mode == DialMode::DomainPlusPlus && case.generic_port_punt {
                expected.outbound = OutboundIndex::ControlPlaneRouting as u32;
            }
            if input.dst_port == 53 && expected.must == 0 {
                expected.outbound = OutboundIndex::ControlPlaneRouting as u32;
            }
            let actual = backend.run_routing_test(&input).unwrap();
            assert_eq!(actual.status, 0, "{:?}/{}", mode, case.label);
            assert_eq!(actual.decision, expected, "{:?}/{}", mode, case.label);
            comparisons += 1;
        }
    }
    eprintln!("native routing: {comparisons} complete-decision golden comparisons");
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn large_prefix_fact_policy() {
    let ids = outbound_ids();
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    let prefixes = (0..=65_536u32)
        .map(|offset| format!("{}/32", std::net::Ipv4Addr::from(0x0a00_0000u32 + offset)))
        .collect();
    let large_router = Router::new(
        &[honk_config::routing::RoutingRule {
            name: "large-ip-fact".into(),
            condition: honk_config::routing::RoutingCondition {
                ip: prefixes,
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("proxy".into()),
            priority: 0,
            must: false,
            mark: 0x500,
        }],
        "direct",
    )
    .unwrap();
    let large_plan = RoutingPushPlan::compile(&large_router, &ids, "direct", DialMode::Ip).unwrap();
    backend.publish_routing_plan(&large_plan, &[]).unwrap();
    let large_match = RoutingDecision {
        outbound: 2,
        mark: 0x500,
        must: 0,
        domain_final: 1,
        rule_id: 0,
    };
    for destination in ["10.0.0.0", "10.1.0.0"] {
        let mut connection = golden::connection();
        connection.dst_ip = destination.parse().unwrap();
        let observed = backend.run_routing_test(&input(&connection)).unwrap();
        assert_eq!(observed.status, 0);
        assert_eq!(observed.decision, large_match);
    }
    let mut outside = golden::connection();
    outside.dst_ip = "10.1.0.1".parse().unwrap();
    let observed = backend.run_routing_test(&input(&outside)).unwrap();
    assert_eq!(observed.status, 0);
    assert_eq!(
        observed.decision,
        RoutingDecision {
            outbound: 0,
            mark: 0,
            must: 0,
            domain_final: 1,
            rule_id: u32::MAX,
        }
    );
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn predicate_bits_and_capacity_limits() {
    let ids = outbound_ids();
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    for domains in [true, false] {
        let rules = (0..256)
            .map(|index| honk_config::routing::RoutingRule {
                name: format!("capacity-{index}"),
                condition: if domains {
                    honk_config::routing::RoutingCondition {
                        domain: vec![format!("fact-{index}.test")],
                        ..Default::default()
                    }
                } else {
                    honk_config::routing::RoutingCondition {
                        ip: vec![format!("192.0.2.{index}")],
                        source_ip: vec![format!("198.51.100.{index}")],
                        mac: vec![format!("02:00:00:00:00:{index:02x}")],
                        ..Default::default()
                    }
                },
                outbound: honk_config::routing::RoutingOutbound::Simple("proxy".into()),
                priority: 0,
                must: false,
                mark: 0x600 + index,
            })
            .collect::<Vec<_>>();
        let router = Router::new(&rules, "direct").unwrap();
        let plan = RoutingPushPlan::compile(&router, &ids, "direct", DialMode::Ip).unwrap();
        if !domains {
            backend.publish_routing_plan(&plan, &[]).unwrap();
        }
        let mut preserved_input = RoutingInput::default();
        for index in [0, 31, 32, 63, 64, 255] {
            let mut connection = golden::connection();
            if domains {
                let learned = [domain_entry(
                    &router,
                    &connection,
                    &format!("fact-{index}.test"),
                )];
                backend.publish_routing_plan(&plan, &learned).unwrap();
            } else {
                connection.dst_ip = format!("192.0.2.{index}").parse().unwrap();
                connection.src_ip = format!("198.51.100.{index}").parse().unwrap();
                connection.mac = Some(format!("02:00:00:00:00:{index:02x}"));
            }
            preserved_input = input(&connection);
            assert_route(
                &mut backend,
                &format!(
                    "{}/predicate bit {index}",
                    if domains {
                        "domain"
                    } else {
                        "destination/source/MAC"
                    }
                ),
                &preserved_input,
                decision(2, 0x600 + index, false, 1, index),
            );
        }
        let mut overflow = rules.clone();
        overflow.push(honk_config::routing::RoutingRule {
            name: "overflow".into(),
            condition: if domains {
                honk_config::routing::RoutingCondition {
                    domain: vec!["fact-overflow.test".into()],
                    ..Default::default()
                }
            } else {
                honk_config::routing::RoutingCondition {
                    ip: vec!["203.0.113.1".into()],
                    ..Default::default()
                }
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("proxy".into()),
            priority: 0,
            must: false,
            mark: 0,
        });
        let rejected = Router::new(&overflow, "direct")
            .and_then(|router| RoutingPushPlan::compile(&router, &ids, "direct", DialMode::Ip));
        assert!(rejected.is_err());
        assert_route(
            &mut backend,
            "capacity rejection preserves prior generation",
            &preserved_input,
            decision(2, 0x6ff, false, 1, 255),
        );
    }
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn publication_failure_recovery_and_frozen_root() {
    let ids = outbound_ids();
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    let initial_rules = (0..256)
        .map(|index| honk_config::routing::RoutingRule {
            name: format!("initial-{index}"),
            condition: honk_config::routing::RoutingCondition {
                ip: vec![format!("192.0.2.{index}")],
                source_ip: vec![format!("198.51.100.{index}")],
                mac: vec![format!("02:00:00:00:00:{index:02x}")],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("proxy".into()),
            priority: 0,
            must: false,
            mark: 0x600 + index,
        })
        .collect::<Vec<_>>();
    let initial_router = Router::new(&initial_rules, "direct").unwrap();
    let initial_plan =
        RoutingPushPlan::compile(&initial_router, &ids, "direct", DialMode::Ip).unwrap();
    backend.publish_routing_plan(&initial_plan, &[]).unwrap();

    let mut active_hit_connection = golden::connection();
    active_hit_connection.dst_ip = "192.0.2.255".parse().unwrap();
    active_hit_connection.src_ip = "198.51.100.255".parse().unwrap();
    active_hit_connection.mac = Some("02:00:00:00:00:ff".into());
    let active_hit = input(&active_hit_connection);
    let mut active_miss_connection = active_hit_connection.clone();
    active_miss_connection.src_ip = "203.0.113.1".parse().unwrap();
    let active_miss = input(&active_miss_connection);
    let active_hit_decision = RoutingDecision {
        outbound: 2,
        mark: 0x6ff,
        must: 0,
        domain_final: 1,
        rule_id: 255,
    };
    let active_miss_decision = RoutingDecision {
        outbound: 0,
        mark: 0,
        must: 0,
        domain_final: 1,
        rule_id: u32::MAX,
    };
    assert_eq!(
        backend.run_routing_test(&active_hit).unwrap().decision,
        active_hit_decision
    );
    assert_eq!(
        backend.run_routing_test(&active_miss).unwrap().decision,
        active_miss_decision
    );
    let old_slot = backend.active_routing_generation().unwrap();

    let recovery_rule = honk_config::routing::RoutingRule {
        name: "publication-recovery".into(),
        condition: honk_config::routing::RoutingCondition {
            ip: vec!["192.0.2.255".into()],
            source_ip: vec!["198.51.100.255".into()],
            mac: vec!["02:00:00:00:00:ff".into()],
            ..Default::default()
        },
        outbound: honk_config::routing::RoutingOutbound::Simple("block".into()),
        priority: 0,
        must: false,
        mark: 0x700,
    };
    let recovery_router = Router::new(std::slice::from_ref(&recovery_rule), "direct").unwrap();
    let recovery =
        RoutingPushPlan::compile(&recovery_router, &ids, "direct", DialMode::Ip).unwrap();
    let mut map_fill_candidate = recovery.clone();
    map_fill_candidate
        .facts
        .destination_v4
        .first_mut()
        .expect("recovery plan destination fact")
        .0
        .prefix_len = 129;
    let map_fill_error = backend
        .publish_routing_plan(&map_fill_candidate, &[])
        .unwrap_err();
    assert!(
        map_fill_error
            .downcast_ref::<aya::maps::MapError>()
            .is_some(),
        "candidate fact-map fill did not fail in the map stage: {map_fill_error:#}"
    );
    assert_route(
        &mut backend,
        "map-fill failure preserves active hit",
        &active_hit,
        active_hit_decision,
    );
    assert_route(
        &mut backend,
        "map-fill failure preserves active miss",
        &active_miss,
        active_miss_decision,
    );
    assert_eq!(backend.active_routing_generation().unwrap(), old_slot);
    let inactive_slot = old_slot ^ 1;
    let inactive_name = ROUTING_SLOT_NAMES[inactive_slot as usize];
    let targets = backend.routing_targets(inactive_name).unwrap();
    let maps = create_maps(&recovery.facts, &[]).unwrap();
    let bytecode =
        crate::control::routing_matcher::codegen::emit_routing_program(&recovery, maps.fds())
            .unwrap();
    let (_btf, program) = load_extension(&targets[0], inactive_name, &bytecode).unwrap();
    let occupied = attach_extension(&program, targets.last().unwrap()).unwrap();
    assert!(backend.publish_routing_plan(&recovery, &[]).is_err());
    assert_eq!(
        backend.run_routing_test(&active_hit).unwrap().decision,
        active_hit_decision
    );
    assert_eq!(
        backend.run_routing_test(&active_miss).unwrap().decision,
        active_miss_decision
    );
    assert_eq!(backend.active_routing_generation().unwrap(), old_slot);
    drop(occupied);
    drop(program);
    drop(maps);

    backend.publish_routing_plan(&recovery, &[]).unwrap();
    let recovered_slot = backend.active_routing_generation().unwrap();
    assert_eq!(recovered_slot, inactive_slot);
    let recovered_hit_decision = RoutingDecision {
        outbound: 1,
        mark: 0x700,
        must: 0,
        domain_final: 1,
        rule_id: 0,
    };
    assert_eq!(
        backend.run_routing_test(&active_hit).unwrap().decision,
        recovered_hit_decision
    );
    assert_eq!(
        backend.run_routing_test(&active_miss).unwrap().decision,
        active_miss_decision
    );

    let mut root_candidate_rule = recovery_rule;
    root_candidate_rule.name = "root-failure".into();
    root_candidate_rule.outbound = honk_config::routing::RoutingOutbound::Simple("proxy".into());
    root_candidate_rule.mark = 0x701;
    let root_candidate_router =
        Router::new(std::slice::from_ref(&root_candidate_rule), "direct").unwrap();
    let root_candidate =
        RoutingPushPlan::compile(&root_candidate_router, &ids, "direct", DialMode::Ip).unwrap();
    let root_candidate_slot = recovered_slot ^ 1;
    let root_candidate_name = ROUTING_SLOT_NAMES[root_candidate_slot as usize];
    let root_candidate_targets = backend.routing_targets(root_candidate_name).unwrap();

    // Freezing only the real root makes its root-last update fail with EPERM.
    let aya::maps::Map::ArrayOfMaps(root) = backend
        .bpf()
        .unwrap()
        .map(ROUTING_POLICY_ROOT_NAME)
        .unwrap()
    else {
        panic!("routing root is not an array of maps");
    };
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = root.fd().as_fd().as_raw_fd() as u32;
    bpf_syscall(bpf_cmd::BPF_MAP_FREEZE, &mut attr).unwrap();

    let root_error = backend
        .publish_routing_plan(&root_candidate, &[])
        .unwrap_err();
    assert!(
        matches!(
            root_error.downcast_ref::<aya::maps::MapError>(),
            Some(aya::maps::MapError::SyscallError(error))
                if error.io_error.raw_os_error() == Some(libc::EPERM)
        ),
        "{root_error:#}"
    );
    assert_eq!(
        backend.run_routing_test(&active_hit).unwrap().decision,
        recovered_hit_decision
    );
    assert_eq!(
        backend.run_routing_test(&active_miss).unwrap().decision,
        active_miss_decision
    );
    assert_eq!(backend.active_routing_generation().unwrap(), recovered_slot);

    // Every root-failed candidate link must have unwound from the inactive targets.
    let probe_maps = create_maps(&root_candidate.facts, &[]).unwrap();
    let probe_bytecode = crate::control::routing_matcher::codegen::emit_routing_program(
        &root_candidate,
        probe_maps.fds(),
    )
    .unwrap();
    let (_probe_btf, probe_program) = load_extension(
        &root_candidate_targets[0],
        root_candidate_name,
        &probe_bytecode,
    )
    .unwrap();
    let _released_links = root_candidate_targets
        .iter()
        .map(|target| attach_extension(&probe_program, target))
        .collect::<anyhow::Result<Vec<_>>>()
        .unwrap();
}
