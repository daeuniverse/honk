use super::*;
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

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn four_mode_golden_policies() {
    let (router, cases) = golden::fixtures();
    let ids = HashMap::from([
        ("direct".into(), 0),
        ("block".into(), 1),
        ("proxy".into(), 2),
    ]);
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
    let ids = HashMap::from([
        ("direct".into(), 0),
        ("block".into(), 1),
        ("proxy".into(), 2),
    ]);
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
    let ids = HashMap::from([
        ("direct".into(), 0),
        ("block".into(), 1),
        ("proxy".into(), 2),
    ]);
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
        backend.publish_routing_plan(&plan, &[]).unwrap();
        let mut connection = golden::connection();
        if domains {
            let bitmap = router.domain_bitmap("fact-255.test").unwrap();
            assert_eq!(bitmap.bitmap[7], 1 << 31);
            backend
                .set_domain_ip_bitmap(
                    &crate::ebpf::maps::ip_addr_to_lpm_key(connection.dst_ip),
                    &bitmap,
                )
                .unwrap();
        } else {
            connection.dst_ip = "192.0.2.255".parse().unwrap();
            connection.src_ip = "198.51.100.255".parse().unwrap();
            connection.mac = Some("02:00:00:00:00:ff".into());
        }
        let observed = backend.run_routing_test(&input(&connection)).unwrap();
        assert_eq!(observed.status, 0);
        assert_eq!(
            observed.decision,
            RoutingDecision {
                outbound: 2,
                mark: 0x6ff,
                must: 0,
                domain_final: 1,
                rule_id: 255,
            }
        );
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
        assert_eq!(
            backend.run_routing_test(&input(&connection)).unwrap(),
            observed
        );
    }
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn publication_failure_recovery_and_frozen_root() {
    let ids = HashMap::from([
        ("direct".into(), 0),
        ("block".into(), 1),
        ("proxy".into(), 2),
    ]);
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
