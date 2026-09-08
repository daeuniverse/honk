use super::*;
use crate::control::routing_matcher::RoutingMatcherBuilder;
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
#[ignore = "requires root, Linux 7.2+, and HONK_ROUTING_TEST_OBJECT"]
fn compiled_policy_matches_goldens_and_preserves_failed_root() {
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
        let plan = RoutingMatcherBuilder::compile(&router, &ids, "direct", mode).unwrap();
        RoutingMatcherBuilder::push_plan(&mut backend, &plan).unwrap();
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
        let plan = RoutingMatcherBuilder::compile(&router, &ids, "direct", DialMode::Ip).unwrap();
        RoutingMatcherBuilder::push_plan(&mut backend, &plan).unwrap();
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
        let rejected = Router::new(&overflow, "direct").and_then(|router| {
            RoutingMatcherBuilder::compile(&router, &ids, "direct", DialMode::Ip)
        });
        assert!(rejected.is_err());
        assert_eq!(
            backend.run_routing_test(&input(&connection)).unwrap(),
            observed
        );
    }

    let unchanged_input = input(&golden::connection());
    let before = backend.run_routing_test(&unchanged_input).unwrap();
    let old_slot = backend.active_routing_generation().unwrap();
    let replacement = RoutingMatcherBuilder::compile(
        &Router::new(&[], "block").unwrap(),
        &ids,
        "block",
        DialMode::Ip,
    )
    .unwrap();
    let targets = backend
        .routing_targets(ROUTING_SLOT_NAMES[(old_slot ^ 1) as usize])
        .unwrap();
    let maps = create_maps(&replacement.facts, &[]).unwrap();
    let bytecode = crate::control::routing_matcher::codegen::emit_routing_program(
        &replacement,
        crate::control::routing_matcher::codegen::RoutingMapFds {
            destination_v4: lpm_fd(&maps.destination_v4),
            destination_v6: lpm_fd(&maps.destination_v6),
            source_v4: lpm_fd(&maps.source_v4),
            source_v6: lpm_fd(&maps.source_v6),
            mac: lpm_fd(&maps.mac),
            domain: map_fd(&maps.domain),
        },
    )
    .unwrap();
    let (_btf, program) = load_extension(
        &targets[0],
        ROUTING_SLOT_NAMES[(old_slot ^ 1) as usize],
        &bytecode,
    )
    .unwrap();
    let occupied = attach_extension(&program, targets.last().unwrap()).unwrap();
    assert!(RoutingMatcherBuilder::push_plan(&mut backend, &replacement).is_err());
    assert_eq!(backend.run_routing_test(&unchanged_input).unwrap(), before);
    assert_eq!(backend.active_routing_generation().unwrap(), old_slot);
    drop(occupied);
    drop(program);
    drop(maps);

    // Freezing the real root forces the final syscall to fail after every inactive attachment.
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
    for _ in 0..2 {
        assert!(RoutingMatcherBuilder::push_plan(&mut backend, &replacement).is_err());
        assert_eq!(backend.run_routing_test(&unchanged_input).unwrap(), before);
        assert_eq!(backend.active_routing_generation().unwrap(), old_slot);
    }
}
