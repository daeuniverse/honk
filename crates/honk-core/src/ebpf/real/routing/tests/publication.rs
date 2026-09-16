use super::super::{attach_extension, bpf_syscall, create_maps, load_extension};
use super::{assert_route, input, object, outbound_ids, rule};
use crate::control::routing_matcher::RoutingPushPlan;
use crate::ebpf::EbpfBackend;
use crate::ebpf::real::RealEbpfBackend;
use crate::routing::{Router, golden};
use aya_obj::generated::{bpf_attr, bpf_cmd};
use honk_config::types::DialMode;
use honk_ebpf_common::{
    DATAPATH_FLAG_NFQ_ENABLED, DATAPATH_FLAG_NFQ_READY, DNS_ROUTE_GENERATION_MAX, DaeParam,
    ROUTING_POLICY_ROOT_NAME, ROUTING_SLOT_NAMES, RoutingDecision,
};
use std::os::fd::{AsFd, AsRawFd};

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn publication_failure_recovery_and_frozen_root() {
    let ids = outbound_ids();
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
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
    let old_slot = backend.active_routing_slot().unwrap();

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
    assert_eq!(backend.active_routing_slot().unwrap(), old_slot);
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
    assert_eq!(backend.active_routing_slot().unwrap(), old_slot);
    drop(occupied);
    drop(program);
    drop(maps);

    backend.publish_routing_plan(&recovery, &[]).unwrap();
    let recovered_slot = backend.active_routing_slot().unwrap();
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

    freeze_root(&backend);

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
    assert_eq!(backend.active_routing_slot().unwrap(), recovered_slot);

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

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn routing_generation_ceiling_preserves_the_committed_root() {
    let old_rules = [rule(
        "old-root",
        honk_config::routing::RoutingCondition {
            port: vec!["8443".into()],
            ..Default::default()
        },
        "proxy",
        0x808,
        false,
    )];
    let replacement_rules = [rule(
        "replacement",
        honk_config::routing::RoutingCondition {
            port: vec!["8443".into()],
            ..Default::default()
        },
        "block",
        0x909,
        false,
    )];
    let ids = outbound_ids();
    let old_router = Router::new(&old_rules, "direct").unwrap();
    let replacement_router = Router::new(&replacement_rules, "direct").unwrap();
    let old = RoutingPushPlan::compile(&old_router, &ids, "direct", DialMode::Ip).unwrap();
    let replacement =
        RoutingPushPlan::compile(&replacement_router, &ids, "direct", DialMode::Ip).unwrap();
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
    backend
        .routing_generation_sequence
        .set(0, DNS_ROUTE_GENERATION_MAX - 1, 0)
        .unwrap();
    backend.publish_routing_plan(&old, &[]).unwrap();
    assert_eq!(
        backend.routing_policy_generation(),
        DNS_ROUTE_GENERATION_MAX
    );

    let mut connection = golden::connection();
    connection.dst_port = 8443;
    let input = input(&connection);
    let committed = backend.run_routing_test(&input).unwrap();
    assert_eq!(committed.decision.outbound, 2);
    assert_eq!(committed.decision.mark, 0x808);

    assert!(backend.publish_routing_plan(&replacement, &[]).is_err());
    assert_eq!(
        backend.routing_policy_generation(),
        DNS_ROUTE_GENERATION_MAX
    );
    assert_eq!(
        backend.run_routing_test(&input).unwrap().decision,
        committed.decision
    );
    backend
        .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED)
        .unwrap();
    assert!(backend.quiesce_udp_staging().is_err());
    assert!(
        backend
            .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
            .is_err()
    );
    assert_eq!(
        backend.run_routing_test(&input).unwrap().decision,
        committed.decision
    );
}

fn freeze_root(backend: &RealEbpfBackend) {
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
}

fn published_descriptor(backend: &RealEbpfBackend) -> honk_ebpf_common::RoutingPolicyDescriptor {
    let root = backend
        .bpf()
        .unwrap()
        .map(ROUTING_POLICY_ROOT_NAME)
        .unwrap();
    let root =
        aya::maps::ArrayOfMaps::<_, super::super::RoutingDescriptor>::try_from(root).unwrap();
    root.get(&0, 0).unwrap().get(&0, 0).unwrap()
}

#[tokio::test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
async fn pinned_generation_survives_restart_and_failed_fence() {
    let pin_root = std::path::Path::new("/sys/fs/bpf").join(format!(
        "honk-routing-generation-test-{}",
        std::process::id()
    ));
    let object = object();
    let rules = [rule(
        "dns-owner",
        honk_config::routing::RoutingCondition {
            port: vec!["53".into()],
            ..Default::default()
        },
        "proxy",
        0x808,
        true,
    )];
    let router = Router::new(&rules, "direct").unwrap();
    let plan = RoutingPushPlan::compile(&router, &outbound_ids(), "direct", DialMode::Ip).unwrap();
    let mut connection = golden::connection();
    connection.dst_port = 53;
    let input = input(&connection);
    let mut backend = RealEbpfBackend::load(&object, &pin_root, 12345, None, "lo", false)
        .await
        .unwrap();
    backend.publish_routing_plan(&plan, &[]).unwrap();
    let initial = backend.routing_policy_generation();
    let decision = backend.run_routing_test(&input).unwrap().decision;
    assert_eq!(decision.outbound, 2);
    assert_eq!(decision.must, 1);
    let before = published_descriptor(&backend);

    backend
        .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED)
        .unwrap();
    backend.quiesce_udp_staging().unwrap();
    let fenced = backend.routing_policy_generation();
    assert!(fenced > initial);
    assert_eq!(backend.run_routing_test(&input).unwrap().decision, decision);
    assert_eq!(
        published_descriptor(&backend),
        honk_ebpf_common::RoutingPolicyDescriptor {
            generation: fenced,
            ..before
        }
    );
    backend
        .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
        .unwrap();

    freeze_root(&backend);
    assert!(backend.publish_routing_plan(&plan, &[]).is_err());
    let reserved = backend.routing_generation_sequence.get(&0, 0).unwrap();
    assert!(reserved > fenced);
    assert_eq!(backend.routing_policy_generation(), fenced);
    backend
        .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED)
        .unwrap();
    assert!(backend.quiesce_udp_staging().is_err());
    let failed_fence = backend.routing_generation_sequence.get(&0, 0).unwrap();
    assert!(failed_fence > reserved);
    assert_eq!(backend.routing_policy_generation(), fenced);
    assert_eq!(backend.run_routing_test(&input).unwrap().decision, decision);
    assert_eq!(
        published_descriptor(&backend),
        honk_ebpf_common::RoutingPolicyDescriptor {
            generation: fenced,
            ..before
        }
    );
    assert!(
        backend
            .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
            .is_err()
    );
    assert_eq!(
        backend.array_get::<u32>("DATAPATH_FLAGS_MAP", 0).unwrap(),
        Some(DATAPATH_FLAG_NFQ_ENABLED)
    );
    drop(backend);

    let mut reloaded = RealEbpfBackend::load(&object, &pin_root, 12345, None, "lo", false)
        .await
        .unwrap();
    reloaded.publish_routing_plan(&plan, &[]).unwrap();
    assert!(reloaded.routing_policy_generation() > failed_fence);
    assert_eq!(
        reloaded.run_routing_test(&input).unwrap().decision,
        decision
    );
    reloaded.cleanup().await.unwrap();
    for name in [
        crate::ebpf::UDP_DECISION_SEQUENCE_MAP,
        super::super::ROUTING_GENERATION_SEQUENCE_MAP,
    ] {
        std::fs::remove_file(pin_root.join(name)).unwrap();
    }
    std::fs::remove_dir(pin_root).unwrap();
}
