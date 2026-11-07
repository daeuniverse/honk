//! More rules than the 256 bits of a fact category, all naming one IP list or
//! one MAC list, publish and decide per rule.

use super::{assert_route, decision, input, object, outbound_ids, rule};
use crate::control::routing_matcher::RoutingPushPlan;
use crate::ebpf::PolicyBackend;
use crate::ebpf::real::RealEbpfBackend;
use crate::routing::{Router, golden};
use honk_config::routing::RoutingCondition;
use honk_config::types::DialMode;
use honk_ebpf_common::{DaeParam, ROUTING_FACT_CAPACITY};
use serde_json::json;

fn publish_and_check(
    shared: serde_json::Value,
    matching: impl Fn(&mut crate::routing::ConnectionInfo),
    other: impl Fn(&mut crate::routing::ConnectionInfo),
) {
    let ports = ROUTING_FACT_CAPACITY + 1;
    let mut rules: Vec<_> = (0..ports)
        .map(|index| {
            let mut condition = shared.clone();
            condition["port"] = json!([(1000 + index).to_string()]);
            rule(
                "shared",
                serde_json::from_value::<RoutingCondition>(condition).unwrap(),
                "proxy",
                index as u32 + 1,
                false,
            )
        })
        .collect();
    let negated = json!({"not": shared.clone(), "port": ["5"]});
    rules.push(rule(
        "negated",
        serde_json::from_value::<RoutingCondition>(negated).unwrap(),
        "proxy",
        9999,
        false,
    ));
    let router = Router::new(&rules, "block").unwrap();
    let plan = RoutingPushPlan::compile(&router, &outbound_ids(), DialMode::Ip).unwrap();
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
    backend.publish_routing_plan(&plan, &[]).unwrap();

    for index in [0, 1, ROUTING_FACT_CAPACITY - 1, ROUTING_FACT_CAPACITY] {
        let mut hit = golden::connection();
        matching(&mut hit);
        hit.dst_port = 1000 + index as u16;
        assert_route(
            &mut backend,
            &format!("shared list, rule {index}"),
            &input(&hit),
            decision(2, index as u32 + 1, false, 1, index as u32),
        );
        let mut miss = golden::connection();
        other(&mut miss);
        miss.dst_port = 1000 + index as u16;
        assert_route(
            &mut backend,
            &format!("list miss, rule {index}"),
            &input(&miss),
            decision(1, 0, false, 1, u32::MAX),
        );
    }
    let mut negated_hit = golden::connection();
    other(&mut negated_hit);
    negated_hit.dst_port = 5;
    assert_route(
        &mut backend,
        "negated shared list",
        &input(&negated_hit),
        decision(2, 9999, false, 1, ports as u32),
    );
    let mut negated_miss = golden::connection();
    matching(&mut negated_miss);
    negated_miss.dst_port = 5;
    assert_route(
        &mut backend,
        "negated shared list, listed",
        &input(&negated_miss),
        decision(1, 0, false, 1, u32::MAX),
    );
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn rules_sharing_one_ip_list_exceed_the_per_category_fact_capacity() {
    publish_and_check(
        json!({"ip": ["198.51.100.0/24"]}),
        |c| c.dst_ip = "198.51.100.7".parse().unwrap(),
        |c| c.dst_ip = "192.0.2.9".parse().unwrap(),
    );
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn rules_sharing_one_mac_list_exceed_the_per_category_fact_capacity() {
    publish_and_check(
        json!({"mac": ["02:00:00:00:00:01"]}),
        |c| c.mac = Some("02:00:00:00:00:01".into()),
        |c| c.mac = Some("02:00:00:00:00:02".into()),
    );
}
