use super::{assert_route, decision, input, object, outbound_ids};
use crate::control::routing_matcher::RoutingPushPlan;
use crate::ebpf::EbpfBackend;
use crate::ebpf::real::RealEbpfBackend;
use crate::routing::golden::parsed;
use honk_config::types::DialMode;
use honk_ebpf_common::DaeParam;
use std::collections::HashSet;

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn parsed_predicates_match_independent_cases() {
    let sources = parsed::sources();
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), DaeParam::default()).unwrap();
    // Mirrors the backend's domain bitmap map, which outlives each case.
    let mut present = HashSet::new();
    let mut comparisons = 0;
    for case in parsed::cases() {
        let router = case.router(&sources);
        let has_domain = router.domain_predicate_count() != 0;
        for mode in [
            DialMode::Ip,
            DialMode::Domain,
            DialMode::DomainPlus,
            DialMode::DomainPlusPlus,
        ] {
            let plan = RoutingPushPlan::compile(&router, &outbound_ids(), mode).unwrap();
            backend.publish_routing_plan(&plan, &[]).unwrap();
            for (index, (connection, hit)) in case.samples.iter().enumerate() {
                let key = crate::ebpf::maps::ip_addr_to_lpm_key(connection.dst_ip);
                if let Some(domain) = connection.domain.as_deref().filter(|_| has_domain) {
                    backend
                        .set_domain_ip_bitmap(&key, &router.domain_bitmap(domain).unwrap())
                        .unwrap();
                    present.insert(key.data);
                } else if present.remove(&key.data) {
                    backend.remove_domain_ip_bitmap(&key).unwrap();
                }
                let domain_final = (!has_domain
                    || !matches!(mode, DialMode::Domain | DialMode::DomainPlusPlus)
                    || connection.domain.is_some()) as u32;
                let expected = if *hit {
                    decision(2, 0, true, domain_final, 0)
                } else {
                    decision(1, 0, false, domain_final, u32::MAX)
                };
                assert_route(
                    &mut backend,
                    &format!("{}/{mode:?}/{index}", case.label),
                    &input(connection),
                    expected,
                );
                comparisons += 1;
            }
        }
    }
    eprintln!("native routing: {comparisons} parsed complete-decision comparisons");
}
