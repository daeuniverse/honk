use super::*;
use crate::ebpf::{RetireKind, UdpDecisionCommitResult, retire_fixture};

fn fixture() -> (RealEbpfBackend, RoutingPushPlan, TproxyListeners) {
    let (mut backend, plan, listeners) = publish(&[rule(
        "aux-occupancy",
        RoutingCondition {
            port: vec!["1-65535".into()],
            ..Default::default()
        },
        "proxy",
        USER_MARK,
        true,
    )]);
    load_classifier(&mut backend, "lan_ingress_l2");
    (backend, plan, listeners)
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn auxiliary_occupancy_counts_inserts_and_subtracts_userspace_reclamation() {
    isolated(|| {
        let (mut backend, _, _listeners) = fixture();
        let client: IpAddr = "192.0.2.61".parse().unwrap();
        let target: IpAddr = "198.51.100.61".parse().unwrap();
        assert_eq!(backend.aux_occupancy().unwrap(), (0, 0));

        for (index, expected) in [(0u16, 1u64), (1, 2)] {
            let outbound = packet(client, target, IPPROTO_UDP, 41000 + index, 443, 0, 0);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &outbound, SkbInput::default()).verdict,
                TC_ACT_REDIRECT
            );
            assert_eq!(backend.aux_occupancy().unwrap(), (expected, expected));
        }

        // A cached packet refreshes the existing elements; it inserts nothing.
        let repeat = packet(client, target, IPPROTO_UDP, 41000, 443, 0, 0);
        assert_eq!(
            run(&backend, "lan_ingress_l2", &repeat, SkbInput::default()).verdict,
            TC_ACT_REDIRECT
        );
        assert_eq!(backend.aux_occupancy().unwrap(), (2, 2));

        let key = tuple(client, target, 41000, 443, IPPROTO_UDP);
        let redirect = backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .unwrap();
        let (counts, result) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiredRedirect {
                expected: &redirect,
                expired_before_ns: u64::MAX,
            },
        );
        assert_eq!(result, UdpDecisionCommitResult::Applied);
        assert_eq!((counts.redirect, counts.handoff), (1, 0));
        assert_eq!(backend.aux_occupancy().unwrap(), (1, 2));

        let handoff = handoff(&backend, &key);
        let (counts, result) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiredHandoff {
                expected: &handoff,
                expired_before_ns: u64::MAX,
            },
        );
        assert_eq!(result, UdpDecisionCommitResult::Applied);
        assert_eq!((counts.redirect, counts.handoff), (0, 1));
        assert_eq!(backend.aux_occupancy().unwrap(), (1, 1));
    });
}
