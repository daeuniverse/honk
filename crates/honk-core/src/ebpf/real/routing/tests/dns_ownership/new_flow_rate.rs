use super::*;
use honk_ebpf_common::conn::BpfStatsKey;

/// The documented per-CPU budget (doc/en/design/datapath.md), deliberately not
/// imported from production so a drifting value fails these tests.
const NEW_FLOW_LIMIT_PER_CPU_SECOND: u16 = 1024;

fn monotonic_ns() -> u64 {
    let mut time: libc::timespec = unsafe { mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) },
        0
    );
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

/// Start a burst early in a second so it cannot straddle the window boundary.
fn align_to_second() {
    while monotonic_ns() % 1_000_000_000 > 200_000_000 {
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn limited(backend: &RealEbpfBackend) -> u64 {
    backend
        .get_bpf_stats(BpfStatsKey::NewFlowRateLimited as u32)
        .ok()
        .flatten()
        .unwrap_or(0)
}

fn state_counts(backend: &RealEbpfBackend) -> (usize, usize) {
    (
        flow_count::<TuplesKey, ConnState>(backend, "CONN_STATE_MAP"),
        flow_count::<TuplesKey, RoutingHandoffEntry>(backend, "ROUTING_HANDOFF_MAP"),
    )
}

fn fixture() -> (RealEbpfBackend, TproxyListeners) {
    let (mut backend, _, listeners) = publish(&[rule(
        "all-ports",
        RoutingCondition {
            port: vec!["1-65535".into()],
            ..Default::default()
        },
        "proxy",
        USER_MARK,
        true,
    )]);
    load_classifier(&mut backend, "lan_ingress_l2");
    (backend, listeners)
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn lan_source_over_the_new_flow_limit_is_dropped_before_any_state_is_published() {
    isolated(|| {
        let families: [(IpAddr, IpAddr, IpAddr); 2] = [
            (
                "192.0.2.90".parse().unwrap(),
                "192.0.2.91".parse().unwrap(),
                "203.0.113.90".parse().unwrap(),
            ),
            (
                "2001:db8:1::90".parse().unwrap(),
                "2001:db8:1::91".parse().unwrap(),
                "2001:db8:2::90".parse().unwrap(),
            ),
        ];
        let kinds = [
            (IPPROTO_TCP, 443, 0x02),
            (IPPROTO_UDP, 443, 0),
            (IPPROTO_UDP, 53, 0),
        ];
        let (backend, _listeners) = fixture();
        pin_to_current_cpu();
        for (family, (attacker, other, target)) in families.into_iter().enumerate() {
            align_to_second();
            let attempt = |source: IpAddr, index: u16, (proto, port, flags)| {
                let bytes = packet(source, target, proto, 20000 + index, port, 0, flags);
                run(&backend, "lan_ingress_l2", &bytes, SkbInput::default()).verdict
            };
            // All three admission paths must spend the same source budget.
            for index in 0..NEW_FLOW_LIMIT_PER_CPU_SECOND {
                assert_eq!(
                    attempt(attacker, index, kinds[index as usize % kinds.len()]),
                    TC_ACT_REDIRECT,
                    "family {family}: admitted attempt #{index}"
                );
            }
            let admitted = state_counts(&backend);
            let before_limited = limited(&backend);
            for (index, kind) in kinds.into_iter().enumerate() {
                // TCP/ordinary UDP are new tuples; UDP/53 repeats its admitted tuple.
                assert_eq!(attempt(attacker, 2, kind), TC_ACT_SHOT);
                assert_eq!(limited(&backend), before_limited + index as u64 + 1);
            }
            assert_eq!(
                state_counts(&backend),
                admitted,
                "family {family}: rejected attempts must leave no conn or handoff state"
            );
            for (index, kind) in [(0, (IPPROTO_TCP, 443, 0x10)), (1, kinds[1])] {
                assert_eq!(
                    attempt(attacker, index, kind),
                    TC_ACT_REDIRECT,
                    "family {family}: cached flow"
                );
            }
            assert_eq!(limited(&backend), before_limited + kinds.len() as u64);
            assert_eq!(
                attempt(other, 0, kinds[1]),
                TC_ACT_REDIRECT,
                "family {family}: another host's new flow"
            );
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn local_udp_learning_shares_the_source_budget_without_dropping_service_requests() {
    isolated(|| {
        assert!(
            std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .unwrap()
                .success()
        );
        pin_to_current_cpu();
        for (client, other, local, target) in [
            (
                "192.0.2.120".parse().unwrap(),
                "192.0.2.121".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                "203.0.113.120".parse().unwrap(),
            ),
            (
                "2001:db8:1::120".parse().unwrap(),
                "2001:db8:1::121".parse().unwrap(),
                "::1".parse().unwrap(),
                "2001:db8:2::120".parse().unwrap(),
            ),
        ] {
            let (backend, _listeners) = fixture();
            let service = UdpSocket::bind(SocketAddr::new(local, 0)).unwrap();
            let port = service.local_addr().unwrap().port();
            let limit = NEW_FLOW_LIMIT_PER_CPU_SECOND;
            let before_drops = limited(&backend);
            align_to_second();
            // Replaying the cached first tuple must not spend another learning slot.
            for index in std::iter::once(0).chain(0..=limit) {
                let request = packet(client, local, IPPROTO_UDP, 20000 + index, port, 0, 0);
                assert_eq!(
                    run(&backend, "lan_ingress_l2", &request, SkbInput::default()).verdict,
                    TC_ACT_OK,
                    "{client}: service request #{index} must stay native"
                );
            }
            assert_eq!(
                state_counts(&backend),
                (usize::from(limit), 0),
                "{client}: only budgeted requests may allocate reverse conn state"
            );
            assert_eq!(
                limited(&backend),
                before_drops,
                "{client}: skipped learning must not count a packet drop"
            );

            let request = packet(other, local, IPPROTO_UDP, 20000, port, 0, 0);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &request, SkbInput::default()).verdict,
                TC_ACT_OK
            );
            assert!(
                backend
                    .conn_state_lookup(&tuple(local, other, port, 20000, IPPROTO_UDP))
                    .unwrap()
                    .is_some(),
                "{client}: another source still learns"
            );

            // The local-service requests spent the same budget as ordinary routed flows.
            let routed = packet(client, target, IPPROTO_UDP, 30000, 443, 0, 0);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &routed, SkbInput::default()).verdict,
                TC_ACT_SHOT,
                "{client}: local and routed traffic must share one budget"
            );
            assert_eq!(limited(&backend), before_drops + 1);
            assert_eq!(state_counts(&backend), (usize::from(limit) + 1, 0));
            for (index, learned) in [(0, true), (limit - 1, true), (limit, false)] {
                let state = backend
                    .conn_state_lookup(&tuple(local, client, port, 20000 + index, IPPROTO_UDP))
                    .unwrap();
                assert_eq!(
                    state.is_some(),
                    learned,
                    "{client}: learned reverse tuple #{index}"
                );
            }
        }
    });
}
