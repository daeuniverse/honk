use super::*;
use honk_ebpf_common::conn::BpfStatsKey;

fn clock_ns() -> u64 {
    let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap();
    time.tv_sec() as u64 * 1_000_000_000 + time.tv_nsec() as u64
}

fn addresses() -> [(IpAddr, IpAddr); 2] {
    [
        (
            "192.0.2.82".parse().unwrap(),
            "198.51.100.82".parse().unwrap(),
        ),
        (
            "2001:db8:1::82".parse().unwrap(),
            "2001:db8:2::82".parse().unwrap(),
        ),
    ]
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn reverse_udp_pressure_keeps_existing_entries_without_learning_new_ones() {
    isolated(|| {
        let (mut backend, _, _listeners) = publish(&[]);
        for (index, name) in ["wan_ingress_l2", "lan_egress_l2"].into_iter().enumerate() {
            load_classifier(&mut backend, name);
            for (client, target) in addresses() {
                backend.set_admission_pressure(false).unwrap();
                let port = 42000 + index as u16 * 10;
                let key = tuple(client, target, port, 443, IPPROTO_UDP);
                let reply = packet(target, client, IPPROTO_UDP, 443, port, 0, 0);
                assert_eq!(
                    run(&backend, name, &reply, SkbInput::default()).verdict,
                    TC_ACT_UNSPEC
                );
                let mut old = backend.conn_state_lookup(&key).unwrap().unwrap();
                assert_eq!(old.is_wan_ingress_direction, 1);
                old.last_seen_ns = clock_ns() - 2_000_000_000;
                backend.flow_insert("CONN_STATE_MAP", &key, &old).unwrap();
                backend.set_admission_pressure(true).unwrap();
                assert_eq!(
                    run(&backend, name, &reply, SkbInput::default()).verdict,
                    TC_ACT_UNSPEC
                );
                let refreshed = backend.conn_state_lookup(&key).unwrap().unwrap();
                assert_eq!(refreshed.incarnation, old.incarnation);
                assert!(refreshed.last_seen_ns > old.last_seen_ns);

                let before = backend
                    .get_bpf_stats(BpfStatsKey::UdpReverseLearningSuspended as u32)
                    .unwrap()
                    .unwrap_or(0);
                let fresh_key = tuple(client, target, port + 1, 443, IPPROTO_UDP);
                let fresh_reply = packet(target, client, IPPROTO_UDP, 443, port + 1, 0, 0);
                assert_eq!(
                    run(&backend, name, &fresh_reply, SkbInput::default()).verdict,
                    TC_ACT_UNSPEC
                );
                assert!(
                    backend.conn_state_lookup(&fresh_key).unwrap().is_none(),
                    "{name}: pressure must not allocate a reverse entry"
                );
                assert_eq!(
                    backend
                        .get_bpf_stats(BpfStatsKey::UdpReverseLearningSuspended as u32)
                        .unwrap(),
                    Some(before + 1)
                );
                backend.set_admission_pressure(false).unwrap();
                assert_eq!(
                    run(&backend, name, &fresh_reply, SkbInput::default()).verdict,
                    TC_ACT_UNSPEC
                );
                assert_eq!(
                    backend
                        .conn_state_lookup(&fresh_key)
                        .unwrap()
                        .unwrap()
                        .is_wan_ingress_direction,
                    1
                );
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn reverse_udp_observation_never_overwrites_forward_authority() {
    isolated(|| {
        let (mut backend, _, _listeners) = publish(&[]);
        for name in ["wan_ingress_l2", "lan_egress_l2"] {
            load_classifier(&mut backend, name);
            for (client, target) in addresses() {
                for (index, state) in [UdpDecisionState::Preparing, UdpDecisionState::Proxy]
                    .into_iter()
                    .enumerate()
                {
                    let port = 43000 + index as u16;
                    let key = tuple(client, target, port, 443, IPPROTO_UDP);
                    let forward = ConnState {
                        is_wan_ingress_direction: 0,
                        incarnation: 71 + index as u64,
                        decision_token: 123,
                        state: state as u8,
                        meta: RoutingMeta {
                            raw: 0x0100_0000_002a_0002,
                        },
                        last_seen_ns: clock_ns(),
                        ..Default::default()
                    };
                    backend
                        .flow_insert("CONN_STATE_MAP", &key, &forward)
                        .unwrap();
                    for pressure in [false, true] {
                        backend.set_admission_pressure(pressure).unwrap();
                        let reply = packet(target, client, IPPROTO_UDP, 443, port, 0, 0);
                        let expected_verdict = if state == UdpDecisionState::Preparing {
                            TC_ACT_SHOT
                        } else {
                            TC_ACT_UNSPEC
                        };
                        assert_eq!(
                            run(&backend, name, &reply, SkbInput::default()).verdict,
                            expected_verdict
                        );
                        let after = backend.conn_state_lookup(&key).unwrap().unwrap();
                        assert_eq!(after.is_wan_ingress_direction, 0);
                        assert_eq!(after.state, forward.state);
                        assert_eq!(after.decision_token, forward.decision_token);
                        assert_eq!(after.incarnation, forward.incarnation);
                        assert_eq!(
                            unsafe { after.meta.raw },
                            unsafe { forward.meta.raw },
                            "{name}, {state:?}, pressure={pressure}"
                        );
                    }
                }
            }
        }
    });
}
