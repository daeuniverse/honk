use super::*;
use crate::ebpf::{UdpDecisionCommitResult, UdpDecisionTransition};

fn fixture() -> (RealEbpfBackend, TproxyListeners) {
    let (mut backend, _, listeners) = publish(&[rule(
        "ambiguous",
        RoutingCondition {
            domain_suffix: vec!["example.test".into()],
            ..Default::default()
        },
        "proxy",
        0,
        false,
    )]);
    backend
        .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
        .unwrap();
    load_classifier(&mut backend, "lan_ingress_l2");
    (backend, listeners)
}

fn now_ns() -> u64 {
    let t = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap();
    t.tv_sec() as u64 * 1_000_000_000 + t.tv_nsec() as u64
}

fn stage(
    backend: &RealEbpfBackend,
    src: IpAddr,
    dst: IpAddr,
    port: u16,
) -> (TuplesKey, Vec<u8>, u32) {
    let key = tuple(src, dst, port, 443, IPPROTO_UDP);
    let bytes = packet(src, dst, IPPROTO_UDP, port, 443, 0, 0);
    let result = run(backend, "lan_ingress_l2", &bytes, SkbInput::default());
    let state = backend.conn_state_lookup(&key).unwrap().unwrap();
    assert_eq!(
        state.state,
        UdpDecisionState::Pending as u8,
        "verdict {}",
        result.verdict
    );
    (key, bytes, state.decision_token)
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT"]
fn pending_and_armed_followers_freeze_the_conn_timestamp() {
    isolated(|| {
        let (mut backend, _listeners) = fixture();
        for (src, dst) in [
            ("192.0.2.10", "198.51.100.20"),
            ("2001:db8:1::10", "2001:db8:2::20"),
        ] {
            let (key, bytes, token) =
                stage(&backend, src.parse().unwrap(), dst.parse().unwrap(), 47000);
            for transition in [None, Some(UdpDecisionTransition::ArmDirect(0))] {
                if let Some(transition) = transition {
                    assert_eq!(
                        backend
                            .commit_udp_decision(&key, token, transition)
                            .unwrap(),
                        UdpDecisionCommitResult::Applied
                    );
                }
                let mut state = backend.conn_state_lookup(&key).unwrap().unwrap();
                state.last_seen_ns = now_ns() - 2_000_000_000;
                backend.udp_conn_state_store(&key, &state).unwrap();
                let _ = run(&backend, "lan_ingress_l2", &bytes, SkbInput::default());
                let after = backend.conn_state_lookup(&key).unwrap().unwrap();
                assert_eq!(
                    format!("{after:?}"),
                    format!("{state:?}"),
                    "staging follower renewed or rewrote the frozen snapshot"
                );
            }
            assert_eq!(
                backend
                    .commit_udp_decision(&key, token, UdpDecisionTransition::ActivateDirect(0))
                    .unwrap(),
                UdpDecisionCommitResult::Applied
            );
            let before = backend.conn_state_lookup(&key).unwrap().unwrap();
            let _ = run(&backend, "lan_ingress_l2", &bytes, SkbInput::default());
            assert!(
                backend
                    .conn_state_lookup(&key)
                    .unwrap()
                    .unwrap()
                    .last_seen_ns
                    > before.last_seen_ns,
                "finished UDP must resume normal refresh"
            );
        }
    });
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT"]
fn armed_direct_activation_does_not_run_a_grace_barrier() {
    isolated(|| {
        let (mut backend, _listeners) = fixture();
        let (key, _, token) = stage(
            &backend,
            "192.0.2.10".parse().unwrap(),
            "198.51.100.20".parse().unwrap(),
            47001,
        );
        assert_eq!(
            backend
                .commit_udp_decision(&key, token, UdpDecisionTransition::ArmDirect(0x1234))
                .unwrap(),
            UdpDecisionCommitResult::Applied
        );
        let armed = backend.conn_state_lookup(&key).unwrap().unwrap();
        backend.retirement_faults.barrier = true;
        assert_eq!(
            backend
                .commit_udp_decision(&key, token, UdpDecisionTransition::ActivateDirect(0x1234))
                .unwrap(),
            UdpDecisionCommitResult::Applied
        );
        assert!(
            backend.retirement_faults.barrier,
            "activation consumed the barrier fault"
        );
        let active = backend.conn_state_lookup(&key).unwrap().unwrap();
        assert_eq!(active.last_seen_ns, armed.last_seen_ns);
        assert_eq!(active.incarnation, armed.incarnation);
        assert_eq!(active.state, UdpDecisionState::None as u8);
        assert_ne!(unsafe { active.meta.raw } & ROUTING_META_FLAG_OFFLOAD, 0);
    });
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT"]
fn a_batched_tuple_is_fenced_once_and_every_transition_rechecks_its_state() {
    isolated(|| {
        let (mut backend, _listeners) = fixture();
        let (key, _, token) = stage(
            &backend,
            "192.0.2.10".parse().unwrap(),
            "198.51.100.20".parse().unwrap(),
            47002,
        );
        let requests = [
            crate::ebpf::UdpDecisionCommit {
                key,
                token,
                transition: UdpDecisionTransition::ArmDirect(0),
            },
            crate::ebpf::UdpDecisionCommit {
                key,
                token,
                transition: UdpDecisionTransition::Block,
            },
        ];
        backend.retirement_faults.acquire = Some(1);
        let mut results = Vec::new();
        backend
            .commit_udp_batch(&requests, &mut |_, apply| {
                results.push(apply()?);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            results,
            vec![
                UdpDecisionCommitResult::Applied,
                UdpDecisionCommitResult::StateMismatch
            ]
        );
        assert_eq!(
            backend.retirement_faults.acquire,
            Some(0),
            "tuple was fenced twice"
        );
        assert_eq!(
            backend.conn_state_lookup(&key).unwrap().unwrap().state,
            UdpDecisionState::DirectArmed as u8
        );
        assert!(
            backend
                .hash_lookup::<_, honk_ebpf_common::conn::RetirementFence>(
                    crate::ebpf::RETIRE_FENCE_MAP,
                    &key
                )
                .unwrap()
                .is_none()
        );
    });
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT"]
fn a_batch_release_failure_reports_error_after_all_successful_mutations() {
    isolated(|| {
        let (mut backend, _listeners) = fixture();
        let mut requests = Vec::new();
        for port in [47003, 47004] {
            let (key, _, token) = stage(
                &backend,
                "192.0.2.10".parse().unwrap(),
                "198.51.100.20".parse().unwrap(),
                port,
            );
            requests.push(crate::ebpf::UdpDecisionCommit {
                key,
                token,
                transition: UdpDecisionTransition::ActivateProxy(2, 0),
            });
        }
        backend.retirement_faults.release = Some(0);
        let mut applied = 0;
        let error = backend
            .commit_udp_batch(&requests, &mut |_, apply| {
                assert_eq!(apply()?, UdpDecisionCommitResult::Applied);
                applied += 1;
                Ok(())
            })
            .unwrap_err();
        assert!(format!("{error:#}").contains("release"));
        assert_eq!(applied, 2);
        assert!(backend.retirement_failed);
        for request in &requests {
            assert_eq!(
                backend
                    .conn_state_lookup(&request.key)
                    .unwrap()
                    .unwrap()
                    .state,
                UdpDecisionState::Proxy as u8
            );
        }
        assert!(
            backend
                .hash_lookup::<_, honk_ebpf_common::conn::RetirementFence>(
                    crate::ebpf::RETIRE_FENCE_MAP,
                    &requests[0].key
                )
                .unwrap()
                .is_some()
        );
        assert!(
            backend
                .hash_lookup::<_, honk_ebpf_common::conn::RetirementFence>(
                    crate::ebpf::RETIRE_FENCE_MAP,
                    &requests[1].key
                )
                .unwrap()
                .is_none()
        );
    });
}
