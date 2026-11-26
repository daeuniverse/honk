use super::*;

#[test]
fn auxiliary_owner_mismatch_refuses_retirement_and_commit_without_mutation() {
    for operation in 0..7 {
        let mut backend = MockEbpfBackend::new();
        let key = TuplesKey {
            l4proto: if operation == 0 { 6 } else { 17 },
            ..Default::default()
        };
        let state = ConnState {
            incarnation: 1,
            decision_token: 7,
            state: UdpDecisionState::Pending as u8,
            ..Default::default()
        };
        backend.seed_staged_udp_flow(&key, state);
        if operation == 0 {
            backend.udp_conn_states.clear();
            backend.tcp_conn_state_store(&key, &state).unwrap();
        }
        let raw = MockEbpfBackend::tuples_key_bytes(&key);
        if matches!(operation, 5 | 6) {
            let track_raw =
                MockEbpfBackend::redirect_tuple_bytes(&RedirectTuple::from_tuples(&key));
            backend
                .redirect_tracks
                .get_mut(&track_raw)
                .unwrap()
                .decision_token = 8;
        } else {
            backend
                .routing_handoffs
                .get_mut()
                .get_mut(&raw)
                .unwrap()
                .result
                .decision_token = 8;
        }
        let outcome = if matches!(operation, 4 | 5) {
            backend
                .commit_udp_decision(&key, 7, UdpDecisionTransition::Block)
                .unwrap()
        } else {
            let kind = match operation {
                0 => RetireKind::Tcp { incarnation: 1 },
                1 | 6 => RetireKind::Udp {
                    token: 7,
                    incarnation: Some(1),
                    pending_only: true,
                },
                2 => RetireKind::ExpiredConn {
                    expected: &state,
                    expired_before_ns: 0,
                },
                _ => RetireKind::ExpiryHint {
                    incarnation: 1,
                    now_ns: u64::MAX,
                },
            };
            let (counts, outcome) = retire_fixture(&mut backend, key, kind);
            assert_eq!(counts, RetireCounts::default());
            outcome
        };
        assert_eq!(outcome, UdpDecisionCommitResult::TokenMismatch);
        let retained = backend.conn_state_lookup(&key).unwrap().unwrap();
        assert_eq!(
            (
                retained.incarnation,
                retained.decision_token,
                retained.state
            ),
            (1, 7, state.state)
        );
        assert_eq!(
            backend
                .routing_handoff_lookup(&key)
                .unwrap()
                .unwrap()
                .result
                .decision_token,
            if matches!(operation, 5 | 6) { 7 } else { 8 }
        );
        assert_eq!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .unwrap()
                .decision_token,
            if matches!(operation, 5 | 6) { 8 } else { 7 }
        );
    }
}

#[test]
fn hint_auxiliary_expiry_refuses_mismatched_tokens_without_conn() {
    let mut backend = MockEbpfBackend::new();
    let key = TuplesKey {
        l4proto: 17,
        ..Default::default()
    };
    backend.seed_staged_udp_flow(
        &key,
        ConnState {
            incarnation: 1,
            decision_token: 7,
            state: UdpDecisionState::Pending as u8,
            ..Default::default()
        },
    );
    backend.udp_conn_states.clear();
    let track_raw = MockEbpfBackend::redirect_tuple_bytes(&RedirectTuple::from_tuples(&key));
    backend
        .redirect_tracks
        .get_mut(&track_raw)
        .unwrap()
        .decision_token = 8;
    let kind = RetireKind::ExpiryHint {
        incarnation: 1,
        now_ns: 121_000_000_000,
    };
    let (counts, outcome) = retire_fixture(&mut backend, key, kind);
    assert_eq!(outcome, UdpDecisionCommitResult::TokenMismatch);
    assert_eq!(counts, RetireCounts::default());
    assert!(backend.routing_handoff_lookup(&key).unwrap().is_some());
    assert_eq!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .unwrap()
            .decision_token,
        8
    );
    backend
        .redirect_tracks
        .get_mut(&track_raw)
        .unwrap()
        .decision_token = 7;
    let (counts, outcome) = retire_fixture(&mut backend, key, kind);
    assert_eq!(outcome, UdpDecisionCommitResult::Applied);
    assert_eq!(
        counts,
        RetireCounts {
            handoff: 1,
            redirect: 1,
            ..Default::default()
        }
    );
}

#[test]
fn expired_conn_retirement_reclaims_matching_auxiliaries() {
    for proto in [6, 17] {
        let mut backend = MockEbpfBackend::new();
        let key = TuplesKey {
            l4proto: proto,
            ..Default::default()
        };
        let state = ConnState {
            incarnation: 1,
            decision_token: 7,
            state: UdpDecisionState::Pending as u8,
            ..Default::default()
        };
        backend.seed_staged_udp_flow(&key, state);
        if proto == 6 {
            backend.udp_conn_states.clear();
            backend.tcp_conn_state_store(&key, &state).unwrap();
        }
        let (counts, outcome) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiredConn {
                expected: &state,
                expired_before_ns: 0,
            },
        );
        assert_eq!(outcome, UdpDecisionCommitResult::Applied);
        assert_eq!(
            counts,
            RetireCounts {
                conn: 1,
                handoff: 1,
                redirect: 1,
            }
        );
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn udp_flow_owner_validates_incarnations_and_preserves_model_identity() {
    use super::super::UdpFlowOwner;
    use honk_ebpf_common::conn::FLOW_INCARNATION_MAX;

    assert_eq!(UdpFlowOwner::new(0, None).unwrap().incarnation(), None);
    for incarnation in [0, FLOW_INCARNATION_MAX + 1, u64::MAX] {
        assert!(UdpFlowOwner::new(7, Some(incarnation)).is_err());
    }
    let backend = MockEbpfBackend::new();
    assert_eq!(backend.udp_flow_owner(0, None).unwrap().incarnation(), None);
    assert!(backend.udp_flow_owner(7, None).is_err());
    for incarnation in [0, 1, FLOW_INCARNATION_MAX] {
        let state = Some(ConnState {
            decision_token: 7,
            incarnation,
            ..Default::default()
        });
        let owner = backend.udp_flow_owner(7, state).unwrap();
        assert_eq!(owner.token, 7);
        assert_eq!(
            owner.incarnation(),
            (incarnation != 0).then_some(incarnation)
        );
        assert!(backend.udp_flow_owner(8, state).is_err());
    }
    assert!(
        backend
            .udp_flow_owner(
                0,
                Some(ConnState {
                    incarnation: FLOW_INCARNATION_MAX + 1,
                    ..Default::default()
                }),
            )
            .is_err()
    );
}

#[test]
fn udp_admission_checks_captured_owner_with_model_and_stateless_exemptions() {
    use super::super::UdpFlowOwner;

    let mut backend = MockEbpfBackend::new();
    let key = TuplesKey {
        src_port: 41000,
        dst_port: 443,
        l4proto: 17,
        ..Default::default()
    };
    let model = UdpFlowOwner::new(0, None).unwrap();
    let (entry, cached_group) = backend.verify_udp_admission(&key, model).unwrap();
    assert!(entry.is_none() && cached_group.is_none());
    assert!(
        backend
            .verify_udp_admission(&key, UdpFlowOwner::new(7, None).unwrap())
            .is_err()
    );
    for incarnation in [0, 41] {
        backend.seed_staged_udp_flow(
            &key,
            ConnState {
                decision_token: 7,
                incarnation,
                state: UdpDecisionState::Pending as u8,
                ..Default::default()
            },
        );
        let owner = backend
            .udp_flow_owner(7, backend.conn_state_lookup(&key).unwrap())
            .unwrap();
        let (entry, cached_group) = backend.verify_udp_admission(&key, owner).unwrap();
        assert!(entry.is_some() && cached_group.is_none());
        assert!(
            backend
                .verify_udp_admission(&key, UdpFlowOwner::new(7, Some(42)).unwrap())
                .is_err()
        );
        let handoff = backend
            .routing_handoffs
            .get_mut()
            .get_mut(&MockEbpfBackend::tuples_key_bytes(&key))
            .unwrap();
        handoff.result.decision_token = 8;
        assert!(backend.verify_udp_admission(&key, owner).is_err());
    }
    backend
        .udp_conn_state_store(
            &key,
            &ConnState {
                incarnation: 41,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(backend.verify_udp_admission(&key, model).is_err());
    let stateless = TuplesKey {
        dst_port: 53,
        ..key
    };
    let (entry, cached_group) = backend.verify_udp_admission(&stateless, model).unwrap();
    assert!(entry.is_none() && cached_group.is_none());
    backend.routing_handoffs.get_mut().insert(
        MockEbpfBackend::tuples_key_bytes(&stateless),
        RoutingHandoffEntry {
            result: RoutingResult {
                decision_token: 7,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    assert!(backend.verify_udp_admission(&stateless, model).is_err());
    backend
        .routing_handoffs
        .get_mut()
        .get_mut(&MockEbpfBackend::tuples_key_bytes(&stateless))
        .unwrap()
        .result
        .decision_token = 0;
    let (entry, cached_group) = backend.verify_udp_admission(&stateless, model).unwrap();
    assert!(entry.is_some() && cached_group.is_none());
}

#[test]
fn expiry_hint_ages_auxiliaries_without_requiring_expired_conn_state() {
    let mut backend = MockEbpfBackend::new();
    let key = TuplesKey {
        l4proto: 17,
        ..Default::default()
    };
    backend.seed_staged_udp_flow(
        &key,
        ConnState {
            incarnation: 1,
            last_seen_ns: 31_000_000_000,
            decision_token: 7,
            state: UdpDecisionState::Pending as u8,
            ..Default::default()
        },
    );
    let (counts, outcome) = retire_fixture(
        &mut backend,
        key,
        RetireKind::ExpiryHint {
            incarnation: 2,
            now_ns: 31_000_000_000,
        },
    );
    assert_eq!(counts, RetireCounts::default());
    assert_eq!(outcome, UdpDecisionCommitResult::Superseded);
    assert!(backend.routing_handoff_lookup(&key).unwrap().is_some());
    let mut outcomes = [RetireOutcome::NotRun];
    let counts = backend
        .retire_batch(
            &[RetireRequest {
                key,
                kind: RetireKind::ExpiryHint {
                    incarnation: 1,
                    now_ns: 31_000_000_000,
                },
            }],
            &mut outcomes,
        )
        .unwrap();
    assert_eq!(
        counts,
        RetireCounts {
            handoff: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        outcomes,
        [RetireOutcome::Done(UdpDecisionCommitResult::Applied)]
    );
    assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
    assert!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .is_some()
    );
    let (counts, outcome) = retire_fixture(
        &mut backend,
        key,
        RetireKind::ExpiryHint {
            incarnation: 1,
            now_ns: 121_000_000_000,
        },
    );
    assert_eq!(
        counts,
        RetireCounts {
            redirect: 1,
            ..Default::default()
        }
    );
    assert_eq!(outcome, UdpDecisionCommitResult::Applied);
    assert!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        backend
            .conn_state_lookup(&key)
            .unwrap()
            .unwrap()
            .incarnation,
        1
    );
    let counts = backend
        .retire_batch(
            &[RetireRequest {
                key,
                kind: RetireKind::ExpiryHint {
                    incarnation: 1,
                    now_ns: 31_000_000_001 + honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS,
                },
            }],
            &mut outcomes,
        )
        .unwrap();
    assert_eq!(counts.conn, 1);
    assert_eq!(outcomes, [RetireOutcome::ConnRetired]);
    assert!(backend.conn_state_lookup(&key).unwrap().is_none());
}

#[test]
fn unchanged_timestamp_does_not_authorize_stale_snapshot_cleanup() {
    let mut backend = MockEbpfBackend::new();
    let key = TuplesKey {
        l4proto: 6,
        ..Default::default()
    };
    let old = ConnState {
        incarnation: 1,
        last_seen_ns: 1,
        ..Default::default()
    };
    let current = ConnState {
        incarnation: 2,
        ..old
    };
    backend.tcp_conn_state_store(&key, &current).unwrap();
    let (counts, outcome) = retire_fixture(
        &mut backend,
        key,
        RetireKind::ExpiredConn {
            expected: &old,
            expired_before_ns: 10,
        },
    );
    assert_eq!(counts.conn, 0);
    assert_eq!(outcome, UdpDecisionCommitResult::Superseded);
    assert_eq!(
        backend
            .conn_state_lookup(&key)
            .unwrap()
            .unwrap()
            .incarnation,
        2
    );
}

#[test]
fn old_tcp_owner_cannot_retire_new_syn_with_same_timestamp() {
    let mut backend = MockEbpfBackend::new();
    let key = TuplesKey {
        l4proto: 6,
        ..Default::default()
    };
    let state = ConnState {
        incarnation: 2,
        last_seen_ns: 1,
        ..Default::default()
    };
    backend.tcp_conn_state_store(&key, &state).unwrap();
    backend.routing_handoffs.get_mut().insert(
        MockEbpfBackend::tuples_key_bytes(&key),
        RoutingHandoffEntry {
            incarnation: 2,
            ..Default::default()
        },
    );
    backend
        .redirect_track_store(
            &RedirectTuple::from_tuples(&key),
            &RedirectEntry {
                incarnation: 2,
                ..Default::default()
            },
        )
        .unwrap();
    let (counts, outcome) = retire_fixture(&mut backend, key, RetireKind::Tcp { incarnation: 1 });
    assert_eq!(outcome, UdpDecisionCommitResult::Superseded);
    assert_eq!(counts, RetireCounts::default());
    assert_eq!(
        backend
            .conn_state_lookup(&key)
            .unwrap()
            .unwrap()
            .incarnation,
        2
    );
    assert_eq!(
        backend
            .routing_handoff_lookup(&key)
            .unwrap()
            .unwrap()
            .incarnation,
        2
    );
    assert_eq!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .unwrap()
            .incarnation,
        2
    );
    let (counts, outcome) = retire_fixture(&mut backend, key, RetireKind::Tcp { incarnation: 2 });
    assert_eq!(outcome, UdpDecisionCommitResult::Applied);
    assert_eq!(
        counts,
        RetireCounts {
            conn: 1,
            redirect: 1,
            handoff: 1,
        }
    );
}

#[test]
fn partial_failure_reports_only_completed_requests_and_real_deletions() {
    let mut backend = MockEbpfBackend::new();
    let key = TuplesKey {
        l4proto: 6,
        ..Default::default()
    };
    let state = ConnState::default();
    backend.tcp_conn_state_store(&key, &state).unwrap();
    let request = RetireRequest {
        key,
        kind: RetireKind::ExpiredConn {
            expected: &state,
            expired_before_ns: 0,
        },
    };
    let mut outcomes = [RetireOutcome::NotRun; 3];
    backend.retire_fault_after = Some(2);
    let error = backend
        .retire_batch(&[request; 3], &mut outcomes)
        .unwrap_err();
    assert_eq!(
        error.counts,
        RetireCounts {
            conn: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        outcomes,
        [
            RetireOutcome::ConnRetired,
            RetireOutcome::Done(UdpDecisionCommitResult::Missing),
            RetireOutcome::NotRun
        ]
    );
    assert!(backend.conn_state_lookup(&key).unwrap().is_none());
    let mut outcomes = [RetireOutcome::Done(UdpDecisionCommitResult::Applied)];
    let error = backend.retire_batch(&[], &mut outcomes).unwrap_err();
    assert_eq!(error.counts, RetireCounts::default());
    assert_eq!(outcomes, [RetireOutcome::NotRun]);
}
