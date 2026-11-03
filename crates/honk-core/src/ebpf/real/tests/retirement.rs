use super::super::retirement as backend_retirement;
use super::*;
use crate::ebpf::retire_fixture;
use honk_ebpf_common::conn::{FlowMapValue, RetirementFence};

mod storage;

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn retirement_release_failure_retains_applied_counts_and_releases_other_fences() {
    let mut backend = retirement_fixture();
    let requests = [
        seed_retirement_flow(&mut backend, 41007),
        seed_retirement_flow(&mut backend, 41008),
    ];
    backend.retirement_faults.release = Some(0);
    let mut outcomes = [RetireOutcome::NotRun; 2];
    let error = backend.retire_batch(&requests, &mut outcomes).unwrap_err();
    assert_eq!(
        error.counts,
        RetireCounts {
            conn: 2,
            redirect: 2,
            handoff: 2,
        }
    );
    assert_eq!(outcomes, [RetireOutcome::ConnRetired; 2]);
    for (index, request) in requests.iter().enumerate() {
        assert!(backend.conn_state_lookup(&request.key).unwrap().is_none());
        assert!(
            backend
                .routing_handoff_lookup(&request.key)
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&request.key))
                .unwrap()
                .is_none()
        );
        assert_retirement_fence(&backend, &request.key, index == 0);
    }
    assert_eq!(
        backend.array_get::<u32>("RETIRE_ACTIVE", 0).unwrap(),
        Some(1)
    );
    assert!(backend.retirement_failed);
}

fn retirement_fixture() -> RealEbpfBackend {
    RealEbpfBackend::load_routing_test_fixture(crate::DEFAULT_BPF_OBJECT, DaeParam::default())
        .expect("load production maps without attaching programs")
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn quiescence_preserves_tcp_closing_while_retiring_udp_staging() -> anyhow::Result<()> {
    let mut backend = retirement_fixture();
    let tcp = TuplesKey {
        src_port: 41120,
        l4proto: libc::IPPROTO_TCP as u8,
        ..Default::default()
    };
    let udp = TuplesKey {
        l4proto: libc::IPPROTO_UDP as u8,
        ..tcp
    };
    backend.tcp_conn_state_store(
        &tcp,
        &ConnState {
            state: honk_ebpf_common::conn::TcpState::TcpStateClosing as u8,
            incarnation: 2,
            ..Default::default()
        },
    )?;
    backend.udp_conn_state_store(
        &udp,
        &ConnState {
            state: UdpDecisionState::Pending as u8,
            decision_token: 7,
            incarnation: 1,
            ..Default::default()
        },
    )?;
    backend.quiesce_udp_staging()?;
    assert_eq!(backend.conn_state_lookup(&tcp)?.unwrap().incarnation, 2);
    assert!(backend.conn_state_lookup(&udp)?.is_none());
    Ok(())
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn quiescence_preserves_native_udp_publication_completed_after_scan() -> anyhow::Result<()> {
    fn key() -> TuplesKey {
        TuplesKey {
            src_port: 41121,
            l4proto: libc::IPPROTO_UDP as u8,
            ..Default::default()
        }
    }
    fn complete_publication(backend: &mut RealEbpfBackend) -> anyhow::Result<()> {
        let mut state = backend.conn_state_lookup(&key())?.unwrap();
        state.state = UdpDecisionState::None as u8;
        state.meta = RoutingMeta {
            raw: ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD,
        };
        backend.udp_conn_state_store(&key(), &state)
    }
    let mut backend = retirement_fixture();
    backend.udp_conn_state_store(
        &key(),
        &ConnState {
            state: UdpDecisionState::Preparing as u8,
            incarnation: 3,
            ..Default::default()
        },
    )?;
    backend.retirement_faults.quiesce_after_scan = Some(complete_publication);
    backend.quiesce_udp_staging()?;
    let retained = backend.conn_state_lookup(&key())?.unwrap();
    assert_eq!(
        (retained.incarnation, retained.state),
        (3, UdpDecisionState::None as u8)
    );
    assert_ne!(unsafe { retained.meta.raw } & ROUTING_META_FLAG_OFFLOAD, 0);
    backend.set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)?;
    Ok(())
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn udp_admission_requires_current_token_and_nonzero_56_bit_incarnation() {
    use honk_ebpf_common::conn::FLOW_INCARNATION_MAX;

    let mut backend = retirement_fixture();
    for token in [0, 7] {
        let key = TuplesKey {
            src_port: 41100 + token as u16,
            l4proto: libc::IPPROTO_UDP as u8,
            ..TuplesKey::default()
        };
        assert!(
            backend
                .udp_flow_owner(token, backend.conn_state_lookup(&key).unwrap())
                .is_err()
        );
        for incarnation in [1, FLOW_INCARNATION_MAX] {
            backend
                .udp_conn_state_store(
                    &key,
                    &ConnState {
                        decision_token: token,
                        incarnation,
                        ..ConnState::default()
                    },
                )
                .unwrap();
            assert_eq!(
                backend
                    .udp_flow_owner(token, backend.conn_state_lookup(&key).unwrap())
                    .unwrap()
                    .incarnation(),
                Some(incarnation)
            );
            assert!(
                backend
                    .udp_flow_owner(token + 1, backend.conn_state_lookup(&key).unwrap())
                    .is_err()
            );
        }
        for incarnation in [0, FLOW_INCARNATION_MAX + 1, u64::MAX] {
            backend
                .udp_conn_state_store(
                    &key,
                    &ConnState {
                        decision_token: token,
                        incarnation,
                        ..ConnState::default()
                    },
                )
                .unwrap();
            assert!(
                backend
                    .udp_flow_owner(token, backend.conn_state_lookup(&key).unwrap())
                    .is_err()
            );
        }
    }
}

fn seed_retirement_flow(backend: &mut RealEbpfBackend, port: u16) -> RetireRequest<'static> {
    let key = TuplesKey {
        src_port: port,
        l4proto: libc::IPPROTO_TCP as u8,
        ..TuplesKey::default()
    };
    let incarnation = u64::from(port);
    publish_retirement_flow(
        backend,
        &key,
        &ConnState {
            incarnation,
            ..ConnState::default()
        },
    )
    .unwrap();
    RetireRequest {
        key,
        kind: RetireKind::Tcp { incarnation },
    }
}

fn assert_retirement_flow_present(backend: &RealEbpfBackend, key: &TuplesKey) {
    assert!(backend.conn_state_lookup(key).unwrap().is_some());
    assert!(backend.routing_handoff_lookup(key).unwrap().is_some());
    assert!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(key))
            .unwrap()
            .is_some()
    );
}

fn assert_retirement_fence(backend: &RealEbpfBackend, key: &TuplesKey, present: bool) {
    assert_eq!(
        backend
            .hash_lookup::<_, RetirementFence>(RETIRE_FENCE_MAP, key)
            .unwrap()
            .is_some(),
        present
    );
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn retirement_acquire_and_barrier_failures_preserve_all_maps_and_release_owned_fences() {
    for barrier in [false, true] {
        let mut backend = retirement_fixture();
        let requests = [
            seed_retirement_flow(&mut backend, 41001),
            seed_retirement_flow(&mut backend, 41002),
        ];
        backend.retirement_faults = backend_retirement::RetirementFaults {
            acquire: (!barrier).then_some(1),
            barrier,
            ..Default::default()
        };
        let mut outcomes = [RetireOutcome::NotRun; 2];
        let error = backend.retire_batch(&requests, &mut outcomes).unwrap_err();
        assert_eq!(error.counts, RetireCounts::default());
        assert_eq!(outcomes, [RetireOutcome::NotRun; 2]);
        for request in &requests {
            assert_retirement_flow_present(&backend, &request.key);
            assert_retirement_fence(&backend, &request.key, false);
        }
        assert_eq!(
            backend.array_get::<u32>("RETIRE_ACTIVE", 0).unwrap(),
            Some(0)
        );
        assert!(!backend.retirement_failed);
        assert_eq!(
            backend.retire_batch(&requests, &mut outcomes).unwrap(),
            RetireCounts {
                conn: 2,
                redirect: 2,
                handoff: 2,
            }
        );
        assert_eq!(outcomes, [RetireOutcome::ConnRetired; 2]);
    }
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn retirement_delete_failure_reports_completed_map_deletions_only() {
    let mut backend = retirement_fixture();
    let request = seed_retirement_flow(&mut backend, 41003);
    backend.retirement_faults.delete = Some(1);
    let mut outcomes = [RetireOutcome::NotRun];
    let error = backend.retire_batch(&[request], &mut outcomes).unwrap_err();
    assert_eq!(
        error.counts,
        RetireCounts {
            handoff: 1,
            ..RetireCounts::default()
        }
    );
    assert_eq!(outcomes, [RetireOutcome::NotRun]);
    assert!(
        backend
            .routing_handoff_lookup(&request.key)
            .unwrap()
            .is_none()
    );
    assert!(backend.conn_state_lookup(&request.key).unwrap().is_some());
    assert!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&request.key))
            .unwrap()
            .is_some()
    );
    assert_retirement_fence(&backend, &request.key, false);
    assert_eq!(
        backend.array_get::<u32>("RETIRE_ACTIVE", 0).unwrap(),
        Some(0)
    );
    let (counts, result) = retire_fixture(&mut backend, request.key, request.kind);
    assert_eq!(
        counts,
        RetireCounts {
            conn: 1,
            redirect: 1,
            ..RetireCounts::default()
        }
    );
    assert_eq!(result, UdpDecisionCommitResult::Applied);
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn retirement_preserves_barrier_and_release_errors_and_inhibits_admission() {
    let mut backend = retirement_fixture();
    let requests = [
        seed_retirement_flow(&mut backend, 41004),
        seed_retirement_flow(&mut backend, 41005),
        seed_retirement_flow(&mut backend, 41006),
    ];
    backend.retirement_faults = backend_retirement::RetirementFaults {
        barrier: true,
        release: Some(1),
        ..Default::default()
    };
    let mut outcomes = [RetireOutcome::NotRun; 3];
    let error = backend.retire_batch(&requests, &mut outcomes).unwrap_err();
    assert_eq!(error.counts, RetireCounts::default());
    assert_eq!(outcomes, [RetireOutcome::NotRun; 3]);
    for (index, request) in requests.iter().enumerate() {
        assert_retirement_flow_present(&backend, &request.key);
        assert_retirement_fence(&backend, &request.key, index == 1);
    }
    assert_eq!(
        backend.array_get::<u32>("RETIRE_ACTIVE", 0).unwrap(),
        Some(1)
    );
    assert!(backend.retirement_failed);
    let error = backend.retire_batch(&requests, &mut outcomes).unwrap_err();
    assert_eq!(error.counts, RetireCounts::default());
    assert_eq!(outcomes, [RetireOutcome::NotRun; 3]);
    assert!(backend.set_datapath_ready(true).is_err());
    assert!(
        backend
            .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
            .is_err()
    );
    assert!(backend.retirement_failed);
}

fn publish_retirement_flow(
    backend: &mut RealEbpfBackend,
    key: &TuplesKey,
    state: &ConnState,
) -> anyhow::Result<()> {
    backend
        .hash_map_mut::<TuplesKey, FlowMapValue<ConnState>>("CONN_STATE_MAP")?
        .insert(key, &FlowMapValue::new(*state), 1 | 4)?;
    backend
        .hash_map_mut::<TuplesKey, FlowMapValue<RoutingHandoffEntry>>("ROUTING_HANDOFF_MAP")?
        .insert(
            key,
            &FlowMapValue::new(RoutingHandoffEntry {
                incarnation: state.incarnation,
                result: RoutingResult {
                    decision_token: state.decision_token,
                    ..Default::default()
                },
                ..Default::default()
            }),
            1 | 4,
        )?;
    backend
        .hash_map_mut::<RedirectTuple, FlowMapValue<RedirectEntry>>("REDIRECT_TRACK")?
        .insert(
            &RedirectTuple::from_tuples(key),
            &FlowMapValue::new(RedirectEntry {
                incarnation: state.incarnation,
                decision_token: state.decision_token,
                ..Default::default()
            }),
            1 | 4,
        )?;
    Ok(())
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn token_zero_lan_retirement_allows_same_tuple_republication() -> anyhow::Result<()> {
    let mut backend = retirement_fixture();
    let key = TuplesKey {
        src_port: 41200,
        l4proto: 17,
        ..Default::default()
    };
    let state = ConnState {
        incarnation: 1,
        meta: RoutingMeta {
            raw: ROUTING_META_FLAG_PUBLISHED | OutboundIndex::UserBase as u64,
        },
        ..Default::default()
    };
    publish_retirement_flow(&mut backend, &key, &state)?;
    let request = RetireRequest {
        key,
        kind: RetireKind::Udp {
            token: 0,
            incarnation: Some(1),
            pending_only: false,
        },
    };
    let (counts, result) = retire_fixture(&mut backend, request.key, request.kind);
    assert_eq!(
        counts,
        RetireCounts {
            conn: 1,
            handoff: 1,
            redirect: 1,
        }
    );
    assert_eq!(result, UdpDecisionCommitResult::Applied);
    assert_retirement_fence(&backend, &key, false);
    publish_retirement_flow(
        &mut backend,
        &key,
        &ConnState {
            incarnation: 2,
            ..state
        },
    )?;
    let (counts, result) = retire_fixture(&mut backend, request.key, request.kind);
    assert_eq!(counts, RetireCounts::default());
    assert_eq!(result, UdpDecisionCommitResult::Superseded);
    assert_retirement_flow_present(&backend, &key);
    let raw = ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD;
    backend.udp_conn_state_store(
        &key,
        &ConnState {
            incarnation: 2,
            meta: RoutingMeta { raw },
            ..state
        },
    )?;
    let native_request = RetireRequest {
        key,
        kind: RetireKind::Udp {
            token: 0,
            incarnation: Some(2),
            pending_only: false,
        },
    };
    let (counts, result) = retire_fixture(&mut backend, native_request.key, native_request.kind);
    assert_eq!(counts, RetireCounts::default());
    assert_eq!(result, UdpDecisionCommitResult::Superseded);
    assert_retirement_flow_present(&backend, &key);
    assert_eq!(
        unsafe { backend.conn_state_lookup(&key)?.unwrap().meta.raw },
        raw
    );
    Ok(())
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn expired_conn_retirement_removes_auxiliaries_before_tuple_reuse() -> anyhow::Result<()> {
    let mut backend = retirement_fixture();
    for (index, (proto, token)) in [(6, 0), (17, 0), (17, 7)].into_iter().enumerate() {
        let key = TuplesKey {
            src_port: 41210 + index as u16,
            l4proto: proto,
            ..Default::default()
        };
        let state = ConnState {
            incarnation: 1,
            decision_token: token,
            last_seen_ns: 10,
            ..Default::default()
        };
        publish_retirement_flow(&mut backend, &key, &state)?;
        let request = RetireRequest {
            key,
            kind: RetireKind::ExpiredConn {
                expected: &state,
                expired_before_ns: 10,
            },
        };
        let (counts, result) = retire_fixture(&mut backend, request.key, request.kind);
        assert_eq!(
            counts,
            RetireCounts {
                conn: 1,
                handoff: 1,
                redirect: 1,
            }
        );
        assert_eq!(result, UdpDecisionCommitResult::Applied);
        publish_retirement_flow(
            &mut backend,
            &key,
            &ConnState {
                incarnation: 2,
                ..state
            },
        )?;
        let (counts, result) = retire_fixture(&mut backend, request.key, request.kind);
        assert_eq!(counts, RetireCounts::default());
        assert_eq!(result, UdpDecisionCommitResult::Superseded);
        assert_retirement_flow_present(&backend, &key);
    }
    Ok(())
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn retirement_auxiliary_owner_mismatch_is_fatal_and_preserves_all_maps() -> anyhow::Result<()> {
    let mut backend = retirement_fixture();
    for operation in 0..5 {
        let key = TuplesKey {
            src_port: 41220 + operation,
            l4proto: if matches!(operation, 0 | 4) { 6 } else { 17 },
            ..Default::default()
        };
        let state = ConnState {
            incarnation: 1,
            meta: RoutingMeta {
                raw: ROUTING_META_FLAG_PUBLISHED | OutboundIndex::UserBase as u64,
            },
            ..Default::default()
        };
        publish_retirement_flow(&mut backend, &key, &state)?;
        if operation == 4 {
            let track_key = RedirectTuple::from_tuples(&key);
            let mut track = backend.redirect_track_lookup(&track_key)?.unwrap();
            track.decision_token = 7;
            backend.flow_insert("REDIRECT_TRACK", &track_key, &track)?;
        } else {
            let mut handoff = backend.routing_handoff_lookup(&key)?.unwrap();
            handoff.result.decision_token = 7;
            backend.flow_insert("ROUTING_HANDOFF_MAP", &key, &handoff)?;
        }
        let kind = match operation {
            0 | 4 => RetireKind::Tcp { incarnation: 1 },
            1 => RetireKind::Udp {
                token: 0,
                incarnation: Some(1),
                pending_only: false,
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
        let (counts, result) = retire_fixture(&mut backend, key, kind);
        assert_eq!(counts, RetireCounts::default());
        assert_eq!(result, UdpDecisionCommitResult::TokenMismatch);
        assert_retirement_flow_present(&backend, &key);
        assert_retirement_fence(&backend, &key, false);
        assert_eq!(backend.conn_state_lookup(&key)?.unwrap().incarnation, 1);
        assert_eq!(
            backend
                .routing_handoff_lookup(&key)?
                .unwrap()
                .result
                .decision_token,
            if operation == 4 { 0 } else { 7 }
        );
        assert_eq!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))?
                .unwrap()
                .decision_token,
            if operation == 4 { 7 } else { 0 }
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn udp_commit_auxiliary_incarnation_mismatch_is_fatal() -> anyhow::Result<()> {
    let mut backend = retirement_fixture();
    for handoff_mismatch in [false, true] {
        let key = TuplesKey {
            src_port: 41250 + u16::from(handoff_mismatch),
            l4proto: 17,
            ..Default::default()
        };
        let state = ConnState {
            incarnation: 1,
            decision_token: 7,
            state: UdpDecisionState::Pending as u8,
            ..Default::default()
        };
        publish_retirement_flow(&mut backend, &key, &state)?;
        if handoff_mismatch {
            let mut entry = backend.routing_handoff_lookup(&key)?.unwrap();
            entry.incarnation = 2;
            backend.flow_insert("ROUTING_HANDOFF_MAP", &key, &entry)?;
        } else {
            let track_key = RedirectTuple::from_tuples(&key);
            let mut entry = backend.redirect_track_lookup(&track_key)?.unwrap();
            entry.incarnation = 2;
            backend.flow_insert("REDIRECT_TRACK", &track_key, &entry)?;
        }
        assert_eq!(
            backend.commit_udp_decision(&key, 7, UdpDecisionTransition::Block)?,
            UdpDecisionCommitResult::TokenMismatch
        );
        assert_eq!(
            backend.conn_state_lookup(&key)?.unwrap().state,
            UdpDecisionState::Pending as u8
        );
        assert_retirement_flow_present(&backend, &key);
        assert_retirement_fence(&backend, &key, false);
    }
    Ok(())
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn expired_conn_delete_failure_preserves_actual_auxiliary_progress() -> anyhow::Result<()> {
    let mut backend = retirement_fixture();
    let seeded = seed_retirement_flow(&mut backend, 41260);
    let expected = backend.conn_state_lookup(&seeded.key)?.unwrap();
    let request = RetireRequest {
        key: seeded.key,
        kind: RetireKind::ExpiredConn {
            expected: &expected,
            expired_before_ns: 0,
        },
    };
    backend.retirement_faults.delete = Some(1);
    let mut outcomes = [RetireOutcome::NotRun];
    let error = backend.retire_batch(&[request], &mut outcomes).unwrap_err();
    assert_eq!(
        error.counts,
        RetireCounts {
            handoff: 1,
            ..Default::default()
        }
    );
    assert_eq!(outcomes, [RetireOutcome::NotRun]);
    assert!(backend.routing_handoff_lookup(&request.key)?.is_none());
    assert!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&request.key))?
            .is_some()
    );
    assert!(backend.conn_state_lookup(&request.key)?.is_some());
    assert_retirement_fence(&backend, &request.key, false);
    let (counts, result) = retire_fixture(&mut backend, request.key, request.kind);
    assert_eq!(
        counts,
        RetireCounts {
            conn: 1,
            redirect: 1,
            ..Default::default()
        }
    );
    assert_eq!(result, UdpDecisionCommitResult::Applied);
    Ok(())
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn hint_auxiliary_expiry_requires_matching_tokens_without_conn() -> anyhow::Result<()> {
    let mut backend = retirement_fixture();
    let key = TuplesKey {
        src_port: 41270,
        l4proto: 17,
        ..Default::default()
    };
    let state = ConnState {
        incarnation: 1,
        decision_token: 7,
        ..Default::default()
    };
    publish_retirement_flow(&mut backend, &key, &state)?;
    backend.hash_remove::<_, FlowMapValue<ConnState>>("CONN_STATE_MAP", &key)?;
    let track_key = RedirectTuple::from_tuples(&key);
    let mut track = backend.redirect_track_lookup(&track_key)?.unwrap();
    track.decision_token = 8;
    backend.flow_insert("REDIRECT_TRACK", &track_key, &track)?;
    let request = RetireRequest {
        key,
        kind: RetireKind::ExpiryHint {
            incarnation: 1,
            now_ns: 121_000_000_000,
        },
    };
    let (counts, result) = retire_fixture(&mut backend, request.key, request.kind);
    assert_eq!(counts, RetireCounts::default());
    assert_eq!(result, UdpDecisionCommitResult::TokenMismatch);
    assert_eq!(
        backend
            .routing_handoff_lookup(&key)?
            .unwrap()
            .result
            .decision_token,
        7
    );
    assert_eq!(
        backend
            .redirect_track_lookup(&track_key)?
            .unwrap()
            .decision_token,
        8
    );
    assert_retirement_fence(&backend, &key, false);
    track.decision_token = 7;
    backend.flow_insert("REDIRECT_TRACK", &track_key, &track)?;
    let (counts, result) = retire_fixture(&mut backend, request.key, request.kind);
    assert_eq!(
        counts,
        RetireCounts {
            handoff: 1,
            redirect: 1,
            ..Default::default()
        }
    );
    assert_eq!(result, UdpDecisionCommitResult::Applied);
    assert!(backend.conn_state_lookup(&key)?.is_none());
    assert_retirement_fence(&backend, &key, false);
    Ok(())
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn aborted_udp_retires_without_age_and_quiescence_keeps_completed_flows() -> anyhow::Result<()> {
    let mut backend = retirement_fixture();
    let key = TuplesKey {
        src_port: 41302,
        l4proto: 17,
        ..Default::default()
    };
    let aborted = ConnState {
        state: UdpDecisionState::Aborted as u8,
        decision_token: 7,
        incarnation: 1,
        last_seen_ns: u64::MAX,
        ..Default::default()
    };
    publish_retirement_flow(&mut backend, &key, &aborted)?;
    let (counts, result) = retire_fixture(
        &mut backend,
        key,
        RetireKind::ExpiredConn {
            expected: &aborted,
            expired_before_ns: 0,
        },
    );
    assert_eq!(
        counts,
        RetireCounts {
            conn: 1,
            handoff: 1,
            redirect: 1,
        }
    );
    assert_eq!(result, UdpDecisionCommitResult::Applied);

    let mut staged = Vec::new();
    for (index, state) in [
        UdpDecisionState::Preparing,
        UdpDecisionState::Pending,
        UdpDecisionState::Aborted,
    ]
    .into_iter()
    .enumerate()
    {
        let key = TuplesKey {
            src_port: 41303 + index as u16,
            ..key
        };
        publish_retirement_flow(
            &mut backend,
            &key,
            &ConnState {
                state: state as u8,
                decision_token: if state == UdpDecisionState::Preparing {
                    0
                } else {
                    7
                },
                incarnation: 2 + index as u64,
                ..aborted
            },
        )?;
        staged.push(key);
    }
    let proxy = TuplesKey {
        src_port: 41306,
        ..key
    };
    publish_retirement_flow(
        &mut backend,
        &proxy,
        &ConnState {
            state: UdpDecisionState::Proxy as u8,
            incarnation: 5,
            ..aborted
        },
    )?;
    backend.quiesce_udp_staging()?;
    for key in staged {
        assert!(backend.conn_state_lookup(&key)?.is_none());
        assert!(backend.routing_handoff_lookup(&key)?.is_none());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))?
                .is_none()
        );
    }
    assert_retirement_flow_present(&backend, &proxy);
    assert_eq!(
        backend.conn_state_lookup(&proxy)?.unwrap().state,
        UdpDecisionState::Proxy as u8
    );
    Ok(())
}
