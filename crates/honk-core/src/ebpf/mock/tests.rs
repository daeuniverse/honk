use super::*;
use honk_ebpf_common::dae_ip::In6Addr;

#[test]
fn listener_clear_rejects_live_admission_and_fences_partial_failure() {
    let mut backend = MockEbpfBackend::new();
    backend
        .publish_listener_sockets(10, Some(11), &[12, 13, 14, 15], &[16, 17, 18, 19])
        .unwrap();
    backend.set_datapath_ready(true).unwrap();
    assert!(backend.clear_listener_sockets().is_err());
    assert!(backend.listener_sockets_published);
    assert_eq!(backend.listener_socket_slots.len(), 10);
    backend.set_datapath_ready(false).unwrap();
    backend.listener_clear_fault_at = Some(4);
    assert!(backend.clear_listener_sockets().is_err());
    assert!(!backend.listener_sockets_published);
    assert!(!backend.datapath_ready);
    assert!(!backend.listener_socket_slots.contains_key(&3));
    assert_eq!(backend.listener_socket_slots.get(&4), Some(&14));
    assert!(backend.set_datapath_ready(true).is_err());
    backend.clear_listener_sockets().unwrap();
    assert!(backend.listener_socket_slots.is_empty());
    assert!(backend.set_datapath_ready(true).is_err());
    backend
        .publish_listener_sockets(20, None, &[22, 23, 24, 25], &[])
        .unwrap();
    assert_eq!(backend.listener_socket_slots.len(), 5);
    assert!(!backend.listener_socket_slots.contains_key(&1));
    assert!(!backend.listener_socket_slots.contains_key(&6));
    backend.set_datapath_ready(true).unwrap();
}

fn decision_test_key() -> TuplesKey {
    let mut key: TuplesKey = unsafe { std::mem::zeroed() };
    key.dst_ip[15] = 1;
    key.src_ip[15] = 2;
    key.dst_port = 443;
    key.src_port = 53000;
    key.l4proto = 17;
    key
}

fn decision_test_meta(outbound: u8, mark: u32, dscp: u8) -> RoutingMeta {
    RoutingMeta {
        raw: outbound as u64
            | ((mark as u64) << 8)
            | (1 << 40)
            | ((dscp as u64) << 48)
            | ROUTING_META_FLAG_PUBLISHED,
    }
}

fn seed_staged_flow(backend: &mut MockEbpfBackend, key: &TuplesKey, token: u32) {
    backend.seed_staged_udp_flow(
        key,
        ConnState {
            state: UdpDecisionState::Pending as u8,
            decision_token: token,
            last_seen_ns: 1,
            meta: decision_test_meta(OutboundIndex::UserBase as u8, TPROXY_MARK, 5),
            pid: 99,
            ..Default::default()
        },
    );
}

#[test]
fn udp_direct_transition_is_two_phase_and_preserves_metadata() {
    let mut backend = MockEbpfBackend::new();
    let key = decision_test_key();
    seed_staged_flow(&mut backend, &key, 7);

    assert_eq!(
        backend
            .commit_udp_decision(&key, 7, UdpDecisionTransition::ArmDirect(0x1234))
            .unwrap(),
        UdpDecisionCommitResult::Applied
    );
    let armed = backend.conn_state_lookup(&key).unwrap().unwrap();
    let armed_raw = unsafe { armed.meta.raw };
    assert_eq!(armed.state, UdpDecisionState::DirectArmed as u8);
    assert_eq!(armed.decision_token, 7);
    assert_eq!(armed.pid, 99);
    assert_eq!(armed_raw & 0xff, OutboundIndex::Direct as u64);
    assert_eq!((armed_raw >> 8) & 0xffff_ffff, 0x1234);
    assert_eq!((armed_raw >> 48) & 0xff, 5);
    assert_eq!(armed_raw & ROUTING_META_FLAG_OFFLOAD, 0);
    assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
    assert!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .is_none()
    );

    assert_eq!(
        backend
            .commit_udp_decision(&key, 7, UdpDecisionTransition::ActivateDirect(0x5678))
            .unwrap(),
        UdpDecisionCommitResult::StateMismatch
    );
    backend.commit_barrier_fault = true;
    assert_eq!(
        backend
            .commit_udp_decision(&key, 7, UdpDecisionTransition::ActivateDirect(0x1234))
            .unwrap(),
        UdpDecisionCommitResult::Applied
    );
    let active = backend.conn_state_lookup(&key).unwrap().unwrap();
    let active_raw = unsafe { active.meta.raw };
    assert_eq!(active.state, UdpDecisionState::None as u8);
    assert_eq!((active_raw >> 8) & 0xffff_ffff, 0x1234);
    assert_ne!(active_raw & ROUTING_META_FLAG_OFFLOAD, 0);
    assert!(
        backend.commit_barrier_fault,
        "activation used a grace barrier"
    );
    assert_eq!(active.last_seen_ns, armed.last_seen_ns);
    assert_eq!(active.incarnation, armed.incarnation);
    assert_eq!(
        backend
            .commit_udp_decision(&key, 7, UdpDecisionTransition::ActivateDirect(0x1234))
            .unwrap(),
        UdpDecisionCommitResult::StateMismatch
    );
}

#[test]
fn udp_proxy_transition_rewrites_exact_track() {
    let mut backend = MockEbpfBackend::new();
    let key = decision_test_key();
    seed_staged_flow(&mut backend, &key, 11);
    assert_eq!(
        backend
            .commit_udp_decision(
                &key,
                11,
                UdpDecisionTransition::ActivateProxy(OutboundIndex::UserBase as u8 + 2, 42),
            )
            .unwrap(),
        UdpDecisionCommitResult::Applied
    );
    let state = backend.conn_state_lookup(&key).unwrap().unwrap();
    let raw = unsafe { state.meta.raw };
    assert_eq!(state.state, UdpDecisionState::Proxy as u8);
    assert_eq!(raw & 0xff, (OutboundIndex::UserBase as u8 + 2) as u64);
    assert_eq!((raw >> 8) & 0xffff_ffff, 42);
    assert_eq!((raw >> 48) & 0xff, 5);
    let track = backend
        .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
        .unwrap()
        .unwrap();
    assert_eq!(track.decision_token, 11);
    assert_eq!(track.outbound, OutboundIndex::UserBase as u8 + 2);
    assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
    assert_eq!(
        retire_fixture(
            &mut backend,
            key,
            RetireKind::Udp {
                token: 11,
                incarnation: None,
                pending_only: false
            }
        )
        .1,
        UdpDecisionCommitResult::Applied
    );
    assert!(backend.conn_state_lookup(&key).unwrap().is_none());
    assert!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .is_none()
    );
}

#[test]
fn udp_transition_distinguishes_missing_token_and_state_mismatches() {
    let mut backend = MockEbpfBackend::new();
    let key = decision_test_key();
    assert_eq!(
        backend
            .commit_udp_decision(&key, 1, UdpDecisionTransition::Block)
            .unwrap(),
        UdpDecisionCommitResult::Missing
    );
    seed_staged_flow(&mut backend, &key, 17);
    assert_eq!(
        backend
            .commit_udp_decision(&key, 18, UdpDecisionTransition::Block)
            .unwrap(),
        UdpDecisionCommitResult::TokenMismatch
    );
    let mut newer = backend.conn_state_lookup(&key).unwrap().unwrap();
    newer.state = UdpDecisionState::Proxy as u8;
    backend.udp_conn_state_store(&key, &newer).unwrap();
    assert_eq!(
        backend
            .commit_udp_decision(&key, 17, UdpDecisionTransition::Block)
            .unwrap(),
        UdpDecisionCommitResult::StateMismatch
    );
    assert!(backend.routing_handoff_lookup(&key).unwrap().is_some());
}

#[test]
fn legacy_removal_retires_auxiliaries_and_preserves_native_state() {
    let mut backend = MockEbpfBackend::new();
    let key = decision_test_key();
    backend
        .udp_conn_state_store(
            &key,
            &ConnState {
                state: UdpDecisionState::None as u8,
                meta: RoutingMeta {
                    raw: OutboundIndex::UserBase as u64 | ROUTING_META_FLAG_PUBLISHED,
                },
                ..Default::default()
            },
        )
        .unwrap();
    backend.routing_handoffs.lock().insert(
        MockEbpfBackend::tuples_key_bytes(&key),
        RoutingHandoffEntry::default(),
    );
    backend
        .redirect_track_store(&RedirectTuple::from_tuples(&key), &RedirectEntry::default())
        .unwrap();

    assert_eq!(
        retire_fixture(
            &mut backend,
            key,
            RetireKind::Udp {
                token: 0,
                incarnation: None,
                pending_only: false
            }
        )
        .1,
        UdpDecisionCommitResult::Applied
    );
    assert!(backend.conn_state_lookup(&key).unwrap().is_none());
    assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
    assert!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .is_none()
    );

    let terminal_raw =
        OutboundIndex::Direct as u64 | ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD;
    backend
        .udp_conn_state_store(
            &key,
            &ConnState {
                state: UdpDecisionState::None as u8,
                meta: RoutingMeta { raw: terminal_raw },
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        retire_fixture(
            &mut backend,
            key,
            RetireKind::Udp {
                token: 0,
                incarnation: None,
                pending_only: false
            }
        )
        .1,
        UdpDecisionCommitResult::Superseded
    );
    assert!(backend.conn_state_lookup(&key).unwrap().is_some());
}

#[test]
fn missing_udp_owner_preserves_auxiliaries() {
    let mut backend = MockEbpfBackend::new();
    let key = decision_test_key();
    seed_staged_flow(&mut backend, &key, 7);
    backend.udp_conn_states.clear();
    let (counts, outcome) = retire_fixture(
        &mut backend,
        key,
        RetireKind::Udp {
            token: 7,
            incarnation: None,
            pending_only: true,
        },
    );
    assert_eq!(counts, RetireCounts::default());
    assert_eq!(outcome, UdpDecisionCommitResult::Missing);
    assert_eq!(
        backend
            .routing_handoff_lookup(&key)
            .unwrap()
            .unwrap()
            .result
            .decision_token,
        7
    );
    assert_eq!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .unwrap()
            .decision_token,
        7
    );
}

#[test]
fn pending_retirement_reports_state_delete_and_sequence_survives_cleanup() {
    let mut backend = MockEbpfBackend::new();
    let key = decision_test_key();
    seed_staged_flow(&mut backend, &key, 31);
    let (counts, outcome) = retire_fixture(
        &mut backend,
        key,
        RetireKind::Udp {
            token: 31,
            incarnation: None,
            pending_only: true,
        },
    );
    assert_eq!(outcome, UdpDecisionCommitResult::Applied);
    assert_eq!(counts.conn, 1);
    assert_eq!(counts.redirect, 1);
    assert_eq!(counts.handoff, 1);
    backend.udp_decision_sequence_next = 123;
    futures::executor::block_on(backend.cleanup()).unwrap();
    assert_eq!(backend.udp_decision_sequence_next, 123);
}

#[test]
fn exhausted_sequence_skips_rollback_reachable_generations() {
    let mut backend = MockEbpfBackend::new();
    backend.udp_decision_sequence_next = UDP_DECISION_SEQUENCE_MASK;
    let key = decision_test_key();
    let live_token = udp_decision_token(1, 7).unwrap();
    backend
        .udp_conn_state_store(
            &key,
            &ConnState {
                state: UdpDecisionState::Proxy as u8,
                decision_token: live_token,
                ..Default::default()
            },
        )
        .unwrap();

    assert!(!backend.reset_udp_decision_sequence(0).unwrap());
    assert!(!backend.reset_udp_decision_sequence(1).unwrap());

    assert!(backend.reset_udp_decision_sequence(2).unwrap());
    assert_eq!(
        backend.udp_decision_sequence_status().unwrap(),
        UdpDecisionSequenceStatus {
            next: 0,
            generation: 2,
        }
    );
}

#[test]
fn exhausted_sequence_skips_live_retirement_fence() {
    let mut backend = MockEbpfBackend::new();
    backend.udp_decision_sequence_next = UDP_DECISION_SEQUENCE_MASK;
    let key = decision_test_key();
    backend.retire_fences.insert(
        MockEbpfBackend::tuples_key_bytes(&key),
        RetirementFence {
            owner: 1,
            decision_token: udp_decision_token(1, 7).unwrap(),
            padding: 0,
        },
    );

    assert!(!backend.reset_udp_decision_sequence(1).unwrap());
    backend.retire_fences.clear();
    assert!(backend.reset_udp_decision_sequence(1).unwrap());
}

fn routing_plan(tag: u8) -> crate::control::routing_matcher::RoutingPushPlan {
    let rule = honk_config::routing::RoutingRule {
        name: format!("policy-{tag}"),
        condition: honk_config::routing::RoutingCondition {
            domain: vec![format!("policy-{tag}.test")],
            ip: vec![format!("192.0.2.{tag}/32")],
            ..Default::default()
        },
        outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
        priority: 0,
        must: false,
        mark: u32::from(tag),
    };
    let router = crate::routing::Router::new(&[rule], "direct").unwrap();
    crate::control::routing_matcher::RoutingPushPlan::compile(
        &router,
        &HashMap::from([("direct".into(), 0)]),
        honk_config::types::DialMode::Domain,
    )
    .unwrap()
}

#[test]
fn routing_publish_is_atomic_and_root_is_last() {
    let mut backend = MockEbpfBackend::new();
    backend.publish_routing_plan(&routing_plan(1), &[]).unwrap();
    let accepted = backend.routing_snapshot();

    let domain_key = LpmKey {
        prefix_len: 128,
        data: [0, 0, 0xffff0000, 2],
    };
    backend.fail_next_routing_phase(RoutingPushPhase::Root);
    assert!(
        backend
            .publish_routing_plan(&routing_plan(2), &[(domain_key, DomainRouting::default())],)
            .is_err()
    );
    assert_eq!(backend.routing_snapshot(), accepted);

    backend.publish_routing_plan(&routing_plan(3), &[]).unwrap();
    assert!(backend.routing_snapshot().domain.is_empty());
    let replacement = routing_plan(2);
    backend
        .publish_routing_plan(&replacement, &[(domain_key, DomainRouting::default())])
        .unwrap();
    let current = backend.routing_snapshot();
    assert_eq!(current.active_slot, 1);
    assert_eq!(current.plan_fingerprint, replacement.fingerprint);
    assert_eq!(current.domain.len(), 1);
    assert_eq!(current.domain[0].1, [0; ROUTING_BITMAP_WORDS]);
    assert!(matches!(
        backend.routing_publication_order.last(),
        Some(MockRoutingPublicationWrite::Root(1))
    ));
}

#[test]
fn routing_generation_ceiling_rejects_before_staging() {
    let mut backend = MockEbpfBackend::new();
    backend.policy.next_generation = DNS_ROUTE_GENERATION_MAX - 1;
    backend.publish_routing_plan(&routing_plan(1), &[]).unwrap();
    let accepted = backend.routing_snapshot();
    let writes = backend.routing_publication_order.clone();

    assert!(backend.publish_routing_plan(&routing_plan(2), &[]).is_err());
    assert_eq!(
        backend.routing_policy_generation(),
        DNS_ROUTE_GENERATION_MAX
    );
    assert_eq!(backend.routing_snapshot(), accepted);
    assert_eq!(backend.routing_publication_order, writes);
}

#[test]
fn active_domain_zero_is_present_until_removed() {
    let mut backend = MockEbpfBackend::new();
    backend.publish_routing_plan(&routing_plan(1), &[]).unwrap();
    let key = LpmKey {
        prefix_len: 128,
        data: [0, 0, 0xffff0000, 3],
    };
    backend
        .set_domain_ip_bitmap(&key, &DomainRouting::default())
        .unwrap();
    assert_eq!(backend.routing_snapshot().domain.len(), 1);
    backend.remove_domain_ip_bitmap(&key).unwrap();
    assert!(backend.routing_snapshot().domain.is_empty());
}

#[test]
fn test_redirect_track_crud() {
    let mut backend = MockEbpfBackend::new();

    let key = RedirectTuple {
        src_ip: In6Addr::default(),
        dst_ip: In6Addr::default(),
        ..Default::default()
    };
    let entry = RedirectEntry {
        last_seen_ns: 1111111111,
        dmac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        smac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        from_wan: 0,
        ifindex: 2,
        ..Default::default()
    };

    assert!(backend.redirect_track_lookup(&key).unwrap().is_none());

    backend.redirect_track_store(&key, &entry).unwrap();
    let found = backend.redirect_track_lookup(&key).unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().last_seen_ns, 1111111111);

    let tuple = TuplesKey {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        src_port: key.src_port,
        dst_port: key.dst_port,
        l4proto: key.l4proto,
        padding: [0; 3],
    };
    assert_eq!(
        retire_fixture(
            &mut backend,
            tuple,
            RetireKind::ExpiredRedirect {
                expected: &entry,
                expired_before_ns: entry.last_seen_ns
            }
        )
        .0
        .redirect,
        1
    );
    assert!(backend.redirect_track_lookup(&key).unwrap().is_none());
}

#[test]
fn test_routing_handoff_lookup_and_retirement() {
    let mut backend = MockEbpfBackend::new();

    let key = TuplesKey {
        src_ip: In6Addr::default(),
        dst_ip: In6Addr::default(),
        src_port: 3000,
        dst_port: 80,
        l4proto: 6,
        padding: [0; 3],
    };

    let entry = RoutingHandoffEntry {
        last_seen_ns: 0,
        result: RoutingResult {
            mark: 1234,
            outbound: 5,
            ..Default::default()
        },
        routing_generation: 0,
        ..Default::default()
    };
    backend
        .routing_handoffs
        .lock()
        .insert(MockEbpfBackend::tuples_key_bytes(&key), entry);

    let found = backend.routing_handoff_lookup(&key).unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().result.mark, 1234);

    assert!(backend.routing_handoff_lookup(&key).unwrap().is_some());
    assert_eq!(
        retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiredHandoff {
                expected: &entry,
                expired_before_ns: 0
            }
        )
        .0
        .handoff,
        1
    );
    assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
}

#[test]
fn test_get_bpf_stats() {
    let mut backend = MockEbpfBackend::new();

    assert!(backend.get_bpf_stats(0).unwrap().is_none());
    assert!(backend.get_bpf_stats(42).unwrap().is_none());

    backend.bpf_stats.insert(0, 100);
    backend.bpf_stats.insert(1, 250);
    backend.bpf_stats.insert(99, 999);

    assert_eq!(backend.get_bpf_stats(0).unwrap(), Some(100));
    assert_eq!(backend.get_bpf_stats(1).unwrap(), Some(250));
    assert_eq!(backend.get_bpf_stats(99).unwrap(), Some(999));
    assert!(backend.get_bpf_stats(50).unwrap().is_none());
}

#[test]
fn trace_capture_exhaustion_and_cleanup_never_reuse_ids() {
    let mut backend = MockEbpfBackend::new();
    let mut witness = KernelRouteWitness::default();
    assert_eq!(backend.capture_route_witness(witness), 0);
    witness.output.flags = ROUTE_TRACE_ENABLED;
    let first = backend.capture_route_witness(witness);
    futures::executor::block_on(backend.cleanup()).unwrap();
    assert!(backend.capture_route_witness(witness) > first);
    backend.next_trace_id = ROUTE_TRACE_LOST - 2;
    assert_eq!(backend.capture_route_witness(witness), ROUTE_TRACE_LOST - 1);
    backend.route_witnesses.clear();
    assert_eq!(backend.capture_route_witness(witness), ROUTE_TRACE_LOST);
    assert_eq!(backend.capture_route_witness(witness), ROUTE_TRACE_LOST);
    assert!(backend.route_witnesses.is_empty());
}

#[test]
fn test_cleanup_clears_all_maps() {
    let mut backend = MockEbpfBackend::new();
    backend
        .tcp_conn_state_store(&TuplesKey::default(), &ConnState::default())
        .unwrap();
    backend
        .udp_conn_state_store(&TuplesKey::default(), &ConnState::default())
        .unwrap();
    backend
        .redirect_track_store(&RedirectTuple::default(), &RedirectEntry::default())
        .unwrap();
    backend.set_outbound_alive(1, 0, 4, true).unwrap();
    backend.bpf_stats.insert(0, 999);

    futures::executor::block_on(backend.cleanup()).unwrap();

    assert!(backend.tcp_conn_states.is_empty());
    assert!(backend.udp_conn_states.is_empty());
    assert!(backend.redirect_tracks.is_empty());
    assert!(backend.routing_handoffs.lock().is_empty());
    assert!(backend.policy.outbound_alive.is_empty());
    assert!(backend.bpf_stats.is_empty());
}
