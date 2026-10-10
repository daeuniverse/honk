use super::*;
use honk_ebpf_common::DATAPATH_FLAG_TRACE_ENABLED;

fn witness(backend: &RealEbpfBackend, id: u32) -> KernelRouteWitness {
    let map = backend.bpf().unwrap().map("ROUTE_TRACE_MAP").unwrap();
    HashMap::<_, u32, KernelRouteWitness>::try_from(map)
        .unwrap()
        .get(&id, 0)
        .unwrap()
}

fn capturing(must: bool) -> (RealEbpfBackend, RoutingPushPlan, TproxyListeners) {
    let rules = [rule(
        "trace",
        RoutingCondition {
            port: vec!["443".into()],
            ..Default::default()
        },
        "proxy",
        0,
        must,
    )];
    let (mut backend, mut plan, listeners) = publish(&rules);
    plan.enable_trace(true);
    backend.publish_routing_plan(&plan, &[]).unwrap();
    backend
        .set_datapath_flags(DATAPATH_FLAG_TRACE_ENABLED)
        .unwrap();
    (backend, plan, listeners)
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn runtime_trace_gate_preserves_redirect_authority_and_admitted_witnesses() {
    isolated(|| {
        let (mut backend, _, _listeners) = capturing(true);
        let src = "192.0.2.26".parse().unwrap();
        let dst = "198.51.100.36".parse().unwrap();
        for side in ["lan_ingress_l2", "wan_egress_l2"] {
            for protocol in [IPPROTO_TCP, IPPROTO_UDP] {
                let port =
                    43100 + if side == "wan_egress_l2" { 10 } else { 0 } + u16::from(protocol);
                let bytes = packet(src, dst, protocol, port, 443, 5, 2);
                let key = tuple(src, dst, port, 443, protocol);
                backend.set_datapath_flags(0).unwrap();
                let count = hash_count::<u32, KernelRouteWitness>(&backend, "ROUTE_TRACE_MAP");
                let sequence = backend
                    .array_get::<[u32; 2]>("ROUTE_TRACE_SEQUENCE", 0)
                    .unwrap();
                let off = run(&backend, side, &bytes, SkbInput::default());
                assert_eq!(off.verdict, TC_ACT_REDIRECT);
                let unrecorded = handoff(&backend, &key);
                assert_eq!(unrecorded.trace_id, 0);
                assert_eq!(off.cb[3], 0);
                assert_eq!(
                    hash_count::<u32, KernelRouteWitness>(&backend, "ROUTE_TRACE_MAP"),
                    count
                );
                assert_eq!(
                    backend
                        .array_get::<[u32; 2]>("ROUTE_TRACE_SEQUENCE", 0)
                        .unwrap(),
                    sequence
                );

                backend
                    .set_datapath_flags(DATAPATH_FLAG_TRACE_ENABLED)
                    .unwrap();
                let bytes = packet(src, dst, protocol, port + 1, 443, 5, 2);
                let key = tuple(src, dst, port + 1, 443, protocol);
                let on = run(&backend, side, &bytes, SkbInput::default());
                let recorded = handoff(&backend, &key);
                assert_eq!((on.verdict, on.mark), (off.verdict, off.mark));
                let authority = |entry: RoutingHandoffEntry| {
                    let result = entry.result;
                    (
                        result.outbound,
                        result.mark,
                        result.must,
                        result.decision_token,
                        result.mac,
                        result.pname,
                        result.pid,
                        result.dscp,
                        entry.routing_generation,
                    )
                };
                assert_eq!(authority(recorded), authority(unrecorded));
                assert_ne!(recorded.trace_id, 0);
                assert_ne!(recorded.trace_id, ROUTE_TRACE_LOST);
                let retained = witness(&backend, recorded.trace_id);
                backend.set_datapath_flags(0).unwrap();
                assert_eq!(witness(&backend, recorded.trace_id).output, retained.output);
                if protocol == IPPROTO_UDP {
                    backend.routing_handoff_take(&key).unwrap().unwrap();
                    let cached = run(&backend, side, &bytes, SkbInput::default());
                    assert_eq!(cached.cb[3], recorded.trace_id);
                    assert_eq!(handoff(&backend, &key).trace_id, recorded.trace_id);
                }
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn cached_token_zero_udp_preserves_original_witness_across_policy_and_packet_changes() {
    isolated(|| {
        let (mut backend, plan, _listeners) = capturing(true);
        let src = "192.0.2.19".parse().unwrap();
        let dst = "198.51.100.29".parse().unwrap();
        for (ordinal, side) in ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate() {
            let port = 43000 + ordinal as u16;
            let key = tuple(src, dst, port, 443, IPPROTO_UDP);
            let first = packet(src, dst, IPPROTO_UDP, port, 443, 5, 0);
            let first_run = run(&backend, side, &first, SkbInput::default());
            assert_eq!(first_run.verdict, TC_ACT_REDIRECT);
            let original = backend.routing_handoff_take(&key).unwrap().unwrap();
            assert_ne!(original.trace_id, 0);
            assert_ne!(original.trace_id, ROUTE_TRACE_LOST);
            assert_eq!(original.result.decision_token, 0);
            assert_eq!(first_run.cb[3], original.trace_id);
            let before = witness(&backend, original.trace_id);
            assert_eq!(before.output.input.dscp, 5);
            assert_eq!(before.output.generation, original.routing_generation);
            backend.set_datapath_flags(0).unwrap();
            backend.publish_routing_plan(&plan, &[]).unwrap();
            let changed = packet(src, dst, IPPROTO_UDP, port, 443, 19, 0);
            let changed_run = run(&backend, side, &changed, SkbInput::default());
            assert_eq!(changed_run.verdict, TC_ACT_REDIRECT);
            assert_eq!(changed_run.cb[3], original.trace_id);
            let restored = handoff(&backend, &key);
            assert_eq!(restored.trace_id, original.trace_id);
            assert_eq!(restored.routing_generation, original.routing_generation);
            assert_eq!(witness(&backend, restored.trace_id).output, before.output);
            backend
                .set_datapath_flags(DATAPATH_FLAG_TRACE_ENABLED)
                .unwrap();
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn staged_udp_witness_uses_exact_token_and_generation() {
    isolated(|| {
        for capture in [false, true] {
            let (mut backend, _, _listeners) = capturing(false);
            backend
                .set_datapath_flags(
                    DATAPATH_FLAG_NFQ_ENABLED
                        | DATAPATH_FLAG_NFQ_READY
                        | if capture {
                            DATAPATH_FLAG_TRACE_ENABLED
                        } else {
                            0
                        },
                )
                .unwrap();
            // A direct fallback is unresolved in the absence of mode-owned offload.
            let src = "192.0.2.20".parse().unwrap();
            let dst = "198.51.100.30".parse().unwrap();
            let key = tuple(src, dst, 43001, 444, IPPROTO_UDP);
            let bytes = packet(src, dst, IPPROTO_UDP, 43001, 444, 0, 0);
            let result = run(&backend, "lan_ingress_l2", &bytes, SkbInput::default());
            assert_eq!(result.verdict, TC_ACT_OK);
            let entry = handoff(&backend, &key);
            assert_ne!(entry.result.decision_token, 0);
            // A staged first packet already records its client, token-free.
            let mut client = RedirectTuple::from_tuples(&key);
            (client.dst_ip, client.dst_port) = (In6Addr::zero(), 0);
            let map = backend.bpf().unwrap().map("CLIENT_REPLY_TRACK").unwrap();
            let record: RedirectEntry = HashMap::try_from(map).unwrap().get(&client, 0).unwrap();
            assert_eq!(record.decision_token, 0);
            assert_eq!(
                result.mark & NFQUEUE_TOKEN_MASK,
                entry.result.decision_token
            );
            assert_eq!(
                entry.routing_generation,
                backend.routing_policy_generation()
            );
            if capture {
                let trace = witness(&backend, entry.trace_id);
                assert_eq!(trace.decision_token, entry.result.decision_token);
                assert_eq!(trace.output.generation, entry.routing_generation);
            } else {
                assert_eq!(entry.trace_id, 0);
                assert_eq!(
                    hash_count::<u32, KernelRouteWitness>(&backend, "ROUTE_TRACE_MAP"),
                    0
                );
            }
            assert_eq!(
                backend
                    .udp_conn_state_lookup(&key)
                    .unwrap()
                    .unwrap()
                    .trace_id,
                entry.trace_id
            );
            run(&backend, "lan_ingress_l2", &bytes, SkbInput::default());
            assert_eq!(handoff(&backend, &key).trace_id, entry.trace_id);
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn tcp_replacement_keeps_ambiguity_after_prior_sidecar_loss() {
    isolated(|| {
        let (mut backend, _, _listeners) = capturing(true);
        let src = "192.0.2.21".parse().unwrap();
        let dst = "198.51.100.31".parse().unwrap();
        let key = tuple(src, dst, 43002, 443, IPPROTO_TCP);
        let syn = packet(src, dst, IPPROTO_TCP, 43002, 443, 0, 2);
        run(&backend, "lan_ingress_l2", &syn, SkbInput::default());
        let first = handoff(&backend, &key);
        let old = witness(&backend, first.trace_id);
        assert_eq!(old.output.flags & ROUTE_TRACE_AMBIGUOUS, 0);
        let map = backend
            .bpf_mut()
            .unwrap()
            .map_mut("ROUTE_TRACE_MAP")
            .unwrap();
        HashMap::<_, u32, KernelRouteWitness>::try_from(map)
            .unwrap()
            .remove(&first.trace_id)
            .unwrap();
        run(&backend, "lan_ingress_l2", &syn, SkbInput::default());
        let second = handoff(&backend, &key);
        assert_ne!(first.trace_id, second.trace_id);
        assert_ne!(
            witness(&backend, second.trace_id).output.flags & ROUTE_TRACE_AMBIGUOUS,
            0
        );
        assert_eq!(old.output.flags & ROUTE_TRACE_AMBIGUOUS, 0);
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn exhausted_capture_ids_do_not_change_redirect_or_decision_tokens() {
    isolated(|| {
        let (mut backend, _, _listeners) = capturing(true);
        // spin_lock and next are u32; ordinary pins are never reopened for this allocator.
        set_array(
            &mut backend,
            "ROUTE_TRACE_SEQUENCE",
            0,
            [0u32, u32::MAX - 1],
        );
        let src = "192.0.2.22".parse().unwrap();
        let dst = "198.51.100.32".parse().unwrap();
        let key = tuple(src, dst, 43003, 443, IPPROTO_UDP);
        let bytes = packet(src, dst, IPPROTO_UDP, 43003, 443, 0, 0);
        let before = backend.udp_decision_sequence_status().unwrap();
        assert_eq!(
            run(&backend, "lan_ingress_l2", &bytes, SkbInput::default()).verdict,
            TC_ACT_REDIRECT
        );
        let entry = handoff(&backend, &key);
        assert_eq!(entry.trace_id, ROUTE_TRACE_LOST);
        assert_eq!(entry.result.outbound, 2);
        assert_eq!(backend.udp_decision_sequence_status().unwrap(), before);
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn sidecar_pressure_preserves_cached_reference_without_fabricating_new_evidence() {
    isolated(|| {
        let (backend, _, _listeners) = capturing(true);
        let src = "192.0.2.23".parse().unwrap();
        let dst = "198.51.100.33".parse().unwrap();
        let mut references = Vec::new();
        for offset in 0..=ROUTE_TRACE_CAPACITY {
            let port = 44000 + offset as u16;
            let key = tuple(src, dst, port, 443, IPPROTO_UDP);
            let bytes = packet(src, dst, IPPROTO_UDP, port, 443, 0, 0);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &bytes, SkbInput::default()).verdict,
                TC_ACT_REDIRECT
            );
            references.push((key, handoff(&backend, &key)));
        }
        let map = backend.bpf().unwrap().map("ROUTE_TRACE_MAP").unwrap();
        let map = HashMap::<_, u32, KernelRouteWitness>::try_from(map).unwrap();
        let (key, original) = references
            .iter()
            .find(|(_, entry)| map.get(&entry.trace_id, 0).is_err())
            .expect("bounded sidecar must evict a witness");
        backend.routing_handoff_take(key).unwrap().unwrap();
        let bytes = packet(src, dst, IPPROTO_UDP, key.src_port, 443, 7, 0);
        assert_eq!(
            run(&backend, "lan_ingress_l2", &bytes, SkbInput::default()).verdict,
            TC_ACT_REDIRECT
        );
        let restored = handoff(&backend, key);
        assert_eq!(restored.trace_id, original.trace_id);
        assert!(map.get(&restored.trace_id, 0).is_err());
        assert_eq!(restored.result.outbound, original.result.outbound);
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn delayed_token_zero_udp_keeps_its_packet_reference_after_conn_recreation() {
    isolated(|| {
        let (mut backend, _, _listeners) = capturing(true);
        load_classifier(&mut backend, "dae0peer_ingress");
        let before_sequence = backend.udp_decision_sequence_status().unwrap();
        for (src, dst) in [
            (
                "192.0.2.24".parse().unwrap(),
                "198.51.100.34".parse().unwrap(),
            ),
            (
                "2001:db8:1::24".parse().unwrap(),
                "2001:db8:2::34".parse().unwrap(),
            ),
        ] {
            for (ordinal, side) in ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate() {
                let port = 43010 + ordinal as u16;
                let key = tuple(src, dst, port, 443, IPPROTO_UDP);
                let packet_a = packet(src, dst, IPPROTO_UDP, port, 443, 5, 0);
                let a = run(&backend, side, &packet_a, SkbInput::default());
                assert_eq!(a.verdict, TC_ACT_REDIRECT);
                let old = backend.routing_handoff_take(&key).unwrap().unwrap();
                assert_eq!(old.result.decision_token, 0);
                assert_ne!(old.trace_id, 0);
                assert_ne!(old.trace_id, ROUTE_TRACE_LOST);
                assert_eq!(a.cb[3], old.trace_id);
                backend.udp_conn_state_remove(&key).unwrap();

                let packet_b = packet(src, dst, IPPROTO_UDP, port, 443, 19, 0);
                let b = run(&backend, side, &packet_b, SkbInput::default());
                assert_eq!(b.verdict, TC_ACT_REDIRECT);
                let current = handoff(&backend, &key);
                assert_eq!(current.result.decision_token, 0);
                assert_ne!(current.trace_id, old.trace_id);
                assert_ne!(current.trace_id, ROUTE_TRACE_LOST);
                assert_eq!(
                    backend
                        .udp_conn_state_lookup(&key)
                        .unwrap()
                        .unwrap()
                        .trace_id,
                    current.trace_id
                );
                assert_eq!(witness(&backend, old.trace_id).output.input.dscp, 5);
                assert_eq!(witness(&backend, current.trace_id).output.input.dscp, 19);

                for (bytes, redirected, expected) in [
                    (&packet_b, &b, current.trace_id),
                    (&packet_a, &a, old.trace_id),
                ] {
                    let peer = run(
                        &backend,
                        "dae0peer_ingress",
                        bytes,
                        SkbInput {
                            mark: redirected.mark,
                            cb: redirected.cb,
                            ..Default::default()
                        },
                    );
                    assert_eq!(peer.verdict, TC_ACT_OK);
                    assert_eq!(peer.mark, TPROXY_MARK);
                    assert_eq!(peer.priority, expected);
                }
                assert_eq!(handoff(&backend, &key).trace_id, current.trace_id);
            }
        }
        assert_eq!(
            backend.udp_decision_sequence_status().unwrap(),
            before_sequence
        );
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn marked_direct_must_wan_redirects_capture_tcp_and_udp_witnesses() {
    isolated(|| {
        let rules = [(443, USER_MARK), (444, 0), (53, USER_MARK)].map(|(port, mark)| {
            rule(
                &format!("direct-{port}"),
                RoutingCondition {
                    port: vec![port.to_string()],
                    ..Default::default()
                },
                "direct",
                mark,
                true,
            )
        });
        let (mut backend, mut plan, _listeners) = publish(&rules);
        plan.enable_trace(true);
        backend.publish_routing_plan(&plan, &[]).unwrap();
        backend
            .set_datapath_flags(DATAPATH_FLAG_TRACE_ENABLED)
            .unwrap();
        for slot in 0..6 {
            set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", slot, 1u64);
        }
        let src = "192.0.2.25".parse().unwrap();
        let dst = "198.51.100.35".parse().unwrap();
        for protocol in [IPPROTO_TCP, IPPROTO_UDP] {
            for (port, mark, redirected) in [
                (443, USER_MARK, true),
                (444, 0, false),
                (53, USER_MARK, true),
            ] {
                let key = tuple(src, dst, 43020, port, protocol);
                let bytes = packet(src, dst, protocol, 43020, port, 5, 2);
                let result = run(&backend, "wan_egress_l2", &bytes, SkbInput::default());
                assert_eq!(
                    result.verdict,
                    if redirected {
                        TC_ACT_REDIRECT
                    } else {
                        TC_ACT_OK
                    }
                );
                if redirected && port == 53 && protocol == IPPROTO_UDP {
                    // Must UDP DNS ownership is per packet: the route rides cb[2]
                    // and no tuple handoff is written.
                    assert!(backend.routing_handoff_take(&key).unwrap().is_none());
                    assert_eq!(
                        result.cb[2],
                        UdpDnsRoute::direct(0, backend.routing_policy_generation())
                            .unwrap()
                            .to_mark()
                    );
                    let trace_id = result.cb[3];
                    assert_ne!(trace_id, 0);
                    assert_ne!(trace_id, ROUTE_TRACE_LOST);
                    let captured = witness(&backend, trace_id);
                    assert_eq!(captured.output.decision.mark, mark);
                    assert_eq!(captured.output.decision.must, 1);
                    assert_ne!(captured.output.flags & ROUTE_TRACE_COMPLETE, 0);
                } else if redirected {
                    let entry = handoff(&backend, &key);
                    assert_eq!(entry.result.outbound, OutboundIndex::Direct as u8);
                    assert_eq!(entry.result.mark, mark);
                    assert_eq!(entry.result.must, 1);
                    assert_ne!(entry.trace_id, 0);
                    assert_ne!(entry.trace_id, ROUTE_TRACE_LOST);
                    let captured = witness(&backend, entry.trace_id);
                    assert_eq!(captured.output.decision.mark, mark);
                    assert_eq!(captured.output.decision.must, 1);
                    assert_ne!(captured.output.flags & ROUTE_TRACE_COMPLETE, 0);
                } else {
                    assert_eq!(result.mark, mark);
                    assert!(backend.routing_handoff_take(&key).unwrap().is_none());
                }
            }
        }
    });
}
