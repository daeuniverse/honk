use super::*;
use crate::ebpf::{
    RetireCounts, RetireKind, RetireOutcome, RetireRequest, UdpDecisionCommitResult, retire_fixture,
};
use aya::maps::RingBuf;
use honk_ebpf_common::conn::{FlowIncarnationSequence, RetirementFence, UDP_CONN_STATE_TIMEOUT_NS};
use honk_ebpf_common::event::{DaeEvent, DaeEventType};

mod expiry_hints;
mod publication;
mod reverse_syn;
mod stable_values;
mod udp_keepalive;

const LAST_INCARNATION: u64 = 0x00ff_ffff_ffff_ffff;
const PEERS: [(IpAddr, IpAddr); 2] = [
    (
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 81)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 81)),
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 81)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 81)),
    ),
];

fn proxy_fixture() -> (RealEbpfBackend, RoutingPushPlan, TproxyListeners) {
    publish(&[rule(
        "retirement",
        RoutingCondition {
            port: vec!["443".into()],
            ..Default::default()
        },
        "proxy",
        USER_MARK,
        true,
    )])
}

fn now_ns() -> u64 {
    let mut time: libc::timespec = unsafe { mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) },
        0
    );
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

// Debug projections include every value field, not repr(C) padding bytes.
fn owned_values(backend: &RealEbpfBackend, key: &TuplesKey) -> String {
    format!(
        "{:?}",
        (
            backend.conn_state_lookup(key).unwrap(),
            backend.routing_handoff_lookup(key).unwrap(),
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(key))
                .unwrap(),
        )
    )
}

fn age_auxiliaries(backend: &mut RealEbpfBackend, key: &TuplesKey, last_seen_ns: u64) {
    let mut entry = handoff(backend, key);
    entry.last_seen_ns = last_seen_ns;
    backend
        .flow_insert("ROUTING_HANDOFF_MAP", key, &entry)
        .unwrap();
    let track_key = RedirectTuple::from_tuples(key);
    let mut track = backend.redirect_track_lookup(&track_key).unwrap().unwrap();
    track.last_seen_ns = last_seen_ns;
    backend.redirect_track_store(&track_key, &track).unwrap();
}

fn seed(backend: &RealEbpfBackend, side: &str, key: &TuplesKey, src: IpAddr, dst: IpAddr) {
    let bytes = packet(src, dst, key.l4proto, key.src_port, key.dst_port, 5, 0x02);
    assert_eq!(
        run(backend, side, &bytes, SkbInput::default()).verdict,
        TC_ACT_REDIRECT
    );
    assert_ne!(handoff(backend, key).incarnation, 0);
}

fn fence(backend: &mut RealEbpfBackend, key: &TuplesKey) {
    set_array(backend, "RETIRE_ACTIVE", 0, 1u32);
    backend
        .hash_insert_noexist(
            "RETIRE_FENCE",
            key,
            &RetirementFence {
                owner: 901,
                decision_token: 0,
                padding: 0,
            },
        )
        .unwrap();
}

fn unfence(backend: &mut RealEbpfBackend, key: &TuplesKey) {
    backend
        .hash_remove::<_, RetirementFence>("RETIRE_FENCE", key)
        .unwrap();
    set_array(backend, "RETIRE_ACTIVE", 0, 0u32);
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn retirement_fence_refuses_forward_reverse_and_reply_writers_without_mutation() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        for name in ["lan_egress_l2", "wan_ingress_l2", "dae0_ingress"] {
            load_classifier(&mut backend, name);
        }
        for (src, dst) in PEERS {
            for protocol in [IPPROTO_TCP, IPPROTO_UDP] {
                for (index, (side, reverse, expected)) in [
                    ("lan_ingress_l2", false, TC_ACT_REDIRECT),
                    ("wan_egress_l2", false, TC_ACT_REDIRECT),
                    ("lan_egress_l2", true, TC_ACT_UNSPEC),
                    ("wan_ingress_l2", true, TC_ACT_UNSPEC),
                    ("dae0_ingress", true, TC_ACT_REDIRECT),
                ]
                .into_iter()
                .enumerate()
                {
                    let key = tuple(src, dst, 45000 + index as u16, 443, protocol);
                    let publisher = if side == "wan_egress_l2" {
                        side
                    } else {
                        "lan_ingress_l2"
                    };
                    seed(&backend, publisher, &key, src, dst);
                    let old = now_ns().saturating_sub(2_000_000_000);
                    let mut state = backend.conn_state_lookup(&key).unwrap().unwrap();
                    state.last_seen_ns = old;
                    backend.udp_conn_state_store(&key, &state).unwrap();
                    age_auxiliaries(&mut backend, &key, old);
                    let before = owned_values(&backend, &key);
                    fence(&mut backend, &key);
                    let (from, to, sport, dport) = if reverse {
                        (dst, src, key.dst_port, key.src_port)
                    } else {
                        (src, dst, key.src_port, key.dst_port)
                    };
                    // Both fresh-SYN replacement and cached refresh must refuse.
                    for flags in if protocol == IPPROTO_TCP {
                        &[0x02, 0x10][..]
                    } else {
                        &[0][..]
                    } {
                        let bytes = packet(from, to, protocol, sport, dport, 19, *flags);
                        assert_eq!(
                            run(&backend, side, &bytes, SkbInput::default()).verdict,
                            TC_ACT_SHOT,
                            "{side} {protocol} {src} flags={flags}"
                        );
                        assert_eq!(
                            owned_values(&backend, &key),
                            before,
                            "{side} changed a fenced owner"
                        );
                    }
                    assert_eq!(
                        backend
                            .hash_lookup::<_, u64>("TCP_PUBLISHING", &key)
                            .unwrap(),
                        None
                    );
                    unfence(&mut backend, &key);
                    let bytes = packet(from, to, protocol, sport, dport, 19, 0x10);
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        expected,
                        "{side} did not resume after fence release"
                    );
                }
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn retirement_fence_prevents_missing_tuple_publication_and_reply_fallback() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        for name in ["lan_egress_l2", "wan_ingress_l2", "dae0_ingress"] {
            load_classifier(&mut backend, name);
        }
        let (src, dst) = PEERS[0];
        for protocol in [IPPROTO_TCP, IPPROTO_UDP] {
            for (index, (side, reverse)) in [
                ("lan_ingress_l2", false),
                ("wan_egress_l2", false),
                ("lan_egress_l2", true),
                ("wan_ingress_l2", true),
                ("dae0_ingress", true),
            ]
            .into_iter()
            .enumerate()
            {
                let key = tuple(src, dst, 45100 + index as u16, 443, protocol);
                fence(&mut backend, &key);
                let before = owned_values(&backend, &key);
                let bytes = if reverse {
                    packet(dst, src, protocol, 443, key.src_port, 5, 0x02)
                } else {
                    packet(src, dst, protocol, key.src_port, 443, 5, 0x02)
                };
                assert_eq!(
                    run(&backend, side, &bytes, SkbInput::default()).verdict,
                    TC_ACT_SHOT,
                    "{side} {protocol} {src}"
                );
                assert_eq!(
                    owned_values(&backend, &key),
                    before,
                    "{side} published behind retirement"
                );
                unfence(&mut backend, &key);
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn forward_syn_publisher_refuses_busy_and_releases_for_reuse_while_reverse_syn_is_ignored() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        for name in ["lan_egress_l2", "wan_ingress_l2"] {
            load_classifier(&mut backend, name);
        }
        let (src, dst) = PEERS[0];
        for (index, (side, reverse, expected)) in [
            ("lan_ingress_l2", false, TC_ACT_REDIRECT),
            ("wan_egress_l2", false, TC_ACT_REDIRECT),
            ("lan_egress_l2", true, TC_ACT_UNSPEC),
            ("wan_ingress_l2", true, TC_ACT_UNSPEC),
        ]
        .into_iter()
        .enumerate()
        {
            let key = tuple(src, dst, 45200 + index as u16, 443, IPPROTO_TCP);
            seed(&backend, "lan_ingress_l2", &key, src, dst);
            let before = owned_values(&backend, &key);
            backend
                .hash_insert_noexist("TCP_PUBLISHING", &key, &777u64)
                .unwrap();
            let syn = if reverse {
                packet(dst, src, IPPROTO_TCP, 443, key.src_port, 19, 0x02)
            } else {
                packet(src, dst, IPPROTO_TCP, key.src_port, 443, 19, 0x02)
            };
            assert_eq!(
                run(&backend, side, &syn, SkbInput::default()).verdict,
                if reverse { TC_ACT_UNSPEC } else { TC_ACT_SHOT },
                "{side} {src}"
            );
            assert_eq!(owned_values(&backend, &key), before);
            assert_eq!(
                backend
                    .hash_lookup::<_, u64>("TCP_PUBLISHING", &key)
                    .unwrap(),
                Some(777)
            );
            backend
                .hash_remove::<_, u64>("TCP_PUBLISHING", &key)
                .unwrap();
            let mut previous = backend
                .conn_state_lookup(&key)
                .unwrap()
                .unwrap()
                .incarnation;
            for isn in 1..=2 {
                assert_eq!(
                    run(
                        &backend,
                        side,
                        &with_isn(syn.clone(), isn),
                        SkbInput::default()
                    )
                    .verdict,
                    expected,
                    "{side} remained busy"
                );
                let current = backend
                    .conn_state_lookup(&key)
                    .unwrap()
                    .unwrap()
                    .incarnation;
                if reverse {
                    assert_eq!(current, previous, "{side} reverse SYN must not publish");
                } else {
                    assert_ne!(current, previous);
                    assert_ne!(current, 0);
                }
                assert_eq!(
                    backend
                        .hash_lookup::<_, u64>("TCP_PUBLISHING", &key)
                        .unwrap(),
                    None
                );
                previous = current;
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn final_56_bit_incarnation_survives_tcp_carrier_and_exhaustion_stays_closed() {
    isolated(|| {
        let (src, dst) = PEERS[0];
        for side in ["lan_ingress_l2", "wan_egress_l2"] {
            let (mut backend, _, _listeners) = proxy_fixture();
            load_classifier(&mut backend, "dae0peer_ingress");
            let live_udp = tuple(src, dst, 45300, 443, IPPROTO_UDP);
            seed(&backend, side, &live_udp, src, dst);
            let live_owner = handoff(&backend, &live_udp).incarnation;
            set_array(
                &mut backend,
                "FLOW_INCARNATION_SEQUENCE",
                0,
                FlowIncarnationSequence {
                    next: LAST_INCARNATION - 1,
                    ..Default::default()
                },
            );
            let key = tuple(src, dst, 45301, 443, IPPROTO_TCP);
            let syn = packet(src, dst, IPPROTO_TCP, key.src_port, 443, 5, 0x02);
            let published = run(&backend, side, &syn, SkbInput::default());
            assert_eq!(published.verdict, TC_ACT_REDIRECT);
            assert_eq!(handoff(&backend, &key).incarnation, LAST_INCARNATION);
            assert_eq!(
                backend
                    .conn_state_lookup(&key)
                    .unwrap()
                    .unwrap()
                    .incarnation,
                LAST_INCARNATION
            );
            assert_eq!(
                backend
                    .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                    .unwrap()
                    .unwrap()
                    .incarnation,
                LAST_INCARNATION
            );
            let peer = run(
                &backend,
                "dae0peer_ingress",
                &syn,
                SkbInput {
                    cb: published.cb,
                    mark: published.mark,
                    ..Default::default()
                },
            );
            assert_eq!(peer.verdict, TC_ACT_OK);
            assert_eq!(
                (u64::from(peer.priority) << 24) | u64::from(peer.mark & 0x00ff_ffff),
                LAST_INCARNATION
            );
            // An identical retry reuses the pending owner and needs no allocation.
            assert_eq!(
                run(&backend, side, &syn, SkbInput::default()).verdict,
                TC_ACT_REDIRECT
            );
            assert_eq!(handoff(&backend, &key).incarnation, LAST_INCARNATION);
            let before = owned_values(&backend, &key);
            for isn in 1..=2 {
                assert_eq!(
                    run(
                        &backend,
                        side,
                        &with_isn(syn.clone(), isn),
                        SkbInput::default()
                    )
                    .verdict,
                    TC_ACT_SHOT
                );
                assert_eq!(owned_values(&backend, &key), before);
                let fresh = tuple(src, dst, 45302, 443, IPPROTO_UDP);
                let bytes = packet(src, dst, IPPROTO_UDP, fresh.src_port, 443, 5, 0);
                assert_eq!(
                    run(&backend, side, &bytes, SkbInput::default()).verdict,
                    TC_ACT_SHOT
                );
                assert!(backend.conn_state_lookup(&fresh).unwrap().is_none());
                assert!(backend.routing_handoff_lookup(&fresh).unwrap().is_none());
                assert!(
                    backend
                        .redirect_track_lookup(&RedirectTuple::from_tuples(&fresh))
                        .unwrap()
                        .is_none()
                );
                let sequence = Array::<_, FlowIncarnationSequence>::try_from(
                    backend
                        .maps()
                        .unwrap()
                        .get("FLOW_INCARNATION_SEQUENCE")
                        .unwrap(),
                )
                .unwrap()
                .get(&0, 0)
                .unwrap();
                assert_eq!(sequence.next, LAST_INCARNATION);
                assert_eq!(
                    backend
                        .hash_lookup::<_, u64>("TCP_PUBLISHING", &key)
                        .unwrap(),
                    None
                );
            }
            let bytes = packet(src, dst, IPPROTO_UDP, live_udp.src_port, 443, 5, 0);
            assert_eq!(
                run(&backend, side, &bytes, SkbInput::default()).verdict,
                TC_ACT_REDIRECT
            );
            assert_eq!(handoff(&backend, &live_udp).incarnation, live_owner);
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn actual_expiry_hints_preserve_kernel_entries_and_batch_revalidates_ownership() {
    isolated(|| {
        // A fresh VM may have <120s uptime. Wait once for a genuine old
        // monotonic timestamp, rather than fabricating a future/wrapped age.
        let wait_ns = 121_000_000_000u64.saturating_sub(now_ns());
        if wait_ns != 0 {
            std::thread::sleep(Duration::from_nanos(wait_ns));
        }
        let (src, dst) = PEERS[0];
        for side in ["lan_ingress_l2", "wan_egress_l2"] {
            let (mut backend, _, _listeners) = proxy_fixture();
            let mut ring =
                RingBuf::try_from(backend.maps_mut().unwrap().remove("EVENT_RINGBUF").unwrap())
                    .unwrap();
            let mut keys = [TuplesKey::default(); 3];
            let mut owners = [0; 3];
            for index in 0..3 {
                let key = tuple(src, dst, 45400 + index as u16, 443, IPPROTO_UDP);
                seed(&backend, side, &key, src, dst);
                let mut state = backend.conn_state_lookup(&key).unwrap().unwrap();
                owners[index] = state.incarnation;
                state.last_seen_ns = 0;
                backend.udp_conn_state_store(&key, &state).unwrap();
                let before = owned_values(&backend, &key);
                let bytes = packet(src, dst, IPPROTO_UDP, key.src_port, 443, 19, 0);
                assert_eq!(
                    run(&backend, side, &bytes, SkbInput::default()).verdict,
                    TC_ACT_SHOT
                );
                assert_eq!(
                    owned_values(&backend, &key),
                    before,
                    "kernel deleted or refreshed expired owner"
                );
                let item = ring.next().expect("expired packet must emit a hint");
                assert_eq!(item.len(), mem::size_of::<DaeEvent>());
                let event: DaeEvent = unsafe { ptr::read_unaligned(item.as_ptr().cast()) };
                assert_eq!(event.type_, DaeEventType::FlowExpired as u32);
                assert_eq!(event.incarnation, state.incarnation);
                assert_eq!(event.l4proto, IPPROTO_UDP);
                assert_eq!(event.sip, unsafe { key.src_ip.u6_addr32 });
                assert_eq!(event.dip, unsafe { key.dst_ip.u6_addr32 });
                assert_eq!((event.sport, event.dport), (key.src_port, key.dst_port));
                assert!(event.timestamp > 120_000_000_000);
                keys[index] = key;
            }
            // Delay one hint across an actual new kernel admission.
            backend
                .hash_remove::<_, FlowMapValue<ConnState>>("CONN_STATE_MAP", &keys[1])
                .unwrap();
            backend
                .hash_remove::<_, FlowMapValue<RoutingHandoffEntry>>(
                    "ROUTING_HANDOFF_MAP",
                    &keys[1],
                )
                .unwrap();
            backend
                .hash_remove::<_, FlowMapValue<RedirectEntry>>(
                    "REDIRECT_TRACK",
                    &RedirectTuple::from_tuples(&keys[1]),
                )
                .unwrap();
            seed(&backend, side, &keys[1], src, dst);
            assert_ne!(handoff(&backend, &keys[1]).incarnation, owners[1]);
            // Delay another hint across refresh of the same incarnation.
            let mut refreshed = backend.conn_state_lookup(&keys[2]).unwrap().unwrap();
            refreshed.last_seen_ns = now_ns() - 2_000_000_000;
            backend.udp_conn_state_store(&keys[2], &refreshed).unwrap();
            let bytes = packet(src, dst, IPPROTO_UDP, keys[2].src_port, 443, 19, 0);
            assert_eq!(
                run(&backend, side, &bytes, SkbInput::default()).verdict,
                TC_ACT_REDIRECT
            );
            let refreshed_now = backend.conn_state_lookup(&keys[2]).unwrap().unwrap();
            assert_eq!(refreshed_now.incarnation, owners[2]);
            assert!(refreshed_now.last_seen_ns > refreshed.last_seen_ns);
            let new_owner = owned_values(&backend, &keys[1]);
            let fresh_state = owned_values(&backend, &keys[2]);
            let mut outcomes = [RetireOutcome::NotRun; 3];
            let counts = backend
                .retire_batch(
                    &[
                        RetireRequest {
                            key: keys[0],
                            kind: RetireKind::ExpiryHint {
                                incarnation: owners[0],
                                now_ns: now_ns(),
                            },
                        },
                        RetireRequest {
                            key: keys[1],
                            kind: RetireKind::ExpiryHint {
                                incarnation: owners[1],
                                now_ns: now_ns(),
                            },
                        },
                        RetireRequest {
                            key: keys[2],
                            kind: RetireKind::ExpiryHint {
                                incarnation: owners[2],
                                now_ns: now_ns(),
                            },
                        },
                    ],
                    &mut outcomes,
                )
                .unwrap();
            assert_eq!(
                counts,
                RetireCounts {
                    conn: 1,
                    redirect: 1,
                    handoff: 1,
                }
            );
            assert_eq!(
                outcomes,
                [
                    RetireOutcome::ConnRetired,
                    RetireOutcome::Done(UdpDecisionCommitResult::Superseded),
                    RetireOutcome::Done(UdpDecisionCommitResult::StateMismatch)
                ]
            );
            assert_eq!(owned_values(&backend, &keys[1]), new_owner);
            assert_eq!(owned_values(&backend, &keys[2]), fresh_state);
            assert!(backend.conn_state_lookup(&keys[0]).unwrap().is_none());
            assert!(backend.routing_handoff_lookup(&keys[0]).unwrap().is_none());
            assert!(
                backend
                    .redirect_track_lookup(&RedirectTuple::from_tuples(&keys[0]))
                    .unwrap()
                    .is_none()
            );
            seed(&backend, side, &keys[0], src, dst);
            assert_ne!(handoff(&backend, &keys[0]).incarnation, owners[0]);
        }
    });
}

fn controlled_claim(
    backend: &mut RealEbpfBackend,
    key: &TuplesKey,
    bytes: &[u8],
    mode: u32,
) -> (u64, Run) {
    set_array(backend, "PREPARING_TEST_KEY", 0, *key);
    load_classifier(backend, "preparing_claim_interleaving_test");
    let result = run(
        backend,
        "preparing_claim_interleaving_test",
        bytes,
        SkbInput {
            cb: [mode, 0, 0, 0, 0],
            ..Default::default()
        },
    );
    assert_eq!(result.verdict, TC_ACT_OK, "controlled claim mode {mode}");
    let incarnation = u64::from(result.cb[1]) | (u64::from(result.cb[2]) << 32);
    assert_ne!(incarnation, 0);
    if mode != 0 {
        // Controlled admitted completion followed by the real barrier, not a
        // claim that this invocation overlapped a parallel retirement reader.
        backend.grace_barrier().unwrap();
        assert_claim_fence(backend, key);
    }
    (incarnation, result)
}

fn assert_claim_fence(backend: &RealEbpfBackend, key: &TuplesKey) {
    assert_eq!(
        backend
            .hash_lookup::<_, RetirementFence>("RETIRE_FENCE", key)
            .unwrap(),
        Some(RetirementFence {
            owner: 901,
            decision_token: 0,
            padding: 0,
        })
    );
    assert_eq!(
        Array::<_, u32>::try_from(backend.maps().unwrap().get("RETIRE_ACTIVE").unwrap())
            .unwrap()
            .get(&0, 0)
            .unwrap(),
        1
    );
}

fn assert_fenced_claim_unchanged(backend: &RealEbpfBackend, key: &TuplesKey, bytes: &[u8]) {
    let before = owned_values(backend, key);
    assert_eq!(
        run(backend, "lan_ingress_l2", bytes, SkbInput::default()).verdict,
        TC_ACT_SHOT
    );
    assert_eq!(owned_values(backend, key), before);
    assert_claim_fence(backend, key);
    let refused = run(
        backend,
        "preparing_claim_interleaving_test",
        bytes,
        SkbInput::default(),
    );
    assert_eq!(refused.verdict, TC_ACT_SHOT);
    assert_eq!((refused.cb[1], refused.cb[2]), (0, 0));
    assert_eq!(owned_values(backend, key), before);
    assert_claim_fence(backend, key);
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn controlled_pre_fence_udp_claim_completes_terminally_then_retires_and_republishes() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        let (src, dst) = PEERS[0];
        let key = tuple(src, dst, 45500, 443, IPPROTO_UDP);
        let bytes = packet(src, dst, IPPROTO_UDP, key.src_port, 443, 5, 0);
        let (incarnation, result) = controlled_claim(&mut backend, &key, &bytes, 1);
        let published = backend.conn_state_lookup(&key).unwrap().unwrap();
        assert_eq!(published.incarnation, incarnation);
        assert_eq!(published.decision_token, 0);
        assert_eq!(result.cb[3], published.state as u32);
        assert_eq!(
            published.state,
            if result.cb[4] == 0 {
                UdpDecisionState::Aborted as u8
            } else {
                UdpDecisionState::Block as u8
            },
            "pre-fence completion left an orphan Preparing claim"
        );
        assert_fenced_claim_unchanged(&backend, &key, &bytes);
        unfence(&mut backend, &key);
        let before = owned_values(&backend, &key);
        assert_eq!(
            run(&backend, "lan_ingress_l2", &bytes, SkbInput::default()).verdict,
            TC_ACT_SHOT
        );
        assert_eq!(
            owned_values(&backend, &key),
            before,
            "terminal follower rewrote captured ownership"
        );
        // Aborted is eligible immediately. For a successful publication,
        // advance only the supplied expiry clock past its normal timeout.
        let expiry_clock = if published.state == UdpDecisionState::Aborted as u8 {
            now_ns()
        } else {
            published.last_seen_ns + UDP_CONN_STATE_TIMEOUT_NS + 1
        };
        let (counts, result) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiryHint {
                incarnation,
                now_ns: expiry_clock,
            },
        );
        assert_eq!(
            counts,
            RetireCounts {
                conn: 1,
                ..Default::default()
            }
        );
        assert_eq!(result, UdpDecisionCommitResult::Applied);
        assert!(backend.conn_state_lookup(&key).unwrap().is_none());
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_none()
        );
        seed(&backend, "lan_ingress_l2", &key, src, dst);
        let republished = backend.conn_state_lookup(&key).unwrap().unwrap();
        assert_ne!(republished.incarnation, incarnation);
        assert_ne!(republished.state, UdpDecisionState::Preparing as u8);
        assert_ne!(republished.state, UdpDecisionState::Aborted as u8);
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn controlled_udp_abort_retains_owned_metadata_until_fenced_retirement_then_republishes() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        let (src, dst) = PEERS[0];
        let key = tuple(src, dst, 45501, 443, IPPROTO_UDP);
        let bytes = packet(src, dst, IPPROTO_UDP, key.src_port, 443, 5, 0);
        let (incarnation, result) = controlled_claim(&mut backend, &key, &bytes, 2);
        assert_eq!(
            result.cb[3], 1,
            "abort must preserve both owned auxiliaries"
        );
        let aborted = backend.conn_state_lookup(&key).unwrap().unwrap();
        assert_eq!(aborted.incarnation, incarnation);
        assert_eq!(aborted.state, UdpDecisionState::Aborted as u8);
        assert_eq!(aborted.decision_token, 41);
        assert_eq!(handoff(&backend, &key).incarnation, incarnation);
        assert_eq!(handoff(&backend, &key).result.decision_token, 41);
        let track = backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .unwrap();
        assert_eq!((track.incarnation, track.decision_token), (incarnation, 41));
        assert_fenced_claim_unchanged(&backend, &key, &bytes);
        unfence(&mut backend, &key);
        let before = owned_values(&backend, &key);
        assert_eq!(
            run(&backend, "lan_ingress_l2", &bytes, SkbInput::default()).verdict,
            TC_ACT_SHOT
        );
        assert_eq!(
            owned_values(&backend, &key),
            before,
            "Aborted follower renewed the marker"
        );
        let (counts, result) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiryHint {
                incarnation,
                now_ns: now_ns(),
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
        assert!(backend.conn_state_lookup(&key).unwrap().is_none());
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_none()
        );
        seed(&backend, "lan_ingress_l2", &key, src, dst);
        let state = backend.conn_state_lookup(&key).unwrap().unwrap();
        assert_ne!(state.incarnation, incarnation);
        assert_ne!(state.state, UdpDecisionState::Preparing as u8);
        assert_ne!(state.state, UdpDecisionState::Aborted as u8);
        assert_eq!(handoff(&backend, &key).incarnation, state.incarnation);
        assert_eq!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .unwrap()
                .incarnation,
            state.incarnation
        );
        assert_eq!(
            run(&backend, "lan_ingress_l2", &bytes, SkbInput::default()).verdict,
            TC_ACT_REDIRECT
        );
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn controlled_udp_abort_preserves_foreign_auxiliaries_and_newer_owner() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        let (src, dst) = PEERS[0];
        for mode in 3..=5 {
            let key = tuple(src, dst, 45500 + mode as u16, 443, IPPROTO_UDP);
            let bytes = packet(src, dst, IPPROTO_UDP, key.src_port, 443, 5, 0);
            let (incarnation, result) = controlled_claim(&mut backend, &key, &bytes, mode);
            assert_eq!(result.cb[3], if mode == 5 { 0 } else { 1 });
            assert_eq!(result.cb[4], 0, "old claim published over a newer owner");
            let entry = handoff(&backend, &key);
            let token = if mode == 3 { 42 } else { 41 };
            let aux_incarnation = if mode == 3 {
                incarnation
            } else {
                assert!(entry.incarnation > incarnation);
                entry.incarnation
            };
            let expected_handoff = RoutingHandoffEntry {
                last_seen_ns: 77,
                incarnation: aux_incarnation,
                result: RoutingResult {
                    decision_token: token,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert_eq!(format!("{entry:?}"), format!("{expected_handoff:?}"));
            let track = backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .unwrap();
            let expected_track = RedirectEntry {
                last_seen_ns: 99,
                decision_token: token,
                incarnation: aux_incarnation,
                ..Default::default()
            };
            assert_eq!(format!("{track:?}"), format!("{expected_track:?}"));
            if mode == 5 {
                let newer = backend.conn_state_lookup(&key).unwrap().unwrap();
                let expected = ConnState {
                    state: UdpDecisionState::Preparing as u8,
                    incarnation: aux_incarnation,
                    last_seen_ns: newer.last_seen_ns,
                    ..Default::default()
                };
                assert_eq!(format!("{newer:?}"), format!("{expected:?}"));
            } else {
                let aborted = backend.conn_state_lookup(&key).unwrap().unwrap();
                assert_eq!(
                    (aborted.incarnation, aborted.decision_token, aborted.state),
                    (incarnation, 41, UdpDecisionState::Aborted as u8)
                );
            }
            assert_fenced_claim_unchanged(&backend, &key, &bytes);
            unfence(&mut backend, &key);
            let before = owned_values(&backend, &key);
            let (counts, result) = retire_fixture(
                &mut backend,
                key,
                RetireKind::ExpiryHint {
                    incarnation,
                    now_ns: now_ns(),
                },
            );
            assert_eq!(counts, RetireCounts::default());
            assert_eq!(
                result,
                if mode == 5 {
                    UdpDecisionCommitResult::Superseded
                } else {
                    UdpDecisionCommitResult::TokenMismatch
                }
            );
            assert_eq!(
                owned_values(&backend, &key),
                before,
                "retirement destroyed foreign authority"
            );
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn udp_preparing_and_aborted_followers_do_not_renew_claim_timestamp() {
    isolated(|| {
        // Keep the age strictly above lazy refresh and below UDP expiry, even
        // in a guest booted immediately before this exact test selection.
        let wait_ns = 3_000_000_000u64.saturating_sub(now_ns());
        if wait_ns != 0 {
            std::thread::sleep(Duration::from_nanos(wait_ns));
        }
        let (mut backend, _, _listeners) = proxy_fixture();
        let (src, dst) = PEERS[0];
        for (index, side) in ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate() {
            let key = tuple(src, dst, 45510 + index as u16, 443, IPPROTO_UDP);
            seed(&backend, side, &key, src, dst);
            let mut preparing = backend.conn_state_lookup(&key).unwrap().unwrap();
            let bytes = packet(src, dst, IPPROTO_UDP, key.src_port, 443, 5, 0);
            for state in [UdpDecisionState::Preparing, UdpDecisionState::Aborted] {
                preparing.state = state as u8;
                preparing.decision_token = if state == UdpDecisionState::Aborted {
                    41
                } else {
                    0
                };
                preparing.last_seen_ns = now_ns() - 2_000_000_000;
                backend.udp_conn_state_store(&key, &preparing).unwrap();
                assert_eq!(
                    run(&backend, side, &bytes, SkbInput::default()).verdict,
                    TC_ACT_SHOT,
                    "{side} {src} {state:?}"
                );
                let followed = backend.conn_state_lookup(&key).unwrap().unwrap();
                assert_eq!(
                    format!("{followed:?}"),
                    format!("{preparing:?}"),
                    "{side} follower renewed or rewrote the unpublished claim"
                );
            }
        }
    });
}
