use super::*;
use aya::maps::PerCpuArray;

const REFRESH_NS: u64 = 1_000_000_000;

fn peers() -> [(IpAddr, IpAddr, IpAddr); 2] {
    [
        (
            "192.0.2.81".parse().unwrap(),
            "198.51.100.81".parse().unwrap(),
            "198.51.100.82".parse().unwrap(),
        ),
        (
            "2001:db8:1::81".parse().unwrap(),
            "2001:db8:2::81".parse().unwrap(),
            "2001:db8:2::82".parse().unwrap(),
        ),
    ]
}

fn now_ns() -> u64 {
    let mut time: libc::timespec = unsafe { mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) },
        0
    );
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

fn client_key(key: &TuplesKey) -> RedirectTuple {
    let mut key = RedirectTuple::from_tuples(key);
    key.dst_ip = In6Addr::zero();
    key.dst_port = 0;
    key
}

fn client_entry(backend: &RealEbpfBackend, key: &TuplesKey) -> Option<RedirectEntry> {
    HashMap::<_, RedirectTuple, RedirectEntry>::try_from(
        backend.bpf().unwrap().map("CLIENT_REPLY_TRACK").unwrap(),
    )
    .unwrap()
    .get(&client_key(key), 0)
    .ok()
}

fn evict_client(backend: &mut RealEbpfBackend, key: &TuplesKey) {
    HashMap::<_, RedirectTuple, RedirectEntry>::try_from(
        backend
            .bpf_mut()
            .unwrap()
            .map_mut("CLIENT_REPLY_TRACK")
            .unwrap(),
    )
    .unwrap()
    .remove(&client_key(key))
    .unwrap();
}

fn rx_packets(backend: &RealEbpfBackend, outbound: u32) -> u64 {
    PerCpuArray::<_, OutboundStatsCounters>::try_from(
        backend.bpf().unwrap().map("OUTBOUND_STATS").unwrap(),
    )
    .unwrap()
    .get(&outbound, 0)
    .unwrap()
    .iter()
    .map(|counter| counter.rx_packets)
    .sum()
}

fn fixture() -> (RealEbpfBackend, RoutingPushPlan, TproxyListeners) {
    let (mut backend, plan, listeners) = publish(&[rule(
        "refresh-a",
        RoutingCondition {
            port: vec!["1-65535".into()],
            ..Default::default()
        },
        "proxy",
        USER_MARK,
        true,
    )]);
    for name in ["lan_ingress_l2", "wan_egress_l2", "dae0_ingress"] {
        load_classifier(&mut backend, name);
    }
    (backend, plan, listeners)
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn client_framing_refills_after_outbound_and_exact_reply_refresh() {
    isolated(|| {
        let [v4, v6] = peers();
        for ((client, target, foreign), source_port, reverse) in [
            (v4, 40000, false),
            (v4, 40000, true),
            (v4, 53, false),
            (v4, 53, true),
            (v6, 40000, true),
        ] {
            let (mut backend, _, _listeners) = fixture();
            let key = tuple(client, target, source_port, 443, IPPROTO_UDP);
            let outbound = packet(client, target, IPPROTO_UDP, source_port, 443, 5, 0);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &outbound, SkbInput::default()).verdict,
                TC_ACT_REDIRECT
            );
            assert!(client_entry(&backend, &key).is_some());
            evict_client(&mut backend, &key);
            let redirect_key = RedirectTuple::from_tuples(&key);
            let mut exact = backend
                .redirect_track_lookup(&redirect_key)
                .unwrap()
                .unwrap();
            exact.last_seen_ns = now_ns().checked_sub(REFRESH_NS + 1).unwrap();
            backend.redirect_track_store(&redirect_key, &exact).unwrap();
            let reply = packet(target, client, IPPROTO_UDP, 443, source_port, 0, 0);
            let (name, bytes) = if reverse {
                ("dae0_ingress", &reply)
            } else {
                ("lan_ingress_l2", &outbound)
            };
            assert_eq!(
                run(&backend, name, bytes, SkbInput::default()).verdict,
                TC_ACT_REDIRECT
            );
            let restored = client_entry(&backend, &key)
                .expect("active exact flow did not restore evicted client framing");
            let current = backend
                .redirect_track_lookup(&redirect_key)
                .unwrap()
                .unwrap();
            assert!(current.last_seen_ns > exact.last_seen_ns);
            assert_eq!(
                (restored.ifindex, restored.smac, restored.dmac),
                (current.ifindex, current.smac, current.dmac)
            );
            assert_eq!(
                (
                    restored.decision_token,
                    restored.incarnation,
                    restored.from_wan
                ),
                (0, 0, 0)
            );
            let received_before = rx_packets(&backend, 2);
            let foreign_packet = packet(foreign, client, IPPROTO_UDP, 3478, source_port, 0, 0);
            let delivered = run(
                &backend,
                "dae0_ingress",
                &foreign_packet,
                SkbInput::default(),
            );
            assert_eq!(delivered.verdict, TC_ACT_REDIRECT);
            assert_eq!(&delivered.data[..6], &current.smac);
            assert_eq!(
                rx_packets(&backend, 2),
                received_before,
                "foreign reply acquired outbound attribution"
            );
            let foreign_key = tuple(client, foreign, source_port, 3478, IPPROTO_UDP);
            assert!(
                backend
                    .redirect_track_lookup(&RedirectTuple::from_tuples(&foreign_key))
                    .unwrap()
                    .is_none()
            );
            assert!(backend.conn_state_lookup(&foreign_key).unwrap().is_none());
        }
    });
    client_framing_refresh_excludes_dns_destinations_and_wan_records();
}

fn client_framing_refresh_excludes_dns_destinations_and_wan_records() {
    isolated(|| {
        for (client, target, _) in peers() {
            for (name, destination_port) in [("lan_ingress_l2", 53), ("wan_egress_l2", 443)] {
                let (mut backend, _, _listeners) = fixture();
                let key = tuple(client, target, 40001, destination_port, IPPROTO_UDP);
                let outbound = packet(client, target, IPPROTO_UDP, 40001, destination_port, 5, 0);
                assert_eq!(
                    run(&backend, name, &outbound, SkbInput::default()).verdict,
                    TC_ACT_REDIRECT
                );
                assert!(client_entry(&backend, &key).is_none());
                let redirect_key = RedirectTuple::from_tuples(&key);
                let mut exact = backend
                    .redirect_track_lookup(&redirect_key)
                    .unwrap()
                    .unwrap();
                exact.last_seen_ns = now_ns().checked_sub(REFRESH_NS + 1).unwrap();
                backend.redirect_track_store(&redirect_key, &exact).unwrap();
                let reply = packet(target, client, IPPROTO_UDP, destination_port, 40001, 0, 0);
                assert_eq!(
                    run(&backend, "dae0_ingress", &reply, SkbInput::default()).verdict,
                    TC_ACT_REDIRECT
                );
                assert!(
                    backend
                        .redirect_track_lookup(&redirect_key)
                        .unwrap()
                        .unwrap()
                        .last_seen_ns
                        > exact.last_seen_ns
                );
                assert!(
                    client_entry(&backend, &key).is_none(),
                    "non-LAN or DNS-query flow created client-only authority"
                );
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn stateless_udp_refreshes_complete_policy_without_changing_owned_lifetimes() {
    isolated(|| {
        for (client, target, _) in peers() {
            for (side, from_wan) in [("lan_ingress_l2", 0), ("wan_egress_l2", 1)] {
                let (mut backend, _, _listeners) = fixture();
                let key = tuple(client, target, 53, 443, IPPROTO_UDP);
                let redirect_key = RedirectTuple::from_tuples(&key);
                assert_eq!(
                    run(
                        &backend,
                        side,
                        &packet(client, target, IPPROTO_UDP, 53, 443, 5, 0),
                        SkbInput::default()
                    )
                    .verdict,
                    TC_ACT_REDIRECT
                );
                let old_handoff = handoff(&backend, &key);
                assert_eq!(
                    (
                        old_handoff.result.outbound,
                        old_handoff.result.mark,
                        old_handoff.result.must,
                        old_handoff.result.dscp
                    ),
                    (2, USER_MARK, 1, 5)
                );
                assert_eq!(
                    (old_handoff.incarnation, old_handoff.result.decision_token),
                    (0, 0)
                );
                let mut ids = outbound_ids();
                ids.insert("alternate".into(), 3);
                let mark = USER_MARK ^ 0x2000;
                let rules = [rule(
                    "refresh-b",
                    RoutingCondition {
                        port: vec!["1-65535".into()],
                        ..Default::default()
                    },
                    "alternate",
                    mark,
                    false,
                )];
                let plan = RoutingPushPlan::compile(
                    &Router::new(&rules, "direct").unwrap(),
                    &ids,
                    DialMode::Ip,
                )
                .unwrap();
                backend.publish_routing_plan(&plan, &[]).unwrap();
                for slot in 3 * 6..4 * 6 {
                    set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", slot, 1u64);
                }
                if from_wan == 0 {
                    evict_client(&mut backend, &key);
                }
                let mut exact = backend
                    .redirect_track_lookup(&redirect_key)
                    .unwrap()
                    .unwrap();
                exact.last_seen_ns = now_ns();
                backend.redirect_track_store(&redirect_key, &exact).unwrap();
                let fresh = packet(client, target, IPPROTO_UDP, 53, 443, 19, 0);
                assert_eq!(
                    run(&backend, side, &fresh, SkbInput::default()).verdict,
                    TC_ACT_REDIRECT
                );
                let current = handoff(&backend, &key);
                assert_eq!(
                    (
                        current.result.outbound,
                        current.result.mark,
                        current.result.must,
                        current.result.dscp
                    ),
                    (3, mark, 0, 19)
                );
                assert_ne!(current.routing_generation, old_handoff.routing_generation);
                assert_eq!((current.incarnation, current.result.decision_token), (0, 0));
                assert!(backend.conn_state_lookup(&key).unwrap().is_none());
                let updated = backend
                    .redirect_track_lookup(&redirect_key)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    (
                        updated.outbound,
                        updated.from_wan,
                        updated.incarnation,
                        updated.decision_token
                    ),
                    (3, from_wan, 0, 0)
                );
                if current.last_seen_ns.saturating_sub(exact.last_seen_ns) < REFRESH_NS {
                    assert_eq!(
                        updated.last_seen_ns, exact.last_seen_ns,
                        "fresh stateless payload postponed the cadence"
                    );
                    assert!(
                        client_entry(&backend, &key).is_none(),
                        "fresh stateless payload rewrote the client LRU before cadence"
                    );
                }
                let mut aged = updated;
                aged.last_seen_ns = now_ns().checked_sub(REFRESH_NS + 1).unwrap();
                backend.redirect_track_store(&redirect_key, &aged).unwrap();
                assert_eq!(
                    run(&backend, side, &fresh, SkbInput::default()).verdict,
                    TC_ACT_REDIRECT
                );
                assert!(
                    backend
                        .redirect_track_lookup(&redirect_key)
                        .unwrap()
                        .unwrap()
                        .last_seen_ns
                        > aged.last_seen_ns
                );
                assert_eq!(client_entry(&backend, &key).is_some(), from_wan == 0);
                let (incarnation, token) = (41, 0);
                let mut foreign_handoff = handoff(&backend, &key);
                foreign_handoff.incarnation = incarnation;
                foreign_handoff.result.decision_token = token;
                backend
                    .flow_insert("ROUTING_HANDOFF_MAP", &key, &foreign_handoff)
                    .unwrap();
                assert_eq!(
                    run(&backend, side, &fresh, SkbInput::default()).verdict,
                    TC_ACT_SHOT
                );
                let retained = handoff(&backend, &key);
                assert_eq!(
                    (retained.incarnation, retained.result.decision_token),
                    (incarnation, token)
                );
                backend
                    .flow_insert("ROUTING_HANDOFF_MAP", &key, &current)
                    .unwrap();
                let mut foreign_redirect = updated;
                foreign_redirect.incarnation = incarnation;
                foreign_redirect.decision_token = token;
                backend
                    .redirect_track_store(&redirect_key, &foreign_redirect)
                    .unwrap();
                assert_eq!(
                    run(&backend, side, &fresh, SkbInput::default()).verdict,
                    TC_ACT_SHOT
                );
                let retained = backend
                    .redirect_track_lookup(&redirect_key)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    (retained.incarnation, retained.decision_token),
                    (incarnation, token)
                );
            }
        }
    });
}
