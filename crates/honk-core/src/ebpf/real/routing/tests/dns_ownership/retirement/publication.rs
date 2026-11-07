use super::*;
use aya::maps::IterableMap;
use honk_ebpf_common::{
    FlowMapValue,
    conn::{ConnState, TCP_SYN_ORIGINAL_INTERCEPT},
};

fn filler(index: u32) -> TuplesKey {
    TuplesKey {
        src_port: index as u16,
        dst_port: (index >> 16) as u16,
        l4proto: IPPROTO_UDP,
        ..Default::default()
    }
}

fn capacity(backend: &RealEbpfBackend, handoff_map: bool) -> u32 {
    if handoff_map {
        backend
            .hash_map::<TuplesKey, FlowMapValue<RoutingHandoffEntry>>("ROUTING_HANDOFF_MAP")
            .unwrap()
            .map()
            .info()
            .unwrap()
            .max_entries()
    } else {
        backend
            .hash_map::<RedirectTuple, FlowMapValue<RedirectEntry>>("REDIRECT_TRACK")
            .unwrap()
            .map()
            .info()
            .unwrap()
            .max_entries()
    }
}

fn put_filler(backend: &mut RealEbpfBackend, handoff_map: bool, index: u32) {
    let key = filler(index);
    if handoff_map {
        backend
            .flow_insert("ROUTING_HANDOFF_MAP", &key, &RoutingHandoffEntry::default())
            .unwrap();
    } else {
        backend
            .flow_insert(
                "REDIRECT_TRACK",
                &RedirectTuple::from_tuples(&key),
                &RedirectEntry::default(),
            )
            .unwrap();
    }
}

fn take_filler(backend: &mut RealEbpfBackend, handoff_map: bool, index: u32) {
    let key = filler(index);
    if handoff_map {
        backend
            .hash_remove::<_, FlowMapValue<RoutingHandoffEntry>>("ROUTING_HANDOFF_MAP", &key)
            .unwrap();
    } else {
        backend
            .hash_remove::<_, FlowMapValue<RedirectEntry>>(
                "REDIRECT_TRACK",
                &RedirectTuple::from_tuples(&key),
            )
            .unwrap();
    }
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn failed_syn_publication_retries_but_committed_metadata_loss_refuses() {
    isolated(|| {
        let mut case = 0u16;
        for (handoff_map, name) in [(true, "ROUTING_HANDOFF_MAP"), (false, "REDIRECT_TRACK")] {
            let (mut backend, _, _listeners) = publish(&[rule(
                "unmarked-proxy",
                RoutingCondition {
                    port: vec!["443".into()],
                    ..Default::default()
                },
                "proxy",
                0,
                false,
            )]);
            // Reuse the full map across tuples; each retry borrows one slot
            // and restores its filler after removing the published metadata.
            for index in 0..capacity(&backend, handoff_map) {
                put_filler(&mut backend, handoff_map, index);
            }
            for (src, dst) in PEERS {
                for side in ["lan_ingress_l2", "wan_egress_l2"] {
                    if !handoff_map {
                        let udp = packet(src, dst, IPPROTO_UDP, 46200 + case, 443, 5, 0);
                        assert_eq!(
                            run(&backend, side, &udp, SkbInput::default()).verdict,
                            TC_ACT_SHOT,
                            "{side} let a proxy UDP datagram escape when redirect publication failed"
                        );
                    }
                    let key = tuple(src, dst, 46100 + case, 443, IPPROTO_TCP);
                    let bytes = packet(src, dst, IPPROTO_TCP, key.src_port, key.dst_port, 5, 0x02);
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        TC_ACT_SHOT,
                        "{side} delivered an incomplete SYN publication with full {name}"
                    );
                    let failed = backend.conn_state_lookup(&key).unwrap().unwrap();
                    assert_eq!(failed.tcp_syn_flags & TCP_SYN_ORIGINAL_INTERCEPT, 0);
                    take_filler(&mut backend, handoff_map, 0);
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT,
                        "{side} could not retry the unpublished SYN after {name} pressure cleared"
                    );
                    let committed: ConnState = backend.conn_state_lookup(&key).unwrap().unwrap();
                    assert_ne!(committed.incarnation, failed.incarnation);
                    assert_ne!(committed.tcp_syn_flags & TCP_SYN_ORIGINAL_INTERCEPT, 0);
                    assert_eq!(handoff(&backend, &key).incarnation, committed.incarnation);
                    assert_eq!(
                        backend
                            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                            .unwrap()
                            .unwrap()
                            .incarnation,
                        committed.incarnation
                    );
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT
                    );
                    let pending = backend.conn_state_lookup(&key).unwrap().unwrap();
                    assert_eq!(pending.incarnation, committed.incarnation);
                    backend
                        .hash_remove::<_, FlowMapValue<RoutingHandoffEntry>>(
                            "ROUTING_HANDOFF_MAP",
                            &key,
                        )
                        .unwrap();
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        TC_ACT_SHOT
                    );
                    assert_eq!(
                        backend
                            .conn_state_lookup(&key)
                            .unwrap()
                            .unwrap()
                            .incarnation,
                        committed.incarnation
                    );
                    assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
                    backend
                        .hash_remove::<_, FlowMapValue<RedirectEntry>>(
                            "REDIRECT_TRACK",
                            &RedirectTuple::from_tuples(&key),
                        )
                        .unwrap();
                    put_filler(&mut backend, handoff_map, 0);
                    case += 1;
                }
            }
        }
    });
}
