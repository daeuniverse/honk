use super::*;

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn native_retained_tuple_elements_observe_same_key_fresh_syn_publication() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        load_classifier(&mut backend, "stable_flow_element_identity_test");
        for (src, dst) in PEERS {
            for (direction, side) in ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate() {
                let key = tuple(src, dst, 45600 + direction as u16, 443, IPPROTO_TCP);
                seed(&backend, side, &key, src, dst);
                let previous = backend
                    .conn_state_lookup(&key)
                    .unwrap()
                    .unwrap()
                    .incarnation;
                assert_ne!(previous, 0, "publication A has no actual incarnation");
                assert_eq!(handoff(&backend, &key).incarnation, previous);
                assert_eq!(
                    backend
                        .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                        .unwrap()
                        .unwrap()
                        .incarnation,
                    previous
                );
                set_array(&mut backend, "PREPARING_TEST_KEY", 0, key);
                let bytes = packet(src, dst, IPPROTO_TCP, key.src_port, key.dst_port, 19, 0x02);
                // The driver retains the actual A pointers, invokes production
                // fresh-SYN publication helpers using A's route/framing and B's
                // parsed TCP/DSCP, then native-lock copies through those pointers
                // and compares every payload byte to B. No pointer escapes and
                // no parallel scheduling or full classifier execution is assumed.
                let result = run(
                    &backend,
                    "stable_flow_element_identity_test",
                    &bytes,
                    SkbInput {
                        cb: [direction as u32, 0, 0, 0, 0],
                        ..Default::default()
                    },
                );
                assert_eq!(
                    result.verdict, TC_ACT_OK,
                    "native publication driver failed for {side} {src}"
                );
                assert_eq!(
                    result.cb[4], 0b111,
                    "production conn/handoff/redirect publication did not complete for {side} {src}"
                );
                let current = u64::from(result.cb[1]) | (u64::from(result.cb[2]) << 32);
                assert_ne!(current, 0, "publication B has no actual incarnation");
                assert_ne!(
                    current, previous,
                    "driver did not publish a fresh SYN incarnation"
                );
                assert_eq!(
                    result.cb[3], 0b111,
                    "retained conn/handoff/redirect element copied stale publication A after native lock for {side} {src}"
                );
                let conn = backend.conn_state_lookup(&key).unwrap().unwrap();
                let handoff = backend.routing_handoff_lookup(&key).unwrap().unwrap();
                let redirect = backend
                    .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    (conn.incarnation, handoff.incarnation, redirect.incarnation),
                    (current, current, current)
                );
                assert_eq!(
                    (
                        conn.decision_token,
                        handoff.result.decision_token,
                        redirect.decision_token
                    ),
                    (0, 0, 0)
                );
                assert_eq!(
                    unsafe { conn.meta.data.dscp },
                    19,
                    "conn metadata did not come from fresh SYN B"
                );
                assert_eq!(
                    handoff.result.dscp, 19,
                    "B metadata did not come from the actual fresh SYN"
                );
                assert_eq!(
                    backend
                        .hash_lookup::<_, u64>("TCP_PUBLISHING", &key)
                        .unwrap(),
                    None
                );
            }
        }
    });
}
