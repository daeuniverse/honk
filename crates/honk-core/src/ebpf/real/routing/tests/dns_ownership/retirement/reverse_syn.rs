use super::*;

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn spoofed_reverse_syn_cannot_overwrite_a_proxied_tcp_flow() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        for name in ["lan_egress_l2", "wan_ingress_l2"] {
            load_classifier(&mut backend, name);
        }
        for (index, (src, dst)) in PEERS.into_iter().enumerate() {
            let key = tuple(src, dst, 45700 + index as u16, 443, IPPROTO_TCP);
            seed(&backend, "lan_ingress_l2", &key, src, dst);
            let published = backend.conn_state_lookup(&key).unwrap().unwrap();
            assert_ne!(unsafe { published.meta.raw }, 0);
            let before = owned_values(&backend, &key);
            let reverse = tuple(dst, src, key.dst_port, key.src_port, IPPROTO_TCP);
            let spoof = packet(dst, src, IPPROTO_TCP, 443, key.src_port, 19, 0x02);
            for side in ["wan_ingress_l2", "lan_egress_l2"] {
                assert_eq!(
                    run(&backend, side, &spoof, SkbInput::default()).verdict,
                    TC_ACT_UNSPEC,
                    "{side} {src}"
                );
                let current = backend.conn_state_lookup(&key).unwrap().unwrap();
                assert_eq!(current.incarnation, published.incarnation, "{side} {src}");
                assert_eq!(
                    unsafe { current.meta.raw },
                    unsafe { published.meta.raw },
                    "{side} {src}"
                );
                assert_eq!(owned_values(&backend, &key), before, "{side} {src}");
                assert!(
                    backend.conn_state_lookup(&reverse).unwrap().is_none(),
                    "{side} {src} created a reverse entry"
                );
            }
            let ack = packet(src, dst, IPPROTO_TCP, key.src_port, 443, 5, 0x10);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &ack, SkbInput::default()).verdict,
                TC_ACT_REDIRECT,
                "{src} ACK escaped the proxy"
            );
            let absent = tuple(src, dst, key.src_port + 5, 443, IPPROTO_TCP);
            let reverse_absent = tuple(dst, src, 443, absent.src_port, IPPROTO_TCP);
            let unsolicited = packet(dst, src, IPPROTO_TCP, 443, absent.src_port, 19, 0x02);
            for side in ["wan_ingress_l2", "lan_egress_l2"] {
                assert_eq!(
                    run(&backend, side, &unsolicited, SkbInput::default()).verdict,
                    TC_ACT_UNSPEC
                );
                assert!(
                    backend.conn_state_lookup(&absent).unwrap().is_none(),
                    "{side} created canonical state for an unsolicited SYN"
                );
                assert!(
                    backend
                        .conn_state_lookup(&reverse_absent)
                        .unwrap()
                        .is_none(),
                    "{side} created reverse state for an unsolicited SYN"
                );
            }
        }
    });
}
