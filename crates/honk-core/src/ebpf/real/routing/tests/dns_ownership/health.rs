use super::*;

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn tcp_health_applies_to_fresh_admission_not_cached_packets_while_udp_stays_gated() {
    isolated(|| {
        let (mut backend, _, _listeners) = publish(&[rule(
            "proxy",
            RoutingCondition {
                port: vec!["53".into(), "443".into()],
                ..Default::default()
            },
            "proxy",
            USER_MARK,
            true,
        )]);
        for (src, dst) in [
            (
                "192.0.2.84".parse().unwrap(),
                "198.51.100.84".parse().unwrap(),
            ),
            (
                "2001:db8:1::84".parse().unwrap(),
                "2001:db8:2::84".parse().unwrap(),
            ),
        ] {
            for key in 2 * 6..3 * 6 {
                set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", key, 0u64);
            }
            let dns_key = tuple(src, dst, 45900, 53, IPPROTO_TCP);
            let dns_syn = packet(src, dst, IPPROTO_TCP, dns_key.src_port, 53, 5, 0x02);
            assert_eq!(
                run(&backend, "wan_egress_l2", &dns_syn, SkbInput::default()).verdict,
                TC_ACT_REDIRECT,
                "{src} TCP53 was dropped by health rather than sent to userspace"
            );
            let entry = handoff(&backend, &dns_key);
            assert_eq!(entry.result.outbound, 2);
            assert_eq!(entry.result.must, 1);

            for (index, side) in ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate() {
                for key in 2 * 6..3 * 6 {
                    set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", key, 1u64);
                }
                let port = 46000 + index as u16 * 10;
                let key = tuple(src, dst, port, 443, IPPROTO_TCP);
                let syn = packet(src, dst, IPPROTO_TCP, port, 443, 5, 0x02);
                let udp = packet(src, dst, IPPROTO_UDP, port, 443, 5, 0);
                for bytes in [&syn, &udp] {
                    assert_eq!(
                        run(&backend, side, bytes, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT
                    );
                }
                let owner = handoff(&backend, &key).incarnation;
                for key in 2 * 6..3 * 6 {
                    set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", key, 0u64);
                }
                let ack = packet(src, dst, IPPROTO_TCP, port, 443, 5, 0x10);
                for bytes in [&ack, &syn] {
                    assert_eq!(
                        run(&backend, side, bytes, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT,
                        "{side} {src} dropped an admitted TCP packet"
                    );
                    assert_eq!(handoff(&backend, &key).incarnation, owner);
                }
                assert_eq!(
                    run(&backend, side, &udp, SkbInput::default()).verdict,
                    TC_ACT_SHOT
                );
                let fresh_syn = packet(src, dst, IPPROTO_TCP, port + 1, 443, 5, 0x02);
                let fresh_udp = packet(src, dst, IPPROTO_UDP, port + 1, 443, 5, 0);
                for bytes in [&fresh_syn, &fresh_udp, &fresh_syn, &fresh_udp] {
                    assert_eq!(
                        run(&backend, side, bytes, SkbInput::default()).verdict,
                        TC_ACT_SHOT,
                        "{side} {src} admitted a fresh dead-outbound flow"
                    );
                }
                let fresh = tuple(src, dst, port + 1, 443, IPPROTO_TCP);
                assert!(backend.routing_handoff_lookup(&fresh).unwrap().is_none());
            }
        }
    });
}
