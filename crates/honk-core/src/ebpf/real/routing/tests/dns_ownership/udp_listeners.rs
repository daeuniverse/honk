use super::udp_group::{LISTENERS, UdpGroup, lookup_cookie};
use super::*;
use aya::programs::SkLookup;

const KEY_UDP4_BASE: u32 = 2;
const KEY_UDP6_BASE: u32 = 6;
const UDP_LISTENER_MARKER: u32 = 0x100;
const FLOWS: u16 = 4;

fn flow(ipv6: bool, index: u16, port: u16) -> (IpAddr, IpAddr, u16) {
    if ipv6 {
        (
            format!("2001:db9:83::{:x}", index + 2).parse().unwrap(),
            "2001:db8:83::7".parse().unwrap(),
            port,
        )
    } else {
        (
            IpAddr::V4(Ipv4Addr::new(
                10,
                83,
                (index / 200) as u8,
                (index % 200) as u8 + 2,
            )),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            port,
        )
    }
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT"]
fn udp_flow_selects_one_listener_across_assign_and_lookup() {
    isolated(|| {
        let (mut backend, _, listeners) = publish(&[rule(
            "udp-listeners",
            RoutingCondition {
                port: vec!["1-65535".into()],
                ..Default::default()
            },
            "proxy",
            USER_MARK,
            true,
        )]);
        for name in ["lan_ingress_l2", "wan_egress_l2", "dae0peer_ingress"] {
            load_classifier(&mut backend, name);
        }
        let lookup: &mut SkLookup = backend
            .bpf_mut()
            .unwrap()
            .program_mut("tproxy_sk_lookup")
            .unwrap()
            .try_into()
            .unwrap();
        lookup.load().unwrap();
        let group = UdpGroup::publish(&mut backend, &listeners);

        for side in ["lan_ingress_l2", "wan_egress_l2"] {
            for ipv6 in [false, true] {
                let base = if ipv6 { KEY_UDP6_BASE } else { KEY_UDP4_BASE };
                let mut used = [false; LISTENERS];
                for index in 0..FLOWS {
                    let (source, destination, source_port) =
                        flow(ipv6, index, 30000 + index * 17 + ipv6 as u16);
                    let bytes = packet(source, destination, IPPROTO_UDP, source_port, 443, 5, 0);
                    let redirect = run(&backend, side, &bytes, SkbInput::default());
                    assert_eq!(redirect.verdict, TC_ACT_REDIRECT, "{side} {source}");
                    let marker = redirect.cb[4];
                    assert_eq!(
                        marker & !0xff,
                        UDP_LISTENER_MARKER,
                        "{side} {source}:{source_port} carries no listener marker"
                    );
                    let listener = (marker & 0xff) as usize;
                    assert!(listener < LISTENERS, "{side} marker {marker:#x}");
                    used[listener] = true;

                    let again = run(&backend, side, &bytes, SkbInput::default());
                    assert_eq!(again.cb[4], marker, "{side} marker is flow-stable");

                    let peer = run(
                        &backend,
                        "dae0peer_ingress",
                        &bytes,
                        SkbInput {
                            mark: redirect.mark,
                            cb: redirect.cb,
                            ..Default::default()
                        },
                    );
                    assert_eq!(peer.verdict, TC_ACT_OK);
                    assert_eq!(
                        peer.cb[4],
                        base + listener as u32,
                        "{side} peer assigns the marked listener"
                    );

                    let selected = lookup_cookie(
                        &backend,
                        SocketAddr::new(source, source_port),
                        SocketAddr::new(destination, 443),
                    );
                    assert_eq!(
                        selected,
                        group.cookie(ipv6, listener),
                        "{side} {source}:{source_port}: sk_lookup and the marker pick different listeners"
                    );
                }
                assert!(
                    used.iter().filter(|used| **used).count() >= 2,
                    "{side} v6={ipv6} flows did not spread over the listeners"
                );
            }
        }

        for ipv6 in [false, true] {
            let (source, destination, port) = flow(ipv6, 1, 31000);
            let bytes = packet(source, destination, IPPROTO_UDP, port, 443, 5, 0);
            let redirect = run(&backend, "lan_ingress_l2", &bytes, SkbInput::default());
            assert_eq!(redirect.verdict, TC_ACT_REDIRECT);
            for stray in [0, UDP_LISTENER_MARKER + LISTENERS as u32] {
                let mut cb = redirect.cb;
                cb[4] = stray;
                let peer = run(
                    &backend,
                    "dae0peer_ingress",
                    &bytes,
                    SkbInput {
                        mark: redirect.mark,
                        cb,
                        ..Default::default()
                    },
                );
                assert_eq!(peer.verdict, TC_ACT_OK);
                assert_eq!(peer.cb[4], 0, "cb[4]={stray:#x} must not assign a listener");
            }
        }
    });
}
