use super::*;

fn fixture() -> (RealEbpfBackend, RoutingPushPlan, TproxyListeners) {
    assert!(
        std::process::Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    let (mut backend, plan, listeners) = publish(&[rule(
        "local-service",
        RoutingCondition {
            port: vec!["1-65535".into()],
            ..Default::default()
        },
        "proxy",
        USER_MARK,
        true,
    )]);
    load_classifier(&mut backend, "lan_ingress_l2");
    load_classifier(&mut backend, "wan_egress_l2");
    (backend, plan, listeners)
}

#[test]
#[ignore = "requires root, Linux 5.15+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn local_udp_service_replies_bypass_routing_and_cache_the_socket_probe() {
    isolated(|| {
        let (mut backend, _, _listeners) = fixture();
        for (client, local) in [
            ("192.0.2.91".parse().unwrap(), "127.0.0.1".parse().unwrap()),
            ("2001:db8:1::91".parse().unwrap(), "::1".parse().unwrap()),
        ] {
            let service = UdpSocket::bind(SocketAddr::new(local, 0)).unwrap();
            let port = service.local_addr().unwrap().port();
            let request = packet(client, local, IPPROTO_UDP, 44000, port, 0, 0);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &request, SkbInput::default()).verdict,
                TC_ACT_OK
            );
            let reply_key = tuple(local, client, port, 44000, IPPROTO_UDP);
            let state = backend
                .conn_state_lookup(&reply_key)
                .unwrap()
                .expect("local socket probe must learn the reply's wire tuple");
            assert_eq!(
                (
                    state.is_wan_ingress_direction,
                    state.decision_token,
                    unsafe { state.meta.raw }
                ),
                (1, 0, 0)
            );
            let reply = packet(local, client, IPPROTO_UDP, port, 44000, 0, 0);
            assert_eq!(
                run(&backend, "wan_egress_l2", &reply, SkbInput::default()).verdict,
                TC_ACT_UNSPEC,
                "single-arm local reply must not be redirected"
            );
            for (pressure, client_port) in [(true, 44001), (false, 53)] {
                backend.set_admission_pressure(pressure).unwrap();
                let request = packet(client, local, IPPROTO_UDP, client_port, port, 0, 0);
                assert_eq!(
                    run(&backend, "lan_ingress_l2", &request, SkbInput::default()).verdict,
                    TC_ACT_OK
                );
                let key = tuple(local, client, port, client_port, IPPROTO_UDP);
                assert!(backend.conn_state_lookup(&key).unwrap().is_none());
                if pressure {
                    let reply = packet(local, client, IPPROTO_UDP, port, client_port, 0, 0);
                    assert_eq!(
                        run(&backend, "wan_egress_l2", &reply, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT,
                        "pressure intentionally leaves local service replies subject to routing"
                    );
                }
            }
            // A cached request must not depend on a fresh socket/FIB probe.
            drop(service);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &request, SkbInput::default()).verdict,
                TC_ACT_OK
            );
        }
    });
}
