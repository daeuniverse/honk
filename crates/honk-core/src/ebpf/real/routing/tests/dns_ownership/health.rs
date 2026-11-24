use super::*;

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
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

#[cfg(feature = "native-api")]
#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn accepted_prefix_failure_updates_real_tc_admission() {
    let kernel = std::env::var("HONK_CI_EXPECTED_KERNEL").unwrap_or_default();
    assert!(
        std::env::var_os("HONK_CI_VM_LANE").is_some()
            && !kernel.is_empty()
            && std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap()
                .trim()
                == kernel,
        "requires the disposable kernel VM gate"
    );
    isolated(|| {
        let mut netlink = crate::netlink::NlSock::new().unwrap();
        let (lo, _) = netlink.get_link("lo").unwrap();
        netlink.set_link_up(lo, true).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(check_routed_tcp_health());
    });
}

#[cfg(feature = "native-api")]
async fn check_routed_tcp_health() {
    use crate::control::ControlPlane;
    use crate::test_support::socks5_relay;
    use honk_config::Config;
    use honk_config::node::{Group, GroupPolicy, Node, OutboundConfig};
    use honk_config::types::NodeProtocol;
    use honk_outbound::alive::{IpVersion, ProbeDomain};
    use honk_outbound::group::{ScoreSelectionContext, SelectionNetwork, Target};
    use honk_outbound::proxy::{DialFailureScope, dial_failure_scope};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    const BASE: u8 = OutboundIndex::UserBase as u8;
    const FAILURE_COUNT: usize = 10;
    const WAIT: Duration = Duration::from_secs(5);
    const PORT: u16 = 46100;

    let refusing = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = socks5_relay().await;
    let exit_relay = socks5_relay().await;
    let exit_addr = exit_relay.addr;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = origin.local_addr().unwrap();
    let node = |name: &str, addr: SocketAddr| {
        let mut node = Node {
            name: name.into(),
            address: addr.to_string(),
            host: addr.ip().to_string(),
            port: addr.port(),
            outbound: OutboundConfig::from_protocol(NodeProtocol::Socks5),
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    };
    let first = node("first", refusing.local_addr().unwrap());
    let second = node("second", relay.addr);
    let exit = node("exit", exit_addr);
    let (first_id, second_id, exit_id) = (first.id, second.id, exit.id);
    let via = |name: &str, nodes| Group {
        name: name.into(),
        policy: GroupPolicy::Fallback,
        nodes,
        exit: Some("exit".into()),
        ..Default::default()
    };
    let mut config = Config {
        nodes: vec![first, second, exit],
        groups: vec![
            Group {
                name: "gated".into(),
                final_outbound: Some("via".into()),
                ..Default::default()
            },
            via("alternate", vec![first_id, second_id]),
            Group {
                final_outbound: Some("block".into()),
                ..via("denied", vec![first_id])
            },
            via("via", vec![first_id]),
        ],
        ..Default::default()
    };
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.routing.default_outbound = "block".into();
    config.routing.rules = [
        ("gated", vec!["53".into(), "443".into()]),
        ("alternate", vec!["8443".into()]),
        ("denied", vec!["9443".into()]),
    ]
    .into_iter()
    .map(|(name, port)| {
        rule(
            name,
            RoutingCondition {
                port,
                ..Default::default()
            },
            name,
            USER_MARK,
            true,
        )
    })
    .collect();

    let mut real = RealEbpfBackend::load_routing_test_fixture_with_programs(
        &object(),
        fixture_param(),
        &[crate::ebpf::interface::TcProgram::WanEgressL2],
    )
    .unwrap();
    let listeners = TproxyListeners::new();
    listeners.publish(&mut real).unwrap();
    let programs = real.programs.clone().unwrap();
    let (plane, stop_updates) = ControlPlane::tc_health_fixture(config, real).unwrap();
    let backend = plane.ebpf_handle();
    backend.write().await.set_datapath_ready(true).unwrap();
    let src = "192.0.2.84".parse().unwrap();
    let dst = "198.51.100.84".parse().unwrap();
    let run_packet = |protocol, src_port, dst_port, flags| {
        let bytes = packet(src, dst, protocol, src_port, dst_port, 5, flags);
        run_with_object(
            &programs.object(),
            "wan_egress_l2",
            &bytes,
            SkbInput::default(),
        )
    };
    let tcp_handoff = async |src_port, dst_port| {
        backend
            .read()
            .await
            .routing_handoff_lookup(&tuple(src, dst, src_port, dst_port, IPPROTO_TCP))
            .unwrap()
    };
    let alive = plane.alive_set();
    let manager = plane.group_manager().read().clone();
    let context =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let plan = |name| manager.dial_plan_for_target(name, &context, None);
    let select = |name| plan(name).0.entries;
    let slot = async |id, domain, family| {
        backend
            .read()
            .await
            .get_outbound_alive(id, domain, family)
            .unwrap()
    };
    assert!(!alive.is_registered(exit_id), "exit must have no raw probe");
    for id in BASE..BASE + 3 {
        assert!(slot(id, 0, 0).await, "initial TCPv4 slot for group {id}");
    }
    assert_eq!(
        select("denied")[0].route.as_deref().unwrap().hops(),
        [first_id, exit_id],
        "terminal block must not preempt a viable route"
    );
    assert_eq!(
        run_packet(IPPROTO_TCP, PORT, 443, 0x02).verdict,
        TC_ACT_REDIRECT
    );
    let admitted = tcp_handoff(PORT, 443).await.unwrap();
    assert_eq!(admitted.result.outbound, BASE);
    assert_ne!(admitted.incarnation, 0);

    let refused = tokio::spawn(async move {
        for _ in 0..FAILURE_COUNT {
            let (mut stream, _) = refusing.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request[..8], [5, 1, 0, 1, 127, 0, 0, 1]);
            assert_eq!(request[8..], exit_addr.port().to_be_bytes());
            stream
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        }
    });
    let (gated, revision) = plan("gated");
    let Ok([entry]) = <[_; 1]>::try_from(gated.entries) else {
        panic!("initial final must resolve to one route");
    };
    let attempt = &manager.own_target(Target {
        node: entry.node,
        route: entry.route,
    });
    let route = attempt.route().unwrap();
    assert_eq!(route.hops(), [first_id, exit_id]);
    let registry = plane.proxy_registry();
    let generation = plane.runtime_registry().read().clone();
    for _ in 0..FAILURE_COUNT {
        let stamp = revision.admit();
        let Err(error) = registry
            .dial_ref(
                generation.clone(),
                attempt.dial_ref(),
                destination,
                None,
                WAIT,
            )
            .await
        else {
            panic!("front must refuse CONNECT to the exit");
        };
        assert_eq!(
            dial_failure_scope(error.as_ref()),
            DialFailureScope::Prefix(1)
        );
        assert!(manager.report_route_failure(
            "gated",
            attempt,
            IpVersion::V4,
            stamp,
            error.as_ref()
        ));
    }
    tokio::time::timeout(WAIT, refused).await.unwrap().unwrap();
    assert!(!manager.route_prefix_available(route, IpVersion::V4));
    assert!(select("gated").is_empty());
    for id in [first_id, exit_id] {
        for family in [IpVersion::V4, IpVersion::V6] {
            assert!(alive.is_alive_for(id, ProbeDomain::Tcp, family));
            assert!(!alive.is_failure_demoted(id, ProbeDomain::Tcp, family));
        }
    }

    // Only the exit's path event can close the live slot; neither node went down.
    tokio::time::timeout(WAIT, async {
        while slot(BASE, 0, 0).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("exit-only prefix failure did not close the real TCPv4 slot");
    assert!(
        slot(BASE, 0, 1).await,
        "IPv6 is unaffected by the IPv4 failure"
    );
    for id in [BASE + 1, BASE + 2] {
        assert!(
            slot(id, 0, 0).await,
            "alternate or terminal block lost its slot"
        );
    }
    let generation_id = backend.read().await.routing_policy_generation();
    for (flags, description) in [(0x10, "established ACK"), (0x02, "cached SYN")] {
        assert_eq!(
            run_packet(IPPROTO_TCP, PORT, 443, flags).verdict,
            TC_ACT_REDIRECT,
            "{description} must keep its admitted route"
        );
        assert_eq!(
            tcp_handoff(PORT, 443).await.unwrap().incarnation,
            admitted.incarnation
        );
    }
    assert_eq!(
        run_packet(IPPROTO_TCP, PORT + 1, 443, 0x02).verdict,
        TC_ACT_SHOT,
        "fresh SYN on the failed prefix"
    );
    assert!(tcp_handoff(PORT + 1, 443).await.is_none());
    for (dst_port, expected) in [(53, BASE), (8443, BASE + 1), (9443, BASE + 2)] {
        assert_eq!(
            run_packet(IPPROTO_TCP, PORT + 2, dst_port, 0x02).verdict,
            TC_ACT_REDIRECT,
            "fresh SYN to {dst_port}"
        );
        let entry = tcp_handoff(PORT + 2, dst_port).await.unwrap();
        assert_eq!(entry.result.outbound, expected);
        assert_eq!(entry.result.must, 1);
        assert_eq!(entry.routing_generation, generation_id);
    }
    assert!(!slot(BASE + 1, 2, 0).await, "exit routes remain TCP-only");
    assert_eq!(run_packet(IPPROTO_UDP, PORT, 8443, 0).verdict, TC_ACT_SHOT);
    let dns = run_packet(IPPROTO_UDP, PORT, 53, 0);
    assert_eq!(dns.verdict, TC_ACT_REDIRECT);
    assert_eq!(
        dns.cb[2],
        UdpDnsRoute::new(BASE, generation_id).unwrap().to_mark()
    );

    let Ok([entry]) = <[_; 1]>::try_from(select("alternate")) else {
        panic!("the remaining route must be selectable");
    };
    let alternate = manager.own_target(Target {
        node: entry.node,
        route: entry.route,
    });
    assert_eq!(alternate.route().unwrap().hops(), [second_id, exit_id]);
    let connected = registry
        .dial_ref(generation, alternate.dial_ref(), destination, None, WAIT)
        .await
        .unwrap();
    assert_eq!(*relay.requests.lock(), [exit_addr]);
    assert_eq!(*exit_relay.requests.lock(), [destination]);
    drop(connected);
    assert!(matches!(
        select("denied").as_slice(),
        [block] if block.node.protocol() == NodeProtocol::Block && block.route.is_none()
    ));
    stop_updates.await.unwrap();
}
