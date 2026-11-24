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
    in_routed_health_vm(check_routed_tcp_health);
}

#[cfg(feature = "native-api")]
#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn accepted_udp_prefix_failure_updates_real_tc_admission() {
    in_routed_health_vm(check_routed_udp_health);
}

#[cfg(feature = "native-api")]
fn in_routed_health_vm<F: Future<Output = ()> + 'static>(test: fn() -> F) {
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
    isolated(move || {
        let mut netlink = crate::netlink::NlSock::new().unwrap();
        let (lo, _) = netlink.get_link("lo").unwrap();
        netlink.set_link_up(lo, true).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(test());
    });
}

#[cfg(feature = "native-api")]
async fn refuse_socks_connects(listener: tokio::net::TcpListener, port: u16, attempts: usize) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    for _ in 0..attempts {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request[..8], [5, 1, 0, 1, 127, 0, 0, 1]);
        assert_eq!(request[8..], port.to_be_bytes());
        stream
            .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    }
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

    let refused = tokio::spawn(refuse_socks_connects(
        refusing,
        exit_addr.port(),
        FAILURE_COUNT,
    ));
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

#[cfg(feature = "native-api")]
async fn check_routed_udp_health() {
    use crate::control::ControlPlane;
    use crate::test_support::routed_udp::{PASSWORD, Peer, dns_reply, front, trojan_peer};
    use honk_config::Config;
    use honk_config::node::{Group, GroupPolicy, Node, OutboundConfig, TrojanConfig};
    use honk_config::types::NodeProtocol;
    use honk_outbound::alive::{IpVersion, ProbeDomain};
    use honk_outbound::group::{ScoreSelectionContext, SelectionNetwork, SelectorNetworks, Target};
    use honk_outbound::proxy::{DialFailureScope, dial_failure_scope};
    use tokio::net::{TcpListener, UdpSocket};

    const BASE: u8 = OutboundIndex::UserBase as u8;
    const FAILURES: usize = 50;
    const WAIT: Duration = Duration::from_secs(5);
    const PORT: u16 = 46300;
    const DOMAIN: ProbeDomain = ProbeDomain::DataUdp;
    const FAMILY: IpVersion = IpVersion::V4;

    let refusing = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let spare = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dns_origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_addr = dns_origin.local_addr().unwrap();
    let inner_addr = inner.local_addr().unwrap();
    let outer_addr = outer.local_addr().unwrap();
    let node = |name: &str, listener: &TcpListener, outbound| {
        let addr = listener.local_addr().unwrap();
        let mut node = Node {
            name: name.into(),
            address: addr.to_string(),
            host: addr.ip().to_string(),
            port: addr.port(),
            outbound,
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    };
    let socks = || OutboundConfig::from_protocol(NodeProtocol::Socks5);
    let first = node("first", &refusing, socks());
    let second = node("second", &spare, socks());
    let middle = node("middle", &inner, socks());
    let land = node(
        "land",
        &outer,
        OutboundConfig::Trojan(TrojanConfig {
            password: Some(PASSWORD.into()),
            ..Default::default()
        }),
    );
    let chain = Node::chain_from_nodes("configured", &[&first, &middle, &land]).unwrap();
    let failed_hops = [first.id, middle.id, land.id];
    let alternate_hops = [second.id, land.id];
    let raw_nodes = vec![first.id, second.id, land.id, chain.id];
    let groups = vec![
        Group {
            name: "gated".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![second.id],
            groups: vec!["inner".into()],
            default: Some("inner".into()),
            exit: Some("land".into()),
            ..Default::default()
        },
        Group {
            name: "standalone".into(),
            final_outbound: Some("configured".into()),
            ..Default::default()
        },
        Group {
            name: "alternate".into(),
            nodes: vec![second.id],
            exit: Some("land".into()),
            ..Default::default()
        },
        Group {
            name: "denied".into(),
            policy: GroupPolicy::Fallback,
            groups: vec!["inner".into()],
            exit: Some("land".into()),
            final_outbound: Some("block".into()),
            ..Default::default()
        },
        Group {
            name: "bare".into(),
            nodes: vec![land.id],
            ..Default::default()
        },
        Group {
            name: "inner".into(),
            final_outbound: Some("first".into()),
            exit: Some("middle".into()),
            ..Default::default()
        },
    ];
    let mut config = Config {
        nodes: vec![first, second, middle, land, chain],
        groups,
        ..Default::default()
    };
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.nfqueue_enable = false;
    config.global.udp_check_dns = Some(vec![dns_addr.to_string()]);
    config.routing.default_outbound = "block".into();
    config.routing.rules = [
        ("gated", vec!["53".into(), "443".into()]),
        ("standalone", vec!["5443".into()]),
        ("alternate", vec!["8443".into()]),
        ("denied", vec!["9443".into()]),
        ("bare", vec!["10443".into()]),
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
    let slot = async |id, domain: ProbeDomain, family: IpVersion| {
        backend
            .read()
            .await
            .get_outbound_alive(id, domain as u32, family as u32)
            .unwrap()
    };
    backend.write().await.set_datapath_ready(true).unwrap();
    for (offset, (group, expected)) in [
        ("gated", true),
        ("standalone", true),
        ("alternate", true),
        ("denied", true),
        ("bare", true),
        ("inner", false),
    ]
    .into_iter()
    .enumerate()
    {
        let id = BASE + offset as u8;
        assert_eq!(
            slot(id, DOMAIN, FAMILY).await,
            expected,
            "initial UDPv4 slot {id} for {group}"
        );
    }
    let manager = plane.group_manager().read().clone();
    manager
        .set_selector_choice("gated", "second", SelectorNetworks::Tcp)
        .unwrap();
    manager
        .set_selector_choice("gated", "inner", SelectorNetworks::Udp)
        .unwrap();
    let alive = plane.alive_set();
    let registry = plane.proxy_registry();
    let generation = plane.runtime_registry().read().clone();
    let context = ScoreSelectionContext::aggregate(SelectionNetwork::Udp, DOMAIN, FAMILY);
    let plan = |group| manager.dial_plan_for_target(group, &context, None);
    let src = "192.0.2.84".parse().unwrap();
    let dst = "198.51.100.84".parse().unwrap();
    let run_udp = |src_port, dst_port| {
        let bytes = packet(src, dst, IPPROTO_UDP, src_port, dst_port, 5, 0);
        run_with_object(
            &programs.object(),
            "wan_egress_l2",
            &bytes,
            SkbInput::default(),
        )
    };

    assert!(
        !alive.is_registered(failed_hops[1]),
        "the nested exit is a route dependency only"
    );
    assert!(plan("inner").0.entries.is_empty());
    for dst_port in [443, 5443, 8443, 9443, 10443] {
        assert_eq!(
            run_udp(PORT, dst_port).verdict,
            TC_ACT_REDIRECT,
            "initial UDP destination port {dst_port}"
        );
    }

    let first_peer = Peer::start(refusing, move |stream, index| {
        front(stream, inner_addr, index < FAILURES)
    });
    let inner_peer = Peer::start(inner, move |stream, _| front(stream, outer_addr, false));
    let exit_peer = Peer::start(outer, move |stream, _| async move {
        trojan_peer(stream, &[dns_addr], dns_addr).await;
    });
    for _ in 0..FAILURES {
        let (plan, revision) = plan("gated");
        assert_eq!(plan.health_family, FAMILY);
        let Ok([entry]) = <[_; 1]>::try_from(plan.entries) else {
            panic!("the nested final must select one route before the failure threshold");
        };
        let target = manager.own_target(Target {
            node: entry.node,
            route: entry.route,
        });
        let route = target.route().unwrap();
        assert_eq!(route.hops(), failed_hops);
        let admission = manager
            .capture_udp_route(
                &target,
                &entry.selection_chain,
                &entry.final_owners,
                revision,
                DOMAIN,
                FAMILY,
            )
            .unwrap();
        let Err(error) = registry
            .dial_udp_route(
                generation.clone(),
                route,
                SocketAddr::new(dst, 443),
                None,
                WAIT,
            )
            .await
        else {
            panic!("front must refuse CONNECT to the nested exit");
        };
        assert_eq!(
            dial_failure_scope(error.as_ref()),
            DialFailureScope::Prefix(1)
        );
        assert!(manager.report_udp_route_failure(&admission, error.as_ref()));
    }
    assert_eq!(first_peer.count(), FAILURES);
    assert_eq!(inner_peer.count(), 0);
    assert_eq!(exit_peer.count(), 0);
    tokio::time::timeout(WAIT, async {
        while slot(BASE, DOMAIN, FAMILY).await || slot(BASE + 1, DOMAIN, FAMILY).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("ordered failure must close both committed IPv4 UDP slots");

    for (offset, dst_port) in [443, 5443].into_iter().enumerate() {
        let id = BASE + offset as u8;
        assert!(slot(id, DOMAIN, IpVersion::V6).await);
        assert!(slot(id, ProbeDomain::DnsUdp, FAMILY).await);
        assert!(slot(id, ProbeDomain::Tcp, FAMILY).await);
        assert_eq!(run_udp(PORT + 1, dst_port).verdict, TC_ACT_SHOT);
    }
    assert!(
        plan("gated").0.entries.is_empty(),
        "an unchosen sibling cannot replace the UDP pin"
    );
    assert!(plan("standalone").0.entries.is_empty());
    assert!(matches!(
        plan("alternate").0.entries.as_slice(),
        [entry] if entry.route.as_ref().is_some_and(|route| route.hops() == alternate_hops)
    ));
    assert!(matches!(
        plan("denied").0.entries.as_slice(),
        [entry] if entry.node.protocol() == NodeProtocol::Block && entry.route.is_none()
    ));
    for (offset, dst_port) in [8443, 9443, 10443].into_iter().enumerate() {
        assert!(slot(BASE + 2 + offset as u8, DOMAIN, FAMILY).await);
        assert_eq!(run_udp(PORT + 1, dst_port).verdict, TC_ACT_REDIRECT);
    }
    let dns = run_udp(PORT + 1, 53);
    assert_eq!(dns.verdict, TC_ACT_REDIRECT);
    let kernel_generation = backend.read().await.routing_policy_generation();
    assert_eq!(
        dns.cb[2],
        UdpDnsRoute::new(BASE, kernel_generation).unwrap().to_mark()
    );

    // Drive the real recovery scheduler without letting ordinary TCP checks
    // consume the scripted peers' accepts. Every raw node is a selector pick
    // or a final here, and held nodes keep probing while idle, so the
    // exemption is cleared as well.
    alive.sync_idle_groups(&[honk_outbound::alive::IdleGroupRegistration {
        name: "ordinary health probes".into(),
        tcp_recovery_members: raw_nodes.clone(),
        udp_recovery_members: raw_nodes.clone(),
        members: raw_nodes,
        idle_timeout: Some(WAIT),
        kind: honk_outbound::alive::IdleGroupKind::Automatic,
    }]);
    alive.set_selected_nodes(Default::default());
    let cycle = tokio::spawn({
        let alive = alive.clone();
        async move { alive.run_health_check_cycle_concurrent(WAIT, 1).await }
    });
    let mut buffer = [0; 512];
    let (len, peer) = tokio::time::timeout(WAIT, dns_origin.recv_from(&mut buffer))
        .await
        .expect("the configured recovery request must reach the DNS origin")
        .unwrap();
    assert_eq!(first_peer.count(), FAILURES + 1);
    assert_eq!(inner_peer.count(), 1);
    assert_eq!(exit_peer.count(), 1);
    assert!(!slot(BASE, DOMAIN, FAMILY).await);
    assert!(!slot(BASE + 1, DOMAIN, FAMILY).await);
    let reply = dns_reply(&buffer[..len]);
    assert_eq!(dns_origin.send_to(&reply, peer).await.unwrap(), reply.len());
    tokio::time::timeout(WAIT, cycle).await.unwrap().unwrap();
    tokio::time::timeout(WAIT, async {
        while !slot(BASE, DOMAIN, FAMILY).await || !slot(BASE + 1, DOMAIN, FAMILY).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the validated reply must reopen both committed IPv4 UDP slots");
    for dst_port in [443, 5443] {
        assert_eq!(run_udp(PORT + 2, dst_port).verdict, TC_ACT_REDIRECT);
    }
    assert!(matches!(
        plan("gated").0.entries.as_slice(),
        [entry] if entry.route.as_ref().is_some_and(|route| route.hops() == failed_hops)
    ));
    alive.shutdown_health_checks().await.unwrap();
    first_peer.finish(FAILURES + 1).await;
    inner_peer.finish(1).await;
    exit_peer.finish(1).await;
    assert_eq!(
        dns_origin.try_recv_from(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    stop_updates.await.unwrap();
}
