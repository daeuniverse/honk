use super::*;
use crate::ebpf::UdpDecisionCommitResult;
use crate::netlink::{FAM_V4, FAM_V6, PROTO_STATIC, ROUTE_UNICAST, SCOPE_UNIVERSE};
use honk_outbound::proxy::ProxyRegistry;
use std::io::{Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RULE_MARK: u32 = 0x200;
const POLICY_TABLE: u32 = 123;

fn attach_wan(backend: &mut RealEbpfBackend, interface: &str) {
    load_classifier(backend, "wan_egress_l2");
    aya::programs::tc::qdisc_add_clsact(interface).unwrap();
    let program: &mut SchedClassifier = backend
        .bpf_mut()
        .unwrap()
        .program_mut("wan_egress_l2")
        .unwrap()
        .try_into()
        .unwrap();
    program.attach(interface, TcAttachType::Egress).unwrap();
}

// The main table blackholes these destinations. Only the rule-mark table
// reaches the resolver across hrwan0, so delivery proves an actual FIB lookup.
fn policy_targets(fixture: &NetworkFixture) -> [IpAddr; 2] {
    let targets = [
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)),
        "2001:db8:99::53".parse().unwrap(),
    ];
    let mut netlink = crate::netlink::NlSock::new().unwrap();
    let (wan, _) = netlink.get_link("hrwan0").unwrap();
    for destination in targets {
        let (family, bytes, gateway, prefix) = match destination {
            IpAddr::V4(address) => (
                FAM_V4,
                address.octets().to_vec(),
                vec![198, 51, 100, 53],
                32,
            ),
            IpAddr::V6(address) => (
                FAM_V6,
                address.octets().to_vec(),
                "2001:db8:81::53"
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec(),
                128,
            ),
        };
        in_netns(&fixture.resolver_ns, || {
            let mut resolver = crate::netlink::NlSock::new().unwrap();
            let (lo, _) = resolver.get_link("lo").unwrap();
            resolver.addr_op(true, lo, family, &bytes, prefix).unwrap();
        });
        netlink
            .add_rule_fwmark(family, RULE_MARK, !SKB_MARK_RESERVED_MASK, POLICY_TABLE)
            .unwrap();
        netlink
            .add_route(
                family,
                POLICY_TABLE,
                ROUTE_UNICAST,
                SCOPE_UNIVERSE,
                PROTO_STATIC,
                Some((&bytes, prefix)),
                Some(&gateway),
                Some(wan),
            )
            .unwrap();
        netlink
            .add_route(
                family,
                254,
                6,
                SCOPE_UNIVERSE,
                PROTO_STATIC,
                Some((&bytes, prefix)),
                None,
                None,
            )
            .unwrap(); // RTN_BLACKHOLE
    }
    // A marked reverse-path check must not reject the native LAN client.
    for scope in ["all", "hrlan0", "hrwan0"] {
        std::fs::write(format!("/proc/sys/net/ipv4/conf/{scope}/rp_filter"), "0").unwrap();
    }
    targets
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, and isolated netns support"]
fn direct_marks_route_native_lan_v4_v6_tcp_udp_and_cached_packets() {
    isolated(|| {
        let mut fixture = NetworkFixture::new(0);
        let targets = policy_targets(&fixture);
        let config = honk_config::parser::parse_dae_config(
            "routing {\n\
                dscp(8) -> direct(must, mark: 0x200)\n\
                dscp(16) -> direct(must)\n\
                l4proto(tcp, udp) -> direct(mark: 0x200)\n\
            }",
        )
        .unwrap();
        let plan = compile(&config.routing.rules);
        fixture.backend.publish_routing_plan(&plan, &[]).unwrap();
        fixture
            .backend
            .set_datapath_flags(DATAPATH_FLAG_OFFLOAD_RULE_DIRECT)
            .unwrap();
        for target in targets {
            for port in [53, 8080] {
                let destination = SocketAddr::new(target, port);
                let udp = in_netns(&fixture.resolver_ns, || udp_socket(destination));
                let tcp = in_netns(&fixture.resolver_ns, || tcp_listener(destination));
                for dscp in if port == 53 { &[8][..] } else { &[8, 0][..] } {
                    let client = fixture.udp_client(destination, *dscp);
                    for _ in 0..2 {
                        exchange_udp(&client, &udp, destination);
                    }
                    if port != 53 {
                        let source = client.local_addr().unwrap();
                        let key = tuple(source.ip(), target, source.port(), port, IPPROTO_UDP);
                        let state = fixture
                            .backend
                            .udp_conn_state_lookup(&key)
                            .unwrap()
                            .unwrap();
                        assert_eq!(
                            fixture.backend.remove_udp_flow(&key, 0).unwrap(),
                            UdpDecisionCommitResult::Superseded
                        );
                        assert_eq!(
                            unsafe {
                                fixture
                                    .backend
                                    .udp_conn_state_lookup(&key)
                                    .unwrap()
                                    .unwrap()
                                    .meta
                                    .raw
                            },
                            unsafe { state.meta.raw }
                        );
                        exchange_udp(&client, &udp, destination);
                    }
                    let mut stream = in_netns(&fixture.client_ns, || {
                        tcp_connect(destination, *dscp, 0).unwrap()
                    });
                    let (mut accepted, source) = accept_connection(&tcp);
                    assert_eq!(source, stream.local_addr().unwrap());
                    for _ in 0..2 {
                        exchange_tcp(&mut stream, &mut accepted, b"marked", b"routed");
                    }
                }
                let unmarked = fixture.udp_client(destination, 16);
                unmarked.send_to(b"no-policy-route", destination).unwrap();
                assert_udp_empty(&udp);
                in_netns(&fixture.client_ns, || {
                    tcp_connect(destination, 16, 0)
                        .expect_err("unmarked native flow must hit main-table blackhole");
                });
                assert_tcp_empty(&tcp);
            }
        }
        fixture.assert_no_redirects();
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, and isolated netns support"]
fn direct_socket_marks_route_v4_v6_tcp_udp_without_cookie_identity_or_recapture() {
    isolated(|| {
        let mut fixture = NetworkFixture::new(0);
        let targets = policy_targets(&fixture);
        fixture
            .backend
            .publish_routing_plan(
                &compile(&[rule(
                    "block-recapture",
                    RoutingCondition {
                        protocol: vec!["tcp".into(), "udp".into()],
                        ..Default::default()
                    },
                    "block",
                    0,
                    true,
                )]),
                &[],
            )
            .unwrap();
        attach_wan(&mut fixture.backend, "hrwan0");
        assert_eq!(
            hash_count::<u64, PIDName>(&fixture.backend, "COOKIE_PID_MAP"),
            0
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let registry = ProxyRegistry::default_resolver().unwrap();
            let direct = honk_config::config::Config::builtin_direct_node();
            let generation = std::sync::Arc::new(
                honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(
                    std::slice::from_ref(&direct),
                    1,
                    None,
                )
                .unwrap()
                .0,
            );
            for target in targets {
                for port in [53, 8080] {
                    let destination = SocketAddr::new(target, port);
                    let udp = in_netns(&fixture.resolver_ns, || udp_socket(destination));
                    let tcp = in_netns(&fixture.resolver_ns, || tcp_listener(destination));
                    let timeout = Duration::from_secs(2);
                    let transport = registry
                        .dial_udp_transport_runtime_marked(
                            std::sync::Arc::clone(&generation),
                            direct.id,
                            destination,
                            None,
                            timeout,
                            honk_outbound::proxy::DirectMark::new(RULE_MARK).unwrap(),
                        )
                        .await
                        .unwrap();
                    let mut stream = registry
                        .dial_runtime_marked(
                            std::sync::Arc::clone(&generation),
                            direct.id,
                            destination,
                            None,
                            timeout,
                            honk_outbound::proxy::DirectMark::new(RULE_MARK).unwrap(),
                        )
                        .await
                        .unwrap();
                    let (mut accepted, _) = accept_connection(&tcp);
                    for _ in 0..2 {
                        transport.send_packet(b"direct-udp").await.unwrap();
                        let mut bytes = [0; 64];
                        let (size, source) = udp.recv_from(&mut bytes).unwrap();
                        assert_eq!(&bytes[..size], b"direct-udp");
                        udp.send_to(b"udp-reply", source).unwrap();
                        let (size, source) = tokio::time::timeout(
                            Duration::from_secs(2),
                            transport.recv_packet(&mut bytes),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        assert_eq!(&bytes[..size], b"udp-reply");
                        assert_eq!(source, destination);
                        stream.stream.write_all(b"direct-tcp").await.unwrap();
                        let mut bytes = [0; 10];
                        accepted.read_exact(&mut bytes).unwrap();
                        assert_eq!(&bytes, b"direct-tcp");
                        accepted.write_all(b"tcp-reply!").unwrap();
                        tokio::time::timeout(
                            Duration::from_secs(2),
                            stream.stream.read_exact(&mut bytes),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        assert_eq!(&bytes, b"tcp-reply!");
                    }
                }
            }
        });
        assert_eq!(
            hash_count::<u64, PIDName>(&fixture.backend, "COOKIE_PID_MAP"),
            0
        );
        assert_eq!(
            hash_count::<TuplesKey, RoutingHandoffEntry>(&fixture.backend, "ROUTING_HANDOFF_MAP"),
            0
        );
        fixture.assert_no_redirects();
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, and isolated netns support"]
fn wan_global_bypass_is_exact_and_pending_tokens_never_bypass() {
    isolated(|| {
        let mut netlink = crate::netlink::NlSock::new().unwrap();
        let (lo, _) = netlink.get_link("lo").unwrap();
        netlink.set_link_up(lo, true).unwrap();
        let mut backend = RealEbpfBackend::load_routing_test_fixture(
            &object(),
            DaeParam {
                dae_socket_mark: RULE_MARK,
                ..fixture_param()
            },
        )
        .unwrap();
        backend
            .publish_routing_plan(
                &compile(&[rule(
                    "block-unowned",
                    RoutingCondition {
                        protocol: vec!["tcp".into(), "udp".into()],
                        ..Default::default()
                    },
                    "block",
                    0,
                    true,
                )]),
                &[],
            )
            .unwrap();
        let listeners = TproxyListeners::new();
        listeners.publish(&mut backend).unwrap();
        attach_wan(&mut backend, "lo");
        backend.set_datapath_ready(true).unwrap();
        for target in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            for port in [53, 8080] {
                let destination = SocketAddr::new(target, port);
                let udp = udp_socket(destination);
                let tcp = tcp_listener(destination);
                nix::sys::socket::setsockopt(&udp, nix::sys::socket::sockopt::Mark, &RULE_MARK)
                    .unwrap();
                nix::sys::socket::setsockopt(&tcp, nix::sys::socket::sockopt::Mark, &RULE_MARK)
                    .unwrap();
                let client = udp_socket(SocketAddr::new(target, 0));
                nix::sys::socket::setsockopt(&client, nix::sys::socket::sockopt::Mark, &RULE_MARK)
                    .unwrap();
                exchange_udp(&client, &udp, destination);
                let mut stream = tcp_connect(destination, 0, RULE_MARK).unwrap();
                let (mut accepted, _) = accept_connection(&tcp);
                exchange_tcp(&mut stream, &mut accepted, b"global", b"bypass");
                for mark in [
                    0,
                    0x100,
                    RULE_MARK | 0x100,
                    RULE_MARK | 1,
                    NFQUEUE_SIGNATURE_MARK | RULE_MARK,
                ] {
                    nix::sys::socket::setsockopt(&client, nix::sys::socket::sockopt::Mark, &mark)
                        .unwrap();
                    client.send_to(b"must-not-bypass", destination).unwrap();
                    assert_udp_empty(&udp);
                    tcp_connect(destination, 0, mark)
                        .expect_err("non-exact global mark must not bypass WAN policy");
                    assert_tcp_empty(&tcp);
                }
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, and isolated netns support"]
fn wan_marked_direct_must_dns_and_cached_flows_reach_transparent_sockets() {
    isolated(|| {
        let mut fixture = NetworkFixture::new(0);
        fixture
            .backend
            .publish_routing_plan(
                &compile(&[rule(
                    "marked-direct",
                    RoutingCondition {
                        protocol: vec!["tcp".into(), "udp".into()],
                        ..Default::default()
                    },
                    "direct",
                    RULE_MARK,
                    true,
                )]),
                &[],
            )
            .unwrap();
        for key in 0..6 {
            set_array(&mut fixture.backend, "OUTBOUND_CONNECTIVITY_MAP", key, 1u64);
        }
        attach_wan(&mut fixture.backend, "hrwan0");
        for (target, source_ip, udp_receiver, tcp_receiver) in [
            (
                "198.51.100.53".parse::<IpAddr>().unwrap(),
                "198.51.100.1".parse::<IpAddr>().unwrap(),
                &fixture.listeners.udp4,
                &fixture.listeners.tcp4,
            ),
            (
                "2001:db8:81::53".parse().unwrap(),
                "2001:db8:81::1".parse().unwrap(),
                &fixture.listeners.udp6,
                &fixture.listeners.tcp6,
            ),
        ] {
            for port in [53, 8080] {
                let destination = SocketAddr::new(target, port);
                let native_udp = in_netns(&fixture.resolver_ns, || udp_socket(destination));
                let native_tcp = in_netns(&fixture.resolver_ns, || tcp_listener(destination));
                let client = udp_socket(SocketAddr::new(source_ip, 0));
                let key = tuple(
                    source_ip,
                    target,
                    client.local_addr().unwrap().port(),
                    port,
                    IPPROTO_UDP,
                );
                for _ in 0..2 {
                    client.send_to(b"reroute", destination).unwrap();
                    let (payload, source, mark) = recv_marked(udp_receiver);
                    assert_eq!(payload, b"reroute");
                    assert_eq!(source, client.local_addr().unwrap());
                    if port == 53 {
                        assert_eq!(
                            UdpDnsRoute::from_mark(mark),
                            UdpDnsRoute::direct(0, fixture.backend.routing_policy_generation())
                        );
                    } else {
                        assert_eq!(mark, TPROXY_MARK);
                        let selected = handoff(&fixture.backend, &key);
                        assert_eq!(selected.result.mark, RULE_MARK);
                        assert_eq!(selected.result.must, 1);
                        assert_eq!(selected.result.outbound, OutboundIndex::Direct as u8);
                    }
                }
                let mut stream = tcp_connect(destination, 0, 0).unwrap();
                let (mut accepted, source) = accept_connection(tcp_receiver);
                assert_eq!(source, stream.local_addr().unwrap());
                for _ in 0..2 {
                    exchange_tcp(&mut stream, &mut accepted, b"reroute", b"proxied");
                }
                assert_udp_empty(&native_udp);
                assert_tcp_empty(&native_tcp);
            }
        }
        fixture.assert_no_redirects();
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, and isolated netns support"]
fn wan_direct_udp_retirement_reselects_marks_on_the_same_tuple() {
    isolated(|| {
        let mut fixture = NetworkFixture::new(0);
        attach_wan(&mut fixture.backend, "hrwan0");
        for key in 0..6 {
            set_array(&mut fixture.backend, "OUTBOUND_CONNECTIVITY_MAP", key, 1u64);
        }
        // The old mark cannot reach the native receiver. A post-retirement dial
        // must apply the new mark before its route lookup, not just update metadata.
        let mut netlink = crate::netlink::NlSock::new().unwrap();
        for family in [FAM_V4, FAM_V6] {
            netlink
                .add_rule_fwmark(family, RULE_MARK, !SKB_MARK_RESERVED_MASK, POLICY_TABLE)
                .unwrap();
            netlink
                .add_route(
                    family,
                    POLICY_TABLE,
                    6,
                    SCOPE_UNIVERSE,
                    PROTO_STATIC,
                    None,
                    None,
                    None,
                )
                .unwrap();
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for must in [true, false] {
            for (destination, source, receiver) in [
                (
                    "198.51.100.53:8080".parse::<SocketAddr>().unwrap(),
                    "198.51.100.1:0".parse().unwrap(),
                    &fixture.listeners.udp4,
                ),
                (
                    "[2001:db8:81::53]:8080".parse().unwrap(),
                    "[2001:db8:81::1]:0".parse().unwrap(),
                    &fixture.listeners.udp6,
                ),
            ] {
                let client = udp_socket(source);
                let source = client.local_addr().unwrap();
                let key = tuple(
                    source.ip(),
                    destination.ip(),
                    source.port(),
                    destination.port(),
                    IPPROTO_UDP,
                );
                let native = in_netns(&fixture.resolver_ns, || udp_socket(destination));
                let mut cookie = 0u64;
                let mut size = mem::size_of_val(&cookie) as libc::socklen_t;
                assert_eq!(
                    unsafe {
                        libc::getsockopt(
                            client.as_raw_fd(),
                            libc::SOL_SOCKET,
                            libc::SO_COOKIE,
                            (&mut cookie as *mut u64).cast(),
                            &mut size,
                        )
                    },
                    0
                );
                let mut identity = PIDName {
                    pid: std::process::id(),
                    ..Default::default()
                };
                identity.pname[..10].copy_from_slice(b"mark-owner");
                fixture.backend.cookie_pid_store(cookie, &identity).unwrap();
                let policy = |mark| {
                    let must = if must { "must, " } else { "" };
                    let config = honk_config::parser::parse_dae_config(&format!(
                        "routing {{\n pname(mark-owner) -> direct({must}mark: {mark})\n fallback: block\n }}"
                    )).unwrap();
                    let router = Router::from_config(&config.routing).unwrap();
                    RoutingPushPlan::compile(&router, &outbound_ids(), DialMode::Ip).unwrap()
                };
                fixture
                    .backend
                    .publish_routing_plan(&policy(RULE_MARK), &[])
                    .unwrap();
                client.send_to(b"initial", destination).unwrap();
                assert_eq!(recv_marked(receiver).0, b"initial");
                let initial = fixture.backend.routing_handoff_take(&key).unwrap().unwrap();
                assert_eq!(initial.result.mark, RULE_MARK);
                assert_eq!(initial.result.must, u8::from(must));
                assert_eq!(initial.result.pname, identity.pname);
                assert_eq!(initial.result.decision_token, 0);

                fixture
                    .backend
                    .with_udp_retirement_fence(&key, 0, |backend| {
                        client.send_to(b"fenced-cached", destination).unwrap();
                        assert_udp_empty(receiver);
                        assert!(backend.routing_handoff_take(&key)?.is_none());
                        Ok(UdpDecisionCommitResult::Applied)
                    })
                    .unwrap();
                let new_mark = 0x300;
                fixture
                    .backend
                    .publish_routing_plan(&policy(new_mark), &[])
                    .unwrap();
                // Repopulate the consumed handoff AFTER publication: it is still
                // cached X and fresh enough for the one-second no-rewrite path.
                client.send_to(b"cached-old", destination).unwrap();
                assert_eq!(recv_marked(receiver).0, b"cached-old");
                assert_eq!(handoff(&fixture.backend, &key).result.mark, RULE_MARK);
                assert_eq!(
                    fixture.backend.remove_udp_flow(&key, 0).unwrap(),
                    UdpDecisionCommitResult::Applied
                );
                assert!(
                    fixture
                        .backend
                        .udp_conn_state_lookup(&key)
                        .unwrap()
                        .is_none()
                );
                assert!(
                    fixture
                        .backend
                        .routing_handoff_take(&key)
                        .unwrap()
                        .is_none()
                );
                assert!(
                    fixture
                        .backend
                        .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                        .unwrap()
                        .is_none()
                );
                fixture
                    .backend
                    .with_udp_retirement_fence(&key, 0, |backend| {
                        client.send_to(b"fenced-new", destination).unwrap();
                        assert_udp_empty(receiver);
                        assert!(backend.udp_conn_state_lookup(&key)?.is_none());
                        assert!(backend.routing_handoff_take(&key)?.is_none());
                        assert!(
                            backend
                                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))?
                                .is_none()
                        );
                        Ok(UdpDecisionCommitResult::Applied)
                    })
                    .unwrap();

                client.send_to(b"new-policy", destination).unwrap();
                assert_eq!(recv_marked(receiver).0, b"new-policy");
                let selected = fixture.backend.routing_handoff_take(&key).unwrap().unwrap();
                assert_eq!(selected.result.mark, new_mark);
                assert_eq!(selected.result.must, u8::from(must));
                assert_eq!(selected.result.outbound, OutboundIndex::Direct as u8);
                runtime.block_on(async {
                    let registry = ProxyRegistry::default_resolver().unwrap();
                    let direct = honk_config::config::Config::builtin_direct_node();
                    let generation = std::sync::Arc::new(
                        honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(
                            std::slice::from_ref(&direct),
                            1,
                            None,
                        )
                        .unwrap()
                        .0,
                    );
                    let transport = registry
                        .dial_udp_transport_runtime_marked(
                            generation,
                            direct.id,
                            destination,
                            None,
                            Duration::from_secs(2),
                            honk_outbound::proxy::DirectMark::new(selected.result.mark).unwrap(),
                        )
                        .await
                        .unwrap();
                    transport.send_packet(b"new-mark-dial").await.unwrap();
                    let mut bytes = [0; 64];
                    let (size, _) = native.recv_from(&mut bytes).unwrap();
                    assert_eq!(&bytes[..size], b"new-mark-dial");
                });
                let state = fixture
                    .backend
                    .udp_conn_state_lookup(&key)
                    .unwrap()
                    .unwrap();
                let track_key = RedirectTuple::from_tuples(&key);
                let track = fixture
                    .backend
                    .redirect_track_lookup(&track_key)
                    .unwrap()
                    .unwrap();
                for (state_token, handoff_token, track_token, expected) in [
                    (Some(7), 7, 7, UdpDecisionCommitResult::Superseded),
                    (None, 7, 7, UdpDecisionCommitResult::Missing),
                    (Some(0), 7, 0, UdpDecisionCommitResult::TokenMismatch),
                    (Some(0), 0, 7, UdpDecisionCommitResult::TokenMismatch),
                ] {
                    if let Some(token) = state_token {
                        fixture
                            .backend
                            .udp_conn_state_store(
                                &key,
                                &ConnState {
                                    decision_token: token,
                                    state: if token == 0 {
                                        UdpDecisionState::None
                                    } else {
                                        UdpDecisionState::Proxy
                                    } as u8,
                                    ..state
                                },
                            )
                            .unwrap();
                    } else {
                        fixture.backend.udp_conn_state_remove(&key).unwrap();
                    }
                    let mut entry = selected;
                    entry.result.decision_token = handoff_token;
                    fixture
                        .backend
                        .hash_insert("ROUTING_HANDOFF_MAP", &key, &entry)
                        .unwrap();
                    fixture
                        .backend
                        .redirect_track_store(
                            &track_key,
                            &RedirectEntry {
                                decision_token: track_token,
                                ..track
                            },
                        )
                        .unwrap();
                    assert_eq!(fixture.backend.remove_udp_flow(&key, 0).unwrap(), expected);
                    assert_eq!(
                        fixture
                            .backend
                            .udp_conn_state_lookup(&key)
                            .unwrap()
                            .map(|s| s.decision_token),
                        state_token
                    );
                    assert_eq!(
                        handoff(&fixture.backend, &key).result.decision_token,
                        handoff_token
                    );
                    assert_eq!(
                        fixture
                            .backend
                            .redirect_track_lookup(&track_key)
                            .unwrap()
                            .unwrap()
                            .decision_token,
                        track_token
                    );
                }
                fixture.backend.udp_conn_state_store(&key, &state).unwrap();
                fixture
                    .backend
                    .hash_insert("ROUTING_HANDOFF_MAP", &key, &selected)
                    .unwrap();
                fixture
                    .backend
                    .redirect_track_store(&track_key, &track)
                    .unwrap();
                assert_eq!(
                    fixture.backend.remove_udp_flow(&key, 0).unwrap(),
                    UdpDecisionCommitResult::Applied
                );

                // An old endpoint callback must not retire a newer native
                // incarnation after the same WAN tuple re-routes without a mark.
                fixture
                    .backend
                    .publish_routing_plan(&policy(0), &[])
                    .unwrap();
                exchange_udp(&client, &native, destination);
                let native_state = fixture
                    .backend
                    .udp_conn_state_lookup(&key)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    fixture.backend.remove_udp_flow(&key, 0).unwrap(),
                    UdpDecisionCommitResult::Superseded
                );
                assert_eq!(
                    unsafe {
                        fixture
                            .backend
                            .udp_conn_state_lookup(&key)
                            .unwrap()
                            .unwrap()
                            .meta
                            .raw
                    },
                    unsafe { native_state.meta.raw }
                );
                exchange_udp(&client, &native, destination);
            }
        }
        fixture.assert_no_redirects();
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, and isolated netns support"]
fn wan_direct_dns_same_tuple_keeps_each_datagrams_mark_before_userspace_reads() {
    isolated(|| {
        let mut fixture = NetworkFixture::new(0);
        let rules = [
            rule(
                "first",
                RoutingCondition {
                    dscp: vec!["8".into()],
                    ..Default::default()
                },
                "direct",
                RULE_MARK,
                true,
            ),
            rule(
                "second",
                RoutingCondition {
                    dscp: vec!["16".into()],
                    ..Default::default()
                },
                "direct",
                0x3fff_ffff,
                true,
            ),
        ];
        let router = Router::new(&rules, "direct").unwrap();
        let plan = RoutingPushPlan::compile(&router, &outbound_ids(), DialMode::Ip).unwrap();
        fixture.backend.publish_routing_plan(&plan, &[]).unwrap();
        attach_wan(&mut fixture.backend, "hrwan0");
        for (destination, source, receiver) in [
            (
                "198.51.100.53:53".parse::<SocketAddr>().unwrap(),
                "198.51.100.1:0".parse().unwrap(),
                &fixture.listeners.udp4,
            ),
            (
                "[2001:db8:81::53]:53".parse().unwrap(),
                "[2001:db8:81::1]:0".parse().unwrap(),
                &fixture.listeners.udp6,
            ),
        ] {
            let client = udp_socket(source);
            // Both skbs reach the transparent socket before either is admitted.
            // A last-writer tuple handoff would assign the second mark to both.
            for (dscp, payload) in [(8, &b"first"[..]), (16, &b"second"[..])] {
                set_dscp(&client, destination.is_ipv6(), dscp);
                client.send_to(payload, destination).unwrap();
            }
            for (payload, expected_mark) in
                [(&b"first"[..], RULE_MARK), (&b"second"[..], 0x3fff_ffff)]
            {
                let (received, source, mark) = recv_marked(receiver);
                assert_eq!(received, payload);
                assert_eq!(source, client.local_addr().unwrap());
                let route = UdpDnsRoute::from_mark(mark).unwrap();
                assert_eq!(
                    u64::from(route.generation()),
                    fixture.backend.routing_policy_generation()
                );
                assert_eq!(
                    router.direct_mark(route.direct_mark_index().unwrap()),
                    Some(expected_mark)
                );
            }
        }
        assert_eq!(
            hash_count::<TuplesKey, RoutingHandoffEntry>(&fixture.backend, "ROUTING_HANDOFF_MAP"),
            0
        );
        assert_eq!(
            hash_count::<TuplesKey, ConnState>(&fixture.backend, "CONN_STATE_MAP"),
            0
        );
        fixture.assert_no_redirects();
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn compiled_direct_mark_index_matches_canonical_table_and_absent_actions() {
    isolated(|| {
        let rules = [
            rule(
                "high",
                RoutingCondition {
                    dscp: vec!["8".into()],
                    ip: vec!["203.0.113.0/24".into()],
                    ..Default::default()
                },
                "direct",
                0x3fff_ffff,
                true,
            ),
            rule(
                "low",
                RoutingCondition {
                    dscp: vec!["16".into()],
                    ..Default::default()
                },
                "direct",
                RULE_MARK,
                true,
            ),
            rule(
                "ordinary",
                RoutingCondition {
                    dscp: vec!["24".into()],
                    ..Default::default()
                },
                "direct",
                0x300,
                false,
            ),
            rule(
                "proxy",
                RoutingCondition {
                    dscp: vec!["32".into()],
                    ..Default::default()
                },
                "proxy",
                0,
                true,
            ),
        ];
        let mut routing = honk_config::routing::RoutingConfig::default();
        routing.rules = rules.into();
        routing.default_must = true;
        // Bit 0 must not seed the generated program's destination-fact READY bit.
        routing.default_mark = 0x181;
        let router = Router::from_config(&routing).unwrap();
        let plan = RoutingPushPlan::compile(&router, &outbound_ids(), DialMode::Ip).unwrap();
        let mut backend =
            RealEbpfBackend::load_routing_test_fixture(&object(), fixture_param()).unwrap();
        backend.publish_routing_plan(&plan, &[]).unwrap();
        for (dscp, outbound, mark, must, indexed) in [
            (8, 0, 0x3fff_ffff, 1, true),
            (16, 0, RULE_MARK, 1, true),
            (24, 0, 0x300, 0, false),
            (32, 2, 0, 1, false),
            (0, 0, 0x181, 1, true),
        ] {
            let observed = backend
                .run_routing_test(&RoutingInput {
                    dscp,
                    dst_ip: Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped().octets(),
                    dst_port: 8080,
                    l4proto: L4ProtoType::Udp as u32,
                    ip_version: IpVersionType::V4 as u32,
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(observed.status, 0);
            assert_eq!(observed.decision.outbound, outbound);
            assert_eq!(observed.decision.mark, mark);
            assert_eq!(observed.decision.must, must);
            assert_eq!(observed.decision.rule_id == u32::MAX, dscp == 0);
            let index = observed.decision.direct_mark_index;
            if indexed {
                assert!(index <= u8::MAX as u32);
                assert_eq!(router.direct_mark(index as u8), Some(mark));
            } else {
                assert_eq!(index, u32::MAX);
            }
        }
        let miss = backend
            .run_routing_test(&RoutingInput {
                dscp: 8,
                dst_ip: Ipv4Addr::new(203, 0, 114, 9).to_ipv6_mapped().octets(),
                dst_port: 8080,
                l4proto: L4ProtoType::Udp as u32,
                ip_version: IpVersionType::V4 as u32,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(miss.status, 0);
        assert_eq!(miss.decision.outbound, OutboundIndex::Direct as u32);
        assert_eq!(miss.decision.rule_id, u32::MAX);
        assert_eq!(miss.decision.mark, 0x181);
        assert_eq!(miss.decision.must, 1);
    });
}
