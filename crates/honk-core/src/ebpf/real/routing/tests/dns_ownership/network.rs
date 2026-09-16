use super::*;
use std::io::Write;
use support::*;

mod fragments;
mod support;

const DSCP_ORDINARY: u8 = 0;
const DSCP_DIRECT_MUST: u8 = 8;
const DSCP_BLOCK_MUST: u8 = 16;
const DSCP_RAW_MUST: u8 = 46;
const DNS_QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x03com\x00\x00\x01\x00\x01";

fn dns_answer() -> Vec<u8> {
    let mut answer = DNS_QUERY.to_vec();
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer
}

#[test]
#[ignore = "requires root, Linux with SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, veth/netkit, and isolated netns support"]
fn dns_exact_local_v4_v6_tcp_udp_obey_ordinary_policy() {
    for use_redirect_peer in [0, 1] {
        isolated(move || {
            let fixture = NetworkFixture::new(use_redirect_peer);
            let controller_mark = fixture.dns_mark(OutboundIndex::ControlPlaneRouting as u8);
            for (destination, receiver, tcp_receiver) in [
                (
                    "10.81.0.1:53".parse::<SocketAddr>().unwrap(),
                    &fixture.listeners.udp4,
                    &fixture.listeners.tcp4,
                ),
                (
                    "[fd81::1]:53".parse().unwrap(),
                    &fixture.listeners.udp6,
                    &fixture.listeners.tcp6,
                ),
            ] {
                let local = udp_socket(destination);
                let tcp = tcp_listener(destination);
                let client = fixture.udp_client(destination, DSCP_ORDINARY);
                client.send_to(b"exact", destination).unwrap();
                let (payload, source, mark) = recv_marked(receiver);
                assert_eq!(payload, b"exact");
                assert_eq!(source, client.local_addr().unwrap());
                assert_eq!(mark, controller_mark);
                let mut stream = in_netns(&fixture.client_ns, || {
                    tcp_connect(destination, DSCP_ORDINARY, 0).unwrap()
                });
                let (mut server, source) = accept_connection(tcp_receiver);
                assert_eq!(source, stream.local_addr().unwrap());
                for _ in 0..2 {
                    exchange_tcp(&mut stream, &mut server, DNS_QUERY, &dns_answer());
                }
                assert_udp_empty(&local);
                assert_tcp_empty(&tcp);
            }
            fixture.assert_no_redirects();
        });
    }
}

#[test]
#[ignore = "requires root, Linux with SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, veth/netkit, and isolated netns support"]
fn dns_wildcard_local_v4_v6_tcp_udp_preserve_selected_must_actions() {
    for use_redirect_peer in [0, 1] {
        isolated(move || {
            let fixture = NetworkFixture::new(use_redirect_peer);
            let controller_mark = fixture.dns_mark(OutboundIndex::ControlPlaneRouting as u8);
            let raw_mark = fixture.dns_mark(2);
            for (destination, wildcard, receiver, tcp_receiver) in [
                (
                    "10.81.0.1:53".parse::<SocketAddr>().unwrap(),
                    "0.0.0.0:53".parse::<SocketAddr>().unwrap(),
                    &fixture.listeners.udp4,
                    &fixture.listeners.tcp4,
                ),
                (
                    "[fd81::1]:53".parse().unwrap(),
                    "[::]:53".parse().unwrap(),
                    &fixture.listeners.udp6,
                    &fixture.listeners.tcp6,
                ),
            ] {
                let local = udp_socket(wildcard);
                let tcp = tcp_listener(wildcard);
                let client = fixture.udp_client(destination, DSCP_BLOCK_MUST);
                client.send_to(b"block-must", destination).unwrap();
                let error = in_netns(&fixture.client_ns, || {
                    tcp_connect(destination, DSCP_BLOCK_MUST, 0).unwrap_err()
                });
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                assert_udp_empty(&local);
                assert_tcp_empty(&tcp);
                assert_udp_empty(receiver);
                assert_tcp_empty(tcp_receiver);

                for (dscp, expected_mark) in
                    [(DSCP_ORDINARY, controller_mark), (DSCP_RAW_MUST, raw_mark)]
                {
                    set_dscp(&client, destination.is_ipv6(), dscp);
                    client.send_to(b"wild", destination).unwrap();
                    let (payload, source, mark) = recv_marked(receiver);
                    assert_eq!(payload, b"wild");
                    assert_eq!(source, client.local_addr().unwrap());
                    assert_eq!(mark, expected_mark);
                    let mut stream = in_netns(&fixture.client_ns, || {
                        tcp_connect(destination, dscp, 0).unwrap()
                    });
                    let (mut server, source) = accept_connection(tcp_receiver);
                    assert_eq!(source, stream.local_addr().unwrap());
                    exchange_tcp(&mut stream, &mut server, DNS_QUERY, &dns_answer());
                }
                assert_udp_empty(&local);
                assert_tcp_empty(&tcp);

                set_dscp(&client, destination.is_ipv6(), DSCP_DIRECT_MUST);
                exchange_udp(&client, &local, destination);
                let mut stream = in_netns(&fixture.client_ns, || {
                    tcp_connect(destination, DSCP_DIRECT_MUST, 0).unwrap()
                });
                let (mut server, source) = accept_connection(&tcp);
                assert_eq!(source, stream.local_addr().unwrap());
                exchange_tcp(&mut stream, &mut server, DNS_QUERY, &dns_answer());
                assert_udp_empty(&local);
                assert_tcp_empty(&tcp);
            }
            fixture.assert_no_redirects();
        });
    }
}

#[test]
#[ignore = "requires root, Linux with SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, veth/netkit, and isolated netns support"]
fn dns_ordinary_loopback_v4_v6_tcp_udp_reach_wildcard_backend() {
    for use_redirect_peer in [0, 1] {
        isolated(move || {
            let fixture = NetworkFixture::new(use_redirect_peer);
            for (destination, wildcard) in [
                (
                    "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
                    "0.0.0.0:53".parse::<SocketAddr>().unwrap(),
                ),
                ("[::1]:53".parse().unwrap(), "[::]:53".parse().unwrap()),
            ] {
                let local = udp_socket(wildcard);
                let tcp = tcp_listener(wildcard);
                let client = udp_socket(SocketAddr::new(destination.ip(), 0));
                exchange_udp(&client, &local, destination);
                let mut stream = tcp_connect(destination, DSCP_ORDINARY, 0).unwrap();
                let (mut server, source) = accept_connection(&tcp);
                assert_eq!(source, stream.local_addr().unwrap());
                exchange_tcp(&mut stream, &mut server, DNS_QUERY, &dns_answer());
                assert_udp_empty(&local);
                assert_tcp_empty(&tcp);
            }
            fixture.assert_no_redirects();
        });
    }
}

#[test]
#[ignore = "requires root, Linux with SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, veth/netkit, and isolated netns support"]
fn non_dns_exact_local_v4_v6_udp_preserves_native_socket_precedence() {
    for use_redirect_peer in [0, 1] {
        isolated(move || {
            let fixture = NetworkFixture::new(use_redirect_peer);
            for destination in [
                "10.81.0.1:5353".parse::<SocketAddr>().unwrap(),
                "[fd81::1]:5353".parse().unwrap(),
            ] {
                let local = udp_socket(destination);
                let client = fixture.udp_client(destination, DSCP_BLOCK_MUST);
                exchange_udp(&client, &local, destination);
            }
            fixture.assert_no_redirects();
        });
    }
}

#[test]
#[ignore = "requires root, Linux with SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, veth/netkit, and isolated netns support"]
fn non_dns_wildcard_v4_v6_udp_locality_preserves_forwarded_policy() {
    for use_redirect_peer in [0, 1] {
        isolated(move || {
            let mut fixture = NetworkFixture::new(use_redirect_peer);
            let plan = compile(&[
                rule(
                    "block-forwarded",
                    RoutingCondition {
                        dscp: vec![DSCP_BLOCK_MUST.to_string()],
                        ..Default::default()
                    },
                    "block",
                    0,
                    true,
                ),
                rule(
                    "native-control",
                    RoutingCondition {
                        dscp: vec![DSCP_DIRECT_MUST.to_string()],
                        ..Default::default()
                    },
                    "direct",
                    0,
                    true,
                ),
            ]);
            fixture.backend.publish_routing_plan(&plan, &[]).unwrap();
            for (destination, wildcard, forwarded) in [
                (
                    "10.81.0.1:5353".parse::<SocketAddr>().unwrap(),
                    "0.0.0.0:5353".parse::<SocketAddr>().unwrap(),
                    "198.51.100.53:5353".parse::<SocketAddr>().unwrap(),
                ),
                (
                    "[fd81::1]:5353".parse().unwrap(),
                    "[::]:5353".parse().unwrap(),
                    "[2001:db8:81::53]:5353".parse().unwrap(),
                ),
            ] {
                let local = udp_socket(wildcard);
                let resolver = in_netns(&fixture.resolver_ns, || udp_socket(forwarded));
                let local_client = fixture.udp_client(destination, DSCP_BLOCK_MUST);
                exchange_udp(&local_client, &local, destination);
                let allowed = fixture.udp_client(forwarded, DSCP_DIRECT_MUST);
                exchange_udp(&allowed, &resolver, forwarded);

                // A different live socket prevents the direct control's cached tuple from
                // making a forwarded wildcard match look like native local ownership.
                let blocked = fixture.udp_client(forwarded, DSCP_BLOCK_MUST);
                assert_ne!(allowed.local_addr().unwrap(), blocked.local_addr().unwrap());
                blocked.send_to(b"blocked-forwarded", forwarded).unwrap();
                assert_udp_empty(&resolver);
                assert_udp_empty(&local);
            }
            fixture.assert_no_redirects();
        });
    }
}

#[test]
#[ignore = "requires root, Linux with SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, veth/netkit, and isolated netns support"]
fn dns_forwarded_v4_v6_tcp_udp_reach_selected_owners_without_snat() {
    for use_redirect_peer in [0, 1] {
        isolated(move || {
            let fixture = NetworkFixture::new(use_redirect_peer);
            let controller_mark = fixture.dns_mark(OutboundIndex::ControlPlaneRouting as u8);
            let raw_mark = fixture.dns_mark(2);
            for (destination, wildcard, receiver, tcp_receiver) in [
                (
                    "198.51.100.53:53".parse::<SocketAddr>().unwrap(),
                    "0.0.0.0:53".parse::<SocketAddr>().unwrap(),
                    &fixture.listeners.udp4,
                    &fixture.listeners.tcp4,
                ),
                (
                    "[2001:db8:81::53]:53".parse().unwrap(),
                    "[::]:53".parse().unwrap(),
                    &fixture.listeners.udp6,
                    &fixture.listeners.tcp6,
                ),
            ] {
                let local = udp_socket(wildcard);
                let tcp = tcp_listener(wildcard);
                let resolver = in_netns(&fixture.resolver_ns, || udp_socket(destination));
                let resolver_tcp = in_netns(&fixture.resolver_ns, || tcp_listener(destination));
                let client = fixture.udp_client(destination, DSCP_RAW_MUST);
                for (dscp, expected_mark) in
                    [(DSCP_RAW_MUST, raw_mark), (DSCP_ORDINARY, controller_mark)]
                {
                    set_dscp(&client, destination.is_ipv6(), dscp);
                    client.send_to(DNS_QUERY, destination).unwrap();
                    let (payload, source, mark) = recv_marked(receiver);
                    assert_eq!(payload, DNS_QUERY);
                    assert_eq!(source, client.local_addr().unwrap());
                    assert_eq!(mark, expected_mark);
                }
                let mut stream = in_netns(&fixture.client_ns, || {
                    tcp_connect(destination, DSCP_ORDINARY, 0).unwrap()
                });
                let (mut server, source) = accept_connection(tcp_receiver);
                assert_eq!(source, stream.local_addr().unwrap());
                exchange_tcp(&mut stream, &mut server, DNS_QUERY, &dns_answer());
                assert_udp_empty(&resolver);
                assert_tcp_empty(&resolver_tcp);

                set_dscp(&client, destination.is_ipv6(), DSCP_DIRECT_MUST);
                exchange_udp(&client, &resolver, destination);
                let mut stream = in_netns(&fixture.client_ns, || {
                    tcp_connect(destination, DSCP_DIRECT_MUST, 0).unwrap()
                });
                let (mut server, source) = accept_connection(&resolver_tcp);
                assert_eq!(source, stream.local_addr().unwrap());
                exchange_tcp(&mut stream, &mut server, DNS_QUERY, &dns_answer());
                assert_udp_empty(&local);
                assert_tcp_empty(&tcp);
            }
            fixture.assert_no_redirects();
        });
    }
}

#[test]
#[ignore = "requires root, Linux with TUN, SO_RCVMARK, HONK_ROUTING_TEST_OBJECT, redirect_peer, veth/netkit, and isolated netns support"]
fn dns_l3_tun_v4_v6_udp_local_and_forwarded_policy_carriers() {
    isolated(|| {
        let mut fixture = NetworkFixture::new(1);
        let mut tun = fixture.l3_tun();
        let controller_mark = fixture.dns_mark(OutboundIndex::ControlPlaneRouting as u8);
        let raw_mark = fixture.dns_mark(2);
        for (source, destination, source_port, receiver) in [
            (
                "10.82.0.2".parse::<IpAddr>().unwrap(),
                "198.51.100.53".parse::<IpAddr>().unwrap(),
                44000,
                &fixture.listeners.udp4,
            ),
            (
                "fd83::2".parse().unwrap(),
                "2001:db8:81::53".parse().unwrap(),
                44002,
                &fixture.listeners.udp6,
            ),
        ] {
            for (dscp, port, expected_mark) in [
                (DSCP_RAW_MUST, source_port, raw_mark),
                (DSCP_ORDINARY, source_port + 1, controller_mark),
            ] {
                let packet = packet(source, destination, IPPROTO_UDP, port, 53, dscp, 0);
                tun.write_all(&packet[14..]).unwrap();
                let (payload, observed_source, observed_mark) = recv_marked(receiver);
                assert_eq!(payload, [0xa5]);
                assert_eq!(observed_source, SocketAddr::new(source, port));
                assert_eq!(observed_mark, expected_mark);
            }
        }
        for (source, destination, receiver) in [
            (
                "10.82.0.2".parse::<IpAddr>().unwrap(),
                "10.81.0.1:53".parse::<SocketAddr>().unwrap(),
                &fixture.listeners.udp4,
            ),
            (
                "fd83::2".parse().unwrap(),
                "[fd81::1]:53".parse().unwrap(),
                &fixture.listeners.udp6,
            ),
        ] {
            let local = udp_socket(destination);
            let packet = packet(
                source,
                destination.ip(),
                IPPROTO_UDP,
                44004,
                53,
                DSCP_ORDINARY,
                0,
            );
            tun.write_all(&packet[14..]).unwrap();
            let (payload, observed_source, mark) = recv_marked(receiver);
            assert_eq!(payload, [0xa5]);
            assert_eq!(observed_source, SocketAddr::new(source, 44004));
            assert_eq!(mark, controller_mark);
            assert_udp_empty(&local);
        }
        fixture.assert_no_redirects();
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, and isolated netns support"]
fn dns_marked_loopback_backend_survives_lan_hook_without_exempting_other_marks() {
    for bypass_mark in [DAE_BYPASS_MARK, 0] {
        isolated(move || {
            let mut netlink = crate::netlink::NlSock::new().unwrap();
            let (lo, _) = netlink.get_link("lo").unwrap();
            netlink.set_link_up(lo, true).unwrap();
            let param = DaeParam {
                dae_socket_mark: bypass_mark,
                ..fixture_param()
            };
            let plan = compile(&[rule(
                "block-dns",
                RoutingCondition {
                    port: vec!["53".into()],
                    ..Default::default()
                },
                "block",
                0,
                true,
            )]);
            let mut backend = RealEbpfBackend::load_routing_test_fixture(&object(), param).unwrap();
            backend.publish_routing_plan(&plan, &[]).unwrap();
            let listeners = TproxyListeners::new();
            listeners.publish(&mut backend).unwrap();
            load_classifier(&mut backend, "lan_ingress_l2");
            aya::programs::tc::qdisc_add_clsact("lo").unwrap();
            let program: &mut SchedClassifier = backend
                .bpf_mut()
                .unwrap()
                .program_mut("lan_ingress_l2")
                .unwrap()
                .try_into()
                .unwrap();
            program.attach("lo", TcAttachType::Ingress).unwrap();
            backend
                .set_datapath_flags(honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_RULE_DIRECT)
                .unwrap();
            backend.set_datapath_ready(true).unwrap();

            for destination in [
                SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 53)),
            ] {
                let server = udp_socket(destination);
                let tcp_server = tcp_listener(destination);
                let client = udp_socket(SocketAddr::new(destination.ip(), 0));
                if bypass_mark != 0 {
                    nix::sys::socket::setsockopt(
                        &client,
                        nix::sys::socket::sockopt::Mark,
                        &bypass_mark,
                    )
                    .unwrap();
                    client.send_to(b"backend-query", destination).unwrap();
                    let mut bytes = [0; 64];
                    let (size, source) = server.recv_from(&mut bytes).unwrap();
                    assert_eq!(&bytes[..size], b"backend-query");
                    assert_eq!(source, client.local_addr().unwrap());
                    server.send_to(b"backend-answer", source).unwrap();
                    let (size, source) = client.recv_from(&mut bytes).unwrap();
                    assert_eq!(&bytes[..size], b"backend-answer");
                    assert_eq!(source, destination);
                    let mut stream = tcp_connect(destination, DSCP_ORDINARY, bypass_mark).unwrap();
                    let (mut accepted, source) = accept_connection(&tcp_server);
                    assert_eq!(source, stream.local_addr().unwrap());
                    for _ in 0..2 {
                        exchange_tcp(&mut stream, &mut accepted, b"query", b"reply");
                    }
                }
                server
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                for mark in [0, DAE_BYPASS_MARK | 0x200] {
                    nix::sys::socket::setsockopt(&client, nix::sys::socket::sockopt::Mark, &mark)
                        .unwrap();
                    client.send_to(b"must-drop", destination).unwrap();
                    let mut bytes = [0; 64];
                    assert_eq!(
                        server.recv_from(&mut bytes).unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock
                    );
                    tcp_connect(destination, DSCP_ORDINARY, mark)
                        .expect_err("a non-exact mark must not bypass the DNS block");
                }
                assert_eq!(
                    tcp_server.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
            backend.set_datapath_ready(false).unwrap();
        });
    }
}
