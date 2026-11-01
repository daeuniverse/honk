use super::*;

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn untouched_passes_return_next_before_backend_admission() {
    isolated(|| {
        // No backend ABI validation: this also replays the pre-cutover object.
        let mut bpf = aya::Ebpf::load(&object()).unwrap();
        for name in [
            "lan_ingress_l2",
            "lan_ingress_l3",
            "lan_egress_l2",
            "lan_egress_l3",
            "wan_ingress_l2",
            "wan_ingress_l3",
            "wan_egress_l2",
            "wan_egress_l3",
            "dae0_ingress",
        ] {
            let program: &mut SchedClassifier = bpf.program_mut(name).unwrap().try_into().unwrap();
            program.load().unwrap();
            let result = program
                .test_run(TestRunOptions {
                    data_in: Some(&[0u8; 64]),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(result.return_value, TC_ACT_UNSPEC, "{name}");
        }
    });
}

fn assert_next(backend: &RealEbpfBackend, name: &str, case: &str, bytes: &[u8], input: SkbInput) {
    let result = run(backend, name, bytes, input);
    assert_eq!(
        result.verdict, TC_ACT_UNSPEC,
        "{name} {case}, input={bytes:02x?}"
    );
    assert_eq!(result.mark, input.mark, "{name} {case}");
    assert_eq!(&result.data[..bytes.len()], bytes, "{name} {case}");
}

const PEERS: [(IpAddr, IpAddr, IpAddr); 2] = [
    (
        IpAddr::V4(Ipv4Addr::new(8, 0, 2, 91)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 91)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x86dd, 0, 0, 0, 0, 91)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 91)),
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
    ),
];

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn pure_passes_continue_tcx_without_changing_marks() {
    isolated(|| {
        let mut backend = RealEbpfBackend::load_routing_test_fixture(
            &object(),
            DaeParam {
                local_ip: u32::from_ne_bytes([203, 0, 113, 99]),
                ..fixture_param()
            },
        )
        .unwrap();
        for name in [
            "lan_ingress_l2",
            "lan_egress_l2",
            "wan_ingress_l2",
            "wan_egress_l2",
            "lan_egress_l3",
            "wan_ingress_l3",
            "wan_egress_l3",
            "dae0_ingress",
        ] {
            load_classifier(&mut backend, name);
        }
        let input = SkbInput {
            mark: USER_MARK,
            ..Default::default()
        };
        for (src, dst, multicast) in PEERS {
            let port = 46000;
            let bytes = packet(src, dst, IPPROTO_UDP, port, 443, 0, 0);
            set_array(&mut backend, "DATAPATH_STATE_MAP", 0, 0u32);
            for name in ["lan_ingress_l2", "wan_egress_l2"] {
                assert_next(&backend, name, "", &bytes, input);
            }
            set_array(&mut backend, "DATAPATH_STATE_MAP", 0, 1u32);

            let mut unsupported = bytes.clone();
            unsupported[14 + if src.is_ipv4() { 9 } else { 6 }] = 47;
            for name in [
                "lan_egress_l2",
                "wan_ingress_l2",
                "wan_egress_l2",
                "dae0_ingress",
            ] {
                assert_next(&backend, name, "", &unsupported, input);
            }
            assert_next(&backend, "dae0_ingress", "", &bytes, input);

            let special = packet(src, multicast, IPPROTO_UDP, port + 1, 5353, 0, 0);
            for name in ["lan_egress_l2", "wan_egress_l2"] {
                assert_next(&backend, name, "", &special, input);
                let mut broadcast = bytes.clone();
                broadcast[..6].fill(0xff);
                assert_next(&backend, name, "", &broadcast, input);
            }
            let result = run(&backend, "lan_ingress_l2", &special, input);
            assert_eq!(
                (result.verdict, result.mark),
                (TC_ACT_OK, USER_MARK | CLASSIFIED_MARK)
            );
            if src.is_ipv4() {
                let local = packet(
                    src,
                    "203.0.113.99".parse().unwrap(),
                    IPPROTO_UDP,
                    port + 2,
                    443,
                    0,
                    0,
                );
                assert_next(&backend, "wan_egress_l2", "", &local, input);
            }
            assert_next(
                &backend,
                "wan_egress_l2",
                "",
                &bytes,
                SkbInput {
                    ingress_ifindex: 1,
                    ..input
                },
            );
            for name in ["lan_egress_l2", "wan_ingress_l2"] {
                for (sport, dport) in [(53, port + 3), (port + 4, 3478)] {
                    let reply = packet(src, dst, IPPROTO_UDP, sport, dport, 0, 0);
                    assert_next(&backend, name, "", &reply, input);
                }
            }
            let ack = packet(src, dst, IPPROTO_TCP, port + 5, 443, 0, 0x10);
            assert_next(&backend, "wan_egress_l2", "", &ack, input);
            let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap();
            let state = ConnState {
                incarnation: 1,
                last_seen_ns: time.tv_sec() as u64 * 1_000_000_000 + time.tv_nsec() as u64,
                ..Default::default()
            };
            backend
                .flow_insert(
                    "CONN_STATE_MAP",
                    &tuple(src, dst, port + 5, 443, IPPROTO_TCP),
                    &state,
                )
                .unwrap();
            assert_next(&backend, "wan_egress_l2", "", &ack, input);
            let reply_state = ConnState {
                is_wan_ingress_direction: 1,
                ..state
            };
            backend
                .flow_insert(
                    "CONN_STATE_MAP",
                    &tuple(src, dst, port, 443, IPPROTO_UDP),
                    &reply_state,
                )
                .unwrap();
            assert_next(&backend, "wan_egress_l2", "", &bytes, input);
        }
        // Test-run frames are Ethernet: an L3-bound program must treat them as L2 does.
        for (src, dst, multicast) in PEERS {
            let bytes = packet(src, dst, IPPROTO_UDP, 46102, 443, 0, 0);
            let mut unsupported = bytes.clone();
            unsupported[14 + if src.is_ipv4() { 9 } else { 6 }] = 47;
            for name in ["lan_egress_l3", "wan_ingress_l3", "wan_egress_l3"] {
                assert_next(&backend, name, "", &unsupported, input);
            }
            let special = packet(src, multicast, IPPROTO_UDP, 46103, 5353, 0, 0);
            for name in ["lan_egress_l3", "wan_egress_l3"] {
                assert_next(&backend, name, "", &special, input);
            }
            let result = run(
                &backend,
                "wan_egress_l3",
                &bytes,
                SkbInput {
                    mark: DAE_BYPASS_MARK,
                    ..Default::default()
                },
            );
            assert_eq!((result.verdict, result.mark), (TC_ACT_OK, DAE_BYPASS_MARK));
        }
        let (src, dst, _) = PEERS[0];
        let bytes = packet(src, dst, IPPROTO_UDP, 46101, 443, 0, 0);
        for (name, mark) in [
            ("lan_ingress_l2", CLASSIFIED_MARK | USER_MARK),
            ("lan_ingress_l2", pack_nfqueue_mark(123).unwrap()),
            ("wan_egress_l2", DAE_BYPASS_MARK),
            ("wan_egress_l2", CLASSIFIED_MARK | USER_MARK),
        ] {
            let result = run(
                &backend,
                name,
                &bytes,
                SkbInput {
                    mark,
                    ..Default::default()
                },
            );
            assert_eq!((result.verdict, result.mark), (TC_ACT_OK, mark), "{name}");
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn unsupported_lan_ingress_frames_continue_tcx_without_marking() {
    isolated(|| {
        // The parser scratch is per CPU: pin so each frame follows the TCP
        // packet on the same CPU, exposing any read of a previous packet's headers.
        pin_to_current_cpu();
        let mut backend =
            RealEbpfBackend::load_routing_test_fixture(&object(), fixture_param()).unwrap();
        for name in ["lan_ingress_l2", "lan_ingress_l3"] {
            load_classifier(&mut backend, name);
        }
        set_array(&mut backend, "DATAPATH_STATE_MAP", 0, 1u32);
        let input = SkbInput {
            mark: USER_MARK,
            ..Default::default()
        };
        // Test-run frames are Ethernet, so both programs must classify them alike.
        for name in ["lan_ingress_l2", "lan_ingress_l3"] {
            for (src, dst, _) in PEERS {
                let v4 = src.is_ipv4();
                let (proto, l4) = (14 + if v4 { 9 } else { 6 }, 14 + if v4 { 20 } else { 40 });
                let tcp = packet(src, dst, IPPROTO_TCP, 46200, 443, 0, 0x02);
                let udp = packet(src, dst, IPPROTO_UDP, 46201, 443, 0, 0);
                let with_ethertype = |ethertype: u16| {
                    let mut bytes = udp.clone();
                    bytes[12..14].copy_from_slice(&ethertype.to_be_bytes());
                    bytes
                };
                let with_protocol = |protocol: u8| {
                    let mut bytes = udp.clone();
                    bytes[proto] = protocol;
                    bytes
                };
                let mut unsupported = vec![
                    ("ARP", with_ethertype(libc::ETH_P_ARP as u16)),
                    ("MACsec", with_ethertype(libc::ETH_P_MACSEC as u16)),
                    ("GRE", with_protocol(libc::IPPROTO_GRE as u8)),
                ];
                if v4 {
                    unsupported.push(("ICMPv4 echo", with_protocol(libc::IPPROTO_ICMP as u8)));
                } else {
                    let mut ns = with_protocol(libc::IPPROTO_ICMPV6 as u8);
                    ns[l4..l4 + 2].copy_from_slice(&[135, 0]);
                    unsupported.push(("ICMPv6 NS", ns));
                }
                for (what, frame) in &unsupported {
                    let _ = run(&backend, name, &tcp, input);
                    assert_next(&backend, name, &format!("{what} {src}"), frame, input);
                }
                // These keep the terminal, classified pass.
                let mut classified = Vec::new();
                if v4 {
                    let mut fragment = udp.clone();
                    fragment[14 + 6..14 + 8].copy_from_slice(&[0, 8]);
                    classified.push(("non-initial fragment", fragment));
                    let mut malformed = udp.clone();
                    malformed[14] = 0x40;
                    classified.push(("malformed IPv4", malformed));
                } else {
                    let mut redirect = with_protocol(libc::IPPROTO_ICMPV6 as u8);
                    redirect[l4..l4 + 2].copy_from_slice(&[137, 0]);
                    classified.push(("NDP Redirect", redirect));
                }
                for (what, frame) in &classified {
                    let _ = run(&backend, name, &tcp, input);
                    let result = run(&backend, name, frame, input);
                    assert_eq!(
                        (result.verdict, result.mark),
                        (TC_ACT_OK, USER_MARK | CLASSIFIED_MARK),
                        "{name} {what} {src}"
                    );
                }
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn conn_capacity_native_passes_continue_tcx_without_clearing_marks() {
    isolated(|| {
        let (mut backend, _, _listeners) = publish(&[]);
        load_classifier(&mut backend, "wan_egress_l2");
        {
            let map = backend
                .bpf_mut()
                .unwrap()
                .map_mut("CONN_STATE_MAP")
                .unwrap();
            let mut map = HashMap::<_, TuplesKey, FlowMapValue<ConnState>>::try_from(map).unwrap();
            for index in 0..honk_ebpf_common::conn::MAX_CONN_STATE_NUM {
                let key = tuple(
                    IpAddr::V4(Ipv4Addr::from(0xac10_0000 + index)),
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 254)),
                    9,
                    9,
                    IPPROTO_UDP,
                );
                map.insert(key, FlowMapValue::new(ConnState::default()), 1 | 4)
                    .unwrap();
            }
        }
        for (src, dst, _) in PEERS {
            for protocol in [IPPROTO_TCP, IPPROTO_UDP] {
                let bytes = packet(src, dst, protocol, 46200, 443, 0, 0x02);
                assert_next(
                    &backend,
                    "wan_egress_l2",
                    "",
                    &bytes,
                    SkbInput {
                        mark: USER_MARK,
                        ..Default::default()
                    },
                );
                assert!(
                    backend
                        .conn_state_lookup(&tuple(src, dst, 46200, 443, protocol))
                        .unwrap()
                        .is_none()
                );
            }
        }
    });
}
