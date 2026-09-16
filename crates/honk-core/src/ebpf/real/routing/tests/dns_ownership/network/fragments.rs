use super::*;
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::{Arc, mpsc};

fn padded_query() -> Vec<u8> {
    let mut query = DNS_QUERY.to_vec();
    query[11] = 1;
    let padding = 2048u16;
    query.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0]);
    query.extend_from_slice(&(padding + 4).to_be_bytes());
    query.extend_from_slice(&12u16.to_be_bytes());
    query.extend_from_slice(&padding.to_be_bytes());
    query.resize(query.len() + usize::from(padding), 0);
    query
}

fn fragment_frames(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    dscp: u8,
    id: u16,
    split: usize,
) -> [Vec<u8>; 2] {
    let length = (8 + payload.len()) as u16;
    let mut udp = Vec::with_capacity(usize::from(length));
    udp.extend_from_slice(&source.port().to_be_bytes());
    udp.extend_from_slice(&destination.port().to_be_bytes());
    udp.extend_from_slice(&length.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let checksum = match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => internet_checksum(&[
            &source.octets(),
            &destination.octets(),
            &[0, IPPROTO_UDP],
            &length.to_be_bytes(),
            &udp,
        ]),
        (IpAddr::V6(source), IpAddr::V6(destination)) => internet_checksum(&[
            &source.octets(),
            &destination.octets(),
            &u32::from(length).to_be_bytes(),
            &[0, 0, 0, IPPROTO_UDP],
            &udp,
        ]),
        _ => panic!("mixed fragment address families"),
    };
    let checksum = if checksum == 0 { u16::MAX } else { checksum };
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    assert!(udp.len() > split);
    std::array::from_fn(|index| {
        let offset = if index == 0 { 0 } else { split };
        let data = if index == 0 {
            &udp[..split]
        } else {
            &udp[split..]
        };
        let mut frame = vec![0; 12];
        match (source.ip(), destination.ip()) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                frame.extend_from_slice(&0x0800u16.to_be_bytes());
                let size = (20 + data.len()) as u16;
                frame.extend_from_slice(&[0x45, dscp << 2]);
                frame.extend_from_slice(&size.to_be_bytes());
                frame.extend_from_slice(&id.to_be_bytes());
                let fragment = (offset as u16 / 8) | if index == 0 { 0x2000 } else { 0 };
                frame.extend_from_slice(&fragment.to_be_bytes());
                frame.extend_from_slice(&[64, IPPROTO_UDP, 0, 0]);
                frame.extend_from_slice(&source.octets());
                frame.extend_from_slice(&destination.octets());
                let checksum = internet_checksum(&[&frame[14..34]]);
                frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                frame.extend_from_slice(&0x86ddu16.to_be_bytes());
                let traffic_class = dscp << 2;
                frame.extend_from_slice(&[0x60 | (traffic_class >> 4), traffic_class << 4, 0, 0]);
                frame.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
                frame.extend_from_slice(&[44, 64]);
                frame.extend_from_slice(&source.octets());
                frame.extend_from_slice(&destination.octets());
                frame.extend_from_slice(&[IPPROTO_UDP, 0]);
                let fragment = offset as u16 | u16::from(index == 0);
                frame.extend_from_slice(&fragment.to_be_bytes());
                frame.extend_from_slice(&u32::from(id).to_be_bytes());
            }
            _ => unreachable!(),
        }
        frame.extend_from_slice(data);
        frame
    })
}

fn send_fragments(fixture: &NetworkFixture, mut frames: [Vec<u8>; 2], reverse: bool) {
    let (_, router_mac) = crate::netlink::NlSock::new()
        .unwrap()
        .get_link("hrlan0")
        .unwrap();
    in_netns(&fixture.client_ns, || {
        let (ifindex, client_mac) = crate::netlink::NlSock::new()
            .unwrap()
            .get_link("hrclient0")
            .unwrap();
        let protocol = u16::from_be_bytes([frames[0][12], frames[0][13]]).to_be();
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(protocol),
            )
        };
        assert!(
            fd >= 0,
            "raw fragment socket: {}",
            std::io::Error::last_os_error()
        );
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = protocol;
        address.sll_ifindex = ifindex as i32;
        address.sll_halen = 6;
        address.sll_addr[..6].copy_from_slice(&router_mac);
        for index in if reverse { [1, 0] } else { [0, 1] } {
            let frame = &mut frames[index];
            frame[..6].copy_from_slice(&router_mac);
            frame[6..12].copy_from_slice(&client_mac);
            assert_eq!(
                unsafe {
                    libc::sendto(
                        socket.as_raw_fd(),
                        frame.as_ptr().cast(),
                        frame.len(),
                        0,
                        (&address as *const libc::sockaddr_ll).cast(),
                        mem::size_of_val(&address) as libc::socklen_t,
                    )
                },
                frame.len() as isize,
                "send fragment: {}",
                std::io::Error::last_os_error()
            );
        }
    });
}

fn queue() -> (
    honk_nfqueue::NfqueueService,
    mpsc::Receiver<(honk_nfqueue::PacketEvent, honk_nfqueue::VerdictGuard)>,
) {
    let (sender, receiver) = mpsc::channel();
    let (service, _) = honk_nfqueue::NfqueueService::start(Arc::new(move |packet, guard| {
        sender.send((packet, guard)).unwrap();
    }))
    .unwrap();
    (service, receiver)
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, NFQUEUE, and isolated netns support"]
fn fragmented_dns_v4_v6_reassembles_before_queue_in_both_orders() {
    for use_redirect_peer in [0, 1] {
        isolated(move || {
            let mut fixture = NetworkFixture::new(use_redirect_peer);
            let (service, receiver) = queue();
            fixture
                .backend
                .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
                .unwrap();
            let initial_sequence = fixture.backend.udp_decision_sequence_status().unwrap();
            let initial_states =
                hash_count::<TuplesKey, ConnState>(&fixture.backend, "CONN_STATE_MAP");
            let payload = padded_query();
            let mut id = 1;
            for destination in ["10.81.0.1:53", "[fd81::1]:53"] {
                let destination: SocketAddr = destination.parse().unwrap();
                let native = udp_socket(destination);
                for reverse in [false, true] {
                    for (dscp, outbound) in [
                        (DSCP_ORDINARY, OutboundIndex::ControlPlaneRouting as u8),
                        (DSCP_RAW_MUST, 2),
                    ] {
                        let client = fixture.udp_client(destination, dscp);
                        let source = client.local_addr().unwrap();
                        send_fragments(
                            &fixture,
                            fragment_frames(source, destination, &payload, dscp, id, 1024),
                            reverse,
                        );
                        id += 1;
                        let (event, mut guard) =
                            receiver.recv_timeout(Duration::from_secs(3)).unwrap();
                        let honk_nfqueue::PacketEvent::Datagram(packet) = event else {
                            panic!("valid reassembled query rejected: {event:?}");
                        };
                        assert_eq!(packet.tuple.client, source);
                        assert_eq!(packet.tuple.destination, destination);
                        assert_eq!(packet.payload.as_ref(), payload);
                        assert_eq!(
                            UdpDnsRoute::from_nfqueue_mark(packet.mark),
                            UdpDnsRoute::new(outbound, fixture.backend.routing_policy_generation())
                        );
                        guard.drop_packet().unwrap();
                        assert_udp_empty(&native);
                        fixture.assert_no_redirects();
                    }
                }
                let client = fixture.udp_client(destination, DSCP_ORDINARY);
                client.send_to(DNS_QUERY, destination).unwrap();
                let listener = if destination.is_ipv4() {
                    &fixture.listeners.udp4
                } else {
                    &fixture.listeners.udp6
                };
                let (data, source, mark) = recv_marked(listener);
                assert_eq!(data, DNS_QUERY);
                assert_eq!(source, client.local_addr().unwrap());
                assert_eq!(
                    mark,
                    fixture.dns_mark(OutboundIndex::ControlPlaneRouting as u8)
                );
                assert!(matches!(
                    receiver.try_recv(),
                    Err(mpsc::TryRecvError::Empty)
                ));
            }
            assert_eq!(
                fixture.backend.udp_decision_sequence_status().unwrap(),
                initial_sequence
            );
            assert_eq!(
                hash_count::<TuplesKey, ConnState>(&fixture.backend, "CONN_STATE_MAP"),
                initial_states
            );
            fixture.backend.set_datapath_ready(false).unwrap();
            service.shutdown().unwrap();
        });
    }
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, NFQUEUE, and isolated netns support"]
fn fragmented_dns_preserves_native_must_block_and_queue_readiness() {
    isolated(|| {
        let mut fixture = NetworkFixture::new(0);
        let (service, receiver) = queue();
        let payload = padded_query();
        let mut id = 100;
        for destination in ["10.81.0.1:53", "[fd81::1]:53"] {
            let destination: SocketAddr = destination.parse().unwrap();
            let native = udp_socket(destination);
            fixture
                .backend
                .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
                .unwrap();
            let client = fixture.udp_client(destination, DSCP_DIRECT_MUST);
            send_fragments(
                &fixture,
                fragment_frames(
                    client.local_addr().unwrap(),
                    destination,
                    &payload,
                    DSCP_DIRECT_MUST,
                    id,
                    1024,
                ),
                true,
            );
            id += 1;
            let mut bytes = [0; 4096];
            let (size, source) = native.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..size], payload);
            assert_eq!(source, client.local_addr().unwrap());
            native.send_to(&dns_answer(), source).unwrap();
            let (size, source) = client.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..size], dns_answer());
            assert_eq!(source, destination);
            for (flags, dscp) in [
                (
                    DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY,
                    DSCP_BLOCK_MUST,
                ),
                (0, DSCP_ORDINARY),
                (DATAPATH_FLAG_NFQ_ENABLED, DSCP_RAW_MUST),
            ] {
                fixture.backend.set_datapath_flags(flags).unwrap();
                let client = fixture.udp_client(destination, dscp);
                send_fragments(
                    &fixture,
                    fragment_frames(
                        client.local_addr().unwrap(),
                        destination,
                        &payload,
                        dscp,
                        id,
                        1024,
                    ),
                    false,
                );
                id += 1;
                assert_udp_empty(&native);
                assert!(matches!(
                    receiver.try_recv(),
                    Err(mpsc::TryRecvError::Empty)
                ));
                fixture.assert_no_redirects();
            }
        }
        fixture.backend.set_datapath_ready(false).unwrap();
        service.shutdown().unwrap();
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn fragmented_dns_parser_state_does_not_capture_following_unfragmented_packets() {
    isolated(|| {
        let allowed = nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0)).unwrap();
        let cpu = (0..nix::sched::CpuSet::count())
            .find(|cpu| allowed.is_set(*cpu).unwrap())
            .unwrap();
        let mut pinned = nix::sched::CpuSet::new();
        pinned.set(cpu).unwrap();
        nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &pinned).unwrap();
        let (mut backend, _, _listeners) = publish(&dns_ordering_rules());
        backend
            .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
            .unwrap();
        for (source, destination) in [
            ("10.81.0.2:43000", "10.81.0.1:53"),
            ("[fd81::2]:43000", "[fd81::1]:53"),
        ] {
            let source: SocketAddr = source.parse().unwrap();
            let destination: SocketAddr = destination.parse().unwrap();
            for split in [256, 64] {
                let mut frames = fragment_frames(
                    source,
                    destination,
                    &padded_query(),
                    DSCP_ORDINARY,
                    200,
                    split,
                );
                for frame in &mut frames {
                    frame[6] = 2;
                }
                let first = run(&backend, "lan_ingress_l2", &frames[0], SkbInput::default());
                assert_eq!(first.verdict, TC_ACT_OK);
                assert!(UdpDnsRoute::from_nfqueue_mark(first.mark).is_some());
                let mut bridged = frames[0].clone();
                bridged[0] = 2;
                let other_host = run(&backend, "lan_ingress_l2", &bridged, SkbInput::default());
                assert_eq!(
                    other_host.verdict, TC_ACT_SHOT,
                    "non-host frames cannot assume inet queue delivery"
                );
                let ordinary = packet(
                    source.ip(),
                    destination.ip(),
                    IPPROTO_UDP,
                    source.port() + 1,
                    53,
                    DSCP_ORDINARY,
                    0,
                );
                let following = run(&backend, "lan_ingress_l2", &ordinary, SkbInput::default());
                assert_eq!(
                    following.verdict, TC_ACT_REDIRECT,
                    "unfragmented DNS must keep direct TC delivery"
                );
                assert_eq!(UdpDnsRoute::from_nfqueue_mark(following.mark), None);
                let trailing = run(&backend, "lan_ingress_l2", &frames[1], SkbInput::default());
                assert_eq!(trailing.verdict, TC_ACT_OK);
                assert_eq!(
                    trailing.mark, CLASSIFIED_MARK,
                    "noninitial fragments must not be classified as a new UDP flow"
                );
                let bypass = run(
                    &backend,
                    "lan_ingress_l2",
                    &frames[0],
                    SkbInput {
                        mark: DAE_BYPASS_MARK,
                        ..Default::default()
                    },
                );
                assert_eq!(bypass.verdict, TC_ACT_OK);
                assert_eq!(bypass.mark, CLASSIFIED_MARK | DAE_BYPASS_MARK);
            }
            if source.is_ipv6() {
                let mut atomic = packet(
                    source.ip(),
                    destination.ip(),
                    IPPROTO_UDP,
                    source.port() + 2,
                    53,
                    0,
                    0,
                );
                atomic[20] = 44;
                let length = u16::from_be_bytes([atomic[18], atomic[19]]) + 8;
                atomic[18..20].copy_from_slice(&length.to_be_bytes());
                atomic.splice(54..54, [IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 1]);
                let result = run(&backend, "lan_ingress_l2", &atomic, SkbInput::default());
                assert_eq!(
                    result.verdict, TC_ACT_REDIRECT,
                    "IPv6 atomic fragments need no reassembly"
                );
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, HONK_ROUTING_TEST_OBJECT, NFQUEUE, and isolated netns support"]
fn fragmented_dns_bad_checksum_drops_without_poisoning_the_queue() {
    isolated(|| {
        let mut fixture = NetworkFixture::new(0);
        let (service, receiver) = queue();
        fixture
            .backend
            .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
            .unwrap();
        let payload = padded_query();
        for destination in ["10.81.0.1:53", "[fd81::1]:53"] {
            let destination: SocketAddr = destination.parse().unwrap();
            let native = udp_socket(destination);
            let client = fixture.udp_client(destination, DSCP_ORDINARY);
            let source = client.local_addr().unwrap();
            let mut bad = fragment_frames(source, destination, &payload, 0, 301, 1024);
            let checksum_offset = if source.is_ipv4() { 40 } else { 68 };
            bad[0][checksum_offset] ^= 1;
            send_fragments(&fixture, bad, true);
            let (event, mut guard) = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
            let honk_nfqueue::PacketEvent::Rejected { tuple, error, .. } = event else {
                panic!("bad UDP checksum admitted: {event:?}");
            };
            assert_eq!(tuple.client, source);
            assert_eq!(tuple.destination, destination);
            assert!(matches!(
                error,
                honk_nfqueue::PacketError::InvalidUdpChecksum
            ));
            guard.drop_packet().unwrap();
            send_fragments(
                &fixture,
                fragment_frames(source, destination, &payload, 0, 302, 1024),
                false,
            );
            let (event, mut guard) = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
            let honk_nfqueue::PacketEvent::Datagram(packet) = event else {
                panic!("valid query after bad checksum rejected: {event:?}");
            };
            assert_eq!(packet.payload.as_ref(), payload);
            guard.drop_packet().unwrap();
            assert_udp_empty(&native);
        }
        fixture.backend.set_datapath_ready(false).unwrap();
        service.shutdown().unwrap();
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn dns_queue_carriers_cannot_escape_through_lan_or_wan_egress() {
    isolated(|| {
        let (mut backend, _, _listeners) = publish(&dns_ordering_rules());
        load_classifier(&mut backend, "lan_egress_l2");
        let route = UdpDnsRoute::new(2, backend.routing_policy_generation()).unwrap();
        for ready in [true, false] {
            backend.set_datapath_ready(ready).unwrap();
            for (source, destination) in [
                ("10.81.0.2:43000", "10.81.0.1:53"),
                ("[fd81::2]:43000", "[fd81::1]:53"),
            ] {
                let source: SocketAddr = source.parse().unwrap();
                let destination: SocketAddr = destination.parse().unwrap();
                let frame = fragment_frames(source, destination, &padded_query(), 0, 401, 1024);
                for program in ["lan_egress_l2", "wan_egress_l2"] {
                    let input = SkbInput {
                        mark: route.to_nfqueue_mark(),
                        ingress_ifindex: 1,
                        ..Default::default()
                    };
                    assert_eq!(
                        run(&backend, program, &frame[0], input).verdict,
                        TC_ACT_SHOT
                    );
                    let native = SkbInput {
                        mark: CLASSIFIED_MARK,
                        ..input
                    };
                    assert_ne!(
                        run(&backend, program, &frame[0], native).verdict,
                        TC_ACT_SHOT
                    );
                }
            }
        }
    });
}
