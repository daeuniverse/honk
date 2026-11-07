use super::*;
use crate::control::netstack::{FlowIo, PacketDriver, PacketOwner};
use honk_netstack::wire::tcp;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn path() -> ReturnPath {
    ReturnPath {
        device: 0,
        mac: [2, 3, 4, 5, 6, 7],
        vlan_tci: [0xa00c, 45],
        vlan_proto: [0x88a8, 0x8100],
        vlan_count: 2,
    }
}

fn fixture_parts() -> (
    PacketScope,
    PacketOwner,
    Arc<MemoryBudget>,
    ControlPlane,
    Arc<tokio::sync::Semaphore>,
) {
    fixture_parts_mtu(1500)
}

fn fixture_parts_mtu(
    mtu: usize,
) -> (
    PacketScope,
    PacketOwner,
    Arc<MemoryBudget>,
    ControlPlane,
    Arc<tokio::sync::Semaphore>,
) {
    let budget = MemoryBudget::new(32 << 20);
    let mut config = honk_netstack::Config::new([89; 32]);
    config.mode = honk_netstack::Mode::Transparent {
        exclude: Default::default(),
    };
    config.mtu = u16::try_from(mtu).unwrap();
    config.max_flows = 8;
    config.memory_limit = 2 << 20;
    config.tcp_rcv_buf_max = 4096;
    config.tcp_snd_buf_max = 8192;
    let (scope, owner): (_, PacketOwner) = PacketScope::new(
        config,
        Arc::clone(&budget),
        RuntimeLimits {
            max_slots: 8,
            control_frames: 2,
            bulk_frames: 2,
            max_waiters: 8,
        },
        Instant::now(),
    )
    .unwrap();
    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.tcp_check_url.clear();
    config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
    config.global.preconnect_node_count = 0;
    config.global.udp_warm_node_count = 0;
    let plane = crate::control::tests::support::control_plane(config);
    let slots = crate::control::tests::support::tcp_slots(&plane);
    (scope, owner, budget, plane, slots)
}

async fn fixture() -> (
    PacketEndpoints,
    PacketEndpointOwner,
    PacketScope,
    Arc<MemoryBudget>,
    Arc<tokio::sync::Semaphore>,
) {
    let (scope, owner, budget, plane, slots) = fixture_parts();
    let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), owner)], 4)
        .await
        .unwrap();
    (endpoints, owner, scope, budget, slots)
}

/// The daemon's start: the driver exists before readiness and this test is its device owner.
async fn driven(
    scope: PacketScope,
    owner: PacketOwner,
    plane: ControlPlane,
) -> (PacketEndpoints, PacketEndpointOwner, PacketDriver) {
    let (endpoints, mut owner, mut drivers) =
        PacketEndpoints::start_driven(plane, vec![(scope, owner)], 4).unwrap();
    poll_fn(|cx| owner.poll_ready(cx)).await.unwrap();
    assert_eq!(drivers.len(), 1);
    (endpoints, owner, drivers.pop().unwrap())
}

/// Close, then keep driving until the parked original owner and supervisor have joined.
async fn join_driven(
    endpoints: PacketEndpoints,
    mut owner: PacketEndpointOwner,
    driver: &mut PacketDriver,
) {
    endpoints.close();
    let (_plane, result) = poll_fn(|cx| {
        driver.service(cx, Instant::now());
        owner.poll_join_plane(cx)
    })
    .await
    .unwrap();
    result.unwrap();
}

fn datagram(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; payload.len() + 80];
    let length = wire::udp::emit_packet(&mut bytes, source, destination, payload).unwrap();
    bytes.truncate(length);
    bytes
}

fn segment(source: SocketAddr, destination: SocketAddr, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    segment_mss(source, destination, seq, ack, flags, 1460)
}

fn segment_mss(
    source: SocketAddr,
    destination: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    mss: u16,
) -> Vec<u8> {
    let mut bytes = vec![0; 128];
    let length = tcp::emit_packet(
        &mut bytes,
        source.ip(),
        destination.ip(),
        &tcp::Header {
            src_port: source.port(),
            dst_port: destination.port(),
            seq,
            ack,
            flags,
            window: 60000,
            urgent: 0,
            options: tcp::Options {
                mss: (flags & tcp::SYN != 0).then_some(mss),
                ..Default::default()
            },
        },
        [&[], &[]],
    )
    .unwrap();
    bytes.truncate(length);
    bytes
}

fn output_realm(driver: PacketDriver, reply: ReturnPath, mtu: usize) -> Realm {
    let link = LogicalLink {
        ifindex: 10,
        mtu: u32::try_from(mtu).unwrap(),
        mac: [4; 6],
        path: LinkPath {
            physical_ifindex: 10,
            vlan_tci: reply.vlan_tci,
            vlan_proto: reply.vlan_proto,
            vlan_count: reply.vlan_count,
        },
    };
    Realm {
        ingress: Ingress {
            scope: driver.scope(),
            namespace: 1,
            ifindex: 10,
            attachment: 1,
            mark: MarkProvenance::BeforeSkb,
        },
        device: reply.device,
        generated: generated_layout(link),
        link,
        driver,
        pending: [None, None],
    }
}

fn output_peer(scope: &PacketScope, address: SocketAddr, path: ReturnPath, now: Instant) -> Peer {
    Peer {
        scope: scope.scope(),
        address: address.ip(),
        path,
        last_seen: now,
        conflict: None,
    }
}

fn generate(
    realm: &mut Realm,
    now: Instant,
    class: TxClass,
    peers: &[Peer],
) -> (Vec<u8>, Retained) {
    let (_, capacity) = realm.generated.expect("eligible realm");
    let mut frame = vec![0xa5; capacity];
    let mut emitted = false;
    let (length, owner) = realm
        .generate_output(now, class, 10, peers, &mut frame, &mut emitted)
        .unwrap()
        .expect("actual Stack output");
    assert!(emitted);
    let Retained::Endpoint(output) = &owner else {
        panic!("generated Endpoint owner");
    };
    assert!(output.packet().is_none());
    assert_eq!(output.scope(), realm.driver.scope());
    assert_eq!(length, realm.generated.unwrap().0 + output.len());
    assert!(frame[length..].iter().all(|byte| *byte == 0xa5));
    frame.truncate(length);
    (frame, owner)
}

fn check_tcp_frame(
    frame: &[u8],
    reply: ReturnPath,
    source: SocketAddr,
    destination: SocketAddr,
) -> (tcp::Header, &[u8]) {
    let l2 = 14 + 4 * usize::from(reply.vlan_count);
    assert_eq!(&frame[..6], &reply.mac);
    assert_eq!(&frame[6..12], &[4; 6]);
    for tag in 0..usize::from(reply.vlan_count) {
        let offset = 12 + tag * 4;
        assert_eq!(
            &frame[offset..offset + 2],
            &reply.vlan_proto[tag].to_be_bytes()
        );
        assert_eq!(
            &frame[offset + 2..offset + 4],
            &reply.vlan_tci[tag].to_be_bytes()
        );
    }
    let ethertype: u16 = if source.is_ipv6() { 0x86dd } else { 0x0800 };
    assert_eq!(&frame[l2 - 2..l2], &ethertype.to_be_bytes());
    let packet = &frame[l2..];
    let ip = wire::parse_ip(packet).unwrap();
    assert_eq!(
        (ip.src, ip.dst, ip.proto),
        (source.ip(), destination.ip(), wire::PROTO_TCP)
    );
    assert_eq!(ip.payload.end, packet.len());
    assert!(tcp::verify_checksum(
        ip.src,
        ip.dst,
        &packet[ip.payload.clone()]
    ));
    let (header, offset) = tcp::parse(&packet[ip.payload.clone()]).unwrap();
    assert_eq!(
        (header.src_port, header.dst_port),
        (source.port(), destination.port())
    );
    (header, &packet[ip.payload.start + offset..ip.payload.end])
}

fn fragment_bytes(packet: &[u8]) -> (u32, usize, bool, &[u8]) {
    assert_eq!(wire::parse_ip(packet), Err(wire::ParseError::Fragment));
    if packet[0] >> 4 == 4 {
        let head = usize::from(packet[0] & 15) * 4;
        assert_eq!(wire::checksum::checksum(&packet[..head]), 0);
        assert_eq!(packet[9], wire::PROTO_UDP);
        let bits = u16::from_be_bytes(packet[6..8].try_into().unwrap());
        (
            u32::from(u16::from_be_bytes(packet[4..6].try_into().unwrap())),
            usize::from(bits & 0x1fff) * 8,
            bits & 0x2000 != 0,
            &packet[head..],
        )
    } else {
        assert_eq!(packet[6], 44);
        assert_eq!(packet[40], wire::PROTO_UDP);
        let bits = u16::from_be_bytes(packet[42..44].try_into().unwrap());
        (
            u32::from_be_bytes(packet[44..48].try_into().unwrap()),
            usize::from(bits & 0xfff8),
            bits & 1 != 0,
            &packet[48..],
        )
    }
}

fn receive(
    endpoints: &PacketEndpoints,
    peers: &mut Vec<Peer>,
    counters: &mut PressureCounters,
    scope: &PacketScope,
    packet: &[u8],
    path: ReturnPath,
    now: Instant,
) {
    receive_endpoint(
        endpoints,
        peers,
        counters,
        scope.scope(),
        packet,
        now,
        path,
        None,
    )
    .unwrap();
}

fn fill_quiescent(peers: &mut Vec<Peer>, scope: ScopeId, now: Instant) {
    for index in peers.len()..PEERS {
        peers.push(Peer {
            scope,
            address: std::net::Ipv4Addr::from(0xc633_0000 + index as u32).into(),
            path: path(),
            last_seen: now + Duration::from_secs(1),
            conflict: None,
        });
    }
}

async fn accept(scope: &PacketScope, client: SocketAddr, destination: SocketAddr) -> (FlowIo, u32) {
    let (_, flow) = scope.poll_accept().expect("the actual pending SYN");
    let synack = scope.next_output().await.unwrap();
    let ip = wire::parse_ip(synack.packet()).unwrap();
    let (header, _) = tcp::parse(&synack.packet()[ip.payload]).unwrap();
    let seq = header.seq.wrapping_add(1);
    synack.release();
    assert_eq!(
        scope.receive(
            &segment(client, destination, 101, seq, tcp::ACK),
            Instant::now()
        ),
        honk_netstack::Rx::Consumed
    );
    (flow, seq)
}

#[tokio::test]
async fn peer_pressure_preserves_initializer_dns_and_actual_reply_headers() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (endpoints, owner, scope, _budget, _slots) = fixture().await;
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let dns_source: SocketAddr = "192.0.2.11:41000".parse().unwrap();
        let mut peers = Vec::with_capacity(PEERS);
        let mut counters = PressureCounters::default();
        let now = Instant::now();
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &datagram(source, destination, b"first"),
            path(),
            now,
        );
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &datagram(dns_source, "127.0.0.1:53".parse().unwrap(), b"queued"),
            path(),
            now,
        );
        fill_quiescent(&mut peers, scope.scope(), now);
        let third: SocketAddr = "192.0.2.12:41000".parse().unwrap();
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &datagram(third, destination, b"third"),
            path(),
            now,
        );
        assert_eq!(counters.peer_reclaimed, 1);
        let mut stolen = path();
        stolen.mac[5] ^= 2;
        for source in [source, dns_source] {
            receive(
                &endpoints,
                &mut peers,
                &mut counters,
                &scope,
                &datagram(source, destination, b"stolen"),
                stolen,
                now + PEER_CONFLICT_HOLD * 2,
            );
            scope
                .datagram_sender(destination)
                .send_to(b"owned", source)
                .await
                .unwrap();
            let output = scope.next_output().await.unwrap();
            let retained = endpoint_return_path(&peers, &output)
                .expect("owned reply remains routable under peer pressure");
            let header = return_header(retained, [4; 6], 2, false).unwrap();
            assert_eq!(&header[..6], path().mac);
            assert_eq!(&header[12..20], &[0x88, 0xa8, 0xa0, 12, 0x81, 0, 0, 45]);
            assert!(output.packet().ends_with(b"owned"));
            output.release();
        }
        assert_eq!(peers.len(), PEERS);
        assert_eq!(counters.peer_conflict, 2);
        endpoints.close();
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("retained peers must survive bounded table churn");
}

#[tokio::test]
async fn stray_reset_never_learns_or_poison_replies_and_tcp_pins_its_peer() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (endpoints, owner, scope, _budget, slots) = fixture().await;
        let _slots = slots
            .clone()
            .acquire_many_owned(slots.available_permits() as u32)
            .await
            .unwrap();
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.9:443".parse().unwrap();
        let mut peers = Vec::with_capacity(PEERS);
        let mut counters = PressureCounters::default();
        let now = Instant::now();
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &segment(source, destination, 1, 0, tcp::RST),
            path(),
            now,
        );
        assert!(peers.is_empty());
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &segment(source, destination, 100, 0, tcp::SYN),
            path(),
            now,
        );
        let (mut flow, server_seq) = accept(&scope, source, destination).await;
        fill_quiescent(&mut peers, scope.scope(), now);
        let mut stolen = path();
        stolen.mac[5] ^= 2;
        let unknown = SocketAddr::new(source.ip(), source.port() + 1);
        let mut reset_priority = path();
        reset_priority.vlan_tci[0] = 0x700c;
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &segment(unknown, destination, 1, 0, tcp::RST),
            reset_priority,
            now,
        );
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &segment(unknown, destination, 1, 0, tcp::RST),
            stolen,
            now + PEER_CONFLICT_HOLD * 2,
        );
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &segment(source, destination, 101, server_seq, tcp::ACK),
            stolen,
            now + PEER_CONFLICT_HOLD * 2,
        );
        let new_source: SocketAddr = "192.0.2.12:41000".parse().unwrap();
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &segment(new_source, destination, 200, 0, tcp::SYN),
            path(),
            now,
        );
        flow.write_all(b"still original").await.unwrap();
        let output = scope.next_output().await.unwrap();
        let retained = endpoint_return_path(&peers, &output).unwrap();
        assert_eq!(retained.mac, path().mac);
        assert_eq!(retained.vlan_tci, path().vlan_tci);
        assert!(output.packet().ends_with(b"still original"));
        assert_eq!(counters.peer_reclaimed, 1);
        output.release();
        drop(flow);
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("stray resets and new sources must not replace live TCP delivery");
}

#[tokio::test]
async fn quoted_endpoint_ptb_reaches_the_real_sender_and_keeps_sequence_checks() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for (source, destination, router) in [
            ("192.0.2.10:41000", "198.51.100.9:443", "198.51.100.1"),
            ("[2001:db8::10]:41000", "[2001:db8::9]:443", "2001:db8::1"),
        ] {
            let source: SocketAddr = source.parse().unwrap();
            let destination: SocketAddr = destination.parse().unwrap();
            let (endpoints, owner, scope, _budget, slots) = fixture().await;
            let _slots = slots
                .clone()
                .acquire_many_owned(slots.available_permits() as u32)
                .await
                .unwrap();
            let mut peers = Vec::with_capacity(PEERS);
            let mut counters = PressureCounters::default();
            receive(
                &endpoints,
                &mut peers,
                &mut counters,
                &scope,
                &segment(source, destination, 100, 0, tcp::SYN),
                path(),
                Instant::now(),
            );
            let (mut flow, _) = accept(&scope, source, destination).await;
            flow.write_all(&[0x5a; 1400]).await.unwrap();
            let sent = scope.next_output().await.unwrap();
            let original = sent.packet().to_vec();
            assert!(original.len() > 1280);
            sent.release();
            let quoted = wire::parse_ip(&original).unwrap();
            let mut forged = original.clone();
            let sent_seq = u32::from_be_bytes(
                original[quoted.payload.start + 4..quoted.payload.start + 8]
                    .try_into()
                    .unwrap(),
            );
            forged[quoted.payload.start + 4..quoted.payload.start + 8]
                .copy_from_slice(&sent_seq.wrapping_add(65536).to_be_bytes());
            let mut error = [0; 256];
            let length = wire::icmp::emit_packet_too_big(
                &mut error,
                router.parse().unwrap(),
                destination.ip(),
                1280,
                &forged,
            )
            .unwrap();
            assert!(retained_endpoint(
                &endpoints,
                scope.scope(),
                PacketView::from_slice(&error[..length])
            ));
            receive(
                &endpoints,
                &mut peers,
                &mut counters,
                &scope,
                &error[..length],
                path(),
                Instant::now(),
            );
            assert!(
                scope
                    .poll_output(&mut Context::from_waker(std::task::Waker::noop()))
                    .is_pending()
            );
            let length = wire::icmp::emit_packet_too_big(
                &mut error,
                router.parse().unwrap(),
                destination.ip(),
                1280,
                &original,
            )
            .unwrap();
            error[length - 1] ^= 1;
            assert!(!retained_endpoint(
                &endpoints,
                scope.scope(),
                PacketView::from_slice(&error[..length])
            ));
            scope.receive(&error[..length], Instant::now());
            assert!(
                scope
                    .poll_output(&mut Context::from_waker(std::task::Waker::noop()))
                    .is_pending()
            );
            error[length - 1] ^= 1;
            for split in [1, 23, length - 1] {
                let segments = [&error[..split], &error[split..length]];
                assert!(retained_endpoint(
                    &endpoints,
                    scope.scope(),
                    PacketView::new(&segments).unwrap()
                ));
            }
            receive(
                &endpoints,
                &mut peers,
                &mut counters,
                &scope,
                &error[..length],
                path(),
                Instant::now(),
            );
            let retransmit = scope.next_output().await.unwrap();
            assert!(retransmit.packet().len() <= 1280);
            let ip = wire::parse_ip(retransmit.packet()).unwrap();
            let (header, offset) = tcp::parse(&retransmit.packet()[ip.payload.clone()]).unwrap();
            assert!(tcp::verify_checksum(
                ip.src,
                ip.dst,
                &retransmit.packet()[ip.payload.clone()]
            ));
            assert_eq!(
                header.seq,
                u32::from_be_bytes(
                    original[quoted.payload.start + 4..quoted.payload.start + 8]
                        .try_into()
                        .unwrap()
                )
            );
            assert!(
                retransmit.packet()[ip.payload.start + offset..ip.payload.end]
                    .iter()
                    .all(|byte| *byte == 0x5a)
            );
            retransmit.release();
            drop(flow);
            endpoints.shutdown().await.unwrap();
            owner.run().await.unwrap();
        }
    })
    .await
    .expect("ICMP feedback must update the owning sender rather than become Core transit");
}

#[tokio::test]
async fn terminal_device_error_escapes_a_real_output_blocked_join_without_refund() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (endpoints, mut owner, scope, budget, slots) = fixture().await;
        scope.datagram_sender("198.51.100.1:53".parse().unwrap()).send_to(b"CQ owned", "192.0.2.10:41000".parse().unwrap()).await.unwrap();
        let output = scope.next_output().await.unwrap();
        endpoints.close();
        assert!(scope.next_output().await.is_none());
        assert!(futures::poll!(std::future::poll_fn(|cx| owner.poll_join_plane(cx))).is_pending());
        // Close aborts synchronously; ordinary pre-join teardown must settle before the fatal
        // path is checked against the output-blocked join.
        let mut retained = budget.used();
        loop {
            tokio::task::yield_now().await;
            let settled = budget.used();
            if settled == retained {
                break;
            }
            retained = settled;
        }
        let mut warned = false;
        let result = tokio::time::timeout(Duration::from_secs(1), join_endpoints(&mut owner,
            |_| Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "invalid CQ").into())), Instant::now(), &mut warned)).await.expect("fatal I/O must escape before the supervisor join");
        assert!(result.is_err());
        assert_eq!(budget.used(), retained);
        assert!(output.packet().ends_with(b"CQ owned"));
        assert!(endpoints.retains_source(scope.scope(), "192.0.2.10".parse().unwrap()));
        output.release();
        let (_plane, joined) = join_endpoints(&mut owner, |_| Poll::Pending, Instant::now(), &mut warned).await.unwrap().unwrap();
        joined.unwrap();
        drop((_plane, endpoints, owner, scope, slots));
        assert_eq!(budget.used(), 0);
    }).await.expect("terminal failures retain actual output, while returned outputs allow normal joined cleanup");
}

#[tokio::test]
async fn terminal_join_sleeps_until_the_actual_output_owner_returns() {
    struct Wake(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for Wake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let (endpoints, mut owner, scope, _budget, _slots) = fixture().await;
    scope
        .datagram_sender("198.51.100.1:53".parse().unwrap())
        .send_to(b"held", "192.0.2.10:41000".parse().unwrap())
        .await
        .unwrap();
    let output = scope.next_output().await.unwrap();
    endpoints.close();
    let wakes = Arc::new(Wake(Default::default()));
    let waker = std::task::Waker::from(wakes.clone());
    let mut warned = false;
    let joined = join_endpoints(&mut owner, |_| Poll::Pending, Instant::now(), &mut warned);
    tokio::pin!(joined);
    assert!(
        joined
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        wakes.0.load(Ordering::SeqCst),
        0,
        "no periodic terminal poll without a device obligation"
    );
    assert!(output.packet().ends_with(b"held"));
    output.release();
    let (_plane, result) = tokio::time::timeout(Duration::from_secs(1), joined)
        .await
        .expect("actual output release wakes the joined owner")
        .unwrap()
        .unwrap();
    result.unwrap();
}

#[tokio::test]
async fn queued_priority_is_preserved_but_exported_output_does_not_freeze_new_priority() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (endpoints, owner, scope, _budget, _slots) = fixture().await;
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = upstream.local_addr().unwrap();
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let mut peers = Vec::with_capacity(PEERS);
        let mut counters = PressureCounters::default();
        let now = Instant::now();
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &datagram(source, destination, b"first"),
            path(),
            now,
        );
        scope
            .datagram_sender(destination)
            .send_to(b"old priority", source)
            .await
            .unwrap();
        let mut priority = path();
        priority.vlan_tci[0] = 0x700c;
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &datagram(source, destination, b"next"),
            priority,
            now,
        );
        let old_output = scope.next_output().await.unwrap();
        let pending = (
            endpoint_return_path(&peers, &old_output).unwrap(),
            old_output,
        );
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &datagram(source, destination, b"current"),
            priority,
            now,
        );
        scope
            .datagram_sender(destination)
            .send_to(b"new priority", source)
            .await
            .unwrap();
        let new_output = scope.next_output().await.unwrap();
        let new_path = endpoint_return_path(&peers, &new_output).unwrap();
        let mut first = vec![0; 22 + pending.1.packet().len()];
        let mut second = vec![0; 22 + new_output.packet().len()];
        fill_output(
            &mut [&mut first],
            &return_header(pending.0, [4; 6], 2, false).unwrap(),
            pending.1.packet(),
        )
        .unwrap();
        fill_output(
            &mut [&mut second],
            &return_header(new_path, [4; 6], 2, false).unwrap(),
            new_output.packet(),
        )
        .unwrap();
        assert_eq!(&first[14..16], &path().vlan_tci[0].to_be_bytes());
        assert_eq!(&second[14..16], &priority.vlan_tci[0].to_be_bytes());
        assert!(first.ends_with(b"old priority"));
        assert!(second.ends_with(b"new priority"));
        drop((pending, new_output));
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("a retained output keeps its own complete TCI while later replies can change QoS");
}

#[tokio::test]
async fn full_live_peer_table_refuses_then_recovers_after_actual_tcp_retirement() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let budget = MemoryBudget::new(MEMORY);
        let mut pairs = Vec::new();
        for _ in 0..4 {
            let mut config = honk_netstack::Config::new([91; 32]);
            config.mode = honk_netstack::Mode::Transparent {
                exclude: Default::default(),
            };
            config.max_flows = 1024;
            config.memory_limit = MEMORY / 8;
            config.tcp_rcv_buf_max = 4096;
            pairs.push(
                PacketScope::new(
                    config,
                    Arc::clone(&budget),
                    RuntimeLimits {
                        max_slots: 1024,
                        control_frames: 2,
                        bulk_frames: 2,
                        max_waiters: 8,
                    },
                    Instant::now(),
                )
                .unwrap(),
            );
        }
        let scopes: Vec<_> = pairs.iter().map(|(scope, _)| scope.clone()).collect();
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
        config.global.preconnect_node_count = 0;
        config.global.udp_warm_node_count = 0;
        let plane = crate::control::tests::support::control_plane(config);
        let slots = crate::control::tests::support::tcp_slots(&plane);
        let (endpoints, owner) = PacketEndpoints::new(plane, pairs, 1).await.unwrap();
        let _slots = slots
            .clone()
            .acquire_many_owned(slots.available_permits() as u32)
            .await
            .unwrap();
        let mut peers = Vec::with_capacity(PEERS);
        let mut counters = PressureCounters::default();
        let now = Instant::now();
        let destination: SocketAddr = "127.0.0.1:9".parse().unwrap();
        for scope in &scopes {
            for index in 0..1024 {
                let source =
                    SocketAddr::new(std::net::Ipv4Addr::from(0xc000_0201 + index).into(), 41000);
                receive(
                    &endpoints,
                    &mut peers,
                    &mut counters,
                    scope,
                    &segment(source, destination, 100, 0, tcp::SYN),
                    path(),
                    now,
                );
            }
            assert_eq!(scope.stats().unwrap().half_open, 1024);
        }
        let newcomer: SocketAddr = "203.0.113.254:41000".parse().unwrap();
        let syn = segment(newcomer, destination, 200, 0, tcp::SYN);
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scopes[0],
            &syn,
            path(),
            now,
        );
        assert_eq!(counters.peer_full, 1);
        assert_eq!(counters.peer_reclaimed, 0);
        assert!(!endpoints.retains(scopes[0].scope(), newcomer, destination, 6));
        let mut pressure = Pressure::new(now);
        pressure.counters = counters;
        pressure.sample(now + Duration::from_secs(1), None, 0, 0, peers.len(), &[]);
        assert!(pressure.active);
        counters.refused = false;
        let (syn, mut flow) = scopes[0].poll_accept().unwrap();
        flow.abort();
        drop(flow);
        assert!(!endpoints.retains_source(scopes[0].scope(), syn.client.ip()));
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scopes[0],
            &segment(newcomer, destination, 200, 0, tcp::SYN),
            path(),
            now,
        );
        assert_eq!(counters.peer_reclaimed, 1);
        assert!(endpoints.retains(scopes[0].scope(), newcomer, destination, 6));
        assert_eq!(scopes[0].stats().unwrap().half_open, 1024);
        pressure.counters = counters;
        pressure.sample(now + Duration::from_secs(2), None, 0, 0, peers.len(), &[]);
        assert!(
            !pressure.active,
            "successful reclamation is not a resource refusal"
        );
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("the fixed peer ceiling must refuse live-owner eviction and recover after quiescence");
}

#[tokio::test]
async fn live_reset_accepts_qos_only_changes_without_relearning_the_reply_path() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (endpoints, owner, scope, _budget, slots) = fixture().await;
        let _slots = slots
            .clone()
            .acquire_many_owned(slots.available_permits() as u32)
            .await
            .unwrap();
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.9:443".parse().unwrap();
        let now = Instant::now();
        let mut peers = Vec::with_capacity(PEERS);
        let mut counters = PressureCounters::default();
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &segment(source, destination, 100, 0, tcp::SYN),
            path(),
            now,
        );
        let (mut flow, seq) = accept(&scope, source, destination).await;
        let reset = segment(source, destination, 101, seq, tcp::RST | tcp::ACK);
        let mut wrong = path();
        wrong.mac[5] ^= 2;
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &reset,
            wrong,
            now + Duration::from_secs(1),
        );
        let mut qos = path();
        qos.vlan_tci[0] = 0x700c;
        qos.vlan_tci[1] |= 0xf000;
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &reset,
            qos,
            now + Duration::from_secs(2),
        );
        assert_eq!(
            flow.read(&mut [0; 1]).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(peers[0].last_seen, now);
        scope
            .datagram_sender(destination)
            .send_to(b"unchanged identity", source)
            .await
            .unwrap();
        let output = scope.next_output().await.unwrap();
        let selected = endpoint_return_path(&peers, &output).unwrap();
        let header = return_header(selected, [4; 6], 2, false).unwrap();
        assert_eq!(&header[14..16], &path().vlan_tci[0].to_be_bytes());
        assert_eq!(&header[18..20], &path().vlan_tci[1].to_be_bytes());
        assert!(output.packet().ends_with(b"unchanged identity"));
        output.release();
        drop(flow);
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("valid TCP resets use peer identity rather than VLAN QoS equality");
}

#[tokio::test]
async fn peer_capacity_cannot_erase_an_unexpired_conflict_hold() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (endpoints, owner, scope, _budget, slots) = fixture().await;
        let _slots = slots
            .clone()
            .acquire_many_owned(slots.available_permits() as u32)
            .await
            .unwrap();
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let newcomer: SocketAddr = "192.0.2.11:41000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.9:443".parse().unwrap();
        let now = Instant::now();
        let mut peers = Vec::with_capacity(PEERS);
        let mut counters = PressureCounters::default();
        let syn = segment(source, destination, 100, 0, tcp::SYN);
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &syn,
            path(),
            now,
        );
        let (_, mut first) = scope.poll_accept().unwrap();
        first.abort();
        drop(first);
        assert!(!endpoints.retains_source(scope.scope(), source.ip()));
        fill_quiescent(&mut peers, scope.scope(), now);
        let mut changed = path();
        changed.mac[5] ^= 2;
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &syn,
            changed,
            now + Duration::from_secs(1),
        );
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &segment(newcomer, destination, 200, 0, tcp::SYN),
            path(),
            now + Duration::from_secs(2),
        );
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &syn,
            changed,
            now + Duration::from_secs(3),
        );
        assert!(!endpoints.retains(scope.scope(), source, destination, wire::PROTO_TCP));
        let reopen = now + Duration::from_secs(3) + PEER_CONFLICT_HOLD;
        let after_hold: SocketAddr = "192.0.2.12:41000".parse().unwrap();
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &segment(after_hold, destination, 300, 0, tcp::SYN),
            path(),
            reopen,
        );
        assert!(
            !peers.iter().any(|peer| peer.address == source.ip()),
            "expired quiescent conflict becomes LRU-eligible"
        );
        receive(
            &endpoints,
            &mut peers,
            &mut counters,
            &scope,
            &syn,
            changed,
            reopen,
        );
        let mut accepted = None;
        while let Some((syn, mut flow)) = scope.poll_accept() {
            if syn.client == source {
                accepted = Some(flow);
            } else {
                flow.abort();
            }
        }
        assert!(accepted.is_some());
        scope.drive(reopen);
        let output = scope.next_output().await.unwrap();
        let selected = endpoint_return_path(&peers, &output).unwrap();
        assert_eq!(selected.mac, changed.mac);
        let ip = wire::parse_ip(output.packet()).unwrap();
        assert_eq!(ip.dst, source.ip());
        let (header, _) = tcp::parse(&output.packet()[ip.payload]).unwrap();
        assert_eq!(header.flags & (tcp::SYN | tcp::ACK), tcp::SYN | tcp::ACK);
        output.release();
        drop(accepted);
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("peer-table churn must preserve the conflict hold until its real deadline");
}

#[test]
fn transmit_finalization_preserves_primary_failure_and_terminal_kick() {
    for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::InvalidData] {
        let work = io::Error::new(kind, "packet work failed");
        let error = finish_transmit::<()>(
            Err(work.into()),
            Err(io::Error::from_raw_os_error(libc::EBADF)),
        )
        .unwrap_err();
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            kind
        );
        let evidence = format!("{error:#}");
        assert!(evidence.contains("packet work failed"));
        assert!(evidence.contains(&io::Error::from_raw_os_error(libc::EBADF).to_string()));
    }
    let error =
        finish_transmit::<()>(Ok(()), Err(io::Error::from_raw_os_error(libc::EBADF))).unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(libc::EBADF)
    );
    let error = finish_transmit::<()>(
        Err(io::Error::from_raw_os_error(libc::EINVAL).into()),
        Ok(()),
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(libc::EINVAL)
    );
    assert_eq!(finish_transmit(Ok(7), Ok(())).unwrap(), 7);
}

#[tokio::test]
async fn endpoint_realms_keep_each_output_on_its_actual_device_and_vlan_path() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixtures = Vec::new();
        for _ in 0..2 {
            let (scope, owner, _budget, plane, _slots) = fixture_parts();
            fixtures.push((scope.clone(), driven(scope, owner, plane).await));
        }
        for (device, (scope, (endpoints, owner, driver))) in fixtures.into_iter().enumerate() {
            let mut reply_path = path();
            reply_path.device = device;
            reply_path.mac[5] += device as u8;
            reply_path.vlan_tci[0] += device as u16;
            let ifindex = device as u32 + 10;
            let mut realm = Realm {
                ingress: Ingress {
                    scope: scope.scope(),
                    namespace: 1,
                    ifindex,
                    attachment: 1,
                    mark: MarkProvenance::BeforeSkb,
                },
                device,
                link: LogicalLink {
                    ifindex,
                    mtu: 1500,
                    mac: [4 + device as u8; 6],
                    path: LinkPath {
                        physical_ifindex: ifindex,
                        vlan_tci: reply_path.vlan_tci,
                        vlan_proto: reply_path.vlan_proto,
                        vlan_count: reply_path.vlan_count,
                    },
                },
                driver,
                generated: Some((22, 1522)),
                pending: [None, None],
            };
            let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
            let destination: SocketAddr = "198.51.100.1:443".parse().unwrap();
            let now = Instant::now();
            let mut cx = Context::from_waker(std::task::Waker::noop());
            scope.receive(&segment(source, destination, 100, 0, tcp::SYN), now);
            let (_, flow) = scope.poll_accept().unwrap();
            // The device's driver, not a separate owner task, materializes the SYN-ACK.
            assert!(!realm.driver.service(&mut cx, now));
            scope
                .datagram_sender(destination)
                .send_to(b"lone final reply", source)
                .await
                .unwrap();
            let peers = [Peer {
                scope: realm.driver.scope(),
                address: source.ip(),
                path: reply_path,
                last_seen: now,
                conflict: None,
            }];
            for class in [TxClass::Control, TxClass::Bulk] {
                let mut outputs = [None, None];
                let (selected, pending_path) = realm.poll_outputs(&mut cx, class, 2, &mut outputs);
                assert_eq!(selected, Poll::Ready(Some(1)));
                assert!(pending_path.is_none());
                let output = outputs[0].take().expect("actual Endpoint output");
                assert!(outputs[1].is_none());
                assert_eq!(output.class(), class);
                let selected = endpoint_return_path(&peers, &output).unwrap();
                let header = realm.output_header(selected, ifindex, false).unwrap();
                assert_eq!(&header[..6], &reply_path.mac);
                assert_eq!(&header[6..12], &realm.link.mac);
                assert_eq!(&header[14..16], &reply_path.vlan_tci[0].to_be_bytes());
                assert_eq!(&header[18..20], &reply_path.vlan_tci[1].to_be_bytes());
                let mut wrong = selected;
                wrong.device = 1 - device;
                assert!(realm.output_header(wrong, ifindex, false).is_err());
                if class == TxClass::Bulk {
                    assert!(output.packet().ends_with(b"lone final reply"));
                }
                output.release();
            }
            drop(flow);
            join_driven(endpoints, owner, &mut realm.driver).await;
        }
    })
    .await
    .expect("each real scoped output must retain its own physical reply path");
}

#[tokio::test]
async fn realm_capacity_fallback_and_pending_head_never_export_a_suffix() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (scope, owner, _budget, plane, _slots) = fixture_parts();
        let (endpoints, owner, driver) = driven(scope.clone(), owner, plane).await;
        let reply_path = path();
        let mut realm = Realm {
            ingress: Ingress {
                scope: scope.scope(),
                namespace: 1,
                ifindex: 10,
                attachment: 1,
                mark: MarkProvenance::BeforeSkb,
            },
            device: 0,
            link: LogicalLink {
                ifindex: 10,
                mtu: 1500,
                mac: [4; 6],
                path: LinkPath {
                    physical_ifindex: 10,
                    vlan_tci: reply_path.vlan_tci,
                    vlan_proto: reply_path.vlan_proto,
                    vlan_count: reply_path.vlan_count,
                },
            },
            driver,
            generated: Some((22, 1522)),
            pending: [None, None],
        };
        let destination: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let sender = scope.datagram_sender("198.51.100.1:443".parse().unwrap());
        for payload in [b"A", b"B"] {
            sender.send_to(payload, destination).await.unwrap();
        }
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut outputs = [None, None];
        let (selected, saved) = realm.poll_outputs(&mut cx, TxClass::Bulk, 1, &mut outputs);
        assert_eq!(selected, Poll::Ready(Some(1)));
        assert!(saved.is_none() && outputs[1].is_none());
        let first = outputs[0].take().unwrap();
        assert!(first.packet().ends_with(b"A"));
        first.release();
        sender.send_to(b"C", destination).await.unwrap();

        let (selected, saved) = realm.poll_outputs(&mut cx, TxClass::Bulk, 0, &mut outputs);
        assert_eq!(selected, Poll::Ready(Some(1)));
        assert!(saved.is_none() && outputs[1].is_none());
        let pending = outputs[0].take().unwrap();
        assert!(pending.packet().ends_with(b"B"));
        realm.pending[1] = Some((pending, reply_path));
        for _ in 0..2 {
            let (selected, saved) = realm.poll_outputs(&mut cx, TxClass::Bulk, BATCH, &mut outputs);
            assert_eq!(selected, Poll::Ready(Some(1)));
            assert!(outputs[1].is_none());
            let saved = saved.expect("pending output keeps its captured return path");
            assert_eq!(saved.mac, reply_path.mac);
            assert_eq!(saved.vlan_tci, reply_path.vlan_tci);
            assert_eq!(saved.vlan_proto, reply_path.vlan_proto);
            assert_eq!(saved.vlan_count, reply_path.vlan_count);
            let pending = outputs[0].take().unwrap();
            assert!(pending.packet().ends_with(b"B"));
            realm.pending[1] = Some((pending, saved));
        }
        realm.pending[1].take().unwrap().0.release();
        sender.send_to(b"D", destination).await.unwrap();
        let (selected, saved) = realm.poll_outputs(&mut cx, TxClass::Bulk, BATCH, &mut outputs);
        assert_eq!(selected, Poll::Ready(Some(2)));
        assert!(saved.is_none());
        for (output, payload) in outputs.iter().zip([b"C", b"D"]) {
            assert!(output.as_ref().unwrap().packet().ends_with(payload));
        }
        let mut completed =
            outputs.map(|output| output.map(|output| Retained::Endpoint(output.into_owner())));
        release_completed(&mut completed.each_mut().map(Option::as_mut));
        drop(completed);
        drop(sender);
        join_driven(endpoints, owner, &mut realm.driver).await;
    })
    .await
    .expect("bounded selection must retain only its one blocked head");
}

#[tokio::test]
async fn held_policy_publication_never_suspends_the_driven_scope_timer_owner() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (scope, owner, _budget, plane, _slots) = fixture_parts();
        let authority = plane
            .core_forward_policy(Execution::MixedEndpoints)
            .await
            .unwrap();
        let config = plane.config_handle();
        let shutdown = plane.shutdown_intent();
        let (endpoints, mut owner, mut driver) = driven(scope.clone(), owner, plane).await;
        let source: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.1:443".parse().unwrap();
        scope.receive(
            &segment(source, destination, 100, 0, tcp::SYN),
            Instant::now(),
        );
        let (_, flow) = scope.poll_accept().unwrap();
        // A reload holds publication while Core resolution is due; no further RX arrives.
        let publication = config.write().await;
        let reader = Some(authority.read_policy());
        tokio::pin!(reader);
        let timer = None;
        tokio::pin!(timer);
        let mut synacks = Vec::new();
        while synacks.len() < 2 {
            let turned = turn(
                reader.as_mut(),
                |cx| owner.poll_join_plane(cx),
                |cx, reading| {
                    assert!(reading);
                    let now = Instant::now();
                    driver.service(cx, now);
                    let mut outputs = [None];
                    if driver.poll_outputs_class(cx, TxClass::Control, &mut outputs)
                        == Poll::Ready(Some(1))
                    {
                        let output = outputs[0].take().unwrap();
                        let ip = wire::parse_ip(output.packet()).unwrap();
                        let (header, _) = tcp::parse(&output.packet()[ip.payload]).unwrap();
                        assert_eq!(header.flags, tcp::SYN | tcp::ACK);
                        synacks.push(header.seq);
                        return Poll::Ready(Ok(()));
                    }
                    poll_deadline(timer.as_mut(), driver.deadline(), now, cx).map(Ok)
                },
                &shutdown,
            )
            .await;
            assert!(matches!(turned, Turn::Serviced(Ok(()))));
        }
        assert_eq!(
            synacks[0], synacks[1],
            "the protocol deadline retransmitted the SYN-ACK"
        );
        drop(publication);
        loop {
            let turned = turn(
                reader.as_mut(),
                |cx| owner.poll_join_plane(cx),
                |cx, _| {
                    driver.service(cx, Instant::now());
                    Poll::Pending
                },
                &shutdown,
            )
            .await;
            if let Turn::Read(read) = turned {
                drop(read);
                break;
            }
        }
        assert!(
            reader.is_none(),
            "the pinned acquisition completed instead of restarting"
        );
        drop(flow);
        join_driven(endpoints, owner, &mut driver).await;
    })
    .await
    .expect("a pending policy reader must sit beside the sole scope timer owner");
}

#[tokio::test]
async fn generated_tcp_wire_matrix_freezes_qos_and_uses_full_eligible_extent() {
    for (client, server) in [
        ("192.0.2.10:41000", "198.51.100.9:443"),
        ("[2001:db8::10]:41000", "[2001:db8::9]:443"),
    ] {
        let client: SocketAddr = client.parse().unwrap();
        let server: SocketAddr = server.parse().unwrap();
        for tags in 0..=2 {
            let mut reply = path();
            reply.vlan_count = tags;
            for tag in usize::from(tags)..2 {
                reply.vlan_tci[tag] = 0;
                reply.vlan_proto[tag] = 0;
            }
            let l2 = 14 + 4 * usize::from(tags);
            for mtu in [1280, honk_xsk::FRAME_SIZE - l2] {
                let (scope, owner, _budget, plane, _slots) = fixture_parts_mtu(mtu);
                let (endpoints, owner, driver) = driven(scope.clone(), owner, plane).await;
                let mut realm = output_realm(driver, reply, mtu);
                assert_eq!(realm.generated, Some((l2, l2 + mtu)));
                let now = Instant::now();
                let mut peers = [output_peer(&scope, client, reply, now)];
                scope.receive(
                    &segment_mss(client, server, 100, 0, tcp::SYN, u16::MAX),
                    now,
                );
                let (_, mut flow) = scope.poll_accept().unwrap();
                realm.driver.begin_turn(now);
                let (synack, syn_owner) = generate(&mut realm, now, TxClass::Control, &peers);
                let (syn, payload) = check_tcp_frame(&synack, reply, server, client);
                assert_eq!(syn.flags, tcp::SYN | tcp::ACK);
                assert_eq!(syn.ack, 101);
                assert!(payload.is_empty());
                drop(syn_owner);
                let mut cx = Context::from_waker(std::task::Waker::noop());
                realm.driver.finish_turn(&mut cx, now);
                assert!(realm.driver.deadline().is_some_and(|due| due > now));
                scope.receive(
                    &segment(client, server, 101, syn.seq.wrapping_add(1), tcp::ACK),
                    now,
                );

                let payload = vec![0x5a; mtu - wire::ip_header_len(client.is_ipv6()) - 20];
                flow.write_all(&payload).await.unwrap();
                let (first, first_owner) = generate(&mut realm, now, TxClass::Bulk, &peers);
                let (header, bytes) = check_tcp_frame(&first, reply, server, client);
                assert_eq!(bytes, payload);
                assert_eq!(first.len(), l2 + mtu);
                assert_eq!(header.seq, syn.seq.wrapping_add(1));
                let next_seq = header.seq.wrapping_add(payload.len() as u32);
                scope.receive(&segment(client, server, 101, next_seq, tcp::ACK), now);
                for tag in 0..usize::from(tags) {
                    peers[0].path.vlan_tci[tag] ^= 0xf000;
                }
                flow.write_all(b"new snapshot").await.unwrap();
                let later = now + Duration::from_millis(50);
                realm.driver.begin_turn(later);
                let (second, second_owner) = generate(&mut realm, later, TxClass::Bulk, &peers);
                let (header, bytes) = check_tcp_frame(&second, peers[0].path, server, client);
                assert_eq!(header.seq, next_seq);
                assert_eq!(bytes, b"new snapshot");
                let mut completed = [Some(first_owner), Some(second_owner)];
                release_completed(&mut completed.each_mut().map(Option::as_mut));
                drop(completed);

                flow.abort();
                drop(flow);
                realm.driver.begin_turn(later);
                let (reset, reset_owner) = generate(&mut realm, later, TxClass::Control, &peers);
                let (header, bytes) = check_tcp_frame(&reset, peers[0].path, server, client);
                assert_ne!(header.flags & tcp::RST, 0);
                assert!(bytes.is_empty());
                assert_eq!(reset.len(), l2 + wire::ip_header_len(client.is_ipv6()) + 20);
                if client.is_ipv4() && tags == 0 {
                    assert_eq!(
                        reset.len(),
                        54,
                        "Port pads this actual extent to 60, not the maximum"
                    );
                }
                drop(reset_owner);
                realm.driver.finish_turn(&mut cx, later);
                join_driven(endpoints, owner, &mut realm.driver).await;
            }
        }
    }
}

#[tokio::test]
async fn generated_fragments_follow_atomic_cpu_and_saved_heads_for_both_families() {
    for (client, server) in [
        ("192.0.2.10:41000", "198.51.100.9:53"),
        ("[2001:db8::10]:41000", "[2001:db8::9]:53"),
    ] {
        let client: SocketAddr = client.parse().unwrap();
        let server: SocketAddr = server.parse().unwrap();
        let (scope, owner, _budget, plane, _slots) = fixture_parts();
        let (endpoints, owner, driver) = driven(scope.clone(), owner, plane).await;
        let mut realm = output_realm(driver, path(), 1500);
        let now = Instant::now();
        let peers = [output_peer(&scope, client, path(), now)];
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut outputs = [None];
        assert!(
            realm
                .poll_outputs(&mut cx, TxClass::Bulk, 1, &mut outputs)
                .0
                .is_pending()
        );
        let sender = scope.datagram_sender(server);
        let payload = vec![0x69; 3500];
        // The app accepts fragment zero after the outer CPU-empty observation.
        sender.send_to(&payload, client).await.unwrap();
        let mut frame = vec![0xa5; realm.generated.unwrap().1];
        let mut emitted = false;
        assert!(
            realm
                .generate_output(now, TxClass::Bulk, 10, &peers, &mut frame, &mut emitted)
                .unwrap()
                .is_none()
        );
        assert!(!emitted);
        assert_eq!(
            realm
                .poll_outputs(&mut cx, TxClass::Bulk, 0, &mut outputs)
                .0,
            Poll::Ready(Some(1))
        );
        let first = outputs[0].take().unwrap();
        let (id, offset, more, bytes) = fragment_bytes(first.packet());
        assert_eq!(offset, 0);
        assert!(more);
        let mut datagram = bytes.to_vec();
        realm.pending[1] = Some((first, path()));
        for _ in 0..2 {
            assert!(
                realm
                    .generate_output(now, TxClass::Bulk, 10, &peers, &mut frame, &mut emitted)
                    .unwrap()
                    .is_none()
            );
            assert!(!emitted, "a saved CPU head blocks direct generation");
        }
        let (selected, saved) = realm.poll_outputs(&mut cx, TxClass::Bulk, 1, &mut outputs);
        assert_eq!(selected, Poll::Ready(Some(1)));
        let first = outputs[0].take().unwrap();
        let header = realm
            .output_header(saved.unwrap(), 10, client.is_ipv6())
            .unwrap();
        let mut first_wire = vec![0; header.len() + first.packet().len()];
        fill_output(&mut [&mut first_wire], &header, first.packet()).unwrap();
        assert_eq!(fragment_bytes(&first_wire[22..]).1, 0);
        let mut completed = [Some(Retained::Endpoint(first.into_owner()))];
        loop {
            let (wire, owner) = generate(&mut realm, now, TxClass::Bulk, &peers);
            assert_eq!(
                wire::packet_addresses(&wire[22..]).unwrap(),
                (server.ip(), client.ip())
            );
            let (next_id, offset, more, bytes) = fragment_bytes(&wire[22..]);
            assert_eq!(next_id, id);
            assert_eq!(offset, datagram.len());
            datagram.extend_from_slice(bytes);
            drop(owner);
            if !more {
                break;
            }
        }
        assert_eq!(&datagram[8..], payload);
        assert!(wire::udp::verify_checksum(
            server.ip(),
            client.ip(),
            &datagram
        ));
        release_completed(&mut completed.each_mut().map(Option::as_mut));
        drop(completed);
        for payload in [b"".as_slice(), b"ordinary CPU reply".as_slice()] {
            sender.send_to(payload, client).await.unwrap();
            emitted = false;
            assert!(
                realm
                    .generate_output(now, TxClass::Bulk, 10, &peers, &mut frame, &mut emitted)
                    .unwrap()
                    .is_none()
            );
            assert!(!emitted);
            assert_eq!(
                realm
                    .poll_outputs(&mut cx, TxClass::Bulk, 1, &mut outputs)
                    .0,
                Poll::Ready(Some(1))
            );
            let output = outputs[0].take().unwrap();
            let ip = wire::parse_ip(output.packet()).unwrap();
            let udp = &output.packet()[ip.payload];
            let (src, dst, data) = wire::udp::parse(udp).unwrap();
            assert_eq!((src, dst), (server.port(), client.port()));
            assert_eq!(&udp[data], payload);
            assert!(wire::udp::verify_checksum(ip.src, ip.dst, udp));
            output.release();
        }
        realm.driver.finish_turn(&mut cx, now);
        drop(sender);
        join_driven(endpoints, owner, &mut realm.driver).await;
    }
}

#[tokio::test]
async fn generated_local_disposal_and_header_errors_retire_unlocked_and_refresh_deadlines() {
    for failure in 0..7 {
        let (scope, owner, _budget, plane, _slots) = fixture_parts();
        let (endpoints, owner, driver) = driven(scope.clone(), owner, plane).await;
        let mut realm = output_realm(driver, path(), 1500);
        let client: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let server: SocketAddr = "198.51.100.9:443".parse().unwrap();
        let now = Instant::now();
        let mut peers = vec![output_peer(&scope, client, path(), now)];
        scope.receive(&segment(client, server, 100, 0, tcp::SYN), now);
        let (_, mut flow) = scope.poll_accept().unwrap();
        let (synack, syn_owner) = generate(&mut realm, now, TxClass::Control, &peers);
        let (syn, _) = check_tcp_frame(&synack, path(), server, client);
        drop(syn_owner);
        scope.receive(
            &segment(client, server, 101, syn.seq.wrapping_add(1), tcp::ACK),
            now,
        );
        let retired = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = retired.clone();
        let callback_scope = scope.clone();
        flow.set_retirement_callback(move || {
            let _ = callback_scope.stats();
            observed.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        flow.abort();
        drop(flow);
        assert_eq!(retired.load(Ordering::SeqCst), 0);
        let mut physical_ifindex = 10;
        match failure {
            0 => peers.clear(),
            1 => peers[0].conflict = Some(now),
            2 => peers[0].path.device = 1,
            3 => physical_ifindex = 11,
            4 => peers[0].path.vlan_tci[0] ^= 1,
            5 => peers[0].path.vlan_proto[0] = 0x0800,
            6 => realm.generated = Some((26, 1526)),
            _ => unreachable!(),
        }
        let mut frame = vec![0xa5; realm.generated.unwrap().1];
        let mut emitted = false;
        realm.driver.begin_turn(now);
        let result = realm.generate_output(
            now,
            TxClass::Control,
            physical_ifindex,
            &peers,
            &mut frame,
            &mut emitted,
        );
        assert!(
            emitted,
            "an emitted-but-disposed packet spends the bounded work budget"
        );
        if failure < 2 {
            assert!(result.unwrap().is_none());
        } else {
            assert!(result.is_err());
        }
        assert_eq!(
            retired.load(Ordering::SeqCst),
            1,
            "local disposal returns the original owner outside its lock"
        );
        let mut cx = Context::from_waker(std::task::Waker::noop());
        realm.driver.finish_turn(&mut cx, now);
        assert!(!endpoints.retains(scope.scope(), client, server, 6));
        assert!(scope.is_protocol_quiescent());
        let deadline = realm.driver.deadline();
        emitted = false;
        assert!(
            realm
                .generate_output(
                    now,
                    TxClass::Control,
                    physical_ifindex,
                    &peers,
                    &mut frame,
                    &mut emitted
                )
                .unwrap()
                .is_none()
        );
        assert!(!emitted);
        realm.driver.finish_turn(&mut cx, now);
        assert_eq!(realm.driver.deadline(), deadline);
        assert_eq!(retired.load(Ordering::SeqCst), 1);
        join_driven(endpoints, owner, &mut realm.driver).await;
    }
}

#[tokio::test]
async fn generated_missing_peer_synack_keeps_its_real_retransmission_deadline() {
    let (scope, owner, _budget, plane, _slots) = fixture_parts();
    let (endpoints, owner, driver) = driven(scope.clone(), owner, plane).await;
    let mut realm = output_realm(driver, path(), 1500);
    let client: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let server: SocketAddr = "198.51.100.9:443".parse().unwrap();
    let now = Instant::now();
    scope.receive(&segment(client, server, 100, 0, tcp::SYN), now);
    let (_, flow) = scope.poll_accept().unwrap();
    realm.driver.begin_turn(now);
    let mut frame = vec![0; realm.generated.unwrap().1];
    let mut emitted = false;
    assert!(
        realm
            .generate_output(now, TxClass::Control, 10, &[], &mut frame, &mut emitted)
            .unwrap()
            .is_none()
    );
    assert!(emitted);
    let ip = wire::parse_ip(&frame[22..]).unwrap();
    let (original, _) = tcp::parse(&frame[22 + ip.payload.start..22 + ip.payload.end]).unwrap();
    let original_seq = original.seq;
    let mut cx = Context::from_waker(std::task::Waker::noop());
    realm.driver.finish_turn(&mut cx, now);
    let due = realm
        .driver
        .deadline()
        .expect("disposed SYNACK still arms the actual protocol timer");
    assert!(due > now);
    emitted = false;
    assert!(
        realm
            .generate_output(now, TxClass::Control, 10, &[], &mut frame, &mut emitted)
            .unwrap()
            .is_none()
    );
    assert!(!emitted);
    realm.driver.finish_turn(&mut cx, now);
    assert_eq!(realm.driver.deadline(), Some(due));
    realm.driver.begin_turn(due);
    let peers = [output_peer(&scope, client, path(), due)];
    let (retry, retained) = generate(&mut realm, due, TxClass::Control, &peers);
    assert_eq!(
        check_tcp_frame(&retry, path(), server, client).0.seq,
        original_seq
    );
    drop(retained);
    realm.driver.finish_turn(&mut cx, due);
    drop(flow);
    join_driven(endpoints, owner, &mut realm.driver).await;
}

#[tokio::test]
async fn mixed_cpu_direct_completion_releases_exact_scopes_through_reuse_close_and_callback_panic()
{
    for panic_callback in [false, true] {
        let client: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let server: SocketAddr = "198.51.100.9:443".parse().unwrap();
        let now = Instant::now();
        let mut fixtures = Vec::new();
        let mut completed = Vec::new();
        let mut original_ids = Vec::new();
        for index in 0..2 {
            let (scope, owner, _budget, plane, _slots) = fixture_parts();
            let (endpoints, owner, driver) = driven(scope.clone(), owner, plane).await;
            let mut realm = output_realm(driver, path(), 1500);
            let peers = [output_peer(&scope, client, path(), now)];
            scope.receive(&segment(client, server, 100, 0, tcp::SYN), now);
            let (_, mut flow) = scope.poll_accept().unwrap();
            original_ids.push(flow.flow_id());
            let (synack, syn_owner) = generate(&mut realm, now, TxClass::Control, &peers);
            let (syn, _) = check_tcp_frame(&synack, path(), server, client);
            drop(syn_owner);
            scope.receive(
                &segment(client, server, 101, syn.seq.wrapping_add(1), tcp::ACK),
                now,
            );
            let retired = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = retired.clone();
            let callback_scope = scope.clone();
            flow.set_retirement_callback(move || {
                let _ = callback_scope.stats();
                observed.fetch_add(1, Ordering::SeqCst);
                assert!(
                    !(panic_callback && index == 0),
                    "injected retirement callback panic"
                );
            })
            .unwrap();
            flow.write_all(b"original retained bytes").await.unwrap();
            let held = if index == 0 {
                generate(&mut realm, now, TxClass::Bulk, &peers).1
            } else {
                let mut cx = Context::from_waker(std::task::Waker::noop());
                realm.driver.service(&mut cx, now);
                let mut outputs = [None];
                assert_eq!(
                    realm
                        .poll_outputs(&mut cx, TxClass::Bulk, 1, &mut outputs)
                        .0,
                    Poll::Ready(Some(1))
                );
                let output = outputs[0].take().unwrap();
                assert_eq!(output.flow_id(), Some(flow.flow_id()));
                assert!(output.packet().ends_with(b"original retained bytes"));
                Retained::Endpoint(output.into_owner())
            };
            completed.push(Some(held));
            flow.abort();
            drop(flow);
            completed.push(Some(generate(&mut realm, now, TxClass::Control, &peers).1));
            assert_eq!(retired.load(Ordering::SeqCst), 0);
            scope.receive(&segment(client, server, 900, 0, tcp::SYN), now);
            let (_, new_flow) = scope.poll_accept().unwrap();
            assert_ne!(new_flow.flow_id(), original_ids[index]);
            let (synack, syn_owner) = generate(&mut realm, now, TxClass::Control, &peers);
            let (syn, _) = check_tcp_frame(&synack, path(), server, client);
            drop(syn_owner);
            scope.receive(
                &segment(client, server, 901, syn.seq.wrapping_add(1), tcp::ACK),
                now,
            );
            fixtures.push((scope, endpoints, owner, realm, new_flow, retired));
        }
        assert_eq!(
            original_ids[0], original_ids[1],
            "FlowIds are local, not completion scope keys"
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut owners: Vec<_> = completed.iter_mut().map(Option::as_mut).collect();
            release_completed(&mut owners);
        }));
        assert_eq!(result.is_err(), panic_callback);
        drop(completed);
        for (scope, endpoints, mut owner, mut realm, mut flow, retired) in fixtures {
            assert_eq!(retired.load(Ordering::SeqCst), 1);
            assert!(endpoints.retains(scope.scope(), client, server, 6));
            let peers = [output_peer(&scope, client, path(), now)];
            flow.write_all(b"new incarnation").await.unwrap();
            let (frame, held) = generate(&mut realm, now, TxClass::Bulk, &peers);
            assert_eq!(
                check_tcp_frame(&frame, path(), server, client).1,
                b"new incarnation"
            );
            endpoints.close();
            drop(flow);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            realm.driver.finish_turn(&mut cx, now);
            assert!(owner.poll_join_plane(&mut cx).is_pending());
            assert!(endpoints.retains_source(scope.scope(), client.ip()));
            let mut final_completion = [Some(held)];
            release_completed(&mut final_completion.each_mut().map(Option::as_mut));
            drop(final_completion);
            join_driven(endpoints, owner, &mut realm.driver).await;
            assert_eq!(retired.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn just_over_generated_limit_keeps_full_cpu_tcp_extent_and_sg_writer() {
    for (client, server) in [
        ("192.0.2.10:41000", "198.51.100.9:443"),
        ("[2001:db8::10]:41000", "[2001:db8::9]:443"),
    ] {
        let client: SocketAddr = client.parse().unwrap();
        let server: SocketAddr = server.parse().unwrap();
        for tags in 0..=2 {
            let mut reply = path();
            reply.vlan_count = tags;
            for tag in usize::from(tags)..2 {
                reply.vlan_tci[tag] = 0;
                reply.vlan_proto[tag] = 0;
            }
            let l2 = 14 + 4 * usize::from(tags);
            let mtu = honk_xsk::FRAME_SIZE + 1 - l2;
            let (scope, owner, _budget, plane, _slots) = fixture_parts_mtu(mtu);
            let (endpoints, owner, driver) = driven(scope.clone(), owner, plane).await;
            let mut realm = output_realm(driver, reply, mtu);
            assert!(realm.generated.is_none());
            let now = Instant::now();
            let peers = [output_peer(&scope, client, reply, now)];
            scope.receive(
                &segment_mss(client, server, 100, 0, tcp::SYN, u16::MAX),
                now,
            );
            let (_, mut flow) = scope.poll_accept().unwrap();
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let mut outputs = [None];
            let mut frame = [0xa5; honk_xsk::FRAME_SIZE];
            let mut emitted = false;
            assert!(
                realm
                    .generate_output(now, TxClass::Control, 10, &peers, &mut frame, &mut emitted)
                    .unwrap()
                    .is_none()
            );
            assert!(!emitted);
            realm.driver.service(&mut cx, now);
            assert_eq!(
                realm
                    .poll_outputs(&mut cx, TxClass::Control, 1, &mut outputs)
                    .0,
                Poll::Ready(Some(1))
            );
            let synack = outputs[0].take().unwrap();
            let ip = wire::parse_ip(synack.packet()).unwrap();
            let (syn, _) = tcp::parse(&synack.packet()[ip.payload]).unwrap();
            assert_eq!(syn.flags, tcp::SYN | tcp::ACK);
            synack.release();
            scope.receive(
                &segment(client, server, 101, syn.seq.wrapping_add(1), tcp::ACK),
                now,
            );
            let payload = vec![0x3c; mtu - wire::ip_header_len(client.is_ipv6()) - 20];
            flow.write_all(&payload).await.unwrap();
            assert!(
                realm
                    .generate_output(now, TxClass::Bulk, 10, &peers, &mut frame, &mut emitted)
                    .unwrap()
                    .is_none()
            );
            assert!(!emitted);
            realm.driver.service(&mut cx, now);
            assert_eq!(
                realm
                    .poll_outputs(&mut cx, TxClass::Bulk, 1, &mut outputs)
                    .0,
                Poll::Ready(Some(1))
            );
            let output = outputs[0].take().unwrap();
            assert_eq!(output.packet().len(), mtu);
            let header = realm
                .output_header(
                    endpoint_return_path(&peers, &output).unwrap(),
                    10,
                    client.is_ipv6(),
                )
                .unwrap();
            let length = header.len() + output.packet().len();
            assert_eq!(length, honk_xsk::FRAME_SIZE + 1);
            let mut wire = vec![0; length];
            let (first, last) = wire.split_at_mut(honk_xsk::FRAME_SIZE);
            assert_eq!(
                last.len(),
                1,
                "the CPU owner requires a whole two-descriptor SG packet"
            );
            fill_output(&mut [first, last], &header, output.packet()).unwrap();
            assert_eq!(check_tcp_frame(&wire, reply, server, client).1, payload);
            let mut completed = [Some(Retained::Endpoint(output.into_owner()))];
            release_completed(&mut completed.each_mut().map(Option::as_mut));
            drop(completed);
            drop(flow);
            join_driven(endpoints, owner, &mut realm.driver).await;
        }
    }
}

#[tokio::test]
async fn generated_empty_turns_do_not_create_protocol_deadlines() {
    let (scope, owner, _budget, plane, _slots) = fixture_parts();
    let (endpoints, owner, driver) = driven(scope, owner, plane).await;
    let mut realm = output_realm(driver, path(), 1500);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let now = Instant::now();
    let mut frame = vec![0xa5; realm.generated.unwrap().1];
    for _ in 0..4 {
        realm.driver.begin_turn(now);
        for class in [TxClass::Control, TxClass::Bulk] {
            let mut emitted = false;
            assert!(
                realm
                    .generate_output(now, class, 10, &[], &mut frame, &mut emitted)
                    .unwrap()
                    .is_none()
            );
            assert!(!emitted);
        }
        realm.driver.finish_turn(&mut cx, now);
        assert!(realm.driver.deadline().is_none());
    }
    join_driven(endpoints, owner, &mut realm.driver).await;
}
