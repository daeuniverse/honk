use super::*;
use crate::control::netstack::{FlowIo, PacketDriver, PacketOwner, RuntimeLimits};
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
        PacketEndpoints::start_driven(plane, vec![(scope, owner)], 4, None, ScopeId::HOST)
            .await
            .unwrap();
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
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let mut pairs = Vec::new();
        for _ in 0..4 {
            let mut config = honk_netstack::Config::new([91; 32]);
            config.mode = honk_netstack::Mode::Transparent {
                exclude: Default::default(),
            };
            config.max_flows = 1024;
            config.memory_limit = CAPTURE_MEMORY / 8;
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
        assert!(pressure.sample(now + Duration::from_secs(1), None, 0, 0, peers.len()));
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
        assert!(pressure.sample(now + Duration::from_secs(2), None, 0, 0, peers.len()));
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

#[cfg(feature = "ebpf")]
#[tokio::test]
#[ignore = "requires smoke-owned disposable-VM namespaces and real AF_XDP/TAP"]
async fn kernel_captured_return_small_jumbo_entry_and_fresh_grace() -> anyhow::Result<()> {
    captured_kernel::positive().await
}

#[cfg(feature = "ebpf")]
#[tokio::test]
#[ignore = "requires retained child owners in smoke-owned disposable-VM namespaces"]
async fn kernel_captured_return_missing_entry_retains_owner() -> anyhow::Result<()> {
    captured_kernel::negative(
        concat!(
            module_path!(),
            "::kernel_captured_return_missing_entry_retains_owner"
        ),
        &["missing-entry"],
    )
    .await
}

#[cfg(feature = "ebpf")]
#[tokio::test]
#[ignore = "requires a real downstream TCX refusal after private XDP admission"]
async fn kernel_captured_return_full_length_write_refused_after_admission() -> anyhow::Result<()> {
    captured_kernel::negative(
        concat!(
            module_path!(),
            "::kernel_captured_return_full_length_write_refused_after_admission"
        ),
        &["downstream-refusal"],
    )
    .await
}

#[cfg(feature = "ebpf")]
#[tokio::test]
#[ignore = "requires actual private TAP prerequisite mutations in a fresh child namespace"]
async fn kernel_captured_return_private_prerequisite_refusal() -> anyhow::Result<()> {
    captured_kernel::negative(
        concat!(
            module_path!(),
            "::kernel_captured_return_private_prerequisite_refusal"
        ),
        &["prerequisite"],
    )
    .await
}

#[cfg(feature = "ebpf")]
#[tokio::test]
#[ignore = "requires actual committed Endpoint takeover in the smoke-owned disposable VM"]
async fn native_committed_executors_never_return_original() -> anyhow::Result<()> {
    captured_kernel::positive().await
}

#[cfg(feature = "ebpf")]
#[tokio::test]
#[ignore = "requires a real retained Port in a smoke-owned child namespace"]
async fn native_nonready_port_retains_runtime_before_take() -> anyhow::Result<()> {
    captured_kernel::negative(
        concat!(
            module_path!(),
            "::native_nonready_port_retains_runtime_before_take"
        ),
        &["nonready-port"],
    )
    .await
}

#[cfg(feature = "ebpf")]
#[tokio::test]
#[ignore = "requires actual Runtime Payload/Flight/Completing owners in retained VM children"]
async fn kernel_captured_return_terminal_proof_failures_retain_phases() -> anyhow::Result<()> {
    captured_kernel::negative(
        concat!(
            module_path!(),
            "::kernel_captured_return_terminal_proof_failures_retain_phases"
        ),
        &[
            "terminal-payload-guard",
            "terminal-flight-seal",
            "terminal-completing-grace",
        ],
    )
    .await
}

#[cfg(feature = "ebpf")]
#[tokio::test]
#[ignore = "requires a genuine ENTERED operation and retained original in a VM child"]
async fn kernel_captured_return_failed_finish_close_stays_retained() -> anyhow::Result<()> {
    captured_kernel::negative(
        concat!(
            module_path!(),
            "::kernel_captured_return_failed_finish_close_stays_retained"
        ),
        &["private-finish-close"],
    )
    .await
}

#[cfg(feature = "ebpf")]
#[tokio::test]
#[ignore = "requires an empty live Runtime in its own disposable-VM child namespace"]
async fn kernel_captured_return_empty_runtime_drop_quiesces_publication() -> anyhow::Result<()> {
    captured_kernel::empty_runtime_drop(concat!(
        module_path!(),
        "::kernel_captured_return_empty_runtime_drop_quiesces_publication"
    ))
    .await
}

#[cfg(feature = "ebpf")]
mod captured_kernel {
    use super::*;
    use crate::control::core_forward::CapturedDecision;
    use crate::ebpf::native::{
        CaptureCommit, ImportedOriginal, NativeBasis, NativeClaimIdentity, NativeOriginal,
        OriginalExtent,
    };
    use honk_ebpf_common::xdp::*;
    use honk_xsk::{RetainedRxHandle, RxDisposition};
    use sha2::{Digest, Sha256};
    use std::{
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::PathBuf,
        process::Stdio,
    };
    use tokio::{
        io::{AsyncBufReadExt, BufReader, Lines},
        process::{Child, ChildStdin, ChildStdout, Command},
    };

    const PEER: &str = r#"
import contextlib, hashlib, json, os, socket, struct, sys, time
home = os.open('/proc/self/ns/net', os.O_RDONLY)
@contextlib.contextmanager
def namespace(name):
    fd = os.open('/run/netns/' + name, os.O_RDONLY)
    try:
        os.setns(fd, 0)
        yield
    finally:
        os.setns(home, 0)
        os.close(fd)
with namespace(sys.argv[1]):
    source = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    source.bind(('c0', 0))
with namespace(sys.argv[2]):
    target = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    target.bind(('s0', 0))
    target.setsockopt(263, 23, 1)
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(('198.51.100.2', 18086))
    dns_sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_sink.bind(('198.51.100.2', 53))
os.close(home)
def checksum(data):
    data += b'\0' * (len(data) % 2)
    n = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while n >> 16:
        n = (n & 65535) + (n >> 16)
    return (~n) & 65535
sent = {}
print(json.dumps({'ready': True}), flush=True)
for line in sys.stdin:
    fields = line.split()
    command, label = fields[:2]
    if command == 'SEND':
        size, port, sequence = map(int, fields[2:5])
        destination_port = int(fields[5]) if len(fields) > 5 else 18086
        payload = bytes((i + sequence) % 251 for i in range(size))
        src, dst = socket.inet_aton('192.0.2.2'), socket.inet_aton('198.51.100.2')
        udp = struct.pack('!HHHH', port, destination_port, size + 8, 0) + payload
        udp = udp[:6] + struct.pack('!H', checksum(src + dst + struct.pack('!BBH', 0, 17, len(udp)) + udp) or 65535) + udp[8:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp) + 20, sequence, 0, 64, 17, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:] + udp
        frame = bytes.fromhex('0200000000100200000000200800') + ip
        assert len(ip) == size + 28 and len(frame) == size + 42
        assert struct.unpack_from('!H', ip, 2)[0] == len(ip) and ip[6:8] == b'\0\0'
        assert struct.unpack_from('!H', ip, 24)[0] == size + 8 and len(ip[28:]) == size
        if size == 65507:
            assert len(ip) == 65535 and len(frame) == 65549
        source.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, sequence & 1)
        assert source.send(frame) == len(frame)
        sent[label] = ip
        print(json.dumps({'label':label, 'frame_length':len(frame), 'sha256':hashlib.sha256(frame).hexdigest(),
                          'source':'192.0.2.2', 'source_port':port, 'destination_port':destination_port, 'ttl':64,
                          'ip_length':len(ip), 'fragment_flags_offset':0, 'payload_length':size}), flush=True)
    elif command == 'OBSERVE':
        minimum, maximum = map(int, fields[2:])
        ip = sent[label]
        expected = ip[:8] + b'\x3f' + ip[9:10] + b'\0\0' + ip[12:]
        expected = expected[:10] + struct.pack('!H', checksum(expected[:20])) + expected[12:]
        deadline, count = time.monotonic() + (8 if minimum else 0.25), 0
        while time.monotonic() < deadline:
            target.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                packet = target.recv(131072)
            except TimeoutError:
                break
            if len(packet) < 42 or packet[12:14] != b'\x08\x00':
                continue
            wire = packet[14:]
            if wire[9] != 17 or wire[12:20] != ip[12:20] or wire[20:24] != ip[20:24] or wire[4:6] != ip[4:6]:
                continue
            length, = struct.unpack_from('!H', wire, 2)
            assert length == len(ip) == len(wire) and len(packet) == length + 14, ('wire extent changed', label, length, len(packet))
            assert wire[6:8] == b'\0\0', ('original fragmented', label)
            assert struct.unpack_from('!H', wire, 24)[0] == len(wire) - 20
            assert len(wire[28:]) == len(ip[28:]), ('payload extent changed', label)
            assert wire == expected, ('original IP bytes/source/TTL changed', label, length)
            assert checksum(wire[:20]) == 0
            count += 1
            assert count <= maximum, ('duplicate Linux delivery/replay', label, count)
            if count >= minimum and minimum:
                deadline = time.monotonic() + 0.25
        packets, dropped = struct.unpack('=II', target.getsockopt(263, 6, 8))
        assert dropped == 0, ('wire observer lost evidence', dropped)
        assert minimum <= count <= maximum, (label, count, minimum, maximum)
        print(json.dumps({'label':label, 'linux_copies':count, 'ttl':63 if count else None,
                          'original_ip_sha256':hashlib.sha256(ip).hexdigest(), 'observer_drops':dropped,
                          'ip_length':len(expected) if count else None, 'frame_length':len(expected) + 14 if count else None,
                          'payload_length':len(expected[28:]) if count else None, 'fragment_flags_offset':0 if count else None}), flush=True)
    elif command == 'STOP':
        source.close()
        target.close()
        sink.close()
        dns_sink.close()
        print(json.dumps({'stopped':True}), flush=True)
        break
    else:
        raise AssertionError(command)
else:
    raise AssertionError('fixture peer lost its owner before STOP')
"#;

    struct Environment {
        namespace: String,
        client: String,
        server: String,
        pins: PathBuf,
        prefix: PathBuf,
        data: PathBuf,
    }

    fn guard(namespace: &str) -> anyhow::Result<u64> {
        ensure!(
            std::fs::read_to_string("/proc/cmdline")?.contains("virtme."),
            "disposable VM required"
        );
        let inode = std::fs::metadata("/proc/self/ns/net")?.ino();
        ensure!(
            inode != std::fs::metadata("/proc/1/ns/net")?.ino(),
            "initial network namespace"
        );
        ensure!(
            inode.to_string() != std::env::var("HONK_XDP_PARENT_NETNS")?,
            "outer smoke namespace"
        );
        ensure!(
            inode == std::fs::metadata(format!("/run/netns/{namespace}"))?.ino(),
            "fixture namespace mismatch"
        );
        for (name, mac) in [("dut0", "02:00:00:00:00:10"), ("dut1", "02:00:00:00:00:11")] {
            ensure!(
                std::fs::read_to_string(format!("/sys/class/net/{name}/address"))?.trim() == mac,
                "unexpected operator link"
            );
        }
        Ok(inode)
    }

    fn environment(label: &str) -> anyhow::Result<Environment> {
        let root = PathBuf::from(
            std::env::var_os("HONK_XDP_ARTIFACT_ROOT").context("smoke artifacts missing")?,
        );
        let prefix = root.join(format!("captured-{label}-{}", std::process::id()));
        Ok(Environment {
            namespace: std::env::var("HONK_CAPTURED_NAMESPACE").unwrap_or_else(|_| "dut".into()),
            client: std::env::var("HONK_CAPTURED_CLIENT").unwrap_or_else(|_| "client".into()),
            server: std::env::var("HONK_CAPTURED_SERVER").unwrap_or_else(|_| "server".into()),
            pins: PathBuf::from(
                std::env::var_os("HONK_XDP_PIN_ROOT").context("smoke pins missing")?,
            )
            .join(format!("captured-{label}-{}", std::process::id())),
            // 9p refuses renameat2 flags (EINVAL), which Native publication needs; use the guest tmpfs the smoke exports at cleanup.
            data: PathBuf::from("/run/honk-xdp-state")
                .join(format!("captured-{label}-{}", std::process::id())),
            prefix,
        })
    }

    async fn command(program: &str, arguments: &[&str]) -> anyhow::Result<std::process::Output> {
        let output = tokio::time::timeout(
            Duration::from_secs(8),
            Command::new(program).args(arguments).output(),
        )
        .await??;
        ensure!(
            output.status.success(),
            "{program} {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    }

    struct PeerOwner {
        child: Child,
        input: ChildStdin,
        output: Lines<BufReader<ChildStdout>>,
    }

    impl PeerOwner {
        async fn start(env: &Environment) -> anyhow::Result<Self> {
            let mut child = Command::new("python3")
                .args(["-u", "-c", PEER, &env.client, &env.server])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()?;
            let input = child.stdin.take().context("peer stdin")?;
            let output = BufReader::new(child.stdout.take().context("peer stdout")?).lines();
            let mut peer = Self {
                child,
                input,
                output,
            };
            ensure!(peer.line().await?["ready"] == true, "peer readiness");
            Ok(peer)
        }

        async fn line(&mut self) -> anyhow::Result<serde_json::Value> {
            let line = tokio::time::timeout(Duration::from_secs(10), self.output.next_line())
                .await??
                .context("peer exited")?;
            Ok(serde_json::from_str(&line)?)
        }

        async fn send(
            &mut self,
            label: &str,
            size: usize,
            port: u16,
            sequence: u16,
        ) -> anyhow::Result<serde_json::Value> {
            self.send_to(label, size, port, sequence, 18086).await
        }

        async fn send_to(
            &mut self,
            label: &str,
            size: usize,
            port: u16,
            sequence: u16,
            destination: u16,
        ) -> anyhow::Result<serde_json::Value> {
            self.input
                .write_all(
                    format!("SEND {label} {size} {port} {sequence} {destination}\n").as_bytes(),
                )
                .await?;
            let value = self.line().await?;
            ensure!(value["label"] == label, "send association");
            Ok(value)
        }

        async fn observe(
            &mut self,
            label: &str,
            minimum: usize,
            maximum: usize,
        ) -> anyhow::Result<serde_json::Value> {
            self.input
                .write_all(format!("OBSERVE {label} {minimum} {maximum}\n").as_bytes())
                .await?;
            let value = self.line().await?;
            ensure!(value["label"] == label, "wire association");
            Ok(value)
        }

        async fn join(&mut self) -> anyhow::Result<()> {
            self.input.write_all(b"STOP owned\n").await?;
            ensure!(self.line().await?["stopped"] == true, "peer stop");
            ensure!(
                tokio::time::timeout(Duration::from_secs(8), self.child.wait())
                    .await??
                    .success(),
                "peer join failed"
            );
            Ok(())
        }
    }

    struct Fixture {
        runtime: Runtime,
        owner: PacketEndpointOwner,
        flags: crate::mode::DatapathFlagsHandle,
        stats: Arc<crate::stats::StatsManager>,
        config: Arc<tokio::sync::RwLock<Arc<Config>>>,
        commands: tokio::sync::mpsc::Sender<crate::control::ControlCommand>,
        projection: Arc<crate::dns::projection::RoutingProjection>,
        router: Arc<tokio::sync::RwLock<crate::routing::Router>>,
        routing_diagnostics: crate::config_diagnostics::SharedDiagnostics,
        shutdown: Arc<crate::control::ShutdownIntent>,
        retained: Option<Taken>,
    }

    async fn start(env: &Environment) -> anyhow::Result<Fixture> {
        guard(&env.namespace)?;
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(&env.pins)?;
        std::fs::DirBuilder::new().mode(0o700).create(&env.data)?;
        honk_config::paths::set_data_dir(env.data.clone()).map_err(|path| {
            anyhow::anyhow!("data directory already initialized: {}", path.display())
        })?;
        let mut config = honk_config::parser::parse_dae_config(
            "global { dial_mode: ip\n nfqueue_enable: false\n so_mark_from_dae: 0x100 }\n\
             dns { bind: '' }\n\
             datapath { backend: xdp\n direct: native\n xsk_mode: copy\n interface { dut0: lan\n dut1: wan } }\n\
             routing { fallback: direct }",
        )?;
        config.ensure_builtin_nodes();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
        config.global.preconnect_node_count = 0;
        config.global.udp_warm_node_count = 0;
        config.global.store_subscribe = false;
        config.global.check_interval_secs = 3600;
        config.groups.push(honk_config::group::Group {
            name: "packet-proof".into(),
            nodes: vec![honk_config::config::DIRECT_NODE_ID],
            ..Default::default()
        });
        config.validate_assembled()?;
        let resolver = crate::dns::DnsResolver::new(&config.dns)?;
        let forwarder = resolver.forwarder();
        let admission = Arc::new(AtomicBool::new(false));
        let pname_support = Arc::new(parking_lot::RwLock::new(
            crate::ebpf::PnameSupport::Unavailable,
        ));
        let mut plane = ControlPlane::new(
            config.clone(),
            Box::new(crate::ebpf::userspace::UserspaceBackend::new(
                Arc::clone(&admission),
                Arc::clone(&pname_support),
            )),
            crate::routing::Router::from_config(&config.routing)?,
            Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver()?),
            resolver,
            forwarder,
        )?;
        plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
            crate::mode::ModeState::new("Global", "packet-proof"),
        )));
        plane.start_datapath_flags_coordinator()?;
        let flags = plane.datapath_flags_handle().context("flags coordinator")?;
        let shutdown = plane.shutdown_intent();
        let config_handle = plane.config_handle();
        let commands = plane.command_sender();
        let projection = plane.native_projection_for_test();
        let router = plane.traffic_router();
        let routing_diagnostics = plane.diagnostics_handle();
        let (polling_publication, process_polling) =
            plane.polling_runtime().context("explicit XDP polling")?;
        let PreparedRuntime {
            devices,
            topology,
            host,
            realms: plans,
            scope_pairs,
            workers,
            inboxes,
            core,
            native,
            native_policy,
            captured,
            originals,
            original_memory,
            memory,
            staging,
            mut links,
            polling_prefix,
            polling_budget,
            diagnostics,
        } = prepare(&plane, &config, &env.pins, Arc::clone(&admission)).await?;
        ensure!(
            host.is_none() && core.is_none(),
            "Transit Native fixture unexpectedly owns another executor"
        );
        let stats = plane.stats_handle();
        stats.install_xdp(Arc::clone(&diagnostics));
        let (endpoints, mut owner, mut drivers) =
            PacketEndpoints::start_driven(plane, scope_pairs, 64, None, ScopeId::HOST).await?;
        let realms = plans
            .into_iter()
            .map(|(ingress, device, link, scope)| {
                let index = drivers
                    .iter()
                    .position(|driver| driver.scope() == scope)
                    .expect("actual prepared scope driver");
                Realm {
                    ingress,
                    device,
                    link,
                    generated: generated_layout(link),
                    driver: drivers.swap_remove(index),
                    pending: [None, None],
                }
            })
            .collect();
        ensure!(drivers.is_empty(), "unowned packet driver");
        let mut runtime = Runtime {
            devices,
            topology,
            host: None,
            admission,
            pname_support,
            realms,
            workers,
            worker: None,
            inbox: inboxes.into_iter().next().unwrap(),
            endpoints,
            core,
            native,
            native_policy,
            next_candidate: 1,
            captured,
            originals,
            original_outcome: None,
            remote_originals: VecDeque::with_capacity(64),
            original_worker: false,
            _original_memory: original_memory,
            native_writer: None,
            native_capture_close: NativeCaptureClose::Unproven,
            native_next: Instant::now() + Duration::from_secs(1),
            waiting: VecDeque::with_capacity(PENDING),
            pending: VecDeque::with_capacity(PENDING),
            staging,
            closing: false,
            finished: false,
            pressure: Pressure::new(Instant::now()),
            diagnostics,
            core_maintenance_checked: Instant::now(),
            polling: AdaptivePoll::new(polling_publication, process_polling),
            polling_prefix,
            polling_budget,
            polling_affinity: None,
            qualified_rx: 0,
            qualification_unavailable: false,
            rx_device: 0,
            rx_queue: 0,
            tx_realm: 0,
            tx_class: 0,
            round_cut_short: false,
            policy_recheck: false,
            context_recheck: false,
            context_revision: 0,
            _memory: Some(memory),
        };
        let timer = None;
        tokio::pin!(timer);
        loop {
            tokio::select! {
                ready = poll_fn(|cx| owner.poll_ready(cx)) => { ready?; break; }
                () = poll_fn(|cx| runtime.poll_scopes(cx, timer.as_mut())) => tokio::task::yield_now().await,
            }
        }
        for device in &mut runtime.devices {
            device.attachment.replace(&device.programs)?;
            device.active = true;
        }
        let indices: Vec<_> = runtime
            .devices
            .iter()
            .map(|device| device.info.ifindex)
            .collect();
        let logical: Vec<_> = runtime
            .realms
            .iter()
            .map(|realm| realm.ingress.ifindex)
            .collect();
        let topology =
            runtime.admit_final_topology(&indices, &logical, config.global.effective_so_mark())?;
        ensure!(
            topology.ipv4_broadcasts() == runtime.topology.get_ref().ipv4_broadcasts(),
            "bootstrap topology changed"
        );
        // SAFETY: the owned Topology descriptor remains stable, as in production run.
        runtime.topology = unsafe { AsyncFd::register(topology) }.map_err(io::Error::from)?;
        links.synchronize()?;
        links.validate_capture(&indices)?;
        for realm in &runtime.realms {
            ensure!(
                links.logical_links().any(|link| link == realm.link),
                "logical link changed"
            );
        }
        for device in &runtime.devices {
            device.info.validate_current()?;
            for queue in &device.queues {
                ensure!(
                    !queue.io.get_ref().zerocopy(),
                    "fixture requires explicit Copy"
                );
            }
        }
        ensure!(
            !runtime.topology.get_mut().check_changed()?,
            "topology changed before readiness"
        );
        runtime.rebuild_polling_context();
        runtime.admission.store(true, Ordering::Release);
        runtime.endpoints.capture_ready()?;
        let publication = runtime
            .native
            .as_ref()
            .context("actual Native publication")?;
        publication.set_ready(true)?;
        publication.set_capture_ready(true)?;
        ensure!(
            publication.selection_snapshot().is_some(),
            "Native root never opened"
        );
        runtime.diagnostics.lifecycle(Lifecycle::Active);
        Ok(Fixture {
            runtime,
            owner,
            flags,
            stats,
            config: config_handle,
            commands,
            projection,
            router,
            routing_diagnostics,
            shutdown,
            retained: None,
        })
    }

    struct Taken {
        device: usize,
        queue: usize,
        realm: usize,
        handle: RetainedRxHandle,
        imported: ImportedOriginal,
        extent: OriginalExtent,
        segments: usize,
        digest: String,
    }

    async fn wait_rx(runtime: &Runtime) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if runtime
                    .devices
                    .iter()
                    .flat_map(|device| &device.queues)
                    .any(|queue| {
                        let rings = queue.io.get_ref().rings();
                        rings.rx_producer != rings.rx_consumer
                    })
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .context("actual physical RX producer did not publish before import")?;
        Ok(())
    }

    fn take(runtime: &mut Runtime, expected: &serde_json::Value) -> anyhow::Result<Taken> {
        let publication = runtime.native.as_ref().context("publication missing")?;
        for (device_index, device) in runtime.devices.iter_mut().enumerate() {
            for (queue_index, queue) in device.queues.iter_mut().enumerate() {
                let mut taken = None;
                let received = queue.io.get_mut().receive_segments_owned(
                    1,
                    NATIVE_METADATA_LEN,
                    |handle, segments, metadata, _| {
                        taken = Some((|| -> anyhow::Result<Taken> {
                            let decoded = device
                                .capture
                                .decode(
                                    segments,
                                    if device.capture.vlan_metadata {
                                        &metadata[..METADATA_LEN]
                                    } else {
                                        &[]
                                    },
                                    queue.id,
                                )
                                .map_err(|_| io::Error::other("actual captured envelope"))?;
                            let realm_index = runtime
                                .realms
                                .iter()
                                .position(|realm| {
                                    realm.device == device_index
                                        && realm.link.mac == decoded.destination_mac
                                        && realm.link.path.vlan_count == decoded.vlan_count
                                })
                                .context("actual ingress realm missing")?;
                            let mut l3 = [&[][..]; 18];
                            let count = l3_segments(segments, decoded, &mut l3)
                                .context("actual whole L3 chain")?;
                            let view = PacketView::new(&l3[..count]).map_err(io::Error::other)?;
                            let ip = view.parse_ip().map_err(io::Error::other)?;
                            let imported = native::imported(
                                publication,
                                runtime.realms[realm_index].driver.scope(),
                                device.capture.authority,
                                view,
                                metadata,
                            )?;
                            let mut digest = Sha256::new();
                            for segment in segments {
                                digest.update(segment);
                            }
                            let digest = digest
                                .finalize()
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>();
                            ensure!(
                                expected["sha256"].as_str() == Some(&digest),
                                "retained original bytes differ from physical source"
                            );
                            ensure!(
                                expected["frame_length"].as_u64() == Some(decoded.frame_len as u64),
                                "original frame truncated"
                            );
                            ensure!(
                                imported.producer.flags == NATIVE_IMPORT_COUNTED,
                                "physical Pending/Armed reservation absent"
                            );
                            ensure!(
                                !runtime.endpoints.retains(
                                    runtime.realms[realm_index].driver.scope(),
                                    SocketAddr::new(
                                        ip.src,
                                        expected["source_port"].as_u64().context("source port")?
                                            as u16
                                    ),
                                    "198.51.100.2:18086".parse()?,
                                    17
                                ),
                                "protocol admitted before original selection"
                            );
                            Ok(Taken {
                                device: device_index,
                                queue: queue_index,
                                realm: realm_index,
                                handle,
                                imported,
                                extent: OriginalExtent {
                                    frame_length: decoded.frame_len.try_into()?,
                                    l3_offset: decoded.l3_offset.try_into()?,
                                    l3_length: decoded.l3_len.try_into()?,
                                    vlan_tci: decoded.vlan_tci,
                                    vlan_proto: decoded.vlan_proto,
                                    vlan_count: decoded.vlan_count.into(),
                                    inline_vlan_count: decoded.inline_vlan_count.into(),
                                    dscp: ip.dscp,
                                },
                                segments: segments.len(),
                                digest,
                            })
                        })());
                        RxDisposition::Retain
                    },
                );
                let closure = publication.finish_import_turn();
                received?;
                closure?;
                if let Some(taken) = taken {
                    ensure!(
                        runtime.originals.is_empty()
                            && runtime.waiting.is_empty()
                            && runtime.workers.peer_count() == 0,
                        "another consumer mutated the original"
                    );
                    let taken = taken?;
                    publication.record_imported(
                        taken.imported.identity,
                        taken.imported.producer,
                        taken.handle,
                    );
                    return Ok(taken);
                }
            }
        }
        anyhow::bail!("published physical RX had no complete retained original")
    }

    fn classify_decision(runtime: &mut Runtime, taken: &Taken) -> anyhow::Result<CapturedDecision> {
        let candidate = runtime.next_candidate;
        ensure!(candidate != 0, "Native candidate identity is exhausted");
        runtime.next_candidate = candidate
            .checked_add(1)
            .context("Native candidate identity exhausted")?;
        let publication = runtime.native.as_ref().context("publication absent")?;
        let (basis_epoch, basis_flags) = publication
            .selection_snapshot()
            .context("current publication closed")?;
        let authority = runtime
            .native_policy
            .as_ref()
            .context("actual routing authority")?;
        let read = authority.try_read_policy()?;
        let device = &runtime.devices[taken.device];
        let realm = &runtime.realms[taken.realm];
        let (query, extent) = device.queues[taken.queue].io.get_ref().with_retained_rx(
            taken.handle,
            |segments, metadata| -> io::Result<_> {
                let decoded = device
                    .capture
                    .decode(
                        segments,
                        if device.capture.vlan_metadata {
                            &metadata[..METADATA_LEN]
                        } else {
                            &[]
                        },
                        device.queues[taken.queue].id,
                    )
                    .map_err(|_| io::Error::other("retained envelope changed"))?;
                let mut l3 = [&[][..]; 18];
                let count = l3_segments(segments, decoded, &mut l3)
                    .ok_or_else(|| io::Error::other("retained SG changed"))?;
                let view = PacketView::new(&l3[..count]).map_err(io::Error::other)?;
                let ip = view.parse_ip().map_err(io::Error::other)?;
                let ports = view.transport_ports(&ip).map_err(io::Error::other)?;
                Ok((
                    honk_datapath::forward::RouteQuery {
                        ingress: realm.ingress,
                        source: ip.src,
                        destination: ip.dst,
                        traffic_class: ip.dscp << 2,
                        protocol: ip.proto,
                        ports,
                    },
                    OriginalExtent {
                        frame_length: decoded.frame_len.try_into().map_err(io::Error::other)?,
                        l3_offset: decoded.l3_offset.try_into().map_err(io::Error::other)?,
                        l3_length: decoded.l3_len.try_into().map_err(io::Error::other)?,
                        vlan_tci: decoded.vlan_tci,
                        vlan_proto: decoded.vlan_proto,
                        vlan_count: decoded.vlan_count.into(),
                        inline_vlan_count: decoded.inline_vlan_count.into(),
                        dscp: ip.dscp,
                    },
                ))
            },
        )??;
        ensure!(
            extent == taken.extent,
            "retained original extent changed before classification"
        );
        let retained_capture = query.ports.is_none_or(|(source, destination)| {
            runtime.endpoints.retains(
                realm.driver.scope(),
                SocketAddr::new(query.source, source),
                SocketAddr::new(query.destination, destination),
                query.protocol,
            )
        });
        let original = NativeOriginal {
            imported: &taken.imported,
            authority: device.capture.authority,
            ingress: realm.ingress,
            facts: realm.driver.scope(),
            realm_index: taken.realm as u32,
            rx_queue: device.queues[taken.queue].id,
            extent,
            basis_epoch,
            basis_flags,
            retained_capture,
            candidate,
        };
        let decision = authority.capture_original(
            &read,
            query,
            realm.driver.scope(),
            &original,
            &runtime.polling_budget,
        )?;
        drop(read);
        ensure!(
            publication.selection_epoch() == Some(basis_epoch),
            "classification publication changed"
        );
        Ok(decision)
    }

    fn classify(runtime: &mut Runtime, taken: &Taken) -> anyhow::Result<NativeBasis> {
        match classify_decision(runtime, taken)? {
            CapturedDecision::TryNativeOriginal(basis) => Ok(basis),
            _ => anyhow::bail!("actual first consumer did not choose literal Direct original"),
        }
    }

    fn begin(runtime: &mut Runtime, taken: &Taken, basis: &NativeBasis) -> io::Result<()> {
        runtime
            .captured
            .as_mut()
            .expect("production captured owner")
            .begin_original(
                runtime.devices[taken.device].queues[taken.queue]
                    .io
                    .get_ref(),
                taken.handle,
                basis,
            )
    }

    async fn outcome(runtime: &mut Runtime) -> anyhow::Result<native::OriginalOutcome> {
        tokio::time::timeout(
            Duration::from_secs(8),
            poll_fn(|cx| runtime.captured.as_mut().unwrap().poll_original(cx)),
        )
        .await
        .context("real operation outcome did not resolve within the fixture bound")?
    }

    fn receipt(
        runtime: &Runtime,
        taken: &Taken,
        proof: &native::OriginalProof,
        transferred: bool,
    ) -> anyhow::Result<serde_json::Value> {
        ensure!(
            proof.identity() == taken.imported.identity
                && proof.producer() == taken.imported.producer
                && proof.handle() == taken.handle,
            "proof associated with a different original"
        );
        let value = runtime.captured.as_ref().unwrap().flight_receipt()?;
        ensure!(
            value["observation"]["status"] == "observed",
            "final flight observation unavailable"
        );
        ensure!(
            value["op_incarnation"].as_u64() == Some(proof.op_incarnation())
                && value["return_attachment"].as_u64() == Some(proof.return_attachment())
                && value["observation"]["entry_seq"].as_u64() == Some(proof.entry_seq()),
            "entry proof association"
        );
        ensure!(
            value["producer"]["epoch"].as_u64() == Some(taken.imported.producer.epoch)
                && value["producer"]["expires_boottime_ns"].as_u64()
                    == Some(taken.imported.producer.expires_boottime_ns),
            "producer horizon renewed"
        );
        if transferred {
            ensure!(
                proof.is_transferred() && proof.entry_seq() != 0,
                "target entry absent"
            );
            ensure!(
                value["observation"]["phase"] == NATIVE_OP_ENTERED
                    && value["entry_observed"] == true
                    && value["fresh_grace_started"] == true
                    && value["fresh_grace_completed"] == true,
                "entry did not precede a new same-publication Grace"
            );
        }
        Ok(value)
    }

    fn intake(runtime: &mut Runtime, selected: Option<(usize, usize)>) -> anyhow::Result<usize> {
        let publication = runtime
            .native
            .as_ref()
            .context("actual Native publication")?
            .clone();
        let mut received = 0;
        for (device_index, device) in runtime.devices.iter_mut().enumerate() {
            for (queue_index, queue) in device.queues.iter_mut().enumerate() {
                if selected.is_some_and(|selected| selected != (device_index, queue_index)) {
                    continue;
                }
                received += native::receive_originals(
                    queue.io.get_mut(),
                    &device.capture,
                    queue.id,
                    device_index,
                    queue_index,
                    &runtime.realms,
                    &publication,
                    &mut runtime.originals,
                    &mut runtime.pressure.counters,
                )?;
            }
        }
        Ok(received)
    }

    fn held_snapshot(
        runtime: &Runtime,
        index: usize,
        expected: &serde_json::Value,
    ) -> anyhow::Result<Taken> {
        let original = runtime
            .originals
            .get(index)
            .context("production retained original missing")?;
        let (device_index, queue_index, realm_index, handle) = (
            original.device(),
            original.queue(),
            original.realm(),
            original.handle(),
        );
        let device = &runtime.devices[device_index];
        let realm = &runtime.realms[realm_index];
        device.queues[queue_index].io.get_ref().with_retained_rx(
            handle,
            |segments, metadata| -> anyhow::Result<Taken> {
                let decoded = device
                    .capture
                    .decode(
                        segments,
                        if device.capture.vlan_metadata {
                            &metadata[..METADATA_LEN]
                        } else {
                            &[]
                        },
                        device.queues[queue_index].id,
                    )
                    .map_err(|_| io::Error::other("production retained envelope"))?;
                let mut l3 = [&[][..]; 18];
                let count = l3_segments(segments, decoded, &mut l3)
                    .context("production retained full L3 chain")?;
                let view = PacketView::new(&l3[..count]).map_err(io::Error::other)?;
                let ip = view.parse_ip().map_err(io::Error::other)?;
                let imported = native::imported(
                    runtime.native.as_ref().unwrap(),
                    realm.driver.scope(),
                    device.capture.authority,
                    view,
                    metadata,
                )?;
                ensure!(
                    original.identity() == imported.identity
                        && original.import() == Some(imported.producer),
                    "Runtime custody differs from the actual authenticated producer"
                );
                let mut digest = Sha256::new();
                for segment in segments {
                    digest.update(segment);
                }
                let digest = digest
                    .finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                ensure!(
                    expected["sha256"].as_str() == Some(&digest)
                        && expected["frame_length"].as_u64() == Some(decoded.frame_len as u64),
                    "production-held full-chain bytes differ from source"
                );
                let payload = expected["payload_length"]
                    .as_u64()
                    .context("source payload extent")?;
                ensure!(
                    decoded.frame_len as u64 == payload + 42
                        && decoded.l3_len as u64 == payload + 28
                        && decoded.l3_offset == 14
                        && decoded.vlan_count == 0
                        && segments.iter().map(|segment| segment.len()).sum::<usize>()
                            == decoded.frame_len,
                    "actual retained IP/wire/payload extent changed"
                );
                if payload == 65507 {
                    ensure!(
                        decoded.frame_len == 65549
                            && decoded.l3_len == 65535
                            && segments.len() == 18,
                        "actual jumbo original lost full physical extent"
                    );
                }
                Ok(Taken {
                    device: device_index,
                    queue: queue_index,
                    realm: realm_index,
                    handle,
                    imported,
                    extent: OriginalExtent {
                        frame_length: decoded.frame_len.try_into()?,
                        l3_offset: decoded.l3_offset.try_into()?,
                        l3_length: decoded.l3_len.try_into()?,
                        vlan_tci: decoded.vlan_tci,
                        vlan_proto: decoded.vlan_proto,
                        vlan_count: decoded.vlan_count.into(),
                        inline_vlan_count: decoded.inline_vlan_count.into(),
                        dscp: ip.dscp,
                    },
                    segments: segments.len(),
                    digest,
                })
            },
        )?
    }

    fn recorded(runtime: &Runtime) -> anyhow::Result<serde_json::Value> {
        let exported = runtime
            .native
            .as_ref()
            .context("actual Native publication")?
            .export_recording(false, false);
        ensure!(
            exported.status.as_str() == "PUBLISHED_DURABLE" && exported.error.is_none(),
            "actual Runtime receipt export failed"
        );
        Ok(serde_json::from_slice(&std::fs::read(
            exported.path.context("actual Runtime receipt path")?,
        )?)?)
    }

    fn original_receipts(
        document: &serde_json::Value,
        identity: &NativeClaimIdentity,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let (epoch, incarnation, scope) = (
            identity.epoch.to_string(),
            identity.incarnation.to_string(),
            identity.scope.to_string(),
        );
        let key = identity.key;
        let exact_key = serde_json::json!({"src_ip":key.src_ip,"dst_ip":key.dst_ip,"src_port":key.src_port,"dst_port":key.dst_port,
            "l4proto":key.l4proto,"ip_version":key.ip_version,"domain":key.domain,"direction":key.direction,
            "namespace_cookie":key.namespace_cookie.to_string(),"zone":key.zone,"zone_state":key.zone_state,"reserved":key.reserved});
        Ok(document["captured_receipts"]
            .as_array()
            .context("actual captured receipt ring")?
            .iter()
            .filter(|item| {
                item["claim_epoch"].as_str() == Some(&epoch)
                    && item["claim_incarnation"].as_str() == Some(&incarnation)
                    && item["claim_scope"].as_str() == Some(&scope)
                    && item["key"] == exact_key
            })
            .cloned()
            .collect())
    }

    fn decimal(value: &serde_json::Value, field: &str) -> anyhow::Result<u64> {
        Ok(value[field]
            .as_str()
            .with_context(|| format!("actual decimal receipt field {field}"))?
            .parse()?)
    }

    fn start_production_flight(
        runtime: &mut Runtime,
        taken: &Taken,
    ) -> anyhow::Result<serde_json::Value> {
        ensure!(
            runtime
                .originals
                .front()
                .is_some_and(|original| original.handle() == taken.handle),
            "operation did not start at the Runtime FIFO head"
        );
        let length = runtime.originals.len();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        ensure!(
            runtime.service_one_native_original(&mut cx, Instant::now())? == 0
                && runtime.originals.len() == length
                && !runtime.captured.as_ref().unwrap().is_idle(),
            "production service skipped retaining the actual private flight"
        );
        let flight = runtime.captured.as_ref().unwrap().flight_receipt()?;
        if let Some(written) = flight["write_result"]["length"].as_u64() {
            ensure!(
                written == u64::from(taken.extent.frame_length),
                "successful private write truncated the actual original"
            );
        }
        let id = taken.handle.receipt_identity();
        ensure!(
            flight["port_identity"]["port"].as_u64() == Some(id.port)
                && flight["port_identity"]["port_generation"].as_u64() == Some(id.port_generation)
                && flight["port_identity"]["slot"].as_u64() == Some(id.slot)
                && flight["port_identity"]["slot_generation"].as_u64() == Some(id.slot_generation),
            "production flight replaced the actual retained packet generation"
        );
        ensure!(
            flight["entry_observed"] == false
                && flight["fresh_grace_started"] == false
                && flight["fresh_grace_completed"] == false,
            "earlier publication Grace proved a newly started flight"
        );
        Ok(flight)
    }

    async fn finish_production_original(
        runtime: &mut Runtime,
        taken: &Taken,
        outcome: &str,
        held: usize,
        count_before: u32,
        count_after: u32,
        phase: u32,
    ) -> anyhow::Result<serde_json::Value> {
        let length = runtime.originals.len();
        ensure!(
            runtime
                .originals
                .front()
                .is_some_and(|original| original.handle() == taken.handle),
            "completion did not begin with the actual Runtime FIFO head"
        );
        tokio::time::timeout(
            Duration::from_secs(8),
            poll_fn(
                |cx| match runtime.service_one_native_original(cx, Instant::now()) {
                    Ok(1) => Poll::Ready(Ok(())),
                    Ok(0) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Ok(_) => Poll::Ready(Err(anyhow::anyhow!(
                        "limited production service completed more than one original"
                    ))),
                    Err(error) => Poll::Ready(Err(error)),
                },
            ),
        )
        .await
        .context(
            "actual Runtime completion/count settlement/Port acknowledgement did not finish",
        )??;
        ensure!(
            runtime.originals.len() + 1 == length
                && runtime
                    .originals
                    .iter()
                    .all(|original| original.handle() != taken.handle)
                && runtime.original_outcome.is_none()
                && runtime.captured.as_ref().unwrap().is_idle(),
            "production Runtime left a completed original or operation owned"
        );
        let port = runtime.devices[taken.device].queues[taken.queue]
            .io
            .get_ref();
        let held_on_port = runtime
            .originals
            .iter()
            .filter(|original| original.device() == taken.device && original.queue() == taken.queue)
            .count();
        ensure!(
            port.retained_rx_count() == held_on_port && port.rx_completion_count() == 0,
            "production Native completion did not release the chain and acknowledge its Port generation"
        );
        let claim = runtime
            .native
            .as_ref()
            .unwrap()
            .claim(&taken.imported.identity.key)?
            .context("completed original owner absent")?;
        ensure!(
            claim.state >> 4 == count_after && claim.state & 15 == phase,
            "production count settlement/resulting phase differs"
        );
        let document = recorded(runtime)?;
        let identity = taken.handle.receipt_identity();
        let completion_handle = serde_json::json!([
            identity.port.to_string(),
            identity.port_generation.to_string(),
            identity.slot.to_string(),
            identity.slot_generation.to_string()
        ]);
        let receipts = original_receipts(&document, &taken.imported.identity)?;
        let finished: Vec<_> = receipts
            .iter()
            .filter(|item| {
                item["kind"] == "ORIGINAL_FINISHED"
                    && item["completion_handle"] == completion_handle
            })
            .collect();
        ensure!(
            finished.len() == 1,
            "actual Runtime path lacks one exact ORIGINAL_FINISHED receipt"
        );
        let finished = finished[0];
        ensure!(
            finished["outcome"] == outcome
                && finished["producer_flags"].as_u64()
                    == Some(u64::from(taken.imported.producer.flags)),
            "Runtime local/return completion outcome or actual producer credit changed"
        );
        ensure!(
            decimal(finished, "inventory_held")? == held as u64
                && decimal(finished, "inventory_pending")? == 0
                && decimal(finished, "inventory_flight")? == 0,
            "Runtime inventory loop did not count its actual held FIFO originals"
        );
        ensure!(
            decimal(finished, "count_before")? == u64::from(count_before)
                && decimal(finished, "count_after")? == u64::from(count_after)
                && finished["phase_after"].as_u64() == Some(u64::from(phase)),
            "actual Runtime completion receipt does not bind count and phase"
        );
        if outcome == "Transferred" {
            ensure!(
                finished["fresh_grace"] == true && decimal(finished, "entry_seq")? != 0,
                "production return lacks matching entry and new Grace"
            );
            let operation = &finished["op_incarnation"];
            let mut previous = 0;
            for kind in [
                "OPERATION_PREPARED",
                "ENTRY_ACQUIRED",
                "FRESH_GRACE_STARTED",
                "FRESH_GRACE_DONE",
                "ORIGINAL_FINISHED",
            ] {
                let entries: Vec<_> = receipts
                    .iter()
                    .filter(|item| item["kind"] == kind && item["op_incarnation"] == *operation)
                    .collect();
                ensure!(
                    entries.len() == 1 && decimal(entries[0], "seq")? > previous,
                    "production operation receipt order differs at {kind}"
                );
                previous = decimal(entries[0], "seq")?;
            }
        }
        Ok(finished.clone())
    }

    fn artifacts(path: &Path, value: &serde_json::Value) -> anyhow::Result<()> {
        use std::io::Write as _;
        let temporary = path.with_extension("json.tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    async fn probe_result(
        env: &Environment,
        arguments: &[&str],
    ) -> anyhow::Result<std::process::Output> {
        let helper =
            std::env::var_os("HONK_XDP_PROBE").context("shared recovery helper missing")?;
        Ok(tokio::time::timeout(
            Duration::from_secs(8),
            Command::new("python3")
                .arg(helper)
                .args(arguments)
                .env("HONK_XDP_PIN_ROOT", &env.pins)
                .env("HONK_XDP_NATIVE_RUN", "1")
                .env("HONK_XDP_NATIVE_STATE_DIR", env.data.join("state"))
                .env(
                    "HONK_XDP_NATIVE_PUBLICATION_ARTIFACT",
                    env.prefix.with_extension("publication.json"),
                )
                .output(),
        )
        .await??)
    }

    async fn probe(env: &Environment, arguments: &[&str]) -> anyhow::Result<std::process::Output> {
        let output = probe_result(env, arguments).await?;
        ensure!(
            output.status.success(),
            "shared native recovery rejected {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    }

    async fn save_readiness(env: &Environment, runtime: &Runtime) -> anyhow::Result<()> {
        use std::io::Read as _;
        let pid = std::process::id().to_string();
        let publication = runtime
            .native
            .as_ref()
            .context("actual Native publication")?;
        let (checkpoint, expected_digest, expected_bytes) = publication
            .initial_checkpoint()
            .context("durable original checkpoint absent before readiness export")?;
        let source = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&checkpoint)?;
        let metadata = source.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1
                && metadata.len() == expected_bytes,
            "unsafe or incorrectly sized initial checkpoint"
        );
        let expected_len = usize::try_from(expected_bytes)?;
        let read_limit = expected_len
            .checked_add(1)
            .context("initial checkpoint read limit overflow")?;
        let mut initial_bytes = Vec::with_capacity(read_limit);
        source
            .take(u64::try_from(read_limit)?)
            .read_to_end(&mut initial_bytes)?;
        ensure!(
            initial_bytes.len() == expected_len
                && <[u8; 32]>::from(Sha256::digest(&initial_bytes)) == expected_digest,
            "initial checkpoint differs from retained producer digest/length"
        );
        let initial: serde_json::Value = serde_json::from_slice(&initial_bytes)?;
        let initial_digest = crate::configuration::encode_digest(&expected_digest);
        let mutable = checkpoint
            .parent()
            .context("checkpoint directory")?
            .parent()
            .context("checkpoint state directory")?
            .join("native-publication")
            .join(
                checkpoint
                    .file_name()
                    .context("checkpoint identity basename")?,
            );
        let mut original = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(env.prefix.with_extension("initial.json"))?;
        std::io::Write::write_all(&mut original, &initial_bytes)?;
        original.sync_all()?;
        let initial_binding = env.prefix.with_extension("initial-binding.json");
        artifacts(
            &initial_binding,
            &serde_json::json!({
            "path":mutable,"checkpoint_path":checkpoint,"sha256":initial_digest,"bytes":expected_bytes,
            "boot_id":initial["boot_id"],"pid":initial["pid"],"root_map_id":initial["root_map_id"],
            "starttime_ticks":decimal(&initial,"starttime_ticks")?,
            "publication_serial":decimal(&initial,"publication_serial")?}),
        )?;
        std::fs::set_permissions(&initial_binding, std::fs::Permissions::from_mode(0o600))?;
        std::fs::File::open(&initial_binding)?.sync_all()?;
        std::fs::File::open(env.prefix.parent().context("initial evidence directory")?)?
            .sync_all()?;
        let exported = publication.export_recording(false, false);
        ensure!(
            exported.status.as_str() == "PUBLISHED_DURABLE" && exported.error.is_none(),
            "actual readiness publication was not durable"
        );
        std::fs::copy(
            exported
                .path
                .as_ref()
                .context("actual readiness artifact")?,
            env.prefix.with_extension("publication.json"),
        )?;
        for device in &runtime.devices {
            let name = device.info.name.as_str();
            let guard = probe(env, &["pin-id", name, "guard"]).await?;
            std::fs::write(
                format!("{}.{name}.guard-id", env.prefix.display()),
                &guard.stdout,
            )?;
            let gate = probe(env, &["native-gate", name, &pid]).await?;
            std::fs::write(
                format!("{}.{name}.native-gate-program.json", env.prefix.display()),
                &gate.stdout,
            )?;
            artifacts(
                &PathBuf::from(format!("{}.{name}.identity.json", env.prefix.display())),
                &serde_json::json!({
                "ifindex":device.info.ifindex,"sysfs_inode":std::fs::metadata(format!("/sys/class/net/{name}"))?.ino()}),
            )?;
        }
        let prefix = env.prefix.to_str().context("readiness prefix encoding")?;
        let snapshot = probe(
            env,
            &[
                "native-return",
                &pid,
                prefix,
                initial_binding
                    .to_str()
                    .context("initial binding path encoding")?,
            ],
        )
        .await?;
        let observed: serde_json::Value = serde_json::from_slice(&snapshot.stdout)?;
        let resources = observed["receipt"]["resources"]
            .as_array()
            .context("real private receipt")?;
        let tap = resources
            .iter()
            .find(|item| item["role"] == "private-tap")
            .context("real private TAP")?;
        ensure!(
            tap["identity"]["mtu"] == 65521
                && tap["identity"]["max_physical_ip_mtu"] == 65535
                && tap["identity"]["max_original_frame_bytes"] == 65557,
            "full-size private/physical geometry absent"
        );
        let links = observed["links"].as_array().context("live return links")?;
        for device in &runtime.devices {
            let link = links
                .iter()
                .find(|link| link["ifindex"].as_u64() == Some(u64::from(device.info.ifindex)))
                .context("actual physical link readback")?;
            ensure!(link["mtu"] == 65535, "physical jumbo MTU reduced");
        }
        let btf = command("sha256sum", &["/sys/kernel/btf/vmlinux"]).await?;
        artifacts(
            &env.prefix.with_extension("startup-geometry.json"),
            &serde_json::json!({
            "page_size":unsafe { libc::sysconf(libc::_SC_PAGESIZE) },
            "possible_cpus":std::fs::read_to_string("/sys/devices/system/cpu/possible")?,
            "running_btf_bytes":std::fs::metadata("/sys/kernel/btf/vmlinux")?.len(),
            "running_btf_sha256":String::from_utf8(btf.stdout)?.split_whitespace().next().context("running BTF hash")?,
            "links":links}),
        )?;
        std::fs::write(
            format!("{}.native-return.json", env.prefix.display()),
            &snapshot.stdout,
        )?;
        Ok(())
    }

    fn pin_identities(root: &Path) -> anyhow::Result<Vec<(PathBuf, (u32, u32))>> {
        pinned_files(root)?
            .into_iter()
            .map(|path| {
                let fd = crate::xdp::host::sys::open_pin(&path, 0)?;
                let identity = crate::xdp::host::sys::identity(std::os::fd::AsFd::as_fd(&fd))?;
                Ok((path, identity))
            })
            .collect()
    }

    fn observed_runtime_drop(runtime: Runtime, env: &Environment) -> anyhow::Result<()> {
        #[derive(Clone, Default)]
        struct DropErrors(Arc<parking_lot::Mutex<Vec<u8>>>);
        impl std::io::Write for DropErrors {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let errors = DropErrors::default();
        let writer = errors.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || drop(runtime));
        let errors = errors.0.lock().clone();
        std::fs::write(env.prefix.with_extension("runtime-drop.log"), &errors)?;
        ensure!(
            errors.is_empty(),
            "actual Runtime Drop reported an error: {}",
            String::from_utf8_lossy(&errors)
        );
        Ok(())
    }

    async fn joined_close(mut fixture: Fixture, env: &Environment) -> anyhow::Result<()> {
        let joined = async {
            let runtime = &mut fixture.runtime;
            runtime.close_capture().context("Runtime::close_capture")?;
            let mut warned = false;
            let timer = None;
            tokio::pin!(timer);
            let notification = runtime.polling.notification();
            tokio::pin!(notification);
            let (plane, result) = join_endpoints(
                &mut fixture.owner,
                |cx| {
                    runtime.poll_service(
                        cx,
                        &fixture.shutdown,
                        timer.as_mut(),
                        false,
                        notification.as_mut(),
                    )
                },
                Instant::now(),
                &mut warned,
            )
            .await
            .context("join_endpoints")??;
            result?;
            drain_transmit(|| runtime.complete_transmit(), Instant::now(), &mut warned)
                .await
                .context("Runtime CQ drain_transmit")?;
            runtime
                .drain_native_originals()
                .context("Runtime::drain_native_originals")?;
            ensure!(
                runtime.ports_ready_for_backend_teardown(),
                "actual Port owners not joined before queue take"
            );
            for device in &mut runtime.devices {
                ensure!(
                    honk_xsk::xdp_state(device.info.ifindex)?.prog_id
                        == device.programs.discover_prog_id(),
                    "actual physical guard not installed"
                );
                for queue in device.queues.drain(..) {
                    let mut port = queue.io.into_inner();
                    ensure!(
                        port.retained_rx_count() == 0 && port.rx_completion_count() == 0,
                        "original chain or generation not joined"
                    );
                    ensure!(
                        port.counters().submitted == port.counters().completed
                            && port.close().ready_for_backend_teardown(),
                        "Port ledger not joined"
                    );
                    port.close_socket();
                }
            }
            runtime.native.as_ref().unwrap().retire_closed_claims()?;
            plane
                .policy_backend_handle()
                .write()
                .await
                .cleanup()
                .await?;
            runtime
                .finalize_native_recording()
                .context("Runtime::finalize_native_recording")?;
            let exported = runtime
                .native
                .as_ref()
                .unwrap()
                .export_recording(true, true);
            ensure!(
                exported.status.as_str() == "PUBLISHED_DURABLE"
                    && exported.error.is_none()
                    && exported.final_export
                    && exported.complete,
                "real joined Native publication export is incomplete: {exported:?}"
            );
            let publication_path = exported
                .path
                .as_ref()
                .context("actual Native publication artifact path")?;
            let publication_bytes = std::fs::read(publication_path)?;
            let publication_digest = Sha256::digest(&publication_bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            ensure!(
                exported.sha256.as_deref() == Some(publication_digest.as_str()),
                "published artifact digest differs"
            );
            std::fs::copy(
                publication_path,
                env.prefix.with_extension("publication.json"),
            )?;
            let publication: serde_json::Value = serde_json::from_slice(&publication_bytes)?;
            Ok::<_, anyhow::Error>(publication)
        }
        .await;
        let publication = match joined {
            Ok(publication) => publication,
            Err(error) => {
                fixture
                    .runtime
                    .diagnostics
                    .lifecycle(Lifecycle::FailedRetained);
                std::mem::forget(fixture);
                return Err(error);
            }
        };

        let devices: Vec<_> = fixture
            .runtime
            .devices
            .iter()
            .map(|device| {
                (
                    device.info.name.clone(),
                    device.info.ifindex,
                    device.programs.discover_prog_id(),
                )
            })
            .collect();
        let pins_before_drop = pin_identities(&env.pins)?;
        fixture.runtime.diagnostics.lifecycle(Lifecycle::Closed);
        observed_runtime_drop(fixture.runtime, env)?;
        ensure!(
            pin_identities(&env.pins)? == pins_before_drop,
            "Runtime Drop changed owned recovery pin identities before cleanup"
        );
        for (_, ifindex, guard) in &devices {
            ensure!(
                honk_xsk::xdp_state(*ifindex)?.prog_id == *guard,
                "Runtime Drop lost an owned physical guard"
            );
        }
        joined_map_identity_negatives(env, &publication).await?;

        let prefix = env.prefix.to_str().context("artifact path encoding")?;
        let output = probe(env, &["native-cleanup", prefix, "dut0", "dut1"]).await?;
        let cleanup: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        ensure!(
            cleanup["status"] == "removed",
            "shared joined cleanup did not remove exact owned pins"
        );
        for (name, ifindex, _) in devices {
            let identity: serde_json::Value = serde_json::from_slice(&std::fs::read(format!(
                "{}.{name}.identity.json",
                env.prefix.display()
            ))?)?;
            ensure!(
                identity["ifindex"].as_u64() == Some(u64::from(ifindex))
                    && ifindex == nix::net::if_::if_nametoindex(name.as_str())?
                    && identity["sysfs_inode"].as_u64()
                        == Some(std::fs::metadata(format!("/sys/class/net/{name}"))?.ino()),
                "joined cleanup replaced an operator device"
            );
            ensure!(
                honk_xsk::xdp_absent(ifindex)?,
                "physical XDP attachment survived joined cleanup"
            );
            probe(env, &["native-gate", &name, "0", "none"]).await?;
            ensure!(
                !env.pins.join(format!("xdp-{ifindex}")).exists(),
                "owned physical pin directory survived joined cleanup"
            );
        }
        ensure!(
            pinned_files(&env.pins)?.is_empty(),
            "private operation/program pins survived joined cleanup"
        );
        artifacts(
            &env.prefix.with_extension("joined.json"),
            &serde_json::json!({"cleanup":cleanup,"phase":"joined","primitive":"IPv4 UDP small/full-SG", "source_sha":env!("HONK_SOURCE_SHA")}),
        )?;
        Ok(())
    }

    struct OperatorSetup {
        mtus: Vec<(&'static str, &'static str, String)>,
        rps: Vec<(PathBuf, String)>,
        affinity: libc::cpu_set_t,
        owner_cpu: usize,
        rps_cpu: usize,
        qdisc_before: serde_json::Value,
    }

    fn rps_received(cpu: usize) -> anyhow::Result<u64> {
        let text = std::fs::read_to_string("/proc/net/softnet_stat")?;
        let line = text
            .lines()
            .nth(cpu)
            .context("actual RPS target CPU softnet row missing")?;
        let value = line
            .split_whitespace()
            .nth(9)
            .context("actual softnet received_rps field missing")?;
        Ok(u64::from_str_radix(value, 16)?)
    }

    impl OperatorSetup {
        async fn prepare(env: &Environment) -> anyhow::Result<Self> {
            let mut affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            ensure!(
                unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut affinity) }
                    == 0,
                "actual owner CPU affinity readback failed"
            );
            let cpus: Vec<_> = (0..libc::CPU_SETSIZE as usize)
                .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &affinity) })
                .collect();
            ensure!(
                cpus.len() >= 2,
                "NOT_EXERCISED: remote original-target RPS requires two allowed online CPUs"
            );
            let (owner_cpu, rps_cpu) = (cpus[0], cpus[1]);
            let mut owner: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::CPU_SET(owner_cpu, &mut owner);
            }
            ensure!(
                unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &owner) } == 0,
                "actual return owner CPU pin failed"
            );
            let output = command(
                "ip",
                &["-n", "client", "-d", "-j", "link", "show", "dev", "c0"],
            )
            .await?;
            let client: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            ensure!(
                client[0]["num_tx_queues"]
                    .as_u64()
                    .is_some_and(|queues| queues >= 2),
                "NOT_EXERCISED: actual c0 has fewer than two TX queues"
            );
            let output = command(
                "ip",
                &[
                    "netns", "exec", "client", "tc", "-j", "qdisc", "show", "dev", "c0",
                ],
            )
            .await?;
            let qdisc_before: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            ensure!(
                qdisc_before
                    .as_array()
                    .context("actual client qdisc inventory")?
                    .iter()
                    .all(|item| item["kind"] == "noqueue"),
                "NOT_EXERCISED: client c0 has an unowned root qdisc"
            );
            command(
                "ip",
                &[
                    "netns", "exec", "client", "tc", "qdisc", "add", "dev", "c0", "root", "handle",
                    "7a01:", "mqprio", "num_tc", "2", "map", "0", "1", "0", "0", "0", "0", "0",
                    "0", "0", "0", "0", "0", "0", "0", "0", "0", "queues", "1@0", "1@1", "hw", "0",
                ],
            )
            .await?;
            let mut rps = Vec::new();
            let mut words = vec![0u32; rps_cpu / 32 + 1];
            words[rps_cpu / 32] = 1u32 << (rps_cpu % 32);
            let mask = words
                .iter()
                .rev()
                .map(|word| format!("{word:08x}"))
                .collect::<Vec<_>>()
                .join(",");
            let mut queues = 0;
            for entry in std::fs::read_dir("/sys/class/net/dut0/queues")? {
                let entry = entry?;
                if !entry.file_name().as_encoded_bytes().starts_with(b"rx-") {
                    continue;
                }
                queues += 1;
                for (field, requested) in [("rps_cpus", mask.as_str()), ("rps_flow_cnt", "0")] {
                    let path = entry.path().join(field);
                    let previous = std::fs::read_to_string(&path)?;
                    std::fs::write(&path, requested)?;
                    let actual = std::fs::read_to_string(&path)?;
                    if field == "rps_cpus" {
                        let observed = actual
                            .trim()
                            .split(',')
                            .rev()
                            .map(|word| u32::from_str_radix(word, 16))
                            .collect::<Result<Vec<_>, _>>()?;
                        ensure!(
                            observed.iter().enumerate().all(|(index, &word)| word
                                == if index == rps_cpu / 32 {
                                    1 << (rps_cpu % 32)
                                } else {
                                    0
                                }),
                            "actual physical RPS mask differs from one remote CPU"
                        );
                    } else {
                        ensure!(
                            actual.trim() == "0",
                            "actual physical RFS table was not disabled"
                        );
                    }
                    rps.push((path, previous));
                }
            }
            ensure!(
                queues >= 2,
                "NOT_EXERCISED: actual dut0 has fewer than two RX queues"
            );
            let mut mtus = Vec::new();
            let mut jumbo_links = Vec::new();
            for (namespace, device) in [
                ("dut", "dut0"),
                ("dut", "dut1"),
                ("client", "c0"),
                ("server", "s0"),
            ] {
                let output = command(
                    "ip",
                    &["-n", namespace, "-j", "link", "show", "dev", device],
                )
                .await?;
                let links: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                let mtu = links[0]["mtu"]
                    .as_u64()
                    .context("operator MTU readback")?
                    .to_string();
                mtus.push((namespace, device, mtu));
                command(
                    "ip",
                    &[
                        "-n", namespace, "link", "set", "dev", device, "mtu", "65535",
                    ],
                )
                .await?;
                let output = command(
                    "ip",
                    &["-n", namespace, "-d", "-j", "link", "show", "dev", device],
                )
                .await?;
                let actual: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                ensure!(
                    actual.as_array().is_some_and(|links| links.len() == 1)
                        && actual[0]["mtu"] == 65535,
                    "actual operator jumbo MTU differs"
                );
                jumbo_links.push(
                    serde_json::json!({"namespace":namespace,"device":device,"link":actual[0]}),
                );
            }
            artifacts(
                &env.prefix.with_extension("operator-jumbo.json"),
                &serde_json::json!({"links":jumbo_links}),
            )?;
            Ok(Self {
                mtus,
                rps,
                affinity,
                owner_cpu,
                rps_cpu,
                qdisc_before,
            })
        }

        async fn restore(self, env: &Environment) -> anyhow::Result<()> {
            let current = command(
                "ip",
                &[
                    "netns", "exec", "client", "tc", "-j", "qdisc", "show", "dev", "c0",
                ],
            )
            .await?;
            let current: serde_json::Value = serde_json::from_slice(&current.stdout)?;
            ensure!(
                current
                    .as_array()
                    .context("owned mqprio readback")?
                    .iter()
                    .any(|item| item["kind"] == "mqprio" && item["handle"] == "7a01:"),
                "owned mqprio changed before removal"
            );
            command(
                "ip",
                &[
                    "netns", "exec", "client", "tc", "qdisc", "del", "dev", "c0", "root", "handle",
                    "7a01:",
                ],
            )
            .await?;
            let restored = command(
                "ip",
                &[
                    "netns", "exec", "client", "tc", "-j", "qdisc", "show", "dev", "c0",
                ],
            )
            .await?;
            let restored: serde_json::Value = serde_json::from_slice(&restored.stdout)?;
            ensure!(
                restored
                    .as_array()
                    .context("restored qdisc readback")?
                    .iter()
                    .all(|item| item["kind"] == "noqueue"),
                "actual client qdisc did not restore"
            );
            for (path, previous) in &self.rps {
                std::fs::write(path, previous)?;
                ensure!(
                    std::fs::read_to_string(path)? == *previous,
                    "physical RPS/RFS restore mismatch"
                );
            }
            for (namespace, device, mtu) in &self.mtus {
                command(
                    "ip",
                    &["-n", namespace, "link", "set", "dev", device, "mtu", mtu],
                )
                .await?;
            }
            ensure!(
                unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &self.affinity) }
                    == 0,
                "owner CPU affinity restore failed"
            );
            artifacts(
                &env.prefix.with_extension("operator-restored.json"),
                &serde_json::json!({"qdisc_before":self.qdisc_before,"owned_qdisc":current,"qdisc_after":restored,
                "physical_rps_restored":self.rps,"mtus_restored":self.mtus,"owner_cpu":self.owner_cpu,"original_target_rps_cpu":self.rps_cpu}),
            )
        }
    }

    pub(super) async fn positive() -> anyhow::Result<()> {
        guard("dut")?;
        let env = environment("positive")?;
        let operator = OperatorSetup::prepare(&env).await?;
        let mut fixture = start(&env).await?;
        let result = async {
            save_readiness(&env, &fixture.runtime).await?;
            let mut peer = PeerOwner::start(&env).await?;
            let mut samples = Vec::new();
            for (name, size, port, sequence) in [("small", 32, 43186, 100), ("jumbo", 65507, 43187, 200)] {
                fixture.flags.set_mode("Global").await?;
                let captured_epoch = fixture.runtime.native.as_ref().unwrap().selection_epoch().context("capture root closed")?;
                let first_name = format!("{name}-first");
                let first_wire = peer.send(&first_name, size, port, sequence).await?;
                wait_rx(&fixture.runtime).await?;
                // The actual descriptor is published while Global still captures; no import has run.
                fixture.flags.set_mode("Rule").await?;
                let selected_epoch = fixture.runtime.native.as_ref().unwrap().selection_epoch().context("final Direct root closed")?;
                ensure!(selected_epoch > captured_epoch, "normal mode publication did not advance");
                ensure!(intake(&mut fixture.runtime, None)? == 1, "first physical original did not enter the production Runtime owner");
                let first = held_snapshot(&fixture.runtime, 0, &first_wire)?;
                ensure!(first.imported.producer.epoch == captured_epoch && first.imported.executor == NATIVE_EXECUTOR_PENDING,
                    "sample was not capture-before-publication/import-after");
                ensure!(first.segments == if size == 65507 { 18 } else { 1 }, "full physical SG extent not exercised");
                ensure!(first.imported.producer.flags == NATIVE_IMPORT_COUNTED, "first actual producer did not reserve its credit");
                let rps_before = rps_received(operator.rps_cpu)?;
                ensure!(unsafe { libc::sched_getcpu() } == operator.owner_cpu as libc::c_int, "actual return owner left its pinned CPU");
                let before = start_production_flight(&mut fixture.runtime, &first)?;
                let armed = fixture.runtime.native.as_ref().unwrap().claim(&first.imported.identity.key)?.context("armed claim absent")?;
                ensure!(armed.executor == NATIVE_EXECUTOR_KERNEL && armed.state & 15 == NATIVE_PHASE_ARMED && armed.state >> 4 == 1,
                    "first flight opened Active before entry and fresh Grace");
                let mut followers = Vec::new();
                let mut actual_queues = vec![fixture.runtime.devices[first.device].queues[first.queue].id];
                for index in 0..2 {
                    let label = format!("{name}-follower-{index}");
                    let wire = peer.send(&label, size, port, sequence + index + 1).await?;
                    wait_rx(&fixture.runtime).await?;
                    ensure!(intake(&mut fixture.runtime, None)? == 1, "actual follower did not enter the production FIFO");
                    let follower = held_snapshot(&fixture.runtime, index as usize + 1, &wire)?;
                    ensure!(follower.imported.identity == first.imported.identity && follower.segments == first.segments, "follower changed claim/whole SG");
                    ensure!(follower.imported.producer.flags == NATIVE_IMPORT_COUNTED, "actual Armed follower did not own one producer credit");
                    actual_queues.push(fixture.runtime.devices[follower.device].queues[follower.queue].id);
                    followers.push((label, follower, wire));
                }
                actual_queues.sort_unstable();
                actual_queues.dedup();
                ensure!(actual_queues.len() >= 2, "NOT_EXERCISED: actual same-claim retained followers did not reach two RX queues");
                ensure!(fixture.runtime.native.as_ref().unwrap().claim(&first.imported.identity.key)?.unwrap().state >> 4 == 3, "Armed followers bypassed their individual reservations");
                let first_receipt = finish_production_original(&mut fixture.runtime, &first, "Transferred", 2, 3, 2, NATIVE_PHASE_DRAINING).await?;
                ensure!(first_receipt["op_incarnation"].as_str() == Some(before["op_incarnation"].as_u64().context("first flight operation")?.to_string().as_str()), "Runtime first completion changed its actual private operation");
                let rps_after = rps_received(operator.rps_cpu)?;
                ensure!(rps_after > rps_before, "NOT_EXERCISED: remote original-target received_rps backlog counter did not advance");
                let draining = fixture.runtime.native.as_ref().unwrap().claim(&first.imported.identity.key)?.context("actual first settled owner")?;
                let first_linux = peer.observe(&first_name, 1, 1).await?;
                let mut releases = Vec::new();
                let mut active = draining;
                let mut previous_operation = decimal(&first_receipt, "op_incarnation")?;
                for (index, (label, follower, wire)) in followers.iter().enumerate() {
                    ensure!(first_receipt["fresh_grace"] == true && decimal(&first_receipt, "entry_seq")? != 0, "follower began before first entry and new Grace");
                    let started = start_production_flight(&mut fixture.runtime, follower)?;
                    let remaining = followers.len() - index - 1;
                    let phase = if remaining == 0 { NATIVE_PHASE_ACTIVE } else { NATIVE_PHASE_DRAINING };
                    let observed = finish_production_original(&mut fixture.runtime, follower, "Transferred", remaining,
                        remaining as u32 + 1, remaining as u32, phase).await?;
                    let operation = decimal(&observed, "op_incarnation")?;
                    ensure!(operation > previous_operation && started["op_incarnation"].as_u64() == Some(operation), "Runtime follower flight incarnation reused or replaced");
                    previous_operation = operation;
                    active = fixture.runtime.native.as_ref().unwrap().claim(&follower.imported.identity.key)?.context("actual follower settled owner")?;
                    let linux = peer.observe(label, 1, 1).await?;
                    releases.push(serde_json::json!({"source":wire,"rx_queue":fixture.runtime.devices[follower.device].queues[follower.queue].id,
                        "retained_sha256":follower.digest,"operation":observed,"linux":linux,"count_after":active.state >> 4,"first_fresh_grace_before_release":true}));
                }
                ensure!(active.executor == NATIVE_EXECUTOR_KERNEL && active.state == NATIVE_PHASE_ACTIVE, "Active preceded actual full-chain completion/count zero");
                for device in &fixture.runtime.devices { for queue in &device.queues {
                    ensure!(queue.io.get_ref().retained_rx_count() == 0 && queue.io.get_ref().rx_completion_count() == 0, "Port chain/generation leaked");
                } }
                let active_name = format!("{name}-active");
                peer.send(&active_name, size, port, sequence + 3).await?;
                let active_linux = peer.observe(&active_name, 1, 1).await?;
                ensure!(fixture.runtime.devices.iter().flat_map(|device| &device.queues).all(|queue| {
                    let rings = queue.io.get_ref().rings(); rings.rx_producer == rings.rx_consumer
                }), "Active input was captured again");
                samples.push(serde_json::json!({"primitive":"IPv4 UDP", "name":name, "source":first_wire,
                    "retained_sha256":first.digest,"segments":first.segments,"captured_epoch":captured_epoch,"import_after_epoch":selected_epoch,
                    "first":first_receipt,"first_linux":first_linux,"followers":releases,"actual_rx_queues":actual_queues,
                    "owner_cpu":operator.owner_cpu,"original_target_rps_cpu":operator.rps_cpu,"received_rps_before":rps_before,"received_rps_after":rps_after,
                    "active_linux":active_linux,"count_before":3,"count_after_first":draining.state >> 4,"count_after":active.state >> 4}));
            }
            let production = production_first_consumer(&mut fixture, &mut peer).await?;
            let source_hold = production_source_hold(&mut fixture, &mut peer).await?;
            let committed = native_committed_executors_never_return_original(&mut fixture, &mut peer).await?;
            let candidate_proof = candidate_proof_rejects_another_candidate(&mut fixture, &mut peer).await?;
            let horizon = production_original_horizon(&mut fixture, &mut peer).await?;
            let exhausted = production_candidate_exhaustion(&mut fixture, &mut peer).await?;
            peer.join().await?;
            artifacts(&env.prefix.with_extension("samples.json"), &serde_json::json!({"samples":samples,"production_first_consumer":production,"production_source_hold":source_hold,"committed_capture":committed,
                "candidate_proof":candidate_proof,"original_horizon":horizon,"candidate_exhaustion":exhausted,
                "captured_reverse_nat_reply":{"status":"NOT_RUN","reason":"M25: Transit import cannot authenticate CT-ORIGINAL-keyed reverse/translated input; seam extension pending user decision"},
                "scope":"IPv4 UDP primitive only; no daemon matrix or physical ZC claim"}))?;
            Ok::<(), anyhow::Error>(())
        }.await;
        if result.is_err() {
            fixture
                .runtime
                .diagnostics
                .lifecycle(Lifecycle::FailedRetained);
            std::mem::forget(fixture);
            return result;
        }
        joined_close(fixture, &env).await?;
        operator.restore(&env).await?;
        Ok(())
    }

    async fn reload_default_must(
        fixture: &mut Fixture,
        must: bool,
        request_id: u64,
    ) -> anyhow::Result<u64> {
        let mut candidate = (**fixture.config.read().await).clone();
        candidate.routing.default_must = must;
        let epoch = reload_policy(fixture, candidate, request_id).await?;
        ensure!(
            fixture.config.read().await.routing.default_must == must,
            "accepted must policy differs"
        );
        Ok(epoch)
    }

    async fn reload_policy(
        fixture: &mut Fixture,
        candidate: Config,
        request_id: u64,
    ) -> anyhow::Result<u64> {
        let (result, mut reply) = tokio::sync::oneshot::channel();
        fixture
            .commands
            .send(crate::control::ControlCommand::ReloadConfig {
                request_id,
                config: Box::new(candidate),
                diagnostics: Vec::new(),
                #[cfg(feature = "native-api")]
                sources: None,
                #[cfg(feature = "native-api")]
                expected_group_revision: None,
                result,
            })
            .await?;
        let timer = None;
        tokio::pin!(timer);
        let applied = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                tokio::select! {
                    applied = &mut reply => break applied.context("actual source-hold reload reply disappeared"),
                    () = poll_fn(|cx| fixture.runtime.poll_scopes(cx, timer.as_mut())) => tokio::task::yield_now().await,
                }
            }
        }).await.context("actual source-hold routing publication did not commit")??;
        ensure!(
            matches!(
                applied.outcome,
                crate::control::ReloadOutcome::Committed { .. }
            ),
            "source-hold routing publication rejected/degraded: {:?}",
            applied.outcome
        );
        ensure!(
            fixture.runtime.originals.is_empty()
                && fixture.runtime.remote_originals.is_empty()
                && fixture.runtime.workers.native.is_empty(),
            "routing reload imported an original before publication"
        );
        fixture
            .runtime
            .native
            .as_ref()
            .unwrap()
            .selection_epoch()
            .context("accepted must publication did not open")
    }

    async fn production_source_hold(
        fixture: &mut Fixture,
        peer: &mut PeerOwner,
    ) -> anyhow::Result<serde_json::Value> {
        let realm = fixture
            .runtime
            .realms
            .iter()
            .find(|realm| fixture.runtime.devices[realm.device].info.name == "dut0")
            .context("actual LAN source scope missing")?;
        let authority = fixture.runtime.devices[realm.device].capture.authority;
        let scope = realm.driver.scope();
        let address = "192.0.2.2".parse()?;
        let destination: SocketAddr = "198.51.100.2:53".parse()?;
        let old_source: SocketAddr = "192.0.2.2:43190".parse()?;
        let fresh_source: SocketAddr = "192.0.2.2:43191".parse()?;
        let mut work = Some(
            fixture
                .runtime
                .endpoints
                .hold_native_source_for_test(scope, address)?,
        );
        ensure!(
            fixture
                .runtime
                .endpoints
                .retains(scope, fresh_source, destination, 17)
                && !fixture.runtime.endpoints.retained_transport(
                    scope,
                    fresh_source,
                    destination,
                    17
                ),
            "actual SourceWork did not distinguish source-wide from exact transport custody"
        );
        let publication = fixture.runtime.native.as_ref().unwrap().clone();
        let mut samples = Vec::new();
        for (held, source, label, sequence, request) in [
            (true, old_source, "source-held", 600, 11),
            (false, fresh_source, "source-released", 601, 13),
        ] {
            let key = crate::xdp::native::key(
                PacketView::from_slice(&datagram(source, destination, &[])),
                authority,
            )?;
            if !held {
                drop(work.take());
                ensure!(
                    !fixture
                        .runtime
                        .endpoints
                        .retains(scope, source, destination, 17)
                        && !fixture.runtime.endpoints.retained_transport(
                            scope,
                            source,
                            destination,
                            17
                        ),
                    "fresh port remained owned after actual SourceWork release"
                );
                reload_default_must(fixture, false, 12).await?;
            }
            fixture.flags.set_mode("Global").await?;
            let producing_epoch = publication
                .selection_epoch()
                .context("DNS capture publication closed")?;
            let wire = peer.send_to(label, 32, source.port(), sequence, 53).await?;
            wait_rx(&fixture.runtime).await?;
            ensure!(
                !fixture
                    .runtime
                    .endpoints
                    .retained_transport(scope, source, destination, 17)
                    && fixture
                        .runtime
                        .endpoints
                        .retains(scope, source, destination, 17)
                        == held,
                "source-hold sample acquired an exact transport before selection"
            );
            let published_epoch = reload_default_must(fixture, true, request).await?;
            ensure!(
                published_epoch > producing_epoch,
                "literal Direct(must) was not published after actual capture"
            );
            let claim = tokio::time::timeout(
                Duration::from_secs(8),
                poll_fn(|cx| {
                    match fixture.runtime.poll_io(cx, None, &fixture.shutdown, false) {
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) | Poll::Pending => {}
                    }
                    let claim = match publication.claim(&key) {
                        Ok(claim) => claim,
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    let expected = if held {
                        (NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED)
                    } else {
                        (NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ACTIVE)
                    };
                    if let Some(claim) = claim
                        && (claim.executor, claim.state) == expected
                        && fixture.runtime.originals.is_empty()
                        && fixture.runtime.remote_originals.is_empty()
                        && fixture.runtime.workers.native.is_empty()
                        && fixture.runtime.captured.as_ref().unwrap().is_idle()
                    {
                        return Poll::Ready(Ok(claim));
                    }
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }),
            )
            .await
            .context("actual Runtime failed source-wide hold/release selection")??;
            ensure!(
                claim.scope == scope.as_u64(),
                "source-hold claim escaped the known LAN scope"
            );
            for device in &fixture.runtime.devices {
                for queue in &device.queues {
                    ensure!(
                        queue.io.get_ref().retained_rx_count() == 0
                            && queue.io.get_ref().rx_completion_count() == 0,
                        "source-hold original did not complete its real Port generation"
                    );
                }
            }
            let exported = publication.export_recording(false, false);
            ensure!(
                exported.status.as_str() == "PUBLISHED_DURABLE" && exported.error.is_none(),
                "actual source-hold evidence export failed"
            );
            let document: serde_json::Value = serde_json::from_slice(&std::fs::read(
                exported.path.context("source-hold evidence path")?,
            )?)?;
            ensure!(
                decimal(&document, "captured_receipts_evicted")? == 0,
                "source-hold captured receipts were evicted"
            );
            for field in [
                "recording_error",
                "clock_error",
                "accounting_error",
                "counter_overflow",
                "export_error",
            ] {
                ensure!(document[field] == false, "source-hold evidence has {field}");
            }
            let identity = NativeClaimIdentity {
                key,
                epoch: claim.epoch,
                incarnation: claim.incarnation,
                scope: scope.as_u64(),
            };
            let receipts = original_receipts(&document, &identity)?;
            let imported: Vec<_> = receipts
                .iter()
                .filter(|item| item["kind"] == "IMPORTED")
                .collect();
            ensure!(
                imported.len() == 1
                    && decimal(imported[0], "producer_epoch")? == producing_epoch
                    && decimal(imported[0], "producer_incarnation")? == claim.incarnation
                    && decimal(imported[0], "producer_expires_boottime_ns")? != 0
                    && imported[0]["producer_flags"].as_u64()
                        == Some(u64::from(NATIVE_IMPORT_COUNTED)),
                "source-hold sample was not authenticated capture-before-publication/import-after"
            );
            let handle = imported[0]["completion_handle"]
                .as_array()
                .context("source-hold actual Port completion handle")?;
            ensure!(handle.len() == 4, "source-hold Port handle extent changed");
            for (index, part) in handle.iter().enumerate() {
                let part: u64 = part
                    .as_str()
                    .context("source-hold decimal Port handle component")?
                    .parse()?;
                ensure!(
                    index == 2 || part != 0,
                    "source-hold Port identity or generation is zero"
                );
            }
            let finished: Vec<_> = receipts
                .iter()
                .filter(|item| item["kind"] == "ORIGINAL_FINISHED")
                .collect();
            ensure!(
                finished.len() == 1
                    && decimal(imported[0], "seq")? < decimal(finished[0], "seq")?
                    && decimal(finished[0], "producer_epoch")? == producing_epoch
                    && decimal(finished[0], "producer_incarnation")? == claim.incarnation
                    && decimal(finished[0], "producer_expires_boottime_ns")?
                        == decimal(imported[0], "producer_expires_boottime_ns")?
                    && finished[0]["producer_flags"].as_u64()
                        == Some(u64::from(NATIVE_IMPORT_COUNTED))
                    && finished[0]["completion_handle"] == imported[0]["completion_handle"],
                "actual source-hold Runtime path did not bind the matching takeover/return completion and Port generation"
            );
            let endpoint_accepted_originals = finished
                .iter()
                .filter(|item| item["outcome"] == "TakenOver")
                .count();
            let transferred_originals = finished
                .iter()
                .filter(|item| item["outcome"] == "Transferred")
                .count();
            ensure!(
                (endpoint_accepted_originals, transferred_originals)
                    == (usize::from(held), usize::from(!held)),
                "source-hold original did not reach exactly its selected custody outcome"
            );
            ensure!(
                decimal(finished[0], "count_before")? == 1
                    && decimal(finished[0], "count_after")? == 0
                    && finished[0]["phase_after"].as_u64() == Some(u64::from(claim.state & 15))
                    && decimal(finished[0], "inventory_held")? == 0
                    && decimal(finished[0], "inventory_pending")? == 0
                    && decimal(finished[0], "inventory_flight")? == 0,
                "actual source-hold completion did not settle its exact credit/inventory"
            );
            let prepared = receipts
                .iter()
                .any(|item| item["kind"] == "OPERATION_PREPARED");
            ensure!(
                prepared != held,
                "Runtime source-wide exclusion was replaced with an exact transport-only check"
            );
            if !held {
                ensure!(
                    finished[0]["fresh_grace"] == true && decimal(finished[0], "entry_seq")? != 0,
                    "released source lacks matching entry and new Grace"
                );
                let operation = decimal(finished[0], "op_incarnation")?;
                ensure!(operation != 0, "released source operation identity is zero");
                let mut previous = decimal(imported[0], "seq")?;
                for kind in [
                    "OPERATION_PREPARED",
                    "ENTRY_ACQUIRED",
                    "FRESH_GRACE_STARTED",
                    "FRESH_GRACE_DONE",
                    "ORIGINAL_FINISHED",
                ] {
                    let entries: Vec<_> = receipts
                        .iter()
                        .filter(|item| {
                            item["kind"] == kind
                                && item["op_incarnation"] == finished[0]["op_incarnation"]
                        })
                        .collect();
                    ensure!(
                        entries.len() == 1 && decimal(entries[0], "seq")? > previous,
                        "released source operation receipt order differs at {kind}"
                    );
                    previous = decimal(entries[0], "seq")?;
                }
            }
            let linux = peer
                .observe(label, usize::from(!held), usize::from(!held))
                .await?;
            samples.push(serde_json::json!({"source_work_live":held,"exact_transport_before":false,"source":wire,
                "capture_epoch":producing_epoch,"must_publication_epoch":published_epoch,"executor":claim.executor,
                "phase":claim.state & 15,"outstanding":claim.state >> 4,"endpoint_accepted_originals":endpoint_accepted_originals,
                "transferred_originals":transferred_originals,
                "receipts":receipts,"linux":linux}));
        }
        reload_default_must(fixture, false, 14).await?;
        Ok(
            serde_json::json!({"destination":"198.51.100.2:53","literal_direct_must":true,"samples":samples}),
        )
    }

    async fn production_first_consumer(
        fixture: &mut Fixture,
        peer: &mut PeerOwner,
    ) -> anyhow::Result<serde_json::Value> {
        let realm = fixture
            .runtime
            .realms
            .iter()
            .find(|realm| fixture.runtime.devices[realm.device].info.name == "dut0")
            .context("actual LAN capture scope missing")?;
        let authority = fixture.runtime.devices[realm.device].capture.authority;
        let scope = realm.driver.scope();
        let key = crate::xdp::native::key(
            PacketView::from_slice(&datagram(
                "192.0.2.2:43189".parse()?,
                "198.51.100.2:18086".parse()?,
                &[],
            )),
            authority,
        )?;
        fixture.flags.set_mode("Global").await?;
        let publication = fixture.runtime.native.as_ref().unwrap().clone();
        let captured_epoch = publication
            .selection_epoch()
            .context("production capture publication closed")?;
        let source = peer.send("production-original", 64, 43189, 500).await?;
        wait_rx(&fixture.runtime).await?;
        let before = fixture.stats.udp_snapshot();
        fixture.flags.set_mode("Rule").await?;
        let import_epoch = publication
            .selection_epoch()
            .context("production Direct publication closed")?;
        ensure!(
            import_epoch > captured_epoch,
            "production import did not follow actual mode publication"
        );
        let (key, claim) = tokio::time::timeout(
            Duration::from_secs(8),
            poll_fn(|cx| {
                match fixture.runtime.poll_io(cx, None, &fixture.shutdown, false) {
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) | Poll::Pending => {}
                }
                let claim = match publication.claim(&key) {
                    Ok(claim) => claim,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                if let Some(claim) = claim
                    && claim.executor == NATIVE_EXECUTOR_KERNEL
                    && claim.state == NATIVE_PHASE_ACTIVE
                    && fixture.runtime.originals.is_empty()
                    && fixture.runtime.remote_originals.is_empty()
                    && fixture.runtime.workers.native.is_empty()
                    && fixture.runtime.captured.as_ref().unwrap().is_idle()
                {
                    return Poll::Ready(Ok((key, claim)));
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }),
        )
        .await
        .context("actual Runtime first consumer did not reach entry/fresh-Grace/count-zero")??;
        ensure!(
            claim.scope == scope.as_u64(),
            "first-consumer claim escaped the known LAN scope"
        );
        ensure!(
            !fixture.runtime.endpoints.retained_transport(
                scope,
                "192.0.2.2:43189".parse()?,
                "198.51.100.2:18086".parse()?,
                17
            ),
            "production original reached a protocol/initializer before Native selection"
        );
        ensure!(
            fixture.runtime.core.is_none()
                && fixture.runtime.waiting.is_empty()
                && fixture.runtime.workers.peer_count() == 0,
            "production original mutated Core/Endpoint state"
        );
        let after = fixture.stats.udp_snapshot();
        ensure!(
            after.slow_permit_accepted == before.slow_permit_accepted
                && after.queue_accepted == before.queue_accepted
                && after.dial_latency.count == before.dial_latency.count
                && after.endpoint_misses == before.endpoint_misses,
            "production first consumer admitted or dialed a UDP Endpoint"
        );
        for device in &fixture.runtime.devices {
            for queue in &device.queues {
                ensure!(
                    queue.io.get_ref().retained_rx_count() == 0
                        && queue.io.get_ref().rx_completion_count() == 0,
                    "production original did not complete its real Port generation"
                );
            }
        }
        let exported = publication.export_recording(false, false);
        ensure!(
            exported.status.as_str() == "PUBLISHED_DURABLE" && exported.error.is_none(),
            "actual production evidence export failed"
        );
        let document: serde_json::Value = serde_json::from_slice(&std::fs::read(
            exported.path.context("production evidence path")?,
        )?)?;
        let identity = NativeClaimIdentity {
            key,
            epoch: claim.epoch,
            incarnation: claim.incarnation,
            scope: scope.as_u64(),
        };
        let receipts = original_receipts(&document, &identity)?;
        let mut ordered = Vec::new();
        let mut last = 0;
        for kind in [
            "IMPORTED",
            "OPERATION_PREPARED",
            "ENTRY_ACQUIRED",
            "FRESH_GRACE_STARTED",
            "FRESH_GRACE_DONE",
            "ORIGINAL_FINISHED",
        ] {
            let matching: Vec<_> = receipts
                .iter()
                .filter(|item| item["kind"] == kind)
                .collect();
            ensure!(
                matching.len() == 1,
                "production original lacks one exact {kind} receipt"
            );
            let sequence: u64 = matching[0]["seq"]
                .as_str()
                .context("actual receipt sequence")?
                .parse()?;
            ensure!(
                sequence > last,
                "production receipt ordering violated at {kind}"
            );
            last = sequence;
            ordered.push(matching[0]);
        }
        ensure!(
            ordered[0]["producer_epoch"].as_str() == Some(captured_epoch.to_string().as_str())
                && ordered[0]["completion_handle"] == ordered[5]["completion_handle"],
            "production import/completion no longer binds the captured Port generation"
        );
        ensure!(
            ordered[2]["entry_seq"].as_str() == Some("1")
                && ordered[4]["fresh_grace"] == true
                && ordered[5]["outcome"] == "Transferred"
                && ordered[1]["op_incarnation"] == ordered[5]["op_incarnation"],
            "production completion lacks exact entry/new-Grace operation association"
        );
        let linux = peer.observe("production-original", 1, 1).await?;
        Ok(
            serde_json::json!({"source":source,"captured_epoch":captured_epoch,"import_after_epoch":import_epoch,
            "key":format!("{key:?}"),"outstanding":claim.state >> 4,"phase":claim.state & 15,
            "endpoint_initializer_delta":after.slow_permit_accepted - before.slow_permit_accepted,
            "udp_dial_delta":after.dial_latency.count - before.dial_latency.count,"receipts":ordered,"linux":linux}),
        )
    }

    async fn candidate_proof_rejects_another_candidate(
        fixture: &mut Fixture,
        peer: &mut PeerOwner,
    ) -> anyhow::Result<serde_json::Value> {
        fixture.flags.set_mode("Global").await?;
        let wire = peer.send("candidate-proof", 48, 43200, 700).await?;
        wait_rx(&fixture.runtime).await?;
        ensure!(
            intake(&mut fixture.runtime, None)? == 1,
            "real candidate proof original did not enter Runtime"
        );
        let taken = held_snapshot(&fixture.runtime, 0, &wire)?;
        let publication = fixture.runtime.native.as_ref().unwrap().clone();
        let basis_epoch = publication
            .selection_epoch()
            .context("candidate proof publication closed")?;
        let first_token = fixture.runtime.next_candidate;
        let CapturedDecision::Endpoint(first) = classify_decision(&mut fixture.runtime, &taken)?
        else {
            anyhow::bail!("first real candidate did not choose Endpoint");
        };
        let second_token = fixture.runtime.next_candidate;
        let CapturedDecision::Endpoint(second) = classify_decision(&mut fixture.runtime, &taken)?
        else {
            anyhow::bail!("second real candidate did not choose Endpoint");
        };
        ensure!(
            first_token != second_token
                && publication.selection_epoch() == Some(basis_epoch)
                && first.basis().identity() == second.basis().identity(),
            "candidate proof control changed policy/claim instead of only candidate identity"
        );
        let CaptureCommit::Selected(proof) =
            publication.commit_capture(&taken.imported.identity, first.basis())?
        else {
            anyhow::bail!("real first Pending candidate did not mint a proof");
        };
        ensure!(
            proof.matches(first.basis()) && !proof.matches(second.basis()),
            "real proof is not bound to the exact first candidate"
        );
        let denied = match second.into_admission(proof) {
            Err(error) => error,
            Ok(_) => {
                anyhow::bail!("foreign real candidate consumed another candidate's Capture proof")
            }
        };
        ensure!(
            denied.kind() == io::ErrorKind::PermissionDenied,
            "foreign real candidate refusal reason changed"
        );
        drop(first);
        ensure!(
            !fixture.runtime.endpoints.retained_transport(
                fixture.runtime.realms[taken.realm].driver.scope(),
                "192.0.2.2:43200".parse()?,
                "198.51.100.2:18086".parse()?,
                17
            ),
            "candidate proof sample is not an actual cold transport"
        );
        let accepted_before = fixture.stats.udp_snapshot().queue_accepted;
        let finished = finish_production_original(
            &mut fixture.runtime,
            &taken,
            "TakenOver",
            0,
            1,
            0,
            NATIVE_PHASE_CAPTURE_COMMITTED,
        )
        .await?;
        ensure!(
            fixture.stats.udp_snapshot().queue_accepted == accepted_before,
            "cold candidate unexpectedly enqueued a follower"
        );
        let linux = peer.observe("candidate-proof", 0, 0).await?;
        Ok(
            serde_json::json!({"source":wire,"basis_epoch":basis_epoch,"first_candidate":first_token,"second_candidate":second_token,
            "refusal":denied.to_string(),"runtime_completion":finished,"linux":linux}),
        )
    }

    fn submit_fact(
        fixture: &Fixture,
        scope: ScopeId,
        snapshot: &Arc<crate::dns::projection::RoutingProjectionSnapshot>,
        expires: Option<tokio::time::Instant>,
    ) -> anyhow::Result<()> {
        use crate::dns::projection::ProjectionObservation;
        let addresses = ["198.51.100.2".parse()?];
        let observation = match expires {
            Some(expires_at) => ProjectionObservation::Positive {
                domain: "captured-horizon.test",
                family: honk_outbound::alive::IpVersion::V4,
                ips: &addresses,
                expires_at,
            },
            None => ProjectionObservation::ClearName {
                domain: "captured-horizon.test",
            },
        };
        ensure!(
            fixture.projection.try_submit(scope, snapshot, observation),
            "actual scoped DNS fact publication was busy or stale"
        );
        ensure!(
            fixture
                .runtime
                .native
                .as_ref()
                .unwrap()
                .selection_snapshot()
                .is_some(),
            "actual scoped DNS writer did not reopen"
        );
        Ok(())
    }

    async fn production_original_horizon(
        fixture: &mut Fixture,
        peer: &mut PeerOwner,
    ) -> anyhow::Result<serde_json::Value> {
        let saved_routing = fixture.config.read().await.routing.clone();
        let mut candidate = (**fixture.config.read().await).clone();
        candidate.routing = honk_config::parser::parse_dae_config(
            "routing { domain(full: captured-horizon.test) -> direct\n fallback: direct }",
        )?
        .routing;
        reload_policy(fixture, candidate, 20).await?;
        let generation = fixture.routing_diagnostics.read().generation;
        let matcher = Arc::new(fixture.router.read().await.clone());
        let snapshot = Arc::new(crate::dns::projection::RoutingProjectionSnapshot::new(
            generation, matcher,
        ));
        let scope = fixture
            .runtime
            .realms
            .iter()
            .find(|realm| fixture.runtime.devices[realm.device].info.name == "dut0")
            .context("actual horizon fact scope")?
            .driver
            .scope();
        let publication = fixture.runtime.native.as_ref().unwrap().clone();
        let mut samples = Vec::new();
        for (index, shortens) in [true, false].into_iter().enumerate() {
            submit_fact(fixture, scope, &snapshot, None)?;
            submit_fact(
                fixture,
                scope,
                &snapshot,
                Some(
                    tokio::time::Instant::now()
                        + Duration::from_secs(if shortens { 30 } else { 10 }),
                ),
            )?;
            fixture.flags.set_mode("Global").await?;
            let producer_epoch = publication
                .selection_epoch()
                .context("horizon capture publication closed")?;
            let label = if shortens {
                "horizon-fact-minimum"
            } else {
                "horizon-producer-minimum"
            };
            let wire = peer
                .send(label, 48, 43201 + index as u16, 702 + index as u16)
                .await?;
            wait_rx(&fixture.runtime).await?;
            if !shortens {
                submit_fact(fixture, scope, &snapshot, None)?;
            }
            submit_fact(
                fixture,
                scope,
                &snapshot,
                Some(
                    tokio::time::Instant::now()
                        + Duration::from_secs(if shortens { 10 } else { 30 }),
                ),
            )?;
            fixture.flags.set_mode("Rule").await?;
            ensure!(
                intake(&mut fixture.runtime, None)? == 1,
                "horizon original did not enter the actual Runtime"
            );
            let taken = held_snapshot(&fixture.runtime, 0, &wire)?;
            ensure!(
                taken.imported.producer.epoch == producer_epoch
                    && taken.imported.producer.expires_boottime_ns != u64::MAX,
                "finite original horizon was not supplied by the actual physical producer"
            );
            let started = start_production_flight(&mut fixture.runtime, &taken)?;
            let receipts =
                original_receipts(&recorded(&fixture.runtime)?, &taken.imported.identity)?;
            let prepared: Vec<_> = receipts
                .iter()
                .filter(|item| item["kind"] == "OPERATION_PREPARED")
                .collect();
            ensure!(
                prepared.len() == 1,
                "actual prepare_original record missing"
            );
            let fact = decimal(prepared[0], "fact_horizon")?;
            let producer = taken.imported.producer.expires_boottime_ns;
            let actual = started["prepared_expires_boottime_ns"]
                .as_u64()
                .context("actual PreparedOriginal horizon readback")?;
            ensure!(
                fact != u64::MAX
                    && (if shortens {
                        fact < producer
                    } else {
                        producer < fact
                    }),
                "real producer and current fact did not establish the requested distinct minimum"
            );
            ensure!(
                actual == producer.min(fact),
                "production prepare_original extended the producer/fact minimum"
            );
            let finished = finish_production_original(
                &mut fixture.runtime,
                &taken,
                "Transferred",
                0,
                1,
                0,
                NATIVE_PHASE_ACTIVE,
            )
            .await?;
            ensure!(
                decimal(&finished, "op_incarnation")?
                    == started["op_incarnation"]
                        .as_u64()
                        .context("actual horizon flight identity")?,
                "horizon completion belongs to another operation"
            );
            let linux = peer.observe(label, 1, 1).await?;
            samples.push(serde_json::json!({"source":wire,"producer_epoch":producer_epoch,"producer_horizon":producer,
                "current_fact_horizon":fact,"actual_prepared_expires":actual,"prepared_record":prepared[0],"runtime_completion":finished,"linux":linux}));
        }
        submit_fact(fixture, scope, &snapshot, None)?;
        let mut candidate = (**fixture.config.read().await).clone();
        candidate.routing = saved_routing;
        reload_policy(fixture, candidate, 21).await?;
        Ok(
            serde_json::json!({"samples":samples,"operation_source":"real physical producer and real scoped DNS owners"}),
        )
    }

    async fn production_candidate_exhaustion(
        fixture: &mut Fixture,
        peer: &mut PeerOwner,
    ) -> anyhow::Result<serde_json::Value> {
        fixture.flags.set_mode("Global").await?;
        let wire = peer.send("candidate-exhaustion", 48, 43203, 704).await?;
        wait_rx(&fixture.runtime).await?;
        fixture.flags.set_mode("Rule").await?;
        ensure!(
            intake(&mut fixture.runtime, None)? == 1,
            "real exhausted candidate input did not enter Runtime"
        );
        let taken = held_snapshot(&fixture.runtime, 0, &wire)?;
        let before = fixture.stats.udp_snapshot();
        fixture.runtime.next_candidate = u64::MAX;
        let finished = finish_production_original(
            &mut fixture.runtime,
            &taken,
            "Disposed",
            0,
            1,
            0,
            NATIVE_PHASE_PENDING,
        )
        .await?;
        ensure!(
            fixture.runtime.next_candidate == u64::MAX
                && fixture.runtime.captured.as_ref().unwrap().is_idle()
                && fixture
                    .runtime
                    .captured
                    .as_ref()
                    .unwrap()
                    .flight_receipt()
                    .is_err(),
            "candidate exhaustion wrapped or began an actual Native flight"
        );
        let receipts = original_receipts(&recorded(&fixture.runtime)?, &taken.imported.identity)?;
        ensure!(
            !receipts
                .iter()
                .any(|item| item["kind"] == "OPERATION_PREPARED"),
            "candidate exhaustion prepared a private original"
        );
        let after = fixture.stats.udp_snapshot();
        ensure!(
            after.queue_accepted == before.queue_accepted
                && after.slow_permit_accepted == before.slow_permit_accepted
                && after.dial_latency.count == before.dial_latency.count,
            "candidate exhaustion entered an Endpoint executor"
        );
        let linux = peer.observe("candidate-exhaustion", 0, 0).await?;
        Ok(
            serde_json::json!({"source":wire,"candidate_before":u64::MAX.to_string(),"candidate_after":fixture.runtime.next_candidate,
            "runtime_completion":finished,"linux":linux}),
        )
    }

    async fn wait_rx_queue(runtime: &Runtime, device: usize, queue: usize) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let rings = runtime.devices[device].queues[queue].io.get_ref().rings();
                if rings.rx_producer != rings.rx_consumer {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .context("NOT_EXERCISED: actual selected RX queue did not publish")?;
        Ok(())
    }

    fn lan_queue(runtime: &Runtime, id: u32) -> anyhow::Result<(usize, usize)> {
        let device = runtime
            .devices
            .iter()
            .position(|device| device.info.name == "dut0")
            .context("actual LAN device")?;
        let queue = runtime.devices[device]
            .queues
            .iter()
            .position(|queue| queue.id == id)
            .context("actual LAN queue")?;
        Ok((device, queue))
    }

    async fn native_committed_executors_never_return_original(
        fixture: &mut Fixture,
        peer: &mut PeerOwner,
    ) -> anyhow::Result<serde_json::Value> {
        fixture.flags.set_mode("Global").await?;
        let q0 = lan_queue(&fixture.runtime, 0)?;
        let q1 = lan_queue(&fixture.runtime, 1)?;
        let publication = fixture.runtime.native.as_ref().unwrap().clone();
        let first_wire = peer.send("committed-first", 48, 43188, 400).await?;
        wait_rx_queue(&fixture.runtime, q0.0, q0.1).await?;
        ensure!(
            intake(&mut fixture.runtime, Some(q0))? == 1,
            "actual first COUNTED input did not enter Runtime q0"
        );
        let first = held_snapshot(&fixture.runtime, 0, &first_wire)?;
        ensure!(
            first.imported.producer.flags == NATIVE_IMPORT_COUNTED,
            "first actual producer lacks COUNTED credit"
        );
        let old_wire = peer.send("committed-old-counted", 48, 43188, 401).await?;
        wait_rx_queue(&fixture.runtime, q1.0, q1.1).await?;
        let old_ring = fixture.runtime.devices[q1.0].queues[q1.1]
            .io
            .get_ref()
            .rings();
        ensure!(
            publication
                .claim(&first.imported.identity.key)?
                .context("Pending owner")?
                .state
                >> 4
                == 2,
            "old unimported q1 producer did not reserve its own credit"
        );
        let accepted_before = fixture.stats.udp_snapshot().queue_accepted;
        let first_finish = finish_production_original(
            &mut fixture.runtime,
            &first,
            "TakenOver",
            0,
            2,
            1,
            NATIVE_PHASE_CAPTURE_COMMITTED,
        )
        .await?;
        ensure!(
            fixture.stats.udp_snapshot().queue_accepted == accepted_before,
            "cold committed original unexpectedly enqueued a follower"
        );
        ensure!(
            fixture.runtime.devices[q1.0].queues[q1.1]
                .io
                .get_ref()
                .rings()
                .rx_consumer
                == old_ring.rx_consumer
                && old_ring.rx_producer != old_ring.rx_consumer,
            "first commit imported or disposed the old q1 credit"
        );
        let committed = publication
            .claim(&first.imported.identity.key)?
            .context("actual committed Capture")?;
        ensure!(
            committed.executor == NATIVE_EXECUTOR_CAPTURE && committed.state >> 4 == 1,
            "first Endpoint takeover spent the unimported q1 credit"
        );
        let scope = fixture.runtime.realms[first.realm].driver.scope();
        ensure!(
            fixture.runtime.endpoints.retains(
                scope,
                "192.0.2.2:43188".parse()?,
                "198.51.100.2:18086".parse()?,
                17
            ),
            "actual Endpoint did not retain selected transport"
        );
        fixture.flags.set_mode("Rule").await?;
        let uncounted_wire = peer
            .send("committed-direct-uncounted", 48, 43188, 402)
            .await?;
        wait_rx_queue(&fixture.runtime, q0.0, q0.1).await?;
        ensure!(
            intake(&mut fixture.runtime, Some(q0))? == 1,
            "actual committed uncounted q0 input absent"
        );
        let uncounted = held_snapshot(&fixture.runtime, 0, &uncounted_wire)?;
        ensure!(
            uncounted.imported.identity == first.imported.identity
                && uncounted.imported.producer.flags == 0,
            "committed producer invented a counted flag or changed owner"
        );
        let accepted_before_uncounted = fixture.stats.udp_snapshot().queue_accepted;
        let uncounted_finish = finish_production_original(
            &mut fixture.runtime,
            &uncounted,
            "TakenOver",
            0,
            1,
            1,
            NATIVE_PHASE_CAPTURE_COMMITTED,
        )
        .await?;
        ensure!(
            fixture.stats.udp_snapshot().queue_accepted == accepted_before_uncounted + 1,
            "committed uncounted original did not enqueue exactly one follower"
        );
        ensure!(
            publication
                .claim(&first.imported.identity.key)?
                .context("Capture owner after UNC0")?
                .state
                >> 4
                == 1
                && fixture.runtime.devices[q1.0].queues[q1.1]
                    .io
                    .get_ref()
                    .rings()
                    .rx_consumer
                    == old_ring.rx_consumer,
            "UNC0 Runtime completion spent or imported the old counted q1 credit"
        );
        ensure!(
            intake(&mut fixture.runtime, Some(q1))? == 1,
            "actual old counted q1 input absent"
        );
        let old = held_snapshot(&fixture.runtime, 0, &old_wire)?;
        ensure!(
            old.imported.identity == first.imported.identity
                && old.imported.producer.flags == NATIVE_IMPORT_COUNTED
                && old.imported.producer.epoch == first.imported.producer.epoch,
            "old actual q1 producer flag/epoch changed after Capture commit"
        );
        let accepted_before_old = fixture.stats.udp_snapshot().queue_accepted;
        let old_finish = finish_production_original(
            &mut fixture.runtime,
            &old,
            "TakenOver",
            0,
            1,
            0,
            NATIVE_PHASE_CAPTURE_COMMITTED,
        )
        .await?;
        ensure!(
            fixture.stats.udp_snapshot().queue_accepted == accepted_before_old + 1,
            "old counted original did not enqueue exactly one follower"
        );
        let after = publication
            .claim(&first.imported.identity.key)?
            .context("committed Capture disappeared")?;
        ensure!(
            after.epoch == committed.epoch
                && after.incarnation == committed.incarnation
                && after.scope == committed.scope
                && after.executor == NATIVE_EXECUTOR_CAPTURE
                && after.state == NATIVE_PHASE_CAPTURE_COMMITTED,
            "actual counted completion migrated the committed executor or failed to settle exactly its credit"
        );
        ensure!(
            fixture.stats.udp_snapshot().queue_accepted == accepted_before + 2,
            "committed originals did not preserve exactly two follower enqueues"
        );
        let completions = [&first_finish, &uncounted_finish, &old_finish];
        ensure!(
            completions[0]["completion_handle"] != completions[1]["completion_handle"]
                && completions[0]["completion_handle"] != completions[2]["completion_handle"]
                && completions[1]["completion_handle"] != completions[2]["completion_handle"],
            "committed originals reused an actual Port completion handle"
        );
        ensure!(
            completions.map(|item| item["producer_flags"].as_u64())
                == [
                    Some(u64::from(NATIVE_IMPORT_COUNTED)),
                    Some(0),
                    Some(u64::from(NATIVE_IMPORT_COUNTED)),
                ],
            "committed completion producer credits changed"
        );
        let accepted_originals = completions
            .iter()
            .filter(|item| item["outcome"] == "TakenOver")
            .count();
        ensure!(
            fixture.runtime.captured.as_ref().unwrap().is_idle()
                && fixture
                    .runtime
                    .captured
                    .as_ref()
                    .unwrap()
                    .flight_receipt()
                    .is_err(),
            "committed Capture attempted Native return"
        );
        let mut wire = Vec::new();
        for label in [
            "committed-first",
            "committed-direct-uncounted",
            "committed-old-counted",
        ] {
            wire.push(peer.observe(label, 0, 0).await?);
        }
        Ok(
            serde_json::json!({"first_counted":first_finish,"new_uncounted":uncounted_finish,"old_counted":old_finish,
            "actual_queue_ids":[fixture.runtime.devices[q0.0].queues[q0.1].id,fixture.runtime.devices[q1.0].queues[q1.1].id],
            "count_sequence":[2,1,1,0],"accepted_originals":accepted_originals,"original_linux_observations":wire}),
        )
    }

    async fn joined_map_identity_negatives(
        env: &Environment,
        publication: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let mut joined = None;
        for entry in std::fs::read_dir(env.data.join("state"))? {
            let entry = entry?;
            if entry.file_name().to_str().is_some_and(|name| {
                name.starts_with("native-return-") && name.ends_with(".joined.json")
            }) {
                ensure!(joined.is_none(), "ambiguous genuine joined archive");
                joined = Some(entry.path());
            }
        }
        let path = joined.context("C did not archive actual joined resources")?;
        let bytes = std::fs::read(&path)?;
        std::fs::copy(&path, env.prefix.with_extension("captured-joined.json"))?;
        let archive: serde_json::Value = serde_json::from_slice(&bytes)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let attachment = archive["return_attachment"]
            .as_u64()
            .context("actual joined attachment")?
            .to_string();
        let acknowledgements: Vec<_> = publication["captured_receipts"]
            .as_array()
            .context("actual B captured receipts")?
            .iter()
            .filter(|receipt| {
                receipt["kind"] == "CAPTURED_JOINED_ACK"
                    && receipt["return_attachment"].as_str() == Some(&attachment)
            })
            .collect();
        ensure!(
            archive["phase"] == "joined" && acknowledgements.len() == 1,
            "genuine joined archive lacks one B acknowledgement"
        );
        let ack = acknowledgements[0];
        ensure!(
            ack["joined_receipt_file"].as_str() == path.file_name().and_then(|name| name.to_str())
                && ack["terminal_inventory_sha256"] == serde_json::to_value(digest)?,
            "B acknowledgement does not bind the actual whole joined file"
        );
        let entries = archive["terminal_inventory"]
            .as_array()
            .context("actual joined terminal inventory")?;
        let mut rejections = Vec::new();
        let prefix = env.prefix.to_str().context("recovery prefix encoding")?;
        for role in ["operation-map", "realm-dispatch-map"] {
            let matches: Vec<_> = entries
                .iter()
                .filter(|item| item["role"] == role && item["state"] == "Unpinned")
                .collect();
            ensure!(matches.len() == 1, "joined map lacks exact unpin inventory");
            let item = matches[0];
            let pin = PathBuf::from(item["pin_path"].as_str().context("actual map pin path")?);
            ensure!(
                pin.starts_with(&env.pins) && !pin.exists(),
                "joined map was not actually unpinned"
            );
            std::fs::create_dir_all(pin.parent().context("map pin directory")?)?;
            let text = pin.to_str().context("map pin encoding")?;
            command(
                "bpftool",
                &[
                    "map",
                    "create",
                    text,
                    "type",
                    "array",
                    "key",
                    "4",
                    "value",
                    "4",
                    "entries",
                    "1",
                    "name",
                    "cr_wrong_map",
                ],
            )
            .await?;
            let wrong = command("bpftool", &["-j", "map", "show", "pinned", text]).await?;
            let wrong: serde_json::Value = serde_json::from_slice(&wrong.stdout)?;
            let rejected = probe_result(env, &["native-cleanup", prefix, "dut0", "dut1"]).await?;
            let stderr = String::from_utf8(rejected.stderr)?;
            let expected = format!("replaced Native {role}");
            ensure!(
                !rejected.status.success() && stderr.contains(&expected),
                "map-specific protecting check did not reject actual replacement: {stderr}"
            );
            std::fs::remove_file(&pin)?;
            ensure!(
                !pin.exists(),
                "fixture replacement pin survived its owned removal"
            );
            rejections.push(serde_json::json!({"role":role,"expected_id":item["id"],"actual_wrong_map":wrong,"refusal":stderr}));
        }
        artifacts(
            &env.prefix.with_extension("map-rejections.json"),
            &serde_json::json!({"joined_receipt":path,
            "joined_receipt_sha256":digest,"joined_receipt_copy":env.prefix.with_extension("captured-joined.json"),"actual_B_ack":ack,"rejections":rejections}),
        )?;
        Ok(())
    }

    fn pinned_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let mut directories = vec![root.to_path_buf()];
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                ensure!(!kind.is_symlink(), "foreign symlink in private pins");
                if kind.is_dir() {
                    directories.push(entry.path());
                } else {
                    files.push(entry.path());
                }
            }
        }
        files.sort();
        Ok(files)
    }

    fn missing_entry_pins(
        root: &Path,
        submitted: &serde_json::Value,
        before: &[(PathBuf, (u32, u32))],
    ) -> anyhow::Result<serde_json::Value> {
        use std::os::fd::FromRawFd as _;
        let objects = submitted["owner_receipt"]["resources"]
            .as_array()
            .context("submitted private resources")?
            .iter()
            .filter_map(|item| item["observed"]["objects"].as_array())
            .flatten()
            .collect::<Vec<_>>();
        let mut remaining = before.to_vec();
        let mut removed = Vec::new();
        for (role, command) in [("target-entry-link", 30), ("target-entry-prog", 13)] {
            let pair = objects
                .iter()
                .filter(|item| item["role"] == role)
                .collect::<Vec<_>>();
            ensure!(
                pair.len() == 1,
                "submitted witness role is not unique: {role}"
            );
            let object = pair[0];
            let path = PathBuf::from(
                object["pin_path"]
                    .as_str()
                    .context("submitted witness pin")?,
            );
            let id: u32 = object["id"]
                .as_u64()
                .context("submitted witness ID")?
                .try_into()?;
            let kind: u32 = object["kind"]
                .as_u64()
                .context("submitted witness kind")?
                .try_into()?;
            ensure!(
                id != 0
                    && path.starts_with(root)
                    && object["state"] == "Installed"
                    && remaining
                        .iter()
                        .filter(|item| item.0 == path && item.1 == (kind, id))
                        .count()
                        == 1,
                "submitted witness differs from original pinned ownership"
            );
            ensure!(
                matches!(std::fs::symlink_metadata(&path), Err(error) if error.raw_os_error() == Some(libc::ENOENT)),
                "removed witness pin still exists or absence lookup failed"
            );
            match crate::xdp::host::sys::bpf(command, &mut [id, 0u32, 0u32]) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(error) => return Err(error.into()),
                Ok(fd) => {
                    drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
                    anyhow::bail!("original witness ID remains live: {role}");
                }
            }
            remaining.retain(|item| item.0 != path);
            removed.push(*object);
        }
        let actual = pin_identities(root)?;
        ensure!(
            actual == remaining,
            "remaining pin path/kind/ID set changed or has extra/missing objects"
        );
        Ok(serde_json::json!({"removed":removed,"remaining":actual}))
    }

    async fn prerequisites(
        runtime: &mut Runtime,
        taken: &Taken,
        basis: &NativeBasis,
    ) -> anyhow::Result<serde_json::Value> {
        let tap = runtime.captured.as_ref().unwrap().tap_name().to_owned();
        let ifindex = runtime.captured.as_ref().unwrap().tap_ifindex();
        runtime.captured.as_ref().unwrap().check_private_receive()?;
        let mut observations = Vec::new();
        let mut rejected = 0;
        for (field, requested) in [("rps_cpus", "1"), ("rps_flow_cnt", "1")] {
            let path = PathBuf::from(format!("/sys/class/net/{tap}/queues/rx-0/{field}"));
            let original = std::fs::read_to_string(&path)?;
            let write = std::fs::write(&path, requested);
            let actual = std::fs::read_to_string(&path)?;
            let changed = actual != original;
            if changed {
                ensure!(
                    write.is_ok(),
                    "prerequisite changed despite reported write failure"
                );
                let check = runtime
                    .captured
                    .as_ref()
                    .unwrap()
                    .check_private_receive()
                    .expect_err("actual nonzero RPS/RFS must refuse");
                let begin = begin(runtime, taken, basis)
                    .expect_err("bad synchronous prerequisite reached writev");
                ensure!(
                    runtime.captured.as_ref().unwrap().is_idle()
                        && runtime.captured.as_ref().unwrap().flight_receipt().is_err(),
                    "preflight refusal installed an operation"
                );
                rejected += 1;
                observations.push(serde_json::json!({"field":field,"requested":requested,"readback":actual,
                    "check_error":check.to_string(),"begin_error":begin.to_string(),"outcome":"RefusedBeforeTransfer","operation_proof":null}));
                // No write/flight occurred, so restoring this readback cannot release transport custody.
                std::fs::write(&path, &original)?;
                ensure!(
                    std::fs::read_to_string(&path)? == original,
                    "private prerequisite restore mismatch"
                );
                runtime.captured.as_ref().unwrap().check_private_receive()?;
            } else {
                observations.push(serde_json::json!({"field":field,"requested":requested,"readback":actual,
                    "mutation_error":write.err().map(|error| error.to_string()),"status":"NOT_EXERCISED: kernel did not install mutation"}));
            }
        }
        let coalesce = command("ethtool", &["-c", &tap]).await?;
        let original_text = String::from_utf8(coalesce.stdout)?;
        let original = original_text
            .lines()
            .find_map(|line| line.trim().strip_prefix("rx-frames:").map(str::trim))
            .context("actual TAP rx-frames readback missing")?
            .to_owned();
        let mutation = Command::new("ethtool")
            .args(["-C", &tap, "rx-frames", "1"])
            .output()
            .await?;
        let readback = command("ethtool", &["-c", &tap]).await?;
        let text = String::from_utf8(readback.stdout)?;
        let actual = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("rx-frames:").map(str::trim))
            .context("mutated TAP rx-frames readback missing")?
            .to_owned();
        if actual != original {
            ensure!(
                mutation.status.success(),
                "coalesce changed despite failed mutation"
            );
            let check = runtime
                .captured
                .as_ref()
                .unwrap()
                .check_private_receive()
                .expect_err("rx_batched must refuse");
            let begin = begin(runtime, taken, basis).expect_err("batched receive reached writev");
            ensure!(
                runtime.captured.as_ref().unwrap().is_idle(),
                "coalesce refusal installed a flight"
            );
            rejected += 1;
            observations.push(serde_json::json!({"field":"rx-frames","requested":1,"readback":actual,
                "check_error":check.to_string(),"begin_error":begin.to_string(),"outcome":"RefusedBeforeTransfer","operation_proof":null}));
            command("ethtool", &["-C", &tap, "rx-frames", &original]).await?;
            runtime.captured.as_ref().unwrap().check_private_receive()?;
        } else {
            observations.push(serde_json::json!({"field":"rx-frames","requested":1,"readback":actual,
                "mutation_status":mutation.status.code(),"mutation_stderr":String::from_utf8_lossy(&mutation.stderr),
                "status":"NOT_EXERCISED: kernel did not install mutation"}));
        }
        let flags_path = format!("/sys/class/net/{tap}/tun_flags");
        let flags = std::fs::read_to_string(&flags_path)?;
        observations.push(serde_json::json!({"field":"tun_flags","readback":flags,
            "status":"NOT_EXERCISED: TUN flags require the exclusive owner FD; no duplicate FD or synthetic flag seam"}));
        ensure!(
            rejected > 0,
            "NOT_EXERCISED: no real private receive prerequisite mutation installed"
        );
        ensure!(
            runtime.captured.as_ref().unwrap().tap_ifindex() == ifindex,
            "private TAP replaced during mutation"
        );
        Ok(
            serde_json::json!({"mutations":observations,"asserted_refusals":rejected,"operation_proof":null,
            "outcome_source":"check_private_receive and begin_original preflight errors; no operation was submitted"}),
        )
    }

    fn private_object(runtime: &Runtime, role: &str) -> anyhow::Result<serde_json::Value> {
        let receipt = runtime.captured.as_ref().unwrap().flight_receipt()?;
        let objects: Vec<_> = receipt["owner_receipt"]["resources"]
            .as_array()
            .context("private resource receipt")?
            .iter()
            .filter_map(|item| item["observed"]["objects"].as_array())
            .flatten()
            .filter(|item| item["role"] == role)
            .cloned()
            .collect();
        ensure!(
            objects.len() == 1,
            "private object is not uniquely owned: {role}"
        );
        Ok(objects.into_iter().next().unwrap())
    }

    fn operation_element(
        fd: std::os::fd::BorrowedFd<'_>,
        operation: &mut NativeCapturedOperation,
        update: bool,
    ) -> io::Result<()> {
        use std::os::fd::AsRawFd as _;
        #[repr(C)]
        struct Element {
            fd: u32,
            pad: u32,
            key: u64,
            value: u64,
            flags: u64,
        }
        let key = 0u32;
        crate::xdp::host::sys::bpf(
            if update { 2 } else { 1 },
            &mut Element {
                fd: fd.as_raw_fd() as u32,
                pad: 0,
                key: &key as *const u32 as u64,
                value: operation as *mut NativeCapturedOperation as u64,
                flags: if update { 2 } else { 0 },
            },
        )?;
        Ok(())
    }

    async fn terminal_retained_child(
        case: &str,
        env: &Environment,
        fixture: &mut Fixture,
        inode: u64,
    ) -> anyhow::Result<()> {
        use std::os::fd::AsFd as _;
        let completing = case == "terminal-completing-grace";
        let phase = if completing {
            "Completing"
        } else if case == "terminal-flight-seal" {
            "Flight"
        } else {
            "Payload"
        };
        let mut peer = PeerOwner::start(env).await?;
        let private_operation = if case == "private-finish-close" {
            let wire = peer.send("entered-before-close", 48, 43385, 309).await?;
            wait_rx(&fixture.runtime).await?;
            fixture.flags.set_mode("Rule").await?;
            ensure!(
                intake(&mut fixture.runtime, None)? == 1,
                "real entry setup original absent"
            );
            let entered = held_snapshot(&fixture.runtime, 0, &wire)?;
            start_production_flight(&mut fixture.runtime, &entered)?;
            let object = private_object(&fixture.runtime, "operation-map")?;
            finish_production_original(
                &mut fixture.runtime,
                &entered,
                "Transferred",
                0,
                1,
                0,
                NATIVE_PHASE_ACTIVE,
            )
            .await?;
            peer.observe("entered-before-close", 1, 1).await?;
            fixture.flags.set_mode("Global").await?;
            Some(object)
        } else {
            None
        };
        let source = peer.send(case, 48, 43386, 310).await?;
        wait_rx(&fixture.runtime).await?;
        if phase == "Flight" {
            fixture.flags.set_mode("Rule").await?;
        }
        ensure!(
            intake(&mut fixture.runtime, None)? == 1,
            "terminal input did not enter actual Runtime custody"
        );
        let taken = held_snapshot(&fixture.runtime, 0, &source)?;
        let mut follower = None;
        if phase == "Flight" {
            start_production_flight(&mut fixture.runtime, &taken)?;
        }
        if completing {
            let mut cx = Context::from_waker(std::task::Waker::noop());
            ensure!(
                fixture
                    .runtime
                    .service_one_native_original(&mut cx, Instant::now())?
                    == 0
                    && fixture.runtime.originals.len() == 1
                    && fixture.runtime.originals.front().unwrap().handle() == taken.handle
                    && fixture.runtime.captured.as_ref().unwrap().is_idle(),
                "real Capture service did not retain its actual Completing owner"
            );
            let port = fixture.runtime.devices[taken.device].queues[taken.queue]
                .io
                .get_ref();
            ensure!(
                port.retained_rx_count() == 0 && port.rx_completion_count() == 1,
                "real Capture service did not release to the owned Port completion"
            );
            let wire = peer.send("terminal-follower", 48, 43386, 311).await?;
            wait_rx(&fixture.runtime).await?;
            ensure!(
                intake(&mut fixture.runtime, None)? == 1,
                "real counted follower absent"
            );
            follower = Some((held_snapshot(&fixture.runtime, 1, &wire)?, wire));
        }
        let publication = fixture.runtime.native.as_ref().unwrap().clone();
        let before = publication
            .claim(&taken.imported.identity.key)?
            .context("actual terminal claim absent")?;
        let handles: Vec<_> = fixture
            .runtime
            .originals
            .iter()
            .map(|original| original.handle())
            .collect();
        let ports = |runtime: &Runtime| {
            runtime
                .devices
                .iter()
                .flat_map(|device| &device.queues)
                .map(|queue| {
                    let port = queue.io.get_ref();
                    (
                        port.retained_rx_count(),
                        port.rx_completion_count(),
                        port.rings().fill_producer,
                        port.rings().rx_consumer,
                        port.counters().submitted,
                        port.counters().completed,
                    )
                })
                .collect::<Vec<_>>()
        };
        let before_ports = ports(&fixture.runtime);
        let pins = pinned_files(&env.pins)?;
        let charge = fixture.runtime.polling_budget.used();
        let tap_name = fixture
            .runtime
            .captured
            .as_ref()
            .unwrap()
            .tap_name()
            .to_owned();
        let tap_ifindex = fixture.runtime.captured.as_ref().unwrap().tap_ifindex();
        let mut errors = Vec::new();
        if case == "private-finish-close" {
            let object = private_operation
                .as_ref()
                .context("genuine entered operation map")?;
            fixture.runtime.captured.as_mut().unwrap().seal()?;
            let pin = PathBuf::from(object["pin_path"].as_str().context("operation pin")?);
            ensure!(
                pin.starts_with(&env.pins),
                "operation pin outside actual fixture custody"
            );
            let fd = crate::xdp::host::sys::open_pin(
                &pin,
                object["id"]
                    .as_u64()
                    .context("operation map ID")?
                    .try_into()?,
            )?;
            let mut original = NativeCapturedOperation::default();
            operation_element(fd.as_fd(), &mut original, false)?;
            ensure!(
                original.phase == NATIVE_OP_ENTERED
                    && original.receipt == 1
                    && original.entry_seq == 1,
                "finish-close control is not the actual successful ENTERED record"
            );
            let mut bad = original;
            bad.receipt = 0;
            operation_element(fd.as_fd(), &mut bad, true)?;
            let error = fixture
                .runtime
                .captured
                .as_mut()
                .unwrap()
                .finish_close()
                .expect_err("foreign ENTERED receipt passed private validation");
            errors.push(format!("{error:#}"));
            operation_element(fd.as_fd(), &mut original, true)?;
            let mut restored = NativeCapturedOperation::default();
            operation_element(fd.as_fd(), &mut restored, false)?;
            ensure!(
                restored == original,
                "real operation map did not restore exactly before repeated close"
            );
            let repeated = fixture.runtime.captured.as_mut().unwrap().finish_close();
            ensure!(
                !matches!(&repeated, Ok(true)),
                "restored operation rehabilitated failed private close"
            );
            errors.push(format!("{repeated:?}"));
        } else {
            match case {
                "terminal-payload-guard" => {
                    command("ip", &["link", "set", "dev", "dut0", "mtu", "1499"]).await?;
                    command("ip", &["link", "set", "dev", "dut0", "mtu", "1500"]).await?;
                }
                "terminal-flight-seal" => {
                    let guard = env
                        .pins
                        .join(format!("xdp-{}", fixture.runtime.devices[0].info.ifindex))
                        .join("guard");
                    command(
                        "ip",
                        &[
                            "link",
                            "set",
                            "dev",
                            &tap_name,
                            "xdp",
                            "pinned",
                            guard.to_str().context("foreign guard pin")?,
                        ],
                    )
                    .await?;
                }
                "terminal-completing-grace" => publication.set_grace_failure_for_test(true),
                _ => anyhow::bail!("unknown terminal retained case"),
            }
            let error = fixture
                .runtime
                .close_capture()
                .expect_err("failed terminal guard/Grace granted capture proof");
            errors.push(format!("{error:#}"));
            if case == "terminal-flight-seal" {
                ensure!(
                    honk_xsk::xdp_state(tap_ifindex)?.prog_id
                        == fixture.runtime.devices[0].programs.discover_prog_id(),
                    "failed private seal overwrote the actual foreign-selected XDP program"
                );
                let dispatch = private_object(&fixture.runtime, "tap-xdp-dispatch")?;
                command(
                    "ip",
                    &[
                        "link",
                        "set",
                        "dev",
                        &tap_name,
                        "xdp",
                        "pinned",
                        dispatch["pin_path"]
                            .as_str()
                            .context("private dispatch pin")?,
                    ],
                )
                .await?;
            }
            publication.set_grace_failure_for_test(false);
            publication.original_grace()?;
            errors.push(format!("{:?}", fixture.runtime.close_capture()));
            ensure!(
                matches!(
                    fixture.runtime.native_capture_close,
                    NativeCaptureClose::Failed
                ),
                "repeated close rehabilitated Failed terminal capture proof"
            );
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let error = fixture
                .runtime
                .service_one_native_original(&mut cx, Instant::now())
                .expect_err("failed terminal proof released a real original");
            errors.push(format!("{error:#}"));
            ensure!(
                fixture.runtime.drain_native_originals().is_err(),
                "failed terminal proof permitted destructive drain"
            );
        }
        ensure!(
            ports(&fixture.runtime) == before_ports
                && fixture
                    .runtime
                    .originals
                    .iter()
                    .map(|original| original.handle())
                    .eq(handles)
                && fixture.runtime.polling_budget.used() == charge
                && charge > 0,
            "failed terminal boundary changed actual handles, Port storage, refill or funding"
        );
        let after = publication
            .claim(&taken.imported.identity.key)?
            .context("failed terminal claim disappeared")?;
        ensure!(
            after.state == before.state
                && after.executor == before.executor
                && after.state >> 4 > 0,
            "failed terminal boundary refunded credit or changed original executor"
        );
        ensure!(
            pinned_files(&env.pins)? == pins
                && nix::net::if_::if_nametoindex(tap_name.as_str())? == tap_ifindex,
            "failed terminal boundary destroyed actual private handles/pins"
        );
        let retained = if let Some((follower, wire)) = &follower {
            ensure!(
                held_snapshot(&fixture.runtime, 1, wire)?.digest == follower.digest,
                "Completing failure recycled follower storage"
            );
            peer.observe("terminal-follower", 0, 0).await?;
            follower.digest.clone()
        } else {
            ensure!(
                held_snapshot(&fixture.runtime, 0, &source)?.digest == taken.digest,
                "terminal failure recycled original storage"
            );
            taken.digest.clone()
        };
        peer.observe(
            case,
            usize::from(phase == "Flight"),
            usize::from(phase == "Flight"),
        )
        .await?;
        peer.join().await?;
        ensure!(
            !fixture.runtime.ports_ready_for_backend_teardown(),
            "failed terminal owner falsely joined"
        );
        let retained_rx: usize = before_ports.iter().map(|port| port.0).sum();
        let completion: usize = before_ports.iter().map(|port| port.1).sum();
        ensure!(
            retained_rx >= 1 && completion == usize::from(completing),
            "actual retained phase custody differs"
        );
        let marker = PathBuf::from(
            std::env::var_os("HONK_CAPTURED_MARKER").context("retained marker path")?,
        );
        artifacts(
            &marker,
            &serde_json::json!({"format":1,"assertions":"passed","outcome":"Ambiguous",
            "cleanup":"FailedRetained","pid":std::process::id(),"netns_inode":inode,
            "namespace":env.namespace,"client_namespace":env.client,"server_namespace":env.server,
            "pin_root":env.pins,"retained_rx":retained_rx,"rx_completion":completion,"terminal_phase":phase,
            "charge_bytes":charge,"claim_outstanding":after.state >> 4,"replay_attempts":0,
            "source_sha":env!("HONK_SOURCE_SHA"),"evidence":{"source":source,"retained_sha256":retained,
            "errors":errors,"pins":pins,"private_tap_ifindex":tap_ifindex}}),
        )?;
        Ok(())
    }

    async fn retained_child(case: &str) -> anyhow::Result<()> {
        let env = environment(case)?;
        let inode = guard(&env.namespace)?;
        ensure!(
            inode.to_string() != std::env::var("HONK_CAPTURED_PARENT_INODE")?,
            "negative fixture reused smoke DUT namespace"
        );
        let mut fixture = start(&env).await?;
        let result = async {
            if case.starts_with("terminal-") || case == "private-finish-close" {
                return terminal_retained_child(case, &env, &mut fixture, inode).await;
            }
            let mut peer = PeerOwner::start(&env).await?;
            let source = peer.send(case, 48, 43286, 300).await?;
            let producing_epoch = fixture.runtime.native.as_ref().unwrap().selection_epoch().context("capture root closed")?;
            wait_rx(&fixture.runtime).await?;
            fixture.flags.set_mode("Rule").await?;
            let taken = take(&mut fixture.runtime, &source)?;
            ensure!(taken.imported.producer.epoch == producing_epoch && taken.imported.executor == NATIVE_EXECUTOR_PENDING, "negative input was not real Pending capture");
            let basis = classify(&mut fixture.runtime, &taken)?;
            let before = fixture.runtime.native.as_ref().unwrap().claim(&taken.imported.identity.key)?.context("negative owner absent")?;
            ensure!(before.state >> 4 == 1, "negative capture credit absent");
            let missing_entry = case == "missing-entry";
            let pins_before = if missing_entry { pin_identities(&env.pins)? } else { Vec::new() };
            let charge_before = fixture.runtime.polling_budget.used();
            let ports = |runtime: &Runtime| runtime.devices.iter().flat_map(|device| &device.queues).map(|queue| {
                let port = queue.io.get_ref();
                let rings = port.rings();
                // Kernel-owned cursors may advance without releasing this owner's retained storage.
                (port.retained_rx_count(), port.rx_completion_count(),
                    [rings.rx_consumer, rings.tx_producer, rings.fill_producer, rings.cq_consumer],
                    port.counters().submitted, port.counters().completed)
            }).collect::<Vec<_>>();
            let ports_before = ports(&fixture.runtime);
            let handle_before = taken.handle.receipt_identity();
            let (outcome_name, evidence) = if matches!(case, "prerequisite" | "nonready-port") {
                ("RefusedBeforeTransfer", prerequisites(&mut fixture.runtime, &taken, &basis).await?)
            } else {
                let fault = match case {
                    "missing-entry" => native::CapturedFault::MissingEntry,
                    "downstream-refusal" => native::CapturedFault::NegativeAfterAdmission,
                    _ => anyhow::bail!("unknown retained fault case"),
                };
                fixture.runtime.captured.as_mut().unwrap().set_fault(fault)?;
                begin(&mut fixture.runtime, &taken, &basis)?;
                let submitted = fixture.runtime.captured.as_ref().unwrap().flight_receipt()?;
                ensure!(submitted["fresh_grace_completed"] == false, "write result proved transfer before an entry Grace");
                let admitted = fixture.runtime.native.as_ref().unwrap().claim(&taken.imported.identity.key)?.context("selected owner absent")?;
                ensure!(admitted.executor == NATIVE_EXECUTOR_KERNEL && admitted.state & 15 == NATIVE_PHASE_ARMED
                    && admitted.state >> 4 == 1, "fault did not follow actual private XDP admission");
                let sealed = fixture.runtime.captured.as_mut().unwrap().seal();
                let seal_error = if missing_entry {
                    let error = sealed.expect_err("missing witness passed active owner readback");
                    ensure!(native::CapturedReturn::is_missing_entry_readback_error(&error),
                        "seal did not fail solely on controlled missing entry readback: {error:#}");
                    fixture.runtime.captured.as_ref().unwrap().check_missing_entry_containment()?;
                    missing_entry_pins(&env.pins, &submitted, &pins_before)?;
                    let original = format!("{error:#}");
                    let mut compound = Some(error);
                    for additional in ["observer", "containment", "Grace"] {
                        super::super::fold_capture_result(&mut compound, Err(io::Error::other(additional).into()));
                        ensure!(!native::CapturedReturn::is_missing_entry_readback_error(compound.as_ref().unwrap()),
                            "additional {additional} failure laundered missing-entry evidence");
                    }
                    let contextual = compound.unwrap().context("additional Core folding context");
                    ensure!(!native::CapturedReturn::is_missing_entry_readback_error(&contextual),
                        "context chain laundered missing-entry evidence");
                    Some(original)
                } else {
                    sealed?;
                    None
                };
                let actual = outcome(&mut fixture.runtime).await?;
                let (name, proof) = match actual {
                    native::OriginalOutcome::Transferred(_) => anyhow::bail!("fault control incorrectly reported Transferred regardless of write result"),
                    native::OriginalOutcome::RefusedBeforeTransfer(proof) => ("RefusedBeforeTransfer", proof),
                    native::OriginalOutcome::Ambiguous(proof) => ("Ambiguous", proof),
                };
                ensure!(!proof.is_transferred(), "negative outcome granted transfer");
                let observed = receipt(&fixture.runtime, &taken, &proof, false)?;
                if case == "missing-entry" {
                    ensure!(name == "Ambiguous" && observed["observation"]["phase"] == NATIVE_OP_REDIRECT_REQUESTED
                        && observed["observation"]["receipt"] == 0 && observed["observation"]["entry_seq"] == 0
                        && observed["entry_observed"] == false && observed["failed_retained"] == true
                        && observed["port_identity"] == submitted["port_identity"]
                        && observed["prepared_expires_boottime_ns"] == submitted["prepared_expires_boottime_ns"]
                        && observed["producer"] == submitted["producer"] && proof.entry_seq() == 0,
                        "missing entry did not retain actual RedirectRequested/receipt0/entry0 uncertainty");
                } else {
                    ensure!(observed["observation"]["phase"] == NATIVE_OP_ADMITTED && proof.entry_seq() == 0, "TCX-only fault did not stop after real Admitted");
                }
                let close_error = fixture.runtime.captured.as_mut().unwrap().finish_close()
                    .expect_err("ambiguous private flight acquired terminal close authority");
                fixture.runtime.original_outcome = Some(proof);
                (name, serde_json::json!({"submitted":submitted,"observed":observed,"seal_error":seal_error,"finish_close_error":format!("{close_error:#}")}))
            };
            let linux = peer.observe(case, 0, if case == "missing-entry" { 1 } else { 0 }).await?;
            peer.join().await?;
            let close_failure = if matches!(case, "prerequisite" | "nonready-port") {
                fixture.runtime.close_capture().context("negative Runtime::close_capture")?;
                None
            } else {
                Some(format!("{:#}", fixture.runtime.close_capture()
                    .expect_err("failed private owner obtained successful terminal capture proof")))
            };
            fixture.runtime.diagnostics.lifecycle(Lifecycle::FailedRetained);
            let port = fixture.runtime.devices[taken.device].queues[taken.queue].io.get_mut();
            let retained_rx = port.retained_rx_count();
            let completion = port.rx_completion_count();
            ensure!(retained_rx == 1 && completion == 0 && !port.close().ready_for_backend_teardown(), "negative reclaimed its actual whole-chain owner");
            ensure!(port.with_retained_rx(taken.handle, |segments, _| segments.iter().map(|segment| segment.len()).sum::<usize>())? == taken.extent.frame_length as usize, "negative lost original bytes");
            let retained_digest = port.with_retained_rx(taken.handle, |segments, _| {
                let mut digest = Sha256::new();
                for segment in segments { digest.update(segment); }
                digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect::<String>()
            })?;
            ensure!(retained_digest == taken.digest, "negative changed retained original bytes");
            let after = fixture.runtime.native.as_ref().unwrap().claim(&taken.imported.identity.key)?.context("negative claim retired")?;
            ensure!(after.state >> 4 == before.state >> 4 && after.state & 15 != NATIVE_PHASE_ACTIVE, "negative refunded charge or opened Active");
            let pins = pinned_files(&env.pins)?;
            let pin_evidence = if missing_entry {
                fixture.runtime.captured.as_ref().unwrap().check_missing_entry_containment()?;
                Some(missing_entry_pins(&env.pins, &evidence["submitted"], &pins_before)?)
            } else {
                ensure!(pins.iter().any(|path| path.file_name().is_some_and(|name| name == "operation-map"))
                    && pins.iter().any(|path| path.file_name().is_some_and(|name| name == "target-entry-prog")), "retained operation/program pins missing");
                None
            };
            let charge = fixture.runtime.polling_budget.used();
            ensure!(charge > 0 && fixture.runtime._original_memory.as_ref().is_some_and(|memory| memory.bytes() > 0)
                && fixture.runtime.captured.is_some(), "retained owner lost its funded resources");
            if missing_entry {
                ensure!(charge == charge_before && ports(&fixture.runtime) == ports_before
                    && taken.handle.receipt_identity() == handle_before,
                    "missing-entry changed exact original handle, Port state or charge");
                ensure!(fixture.runtime.captured.as_ref().unwrap().joined_receipt().is_none(),
                    "missing entry manufactured joined private authority");
                let attachment = evidence["submitted"]["return_attachment"].as_u64().context("submitted attachment")?;
                let receipt = &evidence["submitted"]["owner_receipt"];
                let namespace = receipt["namespace"].as_u64().context("submitted receipt namespace")?;
                let archive = env.data.join("state").join(format!("native-return-{namespace}-{attachment}.joined.json"));
                ensure!(matches!(std::fs::symlink_metadata(archive), Err(error) if error.raw_os_error() == Some(libc::ENOENT)),
                    "missing entry archived joined custody or archive absence lookup failed");
                let publication = recorded(&fixture.runtime)?;
                let attachment = attachment.to_string();
                ensure!(!publication["captured_receipts"].as_array().context("actual captured receipts")?.iter().any(|item|
                    item["kind"] == "CAPTURED_JOINED_ACK" && item["return_attachment"].as_str() == Some(attachment.as_str())),
                    "missing entry received a joined acknowledgment");
            }
            let marker = PathBuf::from(std::env::var_os("HONK_CAPTURED_MARKER").context("retained marker path")?);
            fixture.retained = Some(taken);
            ensure!(fixture.runtime.devices.iter().all(|device| !device.queues.is_empty()), "terminal failure took the actual queue owners");
            let queue_counts: Vec<_> = fixture.runtime.devices.iter().map(|device| device.queues.len()).collect();
            let original_count = fixture.runtime.originals.len();
            ensure!(!fixture.runtime.ports_ready_for_backend_teardown(), "production terminal readiness falsely permits taking a retained Port");
            ensure!(fixture.runtime.devices.iter().map(|device| device.queues.len()).eq(queue_counts)
                && fixture.runtime.originals.len() == original_count && fixture.retained.is_some(), "readiness check removed an original/queue owner");
            if !matches!(case, "prerequisite" | "nonready-port") {
                let queue_counts: Vec<_> = fixture.runtime.devices.iter().map(|device| device.queues.len()).collect();
                ensure!(fixture.runtime.drain_native_originals().is_err(), "unresolved private custody falsely drained");
                ensure!(fixture.runtime.devices.iter().map(|device| device.queues.len()).eq(queue_counts), "failed drain removed actual Port owners");
            }
            artifacts(&marker, &serde_json::json!({"format":1,"assertions":"passed","outcome":outcome_name,
                "cleanup":"FailedRetained","pid":std::process::id(),"netns_inode":inode,
                "namespace":env.namespace,"client_namespace":env.client,"server_namespace":env.server,
                "pin_root":env.pins,"retained_rx":retained_rx,"rx_completion":completion,"charge_bytes":charge,
                "claim_outstanding":after.state >> 4,"replay_attempts":0,"source_sha":env!("HONK_SOURCE_SHA"),
                "negative_writev_after_admission":{"status":"NOT_RUN","reason":"no deterministic stock injection of a negative writev after admission; no fabricated result"},
                "evidence":{"source":source,"retained_sha256":retained_digest,"operation":evidence,"close_capture_error":close_failure,"linux":linux,"pins":pins,"missing_entry_pins":pin_evidence}}))?;
            Ok::<(), anyhow::Error>(())
        }.await;
        if let Err(error) = result {
            std::mem::forget(fixture);
            return Err(error);
        }
        // This bounded test's result is the asserted marker; this child keeps the real owners until VM teardown.
        std::future::pending::<()>().await;
        std::mem::forget(fixture);
        Ok(())
    }

    async fn child_topology(namespace: &str, client: &str, server: &str) -> anyhow::Result<()> {
        for name in [namespace, client, server] {
            command("ip", &["netns", "add", name]).await?;
            command(
                "ip",
                &[
                    "netns",
                    "exec",
                    name,
                    "sysctl",
                    "-qw",
                    "net.ipv6.conf.default.addr_gen_mode=1",
                ],
            )
            .await?;
            command("ip", &["-n", name, "link", "set", "lo", "up"]).await?;
        }
        for (device, peer, destination) in [("dut0", "c0", client), ("dut1", "s0", server)] {
            command(
                "ip",
                &[
                    "-n",
                    namespace,
                    "link",
                    "add",
                    device,
                    "numrxqueues",
                    "2",
                    "numtxqueues",
                    "2",
                    "type",
                    "veth",
                    "peer",
                    "name",
                    peer,
                    "netns",
                    destination,
                ],
            )
            .await?;
        }
        for (name, device, mac) in [
            (namespace, "dut0", "02:00:00:00:00:10"),
            (namespace, "dut1", "02:00:00:00:00:11"),
            (client, "c0", "02:00:00:00:00:20"),
            (server, "s0", "02:00:00:00:00:21"),
        ] {
            command(
                "ip",
                &[
                    "-n",
                    name,
                    "link",
                    "set",
                    "dev",
                    device,
                    "mtu",
                    "1500",
                    "addrgenmode",
                    "none",
                    "address",
                    mac,
                ],
            )
            .await?;
            command(
                "ip",
                &[
                    "netns",
                    "exec",
                    name,
                    "ethtool",
                    "-K",
                    device,
                    "rx",
                    "off",
                    "tx",
                    "off",
                    "tso",
                    "off",
                    "gso",
                    "off",
                    "gro",
                    "off",
                    "rxvlan",
                    "off",
                    "rx-vlan-stag-hw-parse",
                    "off",
                    "tx-vlan-offload",
                    "off",
                    "tx-vlan-stag-hw-insert",
                    "off",
                ],
            )
            .await?;
            command("ip", &["-n", name, "link", "set", device, "up"]).await?;
        }
        for (name, device, address) in [
            (client, "c0", "192.0.2.2/32"),
            (server, "s0", "198.51.100.2/32"),
        ] {
            command("ip", &["-n", name, "addr", "add", address, "dev", device]).await?;
        }
        for (address, device, mac) in [
            ("192.0.2.2", "dut0", "02:00:00:00:00:20"),
            ("198.51.100.2", "dut1", "02:00:00:00:00:21"),
        ] {
            command(
                "ip",
                &["-n", namespace, "route", "add", address, "dev", device],
            )
            .await?;
            command(
                "ip",
                &[
                    "-n",
                    namespace,
                    "neigh",
                    "add",
                    address,
                    "dev",
                    device,
                    "lladdr",
                    mac,
                    "nud",
                    "permanent",
                ],
            )
            .await?;
        }
        command(
            "ip",
            &[
                "netns",
                "exec",
                namespace,
                "sysctl",
                "-qw",
                "net.ipv4.ip_forward=1",
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0",
                "net.ipv4.ip_early_demux=0",
            ],
        )
        .await?;
        Ok(())
    }

    async fn empty_runtime_drop_child() -> anyhow::Result<()> {
        let env = environment("owner-drop")?;
        let inode = guard(&env.namespace)?;
        ensure!(
            inode.to_string() != std::env::var("HONK_CAPTURED_PARENT_INODE")?,
            "empty Drop child reused its parent namespace"
        );
        let fixture = start(&env).await?;
        let runtime = &fixture.runtime;
        ensure!(
            !runtime.closing
                && runtime.originals.is_empty()
                && runtime.remote_originals.is_empty()
                && runtime.workers.native.is_empty()
                && runtime.original_outcome.is_none()
                && runtime.native_writer.is_none()
                && runtime.captured.as_ref().unwrap().is_idle()
                && runtime.waiting.is_empty()
                && runtime.pending.is_empty()
                && runtime
                    .devices
                    .iter()
                    .flat_map(|device| &device.queues)
                    .all(|queue| {
                        let port = queue.io.get_ref();
                        let rings = port.rings();
                        port.retained_rx_count() == 0
                            && port.rx_completion_count() == 0
                            && rings.rx_producer == rings.rx_consumer
                            && rings.cq_producer == rings.cq_consumer
                            && port.counters().submitted == port.counters().completed
                    }),
            "empty Drop case already owns packet or completion custody"
        );
        let publication = runtime
            .native
            .as_ref()
            .context("live Native publication")?
            .clone();
        let live_epoch = publication
            .selection_epoch()
            .context("empty Drop root is already closed")?;
        ensure!(
            live_epoch & 1 == 1,
            "empty Drop did not start from an actual live odd root"
        );
        let before = recorded(runtime)?;
        let root_id = before["root_map_id"]
            .as_u64()
            .context("actual live root map ID")?;
        ensure!(
            root_id != 0 && before["terminal"] == false,
            "empty Drop pre-state is already terminal"
        );
        let guards: Vec<_> = runtime
            .devices
            .iter()
            .map(|device| {
                ensure!(
                    device.active
                        && honk_xsk::xdp_state(device.info.ifindex)?.prog_id
                            == device.programs.data_prog_id(),
                    "empty Drop physical owner is not live data"
                );
                Ok((device.info.ifindex, device.programs.discover_prog_id()))
            })
            .collect::<anyhow::Result<_>>()?;
        let pins = pin_identities(&env.pins)?;
        ensure!(!pins.is_empty(), "empty Drop has no actual pinned owners");
        observed_runtime_drop(fixture.runtime, &env)?;
        ensure!(
            pin_identities(&env.pins)? == pins,
            "empty Runtime Drop lost exact retained pin identity"
        );
        for (ifindex, guard) in &guards {
            ensure!(
                honk_xsk::xdp_state(*ifindex)?.prog_id == *guard,
                "empty Runtime Drop failed to preserve an actual physical guard"
            );
        }
        ensure!(
            publication.selection_snapshot().is_none(),
            "empty Runtime Drop left the actual root open"
        );
        let exported = publication.export_recording(false, false);
        ensure!(
            exported.status.as_str() == "PUBLISHED_DURABLE" && exported.error.is_none(),
            "empty Drop actual partial publication export failed: {exported:?}"
        );
        let bytes = std::fs::read(
            exported
                .path
                .as_ref()
                .context("empty Drop publication path")?,
        )?;
        let document: serde_json::Value = serde_json::from_slice(&bytes)?;
        let epoch = decimal(&document, "final_epoch")?;
        ensure!(
            document["root_map_id"].as_u64() == Some(root_id)
                && document["terminal"] == true
                && epoch > live_epoch
                && epoch & 1 == 0
                && document["final"] == false
                && document["complete"] == false
                && document["hooks_joined"] == false
                && document["collection_end_ns"].is_null(),
            "empty Runtime Drop did not close the same live root without false joined evidence"
        );
        let refusals = vec![
            publication
                .set_ready(true)
                .expect_err("empty Runtime Drop reopened readiness")
                .to_string(),
            publication
                .set_capture_ready(true)
                .expect_err("empty Runtime Drop reopened capture readiness")
                .to_string(),
            publication
                .write(crate::ebpf::native::NativeReason::Policy)
                .err()
                .context("empty Runtime Drop granted a new policy writer")?
                .to_string(),
            publication
                .check_original_selection()
                .expect_err("empty Runtime Drop reopened original selection")
                .to_string(),
        ];
        ensure!(
            publication.selection_snapshot().is_none(),
            "a refused writer reopened the actual root"
        );
        let marker = PathBuf::from(
            std::env::var_os("HONK_CAPTURED_MARKER").context("empty Drop result path")?,
        );
        artifacts(
            &marker,
            &serde_json::json!({"format":1,"assertions":"passed","case":"empty-runtime-drop",
            "pid":std::process::id(),"parent_pid":std::env::var("HONK_CAPTURED_PARENT_PID")?.parse::<u32>()?,
            "netns_inode":inode,"namespace":env.namespace,"client_namespace":env.client,"server_namespace":env.server,
            "source_sha":env!("HONK_SOURCE_SHA"),"live_epoch":live_epoch,"terminal_epoch":epoch,
            "root_map_id":root_id,"publication":document,"refusals":refusals,"guards":guards,"pins":pins,
            "drop_errors":env.prefix.with_extension("runtime-drop.log"),
            "custody":"private prefix retained until this child exits; no joined or cleanup authority"}),
        )?;
        std::mem::forget(fixture.owner);
        Ok(())
    }

    pub(super) async fn empty_runtime_drop(test: &str) -> anyhow::Result<()> {
        if let Ok(case) = std::env::var("HONK_CAPTURED_CHILD") {
            ensure!(
                case == "empty-runtime-drop",
                "wrong exact child case for empty Runtime Drop"
            );
            return empty_runtime_drop_child().await;
        }
        let test = test
            .strip_prefix(concat!(env!("CARGO_CRATE_NAME"), "::"))
            .context("captured child test lacks its crate-qualified module path")?;
        let parent_inode = guard("dut")?;
        let namespace = format!("od{}", std::process::id());
        let client = format!("{namespace}c");
        let server = format!("{namespace}s");
        child_topology(&namespace, &client, &server).await?;
        let root =
            PathBuf::from(std::env::var_os("HONK_XDP_ARTIFACT_ROOT").context("smoke artifacts")?);
        let prefix = root.join(format!("captured-owner-drop-{}", std::process::id()));
        let marker = prefix.with_extension("owner-drop.json");
        ensure!(
            !marker.exists(),
            "old empty Drop result cannot authorize this child"
        );
        let log = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(prefix.with_extension("child.log"))?;
        let mut child = Command::new("ip")
            .args(["netns", "exec", &namespace])
            .arg(std::env::current_exe()?)
            .args([
                test,
                "--exact",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("HONK_CAPTURED_CHILD", "empty-runtime-drop")
            .env("HONK_CAPTURED_NAMESPACE", &namespace)
            .env("HONK_CAPTURED_CLIENT", &client)
            .env("HONK_CAPTURED_SERVER", &server)
            .env("HONK_CAPTURED_PARENT_INODE", parent_inode.to_string())
            .env("HONK_CAPTURED_PARENT_PID", std::process::id().to_string())
            .env("HONK_CAPTURED_MARKER", &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        let pid = child.id().context("empty Drop child PID")?;
        let status = tokio::time::timeout(Duration::from_secs(20), child.wait())
            .await
            .context("bounded empty Drop child deadline; custody left for VM teardown")??;
        ensure!(
            status.success(),
            "empty Runtime Drop child failed: {}",
            prefix.display()
        );
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&marker)?)?;
        let inode = std::fs::metadata(format!("/run/netns/{namespace}"))?.ino();
        ensure!(
            value["format"] == 1
                && value["assertions"] == "passed"
                && value["case"] == "empty-runtime-drop"
                && value["source_sha"] == env!("HONK_SOURCE_SHA")
                && value["pid"].as_u64() == Some(u64::from(pid))
                && value["parent_pid"].as_u64() == Some(u64::from(std::process::id()))
                && value["namespace"] == namespace
                && value["client_namespace"] == client
                && value["server_namespace"] == server
                && inode != parent_inode
                && value["netns_inode"].as_u64() == Some(inode),
            "empty Drop result/source/PID/namespace lineage differs"
        );
        Ok(())
    }

    pub(super) async fn negative(test: &str, cases: &[&str]) -> anyhow::Result<()> {
        if let Ok(case) = std::env::var("HONK_CAPTURED_CHILD") {
            ensure!(
                cases.contains(&case.as_str()),
                "child case does not belong to exact selected test"
            );
            return retained_child(&case).await;
        }
        let test = test
            .strip_prefix(concat!(env!("CARGO_CRATE_NAME"), "::"))
            .context("captured child test lacks its crate-qualified module path")?;
        let parent_inode = guard("dut")?;
        let root =
            PathBuf::from(std::env::var_os("HONK_XDP_ARTIFACT_ROOT").context("smoke artifacts")?);
        for case in cases {
            let namespace = format!("cr{}-{case}", std::process::id());
            let client = format!("{namespace}c");
            let server = format!("{namespace}s");
            child_topology(&namespace, &client, &server).await?;
            let prefix = root.join(format!("captured-{case}-{}", std::process::id()));
            let marker = prefix.with_extension("retained.json");
            ensure!(
                !marker.exists(),
                "old retained marker cannot authorize this child"
            );
            let log = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(prefix.with_extension("child.log"))?;
            let mut child = Command::new("ip")
                .args(["netns", "exec", &namespace])
                .arg(std::env::current_exe()?)
                .args([
                    test,
                    "--exact",
                    "--ignored",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env("HONK_CAPTURED_CHILD", case)
                .env("HONK_CAPTURED_NAMESPACE", &namespace)
                .env("HONK_CAPTURED_CLIENT", &client)
                .env("HONK_CAPTURED_SERVER", &server)
                .env("HONK_CAPTURED_PARENT_INODE", parent_inode.to_string())
                .env("HONK_CAPTURED_MARKER", &marker)
                .stdin(Stdio::null())
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?;
            let pid = child.id().context("retained child pid")?;
            let value = tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    ensure!(
                        child.try_wait()?.is_none(),
                        "retained child exited before assertion marker: {}",
                        prefix.display()
                    );
                    if marker.is_file() {
                        break Ok::<serde_json::Value, anyhow::Error>(serde_json::from_slice(
                            &std::fs::read(&marker)?,
                        )?);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .context(
                "bounded retained child assertion deadline; child/namespace left for VM teardown",
            )??;
            ensure!(
                value["assertions"] == "passed"
                    && value["cleanup"] == "FailedRetained"
                    && matches!(
                        value["outcome"].as_str(),
                        Some("Ambiguous" | "RefusedBeforeTransfer")
                    ),
                "child did not assert an explicit retained negative outcome"
            );
            ensure!(
                value["pid"].as_u64() == Some(u64::from(pid))
                    && value["namespace"] == namespace
                    && value["client_namespace"] == client
                    && value["server_namespace"] == server,
                "retained child identity mismatch"
            );
            let inode = std::fs::metadata(format!("/proc/{pid}/ns/net"))?.ino();
            ensure!(
                inode != parent_inode
                    && inode == std::fs::metadata(format!("/run/netns/{namespace}"))?.ino()
                    && value["netns_inode"].as_u64() == Some(inode),
                "retained owner reused/left its child namespace"
            );
            ensure!(
                value["retained_rx"].as_u64().is_some_and(|count| count > 0)
                    && value["rx_completion"]
                        == if value["terminal_phase"] == "Completing" {
                            1
                        } else {
                            0
                        }
                    && value["charge_bytes"]
                        .as_u64()
                        .is_some_and(|bytes| bytes > 0)
                    && value["claim_outstanding"]
                        .as_u64()
                        .is_some_and(|count| count > 0)
                    && value["replay_attempts"] == 0,
                "retained assertion marker lacks actual custody/count/charge"
            );
            ensure!(
                child.try_wait()?.is_none(),
                "retained owner died after assertion"
            );
            // The child, rather than the smoke's namespace custodian, still owns the Runtime and private operation.
            std::mem::forget(child);
        }
        Ok(())
    }
}
