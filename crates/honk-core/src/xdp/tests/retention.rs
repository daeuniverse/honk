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
    let budget = MemoryBudget::new(32 << 20);
    let mut config = honk_netstack::Config::new([89; 32]);
    config.mode = honk_netstack::Mode::Transparent {
        exclude: Default::default(),
    };
    config.mtu = 1500;
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
                mss: (flags & tcp::SYN != 0).then_some(1460),
                ..Default::default()
            },
        },
        [&[], &[]],
    )
    .unwrap();
    bytes.truncate(length);
    bytes
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
        let mut completed = outputs.map(|output| output.map(Retained::Endpoint));
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
