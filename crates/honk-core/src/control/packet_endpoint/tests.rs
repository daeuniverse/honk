use super::super::netstack::RuntimeLimits;
use super::*;
use honk_netstack::{Config as StackConfig, ExcludeSet, Mode, wire};
use std::time::Duration;

mod source;
mod startup;
mod udp;

fn scope(budget: &Arc<MemoryBudget>) -> (PacketScope, PacketOwner) {
    let mut config = StackConfig::new([73; 32]);
    config.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    config.mtu = 1280;
    config.max_flows = 8;
    config.memory_limit = 2 << 20;
    config.tcp_rcv_buf_max = 4096;
    config.tcp_snd_buf_max = 8192;
    PacketScope::new(
        config,
        Arc::clone(budget),
        RuntimeLimits {
            max_slots: 8,
            control_frames: 2,
            bulk_frames: 2,
            max_waiters: 8,
        },
        Instant::now(),
    )
    .unwrap()
}

async fn local_plane() -> (ControlPlane, tokio::net::TcpListener) {
    let mut config = honk_config::Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();
    config.global.tcp_check_url.clear();
    config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
    config.global.preconnect_node_count = 0;
    config.global.udp_warm_node_count = 0;
    config.groups.push(honk_config::node::Group {
        name: "packet-control".into(),
        nodes: vec![
            honk_config::config::DIRECT_NODE_ID,
            honk_config::config::BLOCK_NODE_ID,
        ],
        ..Default::default()
    });
    let plane = super::super::tests::support::control_plane(config);
    let health = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    plane
        .alive_set
        .set_direct_check_addr(health.local_addr().unwrap().to_string());
    (plane, health)
}
fn pending_tcp(scope: &PacketScope, destination: SocketAddr) -> FlowIo {
    let mut packet = [0; 128];
    let length = wire::tcp::emit_packet(
        &mut packet,
        "192.0.2.10".parse().unwrap(),
        destination.ip(),
        &wire::tcp::Header {
            src_port: 41000,
            dst_port: destination.port(),
            seq: 100,
            ack: 0,
            flags: wire::tcp::SYN,
            window: 4096,
            urgent: 0,
            options: wire::tcp::Options::default(),
        },
        [&[], &[]],
    )
    .unwrap();
    assert_eq!(
        scope.receive(&packet[..length], Instant::now()),
        Rx::Consumed
    );
    scope.poll_accept().unwrap().1
}

async fn established_tcp(scope: &PacketScope, destination: SocketAddr) -> (FlowIo, u32) {
    let flow = pending_tcp(scope, destination);
    let synack = scope.next_output().await.unwrap();
    let ip = wire::parse_ip(synack.packet()).unwrap();
    let (header, _) = wire::tcp::parse(&synack.packet()[ip.payload]).unwrap();
    assert_eq!(
        header.flags & (wire::tcp::SYN | wire::tcp::ACK),
        wire::tcp::SYN | wire::tcp::ACK
    );
    let mut packet = [0; 128];
    let length = wire::tcp::emit_packet(
        &mut packet,
        flow.peer_addr().ip(),
        flow.local_addr().ip(),
        &wire::tcp::Header {
            src_port: flow.peer_addr().port(),
            dst_port: flow.local_addr().port(),
            seq: 101,
            ack: header.seq.wrapping_add(1),
            flags: wire::tcp::ACK,
            window: 4096,
            urgent: 0,
            options: wire::tcp::Options::default(),
        },
        [&[], &[]],
    )
    .unwrap();
    synack.release();
    assert_eq!(
        scope.receive(&packet[..length], Instant::now()),
        Rx::Consumed
    );
    (flow, header.seq.wrapping_add(1))
}

#[tokio::test]
async fn tcp_routing_binds_receive_incarnation_not_accept_queue_order() {
    let budget = MemoryBudget::new(32 << 20);
    let (scope, _owner) = scope(&budget);
    let (plane, _health) = local_plane().await;
    let handle = plane.spawn_handle();
    let destination: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let first: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let second: SocketAddr = "192.0.2.10:41001".parse().unwrap();
    let syn = |source: SocketAddr| {
        let mut packet = vec![0; 128];
        let len = wire::tcp::emit_packet(
            &mut packet,
            source.ip(),
            destination.ip(),
            &wire::tcp::Header {
                src_port: source.port(),
                dst_port: destination.port(),
                seq: 100,
                ack: 0,
                flags: wire::tcp::SYN,
                window: 4096,
                urgent: 0,
                options: wire::tcp::Options::default(),
            },
            [&[], &[]],
        )
        .unwrap();
        packet.truncate(len);
        packet
    };
    let first_snapshot = handle
        .prepare_packet_routing_snapshot(
            first,
            destination,
            "tcp",
            0,
            #[cfg(feature = "native-api")]
            false,
        )
        .await
        .unwrap();
    let original = first_snapshot.config.clone();
    let mut first_admission = Some(EndpointAdmission::new(first_snapshot, &budget).unwrap());
    let now = Instant::now();
    assert_eq!(
        scope
            .receive_admitted_with_source(&syn(first), now, &mut first_admission, false, |_, _| {
                true
            })
            .0,
        Rx::Consumed
    );
    assert!(first_admission.is_none());
    let mut next = (*original).clone();
    next.global.connect_timeout_ms += 1;
    *handle.config.write().await = Arc::new(next);
    let second_snapshot = handle
        .prepare_packet_routing_snapshot(
            second,
            destination,
            "tcp",
            0,
            #[cfg(feature = "native-api")]
            false,
        )
        .await
        .unwrap();
    let newer = second_snapshot.config.clone();
    let mut second_admission = Some(EndpointAdmission::new(second_snapshot, &budget).unwrap());
    scope.receive_admitted_with_source(&syn(first), now, &mut second_admission, false, |_, _| true);
    assert!(
        second_admission.is_some(),
        "a SYN retransmit cannot replace first admission"
    );
    scope
        .receive_admitted_with_source(&syn(second), now, &mut second_admission, false, |_, _| true);
    assert!(second_admission.is_none());
    let (_, mut first_flow) = scope.poll_accept().unwrap();
    let (_, mut second_flow) = scope.poll_accept().unwrap();
    assert_eq!(
        (first_flow.peer_addr(), second_flow.peer_addr()),
        (first, second)
    );
    assert!(Arc::ptr_eq(
        &first_flow.take_routing().unwrap().config,
        &original
    ));
    assert!(Arc::ptr_eq(
        &second_flow.take_routing().unwrap().config,
        &newer
    ));
    scope.shutdown(true);
}

#[tokio::test]
async fn real_udp_outbound_replies_stay_in_their_original_scope() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let budget = MemoryBudget::new(64 << 20);
        let first = scope(&budget);
        let second = scope(&budget);
        let outputs = [first.0.clone(), second.0.clone()];
        let mut config = honk_config::Config::default();
        config.ensure_builtin_nodes();
        config.global.dial_mode = "ip".into();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
        let plane = super::super::tests::support::control_plane(config);
        let health = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        plane
            .alive_set
            .set_direct_check_addr(health.local_addr().unwrap().to_string());
        let backend = Arc::clone(&plane.ebpf);
        let backend_guard = backend.write().await;
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![first, second], 2)
            .await
            .unwrap();
        let owner = tokio::spawn(owner.run());
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let mut observed = Vec::new();
            let mut packet = [0; 128];
            for _ in 0..2 {
                let (length, source) = upstream.recv_from(&mut packet).await.unwrap();
                observed.push(packet[..length].to_vec());
                upstream.send_to(&packet[..length], source).await.unwrap();
            }
            observed.sort();
            assert_eq!(observed, [b"scope-a".to_vec(), b"scope-b".to_vec()]);
        });
        let source = "192.0.2.7:41000".parse().unwrap();
        let mut packet = [0; 128];
        for (scope, data) in outputs.iter().zip([b"scope-a", b"scope-b"]) {
            let length = wire::udp::emit_packet(&mut packet, source, target, data).unwrap();
            endpoints
                .receive(scope.scope(), &packet[..length], Instant::now())
                .unwrap();
        }
        for (scope, expected) in outputs.iter().zip([b"scope-a", b"scope-b"]) {
            let output = scope.next_output().await.unwrap();
            let ip = wire::parse_ip(output.packet()).unwrap();
            assert_eq!(
                (ip.src, ip.dst, ip.proto),
                (target.ip(), source.ip(), wire::PROTO_UDP)
            );
            let udp = &output.packet()[ip.payload];
            assert!(wire::udp::verify_checksum(ip.src, ip.dst, udp));
            let (src, dst, payload) = wire::udp::parse(udp).unwrap();
            assert_eq!(
                (src, dst, &udp[payload]),
                (target.port(), source.port(), expected.as_slice())
            );
            drop(output);
        }
        peer.await.unwrap();
        let key = super::super::connection::build_tuples_key(
            target.ip(),
            target.port(),
            source.ip(),
            source.port(),
            17,
        );
        assert!(backend_guard.conn_state_lookup(&key).unwrap().is_none());
        endpoints.close();
        drop(endpoints);
        owner.await.unwrap().unwrap();
        drop(outputs);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("packet endpoint owner and upstream must join");
}

#[tokio::test]
async fn kernel_reply_descriptors_are_not_needed_by_packet_reply_factory() {
    let budget = MemoryBudget::new(32 << 20);
    let (scope, owner) = scope(&budget);
    let factory = Replies(Arc::from([scope.clone()]));
    assert!(!factory.uses_fd());
    assert!(
        factory
            .create(ScopeId::HOST, "192.0.2.1:53".parse().unwrap())
            .is_err()
    );
    let ReplySocketFd::Packet(sender) = factory
        .create(scope.scope(), "198.51.100.1:53".parse().unwrap())
        .unwrap()
    else {
        panic!("packet factory created a socket")
    };
    sender
        .send_to(b"answer", "192.0.2.1:41000".parse().unwrap())
        .await
        .unwrap();
    let output = scope.next_output().await.unwrap();
    let ip = wire::parse_ip(output.packet()).unwrap();
    let udp = &output.packet()[ip.payload];
    let (_, _, payload) = wire::udp::parse(udp).unwrap();
    assert_eq!(&udp[payload], b"answer");
    drop(output);
    scope.shutdown(true);
    owner.run().await;
}

#[tokio::test]
async fn dropped_join_waiter_keeps_supervisor_until_exported_output_returns() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let mut config = honk_config::Config::default();
        config.ensure_builtin_nodes();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
        let plane = super::super::tests::support::control_plane(config);
        let health = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        plane
            .alive_set
            .set_direct_check_addr(health.local_addr().unwrap().to_string());
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        scope
            .datagram_sender("198.51.100.1:53".parse().unwrap())
            .send_to(b"retained", "192.0.2.1:41000".parse().unwrap())
            .await
            .unwrap();
        let output = scope.next_output().await.unwrap();
        drop(owner);
        tokio::task::yield_now().await;
        let mut closing = Box::pin(endpoints.shutdown());
        assert!(futures::poll!(&mut closing).is_pending());
        assert!(output.packet().ends_with(b"retained"));
        output.release();
        closing.await.unwrap();
        drop(endpoints);
        drop(scope);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("cancelled join waiter must not cancel owned cleanup");
}

#[test]
fn retained_udp_bytes_keep_their_charge_after_lease_and_pool_drop() {
    let budget = MemoryBudget::new(32 << 20);
    let (scope, _owner) = scope(&budget);
    let baseline = budget.used();
    let pool = Arc::new(
        UdpEndpointPool::with_packet_reply_factory(
            1,
            Arc::new(Replies(Arc::from([scope.clone()]))),
            Arc::clone(&budget),
        )
        .unwrap(),
    );
    let (removed, mut removals) = mpsc::channel(1);
    pool.set_remove_sink(removed);
    let stats = crate::stats::StatsManager::new();
    let slot = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let EndpointReservation::Initializing(lease) = pool.reserve_or_enqueue_at(
        scope.scope(),
        "192.0.2.1:41000".parse().unwrap(),
        "198.51.100.1:443".parse().unwrap(),
        b"retained bytes",
        None,
        crate::ebpf::UdpFlowOwner::packet(),
        pool.initialization_epoch(),
        slot,
        super::super::udp_endpoint::queue_now(),
        &stats,
    ) else {
        panic!("packet bytes must be admitted");
    };
    let retained = lease.first_payload();
    drop(lease);
    pool.finish_removal(&removals.try_recv().unwrap(), true);
    drop(pool);
    assert_eq!(retained.as_ref(), b"retained bytes");
    assert!(budget.used() > baseline);
    drop(retained);
    assert_eq!(budget.used(), baseline);
}

#[test]
fn retirement_metadata_stays_reserved_until_exact_removal_completion() {
    let budget = MemoryBudget::new(32 << 20);
    let (scope, _owner) = scope(&budget);
    let pool = Arc::new(
        UdpEndpointPool::with_packet_reply_factory(
            1,
            Arc::new(Replies(Arc::from([scope.clone()]))),
            Arc::clone(&budget),
        )
        .unwrap(),
    );
    let baseline = budget.used();
    let (removed, mut removals) = mpsc::channel(2);
    pool.set_remove_sink(removed);
    let stats = crate::stats::StatsManager::new();
    let reserve = |port| {
        pool.reserve_or_enqueue_at(
            scope.scope(),
            SocketAddr::new("192.0.2.1".parse().unwrap(), port),
            "198.51.100.1:443".parse().unwrap(),
            b"x",
            None,
            crate::ebpf::UdpFlowOwner::packet(),
            pool.initialization_epoch(),
            Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
            super::super::udp_endpoint::queue_now(),
            &stats,
        )
    };
    let EndpointReservation::Initializing(first) = reserve(41000) else {
        panic!("first flow capacity");
    };
    drop(first);
    let retiring = removals.try_recv().unwrap();
    assert!(matches!(
        reserve(41001),
        EndpointReservation::CapacityRejected
    ));
    assert!(budget.used() > baseline);
    pool.finish_removal(&retiring, true);
    assert_eq!(budget.used(), baseline);
    let EndpointReservation::Initializing(next) = reserve(41001) else {
        panic!("settled capacity was not returned");
    };
    drop(next);
    pool.finish_removal(&removals.try_recv().unwrap(), true);
    assert_eq!(budget.used(), baseline);
}

#[tokio::test]
async fn finished_task_credit_is_reaped_before_next_ingress_copy() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = local_plane().await;
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        let (done, completed) = tokio::sync::oneshot::channel();
        let retained = [7u8; 65_536];
        assert!(endpoints.shared.udp_pool.spawn_slow_path(async move {
            std::hint::black_box(retained);
            done.send(()).unwrap();
        }));
        completed.await.unwrap();
        let held = budget.reserve(budget.limit() - budget.used()).unwrap();
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let client = "192.0.2.1:41000".parse().unwrap();
        let mut packet = [0; 128];
        let length = wire::udp::emit_packet(&mut packet, client, target, b"reclaim").unwrap();
        endpoints
            .receive(scope.scope(), &packet[..length], Instant::now())
            .unwrap();
        drop(held);
        let mut received = [0; 64];
        let (length, peer) = upstream.recv_from(&mut received).await.unwrap();
        assert_eq!(&received[..length], b"reclaim");
        upstream.send_to(&received[..length], peer).await.unwrap();
        let reply = scope.next_output().await.unwrap();
        assert!(reply.packet().ends_with(b"reclaim"));
        reply.release();
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("reclaimed task credit must admit the real datagram");
}

#[tokio::test]
async fn startup_failure_waits_for_owned_output_and_supervisor_cleanup() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = local_plane().await;
        let stopped = Arc::clone(&plane.shutdown_requested);
        let config = Arc::clone(&plane.config);
        let config_guard = config.write().await;
        let opening = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1);
        let mut opening = Box::pin(opening);
        assert!(futures::poll!(&mut opening).is_pending());
        scope
            .datagram_sender("198.51.100.1:53".parse().unwrap())
            .send_to(b"owned", "192.0.2.1:41000".parse().unwrap())
            .await
            .unwrap();
        let output = scope.next_output().await.unwrap();
        scope.shutdown(true);
        drop(config_guard);
        while !stopped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        assert!(
            futures::poll!(&mut opening).is_pending(),
            "startup failure must retain a joinable cleanup owner"
        );
        output.release();
        assert!(opening.await.is_err());
        drop(scope);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("failed startup must join after its actual consumer releases output");
}

#[tokio::test]
async fn forced_udp_cleanup_is_not_erased_by_terminal_shutdown() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = local_plane().await;
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope, scope_owner)], 1)
            .await
            .unwrap();
        assert!(
            endpoints
                .shared
                .udp_pool
                .spawn_slow_path(std::future::pending())
        );
        assert!(endpoints.shutdown().await.is_err());
        assert!(owner.run().await.is_err());
    })
    .await
    .expect("forced cancellation still has a real joined result");
}

#[test]
fn already_funded_followers_remain_admissible_at_the_memory_ceiling() {
    let budget = MemoryBudget::new(32 << 20);
    let (scope, _owner) = scope(&budget);
    let pool = Arc::new(
        UdpEndpointPool::with_packet_reply_factory(
            1,
            Arc::new(Replies(Arc::from([scope.clone()]))),
            Arc::clone(&budget),
        )
        .unwrap(),
    );
    let (removed, mut removals) = mpsc::channel(1);
    pool.set_remove_sink(removed);
    let stats = crate::stats::StatsManager::new();
    let client = "192.0.2.1:41000".parse().unwrap();
    let target = "198.51.100.1:443".parse().unwrap();
    let reserve = |data| {
        pool.reserve_payload_or_enqueue_at(
            scope.scope(),
            client,
            target,
            DatagramPayload::Funded(data),
            None,
            crate::ebpf::UdpFlowOwner::packet(),
            pool.initialization_epoch(),
            Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
            super::super::udp_endpoint::queue_now(),
            &stats,
        )
    };
    let first = FundedDatagram::copy_from(b"first", &budget).unwrap();
    let EndpointReservation::Initializing(lease) = reserve(first) else {
        panic!("first admission");
    };
    let follower = FundedDatagram::copy_from(&[9; 32_768], &budget).unwrap();
    let ceiling = budget.reserve(budget.limit() - budget.used()).unwrap();
    assert!(matches!(reserve(follower), EndpointReservation::Enqueued));
    let mut queue = lease.take_queue_receiver().unwrap();
    let received = queue.try_recv().unwrap();
    assert_eq!(received.payload(), &[9; 32_768]);
    drop(received);
    drop(queue);
    drop(ceiling);
    drop(lease);
    pool.finish_removal(&removals.try_recv().unwrap(), true);
}

#[cfg(all(feature = "native-api", feature = "clash-api"))]
#[tokio::test]
async fn startup_publishes_running_before_servicing_native_selector_requests() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (mut plane, _health) = local_plane().await;
        let phase = plane.observe_phase();
        let client = plane.control_client();
        let (_endpoints, owner) = PacketEndpoints::new(plane, vec![(scope, scope_owner)], 1)
            .await
            .unwrap();
        assert_eq!(*phase.borrow(), super::super::EnginePhase::Running);
        client
            .select(super::super::client::SelectionRequest::Name {
                group: "packet-control".into(),
                member: "block".into(),
            })
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("the consumed control receiver must service requests");
}

#[tokio::test]
async fn late_reserved_tcp_ingress_is_disposed_before_scope_join() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = local_plane().await;
        let stopped = Arc::clone(&plane.shutdown_requested);
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        let producer = endpoints.sender.clone().reserve_owned().await.unwrap();
        let slot = Arc::clone(&endpoints.shared.tcp_slots)
            .try_acquire_owned()
            .unwrap();
        let flow = pending_tcp(&scope, "203.0.113.9:443".parse().unwrap());
        endpoints.close();
        while !stopped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        let mut closing = Box::pin(endpoints.shutdown());
        assert!(futures::poll!(&mut closing).is_pending());
        producer.send(Work::Tcp(flow, slot));
        closing.await.unwrap();
        owner.run().await.unwrap();
        drop(endpoints);
        drop(scope);
        assert_eq!(budget.used(), 0);
    })
    .await
    .expect("late producer ownership must be drained before scope join");
}

#[tokio::test]
async fn idle_udp_task_credit_is_returned_by_periodic_maintenance() {
    let budget = MemoryBudget::new(32 << 20);
    let (scope, _owner) = scope(&budget);
    let pool = Arc::new(
        UdpEndpointPool::with_packet_reply_factory(
            1,
            Arc::new(Replies(Arc::from([scope]))),
            Arc::clone(&budget),
        )
        .unwrap(),
    );
    let baseline = budget.used();
    let (done, completed) = tokio::sync::oneshot::channel();
    let payload = [7u8; 65_536];
    assert!(pool.spawn_slow_path(async move {
        std::hint::black_box(payload);
        done.send(()).unwrap();
    }));
    completed.await.unwrap();
    assert!(budget.used() >= baseline + 65_536);
    pool.janitor_cycle();
    assert_eq!(budget.used(), baseline);
}

#[tokio::test]
async fn refused_tcp_task_resets_instead_of_gracefully_closing() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (plane, _health) = local_plane().await;
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        let (flow, _) = established_tcp(&scope, "203.0.113.9:443".parse().unwrap()).await;
        let slot = Arc::clone(&endpoints.shared.tcp_slots)
            .try_acquire_owned()
            .unwrap();
        let ceiling = budget.reserve(budget.limit() - budget.used()).unwrap();
        endpoints.sender.send(Work::Tcp(flow, slot)).await.unwrap();
        let reply = scope.next_output().await.unwrap();
        let ip = wire::parse_ip(reply.packet()).unwrap();
        let (header, _) = wire::tcp::parse(&reply.packet()[ip.payload]).unwrap();
        assert_ne!(header.flags & wire::tcp::RST, 0);
        reply.release();
        drop(ceiling);
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("refused TCP work must terminate with reset");
}

#[derive(Debug)]
struct PanickingTcp(Arc<Notify>);

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for PanickingTcp {
    async fn dial(
        &self,
        _: &honk_config::node::Node,
        target: SocketAddr,
        domain: Option<&str>,
        _: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        Ok(honk_outbound::proxy::ProxyStream {
            stream: Box::new(PanickingRead {
                stream: tokio::net::TcpStream::connect(target).await?,
                panicked: Arc::clone(&self.0),
            }),
            target_addr: target,
            target_domain: domain.map(str::to_owned),
        })
    }
}

#[derive(Debug)]
struct PanickingRead {
    stream: tokio::net::TcpStream,
    panicked: Arc<Notify>,
}

impl tokio::io::AsyncRead for PanickingRead {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.panicked.notify_one();
        panic!("injected connection-local relay panic");
    }
}

impl tokio::io::AsyncWrite for PanickingRead {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn connection_panic_does_not_stop_unrelated_packet_udp() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let budget = MemoryBudget::new(32 << 20);
        let (scope, scope_owner) = scope(&budget);
        let (mut plane, _health) = local_plane().await;
        let panicked = Arc::new(Notify::new());
        let mut registry = honk_outbound::proxy::ProxyRegistry::new();
        registry.register(
            honk_outbound::proxy::ProtocolEntry::new(
                honk_config::types::NodeProtocol::Direct,
                Arc::new(PanickingTcp(Arc::clone(&panicked))),
            )
            .with_packet(Arc::new(honk_outbound::proxy::direct::DirectHandler::new())),
        );
        plane.proxy_registry = Arc::new(registry);
        let (endpoints, owner) = PacketEndpoints::new(plane, vec![(scope.clone(), scope_owner)], 1)
            .await
            .unwrap();
        let tcp_target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (flow, ack) = established_tcp(&scope, tcp_target.local_addr().unwrap()).await;
        let mut packet = [0; 256];
        let length = wire::tcp::emit_packet(
            &mut packet,
            flow.peer_addr().ip(),
            flow.local_addr().ip(),
            &wire::tcp::Header {
                src_port: flow.peer_addr().port(),
                dst_port: flow.local_addr().port(),
                seq: 101,
                ack,
                flags: wire::tcp::ACK | wire::tcp::PSH,
                window: 4096,
                urgent: 0,
                options: wire::tcp::Options::default(),
            },
            [b"GET / HTTP/1.0\r\n\r\n", &[]],
        )
        .unwrap();
        assert_eq!(
            scope.receive(&packet[..length], Instant::now()),
            Rx::Consumed
        );
        let slot = Arc::clone(&endpoints.shared.tcp_slots)
            .try_acquire_owned()
            .unwrap();
        endpoints.sender.send(Work::Tcp(flow, slot)).await.unwrap();
        panicked.notified().await;
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = "192.0.2.10:42000".parse().unwrap();
        let length = wire::udp::emit_packet(
            &mut packet,
            client,
            upstream.local_addr().unwrap(),
            b"still-serving",
        )
        .unwrap();
        endpoints
            .receive(scope.scope(), &packet[..length], Instant::now())
            .unwrap();
        let (length, source) = upstream.recv_from(&mut packet).await.unwrap();
        assert_eq!(&packet[..length], b"still-serving");
        upstream.send_to(&packet[..length], source).await.unwrap();
        loop {
            let reply = scope
                .next_output()
                .await
                .expect("packet runtime survived TCP panic");
            let ip = wire::parse_ip(reply.packet()).unwrap();
            if ip.proto == wire::PROTO_UDP {
                let (_, _, payload) =
                    wire::udp::parse(&reply.packet()[ip.payload.clone()]).unwrap();
                assert_eq!(&reply.packet()[ip.payload][payload], b"still-serving");
                reply.release();
                break;
            }
            reply.release();
        }
        endpoints.shutdown().await.unwrap();
        owner.run().await.unwrap();
    })
    .await
    .expect("a TCP panic must not shut down unrelated packet service");
}
