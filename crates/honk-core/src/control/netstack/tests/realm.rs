use super::*;

fn client_for(realm: &PacketRealm, worker: usize) -> SocketAddr {
    let destination = "203.0.113.9:443".parse().unwrap();
    (40000..50000)
        .map(|port| SocketAddr::new("192.0.2.10".parse().unwrap(), port))
        .find(|client| realm.worker_for_tcp(*client, destination) == worker)
        .unwrap()
}

fn udp_clients(realm: &PacketRealm) -> [SocketAddr; 2] {
    std::array::from_fn(|worker| {
        (1..=254)
            .map(|last| SocketAddr::from(([192, 0, 2, last], 41000)))
            .find(|client| realm.worker_for_udp(client.ip()) == worker)
            .unwrap()
    })
}

#[tokio::test]
async fn physical_tcp_batch_checks_each_ack_and_flushes_before_reset() {
    use crate::xdp::{ReturnPath, worker::PeerAuthority};

    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1280, 1, 16, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap();
    let now = Instant::now();
    let peers = PeerAuthority::new(Arc::new(std::sync::atomic::AtomicBool::new(true)));
    let client = client_for(&realm, 0);
    let path = ReturnPath {
        realm: 1,
        device: 0,
        mac: [2; 6],
        vlan_tci: [7, 0],
        vlan_proto: [0x8100, 0],
        vlan_count: 1,
    };
    let syn = segment(client, 100, 0, tcp::SYN, &[]);
    scope
        .receive_realm_timed(&syn, now, now, &mut None, false, |source, _| {
            peers.retain(scope.scope(), source, path, now, false)
        })
        .unwrap();
    scope.after_receive();
    let (_, flow) = scope.poll_accept().unwrap();
    scope.drive(now);
    let reply = output(scope);
    let server = decode(&reply).0.seq.wrapping_add(1);
    reply.release();
    let ack = segment(client, 101, server, tcp::ACK, &[]);
    let slow = |packet: &[u8], ingress_at, service_at| {
        let (_, report, _) = scope
            .receive_realm_timed(
                packet,
                ingress_at,
                service_at,
                &mut None,
                false,
                |source, pending| peers.retain(scope.scope(), source, path, ingress_at, pending),
            )
            .unwrap();
        scope.after_receive();
        report.qualified_rx
    };
    assert!(!slow(&ack, now, now));
    flow.mark_rx_admitted();
    // Clear retired handshake timers before arming the independent SYN-ACK deadline below.
    let now = now + honk_netstack::MAX_DEFERRED;
    scope.drive(now);
    while let Poll::Ready(Some(reply)) = scope.poll_output(&mut context()) {
        reply.release();
    }
    let before = scope.stats().unwrap().rx_packets;
    let mut batch = None;
    let admitted = || {
        assert!(scope.0.inner.try_lock().is_none());
        true
    };
    let accepted =
        RealmRxBatch::receive(&mut batch, scope, &ack, (now, now), path, &peers, admitted).unwrap();
    assert!(accepted.qualified_rx && accepted.taken_over);
    assert_eq!(accepted.source.unwrap().tcp_flags, Some(tcp::ACK));
    assert!(scope.0.inner.try_lock().is_none());
    assert_eq!(
        RealmRxBatch::receive(&mut batch, scope, &ack, (now, now), path, &peers, admitted),
        Some(accepted)
    );
    let mut corrupt = ack.clone();
    let offset = wire::parse_ip(&ack).unwrap().payload.start;
    corrupt[offset + 16] ^= 1;
    assert_eq!(
        RealmRxBatch::receive(
            &mut batch,
            scope,
            &corrupt,
            (now, now),
            path,
            &peers,
            admitted
        ),
        Some(Default::default())
    );
    let moved = ReturnPath { device: 1, ..path };
    assert_eq!(
        RealmRxBatch::receive(&mut batch, scope, &ack, (now, now), moved, &peers, admitted),
        None
    );
    let rst = segment(client, 101, server, tcp::RST, &[]);
    assert_eq!(
        RealmRxBatch::receive(&mut batch, scope, &rst, (now, now), path, &peers, admitted),
        None
    );
    drop(batch);
    assert_eq!(scope.stats().unwrap().rx_packets - before, 3);

    // A second connection arms a real SYN-ACK retransmission on this same Stack.
    let other = SocketAddr::new(client.ip(), client.port() + 1);
    assert_eq!(
        scope.receive(&segment(other, 200, 0, tcp::SYN, &[]), now),
        Rx::Consumed
    );
    let (_, waiting) = scope.poll_accept().unwrap();
    scope.drive(now);
    let synack = output(scope);
    let original = decode(&synack).0;
    assert_eq!(
        (original.dst_port, original.flags),
        (other.port(), tcp::SYN | tcp::ACK)
    );
    synack.release();
    let due = scope
        .0
        .inner
        .lock()
        .stack
        .as_ref()
        .unwrap()
        .poll_timeout()
        .unwrap();
    assert!(due > now);
    let mut batch = None;
    let early = due - Duration::from_nanos(1);
    assert_eq!(
        RealmRxBatch::receive(
            &mut batch,
            scope,
            &ack,
            (now, early),
            path,
            &peers,
            admitted
        ),
        Some(accepted)
    );
    let denied = || {
        assert!(scope.0.inner.try_lock().is_none());
        false
    };
    assert_eq!(
        RealmRxBatch::receive(&mut batch, scope, &ack, (now, early), path, &peers, denied),
        None
    );
    drop(batch.take());
    assert!(slow(&ack, now, early));
    assert_eq!(
        scope.0.inner.lock().stack.as_ref().unwrap().poll_timeout(),
        Some(due)
    );
    assert_eq!(
        RealmRxBatch::receive(
            &mut batch,
            scope,
            &ack,
            (now, early),
            path,
            &peers,
            admitted
        ),
        Some(accepted)
    );
    assert_eq!(
        RealmRxBatch::receive(&mut batch, scope, &ack, (now, due), path, &peers, admitted),
        None
    );
    drop(batch);
    assert!(slow(&ack, now, due));
    scope.drive(due);
    let retry = output(scope);
    let header = decode(&retry).0;
    assert_eq!(
        (header.dst_port, header.seq, header.ack, header.flags),
        (other.port(), original.seq, original.ack, original.flags)
    );
    retry.release();
    assert!(slow(&rst, now, due));
    drop(waiting);
    drop(flow);
    for owner in owners {
        owner.shutdown().await;
    }
}

#[tokio::test]
async fn identical_local_flow_ids_and_completions_keep_exact_realm_owners() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1280, 1, 16, 2, &budget).unwrap();
    let now = Instant::now();
    let clients = [client_for(&realm, 0), client_for(&realm, 1)];
    let mut flows = Vec::new();
    let mut outputs = Vec::new();
    for (worker, scope) in realm.owners().iter().enumerate() {
        assert_eq!(scope.scope(), realm.scope());
        let syn = segment(clients[worker], 100, 0, tcp::SYN, &[]);
        assert_eq!(scope.receive(&syn, now), Rx::Consumed);
        assert_eq!(scope.receive(&syn, now), Rx::Consumed);
        let (_, flow) = scope.poll_accept().unwrap();
        assert!(
            scope.poll_accept().is_none(),
            "duplicate SYN has only its selected incarnation"
        );
        scope.drive(now);
        outputs.push(output(scope));
        flows.push(flow);
    }
    assert_eq!(flows[0].flow_id(), flows[1].flow_id());
    assert_eq!(outputs[0].scope(), outputs[1].scope());
    for scope in realm.owners() {
        scope.shutdown(true);
    }
    drop(flows);
    outputs.remove(0).release();
    let destination = "203.0.113.9:443".parse().unwrap();
    assert!(!realm.owners()[0].retains_tcp(clients[0], destination));
    assert!(
        realm.owners()[1].retains_tcp(clients[1], destination),
        "another Stack's same index/generation still owns CQ tail"
    );
    outputs.pop().unwrap().release();
    for owner in owners {
        owner.shutdown().await;
    }
}

#[tokio::test]
async fn half_open_source_limit_is_shared_and_shutdown_refunds_only_its_owner() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1280, 1, 16, 2, &budget).unwrap();
    let now = Instant::now();
    let destination = "203.0.113.9:443".parse().unwrap();
    let mut per_worker = [0; 2];
    for port in 40000..40128 {
        let client = SocketAddr::new("192.0.2.10".parse().unwrap(), port);
        let worker = realm.worker_for_tcp(client, destination);
        assert_eq!(
            realm.owners()[worker].receive(&segment(client, 100, 0, tcp::SYN, &[]), now),
            Rx::Consumed
        );
        per_worker[worker] += 1;
    }
    assert!(per_worker.iter().all(|count| *count != 0));
    let extra: SocketAddr = "192.0.2.10:45000".parse().unwrap();
    let worker = realm.worker_for_tcp(extra, destination);
    assert_eq!(
        realm.owners()[worker].receive(&segment(extra, 100, 0, tcp::SYN, &[]), now),
        Rx::Dropped(DropReason::HalfOpen)
    );
    realm.owners()[0].shutdown(true);
    let next = (45001..46000)
        .map(|port| SocketAddr::new(extra.ip(), port))
        .find(|client| realm.worker_for_tcp(*client, destination) == 1)
        .unwrap();
    assert_eq!(
        realm.owners()[1].receive(&segment(next, 100, 0, tcp::SYN, &[]), now),
        Rx::Consumed
    );
    realm.owners()[1].shutdown(true);
    for owner in owners {
        owner.shutdown().await;
    }
}

#[tokio::test]
async fn realm_reply_sender_selects_client_owner_and_shares_pending_fragment_ceiling() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1280, 1, 16, 2, &budget).unwrap();
    let clients = udp_clients(&realm);
    let sender = realm.datagram_sender("203.0.113.9:53".parse().unwrap());
    for (worker, client) in clients.into_iter().enumerate() {
        assert_eq!(sender.send_to(b"foreign reply", client).await.unwrap(), 13);
        let reply = output(&realm.owners()[worker]);
        assert_eq!(
            wire::packet_addresses(reply.packet()).unwrap().1,
            client.ip()
        );
        reply.release();
        assert!(
            realm.owners()[1 - worker]
                .poll_output(&mut context())
                .is_pending()
        );
    }
    let payload = vec![7; 60000];
    let mut accepted = 0;
    for index in 0..16 {
        match sender.send_to(&payload, clients[index % 2]).await {
            Ok(60000) => accepted += 1,
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::OutOfMemory),
            other => panic!("unexpected shared pending admission: {other:?}"),
        }
    }
    assert_eq!(
        accepted, 8,
        "both real UDP fragment queues share the original 512 KiB ceiling"
    );
    for scope in realm.owners() {
        scope.shutdown(true);
    }
    for owner in owners {
        owner.shutdown().await;
    }
}
