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
