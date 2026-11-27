use super::*;
use crate::xdp::{
    ReturnPath,
    worker::{PeerAuthority, PeerPathChanged},
};

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

#[test]
fn tun_realm_partitions_and_refunds_its_capture_budget() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let caps = TxCaps {
        tso4: true,
        ..TxCaps::NONE
    };
    for queues in [1, 2, 3, 8] {
        let (realm, owners) = capture_tun_realm(1280, queues, caps, &budget).unwrap();
        assert_eq!(realm.owners().len(), queues);
        assert_eq!(owners.len(), queues);
        assert!(!realm.queue_affine());
        assert!(!realm.tracks_tcp());
        let first = realm.owner(0).unwrap().0.inner.lock().resources.clone();
        assert_eq!(first.is_some(), queues > 1);
        for (worker, (scope, owner)) in realm.owners().iter().zip(&owners).enumerate() {
            assert!(owner.owns(scope));
            assert_eq!(scope.scope(), realm.scope());
            assert_eq!(scope.worker(), worker);
            let share = |n| n / queues + usize::from(worker < n % queues);
            let inner = scope.0.inner.lock();
            let ledger = inner.ledger.drain_state();
            assert_eq!(ledger.control_free, share(CAPTURE_CONTROL_FRAMES));
            assert_eq!(ledger.bulk_free, share(128));
            assert_eq!(inner.waiters.len(), share(256));
            assert_eq!(
                inner.slots.len(),
                share(1024) + ledger.control_free + ledger.bulk_free
            );
            assert_eq!(
                inner.half_open.len(),
                if queues == 1 { 0 } else { share(1024) }
            );
            assert_eq!(inner.frame_size, u16::MAX as usize);
            assert_eq!(inner.cpu_tx_caps, caps);
            assert!(inner.peers.is_empty());
            assert!(inner.fragment_peers.is_empty());
            if let Some(shared) = &first {
                let resources = inner.resources.as_ref().unwrap();
                assert!(Arc::ptr_eq(shared, resources));
                assert!(!resources.tracks_tcp());
            }
        }
        let required = budget.used();
        drop((realm, owners, first));
        assert_eq!(budget.used(), 0);
        if queues == 1 {
            let (scope, owner) =
                capture_scope_with_output(1280, 1, 128, u16::MAX as usize, caps, &budget).unwrap();
            let singleton = PacketRealm::singleton(scope).unwrap();
            assert_eq!(budget.used(), required);
            drop((singleton, owner));
        }
        let short = MemoryBudget::new(required - 1);
        assert!(capture_tun_realm(1280, queues, caps, &short).is_err());
        assert_eq!(short.used(), 0, "failed reservation must refund all owners");
    }
    for queues in [0, honk_netstack::MAX_ACCOUNTED_SHARDS + 1] {
        assert!(capture_tun_realm(1280, queues, caps, &budget).is_err());
    }
    assert!(capture_realm_for_workers(1280, 1, 128, 3, 1, true, &budget).is_err());
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn tun_shards_keep_tcp_owner_through_time_wait_and_quoted_output() {
    let now = Instant::now();
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    for queues in [1, 2, 3, 8] {
        let (realm, owners) = capture_tun_realm(1280, queues, TxCaps::NONE, &budget).unwrap();
        let worker = queues - 1;
        let client = client_for(&realm, worker);
        let destination: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let mapped = |address: SocketAddr| {
            let IpAddr::V4(ip) = address.ip() else {
                unreachable!()
            };
            SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), address.port())
        };
        assert_eq!(
            realm.worker_for_tcp(mapped(client), mapped(destination)),
            worker
        );
        let syn = segment(client, 100, 0, tcp::SYN, &[]);
        let view = wire::PacketView::from_slice(&syn);
        let barrier = std::sync::Barrier::new(queues);
        std::thread::scope(|threads| {
            for local in 0..queues {
                let realm = &realm;
                let barrier = &barrier;
                threads.spawn(move || {
                    barrier.wait();
                    let (owner, claim) = realm.dispatch_owner(local, view).unwrap();
                    assert!(claim.is_none());
                    assert_eq!(owner.worker(), worker);
                });
            }
        });
        let scope = realm.owner(worker).unwrap();
        let (flow, server) = handshake(scope, now, client, 100);
        let original = flow.flow_id();
        drop(flow);
        scope.drive(now);
        let fin = output(scope);
        assert_eq!(decode(&fin).0.flags, tcp::FIN | tcp::ACK);
        fin.release();
        let server = server.wrapping_add(1);
        scope.receive(&segment(client, 101, server, tcp::ACK, &[]), now);
        let late_fin = segment(client, 101, server, tcp::FIN | tcp::ACK, &[]);
        let (selected, claim) = realm
            .dispatch_owner(0, wire::PacketView::from_slice(&late_fin))
            .unwrap();
        assert!(selected.same_owner(scope) && claim.is_none());
        selected.receive(&late_fin, now);
        scope.drive(now);
        let old_ack = output(scope);
        let old_bytes = old_ack.packet().to_vec();
        assert_eq!(old_ack.flow_id(), Some(original));
        assert_eq!(scope.stats().unwrap().timewait_entries, 1);
        let mut ptb = [0; 128];
        let size = wire::icmp::emit_packet_too_big(
            &mut ptb,
            client.ip(),
            destination.ip(),
            1280,
            old_ack.packet(),
        )
        .unwrap();
        let (quoted, claim) = realm
            .dispatch_owner(0, wire::PacketView::from_slice(&ptb[..size]))
            .unwrap();
        assert!(quoted.same_owner(scope) && claim.is_none());

        let fresh = segment(client, 100_000, 0, tcp::SYN, &[]);
        let (selected, claim) = realm
            .dispatch_owner(0, wire::PacketView::from_slice(&fresh))
            .unwrap();
        assert!(selected.same_owner(scope) && claim.is_none());
        assert_eq!(selected.receive(&fresh, now), Rx::Consumed);
        let (_, replacement) = selected.poll_accept().unwrap();
        assert_ne!(replacement.flow_id(), original);
        assert_eq!(old_ack.packet(), old_bytes);
        assert_eq!(old_ack.flow_id(), Some(original));
        old_ack.release();
        assert!(selected.retains_tcp(client, destination));
        drop(replacement);
        for owner in owners {
            owner.shutdown().await;
        }
        drop(realm);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn tun_shards_enforce_one_half_open_ceiling() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, _owners) = capture_tun_realm(1280, 3, TxCaps::NONE, &budget).unwrap();
    let resources: Vec<_> = realm
        .owners()
        .iter()
        .map(|scope| scope.0.inner.lock().resources.clone().unwrap())
        .collect();
    let address = |source| IpAddr::from([192, 0, 2, source]);
    let now = Instant::now();
    let receive = |client| {
        let packet = segment(client, 100, 0, tcp::SYN, &[]);
        let (scope, claim) = realm
            .dispatch_owner(0, wire::PacketView::from_slice(&packet))
            .unwrap();
        assert!(claim.is_none());
        scope.receive(&packet, now)
    };
    let mut held = Vec::new();
    for source in 1..=8 {
        for index in 0..128 {
            held.push(
                resources[index % resources.len()]
                    .reserve(address(source))
                    .unwrap(),
            );
        }
        if source == 1 {
            assert_eq!(
                receive(SocketAddr::new(address(source), 41000)),
                Rx::Dropped(DropReason::HalfOpen),
                "one source has 128 credits across all owners"
            );
        }
    }
    let new_client = SocketAddr::new(address(9), 41000);
    assert_eq!(receive(new_client), Rx::Dropped(DropReason::HalfOpen));
    drop(held.pop().unwrap());
    assert_eq!(receive(new_client), Rx::Consumed);
}

#[tokio::test]
async fn tun_shards_keep_udp_client_affinity_and_share_pending_bytes() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    for queues in [1, 2, 3, 8] {
        let (realm, owners) = capture_tun_realm(1280, queues, TxCaps::NONE, &budget).unwrap();
        let foreign: SocketAddr = "203.0.113.9:53".parse().unwrap();
        let sender = realm.datagram_sender(foreign);
        let clients: Vec<_> = (0..queues)
            .map(|worker| {
                (1..=254)
                    .map(|last| SocketAddr::from(([192, 0, 2, last], 41000)))
                    .find(|client| realm.worker_for_udp(client.ip()) == worker)
                    .unwrap()
            })
            .collect();
        for (worker, &client) in clients.iter().enumerate() {
            let scope = realm.owner(worker).unwrap();
            for (port, destination) in [
                (51000, foreign),
                (52000, "198.51.100.9:123".parse().unwrap()),
            ] {
                let mut packet = [0; 128];
                let source = SocketAddr::new(client.ip(), port);
                let n = wire::udp::emit_packet(&mut packet, source, destination, b"query").unwrap();
                let (selected, claim) = realm
                    .dispatch_owner(
                        (worker + 1) % queues,
                        wire::PacketView::from_slice(&packet[..n]),
                    )
                    .unwrap();
                assert!(selected.same_owner(scope) && claim.is_none());
            }
            assert_eq!(sender.send_to(b"reply", client).await.unwrap(), 5);
            let reply = output(scope);
            assert_eq!(
                wire::packet_addresses(reply.packet()).unwrap(),
                (foreign.ip(), client.ip())
            );
            reply.release();
            assert!(
                realm
                    .owners()
                    .iter()
                    .all(|scope| scope.poll_output(&mut context()).is_pending())
            );
        }
        let payload = vec![7; 60_000];
        let mut accepted = 0;
        for index in 0..16 {
            match sender.send_to(&payload, clients[index % queues]).await {
                Ok(60_000) => accepted += 1,
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::OutOfMemory),
                other => panic!("unexpected UDP admission: {other:?}"),
            }
        }
        assert_eq!(
            accepted, 8,
            "one 512 KiB pending ceiling for {queues} owners"
        );
        drop(sender);
        for owner in owners {
            owner.shutdown().await;
        }
        drop(realm);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn tun_sharded_write_retries_shared_icmp_and_eagain_keeps_the_record() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_tun_realm(1280, 3, TxCaps::NONE, &budget).unwrap();
    let now = Instant::now();
    let clock = now + Duration::from_secs(60);
    let mut drivers: Vec<_> = owners.iter().map(PacketOwner::hand_off).collect();
    let shared = realm.owners()[0].0.inner.lock().resources.clone().unwrap();
    shared.icmp.lock().1 = clock;
    let clients: [_; 3] = std::array::from_fn(|worker| client_for(&realm, worker));
    for index in 0..=6 {
        let client = clients[index % clients.len()];
        let packet = segment(client, 100, 0, tcp::SYN, &[]);
        let (scope, claim) = realm
            .dispatch_owner(0, wire::PacketView::from_slice(&packet))
            .unwrap();
        assert!(claim.is_none());
        assert_eq!(scope.worker(), index % clients.len());
        let driver = &mut drivers[scope.worker()];
        assert_eq!(scope.receive(&packet, now), Rx::Consumed);
        let id = {
            let mut inner = scope.0.inner.lock();
            let stack = inner.stack.as_mut().unwrap();
            let id = stack.poll_accept().unwrap().id;
            stack.tcp_refuse(id, honk_netstack::Refuse::IcmpAdminProhibited);
            id
        };
        let credits = scope.0.inner.lock().ledger.drain_state();
        let emitted = scope.stats().unwrap().tx_packets;
        let mut blocked = None;
        let mut received = None;
        let mut limited = false;
        for attempt in 0..4 {
            let result = driver.write_tun(now, TxClass::Control, |header, parts, tx| {
                assert!(index < 6, "the shared target burst is exhausted");
                assert_eq!(tx.flow, Some(id));
                let mut bytes = header.to_vec();
                for part in parts {
                    bytes.extend_from_slice(part);
                }
                if index == 0 && blocked.is_none() {
                    blocked = Some((bytes, tx));
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                if let Some((original, metadata)) = &blocked {
                    assert_eq!((&bytes, tx), (original, *metadata));
                }
                received = Some(bytes);
                Ok(())
            });
            assert_eq!(scope.0.inner.lock().ledger.drain_state(), credits);
            match result {
                Ok(TunOutput::Progress) => continue,
                Err(error) if index == 0 => {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    assert!(blocked.is_some());
                    assert_eq!(scope.stats().unwrap().tx_packets, emitted);
                }
                Ok(TunOutput::Packet(len)) => {
                    assert_eq!(received.as_ref().unwrap().len(), len);
                    break;
                }
                Ok(TunOutput::Idle) if index == 6 => {
                    limited = true;
                    break;
                }
                outcome => panic!("unexpected ICMP output on attempt {attempt}: {outcome:?}"),
            }
        }
        if index < 6 {
            let bytes = received.expect("NeedsIcmp retry must reach the TUN sink");
            let ip = wire::parse_ip(&bytes).unwrap();
            assert_eq!(ip.dst, client.ip());
            assert_eq!(ip.proto, wire::PROTO_ICMP);
            assert_eq!(&bytes[ip.payload][..2], [3, 13]);
            assert_eq!(scope.stats().unwrap().tx_packets, emitted + 1);
        } else {
            assert!(limited, "the seventh refusal must drain without a packet");
            assert_eq!(scope.stats().unwrap().tx_packets, emitted);
        }
        assert_eq!(shared.icmp.lock().1, clock);
    }
    drop(drivers);
    for owner in owners {
        owner.shutdown().await;
    }
}

fn physical_synack(
    realm: &PacketRealm,
    peers: &Arc<PeerAuthority>,
    now: Instant,
) -> (ReturnPath, FlowIo, OutputLease) {
    let scope = realm.owner(0).unwrap();
    let client = client_for(realm, 0);
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
    (path, flow, output(scope))
}

#[tokio::test]
async fn physical_tcp_batch_checks_each_ack_and_flushes_before_reset() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1280, 1, 16, 1, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap();
    let now = Instant::now();
    let peers = PeerAuthority::new(Arc::new(true.into()), &budget).unwrap();
    let (path, flow, reply) = physical_synack(&realm, &peers, now);
    let client = flow.peer_addr();
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
async fn physical_tcp_batch_preserves_exported_output() {
    for (workers, members) in [(1, 1), (2, 1), (2, 2)] {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (realm, owners) = capture_realm(1280, 1, 16, workers, members, &budget).unwrap();
        assert_eq!(realm.queue_affine(), workers == 2 && members == 1);
        let scope = realm.owner(0).unwrap();
        assert_eq!(scope.0.workers, workers);
        let now = Instant::now();
        let peers = PeerAuthority::new(Arc::new(true.into()), &budget).unwrap();
        let (path, mut flow, synack) = physical_synack(&realm, &peers, now);
        let original = synack.packet().to_vec();
        let server = decode(&synack).0.seq.wrapping_add(1);
        let client = flow.peer_addr();
        let ack = segment(client, 101, server, tcp::ACK, &[]);
        scope
            .receive_realm_timed(&ack, now, now, &mut None, false, |source, pending| {
                peers.retain(scope.scope(), source, path, now, pending)
            })
            .unwrap();
        scope.after_receive();
        flow.mark_rx_admitted();
        let now = now + honk_netstack::MAX_DEFERRED;
        scope.drive(now);
        while let Poll::Ready(Some(output)) = scope.poll_output(&mut context()) {
            output.release();
        }

        let data = segment(client, 101, server, tcp::ACK, b"data");
        let receive = |path| {
            if workers == 1 {
                RealmRxBatch::receive(&mut None, scope, &data, (now, now), path, &peers, || true)
            } else {
                RealmRxBatch::receive_sharded(
                    &mut None,
                    scope,
                    &data,
                    (now, now),
                    path,
                    &peers,
                    || true,
                )
                .unwrap()
            }
        };
        scope
            .datagram_sender(flow.local_addr())
            .send_to(b"queued", client)
            .await
            .unwrap();
        assert!(
            receive(path).is_none(),
            "queued CPU output still needs service"
        );
        let queued = output(scope);
        assert!(queued.packet().ends_with(b"queued"));
        queued.release();
        for other in [
            ReturnPath { device: 1, ..path },
            ReturnPath {
                vlan_tci: [path.vlan_tci[0] | (5 << 13), 0],
                ..path
            },
        ] {
            assert!(
                receive(other).is_none(),
                "a changed path requires scalar RX"
            );
        }

        {
            let inner = scope.0.inner.lock();
            assert_eq!(inner.queued, 0);
            assert!(inner.output_peers.contains(&Some(client.ip())));
            assert!(
                inner
                    .stack
                    .as_ref()
                    .unwrap()
                    .poll_timeout()
                    .is_none_or(|due| due > now)
            );
        }
        let report = receive(path).expect("the exported lease keeps its own path");
        assert!(report.taken_over && report.qualified_rx);
        assert_eq!(synack.packet(), original);
        assert_eq!(synack.flow_id(), Some(flow.flow_id()));
        assert_eq!(synack.peer_hold().unwrap().original_path(), path);
        synack.release();
        let mut bytes = [0; 4];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);
        assert!(matches!(
            std::pin::Pin::new(&mut flow).poll_read(&mut context(), &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"data");
        drop(flow);
        for owner in owners {
            owner.shutdown().await;
        }
    }
}

#[tokio::test]
async fn physical_tcp_batch_retries_moved_peer_with_pending_output_once() {
    for saturated in [false, true] {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (realm, owners) = capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
        let scope = realm.owner(0).unwrap();
        let peers = PeerAuthority::new(Arc::new(true.into()), &budget).unwrap();
        let now = Instant::now();
        let (path, mut flow, synack) = physical_synack(&realm, &peers, now);
        let server = decode(&synack).0.seq.wrapping_add(1);
        let client = flow.peer_addr();
        let ack = segment(client, 101, server, tcp::ACK, &[]);
        scope
            .receive_realm_timed(&ack, now, now, &mut None, false, |source, pending| {
                peers.retain(scope.scope(), source, path, now, pending)
            })
            .unwrap();
        scope.after_receive();
        flow.mark_rx_admitted();
        let now = now + honk_netstack::MAX_DEFERRED;
        scope.drive(now);
        while let Poll::Ready(Some(output)) = scope.poll_output(&mut context()) {
            output.release();
        }
        assert!(matches!(
            std::pin::Pin::new(&mut flow).poll_write(&mut context(), b"pending"),
            Poll::Ready(Ok(7))
        ));

        if saturated {
            peers.saturate_revision_for_test();
        }
        let before = scope.stats().unwrap();
        let foreign_peers = PeerAuthority::new(Arc::new(true.into()), &budget).unwrap();
        let mut batch = None;
        let warm = RealmRxBatch::receive_sharded(
            &mut batch,
            scope,
            &ack,
            (now, now),
            path,
            &peers,
            || true,
        )
        .unwrap()
        .unwrap();
        assert!(warm.qualified_rx);
        let source = warm.source.unwrap();
        let moved = ReturnPath {
            device: 1,
            vlan_tci: [path.vlan_tci[0] | (5 << 13), 0],
            ..path
        };
        drop(
            peers
                .retain(
                    realm.owner(1).unwrap().scope(),
                    source,
                    moved,
                    now + Duration::from_millis(1),
                    false,
                )
                .unwrap(),
        );

        let data = segment(client, 101, server, tcp::ACK, b"data");
        let mut corrupt = data.clone();
        let offset = wire::parse_ip(&data).unwrap().payload.start;
        corrupt[offset + 16] ^= 1;
        assert_eq!(
            RealmRxBatch::receive_sharded(
                &mut batch,
                scope,
                &corrupt,
                (now, now),
                path,
                &peers,
                || true
            ),
            Ok(Some(Default::default()))
        );
        let refused = RealmRxBatch::receive_sharded(
            &mut batch,
            scope,
            &data,
            (now, now),
            path,
            &foreign_peers,
            || true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(refused.source, Some(source));
        assert!(!refused.taken_over && !refused.qualified_rx);
        assert_eq!(
            RealmRxBatch::receive_sharded(
                &mut batch,
                scope,
                &data,
                (now, now),
                path,
                &peers,
                || true
            ),
            Err(PeerPathChanged)
        );
        drop(batch.take());
        let after_batch = scope.stats().unwrap();
        assert_eq!(after_batch.rx_packets, before.rx_packets + 3);
        let mut expected_drops = before.drops;
        expected_drops[DropReason::Checksum as usize] += 1;
        expected_drops[DropReason::NotForUs as usize] += 1;
        assert_eq!(after_batch.drops, expected_drops);
        let mut bytes = [0; 4];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);
        assert!(
            std::pin::Pin::new(&mut flow)
                .poll_read(&mut context(), &mut buf)
                .is_pending()
        );

        let previous = scope.peer_hold(client.ip()).unwrap();
        assert_eq!(previous.original_path(), path);
        let (rx, report, _) = scope
            .receive_realm_timed(&data, now, now, &mut None, true, |source, pending| {
                assert!(pending, "unmaterialized TCP output still owns the old path");
                let authoritative = peers.retain(scope.scope(), source, path, now, pending)?;
                assert_eq!(authoritative.original_path(), moved);
                Some(previous.clone())
            })
            .unwrap();
        scope.after_receive();
        assert_eq!(rx, Rx::Consumed);
        assert!(report.qualified_rx);
        let after_scalar = scope.stats().unwrap();
        assert_eq!(after_scalar.rx_packets, after_batch.rx_packets + 1);
        assert_eq!(after_scalar.drops, expected_drops);

        assert!(matches!(
            std::pin::Pin::new(&mut flow).poll_read(&mut context(), &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"data");
        scope.drive(now);
        let mut pending_sent = false;
        while let Poll::Ready(Some(output)) = scope.poll_output(&mut context()) {
            if output.packet().ends_with(b"pending") {
                assert_eq!(output.flow_id(), Some(flow.flow_id()));
                assert_eq!(output.peer_hold().unwrap().original_path(), path);
                pending_sent = true;
            }
            output.release();
        }
        assert!(pending_sent);
        assert_eq!(synack.peer_hold().unwrap().original_path(), path);
        synack.release();
        drop((flow, previous));
        for owner in owners {
            owner.shutdown().await;
        }
    }
}

#[tokio::test]
async fn identical_local_flow_ids_and_completions_keep_exact_realm_owners() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
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
    let (realm, owners) = capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
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
    let (realm, owners) = capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
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

#[tokio::test]
async fn simultaneous_syn_dispatch_holds_one_owner_until_the_last_handoff_returns() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
    let client = client_for(&realm, 0);
    let packet = segment(client, 100, 0, tcp::SYN, &[]);
    let view = wire::PacketView::from_slice(&packet);
    let barrier = std::sync::Barrier::new(2);
    let [(first, first_claim), (second, second_claim)] = std::thread::scope(|threads| {
        [0, 1]
            .map(|local| {
                threads.spawn({
                    let realm = &realm;
                    let barrier = &barrier;
                    move || {
                        barrier.wait();
                        let (owner, claim) = realm.dispatch_owner(local, view).unwrap();
                        (owner.worker(), claim.unwrap())
                    }
                })
            })
            .map(|join| join.join().unwrap())
    });
    assert_eq!(first, second);
    let other = 1 - first;
    drop(first_claim);
    assert_eq!(realm.dispatch_owner(other, view).unwrap().0.worker(), first);
    drop(second_claim);
    assert_eq!(realm.dispatch_owner(other, view).unwrap().0.worker(), other);

    let destination = "203.0.113.9:443".parse().unwrap();
    let mut corrupt = packet.clone();
    let offset = wire::parse_ip(&packet).unwrap().payload.start;
    corrupt[offset + 16] ^= 1;
    let (owner, claim) = realm
        .dispatch_owner(first, wire::PacketView::from_slice(&corrupt))
        .unwrap();
    assert_eq!(
        owner.receive(&corrupt, Instant::now()),
        Rx::Dropped(DropReason::Checksum)
    );
    assert_eq!(realm.tcp_directory_owner(client, destination, true), None);
    drop(claim);
    assert_eq!(realm.dispatch_owner(other, view).unwrap().0.worker(), other);

    let mut held = Vec::new();
    for port in 1..client.port() {
        let source = SocketAddr::new(client.ip(), port);
        match realm.tcp_dispatch(1, source, destination, true) {
            Ok((1, Some(claim))) => held.push(claim),
            Err(error) if error.kind() == io::ErrorKind::OutOfMemory => break,
            _ => panic!("first SYN must reserve its receiving worker"),
        }
    }
    assert!(held.len() >= 1024);
    assert_eq!(realm.ownership_dir_full(), 1);
    assert!(realm.dispatch_owner(0, view).is_err());
    let (unknown, claim) = realm.tcp_dispatch(0, client, destination, false).unwrap();
    assert_eq!(unknown, 0);
    assert!(claim.is_none());
    assert_eq!(realm.ownership_dir_full(), 2);
    let retained = SocketAddr::new(client.ip(), 1);
    let mapped = SocketAddr::new("::ffff:192.0.2.10".parse().unwrap(), 1);
    assert_eq!(
        realm.tcp_dispatch(0, mapped, destination, false).unwrap().0,
        1
    );
    assert_eq!(
        realm
            .tcp_dispatch(0, retained, destination, true)
            .unwrap()
            .0,
        1
    );
    assert_eq!(realm.tcp_directory_owner(mapped, destination, true), None);
    assert!(!realm.tcp_directory_retains_source(mapped.ip()));
    let resources = realm.owners()[1].0.inner.lock().resources.clone().unwrap();
    assert!(!resources.retains_tcp_source_on(1, mapped.ip()));
    // A saturated directory still honors a matching reservation. A foreign worker
    // cannot publish a second FlowId even if it is fed the raw packet directly.
    let now = Instant::now();
    let reserved_syn = segment(retained, 50, 0, tcp::SYN, &[]);
    assert_eq!(
        realm.owners()[0].receive(&reserved_syn, now),
        Rx::Dropped(DropReason::HalfOpen)
    );
    assert_eq!(realm.owners()[1].receive(&reserved_syn, now), Rx::Consumed);
    drop(held);
    let (_, reserved_flow) = realm.owners()[1].poll_accept().unwrap();
    assert_eq!(reserved_flow.peer_addr(), retained);
    assert_eq!(
        realm.tcp_directory_owner(mapped, destination, true),
        Some(1)
    );
    assert!(resources.retains_tcp_source_on(1, mapped.ip()));
    assert!(!resources.retains_tcp_source_on(0, mapped.ip()));
    drop(reserved_flow);

    let scope = &realm.owners()[first];
    let now = Instant::now();
    for local in [first, other] {
        let (owner, _claim) = realm.dispatch_owner(local, view).unwrap();
        assert_eq!(owner.worker(), first);
        assert_eq!(owner.receive(&packet, now), Rx::Consumed);
    }
    let (_, flow) = scope.poll_accept().unwrap();
    assert!(scope.poll_accept().is_none());
    assert!(realm.owners()[other].poll_accept().is_none());
    drop(flow);
    for owner in owners {
        owner.shutdown().await;
    }
}

#[tokio::test]
async fn migrated_fin_and_syn_keep_the_compact_time_wait_and_exported_ack_owner() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
    let client = client_for(&realm, 0);
    let now = Instant::now();
    let scope = &realm.owners()[1];
    let (flow, server) = handshake(scope, now, client, 100);
    drop(flow);
    scope.drive(now);
    let fin = output(scope);
    assert_eq!(decode(&fin).0.flags, tcp::FIN | tcp::ACK);
    fin.release();
    let server = server.wrapping_add(1);
    let late_fin = segment(client, 101, server, tcp::FIN | tcp::ACK, &[]);
    scope.receive(&segment(client, 101, server, tcp::ACK, &[]), now);
    scope.receive(&late_fin, now);
    scope.drive(now);
    output(scope).release();
    assert_eq!(scope.stats().unwrap().timewait_entries, 1);
    for packet in [&late_fin, &segment(client, 100, 0, tcp::SYN, &[])] {
        let (owner, _claim) = realm
            .dispatch_owner(0, wire::PacketView::from_slice(packet))
            .unwrap();
        assert_eq!(owner.worker(), 1);
        owner.receive(packet, now);
    }
    scope.drive(now);
    let final_ack = output(scope);
    assert_eq!(decode(&final_ack).0.flags, tcp::ACK);
    let dst: SocketAddr = "203.0.113.9:443".parse().unwrap();
    let mut ptb = [0; 128];
    let size =
        wire::icmp::emit_packet_too_big(&mut ptb, client.ip(), dst.ip(), 1280, final_ack.packet())
            .unwrap();
    let quote = wire::PacketView::from_slice(&ptb[..size]);
    assert_eq!(realm.dispatch_owner(0, quote).unwrap().0.worker(), 1);
    assert!(realm.tcp_directory_retains_source(client.ip()));
    scope.shutdown(true);
    let view = wire::PacketView::from_slice(&late_fin);
    assert_eq!(realm.dispatch_owner(0, view).unwrap().0.worker(), 1);
    final_ack.release();
    assert_eq!(realm.dispatch_owner(0, view).unwrap().0.worker(), 0);
    assert_eq!(realm.dispatch_owner(0, quote).unwrap().0.worker(), 0);
    assert!(!realm.tcp_directory_retains_source(client.ip()));
    for owner in owners {
        owner.shutdown().await;
    }
}

#[tokio::test]
async fn releasing_old_time_wait_output_after_reopen_keeps_the_live_generation() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1280, 1, 16, 2, 1, &budget).unwrap();
    let client = client_for(&realm, 0);
    let destination = "203.0.113.9:443".parse().unwrap();
    let scope = realm.owner(1).unwrap();
    let now = Instant::now();
    let (flow, server) = handshake(scope, now, client, 100);
    let original = flow.flow_id();
    drop(flow);
    scope.drive(now);
    output(scope).release();
    let server = server.wrapping_add(1);
    scope.receive(&segment(client, 101, server, tcp::ACK, &[]), now);
    scope.receive(&segment(client, 101, server, tcp::FIN | tcp::ACK, &[]), now);
    scope.drive(now);
    let old_output = output(scope);
    assert_eq!(old_output.flow_id(), Some(original));
    assert_eq!(scope.stats().unwrap().timewait_entries, 1);
    let syn = segment(client, 100_000, 0, tcp::SYN, &[]);
    let (owner, claim) = realm
        .dispatch_owner(0, wire::PacketView::from_slice(&syn))
        .unwrap();
    assert_eq!(owner.worker(), 1);
    assert_eq!(owner.receive(&syn, now), Rx::Consumed);
    drop(claim);
    let (_, replacement) = owner.poll_accept().unwrap();
    assert_ne!(replacement.flow_id(), original);
    old_output.release();
    assert_eq!(
        realm.tcp_directory_owner(client, destination, true),
        Some(1)
    );
    scope.shutdown(true);
    assert_eq!(
        realm.tcp_directory_owner(client, destination, true),
        Some(1)
    );
    drop(replacement);
    assert_eq!(realm.tcp_directory_owner(client, destination, true), None);
    for owner in owners {
        owner.shutdown().await;
    }
}

fn assert_output_window(scope: &PacketScope, control: usize, bulk: usize) {
    let mut inner = scope.0.inner.lock();
    assert_eq!(inner.frames.len(), control + bulk);
    let mut leases = Vec::with_capacity(control + bulk);
    for (class, count) in [(TxClass::Control, control), (TxClass::Bulk, bulk)] {
        for _ in 0..count {
            let lease = inner.ledger.reserve_tx(class).unwrap();
            let index = inner.index(lease);
            assert_eq!(
                inner.frames[index].as_ref().unwrap().len(),
                inner.frame_size
            );
            leases.push(lease);
        }
        assert_eq!(
            inner.ledger.reserve_tx(class),
            Err(honk_datapath::buffer::LedgerError::NoDescriptor)
        );
    }
    for lease in leases {
        inner.ledger.cancel_tx(lease).unwrap();
    }
}

#[tokio::test]
async fn short_shard_frame_returns_its_lease_and_preserves_the_control_packet() {
    let now = Instant::now();
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, mut owners) = capture_realm(1280, 1, 16, 1, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap();
    let owner = owners.pop().unwrap();
    let mut driver = owner.hand_off();
    let client = "192.0.2.1:41000".parse().unwrap();
    let full_size = {
        let mut inner = scope.0.inner.lock();
        inner
            .stack
            .as_mut()
            .unwrap()
            .receive(now, &segment(client, 1, 700, tcp::ACK, &[]));
        // Inject a short device frame after the descriptor has become available.
        std::mem::replace(&mut inner.frame_size, 39)
    };
    let mut frame = vec![0; full_size];
    let error = driver
        .materialize_into(now, TxClass::Control, &mut frame)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    {
        let mut inner = scope.0.inner.lock();
        inner.frame_size = full_size;
        assert_eq!(inner.ledger.outstanding_tx().count(), 0);
        assert_eq!(inner.queued, 0);
    }
    let output = materialized(&mut driver, now, TxClass::Control, &mut frame);
    assert_eq!(decode_packet(&frame[..output.len()]).0.flags, tcp::RST);
    drop(output);
    scope.shutdown(true);
    drop(driver);
    owner.shutdown().await;
}

#[tokio::test]
async fn sharded_output_window_funds_both_owners_and_refunds_the_overlap() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1500, 1, 256, 2, 1, &budget).unwrap();
    assert!(!realm.widen_startup_output(256));
    let admission = Arc::new(std::sync::atomic::AtomicBool::new(false));
    realm
        .install_admission_fence(Arc::clone(&admission))
        .unwrap();
    let narrow_used = budget.used();
    let mut peak = 0;
    let mut steady_growth = 0;
    for scope in realm.owners() {
        let inner = scope.0.inner.lock();
        let wide = ScopeFrameLayout::new(
            RuntimeLimits {
                max_slots: inner.half_open.len(),
                control_frames: 32,
                bulk_frames: 256,
                max_waiters: inner.waiters.len(),
            },
            inner.frame_size,
            scope.worker(),
            2,
            true,
        )
        .unwrap();
        let new_ledger = FrameLedger::<Option<FlowId>>::metadata_bytes(wide.config).unwrap();
        peak += wide.storage_bytes - 144 * 1500 + wide.metadata_bytes + new_ledger;
        steady_growth += wide.storage_bytes + wide.metadata_bytes + new_ledger
            - inner._storage.bytes()
            - inner.ledger.charged_bytes();
    }
    let first_frame =
        |scope: &PacketScope| scope.0.inner.lock().frames[0].as_ref().unwrap().as_ptr();
    let originals = [
        first_frame(&realm.owners()[0]),
        first_frame(&realm.owners()[1]),
    ];

    // One byte below the joint peak can fund the first replacement, but not both.
    let pressure = budget
        .reserve(CAPTURE_MEMORY - narrow_used - peak + 1)
        .unwrap();
    let pressured = budget.used();
    assert!(!realm.widen_startup_output(256));
    assert_eq!(budget.used(), pressured);
    for scope in realm.owners() {
        assert_output_window(scope, 16, 128);
    }
    drop(pressure);

    let pressure = budget.reserve(CAPTURE_MEMORY - narrow_used - peak).unwrap();
    assert!(realm.widen_startup_output(256));
    assert_eq!(
        budget.used(),
        narrow_used + pressure.bytes() + steady_growth
    );
    let client = "192.0.2.10:40000".parse().unwrap();
    let syn = segment(client, 100, 0, tcp::SYN, &[]);
    for (scope, original_frame) in realm.owners().iter().zip(originals) {
        assert_output_window(scope, 32, 256);
        assert_eq!(first_frame(scope), original_frame);
        assert_eq!(
            scope.receive(&syn, Instant::now()),
            Rx::Dropped(DropReason::Stale)
        );
    }
    for owner in owners {
        owner.shutdown().await;
    }
    drop(realm);
    assert_eq!(budget.used(), pressure.bytes());
    drop(pressure);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn local_window_pair_preserves_parked_source_work_and_funds_both_drivers() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1500, 1, 256, 2, 1, &budget).unwrap();
    realm
        .install_admission_fence(Arc::new(std::sync::atomic::AtomicBool::new(false)))
        .unwrap();
    let Ok([first_owner, second_owner]) = <[PacketOwner; 2]>::try_from(owners) else {
        panic!("two original queue owners");
    };
    let mut first = first_owner.hand_off();
    let mut second = second_owner.hand_off();
    first.make_local(2).unwrap();
    second.make_local(2).unwrap();
    let layout = |driver: &PacketDriver| {
        let inner = &driver.local.as_ref().unwrap().inner;
        let available = inner.ledger.drain_state();
        (
            available.control_free,
            available.bulk_free,
            inner.frames[0].as_ref().unwrap().as_ptr(),
        )
    };
    let narrow = [layout(&first), layout(&second)];
    let held = second
        .scope
        .local_source_work("192.0.2.1".parse().unwrap())
        .unwrap();
    assert!(!PacketDriver::widen_local_pair(
        &mut first,
        &mut second,
        256
    ));
    drop(held);
    let pressure = budget.reserve(budget.limit() - budget.used()).unwrap();
    assert!(!PacketDriver::widen_local_pair(
        &mut first,
        &mut second,
        256
    ));
    assert_eq!([layout(&first), layout(&second)], narrow);
    drop(pressure);
    assert!(PacketDriver::widen_local_pair(&mut first, &mut second, 256));
    for (driver, (control, bulk, frame)) in [&mut first, &mut second].into_iter().zip(narrow) {
        assert_eq!(layout(driver), (control * 2, bulk * 2, frame));
        let aliases = driver.local.as_ref().unwrap().inner.slots.len();
        let sources: Vec<_> = (0..aliases)
            .map(|n| {
                let address = std::net::Ipv4Addr::from(0xc0000200u32 + n as u32);
                driver.scope.local_source_work(address.into()).unwrap()
            })
            .collect();
        assert!(
            driver
                .scope
                .local_source_work("198.51.100.1".parse().unwrap())
                .is_err()
        );
        drop(sources);
        driver.scope.shutdown(true);
        driver.service(&mut context(), Instant::now());
    }
    assert!(first_owner.reclaim().await && second_owner.reclaim().await);
    drop((first, second));
    first_owner.run().await;
    second_owner.run().await;
    drop(realm);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn shared_physical_realms_keep_their_original_dispatch_without_a_local_directory() {
    for (workers, members) in [(1, 1), (2, 1), (2, 2)] {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (realm, owners) =
            capture_realm_for_workers(1280, 64, 16, workers, members, false, &budget).unwrap();
        assert!(!realm.tracks_tcp());
        assert_eq!(realm.queue_affine(), workers == 2 && members == 1);
        let client = client_for(&realm, 0);
        let destination = "203.0.113.9:443".parse().unwrap();
        let syn = segment(client, 100, 0, tcp::SYN, &[]);
        let later = segment(client, 101, 1, tcp::ACK, &[]);
        let (scope, claim) = realm
            .dispatch_owner(workers - 1, wire::PacketView::from_slice(&syn))
            .unwrap();
        let worker = usize::from(realm.queue_affine());
        assert_eq!(scope.worker(), worker);
        assert_eq!(scope.receive(&syn, Instant::now()), Rx::Consumed);
        drop(claim);
        let (_, flow) = scope.poll_accept().unwrap();
        assert_eq!(
            realm
                .dispatch_owner(0, wire::PacketView::from_slice(&later))
                .unwrap()
                .0
                .worker(),
            worker
        );
        assert!(scope.retains_tcp(client, destination));
        assert_eq!(realm.ownership_dir_full(), 0);
        drop(flow);
        for owner in owners {
            owner.shutdown().await;
        }
    }
}

#[tokio::test]
async fn sharded_output_window_keeps_other_capture_layouts() {
    for (mtu, base, workers, members, control, bulk) in [
        (1500, 256, 1, 1, 32, 256),
        (1500, 256, 2, 2, 16, 128),
        (9000, 128, 2, 1, 16, 64),
        (1500, 16, 2, 1, 16, 8),
    ] {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (realm, owners) = capture_realm(mtu, 1, base, workers, members, &budget).unwrap();
        realm
            .install_admission_fence(Arc::new(std::sync::atomic::AtomicBool::new(false)))
            .unwrap();
        let before = budget.used();
        assert!(!realm.widen_startup_output(base));
        assert_eq!(budget.used(), before);
        for scope in realm.owners() {
            assert_output_window(scope, control, bulk);
        }
        for owner in owners {
            owner.shutdown().await;
        }
        drop(realm);
        assert_eq!(budget.used(), 0);
    }
}
