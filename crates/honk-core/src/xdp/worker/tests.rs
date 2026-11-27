use super::*;
use honk_netstack::wire::tcp;
use std::net::SocketAddr;
use std::sync::{Barrier, mpsc as sync_channel};

mod direct_relay;

fn path() -> ReturnPath {
    ReturnPath {
        realm: 1,
        device: 0,
        mac: [2; 6],
        vlan_tci: [7, 0],
        vlan_proto: [0x8100, 0],
        vlan_count: 1,
    }
}

#[tokio::test]
async fn physical_udp_close_during_source_validation_retires_cleanly() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, mut owners) = capture_realm(1500, 1, 16, 1, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap();
    let plane = crate::control::tests::support::control_plane(Config::default());
    let (endpoints, supervisor) =
        PacketEndpoints::new(plane, vec![(scope.clone(), owners.pop().unwrap())], 4)
            .await
            .unwrap();
    let peers = PeerAuthority::new(Arc::new(true.into()), &budget).unwrap();
    let tuple = source(41000, None);
    let mut packet = [0; 128];
    let len = wire::udp::emit_packet(&mut packet, tuple.src, tuple.dst, b"in flight").unwrap();
    let now = Instant::now();
    let received = std::thread::scope(|threads| {
        endpoints.receive_on_timed(
            scope,
            &packet[..len],
            now,
            now,
            None,
            false,
            |src, pending| {
                let peer = peers
                    .retain(scope.scope(), src, path(), now, pending)
                    .unwrap();
                threads.spawn(|| endpoints.close());
                // Close publishes admission before taking the scope lock held by this callback.
                let deadline = Instant::now() + Duration::from_secs(5);
                while !endpoints.is_closing() {
                    assert!(Instant::now() < deadline, "close did not reach admission");
                    std::thread::yield_now();
                }
                Some(peer)
            },
        )
    });
    assert!(endpoints.is_closing());
    supervisor.run().await.unwrap();
    let received =
        received.expect("shutdown must refuse late UDP without failing the device owner");
    assert_eq!(received.source, Some(tuple));
    assert!(!received.taken_over && !received.qualified_rx);
}

#[tokio::test]
async fn physical_peer_slots_reap_across_a_hole_and_relearn() {
    use futures::FutureExt as _;

    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, mut owners) = capture_realm(1500, 1, 16, 1, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap();
    let plane = crate::control::tests::support::control_plane(Config::default());
    let (endpoints, supervisor) =
        PacketEndpoints::new(plane, vec![(scope.clone(), owners.pop().unwrap())], 1)
            .await
            .unwrap();
    let peers = PeerAuthority::new(Arc::new(true.into()), &budget).unwrap();
    let now = Instant::now();
    let destination = source(41000, None).dst;
    let sender = scope.datagram_sender(destination);
    let client = |host| SocketAddr::from(([192, 0, 2, host], 41000));
    let receive = |client, path| {
        let mut packet = [0; 128];
        let len = wire::udp::emit_packet(&mut packet, client, destination, b"request").unwrap();
        let received = endpoints
            .receive_on_timed(
                scope,
                &packet[..len],
                now,
                now,
                None,
                false,
                |src, pending| peers.retain(scope.scope(), src, path, now, pending),
            )
            .unwrap();
        assert_eq!(received.source.unwrap().src, client);
        received.taken_over
    };
    let reply = |client| {
        let sent = sender
            .send_to(b"reply", client)
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(sent, 5);
        let output = scope.next_output().now_or_never().unwrap().unwrap();
        assert_eq!(
            wire::packet_addresses(output.packet()).unwrap().1,
            client.ip()
        );
        output
    };

    // The pending initializer owns the only UDP endpoint through this synchronous packet script.
    // The other peers therefore depend on their exported frames to retain their realm slots.
    assert!(receive(client(1), path()));
    assert!(scope.retains_source(client(1).ip()));
    let mut frames: Vec<_> = (2..=17)
        .map(|host| {
            let frame = reply(client(host));
            assert!(!receive(client(host), path()));
            frame
        })
        .collect();
    let high = client(17);
    frames.remove(0).release();
    assert!(scope.peer_hold(client(2).ip()).is_none());
    let old_reply = reply(high);
    frames.pop().unwrap().release();
    assert_eq!(old_reply.peer_hold().unwrap().original_path(), path());

    for device in [1, 2] {
        let moved = ReturnPath { device, ..path() };
        assert!(!receive(high, moved));
        assert_eq!(scope.peer_hold(high.ip()).unwrap().original_path(), moved);
    }
    assert_eq!(old_reply.peer_hold().unwrap().original_path(), path());
    let high_slot = peers
        .slots
        .lock()
        .iter()
        .position(|peer| peer.address == high.ip())
        .unwrap();
    let high_holds = peers.pin_count(high_slot);
    assert_eq!(high_holds, 2, "one realm slot and one exported reply");

    let newcomer = client(18);
    let reused = reply(newcomer);
    assert!(!receive(newcomer, path()));
    assert!(scope.peer_hold(newcomer.ip()).is_some());
    assert_eq!(
        scope.peer_hold(high.ip()).unwrap().original_path().device,
        2
    );
    old_reply.release();
    assert!(scope.peer_hold(high.ip()).is_none());
    drop(frames);
    reused.release();
    for host in 2..=18 {
        assert!(scope.peer_hold(client(host).ip()).is_none());
    }

    let keep = reply(high);
    let relearned = ReturnPath {
        device: 3,
        ..path()
    };
    assert!(!receive(high, relearned));
    let output = reply(high);
    assert_eq!(output.peer_hold().unwrap().original_path(), relearned);
    drop((keep, output));
    assert!(scope.peer_hold(high.ip()).is_none());

    endpoints.close();
    supervisor.run().await.unwrap();
}

#[test]
fn peer_identity_uses_logical_realm_not_member_or_priority() {
    let first = path();
    let mut next = first;
    next.device = 1;
    next.vlan_tci[0] |= 0xa000;
    assert!(first.same_identity(next));
    next.realm += 1;
    assert!(!first.same_identity(next));
}

fn source(port: u16, flags: Option<u8>) -> honk_netstack::ValidatedSource {
    honk_netstack::ValidatedSource {
        src: SocketAddr::from(([192, 0, 2, 1], port)),
        dst: SocketAddr::from(([198, 51, 100, 1], 443)),
        protocol: if flags.is_some() {
            wire::PROTO_TCP
        } else {
            wire::PROTO_UDP
        },
        tcp_flags: flags,
    }
}

fn envelope(shared: &Shared, number: u8, scope: ScopeId, at: Instant) -> Envelope {
    let first = [number; 4];
    let last = [number + 1; 3];
    let metadata = [number + 2; 8];
    let mut cell = shared.pool.take().unwrap();
    cell.copy(&[&first, &last], &metadata).unwrap();
    Envelope {
        ingress: Ingress {
            scope,
            namespace: 1,
            ifindex: 2,
            attachment: 3,
            mark: MarkProvenance::BeforeSkb,
        },
        scope,
        path: path(),
        ingress_at: at,
        cell,
        body: None,
        _claim: None,
        peer: None,
        l3_offset: 0,
        l3_length: 7,
        payload: Payload::Ingress,
    }
}

#[test]
fn whole_scatter_handoff_is_fifo_and_processing_keeps_the_global_cell() {
    let budget = MemoryBudget::new(32 << 20);
    let (shared, [mut first, mut second]) =
        Shared::new(2, 128, 2, &budget, Arc::new(AtomicBool::new(false))).unwrap();
    let diagnostics = Diagnostics::new(&budget, 0, std::iter::empty()).unwrap();
    shared.diagnostics.set(Arc::clone(&diagnostics)).unwrap();
    assert_eq!(diagnostics.json(false)["cross_worker_handoffs"], "0");
    let scope = ScopeId::allocate().unwrap();
    let at = Instant::now();
    for number in 0..64 {
        assert!(
            shared
                .send(
                    usize::from(number >= 32),
                    envelope(&shared, number, scope, at)
                )
                .is_ok()
        );
    }
    assert!(
        matches!(shared.handoff_cell(1, true, || 23), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "queued and processing storage share the same 64 cells"
    );
    let processing = first.try_recv().unwrap();
    assert!(
        shared.pool.take().is_none(),
        "dequeue does not refund storage still being processed"
    );
    assert_eq!(processing.ingress_at, at);
    assert_eq!(&processing.cell.bytes.as_ref().unwrap()[..8], &[2; 8]);
    assert_eq!(processing.ip(), &[0, 0, 0, 0, 1, 1, 1]);
    drop(processing);
    let returned = shared.pool.take().unwrap();
    assert!(shared.pool.take().is_none());
    drop(returned);
    for number in 1..32 {
        let packet = first.try_recv().unwrap();
        assert_eq!(packet.ip()[0], number);
        assert_eq!(packet.path, path());
    }
    for number in 32..64 {
        assert_eq!(second.try_recv().unwrap().ip()[0], number);
    }
    assert_eq!(shared.pool.free.lock().len(), CELLS);
    for number in 0..32 {
        assert!(shared.send(0, envelope(&shared, number, scope, at)).is_ok());
    }
    let refused = shared
        .send(0, envelope(&shared, 32, scope, at))
        .err()
        .unwrap();
    assert_eq!(
        refused.ip()[0],
        32,
        "a full destination returns the actual owned envelope"
    );
    drop(refused);
    let full = diagnostics.json(true);
    assert_eq!(full["cross_worker_handoffs"], "96");
    assert_eq!(
        full["handoffs"][0][0],
        serde_json::json!({"packets":"64", "l3_bytes":"448", "refused":"1", "refused_l3_bytes":"7"})
    );
    assert_eq!(full["handoffs"][1][0]["l3_bytes"], "224");
    assert_eq!(full["handoffs"][1][1]["refused_l3_bytes"], "23");
}

#[test]
fn bond_peer_moves_future_replies_without_rewriting_retained_output() {
    let peers = PeerAuthority::isolated(Arc::new(true.into()));
    let scope = ScopeId::allocate().unwrap();
    let now = Instant::now();
    let original = peers
        .retain(scope, source(4000, Some(tcp::SYN)), path(), now, false)
        .unwrap();
    let exported = original.clone();
    let mut next = path();
    next.device = 1;
    let current = peers
        .retain(scope, source(4000, Some(tcp::ACK)), next, now, false)
        .unwrap();
    assert_eq!(current.original_path(), next);
    assert_eq!(exported.original_path(), path());
    let mut foreign = next;
    foreign.realm += 1;
    assert!(
        peers
            .retain(scope, source(4000, Some(tcp::ACK)), foreign, now, false)
            .is_none()
    );
    assert_eq!(exported.original_path().device, 0);
    assert_eq!(current.original_path().device, 1);
}

#[test]
fn peer_holds_keep_original_qos_and_prevent_identity_replacement() {
    let peers = PeerAuthority::isolated(Arc::new(true.into()));
    let scope = ScopeId::allocate().unwrap();
    let now = Instant::now();
    let original = peers
        .retain(scope, source(4000, Some(tcp::SYN)), path(), now, false)
        .unwrap();
    let mut priority = path();
    priority.vlan_tci[0] |= 5 << 13;
    let pending = peers
        .retain(scope, source(4000, Some(tcp::ACK)), priority, now, true)
        .unwrap();
    assert_eq!(pending.path(), Some(path()));
    let fresh = peers
        .retain(scope, source(4000, Some(tcp::ACK)), priority, now, false)
        .unwrap();
    assert_eq!(fresh.path(), Some(priority));
    assert_eq!(
        original.path(),
        Some(path()),
        "a later PCP update cannot rewrite an older output snapshot"
    );
    let mut changed = path();
    changed.mac[5] = 4;
    assert!(
        peers
            .retain(
                scope,
                source(4001, Some(tcp::SYN)),
                changed,
                now + PEER_CONFLICT_HOLD,
                false
            )
            .is_none()
    );
    let fragment = peers
        .pin_fragment(scope, source(4000, None).src.ip(), priority)
        .unwrap()
        .unwrap();
    assert_eq!(fragment.path(), Some(priority));
    drop((original, pending, fresh, fragment));
    assert!(
        peers
            .retain(scope, source(4001, Some(tcp::SYN)), changed, now, false)
            .is_none()
    );
    let replacement = peers
        .retain(
            scope,
            source(4001, Some(tcp::SYN)),
            changed,
            now + PEER_CONFLICT_HOLD,
            false,
        )
        .unwrap();
    assert_eq!(replacement.path(), Some(changed));
    let unknown: IpAddr = "192.0.2.55".parse().unwrap();
    let quote = peers
        .pin_fragment(scope, unknown, priority)
        .unwrap()
        .unwrap();
    assert!(!quote.learned());
    assert_eq!(quote.original_path(), priority);
    assert_eq!(
        quote.path(),
        None,
        "an unknown fragment carries metadata without gaining a reply authority"
    );
    let rst = peers
        .retain(
            scope,
            honk_netstack::ValidatedSource {
                src: SocketAddr::new(unknown, 4010),
                ..source(4000, Some(tcp::RST))
            },
            priority,
            now,
            false,
        )
        .unwrap();
    assert!(!rst.learned());
    assert_eq!(peers.slots.lock().len(), 1);
}

#[test]
fn exported_peer_can_finish_during_topology_work_and_holds_its_charge() {
    let budget = MemoryBudget::new(1 << 20);
    let peers = PeerAuthority::new(Arc::new(true.into()), &budget).unwrap();
    let scope = ScopeId::allocate().unwrap();
    let original = peers
        .retain(
            scope,
            source(4000, Some(tcp::SYN)),
            path(),
            Instant::now(),
            false,
        )
        .unwrap();
    let (sent, received) = sync_channel::channel();
    let observed = std::thread::scope(|threads| {
        let guard = peers.slots.lock();
        threads.spawn(|| {
            let exported = original.clone();
            let snapshot = exported.original_path();
            drop(exported);
            let _ = sent.send(snapshot);
        });
        let observed = received.recv_timeout(Duration::from_secs(3));
        drop(guard);
        observed
    });
    assert_eq!(
        observed.expect("output pin and return must not wait for topology"),
        path()
    );
    drop(peers);
    assert!(
        budget.used() > 0,
        "a retained peer still owns its metadata and counter storage"
    );
    drop(original);
    assert_eq!(budget.used(), 0);
}

#[test]
fn full_peer_table_reuses_only_unpinned_slots_and_never_wraps() {
    let peers = PeerAuthority::isolated(Arc::new(true.into()));
    let scope = ScopeId::allocate().unwrap();
    let now = Instant::now();
    let learn = |n: usize| {
        let mut original = source(41000, Some(tcp::SYN));
        original.src = SocketAddr::from(([198, 18, (n >> 8) as u8, n as u8], 41000));
        peers.retain(scope, original, path(), now, false)
    };
    let mut live: Vec<_> = (0..PEERS).map(|n| learn(n).unwrap()).collect();
    let exported = live[0].clone();
    let (slot, generation) = (exported.slot, exported.generation);
    drop(live.swap_remove(0));
    assert!(learn(PEERS).is_none());
    drop(exported);
    let replacement = learn(PEERS).unwrap();
    assert_eq!(
        (replacement.slot, replacement.generation),
        (slot, generation + 1)
    );
    drop(replacement);
    assert_eq!(peers.pin_count(slot), 0);
    // Exercise the real increment at its unreachable-in-memory arithmetic boundary.
    peers.pins[slot].store(usize::MAX - 1, Ordering::Relaxed);
    assert!(peers.pin(slot, true).is_some());
    assert!(peers.pin(slot, true).is_none());
    assert_eq!(peers.pin_count(slot), usize::MAX);
    peers.invalidate();
    assert_eq!(peers.revision.load(Ordering::Acquire), u64::MAX);
    peers.pins[slot].store(0, Ordering::Relaxed);
}

#[test]
fn checked_peer_reuses_one_timestamp_until_another_worker_moves_the_path() {
    let peers = PeerAuthority::isolated(Arc::new(true.into()));
    let scope = ScopeId::allocate().unwrap();
    let now = Instant::now();
    let ack = source(4000, Some(tcp::ACK));
    let original = peers
        .retain(scope, source(4000, Some(tcp::SYN)), path(), now, false)
        .unwrap();
    let mut checked = None;
    assert_eq!(
        peers.confirm_tcp::<true>(&original, scope, ack, path(), now, &mut checked),
        Ok(true)
    );

    // A validated steady ACK completes even while another thread owns the authority mutex.
    let (sent, received) = sync_channel::channel();
    std::thread::scope(|threads| {
        let guard = peers.slots.lock();
        threads.spawn(|| {
            sent.send(peers.confirm_tcp::<true>(&original, scope, ack, path(), now, &mut checked))
                .unwrap()
        });
        let result = received.recv_timeout(Duration::from_secs(3));
        drop(guard);
        assert_eq!(result, Ok(Ok(true)));
    });
    let later = now + Duration::from_millis(1);
    let mut moved = path();
    moved.device = 1;
    moved.vlan_tci[0] |= 5 << 13;
    for saturated in [false, true] {
        if saturated {
            peers.saturate_revision_for_test();
        }
        assert_eq!(
            peers.confirm_tcp::<true>(&original, scope, ack, path(), now, &mut checked),
            Ok(true)
        );
        std::thread::scope(|threads| {
            threads
                .spawn(|| drop(peers.retain(scope, ack, moved, later, false).unwrap()))
                .join()
                .unwrap();
        });
        assert_eq!(
            peers.confirm_tcp::<true>(&original, scope, ack, moved, now, &mut checked),
            Ok(false)
        );
        assert_eq!(
            peers.confirm_tcp::<true>(&original, scope, ack, path(), now, &mut checked),
            Err(PeerPathChanged)
        );
        {
            let slots = peers.slots.lock();
            assert_eq!(slots[original.slot].path, moved);
            assert_eq!(slots[original.slot].last_seen, later);
            assert_eq!(peers.pin_count(original.slot), 1);
        }
        assert_eq!(
            peers.confirm_tcp::<false>(&original, scope, ack, path(), now, &mut checked),
            Ok(true)
        );
        assert_eq!(peers.slots.lock()[original.slot].path, path());
    }
    {
        let mut slots = peers.slots.lock();
        slots[original.slot].conflict = Some(later);
        peers.invalidate();
    }
    assert_eq!(
        peers.confirm_tcp::<true>(&original, scope, ack, path(), now, &mut checked),
        Ok(false)
    );
}

fn syn(client: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    tcp_segment(client, destination, 100, 0, tcp::SYN, &[])
}

fn tcp_segment(
    client: SocketAddr,
    destination: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0; 128 + payload.len()];
    let length = tcp::emit_packet(
        &mut packet,
        client.ip(),
        destination.ip(),
        &tcp::Header {
            src_port: client.port(),
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
        [payload, &[]],
    )
    .unwrap();
    packet.truncate(length);
    packet
}

fn ipv4_halves(packet: &[u8]) -> [Vec<u8>; 2] {
    std::array::from_fn(|part| {
        let (offset, end, flags) = if part == 0 {
            (0, 16, 0x2000u16)
        } else {
            (16, packet.len() - 20, 2)
        };
        let mut fragment = packet[..20].to_vec();
        fragment.extend_from_slice(&packet[20 + offset..20 + end]);
        let len = fragment.len() as u16;
        fragment[2..4].copy_from_slice(&len.to_be_bytes());
        fragment[6..8].copy_from_slice(&flags.to_be_bytes());
        fragment[10..12].fill(0);
        let sum = wire::checksum::checksum(&fragment[..20]);
        fragment[10..12].copy_from_slice(&sum.to_be_bytes());
        fragment
    })
}

#[tokio::test]
async fn physical_tcp_placement_follows_rx_and_recovers_migrated_scatter_quotes_and_fragments() {
    use futures::FutureExt as _;
    use tokio::io::AsyncReadExt;
    for members in [1, 2] {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (shared, mut inboxes) =
            Shared::new(2, 1600, 2, &budget, Arc::new(AtomicBool::new(true))).unwrap();
        let (realm, owners) = capture_realm(1500, 1, 16, 2, members, &budget).unwrap();
        let plane = crate::control::tests::support::control_plane(Config::default());
        let slots = crate::control::tests::support::tcp_slots(&plane);
        let (endpoints, mut supervisor, mut drivers) = PacketEndpoints::start_driven(
            plane,
            vec![(realm.clone(), owners)],
            4,
            None,
            ScopeId::HOST,
        )
        .await
        .unwrap();
        poll_fn(|cx| supervisor.poll_ready(cx)).await.unwrap();
        let _held = slots
            .clone()
            .try_acquire_many_owned(slots.available_permits() as u32)
            .unwrap();
        let at = Instant::now();
        let scope = realm.scope();
        let ingress = Ingress {
            scope,
            namespace: 1,
            ifindex: 2,
            attachment: 1,
            mark: MarkProvenance::BeforeSkb,
        };
        let path = path();
        let mut placements = Placements::new(1, &budget).unwrap();
        placements.entries.push(Placement {
            realm: realm.clone(),
            realm_id: path.realm,
            ingress,
            device: path.device,
            link: LogicalLink {
                ifindex: 2,
                mtu: 1500,
                mac: [4; 6],
                path: LinkPath {
                    physical_ifindex: 2,
                    vlan_tci: path.vlan_tci,
                    vlan_proto: path.vlan_proto,
                    vlan_count: path.vlan_count,
                },
            },
        });
        assert!(shared.placements.set(Arc::new(placements)).is_ok());
        let destination = SocketAddr::from(([198, 51, 100, 1], 443));
        let mut clients = (41000..60000)
            .map(|port| SocketAddr::from(([192, 0, 2, 1], port)))
            .filter(|client| realm.worker_for_tcp(*client, destination) == 0);
        let client = clients.next().unwrap();
        let input = |local, segments: &[&[u8]]| {
            shared
                .physical_endpoint(
                    &mut None,
                    &endpoints,
                    &realm,
                    local,
                    ingress,
                    segments,
                    PacketView::new(segments).unwrap(),
                    &mut [0; 1500],
                    (at, at),
                    path,
                    false,
                    None,
                    &mut None,
                )
                .unwrap()
        };
        let deliver = |inboxes: &mut [mpsc::Receiver<Envelope>; 2],
                       worker: usize,
                       original: &[u8]| {
            let mut queued = inboxes[worker].try_recv().unwrap();
            if matches!(queued.body, Some(PacketBody::Reassembled(_))) {
                let ip = wire::parse_ip(queued.ip()).unwrap();
                let expected = wire::parse_ip(original).unwrap();
                assert_eq!(
                    (ip.src, ip.dst, ip.proto),
                    (expected.src, expected.dst, expected.proto)
                );
                assert_eq!(&queued.ip()[ip.payload], &original[expected.payload]);
            } else {
                assert_eq!(queued.ip(), original);
            }
            assert!(
                matches!(&queued.payload, Payload::Endpoint { owner, .. } if owner.worker() == worker)
            );
            queued
                .receive_endpoint(&shared, &endpoints, at, None)
                .unwrap();
        };
        let owner = usize::from(members == 1);
        let first = syn(client, destination);
        input(1, &[&first[..21], &first[21..]]);
        if owner == 0 {
            deliver(&mut inboxes, owner, &first);
        }
        assert!(inboxes.iter_mut().all(|inbox| inbox.try_recv().is_err()));
        let actual = &realm.owners()[owner];
        let other = &realm.owners()[1 - owner];
        assert!(endpoints.retains_with_lineage(scope, client, destination, wire::PROTO_TCP, None));
        assert!(!endpoints.retains_with_lineage(
            scope,
            client,
            destination,
            wire::PROTO_TCP,
            std::num::NonZeroU64::new(1)
        ));
        assert!(other.poll_accept().is_none());
        let (_, mut flow) = actual.poll_accept().unwrap();
        actual.drive(at);
        let reply = actual.next_output().await.unwrap();
        let ip = wire::parse_ip(reply.packet()).unwrap();
        let (header, _) = tcp::parse(&reply.packet()[ip.payload]).unwrap();
        assert_eq!(header.flags, tcp::SYN | tcp::ACK);
        let server = header.seq.wrapping_add(1);
        let mut ptb = [0; 256];
        let n = wire::icmp::emit_packet_too_big(
            &mut ptb,
            "198.51.100.2".parse().unwrap(),
            destination.ip(),
            1280,
            reply.packet(),
        )
        .unwrap();
        reply.release();
        let quoted = [&ptb[..21], &ptb[21..n]];
        assert!(retained_endpoint(
            &endpoints,
            scope,
            PacketView::new(&quoted).unwrap()
        ));
        input(1 - owner, &quoted);
        deliver(&mut inboxes, owner, &ptb[..n]);
        let ack = tcp_segment(client, destination, 101, server, tcp::ACK, &[]);
        input(1 - owner, &[&ack]);
        deliver(&mut inboxes, owner, &ack);
        let data = tcp_segment(client, destination, 101, server, tcp::ACK, b"physical data");
        let [head, tail] = ipv4_halves(&data);
        input(1, &[&head]);
        let head = inboxes[0].try_recv().unwrap();
        shared.dispatch_envelope(&endpoints, head, None).unwrap();
        input(0, &[&tail]);
        if owner != 0 {
            deliver(&mut inboxes, owner, &data);
        }
        let mut bytes = [0; 13];
        flow.read_exact(&mut bytes).now_or_never().unwrap().unwrap();
        assert_eq!(&bytes, b"physical data");
        other.drive(at);
        assert!(
            other
                .poll_output(&mut Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        );

        let next_client = clients.next().unwrap();
        let next = syn(next_client, destination);
        assert!(!retained_endpoint(
            &endpoints,
            scope,
            PacketView::from_slice(&next)
        ));
        let mut core =
            honk_datapath::forward::CoreForward::new(&[ingress], Arc::clone(&budget), 1).unwrap();
        let packet = core.receive(ingress, at, &next).unwrap().unwrap();
        shared
            .endpoint_packet(&endpoints, scope, 1, packet, at, path, None, None, None)
            .unwrap();
        if owner == 1 {
            let duplicate = core.receive(ingress, at, &next).unwrap().unwrap();
            shared
                .endpoint_packet(&endpoints, scope, 0, duplicate, at, path, None, None, None)
                .unwrap();
            let late_ack = tcp_segment(next_client, destination, 1, 1, tcp::ACK, &[]);
            input(0, &[&late_ack]);
            deliver(&mut inboxes, owner, &next);
            deliver(&mut inboxes, owner, &next);
            let tail = inboxes[owner].try_recv().unwrap();
            assert_eq!(tail.ip(), &late_ack);
            assert!(
                matches!(&tail.payload, Payload::Endpoint { owner, .. } if owner.worker() == 1)
            );
        }
        assert!(actual.poll_accept().is_some());
        assert!(actual.poll_accept().is_none());
        assert!(other.poll_accept().is_none());

        if members == 1 {
            let fresh = (41000..60000)
                .map(|port| SocketAddr::from(([192, 0, 2, 1], port)))
                .find(|client| realm.worker_for_tcp(*client, destination) == 1)
                .unwrap();
            let [head, tail] = ipv4_halves(&syn(fresh, destination));
            assert!(core.receive(ingress, at, &head).unwrap().is_none());
            let complete = core.receive(ingress, at, &tail).unwrap().unwrap();
            assert!(complete.is_reassembled());
            shared
                .endpoint_packet(&endpoints, scope, 1, complete, at, path, None, None, None)
                .unwrap();
            assert_eq!(realm.owners()[0].poll_accept().unwrap().0.client, fresh);
            assert!(inboxes[1].try_recv().is_err());
        }
        drop(flow);
        endpoints.close();
        let (_, joined) = poll_fn(|cx| {
            for driver in &mut drivers {
                driver.service(cx, Instant::now());
            }
            supervisor.poll_join_plane(cx)
        })
        .await
        .unwrap();
        joined.unwrap();
    }
}

#[test]
fn two_runtime_stack_owners_join_only_after_their_exact_output_returns() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1500, 1, 256, 2, 1, &budget).unwrap();
    let destination = SocketAddr::from(([198, 51, 100, 1], 443));
    let rendezvous = Arc::new(Barrier::new(3));
    let (send, receive) = sync_channel::channel();
    let mut joins = Vec::new();
    let mut completions = Vec::new();
    for (worker, owner) in owners.into_iter().enumerate() {
        let scope = realm.owner(worker).unwrap().clone();
        let client = (4000..60000)
            .map(|port| SocketAddr::from(([192, 0, 2, 1], port)))
            .find(|client| realm.worker_for_tcp(*client, destination) == worker)
            .unwrap();
        let rendezvous = Arc::clone(&rendezvous);
        let send = send.clone();
        let (closed, completion) = sync_channel::channel();
        completions.push(completion);
        joins.push(std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let owner = tokio::spawn(owner.run());
                rendezvous.wait();
                let (rx, _) = scope.receive_with_source(
                    &syn(client, destination),
                    Instant::now(),
                    false,
                    |_, _| true,
                );
                assert_eq!(rx, honk_netstack::Rx::Consumed);
                let (_, flow) = scope.poll_accept().unwrap();
                let output = scope.next_output().await.unwrap();
                let ip = wire::parse_ip(output.packet()).unwrap();
                let (header, _) = tcp::parse(&output.packet()[ip.payload]).unwrap();
                assert_eq!(header.flags & (tcp::SYN | tcp::ACK), tcp::SYN | tcp::ACK);
                assert_eq!(header.dst_port, client.port());
                drop(flow);
                scope.shutdown(true);
                assert!(
                    send.send((worker, std::thread::current().id(), output))
                        .is_ok()
                );
                owner.await.unwrap();
                closed.send(()).unwrap();
            });
        }));
    }
    rendezvous.wait();
    let mut outputs: [Option<OutputLease>; 2] = [None, None];
    let mut tids = [None, None];
    for _ in 0..2 {
        let (worker, tid, output) = receive.recv_timeout(Duration::from_secs(5)).unwrap();
        outputs[worker] = Some(output);
        tids[worker] = Some(tid);
    }
    assert_ne!(tids[0], tids[1]);
    assert_eq!(
        outputs[0].as_ref().unwrap().scope(),
        outputs[1].as_ref().unwrap().scope()
    );
    assert_eq!(
        outputs[0].as_ref().unwrap().flow_id(),
        outputs[1].as_ref().unwrap().flow_id()
    );
    assert!(completions.iter().all(|completion| matches!(
        completion.try_recv(),
        Err(sync_channel::TryRecvError::Empty)
    )));
    outputs[0].take().unwrap().release();
    completions[0].recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        matches!(
            completions[1].try_recv(),
            Err(sync_channel::TryRecvError::Empty)
        ),
        "same logical scope and FlowId cannot release the other Stack"
    );
    outputs[1].take().unwrap().release();
    completions[1].recv_timeout(Duration::from_secs(5)).unwrap();
    for join in joins {
        join.join().unwrap();
    }
}

#[test]
fn calibration_requires_both_actual_owner_contexts_and_changes_with_either() {
    let budget = MemoryBudget::new(32 << 20);
    let (shared, _) = Shared::new(2, 128, 2, &budget, Arc::new(AtomicBool::new(false))).unwrap();
    shared.polling_context(0, Ok("queue0-cpu0".into()));
    assert!(shared.combined_polling_context().is_err());
    shared.polling_context(1, Ok("queue1-cpu1".into()));
    let both = shared.combined_polling_context().unwrap();
    assert_ne!(
        both, "queue0-cpu0",
        "single-owner evidence cannot authorize two-owner polling"
    );
    shared.polling_context(1, Ok("queue1-cpu2".into()));
    assert_ne!(both, shared.combined_polling_context().unwrap());
    shared.polling_context(1, Err("offload_query_failed"));
    assert_eq!(
        shared.combined_polling_context(),
        Err("offload_query_failed")
    );
}

#[test]
fn peer_unwind_closes_common_admission_before_refunding_identity() {
    let admission = Arc::new(AtomicBool::new(true));
    let peers = PeerAuthority::isolated(Arc::clone(&admission));
    let scope = ScopeId::allocate().unwrap();
    let hold = peers
        .retain(
            scope,
            source(4000, Some(tcp::SYN)),
            path(),
            Instant::now(),
            false,
        )
        .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _hold = hold;
        panic!("injected protocol owner unwind");
    }));
    assert!(result.is_err());
    assert!(!admission.load(Ordering::Acquire));
    assert_eq!(peers.pin_count(0), 0);
}

#[tokio::test]
async fn quiescence_waits_for_worker_to_seal_its_mailbox() {
    quiesce_mailbox(true).await;
}

#[tokio::test]
async fn idle_secondary_rearms_quiesce_after_begin_close_during_wake_drain() {
    quiesce_mailbox(false).await;
}

async fn quiesce_mailbox(close_before_start: bool) {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let admission = Arc::new(AtomicBool::new(true));
    let (shared, [_, receiver]) = Shared::new(2, 128, 2, &budget, Arc::clone(&admission)).unwrap();
    let permit = shared.senders[1].clone().try_reserve_owned().unwrap();
    assert!(
        shared
            .placements
            .set(Arc::new(Placements::new(0, &budget).unwrap()))
            .is_ok()
    );
    let (realm, mut owners) = capture_realm(1500, 1, 16, 1, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap().clone();
    let config = Config::default();
    let polling = AdaptivePoll::new(polling::PollingPublication::new(&config), None);
    let plane = crate::control::tests::support::control_plane(config);
    let shutdown = plane.shutdown_intent();
    let (endpoints, supervisor) =
        PacketEndpoints::new(plane, vec![(scope.clone(), owners.pop().unwrap())], 4)
            .await
            .unwrap();

    if close_before_start {
        shared.begin_close();
    }
    let quiescing = poll_fn(|cx| shared.poll_quiesced(cx));
    tokio::pin!(quiescing);
    assert!(futures::poll!(quiescing.as_mut()).is_pending());

    let mut worker = Worker::start(
        Arc::clone(&shared),
        &mut [],
        Vec::new(),
        endpoints.clone(),
        receiver,
        false,
        polling,
        budget,
        shutdown,
    )
    .unwrap();
    if !close_before_start {
        let control = worker.test_control();
        tokio::time::timeout(Duration::from_secs(5), async {
            while control.pending_wait().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Force begin_close into the first pass after idle, before it drains old wakes.
        shared
            .close_before_secondary_drain
            .store(true, Ordering::Release);
        shared.wake_worker(1);
    }
    tokio::time::timeout(Duration::from_secs(5), shared.senders[1].closed())
        .await
        .unwrap();
    // Once the receiver closes, this pass has already sampled an unarmed drain.
    assert!(!admission.load(Ordering::Acquire));
    assert!(futures::poll!(quiescing.as_mut()).is_pending());
    shared.quiesce(Instant::now() + Duration::from_secs(5));
    tokio::time::timeout(Duration::from_secs(5), quiescing)
        .await
        .unwrap()
        .unwrap();

    let rejected = shared.send(1, envelope(&shared, 7, scope.scope(), Instant::now()));
    assert!(rejected.is_err());
    drop(rejected);
    assert!(!shared.states[1].lock().exited);
    endpoints.close();
    supervisor.run().await.unwrap();
    let mut joining = std::pin::pin!(worker.join());
    assert!(
        futures::poll!(joining.as_mut()).is_pending(),
        "a producer's reserved mailbox slot keeps the closed receiver nonterminal"
    );
    let late = envelope(&shared, 8, scope.scope(), Instant::now());
    drop(permit.send(late));
    tokio::time::timeout(Duration::from_secs(5), joining)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(shared.pool.free.lock().len(), CELLS);
}

#[test]
fn emergency_close_revokes_worker_drain_permission() {
    let budget = MemoryBudget::new(32 << 20);
    let (shared, _) = Shared::new(2, 128, 2, &budget, Arc::new(AtomicBool::new(true))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    shared.quiesce(deadline);
    assert!(shared.can_kick_outstanding());

    shared.close();
    shared.quiesce(deadline);
    assert!(!shared.can_kick_outstanding());
    shared.acknowledge_quiescence();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(shared.poll_quiesced(&mut cx).is_pending());
}

#[test]
fn elapsed_quiesce_deadline_prevents_a_late_acknowledgement() {
    let budget = MemoryBudget::new(32 << 20);
    let (shared, _) = Shared::new(2, 128, 2, &budget, Arc::new(AtomicBool::new(true))).unwrap();
    shared.quiesce(Instant::now());
    assert!(!shared.can_kick_outstanding());
    shared.acknowledge_quiescence();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(shared.poll_quiesced(&mut cx).is_pending());
}

#[tokio::test]
async fn failed_retained_worker_reports_before_joining_its_live_thread() {
    let budget = MemoryBudget::new(32 << 20);
    let (shared, _) = Shared::new(2, 128, 2, &budget, Arc::new(AtomicBool::new(true))).unwrap();
    let (fail, failed) = sync_channel::channel();
    let (release, retained) = sync_channel::channel();
    let (finished, terminal) = tokio::sync::oneshot::channel();
    let thread_shared = Arc::clone(&shared);
    let thread = std::thread::spawn(move || {
        failed.recv().unwrap();
        thread_shared.failed(1, anyhow::anyhow!("injected retained worker failure"));
        let _ = retained.recv();
        thread_shared.states[1].lock().exited = true;
        thread_shared.wake_worker(0);
        let _ = finished.send(());
    });
    let mut worker = Worker {
        shared: Arc::clone(&shared),
        thread: Some(thread),
    };
    shared.quiesce(Instant::now() + Duration::from_secs(5));
    let quiescing = poll_fn(|cx| shared.poll_quiesced(cx));
    tokio::pin!(quiescing);
    assert!(futures::poll!(quiescing.as_mut()).is_pending());
    let result = {
        let joining = worker.join();
        tokio::pin!(joining);
        poll_fn(|cx| match joining.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("nonterminal worker reported joined"),
        })
        .await;
        fail.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            (quiescing.as_mut().await, joining.as_mut().await)
        })
        .await
    };
    let retained_thread = worker
        .thread
        .as_ref()
        .is_some_and(|thread| !thread.is_finished());
    let still_nonterminal = !shared.states[1].lock().exited;
    release.send(()).unwrap();
    terminal.await.unwrap();
    if let Some(thread) = worker.thread.take() {
        tokio::task::spawn_blocking(move || thread.join())
            .await
            .unwrap()
            .unwrap();
    }
    let (quiesced, joined) = result.expect("failure must wake both waits before thread exit");
    for result in [quiesced, joined] {
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected retained worker failure")
        );
    }
    assert!(
        retained_thread && still_nonterminal,
        "failure keeps the actual live thread in its owner"
    );
    assert!(!shared.admission.load(Ordering::Acquire));
}

#[tokio::test]
async fn worker_one_panic_rejects_readiness_and_join_while_retained() {
    // A real retained worker outlives this test, so give it its own process.
    if crate::test_support::run_exact_in_child(
        "HONK_XDP_WORKER_PANIC_CHILD",
        "xdp::worker::tests::worker_one_panic_rejects_readiness_and_join_while_retained",
    ) {
        return;
    }

    const WAIT: Duration = Duration::from_secs(5);
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let admission = Arc::new(AtomicBool::new(false));
    let (shared, [_, receiver]) = Shared::new(2, 128, 2, &budget, Arc::clone(&admission)).unwrap();
    assert!(
        shared
            .placements
            .set(Arc::new(Placements::new(0, &budget).unwrap()))
            .is_ok()
    );
    let (realm, mut owners) = capture_realm(1500, 1, 16, 1, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap().clone();
    let config = Config::default();
    let polling = AdaptivePoll::new(polling::PollingPublication::new(&config), None);
    let plane = crate::control::tests::support::control_plane(config);
    let shutdown = plane.shutdown_intent();
    let (endpoints, supervisor) = tokio::time::timeout(
        WAIT,
        PacketEndpoints::new(plane, vec![(scope.clone(), owners.pop().unwrap())], 1),
    )
    .await
    .unwrap()
    .unwrap();

    shared.ready(0);
    assert!(
        shared
            .all_ready(&mut Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );
    let mut worker = Worker::start(
        Arc::clone(&shared),
        &mut [],
        Vec::new(),
        endpoints.clone(),
        receiver,
        false,
        polling,
        budget,
        shutdown,
    )
    .unwrap();
    tokio::time::timeout(WAIT, poll_fn(|cx| shared.all_ready(cx)))
        .await
        .unwrap()
        .unwrap();

    // Fault the internal envelope extent after the real worker has published readiness.
    let mut fault = envelope(&shared, 1, scope.scope(), Instant::now());
    fault.payload = Payload::Endpoint {
        owner: scope,
        admission: None,
        check_output: false,
    };
    fault.l3_length += 1;
    admission.store(true, Ordering::Release);
    assert!(shared.send(1, fault).is_ok());
    let failure = tokio::time::timeout(WAIT, poll_fn(|cx| shared.poll_quiesced(cx)))
        .await
        .expect("the actual worker panic must wake the coordinator")
        .unwrap_err();
    assert!(failure.to_string().contains("XDP worker 1 panicked"));
    tokio::time::timeout(WAIT, async {
        while admission.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker panic must close capture admission");
    assert!(matches!(
        shared.all_ready(&mut Context::from_waker(std::task::Waker::noop())),
        Poll::Ready(Err(_))
    ));
    let joined = tokio::time::timeout(WAIT, worker.join())
        .await
        .expect("join must report failure without waiting for the retained thread")
        .unwrap_err();
    assert_eq!(joined.to_string(), failure.to_string());
    assert!(!shared.states[1].lock().exited);
    assert!(
        worker
            .thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    );

    endpoints.close();
    tokio::time::timeout(WAIT, supervisor.run())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !shared.senders[1].is_closed(),
        "the retained worker still owns its mailbox"
    );
}
