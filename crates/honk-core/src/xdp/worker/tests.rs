use super::*;
use honk_netstack::wire::tcp;
use std::net::SocketAddr;
use std::sync::{Barrier, mpsc as sync_channel};

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
    let (realm, mut owners) = capture_realm(1500, 1, 16, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap();
    let plane = crate::control::tests::support::control_plane(Config::default());
    let (endpoints, supervisor) =
        PacketEndpoints::new(plane, vec![(scope.clone(), owners.pop().unwrap())], 4)
            .await
            .unwrap();
    let peers = PeerAuthority::new(Arc::new(AtomicBool::new(true)));
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
    let (realm, mut owners) = capture_realm(1500, 1, 16, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap();
    let plane = crate::control::tests::support::control_plane(Config::default());
    let (endpoints, supervisor) =
        PacketEndpoints::new(plane, vec![(scope.clone(), owners.pop().unwrap())], 1)
            .await
            .unwrap();
    let peers = PeerAuthority::new(Arc::new(AtomicBool::new(true)));
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
    let high_holds = peers
        .0
        .lock()
        .iter()
        .find(|peer| peer.address == high.ip())
        .unwrap()
        .holds;
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
    let cell = shared.copy(&[&first, &last], &metadata).unwrap();
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
        shared.pool.take().is_none(),
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
}

#[test]
fn bond_peer_moves_future_replies_without_rewriting_retained_output() {
    let peers = PeerAuthority::new(Arc::new(AtomicBool::new(true)));
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
    let peers = PeerAuthority::new(Arc::new(AtomicBool::new(true)));
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
    assert_eq!(peers.0.lock().len(), 1);
}

fn syn(client: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut packet = vec![0; 128];
    let length = tcp::emit_packet(
        &mut packet,
        client.ip(),
        destination.ip(),
        &tcp::Header {
            src_port: client.port(),
            dst_port: destination.port(),
            seq: 100,
            ack: 0,
            flags: tcp::SYN,
            window: 60000,
            urgent: 0,
            options: tcp::Options {
                mss: Some(1460),
                ..Default::default()
            },
        },
        [&[], &[]],
    )
    .unwrap();
    packet.truncate(length);
    packet
}

#[test]
fn two_runtime_stack_owners_join_only_after_their_exact_output_returns() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let (realm, owners) = capture_realm(1500, 1, 256, 2, &budget).unwrap();
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
    let peers = PeerAuthority::new(Arc::clone(&admission));
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
    assert_eq!(peers.0.lock()[0].holds, 0);
}

#[tokio::test]
async fn quiescence_waits_for_worker_to_seal_its_mailbox() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let admission = Arc::new(AtomicBool::new(true));
    let (shared, [_, receiver]) = Shared::new(2, 128, 2, &budget, Arc::clone(&admission)).unwrap();
    let (realm, mut owners) = capture_realm(1500, 1, 16, 1, &budget).unwrap();
    let scope = realm.owner(0).unwrap().clone();
    let config = Config::default();
    let polling = AdaptivePoll::new(polling::PollingPublication::new(&config), None);
    let plane = crate::control::tests::support::control_plane(config);
    let shutdown = plane.shutdown_intent();
    let (endpoints, supervisor) =
        PacketEndpoints::new(plane, vec![(scope.clone(), owners.pop().unwrap())], 4)
            .await
            .unwrap();

    shared.begin_close();
    assert!(!admission.load(Ordering::Acquire));
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
    tokio::time::timeout(Duration::from_secs(5), shared.senders[1].closed())
        .await
        .unwrap();
    assert!(futures::poll!(quiescing.as_mut()).is_pending());
    shared.quiesce(Instant::now() + Duration::from_secs(5));
    tokio::time::timeout(Duration::from_secs(5), quiescing)
        .await
        .unwrap()
        .unwrap();

    let rejected = shared.send(1, envelope(&shared, 7, scope.scope(), Instant::now()));
    assert!(rejected.is_err());
    assert!(!shared.states[1].lock().exited);
    endpoints.close();
    supervisor.run().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), worker.join())
        .await
        .unwrap()
        .unwrap();
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
