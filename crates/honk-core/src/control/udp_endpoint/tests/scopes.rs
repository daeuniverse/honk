use super::*;

fn slow_permit() -> OwnedSemaphorePermit {
    Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap()
}

#[tokio::test]
async fn pending_scopes_share_capacity_but_not_queues_or_retirement() {
    let pool = Arc::new(UdpEndpointPool::with_capacity_limit(2));
    let stats = StatsManager::new();
    let scopes = [ScopeId::allocate().unwrap(), ScopeId::allocate().unwrap()];
    let client = make_addr("192.0.2.1", 40000);
    let dst = make_addr("198.51.100.1", 443);
    let owner = UdpFlowOwner::new(71, Some(99)).unwrap();
    let (removed_tx, mut removed_rx) = mpsc::channel(8);
    pool.set_remove_sink(removed_tx);
    let reserve = |scope, data: &'static [u8], expected| {
        pool.reserve_owned_or_enqueue_at(
            scope,
            client,
            dst,
            Bytes::from_static(data),
            owner,
            expected,
            slow_permit(),
            Instant::now(),
            &stats,
        )
    };
    let EndpointReservation::Initializing(mut a) = reserve(scopes[0], b"first-a", None) else {
        panic!("first scope must reserve");
    };
    let EndpointReservation::Initializing(mut b) = reserve(scopes[1], b"first-b", None) else {
        panic!("overlapping tuple in another scope must reserve independently");
    };
    assert_eq!((a.scope(), b.scope()), (scopes[0], scopes[1]));
    assert_eq!((a.owner(), b.owner()), (owner, owner));
    assert!(matches!(
        reserve(ScopeId::HOST, b"over-capacity", None),
        EndpointReservation::CapacityRejected
    ));
    assert!(matches!(
        reserve(scopes[0], b"follower-a", Some(a.generation())),
        EndpointReservation::Enqueued
    ));
    assert_eq!(
        pool.enqueue_owned_by_token_at(
            scopes[1],
            client,
            dst,
            Bytes::from_static(b"follower-b"),
            owner,
            Instant::now(),
            &stats,
        ),
        Ok(b.generation())
    );
    let mut queue_a = a.take_queue_receiver().unwrap();
    let mut queue_b = b.take_queue_receiver().unwrap();
    assert_eq!(a.take_first().unwrap().payload(), b"first-a");
    assert_eq!(b.take_first().unwrap().payload(), b"first-b");
    assert_eq!(queue_a.try_recv().unwrap().payload(), b"follower-a");
    assert_eq!(queue_b.try_recv().unwrap().payload(), b"follower-b");
    assert!(queue_a.try_recv().is_err());
    assert!(queue_b.try_recv().is_err());

    assert!(pool.retire_staged_identity(scopes[0], client, dst, owner.token, a.generation()));
    let old = removed_rx.try_recv().unwrap();
    assert_eq!((old.scope, old.owner), (scopes[0], owner));
    drop(a);
    assert!(b.still_initializing());
    pool.finish_removal(&old, true);
    let EndpointReservation::Initializing(replacement) = reserve(scopes[0], b"replacement", None)
    else {
        panic!("acknowledged scope may reuse its tuple");
    };
    assert_ne!(replacement.generation(), old.generation);
    pool.finish_removal(&old, true);
    assert!(!pool.close_exact(old.scope, client, dst, owner.token, old.generation, None));
    assert!(replacement.still_initializing());
    assert!(b.still_initializing());

    drop((b, replacement, queue_a, queue_b));
    for _ in 0..2 {
        let removal = removed_rx.try_recv().unwrap();
        pool.finish_removal(&removal, true);
    }
    assert!(pool.is_empty());
    assert_eq!(pool.endpoint_slots.available_permits(), 2);
    assert_eq!(
        pool.global_payload_bytes.available_permits(),
        GLOBAL_PAYLOAD_CAPACITY
    );
    assert!(pool.shutdown().await.joined);
}

#[tokio::test]
async fn tracker_close_keeps_its_scope_after_tuple_reuse() {
    use crate::connection_tracker::{CloseOutcome, ConnectionTracker};

    let pool = Arc::new(UdpEndpointPool::with_capacity_limit(2));
    let stats = StatsManager::new();
    let tracker = ConnectionTracker::new();
    tracker.enable();
    let scopes = [ScopeId::HOST, ScopeId::allocate().unwrap()];
    let client = make_addr("127.0.0.1", 40000);
    let dst = make_addr("127.0.0.1", 40001);
    let (removed_tx, mut removed_rx) = mpsc::channel(8);
    pool.set_remove_sink(removed_tx);
    let mut endpoints = Vec::new();
    for (scope, id) in scopes.into_iter().zip(["scope-a", "scope-b"]) {
        let EndpointReservation::Initializing(mut lease) = pool.reserve_owned_or_enqueue(
            scope,
            client,
            dst,
            Bytes::from_static(b"first"),
            71,
            None,
            slow_permit(),
            &stats,
        ) else {
            panic!("scoped tuple must reserve");
        };
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let endpoint = Arc::new(UdpEndpoint::new(
            transport(socket, dst),
            dst,
            uuid::Uuid::new_v4(),
        ));
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        pool.register_ready_tracker(
            scope,
            client,
            dst,
            71,
            lease.generation(),
            &endpoint,
            &tracker,
            Vec::new(),
            || closure::tracked_entry(id, client, dst),
        )
        .unwrap();
        endpoints.push(endpoint);
    }
    let mut close = Box::pin(tracker.close_id("scope-a"));
    assert!(futures::poll!(&mut close).is_pending());
    let old = removed_rx.try_recv().unwrap();
    assert_eq!(old.scope, scopes[0]);
    assert!(pool.get(scopes[1], client, dst).is_some());
    drop(endpoints.remove(0));
    assert!(pool.wait_removal_io(&old).await);
    pool.finish_removal(&old, true);
    assert_eq!(close.await, CloseOutcome::Closed);

    let EndpointReservation::Initializing(replacement) = pool.reserve_owned_or_enqueue(
        scopes[0],
        client,
        dst,
        Bytes::from_static(b"replacement"),
        71,
        None,
        slow_permit(),
        &stats,
    ) else {
        panic!("closed scope must permit a new incarnation");
    };
    assert_eq!(tracker.close_id("scope-a").await, CloseOutcome::Closed);
    assert!(replacement.still_initializing());
    assert!(pool.get(scopes[1], client, dst).is_some());
    pool.remove(scopes[1], client, dst);
    drop((replacement, endpoints));
    for _ in 0..2 {
        let removal = removed_rx.try_recv().unwrap();
        assert!(pool.wait_removal_io(&removal).await);
        pool.finish_removal(&removal, true);
    }
    assert!(pool.shutdown().await.joined);
}

#[tokio::test]
async fn host_lineage_fences_followers_tracker_close_and_retirement() {
    let (scope, _owner) = host_packet_scope();
    let first = scope.hold_host_source(&host_facts(11, 7)).unwrap();
    let changed = scope.hold_host_source(&host_facts(11, 8)).unwrap();
    let other = scope.hold_host_source(&host_facts(12, 7)).unwrap();
    assert_eq!(first.context().lineage, changed.context().lineage);
    assert_ne!(first.context().snapshot, changed.context().snapshot);
    assert_ne!(first.context().lineage, other.context().lineage);
    let pool = Arc::new(UdpEndpointPool::with_capacity_limit(2));
    let stats = StatsManager::new();
    let tracker = crate::connection_tracker::ConnectionTracker::new();
    tracker.enable();
    let (removed_tx, mut removed_rx) = mpsc::channel(4);
    pool.set_remove_sink(removed_tx);
    let client = make_addr("192.0.2.1", 40000);
    let target = make_addr("198.51.100.1", 443);
    let reserve = |source: SourceWork| {
        pool.reserve_payload_or_enqueue_at(
            scope.scope(),
            client,
            target,
            DatagramPayload::Borrowed(b"first"),
            None,
            UdpFlowOwner::packet(),
            pool.initialization_epoch(),
            slow_permit(),
            queue_now(),
            &stats,
            Some(source),
        )
    };
    let EndpointReservation::Initializing(mut a) = reserve(first.clone()) else {
        panic!("first Host initializer");
    };
    let EndpointReservation::Initializing(mut b) = reserve(other.clone()) else {
        panic!("separate Host initializer");
    };
    assert_eq!(a.packet_source().unwrap().facts().skb_mark, 7);
    let mut queue_a = a.take_queue_receiver().unwrap();
    let mut queue_b = b.take_queue_receiver().unwrap();
    assert!(matches!(
        pool.enqueue_bound_payload_at(
            scope.scope(),
            client,
            target,
            DatagramPayload::Borrowed(b"follower"),
            None,
            queue_now(),
            &stats,
            Some(changed.context().lineage),
            Some(pool.initialization_epoch()),
        ),
        Some((EndpointReservation::Enqueued, false))
    ));
    assert_eq!(queue_a.try_recv().unwrap().payload(), b"follower");
    assert!(queue_b.try_recv().is_err());
    assert_eq!(a.packet_source().unwrap().context(), first.context());
    let mut endpoints = Vec::new();
    for (lease, source, id) in [(&mut a, &first, "host-a"), (&mut b, &other, "host-b")] {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut endpoint =
            UdpEndpoint::new(transport(socket, target), target, uuid::Uuid::new_v4());
        endpoint.bind_packet_source(Some(source.clone())).unwrap();
        let endpoint = Arc::new(endpoint);
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        pool.register_ready_tracker(
            scope.scope(),
            client,
            target,
            0,
            lease.generation(),
            &endpoint,
            &tracker,
            Vec::new(),
            || closure::tracked_entry(id, client, target),
        )
        .unwrap();
        endpoints.push(endpoint);
    }
    assert!(!pool.close_exact(scope.scope(), client, target, 0, a.generation(), None));
    let mut closed = Box::pin(tracker.close_id("host-a"));
    assert!(futures::poll!(&mut closed).is_pending());
    let removal = removed_rx.try_recv().unwrap();
    assert_eq!(removal.packet_lineage, Some(first.context().lineage));
    let key = EndpointKey::new(scope.scope(), client, target, removal.packet_lineage);
    assert!(
        matches!(pool.endpoints.get(&key).unwrap().value(), EndpointEntry::Retiring {
        _packet_source: Some(source), ..
    } if source.context() == first.context())
    );
    assert!(pool.contains(scope.scope(), client, target, Some(other.context().lineage)));
    assert_eq!(endpoints[0].packet_source().unwrap().facts().skb_mark, 7);
    drop(endpoints.remove(0));
    assert!(pool.wait_removal_io(&removal).await);
    pool.finish_removal(&removal, true);
    assert_eq!(
        closed.await,
        crate::connection_tracker::CloseOutcome::Closed
    );
    assert!(!pool.close_exact(
        scope.scope(),
        client,
        target,
        0,
        b.generation(),
        removal.packet_lineage
    ));
    assert!(pool.close_exact(
        scope.scope(),
        client,
        target,
        0,
        b.generation(),
        Some(other.context().lineage)
    ));
    drop(endpoints);
    let removal = removed_rx.try_recv().unwrap();
    assert!(pool.wait_removal_io(&removal).await);
    pool.finish_removal(&removal, true);
    drop((a, b, queue_a, queue_b, first, changed, other));
    assert!(pool.shutdown().await.joined);
}

#[derive(Debug)]
struct HostReplies {
    scope: crate::control::netstack::PacketScope,
    first_creates: std::sync::Barrier,
    creates: AtomicUsize,
}

impl UdpReplySocketFactory for HostReplies {
    fn create(
        &self,
        scope: ScopeId,
        address: SocketAddr,
        source: Option<&SourceWork>,
    ) -> io::Result<ReplySocketFd> {
        assert_eq!(scope, self.scope.scope());
        if self.creates.fetch_add(1, Ordering::Relaxed) < 2 {
            self.first_creates.wait();
        }
        self.scope
            .datagram_sender_for(address, source.expect("Host reply source").clone())
            .map(ReplySocketFd::Packet)
    }

    fn uses_fd(&self) -> bool {
        false
    }
}

#[test]
fn host_reply_cache_rechecks_races_and_separates_full_snapshots() {
    let (scope, _owner) = host_packet_scope();
    let source = scope.hold_host_source(&host_facts(21, 7)).unwrap();
    let changed = scope.hold_host_source(&host_facts(21, 8)).unwrap();
    let other = scope.hold_host_source(&host_facts(22, 7)).unwrap();
    let pool = UdpEndpointPool::with_reply_socket_factory(
        1,
        Arc::new(HostReplies {
            scope: scope.clone(),
            first_creates: std::sync::Barrier::new(2),
            creates: AtomicUsize::new(0),
        }),
    );
    let peer = make_addr("198.51.100.1", 9000);
    let (first, raced) = std::thread::scope(|threads| {
        let create = || {
            pool.foreign_replies
                .get(scope.scope(), peer, Some(&source))
                .unwrap()
        };
        let first = threads.spawn(create);
        let raced = threads.spawn(create);
        (first.join().unwrap(), raced.join().unwrap())
    });
    assert!(Arc::ptr_eq(&first, &raced));
    let changed_reply = pool
        .foreign_replies
        .get(scope.scope(), peer, Some(&changed))
        .unwrap();
    let other_reply = pool
        .foreign_replies
        .get(scope.scope(), peer, Some(&other))
        .unwrap();
    assert!(!Arc::ptr_eq(&first, &changed_reply));
    assert!(!Arc::ptr_eq(&first, &other_reply));
    assert_eq!(first.packet_source, Some(source.context()));
    assert_eq!(changed_reply.packet_source, Some(changed.context()));
    assert_eq!(pool.foreign_replies.cached().len(), 3);
    pool.foreign_replies.clear();
    assert!(pool.foreign_replies.cached().is_empty());
    assert_eq!(first.packet_source, Some(source.context()));
    drop((first, raced, changed_reply, other_reply));
}
