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
    assert!(!pool.close_exact(old.scope, client, dst, owner.token, old.generation));
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
