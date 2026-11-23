use super::*;
use crate::control::ShutdownIntent;

fn shared(workers: u8, budget: &Arc<MemoryBudget>) -> Arc<Shared> {
    Shared::new(workers, 128, 2, budget, Arc::new(AtomicBool::new(false)))
        .unwrap()
        .0
}

#[tokio::test]
async fn secondary_startup_failure_interrupts_pending_endpoint_readiness() {
    let workers = shared(2, &MemoryBudget::new(CAPTURE_MEMORY));
    let shutdown = ShutdownIntent::default();
    workers.ready(0);
    let mut startup = std::pin::pin!(wait_capture_startup(
        &workers,
        true,
        &shutdown,
        |_| Poll::Pending,
        |_| Poll::Pending,
    ));
    assert!(futures::poll!(&mut startup).is_pending());
    workers.failed(1, anyhow::anyhow!("secondary socket registration failed"));
    assert_eq!(
        futures::poll!(&mut startup).map(|result| result.unwrap_err().to_string()),
        Poll::Ready("secondary socket registration failed".into())
    );
}

#[tokio::test]
async fn endpoint_readiness_is_consumed_once_while_waiting_for_secondary() {
    let workers = shared(2, &MemoryBudget::new(CAPTURE_MEMORY));
    let shutdown = ShutdownIntent::default();
    workers.ready(0);
    let mut endpoint_ready = Some(());
    let mut startup = std::pin::pin!(wait_capture_startup(
        &workers,
        false,
        &shutdown,
        |_| {
            assert!(
                endpoint_ready.take().is_some(),
                "endpoint readiness consumed twice"
            );
            Poll::Ready(Ok(()))
        },
        |_| Poll::Pending,
    ));
    assert!(futures::poll!(&mut startup).is_pending());
    workers.ready(1);
    assert!(matches!(futures::poll!(&mut startup), Poll::Ready(Ok(()))));
}

#[tokio::test]
async fn partial_fence_budget_refunds_first_owner_and_publishes_neither() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let workers = shared(2, &budget);
    let shutdown = ShutdownIntent::default();
    let (realm, _owners) = capture_realm(1500, 16, 16, 2, 1, &budget).unwrap();
    let probe = DirectRelayFence::new(&budget).unwrap();
    let before_drop = budget.used();
    drop(probe);
    let one_fence = before_drop - budget.used();
    let pressure = budget
        .reserve(budget.limit() - budget.used() - one_fence)
        .unwrap();
    let before = budget.used();
    workers.prepare_relays(&budget).unwrap();
    assert_eq!(budget.used(), before);
    workers.publish_relays(&realm, &shutdown).unwrap();
    assert!(workers.relays.get().is_none());
    assert!(
        realm
            .owners()
            .iter()
            .all(|scope| !scope.direct_relay_published())
    );
    drop(pressure);
    workers.prepare_relays(&budget).unwrap();
    assert!(
        workers.publish_relays(&realm, &shutdown).is_err(),
        "secondary has not registered its runtime"
    );
    assert!(
        realm
            .owners()
            .iter()
            .all(|scope| !scope.direct_relay_published())
    );
}

#[tokio::test]
async fn shutdown_winning_before_publication_leaves_both_relay_owners_unbound() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let workers = shared(2, &budget);
    let (realm, _owners) = capture_realm(1500, 16, 16, 2, 1, &budget).unwrap();
    workers.prepare_relays(&budget).unwrap();
    workers.ready(1);

    let shutdown = ShutdownIntent::default();
    let _state = workers.states[1].lock();
    // A shutdown request can finish while activation still owns the worker status lock.
    shutdown.request();
    let result = workers.publish_relays(&realm, &shutdown);
    assert!(
        !realm
            .owners()
            .iter()
            .any(PacketScope::direct_relay_published),
        "shutdown published relay owners"
    );
    assert!(result.is_err());
    assert!(!workers.admission.load(Ordering::Acquire));
}

#[tokio::test]
async fn close_and_activation_orders_keep_capture_closed() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let plane = crate::control::tests::support::control_plane(Config::default());
    let shutdown = plane.shutdown_intent();
    let pair = capture_scope(1500, 16, 16, &budget).unwrap();
    let id = pair.0.scope();
    let (endpoints, owner) = PacketEndpoints::new(plane, vec![pair], 1).await.unwrap();

    let before = shared(1, &budget);
    before.begin_close();
    assert!(
        before
            .activate(&shutdown, &endpoints, None, std::iter::empty())
            .is_err()
    );
    assert!(!before.admission.load(Ordering::Acquire));

    let late = shared(1, &budget);
    late.prepare_relays(&budget).unwrap();
    let packet = endpoints.realm(id).unwrap();
    let probe = std::iter::once_with(|| {
        late.failed(0, anyhow::anyhow!("failed during final PF check"));
        (packet, 1, true)
    });
    assert!(
        late.activate(&shutdown, &endpoints, Some(DirectProfile::Endpoint), probe)
            .is_err()
    );
    assert!(!late.admission.load(Ordering::Acquire));
    assert!(!packet.owners()[0].direct_relay_published());

    let after = shared(1, &budget);
    after
        .activate(&shutdown, &endpoints, None, std::iter::empty())
        .unwrap();
    assert!(after.admission.load(Ordering::Acquire));
    // An external backend can close the raw gate after publication. Startup is one-shot.
    after.admission.store(false, Ordering::Release);
    assert!(
        after
            .activate(&shutdown, &endpoints, None, std::iter::empty())
            .is_err()
    );
    assert!(!after.admission.load(Ordering::Acquire));
    let running = shared(1, &budget);
    running
        .activate(&shutdown, &endpoints, None, std::iter::empty())
        .unwrap();
    running.failed(0, anyhow::anyhow!("failed after activation"));
    assert!(!running.admission.load(Ordering::Acquire));

    let requested = shared(1, &budget);
    shutdown.request();
    assert!(
        requested
            .activate(&shutdown, &endpoints, None, std::iter::empty())
            .is_err()
    );
    assert!(!requested.admission.load(Ordering::Acquire));
    endpoints.close();
    owner.run().await.unwrap();
}
