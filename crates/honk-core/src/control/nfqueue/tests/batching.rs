use super::*;
use crate::ebpf::mock::MockEbpfBackend;
use std::sync::atomic::{AtomicU32, Ordering};

fn deadline(fixture: &DecisionFixture, remaining: Duration) {
    let cell = fixture.pending.matching_cell(fixture.identity).unwrap();
    let mut state = cell.state.lock();
    let CellState::Pending { started_at, .. } = &mut *state else {
        panic!("pending fixture")
    };
    *started_at = Instant::now() - HARD_HOLD_TIMEOUT + remaining;
}

fn pair(mut mock: MockEbpfBackend) -> (DecisionFixture, UdpInitLease, PendingUdpIdentity) {
    let key = FlowKey::new(
        "192.0.2.10:40001".parse().unwrap(),
        "198.51.100.20:443".parse().unwrap(),
    );
    mock.seed_staged_udp_flow(
        &key.tuples(),
        retained(42, UdpDecisionState::Pending, ROUTING_META_FLAG_PUBLISHED),
    );
    let fixture = pending_fixture_with(41, mock);
    let lease = match fixture.pending.endpoints.reserve_owned_or_enqueue(
        honk_datapath::ScopeId::HOST,
        key.client,
        key.destination,
        bytes::Bytes::from_static(b"second"),
        42,
        None,
        test_flow_slot(),
        &fixture.stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("second flow must initialize"),
    };
    let identity = PendingUdpVerdicts::identity_for_lease(&lease);
    fixture.pending.cells.insert(
        key,
        Arc::new(FlowCell::pending(
            identity,
            Instant::now(),
            HeldVerdict::test(2, Instant::now(), Arc::clone(&fixture.sink)),
            Arc::clone(&fixture.pending.flow_slots)
                .try_acquire_owned()
                .unwrap(),
        )),
    );
    fixture.stats.increment_udp_nfqueue_active_flows();
    (fixture, lease, identity)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn blocking_commit_leaves_the_worker_free_for_other_tasks() {
    let mut mock = MockEbpfBackend::new();
    mock.commit_delay = Some(Duration::from_millis(300));
    let fixture = pending_fixture_with(31, mock);
    let ticks = Arc::new(AtomicU32::new(0));
    let ticker = tokio::spawn({
        let ticks = Arc::clone(&ticks);
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                ticks.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    let commit = tokio::spawn(async move {
        fixture
            .pending
            .activate_proxy(fixture.identity, &fixture.lease, 4, 0x3400)
            .await
            .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), commit)
        .await
        .expect("commit must finish")
        .unwrap();
    ticker.abort();

    assert!(
        ticks.load(Ordering::Relaxed) >= 10,
        "blocking commit starved the only worker"
    );
}

#[tokio::test]
async fn expired_commits_are_rejected_at_dequeue_and_after_backend_lock() {
    for (remaining, after_lock_delay) in [
        (Duration::ZERO, None),
        (Duration::from_millis(200), Some(Duration::from_millis(400))),
    ] {
        let mock = MockEbpfBackend::new();
        let batches = Arc::clone(&mock.commit_batch_sizes);
        let fixture = pending_fixture_with(32, mock);
        deadline(&fixture, remaining);
        *fixture.pending.commits.after_lock_delay.lock() = after_lock_delay;
        let operation = fixture
            .pending
            .activate_proxy(fixture.identity, &fixture.lease, 4, 0);
        tokio::pin!(operation);
        assert!(futures::poll!(&mut operation).is_pending());
        assert!(
            !fixture.pending.commits.is_idle(),
            "request must be admitted before dequeue"
        );
        assert!(matches!(
            operation.await,
            Err(PendingUdpDecisionError::StaleIdentity)
        ));
        assert!(
            batches.lock().is_empty(),
            "expired commit reached the backend"
        );
        assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
        fixture.pending.shutdown_commit_pump().await.unwrap();
    }
}

#[tokio::test]
async fn commit_rechecks_deadline_after_the_grace_period() {
    let mut mock = MockEbpfBackend::new();
    mock.commit_delay = Some(Duration::from_millis(400));
    let batches = Arc::clone(&mock.commit_batch_sizes);
    let trace = Arc::clone(&mock.commit_trace);
    let fixture = pending_fixture_with(34, mock);
    deadline(&fixture, Duration::from_millis(200));
    assert!(matches!(
        fixture
            .pending
            .activate_proxy(fixture.identity, &fixture.lease, 4, 0)
            .await,
        Err(PendingUdpDecisionError::StaleIdentity)
    ));
    assert_eq!(*batches.lock(), vec![1]);
    assert!(
        trace.lock().is_empty(),
        "expired post-grace request mutated maps"
    );
    assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
    fixture.pending.shutdown_commit_pump().await.unwrap();
}

#[tokio::test]
async fn each_batch_item_rechecks_its_own_deadline_before_applying() {
    let mut mock = MockEbpfBackend::new();
    mock.commit_item_delay = Some((1, Duration::from_millis(400)));
    let batches = Arc::clone(&mock.commit_batch_sizes);
    let (fixture, second, second_id) = pair(mock);
    let second_cell = fixture.pending.matching_cell(second_id).unwrap();
    {
        let mut state = second_cell.state.lock();
        let CellState::Pending { started_at, .. } = &mut *state else {
            panic!("pending")
        };
        *started_at = Instant::now() - HARD_HOLD_TIMEOUT + Duration::from_millis(200);
    }
    let first = fixture
        .pending
        .activate_proxy(fixture.identity, &fixture.lease, 4, 0);
    let second = fixture.pending.activate_proxy(second_id, &second, 4, 0);
    let (first, second) = tokio::join!(biased; first, second);
    assert!(first.is_ok());
    assert!(matches!(
        second,
        Err(PendingUdpDecisionError::StaleIdentity)
    ));
    assert_eq!(*batches.lock(), vec![2]);
    assert_eq!(
        fixture
            .backend
            .read()
            .await
            .conn_state_lookup(&second_id.tuples())
            .unwrap()
            .unwrap()
            .state,
        UdpDecisionState::Pending as u8
    );
    fixture.pending.shutdown_commit_pump().await.unwrap();
}

#[tokio::test]
async fn batched_direct_decisions_keep_arm_verdict_and_activation_order() {
    let mock = MockEbpfBackend::new();
    let batches = Arc::clone(&mock.commit_batch_sizes);
    let trace = Arc::clone(&mock.commit_trace);
    let (fixture, second, second_id) = pair(mock);
    let first_cell = fixture.pending.matching_cell(fixture.identity).unwrap();
    {
        let mut state = first_cell.state.lock();
        let CellState::Pending { verdicts, .. } = &mut *state else {
            panic!("pending")
        };
        verdicts.push_back(HeldVerdict::test(
            3,
            Instant::now(),
            Arc::clone(&fixture.sink),
        ));
    }
    let first = fixture
        .pending
        .activate_direct(fixture.identity, fixture.lease, 0x1200);
    let second = fixture.pending.activate_direct(second_id, second, 0x1200);
    let (first, second) = tokio::join!(biased; first, second);
    first.unwrap();
    second.unwrap();
    assert_eq!(*batches.lock(), vec![2]);
    assert_eq!(
        trace.lock().as_slice(),
        &[
            (
                fixture.identity.owner.token,
                UdpDecisionTransition::ArmDirect(0x1200)
            ),
            (
                second_id.owner.token,
                UdpDecisionTransition::ArmDirect(0x1200)
            ),
            (
                fixture.identity.owner.token,
                UdpDecisionTransition::ActivateDirect(0x1200)
            ),
            (
                second_id.owner.token,
                UdpDecisionTransition::ActivateDirect(0x1200)
            ),
        ]
    );
    assert_eq!(
        fixture.sink.lock().as_slice(),
        &[1, 3, 2].map(|id| TestVerdict::Accept {
            id,
            mark: CLASSIFIED_MARK | 0x1200,
        })
    );
    fixture.pending.shutdown_commit_pump().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn cancelled_direct_waiter_leaves_its_lease_and_work_with_the_joined_pump() {
    let mut mock = MockEbpfBackend::new();
    mock.commit_delay = Some(Duration::from_millis(100));
    let mut fixture = pending_fixture_with(35, mock);
    let pending = Arc::clone(&fixture.pending);
    let started = Instant::now();
    let mut operation = Box::pin(pending.activate_direct(fixture.identity, fixture.lease, 0x1200));
    assert!(futures::poll!(&mut operation).is_pending());
    // Cancellation must drop the waiter, not the admitted request's lease.
    drop(operation);
    fixture.pending.shutdown_commit_pump().await.unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "shutdown detached a blocking commit"
    );
    assert!(fixture.pending.commits.is_idle());
    let cell = fixture.pending.matching_cell(fixture.identity).unwrap();
    assert!(matches!(
        &*cell.state.lock(),
        CellState::ActiveDirect { .. }
    ));
    assert_eq!(
        fixture
            .backend
            .read()
            .await
            .conn_state_lookup(&fixture.identity.tuples())
            .unwrap()
            .unwrap()
            .state,
        UdpDecisionState::None as u8
    );
    assert_eq!(
        *fixture.sink.lock(),
        vec![TestVerdict::Accept {
            id: 1,
            mark: CLASSIFIED_MARK | 0x1200
        }]
    );
    assert!(fixture.fatal.try_recv().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn fence_release_failure_never_acknowledges_an_applied_batch_as_success() {
    let mut mock = MockEbpfBackend::new();
    mock.commit_release_delay = Some(Duration::from_millis(100));
    mock.commit_release_fault = true;
    let (mut fixture, second, second_id) = pair(mock);
    let started = Instant::now();
    let first = fixture
        .pending
        .activate_proxy(fixture.identity, &fixture.lease, 4, 0);
    let second = fixture.pending.activate_proxy(second_id, &second, 4, 0);
    let (first, second) = tokio::join!(biased; first, second);
    assert!(matches!(first, Err(PendingUdpDecisionError::Fatal(_))));
    assert!(matches!(second, Err(PendingUdpDecisionError::Fatal(_))));
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "applied item replied before fence release"
    );
    assert!(fixture.fatal.try_recv().is_ok());
    assert_eq!(
        *fixture.sink.lock(),
        vec![TestVerdict::Drop { id: 1 }, TestVerdict::Drop { id: 2 }]
    );
    let backend = fixture.backend.read().await;
    assert!(
        backend
            .udp_flow_owner(
                fixture.identity.owner.token,
                backend
                    .conn_state_lookup(&fixture.identity.tuples())
                    .unwrap()
            )
            .is_err(),
        "model admitted through unresolved fence ownership"
    );
    drop(backend);
    fixture.pending.shutdown_commit_pump().await.unwrap();
}

#[tokio::test]
async fn cancelling_an_owned_armed_flow_waits_for_activation_instead_of_killing_it() {
    let fixture = pending_fixture(43);
    let pending = Arc::clone(&fixture.pending);
    let reader = fixture.backend.read().await;
    let identity = fixture.identity;
    let activation =
        tokio::spawn(async move { pending.activate_direct(identity, fixture.lease, 0).await });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let (entered, blocked) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let backend = Arc::clone(&fixture.backend);
    let blocker = tokio::spawn(async move {
        let _writer = backend.write().await;
        entered.send(()).unwrap();
        released.await.unwrap();
    });
    tokio::task::yield_now().await;
    drop(reader);
    blocked.await.unwrap();
    assert!(matches!(
        &*fixture
            .pending
            .matching_cell(identity)
            .unwrap()
            .state
            .lock(),
        CellState::Pending { armed: true, .. }
    ));
    let pending = Arc::clone(&fixture.pending);
    let cancel = tokio::spawn(async move { pending.cancel(identity).await });
    tokio::task::yield_now().await;
    assert!(!cancel.is_finished(), "cancellation killed pump-owned work");
    release.send(()).unwrap();
    blocker.await.unwrap();
    activation.await.unwrap().unwrap();
    cancel.await.unwrap().unwrap();
    fixture.pending.shutdown_commit_pump().await.unwrap();
}

#[tokio::test]
async fn an_expired_armed_cancellation_is_still_fatal() {
    let mut fixture = pending_fixture(44);
    let cell = fixture.pending.matching_cell(fixture.identity).unwrap();
    {
        let mut state = cell.state.lock();
        let CellState::Pending {
            started_at, armed, ..
        } = &mut *state
        else {
            panic!("pending")
        };
        *armed = true;
        *started_at = Instant::now() - HARD_HOLD_TIMEOUT;
    }
    assert!(matches!(
        fixture.pending.cancel(fixture.identity).await,
        Err(PendingUdpDecisionError::ArmedInProgress)
    ));
    assert_eq!(
        fixture.fatal.try_recv().unwrap().operation,
        "armed flow cancellation"
    );
    assert!(matches!(&*cell.state.lock(), CellState::Dead { .. }));
    assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
}

#[tokio::test]
async fn cleanup_of_a_now_armed_request_does_not_stall_the_hold_watchdog() {
    let mut fixture = pending_fixture(45);
    fixture
        .pending
        .schedule_cleanup(CleanupRequest::Flow(fixture.identity));
    let cell = fixture.pending.matching_cell(fixture.identity).unwrap();
    {
        let mut state = cell.state.lock();
        let CellState::Pending { armed, .. } = &mut *state else {
            panic!("pending")
        };
        *armed = true;
    }
    tokio::time::timeout(Duration::from_millis(20), fixture.pending.watchdog_tick())
        .await
        .expect("armed cleanup blocked the independent watchdog");
    assert!(
        fixture
            .pending
            .scheduled_cleanups
            .lock()
            .contains(&CleanupRequest::Flow(fixture.identity))
    );
    assert!(fixture.fatal.try_recv().is_err());
    assert!(fixture.sink.lock().is_empty());
}

#[tokio::test]
async fn terminal_verdicts_are_settled_before_another_batched_flow_waits_to_activate() {
    let (fixture, second, second_id) = pair(MockEbpfBackend::new());
    let reader = fixture.backend.read().await;
    let operation = async {
        tokio::join!(biased;
            fixture.pending.activate_direct(fixture.identity, fixture.lease, 0),
            fixture.pending.activate_proxy(second_id, &second, 4, 0),
        )
    };
    tokio::pin!(operation);
    assert!(futures::poll!(&mut operation).is_pending());
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let backend = Arc::clone(&fixture.backend);
    let (entered, blocked) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let blocker = tokio::spawn(async move {
        let _writer = backend.write().await;
        entered.send(()).unwrap();
        released.await.unwrap();
    });
    tokio::task::yield_now().await;
    drop(reader);
    blocked.await.unwrap();
    assert_eq!(
        fixture.sink.lock().first(),
        Some(&TestVerdict::Drop { id: 2 })
    );
    release.send(()).unwrap();
    blocker.await.unwrap();
    let (direct, proxy) = operation.await;
    direct.unwrap();
    proxy.unwrap();
    fixture.pending.shutdown_commit_pump().await.unwrap();
}
