use super::*;

use honk_ebpf_common::{ConnState, NFQUEUE_PENDING_MARK, RoutingMeta};

fn identity(token: u32, generation: u64) -> PendingUdpIdentity {
    PendingUdpIdentity::new(
        FlowKey::new(
            "192.0.2.10:40000".parse().unwrap(),
            "198.51.100.20:443".parse().unwrap(),
        ),
        token,
        generation,
    )
}

fn test_flow_slot() -> OwnedSemaphorePermit {
    Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap()
}

fn retained(token: u32, state: UdpDecisionState, raw: u64) -> ConnState {
    ConnState {
        state: state as u8,
        decision_token: token,
        meta: RoutingMeta { raw },
        ..ConnState::default()
    }
}

#[test]
fn retained_terminal_state_requires_exact_active_direct_encoding() {
    let direct_rule_mark = 0x0000_1200;
    let raw = OutboundIndex::Direct as u64
        | ((direct_rule_mark as u64) << 8)
        | ROUTING_META_FLAG_PUBLISHED
        | ROUTING_META_FLAG_OFFLOAD;
    assert_eq!(
        retained_state(&retained(9, UdpDecisionState::None, raw)),
        RetainedState::ActiveDirect(direct_rule_mark | CLASSIFIED_MARK)
    );
    assert_eq!(
        retained_state(&retained(
            9,
            UdpDecisionState::None,
            raw & !ROUTING_META_FLAG_OFFLOAD,
        )),
        RetainedState::Reject
    );
    assert_eq!(
        retained_state(&retained(
            9,
            UdpDecisionState::None,
            raw | ((NFQUEUE_PENDING_MARK as u64) << 8),
        )),
        RetainedState::Reject
    );
}

#[test]
fn retained_staged_phases_are_not_guessed_from_routing_metadata() {
    assert_eq!(
        retained_state(&retained(7, UdpDecisionState::Pending, u64::MAX)),
        RetainedState::Pending
    );
    assert_eq!(
        retained_state(&retained(7, UdpDecisionState::DirectArmed, 0)),
        RetainedState::DirectArmed
    );
    assert_eq!(
        retained_state(&retained(7, UdpDecisionState::Proxy, 0)),
        RetainedState::Proxy
    );
    assert_eq!(
        retained_state(&retained(7, UdpDecisionState::Block, 0)),
        RetainedState::Block
    );
    assert_eq!(
        retained_state(&retained(7, UdpDecisionState::Preparing, 0)),
        RetainedState::Reject
    );
}

#[test]
fn token_and_generation_both_identify_a_live_cell() {
    let exact = identity(11, 3);
    let cell = FlowCell::terminal(
        exact,
        CellState::Dead {
            expires_at: Instant::now() + TERMINAL_GRACE,
        },
        test_flow_slot(),
    );
    assert_eq!(cell.identity, exact);
    assert_ne!(cell.identity, identity(12, 3));
    assert_ne!(cell.identity, identity(11, 4));
}

#[test]
fn newer_token_supersedes_only_terminal_cell() {
    let now = Instant::now();
    let terminal = FlowCell::terminal(
        identity(11, 3),
        CellState::Dead {
            expires_at: now + TERMINAL_GRACE,
        },
        test_flow_slot(),
    );
    assert!(!terminal_cell_is_stale(&terminal, 11, now));
    assert!(terminal_cell_is_stale(&terminal, 12, now));

    let expired = FlowCell::terminal(
        identity(11, 3),
        CellState::Dead { expires_at: now },
        test_flow_slot(),
    );
    assert!(terminal_cell_is_stale(&expired, 11, now));

    let pending = FlowCell {
        _flow_slot: test_flow_slot(),
        identity: identity(11, 3),
        state: Mutex::new(CellState::Pending {
            started_at: now,
            armed: false,
            cancelling: false,
            verdicts: VecDeque::new(),
        }),
        changed: Notify::new(),
    };
    assert!(!terminal_cell_is_stale(&pending, 12, now));
}

#[test]
fn held_guards_preserve_fifo_without_retaining_payloads() {
    let sink = Arc::new(Mutex::new(Vec::new()));
    let received_at = Instant::now();
    let mut verdicts = VecDeque::new();
    verdicts.push_back(HeldVerdict::test(1, received_at, Arc::clone(&sink)));
    verdicts.push_back(HeldVerdict::test(2, received_at, Arc::clone(&sink)));
    verdicts.push_back(HeldVerdict::test(3, received_at, Arc::clone(&sink)));
    while let Some(mut verdict) = verdicts.pop_front() {
        verdict.guard.accept(CLASSIFIED_MARK).unwrap();
    }
    assert_eq!(
        *sink.lock(),
        vec![
            TestVerdict::Accept {
                id: 1,
                mark: CLASSIFIED_MARK,
            },
            TestVerdict::Accept {
                id: 2,
                mark: CLASSIFIED_MARK,
            },
            TestVerdict::Accept {
                id: 3,
                mark: CLASSIFIED_MARK,
            },
        ]
    );
}

#[tokio::test]
async fn cancel_token_mismatch_drops_local_guards_and_marks_cell_dead() {
    let identity = identity(11, 3);
    let mut backend = crate::ebpf::mock::MockEbpfBackend::new();
    backend
        .udp_conn_state_store(
            &identity.tuples(),
            &ConnState {
                state: UdpDecisionState::Pending as u8,
                decision_token: 12,
                ..ConnState::default()
            },
        )
        .unwrap();
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(backend)));
    let endpoints = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let (pending, _fatal) = PendingUdpVerdicts::new(backend, endpoints, stats);
    let sink = Arc::new(Mutex::new(Vec::new()));
    let cell = Arc::new(FlowCell::pending(
        identity,
        Instant::now(),
        HeldVerdict::test(1, Instant::now(), Arc::clone(&sink)),
        test_flow_slot(),
    ));
    pending.cells.insert(identity.key, Arc::clone(&cell));

    assert!(matches!(
        pending.cancel(identity).await,
        Err(PendingUdpDecisionError::StaleIdentity)
    ));
    assert!(matches!(&*cell.state.lock(), CellState::Dead { .. }));
    assert_eq!(*sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
}

struct DecisionFixture {
    pending: PendingUdpVerdicts,
    backend: Arc<RwLock<Box<dyn EbpfBackend>>>,
    lease: UdpInitLease,
    identity: PendingUdpIdentity,
    sink: Arc<Mutex<Vec<TestVerdict>>>,
    stats: Arc<StatsManager>,
    fatal: mpsc::Receiver<PendingUdpFatal>,
}

fn pending_fixture(token: u32) -> DecisionFixture {
    let key = identity(token, 0).key;
    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.seed_staged_udp_flow(
        &key.tuples(),
        ConnState {
            state: UdpDecisionState::Pending as u8,
            decision_token: token,
            meta: RoutingMeta {
                raw: ROUTING_META_FLAG_PUBLISHED,
            },
            ..ConnState::default()
        },
    );
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
    let endpoints = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let (pending, fatal) = PendingUdpVerdicts::new(
        Arc::clone(&backend),
        Arc::clone(&endpoints),
        Arc::clone(&stats),
    );
    pending.open_admission();
    let lease = match endpoints.reserve_owned_or_enqueue(
        key.client,
        key.destination,
        bytes::Bytes::from_static(b"first"),
        token,
        None,
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap(),
        &stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("pending fixture must initialize"),
    };
    let identity = PendingUdpVerdicts::identity_for_lease(&lease);
    let sink = Arc::new(Mutex::new(Vec::new()));
    pending.cells.insert(
        key,
        Arc::new(FlowCell::pending(
            identity,
            Instant::now(),
            HeldVerdict::test(1, Instant::now(), Arc::clone(&sink)),
            Arc::clone(&pending.flow_slots).try_acquire_owned().unwrap(),
        )),
    );
    stats.increment_udp_nfqueue_active_flows();
    DecisionFixture {
        pending,
        backend,
        lease,
        identity,
        sink,
        stats,
        fatal,
    }
}

#[test]
fn armed_direct_follower_queues_without_slow_or_endpoint_admission() {
    let fixture = pending_fixture(20);
    let cell = Arc::clone(
        fixture
            .pending
            .cells
            .get(&fixture.identity.key)
            .unwrap()
            .value(),
    );
    {
        let mut state = cell.state.lock();
        let CellState::Pending { armed, .. } = &mut *state else {
            panic!("fixture cell must be pending");
        };
        *armed = true;
    }

    let result = fixture.pending.ingest_existing(
        Arc::clone(&cell),
        fixture.identity.decision_token,
        bytes::Bytes::from_static(b"discarded armed payload"),
        HeldVerdict::test(2, Instant::now(), Arc::clone(&fixture.sink)),
        None,
    );

    assert!(matches!(result, NfqueueIngest::Queued));
    assert!(fixture.sink.lock().is_empty());
    let state = cell.state.lock();
    let CellState::Pending { verdicts, .. } = &*state else {
        panic!("armed cell must remain pending until activation");
    };
    assert_eq!(verdicts.len(), 2);
}

#[test]
fn armed_direct_verdicts_are_bounded_per_flow() {
    let fixture = pending_fixture(39);
    let cell = Arc::clone(
        fixture
            .pending
            .cells
            .get(&fixture.identity.key)
            .unwrap()
            .value(),
    );
    {
        let mut state = cell.state.lock();
        let CellState::Pending {
            armed, verdicts, ..
        } = &mut *state
        else {
            panic!("fixture cell must be pending");
        };
        *armed = true;
        for id in 2..=MAX_HELD_VERDICTS_PER_FLOW as u64 {
            verdicts.push_back(HeldVerdict::test(
                id,
                Instant::now(),
                Arc::clone(&fixture.sink),
            ));
        }
    }

    let result = fixture.pending.ingest_existing(
        Arc::clone(&cell),
        fixture.identity.decision_token,
        bytes::Bytes::from_static(b"bounded armed payload"),
        HeldVerdict::test(
            MAX_HELD_VERDICTS_PER_FLOW as u64 + 1,
            Instant::now(),
            Arc::clone(&fixture.sink),
        ),
        None,
    );

    assert!(matches!(result, NfqueueIngest::Dropped));
    assert_eq!(
        *fixture.sink.lock(),
        vec![TestVerdict::Drop {
            id: MAX_HELD_VERDICTS_PER_FLOW as u64 + 1,
        }]
    );
    let state = cell.state.lock();
    let CellState::Pending { verdicts, .. } = &*state else {
        panic!("armed cell must remain pending");
    };
    assert_eq!(verdicts.len(), MAX_HELD_VERDICTS_PER_FLOW);
    assert_eq!(fixture.stats.udp_snapshot().nfqueue.correlator_full, 1);
}

#[tokio::test]
async fn correlator_flow_slots_fail_closed_at_the_hard_cap() {
    let token = 40;
    let key = identity(token, 0).key;
    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.seed_staged_udp_flow(
        &key.tuples(),
        ConnState {
            state: UdpDecisionState::Pending as u8,
            decision_token: token,
            ..ConnState::default()
        },
    );
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
    let stats = Arc::new(StatsManager::new());
    let (pending, _fatal) = PendingUdpVerdicts::new(
        backend,
        Arc::new(UdpEndpointPool::new()),
        Arc::clone(&stats),
    );
    pending.open_admission();
    let _all_slots = Arc::clone(&pending.flow_slots)
        .try_acquire_many_owned(MAX_CORRELATOR_FLOWS as u32)
        .unwrap();
    let sink = Arc::new(Mutex::new(Vec::new()));
    let received_at = Instant::now();
    let packet = QueuedPacket {
        tuple: honk_nfqueue::UdpTuple {
            client: key.client,
            destination: key.destination,
        },
        payload: bytes::Bytes::from_static(b"over capacity"),
        mark: honk_ebpf_common::pack_nfqueue_mark(token).unwrap(),
        received_at,
    };

    let result = pending
        .ingest_held_wait(
            packet,
            HeldVerdict::test(1, received_at, Arc::clone(&sink)),
            Some(test_flow_slot()),
        )
        .await;

    assert!(matches!(result, NfqueueIngest::Dropped));
    assert_eq!(*sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
    assert_eq!(stats.udp_snapshot().nfqueue.correlator_full, 1);
    assert!(
        pending
            .scheduled_cleanups
            .lock()
            .contains(&CleanupRequest::Token {
                key,
                decision_token: token,
            })
    );
}

#[tokio::test]
async fn armed_direct_backend_wait_is_bounded_by_hold_deadline() {
    let DecisionFixture {
        pending,
        backend,
        mut lease,
        identity,
        sink,
        mut fatal,
        ..
    } = pending_fixture(26);
    let pending = Arc::new(pending);
    let initial_reader = backend.read().await;
    let activation_pending = Arc::clone(&pending);
    let activation = tokio::spawn(async move {
        activation_pending
            .activate_direct(identity, &mut lease, 0x1200)
            .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let blocked_backend = Arc::clone(&backend);
    let (blocked_tx, blocked_rx) = tokio::sync::oneshot::channel();
    let blocker = tokio::spawn(async move {
        let _backend = blocked_backend.write().await;
        let _ = blocked_tx.send(());
        tokio::time::sleep(HARD_HOLD_TIMEOUT + Duration::from_secs(1)).await;
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    drop(initial_reader);
    tokio::time::timeout(Duration::from_secs(1), blocked_rx)
        .await
        .expect("second backend writer must acquire after ArmDirect")
        .expect("second backend writer signal");
    assert_eq!(
        *sink.lock(),
        vec![TestVerdict::Accept {
            id: 1,
            mark: CLASSIFIED_MARK | 0x1200,
        }],
        "the competing writer must acquire between ArmDirect and ActivateDirect"
    );
    let cell = Arc::clone(pending.cells.get(&identity.key).unwrap().value());
    assert!(matches!(
        pending.ingest_existing(
            cell,
            identity.decision_token,
            bytes::Bytes::from_static(b"armed follower"),
            HeldVerdict::test(2, Instant::now(), Arc::clone(&sink)),
            None,
        ),
        NfqueueIngest::Queued
    ));

    assert!(matches!(
        activation.await.expect("activation task"),
        Err(PendingUdpDecisionError::ArmedInProgress)
    ));
    assert_eq!(
        *sink.lock(),
        vec![
            TestVerdict::Accept {
                id: 1,
                mark: CLASSIFIED_MARK | 0x1200,
            },
            TestVerdict::Drop { id: 2 },
        ]
    );
    let fatal = tokio::time::timeout(Duration::from_secs(1), fatal.recv())
        .await
        .expect("armed timeout must report fatal")
        .expect("armed timeout fatal channel");
    assert_eq!(fatal.operation, "armed flow cancellation");
    blocker.abort();
}

#[tokio::test]
async fn wait_empty_includes_cleanup_blocked_on_backend() {
    let identity = identity(27, 0);
    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.seed_staged_udp_flow(
        &identity.tuples(),
        retained(27, UdpDecisionState::Pending, 0),
    );
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
    let (pending, _fatal) = PendingUdpVerdicts::new(
        Arc::clone(&backend),
        Arc::new(UdpEndpointPool::new()),
        Arc::new(StatsManager::new()),
    );
    let pending = Arc::new(pending);
    pending.schedule_cleanup(CleanupRequest::Token {
        key: identity.key,
        decision_token: identity.decision_token,
    });

    let backend_guard = backend.write().await;
    tokio::time::timeout(
        Duration::from_millis(20),
        pending.drain_scheduled_cleanups(),
    )
    .await
    .expect("contended cleanup must defer without blocking");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), pending.wait_empty())
            .await
            .is_err(),
        "a deferred token abort must keep the generation drain non-empty"
    );
    drop(backend_guard);
    pending.drain_scheduled_cleanups().await;
    tokio::time::timeout(Duration::from_secs(1), pending.wait_empty())
        .await
        .expect("completed token abort must release the generation drain");
    assert!(
        backend
            .read()
            .await
            .udp_conn_state_lookup(&identity.tuples())
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn deferred_token_cleanup_does_not_stall_hold_watchdog() {
    let fixture = pending_fixture(29);
    {
        let cell = fixture.pending.cells.get(&fixture.identity.key).unwrap();
        let mut state = cell.state.lock();
        let CellState::Pending { started_at, .. } = &mut *state else {
            panic!("fixture cell must be pending");
        };
        *started_at = Instant::now() - HARD_HOLD_TIMEOUT;
    }
    fixture.pending.schedule_cleanup(CleanupRequest::Token {
        key: fixture.identity.key,
        decision_token: 30,
    });
    let _writer = fixture.backend.write().await;

    tokio::time::timeout(Duration::from_millis(20), fixture.pending.watchdog_tick())
        .await
        .expect("contended token cleanup must not stall the hold watchdog");

    assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
}

#[tokio::test]
async fn direct_arms_accepts_fifo_then_activates_without_copying_payload() {
    let mut fixture = pending_fixture(21);
    {
        let cell = fixture.pending.cells.get(&fixture.identity.key).unwrap();
        let mut state = cell.state.lock();
        let CellState::Pending { verdicts, .. } = &mut *state else {
            panic!("fixture cell must be pending");
        };
        verdicts.push_back(HeldVerdict::test(
            2,
            Instant::now(),
            Arc::clone(&fixture.sink),
        ));
    }

    fixture
        .pending
        .activate_direct(fixture.identity, &mut fixture.lease, 0x1200)
        .await
        .unwrap();

    assert_eq!(
        *fixture.sink.lock(),
        vec![
            TestVerdict::Accept {
                id: 1,
                mark: CLASSIFIED_MARK | 0x1200,
            },
            TestVerdict::Accept {
                id: 2,
                mark: CLASSIFIED_MARK | 0x1200,
            },
        ]
    );
    let state = fixture
        .backend
        .read()
        .await
        .udp_conn_state_lookup(&fixture.identity.tuples())
        .unwrap()
        .unwrap();
    let raw = unsafe { state.meta.raw };
    assert_eq!(state.state, UdpDecisionState::None as u8);
    assert_eq!(state.decision_token, fixture.identity.decision_token);
    assert_eq!(raw & 0xff, OutboundIndex::Direct as u64);
    assert_eq!(((raw >> 8) & u32::MAX as u64) as u32, 0x1200);
    assert_ne!(raw & ROUTING_META_FLAG_OFFLOAD, 0);
    assert_eq!(fixture.stats.udp_snapshot().nfqueue.direct_accepted, 2);
    assert!(matches!(
        fixture.fatal.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn proxy_commits_before_dropping_original_and_retains_copied_payload() {
    let mut fixture = pending_fixture(22);
    fixture
        .pending
        .activate_proxy(fixture.identity, &fixture.lease, 4, 0x3400)
        .await
        .unwrap();

    assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
    assert_eq!(
        fixture.lease.first_payload(),
        bytes::Bytes::from_static(b"first")
    );
    let state = fixture
        .backend
        .read()
        .await
        .udp_conn_state_lookup(&fixture.identity.tuples())
        .unwrap()
        .unwrap();
    let raw = unsafe { state.meta.raw };
    assert_eq!(state.state, UdpDecisionState::Proxy as u8);
    assert_eq!(state.decision_token, fixture.identity.decision_token);
    assert_eq!(raw & 0xff, 4);
    assert_eq!(((raw >> 8) & u32::MAX as u64) as u32, 0x3400);
    assert_eq!(raw & ROUTING_META_FLAG_OFFLOAD, 0);
    let snapshot = fixture.stats.udp_snapshot();
    assert_eq!(snapshot.nfqueue.proxy_copied, 1);
    assert_eq!(snapshot.nfqueue.proxy_dropped, 1);
    assert!(matches!(
        fixture.fatal.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn block_commits_then_drops_original_and_retires_initializer() {
    let mut fixture = pending_fixture(23);
    fixture
        .pending
        .block(fixture.identity, &mut fixture.lease)
        .await
        .unwrap();

    assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
    let state = fixture
        .backend
        .read()
        .await
        .udp_conn_state_lookup(&fixture.identity.tuples())
        .unwrap()
        .unwrap();
    let raw = unsafe { state.meta.raw };
    assert_eq!(state.state, UdpDecisionState::Block as u8);
    assert_eq!(state.decision_token, fixture.identity.decision_token);
    assert_eq!(raw & 0xff, OutboundIndex::Block as u64);
    assert_eq!(fixture.stats.udp_snapshot().nfqueue.block, 1);
    assert!(matches!(
        fixture.fatal.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn cancel_drops_original_and_removes_exact_pending_state() {
    let mut fixture = pending_fixture(24);
    let cancellation = fixture.lease.wait_cancellation();
    fixture.pending.cancel(fixture.identity).await.unwrap();
    tokio::time::timeout(Duration::from_millis(100), cancellation)
        .await
        .expect("pending cancellation must wake the exact initializer");

    assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
    assert!(
        fixture
            .backend
            .read()
            .await
            .udp_conn_state_lookup(&fixture.identity.tuples())
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.stats.udp_snapshot().nfqueue.cancel, 1);
    assert!(matches!(
        fixture.fatal.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn close_admission_waits_for_inflight_ingest_publication() {
    let gate = Arc::new(AdmissionGate::new());
    gate.open();
    let in_flight = gate.try_enter().unwrap();
    let closing_gate = Arc::clone(&gate);
    let close = tokio::spawn(async move {
        closing_gate.close_and_wait().await;
    });

    while gate.state.lock().open {
        tokio::task::yield_now().await;
    }
    assert!(!close.is_finished());
    drop(in_flight);
    tokio::time::timeout(Duration::from_secs(1), close)
        .await
        .unwrap()
        .unwrap();
    assert!(gate.try_enter().is_none());
}

#[tokio::test]
async fn backend_write_lock_cannot_extend_packet_hold_deadline() {
    let token = 25;
    let key = identity(token, 0).key;
    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.seed_staged_udp_flow(
        &key.tuples(),
        ConnState {
            state: UdpDecisionState::Pending as u8,
            decision_token: token,
            ..ConnState::default()
        },
    );
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
    let stats = Arc::new(StatsManager::new());
    let (pending, _fatal) = PendingUdpVerdicts::new(
        Arc::clone(&backend),
        Arc::new(UdpEndpointPool::new()),
        Arc::clone(&stats),
    );
    pending.open_admission();
    let pending = Arc::new(pending);
    let sink = Arc::new(Mutex::new(Vec::new()));
    let received_at = Instant::now();
    let packet = QueuedPacket {
        tuple: honk_nfqueue::UdpTuple {
            client: key.client,
            destination: key.destination,
        },
        payload: bytes::Bytes::from_static(b"held"),
        mark: honk_ebpf_common::pack_nfqueue_mark(token).unwrap(),
        received_at,
    };
    let writer = backend.write().await;

    let task = tokio::spawn({
        let pending = Arc::clone(&pending);
        let sink = Arc::clone(&sink);
        async move {
            pending
                .ingest_held_wait(packet, HeldVerdict::test(1, received_at, sink), None)
                .await
        }
    });

    let result = tokio::time::timeout(HARD_HOLD_TIMEOUT + Duration::from_secs(1), task)
        .await
        .expect("ingest must resolve at its absolute hold deadline")
        .unwrap();
    assert!(matches!(result, NfqueueIngest::Dropped));
    assert_eq!(*sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
    let snapshot = stats.udp_snapshot();
    assert_eq!(snapshot.nfqueue.received, 1);
    assert_eq!(snapshot.nfqueue.cancel, 1);
    assert_eq!(snapshot.nfqueue.receipt_to_verdict_latency.count, 1);
    drop(writer);
}

#[tokio::test]
async fn active_direct_follower_does_not_wait_for_backend() {
    let fixture = pending_fixture(28);
    {
        let cell = fixture.pending.cells.get(&fixture.identity.key).unwrap();
        *cell.state.lock() = CellState::ActiveDirect {
            expires_at: Instant::now() + TERMINAL_GRACE,
            final_mark: CLASSIFIED_MARK | 0x1200,
        };
    }
    fixture.sink.lock().clear();
    let received_at = Instant::now() - HARD_HOLD_TIMEOUT + Duration::from_millis(50);
    let packet = QueuedPacket {
        tuple: honk_nfqueue::UdpTuple {
            client: fixture.identity.client(),
            destination: fixture.identity.destination(),
        },
        payload: bytes::Bytes::from_static(b"direct follower"),
        mark: honk_ebpf_common::pack_nfqueue_mark(fixture.identity.decision_token).unwrap(),
        received_at,
    };
    let _writer = fixture.backend.write().await;

    let result = tokio::time::timeout(
        Duration::from_millis(20),
        fixture.pending.ingest_held_wait(
            packet,
            HeldVerdict::test(2, received_at, Arc::clone(&fixture.sink)),
            None,
        ),
    )
    .await
    .expect("known direct flow must bypass backend lookup");

    assert!(matches!(result, NfqueueIngest::Queued));
    assert_eq!(
        *fixture.sink.lock(),
        vec![TestVerdict::Accept {
            id: 2,
            mark: CLASSIFIED_MARK | 0x1200,
        }]
    );
}

#[tokio::test]
async fn rejected_dns_carrier_never_aborts_an_ordinary_token_incarnation() {
    let route = UdpDnsRoute::new(OutboundIndex::ControlPlaneRouting as u8, 1).unwrap();
    let mark = route.to_nfqueue_mark();
    let token = extract_nfqueue_token(mark).unwrap();
    let client = "192.0.2.10:40000".parse().unwrap();
    let dns = FlowKey::new(client, "198.51.100.20:53".parse().unwrap());
    let ordinary = FlowKey::new(client, "198.51.100.20:443".parse().unwrap());
    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    for key in [dns, ordinary] {
        mock.seed_staged_udp_flow(
            &key.tuples(),
            ConnState {
                state: UdpDecisionState::Pending as u8,
                decision_token: token,
                ..ConnState::default()
            },
        );
    }
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
    let (pending, mut fatal) = PendingUdpVerdicts::new(
        Arc::clone(&backend),
        Arc::new(UdpEndpointPool::new()),
        Arc::new(StatsManager::new()),
    );
    let sink = Arc::new(Mutex::new(Vec::new()));
    for (id, key) in [(1, dns), (2, ordinary)] {
        pending.reject_held_packet(
            UdpTuple {
                client: key.client,
                destination: key.destination,
            },
            mark,
            HeldVerdict::test(id, Instant::now(), Arc::clone(&sink)),
            DropOutcome::Other,
        );
    }
    pending.drain_scheduled_cleanups().await;
    let backend = backend.read().await;
    assert_eq!(
        backend
            .udp_conn_state_lookup(&dns.tuples())
            .unwrap()
            .unwrap()
            .decision_token,
        token,
        "DNS rejection must not reinterpret its route carrier as a cleanup token"
    );
    assert!(
        backend
            .udp_conn_state_lookup(&ordinary.tuples())
            .unwrap()
            .is_none(),
        "known rejected ordinary packets still retire their exact pending token"
    );
    assert_eq!(
        *sink.lock(),
        vec![TestVerdict::Drop { id: 1 }, TestVerdict::Drop { id: 2 }]
    );
    assert!(matches!(
        fatal.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}
#[tokio::test]
async fn transition_write_lock_respects_original_packet_deadline() {
    let fixture = pending_fixture(26);
    {
        let cell = fixture.pending.cells.get(&fixture.identity.key).unwrap();
        let mut state = cell.state.lock();
        let CellState::Pending { started_at, .. } = &mut *state else {
            panic!("fixture cell must be pending");
        };
        *started_at = Instant::now() - HARD_HOLD_TIMEOUT + Duration::from_millis(50);
    }
    let writer = fixture.backend.write().await;
    let started = Instant::now();
    let result = fixture
        .pending
        .activate_proxy(fixture.identity, &fixture.lease, 4, 0x3400)
        .await;
    assert!(matches!(
        result,
        Err(PendingUdpDecisionError::StaleIdentity)
    ));
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
    assert_eq!(fixture.stats.udp_snapshot().nfqueue.cancel, 1);
    drop(writer);
}

#[test]
fn fixed_deadlines_match_the_held_packet_contract() {
    assert_eq!(TERMINAL_GRACE, Duration::from_millis(500));
    assert_eq!(WATCHDOG_INTERVAL, Duration::from_millis(100));
    assert_eq!(HARD_HOLD_TIMEOUT, Duration::from_secs(3));
}
