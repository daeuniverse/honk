use super::*;

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
    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(backend)));
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
            .tc()
            .unwrap()
            .conn_state_lookup(&fixture.identity.tuples())
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
async fn staged_admission_keeps_captured_incarnation_through_cancel() {
    let token = 47;
    let key = identity(token, 0).key;
    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.seed_staged_udp_flow(
        &key.tuples(),
        ConnState {
            state: UdpDecisionState::Pending as u8,
            decision_token: token,
            incarnation: 61,
            meta: RoutingMeta {
                raw: ROUTING_META_FLAG_PUBLISHED,
            },
            ..Default::default()
        },
    );
    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(mock)));
    let endpoints = Arc::new(UdpEndpointPool::new());
    let (pending, mut fatal) = PendingUdpVerdicts::new(
        Arc::clone(&backend),
        endpoints,
        Arc::new(StatsManager::new()),
    );
    pending.open_admission();
    let sink = Arc::new(Mutex::new(Vec::new()));
    let received_at = Instant::now();
    let packet = QueuedPacket {
        tuple: UdpTuple {
            client: key.client,
            destination: key.destination,
        },
        payload: bytes::Bytes::from_static(b"old"),
        mark: honk_ebpf_common::pack_nfqueue_mark(token).unwrap(),
        priority: None,
        received_at,
    };
    let NfqueueIngest::Initialize { lease, identity } = pending
        .ingest_held_wait(
            packet,
            HeldVerdict::test(1, received_at, Arc::clone(&sink)),
            Some(test_flow_slot()),
        )
        .await
    else {
        panic!("pending flow must initialize")
    };
    assert_eq!(lease.owner().incarnation(), Some(61));
    assert_eq!(identity.owner.incarnation(), Some(61));
    {
        let mut backend = tokio::sync::RwLockWriteGuard::map(backend.write().await, |backend| {
            backend.tc_mut().unwrap()
        });
        let mut state = backend.conn_state_lookup(&key.tuples()).unwrap().unwrap();
        state.incarnation = 62;
        backend.udp_conn_state_store(&key.tuples(), &state).unwrap();
    }
    assert!(matches!(
        pending.cancel(identity).await,
        Err(PendingUdpDecisionError::StaleIdentity)
    ));
    assert_eq!(*sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
    assert_eq!(
        backend
            .read()
            .await
            .tc()
            .unwrap()
            .conn_state_lookup(&key.tuples())
            .unwrap()
            .unwrap()
            .incarnation,
        62
    );
    assert!(fatal.try_recv().is_err());
    drop(lease);
}
