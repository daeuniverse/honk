use super::*;
/// A Cold URLTest loser owns its physical dial. Aborting the caller must
/// drop its detached reservation, releasing its provisional cap slot.
#[tokio::test]
async fn speculative_checkout_cancellation_releases_blocked_dial_slot() {
    let pool = Arc::new(pool(SessionPoolConfig {
        max_sessions: 1,
        ..Default::default()
    }));
    let entered = Arc::new(tokio::sync::Notify::new());
    let task = tokio::spawn({
        let pool = Arc::clone(&pool);
        let entered = Arc::clone(&entered);
        async move {
            let _reservation = match pool.checkout_speculative().await.unwrap() {
                SpeculativeCheckout::Detached(reservation) => reservation,
                SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
            };
            entered.notify_one();
            futures_util::future::pending::<()>().await;
        }
    });
    entered.notified().await;
    assert_eq!(pool.pool.lock().provisional.len(), 1);

    task.abort();
    let _ = task.await;
    assert!(
        pool.pool.lock().provisional.is_empty(),
        "aborting a caller-owned dial must release its provisional slot"
    );
}

#[tokio::test]
async fn detached_checkout_shutdown_closes_attached_session_and_rejects_commit() {
    let pool = Arc::new(pool(SessionPoolConfig::default()));
    let mut reservation = match pool.checkout_speculative().await.unwrap() {
        SpeculativeCheckout::Detached(reservation) => reservation,
        SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
    };
    let session = TestSession::new();
    reservation.attach(&session).unwrap();

    pool.shutdown();

    assert!(
        session.is_closed(),
        "terminal shutdown must close an attached detached session"
    );
    assert!(
        reservation.commit().is_err(),
        "a detached reservation may not repopulate a terminal pool"
    );
    assert_eq!(pool.metrics().sessions, 0);
}

#[tokio::test(start_paused = true)]
async fn provisional_slot_does_not_block_normal_offer() {
    let pool = Arc::new(pool(SessionPoolConfig {
        max_sessions: 1,
        ..Default::default()
    }));
    let _reservation = match pool.checkout_speculative().await.unwrap() {
        SpeculativeCheckout::Detached(reservation) => reservation,
        SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
    };
    // A held speculative reservation must not park the normal dial path:
    // parked offers have no timeout of their own, so a hung speculative
    // dial would otherwise kill real flows at their outer deadline.
    let session = pool
        .offer(|| async { Ok(TestSession::new()) })
        .await
        .unwrap();
    assert!(!session.is_closed());
}

#[tokio::test]
async fn detached_commit_inserts_once_into_the_captured_pool() {
    let pool = Arc::new(pool(SessionPoolConfig::default()));
    let mut reservation = match pool.checkout_speculative().await.unwrap() {
        SpeculativeCheckout::Detached(reservation) => reservation,
        SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
    };
    let session = TestSession::new();
    reservation.attach(&session).unwrap();
    let committed = reservation.commit().unwrap();

    assert!(Arc::ptr_eq(&session, &committed));
    assert_eq!(pool.metrics().sessions, 1);
    assert!(pool.pool.lock().provisional.is_empty());
    let offered = pool
        .offer(|| async { unreachable!("committed session must be reused") })
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&committed, &offered));
    assert_eq!(
        pool.metrics().sessions,
        1,
        "commit cannot duplicate insertion"
    );
}

#[tokio::test]
async fn detached_commit_at_capacity_admits_drain_only() {
    let pool = Arc::new(pool(SessionPoolConfig {
        max_sessions: 1,
        ..Default::default()
    }));
    let mut reservation = match pool.checkout_speculative().await.unwrap() {
        SpeculativeCheckout::Detached(reservation) => reservation,
        SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
    };
    let winner = TestSession::new();
    reservation.attach(&winner).unwrap();
    // Normal offers don't count provisional slots, so the pool can fill
    // while the speculative dial is detached.
    let active = pool
        .offer(|| async { Ok(TestSession::new()) })
        .await
        .unwrap();

    let committed = reservation.commit().unwrap();

    assert!(Arc::ptr_eq(&committed, &winner));
    assert_eq!(
        committed.state(),
        SessionState::Draining,
        "a commit arriving at a full pool must not exceed max_sessions"
    );
    assert_eq!(active.state(), SessionState::Active);
}

#[tokio::test]
async fn shared_checkout_reserves_its_stream_permit_atomically() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 1,
        janitor_interval: Duration::from_secs(30),
        ..Default::default()
    }));
    let session = ReservedTestSession::new(1);
    pool.insert(&session);
    let permit = match pool.checkout_speculative().await.unwrap() {
        SpeculativeCheckout::Shared {
            session: checked,
            permit,
        } => {
            assert!(Arc::ptr_eq(&session, &checked));
            permit
        }
        SpeculativeCheckout::Detached(_) => panic!("live session must be checked out first"),
    };
    assert_eq!(session.active_streams(), 1);

    let blocked = tokio::spawn({
        let pool = Arc::clone(&pool);
        async move { pool.checkout_speculative().await }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(
        !blocked.is_finished(),
        "the occupied shared stream slot must not be offered twice"
    );
    drop(permit);
    let next = tokio::time::timeout(Duration::from_millis(100), blocked)
        .await
        .expect("second checkout did not observe released stream capacity")
        .unwrap()
        .unwrap();
    assert!(matches!(next, SpeculativeCheckout::Shared { .. }));
}
