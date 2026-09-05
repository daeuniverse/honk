use super::*;
#[tokio::test(start_paused = true)]
async fn offer_dials_once_and_reuses() {
    let pool = pool(SessionPoolConfig::default());
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = {
        let dials = Arc::clone(&dials);
        move || {
            let dials = Arc::clone(&dials);
            async move {
                dials.fetch_add(1, Ordering::Relaxed);
                Ok(TestSession::new())
            }
        }
    };
    let s1 = pool.offer(dial).await.unwrap();
    let dials2 = Arc::clone(&dials);
    let s2 = pool
        .offer(move || async move {
            dials2.fetch_add(1, Ordering::Relaxed);
            Ok(TestSession::new())
        })
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&s1, &s2));
    assert_eq!(dials.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn warm_session_starts_feedback_before_blocked_open() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_streams_per_session: 1,
        ..Default::default()
    }));
    let session = ReservedTestSession::new(1);
    pool.insert(&session);
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
            .unwrap()
            .0,
    );
    let feedback_started = Arc::new(AtomicBool::new(false));
    let open_entered = Arc::new(tokio::sync::Notify::new());
    let release_open = Arc::new(tokio::sync::Notify::new());
    let task = {
        let pool = Arc::clone(&pool);
        let generation = Arc::clone(&generation);
        let feedback_started = Arc::clone(&feedback_started);
        let open_entered = Arc::clone(&open_entered);
        let release_open = Arc::clone(&release_open);
        let feedback_started_for_open = Arc::clone(&feedback_started);
        tokio::spawn(async move {
            generation
                .scope_dials_with_start(
                    pool.open_with(
                        || async { anyhow::bail!("warm session must not dial") },
                        move |_session, permit| {
                            let feedback_started = Arc::clone(&feedback_started_for_open);
                            let open_entered = Arc::clone(&open_entered);
                            let release_open = Arc::clone(&release_open);
                            async move {
                                assert!(feedback_started.load(Ordering::Acquire));
                                open_entered.notify_one();
                                release_open.notified().await;
                                drop(permit);
                                Ok::<_, OpenError>(())
                            }
                        },
                    ),
                    move || feedback_started.store(true, Ordering::Release),
                )
                .await
        })
    };

    tokio::time::timeout(Duration::from_secs(1), open_entered.notified())
        .await
        .expect("warm logical open did not start");
    assert!(feedback_started.load(Ordering::Acquire));
    release_open.notify_one();
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn spread_sessions_fills_idle_capacity_before_multiplexing() {
    let pool = pool(SessionPoolConfig {
        max_sessions: 2,
        spread_sessions: true,
        ..Default::default()
    });
    let dials = Arc::new(AtomicUsize::new(0));
    let dial = |dials: Arc<AtomicUsize>| async move {
        dials.fetch_add(1, Ordering::Relaxed);
        Ok(TestSession::new())
    };

    let first = pool
        .offer({
            let dials = Arc::clone(&dials);
            move || dial(dials)
        })
        .await
        .unwrap();
    first.streams.store(1, Ordering::Relaxed);
    let second = pool
        .offer({
            let dials = Arc::clone(&dials);
            move || dial(dials)
        })
        .await
        .unwrap();

    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(dials.load(Ordering::Relaxed), 2);

    second.streams.store(2, Ordering::Relaxed);
    let at_cap = pool
        .offer({
            let dials = Arc::clone(&dials);
            move || dial(dials)
        })
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&first, &at_cap));
    assert_eq!(dials.load(Ordering::Relaxed), 2);
}

#[tokio::test(start_paused = true)]
async fn spread_sessions_reuses_busy_session_when_extra_dial_fails() {
    let pool = pool(SessionPoolConfig {
        max_sessions: 2,
        spread_sessions: true,
        ..Default::default()
    });
    let first = pool
        .offer(|| async { Ok(TestSession::new()) })
        .await
        .unwrap();
    first.streams.store(1, Ordering::Relaxed);

    let fallback = pool
        .offer(|| async { anyhow::bail!("extra session unavailable") })
        .await
        .unwrap();

    assert!(Arc::ptr_eq(&first, &fallback));
    assert!(!first.is_closed());
}

#[tokio::test(start_paused = true)]
async fn least_loaded_is_offered() {
    let pool = Arc::new(pool(SessionPoolConfig {
        max_streams_per_session: 2,
        ..Default::default()
    }));
    let dial_count = Arc::new(AtomicUsize::new(0));
    let mk = |pool: Arc<SessionPool<TestSession>>, dials: Arc<AtomicUsize>| {
        let d = Arc::clone(&dials);
        async move {
            pool.offer(move || async move {
                d.fetch_add(1, Ordering::Relaxed);
                Ok(TestSession::new())
            })
            .await
            .unwrap()
        }
    };
    let s1 = mk(Arc::clone(&pool), Arc::clone(&dial_count)).await;
    s1.streams.store(2, Ordering::Relaxed); // saturated
    let s2 = mk(Arc::clone(&pool), Arc::clone(&dial_count)).await; // dials again
    assert!(!Arc::ptr_eq(&s1, &s2));
    s1.streams.store(1, Ordering::Relaxed);
    s2.streams.store(3, Ordering::Relaxed); // over cap
    let s3 = mk(Arc::clone(&pool), Arc::clone(&dial_count)).await;
    assert!(Arc::ptr_eq(&s1, &s3), "least-loaded below cap wins");
}

#[tokio::test(start_paused = true)]
async fn saturated_session_wakes_when_its_permit_is_released() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 1,
        max_streams_per_session: 1,
        janitor_interval: Duration::from_secs(30),
        ..Default::default()
    }));
    let session = ReservedTestSession::new(1);
    pool.insert(&session);
    let held = pool
        .open_with(
            || async { anyhow::bail!("no fresh dial expected") },
            |_session, permit| async { Ok::<_, OpenError>(permit) },
        )
        .await
        .unwrap();

    let blocked = tokio::spawn({
        let pool = Arc::clone(&pool);
        async move {
            pool.open_with(
                || async { anyhow::bail!("no fresh dial expected") },
                |_session, _permit| async { Ok::<_, OpenError>(()) },
            )
            .await
        }
    });
    tokio::task::yield_now().await;
    assert!(!blocked.is_finished());
    assert!(!session.is_closed());

    drop(held);
    tokio::time::timeout(Duration::from_millis(100), blocked)
        .await
        .expect("released stream capacity did not wake the waiter")
        .unwrap()
        .unwrap();
    assert!(!session.is_closed());
}
#[tokio::test(start_paused = true)]
async fn draining_sessions_do_not_block_a_replacement_dial() {
    let pool = SessionPool::new(SessionPoolConfig {
        max_sessions: 2,
        ..Default::default()
    });
    let first = TestSession::new();
    let second = TestSession::new();
    for session in [&first, &second] {
        session.streams.store(1, Ordering::Relaxed);
        session.begin_drain();
        pool.insert(session);
    }

    let replacement = tokio::time::timeout(
        Duration::from_millis(100),
        pool.offer(|| async { Ok(TestSession::new()) }),
    )
    .await
    .expect("draining carriers consumed the replacement slots")
    .unwrap();

    assert_eq!(replacement.state(), SessionState::Active);
    assert_eq!(pool.metrics().sessions, 3);
    assert!(!first.is_closed());
    assert!(!second.is_closed());
}

#[tokio::test(start_paused = true)]
async fn pre_reservation_drain_does_not_close_live_session() {
    #[derive(Debug)]
    struct DrainOnReserveSession {
        state: AtomicUsize,
        drain_once: AtomicBool,
        permits: Arc<tokio::sync::Semaphore>,
    }

    impl DrainOnReserveSession {
        fn new(drain_once: bool) -> Arc<Self> {
            Arc::new(Self {
                state: AtomicUsize::new(0),
                drain_once: AtomicBool::new(drain_once),
                permits: Arc::new(tokio::sync::Semaphore::new(1)),
            })
        }
    }

    impl ManagedSession for DrainOnReserveSession {
        fn active_streams(&self) -> usize {
            1 - self.permits.available_permits()
        }

        fn is_closed(&self) -> bool {
            self.state.load(Ordering::Acquire) == 2
        }

        fn close(&self) {
            self.state.store(2, Ordering::Release);
        }

        fn state(&self) -> SessionState {
            match self.state.load(Ordering::Acquire) {
                0 => SessionState::Active,
                1 => SessionState::Draining,
                _ => SessionState::Closed,
            }
        }

        fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
            if self.drain_once.swap(false, Ordering::AcqRel) {
                self.state.store(1, Ordering::Release);
                return None;
            }
            if self.state() != SessionState::Active {
                return None;
            }
            let permit = Arc::clone(&self.permits).try_acquire_owned().ok()?;
            Some(SessionPermit::new(Arc::clone(self), permit))
        }
    }

    let pool = SessionPool::new(SessionPoolConfig {
        max_sessions: 2,
        max_streams_per_session: 1,
        ..Default::default()
    });
    let draining = DrainOnReserveSession::new(true);
    pool.insert(&draining);

    pool.open_with(
        || async { Ok(DrainOnReserveSession::new(false)) },
        |_session, _permit| async { Ok::<_, OpenError>(()) },
    )
    .await
    .unwrap();

    assert_eq!(draining.state(), SessionState::Draining);
    assert!(!draining.is_closed());
    assert_eq!(pool.metrics().sessions, 2);
}

#[tokio::test(start_paused = true)]
async fn insert_over_cap_still_tracked() {
    let pool = pool(SessionPoolConfig {
        max_sessions: 1,
        ..Default::default()
    });
    let s1 = TestSession::new();
    let s2 = TestSession::new();
    pool.insert(&s1);
    pool.insert(&s2); // over the cap: must still be tracked
    let offered = pool
        .offer(|| async { unreachable!("no dial needed") })
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&offered, &s1) || Arc::ptr_eq(&offered, &s2));
    // An orphaned (untracked) session would be invisible here.
    assert_eq!(pool.metrics().sessions, 2);
}
