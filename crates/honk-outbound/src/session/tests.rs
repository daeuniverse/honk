use super::*;
use std::sync::atomic::AtomicBool;

#[derive(Debug)]
struct TestSession {
    streams: AtomicUsize,
    closed: AtomicBool,
    state: AtomicUsize,
}

impl TestSession {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            streams: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            state: AtomicUsize::new(0),
        })
    }
}

impl ManagedSession for TestSession {
    fn active_streams(&self) -> usize {
        self.streams.load(Ordering::Relaxed)
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
    fn state(&self) -> SessionState {
        match self.state.load(Ordering::Relaxed) {
            _ if self.is_closed() => SessionState::Closed,
            0 => SessionState::Active,
            _ => SessionState::Draining,
        }
    }
    fn begin_drain(&self) {
        self.state.store(1, Ordering::Relaxed);
    }
}

fn pool(config: SessionPoolConfig) -> SessionPool<TestSession> {
    SessionPool::new(config)
}

#[derive(Debug)]
struct ReservedTestSession {
    closed: AtomicBool,
    stream_permits: Arc<tokio::sync::Semaphore>,
    capacity: usize,
}

impl ReservedTestSession {
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            closed: AtomicBool::new(false),
            stream_permits: Arc::new(tokio::sync::Semaphore::new(capacity)),
            capacity,
        })
    }
}

impl ManagedSession for ReservedTestSession {
    fn active_streams(&self) -> usize {
        self.capacity - self.stream_permits.available_permits()
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
    fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
        if self.is_closed() {
            return None;
        }
        let permit = Arc::clone(&self.stream_permits).try_acquire_owned().ok()?;
        if self.is_closed() {
            drop(permit);
            return None;
        }
        Some(SessionPermit::new(Arc::clone(self), permit))
    }
}

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

/// v2 (pool-owned dial): cancelling a caller never stops the shared
/// dial — the waiter still receives the session the pool task
/// establishes, and no second dial is stamped (single-flight).
#[tokio::test(start_paused = true)]
async fn caller_cancel_does_not_stop_shared_dial() {
    let pool = Arc::new(pool(SessionPoolConfig::default()));
    let (tx, rx) = tokio::sync::oneshot::channel::<Arc<TestSession>>();
    let p1 = Arc::clone(&pool);
    let leader = tokio::spawn(async move {
        p1.offer(move || async move {
            let s: anyhow::Result<Arc<TestSession>> = Ok(rx.await.expect("trigger"));
            s
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    leader.abort();
    let _ = leader.await;
    let dials = Arc::new(AtomicUsize::new(0));
    let d = Arc::clone(&dials);
    let p2 = Arc::clone(&pool);
    let waiter = tokio::spawn(async move {
        p2.offer(move || async move {
            d.fetch_add(1, Ordering::Relaxed);
            Ok(TestSession::new())
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        dials.load(Ordering::Relaxed),
        0,
        "single-flight: the shared dial keeps running, no second dial"
    );
    tx.send(TestSession::new()).unwrap();
    let session = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("waiter stuck behind the shared dial")
        .unwrap()
        .unwrap();
    assert!(!session.is_closed());
    assert!(pool.pool.lock().dial_done.is_none());
    assert_eq!(pool.pool.lock().dial_failures, 0);
}

/// v2: a panicking dial surfaces as an internal failure to every
/// waiter; the inflight entry clears and the next offer re-dials.
#[tokio::test(start_paused = true)]
async fn dial_panic_wakes_waiters_and_reelects() {
    let pool = Arc::new(pool(SessionPoolConfig::default()));
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = Arc::clone(&attempts);
    let result = pool
        .offer(move || {
            let n = a.fetch_add(1, Ordering::Relaxed);
            async move {
                if n == 0 {
                    panic!("boom")
                } else {
                    Ok(TestSession::new())
                }
            }
        })
        .await;
    assert!(result.is_err(), "panicking dial surfaces as failure");
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    assert!(pool.pool.lock().dial_done.is_none());
    // Past the short backoff, a fresh offer re-dials and succeeds.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let a2 = Arc::clone(&attempts);
    let session = pool
        .offer(move || {
            a2.fetch_add(1, Ordering::Relaxed);
            async { Ok(TestSession::new()) }
        })
        .await
        .unwrap();
    assert!(!session.is_closed());
}

/// Phase 1: shutdown aborts the in-flight dial (leader), wakes every
/// waiter with PoolClosed, and rejects offers/inserts afterwards.
#[tokio::test(start_paused = true)]
async fn shutdown_wakes_leader_and_waiters() {
    let pool = Arc::new(pool(SessionPoolConfig::default()));
    let p1 = Arc::clone(&pool);
    let leader = tokio::spawn(async move {
        p1.offer(|| async {
            futures_util::future::pending::<anyhow::Result<Arc<TestSession>>>().await
        })
        .await
    });
    let p2 = Arc::clone(&pool);
    let waiter =
        tokio::spawn(async move { p2.offer(|| async { Ok(TestSession::new()) }).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    pool.shutdown();
    assert!(waiter.await.unwrap().is_err(), "waiter must see PoolClosed");
    assert!(
        leader.await.unwrap().is_err(),
        "leader's dial must abort with PoolClosed"
    );
    pool.shutdown(); // idempotent
    assert!(
        pool.offer(|| async { Ok(TestSession::new()) })
            .await
            .is_err(),
        "offers stay rejected after shutdown"
    );
    let s = TestSession::new();
    pool.insert(&s);
    assert!(
        s.closed.load(Ordering::Relaxed),
        "insert after shutdown closes the session"
    );
    assert!(
        !pool.has_usable_session(),
        "a shutdown pool cannot retain a late session insertion"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_before_ensure_does_not_register_janitor_or_prewarm() {
    let pool = Arc::new(pool(SessionPoolConfig {
        janitor_interval: Duration::from_secs(1),
        ..Default::default()
    }));
    let prewarm_calls = Arc::new(AtomicUsize::new(0));
    pool.shutdown();
    pool.ensure_janitor(1, Duration::from_secs(60), {
        let prewarm_calls = Arc::clone(&prewarm_calls);
        move || {
            let prewarm_calls = Arc::clone(&prewarm_calls);
            async move {
                prewarm_calls.fetch_add(1, Ordering::Relaxed);
                Ok(TestSession::new())
            }
        }
    });
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!({
        let pool = pool.pool.lock();
        pool.sessions.is_empty()
            && pool.provisional.is_empty()
            && pool.dial_done.is_none()
            && !pool.janitor_running
    });
    assert_eq!(prewarm_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn shutdown_before_first_janitor_poll_exits_without_mutating_pool() {
    let pool = Arc::new(pool(SessionPoolConfig {
        janitor_interval: Duration::from_secs(1),
        ..Default::default()
    }));
    pool.pool.lock().janitor_running = true;
    let _shutdown_listener = pool.shutdown_tx.subscribe();
    pool.shutdown();
    let shutdown_rx = pool.shutdown_tx.subscribe();
    assert!(
        *shutdown_rx.borrow(),
        "first poll observes terminal watch state"
    );
    let prewarm_calls = Arc::new(AtomicUsize::new(0));
    let janitor = tokio::spawn(Arc::clone(&pool).run_janitor(
        Duration::from_secs(60),
        {
            let prewarm_calls = Arc::clone(&prewarm_calls);
            move || {
                let prewarm_calls = Arc::clone(&prewarm_calls);
                async move {
                    prewarm_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(TestSession::new())
                }
            }
        },
        shutdown_rx,
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(
        janitor.is_finished(),
        "terminal janitor must exit on first poll"
    );
    assert!(
        {
            let pool = pool.pool.lock();
            pool.sessions.is_empty() && pool.provisional.is_empty() && pool.dial_done.is_none()
        },
        "terminal janitor must not mutate its pool"
    );
    assert_eq!(prewarm_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn warm_retention_pins_one_idle_session_until_release() {
    let pool = Arc::new(pool(SessionPoolConfig {
        janitor_interval: Duration::from_secs(1),
        ..Default::default()
    }));
    pool.ensure_janitor(0, Duration::from_secs(2), || async {
        unreachable!("a retained idle session already satisfies the floor")
    });
    let session = pool
        .offer(|| async { Ok(TestSession::new()) })
        .await
        .unwrap();

    pool.set_warm_retained(true);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!session.is_closed(), "warm ownership pins one idle session");

    pool.set_warm_retained(false);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        session.is_closed(),
        "unpin restores the configured zero floor"
    );
}

/// v2 max-age: past the jittered deadline the session drains (no new
/// channels) and the janitor closes it once empty.
#[tokio::test(start_paused = true)]
async fn max_age_drains_and_janitor_closes_empty_session() {
    let pool = Arc::new(pool(SessionPoolConfig {
        max_session_age: Some(Duration::from_secs(60)),
        janitor_interval: Duration::from_secs(5),
        ..Default::default()
    }));
    pool.ensure_janitor(0, Duration::from_secs(3600), || async {
        unreachable!("no prewarm")
    });
    let session = pool
        .offer(|| async { Ok(TestSession::new()) })
        .await
        .unwrap();
    assert_eq!(session.state(), SessionState::Active);
    // Past 60s × 1.1 (the worst jitter), the janitor has drained it
    // (an empty session may already be closed in the same tick).
    tokio::time::sleep(Duration::from_secs(80)).await;
    assert!(
        session.state() == SessionState::Draining || session.is_closed(),
        "past max-age the session drains"
    );
    // Drained and empty: the janitor closes it.
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert!(session.is_closed());
}

#[tokio::test(start_paused = true)]
async fn dial_single_flight() {
    let pool = Arc::new(pool(SessionPoolConfig::default()));
    let dials = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let pool = Arc::clone(&pool);
        let dials = Arc::clone(&dials);
        handles.push(tokio::spawn(async move {
            pool.offer(move || async move {
                dials.fetch_add(1, Ordering::Relaxed);
                // Hold the in-flight dial so the others must wait.
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(TestSession::new())
            })
            .await
        }));
    }
    let results: Vec<_> = futures_util::future::join_all(handles)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(results.iter().all(|r| r.is_ok()));
    assert_eq!(dials.load(Ordering::Relaxed), 1);
    let first = results[0].as_ref().unwrap();
    assert!(
        results[1..]
            .iter()
            .all(|r| Arc::ptr_eq(r.as_ref().unwrap(), first))
    );
}

#[tokio::test(start_paused = true)]
async fn dial_failures_back_off() {
    let pool = pool(SessionPoolConfig {
        dial_backoff: Duration::from_secs(10),
        max_dial_backoff: Duration::from_secs(60),
        ..Default::default()
    });
    let dials = Arc::new(AtomicUsize::new(0));
    let offer_once = |dials: &Arc<AtomicUsize>| {
        let dials = Arc::clone(dials);
        pool.offer(move || async move {
            dials.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("boom")
        })
    };
    assert!(offer_once(&dials).await.is_err());
    assert_eq!(dials.load(Ordering::Relaxed), 1);
    // Inside the window callers fail fast instead of parking.
    let start = Instant::now();
    assert!(offer_once(&dials).await.is_err());
    assert_eq!(start.elapsed(), Duration::ZERO);
    assert_eq!(dials.load(Ordering::Relaxed), 1);
    // Past the window the pool redials: 10s base, doubling to 20s.
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(offer_once(&dials).await.is_err());
    assert_eq!(dials.load(Ordering::Relaxed), 2);
    tokio::time::advance(Duration::from_secs(15)).await;
    assert!(offer_once(&dials).await.is_err());
    assert_eq!(dials.load(Ordering::Relaxed), 2);
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(offer_once(&dials).await.is_err());
    assert_eq!(dials.load(Ordering::Relaxed), 3);
}

#[tokio::test(start_paused = true)]
async fn dial_backoff_is_capped() {
    let pool = pool(SessionPoolConfig {
        dial_backoff: Duration::from_secs(10),
        max_dial_backoff: Duration::from_secs(15),
        ..Default::default()
    });
    let dials = Arc::new(AtomicUsize::new(0));
    let offer_once = |dials: &Arc<AtomicUsize>| {
        let dials = Arc::clone(dials);
        pool.offer(move || async move {
            dials.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("boom")
        })
    };
    assert!(offer_once(&dials).await.is_err());
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(offer_once(&dials).await.is_err());
    assert_eq!(dials.load(Ordering::Relaxed), 2);
    // The raw doubling would give 20s; the cap holds it at 15s.
    tokio::time::advance(Duration::from_secs(14)).await;
    assert!(offer_once(&dials).await.is_err());
    assert_eq!(dials.load(Ordering::Relaxed), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(offer_once(&dials).await.is_err());
    assert_eq!(dials.load(Ordering::Relaxed), 3);
}

/// A session that dies before serving a stream counts as a dial failure:
/// the breaker arms and the next caller fails fast instead of hot-spinning
/// fresh dials against a server that kills every fresh session.
#[tokio::test(start_paused = true)]
async fn dead_on_arrival_session_engages_the_breaker() {
    let pool = pool(SessionPoolConfig::default());
    let dials = Arc::new(AtomicUsize::new(0));
    let offer_dead = |dials: &Arc<AtomicUsize>| {
        let dials = Arc::clone(dials);
        pool.offer(move || async move {
            dials.fetch_add(1, Ordering::Relaxed);
            let session = TestSession::new();
            session.close();
            Ok(session)
        })
    };
    let error = offer_dead(&dials).await.unwrap_err().to_string();
    assert!(error.contains("immediately unusable"), "{error}");
    assert_eq!(dials.load(Ordering::Relaxed), 1);
    let error = offer_dead(&dials).await.unwrap_err().to_string();
    assert!(error.contains("backing off"), "{error}");
    assert_eq!(dials.load(Ordering::Relaxed), 1);
    tokio::time::advance(Duration::from_secs(2)).await;
    let _ = offer_dead(&dials).await;
    assert_eq!(dials.load(Ordering::Relaxed), 2);
}

#[tokio::test(start_paused = true)]
async fn closed_sessions_are_pruned() {
    let pool = pool(SessionPoolConfig::default());
    let s1 = pool
        .offer(|| async { Ok(TestSession::new()) })
        .await
        .unwrap();
    pool.invalidate(&s1);
    let dials = Arc::new(AtomicUsize::new(0));
    let d = Arc::clone(&dials);
    let s2 = pool
        .offer(move || {
            let d = Arc::clone(&d);
            async move {
                d.fetch_add(1, Ordering::Relaxed);
                Ok(TestSession::new())
            }
        })
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&s1, &s2));
    assert_eq!(dials.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn shutdown_closes_everything() {
    let pool = pool(SessionPoolConfig::default());
    let s = pool
        .offer(|| async { Ok(TestSession::new()) })
        .await
        .unwrap();
    pool.shutdown();
    assert!(s.is_closed());
    assert_eq!(pool.metrics().sessions, 0);
}

#[tokio::test(start_paused = true)]
async fn retirement_rejects_new_work_but_drains_live_sessions() {
    let pool = pool(SessionPoolConfig::default());
    let session = pool
        .offer(|| async { Ok(TestSession::new()) })
        .await
        .unwrap();
    session.streams.store(1, Ordering::Relaxed);

    pool.retire();

    assert_eq!(session.state(), SessionState::Draining);
    assert!(
        !session.is_closed(),
        "retirement must preserve live streams"
    );
    assert!(
        pool.offer(|| async { Ok(TestSession::new()) })
            .await
            .is_err(),
        "retired pools must reject new sessions"
    );

    session.streams.store(0, Ordering::Relaxed);
    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    assert!(session.is_closed(), "drained sessions must close promptly");
    assert_eq!(pool.metrics().sessions, 0);
}

#[tokio::test(start_paused = true)]
async fn shutdown_after_retirement_force_closes_live_sessions() {
    let pool = pool(SessionPoolConfig::default());
    let session = pool
        .offer(|| async { Ok(TestSession::new()) })
        .await
        .unwrap();
    session.streams.store(1, Ordering::Relaxed);
    pool.retire();
    assert!(!session.is_closed());

    pool.shutdown();

    assert!(session.is_closed());
    assert_eq!(pool.metrics().sessions, 0);
}

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

#[tokio::test]
async fn successful_offer_releases_reusable_admission_permit() {
    let pool_a = Arc::new(pool(SessionPoolConfig::default()));
    let pool_b = Arc::new(pool(SessionPoolConfig::default()));
    let generation = crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        &[], 1, 1, None,
    )
    .unwrap()
    .0;
    let admission = generation
        .scope_dials(async { crate::runtime::capture_dial_admission() })
        .await;
    pool_a.set_dial_admission(admission.clone());
    pool_b.set_dial_admission(admission);

    let offer_admission = pool_a.dial_admission.read().clone();
    offer_admission
        .scope(pool_a.offer(|| async {
            crate::runtime::admit_physical_dial(async {
                Ok::<_, anyhow::Error>(TestSession::new())
            })
            .await
        }))
        .await
        .unwrap();

    tokio::time::timeout(
        Duration::from_millis(100),
        generation.scope_dials(crate::runtime::admit_physical_dial(async {
            Ok::<_, anyhow::Error>(())
        })),
    )
    .await
    .expect("completed pool offer retained its physical dial permit")
    .unwrap();
    assert!(!pool_b.is_retired());
}

#[tokio::test]
async fn janitor_replacement_waits_for_limit_one() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Arc::new(pool(SessionPoolConfig {
        max_sessions: 1,
        janitor_interval: Duration::from_millis(10),
        ..Default::default()
    }));
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
            .unwrap()
            .0,
    );
    let held = generation.acquire_dial_permit().await;
    let started = Arc::new(AtomicBool::new(false));
    let started_notify = Arc::new(tokio::sync::Notify::new());

    generation
        .scope_dials(async {
            pool.set_dial_admission(crate::runtime::capture_dial_admission());
        })
        .await;
    pool.ensure_janitor(1, Duration::from_secs(60), {
        let started = Arc::clone(&started);
        let started_notify = Arc::clone(&started_notify);
        move || {
            let started = Arc::clone(&started);
            let started_notify = Arc::clone(&started_notify);
            async move {
                let stream = crate::address_race::race_resolved_addrs(&[addr], move |addr| {
                    let started = Arc::clone(&started);
                    let started_notify = Arc::clone(&started_notify);
                    async move {
                        started.store(true, Ordering::Release);
                        started_notify.notify_one();
                        tokio::net::TcpStream::connect(addr).await
                    }
                })
                .await
                .expect("one address")?;
                drop(stream);
                Ok(TestSession::new())
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !started.load(Ordering::Acquire),
        "janitor replacement bypassed the physical dial limit"
    );
    drop(held);
    tokio::time::timeout(Duration::from_secs(1), started_notify.notified())
        .await
        .expect("admitted janitor replacement did not start");
    let (_server, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .expect("janitor replacement opened no TCP connection")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while pool.metrics().sessions == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("janitor did not publish its replacement session");
    pool.shutdown();
}
