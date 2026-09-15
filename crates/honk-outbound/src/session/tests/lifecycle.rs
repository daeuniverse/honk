use super::*;
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

#[tokio::test(start_paused = true)]
async fn shared_dial_waiters_preserve_typed_capacity_rejection() {
    let pool = Arc::new(pool(SessionPoolConfig::default()));
    let (release, blocked) = tokio::sync::oneshot::channel();
    let leader_pool = Arc::clone(&pool);
    let leader = tokio::spawn(async move {
        leader_pool
            .offer(move || async move {
                blocked.await.unwrap();
                Err(anyhow::Error::new(crate::proxy::PacketRejection::Capacity))
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let waiter_pool = Arc::clone(&pool);
    let waiter = tokio::spawn(async move {
        waiter_pool
            .offer(|| async { unreachable!("waiter must share the in-flight dial") })
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    release.send(()).unwrap();

    for result in [leader.await.unwrap(), waiter.await.unwrap()] {
        let error = result.unwrap_err();
        assert!(error.chain().any(|cause| matches!(
            cause.downcast_ref::<crate::proxy::PacketRejection>(),
            Some(crate::proxy::PacketRejection::Capacity)
        )));
    }
    assert_eq!(pool.pool.lock().dial_failures, 0);
    assert!(pool.pool.lock().next_dial_at.is_none());
    let session = pool
        .offer(|| async { Ok(TestSession::new()) })
        .await
        .expect("released capacity must admit without a synthetic backoff");
    assert!(!session.is_closed());
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

/// Shutdown aborts the in-flight dial, wakes every waiter with PoolClosed,
/// and rejects later offers.
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
    let waiter = tokio::spawn(async move { p2.offer(|| async { Ok(TestSession::new()) }).await });
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

#[tokio::test(start_paused = true)]
async fn janitor_preserves_and_replenishes_warm_carriers_while_old_streams_drain() {
    let pool = Arc::new(pool(SessionPoolConfig {
        janitor_interval: Duration::from_secs(1),
        ..Default::default()
    }));
    let old = TestSession::new();
    old.streams.store(1, Ordering::Relaxed);
    old.begin_drain();
    let replacement = TestSession::new();
    pool.insert(&old);
    pool.insert(&replacement);
    pool.set_warm_retained(true);
    let rewarmed = TestSession::new();
    pool.ensure_janitor(0, Duration::from_secs(2), {
        let rewarmed = Arc::clone(&rewarmed);
        move || {
            let rewarmed = Arc::clone(&rewarmed);
            async move { Ok(rewarmed) }
        }
    });

    tokio::time::sleep(Duration::from_secs(5)).await;
    let offered = pool
        .offer(|| async { anyhow::bail!("warm replacement must avoid redial") })
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&offered, &replacement));
    assert!(!old.is_closed(), "the old live stream must survive reaping");

    replacement.streams.store(1, Ordering::Relaxed);
    replacement.begin_drain();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let offered = pool
        .offer(|| async { anyhow::bail!("janitor must restore a reusable warm carrier") })
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&offered, &rewarmed));
    assert!(!old.is_closed());
    assert!(!replacement.is_closed());
    pool.shutdown();
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
