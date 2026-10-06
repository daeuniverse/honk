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
    let pool = Arc::new(SessionPool::new(SessionPoolConfig::default()));
    let mut reservation = match pool.checkout_speculative().await.unwrap() {
        SpeculativeCheckout::Detached(reservation) => reservation,
        SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
    };
    let session = ReservedTestSession::new(1);
    let _permit = reservation.attach(&session).unwrap();

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

#[tokio::test]
async fn detached_capacity_refusal_is_health_neutral_and_rolls_back() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 1,
        ..Default::default()
    }));
    let SpeculativeCheckout::Detached(mut reservation) = pool.checkout_speculative().await.unwrap()
    else {
        panic!("empty pool must reserve a detached dial");
    };
    let session = ReservedTestSession::new(1);
    let held = session.try_reserve().unwrap();
    let error = reservation.attach(&session).unwrap_err();
    assert_eq!(
        crate::proxy::packet_rejection(&error),
        Some(crate::proxy::PacketRejection::Capacity)
    );
    assert_eq!(
        crate::group::ScoreOutcome::from_error(&error),
        crate::group::ScoreOutcome::Rejected
    );

    drop(reservation);
    drop(held);
    assert!(session.is_closed());
    assert_eq!(pool.metrics().sessions, 0);
    assert!(matches!(
        pool.checkout_speculative().await.unwrap(),
        SpeculativeCheckout::Detached(_)
    ));
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
    let pool = Arc::new(SessionPool::new(SessionPoolConfig::default()));
    let mut reservation = match pool.checkout_speculative().await.unwrap() {
        SpeculativeCheckout::Detached(reservation) => reservation,
        SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
    };
    let session = ReservedTestSession::new(2);
    let _permit = reservation.attach(&session).unwrap();
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
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 1,
        ..Default::default()
    }));
    let mut reservation = match pool.checkout_speculative().await.unwrap() {
        SpeculativeCheckout::Detached(reservation) => reservation,
        SpeculativeCheckout::Shared { .. } => panic!("empty pool cannot be shared"),
    };
    let winner = ReservedTestSession::new(1);
    let _permit = reservation.attach(&winner).unwrap();
    // Normal offers don't count provisional slots, so the pool can fill
    // while the speculative dial is detached.
    let active = pool
        .offer(|| async { Ok(ReservedTestSession::new(1)) })
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
async fn detached_commit_preserves_inflight_normal_dial_slot() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 1,
        ..Default::default()
    }));
    let SpeculativeCheckout::Detached(mut reservation) = pool.checkout_speculative().await.unwrap()
    else {
        panic!("empty pool must reserve a detached dial");
    };
    let detached = ReservedTestSession::new(1);
    let detached_permit = reservation.attach(&detached).unwrap();
    let (started, entered) = tokio::sync::oneshot::channel();
    let (release, blocked) = tokio::sync::oneshot::channel();
    let normal = tokio::spawn({
        let pool = Arc::clone(&pool);
        async move {
            pool.offer(move || async move {
                started.send(()).unwrap();
                blocked.await.unwrap();
                Ok(ReservedTestSession::new(1))
            })
            .await
        }
    });
    entered.await.unwrap();

    let committed = reservation.commit().unwrap();
    assert!(Arc::ptr_eq(&committed, &detached));
    assert_eq!(committed.state(), SessionState::Draining);
    assert_eq!(committed.active_streams(), 1);
    assert!(!committed.is_closed());

    release.send(()).unwrap();
    let active = normal.await.unwrap().unwrap();
    assert_eq!(active.state(), SessionState::Active);
    assert!(!Arc::ptr_eq(&active, &detached));
    assert_eq!(pool.active_session_total(), 1);
    assert_eq!(pool.live_session_count(), 2);
    let active_permit = pool
        .open_with(
            || async { unreachable!("normal publication must remain reusable") },
            |_session, permit| async { Ok::<_, OpenError>(permit) },
        )
        .await
        .unwrap();

    drop(detached_permit);
    assert_eq!(pool.reap_unretained_idle(), 1);
    assert!(detached.is_closed());
    assert!(!active.is_closed());
    assert_eq!(active.active_streams(), 1);
    assert_eq!(pool.live_session_count(), 1);
    drop(active_permit);
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

    let mut blocked = std::pin::pin!(pool.checkout_speculative());
    assert!(futures_util::poll!(blocked.as_mut()).is_pending());
    drop(permit);
    let std::task::Poll::Ready(Ok(next)) = futures_util::poll!(blocked.as_mut()) else {
        panic!("second checkout did not observe released stream capacity");
    };
    assert!(matches!(next, SpeculativeCheckout::Shared { .. }));
}

#[tokio::test]
async fn detached_commit_wakes_all_eligible_waiters_without_oversubscribing() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 1,
        max_streams_per_session: 3,
        ..Default::default()
    }));
    let SpeculativeCheckout::Detached(mut reservation) = pool.checkout_speculative().await.unwrap()
    else {
        panic!("empty pool must reserve a detached dial");
    };
    let mut cancelled = Box::pin(pool.checkout_speculative());
    let mut first = std::pin::pin!(pool.checkout_speculative());
    let mut second = std::pin::pin!(pool.checkout_speculative());
    let mut third = std::pin::pin!(pool.checkout_speculative());
    assert!(futures_util::poll!(cancelled.as_mut()).is_pending());
    assert!(futures_util::poll!(first.as_mut()).is_pending());
    assert!(futures_util::poll!(second.as_mut()).is_pending());
    assert!(futures_util::poll!(third.as_mut()).is_pending());

    let session = ReservedTestSession::new(3);
    let held = reservation.attach(&session).unwrap();
    reservation.commit().unwrap();
    drop(cancelled);

    let std::task::Poll::Ready(Ok(SpeculativeCheckout::Shared {
        session: first_session,
        permit: _first_permit,
    })) = futures_util::poll!(first.as_mut())
    else {
        panic!("commit did not wake the first eligible checkout");
    };
    let std::task::Poll::Ready(Ok(SpeculativeCheckout::Shared {
        session: second_session,
        permit: _second_permit,
    })) = futures_util::poll!(second.as_mut())
    else {
        panic!("commit stranded an eligible checkout");
    };
    assert!(Arc::ptr_eq(&first_session, &session));
    assert!(Arc::ptr_eq(&second_session, &session));
    assert!(futures_util::poll!(third.as_mut()).is_pending());
    assert_eq!(session.active_streams(), 3);

    pool.shutdown();
    assert!(matches!(
        futures_util::poll!(third.as_mut()),
        std::task::Poll::Ready(Err(_))
    ));
    drop(held);
}

#[tokio::test]
async fn detached_first_permit_release_wakes_offer_and_speculative_waiters() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 1,
        max_streams_per_session: 1,
        ..Default::default()
    }));
    let SpeculativeCheckout::Detached(mut reservation) = pool.checkout_speculative().await.unwrap()
    else {
        panic!("empty pool must reserve a detached dial");
    };
    let session = ReservedTestSession::new(1);
    let held = reservation.attach(&session).unwrap();
    reservation.commit().unwrap();

    let mut offered = std::pin::pin!(
        pool.offer(|| async { unreachable!("released capacity must not require a dial") })
    );
    let mut first = std::pin::pin!(pool.checkout_speculative());
    let mut second = std::pin::pin!(pool.checkout_speculative());
    assert!(futures_util::poll!(offered.as_mut()).is_pending());
    assert!(futures_util::poll!(first.as_mut()).is_pending());
    assert!(futures_util::poll!(second.as_mut()).is_pending());
    drop(held);

    let std::task::Poll::Ready(Ok(offered)) = futures_util::poll!(offered.as_mut()) else {
        panic!("first detached permit release did not wake the normal offer");
    };
    assert!(Arc::ptr_eq(&offered, &session));
    let std::task::Poll::Ready(Ok(SpeculativeCheckout::Shared { permit, .. })) =
        futures_util::poll!(first.as_mut())
    else {
        panic!("a non-reserving offer consumed the only capacity wakeup");
    };
    assert!(futures_util::poll!(second.as_mut()).is_pending());
    drop(permit);
    let std::task::Poll::Ready(Ok(SpeculativeCheckout::Shared {
        permit: _permit, ..
    })) = futures_util::poll!(second.as_mut())
    else {
        panic!("shared permit release did not wake the remaining checkout");
    };
    assert_eq!(session.active_streams(), 1);
}

#[tokio::test]
async fn speculative_checkout_registers_before_checking_capacity() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 1,
        max_streams_per_session: 1,
        ..Default::default()
    }));
    let session = ReservedTestSession::new(1);
    pool.insert(&session);
    let held = pool
        .open_with(
            || async { unreachable!("seeded session must be reused") },
            |_session, permit| async { Ok::<_, OpenError>(permit) },
        )
        .await
        .unwrap();
    *session.release_on_check.lock() = Some(held);

    let mut checkout = std::pin::pin!(pool.checkout_speculative());
    let std::task::Poll::Ready(Ok(SpeculativeCheckout::Shared {
        session: reused,
        permit: _permit,
    })) = futures_util::poll!(checkout.as_mut())
    else {
        panic!("a release during the capacity check was lost before parking");
    };
    assert!(Arc::ptr_eq(&reused, &session));
    assert_eq!(session.active_streams(), 1);
}

#[tokio::test]
async fn normal_dial_publication_wakes_a_speculative_capacity_waiter() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 1,
        ..Default::default()
    }));
    let SpeculativeCheckout::Detached(_reservation) = pool.checkout_speculative().await.unwrap()
    else {
        panic!("empty pool must reserve a detached dial");
    };
    let mut checkout = std::pin::pin!(pool.checkout_speculative());
    assert!(futures_util::poll!(checkout.as_mut()).is_pending());

    let session = pool
        .offer(|| async { Ok(ReservedTestSession::new(1)) })
        .await
        .unwrap();
    let std::task::Poll::Ready(Ok(SpeculativeCheckout::Shared {
        session: reused,
        permit: _permit,
    })) = futures_util::poll!(checkout.as_mut())
    else {
        panic!("normal publication stranded an already-parked speculative checkout");
    };
    assert!(Arc::ptr_eq(&reused, &session));
}

#[tokio::test]
async fn detached_batch_commit_publishes_all_sessions_once() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 2,
        ..Default::default()
    }));
    let mut reservations = Vec::new();
    let mut sessions = Vec::new();
    let mut permits = Vec::new();
    for _ in 0..2 {
        let SpeculativeCheckout::Detached(mut reservation) =
            pool.checkout_speculative().await.unwrap()
        else {
            panic!("unpublished sessions must remain private");
        };
        let session = ReservedTestSession::new(1);
        permits.push(reservation.attach(&session).unwrap());
        sessions.push(session);
        reservations.push(reservation);
    }
    assert_eq!(pool.live_session_count(), 0);
    DetachedSessionReservation::commit_all(reservations).unwrap();
    {
        let published = pool.pool.lock();
        assert_eq!(published.sessions.len(), 2);
        for (expected, actual) in sessions.iter().zip(&published.sessions) {
            assert!(Arc::ptr_eq(expected, actual));
            assert_eq!(actual.state(), SessionState::Active);
        }
    }
    assert_eq!(pool.live_session_count(), 2);
    assert!(pool.pool.lock().provisional.is_empty());
    drop(permits);
    pool.shutdown();
}

#[tokio::test]
async fn detached_batch_commit_publishes_draining_members_without_charging_capacity() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 2,
        ..Default::default()
    }));
    let mut reservations = Vec::new();
    let mut sessions = Vec::new();
    let mut permits = Vec::new();
    for draining in [true, false] {
        let SpeculativeCheckout::Detached(mut reservation) =
            pool.checkout_speculative().await.unwrap()
        else {
            panic!("unpublished sessions must remain private");
        };
        let session = ReservedTestSession::new(2);
        permits.push(reservation.attach(&session).unwrap());
        if draining {
            session.begin_drain();
        }
        sessions.push(session);
        reservations.push(reservation);
    }
    let incumbent = ReservedTestSession::new(1);
    let incumbent_permit = incumbent.try_reserve().unwrap();
    pool.insert(&incumbent);
    DetachedSessionReservation::commit_all(reservations).unwrap();
    assert_eq!(pool.live_session_count(), 3);
    assert!(pool.pool.lock().provisional.is_empty());
    assert_eq!(sessions[0].state(), SessionState::Draining);
    assert!(!sessions[0].is_closed());
    let SpeculativeCheckout::Shared { session, permit } =
        pool.checkout_speculative().await.unwrap()
    else {
        panic!("the active member must remain reusable");
    };
    assert!(Arc::ptr_eq(&session, &sessions[1]));
    drop(permit);
    drop(incumbent_permit);
    drop(permits);
    pool.shutdown();
    assert!(sessions.iter().all(|session| session.is_closed()));
}

#[tokio::test]
async fn detached_batch_commit_rejects_terminal_or_invalid_member_without_partial_publication() {
    for shutdown in [false, true] {
        let pool = Arc::new(SessionPool::new(SessionPoolConfig {
            max_sessions: 2,
            ..Default::default()
        }));
        let mut reservations = Vec::new();
        let mut sessions = Vec::new();
        let mut permits = Vec::new();
        for _ in 0..2 {
            let SpeculativeCheckout::Detached(mut reservation) =
                pool.checkout_speculative().await.unwrap()
            else {
                panic!("unpublished sessions must remain private");
            };
            let session = ReservedTestSession::new(1);
            permits.push(reservation.attach(&session).unwrap());
            sessions.push(session);
            reservations.push(reservation);
        }
        if shutdown {
            pool.shutdown();
        } else {
            sessions[1].close();
        }
        assert!(DetachedSessionReservation::commit_all(reservations).is_err());
        assert_eq!(pool.live_session_count(), 0);
        assert!(pool.pool.lock().provisional.is_empty());
        assert!(sessions.iter().all(|session| session.is_closed()));
        drop(permits);
    }
}

#[tokio::test]
async fn detached_batch_capacity_refusal_closes_private_sessions_but_preserves_shared_owners() {
    let pool = Arc::new(SessionPool::new(SessionPoolConfig {
        max_sessions: 2,
        ..Default::default()
    }));
    let SpeculativeCheckout::Detached(mut reservation) = pool.checkout_speculative().await.unwrap()
    else {
        panic!("empty pool must reserve a private slot");
    };
    let private = ReservedTestSession::new(1);
    let _permit = reservation.attach(&private).unwrap();
    let incumbents = [ReservedTestSession::new(1), ReservedTestSession::new(1)];
    for incumbent in &incumbents {
        pool.insert(incumbent);
    }
    let error = DetachedSessionReservation::commit_all(vec![reservation]).unwrap_err();
    assert_eq!(
        crate::proxy::packet_rejection(&error),
        Some(crate::proxy::PacketRejection::Capacity)
    );
    assert_eq!(
        crate::group::ScoreOutcome::from_error(&error),
        crate::group::ScoreOutcome::Rejected
    );
    assert!(private.is_closed());
    assert!(
        incumbents
            .iter()
            .all(|session| session.state() == SessionState::Active)
    );
    assert_eq!(pool.live_session_count(), 2);
    assert!(pool.pool.lock().provisional.is_empty());
    pool.shutdown();
}

#[tokio::test]
async fn carrier_first_capacity_refusal_never_publishes_mux_or_disturbs_shared_carriers() {
    for outer_terminal in [false, true] {
        let outer = Arc::new(SessionPool::new(SessionPoolConfig {
            max_sessions: 1,
            ..Default::default()
        }));
        let inner = Arc::new(SessionPool::new(SessionPoolConfig {
            max_sessions: 2,
            ..Default::default()
        }));
        let SpeculativeCheckout::Detached(mut outer_guard) =
            outer.checkout_speculative().await.unwrap()
        else {
            panic!("empty outer pool must reserve a private slot");
        };
        let SpeculativeCheckout::Detached(mut inner_guard) =
            inner.checkout_speculative().await.unwrap()
        else {
            panic!("empty inner pool must reserve a private slot");
        };
        let outer_session = ReservedTestSession::new(1);
        let inner_session = ReservedTestSession::new(1);
        let _outer_permit = outer_guard.attach(&outer_session).unwrap();
        let _inner_permit = inner_guard.attach(&inner_session).unwrap();
        let incumbents = [ReservedTestSession::new(1), ReservedTestSession::new(1)];
        for incumbent in &incumbents {
            inner.insert(incumbent);
        }
        if outer_terminal {
            outer.shutdown();
        }
        let result = (|| {
            DetachedSessionReservation::commit_all(vec![inner_guard])?;
            outer_guard.commit()?;
            Ok::<_, anyhow::Error>(())
        })();
        let error = result.unwrap_err();
        assert_eq!(
            crate::proxy::packet_rejection(&error),
            Some(crate::proxy::PacketRejection::Capacity)
        );
        assert_eq!(outer.live_session_count(), 0);
        assert_eq!(inner.live_session_count(), 2);
        assert!(outer_session.is_closed());
        assert!(inner_session.is_closed());
        assert!(outer.pool.lock().provisional.is_empty());
        assert!(inner.pool.lock().provisional.is_empty());
        assert!(
            incumbents
                .iter()
                .all(|session| session.state() == SessionState::Active)
        );
        outer.shutdown();
        inner.shutdown();
    }
}

#[tokio::test]
async fn carrier_first_publication_preserves_mux_winner_retirement_and_loser_rollback() {
    for outcome in ["winner", "retired", "loser"] {
        let outer = Arc::new(SessionPool::new(SessionPoolConfig::default()));
        let inner = Arc::new(SessionPool::new(SessionPoolConfig::default()));
        let SpeculativeCheckout::Detached(mut outer_guard) =
            outer.checkout_speculative().await.unwrap()
        else {
            panic!("empty mux pool must reserve a private slot");
        };
        let SpeculativeCheckout::Detached(mut inner_guard) =
            inner.checkout_speculative().await.unwrap()
        else {
            panic!("empty carrier pool must reserve a private slot");
        };
        let mux = ReservedTestSession::new(1);
        let carrier = ReservedTestSession::new(1);
        let _mux_permit = outer_guard.attach(&mux).unwrap();
        let _carrier_permit = inner_guard.attach(&carrier).unwrap();
        if outcome == "loser" {
            drop(inner_guard);
            drop(outer_guard);
            assert_eq!(inner.live_session_count(), 0);
            assert_eq!(outer.live_session_count(), 0);
            assert!(mux.is_closed());
            assert!(carrier.is_closed());
        } else {
            if outcome == "retired" {
                outer.retire();
            }
            DetachedSessionReservation::commit_all(vec![inner_guard]).unwrap();
            let result = outer_guard.commit();
            assert_eq!(result.is_ok(), outcome == "winner");
            assert_eq!(outer.live_session_count(), usize::from(outcome == "winner"));
            assert_eq!(inner.live_session_count(), 1);
            assert_eq!(mux.is_closed(), outcome == "retired");
            assert!(!carrier.is_closed());
        }
        assert!(outer.pool.lock().provisional.is_empty());
        assert!(inner.pool.lock().provisional.is_empty());
        outer.shutdown();
        inner.shutdown();
    }
}
