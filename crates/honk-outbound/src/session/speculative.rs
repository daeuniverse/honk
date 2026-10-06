use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::time::Instant;

use super::{
    DetachedSessionReservation, DialSignal, ManagedSession, PoolState, SessionPermit, SessionPool,
    SessionState, SpeculativeCheckout,
};

impl<S: ManagedSession + 'static> std::fmt::Debug for SpeculativeCheckout<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shared { .. } => f.debug_tuple("SpeculativeCheckout::Shared").finish(),
            Self::Detached(_) => f.debug_tuple("SpeculativeCheckout::Detached").finish(),
        }
    }
}

impl<S: ManagedSession + 'static> std::fmt::Debug for DetachedSessionReservation<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachedSessionReservation")
            .field("slot_id", &self.slot_id)
            .finish_non_exhaustive()
    }
}

impl<S: ManagedSession + 'static> SessionPool<S> {
    /// Atomically reserve an existing stream slot, or reserve capacity for
    /// one caller-owned speculative physical dial. Unlike [`Self::offer`], a
    /// detached dial is never spawned by the pool: aborting its caller drops
    /// the reservation and therefore the dial/session with it.
    pub async fn checkout_speculative(self: &Arc<Self>) -> anyhow::Result<SpeculativeCheckout<S>> {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        loop {
            let capacity_changed = self.capacity_notify.notified();
            tokio::pin!(capacity_changed);
            capacity_changed.as_mut().enable();
            enum Step<S: ManagedSession + 'static> {
                Closed,
                Shared(Arc<S>, SessionPermit<S>),
                Wait(tokio::sync::watch::Receiver<DialSignal>),
                Backoff(Duration),
                Capacity,
                Detached(u64),
            }
            let step = {
                let mut pool = self.pool.lock();
                if self.state() != PoolState::Running {
                    Step::Closed
                } else {
                    pool.sessions.retain(|session| !session.is_closed());
                    if let Some((session, permit)) = pool.sessions.iter().find_map(|session| {
                        if session.state() != SessionState::Active {
                            return None;
                        }
                        let session = Arc::clone(session);
                        self.try_reserve(&session).map(|permit| (session, permit))
                    }) {
                        Step::Shared(session, permit)
                    } else if let Some((_, done)) = &pool.dial_done {
                        // A normal offer already owns capacity for this dial;
                        // wait rather than oversubscribe the hard cap.
                        Step::Wait(done.subscribe())
                    } else if let Some(wait) = pool
                        .next_dial_at
                        .and_then(|at| at.checked_duration_since(Instant::now()))
                        .filter(|wait| *wait > Duration::ZERO)
                    {
                        Step::Backoff(wait)
                    } else if Self::occupied_slots(&pool) >= self.config.max_sessions {
                        Step::Capacity
                    } else {
                        let slot_id = pool.next_provisional_id;
                        pool.next_provisional_id += 1;
                        pool.provisional.insert(slot_id, None);
                        Step::Detached(slot_id)
                    }
                }
            };

            match step {
                Step::Closed => return Err(Self::pool_closed_err()),
                Step::Shared(session, permit) => {
                    return Ok(SpeculativeCheckout::Shared { session, permit });
                }
                Step::Detached(slot_id) => {
                    return Ok(SpeculativeCheckout::Detached(DetachedSessionReservation {
                        pool: Arc::clone(self),
                        slot_id,
                        active: true,
                    }));
                }
                Step::Capacity => {
                    tokio::select! {
                        _ = &mut capacity_changed => {}
                        _ = shutdown_rx.changed() => return Err(Self::pool_closed_err()),
                    }
                }
                Step::Backoff(wait) => {
                    // Same fast-fail contract as offer(): speculative callers
                    // are exploratory by definition and must not park.
                    return Err(anyhow!("session dial backing off ({wait:?} remaining)"));
                }
                Step::Wait(mut rx) => {
                    let signal = tokio::select! {
                        result = rx.wait_for(|signal| !matches!(signal, DialSignal::Pending)) => {
                            match result {
                                Ok(signal) => signal.clone(),
                                // A cancelled/panicked normal dial released its
                                // guard; re-check and reserve our own slot.
                                Err(_) => DialSignal::Done,
                            }
                        }
                        _ = shutdown_rx.changed() => return Err(Self::pool_closed_err()),
                    };
                    match signal {
                        DialSignal::Closed => return Err(Self::pool_closed_err()),
                        DialSignal::Failed(error) => {
                            return Err(anyhow::Error::new(error).context("session dial failed"));
                        }
                        DialSignal::Pending | DialSignal::Done => {}
                    }
                }
            }
        }
    }
}

impl<S: ManagedSession + 'static> DetachedSessionReservation<S> {
    /// Wait until the captured pool generation begins retirement or shutdown.
    /// Callers race this against their detached physical dial so generation
    /// retirement cancels work that the pool deliberately does not own.
    pub async fn cancelled(&self) {
        let mut shutdown_rx = self.pool.shutdown_tx.subscribe();
        if self.pool.state() != PoolState::Running {
            return;
        }
        let _ = shutdown_rx.changed().await;
    }

    /// Attach a completed detached session and reserve its first pool-owned stream
    /// permit. Retirement, shutdown, and cancellation close it until commit.
    pub fn attach(&mut self, session: &Arc<S>) -> anyhow::Result<SessionPermit<S>> {
        let attached = {
            let mut pool = self.pool.pool.lock();
            if !self.active || self.pool.state() != PoolState::Running {
                false
            } else {
                pool.provisional.get_mut(&self.slot_id).is_some_and(|slot| {
                    if slot.is_some() {
                        false
                    } else {
                        session.bind_capacity_notify(Arc::clone(&self.pool.capacity_notify));
                        *slot = Some(Arc::clone(session));
                        true
                    }
                })
            }
        };
        if attached {
            self.pool.try_reserve(session).ok_or_else(|| {
                anyhow::Error::new(crate::proxy::PacketRejection::Capacity)
                    .context("detached session has no stream capacity")
            })
        } else {
            session.close();
            Err(SessionPool::<S>::pool_closed_err())
        }
    }

    /// Promote the attached session exactly once into the captured pool. A
    /// terminal pool removes the slot and closes the session instead of
    /// allowing a stale generation to repopulate it.
    pub fn commit(mut self) -> anyhow::Result<Arc<S>> {
        let outcome = {
            let mut pool = self.pool.pool.lock();
            let session = pool.provisional.remove(&self.slot_id).flatten();
            if self.pool.state() == PoolState::Running {
                if let Some(session) = session {
                    pool.sessions.retain(|existing| !existing.is_closed());
                    // Preserve normal offers' publication slots; detached winners
                    // retain already-reserved streams as drain-only above the cap.
                    let active = pool
                        .sessions
                        .iter()
                        .filter(|s| s.state() == SessionState::Active)
                        .count();
                    if active + usize::from(pool.dial_done.is_some())
                        >= self.pool.config.max_sessions
                    {
                        session.begin_drain();
                    }
                    pool.sessions.push(Arc::clone(&session));
                    Ok(session)
                } else {
                    Err(None)
                }
            } else {
                Err(session)
            }
        };
        self.active = false;
        self.pool.capacity_notify.notify_waiters();
        match outcome {
            Ok(session) => Ok(session),
            Err(session) => {
                if let Some(session) = session {
                    session.close();
                }
                Err(SessionPool::<S>::pool_closed_err())
            }
        }
    }

    /// Publish one preparation's physical sessions under a single pool lock.
    /// Every reservation is validated before any session becomes reusable.
    pub(crate) fn commit_all(mut reservations: Vec<Self>) -> anyhow::Result<()> {
        let Some(first) = reservations.first() else {
            return Ok(());
        };
        let owner = Arc::clone(&first.pool);
        anyhow::ensure!(
            reservations
                .iter()
                .all(|reservation| Arc::ptr_eq(&owner, &reservation.pool)),
            "detached sessions belong to different pools"
        );
        {
            let mut pool = owner.pool.lock();
            if owner.state() != PoolState::Running {
                return Err(SessionPool::<S>::pool_closed_err());
            }
            let mut incoming_active = 0;
            for reservation in &reservations {
                let session = pool
                    .provisional
                    .get(&reservation.slot_id)
                    .and_then(Option::as_ref);
                match session.map(|session| session.state()) {
                    Some(SessionState::Active) if reservation.active => incoming_active += 1,
                    Some(SessionState::Draining) if reservation.active => {}
                    _ => return Err(SessionPool::<S>::pool_closed_err()),
                }
            }
            pool.sessions.retain(|session| !session.is_closed());
            let active = pool
                .sessions
                .iter()
                .filter(|session| session.state() == SessionState::Active)
                .count();
            if active + usize::from(pool.dial_done.is_some()) + incoming_active
                > owner.config.max_sessions
            {
                return Err(anyhow::Error::new(crate::proxy::PacketRejection::Capacity));
            }
            for reservation in &mut reservations {
                let session = pool
                    .provisional
                    .remove(&reservation.slot_id)
                    .flatten()
                    .expect("validated detached session");
                pool.sessions.push(session);
                reservation.active = false;
            }
        };
        owner.capacity_notify.notify_waiters();
        Ok(())
    }
}

impl<S: ManagedSession + 'static> Drop for DetachedSessionReservation<S> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let session = self
            .pool
            .pool
            .lock()
            .provisional
            .remove(&self.slot_id)
            .flatten();
        self.active = false;
        if let Some(session) = session {
            session.close();
        }
        self.pool.capacity_notify.notify_waiters();
    }
}
