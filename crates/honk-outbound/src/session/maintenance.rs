use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::Instant;

use super::{ManagedSession, PoolState, SessionPool, SessionState};

impl<S: ManagedSession + 'static> SessionPool<S> {
    /// Drain idle sessions above the configured or runtime-retained reusable floor.
    /// Sessions with live streams are never disturbed; terminal sessions are pruned.
    #[cfg(any(feature = "rprx", test))]
    pub fn reap_unretained_idle(&self) -> usize {
        if self.state() != PoolState::Running {
            return 0;
        }
        let (to_close, capacity_changed) = {
            let mut pool = self.pool.lock();
            if self.state() != PoolState::Running {
                return 0;
            }
            let min_live = pool
                .base_min_idle
                .max(if pool.warm_retained { 1 } else { 0 });
            let mut remaining = pool
                .sessions
                .iter()
                .filter(|session| session.state() == SessionState::Active)
                .count();
            let mut to_close = Vec::new();
            let mut capacity_changed = false;
            pool.sessions.retain(|session| {
                if session.is_closed() {
                    capacity_changed = true;
                    return false;
                }
                let active = session.state() == SessionState::Active;
                if session.active_streams() != 0 || (active && remaining <= min_live) {
                    return true;
                }
                session.begin_drain();
                if active {
                    capacity_changed = true;
                    remaining -= 1;
                }
                if session.active_streams() == 0 {
                    to_close.push(Arc::clone(session));
                    false
                } else {
                    true
                }
            });
            (to_close, capacity_changed)
        };
        let reaped = to_close.len();
        for session in to_close {
            session.close();
        }
        if capacity_changed || reaped != 0 {
            self.capacity_notify.notify_waiters();
        }
        reaped
    }

    /// Pin or unpin a reusable warm session. Unpinning immediately closes
    /// idle sessions above the explicit standby floor and drains active excess
    /// sessions without cutting their streams.
    pub fn set_warm_retained(&self, retained: bool) {
        if self.state() != PoolState::Running {
            return;
        }
        let to_close = {
            let mut pool = self.pool.lock();
            if self.state() != PoolState::Running {
                return;
            }
            if pool.warm_retained == retained {
                return;
            }
            pool.warm_retained = retained;
            if retained {
                Vec::new()
            } else {
                let base_min_idle = pool.base_min_idle;
                let mut active_kept = 0usize;
                let mut to_close = Vec::new();
                pool.sessions.retain(|session| {
                    if session.is_closed() {
                        return false;
                    }
                    if session.state() == SessionState::Active && active_kept < base_min_idle {
                        active_kept += 1;
                        return true;
                    }
                    session.begin_drain();
                    if session.active_streams() == 0 {
                        to_close.push(Arc::clone(session));
                        false
                    } else {
                        true
                    }
                });
                to_close
            }
        };
        for session in to_close {
            session.close();
        }
        if !retained {
            self.capacity_notify.notify_waiters();
        }
    }

    #[cfg(test)]
    pub(crate) fn is_warm_retained(&self) -> bool {
        self.pool.lock().warm_retained
    }

    pub(super) async fn run_janitor<F, Fut>(
        self: Arc<Self>,
        idle_timeout: Duration,
        prewarm: F,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = anyhow::Result<Arc<S>>> + Send + 'static,
    {
        if *shutdown_rx.borrow() || self.state() != PoolState::Running {
            return;
        }
        let mut interval = tokio::time::interval(self.config.janitor_interval);
        interval.tick().await;
        // Zero-stream streak start for sessions that keep no idle clock,
        // keyed by Arc identity (positions in the vec shift as sessions
        // come and go). Sessions with a clock answer from their own transitions.
        let mut idle_since: HashMap<usize, Instant> = HashMap::new();
        // Per-session max-age deadline (jittered ±10% by pointer so a
        // fleet of same-age sessions never reconnects in lockstep).
        let mut drain_at: HashMap<usize, Instant> = HashMap::new();
        loop {
            tokio::select! {
                biased;
                // Pool shutdown: exit, no further prewarm/reap.
                _ = shutdown_rx.changed() => return,
                _ = interval.tick() => {}
            }
            let now = Instant::now();
            let (idle_to_close, capacity_changed) = {
                let mut pool = self.pool.lock();
                if self.state() != PoolState::Running {
                    return;
                }
                let previous_live = pool.sessions.len();
                pool.sessions.retain(|s| !s.is_closed());
                let live = &pool.sessions;
                let mut to_close = Vec::new();
                idle_since.retain(|ptr, _| live.iter().any(|s| Arc::as_ptr(s) as usize == *ptr));
                drain_at.retain(|ptr, _| live.iter().any(|s| Arc::as_ptr(s) as usize == *ptr));
                let min_idle = pool
                    .base_min_idle
                    .max(if pool.warm_retained { 1 } else { 0 });
                let mut remaining_active = live
                    .iter()
                    .filter(|session| session.state() == SessionState::Active)
                    .count();
                let initial_active = remaining_active;
                for s in live {
                    let ptr = Arc::as_ptr(s) as usize;
                    let was_active = s.state() == SessionState::Active;
                    // Max-age drain: stop taking new streams past the
                    // jittered deadline; close once fully drained.
                    if let Some(max_age) = self.config.max_session_age {
                        let deadline = drain_at.entry(ptr).or_insert_with(|| {
                            let jitter = 0.9 + ((ptr % 200) as f64) / 1000.0;
                            s.created_at() + max_age.mul_f64(jitter)
                        });
                        if now >= *deadline {
                            s.begin_drain();
                        }
                    }
                    if was_active && s.state() != SessionState::Active {
                        remaining_active -= 1;
                    }
                    if s.state() != SessionState::Active && s.active_streams() == 0 {
                        to_close.push(Arc::clone(s));
                        continue;
                    }
                    if s.active_streams() > 0 {
                        idle_since.remove(&ptr);
                        continue;
                    }
                    let since = match s.idle_since() {
                        Some(since) => since,
                        None => *idle_since.entry(ptr).or_insert(now),
                    };
                    if now.duration_since(since) >= idle_timeout && remaining_active > min_idle {
                        to_close.push(Arc::clone(s));
                        remaining_active -= 1;
                    }
                }
                (
                    to_close,
                    previous_live != live.len() || remaining_active != initial_active,
                )
            };
            for s in &idle_to_close {
                self.invalidate(s);
            }
            if capacity_changed && idle_to_close.is_empty() {
                self.capacity_notify.notify_waiters();
            }
            // Prewarm to the explicit or runtime-pinned floor while the pool
            // remains live.
            let (current, min_idle) = {
                let pool = self.pool.lock();
                if self.state() != PoolState::Running {
                    return;
                }
                (
                    pool.sessions
                        .iter()
                        .filter(|session| session.state() == SessionState::Active)
                        .count(),
                    pool.base_min_idle
                        .max(if pool.warm_retained { 1 } else { 0 }),
                )
            };
            if current < min_idle {
                let admission = self
                    .dial_admission
                    .read()
                    .clone()
                    .unwrap_or_else(crate::runtime::capture_dial_admission);
                if let Ok(s) = admission
                    .scope(self.offer({
                        let prewarm = prewarm.clone();
                        move || prewarm()
                    }))
                    .await
                {
                    drop(s);
                }
            }
        }
    }

    pub(crate) fn set_dial_admission(&self, admission: crate::runtime::CapturedDialAdmission) {
        let mut current = self.dial_admission.write();
        if self.state() == PoolState::Running {
            *current = Some(admission);
        }
    }

    pub(crate) fn bind_current_dial_admission_if_unbound(&self) {
        let Some(admission) = crate::runtime::try_capture_dial_admission() else {
            return;
        };
        let mut current = self.dial_admission.write();
        if self.state() == PoolState::Running && current.is_none() {
            *current = Some(admission);
        }
    }

    /// Start the pool janitor (prune closed/expired, prewarm to the explicit
    /// or runtime-pinned floor) once; subsequent calls update the explicit
    /// floor without spawning another task. `prewarm` dials a fresh session
    /// only when the effective floor is not met.
    pub fn ensure_janitor<F, Fut>(
        self: &Arc<Self>,
        min_idle: usize,
        idle_timeout: Duration,
        prewarm: F,
    ) where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = anyhow::Result<Arc<S>>> + Send + 'static,
    {
        if self.state() != PoolState::Running {
            return;
        }
        self.bind_current_dial_admission_if_unbound();
        {
            let mut pool = self.pool.lock();
            if self.state() != PoolState::Running {
                return;
            }
            pool.base_min_idle = min_idle;
            if pool.janitor_running {
                return;
            }
            pool.janitor_running = true;
        }
        let pool = Arc::clone(self);
        let shutdown_rx = self.shutdown_tx.subscribe();
        let _ = self
            .task_scope
            .spawn(pool.run_janitor(idle_timeout, prewarm, shutdown_rx));
    }

    /// Retire the pool without cutting live streams. New offers, inserts,
    /// prewarms, and speculative checkouts fail immediately; pool-owned dials
    /// and provisional sessions are cancelled. Published sessions enter
    /// Draining and are closed individually once their last stream releases.
    pub fn retire(&self) {
        if self
            .state
            .compare_exchange(
                PoolState::Running as usize,
                PoolState::Draining as usize,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        self.dial_admission.write().take();
        let _ = self.shutdown_tx.send(true);
        // Dials and janitors observe this signal. A late dial verifies the
        // terminal state under the registration lock before publication.
        let (sessions, provisional) = {
            let mut pool = self.pool.lock();
            pool.dial_done = None;
            let sessions = pool.sessions.clone();
            let provisional = pool
                .provisional
                .drain()
                .filter_map(|(_, session)| session)
                .collect::<Vec<_>>();
            (sessions, provisional)
        };
        for session in provisional {
            session.close();
        }
        for session in &sessions {
            session.begin_drain();
        }

        let pool = Arc::clone(&self.pool);
        let state = Arc::clone(&self.state);
        let _ = self.task_scope.spawn(async move {
            loop {
                let (to_close, empty) = {
                    let mut pool = pool.lock();
                    let mut to_close = Vec::new();
                    pool.sessions.retain(|session| {
                        if session.is_closed() {
                            return false;
                        }
                        if session.active_streams() == 0 {
                            to_close.push(Arc::clone(session));
                            return false;
                        }
                        true
                    });
                    let empty = pool.sessions.is_empty()
                        && pool.provisional.is_empty()
                        && pool.dial_done.is_none();
                    (to_close, empty)
                };
                for session in to_close {
                    session.close();
                }
                if empty {
                    let _ = state.compare_exchange(
                        PoolState::Draining as usize,
                        PoolState::Closed as usize,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }

    /// Shut the pool down: reject offers/inserts/prewarms, abort the
    /// in-flight dial, wake every waiter with PoolClosed, close all
    /// sessions, and stop the janitor. Terminal and idempotent.
    pub fn shutdown(&self) {
        loop {
            let current = self.state();
            match current {
                PoolState::Closed | PoolState::ShuttingDown => return,
                PoolState::Running | PoolState::Draining => {
                    if self
                        .state
                        .compare_exchange(
                            current as usize,
                            PoolState::ShuttingDown as usize,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
            }
        }
        self.dial_admission.write().take();
        let _ = self.shutdown_tx.send(true);
        // Dials and janitors observe the terminal signal; terminal
        // registration checks close late dial results safely.
        let sessions: Vec<Arc<S>> = {
            let mut pool = self.pool.lock();
            pool.dial_done = None;
            let mut sessions = std::mem::take(&mut pool.sessions);
            sessions.extend(pool.provisional.drain().filter_map(|(_, session)| session));
            sessions
        };
        for s in sessions {
            s.close();
        }
        self.state
            .store(PoolState::Closed as usize, Ordering::Release);
    }
}
