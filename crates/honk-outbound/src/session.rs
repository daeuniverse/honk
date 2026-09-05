//! Unified session pool for multiplexed outbounds (AnyTLS;
//! QUIC protocols keep their own single-connection holder —
//! see `quic::QuicClient`).
//!
//! Pool invariants:
//! - one node-owned pool with a hard reusable-session cap; draining sessions
//!   may overlap their replacements until existing channels finish;
//! - optional idle-first spreading, then least-loaded scheduling over `Active`
//!   sessions (Draining ones take no new channels);
//! - **pool-owned dial single-flight**: the first caller to find no
//!   in-flight dial registers it and the pool spawns the dial task — a
//!   cancelled caller only ends its own wait, never the shared dial
//!   (outcomes broadcast to every waiter);
//! - caller-owned speculative checkout: atomically reserve an existing stream
//!   permit or a provisional, cap-counted physical-dial slot that cancellation
//!   drops and only an explicit winner commit may publish; provisional slots
//!   bound speculative work only — normal offers are bounded by real sessions,
//!   so hung speculative dials can never starve them;
//! - dial circuit breaker: consecutive establishment failures (including
//!   dead-on-arrival sessions) pace redials with a capped backoff, and
//!   callers fail fast inside the window instead of parking — a dead server
//!   neither eats a TCP connect per proxied flow nor stalls flows until
//!   their outer dial deadline;
//! - RAII stream-slot permits (`SessionPermit`) as the single capacity
//!   truth, and [`SessionPool::open_with`] for atomic reserve+open;
//! - idle reaping, jittered max-age drains and optional prewarm
//!   (`min_idle`) via one janitor;
//! - generation retirement that rejects new work while live stream permits
//!   drain, distinct from process shutdown's immediate force-close;
//! - a metrics snapshot (sessions, streams, dial failures).
//!
//! What stays protocol-owned: session establishment, stream open,
//! framing, heartbeats. The pool only knows [`ManagedSession`].

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::Instant;

use anyhow::anyhow;
use futures_util::FutureExt;
use parking_lot::{Mutex, RwLock};

/// Pool sizing and lifecycle policy.
#[derive(Debug, Clone)]
pub struct SessionPoolConfig {
    /// Hard cap on reusable sessions and physical dials. Draining sessions
    /// with live channels may temporarily overlap their replacements.
    pub max_sessions: usize,
    /// Soft per-session stream cap: sessions at or above it are skipped
    /// by the scheduler (a new session is dialed instead).
    pub max_streams_per_session: usize,
    /// Prefer an idle session; while every usable session is busy, establish
    /// another one up to `max_sessions` before multiplexing more streams.
    pub spread_sessions: bool,
    /// Janitor tick (prune + prewarm cadence).
    pub janitor_interval: Duration,
    /// First dial-failure backoff; doubles per consecutive failure up to
    /// [`Self::max_dial_backoff`].
    pub dial_backoff: Duration,
    /// Cap for the dial-failure backoff. Callers fail fast inside the
    /// window, so this cap is the recovery latency after a failure: how soon
    /// the next arriving flow redials. Keep it small — single-flight already
    /// paces concurrent dials.
    pub max_dial_backoff: Duration,
    /// Max session age before it drains (no new streams; existing ones
    /// finish). Jittered ±10% per session to avoid reconnect storms.
    /// `None` = sessions never age out.
    pub max_session_age: Option<Duration>,
}

impl Default for SessionPoolConfig {
    fn default() -> Self {
        Self {
            max_sessions: 8,
            max_streams_per_session: 8,
            spread_sessions: false,
            janitor_interval: Duration::from_secs(30),
            dial_backoff: Duration::from_secs(1),
            max_dial_backoff: Duration::from_secs(2),
            max_session_age: None,
        }
    }
}

/// Lifecycle of an established session. `Connecting` is not here — it
/// lives in the pool's inflight dial; writer/demux failures go straight
/// to `Closed`; GOAWAY/max-age go through `Draining` (no new permits,
/// existing channels finish).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Draining,
    Closed,
}

/// RAII stream-slot reservation on one session — the single capacity
/// truth. Released on Drop (stream end, failed open, caller cancel).
pub struct SessionPermit<S: ManagedSession> {
    session: Arc<S>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    capacity_notify: Option<Arc<Notify>>,
}

impl<S: ManagedSession> SessionPermit<S> {
    pub fn new(session: Arc<S>, permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self {
            session,
            permit: Some(permit),
            capacity_notify: None,
        }
    }

    fn with_capacity_notify(mut self, notify: Arc<Notify>) -> Self {
        self.capacity_notify = Some(notify);
        self
    }
}

impl<S: ManagedSession> std::fmt::Debug for SessionPermit<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionPermit").finish_non_exhaustive()
    }
}

impl<S: ManagedSession> Drop for SessionPermit<S> {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.session.permit_released();
        if let Some(notify) = self.capacity_notify.take() {
            notify.notify_one();
        }
    }
}

/// What the pool needs to know about a session; everything else stays
/// with the protocol.
pub trait ManagedSession: Send + Sync {
    /// Currently open streams on this session.
    fn active_streams(&self) -> usize;
    /// Closed/broken sessions are pruned and never offered again.
    fn is_closed(&self) -> bool;
    /// Close the session (idle reap, pool shutdown).
    fn close(&self);
    /// Session state; `Draining` takes no new permits. Default derives
    /// from `is_closed` (legacy sessions without a real machine).
    fn state(&self) -> SessionState {
        if self.is_closed() {
            SessionState::Closed
        } else {
            SessionState::Active
        }
    }
    /// When the session was established (max-age drains; default `now`
    /// means "never ages out" for legacy sessions).
    fn created_at(&self) -> Instant {
        Instant::now()
    }
    /// Stop accepting new logical channels (GOAWAY, max-age); existing
    /// ones run to the end and the session closes at zero.
    fn begin_drain(&self) {}
    /// Observe release after the semaphore slot becomes available.
    fn permit_released(&self) {}
    /// Atomically reserve one stream slot: check `Active` → acquire →
    /// re-check `Active` (a session that began draining in between
    /// releases the permit immediately and reports `None`). Default `None`
    /// means "no capacity tracking" (legacy protocols not yet on
    /// [`SessionPool::open_with`]).
    fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>>
    where
        Self: Sized,
    {
        let _ = self;
        None
    }
}

/// Pool lifecycle. Retirement rejects new work while existing sessions drain;
/// shutdown force-closes everything. Both terminal paths wake waiters and stop
/// pool-owned dials and janitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolState {
    Running,
    Draining,
    ShuttingDown,
    Closed,
}

impl From<usize> for PoolState {
    fn from(v: usize) -> Self {
        match v {
            0 => PoolState::Running,
            1 => PoolState::Draining,
            2 => PoolState::ShuttingDown,
            _ => PoolState::Closed,
        }
    }
}

/// Signal broadcast when a pool-owned dial completes.
#[derive(Clone)]
enum DialSignal {
    /// Dial still in flight.
    Pending,
    /// The pool became terminal before the owned dial could publish.
    Closed,
    /// Dial completed — re-check the pool (session inserted or backoff
    /// recorded).
    Done,
    /// Dial failed — waiters surface the error themselves.
    Failed(Arc<anyhow::Error>),
}

/// How a protocol open failed, for the pool's retry decision.
pub enum OpenError {
    /// The session died mid-open: retire it; the pool may retry once on
    /// a fresh session (SYN/first frame was not committed yet — retrying
    /// cannot duplicate a request).
    Session(anyhow::Error),
    /// The target/protocol refused or auth failed: the session is
    /// healthy — surface immediately, never retry.
    Refused(anyhow::Error),
    /// The carrier stopped accepting new streams but existing streams remain
    /// valid. Drain it and retry on a fresh session without force-closing it.
    #[cfg_attr(not(feature = "rprx"), allow(dead_code))]
    Draining(anyhow::Error),
}

/// A speculative checkout atomically either reserves one stream on an
/// existing pooled session or owns one bounded, caller-cancellable dial slot.
pub enum SpeculativeCheckout<S: ManagedSession + 'static> {
    Shared {
        session: Arc<S>,
        permit: SessionPermit<S>,
    },
    Detached(DetachedSessionReservation<S>),
}

impl<S: ManagedSession + 'static> std::fmt::Debug for SpeculativeCheckout<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shared { .. } => f.debug_tuple("SpeculativeCheckout::Shared").finish(),
            Self::Detached(_) => f.debug_tuple("SpeculativeCheckout::Detached").finish(),
        }
    }
}

/// Caller-owned capacity reservation for one speculative physical dial.
/// Dropping it removes only its generation-safe slot and closes an attached
/// detached session, so cancellation cannot populate the pool.
pub struct DetachedSessionReservation<S: ManagedSession + 'static> {
    pool: Arc<SessionPool<S>>,
    slot_id: u64,
    active: bool,
}

impl<S: ManagedSession + 'static> std::fmt::Debug for DetachedSessionReservation<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachedSessionReservation")
            .field("slot_id", &self.slot_id)
            .finish_non_exhaustive()
    }
}

/// Pool state.
struct KeyPool<S> {
    sessions: Vec<Arc<S>>,
    /// Caller-owned speculative dial slots. The `Option` is filled after a
    /// detached dial succeeds so shutdown and Drop can synchronously close
    /// that otherwise-unpooled session.
    provisional: HashMap<u64, Option<Arc<S>>>,
    /// Next provisional slot generation.
    next_provisional_id: u64,
    /// While a dial is in flight this is `Some((inflight_id, sender))`;
    /// waiters `wait_for(!Pending)` on a receiver cloned under the lock
    /// (race-free — `watch::Receiver::wait_for` evaluates the predicate
    /// against the current value before parking). The inflight id lets a
    /// [`DialGuard`] clear only its own dial.
    dial_done: Option<(u64, tokio::sync::watch::Sender<DialSignal>)>,
    /// Next inflight-dial id.
    next_inflight_id: u64,
    /// Consecutive dial failures and when the next dial is allowed.
    dial_failures: u32,
    next_dial_at: Option<Instant>,
    /// Whether the pool janitor task is running.
    janitor_running: bool,
    /// Configured standby floor; zero lets unpinned idle sessions drain.
    base_min_idle: usize,
    /// Runtime retention owned by selector/UDP warm policies.
    warm_retained: bool,
}

impl<S> Default for KeyPool<S> {
    fn default() -> Self {
        Self {
            sessions: Vec::new(),
            provisional: HashMap::new(),
            next_provisional_id: 0,
            dial_done: None,
            next_inflight_id: 0,
            dial_failures: 0,
            next_dial_at: None,
            janitor_running: false,
            base_min_idle: 0,
            warm_retained: false,
        }
    }
}

/// RAII cleanup for the dial leader: if the leader's future is dropped
/// (caller cancellation or unwind) before completion, the inflight entry
/// is cleared — but only when it still matches this guard's id, so a
/// stale guard can never clear a later dial. Clearing drops the watch
/// sender, which closes the channel: waiters' `wait_for` errors and the
/// next caller re-elects a leader. A cancelled caller never touches the
/// failure count or backoff.
struct DialGuard<S> {
    pool: Arc<Mutex<KeyPool<S>>>,
    inflight_id: u64,
    armed: bool,
}

impl<S> Drop for DialGuard<S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut pool = self.pool.lock();
        if pool.dial_done.as_ref().map(|(id, _)| *id) == Some(self.inflight_id) {
            pool.dial_done = None;
        }
    }
}

/// Aggregate pool metrics used by behavioral tests.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct PoolMetrics {
    pub sessions: usize,
}

/// Generic node-owned session pool. One instance replaces each node's
/// bespoke/static manager.
pub struct SessionPool<S: ManagedSession + 'static> {
    config: SessionPoolConfig,
    pool: Arc<Mutex<KeyPool<S>>>,
    state: Arc<AtomicUsize>,
    shutdown_tx: Arc<tokio::sync::watch::Sender<bool>>,
    capacity_notify: Arc<Notify>,
    dial_admission: RwLock<Option<crate::runtime::CapturedDialAdmission>>,
}

impl<S: ManagedSession + 'static> std::fmt::Debug for SessionPool<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionPool")
            .field("state", &self.state())
            .field("sessions", &self.pool.lock().sessions.len())
            .finish_non_exhaustive()
    }
}

impl<S: ManagedSession + 'static> SessionPool<S> {
    pub fn new(config: SessionPoolConfig) -> Self {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        Self {
            config,
            pool: Arc::new(Mutex::new(KeyPool::default())),
            state: Arc::new(AtomicUsize::new(PoolState::Running as usize)),
            shutdown_tx: Arc::new(shutdown_tx),
            capacity_notify: Arc::new(Notify::new()),
            dial_admission: RwLock::new(None),
        }
    }

    fn state(&self) -> PoolState {
        PoolState::from(self.state.load(Ordering::Acquire))
    }

    fn active_session_total(&self) -> usize {
        self.pool
            .lock()
            .sessions
            .iter()
            .filter(|session| session.state() == SessionState::Active)
            .count()
    }

    /// Record one establishment failure and arm the redial backoff. A session
    /// that is dead on arrival (closed before it could serve a stream) also
    /// counts — treating it as success would reset the breaker and let the
    /// pool hot-spin against a server that kills every fresh session.
    fn record_dial_failure(pool: &mut KeyPool<S>, config: &SessionPoolConfig) -> Duration {
        pool.dial_failures += 1;
        let shift = pool.dial_failures.min(8) - 1;
        let backoff =
            (config.dial_backoff.saturating_mul(1u32 << shift)).min(config.max_dial_backoff);
        pool.next_dial_at = Some(Instant::now() + backoff);
        backoff
    }

    fn occupied_slots(pool: &KeyPool<S>) -> usize {
        pool.sessions
            .iter()
            .filter(|session| session.state() == SessionState::Active)
            .count()
            + pool.provisional.len()
    }

    #[cfg(test)]
    pub(crate) fn is_retired(&self) -> bool {
        self.state() != PoolState::Running
    }

    fn pool_closed_err() -> anyhow::Error {
        anyhow!("session pool is closed")
    }

    /// Whether the pool has a currently usable session. This uses the same
    /// active/capacity predicate as `offer`, without registering a dial.
    pub fn has_usable_session(&self) -> bool {
        if self.state() != PoolState::Running {
            return false;
        }
        let mut pool = self.pool.lock();
        if self.state() != PoolState::Running {
            return false;
        }
        pool.sessions.retain(|session| !session.is_closed());
        pool.sessions.iter().any(|session| {
            session.state() == SessionState::Active
                && session.active_streams() < self.config.max_streams_per_session
        })
    }

    /// Live (not closed) session count — the warm-resource gauge behind
    /// `/stats`.
    pub fn live_session_count(&self) -> usize {
        let mut pool = self.pool.lock();
        pool.sessions.retain(|session| !session.is_closed());
        pool.sessions.len()
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
            pool.warm_retained = retained;
            if retained {
                Vec::new()
            } else {
                pool.sessions.retain(|session| !session.is_closed());
                let mut active_kept = 0usize;
                let mut to_close = Vec::new();
                for session in &pool.sessions {
                    if session.state() == SessionState::Active && active_kept < pool.base_min_idle {
                        active_kept += 1;
                        continue;
                    }
                    session.begin_drain();
                    if session.active_streams() == 0 {
                        to_close.push(Arc::clone(session));
                    }
                }
                pool.sessions
                    .retain(|session| !to_close.iter().any(|closed| Arc::ptr_eq(closed, session)));
                to_close
            }
        };
        for session in to_close {
            session.close();
        }
    }

    #[cfg(test)]
    pub(crate) fn is_warm_retained(&self) -> bool {
        self.pool.lock().warm_retained
    }

    /// Offer a live session. Pools may fill idle physical-session capacity
    /// before least-loaded multiplexing; otherwise a new session is dialed
    /// only when none is usable. Concurrent callers share one pool-owned
    /// establishment, and dial failures back off for the pool.
    pub async fn offer<F, Fut>(&self, dial: F) -> anyhow::Result<Arc<S>>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<Arc<S>>> + Send + 'static,
    {
        let mut dial = Some(dial);
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        loop {
            if self.state() != PoolState::Running {
                return Err(Self::pool_closed_err());
            }
            // Phase 1: pick a live session, register the dial, or park on
            // the in-flight one.
            enum Step<S> {
                Closed,
                Have(Arc<S>),
                Register(u64, tokio::sync::watch::Sender<DialSignal>),
                Wait(tokio::sync::watch::Receiver<DialSignal>),
                Backoff(Duration, u32),
                Capacity,
            }
            let step = {
                let mut pool = self.pool.lock();
                if self.state() != PoolState::Running {
                    Step::Closed
                } else {
                    pool.sessions.retain(|s| !s.is_closed());
                    let candidate = pool
                        .sessions
                        .iter()
                        // Draining sessions take no new channels.
                        .filter(|s| {
                            s.state() == SessionState::Active
                                && s.active_streams() < self.config.max_streams_per_session
                        })
                        .min_by_key(|s| s.active_streams());
                    // Normal offers are bounded by real sessions only:
                    // provisional slots belong to caller-owned speculative
                    // dials that may never publish — counting them here once
                    // let hung speculative work park normal dials with no
                    // timeout of their own.
                    let occupied_slots = pool
                        .sessions
                        .iter()
                        .filter(|session| session.state() == SessionState::Active)
                        .count();
                    let should_spread = self.config.spread_sessions
                        && candidate.is_some_and(|session| session.active_streams() > 0)
                        && occupied_slots < self.config.max_sessions;
                    if !should_spread && let Some(candidate) = candidate {
                        Step::Have(Arc::clone(candidate))
                    } else if let Some((_, done)) = &pool.dial_done {
                        Step::Wait(done.subscribe())
                    } else if let Some(wait) = pool
                        .next_dial_at
                        .and_then(|t| t.checked_duration_since(Instant::now()))
                        .filter(|w| *w > Duration::ZERO)
                    {
                        candidate.map_or(Step::Backoff(wait, pool.dial_failures), |session| {
                            Step::Have(Arc::clone(session))
                        })
                    } else if occupied_slots >= self.config.max_sessions {
                        candidate.map_or(Step::Capacity, |session| Step::Have(Arc::clone(session)))
                    } else {
                        let id = pool.next_inflight_id;
                        pool.next_inflight_id += 1;
                        let (tx, _) = tokio::sync::watch::channel(DialSignal::Pending);
                        pool.dial_done = Some((id, tx.clone()));
                        Step::Register(id, tx)
                    }
                }
            };

            match step {
                Step::Closed => return Err(Self::pool_closed_err()),
                Step::Have(s) => return Ok(s),
                Step::Capacity => {
                    tracing::debug!(
                        active_sessions = self.active_session_total(),
                        max = self.config.max_sessions,
                        "offer parked on pool capacity"
                    );
                    tokio::select! {
                        _ = self.capacity_notify.notified() => {}
                        _ = shutdown_rx.changed() => {
                            return Err(Self::pool_closed_err());
                        }
                    }
                }
                Step::Backoff(wait, failures) => {
                    // The breaker only paces redials; callers fail fast
                    // instead of parking inside the window.
                    return Err(anyhow!(
                        "session dial backing off ({failures} consecutive, {wait:?} remaining)"
                    ));
                }
                Step::Wait(mut rx) => {
                    tracing::debug!("offer parked on in-flight dial");
                    let signal = tokio::select! {
                        // `wait_for` checks the current value first — no
                        // race with a dial that completed before parking.
                        r = rx.wait_for(|s| !matches!(s, DialSignal::Pending)) => {
                            match r {
                                Ok(v) => v.clone(),
                                // Sender dropped (leader cancelled): the
                                // inflight entry is gone — re-elect.
                                Err(_) => DialSignal::Done,
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            return Err(Self::pool_closed_err());
                        }
                    };
                    match signal {
                        DialSignal::Closed => return Err(Self::pool_closed_err()),
                        DialSignal::Failed(e) => {
                            if self.config.spread_sessions && self.has_usable_session() {
                                continue;
                            }
                            return Err(anyhow::anyhow!(e).context("session dial failed"));
                        }
                        DialSignal::Pending | DialSignal::Done => {}
                    }
                }
                Step::Register(id, done) => {
                    // Pool-owned dial task: no caller's cancellation can
                    // poison it; the DialGuard is the panic backstop.
                    let Some(dial_fut) = dial.take().map(|d| d()) else {
                        // The closure was consumed by this call's earlier
                        // Register, and the fresh session was pruned dead on
                        // arrival. This second registration spawns no task,
                        // so its inflight entry is a phantom nobody will ever
                        // signal: clear it (dropping the sender wakes waiters
                        // to re-elect) and count the dead session as a dial
                        // failure so the breaker paces redials.
                        let backoff = {
                            let mut pool = self.pool.lock();
                            if pool.dial_done.as_ref().map(|(i, _)| *i) == Some(id) {
                                pool.dial_done = None;
                            }
                            Self::record_dial_failure(&mut pool, &self.config)
                        };
                        return Err(anyhow!(
                            "session established but immediately unusable (backoff {backoff:?})"
                        ));
                    };
                    let task_pool = Arc::clone(&self.pool);
                    let task_state = Arc::clone(&self.state);
                    let config = self.config.clone();
                    let mut task_shutdown_rx = self.shutdown_tx.subscribe();
                    let dial_scope = crate::runtime::capture_dial_scope();
                    tracing::debug!(id, "pool dial task spawned");
                    tokio::spawn(dial_scope.scope(async move {
                        let mut guard = DialGuard {
                            pool: Arc::clone(&task_pool),
                            inflight_id: id,
                            armed: true,
                        };
                        let result = tokio::select! {
                            result = std::panic::AssertUnwindSafe(dial_fut).catch_unwind() => Some(result),
                            _ = task_shutdown_rx.changed() => None,
                        };
                        let signal = {
                            let mut pool = task_pool.lock();
                            if PoolState::from(task_state.load(Ordering::Acquire))
                                != PoolState::Running
                            {
                                if let Some(Ok(Ok(session))) = &result {
                                    // A completion that lost the terminal race is never
                                    // published: protocol-owned tasks may retain its Arc.
                                    session.close();
                                }
                                if pool.dial_done.as_ref().map(|(i, _)| *i) == Some(id) {
                                    pool.dial_done = None;
                                }
                                guard.armed = false;
                                DialSignal::Closed
                            } else {
                                if pool.dial_done.as_ref().map(|(i, _)| *i) == Some(id) {
                                    pool.dial_done = None;
                                }
                                guard.armed = false;
                                match result.expect("running pool cannot receive shutdown") {
                                    Ok(Ok(session)) => {
                                        pool.dial_failures = 0;
                                        pool.next_dial_at = None;
                                        tracing::debug!(id, "pool dial succeeded");
                                        pool.sessions.push(session);
                                        DialSignal::Done
                                    }
                                    Ok(Err(e)) => {
                                        let backoff =
                                            Self::record_dial_failure(&mut pool, &config);
                                        // The waiter only sees the outer context; keep
                                        // the full chain available for diagnostics.
                                        tracing::debug!(
                                            consecutive = pool.dial_failures,
                                            ?backoff,
                                            "session dial failed: {:#}",
                                            e
                                        );
                                        DialSignal::Failed(Arc::new(e.context(anyhow!(
                                            "session dial failed ({} consecutive, backoff {:?})",
                                            pool.dial_failures,
                                            backoff
                                        ))))
                                    }
                                    Err(_panic) => {
                                        pool.dial_failures += 1;
                                        pool.next_dial_at =
                                            Some(Instant::now() + config.dial_backoff);
                                        DialSignal::Failed(Arc::new(anyhow!(
                                            "session dial panicked (backoff {:?})",
                                            config.dial_backoff
                                        )))
                                    }
                                }
                            }
                        };
                        let _ = done.send(signal);
                    }));
                    // Fall through: wait on the dial like everyone else.
                }
            }
        }
    }

    /// Atomically reserve an existing stream slot, or reserve capacity for
    /// one caller-owned speculative physical dial. Unlike [`Self::offer`], a
    /// detached dial is never spawned by the pool: aborting its caller drops
    /// the reservation and therefore the dial/session with it.
    pub async fn checkout_speculative(self: &Arc<Self>) -> anyhow::Result<SpeculativeCheckout<S>> {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        loop {
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
                        session.try_reserve().map(|permit| {
                            (
                                session,
                                permit.with_capacity_notify(Arc::clone(&self.capacity_notify)),
                            )
                        })
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
                        _ = self.capacity_notify.notified() => {}
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
                            return Err(anyhow::anyhow!(error).context("session dial failed"));
                        }
                        DialSignal::Pending | DialSignal::Done => {}
                    }
                }
            }
        }
    }

    /// Drop a session from the pool and close it.
    pub fn invalidate(&self, session: &Arc<S>) {
        session.close();
        {
            let mut pool = self.pool.lock();
            pool.sessions.retain(|s| !Arc::ptr_eq(s, session));
        }
        self.capacity_notify.notify_one();
    }

    /// Open a logical channel on a pooled session: atomically reserve a
    /// stream slot on an Active session, then run the protocol open.
    /// Reserve and open never race the session cap — the permit is taken
    /// before the open starts. A session that dies mid-open is retired
    /// and the open retried once on a fresh session; protocol refusals
    /// and auth errors ([`OpenError::Refused`]) are returned as-is.
    pub async fn open_with<T, D, DFut, O, OFut>(&self, dial: D, open: O) -> anyhow::Result<T>
    where
        D: FnOnce() -> DFut + Clone + Send + 'static,
        DFut: Future<Output = anyhow::Result<Arc<S>>> + Send + 'static,
        O: Fn(Arc<S>, SessionPermit<S>) -> OFut,
        OFut: Future<Output = Result<T, OpenError>>,
    {
        let mut last_err: Option<anyhow::Error> = None;
        for _attempt in 0..2 {
            let session = self.offer(dial.clone()).await?;
            let Some(permit) = session.try_reserve() else {
                if session.state() == SessionState::Closed {
                    self.invalidate(&session);
                }
                // Active means capacity raced us; Draining means GOAWAY or
                // protocol exhaustion raced us. Both retain live streams and
                // must stay tracked while the next attempt finds a carrier.
                last_err = Some(anyhow!("session has no stream capacity"));
                continue;
            };
            let permit = permit.with_capacity_notify(Arc::clone(&self.capacity_notify));
            match open(Arc::clone(&session), permit).await {
                Ok(t) => return Ok(t),
                Err(OpenError::Refused(e)) => return Err(e),
                Err(OpenError::Draining(e)) => {
                    session.begin_drain();
                    last_err = Some(e);
                }
                Err(OpenError::Session(e)) => {
                    self.invalidate(&session);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.expect("open_with attempts always record an error"))
    }

    /// Insert an externally-established session (e.g. one built on a
    /// pooled TCP stream). The session is always tracked — even over the
    /// hard cap: an untracked session is orphaned from the janitor while
    /// its demux task holds it (and its TCP connection) open forever.
    /// Over-cap entries are transient; the janitor reaps them when idle.
    /// After shutdown the session is closed instead of inserted.
    #[cfg(test)]
    pub fn insert(&self, session: &Arc<S>) {
        if self.state() != PoolState::Running {
            session.close();
            return;
        }
        let mut pool = self.pool.lock();
        // Re-check under the registration lock: shutdown marks terminal
        // before draining the pool, so a late dial cannot repopulate it.
        if self.state() != PoolState::Running {
            drop(pool);
            session.close();
            return;
        }
        pool.sessions.retain(|s| !s.is_closed());
        pool.sessions.push(Arc::clone(session));
    }

    /// Current metrics snapshot.
    #[cfg(test)]
    pub fn metrics(&self) -> PoolMetrics {
        PoolMetrics {
            sessions: self.pool.lock().sessions.len(),
        }
    }

    async fn run_janitor<F, Fut>(
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
        // Per-session zero-stream streak start, keyed by Arc identity
        // (positions in the vec shift as sessions come and go).
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
            let idle_to_close = {
                let mut pool = self.pool.lock();
                if self.state() != PoolState::Running {
                    return;
                }
                pool.sessions.retain(|s| !s.is_closed());
                let live: Vec<Arc<S>> = pool.sessions.clone();
                let mut to_close = Vec::new();
                idle_since.retain(|ptr, _| live.iter().any(|s| Arc::as_ptr(s) as usize == *ptr));
                drain_at.retain(|ptr, _| live.iter().any(|s| Arc::as_ptr(s) as usize == *ptr));
                let min_idle = pool
                    .base_min_idle
                    .max(if pool.warm_retained { 1 } else { 0 });
                for s in &live {
                    let ptr = Arc::as_ptr(s) as usize;
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
                    if s.state() == SessionState::Draining && s.active_streams() == 0 {
                        to_close.push(Arc::clone(s));
                        continue;
                    }
                    if s.active_streams() > 0 {
                        idle_since.remove(&ptr);
                        continue;
                    }
                    let since = idle_since.entry(ptr).or_insert(now);
                    if now.duration_since(*since) >= idle_timeout
                        && live.len() - to_close.len() > min_idle
                    {
                        to_close.push(Arc::clone(s));
                    }
                }
                to_close
            };
            for s in &idle_to_close {
                self.invalidate(s);
            }
            // Prewarm to the explicit or runtime-pinned floor while the pool
            // remains live.
            let (current, min_idle) = {
                let pool = self.pool.lock();
                if self.state() != PoolState::Running {
                    return;
                }
                (
                    pool.sessions.len(),
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

    #[cfg(test)]
    pub(crate) fn dial_scope_matches(
        &self,
        registry: &crate::runtime::OutboundRuntimeRegistry,
    ) -> bool {
        self.dial_admission
            .read()
            .as_ref()
            .is_some_and(|admission| admission.matches_registry(registry))
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
        tokio::spawn(pool.run_janitor(idle_timeout, prewarm, shutdown_rx));
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
        tokio::spawn(async move {
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

    /// Attach a completed detached session so pool retirement/shutdown and reservation
    /// cancellation close it before it can escape as a pooled session.
    pub fn attach(&mut self, session: &Arc<S>) -> anyhow::Result<()> {
        let attached = {
            let mut pool = self.pool.pool.lock();
            if !self.active || self.pool.state() != PoolState::Running {
                false
            } else {
                pool.provisional.get_mut(&self.slot_id).is_some_and(|slot| {
                    if slot.is_some() {
                        false
                    } else {
                        *slot = Some(Arc::clone(session));
                        true
                    }
                })
            }
        };
        if attached {
            Ok(())
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
                    // Normal offers don't count provisional slots, so a commit
                    // can arrive after the pool filled up meanwhile. Admit the
                    // winner drain-only instead of exceeding max_sessions; its
                    // already-reserved streams are unaffected.
                    let active = pool
                        .sessions
                        .iter()
                        .filter(|s| s.state() == SessionState::Active)
                        .count();
                    if active >= self.pool.config.max_sessions {
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
        self.pool.capacity_notify.notify_one();
    }
}

#[cfg(test)]
mod tests;
