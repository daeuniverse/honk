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
//! - dial circuit breaker: consecutive establishment failures back off
//!   exponentially before the pool dials again (a dead server must not
//!   eat a TCP connect per proxied flow);
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
    /// Cap for the dial-failure backoff. Must stay well below a flow's dial
    /// budget (`connect_timeout * 3`): a caller parked in a longer backoff
    /// window dies by its own outer timeout without ever attempting a dial,
    /// so a brief outage would keep failing flows long after the server
    /// recovers. Single-flight already paces concurrent dials; this only
    /// paces redials after a failure.
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
    dial_scope: RwLock<crate::runtime::CapturedDialScope>,
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
            dial_scope: RwLock::new(crate::runtime::capture_dial_admission()),
        }
    }

    fn state(&self) -> PoolState {
        PoolState::from(self.state.load(Ordering::Acquire))
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
                Backoff(Duration),
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
                    // The normal dial path is bounded by real sessions
                    // only: provisional slots are caller-owned speculative
                    // reservations that may never publish, and parked
                    // offers have no timeout of their own — counting them
                    // here let hung speculative work starve normal dials
                    // until the caller's outer deadline killed them without
                    // a dial ever being attempted.
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
                        candidate.map_or(Step::Backoff(wait), |session| {
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
                    tokio::select! {
                        _ = self.capacity_notify.notified() => {}
                        _ = shutdown_rx.changed() => {
                            return Err(Self::pool_closed_err());
                        }
                    }
                }
                Step::Backoff(wait) => {
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = shutdown_rx.changed() => {
                            return Err(Self::pool_closed_err());
                        }
                    }
                }
                Step::Wait(mut rx) => {
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
                        // A previous Register in this very call consumed
                        // the closure, and the freshly dialed session was
                        // dead on arrival (pruned before it could be
                        // offered) — fail instead of panic/re-dialing.
                        return Err(anyhow!("session established but immediately unusable"));
                    };
                    let task_pool = Arc::clone(&self.pool);
                    let task_state = Arc::clone(&self.state);
                    let config = self.config.clone();
                    let mut task_shutdown_rx = self.shutdown_tx.subscribe();
                    let dial_scope = crate::runtime::capture_dial_scope();
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
                                        pool.sessions.push(session);
                                        DialSignal::Done
                                    }
                                    Ok(Err(e)) => {
                                        pool.dial_failures += 1;
                                        let shift = pool.dial_failures.min(8) - 1;
                                        let backoff =
                                            (config.dial_backoff.saturating_mul(1u32 << shift))
                                                .min(config.max_dial_backoff);
                                        pool.next_dial_at = Some(Instant::now() + backoff);
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
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = shutdown_rx.changed() => return Err(Self::pool_closed_err()),
                    }
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
                let dial_scope = self.dial_scope.read().clone();
                if let Ok(s) = dial_scope
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

    pub(crate) fn set_dial_scope(&self, scope: crate::runtime::CapturedDialScope) {
        *self.dial_scope.write() = scope;
    }

    #[cfg(test)]
    pub(crate) fn dial_scope_matches(
        &self,
        registry: &crate::runtime::OutboundRuntimeRegistry,
    ) -> bool {
        self.dial_scope.read().matches_registry(registry)
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
        if let Some(scope) = crate::runtime::try_capture_dial_admission() {
            self.set_dial_scope(scope);
        }
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
mod tests {
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
        let fail = || async { anyhow::bail!("boom") };
        let start = Instant::now();
        assert!(pool.offer::<fn() -> _, _>(fail).await.is_err());
        assert_eq!(start.elapsed(), Duration::ZERO);
        // Second attempt waits out the backoff before re-dialing.
        assert!(pool.offer::<fn() -> _, _>(fail).await.is_err());
        assert!(start.elapsed() >= Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn dial_backoff_cap_keeps_redial_inside_flow_budget() {
        let pool = pool(SessionPoolConfig::default());
        let fail = || async { anyhow::bail!("boom") };
        // Enough consecutive failures to push the raw backoff far past the
        // cap; every further attempt must still redial within it.
        for _ in 0..8 {
            assert!(pool.offer::<fn() -> _, _>(fail).await.is_err());
        }
        let start = Instant::now();
        assert!(pool.offer::<fn() -> _, _>(fail).await.is_err());
        assert!(start.elapsed() <= Duration::from_secs(2));
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
                pool.set_dial_scope(crate::runtime::capture_dial_admission());
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
}
