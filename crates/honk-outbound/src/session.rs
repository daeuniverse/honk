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

mod maintenance;
mod speculative;

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

/// When a session last had no open stream. A session stamps it at the two
/// transitions the janitor cannot see from its tick — a permit taken, the
/// last permit released — so a stream that opened and closed between two
/// ticks still counts as activity.
#[derive(Debug)]
pub struct IdleClock {
    since: Mutex<Option<Instant>>,
}

impl Default for IdleClock {
    fn default() -> Self {
        Self::new()
    }
}

impl IdleClock {
    /// A fresh session is idle from now.
    pub fn new() -> Self {
        Self {
            since: Mutex::new(Some(Instant::now())),
        }
    }

    /// A stream slot was taken.
    pub fn stream_opened(&self) {
        *self.since.lock() = None;
    }

    /// A stream slot was released; `active_streams` is the count after the release.
    pub fn stream_released(&self, active_streams: usize) {
        if active_streams == 0 {
            *self.since.lock() = Some(Instant::now());
        }
    }

    /// `Some` while no stream is open: the instant the last one closed, or creation.
    pub fn idle_since(&self) -> Option<Instant> {
        *self.since.lock()
    }
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
            // An offer can wake without reserving, so one wake can strand a checkout.
            notify.notify_waiters();
        }
    }
}

/// What the pool needs to know about a session; everything else stays
/// with the protocol.
pub trait ManagedSession: Send + Sync {
    /// Currently open streams on this session.
    fn active_streams(&self) -> usize;
    /// Protocol-negotiated admission limit in addition to the configured soft cap.
    /// Existing streams may remain alive after the peer reduces this limit.
    fn has_capacity(&self) -> bool {
        true
    }
    /// Closed/broken sessions are pruned and never offered again.
    fn is_closed(&self) -> bool;
    /// Close the session (idle reap, pool shutdown).
    fn close(&self);
    /// Bind the owning pool before publication or provisional attachment.
    /// Autonomous close/drain transitions must wake this notification after
    /// publishing their state. Repeated binding must preserve the same owner.
    fn bind_capacity_notify(&self, _notify: Arc<Notify>) {}
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
    /// When the session last went to zero streams, or creation for a session
    /// that has never carried one; `None` while a stream is open. A session
    /// that keeps no [`IdleClock`] returns `None` and the janitor samples
    /// instead, which can miss a stream shorter than one tick.
    fn idle_since(&self) -> Option<Instant> {
        None
    }
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
    Failed(crate::SharedError),
}

struct ObservedSharedDialWait {
    observer: crate::runtime::flow_observation::FlowObserver,
    completion: tokio::sync::watch::Receiver<DialSignal>,
}

impl Drop for ObservedSharedDialWait {
    fn drop(&mut self) {
        let pending = self.completion.has_changed().is_ok()
            && matches!(*self.completion.borrow(), DialSignal::Pending);
        if pending {
            // Cancelling a waiter does not cancel the pool-owned physical dial.
            self.observer
                .publish(crate::runtime::flow_observation::FlowEvent::Gap(
                    crate::runtime::flow_observation::GapReason::SharedDialContinuesAfterWaiter,
                ));
        }
    }
}

pub(crate) struct ObservedSessionOpen {
    observer: Option<crate::runtime::flow_observation::FlowObserver>,
}

impl ObservedSessionOpen {
    pub(crate) fn start() -> Self {
        let observer = crate::runtime::flow_observation::current();
        if let Some(observer) = &observer {
            observer.publish(crate::runtime::flow_observation::FlowEvent::Session(
                crate::runtime::flow_observation::SessionEvent::OpenStarted,
            ));
        }
        Self { observer }
    }

    pub(crate) fn finish(mut self, event: crate::runtime::flow_observation::SessionEvent) {
        if let Some(observer) = self.observer.take() {
            observer.publish(crate::runtime::flow_observation::FlowEvent::Session(event));
        }
    }

    pub(crate) fn finish_open<T>(self, result: &Result<T, OpenError>) {
        use crate::runtime::flow_observation::SessionEvent;
        self.finish(match result {
            Ok(_) => SessionEvent::OpenSucceeded,
            Err(OpenError::Refused(_)) => SessionEvent::OpenRefused,
            Err(OpenError::Draining(_)) => SessionEvent::OpenDraining,
            Err(OpenError::Session(_)) => SessionEvent::OpenFailed,
        });
    }
}

impl Drop for ObservedSessionOpen {
    fn drop(&mut self) {
        if let Some(observer) = &self.observer {
            observer.publish(crate::runtime::flow_observation::FlowEvent::Session(
                crate::runtime::flow_observation::SessionEvent::OpenCancelled,
            ));
        }
    }
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

/// Caller-owned capacity reservation for one speculative physical dial.
/// Dropping it removes only its generation-safe slot and closes an attached
/// detached session, so cancellation cannot populate the pool.
pub struct DetachedSessionReservation<S: ManagedSession + 'static> {
    pool: Arc<SessionPool<S>>,
    slot_id: u64,
    active: bool,
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
    pub streams: usize,
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
    task_scope: crate::runtime::TaskScope,
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
            task_scope: crate::runtime::TaskScope::capture(),
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

    pub(crate) fn try_reserve(&self, session: &Arc<S>) -> Option<SessionPermit<S>> {
        session
            .try_reserve()
            .map(|permit| permit.with_capacity_notify(Arc::clone(&self.capacity_notify)))
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
                && session.has_capacity()
        })
    }

    /// Live (not closed) session count — the warm-resource gauge behind
    /// `/stats`.
    pub fn live_session_count(&self) -> usize {
        let mut pool = self.pool.lock();
        pool.sessions.retain(|session| !session.is_closed());
        pool.sessions.len()
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
            let capacity_changed = self.capacity_notify.notified();
            tokio::pin!(capacity_changed);
            capacity_changed.as_mut().enable();
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
                                && s.has_capacity()
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

            let mut dial_observer = None;
            let mut rx = match step {
                Step::Closed => return Err(Self::pool_closed_err()),
                Step::Have(s) => return Ok(s),
                Step::Capacity => {
                    tracing::debug!(
                        active_sessions = self.active_session_total(),
                        max = self.config.max_sessions,
                        "offer parked on pool capacity"
                    );
                    tokio::select! {
                        _ = &mut capacity_changed => {}
                        _ = shutdown_rx.changed() => {
                            return Err(Self::pool_closed_err());
                        }
                    }
                    continue;
                }
                Step::Backoff(wait, failures) => {
                    // The breaker only paces redials; callers fail fast
                    // instead of parking inside the window.
                    return Err(anyhow!(
                        "session dial backing off ({failures} consecutive, {wait:?} remaining)"
                    ));
                }
                Step::Wait(rx) => rx,
                Step::Register(id, done) => {
                    // Subscribe before spawning: a fast failure can clear the
                    // pool's entry before this caller gets to await it.
                    let rx = done.subscribe();
                    {
                        dial_observer = crate::runtime::flow_observation::current();
                    }
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
                    let capacity_notify = Arc::clone(&self.capacity_notify);
                    let config = self.config.clone();
                    let mut task_shutdown_rx = self.shutdown_tx.subscribe();
                    let dial_scope = self
                        .task_scope
                        .sync_scope(crate::runtime::capture_dial_scope);
                    tracing::debug!(id, "pool dial task spawned");
                    let _ = self.task_scope.spawn(dial_scope.scope(async move {
                        let mut guard = DialGuard {
                            pool: Arc::clone(&task_pool),
                            inflight_id: id,
                            armed: true,
                        };
                        // Subscription cannot replay a shutdown that preceded it.
                        let result = if PoolState::from(task_state.load(Ordering::Acquire))
                            != PoolState::Running
                        {
                            None
                        } else {
                            tokio::select! {
                                result = std::panic::AssertUnwindSafe(dial_fut).catch_unwind() => Some(result),
                                _ = task_shutdown_rx.changed() => None,
                            }
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
                                        session.bind_capacity_notify(Arc::clone(&capacity_notify));
                                        pool.sessions.push(session);
                                        DialSignal::Done
                                    }
                                    Ok(Err(e)) => {
                                        let backoff = if crate::proxy::is_packet_rejection(&e) {
                                            None
                                        } else {
                                            Some(Self::record_dial_failure(&mut pool, &config))
                                        };
                                        // The waiter only sees the outer context; keep
                                        // the full chain available for diagnostics.
                                        tracing::debug!(
                                            consecutive = pool.dial_failures,
                                            ?backoff,
                                            "session dial failed: {:#}",
                                            e
                                        );
                                        let context = backoff.map_or_else(
                                            || "session dial rejected".to_owned(),
                                            |backoff| {
                                                format!(
                                                    "session dial failed ({} consecutive, backoff {:?})",
                                                    pool.dial_failures, backoff
                                                )
                                            },
                                        );
                                        DialSignal::Failed(crate::SharedError::fanout(e.context(context)))
                                    }
                                    Err(_panic) => {
                                        // A dial must fail with an error, never panic.
                                        tracing::error!(id, "session dial panicked");
                                        pool.dial_failures += 1;
                                        pool.next_dial_at =
                                            Some(Instant::now() + config.dial_backoff);
                                        DialSignal::Failed(crate::SharedError::new(anyhow!(
                                            "session dial panicked (backoff {:?})",
                                            config.dial_backoff
                                        )))
                                    }
                                }
                            }
                        };
                        let _ = done.send(signal);
                        capacity_notify.notify_waiters();
                    }));
                    rx
                }
            };
            let _observation = dial_observer.map(|observer| ObservedSharedDialWait {
                observer,
                completion: rx.clone(),
            });
            tracing::debug!("offer parked on in-flight dial");
            let signal = tokio::select! {
                // `wait_for` checks the current value first — no
                // race with a dial that completed before parking.
                r = rx.wait_for(|s| !matches!(s, DialSignal::Pending)) => {
                    match r {
                        Ok(v) => v.clone(),
                        // The pool task dropped its sender: re-elect.
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
                    let error = anyhow::Error::new(e);
                    if self.config.spread_sessions
                        && !crate::proxy::is_packet_rejection(&error)
                        && self.has_usable_session()
                    {
                        continue;
                    }
                    return Err(error.context("session dial failed"));
                }
                DialSignal::Pending | DialSignal::Done => {}
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
        self.capacity_notify.notify_waiters();
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
            let Some(permit) = self.try_reserve(&session) else {
                if let Some(observer) = crate::runtime::flow_observation::current() {
                    observer.publish(crate::runtime::flow_observation::FlowEvent::Session(
                        crate::runtime::flow_observation::SessionEvent::OpenCapacity,
                    ));
                }
                if session.state() == SessionState::Closed {
                    self.invalidate(&session);
                }
                // Active means capacity raced us; Draining means GOAWAY or
                // protocol exhaustion raced us. Both retain live streams and
                // must stay tracked while the next attempt finds a carrier.
                last_err = Some(
                    anyhow::Error::new(crate::proxy::PacketRejection::Capacity)
                        .context("session has no stream capacity"),
                );
                continue;
            };
            // A shared session is already physically admitted; time the
            // logical open before protocol negotiation can block or cancel.
            // A cold offer has already fired this one-shot hook on admission.
            crate::runtime::start_scoped_dial();
            if let Some(observer) = crate::runtime::flow_observation::current() {
                observer.publish(
                    crate::runtime::flow_observation::FlowEvent::TransportAttached {
                        server_addr: None,
                        resolution_location:
                            crate::runtime::flow_observation::ResolutionLocation::Unknown,
                    },
                );
            }
            let observation = ObservedSessionOpen::start();
            let result = open(Arc::clone(&session), permit).await;
            observation.finish_open(&result);
            match result {
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

    /// Seed a session for tests that exercise the production pool paths.
    #[cfg(test)]
    pub fn insert(&self, session: &Arc<S>) {
        session.bind_capacity_notify(Arc::clone(&self.capacity_notify));
        self.pool.lock().sessions.push(Arc::clone(session));
        self.capacity_notify.notify_waiters();
    }

    /// Current metrics snapshot.
    #[cfg(test)]
    pub fn metrics(&self) -> PoolMetrics {
        let pool = self.pool.lock();
        PoolMetrics {
            sessions: pool.sessions.len(),
            streams: pool
                .sessions
                .iter()
                .map(|session| session.active_streams())
                .sum(),
        }
    }
}

#[cfg(test)]
mod tests;
