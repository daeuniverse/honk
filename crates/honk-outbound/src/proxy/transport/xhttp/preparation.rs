use std::{sync::Arc, time::Duration};

use futures_util::{StreamExt, stream::FuturesUnordered};
use parking_lot::Mutex;
use tokio::{net::TcpStream, sync::Notify};

use super::{MAX_CARRIERS, XhttpRuntime, XhttpSession, runtime::Phase};
use crate::runtime::NodeRuntime;
use crate::session::{
    DetachedSessionReservation, ManagedSession, SessionPermit, SessionState, SpeculativeCheckout,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum PhaseState {
    Open,
    Committed,
    Cancelled,
}

impl PhaseState {
    fn ensure_open(self) -> anyhow::Result<()> {
        anyhow::ensure!(self != Self::Cancelled, "XHTTP preparation cancelled");
        Ok(())
    }
}

struct State {
    phase: PhaseState,
    sessions: Vec<(Arc<XhttpSession>, DetachedSessionReservation<XhttpSession>)>,
}

/// One candidate's unpublished physical sessions. Shared sessions remain pool-owned.
pub(super) struct PreparationState {
    transport: Arc<XhttpRuntime>,
    state: Mutex<State>,
    changed: Notify,
}

impl PreparationState {
    pub(super) fn new(transport: Arc<XhttpRuntime>) -> Arc<Self> {
        Arc::new(Self {
            transport,
            state: Mutex::new(State {
                phase: PhaseState::Open,
                sessions: Vec::new(),
            }),
            changed: Notify::new(),
        })
    }

    async fn cancelled(&self) {
        loop {
            let changed = self.changed.notified();
            let lifecycle_changed = self.transport.lifecycle_changed.notified();
            tokio::pin!(changed, lifecycle_changed);
            changed.as_mut().enable();
            lifecycle_changed.as_mut().enable();
            {
                let lifecycle = self.transport.lifecycle.lock();
                let state = self.state.lock();
                if state.phase == PhaseState::Cancelled
                    || (lifecycle.is_retired() && state.phase != PhaseState::Committed)
                    || lifecycle.phase == Phase::ShuttingDown
                {
                    return;
                }
            }
            tokio::select! { _ = changed => {}, _ = lifecycle_changed => {} }
        }
    }

    async fn cancellation_error(&self) -> anyhow::Error {
        self.cancelled().await;
        anyhow::anyhow!("XHTTP preparation cancelled")
    }

    pub(super) async fn reserve(
        self: &Arc<Self>,
        runtime: &Arc<NodeRuntime>,
        tcp: Arc<Mutex<Option<TcpStream>>>,
        timeout: Duration,
    ) -> anyhow::Result<(Arc<XhttpSession>, SessionPermit<XhttpSession>)> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let (committed, sessions, closed) = {
                let lifecycle = self.transport.lifecycle.lock();
                let mut state = self.state.lock();
                state.phase.ensure_open()?;
                let committed = state.phase == PhaseState::Committed;
                if !committed {
                    anyhow::ensure!(!lifecycle.is_retired(), "XHTTP runtime retired");
                }
                let closed: Vec<_> = state
                    .sessions
                    .extract_if(.., |(session, _)| session.state() == SessionState::Closed)
                    .collect();
                let sessions: [Option<Arc<XhttpSession>>; MAX_CARRIERS] =
                    std::array::from_fn(|index| {
                        state
                            .sessions
                            .get(index)
                            .map(|(session, _)| session.clone())
                    });
                (committed, sessions, closed)
            };
            drop(closed);
            if committed {
                return self.transport.reserve_pooled(runtime, tcp, timeout).await;
            }
            // Poll all private capacity notifications before checking their reservations.
            // These sessions remain invisible to shared pool checkout until winner commit.
            let mut wakeups: FuturesUnordered<_> = sessions
                .iter()
                .flatten()
                .map(|session| session.progress.changed.notified())
                .collect();
            if !wakeups.is_empty() && futures_util::poll!(wakeups.next()).is_ready() {
                continue;
            }
            for session in sessions.iter().flatten() {
                if session.state() == SessionState::Active
                    && let Some(permit) = self.transport.pool.try_reserve(session)
                {
                    return Ok((session.clone(), permit));
                }
            }
            let checkout = tokio::select! {
                result = self.transport.pool.checkout_speculative() => result?,
                error = self.cancellation_error() => return Err(error),
                _ = &mut changed => continue,
                _ = wakeups.next(), if !wakeups.is_empty() => continue,
            };
            match checkout {
                SpeculativeCheckout::Shared { session, permit } => {
                    self.state.lock().phase.ensure_open()?;
                    return Ok((session, permit));
                }
                SpeculativeCheckout::Detached(mut reservation) => {
                    let session = tokio::select! {
                        result = XhttpRuntime::dial(runtime.clone(), tcp.clone(), timeout) => result?,
                        _ = reservation.cancelled() => anyhow::bail!("XHTTP pool retired during preparation"),
                        error = self.cancellation_error() => return Err(error),
                    };
                    let permit = reservation.attach(&session)?;
                    let lifecycle = self.transport.lifecycle.lock();
                    let mut state = self.state.lock();
                    state.phase.ensure_open()?;
                    if state.phase == PhaseState::Committed {
                        DetachedSessionReservation::commit_all(vec![reservation])?;
                    } else {
                        anyhow::ensure!(!lifecycle.is_retired(), "XHTTP runtime retired");
                        state.sessions.push((session.clone(), reservation));
                    }
                    self.changed.notify_waiters();
                    return Ok((session, permit));
                }
            }
        }
    }

    fn cancel(&self) {
        let sessions = {
            let mut state = self.state.lock();
            if state.phase != PhaseState::Open {
                return;
            }
            state.phase = PhaseState::Cancelled;
            std::mem::take(&mut state.sessions)
        };
        self.changed.notify_waiters();
        drop(sessions);
    }

    fn commit(&self) -> anyhow::Result<()> {
        // The lifecycle lock fences publication against retirement and shutdown.
        let lifecycle = self.transport.lifecycle.lock();
        let mut state = self.state.lock();
        state.phase.ensure_open()?;
        anyhow::ensure!(!lifecycle.is_retired(), "XHTTP runtime retired");
        if state.phase == PhaseState::Committed {
            return Ok(());
        }
        DetachedSessionReservation::commit_all(
            std::mem::take(&mut state.sessions)
                .into_iter()
                .map(|(_, reservation)| reservation)
                .collect(),
        )?;
        state.phase = PhaseState::Committed;
        self.changed.notify_waiters();
        Ok(())
    }
}

/// Winner-only publication guard. Dropping a loser closes only its private sessions.
pub(crate) struct XhttpPreparation {
    state: Arc<PreparationState>,
}

impl XhttpPreparation {
    pub(super) fn new(state: Arc<PreparationState>) -> Self {
        Self { state }
    }
    pub(crate) fn commit(self) -> anyhow::Result<()> {
        self.state.commit()
    }
}

impl Drop for XhttpPreparation {
    fn drop(&mut self) {
        self.state.cancel();
    }
}
