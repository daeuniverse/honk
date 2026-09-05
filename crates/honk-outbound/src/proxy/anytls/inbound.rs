use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, mpsc};
use tokio::time::Instant;

use super::{AnyTlsSession, OVERFLOW_EMERGENCY_WAIT, OVERFLOW_STALL_GRACE, StreamEvent};

pub(super) struct BudgetWait(Arc<AnyTlsSession>);

impl BudgetWait {
    fn new(session: &Arc<AnyTlsSession>) -> Self {
        let previous = session.inbound_budget_epoch.fetch_add(1, Ordering::SeqCst);
        debug_assert_eq!(previous & 1, 0, "only one demux may wait per session");
        Self(Arc::clone(session))
    }
}

impl Drop for BudgetWait {
    fn drop(&mut self) {
        let previous = self.0.inbound_budget_epoch.fetch_add(1, Ordering::SeqCst);
        debug_assert_eq!(previous & 1, 1, "budget wait state must be active");
    }
}

pub(super) const INBOUND_PAYLOAD_BUDGET: usize = 12 * 1024 * 1024;

pub(super) struct InboundPayloadBudget {
    tcp_permits: Arc<Semaphore>,
    uot_permits: Arc<Semaphore>,
    sessions: Mutex<Vec<Weak<AnyTlsSession>>>,
}

impl std::fmt::Debug for InboundPayloadBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundPayloadBudget")
            .field("tcp_available", &self.tcp_permits.available_permits())
            .finish()
    }
}

impl InboundPayloadBudget {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            tcp_permits: Arc::new(Semaphore::new(limit)),
            uot_permits: Arc::new(Semaphore::new(limit)),
            sessions: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn register(&self, session: &Arc<AnyTlsSession>) {
        let mut sessions = self.sessions.lock();
        sessions.retain(|session| session.strong_count() != 0);
        sessions.push(Arc::downgrade(session));
    }

    pub(super) async fn acquire(
        &self,
        owner: &Arc<AnyTlsSession>,
        sid: u32,
        len: usize,
    ) -> Result<(Option<OwnedSemaphorePermit>, Option<BudgetWait>), tokio::sync::AcquireError> {
        let count = u32::try_from(len).expect("AnyTLS frame length fits u32");
        let permits = Arc::clone(&self.tcp_permits);
        if let Ok(permit) = Arc::clone(&permits).try_acquire_many_owned(count) {
            return Ok((Some(permit), None));
        }
        if permits.is_closed() {
            return permits
                .acquire_many_owned(count)
                .await
                .map(|permit| (Some(permit), None));
        }

        let waiting = BudgetWait::new(owner);
        let acquire = permits.acquire_many_owned(count);
        tokio::pin!(acquire);
        loop {
            tokio::select! {
                biased;
                result = &mut acquire => {
                    return result.map(|permit| (Some(permit), Some(waiting)));
                }
                _ = tokio::time::sleep(OVERFLOW_EMERGENCY_WAIT) => {
                    if !owner.tcp_sink_is_live(sid) {
                        return Ok((None, Some(waiting)));
                    }
                    self.reap_stalled();
                }
            }
        }
    }

    pub(super) fn try_acquire(&self, len: usize) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        Arc::clone(&self.uot_permits)
            .try_acquire_many_owned(u32::try_from(len).expect("AnyTLS frame length fits u32"))
    }

    #[cfg(test)]
    pub(super) fn available_permits(&self) -> usize {
        self.tcp_permits.available_permits()
    }

    fn reap_stalled(&self) {
        let sessions = {
            let mut registered = self.sessions.lock();
            let mut sessions = Vec::with_capacity(registered.len());
            registered.retain(|session| {
                if let Some(session) = session.upgrade() {
                    sessions.push(session);
                    true
                } else {
                    false
                }
            });
            sessions
        };
        let now = Instant::now();
        let victim = sessions
            .into_iter()
            .filter_map(|session| {
                session
                    .oldest_inbound_stall()
                    .map(|(since, sid)| (since, session.seq, sid, session))
            })
            .min_by_key(|(since, seq, sid, _)| (*since, *seq, *sid));
        if let Some((since, _, sid, session)) = victim
            && now.saturating_duration_since(since) >= OVERFLOW_STALL_GRACE
        {
            session.reap_inbound_stall(sid, now);
        }
    }
}

#[derive(Debug)]
struct RetentionState {
    bytes: usize,
    last_progress_at: Option<Instant>,
}

pub(super) struct TcpInbound {
    delivery: Mutex<()>,
    retention: Mutex<RetentionState>,
    receive: Weak<Mutex<TcpReceiveState>>,
}

impl TcpInbound {
    pub(super) fn new(receive: &Arc<Mutex<TcpReceiveState>>) -> Arc<Self> {
        Arc::new(Self {
            delivery: Mutex::new(()),
            retention: Mutex::new(RetentionState {
                bytes: 0,
                last_progress_at: None,
            }),
            receive: Arc::downgrade(receive),
        })
    }

    pub(super) fn delivery_guard(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.delivery.lock()
    }

    fn retain(&self, bytes: usize) {
        let mut state = self.retention.lock();
        if state.bytes == 0 {
            state.last_progress_at = Some(Instant::now());
        }
        state.bytes += bytes;
    }

    fn release(&self, bytes: usize) {
        let mut state = self.retention.lock();
        assert!(state.bytes >= bytes, "AnyTLS inbound retention underflow");
        state.bytes -= bytes;
        if state.bytes == 0 {
            state.last_progress_at = None;
        }
    }

    fn note_progress(&self) {
        let mut state = self.retention.lock();
        if state.bytes != 0 {
            state.last_progress_at = Some(Instant::now());
        }
    }

    pub(super) fn stalled_since(&self) -> Option<Instant> {
        let state = self.retention.lock();
        (state.bytes != 0)
            .then_some(state.last_progress_at)
            .flatten()
    }

    pub(super) fn reap_if_stalled<T>(
        &self,
        now: Instant,
        reap: impl FnOnce() -> T,
    ) -> Option<(Instant, usize, T)> {
        let receive = self.receive.upgrade()?;
        let mut receive = receive.lock();
        let (since, bytes) = {
            let state = self.retention.lock();
            (state.last_progress_at?, state.bytes)
        };
        if bytes == 0 || now.saturating_duration_since(since) < OVERFLOW_STALL_GRACE {
            return None;
        }
        let result = reap();
        receive.reset = true;
        receive.discard_payloads();
        Some((since, bytes, result))
    }
}

pub(super) struct TcpReceiveState {
    pub(super) rx: mpsc::Receiver<StreamEvent>,
    pub(super) read_buf: Option<InboundPayload>,
    pub(super) read_pos: usize,
    reset: bool,
}

impl TcpReceiveState {
    pub(super) fn new(rx: mpsc::Receiver<StreamEvent>) -> Self {
        Self {
            rx,
            read_buf: None,
            read_pos: 0,
            reset: false,
        }
    }
    pub(super) fn discard_payloads(&mut self) {
        self.rx.close();
        self.read_buf = None;
        self.read_pos = 0;
        while self.rx.try_recv().is_ok() {}
    }

    pub(super) fn was_reset(&self) -> bool {
        self.reset
    }
}

pub(super) struct InboundPayload {
    data: Vec<u8>,
    credit: Option<OwnedSemaphorePermit>,
    retention: Option<Arc<TcpInbound>>,
}

impl std::fmt::Debug for InboundPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundPayload")
            .field("len", &self.data.len())
            .finish()
    }
}

impl InboundPayload {
    pub(super) fn new(data: Vec<u8>, credit: OwnedSemaphorePermit) -> Self {
        debug_assert_eq!(data.len(), credit.num_permits());
        Self {
            data,
            credit: Some(credit),
            retention: None,
        }
    }

    pub(super) fn for_tcp(
        data: Vec<u8>,
        credit: OwnedSemaphorePermit,
        retention: Arc<TcpInbound>,
    ) -> Self {
        retention.retain(data.len());
        Self {
            data,
            credit: Some(credit),
            retention: Some(retention),
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(data: Vec<u8>) -> Self {
        let permits = Arc::new(Semaphore::new(data.len()));
        let credit = permits
            .try_acquire_many_owned(data.len() as u32)
            .expect("test payload budget");
        Self::new(data, credit)
    }

    pub(super) fn note_progress(&self) {
        if let Some(retention) = &self.retention {
            retention.note_progress();
        }
    }

    pub(super) fn delivery_owner(&self) -> Arc<TcpInbound> {
        self.retention
            .as_ref()
            .expect("TCP inbound payload owns delivery state")
            .clone()
    }

    pub(super) fn into_parts(mut self) -> (Vec<u8>, OwnedSemaphorePermit) {
        debug_assert!(self.retention.is_none());
        let data = std::mem::take(&mut self.data);
        let credit = self.credit.take().expect("inbound payload owns credit");
        (data, credit)
    }
}

impl Drop for InboundPayload {
    fn drop(&mut self) {
        if let Some(retention) = &self.retention {
            retention.release(self.data.len());
        }
    }
}

impl std::ops::Deref for InboundPayload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

#[cfg(test)]
impl PartialEq<Vec<u8>> for InboundPayload {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.data.as_slice() == other.as_slice()
    }
}
