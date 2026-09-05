//! Pool-wide payload ownership, frame demultiplexing, and TCP stream reads.

use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, mpsc};
use tokio::time::Instant;
use tracing::{debug, warn};

use super::{
    AnyTlsSession, AnyTlsStream, BoxedReader, CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST,
    CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS, CMD_SETTINGS, CMD_SYN, CMD_SYNACK,
    CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, MAX_STREAM_ERROR_SOURCE_BYTES, OVERFLOW_EMERGENCY_WAIT,
    OVERFLOW_STALL_GRACE, StreamEvent, StreamSink, drain_frame_body, read_frame_body,
    read_frame_header, server_synack_setting,
};

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
async fn complete_frame_body<T>(
    budget_waited: bool,
    body: impl Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    if !budget_waited {
        return body.await;
    }
    tokio::time::timeout(OVERFLOW_STALL_GRACE, body)
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "AnyTLS frame body stalled after inbound budget wait",
            )
        })?
}

pub(super) async fn session_demux(session: Arc<AnyTlsSession>, mut read: BoxedReader) {
    let mut fail_reason: Option<anyhow::Error> = None;
    loop {
        let (cmd, sid, payload_len) = match read_frame_header(&mut read).await {
            Ok(header) => header,
            Err(e) => {
                debug!("AnyTLS session {} demux read failed: {}", session.seq, e);
                fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                break;
            }
        };

        if cmd == CMD_PSH && payload_len != 0 {
            let sink = session.streams.lock().unwrap().get(&sid).cloned();
            match sink {
                Some(StreamSink::Tcp(_)) => {
                    let inbound = session.tcp_inbound.lock().get(&sid).cloned();
                    let Some(inbound) = inbound else {
                        session.end_stream(sid, false);
                        if let Err(e) = drain_frame_body(&mut read, payload_len).await {
                            fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                            break;
                        }
                        session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let (credit, budget_wait) = match session
                        .inbound_payload_budget
                        .acquire(&session, sid, payload_len)
                        .await
                    {
                        Ok(result) => result,
                        Err(e) => {
                            fail_reason =
                                Some(anyhow::anyhow!("inbound payload budget closed: {e}"));
                            break;
                        }
                    };
                    let Some(credit) = credit else {
                        session.end_stream(sid, false);
                        if let Err(e) = complete_frame_body(
                            budget_wait.is_some(),
                            drain_frame_body(&mut read, payload_len),
                        )
                        .await
                        {
                            fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                            break;
                        }
                        session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
                        drop(budget_wait);
                        continue;
                    };
                    if !session.tcp_sink_is_live(sid) {
                        drop(credit);
                        session.end_stream(sid, false);
                        if let Err(e) = complete_frame_body(
                            budget_wait.is_some(),
                            drain_frame_body(&mut read, payload_len),
                        )
                        .await
                        {
                            fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                            break;
                        }
                        session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
                        drop(budget_wait);
                        continue;
                    }
                    let data = match complete_frame_body(
                        budget_wait.is_some(),
                        read_frame_body(&mut read, payload_len),
                    )
                    .await
                    {
                        Ok(data) => data,
                        Err(e) => {
                            fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                            break;
                        }
                    };
                    session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
                    drop(budget_wait);
                    session
                        .dispatch_payload(sid, InboundPayload::for_tcp(data, credit, inbound))
                        .await;
                }
                Some(StreamSink::Uot(tx)) => {
                    let queue = match tx.try_reserve_owned() {
                        Ok(queue) => queue,
                        Err(_) => {
                            session.end_uot_stream(sid, true);
                            if let Err(e) = drain_frame_body(&mut read, payload_len).await {
                                fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                                break;
                            }
                            session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    let credit = match session.inbound_payload_budget.try_acquire(payload_len) {
                        Ok(credit) => credit,
                        Err(_) => {
                            drop(queue);
                            session.end_uot_stream(sid, true);
                            if let Err(e) = drain_frame_body(&mut read, payload_len).await {
                                fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                                break;
                            }
                            session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    let live = matches!(
                        session.streams.lock().unwrap().get(&sid),
                        Some(StreamSink::Uot(tx)) if !tx.is_closed()
                    );
                    if !live {
                        drop(queue);
                        drop(credit);
                        session.end_uot_stream(sid, true);
                        if let Err(e) = drain_frame_body(&mut read, payload_len).await {
                            fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                            break;
                        }
                        session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let data = match read_frame_body(&mut read, payload_len).await {
                        Ok(data) => data,
                        Err(e) => {
                            fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                            break;
                        }
                    };
                    session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
                    queue.send(StreamEvent::Data(InboundPayload::new(data, credit)));
                }
                None => {
                    debug!(
                        "AnyTLS session {} PSH for unknown sid={} ({} bytes)",
                        session.seq, sid, payload_len
                    );
                    if let Err(e) = drain_frame_body(&mut read, payload_len).await {
                        fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                        break;
                    }
                    session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
                }
            }
            continue;
        }

        let retain_body = matches!(
            cmd,
            CMD_SYNACK | CMD_ALERT | CMD_SERVER_SETTINGS | CMD_UPDATE_PADDING_SCHEME
        );
        let data = if retain_body {
            match read_frame_body(&mut read, payload_len).await {
                Ok(data) => data,
                Err(e) => {
                    fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                    break;
                }
            }
        } else {
            if let Err(e) = drain_frame_body(&mut read, payload_len).await {
                fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                break;
            }
            Vec::new()
        };

        session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
        match cmd {
            CMD_FIN => session.dispatch_fin(sid).await,
            CMD_SYNACK => {
                session.settle_syn_pending(sid);
                if !data.is_empty() {
                    let shown = &data[..data.len().min(MAX_STREAM_ERROR_SOURCE_BYTES)];
                    let suffix = if shown.len() == data.len() {
                        ""
                    } else {
                        " [truncated]"
                    };
                    let message: Arc<str> = Arc::from(format!(
                        "target refused: {}{suffix}",
                        String::from_utf8_lossy(shown)
                    ));
                    debug!(
                        "AnyTLS session {} sid={} remote dial error: {}",
                        session.seq, sid, message
                    );
                    session.dispatch_error(sid, message).await;
                }
            }
            CMD_HEART_REQUEST => {
                if session
                    .enqueue_control(CMD_HEART_RESPONSE, sid, bytes::Bytes::new())
                    .is_err()
                {
                    break;
                }
            }
            CMD_ALERT if !data.is_empty() => {
                warn!(
                    "AnyTLS session {} alert from server: {}",
                    session.seq,
                    String::from_utf8_lossy(&data)
                );
                break;
            }
            CMD_SERVER_SETTINGS => {
                if let Some(supports_synack) = server_synack_setting(&data) {
                    session
                        .peer_supports_synack
                        .store(supports_synack, Ordering::Release);
                }
            }
            CMD_UPDATE_PADDING_SCHEME if !data.is_empty() => {
                if session.padding_state.update(&data) {
                    debug!(
                        session = session.seq,
                        md5 = %session.padding_state.snapshot().md5,
                        "AnyTLS padding scheme updated"
                    );
                } else {
                    warn!(
                        session = session.seq,
                        "AnyTLS server sent an invalid padding scheme"
                    );
                }
            }
            CMD_WASTE
            | CMD_SETTINGS
            | CMD_HEART_RESPONSE
            | CMD_SYN
            | CMD_PSH
            | CMD_ALERT
            | CMD_UPDATE_PADDING_SCHEME => {}
            other => {
                debug!(
                    "AnyTLS session {} ignoring unknown cmd {}",
                    session.seq, other
                );
            }
        }
    }
    match fail_reason {
        Some(e) => session.fail(e),
        None => session.close(),
    }
}
impl tokio::io::AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.read_eof {
            return std::task::Poll::Ready(Ok(()));
        }
        if let Some(e) = this.read_err.take() {
            this.read_eof = true;
            return std::task::Poll::Ready(Err(e));
        }

        let mut receive = this.receive.lock();
        let mut got_any = receive
            .read_buf
            .as_ref()
            .is_some_and(|data| receive.read_pos < data.len());
        loop {
            let n = receive.read_buf.as_ref().map_or(0, |data| {
                (data.len() - receive.read_pos).min(out.remaining())
            });
            if n > 0 {
                let data = receive.read_buf.as_ref().expect("read payload present");
                out.put_slice(&data[receive.read_pos..receive.read_pos + n]);
                data.note_progress();
                receive.read_pos += n;
            }
            if receive
                .read_buf
                .as_ref()
                .is_some_and(|data| receive.read_pos == data.len())
            {
                receive.read_buf = None;
                receive.read_pos = 0;
            }
            if out.remaining() == 0 {
                return std::task::Poll::Ready(Ok(()));
            }

            let next = if got_any {
                match receive.rx.try_recv() {
                    Ok(ev) => std::task::Poll::Ready(Some(ev)),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => std::task::Poll::Pending,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        std::task::Poll::Ready(None)
                    }
                }
            } else {
                receive.rx.poll_recv(cx)
            };

            if matches!(next, std::task::Poll::Ready(Some(_))) {
                this.session.flush_overflow(this.sid);
            }
            match next {
                std::task::Poll::Ready(Some(StreamEvent::Data(data))) => {
                    receive.read_buf = Some(data);
                    got_any = true;
                }
                std::task::Poll::Ready(Some(StreamEvent::Error(e))) => {
                    receive.discard_payloads();
                    let killed = this.session.end_stream(this.sid, true);
                    let err = if killed {
                        std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "stream killed: slow consumer (HOL)",
                        )
                    } else {
                        std::io::Error::new(std::io::ErrorKind::ConnectionReset, e.to_string())
                    };

                    if got_any {
                        this.read_err = Some(err);
                        return std::task::Poll::Ready(Ok(()));
                    }
                    this.read_eof = true;
                    this._permit.take();
                    return std::task::Poll::Ready(Err(err));
                }
                std::task::Poll::Ready(Some(StreamEvent::Fin)) => {
                    receive.discard_payloads();
                    let killed = this.session.end_stream(this.sid, false);
                    if killed {
                        let err = std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "stream killed: slow consumer (HOL)",
                        );
                        if got_any {
                            this.read_err = Some(err);
                            return std::task::Poll::Ready(Ok(()));
                        }
                        this.read_eof = true;
                        this._permit.take();
                        return std::task::Poll::Ready(Err(err));
                    }
                    this.read_eof = true;
                    this._permit.take();
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(None) => {
                    receive.discard_payloads();
                    let killed = this.session.end_stream(this.sid, false);
                    let pending: Option<std::io::Error> =
                        if let Some(e) = this.session.terminal_error.get() {
                            Some(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                e.to_string(),
                            ))
                        } else if killed || receive.was_reset() {
                            Some(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "stream reset: inbound payload budget",
                            ))
                        } else {
                            None
                        };
                    if let Some(err) = pending {
                        if got_any {
                            this.read_err = Some(err);
                            return std::task::Poll::Ready(Ok(()));
                        }
                        this.read_eof = true;
                        this._permit.take();
                        return std::task::Poll::Ready(Err(err));
                    }
                    this.read_eof = true;
                    this._permit.take();
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Pending => {
                    return if got_any {
                        std::task::Poll::Ready(Ok(()))
                    } else {
                        std::task::Poll::Pending
                    };
                }
            }
        }
    }
}
