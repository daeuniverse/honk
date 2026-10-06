use super::super::h2_io::{DataProgress, FlushProgress};
use super::upload::UploadLane;
use super::{CONNECTION_WINDOW, MAX_REQUESTS, RECEIVE_WINDOW, STREAM_WRITE};
use crate::proxy::AsyncReadWrite;
use crate::session::{IdleClock, ManagedSession, OpenError, SessionPermit, SessionState};
use parking_lot::Mutex;
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    task::Poll,
};
use tokio::{
    sync::{Notify, Semaphore},
    time::Instant,
};
pub(super) type TrackedIo = super::super::h2_io::TrackedIo<IoProgress>;
pub(super) type QueuedData = super::super::h2_io::QueuedData<QueueProgress>;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum TerminalState {
    Active,
    Draining,
    Closed,
    CleanEnd,
}

impl TerminalState {
    fn from_raw(state: u8) -> Self {
        match state {
            0 => Self::Active,
            1 => Self::Draining,
            2 => Self::Closed,
            3 => Self::CleanEnd,
            _ => unreachable!("invalid carrier state"),
        }
    }
    fn session_state(self) -> SessionState {
        match self {
            Self::Active => SessionState::Active,
            Self::Draining => SessionState::Draining,
            Self::Closed | Self::CleanEnd => SessionState::Closed,
        }
    }
}

#[derive(Debug)]
pub(super) struct IoProgress {
    pub(super) flushed: AtomicBool,
    pub(super) changed: Notify,
}
impl Default for IoProgress {
    fn default() -> Self {
        Self {
            flushed: AtomicBool::new(false),
            changed: Notify::new(),
        }
    }
}
impl FlushProgress for IoProgress {
    fn writing(&self) {
        self.flushed.store(false, Ordering::Release);
    }
    fn flushed(&self) {
        self.flushed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

#[derive(Debug)]
pub(super) struct QueueProgress {
    pub(super) pending: Arc<AtomicUsize>,
    pub(super) io: Arc<IoProgress>,
}

impl DataProgress for QueueProgress {
    fn released(&self) {
        // DATA ownership can end before the encoded frame reaches physical I/O.
        self.io.writing();
        self.pending.fetch_sub(1, Ordering::AcqRel);
        self.io.changed.notify_waiters();
    }
}

pub(crate) struct XhttpSession {
    state: AtomicU8,
    created: Instant,
    idle: IdleClock,
    capacity: Arc<Semaphore>,
    peer_limit: AtomicUsize,
    capacity_notify: OnceLock<Arc<Notify>>,
    sender: Mutex<h2::client::SendRequest<QueuedData>>,
    driver: Mutex<Option<tokio::task::AbortHandle>>,
    failure: OnceLock<crate::SharedError>,
    pub(super) progress: Arc<IoProgress>,
}
impl std::fmt::Debug for XhttpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XhttpSession")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}
impl XhttpSession {
    fn terminal_state(&self) -> TerminalState {
        TerminalState::from_raw(self.state.load(Ordering::Acquire))
    }
    #[cfg(test)]
    pub(super) fn is_clean_end(&self) -> bool {
        self.terminal_state() == TerminalState::CleanEnd
    }
    pub(super) fn is_failed_terminal(&self) -> bool {
        self.terminal_state() == TerminalState::Closed
    }
    pub(super) fn admits_more(&self) -> bool {
        self.state() == SessionState::Active && self.has_capacity()
    }
    // A reservation already counts toward active_streams: equality is legal here,
    // whereas admitting another reservation requires strictly fewer active streams.
    pub(super) fn reservation_fits(&self, limit: usize) -> bool {
        self.active_streams() <= limit
    }
    pub(super) fn reserved_lane_usable(&self) -> bool {
        self.state() == SessionState::Active
            && self.reservation_fits(self.peer_limit.load(Ordering::Acquire))
    }
    pub(super) fn wake(&self) {
        self.progress.changed.notify_waiters();
        if let Some(notify) = self.capacity_notify.get() {
            notify.notify_waiters();
        }
    }
    pub(super) fn error(&self, error: h2::Error) -> io::Error {
        let kind = error
            .get_io()
            .map(io::Error::kind)
            .unwrap_or(io::ErrorKind::ConnectionReset);
        if error.is_io() || (error.is_go_away() && error.reason() != Some(h2::Reason::NO_ERROR)) {
            let failure = self.failure.get_or_init(|| {
                crate::SharedError::fanout(crate::proxy::NodeFailure(error.into()).into())
            });
            io::Error::new(kind, failure.clone())
        } else {
            io::Error::new(kind, error)
        }
    }
    pub(super) fn stopped(&self) -> io::Error {
        self.failure.get().map_or_else(
            || io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP carrier closed"),
            |error| io::Error::new(io::ErrorKind::ConnectionReset, error.clone()),
        )
    }
    pub(super) async fn request(
        self: Arc<Self>,
        permit: RequestOwner,
        request: &mut Option<http::Request<()>>,
        end: bool,
    ) -> Result<Request, OpenError> {
        if self.state() != SessionState::Active {
            return Err(OpenError::Draining(self.stopped().into()));
        }
        let mut sender = self.sender.lock().clone();
        if let Err(error) = poll_fn(|cx| sender.poll_ready(cx)).await {
            return Err(OpenError::Draining(self.error(error).into()));
        }
        if self.state() != SessionState::Active {
            return Err(OpenError::Draining(self.stopped().into()));
        }
        if !self.reservation_fits(sender.current_max_send_streams()) {
            return Err(OpenError::Draining(anyhow::Error::new(
                crate::proxy::PacketRejection::Capacity,
            )));
        }
        crate::runtime::start_scoped_dial();
        self.progress.flushed.store(false, Ordering::Release);
        // Once h2 accepts HEADERS we never authorize SessionPool to replay this request.
        let (response, send) = sender
            .send_request(
                request
                    .take()
                    .expect("request is consumed only once after admission"),
                end,
            )
            .map_err(|error| OpenError::Refused(self.error(error).into()))?;
        Ok(Request {
            response,
            send,
            permit,
            session: self,
        })
    }
}
impl ManagedSession for XhttpSession {
    fn active_streams(&self) -> usize {
        MAX_REQUESTS - self.capacity.available_permits()
    }
    fn has_capacity(&self) -> bool {
        self.active_streams() < self.peer_limit.load(Ordering::Acquire)
    }
    fn is_closed(&self) -> bool {
        self.state() == SessionState::Closed
    }
    fn state(&self) -> SessionState {
        self.terminal_state().session_state()
    }
    fn created_at(&self) -> Instant {
        self.created
    }
    fn idle_since(&self) -> Option<Instant> {
        self.idle.idle_since()
    }
    fn bind_capacity_notify(&self, notify: Arc<Notify>) {
        if let Err(notify) = self.capacity_notify.set(notify) {
            assert!(Arc::ptr_eq(self.capacity_notify.get().unwrap(), &notify));
        }
    }
    fn close(&self) {
        self.state
            .store(TerminalState::Closed as u8, Ordering::Release);
        self.capacity.close();
        if let Some(driver) = self.driver.lock().take() {
            driver.abort();
        }
        self.wake();
    }
    fn begin_drain(&self) {
        let _ = self.state.compare_exchange(
            TerminalState::Active as u8,
            TerminalState::Draining as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.wake();
        if self.active_streams() == 0 {
            self.close();
        }
    }
    fn permit_released(&self) {
        let active = self.active_streams();
        self.idle.stream_released(active);
        self.wake();
        if active == 0 && self.state() == SessionState::Draining {
            self.close();
        }
    }
    fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
        if !self.admits_more() {
            return None;
        }
        let permit = self.capacity.clone().try_acquire_owned().ok()?;
        self.idle.stream_opened();
        let permit = SessionPermit::new(self.clone(), permit);
        if !self.reserved_lane_usable() {
            return None;
        }
        Some(permit)
    }
}
impl Drop for XhttpSession {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.get_mut().take() {
            driver.abort();
        }
    }
}

pub(super) async fn connect(inner: Box<dyn AsyncReadWrite>) -> anyhow::Result<Arc<XhttpSession>> {
    let progress = Arc::new(IoProgress::default());
    let (sender, mut connection) = h2::client::Builder::new()
        .enable_push(false)
        .max_local_error_reset_streams(Some(0))
        .max_header_list_size(64 * 1024)
        .max_send_buffer_size(STREAM_WRITE)
        // Before SETTINGS, admit only one request so a GET cannot strand its upload.
        .initial_max_send_streams(1)
        .initial_window_size(RECEIVE_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .handshake(TrackedIo {
            inner,
            progress: progress.clone(),
        })
        .await?;
    let session = Arc::new(XhttpSession {
        state: AtomicU8::new(TerminalState::Active as u8),
        created: Instant::now(),
        idle: IdleClock::new(),
        capacity: Arc::new(Semaphore::new(MAX_REQUESTS)),
        peer_limit: AtomicUsize::new(1),
        capacity_notify: OnceLock::new(),
        sender: Mutex::new(sender),
        driver: Mutex::new(None),
        failure: OnceLock::new(),
        progress,
    });
    let weak = Arc::downgrade(&session);
    let driver = tokio::spawn(async move {
        let result = poll_fn(|cx| {
            let result = Pin::new(&mut connection).poll(cx);
            if let Some(session) = weak.upgrade() {
                let mut sender = session.sender.lock();
                let limit = sender.current_max_send_streams().min(MAX_REQUESTS);
                if session.peer_limit.swap(limit, Ordering::AcqRel) != limit {
                    session.wake();
                }
                if let Poll::Ready(Err(error)) = sender.poll_ready(cx)
                    && error.is_go_away()
                    && error.reason() == Some(h2::Reason::NO_ERROR)
                {
                    session.begin_drain();
                }
            }
            result
        })
        .await;
        if let Some(session) = weak.upgrade() {
            let terminal = match result {
                Err(error) => {
                    session.failure.get_or_init(|| {
                        crate::SharedError::fanout(crate::proxy::NodeFailure(error.into()).into())
                    });
                    TerminalState::Closed
                }
                Ok(()) => TerminalState::CleanEnd,
            };
            // An explicit pool close wins over a concurrent successful driver end.
            let _ = session
                .state
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                    matches!(
                        TerminalState::from_raw(state),
                        TerminalState::Active | TerminalState::Draining
                    )
                    .then_some(terminal as u8)
                });
            session.capacity.close();
            session.wake();
        }
    });
    *session.driver.lock() = Some(driver.abort_handle());
    Ok(session)
}
pub(super) enum RequestOwner {
    Pool {
        _permit: SessionPermit<XhttpSession>,
    },
    Lane {
        _lane: Arc<UploadLane>,
        _use: tokio::sync::OwnedSemaphorePermit,
    },
}

pub(super) struct Request {
    pub(super) response: h2::client::ResponseFuture,
    pub(super) send: h2::SendStream<QueuedData>,
    pub(super) permit: RequestOwner,
    pub(super) session: Arc<XhttpSession>,
}
