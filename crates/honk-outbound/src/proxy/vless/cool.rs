#![cfg_attr(all(test, not(feature = "rprx")), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::proxy::{AsyncReadWrite, MuxSession, PacketTransport};
use crate::session::{
    IdleClock, ManagedSession, OpenError, SessionPermit, SessionPool, SessionPoolConfig,
    SessionState,
};

mod child;
mod codec;

#[cfg(test)]
use child::StreamOperation;
pub use child::VlessXudpTransport;
#[cfg(any(feature = "rprx", test))]
pub(crate) use child::connect_single_xudp;
pub(crate) use child::open_xudp;
use child::{VlessCoolStream, open_tcp};
use codec::{
    IncomingFrame, OPTION_ERROR, STATUS_END, STATUS_KEEP, STATUS_KEEPALIVE, STATUS_NEW, end_frame,
    parse_keep_peer, read_frame,
};
#[cfg(test)]
use codec::{NETWORK_UDP, OPTION_DATA, base_metadata, encode_address, metadata_frame, udp_frame};

pub(crate) const VLESS_MUX_COMMAND: u8 = 0x03;
pub(crate) const MAX_STREAMS_PER_SESSION: usize = 128;
pub(crate) const MAX_SINGLE_XUDP_PACKET_SIZE: usize = 7526;
pub(crate) const MAX_MUX_XUDP_PACKET_SIZE: usize = 8 * 1024;

const MAX_TCP_CHUNK: usize = 8 * 1024;
const MAX_METADATA: usize = 512;
const WRITER_QUEUE_CAPACITY: usize = 64;
const TCP_QUEUE_CAPACITY: usize = 1024;
const UDP_QUEUE_CAPACITY: usize = 64;
const WRITER_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const RECEIVE_BYTE_BUDGET: usize = 8 * 1024 * 1024;
// A line-rate burst can fill the budget before its reader task is first scheduled.
const RECEIVE_BACKPRESSURE_WAIT: std::time::Duration = std::time::Duration::from_millis(100);
const READER_YIELD_INTERVAL: usize = 16;

pub(crate) type VlessCoolPool = SessionPool<VlessCoolSession>;

pub(crate) fn session_pool_config(max_streams_per_session: usize) -> SessionPoolConfig {
    SessionPoolConfig {
        // Node-local rollover stays adaptive; the startup lifetime gate bounds carriers globally.
        max_sessions: usize::MAX,
        max_streams_per_session,
        spread_sessions: false,
        max_session_age: None,
        ..SessionPoolConfig::default()
    }
}

#[derive(Clone, Debug)]
enum FailureCause {
    Message(Arc<str>),
    Shared(crate::SharedError),
    SourcePostAdmissionCancellation,
}

#[derive(Clone, Debug)]
struct Failure {
    kind: io::ErrorKind,
    cause: FailureCause,
}

#[derive(Debug)]
struct SourcePostAdmissionCancellation;

impl std::fmt::Display for SourcePostAdmissionCancellation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mux.Cool UDP send was cancelled after queue admission")
    }
}

impl std::error::Error for SourcePostAdmissionCancellation {}

pub fn is_vless_source_post_admission_cancel(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<SourcePostAdmissionCancellation>())
}

impl Failure {
    fn new(kind: io::ErrorKind, message: impl Into<Arc<str>>) -> Self {
        Self {
            kind,
            cause: FailureCause::Message(message.into()),
        }
    }

    fn source_post_admission_cancel() -> Self {
        Self {
            kind: io::ErrorKind::ConnectionAborted,
            cause: FailureCause::SourcePostAdmissionCancellation,
        }
    }

    fn from_io(error: io::Error, context: &'static str) -> Self {
        Self {
            kind: error.kind(),
            cause: FailureCause::Shared(crate::SharedError::fanout(
                crate::proxy::NodeFailure(anyhow::Error::new(error).context(context)).into(),
            )),
        }
    }

    fn io(&self) -> io::Error {
        match &self.cause {
            FailureCause::Message(message) => io::Error::new(self.kind, message.to_string()),
            FailureCause::Shared(error) => io::Error::new(self.kind, error.clone()),
            FailureCause::SourcePostAdmissionCancellation => {
                io::Error::new(self.kind, SourcePostAdmissionCancellation)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct FrameSendFailure {
    failure: Failure,
    committed: bool,
}

struct WriterCommand {
    frame: Bytes,
    flush: bool,
    done: oneshot::Sender<Result<(), FrameSendFailure>>,
}

#[derive(Clone)]
struct CarrierWriter {
    tx: mpsc::Sender<WriterCommand>,
    failure: Arc<OnceLock<Failure>>,
}

impl CarrierWriter {
    fn closed_failure(&self, message: &'static str) -> Failure {
        self.failure
            .get()
            .cloned()
            .unwrap_or_else(|| Failure::new(io::ErrorKind::BrokenPipe, message))
    }

    async fn send(&self, frame: Bytes, flush: bool) -> Result<(), FrameSendFailure> {
        self.send_inner(frame, flush, None, || {}).await
    }

    /// Run the binding update only after queue capacity is owned, with no await
    /// between that update, the admission marker, and command publication.
    async fn send_with_admission<F>(
        &self,
        frame: Bytes,
        flush: bool,
        admitted: &AtomicBool,
        before_publish: F,
    ) -> Result<(), FrameSendFailure>
    where
        F: FnOnce() + Send,
    {
        self.send_inner(frame, flush, Some(admitted), before_publish)
            .await
    }

    async fn send_inner<F>(
        &self,
        frame: Bytes,
        flush: bool,
        admitted: Option<&AtomicBool>,
        before_publish: F,
    ) -> Result<(), FrameSendFailure>
    where
        F: FnOnce() + Send,
    {
        let (done, wait) = oneshot::channel();
        let permit = self.tx.reserve().await.map_err(|_| FrameSendFailure {
            failure: self.closed_failure("Mux.Cool carrier writer closed"),
            committed: false,
        })?;
        before_publish();
        if let Some(admitted) = admitted {
            admitted.store(true, Ordering::Release);
        }
        permit.send(WriterCommand { frame, flush, done });
        wait.await.unwrap_or_else(|_| {
            Err(FrameSendFailure {
                failure: self
                    .closed_failure("Mux.Cool carrier writer stopped before acknowledgement"),
                committed: true,
            })
        })
    }

    async fn flush(&self) -> io::Result<()> {
        self.send(Bytes::new(), true)
            .await
            .map_err(|error| error.failure.io())
    }
}

struct QueuedPayload {
    payload: Bytes,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

struct Datagram {
    payload: Bytes,
    peer: SocketAddr,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
#[derive(Clone)]
struct UdpDestination {
    peer: SocketAddr,
    target_domain: Option<Arc<str>>,
}

enum ChildSink {
    Tcp {
        tx: mpsc::Sender<QueuedPayload>,
        failure: Arc<Mutex<Option<Failure>>>,
        ended: Arc<AtomicBool>,
    },
    Udp {
        tx: mpsc::Sender<Datagram>,
        failure: Arc<Mutex<Option<Failure>>>,
        ended: Arc<AtomicBool>,
        destination: Arc<Mutex<Option<UdpDestination>>>,
    },
}

impl ChildSink {
    fn set_failure(&self, failure: Failure) {
        let state = match self {
            Self::Tcp { failure: state, .. } | Self::Udp { failure: state, .. } => state,
        };
        *state.lock() = Some(failure);
    }

    fn set_ended(&self) {
        let ended = match self {
            Self::Tcp { ended, .. } | Self::Udp { ended, .. } => ended,
        };
        ended.store(true, Ordering::Release);
    }
}

pub struct VlessCoolSession {
    state: AtomicU8,
    created_at: Instant,
    /// Idle bookkeeping for the pool janitor, stamped at stream open and close.
    idle: IdleClock,
    capacity: Arc<tokio::sync::Semaphore>,
    capacity_notify: std::sync::OnceLock<Arc<tokio::sync::Notify>>,
    active_limit: usize,
    receive_budget: Arc<tokio::sync::Semaphore>,
    next_id: AtomicU16,
    zero_id_issued: AtomicBool,
    writer: CarrierWriter,
    children: Mutex<HashMap<u16, ChildSink>>,
    ending_ids: Mutex<HashSet<u16>>,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
    task_scope: crate::runtime::TaskScope,
}

impl std::fmt::Debug for VlessCoolSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessCoolSession")
            .field("state", &self.state())
            .field("active_streams", &self.active_streams())
            .field("next_id", &self.next_id.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

struct ChildCancellationGuard {
    session: Arc<VlessCoolSession>,
    id: u16,
    armed: bool,
}

impl ChildCancellationGuard {
    fn new(session: &Arc<VlessCoolSession>, id: u16) -> Self {
        Self {
            session: Arc::clone(session),
            id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ChildCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.session.fail_child(
                self.id,
                Failure::new(
                    io::ErrorKind::ConnectionAborted,
                    "Mux.Cool logical open or send was cancelled",
                ),
            );
            let _ = self.session.schedule_end(self.id);
        }
    }
}

impl VlessCoolSession {
    fn install_task(&self, task: Option<tokio::task::AbortHandle>) {
        let Some(task) = task else { return };
        let mut tasks = self.tasks.lock();
        if self.is_closed() {
            task.abort();
        } else {
            tasks.push(task);
        }
    }

    fn schedule_end(self: &Arc<Self>, id: u16) -> io::Result<()> {
        let unissued = if id == 0 {
            !self.zero_id_issued.load(Ordering::Acquire)
        } else {
            id > MAX_STREAMS_PER_SESSION as u16 || id >= self.next_id.load(Ordering::Acquire)
        };
        if unissued {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Mux.Cool peer referenced an unissued session ID",
            ));
        }
        tokio::runtime::Handle::try_current().map_err(|error| {
            io::Error::other(format!(
                "Mux.Cool END scheduling requires a Tokio runtime: {error}"
            ))
        })?;
        if !self.ending_ids.lock().insert(id) {
            return Ok(());
        }
        let session = Arc::clone(self);
        let writer = self.writer.clone();
        let _ = self.task_scope.spawn(async move {
            let failure =
                match tokio::time::timeout(WRITER_IO_TIMEOUT, writer.send(end_frame(id), true))
                    .await
                {
                    Ok(Ok(())) => return,
                    Ok(Err(error)) => error.failure,
                    Err(_) => Failure::from_io(
                        io::Error::new(io::ErrorKind::TimedOut, "Mux.Cool END delivery timed out"),
                        "Mux.Cool carrier stalled",
                    ),
                };
            session.fail(failure);
        });
        Ok(())
    }

    fn fail(&self, failure: Failure) {
        // Even a losing set waits for publication before acknowledgements can disappear.
        if self.writer.failure.set(failure.clone()).is_err() {
            return;
        }
        self.state
            .store(SessionState::Closed as u8, Ordering::Release);
        self.capacity.close();
        let children = std::mem::take(&mut *self.children.lock());
        for child in children.values() {
            child.set_failure(failure.clone());
        }
        for task in self.tasks.lock().drain(..) {
            task.abort();
        }
        if let Some(notify) = self.capacity_notify.get() {
            notify.notify_waiters();
        }
    }

    fn allocate_id(&self) -> Result<u16, OpenError> {
        if self.state() != SessionState::Active {
            return Err(OpenError::Draining(anyhow::anyhow!(
                "Mux.Cool carrier is draining"
            )));
        }
        let id = self.next_id.fetch_add(1, Ordering::AcqRel);
        if id == 0 || id > MAX_STREAMS_PER_SESSION as u16 {
            self.begin_drain();
            return Err(OpenError::Draining(anyhow::anyhow!(
                "Mux.Cool carrier exhausted its session IDs"
            )));
        }
        if id == MAX_STREAMS_PER_SESSION as u16 {
            self.begin_drain();
        }
        Ok(id)
    }

    fn insert_child(&self, id: u16, child: ChildSink) -> io::Result<()> {
        let mut children = self.children.lock();
        if children.contains_key(&id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Mux.Cool session ID already exists",
            ));
        }
        children.insert(id, child);
        if id == 0 {
            self.zero_id_issued.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn remove_child(&self, id: u16) {
        self.children.lock().remove(&id);
    }

    fn end_child(&self, id: u16) {
        if let Some(child) = self.children.lock().remove(&id) {
            child.set_ended();
        }
    }

    fn fail_child(&self, id: u16, failure: Failure) {
        if let Some(child) = self.children.lock().remove(&id) {
            child.set_failure(failure);
        }
    }

    fn fail_slow_tcp(self: &Arc<Self>, id: u16, message: &'static str) -> io::Result<()> {
        self.fail_child(id, Failure::new(io::ErrorKind::ConnectionReset, message));
        self.schedule_end(id)
    }

    async fn dispatch(self: &Arc<Self>, frame: IncomingFrame) -> io::Result<()> {
        if frame.status == STATUS_KEEPALIVE {
            return Ok(());
        }
        if frame.status == STATUS_NEW {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Mux.Cool server sent forbidden NEW frame",
            ));
        }
        if !matches!(frame.status, STATUS_KEEP | STATUS_END) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Mux.Cool frame has unknown status",
            ));
        }

        let terminal = frame.status == STATUS_END;
        if frame.options & OPTION_ERROR != 0 {
            let error =
                anyhow::anyhow!("Mux.Cool peer closed the logical connection with an error");
            let error = if matches!(
                self.children.lock().get(&frame.id),
                Some(ChildSink::Udp { .. })
            ) {
                anyhow::Error::new(crate::proxy::NodeFailure(error))
            } else {
                anyhow::Error::new(crate::proxy::TargetFailure(error))
            };
            self.fail_child(
                frame.id,
                Failure {
                    kind: io::ErrorKind::ConnectionReset,
                    cause: FailureCause::Shared(crate::SharedError::fanout(error)),
                },
            );
            return Ok(());
        }
        if terminal && frame.payload.is_none() {
            self.end_child(frame.id);
            return Ok(());
        }

        let Some(payload) = frame.payload else {
            return Ok(());
        };
        enum Delivery {
            Tcp(mpsc::Sender<QueuedPayload>),
            Udp(mpsc::Sender<Datagram>, SocketAddr),
        }
        // A KEEP frame whose UDP metadata cannot be read, or that arrives
        // before its child committed a destination, is that child's failure:
        // the other logical connections on the carrier are untouched.
        let delivery = {
            let children = self.children.lock();
            match children.get(&frame.id) {
                None => None,
                Some(ChildSink::Tcp { tx, .. }) => Some(Delivery::Tcp(tx.clone())),
                Some(ChildSink::Udp {
                    tx, destination, ..
                }) => {
                    let peer = destination
                        .lock()
                        .clone()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "XUDP peer replied before the first NEW destination was committed",
                            )
                        })
                        .and_then(|destination| {
                            parse_keep_peer(
                                &frame.metadata,
                                destination.peer,
                                destination.target_domain.as_deref(),
                            )
                        });
                    match peer {
                        Ok(peer) => Some(Delivery::Udp(tx.clone(), peer)),
                        Err(error) => {
                            drop(children);
                            self.fail_child(
                                frame.id,
                                Failure::from_io(error, "invalid XUDP KEEP frame"),
                            );
                            if !terminal {
                                self.schedule_end(frame.id)?;
                            }
                            return Ok(());
                        }
                    }
                }
            }
        };
        let Some(delivery) = delivery else {
            if !terminal {
                self.schedule_end(frame.id)?;
            }
            return Ok(());
        };
        match delivery {
            Delivery::Tcp(_) if payload.is_empty() => {}
            Delivery::Tcp(tx) => {
                let deadline = Instant::now() + RECEIVE_BACKPRESSURE_WAIT;
                let budget = Arc::clone(&self.receive_budget);
                let permit = match Arc::clone(&budget).try_acquire_many_owned(payload.len() as u32)
                {
                    Ok(permit) => permit,
                    Err(_) => match tokio::time::timeout_at(
                        deadline,
                        budget.acquire_many_owned(payload.len() as u32),
                    )
                    .await
                    {
                        Ok(Ok(permit)) => permit,
                        Ok(Err(_)) | Err(_) => {
                            self.fail_slow_tcp(
                                frame.id,
                                "Mux.Cool logical TCP receive budget stalled",
                            )?;
                            return Ok(());
                        }
                    },
                };
                let queued = QueuedPayload {
                    payload,
                    _permit: permit,
                };
                match tx.try_send(queued) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(queued)) => {
                        match tokio::time::timeout_at(deadline, tx.send(queued)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) => {
                                self.remove_child(frame.id);
                                self.schedule_end(frame.id)?;
                            }
                            Err(_) => {
                                self.fail_slow_tcp(
                                    frame.id,
                                    "Mux.Cool logical TCP consumer stopped draining",
                                )?;
                            }
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.remove_child(frame.id);
                        self.schedule_end(frame.id)?;
                    }
                }
            }
            Delivery::Udp(tx, peer) => {
                if let Ok(permit) =
                    Arc::clone(&self.receive_budget).try_acquire_many_owned(payload.len() as u32)
                {
                    match tx.try_send(Datagram {
                        payload,
                        peer,
                        _permit: permit,
                    }) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            self.remove_child(frame.id);
                            self.schedule_end(frame.id)?;
                        }
                    }
                }
            }
        }
        if terminal {
            self.end_child(frame.id);
        }
        Ok(())
    }
}

impl Drop for VlessCoolSession {
    fn drop(&mut self) {
        for task in self.tasks.get_mut().drain(..) {
            task.abort();
        }
    }
}

impl ManagedSession for VlessCoolSession {
    fn active_streams(&self) -> usize {
        self.active_limit - self.capacity.available_permits()
    }
    fn is_closed(&self) -> bool {
        self.state() == SessionState::Closed
    }

    fn close(&self) {
        self.fail(Failure::new(
            io::ErrorKind::ConnectionAborted,
            "Mux.Cool carrier closed",
        ));
    }

    fn bind_capacity_notify(&self, notify: Arc<tokio::sync::Notify>) {
        if let Err(notify) = self.capacity_notify.set(notify) {
            assert!(
                Arc::ptr_eq(self.capacity_notify.get().unwrap(), &notify),
                "session cannot belong to multiple pools"
            );
        }
    }

    fn state(&self) -> SessionState {
        match self.state.load(Ordering::Acquire) {
            value if value == SessionState::Active as u8 => SessionState::Active,
            value if value == SessionState::Draining as u8 => SessionState::Draining,
            _ => SessionState::Closed,
        }
    }

    fn created_at(&self) -> Instant {
        self.created_at
    }

    fn begin_drain(&self) {
        if self
            .state
            .compare_exchange(
                SessionState::Active as u8,
                SessionState::Draining as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            if let Some(notify) = self.capacity_notify.get() {
                notify.notify_waiters();
            }
            if self.active_streams() == 0 {
                self.close();
            }
        }
    }

    fn permit_released(&self) {
        let active = self.active_streams();
        self.idle.stream_released(active);
        if self.state() == SessionState::Draining && active == 0 {
            self.close();
        }
    }

    fn idle_since(&self) -> Option<Instant> {
        self.idle.idle_since()
    }

    fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
        if self.state() != SessionState::Active {
            return None;
        }
        let permit = Arc::clone(&self.capacity).try_acquire_owned().ok()?;
        self.idle.stream_opened();
        let permit = SessionPermit::new(Arc::clone(self), permit);
        if self.state() != SessionState::Active {
            drop(permit);
            return None;
        }
        Some(permit)
    }
}

async fn run_writer<W: AsyncWrite + Unpin>(
    mut stream: W,
    mut rx: mpsc::Receiver<WriterCommand>,
    session: std::sync::Weak<VlessCoolSession>,
) {
    while let Some(command) = rx.recv().await {
        let mut offset = 0;
        let result = tokio::time::timeout(WRITER_IO_TIMEOUT, async {
            while offset < command.frame.len() {
                let written = stream.write(&command.frame[offset..]).await?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                offset += written;
            }
            if command.flush {
                stream.flush().await?;
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Mux.Cool carrier write timed out",
            ))
        });
        match result {
            Ok(()) => {
                let _ = command.done.send(Ok(()));
            }
            Err(error) => {
                let failure = FrameSendFailure {
                    failure: Failure::from_io(error, "Mux.Cool carrier write failed"),
                    committed: offset != 0,
                };
                if let Some(session) = session.upgrade() {
                    session.fail(failure.failure.clone());
                }
                let _ = command.done.send(Err(failure));
                return;
            }
        }
    }
}

async fn run_reader<R: AsyncRead + Unpin>(
    mut stream: R,
    session: std::sync::Weak<VlessCoolSession>,
) {
    let mut frames_until_yield = READER_YIELD_INTERVAL;
    loop {
        let frame = match read_frame(&mut stream).await {
            Ok(frame) => frame,
            Err(error) => {
                if let Some(session) = session.upgrade() {
                    session.fail(Failure::from_io(error, "Mux.Cool carrier read failed"));
                }
                return;
            }
        };
        let Some(session) = session.upgrade() else {
            return;
        };
        if let Err(error) = session.dispatch(frame).await {
            session.fail(Failure::from_io(error, "invalid Mux.Cool frame"));
            return;
        }
        frames_until_yield -= 1;
        if frames_until_yield == 0 {
            frames_until_yield = READER_YIELD_INTERVAL;
            tokio::task::yield_now().await;
        }
    }
}

pub(crate) fn connect(
    stream: Box<dyn AsyncReadWrite>,
    active_limit: usize,
) -> Arc<VlessCoolSession> {
    let (reader, writer) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel(WRITER_QUEUE_CAPACITY);
    let session = Arc::new(VlessCoolSession {
        state: AtomicU8::new(SessionState::Active as u8),
        created_at: Instant::now(),
        idle: IdleClock::new(),
        capacity: Arc::new(tokio::sync::Semaphore::new(active_limit)),
        capacity_notify: std::sync::OnceLock::new(),
        active_limit,
        next_id: AtomicU16::new(1),
        zero_id_issued: AtomicBool::new(false),
        writer: CarrierWriter {
            tx,
            failure: Arc::new(OnceLock::new()),
        },
        children: Mutex::new(HashMap::new()),
        ending_ids: Mutex::new(HashSet::new()),
        receive_budget: Arc::new(tokio::sync::Semaphore::new(RECEIVE_BYTE_BUDGET)),
        tasks: Mutex::new(Vec::with_capacity(2)),
        task_scope: crate::runtime::TaskScope::capture(),
    });
    let writer_task = crate::runtime::spawn_owned(run_writer(writer, rx, Arc::downgrade(&session)));
    session.install_task(writer_task);
    let reader_task = crate::runtime::spawn_owned(run_reader(reader, Arc::downgrade(&session)));
    session.install_task(reader_task);
    session
}

impl MuxSession for VlessCoolSession {
    type Stream = VlessCoolStream;
    type Packet = VlessXudpTransport;

    fn open_stream(
        self: Arc<Self>,
        permit: SessionPermit<Self>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> impl Future<Output = Result<Self::Stream, OpenError>> + Send {
        open_tcp(self, permit, target, target_domain)
    }

    fn open_packet(
        self: Arc<Self>,
        permit: SessionPermit<Self>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> impl Future<Output = Result<Arc<Self::Packet>, OpenError>> + Send {
        open_xudp(self, permit, target, target_domain, [0; 8])
    }
}

#[cfg(test)]
mod tests;
