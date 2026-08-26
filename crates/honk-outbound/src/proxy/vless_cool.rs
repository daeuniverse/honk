#![cfg_attr(not(feature = "rprx"), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use super::{AsyncReadWrite, MuxSession, PacketTransport};
use crate::session::{
    ManagedSession, OpenError, SessionPermit, SessionPool, SessionPoolConfig, SessionState,
};

pub(crate) const VLESS_MUX_COMMAND: u8 = 0x03;
pub(crate) const MAX_SESSIONS: usize = 2;
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

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEPALIVE: u8 = 0x04;
const OPTION_DATA: u8 = 0x01;
const OPTION_ERROR: u8 = 0x02;
const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x02;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

pub(crate) type VlessCoolPool = SessionPool<VlessCoolSession>;

pub(crate) fn session_pool_config() -> SessionPoolConfig {
    SessionPoolConfig {
        max_sessions: MAX_SESSIONS,
        max_streams_per_session: MAX_STREAMS_PER_SESSION,
        spread_sessions: false,
        max_session_age: None,
        ..SessionPoolConfig::default()
    }
}

#[derive(Clone, Debug)]
struct Failure {
    kind: io::ErrorKind,
    message: Arc<str>,
}

impl Failure {
    fn new(kind: io::ErrorKind, message: impl Into<Arc<str>>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn from_io(error: io::Error, context: &'static str) -> Self {
        Self::new(error.kind(), format!("{context}: {error}"))
    }

    fn io(&self) -> io::Error {
        io::Error::new(self.kind, self.message.to_string())
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
}

impl CarrierWriter {
    async fn send(&self, frame: Bytes, flush: bool) -> Result<(), FrameSendFailure> {
        let (done, wait) = oneshot::channel();
        self.tx
            .send(WriterCommand { frame, flush, done })
            .await
            .map_err(|_| FrameSendFailure {
                failure: Failure::new(io::ErrorKind::BrokenPipe, "Mux.Cool carrier writer closed"),
                committed: false,
            })?;
        wait.await.unwrap_or_else(|_| {
            Err(FrameSendFailure {
                failure: Failure::new(
                    io::ErrorKind::BrokenPipe,
                    "Mux.Cool carrier writer stopped before acknowledgement",
                ),
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
        peer: SocketAddr,
        target_domain: Option<Arc<str>>,
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
    capacity: Arc<tokio::sync::Semaphore>,
    receive_budget: Arc<tokio::sync::Semaphore>,
    next_id: AtomicU16,
    zero_id_issued: AtomicBool,
    writer: CarrierWriter,
    children: Mutex<HashMap<u16, ChildSink>>,
    ending_ids: Mutex<HashSet<u16>>,
    failure: Mutex<Option<Failure>>,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
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
    fn install_task(&self, task: tokio::task::AbortHandle) {
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
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            io::Error::other(format!(
                "Mux.Cool END scheduling requires a Tokio runtime: {error}"
            ))
        })?;
        if !self.ending_ids.lock().insert(id) {
            return Ok(());
        }
        let session = Arc::clone(self);
        let writer = self.writer.clone();
        runtime.spawn(async move {
            let failure =
                match tokio::time::timeout(WRITER_IO_TIMEOUT, writer.send(end_frame(id), true))
                    .await
                {
                    Ok(Ok(())) => return,
                    Ok(Err(error)) => error.failure,
                    Err(_) => {
                        Failure::new(io::ErrorKind::TimedOut, "Mux.Cool END delivery timed out")
                    }
                };
            session.fail(failure);
        });
        Ok(())
    }

    fn fail(&self, failure: Failure) {
        if self
            .state
            .swap(SessionState::Closed as u8, Ordering::AcqRel)
            == SessionState::Closed as u8
        {
            return;
        }
        *self.failure.lock() = Some(failure.clone());
        self.capacity.close();
        let children = std::mem::take(&mut *self.children.lock());
        for child in children.values() {
            child.set_failure(failure.clone());
        }
        for task in self.tasks.lock().drain(..) {
            task.abort();
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
            self.fail_child(
                frame.id,
                Failure::new(
                    io::ErrorKind::ConnectionReset,
                    "Mux.Cool peer closed the logical connection with an error",
                ),
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
        let delivery = {
            let children = self.children.lock();
            match children.get(&frame.id) {
                None => None,
                Some(ChildSink::Tcp { tx, .. }) => Some(Delivery::Tcp(tx.clone())),
                Some(ChildSink::Udp {
                    tx,
                    peer,
                    target_domain,
                    ..
                }) => Some(Delivery::Udp(
                    tx.clone(),
                    parse_keep_peer(&frame.metadata, *peer, target_domain.as_deref())?,
                )),
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
        MAX_STREAMS_PER_SESSION - self.capacity.available_permits()
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
            && self.active_streams() == 0
        {
            self.close();
        }
    }

    fn permit_released(&self) {
        if self.state() == SessionState::Draining && self.active_streams() == 0 {
            self.close();
        }
    }

    fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
        if self.state() != SessionState::Active {
            return None;
        }
        let permit = Arc::clone(&self.capacity).try_acquire_owned().ok()?;
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
                let _ = command.done.send(Err(failure.clone()));
                if let Some(session) = session.upgrade() {
                    session.fail(failure.failure);
                }
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

pub(crate) async fn connect(
    stream: Box<dyn AsyncReadWrite>,
) -> anyhow::Result<Arc<VlessCoolSession>> {
    let (reader, writer) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel(WRITER_QUEUE_CAPACITY);
    let session = Arc::new(VlessCoolSession {
        state: AtomicU8::new(SessionState::Active as u8),
        created_at: Instant::now(),
        capacity: Arc::new(tokio::sync::Semaphore::new(MAX_STREAMS_PER_SESSION)),
        next_id: AtomicU16::new(1),
        zero_id_issued: AtomicBool::new(false),
        writer: CarrierWriter { tx },
        children: Mutex::new(HashMap::new()),
        ending_ids: Mutex::new(HashSet::new()),
        receive_budget: Arc::new(tokio::sync::Semaphore::new(RECEIVE_BYTE_BUDGET)),
        failure: Mutex::new(None),
        tasks: Mutex::new(Vec::with_capacity(2)),
    });
    let writer_task = tokio::spawn(run_writer(writer, rx, Arc::downgrade(&session)));
    session.install_task(writer_task.abort_handle());
    let reader_task = tokio::spawn(run_reader(reader, Arc::downgrade(&session)));
    session.install_task(reader_task.abort_handle());
    Ok(session)
}

fn encode_address(
    output: &mut BytesMut,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> io::Result<()> {
    output.extend_from_slice(&target.port().to_be_bytes());
    if let Some(domain) = target_domain {
        if domain.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mux.Cool target domain exceeds 255 bytes",
            ));
        }
        output.extend_from_slice(&[ATYP_DOMAIN, domain.len() as u8]);
        output.extend_from_slice(domain.as_bytes());
    } else {
        match target.ip() {
            IpAddr::V4(ip) => {
                output.extend_from_slice(&[ATYP_IPV4]);
                output.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                output.extend_from_slice(&[ATYP_IPV6]);
                output.extend_from_slice(&ip.octets());
            }
        }
    }
    Ok(())
}

fn metadata_frame(metadata: BytesMut, payload: Option<&[u8]>) -> io::Result<Bytes> {
    if !(4..=MAX_METADATA).contains(&metadata.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mux.Cool metadata length is outside 4..=512",
        ));
    }
    let payload_len = payload.map_or(0, <[u8]>::len);
    if payload_len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mux.Cool payload exceeds the wire length",
        ));
    }
    let mut frame = BytesMut::with_capacity(2 + metadata.len() + 2 + payload_len);
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    if let Some(payload) = payload {
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
    }
    Ok(frame.freeze())
}

fn base_metadata(id: u16, status: u8, options: u8) -> BytesMut {
    let mut metadata = BytesMut::with_capacity(32);
    metadata.extend_from_slice(&id.to_be_bytes());
    metadata.extend_from_slice(&[status, options]);
    metadata
}

fn new_tcp_frame(id: u16, target: SocketAddr, target_domain: Option<&str>) -> io::Result<Bytes> {
    let mut metadata = base_metadata(id, STATUS_NEW, 0);
    metadata.extend_from_slice(&[NETWORK_TCP]);
    encode_address(&mut metadata, target, target_domain)?;
    metadata_frame(metadata, None)
}

fn keep_tcp_frame(id: u16, payload: &[u8]) -> io::Result<Bytes> {
    metadata_frame(base_metadata(id, STATUS_KEEP, OPTION_DATA), Some(payload))
}

fn end_frame(id: u16) -> Bytes {
    metadata_frame(base_metadata(id, STATUS_END, 0), None)
        .expect("fixed Mux.Cool END metadata is valid")
}

fn udp_frame(
    id: u16,
    first: bool,
    target: SocketAddr,
    target_domain: Option<&str>,
    global_id: [u8; 8],
    payload: &[u8],
) -> io::Result<Bytes> {
    let max_packet_size = if id == 0 {
        MAX_SINGLE_XUDP_PACKET_SIZE
    } else {
        MAX_MUX_XUDP_PACKET_SIZE
    };
    if payload.is_empty() || payload.len() > max_packet_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("XUDP datagram length must be 1..={max_packet_size}"),
        ));
    }
    let mut metadata = base_metadata(
        id,
        if first { STATUS_NEW } else { STATUS_KEEP },
        OPTION_DATA,
    );
    metadata.extend_from_slice(&[NETWORK_UDP]);
    encode_address(&mut metadata, target, target_domain)?;
    if first && global_id != [0; 8] {
        metadata.extend_from_slice(&global_id);
    }
    metadata_frame(metadata, Some(payload))
}

struct IncomingFrame {
    metadata: Bytes,
    id: u16,
    status: u8,
    options: u8,
    payload: Option<Bytes>,
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<IncomingFrame> {
    let metadata_len = reader.read_u16().await? as usize;
    if !(4..=MAX_METADATA).contains(&metadata_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Mux.Cool metadata length is outside 4..=512",
        ));
    }
    let mut metadata = BytesMut::zeroed(metadata_len);
    reader.read_exact(&mut metadata).await?;
    let id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let options = metadata[3];
    let payload = if options & OPTION_DATA != 0 {
        let payload_len = reader.read_u16().await? as usize;
        let mut payload = BytesMut::zeroed(payload_len);
        reader.read_exact(&mut payload).await?;
        Some(payload.freeze())
    } else {
        None
    };
    Ok(IncomingFrame {
        metadata: metadata.freeze(),
        id,
        status,
        options,
        payload,
    })
}

fn parse_keep_peer(
    metadata: &[u8],
    fallback: SocketAddr,
    expected_domain: Option<&str>,
) -> io::Result<SocketAddr> {
    if metadata.len() == 4 {
        return Ok(fallback);
    }
    if metadata.len() < 8 || metadata[4] != NETWORK_UDP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XUDP KEEP metadata has an invalid UDP endpoint",
        ));
    }
    let port = u16::from_be_bytes([metadata[5], metadata[6]]);
    match metadata[7] {
        ATYP_IPV4 if metadata.len() == 12 => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                metadata[8],
                metadata[9],
                metadata[10],
                metadata[11],
            )),
            port,
        )),
        ATYP_IPV6 if metadata.len() == 24 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(&metadata[8..24]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        ATYP_DOMAIN if metadata.len() >= 9 && metadata.len() == 9 + metadata[8] as usize => {
            let domain = &metadata[9..];
            if !expected_domain
                .is_some_and(|expected| domain.eq_ignore_ascii_case(expected.as_bytes()))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XUDP KEEP response domain differs from the requested target",
                ));
            }
            Ok(SocketAddr::new(fallback.ip(), port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XUDP KEEP metadata has a truncated or unknown address",
        )),
    }
}

type IoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
type ReserveFuture = Pin<
    Box<
        dyn Future<Output = Result<mpsc::OwnedPermit<WriterCommand>, mpsc::error::SendError<()>>>
            + Send,
    >,
>;

enum StreamOperation {
    Reserve(ReserveFuture),
    Flush(IoFuture),
    Shutdown(IoFuture),
}

pub(crate) struct VlessCoolStream {
    session: Arc<VlessCoolSession>,
    id: u16,
    writer: CarrierWriter,
    rx: mpsc::Receiver<QueuedPayload>,
    current: Option<QueuedPayload>,
    failure: Arc<Mutex<Option<Failure>>>,
    ended: Arc<AtomicBool>,
    operation: Option<StreamOperation>,
    closed: bool,
    _permit: SessionPermit<VlessCoolSession>,
}

impl std::fmt::Debug for VlessCoolStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessCoolStream")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl VlessCoolStream {
    fn poll_operation(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<usize>>> {
        let Some(operation) = self.operation.as_mut() else {
            return Poll::Ready(Ok(None));
        };
        let result = match operation {
            StreamOperation::Reserve(_) => unreachable!("write reserves are polled by poll_write"),
            StreamOperation::Flush(future) | StreamOperation::Shutdown(future) => {
                match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result.map(|()| None),
                }
            }
        };
        self.operation = None;
        Poll::Ready(result)
    }
    fn terminal_error(&self) -> Option<io::Error> {
        self.failure.lock().as_ref().map(Failure::io)
    }
}

impl AsyncRead for VlessCoolStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.current.is_some() {
            let empty = {
                let current = self.current.as_mut().expect("current payload exists");
                let count = output.remaining().min(current.payload.len());
                output.put_slice(&current.payload[..count]);
                current.payload.advance(count);
                current.payload.is_empty()
            };
            if empty {
                self.current = None;
            }
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(data)) => {
                self.current = Some(data);
                self.poll_read(cx, output)
            }
            Poll::Ready(None) => self.failure.lock().as_ref().map_or_else(
                || Poll::Ready(Ok(())),
                |failure| Poll::Ready(Err(failure.io())),
            ),
        }
    }
}

impl AsyncWrite for VlessCoolStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || self.ended.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let shutdown_pending = matches!(self.operation, Some(StreamOperation::Shutdown(_)));
        if self.operation.is_none() {
            if let Some(error) = self.terminal_error() {
                return Poll::Ready(Err(error));
            }
            self.operation = Some(StreamOperation::Reserve(Box::pin(
                self.writer.tx.clone().reserve_owned(),
            )));
        }
        if let Some(StreamOperation::Reserve(reserve)) = self.operation.as_mut() {
            let permit = match reserve.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(permit)) => permit,
                Poll::Ready(Err(_)) => {
                    self.operation = None;
                    return Poll::Ready(Err(self.terminal_error().unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "Mux.Cool carrier writer closed")
                    })));
                }
            };
            self.operation = None;
            if self.closed || self.ended.load(Ordering::Acquire) {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if let Some(error) = self.terminal_error() {
                return Poll::Ready(Err(error));
            }
            let length = data.len().min(MAX_TCP_CHUNK);
            let frame = match keep_tcp_frame(self.id, &data[..length]) {
                Ok(frame) => frame,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let (done, wait) = oneshot::channel();
            drop(wait);
            let _sender = permit.send(WriterCommand {
                frame,
                flush: false,
                done,
            });
            return Poll::Ready(Ok(length));
        }
        match self.poll_operation(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(None)) if shutdown_pending => {
                self.closed = true;
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            Poll::Ready(Ok(None)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Ok(Some(_))) => {
                unreachable!("TCP data writes do not await acknowledgements")
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.operation, Some(StreamOperation::Reserve(_))) {
            self.operation = None;
        }
        loop {
            if self.operation.is_none() {
                if self.ended.load(Ordering::Acquire) {
                    return Poll::Ready(Ok(()));
                }
                if let Some(error) = self.terminal_error() {
                    return Poll::Ready(Err(error));
                }
                let writer = self.writer.clone();
                self.operation = Some(StreamOperation::Flush(Box::pin(async move {
                    writer.flush().await
                })));
            }
            let shutdown_pending = matches!(self.operation, Some(StreamOperation::Shutdown(_)));
            match self.poll_operation(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(Some(_))) => continue,
                Poll::Ready(Ok(None)) => {
                    if shutdown_pending {
                        self.closed = true;
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed || self.ended.load(Ordering::Acquire) {
            self.operation = None;
            self.closed = true;
            return Poll::Ready(Ok(()));
        }
        if matches!(self.operation, Some(StreamOperation::Reserve(_))) {
            self.operation = None;
        }
        loop {
            if self.operation.is_none() {
                let writer = self.writer.clone();
                let session = Arc::clone(&self.session);
                let id = self.id;
                self.operation = Some(StreamOperation::Shutdown(Box::pin(async move {
                    let result = writer
                        .send(end_frame(id), true)
                        .await
                        .map_err(|error| error.failure.io());
                    session.remove_child(id);
                    result
                })));
            }
            match self.poll_operation(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(Some(_))) => continue,
                Poll::Ready(Ok(None)) => {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    self.closed = true;
                    return Poll::Ready(Err(error));
                }
            }
        }
    }
}

impl Drop for VlessCoolStream {
    fn drop(&mut self) {
        self.session.remove_child(self.id);
        if !self.closed && !self.ended.load(Ordering::Acquire) && self.failure.lock().is_none() {
            let _ = self.session.schedule_end(self.id);
        }
    }
}

async fn open_tcp(
    session: Arc<VlessCoolSession>,
    permit: SessionPermit<VlessCoolSession>,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> Result<VlessCoolStream, OpenError> {
    let frame = new_tcp_frame(1, target, target_domain)
        .map_err(|error| OpenError::Refused(anyhow::Error::new(error)))?;
    let id = session.allocate_id()?;
    let frame = if id == 1 {
        frame
    } else {
        new_tcp_frame(id, target, target_domain)
            .map_err(|error| OpenError::Refused(anyhow::Error::new(error)))?
    };
    let (tx, rx) = mpsc::channel(TCP_QUEUE_CAPACITY);
    let failure = Arc::new(Mutex::new(None));
    let ended = Arc::new(AtomicBool::new(false));
    session
        .insert_child(
            id,
            ChildSink::Tcp {
                tx,
                failure: Arc::clone(&failure),
                ended: Arc::clone(&ended),
            },
        )
        .map_err(|error| OpenError::Session(anyhow::Error::new(error)))?;
    let mut cancellation = ChildCancellationGuard::new(&session, id);
    if let Err(error) = session.writer.send(frame, true).await {
        session.fail_child(id, error.failure.clone());
        cancellation.disarm();
        return Err(if error.committed {
            OpenError::Refused(anyhow::Error::new(error.failure.io()))
        } else {
            OpenError::Session(anyhow::Error::new(error.failure.io()))
        });
    }
    cancellation.disarm();
    Ok(VlessCoolStream {
        writer: session.writer.clone(),
        session,
        id,
        rx,
        current: None,
        failure,
        ended,
        operation: None,
        closed: false,
        _permit: permit,
    })
}

struct UdpWriteState {
    started: bool,
    poisoned: bool,
}

struct UdpReadState {
    rx: mpsc::Receiver<Datagram>,
    pending: Option<Datagram>,
}

pub(crate) struct VlessCoolXudpTransport {
    session: Arc<VlessCoolSession>,
    id: u16,
    writer: CarrierWriter,
    write: tokio::sync::Mutex<UdpWriteState>,
    read: tokio::sync::Mutex<UdpReadState>,
    failure: Arc<Mutex<Option<Failure>>>,
    ended: Arc<AtomicBool>,
    target: SocketAddr,
    target_domain: Option<Arc<str>>,
    global_id: [u8; 8],
    _permit: SessionPermit<VlessCoolSession>,
}

impl std::fmt::Debug for VlessCoolXudpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessCoolXudpTransport")
            .field("id", &self.id)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl VlessCoolXudpTransport {
    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        let mut state = self.write.lock().await;
        if self.ended.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if state.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XUDP transport is closed after an interrupted send",
            ));
        }
        if let Some(failure) = self.failure.lock().as_ref() {
            return Err(failure.io());
        }
        let first = !state.started;
        let frame = udp_frame(
            self.id,
            first,
            self.target,
            self.target_domain.as_deref(),
            self.global_id,
            payload,
        )?;
        state.started = true;
        state.poisoned = true;
        let mut cancellation = ChildCancellationGuard::new(&self.session, self.id);
        let result = self.writer.send(frame, true).await;
        cancellation.disarm();
        result.map_err(|error| error.failure.io())?;
        state.poisoned = false;
        Ok(())
    }
}

impl Drop for VlessCoolXudpTransport {
    fn drop(&mut self) {
        self.session.remove_child(self.id);
        let Ok(state) = self.write.try_lock() else {
            return;
        };
        if state.started
            && !state.poisoned
            && !self.ended.load(Ordering::Acquire)
            && self.failure.lock().is_none()
        {
            let _ = self.session.schedule_end(self.id);
        }
    }
}

#[async_trait]
impl PacketTransport for VlessCoolXudpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }
    fn allows_full_cone_replies(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.send(data).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> io::Result<()> {
        self.send(data).await
    }

    async fn recv_packet(&self, output: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut reader = self.read.lock().await;
        loop {
            if let Some(packet) = reader.pending.as_ref() {
                if packet.payload.len() > output.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "XUDP datagram exceeds receive buffer",
                    ));
                }
                let packet = reader.pending.take().expect("pending packet exists");
                output[..packet.payload.len()].copy_from_slice(&packet.payload);
                return Ok((packet.payload.len(), packet.peer));
            }
            match reader.rx.recv().await {
                Some(packet) => reader.pending = Some(packet),
                None => {
                    return Err(self.failure.lock().as_ref().map_or_else(
                        || {
                            io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "XUDP logical connection closed",
                            )
                        },
                        Failure::io,
                    ));
                }
            }
        }
    }
}

async fn open_udp_with_id(
    session: Arc<VlessCoolSession>,
    permit: SessionPermit<VlessCoolSession>,
    id: u16,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> Result<Arc<VlessCoolXudpTransport>, OpenError> {
    let mut address_check = BytesMut::new();
    encode_address(&mut address_check, target, target_domain)
        .map_err(|error| OpenError::Refused(anyhow::Error::new(error)))?;
    let target_domain = target_domain.map(Arc::<str>::from);
    let (tx, rx) = mpsc::channel(UDP_QUEUE_CAPACITY);
    let failure = Arc::new(Mutex::new(None));
    let ended = Arc::new(AtomicBool::new(false));
    session
        .insert_child(
            id,
            ChildSink::Udp {
                tx,
                failure: Arc::clone(&failure),
                ended: Arc::clone(&ended),
                peer: target,
                target_domain: target_domain.clone(),
            },
        )
        .map_err(|error| OpenError::Session(anyhow::Error::new(error)))?;
    Ok(Arc::new(VlessCoolXudpTransport {
        writer: session.writer.clone(),
        session,
        id,
        write: tokio::sync::Mutex::new(UdpWriteState {
            started: false,
            poisoned: false,
        }),
        read: tokio::sync::Mutex::new(UdpReadState { rx, pending: None }),
        failure,
        ended,
        target,
        target_domain,
        global_id: [0; 8],
        _permit: permit,
    }))
}

async fn open_udp(
    session: Arc<VlessCoolSession>,
    permit: SessionPermit<VlessCoolSession>,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> Result<Arc<VlessCoolXudpTransport>, OpenError> {
    let id = session.allocate_id()?;
    open_udp_with_id(session, permit, id, target, target_domain).await
}

pub(crate) async fn connect_single_xudp(
    stream: Box<dyn AsyncReadWrite>,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> anyhow::Result<Arc<VlessCoolXudpTransport>> {
    let session = connect(stream).await?;
    let permit = session
        .try_reserve()
        .ok_or_else(|| anyhow::anyhow!("Single XUDP carrier has no capacity"))?;
    open_udp_with_id(session, permit, 0, target, target_domain)
        .await
        .map_err(|error| match error {
            OpenError::Session(error) | OpenError::Refused(error) | OpenError::Draining(error) => {
                error
            }
        })
}

impl MuxSession for VlessCoolSession {
    type Stream = VlessCoolStream;
    type Packet = VlessCoolXudpTransport;

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
        open_udp(self, permit, target, target_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::task::Waker;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn response_frame(
        id: u16,
        status: u8,
        options: u8,
        peer: Option<SocketAddr>,
        payload: Option<&[u8]>,
    ) -> Bytes {
        let mut metadata = base_metadata(id, status, options);
        if let Some(peer) = peer {
            metadata.extend_from_slice(&[NETWORK_UDP]);
            encode_address(&mut metadata, peer, None).unwrap();
        }
        metadata_frame(metadata, payload).unwrap()
    }

    async fn read_wire_frame<R: AsyncRead + Unpin>(wire: &mut R) -> IncomingFrame {
        read_frame(wire).await.unwrap()
    }

    fn udp_target() -> SocketAddr {
        "1.2.3.4:53".parse().unwrap()
    }

    #[test]
    fn documented_xudp_new_vector_is_exact() {
        let frame = udp_frame(
            1,
            true,
            udp_target(),
            None,
            [1, 2, 3, 4, 5, 6, 7, 8],
            b"abc",
        )
        .unwrap();
        assert_eq!(
            &frame[..],
            &[
                0x00, 0x14, 0x00, 0x01, 0x01, 0x01, 0x02, 0x00, 0x35, 0x01, 0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x03, b'a', b'b', b'c',
            ]
        );
    }

    #[test]
    fn xudp_packet_caps_match_carrier_modes() {
        assert!(
            udp_frame(
                0,
                true,
                udp_target(),
                None,
                [0; 8],
                &vec![0; MAX_SINGLE_XUDP_PACKET_SIZE + 1],
            )
            .is_err()
        );
        assert!(
            udp_frame(
                1,
                true,
                udp_target(),
                None,
                [0; 8],
                &vec![0; MAX_MUX_XUDP_PACKET_SIZE],
            )
            .is_ok()
        );
        assert!(
            udp_frame(
                1,
                true,
                udp_target(),
                None,
                [0; 8],
                &vec![0; MAX_MUX_XUDP_PACKET_SIZE + 1],
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn reader_accepts_payloads_larger_than_xray_writer_chunks() {
        let (mut wire, mut reader) = tokio::io::duplex(1 << 14);
        let payload = vec![0x5a; 8192];
        wire.write_all(&response_frame(
            1,
            STATUS_KEEP,
            OPTION_DATA,
            None,
            Some(&payload),
        ))
        .await
        .unwrap();
        assert_eq!(
            read_wire_frame(&mut reader).await.payload.unwrap().len(),
            8192
        );
    }

    #[tokio::test]
    async fn missing_writer_ack_is_conservatively_committed() {
        let (tx, mut rx) = mpsc::channel(1);
        let writer = CarrierWriter { tx };
        let pending =
            tokio::spawn(async move { writer.send(Bytes::from_static(b"frame"), true).await });
        let command = rx.recv().await.unwrap();
        drop(command.done);

        let error = pending.await.unwrap().unwrap_err();
        assert!(error.committed, "ambiguous writes must never be replayed");
    }

    #[tokio::test]
    async fn fragmented_and_coalesced_responses_are_demultiplexed() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let session = connect(Box::new(client)).await.unwrap();
        let mut stream = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("TCP stream must open"));
        assert_eq!(read_wire_frame(&mut wire).await.id, 1);

        let first = response_frame(1, STATUS_KEEP, OPTION_DATA, None, Some(b"ab"));
        for &byte in first.iter() {
            wire.write_all(&[byte]).await.unwrap();
        }
        let mut joined = BytesMut::new();
        joined.extend_from_slice(&response_frame(
            1,
            STATUS_KEEP,
            OPTION_DATA,
            None,
            Some(b"cd"),
        ));
        joined.extend_from_slice(&response_frame(0xbeef, STATUS_KEEPALIVE, 0, None, None));
        wire.write_all(&joined).await.unwrap();
        let mut output = [0; 4];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"abcd");
        session.close();
    }

    #[tokio::test]
    async fn tcp_receive_budget_waits_for_transient_reader_backpressure() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let session = connect(Box::new(client)).await.unwrap();
        let mut stream = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("TCP stream must open"));
        assert_eq!(read_wire_frame(&mut wire).await.id, 1);

        let held = Arc::clone(&session.receive_budget)
            .acquire_many_owned(RECEIVE_BYTE_BUDGET as u32)
            .await
            .unwrap();
        let dispatch = {
            let session = Arc::clone(&session);
            tokio::spawn(async move {
                session
                    .dispatch(IncomingFrame {
                        metadata: base_metadata(1, STATUS_KEEP, OPTION_DATA).freeze(),
                        id: 1,
                        status: STATUS_KEEP,
                        options: OPTION_DATA,
                        payload: Some(Bytes::from_static(b"ready")),
                    })
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(!dispatch.is_finished());

        drop(held);
        tokio::time::timeout(Duration::from_secs(1), dispatch)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut output = [0; 5];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"ready");
        session.close();
    }

    #[tokio::test]
    async fn unread_tcp_child_does_not_block_siblings() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let session = connect(Box::new(client)).await.unwrap();
        let _blocked = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("blocked TCP stream must open"));
        let blocked_id = read_wire_frame(&mut wire).await.id;
        let mut sibling = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "93.184.216.35:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("sibling TCP stream must open"));
        let sibling_id = read_wire_frame(&mut wire).await.id;

        for _ in 0..=TCP_QUEUE_CAPACITY {
            wire.write_all(&response_frame(
                blocked_id,
                STATUS_KEEP,
                OPTION_DATA,
                None,
                Some(b"x"),
            ))
            .await
            .unwrap();
        }
        wire.write_all(&response_frame(
            sibling_id,
            STATUS_KEEP,
            OPTION_DATA,
            None,
            Some(b"ok"),
        ))
        .await
        .unwrap();

        let mut output = [0; 2];
        tokio::time::timeout(Duration::from_secs(1), sibling.read_exact(&mut output))
            .await
            .expect("unread child blocked the physical carrier")
            .unwrap();
        assert_eq!(&output, b"ok");
        assert_eq!(session.state(), SessionState::Active);
        session.close();
    }

    #[tokio::test]
    async fn short_udp_buffer_preserves_packet_and_response_peer_can_change() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let session = connect(Box::new(client)).await.unwrap();
        let udp = open_udp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            udp_target(),
            Some("dns.example"),
        )
        .await
        .unwrap_or_else(|_| panic!("UDP transport must open"));
        udp.send_packet_confirmed(b"query").await.unwrap();
        let request = read_wire_frame(&mut wire).await;
        let first_peer = "5.6.7.8:1000".parse().unwrap();
        let second_peer = "9.10.11.12:2000".parse().unwrap();
        wire.write_all(&response_frame(
            request.id,
            STATUS_KEEP,
            OPTION_DATA,
            Some(first_peer),
            Some(b"answer"),
        ))
        .await
        .unwrap();
        assert_eq!(
            udp.recv_packet(&mut [0; 2]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut output = [0; 16];
        assert_eq!(udp.recv_packet(&mut output).await.unwrap(), (6, first_peer));
        assert_eq!(&output[..6], b"answer");

        wire.write_all(&response_frame(
            request.id,
            STATUS_KEEP,
            OPTION_DATA,
            Some(second_peer),
            Some(b"next"),
        ))
        .await
        .unwrap();
        assert_eq!(
            udp.recv_packet(&mut output).await.unwrap(),
            (4, second_peer)
        );
        assert_eq!(&output[..4], b"next");
        wire.write_all(&response_frame(
            request.id,
            STATUS_KEEP,
            OPTION_DATA,
            None,
            Some(b"fixed"),
        ))
        .await
        .unwrap();
        assert_eq!(
            udp.recv_packet(&mut output).await.unwrap(),
            (5, udp_target())
        );
        assert_eq!(&output[..5], b"fixed");
        let mut domain_response = base_metadata(request.id, STATUS_KEEP, OPTION_DATA);
        domain_response.extend_from_slice(&[NETWORK_UDP]);
        encode_address(&mut domain_response, udp_target(), Some("dns.example")).unwrap();
        wire.write_all(&metadata_frame(domain_response, Some(b"domain")).unwrap())
            .await
            .unwrap();
        assert_eq!(
            udp.recv_packet(&mut output).await.unwrap(),
            (6, "1.2.3.4:53".parse().unwrap())
        );
        assert_eq!(&output[..6], b"domain");
        wire.write_all(&response_frame(request.id, STATUS_END, 0, None, None))
            .await
            .unwrap();
        assert_eq!(
            udp.recv_packet(&mut output).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            udp.send_packet_confirmed(b"late").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        session.close();
    }

    #[test]
    fn keep_domain_preserves_wire_port_and_validates_identity() {
        let mut metadata = base_metadata(1, STATUS_KEEP, OPTION_DATA);
        metadata.extend_from_slice(&[NETWORK_UDP]);
        encode_address(
            &mut metadata,
            "9.9.9.9:5353".parse().unwrap(),
            Some("DNS.Example"),
        )
        .unwrap();
        assert_eq!(
            parse_keep_peer(
                &metadata,
                "1.2.3.4:53".parse().unwrap(),
                Some("dns.example")
            )
            .unwrap(),
            "1.2.3.4:5353".parse().unwrap()
        );
        assert!(
            parse_keep_peer(
                &metadata,
                "1.2.3.4:53".parse().unwrap(),
                Some("other.example")
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn udp_receive_byte_budget_drops_excess_datagrams() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let session = connect(Box::new(client)).await.unwrap();
        Arc::clone(&session.receive_budget)
            .acquire_many_owned((RECEIVE_BYTE_BUDGET - 4) as u32)
            .await
            .unwrap()
            .forget();
        let udp = open_udp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            udp_target(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("UDP transport must open"));
        udp.send_packet_confirmed(b"query").await.unwrap();
        let request = read_wire_frame(&mut wire).await;
        wire.write_all(&response_frame(
            request.id,
            STATUS_KEEP,
            OPTION_DATA,
            None,
            Some(b"large"),
        ))
        .await
        .unwrap();
        wire.write_all(&response_frame(
            request.id,
            STATUS_KEEP,
            OPTION_DATA,
            None,
            Some(b"fits"),
        ))
        .await
        .unwrap();

        let mut output = [0; 8];
        assert_eq!(udp.recv_packet(&mut output).await.unwrap().0, 4);
        assert_eq!(&output[..4], b"fits");
        assert_eq!(session.receive_budget.available_permits(), 4);
        session.close();
    }

    #[tokio::test]
    async fn new_tcp_is_flushed_for_target_speaks_first() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let server = tokio::spawn(async move {
            let request = read_wire_frame(&mut wire).await;
            assert_eq!(request.status, STATUS_NEW);
            assert!(request.payload.is_none());
            wire.write_all(&response_frame(
                request.id,
                STATUS_KEEP,
                OPTION_DATA,
                None,
                Some(b""),
            ))
            .await
            .unwrap();
            wire.write_all(&response_frame(
                request.id,
                STATUS_KEEP,
                OPTION_DATA,
                None,
                Some(b"hello"),
            ))
            .await
            .unwrap();
        });
        let session = connect(Box::new(client)).await.unwrap();
        let mut stream = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("TCP stream must open"));
        let mut greeting = [0; 5];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"hello");
        session.close();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ready_tcp_consumer_survives_a_large_carrier_burst() {
        const FRAMES: usize = 2048;
        let (client, mut wire) = tokio::io::duplex(20 << 20);
        let session = connect(Box::new(client)).await.unwrap();
        let mut stream = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("TCP stream must open"));
        let request = read_wire_frame(&mut wire).await;
        let payload = vec![0xA5; MAX_TCP_CHUNK];
        let response = response_frame(request.id, STATUS_KEEP, OPTION_DATA, None, Some(&payload));
        for _ in 0..FRAMES {
            wire.write_all(&response).await.unwrap();
        }

        let mut output = vec![0; FRAMES * payload.len()];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut output))
            .await
            .expect("ready TCP consumer was starved by the carrier reader")
            .unwrap();
        assert!(output.iter().all(|byte| *byte == 0xA5));
        session.close();
    }

    #[tokio::test]
    async fn concurrent_tcp_and_udp_share_one_atomic_writer() {
        let (client, mut wire) = tokio::io::duplex(1 << 20);
        let session = connect(Box::new(client)).await.unwrap();
        let mut tcp = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("TCP stream must open"));
        let tcp_new = read_wire_frame(&mut wire).await;
        assert_eq!(tcp_new.id, 1);
        let udp = open_udp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            udp_target(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("UDP transport must open"));
        let (tcp_result, udp_result) = tokio::join!(
            tcp.write_all(b"tcp-data"),
            udp.send_packet_confirmed(b"udp-first")
        );
        tcp_result.unwrap();
        udp_result.unwrap();
        let mut frames = [
            read_wire_frame(&mut wire).await,
            read_wire_frame(&mut wire).await,
        ];
        frames.sort_by_key(|frame| frame.id);
        assert_eq!(frames[0].id, 1);
        assert_eq!(frames[0].status, STATUS_KEEP);
        assert_eq!(frames[0].payload.as_deref(), Some(&b"tcp-data"[..]));
        assert_eq!(frames[1].id, 2);
        assert_eq!(frames[1].status, STATUS_NEW);
        assert_eq!(frames[1].payload.as_deref(), Some(&b"udp-first"[..]));
        session.close();
    }

    #[tokio::test]
    async fn session_ids_are_never_reused_and_carrier_drains_at_128() {
        let (client, mut wire) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let mut ids = Vec::new();
            for _ in 0..MAX_STREAMS_PER_SESSION {
                let new = read_wire_frame(&mut wire).await;
                ids.push(new.id);
                let end = read_wire_frame(&mut wire).await;
                assert_eq!(end.id, new.id);
                assert_eq!(end.status, STATUS_END);
            }
            ids
        });
        let session = connect(Box::new(client)).await.unwrap();
        for _ in 0..MAX_STREAMS_PER_SESSION {
            let permit = session.try_reserve().unwrap();
            let mut stream = open_tcp(
                Arc::clone(&session),
                permit,
                "127.0.0.1:80".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|_| panic!("ID within lifetime cap must open"));
            stream.shutdown().await.unwrap();
            drop(stream);
        }
        let ids = server.await.unwrap();
        assert_eq!(
            ids,
            (1..=MAX_STREAMS_PER_SESSION as u16).collect::<Vec<_>>()
        );
        assert!(session.is_closed());
        assert!(session.try_reserve().is_none());
    }

    #[tokio::test]
    async fn end_error_and_physical_eof_fail_children() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let session = connect(Box::new(client)).await.unwrap();
        let mut first = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("first stream must open"));
        let first_id = read_wire_frame(&mut wire).await.id;
        let mut second = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "127.0.0.1:81".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("second stream must open"));
        let second_id = read_wire_frame(&mut wire).await.id;
        wire.write_all(&response_frame(first_id, STATUS_END, 0, None, None))
            .await
            .unwrap();
        wire.write_all(&response_frame(
            second_id,
            STATUS_KEEP,
            OPTION_ERROR,
            None,
            None,
        ))
        .await
        .unwrap();
        let mut eof = [0; 1];
        assert_eq!(first.read(&mut eof).await.unwrap(), 0);
        assert_eq!(
            first.write_all(b"late").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            second.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );

        let mut third = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "127.0.0.1:82".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("third stream must open"));
        let mut fourth = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "127.0.0.1:83".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("fourth stream must open"));
        let _ = read_wire_frame(&mut wire).await;
        let _ = read_wire_frame(&mut wire).await;
        drop(wire);
        assert!(third.read_u8().await.is_err());
        assert!(fourth.read_u8().await.is_err());
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn zero_global_id_is_omitted_without_a_source_identity() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let session = connect(Box::new(client)).await.unwrap();
        let first = open_udp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            udp_target(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("first UDP transport must open"));
        let second = open_udp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "5.6.7.8:53".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("second UDP transport must open"));
        assert_eq!(first.global_id, [0; 8]);
        assert_eq!(second.global_id, [0; 8]);
        first.send_packet_confirmed(b"one").await.unwrap();
        first.send_packet_confirmed(b"two").await.unwrap();
        second.send_packet_confirmed(b"three").await.unwrap();
        let new_first = read_wire_frame(&mut wire).await;
        let keep_first = read_wire_frame(&mut wire).await;
        let new_second = read_wire_frame(&mut wire).await;
        assert_eq!(new_first.metadata.len(), 12);
        assert_eq!(keep_first.status, STATUS_KEEP);
        assert_eq!(new_second.metadata.len(), 12);
        session.close();
    }

    #[derive(Debug, Default)]
    struct FlushGate {
        open: AtomicBool,
        waker: Mutex<Option<Waker>>,
    }

    impl FlushGate {
        fn open(&self) {
            self.open.store(true, Ordering::Release);
            if let Some(waker) = self.waker.lock().take() {
                waker.wake();
            }
        }

        fn close(&self) {
            self.open.store(false, Ordering::Release);
        }
    }

    #[derive(Debug)]
    struct GatedFlushIo<S> {
        inner: S,
        gate: Arc<FlushGate>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for GatedFlushIo<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, output)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for GatedFlushIo<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, data)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.gate.open.load(Ordering::Acquire) {
                Pin::new(&mut self.inner).poll_flush(cx)
            } else {
                *self.gate.waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_carrier_writer_times_out() {
        let (client, _wire) = tokio::io::duplex(1 << 16);
        let gate = Arc::new(FlushGate::default());
        let (tx, rx) = mpsc::channel(1);
        let writer = CarrierWriter { tx };
        let driver = tokio::spawn(run_writer(
            GatedFlushIo {
                inner: client,
                gate,
            },
            rx,
            std::sync::Weak::new(),
        ));
        let send =
            tokio::spawn(async move { writer.send(Bytes::from_static(b"blocked"), true).await });
        tokio::task::yield_now().await;
        tokio::time::advance(WRITER_IO_TIMEOUT + Duration::from_millis(1)).await;
        assert_eq!(
            send.await.unwrap().unwrap_err().failure.kind,
            io::ErrorKind::TimedOut
        );
        driver.await.unwrap();
    }

    #[tokio::test]
    async fn saturated_writer_still_delivers_required_end() {
        let (client, mut wire) = tokio::io::duplex(1 << 20);
        let gate = Arc::new(FlushGate::default());
        let session = connect(Box::new(GatedFlushIo {
            inner: client,
            gate: Arc::clone(&gate),
        }))
        .await
        .unwrap();
        let blocker = {
            let writer = session.writer.clone();
            tokio::spawn(async move { writer.flush().await })
        };
        tokio::task::yield_now().await;
        let queued = (1..=WRITER_QUEUE_CAPACITY as u16)
            .map(|id| {
                let writer = session.writer.clone();
                tokio::spawn(async move { writer.send(end_frame(id), false).await })
            })
            .collect::<Vec<_>>();
        tokio::task::yield_now().await;
        assert!(
            session
                .dispatch(IncomingFrame {
                    metadata: base_metadata(128, STATUS_KEEP, OPTION_DATA).freeze(),
                    id: 128,
                    status: STATUS_KEEP,
                    options: OPTION_DATA,
                    payload: Some(Bytes::from_static(b"forged")),
                })
                .await
                .is_err()
        );
        assert!(!session.ending_ids.lock().contains(&128));
        session.next_id.store(129, Ordering::Release);
        session
            .dispatch(IncomingFrame {
                metadata: base_metadata(128, STATUS_KEEP, OPTION_DATA).freeze(),
                id: 128,
                status: STATUS_KEEP,
                options: OPTION_DATA,
                payload: Some(Bytes::from_static(b"orphan")),
            })
            .await
            .unwrap();
        gate.open();
        blocker.await.unwrap().unwrap();
        for send in queued {
            send.await.unwrap().unwrap();
        }
        let mut found = false;
        for _ in 0..=WRITER_QUEUE_CAPACITY {
            let frame = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut wire))
                .await
                .expect("required END was dropped")
                .unwrap();
            found |= frame.id == 128 && frame.status == STATUS_END;
        }
        assert!(found);
        session.close();
    }

    #[tokio::test]
    async fn cancelled_tcp_write_does_not_send_or_replay_bytes() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let gate = Arc::new(FlushGate::default());
        gate.open();
        let session = connect(Box::new(GatedFlushIo {
            inner: client,
            gate: Arc::clone(&gate),
        }))
        .await
        .unwrap();
        let mut stream = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("TCP stream must open"));
        let _ = read_wire_frame(&mut wire).await;
        gate.close();
        let blocker = {
            let writer = session.writer.clone();
            tokio::spawn(async move { writer.flush().await })
        };
        tokio::task::yield_now().await;
        assert!(gate.waker.lock().is_some());
        for id in 2..=WRITER_QUEUE_CAPACITY as u16 + 1 {
            let (done, _wait) = oneshot::channel();
            assert!(
                session
                    .writer
                    .tx
                    .try_send(WriterCommand {
                        frame: end_frame(id),
                        flush: false,
                        done,
                    })
                    .is_ok()
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), stream.write(b"old"))
                .await
                .is_err()
        );
        gate.open();
        blocker.await.unwrap().unwrap();
        stream.write_all(b"new").await.unwrap();
        stream.flush().await.unwrap();

        let mut saw_new = 0;
        for _ in 0..=WRITER_QUEUE_CAPACITY {
            let frame = read_wire_frame(&mut wire).await;
            assert_ne!(frame.payload.as_deref(), Some(&b"old"[..]));
            saw_new += usize::from(frame.payload.as_deref() == Some(&b"new"[..]));
        }
        assert_eq!(saw_new, 1);
        session.close();
    }

    #[tokio::test]
    async fn dropping_a_pending_shutdown_still_sends_end() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let session = connect(Box::new(client)).await.unwrap();
        let mut stream = open_tcp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("TCP stream must open"));
        let id = read_wire_frame(&mut wire).await.id;
        stream.operation = Some(StreamOperation::Shutdown(Box::pin(std::future::pending())));
        drop(stream);
        let end = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut wire))
            .await
            .expect("pending shutdown suppressed END")
            .unwrap();
        assert_eq!((end.id, end.status), (id, STATUS_END));
        session.close();
    }

    #[tokio::test]
    async fn first_send_waits_for_flush_and_cancellation_never_replays() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let gate = Arc::new(FlushGate::default());
        let session = connect(Box::new(GatedFlushIo {
            inner: client,
            gate: Arc::clone(&gate),
        }))
        .await
        .unwrap();
        let udp = open_udp(
            Arc::clone(&session),
            session.try_reserve().unwrap(),
            udp_target(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("UDP transport must open"));
        let sender = tokio::spawn({
            let udp = Arc::clone(&udp);
            async move { udp.send_packet_confirmed(b"first").await }
        });
        let first = read_wire_frame(&mut wire).await;
        assert_eq!(first.status, STATUS_NEW);
        assert_eq!(first.payload.as_deref(), Some(&b"first"[..]));
        assert!(!sender.is_finished(), "confirmation must wait for flush");
        sender.abort();
        let _ = sender.await;
        gate.open();
        tokio::task::yield_now().await;
        assert_eq!(
            udp.send_packet_confirmed(b"second")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        let end = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut wire))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(end.status, STATUS_END);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), read_frame(&mut wire))
                .await
                .is_err(),
            "cancelled first send must not be replayed"
        );
        session.close();
    }

    #[tokio::test]
    async fn single_xudp_uses_session_id_zero() {
        let (client, mut wire) = tokio::io::duplex(1 << 16);
        let udp = connect_single_xudp(Box::new(client), udp_target(), None)
            .await
            .unwrap();
        udp.send_packet_confirmed(b"single").await.unwrap();
        let frame = read_wire_frame(&mut wire).await;
        assert_eq!(frame.id, 0);
        assert_eq!(frame.status, STATUS_NEW);
        assert_eq!(frame.payload.as_deref(), Some(&b"single"[..]));
        udp.session.close();
    }
}
