//! AnyTLS proxy handler with sing-anytls session multiplexing.

use crate::tls::TlsConnector;
use async_trait::async_trait;
use honk_config::node::Node;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::addr;
use super::{
    MuxSession as _, PacketOutbound, PacketTransport, PreparedUdpTransport, ProbeableOutbound,
    ProxyStream, TcpOutbound, WarmRequirement, WarmableOutbound,
};
use crate::session::SpeculativeCheckout;

mod inbound;
mod overflow;
mod padding;
mod uot;
mod writer;

use inbound::{
    INBOUND_PAYLOAD_BUDGET, InboundPayload, InboundPayloadBudget, TcpInbound, TcpReceiveState,
    session_demux,
};
use overflow::{OVERFLOW_EMERGENCY_WAIT, OVERFLOW_STALL_GRACE, StreamOverflow};
use padding::PaddingInstruction;
pub(crate) use uot::AnyTlsUotTransport;
use uot::{UOT_DRAIN_QUEUE_CAP, UotReceiveState};
use writer::{FrameCommand, WRITER_DATA_BYTES_CAP, session_writer};
#[cfg(test)]
use writer::{WRITER_CONTROL_RESERVED, WRITER_IO_TIMEOUT, WRITER_QUEUE_CAP};

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const FRAME_HEADER_LEN: usize = 7;

/// sing-anytls defaults (session/client.go): values below 5s clamp to 30s.
const DEFAULT_IDLE_CHECK_INTERVAL_SECS: u64 = 30;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;
const CLIENT_NAME: &str = concat!("honk/", env!("CARGO_PKG_VERSION"));
const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8\n\
0=30-30\n\
1=100-400\n\
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
3=9-9,500-1000\n\
4=500-1000\n\
5=500-1000\n\
6=500-1000\n\
7=500-1000";
/// Reused v2 sessions must prove that a newly opened target is still live.
const SYNACK_TIMEOUT: Duration = Duration::from_secs(3);
/// A session that stays fully silent this long after a missed SYNACK is
/// retired together with its streams.
const SILENT_SESSION_GRACE: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct PaddingScheme {
    stop: u32,
    packets: HashMap<u32, Vec<PaddingInstruction>>,
    md5: String,
}

#[derive(Debug)]
struct PaddingState {
    current: parking_lot::RwLock<Arc<PaddingScheme>>,
}

/// Per-stream demux queue depth (frames). A full queue parks frames in
/// the session overflow instead of blocking the demux.
const STREAM_QUEUE_CAP: usize = 64;
const MAX_STREAM_ERROR_SOURCE_BYTES: usize = 1024;

/// Transport halves behind trait objects so tests can drive a session over
/// an in-memory duplex instead of a real TLS connection.
type BoxedReader = Box<dyn AsyncRead + Send + Unpin>;
type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// AnyTLS proxy handler. Stateless: the node's session pool lives in its
/// generation-owned runtime; node-based calls (tests, standalone probing)
/// get a throwaway pool per call.
#[derive(Debug, Default, Clone)]
pub struct AnyTlsHandler;

/// Pool configuration shared by generation-owned and ephemeral AnyTLS runtimes.
pub(crate) fn session_pool_config() -> crate::session::SessionPoolConfig {
    crate::session::SessionPoolConfig {
        max_sessions: 2,
        max_streams_per_session: MAX_STREAMS_PER_SESSION,
        spread_sessions: true,
        janitor_interval: Duration::from_secs(DEFAULT_IDLE_CHECK_INTERVAL_SECS),

        max_session_age: Some(Duration::from_secs(30 * 60)),
        ..Default::default()
    }
}

/// Monotonic diagnostic session id (sing `sessionCounter`).
static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

/// Inbound events delivered from the session demux to a stream task.
#[derive(Debug)]
enum StreamEvent {
    Data(InboundPayload),
    Fin,
    Error(crate::SharedError),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OverflowUsage {
    frames: usize,
    bytes: usize,
}

#[derive(Default)]
struct OverflowState {
    streams: HashMap<u32, StreamOverflow>,
    frames: usize,
    bytes: usize,
    flushing: HashSet<u32>,
    flush_requested: HashSet<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OverflowVictim {
    sid: u32,
    session: OverflowUsage,
    stream: OverflowUsage,
    stalled_for: Duration,
}

/// Per-stream demux delivery channel.
#[derive(Clone)]
enum StreamSink {
    /// TCP streams: bounded queue plus the session overflow. Payload is
    /// retained in order; a stream parked at an overflow cap with no
    /// flush progress past [`OVERFLOW_STALL_GRACE`] gets only its own
    /// stream reset.
    Tcp(mpsc::Sender<StreamEvent>),
    /// UoT streams: a saturated receiver retires only this sid. Dropping an
    /// arbitrary AnyTLS chunk would corrupt the length-delimited byte stream.
    Uot(mpsc::Sender<StreamEvent>),
}

impl StreamSink {
    #[cfg(test)]
    async fn send_data(&self, data: Vec<u8>) -> bool {
        let event = StreamEvent::Data(InboundPayload::for_test(data));
        match self {
            StreamSink::Tcp(tx) => tx.send(event).await.is_ok(),
            StreamSink::Uot(tx) => tx.try_send(event).is_ok(),
        }
    }
    #[cfg(test)]
    async fn send_fin(&self) {
        match self {
            StreamSink::Tcp(tx) => {
                let _ = tx.send(StreamEvent::Fin).await;
            }
            StreamSink::Uot(tx) => {
                let _ = tx.try_send(StreamEvent::Fin);
            }
        }
    }
}

/// Ownership token for one registered stream id: the session's active
/// count moves exactly once in each direction through this token, and a
/// registration abandoned mid-open is cleaned up on Drop. TCP streams commit
/// after their SYN+PSH opening pair is queued; a UoT transport owns its lazy
/// connect request from commit until the first datagram is queued.
struct StreamRegistration {
    session: Arc<AnyTlsSession>,
    sid: u32,
    /// A frame write is in progress: a partial frame may be on the wire.
    frame_started: bool,
    /// Lifecycle handed to the caller; Drop is then a no-op.
    committed: bool,
    /// Stream-slot capacity reserved for this registration. Moves to the
    /// stream on commit; released on an abandoned registration (the
    /// semaphore is the only capacity truth).
    permit: Option<crate::session::SessionPermit<AnyTlsSession>>,
}

impl StreamRegistration {
    /// Hand the lifecycle (and the capacity slot) to the caller's stream.
    fn commit(mut self) -> crate::session::SessionPermit<AnyTlsSession> {
        self.committed = true;
        self.permit.take().expect("registration owns a permit")
    }
}

impl Drop for StreamRegistration {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.session.end_stream(self.sid, self.frame_started);
    }
}

/// Session writer queue: every frame goes out in enqueue order through a
/// single task — no cross-stream mutex, and a cancelled caller can never
/// truncate a queued frame (only a physical write failure closes the
/// session). Data capacity is `WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED`
/// frames and `WRITER_DATA_BYTES_CAP` bytes of payload, whichever fills
/// first; control frames take the reserved headroom.
struct WriterQueue {
    queue: parking_lot::Mutex<std::collections::VecDeque<FrameCommand>>,
    notify: tokio::sync::Notify,
    data_permits: Arc<tokio::sync::Semaphore>,
    data_bytes: Arc<tokio::sync::Semaphore>,
    closed: AtomicBool,
}

/// What one queued data frame holds until the writer has flushed it: a
/// frame slot and its payload's bytes. Dropped together with the command,
/// so a batch in flight still counts against both caps.
struct DataPermit {
    _frame: tokio::sync::OwnedSemaphorePermit,
    _bytes: tokio::sync::OwnedSemaphorePermit,
}

/// Open streams awaiting their SYNACK. A SID is registered when its SYN is
/// queued (so an early SYNACK can settle it) and gets its own deadline when
/// the writer puts the SYN on the wire.
#[derive(Default)]
struct SynackPending {
    sids: std::collections::HashMap<u32, Option<tokio::task::AbortHandle>>,
}

/// Session pool plus server-specific padding state for one AnyTLS node.
#[derive(Debug)]
pub(crate) struct AnyTlsPool {
    sessions: Arc<crate::session::SessionPool<AnyTlsSession>>,
    padding: Arc<PaddingState>,
    inbound_payload_budget: Arc<InboundPayloadBudget>,
}

impl AnyTlsPool {
    pub(crate) fn new() -> Self {
        Self {
            sessions: Arc::new(crate::session::SessionPool::new(session_pool_config())),
            padding: Arc::new(PaddingState::default()),
            inbound_payload_budget: InboundPayloadBudget::new(INBOUND_PAYLOAD_BUDGET),
        }
    }

    fn padding_state(&self) -> Arc<PaddingState> {
        Arc::clone(&self.padding)
    }

    fn inbound_payload_budget(&self) -> Arc<InboundPayloadBudget> {
        Arc::clone(&self.inbound_payload_budget)
    }
}

impl std::ops::Deref for AnyTlsPool {
    type Target = Arc<crate::session::SessionPool<AnyTlsSession>>;

    fn deref(&self) -> &Self::Target {
        &self.sessions
    }
}

/// Per-session stream capacity (v3.1): the semaphore is the single
/// capacity truth — 128 concurrent streams per session (initial value,
/// tune by load test).
pub(crate) const MAX_STREAMS_PER_SESSION: usize = 128;

struct StreamObservation {
    observer: crate::runtime::flow_observation::FlowObserver,
    uot: bool,
    request_sent: bool,
    confirmation: Option<bool>,
}

/// A multiplexed AnyTLS session: one TLS connection carrying any number of
/// concurrent streams (sing-anytls `Session`).
pub(crate) struct AnyTlsSession {
    /// Process-unique diagnostic id.
    seq: u64,
    /// AnyTLS server address retained for diagnostics.
    addr: String,
    /// Server-specific scheme shared by every live session in this pool.
    padding_state: Arc<PaddingState>,
    /// Idle bookkeeping for the pool janitor, stamped at stream open and close.
    idle: crate::session::IdleClock,
    /// Settings waits for the first stream so packet 1 is SETTINGS+SYN+PSH.
    initial_settings: parking_lot::Mutex<Option<bytes::Bytes>>,
    /// Ordered writer queue: every frame goes out through the single
    /// writer task (no cross-stream mutex, uncancellable once queued).
    writer_q: Arc<WriterQueue>,
    /// Writer task handle, aborted on close.
    writer_task: Mutex<Option<tokio::task::AbortHandle>>,
    /// Open streams: sid → demux delivery channel.
    streams: Mutex<HashMap<u32, StreamSink>>,
    /// TCP payload ownership, including queues held by callers after a stream reset.
    tcp_inbound: parking_lot::Mutex<HashMap<u32, Arc<TcpInbound>>>,
    /// Remote FINs suppress the local Drop notification.
    remote_fin: parking_lot::Mutex<HashSet<u32>>,
    /// Stream id allocator (sing `streamId`); first stream gets sid 1.
    next_sid: AtomicU32,
    /// Negotiated through `CMD_SERVER_SETTINGS`; v2 peers acknowledge opens.
    peer_supports_synack: AtomicBool,
    /// Per-SID open acknowledgements outstanding; the timer runs while any
    /// SYN is past the wire without its SYNACK (sing-anytls parity).
    synack_pending: parking_lot::Mutex<SynackPending>,
    /// Set once the TLS connection dies or an ALERT arrives; idempotent
    /// close via [`AnyTlsSession::close`].
    closed: AtomicBool,
    /// Establishment time (max-age drains).
    created: Instant,
    /// Lifecycle: Active → Draining → Closed (a usize of
    /// [`crate::session::SessionState`] discriminants).
    session_state: AtomicUsize,
    /// First physical-failure reason (demux read error, writer failure):
    /// streams report it after draining queued data — a dead session is
    /// never a clean EOF.
    terminal_error: std::sync::OnceLock<crate::SharedError>,
    /// Streams killed locally (HOL slow-consumer): their readers see a
    /// reset after the queued data drains, not a clean EOF. A tombstone
    /// survives map/session teardown until the owning stream reads or drops.
    killed_streams: Mutex<HashSet<u32>>,
    /// Per-stream ordered overflow for full TCP queues, with exact session
    /// and stream frame/byte accounting.
    overflow: parking_lot::Mutex<OverflowState>,
    /// Wakes the demux waiting at an emergency hard cap when a flush
    /// actually frees overflow space (reader progress).
    overflow_notify: tokio::sync::Notify,
    /// Stream-slot capacity: the single capacity truth (replaces the old
    /// active_streams counter — a permit outlives the counter's races).
    stream_permits: Arc<tokio::sync::Semaphore>,
    capacity_notify: std::sync::OnceLock<Arc<tokio::sync::Notify>>,
    /// Shared across every physical session retained or draining under the
    /// originating node pool.
    inbound_payload_budget: Arc<InboundPayloadBudget>,
    /// Odd while a locally budget-blocked frame has not completed dispatch.
    inbound_budget_epoch: AtomicU64,
    /// Demux task handle, aborted on close.
    demux: Mutex<Option<tokio::task::AbortHandle>>,
    /// Inbound frame counter, bumped by the demux per frame; lets the SYNACK
    /// deadline distinguish a silently-dead session from one whose server is
    /// merely slow to open a stream.
    rx_frame_seq: AtomicU64,
    task_scope: crate::runtime::TaskScope,
    observations: parking_lot::Mutex<HashMap<u32, StreamObservation>>,
}

impl AnyTlsSession {
    /// Establish a session on a connected transport: write packet 0 auth,
    /// retain settings for the first stream, and spawn the session tasks.
    async fn establish(
        addr: &str,
        transport_read: BoxedReader,
        mut transport_write: BoxedWriter,
        auth: &[u8],
        settings: bytes::Bytes,
        padding_state: Arc<PaddingState>,
        inbound_payload_budget: Arc<InboundPayloadBudget>,
    ) -> anyhow::Result<Arc<Self>> {
        transport_write.write_all(auth).await?;
        transport_write.flush().await?;

        let session = Arc::new(Self {
            seq: SESSION_SEQ.fetch_add(1, Ordering::Relaxed),
            addr: addr.to_string(),
            padding_state,
            initial_settings: parking_lot::Mutex::new(Some(settings)),
            writer_q: Arc::new(WriterQueue::new()),
            writer_task: Mutex::new(None),
            streams: Mutex::new(HashMap::new()),
            tcp_inbound: parking_lot::Mutex::new(HashMap::new()),
            remote_fin: parking_lot::Mutex::new(HashSet::new()),
            next_sid: AtomicU32::new(0),
            peer_supports_synack: AtomicBool::new(false),
            synack_pending: parking_lot::Mutex::new(SynackPending::default()),
            closed: AtomicBool::new(false),
            created: Instant::now(),
            session_state: AtomicUsize::new(crate::session::SessionState::Active as usize),
            terminal_error: std::sync::OnceLock::new(),
            killed_streams: Mutex::new(HashSet::new()),
            overflow: parking_lot::Mutex::new(OverflowState::default()),
            overflow_notify: tokio::sync::Notify::new(),
            stream_permits: Arc::new(tokio::sync::Semaphore::new(MAX_STREAMS_PER_SESSION)),
            idle: crate::session::IdleClock::new(),
            capacity_notify: std::sync::OnceLock::new(),
            inbound_payload_budget,
            inbound_budget_epoch: AtomicU64::new(0),
            demux: Mutex::new(None),
            rx_frame_seq: AtomicU64::new(0),
            task_scope: crate::runtime::TaskScope::capture(),
            observations: parking_lot::Mutex::new(HashMap::new()),
        });
        session.inbound_payload_budget.register(&session);

        let demux_handle = {
            let session = Arc::clone(&session);
            crate::runtime::spawn_owned(async move { session_demux(session, transport_read).await })
        };
        *session.demux.lock().unwrap() = demux_handle;
        let writer_handle = {
            let session = Arc::clone(&session);
            let queue = Arc::clone(&session.writer_q);
            crate::runtime::spawn_owned(async move {
                session_writer(session, transport_write, queue).await
            })
        };
        *session.writer_task.lock().unwrap() = writer_handle;

        debug!("AnyTLS session {} for {} established", session.seq, addr);
        Ok(session)
    }

    fn observe_request(&self, sid: u32, uot: bool) {
        // Inert builds register no observers; skip the per-frame lock.
        if !cfg!(feature = "flow-observation") {
            return;
        }
        let mut observations = self.observations.lock();
        let Some(observation) = observations.get_mut(&sid) else {
            return;
        };
        if observation.uot != uot || observation.request_sent {
            return;
        }
        observation.request_sent = true;
        observation
            .observer
            .milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
        if !observation.uot && observation.confirmation == Some(true) {
            observation
                .observer
                .milestone_once(crate::runtime::flow_observation::Milestone::TargetConfirmed);
        }
        if observation.uot || observation.confirmation.is_some() {
            observations.remove(&sid);
        }
    }

    fn observe_synack(&self, sid: u32, accepted: bool) {
        let mut observations = self.observations.lock();
        let Some(observation) = observations.get_mut(&sid) else {
            return;
        };
        // UoT's SYNACK acknowledges the magic service, not the datagram target.
        if observation.uot {
            return;
        }
        observation.confirmation = Some(accepted);
        if observation.request_sent {
            if accepted {
                observation
                    .observer
                    .milestone_once(crate::runtime::flow_observation::Milestone::TargetConfirmed);
            }
            observations.remove(&sid);
        }
    }

    fn end_observation(&self, sid: u32) {
        self.observations.lock().remove(&sid);
    }

    #[cfg(test)]
    fn flush_initial_settings_for_test(&self) -> std::io::Result<()> {
        let Some(settings) = self.initial_settings.lock().take() else {
            return Ok(());
        };
        self.enqueue_control(CMD_SETTINGS, 0, settings)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn register_synack(&self, sid: u32) {
        if sid < 2 || !self.peer_supports_synack.load(Ordering::Acquire) {
            return;
        }
        self.synack_pending.lock().sids.insert(sid, None);
    }

    /// The SYN is on the wire; start its deadline. A fast peer may have
    /// acked while the frame sat in the queue — then there is nothing to arm.
    /// `activity_marker` is the inbound frame count sampled just before the
    /// write, so frames received while a blocked flush was in flight still
    /// count as session activity.
    fn start_synack_deadline(self: &Arc<Self>, sid: u32, activity_marker: u64) {
        let mut pending = self.synack_pending.lock();
        let Some(slot) = pending.sids.get_mut(&sid) else {
            return;
        };
        if slot.is_some() || self.is_closed() {
            return;
        }
        let session = Arc::clone(self);
        *slot = self.task_scope.spawn(async move {
            tokio::time::sleep(SYNACK_TIMEOUT).await;
            let overdue = session.synack_pending.lock().sids.remove(&sid).is_some();
            if !overdue {
                return;
            }
            let budget_waiting = session.inbound_budget_epoch.load(Ordering::SeqCst) & 1 != 0;
            if budget_waiting || session.rx_frame_seq.load(Ordering::Relaxed) > activity_marker {
                // SYNACK follows the target dial; UoT instead opens the
                // proxy's magic service, so its failure stays node-scoped.
                let error = anyhow::anyhow!("stream open not acknowledged");
                let error = if session.tcp_sink_is_live(sid) {
                    anyhow::Error::new(crate::proxy::TargetFailure(error))
                } else {
                    anyhow::Error::new(crate::proxy::NodeFailure(error))
                };
                session
                    .dispatch_error(sid, crate::SharedError::new(error))
                    .await;
            } else {
                // Loss bursts silence every stream at once and TCP delivers
                // afterwards, so one missed open must not reset its siblings:
                // stop offering the carrier, fail only this open, and retire the
                // carrier if it stays silent through the grace period.
                crate::session::ManagedSession::begin_drain(&*session);
                let silent_marker = session.rx_frame_seq.load(Ordering::Relaxed);
                let error = anyhow::anyhow!("stream {sid} SYNACK timed out after {SYNACK_TIMEOUT:?}");
                session
                    .dispatch_error(
                        sid,
                        crate::SharedError::new(anyhow::Error::new(crate::proxy::NodeFailure(error))),
                    )
                    .await;
                tokio::time::sleep(SILENT_SESSION_GRACE).await;
                if !session.is_closed()
                    && session.rx_frame_seq.load(Ordering::Relaxed) == silent_marker
                {
                    session.fail(anyhow::anyhow!(
                        "session silent for {SILENT_SESSION_GRACE:?} after stream {sid} SYNACK timeout"
                    ));
                }
            }
        });
    }

    /// Settle a pending open: cancel its deadline and drop the entry. A SYNACK
    /// settles only its own SID; a locally torn-down stream must do the same,
    /// or its orphaned timer fires later and fails a healthy session.
    fn settle_syn_pending(&self, sid: u32) {
        if let Some(timer) = self.synack_pending.lock().sids.remove(&sid).flatten() {
            timer.abort();
        }
    }

    fn clear_synack_pending(&self) {
        for (_, timer) in self.synack_pending.lock().sids.drain() {
            if let Some(timer) = timer {
                timer.abort();
            }
        }
    }

    fn session_error(&self, kind: std::io::ErrorKind, message: &'static str) -> std::io::Error {
        match self.terminal_error.get() {
            Some(error) => std::io::Error::new(kind, error.clone()),
            None => std::io::Error::new(kind, message),
        }
    }

    fn writer_queue_error(&self) -> std::io::Error {
        let overloaded = !self.writer_q.is_closed();
        if overloaded {
            self.fail(anyhow::anyhow!("writer queue capacity exceeded"));
        }
        self.session_error(
            std::io::ErrorKind::ConnectionAborted,
            if overloaded {
                "AnyTLS writer queue capacity exceeded"
            } else {
                "AnyTLS writer queue is closed"
            },
        )
    }

    /// Open streams on this session (capacity taken from the semaphore —
    /// the single truth; `MAX_STREAMS_PER_SESSION - available`).
    fn active_streams(&self) -> usize {
        MAX_STREAMS_PER_SESSION - self.stream_permits.available_permits()
    }

    /// Enqueue a control frame (SYN/FIN/HEART): ordered, reserved
    /// headroom, uncancellable once queued. Exhausting the bounded queue
    /// makes the shared session terminal rather than growing memory.
    fn enqueue_control(&self, cmd: u8, sid: u32, payload: bytes::Bytes) -> std::io::Result<()> {
        if self.is_closed() {
            return Err(self.session_error(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        self.writer_q
            .push_batch([FrameCommand::Control { cmd, sid, payload }])
            .map_err(|_| self.writer_queue_error())
    }

    /// Enqueue a payload PSH for a stream: bounded by the writer-queue
    /// data permits, so a fast stream backpressures here instead of
    /// growing memory. Uncancellable once queued.
    async fn enqueue_data(&self, sid: u32, payload: bytes::Bytes) -> std::io::Result<()> {
        if self.is_closed() {
            return Err(self.session_error(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        let permit = self.acquire_data_permit(payload.len()).await?;
        self.enqueue_data_with_permit(sid, payload, permit)
    }

    /// Enqueue one frame and wait until the session writer flushes its batch.
    /// Used where an enqueue acknowledgement would turn writer loss into a
    /// false successful send.
    async fn enqueue_confirmed_data(&self, sid: u32, payload: bytes::Bytes) -> std::io::Result<()> {
        let permit = self.acquire_data_permit(payload.len()).await?;
        let completed = self.enqueue_confirmed_data_with_permit(sid, payload, permit)?;
        self.wait_for_confirmed_data(completed).await
    }

    fn enqueue_confirmed_data_with_permit(
        &self,
        sid: u32,
        payload: bytes::Bytes,
        permit: DataPermit,
    ) -> std::io::Result<tokio::sync::oneshot::Receiver<bool>> {
        let (completion, completed) = tokio::sync::oneshot::channel();
        let queued = {
            let streams = self.streams.lock().unwrap();
            if !streams.contains_key(&sid) {
                return Err(self.stream_not_registered_error());
            }
            if self.is_closed() {
                return Err(self.session_error(
                    std::io::ErrorKind::ConnectionAborted,
                    "AnyTLS session is closed",
                ));
            }
            self.writer_q.push_batch([FrameCommand::Data {
                sid,
                payload,
                _permit: permit,
                completion: Some(completion),
            }])
        };
        queued.map_err(|_| self.writer_queue_error())?;
        Ok(completed)
    }

    async fn wait_for_confirmed_data(
        &self,
        completed: tokio::sync::oneshot::Receiver<bool>,
    ) -> std::io::Result<()> {
        match completed.await {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(self.session_error(
                std::io::ErrorKind::BrokenPipe,
                "AnyTLS writer failed before flushing frame",
            )),
        }
    }

    /// Acquire a writer-queue data permit for a `bytes`-long payload
    /// (async): one frame slot, then the payload's bytes.
    async fn acquire_data_permit(&self, bytes: usize) -> std::io::Result<DataPermit> {
        if self.is_closed() {
            return Err(self.session_error(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        let closed = || {
            self.session_error(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS writer queue is closed",
            )
        };
        let frame = Arc::clone(&self.writer_q.data_permits)
            .acquire_owned()
            .await
            .map_err(|_| closed())?;
        let bytes = Arc::clone(&self.writer_q.data_bytes)
            .acquire_many_owned(Self::byte_permits(bytes))
            .await
            .map_err(|_| closed())?;
        Ok(DataPermit {
            _frame: frame,
            _bytes: bytes,
        })
    }

    /// Frame payloads are at most `u16::MAX`, far below the byte cap, so a
    /// request can always be satisfied once the queue drains.
    fn byte_permits(bytes: usize) -> u32 {
        debug_assert!(bytes <= WRITER_DATA_BYTES_CAP);
        u32::try_from(bytes.min(WRITER_DATA_BYTES_CAP)).expect("byte cap fits u32")
    }

    /// Try to enqueue a data frame without waiting; returns the payload
    /// back when the writer queue is full (caller keeps it in its slot).
    fn try_enqueue_data(&self, sid: u32, payload: bytes::Bytes) -> Result<(), bytes::Bytes> {
        if self.is_closed() {
            return Err(payload);
        }
        let Ok(frame) = Arc::clone(&self.writer_q.data_permits).try_acquire_owned() else {
            return Err(payload);
        };
        let Ok(bytes) = Arc::clone(&self.writer_q.data_bytes)
            .try_acquire_many_owned(Self::byte_permits(payload.len()))
        else {
            return Err(payload);
        };
        match self.writer_q.push_batch([FrameCommand::Data {
            sid,
            payload,
            _permit: DataPermit {
                _frame: frame,
                _bytes: bytes,
            },
            completion: None,
        }]) {
            Ok(()) => Ok(()),
            Err(commands) => {
                let [FrameCommand::Data { payload, .. }] = commands else {
                    unreachable!("queued one data command")
                };
                let _ = self.writer_queue_error();
                Err(payload)
            }
        }
    }

    /// Enqueue a data frame with an already-acquired permit.
    fn enqueue_data_with_permit(
        &self,
        sid: u32,
        payload: bytes::Bytes,
        permit: DataPermit,
    ) -> std::io::Result<()> {
        let queued = {
            let streams = self.streams.lock().unwrap();
            if !streams.contains_key(&sid) {
                return Err(self.stream_not_registered_error());
            }
            if self.is_closed() {
                return Err(self.session_error(
                    std::io::ErrorKind::ConnectionAborted,
                    "AnyTLS session is closed",
                ));
            }
            self.writer_q.push_batch([FrameCommand::Data {
                sid,
                payload,
                _permit: permit,
                completion: None,
            }])
        };
        queued.map_err(|_| self.writer_queue_error())
    }

    async fn write_uot_datagram(&self, sid: u32, payload: bytes::Bytes) -> std::io::Result<()> {
        self.ensure_stream_registered(sid)?;
        self.enqueue_data(sid, payload).await
    }

    async fn write_uot_datagram_confirmed(
        &self,
        sid: u32,
        payload: bytes::Bytes,
    ) -> std::io::Result<()> {
        self.ensure_stream_registered(sid)?;
        self.enqueue_confirmed_data(sid, payload).await
    }

    async fn register_and_open(
        self: &Arc<Self>,
        target_addr: Vec<u8>,
        sink: StreamSink,
        tcp_inbound: Option<Arc<TcpInbound>>,
        permit: crate::session::SessionPermit<Self>,
    ) -> anyhow::Result<(u32, StreamRegistration)> {
        if self.is_closed() {
            anyhow::bail!("AnyTLS session {} is closed", self.seq);
        }
        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(observer) = crate::runtime::flow_observation::current() {
            self.observations.lock().insert(
                sid,
                StreamObservation {
                    observer,
                    uot: matches!(&sink, StreamSink::Uot(_)),
                    request_sent: false,
                    confirmation: None,
                },
            );
        }
        if let Some(inbound) = tcp_inbound {
            self.tcp_inbound.lock().insert(sid, inbound);
        }
        self.streams.lock().unwrap().insert(sid, sink);
        let mut guard = StreamRegistration {
            session: Arc::clone(self),
            sid,
            frame_started: true,
            committed: false,
            permit: Some(permit),
        };

        if self.is_closed() {
            return Err(anyhow::anyhow!("AnyTLS session {} is closed", self.seq));
        }
        self.register_synack(sid);
        let mut initial_settings = self.initial_settings.lock();
        // Keep ownership through the queue write: another opener must not enqueue SYN first.
        let queued = if let Some(settings) = initial_settings.take() {
            self.writer_q
                .push_batch([
                    FrameCommand::Control {
                        cmd: CMD_SETTINGS,
                        sid: 0,
                        payload: settings,
                    },
                    FrameCommand::Control {
                        cmd: CMD_SYN,
                        sid,
                        payload: bytes::Bytes::new(),
                    },
                    FrameCommand::Control {
                        cmd: CMD_PSH,
                        sid,
                        payload: bytes::Bytes::from(target_addr),
                    },
                ])
                .map_err(drop)
        } else {
            self.writer_q
                .push_batch([
                    FrameCommand::Control {
                        cmd: CMD_SYN,
                        sid,
                        payload: bytes::Bytes::new(),
                    },
                    FrameCommand::Control {
                        cmd: CMD_PSH,
                        sid,
                        payload: bytes::Bytes::from(target_addr),
                    },
                ])
                .map_err(drop)
        };
        drop(initial_settings);
        queued.map_err(|_| self.writer_queue_error())?;
        guard.frame_started = false;
        Ok((sid, guard))
    }

    async fn open_uot_stream(
        self: &Arc<Self>,
        target_addr: Vec<u8>,
        permit: crate::session::SessionPermit<Self>,
    ) -> anyhow::Result<(u32, mpsc::Receiver<StreamEvent>, StreamRegistration)> {
        let (tx, rx) = mpsc::channel(UOT_DRAIN_QUEUE_CAP);
        let (sid, guard) = self
            .register_and_open(target_addr, StreamSink::Uot(tx), None, permit)
            .await?;
        debug!("AnyTLS session {} opened uot sid={}", self.seq, sid);
        Ok((sid, rx, guard))
    }

    fn stream_not_registered_error(&self) -> std::io::Error {
        self.session_error(
            std::io::ErrorKind::BrokenPipe,
            "AnyTLS stream is no longer registered",
        )
    }

    fn ensure_stream_registered(&self, sid: u32) -> std::io::Result<()> {
        self.streams
            .lock()
            .unwrap()
            .contains_key(&sid)
            .then_some(())
            .ok_or_else(|| self.stream_not_registered_error())
    }

    fn tcp_sink_is_live(&self, sid: u32) -> bool {
        matches!(
            self.streams.lock().unwrap().get(&sid),
            Some(StreamSink::Tcp(tx)) if !tx.is_closed()
        )
    }

    fn oldest_inbound_stall(&self) -> Option<(Instant, u32)> {
        self.tcp_inbound
            .lock()
            .iter()
            .filter_map(|(&sid, inbound)| inbound.stalled_since().map(|since| (since, sid)))
            .min()
    }

    fn reap_inbound_stall(&self, sid: u32, now: Instant) -> bool {
        let inbound = {
            let inbound = self.tcp_inbound.lock();
            let Some(inbound) = inbound.get(&sid) else {
                return false;
            };
            Arc::clone(inbound)
        };
        let _delivery = inbound.delivery_guard();
        let Some((since, retained_bytes, queue_capacity)) =
            inbound.reap_if_stalled(now, || self.kill_stream(sid))
        else {
            return false;
        };
        let stalled_for = now.saturating_duration_since(since);
        let mut registered = self.tcp_inbound.lock();
        if registered
            .get(&sid)
            .is_some_and(|current| Arc::ptr_eq(current, &inbound))
        {
            registered.remove(&sid);
        }
        drop(registered);
        let stall_ms = u64::try_from(stalled_for.as_millis()).unwrap_or(u64::MAX);
        warn!(
            session = self.seq,
            victim_sid = sid,
            retained_bytes,
            stall_ms,
            stream_killed = queue_capacity.is_some(),
            "AnyTLS inbound payload budget reaped stalled retention"
        );
        if queue_capacity.is_some()
            && self
                .enqueue_control(CMD_FIN, sid, bytes::Bytes::new())
                .is_err()
        {
            self.fail(anyhow::anyhow!(
                "writer queue unavailable on inbound budget kill"
            ));
        }
        true
    }

    /// TCP payload must not be dropped, unlike UoT.
    async fn open_stream_direct(
        self: &Arc<Self>,
        target_addr: Vec<u8>,
        permit: crate::session::SessionPermit<Self>,
    ) -> anyhow::Result<AnyTlsStream> {
        let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
        let receive = Arc::new(parking_lot::Mutex::new(TcpReceiveState::new(rx)));
        let inbound = TcpInbound::new(&receive);
        let (sid, guard) = self
            .register_and_open(target_addr, StreamSink::Tcp(tx), Some(inbound), permit)
            .await?;
        let permit = guard.commit();
        debug!("AnyTLS session {} opened direct sid={}", self.seq, sid);
        Ok(AnyTlsStream::from_receive(
            Arc::clone(self),
            sid,
            receive,
            permit,
        ))
    }

    /// Unregister a UoT stream, optionally notifying the server with FIN.
    /// Stream capacity is released by the transport permit, not this map.
    fn end_uot_stream(&self, sid: u32, notify_fin: bool) {
        self.settle_syn_pending(sid);
        self.end_observation(sid);
        let (was_registered, received_fin) = {
            let mut remote_fin = self.remote_fin.lock();
            let received_fin = remote_fin.remove(&sid);
            let was_registered = self.streams.lock().unwrap().remove(&sid).is_some();
            (was_registered, received_fin)
        };
        if notify_fin && was_registered && !received_fin {
            let _ = self.enqueue_control(CMD_FIN, sid, bytes::Bytes::new());
        }
        debug!("AnyTLS session {} sid={} uot stream ended", self.seq, sid);
    }

    /// Unregister a stream, optionally notifying the server with FIN. This is
    /// synchronous so cleanup is ordered before the stream permit is dropped.
    /// Returns whether an overflow or byte-budget reap had killed this stream.
    fn end_stream(&self, sid: u32, notify_fin: bool) -> bool {
        self.settle_syn_pending(sid);
        self.end_observation(sid);
        let (was_registered, received_fin, was_killed) = {
            let mut remote_fin = self.remote_fin.lock();
            let mut killed_streams = self.killed_streams.lock().unwrap();
            let received_fin = remote_fin.remove(&sid);
            let was_killed = killed_streams.remove(&sid);
            let was_registered = self.streams.lock().unwrap().remove(&sid).is_some();
            (was_registered, received_fin, was_killed)
        };

        self.discard_overflow(sid);
        self.tcp_inbound.lock().remove(&sid);
        if notify_fin && was_registered && !received_fin {
            let _ = self.enqueue_control(CMD_FIN, sid, bytes::Bytes::new());
        }
        debug!("AnyTLS session {} sid={} stream ended", self.seq, sid);
        was_killed
    }

    fn kill_stream(&self, sid: u32) -> Option<usize> {
        self.settle_syn_pending(sid);
        self.end_observation(sid);
        let queue_capacity = {
            let mut remote_fin = self.remote_fin.lock();
            let mut killed_streams = self.killed_streams.lock().unwrap();
            let mut streams = self.streams.lock().unwrap();
            let Some(StreamSink::Tcp(tx)) = streams.get(&sid).cloned() else {
                return None;
            };
            if tx.is_closed() {
                return None;
            }
            streams.remove(&sid);
            remote_fin.remove(&sid);
            killed_streams.insert(sid);
            tx.capacity()
        };

        self.discard_overflow(sid);
        Some(queue_capacity)
    }

    /// Mark a registered stream before queueing its remote FIN event. The
    /// lock order matches the end_* methods so Drop cannot race the marker.
    fn mark_remote_fin(&self, sid: u32) -> Option<StreamSink> {
        let mut remote_fin = self.remote_fin.lock();
        let sink = self.streams.lock().unwrap().get(&sid).cloned();
        if sink.is_some() {
            remote_fin.insert(sid);
        }
        sink
    }

    /// Record the first physical-failure reason and close: streams
    /// report the reason after draining queued data.
    fn fail(&self, reason: anyhow::Error) {
        let _ = self.terminal_error.set(crate::SharedError::fanout(
            crate::proxy::NodeFailure(reason).into(),
        ));
        self.close();
    }

    /// Close the session: flag it, drop all stream dispatch channels (their
    /// tasks EOF the client side and exit), stop the demux, shut down the
    /// write half. Idempotent. Pool pruning happens on the next
    /// `SessionPool::offer`/janitor pass (closed sessions are retained
    /// never).
    fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.session_state.store(
            crate::session::SessionState::Closed as usize,
            Ordering::Release,
        );
        self.remote_fin.lock().clear();
        self.streams.lock().unwrap().clear();
        self.clear_overflow();
        if let Some(handle) = self.demux.lock().unwrap().take() {
            handle.abort();
        }
        if let Some(handle) = self.writer_task.lock().unwrap().take() {
            handle.abort();
        }
        self.clear_synack_pending();
        self.observations.lock().clear();
        self.writer_q.close();
        if let Some(notify) = self.capacity_notify.get() {
            notify.notify_waiters();
        }
        debug!("AnyTLS session {} for {} closed", self.seq, self.addr);
    }

    /// Deliver a server TCP payload without blocking the demultiplexer.
    /// Full per-stream queues park in SID order until reader progress; a
    /// consumer is reset only once the session cap or byte budget is hit.
    #[cfg(test)]
    async fn dispatch_data(self: &Arc<Self>, sid: u32, data: Vec<u8>) {
        let (credit, _wait) = self
            .inbound_payload_budget
            .acquire(self, sid, data.len())
            .await
            .expect("test session payload budget open");
        let credit = credit.expect("test stream remains live");
        let data = bytes::Bytes::from(data);
        let payload = match self.tcp_inbound.lock().get(&sid).cloned() {
            Some(inbound) => InboundPayload::for_tcp(data, credit, inbound),
            None => InboundPayload::new(data, credit),
        };
        self.dispatch_payload(sid, payload).await;
    }

    async fn dispatch_payload(self: &Arc<Self>, sid: u32, data: InboundPayload) {
        let Some(StreamSink::Tcp(tx)) = self.streams.lock().unwrap().get(&sid).cloned() else {
            return;
        };
        let delivery_owner = data.delivery_owner();
        let delivery = delivery_owner.delivery_guard();
        if !self.tcp_sink_is_live(sid) {
            return;
        }
        if self.overflow_has(sid) {
            drop(delivery);
            self.park_overflow(sid, StreamEvent::Data(data)).await;
            return;
        }
        let result = tx.try_send(StreamEvent::Data(data));
        drop(delivery);
        match result {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(ev)) => {
                self.park_overflow(sid, ev).await;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.end_stream(sid, false);
            }
        }
    }

    async fn dispatch_fin(self: &Arc<Self>, sid: u32) {
        if self.overflow_has(sid) {
            if self.mark_remote_fin(sid).is_some() {
                self.park_overflow(sid, StreamEvent::Fin).await;
            }
            return;
        }
        let sink = self.mark_remote_fin(sid);
        match sink {
            Some(StreamSink::Tcp(tx)) => match tx.try_send(StreamEvent::Fin) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(event)) => {
                    self.park_overflow(sid, event).await;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.end_stream(sid, false);
                }
            },
            Some(StreamSink::Uot(tx)) => match tx.try_send(StreamEvent::Fin) {
                Ok(()) => {}
                Err(_) => self.end_uot_stream(sid, false),
            },
            None => {}
        }
    }

    async fn dispatch_error(self: &Arc<Self>, sid: u32, message: crate::SharedError) {
        let sink = self.streams.lock().unwrap().get(&sid).cloned();
        match sink {
            Some(StreamSink::Tcp(tx)) => {
                if self.overflow_has(sid) {
                    self.park_overflow(sid, StreamEvent::Error(message)).await;
                    return;
                }
                match tx.try_send(StreamEvent::Error(message)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(event)) => {
                        self.park_overflow(sid, event).await;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.end_stream(sid, false);
                    }
                }
            }
            Some(StreamSink::Uot(tx)) => match tx.try_send(StreamEvent::Error(message)) {
                Ok(()) => {}
                Err(_) => self.end_uot_stream(sid, false),
            },
            None => {}
        }
    }
}

fn server_synack_setting(data: &[u8]) -> Option<bool> {
    let mut value = None;
    for line in data.split(|byte| *byte == b'\n') {
        if let Some(version) = line.strip_prefix(b"v=") {
            value = Some(version);
        }
    }
    let version = std::str::from_utf8(value?).ok()?.parse::<i64>().ok()?;
    Some((version as u8) >= 2)
}

impl crate::session::ManagedSession for AnyTlsSession {
    fn active_streams(&self) -> usize {
        MAX_STREAMS_PER_SESSION - self.stream_permits.available_permits()
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
    fn close(&self) {
        AnyTlsSession::close(self)
    }
    fn bind_capacity_notify(&self, notify: Arc<tokio::sync::Notify>) {
        if let Err(notify) = self.capacity_notify.set(notify) {
            assert!(
                Arc::ptr_eq(self.capacity_notify.get().unwrap(), &notify),
                "session cannot belong to multiple pools"
            );
        }
    }
    fn state(&self) -> crate::session::SessionState {
        match self.session_state.load(Ordering::Acquire) {
            0 => crate::session::SessionState::Active,
            1 => crate::session::SessionState::Draining,
            _ => crate::session::SessionState::Closed,
        }
    }
    /// GOAWAY/max-age: stop taking new streams; the pool stops offering
    /// this session and existing streams run to the end.
    fn begin_drain(&self) {
        if self
            .session_state
            .compare_exchange(
                crate::session::SessionState::Active as usize,
                crate::session::SessionState::Draining as usize,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
            && let Some(notify) = self.capacity_notify.get()
        {
            notify.notify_waiters();
        }
    }
    fn created_at(&self) -> Instant {
        self.created
    }
    /// Active → acquire → re-check Active: a session that began draining
    /// in between releases the slot immediately instead of taking one
    /// more stream it will never serve.
    fn try_reserve(self: &Arc<Self>) -> Option<crate::session::SessionPermit<Self>> {
        use crate::session::{SessionPermit, SessionState};
        if self.state() != SessionState::Active {
            return None;
        }
        let permit = Arc::clone(&self.stream_permits).try_acquire_owned().ok()?;
        if self.state() != SessionState::Active {
            drop(permit);
            return None;
        }
        self.idle.stream_opened();
        Some(SessionPermit::new(Arc::clone(self), permit))
    }
    fn permit_released(&self) {
        self.idle.stream_released(self.active_streams());
    }
    fn idle_since(&self) -> Option<Instant> {
        self.idle.idle_since()
    }
}

#[allow(
    clippy::manual_async_fn,
    reason = "the MuxSession trait requires an allocation-free Send future"
)]
impl super::MuxSession for AnyTlsSession {
    type Stream = AnyTlsStream;
    type Packet = AnyTlsUotTransport;

    fn open_stream(
        self: Arc<Self>,
        permit: crate::session::SessionPermit<Self>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> impl Future<Output = Result<Self::Stream, crate::session::OpenError>> + Send {
        async move {
            debug!(
                "AnyTLS: multiplexing on session {} ({} open stream(s))",
                self.seq,
                self.active_streams(),
            );
            let address = addr::encode_address(target, target_domain)
                .map_err(|error| crate::session::OpenError::Refused(anyhow::Error::new(error)))?;
            self.open_stream_direct(address, permit)
                .await
                .map_err(|error| {
                    if self.is_closed() {
                        crate::session::OpenError::Session(error)
                    } else {
                        crate::session::OpenError::Refused(error)
                    }
                })
        }
    }

    fn open_packet(
        self: Arc<Self>,
        permit: crate::session::SessionPermit<Self>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> impl Future<Output = Result<Arc<Self::Packet>, crate::session::OpenError>> + Send {
        async move {
            let setup = crate::proxy::uot::connect_request(target, target_domain)
                .map_err(|error| crate::session::OpenError::Refused(anyhow::Error::new(error)))?;
            let magic = addr::encode_address(
                "0.0.0.0:0".parse().unwrap(),
                Some(crate::proxy::uot::MAGIC_ADDRESS),
            )
            .expect("UoT magic domain fits SOCKS address");
            let (sid, rx, guard) = self.open_uot_stream(magic, permit).await.map_err(|error| {
                if self.is_closed() {
                    crate::session::OpenError::Session(error)
                } else {
                    crate::session::OpenError::Refused(error)
                }
            })?;
            let permit = guard.commit();
            Ok(Arc::new(AnyTlsUotTransport {
                session: self,
                sid,
                receive: tokio::sync::Mutex::new(UotReceiveState::new(rx)),
                setup: tokio::sync::Mutex::new(Some(setup)),
                target,
                target_domain: target_domain.map(str::to_string),
                _permit: permit,
            }))
        }
    }
}

/// Dial a fresh TLS + AnyTLS session (the `SessionPool::offer` dial
/// closure and the janitor's prewarm share this).
async fn dial_session(
    node: &Node,
    addr: &str,
    connect_timeout: Duration,
    tls_connector: Option<Arc<TlsConnector>>,
    padding_state: Arc<PaddingState>,
    inbound_payload_budget: Arc<InboundPayloadBudget>,
) -> anyhow::Result<Arc<AnyTlsSession>> {
    let timeout = connect_timeout.saturating_mul(3);
    tokio::time::timeout(timeout, async {
        let padding = padding_state.snapshot();
        let settings = padding.settings_payload();
        let (read, write, auth) =
            connect_transport(node, addr, connect_timeout, tls_connector, &padding).await?;
        AnyTlsSession::establish(
            addr,
            read,
            write,
            &auth,
            settings,
            padding_state,
            inbound_payload_budget,
        )
        .await
    })
    .await
    .map_err(|_| anyhow::anyhow!("AnyTLS session dial timed out after {timeout:?}"))?
}

fn authentication_payload(password: &str, padding: &PaddingScheme) -> Vec<u8> {
    let auth_key: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    let padding_len = padding.auth_padding_len();
    let mut auth = vec![0u8; 34 + padding_len];
    auth[..32].copy_from_slice(&auth_key);
    auth[32..34].copy_from_slice(&(padding_len as u16).to_be_bytes());
    auth
}

/// Connect to the AnyTLS server, wrap it in TLS, and build packet 0 authentication.
async fn connect_transport(
    node: &Node,
    addr: &str,
    connect_timeout: Duration,
    tls_connector: Option<Arc<TlsConnector>>,
    padding: &PaddingScheme,
) -> anyhow::Result<(BoxedReader, BoxedWriter, Vec<u8>)> {
    let password = node.anytls().unwrap().password.as_deref().unwrap_or("");
    let auth = authentication_payload(password, padding);
    let tcp = crate::util::connect_outbound(addr, connect_timeout).await?;
    let tcp = crate::transport_quality::tcp::ObservedTcp::new(tcp);
    debug!("AnyTLS: TCP connected to {}", addr);

    let connector = match tls_connector {
        Some(connector) => connector,
        None => Arc::new(crate::tls::build_connector(node)?),
    };
    let server_name = node
        .anytls()
        .unwrap()
        .tls
        .sni
        .clone()
        .unwrap_or_else(|| node.host().to_string());
    let mut tls = tokio::time::timeout(connect_timeout, connector.connect(&server_name, tcp))
        .await
        .map_err(|_| {
            anyhow::anyhow!("AnyTLS TLS handshake timed out after {connect_timeout:?}")
        })??;
    tls.get_mut().activate();
    crate::runtime::flow_observation::milestone(
        crate::runtime::flow_observation::Milestone::TransportReady,
    );
    debug!("AnyTLS: TLS handshake completed with {}", addr);
    let (read, write) = tokio::io::split(crate::tls::BatchRead::new(tls));

    Ok((Box::new(read), Box::new(write), auth))
}

impl AnyTlsHandler {
    /// Create a new AnyTLS handler.
    pub fn new() -> Self {
        Self
    }

    /// Lazily start the pool janitor for this node (once per pool).
    fn ensure_janitor(
        node: &Node,
        pool: &Arc<AnyTlsPool>,
        runtime: Option<Arc<crate::runtime::NodeRuntime>>,
    ) {
        let config = node.anytls().unwrap();
        let min_idle = config.min_idle_session.unwrap_or(0);
        let idle_timeout = Duration::from_secs(
            config
                .idle_session_timeout
                .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS),
        );
        let prewarm_node = node.clone();
        let label = format!("{}:{}", node.host(), node.port);
        let padding_state = pool.padding_state();
        let inbound_payload_budget = pool.inbound_payload_budget();
        pool.ensure_janitor(min_idle, idle_timeout, move || {
            let node = prewarm_node.clone();
            let label = label.clone();
            let runtime = runtime.clone();
            let padding_state = Arc::clone(&padding_state);
            let inbound_payload_budget = Arc::clone(&inbound_payload_budget);
            async move {
                let tls_connector = runtime
                    .as_ref()
                    .map(|runtime| runtime.anytls_tls_connector())
                    .transpose()?;
                let dial = dial_session(
                    &node,
                    &label,
                    Duration::from_secs(10),
                    tls_connector,
                    padding_state,
                    inbound_payload_budget,
                );
                match runtime {
                    Some(runtime) => runtime.transport_quality().scope(dial).await,
                    None => dial.await,
                }
            }
        });
    }

    /// Warm the explicit generation-owned AnyTLS pool. The generic dial seam
    /// keeps the production path small while letting unit tests use the
    /// in-memory AnyTLS session fixture instead of a network connection.
    async fn warm_pool_with<F, Fut>(
        runtime: Arc<crate::runtime::NodeRuntime>,
        dial: F,
    ) -> anyhow::Result<()>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<Arc<AnyTlsSession>>> + Send + 'static,
    {
        let warm = async {
            let pool = runtime.anytls_pool()?;
            Self::ensure_janitor(&runtime.node, &pool, Some(Arc::clone(&runtime)));
            let _session = pool.offer(dial).await?;
            if !pool.has_usable_session() {
                anyhow::bail!("AnyTLS warm dial completed without a usable session");
            }
            Ok(())
        };
        let warm = crate::runtime::flow_observation::without(warm);
        warm.await
    }

    /// Prepare an AnyTLS UoT transport on an explicitly captured pool without
    /// publishing a detached session or starting the janitor. The injected
    /// dial seam keeps cancellation observable in tests.
    async fn dial_udp_transport_speculative_for_pool_with<F, Fut>(
        node: &Node,
        pool: Arc<AnyTlsPool>,
        target: SocketAddr,
        target_domain: Option<&str>,
        runtime: Option<Arc<crate::runtime::NodeRuntime>>,
        dial: F,
    ) -> anyhow::Result<PreparedUdpTransport>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = anyhow::Result<Arc<AnyTlsSession>>> + Send,
    {
        if !crate::descriptor::network_allows_udp(node) {
            anyhow::bail!("node '{}' does not allow UDP", node.name);
        }
        pool.sessions.bind_current_dial_admission_if_unbound();

        let (session, permit, detached) = match pool.checkout_speculative().await? {
            SpeculativeCheckout::Shared { session, permit } => (session, permit, None),
            SpeculativeCheckout::Detached(mut reservation) => {
                let session = tokio::select! {
                    result = dial() => result?,
                    _ = reservation.cancelled() => {
                        anyhow::bail!("AnyTLS speculative dial cancelled by pool shutdown")
                    }
                };
                let permit = reservation.attach(&session)?;
                (session, permit, Some(reservation))
            }
        };

        let transport = session
            .open_packet(permit, target, target_domain)
            .await
            .map_err(|error| match error {
                crate::session::OpenError::Session(error)
                | crate::session::OpenError::Draining(error)
                | crate::session::OpenError::Refused(error) => error,
            })?;
        let transport: Arc<dyn PacketTransport> = transport;

        let commit_node = node.clone();
        Ok(PreparedUdpTransport::new(async move {
            if let Some(reservation) = detached {
                reservation.commit()?;
            }
            if runtime.is_some() {
                Self::ensure_janitor(&commit_node, &pool, runtime);
            }
            Ok(transport)
        }))
    }
}

/// Direct `AsyncRead`/`AsyncWrite` over a session stream. Avoiding an
/// intermediate duplex bridge removes two task hops and two copies per byte.
pub(crate) struct AnyTlsStream {
    session: Arc<AnyTlsSession>,
    sid: u32,
    receive: Arc<parking_lot::Mutex<TcpReceiveState>>,
    /// Set when the Fin/disconnect event was consumed in the same poll
    /// that also delivered data: the data goes out now, the zero-byte
    /// EOF is owed to the next poll (a consumed Fin is otherwise lost
    /// and the relay hangs forever).
    read_eof: bool,
    /// A stream-level failure consumed after data was already delivered
    /// in the same poll: the error is owed to the next poll (data
    /// first, then the error — never silently merge them).
    read_err: Option<std::io::Error>,
    /// Outbound frame slot: the payload is owned by the stream until it
    /// is enqueued, so a resumed write cannot enqueue it twice, and a
    /// cancelled one queued nothing to lose. `poll_write` only returns
    /// `Ok(n)` after exactly these `n` bytes were queued (never a number
    /// derived from a different call's buffer).
    out_slot: Option<(bytes::Bytes, usize)>,
    /// Waiter for a writer-queue data permit while `out_slot` is occupied.
    permit_fut: Option<std::pin::Pin<Box<dyn Future<Output = std::io::Result<DataPermit>> + Send>>>,
    /// Stream-slot capacity, held until either endpoint closes the stream.
    /// A server FIN releases it immediately even if callers retain the EOF
    /// stream object.
    _permit: Option<crate::session::SessionPermit<AnyTlsSession>>,
}

impl AnyTlsStream {
    #[cfg(test)]
    fn new(
        session: Arc<AnyTlsSession>,
        sid: u32,
        rx: mpsc::Receiver<StreamEvent>,
        permit: crate::session::SessionPermit<AnyTlsSession>,
    ) -> Self {
        let receive = Arc::new(parking_lot::Mutex::new(TcpReceiveState::new(rx)));
        let inbound = TcpInbound::new(&receive);
        session.tcp_inbound.lock().insert(sid, inbound);
        Self::from_receive(session, sid, receive, permit)
    }

    fn from_receive(
        session: Arc<AnyTlsSession>,
        sid: u32,
        receive: Arc<parking_lot::Mutex<TcpReceiveState>>,
        permit: crate::session::SessionPermit<AnyTlsSession>,
    ) -> Self {
        Self {
            session,
            sid,
            receive,
            read_eof: false,
            read_err: None,
            out_slot: None,
            permit_fut: None,
            _permit: Some(permit),
        }
    }
}

impl std::fmt::Debug for AnyTlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let receive = self.receive.lock();
        f.debug_struct("AnyTlsStream")
            .field("sid", &self.sid)
            .field(
                "pending_read",
                &receive
                    .read_buf
                    .as_ref()
                    .map_or(0, |data| data.len() - receive.read_pos),
            )
            .finish()
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        self.session.end_stream(self.sid, true);
    }
}

impl tokio::io::AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let chunk = buf.len().min(u16::MAX as usize);
        if chunk == 0 {
            return std::task::Poll::Ready(Ok(0));
        }
        let this = self.as_mut().get_mut();

        // A payload sits here only while it is still unqueued — a successful
        // enqueue takes it — and a write that returned Pending accepted no
        // bytes, so a cancelled call's payload belongs to nobody and this
        // call's buffer replaces it. Equal bytes need no replacement, which
        // keeps a resumed write from reallocating on every poll.
        match &this.out_slot {
            Some((payload, _)) if payload.as_ref() == &buf[..chunk] => {}
            _ => {
                // A permit being awaited was sized for the replaced payload.
                this.permit_fut = None;
                this.out_slot = Some((bytes::Bytes::copy_from_slice(&buf[..chunk]), chunk));
            }
        }

        if let Some((payload, n)) = this.out_slot.take() {
            match this.session.try_enqueue_data(this.sid, payload) {
                Ok(()) => {
                    // A retry that got in through the fast path leaves its
                    // earlier waiter behind; that waiter may already hold
                    // permits for this payload, so drop it here rather than
                    // keep a second reservation until the next write.
                    this.permit_fut = None;
                    return std::task::Poll::Ready(Ok(n));
                }
                Err(payload) => this.out_slot = Some((payload, n)),
            }
        }

        if this.permit_fut.is_none() {
            let session = Arc::clone(&this.session);
            let bytes = this
                .out_slot
                .as_ref()
                .map_or(0, |(payload, _)| payload.len());
            this.permit_fut = Some(Box::pin(
                async move { session.acquire_data_permit(bytes).await },
            ));
        }
        let fut = this.permit_fut.as_mut().expect("permit wait just queued");
        match fut.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok(permit)) => {
                this.permit_fut = None;
                let (payload, n) = this.out_slot.take().expect("slot held while waiting");
                let r = this
                    .session
                    .enqueue_data_with_permit(this.sid, payload, permit);
                std::task::Poll::Ready(r.map(|()| n))
            }
            std::task::Poll::Ready(Err(e)) => {
                this.permit_fut = None;
                std::task::Poll::Ready(Err(e))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let Some(fut) = this.permit_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                std::task::Poll::Ready(Ok(permit)) => {
                    this.permit_fut = None;
                    if let Some((payload, _)) = this.out_slot.take() {
                        this.session
                            .enqueue_data_with_permit(this.sid, payload, permit)?;
                    }
                }
                std::task::Poll::Ready(Err(e)) => {
                    this.permit_fut = None;
                    return std::task::Poll::Ready(Err(e));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.as_mut().poll_flush(cx)
    }
}

#[async_trait]
impl WarmableOutbound for AnyTlsHandler {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        let node = Arc::clone(&runtime.node);
        let addr = format!("{}:{}", node.host(), node.port);
        let dial_runtime = Arc::clone(&runtime);
        let pool = runtime.anytls_pool()?;
        let padding_state = pool.padding_state();
        let inbound_payload_budget = pool.inbound_payload_budget();
        Self::warm_pool_with(runtime, move || async move {
            let tls_connector = dial_runtime.anytls_tls_connector()?;
            dial_runtime
                .transport_quality()
                .scope(dial_session(
                    &node,
                    &addr,
                    connect_timeout,
                    Some(tls_connector),
                    padding_state,
                    inbound_payload_budget,
                ))
                .await
        })
        .await
    }
}

#[async_trait]
impl TcpOutbound for AnyTlsHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let owner = crate::runtime::NodeRuntime::try_ephemeral_guarded(node)?;
        let stream = self
            .dial_runtime(owner.runtime(), target, target_domain, connect_timeout)
            .await?;
        Ok(stream.with_owner(owner))
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let pool = runtime.anytls_pool()?;
        let node = Arc::clone(&runtime.node);
        if !runtime.is_ephemeral() {
            Self::ensure_janitor(&node, &pool, Some(Arc::clone(&runtime)));
        }
        let dial_node = Arc::clone(&node);
        let dial_addr = format!("{}:{}", node.host(), node.port);
        let dial_runtime = Arc::clone(&runtime);
        let padding_state = pool.padding_state();
        let inbound_payload_budget = pool.inbound_payload_budget();
        let domain = target_domain.map(str::to_string);
        let stream = pool
            .open_with(
                move || {
                    let node = Arc::clone(&dial_node);
                    let addr = dial_addr.clone();
                    let runtime = Arc::clone(&dial_runtime);
                    let padding_state = Arc::clone(&padding_state);
                    let inbound_payload_budget = Arc::clone(&inbound_payload_budget);
                    async move {
                        let tls_connector = runtime.anytls_tls_connector()?;
                        runtime
                            .transport_quality()
                            .scope(dial_session(
                                &node,
                                &addr,
                                connect_timeout,
                                Some(tls_connector),
                                padding_state,
                                inbound_payload_budget,
                            ))
                            .await
                    }
                },
                move |session, permit| {
                    let domain = domain.clone();
                    async move { session.open_stream(permit, target, domain.as_deref()).await }
                },
            )
            .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }
}

#[async_trait]
impl PacketOutbound for AnyTlsHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let owner = crate::runtime::NodeRuntime::try_ephemeral_guarded(node)?;
        let transport = self
            .dial_udp_transport_runtime(owner.runtime(), target, target_domain, connect_timeout)
            .await?;
        Ok(super::packet_transport_with_owner(transport, owner))
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let pool = runtime.anytls_pool()?;
        let node = Arc::clone(&runtime.node);
        if !crate::descriptor::network_allows_udp(&node) {
            anyhow::bail!("node '{}' does not allow UDP", node.name);
        }

        if !runtime.is_ephemeral() {
            Self::ensure_janitor(&node, &pool, Some(Arc::clone(&runtime)));
        }
        let dial_node = Arc::clone(&node);
        let dial_runtime = Arc::clone(&runtime);
        let dial_addr = format!("{}:{}", node.host(), node.port);
        let padding_state = pool.padding_state();
        let inbound_payload_budget = pool.inbound_payload_budget();
        let transport = pool
            .open_with(
                move || {
                    let node = Arc::clone(&dial_node);
                    let runtime = Arc::clone(&dial_runtime);
                    let addr = dial_addr.clone();
                    let padding_state = Arc::clone(&padding_state);
                    let inbound_payload_budget = Arc::clone(&inbound_payload_budget);
                    async move {
                        let tls_connector = runtime.anytls_tls_connector()?;
                        runtime
                            .transport_quality()
                            .scope(dial_session(
                                &node,
                                &addr,
                                connect_timeout,
                                Some(tls_connector),
                                padding_state,
                                inbound_payload_budget,
                            ))
                            .await
                    }
                },
                move |session, permit| {
                    let domain = target_domain.map(str::to_string);
                    async move { session.open_packet(permit, target, domain.as_deref()).await }
                },
            )
            .await?;

        let transport: Arc<dyn PacketTransport> = transport;
        Ok(transport)
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let pool = runtime.anytls_pool()?;
        let node = Arc::clone(&runtime.node);
        let dial_node = Arc::clone(&node);
        let dial_runtime = Arc::clone(&runtime);
        let dial_addr = format!("{}:{}", node.host(), node.port);
        let padding_state = pool.padding_state();
        let inbound_payload_budget = pool.inbound_payload_budget();
        runtime
            .scope_tasks(Self::dial_udp_transport_speculative_for_pool_with(
                node.as_ref(),
                pool,
                target,
                target_domain,
                Some(Arc::clone(&runtime)),
                move || async move {
                    let tls_connector = dial_runtime.anytls_tls_connector()?;
                    let padding_state = Arc::clone(&padding_state);
                    let inbound_payload_budget = Arc::clone(&inbound_payload_budget);
                    dial_runtime
                        .transport_quality()
                        .scope(dial_session(
                            dial_node.as_ref(),
                            &dial_addr,
                            connect_timeout,
                            Some(tls_connector),
                            padding_state,
                            inbound_payload_budget,
                        ))
                        .await
                },
            ))
            .await
    }
}

#[async_trait]
impl ProbeableOutbound for AnyTlsHandler {}

#[cfg(test)]
/// Write a single AnyTLS frame.
async fn write_frame<W>(writer: &mut W, cmd: u8, sid: u32, data: &[u8]) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let len = u16::try_from(data.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AnyTLS frame payload exceeds 65535 bytes",
        )
    })?;
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[0] = cmd;
    header[1..5].copy_from_slice(&sid.to_be_bytes());
    header[5..7].copy_from_slice(&len.to_be_bytes());
    writer.write_all(&header).await?;
    if !data.is_empty() {
        writer.write_all(data).await?;
    }
    Ok(())
}

async fn read_frame_header<R>(reader: &mut R) -> std::io::Result<(u8, u32, usize)>
where
    R: AsyncReadExt + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    Ok((
        header[0],
        u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        u16::from_be_bytes([header[5], header[6]]) as usize,
    ))
}

/// Read `len` body bytes into a buffer of exactly that size and hand it out
/// frozen. `read_buf` fills spare capacity, so the body is not zeroed before
/// the read, and a full buffer freezes without a second allocation. One
/// allocation per frame remains: consumers own the body, and recycling it
/// needs the buffer to come back from them.
async fn read_frame_body<R>(reader: &mut R, len: usize) -> std::io::Result<bytes::Bytes>
where
    R: AsyncReadExt + Unpin,
{
    use bytes::BufMut;
    let mut body = bytes::BytesMut::with_capacity(len);
    while body.len() < len {
        let remaining = len - body.len();
        let n = reader.read_buf(&mut (&mut body).limit(remaining)).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "AnyTLS frame body ended early",
            ));
        }
    }
    Ok(body.freeze())
}

async fn drain_frame_body<R>(reader: &mut R, mut len: usize) -> std::io::Result<()>
where
    R: AsyncReadExt + Unpin,
{
    let mut scratch = [0u8; 4096];
    while len != 0 {
        let chunk = len.min(scratch.len());
        reader.read_exact(&mut scratch[..chunk]).await?;
        len -= chunk;
    }
    Ok(())
}

/// Read a single AnyTLS frame in tests.
#[cfg(test)]
async fn read_frame<R>(reader: &mut R) -> std::io::Result<(u8, u32, Vec<u8>)>
where
    R: AsyncReadExt + Unpin,
{
    let (cmd, sid, len) = read_frame_header(reader).await?;
    let data = read_frame_body(reader, len).await?;
    Ok((cmd, sid, data.to_vec()))
}

#[cfg(test)]
mod tests;
