//! AnyTLS proxy handler with sing-anytls session multiplexing.

use crate::tls::TlsConnector;
use async_trait::async_trait;
use honk_config::node::Node;
#[cfg(test)]
use honk_config::types::NodeProtocol;
use md5::Md5;
use rand::RngExt as _;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::addr;
use super::{
    MuxSession as _, PacketOutbound, PacketTransport, PreparedUdpTransport, ProbeableOutbound,
    ProxyStream, TcpOutbound, WarmRequirement, WarmableOutbound,
};
use crate::session::{ManagedSession as _, SpeculativeCheckout};

mod uot;

pub(crate) use uot::AnyTlsUotTransport;
use uot::{UOT_DRAIN_QUEUE_CAP, UotReceiveState};

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

#[derive(Clone, Copy, Debug)]
enum PaddingInstruction {
    Range(u16, u16),
    Check,
}

#[derive(Debug)]
struct PaddingScheme {
    stop: u32,
    packets: HashMap<u32, Vec<PaddingInstruction>>,
    md5: String,
}

impl PaddingScheme {
    fn parse(raw: &[u8]) -> Option<Self> {
        let mut values = HashMap::<&[u8], &[u8]>::new();
        for line in raw.split(|byte| *byte == b'\n') {
            let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
                continue;
            };
            values.insert(&line[..separator], &line[separator + 1..]);
        }

        let stop = std::str::from_utf8(values.get(b"stop".as_slice()).copied()?)
            .ok()?
            .parse::<u32>()
            .ok()?;
        let mut packets = HashMap::new();
        for (key, value) in values {
            if key == b"stop"
                || key.is_empty()
                || (key.len() > 1 && key[0] == b'0')
                || !key.iter().all(u8::is_ascii_digit)
            {
                continue;
            }
            let Ok(packet) = std::str::from_utf8(key).unwrap().parse::<u32>() else {
                continue;
            };
            let instructions: Vec<_> = value
                .split(|byte| *byte == b',')
                .filter_map(|part| {
                    if part == b"c" {
                        return Some(PaddingInstruction::Check);
                    }
                    let mut bounds = part.split(|byte| *byte == b'-');
                    let (Some(start), Some(end), None) =
                        (bounds.next(), bounds.next(), bounds.next())
                    else {
                        return None;
                    };
                    let (mut start, mut end) = (
                        std::str::from_utf8(start).ok()?.parse::<i64>().ok()?,
                        std::str::from_utf8(end).ok()?.parse::<i64>().ok()?,
                    );
                    if start <= 0 || end <= 0 {
                        return None;
                    }
                    if start > end {
                        std::mem::swap(&mut start, &mut end);
                    }
                    Some(PaddingInstruction::Range(
                        u16::try_from(start).ok()?,
                        u16::try_from(end).ok()?,
                    ))
                })
                .collect();
            if instructions.is_empty() {
                packets.remove(&packet);
            } else {
                packets.insert(packet, instructions);
            }
        }
        if packets
            .get(&0)
            .and_then(|instructions| instructions.first())
            .is_some_and(|instruction| matches!(instruction, PaddingInstruction::Check))
        {
            return None;
        }
        let digest = Md5::digest(raw);
        let mut md5 = String::with_capacity(32);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            md5.push(HEX[(byte >> 4) as usize] as char);
            md5.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Some(Self { stop, packets, md5 })
    }

    fn sample_range(start: u16, end: u16) -> usize {
        if start == end {
            start as usize
        } else {
            rand::rng().random_range(start..end) as usize
        }
    }

    fn auth_padding_len(&self) -> usize {
        match self
            .packets
            .get(&0)
            .and_then(|instructions| instructions.first())
        {
            Some(PaddingInstruction::Range(start, end)) => Self::sample_range(*start, *end),
            Some(PaddingInstruction::Check) | None => 0,
        }
    }

    fn settings_payload(&self) -> bytes::Bytes {
        bytes::Bytes::from(format!(
            "v=2\nclient={CLIENT_NAME}\npadding-md5={}\n",
            self.md5
        ))
    }
}

#[derive(Debug)]
struct PaddingState {
    current: parking_lot::RwLock<Arc<PaddingScheme>>,
}

impl Default for PaddingState {
    fn default() -> Self {
        Self {
            current: parking_lot::RwLock::new(Arc::new(
                PaddingScheme::parse(DEFAULT_PADDING_SCHEME)
                    .expect("built-in AnyTLS padding scheme is valid"),
            )),
        }
    }
}

impl PaddingState {
    fn snapshot(&self) -> Arc<PaddingScheme> {
        Arc::clone(&self.current.read())
    }

    fn update(&self, raw: &[u8]) -> bool {
        let Some(scheme) = PaddingScheme::parse(raw) else {
            return false;
        };
        *self.current.write() = Arc::new(scheme);
        true
    }
}

/// Per-stream demux queue depth (frames). A full queue parks frames in
/// the session overflow instead of blocking the demux.
const STREAM_QUEUE_CAP: usize = 64;
/// Soft caps on parked overflow (data frames/payload, session-wide and
/// per stream). Tripping one never blocks the demux: the frame parks and
/// the stall watchdog reaps consumers that make no flush progress for
/// [`OVERFLOW_STALL_GRACE`]. Soft because a fast peer can burst past
/// them in the milliseconds before the reader task is first scheduled.
const SESSION_OVERFLOW_CAP: usize = 512;
const STREAM_OVERFLOW_BYTES_CAP: usize = 2 * 1024 * 1024;
const SESSION_OVERFLOW_BYTES_CAP: usize = 8 * 1024 * 1024;
/// Emergency session-wide hard caps. Tripping one reaps the most-stalled
/// parked stream on the spot when it is past the grace; while every
/// stalled stream is inside the grace the demux waits bounded
/// [`OVERFLOW_EMERGENCY_WAIT`] rounds for reader progress (woken by
/// flushes) — TCP-style backpressure, since at wire rate a healthy burst
/// fills any feasible buffer before the reader task is first scheduled,
/// so the only alternatives are blocking reads or killing the innocent.
const SESSION_OVERFLOW_HARD_CAP: usize = 768;
const SESSION_OVERFLOW_HARD_BYTES_CAP: usize = 12 * 1024 * 1024;
/// Terminal events (Fin/Error) parked per stream. They bypass the frame
/// quota — a full quota must not break stream termination — but are not
/// unbounded: the stream is already terminating, so extras are dropped.
const MAX_OVERFLOW_TERMINAL_EVENTS: usize = 2;
/// How long a parked stream may go without flush progress before the
/// watchdog judges it a stuck consumer and resets it. Parked bytes are
/// not a stall — only the absence of reader progress is.
const OVERFLOW_STALL_GRACE: Duration = Duration::from_secs(3);
/// One bounded wait round at an emergency hard cap with no stream past
/// the grace. Sized well above the 12–16ms reader-task startup delay
/// measured on a 9.4Gbps burst (a healthy reader's first flush wakes the
/// wait immediately), and far below the stall grace so a genuinely stuck
/// consumer is reaped the round it crosses the grace.
const OVERFLOW_EMERGENCY_WAIT: Duration = Duration::from_millis(100);
/// Overflow watchdog tick. The task is spawned by the first park,
/// retires when the overflow drains, and is aborted on session close.
const OVERFLOW_WATCHDOG_TICK: Duration = Duration::from_millis(250);
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
    Data(Vec<u8>),
    Fin,
    Error(Arc<str>),
}

impl StreamEvent {
    fn payload_len(&self) -> usize {
        match self {
            Self::Data(data) => data.len(),
            Self::Fin | Self::Error(_) => 0,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OverflowUsage {
    frames: usize,
    bytes: usize,
}

#[derive(Default)]
struct StreamOverflow {
    events: VecDeque<StreamEvent>,
    /// Data frames only: terminal events bypass the frame quota.
    frames: usize,
    bytes: usize,
    terminal_events: usize,
    last_progress_at: Option<tokio::time::Instant>,
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
enum OverflowLimit {
    SessionFrames,
    StreamBytes,
    SessionBytes,
    /// Watchdog reap: no flush progress for a full stall grace.
    StallGrace,
}

impl OverflowLimit {
    fn as_str(self) -> &'static str {
        match self {
            Self::SessionFrames => "session_frames",
            Self::StreamBytes => "stream_bytes",
            Self::SessionBytes => "session_bytes",
            Self::StallGrace => "stall_grace",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OverflowVictim {
    sid: u32,
    limit: OverflowLimit,
    session: OverflowUsage,
    stream: OverflowUsage,
    stalled_for: Duration,
}

enum OverflowAction {
    Parked,
    /// A terminal event past the per-stream cap: the stream is already
    /// terminating, so dropping it is harmless.
    Dropped,
    /// Emergency-cap reap: the caller kills the victim outside the lock
    /// and retries with the returned event.
    Kill(OverflowVictim, StreamEvent),
    /// Hard cap with every stalled stream inside the grace: the caller
    /// waits up to the given bound for flush progress, then retries with
    /// the returned event.
    Wait(StreamEvent, Duration),
}

impl OverflowState {
    fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }
    fn has(&self, sid: u32) -> bool {
        self.streams.contains_key(&sid)
    }

    fn usage(&self) -> OverflowUsage {
        OverflowUsage {
            frames: self.frames,
            bytes: self.bytes,
        }
    }

    fn stream_usage(&self, sid: u32) -> OverflowUsage {
        self.streams
            .get(&sid)
            .map(|stream| OverflowUsage {
                frames: stream.frames,
                bytes: stream.bytes,
            })
            .unwrap_or_default()
    }

    /// Soft bounds, checked for data frames only (terminal events bypass
    /// the quota). Session-wide bounds first: a stream past its soft cap
    /// keeps parking until the watchdog's grace expires, so only this
    /// order keeps session memory capped while stall age accrues.
    fn limit_for(&self, sid: u32, event: &StreamEvent) -> Option<OverflowLimit> {
        let bytes = event.payload_len();
        if bytes != 0 && self.bytes.saturating_add(bytes) > SESSION_OVERFLOW_BYTES_CAP {
            return Some(OverflowLimit::SessionBytes);
        }
        if self.frames >= SESSION_OVERFLOW_CAP {
            return Some(OverflowLimit::SessionFrames);
        }
        if bytes != 0
            && self.stream_usage(sid).bytes.saturating_add(bytes) > STREAM_OVERFLOW_BYTES_CAP
        {
            return Some(OverflowLimit::StreamBytes);
        }
        None
    }

    /// Time since the reader last made flush progress on this stream (or
    /// since the first park, if it never has).
    fn stalled_for(&self, sid: u32) -> Duration {
        self.streams
            .get(&sid)
            .and_then(|stream| stream.last_progress_at)
            .map(|progress| progress.elapsed())
            .unwrap_or_default()
    }

    fn last_progress_at(&self, sid: u32) -> Option<tokio::time::Instant> {
        self.streams
            .get(&sid)
            .and_then(|stream| stream.last_progress_at)
    }

    fn restore_last_progress_at(&mut self, sid: u32, progress: Option<tokio::time::Instant>) {
        if let (Some(stream), Some(progress)) = (self.streams.get_mut(&sid), progress) {
            stream.last_progress_at = Some(progress);
        }
    }

    /// A parked frame reached the stream queue: the consumer is alive.
    fn note_progress(&mut self, sid: u32) {
        if let Some(stream) = self.streams.get_mut(&sid) {
            stream.last_progress_at = Some(tokio::time::Instant::now());
        }
    }

    /// (data frames, payload bytes) — terminal events bypass the quota.
    fn event_weight(event: &StreamEvent) -> (usize, usize) {
        match event {
            StreamEvent::Data(data) => (1, data.len()),
            StreamEvent::Fin | StreamEvent::Error(_) => (0, 0),
        }
    }

    fn push_back(&mut self, sid: u32, event: StreamEvent) {
        let (frames, bytes) = Self::event_weight(&event);
        let stream = self.streams.entry(sid).or_default();
        stream
            .last_progress_at
            .get_or_insert_with(tokio::time::Instant::now);
        stream.events.push_back(event);
        stream.frames += frames;
        stream.bytes += bytes;
        stream.terminal_events += usize::from(frames == 0);
        self.frames += frames;
        self.bytes += bytes;
    }

    fn push_front(&mut self, sid: u32, event: StreamEvent) {
        let (frames, bytes) = Self::event_weight(&event);
        let stream = self.streams.entry(sid).or_default();
        stream
            .last_progress_at
            .get_or_insert_with(tokio::time::Instant::now);
        stream.events.push_front(event);
        stream.frames += frames;
        stream.bytes += bytes;
        stream.terminal_events += usize::from(frames == 0);
        self.frames += frames;
        self.bytes += bytes;
    }

    fn pop_front(&mut self, sid: u32) -> Option<StreamEvent> {
        let (event, empty) = {
            let stream = self.streams.get_mut(&sid)?;
            let event = stream.events.pop_front()?;
            let (frames, bytes) = Self::event_weight(&event);
            stream.frames -= frames;
            stream.bytes -= bytes;
            stream.terminal_events -= usize::from(frames == 0);
            self.frames -= frames;
            self.bytes -= bytes;
            (event, stream.events.is_empty())
        };
        if empty {
            self.streams.remove(&sid);
        }
        Some(event)
    }

    fn remove_stream(&mut self, sid: u32) -> OverflowUsage {
        let Some(stream) = self.streams.remove(&sid) else {
            return OverflowUsage::default();
        };
        self.frames -= stream.frames;
        self.bytes -= stream.bytes;
        OverflowUsage {
            frames: stream.frames,
            bytes: stream.bytes,
        }
    }

    fn clear(&mut self) -> OverflowUsage {
        let usage = self.usage();
        self.streams.clear();
        self.frames = 0;
        self.bytes = 0;
        usage
    }

    fn request_flush(&mut self, sid: u32) -> bool {
        if self.flushing.insert(sid) {
            true
        } else {
            self.flush_requested.insert(sid);
            false
        }
    }

    fn finish_flush(&mut self, sid: u32) -> bool {
        if self.flush_requested.remove(&sid) {
            true
        } else {
            self.flushing.remove(&sid);
            false
        }
    }

    fn cancel_flush(&mut self, sid: u32) {
        self.flushing.remove(&sid);
        self.flush_requested.remove(&sid);
    }

    /// The parked stream with the oldest flush progress (ties to the
    /// lowest sid): the prime stuck-consumer suspect at a session cap.
    fn most_stalled_stream(&self) -> Option<u32> {
        self.streams
            .iter()
            .filter_map(|(&sid, stream)| stream.last_progress_at.map(|at| (at, sid)))
            .min()
            .map(|(_, sid)| sid)
    }

    /// The most-stalled parked stream among those past
    /// [`OVERFLOW_STALL_GRACE`] without flush progress.
    fn most_stalled_past_grace(&self) -> Option<u32> {
        self.streams
            .iter()
            .filter_map(|(&sid, stream)| stream.last_progress_at.map(|at| (at, sid)))
            .filter(|(at, _)| at.elapsed() >= OVERFLOW_STALL_GRACE)
            .min()
            .map(|(_, sid)| sid)
    }

    /// Detach a parked stream's overflow and snapshot its usage for the
    /// kill log line.
    fn take_victim(&mut self, sid: u32, limit: OverflowLimit) -> OverflowVictim {
        let victim = OverflowVictim {
            sid,
            limit,
            session: self.usage(),
            stream: self.stream_usage(sid),
            stalled_for: self.stalled_for(sid),
        };
        self.remove_stream(sid);
        victim
    }

    /// Emergency session-wide bounds on parked data.
    fn hard_limit_for(&self, event: &StreamEvent) -> Option<OverflowLimit> {
        let bytes = event.payload_len();
        if self.bytes.saturating_add(bytes) > SESSION_OVERFLOW_HARD_BYTES_CAP {
            return Some(OverflowLimit::SessionBytes);
        }
        if self.frames >= SESSION_OVERFLOW_HARD_CAP {
            return Some(OverflowLimit::SessionFrames);
        }
        None
    }

    /// One wait round at a hard cap, clamped to the nearest grace expiry
    /// so a stream crossing the grace is reaped without a stale round.
    fn emergency_wait(&self) -> Duration {
        let remaining = self
            .most_stalled_stream()
            .map(|sid| OVERFLOW_STALL_GRACE.saturating_sub(self.stalled_for(sid)))
            .unwrap_or(OVERFLOW_EMERGENCY_WAIT);
        remaining.min(OVERFLOW_EMERGENCY_WAIT)
    }

    /// Admit an overflow-bound event, parking it inline or returning the
    /// verdict for the caller to execute outside the lock. Below the
    /// emergency hard caps every frame parks and the watchdog reaps
    /// consumers stalled past [`OVERFLOW_STALL_GRACE`]. At a hard cap a
    /// past-grace stream is reaped on the spot; with every stalled stream
    /// inside the grace the caller waits bounded
    /// [`OVERFLOW_EMERGENCY_WAIT`] rounds for flush progress (woken via
    /// the session overflow notify) — bounded TCP-style backpressure, and
    /// each elapsed round re-judges, so a stream is only ever reaped once
    /// its full grace has expired. Terminal events bypass the frame quota
    /// but are capped per stream: the stream is already terminating, so
    /// extras drop.
    fn admit(&mut self, sid: u32, event: StreamEvent) -> OverflowAction {
        if !matches!(event, StreamEvent::Data(_)) {
            let terminals = self
                .streams
                .get(&sid)
                .map(|stream| stream.terminal_events)
                .unwrap_or_default();
            if terminals >= MAX_OVERFLOW_TERMINAL_EVENTS {
                return OverflowAction::Dropped;
            }
            self.push_back(sid, event);
            return OverflowAction::Parked;
        }
        if self.limit_for(sid, &event).is_none() {
            self.push_back(sid, event);
            return OverflowAction::Parked;
        }
        let Some(hard) = self.hard_limit_for(&event) else {
            self.push_back(sid, event);
            return OverflowAction::Parked;
        };
        if let Some(victim_sid) = self.most_stalled_past_grace() {
            return OverflowAction::Kill(self.take_victim(victim_sid, hard), event);
        }
        OverflowAction::Wait(event, self.emergency_wait())
    }
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
        match self {
            StreamSink::Tcp(tx) => tx.send(StreamEvent::Data(data)).await.is_ok(),
            StreamSink::Uot(tx) => tx.try_send(StreamEvent::Data(data)).is_ok(),
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

/// One ordered writer command. Data commands hold a queue permit until
/// popped (bounded → backpressure); control commands ride the reserved
/// headroom so SYN/FIN can never be starved by payload.
enum FrameCommand {
    Data {
        sid: u32,
        payload: bytes::Bytes,
        _permit: tokio::sync::OwnedSemaphorePermit,
        completion: Option<tokio::sync::oneshot::Sender<bool>>,
    },
    Control {
        cmd: u8,
        sid: u32,
        payload: bytes::Bytes,
    },
}

impl FrameCommand {
    /// Serialized size (header + payload).
    fn wire_len(&self) -> usize {
        let payload = match self {
            FrameCommand::Data { payload, .. } | FrameCommand::Control { payload, .. } => {
                payload.len()
            }
        };
        FRAME_HEADER_LEN + payload
    }

    /// Append the serialized frame to `buf`.
    fn encode_into(&self, buf: &mut bytes::BytesMut) {
        use bytes::BufMut as _;
        let (cmd, sid, payload) = match self {
            FrameCommand::Data { sid, payload, .. } => (CMD_PSH, *sid, payload),
            FrameCommand::Control { cmd, sid, payload } => (*cmd, *sid, payload),
        };
        debug_assert!(payload.len() <= u16::MAX as usize);
        buf.put_u8(cmd);
        buf.put_u32(sid);
        buf.put_u16(payload.len() as u16);
        buf.extend_from_slice(payload);
    }
}

/// Session writer queue: every frame goes out in enqueue order through a
/// single task — no cross-stream mutex, and a cancelled caller can never
/// truncate a queued frame (only a physical write failure closes the
/// session). Data capacity is `WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED`;
/// control frames take the reserved headroom.
struct WriterQueue {
    queue: parking_lot::Mutex<std::collections::VecDeque<FrameCommand>>,
    notify: tokio::sync::Notify,
    data_permits: Arc<tokio::sync::Semaphore>,
    closed: AtomicBool,
}

/// Open streams awaiting their SYNACK. A SID is registered when its SYN is
/// queued (so an early SYNACK can settle it) and gets its own deadline when
/// the writer puts the SYN on the wire.
#[derive(Default)]
struct SynackPending {
    sids: std::collections::HashMap<u32, Option<tokio::task::AbortHandle>>,
}

/// Total writer-queue depth (data + control headroom).
const WRITER_QUEUE_CAP: usize = 1024;
/// Slots reserved for control frames (SYN/FIN/HEART) — data can never
/// fill the queue past `WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED`.
const WRITER_CONTROL_RESERVED: usize = 128;
/// sing-anytls bounds control writes at five seconds. A stuck shared writer
/// must become terminal instead of remaining selectable by the session pool.
const WRITER_IO_TIMEOUT: Duration = Duration::from_secs(5);

impl WriterQueue {
    fn new() -> Self {
        Self {
            queue: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            notify: tokio::sync::Notify::new(),
            data_permits: Arc::new(tokio::sync::Semaphore::new(
                WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED,
            )),
            closed: AtomicBool::new(false),
        }
    }

    /// Push commands atomically as one batch (the SYN+PSH opening pair is
    /// never interleaved with another stream's frame).
    fn push_batch<const N: usize>(&self, cmds: [FrameCommand; N]) -> Result<(), [FrameCommand; N]> {
        let mut queue = self.queue.lock();
        if self.closed.load(Ordering::Acquire) || queue.len().saturating_add(N) > WRITER_QUEUE_CAP {
            return Err(cmds);
        }
        queue.extend(cmds);
        drop(queue);
        self.notify.notify_one();
        Ok(())
    }

    async fn pop(&self) -> Option<FrameCommand> {
        loop {
            if let Some(cmd) = self.queue.lock().pop_front() {
                return Some(cmd);
            }
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            self.notify.notified().await;
        }
    }

    /// Move up to `max_frames` already-queued commands (staying under
    /// `max_bytes` of serialized payload) to the end of `out` without
    /// blocking. Only drains what is queued *now* — never waits, so it adds
    /// no latency to a live writer loop.
    fn drain_available(&self, out: &mut Vec<FrameCommand>, max_frames: usize, max_bytes: usize) {
        let mut queue = self.queue.lock();
        let mut bytes = 0usize;
        let mut taken = 0usize;
        while taken < max_frames {
            let Some(front) = queue.front() else { break };
            let next = bytes + front.wire_len();
            if next > max_bytes {
                break;
            }
            bytes = next;
            out.push(queue.pop_front().expect("front checked"));
            taken += 1;
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        let mut queue = self.queue.lock();
        self.closed.store(true, Ordering::Release);
        queue.clear();
        self.data_permits.close();
        drop(queue);
        self.notify.notify_one();
    }
}

/// Batch caps for the writer's opportunistic gather: after the blocking
/// pop, at most this many extra queued frames (or this many serialized
/// bytes) ride the same `write_all` + single `flush`. Only what is already
/// queued is taken — batching never waits, so it adds no latency.
const WRITER_BATCH_MAX_FRAMES: usize = 64;
const WRITER_BATCH_MAX_BYTES: usize = 256 * 1024;

async fn write_padded<W>(
    writer: &mut W,
    mut payload: &[u8],
    scheme: &PaddingScheme,
    packet: u32,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let Some(instructions) = (packet < scheme.stop)
        .then(|| scheme.packets.get(&packet))
        .flatten()
    else {
        return writer.write_all(payload).await;
    };

    for instruction in instructions {
        let PaddingInstruction::Range(start, end) = instruction else {
            if payload.is_empty() {
                return Ok(());
            }
            continue;
        };
        let target = PaddingScheme::sample_range(*start, *end);
        if payload.len() > target {
            writer.write_all(&payload[..target]).await?;
            payload = &payload[target..];
        } else if !payload.is_empty() {
            let padding_len = target.saturating_sub(payload.len() + FRAME_HEADER_LEN);
            if padding_len == 0 {
                writer.write_all(payload).await?;
            } else {
                let mut padded = Vec::with_capacity(payload.len() + FRAME_HEADER_LEN + padding_len);
                padded.extend_from_slice(payload);
                padded.push(CMD_WASTE);
                padded.extend_from_slice(&0u32.to_be_bytes());
                padded.extend_from_slice(&(padding_len as u16).to_be_bytes());
                padded.resize(padded.len() + padding_len, 0);
                writer.write_all(&padded).await?;
            }
            payload = &[];
        } else {
            let mut waste = vec![0; FRAME_HEADER_LEN + target];
            waste[0] = CMD_WASTE;
            waste[5..7].copy_from_slice(&(target as u16).to_be_bytes());
            writer.write_all(&waste).await?;
        }
    }
    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }
    Ok(())
}

/// The single writer task for a session: drains the queue in order and
/// gather-writes whole batches per flush — one `write_all` of the
/// concatenated frames instead of a header/payload write pair plus flush
/// per frame (profiling showed flush-per-frame dominating CPU at line
/// rate). Order is preserved; framing is byte-level so batches are
/// transparent to the peer. A physical write failure kills the session
/// (sing `writeControlFrame` parity) — frames already queued are lost
/// with it.
async fn session_writer(
    session: Arc<AnyTlsSession>,
    mut write: BoxedWriter,
    queue: Arc<WriterQueue>,
) {
    let mut batch: Vec<FrameCommand> = Vec::with_capacity(WRITER_BATCH_MAX_FRAMES);
    let mut buf = bytes::BytesMut::with_capacity(64 * 1024);
    let mut packet = 0u32;
    let mut send_padding = true;
    loop {
        let Some(first) = queue.pop().await else {
            break;
        };
        let initial = matches!(
            &first,
            FrameCommand::Control {
                cmd: CMD_SETTINGS,
                ..
            }
        );
        batch.push(first);
        let next_packet = packet.wrapping_add(1);
        let padding = session.padding_state.snapshot();
        let apply_padding = send_padding && next_packet < padding.stop;
        if send_padding && !apply_padding {
            send_padding = false;
        }
        let extra_frames = if initial {
            2
        } else if apply_padding {
            0
        } else {
            WRITER_BATCH_MAX_FRAMES - 1
        };
        queue.drain_available(&mut batch, extra_frames, WRITER_BATCH_MAX_BYTES);
        buf.clear();
        buf.reserve(batch.iter().map(FrameCommand::wire_len).sum());
        for cmd in &batch {
            cmd.encode_into(&mut buf);
        }
        packet = next_packet;
        // The activity marker for any SYN in this batch must be sampled
        // before the write: frames arriving while a blocked flush is still
        // in flight belong to the window and must count as session activity.
        let pre_write_activity = session.rx_frame_seq.load(Ordering::Relaxed);
        let succeeded = matches!(
            tokio::time::timeout(WRITER_IO_TIMEOUT, async {
                if apply_padding {
                    write_padded(&mut write, &buf, &padding, packet).await?;
                } else {
                    write.write_all(&buf).await?;
                }
                write.flush().await
            })
            .await,
            Ok(Ok(()))
        );
        for command in &mut batch {
            match command {
                FrameCommand::Control {
                    cmd: CMD_SYN, sid, ..
                } if succeeded => {
                    session.start_synack_deadline(*sid, pre_write_activity);
                }
                FrameCommand::Data { completion, .. } => {
                    if let Some(completion) = completion.take() {
                        let _ = completion.send(succeeded);
                    }
                }
                _ => {}
            }
        }

        batch.clear();
        if !succeeded {
            debug!("AnyTLS session {} writer failed, closing", session.seq);
            session.fail(anyhow::anyhow!("writer task write failed"));
            break;
        }
        if session.is_closed() {
            break;
        }
    }
}

/// Session pool plus server-specific padding state for one AnyTLS node.
#[derive(Debug)]
pub(crate) struct AnyTlsPool {
    sessions: Arc<crate::session::SessionPool<AnyTlsSession>>,
    padding: Arc<PaddingState>,
}

impl AnyTlsPool {
    pub(crate) fn new() -> Self {
        Self {
            sessions: Arc::new(crate::session::SessionPool::new(session_pool_config())),
            padding: Arc::new(PaddingState::default()),
        }
    }

    fn padding_state(&self) -> Arc<PaddingState> {
        Arc::clone(&self.padding)
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

/// A multiplexed AnyTLS session: one TLS connection carrying any number of
/// concurrent streams (sing-anytls `Session`).
pub(crate) struct AnyTlsSession {
    /// Process-unique diagnostic id.
    seq: u64,
    /// AnyTLS server address retained for diagnostics.
    addr: String,
    /// Server-specific scheme shared by every live session in this pool.
    padding_state: Arc<PaddingState>,
    /// Settings waits for the first stream so packet 1 is SETTINGS+SYN+PSH.
    initial_settings: parking_lot::Mutex<Option<bytes::Bytes>>,
    /// Ordered writer queue: every frame goes out through the single
    /// writer task (no cross-stream mutex, uncancellable once queued).
    writer_q: Arc<WriterQueue>,
    /// Writer task handle, aborted on close.
    writer_task: Mutex<Option<tokio::task::AbortHandle>>,
    /// Open streams: sid → demux delivery channel.
    streams: Mutex<HashMap<u32, StreamSink>>,
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
    terminal_error: std::sync::OnceLock<Arc<anyhow::Error>>,
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
    /// Overflow stall watchdog (reaps parked streams with no flush
    /// progress past the grace): spawned by the first park, retires when
    /// the overflow drains, aborted on close. `None` while not running.
    watchdog: Mutex<Option<tokio::task::AbortHandle>>,
    /// Stream-slot capacity: the single capacity truth (replaces the old
    /// active_streams counter — a permit outlives the counter's races).
    stream_permits: Arc<tokio::sync::Semaphore>,
    /// Demux task handle, aborted on close.
    demux: Mutex<Option<tokio::task::AbortHandle>>,
    /// Inbound frame counter, bumped by the demux per frame; lets the SYNACK
    /// deadline distinguish a silently-dead session from one whose server is
    /// merely slow to open a stream.
    rx_frame_seq: AtomicU64,
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
            watchdog: Mutex::new(None),
            stream_permits: Arc::new(tokio::sync::Semaphore::new(MAX_STREAMS_PER_SESSION)),
            demux: Mutex::new(None),
            rx_frame_seq: AtomicU64::new(0),
        });

        let demux_handle = {
            let session = Arc::clone(&session);
            tokio::spawn(async move { session_demux(session, transport_read).await })
        };
        *session.demux.lock().unwrap() = Some(demux_handle.abort_handle());
        let writer_handle = {
            let session = Arc::clone(&session);
            let queue = Arc::clone(&session.writer_q);
            tokio::spawn(async move { session_writer(session, transport_write, queue).await })
        };
        *session.writer_task.lock().unwrap() = Some(writer_handle.abort_handle());

        debug!("AnyTLS session {} for {} established", session.seq, addr);
        Ok(session)
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
        *slot = Some(
            tokio::spawn(async move {
                tokio::time::sleep(SYNACK_TIMEOUT).await;
                let overdue = session.synack_pending.lock().sids.remove(&sid).is_some();
                if !overdue {
                    return;
                }
                if session.rx_frame_seq.load(Ordering::Relaxed) > activity_marker {
                    // Frames kept arriving through the window: the server is
                    // alive but never acknowledged this open. Reset only this
                    // stream — failing the session would kill every healthy
                    // sibling with it.
                    session
                        .dispatch_error(sid, Arc::from("stream open not acknowledged"))
                        .await;
                } else {
                    session.fail(anyhow::anyhow!(
                        "stream {sid} SYNACK timed out after {SYNACK_TIMEOUT:?}"
                    ));
                }
            })
            .abort_handle(),
        );
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

    fn writer_queue_error(&self) -> std::io::Error {
        let overloaded = !self.writer_q.is_closed();
        if overloaded {
            self.fail(anyhow::anyhow!("writer queue capacity exceeded"));
        }
        std::io::Error::new(
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
            return Err(std::io::Error::new(
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        let permit = self.acquire_data_permit().await?;
        self.enqueue_data_with_permit(sid, payload, permit)
    }

    /// Enqueue one frame and wait until the session writer flushes its batch.
    /// Used where an enqueue acknowledgement would turn writer loss into a
    /// false successful send.
    async fn enqueue_confirmed_data(&self, sid: u32, payload: bytes::Bytes) -> std::io::Result<()> {
        let permit = self.acquire_data_permit().await?;
        let completed = self.enqueue_confirmed_data_with_permit(sid, payload, permit)?;
        Self::wait_for_confirmed_data(completed).await
    }

    fn enqueue_confirmed_data_with_permit(
        &self,
        sid: u32,
        payload: bytes::Bytes,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> std::io::Result<tokio::sync::oneshot::Receiver<bool>> {
        if self.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }

        let (completion, completed) = tokio::sync::oneshot::channel();
        self.writer_q
            .push_batch([FrameCommand::Data {
                sid,
                payload,
                _permit: permit,
                completion: Some(completion),
            }])
            .map_err(|_| self.writer_queue_error())?;
        Ok(completed)
    }

    async fn wait_for_confirmed_data(
        completed: tokio::sync::oneshot::Receiver<bool>,
    ) -> std::io::Result<()> {
        match completed.await {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "AnyTLS writer failed before flushing frame",
            )),
        }
    }

    /// Acquire one writer-queue data permit (async).
    async fn acquire_data_permit(&self) -> std::io::Result<tokio::sync::OwnedSemaphorePermit> {
        if self.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        Arc::clone(&self.writer_q.data_permits)
            .acquire_owned()
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "AnyTLS writer queue is closed",
                )
            })
    }

    /// Try to enqueue a data frame without waiting; returns the payload
    /// back when the writer queue is full (caller keeps it in its slot).
    fn try_enqueue_data(&self, sid: u32, payload: bytes::Bytes) -> Result<(), bytes::Bytes> {
        if self.is_closed() {
            return Err(payload);
        }
        let Ok(permit) = Arc::clone(&self.writer_q.data_permits).try_acquire_owned() else {
            return Err(payload);
        };
        match self.writer_q.push_batch([FrameCommand::Data {
            sid,
            payload,
            _permit: permit,
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
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> std::io::Result<()> {
        if self.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        self.writer_q
            .push_batch([FrameCommand::Data {
                sid,
                payload,
                _permit: permit,
                completion: None,
            }])
            .map_err(|_| self.writer_queue_error())
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
        queue_cap: usize,
        sink: fn(mpsc::Sender<StreamEvent>) -> StreamSink,
        permit: crate::session::SessionPermit<Self>,
    ) -> anyhow::Result<(u32, mpsc::Receiver<StreamEvent>, StreamRegistration)> {
        if self.is_closed() {
            anyhow::bail!("AnyTLS session {} is closed", self.seq);
        }
        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = mpsc::channel(queue_cap);
        self.streams.lock().unwrap().insert(sid, sink(tx));
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
        Ok((sid, rx, guard))
    }

    async fn open_uot_stream(
        self: &Arc<Self>,
        target_addr: Vec<u8>,
        permit: crate::session::SessionPermit<Self>,
    ) -> anyhow::Result<(u32, mpsc::Receiver<StreamEvent>, StreamRegistration)> {
        let (sid, rx, guard) = self
            .register_and_open(target_addr, UOT_DRAIN_QUEUE_CAP, StreamSink::Uot, permit)
            .await?;
        debug!("AnyTLS session {} opened uot sid={}", self.seq, sid);
        Ok((sid, rx, guard))
    }

    fn ensure_stream_registered(&self, sid: u32) -> std::io::Result<()> {
        if self.streams.lock().unwrap().contains_key(&sid) {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "AnyTLS UoT stream is no longer registered",
            ))
        }
    }

    /// TCP payload must not be dropped, unlike UoT.
    async fn open_stream_direct(
        self: &Arc<Self>,
        target_addr: Vec<u8>,
        permit: crate::session::SessionPermit<Self>,
    ) -> anyhow::Result<AnyTlsStream> {
        let (sid, rx, guard) = self
            .register_and_open(target_addr, STREAM_QUEUE_CAP, StreamSink::Tcp, permit)
            .await?;
        let permit = guard.commit();
        debug!("AnyTLS session {} opened direct sid={}", self.seq, sid);
        Ok(AnyTlsStream::new(Arc::clone(self), sid, rx, permit))
    }

    /// Unregister a UoT stream, optionally notifying the server with FIN.
    /// Stream capacity is released by the transport permit, not this map.
    fn end_uot_stream(&self, sid: u32, notify_fin: bool) {
        self.settle_syn_pending(sid);
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
    /// Returns whether the watchdog had killed this stream.
    fn end_stream(&self, sid: u32, notify_fin: bool) -> bool {
        self.settle_syn_pending(sid);
        let (was_registered, received_fin, was_killed) = {
            let mut remote_fin = self.remote_fin.lock();
            let mut killed_streams = self.killed_streams.lock().unwrap();
            let received_fin = remote_fin.remove(&sid);
            let was_killed = killed_streams.remove(&sid);
            let was_registered = self.streams.lock().unwrap().remove(&sid).is_some();
            (was_registered, received_fin, was_killed)
        };

        self.discard_overflow(sid);
        if notify_fin && was_registered && !received_fin {
            let _ = self.enqueue_control(CMD_FIN, sid, bytes::Bytes::new());
        }
        debug!("AnyTLS session {} sid={} stream ended", self.seq, sid);
        was_killed
    }

    fn kill_stream(&self, sid: u32) -> Option<usize> {
        self.settle_syn_pending(sid);
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
        let _ = self.terminal_error.set(Arc::new(reason));
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
        if let Some(handle) = self.watchdog.lock().unwrap().take() {
            handle.abort();
        }
        self.writer_q.close();
        debug!("AnyTLS session {} for {} closed", self.seq, self.addr);
    }

    /// Deliver a server payload frame to its stream. TCP sinks park a
    /// full per-stream queue into the session overflow (flushed later by
    /// the reader's progress — see [`Self::flush_overflow`]). Below the
    /// emergency hard caps parking never waits: every frame parks and the
    /// stall watchdog resets consumers with no flush progress past
    /// [`OVERFLOW_STALL_GRACE`] — parked bytes are not a stall (a fast
    /// peer bursts megabytes before the reader task is first scheduled),
    /// only missing flush progress past the grace kills. At a hard cap
    /// the demux waits bounded rounds for that progress (see
    /// [`Self::park_overflow`]). A saturated UoT sink retires only its sid.
    async fn dispatch_data(self: &Arc<Self>, sid: u32, data: Vec<u8>) {
        let sink = self.streams.lock().unwrap().get(&sid).cloned();
        match sink {
            Some(StreamSink::Tcp(tx)) => {
                if self.overflow_has(sid) {
                    self.park_overflow(sid, StreamEvent::Data(data)).await;
                    return;
                }
                match tx.try_send(StreamEvent::Data(data)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(ev)) => {
                        self.park_overflow(sid, ev).await;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.end_stream(sid, false);
                    }
                }
            }
            Some(StreamSink::Uot(tx)) => {
                if tx.try_send(StreamEvent::Data(data)).is_err() {
                    self.end_uot_stream(sid, true);
                }
            }
            None => {
                debug!(
                    "AnyTLS session {} PSH for unknown sid={} ({} bytes)",
                    self.seq,
                    sid,
                    data.len()
                );
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

    fn overflow_sink_is_live(&self, sid: u32) -> bool {
        let closed = match self.streams.lock().unwrap().get(&sid) {
            Some(StreamSink::Tcp(tx)) => tx.is_closed(),
            Some(StreamSink::Uot(_)) | None => return false,
        };
        if closed {
            self.end_stream(sid, false);
            false
        } else {
            true
        }
    }

    fn overflow_has(&self, sid: u32) -> bool {
        self.overflow.lock().has(sid)
    }

    fn discard_overflow(&self, sid: u32) -> OverflowUsage {
        self.overflow.lock().remove_stream(sid)
    }

    fn clear_overflow(&self) -> OverflowUsage {
        self.overflow.lock().clear()
    }

    fn kill_overflow_victim(&self, victim: OverflowVictim) {
        let Some(queue_capacity) = self.kill_stream(victim.sid) else {
            return;
        };
        let stall_ms = u64::try_from(victim.stalled_for.as_millis()).unwrap_or(u64::MAX);
        warn!(
            session = self.seq,
            victim_sid = victim.sid,
            cap_reason = victim.limit.as_str(),
            after_stall_grace = victim.stalled_for >= OVERFLOW_STALL_GRACE,
            session_frames = victim.session.frames,
            session_bytes = victim.session.bytes,
            stream_frames = victim.stream.frames,
            stream_bytes = victim.stream.bytes,
            stall_ms,
            queue_capacity,
            "AnyTLS overflow killed stream"
        );
        if self
            .enqueue_control(CMD_FIN, victim.sid, bytes::Bytes::new())
            .is_err()
        {
            self.fail(anyhow::anyhow!("writer queue unavailable on overflow kill"));
        }
    }

    async fn park_overflow(self: &Arc<Self>, sid: u32, mut event: StreamEvent) {
        loop {
            if !self.overflow_sink_is_live(sid) {
                self.discard_overflow(sid);
                return;
            }

            let wait = self.overflow_notify.notified();
            tokio::pin!(wait);
            wait.as_mut().enable();

            let action = self.overflow.lock().admit(sid, event);
            match action {
                OverflowAction::Parked => {
                    self.flush_overflow(sid);
                    if !self.overflow_sink_is_live(sid) {
                        self.discard_overflow(sid);
                    }
                    self.ensure_watchdog();
                    return;
                }
                OverflowAction::Dropped => return,
                OverflowAction::Kill(victim, returned) => {
                    let own = victim.sid == sid;
                    self.kill_overflow_victim(victim);
                    if own {
                        return;
                    }
                    event = returned;
                }
                OverflowAction::Wait(returned, wait_for) => {
                    event = returned;
                    let _ = tokio::time::timeout(wait_for, wait).await;
                }
            }
        }
    }

    fn ensure_watchdog(self: &Arc<Self>) {
        if self.overflow.lock().is_empty() {
            return;
        }
        let mut handle = self.watchdog.lock().unwrap();
        if handle.is_none() {
            let session = Arc::clone(self);
            *handle = Some(
                tokio::spawn(async move { session.run_overflow_watchdog().await }).abort_handle(),
            );
        }
    }

    async fn run_overflow_watchdog(self: &Arc<Self>) {
        let mut ticker = tokio::time::interval(OVERFLOW_WATCHDOG_TICK);
        loop {
            ticker.tick().await;
            if self.is_closed() {
                return;
            }
            let victim = {
                let mut overflow = self.overflow.lock();
                if overflow.is_empty() {
                    *self.watchdog.lock().unwrap() = None;
                    return;
                }
                overflow
                    .most_stalled_past_grace()
                    .map(|sid| overflow.take_victim(sid, OverflowLimit::StallGrace))
            };
            if let Some(victim) = victim {
                self.kill_overflow_victim(victim);
            }
        }
    }

    fn flush_overflow(&self, sid: u32) {
        if self.drain_overflow(sid) {
            self.overflow_notify.notify_waiters();
        }
    }

    /// Returns whether any parked event reached the stream queue.
    fn drain_overflow(&self, sid: u32) -> bool {
        {
            let mut overflow = self.overflow.lock();
            if !overflow.has(sid) || !overflow.request_flush(sid) {
                return false;
            }
        }

        let mut moved = false;
        loop {
            let tx = match self.streams.lock().unwrap().get(&sid).cloned() {
                Some(StreamSink::Tcp(tx)) => tx,
                _ => {
                    let mut overflow = self.overflow.lock();
                    overflow.remove_stream(sid);
                    overflow.cancel_flush(sid);
                    drop(overflow);
                    return moved;
                }
            };

            let mut overflow = self.overflow.lock();
            let last_progress_at = overflow.last_progress_at(sid);
            let Some(event) = overflow.pop_front(sid) else {
                if overflow.finish_flush(sid) {
                    drop(overflow);
                    continue;
                }
                drop(overflow);
                return moved;
            };
            match tx.try_send(event) {
                Ok(()) => {
                    overflow.note_progress(sid);
                    moved = true;
                }
                Err(mpsc::error::TrySendError::Full(event)) => {
                    overflow.push_front(sid, event);
                    overflow.restore_last_progress_at(sid, last_progress_at);
                    if overflow.finish_flush(sid) {
                        drop(overflow);
                        continue;
                    }
                    drop(overflow);
                    return moved;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    overflow.remove_stream(sid);
                    overflow.cancel_flush(sid);
                    drop(overflow);
                    self.end_stream(sid, false);
                    return moved;
                }
            }
        }
    }

    async fn dispatch_error(self: &Arc<Self>, sid: u32, message: Arc<str>) {
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

async fn session_demux(session: Arc<AnyTlsSession>, mut read: BoxedReader) {
    let mut fail_reason: Option<anyhow::Error> = None;
    loop {
        let (cmd, sid, data) = match read_frame(&mut read).await {
            Ok(frame) => frame,
            Err(e) => {
                debug!("AnyTLS session {} demux read failed: {}", session.seq, e);
                fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                break;
            }
        };
        session.rx_frame_seq.fetch_add(1, Ordering::Relaxed);
        match cmd {
            CMD_PSH if !data.is_empty() => session.dispatch_data(sid, data).await,
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
        let _ = self.session_state.compare_exchange(
            crate::session::SessionState::Active as usize,
            crate::session::SessionState::Draining as usize,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
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
        Some(SessionPermit::new(Arc::clone(self), permit))
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
) -> anyhow::Result<Arc<AnyTlsSession>> {
    let timeout = connect_timeout.saturating_mul(3);
    tokio::time::timeout(timeout, async {
        let padding = padding_state.snapshot();
        let settings = padding.settings_payload();
        let (read, write, auth) =
            connect_transport(node, addr, connect_timeout, None, tls_connector, &padding).await?;
        AnyTlsSession::establish(addr, read, write, &auth, settings, padding_state).await
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

/// Connect to the AnyTLS server (using `tcp` when the caller provides a
/// pre-connected stream), wrap it in TLS, and build packet 0 authentication.
async fn connect_transport(
    node: &Node,
    addr: &str,
    connect_timeout: Duration,
    tcp: Option<TcpStream>,
    tls_connector: Option<Arc<TlsConnector>>,
    padding: &PaddingScheme,
) -> anyhow::Result<(BoxedReader, BoxedWriter, Vec<u8>)> {
    let auth = authentication_payload(AnyTlsHandler::resolve_password(node), padding);

    let tcp = match tcp {
        Some(tcp) => tcp,

        None => crate::util::connect_outbound(addr, connect_timeout).await?,
    };
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
    let tls = tokio::time::timeout(connect_timeout, connector.connect(&server_name, tcp))
        .await
        .map_err(|_| {
            anyhow::anyhow!("AnyTLS TLS handshake timed out after {connect_timeout:?}")
        })??;
    debug!("AnyTLS: TLS handshake completed with {}", addr);
    let (read, write) = tokio::io::split(crate::tls::BatchRead::new(tls));

    Ok((Box::new(read), Box::new(write), auth))
}

impl AnyTlsHandler {
    /// Create a new AnyTLS handler.
    pub fn new() -> Self {
        Self
    }

    fn resolve_password(node: &Node) -> &str {
        node.anytls().unwrap().password.as_deref().unwrap_or("")
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
        pool.ensure_janitor(min_idle, idle_timeout, move || {
            let node = prewarm_node.clone();
            let label = label.clone();
            let runtime = runtime.clone();
            let padding_state = Arc::clone(&padding_state);
            async move {
                let tls_connector = runtime
                    .as_ref()
                    .map(|runtime| runtime.anytls_tls_connector())
                    .transpose()?;
                dial_session(
                    &node,
                    &label,
                    Duration::from_secs(10),
                    tls_connector,
                    padding_state,
                )
                .await
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
        let pool = runtime.anytls_pool()?;
        Self::ensure_janitor(&runtime.node, &pool, Some(Arc::clone(&runtime)));
        let _session = pool.offer(dial).await?;
        if !pool.has_usable_session() {
            anyhow::bail!("AnyTLS warm dial completed without a usable session");
        }
        Ok(())
    }

    /// Keeps cancellation observable without opening a physical session.
    #[cfg(test)]
    async fn dial_udp_transport_speculative_with<F, Fut>(
        &self,
        node: &Node,
        pool: Arc<AnyTlsPool>,
        target: SocketAddr,
        target_domain: Option<&str>,
        dial: F,
    ) -> anyhow::Result<PreparedUdpTransport>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = anyhow::Result<Arc<AnyTlsSession>>> + Send,
    {
        Self::dial_udp_transport_speculative_for_pool_with(
            node,
            pool,
            target,
            target_domain,
            None,
            dial,
        )
        .await
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
        let commit_dial_scope = crate::runtime::capture_dial_admission();

        let (session, permit, detached) = match pool.checkout_speculative().await? {
            SpeculativeCheckout::Shared { session, permit } => (session, permit, None),
            SpeculativeCheckout::Detached(mut reservation) => {
                let session = tokio::select! {
                    result = dial() => result?,
                    _ = reservation.cancelled() => {
                        anyhow::bail!("AnyTLS speculative dial cancelled by pool shutdown")
                    }
                };
                reservation.attach(&session)?;
                let permit = session.try_reserve().ok_or_else(|| {
                    anyhow::anyhow!("fresh AnyTLS session has no stream capacity")
                })?;
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

        if let Some(reservation) = detached {
            let commit_node = node.clone();
            let commit_pool = Arc::clone(&pool);
            let commit_runtime = runtime.clone();
            return Ok(PreparedUdpTransport::new(transport, move || {
                commit_dial_scope.scope(async move {
                    reservation.commit()?;
                    if commit_runtime.is_some() {
                        Self::ensure_janitor(&commit_node, &commit_pool, commit_runtime);
                    }
                    Ok(())
                })
            }));
        }

        let commit_node = node.clone();
        Ok(PreparedUdpTransport::new(transport, move || {
            commit_dial_scope.scope(async move {
                if runtime.is_some() {
                    Self::ensure_janitor(&commit_node, &pool, runtime);
                }
                Ok(())
            })
        }))
    }

    async fn dial_udp_transport_for_pool(
        &self,
        node: Arc<Node>,
        pool: Arc<AnyTlsPool>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        runtime: Option<Arc<crate::runtime::NodeRuntime>>,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        if !crate::descriptor::network_allows_udp(&node) {
            anyhow::bail!("node '{}' does not allow UDP", node.name);
        }

        let addr = format!("{}:{}", node.host(), node.port);
        if runtime.as_ref().is_some_and(|r| !r.is_ephemeral()) {
            Self::ensure_janitor(node.as_ref(), &pool, runtime.clone());
        }
        let dial_node = Arc::clone(&node);
        let dial_addr = addr.clone();
        let padding_state = pool.padding_state();
        let transport = pool
            .open_with(
                move || {
                    let node = Arc::clone(&dial_node);
                    let addr = dial_addr.clone();
                    let runtime = runtime.clone();
                    let padding_state = Arc::clone(&padding_state);
                    async move {
                        let tls_connector = runtime
                            .as_ref()
                            .map(|runtime| runtime.anytls_tls_connector())
                            .transpose()?;
                        dial_session(
                            node.as_ref(),
                            &addr,
                            connect_timeout,
                            tls_connector,
                            padding_state,
                        )
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
}

/// Direct `AsyncRead`/`AsyncWrite` over a session stream. Avoiding an
/// intermediate duplex bridge removes two task hops and two copies per byte.
pub(crate) struct AnyTlsStream {
    session: Arc<AnyTlsSession>,
    sid: u32,
    rx: mpsc::Receiver<StreamEvent>,
    read_buf: Vec<u8>,
    read_pos: usize,
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
    /// is enqueued — cancelling the caller's write future can neither
    /// lose it nor enqueue it twice. `poll_write` only returns `Ok(n)`
    /// after exactly these `n` bytes were queued (never a number derived
    /// from a different call's buffer).
    out_slot: Option<(bytes::Bytes, usize)>,
    /// Waiter for a writer-queue data permit while `out_slot` is occupied.
    permit_fut: Option<
        std::pin::Pin<
            Box<dyn Future<Output = std::io::Result<tokio::sync::OwnedSemaphorePermit>> + Send>,
        >,
    >,
    /// Stream-slot capacity, held until either endpoint closes the stream.
    /// A server FIN releases it immediately even if callers retain the EOF
    /// stream object.
    _permit: Option<crate::session::SessionPermit<AnyTlsSession>>,
}

impl AnyTlsStream {
    fn new(
        session: Arc<AnyTlsSession>,
        sid: u32,
        rx: mpsc::Receiver<StreamEvent>,
        permit: crate::session::SessionPermit<AnyTlsSession>,
    ) -> Self {
        Self {
            session,
            sid,
            rx,
            read_buf: Vec::new(),
            read_pos: 0,
            read_eof: false,
            read_err: None,
            out_slot: None,
            permit_fut: None,
            _permit: Some(permit),
        }
    }

    fn release_permit(&mut self) {
        self._permit.take();
    }
}

impl std::fmt::Debug for AnyTlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsStream")
            .field("sid", &self.sid)
            .field("pending_read", &(self.read_buf.len() - self.read_pos))
            .finish()
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        self.session.end_stream(self.sid, true);
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

        let mut got_any = this.read_pos < this.read_buf.len();
        loop {
            let n = (this.read_buf.len() - this.read_pos).min(out.remaining());
            if n > 0 {
                out.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
            }
            if out.remaining() == 0 {
                return std::task::Poll::Ready(Ok(()));
            }

            this.read_buf.clear();
            this.read_pos = 0;

            let next = if got_any {
                match this.rx.try_recv() {
                    Ok(ev) => std::task::Poll::Ready(Some(ev)),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => std::task::Poll::Pending,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        std::task::Poll::Ready(None)
                    }
                }
            } else {
                this.rx.poll_recv(cx)
            };

            if matches!(next, std::task::Poll::Ready(Some(_))) {
                this.session.flush_overflow(this.sid);
            }
            match next {
                std::task::Poll::Ready(Some(StreamEvent::Data(data))) => {
                    this.read_buf = data;
                    got_any = true;
                }
                std::task::Poll::Ready(Some(StreamEvent::Error(e))) => {
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
                    this.release_permit();
                    return std::task::Poll::Ready(Err(err));
                }
                std::task::Poll::Ready(Some(StreamEvent::Fin)) => {
                    let killed = this.session.end_stream(this.sid, false);
                    if killed {
                        // A cloned sender can outlive watchdog removal and carry this FIN.
                        let err = std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "stream killed: slow consumer (HOL)",
                        );
                        if got_any {
                            this.read_err = Some(err);
                            return std::task::Poll::Ready(Ok(()));
                        }
                        this.read_eof = true;
                        this.release_permit();
                        return std::task::Poll::Ready(Err(err));
                    }
                    this.read_eof = true;
                    this.release_permit();
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(None) => {
                    let killed = this.session.end_stream(this.sid, false);
                    let pending: Option<std::io::Error> =
                        if let Some(e) = this.session.terminal_error.get() {
                            Some(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                e.to_string(),
                            ))
                        } else if killed {
                            Some(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "stream killed: slow consumer (HOL)",
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
                        this.release_permit();
                        return std::task::Poll::Ready(Err(err));
                    }
                    this.read_eof = true;
                    this.release_permit();
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

        if this.out_slot.is_none() {
            this.out_slot = Some((bytes::Bytes::copy_from_slice(&buf[..chunk]), chunk));
        }

        if let Some((payload, n)) = this.out_slot.take() {
            match this.session.try_enqueue_data(this.sid, payload) {
                Ok(()) => return std::task::Poll::Ready(Ok(n)),
                Err(payload) => this.out_slot = Some((payload, n)),
            }
        }

        if this.permit_fut.is_none() {
            let session = Arc::clone(&this.session);
            this.permit_fut = Some(Box::pin(async move { session.acquire_data_permit().await }));
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
        let padding_state = runtime.anytls_pool()?.padding_state();
        Self::warm_pool_with(runtime, move || async move {
            let tls_connector = dial_runtime.anytls_tls_connector()?;
            dial_session(
                &node,
                &addr,
                connect_timeout,
                Some(tls_connector),
                padding_state,
            )
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
        let owner = crate::runtime::NodeRuntime::ephemeral_guarded(node);
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
        let domain = target_domain.map(str::to_string);
        let stream = pool
            .open_with(
                move || {
                    let node = Arc::clone(&dial_node);
                    let addr = dial_addr.clone();
                    let runtime = Arc::clone(&dial_runtime);
                    let padding_state = Arc::clone(&padding_state);
                    async move {
                        let tls_connector = runtime.anytls_tls_connector()?;
                        dial_session(
                            &node,
                            &addr,
                            connect_timeout,
                            Some(tls_connector),
                            padding_state,
                        )
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
        let owner = crate::runtime::NodeRuntime::ephemeral_guarded(node);
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
        self.dial_udp_transport_for_pool(
            node,
            pool,
            target,
            target_domain,
            connect_timeout,
            Some(runtime),
        )
        .await
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
        Self::dial_udp_transport_speculative_for_pool_with(
            node.as_ref(),
            pool,
            target,
            target_domain,
            Some(runtime),
            move || async move {
                let tls_connector = dial_runtime.anytls_tls_connector()?;
                let padding_state = Arc::clone(&padding_state);
                dial_session(
                    dial_node.as_ref(),
                    &dial_addr,
                    connect_timeout,
                    Some(tls_connector),
                    padding_state,
                )
                .await
            },
        )
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

/// Read a single AnyTLS frame.
async fn read_frame<R>(reader: &mut R) -> std::io::Result<(u8, u32, Vec<u8>)>
where
    R: AsyncReadExt + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let cmd = header[0];
    let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut data).await?;
    }
    Ok((cmd, sid, data))
}

/// Compute the lowercase hex MD5 digest of a byte slice.
#[cfg(test)]
mod tests;
