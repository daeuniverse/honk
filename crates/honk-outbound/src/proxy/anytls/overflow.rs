use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::warn;

use super::{
    AnyTlsSession, CMD_FIN, OverflowState, OverflowUsage, OverflowVictim, StreamEvent, StreamSink,
};

/// Emergency session-wide frame cap. Tripping it reaps the most-stalled
/// parked stream on the spot when it is past the grace; while every
/// stalled stream is inside the grace the demux waits bounded
/// [`OVERFLOW_EMERGENCY_WAIT`] rounds for reader progress (woken by
/// flushes) — TCP-style backpressure, since at wire rate a healthy burst
/// fills any feasible buffer before the reader task is first scheduled,
/// so the only alternatives are blocking reads or killing the innocent.
pub(super) const SESSION_OVERFLOW_HARD_CAP: usize = 768;
/// Terminal events (Fin/Error) parked per stream. They bypass the frame
/// quota — a full quota must not break stream termination — but are not
/// unbounded: the stream is already terminating, so extras are dropped.
const MAX_OVERFLOW_TERMINAL_EVENTS: usize = 2;
/// How long a parked stream may go without flush progress before the
/// watchdog judges it a stuck consumer and resets it. Parked bytes are
/// not a stall — only the absence of reader progress is.
pub(super) const OVERFLOW_STALL_GRACE: Duration = Duration::from_secs(3);
/// One bounded wait round at an emergency hard cap with no stream past
/// the grace. Sized well above the 12–16ms reader-task startup delay
/// measured on a 9.4Gbps burst (a healthy reader's first flush wakes the
/// wait immediately), and far below the stall grace so a genuinely stuck
/// consumer is reaped the round it crosses the grace.
pub(super) const OVERFLOW_EMERGENCY_WAIT: Duration = Duration::from_millis(100);
/// Overflow watchdog tick. The task is spawned by the first park,
/// retires when the overflow drains, and is aborted on session close.
pub(super) const OVERFLOW_WATCHDOG_TICK: Duration = Duration::from_millis(250);

#[derive(Default)]
pub(super) struct StreamOverflow {
    events: VecDeque<StreamEvent>,
    /// Data frames only: terminal events bypass the frame quota.
    frames: usize,
    bytes: usize,
    terminal_events: usize,
    last_progress_at: Option<tokio::time::Instant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OverflowLimit {
    SessionFrames,
    /// Watchdog reap: no flush progress for a full stall grace.
    StallGrace,
}

impl OverflowLimit {
    fn as_str(self) -> &'static str {
        match self {
            Self::SessionFrames => "session_frames",
            Self::StallGrace => "stall_grace",
        }
    }
}

pub(super) enum OverflowAction {
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
    pub(super) fn has(&self, sid: u32) -> bool {
        self.streams.contains_key(&sid)
    }

    pub(super) fn usage(&self) -> OverflowUsage {
        OverflowUsage {
            frames: self.frames,
            bytes: self.bytes,
        }
    }

    pub(super) fn stream_usage(&self, sid: u32) -> OverflowUsage {
        self.streams
            .get(&sid)
            .map(|stream| OverflowUsage {
                frames: stream.frames,
                bytes: stream.bytes,
            })
            .unwrap_or_default()
    }

    /// Time since the reader last made flush progress on this stream (or
    /// since the first park, if it never has).
    pub(super) fn stalled_for(&self, sid: u32) -> Duration {
        self.streams
            .get(&sid)
            .and_then(|stream| stream.last_progress_at)
            .map(|progress| progress.elapsed())
            .unwrap_or_default()
    }

    pub(super) fn last_progress_at(&self, sid: u32) -> Option<tokio::time::Instant> {
        self.streams
            .get(&sid)
            .and_then(|stream| stream.last_progress_at)
    }

    pub(super) fn restore_last_progress_at(
        &mut self,
        sid: u32,
        progress: Option<tokio::time::Instant>,
    ) {
        if let (Some(stream), Some(progress)) = (self.streams.get_mut(&sid), progress) {
            stream.last_progress_at = Some(progress);
        }
    }

    /// A parked frame reached the stream queue: the consumer is alive.
    pub(super) fn note_progress(&mut self, sid: u32) {
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

    pub(super) fn push_back(&mut self, sid: u32, event: StreamEvent) {
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

    pub(super) fn push_front(&mut self, sid: u32, event: StreamEvent) {
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

    pub(super) fn pop_front(&mut self, sid: u32) -> Option<StreamEvent> {
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

    pub(super) fn remove_stream(&mut self, sid: u32) -> OverflowUsage {
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

    pub(super) fn clear(&mut self) -> OverflowUsage {
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
    pub(super) fn take_victim(&mut self, sid: u32, limit: OverflowLimit) -> OverflowVictim {
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

    /// Emergency session-wide bound on parked data frames. Payload bytes are
    /// already bounded across every owner by the pool semaphore.
    fn hard_limit(&self) -> Option<OverflowLimit> {
        (self.frames >= SESSION_OVERFLOW_HARD_CAP).then_some(OverflowLimit::SessionFrames)
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
    pub(super) fn admit(&mut self, sid: u32, event: StreamEvent) -> OverflowAction {
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
        let Some(hard) = self.hard_limit() else {
            self.push_back(sid, event);
            return OverflowAction::Parked;
        };
        if let Some(victim_sid) = self.most_stalled_past_grace() {
            return OverflowAction::Kill(self.take_victim(victim_sid, hard), event);
        }
        OverflowAction::Wait(event, self.emergency_wait())
    }
}

impl AnyTlsSession {
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

    pub(super) fn overflow_has(&self, sid: u32) -> bool {
        self.overflow.lock().has(sid)
    }

    pub(super) fn discard_overflow(&self, sid: u32) -> OverflowUsage {
        self.overflow.lock().remove_stream(sid)
    }

    pub(super) fn clear_overflow(&self) -> OverflowUsage {
        self.overflow.lock().clear()
    }

    pub(super) fn kill_overflow_victim(&self, victim: OverflowVictim) {
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

    pub(super) async fn park_overflow(self: &Arc<Self>, sid: u32, mut event: StreamEvent) {
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
            *handle = self
                .task_scope
                .spawn(async move { session.run_overflow_watchdog().await });
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

    pub(super) fn flush_overflow(&self, sid: u32) {
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
}
