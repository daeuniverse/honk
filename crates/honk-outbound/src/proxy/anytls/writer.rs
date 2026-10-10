use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::debug;

use super::padding::write_padded;
use super::{
    AnyTlsSession, BoxedWriter, CMD_PSH, CMD_SETTINGS, CMD_SYN, DataPermit, FRAME_HEADER_LEN,
    WriterQueue,
};

/// One ordered writer command. Data commands hold their frame and byte
/// permits until the writer has flushed the batch they rode in (bounded →
/// backpressure); control commands ride the reserved headroom so SYN/FIN
/// can never be starved by payload.
pub(super) enum FrameCommand {
    Data {
        sid: u32,
        payload: bytes::Bytes,
        _permit: DataPermit,
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
    pub(super) fn encode_into(&self, buf: &mut bytes::BytesMut) {
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

/// Total writer-queue depth (data + control headroom).
pub(super) const WRITER_QUEUE_CAP: usize = 1024;
/// Slots reserved for control frames (SYN/FIN/HEART) — data can never
/// fill the queue past `WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED`.
pub(super) const WRITER_CONTROL_RESERVED: usize = 128;
/// Payload bytes queued ahead of the TLS writer, per session. The frame cap
/// alone allowed 896 × 65,535 bytes (56 MiB) of in-flight payload: at line
/// rate the relay fills it and RSS follows (124 MB peak measured with four
/// upload streams). 8 MiB covers the writer's latency without changing
/// throughput on the same run (62 MB peak).
pub(super) const WRITER_DATA_BYTES_CAP: usize = 8 * 1024 * 1024;
/// sing-anytls bounds control writes at five seconds. A stuck shared writer
/// must become terminal instead of remaining selectable by the session pool.
/// Data batches stay unbounded like upstream: under uplink congestion the
/// queue cap backpressures streams instead of killing the session and every
/// sibling flow with it.
pub(super) const WRITER_IO_TIMEOUT: Duration = Duration::from_secs(5);

impl WriterQueue {
    pub(super) fn new() -> Self {
        Self {
            queue: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            notify: tokio::sync::Notify::new(),
            data_permits: Arc::new(tokio::sync::Semaphore::new(
                WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED,
            )),
            data_bytes: Arc::new(tokio::sync::Semaphore::new(WRITER_DATA_BYTES_CAP)),
            closed: AtomicBool::new(false),
        }
    }

    /// Push commands atomically as one batch (the SYN+PSH opening pair is
    /// never interleaved with another stream's frame).
    pub(super) fn push_batch<const N: usize>(
        &self,
        cmds: [FrameCommand; N],
    ) -> Result<(), [FrameCommand; N]> {
        let mut queue = self.queue.lock();
        if self.closed.load(Ordering::Acquire) || queue.len().saturating_add(N) > WRITER_QUEUE_CAP {
            return Err(cmds);
        }
        queue.extend(cmds);
        drop(queue);
        self.notify.notify_one();
        Ok(())
    }

    pub(super) async fn pop(&self) -> Option<FrameCommand> {
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
    pub(super) fn drain_available(
        &self,
        out: &mut Vec<FrameCommand>,
        max_frames: usize,
        max_bytes: usize,
    ) {
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

    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(super) fn close(&self) {
        let mut queue = self.queue.lock();
        self.closed.store(true, Ordering::Release);
        queue.clear();
        self.data_permits.close();
        self.data_bytes.close();
        drop(queue);
        self.notify.notify_one();
    }
}

/// Batch caps for the writer's opportunistic gather: after the blocking
/// pop, at most this many extra queued frames (or this many serialized
/// bytes) ride the same `write_all` + single `flush`. Only what is already
/// queued is taken — batching never waits, so it adds no latency.
pub(super) const WRITER_BATCH_MAX_FRAMES: usize = 64;
pub(super) const WRITER_BATCH_MAX_BYTES: usize = 256 * 1024;

/// The single writer task for a session: drains the queue in order and
/// gather-writes whole batches per flush — one `write_all` of the
/// concatenated frames instead of a header/payload write pair plus flush
/// per frame (profiling showed flush-per-frame dominating CPU at line
/// rate). Order is preserved; framing is byte-level so batches are
/// transparent to the peer. A physical write failure kills the session
/// (sing `writeControlFrame` parity) — frames already queued are lost
/// with it.
pub(super) async fn session_writer(
    session: Arc<AnyTlsSession>,
    mut write: BoxedWriter,
    queue: Arc<WriterQueue>,
) {
    // Both grow to the first real batch: a pooled idle session (health probes
    // keep dozens warm) otherwise pins about 70 KiB each for nothing.
    let mut batch: Vec<FrameCommand> = Vec::new();
    let mut buf = bytes::BytesMut::new();
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
        let padding = send_padding
            .then(|| session.padding_state.snapshot())
            .filter(|padding| next_packet < padding.stop);
        send_padding = padding.is_some();
        let extra_frames = if initial {
            2
        } else if padding.is_some() {
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
        let control_only = !batch
            .iter()
            .any(|cmd| matches!(cmd, FrameCommand::Data { .. }));
        let write_op = async {
            if let Some(padding) = &padding {
                write_padded(&mut write, &buf, padding, packet).await?;
            } else {
                write.write_all(&buf).await?;
            }
            write.flush().await
        };
        let write_result = if control_only {
            tokio::time::timeout(WRITER_IO_TIMEOUT, write_op).await
        } else {
            Ok(write_op.await)
        };
        let write_error = match write_result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(anyhow::Error::new(error)),
            Err(error) => Some(
                anyhow::Error::new(error)
                    .context(format!("write timed out after {WRITER_IO_TIMEOUT:?}")),
            ),
        };
        let succeeded = write_error.is_none();
        if let Some(reason) = write_error {
            debug!(
                "AnyTLS session {} writer failed, closing: {}",
                session.seq, reason
            );
            let _ = session.terminal_error.set(crate::SharedError::fanout(
                crate::proxy::NodeFailure(reason.context("writer task write failed")).into(),
            ));
        }
        for command in &mut batch {
            match command {
                FrameCommand::Control {
                    cmd: CMD_SYN, sid, ..
                } if succeeded => {
                    session.start_synack_deadline(*sid, pre_write_activity);
                }
                FrameCommand::Control {
                    cmd: CMD_PSH, sid, ..
                } if succeeded => {
                    session.observe_request(*sid, false);
                }
                FrameCommand::Data {
                    sid, completion, ..
                } => {
                    if succeeded {
                        session.observe_request(*sid, true);
                    }
                    if let Some(completion) = completion.take() {
                        let _ = completion.send(succeeded);
                    }
                }
                _ => {}
            }
        }

        batch.clear();
        if !succeeded {
            session.close();
            break;
        }
        if session.is_closed() {
            break;
        }
    }
}
