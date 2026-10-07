use super::XhttpRuntime;
use super::response::{ResponseReader, clone_error};
use crate::runtime::NodeRuntime;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::task::{ArcWake, AtomicWaker, waker_ref};
use parking_lot::Mutex;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
};

pub(super) struct WriteState {
    pub(super) bytes: BytesMut,
    pub(super) accepted: u64,
    pub(super) flushed: u64,
    pub(super) shutdown: bool,
    pub(super) finished: bool,
    pub(super) error: Option<Arc<io::Error>>,
}
pub(super) struct Flow {
    pub(super) state: Mutex<WriteState>,
    pub(super) changed: Notify,
    pub(super) write: AtomicWaker,
    pub(super) read: AtomicWaker,
    pub(super) limit: usize,
}
impl ArcWake for Flow {
    fn wake_by_ref(flow: &Arc<Self>) {
        flow.read.wake();
        flow.write.wake();
    }
}
impl Flow {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(WriteState {
                bytes: BytesMut::new(),
                accepted: 0,
                flushed: 0,
                shutdown: false,
                finished: false,
                error: None,
            }),
            changed: Notify::new(),
            write: AtomicWaker::new(),
            read: AtomicWaker::new(),
            limit,
        })
    }
    pub(super) fn fail(&self, error: io::Error) {
        self.state
            .lock()
            .error
            .get_or_insert_with(|| Arc::new(error));
        self.write.wake();
        self.read.wake();
        self.changed.notify_waiters();
    }
    pub(super) fn error(&self) -> Option<io::Error> {
        self.state.lock().error.as_ref().map(clone_error)
    }
    pub(super) fn sent(&self, count: u64, finished: bool) {
        let mut state = self.state.lock();
        state.flushed += count;
        state.finished |= finished;
        drop(state);
        self.write.wake();
    }
}
pub(super) struct FlowPermit {
    pub(super) permit: Option<tokio::sync::OwnedSemaphorePermit>,
    pub(super) transport: Arc<XhttpRuntime>,
}
impl Drop for FlowPermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.transport.finish_retirement();
    }
}

pub(super) struct FlushBarriers {
    pub(super) remaining: u8,
    pub(super) settled_prefix: u64,
}

pub(super) struct XhttpStream {
    pub(super) download: ResponseReader,
    pub(super) flow: Arc<Flow>,
    pub(super) packet_flush_barriers: Option<FlushBarriers>,
    pub(super) driver: tokio::task::AbortHandle,
    pub(super) _runtime: Arc<NodeRuntime>,
    pub(super) _flow_permit: FlowPermit,
    pub(super) read_result: Option<Result<(), Arc<io::Error>>>,
    pub(super) payload: Bytes,
}
impl XhttpStream {
    pub(super) fn poll_control(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        self.flow.write.register(cx.waker());
        let wake = waker_ref(&self.flow);
        let stable = &mut Context::from_waker(&wake);
        if let Poll::Ready(Err(error)) = self.download.poll_headers(stable) {
            self.flow.fail(error);
        }
        self.flow.error().map_or(Ok(()), Err)
    }
}
impl std::fmt::Debug for XhttpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XhttpStream").finish_non_exhaustive()
    }
}
impl Drop for XhttpStream {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl AsyncRead for XhttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.flow.read.register(cx.waker());
        loop {
            if !self.payload.is_empty() {
                let len = self.payload.len().min(buf.remaining());
                buf.put_slice(&self.payload[..len]);
                self.payload.advance(len);
                if let Err(error) = self.download.release(len) {
                    self.flow.fail(error);
                }
                return Poll::Ready(Ok(()));
            }
            if let Some(result) = &self.read_result {
                return Poll::Ready(result.as_ref().map(|_| ()).map_err(clone_error));
            }
            // Poll received DATA first: an upload failure cannot discard already buffered RX.
            let flow = self.flow.clone();
            let wake = waker_ref(&flow);
            let stable = &mut Context::from_waker(&wake);
            match self.download.poll_data(stable) {
                Poll::Ready(Ok(Some(bytes))) => {
                    self.payload = bytes;
                }
                Poll::Ready(Ok(None)) => {
                    self.read_result = Some(
                        self.flow
                            .error()
                            .map_or(Ok(()), |error| Err(Arc::new(error))),
                    );
                }
                Poll::Ready(Err(error)) => {
                    let error = Arc::new(error);
                    self.flow.fail(clone_error(&error));
                    self.read_result = Some(Err(error));
                }
                Poll::Pending => {
                    if let Some(error) = self.flow.error() {
                        let error = Arc::new(error);
                        self.read_result = Some(Err(error.clone()));
                        return Poll::Ready(Err(clone_error(&error)));
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}
impl AsyncWrite for XhttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_control(cx)?;
        let mut state = self.flow.state.lock();
        if let Some(error) = &state.error {
            return Poll::Ready(Err(clone_error(error)));
        }
        if state.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP upload half-closed",
            )));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = bytes.len().min(self.flow.limit - state.bytes.len());
        if count == 0 {
            return Poll::Pending;
        }
        state.bytes.extend_from_slice(&bytes[..count]);
        state.accepted += count as u64;
        drop(state);
        self.flow.changed.notify_one();
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_control(cx)?;
        let state = self.flow.state.lock();
        if let Some(error) = &state.error {
            return Poll::Ready(Err(clone_error(error)));
        }
        let accepted = state.accepted;
        let flushed = state.flushed;
        drop(state);
        // Setup flushes precede core's first datagram; later barriers would defeat batching.
        if let Some(barriers) = &mut self.packet_flush_barriers {
            if barriers.remaining == 0 || accepted == barriers.settled_prefix {
                return Poll::Ready(Ok(()));
            }
            if flushed < accepted {
                return Poll::Pending;
            }
            barriers.remaining -= 1;
            barriers.settled_prefix = accepted;
        } else if flushed != accepted {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_control(cx)?;
        let mut state = self.flow.state.lock();
        if let Some(error) = &state.error {
            return Poll::Ready(Err(clone_error(error)));
        }
        state.shutdown = true;
        if state.finished {
            return Poll::Ready(Ok(()));
        }
        drop(state);
        self.flow.changed.notify_one();
        Poll::Pending
    }
}
