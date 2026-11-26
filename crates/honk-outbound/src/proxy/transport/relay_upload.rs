//! VMess ends its upload with an encrypted chunk, not a transport half-close.
//! Fence that write through buffered relays without closing their read sides
//! or turning ordinary flushes into network round trips.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, Weak};
use std::task::{Context, Poll, ready};
use tokio::sync::oneshot;

tokio::task_local! { static TERMINATOR: bool; }

pub(in crate::proxy) fn scope<F: Future>(future: F) -> impl Future<Output = F::Output> {
    TERMINATOR.scope(true, future)
}

pub(super) fn is_terminator() -> bool {
    TERMINATOR.try_with(|marked| *marked).unwrap_or(false)
}

#[cfg(feature = "rprx")]
pub(super) fn drive<T>(marked: bool, poll: impl FnOnce() -> T) -> T {
    TERMINATOR.sync_scope(marked, poll)
}

type Marker = (u64, oneshot::Sender<()>);
pub(super) type MarkerSlot = OnceLock<parking_lot::Mutex<Option<Marker>>>;

#[derive(Debug)]
pub(in crate::proxy) struct Reader {
    request: crate::runtime::flow_observation::RelayedPipe,
    marker: Option<Arc<MarkerSlot>>,
}

impl Reader {
    fn terminator(&self, through: u64) -> Option<oneshot::Sender<()>> {
        let mut marker = self.marker.as_ref()?.get()?.lock();
        if marker.as_ref()?.0 > through {
            return None;
        }
        marker.take().map(|(_, ack)| ack)
    }

    pub(in crate::proxy) async fn forward<E, F: Future<Output = Result<(), E>>>(
        &self,
        through: u64,
        frame: impl FnOnce(bool) -> F,
    ) -> Result<(), E> {
        let ack = self.terminator(through);
        let request = self.request.take(through);
        let frame = frame(ack.is_some() || request.is_some());
        let write = async {
            match request {
                Some(request) => request.write(std::pin::pin!(frame)).await,
                None => frame.await,
            }
        };
        if let Some(ack) = ack {
            scope(write).await?;
            let _ = ack.send(());
            Ok(())
        } else {
            write.await
        }
    }
}

#[derive(Debug)]
pub(in crate::proxy) struct Writer {
    request: crate::runtime::flow_observation::RelayedPipe,
    marker: Weak<MarkerSlot>,
    accepted: u64,
    pending: Option<oneshot::Receiver<()>>,
}

pub(in crate::proxy) fn pipe() -> (Writer, Reader) {
    let request = crate::runtime::flow_observation::RelayedPipe::new();
    // Only VMess (rprx) emits these writes. The worker owns the marker so
    // aborting it fails any outstanding acknowledgment even if the pipe lives.
    let marker = cfg!(feature = "rprx").then(Arc::<MarkerSlot>::default);
    let writer = Writer {
        request: request.clone(),
        marker: marker.as_ref().map(Arc::downgrade).unwrap_or_default(),
        accepted: 0,
        pending: None,
    };
    (writer, Reader { request, marker })
}

impl Writer {
    #[cfg(feature = "rprx")]
    pub(super) fn owner(&self) -> Weak<MarkerSlot> {
        self.marker.clone()
    }

    #[cfg(feature = "rprx")]
    pub(super) fn unforwarded(&self, forwarded: u64) -> Option<u64> {
        self.accepted.checked_sub(forwarded)
    }

    pub(in crate::proxy) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(rx) = &mut self.pending {
            if rx.is_terminated() || ready!(Pin::new(rx).poll(cx)).is_err() {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            self.pending = None;
        }
        Poll::Ready(Ok(()))
    }

    pub(in crate::proxy) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        write: impl FnOnce(&mut Context<'_>) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        if !cfg!(feature = "rprx") {
            return self.request.poll_write(|| write(cx));
        }
        if !is_terminator() {
            let n = ready!(self.request.poll_write(|| write(cx)))?;
            self.accepted += n as u64;
            return Poll::Ready(Ok(n));
        }
        ready!(self.poll_flush(cx))?;
        // Only one writer. Publish the last accepted byte under the same lock
        // the relay takes after its read, before it can forward this frame.
        let Some(slot) = self.marker.upgrade() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let mut marker = slot.get_or_init(Default::default).lock();
        let n = ready!(self.request.poll_write(|| write(cx)))?;
        if n != 0 {
            self.accepted += n as u64;
            let (ack, rx) = oneshot::channel();
            *marker = Some((self.accepted, ack));
            self.pending = Some(rx);
        }
        Poll::Ready(Ok(n))
    }
}
