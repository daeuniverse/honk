use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use honk_datapath::ScopeId;
use honk_netstack::{FlowId, MemoryReservation, StreamError, SynInfo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{PacketScope, RetirementCallback, Waiter, capacity, closed, register};

/// Application ownership of an original, Stack-local TCP incarnation.
#[derive(Debug)]
pub struct FlowIo {
    scope: PacketScope,
    id: FlowId,
    local: SocketAddr,
    peer: SocketAddr,
    dscp: u8,
    open: bool,
    routing: Option<crate::control::packet_endpoint::EndpointAdmission>,
}

impl FlowIo {
    pub(super) fn new(scope: PacketScope, syn: SynInfo) -> Self {
        Self {
            scope,
            id: syn.id,
            local: syn.original_dst,
            peer: syn.client,
            dscp: syn.dscp,
            open: true,
            routing: None,
        }
    }

    pub fn scope(&self) -> ScopeId {
        self.scope.scope()
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    pub fn dscp(&self) -> u8 {
        self.dscp
    }
    pub fn flow_id(&self) -> FlowId {
        self.id
    }

    /// Mark only a successfully selected non-Block outbound stream, never pending routing.
    pub(in crate::control) fn mark_rx_admitted(&self) {
        self.scope.0.with(|inner| {
            if inner.closing || inner.finished {
                return;
            }
            if let Some(slot) = inner.slot(self.id)
                && slot.app_open
                && !slot.close_pending
                && !slot.retiring
            {
                slot.rx_admitted = true;
            }
        });
    }

    pub(in crate::control) fn set_routing(
        &mut self,
        routing: Option<crate::control::packet_endpoint::EndpointAdmission>,
    ) {
        self.routing = routing;
    }

    pub(in crate::control) fn take_routing(
        &mut self,
    ) -> Option<crate::control::connection::routing::PacketRoutingSnapshot> {
        self.routing
            .take()
            .map(crate::control::packet_endpoint::EndpointAdmission::into_snapshot)
    }

    pub fn reserve_memory(&self, bytes: usize) -> io::Result<MemoryReservation> {
        self.scope.0.budget.reserve(bytes).ok_or_else(capacity)
    }

    /// The guard aborts on cancellation; exact completion is still owned by the runtime.
    pub fn retirement(&self) -> FlowRetirement {
        FlowRetirement {
            scope: self.scope.clone(),
            id: self.id,
            completed: false,
        }
    }

    /// Install before publishing core registration. Closure backing is charged before boxing;
    /// callers retain their own charges for heap-backed captures. Runs outside the runtime
    /// mutex at exact retirement, including on cancellation.
    pub fn set_retirement_callback<F: FnOnce() + Send + 'static>(
        &mut self,
        callback: F,
    ) -> io::Result<()> {
        set_callback(&self.scope, self.id, callback)
    }

    fn close(&mut self) {
        if !self.open {
            return;
        }
        self.open = false;
        self.scope.0.with(|inner| {
            if let Some(slot) = inner.slot(self.id) {
                slot.app_open = false;
                slot.close_pending = true;
                slot.rx = None;
                slot.tx = None;
                inner.pending_closes += 1;
                inner.closed_apps += 1;
            }
        });
    }

    pub fn abort(&mut self) {
        self.scope.0.with(|inner| {
            if let Some(stack) = &mut inner.stack {
                stack.tcp_abort(self.id);
            }
        });
        self.close();
    }

    /// Release application ownership, then wait for protocol state and every original output.
    /// Cancellation leaves a runtime-owned callback/alias, not a detached cleanup task.
    pub async fn retire(&mut self) -> io::Result<()> {
        self.close();
        wait(&self.scope, self.id).await
    }
}

impl Drop for FlowIo {
    fn drop(&mut self) {
        self.close();
    }
}

/// A cancellation guard, not kernel capture/handoff or final-retirement evidence by itself.
#[derive(Debug)]
pub struct FlowRetirement {
    scope: PacketScope,
    id: FlowId,
    completed: bool,
}

impl FlowRetirement {
    pub fn abort(&self) {
        self.scope.0.with(|inner| {
            if let Some(stack) = &mut inner.stack {
                stack.tcp_abort(self.id);
            }
            if let Some(slot) = inner.slot(self.id) {
                if let Some(waker) = slot.rx.take() {
                    waker.wake();
                }
                if let Some(waker) = slot.tx.take() {
                    waker.wake();
                }
            }
        });
    }

    pub fn on_retired<F: FnOnce() + Send + 'static>(&self, callback: F) -> io::Result<()> {
        set_callback(&self.scope, self.id, callback)
    }

    pub async fn wait(&mut self) -> io::Result<()> {
        wait(&self.scope, self.id).await?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for FlowRetirement {
    fn drop(&mut self) {
        if !self.completed {
            self.abort();
        }
    }
}

fn set_callback<F: FnOnce() + Send + 'static>(
    scope: &PacketScope,
    id: FlowId,
    callback: F,
) -> io::Result<()> {
    let memory = scope
        .0
        .budget
        .reserve(size_of::<F>())
        .ok_or_else(capacity)?;
    let mut callback = Some(RetirementCallback {
        callback: Box::new(callback),
        _memory: memory,
    });
    scope.0.with(|inner| {
        let slot = inner.slot(id).ok_or_else(closed)?;
        if slot.callback.is_some() || slot.retiring {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "retirement callback already set",
            ));
        }
        slot.callback = callback.take();
        Ok(())
    })
}

async fn wait(scope: &PacketScope, id: FlowId) -> io::Result<()> {
    let mut waiter = Waiter::new(scope.clone());
    poll_fn(|cx| {
        scope.0.with(|inner| {
            if inner.slot(id).is_none() {
                Poll::Ready(Ok(()))
            } else {
                waiter.pending(inner, cx)
            }
        })
    })
    .await
}

fn stream_error(error: StreamError) -> io::Error {
    let kind = match error {
        StreamError::WouldBlock => io::ErrorKind::WouldBlock,
        StreamError::Closed => io::ErrorKind::BrokenPipe,
        StreamError::Reset => io::ErrorKind::ConnectionReset,
        StreamError::TimedOut => io::ErrorKind::TimedOut,
        StreamError::Unreachable => io::ErrorKind::HostUnreachable,
        StreamError::Stale => io::ErrorKind::NotConnected,
    };
    io::Error::new(kind, error)
}

impl AsyncRead for FlowIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.scope.0.with(|inner| {
            let Some(stack) = &mut inner.stack else {
                return Poll::Ready(Err(closed()));
            };
            match stack.tcp_read(self.id, buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    Poll::Ready(Ok(()))
                }
                Err(StreamError::WouldBlock) => {
                    if let Some(slot) = inner.slot(self.id) {
                        register(&mut slot.rx, cx.waker());
                    }
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(stream_error(error))),
            }
        })
    }
}

impl AsyncWrite for FlowIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.scope.0.with(|inner| {
            let Some(stack) = &mut inner.stack else {
                return Poll::Ready(Err(closed()));
            };
            match stack.tcp_write(self.id, data) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(StreamError::WouldBlock) => {
                    if let Some(slot) = inner.slot(self.id) {
                        register(&mut slot.tx, cx.waker());
                    }
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(stream_error(error))),
            }
        })
    }

    /// Accepted bytes belong to the stack's retransmission queue until acknowledged.
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.open && self.scope.0.inner.lock().stack.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(closed()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.scope.0.with(|inner| {
            let Some(stack) = &mut inner.stack else {
                return Poll::Ready(Err(closed()));
            };
            match stack.tcp_shutdown(self.id) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(StreamError::WouldBlock) => {
                    if let Some(slot) = inner.slot(self.id) {
                        register(&mut slot.tx, cx.waker());
                    }
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(stream_error(error))),
            }
        })
    }
}
