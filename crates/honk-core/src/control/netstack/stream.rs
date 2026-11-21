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
    packet_source: Option<super::SourceWork>,
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
            packet_source: None,
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

    pub(in crate::control) fn direct_relay_runtime(&self) -> Option<&super::DirectRelayOwner> {
        #[cfg(target_os = "linux")]
        {
            self.scope.0.direct_relay_runtime.get()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    pub(in crate::control) fn packet_source(&self) -> Option<&super::SourceWork> {
        self.packet_source.as_ref()
    }

    pub(super) fn set_packet_source(&mut self, source: super::SourceWork) {
        self.packet_source = Some(source);
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
        self.try_reserve_memory(bytes).ok_or_else(capacity)
    }

    pub(in crate::control) fn try_reserve_memory(&self, bytes: usize) -> Option<MemoryReservation> {
        self.scope.0.budget.reserve(bytes)
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
        let registrations = self.scope.0.with(|inner| {
            let slot = inner.slot(self.id)?;
            slot.app_open = false;
            slot.close_pending = true;
            let registrations = [slot.rx.take(), slot.tx.take()];
            inner.pending_closes += 1;
            inner.closed_apps += 1;
            inner.reap_pending = true;
            Some(registrations)
        });
        drop(registrations);
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
        let mut inner = self.scope.0.inner.lock();
        if let Some(stack) = &mut inner.stack {
            stack.tcp_abort(self.id);
        }
        let wakers = inner
            .slot(self.id)
            .filter(|slot| slot.rx.is_some() || slot.tx.is_some())
            .map(|slot| [slot.rx.take(), slot.tx.take()]);
        self.scope.0.finish_with_wakers(inner, wakers);
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

#[cfg(all(test, target_os = "linux"))]
#[test]
fn direct_relay_runtime_belongs_to_the_original_flow_scope() {
    use honk_netstack::{MemoryBudget, Rx, wire::tcp};
    use std::time::Instant;
    use tokio::runtime::Builder;

    let coordinator = Builder::new_current_thread().build().unwrap();
    let shared = Builder::new_current_thread().build().unwrap();
    let budget = MemoryBudget::new(32 << 20);
    let (realm, mut owners) = super::capture_realm(1280, 64, 1, 1, &budget).unwrap();
    let coordinator_owner = owners.pop().unwrap();
    let driver = coordinator_owner.hand_off();
    let scope = realm.owner(0).unwrap();
    let (other_scope, _other_owner) = super::capture_scope(1280, 64, 1, &budget).unwrap();
    let fence = super::DirectRelayFence::new(&budget).unwrap();

    {
        let _entered = coordinator.enter();
        driver
            .sole_owner()
            .unwrap()
            .publish_direct_relay_runtime(tokio::runtime::Handle::current(), fence.clone())
            .unwrap();
    }
    let _entered = shared.enter();
    assert!(
        scope
            .publish_direct_relay_runtime(tokio::runtime::Handle::current(), fence.clone())
            .is_err()
    );

    let mut packet = [0; 60];
    let len = tcp::emit_packet(
        &mut packet,
        "192.0.2.10".parse().unwrap(),
        "203.0.113.9".parse().unwrap(),
        &tcp::Header {
            src_port: 40000,
            dst_port: 443,
            seq: 100,
            ack: 0,
            flags: tcp::SYN,
            window: 1024,
            urgent: 0,
            options: tcp::Options::default(),
        },
        [&[], &[]],
    )
    .unwrap();
    let now = Instant::now();
    assert_eq!(scope.receive(&packet[..len], now), Rx::Consumed);
    assert_eq!(other_scope.receive(&packet[..len], now), Rx::Consumed);
    let (_, flow) = scope.poll_accept().unwrap();
    let (_, other_flow) = other_scope.poll_accept().unwrap();

    assert_ne!(flow.scope(), other_flow.scope());
    assert_eq!(flow.flow_id(), other_flow.flow_id());
    let owner = flow.direct_relay_runtime().unwrap();
    assert_eq!(owner.runtime.id(), coordinator.handle().id());
    assert!(std::sync::Arc::ptr_eq(&owner.fence, &fence));
    assert!(other_flow.direct_relay_runtime().is_none());
}

#[cfg(test)]
#[tokio::test]
async fn direct_relay_close_waits_for_existing_lease_and_bars_new_owners() {
    let budget = honk_netstack::MemoryBudget::new(4096);
    let fence = super::DirectRelayFence::new(&budget).unwrap();
    let (started, active) = tokio::sync::oneshot::channel();
    let (observed, closing) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let owner = fence.clone();
    let relay = tokio::spawn(async move {
        let _lease = owner.try_join_lease().unwrap();
        started.send(()).unwrap();
        owner.wait_closed().await;
        observed.send(()).unwrap();
        released.await.unwrap();
    });
    active.await.unwrap();
    let last_lease = fence.try_join_lease().unwrap();
    {
        let join = fence.close_and_join();
        tokio::pin!(join);
        assert!(futures::poll!(&mut join).is_pending());
        tokio::time::timeout(std::time::Duration::from_secs(3), closing)
            .await
            .unwrap()
            .unwrap();
        assert!(futures::poll!(std::pin::pin!(fence.wait_closed())).is_ready());
        assert!(fence.try_join_lease().is_none());
        assert!(futures::poll!(&mut join).is_pending());
        release.send(()).unwrap();
        relay.await.unwrap();
        assert!(futures::poll!(&mut join).is_pending());
        drop(last_lease);
        join.await;
    }
    assert!(fence.try_join_lease().is_none());
    assert!(budget.used() > 0);
    drop(fence);
    assert_eq!(budget.used(), 0);
}
