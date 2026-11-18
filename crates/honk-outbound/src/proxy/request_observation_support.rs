//! Fixtures for tests of when a handshake publishes `TargetRequestSent`.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::runtime::flow_observation::{
    FlowContext, FlowEvent, FlowObserver, Milestone, RequestWrite,
};

pub(super) type Events = Arc<parking_lot::Mutex<Vec<FlowEvent>>>;

pub(super) fn observed() -> (FlowObserver, Events) {
    let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let observer = FlowObserver::new(
        FlowContext {
            flow_id: uuid::Uuid::new_v4(),
            generation: 1,
            attempt_id: Some(uuid::Uuid::new_v4()),
            lookup_id: None,
            dns_purpose: "proxy_server",
        },
        Arc::new(move |_, event| captured.lock().push(event)),
    );
    (observer, events)
}

pub(super) fn milestones(events: &[FlowEvent], expected: Milestone) -> usize {
    events
        .iter()
        .filter(
            |event| matches!(event, FlowEvent::Milestone { milestone } if *milestone == expected),
        )
        .count()
}

pub(super) type PendingRequest = Arc<parking_lot::Mutex<Option<(RequestWrite, u64)>>>;

/// Defers the request event until the test reports delivery, as an
/// observed frame transport does.
#[derive(Debug)]
pub(super) struct DeferringCarrier<T> {
    inner: T,
    accepted: u64,
    request: PendingRequest,
}

impl<T> DeferringCarrier<T> {
    pub(super) fn new(inner: T) -> (Self, PendingRequest) {
        let request = PendingRequest::default();
        let carrier = Self {
            inner,
            accepted: 0,
            request: Arc::clone(&request),
        };
        (carrier, request)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for DeferringCarrier<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for DeferringCarrier<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(size)) = result {
            this.accepted += size as u64;
            if size != 0
                && let Some(request) = RequestWrite::current()
            {
                request.defer(this.accepted);
                *this.request.lock() = Some((request, this.accepted));
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
