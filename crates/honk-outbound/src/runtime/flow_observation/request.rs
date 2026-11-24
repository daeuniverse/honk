use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
};

use parking_lot::Mutex;

use super::{FlowObserver, Milestone, REQUEST_WRITE, current, is_suppressed};
use crate::proxy::ProxyStream;

mod submission;
pub(crate) use submission::QuicSubmissions;

struct Attempt(Option<Arc<QuicSubmissions>>);

impl Drop for Attempt {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            owner.cancel();
        }
    }
}

pub(crate) async fn observe_chain_request<F: Future<Output = anyhow::Result<ProxyStream>>>(
    dial: F,
) -> anyhow::Result<ProxyStream> {
    let Some(mut observer) =
        current().filter(|flow| flow.dropped & Milestone::TargetRequestSent.bit() == 0)
    else {
        return dial.await;
    };
    let owner = Arc::new(QuicSubmissions::default());
    observer.request_lifetime = Some(Arc::downgrade(&owner));
    let mut attempt = Attempt(Some(owner.clone()));
    match observer.scope(dial).await {
        Ok(stream) => Ok(stream.with_owner(attempt)),
        Err(error) => {
            // A protocol error after a successful request write does not undo its submission.
            // Reap available facts before the caller records the terminal dial result.
            owner.reap_ready();
            if crate::proxy::packet_rejection(&error)
                != Some(crate::proxy::PacketRejection::Cancelled)
            {
                attempt.0.take();
            }
            Err(error)
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RequestWrite(Arc<Request>);

#[derive(Debug)]
struct Request {
    target: Target,
    failed: AtomicBool,
    private_receipts: Mutex<std::sync::Weak<QuicSubmissions>>,
}

#[derive(Debug)]
enum Target {
    Flow(FlowObserver),
    // One encoded frame can carry bytes from several logical requests.
    Frame(Vec<RequestDelivery>),
}

impl Drop for Request {
    fn drop(&mut self) {
        if *self.failed.get_mut() {
            return;
        }
        match &mut self.target {
            Target::Flow(flow) => {
                let publish = || flow.milestone_once(Milestone::TargetRequestSent);
                match &flow.request_lifetime {
                    Some(owner) => {
                        if let Some(owner) = owner.upgrade() {
                            owner.publish(publish);
                        }
                    }
                    None => publish(),
                }
            }
            Target::Frame(parents) => {
                for parent in parents.drain(..) {
                    parent.complete();
                }
            }
        }
    }
}

impl RequestWrite {
    fn new(target: Target) -> Self {
        Self(Arc::new(Request {
            target,
            private_receipts: Default::default(),
            failed: AtomicBool::new(false),
        }))
    }

    pub(crate) fn current() -> Option<Self> {
        if is_suppressed() {
            return None;
        }
        REQUEST_WRITE
            .try_with(Clone::clone)
            .ok()
            .flatten()
            .filter(|request| !request.0.failed.load(Ordering::Relaxed))
    }

    fn lifetime(&self) -> Option<&std::sync::Weak<QuicSubmissions>> {
        match &self.0.target {
            Target::Flow(flow) => flow.request_lifetime.as_ref(),
            Target::Frame(parents) => {
                let owner = parents.first()?.request().lifetime()?;
                parents
                    .iter()
                    .skip(1)
                    .all(|parent| {
                        parent
                            .request()
                            .lifetime()
                            .is_some_and(|other| other.ptr_eq(owner))
                    })
                    .then_some(owner)
            }
        }
    }

    pub(crate) fn track(self, receipt: quinn::SendReceipt) {
        let owner = if let Some(attempt) = self.lifetime() {
            let Some(owner) = attempt.upgrade() else {
                return;
            };
            owner
        } else {
            // A manually composed request, or a frame joining distinct owners, must not
            // charge its whole submission to the lifetime of an arbitrary first parent.
            let mut slot = self.0.private_receipts.lock();
            slot.upgrade().unwrap_or_else(|| {
                let owner = Arc::new(QuicSubmissions::default());
                *slot = Arc::downgrade(&owner);
                owner
            })
        };
        owner.track(receipt, self);
    }

    pub(crate) fn pending(self) -> RequestDelivery {
        RequestDelivery(Some(self))
    }
}

/// An uncompleted obligation fails on drop. The final successful release publishes once.
#[derive(Debug)]
pub(crate) struct RequestDelivery(Option<RequestWrite>);

impl RequestDelivery {
    fn request(&self) -> &RequestWrite {
        self.0.as_ref().expect("live request delivery")
    }

    pub(crate) fn complete(mut self) {
        self.0.take();
    }

    async fn write<T, E>(
        self,
        write: Pin<&mut impl Future<Output = Result<T, E>>>,
    ) -> Result<T, E> {
        let result = REQUEST_WRITE
            .scope(Some(self.request().clone()), write)
            .await;
        if result.is_ok() {
            self.complete();
        }
        result
    }
}

impl Drop for RequestDelivery {
    fn drop(&mut self) {
        if let Some(request) = &self.0 {
            request.0.failed.store(true, Ordering::Relaxed);
        }
    }
}

pub(crate) async fn request_write<T, E>(
    future: Pin<&mut impl Future<Output = Result<T, E>>>,
) -> Result<T, E> {
    let Some(observer) =
        current().filter(|flow| flow.dropped & Milestone::TargetRequestSent.bit() == 0)
    else {
        return future.await;
    };
    RequestWrite::new(Target::Flow(observer))
        .pending()
        .write(future)
        .await
}

#[derive(Debug)]
struct Span {
    start: u64,
    end: u64,
    delivery: RequestDelivery,
}

#[derive(Debug, Default)]
struct PipeState {
    accepted: AtomicU64,
    spans: Mutex<VecDeque<Span>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RelayedPipe(Arc<PipeState>);

impl RelayedPipe {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn poll_write(
        &self,
        write: impl FnOnce() -> Poll<std::io::Result<usize>>,
    ) -> Poll<std::io::Result<usize>> {
        let Some(request) = RequestWrite::current() else {
            let result = write();
            if let Poll::Ready(Ok(n)) = result {
                self.0.accepted.fetch_add(n as u64, Ordering::Relaxed);
            }
            return result;
        };
        // Publish the byte span before a concurrent reader can claim those bytes.
        let mut spans = self.0.spans.lock();
        let result = write();
        if let Poll::Ready(Ok(n)) = result
            && n != 0
        {
            let start = self.0.accepted.fetch_add(n as u64, Ordering::Relaxed);
            let end = start + n as u64;
            if let Some(last) = spans.back_mut()
                && last.end == start
                && Arc::ptr_eq(&last.delivery.request().0, &request.0)
            {
                last.end = end;
            } else {
                spans.push_back(Span {
                    start,
                    end,
                    delivery: request.pending(),
                });
            }
        }
        result
    }

    pub(crate) fn take(&self, relayed: u64) -> Option<RelayedRequest> {
        let mut spans = self.0.spans.lock();
        let mut first: Option<RequestDelivery> = None;
        let mut more = Vec::new();
        while let Some(span) = spans.front_mut()
            && span.start < relayed
        {
            // A prefix read is a distinct delivery obligation, even when the last byte is
            // still in the pipe. Adjacent reads cannot stand in for each other.
            let delivery = if span.end <= relayed {
                spans.pop_front().unwrap().delivery
            } else {
                span.start = relayed;
                span.delivery.request().clone().pending()
            };
            match &first {
                None => first = Some(delivery),
                Some(prior) if Arc::ptr_eq(&prior.request().0, &delivery.request().0) => {
                    delivery.complete()
                }
                Some(_) => more.push(delivery),
            }
        }
        let first = first?;
        let delivery = if more.is_empty() {
            first
        } else {
            more.push(first);
            RequestWrite::new(Target::Frame(more)).pending()
        };
        Some(RelayedRequest(delivery))
    }
}

#[derive(Debug)]
pub(crate) struct RelayedRequest(RequestDelivery);

impl RelayedRequest {
    pub(crate) async fn write<T, E>(
        self,
        write: Pin<&mut impl Future<Output = Result<T, E>>>,
    ) -> Result<T, E> {
        self.0.write(write).await
    }
}

#[derive(Debug, Default)]
pub(crate) struct DriverRequest(Option<RequestDelivery>);

impl DriverRequest {
    pub(crate) const fn new() -> Self {
        Self(None)
    }
    pub(crate) fn capture(&mut self) {
        self.0 = RequestWrite::current().map(RequestWrite::pending);
    }
    pub(crate) fn drive<T>(&self, poll: impl FnOnce() -> T) -> T {
        REQUEST_WRITE.sync_scope(self.0.as_ref().map(|d| d.request().clone()), poll)
    }
    pub(crate) fn release(&mut self) {
        if let Some(pending) = self.0.take() {
            pending.complete();
        }
    }
    pub(crate) fn discard(&mut self) {
        self.0 = None;
    }
}
