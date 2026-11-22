use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker, ready},
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use parking_lot::Mutex;
use quinn::SendReceipt;
use tokio::task::AbortHandle;

use super::{RequestDelivery, RequestWrite};

/// One chain attempt owns one physical entry stream. A relay may gracefully close its
/// lower writer before Quinn reports submission, so the attempt, not that writer, owns this.
#[derive(Default)]
pub(crate) struct QuicSubmissions {
    cancelled: Mutex<bool>,
    pending: Mutex<Pending>,
}

struct Submission {
    receipt: SendReceipt,
    delivery: Option<RequestDelivery>,
}

impl Future for Submission {
    type Output = (RequestDelivery, bool);
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = ready!(Pin::new(&mut tokio::task::unconstrained(&mut self.receipt)).poll(cx));
        Poll::Ready((
            self.delivery.take().expect("polled after completion"),
            result.is_ok(),
        ))
    }
}

#[derive(Default)]
struct Pending {
    first: Option<Submission>,
    more: Option<FuturesUnordered<Submission>>,
    waiter: Option<Waker>,
    task: Option<AbortHandle>,
}

impl Pending {
    fn reap(&mut self, cx: &mut Context<'_>) {
        if let Some(first) = self.first.as_mut()
            && let Poll::Ready((delivery, confirmed)) = Pin::new(first).poll(cx)
        {
            self.first = None;
            if confirmed {
                delivery.complete();
            }
        }
        if let Some(more) = self.more.as_mut() {
            loop {
                match more.poll_next_unpin(cx) {
                    Poll::Ready(Some((delivery, true))) => delivery.complete(),
                    Poll::Ready(Some((_unconfirmed, false))) => (),
                    Poll::Ready(None) => {
                        self.more = None;
                        return;
                    }
                    Poll::Pending => return,
                }
            }
        }
    }

    fn reap_ready(&mut self) {
        let waker = self.waiter.clone();
        self.reap(&mut Context::from_waker(
            waker.as_ref().unwrap_or(Waker::noop()),
        ));
    }
}

impl QuicSubmissions {
    pub(super) fn publish(&self, report: impl FnOnce()) {
        // Serialize the bounded, non-reentrant callback with cancellation, not with socket I/O.
        let cancelled = self.cancelled.lock();
        if !*cancelled {
            report();
        }
    }

    pub(super) fn cancel(&self) {
        *self.cancelled.lock() = true;
        let pending = std::mem::take(&mut *self.pending.lock());
        if let Some(task) = pending.task {
            task.abort();
        }
    }

    pub(super) fn reap_ready(&self) {
        self.pending.lock().reap_ready();
    }

    pub(crate) fn track(self: &Arc<Self>, receipt: SendReceipt, request: RequestWrite) {
        let mut pending = self.pending.lock();
        if *self.cancelled.lock() {
            return;
        }
        // Reclaim ready prefixes also on registration: a starved worker must not accumulate
        // history beyond outstanding QUIC send credit and its current completion batch.
        pending.reap_ready();
        let submission = Submission {
            receipt,
            delivery: Some(request.pending()),
        };
        if pending.first.is_none() {
            pending.first = Some(submission);
        } else {
            pending
                .more
                .get_or_insert_with(FuturesUnordered::new)
                .push(submission);
        }
        if pending.task.is_some() {
            let wake = pending.waiter.clone();
            drop(pending);
            if let Some(w) = wake {
                w.wake();
            }
            return;
        }
        // TaskOwner admission can close the whole runtime at capacity. This observer owns no
        // endpoint or permit and is bounded and cancelled by the logical attempt itself.
        let owner = Arc::clone(self);
        pending.task = Some(
            tokio::spawn(poll_fn(move |cx| {
                let mut pending = owner.pending.lock();
                pending.waiter = Some(cx.waker().clone());
                pending.reap(cx);
                if pending.first.is_none() && pending.more.is_none() {
                    pending.waiter = None;
                    pending.task = None;
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }))
            .abort_handle(),
        );
    }
}
