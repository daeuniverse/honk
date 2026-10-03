use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use honk_outbound::SharedError;
use parking_lot::Mutex;
use tokio::sync::Notify;

mod guards {
    use std::sync::Arc;

    use super::{BuildFailure, LifecycleSlot, SharedError, SlotState};

    pub(super) struct BuildGuard<'a, T> {
        slot: &'a LifecycleSlot<T>,
        generation: u64,
        armed: bool,
    }

    impl<'a, T> BuildGuard<'a, T> {
        pub(super) fn new(slot: &'a LifecycleSlot<T>, generation: u64) -> Self {
            Self {
                slot,
                generation,
                armed: true,
            }
        }

        pub(super) fn publish(mut self, value: T) -> Arc<T> {
            let value = Arc::new(value);
            {
                let mut inner = self.slot.inner.lock();
                inner.state = SlotState::Ready(Arc::clone(&value));
            }
            self.armed = false;
            self.slot.changed.notify_waiters();
            value
        }

        pub(super) fn fail(mut self, error: SharedError) {
            self.record_failure(error);
            self.armed = false;
        }

        fn record_failure(&self, error: SharedError) {
            {
                let mut inner = self.slot.inner.lock();
                if matches!(
                    inner.state,
                    SlotState::Building { generation } if generation == self.generation
                ) {
                    inner.state = SlotState::Closed;
                    inner.last_failure = Some(BuildFailure {
                        generation: self.generation,
                        error,
                    });
                }
            }
            self.slot.changed.notify_waiters();
        }
    }

    impl<T> Drop for BuildGuard<'_, T> {
        fn drop(&mut self) {
            if self.armed {
                self.record_failure(SharedError::new(anyhow::anyhow!(
                    "transport initialization cancelled"
                )));
            }
        }
    }
}

use guards::BuildGuard;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifecycleState {
    Building,
    Ready,
    Closing,
    Closed,
}

struct BuildFailure {
    generation: u64,
    error: SharedError,
}

enum SlotState<T> {
    Building {
        generation: u64,
    },
    Ready(Arc<T>),
    Closing {
        value: Arc<T>,
        teardown: Shared<BoxFuture<'static, ()>>,
    },
    Closed,
}

struct SlotInner<T> {
    state: SlotState<T>,
    generation: u64,
    last_failure: Option<BuildFailure>,
}

pub(crate) struct LifecycleSlot<T> {
    inner: Mutex<SlotInner<T>>,
    changed: Notify,
    init_count: AtomicUsize,
    close_count: AtomicUsize,
}

impl<T> Default for LifecycleSlot<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LifecycleSlot<T> {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(SlotInner {
                state: SlotState::Closed,
                generation: 0,
                last_failure: None,
            }),
            changed: Notify::new(),
            init_count: AtomicUsize::new(0),
            close_count: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> LifecycleState {
        match &self.inner.lock().state {
            SlotState::Building { .. } => LifecycleState::Building,
            SlotState::Ready(_) => LifecycleState::Ready,
            SlotState::Closing { .. } => LifecycleState::Closing,
            SlotState::Closed => LifecycleState::Closed,
        }
    }

    pub(crate) fn init_count(&self) -> usize {
        self.init_count.load(Ordering::SeqCst)
    }

    pub(crate) fn close_count(&self) -> usize {
        self.close_count.load(Ordering::SeqCst)
    }

    async fn finish_close(&self, value: Arc<T>, teardown: Shared<BoxFuture<'static, ()>>) {
        teardown.await;
        let mut inner = self.inner.lock();
        if matches!(&inner.state, SlotState::Closing { value: current, .. } if Arc::ptr_eq(current, &value))
        {
            inner.state = SlotState::Closed;
            self.close_count.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
        }
    }

    /// The reuse flag includes callers coalesced behind another caller's build.
    /// Acquiring a pool wrapper is not evidence of a physical connection.
    pub(crate) async fn acquire<F, Fut>(&self, build: F) -> anyhow::Result<(Arc<T>, bool)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<T>>,
    {
        let mut build = Some(build);
        let mut waited_generation = None;
        loop {
            let notified = self.changed.notified();
            let mut closing = None;
            let action = {
                let mut inner = self.inner.lock();
                if let Some(generation) = waited_generation
                    && let Some(failure) = &inner.last_failure
                    && failure.generation == generation
                {
                    return Err(anyhow::Error::new(failure.error.clone()));
                }
                match &inner.state {
                    SlotState::Ready(value) => return Ok((Arc::clone(value), true)),
                    SlotState::Building { generation } => {
                        waited_generation = Some(*generation);
                        None
                    }
                    SlotState::Closing { value, teardown } => {
                        closing = Some((Arc::clone(value), teardown.clone()));
                        None
                    }
                    SlotState::Closed => {
                        inner.generation = inner.generation.wrapping_add(1);
                        let generation = inner.generation;
                        inner.state = SlotState::Building { generation };
                        self.init_count.fetch_add(1, Ordering::SeqCst);
                        crate::stats::record_dns_event(crate::stats::DnsStatEvent::TransportInit);
                        tracing::debug!(phase = "start", "DNS transport initialization");
                        Some(generation)
                    }
                }
            };

            if let Some((value, teardown)) = closing {
                self.finish_close(value, teardown).await;
                continue;
            }

            let Some(generation) = action else {
                notified.await;
                continue;
            };
            let guard = BuildGuard::new(self, generation);
            let initializer = build
                .take()
                .ok_or_else(|| anyhow::anyhow!("initializer was already consumed"))?;
            match initializer().await {
                Ok(value) => return Ok((guard.publish(value), false)),
                Err(error) => {
                    let error = SharedError::fanout(error);
                    guard.fail(error.clone());
                    return Err(anyhow::Error::new(error));
                }
            }
        }
    }

    pub(crate) async fn close<F, Fut>(&self, close: F)
    where
        T: Send + Sync + 'static,
        F: FnOnce(Arc<T>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.close_observed(None, close).await;
    }

    pub(crate) async fn retire<F, Fut>(&self, observed: &Arc<T>, close: F)
    where
        T: Send + Sync + 'static,
        F: FnOnce(Arc<T>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.close_observed(Some(observed), close).await;
    }

    async fn close_observed<F, Fut>(&self, observed: Option<&Arc<T>>, close: F)
    where
        T: Send + Sync + 'static,
        F: FnOnce(Arc<T>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (value, teardown) = loop {
            let notified = self.changed.notified();
            {
                let mut inner = self.inner.lock();
                match &inner.state {
                    SlotState::Ready(value) | SlotState::Closing { value, .. }
                        if observed.is_some_and(|observed| !Arc::ptr_eq(value, observed)) =>
                    {
                        return;
                    }
                    SlotState::Ready(value) => {
                        let value = Arc::clone(value);
                        let resource = Arc::clone(&value);
                        // Invoke the callback only when polled after releasing the state lock.
                        let teardown = async move { close(resource).await }.boxed().shared();
                        inner.state = SlotState::Closing {
                            value: Arc::clone(&value),
                            teardown: teardown.clone(),
                        };
                        break (value, teardown);
                    }
                    SlotState::Closing { value, teardown } => {
                        break (Arc::clone(value), teardown.clone());
                    }
                    SlotState::Building { .. } if observed.is_none() => {}
                    SlotState::Building { .. } | SlotState::Closed => return,
                }
            }
            notified.await;
        };
        self.finish_close(value, teardown).await;
    }
}

pub(super) fn attached() {
    if let Some(observer) = honk_outbound::runtime::flow_observation::current() {
        observer.publish(
            honk_outbound::runtime::flow_observation::FlowEvent::TransportAttached {
                server_addr: None,
                resolution_location:
                    honk_outbound::runtime::flow_observation::ResolutionLocation::Unknown,
            },
        );
    }
}

use honk_outbound::runtime::flow_observation::SessionEvent;

pub(super) struct SessionObservation {
    observer: Option<honk_outbound::runtime::flow_observation::FlowObserver>,
    finished: bool,
}

impl SessionObservation {
    pub(super) fn start() -> Self {
        Self {
            observer: honk_outbound::runtime::flow_observation::current(),
            finished: false,
        }
    }

    pub(super) fn record(&self, event: SessionEvent) {
        if let Some(observer) = &self.observer {
            observer.publish(honk_outbound::runtime::flow_observation::FlowEvent::Session(event));
        }
    }

    pub(super) fn finish<T>(
        mut self,
        result: anyhow::Result<T>,
        success: SessionEvent,
    ) -> anyhow::Result<T> {
        if self.observer.is_some() {
            self.record(match &result {
                Ok(_) => success,
                Err(error) => match honk_outbound::proxy::packet_rejection(error) {
                    Some(honk_outbound::proxy::PacketRejection::Cancelled) => {
                        SessionEvent::DnsSessionReadyCancelled
                    }
                    Some(_) => SessionEvent::DnsSessionReadyRefused,
                    None => SessionEvent::DnsSessionReadyFailed,
                },
            });
        }
        self.finished = true;
        result
    }
}

impl Drop for SessionObservation {
    fn drop(&mut self) {
        if !self.finished {
            self.record(SessionEvent::DnsSessionReadyCancelled);
        }
    }
}

pub(crate) struct SessionFailure<T> {
    session: std::sync::Weak<T>,
    error: anyhow::Error,
}

impl<T: 'static> SessionFailure<T> {
    pub(crate) fn new(session: Arc<T>, error: anyhow::Error) -> Self {
        Self {
            session: Arc::downgrade(&session),
            error,
        }
    }

    pub(crate) fn session(error: &anyhow::Error) -> Option<Arc<T>> {
        error
            .chain()
            .find_map(|source| source.downcast_ref::<Self>())
            .and_then(|failure| failure.session.upgrade())
    }
}

impl<T> std::fmt::Debug for SessionFailure<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.error, formatter)
    }
}

impl<T> std::fmt::Display for SessionFailure<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, formatter)
    }
}

impl<T> std::error::Error for SessionFailure<T> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

#[cfg(test)]
mod tests;
