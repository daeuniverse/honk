use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use honk_outbound::SharedError;
use parking_lot::Mutex;
use tokio::sync::Notify;

mod guards {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use super::{BuildFailure, LifecycleSlot, SharedError, SlotState};

    pub(super) struct CloseGuard<'a, T> {
        slot: &'a LifecycleSlot<T>,
        armed: bool,
    }

    impl<'a, T> CloseGuard<'a, T> {
        pub(super) fn new(slot: &'a LifecycleSlot<T>) -> Self {
            Self { slot, armed: true }
        }

        pub(super) fn complete(mut self) {
            {
                let mut inner = self.slot.inner.lock();
                inner.state = SlotState::Closed;
            }
            self.slot.close_count.fetch_add(1, Ordering::SeqCst);
            self.armed = false;
            self.slot.changed.notify_waiters();
        }
    }

    impl<T> Drop for CloseGuard<'_, T> {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            {
                let mut inner = self.slot.inner.lock();
                if let SlotState::Closing { owner, .. } = &mut inner.state {
                    *owner = false;
                }
            }
            self.slot.changed.notify_waiters();
        }
    }

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

use guards::{BuildGuard, CloseGuard};

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
    Building { generation: u64 },
    Ready(Arc<T>),
    Closing { value: Arc<T>, owner: bool },
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

    pub(crate) async fn acquire<F, Fut>(&self, build: F) -> anyhow::Result<Arc<T>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<T>>,
    {
        let mut build = Some(build);
        let mut waited_generation = None;
        loop {
            let notified = self.changed.notified();
            let action = {
                let mut inner = self.inner.lock();
                if let Some(generation) = waited_generation
                    && let Some(failure) = &inner.last_failure
                    && failure.generation == generation
                {
                    return Err(anyhow::Error::new(failure.error.clone()));
                }
                match &inner.state {
                    SlotState::Ready(value) => return Ok(Arc::clone(value)),
                    SlotState::Building { generation } => {
                        waited_generation = Some(*generation);
                        None
                    }
                    SlotState::Closing { .. } => None,
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

            let Some(generation) = action else {
                notified.await;
                continue;
            };
            let guard = BuildGuard::new(self, generation);
            let initializer = build
                .take()
                .ok_or_else(|| anyhow::anyhow!("initializer was already consumed"))?;
            match initializer().await {
                Ok(value) => return Ok(guard.publish(value)),
                Err(error) => {
                    let error = SharedError::new(error);
                    guard.fail(error.clone());
                    return Err(anyhow::Error::new(error));
                }
            }
        }
    }

    pub(crate) async fn close<F, Fut>(&self, close: F)
    where
        F: FnOnce(Arc<T>) -> Fut,
        Fut: Future<Output = ()>,
    {
        let mut close = Some(close);
        loop {
            let notified = self.changed.notified();
            let resource = {
                let mut inner = self.inner.lock();
                match &mut inner.state {
                    SlotState::Ready(value) => {
                        let value = Arc::clone(value);
                        inner.state = SlotState::Closing {
                            value: Arc::clone(&value),
                            owner: true,
                        };
                        Some(value)
                    }
                    SlotState::Closing { value, owner } if !*owner => {
                        *owner = true;
                        Some(Arc::clone(value))
                    }
                    SlotState::Building { .. } | SlotState::Closing { .. } => None,
                    SlotState::Closed => return,
                }
            };
            let Some(resource) = resource else {
                notified.await;
                continue;
            };
            let guard = CloseGuard::new(self);
            let close_resource = close
                .take()
                .ok_or_else(|| anyhow::anyhow!("close operation was already consumed"));
            if let Ok(close_resource) = close_resource {
                close_resource(resource).await;
            }
            guard.complete();
            return;
        }
    }
}

#[cfg(test)]
mod tests;
