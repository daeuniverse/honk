use honk_netstack::{MemoryBudget, MemoryReservation};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// Tokio task headers, JoinSet links and alignment; the future and buffers are charged separately.
pub(super) const TASK_BOOKKEEPING: usize = 512;

#[derive(Default)]
pub(super) struct TaskRegistry {
    pub(super) closed: bool,
    tasks: tokio::task::JoinSet<()>,
    charges: Option<TaskCharges>,
}

struct TaskCharges {
    entries: Box<[Option<(tokio::task::Id, MemoryReservation)>]>,
    budget: Arc<MemoryBudget>,
    completed: Arc<AtomicUsize>,
    _bytes: MemoryReservation,
}

struct Completed(Arc<AtomicUsize>);

impl Drop for Completed {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Release);
    }
}

impl TaskRegistry {
    pub(super) fn closed() -> Self {
        Self {
            closed: true,
            ..Self::default()
        }
    }

    pub(super) fn accounted(capacity: usize, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        Self::with_completions(capacity, budget, None)
    }

    pub(super) fn with_completions(
        capacity: usize,
        budget: &Arc<MemoryBudget>,
        completed: Option<Arc<AtomicUsize>>,
    ) -> io::Result<Self> {
        let extra = if completed.is_none() {
            3 * size_of::<usize>()
        } else {
            0
        };
        let bytes = capacity
            .checked_mul(size_of::<Option<(tokio::task::Id, MemoryReservation)>>())
            .and_then(|n| n.checked_add(extra))
            .ok_or_else(capacity_error)?;
        let reservation = budget.reserve(bytes).ok_or_else(capacity_error)?;
        Ok(Self {
            closed: false,
            tasks: tokio::task::JoinSet::new(),
            charges: Some(TaskCharges {
                entries: (0..capacity).map(|_| None).collect(),
                budget: Arc::clone(budget),
                completed: completed.unwrap_or_else(|| Arc::new(AtomicUsize::new(0))),
                _bytes: reservation,
            }),
        })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
    pub(super) fn abort_all(&mut self) {
        self.tasks.abort_all();
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.tasks.len()
    }

    pub(super) fn is_accounted(&self) -> bool {
        self.charges.is_some()
    }

    pub(super) fn spawn<F>(
        &mut self,
        future: F,
        buffers: usize,
    ) -> io::Result<tokio::task::AbortHandle>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawn_with(|| future, buffers)
    }

    pub(super) fn spawn_with<F>(
        &mut self,
        create: impl FnOnce() -> F,
        buffers: usize,
    ) -> io::Result<tokio::task::AbortHandle>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "task admission closed",
            ));
        }
        let Some(charges) = &mut self.charges else {
            return Ok(self.tasks.spawn(create()));
        };
        let index = charges
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or_else(capacity_error)?;
        let bytes = size_of::<F>()
            .checked_add(TASK_BOOKKEEPING + size_of::<Completed>())
            .and_then(|n| n.checked_add(buffers))
            .ok_or_else(capacity_error)?;
        let memory = charges.budget.reserve(bytes).ok_or_else(capacity_error)?;
        let future = create();
        let completed = Completed(Arc::clone(&charges.completed));
        let task = self.tasks.spawn(async move {
            future.await;
            drop(completed);
        });
        charges.entries[index] = Some((task.id(), memory));
        Ok(task)
    }

    fn joined(
        &mut self,
        result: Result<(tokio::task::Id, ()), tokio::task::JoinError>,
    ) -> Result<(), tokio::task::JoinError> {
        let id = match &result {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        if let Some(charges) = &mut self.charges
            && let Some(slot) = charges
                .entries
                .iter_mut()
                .find(|slot| slot.as_ref().is_some_and(|(found, _)| *found == id))
        {
            slot.take();
            assert!(charges.completed.fetch_sub(1, Ordering::AcqRel) != 0);
        }
        result.map(|(_, result)| result)
    }

    pub(super) fn try_join_next(&mut self) -> Option<Result<(), tokio::task::JoinError>> {
        self.tasks
            .try_join_next_with_id()
            .map(|result| self.joined(result))
    }

    pub(super) async fn join_next(&mut self) -> Option<Result<(), tokio::task::JoinError>> {
        self.tasks
            .join_next_with_id()
            .await
            .map(|result| self.joined(result))
    }
}

pub(super) fn capacity_error() -> io::Error {
    io::Error::new(io::ErrorKind::OutOfMemory, "packet memory capacity")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{Notify, oneshot};

    #[tokio::test]
    async fn cancelled_task_keeps_allocation_credit_until_it_is_joined() {
        struct Released(Arc<Notify>);
        impl Drop for Released {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let budget = MemoryBudget::new(256 << 10);
        let mut tasks = TaskRegistry::accounted(1, &budget).unwrap();
        let baseline = budget.used();
        let released = Arc::new(Notify::new());
        let observed = Arc::clone(&released);
        let (started, ready) = oneshot::channel();
        let task = tasks
            .spawn(
                async move {
                    let _released = Released(observed);
                    let buffer = vec![0x5a; 65536];
                    started.send(buffer.len()).unwrap();
                    std::future::pending::<()>().await;
                    std::hint::black_box(buffer);
                },
                65536,
            )
            .unwrap();
        assert_eq!(ready.await.unwrap(), 65536);
        task.abort();
        released.notified().await;
        assert!(budget.used() >= baseline + 65536);
        assert!(tasks.spawn(async {}, 0).is_err());
        assert!(tasks.join_next().await.unwrap().unwrap_err().is_cancelled());
        assert_eq!(budget.used(), baseline);
        let task = tasks.spawn(async {}, 0).unwrap();
        drop(task);
        tasks.join_next().await.unwrap().unwrap();
        drop(tasks);
        assert_eq!(budget.used(), 0);
    }
}
