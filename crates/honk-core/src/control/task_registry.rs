use futures::{
    FutureExt,
    future::{AbortHandle, AbortRegistration},
    task::AtomicWaker,
};
use honk_netstack::{MemoryBudget, MemoryReservation};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

// Tokio task headers, JoinSet links and alignment; the future and buffers are charged separately.
pub(super) const TASK_BOOKKEEPING: usize = 512;

// The abort pair shares an Arc allocation for the waker and flag, including header and padding.
const ABORT_PAIR_MEMORY: usize = size_of::<AtomicWaker>() + 5 * size_of::<usize>();

#[derive(Default)]
pub(super) struct TaskRegistry {
    pub(super) closed: bool,
    tasks: tokio::task::JoinSet<()>,
    charges: Option<TaskCharges>,
}

struct TaskCharge {
    state: TaskState,
    _memory: MemoryReservation,
}

enum TaskState {
    Ordinary(tokio::task::AbortHandle),
    Scoped(tokio::task::Id, AbortHandle),
    Joined(tokio::task::Id),
    JoinError(tokio::task::JoinError),
}

impl TaskCharge {
    fn id(&self) -> tokio::task::Id {
        match &self.state {
            TaskState::Ordinary(handle) => handle.id(),
            TaskState::Scoped(id, _) | TaskState::Joined(id) => *id,
            TaskState::JoinError(error) => error.id(),
        }
    }
}

fn joined_id(result: &Result<(tokio::task::Id, ()), tokio::task::JoinError>) -> tokio::task::Id {
    match result {
        Ok((id, ())) => *id,
        Err(error) => error.id(),
    }
}

struct TaskCharges {
    entries: Box<[Option<TaskCharge>]>,
    budget: Arc<MemoryBudget>,
    completed: Arc<AtomicUsize>,
    runtime: Option<tokio::runtime::Handle>,
    _bytes: MemoryReservation,
}

// Its own terminal Tokio bookkeeping is the only backing left when reaper credit is released.
struct TaskReaper {
    tasks: tokio::task::JoinSet<()>,
    charges: TaskCharges,
}

impl Future for TaskReaper {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let Self { tasks, charges } = self.get_mut();
        while let Some(result) = std::task::ready!(tasks.poll_join_next_with_id(cx)) {
            let key = Some(joined_id(&result));
            let index = charges
                .entries
                .binary_search_by_key(&key, |slot| slot.as_ref().map(TaskCharge::id))
                .expect("accounted task charge");
            // A panic payload may panic on Drop, so retain every result until all joins.
            charges.entries[index].as_mut().unwrap().state = match result {
                Ok((id, ())) => TaskState::Joined(id),
                Err(error) => TaskState::JoinError(error),
            };
            charges.completed.fetch_sub(1, Ordering::AcqRel);
        }
        Poll::Ready(())
    }
}

impl Drop for TaskRegistry {
    fn drop(&mut self) {
        if self.tasks.is_empty() || self.charges.is_none() {
            return;
        }
        self.abort_all();
        let tasks = std::mem::take(&mut self.tasks);
        let mut charges = self.charges.take().expect("accounted registry");
        // Index live handles and retained results in place so the reaper needs no extra table.
        charges
            .entries
            .sort_unstable_by_key(|slot| slot.as_ref().map(TaskCharge::id));
        // The embedding must keep this runtime running until owned cleanup completes.
        let runtime = charges
            .runtime
            .as_ref()
            .expect("accounted task runtime")
            .clone();
        drop(runtime.spawn(TaskReaper { tasks, charges }));
    }
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
            tasks: tokio::task::JoinSet::new(),
            charges: None,
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
            .checked_mul(size_of::<Option<TaskCharge>>())
            .and_then(|n| n.checked_add(extra))
            .and_then(|n| n.checked_add(TASK_BOOKKEEPING + size_of::<TaskReaper>()))
            .ok_or_else(capacity_error)?;
        let reservation = budget.reserve(bytes).ok_or_else(capacity_error)?;
        Ok(Self {
            closed: false,
            tasks: tokio::task::JoinSet::new(),
            charges: Some(TaskCharges {
                entries: (0..capacity).map(|_| None).collect(),
                budget: Arc::clone(budget),
                completed: completed.unwrap_or_else(|| Arc::new(AtomicUsize::new(0))),
                runtime: None,
                _bytes: reservation,
            }),
        })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
    pub(super) fn abort_all(&mut self) {
        if let Some(charges) = &self.charges {
            for task in charges.entries.iter().flatten() {
                match &task.state {
                    TaskState::Ordinary(handle) => handle.abort(),
                    TaskState::Scoped(_, handle) => handle.abort(),
                    TaskState::Joined(_) | TaskState::JoinError(_) => {}
                }
            }
        } else {
            self.tasks.abort_all();
        }
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
        self.check_open()?;
        if self.charges.is_none() {
            return Ok(self.tasks.spawn(create()));
        }
        self.spawn_accounted(
            |completed| {
                let future = create();
                let completed = Completed(completed);
                (future.map(move |()| drop(completed)), None)
            },
            buffers,
            Some(size_of::<F>() + size_of::<Completed>()),
        )
        .map(|task| task.expect("ordinary task abort handle"))
    }

    /// The registration cancels the work while the funded task can still join its owner.
    pub(super) fn spawn_scoped_with<F>(
        &mut self,
        create: impl FnOnce(AbortRegistration) -> F,
        buffers: usize,
    ) -> io::Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.check_open()?;
        let buffers = buffers
            .checked_add(ABORT_PAIR_MEMORY)
            .ok_or_else(capacity_error)?;
        self.spawn_accounted(
            |completed| {
                let (abort, registration) = AbortHandle::new_pair();
                let future = create(registration);
                let completed = Completed(completed);
                (future.map(move |()| drop(completed)), Some(abort))
            },
            buffers,
            None,
        )
        .map(|_| ())
    }

    fn check_open(&self) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "task admission closed",
            ));
        }
        Ok(())
    }

    fn spawn_accounted<F>(
        &mut self,
        create: impl FnOnce(Arc<AtomicUsize>) -> (F, Option<AbortHandle>),
        buffers: usize,
        ordinary_future_bytes: Option<usize>,
    ) -> io::Result<Option<tokio::task::AbortHandle>>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let charges = self.charges.as_mut().ok_or_else(capacity_error)?;
        let index = charges
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or_else(capacity_error)?;
        let bytes = ordinary_future_bytes
            .unwrap_or(size_of::<F>())
            .checked_add(TASK_BOOKKEEPING)
            .and_then(|n| n.checked_add(buffers))
            .ok_or_else(capacity_error)?;
        let memory = charges.budget.reserve(bytes).ok_or_else(capacity_error)?;
        let runtime = charges
            .runtime
            .get_or_insert_with(tokio::runtime::Handle::current);
        let (future, scoped_abort) = create(Arc::clone(&charges.completed));
        let task = self.tasks.spawn_on(future, runtime);
        let (state, exposed) = match scoped_abort {
            Some(handle) => (TaskState::Scoped(task.id(), handle), None),
            None => (TaskState::Ordinary(task.clone()), Some(task)),
        };
        charges.entries[index] = Some(TaskCharge {
            state,
            _memory: memory,
        });
        Ok(exposed)
    }

    fn joined(
        &mut self,
        result: Result<(tokio::task::Id, ()), tokio::task::JoinError>,
    ) -> Result<(), tokio::task::JoinError> {
        let id = joined_id(&result);
        if let Some(charges) = &mut self.charges
            && let Some(slot) = charges
                .entries
                .iter_mut()
                .find(|slot| slot.as_ref().is_some_and(|charge| charge.id() == id))
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

    #[tokio::test]
    async fn scoped_admission_refusal_keeps_owners_for_shared_admission() {
        let budget = MemoryBudget::new(4096);
        let mut tasks = TaskRegistry::accounted(1, &budget).unwrap();
        let ordinary_bytes =
            TASK_BOOKKEEPING + size_of::<Completed>() + size_of::<std::future::Ready<()>>();
        let _competitor = budget
            .reserve(budget.limit() - budget.used() - ordinary_bytes)
            .unwrap();
        let baseline = budget.used();
        let mut owners = Some(Box::new(42));
        let create = |owners: &mut Option<Box<u8>>| {
            assert_eq!(*owners.take().unwrap(), 42);
            std::future::ready(())
        };

        let error = tasks
            .spawn_scoped_with(|_| create(&mut owners), 0)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(owners.is_some());
        assert_eq!(budget.used(), baseline);

        drop(tasks.spawn_with(|| create(&mut owners), 0).unwrap());
        assert!(owners.is_none());
        assert_eq!(budget.used(), budget.limit());
        tasks.join_next().await.unwrap().unwrap();
        assert_eq!(budget.used(), baseline);
    }

    #[test]
    fn dropped_registry_cancels_scoped_work_and_funds_joined_cleanup() {
        use futures::future::Abortable;
        use std::future::pending;
        use std::time::Duration;
        use tokio::runtime::{Builder, Handle};

        let shared = Builder::new_current_thread().enable_time().build().unwrap();
        let owner = Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        let owner_handle = owner.handle().clone();
        let (started, ready) = oneshot::channel();
        let (cancelled, cancelling) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let (cleaned, cleanup) = oneshot::channel();
        let (ordinary, ordinary_dropped) = oneshot::channel::<()>();
        let budget = MemoryBudget::new(256 << 10);
        let mut tasks = TaskRegistry::accounted(2, &budget).unwrap();
        let timeout = Duration::from_secs(3);
        let buffers = 65536;

        shared.block_on(async {
            tasks
                .spawn(
                    async move {
                        pending::<()>().await;
                        drop(ordinary);
                    },
                    0,
                )
                .map(drop)
                .unwrap();
            tasks
                .spawn_scoped_with(
                    |registration| async move {
                        owner_handle
                            .spawn(async move {
                                let held = vec![0x5a_u8; buffers];
                                let work = async move {
                                    started.send(Handle::current().id()).unwrap();
                                    pending::<()>().await;
                                };
                                assert!(Abortable::new(work, registration).await.is_err());
                                cancelled.send(()).unwrap();
                                released.await.unwrap();
                                std::hint::black_box(held);
                            })
                            .await
                            .unwrap();
                        cleaned.send(Handle::current().id()).unwrap();
                    },
                    buffers,
                )
                .unwrap();
            let owner_id = tokio::time::timeout(timeout, ready).await.unwrap().unwrap();
            assert_eq!(owner_id, owner.handle().id());
        });
        let funded = budget.used();
        let competitor = budget.reserve(budget.limit() - funded).unwrap();

        drop(tasks);

        shared.block_on(async {
            tokio::time::timeout(timeout, async {
                cancelling.await.unwrap();
                assert!(ordinary_dropped.await.is_err());
                assert_eq!(budget.used(), budget.limit());
                assert!(budget.reserve(1).is_none());
                release.send(()).unwrap();
                assert_eq!(cleanup.await.unwrap(), shared.handle().id());
                while budget.used() != budget.limit() - funded {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        });
        drop(competitor);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn dropped_registry_keeps_credit_until_blocked_destructor_is_joined_on_its_runtime() {
        assert_registry_drop_retains_credit(false);
    }

    #[test]
    fn reaper_keeps_other_tasks_funded_while_deferring_panicking_error_payloads() {
        assert_registry_drop_retains_credit(true);
    }

    fn assert_registry_drop_retains_credit(panicking_payload: bool) {
        struct BlockedDrop {
            entered: Option<oneshot::Sender<()>>,
            release: std::sync::mpsc::Receiver<()>,
            buffer: Vec<u8>,
        }
        impl Drop for BlockedDrop {
            fn drop(&mut self) {
                self.entered.take().unwrap().send(()).unwrap();
                self.release.recv().unwrap();
                assert_eq!(self.buffer.len(), 65536);
                panic!("task destructor failed");
            }
        }
        struct ReleaseOnDrop(std::sync::mpsc::Sender<()>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        struct PanicPayload(Arc<AtomicUsize>);
        impl Drop for PanicPayload {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
                panic!("panic payload destructor failed");
            }
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let budget = MemoryBudget::new(256 << 10);
        let completed = Arc::new(AtomicUsize::new(0));
        let mut tasks =
            TaskRegistry::with_completions(2, &budget, Some(Arc::clone(&completed))).unwrap();
        let (entered, dropping) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let release = ReleaseOnDrop(release);
        let (started, ready) = oneshot::channel();
        let task = runtime.block_on(async {
            let task = tasks
                .spawn_with(
                    || async move {
                        let held = BlockedDrop {
                            entered: Some(entered),
                            release: released,
                            buffer: vec![0x5a; 65536],
                        };
                        started.send(()).unwrap();
                        std::future::pending::<()>().await;
                        std::hint::black_box(held);
                    },
                    65536,
                )
                .unwrap();
            ready.await.unwrap();
            task
        });
        let payload_dropped = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&payload_dropped);
        runtime.block_on(async {
            let panicked = tasks
                .spawn(
                    async move {
                        if panicking_payload {
                            std::panic::panic_any(PanicPayload(observed));
                        }
                        panic!("child failed");
                    },
                    0,
                )
                .unwrap();
            while !panicked.is_finished() {
                tokio::task::yield_now().await;
            }
        });
        let retained = budget.used();
        let contested = budget.limit() - retained;
        let competitor = budget.reserve(contested).unwrap();
        task.abort();
        runtime.block_on(dropping).unwrap();
        let completed_before_drop = completed.load(Ordering::Acquire);

        let other_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            other_runtime.block_on(async move {
                let _tasks = tasks;
                if !panicking_payload {
                    panic!("supervisor failed");
                }
            });
        }));
        assert_eq!(unwound.is_err(), !panicking_payload);
        drop(other_runtime);
        assert_eq!(budget.used(), budget.limit());
        assert!(budget.reserve(1).is_none());
        runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                while completed.load(Ordering::Acquire) >= completed_before_drop {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        });
        assert_eq!(payload_dropped.load(Ordering::SeqCst), 0);
        assert_eq!(budget.used(), budget.limit());

        drop(release);
        runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                while budget.used() != contested {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        });
        assert_eq!(completed.load(Ordering::Acquire), 0);
        assert_eq!(
            payload_dropped.load(Ordering::SeqCst),
            usize::from(panicking_payload)
        );
        let reclaimed = budget.reserve(retained).unwrap();
        drop(reclaimed);
        drop(competitor);
        assert_eq!(budget.used(), 0);
    }
}
