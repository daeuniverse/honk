use super::input::{PacketFlow, TcpFlow};
use super::{RelayCompletion, SniffPrefix};
use crate::control::netstack::{DirectRelayFence, DirectRelayLease, FlowIo};
use crate::control::task_registry::TASK_BOOKKEEPING;
use crate::relay::RelayProgress;
use honk_netstack::MemoryReservation;
use honk_outbound::ProxyStream;
use parking_lot::Mutex;
use std::panic::resume_unwind;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::task::{AbortHandle, JoinError, JoinHandle};

type RelayOutput = (TcpFlow, RelayCompletion);

struct RelayTask<'a> {
    join: JoinHandle<RelayOutput>,
    _memory: Option<MemoryReservation>,
    _join_lease: DirectRelayLease<'a>,
}

#[derive(Default)]
pub(super) struct RelayPublication {
    task: Mutex<Option<AbortHandle>>,
    abort_requested: AtomicBool,
}

impl RelayPublication {
    pub(super) fn cancel_active(&self) -> bool {
        let task = self.task.lock();
        let Some(task) = task.as_ref() else {
            return false;
        };
        // Only an abort requested while the task is live can explain a cancelled join.
        if !task.is_finished() && !self.abort_requested.swap(true, Ordering::Relaxed) {
            task.abort();
        }
        true
    }

    pub(super) fn active(&self) -> bool {
        // Finished output remains active until the parent has taken it from the join.
        self.task.lock().is_some()
    }

    fn clear(&self) -> bool {
        let mut task = self.task.lock();
        drop(task.take());
        self.abort_requested.swap(false, Ordering::Relaxed)
    }
}

/// Lives outside the parent operation so its cancellation or unwind can join the relay.
pub(super) struct DirectRelay<'a> {
    owner: Handle,
    publication: &'a RelayPublication,
    fence: &'a DirectRelayFence,
    task: Option<RelayTask<'a>>,
}

impl<'a> DirectRelay<'a> {
    pub(super) fn new(
        owner: Handle,
        publication: &'a RelayPublication,
        fence: &'a DirectRelayFence,
    ) -> Self {
        Self {
            owner,
            publication,
            fence,
            task: None,
        }
    }

    pub(super) fn reserve<F: Future<Output = RelayOutput>>(
        &self,
        flow: &FlowIo,
        proxy: &ProxyStream,
        prefix: &SniffPrefix,
        _create: &impl FnOnce(PacketFlow, ProxyStream, RelayProgress, SniffPrefix) -> F,
    ) -> Option<(Option<MemoryReservation>, DirectRelayLease<'a>)> {
        if !proxy.stream.as_ref().as_any().is::<TcpStream>() {
            return None;
        }
        // Tokio can box the future separately from the task that stores its output.
        // The parent stays funded for the copy buffers and released sniff scratch through join.
        let task_bytes =
            TASK_BOOKKEEPING + size_of::<F>() + size_of::<Result<RelayOutput, JoinError>>();
        let sniff_slack = crate::sniffing::SNIFF_MEMORY.saturating_sub(prefix.bytes.capacity());
        let extra = task_bytes.saturating_sub(sniff_slack);
        let memory = if extra == 0 {
            None
        } else {
            Some(flow.try_reserve_memory(extra)?)
        };
        // A join lease commits the transfer even if shutdown starts before the job polls.
        let join_lease = self.fence.try_join_lease()?;
        Some((memory, join_lease))
    }

    pub(super) fn run(
        &mut self,
        memory: Option<MemoryReservation>,
        join_lease: DirectRelayLease<'a>,
        future: impl Future<Output = RelayOutput> + Send + 'static,
    ) -> impl Future<Output = Option<RelayOutput>> + '_ {
        assert!(self.task.is_none(), "TCP relay already started");
        let join = self.owner.spawn(future);
        let abort = join.abort_handle();
        self.task = Some(RelayTask {
            join,
            _memory: memory,
            _join_lease: join_lease,
        });
        *self.publication.task.lock() = Some(abort);
        async move {
            let fence = self.fence;
            let (result, abort_requested) = tokio::select! {
                biased;
                result = self.join() => result,
                () = fence.wait_closed() => {
                    self.publication.cancel_active();
                    self.join().await
                }
            };
            match result {
                Ok(output) => Some(output),
                Err(error) if error.is_panic() => resume_unwind(error.into_panic()),
                Err(error) if abort_requested && error.is_cancelled() => None,
                Err(error) => panic!("owner TCP relay cancelled unexpectedly: {error}"),
            }
        }
    }

    pub(super) async fn cancel_and_join(&mut self) {
        if let Some(task) = &self.task {
            task.join.abort();
            if let (Err(error), _) = self.join().await
                && error.is_panic()
            {
                resume_unwind(error.into_panic());
            }
        }
    }

    async fn join(&mut self) -> (Result<RelayOutput, JoinError>, bool) {
        // A cancelled wait must leave the handle, credit and fence lease for cleanup.
        let result = (&mut self.task.as_mut().expect("started TCP relay").join).await;
        let abort_requested = self.publication.clear();
        self.task = None;
        (result, abort_requested)
    }
}

impl Drop for DirectRelay<'_> {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            // Runtime destruction can skip the parent task's joined cleanup.
            task.join.abort();
            self.publication.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use honk_netstack::MemoryBudget;
    use std::panic::AssertUnwindSafe;
    use std::pin::pin;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::runtime::{Builder, Runtime};
    use tokio::sync::oneshot;

    const WAIT: Duration = Duration::from_secs(5);

    fn runtime() -> Runtime {
        Builder::new_current_thread().enable_time().build().unwrap()
    }

    fn relay_fence() -> Arc<DirectRelayFence> {
        DirectRelayFence::new(&MemoryBudget::new(4096)).unwrap()
    }

    #[test]
    fn cancelled_wait_keeps_credit_until_owner_is_joined() {
        let shared = runtime();
        let owner = runtime();
        let publication = RelayPublication::default();
        let fence = relay_fence();
        let mut relay = DirectRelay::new(owner.handle().clone(), &publication, &fence);
        let budget = MemoryBudget::new(TASK_BOOKKEEPING);
        let memory = budget.reserve(TASK_BOOKKEEPING).unwrap();
        let (dropped, released) = oneshot::channel::<()>();
        shared.block_on(async {
            let lease = fence.try_join_lease().unwrap();
            let mut run = pin!(relay.run(Some(memory), lease, async move {
                drop(dropped);
                panic!("aborted relay was polled")
            }));
            assert!(futures::poll!(&mut run).is_pending());
        });
        assert_eq!(budget.used(), TASK_BOOKKEEPING);
        shared.block_on(async {
            let mut cleanup = pin!(relay.cancel_and_join());
            assert!(futures::poll!(&mut cleanup).is_pending());
        });
        owner.block_on(async {
            assert!(tokio::time::timeout(WAIT, released).await.unwrap().is_err());
        });
        assert_eq!(budget.used(), TASK_BOOKKEEPING);
        shared.block_on(relay.cancel_and_join());
        assert!(!publication.active());
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn fatal_fence_aborts_pending_owner_and_waits_for_join() {
        let shared = runtime();
        let owner = runtime();
        let publication = RelayPublication::default();
        let fence = relay_fence();
        let mut relay = DirectRelay::new(owner.handle().clone(), &publication, &fence);
        let budget = MemoryBudget::new(TASK_BOOKKEEPING);
        let memory = budget.reserve(TASK_BOOKKEEPING).unwrap();
        let (started, ready) = oneshot::channel();
        let (dropped, released) = oneshot::channel::<()>();
        let lease = fence.try_join_lease().unwrap();
        let mut run = pin!(relay.run(Some(memory), lease, async move {
            let _dropped = dropped;
            started.send(()).unwrap();
            std::future::pending::<RelayOutput>().await
        }));
        shared.block_on(async {
            assert!(futures::poll!(&mut run).is_pending());
        });
        owner.block_on(async {
            tokio::time::timeout(WAIT, ready).await.unwrap().unwrap();
        });
        let mut closing = pin!(fence.close_and_join());
        shared.block_on(async {
            assert!(futures::poll!(&mut closing).is_pending());
            assert!(fence.try_join_lease().is_none());
            assert!(futures::poll!(&mut run).is_pending());
        });
        owner.block_on(async {
            assert!(tokio::time::timeout(WAIT, released).await.unwrap().is_err());
        });
        assert!(publication.task.lock().as_ref().unwrap().is_finished());
        assert!(publication.active());
        assert_eq!(budget.used(), TASK_BOOKKEEPING);
        shared.block_on(async {
            assert!(futures::poll!(&mut closing).is_pending());
            assert!(run.await.is_none());
            tokio::time::timeout(WAIT, closing).await.unwrap();
        });
        assert!(!publication.active());
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn owner_shutdown_while_relay_is_pending_fails_closed() {
        let shared = runtime();
        let owner = runtime();
        let publication = RelayPublication::default();
        let fence = relay_fence();
        let mut relay = DirectRelay::new(owner.handle().clone(), &publication, &fence);
        let budget = MemoryBudget::new(TASK_BOOKKEEPING);
        let memory = budget.reserve(TASK_BOOKKEEPING).unwrap();
        let (started, ready) = oneshot::channel();
        let lease = fence.try_join_lease().unwrap();
        let mut run = pin!(
            AssertUnwindSafe(relay.run(Some(memory), lease, async move {
                started
                    .send((Handle::current().id(), std::thread::current().id()))
                    .unwrap();
                std::future::pending::<RelayOutput>().await
            }))
            .catch_unwind()
        );
        shared.block_on(async {
            assert!(futures::poll!(&mut run).is_pending());
        });
        let owner_id = owner.handle().id();
        std::thread::spawn(move || {
            let witness = owner.block_on(async { tokio::time::timeout(WAIT, ready).await });
            assert_eq!(
                witness.unwrap().unwrap(),
                (owner_id, std::thread::current().id()),
            );
        })
        .join()
        .unwrap();
        assert_eq!(budget.used(), TASK_BOOKKEEPING);
        assert!(publication.cancel_active());
        let Err(panic) = shared.block_on(run) else {
            panic!("unexpected owner cancellation returned a relay result");
        };
        assert!(
            panic
                .downcast_ref::<String>()
                .unwrap()
                .contains("owner TCP relay cancelled")
        );
        assert!(!publication.active());
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn cleanup_rethrows_panic_from_finished_owner() {
        struct OwnerPanic;

        let shared = runtime();
        let owner = runtime();
        let publication = RelayPublication::default();
        let fence = relay_fence();
        let mut relay = DirectRelay::new(owner.handle().clone(), &publication, &fence);
        let budget = MemoryBudget::new(TASK_BOOKKEEPING);
        let memory = budget.reserve(TASK_BOOKKEEPING).unwrap();
        let (terminated, finished) = oneshot::channel::<()>();
        shared.block_on(async {
            let lease = fence.try_join_lease().unwrap();
            let mut run = pin!(relay.run(Some(memory), lease, async move {
                let _terminated = terminated;
                std::panic::panic_any(OwnerPanic)
            }));
            assert!(futures::poll!(&mut run).is_pending());
        });
        owner.block_on(async {
            assert!(tokio::time::timeout(WAIT, finished).await.unwrap().is_err());
        });
        assert_eq!(budget.used(), TASK_BOOKKEEPING);
        let panic = shared
            .block_on(AssertUnwindSafe(relay.cancel_and_join()).catch_unwind())
            .unwrap_err();
        assert!(panic.is::<OwnerPanic>());
        assert!(!publication.active());
        assert_eq!(budget.used(), 0);
    }
}
