use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

pub(crate) struct OwnedTask {
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl OwnedTask {
    pub(crate) fn spawn<F>(future: F, active: Arc<AtomicUsize>) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        active.fetch_add(1, Ordering::SeqCst);
        let guard = ActiveTaskGuard(active);
        let handle = tokio::spawn(async move {
            let _guard = guard;
            future.await;
        });
        Self {
            handle: Mutex::new(Some(handle)),
        }
    }

    pub(crate) async fn shutdown(&self, timeout: Duration) {
        let mut slot = self.handle.lock().await;
        let Some(handle) = slot.as_mut() else {
            return;
        };
        if tokio::time::timeout(timeout, &mut *handle).await.is_err() {
            handle.abort();
            let _ = handle.await;
        }
        slot.take();
    }
}

impl Drop for OwnedTask {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.get_mut().take() {
            handle.abort();
        }
    }
}

struct ActiveTaskGuard(Arc<AtomicUsize>);

impl Drop for ActiveTaskGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_close_then_last_owner_drop_aborts_driver() {
        let active = Arc::new(AtomicUsize::new(0));
        let (started, running) = tokio::sync::oneshot::channel();
        let slot = super::super::lifecycle::LifecycleSlot::new();
        slot.acquire(|| async {
            Ok(OwnedTask::spawn(
                async move {
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                },
                Arc::clone(&active),
            ))
        })
        .await
        .map(|(value, _)| value)
        .unwrap();
        running.await.unwrap();
        let mut close = Box::pin(slot.close(|task| async move {
            task.shutdown(Duration::from_secs(60)).await;
        }));
        assert!(futures::poll!(close.as_mut()).is_pending());
        drop(close);
        drop(slot);
        tokio::time::timeout(Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the last owner must abort its driver");
    }

    #[tokio::test]
    async fn dropping_unpolled_task_releases_active_count() {
        let active = Arc::new(AtomicUsize::new(0));
        let task = OwnedTask::spawn(std::future::pending(), Arc::clone(&active));
        drop(task);
        tokio::time::timeout(Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("an unpolled task must release its active count");
    }

    #[tokio::test]
    async fn shutdown_awaits_task_termination() {
        // Given
        let active = Arc::new(AtomicUsize::new(0));
        let task = OwnedTask::spawn(std::future::pending(), Arc::clone(&active));
        assert_eq!(active.load(Ordering::SeqCst), 1);

        // When
        task.shutdown(Duration::ZERO).await;

        // Then
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
