use std::future::Future;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::task::JoinSet;

struct Registry {
    closed: bool,
    tasks: JoinSet<()>,
}

pub(super) struct RefreshTasks {
    registry: Mutex<Registry>,
}

impl RefreshTasks {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(Registry {
                closed: false,
                tasks: JoinSet::new(),
            }),
        })
    }

    pub(super) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> bool {
        let mut registry = self.registry.lock();
        while registry.tasks.try_join_next().is_some() {}
        if registry.closed {
            return false;
        }

        registry.tasks.spawn(task);
        true
    }

    pub(super) async fn shutdown(&self) {
        let mut tasks = {
            let mut registry = self.registry.lock();
            registry.closed = true;
            std::mem::take(&mut registry.tasks)
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    #[cfg(test)]
    pub(super) fn active(&self) -> usize {
        let mut registry = self.registry.lock();
        while registry.tasks.try_join_next().is_some() {}
        registry.tasks.len()
    }
}
