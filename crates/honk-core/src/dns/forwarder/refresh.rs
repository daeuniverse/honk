use std::future::Future;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::task::JoinSet;

struct Registry {
    closed: bool,
    failed: bool,
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
                failed: false,
                tasks: JoinSet::new(),
            }),
        })
    }

    pub(super) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> bool {
        let mut registry = self.registry.lock();
        while let Some(result) = registry.tasks.try_join_next() {
            registry.failed |= result.is_err_and(|error| !error.is_cancelled());
        }
        if registry.closed {
            return false;
        }

        #[cfg(feature = "native-api")]
        let task = honk_outbound::runtime::TaskScope::capture().scope_owned(task);
        registry.tasks.spawn(task);
        true
    }

    pub(super) fn request_shutdown(&self) {
        let mut registry = self.registry.lock();
        registry.closed = true;
        registry.tasks.abort_all();
    }

    pub(super) async fn shutdown(&self) -> bool {
        let mut tasks = {
            let mut registry = self.registry.lock();
            registry.closed = true;
            std::mem::take(&mut registry.tasks)
        };
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            self.registry.lock().failed |= result.is_err_and(|error| !error.is_cancelled());
        }
        !self.registry.lock().failed
    }

    #[cfg(test)]
    pub(super) fn active(&self) -> usize {
        let mut registry = self.registry.lock();
        while let Some(result) = registry.tasks.try_join_next() {
            registry.failed |= result.is_err_and(|error| !error.is_cancelled());
        }
        registry.tasks.len()
    }
}
