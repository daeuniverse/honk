use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::{Instant, sleep_until};

use super::DRAIN_DEADLINE;

const CHECK: Duration = Duration::from_millis(100);

#[derive(Default)]
pub(super) struct CopyProgress {
    pub(super) read: AtomicU64,
    pub(super) written: AtomicU64,
}

impl CopyProgress {
    pub(super) fn snapshot(&self) -> (u64, u64) {
        (
            self.read.load(Ordering::Relaxed),
            self.written.load(Ordering::Relaxed),
        )
    }
}

pub(super) async fn drain_copy_idle(upload: &CopyProgress, download: &CopyProgress) {
    let progress = || (upload.snapshot(), download.snapshot());
    let mut last = progress();
    let mut now = Instant::now();
    let mut deadline = now + DRAIN_DEADLINE;
    loop {
        sleep_until(deadline.min(now + CHECK)).await;
        now = Instant::now();
        let current = progress();
        if current != last {
            last = current;
            deadline = now + DRAIN_DEADLINE;
        } else if now >= deadline {
            tracing::debug!("relay drain stalled; closing both directions");
            return;
        }
    }
}

pub(super) async fn drain_idle<T: PartialEq>(mut last: T, progress: impl Fn() -> T) {
    let mut stalled = Duration::ZERO;
    loop {
        tokio::time::sleep(CHECK).await;
        let now = progress();
        if now != last {
            last = now;
            stalled = Duration::ZERO;
        } else {
            stalled += CHECK;
            if stalled >= DRAIN_DEADLINE {
                tracing::debug!("relay drain stalled; closing both directions");
                return;
            }
        }
    }
}
