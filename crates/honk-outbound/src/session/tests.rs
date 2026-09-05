use super::*;
use std::sync::atomic::AtomicBool;
mod admission;
mod lifecycle;
mod scheduling;
mod speculative;

#[derive(Debug)]
struct TestSession {
    streams: AtomicUsize,
    closed: AtomicBool,
    state: AtomicUsize,
}

impl TestSession {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            streams: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            state: AtomicUsize::new(0),
        })
    }
}

impl ManagedSession for TestSession {
    fn active_streams(&self) -> usize {
        self.streams.load(Ordering::Relaxed)
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
    fn state(&self) -> SessionState {
        match self.state.load(Ordering::Relaxed) {
            _ if self.is_closed() => SessionState::Closed,
            0 => SessionState::Active,
            _ => SessionState::Draining,
        }
    }
    fn begin_drain(&self) {
        self.state.store(1, Ordering::Relaxed);
    }
}

fn pool(config: SessionPoolConfig) -> SessionPool<TestSession> {
    SessionPool::new(config)
}

#[derive(Debug)]
struct ReservedTestSession {
    closed: AtomicBool,
    stream_permits: Arc<tokio::sync::Semaphore>,
    capacity: usize,
}

impl ReservedTestSession {
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            closed: AtomicBool::new(false),
            stream_permits: Arc::new(tokio::sync::Semaphore::new(capacity)),
            capacity,
        })
    }
}

impl ManagedSession for ReservedTestSession {
    fn active_streams(&self) -> usize {
        self.capacity - self.stream_permits.available_permits()
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
    fn try_reserve(self: &Arc<Self>) -> Option<SessionPermit<Self>> {
        if self.is_closed() {
            return None;
        }
        let permit = Arc::clone(&self.stream_permits).try_acquire_owned().ok()?;
        if self.is_closed() {
            drop(permit);
            return None;
        }
        Some(SessionPermit::new(Arc::clone(self), permit))
    }
}
