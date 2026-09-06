//! Rollback-safe exact-key DNS cache persistence.
//!
//! Version-two entries live under `dns:v2:` and never modify or consume the
//! legacy `dns:` representation. A bounded actor owns SQLite writes and
//! linearizes explicit flushes with an epoch barrier.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use super::cache::{CacheKey, DnsCacheService};
use super::policy::PolicyId;
use crate::cachedb::CacheDb;

mod codec;
mod counters {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct PersistCounters {
        pub queued: usize,
        pub pending: usize,
        pub dropped_full: u64,
        pub dropped_pending_full: u64,
        pub dropped_closed: u64,
        pub old_epoch_discarded: u64,
        pub written: u64,
        pub restored: u64,
        pub stale: u64,
        pub corrupt: u64,
        pub version_mismatch: u64,
        pub policy_mismatch: u64,
        pub db_errors: u64,
        pub write_attempts: u64,
    }

    #[derive(Default)]
    pub(super) struct CounterSet {
        pub(super) queued: AtomicUsize,
        pub(super) pending: AtomicUsize,
        pub(super) dropped_full: AtomicU64,
        pub(super) dropped_pending_full: AtomicU64,
        pub(super) dropped_closed: AtomicU64,
        pub(super) old_epoch_discarded: AtomicU64,
        pub(super) written: AtomicU64,
        pub(super) restored: AtomicU64,
        pub(super) stale: AtomicU64,
        pub(super) corrupt: AtomicU64,
        pub(super) version_mismatch: AtomicU64,
        pub(super) policy_mismatch: AtomicU64,
        pub(super) db_errors: AtomicU64,
        pub(super) write_attempts: AtomicU64,
    }

    impl CounterSet {
        pub(super) fn snapshot(&self) -> PersistCounters {
            PersistCounters {
                queued: self.queued.load(Ordering::Relaxed),
                pending: self.pending.load(Ordering::Relaxed),
                dropped_full: self.dropped_full.load(Ordering::Relaxed),
                dropped_pending_full: self.dropped_pending_full.load(Ordering::Relaxed),
                dropped_closed: self.dropped_closed.load(Ordering::Relaxed),
                old_epoch_discarded: self.old_epoch_discarded.load(Ordering::Relaxed),
                written: self.written.load(Ordering::Relaxed),
                restored: self.restored.load(Ordering::Relaxed),
                stale: self.stale.load(Ordering::Relaxed),
                corrupt: self.corrupt.load(Ordering::Relaxed),
                version_mismatch: self.version_mismatch.load(Ordering::Relaxed),
                policy_mismatch: self.policy_mismatch.load(Ordering::Relaxed),
                db_errors: self.db_errors.load(Ordering::Relaxed),
                write_attempts: self.write_attempts.load(Ordering::Relaxed),
            }
        }
    }
}
mod worker;

use counters::CounterSet;
pub use counters::PersistCounters;

const COMMAND_CAPACITY: usize = 4096;

struct Put {
    epoch: u64,
    key: CacheKey,
    response: bytes::Bytes,
    expire_at_unix: u64,
}

struct Remove {
    epoch: u64,
    key: CacheKey,
}

enum Command {
    Put(Put),
    Remove(Remove),
    Flush {
        epoch: u64,
        ack: oneshot::Sender<Result<(), PersistControlError>>,
    },
    Restore {
        cache: Arc<DnsCacheService>,
        policy: Option<PolicyId>,
        ack: oneshot::Sender<usize>,
    },
    Shutdown {
        ack: oneshot::Sender<Result<(), PersistControlError>>,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PersistControlError {
    #[error("DNS persistence writer is closed")]
    Closed,
    #[error("DNS persistence writer stopped before acknowledging the command")]
    AckDropped,
    #[error("DNS persistence worker thread failed")]
    WorkerFailed,
    #[error("DNS persistence database operation failed: {0}")]
    Database(String),
}

#[derive(Clone)]
pub struct DnsCachePersister {
    tx: mpsc::Sender<Command>,
    epoch: Arc<AtomicU64>,
    counters: Arc<CounterSet>,
    worker: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
    #[cfg(test)]
    flush_gate: Arc<Mutex<Option<FlushGate>>>,
}

#[cfg(test)]
struct FlushGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
}

impl std::fmt::Debug for DnsCachePersister {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DnsCachePersister")
            .field("epoch", &self.epoch.load(Ordering::SeqCst))
            .field("counters", &self.counters())
            .finish_non_exhaustive()
    }
}

impl DnsCachePersister {
    pub fn spawn(db: Arc<CacheDb>) -> Self {
        let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
        let counters = Arc::new(CounterSet::default());
        let worker_counters = Arc::clone(&counters);
        let handle = std::thread::Builder::new()
            .name("honk-dns-persist".to_string())
            .spawn(move || worker::run(db, rx, worker_counters))
            .ok();
        Self {
            tx,
            epoch: Arc::new(AtomicU64::new(0)),
            counters,
            worker: Arc::new(Mutex::new(handle)),
            #[cfg(test)]
            flush_gate: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn save(&self, key: CacheKey, response: bytes::Bytes, expire_at_unix: u64) {
        let command = Command::Put(Put {
            epoch: self.epoch.load(Ordering::SeqCst),
            key,
            response,
            expire_at_unix,
        });
        self.counters.queued.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(command) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.counters.queued.fetch_sub(1, Ordering::Relaxed);
                self.counters.dropped_full.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::PersistenceDrop);
                tracing::debug!(
                    reason = "command_queue_full",
                    "DNS persistence write dropped"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.counters.queued.fetch_sub(1, Ordering::Relaxed);
                self.counters.dropped_closed.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::PersistenceDrop);
                tracing::debug!(reason = "worker_closed", "DNS persistence write dropped");
            }
        }
    }

    pub(crate) fn remove(&self, key: CacheKey) {
        let command = Command::Remove(Remove {
            epoch: self.epoch.load(Ordering::SeqCst),
            key,
        });
        self.counters.queued.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(command) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.counters.queued.fetch_sub(1, Ordering::Relaxed);
                self.counters.dropped_full.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::PersistenceDrop);
                tracing::debug!(
                    reason = "command_queue_full",
                    "DNS persistence removal dropped"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.counters.queued.fetch_sub(1, Ordering::Relaxed);
                self.counters.dropped_closed.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::PersistenceDrop);
                tracing::debug!(reason = "worker_closed", "DNS persistence removal dropped");
            }
        }
    }

    pub async fn restore(
        &self,
        cache: Arc<DnsCacheService>,
        policy: Option<PolicyId>,
    ) -> Result<usize, PersistControlError> {
        let (ack, receive) = oneshot::channel();
        self.send_control(Command::Restore { cache, policy, ack })
            .await?;
        receive.await.map_err(|_| PersistControlError::AckDropped)
    }

    pub async fn restore_cache(
        &self,
        cache: &Arc<tokio::sync::Mutex<super::cache::DnsCache>>,
        policy: Option<PolicyId>,
    ) -> Result<usize, PersistControlError> {
        let service = cache.lock().await.service();
        self.restore(service, policy).await
    }

    pub async fn flush(&self) -> Result<(), PersistControlError> {
        let epoch = self.epoch.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let (ack, receive) = oneshot::channel();
        if let Err(error) = self.send_control(Command::Flush { epoch, ack }).await {
            record_flush_failure(&error);
            return Err(error);
        }
        #[cfg(test)]
        let flush_gate = self
            .flush_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        #[cfg(test)]
        if let Some(gate) = flush_gate {
            gate.entered.notify_one();
            gate.release
                .acquire()
                .await
                .unwrap_or_else(|_| unreachable!("test flush gate remains open"))
                .forget();
        }
        let result = receive
            .await
            .map_err(|_| PersistControlError::AckDropped)
            .and_then(std::convert::identity);
        if let Err(error) = &result {
            record_flush_failure(error);
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn gate_next_flush(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Semaphore>) {
        let gate = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Semaphore::new(0)),
        );
        let stored = FlushGate {
            entered: Arc::clone(&gate.0),
            release: Arc::clone(&gate.1),
        };
        *self
            .flush_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(stored);
        gate
    }

    pub async fn shutdown(&self) -> Result<(), PersistControlError> {
        let (ack, receive) = oneshot::channel();
        self.send_control(Command::Shutdown { ack }).await?;
        let result = receive.await.map_err(|_| PersistControlError::AckDropped)?;
        let handle = self
            .worker
            .lock()
            .map_err(|_| PersistControlError::WorkerFailed)?
            .take();
        if let Some(handle) = handle {
            tokio::task::spawn_blocking(move || handle.join())
                .await
                .map_err(|_| PersistControlError::WorkerFailed)?
                .map_err(|_| PersistControlError::WorkerFailed)?;
        }
        result
    }

    pub fn counters(&self) -> PersistCounters {
        self.counters.snapshot()
    }

    async fn send_control(&self, command: Command) -> Result<(), PersistControlError> {
        self.counters.queued.fetch_add(1, Ordering::Relaxed);
        if self.tx.send(command).await.is_err() {
            self.counters.queued.fetch_sub(1, Ordering::Relaxed);
            return Err(PersistControlError::Closed);
        }
        Ok(())
    }
}

fn record_flush_failure(error: &PersistControlError) {
    crate::stats::record_dns_event(crate::stats::DnsStatEvent::PersistenceFlushFailure);
    let error_kind = match error {
        PersistControlError::Closed => "worker_closed",
        PersistControlError::AckDropped => "ack_dropped",
        PersistControlError::WorkerFailed => "worker_failed",
        PersistControlError::Database(_) => "database",
    };
    tracing::warn!(error_kind, "DNS persistence flush failed");
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
