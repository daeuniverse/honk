//! Exact-key DNS cache persistence in the state db's `dns_answer` table.
//!
//! A bounded actor owns SQLite writes and linearizes explicit flushes with an
//! epoch barrier.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use super::cache::{CacheKey, DnsCacheService};
use super::policy::PolicyId;
use crate::state::cache::CacheDb;

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
        pub oversize: u64,
        pub budget_skipped: u64,
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
        pub(super) oversize: AtomicU64,
        pub(super) budget_skipped: AtomicU64,
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
                oversize: self.oversize.load(Ordering::Relaxed),
                budget_skipped: self.budget_skipped.load(Ordering::Relaxed),
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

const COMMAND_CAPACITY: usize = 1024;

struct Put {
    epoch: u64,
    key: CacheKey,
    response: bytes::Bytes,
    expire_at_unix: u64,
}

enum Command {
    Put(Put),
    Flush {
        epoch: u64,
        ack: oneshot::Sender<Result<(), PersistControlError>>,
    },
    #[cfg(any(feature = "native-api", test))]
    Invalidate {
        epoch: u64,
        selection: PersistInvalidation,
        ack: oneshot::Sender<Result<(), PersistControlError>>,
    },
    Restore {
        cache: Arc<DnsCacheService>,
        publication_epoch: super::cache::PublicationEpoch,
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

pub(crate) enum PersistInvalidation {
    All,
    #[cfg(any(feature = "native-api", test))]
    Keys(Vec<CacheKey>),
    #[cfg(any(feature = "native-api", test))]
    Name {
        name: String,
        types: Vec<u16>,
    },
}

pub(crate) struct ReservedInvalidation<'a> {
    permit: mpsc::Permit<'a, Command>,
    persister: &'a DnsCachePersister,
}

pub(crate) struct PendingInvalidation {
    receive: oneshot::Receiver<Result<(), PersistControlError>>,
    #[cfg(test)]
    gate: Option<FlushGate>,
}

impl ReservedInvalidation<'_> {
    pub(crate) fn send(self, selection: PersistInvalidation) -> PendingInvalidation {
        let epoch = self
            .persister
            .epoch
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |epoch| {
                epoch.checked_add(1)
            })
            .expect("DNS persistence epoch exhausted")
            + 1;
        let (ack, receive) = oneshot::channel();
        let command = match selection {
            PersistInvalidation::All => Command::Flush { epoch, ack },
            #[cfg(any(feature = "native-api", test))]
            selection => Command::Invalidate {
                epoch,
                selection,
                ack,
            },
        };
        self.persister
            .counters
            .queued
            .fetch_add(1, Ordering::Relaxed);
        self.permit.send(command);
        PendingInvalidation {
            receive,
            #[cfg(test)]
            gate: self
                .persister
                .flush_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        }
    }
}

impl PendingInvalidation {
    pub(crate) async fn complete(self) -> Result<(), PersistControlError> {
        #[cfg(test)]
        if let Some(gate) = self.gate {
            gate.entered.notify_one();
            gate.release
                .acquire()
                .await
                .unwrap_or_else(|_| unreachable!("test flush gate remains open"))
                .forget();
        }
        let result = self
            .receive
            .await
            .map_err(|_| PersistControlError::AckDropped)
            .and_then(std::convert::identity);
        if let Err(error) = &result {
            record_flush_failure(error);
        }
        result
    }
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
        // Cannot fit once encoded; `receive_put` checks the exact size.
        if response.len() > worker::MAX_ENTRY_BYTES {
            self.counters.oversize.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(reason = "oversize", "DNS persistence write dropped");
            return;
        }
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

    pub async fn restore(
        &self,
        cache: Arc<DnsCacheService>,
        policy: Option<PolicyId>,
    ) -> Result<usize, PersistControlError> {
        let (ack, receive) = oneshot::channel();
        let publication_epoch = cache.publication_epoch();
        self.send_control(Command::Restore {
            cache,
            publication_epoch,
            policy,
            ack,
        })
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
        self.reserve_invalidation()
            .await?
            .send(PersistInvalidation::All)
            .complete()
            .await
    }

    pub(crate) async fn reserve_invalidation(
        &self,
    ) -> Result<ReservedInvalidation<'_>, PersistControlError> {
        let permit = self
            .tx
            .reserve()
            .await
            .map_err(|_| PersistControlError::Closed)?;
        Ok(ReservedInvalidation {
            permit,
            persister: self,
        })
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
        let permit = self
            .tx
            .reserve()
            .await
            .map_err(|_| PersistControlError::Closed)?;
        self.counters.queued.fetch_add(1, Ordering::Relaxed);
        permit.send(command);
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
