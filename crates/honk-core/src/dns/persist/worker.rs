use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::mpsc;

use super::codec;
use super::{COMMAND_CAPACITY, Command, CounterSet, PersistControlError, Put, Remove};
use crate::cachedb::CacheDb;

mod restore {
    use std::sync::atomic::Ordering;

    use super::super::codec::{self, DecodeError};
    use super::super::{CounterSet, unix_now};
    use crate::cachedb::CacheDb;
    use crate::dns::cache::DnsCacheService;
    use crate::dns::policy::PolicyId;

    pub(super) fn restore(
        db: &CacheDb,
        cache: &DnsCacheService,
        policy: Option<&PolicyId>,
        counters: &CounterSet,
    ) -> usize {
        let rows = match db.load_dns_v2() {
            Ok(rows) => rows,
            Err(error) => {
                counters.db_errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%error, "DNS persistence restore query failed");
                return 0;
            }
        };
        let now = unix_now();
        let mut restored = 0usize;
        for (suffix, bytes) in rows {
            match codec::decode(&suffix, &bytes, policy) {
                Ok(entry) if entry.expire_at_unix <= now => {
                    counters.stale.fetch_add(1, Ordering::Relaxed);
                }
                Ok(entry) => {
                    let remaining = entry.expire_at_unix.saturating_sub(now);
                    let Ok(ttl) = u32::try_from(remaining) else {
                        counters.corrupt.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    cache.put_restored_exact(entry.key, entry.response, ttl);
                    restored = restored.saturating_add(1);
                    counters.restored.fetch_add(1, Ordering::Relaxed);
                }
                Err(DecodeError::Version(_)) => {
                    counters.version_mismatch.fetch_add(1, Ordering::Relaxed);
                }
                Err(DecodeError::PolicyMismatch) => {
                    counters.policy_mismatch.fetch_add(1, Ordering::Relaxed);
                }
                Err(DecodeError::Collision | DecodeError::Corrupt) => {
                    counters.corrupt.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        restored
    }
}

const FLUSH_INTERVAL: Duration = Duration::from_millis(100);
const PENDING_CAPACITY: usize = COMMAND_CAPACITY;

struct Pending {
    epoch: u64,
    bytes: Vec<u8>,
}

pub(super) fn run(db: Arc<CacheDb>, receiver: mpsc::Receiver<Command>, counters: Arc<CounterSet>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::warn!(%error, "DNS persistence worker runtime failed");
            return;
        }
    };
    runtime.block_on(run_loop(db, receiver, counters));
}

async fn run_loop(
    db: Arc<CacheDb>,
    mut receiver: mpsc::Receiver<Command>,
    counters: Arc<CounterSet>,
) {
    let mut active_epoch = 0u64;
    let mut cleared_epoch = 0u64;
    let mut pending = HashMap::<String, Pending>::new();
    let mut interval = tokio::time::interval(FLUSH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = interval.tick() => {
                let _ = write_active(&db, &mut pending, active_epoch, &counters);
            }
            command = receiver.recv() => {
                let Some(command) = command else {
                    let _ = write_newest(&db, &mut pending, &mut active_epoch, &counters);
                    return;
                };
                counters.queued.fetch_sub(1, Ordering::Relaxed);
                match command {
                    Command::Put(value) => receive_put(
                        value,
                        active_epoch,
                        &mut pending,
                        &counters,
                    ),
                    Command::Remove(value) => {
                        if let Err(error) = receive_remove(
                            value,
                            active_epoch,
                            &mut pending,
                            &counters,
                            &db,
                        ) {
                            counters.db_errors.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(%error, "DNS persistence exact removal failed");
                        }
                    }
                    Command::Flush { epoch, ack } => {
                        let result = flush(
                            &db,
                            &mut pending,
                            &mut active_epoch,
                            &mut cleared_epoch,
                            epoch,
                            &counters,
                        );
                        let _ = ack.send(result);
                    }
                    Command::Restore { cache, policy, ack } => {
                        let restored = restore::restore(&db, &cache, policy.as_ref(), &counters);
                        let _ = ack.send(restored);
                    }
                    Command::Shutdown { ack } => {
                        let result =
                            write_newest(&db, &mut pending, &mut active_epoch, &counters);
                        let _ = ack.send(result);
                        return;
                    }
                }
            }
        }
    }
}

fn receive_put(
    value: Put,
    active_epoch: u64,
    pending: &mut HashMap<String, Pending>,
    counters: &CounterSet,
) {
    if value.epoch < active_epoch {
        counters.old_epoch_discarded.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let encoded = codec::encode(&value.key, &value.response, value.expire_at_unix);
    if pending
        .get(&encoded.suffix)
        .is_some_and(|existing| existing.epoch > value.epoch)
    {
        counters.old_epoch_discarded.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if pending.len() >= PENDING_CAPACITY && !pending.contains_key(&encoded.suffix) {
        counters
            .dropped_pending_full
            .fetch_add(1, Ordering::Relaxed);
        crate::stats::record_dns_event(crate::stats::DnsStatEvent::PersistenceDrop);
        tracing::debug!(reason = "pending_set_full", "DNS persistence write dropped");
        return;
    }
    pending.insert(
        encoded.suffix,
        Pending {
            epoch: value.epoch,
            bytes: encoded.bytes,
        },
    );
    counters.pending.store(pending.len(), Ordering::Relaxed);
}

fn receive_remove(
    value: Remove,
    active_epoch: u64,
    pending: &mut HashMap<String, Pending>,
    counters: &CounterSet,
    db: &CacheDb,
) -> Result<(), crate::cachedb::CacheDbError> {
    if value.epoch < active_epoch {
        counters.old_epoch_discarded.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    let suffix = codec::key_suffix(&value.key);
    if pending
        .get(&suffix)
        .is_some_and(|existing| existing.epoch > value.epoch)
    {
        counters.old_epoch_discarded.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    pending.remove(&suffix);
    counters.pending.store(pending.len(), Ordering::Relaxed);
    db.remove_dns_v2(&suffix)
}

fn write_active(
    db: &CacheDb,
    pending: &mut HashMap<String, Pending>,
    active_epoch: u64,
    counters: &CounterSet,
) -> Result<(), PersistControlError> {
    let entries = pending
        .iter()
        .filter(|(_, value)| value.epoch == active_epoch)
        .map(|(suffix, value)| (suffix.clone(), value.bytes.clone()))
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return Ok(());
    }
    counters.write_attempts.fetch_add(1, Ordering::Relaxed);
    match db.write_dns_v2(&entries) {
        Ok(()) => {
            for (suffix, _) in &entries {
                pending.remove(suffix);
            }
            counters.written.fetch_add(
                u64::try_from(entries.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            counters.pending.store(pending.len(), Ordering::Relaxed);
            Ok(())
        }
        Err(error) => {
            counters.db_errors.fetch_add(1, Ordering::Relaxed);
            Err(PersistControlError::Database(error.to_string()))
        }
    }
}

fn flush(
    db: &CacheDb,
    pending: &mut HashMap<String, Pending>,
    active_epoch: &mut u64,
    cleared_epoch: &mut u64,
    epoch: u64,
    counters: &CounterSet,
) -> Result<(), PersistControlError> {
    if epoch < *active_epoch {
        return if epoch <= *cleared_epoch {
            Ok(())
        } else {
            Err(PersistControlError::Database(
                "newer DNS flush barrier did not clear persistent rows".to_string(),
            ))
        };
    }
    *active_epoch = epoch;
    discard_before(pending, epoch, counters);
    db.flush_dns_namespaces().map_err(|error| {
        counters.db_errors.fetch_add(1, Ordering::Relaxed);
        PersistControlError::Database(error.to_string())
    })?;
    *cleared_epoch = epoch;
    write_active(db, pending, *active_epoch, counters)
}

fn write_newest(
    db: &CacheDb,
    pending: &mut HashMap<String, Pending>,
    active_epoch: &mut u64,
    counters: &CounterSet,
) -> Result<(), PersistControlError> {
    if let Some(newest) = pending.values().map(|value| value.epoch).max() {
        *active_epoch = (*active_epoch).max(newest);
        discard_before(pending, *active_epoch, counters);
    }
    write_active(db, pending, *active_epoch, counters)
}

fn discard_before(pending: &mut HashMap<String, Pending>, epoch: u64, counters: &CounterSet) {
    let before = pending.len();
    pending.retain(|_, value| value.epoch >= epoch);
    counters.old_epoch_discarded.fetch_add(
        u64::try_from(before.saturating_sub(pending.len())).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    counters.pending.store(pending.len(), Ordering::Relaxed);
}
