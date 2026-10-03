use std::collections::HashMap;
#[cfg(any(feature = "native-api", test))]
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::mpsc;

#[cfg(any(feature = "native-api", test))]
use super::PersistInvalidation;
use super::codec;
use super::{COMMAND_CAPACITY, Command, CounterSet, PersistControlError, Put};
use crate::state::cache::{CacheDb, DnsWrite};

mod restore {
    use std::sync::atomic::Ordering;

    use super::super::codec::{self, DecodeError};
    use super::super::{CounterSet, unix_now};
    use crate::dns::cache::DnsCacheService;
    use crate::dns::policy::PolicyId;
    use crate::state::cache::CacheDb;

    pub(super) fn restore(
        db: &CacheDb,
        cache: &DnsCacheService,
        publication_epoch: crate::dns::cache::PublicationEpoch,
        policy: Option<&PolicyId>,
        counters: &CounterSet,
    ) -> usize {
        let now = unix_now();
        let mut restored = 0usize;
        let result = db.for_each_dns(|suffix, bytes| match codec::decode(suffix, bytes, policy) {
            Ok(entry) if entry.expire_at_unix <= now => {
                counters.stale.fetch_add(1, Ordering::Relaxed);
            }
            Ok(entry) => {
                let remaining = entry.expire_at_unix.saturating_sub(now);
                let Ok(ttl) = u32::try_from(remaining) else {
                    counters.corrupt.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                if cache.put_restored_exact_if_current(
                    publication_epoch,
                    entry.key,
                    entry.response,
                    ttl,
                ) {
                    restored = restored.saturating_add(1);
                    counters.restored.fetch_add(1, Ordering::Relaxed);
                }
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
        });
        if let Err(error) = result {
            counters.db_errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%error, "DNS persistence restore query failed");
        }
        restored
    }
}

const FLUSH_INTERVAL: Duration = Duration::from_millis(100);
const PENDING_CAPACITY: usize = COMMAND_CAPACITY;
/// The `dns_answer.entry` `CHECK`. A row above it would abort the whole batch
/// transaction, which `write_active` would then retry forever.
pub(super) const MAX_ENTRY_BYTES: usize = 4096;

struct Pending {
    epoch: u64,
    expire_at_unix: u64,
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
                    #[cfg(any(feature = "native-api", test))]
                    Command::Invalidate { epoch, selection, ack } => {
                        let result = invalidate(&db, &mut pending, &mut active_epoch,
                            epoch, selection, &counters);
                        let _ = ack.send(result);
                    }
                    Command::Restore { cache, publication_epoch, policy, ack } => {
                        let restored = restore::restore(&db, &cache, publication_epoch, policy.as_ref(), &counters);
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
    if encoded.bytes.len() > MAX_ENTRY_BYTES {
        counters.oversize.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(reason = "oversize", "DNS persistence write dropped");
        return;
    }
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
            expire_at_unix: value.expire_at_unix,
            bytes: encoded.bytes,
        },
    );
    counters.pending.store(pending.len(), Ordering::Relaxed);
}

fn write_active(
    db: &CacheDb,
    pending: &mut HashMap<String, Pending>,
    active_epoch: u64,
    counters: &CounterSet,
) -> Result<(), PersistControlError> {
    // The batch moves out of `pending` and comes back only on failure.
    let (batch, rest): (HashMap<_, _>, HashMap<_, _>) = std::mem::take(pending)
        .into_iter()
        .partition(|(_, value)| value.epoch == active_epoch);
    *pending = rest;
    if batch.is_empty() {
        return Ok(());
    }
    let entries = batch
        .into_iter()
        .map(|(suffix, value)| (suffix, value.expire_at_unix, value.bytes))
        .collect::<Vec<_>>();
    let written = entries.len();
    counters.write_attempts.fetch_add(1, Ordering::Relaxed);
    let result = match db.write_dns(entries) {
        Ok(DnsWrite::Written) => {
            counters.written.fetch_add(
                u64::try_from(written).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            Ok(())
        }
        Ok(DnsWrite::Skipped) => {
            counters.budget_skipped.fetch_add(
                u64::try_from(written).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            Ok(())
        }
        Err((error, entries)) => {
            for (suffix, expire_at_unix, bytes) in entries {
                pending.insert(
                    suffix,
                    Pending {
                        epoch: active_epoch,
                        expire_at_unix,
                        bytes,
                    },
                );
            }
            counters.db_errors.fetch_add(1, Ordering::Relaxed);
            Err(PersistControlError::Database(error.to_string()))
        }
    };
    counters.pending.store(pending.len(), Ordering::Relaxed);
    result
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
    db.flush_dns().map_err(|error| {
        counters.db_errors.fetch_add(1, Ordering::Relaxed);
        PersistControlError::Database(error.to_string())
    })?;
    *cleared_epoch = epoch;
    write_active(db, pending, *active_epoch, counters)
}

#[cfg(any(feature = "native-api", test))]
fn invalidate(
    db: &CacheDb,
    pending: &mut HashMap<String, Pending>,
    active_epoch: &mut u64,
    epoch: u64,
    selection: PersistInvalidation,
    counters: &CounterSet,
) -> Result<(), PersistControlError> {
    if epoch < *active_epoch {
        return Err(PersistControlError::Database(
            "DNS invalidation barrier was superseded".into(),
        ));
    }
    let keys: HashSet<_> = match &selection {
        PersistInvalidation::Keys(keys) => keys.iter().map(codec::key_suffix).collect(),
        PersistInvalidation::Name { .. } => HashSet::new(),
        PersistInvalidation::All => unreachable!("full invalidations use Flush"),
    };
    let matches = |suffix: &str, bytes: &[u8]| match &selection {
        PersistInvalidation::Keys(_) => keys.contains(suffix),
        PersistInvalidation::Name { name, types } => codec::question_matches(bytes, name, types),
        PersistInvalidation::All => unreachable!("full invalidations use Flush"),
    };
    let before = pending.len();
    pending.retain(|suffix, value| value.epoch >= epoch || !matches(suffix, &value.bytes));
    *active_epoch = (*active_epoch).max(epoch);
    // Unrelated queued puts remain live across the global stale-work fence.
    for value in pending.values_mut() {
        value.epoch = value.epoch.max(*active_epoch);
    }
    counters
        .old_epoch_discarded
        .fetch_add((before - pending.len()) as u64, Ordering::Relaxed);
    counters.pending.store(pending.len(), Ordering::Relaxed);
    let result = (|| {
        let suffixes: Vec<String> = match &selection {
            PersistInvalidation::Keys(_) => keys.iter().cloned().collect(),
            PersistInvalidation::Name { .. } => {
                let mut suffixes = Vec::new();
                db.for_each_dns(|suffix, bytes| {
                    if matches(suffix, bytes) {
                        suffixes.push(suffix.to_owned());
                    }
                })?;
                suffixes
            }
            PersistInvalidation::All => unreachable!("full invalidations use Flush"),
        };
        db.delete_dns_entries(&suffixes)
    })();
    result.map_err(|error| {
        counters.db_errors.fetch_add(1, Ordering::Relaxed);
        PersistControlError::Database(error.to_string())
    })
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
