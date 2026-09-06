use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use honk_config::dns::DnsStrategy;

use tokio::sync::broadcast;

use super::cache::{CacheKey, OperationKind};
use super::forwarder::{DnsForwardError, ResolveMode};
use super::query::DnsRequestMeta;
use super::response::ResponseTemplate;

pub(crate) const MAX_ACTIVE_FLIGHTS: usize = 2048;
pub(crate) const MAX_WAITERS_PER_FLIGHT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum FlightKey {
    Resolve {
        cache_key: CacheKey,
        mode: ResolveMode,
        prefer_meta: Option<DnsRequestMeta>,
    },
    Refresh(CacheKey),
}

impl FlightKey {
    pub(crate) fn resolve(
        cache_key: CacheKey,
        mode: ResolveMode,
        strategy: &DnsStrategy,
        qtype: u16,
        metadata: DnsRequestMeta,
    ) -> Self {
        let prefer_meta = matches!(
            (strategy, qtype),
            (DnsStrategy::PreferIpv4, 28) | (DnsStrategy::PreferIpv6, 1)
        )
        .then_some(metadata);
        Self::Resolve {
            cache_key,
            mode,
            prefer_meta,
        }
    }

    fn operation(&self) -> OperationKind {
        match self {
            Self::Resolve { cache_key, .. } | Self::Refresh(cache_key) => cache_key.operation(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlightCounters {
    pub leaders: u64,
    pub waiters: u64,
    /// Saturated-key requests rejected rather than opening an unbounded exchange.
    pub rejections: u64,
    /// Followers attached to a shared upstream exchange.
    pub amplification_avoided: u64,
    pub aborts: u64,
    pub retries: u64,
    pub refreshes: u64,
}

#[derive(Default)]
struct CounterSet {
    leaders: AtomicU64,
    waiters: AtomicU64,
    rejections: AtomicU64,
    amplification_avoided: AtomicU64,
    aborts: AtomicU64,
    retries: AtomicU64,
    refreshes: AtomicU64,
}

pub(crate) type FlightResult = Result<Arc<ResponseTemplate>, Arc<DnsForwardError>>;

#[derive(Clone, Default)]
pub(crate) struct Singleflight {
    entries: Arc<Mutex<HashMap<FlightKey, broadcast::Sender<FlightResult>>>>,
    counters: Arc<CounterSet>,
}

pub(crate) enum FlightRole {
    Leader(FlightLeader),
    Waiter(FlightWaiter),
    Rejected,
}

pub(crate) struct FlightWaiter {
    receiver: broadcast::Receiver<FlightResult>,
    counters: Arc<CounterSet>,
}

pub(crate) struct FlightLeader {
    key: Option<FlightKey>,
    entries: Arc<Mutex<HashMap<FlightKey, broadcast::Sender<FlightResult>>>>,
    counters: Arc<CounterSet>,
}

impl Singleflight {
    pub(crate) fn acquire(&self, key: FlightKey) -> FlightRole {
        let mut entries = lock(&self.entries);
        if let Some(sender) = entries.get(&key) {
            if sender.receiver_count() >= MAX_WAITERS_PER_FLIGHT {
                self.counters.rejections.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::SingleflightRejected);
                tracing::warn!(
                    saturation = "waiters",
                    action = "reject",
                    "DNS singleflight saturated"
                );
                return FlightRole::Rejected;
            }
            self.counters.waiters.fetch_add(1, Ordering::Relaxed);
            self.counters
                .amplification_avoided
                .fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(
                crate::stats::DnsStatEvent::SingleflightAmplificationAvoided,
            );
            return FlightRole::Waiter(FlightWaiter {
                receiver: sender.subscribe(),
                counters: Arc::clone(&self.counters),
            });
        }
        if entries.len() >= MAX_ACTIVE_FLIGHTS {
            self.counters.rejections.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::SingleflightRejected);
            tracing::warn!(
                saturation = "keys",
                action = "reject",
                "DNS singleflight saturated"
            );
            return FlightRole::Rejected;
        }
        let (sender, _) = broadcast::channel(1);
        entries.insert(key.clone(), sender);
        self.counters.leaders.fetch_add(1, Ordering::Relaxed);
        if matches!(key.operation(), OperationKind::Refresh) {
            self.counters.refreshes.fetch_add(1, Ordering::Relaxed);
        }
        FlightRole::Leader(FlightLeader {
            key: Some(key),
            entries: Arc::clone(&self.entries),
            counters: Arc::clone(&self.counters),
        })
    }

    pub(crate) fn counters(&self) -> FlightCounters {
        FlightCounters {
            leaders: self.counters.leaders.load(Ordering::Relaxed),
            waiters: self.counters.waiters.load(Ordering::Relaxed),
            rejections: self.counters.rejections.load(Ordering::Relaxed),
            amplification_avoided: self.counters.amplification_avoided.load(Ordering::Relaxed),
            aborts: self.counters.aborts.load(Ordering::Relaxed),
            retries: self.counters.retries.load(Ordering::Relaxed),
            refreshes: self.counters.refreshes.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn active_len(&self) -> usize {
        lock(&self.entries).len()
    }
}

impl FlightWaiter {
    pub(crate) async fn receive(mut self) -> Option<FlightResult> {
        match self.receiver.recv().await {
            Ok(template) => Some(template),
            Err(_) => {
                self.counters.retries.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::SingleflightRetry);
                tracing::debug!(reason = "leader_unavailable", "DNS singleflight retry");
                None
            }
        }
    }
}

impl FlightLeader {
    pub(crate) fn publish(mut self, result: FlightResult) {
        let Some(key) = self.key.take() else {
            return;
        };
        let mut entries = lock(&self.entries);
        let Some(sender) = entries.remove(&key) else {
            return;
        };
        // Sending while `entries` is locked is completion's linearization point:
        // attached waiters are notified before a successor can be acquired.
        let _ = sender.send(result);
    }

    pub(crate) fn fail(self, error: DnsForwardError) -> DnsForwardError {
        let error = Arc::new(error);
        self.publish(Err(Arc::clone(&error)));
        Arc::try_unwrap(error).unwrap_or_else(DnsForwardError::Shared)
    }
}

impl Drop for FlightLeader {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let aborted = lock(&self.entries).remove(&key).is_some();
        if aborted {
            self.counters.aborts.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::SingleflightCancel);
            tracing::debug!(role = "leader", "DNS singleflight cancelled");
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
