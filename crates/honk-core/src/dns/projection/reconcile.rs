use std::net::IpAddr;
use std::time::Duration;

use tokio::time::Instant;

use super::state::{Batch, DesiredState, IP_CAPACITY, PendingSet, RetryMetadata};

const RETRY_MIN: Duration = Duration::from_millis(100);
const RETRY_MAX: Duration = Duration::from_secs(5);
pub(super) const MAX_BATCH_ENTRIES: usize = 256;

impl DesiredState {
    pub(super) fn batch(&mut self, now: Instant) -> Batch {
        let mut sets = Vec::new();
        let mut removes = Vec::new();
        let mut available = IP_CAPACITY.saturating_sub(self.applied.len());
        let candidates = self
            .dirty_ips
            .iter()
            .filter(|ip| !self.desired.contains_key(ip))
            .chain(
                self.dirty_ips
                    .iter()
                    .filter(|ip| self.desired.contains_key(ip)),
            )
            .copied()
            .filter(|ip| self.next_attempt_at(*ip, now) == Some(now))
            .take(MAX_BATCH_ENTRIES)
            .collect::<Vec<_>>();
        for ip in candidates {
            match self.desired.get(&ip) {
                Some(desired)
                    if self
                        .applied
                        .get(&ip)
                        .is_none_or(|applied| applied.bitmap != desired.bitmap) =>
                {
                    if !self.applied.contains_key(&ip) {
                        if available == 0 {
                            continue;
                        }
                        available -= 1;
                    }
                    sets.push(PendingSet {
                        ip,
                        bitmap: *desired,
                    });
                }
                None if self.applied.contains_key(&ip) => {
                    removes.push(ip);
                }
                Some(_) | None => {
                    self.dirty_ips.remove(&ip);
                    self.retries.remove(&ip);
                }
            }
        }
        Batch {
            generation: self.snapshot.generation(),
            sets,
            removes,
        }
    }

    pub(super) fn commit_success(&mut self, sets: &[PendingSet], removes: &[IpAddr]) -> bool {
        let mut current = true;
        for set in sets {
            self.applied.insert(set.ip, set.bitmap);
            self.retries.remove(&set.ip);
            if self
                .desired
                .get(&set.ip)
                .is_some_and(|desired| desired.bitmap == set.bitmap.bitmap)
            {
                self.dirty_ips.remove(&set.ip);
            } else {
                self.dirty_ips.insert(set.ip);
                current = false;
            }
        }
        for &ip in removes {
            self.applied.remove(&ip);
            self.retries.remove(&ip);
            if !self.desired.contains_key(&ip) {
                self.dirty_ips.remove(&ip);
            } else {
                self.dirty_ips.insert(ip);
                current = false;
            }
        }
        current
    }

    pub(super) fn record_failure(&mut self, ip: std::net::IpAddr, now: Instant) {
        let attempts = self
            .retries
            .get(&ip)
            .map_or(1, |retry| retry.attempts.saturating_add(1));
        let factor = 1u32 << u32::from(attempts.saturating_sub(1).min(6));
        let next_at = now + RETRY_MIN.saturating_mul(factor).min(RETRY_MAX);
        self.retries.insert(ip, RetryMetadata { attempts, next_at });
        self.dirty_ips.insert(ip);
    }

    fn next_attempt_at(&self, ip: std::net::IpAddr, now: Instant) -> Option<Instant> {
        if self.desired.contains_key(&ip)
            && !self.applied.contains_key(&ip)
            && self.applied.len() >= IP_CAPACITY
        {
            return None;
        }
        Some(
            self.retries
                .get(&ip)
                .map_or(now, |retry| retry.next_at.max(now)),
        )
    }

    pub(super) fn next_deadline(&mut self) -> Option<Instant> {
        self.compact_owner_heaps_if_needed();
        let now = Instant::now();
        let mut deadline = self.expiry_deadlines.peek().map(|entry| entry.0.at);
        for ip in &self.dirty_ips {
            if let Some(next) = self.next_attempt_at(*ip, now) {
                if next == now {
                    return Some(now);
                }
                deadline = Some(deadline.map_or(next, |current| current.min(next)));
            }
        }
        deadline
    }
}
