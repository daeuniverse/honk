//! A byte budget several stacks of one process draw from.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A byte limit shared by every [`Stack`](crate::Stack) whose [`Config`](crate::Config) holds
/// the same `Arc`. It counts the same commitments a stack's own `memory_limit` counts (per-flow
/// floors, shared chunk commitments, descriptor storage), so a stack admits a flow or grows a
/// window only when both limits have room, and gives everything back as its flows retire or
/// the stack is dropped. Lock-free: one atomic update per chunk-sized charge, never per byte.
#[derive(Debug)]
pub struct MemoryBudget {
    limit: usize,
    used: AtomicUsize,
}

impl MemoryBudget {
    pub fn new(limit_bytes: usize) -> Arc<MemoryBudget> {
        Arc::new(MemoryBudget {
            limit: limit_bytes,
            used: AtomicUsize::new(0),
        })
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Bytes currently charged by all stacks.
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    pub(crate) fn available(&self) -> usize {
        self.limit.saturating_sub(self.used())
    }

    pub(crate) fn try_charge(&self, bytes: usize) -> bool {
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|&n| n <= self.limit)
            })
            .is_ok()
    }

    pub(crate) fn refund(&self, bytes: usize) {
        let before = self.used.fetch_sub(bytes, Ordering::Relaxed);
        debug_assert!(bytes <= before, "budget refunded more than it holds");
    }
}
