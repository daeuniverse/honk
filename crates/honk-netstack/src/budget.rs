//! A byte budget several stacks of one process draw from.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Growth may retain the old backing while allocating a doubled replacement.
pub(crate) fn collection_peak<T>(len: usize) -> Option<usize> {
    let cells = len.max(4).checked_next_power_of_two()?;
    cells
        .checked_mul(std::mem::size_of::<T>())?
        .checked_mul(3)
        .filter(|&bytes| bytes <= isize::MAX as usize)
}

/// Hash tables need spare buckets and control bytes, including during rehash.
pub(crate) fn map_peak<K, V>(len: usize) -> Option<usize> {
    let buckets = len.checked_mul(2)?.max(4).checked_next_power_of_two()?;
    buckets
        .checked_mul(std::mem::size_of::<(K, V)>().checked_add(1)?)?
        .checked_add(16)?
        .checked_mul(3)
        .filter(|&bytes| bytes <= isize::MAX as usize)
}
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

/// A fixed capacity charge. Keep it until the storage or commitment it funds is released.
#[derive(Debug)]
#[must_use = "the reservation must outlive the storage it funds"]
pub struct MemoryReservation {
    budget: Arc<MemoryBudget>,
    bytes: usize,
}

impl MemoryReservation {
    /// Adopts an existing charge without charging again. The caller must relinquish exactly
    /// these previously charged bytes from its own accounting without refunding the budget.
    pub(crate) fn from_charged(budget: Arc<MemoryBudget>, bytes: usize) -> Self {
        Self { budget, bytes }
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn belongs_to(&self, budget: &Arc<MemoryBudget>) -> bool {
        Arc::ptr_eq(&self.budget, budget)
    }
}

impl Drop for MemoryReservation {
    fn drop(&mut self) {
        if self.bytes != 0 {
            self.budget.refund(self.bytes);
        }
    }
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

    /// Reserves capacity before allocation or publication. Dropping the returned owner refunds it.
    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Option<MemoryReservation> {
        self.try_charge(bytes).then(|| MemoryReservation {
            budget: Arc::clone(self),
            bytes,
        })
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
