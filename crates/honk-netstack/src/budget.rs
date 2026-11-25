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
    backing: Option<MemoryReservation>,
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

    /// Transfers another live charge from the same budget without refunding either one.
    pub fn absorb(&mut self, mut other: Self) {
        assert!(Arc::ptr_eq(&other.budget, &self.budget));
        self.bytes += std::mem::take(&mut other.bytes);
    }

    pub(crate) fn belongs_to(&self, budget: &Arc<MemoryBudget>) -> bool {
        let mut current = &self.budget;
        loop {
            if Arc::ptr_eq(current, budget) {
                return true;
            }
            let Some(backing) = &current.backing else {
                return false;
            };
            current = &backing.budget;
        }
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
            backing: None,
        })
    }

    /// A fixed share held against this budget until the last child reservation is gone.
    pub fn child(self: &Arc<Self>, bytes: usize) -> Option<Arc<Self>> {
        let overhead = size_of::<Self>() + 2 * size_of::<usize>();
        let limit = bytes.checked_sub(overhead)?;
        Some(Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
            backing: Some(self.reserve(bytes)?),
        }))
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

#[cfg(test)]
#[test]
fn child_payload_retains_its_exact_root_grant() {
    let root = MemoryBudget::new(8192);
    let child = root.child(4096).unwrap();
    let other = root.child(4096).unwrap();
    let payload = child.reserve(child.limit()).unwrap();
    assert!(payload.belongs_to(&root));
    assert!(!payload.belongs_to(&other));
    assert!(child.reserve(1).is_none());
    assert!(root.reserve(1).is_none());
    drop((child, other));
    assert_eq!(root.used(), 4096);
    drop(payload);
    assert_eq!(root.used(), 0);
}
