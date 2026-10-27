//! One live timer per flow; later deadlines reuse the old entry until it is popped. State
//! changes coalesce in a bounded dirty list before heap refresh. Deadline queries include that
//! list, so deferring the refresh cannot make the owner sleep past a live deadline.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::Instant;

use crate::flow::{Flow, Slot, Table};

/// Changed flows between flushes; a full list flushes, so `pending` stays bounded.
const DIRTY_MAX: usize = 64;

fn deadline(slot: &Slot) -> Option<Instant> {
    match slot.flow.as_ref() {
        Some(Flow::Tcp(t)) => t.next_deadline(),
        Some(Flow::TimeWait(t)) => Some(t.expiry),
        _ => None,
    }
}

pub struct Timers {
    heap: BinaryHeap<Reverse<(Instant, u32, u32)>>,
    /// Slots marked since the last flush, each once (`Slot::dirty`).
    dirty: Vec<u32>,
    /// Full rebuilds so far; lets tests assert that a burst of flows leaves them rare.
    #[cfg(test)]
    rebuilds: usize,
}

impl Timers {
    pub fn new() -> Timers {
        Timers {
            heap: BinaryHeap::new(),
            dirty: Vec::with_capacity(DIRTY_MAX),
            #[cfg(test)]
            rebuilds: 0,
        }
    }

    /// Defers [`Self::refresh`] of a changed flow to the next [`Self::flush`].
    pub fn mark(&mut self, table: &mut Table, index: u32) {
        if table.slots[index as usize].dirty {
            return;
        }
        if self.dirty.len() == DIRTY_MAX {
            self.flush(table);
        }
        table.slots[index as usize].dirty = true;
        self.dirty.push(index);
    }

    pub fn flush(&mut self, table: &mut Table) {
        while let Some(index) = self.dirty.pop() {
            table.slots[index as usize].dirty = false;
            self.refresh(table, index);
        }
    }

    /// Earliest deadline of the marked flows, which the heap may not cover yet.
    pub fn pending(&self, table: &Table) -> Option<Instant> {
        self.dirty
            .iter()
            .filter_map(|&index| deadline(&table.slots[index as usize]))
            .min()
    }

    pub fn refresh(&mut self, table: &mut Table, index: u32) {
        let slot = &mut table.slots[index as usize];
        let next = deadline(slot);
        if let Some(next) = next
            && slot.scheduled.is_none_or(|old| next < old)
        {
            slot.scheduled = Some(next);
            self.heap.push(Reverse((next, index, slot.generation)));
        }
        // A rebuild walks every slab slot, so it must be paid for by as many pushes as the slab has
        // slots: sizing the bound by live flows made each rebuild after a connection burst O(burst).
        if self.heap.len() > 2 * table.slots.len().max(16) {
            self.rebuild(table);
        }
    }

    #[cfg(feature = "fuzz-checks")]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// The marked list holds exactly the slots flagged dirty, each once, within its bound.
    #[cfg(feature = "fuzz-checks")]
    pub fn check_dirty(&self, table: &Table) {
        assert!(self.dirty.len() <= DIRTY_MAX);
        assert!(
            self.dirty
                .iter()
                .all(|&index| table.slots[index as usize].dirty)
        );
        assert_eq!(
            table.slots.iter().filter(|slot| slot.dirty).count(),
            self.dirty.len()
        );
    }

    pub fn next(&self) -> Option<Instant> {
        self.heap.peek().map(|v| v.0.0)
    }

    pub fn pop_due(&mut self, now: Instant) -> Option<(Instant, u32, u32)> {
        if self.heap.peek().is_some_and(|v| v.0.0 <= now) {
            self.heap.pop().map(|v| v.0)
        } else {
            // A connection burst leaves room for the burst; give it back once the heap is sparse.
            if self.heap.capacity() > 64 && self.heap.len() < self.heap.capacity() / 4 {
                self.heap.shrink_to(self.heap.len() * 2);
            }
            None
        }
    }

    fn rebuild(&mut self, table: &mut Table) {
        #[cfg(test)]
        {
            self.rebuilds += 1;
        }
        self.heap.clear();
        for (index, slot) in table.slots.iter_mut().enumerate() {
            let next = deadline(slot);
            slot.scheduled = next;
            if let Some(next) = next {
                self.heap
                    .push(Reverse((next, index as u32, slot.generation)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FourTuple, TimeWait};
    use std::time::Duration;

    fn entry(expiry: Instant) -> Flow {
        Flow::TimeWait(TimeWait {
            tuple: FourTuple {
                local: "192.0.2.1:40000".parse().unwrap(),
                remote: "198.51.100.1:443".parse().unwrap(),
            },
            snd_nxt: 100,
            rcv_nxt: 200,
            max_snd_wnd: u16::MAX.into(),
            ts_recent: None,
            ts_offset: 0,
            ts_last: 0,
            window: 0,
            expiry,
            ack_due: false,
        })
    }

    #[test]
    fn postpone_reuses_old_entry_and_rechecks_when_popped() {
        let now = Instant::now();
        let mut table = Table::new();
        let id = table.insert(entry(now + Duration::from_secs(1)));
        let mut timers = Timers::new();
        timers.refresh(&mut table, id.idx);
        if let Some(Flow::TimeWait(t)) = &mut table.slots[id.idx as usize].flow {
            t.expiry = now + Duration::from_secs(5);
        }
        timers.refresh(&mut table, id.idx);
        assert_eq!(timers.heap.len(), 1, "postponing must not push");
        let (deadline, index, generation) = timers.pop_due(now + Duration::from_secs(1)).unwrap();
        assert_eq!(
            (deadline, index, generation),
            (now + Duration::from_secs(1), id.idx, id.generation)
        );
        table.slots[index as usize].scheduled = None;
        timers.refresh(&mut table, index);
        assert_eq!(timers.next(), Some(now + Duration::from_secs(5)));
    }

    #[test]
    fn earlier_pushes_rebuild_stale_entries() {
        let now = Instant::now();
        let mut table = Table::new();
        let id = table.insert(entry(now + Duration::from_secs(100)));
        let mut timers = Timers::new();
        timers.refresh(&mut table, id.idx);
        for seconds in (1..100).rev() {
            if let Some(Flow::TimeWait(t)) = &mut table.slots[id.idx as usize].flow {
                t.expiry = now + Duration::from_secs(seconds);
            }
            timers.refresh(&mut table, id.idx);
            assert!(
                timers.heap.len() <= 32,
                "stale beyond the slab bound must rebuild"
            );
            assert_eq!(timers.next(), Some(now + Duration::from_secs(seconds)));
        }
    }

    #[test]
    fn a_connection_burst_does_not_make_rebuilds_frequent() {
        let now = Instant::now();
        let mut table = Table::new();
        let mut timers = Timers::new();
        let ids: Vec<_> = (0..2000)
            .map(|_| table.insert(entry(now + Duration::from_secs(1000))))
            .collect();
        for id in &ids {
            timers.refresh(&mut table, id.idx);
        }
        for id in &ids[1..] {
            table.remove(id.idx);
        }
        // One survivor keeps pulling its deadline earlier; each rebuild walks all 2000 slots.
        for seconds in (1..100).rev() {
            if let Some(Flow::TimeWait(t)) = &mut table.slots[ids[0].idx as usize].flow {
                t.expiry = now + Duration::from_secs(seconds);
            }
            timers.refresh(&mut table, ids[0].idx);
        }
        assert_eq!(
            timers.rebuilds, 0,
            "pushes are paid for by the slab size, not the live count"
        );
    }
}
