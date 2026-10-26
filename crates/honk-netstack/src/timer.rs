//! One live timer per flow; later deadlines reuse the old entry until it is popped.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::Instant;

use crate::flow::{Flow, Table};

pub struct Timers {
    heap: BinaryHeap<Reverse<(Instant, u32, u32)>>,
}

impl Timers {
    pub fn new() -> Timers {
        Timers {
            heap: BinaryHeap::new(),
        }
    }

    pub fn refresh(&mut self, table: &mut Table, index: u32) {
        let slot = &mut table.slots[index as usize];
        let next = match slot.flow.as_ref() {
            Some(Flow::Tcp(t)) => t.next_deadline(),
            Some(Flow::TimeWait(t)) => Some(t.expiry),
            _ => None,
        };
        if let Some(next) = next
            && slot.scheduled.is_none_or(|old| next < old)
        {
            slot.scheduled = Some(next);
            self.heap.push(Reverse((next, index, slot.generation)));
        }
        let live = table.active as usize + table.timewait.len();
        if self.heap.len() > 2 * live.max(1) {
            self.rebuild(table);
        }
    }

    pub fn next(&self) -> Option<Instant> {
        self.heap.peek().map(|v| v.0.0)
    }

    pub fn pop_due(&mut self, now: Instant) -> Option<(Instant, u32, u32)> {
        if self.heap.peek().is_some_and(|v| v.0.0 <= now) {
            self.heap.pop().map(|v| v.0)
        } else {
            None
        }
    }

    fn rebuild(&mut self, table: &mut Table) {
        self.heap.clear();
        for (index, slot) in table.slots.iter_mut().enumerate() {
            let next = match slot.flow.as_ref() {
                Some(Flow::Tcp(t)) => t.next_deadline(),
                Some(Flow::TimeWait(t)) => Some(t.expiry),
                _ => None,
            };
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
            assert!(timers.heap.len() <= 2, "stale > live must rebuild");
            assert_eq!(timers.next(), Some(now + Duration::from_secs(seconds)));
        }
    }
}
