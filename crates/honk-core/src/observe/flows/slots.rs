use super::{Record, Uuid};
use std::collections::{HashMap, VecDeque};

#[derive(Default)]
pub(super) struct RecordSlots {
    slots: Vec<Option<Record>>,
    free: Vec<usize>,
    order: VecDeque<usize>,
    by_id: HashMap<Uuid, usize>,
    // Deletion can reduce HashMap::capacity without returning its bucket allocation.
    peak_capacity: usize,
}

impl RecordSlots {
    pub(super) fn insert(&mut self, key: Uuid, record: Record) {
        let slot = if let Some(slot) = self.free.pop() {
            self.slots[slot] = Some(record);
            slot
        } else {
            self.slots.push(Some(record));
            self.slots.len() - 1
        };
        assert!(self.by_id.insert(key, slot).is_none());
        self.peak_capacity = self.peak_capacity.max(self.by_id.capacity());
        self.order.push_back(slot);
    }

    pub(super) fn at(&self, position: usize) -> &Record {
        self.slots[self.order[position]]
            .as_ref()
            .expect("ordered live slot")
    }

    pub(super) fn get(&self, key: &Uuid) -> Option<&Record> {
        self.slots[*self.by_id.get(key)?].as_ref()
    }

    pub(super) fn get_mut(&mut self, key: &Uuid) -> Option<&mut Record> {
        self.slots[*self.by_id.get(key)?].as_mut()
    }

    pub(super) fn position(&self, key: &Uuid) -> Option<usize> {
        let slot = self.by_id.get(key)?;
        self.order.iter().position(|s| s == slot)
    }

    pub(super) fn lookup(&self, id: &str) -> Option<&Record> {
        self.get(&Uuid::parse_str(id).ok()?)
            .filter(|record| record.id() == id)
    }

    pub(super) fn remove(&mut self, position: usize) -> Record {
        let slot = self.order.remove(position).expect("known record position");
        let record = self.slots[slot].take().expect("ordered live slot");
        self.by_id
            .remove(&record.id().parse::<Uuid>().expect("recorder UUID"));
        self.free.push(slot);
        record
    }

    pub(super) fn iter(&self) -> impl DoubleEndedIterator<Item = &Record> {
        self.order
            .iter()
            .map(|&slot| self.slots[slot].as_ref().expect("ordered live slot"))
    }

    pub(super) fn len(&self) -> usize {
        self.order.len()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub(super) fn overhead(&self) -> usize {
        // A power-of-two hash table has one control byte per bucket plus a trailing
        // control group and alignment slack. Charge a conservative extra group.
        let index = if self.peak_capacity == 0 {
            0
        } else {
            self.peak_capacity.next_power_of_two() * (size_of::<(Uuid, usize)>() + 1) + 64
        };
        self.slots.capacity() * size_of::<Option<Record>>() - self.len() * size_of::<Record>()
            + (self.free.capacity() + self.order.capacity()) * size_of::<usize>()
            + index
    }

    pub(super) fn shrink_to_fit(&mut self) {
        while self.slots.last().is_some_and(Option::is_none) {
            self.slots.pop();
        }
        self.free.retain(|&slot| slot < self.slots.len());
        self.free.shrink_to_fit();
        self.order.shrink_to_fit();
        self.slots.shrink_to_fit();
        if self.by_id.len() < self.peak_capacity / 2 {
            let before = self.by_id.capacity();
            self.by_id.shrink_to_fit();
            let after = self.by_id.capacity();
            if after != before || self.by_id.is_empty() {
                self.peak_capacity = after;
            }
        }
    }
}
