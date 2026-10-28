//! Receiver-side out-of-order range table and RFC 2018 block selection.

pub const MAX_RANGES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Range {
    start: u32,
    end: u32,
    /// Recency of the last segment that touched this range.
    touched: u32,
    /// Tick of the last ACK that reported it, for rotation among surplus ranges.
    reported: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Insert {
    Added,
    /// Entirely inside an existing range; the segment is a duplicate.
    Duplicate,
    /// A new disjoint range would exceed [`MAX_RANGES`].
    Full,
}

#[derive(Default)]
pub struct OooTable {
    ranges: Vec<Range>,
    clock: u32,
}

impl OooTable {
    pub(super) fn overhead_bound() -> Option<usize> {
        crate::budget::collection_peak::<Range>(MAX_RANGES)
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn insert(&mut self, start: u32, end: u32) -> Insert {
        use super::seq::{le, lt, max, min};
        if let Some(r) = self
            .ranges
            .iter_mut()
            .find(|r| le(r.start, start) && le(end, r.end))
        {
            self.clock = self.clock.wrapping_add(1);
            r.touched = self.clock;
            return Insert::Duplicate;
        }
        let first = self.ranges.partition_point(|r| lt(r.end, start));
        let mut last = first;
        let (mut left, mut right) = (start, end);
        while last < self.ranges.len() && le(self.ranges[last].start, right) {
            left = min(left, self.ranges[last].start);
            right = max(right, self.ranges[last].end);
            last += 1;
        }
        if first == last && self.ranges.len() == MAX_RANGES {
            return Insert::Full;
        }
        self.ranges.drain(first..last);
        self.clock = self.clock.wrapping_add(1);
        self.ranges.insert(
            first,
            Range {
                start: left,
                end: right,
                touched: self.clock,
                reported: 0,
            },
        );
        Insert::Added
    }

    /// Drops every range reached by `rcv_nxt` and returns the advanced edge.
    pub fn advance(&mut self, mut rcv_nxt: u32) -> u32 {
        while let Some(r) = self.ranges.first() {
            if !super::seq::le(r.start, rcv_nxt) {
                break;
            }
            rcv_nxt = super::seq::max(rcv_nxt, r.end);
            self.ranges.remove(0);
        }
        // A reordering episode ends with an empty table; an idle flow keeps no range storage.
        if self.ranges.is_empty() {
            self.ranges.shrink_to_fit();
        }
        rcv_nxt
    }

    /// First block holds the most recently touched range; the rest rotate through the
    /// ranges reported least recently, so with more ranges than slots every one is
    /// eventually reported (RFC 2018 §4).
    pub fn blocks(&self, slots: usize) -> crate::wire::tcp::SackBlocks {
        let mut out = crate::wire::tcp::SackBlocks::new();
        if slots == 0 || self.ranges.is_empty() {
            return out;
        }
        let newest = (0..self.ranges.len())
            .max_by_key(|&i| self.ranges[i].touched)
            .unwrap_or(0);
        let mut indices = [0usize; MAX_RANGES];
        let mut len = 0;
        for i in 0..self.ranges.len() {
            if i != newest {
                indices[len] = i;
                len += 1;
            }
        }
        indices[..len].sort_unstable_by_key(|&i| {
            (
                self.ranges[i].reported,
                std::cmp::Reverse(self.ranges[i].touched),
            )
        });
        len = len.min(slots - 1);
        indices[..len].sort_unstable_by_key(|&i| std::cmp::Reverse(self.ranges[i].touched));
        for i in std::iter::once(newest).chain(indices[..len].iter().copied()) {
            out.push(self.ranges[i].start, self.ranges[i].end);
        }
        out
    }

    pub fn reported(&mut self, blocks: &crate::wire::tcp::SackBlocks) {
        self.clock = self.clock.wrapping_add(1);
        for r in &mut self.ranges {
            if blocks.as_slice().contains(&(r.start, r.end)) {
                r.reported = self.clock;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(t: &mut OooTable, slots: usize) -> Vec<(u32, u32)> {
        let blocks = t.blocks(slots);
        t.reported(&blocks);
        blocks.as_slice().to_vec()
    }
    fn all(t: &OooTable) -> Vec<(u32, u32)> {
        t.ranges.iter().map(|r| (r.start, r.end)).collect()
    }

    #[test]
    fn merge_adjacent_and_overlapping() {
        let mut t = OooTable::default();
        assert_eq!(t.insert(100, 200), Insert::Added);
        assert_eq!(t.insert(300, 400), Insert::Added);
        assert_eq!(t.insert(200, 300), Insert::Added);
        assert_eq!(all(&t), [(100, 400)]);
        assert_eq!(t.insert(150, 250), Insert::Duplicate);
        assert_eq!(t.insert(50, 120), Insert::Added);
        assert_eq!(all(&t), [(50, 400)]);
    }

    #[test]
    fn keeps_order_across_wraparound() {
        let mut t = OooTable::default();
        t.insert(10, 20);
        t.insert(u32::MAX - 5, 4);
        assert_eq!(all(&t), [(u32::MAX - 5, 4), (10, 20)]);
    }

    #[test]
    fn cap_drops_new_disjoint_but_not_merges() {
        let mut t = OooTable::default();
        for i in 0..MAX_RANGES as u32 {
            assert_eq!(t.insert(i * 20 + 10, i * 20 + 15), Insert::Added);
        }
        assert_eq!(t.insert(1000, 1005), Insert::Full);
        assert_eq!(t.len(), MAX_RANGES);
        assert_eq!(
            t.insert(15, 30),
            Insert::Added,
            "extends range 0 and merges range 1"
        );
        assert_eq!(t.len(), MAX_RANGES - 1);
    }

    #[test]
    fn advance_absorbs_reached_ranges() {
        let mut t = OooTable::default();
        t.insert(10, 20);
        t.insert(20, 30);
        t.insert(40, 50);
        assert_eq!(t.advance(10), 30);
        assert_eq!(all(&t), [(40, 50)]);
        assert_eq!(t.advance(5), 5);
    }

    #[test]
    fn report_newest_first_then_rotates() {
        let mut t = OooTable::default();
        for i in 0..6u32 {
            t.insert(100 + i * 20, 110 + i * 20);
        }
        let mut out = report(&mut t, 3);
        assert_eq!(out[0], (200, 210), "newest touched range leads");
        let first: Vec<_> = out.clone();
        out = report(&mut t, 3);
        assert_eq!(out[0], (200, 210));
        assert!(
            out[1..].iter().all(|b| !first[1..].contains(b)),
            "surplus ranges rotate"
        );
        let mut seen = std::collections::HashSet::new();
        for _ in 0..4 {
            out = report(&mut t, 3);
            seen.extend(out.iter().copied());
        }
        assert_eq!(seen.len(), 6);
    }
}
