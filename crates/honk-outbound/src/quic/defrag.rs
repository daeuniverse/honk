use std::collections::HashMap;
use std::time::{Duration, Instant};

const DEFRAG_MAX_PENDING: usize = 64;
const DEFRAG_MAX_FRAGMENTS: usize = 64;
const DEFRAG_MAX_AGE: Duration = Duration::from_secs(10);

struct DefragBuffer {
    frags: Vec<Option<Vec<u8>>>,
    count: usize,
    bytes: usize,
    updated: Instant,
}

pub(crate) struct Defragmenter {
    map: HashMap<u64, DefragBuffer>,
    latest_packet: Option<u64>,
    max_payload: usize,
}

impl Defragmenter {
    pub(crate) fn new(max_payload: usize) -> Self {
        Self {
            map: HashMap::new(),
            latest_packet: None,
            max_payload,
        }
    }

    fn packet_key(&mut self, packet_id: u16) -> u64 {
        let packet_id = u64::from(packet_id);
        let Some(latest) = self.latest_packet else {
            // Leave one complete cycle below the initial key for delayed fragments.
            let key = (1 << 16) | packet_id;
            self.latest_packet = Some(key);
            return key;
        };
        let base = latest & !u64::from(u16::MAX);
        let candidate = base | packet_id;
        let delta = candidate as i128 - latest as i128;
        let key = if delta > i128::from(1u64 << 15) {
            candidate.saturating_sub(1 << 16)
        } else if delta < -i128::from(1u64 << 15) {
            candidate.saturating_add(1 << 16)
        } else {
            candidate
        };
        if key > latest {
            self.latest_packet = Some(key);
        }
        key
    }

    pub(crate) fn feed(
        &mut self,
        packet_id: u16,
        frag_id: u8,
        frag_total: u8,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        if frag_total == 0
            || usize::from(frag_id) >= usize::from(frag_total)
            || usize::from(frag_total) > DEFRAG_MAX_FRAGMENTS
            || data.len() > self.max_payload
        {
            return None;
        }
        let packet_key = self.packet_key(packet_id);
        if frag_total == 1 {
            return Some(data);
        }
        let frag_total = usize::from(frag_total);
        if self.map.len() >= DEFRAG_MAX_PENDING && !self.map.contains_key(&packet_key) {
            self.map
                .retain(|_, buffer| buffer.updated.elapsed() < DEFRAG_MAX_AGE);
            if self.map.len() >= DEFRAG_MAX_PENDING {
                return None;
            }
        }
        let entry = self.map.entry(packet_key).or_insert_with(|| DefragBuffer {
            frags: (0..frag_total).map(|_| None).collect(),
            count: 0,
            bytes: 0,
            updated: Instant::now(),
        });
        if entry.frags.len() != frag_total {
            entry.frags = (0..frag_total).map(|_| None).collect();
            entry.count = 0;
            entry.bytes = 0;
        }
        let frag_id = usize::from(frag_id);
        if entry.frags[frag_id].is_some() {
            return None;
        }
        let Some(bytes) = entry.bytes.checked_add(data.len()) else {
            self.map.remove(&packet_key);
            return None;
        };
        if bytes > self.max_payload {
            self.map.remove(&packet_key);
            return None;
        }
        entry.frags[frag_id] = Some(data);
        entry.count += 1;
        entry.bytes = bytes;
        entry.updated = Instant::now();
        if entry.count != entry.frags.len() {
            return None;
        }
        let entry = self.map.remove(&packet_key).expect("entry just inserted");
        let mut data = Vec::with_capacity(entry.bytes);
        for frag in entry.frags.into_iter().flatten() {
            data.extend_from_slice(&frag);
        }
        Some(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembly_is_bounded_and_packet_id_wrap_is_distinct() {
        let mut defrag = Defragmenter::new(4);
        assert!(defrag.feed(7, 0, 65, vec![]).is_none());
        assert!(defrag.feed(8, 0, 2, vec![1, 2, 3]).is_none());
        assert!(defrag.feed(8, 1, 2, vec![4, 5]).is_none());

        assert!(defrag.feed(0, 0, 2, vec![0]).is_none());
        assert_eq!(defrag.feed(32_767, 0, 1, vec![0]), Some(vec![0]));
        assert_eq!(defrag.feed(65_534, 0, 1, vec![0]), Some(vec![0]));
        assert_eq!(defrag.feed(1, 0, 1, vec![0]), Some(vec![0]));
        assert!(defrag.feed(0, 0, 2, vec![2]).is_none());
        assert_eq!(defrag.feed(0, 1, 2, vec![3]), Some(vec![2, 3]));
    }

    #[test]
    fn inferred_previous_cycle_ids_never_alias() {
        let mut defrag = Defragmenter::new(8);
        assert!(defrag.feed(1, 0, 2, vec![1]).is_none());
        assert!(defrag.feed(40_001, 0, 2, vec![2]).is_none());
        assert!(defrag.feed(50_001, 1, 2, vec![3]).is_none());
        assert_eq!(defrag.feed(40_001, 1, 2, vec![4]), Some(vec![2, 4]));
        assert_eq!(defrag.feed(50_001, 0, 2, vec![5]), Some(vec![5, 3]));
    }

    #[test]
    fn delayed_previous_cycle_fragments_do_not_collide() {
        let mut defrag = Defragmenter::new(8);
        assert!(defrag.feed(65_530, 0, 2, vec![1]).is_none());
        assert!(defrag.feed(100, 0, 2, vec![2]).is_none());
        assert!(defrag.feed(0, 0, 2, vec![3]).is_none());
        assert!(defrag.feed(65_500, 0, 2, vec![4]).is_none());
        assert_eq!(defrag.feed(0, 1, 2, vec![5]), Some(vec![3, 5]));
        assert_eq!(defrag.feed(65_500, 1, 2, vec![6]), Some(vec![4, 6]));
    }

    #[test]
    fn malformed_fragments_do_not_advance_packet_epoch() {
        let mut defrag = Defragmenter::new(8);
        assert_eq!(defrag.packet_key(10), (1 << 16) | 10);
        assert!(defrag.feed(65_000, 0, 65, vec![1]).is_none());
        assert_eq!(defrag.latest_packet, Some((1 << 16) | 10));
        assert!(defrag.feed(11, 0, 2, vec![2]).is_none());
        assert_eq!(defrag.feed(11, 1, 2, vec![3]), Some(vec![2, 3]));
    }
}
