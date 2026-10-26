//! Bounded IPv4/IPv6 reassembly for transparent mode.
//!
//! One contiguous buffer per datagram plus a sorted list of received ranges. Limits: entries,
//! total buffered bytes, holes per datagram and a fixed timeout counted from the first fragment.
//! Overlapping fragments (exact duplicates included) kill the datagram (RFC 5722 / RFC 8200 §4.5,
//! Linux): its buffer is freed at once and a bufferless tombstone absorbs the rest of the
//! fragments until the timeout. When the table or the byte budget is exhausted the oldest datagram
//! is evicted silently, so a flood of first fragments cannot starve a burst that completes.
//! A timeout answers with ICMP Time Exceeded (code 1) only if fragment 0 arrived.
//!
//! Sans-I/O like the rest of the stack: the caller supplies `now`, polls
//! [`Reassembler::poll_timeout`] and drains [`Reassembler::poll_icmp`].


use std::collections::VecDeque;
use std::net::IpAddr;
use std::ops::Range;
use std::time::{Duration, Instant};

use crate::icmp_out::{IcmpEmit, IcmpOut, Reject};
use crate::tcp::output::Output;
use crate::wire::frag::{self, Fragment};
use crate::{DropReason, Rx};

/// Bookkeeping charged per datagram next to its buffer (entry, ranges, key).
const ENTRY_OVERHEAD: usize = 256;
/// Time Exceeded quotes waiting for `poll_icmp`; further ones are dropped.
const MAX_PENDING_ICMP: usize = 16;
/// Bytes of upper-layer header kept after the IP header in a Time Exceeded quote.
const QUOTE_L4: usize = 8;

#[derive(Clone, Copy, Debug)]
pub struct FragmentLimits {
    pub max_entries: usize,
    pub max_bytes: usize,
    /// Gaps a datagram may have (the open tail counts until the last fragment arrives).
    pub max_holes: usize,
    pub timeout: Duration,
}

impl Default for FragmentLimits {
    fn default() -> Self {
        FragmentLimits {
            max_entries: 64,
            max_bytes: 4 * 1024 * 1024,
            max_holes: 32,
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
pub(crate) enum Push {
    /// Stored (or absorbed by a tombstone); nothing to process yet.
    Pending,
    Complete(Reassembled),
    Dropped(DropReason),
}

/// A complete datagram as a normal IP packet that `wire::parse_ip` accepts.
#[derive(Debug)]
pub(crate) struct Reassembled {
    pub packet: Vec<u8>,
}

impl Reassembled {
    /// Re-expresses the result of processing [`Self::packet`] for the caller, who may only
    /// borrow from its own input: borrowed transparent UDP becomes the owned variant.
    pub(crate) fn wrap(self, rx: Rx) -> Rx {
        match rx {
            Rx::Transparent { src, dst, payload } => Rx::TransparentOwned {
                src,
                dst,
                packet: self.packet,
                payload,
            },
            other => other,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FragmentStats {
    pub completed: u64,
    pub overlaps: u64,
    pub timeouts: u64,
    pub evicted: u64,
    pub invalid: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    proto: u8,
}

struct Live {
    data: Vec<u8>,
    /// Received `[start, end)` ranges: sorted, disjoint, adjacent ones merged.
    ranges: Vec<(usize, usize)>,
    /// Known once the last fragment arrived.
    total: Option<usize>,
    /// Fragment 0's headers as received.
    head: Vec<u8>,
}

impl Live {
    fn charge(&self) -> usize {
        ENTRY_OVERHEAD + self.data.len() + self.head.len()
    }

    fn holes(&self) -> usize {
        let mut holes = usize::from(self.ranges.first().is_some_and(|r| r.0 != 0));
        holes += self.ranges.len().saturating_sub(1);
        let tail = self.ranges.last().map_or(0, |r| r.1);
        holes + usize::from(self.total.is_none_or(|t| t != tail))
    }
}

struct Entry {
    key: Key,
    created: Instant,
    /// `None` is a tombstone: the datagram died (overlap or inconsistency).
    live: Option<Live>,
    /// What `Reassembler::bytes` currently holds for this entry.
    charged: usize,
}

pub(crate) struct Reassembler {
    limits: FragmentLimits,
    /// Oldest first.
    entries: Vec<Entry>,
    bytes: usize,
    /// Quotes of timed-out datagrams that had fragment 0.
    expired: VecDeque<Vec<u8>>,
    pub(crate) stats: FragmentStats,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(FragmentLimits::default())
    }
}

impl Reassembler {
    pub(crate) fn new(limits: FragmentLimits) -> Reassembler {
        Reassembler {
            limits,
            entries: Vec::new(),
            bytes: 0,
            expired: VecDeque::new(),
            stats: FragmentStats::default(),
        }
    }

    /// Feeds one received IP packet that `wire::parse_ip` rejected as `Fragment`.
    pub(crate) fn push(&mut self, now: Instant, packet: &[u8]) -> Push {
        let f = match frag::parse(packet) {
            Ok(f) => f,
            Err(e) => return Push::Dropped(e.into()),
        };
        let end = f.offset + f.data.len();
        if f.data.is_empty() || (f.more && f.data.len() % 8 != 0) || end > f.max_total() {
            self.stats.invalid += 1;
            return Push::Dropped(DropReason::Malformed);
        }
        if !f.more && f.offset == 0 {
            // RFC 6946: an atomic fragment is a whole datagram carrying a useless header.
            return self.finish(f.head, f.data, f.is_v6());
        }
        let key = Key {
            src: f.src,
            dst: f.dst,
            id: f.id,
            proto: f.proto,
        };
        let idx = match self.entries.iter().position(|e| e.key == key) {
            Some(i) => i,
            None => {
                if self.entries.len() >= self.limits.max_entries {
                    self.evict_oldest(None);
                }
                self.entries.push(Entry {
                    key,
                    created: now,
                    live: Some(Live {
                        data: Vec::new(),
                        ranges: Vec::new(),
                        total: None,
                        head: Vec::new(),
                    }),
                    charged: ENTRY_OVERHEAD,
                });
                self.bytes += ENTRY_OVERHEAD;
                self.entries.len() - 1
            }
        };
        if self.entries[idx].live.is_none() {
            return Push::Dropped(DropReason::Fragment);
        }
        match self.store(idx, &f, end) {
            Ok(None) => Push::Pending,
            Ok(Some(done)) => done,
            Err(()) => Push::Dropped(DropReason::Fragment),
        }
    }

    /// `Err` means the datagram was killed (and is now a tombstone or gone).
    fn store(&mut self, idx: usize, f: &Fragment<'_>, end: usize) -> Result<Option<Push>, ()> {
        let live = self.entries[idx].live.as_ref().expect("live entry");
        let at = live.ranges.partition_point(|r| r.1 <= f.offset);
        let overlaps = live.ranges.get(at).is_some_and(|r| r.0 < end);
        let beyond_total = live.total.is_some_and(|t| end > t || (!f.more && end != t));
        let before_data = !f.more && live.ranges.last().is_some_and(|r| r.1 > end);
        if overlaps || beyond_total || before_data {
            if overlaps {
                self.stats.overlaps += 1;
            } else {
                self.stats.invalid += 1;
            }
            self.kill(idx);
            return Err(());
        }
        // Dry-run the hole count: the new range may close or open gaps.
        let mut ranges = live.ranges.clone();
        let mut total = live.total;
        insert_range(&mut ranges, at, f.offset, end);
        if !f.more {
            total = Some(end);
        }
        let holes = Live {
            data: Vec::new(),
            ranges,
            total,
            head: Vec::new(),
        };
        if holes.holes() > self.limits.max_holes {
            self.stats.invalid += 1;
            self.kill(idx);
            return Err(());
        }
        let growth =
            end.saturating_sub(live.data.len()) + if f.offset == 0 { f.head.len() } else { 0 };
        let mut idx = idx;
        while self.bytes + growth > self.limits.max_bytes {
            let key = self.entries[idx].key;
            if self.entries.len() == 1 {
                self.stats.invalid += 1;
                self.kill(idx);
                return Err(());
            }
            self.evict_oldest(Some(key));
            idx = self
                .entries
                .iter()
                .position(|e| e.key == key)
                .expect("kept");
        }
        let entry = &mut self.entries[idx];
        let live = entry.live.as_mut().expect("live entry");
        if live.data.len() < end {
            live.data.resize(end, 0);
        }
        live.data[f.offset..end].copy_from_slice(f.data);
        live.ranges = holes.ranges;
        live.total = total;
        if f.offset == 0 {
            live.head = f.head.to_vec();
        }
        let charge = live.charge();
        self.bytes = self.bytes - entry.charged + charge;
        entry.charged = charge;
        if live.total == Some(live.data.len())
            && live.ranges.len() == 1
            && live.ranges[0] == (0, live.data.len())
        {
            let entry = self.entries.remove(idx);
            self.bytes -= entry.charged;
            let live = entry.live.expect("live entry");
            return Ok(Some(self.finish(&live.head, &live.data, f.is_v6())));
        }
        Ok(None)
    }

    fn finish(&mut self, head: &[u8], data: &[u8], v6: bool) -> Push {
        let Some(mut packet) = frag::seal_head(head, v6, data.len()) else {
            self.stats.invalid += 1;
            return Push::Dropped(DropReason::Fragment);
        };
        packet.extend_from_slice(data);
        self.stats.completed += 1;
        Push::Complete(Reassembled { packet })
    }

    /// Frees the buffer; the entry stays as a tombstone until its timeout.
    fn kill(&mut self, idx: usize) {
        let entry = &mut self.entries[idx];
        entry.live = None;
        self.bytes = self.bytes - entry.charged + ENTRY_OVERHEAD;
        entry.charged = ENTRY_OVERHEAD;
    }

    /// Silently evicts the oldest entry other than `keep`.
    fn evict_oldest(&mut self, keep: Option<Key>) {
        let Some(i) = self.entries.iter().position(|e| Some(e.key) != keep) else {
            return;
        };
        let entry = self.entries.remove(i);
        self.bytes -= entry.charged;
        self.stats.evicted += 1;
    }

    /// Earliest instant [`Self::expire`] has work.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        self.entries
            .iter()
            .map(|e| e.created + self.limits.timeout)
            .min()
    }

    /// Drops datagrams older than the timeout; those with fragment 0 queue an ICMP quote.
    pub(crate) fn expire(&mut self, now: Instant) {
        let timeout = self.limits.timeout;
        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].created + timeout > now {
                i += 1;
                continue;
            }
            let entry = self.entries.remove(i);
            self.bytes -= entry.charged;
            self.stats.timeouts += 1;
            if let Some(live) = entry.live
                && !live.head.is_empty()
                && self.expired.len() < MAX_PENDING_ICMP
            {
                let l4 = QUOTE_L4.min(live.data.len());
                let mut quote = live.head;
                quote.extend_from_slice(&live.data[..l4]);
                self.expired.push_back(quote);
            }
        }
    }

    /// Emits queued Time Exceeded errors, one packet per call.
    pub(crate) fn poll_icmp(&mut self, now: Instant, icmp: &mut IcmpOut, out: &mut [u8]) -> Output {
        while let Some(quote) = self.expired.front() {
            match icmp.emit(now, Reject::TimeExceeded, quote, out) {
                IcmpEmit::Sent(n) => {
                    self.expired.pop_front();
                    return Output::Sent(n);
                }
                IcmpEmit::TooSmall => return Output::Blocked,
                IcmpEmit::Suppressed | IcmpEmit::RateLimited => {
                    self.expired.pop_front();
                }
            }
        }
        Output::None
    }

    #[cfg(test)]
    pub(crate) fn pending_icmp(&self) -> bool {
        !self.expired.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Recounts the charge and checks the limits and range invariants.
    #[cfg(any(test, feature = "fuzz-checks"))]
    pub(crate) fn check(&self) {
        assert!(self.entries.len() <= self.limits.max_entries);
        assert!(self.bytes <= self.limits.max_bytes);
        assert!(self.expired.len() <= MAX_PENDING_ICMP);
        let mut sum = 0;
        for e in &self.entries {
            let expect = e.live.as_ref().map_or(ENTRY_OVERHEAD, Live::charge);
            assert_eq!(e.charged, expect);
            sum += e.charged;
            if let Some(l) = &e.live {
                assert!(l.holes() <= self.limits.max_holes);
                assert!(l.ranges.windows(2).all(|w| w[0].1 < w[1].0));
                assert_eq!(l.ranges.last().map_or(0, |r| r.1), l.data.len());
            }
        }
        assert_eq!(sum, self.bytes);
    }

    #[cfg(any(test, feature = "fuzz-checks"))]
    pub(crate) fn assert_idle(&self) {
        self.check();
        assert!(self.entries.is_empty() && self.expired.is_empty() && self.bytes == 0);
    }
}

/// Inserts `[start, end)` at position `at`, merging touching neighbours.
fn insert_range(ranges: &mut Vec<(usize, usize)>, at: usize, start: usize, end: usize) {
    let join_prev = at > 0 && ranges[at - 1].1 == start;
    let join_next = ranges.get(at).is_some_and(|r| r.0 == end);
    match (join_prev, join_next) {
        (true, true) => {
            ranges[at - 1].1 = ranges[at].1;
            ranges.remove(at);
        }
        (true, false) => ranges[at - 1].1 = end,
        (false, true) => ranges[at].0 = start,
        (false, false) => ranges.insert(at, (start, end)),
    }
}

#[allow(unused)]
fn _range_type(_: Range<usize>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::testutil::*;
    use crate::wire::{self, ipv4, ipv6, udp};
    use std::net::SocketAddr;

    /// Independent splitter: cuts a full UDP IP datagram into fragments of `size` data bytes.
    pub(crate) fn split(packet: &[u8], id: u32, size: usize) -> Vec<Vec<u8>> {
        let ip = wire::parse_ip(packet).unwrap();
        let data = &packet[ip.payload.clone()];
        let mut out = Vec::new();
        let mut off = 0;
        while off < data.len() {
            let n = size.min(data.len() - off);
            let more = off + n < data.len();
            let mut p = vec![0u8; 100 + n];
            let h = match (ip.src, ip.dst) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    ipv4::emit_fragment(&mut p, s, d, ip.proto, n, (id as u16, off, more)).unwrap()
                }
                (IpAddr::V6(s), IpAddr::V6(d)) => {
                    let h = ipv6::emit(&mut p, s, d, 44, 8 + n).unwrap();
                    h + ipv6::emit_fragment_header(&mut p[h..], ip.proto, off, more, id).unwrap()
                }
                _ => unreachable!(),
            };
            p[h..h + n].copy_from_slice(&data[off..off + n]);
            p.truncate(h + n);
            out.push(p);
            off += n;
        }
        out
    }

    fn datagram(src: IpAddr, dst: IpAddr, len: usize, seed: u64) -> Vec<u8> {
        let mut out = vec![0u8; len + 100];
        let payload = Rng::new(seed).bytes(len);
        let n = udp::emit_packet(
            &mut out,
            SocketAddr::new(src, 5000),
            SocketAddr::new(dst, 53),
            &payload,
        )
        .unwrap();
        out.truncate(n);
        out
    }

    fn families() -> [(IpAddr, IpAddr); 2] {
        [(v4(10, 0, 0, 2), v4(198, 51, 100, 7)), (v6(2), v6(7))]
    }

    fn complete(r: Push) -> Vec<u8> {
        match r {
            Push::Complete(r) => r.packet,
            other => panic!("expected a complete datagram, got {other:?}"),
        }
    }

    fn pending(r: Push) {
        assert!(matches!(r, Push::Pending), "{r:?}");
    }

    #[test]
    fn roundtrip_any_order_both_families() {
        let t = Instant::now();
        for (src, dst) in families() {
            for (len, size) in [
                (3000usize, 1000usize),
                (65_000, 1480 & !7),
                (100, 8),
                (9, 8),
            ] {
                let whole = datagram(src, dst, len, len as u64);
                let frags = split(&whole, 77, size);
                assert!(frags.len() > 1);
                let mut rng = Rng::new(len as u64);
                for round in 0..8 {
                    let mut order: Vec<usize> = (0..frags.len()).collect();
                    for i in (1..order.len()).rev() {
                        order.swap(i, rng.below(i + 1));
                    }
                    if round == 0 {
                        order.reverse();
                    }
                    let mut r = Reassembler::new(FragmentLimits {
                        max_holes: usize::MAX,
                        ..FragmentLimits::default()
                    });
                    let mut done = None;
                    for (n, &i) in order.iter().enumerate() {
                        let res = r.push(t, &frags[i]);
                        r.check();
                        if n + 1 == order.len() {
                            done = Some(complete(res));
                        } else {
                            pending(res);
                        }
                    }
                    let got = done.unwrap();
                    // The result is a plain packet carrying the original datagram.
                    let ip = wire::parse_ip(&got).unwrap();
                    let orig = wire::parse_ip(&whole).unwrap();
                    assert_eq!(&got[ip.payload], &whole[orig.payload]);
                    assert_eq!((ip.src, ip.dst, ip.proto), (src, dst, wire::PROTO_UDP));
                    r.assert_idle();
                }
            }
        }
    }

    #[test]
    fn overlap_kills_the_datagram_and_tombstone_absorbs_the_rest() {
        let t = Instant::now();
        for (src, dst) in families() {
            let whole = datagram(src, dst, 2000, 9);
            let f = split(&whole, 5, 400);
            // Partial overlap: re-cut with a different size so a fragment straddles old ranges.
            let g = split(&whole, 5, 408);
            let mut r = Reassembler::default();
            pending(r.push(t, &f[0]));
            pending(r.push(t, &f[1]));
            assert!(r.bytes() > 0);
            assert!(matches!(
                r.push(t, &g[1]),
                Push::Dropped(DropReason::Fragment)
            ));
            assert_eq!(r.stats.overlaps, 1);
            // Buffer is freed immediately; only the tombstone remains.
            assert_eq!(r.len(), 1);
            assert_eq!(r.bytes(), ENTRY_OVERHEAD);
            // Later fragments, even valid ones, never complete it.
            for p in &f[2..] {
                assert!(matches!(r.push(t, p), Push::Dropped(DropReason::Fragment)));
            }
            r.check();
            // The tombstone expires with no ICMP.
            r.expire(t + Duration::from_secs(31));
            assert!(!r.pending_icmp());
            r.assert_idle();
        }
    }

    #[test]
    fn exact_duplicate_counts_as_overlap() {
        let t = Instant::now();
        let (src, dst) = families()[0];
        let f = split(&datagram(src, dst, 1000, 1), 5, 400);
        let mut r = Reassembler::default();
        pending(r.push(t, &f[0]));
        assert!(matches!(
            r.push(t, &f[0]),
            Push::Dropped(DropReason::Fragment)
        ));
        assert_eq!(r.stats.overlaps, 1);
    }

    #[test]
    fn timeout_sends_time_exceeded_only_if_fragment_zero_was_seen() {
        let t = Instant::now();
        for (src, dst) in families() {
            let f = split(&datagram(src, dst, 3000, 3), 8, 1000);
            let late = t + Duration::from_secs(30);
            let mut icmp = IcmpOut::default();
            let mut out = [0u8; 1500];

            // Without fragment 0: silent.
            let mut r = Reassembler::default();
            pending(r.push(t, &f[1]));
            pending(r.push(t, &f[2]));
            assert_eq!(r.poll_timeout(), Some(late));
            r.expire(late - Duration::from_millis(1));
            assert_eq!(r.len(), 1, "not yet");
            r.expire(late);
            assert!(!r.pending_icmp(), "no fragment 0, no Time Exceeded");
            assert!(matches!(
                r.poll_icmp(late, &mut icmp, &mut out),
                Output::None
            ));
            r.assert_idle();

            // With fragment 0: Time Exceeded code 1 to the sender, quoting the first fragment.
            let mut r = Reassembler::default();
            pending(r.push(t, &f[0]));
            pending(r.push(t, &f[2]));
            r.expire(late);
            let Output::Sent(n) = r.poll_icmp(late, &mut icmp, &mut out) else {
                panic!("no Time Exceeded")
            };
            let ip = wire::parse_ip(&out[..n]).unwrap();
            assert_eq!((ip.src, ip.dst), (dst, src));
            let msg = &out[ip.payload];
            let (ty, code) = if src.is_ipv4() { (11, 1) } else { (3, 1) };
            assert_eq!((msg[0], msg[1]), (ty, code));
            // Quote: the first fragment's headers plus eight bytes of its payload.
            let quote = if src.is_ipv4() { 20 + 8 } else { 40 + 8 + 8 };
            assert_eq!(&msg[8..], &f[0][..quote]);
            assert!(matches!(
                r.poll_icmp(late, &mut icmp, &mut out),
                Output::None
            ));
            r.assert_idle();
        }
    }

    #[test]
    fn entry_count_is_bounded_and_oldest_is_evicted() {
        let t = Instant::now();
        let (src, dst) = families()[0];
        let mut r = Reassembler::new(FragmentLimits {
            max_entries: 4,
            ..FragmentLimits::default()
        });
        let victim = split(&datagram(src, dst, 2000, 1), 100, 800);
        pending(r.push(t, &victim[0]));
        for id in 0..8u32 {
            let f = split(&datagram(src, dst, 2000, 2), id, 800);
            pending(r.push(t, &f[0]));
            assert!(r.len() <= 4);
            r.check();
        }
        assert_eq!(r.stats.evicted, 5);
        // The victim was evicted: its remaining fragments restart a datagram and cannot finish it.
        pending(r.push(t, &victim[2]));
        pending(r.push(t, &victim[1]));
    }

    #[test]
    fn byte_budget_is_enforced_by_evicting_oldest_then_refusing() {
        let t = Instant::now();
        let (src, dst) = families()[0];
        // Room for about two 64 KiB buffers.
        let mut r = Reassembler::new(FragmentLimits {
            max_bytes: 140_000,
            ..FragmentLimits::default()
        });
        for id in 0..6u32 {
            // A last fragment at the far end forces the whole 64 KiB buffer.
            let f = split(&datagram(src, dst, 64_000, 4), id, 1400);
            pending(r.push(t, f.last().unwrap()));
            assert!(r.bytes() <= 140_000, "{}", r.bytes());
            r.check();
        }
        assert!(r.len() <= 2);
        // A single datagram that alone exceeds the budget is refused outright.
        let mut tiny = Reassembler::new(FragmentLimits {
            max_bytes: 10_000,
            ..FragmentLimits::default()
        });
        let f = split(&datagram(src, dst, 64_000, 4), 1, 1400);
        assert!(matches!(tiny.push(t, f.last().unwrap()), Push::Dropped(_)));
        tiny.check();
    }

    #[test]
    fn hole_limit_kills_scattered_datagrams() {
        let t = Instant::now();
        let (src, dst) = families()[0];
        let f = split(&datagram(src, dst, 8000, 6), 3, 200);
        let mut r = Reassembler::new(FragmentLimits {
            max_holes: 3,
            ..FragmentLimits::default()
        });
        // Every other fragment: each one opens another gap.
        let mut dropped = false;
        for p in f.iter().step_by(2) {
            if matches!(r.push(t, p), Push::Dropped(DropReason::Fragment)) {
                dropped = true;
                break;
            }
        }
        assert!(dropped);
        assert_eq!(r.bytes(), ENTRY_OVERHEAD);
        r.check();
    }

    #[test]
    fn malformed_fragments_are_dropped() {
        let t = Instant::now();
        for (src, dst) in families() {
            let f = split(&datagram(src, dst, 3000, 7), 1, 1000);
            // Non-last fragment whose length is not a multiple of 8.
            let short = split(&datagram(src, dst, 3000, 7), 1, 1004);
            let mut r = Reassembler::default();
            assert!(matches!(
                r.push(t, &short[0]),
                Push::Dropped(DropReason::Malformed)
            ));
            // Fragment past the end of the datagram announced by the last fragment.
            pending(r.push(t, f.last().unwrap()));
            let longer = split(&datagram(src, dst, 5000, 7), 1, 1000);
            assert!(matches!(
                r.push(t, &longer[4]),
                Push::Dropped(DropReason::Fragment)
            ));
            // Offset + length beyond 64 KiB.
            let mut huge = f[1].clone();
            if src.is_ipv4() {
                huge[6..8].copy_from_slice(&0x3FF0u16.to_be_bytes());
                huge[10..12].fill(0);
                let ck = wire::checksum::checksum(&huge[..20]);
                huge[10..12].copy_from_slice(&ck.to_be_bytes());
            } else {
                huge[42..44].copy_from_slice(&0xFFF9u16.to_be_bytes());
            }
            assert!(matches!(
                Reassembler::default().push(t, &huge),
                Push::Dropped(DropReason::Malformed)
            ));
            // Truncated and corrupt headers.
            assert!(matches!(
                Reassembler::default().push(t, &f[0][..30]),
                Push::Dropped(_)
            ));
            if src.is_ipv4() {
                let mut bad = f[0].clone();
                bad[11] ^= 1;
                assert!(matches!(
                    Reassembler::default().push(t, &bad),
                    Push::Dropped(DropReason::Checksum)
                ));
            }
        }
    }

    #[test]
    fn ipv6_atomic_fragment_is_delivered_without_state() {
        let t = Instant::now();
        let (src, dst) = families()[1];
        let whole = datagram(src, dst, 200, 2);
        let atomic = split(&whole, 9, 1000);
        assert_eq!(atomic.len(), 1);
        let mut r = Reassembler::default();
        let got = complete(r.push(t, &atomic[0]));
        r.assert_idle();
        let ip = wire::parse_ip(&got).unwrap();
        let orig = wire::parse_ip(&whole).unwrap();
        assert_eq!(&got[ip.payload], &whole[orig.payload]);
    }

    #[test]
    fn extension_headers_before_the_fragment_header_are_preserved() {
        let t = Instant::now();
        let (src, dst) = families()[1];
        let whole = datagram(src, dst, 3000, 5);
        let ip = wire::parse_ip(&whole).unwrap();
        let data = &whole[ip.payload];
        // IPv6 header (next = destination options) + 8-byte destination options + fragment header.
        let mut frags = Vec::new();
        for (i, chunk) in data.chunks(1000).enumerate() {
            let off = i * 1000;
            let more = off + chunk.len() < data.len();
            let mut p = vec![0u8; 40 + 8 + 8 + chunk.len()];
            ipv6::emit(
                &mut p,
                "fd00::2".parse().unwrap(),
                "fd00::7".parse().unwrap(),
                60,
                8 + 8 + chunk.len(),
            )
            .unwrap();
            p[40] = 44;
            p[41] = 0;
            p[42] = 1; // PadN
            ipv6::emit_fragment_header(&mut p[48..], wire::PROTO_UDP, off, more, 11).unwrap();
            p[56..].copy_from_slice(chunk);
            frags.push(p);
        }
        let mut r = Reassembler::default();
        pending(r.push(t, &frags[3]));
        pending(r.push(t, &frags[2]));
        pending(r.push(t, &frags[0]));
        let got = complete(r.push(t, &frags[1]));
        let ip = wire::parse_ip(&got).unwrap();
        assert_eq!(ip.proto, wire::PROTO_UDP);
        assert_eq!(&got[ip.payload], data);
        assert_eq!(got[6], 60, "unfragmentable part keeps its own chain");
        assert_eq!(
            got[40],
            wire::PROTO_UDP,
            "last extension header now names the payload"
        );
    }

    #[test]
    fn a_datagram_without_fragment_zero_never_completes_and_expiry_returns_state() {
        let t = Instant::now();
        for (src, dst) in families() {
            let mut r = Reassembler::default();
            for id in 0..10u32 {
                let f = split(&datagram(src, dst, 3000, 1), id, 1000);
                // Every byte but the head has arrived, the end included.
                for p in f[1..].iter().rev() {
                    pending(r.push(t, p));
                }
            }
            assert_eq!(r.len(), 10);
            assert!(r.bytes() > 0);
            r.expire(t + Duration::from_secs(30));
            assert!(!r.pending_icmp());
            r.assert_idle();
        }
    }
}
