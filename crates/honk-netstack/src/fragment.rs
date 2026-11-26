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
use std::num::NonZeroU64;
use std::ops::{Deref, Range};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::icmp_out::{IcmpEmit, IcmpOut, Reject};
use crate::tcp::output::Output;
use crate::wire::frag::{self, Fragment};
use crate::{
    DropReason, IcmpState, IovTransmit, MemoryBudget, MemoryReservation, Rx, SourceContext,
    Transmit,
};

/// Fixed bookkeeping charged per datagram next to its data, header and range storage.
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

/// Fragmentation provenance retained only for a completed IPv6 datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Fragment {
    pub id: u32,
    /// Largest received fragment, including IPv6/extension/Fragment headers, without padding.
    pub max_size: usize,
}

/// One IP datagram within its caller's exact ingress/realm identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FragmentIdentity {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub id: u32,
}

impl FragmentIdentity {
    fn from_fragment(fragment: &Fragment<'_>) -> Self {
        Self {
            src: fragment.src,
            dst: fragment.dst,
            proto: fragment.proto,
            id: fragment.id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentInfo {
    pub identity: FragmentIdentity,
    pub original_ingress: Instant,
    /// Scoped to this reassembler; atomic datagrams have no retained incarnation.
    pub incarnation: Option<NonZeroU64>,
}

#[derive(Debug)]
pub struct ReassemblyReport {
    pub packet: Option<OwnedPacket>,
    pub fragment: FragmentInfo,
}

/// An affected assembly may retain a tombstone or timeout quote after rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("fragment reassembly rejected: {reason:?}")]
pub struct FragmentError {
    pub reason: DropReason,
    pub fragment: Option<FragmentInfo>,
}

impl From<DropReason> for FragmentError {
    fn from(reason: DropReason) -> Self {
        Self {
            reason,
            fragment: None,
        }
    }
}

/// Reassembled bytes whose capacity charge follows their lifetime, including beyond Stack drop.
#[derive(Debug)]
pub struct OwnedPacket {
    bytes: Box<[u8]>,
    ipv6_fragment: Option<Ipv6Fragment>,
    fragment: FragmentInfo,
    completion_ingress: Instant,
    _reservation: Option<MemoryReservation>,
}

impl OwnedPacket {
    /// Maximum original ingress of the packet's underlying fragments, independent of service.
    pub fn completion_ingress(&self) -> Instant {
        self.completion_ingress
    }

    /// Original IP fragment identity, including on an exported timeout quote.
    pub fn fragment_identity(&self) -> FragmentIdentity {
        self.fragment.identity
    }

    pub fn fragment_info(&self) -> FragmentInfo {
        self.fragment
    }

    /// Original IPv6 fragmentation facts; timeout quotes and IPv4 completions have none.
    pub fn ipv6_fragment(&self) -> Option<Ipv6Fragment> {
        self.ipv6_fragment
    }

    /// Whether these retained bytes are funded by this exact shared budget.
    pub fn charged_to(&self, budget: &Arc<MemoryBudget>) -> bool {
        self._reservation
            .as_ref()
            .is_some_and(|reservation| reservation.belongs_to(budget))
    }
}

impl Deref for OwnedPacket {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for OwnedPacket {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for OwnedPacket {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl PartialEq for OwnedPacket {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for OwnedPacket {}

#[derive(Debug)]
pub(crate) enum Push {
    /// Stored (or absorbed by a tombstone); nothing to process yet.
    Pending(FragmentInfo),
    Complete(Reassembled),
    Dropped(DropReason),
}

/// A complete datagram as a normal IP packet that `wire::parse_ip` accepts.
#[derive(Debug)]
pub(crate) struct Reassembled {
    pub packet: OwnedPacket,
    pub source: Option<SourceContext>,
}

impl Reassembled {
    /// Re-expresses the result of processing [`Self::packet`] for the caller, who may only
    /// borrow from its own input: borrowed transparent UDP becomes the owned variant.
    pub(crate) fn wrap(self, rx: Rx) -> Rx {
        match rx {
            Rx::Transparent {
                src,
                dst,
                dscp,
                payload,
            } => Rx::TransparentOwned {
                src,
                dst,
                dscp,
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
    lineage: Option<NonZeroU64>,
}

impl Key {
    fn identity(self) -> FragmentIdentity {
        FragmentIdentity {
            src: self.src,
            dst: self.dst,
            proto: self.proto,
            id: self.id,
        }
    }
}

struct Live {
    data: Vec<u8>,
    /// Received `[start, end)` ranges: sorted, disjoint, adjacent ones merged.
    ranges: Vec<(usize, usize)>,
    /// Known once the last fragment arrived.
    total: Option<usize>,
    /// Fragment 0's headers as received.
    head: Vec<u8>,
    max_fragment_size: usize,
    /// Bitset of received ECN codepoints, independent of fragment arrival order.
    ecn: u8,
}

impl Live {
    fn charge(&self) -> usize {
        ENTRY_OVERHEAD
            + self.data.capacity()
            + self.head.capacity()
            + self.ranges.capacity() * std::mem::size_of::<(usize, usize)>()
    }

    fn holes_after_insert(
        &self,
        count: usize,
        start: usize,
        end: usize,
        total: Option<usize>,
    ) -> usize {
        let leading = start != 0 && self.ranges.first().is_none_or(|r| r.0 != 0);
        let tail = self.ranges.last().map_or(end, |r| r.1.max(end));
        usize::from(leading) + count - 1 + usize::from(total != Some(tail))
    }

    #[cfg(any(test, feature = "fuzz-checks"))]
    fn holes(&self) -> usize {
        let mut holes = usize::from(self.ranges.first().is_some_and(|r| r.0 != 0));
        holes += self.ranges.len().saturating_sub(1);
        let tail = self.ranges.last().map_or(0, |r| r.1);
        holes + usize::from(self.total.is_none_or(|t| t != tail))
    }
}

struct Entry {
    key: Key,
    /// Kept on killed entries so their original lineage cannot be reclaimed early.
    source: Option<SourceContext>,
    created: Instant,
    latest_ingress: Instant,
    incarnation: NonZeroU64,
    /// `None` is a tombstone: the datagram died (overlap or inconsistency).
    live: Option<Live>,
    /// What `Reassembler::bytes` currently holds for this entry.
    charged: usize,
}

struct ExpiredQuote {
    bytes: Vec<u8>,
    source: Option<SourceContext>,
    fragment: FragmentInfo,
    latest_ingress: Instant,
}

pub(crate) struct Reassembler {
    limits: FragmentLimits,
    transit_quotes: bool,
    /// Arrival order; age follows each datagram's earliest original ingress.
    entries: Vec<Entry>,
    bytes: usize,
    /// The process-wide budget `bytes` is also charged to (and refunded to on drop).
    budget: Option<Arc<MemoryBudget>>,
    /// Quotes of timed-out datagrams that had fragment 0.
    expired: VecDeque<ExpiredQuote>,
    last_incarnation: u64,
    pub(crate) stats: FragmentStats,
}

impl Reassembler {
    pub(crate) fn overhead_bound(limits: FragmentLimits) -> Option<usize> {
        crate::budget::collection_peak::<Entry>(limits.max_entries)?.checked_add(
            crate::budget::collection_peak::<ExpiredQuote>(MAX_PENDING_ICMP)?,
        )
    }

    pub(crate) fn scratch_bound(limits: FragmentLimits) -> Option<usize> {
        // Retain scratch for overlapping old and new range and packet allocations.
        crate::budget::collection_peak::<(usize, usize)>(limits.max_holes.checked_add(2)?)?
            .checked_add(
                usize::from(u16::MAX)
                    .checked_mul(2)?
                    .checked_add(crate::icmp_out::quote_limit(true) + 20)?,
            )
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(FragmentLimits::default())
    }
}

impl Drop for Reassembler {
    fn drop(&mut self) {
        self.entries.clear();
        self.expired.clear();
        self.shrink(self.bytes);
    }
}

impl Reassembler {
    pub(crate) fn for_transit(mut self) -> Self {
        self.transit_quotes = true;
        self
    }

    pub(crate) fn new(limits: FragmentLimits) -> Reassembler {
        Reassembler {
            limits,
            transit_quotes: false,
            entries: Vec::new(),
            bytes: 0,
            budget: None,
            expired: VecDeque::new(),
            last_incarnation: 0,
            stats: FragmentStats::default(),
        }
    }

    /// Also charges every buffered byte to `budget` (refunded as datagrams leave and on drop).
    pub(crate) fn with_budget(mut self, budget: Option<Arc<MemoryBudget>>) -> Self {
        debug_assert_eq!(self.bytes, 0);
        self.budget = budget;
        self
    }

    /// Charges `n` bytes to the shared budget and this table; `false` leaves both unchanged.
    fn grow(&mut self, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        if self
            .bytes
            .checked_add(n)
            .is_none_or(|v| v > self.limits.max_bytes)
            || self.budget.as_ref().is_some_and(|b| !b.try_charge(n))
        {
            return false;
        }
        self.bytes += n;
        true
    }

    fn shrink(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        self.bytes -= n;
        if let Some(b) = &self.budget {
            b.refund(n);
        }
    }

    /// Feeds one decoded fragment after the stack applies its destination filter.
    pub(crate) fn push(
        &mut self,
        now: Instant,
        f: Fragment<'_>,
        source: Option<SourceContext>,
    ) -> Push {
        self.push_at(now, now, f, source)
    }

    pub(crate) fn push_for_dispatch_at(
        &mut self,
        ingress_at: Instant,
        service_at: Instant,
        fragment: Fragment<'_>,
    ) -> Result<ReassemblyReport, FragmentError> {
        let mut receipt = None;
        let pushed = self.push_at_inner(ingress_at, service_at, fragment, None, Some(&mut receipt));
        match pushed {
            Push::Complete(complete) => Ok(ReassemblyReport {
                fragment: complete.packet.fragment,
                packet: Some(complete.packet),
            }),
            Push::Pending(fragment) => Ok(ReassemblyReport {
                packet: None,
                fragment,
            }),
            Push::Dropped(reason) => Err(FragmentError {
                reason,
                fragment: receipt,
            }),
        }
    }

    pub(crate) fn retains_fragment(&self, fragment: FragmentInfo) -> bool {
        let Some(incarnation) = fragment.incarnation else {
            return false;
        };
        self.entries
            .iter()
            .any(|entry| entry.incarnation == incarnation)
            || self
                .expired
                .iter()
                .any(|quote| quote.fragment.incarnation == Some(incarnation))
    }

    pub(crate) fn push_at(
        &mut self,
        ingress_at: Instant,
        service_at: Instant,
        f: Fragment<'_>,
        source: Option<SourceContext>,
    ) -> Push {
        self.push_at_inner(ingress_at, service_at, f, source, None)
    }

    fn push_at_inner(
        &mut self,
        ingress_at: Instant,
        service_at: Instant,
        f: Fragment<'_>,
        source: Option<SourceContext>,
        mut receipt: Option<&mut Option<FragmentInfo>>,
    ) -> Push {
        let end = f.offset + f.data.len();
        if f.data.is_empty() || (f.more && !f.data.len().is_multiple_of(8)) || end > f.max_total() {
            self.stats.invalid += 1;
            return Push::Dropped(DropReason::Malformed);
        }
        if !f.more && f.offset == 0 {
            // RFC 6946: an atomic fragment is a whole datagram carrying a useless header.
            let provenance = f.is_v6().then_some(Ipv6Fragment {
                id: f.id,
                max_size: f.head.len() + f.data.len(),
            });
            let fragment = FragmentInfo {
                identity: FragmentIdentity::from_fragment(&f),
                original_ingress: ingress_at,
                incarnation: None,
            };
            if let Some(receipt) = receipt.as_deref_mut() {
                *receipt = Some(fragment);
            }
            return self.finish(
                f.head,
                f.data,
                provenance,
                false,
                source,
                (fragment, ingress_at),
            );
        }
        let key = Key {
            src: f.src,
            dst: f.dst,
            id: f.id,
            proto: f.proto,
            lineage: source.map(|source| source.lineage),
        };
        let idx = match self.entries.iter().position(|e| e.key == key) {
            Some(i) => {
                self.entries[i].created = self.entries[i].created.min(ingress_at);
                self.entries[i].latest_ingress = self.entries[i].latest_ingress.max(ingress_at);
                if let Some(receipt) = receipt.as_deref_mut() {
                    *receipt = Some(FragmentInfo {
                        identity: self.entries[i].key.identity(),
                        original_ingress: self.entries[i].created,
                        incarnation: Some(self.entries[i].incarnation),
                    });
                }
                if service_at >= self.entries[i].created + self.limits.timeout {
                    self.expire(service_at);
                    if service_at < ingress_at + self.limits.timeout {
                        return self.push_at_inner(ingress_at, service_at, f, source, receipt);
                    }
                    return Push::Dropped(DropReason::Fragment);
                }
                i
            }
            None => {
                if service_at >= ingress_at + self.limits.timeout {
                    return Push::Dropped(DropReason::Fragment);
                }
                let Some(incarnation) = self
                    .last_incarnation
                    .checked_add(1)
                    .and_then(NonZeroU64::new)
                else {
                    return Push::Dropped(DropReason::Capacity);
                };
                self.expire(service_at);
                if self.limits.max_entries == 0 {
                    return Push::Dropped(DropReason::Capacity);
                }
                if self.entries.len() >= self.limits.max_entries {
                    self.evict_oldest(None);
                }
                while !self.grow(ENTRY_OVERHEAD) {
                    if self.entries.is_empty() {
                        return Push::Dropped(DropReason::Capacity);
                    }
                    self.evict_oldest(None);
                }
                self.entries.push(Entry {
                    key,
                    source,
                    created: ingress_at,
                    latest_ingress: ingress_at,
                    incarnation,
                    live: Some(Live {
                        data: Vec::new(),
                        ranges: Vec::new(),
                        total: None,
                        head: Vec::new(),
                        max_fragment_size: 0,
                        ecn: 0,
                    }),
                    charged: ENTRY_OVERHEAD,
                });
                self.last_incarnation = incarnation.get();
                if let Some(receipt) = receipt {
                    *receipt = Some(FragmentInfo {
                        identity: key.identity(),
                        original_ingress: ingress_at,
                        incarnation: Some(incarnation),
                    });
                }
                self.entries.len() - 1
            }
        };
        if self.entries[idx].live.is_none() {
            return Push::Dropped(DropReason::Fragment);
        }
        if self.entries[idx].source != source {
            self.stats.invalid += 1;
            self.kill(idx);
            return Push::Dropped(DropReason::Fragment);
        }
        let fragment = FragmentInfo {
            identity: self.entries[idx].key.identity(),
            original_ingress: self.entries[idx].created,
            incarnation: Some(self.entries[idx].incarnation),
        };
        match self.store(idx, &f, end) {
            Ok(None) => Push::Pending(fragment),
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
        let ecn = live.ecn | (1 << f.ecn());
        // RFC 3168 §5.3; like Linux, reject every Not-ECT/ECN-capable mixture.
        let invalid_ecn = ecn & 1 != 0 && ecn != 1;
        if overlaps || beyond_total || before_data || invalid_ecn {
            if overlaps {
                self.stats.overlaps += 1;
            } else {
                self.stats.invalid += 1;
            }
            self.kill(idx);
            return Err(());
        }
        let total = if f.more { live.total } else { Some(end) };
        let join_left = at > 0 && live.ranges[at - 1].1 == f.offset;
        let join_right = live.ranges.get(at).is_some_and(|r| r.0 == end);
        let count = live.ranges.len() + 1 - usize::from(join_left) - usize::from(join_right);
        if live.holes_after_insert(count, f.offset, end, total) > self.limits.max_holes {
            self.stats.invalid += 1;
            self.kill(idx);
            return Err(());
        }
        let head = if f.offset == 0 {
            f.head.len()
        } else {
            live.head.capacity()
        };
        let range_capacity = live.ranges.capacity().max(count);
        let metadata = ENTRY_OVERHEAD + head + range_capacity * size_of::<(usize, usize)>();
        let ceiling = total.unwrap_or(usize::from(u16::MAX));
        let exact = live.data.capacity().min(ceiling).max(end);
        let mut capacity = if end > live.data.capacity() {
            end.max(4096).next_power_of_two().min(ceiling)
        } else {
            exact
        };
        let old_charge = self.entries[idx].charged;
        let mut idx = idx;
        while !self.grow((metadata + capacity).saturating_sub(old_charge)) {
            if capacity > exact {
                capacity = exact;
                continue;
            }
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
        let charge = metadata + capacity;
        let entry = &mut self.entries[idx];
        let live = entry.live.as_mut().expect("live entry");
        if capacity > live.data.capacity() {
            live.data.reserve_exact(capacity - live.data.len());
        }
        live.data.resize(live.data.len().max(end), 0);
        if live.data.capacity() > capacity {
            // The final extent can retire geometric slack before the completion is funded.
            let len = live.data.len();
            live.data.resize(capacity, 0);
            live.data = std::mem::take(&mut live.data).into_boxed_slice().into_vec();
            live.data.truncate(len);
        }
        live.data[f.offset..end].copy_from_slice(f.data);
        if count > live.ranges.capacity() {
            live.ranges.reserve_exact(count - live.ranges.len());
        }
        insert_range(&mut live.ranges, at, f.offset, end, join_left, join_right);
        if live.ranges.capacity() > range_capacity {
            live.ranges = std::mem::take(&mut live.ranges)
                .into_boxed_slice()
                .into_vec();
        }
        live.total = total;
        live.max_fragment_size = live.max_fragment_size.max(f.head.len() + f.data.len());
        live.ecn = ecn;
        if f.offset == 0 {
            live.head = f.head.to_vec();
        }
        debug_assert_eq!(charge, live.charge());
        entry.charged = charge;
        let complete = live.total == Some(live.data.len())
            && live.ranges.len() == 1
            && live.ranges[0] == (0, live.data.len());
        if charge < old_charge {
            self.shrink(old_charge - charge);
        }
        if complete {
            let entry = self.entries.remove(idx);
            let charged = entry.charged;
            let live = entry.live.expect("live entry");
            let provenance = f.is_v6().then_some(Ipv6Fragment {
                id: entry.key.id,
                max_size: live.max_fragment_size,
            });
            let result = self.finish(
                &live.head,
                &live.data,
                provenance,
                live.ecn & (1 << 3) != 0,
                entry.source,
                (
                    FragmentInfo {
                        identity: entry.key.identity(),
                        original_ingress: entry.created,
                        incarnation: Some(entry.incarnation),
                    },
                    entry.latest_ingress,
                ),
            );
            drop(live);
            self.shrink(charged);
            return Ok(Some(result));
        }
        Ok(None)
    }

    fn finish(
        &mut self,
        head: &[u8],
        data: &[u8],
        ipv6_fragment: Option<Ipv6Fragment>,
        ce: bool,
        source: Option<SourceContext>,
        (fragment, completion_ingress): (FragmentInfo, Instant),
    ) -> Push {
        let v6 = ipv6_fragment.is_some();
        let Some(len) = frag::reassembled_len(head.len(), v6, data.len()) else {
            self.stats.invalid += 1;
            return Push::Dropped(DropReason::Fragment);
        };
        let reservation = match &self.budget {
            Some(budget) => match budget.reserve(len) {
                Some(reservation) => Some(reservation),
                None => return Push::Dropped(DropReason::Capacity),
            },
            None => None,
        };
        let Some(bytes) = frag::seal_packet(head, v6, data, ce) else {
            self.stats.invalid += 1;
            return Push::Dropped(DropReason::Fragment);
        };
        debug_assert_eq!(bytes.len(), len);
        self.stats.completed += 1;
        Push::Complete(Reassembled {
            source,
            packet: OwnedPacket {
                bytes,
                ipv6_fragment,
                fragment,
                completion_ingress,
                _reservation: reservation,
            },
        })
    }

    /// Frees the buffer; the entry stays as a tombstone until its timeout.
    fn kill(&mut self, idx: usize) {
        let entry = &mut self.entries[idx];
        entry.live = None;
        let freed = entry.charged - ENTRY_OVERHEAD;
        entry.charged = ENTRY_OVERHEAD;
        self.shrink(freed);
    }

    /// Silently evicts the oldest entry other than `keep`.
    fn evict_oldest(&mut self, keep: Option<Key>) {
        let Some((i, _)) = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| Some(entry.key) != keep)
            .min_by_key(|(_, entry)| entry.created)
        else {
            return;
        };
        let entry = self.entries.remove(i);
        let charged = entry.charged;
        drop(entry);
        self.shrink(charged);
        self.stats.evicted += 1;
    }

    /// Earliest instant [`Self::expire`] has work.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        self.entries
            .iter()
            .map(|e| e.created + self.limits.timeout)
            .min()
    }

    pub(crate) fn is_quiescent(&self) -> bool {
        self.entries.is_empty() && self.expired.is_empty()
    }

    pub(crate) fn obligations(&self) -> impl Iterator<Item = (IpAddr, IpAddr, u8)> + Clone + '_ {
        self.entries
            .iter()
            .filter(|entry| entry.live.is_some())
            .map(|entry| (entry.key.src, entry.key.dst, entry.key.proto))
            .chain(self.expired.iter().filter_map(|quote| {
                crate::icmp_out::quote_metadata(&quote.bytes)
                    .map(|quote| (quote.source, quote.destination, quote.protocol))
            }))
    }

    pub(crate) fn retains_source_output_with_lineage(&self, lineage: NonZeroU64) -> bool {
        self.expired
            .iter()
            .any(|quote| quote.source.is_some_and(|source| source.lineage == lineage))
    }

    pub(crate) fn visit_retained_source_contexts(&self, mut visit: impl FnMut(SourceContext)) {
        for source in self
            .entries
            .iter()
            .filter_map(|entry| entry.source)
            .chain(self.expired.iter().filter_map(|quote| quote.source))
        {
            visit(source);
        }
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
            let mut retained = 0;
            self.stats.timeouts += 1;
            if let Some(live) = entry.live
                && !live.head.is_empty()
                && self.expired.len() < MAX_PENDING_ICMP
            {
                let cap = crate::icmp_out::quote_limit(entry.key.src.is_ipv6());
                let prefix = live
                    .ranges
                    .first()
                    .filter(|range| range.0 == 0)
                    .map_or(0, |range| range.1);
                let l4 = (if self.transit_quotes { 20 } else { QUOTE_L4 })
                    .min(live.data.len())
                    .min(prefix)
                    .min(cap.saturating_sub(live.head.len()));
                let mut quote = live.head;
                quote.truncate(cap);
                quote.extend_from_slice(&live.data[..l4]);
                let quote = quote.into_boxed_slice().into_vec();
                retained = quote.capacity();
                self.expired.push_back(ExpiredQuote {
                    bytes: quote,
                    source: entry.source,
                    fragment: FragmentInfo {
                        identity: entry.key.identity(),
                        original_ingress: entry.created,
                        incarnation: Some(entry.incarnation),
                    },
                    latest_ingress: entry.latest_ingress,
                });
            }
            self.shrink(entry.charged - retained);
        }
    }

    /// Transfers a queued quote's existing charge; exporting it needs no extra budget headroom.
    pub(crate) fn take_expired(&mut self) -> Option<OwnedPacket> {
        let quote = self.expired.pop_front()?;
        let charged = quote.bytes.capacity();
        let reservation = self
            .budget
            .as_ref()
            .map(|budget| MemoryReservation::from_charged(Arc::clone(budget), charged));
        self.bytes -= charged;
        Some(OwnedPacket {
            bytes: quote.bytes.into_boxed_slice(),
            ipv6_fragment: None,
            fragment: quote.fragment,
            completion_ingress: quote.latest_ingress,
            _reservation: reservation,
        })
    }

    /// Emits queued Time Exceeded errors, one packet per call.
    pub(crate) fn poll_icmp(
        &mut self,
        now: Instant,
        icmp: &mut IcmpOut,
        out: &mut [u8],
        tx: &mut Transmit,
    ) -> Output {
        self.poll_icmp_with_fragment(now, icmp, out, tx).0
    }

    pub(crate) fn poll_icmp_with_fragment(
        &mut self,
        now: Instant,
        icmp: &mut IcmpOut,
        out: &mut [u8],
        tx: &mut Transmit,
    ) -> (Output, Option<FragmentInfo>) {
        while let Some(quote) = self.expired.front() {
            let result = icmp.emit(now, Reject::TimeExceeded, &quote.bytes, out);
            if result == IcmpEmit::TooSmall {
                return (Output::Blocked, None);
            }
            let (source, fragment) = self.release_expired();
            if let IcmpEmit::Sent(n) = result {
                tx.source = source;
                return (Output::Sent(n), Some(fragment));
            }
        }
        (Output::None, None)
    }

    pub(crate) fn poll_icmp_iov<E>(
        &mut self,
        now: Instant,
        icmp: &mut IcmpState,
        max_len: usize,
        emit: &mut impl FnMut(&[u8], &[&[u8]], Transmit) -> Result<(), E>,
    ) -> Result<(IovTransmit, Option<FragmentInfo>), E> {
        let Some(quote) = self.expired.front() else {
            return Ok((IovTransmit::Idle, None));
        };
        let mut tx = Transmit {
            source: quote.source,
            ..Transmit::plain(0)
        };
        match icmp.emit_iov(now, Reject::TimeExceeded, &quote.bytes, max_len, tx, emit)? {
            Some(IcmpEmit::Sent(n)) => {
                let (_, fragment) = self.release_expired();
                tx.len = n;
                Ok((IovTransmit::Packet(tx), Some(fragment)))
            }
            Some(IcmpEmit::TooSmall) => Ok((IovTransmit::BufferTooSmall, None)),
            Some(IcmpEmit::Suppressed | IcmpEmit::RateLimited) => {
                self.release_expired();
                Ok((IovTransmit::Progress, None))
            }
            None => Ok((IovTransmit::Progress, None)),
        }
    }

    fn release_expired(&mut self) -> (Option<SourceContext>, FragmentInfo) {
        let quote = self.expired.pop_front().expect("front");
        let charged = quote.bytes.capacity();
        let result = (quote.source, quote.fragment);
        drop(quote);
        self.shrink(charged);
        result
    }

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
        assert!(std::mem::size_of::<Entry>() <= ENTRY_OVERHEAD);
        assert!(self.entries.len() <= self.limits.max_entries);
        assert!(self.bytes <= self.limits.max_bytes);
        assert!(self.expired.len() <= MAX_PENDING_ICMP);
        for (index, quote) in self.expired.iter().enumerate() {
            assert!(quote.fragment.original_ingress <= quote.latest_ingress);
            let incarnation = quote
                .fragment
                .incarnation
                .expect("only retained entries time out");
            assert!(incarnation.get() <= self.last_incarnation);
            assert!(
                self.entries
                    .iter()
                    .all(|entry| entry.incarnation != incarnation)
            );
            assert!(
                self.expired
                    .iter()
                    .skip(index + 1)
                    .all(|other| other.fragment.incarnation != Some(incarnation))
            );
        }
        let mut sum = self
            .expired
            .iter()
            .map(|quote| quote.bytes.capacity())
            .sum::<usize>();
        for (index, e) in self.entries.iter().enumerate() {
            assert!(e.created <= e.latest_ingress);
            assert!(e.incarnation.get() <= self.last_incarnation);
            assert!(
                self.entries
                    .iter()
                    .skip(index + 1)
                    .all(|other| other.incarnation != e.incarnation)
            );
            assert_eq!(e.key.lineage, e.source.map(|source| source.lineage));
            let expect = e.live.as_ref().map_or(ENTRY_OVERHEAD, Live::charge);
            assert_eq!(e.charged, expect);
            sum += e.charged;
            if let Some(l) = &e.live {
                assert!(l.ecn != 0 && l.ecn <= 15 && (l.ecn == 1 || l.ecn & 1 == 0));
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
fn insert_range(
    ranges: &mut Vec<(usize, usize)>,
    at: usize,
    start: usize,
    end: usize,
    join_prev: bool,
    join_next: bool,
) {
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

    mod ecn;
    mod expiry;
    mod ownership;

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
            Push::Complete(r) => r.packet.to_vec(),
            other => panic!("expected a complete datagram, got {other:?}"),
        }
    }

    fn pending(r: Push) {
        assert!(matches!(r, Push::Pending(_)), "{r:?}");
    }

    fn push(r: &mut Reassembler, now: Instant, packet: &[u8]) -> Push {
        match frag::parse(packet) {
            Ok(fragment) => r.push(now, fragment, None),
            Err(e) => Push::Dropped(e.into()),
        }
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
                        let res = push(&mut r, t, &frags[i]);
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
            pending(push(&mut r, t, &f[0]));
            pending(push(&mut r, t, &f[1]));
            assert!(r.bytes() > 0);
            assert!(matches!(
                push(&mut r, t, &g[1]),
                Push::Dropped(DropReason::Fragment)
            ));
            assert_eq!(r.stats.overlaps, 1);
            // Buffer is freed immediately; only the tombstone remains.
            assert_eq!(r.len(), 1);
            assert_eq!(r.bytes(), ENTRY_OVERHEAD);
            // Later fragments, even valid ones, never complete it.
            for p in &f[2..] {
                assert!(matches!(
                    push(&mut r, t, p),
                    Push::Dropped(DropReason::Fragment)
                ));
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
        pending(push(&mut r, t, &f[0]));
        assert!(matches!(
            push(&mut r, t, &f[0]),
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
            pending(push(&mut r, t, &f[1]));
            pending(push(&mut r, t, &f[2]));
            assert_eq!(r.poll_timeout(), Some(late));
            r.expire(late - Duration::from_millis(1));
            assert_eq!(r.len(), 1, "not yet");
            r.expire(late);
            assert!(!r.pending_icmp(), "no fragment 0, no Time Exceeded");
            assert!(matches!(
                r.poll_icmp(late, &mut icmp, &mut out, &mut Transmit::plain(0)),
                Output::None
            ));
            r.assert_idle();

            // With fragment 0: Time Exceeded code 1 to the sender, quoting the first fragment.
            let mut r = Reassembler::default();
            pending(push(&mut r, t, &f[0]));
            pending(push(&mut r, t, &f[2]));
            r.expire(late);
            let Output::Sent(n) = r.poll_icmp(late, &mut icmp, &mut out, &mut Transmit::plain(0))
            else {
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
                r.poll_icmp(late, &mut icmp, &mut out, &mut Transmit::plain(0)),
                Output::None
            ));
            r.assert_idle();
        }
    }

    #[test]
    fn rejected_iov_timeout_keeps_quote_and_limiter_until_retry() {
        use std::io::ErrorKind::{BrokenPipe, WouldBlock};

        let now = Instant::now();
        for (src, dst) in families() {
            let budget = MemoryBudget::new(64 * 1024);
            let mut r = Reassembler::default().with_budget(Some(Arc::clone(&budget)));
            let source = Some(SourceContext {
                lineage: NonZeroU64::MIN,
                snapshot: NonZeroU64::MIN,
            });
            let first = datagram(src, dst, 3000, 3);
            let reversed = datagram(dst, src, 3000, 4);
            for (id, whole) in [(8, &first), (9, &first), (10, &reversed)] {
                let f = split(whole, id, 1000);
                pending(r.push(now, frag::parse(&f[0]).unwrap(), source));
            }
            let late = now + r.limits.timeout;
            r.expire(late);
            assert_eq!(r.stats.timeouts, 3);
            let order = |r: &Reassembler| r.expired.iter().map(|q| q.fragment).collect::<Vec<_>>();
            let queued = order(&r);
            let quote = &r.expired[0].bytes;
            let charge = quote.capacity();
            let retained = quote.as_ptr();
            let mut expected = [0; 1500];
            let IcmpEmit::Sent(len) =
                IcmpOut::default().emit(late, Reject::TimeExceeded, quote, &mut expected)
            else {
                panic!("expected Time Exceeded");
            };
            let mut icmp = IcmpOut::new(crate::IcmpLimits {
                target_burst: 1,
                ..crate::IcmpLimits::default()
            });
            let no_emit =
                &mut |_: &[u8], _: &[&[u8]], _: Transmit| -> Result<(), std::io::ErrorKind> {
                    panic!("quote maintenance must not offer a packet")
                };
            let epoch = budget.release_epoch();
            assert_eq!(budget.used(), 3 * charge);
            assert!(matches!(
                r.poll_icmp_iov(late, &mut icmp, len - 1, no_emit),
                Ok((IovTransmit::BufferTooSmall, None)),
            ));
            assert!(matches!(
                r.poll_icmp_iov(late, &mut icmp, len, no_emit),
                Ok((IovTransmit::Progress, None)),
            ));
            assert_eq!(order(&r), queued);
            assert_eq!((budget.used(), budget.release_epoch()), (3 * charge, epoch));
            let limiter = icmp.limiter_snapshot();
            let tx = Transmit {
                source,
                ..Transmit::plain(len)
            };
            let check = |h: &[u8], parts: &[&[u8]], offered: Transmit| {
                assert_eq!(parts.len(), 1);
                assert_eq!(parts[0].as_ptr(), retained);
                assert_eq!(offered, tx);
                assert_eq!([h, parts[0]].concat(), expected[..len]);
            };
            for failure in [WouldBlock, BrokenPipe] {
                let result = r.poll_icmp_iov(late, &mut icmp, len, &mut |h, p, t| {
                    check(h, p, t);
                    Err(failure)
                });
                assert_eq!(result.unwrap_err(), failure);
                assert_eq!(order(&r), queued);
                assert_eq!(r.bytes(), 3 * charge);
                assert_eq!((budget.used(), budget.release_epoch()), (3 * charge, epoch));
                assert_eq!(icmp.limiter_snapshot(), limiter);
                assert_eq!((icmp.sent, icmp.suppressed, icmp.rate_limited), (0, 0, 0));
            }
            let result = r.poll_icmp_iov(late, &mut icmp, len, &mut |h, p, t| {
                check(h, p, t);
                Ok::<_, std::io::ErrorKind>(())
            });
            assert!(
                matches!(result, Ok((IovTransmit::Packet(sent), Some(info))) if sent == tx && info == queued[0])
            );
            assert_eq!(order(&r), queued[1..]);
            assert_eq!(
                (budget.used(), budget.release_epoch()),
                (2 * charge, epoch + 1)
            );

            assert!(matches!(
                r.poll_icmp_iov(late, &mut icmp, len, no_emit),
                Ok((IovTransmit::Progress, None)),
            ));
            assert_eq!(order(&r), queued[2..]);
            assert_eq!((budget.used(), budget.release_epoch()), (charge, epoch + 2));
            assert_eq!((icmp.sent, icmp.suppressed, icmp.rate_limited), (1, 0, 1));
            let result = r.poll_icmp_iov(late, &mut icmp, len, &mut |_, _, _| {
                Ok::<_, std::io::ErrorKind>(())
            });
            assert!(
                matches!(result, Ok((IovTransmit::Packet(_), Some(info))) if info == queued[2])
            );
            assert_eq!((budget.used(), budget.release_epoch()), (0, epoch + 3));
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
        pending(push(&mut r, t, &victim[0]));
        for id in 0..8u32 {
            let f = split(&datagram(src, dst, 2000, 2), id, 800);
            pending(push(&mut r, t, &f[0]));
            assert!(r.len() <= 4);
            r.check();
        }
        assert_eq!(r.stats.evicted, 5);
        // The victim was evicted: its remaining fragments restart a datagram and cannot finish it.
        pending(push(&mut r, t, &victim[2]));
        pending(push(&mut r, t, &victim[1]));
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
            pending(push(&mut r, t, f.last().unwrap()));
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
        assert!(matches!(
            push(&mut tiny, t, f.last().unwrap()),
            Push::Dropped(_)
        ));
        tiny.check();
    }

    #[test]
    fn bytes_are_charged_to_the_shared_budget_and_refunded_on_every_exit() {
        let t = Instant::now();
        let (src, dst) = families()[0];
        let budget = MemoryBudget::new(150_000);
        let mut r = Reassembler::default().with_budget(Some(budget.clone()));
        let held = |r: &Reassembler, other: usize| {
            assert_eq!(budget.used(), r.bytes() + other);
            r.bytes()
        };
        let f = split(&datagram(src, dst, 3000, 1), 1, 1000);
        // Completion refunds everything.
        pending(push(&mut r, t, &f[1]));
        assert!(held(&r, 0) > 3000 - 1000);
        pending(push(&mut r, t, &f[0]));
        pending(push(&mut r, t, &f[2]));
        let live = r.entries[0].live.as_ref().unwrap();
        assert!(live.data.capacity() >= live.data.len());
        assert_eq!(budget.used(), live.charge());
        complete(push(&mut r, t, &f[3]));
        assert_eq!(held(&r, 0), 0);
        // A killed datagram keeps only its tombstone, which expiry then refunds.
        pending(push(&mut r, t, &f[0]));
        assert!(matches!(push(&mut r, t, &f[0]), Push::Dropped(_)));
        assert_eq!(held(&r, 0), ENTRY_OVERHEAD);
        r.expire(t + Duration::from_secs(30));
        assert_eq!(held(&r, 0), 0);
        // Another stack holds most of the budget: eviction makes room, refusal drops the rest.
        let hog = budget.try_charge(100_000);
        assert!(hog);
        for id in 0..3u32 {
            let f = split(&datagram(src, dst, 20_000, 2), id, 1400);
            pending(push(&mut r, t, f.last().unwrap()));
            assert!(budget.used() <= budget.limit());
            held(&r, 100_000);
        }
        assert_eq!((r.len(), r.stats.evicted), (2, 1));
        let f = split(&datagram(src, dst, 64_000, 3), 9, 1400);
        assert!(matches!(
            push(&mut r, t, f.last().unwrap()),
            Push::Dropped(_)
        ));
        assert!(budget.used() <= budget.limit());
        r.check();
        drop(r);
        assert_eq!(
            budget.used(),
            100_000,
            "dropping the table refunds its bytes"
        );
        budget.refund(100_000);
        assert_eq!(budget.used(), 0);
        for limits in [
            FragmentLimits {
                max_entries: 0,
                ..FragmentLimits::default()
            },
            FragmentLimits {
                max_bytes: ENTRY_OVERHEAD - 1,
                ..FragmentLimits::default()
            },
        ] {
            let mut r = Reassembler::new(limits).with_budget(Some(budget.clone()));
            assert!(matches!(
                push(&mut r, t, &f[0]),
                Push::Dropped(DropReason::Capacity)
            ));
            r.assert_idle();
            assert_eq!(budget.used(), 0, "no charge for a refused entry");
        }
    }

    #[test]
    fn sequential_fragments_bound_growth_and_copy_extent() {
        let now = Instant::now();
        let (src, dst) = families()[0];
        let bytes = datagram(src, dst, 65_507, 9);
        let parts = split(&bytes, 41, 512);
        let budget = MemoryBudget::new(140_000);
        let mut r = Reassembler::default().with_budget(Some(budget.clone()));
        let (mut capacity, mut extent, mut growths, mut copy_bound) = (0, 0, 0, 0);
        for packet in &parts[..parts.len() - 1] {
            pending(push(&mut r, now, packet));
            let live = r.entries[0].live.as_ref().unwrap();
            if live.data.capacity() != capacity {
                growths += 1;
                copy_bound += extent;
                capacity = live.data.capacity();
            }
            extent = live.data.len();
            assert_eq!(budget.used(), live.charge());
        }
        assert!(
            growths <= 5 && copy_bound <= 65_536,
            "{growths} growths, {copy_bound} bytes"
        );
        let actual = complete(push(&mut r, now, parts.last().unwrap()));
        // IPv4 identification changes during fragmentation.
        assert_eq!(&actual[20..], &bytes[20..]);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn exact_fragment_growth_preserves_other_datagrams_and_funds_completion() {
        let now = Instant::now();
        let (src, dst) = families()[0];
        let bytes = datagram(src, dst, 2000, 7);
        let first = split(&bytes, 1, 1000);
        let second = split(&bytes, 2, 1000);
        let budget = MemoryBudget::new(6200);
        let mut r = Reassembler::default().with_budget(Some(budget.clone()));
        pending(push(&mut r, now, &first[0]));
        let live = r.entries[0].live.as_ref().unwrap();
        assert!(live.data.capacity() > live.data.len());
        pending(push(&mut r, now, &second[0]));
        let live = r.entries[1].live.as_ref().unwrap();
        assert_eq!(live.data.capacity(), live.data.len());
        assert_eq!(r.stats.evicted, 0);
        r.expire(now + Duration::from_secs(31));
        drop(r);
        assert_eq!(budget.used(), 0);
        let budget = MemoryBudget::new(4500);
        let mut r = Reassembler::default().with_budget(Some(budget.clone()));
        pending(push(&mut r, now, &first[0]));
        pending(push(&mut r, now, &first[1]));
        let actual = complete(push(&mut r, now, &first[2]));
        assert_eq!(&actual[20..], &bytes[20..]);
        assert_eq!(budget.used(), 0);
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
            if matches!(push(&mut r, t, p), Push::Dropped(DropReason::Fragment)) {
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
                push(&mut r, t, &short[0]),
                Push::Dropped(DropReason::Malformed)
            ));
            // Fragment past the end of the datagram announced by the last fragment.
            pending(push(&mut r, t, f.last().unwrap()));
            let longer = split(&datagram(src, dst, 5000, 7), 1, 1000);
            assert!(matches!(
                push(&mut r, t, &longer[4]),
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
                push(&mut Reassembler::default(), t, &huge),
                Push::Dropped(DropReason::Malformed)
            ));
            // Truncated and corrupt headers.
            assert!(matches!(
                push(&mut Reassembler::default(), t, &f[0][..30]),
                Push::Dropped(_)
            ));
            if src.is_ipv4() {
                let mut bad = f[0].clone();
                bad[11] ^= 1;
                assert!(matches!(
                    push(&mut Reassembler::default(), t, &bad),
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
        let got = complete(push(&mut r, t, &atomic[0]));
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
        pending(push(&mut r, t, &frags[3]));
        pending(push(&mut r, t, &frags[2]));
        pending(push(&mut r, t, &frags[0]));
        let got = complete(push(&mut r, t, &frags[1]));
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
                    pending(push(&mut r, t, p));
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
