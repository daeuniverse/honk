//! Chunk pool and the byte rings that live on it (design §5).
//!
//! Payload reservations are whole chunks; descriptor reservations use their allocated
//! capacity. Each admitted flow reserves its progress floor before using shared space.

use std::collections::VecDeque;
use std::sync::Arc;

use crate::budget::MemoryBudget;

/// Endpoint-mode chunk size and the default of a [`Pool`] built without [`Pool::with_chunk`].
pub const CHUNK: usize = 16 * 1024;
/// Transparent-mode default: with many small client flows a 4 KiB chunk keeps the per-flow floor
/// (accounting only, an idle flow holds no chunk) near 9 KiB.
pub const TRANSPARENT_CHUNK: usize = 4 * 1024;
/// Smallest and largest configurable chunk.
pub const MIN_CHUNK: usize = 4 * 1024;
pub const MAX_CHUNK: usize = 64 * 1024;
/// Payload slices a maximum-size (64 KiB) IP packet can span at the smallest chunk, including an
/// unaligned first chunk.
pub const MAX_PARTS: usize = 65536 / MIN_CHUNK + 2;

/// What admission reserves for one TCP flow: a TX and an RX chunk and the descriptor floor.
pub const fn floor(chunk: usize) -> usize {
    2 * chunk + super::sent::FLOOR_BYTES
}

/// A configured chunk size, clamped to `[MIN_CHUNK, MAX_CHUNK]`.
pub fn clamp_chunk(chunk: usize) -> usize {
    chunk.clamp(MIN_CHUNK, MAX_CHUNK)
}

/// Free chunks kept for reuse at most, so a bulk flow does not return a chunk to the allocator and
/// take one back for every 16 KiB. An idle pool keeps one (see `free`).
const FREE_CACHE: usize = 64;
/// Chunk-list slots an emptied ring keeps, so a flow draining a few chunks per batch does not
/// reallocate its list each time; a ring that once held a whole window gives the rest back.
const KEEP_SLOTS: usize = 4;

fn trim<T>(chunks: &mut VecDeque<T>) {
    if chunks.capacity() > KEEP_SLOTS {
        chunks.shrink_to(KEEP_SLOTS);
    }
}

/// `Box<[u8]>` of the pool's chunk size.
pub type Chunk = Box<[u8]>;

pub struct Pool {
    chunk: usize,
    free: Vec<Chunk>,
    shared_limit: usize,
    shared_used: usize,
    live: usize,
    metadata: usize,
    total_limit: usize,
    /// Process-wide budget, charged for floors and shared reservations next to this pool's own
    /// limits; `held` is what this pool owes it back.
    budget: Option<Arc<MemoryBudget>>,
    held: usize,
}

impl Pool {
    #[cfg(test)]
    pub fn new(shared_limit_chunks: usize) -> Pool {
        Self::with_limits(shared_limit_chunks * CHUNK, usize::MAX)
    }

    pub fn with_limits(shared_limit_bytes: usize, total_limit: usize) -> Pool {
        Pool {
            chunk: CHUNK,
            free: Vec::new(),
            shared_limit: shared_limit_bytes,
            shared_used: 0,
            live: 0,
            metadata: 0,
            total_limit,
            budget: None,
            held: 0,
        }
    }

    pub fn with_budget(mut self, budget: Option<Arc<MemoryBudget>>) -> Pool {
        self.budget = budget;
        self
    }

    /// Chunk size for every chunk this pool hands out; call before the first allocation.
    pub fn with_chunk(mut self, chunk: usize) -> Pool {
        self.chunk = chunk;
        self
    }

    pub fn chunk(&self) -> usize {
        self.chunk
    }

    pub fn floor(&self) -> usize {
        floor(self.chunk)
    }

    /// Charges one flow's floor to the process budget (the pool's own floors are carved out of
    /// its limit up front). Pair with `release_floor` when the flow retires.
    pub fn admit_floor(&mut self) -> bool {
        self.charge(self.floor())
    }

    pub fn release_floor(&mut self) {
        self.refund(self.floor());
    }

    fn charge(&mut self, bytes: usize) -> bool {
        if let Some(b) = &self.budget {
            if !b.try_charge(bytes) {
                return false;
            }
            self.held += bytes;
        }
        true
    }

    fn refund(&mut self, bytes: usize) {
        if let Some(b) = &self.budget {
            debug_assert!(bytes <= self.held);
            b.refund(bytes);
            self.held -= bytes;
        }
    }

    pub fn reserve(&mut self, chunks: usize) -> bool {
        self.reserve_bytes(chunks * self.chunk)
    }

    pub fn reserve_bytes(&mut self, bytes: usize) -> bool {
        if bytes > self.shared_limit.saturating_sub(self.shared_used) || !self.charge(bytes) {
            return false;
        }
        self.shared_used += bytes;
        true
    }

    pub fn release(&mut self, chunks: usize) {
        self.release_bytes(chunks * self.chunk);
    }

    pub fn release_bytes(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.shared_used);
        let bytes = bytes.min(self.shared_used);
        self.shared_used -= bytes;
        self.refund(bytes);
    }

    pub fn shared_free(&self) -> usize {
        let own = self.shared_limit - self.shared_used;
        self.budget.as_ref().map_or(own, |b| own.min(b.available())) / self.chunk
    }

    #[cfg(test)]
    pub fn shared_used(&self) -> usize {
        self.shared_used / self.chunk
    }

    pub fn shared_bytes(&self) -> usize {
        self.shared_used
    }

    #[cfg(test)]
    pub fn live_chunks(&self) -> usize {
        self.live
    }

    /// Every reservation, chunk and descriptor charge has been returned.
    #[cfg(feature = "fuzz-checks")]
    pub fn assert_idle(&self) {
        assert_eq!(
            (self.shared_used, self.live, self.metadata, self.held),
            (0, 0, 0, 0),
            "pool charges leaked"
        );
        assert!(
            self.free.len() <= 1,
            "an idle pool caches one chunk at most"
        );
    }

    /// With a budget, this pool owes exactly its floors and shared reservations.
    #[cfg(feature = "fuzz-checks")]
    pub fn check_held(&self, floors: usize) {
        if self.budget.is_some() {
            assert_eq!(self.held, floors * self.floor() + self.shared_used);
        }
    }

    pub fn allocated_bytes(&self) -> usize {
        (self.live + self.free.len()) * self.chunk + self.metadata
    }

    pub fn metadata_grow(&mut self, bytes: usize) {
        self.metadata += bytes;
        while self.allocated_bytes() > self.total_limit && !self.free.is_empty() {
            self.free.pop();
        }
        debug_assert!(self.allocated_bytes() <= self.total_limit);
    }

    pub fn metadata_shrink(&mut self, bytes: usize) {
        self.metadata -= bytes;
    }

    pub fn alloc(&mut self) -> Chunk {
        self.live += 1;
        self.free
            .pop()
            .unwrap_or_else(|| vec![0u8; self.chunk].into_boxed_slice())
    }

    pub fn free(&mut self, chunk: Chunk) {
        self.live -= 1;
        // While anything is in use, bursts (a write of 64 packets, then its ACK) refill from the
        // cache. A pool with nothing in use keeps one spare, the chunk a request/response flow
        // takes back on its next segment, and returns the rest to the allocator.
        let cap = if self.live == 0 { 1 } else { FREE_CACHE };
        if self.free.len() < cap {
            self.free.push(chunk);
        }
        self.free.truncate(cap);
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.refund(self.held);
    }
}

/// Bytes from the oldest unacknowledged byte onward.
#[derive(Default)]
pub struct SendRing {
    chunks: VecDeque<Chunk>,
    head: usize,
    len: usize,
}

impl SendRing {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn tail_room(&self, pool: &Pool) -> usize {
        let chunk = pool.chunk();
        if self.chunks.is_empty() {
            chunk
        } else {
            self.chunks.len() * chunk - self.head - self.len
        }
    }

    pub fn write(&mut self, pool: &mut Pool, data: &[u8]) -> usize {
        let chunk = pool.chunk();
        let mut done = 0;
        while done < data.len() {
            let end = self.head + self.len;
            let (ci, co) = (end / chunk, end % chunk);
            if ci == self.chunks.len() {
                // The first chunk is the free floor; later ones are shared.
                if !self.chunks.is_empty() && !pool.reserve(1) {
                    break;
                }
                self.chunks.push_back(pool.alloc());
            }
            let n = (chunk - co).min(data.len() - done);
            self.chunks[ci][co..co + n].copy_from_slice(&data[done..done + n]);
            done += n;
            self.len += n;
        }
        done
    }

    /// A maximum-size IP packet spans at most [`MAX_PARTS`] chunks, including an unaligned first
    /// chunk. The unused array slots never reach the checksum loop.
    pub fn slices(&self, off: usize, len: usize) -> ([&[u8]; MAX_PARTS], usize) {
        debug_assert!(off + len <= self.len && len <= usize::from(u16::MAX));
        let mut parts: [&[u8]; MAX_PARTS] = [&[]; MAX_PARTS];
        let mut pos = self.head + off;
        let (mut left, mut count) = (len, 0);
        let chunk = self.chunks.front().map_or(1, |c| c.len());
        while left != 0 {
            let (ci, co) = (pos / chunk, pos % chunk);
            let n = left.min(chunk - co);
            parts[count] = &self.chunks[ci][co..co + n];
            count += 1;
            pos += n;
            left -= n;
        }
        (parts, count)
    }

    pub fn consume(&mut self, pool: &mut Pool, n: usize) {
        debug_assert!(n <= self.len);
        self.head += n;
        self.len -= n;
        if self.len == 0 {
            self.clear(pool);
            return;
        }
        let chunk = pool.chunk();
        while self.head >= chunk {
            self.pop_front(pool);
            self.head -= chunk;
        }
    }

    pub fn clear(&mut self, pool: &mut Pool) {
        while !self.chunks.is_empty() {
            self.pop_front(pool);
        }
        trim(&mut self.chunks);
        self.head = 0;
        self.len = 0;
    }

    fn pop_front(&mut self, pool: &mut Pool) {
        if self.chunks.len() > 1 {
            pool.release(1);
        }
        if let Some(c) = self.chunks.pop_front() {
            pool.free(c);
        }
    }

    #[cfg(test)]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

/// Covers `[rd_seq, right edge)`. Chunks are allocated when data lands in them, the
/// shared-pool charge follows the advertised right edge instead (window commitment).
pub struct RecvRing {
    chunks: VecDeque<Option<Chunk>>,
    head: usize,
    charged: usize,
    pub rd_seq: u32,
}

impl RecvRing {
    pub fn new(rd_seq: u32) -> RecvRing {
        RecvRing {
            chunks: VecDeque::new(),
            head: 0,
            charged: 0,
            rd_seq,
        }
    }

    fn want_charge(&self, chunk: usize, right: u32) -> usize {
        let span = self.head + right.wrapping_sub(self.rd_seq) as usize;
        span.div_ceil(chunk).saturating_sub(1)
    }

    pub fn limit_right(&self, pool: &Pool, want: u32) -> u32 {
        let capacity = (self.charged + 1 + pool.shared_free()) * pool.chunk() - self.head;
        self.rd_seq.wrapping_add(
            want.wrapping_sub(self.rd_seq)
                .min(capacity.min(u32::MAX as usize) as u32),
        )
    }

    /// Reserve shared chunks so the window may extend to `right`.
    pub fn grow(&mut self, pool: &mut Pool, right: u32) -> bool {
        let want = self.want_charge(pool.chunk(), right);
        if want > self.charged {
            if !pool.reserve(want - self.charged) {
                return false;
            }
            self.charged = want;
        }
        true
    }

    pub fn shrink(&mut self, pool: &mut Pool, right: u32) {
        let want = self.want_charge(pool.chunk(), right);
        if want < self.charged {
            pool.release(self.charged - want);
            self.charged = want;
        }
    }

    /// `seq` must be inside the committed window.
    pub fn write_at(&mut self, pool: &mut Pool, seq: u32, data: &[u8]) {
        let chunk_len = pool.chunk();
        let mut pos = self.head + seq.wrapping_sub(self.rd_seq) as usize;
        let mut rest = data;
        while !rest.is_empty() {
            let (ci, co) = (pos / chunk_len, pos % chunk_len);
            while self.chunks.len() <= ci {
                self.chunks.push_back(None);
            }
            let chunk = self.chunks[ci].get_or_insert_with(|| pool.alloc());
            let n = (chunk_len - co).min(rest.len());
            chunk[co..co + n].copy_from_slice(&rest[..n]);
            rest = &rest[n..];
            pos += n;
        }
    }

    /// Copies up to `avail` in-order bytes.
    pub fn read(&mut self, pool: &mut Pool, out: &mut [u8], avail: usize) -> usize {
        let want = out.len().min(avail);
        let mut done = 0;
        while done < want {
            let Some(Some(chunk)) = self.chunks.front() else {
                break;
            };
            let n = (chunk.len() - self.head).min(want - done);
            out[done..done + n].copy_from_slice(&chunk[self.head..self.head + n]);
            done += n;
            self.head += n;
            if self.head == chunk.len() {
                if let Some(Some(c)) = self.chunks.pop_front() {
                    pool.free(c);
                }
                self.head = 0;
            }
        }
        self.rd_seq = self.rd_seq.wrapping_add(done as u32);
        done
    }

    /// The ring is empty and holds nothing out of order: give every chunk back. The progress floor
    /// stays an accounting guarantee (admission), not resident memory; the pool's small free
    /// cache keeps request/response traffic from calling the allocator on every drain.
    pub fn compact(&mut self, pool: &mut Pool, right: u32) {
        self.free_chunks(pool);
        self.shrink(pool, right);
    }

    pub fn release_all(&mut self, pool: &mut Pool) {
        self.free_chunks(pool);
        pool.release(self.charged);
        self.charged = 0;
    }

    fn free_chunks(&mut self, pool: &mut Pool) {
        while let Some(c) = self.chunks.pop_front() {
            if let Some(c) = c {
                pool.free(c);
            }
        }
        trim(&mut self.chunks);
        self.head = 0;
    }

    pub fn charged(&self) -> usize {
        self.charged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn send_ring_roundtrip_across_chunks() {
        let mut pool = Pool::new(8);
        let mut ring = SendRing::default();
        let data = pattern(CHUNK * 2 + 100, 1);
        assert_eq!(ring.write(&mut pool, &data), data.len());
        assert_eq!(ring.chunk_count(), 3);
        assert_eq!(pool.shared_used(), 2, "first chunk is the free floor");
        let ([a, b, ..], count) = ring.slices(CHUNK - 10, 30);
        assert_eq!(count, 2);
        assert_eq!((a.len(), b.len()), (10, 20));
        assert_eq!([a, b].concat(), data[CHUNK - 10..CHUNK + 20]);
        ring.consume(&mut pool, CHUNK + 5);
        assert_eq!(ring.len(), data.len() - CHUNK - 5);
        assert_eq!(pool.shared_used(), 1);
        assert_eq!(ring.slices(0, 50).0[0], &data[CHUNK + 5..CHUNK + 55]);
        ring.consume(&mut pool, ring.len());
        assert_eq!(
            (pool.shared_used(), pool.live_chunks(), ring.chunk_count()),
            (0, 0, 0),
            "a fully acknowledged ring holds no chunk"
        );
    }

    #[test]
    fn send_ring_keeps_its_floor_accounting_across_a_drain() {
        let mut pool = Pool::new(2);
        let mut ring = SendRing::default();
        let data = pattern(CHUNK * 3, 5);
        for _ in 0..2 {
            assert_eq!(ring.write(&mut pool, &data), data.len());
            assert_eq!(pool.shared_used(), 2, "first chunk is the free floor");
            ring.consume(&mut pool, data.len());
            assert_eq!((pool.shared_used(), pool.live_chunks()), (0, 0));
        }
        assert_eq!(ring.tail_room(&pool), CHUNK);
    }

    #[test]
    fn send_ring_stops_when_shared_pool_is_empty() {
        let mut pool = Pool::new(1);
        let mut ring = SendRing::default();
        let data = pattern(CHUNK * 4, 2);
        assert_eq!(ring.write(&mut pool, &data), 2 * CHUNK);
        assert_eq!(ring.write(&mut pool, &data), 0);
    }

    #[test]
    fn recv_ring_ooo_write_then_inorder_read() {
        let mut pool = Pool::new(8);
        let mut ring = RecvRing::new(1000);
        let right = 1000 + 3 * CHUNK as u32;
        assert!(ring.grow(&mut pool, right));
        assert_eq!(ring.charged(), 2);
        let tail = pattern(100, 9);
        ring.write_at(&mut pool, 1000 + CHUNK as u32 + 50, &tail);
        assert_eq!(pool.live_chunks(), 1, "only the touched chunk is allocated");
        let head = pattern(CHUNK + 50, 3);
        ring.write_at(&mut pool, 1000, &head);
        let mut out = vec![0u8; CHUNK + 150];
        assert_eq!(ring.read(&mut pool, &mut out, CHUNK + 150), CHUNK + 150);
        assert_eq!(&out[..CHUNK + 50], &head[..]);
        assert_eq!(&out[CHUNK + 50..], &tail[..]);
        assert_eq!(ring.rd_seq, 1000 + CHUNK as u32 + 150);
        ring.shrink(&mut pool, right);
        assert_eq!(ring.charged(), 1);
    }

    #[test]
    fn recv_ring_compact_releases_every_chunk_and_keeps_the_charge_floor() {
        let mut pool = Pool::new(8);
        let mut ring = RecvRing::new(5);
        let right = 5 + 2 * CHUNK as u32;
        assert!(ring.grow(&mut pool, right));
        ring.write_at(&mut pool, 5, &pattern(10, 4));
        let mut out = [0u8; 10];
        assert_eq!(ring.read(&mut pool, &mut out, 10), 10);
        ring.compact(&mut pool, right + 10);
        assert_eq!(pool.live_chunks(), 0, "a drained ring holds no chunk");
        assert_eq!(ring.charged(), 1, "the window stays committed");
        ring.write_at(&mut pool, 15, &pattern(10, 5));
        assert_eq!(
            pool.live_chunks(),
            1,
            "the next segment allocates lazily again"
        );
        ring.release_all(&mut pool);
        assert_eq!((pool.live_chunks(), pool.shared_used()), (0, 0));
    }

    #[test]
    fn receive_floor_commits_all_sixteen_kib_without_shared_memory() {
        let mut pool = Pool::new(0);
        let mut ring = RecvRing::new(1000);
        let right = ring.limit_right(&pool, 1000 + u16::MAX as u32);
        assert_eq!(right, 1000 + CHUNK as u32);
        assert!(ring.grow(&mut pool, right));
        assert_eq!(pool.shared_used(), 0);
    }

    #[test]
    fn metadata_reclaims_cached_chunks_before_exceeding_truesize_budget() {
        let mut pool = Pool::with_limits(CHUNK, 3 * CHUNK);
        let a = pool.alloc();
        let b = pool.alloc();
        let c = pool.alloc();
        pool.free(c);
        assert_eq!(pool.allocated_bytes(), 3 * CHUNK);
        pool.metadata_grow(64);
        assert_eq!(pool.allocated_bytes(), 2 * CHUNK + 64);
        pool.free(a);
        pool.free(b);
        pool.metadata_shrink(64);
        assert_eq!(
            pool.allocated_bytes(),
            CHUNK,
            "an idle pool caches one chunk"
        );
    }

    #[test]
    fn free_cache_follows_the_chunks_in_use() {
        let mut pool = Pool::new(0);
        let chunks: Vec<Chunk> = (0..200).map(|_| pool.alloc()).collect();
        for c in chunks {
            pool.free(c);
        }
        assert_eq!(pool.live_chunks(), 0);
        assert_eq!(
            pool.allocated_bytes(),
            CHUNK,
            "drained pool keeps one spare"
        );
        let mut held: Vec<Chunk> = (0..40).map(|_| pool.alloc()).collect();
        let last = held.pop().unwrap();
        for c in held {
            pool.free(c);
        }
        assert_eq!(
            pool.allocated_bytes(),
            40 * CHUNK,
            "bursts refill from the cache while a chunk is in use"
        );
        pool.free(last);
        assert_eq!(pool.allocated_bytes(), CHUNK);
        // A refill after a drain is served from the cache, not the allocator.
        let c = pool.alloc();
        assert_eq!(pool.allocated_bytes(), CHUNK);
        pool.free(c);
    }
}
