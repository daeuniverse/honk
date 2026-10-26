//! Chunk pool and the byte rings that live on it (design §5).
//!
//! Payload reservations are whole chunks; descriptor reservations use their allocated
//! capacity. Each admitted flow reserves its progress floor before using shared space.

use std::collections::VecDeque;

pub const CHUNK: usize = 16 * 1024;
const FREE_CACHE: usize = 64;

pub type Chunk = Box<[u8]>;

pub struct Pool {
    free: Vec<Chunk>,
    shared_limit: usize,
    shared_used: usize,
    live: usize,
    metadata: usize,
    total_limit: usize,
}

impl Pool {
    #[cfg(test)]
    pub fn new(shared_limit_chunks: usize) -> Pool {
        Self::with_limits(shared_limit_chunks * CHUNK, usize::MAX)
    }

    pub fn with_limits(shared_limit_bytes: usize, total_limit: usize) -> Pool {
        Pool {
            free: Vec::new(),
            shared_limit: shared_limit_bytes,
            shared_used: 0,
            live: 0,
            metadata: 0,
            total_limit,
        }
    }

    pub fn reserve(&mut self, chunks: usize) -> bool {
        self.reserve_bytes(chunks * CHUNK)
    }

    pub fn reserve_bytes(&mut self, bytes: usize) -> bool {
        if bytes > self.shared_limit.saturating_sub(self.shared_used) {
            return false;
        }
        self.shared_used += bytes;
        true
    }

    pub fn release(&mut self, chunks: usize) {
        self.release_bytes(chunks * CHUNK);
    }

    pub fn release_bytes(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.shared_used);
        self.shared_used = self.shared_used.saturating_sub(bytes);
    }

    pub fn shared_free(&self) -> usize {
        (self.shared_limit - self.shared_used) / CHUNK
    }

    #[cfg(test)]
    pub fn shared_used(&self) -> usize {
        self.shared_used / CHUNK
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
            (self.shared_used, self.live, self.metadata),
            (0, 0, 0),
            "pool charges leaked"
        );
        assert!(self.free.len() <= FREE_CACHE);
    }

    pub fn allocated_bytes(&self) -> usize {
        (self.live + self.free.len()) * CHUNK + self.metadata
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
            .unwrap_or_else(|| vec![0u8; CHUNK].into_boxed_slice())
    }

    pub fn free(&mut self, chunk: Chunk) {
        self.live -= 1;
        if self.free.len() < FREE_CACHE {
            self.free.push(chunk);
        }
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

    pub fn tail_room(&self) -> usize {
        if self.chunks.is_empty() {
            CHUNK
        } else {
            self.chunks.len() * CHUNK - self.head - self.len
        }
    }

    pub fn write(&mut self, pool: &mut Pool, data: &[u8]) -> usize {
        let mut done = 0;
        while done < data.len() {
            let end = self.head + self.len;
            let (ci, co) = (end / CHUNK, end % CHUNK);
            if ci == self.chunks.len() {
                // The first chunk is the free floor; later ones are shared.
                if !self.chunks.is_empty() && !pool.reserve(1) {
                    break;
                }
                self.chunks.push_back(pool.alloc());
            }
            let n = (CHUNK - co).min(data.len() - done);
            self.chunks[ci][co..co + n].copy_from_slice(&data[done..done + n]);
            done += n;
            self.len += n;
        }
        done
    }

    /// A maximum-size IP packet spans at most five 16 KiB chunks, including an
    /// unaligned first chunk. The unused array slots never reach the checksum loop.
    pub fn slices(&self, off: usize, len: usize) -> ([&[u8]; 5], usize) {
        debug_assert!(off + len <= self.len && len <= usize::from(u16::MAX));
        let mut parts: [&[u8]; 5] = [&[]; 5];
        let mut pos = self.head + off;
        let (mut left, mut count) = (len, 0);
        while left != 0 {
            let (ci, co) = (pos / CHUNK, pos % CHUNK);
            let n = left.min(CHUNK - co);
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
            while self.chunks.len() > 1 {
                self.pop_front(pool);
            }
            self.head = 0;
            return;
        }
        while self.head >= CHUNK {
            self.pop_front(pool);
            self.head -= CHUNK;
        }
    }

    pub fn clear(&mut self, pool: &mut Pool) {
        while !self.chunks.is_empty() {
            self.pop_front(pool);
        }
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

    fn want_charge(&self, right: u32) -> usize {
        let span = self.head + right.wrapping_sub(self.rd_seq) as usize;
        span.div_ceil(CHUNK).saturating_sub(1)
    }

    pub fn limit_right(&self, pool: &Pool, want: u32) -> u32 {
        let capacity = (self.charged + 1 + pool.shared_free()) * CHUNK - self.head;
        self.rd_seq.wrapping_add(
            want.wrapping_sub(self.rd_seq)
                .min(capacity.min(u32::MAX as usize) as u32),
        )
    }

    /// Reserve shared chunks so the window may extend to `right`.
    pub fn grow(&mut self, pool: &mut Pool, right: u32) -> bool {
        let want = self.want_charge(right);
        if want > self.charged {
            if !pool.reserve(want - self.charged) {
                return false;
            }
            self.charged = want;
        }
        true
    }

    pub fn shrink(&mut self, pool: &mut Pool, right: u32) {
        let want = self.want_charge(right);
        if want < self.charged {
            pool.release(self.charged - want);
            self.charged = want;
        }
    }

    /// `seq` must be inside the committed window.
    pub fn write_at(&mut self, pool: &mut Pool, seq: u32, data: &[u8]) {
        let mut pos = self.head + seq.wrapping_sub(self.rd_seq) as usize;
        let mut rest = data;
        while !rest.is_empty() {
            let (ci, co) = (pos / CHUNK, pos % CHUNK);
            while self.chunks.len() <= ci {
                self.chunks.push_back(None);
            }
            let chunk = self.chunks[ci].get_or_insert_with(|| pool.alloc());
            let n = (CHUNK - co).min(rest.len());
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
            let n = (CHUNK - self.head).min(want - done);
            out[done..done + n].copy_from_slice(&chunk[self.head..self.head + n]);
            done += n;
            self.head += n;
            if self.head == CHUNK {
                if let Some(Some(c)) = self.chunks.pop_front() {
                    pool.free(c);
                }
                self.head = 0;
            }
        }
        self.rd_seq = self.rd_seq.wrapping_add(done as u32);
        done
    }

    /// Retain the lazy floor once used: request/response traffic must not allocate a
    /// fresh chunk every time the application drains its ring.
    pub fn compact(&mut self, pool: &mut Pool, right: u32) {
        let retained = self
            .chunks
            .pop_front()
            .flatten()
            .unwrap_or_else(|| pool.alloc());
        while let Some(c) = self.chunks.pop_front() {
            if let Some(c) = c {
                pool.free(c);
            }
        }
        self.chunks.push_back(Some(retained));
        self.head = 0;
        self.shrink(pool, right);
    }

    pub fn release_all(&mut self, pool: &mut Pool) {
        while let Some(c) = self.chunks.pop_front() {
            if let Some(c) = c {
                pool.free(c);
            }
        }
        pool.release(self.charged);
        self.charged = 0;
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
        assert_eq!((pool.shared_used(), pool.live_chunks()), (0, 1));
        ring.clear(&mut pool);
        assert_eq!(pool.live_chunks(), 0);
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
    fn recv_ring_compact_retains_only_the_progress_floor() {
        let mut pool = Pool::new(8);
        let mut ring = RecvRing::new(5);
        let right = 5 + 2 * CHUNK as u32;
        assert!(ring.grow(&mut pool, right));
        ring.write_at(&mut pool, 5, &pattern(10, 4));
        let mut out = [0u8; 10];
        assert_eq!(ring.read(&mut pool, &mut out, 10), 10);
        ring.compact(&mut pool, right + 10);
        assert_eq!(pool.live_chunks(), 1);
        assert_eq!(ring.charged(), 1);
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
        assert_eq!(pool.allocated_bytes(), 2 * CHUNK);
    }
}
