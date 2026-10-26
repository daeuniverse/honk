//! RFC 1071 Internet checksum with a 64-bit accumulator.
//!
//! 2^16 ≡ 1 (mod 0xFFFF), so summing big-endian 64-bit words with end-around carry and
//! folding once at the end equals the 16-bit one's-complement sum.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Default)]
pub struct Checksum {
    acc: u64,
    /// High byte of a 16-bit word whose low byte arrives in the next `add`.
    odd: Option<u8>,
}

impl Checksum {
    pub fn new() -> Self {
        Self::default()
    }

    fn accumulate(&mut self, v: u64) {
        let (s, carry) = self.acc.overflowing_add(v);
        self.acc = s + u64::from(carry);
    }

    fn tail(&mut self, rem: &[u8]) {
        let (pairs, rem) = rem.as_chunks::<2>();
        for &p in pairs {
            self.accumulate(u64::from(u16::from_be_bytes(p)));
        }
        self.odd = rem.first().copied();
    }

    fn complete_odd(&mut self, lo: u8) {
        if let Some(hi) = self.odd.take() {
            self.accumulate(u64::from(u16::from_be_bytes([hi, lo])));
        }
    }

    pub fn add(&mut self, mut data: &[u8]) {
        if self.odd.is_some() {
            let Some((&lo, rest)) = data.split_first() else {
                return;
            };
            self.complete_odd(lo);
            data = rest;
        }
        let (chunks, rem) = data.as_chunks::<8>();
        for &c in chunks {
            self.accumulate(u64::from_be_bytes(c));
        }
        self.tail(rem);
    }

    /// Must only be called at an even stream offset (no pending odd byte); for pseudo headers.
    pub fn add_u16(&mut self, v: u16) {
        debug_assert!(self.odd.is_none());
        self.accumulate(u64::from(v));
    }

    /// Must only be called at an even stream offset (no pending odd byte); for pseudo headers.
    pub fn add_u32(&mut self, v: u32) {
        debug_assert!(self.odd.is_none());
        self.accumulate(u64::from(v));
    }

    /// Copies `src` into `dst` while summing it, with the same odd-byte carry as [`add`](Self::add).
    pub fn copy_add(&mut self, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        let mut off = 0;
        if self.odd.is_some() {
            let Some(&lo) = src.first() else {
                return;
            };
            dst[0] = lo;
            self.complete_odd(lo);
            off = 1;
        }
        let (d, dst_rem) = dst[off..].as_chunks_mut::<8>();
        let (s, rem) = src[off..].as_chunks::<8>();
        for (dc, &sc) in d.iter_mut().zip(s) {
            *dc = sc;
            self.accumulate(u64::from_be_bytes(sc));
        }
        dst_rem.copy_from_slice(rem);
        self.tail(rem);
    }

    /// Folded and complemented; a packet that carries its own checksum finishes as 0.
    pub fn finish(self) -> u16 {
        let mut c = self;
        if let Some(hi) = c.odd.take() {
            c.accumulate(u64::from(hi) << 8);
        }
        let mut a = c.acc;
        while a >> 16 != 0 {
            a = (a & 0xFFFF) + (a >> 16);
        }
        !(a as u16)
    }

    /// Callers must pass addresses of one family; a mismatch is a bug, not input.
    pub fn pseudo(src: IpAddr, dst: IpAddr, proto: u8, upper_len: usize) -> Checksum {
        debug_assert_eq!(src.is_ipv4(), dst.is_ipv4());
        let mut c = Checksum::new();
        for a in [src, dst] {
            match a {
                IpAddr::V4(a) => c.add(&a.octets()),
                IpAddr::V6(a) => c.add(&a.octets()),
            }
        }
        if src.is_ipv4() {
            c.add_u16(u16::from(proto));
            c.add_u16(upper_len as u16);
        } else {
            c.add_u32(upper_len as u32);
            c.add_u32(u32::from(proto));
        }
        c
    }
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut c = Checksum::new();
    c.add(data);
    c.finish()
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;

    #[test]
    fn rfc1071_example() {
        // RFC 1071 §3: words 0001 f203 f4f5 f6f7 sum to ddf2 (one's complement), checksum 220d.
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
    }

    #[test]
    fn empty_and_all_ff() {
        assert_eq!(checksum(&[]), 0xFFFF);
        assert_eq!(checksum(&[0xFF; 2]), 0);
        assert_eq!(checksum(&[0xFF; 3]), 0x00FF);
    }

    #[test]
    fn odd_single_byte_is_high_byte() {
        assert_eq!(checksum(&[0x12]), !0x1200);
    }

    #[test]
    fn huge_ff_buffer_carries_many_times() {
        for len in [1usize << 20, (1 << 20) + 5, 8 * 1000 + 3] {
            let data = vec![0xFF; len];
            assert_eq!(checksum(&data), naive_checksum(&data), "len {len}");
        }
    }

    #[test]
    fn random_lengths_and_splits_match_naive() {
        let mut rng = Rng::new(0xC0FFEE);
        for len in 0..300 {
            let data = rng.bytes(len);
            let want = naive_checksum(&data);
            assert_eq!(checksum(&data), want, "one-shot len {len}");
            for _ in 0..8 {
                let mut c = Checksum::new();
                let mut rest = &data[..];
                while !rest.is_empty() {
                    let n = 1 + rng.below(rest.len());
                    c.add(&rest[..n]);
                    rest = &rest[n..];
                    if rng.below(4) == 0 {
                        c.add(&[]);
                    }
                }
                assert_eq!(c.finish(), want, "split len {len}");
            }
        }
    }

    #[test]
    fn copy_add_copies_and_matches_add() {
        let mut rng = Rng::new(7);
        for len in 0..200 {
            let data = rng.bytes(len);
            let want = naive_checksum(&data);
            let mut out = vec![0u8; len];
            let mut c = Checksum::new();
            c.copy_add(&mut out, &data);
            assert_eq!(out, data);
            assert_eq!(c.finish(), want, "len {len}");

            let cut = if len == 0 { 0 } else { rng.below(len + 1) };
            let mut out = vec![0u8; len];
            let mut c = Checksum::new();
            let (a, b) = data.split_at(cut);
            let (oa, ob) = out.split_at_mut(cut);
            c.copy_add(oa, a);
            c.copy_add(ob, b);
            assert_eq!(out, data);
            assert_eq!(c.finish(), want, "split {cut}/{len}");
        }
    }

    #[test]
    fn copy_add_mixed_with_add_across_odd_boundary() {
        let data: Vec<u8> = (0..41).collect();
        let want = naive_checksum(&data);
        let mut out = [0u8; 20];
        let mut c = Checksum::new();
        c.add(&data[..21]);
        c.copy_add(&mut out, &data[21..]);
        assert_eq!(&out[..], &data[21..]);
        assert_eq!(c.finish(), want);
    }

    #[test]
    fn packet_with_own_checksum_sums_to_zero() {
        let mut rng = Rng::new(99);
        for len in [0usize, 1, 2, 19, 20, 21, 64, 255] {
            let mut data = vec![0, 0];
            data.extend_from_slice(&rng.bytes(len));
            let ck = checksum(&data);
            data[..2].copy_from_slice(&ck.to_be_bytes());
            assert_eq!(checksum(&data), 0, "len {len}");
        }
    }

    #[test]
    fn pseudo_matches_byte_level_reference() {
        for (src, dst) in [
            (v4(192, 168, 1, 1), v4(8, 8, 8, 8)),
            (v6(0x1234), v6(0xabcd)),
        ] {
            for len in [0usize, 1, 20, 1500, 65_535] {
                let mut want = pseudo_bytes(src, dst, 6, len);
                want.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
                let mut c = Checksum::pseudo(src, dst, 6, len);
                c.add(&[0xAB, 0xCD, 0xEF]);
                assert_eq!(c.finish(), naive_checksum(&want), "{src} len {len}");
            }
        }
    }
}
