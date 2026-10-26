//! In-tree splitmix64. No `rand` dependency: the simulator's determinism must not depend on an
//! external crate's stream-stability promises.

#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        mix(self.0)
    }

    /// `p <= 0` never fires and `p >= 1` always fires, exactly.
    pub fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            return false;
        }
        if p >= 1.0 {
            return true;
        }
        // 53 high bits give a uniform f64 in [0, 1).
        ((self.next_u64() >> 11) as f64) < p * (1u64 << 53) as f64
    }

    /// Uniform in `[0, max]`.
    pub fn up_to(&mut self, max: u64) -> u64 {
        if max == u64::MAX {
            return self.next_u64();
        }
        // Modulo bias is below 2^-40 for the nanosecond ranges used here.
        self.next_u64() % (max + 1)
    }
}

/// The splitmix64 finalizer; also the stateless hash behind the payload pattern.
pub fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
