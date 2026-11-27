use std::sync::atomic::{AtomicU64, Ordering};

/// A process-lifetime index domain, not packet-capture or routing authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScopeId(u64);

static LAST_SCOPE: AtomicU64 = AtomicU64::new(0);

impl ScopeId {
    /// The existing kernel datapath's reserved domain.
    pub const HOST: Self = Self(0);

    /// Returns the opaque domain value for downstream identity hashing.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Allocates a distinct domain that is never recycled in this process.
    /// Exhaustion is permanent and cannot issue the reserved host identity.
    pub fn allocate() -> Option<Self> {
        Self::allocate_from(&LAST_SCOPE)
    }

    fn allocate_from(last: &AtomicU64) -> Option<Self> {
        last.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .ok()
        .map(|value| Self(value + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn concurrent_allocations_never_share_a_domain() {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    (0..128)
                        .map(|_| ScopeId::allocate().unwrap())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut issued = HashSet::new();
        for worker in workers {
            for scope in worker.join().unwrap() {
                assert_ne!(scope, ScopeId::HOST);
                assert!(issued.insert(scope));
            }
        }
        assert_eq!(issued.len(), 1024);
    }

    #[test]
    fn exhaustion_never_wraps_or_recycles() {
        let last = AtomicU64::new(u64::MAX - 1);
        assert_eq!(ScopeId::allocate_from(&last), Some(ScopeId(u64::MAX)));
        assert_eq!(ScopeId::allocate_from(&last), None);
        assert_eq!(ScopeId::allocate_from(&last), None);
        assert_eq!(last.load(Ordering::Relaxed), u64::MAX);
    }
}
