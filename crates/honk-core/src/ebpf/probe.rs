//! Runtime capability probing for batched `bpf()` map commands.
//!
//! Aya does not expose `BPF_MAP_LOOKUP_BATCH` (Linux 5.6+), so
//! `ebpf::map_snapshot` issues it as a raw syscall. Availability is detected at runtime instead of
//! relying on kernel version parsing. On capability failure the storage adapter
//! either selects its proven-safe fallback or returns an explicit unsupported
//! error. An already-in-flight successful call can still record support later.
//!
//! Keep separate observations for plain and BPF_F_LOCK batch copies: support
//! for ordinary hashes does not prove support for locked flow values. Request
//! enumeration requires plain batch support rather than an unsafe fallback.

use std::ffi::c_long;
use std::sync::atomic::{AtomicBool, Ordering};

/// Errno values that mean "this bpf() command (for this map type) is not
/// available on the running kernel":
/// - `EINVAL`: the command number is unknown (pre-5.6 kernels have no
///   batch commands);
/// - `EOPNOTSUPP` (== `ENOTSUP` on Linux): the map type provides no
///   implementation for the command;
/// - `EPERM`: bpf() is restricted (e.g. `kernel.unprivileged_bpf_disabled`
///   without the required capabilities);
/// - `ENOSYS`: the bpf() syscall is missing entirely.
pub fn is_capability_errno(errno: c_long) -> bool {
    errno == libc::EINVAL as c_long
        || errno == libc::EOPNOTSUPP as c_long
        || errno == libc::EPERM as c_long
        || errno == libc::ENOSYS as c_long
}

/// Unknown and supported have the same fallback behavior. Keep only whether
/// the latest decisive observation reported an unsupported command.
#[derive(Debug)]
pub struct BatchCapability(AtomicBool);

impl Default for BatchCapability {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchCapability {
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Check whether subsequent attempts should use the per-element fallback.
    pub fn is_unsupported(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// Consume successful/missing results and real errors normally. Preserve
    /// observation order: a late success or `ENOENT` can replace a failure.
    pub fn observe(&self, result: Result<(), c_long>) -> bool {
        match result {
            result if result.is_ok() || result == Err(libc::ENOENT as c_long) => {
                self.0.store(false, Ordering::Relaxed);
                true
            }
            Err(error) if is_capability_errno(error) => {
                self.0.store(true, Ordering::Relaxed);
                false
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_misses_and_runtime_errors_keep_the_command_usable() {
        let cap = BatchCapability::new();
        for result in [
            Ok(()),
            Err(libc::ENOENT as c_long),
            Err(libc::EFAULT as c_long),
            Err(libc::E2BIG as c_long),
        ] {
            assert!(cap.observe(result));
            assert!(!cap.is_unsupported());
        }
    }

    #[test]
    fn capability_results_preserve_observation_order() {
        for errno in [libc::EINVAL, libc::EOPNOTSUPP, libc::EPERM, libc::ENOSYS] {
            let cap = BatchCapability::new();
            for supported in [Ok(()), Err(libc::ENOENT as c_long)] {
                assert!(cap.observe(supported));
                assert!(!cap.observe(Err(errno as c_long)));
                assert!(cap.is_unsupported());
                assert!(cap.observe(Err(libc::EFAULT as c_long)));
                assert!(cap.is_unsupported());
                assert!(cap.observe(supported));
                assert!(!cap.is_unsupported());
            }
        }
    }
}
