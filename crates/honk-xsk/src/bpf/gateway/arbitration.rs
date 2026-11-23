use super::*;
use honk_ebpf_common::xdp_gateway::{HOLD_SEQUENCE_MAX, NATIVE_PENDING_CAP};

#[repr(C, align(64))]
struct Control {
    pending: AtomicU64,
    last_issued: AtomicU64,
    _pad: [u8; 48],
}

const _: () = {
    assert!(size_of::<Control>() == 64);
    assert!(std::mem::offset_of!(Control, pending) == 0);
    assert!(std::mem::offset_of!(Control, last_issued) == 8);
};

pub struct GatewayArbitration {
    pub(in crate::bpf) guards: OwnedFd,
    pub(in crate::bpf) control: OwnedFd,
    grace_root: OwnedFd,
    grace_inner: OwnedFd,
    slot: NonNull<Control>,
}

// SAFETY: the mapping is owned until drop and shared access uses aligned atomics only.
unsafe impl Send for GatewayArbitration {}
unsafe impl Sync for GatewayArbitration {}

impl Drop for GatewayArbitration {
    fn drop(&mut self) {
        // SAFETY: this is the original mmap address and length.
        unsafe { libc::munmap(self.slot.as_ptr().cast(), size_of::<Control>()) };
    }
}

impl GatewayArbitration {
    pub fn new(last_issued: u64) -> io::Result<Self> {
        if last_issued > HOLD_SEQUENCE_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gateway hold sequence exceeds its stamp field",
            ));
        }
        if !cfg!(all(
            target_endian = "little",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported gateway arbitration atomic architecture",
            ));
        }
        // Each non-sleepable XDP invocation owns at most one key per CPU. The single
        // userspace collector may hold one more while any of those CPUs is active.
        let cpus = possible_cpu_count(&std::fs::read_to_string(
            "/sys/devices/system/cpu/possible",
        )?)?;
        let entries = u32::try_from(cpus)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| invalid_data("gateway guard capacity overflow"))?;
        let guards = create::<GatewayKey, u32>(1, entries, b"honk_gw_guards", -1)?;
        let control = create_with_flags::<u32, Control>(2, 1, b"honk_gw_ctl", -1, BPF_F_MMAPABLE)?;
        let grace_inner = create::<u32, u32>(2, 1, b"honk_gw_grace_i", -1)?;
        let grace_root = create::<u32, u32>(12, 1, b"honk_gw_grace_r", grace_inner.as_raw_fd())?;
        update(grace_root.as_fd(), &0u32, &grace_inner.as_raw_fd(), 0)?;
        let mut inner_info = MapInfo::default();
        object_info(grace_inner.as_fd(), &mut inner_info)?;
        if inner_info.id == 0 || lookup(grace_root.as_fd(), &0u32)? != Some(inner_info.id) {
            return Err(invalid_data(
                "gateway grace root inner map identity mismatch",
            ));
        }
        let slot = mmap_slots::<Control>(control.as_fd(), 1)?;
        let arbitration = Self {
            guards,
            control,
            grace_root,
            grace_inner,
            slot,
        };
        arbitration
            .slot()
            .last_issued
            .store(last_issued, Ordering::SeqCst);
        Ok(arbitration)
    }

    pub fn object_fds(&self) -> [BorrowedFd<'_>; 4] {
        [
            &self.guards,
            &self.control,
            &self.grace_root,
            &self.grace_inner,
        ]
        .map(AsFd::as_fd)
    }

    fn slot(&self) -> &Control {
        // SAFETY: this aligned, zero-initialized array remains mapped throughout the borrow.
        unsafe { self.slot.as_ref() }
    }

    pub fn pending(&self) -> u64 {
        self.slot().pending.load(Ordering::SeqCst)
    }

    /// Last valid sequence to carry into the next capture generation. Concurrent reservations
    /// admitted before exhaustion can advance the raw counter past the last usable sequence.
    pub fn last_issued(&self) -> u64 {
        self.slot()
            .last_issued
            .load(Ordering::SeqCst)
            .min(HOLD_SEQUENCE_MAX)
    }

    pub fn synchronize_readers(&self) -> io::Result<()> {
        // Replacing an occupied map-in-map slot synchronously waits for old BPF readers,
        // including when the new inner FD identifies the very same map.
        update(
            self.grace_root.as_fd(),
            &0u32,
            &self.grace_inner.as_raw_fd(),
            0,
        )
    }

    pub(super) fn with_guard(
        &self,
        key: &GatewayKey,
        retire: impl FnOnce() -> io::Result<bool>,
    ) -> io::Result<bool> {
        match update(self.guards.as_fd(), key, &1u32, 1) {
            Ok(()) => (),
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => return Ok(false),
            Err(error) => return Err(error),
        }
        let result = retire();
        if let Err(release) = bpf(
            BPF_MAP_DELETE_ELEM,
            &mut elem(self.guards.as_fd(), key, 0, 0),
        ) {
            return Err(io::Error::other(match result {
                Ok(_) => format!("gateway hold guard release failed: {release}"),
                Err(error) => format!(
                    "gateway hold retirement failed: {error}; guard release failed: {release}"
                ),
            }));
        }
        result
    }

    pub(super) fn refund(&self) -> io::Result<()> {
        self.slot()
            .pending
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |pending| {
                (1..=NATIVE_PENDING_CAP)
                    .contains(&pending)
                    .then(|| pending - 1)
            })
            .map(|_| ())
            .map_err(|_| invalid_data("invalid gateway native pending count on refund"))
    }
}
