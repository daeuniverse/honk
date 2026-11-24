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
    grace: AuxReaderGrace,
    // All userspace operations share the one guard slot reserved in addition to the CPUs.
    userspace: Mutex<()>,
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

pub struct AuxReaderGrace {
    root: OwnedFd,
    inner: OwnedFd,
}

impl AuxReaderGrace {
    pub fn new() -> io::Result<Self> {
        let inner = create::<u32, u32>(2, 1, b"honk_gw_grace_i", -1)?;
        let root = create::<u32, u32>(12, 1, b"honk_gw_grace_r", inner.as_raw_fd())?;
        update(root.as_fd(), &0u32, &inner.as_raw_fd(), 0)?;
        let mut info = MapInfo::default();
        object_info(inner.as_fd(), &mut info)?;
        if info.id == 0 || lookup(root.as_fd(), &0u32)? != Some(info.id) {
            return Err(invalid_data(
                "gateway grace root inner map identity mismatch",
            ));
        }
        Ok(Self { root, inner })
    }

    pub fn object_fds(&self) -> [BorrowedFd<'_>; 2] {
        [self.root.as_fd(), self.inner.as_fd()]
    }

    pub fn synchronize(&self) -> io::Result<()> {
        // Updating an occupied map-in-map slot waits for pre-existing non-sleepable BPF readers.
        update(self.root.as_fd(), &0u32, &self.inner.as_raw_fd(), 0)
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
        // Each non-sleepable writer owns at most one key per CPU. Userspace serializes
        // admissions, the idle collector and offline cleanup into one additional slot.
        let cpus = possible_cpu_count(&std::fs::read_to_string(
            "/sys/devices/system/cpu/possible",
        )?)?;
        let entries = u32::try_from(cpus)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| invalid_data("gateway guard capacity overflow"))?;
        let guards = create::<GatewayKey, u32>(1, entries, b"honk_gw_guards", -1)?;
        let control = create_with_flags::<u32, Control>(2, 1, b"honk_gw_ctl", -1, BPF_F_MMAPABLE)?;
        let grace = AuxReaderGrace::new()?;
        let slot = mmap_slots::<Control>(control.as_fd(), 1)?;
        let arbitration = Self {
            guards,
            control,
            grace,
            userspace: Mutex::new(()),
            slot,
        };
        arbitration
            .slot()
            .last_issued
            .store(last_issued, Ordering::SeqCst);
        Ok(arbitration)
    }

    pub fn object_fds(&self) -> [BorrowedFd<'_>; 4] {
        let [root, inner] = self.grace.object_fds();
        [self.guards.as_fd(), self.control.as_fd(), root, inner]
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
        self.grace.synchronize()
    }

    pub(super) fn with_guard<T>(
        &self,
        key: &GatewayKey,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<Option<T>> {
        let _user = self
            .userspace
            .lock()
            .map_err(|_| invalid_data("gateway userspace guard poisoned"))?;
        match update(self.guards.as_fd(), key, &1u32, 1) {
            Ok(()) => (),
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => return Ok(None),
            Err(error) => return Err(error),
        }
        let result = operation();
        if let Err(release) = bpf(
            BPF_MAP_DELETE_ELEM,
            &mut elem(self.guards.as_fd(), key, 0, 0),
        ) {
            return Err(io::Error::other(match result {
                Ok(_) => format!("gateway hold guard release failed: {release}"),
                Err(error) => format!(
                    "gateway hold operation failed: {error}; guard release failed: {release}"
                ),
            }));
        }
        result.map(Some)
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
