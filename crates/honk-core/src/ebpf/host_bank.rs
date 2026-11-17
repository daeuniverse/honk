//! The one read-only socket-bank mapping shared by concrete capture owners.
use super::real::btf::Btf;
use anyhow::{Context as _, ensure};
use aya_obj::generated::{BPF_F_MMAPABLE, bpf_attr, bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, bpf_map_info};
use honk_ebpf_common::host::{HOST_SOCKET_BUCKETS, HostSocketPayload};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering, compiler_fence};

pub(crate) struct HostSocketBank {
    base: NonNull<u8>,
    length: usize,
}

// The mapping is read-only and kept alive by its VMA; all shared loads are atomic.
unsafe impl Send for HostSocketBank {}
unsafe impl Sync for HostSocketBank {}

impl HostSocketBank {
    pub(crate) fn map(fd: BorrowedFd<'_>) -> anyhow::Result<Self> {
        ensure!(
            cfg!(all(target_arch = "x86_64", target_endian = "little")),
            "Host bank requires x86-64 little endian"
        );
        let mut info: bpf_map_info = unsafe { std::mem::zeroed() };
        let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
        attr.info.bpf_fd = fd.as_raw_fd() as u32;
        attr.info.info_len = std::mem::size_of_val(&info) as u32;
        attr.info.info = (&mut info as *mut bpf_map_info) as u64;
        ensure!(
            unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    BPF_OBJ_GET_INFO_BY_FD as libc::c_uint,
                    &raw mut attr,
                    std::mem::size_of_val(&attr),
                )
            } == 0,
            "Host bank map info: {}",
            std::io::Error::last_os_error()
        );
        let stride = std::mem::size_of::<HostSocketPayload>();
        ensure!(
            info.type_ == 2
                && info.id != 0
                && info.key_size == 4
                && info.value_size as usize == stride
                && info.max_entries as usize == HOST_SOCKET_BUCKETS
                && info.map_flags == BPF_F_MMAPABLE
                && stride == 520
                && stride.is_multiple_of(8),
            "Host bank mmap ABI mismatch"
        );
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
        ensure!(
            page >= 8 && page.is_power_of_two(),
            "Host bank page alignment"
        );
        let length = stride
            .checked_mul(HOST_SOCKET_BUCKETS)
            .and_then(|bytes| bytes.checked_add(page - 1))
            .context("Host bank mapping extent")?
            & !(page - 1);
        // ARRAY mmap offset zero addresses the value area, not the kernel-only header page.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        ensure!(
            address != libc::MAP_FAILED,
            "Host bank read-only mmap: {}",
            std::io::Error::last_os_error()
        );
        let Some(base) = NonNull::new(address.cast::<u8>()) else {
            unsafe { libc::munmap(address, length) };
            anyhow::bail!("Host bank null mapping");
        };
        Ok(Self { base, length })
    }

    pub(crate) fn read(&self, index: u32) -> anyhow::Result<HostSocketPayload> {
        ensure!(
            (index as usize) < HOST_SOCKET_BUCKETS,
            "Host bank index out of range"
        );
        // Exact eight-byte ARRAY stride and page alignment admit aligned atomic observations.
        let payload = unsafe {
            self.base
                .as_ptr()
                .add(index as usize * std::mem::size_of::<HostSocketPayload>())
        };
        unsafe { sample(payload.cast()) }.context("unstable Host socket bucket; ownership retained")
    }
}

// BPF JIT stores and these loads are ordered on the admitted x86-64 target. Compiler
// barriers keep the payload word loads between the two aligned version loads; no
// syscall copy, memcpy/rep-movsb, unaligned access or BPF_F_LOCK fallback is admitted.
unsafe fn sample(payload: *mut u64) -> Option<HostSocketPayload> {
    let before = unsafe { AtomicU64::from_ptr(payload) }.load(Ordering::Acquire);
    if before & 1 != 0 {
        return None;
    }
    compiler_fence(Ordering::SeqCst);
    let mut snapshot = std::mem::MaybeUninit::<HostSocketPayload>::uninit();
    let out = snapshot.as_mut_ptr().cast::<u64>();
    unsafe { out.write(before) };
    for word in 1..std::mem::size_of::<HostSocketPayload>() / 8 {
        let value = unsafe { AtomicU64::from_ptr(payload.add(word)) }.load(Ordering::Relaxed);
        unsafe { out.add(word).write(value) };
    }
    compiler_fence(Ordering::SeqCst);
    let after = unsafe { AtomicU64::from_ptr(payload) }.load(Ordering::Acquire);
    (before == after && after & 1 == 0).then(|| unsafe { snapshot.assume_init() })
}

impl Drop for HostSocketBank {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base.as_ptr().cast(), self.length) };
    }
}

/// Admit the actual map value types, recursively excluding locks from the payload.
/// Concrete loaders pass the two BTF map value type IDs, never just a type name.
pub(crate) fn validate_btf(btf: &Btf<'_>, payload: u32, locks: u32) -> anyhow::Result<()> {
    fn integer(btf: &Btf<'_>, id: u32, width: u32) -> bool {
        let Some(ty) = btf.resolve_modifiers(id) else {
            return false;
        };
        btf.kind(ty) == Some(1)
            && btf.u32_at(ty + 8) == Some(width)
            && btf.u32_at(ty + 12) == Some(width * 8)
    }
    fn structure(btf: &Btf<'_>, id: u32, size: u32, members: u32) -> anyhow::Result<usize> {
        let ty = btf.resolve_composite(id).context("Host bank structure")?;
        ensure!(
            btf.kind(ty) == Some(4)
                && btf.u32_at(ty + 8) == Some(size)
                && btf.u32_at(ty + 4) == Some((4 << 24) | members),
            "Host bank structure ABI"
        );
        Ok(ty)
    }
    fn field(btf: &Btf<'_>, ty: usize, name: &str, offset: u32) -> anyhow::Result<u32> {
        let (id, actual) = btf.direct_member(ty, name).context("Host bank field")?;
        ensure!(actual == offset, "Host bank field offset: {name}");
        Ok(id)
    }
    fn array(btf: &Btf<'_>, id: u32, count: u32) -> anyhow::Result<u32> {
        let ty = btf.resolve_modifiers(id).context("Host bank array")?;
        ensure!(
            btf.kind(ty) == Some(3) && btf.u32_at(ty + 20) == Some(count),
            "Host bank array extent"
        );
        btf.u32_at(ty + 12).context("Host bank array element")
    }
    let payload = structure(btf, payload, 520, 2)?;
    ensure!(
        integer(btf, field(btf, payload, "version", 0)?, 8),
        "Host bank version type"
    );
    let entries = array(btf, field(btf, payload, "value", 8)?, 8)?;
    let entry = structure(btf, entries, 64, 10)?;
    for (name, offset, width) in [
        ("cookie", 0, 8),
        ("socket_address", 8, 8),
        ("pid", 16, 4),
        ("flags", 36, 4),
        ("operation_incarnation", 40, 8),
        ("disconnect_generation", 48, 4),
        ("selection", 52, 4),
        ("output_ifindex", 56, 4),
        ("reserved", 60, 4),
    ] {
        ensure!(
            integer(btf, field(btf, entry, name, offset)?, width),
            "Host bank integer field: {name}"
        );
    }
    ensure!(
        integer(btf, array(btf, field(btf, entry, "pname", 20)?, 16)?, 1),
        "Host bank pname type"
    );
    let locks = structure(btf, locks, 8, 2)?;
    let lock = structure(btf, field(btf, locks, "lock", 0)?, 4, 1)?;
    ensure!(
        btf.string(btf.u32_at(lock).context("Host bank lock name")?) == Some("bpf_spin_lock")
            && integer(btf, field(btf, lock, "val", 0)?, 4)
            && integer(btf, field(btf, locks, "padding", 4)?, 4),
        "Host external lock ABI"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_samples_reject_odd_and_keep_bucket_version_after_free() {
        let mut payload = HostSocketPayload {
            version: 2,
            ..Default::default()
        };
        payload.value[7].cookie = 123;
        let ptr = (&raw mut payload).cast::<u64>();
        assert_eq!(unsafe { sample(ptr) }.unwrap().value[7].cookie, 123);
        unsafe { ptr.write(3) };
        assert!(unsafe { sample(ptr) }.is_none());
        unsafe {
            (&raw mut (*ptr.cast::<HostSocketPayload>()).value[7]).write(Default::default());
            ptr.write(4);
        }
        let retired = unsafe { sample(ptr) }.unwrap();
        assert_eq!(retired.version, 4);
        assert!(retired.value.iter().all(|entry| entry.cookie == 0));
    }
}
