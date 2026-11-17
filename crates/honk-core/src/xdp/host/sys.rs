use super::receipt::Receipt;
use anyhow::ensure;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

pub(crate) fn bpf<T>(command: u32, attr: &mut T) -> std::io::Result<i32> {
    let mut storage: aya_obj::generated::bpf_attr = unsafe { std::mem::zeroed() };
    assert!(size_of::<T>() <= size_of_val(&storage));
    // These private command structures are initialized UAPI prefixes. Zero the
    // unused union tail before using the existing core syscall implementation.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (attr as *const T).cast::<u8>(),
            (&mut storage as *mut aya_obj::generated::bpf_attr).cast::<u8>(),
            size_of::<T>(),
        );
    }
    let result =
        unsafe { crate::ebpf::real::syscall::bpf_syscall(command as libc::c_long, &mut storage) };
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&storage as *const aya_obj::generated::bpf_attr).cast::<u8>(),
            (attr as *mut T).cast::<u8>(),
            size_of::<T>(),
        );
    }
    result
        .map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))
        .and_then(|value| i32::try_from(value).map_err(std::io::Error::other))
}

pub(crate) fn pin(fd: BorrowedFd<'_>, path: &Path) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    #[repr(C)]
    struct Attr {
        pathname: u64,
        fd: u32,
        flags: u32,
    }
    bpf(
        6,
        &mut Attr {
            pathname: name.as_ptr() as u64,
            fd: fd.as_raw_fd() as u32,
            flags: 0,
        },
    )?;
    Ok(())
}

pub(crate) fn identity(fd: BorrowedFd<'_>) -> anyhow::Result<(u32, u32)> {
    #[repr(C)]
    struct Attr {
        fd: u32,
        len: u32,
        info: u64,
    }
    let mut info = [0u32; 2];
    bpf(
        15,
        &mut Attr {
            fd: fd.as_raw_fd() as u32,
            len: 8,
            info: info.as_mut_ptr() as u64,
        },
    )?;
    ensure!(info[1] != 0, "zero Host BPF identity");
    Ok((info[0], info[1]))
}

pub(crate) fn link_program(fd: BorrowedFd<'_>) -> anyhow::Result<u32> {
    #[repr(C)]
    struct Attr {
        fd: u32,
        len: u32,
        info: u64,
    }
    let mut info = [0u32; 3];
    bpf(
        15,
        &mut Attr {
            fd: fd.as_raw_fd() as u32,
            len: 12,
            info: info.as_mut_ptr() as u64,
        },
    )?;
    ensure!(info[2] != 0, "Host link program absent");
    Ok(info[2])
}

pub(crate) fn open_pin(path: &Path, expected: u32) -> anyhow::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt as _;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    #[repr(C)]
    struct Attr {
        pathname: u64,
        fd: u32,
        flags: u32,
    }
    let fd = unsafe {
        OwnedFd::from_raw_fd(bpf(
            7,
            &mut Attr {
                pathname: name.as_ptr() as u64,
                fd: 0,
                flags: 0,
            },
        )?)
    };
    ensure!(
        expected == 0 || identity(fd.as_fd())?.1 == expected,
        "Host pin {} replaced",
        path.display()
    );
    Ok(fd)
}

pub(super) fn newly_pinned_id(path: &Path) -> anyhow::Result<u32> {
    let fd = open_pin(path, 0)?;
    Ok(identity(fd.as_fd())?.1)
}

pub(crate) fn detach(fd: BorrowedFd<'_>) -> anyhow::Result<()> {
    #[repr(C)]
    struct Attr {
        fd: u32,
    }
    match bpf(
        34,
        &mut Attr {
            fd: fd.as_raw_fd() as u32,
        },
    ) {
        Ok(_) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ENOLINK) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn attach_selector(
    program: BorrowedFd<'_>,
    cgroup: &File,
    pin_path: &Path,
) -> anyhow::Result<OwnedFd> {
    #[repr(C)]
    struct Attr {
        program: u32,
        target: u32,
        kind: u32,
        flags: u32,
    }
    let fd = bpf(
        28,
        &mut Attr {
            program: program.as_raw_fd() as u32,
            target: cgroup.as_raw_fd() as u32,
            kind: 1,
            flags: 0,
        },
    )?;
    let link = unsafe { OwnedFd::from_raw_fd(fd) };
    if let Err(error) = pin(link.as_fd(), pin_path) {
        std::mem::forget(link);
        return Err(error);
    }
    Ok(link)
}

pub(crate) struct Grace {
    outer: OwnedFd,
    inner: OwnedFd,
}
impl Grace {
    pub fn new() -> anyhow::Result<Self> {
        #[repr(C)]
        struct Attr {
            kind: u32,
            key: u32,
            value: u32,
            count: u32,
            flags: u32,
            inner: u32,
        }
        let inner = unsafe {
            OwnedFd::from_raw_fd(bpf(
                0,
                &mut Attr {
                    kind: 2,
                    key: 4,
                    value: 4,
                    count: 1,
                    flags: 0,
                    inner: 0,
                },
            )?)
        };
        let outer = unsafe {
            OwnedFd::from_raw_fd(bpf(
                0,
                &mut Attr {
                    kind: 12,
                    key: 4,
                    value: 4,
                    count: 1,
                    flags: 0,
                    inner: inner.as_raw_fd() as u32,
                },
            )?)
        };
        let grace = Self { outer, inner };
        grace.barrier()?;
        Ok(grace)
    }
    pub fn memory_bytes(&self) -> anyhow::Result<usize> {
        honk_xsk::kernel_memory_bytes(self.outer.as_fd())?
            .checked_add(honk_xsk::kernel_memory_bytes(self.inner.as_fd())?)
            .ok_or_else(|| anyhow::anyhow!("Host reader-grace memory overflow"))
    }
    pub fn barrier(&self) -> anyhow::Result<()> {
        #[repr(C)]
        struct Attr {
            fd: u32,
            pad: u32,
            key: u64,
            value: u64,
            flags: u64,
        }
        let key = 0u32;
        let inner = self.inner.as_raw_fd() as u32;
        // Same-inner replacement synchronously waits for pre-update BPF readers.
        bpf(
            2,
            &mut Attr {
                fd: self.outer.as_raw_fd() as u32,
                pad: 0,
                key: &key as *const u32 as u64,
                value: &inner as *const u32 as u64,
                flags: 0,
            },
        )?;
        Ok(())
    }
}

fn effective(fd: BorrowedFd<'_>, kind: u32) -> anyhow::Result<([u32; 64], usize)> {
    #[repr(C)]
    struct Query {
        target: u32,
        kind: u32,
        query_flags: u32,
        attach_flags: u32,
        ids: u64,
        count: u32,
        pad: u32,
    }
    let mut ids = [0u32; 64];
    let mut attr = Query {
        target: fd.as_raw_fd() as u32,
        kind,
        query_flags: 1,
        attach_flags: 0,
        ids: ids.as_mut_ptr() as u64,
        count: 64,
        pad: 0,
    };
    bpf(16, &mut attr)?;
    ensure!(attr.count <= 64, "Host effective cgroup chain overflow");
    Ok((ids, attr.count as usize))
}

pub(crate) struct Cgroups {
    roots: Vec<(PathBuf, File, [i64; 4])>,
    required: Vec<(u32, u32)>,
}
fn directory_stamp(metadata: &std::fs::Metadata) -> [i64; 4] {
    use std::os::unix::fs::MetadataExt as _;
    [
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ]
}
impl Cgroups {
    pub fn capture(
        root: &File,
        required: &[(u32, u32)],
        receipt: &mut Receipt,
    ) -> anyhow::Result<Self> {
        let root = std::fs::read_link(format!("/proc/self/fd/{}", root.as_raw_fd()))?;
        let mut todo = vec![root];
        let mut roots = Vec::new();
        while let Some(path) = todo.pop() {
            ensure!(
                roots.len() + todo.len() < 4096,
                "Host cgroup inventory exceeds bound"
            );
            let file = File::open(&path)?;
            let stamp = directory_stamp(&file.metadata()?);
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    todo.push(entry.path());
                }
            }
            roots.push((path, file, stamp));
        }
        let result = Self {
            roots,
            required: required.to_vec(),
        };
        result.check()?;
        let intent = receipt.intent(
            "effective_cgroups",
            serde_json::json!({"required":required}),
        )?;
        receipt.acknowledge(intent,serde_json::json!({"paths":result.roots.iter().map(|(path,..)|path).collect::<Vec<_>>(),"programs":required}))?;
        Ok(result)
    }
    pub fn check(&self) -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt as _;
        for (path, file, stamp) in &self.roots {
            let named = std::fs::metadata(path)?;
            let held = file.metadata()?;
            ensure!(
                named.dev() == held.dev() && named.ino() == held.ino(),
                "Host cgroup identity changed"
            );
            ensure!(
                directory_stamp(&named) == *stamp,
                "Host cgroup subtree changed"
            );
            for &(kind, id) in &self.required {
                let (ids, count) = effective(file.as_fd(), kind)?;
                ensure!(
                    ids[..count] == [id],
                    "Host effective cgroup hook changed: {} type {kind}",
                    path.display()
                );
            }
            for kind in [0, 3, 8, 9, 12, 13, 19, 20, 21, 22, 29, 30, 31, 32, 34] {
                if self.required.iter().any(|&(expected, _)| expected == kind) {
                    continue;
                }
                ensure!(
                    effective(file.as_fd(), kind)?.1 == 0,
                    "foreign Host cgroup hook type {kind}"
                );
            }
        }
        Ok(())
    }
}
