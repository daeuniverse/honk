use super::*;

#[repr(C)]
pub(super) struct LinkCreateAttr {
    pub(super) prog_fd: u32,
    pub(super) target_ifindex: u32,
    pub(super) attach_type: u32,
    pub(super) flags: u32,
}

#[repr(C)]
pub(super) struct LinkUpdateAttr {
    pub(super) link_fd: u32,
    pub(super) new_prog_fd: u32,
    pub(super) flags: u32,
    pub(super) old_prog_fd: u32,
}

#[repr(C)]
#[derive(Default)]
pub(super) struct LinkInfo {
    pub(super) kind: u32,
    pub(super) id: u32,
    pub(super) prog_id: u32,
    reserved: u32,
    pub(super) ifindex: u32,
    tail_padding: u32,
}
/// Persistent XDP custody with exclusively pinned guard/data programs.
/// The netdev retains driver-mode custody independently of creator FDs.
/// Drop never detaches; deliberate removal requires source-quiesced recovery.
#[derive(Clone)]
pub struct PersistentAttachment {
    ifindex: u32,
    discover_id: u32,
    data_id: u32,
}

impl PersistentAttachment {
    pub fn create(ifindex: u32, programs: &Programs, pin_root: &Path) -> io::Result<Self> {
        validate_ifindex(ifindex)?;
        let root = private_bpffs(pin_root)?;
        pin_program(root.as_fd(), c"guard", programs.discover.as_fd())?;
        // A partial pair is retained as explicit startup-failure custody.
        pin_program(root.as_fd(), c"data", programs.data.as_fd())?;
        if !xdp_absent(ifindex)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "foreign or stale XDP attachment",
            ));
        }
        let attachment = Self {
            ifindex,
            discover_id: programs.discover_id,
            data_id: programs.data_id,
        };
        set_xdp(ifindex, programs.discover.as_raw_fd(), None)?;
        require_native(xdp_state(ifindex)?, programs.discover_id)?;
        Ok(attachment)
    }

    pub fn replace(&self, programs: &Programs) -> io::Result<XdpState> {
        self.check_programs(programs)?;
        require_native(xdp_state(self.ifindex)?, self.discover_id)?;
        set_xdp(
            self.ifindex,
            programs.data.as_raw_fd(),
            Some(programs.discover.as_raw_fd()),
        )?;
        require_native(xdp_state(self.ifindex)?, self.data_id)
    }

    /// Reinstall the selected-traffic DROP guard before withdrawing any XSK.
    pub fn guard(&self, programs: &Programs) -> io::Result<()> {
        self.check_programs(programs)?;
        let state = xdp_state(self.ifindex)?;
        if state.prog_id == self.discover_id {
            require_native(state, self.discover_id)?;
            return Ok(());
        }
        require_native(state, self.data_id)?;
        set_xdp(
            self.ifindex,
            programs.discover.as_raw_fd(),
            Some(programs.data.as_raw_fd()),
        )?;
        require_native(xdp_state(self.ifindex)?, self.discover_id)?;
        Ok(())
    }

    fn check_programs(&self, programs: &Programs) -> io::Result<()> {
        if programs.discover_id != self.discover_id || programs.data_id != self.data_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "foreign XDP programs",
            ));
        }
        Ok(())
    }
}

pub(super) fn private_bpffs(path: &Path) -> io::Result<OwnedFd> {
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    // SAFETY: the statfs output structure accepts an all-zero initialization.
    let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: statfs is writable and the descriptor denotes the opened directory.
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut statfs) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if statfs.f_type as u32 != 0xcafe4a11 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XDP pin root must be bpffs",
        ));
    }
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no pointer arguments or failure case.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "XDP pin root must be private and owned by the effective user",
        ));
    }
    Ok(directory.into())
}

pub(super) fn pin_program(
    root: BorrowedFd<'_>,
    name: &std::ffi::CStr,
    program: BorrowedFd<'_>,
) -> io::Result<()> {
    #[repr(C)]
    struct PinAttr {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
        path_fd: i32,
        padding: u32,
    }
    bpf(
        BPF_OBJ_PIN,
        &mut PinAttr {
            pathname: name.as_ptr() as u64,
            bpf_fd: program.as_raw_fd() as u32,
            file_flags: BPF_F_PATH_FD,
            path_fd: root.as_raw_fd(),
            padding: 0,
        },
    )?;
    Ok(())
}
pub struct Attachment {
    fd: OwnedFd,
    ifindex: u32,
    id: u32,
    discover_id: u32,
    data_id: u32,
}

impl Attachment {
    pub fn create(ifindex: u32, programs: &Programs) -> io::Result<Self> {
        validate_ifindex(ifindex)?;
        let fd = bpf_fd(
            BPF_LINK_CREATE,
            &mut LinkCreateAttr {
                prog_fd: programs.discover.as_raw_fd() as u32,
                target_ifindex: ifindex,
                attach_type: BPF_XDP,
                flags: XDP_FLAGS_DRV_MODE,
            },
        )?;
        let identity = (|| {
            let mut info = LinkInfo::default();
            object_info(fd.as_fd(), &mut info)?;
            if info.kind != BPF_LINK_TYPE_XDP
                || info.id == 0
                || info.prog_id != programs.discover_id
                || info.ifindex != ifindex
            {
                return Err(invalid_data("native XDP link identity readback mismatch"));
            }
            require_native(xdp_state(ifindex)?, programs.discover_id)?;
            Ok(info.id)
        })();
        let id = match identity {
            Ok(id) => id,
            Err(error) => {
                // Detaching on a readback error could expose the still-live local upstream.
                std::mem::forget(fd);
                return Err(error);
            }
        };
        Ok(Self {
            fd,
            ifindex,
            id,
            discover_id: programs.discover_id,
            data_id: programs.data_id,
        })
    }

    pub fn replace(&self, programs: &Programs) -> io::Result<XdpState> {
        if programs.discover_id != self.discover_id || programs.data_id != self.data_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "programs do not belong to this attachment",
            ));
        }
        bpf(
            BPF_LINK_UPDATE,
            &mut LinkUpdateAttr {
                link_fd: self.fd.as_raw_fd() as u32,
                new_prog_fd: programs.data.as_raw_fd() as u32,
                flags: BPF_F_REPLACE,
                old_prog_fd: programs.discover.as_raw_fd() as u32,
            },
        )?;
        let mut info = LinkInfo::default();
        object_info(self.fd.as_fd(), &mut info)?;
        if info.kind != BPF_LINK_TYPE_XDP
            || info.id != self.id
            || info.prog_id != self.data_id
            || info.ifindex != self.ifindex
        {
            return Err(invalid_data("updated XDP link identity readback mismatch"));
        }
        require_native(xdp_state(self.ifindex)?, self.data_id)
    }

    /// Reinstall the selected-traffic DROP guard before withdrawing any XSK.
    pub fn guard(&self, programs: &Programs) -> io::Result<()> {
        if programs.discover_id != self.discover_id || programs.data_id != self.data_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "foreign XDP programs",
            ));
        }
        bpf(
            BPF_LINK_UPDATE,
            &mut LinkUpdateAttr {
                link_fd: self.fd.as_raw_fd() as u32,
                new_prog_fd: programs.discover.as_raw_fd() as u32,
                flags: BPF_F_REPLACE,
                old_prog_fd: programs.data.as_raw_fd() as u32,
            },
        )?;
        require_native(xdp_state(self.ifindex)?, self.discover_id)?;
        Ok(())
    }

    pub fn id(&self) -> u32 {
        self.id
    }
}

impl AsFd for Attachment {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Attachment {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
