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
/// Physical XDP attachment whose lifetime is the lifetime of its link FD.
pub struct OwnedXdpLink {
    fd: OwnedFd,
    ifindex: u32,
    id: u32,
}

impl OwnedXdpLink {
    pub fn create(ifindex: u32, program: BorrowedFd<'_>) -> io::Result<Self> {
        validate_ifindex(ifindex)?;
        if !xdp_absent(ifindex)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "foreign XDP attachment",
            ));
        }
        let program_id = xdp_program_id(program)?;
        let fd = bpf_fd(
            BPF_LINK_CREATE,
            &mut LinkCreateAttr {
                prog_fd: program.as_raw_fd() as u32,
                target_ifindex: ifindex,
                attach_type: BPF_XDP,
                flags: XDP_FLAGS_DRV_MODE,
            },
        )?;
        // SAFETY: F_GETFD has no pointer argument and fd is live.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::FD_CLOEXEC == 0 {
            return Err(invalid_data("XDP link FD is not close-on-exec"));
        }
        let mut info = LinkInfo::default();
        object_info(fd.as_fd(), &mut info)?;
        let link = Self {
            fd,
            ifindex,
            id: info.id,
        };
        link.verify(program_id)?;
        Ok(link)
    }

    pub fn replace(&self, expected_old: BorrowedFd<'_>, new: BorrowedFd<'_>) -> io::Result<()> {
        let old_id = xdp_program_id(expected_old)?;
        let new_id = xdp_program_id(new)?;
        self.verify(old_id)?;
        bpf(
            BPF_LINK_UPDATE,
            &mut LinkUpdateAttr {
                link_fd: self.fd.as_raw_fd() as u32,
                new_prog_fd: new.as_raw_fd() as u32,
                flags: BPF_F_REPLACE,
                old_prog_fd: expected_old.as_raw_fd() as u32,
            },
        )?;
        self.verify(new_id)
    }

    pub fn verify(&self, program_id: u32) -> io::Result<()> {
        self.verify_fd(program_id)?;
        require_native(xdp_state(self.ifindex)?, program_id)?;
        Ok(())
    }

    /// Checks the owned link's identity through its FD. Use [`Self::verify`]
    /// for full native XDP mode validation.
    pub fn verify_fd(&self, program_id: u32) -> io::Result<()> {
        let mut info = LinkInfo::default();
        object_info(self.fd.as_fd(), &mut info)?;
        if info.kind != BPF_LINK_TYPE_XDP
            || info.id == 0
            || info.id != self.id
            || info.prog_id != program_id
            || info.ifindex != self.ifindex
        {
            return Err(invalid_data("native XDP link identity readback mismatch"));
        }
        Ok(())
    }

    pub fn detach(self) -> io::Result<()> {
        use std::os::fd::IntoRawFd;
        // SAFETY: into_raw_fd transfers the unique FD, and Linux closes it even on EINTR.
        if unsafe { libc::close(self.fd.into_raw_fd()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn xdp_program_id(program: BorrowedFd<'_>) -> io::Result<u32> {
    let mut info = ProgInfo::default();
    object_info(program, &mut info)?;
    if info.kind != BPF_PROG_TYPE_XDP || info.id == 0 {
        return Err(invalid_data("XDP program identity readback mismatch"));
    }
    Ok(info.id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    fn require_vm() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "NOT_EXERCISED: requires guest root"
        );
        assert!(
            std::fs::read_to_string("/proc/cmdline")
                .unwrap()
                .contains("virtme."),
            "NOT_EXERCISED: requires disposable virtme guest"
        );
        assert_ne!(
            std::fs::metadata("/proc/self/ns/net").unwrap().ino(),
            std::fs::metadata("/proc/1/ns/net").unwrap().ino(),
            "NOT_EXERCISED: requires private guest netns"
        );
    }

    struct Veth(String, u32);
    impl Veth {
        fn new(slot: u8) -> Self {
            let name = format!("h2b{}x{slot}", std::process::id());
            let peer = format!("h2b{}y{slot}", std::process::id());
            assert!(
                Command::new("ip")
                    .args(["link", "add", &name, "type", "veth", "peer", "name", &peer])
                    .status()
                    .unwrap()
                    .success()
            );
            let index = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            Self(name, index)
        }
    }
    impl Drop for Veth {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["link", "del", &self.0]).status();
        }
    }

    fn program(action: i32) -> (OwnedFd, u32) {
        let mut builder = Builder::new();
        builder.emit(Insn::new(MOV_K, 0, 0, 0, action));
        builder.emit(Insn::new(EXIT, 0, 0, 0, 0));
        load_program(
            &builder.finish().unwrap(),
            b"honk_fd_test",
            &mut vec![0; 65536],
        )
        .unwrap()
    }

    #[test]
    fn xdp_link_uapi_uses_xdp_union_and_expected_old_fd() {
        assert_eq!(size_of::<LinkCreateAttr>(), 16);
        assert_eq!(size_of::<LinkUpdateAttr>(), 16);
        assert_eq!(std::mem::offset_of!(LinkInfo, ifindex), 16);
        assert_eq!(size_of::<LinkInfo>(), 24);
    }

    #[test]
    #[ignore = "requires root in a disposable virtme guest private netns"]
    fn kernel_owned_links_replace_foreign_rejection_and_queue_failure_unwind() {
        require_vm();
        if let Ok(fd) = std::env::var("HONK_TEST_LINK_EXEC_FD") {
            let target = std::fs::read_link(format!("/proc/self/fd/{fd}"));
            assert!(!target.is_ok_and(|path| path.to_string_lossy().contains("bpf-link")));
            return;
        }
        let devices = [Veth::new(0), Veth::new(1), Veth::new(2)];
        let (old, old_id) = program(1);
        let (new, new_id) = program(2);
        let (foreign, foreign_id) = program(2);
        let link = OwnedXdpLink::create(devices[0].1, old.as_fd()).unwrap();
        assert!(OwnedXdpLink::create(devices[0].1, foreign.as_fd()).is_err());
        assert!(link.replace(foreign.as_fd(), new.as_fd()).is_err());
        link.verify(old_id).unwrap();
        link.replace(old.as_fd(), new.as_fd()).unwrap();
        link.verify(new_id).unwrap();
        link.verify_fd(new_id).unwrap();
        assert_eq!(
            link.verify_fd(old_id).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "bpf::attachment::tests::kernel_owned_links_replace_foreign_rejection_and_queue_failure_unwind", "--ignored"])
            .env("HONK_TEST_LINK_EXEC_FD", link.fd.as_raw_fd().to_string()).status().unwrap().success());
        link.verify(new_id).unwrap();
        link.detach().unwrap();
        assert!(xdp_absent(devices[0].1).unwrap());

        // A foreign legacy attachment must survive the entire failed startup.
        set_xdp(devices[2].1, foreign.as_raw_fd(), None).unwrap();
        let failed = (|| -> io::Result<()> {
            let mut links = Vec::new();
            for device in &devices {
                links.push(OwnedXdpLink::create(device.1, old.as_fd())?);
            }
            Ok(())
        })();
        assert!(failed.is_err());
        for device in &devices[..2] {
            assert!(xdp_absent(device.1).unwrap());
        }
        require_native(xdp_state(devices[2].1).unwrap(), foreign_id).unwrap();
        set_xdp(devices[2].1, -1, Some(foreign.as_raw_fd())).unwrap();

        let [device, ..] = devices;
        let link = OwnedXdpLink::create(device.1, old.as_fd()).unwrap();
        link.verify_fd(old_id).unwrap();
        // Netdev removal leaves the BPF FD live but clears its attached ifindex.
        drop(device);
        assert_eq!(
            link.verify_fd(old_id).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    use std::io::{BufRead, Write};
    use std::process::{Child, Stdio};

    struct ChildOwner(Child);
    impl Drop for ChildOwner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "requires root in a disposable virtme guest private netns"]
    fn kernel_owned_link_sigkill_detaches_without_pins() {
        require_vm();
        if let Ok(index) = std::env::var("HONK_TEST_LINK_KILL_IFINDEX") {
            let (program, id) = program(1);
            let link = OwnedXdpLink::create(index.parse().unwrap(), program.as_fd()).unwrap();
            link.verify(id).unwrap();
            println!("OWNED_LINK_READY");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        }
        let device = Veth::new(3);
        let mut child = ChildOwner(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "bpf::attachment::tests::kernel_owned_link_sigkill_detaches_without_pins",
                    "--ignored",
                    "--nocapture",
                ])
                .env("HONK_TEST_LINK_KILL_IFINDEX", device.1.to_string())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut output = std::io::BufReader::new(child.0.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "child exited before attachment"
            );
            if line.contains("OWNED_LINK_READY") {
                break;
            }
        }
        assert!(!xdp_absent(device.1).unwrap());
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        assert!(xdp_absent(device.1).unwrap());
    }
}
