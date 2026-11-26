use super::{kernel::KernelLayout, receipt::Receipt, sys};
use crate::ebpf::{
    PnameSupport,
    host_bank::{self, HostSocketBank},
    real::{
        btf::Btf,
        process_name::{self, PnameCaptureMode},
        syscall,
    },
};
use anyhow::{Context as _, ensure};
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, MapData, Queue},
    programs::{
        CgroupAttachMode, CgroupSock, CgroupSockAddr, Lsm,
        links::{FdLink, PinnedLink},
    },
};
use honk_ebpf_common::{host::*, tun::*};
pub(super) use honk_xsk::TunProgramConfig;
use honk_xsk::{TunMaps, TunPrograms};
use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
use std::path::Path;

pub(super) struct Object {
    pub bpf: Ebpf,
    pub links: Vec<PinnedLink>,
    pub hooks: Vec<(u32, u32)>,
    pub cgroup: File,
    mode: PnameCaptureMode,
    raw: Option<TunPrograms>,
    raw_links: Vec<OwnedFd>,
    btf_bytes: usize,
}

impl Object {
    pub fn active_lsm() -> anyhow::Result<String> {
        let active =
            std::fs::read_to_string("/sys/kernel/security/lsm").context("TUN active LSM list")?;
        ensure!(
            active.trim().split(',').any(|value| value == "bpf"),
            "TUN requires active BPF LSM"
        );
        Ok(active)
    }

    pub fn load(
        bytes: &[u8],
        layout: &KernelLayout,
        namespace: u64,
        _mark: u32,
    ) -> anyhow::Result<Self> {
        ensure!(
            bytes.len() <= 1 << 20,
            "TUN narrow object exceeds loader allocation bound"
        );
        ensure!(
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) } == 4096,
            "TUN mmap ABI requires 4 KiB pages"
        );
        ensure!(
            aya::util::nr_cpus().map_err(|(_, error)| error)?.get() <= 4096,
            "TUN possible CPU allocation bound"
        );
        ensure!(
            layout.memory_bytes() <= 256 << 20,
            "TUN retained BTF construction bound"
        );
        let btf_bytes = validate_object(bytes)?;
        let mut loader = EbpfLoader::new();
        loader
            .btf(layout.btf())
            .override_global("HOST_SOURCE_NETNS_COOKIE", &namespace, true)
            .override_global("HOST_HAS_BPF_GET_CURRENT_TASK", &1u32, true)
            .override_global("HOST_SOCKET_COOKIE_OFFSET", &layout.socket_cookie, true)
            .override_global("TASK_MM_OFFSET", &layout.task_mm, true)
            .override_global("MM_ARG_START_OFFSET", &layout.mm_arg_start, true);
        let mut bpf = loader.load(bytes)?;
        use aya_obj::generated::bpf_map_type::*;
        for (name, kind, key, value, count, flags) in [
            (
                "HOST_SOCKETS",
                BPF_MAP_TYPE_ARRAY,
                4,
                520,
                8192,
                TUN_MMAP_FLAG,
            ),
            ("HOST_SOCKET_LOCKS", BPF_MAP_TYPE_ARRAY, 4, 8, 8192, 0),
            ("HOST_GATE", BPF_MAP_TYPE_ARRAY, 4, 4, 1, 0),
            ("HOST_SEQUENCE", BPF_MAP_TYPE_ARRAY, 4, 16, 1, 0),
            ("HOST_IDENTITY_STATS", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 2, 0),
            (
                "TUN_PACKETS",
                BPF_MAP_TYPE_ARRAY,
                4,
                192,
                TUN_PACKET_CELLS,
                0,
            ),
            ("TUN_FREE", BPF_MAP_TYPE_QUEUE, 0, 4, TUN_PACKET_CELLS, 0),
            ("TUN_OWNER", BPF_MAP_TYPE_ARRAY, 4, 256, 1, TUN_MMAP_FLAG),
            (
                "TUN_READ_WINDOW",
                BPF_MAP_TYPE_ARRAY,
                4,
                512,
                1,
                TUN_MMAP_FLAG,
            ),
        ] {
            syscall::validate_map_layout(&bpf, name, kind, key, value, count, flags)?;
        }
        Array::<_, u32>::try_from(bpf.map_mut("HOST_GATE").context("TUN identity gate")?)?
            .set(0, &0, 0)?;
        Array::<_, HostSequence>::try_from(
            bpf.map_mut("HOST_SEQUENCE")
                .context("TUN selection sequence")?,
        )?
        .set(0, &HostSequence::new(1), 0)?;
        Array::<_, TunOwnerV1>::try_from(bpf.map_mut("TUN_OWNER").context("TUN owner map")?)?.set(
            0,
            &TunOwnerV1::default(),
            0,
        )?;
        Array::<_, TunReadWindowV1>::try_from(
            bpf.map_mut("TUN_READ_WINDOW").context("TUN read window")?,
        )?
        .set(0, &TunReadWindowV1::default(), 0)?;
        let mut free =
            Queue::<_, u32>::try_from(bpf.map_mut("TUN_FREE").context("TUN free queue")?)?;
        for index in 0..TUN_PACKET_CELLS {
            free.push(&index, 0)?;
        }
        let mode = if process_name::load_pair(
            &mut bpf,
            "tproxy_wan_cg_sock_create",
            "tproxy_wan_cg_connect4",
        ) {
            PnameCaptureMode::Argv0
        } else {
            PnameCaptureMode::Comm
        };
        let mut mounts = String::new();
        File::open("/proc/thread-self/mountinfo")?
            .take((1 << 20) + 1)
            .read_to_string(&mut mounts)?;
        ensure!(
            mounts.len() <= 1 << 20,
            "TUN mount inventory exceeds loader bound"
        );
        let mut roots = mounts.lines().filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            if right.split_whitespace().next()? != "cgroup2" {
                return None;
            }
            let mut fields = left.split_whitespace();
            fields.next()?;
            fields.next()?;
            fields.next()?;
            (fields.next()? == "/").then(|| fields.next()).flatten()
        });
        let root = roots
            .next()
            .context("TUN requires actual cgroup2 root mount")?;
        ensure!(
            roots.next().is_none() && !root.contains('\\'),
            "ambiguous TUN cgroup root"
        );
        let cgroup = File::open(root)?;
        Ok(Self {
            bpf,
            links: Vec::with_capacity(6),
            hooks: Vec::with_capacity(6),
            cgroup,
            mode,
            raw: None,
            raw_links: Vec::with_capacity(7),
            btf_bytes,
        })
    }

    pub fn map(&self, name: &str) -> anyhow::Result<BorrowedFd<'_>> {
        let map = self
            .bpf
            .map(name)
            .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))?;
        Ok(syscall::map_data(map).fd().as_fd())
    }

    pub fn gate(&mut self, value: u32) -> anyhow::Result<()> {
        ensure!(value <= 1, "invalid TUN source gate");
        let owner_fd = self.map("TUN_OWNER")?;
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                owner_fd.as_raw_fd(),
                0,
            )
        };
        ensure!(
            page != libc::MAP_FAILED,
            "TUN gate mapping: {}",
            std::io::Error::last_os_error()
        );
        let result = (|| -> anyhow::Result<()> {
            let owner = page.cast::<TunOwnerV1>();
            let gate = unsafe { std::sync::atomic::AtomicU64::from_ptr(&raw mut (*owner).gate) };
            let fatal = unsafe { std::sync::atomic::AtomicU64::from_ptr(&raw mut (*owner).fatal) };
            if value == 0 {
                gate.store(0, std::sync::atomic::Ordering::Release);
            }
            let mut shared = Array::<_, u32>::try_from(
                self.bpf.map_mut("HOST_GATE").context("TUN identity gate")?,
            )?;
            if value != 0 {
                ensure!(
                    fatal.load(std::sync::atomic::Ordering::Acquire) == 0,
                    "TUN source fatal latch is set"
                );
            }
            shared.set(0, &value, 0)?;
            ensure!(shared.get(&0, 0)? == value, "TUN identity gate readback");
            if value != 0 {
                gate.store(1, std::sync::atomic::Ordering::Release);
            }
            Ok(())
        })();
        let unmapped = unsafe { libc::munmap(page, 4096) };
        result?;
        ensure!(unmapped == 0, "TUN gate unmap failure");
        Ok(())
    }

    pub fn attach(
        &mut self,
        layout: &KernelLayout,
        pins: &Path,
        receipt: &mut Receipt,
        active_lsm: &str,
    ) -> anyhow::Result<()> {
        let entry = receipt.intent(
            "active_lsm",
            serde_json::json!({"path":"/sys/kernel/security/lsm"}),
        )?;
        receipt.acknowledge(entry, serde_json::json!({"active":active_lsm.trim()}))?;
        for (name, map) in self.bpf.maps() {
            if name.starts_with('.') {
                continue;
            }
            let path = pins.join(name);
            let entry = receipt.intent("map", serde_json::json!({"name":name,"pin_path":path}))?;
            map.pin(&path)?;
            let info = MapData::from_pin(&path)?.info()?;
            receipt.acknowledge(entry, serde_json::json!({"name":name,"pin_path":path,"id":info.id(),"key_size":info.key_size(),"value_size":info.value_size(),"entries":info.max_entries()}))?;
        }
        for (base, attach_type) in [
            ("tproxy_wan_cg_sock_create", 2u32),
            ("tproxy_wan_cg_connect4", 10),
            ("tproxy_wan_cg_connect6", 11),
            ("tproxy_wan_cg_sendmsg4", 14),
            ("tproxy_wan_cg_sendmsg6", 15),
        ] {
            let name = if self.mode == PnameCaptureMode::Comm {
                format!("{base}_comm")
            } else {
                base.to_owned()
            };
            let path = pins.join(&name);
            let entry = receipt.intent(
                "cgroup_link",
                serde_json::json!({"name":name,"attach_type":attach_type,"pin_path":path}),
            )?;
            let program = self
                .bpf
                .program_mut(&name)
                .context("mandatory TUN identity program")?;
            let (link, program_id): (FdLink, u32) = if attach_type == 2 {
                let program: &mut CgroupSock = program.try_into()?;
                if program.fd().is_err() {
                    program.load()?;
                }
                let id = program.info()?.id();
                let link = program.attach(&self.cgroup, CgroupAttachMode::Single)?;
                (program.take_link(link)?.try_into()?, id)
            } else {
                let program: &mut CgroupSockAddr = program.try_into()?;
                if program.fd().is_err() {
                    program.load()?;
                }
                let id = program.info()?.id();
                let link = program.attach(&self.cgroup, CgroupAttachMode::Single)?;
                (program.take_link(link)?.try_into()?, id)
            };
            let id = link.info()?.id();
            self.links.push(link.pin(&path)?);
            self.hooks.push((attach_type, program_id));
            receipt.acknowledge(
                entry,
                serde_json::json!({"link_id":id,"program_id":program_id,"pin_path":path}),
            )?;
        }
        let path = pins.join("sk_free_security");
        let entry = receipt.intent(
            "lsm_link",
            serde_json::json!({"hook":"sk_free_security","pin_path":path}),
        )?;
        let lsm: &mut Lsm = self
            .bpf
            .program_mut("honk_host_sk_free_security")
            .context("TUN final-free LSM missing")?
            .try_into()?;
        lsm.load("sk_free_security", layout.btf())?;
        let program_id = lsm.info()?.id();
        let link = lsm.attach()?;
        let link: FdLink = lsm.take_link(link)?.into();
        let id = link.info()?.id();
        self.links.push(link.pin(&path)?);
        receipt.acknowledge(
            entry,
            serde_json::json!({"link_id":id,"program_id":program_id,"pin_path":path}),
        )?;
        self.identity_canary(receipt)
    }

    pub fn bind(
        &mut self,
        layout: &KernelLayout,
        fd: RawFd,
        config: TunProgramConfig,
        pins: &Path,
        receipt: &mut Receipt,
    ) -> anyhow::Result<()> {
        ensure!(self.raw.is_none(), "TUN producer rebound");
        let maps = TunMaps {
            sockets: self.map("HOST_SOCKETS")?.as_raw_fd(),
            locks: self.map("HOST_SOCKET_LOCKS")?.as_raw_fd(),
            gate: self.map("HOST_GATE")?.as_raw_fd(),
            sequence: self.map("HOST_SEQUENCE")?.as_raw_fd(),
            packets: self.map("TUN_PACKETS")?.as_raw_fd(),
            free: self.map("TUN_FREE")?.as_raw_fd(),
            owner: self.map("TUN_OWNER")?.as_raw_fd(),
            window: self.map("TUN_READ_WINDOW")?.as_raw_fd(),
        };
        let programs = TunPrograms::load(
            &config,
            &layout.offsets,
            maps,
            layout.read,
            layout.copy,
            layout.close,
        )?;
        for (name, program, id) in programs.programs() {
            let path = pins.join(name);
            let entry = receipt.intent(
                "raw_program",
                serde_json::json!({"name":name,"pin_path":path}),
            )?;
            sys::pin(program, &path)?;
            ensure!(
                sys::identity(sys::open_pin(&path, id)?.as_fd())?.1 == id,
                "TUN raw program pin identity"
            );
            receipt.acknowledge(entry, serde_json::json!({"program_id":id,"pin_path":path}))?;
        }
        for index in 2..8 {
            let name = TunPrograms::NAMES[index];
            let path = pins.join(format!("{name}_link"));
            let entry = receipt.intent(
                "tracing_link",
                serde_json::json!({"name":name,"pin_path":path}),
            )?;
            let link = programs.attach_trace(index)?;
            let id = sys::identity(link.as_fd())?.1;
            let program_id = sys::link_program(link.as_fd())?;
            sys::pin(link.as_fd(), &path)?;
            self.raw_links.push(link);
            receipt.acknowledge(
                entry,
                serde_json::json!({"link_id":id,"program_id":program_id,"pin_path":path}),
            )?;
        }
        let (selector, program_id) = programs.selector();
        let path = pins.join("tun_selector_link");
        let entry = receipt.intent(
            "selector",
            serde_json::json!({"attach_type":1,"pin_path":path}),
        )?;
        let link = sys::attach_selector(selector, &self.cgroup, &path)?;
        let id = sys::identity(link.as_fd())?.1;
        self.raw_links.push(link);
        self.hooks.push((1, program_id));
        receipt.acknowledge(
            entry,
            serde_json::json!({"link_id":id,"program_id":program_id,"pin_path":path}),
        )?;
        let (filter, program_id) = programs.filter();
        let filter_fd = filter.as_raw_fd();
        let entry = receipt.intent(
            "tun_filter",
            serde_json::json!({"ifindex":config.ifindex,"attachment":config.attachment}),
        )?;
        // The ioctl copies the u32 FD and takes its own program reference.
        let result = unsafe { libc::ioctl(fd, libc::TUNSETFILTEREBPF, &filter_fd) };
        ensure!(
            result == 0,
            "TUNSETFILTEREBPF: {}",
            std::io::Error::last_os_error()
        );
        receipt.acknowledge(entry, serde_json::json!({"program_id":program_id,"ifindex":config.ifindex,"attachment":config.attachment}))?;
        self.raw = Some(programs);
        Ok(())
    }

    fn identity_canary(&self, receipt: &mut Receipt) -> anyhow::Result<()> {
        let intent =
            receipt.intent("identity_canary", serde_json::json!({"map":"HOST_SOCKETS"}))?;
        let bank = HostSocketBank::map(self.map("HOST_SOCKETS")?)?;
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        let mut cookie = 0u64;
        let mut len = 8u32;
        ensure!(
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_COOKIE,
                    (&mut cookie as *mut u64).cast(),
                    &mut len,
                )
            } == 0,
            "TUN identity SO_COOKIE: {}",
            std::io::Error::last_os_error()
        );
        ensure!(len == 8 && cookie != 0, "TUN identity canary cookie");
        let key = (cookie & (HOST_SOCKET_BUCKETS as u64 - 1)) as u32;
        let before = bank.read(key)?;
        let slot = before
            .value
            .iter()
            .find(|entry| entry.cookie == cookie)
            .context("TUN create capture canary missing")?;
        ensure!(
            slot.pid == std::process::id()
                && slot.flags & HOST_SOCKET_PROCESS_PRESENT != 0
                && slot.socket_address != 0,
            "TUN identity canary process mismatch"
        );
        drop(socket);
        ensure!(
            !bank
                .read(key)?
                .value
                .iter()
                .any(|entry| entry.cookie == cookie),
            "TUN actual final-free canary failed"
        );
        receipt.acknowledge(intent, serde_json::json!({"socket_cookie":cookie,"bucket":key,"pid":slot.pid,"captured":true,"retired":true}))?;
        Ok(())
    }

    pub fn pname_support(&self) -> PnameSupport {
        match self.mode {
            PnameCaptureMode::Argv0 => PnameSupport::HostFull,
            PnameCaptureMode::Comm => PnameSupport::HostThreadName,
        }
    }

    pub fn memory_bytes(&self) -> anyhow::Result<usize> {
        let cpus = aya::util::nr_cpus().map_err(|(_, error)| error)?.get() as usize;
        ensure!(
            cpus <= 4096,
            "TUN possible CPU count exceeds identity allocation bound"
        );
        let mut bytes = 0usize;
        let mut add = |value: usize| -> anyhow::Result<()> {
            bytes = bytes
                .checked_add(value)
                .context("TUN kernel allocation bound overflow")?;
            Ok(())
        };
        for (name, _) in self.bpf.maps() {
            let fd = self.map(name)?;
            let info = syscall::raw_map_info(fd.as_raw_fd())?;
            let value = usize::try_from(info.value_size)?.div_ceil(8) * 8;
            let entries = usize::try_from(info.max_entries)?;
            let backing = if info.type_ == 22 {
                (entries + 1)
                    .checked_mul(value)
                    .context("TUN queue backing")?
            } else {
                entries
                    .checked_mul(value)
                    .and_then(|x| x.checked_mul(if info.type_ == 6 { cpus as usize } else { 1 }))
                    .context("TUN map backing")?
            };
            let rounded = backing.checked_add(4095).context("TUN map rounding")? / 4096 * 4096;
            // A 64 KiB per-map slab/header ceiling covers the admitted ARRAY/QUEUE kinds.
            add(honk_xsk::kernel_memory_bytes(fd)?
                .max(rounded)
                .checked_add(65536 + 8192)
                .context("TUN map allocation overhead")?)?;
        }
        for (_, program) in self.bpf.programs() {
            if let Ok(fd) = program.fd() {
                add(program_allocation(fd.as_fd())?)?;
            }
        }
        if let Some(raw) = &self.raw {
            for (_, fd, _) in raw.programs() {
                add(program_allocation(fd)?)?;
            }
        }
        add((self.links.len() + self.raw_links.len())
            .checked_mul(65536)
            .context("TUN link allocation bound")?)?;
        add(self
            .btf_bytes
            .checked_mul(4)
            .and_then(|x| x.checked_add(65536))
            .context("TUN object BTF allocation bound")?)?;
        Ok(bytes)
    }
}

fn program_allocation(fd: BorrowedFd<'_>) -> anyhow::Result<usize> {
    #[repr(C)]
    struct Info {
        kind: u32,
        id: u32,
        tag: [u8; 8],
        jited_len: u32,
        translated_len: u32,
    }
    #[repr(C)]
    struct Attr {
        fd: u32,
        length: u32,
        info: u64,
    }
    let mut info = Info {
        kind: 0,
        id: 0,
        tag: [0; 8],
        jited_len: 0,
        translated_len: 0,
    };
    sys::bpf(
        15,
        &mut Attr {
            fd: fd.as_raw_fd() as u32,
            length: size_of::<Info>() as u32,
            info: (&mut info as *mut Info) as u64,
        },
    )?;
    ensure!(
        info.id != 0
            && info.translated_len > 0
            && info.translated_len <= 1 << 20
            && info.jited_len > 0
            && info.jited_len <= 1 << 20,
        "TUN program allocation readback unavailable/out of bound"
    );
    let reported = honk_xsk::kernel_memory_bytes(fd)?;
    usize::try_from(info.translated_len)?
        .checked_mul(3)
        .and_then(|x| x.checked_add(info.jited_len as usize))
        .and_then(|x| x.checked_add(262144))
        .map(|bound| bound.max(reported))
        .context("TUN program allocation bound overflow")
}

fn validate_object(bytes: &[u8]) -> anyhow::Result<usize> {
    let object = aya_obj::Object::parse(bytes)?;
    let data = object
        .btf
        .as_ref()
        .context("TUN narrow object BTF missing")?
        .to_bytes();
    let btf = Btf::parse(&data).context("TUN narrow BTF invalid")?;
    ensure!(
        object.maps.len() <= 12 && object.programs.len() == 11,
        "TUN narrow object inventory bound"
    );
    for (name, map) in &object.maps {
        ensure!(
            map.pinning() == aya_obj::maps::PinningType::None,
            "TUN implicit pinning forbidden"
        );
        ensure!(
            name.starts_with('.')
                || matches!(
                    name.as_str(),
                    "HOST_SOCKETS"
                        | "HOST_SOCKET_LOCKS"
                        | "HOST_GATE"
                        | "HOST_SEQUENCE"
                        | "HOST_IDENTITY_STATS"
                        | "TUN_PACKETS"
                        | "TUN_FREE"
                        | "TUN_OWNER"
                        | "TUN_READ_WINDOW"
                ),
            "foreign map in TUN narrow object: {name}"
        );
    }
    let map_type = |name: &str| -> anyhow::Result<u32> {
        let Some(aya_obj::maps::Map::Btf(map)) = object.maps.get(name) else {
            anyhow::bail!("TUN typed map missing: {name}")
        };
        Ok(map.def.btf_value_type_id)
    };
    host_bank::validate_btf(
        &btf,
        map_type("HOST_SOCKETS")?,
        map_type("HOST_SOCKET_LOCKS")?,
    )?;
    for (name, size, fields) in [
        (
            "TUN_PACKETS",
            192,
            &[
                ("state", 0, 8),
                ("packet_id", 8, 8),
                ("owner_epoch", 16, 8),
                ("original_skb_address", 24, 8),
                ("captured_ns", 32, 8),
                ("expires_ns", 40, 8),
                ("attachment", 48, 8),
                ("netns_cookie", 56, 8),
                ("output_ifindex", 64, 4),
                ("original_record_len", 68, 4),
                ("source_kind", 72, 4),
                ("representation_flags", 76, 4),
                ("source", 80, 80),
                ("original_truesize", 160, 4),
                ("original_ingress_ifindex", 164, 4),
                ("claiming_read_id", 168, 8),
                ("reserved", 176, 16),
            ][..],
        ),
        (
            "TUN_READ_WINDOW",
            512,
            &[
                ("magic", 0, 4),
                ("version", 4, 2),
                ("extent", 6, 2),
                ("phase", 8, 8),
                ("fatal", 16, 8),
                ("owner_epoch", 24, 8),
                ("attachment", 32, 8),
                ("netns_cookie", 40, 8),
                ("read_id", 48, 8),
                ("requested_extent", 56, 8),
                ("output_ifindex", 64, 4),
                ("reader_tid", 68, 4),
                ("actual_task_address", 72, 8),
                ("actual_leader_start_boottime", 80, 8),
                ("actual_file_address", 88, 8),
                ("actual_tfile_address", 96, 8),
                ("actual_tun_address", 104, 8),
                ("actual_iocb_address", 112, 8),
                ("actual_iter_address", 120, 8),
                ("outer_entry_count", 128, 8),
                ("copy_entry_count", 136, 8),
                ("copy_exit_count", 144, 8),
                ("outer_exit_count", 152, 8),
                ("packet_id", 160, 8),
                ("original_skb_address", 168, 8),
                ("captured_ns", 176, 8),
                ("expires_ns", 184, 8),
                ("packet_cell", 192, 4),
                ("original_record_len", 196, 4),
                ("source_kind", 200, 4),
                ("representation_flags", 204, 4),
                ("copy_offset", 208, 4),
                ("copy_length", 212, 4),
                ("copy_result", 216, 8),
                ("outer_result", 224, 8),
                ("witnesses", 232, 8),
                ("status", 240, 4),
                ("owner_tgid", 244, 4),
                ("source", 248, 80),
                ("acknowledged_read_id", 328, 8),
                ("actual_task_start_boottime", 336, 8),
                ("reserved", 344, 168),
            ][..],
        ),
        (
            "TUN_OWNER",
            256,
            &[
                ("magic", 0, 4),
                ("version", 4, 2),
                ("extent", 6, 2),
                ("gate", 8, 8),
                ("fatal", 16, 8),
                ("owner_epoch", 24, 8),
                ("attachment", 32, 8),
                ("netns_cookie", 40, 8),
                ("next_packet_id", 48, 8),
                ("bound_file_address", 56, 8),
                ("bound_tfile_address", 64, 8),
                ("bound_tun_address", 72, 8),
                ("bound_dev_address", 80, 8),
                ("close_enter", 88, 8),
                ("close_exit", 96, 8),
                ("close_file_address", 104, 8),
                ("close_tfile_address", 112, 8),
                ("close_tun_address", 120, 8),
                ("output_ifindex", 128, 4),
                ("owner_tgid", 132, 4),
                ("vnet_header_size", 136, 4),
                ("tun_flags", 140, 4),
                ("refusal_count", 144, 8),
                ("accepted_count", 152, 8),
                ("retired_count", 160, 8),
                ("close_task_address", 168, 8),
                ("reserved", 176, 80),
            ][..],
        ),
    ] {
        let id = map_type(name)?;
        structure(&btf, id, size, fields)?;
        pod(&btf, id, 0)?;
        if name != "TUN_OWNER" {
            let at = btf
                .resolve_composite(id)
                .context("TUN source-bearing value")?;
            let (source, _) = btf
                .direct_member(at, "source")
                .context("TUN source payload")?;
            structure(
                &btf,
                source,
                80,
                &[
                    ("netns_cookie", 0, 8),
                    ("attachment", 8, 8),
                    ("socket_cookie", 16, 8),
                    ("return_generation", 24, 8),
                    ("output_ifindex", 32, 4),
                    ("skb_mark", 36, 4),
                    ("socket_mark", 40, 4),
                    ("pid", 44, 4),
                    ("pname", 48, 16),
                    ("flags", 64, 4),
                    ("stage", 68, 2),
                    ("family", 70, 2),
                    ("operation_incarnation", 72, 8),
                ],
            )?;
        }
    }
    let sequence = map_type("HOST_SEQUENCE")?;
    structure(
        &btf,
        sequence,
        16,
        &[("lock", 0, 4), ("padding", 4, 4), ("value", 8, 8)],
    )?;
    for name in ["HOST_GATE", "HOST_IDENTITY_STATS", "TUN_FREE"] {
        let id = map_type(name)?;
        pod(&btf, id, 0)?;
        ensure!(
            btf.type_size(id) == Some(if name == "HOST_IDENTITY_STATS" { 8 } else { 4 }),
            "TUN scalar map type"
        );
    }
    Ok(data.len())
}
fn structure(btf: &Btf<'_>, id: u32, size: u32, fields: &[(&str, u32, u32)]) -> anyhow::Result<()> {
    let at = btf.resolve_composite(id).context("TUN ABI structure")?;
    ensure!(
        btf.kind(at) == Some(4)
            && btf.u32_at(at + 8) == Some(size)
            && btf.u32_at(at + 4) == Some((4 << 24) | fields.len() as u32),
        "TUN structure extent/member count"
    );
    for &(name, offset, width) in fields {
        let (member, actual) = btf
            .direct_member(at, name)
            .with_context(|| format!("TUN ABI field {name}"))?;
        ensure!(
            actual == offset && btf.type_size(member) == Some(width),
            "TUN ABI field extent: {name}"
        );
    }
    Ok(())
}
fn pod(btf: &Btf<'_>, id: u32, depth: u8) -> anyhow::Result<u32> {
    ensure!(depth < 8, "TUN recursive ABI depth");
    let at = btf.resolve_modifiers(id).context("TUN ABI member type")?;
    let size = match btf.kind(at) {
        Some(1) => {
            let size = btf.u32_at(at + 8).context("TUN integer size")?;
            ensure!(
                matches!(size, 1 | 2 | 4 | 8)
                    && btf
                        .u32_at(at + 12)
                        .is_some_and(|x| x & 0xffffff == size * 8),
                "TUN complete integer ABI"
            );
            size
        }
        Some(3) => {
            let element = btf.u32_at(at + 12).context("TUN array element")?;
            let count = btf.u32_at(at + 20).context("TUN array count")?;
            pod(btf, element, depth + 1)?
                .checked_mul(count)
                .context("TUN array extent")?
        }
        Some(4) => {
            let info = btf.u32_at(at + 4).context("TUN struct information")?;
            ensure!(
                info >> 31 == 0
                    && btf.string(btf.u32_at(at).context("TUN type name")?)
                        != Some("bpf_spin_lock"),
                "TUN lock/bitfield in filter payload"
            );
            let mut end = 0;
            for index in 0..(info & 0xffff) as usize {
                let pos = at + 12 + index * 12;
                ensure!(
                    btf.u32_at(pos + 8) == Some(end * 8),
                    "TUN implicit ABI padding"
                );
                end = end
                    .checked_add(pod(
                        btf,
                        btf.u32_at(pos + 4).context("TUN member type")?,
                        depth + 1,
                    )?)
                    .context("TUN struct extent overflow")?;
            }
            ensure!(btf.u32_at(at + 8) == Some(end), "TUN implicit tail padding");
            end
        }
        _ => anyhow::bail!("non-POD TUN filter map ABI"),
    };
    Ok(size)
}
