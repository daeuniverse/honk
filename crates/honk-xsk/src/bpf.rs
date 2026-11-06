use std::io;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use aya_obj::btf::{Btf, BtfKind};

use crate::{Capture, Protocol};

mod general;

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_PROG_LOAD: u32 = 5;
const BPF_OBJ_PIN: u32 = 6;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
const BPF_LINK_CREATE: u32 = 28;
const BPF_LINK_UPDATE: u32 = 29;
const BPF_PROG_TYPE_XDP: u32 = 6;
const BPF_XDP: u32 = 37;
const BPF_LINK_TYPE_XDP: u32 = 6;
const BPF_F_REPLACE: u32 = 4;
const BPF_F_PATH_FD: u32 = 1 << 14;
const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1;
const XDP_FLAGS_REPLACE: u32 = 1 << 4;
const XDP_FLAGS_DRV_MODE: u32 = 4;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const MAX_QUEUES: u32 = 256;

#[repr(C)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
}

#[repr(C)]
struct MapElemAttr {
    map_fd: u32,
    reserved: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
struct LinkCreateAttr {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    flags: u32,
}

#[repr(C)]
struct LinkUpdateAttr {
    link_fd: u32,
    new_prog_fd: u32,
    flags: u32,
    old_prog_fd: u32,
}

#[repr(C)]
#[derive(Default)]
struct ProgInfo {
    kind: u32,
    id: u32,
}

#[repr(C)]
#[derive(Default)]
struct LinkInfo {
    kind: u32,
    id: u32,
    prog_id: u32,
    reserved: u32,
    ifindex: u32,
    tail_padding: u32,
}

fn bpf<T>(command: u32, attr: &mut T) -> io::Result<RawFd> {
    // SAFETY: callers supply the command's repr(C) UAPI layout and keep every
    // referenced buffer alive and appropriately readable/writable through this call.
    let result = unsafe { libc::syscall(libc::SYS_bpf, command, attr as *mut T, size_of::<T>()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        i32::try_from(result).map_err(|_| io::Error::other("BPF syscall result exceeds RawFd"))
    }
}

fn bpf_fd<T>(command: u32, attr: &mut T) -> io::Result<OwnedFd> {
    let fd = bpf(command, attr)?;
    // SAFETY: these commands return a newly owned descriptor on success.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn object_info<T>(fd: BorrowedFd<'_>, info: &mut T) -> io::Result<()> {
    let mut attr = InfoAttr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: size_of::<T>() as u32,
        info: info as *mut T as u64,
    };
    bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr)?;
    if (attr.info_len as usize) < size_of::<T>() {
        return Err(invalid_data("short BPF object information"));
    }
    Ok(())
}

fn object_name(name: &[u8]) -> [u8; 16] {
    let mut result = [0; 16];
    assert!(name.len() < result.len());
    result[..name.len()].copy_from_slice(name);
    result
}

fn create_map(kind: u32, value_size: u32, entries: u32, name: &[u8]) -> io::Result<OwnedFd> {
    bpf_fd(
        BPF_MAP_CREATE,
        &mut MapCreateAttr {
            map_type: kind,
            key_size: 4,
            value_size,
            max_entries: entries,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: object_name(name),
        },
    )
}

fn map_attr(fd: BorrowedFd<'_>, key: &u32, value: u64) -> MapElemAttr {
    MapElemAttr {
        map_fd: fd.as_raw_fd() as u32,
        reserved: 0,
        key: key as *const u32 as u64,
        value,
        flags: 0,
    }
}

pub struct Programs {
    counters: OwnedFd,
    xsks: OwnedFd,
    discover: OwnedFd,
    data: OwnedFd,
    discover_id: u32,
    data_id: u32,
    queues: u32,
}

impl Programs {
    pub fn load_general(
        capture: &crate::capture::GeneralCapture,
        queues: u32,
        ipv4_broadcasts: &[std::net::Ipv4Addr],
    ) -> io::Result<Self> {
        validate_queues(queues)?;
        if !capture.authority.is_valid()
            || capture.bypass_mark == 0
            || capture.bypass_mark & honk_ebpf_common::CLASSIFIED_MARK != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid XDP capture authority or bypass mark",
            ));
        }
        let counters = create_map(2, 8, queues + 4, b"honk_xdp_count")?;
        let xsks = create_map(17, 4, queues, b"honk_xdp_xsks")?;
        let mut log = vec![0; 1 << 20];
        let vlan_kfunc = if capture.vlan_metadata {
            Some(
                Btf::from_sys_fs()
                    .and_then(|btf| {
                        btf.id_by_type_name_kind("bpf_xdp_metadata_rx_vlan_tag", BtfKind::Func)
                    })
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::Unsupported,
                            format!("RX VLAN kfunc BTF: {error}"),
                        )
                    })?,
            )
        } else {
            None
        };
        let (discover, discover_id) = load_program(
            &general::build(
                capture,
                ipv4_broadcasts,
                queues,
                counters.as_raw_fd(),
                xsks.as_raw_fd(),
                false,
                vlan_kfunc,
            )?,
            b"honk_xdp_guard",
            &mut log,
        )?;
        let (data, data_id) = load_program(
            &general::build(
                capture,
                ipv4_broadcasts,
                queues,
                counters.as_raw_fd(),
                xsks.as_raw_fd(),
                true,
                vlan_kfunc,
            )?,
            b"honk_xdp_data",
            &mut log,
        )?;
        Ok(Self {
            counters,
            xsks,
            discover,
            data,
            discover_id,
            data_id,
            queues,
        })
    }
}

#[derive(Debug)]
pub struct CaptureCounters {
    pub per_queue: Vec<u64>,
    pub fragments: u64,
    pub options: u64,
    pub malformed: u64,
}

impl Programs {
    pub fn load(capture: &Capture, queues: u32) -> io::Result<Self> {
        validate_queues(queues)?;
        let counters = create_map(2, 8, queues + 4, b"honk_x0_count")?;
        let xsks = create_map(17, 4, queues, b"honk_x0_xsks")?;
        let mut log = vec![0; 1 << 20];
        let (discover, discover_id) = load_program(
            &build_program(
                capture,
                queues,
                counters.as_raw_fd(),
                xsks.as_raw_fd(),
                false,
            )?,
            b"honk_x0_disc",
            &mut log,
        )?;
        let (data, data_id) = load_program(
            &build_program(
                capture,
                queues,
                counters.as_raw_fd(),
                xsks.as_raw_fd(),
                true,
            )?,
            b"honk_x0_data",
            &mut log,
        )?;
        Ok(Self {
            counters,
            xsks,
            discover,
            data,
            discover_id,
            data_id,
            queues,
        })
    }

    pub fn discover_prog_id(&self) -> u32 {
        self.discover_id
    }

    pub fn data_prog_id(&self) -> u32 {
        self.data_id
    }

    pub fn counters(&self) -> io::Result<CaptureCounters> {
        let mut per_queue = Vec::with_capacity(self.queues as usize);
        for queue in 0..self.queues {
            per_queue.push(self.counter(queue)?);
        }
        Ok(CaptureCounters {
            per_queue,
            fragments: self.counter(self.queues)?,
            options: self.counter(self.queues + 1)?,
            malformed: self.counter(self.queues + 2)?,
        })
    }

    /// Runtime metadata-preparation failures, not a preflight capability proof.
    /// Wire-only and legacy narrow-tuple programs reserve this slot but never increment it.
    pub fn metadata_failures(&self) -> io::Result<u64> {
        self.counter(self.queues + 3)
    }

    fn counter(&self, key: u32) -> io::Result<u64> {
        let mut value = 0u64;
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            &mut map_attr(self.counters.as_fd(), &key, &mut value as *mut u64 as u64),
        )?;
        Ok(value)
    }

    pub fn insert_xsk(&self, queue: u32, fd: BorrowedFd<'_>) -> io::Result<()> {
        self.check_queue(queue)?;
        let value = fd.as_raw_fd() as u32;
        bpf(
            BPF_MAP_UPDATE_ELEM,
            &mut map_attr(self.xsks.as_fd(), &queue, &value as *const u32 as u64),
        )?;
        Ok(())
    }

    pub fn delete_xsk(&self, queue: u32) -> io::Result<()> {
        self.check_queue(queue)?;
        match bpf(
            BPF_MAP_DELETE_ELEM,
            &mut map_attr(self.xsks.as_fd(), &queue, 0),
        ) {
            Ok(_) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn check_queue(&self, queue: u32) -> io::Result<()> {
        if queue >= self.queues {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XSK queue exceeds capture map",
            ))
        } else {
            Ok(())
        }
    }
}

fn validate_queues(queues: u32) -> io::Result<()> {
    if !(1..=MAX_QUEUES).contains(&queues) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RX queue count must be 1..=256",
        ));
    }
    Ok(())
}

fn load_program(program: &Program, name: &[u8], log: &mut [u8]) -> io::Result<(OwnedFd, u32)> {
    log.fill(0);
    let mut attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_XDP,
        insn_cnt: program.len as u32,
        insns: program.insns.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: program.flags,
        prog_name: object_name(name),
        prog_ifindex: program.ifindex,
        expected_attach_type: BPF_XDP,
    };
    let fd = bpf_fd(BPF_PROG_LOAD, &mut attr).map_err(|error| {
        let length = log.iter().position(|&byte| byte == 0).unwrap_or(log.len());
        io::Error::new(
            error.kind(),
            format!(
                "BPF_PROG_LOAD {}: {error}\n{}",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(&log[..length]),
            ),
        )
    })?;
    let mut info = ProgInfo::default();
    object_info(fd.as_fd(), &mut info)?;
    if info.kind != BPF_PROG_TYPE_XDP || info.id == 0 {
        return Err(invalid_data("XDP program identity readback mismatch"));
    }
    Ok((fd, info.id))
}

/// Native netdev-held XDP custody for the daemon, independent of process lifetime.
/// `guard` and `data` are exclusively pinned programs in the private bpffs root.
/// Drop and errors never detach or unpin; operators must quiesce sources before
/// detaching the netdev program, then remove these pins before restarting.
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
        set_xdp(ifindex, programs.discover.as_raw_fd(), None)?;
        require_native(xdp_state(ifindex)?, programs.discover_id)?;
        Ok(Self {
            ifindex,
            discover_id: programs.discover_id,
            data_id: programs.data_id,
        })
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

fn private_bpffs(path: &Path) -> io::Result<OwnedFd> {
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

fn pin_program(
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpState {
    pub attached: u8,
    pub prog_id: u32,
    pub drv_prog_id: u32,
    pub skb_prog_id: u32,
    pub hw_prog_id: u32,
    pub flags: u32,
}

fn require_native(state: XdpState, program: u32) -> io::Result<XdpState> {
    if state.attached != 1
        || state.prog_id != program
        || state.drv_prog_id != program
        || state.skb_prog_id != 0
        || state.hw_prog_id != 0
    {
        return Err(invalid_data("native DRV XDP attachment readback mismatch"));
    }
    Ok(state)
}

pub fn xdp_absent(ifindex: u32) -> io::Result<bool> {
    let state = xdp_state(ifindex)?;
    Ok(state.attached == 0
        && state.prog_id == 0
        && state.drv_prog_id == 0
        && state.skb_prog_id == 0
        && state.hw_prog_id == 0)
}

fn validate_ifindex(ifindex: u32) -> io::Result<()> {
    if ifindex == 0 || ifindex > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid XDP interface index",
        ));
    }
    Ok(())
}

pub fn xdp_state(ifindex: u32) -> io::Result<XdpState> {
    validate_ifindex(ifindex)?;
    let mut request = [0u8; 32];
    request[..4].copy_from_slice(&32u32.to_ne_bytes());
    request[4..6].copy_from_slice(&18u16.to_ne_bytes());
    request[6..8].copy_from_slice(&1u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[20..24].copy_from_slice(&(ifindex as i32).to_ne_bytes());
    exchange_netlink(&request, |bytes| parse_link_messages(bytes, 1, ifindex))
}

fn xdp_update_request(ifindex: u32, program: RawFd, expected: Option<RawFd>) -> ([u8; 60], usize) {
    let mut request = [0u8; 60];
    let length = if expected.is_some() { 60 } else { 52 };
    request[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&19u16.to_ne_bytes()); // RTM_SETLINK
    request[6..8].copy_from_slice(&5u16.to_ne_bytes()); // REQUEST | ACK
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[20..24].copy_from_slice(&(ifindex as i32).to_ne_bytes());
    request[32..34].copy_from_slice(&((length - 32) as u16).to_ne_bytes());
    request[34..36].copy_from_slice(&(43u16 | 0x8000).to_ne_bytes()); // IFLA_XDP
    let flags = XDP_FLAGS_DRV_MODE
        | if expected.is_some() {
            XDP_FLAGS_REPLACE
        } else {
            XDP_FLAGS_UPDATE_IF_NOEXIST
        };
    for (offset, kind, value) in [(36, 1u16, program as u32), (44, 3, flags)] {
        request[offset..offset + 2].copy_from_slice(&8u16.to_ne_bytes());
        request[offset + 2..offset + 4].copy_from_slice(&kind.to_ne_bytes());
        request[offset + 4..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
    if let Some(expected) = expected {
        request[52..54].copy_from_slice(&8u16.to_ne_bytes());
        request[54..56].copy_from_slice(&8u16.to_ne_bytes()); // IFLA_XDP_EXPECTED_FD
        request[56..60].copy_from_slice(&expected.to_ne_bytes());
    }
    (request, length)
}

fn set_xdp(ifindex: u32, program: RawFd, expected: Option<RawFd>) -> io::Result<()> {
    let (request, length) = xdp_update_request(ifindex, program, expected);
    exchange_netlink(&request[..length], |bytes| parse_setlink_ack(bytes, 1))
}

fn parse_setlink_ack(mut bytes: &[u8], sequence: u32) -> io::Result<Option<()>> {
    // Reuse the readback parser's framing and kernel-errno validation.
    parse_link_messages(bytes, sequence, 0)?;
    while !bytes.is_empty() {
        let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        if u16::from_ne_bytes(bytes[4..6].try_into().unwrap()) == 2
            && u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) == sequence
        {
            return Ok(Some(()));
        }
        bytes = &bytes[aligned_extent(length, bytes.len())?..];
    }
    Ok(None)
}

fn exchange_netlink<T>(
    request: &[u8],
    mut parse: impl FnMut(&[u8]) -> io::Result<Option<T>>,
) -> io::Result<T> {
    // SAFETY: socket has no pointer arguments and returns a newly owned descriptor.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is the newly created descriptor, transferred exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: an all-zero sockaddr_nl is valid before setting its family.
    let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: local points to a complete sockaddr_nl for the supplied length.
    if unsafe {
        libc::bind(
            raw,
            (&local as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let kernel = local;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: request and kernel are live buffers matching their supplied lengths.
        let sent = unsafe {
            libc::sendto(
                raw,
                request.as_ptr().cast(),
                request.len(),
                libc::MSG_DONTWAIT,
                (&kernel as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent >= 0 {
            if sent as usize != request.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short route netlink send",
                ));
            }
            break;
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) {
            return Err(error);
        }
        wait_netlink(fd.as_fd(), libc::POLLOUT, deadline)?;
    }
    let mut buffer = [0u8; 16384];
    loop {
        wait_netlink(fd.as_fd(), libc::POLLIN, deadline)?;
        let mut source = local;
        let mut source_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: buffer/source are writable for the lengths supplied to recvfrom.
        let received = unsafe {
            libc::recvfrom(
                raw,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                (&mut source as *mut libc::sockaddr_nl).cast(),
                &mut source_len,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
        let received = received as usize;
        if received == 0 || received > buffer.len() {
            return Err(invalid_data("empty or truncated route netlink datagram"));
        }
        if source_len as usize != size_of::<libc::sockaddr_nl>()
            || source.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || source.nl_pid != 0
        {
            return Err(invalid_data("route netlink reply is not from the kernel"));
        }
        if let Some(reply) = parse(&buffer[..received])? {
            return Ok(reply);
        }
    }
}

pub(crate) fn wait_netlink(
    fd: BorrowedFd<'_>,
    events: libc::c_short,
    deadline: Instant,
) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() && events & libc::POLLIN == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "route netlink deadline expired",
            ));
        }
        // RTM_SETLINK may execute synchronously inside sendto beyond the deadline.
        // Its queued ACK still owns the outcome; poll it once without extending the wait.
        let milliseconds = if remaining.is_zero() {
            0
        } else {
            remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32
        };
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: pollfd is a live single-element array for the duration of poll.
        let result = unsafe { libc::poll(&mut pollfd, 1, milliseconds) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("RTM_GETLINK socket poll error"));
        }
        if result > 0 && pollfd.revents & events != 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "route netlink deadline expired",
            ));
        }
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn aligned_extent(length: usize, remaining: usize) -> io::Result<usize> {
    let aligned = length
        .checked_add(3)
        .ok_or_else(|| invalid_data("netlink length overflow"))?
        & !3;
    if aligned > remaining && length != remaining {
        return Err(invalid_data("truncated netlink alignment padding"));
    }
    Ok(aligned.min(remaining))
}

pub(crate) fn attributes<'a>(
    mut bytes: &'a [u8],
    mut visit: impl FnMut(u16, &'a [u8]) -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid_data("truncated netlink attribute header"));
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        if length < 4 || length > bytes.len() {
            return Err(invalid_data("invalid netlink attribute extent"));
        }
        let advance = aligned_extent(length, bytes.len())?;
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff;
        visit(kind, &bytes[4..length])?;
        bytes = &bytes[advance..];
    }
    Ok(())
}

fn parse_xdp_attributes(bytes: &[u8]) -> io::Result<XdpState> {
    let mut state = XdpState::default();
    attributes(bytes, |kind, value| {
        if kind == 2 {
            if value.len() != 1 {
                return Err(invalid_data("invalid IFLA_XDP_ATTACHED extent"));
            }
            state.attached = value[0];
        } else if (3..=7).contains(&kind) {
            let value = u32::from_ne_bytes(
                value
                    .try_into()
                    .map_err(|_| invalid_data("invalid IFLA_XDP integer extent"))?,
            );
            match kind {
                3 => state.flags = value,
                4 => state.prog_id = value,
                5 => state.drv_prog_id = value,
                6 => state.skb_prog_id = value,
                7 => state.hw_prog_id = value,
                _ => unreachable!(),
            }
        }
        Ok(())
    })?;
    Ok(state)
}

fn parse_link_messages(
    mut bytes: &[u8],
    sequence: u32,
    ifindex: u32,
) -> io::Result<Option<XdpState>> {
    let mut found = None;
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(invalid_data("truncated netlink message header"));
        }
        let length = usize::try_from(u32::from_ne_bytes(bytes[..4].try_into().unwrap()))
            .map_err(|_| invalid_data("netlink message length exceeds usize"))?;
        if length < 16 || length > bytes.len() {
            return Err(invalid_data("invalid netlink message extent"));
        }
        let advance = aligned_extent(length, bytes.len())?;
        let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
        let actual_sequence = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        if actual_sequence == sequence {
            if flags & 0x10 != 0 {
                return Err(invalid_data("interrupted RTM_GETLINK reply"));
            }
            let body = &bytes[16..length];
            match kind {
                2 => {
                    let error = i32::from_ne_bytes(
                        body.get(..4)
                            .ok_or_else(|| invalid_data("truncated netlink error"))?
                            .try_into()
                            .unwrap(),
                    );
                    if error < 0 {
                        return Err(io::Error::from_raw_os_error(
                            error
                                .checked_neg()
                                .ok_or_else(|| invalid_data("invalid netlink errno"))?,
                        ));
                    }
                    if error != 0 {
                        return Err(invalid_data("invalid positive netlink errno"));
                    }
                }
                3 if found.is_none() => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "RTM_GETLINK did not return the interface",
                    ));
                }
                4 => return Err(invalid_data("RTM_GETLINK overrun")),
                16 => {
                    if body.len() < 16 {
                        return Err(invalid_data("truncated ifinfomsg"));
                    }
                    let actual_index = i32::from_ne_bytes(body[4..8].try_into().unwrap());
                    if actual_index == ifindex as i32 {
                        let mut state = XdpState::default();
                        attributes(&body[16..], |kind, value| {
                            if kind == 43 {
                                state = parse_xdp_attributes(value)?;
                            }
                            Ok(())
                        })?;
                        if found.replace(state).is_some() {
                            return Err(invalid_data("duplicate RTM_GETLINK interface reply"));
                        }
                    }
                }
                _ => {}
            }
        }
        bytes = &bytes[advance..];
    }
    Ok(found)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Insn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

impl Insn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        let regs = if cfg!(target_endian = "little") {
            dst | src << 4
        } else {
            dst << 4 | src
        };
        Self {
            code,
            regs,
            off,
            imm,
        }
    }
}

const LD_MAP: u8 = 0x18;
const LDX_W: u8 = 0x61;
const LDX_H: u8 = 0x69;
const LDX_B: u8 = 0x71;
const ST_W: u8 = 0x62;
const STX_W: u8 = 0x63;
const ATOMIC_ADD_DW: u8 = 0xdb;
const MOV_K: u8 = 0xb7;
const MOV_X: u8 = 0xbf;
const ADD_K: u8 = 0x07;
const ADD_X: u8 = 0x0f;
const AND_K: u8 = 0x57;
const LSH_K: u8 = 0x67;
const RSH_K: u8 = 0x77;
const BE16: u8 = 0xdc;
const JA: u8 = 0x05;
const JEQ_K: u8 = 0x15;
const JGT_K: u8 = 0x25;
const JGT_X: u8 = 0x2d;
const JGE_K: u8 = 0x35;
const JSET_K: u8 = 0x45;
const JNE_K: u8 = 0x55;
const JNE_X: u8 = 0x5d;
const JNE32_K: u8 = 0x56;
const JLT_K: u8 = 0xa5;
const CALL: u8 = 0x85;
const EXIT: u8 = 0x95;

#[derive(Clone, Copy)]
#[repr(usize)]
enum Label {
    Pass,
    Drop,
    Fragments,
    Options,
    Malformed,
    CountDrop,
    Ipv4,
    Ipv6,
    Selected,
}

struct Program {
    insns: [Insn; 1024],
    len: usize,
    flags: u32,
    ifindex: u32,
}

struct Builder {
    program: Program,
    labels: [usize; 9],
    jumps: [(usize, Label); 256],
    jump_count: usize,
}

impl Builder {
    fn new() -> Self {
        Self {
            program: Program {
                insns: [Insn::default(); 1024],
                len: 0,
                flags: 0,
                ifindex: 0,
            },
            labels: [usize::MAX; 9],
            jumps: [(0, Label::Pass); 256],
            jump_count: 0,
        }
    }

    fn emit(&mut self, instruction: Insn) -> usize {
        let at = self.program.len;
        self.program.insns[at] = instruction;
        self.program.len += 1;
        at
    }

    fn jump(&mut self, instruction: Insn, target: Label) {
        let at = self.emit(instruction);
        self.jumps[self.jump_count] = (at, target);
        self.jump_count += 1;
    }

    fn label(&mut self, label: Label) {
        assert_eq!(self.labels[label as usize], usize::MAX);
        self.labels[label as usize] = self.program.len;
    }

    fn map_fd(&mut self, fd: RawFd) {
        self.emit(Insn::new(LD_MAP, 1, 1, 0, fd));
        self.emit(Insn::default());
    }

    fn bound(&mut self, length: i32, target: Label) {
        self.emit(Insn::new(MOV_X, 0, 6, 0, 0));
        self.emit(Insn::new(ADD_K, 0, 0, 0, length));
        self.jump(Insn::new(JGT_X, 0, 7, 0, 0), target);
    }

    fn count(&mut self, counters_fd: RawFd) {
        self.map_fd(counters_fd);
        self.emit(Insn::new(MOV_X, 2, 10, 0, 0));
        self.emit(Insn::new(ADD_K, 2, 0, 0, -4));
        self.emit(Insn::new(CALL, 0, 0, 0, 1));
        self.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        self.emit(Insn::new(MOV_K, 1, 0, 0, 1));
        self.emit(Insn::new(ATOMIC_ADD_DW, 0, 1, 0, 0));
    }

    fn finish(mut self) -> io::Result<Program> {
        for &(at, label) in &self.jumps[..self.jump_count] {
            let target = self.labels[label as usize];
            if target >= self.program.len {
                return Err(io::Error::other("unresolved XDP program label"));
            }
            let offset = isize::try_from(target).unwrap() - isize::try_from(at).unwrap() - 1;
            self.program.insns[at].off = i16::try_from(offset)
                .map_err(|_| io::Error::other("XDP jump offset exceeds i16"))?;
        }
        Ok(self.program)
    }
}

fn build_program(
    capture: &Capture,
    queues: u32,
    counters_fd: RawFd,
    xsks_fd: RawFd,
    data: bool,
) -> io::Result<Program> {
    validate_queues(queues)?;
    let mut b = Builder::new();
    b.emit(Insn::new(LDX_W, 6, 1, 0, 0));
    b.emit(Insn::new(LDX_W, 7, 1, 4, 0));
    b.emit(Insn::new(LDX_W, 8, 1, 16, 0));
    b.bound(14, Label::Pass);
    b.emit(Insn::new(LDX_H, 0, 6, 12, 0));
    b.jump(
        Insn::new(JNE_K, 0, 0, 0, u16::from_ne_bytes([8, 0]) as i32),
        Label::Pass,
    );
    b.bound(34, Label::Pass);
    b.emit(Insn::new(LDX_B, 0, 6, 23, 0));
    b.jump(
        Insn::new(JNE_K, 0, 0, 0, i32::from(capture.protocol.number())),
        Label::Pass,
    );
    b.emit(Insn::new(LDX_W, 0, 6, 26, 0));
    b.jump(
        Insn::new(
            JNE32_K,
            0,
            0,
            0,
            u32::from_ne_bytes(capture.client.ip().octets()) as i32,
        ),
        Label::Pass,
    );
    b.emit(Insn::new(LDX_W, 0, 6, 30, 0));
    b.jump(
        Insn::new(
            JNE32_K,
            0,
            0,
            0,
            u32::from_ne_bytes(capture.service.ip().octets()) as i32,
        ),
        Label::Pass,
    );
    // The exclusive IP/protocol fence must precede ports and MAC guards: later
    // fragments have no ports and must never reach the colocated kernel service.
    b.emit(Insn::new(LDX_H, 0, 6, 20, 0));
    b.jump(
        Insn::new(JSET_K, 0, 0, 0, u16::from_be(0x3fff) as i32),
        Label::Fragments,
    );
    b.emit(Insn::new(LDX_B, 0, 6, 14, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0x40), Label::Malformed);
    b.emit(Insn::new(LDX_B, 0, 6, 14, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0x0f));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 5), Label::Options);
    let l4_min = match capture.protocol {
        Protocol::Tcp => 20,
        Protocol::Udp => 8,
    };
    b.emit(Insn::new(LDX_H, 9, 6, 16, 0));
    b.emit(Insn::new(BE16, 9, 0, 0, 16));
    b.jump(Insn::new(JLT_K, 9, 0, 0, 20 + l4_min), Label::Malformed);
    b.jump(Insn::new(JGT_K, 9, 0, 0, 1500), Label::Malformed);
    b.emit(Insn::new(MOV_X, 0, 6, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 14));
    b.emit(Insn::new(ADD_X, 0, 9, 0, 0));
    b.jump(Insn::new(JGT_X, 0, 7, 0, 0), Label::Malformed);
    b.bound(34 + l4_min, Label::Malformed);
    match capture.protocol {
        Protocol::Tcp => {
            b.emit(Insn::new(LDX_B, 0, 6, 46, 0));
            b.emit(Insn::new(RSH_K, 0, 0, 0, 4));
            b.emit(Insn::new(LSH_K, 0, 0, 0, 2));
            b.jump(Insn::new(JLT_K, 0, 0, 0, 20), Label::Malformed);
            b.emit(Insn::new(ADD_K, 0, 0, 0, 20));
            b.jump(Insn::new(JGT_X, 0, 9, 0, 0), Label::Malformed);
        }
        Protocol::Udp => {
            b.emit(Insn::new(LDX_H, 0, 6, 38, 0));
            b.emit(Insn::new(BE16, 0, 0, 0, 16));
            b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
            b.emit(Insn::new(ADD_K, 1, 0, 0, -20));
            b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
        }
    }
    for (offset, port) in [(34, capture.client.port()), (36, capture.service.port())] {
        b.emit(Insn::new(LDX_H, 0, 6, offset, 0));
        b.jump(
            Insn::new(JNE_K, 0, 0, 0, i32::from(port.to_be())),
            Label::Pass,
        );
    }
    for (offset, mac) in [(0, capture.own_mac), (6, capture.peer_mac)] {
        b.emit(Insn::new(LDX_W, 0, 6, offset, 0));
        b.jump(
            Insn::new(
                JNE32_K,
                0,
                0,
                0,
                u32::from_ne_bytes(mac[..4].try_into().unwrap()) as i32,
            ),
            Label::Malformed,
        );
        b.emit(Insn::new(LDX_H, 0, 6, offset + 4, 0));
        b.jump(
            Insn::new(
                JNE_K,
                0,
                0,
                0,
                i32::from(u16::from_ne_bytes([mac[4], mac[5]])),
            ),
            Label::Malformed,
        );
    }
    b.jump(Insn::new(JGE_K, 8, 0, 0, queues as i32), Label::Malformed);
    b.emit(Insn::new(STX_W, 10, 8, -4, 0));
    b.count(counters_fd);
    if data {
        b.map_fd(xsks_fd);
        b.emit(Insn::new(MOV_X, 2, 8, 0, 0));
        b.emit(Insn::new(MOV_K, 3, 0, 0, XDP_DROP));
        b.emit(Insn::new(CALL, 0, 0, 0, 51));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    } else {
        b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
    }
    for (label, key) in [
        (Label::Fragments, queues),
        (Label::Options, queues + 1),
        (Label::Malformed, queues + 2),
    ] {
        b.label(label);
        b.emit(Insn::new(ST_W, 10, 0, -4, key as i32));
        b.jump(Insn::new(JA, 0, 0, 0, 0), Label::CountDrop);
    }
    b.label(Label::CountDrop);
    b.count(counters_fd);
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_DROP));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Pass);
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_PASS));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(protocol: Protocol) -> Capture {
        Capture {
            protocol,
            client: "10.10.10.251:41000".parse().unwrap(),
            service: "10.10.10.252:42000".parse().unwrap(),
            own_mac: [0x58, 0x47, 0xca, 0x74, 0xec, 0x9d],
            peer_mac: [0xba, 0xda, 0x2e, 0x00, 0x76, 0xa0],
        }
    }

    #[test]
    fn program_builder_rejects_invalid_queue_domains() {
        assert!(build_program(&capture(Protocol::Udp), 0, 10, 11, true).is_err());
        assert!(build_program(&capture(Protocol::Udp), 257, 10, 11, true).is_err());
        let mut unresolved = Builder::new();
        unresolved.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
        assert!(unresolved.finish().is_err());
    }

    #[test]
    fn persistent_pin_preflight_rejects_ordinary_filesystem_without_writes() {
        let error = private_bpffs(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "XDP pin root must be bpffs");
    }

    #[test]
    fn persistent_updates_encode_native_exclusion_and_kernel_comparison() {
        for expected in [None, Some(11)] {
            let (request, length) = xdp_update_request(7, 12, expected);
            assert_eq!(
                u32::from_ne_bytes(request[..4].try_into().unwrap()) as usize,
                length,
            );
            assert_eq!(u16::from_ne_bytes(request[4..6].try_into().unwrap()), 19);
            assert_eq!(u16::from_ne_bytes(request[6..8].try_into().unwrap()), 5);
            assert_eq!(i32::from_ne_bytes(request[20..24].try_into().unwrap()), 7);
            let mut outer = 0;
            attributes(&request[32..length], |kind, value| {
                outer += 1;
                assert_eq!(kind, 43);
                let mut fields = Vec::new();
                attributes(value, |kind, value| {
                    fields.push((kind, i32::from_ne_bytes(value.try_into().unwrap())));
                    Ok(())
                })?;
                assert_eq!(fields[0], (1, 12));
                assert_eq!(fields[1], (3, if expected.is_some() { 20 } else { 5 }));
                if let Some(expected) = expected {
                    assert_eq!(fields, [(1, 12), (3, 20), (8, expected)]);
                } else {
                    assert_eq!(fields, [(1, 12), (3, 5)]);
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(outer, 1);
        }
        let native = XdpState {
            attached: 1,
            prog_id: 12,
            drv_prog_id: 12,
            ..XdpState::default()
        };
        assert!(require_native(native, 12).is_ok());
        for foreign in [
            XdpState {
                prog_id: 13,
                ..native
            },
            XdpState {
                skb_prog_id: 13,
                ..native
            },
            XdpState {
                hw_prog_id: 13,
                ..native
            },
            XdpState {
                attached: 2,
                drv_prog_id: 0,
                skb_prog_id: 12,
                ..native
            },
            XdpState::default(),
        ] {
            assert!(require_native(foreign, 12).is_err());
        }
    }

    #[test]
    fn queued_kernel_setlink_ack_survives_an_expired_send_deadline() {
        // No interface index or name: the kernel must reject this without touching a link.
        let (request, length) = xdp_update_request(0, -1, Some(-1));
        // SAFETY: socket has scalar arguments and returns a unique owned descriptor.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        assert!(raw >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: the request and kernel address remain live during the synchronous send.
        assert_eq!(
            unsafe {
                libc::sendto(
                    raw,
                    request.as_ptr().cast(),
                    length,
                    0,
                    std::ptr::from_ref(&kernel).cast(),
                    size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            },
            length as isize
        );
        let deadline = Instant::now() - Duration::from_secs(1);
        wait_netlink(fd.as_fd(), libc::POLLIN, deadline).unwrap();
        let mut reply = [0u8; 512];
        // SAFETY: reply is writable for its whole extent; no sender address is requested.
        let received = unsafe {
            libc::recv(
                raw,
                reply.as_mut_ptr().cast(),
                reply.len(),
                libc::MSG_DONTWAIT,
            )
        };
        assert!(received >= 20);
        let error = parse_setlink_ack(&reply[..received as usize], 1).unwrap_err();
        assert!(matches!(
            error.raw_os_error(),
            Some(libc::EINVAL | libc::EPERM)
        ));
        assert_eq!(
            wait_netlink(fd.as_fd(), libc::POLLIN, deadline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            wait_netlink(fd.as_fd(), libc::POLLOUT, deadline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn persistent_updates_require_successful_matching_kernel_ack() {
        let mut ack = [0u8; 20];
        ack[..4].copy_from_slice(&20u32.to_ne_bytes());
        ack[4..6].copy_from_slice(&2u16.to_ne_bytes());
        ack[8..12].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(parse_setlink_ack(&ack, 1).unwrap(), Some(()));
        assert_eq!(parse_setlink_ack(&ack, 2).unwrap(), None);
        for end in 1..ack.len() {
            assert!(parse_setlink_ack(&ack[..end], 1).is_err());
        }
        for errno in [libc::EEXIST, libc::EBUSY, libc::EINVAL, libc::EOPNOTSUPP] {
            ack[16..20].copy_from_slice(&(-errno).to_ne_bytes());
            assert_eq!(
                parse_setlink_ack(&ack, 1).unwrap_err().raw_os_error(),
                Some(errno),
            );
        }
    }

    fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
        let length = 4 + value.len();
        bytes.extend_from_slice(&(length as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
    }

    #[test]
    fn netlink_readback_checks_nested_extents_and_native_identity() {
        let mut nested = Vec::new();
        attribute(&mut nested, 2, &[1]);
        attribute(&mut nested, 3, &4u32.to_ne_bytes());
        attribute(&mut nested, 4, &123u32.to_ne_bytes());
        attribute(&mut nested, 5, &123u32.to_ne_bytes());
        let mut reply = vec![0; 32];
        reply[4..6].copy_from_slice(&16u16.to_ne_bytes());
        reply[8..12].copy_from_slice(&1u32.to_ne_bytes());
        reply[20..24].copy_from_slice(&7i32.to_ne_bytes());
        attribute(&mut reply, 43 | 0x8000, &nested);
        let length = reply.len() as u32;
        reply[..4].copy_from_slice(&length.to_ne_bytes());
        let state = parse_link_messages(&reply, 1, 7).unwrap().unwrap();
        assert_eq!(require_native(state, 123).unwrap().flags, 4);
        assert!(require_native(state, 124).is_err());
        assert!(parse_link_messages(&reply, 2, 7).unwrap().is_none());
        assert!(parse_link_messages(&reply, 1, 8).unwrap().is_none());
        for end in 1..reply.len() {
            assert!(parse_link_messages(&reply[..end], 1, 7).is_err());
        }
        for bad in [
            &[3, 0, 2, 0][..],
            &[8, 0, 4, 0, 1][..],
            &[5, 0, 4, 0, 1][..],
        ] {
            assert!(parse_xdp_attributes(bad).is_err());
        }
        assert_eq!(size_of::<MapElemAttr>(), 32);
        assert_eq!(size_of::<ProgLoadAttr>(), 72);
        assert_eq!(size_of::<LinkCreateAttr>(), 16);
        assert_eq!(size_of::<LinkUpdateAttr>(), 16);
        assert_eq!(std::mem::offset_of!(LinkInfo, ifindex), 16);
    }
}
