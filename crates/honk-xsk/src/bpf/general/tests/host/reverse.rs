//! Bounded, guest-only ordinary Linux input through an owned private XSK carrier.
use super::*;
use std::fs::{File, OpenOptions};
use std::mem::size_of_val;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::unix::fs::OpenOptionsExt;

const CONTEXT: usize = 40;
const L3: usize = 14 + CONTEXT;
const V6_LOCAL: [u8; 16] = [0xfd, 0x42, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const V6_REMOTE: [u8; 16] = [0xfd, 0x42, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const GATE_SEEN: u32 = 0;
const HANDOFF: u32 = 1;
const PRIVATE_SEEN: u32 = 2;
const PRIVATE_MATCH: u32 = 3;
const NATIVE_SEEN: u32 = 4;
const BAD_FORMAT: u32 = 5;
const BAD_VERSION: u32 = 6;
const BAD_ATTACHMENT: u32 = 7;
const BAD_GENERATION: u32 = 8;
const BAD_PRIVATE: u32 = 9;
const BAD_TARGET: u32 = 10;
const BAD_FAMILY: u32 = 11;
const BAD_EXTENT: u32 = 12;
const GATE_ERROR: u32 = 13;
const COUNT_LEN: usize = 14;
const NONEXISTENT: u32 = 0x7fff_fffe;

fn syscall(result: i32) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn namespace_inode(kind: &str) -> io::Result<u64> {
    Ok(std::fs::metadata(format!("/proc/thread-self/ns/{kind}"))?.ino())
}

struct NamespaceScope {
    net: File,
    mount: File,
    net_inode: u64,
    mount_inode: u64,
}

impl NamespaceScope {
    fn enter(child: &File) -> io::Result<Self> {
        let scope = Self {
            net: File::open("/proc/thread-self/ns/net")?,
            mount: File::open("/proc/thread-self/ns/mnt")?,
            net_inode: namespace_inode("net")?,
            mount_inode: namespace_inode("mnt")?,
        };
        // Port queue discovery uses a mount-specific sysfs view. Never remount the wrapper's view.
        // SAFETY: unshare affects only this synchronous test thread's mount/FS context.
        syscall(unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_FS) })?;
        // SAFETY: C strings are static, flags are the mount UAPI, and no data is supplied.
        syscall(unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        })?;
        // SAFETY: child is an owned, inode-checked network namespace FD.
        syscall(unsafe { libc::setns(child.as_raw_fd(), libc::CLONE_NEWNET) })?;
        // SAFETY: this fresh private mount namespace owns the mount; sysfs selects the current netns.
        syscall(unsafe {
            libc::mount(
                c"sysfs".as_ptr(),
                c"/sys".as_ptr(),
                c"sysfs".as_ptr(),
                libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            )
        })?;
        ensure(
            namespace_inode("net")? == child.metadata()?.ino(),
            "child setns readback",
        )?;
        Ok(scope)
    }
}

impl Drop for NamespaceScope {
    fn drop(&mut self) {
        // A failed restoration cannot safely unwind into another test or command in the wrong namespace.
        // SAFETY: these FDs were captured from this thread before its scoped switch and remain owned.
        let restored = unsafe {
            libc::setns(self.net.as_raw_fd(), libc::CLONE_NEWNET) == 0
                && libc::setns(self.mount.as_raw_fd(), libc::CLONE_NEWNS) == 0
        };
        if !restored
            || namespace_inode("net").ok() != Some(self.net_inode)
            || namespace_inode("mnt").ok() != Some(self.mount_inode)
        {
            eprintln!(
                "Host reverse namespace restoration failed; retain wrapper custody until VM poweroff"
            );
            std::process::abort();
        }
    }
}

fn with_child<T>(child: &File, work: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let _scope = NamespaceScope::enter(child)?;
    work()
}

fn child_namespace(source: u64) -> io::Result<File> {
    let path = std::env::var("HONK_HOST_REVERSE_NETNS_PATH").map_err(io::Error::other)?;
    let suffix = path.strip_prefix("/run/netns/honk-reverse-").unwrap_or("");
    ensure(
        suffix.len() == 12 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "reverse namespace must be the wrapper-owned named pin",
    )?;
    let inode: u64 = std::env::var("HONK_HOST_REVERSE_NETNS_INODE")
        .map_err(io::Error::other)?
        .parse()
        .map_err(io::Error::other)?;
    let child = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)?;
    ensure(
        inode != source && inode != 0 && child.metadata()?.ino() == inode,
        "child namespace identity",
    )?;
    with_child(&child, || {
        ensure(
            command("ip", &["-o", "link", "show"])?.lines().count() == 1,
            "child must contain only loopback",
        )?;
        ensure(index("lo")? == 1, "child loopback identity")?;
        ensure(
            command("ip", &["-o", "address", "show"])?.trim().is_empty(),
            "child must have no addresses",
        )?;
        for family in ["-4", "-6"] {
            ensure(
                command("ip", &[family, "route", "show", "table", "all"])?
                    .trim()
                    .is_empty(),
                "child must have no routes",
            )?;
        }
        Ok(())
    })?;
    eprintln!("Host reverse child: path={path} inode={inode} wrapper_owned=true");
    Ok(child)
}

fn move_peer(ifindex: u32, child: &File) -> io::Result<()> {
    let mut request = [0u8; 40];
    request[..4].copy_from_slice(&40u32.to_ne_bytes());
    request[4..6].copy_from_slice(&16u16.to_ne_bytes()); // RTM_NEWLINK.
    request[6..8].copy_from_slice(&5u16.to_ne_bytes()); // REQUEST | ACK.
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    request[32..34].copy_from_slice(&8u16.to_ne_bytes());
    request[34..36].copy_from_slice(&28u16.to_ne_bytes()); // IFLA_NET_NS_FD.
    request[36..40].copy_from_slice(&child.as_raw_fd().to_ne_bytes());
    exchange_netlink(&request, |bytes| parse_setlink_ack(bytes, 1))
}

fn sysctl(key: &str, value: &str) -> io::Result<()> {
    let path = format!("/proc/sys/net/{key}");
    std::fs::write(&path, value)?;
    ensure(
        std::fs::read_to_string(path)?.trim() == value,
        "fixture sysctl readback",
    )
}

fn features_off(name: &str) -> io::Result<()> {
    command(
        "ethtool",
        &[
            "-K",
            name,
            "gro",
            "off",
            "lro",
            "off",
            "rx-gro-list",
            "off",
            "rx-udp-gro-forwarding",
            "off",
            "gso",
            "off",
            "tso",
            "off",
        ],
    )?;
    let features = command("ethtool", &["-k", name])?;
    for feature in [
        "generic-receive-offload",
        "large-receive-offload",
        "rx-gro-list",
        "rx-udp-gro-forwarding",
        "generic-segmentation-offload",
        "tcp-segmentation-offload",
    ] {
        ensure(
            features
                .lines()
                .any(|line| line.trim_start().starts_with(&format!("{feature}: off"))),
            "private receive aggregation readback",
        )?;
    }
    eprintln!("Host reverse private feature readback {name}:\n{features}");
    Ok(())
}

fn link_facts(name: &str, ifindex: u32, peer: u32, mac: [u8; 6]) -> io::Result<()> {
    ensure(
        index(name)? == ifindex
            && number(name, "ifindex")? == ifindex
            && number(name, "iflink")? == peer,
        "reverse link/peer identity",
    )?;
    ensure(
        number(name, "mtu")? == 1500 && number(name, "type")? == 1,
        "reverse Ethernet/MTU identity",
    )?;
    let path = Path::new("/sys/class/net").join(name);
    let expected = mac.map(|byte| format!("{byte:02x}")).join(":");
    ensure(
        std::fs::read_to_string(path.join("address"))?.trim() == expected,
        "reverse MAC identity",
    )?;
    let mut queues = Vec::new();
    for entry in std::fs::read_dir(path.join("queues"))? {
        queues.push(entry?.file_name());
    }
    queues.sort();
    ensure(
        queues
            == [
                std::ffi::OsString::from("rx-0"),
                std::ffi::OsString::from("tx-0"),
            ],
        "reverse sole queue zero",
    )?;
    for entry in std::fs::read_dir(path)? {
        let leaf = entry?.file_name();
        let leaf = leaf.to_string_lossy();
        ensure(
            !leaf.starts_with("upper_") && leaf != "master",
            "reverse foreign upper/master",
        )?;
    }
    ensure(
        command("tc", &["qdisc", "show", "dev", name])?
            .lines()
            .all(|line| line.starts_with("qdisc noqueue ")),
        "reverse foreign qdisc",
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReturnRecord {
    attachment: u64,
    generation: u64,
    target: u32,
    private_tx: u32,
    private_rx: u32,
}

impl ReturnRecord {
    fn context(self, ipv6: bool, length: usize) -> [u8; CONTEXT] {
        let mut bytes = [0; CONTEXT];
        bytes[..4].copy_from_slice(b"HRV1");
        bytes[4..6].copy_from_slice(&1u16.to_ne_bytes());
        bytes[6..8].copy_from_slice(&(CONTEXT as u16).to_ne_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&(if ipv6 { 6u32 } else { 4 }).to_ne_bytes());
        bytes[16..24].copy_from_slice(&self.attachment.to_ne_bytes());
        bytes[24..32].copy_from_slice(&self.generation.to_ne_bytes());
        bytes[32..36].copy_from_slice(&self.target.to_ne_bytes());
        bytes[36..40].copy_from_slice(&(length as u32).to_ne_bytes());
        bytes
    }
}

fn reason(b: &mut Builder, key: u32) {
    b.emit(Insn::new(MOV_K, 8, 0, 0, key as i32));
}

fn terminal(record: ReturnRecord, counts: RawFd) -> io::Result<Program> {
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    count(&mut b, counts, GATE_SEEN);
    reason(&mut b, BAD_FORMAT);
    for (offset, expected) in [
        (36, record.private_tx as i32),
        (40, record.private_tx as i32),
        (20, 0),
        (164, 0),
        (176, 0),
    ] {
        equal(&mut b, LDX_W, 9, offset, expected, Label::CountDrop);
    }
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 39)); // bpf_skb_pull_data.
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::CountDrop);
    b.emit(Insn::new(LDX_W, 6, 9, 76, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 80, 0));
    b.bound(L3 as i32, Label::CountDrop);
    bytes_equal(&mut b, 0, &TX_MAC, Label::CountDrop);
    bytes_equal(&mut b, 6, &RX_MAC, Label::CountDrop);
    let context = record.context(false, 0);
    bytes_equal(&mut b, 14, &context[..4], Label::CountDrop);
    bytes_equal(&mut b, 20, &context[6..12], Label::CountDrop);
    reason(&mut b, BAD_VERSION);
    bytes_equal(&mut b, 18, &context[4..6], Label::CountDrop);
    reason(&mut b, BAD_ATTACHMENT);
    bytes_equal(&mut b, 30, &context[16..24], Label::CountDrop);
    reason(&mut b, BAD_GENERATION);
    bytes_equal(&mut b, 38, &context[24..32], Label::CountDrop);
    reason(&mut b, BAD_PRIVATE);
    b.emit(Insn::new(LDX_W, 0, 6, 46, 0));
    b.jump(
        Insn::new(JEQ_K, 0, 0, 0, record.private_tx as i32),
        Label::CountDrop,
    );
    b.jump(
        Insn::new(JEQ_K, 0, 0, 0, record.private_rx as i32),
        Label::CountDrop,
    );
    reason(&mut b, BAD_TARGET);
    b.jump(
        Insn::new(JNE_K, 0, 0, 0, record.target as i32),
        Label::CountDrop,
    );
    reason(&mut b, BAD_EXTENT);
    b.emit(Insn::new(LDX_W, 0, 6, 50, 0));
    b.jump(Insn::new(JLT_K, 0, 0, 0, 28), Label::CountDrop);
    b.jump(
        Insn::new(JGT_K, 0, 0, 0, 1500 - CONTEXT as i32),
        Label::CountDrop,
    );
    b.emit(Insn::new(STX_W, 10, 0, -16, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, L3 as i32));
    b.emit(Insn::new(LDX_W, 1, 9, 0, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::CountDrop);
    reason(&mut b, BAD_FAMILY);
    b.emit(Insn::new(LDX_W, 0, 6, 26, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 4), Label::Ipv4);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 6), Label::CountDrop);
    bytes_equal(&mut b, 12, &0x86ddu16.to_be_bytes(), Label::CountDrop);
    b.bound((L3 + 40) as i32, Label::CountDrop);
    equal(&mut b, LDX_B, 6, L3 as i16, 0x60, Label::CountDrop);
    equal(&mut b, LDX_B, 6, (L3 + 6) as i16, 17, Label::CountDrop);
    reason(&mut b, BAD_EXTENT);
    b.emit(Insn::new(LDX_H, 0, 6, (L3 + 4) as i16, 0));
    b.emit(Insn::new(BE16, 0, 0, 0, 16));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 40));
    b.emit(Insn::new(LDX_W, 1, 10, -16, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::CountDrop);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Selected);
    b.label(Label::Ipv4);
    bytes_equal(&mut b, 12, &0x0800u16.to_be_bytes(), Label::CountDrop);
    b.bound((L3 + 20) as i32, Label::CountDrop);
    equal(&mut b, LDX_B, 6, L3 as i16, 0x45, Label::CountDrop);
    equal(&mut b, LDX_B, 6, (L3 + 9) as i16, 17, Label::CountDrop);
    b.emit(Insn::new(LDX_H, 0, 6, (L3 + 6) as i16, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, i32::from(0x3fffu16.to_be())));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::CountDrop);
    reason(&mut b, BAD_EXTENT);
    b.emit(Insn::new(LDX_H, 0, 6, (L3 + 2) as i16, 0));
    b.emit(Insn::new(BE16, 0, 0, 0, 16));
    b.emit(Insn::new(LDX_W, 1, 10, -16, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::CountDrop);
    b.label(Label::Selected);
    reason(&mut b, GATE_ERROR);
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, -(CONTEXT as i32)));
    b.emit(Insn::new(MOV_K, 3, 0, 0, 1)); // BPF_ADJ_ROOM_MAC.
    b.emit(Insn::new(MOV_K, 4, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 50));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::CountDrop);
    b.emit(Insn::new(LDX_W, 6, 9, 76, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 80, 0));
    b.bound(14, Label::CountDrop);
    for (offset, byte) in SOURCE_MAC.into_iter().chain(SOURCE_PEER_MAC).enumerate() {
        b.emit(Insn::new(0x72, 6, 0, offset as i16, i32::from(byte))); // ST_B.
    }
    count(&mut b, counts, HANDOFF);
    b.emit(Insn::new(MOV_K, 1, 0, 0, record.target as i32));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 1)); // BPF_F_INGRESS.
    b.emit(Insn::new(CALL, 0, 0, 0, 23));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 7), Label::CountDrop);
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::CountDrop);
    b.emit(Insn::new(STX_W, 10, 8, -4, 0));
    b.count(counts);
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, 2)); // TCX_DROP, never NEXT/PASS.
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

fn observer(ifindex: u32, counts: RawFd, private: bool) -> io::Result<Program> {
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    if private {
        count(&mut b, counts, PRIVATE_SEEN);
    }
    equal(&mut b, LDX_W, 9, 12, ifindex as i32, Label::Drop);
    b.emit(Insn::new(LDX_W, 6, 9, 0, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 4, 0));
    b.bound(if private { L3 as i32 } else { 14 }, Label::Drop);
    if private {
        bytes_equal(&mut b, 14, b"HRV1", Label::Drop);
    } else {
        bytes_equal(&mut b, 0, &SOURCE_MAC, Label::Drop);
        bytes_equal(&mut b, 6, &SOURCE_PEER_MAC, Label::Drop);
    }
    count(
        &mut b,
        counts,
        if private { PRIVATE_MATCH } else { NATIVE_SEEN },
    );
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_DROP));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

fn attach_terminal(
    program: &Program,
    ifindex: u32,
    log: &mut [u8],
) -> io::Result<(OwnedFd, OwnedFd, u32)> {
    log.fill(0);
    let mut attr = ProgLoadAttr {
        prog_type: 3,
        insn_cnt: program.len as u32,
        insns: program.insns.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name: object_name(b"hxr_terminal"),
        prog_ifindex: 0,
        expected_attach_type: BPF_TCX_INGRESS,
        ..Default::default()
    };
    let program = bpf_fd(BPF_PROG_LOAD, &mut attr).map_err(|error| {
        let length = log.iter().position(|byte| *byte == 0).unwrap_or(log.len());
        io::Error::other(format!(
            "reverse SCHED_CLS load: {error}\n{}",
            String::from_utf8_lossy(&log[..length])
        ))
    })?;
    let mut info = ProgInfo::default();
    object_info(program.as_fd(), &mut info)?;
    ensure(
        info.kind == 3 && info.id != 0,
        "reverse terminal program identity",
    )?;
    #[repr(C)]
    struct Create {
        program: u32,
        target: u32,
        attach_type: u32,
        flags: u32,
        relative: u32,
        padding: u32,
        revision: u64,
    }
    let link = bpf_fd(
        BPF_LINK_CREATE,
        &mut Create {
            program: program.as_raw_fd() as u32,
            target: ifindex,
            attach_type: BPF_TCX_INGRESS,
            flags: 1 << 4,
            relative: 0,
            padding: 0,
            revision: 0,
        },
    )?;
    let mut identity = TcxInfo::default();
    object_info(link.as_fd(), &mut identity)?;
    ensure(
        identity.kind == 11
            && identity.id != 0
            && identity.program == info.id
            && identity.ifindex == ifindex
            && identity.attach_type == BPF_TCX_INGRESS,
        "reverse terminal link identity",
    )?;
    ensure(
        chain(ifindex, BPF_TCX_INGRESS)? == [info.id],
        "reverse terminal must be sole ingress hook",
    )?;
    Ok((program, link, info.id))
}

fn snapshot(map: &OwnedFd) -> io::Result<[u64; COUNT_LEN]> {
    let mut values = [0; COUNT_LEN];
    for (key, value) in values.iter_mut().enumerate() {
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            &mut map_attr(map.as_fd(), &(key as u32), value as *mut u64 as u64),
        )?;
    }
    Ok(values)
}

struct Receiver {
    socket: UdpSocket,
    cookie: u64,
    local: SocketAddr,
    remote: SocketAddr,
    connected: bool,
    zero: bool,
}

fn option(socket: RawFd, level: i32, name: i32, value: i32) -> io::Result<()> {
    // SAFETY: value is a complete integer socket option borrowed for this call.
    syscall(unsafe {
        libc::setsockopt(
            socket,
            level,
            name,
            (&value as *const i32).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    })
}

fn receiver(name: &str, ipv6: bool, kind: usize) -> io::Result<Receiver> {
    let local = if ipv6 {
        SocketAddr::from((Ipv6Addr::from(V6_LOCAL), 46100 + kind as u16))
    } else {
        SocketAddr::from((SOURCE, 46100 + kind as u16))
    };
    let remote = if ipv6 {
        SocketAddr::from((Ipv6Addr::from(V6_REMOTE), DESTINATION_PORT))
    } else {
        SocketAddr::from((DESTINATION, DESTINATION_PORT))
    };
    let socket = UdpSocket::bind(local)?;
    let device = CString::new(name).map_err(io::Error::other)?;
    // SAFETY: device is a NUL-terminated name borrowed for SO_BINDTODEVICE.
    syscall(unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device.as_ptr().cast(),
            device.as_bytes_with_nul().len() as libc::socklen_t,
        )
    })?;
    let mut bound = [0u8; libc::IFNAMSIZ];
    let mut length = bound.len() as libc::socklen_t;
    // SAFETY: bound/length are writable for their supplied extents.
    syscall(unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            bound.as_mut_ptr().cast(),
            &mut length,
        )
    })?;
    ensure(
        &bound[..length as usize] == device.as_bytes_with_nul(),
        "actual SO_BINDTODEVICE readback",
    )?;
    option(
        socket.as_raw_fd(),
        if ipv6 {
            libc::IPPROTO_IPV6
        } else {
            libc::IPPROTO_IP
        },
        if ipv6 {
            libc::IPV6_RECVPKTINFO
        } else {
            libc::IP_PKTINFO
        },
        1,
    )?;
    let connected = kind == 0;
    if connected {
        socket.connect(remote)?;
        ensure(socket.peer_addr()? == remote, "connected UDP kernel peer")?;
    } else {
        ensure(
            socket
                .peer_addr()
                .is_err_and(|error| error.raw_os_error() == Some(libc::ENOTCONN)),
            "unconnected UDP kernel state",
        )?;
    }
    socket.set_nonblocking(true)?;
    let mut cookie = 0u64;
    let mut length = size_of::<u64>() as libc::socklen_t;
    // SAFETY: cookie/length have the SO_COOKIE UAPI extent.
    syscall(unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut length,
        )
    })?;
    ensure(
        cookie != 0 && length as usize == size_of::<u64>() && socket.local_addr()? == local,
        "actual UDP owner cookie/local address",
    )?;
    Ok(Receiver {
        socket,
        cookie,
        local,
        remote,
        connected,
        zero: kind == 2,
    })
}

fn frame(output: &mut [u8], receiver: &Receiver, record: ReturnRecord, payload: &[u8]) -> usize {
    let ipv6 = receiver.local.is_ipv6();
    let ip_len = if ipv6 { 40 } else { 20 };
    let l3_len = ip_len + 8 + payload.len();
    let total = L3 + l3_len;
    let bytes = &mut output[..total];
    bytes.fill(0);
    bytes[..6].copy_from_slice(&TX_MAC);
    bytes[6..12].copy_from_slice(&RX_MAC);
    bytes[12..14].copy_from_slice(&(if ipv6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
    bytes[14..L3].copy_from_slice(&record.context(ipv6, l3_len));
    let udp = L3 + ip_len;
    let udp_len = (8 + payload.len()) as u16;
    bytes[udp..udp + 2].copy_from_slice(&receiver.remote.port().to_be_bytes());
    bytes[udp + 2..udp + 4].copy_from_slice(&receiver.local.port().to_be_bytes());
    bytes[udp + 4..udp + 6].copy_from_slice(&udp_len.to_be_bytes());
    bytes[udp + 8..].copy_from_slice(payload);
    let mut pseudo = [0u8; 128];
    let pseudo_len = if ipv6 {
        bytes[L3] = 0x60;
        bytes[L3 + 4..L3 + 6].copy_from_slice(&udp_len.to_be_bytes());
        bytes[L3 + 6] = 17;
        bytes[L3 + 7] = 64;
        bytes[L3 + 8..L3 + 24].copy_from_slice(&V6_REMOTE);
        bytes[L3 + 24..L3 + 40].copy_from_slice(&V6_LOCAL);
        pseudo[..32].copy_from_slice(&bytes[L3 + 8..L3 + 40]);
        pseudo[32..36].copy_from_slice(&u32::from(udp_len).to_be_bytes());
        pseudo[39] = 17;
        pseudo[40..40 + udp_len as usize].copy_from_slice(&bytes[udp..]);
        40 + udp_len as usize
    } else {
        bytes[L3] = 0x45;
        bytes[L3 + 2..L3 + 4].copy_from_slice(&(l3_len as u16).to_be_bytes());
        bytes[L3 + 8] = 64;
        bytes[L3 + 9] = 17;
        bytes[L3 + 12..L3 + 16].copy_from_slice(&DESTINATION);
        bytes[L3 + 16..L3 + 20].copy_from_slice(&SOURCE);
        let sum = checksum(&bytes[L3..L3 + 20]);
        bytes[L3 + 10..L3 + 12].copy_from_slice(&sum.to_be_bytes());
        pseudo[..8].copy_from_slice(&bytes[L3 + 12..L3 + 20]);
        pseudo[9] = 17;
        pseudo[10..12].copy_from_slice(&udp_len.to_be_bytes());
        pseudo[12..12 + udp_len as usize].copy_from_slice(&bytes[udp..]);
        12 + udp_len as usize
    };
    let sum = checksum(&pseudo[..pseudo_len]);
    bytes[udp + 6..udp + 8].copy_from_slice(&(if sum == 0 { u16::MAX } else { sum }).to_be_bytes());
    total
}

fn receive_one(receiver: &Receiver, target: u32, expected: &[u8]) -> io::Result<bool> {
    let mut bytes = [0u8; 256];
    let mut ancillary = [0u64; 16];
    // SAFETY: zero is a valid initial sockaddr_storage and msghdr representation.
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: every pointed-to buffer remains alive and writable until recvmsg returns.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_name = (&mut address as *mut libc::sockaddr_storage).cast();
    message.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&ancillary) as _;
    // SAFETY: message describes complete live writable extents; DONTWAIT bounds this observation.
    let received = unsafe {
        libc::recvmsg(
            receiver.socket.as_raw_fd(),
            &mut message,
            libc::MSG_DONTWAIT,
        )
    };
    if received < 0 {
        let error = io::Error::last_os_error();
        return if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            Ok(false)
        } else {
            Err(error)
        };
    }
    ensure(
        message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
            && &bytes[..received as usize] == expected,
        "actual UDP application bytes/extent",
    )?;
    let peer = if i32::from(address.ss_family) == libc::AF_INET {
        ensure(
            message.msg_namelen as usize == size_of::<libc::sockaddr_in>(),
            "IPv4 peer extent",
        )?;
        // SAFETY: family/extent were checked; unaligned load avoids sockaddr_storage alignment assumptions.
        let address = unsafe {
            std::ptr::read_unaligned(
                (&address as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
            )
        };
        SocketAddr::from((
            address.sin_addr.s_addr.to_ne_bytes(),
            u16::from_be(address.sin_port),
        ))
    } else {
        ensure(
            i32::from(address.ss_family) == libc::AF_INET6
                && message.msg_namelen as usize == size_of::<libc::sockaddr_in6>(),
            "IPv6 peer family/extent",
        )?;
        // SAFETY: family and writable extent have been checked above.
        let address = unsafe {
            std::ptr::read_unaligned(
                (&address as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
            )
        };
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(address.sin6_addr.s6_addr),
            u16::from_be(address.sin6_port),
            address.sin6_flowinfo,
            address.sin6_scope_id,
        ))
    };
    ensure(peer == receiver.remote, "actual kernel UDP peer")?;
    let mut pktinfo = 0;
    // SAFETY: recvmsg produced bounded ancillary data in an aligned buffer; CMSG helpers enforce its extent.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&message);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_PKTINFO {
                ensure(
                    !receiver.local.is_ipv6()
                        && (*cmsg).cmsg_len as u64
                            == u64::from(libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as u32)),
                    "IPv4 pktinfo extent",
                )?;
                let info =
                    std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in_pktinfo>());
                ensure(
                    info.ipi_ifindex as u32 == target
                        && info.ipi_addr.s_addr.to_ne_bytes() == SOURCE
                        && info.ipi_spec_dst.s_addr.to_ne_bytes() == SOURCE,
                    "actual IPv4 original ingress/destination",
                )?;
                pktinfo += 1;
            } else if (*cmsg).cmsg_level == libc::IPPROTO_IPV6
                && (*cmsg).cmsg_type == libc::IPV6_PKTINFO
            {
                ensure(
                    receiver.local.is_ipv6()
                        && (*cmsg).cmsg_len as u64
                            == u64::from(libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as u32)),
                    "IPv6 pktinfo extent",
                )?;
                let info =
                    std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>());
                ensure(
                    info.ipi6_ifindex == target && info.ipi6_addr.s6_addr == V6_LOCAL,
                    "actual IPv6 original ingress/destination",
                )?;
                pktinfo += 1;
            }
            cmsg = libc::CMSG_NXTHDR(&message, cmsg);
        }
    }
    ensure(pktinfo == 1, "exactly one kernel ingress pktinfo")?;
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutputOwner {
    ticket: u32,
    cookie: u64,
    record: ReturnRecord,
}

#[derive(Clone, Copy, Debug)]
enum Observation {
    Delivered,
    GateDrop(u32),
    NoReflection(bool),
    NativeCalibration,
}

fn observe(
    port: &mut Port<OutputOwner>,
    counts: &OwnedFd,
    receivers: &[Receiver],
    selected: usize,
    publication: (ReturnRecord, u32),
    outcome: Observation,
    submit: impl FnOnce(&mut Port<OutputOwner>, &[u8], OutputOwner) -> io::Result<()>,
) -> io::Result<()> {
    let (record, ticket) = publication;
    let before = snapshot(counts)?;
    let submitted = port.counters().submitted;
    let receiver = &receivers[selected];
    let mut bytes = [0; 17];
    bytes[..13].copy_from_slice(b"host-reverse-");
    bytes[13..].copy_from_slice(&ticket.to_be_bytes());
    let data = &bytes[..if receiver.zero { 0 } else { bytes.len() }];
    let owner = OutputOwner {
        ticket,
        cookie: receiver.cookie,
        record,
    };
    let needs_cq = matches!(outcome, Observation::Delivered | Observation::GateDrop(_));
    submit(port, data, owner)?;
    if needs_cq {
        ensure(
            port.counters().submitted == submitted + 1 && port.outstanding().count() == 1,
            "actual single XSK publication retains original owner",
        )?;
    }
    let mut expected = [0u64; COUNT_LEN];
    match outcome {
        Observation::Delivered => {
            expected[GATE_SEEN as usize] = 1;
            expected[HANDOFF as usize] = 1;
        }
        Observation::GateDrop(reason) => {
            expected[GATE_SEEN as usize] = 1;
            expected[reason as usize] = 1;
        }
        Observation::NoReflection(_) => {
            expected[PRIVATE_SEEN as usize] = 1;
            expected[PRIVATE_MATCH as usize] = 1;
        }
        Observation::NativeCalibration => {
            expected[NATIVE_SEEN as usize] = 1;
        }
    }
    let end = Instant::now() + DEADLINE;
    let mut settled = None;
    let mut delivered = 0;
    let mut returned = 0;
    loop {
        for (position, socket) in receivers.iter().enumerate() {
            if receive_one(socket, record.target, data)? {
                ensure(
                    matches!(outcome, Observation::Delivered)
                        && position == selected
                        && delivered == 0,
                    "unexpected/duplicate/foreign application delivery",
                )?;
                delivered += 1;
            }
        }
        port.kick()?;
        let mut valid_owners = true;
        port.complete(|owners| {
            for actual in owners.iter().flatten() {
                valid_owners &= **actual == owner;
                returned += 1;
            }
        })?;
        ensure(
            valid_owners && returned <= usize::from(needs_cq),
            "actual CQ returned original retained owner once",
        )?;
        let after = snapshot(counts)?;
        let mut ready = delivered == usize::from(matches!(outcome, Observation::Delivered));
        for key in 0..COUNT_LEN {
            let delta = after[key].checked_sub(before[key]);
            ensure(
                delta.is_some_and(|value| value <= expected[key]),
                "reverse observed consumer counter exceeds case bound",
            )?;
            ready &= delta == Some(expected[key]);
        }
        if needs_cq {
            ready &= returned == 1
                && port.counters().completed == submitted + 1
                && port.outstanding().next().is_none();
        } else {
            ensure(
                port.counters().submitted == submitted && returned == 0,
                "raw/calibration unexpectedly used XSK TX",
            )?;
        }
        let now = Instant::now();
        if ready && now >= *settled.get_or_insert(now + QUIET) {
            break;
        }
        ensure(now < end, "actual reverse consumer/application/CQ deadline")?;
        std::thread::sleep(Duration::from_millis(1));
    }
    eprintln!(
        "Host reverse case: ticket={ticket} family={} connected={} zero={} outcome={outcome:?} qdisc_bypass={} app={delivered} original_iif={} cookie={} CQ={returned} counters={expected:?}",
        if receiver.local.is_ipv6() { 6 } else { 4 },
        receiver.connected,
        receiver.zero,
        matches!(outcome, Observation::NoReflection(true)),
        record.target,
        receiver.cookie
    );
    Ok(())
}

fn publish(
    port: &mut Port<OutputOwner>,
    receiver: &Receiver,
    record: ReturnRecord,
    data: &[u8],
    owner: OutputOwner,
    mutate: impl FnOnce(&mut [u8]),
) -> io::Result<()> {
    let size = L3 + if receiver.local.is_ipv6() { 48 } else { 28 } + data.len();
    ensure(
        port.transmit_generated(TxClass::Bulk, size, |output| {
            let size = frame(output, receiver, record, data);
            mutate(&mut output[..size]);
            Ok(Some((size, owner)))
        })?,
        "reverse XSK TX publication refused",
    )
}

fn closed(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFD is a nonmutating query and takes no pointer argument.
    ensure(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1
            && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF),
        "owned descriptor remains open",
    )
}

pub(super) fn exercise() -> io::Result<()> {
    let source_net = namespace_inode("net")?;
    let source_mount = namespace_inode("mnt")?;
    let source_mounts = std::fs::read_to_string("/proc/thread-self/mountinfo")?;
    let child = child_namespace(source_net)?;
    let child_inode = child.metadata()?.ino();
    let links = Links::create()?;
    let original = links.indices[0];
    let tx = links.indices[2];
    let previous_all = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter")?;
    sysctl("ipv4/conf/all/rp_filter", "1")?;
    sysctl(&format!("ipv4/conf/{}/rp_filter", links.names[0]), "1")?;
    let all: u32 = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter")?
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    let target: u32 = std::fs::read_to_string(format!(
        "/proc/sys/net/ipv4/conf/{}/rp_filter",
        links.names[0]
    ))?
    .trim()
    .parse()
    .map_err(io::Error::other)?;
    ensure(
        all.max(target) == 1,
        "effective original-interface rp_filter must be strict",
    )?;
    eprintln!(
        "Host reverse IPv4 rp_filter: all={all} original={target} effective={}",
        all.max(target)
    );
    for (leaf, value) in [
        ("accept_ra", "0"),
        ("autoconf", "0"),
        ("addr_gen_mode", "1"),
        ("disable_ipv6", "0"),
    ] {
        sysctl(&format!("ipv6/conf/{}/{leaf}", links.names[0]), value)?;
    }
    command(
        "ip",
        &[
            "-6",
            "address",
            "add",
            "fd42:1900::1/64",
            "dev",
            &links.names[0],
            "nodad",
        ],
    )?;
    command(
        "ip",
        &[
            "-6",
            "neigh",
            "add",
            "fd42:1900::2",
            "lladdr",
            "02:00:00:01:00:02",
            "nud",
            "permanent",
            "dev",
            &links.names[0],
        ],
    )?;
    let v6_addresses = command(
        "ip",
        &["-o", "-6", "address", "show", "dev", &links.names[0]],
    )?;
    ensure(
        v6_addresses.lines().count() == 1
            && v6_addresses.contains("fd42:1900::1/64")
            && !v6_addresses.contains("tentative"),
        "enabled original IPv6 address readback",
    )?;
    for (family, remote, local) in [
        ("-4", "198.19.0.2", "198.19.0.1"),
        ("-6", "fd42:1900::2", "fd42:1900::1"),
    ] {
        let route = command("ip", &[family, "route", "get", remote, "from", local])?;
        ensure(
            route.contains(&format!("dev {} ", links.names[0])),
            "reverse source validation route must select original interface",
        )?;
        let input = command(
            "ip",
            &[
                family,
                "route",
                "get",
                local,
                "from",
                remote,
                "iif",
                &links.names[0],
            ],
        )?;
        ensure(
            input.starts_with("local "),
            "reverse input route must be local",
        )?;
        eprintln!("Host reverse route {family}: {route}{input}");
    }
    features_off(&links.names[2])?;
    move_peer(links.indices[3], &child)?;
    let private_name = CString::new(links.names[3].as_str()).map_err(io::Error::other)?;
    // SAFETY: private_name is a live NUL-terminated name; this only queries the source netns.
    ensure(
        unsafe { libc::if_nametoindex(private_name.as_ptr()) } == 0,
        "private RX remains in source namespace",
    )?;
    let rx = with_child(&child, || {
        let rx = index(&links.names[3])?;
        sysctl(&format!("ipv6/conf/{}/disable_ipv6", links.names[3]), "1")?;
        command("ip", &["link", "set", "dev", &links.names[3], "up"])?;
        features_off(&links.names[3])?;
        link_facts(&links.names[3], rx, tx, RX_MAC)?;
        ensure(
            command("ip", &["-o", "link", "show"])?.lines().count() == 2,
            "child has foreign links",
        )?;
        ensure(
            command("ip", &["-o", "address", "show"])?.trim().is_empty(),
            "child has ambient addresses",
        )?;
        for family in ["-4", "-6"] {
            ensure(
                command("ip", &[family, "route", "show", "table", "all"])?
                    .trim()
                    .is_empty(),
                "child has ambient routes",
            )?;
        }
        ensure(
            xdp_absent(rx)?
                && chain(rx, BPF_TCX_INGRESS)?.is_empty()
                && chain(rx, BPF_TCX_EGRESS)?.is_empty(),
            "child has foreign hooks",
        )?;
        Ok(rx)
    })?;
    ensure(
        rx != original && rx != tx,
        "private target identifiers must be distinct",
    )?;
    link_facts(&links.names[0], original, links.indices[1], SOURCE_MAC)?;
    link_facts(&links.names[1], links.indices[1], original, SOURCE_PEER_MAC)?;
    ensure(
        xdp_absent(links.indices[1])?,
        "original peer has foreign XDP",
    )?;
    for ifindex in [original, links.indices[1]] {
        ensure(
            chain(ifindex, BPF_TCX_INGRESS)?.is_empty()
                && chain(ifindex, BPF_TCX_EGRESS)?.is_empty(),
            "original return path has foreign TCX",
        )?;
    }
    link_facts(&links.names[2], tx, rx, TX_MAC)?;
    let record = ReturnRecord {
        attachment: 0x1234_0000_0000_0000 | u64::from(std::process::id()),
        generation: 0xabcd_0000_0000_0000 | u64::from(original),
        target: original,
        private_tx: tx,
        private_rx: rx,
    };
    let counts = create_map(2, 8, COUNT_LEN as u32, b"hxr_counts")?;
    let mut log = vec![0; 1 << 20];
    let (native_program, native_id) = load_program(
        &observer(original, counts.as_raw_fd(), false)?,
        b"hxr_native",
        &mut log,
    )?;
    let native_link = attach_guard(&native_program, native_id, original)?;
    let (private_program, private_link, private_id, mut port) = with_child(&child, || {
        let (program, id) = load_program(
            &observer(rx, counts.as_raw_fd(), true)?,
            b"hxr_private",
            &mut log,
        )?;
        let link = attach_guard(&program, id, rx)?;
        let config = PortConfig {
            rx_frames: 16,
            control_frames: 2,
            bulk_frames: 2,
            ring_size: 16,
        };
        let port = Port::<OutputOwner>::open_device(
            rx,
            0,
            BindMode::Copy,
            config,
            1500,
            false,
            0,
            &MemoryBudget::new(4 << 20),
        )?;
        ensure(
            !port.zerocopy(),
            "reverse sole XSK must use actual Copy mode",
        )?;
        Ok((program, link, id, port))
    })?;
    let (terminal_program, terminal_link, terminal_id) =
        attach_terminal(&terminal(record, counts.as_raw_fd())?, tx, &mut log)?;
    ensure(xdp_absent(tx)?, "private reverse ingress must have no XDP")?;
    ensure(
        chain(tx, BPF_TCX_EGRESS)?.is_empty(),
        "private TX has foreign egress hooks",
    )?;
    let mut receivers = Vec::with_capacity(6);
    for ipv6 in [false, true] {
        for kind in 0..3 {
            receivers.push(receiver(&links.names[0], ipv6, kind)?);
        }
    }
    let mut ticket = 0u32;
    for selected in [0, 3] {
        ticket += 1;
        observe(
            &mut port,
            &counts,
            &receivers,
            selected,
            (record, ticket),
            Observation::NativeCalibration,
            |_, data, _| {
                let mut bytes = [0; 256];
                let size = frame(&mut bytes, &receivers[selected], record, data);
                bytes.copy_within(L3..size, 14);
                bytes[..6].copy_from_slice(&SOURCE_MAC);
                bytes[6..12].copy_from_slice(&SOURCE_PEER_MAC);
                send_packet(links.indices[1], &bytes[..size - CONTEXT], false)
            },
        )?;
    }
    for selected in 0..receivers.len() {
        ticket += 1;
        observe(
            &mut port,
            &counts,
            &receivers,
            selected,
            (record, ticket),
            Observation::Delivered,
            |port, data, owner| publish(port, &receivers[selected], record, data, owner, |_| {}),
        )?;
    }
    let mut nonexistent = [0; libc::IFNAMSIZ];
    // SAFETY: nonexistent has exactly IFNAMSIZ writable bytes for the lookup.
    ensure(
        unsafe { libc::if_indextoname(NONEXISTENT, nonexistent.as_mut_ptr()) }.is_null(),
        "nonexistent target negative precondition",
    )?;
    let version = 2u16.to_ne_bytes();
    let attachment = (record.attachment ^ (1 << 40)).to_ne_bytes();
    let generation = (record.generation ^ (1 << 40)).to_ne_bytes();
    let private_tx = tx.to_ne_bytes();
    let private_rx = rx.to_ne_bytes();
    let absent = NONEXISTENT.to_ne_bytes();
    let family = 6u32.to_ne_bytes();
    let extent = 29u32.to_ne_bytes();
    for (label, reason_key, offset, replacement) in [
        ("malformed magic", BAD_FORMAT, 14, &[0][..]),
        ("context version", BAD_VERSION, 18, version.as_slice()),
        (
            "attachment high bits",
            BAD_ATTACHMENT,
            30,
            attachment.as_slice(),
        ),
        (
            "retired generation high bits",
            BAD_GENERATION,
            38,
            generation.as_slice(),
        ),
        ("private TX target", BAD_PRIVATE, 46, private_tx.as_slice()),
        ("private RX target", BAD_PRIVATE, 46, private_rx.as_slice()),
        ("nonexistent target", BAD_TARGET, 46, absent.as_slice()),
        ("family disagreement", BAD_FAMILY, 26, family.as_slice()),
        ("extent disagreement", BAD_EXTENT, 50, extent.as_slice()),
    ] {
        ticket += 1;
        observe(
            &mut port,
            &counts,
            &receivers,
            0,
            (record, ticket),
            Observation::GateDrop(reason_key),
            |port, data, owner| {
                publish(port, &receivers[0], record, data, owner, |bytes| {
                    bytes[offset..offset + replacement.len()].copy_from_slice(replacement)
                })
            },
        )?;
        eprintln!("Host reverse negative observed: {label}");
    }
    for bypass in [false, true] {
        ticket += 1;
        observe(
            &mut port,
            &counts,
            &receivers,
            0,
            (record, ticket),
            Observation::NoReflection(bypass),
            |_, data, _| {
                let mut bytes = [0; 256];
                let size = frame(&mut bytes, &receivers[0], record, data);
                send_packet(tx, &bytes[..size], bypass)
            },
        )?;
    }
    for selected in [0, 3] {
        ticket += 1;
        observe(
            &mut port,
            &counts,
            &receivers,
            selected,
            (record, ticket),
            Observation::Delivered,
            |port, data, owner| publish(port, &receivers[selected], record, data, owner, |_| {}),
        )?;
    }
    ensure(
        ticket == 21,
        "reverse observed packet budget must be exactly 21 (below 32)",
    )?;
    ensure(
        snapshot(&counts)?[NATIVE_SEEN as usize] == 2,
        "calibrated native XDP must not rerun on reverse software input",
    )?;
    require_native(xdp_state(original)?, native_id)?;
    ensure(
        chain(tx, BPF_TCX_INGRESS)? == [terminal_id] && xdp_absent(tx)?,
        "terminal attachment incarnation changed",
    )?;
    with_child(&child, || {
        require_native(xdp_state(rx)?, private_id)?;
        Ok(())
    })?;
    port.close();
    let end = Instant::now() + DEADLINE;
    loop {
        port.kick()?;
        let mut owners = 0;
        port.complete(|values| owners += values.iter().flatten().count())?;
        ensure(owners == 0, "late owner escaped per-case CQ accounting")?;
        port.observe_fill()?;
        if !port.needs_service_retry()
            && port.drain_state().ready_for_backend_teardown()
            && port.outstanding().next().is_none()
            && port.counters().submitted == port.counters().completed
        {
            break;
        }
        ensure(Instant::now() < end, "reverse joined XSK/CQ drain deadline")?;
        std::thread::sleep(Duration::from_millis(1));
    }
    command("ip", &["link", "set", "dev", &links.names[2], "down"])?;
    with_child(&child, || {
        command("ip", &["link", "set", "dev", &links.names[3], "down"])?;
        Ok(())
    })?;
    let xsk_fd = port.as_raw_fd();
    port.close_socket();
    ensure(port.as_raw_fd() == -1, "reverse XSK remains open")?;
    closed(xsk_fd)?;
    drop(port);
    let private_fd = private_link.as_raw_fd();
    drop(private_link);
    closed(private_fd)?;
    with_child(&child, || {
        ensure(xdp_absent(rx)?, "reverse private guard remains")
    })?;
    let terminal_fd = terminal_link.as_raw_fd();
    drop(terminal_link);
    closed(terminal_fd)?;
    ensure(
        chain(tx, BPF_TCX_INGRESS)?.is_empty(),
        "reverse terminal remains",
    )?;
    for name in &links.names[..2] {
        command("ip", &["link", "set", "dev", name, "down"])?;
    }
    let native_fd = native_link.as_raw_fd();
    drop(native_link);
    closed(native_fd)?;
    ensure(
        xdp_absent(original)?,
        "reverse original native observer remains",
    )?;
    let mut descriptors = vec![
        native_program.as_raw_fd(),
        private_program.as_raw_fd(),
        terminal_program.as_raw_fd(),
        counts.as_raw_fd(),
    ];
    descriptors.extend(receivers.iter().map(|receiver| receiver.socket.as_raw_fd()));
    drop((
        receivers,
        native_program,
        private_program,
        terminal_program,
        counts,
    ));
    for fd in descriptors {
        closed(fd)?;
    }
    sysctl("ipv4/conf/all/rp_filter", previous_all.trim())?;
    links.remove()?;
    with_child(&child, || {
        ensure(
            command("ip", &["-o", "link", "show"])?.lines().count() == 1 && index("lo")? == 1,
            "reverse child links remain",
        )?;
        ensure(
            command("ip", &["-o", "address", "show"])?.trim().is_empty(),
            "reverse child addresses remain",
        )?;
        for family in ["-4", "-6"] {
            ensure(
                command("ip", &[family, "route", "show", "table", "all"])?
                    .trim()
                    .is_empty(),
                "reverse child routes remain",
            )?;
        }
        Ok(())
    })?;
    let child_fd = child.as_raw_fd();
    drop(child);
    closed(child_fd)?;
    ensure(
        namespace_inode("net")? == source_net
            && namespace_inode("mnt")? == source_mount
            && std::fs::read_to_string("/proc/thread-self/mountinfo")? == source_mounts,
        "reverse source namespace/mount context changed",
    )?;
    eprintln!(
        "Host reverse cleanup: child_netns_inode={child_inode} child_netns_fd_closed=true source_netns_restored=true source_mount_restored=true xsk_closed=true links_deleted=true hooks_detached=true children_joined=true"
    );
    Ok(())
}
