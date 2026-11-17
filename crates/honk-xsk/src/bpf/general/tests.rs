//! Real BPF execution proves the emitted policy and counter ABI, not driver metadata support.
use super::super as gate_bpf;
use super::*;
use honk_ebpf_common::xdp::{CaptureAuthority, NATIVE_IMPORT_LEN, NativeImport};
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

mod host;
mod native_watch;

fn capture() -> GeneralCapture {
    GeneralCapture {
        authority: CaptureAuthority {
            namespace_cookie: 1,
            attachment_generation: 2,
            scope: 3,
            config_generation: 4,
            ifindex: 1,
            reserved: 0,
        },
        bypass_mark: 128,
        vlan_metadata: false,
    }
}

fn require_vm() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "NOT_EXERCISED: requires guest root"
    );
    assert!(
        gate_io(std::fs::read_to_string("/proc/cmdline")).contains("virtme."),
        "NOT_EXERCISED: requires a disposable virtme guest"
    );
    assert_ne!(
        gate_io(std::fs::metadata("/proc/self/ns/net")).ino(),
        gate_io(std::fs::metadata("/proc/1/ns/net")).ino(),
        "NOT_EXERCISED: requires the disposable guest's private network namespace"
    );
}

#[repr(C)]
#[derive(Default)]
struct TestRun {
    program: u32,
    action: u32,
    input_len: u32,
    output_len: u32,
    input: u64,
    output: u64,
    repeat: u32,
    duration: u32,
    context_len: u32,
    result_len: u32,
    context: u64,
    result: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    reserved: u32,
}

fn run(program: &OwnedFd, frame: &[u8], metadata_len: usize) -> (u32, Vec<u8>, Vec<u8>) {
    let mut input = vec![0; metadata_len];
    input.extend_from_slice(frame);
    let context = [metadata_len as u32, input.len() as u32, 0, 1, 0, 0];
    let mut result = [0u32; 6];
    let mut output = vec![0; input.len() + 256];
    let mut attr = TestRun {
        program: program.as_raw_fd() as u32,
        input_len: input.len() as u32,
        output_len: output.len() as u32,
        input: input.as_ptr() as u64,
        output: output.as_mut_ptr() as u64,
        repeat: 1,
        context_len: size_of::<[u32; 6]>() as u32,
        result_len: size_of::<[u32; 6]>() as u32,
        context: context.as_ptr() as u64,
        result: result.as_mut_ptr() as u64,
        ..TestRun::default()
    };
    bpf(10, &mut attr).unwrap();
    assert_eq!(result[2], 0);
    assert_eq!(result[1], attr.output_len);
    let metadata = output[..result[0] as usize].to_vec();
    let packet = output[result[0] as usize..result[1] as usize].to_vec();
    (attr.action, metadata, packet)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in bytes.chunks(2) {
        sum += u32::from(word[0]) << 8 | u32::from(*word.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn packet(source: SocketAddr, destination: SocketAddr, mac: [u8; 6], tags: usize) -> Vec<u8> {
    let offset = 14 + 4 * tags;
    let ipv6 = source.is_ipv6();
    assert_eq!(ipv6, destination.is_ipv6());
    let ip_len = if ipv6 { 48 } else { 28 };
    let mut bytes = vec![0; (offset + ip_len).max(60 + 4 * tags)];
    bytes[..6].copy_from_slice(&mac);
    bytes[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    for tag in 0..tags {
        bytes[12 + 4 * tag..14 + 4 * tag].copy_from_slice(&0x8100u16.to_be_bytes());
        bytes[14 + 4 * tag..16 + 4 * tag].copy_from_slice(&(tag as u16 + 42).to_be_bytes());
    }
    bytes[offset - 2..offset]
        .copy_from_slice(&(if ipv6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
    let transport = offset + if ipv6 { 40 } else { 20 };
    bytes[transport..transport + 2].copy_from_slice(&source.port().to_be_bytes());
    bytes[transport + 2..transport + 4].copy_from_slice(&destination.port().to_be_bytes());
    bytes[transport + 4..transport + 6].copy_from_slice(&8u16.to_be_bytes());
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            bytes[offset] = 0x45;
            bytes[offset + 2..offset + 4].copy_from_slice(&28u16.to_be_bytes());
            bytes[offset + 8] = 64;
            bytes[offset + 9] = 17;
            bytes[offset + 12..offset + 16].copy_from_slice(&source.octets());
            bytes[offset + 16..offset + 20].copy_from_slice(&destination.octets());
            let sum = checksum(&bytes[offset..offset + 20]);
            bytes[offset + 10..offset + 12].copy_from_slice(&sum.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            bytes[offset] = 0x60;
            bytes[offset + 4..offset + 6].copy_from_slice(&8u16.to_be_bytes());
            bytes[offset + 6] = 17;
            bytes[offset + 7] = 64;
            bytes[offset + 8..offset + 24].copy_from_slice(&source.octets());
            bytes[offset + 24..offset + 40].copy_from_slice(&destination.octets());
            let mut pseudo = bytes[offset + 8..offset + 40].to_vec();
            pseudo.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0, 17]);
            pseudo.extend_from_slice(&bytes[transport..transport + 8]);
            let sum = checksum(&pseudo);
            bytes[transport + 6..transport + 8].copy_from_slice(&sum.to_be_bytes());
        }
        _ => unreachable!(),
    }
    bytes
}

#[test]
fn capture_rejects_missing_authority_without_loading() {
    let mut capture = capture();
    for queues in [0, 257] {
        assert!(build(&capture, &[], queues, 9, 10, true, None).is_err());
    }
    assert!(build(&capture, &[Ipv4Addr::BROADCAST; 65], 1, 9, 10, true, None).is_err());
    capture.vlan_metadata = true;
    assert!(build(&capture, &[], 1, 9, 10, true, None).is_err());
    assert!(build(&capture, &[], 1, 9, 10, true, Some(0)).is_err());
}
#[test]
fn native_import_requires_exact_authenticated_tail() {
    let mut bytes = [0u8; NATIVE_IMPORT_LEN];
    bytes[..8].copy_from_slice(&7u64.to_ne_bytes());
    bytes[8..16].copy_from_slice(&11u64.to_ne_bytes());
    bytes[16..24].copy_from_slice(&19u64.to_ne_bytes());
    bytes[24..28].copy_from_slice(&honk_ebpf_common::xdp::NATIVE_IMPORT_COUNTED.to_ne_bytes());
    assert_eq!(
        NativeImport::decode(&bytes),
        Some(NativeImport {
            epoch: 7,
            incarnation: 11,
            expires_boottime_ns: 19,
            flags: honk_ebpf_common::xdp::NATIVE_IMPORT_COUNTED,
            reserved: 0,
        })
    );
    assert!(NativeImport::decode(&bytes[..NATIVE_IMPORT_LEN - 1]).is_none());
    assert!(NativeImport::decode(&bytes[..16]).is_none());
    assert!(NativeImport::decode(&[bytes.as_slice(), &[0]].concat()).is_none());
    for offset in [24, 28] {
        let mut malformed = bytes;
        malformed[offset] = 2;
        assert!(
            NativeImport::decode(&malformed).is_none(),
            "offset {offset}"
        );
    }
}

fn native_metadata_body(capture: &GeneralCapture) -> Program {
    let mut body = Builder::new();
    body.program.flags = (1 << 5) | if capture.vlan_metadata { 1 << 6 } else { 0 };
    body.program.ifindex = if capture.vlan_metadata {
        capture.authority.ifindex
    } else {
        0
    };
    body.emit(Insn::new(
        MOV_K,
        2,
        0,
        0,
        -(honk_ebpf_common::xdp::NATIVE_METADATA_LEN as i32),
    ));
    body.emit(Insn::new(CALL, 0, 0, 0, 54));
    body.emit(Insn::new(EXIT, 0, 0, 0, 0));
    body.finish().unwrap()
}

#[test]
fn native_dispatch_precedes_any_capture_metadata_reservation() {
    let mut capture = capture();
    capture.vlan_metadata = true;
    let native = build_with_native(
        Input {
            capture: &capture,
            ipv4_broadcasts: &[],
        },
        1,
        9,
        10,
        Some(1),
        native_metadata_body(&capture),
    )
    .unwrap();
    let helpers: Vec<_> = native.insns[..native.len]
        .iter()
        .filter(|insn| insn.code == CALL)
        .map(|insn| insn.imm)
        .collect();
    assert_eq!(
        helpers.iter().filter(|&&helper| helper == 54).count(),
        1,
        "only the attached Native body may reserve capture metadata"
    );
    assert!(!helpers.contains(&12));
    assert!(!helpers.contains(&51));
    assert_eq!(
        native.insns[native.len - 3].imm,
        -(honk_ebpf_common::xdp::NATIVE_METADATA_LEN as i32)
    );
}

#[test]
fn native_xdp_entries_do_not_reference_a_program_array() {
    for metadata in [false, true] {
        let mut capture = capture();
        capture.vlan_metadata = metadata;
        let vlan = metadata.then_some(1);
        let guard = build(&capture, &[], 1, 9, 10, false, vlan).unwrap();
        let data = build_with_native(
            Input {
                capture: &capture,
                ipv4_broadcasts: &[],
            },
            1,
            9,
            10,
            vlan,
            native_metadata_body(&capture),
        )
        .unwrap();
        for program in [guard, data] {
            assert!(
                !program.insns[..program.len]
                    .iter()
                    .any(|insn| insn.code == CALL && insn.imm == 12)
            );
        }
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_group_unicast_cannot_borrow_connected_socket_exemption() {
    require_vm();
    let capture = capture();
    let programs = Programs::load_general(&capture, 1, &[]).unwrap();
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let socket = UdpSocket::bind(bind).unwrap();
        let peer = UdpSocket::bind(bind).unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        let mark = capture.bypass_mark;
        // SAFETY: SO_MARK consumes this live u32 and does not retain its pointer.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    std::ptr::from_ref(&mark).cast(),
                    size_of::<u32>() as libc::socklen_t,
                )
            },
            0
        );
        for program in [&programs.discover, &programs.data] {
            for tags in 0..=2 {
                let unicast = packet(
                    peer.local_addr().unwrap(),
                    socket.local_addr().unwrap(),
                    [2, 0, 0, 0, 0, 1],
                    tags,
                );
                assert_eq!(run(program, &unicast, 0).0, XDP_PASS as u32);
                for mac in [[0xff; 6], [1, 0, 0x5e, 0, 0, 1]] {
                    let group = packet(
                        peer.local_addr().unwrap(),
                        socket.local_addr().unwrap(),
                        mac,
                        tags,
                    );
                    let before = programs.counters().unwrap().per_queue[0];
                    assert_eq!(run(program, &group, 0).0, XDP_DROP as u32);
                    assert_eq!(programs.counters().unwrap().per_queue[0], before + 1);
                }
            }
        }
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_destinations_and_metadata_counter_are_distinct() {
    require_vm();
    let capture = capture();
    let broadcast = Ipv4Addr::new(192, 0, 2, 255);
    let programs = Programs::load_general(&capture, 1, &[broadcast]).unwrap();
    for program in [&programs.discover, &programs.data] {
        for (source, destination) in [
            ("0.0.0.0:68", "255.255.255.255:67"),
            ("192.0.2.1:68", "192.0.2.255:67"),
            ("192.0.2.1:5353", "224.0.0.251:5353"),
            ("192.0.2.1:1900", "239.255.255.250:1900"),
            ("[2001:db8::1]:5353", "[ff02::fb]:5353"),
        ] {
            for tags in 0..=2 {
                let frame = packet(
                    source.parse().unwrap(),
                    destination.parse().unwrap(),
                    [0xff; 6],
                    tags,
                );
                assert_eq!(run(program, &frame, 0).0, XDP_PASS as u32);
            }
        }
    }
    assert_eq!(programs.counters().unwrap().per_queue, [0]);
    assert_eq!(programs.metadata_failures().unwrap(), 0);
    let frame = packet(
        "192.0.2.1:41000".parse().unwrap(),
        "198.51.100.1:42000".parse().unwrap(),
        [0xff; 6],
        2,
    );
    for (index, prefix) in [0, METADATA_LEN].into_iter().enumerate() {
        let (action, untouched, received) = run(&programs.data, &frame, prefix);
        assert_eq!(action, XDP_DROP as u32); // No XSK exists: redirect fallback stays closed.
        assert_eq!(untouched.len(), prefix);
        assert_eq!(programs.counters().unwrap().per_queue, [index as u64 + 1]);
        assert_eq!(programs.metadata_failures().unwrap(), 0);
        let decoded = capture.decode(&[&received], &[], 0).unwrap();
        assert_eq!((decoded.l3_offset, decoded.l3_len), (22, 28));
        assert_eq!(decoded.vlan_count, 2);
        assert_eq!(
            &received[decoded.l3_offset..decoded.l3_offset + decoded.l3_len],
            &frame[22..50]
        );
        if prefix != 0 {
            assert_eq!(
                capture.decode(&[&received], &untouched, 0),
                Err(crate::DecodeError::Metadata)
            );
        }
    }
    // Device-bound VLAN programs cannot TEST_RUN. Exercise their shared selected
    // packet emitter with real helpers, without pretending to prove a driver/kfunc.
    let mut b = Builder::new();
    b.program.flags = 1 << 5;
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    b.emit(Insn::new(LDX_W, 8, 9, 16, 0));
    b.jump(Insn::new(JEQ32_K, 8, 0, 0, -1), Label::Pass);
    for offset in (-64..-32).step_by(4) {
        b.emit(Insn::new(ST_W, 10, 0, offset, 0));
    }
    // Newer TEST_RUN reserves xdp_frame headroom before executing the program.
    // Reach exhaustion through the real helper, not an invalid input context.
    b.emit(Insn::new(LDX_W, 0, 9, 0, 0));
    b.emit(Insn::new(LDX_W, 1, 9, 8, 0));
    let exhaust = forward(&mut b, JNE_X, 0, 1, 0);
    let ready = forward(&mut b, JA, 0, 0, 0);
    patch(&mut b, exhaust);
    for _ in 0..(256 / METADATA_LEN) {
        b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
        b.emit(Insn::new(MOV_K, 2, 0, 0, -(METADATA_LEN as i32)));
        b.emit(Insn::new(CALL, 0, 0, 0, 54));
    }
    patch(&mut b, ready);
    selected(
        &mut b,
        1,
        programs.counters.as_raw_fd(),
        programs.xsks.as_raw_fd(),
        true,
        true,
        None,
    )
    .unwrap();
    let mut log = vec![0; 1 << 20];
    let (metadata_program, _) =
        load_program(&b.finish().unwrap(), b"honk_meta_test", &mut log).unwrap();
    assert_eq!(
        run(&metadata_program, &frame, METADATA_LEN).0,
        XDP_DROP as u32
    );
    assert_eq!(programs.counters().unwrap().per_queue, [2]);
    assert_eq!(programs.metadata_failures().unwrap(), 1);
    let (action, metadata, _) = run(&metadata_program, &frame, 0);
    assert_eq!(action, XDP_DROP as u32);
    assert_eq!(metadata.len(), METADATA_LEN);
    assert_eq!(programs.counters().unwrap().per_queue, [3]);
    assert_eq!(programs.metadata_failures().unwrap(), 1);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_legacy_capture_keeps_rejection_counters_and_xsk_miss_closed() {
    require_vm();
    let capture = Capture {
        protocol: Protocol::Udp,
        client: "192.0.2.1:41000".parse().unwrap(),
        service: "198.51.100.1:42000".parse().unwrap(),
        own_mac: [2, 0, 0, 0, 0, 1],
        peer_mac: [2, 0, 0, 0, 0, 2],
    };
    let programs = Programs::load(&capture, 1).unwrap();
    for program in [&programs.discover, &programs.data] {
        let frame = packet(
            capture.client.into(),
            capture.service.into(),
            capture.own_mac,
            0,
        );
        let before = programs.counters().unwrap();
        assert_eq!(run(program, &frame, 0).0, XDP_DROP as u32);
        assert_eq!(
            programs.counters().unwrap().per_queue[0],
            before.per_queue[0] + 1
        );
        for (offset, value) in [(20, 0x20), (14, 0x46), (0, 3)] {
            let mut bad = frame.clone();
            bad[offset] = value;
            assert_eq!(run(program, &bad, 0).0, XDP_DROP as u32);
        }
        let after = programs.counters().unwrap();
        assert_eq!(after.fragments, before.fragments + 1);
        assert_eq!(after.options, before.options + 1);
        assert_eq!(after.malformed, before.malformed + 1);
        assert_eq!(programs.metadata_failures().unwrap(), 0);
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_counter_reference_admission_survives_prog_info_reuse() {
    require_vm();
    let counters = create_map(
        2,
        size_of::<honk_ebpf_common::xdp::NativeClosedCounterV1>() as u32,
        honk_ebpf_common::xdp::NATIVE_COUNTER_ENTRIES,
        b"hxsk_native_ct",
    )
    .unwrap();
    let mut counter_identity = ProgInfo::default();
    object_info(counters.as_fd(), &mut counter_identity).unwrap();
    let mut b = Builder::new();
    b.map_fd(counters.as_raw_fd());
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_PASS));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    let mut log = vec![0; 1 << 20];
    let (program, _) = load_program(&b.finish().unwrap(), b"hxsk_ct_ref", &mut log).unwrap();
    // The first info reply fills jited_len/xlated_len; replaying them with null instruction
    // pointers is EFAULT wherever raw dumps are permitted, so the second query must start fresh.
    super::super::native::admit_counter_reference(program.as_fd(), counter_identity.id).unwrap();
    assert!(
        super::super::native::admit_counter_reference(program.as_fd(), counter_identity.id + 1)
            .is_err()
    );
}

fn gate_io<T>(result: io::Result<T>) -> T {
    result.unwrap_or_else(|error| panic!("NOT_EXERCISED: native gate fixture: {error}"))
}

fn gate_command(args: &[&str]) -> io::Result<()> {
    let output = Command::new("ip").args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "ip {args:?}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        )));
    }
    Ok(())
}

fn gate_index(name: &str) -> io::Result<u32> {
    let name = CString::new(name).map_err(io::Error::other)?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

struct GateFixture {
    original_namespace: std::fs::File,
    original_mount: std::fs::File,
    namespace_inodes: (u64, u64),
    isolated: bool,
    device: String,
    peer: String,
    ifindex: u32,
    peer_ifindex: u32,
    directory: PathBuf,
    pins: PathBuf,
    artifacts: PathBuf,
    created_device: bool,
    created_directory: bool,
    created_artifacts: bool,
}

impl GateFixture {
    fn new() -> io::Result<Self> {
        Self::with_addresses(true, true)
    }

    fn with_addresses(isolate: bool, local_delivery: bool) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let generation = NEXT.fetch_add(1, Ordering::Relaxed);
        let suffix = format!("{:x}{generation:x}", std::process::id());
        let original_namespace = std::fs::File::open("/proc/thread-self/ns/net")?;
        let original_mount = std::fs::File::open("/proc/thread-self/ns/mnt")?;
        let namespace_inodes = (
            original_namespace.metadata()?.ino(),
            original_mount.metadata()?.ino(),
        );
        let bpffs = std::env::var_os("HONK_XDP_PIN_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/sys/fs/bpf"));
        let bpffs = std::fs::canonicalize(bpffs)?;
        if bpffs.starts_with("/sys") {
            return Err(io::Error::other(
                "HONK_XDP_PIN_ROOT must name the existing bpffs outside /sys before private sysfs is mounted",
            ));
        }
        let pin_root = std::fs::File::open(&bpffs)?;
        let pin_identity = gate_bpf::directory_identity(pin_root.as_fd())?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(pin_root.as_raw_fd(), &mut filesystem) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if filesystem.f_type as u32 != 0xcafe4a11 {
            return Err(io::Error::other(
                "HONK_XDP_PIN_ROOT is not the existing bpffs instance",
            ));
        }
        let mut fixture = Self {
            original_namespace,
            original_mount,
            namespace_inodes,
            isolated: false,
            device: format!("hg{suffix}d"),
            peer: format!("hg{suffix}p"),
            ifindex: 0,
            peer_ifindex: 0,
            directory: bpffs.join(format!("honk-gate-{suffix}")),
            pins: PathBuf::new(),
            artifacts: std::env::temp_dir().join(format!("honk-gate-{suffix}")),
            created_device: false,
            created_directory: false,
            created_artifacts: false,
        };
        if isolate {
            // Queue discovery and Python identity must see this netns without remounting the wrapper's sysfs.
            if unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_FS) } != 0 {
                return Err(io::Error::last_os_error());
            }
            fixture.isolated = true;
            if unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe {
                libc::mount(
                    c"sysfs".as_ptr(),
                    c"/sys".as_ptr(),
                    c"sysfs".as_ptr(),
                    libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    std::ptr::null(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let visible_root = std::fs::File::open(&bpffs)?;
        if gate_bpf::directory_identity(visible_root.as_fd())? != pin_identity {
            return Err(io::Error::other(
                "private sysfs changed the original bpffs pin root identity",
            ));
        }
        gate_command(&[
            "link",
            "add",
            "name",
            &fixture.device,
            "numtxqueues",
            "1",
            "numrxqueues",
            "1",
            "type",
            "veth",
            "peer",
            "name",
            &fixture.peer,
            "numtxqueues",
            "1",
            "numrxqueues",
            "1",
        ])?;
        fixture.created_device = true;
        fixture.ifindex = gate_index(&fixture.device)?;
        fixture.peer_ifindex = gate_index(&fixture.peer)?;
        for device in [&fixture.device, &fixture.peer] {
            gate_command(&["link", "set", "dev", device, "addrgenmode", "none"])?;
        }
        gate_command(&[
            "link",
            "set",
            "dev",
            &fixture.device,
            "address",
            "02:00:00:00:00:01",
            "up",
        ])?;
        gate_command(&[
            "link",
            "set",
            "dev",
            &fixture.peer,
            "address",
            "02:00:00:00:00:02",
            "up",
        ])?;
        if local_delivery {
            // Keep local UDP destinations off the capture root; exact source routes retain strict RPF.
            gate_command(&["link", "set", "dev", "lo", "up"])?;
            gate_command(&["addr", "add", "198.18.0.2/32", "dev", "lo"])?;
            gate_command(&[
                "-6",
                "addr",
                "add",
                "2001:db8:feed::2/128",
                "dev",
                "lo",
                "nodad",
            ])?;
            gate_command(&[
                "route",
                "add",
                "198.18.0.1/32",
                "dev",
                &fixture.device,
                "src",
                "198.18.0.2",
            ])?;
            gate_command(&[
                "-6",
                "route",
                "add",
                "2001:db8:feed::1/128",
                "dev",
                &fixture.device,
                "src",
                "2001:db8:feed::2",
            ])?;
        }
        std::fs::create_dir(&fixture.directory)?;
        fixture.created_directory = true;
        std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o700))?;
        fixture.pins = fixture.directory.join(format!("xdp-{}", fixture.ifindex));
        std::fs::create_dir(&fixture.pins)?;
        std::fs::set_permissions(&fixture.pins, std::fs::Permissions::from_mode(0o700))?;
        std::fs::create_dir(&fixture.artifacts)?;
        fixture.created_artifacts = true;
        Ok(fixture)
    }

    fn capture(&self) -> io::Result<GeneralCapture> {
        gate_capture(self.ifindex)
    }

    fn bootstrap(&self) -> io::Result<(Programs, gate_bpf::PersistentAttachment)> {
        let programs = Programs::load_general_native(&self.capture()?, 1, &[])?;
        let attachment =
            gate_bpf::PersistentAttachment::create(self.ifindex, &programs, &self.pins)?;
        Ok((programs, attachment))
    }

    fn inventory(&self) -> io::Result<GateInventory> {
        gate_inventory(self.ifindex, &self.device, &self.pins)
    }

    fn alongside(&self) -> io::Result<Self> {
        let mut other = Self::with_addresses(false, false)?;
        let pins = self.directory.join(format!("xdp-{}", other.ifindex));
        std::fs::rename(&other.pins, &pins)?;
        other.pins = pins;
        Ok(other)
    }
}

impl Drop for GateFixture {
    fn drop(&mut self) {
        // Device teardown follows every assertion, so unregister cannot satisfy an absence oracle.
        if self.created_device {
            let _ = gate_command(&["link", "set", "dev", &self.peer, "down"]);
            let _ = gate_command(&["link", "del", "dev", &self.device]);
        }
        if let Ok(entries) = std::fs::read_dir(&self.directory)
            && self.created_directory
        {
            for entry in entries.flatten() {
                if let Ok(pins) = std::fs::read_dir(entry.path()) {
                    for pin in pins.flatten() {
                        let _ = std::fs::remove_file(pin.path());
                    }
                    let _ = std::fs::remove_dir(entry.path());
                }
            }
            let _ = std::fs::remove_dir(&self.directory);
        }
        if self.created_artifacts {
            let _ = std::fs::remove_dir_all(&self.artifacts);
        }
        if self.isolated {
            // Failed restoration must not return another test to an unexpected network or mount view.
            let restored = unsafe {
                libc::setns(self.original_namespace.as_raw_fd(), libc::CLONE_NEWNET) == 0
                    && libc::setns(self.original_mount.as_raw_fd(), libc::CLONE_NEWNS) == 0
            };
            let net = std::fs::metadata("/proc/thread-self/ns/net").map(|metadata| metadata.ino());
            let mount =
                std::fs::metadata("/proc/thread-self/ns/mnt").map(|metadata| metadata.ino());
            if !restored
                || net.ok() != Some(self.namespace_inodes.0)
                || mount.ok() != Some(self.namespace_inodes.1)
            {
                eprintln!(
                    "Native gate namespace restoration failed; retain guest custody until VM poweroff"
                );
                std::process::abort();
            }
        }
    }
}

fn gate_capture(ifindex: u32) -> io::Result<GeneralCapture> {
    let mut capture = capture();
    capture.authority.namespace_cookie = gate_bpf::current_namespace_cookie()?;
    capture.authority.ifindex = ifindex;
    Ok(capture)
}

fn gate_open(root: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct Get {
        path: u64,
        fd: u32,
        flags: u32,
        root: i32,
        pad: u32,
    }
    gate_bpf::bpf_fd(
        7,
        &mut Get {
            path: name.as_ptr() as u64,
            fd: 0,
            flags: gate_bpf::BPF_F_PATH_FD,
            root: root.as_raw_fd(),
            pad: 0,
        },
    )
}

type PinEntry = (String, u32, u32, u64, u64);

#[derive(Debug, PartialEq, Eq)]
struct GateInventory {
    namespace: (u64, u64, u64),
    device: (u64, u32, String, String),
    directory: (u64, u64),
    ingress: Vec<(u32, u32)>,
    egress: Vec<(u32, u32)>,
    revisions: (u64, u64),
    pins: Vec<PinEntry>,
    links: Vec<(u32, u32, u32, u32, u32)>,
    xdp: gate_bpf::XdpState,
}

fn gate_inventory(ifindex: u32, device: &str, pins: &Path) -> io::Result<GateInventory> {
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    let device_path = Path::new("/sys/class/net").join(device);
    let metadata = std::fs::metadata(&device_path)?;
    if gate_index(device)? != ifindex {
        return Err(io::Error::other("owned device identity changed"));
    }
    let root = gate_bpf::private_bpffs(pins)?;
    let mut pinned = Vec::new();
    let mut links = Vec::new();
    for entry in std::fs::read_dir(pins)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("non-UTF8 pin"))?;
        let c_name = CString::new(name.as_str()).map_err(io::Error::other)?;
        let program = gate_open(root.as_fd(), &c_name)?;
        let mut info = gate_bpf::ProgInfo::default();
        gate_bpf::object_info(program.as_fd(), &mut info)?;
        if name.ends_with("-link") {
            let mut link = [0u32; 6];
            gate_bpf::object_info(program.as_fd(), &mut link)?;
            links.push((link[1], link[0], link[2], link[4], link[5]));
        }
        let metadata = entry.metadata()?;
        pinned.push((name, info.kind, info.id, metadata.dev(), metadata.ino()));
    }
    pinned.sort();
    links.sort_unstable();
    let ingress = gate_bpf::query_tcx(ifindex, gate_bpf::BPF_TCX_INGRESS)?;
    let egress = gate_bpf::query_tcx(ifindex, gate_bpf::BPF_TCX_EGRESS)?;
    let entries = |chain: &gate_bpf::TcxChain| {
        chain.programs[..chain.count]
            .iter()
            .copied()
            .zip(chain.links[..chain.count].iter().copied())
            .collect()
    };
    Ok(GateInventory {
        namespace: (
            namespace.dev(),
            namespace.ino(),
            gate_bpf::current_namespace_cookie()?,
        ),
        device: (
            metadata.ino(),
            ifindex,
            std::fs::read_to_string(device_path.join("iflink"))?,
            std::fs::read_to_string(device_path.join("address"))?,
        ),
        directory: gate_bpf::directory_identity(root.as_fd())?,
        ingress: entries(&ingress),
        egress: entries(&egress),
        revisions: (ingress.revision, egress.revision),
        pins: pinned,
        links,
        xdp: gate_bpf::xdp_state(ifindex)?,
    })
}

// Only syscall prefixes and the terminal post-restorer chain are singletons.
fn gate_singleton(inventory: &GateInventory, expected: u32) {
    assert_eq!(
        inventory.ingress,
        [(expected, 0)],
        "NOT_EXERCISED: exact non-link gate"
    );
    assert!(inventory.egress.is_empty(), "NOT_EXERCISED: foreign egress");
    assert!(
        inventory.pins.iter().any(|pin| pin.0 == "native-gate-prog"
            && pin.1 == gate_bpf::BPF_PROG_TYPE_SCHED_CLS
            && pin.2 == expected),
        "NOT_EXERCISED: exact gate program pin"
    );
}

fn gate_captured_chain(
    inventory: &GateInventory,
    expected: u32,
    resources: &[gate_bpf::CapturedResource],
) {
    use gate_bpf::CapturedResourceState::Installed;
    let program = resources
        .iter()
        .find(|item| {
            item.role == "native-return-restorer-prog" && item.ifindex == inventory.device.1
        })
        .expect("NOT_EXERCISED: owned restorer program");
    let link = resources
        .iter()
        .find(|item| {
            item.role == "native-return-restorer-link" && item.ifindex == inventory.device.1
        })
        .expect("NOT_EXERCISED: owned restorer link");
    assert_eq!((program.state, link.state), (Installed, Installed));
    assert!(program.id != 0 && link.id != 0);
    gate_captured_ids(inventory, expected, program.id, link.id);
}

fn gate_captured_ids(inventory: &GateInventory, expected: u32, program: u32, link: u32) {
    assert_eq!(
        inventory.ingress,
        [(program, link), (expected, 0)],
        "NOT_EXERCISED: exact owned restorer before existing non-link gate"
    );
    assert!(inventory.egress.is_empty(), "NOT_EXERCISED: foreign egress");
    for (role, kind, id) in [
        (
            "native-gate-prog",
            gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
            expected,
        ),
        (
            "native-return-restorer-prog",
            gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
            program,
        ),
        ("native-return-restorer-link", 11, link),
    ] {
        assert!(
            inventory
                .pins
                .iter()
                .any(|pin| pin.0 == role && pin.1 == kind && pin.2 == id),
            "NOT_EXERCISED: missing exact {role} pin"
        );
    }
    assert!(
        inventory.links.contains(&(
            link,
            11,
            program,
            inventory.device.1,
            gate_bpf::BPF_TCX_INGRESS
        )),
        "NOT_EXERCISED: restorer link/program/device relation"
    );
}

struct GateCaptured {
    root: host::CapturedFixtureMap,
    operation: host::CapturedFixtureMap,
    _tap: OwnedFd,
    pin_root: PathBuf,
    loaded: gate_bpf::CapturedPrograms,
    _cold: std::mem::ManuallyDrop<honk_netstack::MemoryReservation>,
}

impl GateCaptured {
    fn new(
        pin_root: &Path,
        target: Arc<gate_bpf::NativeTarget>,
        maps: &mut GateNative,
    ) -> io::Result<Self> {
        let ifindex = target.capture().authority.ifindex;
        Self::new_targets(
            pin_root,
            &[gate_bpf::CapturedTarget {
                realm_index: 0,
                logical_ifindex: ifindex,
                target,
            }],
            maps,
        )
    }

    fn new_targets(
        pin_root: &Path,
        targets: &[gate_bpf::CapturedTarget],
        maps: &mut GateNative,
    ) -> io::Result<Self> {
        let target = &targets
            .first()
            .ok_or_else(|| io::Error::other("empty captured fixture targets"))?
            .target;
        let cold_bytes = gate_bpf::NativeTarget::captured_preparation_bytes(1500, targets.len())?;
        let budget = honk_netstack::MemoryBudget::new(cold_bytes);
        // Raw custody pins can survive this fixture, so the cold charge stays until process exit.
        let cold = std::mem::ManuallyDrop::new(budget.reserve(cold_bytes).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "captured fixture cold reserve")
        })?);
        let tap_fd = host::captured_fixture_tap_open()?;
        let layout = target.admit_captured_layout()?;
        let root =
            host::CapturedFixtureMap::new(size_of::<gate_bpf::NativeRoot>(), b"hg_ret_root")?;
        maps.root = root.fd.try_clone()?;
        maps.epoch(2)?;
        let operation = host::CapturedFixtureMap::new(
            size_of::<honk_ebpf_common::xdp::NativeCapturedOperation>(),
            b"hg_ret_op",
        )?;
        let ifindex = target.capture().authority.ifindex;
        let name = format!("hgr{ifindex:x}");
        let tap = host::captured_fixture_tap(&name, tap_fd)?;
        for (key, value) in [("disable_ipv6", "1"), ("accept_ra", "0"), ("autoconf", "0")] {
            std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/{key}"), value)?;
        }
        gate_command(&[
            "link",
            "set",
            "dev",
            &name,
            "addrgenmode",
            "none",
            "mtu",
            "1500",
            "up",
        ])?;
        let table = format!("honk_gate_return_{ifindex}");
        let status = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped())
            .spawn().and_then(|mut child| {
                use std::io::Write as _;
                child.stdin.take().unwrap().write_all(format!(
                    "add table netdev {table}\nadd chain netdev {table} tap {{ type filter hook ingress device \"{name}\" priority 0; policy drop; }}\n").as_bytes())?;
                child.wait()
            })?;
        if !status.success() {
            return Err(io::Error::other("private TAP terminal DROP setup failed"));
        }
        let config = gate_bpf::CapturedProgramConfig {
            root: root.fd.as_fd(),
            operation: operation.fd.as_fd(),
            return_attachment: u64::from(ifindex),
            tap_ifindex: gate_index(&name)?,
            targets,
            pin_root,
        };
        let loaded = targets[0].target.load_captured_programs(&config, layout)?;
        loaded.check()?;
        Ok(Self {
            root,
            operation,
            _tap: tap,
            pin_root: pin_root.to_owned(),
            loaded,
            _cold: cold,
        })
    }

    fn config(&self) -> gate_bpf::CapturedProgramConfig<'_> {
        gate_bpf::CapturedProgramConfig {
            root: self.root.fd.as_fd(),
            operation: self.operation.fd.as_fd(),
            return_attachment: self.loaded.return_attachment(),
            tap_ifindex: self.loaded.tap_ifindex(),
            targets: self.loaded.targets(),
            pin_root: &self.pin_root,
        }
    }

    fn pin_inventory(&self) -> io::Result<Vec<PinEntry>> {
        let directory = self
            .pin_root
            .join(format!("native-return-{}", self.loaded.return_attachment()));
        let root = gate_bpf::private_bpffs(&directory)?;
        let mut inventory = Vec::new();
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| io::Error::other("non-UTF8 private pin"))?;
            let object = gate_open(
                root.as_fd(),
                &CString::new(name.as_str()).map_err(io::Error::other)?,
            )?;
            let mut info = gate_bpf::ProgInfo::default();
            gate_bpf::object_info(object.as_fd(), &mut info)?;
            let metadata = entry.metadata()?;
            inventory.push((name, info.kind, info.id, metadata.dev(), metadata.ino()));
        }
        inventory.sort();
        Ok(inventory)
    }
}

fn gate_program(kind: u32, name: &[u8]) -> io::Result<(OwnedFd, u32)> {
    let mut builder = Builder::new();
    builder.emit(Insn::new(
        MOV_K,
        0,
        0,
        0,
        if kind == gate_bpf::BPF_PROG_TYPE_XDP {
            XDP_PASS
        } else {
            -1
        },
    ));
    builder.emit(Insn::new(EXIT, 0, 0, 0, 0));
    gate_bpf::load_typed_program(
        &builder.finish()?,
        name,
        &mut vec![0; 1 << 20],
        kind,
        if kind == gate_bpf::BPF_PROG_TYPE_XDP {
            gate_bpf::BPF_XDP
        } else {
            gate_bpf::BPF_TCX_INGRESS
        },
    )
}

fn gate_mutate(
    command: u32,
    program: BorrowedFd<'_>,
    ifindex: u32,
    revision: u64,
) -> io::Result<()> {
    gate_bpf::tcx_mutate_with(
        command,
        program,
        ifindex,
        revision,
        gate_bpf::duplicate_nonzero_fd,
        |command, attr| gate_bpf::bpf(command, attr).map(|_| ()),
        || Ok(()),
    )
}

fn gate_detach(program: BorrowedFd<'_>, ifindex: u32, revision: u64, id: u32) -> io::Result<()> {
    gate_bpf::tcx_mutate_with(
        gate_bpf::BPF_PROG_DETACH,
        program,
        ifindex,
        revision,
        gate_bpf::duplicate_nonzero_fd,
        |command, attr| gate_bpf::bpf(command, attr).map(|_| ()),
        || {
            let chain = gate_bpf::query_tcx(ifindex, gate_bpf::BPF_TCX_INGRESS)?;
            if chain.programs[..chain.count].contains(&id) {
                return Err(io::Error::other(
                    "exact detach did not remove the opened program",
                ));
            }
            Ok(())
        },
    )
}

struct GateNative {
    root: OwnedFd,
    claims: OwnedFd,
    scratch: OwnedFd,
    counters: OwnedFd,
    policy: Vec<gate_bpf::bpf_insn>,
}

impl GateNative {
    fn new() -> io::Result<Self> {
        use honk_ebpf_common::xdp::{NativeClaim, NativeClosedCounterV1, NativeKey, NativeScratch};
        let root = create_map(2, size_of::<gate_bpf::NativeRoot>() as u32, 1, b"hg_root")?;
        let claims = gate_bpf::bpf_fd(
            gate_bpf::BPF_MAP_CREATE,
            &mut gate_bpf::MapCreateAttr {
                map_type: 1,
                key_size: size_of::<NativeKey>() as u32,
                value_size: size_of::<NativeClaim>() as u32,
                max_entries: 64,
                map_flags: 0,
                inner_map_fd: 0,
                numa_node: 0,
                map_name: gate_bpf::object_name(b"hg_claims"),
            },
        )?;
        let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
        if !(1..=65536).contains(&cpus) {
            return Err(io::Error::other(
                "CPU inventory unavailable for native scratch",
            ));
        }
        let scratch = create_map(
            2,
            size_of::<NativeScratch>() as u32,
            cpus as u32,
            b"hg_scratch",
        )?;
        let counters = create_map(
            2,
            size_of::<NativeClosedCounterV1>() as u32,
            honk_ebpf_common::xdp::NATIVE_COUNTER_ENTRIES,
            b"hg_closed",
        )?;
        for epoch in [2, 4, 6] {
            for hook in 0..2 {
                let index =
                    honk_ebpf_common::xdp::native_closed_counter_index(epoch, hook).unwrap();
                let cell = NativeClosedCounterV1 {
                    epoch,
                    ..NativeClosedCounterV1::default()
                };
                gate_bpf::bpf(
                    gate_bpf::BPF_MAP_UPDATE_ELEM,
                    &mut gate_bpf::map_attr(counters.as_fd(), &index, &cell as *const _ as u64),
                )?;
            }
        }
        let mut policy = Builder::new();
        policy.emit(Insn::new(ST_W, 2, 0, 0, 0));
        policy.emit(Insn::new(ST_W, 2, 0, 12, 1));
        policy.emit(Insn::new(MOV_K, 0, 0, 0, 0));
        policy.emit(Insn::new(EXIT, 0, 0, 0, 0));
        let maps = Self {
            root,
            claims,
            scratch,
            counters,
            policy: policy
                .finish()?
                .insns
                .into_iter()
                .map(|instruction| {
                    // Both repr(C) instruction layouts contain the same eight initialized ABI bytes.
                    unsafe { std::mem::transmute::<Insn, gate_bpf::bpf_insn>(instruction) }
                })
                .collect(),
        };
        maps.epoch(2)?;
        Ok(maps)
    }

    fn epoch(&self, epoch: u64) -> io::Result<()> {
        self.epoch_flags(epoch, honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_ALL)
    }

    fn epoch_flags(&self, epoch: u64, flags: u32) -> io::Result<()> {
        let root = gate_bpf::NativeRoot {
            epoch,
            flags,
            reserved: 0,
        };
        gate_bpf::bpf(
            gate_bpf::BPF_MAP_UPDATE_ELEM,
            &mut gate_bpf::map_attr(self.root.as_fd(), &0, &root as *const _ as u64),
        )?;
        Ok(())
    }

    fn prepare(
        &self,
        target: &gate_bpf::NativeTarget,
        epoch: u64,
    ) -> io::Result<gate_bpf::NativePrograms> {
        target.prepare(&gate_bpf::NativeProgramConfig {
            bytecode: &self.policy,
            root: self.root.as_raw_fd(),
            claims: self.claims.as_raw_fd(),
            scratch: self.scratch.as_raw_fd(),
            closed_counters: self.counters.as_raw_fd(),
            hook_ids: [1, 2],
            epoch,
            scope: target.capture().authority.scope,
            expires_boottime_ns: u64::MAX,
            redirect_limit: 16,
            captured: None,
            reply_block_rules: &[],
            preparation_memory_bytes: target.preparation_memory_bytes()?,
        })
    }

    fn prepare_captured(
        &self,
        target: &gate_bpf::NativeTarget,
        epoch: u64,
        captured: &gate_bpf::CapturedProgramConfig<'_>,
    ) -> io::Result<gate_bpf::NativePrograms> {
        target.prepare(&gate_bpf::NativeProgramConfig {
            bytecode: &self.policy,
            root: self.root.as_raw_fd(),
            claims: self.claims.as_raw_fd(),
            scratch: self.scratch.as_raw_fd(),
            closed_counters: self.counters.as_raw_fd(),
            hook_ids: [1, 2],
            epoch,
            scope: target.capture().authority.scope,
            expires_boottime_ns: u64::MAX,
            redirect_limit: 16,
            captured: Some(captured),
            reply_block_rules: &[],
            preparation_memory_bytes: target.preparation_memory_bytes()?,
        })
    }
}

fn gate_packet_socket(ifindex: u32) -> io::Result<OwnedFd> {
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            u16::to_be(3) as i32,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = u16::to_be(3);
    address.sll_ifindex = ifindex as i32;
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_ll).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn gate_send(sender: BorrowedFd<'_>, frame: &[u8]) -> io::Result<()> {
    let sent = unsafe { libc::send(sender.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
    if sent != frame.len() as isize {
        return Err(if sent < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::other("short raw frame send")
        });
    }
    Ok(())
}

fn gate_tap(tap: BorrowedFd<'_>, marker: &[u8], timeout: Duration) -> io::Result<bool> {
    Ok(gate_tap_frame(tap, marker, timeout)?.is_some())
}

fn gate_tap_frame(
    tap: BorrowedFd<'_>,
    marker: &[u8],
    timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; 2048];
    loop {
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut size = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let length = unsafe {
            libc::recvfrom(
                tap.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                (&mut address as *mut libc::sockaddr_ll).cast(),
                &mut size,
            )
        };
        if length >= 0 {
            if address.sll_pkttype != libc::PACKET_OUTGOING
                && buffer[..length as usize]
                    .windows(marker.len())
                    .any(|bytes| bytes == marker)
            {
                return Ok(Some(buffer[..length as usize].to_vec()));
            }
        } else if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
            return Err(io::Error::last_os_error());
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn gate_frame(ipv6: bool, port: u16, marker: &[u8]) -> Vec<u8> {
    let source = if ipv6 {
        format!("[2001:db8:feed::1]:{port}")
    } else {
        format!("198.18.0.1:{port}")
    };
    let destination = if ipv6 {
        "[2001:db8:feed::2]:42000"
    } else {
        "198.18.0.2:42000"
    };
    let mut frame = packet(
        source.parse().unwrap(),
        destination.parse().unwrap(),
        [2, 0, 0, 0, 0, 1],
        0,
    );
    let transport = if ipv6 { 54 } else { 34 };
    frame.resize(transport + 8 + marker.len(), 0);
    frame[transport + 8..].copy_from_slice(marker);
    let udp_length = (8 + marker.len()) as u16;
    frame[transport + 4..transport + 6].copy_from_slice(&udp_length.to_be_bytes());
    frame[transport + 6..transport + 8].fill(0);
    if ipv6 {
        frame[18..20].copy_from_slice(&udp_length.to_be_bytes());
        let mut pseudo = frame[22..54].to_vec();
        pseudo.extend_from_slice(&(udp_length as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(&frame[transport..]);
        let sum = checksum(&pseudo);
        frame[transport + 6..transport + 8]
            .copy_from_slice(&if sum == 0 { u16::MAX } else { sum }.to_be_bytes());
    } else {
        frame[16..18].copy_from_slice(&(20 + udp_length).to_be_bytes());
        frame[24..26].fill(0);
        let sum = checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&sum.to_be_bytes());
    }
    frame.resize(frame.len().max(60), 0);
    frame
}

fn gate_tap_control(sender: BorrowedFd<'_>, tap: BorrowedFd<'_>, marker: &[u8]) {
    let mut frame = vec![0; 60 + marker.len()];
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    frame[60..].copy_from_slice(marker);
    gate_io(gate_send(sender, &frame));
    assert!(
        gate_io(gate_tap(tap, marker, Duration::from_secs(1))),
        "NOT_EXERCISED: ingress tap positive control did not arrive"
    );
}

fn gate_map_id(map: BorrowedFd<'_>) -> io::Result<u32> {
    let mut info = gate_bpf::ProgInfo::default();
    gate_bpf::object_info(map, &mut info)?;
    Ok(info.id)
}

fn gate_map_by_id(id: u32) -> io::Result<OwnedFd> {
    gate_bpf::bpf_fd(14, &mut [id, 0u32, 0u32])
}

fn gate_xsk_present(xsks: BorrowedFd<'_>) -> bool {
    let mut builder = Builder::new();
    builder.map_fd(xsks.as_raw_fd());
    builder.emit(Insn::new(ST_W, 10, 0, -4, 0));
    builder.emit(Insn::new(MOV_X, 2, 10, 0, 0));
    builder.emit(Insn::new(ADD_K, 2, 0, 0, -4));
    builder.emit(Insn::new(CALL, 0, 0, 0, 1));
    let absent = forward(&mut builder, JEQ_K, 0, 0, 0);
    builder.emit(Insn::new(MOV_K, 0, 0, 0, XDP_PASS));
    builder.emit(Insn::new(EXIT, 0, 0, 0, 0));
    patch(&mut builder, absent);
    builder.emit(Insn::new(MOV_K, 0, 0, 0, XDP_DROP));
    builder.emit(Insn::new(EXIT, 0, 0, 0, 0));
    let (program, _) = gate_io(load_program(
        &gate_io(builder.finish()),
        b"hg_xsk_read",
        &mut vec![0; 1 << 20],
    ));
    // XSKMAP deliberately rejects userspace LOOKUP; a real helper invocation can observe membership.
    let frame = gate_frame(false, 41999, b"membership-only");
    let mut request = TestRun {
        program: program.as_raw_fd() as u32,
        input_len: frame.len() as u32,
        input: frame.as_ptr() as u64,
        repeat: 1,
        ..TestRun::default()
    };
    gate_io(gate_bpf::bpf(10, &mut request));
    match request.action {
        value if value == XDP_PASS as u32 => true,
        value if value == XDP_DROP as u32 => false,
        value => panic!("NOT_EXERCISED: XSK membership probe returned {value}"),
    }
}

fn gate_candidate_slot(dispatch: BorrowedFd<'_>) -> Option<u32> {
    match gate_bpf::map_value(dispatch, &1) {
        Ok(value) => Some(value),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
        Err(error) => panic!("NOT_EXERCISED: TC candidate slot readback: {error}"),
    }
}

fn gate_creator_child() -> ! {
    let index = gate_io(
        std::env::var("HONK_GATE_IFINDEX")
            .map_err(io::Error::other)
            .and_then(|value| value.parse::<u32>().map_err(io::Error::other)),
    );
    let pins =
        PathBuf::from(std::env::var_os("HONK_GATE_PINS").expect("NOT_EXERCISED: child pin path"));
    let ready = PathBuf::from(
        std::env::var_os("HONK_GATE_READY").expect("NOT_EXERCISED: child readiness path"),
    );
    let mode = std::env::var("HONK_GATE_CHILD_MODE").expect("NOT_EXERCISED: child mode");
    let capture = gate_io(gate_capture(index));
    let programs = gate_io(Programs::load_general_native(&capture, 1, &[]));
    let attachment = gate_io(gate_bpf::PersistentAttachment::create(
        index, &programs, &pins,
    ));
    let counters = gate_io(gate_map_id(programs.counters.as_fd()));
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    if mode == "attach-return" {
        gate_io(std::fs::write(
            &ready,
            format!(
                "{tid} {} {} {counters}\n",
                programs.discover_id, programs.data_id
            ),
        ));
        assert_eq!(
            unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) },
            0,
            "NOT_EXERCISED: PTRACE_TRACEME: {}",
            io::Error::last_os_error()
        );
        assert_eq!(
            unsafe { libc::raise(libc::SIGTRAP) },
            0,
            "NOT_EXERCISED: trace rendezvous"
        );
        let _gate = gate_io(programs.attach_native_gate(&attachment, &pins));
        panic!("NOT_EXERCISED: parent missed successful PROG_ATTACH syscall exit");
    }
    assert_eq!(mode, "ready", "NOT_EXERCISED: unknown creator checkpoint");
    let gate = gate_io(programs.attach_native_gate(&attachment, &pins));
    let target = Arc::new(gate_io(programs.native_target(&capture, &[], &attachment)));
    let mut native = gate_io(GateNative::new());
    let captured = gate_io(GateCaptured::new(
        pins.parent().unwrap(),
        Arc::clone(&target),
        &mut native,
    ));
    let budget = honk_netstack::MemoryBudget::new(4 << 20);
    let mut port = gate_io(crate::Port::<u32>::open_device(
        index,
        0,
        crate::BindMode::Copy,
        crate::PortConfig {
            rx_frames: 16,
            control_frames: 2,
            bulk_frames: 2,
            ring_size: 16,
        },
        1500,
        false,
        honk_ebpf_common::xdp::NATIVE_METADATA_LEN,
        &budget,
    ));
    gate_io(port.refill());
    let socket = port.as_raw_fd() as u32;
    gate_io(gate_bpf::bpf(
        gate_bpf::BPF_MAP_UPDATE_ELEM,
        &mut gate_bpf::map_attr(programs.xsks.as_fd(), &0, &socket as *const _ as u64),
    ));
    assert!(
        gate_xsk_present(programs.xsks.as_fd()),
        "NOT_EXERCISED: ready creator did not publish a live XSK"
    );
    let data = gate_io(native.prepare_captured(&target, 2, &captured.config()));
    gate_io(data.publish(&target));
    gate_io(target.finish_publication());
    gate_io(attachment.replace(&programs));
    gate_io(native.epoch(3));
    let dispatch = programs
        .native_dispatch_fd()
        .expect("NOT_EXERCISED: native dispatcher");
    let slot: u32 = gate_io(gate_bpf::map_value(dispatch, &1));
    assert_eq!(
        slot,
        data.tc_program_id(),
        "NOT_EXERCISED: ready candidate slot"
    );
    gate_io(std::fs::write(
        &ready,
        format!(
            "{tid} {} {} {counters} {} {} {} {} {} {} {}\n",
            programs.discover_id,
            data.program_id(),
            gate.program_id(),
            gate_io(gate_map_id(dispatch)),
            gate_io(gate_map_id(programs.xsks.as_fd())),
            gate_io(gate_map_id(native.root.as_fd())),
            slot,
            captured
                .loaded
                .inventory()
                .iter()
                .find(|item| item.role == "native-return-restorer-prog" && item.ifindex == index)
                .unwrap()
                .id,
            captured
                .loaded
                .inventory()
                .iter()
                .find(|item| item.role == "native-return-restorer-link" && item.ifindex == index)
                .unwrap()
                .id,
        ),
    ));
    assert_eq!(
        unsafe { libc::raise(libc::SIGSTOP) },
        0,
        "NOT_EXERCISED: readiness rendezvous"
    );
    panic!("NOT_EXERCISED: creator resumed instead of being killed");
}

struct GateChild {
    process: Child,
    tid: libc::pid_t,
    ready: Vec<u64>,
    traced: bool,
    reaped: bool,
}

impl GateChild {
    fn spawn(fixture: &GateFixture, name: &str, mode: &str) -> Self {
        let exact = format!("bpf::general::tests::{name}");
        let ready_path = fixture.artifacts.join("creator-ready");
        let process = gate_io(
            Command::new(gate_io(std::env::current_exe()))
                .args([
                    "--exact",
                    &exact,
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("HONK_GATE_CHILD_MODE", mode)
                .env("HONK_GATE_IFINDEX", fixture.ifindex.to_string())
                .env("HONK_GATE_PINS", &fixture.pins)
                .env("HONK_GATE_READY", &ready_path)
                .env("HONK_XDP_PIN_ROOT", &fixture.directory)
                .stdin(Stdio::null())
                .spawn(),
        );
        let mut child = Self {
            process,
            tid: 0,
            ready: Vec::new(),
            traced: false,
            reaped: false,
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(text) = std::fs::read_to_string(&ready_path)
                && text.ends_with('\n')
            {
                child.ready = text
                    .split_whitespace()
                    .map(|word| {
                        word.parse::<u64>()
                            .expect("NOT_EXERCISED: malformed creator identity")
                    })
                    .collect();
                assert!(
                    child.ready.len() >= 4,
                    "NOT_EXERCISED: incomplete creator identity"
                );
                child.tid = child.ready[0] as libc::pid_t;
                break;
            }
            assert!(
                gate_io(child.process.try_wait()).is_none(),
                "NOT_EXERCISED: creator exited before rendezvous"
            );
            assert!(
                Instant::now() < deadline,
                "NOT_EXERCISED: creator rendezvous deadline"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        child
    }

    fn stop(&mut self, traced: bool) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut status = 0;
            let who = if traced {
                self.tid
            } else {
                self.process.id() as libc::pid_t
            };
            let result = unsafe {
                libc::waitpid(
                    who,
                    &mut status,
                    libc::WNOHANG | libc::WUNTRACED | libc::__WALL,
                )
            };
            assert!(
                result >= 0,
                "NOT_EXERCISED: waitpid: {}",
                io::Error::last_os_error()
            );
            if result != 0 {
                assert!(
                    libc::WIFSTOPPED(status),
                    "NOT_EXERCISED: creator exited before syscall checkpoint: {status}"
                );
                return libc::WSTOPSIG(status);
            }
            assert!(
                Instant::now() < deadline,
                "NOT_EXERCISED: creator syscall stop deadline"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn kill_and_reap(&mut self) {
        gate_io(self.process.kill());
        if self.traced && self.tid != self.process.id() as libc::pid_t {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.tid, &mut status, libc::__WALL) };
            assert_eq!(
                result, self.tid,
                "NOT_EXERCISED: traced creator thread was not reaped"
            );
            assert!(
                libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
                "NOT_EXERCISED: traced creator thread did not terminate by SIGKILL"
            );
        }
        let status = gate_io(self.process.wait());
        self.reaped = true;
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "NOT_EXERCISED: creator was not SIGKILLed and reaped"
        );
    }
}

impl Drop for GateChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.process.kill();
            if self.traced && self.tid != self.process.id() as libc::pid_t {
                let mut status = 0;
                unsafe { libc::waitpid(self.tid, &mut status, libc::__WALL) };
            }
            let _ = self.process.wait();
        }
    }
}

fn gate_attach_syscall_exit(child: &mut GateChild) -> u32 {
    child.traced = true;
    assert_eq!(
        child.stop(true),
        libc::SIGTRAP,
        "NOT_EXERCISED: initial trace checkpoint"
    );
    assert_eq!(
        unsafe {
            libc::ptrace(
                libc::PTRACE_SETOPTIONS,
                child.tid,
                0,
                libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_EXITKILL,
            )
        },
        0,
        "NOT_EXERCISED: syscall trace options: {}",
        io::Error::last_os_error()
    );
    let mut attaching = None;
    for _ in 0..4096 {
        assert_eq!(
            unsafe { libc::ptrace(libc::PTRACE_SYSCALL, child.tid, 0, 0) },
            0,
            "NOT_EXERCISED: PTRACE_SYSCALL: {}",
            io::Error::last_os_error()
        );
        assert_eq!(
            child.stop(true),
            libc::SIGTRAP | 0x80,
            "NOT_EXERCISED: unexpected signal at gate syscall checkpoint"
        );
        let mut info = [0u64; 11];
        // GET_SYSCALL_INFO distinguishes entry from exit without guessing the first stop's phase.
        let length =
            unsafe { libc::ptrace(0x420e, child.tid, size_of::<[u64; 11]>(), info.as_mut_ptr()) };
        assert!(
            length >= 33,
            "NOT_EXERCISED: incomplete syscall information: {length}"
        );
        match (info[0] as u8, attaching) {
            (1, _) => {
                assert!(
                    length >= 80,
                    "NOT_EXERCISED: incomplete syscall entry arguments"
                );
                attaching = if info[3] == libc::SYS_bpf as u64
                    && matches!(
                        info[4] as u32,
                        gate_bpf::BPF_PROG_ATTACH | gate_bpf::BPF_LINK_CREATE
                    ) {
                    Some(info[4] as u32)
                } else {
                    None
                };
            }
            (2, Some(command)) => {
                let result = info[3] as i64;
                assert!(
                    if command == gate_bpf::BPF_PROG_ATTACH {
                        result == 0
                    } else {
                        result >= 0
                    },
                    "NOT_EXERCISED: gate command {command} failed before syscall-exit barrier: {result}"
                );
                assert_eq!(
                    info[4] as u8, 0,
                    "NOT_EXERCISED: gate command {command} returned a syscall error"
                );
                return command;
            }
            (2, None) => {}
            (operation, _) => {
                panic!("NOT_EXERCISED: unsupported syscall checkpoint operation {operation}")
            }
        }
    }
    panic!("NOT_EXERCISED: gate PROG_ATTACH/LINK_CREATE success-exit barrier was not reached");
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_survives_creator_death_after_attach() {
    require_vm();
    if std::env::var_os("HONK_GATE_CHILD_MODE").is_some() {
        gate_creator_child();
    }
    let fixture = gate_io(GateFixture::new());
    let sender = gate_io(gate_packet_socket(fixture.peer_ifindex));
    let tap = gate_io(gate_packet_socket(fixture.ifindex));
    let mut child = GateChild::spawn(
        &fixture,
        "kernel_native_gate_survives_creator_death_after_attach",
        "attach-return",
    );
    let command = gate_attach_syscall_exit(&mut child);
    eprintln!(
        "V1 frozen gate syscall-exit command={command}; no production query/return or link pin has run"
    );
    let before = gate_io(fixture.inventory());
    let expected = before
        .pins
        .iter()
        .find(|pin| pin.0 == "native-gate-prog")
        .expect("NOT_EXERCISED: gate was not pre-pinned at successful attach")
        .2;
    assert_eq!(
        before.ingress.len(),
        1,
        "NOT_EXERCISED: live creator has no singleton gate"
    );
    assert_eq!(
        before.ingress[0].0, expected,
        "NOT_EXERCISED: live gate differs from pre-pinned program"
    );
    assert_eq!(
        before.ingress[0].1 == 0,
        command == gate_bpf::BPF_PROG_ATTACH,
        "NOT_EXERCISED: live gate tuple does not match its actual mutation command"
    );
    assert!(
        before.egress.is_empty(),
        "NOT_EXERCISED: foreign egress at live creator barrier"
    );
    assert!(
        before.pins.iter().any(|pin| pin.0 == "native-gate-prog"
            && pin.1 == gate_bpf::BPF_PROG_TYPE_SCHED_CLS
            && pin.2 == expected),
        "NOT_EXERCISED: live gate has no exact SCHED_CLS program pin"
    );
    gate_io(gate_bpf::require_native(before.xdp, child.ready[1] as u32));
    child.kill_and_reap();
    let after = gate_io(fixture.inventory());
    gate_singleton(&after, expected);
    assert_eq!(
        after, before,
        "gate custody changed after death before production query/return"
    );
    let counters = gate_io(gate_map_by_id(child.ready[3] as u32));
    gate_tap_control(sender.as_fd(), tap.as_fd(), b"V1-tap-positive");
    for (ipv6, marker) in [
        (false, b"V1-selected-v4".as_slice()),
        (true, b"V1-selected-v6".as_slice()),
    ] {
        let count: u64 = gate_io(gate_bpf::map_value(counters.as_fd(), &0));
        gate_io(gate_send(sender.as_fd(), &gate_frame(ipv6, 41001, marker)));
        assert!(
            !gate_io(gate_tap(tap.as_fd(), marker, Duration::from_millis(100))),
            "Selected frame crossed the bootstrap pre-tap boundary after creator death"
        );
        let next: u64 = gate_io(gate_bpf::map_value(counters.as_fd(), &0));
        assert_eq!(
            next,
            count + 1,
            "NOT_EXERCISED: actual dual-stack Selected guard branch was not reached"
        );
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_failure_points_retain_custody() {
    require_vm();
    use std::cell::Cell;
    for failure in [
        "pin",
        "pre-info",
        "attach",
        "query",
        "post-info",
        "register",
        "normal-exit",
    ] {
        let fixture = gate_io(GateFixture::new());
        let (programs, attachment) = gate_io(fixture.bootstrap());
        let guard_id = programs.discover_id;
        let dispatch = programs
            .native_dispatch
            .as_ref()
            .expect("NOT_EXERCISED: native dispatch");
        let body = gate_io(gate_bpf::native::dispatch(
            &dispatch.capture,
            &dispatch.broadcasts,
            dispatch.map.as_raw_fd(),
        ));
        let (program, program_id) = gate_io(gate_bpf::load_typed_program(
            &body,
            b"honk_nat_gate",
            &mut vec![0; 1 << 20],
            gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
            gate_bpf::BPF_TCX_INGRESS,
        ));
        let owner = Arc::new(gate_bpf::NativeTcxAttachment {
            program,
            program_id,
            root: gate_io(gate_bpf::private_bpffs(&fixture.pins)),
            ifindex: fixture.ifindex,
            authority: gate_io(fixture.capture()).authority,
            pin: fixture.pins.join("native-gate-prog"),
            captured: std::sync::Mutex::new(None),
        });
        let weak = Arc::downgrade(&owner);
        let attached = Cell::new(false);
        let injected = Cell::new(false);
        let mutations = Cell::new(0);
        let failed = || {
            injected.set(true);
            io::Error::from_raw_os_error(libc::EIO)
        };
        let result = gate_bpf::install_native_gate_with(
            owner,
            |owner| {
                assert!(
                    gate_io(fixture.inventory()).ingress.is_empty(),
                    "pre-pin barrier observed an attach before program custody"
                );
                if failure == "pin" {
                    return Err(failed());
                }
                gate_bpf::pin_program(
                    owner.root.as_fd(),
                    c"native-gate-prog",
                    owner.program.as_fd(),
                )
            },
            |owner| {
                if failure
                    == if attached.get() {
                        "post-info"
                    } else {
                        "pre-info"
                    }
                {
                    return Err(failed());
                }
                gate_bpf::pinned_program_id(
                    owner.root.as_fd(),
                    c"native-gate-prog",
                    gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
                )
            },
            |ifindex, direction| {
                if attached.get() && failure == "query" {
                    return Err(failed());
                }
                gate_bpf::query_tcx(ifindex, direction)
            },
            |command, attr| {
                assert_eq!(
                    command,
                    gate_bpf::BPF_PROG_ATTACH,
                    "failure rollback sent a detach"
                );
                mutations.set(mutations.get() + 1);
                if failure == "attach" {
                    return Err(failed());
                }
                gate_bpf::bpf(command, attr)?;
                attached.set(true);
                Ok(())
            },
            |owner| {
                if failure == "register" {
                    return Err(failed());
                }
                attachment
                    .native
                    .as_ref()
                    .expect("NOT_EXERCISED: native owner")
                    .lock()
                    .map_err(|_| io::Error::other("native owner lock poisoned"))?
                    .register_gate(owner)
            },
        );
        if failure == "normal-exit" {
            drop(gate_io(result));
        } else {
            assert!(
                injected.get(),
                "NOT_EXERCISED: {failure} injection was not reached"
            );
            assert_eq!(
                result
                    .err()
                    .expect("injected installation failure unexpectedly succeeded")
                    .raw_os_error(),
                Some(libc::EIO)
            );
            assert!(
                attachment.replace(&programs).is_err(),
                "failed installation allowed XDP data activation"
            );
        }
        assert_eq!(
            mutations.get(),
            usize::from(!matches!(failure, "pin" | "pre-info"))
        );
        assert!(
            !gate_xsk_present(programs.xsks.as_fd()),
            "NOT_EXERCISED: failure fixture opened an XSK"
        );
        let slot = gate_bpf::map_value::<u32>(programs.native_dispatch_fd().unwrap(), &1);
        assert_eq!(
            slot.unwrap_err().raw_os_error(),
            Some(libc::ENOENT),
            "NOT_EXERCISED: failure fixture published TC slot one"
        );
        let installed = matches!(failure, "query" | "post-info" | "register" | "normal-exit");
        drop(attachment);
        drop(programs);
        assert!(
            weak.upgrade().is_none(),
            "NOT_EXERCISED: a Rust owner survived the exit checkpoint"
        );
        let inventory = gate_io(fixture.inventory());
        if installed {
            gate_singleton(&inventory, program_id);
        } else {
            assert!(
                inventory.ingress.is_empty(),
                "pre-attach failure attached a gate"
            );
        }
        assert_eq!(
            inventory.pins.iter().any(|pin| pin.0 == "native-gate-prog"),
            failure != "pin"
        );
        gate_io(gate_bpf::require_native(inventory.xdp, guard_id));
    }
}

fn gate_legacy_link(ifindex: u32, program: BorrowedFd<'_>, id: u32) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct Create {
        program: u32,
        target: u32,
        attach_type: u32,
        flags: u32,
        relative: u32,
        pad: u32,
        revision: u64,
    }
    let revision = gate_bpf::query_tcx(ifindex, gate_bpf::BPF_TCX_INGRESS)?.revision;
    let link = gate_bpf::bpf_fd(
        gate_bpf::BPF_LINK_CREATE,
        &mut Create {
            program: program.as_raw_fd() as u32,
            target: ifindex,
            attach_type: gate_bpf::BPF_TCX_INGRESS,
            flags: 0,
            relative: 0,
            pad: 0,
            revision,
        },
    )?;
    let mut info = [0u32; 6];
    gate_bpf::object_info(link.as_fd(), &mut info)?;
    if info[0] != 11
        || info[1] == 0
        || info[2] != id
        || info[4] != ifindex
        || info[5] != gate_bpf::BPF_TCX_INGRESS
    {
        return Err(io::Error::other(format!(
            "legacy TCX link identity mismatch: {info:?}"
        )));
    }
    Ok(link)
}

fn gate_closed(fixture: &GateFixture, native: &GateNative, guard: u32) {
    let root: gate_bpf::NativeRoot = gate_io(gate_bpf::map_value(native.root.as_fd(), &0));
    assert_eq!(root.epoch, 2, "rejection changed the closed root epoch");
    assert_eq!(root.reserved, 0, "rejection changed the closed root ABI");
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(fixture.ifindex)),
        guard,
    ));
}

// These singleton controls exercise the TCX syscall compare ABI before captured readiness.
#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_production_kernel_compare_rejections() {
    require_vm();
    let fixture = gate_io(GateFixture::new());
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let expected = gate.program_id();
    let native = gate_io(GateNative::new());
    let (advance, advance_id) = gate_io(gate_program(
        gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
        b"hg_revision",
    ));
    let (fresh, fresh_id) = gate_io(gate_program(gate_bpf::BPF_PROG_TYPE_SCHED_CLS, b"hg_fresh"));
    assert!(
        gate.program.as_raw_fd() > 0 && fresh.as_raw_fd() > 0,
        "NOT_EXERCISED: nonzero exact program FDs"
    );
    for command in [gate_bpf::BPF_PROG_ATTACH, gate_bpf::BPF_PROG_DETACH] {
        let old = gate_io(gate_bpf::query_tcx(
            fixture.ifindex,
            gate_bpf::BPF_TCX_INGRESS,
        ))
        .revision;
        gate_singleton(&gate_io(fixture.inventory()), expected);
        gate_io(gate_mutate(
            gate_bpf::BPF_PROG_ATTACH,
            advance.as_fd(),
            fixture.ifindex,
            old,
        ));
        let changed = gate_io(gate_bpf::query_tcx(
            fixture.ifindex,
            gate_bpf::BPF_TCX_INGRESS,
        ));
        assert!(
            changed.revision > old && changed.programs[..changed.count].contains(&expected),
            "NOT_EXERCISED: original bundle did not survive the revision advance"
        );
        gate_io(gate_detach(
            advance.as_fd(),
            fixture.ifindex,
            changed.revision,
            advance_id,
        ));
        let frozen = gate_io(fixture.inventory());
        gate_singleton(&frozen, expected);
        assert!(
            frozen.revisions.0 > changed.revision,
            "NOT_EXERCISED: removal did not advance the same live bundle"
        );
        assert!(
            !frozen.ingress.iter().any(|entry| entry.0 == fresh_id),
            "NOT_EXERCISED: stale attach candidate was already attached"
        );
        let program = if command == gate_bpf::BPF_PROG_ATTACH {
            fresh.as_fd()
        } else {
            gate.program.as_fd()
        };
        let result = gate_bpf::tcx_mutate_with(
            command,
            program,
            fixture.ifindex,
            old,
            gate_bpf::duplicate_nonzero_fd,
            |actual, attr| gate_bpf::bpf(actual, attr).map(|_| ()),
            || panic!("stale mutation reached success readback"),
        );
        let error = result.expect_err("stale production request unexpectedly succeeded");
        assert_eq!(
            error.raw_os_error(),
            Some(libc::ESTALE),
            "production command {command} rejected for the wrong reason: {error}"
        );
        assert_eq!(
            gate_io(fixture.inventory()),
            frozen,
            "stale production request changed objects, attachments or pins"
        );
        gate_closed(&fixture, &native, programs.discover_id);
    }
    let frozen = gate_io(fixture.inventory());
    let error = gate_mutate(
        gate_bpf::BPF_PROG_DETACH,
        fresh.as_fd(),
        fixture.ifindex,
        frozen.revisions.0,
    )
    .expect_err("wrong exact program FD detached the gate");
    assert_eq!(
        error.raw_os_error(),
        Some(libc::ENOENT),
        "wrong-FD production detach: {error}"
    );
    assert_eq!(gate_io(fixture.inventory()), frozen);
    gate_closed(&fixture, &native, programs.discover_id);
    let (legacy_program, legacy_id) = gate_io(gate_program(
        gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
        b"hg_legacy",
    ));
    let legacy = gate_io(gate_legacy_link(
        fixture.ifindex,
        legacy_program.as_fd(),
        legacy_id,
    ));
    gate_io(gate_bpf::pin_program(
        gate.root.as_fd(),
        c"native-gate-link",
        legacy.as_fd(),
    ));
    let frozen = gate_io(fixture.inventory());
    assert!(
        frozen
            .ingress
            .iter()
            .any(|entry| entry.0 == legacy_id && entry.1 != 0),
        "NOT_EXERCISED: legacy item is not a real link attachment"
    );
    let error = gate_mutate(
        gate_bpf::BPF_PROG_DETACH,
        legacy_program.as_fd(),
        fixture.ifindex,
        frozen.revisions.0,
    )
    .expect_err("non-link production detach removed a legacy link");
    assert_eq!(
        error.raw_os_error(),
        Some(libc::EBUSY),
        "legacy-link production detach: {error}"
    );
    assert_eq!(gate_io(fixture.inventory()), frozen);
    gate_closed(&fixture, &native, programs.discover_id);
}

// Raw TCX request-layout controls intentionally have no captured-return operation.
#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_abi_negative_controls() {
    require_vm();
    #[repr(C)]
    struct RawRequest {
        target: u32,
        program: u32,
        attach_type: u32,
        flags: u32,
        old_program: u32,
        relative: u32,
        revision: u64,
    }
    let fixture = gate_io(GateFixture::new());
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let native = gate_io(GateNative::new());
    let (wrong, _) = gate_io(gate_program(
        gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
        b"hg_wrong_old",
    ));
    let (replacement, replacement_id) = gate_io(gate_program(
        gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
        b"hg_replace_one",
    ));
    let frozen = gate_io(fixture.inventory());
    assert!(
        wrong.as_raw_fd() > 0 && replacement.as_raw_fd() > 0 && gate.program.as_raw_fd() > 0,
        "NOT_EXERCISED: ABI controls require nonzero valid exact FDs"
    );
    assert!(
        !frozen.ingress.iter().any(|entry| entry.0 == replacement_id),
        "NOT_EXERCISED: REPLACE candidate already attached"
    );
    let error = gate_bpf::bpf(
        gate_bpf::BPF_PROG_ATTACH,
        &mut RawRequest {
            target: fixture.ifindex,
            program: replacement.as_raw_fd() as u32,
            attach_type: gate_bpf::BPF_TCX_INGRESS,
            flags: 4,
            old_program: wrong.as_raw_fd() as u32,
            relative: 0,
            revision: frozen.revisions.0,
        },
    )
    .expect_err("raw wrong-old-FD REPLACE unexpectedly succeeded");
    assert_eq!(
        error.raw_os_error(),
        Some(libc::ENOENT),
        "ABI wrong-old-FD REPLACE: {error}"
    );
    assert_eq!(gate_io(fixture.inventory()), frozen);
    gate_closed(&fixture, &native, programs.discover_id);
    let error = gate_bpf::bpf(
        gate_bpf::BPF_PROG_DETACH,
        &mut RawRequest {
            target: fixture.ifindex,
            program: gate.program.as_raw_fd() as u32,
            attach_type: gate_bpf::BPF_TCX_INGRESS,
            flags: 4,
            old_program: 0,
            relative: 0,
            revision: frozen.revisions.0,
        },
    )
    .expect_err("raw DETACH|REPLACE unexpectedly succeeded");
    assert_eq!(
        error.raw_os_error(),
        Some(libc::EINVAL),
        "ABI DETACH|REPLACE: {error}"
    );
    assert_eq!(gate_io(fixture.inventory()), frozen);
    gate_closed(&fixture, &native, programs.discover_id);
    let (legacy_program, legacy_id) = gate_io(gate_program(
        gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
        b"hg_old_link",
    ));
    let legacy = gate_io(gate_legacy_link(
        fixture.ifindex,
        legacy_program.as_fd(),
        legacy_id,
    ));
    gate_io(gate_bpf::pin_program(
        gate.root.as_fd(),
        c"native-gate-link",
        legacy.as_fd(),
    ));
    let (replacement, replacement_id) = gate_io(gate_program(
        gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
        b"hg_replace_two",
    ));
    let frozen = gate_io(fixture.inventory());
    assert!(
        legacy_program.as_raw_fd() > 0 && replacement.as_raw_fd() > 0,
        "NOT_EXERCISED: legacy REPLACE requires nonzero valid exact FDs"
    );
    assert!(
        !frozen.ingress.iter().any(|entry| entry.0 == replacement_id),
        "NOT_EXERCISED: second REPLACE candidate already attached"
    );
    let error = gate_bpf::bpf(
        gate_bpf::BPF_PROG_ATTACH,
        &mut RawRequest {
            target: fixture.ifindex,
            program: replacement.as_raw_fd() as u32,
            attach_type: gate_bpf::BPF_TCX_INGRESS,
            flags: 4,
            old_program: legacy_program.as_raw_fd() as u32,
            relative: 0,
            revision: frozen.revisions.0,
        },
    )
    .expect_err("raw non-link REPLACE removed a legacy link");
    assert_eq!(
        error.raw_os_error(),
        Some(libc::EBUSY),
        "ABI legacy-link REPLACE: {error}"
    );
    assert_eq!(gate_io(fixture.inventory()), frozen);
    gate_closed(&fixture, &native, programs.discover_id);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_unlink_is_not_detach() {
    require_vm();
    // Unlink/detach syscall semantics are independent of production readiness.
    let fixture = gate_io(GateFixture::new());
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let expected = gate.program_id();
    let exact = gate_io(gate_open(gate.root.as_fd(), c"native-gate-prog"));
    assert!(
        exact.as_raw_fd() > 0,
        "NOT_EXERCISED: retained exact program FD must be nonzero"
    );
    let before = gate_io(fixture.inventory());
    gate_singleton(&before, expected);
    gate_io(gate_command(&["link", "set", "dev", &fixture.peer, "down"]));
    gate_io(std::fs::remove_file(gate.pin_path()));
    let unlinked = gate_io(fixture.inventory());
    assert_eq!(
        unlinked.ingress, before.ingress,
        "unlink unexpectedly detached the non-link gate"
    );
    assert_eq!(
        unlinked.revisions, before.revisions,
        "unlink changed TCX revision"
    );
    assert_eq!(
        unlinked.xdp, before.xdp,
        "unlink changed the exact XDP guard"
    );
    assert!(!unlinked.pins.iter().any(|pin| pin.0 == "native-gate-prog"));
    let mut identity = gate_bpf::ProgInfo::default();
    gate_io(gate_bpf::object_info(exact.as_fd(), &mut identity));
    assert_eq!(
        (identity.kind, identity.id),
        (gate_bpf::BPF_PROG_TYPE_SCHED_CLS, expected),
        "NOT_EXERCISED: unlink lost the already-opened exact program identity"
    );
    gate_io(gate_detach(
        exact.as_fd(),
        fixture.ifindex,
        unlinked.revisions.0,
        expected,
    ));
    let detached = gate_io(fixture.inventory());
    assert!(
        detached.ingress.is_empty() && detached.egress.is_empty(),
        "exact PROG_DETACH left a TCX item"
    );
    assert_eq!(
        detached.pins, unlinked.pins,
        "explicit detach changed other custody pins"
    );
    assert_eq!(detached.xdp, before.xdp);

    let recovered = gate_io(GateFixture::new());
    let (programs, gate, captured) = gate_recovery_setup(&recovered);
    let before = gate_io(recovered.inventory());
    gate_captured_chain(&before, gate.program_id(), &captured.loaded.inventory());
    gate_io(gate_bpf::require_native(before.xdp, programs.discover_id));
    assert_eq!(
        before
            .pins
            .iter()
            .map(|pin| pin.0.as_str())
            .collect::<Vec<_>>(),
        [
            "data",
            "guard",
            "native-gate-prog",
            "native-return-restorer-link",
            "native-return-restorer-prog"
        ],
        "NOT_EXERCISED: cleanup lacks the exact owned five-pin format"
    );
    gate_recovery_save(&recovered, &recovered, programs.discover_id);
    assert_eq!(
        gate_io(recovered.inventory()),
        before,
        "NOT_EXERCISED: cleanup inventory collection changed frozen custody"
    );
    let private_before = gate_io(captured.pin_inventory());
    let prefix = recovered.artifacts.join("recovery");
    let output = gate_io(gate_probe(
        &recovered,
        &[
            "native-cleanup",
            prefix
                .to_str()
                .expect("NOT_EXERCISED: cleanup artifact path is not UTF8"),
            &recovered.device,
        ],
    ));
    assert!(
        !output.status.success(),
        "loader-only native_cleanup fabricated a production join: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("missing, foreign or ambiguous joined captured-return receipt"),
        "NOT_EXERCISED: loader-only cleanup missed its required C receipt rejection: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        gate_io(gate_index(&recovered.device)),
        before.device.1,
        "NOT_EXERCISED: cleanup unregistered the test device"
    );
    assert_eq!(
        gate_io(std::fs::metadata(
            Path::new("/sys/class/net").join(&recovered.device)
        ))
        .ino(),
        before.device.0,
        "NOT_EXERCISED: cleanup replaced the test device"
    );
    let ingress = gate_io(gate_bpf::query_tcx(
        recovered.ifindex,
        gate_bpf::BPF_TCX_INGRESS,
    ));
    let egress = gate_io(gate_bpf::query_tcx(
        recovered.ifindex,
        gate_bpf::BPF_TCX_EGRESS,
    ));
    assert_eq!(
        (ingress.count, egress.count),
        (2, 0),
        "loader-only native_cleanup changed the retained target chain"
    );
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(recovered.ifindex)),
        programs.discover_id,
    ));
    for name in [
        "guard",
        "data",
        "native-gate-prog",
        "native-return-restorer-prog",
        "native-return-restorer-link",
    ] {
        assert!(
            gate_io(recovered.pins.join(name).try_exists()),
            "loader-only native_cleanup removed {name}"
        );
    }
    assert!(
        gate_io(recovered.pins.try_exists()),
        "loader-only native_cleanup removed its pin directory"
    );
    assert_eq!(
        gate_io(recovered.inventory()),
        before,
        "refused cleanup changed frozen physical custody"
    );
    assert_eq!(
        gate_io(captured.pin_inventory()),
        private_before,
        "refused cleanup changed private custody"
    );

    // An untouched Idle cell can close its raw hooks; only C can issue the production joined receipt.
    let operation: honk_ebpf_common::xdp::NativeCapturedOperation =
        gate_io(gate_bpf::map_value(captured.operation.fd.as_fd(), &0));
    assert_eq!(
        (operation.phase, operation.op_incarnation),
        (honk_ebpf_common::xdp::NATIVE_OP_IDLE, 0)
    );
    gate_io(captured.loaded.seal());
    assert!(
        gate_io(captured.loaded.finish_close()),
        "untouched idle raw loader failed to close"
    );
    let closed = gate_io(recovered.inventory());
    gate_singleton(&closed, gate.program_id());
    let output = gate_io(gate_probe(
        &recovered,
        &[
            "native-cleanup",
            prefix.to_str().unwrap(),
            &recovered.device,
        ],
    ));
    assert!(
        !output.status.success(),
        "raw loader close forged a C joined recovery receipt"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("missing, foreign or ambiguous joined captured-return receipt")
    );
    assert_eq!(
        gate_io(recovered.inventory()),
        closed,
        "receipt refusal removed terminal singleton custody"
    );
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_pre_tap_and_pre_ip_boundaries() {
    require_vm();
    let fixture = gate_io(GateFixture::new());
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let sender = gate_io(gate_packet_socket(fixture.peer_ifindex));
    let tap = gate_io(gate_packet_socket(fixture.ifindex));
    gate_tap_control(sender.as_fd(), tap.as_fd(), b"V3-bootstrap-tap-positive");
    let before = gate_io(fixture.inventory());
    assert!(
        before.ingress.is_empty(),
        "NOT_EXERCISED: bootstrap control already had a gate"
    );
    assert!(
        attachment.replace(&programs).is_err(),
        "missing gate admitted data selection"
    );
    assert_eq!(
        gate_io(fixture.inventory()),
        before,
        "missing-gate activation mutated custody"
    );
    for (ipv6, marker) in [
        (false, b"V3-bootstrap-v4".as_slice()),
        (true, b"V3-bootstrap-v6".as_slice()),
    ] {
        let count = gate_io(programs.counters()).per_queue[0];
        gate_io(gate_send(sender.as_fd(), &gate_frame(ipv6, 41003, marker)));
        assert!(
            !gate_io(gate_tap(tap.as_fd(), marker, Duration::from_millis(100))),
            "bootstrap Selected traffic crossed ingress tap without gate admission"
        );
        assert_eq!(
            gate_io(programs.counters()).per_queue[0],
            count + 1,
            "NOT_EXERCISED: bootstrap Selected branch was not reached"
        );
    }
    let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let target = Arc::new(gate_io(programs.native_target(
        &gate_io(fixture.capture()),
        &[],
        &attachment,
    )));
    let mut maps = gate_io(GateNative::new());
    let captured = gate_io(GateCaptured::new(
        &fixture.directory,
        Arc::clone(&target),
        &mut maps,
    ));
    let candidate = gate_io(maps.prepare_captured(&target, 2, &captured.config()));
    gate_io(candidate.publish(&target));
    gate_io(target.finish_publication());
    gate_io(attachment.replace(&programs));
    gate_io(maps.epoch(3));
    let receiver = gate_io(UdpSocket::bind("198.18.0.2:42000"));
    gate_io(receiver.set_read_timeout(Some(Duration::from_millis(250))));
    let mut bytes = [0u8; 128];
    gate_io(gate_send(
        sender.as_fd(),
        &gate_frame(false, 41004, b"V3-open-after-XDP"),
    ));
    assert!(
        gate_io(gate_tap(
            tap.as_fd(),
            b"V3-open-after-XDP",
            Duration::from_secs(1)
        )),
        "NOT_EXERCISED: real open candidate did not pass XDP and reach ingress tap"
    );
    let (length, _) = gate_io(receiver.recv_from(&mut bytes));
    assert_eq!(
        &bytes[..length],
        b"V3-open-after-XDP",
        "NOT_EXERCISED: open pre-IP positive control"
    );
    gate_io(
        gate_bpf::set_xdp(fixture.ifindex, -1, Some(candidate.xdp_program.as_raw_fd()))
            .map_err(io::Error::from),
    );
    assert!(
        gate_io(gate_bpf::xdp_absent(fixture.ifindex)),
        "NOT_EXERCISED: gate-only isolation still had XDP"
    );
    gate_io(gate.check());
    gate_io(gate_send(
        sender.as_fd(),
        &gate_frame(false, 41005, b"V3-gate-only-open"),
    ));
    assert!(
        gate_io(gate_tap(
            tap.as_fd(),
            b"V3-gate-only-open",
            Duration::from_secs(1)
        )),
        "NOT_EXERCISED: gate-only isolation failed to expose the pre-TCX tap"
    );
    let (length, _) = gate_io(receiver.recv_from(&mut bytes));
    assert_eq!(
        &bytes[..length],
        b"V3-gate-only-open",
        "NOT_EXERCISED: gate-only pre-IP positive control"
    );
    gate_io(maps.epoch(4));
    let index = honk_ebpf_common::xdp::native_closed_counter_index(4, 1).unwrap();
    let before: honk_ebpf_common::xdp::NativeClosedCounterV1 =
        gate_io(gate_bpf::map_value(maps.counters.as_fd(), &index));
    gate_io(gate_send(
        sender.as_fd(),
        &gate_frame(false, 41006, b"V3-gate-only-closed"),
    ));
    assert!(
        gate_io(gate_tap(
            tap.as_fd(),
            b"V3-gate-only-closed",
            Duration::from_secs(1)
        )),
        "NOT_EXERCISED: closed gate traffic never reached the independent ingress tap"
    );
    let error = receiver
        .recv_from(&mut bytes)
        .expect_err("closed TC candidate admitted a packet to IP/UDP");
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ),
        "NOT_EXERCISED: pre-IP observation failed for another reason: {error}"
    );
    let after: honk_ebpf_common::xdp::NativeClosedCounterV1 =
        gate_io(gate_bpf::map_value(maps.counters.as_fd(), &index));
    assert_eq!(
        after.ordinary_drops,
        before.ordinary_drops + 1,
        "NOT_EXERCISED: actual TC candidate closed-root check was not reached"
    );
    assert_eq!(
        after.overflow, 0,
        "NOT_EXERCISED: closed counter overflowed"
    );
    panic!(
        "NOT_EXERCISED: pre-tap/pre-IP compatibility observed; honk-xsk exposes no rendezvous to close epoch after a frame passes XDP and before TC/frontier recheck"
    );
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_captured_republication_same_epoch() {
    use std::mem::ManuallyDrop;

    require_vm();
    // Failure keeps the real owners and namespace; fixture teardown cannot satisfy these oracles.
    let fixture = ManuallyDrop::new(gate_io(GateFixture::new()));
    gate_io(gate_command(&["link", "set", "dev", &fixture.peer, "down"]));
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let programs = ManuallyDrop::new(programs);
    let attachment = ManuallyDrop::new(attachment);
    let gate = ManuallyDrop::new(gate_io(
        programs.attach_native_gate(&attachment, &fixture.pins),
    ));
    let target = ManuallyDrop::new(Arc::new(gate_io(programs.native_target(
        &gate_io(fixture.capture()),
        &[],
        &attachment,
    ))));
    let mut maps = ManuallyDrop::new(gate_io(GateNative::new()));
    let captured = ManuallyDrop::new(gate_io(GateCaptured::new(
        &fixture.directory,
        Arc::clone(&target),
        &mut maps,
    )));
    let root_id = captured.loaded.root_map_id();
    let directory = captured.pin_root.join(format!(
        "native-return-{}",
        captured.loaded.return_attachment()
    ));
    let pin_directory = ManuallyDrop::new(gate_io(gate_bpf::private_bpffs(&directory)));
    let realm_dispatch = ManuallyDrop::new(gate_io(gate_open(
        pin_directory.as_fd(),
        c"realm-dispatch-map",
    )));
    let pin_id = |path: &Path| {
        let name = CString::new(path.file_name().unwrap().as_encoded_bytes()).unwrap();
        let fd = gate_io(gate_open(pin_directory.as_fd(), &name));
        let mut info = gate_bpf::ProgInfo::default();
        gate_io(gate_bpf::object_info(fd.as_fd(), &mut info));
        assert_eq!(info.kind, gate_bpf::BPF_PROG_TYPE_XDP);
        info.id
    };
    let mut candidates = ManuallyDrop::new(Vec::<gate_bpf::NativePrograms>::with_capacity(3));
    let mut identities = Vec::<gate_bpf::CapturedGateIdentity>::with_capacity(3);
    let mut receipt_bound = 0;
    // The peer is down, no packet sockets exist, and the root never opens: there are no readers to join.
    for round in 0..3 {
        let root: gate_bpf::NativeRoot = gate_io(gate_bpf::map_value(maps.root.as_fd(), &0));
        assert_eq!((root.epoch, root.reserved), (2, 0));
        assert_eq!(gate_io(gate_map_id(maps.root.as_fd())), root_id);
        if let Some(previous) = identities.last() {
            assert!(gate_io(previous.resource.pin_path.try_exists()));
            assert_eq!(pin_id(&previous.resource.pin_path), previous.resource.id);
        }
        candidates.push(gate_io(maps.prepare_captured(
            &target,
            2,
            &captured.config(),
        )));
        let current = &candidates[round];
        let identity = current
            .captured_gate()
            .expect("actual canonical gate identity");
        assert_eq!((identity.realm_index, identity.closed_epoch), (0, 2));
        assert_eq!(current.root_fd(), maps.root.as_raw_fd());
        assert_ne!(identity.resource.id, 0);
        assert_eq!(pin_id(&identity.resource.pin_path), identity.resource.id);
        for (previous, candidate) in identities.iter().zip(candidates.iter()) {
            assert_ne!(identity.resource.pin_path, previous.resource.pin_path);
            assert_ne!(identity.resource.id, previous.resource.id);
            assert_ne!(current.program_id(), candidate.program_id());
            assert_ne!(current.tc_program_id(), candidate.tc_program_id());
        }
        if let Some(previous) = identities.last() {
            assert_eq!(pin_id(&previous.resource.pin_path), previous.resource.id);
        }
        if round == 1 {
            receipt_bound = captured.loaded.inventory().len();
        } else if round == 2 {
            let inventory = captured.loaded.inventory();
            assert_eq!(
                inventory.len(),
                receipt_bound,
                "retired object slot was not reused"
            );
            assert!(
                inventory
                    .iter()
                    .all(|item| item.pin_path != identities[0].resource.pin_path)
            );
            let retired = candidates[0].captured_gate().unwrap();
            assert_eq!(retired.resource.pin_path, identities[0].resource.pin_path);
            assert_eq!(retired.resource.id, identities[0].resource.id);
            assert_eq!(
                retired.resource.state,
                gate_bpf::CapturedResourceState::Unpinned
            );
        }
        gate_io(current.publish(&target));
        gate_io(attachment.replace(&programs));
        gate_io(gate_bpf::require_native(
            gate_io(gate_bpf::xdp_state(fixture.ifindex)),
            current.program_id(),
        ));
        assert_eq!(
            gate_io(gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)),
            current.tc_program_id()
        );
        assert_eq!(
            gate_io(gate_bpf::map_value::<u32>(realm_dispatch.as_fd(), &0)),
            identity.resource.id
        );
        if let Some(previous) = identities.last() {
            assert_eq!(pin_id(&previous.resource.pin_path), previous.resource.id);
        }
        gate_io(target.finish_publication());
        for previous in &identities {
            assert!(!gate_io(previous.resource.pin_path.try_exists()));
        }
        assert_eq!(pin_id(&identity.resource.pin_path), identity.resource.id);
        let selected = captured.loaded.realm_gate_inventory();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].resource.pin_path, identity.resource.pin_path);
        assert_eq!(selected[0].resource.id, identity.resource.id);
        gate_captured_chain(
            &gate_io(fixture.inventory()),
            gate.program_id(),
            &captured.loaded.inventory(),
        );
        gate_io(captured.loaded.check());
        identities.push(identity);
    }
    let operation: honk_ebpf_common::xdp::NativeCapturedOperation =
        gate_io(gate_bpf::map_value(captured.operation.fd.as_fd(), &0));
    assert_eq!((operation.phase, operation.op_incarnation), (0, 0));
    let root: gate_bpf::NativeRoot = gate_io(gate_bpf::map_value(maps.root.as_fd(), &0));
    assert_eq!((root.epoch, root.reserved), (2, 0));
    gate_io(target.withdraw_recording_hooks());
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(fixture.ifindex)),
        programs.discover_id,
    ));
    assert_eq!(
        gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    gate_io(captured.loaded.seal());
    assert!(
        gate_io(captured.loaded.finish_close()),
        "idle captured hooks failed to join"
    );
    gate_singleton(&gate_io(fixture.inventory()), gate.program_id());
    assert!(gate_io(captured.pin_inventory()).is_empty());
    for identity in &identities {
        assert!(!gate_io(identity.resource.pin_path.try_exists()));
    }
    let terminal = captured.loaded.inventory();
    assert!(
        terminal
            .iter()
            .filter(|item| item.role == "realm-gate-prog"
                || item.role.starts_with("native-return-restorer-"))
            .all(
                |item| item.state == gate_bpf::CapturedResourceState::Unpinned
                    || (item.role.ends_with("link")
                        && item.state == gate_bpf::CapturedResourceState::Detached)
            )
    );
    assert!(gate_io(gate_bpf::xdp_absent(captured.loaded.tap_ifindex())));
    assert_eq!(
        gate_io(gate_bpf::query_tcx(
            captured.loaded.tap_ifindex(),
            gate_bpf::BPF_TCX_INGRESS
        ))
        .count,
        0
    );
    let status = gate_io(
        Command::new("nft")
            .args([
                "delete",
                "table",
                "netdev",
                &format!("honk_gate_return_{}", fixture.ifindex),
            ])
            .status(),
    );
    assert!(status.success(), "private TAP containment cleanup failed");
    let tap_path = PathBuf::from(format!("/sys/class/net/hgr{:x}", fixture.ifindex));
    let GateCaptured {
        root,
        operation,
        _tap: tap,
        pin_root,
        loaded,
        _cold,
    } = ManuallyDrop::into_inner(captured);
    drop(ManuallyDrop::into_inner(candidates));
    drop(loaded);
    drop(ManuallyDrop::into_inner(target));
    drop(ManuallyDrop::into_inner(gate));
    drop(ManuallyDrop::into_inner(attachment));
    drop(ManuallyDrop::into_inner(programs));
    drop(ManuallyDrop::into_inner(realm_dispatch));
    drop(ManuallyDrop::into_inner(pin_directory));
    drop(tap);
    assert!(
        !gate_io(tap_path.try_exists()),
        "real TAP owner was not released"
    );
    drop(ManuallyDrop::into_inner(maps));
    drop(operation);
    drop(root);
    drop(pin_root);
    // The retained cold charge is released only after every funded FD, map and owner.
    drop(ManuallyDrop::into_inner(_cold));
    drop(ManuallyDrop::into_inner(fixture));
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_reload_and_missing_gate_refusal() {
    require_vm();
    let fixture = gate_io(GateFixture::new());
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let expected = gate.program_id();
    let initial = gate_io(fixture.inventory());
    gate_singleton(&initial, expected);
    let target = Arc::new(gate_io(programs.native_target(
        &gate_io(fixture.capture()),
        &[],
        &attachment,
    )));
    let mut maps = gate_io(GateNative::new());
    let captured = gate_io(GateCaptured::new(
        &fixture.directory,
        Arc::clone(&target),
        &mut maps,
    ));
    let first = gate_io(maps.prepare_captured(&target, 2, &captured.config()));
    gate_io(first.publish(&target));
    gate_io(target.finish_publication());
    gate_io(attachment.replace(&programs));
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(fixture.ifindex)),
        first.program_id(),
    ));
    gate_captured_chain(
        &gate_io(fixture.inventory()),
        expected,
        &captured.loaded.inventory(),
    );
    assert_eq!(
        gate_io(gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)),
        first.tc_program_id()
    );
    gate_io(maps.epoch(4));
    let next = gate_io(maps.prepare_captured(&target, 4, &captured.config()));
    gate_io(next.publish(&target));
    gate_io(target.finish_publication());
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(fixture.ifindex)),
        next.program_id(),
    ));
    assert_ne!(
        first.program_id(),
        next.program_id(),
        "NOT_EXERCISED: reload did not select a new actual XDP program"
    );
    assert_ne!(
        first.tc_program_id(),
        next.tc_program_id(),
        "NOT_EXERCISED: reload did not replace the actual TC candidate"
    );
    assert_eq!(
        gate_io(gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)),
        next.tc_program_id()
    );
    gate_captured_chain(
        &gate_io(fixture.inventory()),
        expected,
        &captured.loaded.inventory(),
    );
    gate_io(attachment.guard(&programs));
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(fixture.ifindex)),
        programs.discover_id,
    ));
    gate_captured_chain(
        &gate_io(fixture.inventory()),
        expected,
        &captured.loaded.inventory(),
    );
    gate_io(maps.epoch(6));
    let rejected = gate_io(maps.prepare_captured(&target, 6, &captured.config()));
    let revision = gate_io(gate_bpf::query_tcx(
        fixture.ifindex,
        gate_bpf::BPF_TCX_INGRESS,
    ))
    .revision;
    gate_io(gate_detach(
        gate.program.as_fd(),
        fixture.ifindex,
        revision,
        expected,
    ));
    let before = gate_io(fixture.inventory());
    let slot: u32 = gate_io(gate_bpf::map_value(target.dispatch_fd(), &1));
    assert!(
        rejected.publish(&target).is_err(),
        "publication reopened after the registered gate was removed"
    );
    assert!(
        attachment.replace(&programs).is_err(),
        "activation reopened after the registered gate was removed"
    );
    assert_eq!(
        gate_io(fixture.inventory()),
        before,
        "missing-gate rejection changed XDP/pins/TCX"
    );
    assert_eq!(
        gate_io(gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)),
        slot,
        "missing-gate publication wrote TC slot one"
    );
    let root: gate_bpf::NativeRoot = gate_io(gate_bpf::map_value(maps.root.as_fd(), &0));
    assert_eq!(root.epoch, 6, "missing-gate publication reopened the root");
    gate_io(attachment.guard(&programs));
    panic!(
        "NOT_EXERCISED: real guard/data/reload/guard and missing-gate refusal observed; the two honk-core publication reader-grace calls are unavailable in honk-xsk"
    );
}

fn gate_recovery_setup(
    fixture: &GateFixture,
) -> (Programs, Arc<gate_bpf::NativeTcxAttachment>, GateCaptured) {
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let target = Arc::new(gate_io(programs.native_target(
        &gate_io(fixture.capture()),
        &[],
        &attachment,
    )));
    let mut maps = gate_io(GateNative::new());
    let captured = gate_io(GateCaptured::new(
        fixture.pins.parent().unwrap(),
        Arc::clone(&target),
        &mut maps,
    ));
    let data = gate_io(maps.prepare_captured(&target, 2, &captured.config()));
    gate_io(data.publish(&target));
    gate_io(target.finish_publication());
    gate_io(gate_command(&["link", "set", "dev", &fixture.peer, "down"]));
    gate_captured_chain(
        &gate_io(fixture.inventory()),
        gate.program_id(),
        &captured.loaded.inventory(),
    );
    (programs, gate, captured)
}

fn gate_probe(fixture: &GateFixture, args: &[&str]) -> io::Result<std::process::Output> {
    let probe = std::env::var_os("HONK_XDP_PROBE").ok_or_else(|| {
        io::Error::other("HONK_XDP_PROBE is required for the real recovery entrypoint")
    })?;
    Command::new("python3")
        .arg(probe)
        .args(args)
        .env("HONK_XDP_PIN_ROOT", &fixture.directory)
        .env(
            "HONK_XDP_NATIVE_STATE_DIR",
            fixture.artifacts.join("native-state"),
        )
        .output()
}

fn gate_recovery_save(root: &GateFixture, fixture: &GateFixture, guard: u32) {
    let output = gate_io(gate_probe(
        root,
        &[
            "native-gate",
            &fixture.device,
            &std::process::id().to_string(),
        ],
    ));
    assert!(
        output.status.success(),
        "NOT_EXERCISED: real recovery inventory failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.stdout.is_empty(),
        "NOT_EXERCISED: real recovery inventory was empty"
    );
    let prefix = root.artifacts.join("recovery");
    gate_io(std::fs::write(
        format!(
            "{}.{}.native-gate-program.json",
            prefix.display(),
            fixture.device
        ),
        output.stdout,
    ));
    gate_io(std::fs::write(
        format!("{}.{}.guard-id", prefix.display(), fixture.device),
        guard.to_string(),
    ));
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_stale_foreign_partial_recovery() {
    require_vm();
    {
        let fixture = gate_io(GateFixture::new());
        let (programs, attachment) = gate_io(fixture.bootstrap());
        let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
        gate_io(gate_command(&["link", "set", "dev", &fixture.peer, "down"]));
        gate_io(
            gate_bpf::set_xdp(fixture.ifindex, -1, Some(programs.discover.as_raw_fd()))
                .map_err(io::Error::from),
        );
        assert!(
            gate_io(gate_bpf::xdp_absent(fixture.ifindex)),
            "NOT_EXERCISED: stale-TCX fixture still has XDP"
        );
        let fresh = fixture.directory.join("fresh");
        gate_io(std::fs::create_dir(&fresh));
        gate_io(std::fs::set_permissions(
            &fresh,
            std::fs::Permissions::from_mode(0o700),
        ));
        gate_io(gate_bpf::private_bpffs(&fresh));
        assert_eq!(
            gate_io(std::fs::read_dir(&fresh)).count(),
            0,
            "NOT_EXERCISED: fresh pin directory is not empty"
        );
        let next = gate_io(Programs::load_general_native(
            &gate_io(fixture.capture()),
            1,
            &[],
        ));
        let before = gate_io(fixture.inventory());
        gate_singleton(&before, gate.program_id());
        let error = gate_bpf::PersistentAttachment::create(fixture.ifindex, &next, &fresh)
            .err()
            .expect("stale TCX admitted fresh-root XDP mutation");
        assert_eq!(
            error.to_string(),
            "foreign or stale Native TCX attachment",
            "NOT_EXERCISED: stale TCX was not the sole create rejection: {error}"
        );
        assert_eq!(
            gate_io(fixture.inventory()),
            before,
            "TCX preflight mutated XDP, attachments or original pins"
        );
        assert_eq!(
            gate_io(std::fs::read_dir(&fresh)).count(),
            0,
            "TCX preflight created fresh custody pins"
        );
        gate_io(gate_detach(
            gate.program.as_fd(),
            fixture.ifindex,
            before.revisions.0,
            gate.program_id(),
        ));
        let clean = gate_io(gate_bpf::PersistentAttachment::create(
            fixture.ifindex,
            &next,
            &fresh,
        ));
        gate_io(gate_bpf::require_native(
            gate_io(gate_bpf::xdp_state(fixture.ifindex)),
            next.discover_id,
        ));
        assert!(
            clean.native.is_some(),
            "NOT_EXERCISED: removing only stale TCX did not admit the same fresh-root create"
        );
    }
    for condition in [
        "prepared-only",
        "wrong-restorer-program",
        "wrong-restorer-link",
        "wrong-restorer-order",
        "extra-program",
        "missing-restorer-program",
        "missing-restorer-link",
        "loader-only-operation-map-receipt-refusal",
        "loader-only-dispatch-map-receipt-refusal",
        "legacy",
        "mixed",
        "foreign",
        "wrong-device",
        "ifindex-reuse",
        "partial",
    ] {
        let fixture = gate_io(GateFixture::new());
        let (programs, gate, captured) = gate_recovery_setup(&fixture);
        gate_recovery_save(&fixture, &fixture, programs.discover_id);
        let other = if matches!(
            condition,
            "wrong-device" | "partial" | "wrong-restorer-link"
        ) {
            Some(gate_io(fixture.alongside()))
        } else {
            None
        };
        let other_owner = other.as_ref().map(gate_recovery_setup);
        if let (Some(other), Some((programs, _, _))) = (&other, &other_owner) {
            gate_recovery_save(&fixture, other, programs.discover_id);
        }
        let mut legacy = None;
        let mut foreign = None;
        match condition {
            "loader-only-operation-map-receipt-refusal"
            | "loader-only-dispatch-map-receipt-refusal" => {
                let (role, replacement) =
                    if condition == "loader-only-operation-map-receipt-refusal" {
                        (
                            "operation-map",
                            host::CapturedFixtureMap::new(
                                size_of::<honk_ebpf_common::xdp::NativeCapturedOperation>(),
                                b"hg_foreign_op",
                            )
                            .and_then(|map| map.fd.try_clone()),
                        )
                    } else {
                        (
                            "realm-dispatch-map",
                            create_map(gate_bpf::BPF_MAP_TYPE_PROG_ARRAY, 4, 1, b"hg_foreign_rlms"),
                        )
                    };
                let replacement = gate_io(replacement);
                let directory = captured.pin_root.join(format!(
                    "native-return-{}",
                    captured.loaded.return_attachment()
                ));
                let root = gate_io(gate_bpf::private_bpffs(&directory));
                let name = CString::new(role).unwrap();
                gate_io(std::fs::remove_file(directory.join(role)));
                gate_io(gate_bpf::pin_program(
                    root.as_fd(),
                    &name,
                    replacement.as_fd(),
                ));
                foreign = Some(replacement);
            }
            "wrong-restorer-program" => {
                let (program, _) = gate_io(gate_program(
                    gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
                    b"hg_wrong_rstor",
                ));
                gate_io(std::fs::remove_file(
                    fixture.pins.join("native-return-restorer-prog"),
                ));
                gate_io(gate_bpf::pin_program(
                    gate.root.as_fd(),
                    c"native-return-restorer-prog",
                    program.as_fd(),
                ));
                foreign = Some(program);
            }
            "wrong-restorer-link" => {
                let other_gate = &other_owner.as_ref().unwrap().1;
                let link = gate_io(gate_open(
                    other_gate.root.as_fd(),
                    c"native-return-restorer-link",
                ));
                gate_io(std::fs::remove_file(
                    fixture.pins.join("native-return-restorer-link"),
                ));
                gate_io(gate_bpf::pin_program(
                    gate.root.as_fd(),
                    c"native-return-restorer-link",
                    link.as_fd(),
                ));
                foreign = Some(link);
            }
            "wrong-restorer-order" => {
                let program = gate_io(gate_open(gate.root.as_fd(), c"native-return-restorer-prog"));
                let old = gate_io(gate_open(gate.root.as_fd(), c"native-return-restorer-link"));
                #[repr(C)]
                struct LinkDetachAttr {
                    link_fd: u32,
                }
                const BPF_LINK_DETACH: u32 = 34;
                gate_io(gate_bpf::bpf(
                    BPF_LINK_DETACH,
                    &mut LinkDetachAttr {
                        link_fd: old.as_raw_fd() as u32,
                    },
                ));
                let id = gate_io(fixture.inventory())
                    .pins
                    .iter()
                    .find(|pin| pin.0 == "native-return-restorer-prog")
                    .unwrap()
                    .2;
                let link = gate_io(gate_legacy_link(fixture.ifindex, program.as_fd(), id));
                gate_io(std::fs::remove_file(
                    fixture.pins.join("native-return-restorer-link"),
                ));
                gate_io(gate_bpf::pin_program(
                    gate.root.as_fd(),
                    c"native-return-restorer-link",
                    link.as_fd(),
                ));
                assert_eq!(
                    gate_io(fixture.inventory()).ingress[0],
                    (gate.program_id(), 0),
                    "NOT_EXERCISED: restorer did not move after the gate"
                );
                legacy = Some((program, link));
            }
            "extra-program" => {
                let (program, _) =
                    gate_io(gate_program(gate_bpf::BPF_PROG_TYPE_SCHED_CLS, b"hg_extra"));
                let revision = gate_io(fixture.inventory()).revisions.0;
                gate_io(gate_mutate(
                    gate_bpf::BPF_PROG_ATTACH,
                    program.as_fd(),
                    fixture.ifindex,
                    revision,
                ));
                assert_eq!(gate_io(fixture.inventory()).ingress.len(), 3);
                foreign = Some(program);
            }
            "missing-restorer-program" | "missing-restorer-link" => {
                let role = if condition == "missing-restorer-program" {
                    "native-return-restorer-prog"
                } else {
                    "native-return-restorer-link"
                };
                gate_io(std::fs::remove_file(fixture.pins.join(role)));
            }
            "prepared-only" => {
                let revision = gate_io(fixture.inventory()).revisions.0;
                gate_io(gate_detach(
                    gate.program.as_fd(),
                    fixture.ifindex,
                    revision,
                    gate.program_id(),
                ));
            }
            "legacy" | "mixed" => {
                let (program, id) = gate_io(gate_program(
                    gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
                    b"hg_old_format",
                ));
                let link = gate_io(gate_legacy_link(fixture.ifindex, program.as_fd(), id));
                gate_io(gate_bpf::pin_program(
                    gate.root.as_fd(),
                    c"native-gate-link",
                    link.as_fd(),
                ));
                if condition == "legacy" {
                    let revision = gate_io(fixture.inventory()).revisions.0;
                    gate_io(gate_detach(
                        gate.program.as_fd(),
                        fixture.ifindex,
                        revision,
                        gate.program_id(),
                    ));
                    gate_io(std::fs::remove_file(gate.pin_path()));
                }
                legacy = Some((program, link));
            }
            "foreign" => {
                let body = gate_io(gate_bpf::native::dispatch(
                    &gate_io(fixture.capture()),
                    &[],
                    programs.native_dispatch_fd().unwrap().as_raw_fd(),
                ));
                let (program, _) = gate_io(gate_bpf::load_typed_program(
                    &body,
                    b"honk_nat_gate",
                    &mut vec![0; 1 << 20],
                    gate_bpf::BPF_PROG_TYPE_SCHED_CLS,
                    gate_bpf::BPF_TCX_INGRESS,
                ));
                gate_io(std::fs::remove_file(gate.pin_path()));
                gate_io(gate_bpf::pin_program(
                    gate.root.as_fd(),
                    c"native-gate-prog",
                    program.as_fd(),
                ));
                foreign = Some(program);
            }
            "wrong-device" => {
                let other_gate = &other_owner.as_ref().unwrap().1;
                assert_ne!(
                    other_gate.ifindex(),
                    fixture.ifindex,
                    "NOT_EXERCISED: wrong-device control reused the same device"
                );
                gate_io(std::fs::remove_file(gate.pin_path()));
                gate_io(gate_bpf::pin_program(
                    gate.root.as_fd(),
                    c"native-gate-prog",
                    other_gate.program.as_fd(),
                ));
            }
            "ifindex-reuse" => {
                let old_device = gate_io(fixture.inventory()).device;
                gate_io(gate_command(&["link", "del", "dev", &fixture.device]));
                gate_io(gate_command(&[
                    "link",
                    "add",
                    "name",
                    &fixture.device,
                    "index",
                    &fixture.ifindex.to_string(),
                    "type",
                    "veth",
                    "peer",
                    "name",
                    &fixture.peer,
                ]));
                assert_eq!(
                    gate_io(gate_index(&fixture.device)),
                    fixture.ifindex,
                    "NOT_EXERCISED: ifindex reuse was not reached"
                );
                gate_io(gate_command(&[
                    "link",
                    "set",
                    "dev",
                    &fixture.device,
                    "address",
                    "02:00:00:00:00:01",
                    "up",
                ]));
                let restorer =
                    gate_io(gate_open(gate.root.as_fd(), c"native-return-restorer-prog"));
                let restorer_id = captured
                    .loaded
                    .inventory()
                    .iter()
                    .find(|item| {
                        item.role == "native-return-restorer-prog"
                            && item.ifindex == fixture.ifindex
                    })
                    .unwrap()
                    .id;
                let restorer_link = gate_io(gate_legacy_link(
                    fixture.ifindex,
                    restorer.as_fd(),
                    restorer_id,
                ));
                gate_io(std::fs::remove_file(
                    fixture.pins.join("native-return-restorer-link"),
                ));
                gate_io(gate_bpf::pin_program(
                    gate.root.as_fd(),
                    c"native-return-restorer-link",
                    restorer_link.as_fd(),
                ));
                let mut link_info = [0u32; 6];
                gate_io(gate_bpf::object_info(restorer_link.as_fd(), &mut link_info));
                legacy = Some((restorer, restorer_link));
                let revision = gate_io(gate_bpf::query_tcx(
                    fixture.ifindex,
                    gate_bpf::BPF_TCX_INGRESS,
                ))
                .revision;
                gate_io(gate_mutate(
                    gate_bpf::BPF_PROG_ATTACH,
                    gate.program.as_fd(),
                    fixture.ifindex,
                    revision,
                ));
                gate_io(
                    gate_bpf::set_xdp(fixture.ifindex, programs.discover.as_raw_fd(), None)
                        .map_err(io::Error::from),
                );
                let current = gate_io(fixture.inventory());
                gate_captured_ids(&current, gate.program_id(), restorer_id, link_info[1]);
                assert_ne!(
                    current.device, old_device,
                    "NOT_EXERCISED: replacement netdev identity did not change"
                );
            }
            "partial" => {
                let other = other.as_ref().unwrap();
                let other_gate = &other_owner.as_ref().unwrap().1;
                let revision = gate_io(other.inventory()).revisions.0;
                gate_io(gate_detach(
                    other_gate.program.as_fd(),
                    other.ifindex,
                    revision,
                    other_gate.program_id(),
                ));
            }
            _ => unreachable!(),
        }
        let invalid_owner = if condition == "partial" {
            &other_owner.as_ref().unwrap().2
        } else {
            &captured
        };
        assert!(
            invalid_owner.loaded.check().is_err(),
            "A loader accepted invalid {condition} inventory"
        );
        let private_before = gate_io(captured.pin_inventory());
        let other_private_before = other_owner
            .as_ref()
            .map(|(_, _, captured)| gate_io(captured.pin_inventory()));
        let before = gate_io(fixture.inventory());
        let other_before = other.as_ref().map(|other| gate_io(other.inventory()));
        let prefix = fixture.artifacts.join("recovery");
        let prefix = prefix
            .to_str()
            .expect("NOT_EXERCISED: recovery artifact path is not UTF8");
        let mut args = vec!["native-cleanup", prefix, fixture.device.as_str()];
        if condition == "partial" {
            args.push(other.as_ref().unwrap().device.as_str());
        }
        let output = gate_io(gate_probe(&fixture, &args));
        assert!(
            !output.status.success(),
            "invalid {condition} recovery reported success"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason = match condition {
            "legacy" | "mixed" => "legacy or mixed Native pin format",
            "prepared-only"
            | "partial"
            | "foreign"
            | "wrong-device"
            | "wrong-restorer-order"
            | "extra-program" => "extra, missing, reordered or wrong Native TCX attachment",
            "wrong-restorer-program" | "wrong-restorer-link" => "foreign restorer link",
            "missing-restorer-program" | "missing-restorer-link" => {
                "prepared-only, unknown or staging Native pins"
            }
            // Without a C joined receipt, Python proves refusal only; A checks pin identity above.
            "loader-only-operation-map-receipt-refusal"
            | "loader-only-dispatch-map-receipt-refusal" => {
                "missing, foreign or ambiguous joined captured-return receipt"
            }
            "ifindex-reuse" => "Native gate or namespace/device/capture changed",
            _ => unreachable!(),
        };
        assert!(
            stderr.contains(reason),
            "NOT_EXERCISED: {condition} recovery missed its intended rejection: {stderr}"
        );
        assert_eq!(
            gate_io(fixture.inventory()),
            before,
            "failed {condition} recovery removed custody after child exit"
        );
        assert_eq!(
            gate_io(captured.pin_inventory()),
            private_before,
            "failed {condition} recovery changed private operation/program custody pins"
        );
        if let (Some((_, _, captured)), Some(before)) = (&other_owner, other_private_before) {
            assert_eq!(
                gate_io(captured.pin_inventory()),
                before,
                "failed multi-device recovery changed other private pins"
            );
        }
        if let (Some(other), Some(before)) = (&other, other_before) {
            assert_eq!(
                gate_io(other.inventory()),
                before,
                "failed multi-device recovery changed the other inventory"
            );
        }
        drop(foreign);
        drop(legacy);
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_creator_death_custody_survives() {
    require_vm();
    if std::env::var_os("HONK_GATE_CHILD_MODE").is_some() {
        gate_creator_child();
    }
    let fixture = gate_io(GateFixture::new());
    let sender = gate_io(gate_packet_socket(fixture.peer_ifindex));
    let tap = gate_io(gate_packet_socket(fixture.ifindex));
    let mut child = GateChild::spawn(
        &fixture,
        "kernel_native_gate_creator_death_custody_survives",
        "ready",
    );
    assert_eq!(
        child.stop(false),
        libc::SIGSTOP,
        "NOT_EXERCISED: creator did not reach real readiness"
    );
    assert_eq!(
        child.ready.len(),
        11,
        "NOT_EXERCISED: incomplete readiness inventory"
    );
    let before = gate_io(fixture.inventory());
    let expected = child.ready[4] as u32;
    gate_captured_ids(
        &before,
        expected,
        child.ready[9] as u32,
        child.ready[10] as u32,
    );
    gate_io(gate_bpf::require_native(before.xdp, child.ready[2] as u32));
    gate_tap_control(sender.as_fd(), tap.as_fd(), b"V7A-tap-positive");
    gate_io(gate_send(
        sender.as_fd(),
        &gate_frame(false, 41071, b"V7A-ready-selected"),
    ));
    assert!(
        gate_io(gate_tap(
            tap.as_fd(),
            b"V7A-ready-selected",
            Duration::from_secs(1)
        )),
        "NOT_EXERCISED: readiness data program never admitted actual Selected traffic"
    );
    child.kill_and_reap();
    let after = gate_io(fixture.inventory());
    gate_captured_ids(
        &after,
        expected,
        child.ready[9] as u32,
        child.ready[10] as u32,
    );
    assert_eq!(
        after, before,
        "readiness creator death changed frozen gate, netns/device/pins or DRV XDP identity"
    );
    let xsks = gate_io(gate_map_by_id(child.ready[6] as u32));
    let dispatch = gate_io(gate_map_by_id(child.ready[5] as u32));
    let socket = gate_xsk_present(xsks.as_fd());
    let slot = gate_candidate_slot(dispatch.as_fd());
    eprintln!(
        "V7-A after reap: live XSK={socket}, TC slot one={slot:?}; creator death is not a reader/DMA join"
    );
    gate_tap_control(sender.as_fd(), tap.as_fd(), b"V7A-after-tap-positive");
    gate_io(gate_send(
        sender.as_fd(),
        &gate_frame(false, 41074, b"V7A-new-flow-after-reap"),
    ));
    let appeared = gate_io(gate_tap(
        tap.as_fd(),
        b"V7A-new-flow-after-reap",
        Duration::from_millis(100),
    ));
    eprintln!(
        "V7-A compatibility: unique new-flow frame at ingress tap={appeared}; no in-flight userspace operation was started"
    );
    panic!(
        "NOT_EXERCISED: honk-xsk readiness custody and kill-after new-flow tap observations completed; actual daemon/readiness lifecycle and in-flight userspace operation boundaries require the core lifecycle fixture"
    );
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_normal_stop_final_owner_drop() {
    require_vm();
    let fixture = gate_io(GateFixture::new());
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let expected = gate.program_id();
    let weak = Arc::downgrade(&gate);
    let target = Arc::new(gate_io(programs.native_target(
        &gate_io(fixture.capture()),
        &[],
        &attachment,
    )));
    let mut maps = gate_io(GateNative::new());
    let captured = gate_io(GateCaptured::new(
        &fixture.directory,
        Arc::clone(&target),
        &mut maps,
    ));
    let budget = honk_netstack::MemoryBudget::new(4 << 20);
    let mut port = gate_io(crate::Port::<u32>::open_device(
        fixture.ifindex,
        0,
        crate::BindMode::Copy,
        crate::PortConfig {
            rx_frames: 16,
            control_frames: 2,
            bulk_frames: 2,
            ring_size: 16,
        },
        1500,
        false,
        honk_ebpf_common::xdp::NATIVE_METADATA_LEN,
        &budget,
    ));
    gate_io(port.refill());
    let socket = port.as_raw_fd() as u32;
    gate_io(gate_bpf::bpf(
        gate_bpf::BPF_MAP_UPDATE_ELEM,
        &mut gate_bpf::map_attr(programs.xsks.as_fd(), &0, &socket as *const _ as u64),
    ));
    assert!(
        gate_xsk_present(programs.xsks.as_fd()),
        "NOT_EXERCISED: normal-stop XSK positive control"
    );
    let data = gate_io(maps.prepare_captured(&target, 2, &captured.config()));
    gate_io(data.publish(&target));
    gate_io(target.finish_publication());
    gate_io(attachment.replace(&programs));
    gate_io(maps.epoch(4));
    let closed: gate_bpf::NativeRoot = gate_io(gate_bpf::map_value(maps.root.as_fd(), &0));
    assert_eq!(
        closed.epoch, 4,
        "NOT_EXERCISED: owner stop failed to close root first"
    );
    gate_io(target.withdraw_recording_hooks());
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(fixture.ifindex)),
        programs.discover_id,
    ));
    let missing = gate_bpf::map_value::<u32>(target.dispatch_fd(), &1).unwrap_err();
    assert_eq!(
        missing.raw_os_error(),
        Some(libc::ENOENT),
        "NOT_EXERCISED: owner stop left TC slot one published"
    );
    gate_io(gate_bpf::bpf(
        gate_bpf::BPF_MAP_DELETE_ELEM,
        &mut gate_bpf::map_attr(programs.xsks.as_fd(), &0, 0),
    ));
    port.close_socket();
    assert!(
        !gate_xsk_present(programs.xsks.as_fd()),
        "normal-stop XSK removal did not complete"
    );
    let installed = captured.loaded.inventory();
    gate_captured_chain(&gate_io(fixture.inventory()), expected, &installed);
    let operation: honk_ebpf_common::xdp::NativeCapturedOperation =
        gate_io(gate_bpf::map_value(captured.operation.fd.as_fd(), &0));
    assert_eq!(
        (operation.phase, operation.op_incarnation),
        (honk_ebpf_common::xdp::NATIVE_OP_IDLE, 0)
    );
    gate_io(captured.loaded.seal());
    assert!(
        gate_io(captured.loaded.finish_close()),
        "idle raw captured loader did not join"
    );
    let terminal = captured.loaded.inventory();
    for (role, states) in [
        (
            "native-return-restorer-link",
            &[
                gate_bpf::CapturedResourceState::Detached,
                gate_bpf::CapturedResourceState::Unpinned,
            ][..],
        ),
        (
            "native-return-restorer-prog",
            &[gate_bpf::CapturedResourceState::Unpinned][..],
        ),
    ] {
        let prior = installed
            .iter()
            .find(|item| item.ifindex == fixture.ifindex && item.role == role)
            .unwrap();
        let observed: Vec<_> = terminal
            .iter()
            .filter(|item| item.ifindex == fixture.ifindex && item.role == role)
            .map(|item| {
                assert_eq!(
                    (&item.pin_path, item.kind, item.id, item.ifindex),
                    (&prior.pin_path, prior.kind, prior.id, prior.ifindex),
                    "terminal {role} identity changed"
                );
                item.state
            })
            .collect();
        assert_eq!(observed, states, "wrong terminal {role} custody history");
        assert!(
            !gate_io(fixture.pins.join(role).try_exists()),
            "terminal {role} pin remained"
        );
    }
    let before = gate_io(fixture.inventory());
    gate_singleton(&before, expected);
    eprintln!(
        "V7-B checkpoint=before-normal-owner-release; core Runtime::drop is not available in this crate"
    );
    drop(gate);
    drop(data);
    drop(captured);
    drop(target);
    drop(attachment);
    drop(programs);
    assert!(
        weak.upgrade().is_none(),
        "NOT_EXERCISED: final native gate Arc owner was not normally destroyed"
    );
    eprintln!("V7-B checkpoint=final-gate-Arc-destroyed");
    let after = gate_io(fixture.inventory());
    gate_singleton(&after, expected);
    assert_eq!(
        after, before,
        "final normal gate Arc destruction detached TCX, XDP or removed custody pins"
    );
    eprintln!("V7-B checkpoint=independent-kernel-readback");
    panic!(
        "NOT_EXERCISED: ordered root close/guard/XSK withdrawal, final honk-xsk gate Arc destruction and attachment survival observed; actual honk-core joined stop and Runtime::drop checkpoint require the core lifecycle fixture"
    );
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_live_xsk_frontier_pre_tap() {
    require_vm();
    if std::env::var_os("HONK_GATE_CHILD_MODE").is_some() {
        gate_creator_child();
    }
    let fixture = gate_io(GateFixture::new());
    let sender = gate_io(gate_packet_socket(fixture.peer_ifindex));
    let tap = gate_io(gate_packet_socket(fixture.ifindex));
    let mut child = GateChild::spawn(
        &fixture,
        "kernel_native_gate_live_xsk_frontier_pre_tap",
        "ready",
    );
    assert_eq!(
        child.stop(false),
        libc::SIGSTOP,
        "NOT_EXERCISED: live-XSK creator readiness was not reached"
    );
    assert_eq!(
        child.ready.len(),
        11,
        "NOT_EXERCISED: incomplete live-XSK readiness identity"
    );
    let before = gate_io(fixture.inventory());
    gate_captured_ids(
        &before,
        child.ready[4] as u32,
        child.ready[9] as u32,
        child.ready[10] as u32,
    );
    gate_io(gate_bpf::require_native(before.xdp, child.ready[2] as u32));
    gate_tap_control(sender.as_fd(), tap.as_fd(), b"V7C-before-tap-positive");
    gate_io(gate_send(
        sender.as_fd(),
        &gate_frame(false, 41072, b"V7C-before-live-selected"),
    ));
    assert!(
        gate_io(gate_tap(
            tap.as_fd(),
            b"V7C-before-live-selected",
            Duration::from_secs(1)
        )),
        "NOT_EXERCISED: live owner never admitted an actual Selected frame"
    );
    child.kill_and_reap();
    assert_eq!(
        gate_io(fixture.inventory()),
        before,
        "live-XSK creator death changed the frozen XDP/device/gate identity"
    );
    let dispatch = gate_io(gate_map_by_id(child.ready[5] as u32));
    let root = gate_io(gate_map_by_id(child.ready[7] as u32));
    let epoch: gate_bpf::NativeRoot = gate_io(gate_bpf::map_value(root.as_fd(), &0));
    let slot = gate_candidate_slot(dispatch.as_fd());
    let xsks = gate_io(gate_map_by_id(child.ready[6] as u32));
    let live = gate_xsk_present(xsks.as_fd());
    eprintln!(
        "V7-C after reap: root={epoch:?}, live XSK={live}, TC slot one={slot:?}, before slot one={}",
        child.ready[8]
    );
    gate_tap_control(sender.as_fd(), tap.as_fd(), b"V7C-after-tap-positive");
    let counters = gate_io(gate_map_by_id(child.ready[3] as u32));
    let count: u64 = gate_io(gate_bpf::map_value(counters.as_fd(), &0));
    gate_io(gate_send(
        sender.as_fd(),
        &gate_frame(false, 41073, b"V7C-new-selected-after-kill"),
    ));
    let appeared = gate_io(gate_tap(
        tap.as_fd(),
        b"V7C-new-selected-after-kill",
        Duration::from_millis(250),
    ));
    let next: u64 = gate_io(gate_bpf::map_value(counters.as_fd(), &0));
    assert_eq!(
        next,
        count + 1,
        "NOT_EXERCISED: kill-after new frame did not reach the outer Selected branch"
    );
    eprintln!("V7-C compatibility: unique new Selected frame at ingress tap={appeared}");
    assert!(
        !appeared,
        "NOT_EXERCISED: post-kill new Selected frame reached ingress tap; live-XSK pre-tap refusal was not observed"
    );
    panic!(
        "NOT_EXERCISED: pre-tap compatibility observed; no per-frame live-XSK/frontier branch witness or initial-check-to-final-recheck revocation rendezvous excludes other XDP refusal conditions"
    );
}

fn gate_udp_claim(
    map: BorrowedFd<'_>,
    key: &honk_ebpf_common::xdp::NativeKey,
) -> io::Result<honk_ebpf_common::xdp::NativeClaim> {
    let mut value = honk_ebpf_common::xdp::NativeClaim::default();
    gate_bpf::bpf(
        gate_bpf::BPF_MAP_LOOKUP_ELEM,
        &mut gate_bpf::MapElemAttr {
            map_fd: map.as_raw_fd() as u32,
            reserved: 0,
            key: key as *const _ as u64,
            value: &mut value as *mut _ as u64,
            flags: 0,
        },
    )?;
    Ok(value)
}

fn gate_udp_activity(
    map: BorrowedFd<'_>,
    key: &honk_ebpf_common::xdp::NativeKey,
    value: &honk_ebpf_common::xdp::NativeClaim,
) {
    gate_io(gate_bpf::bpf(
        gate_bpf::BPF_MAP_UPDATE_ELEM,
        &mut gate_bpf::MapElemAttr {
            map_fd: map.as_raw_fd() as u32,
            reserved: 0,
            key: key as *const _ as u64,
            value: value as *const _ as u64,
            flags: 2,
        },
    ));
}

fn gate_monotonic_ns() -> u64 {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) },
        0
    );
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_ipv6_extensions_execute_xdp_and_tcx_wrappers() {
    use honk_ebpf_common::xdp::{NATIVE_EXECUTOR_KERNEL, NativeKey};

    require_vm();
    let fixture = gate_io(GateFixture::new());
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let _gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let target = Arc::new(gate_io(programs.native_target(
        &gate_io(fixture.capture()),
        &[],
        &attachment,
    )));
    let mut maps = gate_io(GateNative::new());
    let captured = gate_io(GateCaptured::new(
        &fixture.directory,
        Arc::clone(&target),
        &mut maps,
    ));
    let budget = honk_netstack::MemoryBudget::new(4 << 20);
    let mut port = gate_io(crate::Port::<u32>::open_device(
        fixture.ifindex,
        0,
        crate::BindMode::Copy,
        crate::PortConfig {
            rx_frames: 16,
            control_frames: 2,
            bulk_frames: 2,
            ring_size: 16,
        },
        1500,
        false,
        honk_ebpf_common::xdp::NATIVE_METADATA_LEN,
        &budget,
    ));
    gate_io(port.refill());
    gate_io(programs.insert_xsk(0, port.as_fd()));
    assert!(gate_xsk_present(target.xsks_fd()));
    let candidate = gate_io(maps.prepare_captured(&target, 2, &captured.config()));
    gate_io(candidate.publish(&target));
    gate_io(target.finish_publication());
    gate_io(maps.epoch(3));
    let claim_keys = || {
        let mut keys = Vec::new();
        let mut previous = [0u8; 56];
        loop {
            let mut next = [0u8; 56];
            let result = gate_bpf::bpf(
                4,
                &mut gate_bpf::MapElemAttr {
                    map_fd: maps.claims.as_raw_fd() as u32,
                    reserved: 0,
                    key: if keys.is_empty() {
                        0
                    } else {
                        previous.as_ptr() as u64
                    },
                    value: next.as_mut_ptr() as u64,
                    flags: 0,
                },
            );
            match result {
                Ok(_) => {
                    keys.push(next);
                    previous = next;
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => break,
                Err(error) => panic!("NOT_EXERCISED: native claim enumeration: {error}"),
            }
        }
        keys.sort_unstable();
        keys
    };

    // Execute each complete emitted wrapper independently; the XDP-to-TCX chain must not
    // hide a TCX parser refusal behind a successful XDP claim lookup.
    for (tc, program) in [
        (false, &candidate.xdp_program),
        (true, &candidate.tc_program),
    ] {
        let execute = |frame: &[u8]| {
            let mut context = vec![0u32; if tc { 48 } else { 6 }];
            context[if tc { 9 } else { 3 }] = fixture.ifindex;
            if !tc {
                context[1] = frame.len() as u32;
            }
            let mut result = vec![0u32; context.len()];
            let mut output = vec![0u8; frame.len() + 256];
            let mut request = TestRun {
                program: program.as_raw_fd() as u32,
                input_len: frame.len() as u32,
                output_len: output.len() as u32,
                input: frame.as_ptr() as u64,
                output: output.as_mut_ptr() as u64,
                repeat: 1,
                context_len: (context.len() * size_of::<u32>()) as u32,
                result_len: (result.len() * size_of::<u32>()) as u32,
                context: context.as_ptr() as u64,
                result: result.as_mut_ptr() as u64,
                ..TestRun::default()
            };
            gate_io(gate_bpf::bpf(10, &mut request));
            assert_eq!(&output[..request.output_len as usize], frame);
            request.action
        };
        let extended = |source_port, headers: usize| {
            let plain = gate_frame(true, source_port, b"native-hbh-wrapper");
            let mut frame = plain[..54].to_vec();
            frame[20] = 0;
            for index in 0..headers {
                frame.extend_from_slice(&[
                    if index + 1 == headers { 17 } else { 0 },
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]);
            }
            frame.extend_from_slice(&plain[54..]);
            let length = (frame.len() - 54) as u16;
            frame[18..20].copy_from_slice(&length.to_be_bytes());
            frame
        };
        let source_port = if tc { 41231 } else { 41230 };
        let frame = extended(source_port, 1);
        let key = NativeKey {
            src_ip: std::array::from_fn(|i| {
                u32::from_ne_bytes(frame[22 + 4 * i..26 + 4 * i].try_into().unwrap())
            }),
            dst_ip: std::array::from_fn(|i| {
                u32::from_ne_bytes(frame[38 + 4 * i..42 + 4 * i].try_into().unwrap())
            }),
            src_port: source_port.to_be(),
            dst_port: 42000u16.to_be(),
            l4proto: 17,
            ip_version: 6,
            domain: 0,
            direction: 0,
            namespace_cookie: target.capture().authority.namespace_cookie,
            zone: 0,
            zone_state: 2,
            reserved: [0; 5],
        };
        let mut malformed = vec![extended(source_port, 9)];
        let mut extent = frame.clone();
        extent[55] = 255;
        malformed.push(extent);
        let mut length = frame.clone();
        length[66..68].copy_from_slice(&8u16.to_be_bytes());
        malformed.push(length);
        let mut routing = frame.clone();
        routing[20] = 43;
        routing[57] = 1;
        malformed.push(routing);
        for protocol in [44, 50, 51, 59, 253] {
            let mut unsupported = frame.clone();
            unsupported[54] = protocol;
            malformed.push(unsupported);
        }
        let claims_before = claim_keys();
        for bad in &malformed {
            assert_eq!(execute(bad), if tc { 2 } else { XDP_DROP as u32 });
            assert_eq!(
                claim_keys(),
                claims_before,
                "malformed frame allocated a claim"
            );
            assert_eq!(
                gate_udp_claim(maps.claims.as_fd(), &key)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ENOENT)
            );
        }
        assert_eq!(execute(&frame), if tc { 0 } else { XDP_PASS as u32 });
        let claim = gate_io(gate_udp_claim(maps.claims.as_fd(), &key));
        assert_eq!(
            (claim.epoch, claim.incarnation, claim.scope, claim.executor),
            (
                3,
                3,
                target.capture().authority.scope,
                NATIVE_EXECUTOR_KERNEL
            )
        );
        assert_eq!(
            execute(&extended(source_port, 8)),
            if tc { 0 } else { XDP_PASS as u32 }
        );
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_udp_claim_activity_reload_expiry_and_readonly_query() {
    use honk_ebpf_common::xdp::{
        NATIVE_CLAIM_UPDATE_INTERVAL_NS, NATIVE_CLAIM_VALUE_BYTES, NATIVE_EXECUTOR_KERNEL,
        NativeClaim, NativeKey,
    };

    require_vm();
    let timeout = honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS;
    assert_eq!(size_of::<NativeClaim>(), NATIVE_CLAIM_VALUE_BYTES);
    assert_eq!(NATIVE_CLAIM_VALUE_BYTES, 72);
    for ipv6 in [false, true] {
        let fixture = gate_io(GateFixture::new());
        let (programs, attachment) = gate_io(fixture.bootstrap());
        let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
        let target = Arc::new(gate_io(programs.native_target(
            &gate_io(fixture.capture()),
            &[],
            &attachment,
        )));
        let mut maps = gate_io(GateNative::new());
        let captured = gate_io(GateCaptured::new(
            &fixture.directory,
            Arc::clone(&target),
            &mut maps,
        ));
        let budget = honk_netstack::MemoryBudget::new(4 << 20);
        let mut port = gate_io(crate::Port::<u32>::open_device(
            fixture.ifindex,
            0,
            crate::BindMode::Copy,
            crate::PortConfig {
                rx_frames: 16,
                control_frames: 2,
                bulk_frames: 2,
                ring_size: 16,
            },
            1500,
            false,
            honk_ebpf_common::xdp::NATIVE_METADATA_LEN,
            &budget,
        ));
        gate_io(port.refill());
        gate_io(programs.insert_xsk(0, port.as_fd()));
        assert!(gate_xsk_present(target.xsks_fd()));
        let first = gate_io(maps.prepare_captured(&target, 2, &captured.config()));
        eprintln!(
            "Native UDP actual verifier load: ipv6={ipv6} XDP={} TCX={}",
            first.program_id(),
            first.tc_program_id()
        );
        gate_io(first.publish(&target));
        gate_io(target.finish_publication());
        gate_io(attachment.replace(&programs));
        gate_io(maps.epoch(3));
        let sender = gate_io(gate_packet_socket(fixture.peer_ifindex));
        let tap = gate_io(gate_packet_socket(fixture.ifindex));
        gate_tap_control(sender.as_fd(), tap.as_fd(), b"udp-cache-tap-control");
        let receiver = gate_io(UdpSocket::bind(if ipv6 {
            "[2001:db8:feed::2]:42000"
        } else {
            "198.18.0.2:42000"
        }));
        gate_io(receiver.set_read_timeout(Some(Duration::from_millis(250))));
        let source: SocketAddr = if ipv6 {
            "[2001:db8:feed::1]:41120"
        } else {
            "198.18.0.1:41120"
        }
        .parse()
        .unwrap();
        let words = |ip: IpAddr| {
            let octets = match ip {
                IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
                IpAddr::V6(ip) => ip.octets(),
            };
            std::array::from_fn(|i| {
                u32::from_ne_bytes(octets[i * 4..i * 4 + 4].try_into().unwrap())
            })
        };
        let key = NativeKey {
            src_ip: words(source.ip()),
            dst_ip: words(gate_io(receiver.local_addr()).ip()),
            src_port: source.port().to_be(),
            dst_port: 42000u16.to_be(),
            l4proto: 17,
            ip_version: if ipv6 { 6 } else { 4 },
            domain: 0,
            direction: 0,
            namespace_cookie: target.capture().authority.namespace_cookie,
            zone: 0,
            zone_state: 2,
            reserved: [0; 5],
        };
        let deliver = |marker: &[u8]| {
            let frame = gate_frame(ipv6, source.port(), marker);
            gate_io(gate_send(sender.as_fd(), &frame));
            assert_eq!(
                gate_io(gate_tap_frame(tap.as_fd(), marker, Duration::from_secs(1))),
                Some(frame),
                "actual veth ingress changed frame bytes, including source and TTL/hop limit"
            );
            let mut bytes = [0u8; 128];
            let (length, peer) = gate_io(receiver.recv_from(&mut bytes));
            assert_eq!((&bytes[..length], peer), (marker, source));
        };
        let refuse = |marker: &[u8]| {
            gate_io(gate_send(
                sender.as_fd(),
                &gate_frame(ipv6, source.port(), marker),
            ));
            let error = receiver
                .recv_from(&mut [0u8; 128])
                .expect_err("refused UDP reached IP");
            assert!(matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ));
        };
        let before = gate_monotonic_ns();
        deliver(b"udp-cache-created");
        let original = gate_io(gate_udp_claim(maps.claims.as_fd(), &key));
        assert_eq!(
            (original.epoch, original.incarnation, original.scope),
            (3, 3, target.capture().authority.scope)
        );
        assert_eq!(
            (original.executor, original.state),
            (
                NATIVE_EXECUTOR_KERNEL,
                honk_ebpf_common::xdp::NATIVE_PHASE_ACTIVE
            )
        );
        assert!((before..=gate_monotonic_ns()).contains(&original.last_seen_ns));

        let interval_ns = 2 * NATIVE_CLAIM_UPDATE_INTERVAL_NS;
        let mut last_seen_ns = original.last_seen_ns;
        for sequence in 0..=timeout / interval_ns {
            std::thread::sleep(Duration::from_nanos(interval_ns));
            let before = gate_monotonic_ns();
            deliver(format!("udp-cache-active-{sequence}").as_bytes());
            let active = gate_io(gate_udp_claim(maps.claims.as_fd(), &key));
            assert_eq!(
                active,
                NativeClaim {
                    last_seen_ns: active.last_seen_ns,
                    ..original
                }
            );
            assert!(active.last_seen_ns > last_seen_ns);
            assert!((before..=gate_monotonic_ns()).contains(&active.last_seen_ns));
            last_seen_ns = active.last_seen_ns;
        }
        assert!(last_seen_ns - original.last_seen_ns > timeout);

        // Query is the production marked BPF_PROG_TEST_RUN branch, not wire evidence.
        gate_io(maps.epoch_flags(4, 0));
        let stale = NativeClaim {
            last_seen_ns: gate_monotonic_ns() - 2 * NATIVE_CLAIM_UPDATE_INTERVAL_NS,
            ..original
        };
        gate_udp_activity(maps.claims.as_fd(), &key, &stale);
        let owned = gate_io(target.kernel_owned(&key));
        assert_eq!(gate_io(target.kernel_owned(&key)), owned);
        assert_eq!(gate_io(gate_udp_claim(maps.claims.as_fd(), &key)), stale);
        let absent = NativeKey {
            src_port: 41121u16.to_be(),
            ..key
        };
        assert!(!gate_io(target.kernel_owned(&absent)));
        assert_eq!(
            gate_udp_claim(maps.claims.as_fd(), &absent)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );

        for (epoch, outbound, marker) in [
            (4, 1, b"udp-cache-block".as_slice()),
            (6, 2, b"udp-cache-proxy".as_slice()),
        ] {
            gate_io(maps.epoch_flags(epoch, 0));
            maps.policy[0].imm = outbound;
            let next = gate_io(maps.prepare_captured(&target, epoch, &captured.config()));
            gate_io(next.publish(&target));
            gate_io(target.finish_publication());
            gate_io(maps.epoch_flags(epoch + 1, 0));
            gate_captured_chain(
                &gate_io(fixture.inventory()),
                gate.program_id(),
                &captured.loaded.inventory(),
            );
            assert_eq!(
                gate_io(gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)),
                next.tc_program_id()
            );
            gate_io(gate_bpf::require_native(
                gate_io(gate_bpf::xdp_state(fixture.ifindex)),
                next.program_id(),
            ));
            let retained = gate_io(gate_udp_claim(maps.claims.as_fd(), &key));
            assert_eq!(
                retained,
                NativeClaim {
                    last_seen_ns: retained.last_seen_ns,
                    ..original
                }
            );
            let stale = NativeClaim {
                last_seen_ns: gate_monotonic_ns() - 2 * NATIVE_CLAIM_UPDATE_INTERVAL_NS,
                ..retained
            };
            gate_udp_activity(maps.claims.as_fd(), &key, &stale);
            let before = gate_monotonic_ns();
            deliver(marker);
            let refreshed = gate_io(gate_udp_claim(maps.claims.as_fd(), &key));
            assert_eq!(
                refreshed,
                NativeClaim {
                    last_seen_ns: refreshed.last_seen_ns,
                    ..original
                }
            );
            assert!((before..=gate_monotonic_ns()).contains(&refreshed.last_seen_ns));
            if outbound == 1 {
                gate_io(gate_send(
                    sender.as_fd(),
                    &gate_frame(ipv6, 41121, b"udp-fresh-block"),
                ));
                let error = receiver
                    .recv_from(&mut [0u8; 128])
                    .expect_err("fresh Block admitted UDP");
                assert!(matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ));
                assert_eq!(
                    gate_udp_claim(maps.claims.as_fd(), &absent)
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::ENOENT)
                );
            } else {
                let expired = NativeClaim {
                    last_seen_ns: gate_monotonic_ns() - timeout - 1,
                    ..original
                };
                gate_udp_activity(maps.claims.as_fd(), &key, &expired);
                refuse(b"udp-cache-xdp-expired");
                assert!(!gate_io(gate_tap(
                    tap.as_fd(),
                    b"udp-cache-xdp-expired",
                    Duration::from_millis(100)
                )));
                assert_eq!(gate_io(gate_udp_claim(maps.claims.as_fd(), &key)), expired);

                // Isolate the actual TC evaluator using the existing gate-only ingress contract.
                gate_io(
                    gate_bpf::set_xdp(fixture.ifindex, -1, Some(next.xdp_program.as_raw_fd()))
                        .map_err(io::Error::from),
                );
                assert!(gate_io(gate_bpf::xdp_absent(fixture.ifindex)));
                gate_io(gate.check());
                gate_udp_activity(maps.claims.as_fd(), &key, &stale);
                let before = gate_monotonic_ns();
                deliver(b"udp-cache-tcx-proxy");
                let refreshed = gate_io(gate_udp_claim(maps.claims.as_fd(), &key));
                assert_eq!(
                    refreshed,
                    NativeClaim {
                        last_seen_ns: refreshed.last_seen_ns,
                        ..original
                    }
                );
                assert!((before..=gate_monotonic_ns()).contains(&refreshed.last_seen_ns));
                gate_udp_activity(maps.claims.as_fd(), &key, &expired);
                refuse(b"udp-cache-tcx-expired");
                assert!(gate_io(gate_tap(
                    tap.as_fd(),
                    b"udp-cache-tcx-expired",
                    Duration::from_secs(1)
                )));
                assert_eq!(gate_io(gate_udp_claim(maps.claims.as_fd(), &key)), expired);
                gate_io(maps.epoch_flags(6, 0));
                let _ = gate_io(target.kernel_owned(&key));
                assert_eq!(gate_io(gate_udp_claim(maps.claims.as_fd(), &key)), expired);
            }
        }
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_v2_projection_import_rejections() {
    use honk_ebpf_common::xdp::*;

    require_vm();
    let fixture = gate_io(GateFixture::new());
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let _gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let target = Arc::new(gate_io(programs.native_target(
        &gate_io(fixture.capture()),
        &[],
        &attachment,
    )));
    let mut maps = gate_io(GateNative::new());
    let captured = gate_io(GateCaptured::new(
        &fixture.directory,
        Arc::clone(&target),
        &mut maps,
    ));
    let budget = honk_netstack::MemoryBudget::new(4 << 20);
    let mut port = gate_io(crate::Port::<u32>::open_device(
        fixture.ifindex,
        0,
        crate::BindMode::Copy,
        crate::PortConfig {
            rx_frames: 16,
            control_frames: 2,
            bulk_frames: 2,
            ring_size: 16,
        },
        1500,
        false,
        NATIVE_METADATA_LEN,
        &budget,
    ));
    gate_io(port.refill());
    gate_io(programs.insert_xsk(0, port.as_fd()));
    assert!(
        gate_xsk_present(target.xsks_fd()),
        "NOT_EXERCISED: v2 normal-hook live XSK control"
    );
    let candidate = gate_io(maps.prepare_captured(&target, 2, &captured.config()));
    gate_io(candidate.publish(&target));
    gate_io(target.finish_publication());
    gate_io(maps.epoch(3));
    let frame = gate_frame(false, 41180, b"native-v2-projection");
    let execute = |tc: bool, program: &OwnedFd| {
        let mut context = vec![0u32; if tc { 48 } else { 6 }];
        context[if tc { 9 } else { 3 }] = fixture.ifindex;
        if !tc {
            context[1] = frame.len() as u32;
        }
        let mut result = vec![0u32; context.len()];
        let mut output = vec![0u8; frame.len() + 256];
        let mut request = TestRun {
            program: program.as_raw_fd() as u32,
            input_len: frame.len() as u32,
            output_len: output.len() as u32,
            input: frame.as_ptr() as u64,
            output: output.as_mut_ptr() as u64,
            repeat: 1,
            context_len: (context.len() * size_of::<u32>()) as u32,
            result_len: (result.len() * size_of::<u32>()) as u32,
            context: context.as_ptr() as u64,
            result: result.as_mut_ptr() as u64,
            ..TestRun::default()
        };
        gate_io(gate_bpf::bpf(10, &mut request));
        assert_eq!(
            &output[..request.output_len as usize],
            frame.as_slice(),
            "normal hook changed the v2 test frame"
        );
        request.action
    };
    let key = NativeKey {
        src_ip: [0, 0, 0xffff0000, u32::from_ne_bytes([198, 18, 0, 1])],
        dst_ip: [0, 0, 0xffff0000, u32::from_ne_bytes([198, 18, 0, 2])],
        src_port: 41180u16.to_be(),
        dst_port: 42000u16.to_be(),
        l4proto: 17,
        ip_version: 4,
        domain: 0,
        direction: 0,
        namespace_cookie: target.capture().authority.namespace_cookie,
        zone: 0,
        zone_state: 2,
        reserved: [0; 5],
    };
    let claim = NativeClaim {
        epoch: 3,
        incarnation: 3,
        scope: target.capture().authority.scope,
        executor: NATIVE_EXECUTOR_KERNEL,
        state: NATIVE_PHASE_ACTIVE,
        last_seen_ns: gate_monotonic_ns(),
        ..NativeClaim::default()
    };
    gate_io(gate_bpf::bpf(
        gate_bpf::BPF_MAP_UPDATE_ELEM,
        &mut gate_bpf::MapElemAttr {
            map_fd: maps.claims.as_raw_fd() as u32,
            reserved: 0,
            key: &key as *const _ as u64,
            value: &claim as *const _ as u64,
            flags: 0,
        },
    ));
    for (tc, program, pass, drop) in [
        (
            false,
            &candidate.xdp_program,
            XDP_PASS as u32,
            XDP_DROP as u32,
        ),
        (true, &candidate.tc_program, 0, 2),
    ] {
        gate_udp_activity(maps.claims.as_fd(), &key, &claim);
        assert_eq!(
            execute(tc, program),
            pass,
            "valid normal-hook claim control: tc={tc}"
        );
        for (name, invalid) in [
            ("phase", NativeClaim { state: 15, ..claim }),
            (
                "executor-phase",
                NativeClaim {
                    executor: NATIVE_EXECUTOR_CAPTURE,
                    ..claim
                },
            ),
            (
                "active-count",
                NativeClaim {
                    state: NATIVE_PHASE_ACTIVE | 16,
                    ..claim
                },
            ),
            (
                "owner-cookie",
                NativeClaim {
                    owner_cookie: 1,
                    ..claim
                },
            ),
            (
                "owner-incarnation",
                NativeClaim {
                    owner_incarnation: 1,
                    ..claim
                },
            ),
            (
                "attachment-generation",
                NativeClaim {
                    attachment_generation: 1,
                    ..claim
                },
            ),
            (
                "unknown-mark",
                NativeClaim {
                    mark_kind: 2,
                    ..claim
                },
            ),
            (
                "keep-value",
                NativeClaim {
                    mark_value: 1,
                    ..claim
                },
            ),
            (
                "set-zero",
                NativeClaim {
                    mark_kind: 1,
                    ..claim
                },
            ),
            (
                "set-value",
                NativeClaim {
                    mark_kind: 1,
                    mark_value: 7,
                    ..claim
                },
            ),
            (
                "source-pending",
                NativeClaim {
                    executor: NATIVE_EXECUTOR_PENDING,
                    state: NATIVE_PHASE_SOURCE_PENDING,
                    ..claim
                },
            ),
        ] {
            gate_udp_activity(maps.claims.as_fd(), &key, &invalid);
            assert_eq!(
                execute(tc, program),
                drop,
                "normal hook accepted {name}: tc={tc}"
            );
            assert_eq!(
                gate_io(gate_udp_claim(maps.claims.as_fd(), &key)),
                invalid,
                "rejected normal hook mutated {name}: tc={tc}"
            );
        }
    }
    gate_udp_activity(maps.claims.as_fd(), &key, &claim);
    let mut invalid_keys = vec![
        NativeKey { domain: 3, ..key },
        NativeKey {
            direction: 2,
            ..key
        },
        NativeKey {
            namespace_cookie: 0,
            ..key
        },
        NativeKey {
            zone_state: 3,
            ..key
        },
        NativeKey {
            domain: 1,
            direction: 1,
            ..key
        },
        NativeKey {
            zone_state: 0,
            ..key
        },
        NativeKey {
            domain: 2,
            zone_state: 0,
            ..key
        },
    ];
    for index in 0..5 {
        let mut invalid = key;
        invalid.reserved[index] = 1;
        invalid_keys.push(invalid);
    }
    // This typed API boundary rejects malformed keys before the separate CT/socket query.
    for invalid in invalid_keys {
        let error = target
            .kernel_owned(&invalid)
            .expect_err("malformed key crossed the typed query boundary");
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidInput,
            "invalid key {invalid:?}"
        );
    }
    native_import_requires_exact_authenticated_tail();
    gate_io(maps.epoch(4));
    for (key_size, value_size) in [(40, 40), (40, 72), (56, 40), (56, 48)] {
        let old = gate_io(gate_bpf::bpf_fd(
            gate_bpf::BPF_MAP_CREATE,
            &mut gate_bpf::MapCreateAttr {
                map_type: 1,
                key_size,
                value_size,
                max_entries: 64,
                map_flags: 0,
                inner_map_fd: 0,
                numa_node: 0,
                map_name: gate_bpf::object_name(b"hg_old_claims"),
            },
        ));
        assert!(
            target
                .prepare(&gate_bpf::NativeProgramConfig {
                    bytecode: &maps.policy,
                    root: maps.root.as_raw_fd(),
                    claims: old.as_raw_fd(),
                    scratch: maps.scratch.as_raw_fd(),
                    closed_counters: maps.counters.as_raw_fd(),
                    hook_ids: [1, 2],
                    epoch: 4,
                    scope: target.capture().authority.scope,
                    expires_boottime_ns: u64::MAX,
                    redirect_limit: 16,
                    captured: Some(&captured.config()),
                    reply_block_rules: &[],
                    preparation_memory_bytes: gate_io(target.preparation_memory_bytes()),
                })
                .is_err(),
            "legacy map accepted: {key_size}/{value_size}"
        );
    }
    gate_io(target.withdraw_recording_hooks());
    gate_io(gate_bpf::bpf(
        gate_bpf::BPF_MAP_DELETE_ELEM,
        &mut gate_bpf::map_attr(programs.xsks.as_fd(), &0, 0),
    ));
    port.close_socket();
    assert!(
        !gate_xsk_present(target.xsks_fd()),
        "v2 normal-hook cleanup retained its XSK"
    );
}
