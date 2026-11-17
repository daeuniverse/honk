//! One guest-only IPv4 UDP-L4 materialization experiment; no production Host authority.
use super::*;
use crate::{BindMode, Port, PortConfig};
use honk_datapath::buffer::TxClass;
use honk_netstack::MemoryBudget;
use std::ffi::CString;
use std::process::{Command, Stdio};

const LDX_DW: u8 = 0x79;
const STX_DW: u8 = 0x7b;
const BPF_TCX_INGRESS: u32 = 46;
const BPF_TCX_EGRESS: u32 = 47;
const MARKER: u16 = 0x0a51;
const SOURCE: [u8; 4] = [198, 19, 0, 1];
const DESTINATION: [u8; 4] = [198, 19, 0, 2];
const SOURCE_PORT: u16 = 46000;
const DESTINATION_PORT: u16 = 46001;
const SOURCE_MAC: [u8; 6] = [2, 0, 0, 1, 0, 1];
const SOURCE_PEER_MAC: [u8; 6] = [2, 0, 0, 1, 0, 2];
const TX_MAC: [u8; 6] = [2, 0, 0, 2, 0, 1];
const RX_MAC: [u8; 6] = [2, 0, 0, 2, 0, 2];
const CAPSULE: usize = 48;
const PREFIX: usize = 14 + 20 + 8 + CAPSULE;
const INNER_AGGREGATE: usize = 20 + 8 + 128;
const INNER_CHILD: usize = 20 + 8 + 64;
const FRAME: usize = PREFIX + INNER_CHILD;
const DEADLINE: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(100);
const MAX_PACKETS: usize = 16;
const SOURCE_HITS: u32 = 0;
const SOURCE_GSO_SIZE: u32 = 1;
const SOURCE_GSO_SEGS: u32 = 2;
const SOURCE_COOKIE: u32 = 3;
const SOURCE_REDIRECTS: u32 = 4;
const SOURCE_ERRORS: u32 = 5;
const OBSERVED: u32 = 6;
const DROPPED: u32 = 7;
const ADMITTED: u32 = 8;
const MATCH_OBSERVED: u32 = 9;
const MATCH_DROPPED: u32 = 10;
const COUNTERS: usize = 11;

type TestPort = Port<u32>;

fn ensure(condition: bool, message: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid_data(message))
    }
}

fn command(program: &str, args: &[&str]) -> io::Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let end = Instant::now() + DEADLINE;
    loop {
        if child.try_wait()?.is_some() {
            let output = child.wait_with_output()?;
            ensure(
                output.stdout.len() + output.stderr.len() <= 65536,
                "fixture command output bound",
            )?;
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "{program} {args:?}: {}\n{}\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                )));
            }
            return String::from_utf8(output.stdout).map_err(io::Error::other);
        }
        if Instant::now() >= end {
            let kill = child.kill();
            let joined = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{program} {args:?}: deadline; kill={kill:?}, join={joined:?}"),
            ));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn index(name: &str) -> io::Result<u32> {
    let name = CString::new(name).map_err(io::Error::other)?;
    // SAFETY: name is NUL terminated and only borrowed during the syscall.
    let result = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn number(name: &str, leaf: &str) -> io::Result<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/{leaf}"))?
        .trim()
        .parse()
        .map_err(io::Error::other)
}

#[repr(C)]
#[derive(Default)]
struct Query {
    target: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    programs: u64,
    count: u32,
    padding: u32,
    program_flags: u64,
    links: u64,
    link_flags: u64,
    revision: u64,
}

fn chain(ifindex: u32, attach_type: u32) -> io::Result<Vec<u32>> {
    let mut ids = [0u32; 4];
    let mut links = [0u32; 4];
    let mut query = Query {
        target: ifindex,
        attach_type,
        programs: ids.as_mut_ptr() as u64,
        links: links.as_mut_ptr() as u64,
        count: ids.len() as u32,
        ..Query::default()
    };
    bpf(16, &mut query)?;
    ensure(
        query.count as usize <= ids.len(),
        "TCX chain exceeds fixture bound",
    )?;
    Ok(ids[..query.count as usize].to_vec())
}

struct Links {
    names: [String; 4],
    indices: [u32; 4],
    source_features: String,
}

impl Links {
    fn create() -> io::Result<Self> {
        let prefix = format!("hx{:x}", std::process::id());
        let names = [
            format!("{prefix}s"),
            format!("{prefix}p"),
            format!("{prefix}t"),
            format!("{prefix}r"),
        ];
        for name in &names {
            ensure(
                name.len() < libc::IFNAMSIZ,
                "owned link name exceeds IFNAMSIZ",
            )?;
            let name = CString::new(name.as_str()).map_err(io::Error::other)?;
            // SAFETY: name is a NUL-terminated interface name.
            ensure(
                unsafe { libc::if_nametoindex(name.as_ptr()) } == 0,
                "owned link already exists",
            )?;
        }
        for (left, right) in [(0, 1), (2, 3)] {
            command(
                "ip",
                &[
                    "link",
                    "add",
                    "name",
                    &names[left],
                    "numtxqueues",
                    "1",
                    "numrxqueues",
                    "1",
                    "type",
                    "veth",
                    "peer",
                    "name",
                    &names[right],
                    "numtxqueues",
                    "1",
                    "numrxqueues",
                    "1",
                ],
            )?;
        }
        let mut indices = [0; 4];
        for (slot, name) in indices.iter_mut().zip(&names) {
            *slot = index(name)?;
            std::fs::write(
                format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"),
                b"1\n",
            )?;
            ensure(
                std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"))?
                    .trim()
                    == "1",
                "owned IPv6 disable readback",
            )?;
        }
        for (name, mac) in names.iter().zip([
            "02:00:00:01:00:01",
            "02:00:00:01:00:02",
            "02:00:00:02:00:01",
            "02:00:00:02:00:02",
        ]) {
            command(
                "ip",
                &[
                    "link", "set", "dev", name, "address", mac, "mtu", "1500", "up",
                ],
            )?;
        }
        command("ip", &["address", "add", "198.19.0.1/30", "dev", &names[0]])?;
        command(
            "ip",
            &[
                "neigh",
                "add",
                "198.19.0.2",
                "lladdr",
                "02:00:00:01:00:02",
                "nud",
                "permanent",
                "dev",
                &names[0],
            ],
        )?;
        let source_features = command("ethtool", &["-k", &names[0]])?;
        command(
            "ethtool",
            &[
                "-K",
                &names[2],
                "tx",
                "off",
                "gso",
                "off",
                "tso",
                "off",
                "tx-udp-segmentation",
                "off",
                "tx-udp_tnl-segmentation",
                "off",
                "tx-udp_tnl-csum-segmentation",
                "off",
            ],
        )?;
        let links = Self {
            names,
            indices,
            source_features,
        };
        links.readback()?;
        Ok(links)
    }

    fn readback(&self) -> io::Result<()> {
        for (position, name) in self.names.iter().enumerate() {
            ensure(
                index(name)? == self.indices[position]
                    && number(name, "ifindex")? == self.indices[position],
                "owned ifindex readback",
            )?;
            ensure(
                number(name, "iflink")? == self.indices[position ^ 1],
                "owned veth peer readback",
            )?;
            ensure(
                number(name, "mtu")? == 1500 && number(name, "type")? == 1,
                "owned Ethernet/MTU readback",
            )?;
            let path = Path::new("/sys/class/net").join(name);
            let expected_mac = [SOURCE_MAC, SOURCE_PEER_MAC, TX_MAC, RX_MAC][position]
                .map(|byte| format!("{byte:02x}"))
                .join(":");
            ensure(
                std::fs::read_to_string(path.join("address"))?.trim() == expected_mac,
                "owned MAC readback",
            )?;
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let leaf = entry.file_name();
                let leaf = leaf.to_string_lossy();
                ensure(
                    !leaf.starts_with("upper_") && leaf != "master",
                    "owned link has upper/master",
                )?;
            }
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
                "owned links require exactly queue zero",
            )?;
            ensure(
                xdp_absent(self.indices[position])?,
                "foreign XDP on owned link",
            )?;
            for direction in [BPF_TCX_INGRESS, BPF_TCX_EGRESS] {
                ensure(
                    chain(self.indices[position], direction)?.is_empty(),
                    "foreign TCX on owned link",
                )?;
            }
            let qdiscs = command("tc", &["qdisc", "show", "dev", name])?;
            ensure(
                qdiscs
                    .lines()
                    .all(|line| line.starts_with("qdisc noqueue ")),
                "foreign qdisc on owned link",
            )?;
            let addresses = command("ip", &["-o", "address", "show", "dev", name])?;
            if position == 0 {
                ensure(
                    addresses.lines().count() == 1 && addresses.contains(" inet 198.19.0.1/30 "),
                    "source address readback",
                )?;
            } else {
                ensure(
                    addresses.trim().is_empty(),
                    "unnumbered owned peer acquired an address",
                )?;
            }
        }
        let route = command(
            "ip",
            &["-o", "route", "get", "198.19.0.2", "from", "198.19.0.1"],
        )?;
        ensure(
            route.contains(&format!("dev {} ", self.names[0])),
            "source egress route readback",
        )?;
        let neighbor = command(
            "ip",
            &["neigh", "show", "to", "198.19.0.2", "dev", &self.names[0]],
        )?;
        ensure(
            neighbor.contains("lladdr 02:00:00:01:00:02 PERMANENT"),
            "fixed source neighbor readback",
        )?;
        let features = command("ethtool", &["-k", &self.names[2]])?;
        for (name, state) in [
            ("tx-vlan-offload", "on"),
            ("tx-checksum-ip-generic", "off"),
            ("generic-segmentation-offload", "off"),
            ("tcp-segmentation-offload", "off"),
            ("tx-udp-segmentation", "off"),
            ("tx-udp_tnl-segmentation", "off"),
            ("tx-udp_tnl-csum-segmentation", "off"),
        ] {
            ensure(
                features.lines().any(|line| {
                    line.split_whitespace()
                        .take(2)
                        .eq([format!("{name}:"), state.to_owned()])
                }),
                "private TX offload readback",
            )?;
        }
        eprintln!("Host primitive private TX feature readback:\n{features}");
        ensure(
            command("ethtool", &["-k", &self.names[0]])? == self.source_features,
            "source offloads changed",
        )
    }

    fn remove(self) -> io::Result<()> {
        for position in [0, 2] {
            ensure(
                index(&self.names[position])? == self.indices[position],
                "owned link changed before removal",
            )?;
            command("ip", &["link", "delete", "dev", &self.names[position]])?;
        }
        for name in &self.names {
            let name = CString::new(name.as_str()).map_err(io::Error::other)?;
            // SAFETY: name is NUL terminated; this is a readback only.
            ensure(
                unsafe { libc::if_nametoindex(name.as_ptr()) } == 0,
                "owned link remains after deletion",
            )?;
        }
        Ok(())
    }
}

fn count(b: &mut Builder, counters: RawFd, key: u32) {
    b.emit(Insn::new(ST_W, 10, 0, -4, key as i32));
    b.count(counters);
}

fn fact(b: &mut Builder, counters: RawFd, key: u32, register: u8) {
    b.emit(Insn::new(STX_DW, 10, register, -40, 0));
    b.emit(Insn::new(ST_W, 10, 0, -4, key as i32));
    b.map_fd(counters);
    b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
    b.emit(Insn::new(ADD_K, 2, 0, 0, -4));
    b.emit(Insn::new(CALL, 0, 0, 0, 1));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_DW, 1, 10, -40, 0));
    b.emit(Insn::new(STX_DW, 0, 1, 0, 0));
}

fn immediate64(b: &mut Builder, register: u8, value: u64) {
    b.emit(Insn::new(LD_MAP, register, 0, 0, value as u32 as i32));
    b.emit(Insn::new(0, 0, 0, 0, (value >> 32) as u32 as i32));
}

fn equal(b: &mut Builder, code: u8, base: u8, offset: i16, expected: i32, failure: Label) {
    b.emit(Insn::new(code, 0, base, offset, 0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, expected), failure);
}

fn bytes_equal(b: &mut Builder, offset: usize, bytes: &[u8], failure: Label) {
    for (position, byte) in bytes.iter().enumerate() {
        equal(
            b,
            LDX_B,
            6,
            (offset + position) as i16,
            i32::from(*byte),
            failure,
        );
    }
}

fn header(cookie: u64, source: u32, private_tx: u32, inner_len: usize) -> [u8; PREFIX] {
    let mut bytes = [0u8; PREFIX];
    bytes[..6].copy_from_slice(&RX_MAC);
    bytes[6..12].copy_from_slice(&TX_MAC);
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((PREFIX - 14 + inner_len) as u16).to_be_bytes());
    bytes[18..20].copy_from_slice(&0x3434u16.to_be_bytes());
    bytes[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[198, 18, 0, 1]);
    bytes[30..34].copy_from_slice(&[198, 18, 0, 2]);
    let sum = checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&sum.to_be_bytes());
    bytes[34..36].copy_from_slice(&49000u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&49001u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&((8 + CAPSULE + inner_len) as u16).to_be_bytes());
    // UDP tunnel GSO does not repair a nonzero aggregate outer checksum.
    bytes[42..46].copy_from_slice(b"HXSK");
    bytes[46..48].copy_from_slice(&1u16.to_be_bytes());
    bytes[48..56].copy_from_slice(&cookie.to_ne_bytes());
    bytes[56..60].copy_from_slice(&source.to_ne_bytes());
    bytes[60..64].copy_from_slice(&private_tx.to_ne_bytes());
    bytes[64..68].copy_from_slice(&SOURCE);
    bytes[68..72].copy_from_slice(&DESTINATION);
    bytes[72..74].copy_from_slice(&SOURCE_PORT.to_be_bytes());
    bytes[74..76].copy_from_slice(&DESTINATION_PORT.to_be_bytes());
    bytes[76..80].copy_from_slice(&(INNER_AGGREGATE as u32).to_ne_bytes());
    bytes[80..84].copy_from_slice(&64u32.to_ne_bytes());
    bytes[84..88].copy_from_slice(&2u32.to_ne_bytes());
    bytes
}

fn producer(source: u32, private_tx: u32, cookie: u64, counters: RawFd) -> io::Result<Program> {
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    for (offset, value) in [
        (40, source as i32),
        (36, 0),
        (4, 0),
        (12, 0),
        (16, i32::from(0x0800u16.to_be())),
        (20, 0),
        (0, (14 + INNER_AGGREGATE) as i32),
    ] {
        equal(&mut b, LDX_W, 9, offset, value, Label::Malformed);
    }
    b.emit(Insn::new(LDX_DW, 1, 9, 168, 0));
    b.jump(Insn::new(JEQ_K, 1, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(CALL, 0, 0, 0, 95));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(MOV_X, 8, 0, 0, 0));
    for (offset, value) in [
        (0, source as i32),
        (4, libc::AF_INET),
        (8, libc::SOCK_DGRAM),
        (12, libc::IPPROTO_UDP),
        (24, u32::from_ne_bytes(SOURCE) as i32),
        (44, i32::from(SOURCE_PORT)),
        (48, i32::from(DESTINATION_PORT.to_be())),
        (52, u32::from_ne_bytes(DESTINATION) as i32),
    ] {
        equal(&mut b, LDX_W, 8, offset, value, Label::Malformed);
    }
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 46));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    immediate64(&mut b, 1, cookie);
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(MOV_X, 8, 0, 0, 0));
    b.emit(Insn::new(STX_DW, 10, 8, -16, 0));
    fact(&mut b, counters, SOURCE_COOKIE, 8);
    for (offset, stack, key, value) in [
        (176, -20, SOURCE_GSO_SIZE, 64),
        (164, -24, SOURCE_GSO_SEGS, 2),
    ] {
        b.emit(Insn::new(LDX_W, 8, 9, offset, 0));
        b.emit(Insn::new(STX_W, 10, 8, stack, 0));
        fact(&mut b, counters, key, 8);
        b.jump(Insn::new(JNE_K, 8, 0, 0, value), Label::Malformed);
    }
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, (14 + INNER_AGGREGATE) as i32));
    b.emit(Insn::new(CALL, 0, 0, 0, 39));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(LDX_W, 6, 9, 76, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 80, 0));
    b.bound((14 + INNER_AGGREGATE) as i32, Label::Malformed);
    bytes_equal(&mut b, 0, &SOURCE_PEER_MAC, Label::Malformed);
    bytes_equal(&mut b, 6, &SOURCE_MAC, Label::Malformed);
    bytes_equal(&mut b, 12, &0x0800u16.to_be_bytes(), Label::Malformed);
    equal(&mut b, LDX_B, 6, 14, 0x45, Label::Malformed);
    equal(&mut b, LDX_B, 6, 23, 17, Label::Malformed);
    bytes_equal(
        &mut b,
        16,
        &(INNER_AGGREGATE as u16).to_be_bytes(),
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_H, 0, 6, 20, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, i32::from(0x3fffu16.to_be())));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    bytes_equal(&mut b, 26, &SOURCE, Label::Malformed);
    bytes_equal(&mut b, 30, &DESTINATION, Label::Malformed);
    bytes_equal(&mut b, 34, &SOURCE_PORT.to_be_bytes(), Label::Malformed);
    bytes_equal(
        &mut b,
        36,
        &DESTINATION_PORT.to_be_bytes(),
        Label::Malformed,
    );
    bytes_equal(&mut b, 38, &136u16.to_be_bytes(), Label::Malformed);
    b.emit(Insn::new(LDX_H, 0, 6, 40, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    count(&mut b, counters, SOURCE_HITS);
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, (20 + 8 + CAPSULE) as i32));
    b.emit(Insn::new(MOV_K, 3, 0, 0, 1)); // BPF_ADJ_ROOM_MAC.
    b.emit(Insn::new(MOV_K, 4, 0, 0, (1 << 0) | (1 << 1) | (1 << 4)));
    b.emit(Insn::new(CALL, 0, 0, 0, 50));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    let prefix = header(0, source, private_tx, INNER_AGGREGATE);
    for (word, bytes) in prefix[..88].as_chunks::<4>().0.iter().enumerate() {
        b.emit(Insn::new(
            ST_W,
            10,
            0,
            -256 + word as i16 * 4,
            i32::from_ne_bytes(*bytes),
        ));
    }
    b.emit(Insn::new(ST_H, 10, 0, -168, 0));
    for (code, load, store) in [(LDX_DW, -16, -208), (LDX_W, -20, -176), (LDX_W, -24, -172)] {
        b.emit(Insn::new(code, 0, 10, load, 0));
        b.emit(Insn::new(
            if code == LDX_DW { STX_DW } else { STX_W },
            10,
            0,
            store,
            0,
        ));
    }
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    b.emit(Insn::new(MOV_X, 3, 10, 0, 0));
    b.emit(Insn::new(ADD_K, 3, 0, 0, -256));
    b.emit(Insn::new(MOV_K, 4, 0, 0, PREFIX as i32));
    b.emit(Insn::new(MOV_K, 5, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 9));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, i32::from(0x8100u16.to_be())));
    b.emit(Insn::new(MOV_K, 3, 0, 0, i32::from(MARKER)));
    b.emit(Insn::new(CALL, 0, 0, 0, 18));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    count(&mut b, counters, SOURCE_REDIRECTS);
    b.emit(Insn::new(MOV_K, 1, 0, 0, private_tx as i32));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 23));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 7), Label::Malformed);
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Malformed);
    count(&mut b, counters, SOURCE_ERRORS);
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, 2)); // TCX_DROP / TC_ACT_SHOT.
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

fn guard(
    rx: u32,
    source: u32,
    tx: u32,
    cookie: u64,
    counters: RawFd,
    xsks: RawFd,
    kfunc: u32,
) -> io::Result<Program> {
    let mut b = Builder::new();
    b.program.flags = 1 << 6;
    b.program.ifindex = rx;
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    count(&mut b, counters, OBSERVED);
    equal(&mut b, LDX_W, 9, 12, rx as i32, Label::Malformed);
    equal(&mut b, LDX_W, 9, 16, 0, Label::Malformed);
    b.emit(Insn::new(LDX_W, 6, 9, 0, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 4, 0));
    b.bound(18, Label::Malformed);
    bytes_equal(&mut b, 0, &RX_MAC, Label::Malformed);
    bytes_equal(&mut b, 6, &TX_MAC, Label::Malformed);
    b.emit(Insn::new(ST_W, 10, 0, -32, 0));
    b.emit(Insn::new(LDX_H, 0, 6, 12, 0));
    let untagged = forward(&mut b, JNE_K, 0, 0, i32::from(0x8100u16.to_be()));
    bytes_equal(&mut b, 14, &MARKER.to_be_bytes(), Label::Malformed);
    b.emit(Insn::new(ST_W, 10, 0, -32, 1));
    b.emit(Insn::new(ADD_K, 6, 0, 0, 4));
    patch(&mut b, untagged);
    b.bound(FRAME as i32, Label::Malformed);
    b.emit(Insn::new(MOV_X, 0, 6, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, FRAME as i32));
    b.jump(Insn::new(JNE_X, 0, 7, 0, 0), Label::Malformed);
    let expected = header(cookie, source, tx, INNER_CHILD);
    // IPv4 IDs and their checksums are independently checked after real RX.
    for (position, byte) in expected.iter().enumerate().skip(12) {
        if ![18, 19, 24, 25].contains(&position) {
            equal(
                &mut b,
                LDX_B,
                6,
                position as i16,
                i32::from(*byte),
                Label::Malformed,
            );
        }
    }
    equal(&mut b, LDX_B, 6, PREFIX as i16, 0x45, Label::Malformed);
    equal(&mut b, LDX_B, 6, (PREFIX + 9) as i16, 17, Label::Malformed);
    bytes_equal(
        &mut b,
        PREFIX + 2,
        &(INNER_CHILD as u16).to_be_bytes(),
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_H, 0, 6, (PREFIX + 6) as i16, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, i32::from(0x3fffu16.to_be())));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    bytes_equal(&mut b, PREFIX + 12, &SOURCE, Label::Malformed);
    bytes_equal(&mut b, PREFIX + 16, &DESTINATION, Label::Malformed);
    bytes_equal(
        &mut b,
        PREFIX + 20,
        &SOURCE_PORT.to_be_bytes(),
        Label::Malformed,
    );
    bytes_equal(
        &mut b,
        PREFIX + 22,
        &DESTINATION_PORT.to_be_bytes(),
        Label::Malformed,
    );
    bytes_equal(&mut b, PREFIX + 24, &72u16.to_be_bytes(), Label::Malformed);
    bytes_equal(&mut b, PREFIX + 28, &[0x5a; 64], Label::Malformed);
    count(&mut b, counters, MATCH_OBSERVED);
    b.emit(Insn::new(ST_W, 10, 0, -48, 0));
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
    b.emit(Insn::new(ADD_K, 2, 0, 0, -48));
    b.emit(Insn::new(MOV_X, 3, 10, 0, 0));
    b.emit(Insn::new(ADD_K, 3, 0, 0, -46));
    b.emit(Insn::new(CALL, 0, 2, 0, kfunc as i32));
    b.jump(Insn::new(JNE32_K, 0, 0, 0, 0), Label::CountDrop);
    equal(
        &mut b,
        LDX_H,
        10,
        -48,
        i32::from(0x8100u16.to_be()),
        Label::CountDrop,
    );
    equal(&mut b, LDX_H, 10, -46, i32::from(MARKER), Label::CountDrop);
    equal(&mut b, LDX_W, 10, -32, 0, Label::CountDrop);
    b.map_fd(xsks);
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    b.emit(Insn::new(MOV_K, 3, 0, 0, XDP_DROP));
    b.emit(Insn::new(CALL, 0, 0, 0, 51));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 4), Label::CountDrop);
    count(&mut b, counters, ADMITTED);
    b.emit(Insn::new(MOV_K, 0, 0, 0, 4));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::CountDrop);
    count(&mut b, counters, MATCH_DROPPED);
    b.label(Label::Malformed);
    count(&mut b, counters, DROPPED);
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_DROP));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

fn load_producer(program: &Program, log: &mut [u8]) -> io::Result<(OwnedFd, u32)> {
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
        prog_name: object_name(b"hxsk_producer"),
        prog_ifindex: 0,
        expected_attach_type: BPF_TCX_EGRESS,
        ..Default::default()
    };
    let fd = bpf_fd(BPF_PROG_LOAD, &mut attr).map_err(|error| {
        let length = log.iter().position(|&byte| byte == 0).unwrap_or(log.len());
        io::Error::new(
            error.kind(),
            format!(
                "SCHED_CLS producer load: {error}\n{}",
                String::from_utf8_lossy(&log[..length])
            ),
        )
    })?;
    let mut info = ProgInfo::default();
    object_info(fd.as_fd(), &mut info)?;
    ensure(
        info.kind == 3 && info.id != 0,
        "SCHED_CLS producer identity readback",
    )?;
    Ok((fd, info.id))
}

#[repr(C)]
#[derive(Default)]
struct TcxInfo {
    kind: u32,
    id: u32,
    program: u32,
    padding: u32,
    ifindex: u32,
    attach_type: u32,
}

fn attach_producer(program: &OwnedFd, program_id: u32, ifindex: u32) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct TcxCreate {
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
        &mut TcxCreate {
            program: program.as_raw_fd() as u32,
            target: ifindex,
            attach_type: BPF_TCX_EGRESS,
            flags: 1 << 4,
            relative: 0,
            padding: 0,
            revision: 0,
        },
    )?;
    let mut info = TcxInfo::default();
    object_info(link.as_fd(), &mut info)?;
    ensure(
        info.kind == 11
            && info.id != 0
            && info.program == program_id
            && info.ifindex == ifindex
            && info.attach_type == BPF_TCX_EGRESS,
        "TCX link identity readback",
    )?;
    ensure(
        chain(ifindex, BPF_TCX_EGRESS)? == [program_id],
        "TCX producer is not sole egress hook",
    )?;
    Ok(link)
}

fn attach_guard(program: &OwnedFd, id: u32, ifindex: u32) -> io::Result<OwnedFd> {
    let link = bpf_fd(
        BPF_LINK_CREATE,
        &mut LinkCreateAttr {
            prog_fd: program.as_raw_fd() as u32,
            target_ifindex: ifindex,
            attach_type: BPF_XDP,
            flags: XDP_FLAGS_DRV_MODE,
        },
    )?;
    let mut info = LinkInfo::default();
    object_info(link.as_fd(), &mut info)?;
    ensure(
        info.kind == BPF_LINK_TYPE_XDP
            && info.id != 0
            && info.prog_id == id
            && info.ifindex == ifindex,
        "private native XDP link identity readback",
    )?;
    require_native(xdp_state(ifindex)?, id)?;
    Ok(link)
}

fn counters(map: &OwnedFd) -> io::Result<[u64; COUNTERS]> {
    let mut values = [0u64; COUNTERS];
    for (key, value) in values.iter_mut().enumerate() {
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            &mut map_attr(map.as_fd(), &(key as u32), value as *mut u64 as u64),
        )?;
    }
    Ok(values)
}

fn sender(name: &str) -> io::Result<(UdpSocket, u64)> {
    let sender = UdpSocket::bind((Ipv4Addr::from(SOURCE), SOURCE_PORT))?;
    let name = CString::new(name).map_err(io::Error::other)?;
    // SAFETY: the option borrows a NUL-terminated interface name for this syscall.
    let result = unsafe {
        libc::setsockopt(
            sender.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    sender.connect((Ipv4Addr::from(DESTINATION), DESTINATION_PORT))?;
    sender.set_write_timeout(Some(DEADLINE))?;
    ensure(
        sender.local_addr()? == SocketAddr::from((SOURCE, SOURCE_PORT)),
        "sender local binding",
    )?;
    ensure(
        sender.peer_addr()? == SocketAddr::from((DESTINATION, DESTINATION_PORT)),
        "sender peer tuple",
    )?;
    let mut cookie = 0u64;
    let mut size = size_of::<u64>() as libc::socklen_t;
    // SAFETY: cookie and size are writable objects of the SO_COOKIE UAPI extent.
    let result = unsafe {
        libc::getsockopt(
            sender.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut size,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    ensure(
        size as usize == size_of::<u64>() && cookie != 0,
        "sender SO_COOKIE readback",
    )?;
    Ok((sender, cookie))
}

fn send_segments(sender: &UdpSocket) -> io::Result<()> {
    let payload = [0x5au8; 128];
    let mut vector = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut control = [0u64; 4];
    // SAFETY: zero is the empty msghdr representation; referenced buffers outlive sendmsg.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<u16>() as u32) } as usize;
    // SAFETY: aligned control has enough initialized storage for one u16 control message.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        (*cmsg).cmsg_level = libc::IPPROTO_UDP;
        (*cmsg).cmsg_type = 103; // UDP_SEGMENT.
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<u16>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<u16>(), 64);
    }
    // SAFETY: all msghdr/iovec/control extents above remain alive and are immutable input.
    let result = unsafe { libc::sendmsg(sender.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    ensure(result == 128, "UDP_SEGMENT short submission")
}

fn send_packet(ifindex: u32, frame: &[u8], bypass: bool) -> io::Result<()> {
    // SAFETY: socket returns a fresh descriptor or a negative errno result.
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(0x0003u16.to_be()),
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a newly owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: DEADLINE.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    // SAFETY: timeout and option have the documented integer/timeval extents.
    let result = unsafe {
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&timeout as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if bypass {
        let enabled = 1i32;
        // SAFETY: enabled is the integer PACKET_QDISC_BYPASS option.
        let result = unsafe {
            libc::setsockopt(
                raw,
                263,
                20,
                (&enabled as *const i32).cast(),
                size_of::<i32>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: zero initializes all reserved sockaddr_ll bytes.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = 0x0003u16.to_be();
    address.sll_ifindex = ifindex as i32;
    address.sll_halen = 6;
    address.sll_addr[..6].copy_from_slice(&RX_MAC);
    // SAFETY: address and complete frame are borrowed for sendto only.
    let result = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            libc::MSG_NOSIGNAL,
            (&address as *const libc::sockaddr_ll).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    ensure(result as usize == frame.len(), "AF_PACKET short submission")
}

fn receive(port: &mut TestPort, packets: &mut Vec<Vec<u8>>) -> io::Result<()> {
    let mut overflow = false;
    port.receive_segments(MAX_PACKETS, 0, |segments, metadata| {
        if packets.len() == MAX_PACKETS || segments.len() != 1 || !metadata.is_empty() {
            overflow = true;
        } else {
            packets.push(segments[0].to_vec());
        }
    })?;
    ensure(!overflow, "RX packet/segment bound")?;
    port.kick()
}

fn validate(frame: &[u8], cookie: u64, source: u32, tx: u32) -> io::Result<()> {
    ensure(frame.len() == FRAME, "materialized frame extent")?;
    let expected = header(cookie, source, tx, INNER_CHILD);
    for (offset, (&actual, &expected)) in frame[..PREFIX].iter().zip(&expected).enumerate() {
        if ![18, 19, 24, 25].contains(&offset) {
            ensure(
                actual == expected,
                "materialized capsule/outer envelope mismatch",
            )?;
        }
    }
    ensure(checksum(&frame[14..34]) == 0, "outer IPv4 checksum")?;
    let ip = &frame[PREFIX..];
    ensure(
        ip[0] == 0x45 && ip[9] == 17 && u16::from_be_bytes([ip[2], ip[3]]) as usize == INNER_CHILD,
        "inner IPv4 representation",
    )?;
    ensure(
        u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff == 0,
        "inner IPv4 fragmentation",
    )?;
    ensure(
        ip[12..16] == SOURCE && ip[16..20] == DESTINATION,
        "inner IPv4 tuple",
    )?;
    ensure(checksum(&ip[..20]) == 0, "inner IPv4 checksum")?;
    let udp = &ip[20..];
    ensure(
        udp[..2] == SOURCE_PORT.to_be_bytes()
            && udp[2..4] == DESTINATION_PORT.to_be_bytes()
            && udp[4..6] == 72u16.to_be_bytes(),
        "inner UDP tuple/extent",
    )?;
    ensure(
        udp[6..8] != [0, 0] && udp[8..] == [0x5a; 64],
        "inner UDP checksum/payload presence",
    )?;
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&ip[12..20]);
    pseudo.extend_from_slice(&[0, 17, 0, 72]);
    pseudo.extend_from_slice(udp);
    ensure(checksum(&pseudo) == 0, "inner UDP checksum")
}

fn wait_positive(
    sender: &UdpSocket,
    port: &mut TestPort,
    map: &OwnedFd,
    cookie: u64,
    source: u32,
    tx: u32,
) -> io::Result<Vec<Vec<u8>>> {
    let before = counters(map)?;
    send_segments(sender)?;
    let end = Instant::now() + DEADLINE;
    let mut settled = None;
    let mut packets = Vec::with_capacity(MAX_PACKETS);
    loop {
        receive(port, &mut packets)?;
        ensure(packets.len() <= 2, "extra positive children")?;
        let now = Instant::now();
        if packets.len() == 2 {
            let quiet = settled.get_or_insert(now + QUIET);
            if now >= *quiet {
                break;
            }
        }
        ensure(now < end, "positive RX deadline")?;
        std::thread::sleep(Duration::from_millis(1));
    }
    for packet in &packets {
        validate(packet, cookie, source, tx)?;
    }
    ensure(
        packets[0][PREFIX + 28..] == packets[1][PREFIX + 28..],
        "child payload inequality",
    )?;
    let after = counters(map)?;
    for (key, delta) in [
        (SOURCE_HITS, 1),
        (SOURCE_REDIRECTS, 1),
        (SOURCE_ERRORS, 0),
        (OBSERVED, 2),
        (DROPPED, 0),
        (ADMITTED, 2),
        (MATCH_OBSERVED, 2),
        (MATCH_DROPPED, 0),
    ] {
        ensure(
            after[key as usize].checked_sub(before[key as usize]) == Some(delta),
            "positive source/peer counter delta",
        )?;
    }
    ensure(
        after[SOURCE_GSO_SIZE as usize] == 64
            && after[SOURCE_GSO_SEGS as usize] == 2
            && after[SOURCE_COOKIE as usize] == cookie,
        "actual pre-helper GSO/cookie observation",
    )?;
    eprintln!(
        "Host primitive positive: one UDP_SEGMENT submission, GSO=(64,2), SO_COOKIE={cookie}, actual children=2"
    );
    Ok(packets)
}

fn wait_negative(
    label: &str,
    port: &mut TestPort,
    injector: &mut TestPort,
    map: &OwnedFd,
    submit: impl FnOnce(&mut TestPort) -> io::Result<()>,
    needs_cq: bool,
) -> io::Result<()> {
    let before = counters(map)?;
    let submitted = injector.counters().submitted;
    submit(injector)?;
    let end = Instant::now() + DEADLINE;
    let mut packets = Vec::with_capacity(MAX_PACKETS);
    let mut settled = None;
    let mut returned_owners = 0;
    loop {
        receive(port, &mut packets)?;
        ensure(packets.is_empty(), "negative admitted an XSK child")?;
        injector.kick()?;
        injector.complete(|owners| {
            returned_owners += owners.iter().filter(|owner| owner.is_some()).count();
        })?;
        let after = counters(map)?;
        ensure(
            after[ADMITTED as usize] == before[ADMITTED as usize],
            "negative admission counter increased",
        )?;
        ensure(
            after[SOURCE_HITS as usize] == before[SOURCE_HITS as usize]
                && after[SOURCE_REDIRECTS as usize] == before[SOURCE_REDIRECTS as usize],
            "negative traversed producer",
        )?;
        let observed = after[MATCH_OBSERVED as usize].checked_sub(before[MATCH_OBSERVED as usize]);
        let dropped = after[MATCH_DROPPED as usize].checked_sub(before[MATCH_DROPPED as usize]);
        ensure(
            observed.is_some_and(|value| value <= 1) && dropped.is_some_and(|value| value <= 1),
            "negative peer packet bound",
        )?;
        let cq = !needs_cq
            || (injector.counters().submitted == submitted + 1
                && injector.counters().completed == submitted + 1
                && returned_owners == 1
                && injector.outstanding().next().is_none());
        let now = Instant::now();
        if observed == Some(1) && dropped == Some(1) && cq {
            let quiet = settled.get_or_insert(now + QUIET);
            if now >= *quiet {
                ensure(
                    after[OBSERVED as usize].checked_sub(before[OBSERVED as usize]) == Some(1)
                        && after[DROPPED as usize].checked_sub(before[DROPPED as usize]) == Some(1),
                    "negative exact peer observation/drop delta",
                )?;
                break;
            }
        }
        ensure(now < end, "negative observation/CQ deadline")?;
        std::thread::sleep(Duration::from_millis(1));
    }
    eprintln!(
        "Host primitive negative {label}: matching peer observed=1/drop=1, admitted=0/RX=0, actual CQ={needs_cq}"
    );
    Ok(())
}

fn drain(port: &mut TestPort) -> io::Result<()> {
    port.close();
    let end = Instant::now() + DEADLINE;
    let mut packets = Vec::with_capacity(MAX_PACKETS);
    loop {
        receive(port, &mut packets)?;
        port.complete(|_| {})?;
        port.observe_fill()?;
        if !port.needs_service_retry()
            && port.drain_state().ready_for_backend_teardown()
            && port.outstanding().next().is_none()
            && port.counters().submitted == port.counters().completed
        {
            ensure(packets.is_empty(), "unexpected queued RX during cleanup")?;
            return Ok(());
        }
        ensure(Instant::now() < end, "actual RX/TX/CQ drain deadline")?;
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_private_host_vlan_marker_and_udp_segments() {
    require_vm();
    let result = (|| -> io::Result<()> {
        let links = Links::create()?;
        let (sender, cookie) = sender(&links.names[0])?;
        let count_map = create_map(2, 8, COUNTERS as u32, b"hxsk_counts")?;
        let xsks = create_map(17, 4, 1, b"hxsk_sockets")?;
        let kfunc = Btf::from_sys_fs()
            .and_then(|btf| btf.id_by_type_name_kind("bpf_xdp_metadata_rx_vlan_tag", BtfKind::Func))
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("RX VLAN kfunc BTF: {error}"),
                )
            })?;
        ensure(kfunc != 0, "zero VLAN kfunc BTF ID")?;
        let mut log = vec![0; 1 << 20];
        let (producer_program, producer_id) = load_producer(
            &producer(
                links.indices[0],
                links.indices[2],
                cookie,
                count_map.as_raw_fd(),
            )?,
            &mut log,
        )?;
        let (guard_program, guard_id) = load_program(
            &guard(
                links.indices[3],
                links.indices[0],
                links.indices[2],
                cookie,
                count_map.as_raw_fd(),
                xsks.as_raw_fd(),
                kfunc,
            )?,
            b"hxsk_guard",
            &mut log,
        )?;
        let guard_link = attach_guard(&guard_program, guard_id, links.indices[3])?;
        let config = PortConfig {
            rx_frames: 16,
            control_frames: 2,
            bulk_frames: 2,
            ring_size: 16,
        };
        let budget = MemoryBudget::new(4 << 20);
        let mut receiver = TestPort::open_device(
            links.indices[3],
            0,
            BindMode::Copy,
            config,
            1500,
            false,
            0,
            &budget,
        )?;
        let mut injector = TestPort::open_device(
            links.indices[2],
            0,
            BindMode::Copy,
            config,
            1500,
            false,
            0,
            &budget,
        )?;
        ensure(
            !receiver.zerocopy() && !injector.zerocopy(),
            "actual Copy socket mode readback",
        )?;
        receiver.refill()?;
        let socket = receiver.as_raw_fd() as u32;
        bpf(
            BPF_MAP_UPDATE_ELEM,
            &mut map_attr(xsks.as_fd(), &0, &socket as *const u32 as u64),
        )?;
        let producer_link = attach_producer(&producer_program, producer_id, links.indices[0])?;
        require_native(xdp_state(links.indices[3])?, guard_id)?;
        let golden = wait_positive(
            &sender,
            &mut receiver,
            &count_map,
            cookie,
            links.indices[0],
            links.indices[2],
        )?
        .remove(0);
        for (label, bypass) in [("AF_PACKET", false), ("PACKET_QDISC_BYPASS", true)] {
            wait_negative(
                label,
                &mut receiver,
                &mut injector,
                &count_map,
                |_| send_packet(links.indices[2], &golden, bypass),
                false,
            )?;
        }
        wait_negative(
            "AF_XDP Copy TX",
            &mut receiver,
            &mut injector,
            &count_map,
            |port| {
                ensure(
                    port.transmit_generated(TxClass::Bulk, golden.len(), |output| {
                        output.copy_from_slice(&golden);
                        Ok(Some((golden.len(), 1)))
                    })?,
                    "AF_XDP negative was not published",
                )
            },
            true,
        )?;
        let mut inline = Vec::with_capacity(golden.len() + 4);
        inline.extend_from_slice(&golden[..12]);
        inline.extend_from_slice(&0x8100u16.to_be_bytes());
        inline.extend_from_slice(&MARKER.to_be_bytes());
        inline.extend_from_slice(&golden[12..]);
        wait_negative(
            "identical inline VLAN",
            &mut receiver,
            &mut injector,
            &count_map,
            |_| send_packet(links.indices[2], &inline, false),
            false,
        )?;
        wait_positive(
            &sender,
            &mut receiver,
            &count_map,
            cookie,
            links.indices[0],
            links.indices[2],
        )?;
        drop(sender);
        drop(producer_link);
        ensure(
            chain(links.indices[0], BPF_TCX_EGRESS)?.is_empty(),
            "producer admission remains attached",
        )?;
        drain(&mut receiver)?;
        drain(&mut injector)?;
        bpf(BPF_MAP_DELETE_ELEM, &mut map_attr(xsks.as_fd(), &0, 0))?;
        receiver.close_socket();
        injector.close_socket();
        ensure(
            receiver.as_raw_fd() == -1 && injector.as_raw_fd() == -1,
            "owned XSK sockets remain open",
        )?;
        drop(guard_link);
        ensure(
            xdp_absent(links.indices[3])?,
            "private XDP link remains attached",
        )?;
        drop((
            receiver,
            injector,
            producer_program,
            guard_program,
            xsks,
            count_map,
        ));
        ensure(
            command("ethtool", &["-k", &links.names[0]])? == links.source_features,
            "source offloads changed during fixture",
        )?;
        links.remove()?;
        Ok(())
    })();
    result.expect(
        "Host-XSK primitive failed; preserve this guest failure and verifier/runtime output",
    );
    println!("PASS: private Host VLAN marker and UDP segments");
}

const METADATA_FACT_BYTES: usize = 48;
const METADATA_MISSING: u32 = COUNTERS as u32;
const METADATA_MISMATCH: u32 = METADATA_MISSING + 1;
const METADATA_COUNTERS: u32 = METADATA_MISMATCH + 1;

#[derive(Clone, Copy)]
struct MetadataCase {
    id: u64,
    payload: usize,
    gso: bool,
}

impl MetadataCase {
    fn source_ip_len(self) -> usize {
        28 + self.payload
    }

    fn child_payload(self) -> usize {
        if self.gso { 64 } else { self.payload }
    }

    fn children(self) -> usize {
        if self.gso { 2 } else { 1 }
    }
}

fn metadata_record(
    case: MetadataCase,
    devices: [u32; 2],
    cookie: u64,
    gso_segs: u32,
) -> [u8; METADATA_FACT_BYTES] {
    let mut record = [0u8; METADATA_FACT_BYTES];
    record[..8].copy_from_slice(&case.id.to_ne_bytes());
    record[8..16].copy_from_slice(&cookie.to_ne_bytes());
    record[16..20].copy_from_slice(&devices[0].to_ne_bytes());
    record[20..24].copy_from_slice(&devices[1].to_ne_bytes());
    record[24..28].copy_from_slice(&(case.source_ip_len() as u32).to_ne_bytes());
    record[28..32].copy_from_slice(&(if case.gso { 64u32 } else { 0 }).to_ne_bytes());
    record[32..36].copy_from_slice(&gso_segs.to_ne_bytes());
    record[36..40].copy_from_slice(&SOURCE);
    record[40..44].copy_from_slice(&DESTINATION);
    record[44..46].copy_from_slice(&SOURCE_PORT.to_be_bytes());
    record[46..48].copy_from_slice(&DESTINATION_PORT.to_be_bytes());
    record
}

fn metadata_producer(
    case: MetadataCase,
    devices: [u32; 2],
    cookie: u64,
    counters: RawFd,
    facts: RawFd,
    stamp: u64,
    publish: bool,
) -> io::Result<Program> {
    ensure(
        case.id != 0 && case.id < (1 << 48) && stamp != 0 && stamp < (1 << 48),
        "metadata ID domain",
    )?;
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    for (offset, value) in [
        (40, devices[0] as i32),
        (36, 0),
        (4, 0),
        (12, 0),
        (16, i32::from(0x0800u16.to_be())),
        (20, 0),
        (0, (14 + case.source_ip_len()) as i32),
    ] {
        equal(&mut b, LDX_W, 9, offset, value, Label::Malformed);
    }
    b.emit(Insn::new(LDX_DW, 1, 9, 168, 0));
    b.jump(Insn::new(JEQ_K, 1, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(CALL, 0, 0, 0, 95));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(MOV_X, 8, 0, 0, 0));
    for (offset, value) in [
        (0, devices[0] as i32),
        (4, libc::AF_INET),
        (8, libc::SOCK_DGRAM),
        (12, libc::IPPROTO_UDP),
        (24, u32::from_ne_bytes(SOURCE) as i32),
        (44, i32::from(SOURCE_PORT)),
        (48, i32::from(DESTINATION_PORT.to_be())),
        (52, u32::from_ne_bytes(DESTINATION) as i32),
        (72, 1),
    ] {
        equal(&mut b, LDX_W, 8, offset, value, Label::Malformed);
    }
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 46));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    immediate64(&mut b, 1, cookie);
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(MOV_X, 8, 0, 0, 0));
    b.emit(Insn::new(STX_DW, 10, 8, -16, 0));
    fact(&mut b, counters, SOURCE_COOKIE, 8);
    for (offset, stack, key) in [(176, -20, SOURCE_GSO_SIZE), (164, -24, SOURCE_GSO_SEGS)] {
        b.emit(Insn::new(LDX_W, 8, 9, offset, 0));
        b.emit(Insn::new(STX_W, 10, 8, stack, 0));
        fact(&mut b, counters, key, 8);
        if key == SOURCE_GSO_SIZE || case.gso {
            let expected = if case.gso {
                if key == SOURCE_GSO_SIZE { 64 } else { 2 }
            } else {
                0
            };
            b.jump(Insn::new(JNE_K, 8, 0, 0, expected), Label::Malformed);
        }
    }
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(
        MOV_K,
        2,
        0,
        0,
        (14 + case.source_ip_len()) as i32,
    ));
    b.emit(Insn::new(CALL, 0, 0, 0, 39));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(LDX_W, 6, 9, 76, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 80, 0));
    b.bound((14 + case.source_ip_len()) as i32, Label::Malformed);
    bytes_equal(&mut b, 0, &SOURCE_PEER_MAC, Label::Malformed);
    bytes_equal(&mut b, 6, &SOURCE_MAC, Label::Malformed);
    bytes_equal(&mut b, 12, &0x0800u16.to_be_bytes(), Label::Malformed);
    equal(&mut b, LDX_B, 6, 14, 0x45, Label::Malformed);
    equal(&mut b, LDX_B, 6, 23, 17, Label::Malformed);
    bytes_equal(
        &mut b,
        16,
        &(case.source_ip_len() as u16).to_be_bytes(),
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_H, 0, 6, 20, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, i32::from(0x3fffu16.to_be())));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    bytes_equal(&mut b, 26, &SOURCE, Label::Malformed);
    bytes_equal(&mut b, 30, &DESTINATION, Label::Malformed);
    bytes_equal(&mut b, 34, &SOURCE_PORT.to_be_bytes(), Label::Malformed);
    bytes_equal(
        &mut b,
        36,
        &DESTINATION_PORT.to_be_bytes(),
        Label::Malformed,
    );
    bytes_equal(
        &mut b,
        38,
        &((case.payload + 8) as u16).to_be_bytes(),
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_H, 0, 6, 40, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    count(&mut b, counters, SOURCE_HITS);
    let mut ethernet = [0u8; 12];
    ethernet[..6].copy_from_slice(&RX_MAC);
    ethernet[6..].copy_from_slice(&TX_MAC);
    for (word, bytes) in ethernet.as_chunks::<4>().0.iter().enumerate() {
        b.emit(Insn::new(
            ST_W,
            10,
            0,
            -64 + word as i16 * 4,
            i32::from_ne_bytes(*bytes),
        ));
    }
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    b.emit(Insn::new(MOV_X, 3, 10, 0, 0));
    b.emit(Insn::new(ADD_K, 3, 0, 0, -64));
    b.emit(Insn::new(MOV_K, 4, 0, 0, 12));
    b.emit(Insn::new(MOV_K, 5, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 9));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    if publish {
        let expected = metadata_record(case, devices, 0, 0);
        for (word, bytes) in expected.as_chunks::<4>().0.iter().enumerate() {
            b.emit(Insn::new(
                ST_W,
                10,
                0,
                -128 + word as i16 * 4,
                i32::from_ne_bytes(*bytes),
            ));
        }
        for (code, from, to) in [(LDX_DW, -16, -120), (LDX_W, -20, -100), (LDX_W, -24, -96)] {
            b.emit(Insn::new(code, 0, 10, from, 0));
            b.emit(Insn::new(
                if code == LDX_DW { STX_DW } else { STX_W },
                10,
                0,
                to,
                0,
            ));
        }
        b.emit(Insn::new(ST_W, 10, 0, -32, 0));
        b.map_fd(facts);
        b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
        b.emit(Insn::new(ADD_K, 2, 0, 0, -32));
        b.emit(Insn::new(CALL, 0, 0, 0, 1));
        let exists = forward(&mut b, JNE_K, 0, 0, 0);
        b.map_fd(facts);
        b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
        b.emit(Insn::new(ADD_K, 2, 0, 0, -32));
        b.emit(Insn::new(MOV_X, 3, 10, 0, 0));
        b.emit(Insn::new(ADD_K, 3, 0, 0, -128));
        b.emit(Insn::new(MOV_K, 4, 0, 0, 1)); // BPF_NOEXIST; this record never changes.
        b.emit(Insn::new(CALL, 0, 0, 0, 2));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
        b.map_fd(facts);
        b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
        b.emit(Insn::new(ADD_K, 2, 0, 0, -32));
        b.emit(Insn::new(CALL, 0, 0, 0, 1));
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
        patch(&mut b, exists);
        b.emit(Insn::new(MOV_X, 8, 0, 0, 0));
        for offset in (0..METADATA_FACT_BYTES as i16).step_by(4) {
            b.emit(Insn::new(LDX_W, 0, 8, offset, 0));
            b.emit(Insn::new(LDX_W, 1, 10, -128 + offset, 0));
            b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
        }
    }
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, stamp as u32 as i32));
    b.emit(Insn::new(CALL, 0, 0, 0, 48));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, i32::from(0x8100u16.to_be())));
    b.emit(Insn::new(MOV_K, 3, 0, 0, (stamp >> 32) as i32));
    b.emit(Insn::new(CALL, 0, 0, 0, 18));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    count(&mut b, counters, SOURCE_REDIRECTS);
    b.emit(Insn::new(MOV_K, 1, 0, 0, devices[1] as i32));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 23));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 7), Label::Malformed);
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Malformed);
    count(&mut b, counters, SOURCE_ERRORS);
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, 2));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

fn metadata_guard(
    case: MetadataCase,
    devices: [u32; 3],
    cookie: u64,
    counters: RawFd,
    maps: [RawFd; 2],
    kfuncs: [u32; 2],
) -> io::Result<Program> {
    let mut b = Builder::new();
    b.program.flags = 1 << 6;
    b.program.ifindex = devices[2];
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    count(&mut b, counters, OBSERVED);
    equal(&mut b, LDX_W, 9, 12, devices[2] as i32, Label::Malformed);
    equal(&mut b, LDX_W, 9, 16, 0, Label::Malformed);
    b.emit(Insn::new(LDX_W, 6, 9, 0, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 4, 0));
    b.bound(18, Label::Malformed);
    bytes_equal(&mut b, 0, &RX_MAC, Label::Malformed);
    bytes_equal(&mut b, 6, &TX_MAC, Label::Malformed);
    b.emit(Insn::new(ST_W, 10, 0, -32, 0));
    b.emit(Insn::new(LDX_H, 0, 6, 12, 0));
    let untagged = forward(&mut b, JNE_K, 0, 0, i32::from(0x8100u16.to_be()));
    bytes_equal(
        &mut b,
        14,
        &((case.id >> 32) as u16).to_be_bytes(),
        Label::Malformed,
    );
    b.emit(Insn::new(ST_W, 10, 0, -32, 1));
    b.emit(Insn::new(ADD_K, 6, 0, 0, 4));
    patch(&mut b, untagged);
    let extent = 42 + case.child_payload();
    b.bound(extent as i32, Label::Malformed);
    b.emit(Insn::new(MOV_X, 0, 6, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, extent as i32));
    b.jump(Insn::new(JNE_X, 0, 7, 0, 0), Label::Malformed);
    bytes_equal(&mut b, 12, &0x0800u16.to_be_bytes(), Label::Malformed);
    equal(&mut b, LDX_B, 6, 14, 0x45, Label::Malformed);
    equal(&mut b, LDX_B, 6, 23, 17, Label::Malformed);
    bytes_equal(
        &mut b,
        16,
        &((28 + case.child_payload()) as u16).to_be_bytes(),
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_H, 0, 6, 20, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, i32::from(0x3fffu16.to_be())));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    bytes_equal(&mut b, 26, &SOURCE, Label::Malformed);
    bytes_equal(&mut b, 30, &DESTINATION, Label::Malformed);
    bytes_equal(&mut b, 34, &SOURCE_PORT.to_be_bytes(), Label::Malformed);
    bytes_equal(
        &mut b,
        36,
        &DESTINATION_PORT.to_be_bytes(),
        Label::Malformed,
    );
    bytes_equal(
        &mut b,
        38,
        &((8 + case.child_payload()) as u16).to_be_bytes(),
        Label::Malformed,
    );
    bytes_equal(&mut b, 42, &[0x5a; 16], Label::Malformed);
    count(&mut b, counters, MATCH_OBSERVED);
    for offset in [-48, -44, -40] {
        b.emit(Insn::new(ST_W, 10, 0, offset, 0));
    }
    for (kfunc, first, second) in [(kfuncs[0], -48, -46), (kfuncs[1], -44, -40)] {
        b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
        b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
        b.emit(Insn::new(ADD_K, 2, 0, 0, first));
        b.emit(Insn::new(MOV_X, 3, 10, 0, 0));
        b.emit(Insn::new(ADD_K, 3, 0, 0, second));
        b.emit(Insn::new(CALL, 0, 2, 0, kfunc as i32));
        b.jump(Insn::new(JNE32_K, 0, 0, 0, 0), Label::CountDrop);
    }
    equal(
        &mut b,
        LDX_H,
        10,
        -48,
        i32::from(0x8100u16.to_be()),
        Label::CountDrop,
    );
    equal(&mut b, LDX_W, 10, -40, 8, Label::CountDrop); // XDP_RSS_TYPE_L4_ANY.
    equal(&mut b, LDX_W, 10, -32, 0, Label::CountDrop);
    b.emit(Insn::new(LDX_H, 8, 10, -46, 0));
    b.emit(Insn::new(LSH_K, 8, 0, 0, 32));
    b.emit(Insn::new(LDX_W, 0, 10, -44, 0));
    b.emit(Insn::new(0x4f, 8, 0, 0, 0)); // OR_X, preserving unsigned low32.
    b.emit(Insn::new(STX_DW, 10, 8, -64, 0));
    b.emit(Insn::new(ST_W, 10, 0, -36, 0));
    b.map_fd(maps[1]);
    b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
    b.emit(Insn::new(ADD_K, 2, 0, 0, -36));
    b.emit(Insn::new(CALL, 0, 0, 0, 1));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Fragments);
    b.emit(Insn::new(MOV_X, 8, 0, 0, 0));
    b.emit(Insn::new(LDX_DW, 0, 8, 0, 0));
    b.emit(Insn::new(LDX_DW, 1, 10, -64, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Options);
    b.emit(Insn::new(LDX_DW, 0, 8, 8, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::CountDrop);
    immediate64(&mut b, 1, cookie);
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::CountDrop);
    let expected = metadata_record(case, [devices[0], devices[1]], cookie, 2);
    for (word, bytes) in expected[16..].as_chunks::<4>().0.iter().enumerate() {
        let offset = 16 + word as i16 * 4;
        if offset != 32 || case.gso {
            b.emit(Insn::new(LDX_W, 0, 8, offset, 0));
            b.jump(
                Insn::new(JNE32_K, 0, 0, 0, i32::from_ne_bytes(*bytes)),
                Label::CountDrop,
            );
        }
    }
    b.emit(Insn::new(ST_W, 10, 0, -96, i32::from_ne_bytes(*b"HXMI")));
    b.emit(Insn::new(ST_H, 10, 0, -92, 1));
    b.emit(Insn::new(ST_H, 10, 0, -90, 32));
    b.emit(Insn::new(LDX_DW, 0, 10, -64, 0));
    b.emit(Insn::new(STX_DW, 10, 0, -88, 0));
    for (from, to) in [(8, -80), (16, -72)] {
        b.emit(Insn::new(LDX_DW, 0, 8, from, 0));
        b.emit(Insn::new(STX_DW, 10, 0, to, 0));
    }
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, -32));
    b.emit(Insn::new(CALL, 0, 0, 0, 54));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::CountDrop);
    b.emit(Insn::new(LDX_W, 6, 9, 8, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 0, 0));
    b.bound(32, Label::CountDrop);
    for offset in (0..32).step_by(4) {
        b.emit(Insn::new(LDX_W, 0, 10, -96 + offset, 0));
        b.emit(Insn::new(STX_W, 6, 0, offset, 0));
    }
    b.map_fd(maps[0]);
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    b.emit(Insn::new(MOV_K, 3, 0, 0, XDP_DROP));
    b.emit(Insn::new(CALL, 0, 0, 0, 51));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 4), Label::CountDrop);
    count(&mut b, counters, ADMITTED);
    b.emit(Insn::new(MOV_K, 0, 0, 0, 4));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Fragments);
    count(&mut b, counters, METADATA_MISSING);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::CountDrop);
    b.label(Label::Options);
    count(&mut b, counters, METADATA_MISMATCH);
    b.label(Label::CountDrop);
    count(&mut b, counters, MATCH_DROPPED);
    b.label(Label::Malformed);
    count(&mut b, counters, DROPPED);
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_DROP));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

fn replace_metadata_producer(
    link: &OwnedFd,
    old: &OwnedFd,
    new: &OwnedFd,
    id: u32,
    ifindex: u32,
) -> io::Result<()> {
    let mut before = TcxInfo::default();
    object_info(link.as_fd(), &mut before)?;
    bpf(
        BPF_LINK_UPDATE,
        &mut LinkUpdateAttr {
            link_fd: link.as_raw_fd() as u32,
            new_prog_fd: new.as_raw_fd() as u32,
            flags: BPF_F_REPLACE,
            old_prog_fd: old.as_raw_fd() as u32,
        },
    )?;
    let mut after = TcxInfo::default();
    object_info(link.as_fd(), &mut after)?;
    ensure(
        after.kind == 11
            && after.id == before.id
            && after.program == id
            && after.ifindex == ifindex
            && after.attach_type == BPF_TCX_EGRESS,
        "metadata producer replacement identity",
    )?;
    ensure(
        chain(ifindex, BPF_TCX_EGRESS)? == [id],
        "metadata producer replacement chain",
    )
}

fn metadata_counter(map: &OwnedFd, key: u32) -> io::Result<u64> {
    let mut value = 0u64;
    bpf(
        BPF_MAP_LOOKUP_ELEM,
        &mut map_attr(map.as_fd(), &key, &mut value as *mut u64 as u64),
    )?;
    Ok(value)
}

fn metadata_fact_snapshot(map: &OwnedFd) -> io::Result<[u8; METADATA_FACT_BYTES]> {
    let mut record = [0u8; METADATA_FACT_BYTES];
    bpf(
        BPF_MAP_LOOKUP_ELEM,
        &mut map_attr(map.as_fd(), &0, record.as_mut_ptr() as u64),
    )?;
    Ok(record)
}

fn metadata_validate(
    frame: &[u8],
    metadata: &[u8],
    case: MetadataCase,
    devices: [u32; 2],
    cookie: u64,
) -> io::Result<()> {
    let payload = case.child_payload();
    ensure(
        frame.len() == 42 + payload,
        "metadata carrier wire growth/extent",
    )?;
    ensure(
        frame[..6] == RX_MAC && frame[6..12] == TX_MAC && frame[12..14] == 0x0800u16.to_be_bytes(),
        "metadata carrier Ethernet header",
    )?;
    let ip = &frame[14..];
    ensure(
        ip[0] == 0x45
            && ip[9] == 17
            && ip[2..4] == ((28 + payload) as u16).to_be_bytes()
            && u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff == 0,
        "metadata IPv4 extent/representation",
    )?;
    ensure(
        ip[12..16] == SOURCE && ip[16..20] == DESTINATION && checksum(&ip[..20]) == 0,
        "metadata IPv4 tuple/checksum",
    )?;
    let udp = &ip[20..];
    ensure(
        udp[..2] == SOURCE_PORT.to_be_bytes()
            && udp[2..4] == DESTINATION_PORT.to_be_bytes()
            && udp[4..6] == ((8 + payload) as u16).to_be_bytes()
            && udp[6..8] != [0, 0],
        "metadata UDP tuple/extent/checksum presence",
    )?;
    ensure(
        udp[8..].iter().all(|&byte| byte == 0x5a),
        "metadata complete UDP payload",
    )?;
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&ip[12..20]);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    ensure(checksum(&pseudo) == 0, "metadata complete UDP checksum")?;
    ensure(metadata.len() == 32, "private metadata extent")?;
    let mut expected = [0u8; 32];
    expected[..4].copy_from_slice(b"HXMI");
    expected[4..6].copy_from_slice(&1u16.to_ne_bytes());
    expected[6..8].copy_from_slice(&32u16.to_ne_bytes());
    expected[8..16].copy_from_slice(&case.id.to_ne_bytes());
    expected[16..24].copy_from_slice(&cookie.to_ne_bytes());
    expected[24..28].copy_from_slice(&devices[0].to_ne_bytes());
    expected[28..32].copy_from_slice(&devices[1].to_ne_bytes());
    ensure(
        metadata == expected,
        "actual recovered full ID/fact-cookie metadata",
    )
}

#[derive(Clone, Copy)]
enum MetadataObservation {
    Positive,
    RawDrop(bool),
    SourceDrop(u32),
}

fn metadata_observe(
    ports: [&mut TestPort; 2],
    map: &OwnedFd,
    case: MetadataCase,
    authority: ([u32; 2], u64),
    submit: impl FnOnce(&mut TestPort) -> io::Result<()>,
    outcome: MetadataObservation,
) -> io::Result<Vec<Vec<u8>>> {
    let [receiver, injector] = ports;
    let before = counters(map)?;
    let reasons = [
        metadata_counter(map, METADATA_MISSING)?,
        metadata_counter(map, METADATA_MISMATCH)?,
    ];
    let submitted = injector.counters().submitted;
    submit(injector)?;
    let children = if matches!(outcome, MetadataObservation::Positive) {
        case.children()
    } else {
        0
    };
    let peer_packets = if children == 0 { 1 } else { children };
    let source = u64::from(!matches!(outcome, MetadataObservation::RawDrop(_)));
    let needs_cq = matches!(outcome, MetadataObservation::RawDrop(true));
    let end = Instant::now() + DEADLINE;
    let mut settled = None;
    let mut returned_owners = 0;
    let mut packets = Vec::with_capacity(MAX_PACKETS);
    loop {
        let mut failure = None;
        receiver.receive_segments(MAX_PACKETS, 32, |segments, metadata| {
            let result = (|| {
                ensure(
                    packets.len() < MAX_PACKETS && segments.len() == 1,
                    "metadata RX packet/segment bound",
                )?;
                metadata_validate(segments[0], metadata, case, authority.0, authority.1)?;
                packets.push(segments[0].to_vec());
                Ok::<_, io::Error>(())
            })();
            if let Err(error) = result {
                failure = Some(error);
            }
        })?;
        if let Some(error) = failure {
            return Err(error);
        }
        ensure(
            packets.len() <= children,
            "metadata extra/unexpected admitted child",
        )?;
        receiver.kick()?;
        injector.kick()?;
        injector.complete(|owners| {
            returned_owners += owners.iter().filter(|owner| owner.is_some()).count()
        })?;
        let after = counters(map)?;
        let expected = [
            (SOURCE_HITS, source),
            (SOURCE_REDIRECTS, source),
            (SOURCE_ERRORS, 0),
            (OBSERVED, peer_packets as u64),
            (MATCH_OBSERVED, peer_packets as u64),
            (DROPPED, u64::from(children == 0)),
            (MATCH_DROPPED, u64::from(children == 0)),
            (ADMITTED, children as u64),
        ];
        let mut ready = packets.len() == children;
        for (key, expected) in expected {
            let actual = after[key as usize].checked_sub(before[key as usize]);
            ensure(
                actual.is_some_and(|actual| actual <= expected),
                "metadata source/peer counter bound",
            )?;
            ready &= actual == Some(expected);
        }
        for (position, key) in [METADATA_MISSING, METADATA_MISMATCH]
            .into_iter()
            .enumerate()
        {
            let expected = u64::from(
                matches!(outcome, MetadataObservation::SourceDrop(reason) if reason == key),
            );
            let actual = metadata_counter(map, key)?.checked_sub(reasons[position]);
            ensure(
                actual.is_some_and(|actual| actual <= expected),
                "metadata rejection branch counter bound",
            )?;
            ready &= actual == Some(expected);
        }
        if needs_cq {
            ensure(
                injector.counters().submitted == submitted + 1,
                "metadata Copy TX publication",
            )?;
            ready &= injector.counters().completed == submitted + 1
                && returned_owners == 1
                && injector.outstanding().next().is_none();
        }
        let now = Instant::now();
        if ready {
            let quiet = settled.get_or_insert(now + QUIET);
            if now >= *quiet {
                break;
            }
        }
        ensure(now < end, "metadata source/peer/RX/CQ observation deadline")?;
        std::thread::sleep(Duration::from_millis(1));
    }
    if children != 0 {
        let after = counters(map)?;
        ensure(
            after[SOURCE_COOKIE as usize] == authority.1
                && after[SOURCE_GSO_SIZE as usize] == if case.gso { 64 } else { 0 }
                && (!case.gso || after[SOURCE_GSO_SEGS as usize] == 2),
            "metadata actual source cookie/GSO",
        )?;
        if case.gso {
            ensure(
                packets[0][42..] == packets[1][42..],
                "metadata GSO child payload identity",
            )?;
        }
    }
    eprintln!(
        "Host metadata ID={:#014x} source_payload={} gso={} actual_RX={} matching_peer={} drop={} actual_CQ={needs_cq}",
        case.id,
        case.payload,
        case.gso,
        packets.len(),
        peer_packets,
        children == 0
    );
    Ok(packets)
}

fn metadata_send(sender: &UdpSocket, case: MetadataCase) -> io::Result<()> {
    if case.gso {
        send_segments(sender)
    } else {
        ensure(
            sender.send(&vec![0x5a; case.payload])? == case.payload,
            "plain metadata UDP short submission",
        )
    }
}

fn metadata_case(case: MetadataCase, record_negatives: bool) -> io::Result<()> {
    let links = Links::create()?;
    let devices = [links.indices[0], links.indices[2]];
    let (sender, cookie) = sender(&links.names[0])?;
    let counts = create_map(2, 8, METADATA_COUNTERS, b"hxmi_counts")?;
    let xsks = create_map(17, 4, 1, b"hxmi_sockets")?;
    let facts = create_map(1, METADATA_FACT_BYTES as u32, 1, b"hxmi_facts")?;
    let btf = Btf::from_sys_fs().map_err(io::Error::other)?;
    let mut kfuncs = [0; 2];
    for (slot, name) in kfuncs
        .iter_mut()
        .zip(["bpf_xdp_metadata_rx_vlan_tag", "bpf_xdp_metadata_rx_hash"])
    {
        *slot = btf
            .id_by_type_name_kind(name, BtfKind::Func)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("metadata kfunc BTF {name}: {error}"),
                )
            })?;
        ensure(*slot != 0, "zero metadata kfunc BTF ID")?;
    }
    let mut log = vec![0; 1 << 20];
    let (valid_program, valid_id) = load_producer(
        &metadata_producer(
            case,
            devices,
            cookie,
            counts.as_raw_fd(),
            facts.as_raw_fd(),
            case.id,
            true,
        )?,
        &mut log,
    )?;
    let (guard_program, guard_id) = load_program(
        &metadata_guard(
            case,
            [devices[0], devices[1], links.indices[3]],
            cookie,
            counts.as_raw_fd(),
            [xsks.as_raw_fd(), facts.as_raw_fd()],
            kfuncs,
        )?,
        b"hxmi_guard",
        &mut log,
    )?;
    let guard_link = attach_guard(&guard_program, guard_id, links.indices[3])?;
    let config = PortConfig {
        rx_frames: 16,
        control_frames: 2,
        bulk_frames: 2,
        ring_size: 16,
    };
    let budget = MemoryBudget::new(4 << 20);
    let mut receiver = TestPort::open_device(
        links.indices[3],
        0,
        BindMode::Copy,
        config,
        1500,
        false,
        32,
        &budget,
    )?;
    let mut injector = TestPort::open_device(
        devices[1],
        0,
        BindMode::Copy,
        config,
        1500,
        false,
        0,
        &budget,
    )?;
    ensure(
        !receiver.zerocopy() && !injector.zerocopy(),
        "metadata actual Copy mode",
    )?;
    receiver.refill()?;
    let socket = receiver.as_raw_fd() as u32;
    bpf(
        BPF_MAP_UPDATE_ELEM,
        &mut map_attr(xsks.as_fd(), &0, &socket as *const u32 as u64),
    )?;
    let mut retained_variants = Vec::with_capacity(2);
    let producer_link = if record_negatives {
        let (missing_program, missing_id) = load_producer(
            &metadata_producer(
                case,
                devices,
                cookie,
                counts.as_raw_fd(),
                facts.as_raw_fd(),
                case.id,
                false,
            )?,
            &mut log,
        )?;
        let link = attach_producer(&missing_program, missing_id, devices[0])?;
        ensure(
            metadata_fact_snapshot(&facts)
                .is_err_and(|error| error.raw_os_error() == Some(libc::ENOENT)),
            "missing metadata record precondition",
        )?;
        metadata_observe(
            [&mut receiver, &mut injector],
            &counts,
            case,
            (devices, cookie),
            |_| metadata_send(&sender, case),
            MetadataObservation::SourceDrop(METADATA_MISSING),
        )?;
        ensure(
            metadata_fact_snapshot(&facts)
                .is_err_and(|error| error.raw_os_error() == Some(libc::ENOENT)),
            "missing metadata source unexpectedly published facts",
        )?;
        replace_metadata_producer(
            &link,
            &missing_program,
            &valid_program,
            valid_id,
            devices[0],
        )?;
        retained_variants.push(missing_program);
        link
    } else {
        attach_producer(&valid_program, valid_id, devices[0])?
    };
    require_native(xdp_state(links.indices[3])?, guard_id)?;
    let golden = metadata_observe(
        [&mut receiver, &mut injector],
        &counts,
        case,
        (devices, cookie),
        |_| metadata_send(&sender, case),
        MetadataObservation::Positive,
    )?
    .remove(0);
    let observed_segs =
        u32::try_from(counters(&counts)?[SOURCE_GSO_SEGS as usize]).map_err(io::Error::other)?;
    let record = metadata_fact_snapshot(&facts)?;
    ensure(
        record == metadata_record(case, devices, cookie, observed_segs),
        "actual immutable source fact snapshot",
    )?;
    if record_negatives {
        let mismatch = case.id ^ (1 << 33);
        ensure(
            mismatch != 0 && mismatch < (1 << 48) && mismatch as u32 == case.id as u32,
            "valid full-ID mismatch precondition",
        )?;
        let (mismatch_program, mismatch_id) = load_producer(
            &metadata_producer(
                case,
                devices,
                cookie,
                counts.as_raw_fd(),
                facts.as_raw_fd(),
                mismatch,
                true,
            )?,
            &mut log,
        )?;
        replace_metadata_producer(
            &producer_link,
            &valid_program,
            &mismatch_program,
            mismatch_id,
            devices[0],
        )?;
        metadata_observe(
            [&mut receiver, &mut injector],
            &counts,
            case,
            (devices, cookie),
            |_| metadata_send(&sender, case),
            MetadataObservation::SourceDrop(METADATA_MISMATCH),
        )?;
        ensure(
            metadata_fact_snapshot(&facts)? == record,
            "full-ID mismatch changed live facts",
        )?;
        replace_metadata_producer(
            &producer_link,
            &mismatch_program,
            &valid_program,
            valid_id,
            devices[0],
        )?;
        retained_variants.push(mismatch_program);
        metadata_observe(
            [&mut receiver, &mut injector],
            &counts,
            case,
            (devices, cookie),
            |_| metadata_send(&sender, case),
            MetadataObservation::Positive,
        )?;
    }
    for (label, bypass) in [("AF_PACKET", false), ("PACKET_QDISC_BYPASS", true)] {
        metadata_observe(
            [&mut receiver, &mut injector],
            &counts,
            case,
            (devices, cookie),
            |_| send_packet(devices[1], &golden, bypass),
            MetadataObservation::RawDrop(false),
        )?;
        eprintln!(
            "Host metadata raw negative {label}: actual matching peer DROP and zero admission/RX"
        );
    }
    metadata_observe(
        [&mut receiver, &mut injector],
        &counts,
        case,
        (devices, cookie),
        |port| {
            ensure(
                port.transmit_generated(TxClass::Bulk, golden.len(), |output| {
                    output.copy_from_slice(&golden);
                    Ok(Some((golden.len(), 1)))
                })?,
                "metadata Copy negative was not published",
            )
        },
        MetadataObservation::RawDrop(true),
    )?;
    let mut inline = Vec::with_capacity(golden.len() + 4);
    inline.extend_from_slice(&golden[..12]);
    inline.extend_from_slice(&0x8100u16.to_be_bytes());
    inline.extend_from_slice(&((case.id >> 32) as u16).to_be_bytes());
    inline.extend_from_slice(&golden[12..]);
    metadata_observe(
        [&mut receiver, &mut injector],
        &counts,
        case,
        (devices, cookie),
        |_| send_packet(devices[1], &inline, false),
        MetadataObservation::RawDrop(false),
    )?;
    metadata_observe(
        [&mut receiver, &mut injector],
        &counts,
        case,
        (devices, cookie),
        |_| metadata_send(&sender, case),
        MetadataObservation::Positive,
    )?;
    ensure(
        metadata_fact_snapshot(&facts)? == record,
        "immutable metadata facts changed across sends",
    )?;
    drop(sender);
    drop(producer_link);
    ensure(
        chain(devices[0], BPF_TCX_EGRESS)?.is_empty(),
        "metadata source admission remains",
    )?;
    drain(&mut receiver)?;
    drain(&mut injector)?;
    bpf(BPF_MAP_DELETE_ELEM, &mut map_attr(xsks.as_fd(), &0, 0))?;
    receiver.close_socket();
    injector.close_socket();
    ensure(
        receiver.as_raw_fd() == -1 && injector.as_raw_fd() == -1,
        "metadata sockets remain open",
    )?;
    drop(guard_link);
    ensure(xdp_absent(links.indices[3])?, "metadata native XDP remains")?;
    drop((
        receiver,
        injector,
        retained_variants,
        valid_program,
        guard_program,
        xsks,
        facts,
        counts,
    ));
    ensure(
        command("ethtool", &["-k", &links.names[0]])? == links.source_features,
        "metadata changed source offloads",
    )?;
    links.remove()
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_private_host_metadata_identifier() {
    require_vm();
    for (position, case) in [
        MetadataCase {
            id: 0x0001_0000_0000,
            payload: 64,
            gso: false,
        },
        MetadataCase {
            id: 0x0000_ffff_ffff,
            payload: 128,
            gso: true,
        },
        MetadataCase {
            id: 0x0001_0000_0000,
            payload: 1472,
            gso: false,
        },
        MetadataCase {
            id: 0xfedc_89ab_cdef,
            payload: 64,
            gso: false,
        },
    ]
    .into_iter()
    .enumerate()
    {
        metadata_case(case, position == 0)
            .expect("Host metadata primitive failed; preserve guest verifier/runtime output and failure custody");
    }
    println!("PASS: private Host metadata identifier");
}

mod reverse;

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_private_host_reverse_input() {
    require_vm();
    reverse::exercise().expect(
        "Host reverse primitive failed; wrapper retains both namespace pins until VM poweroff",
    );
    println!("PASS: private Host reverse input");
}
