use super::*;
use aya_obj::generated::bpf_insn;
use honk_ebpf_common::xdp_gateway::{
    CaptureRealmKey, FRAGMENT_TTL_NS, FragmentKey, FragmentVerdict, GATEWAY_DNS_BITMAP_OFFSET,
    GATEWAY_DNS_READY, GATEWAY_ROUTE_NEED_DNS, GatewayDnsKey, GatewayDnsValue, GatewayHold,
    GatewayKey, GatewayReason, HOLD_REFRESH_NS, LocalAddressKey,
};
use honk_ebpf_common::{DATAPATH_FLAG_OFFLOAD_ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT};
use honk_ebpf_common::{IpVersionType, L4ProtoType, RoutingInput};
use std::os::fd::FromRawFd;

mod ownership;

struct Fixture {
    maps: GatewayMaps,
    ct: ConntrackKfuncs,
    counters: OwnedFd,
    xsks: OwnedFd,
}

impl Fixture {
    fn new() -> Self {
        require_vm();
        assert!(matches!(
            std::env::var("HONK_CI_VM_LANE").as_deref(),
            Ok("floor" | "recent")
        ));
        assert_eq!(
            std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap()
                .trim(),
            std::env::var("HONK_CI_EXPECTED_KERNEL").unwrap()
        );
        let maps = GatewayMaps::new(
            &[(
                CaptureRealmKey {
                    physical_ifindex: 1,
                    ..CaptureRealmKey::default()
                },
                7,
            )],
            &[],
        )
        .unwrap();
        maps.set_mode_flags(DATAPATH_FLAG_OFFLOAD_RULE_DIRECT)
            .unwrap();
        Self {
            maps,
            ct: ConntrackKfuncs::read().unwrap(),
            counters: create_map(2, 8, 5, b"honk_gw_test_c").unwrap(),
            xsks: create_map(17, 4, 1, b"honk_gw_test_x").unwrap(),
        }
    }

    fn load(&self, terminal_direct: bool) -> OwnedFd {
        // These terminal bodies isolate caller behavior; canonical routing differentials live in core.
        let routing = [
            instruction(MOV_K, 0, 0, 0, i32::from(terminal_direct)),
            instruction(EXIT, 0, 0, 0, 0),
        ];
        let mut program = build_gateway(
            &capture(),
            &[],
            1,
            self.counters.as_raw_fd(),
            self.xsks.as_raw_fd(),
            true,
            None,
            &GatewayLoad {
                routing: &routing,
                maps: &self.maps,
                conntrack: Some(&self.ct),
                dns: None,
                arbitration: None,
            },
        )
        .unwrap();
        program.kfunc_btf = self
            .ct
            .btf
            .as_ref()
            .map(OwnedFd::try_clone)
            .transpose()
            .unwrap();
        load_program(&program, b"honk_gw_test", &mut vec![0; 4 << 20])
            .unwrap()
            .0
    }

    fn stat(&self, reason: GatewayReason) -> u64 {
        let cpus = crate::bpf::gateway::possible_cpu_count(
            &std::fs::read_to_string("/sys/devices/system/cpu/possible").unwrap(),
        )
        .unwrap();
        let mut values = vec![0u64; cpus];
        get(
            self.maps.stats.as_fd(),
            &(reason as u32),
            values.as_mut_ptr() as u64,
        );
        values.iter().sum()
    }

    fn scratch(&self) -> Vec<[u64; 64]> {
        let cpus = crate::bpf::gateway::possible_cpu_count(
            &std::fs::read_to_string("/sys/devices/system/cpu/possible").unwrap(),
        )
        .unwrap();
        let mut values = vec![[0u64; 64]; cpus];
        get(self.maps.scratch.as_fd(), &0u32, values.as_mut_ptr() as u64);
        values
    }

    fn input(&self, source_port: u32) -> RoutingInput {
        self.scratch()
            .iter()
            .find_map(|scratch| {
                assert_eq!(
                    scratch[0], 0,
                    "scratch busy must be released after the real BPF call"
                );
                // SAFETY: the 512-byte, eight-byte-aligned map value contains a complete numeric input at 8.
                let input = unsafe {
                    std::ptr::read(scratch.as_ptr().cast::<u8>().add(8).cast::<RoutingInput>())
                };
                (input.src_port == source_port).then_some(input)
            })
            .expect("canonical input was not populated by the packet emitter")
    }
}

fn instruction(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> bpf_insn {
    bpf_insn {
        code,
        _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
        off,
        imm,
    }
}

fn get<K>(fd: BorrowedFd<'_>, key: &K, value: u64) {
    bpf(
        BPF_MAP_LOOKUP_ELEM,
        &mut MapElemAttr {
            map_fd: fd.as_raw_fd() as u32,
            reserved: 0,
            key: key as *const K as u64,
            value,
            flags: 0,
        },
    )
    .unwrap();
}

fn put<K, V>(fd: BorrowedFd<'_>, key: &K, value: &V) {
    bpf(
        BPF_MAP_UPDATE_ELEM,
        &mut MapElemAttr {
            map_fd: fd.as_raw_fd() as u32,
            reserved: 0,
            key: key as *const K as u64,
            value: value as *const V as u64,
            flags: 0,
        },
    )
    .unwrap();
}

fn remove<K>(fd: BorrowedFd<'_>, key: &K) {
    bpf(
        BPF_MAP_DELETE_ELEM,
        &mut MapElemAttr {
            map_fd: fd.as_raw_fd() as u32,
            reserved: 0,
            key: key as *const K as u64,
            value: 0,
            flags: 0,
        },
    )
    .unwrap();
}

fn now() -> u64 {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) },
        0
    );
    let time = unsafe { time.assume_init() };
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

fn tuple_key(source: SocketAddr, destination: SocketAddr, proto: u8) -> GatewayKey {
    let mapped = |address| match address {
        IpAddr::V4(address) => address.to_ipv6_mapped().octets(),
        IpAddr::V6(address) => address.octets(),
    };
    GatewayKey {
        realm_id: 7,
        family: if source.is_ipv6() { 6 } else { 4 },
        src: mapped(source.ip()),
        dst: mapped(destination.ip()),
        sport: source.port().to_be(),
        dport: destination.port().to_be(),
        proto,
        reserved: [0; 3],
    }
}

fn udp(port: u16) -> (GatewayKey, Vec<u8>) {
    let source = SocketAddr::from(([192, 0, 2, 1], port));
    let destination = "198.51.100.1:443".parse().unwrap();
    (
        tuple_key(source, destination, 17),
        packet(source, destination, [2, 0, 0, 0, 0, 1], 0),
    )
}

fn tcp(port: u16, flags: u8) -> (GatewayKey, Vec<u8>) {
    let (mut key, mut frame) = udp(port);
    key.proto = 6;
    frame[16..18].copy_from_slice(&40u16.to_be_bytes());
    frame[23] = 6;
    frame[38..54].fill(0);
    frame[46] = 5 << 4;
    frame[47] = flags;
    ipv4_checksum(&mut frame, 20);
    (key, frame)
}

fn ipv4_checksum(frame: &mut [u8], header: usize) {
    frame[24..26].fill(0);
    let sum = checksum(&frame[14..14 + header]);
    frame[24..26].copy_from_slice(&sum.to_be_bytes());
}

fn ipv4_fragment(frame: &mut [u8], id: u16, offset: u16) {
    frame[18..20].copy_from_slice(&id.to_be_bytes());
    frame[20..22].copy_from_slice(&offset.to_be_bytes());
    let header = usize::from(frame[14] & 15) * 4;
    ipv4_checksum(frame, header);
}

fn fragment_key(key: GatewayKey, id: u32) -> FragmentKey {
    FragmentKey {
        realm_id: key.realm_id,
        family: key.family,
        src: key.src,
        dst: key.dst,
        id,
        proto: if key.family == 6 { 0 } else { key.proto },
        reserved: [0; 3],
    }
}

fn reverse(key: GatewayKey) -> GatewayKey {
    GatewayKey {
        src: key.dst,
        dst: key.src,
        sport: key.dport,
        dport: key.sport,
        ..key
    }
}

fn address(bytes: [u8; 16], family: u32) -> IpAddr {
    if family == 4 {
        IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
    } else {
        IpAddr::V6(bytes.into())
    }
}

fn frame_for(key: GatewayKey) -> Vec<u8> {
    packet(
        SocketAddr::new(address(key.src, key.family), u16::from_be(key.sport)),
        SocketAddr::new(address(key.dst, key.family), u16::from_be(key.dport)),
        [2, 0, 0, 0, 0, 1],
        0,
    )
}

fn icmp_quote(quoted: GatewayKey) -> Vec<u8> {
    let mut inner = frame_for(quoted);
    if quoted.family == 4 {
        inner[23] = quoted.proto;
        ipv4_checksum(&mut inner, 20);
    } else {
        inner[20] = quoted.proto;
    }
    let mut frame = frame_for(reverse(quoted));
    let header = if quoted.family == 4 { 20 } else { 40 };
    let start = 14 + header;
    let end = start + 8 + header + 8;
    frame.resize(end, 0);
    frame[start..start + 8].fill(0);
    frame[start + 8..].copy_from_slice(&inner[14..14 + header + 8]);
    if quoted.family == 4 {
        frame[23] = 1;
        frame[16..18].copy_from_slice(&((end - 14) as u16).to_be_bytes());
        frame[start] = 3;
        frame[start + 1] = 4;
        let sum = checksum(&frame[start..]);
        frame[start + 2..start + 4].copy_from_slice(&sum.to_be_bytes());
        ipv4_checksum(&mut frame, header);
    } else {
        frame[20] = 58;
        frame[18..20].copy_from_slice(&((end - start) as u16).to_be_bytes());
        frame[start] = 2;
        let mut pseudo = frame[22..54].to_vec();
        pseudo.extend_from_slice(&((end - start) as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 58]);
        pseudo.extend_from_slice(&frame[start..]);
        let sum = checksum(&pseudo);
        frame[start + 2..start + 4].copy_from_slice(&sum.to_be_bytes());
    }
    frame
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_g17_tcp_non_syn_miss_and_monotonic_hold_refresh() {
    let fixture = Fixture::new();
    let program = fixture.load(false);
    let (key, mut ack) = tcp(43001, 0x10);
    assert_eq!(run(&program, &ack, 0).0, XDP_PASS as u32);
    assert_eq!(fixture.stat(GatewayReason::PassTcpNonSynMiss), 1);
    assert_eq!(fixture.stat(GatewayReason::D1Evaluated), 0);
    assert_eq!(fixture.maps.lookup_hold(&key).unwrap(), None);
    let (_, syn) = tcp(43001, 2);
    assert_eq!(run(&program, &syn, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::D1Evaluated), 1);
    let first = fixture.maps.lookup_hold(&key).unwrap().unwrap();
    assert_eq!(first.stamp, first.last_seen_ns);
    ack[15] = 46 << 2;
    ack[6..12].copy_from_slice(&[2, 8, 7, 6, 5, 4]);
    ipv4_checksum(&mut ack, 20);
    let before = now();
    let old = GatewayHold {
        stamp: first.stamp,
        last_seen_ns: past_time(2 * HOLD_REFRESH_NS),
    };
    put(fixture.maps.hold.as_fd(), &key, &old);
    assert_eq!(run(&program, &ack, 0).0, XDP_DROP as u32);
    let refreshed = fixture.maps.lookup_hold(&key).unwrap().unwrap();
    assert_eq!(refreshed.stamp, old.stamp);
    assert!(refreshed.last_seen_ns >= before);
    assert_eq!(fixture.stat(GatewayReason::D1Evaluated), 1);
    let before = now();
    assert_eq!(run(&program, &ack, 0).0, XDP_DROP as u32);
    assert!(
        now() - before < HOLD_REFRESH_NS / 2,
        "VM paused across the refresh interval"
    );
    assert_eq!(fixture.maps.lookup_hold(&key).unwrap().unwrap(), refreshed);
    assert_eq!(
        fixture
            .maps
            .retire_if_unretained(now(), std::time::Duration::from_secs(30), None, |_| false)
            .unwrap(),
        0
    );
    assert_eq!(fixture.maps.lookup_hold(&key).unwrap(), Some(refreshed));
    let future = GatewayHold {
        last_seen_ns: now() + 60 * HOLD_REFRESH_NS,
        ..refreshed
    };
    put(fixture.maps.hold.as_fd(), &key, &future);
    assert_eq!(run(&program, &ack, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.maps.lookup_hold(&key).unwrap().unwrap(), future);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 3);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_local_then_hold_then_real_conntrack_and_reverse_quote() {
    let fixture = Fixture::new();
    let program = fixture.load(false);
    let (key, frame) = udp(43002);
    fixture.maps.insert_hold(&key, now()).unwrap();
    insert_conntrack(key);
    fixture
        .maps
        .replace_local_addresses(&[LocalAddressKey {
            family: key.family,
            address: key.dst,
        }])
        .unwrap();
    assert_eq!(run(&program, &frame, 0).0, XDP_PASS as u32);
    assert_eq!(fixture.stat(GatewayReason::PassLocal), 1);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 0);
    fixture.maps.replace_local_addresses(&[]).unwrap();
    assert_eq!(run(&program, &frame, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 1);
    assert_eq!(fixture.stat(GatewayReason::PassCtOriginal), 0);
    let quote = icmp_quote(reverse(key));
    assert_eq!(run(&program, &quote, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 2);
    remove(fixture.maps.hold.as_fd(), &key);
    assert_eq!(run(&program, &frame, 0).0, XDP_PASS as u32);
    assert_eq!(fixture.stat(GatewayReason::PassCtOriginal), 1);
    assert_eq!(
        run(&program, &frame_for(reverse(key)), 0).0,
        XDP_PASS as u32
    );
    assert_eq!(fixture.stat(GatewayReason::PassCtReply), 1);
    assert_eq!(run(&program, &quote, 0).0, XDP_PASS as u32);
    assert_eq!(fixture.stat(GatewayReason::PassCtOriginal), 2);
    assert_eq!(fixture.stat(GatewayReason::D1Evaluated), 0);
    let source = "[2001:db8::31]:43002".parse().unwrap();
    let destination = "[2001:db8::32]:443".parse().unwrap();
    let key6 = tuple_key(source, destination, 17);
    fixture.maps.insert_hold(&key6, now()).unwrap();
    insert_conntrack(key6);
    let quote6 = icmp_quote(reverse(key6));
    assert_eq!(run(&program, &quote6, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 3);
    remove(fixture.maps.hold.as_fd(), &key6);
    assert_eq!(run(&program, &quote6, 0).0, XDP_PASS as u32);
    assert_eq!(fixture.stat(GatewayReason::PassCtOriginal), 3);
    assert_eq!(
        run(&program, &frame_for(reverse(key6)), 0).0,
        XDP_PASS as u32
    );
    assert_eq!(fixture.stat(GatewayReason::PassCtReply), 2);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_g02_non_transport_quotes_pass() {
    let fixture = Fixture::new();
    let program = fixture.load(false);
    let (key4, _) = udp(43300);
    let key6 = tuple_key(
        "[2001:db8::41]:43300".parse().unwrap(),
        "[2001:db8::42]:443".parse().unwrap(),
        17,
    );
    for key in [key4, key6] {
        for proto in [47, 50] {
            let quoted = GatewayKey { proto, ..key };
            assert_eq!(run(&program, &icmp_quote(quoted), 0).0, XDP_PASS as u32);
        }
    }
    assert_eq!(fixture.stat(GatewayReason::PassNonTransport), 4);
    assert_eq!(fixture.stat(GatewayReason::IcmpQuoteUnresolved), 0);
    assert_eq!(fixture.stat(GatewayReason::D1Evaluated), 0);
    let mut redirects = 0u64;
    get(
        fixture.counters.as_fd(),
        &0u32,
        &mut redirects as *mut _ as u64,
    );
    assert_eq!(redirects, 0);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_g02_dnat_reverse_quote_ct_alias_miss_selects_xsk() {
    let fixture = Fixture::new();
    let program = fixture.load(false);
    let original = tuple_key(
        "192.0.2.41:43301".parse().unwrap(),
        "198.51.100.41:443".parse().unwrap(),
        17,
    );
    let reply = tuple_key(
        "192.0.2.42:8443".parse().unwrap(),
        "192.0.2.41:43301".parse().unwrap(),
        17,
    );
    insert_conntrack_aliases(original, reply);
    assert_eq!(run(&program, &frame_for(original), 0).0, XDP_PASS as u32);
    assert_eq!(run(&program, &frame_for(reply), 0).0, XDP_PASS as u32);
    assert_eq!(fixture.stat(GatewayReason::PassCtOriginal), 1);
    assert_eq!(fixture.stat(GatewayReason::PassCtReply), 1);
    let lookup = reverse(reply);
    assert_ne!(lookup, original);
    assert_ne!(lookup, reply);
    assert_eq!(fixture.maps.lookup_hold(&lookup).unwrap(), None);
    // The real CT aliases model DNAT; only the smoke proves NAT execution and PTB wire direction.
    assert_eq!(run(&program, &icmp_quote(reply), 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::IcmpQuoteUnresolved), 1);
    assert_eq!(fixture.stat(GatewayReason::PassCtOriginal), 1);
    assert_eq!(fixture.stat(GatewayReason::PassCtReply), 1);
    assert_eq!(fixture.stat(GatewayReason::D1Evaluated), 0);
    let mut redirects = 0u64;
    get(
        fixture.counters.as_fd(),
        &0u32,
        &mut redirects as *mut _ as u64,
    );
    assert_eq!(redirects, 1, "empty XSK map drops the selected XSK path");
    assert_eq!(fixture.maps.lookup_hold(&lookup).unwrap(), None);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
/// Test-run payload scattering does not prove a physical first-buffer boundary; smoke owns real SG.
fn kernel_gateway_g12_ihl_and_required_prefix_test_run_not_physical_sg() {
    let fixture = Fixture::new();
    let program = fixture.load(false);
    let (zero_key, zero_payload) = udp(43003);
    assert_eq!(run(&program, &zero_payload, 0).0, XDP_DROP as u32);
    assert!(fixture.maps.lookup_hold(&zero_key).unwrap().is_some());
    for ihl in 5u8..=15 {
        let (options_key, mut options) = udp(43400 + u16::from(ihl));
        let extra = usize::from(ihl - 5) * 4;
        options.splice(34..34, std::iter::repeat_n(1u8, extra));
        options[14] = 0x40 | ihl;
        options[16..18].copy_from_slice(&((28 + extra) as u16).to_be_bytes());
        ipv4_checksum(&mut options, usize::from(ihl) * 4);
        assert_eq!(run(&program, &options, 0).0, XDP_DROP as u32, "IHL={ihl}");
        assert!(fixture.maps.lookup_hold(&options_key).unwrap().is_some());
        assert_eq!(
            fixture.input(43400 + u32::from(ihl)).l4proto,
            L4ProtoType::Udp as u32
        );
    }
    let (sg_key, mut sg) = udp(43005);
    sg.resize(9014, 0);
    sg[16..18].copy_from_slice(&9000u16.to_be_bytes());
    sg[38..40].copy_from_slice(&8980u16.to_be_bytes());
    ipv4_checksum(&mut sg, 20);
    let (action, metadata, received) = run(&program, &sg, 0);
    assert_eq!(action, XDP_DROP as u32);
    assert!(metadata.is_empty());
    assert_eq!(received, sg);
    assert!(fixture.maps.lookup_hold(&sg_key).unwrap().is_some());
    assert_eq!(fixture.stat(GatewayReason::UnclassifiableHeader), 0);
    let (short_key, mut short) = tcp(43006, 2);
    fixture.maps.insert_hold(&short_key, now()).unwrap();
    short.truncate(14 + 20 + 13);
    short[16..18].copy_from_slice(&33u16.to_be_bytes());
    ipv4_fragment(&mut short, 101, 0x2000);
    assert_eq!(run(&program, &short, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::UnclassifiableHeader), 1);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 0);
    let (_, mut first_prefix) = tcp(43006, 2);
    first_prefix.truncate(14 + 20 + 16);
    first_prefix[16..18].copy_from_slice(&36u16.to_be_bytes());
    ipv4_fragment(&mut first_prefix, 101, 0x2000);
    assert_eq!(run(&program, &first_prefix, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 1);
    assert_eq!(fixture.stat(GatewayReason::UnclassifiableHeader), 1);
    let (_, mut short_options) = udp(43416);
    short_options.splice(34..34, [1u8; 40]);
    short_options[14] = 0x4f;
    short_options.truncate(14 + 59);
    short_options[16..18].copy_from_slice(&59u16.to_be_bytes());
    assert_eq!(run(&program, &short_options, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::UnclassifiableHeader), 2);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_fragment_verdict_ttl_and_post_hold_late_fragment() {
    let fixture = Fixture::new();
    let program = fixture.load(false);
    let (key, mut first) = udp(43007);
    fixture
        .maps
        .replace_local_addresses(&[LocalAddressKey {
            family: key.family,
            address: key.dst,
        }])
        .unwrap();
    ipv4_fragment(&mut first, 102, 0x2000);
    assert_eq!(run(&program, &first, 0).0, XDP_PASS as u32);
    let mut later = first.clone();
    ipv4_fragment(&mut later, 102, 1);
    later[34..42].fill(0xff);
    fixture.maps.replace_local_addresses(&[]).unwrap();
    assert_eq!(run(&program, &later, 0).0, XDP_PASS as u32);
    assert_eq!(fixture.stat(GatewayReason::PassFragment), 1);
    let id = u16::from_ne_bytes(102u16.to_be_bytes()) as u32;
    let fragment = fragment_key(key, id);
    let mut verdict = FragmentVerdict::default();
    get(
        fixture.maps.fragments.as_fd(),
        &fragment,
        &mut verdict as *mut _ as u64,
    );
    let original_time = verdict.ktime_ns;
    assert_eq!(run(&program, &later, 0).0, XDP_PASS as u32);
    get(
        fixture.maps.fragments.as_fd(),
        &fragment,
        &mut verdict as *mut _ as u64,
    );
    assert_eq!(verdict.ktime_ns, original_time);
    verdict.ktime_ns = past_time(FRAGMENT_TTL_NS + 1);
    put(fixture.maps.fragments.as_fd(), &fragment, &verdict);
    assert_eq!(run(&program, &later, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::FragmentMiss), 1);
    ipv4_fragment(&mut first, 103, 0x2000);
    assert_eq!(run(&program, &first, 0).0, XDP_DROP as u32);
    remove(fixture.maps.hold.as_fd(), &key);
    ipv4_fragment(&mut later, 103, 1);
    assert_eq!(run(&program, &later, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::XskFragment), 1);
    assert_eq!(fixture.stat(GatewayReason::D1Evaluated), 1);
    ipv4_fragment(&mut later, 104, 1);
    assert_eq!(run(&program, &later, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::FragmentMiss), 2);
}

fn v6_extensions(port: u16, protocols: &[u8], lengths: &[usize]) -> (GatewayKey, Vec<u8>) {
    let source = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], port));
    let destination = "[2001:db8::2]:443".parse().unwrap();
    let mut frame = packet(source, destination, [2, 0, 0, 0, 0, 1], 0);
    let payload: usize = lengths.iter().sum::<usize>() + 8;
    frame.resize(14 + 40 + payload, 0);
    frame[54..].fill(0);
    frame[18..20].copy_from_slice(&(payload as u16).to_be_bytes());
    frame[20] = *protocols.first().unwrap_or(&17);
    let mut offset = 54;
    for (index, protocol) in protocols.iter().enumerate() {
        frame[offset] = protocols.get(index + 1).copied().unwrap_or(17);
        if *protocol == 44 {
            frame[offset + 3] = 1;
            frame[offset + 4..offset + 8].copy_from_slice(&105u32.to_be_bytes());
        } else {
            frame[offset + 1] = (lengths[index] / 8 - 1) as u8;
        }
        offset += lengths[index];
    }
    frame[offset..offset + 2].copy_from_slice(&source.port().to_be_bytes());
    frame[offset + 2..offset + 4].copy_from_slice(&443u16.to_be_bytes());
    frame[offset + 4..offset + 6].copy_from_slice(&8u16.to_be_bytes());
    (tuple_key(source, destination, 17), frame)
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_g12_ipv6_fragment_then_destination_options_and_extension_bounds() {
    let fixture = Fixture::new();
    let program = fixture.load(false);
    let (key, frame) = v6_extensions(43008, &[44, 60], &[8, 8]);
    assert_eq!(&frame[54..62], &[60, 0, 0, 1, 0, 0, 0, 105]);
    assert_eq!(run(&program, &frame, 0).0, XDP_DROP as u32);
    assert!(fixture.maps.lookup_hold(&key).unwrap().is_some());
    let mut verdict = FragmentVerdict::default();
    get(
        fixture.maps.fragments.as_fd(),
        &fragment_key(key, u32::from_ne_bytes(105u32.to_be_bytes())),
        &mut verdict as *mut _ as u64,
    );
    assert_eq!(verdict.verdict, 4);
    let mut later = frame[..62].to_vec();
    later[18..20].copy_from_slice(&8u16.to_be_bytes());
    later[56..58].copy_from_slice(&8u16.to_be_bytes());
    assert_eq!(run(&program, &later, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::XskFragment), 1);
    let (chain_key, chain) = v6_extensions(43417, &[0, 43, 44, 60], &[8, 8, 8, 8]);
    assert_eq!(run(&program, &chain, 0).0, XDP_DROP as u32);
    assert!(fixture.maps.lookup_hold(&chain_key).unwrap().is_some());
    assert_eq!(fixture.input(43417).l4proto, L4ProtoType::Udp as u32);
    let (bounded_key, bounded) = v6_extensions(43009, &[60; 8], &[32; 8]);
    assert_eq!(run(&program, &bounded, 0).0, XDP_DROP as u32);
    assert!(fixture.maps.lookup_hold(&bounded_key).unwrap().is_some());
    let (ninth_key, ninth) = v6_extensions(43010, &[60; 9], &[8; 9]);
    assert_eq!(run(&program, &ninth, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.maps.lookup_hold(&ninth_key).unwrap(), None);
    let (_, over_bytes) = v6_extensions(43011, &[60, 60], &[256, 8]);
    assert_eq!(run(&program, &over_bytes, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::UnclassifiableHeader), 2);
    let (atomic_key, mut atomic) = v6_extensions(43012, &[44, 60], &[8, 8]);
    atomic[57] = 0;
    atomic[58..62].copy_from_slice(&106u32.to_be_bytes());
    assert_eq!(run(&program, &atomic, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::XskNewFlow), 4);
    assert_eq!(fixture.stat(GatewayReason::PassNonTransport), 0);
    let atomic_fragment = fragment_key(atomic_key, u32::from_ne_bytes(106u32.to_be_bytes()));
    let error = bpf(
        BPF_MAP_LOOKUP_ELEM,
        &mut MapElemAttr {
            map_fd: fixture.maps.fragments.as_raw_fd() as u32,
            reserved: 0,
            key: &atomic_fragment as *const _ as u64,
            value: &mut verdict as *mut _ as u64,
            flags: 0,
        },
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
    let mut nd = packet(
        "[2001:db8::1]:1000".parse().unwrap(),
        "[ff02::1]:1000".parse().unwrap(),
        [0x33, 0x33, 0, 0, 0, 1],
        0,
    );
    nd[20] = 58;
    nd[54] = 135;
    nd[55] = 0;
    assert_eq!(run(&program, &nd, 0).0, XDP_DROP as u32);
    nd[21] = 255;
    assert_eq!(run(&program, &nd, 0).0, XDP_PASS as u32);
    nd[55] = 1;
    assert_eq!(run(&program, &nd, 0).0, XDP_DROP as u32);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_canonical_call_input_and_runtime_rule_permission() {
    let fixture = Fixture::new();
    let program = fixture.load(false);
    for (index, flags) in [
        DATAPATH_FLAG_OFFLOAD_RULE_DIRECT,
        DATAPATH_FLAG_OFFLOAD_ALL,
        0,
    ]
    .into_iter()
    .enumerate()
    {
        fixture.maps.set_mode_flags(flags).unwrap();
        let (_, mut frame) = udp(43100 + index as u16);
        frame[15] = 46 << 2;
        ipv4_checksum(&mut frame, 20);
        assert_eq!(run(&program, &frame, 0).0, XDP_DROP as u32);
        let input = fixture.input(43100 + index as u32);
        assert_eq!(&input.mac[10..], &[2, 0, 0, 0, 0, 2]);
        assert_eq!(&input.mac[..10], &[0; 10]);
        assert_eq!(input.dst_port, 443);
        assert_eq!(input.l4proto, L4ProtoType::Udp as u32);
        assert_eq!(input.ip_version, IpVersionType::V4 as u32);
        assert_eq!(input.dscp, 46);
        assert_eq!(
            input.flags,
            1 | if flags == DATAPATH_FLAG_OFFLOAD_RULE_DIRECT {
                2
            } else {
                0
            }
        );
    }
    let (_, tcp4) = tcp(43103, 2);
    let source6 = "[2001:db8::1]:43104".parse().unwrap();
    let destination6 = "[2001:db8::2]:443".parse().unwrap();
    let udp6 = packet(source6, destination6, [2, 0, 0, 0, 0, 1], 0);
    let mut tcp6 = packet(
        "[2001:db8::1]:43105".parse().unwrap(),
        destination6,
        [2, 0, 0, 0, 0, 1],
        0,
    );
    tcp6.resize(74, 0);
    tcp6[18..20].copy_from_slice(&20u16.to_be_bytes());
    tcp6[20] = 6;
    tcp6[58..74].fill(0);
    tcp6[66] = 5 << 4;
    tcp6[67] = 2;
    for (frame, port, protocol, version) in [
        (tcp4, 43103, L4ProtoType::Tcp, IpVersionType::V4),
        (udp6, 43104, L4ProtoType::Udp, IpVersionType::V6),
        (tcp6, 43105, L4ProtoType::Tcp, IpVersionType::V6),
    ] {
        assert_eq!(run(&program, &frame, 0).0, XDP_DROP as u32);
        let input = fixture.input(port);
        assert_eq!(input.l4proto, protocol as u32);
        assert_eq!(input.ip_version, version as u32);
    }
    let direct = fixture.load(true);
    let (_, syn) = tcp(43110, 2);
    assert_eq!(run(&direct, &syn, 0).0, XDP_PASS as u32);
    assert_eq!(fixture.stat(GatewayReason::PassD1), 1);
}

fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() + 4;
    let mut bytes = Vec::with_capacity((length + 3) & !3);
    bytes.extend_from_slice(&(length as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize((length + 3) & !3, 0);
    bytes
}

fn ct_tuple(key: GatewayKey) -> Vec<u8> {
    let mut ip = Vec::new();
    let (source, destination, start) = if key.family == 4 {
        (1, 2, 12)
    } else {
        (3, 4, 0)
    };
    ip.extend(attr(source, &key.src[start..]));
    ip.extend(attr(destination, &key.dst[start..]));
    let mut protocol = attr(1, &[key.proto]);
    protocol.extend(attr(2, &key.sport.to_ne_bytes()));
    protocol.extend(attr(3, &key.dport.to_ne_bytes()));
    let mut tuple = attr(1 | 0x8000, &ip);
    tuple.extend(attr(2 | 0x8000, &protocol));
    tuple
}

fn insert_conntrack(key: GatewayKey) {
    insert_conntrack_aliases(key, reverse(key));
}

fn insert_conntrack_aliases(key: GatewayKey, reply: GatewayKey) {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        )
    };
    assert!(raw >= 0, "{}", io::Error::last_os_error());
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut body = vec![
        if key.family == 4 {
            libc::AF_INET as u8
        } else {
            libc::AF_INET6 as u8
        },
        0,
        0,
        0,
    ];
    body.extend(attr(1 | 0x8000, &ct_tuple(key)));
    body.extend(attr(2 | 0x8000, &ct_tuple(reply)));
    // ctnetlink confirms the new entry before applying CTA_STATUS, which cannot clear CONFIRMED.
    let status = (1u32 << 1) | (1u32 << 3); // IPS_SEEN_REPLY | IPS_CONFIRMED
    body.extend(attr(3, &status.to_be_bytes()));
    body.extend(attr(7, &300u32.to_be_bytes()));
    let mut message = Vec::new();
    message.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    message.extend_from_slice(&0x100u16.to_ne_bytes());
    message.extend_from_slice(&(1u16 | 4 | 0x200 | 0x400).to_ne_bytes());
    message.extend_from_slice(&1u32.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend(body);
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    assert_eq!(
        unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
                std::ptr::from_ref(&kernel).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        },
        message.len() as isize,
        "{}",
        io::Error::last_os_error()
    );
    let mut reply = [0u8; 4096];
    let length = unsafe { libc::recv(fd.as_raw_fd(), reply.as_mut_ptr().cast(), reply.len(), 0) };
    assert!(length >= 20, "{}", io::Error::last_os_error());
    assert_eq!(u16::from_ne_bytes(reply[4..6].try_into().unwrap()), 2);
    assert_eq!(
        i32::from_ne_bytes(reply[16..20].try_into().unwrap()),
        0,
        "ctnetlink create failed"
    );
}

fn load_dns_fixture(
    fixture: &Fixture,
    dns: &crate::GatewayDnsMaps,
    arbitration: Option<&crate::GatewayArbitration>,
) -> Programs {
    // A reachable domain condition in both calls. The last bitmap word catches partial copies.
    let routing = [
        instruction(JNE_K, 3, 0, 2, GATEWAY_DNS_READY),
        instruction(LDX_W, 0, 2, GATEWAY_DNS_BITMAP_OFFSET as i16 + 28, 0),
        instruction(JA, 0, 0, 1, 0),
        instruction(MOV_K, 0, 0, 0, GATEWAY_ROUTE_NEED_DNS),
        instruction(EXIT, 0, 0, 0, 0),
    ];
    Programs::load_general_gateway(
        &capture(),
        1,
        &[],
        GatewayLoad {
            routing: &routing,
            maps: &fixture.maps,
            conntrack: Some(&fixture.ct),
            dns: Some(dns),
            arbitration,
        },
    )
    .unwrap()
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_dns_shadow_counts_only_authorized_data_and_keeps_xsk_fragment() {
    let fixture = Fixture::new();
    let dns = crate::GatewayDnsMaps::new(9).unwrap();
    let programs = load_dns_fixture(&fixture, &dns, None);
    let other = crate::GatewayDnsMaps::new(9).unwrap();
    for (fd, id) in [
        (&programs.discover, programs.discover_id),
        (&programs.data, programs.data_id),
    ] {
        let error = other.validate_program(fd.as_fd(), id).unwrap_err();
        assert_eq!(
            crate::gateway_dns_load_failure(&error),
            Some("map_identity")
        );
    }
    let key = GatewayDnsKey {
        canonical_dst: udp(43080).0.dst,
        realm_id: 7,
        export_epoch: 1,
        reserved: 0,
    };
    let mut live = GatewayDnsValue {
        valid_before_mono_ns: u64::MAX,
        ..Default::default()
    };
    live.bitmap.bitmap[7] = 1;
    dns.set_epoch(7, 1);
    dns.insert(&GatewayDnsKey { realm_id: 8, ..key }, &live)
        .unwrap();
    let check = |port, count| {
        let (tuple, frame) = udp(port);
        assert_eq!(run(&programs.data, &frame, 0).0, XDP_DROP as u32); // empty XSK
        assert!(fixture.maps.lookup_hold(&tuple).unwrap().is_some());
        assert_eq!(
            fixture
                .maps
                .reason_count(GatewayReason::WouldPassDns)
                .unwrap(),
            count
        );
    };
    check(43080, 0); // same IP exported in a different realm
    dns.insert(&key, &live).unwrap();
    dns.set_epoch(7, 0);
    check(43081, 0);
    dns.set_epoch(7, 2);
    check(43082, 0); // old epoch still resident
    dns.insert(
        &GatewayDnsKey {
            export_epoch: 2,
            ..key
        },
        &GatewayDnsValue {
            valid_before_mono_ns: now(),
            ..live
        },
    )
    .unwrap();
    check(43083, 0); // matching epoch but expired permit
    dns.set_epoch(7, 3);
    dns.insert(
        &GatewayDnsKey {
            export_epoch: 3,
            ..key
        },
        &GatewayDnsValue {
            valid_before_mono_ns: u64::MAX,
            ..Default::default()
        },
    )
    .unwrap();
    check(43084, 0); // known zero is evaluated and returns Endpoint
    dns.set_epoch(7, 4);
    dns.insert(
        &GatewayDnsKey {
            export_epoch: 4,
            ..key
        },
        &live,
    )
    .unwrap();
    let (tuple, mut frame) = udp(43085);
    ipv4_fragment(&mut frame, 123, 0x2000);
    assert_eq!(run(&programs.discover, &frame, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::WouldPassDns), 0);
    assert_eq!(run(&programs.data, &frame, 0).0, XDP_DROP as u32);
    assert!(fixture.maps.lookup_hold(&tuple).unwrap().is_some());
    assert_eq!(fixture.stat(GatewayReason::WouldPassDns), 1);
    assert_eq!(run(&programs.data, &frame, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 1);
    ipv4_fragment(&mut frame, 123, 1);
    assert_eq!(run(&programs.data, &frame, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::XskFragment), 1);
    assert_eq!(fixture.stat(GatewayReason::PassD1), 0);
    assert_eq!(fixture.stat(GatewayReason::WouldPassDns), 1);
    assert!(fixture.scratch().iter().all(|slot| slot[0] == 0));
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_dns_shadow_concurrent_epoch_reuse() {
    let fixture = Fixture::new();
    let dns = crate::GatewayDnsMaps::new(9).unwrap();
    let programs = load_dns_fixture(&fixture, &dns, None);
    let mut key = GatewayDnsKey {
        realm_id: 7,
        export_epoch: 1,
        canonical_dst: udp(45000).0.dst,
        reserved: 0,
    };
    // The only reusable slot alternates between a live zero bitmap and an expired one bitmap.
    // Neither complete value authorizes the packet. A torn copy could combine the two authorities.
    let zero = GatewayDnsValue {
        valid_before_mono_ns: u64::MAX,
        ..Default::default()
    };
    let mut expired = GatewayDnsValue::default();
    expired.bitmap.bitmap[7] = 1;
    for i in 0..4095u32 {
        dns.insert(
            &GatewayDnsKey {
                realm_id: 8,
                canonical_dst: std::net::Ipv4Addr::from(i).to_ipv6_mapped().octets(),
                ..key
            },
            &zero,
        )
        .unwrap();
    }
    let live = GatewayDnsValue {
        valid_before_mono_ns: u64::MAX,
        ..expired
    };
    dns.insert(&key, &live).unwrap();
    dns.set_epoch(7, 1);
    assert_eq!(run(&programs.data, &udp(44999).1, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::WouldPassDns), 1);
    std::thread::scope(|scope| {
        let (step, reached) = std::sync::mpsc::sync_channel(0);
        let dns = &dns;
        scope.spawn(move || {
            let facts = dns.object_fds()[0];
            for next in 2..=4097 {
                dns.set_epoch(7, next);
                remove(facts, &key);
                key.export_epoch = next;
                dns.insert(&key, if next % 2 == 0 { &expired } else { &zero })
                    .unwrap();
                if next == 2 || next == 2049 {
                    step.send(()).unwrap();
                }
            }
        });
        reached.recv().unwrap();
        for port in 45000..45512 {
            assert_eq!(run(&programs.data, &udp(port).1, 0).0, XDP_DROP as u32);
            if port == 45255 {
                reached.recv().unwrap();
            }
        }
    });
    assert_eq!(fixture.stat(GatewayReason::XskNewFlow), 513);
    assert_eq!(fixture.stat(GatewayReason::WouldPassDns), 1);
    assert_eq!(fixture.stat(GatewayReason::PassD1), 0);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_reload_preserves_xsk_and_counter_map_identity() {
    let fixture = Fixture::new();
    let endpoint = [
        instruction(MOV_K, 0, 0, 0, 0),
        instruction(EXIT, 0, 0, 0, 0),
    ];
    let direct = [
        instruction(MOV_K, 0, 0, 0, 1),
        instruction(EXIT, 0, 0, 0, 0),
    ];
    let old = Programs::load_general_gateway(
        &capture(),
        1,
        &[],
        GatewayLoad {
            routing: &endpoint,
            maps: &fixture.maps,
            conntrack: Some(&fixture.ct),
            dns: None,
            arbitration: None,
        },
    )
    .unwrap();
    let (held_key, first) = udp(43200);
    assert_eq!(run(&old.data, &first, 0).0, XDP_DROP as u32);
    let next = old
        .reload_general_gateway(GatewayLoad {
            routing: &direct,
            maps: &fixture.maps,
            conntrack: Some(&fixture.ct),
            dns: None,
            arbitration: None,
        })
        .unwrap();
    #[repr(C)]
    #[derive(Default)]
    struct Identity {
        kind: u32,
        id: u32,
    }
    let identity = |fd: BorrowedFd<'_>| {
        let mut info = Identity::default();
        object_info(fd, &mut info).unwrap();
        (info.kind, info.id)
    };
    assert!(std::sync::Arc::ptr_eq(old.queue_maps(), next.queue_maps()));
    assert_eq!(
        identity(old.queue_maps.xsks.as_fd()),
        identity(next.queue_maps.xsks.as_fd())
    );
    assert_eq!(
        identity(old.queue_maps.counters.as_fd()),
        identity(next.queue_maps.counters.as_fd())
    );
    assert_ne!(old.data_id, next.data_id);
    assert_ne!(old.discover_id, next.discover_id);
    drop(old);
    assert_eq!(run(&next.data, &first, 0).0, XDP_DROP as u32);
    assert!(fixture.maps.lookup_hold(&held_key).unwrap().is_some());
    let (_, fresh) = udp(43201);
    assert_eq!(run(&next.data, &fresh, 0).0, XDP_PASS as u32);
    assert_eq!(next.counters().unwrap().per_queue[0], 2);
}

fn past_time(age: u64) -> u64 {
    let current = now();
    if current < age {
        std::thread::sleep(std::time::Duration::from_nanos(age - current + 1_000_000));
    }
    now() - age
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_gateway_vlan_realm_masks_pcp_dei_and_rejects_unknown_vid() {
    let mut fixture = Fixture::new();
    fixture.maps = GatewayMaps::new(
        &[(
            CaptureRealmKey {
                physical_ifindex: 1,
                vlan_count: 2,
                tpid: [0x8100, 0x88a8],
                vid: [42, 43],
            },
            7,
        )],
        &[],
    )
    .unwrap();
    let program = fixture.load(false);
    let source = "192.0.2.1:43202".parse().unwrap();
    let destination = "198.51.100.1:443".parse().unwrap();
    let key = tuple_key(source, destination, 17);
    let mut frame = packet(source, destination, [2, 0, 0, 0, 0, 1], 2);
    frame[16..18].copy_from_slice(&0x88a8u16.to_be_bytes());
    assert_eq!(run(&program, &frame, 0).0, XDP_DROP as u32);
    assert!(fixture.maps.lookup_hold(&key).unwrap().is_some());
    frame[14..16].copy_from_slice(&(42u16 | 0xe000).to_be_bytes());
    frame[18..20].copy_from_slice(&(43u16 | 0x1000).to_be_bytes());
    assert_eq!(run(&program, &frame, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 1);
    frame[18..20].copy_from_slice(&44u16.to_be_bytes());
    assert_eq!(run(&program, &frame, 0).0, XDP_DROP as u32);
    assert_eq!(fixture.stat(GatewayReason::UnknownRealm), 1);
    assert_eq!(fixture.stat(GatewayReason::XskEndpointHold), 1);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
/// The capacity-one map covers small-capacity behavior; G17 separately fills the production map.
fn kernel_gateway_local_dns_exception_and_full_hold_drop() {
    let mut fixture = Fixture::new();
    fixture.maps.hold = bpf_fd(
        BPF_MAP_CREATE,
        &mut MapCreateAttr {
            map_type: 1,
            key_size: size_of::<GatewayKey>() as u32,
            value_size: size_of::<GatewayHold>() as u32,
            max_entries: 1,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: object_name(b"honk_gw_full"),
        },
    )
    .unwrap();
    let program = fixture.load(false);
    let (key, ordinary) = udp(43203);
    fixture
        .maps
        .replace_local_addresses(&[LocalAddressKey {
            family: key.family,
            address: key.dst,
        }])
        .unwrap();
    assert_eq!(run(&program, &ordinary, 0).0, XDP_PASS as u32);
    assert_eq!(fixture.maps.lookup_hold(&key).unwrap(), None);
    let dns = GatewayKey {
        dport: 53u16.to_be(),
        ..key
    };
    assert_eq!(run(&program, &frame_for(dns), 0).0, XDP_DROP as u32);
    assert!(fixture.maps.lookup_hold(&dns).unwrap().is_some());
    let another = GatewayKey {
        sport: 43204u16.to_be(),
        ..dns
    };
    assert_eq!(run(&program, &frame_for(another), 0).0, XDP_DROP as u32);
    assert_eq!(fixture.maps.lookup_hold(&another).unwrap(), None);
    assert_eq!(fixture.stat(GatewayReason::PassLocal), 1);
    assert_eq!(fixture.stat(GatewayReason::XskNewFlow), 1);
    assert_eq!(fixture.stat(GatewayReason::HoldInsertFailed), 1);
    let mut count = 0u64;
    get(fixture.counters.as_fd(), &0u32, &mut count as *mut _ as u64);
    assert_eq!(count, 1, "hold insertion failure must precede redirect");
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns and the full production hold map"]
fn kernel_gateway_g17_production_capacity_hold_full_drops_before_xsk() {
    let fixture = Fixture::new();
    let program = fixture.load(false);
    let mut info = [0u32; 6];
    object_info(fixture.maps.hold.as_fd(), &mut info).unwrap();
    assert_eq!(info[0], 1, "production hold must remain a non-LRU hash");
    let capacity = info[4];
    assert_eq!(capacity, 65536);
    let (base, _) = udp(0);
    let inserted_at = now();
    let initial = GatewayHold {
        stamp: inserted_at,
        last_seen_ns: inserted_at,
    };
    for port in 0..capacity {
        let key = GatewayKey {
            sport: (port as u16).to_be(),
            ..base
        };
        fixture.maps.insert_hold(&key, initial.stamp).unwrap();
    }
    let entries = || {
        let mut cursor: Option<GatewayKey> = None;
        let mut count = 0u32;
        loop {
            let mut next = GatewayKey::default();
            match bpf(
                4,
                &mut MapElemAttr {
                    map_fd: fixture.maps.hold.as_raw_fd() as u32,
                    reserved: 0,
                    key: cursor.as_ref().map_or(0, |key| key as *const _ as u64),
                    value: &mut next as *mut _ as u64,
                    flags: 0,
                },
            ) {
                Ok(_) => {
                    count += 1;
                    assert!(count <= capacity);
                    assert_eq!(fixture.maps.lookup_hold(&next).unwrap(), Some(initial));
                    cursor = Some(next);
                }
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
                    return count;
                }
            }
        }
    };
    let before_entries = entries();
    assert_eq!(before_entries, capacity);
    let candidate = GatewayKey {
        dport: 444u16.to_be(),
        ..base
    };
    let before_failed = fixture.stat(GatewayReason::HoldInsertFailed);
    let before_xsk = fixture.stat(GatewayReason::XskNewFlow);
    let mut before_redirects = 0u64;
    get(
        fixture.counters.as_fd(),
        &0u32,
        &mut before_redirects as *mut _ as u64,
    );
    assert_eq!(run(&program, &frame_for(candidate), 0).0, XDP_DROP as u32);
    assert_eq!(fixture.maps.lookup_hold(&candidate).unwrap(), None);
    assert_eq!(
        fixture.stat(GatewayReason::HoldInsertFailed),
        before_failed + 1
    );
    assert_eq!(fixture.stat(GatewayReason::XskNewFlow), before_xsk);
    let mut after_redirects = 0u64;
    get(
        fixture.counters.as_fd(),
        &0u32,
        &mut after_redirects as *mut _ as u64,
    );
    assert_eq!(
        after_redirects, before_redirects,
        "full hold must fail before redirect"
    );
    let after_entries = entries();
    assert_eq!(after_entries, capacity);
    for port in 0..capacity {
        assert_eq!(
            fixture
                .maps
                .lookup_hold(&GatewayKey {
                    sport: (port as u16).to_be(),
                    ..base
                })
                .unwrap(),
            Some(initial),
            "existing entry {port} was evicted or rewritten"
        );
    }
    println!(
        "G17 production hold capacity={capacity} entries_before={before_entries} entries_after={after_entries} hold_insert_failed_delta=1 redirect_delta=0"
    );
}
