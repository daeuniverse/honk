#![cfg(feature = "ebpf")]

//! Root-only regression coverage for the production TC object.
//!
//! L2 contracts execute through BPF_PROG_TEST_RUN without host attachments.
//! The kernel always supplies Ethernet to SCHED_CLS test-run; L3 therefore
//! uses real TUN interfaces in an isolated network namespace.

use aya::maps::{Array, HashMap, MapError, PerCpuArray};
use aya::programs::{SchedClassifier, TestRun, TestRunOptions};
use aya::{Ebpf, EbpfLoader, Pod};
use aya_ebpf_bindings::bindings::__sk_buff;
use honk_ebpf_common::dae_ip::In6Addr;
use honk_ebpf_common::*;
use std::convert::TryInto;
use std::mem;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::ptr;

const TC_ACT_OK: u32 = 0;
const TC_ACT_SHOT: u32 = 2;
const TC_ACT_PIPE: u32 = 3;
const TC_ACT_REDIRECT: u32 = 7;
const IPPROTO_ICMPV6: u8 = 58;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const ETH_P_IPV6: u16 = 0x86dd;
const BLOCK_OUTBOUND: u8 = 1;
const TEST_OUTBOUND: u8 = 2;

const TC_PROGRAMS: &[&str] = &[
    "lan_ingress_l2",
    "lan_ingress_l3",
    "wan_ingress_l2",
    "wan_ingress_l3",
    "dae0peer_ingress",
    "dae0_ingress",
    "lan_egress_l2",
    "lan_egress_l3",
    "wan_egress_l2",
    "wan_egress_l3",
];

struct Fixture {
    bpf: Ebpf,
    _pin: tempfile::TempDir,
}

#[derive(Clone, Copy)]
struct SkbInput {
    mark: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    cb: [u32; 5],
}

impl Default for SkbInput {
    fn default() -> Self {
        Self {
            mark: 0,
            ingress_ifindex: 0,
            // Index one is the loopback device used by the kernel test-run
            // fixture; values greater than one would require a real device.
            ifindex: 1,
            cb: [0; 5],
        }
    }
}

struct Run {
    return_value: u32,
    data_size_out: u32,
    mark: u32,
}

impl Fixture {
    fn load() -> Self {
        assert_eq!(unsafe { libc::geteuid() }, 0, "requires root");
        let object = match std::env::var_os("HONK_TEST_BPF_OBJECT") {
            Some(path) => std::fs::read(PathBuf::from(path)).expect("read test BPF object"),
            None => include_bytes!(env!("HONK_EBPF_OBJECT")).to_vec(),
        };
        let pin = tempfile::Builder::new()
            .prefix("honk-datapath-")
            .tempdir_in("/sys/fs/bpf")
            .expect("create owned bpffs test directory");
        let param = DaeParam {
            tproxy_port: 12345u16.to_be() as u32,
            dae0_ifindex: 1,
            wan_ifindex: 1,
            dae0peer_mac: [0x02, 0, 0, 0, 0, 2],
            dae_socket_mark: DAE_BYPASS_MARK,
            ..Default::default()
        };
        let wan_ifindex = 1u32;
        let dae0peer_ifindex = 1u32;
        let task_mm_offset = 0u32;
        let mm_arg_start_offset = 0u32;
        let mut loader = EbpfLoader::new();
        loader
            .override_global("PARAM", &param, true)
            .override_global("WAN_IFINDEX", &wan_ifindex, true)
            .override_global("DAE0PEER_IFINDEX", &dae0peer_ifindex, true)
            .override_global("TASK_MM_OFFSET", &task_mm_offset, true)
            .override_global("MM_ARG_START_OFFSET", &mm_arg_start_offset, true)
            .map_pin_path(
                "UDP_DECISION_SEQUENCE",
                pin.path().join("UDP_DECISION_SEQUENCE"),
            );
        let mut bpf = loader.load(&object).expect("load BPF object");

        // Loading every production classifier catches missing map relocations
        // and verifier regressions without installing any host hook.
        for name in TC_PROGRAMS {
            let program: &mut SchedClassifier = bpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("missing TC program {name}"))
                .try_into()
                .unwrap_or_else(|error| panic!("{name} is not SCHED_CLS: {error}"));
            program
                .load()
                .unwrap_or_else(|error| panic!("load TC program {name}: {error}"));
        }
        set_array(&mut bpf, "DATAPATH_STATE_MAP", 0, 1u32).expect("open datapath admission");
        Self { bpf, _pin: pin }
    }

    fn run(&self, name: &str, packet: &[u8], input: SkbInput) -> Run {
        assert!(
            packet.len() >= 14,
            "SCHED_CLS test-run requires Ethernet input"
        );
        let program: &SchedClassifier = self
            .bpf
            .program(name)
            .unwrap_or_else(|| panic!("missing loaded TC program {name}"))
            .try_into()
            .unwrap_or_else(|error| panic!("{name} is not SCHED_CLS: {error}"));
        let context = skb_context(input);
        let context_bytes = unsafe {
            std::slice::from_raw_parts(
                (&context as *const __sk_buff).cast::<u8>(),
                mem::size_of::<__sk_buff>(),
            )
        };
        let mut output = vec![0u8; packet.len() + 64];
        let mut context_out = vec![0u8; mem::size_of::<__sk_buff>()];
        let result = program
            .test_run(TestRunOptions {
                data_in: Some(packet),
                data_out: Some(&mut output),
                ctx_in: Some(context_bytes),
                ctx_out: Some(&mut context_out),
                repeat: 1,
                ..Default::default()
            })
            .unwrap_or_else(|error| panic!("BPF_PROG_TEST_RUN {name}: {error}"));
        let returned: __sk_buff = unsafe { ptr::read_unaligned(context_out.as_ptr().cast()) };
        Run {
            return_value: result.return_value,
            data_size_out: result.data_size_out,
            mark: returned.mark,
        }
    }
}

fn skb_context(input: SkbInput) -> __sk_buff {
    let mut context: __sk_buff = unsafe { mem::zeroed() };
    context.mark = input.mark;
    context.ingress_ifindex = input.ingress_ifindex;
    context.ifindex = input.ifindex;
    context.cb = input.cb;
    // protocol, len, data, and data_end intentionally remain zero.  The
    // kernel test-run derives protocol and packet pointers from Ethernet data.
    context
}

fn set_array<V: Pod>(bpf: &mut Ebpf, name: &str, index: u32, value: V) -> Result<(), MapError> {
    let map = bpf.map_mut(name).expect("array map present");
    let mut array = Array::<_, V>::try_from(map).expect("array map type/layout");
    array.set(index, value, 0)
}

fn put_hash<K: Pod, V: Pod>(bpf: &mut Ebpf, name: &str, key: K, value: V) -> Result<(), MapError> {
    let map = bpf.map_mut(name).expect("hash map present");
    let mut hash = HashMap::<_, K, V>::try_from(map).expect("hash map type/layout");
    hash.insert(key, value, 0)
}

fn hash_count<K: Pod, V: Pod>(bpf: &Ebpf, name: &str) -> usize {
    let map = bpf.map(name).expect("hash map present");
    let hash = HashMap::<_, K, V>::try_from(map).expect("hash map type/layout");
    hash.keys().map(Result::unwrap).count()
}

fn outbound_stats(bpf: &Ebpf, outbound: u8) -> OutboundStatsCounters {
    let map = bpf.map("OUTBOUND_STATS").expect("stats map present");
    let array =
        PerCpuArray::<_, OutboundStatsCounters>::try_from(map).expect("stats map type/layout");
    let values = array
        .get(&(outbound as u32), 0)
        .expect("read per-cpu stats");
    values
        .iter()
        .fold(OutboundStatsCounters::default(), |mut total, value| {
            total.wrapping_add_assign(value);
            total
        })
}

fn v4(octets: [u8; 4]) -> In6Addr {
    In6Addr::from_ipv4_bytes(octets)
}
fn tuple(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, l4proto: u8) -> TuplesKey {
    let mut key: TuplesKey = unsafe { mem::zeroed() };
    key.src_ip = v4(src);
    key.dst_ip = v4(dst);
    key.src_port = sport;
    key.dst_port = dport;
    key.l4proto = l4proto;
    key
}

fn routing_meta(outbound: u8, mark: u32, must: bool, offload: bool) -> RoutingMeta {
    let mut raw = outbound as u64
        | (u64::from(mark) << 8)
        | (u64::from(must as u8) << 40)
        | ROUTING_META_FLAG_PUBLISHED;
    if offload {
        raw |= ROUTING_META_FLAG_OFFLOAD;
    }
    RoutingMeta { raw }
}

fn cached_state(outbound: u8, state: u8, token: u32, must: bool, offload: bool) -> ConnState {
    let mut value: ConnState = unsafe { mem::zeroed() };
    let mut now: libc::timespec = unsafe { mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) },
        0
    );
    value.last_seen_ns = now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64;
    value.state = state;
    value.decision_token = token;
    value.meta = routing_meta(outbound, 0, must, offload);
    value
}

fn set_health(bpf: &mut Ebpf, outbound: u8, l4proto: u8, dport: u16, alive: bool) {
    let domain = if l4proto == IPPROTO_TCP {
        0
    } else if dport == 53 {
        1
    } else {
        2
    };
    let key = u32::from(outbound) * 6 + domain * 2;
    set_array(bpf, "OUTBOUND_CONNECTIVITY_MAP", key, u64::from(alive)).expect("set health map");
}

fn ethernet(ether_type: u16) -> Vec<u8> {
    let mut packet = vec![
        0x02, 0, 0, 0, 0, 2, // destination
        0x02, 0, 0, 0, 0, 1, // source
    ];
    packet.extend_from_slice(&ether_type.to_be_bytes());
    packet
}

fn ipv4_packet(src: [u8; 4], dst: [u8; 4], l4proto: u8, transport: &[u8]) -> Vec<u8> {
    let total_len = (20 + transport.len()) as u16;
    let mut packet = ethernet(0x0800);
    packet.extend_from_slice(&[
        0x45,
        0,
        (total_len >> 8) as u8,
        total_len as u8,
        0,
        0,
        0,
        0,
        64,
        l4proto,
        0,
        0,
    ]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(transport);
    packet
}

fn udp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload_len: usize) -> Vec<u8> {
    let length = (8 + payload_len) as u16;
    let mut udp = Vec::with_capacity(8 + payload_len);
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&length.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend(std::iter::repeat_n(0xa5, payload_len));
    ipv4_packet(src, dst, IPPROTO_UDP, &udp)
}

fn tcp_packet(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    flags: u8,
    payload_len: usize,
) -> Vec<u8> {
    let mut tcp = vec![0u8; 20 + payload_len];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[20..].fill(0x5a);
    ipv4_packet(src, dst, IPPROTO_TCP, &tcp)
}

fn ipv6_packet(src: [u8; 16], dst: [u8; 16], next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = ethernet(ETH_P_IPV6);
    packet.extend_from_slice(&[0x60, 0, 0, 0]);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(&[next_header, 64]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(payload);
    packet
}

fn icmp6(src: [u8; 16], dst: [u8; 16], message_type: u8) -> Vec<u8> {
    ipv6_packet(
        src,
        dst,
        IPPROTO_ICMPV6,
        &[message_type, 0, 0, 0, 0, 0, 0, 0],
    )
}

fn icmp6_with_hop_extension(
    src: [u8; 16],
    dst: [u8; 16],
    extension_len_units: u8,
    message_type: u8,
    pad_to: Option<usize>,
) -> Vec<u8> {
    let extension_len = (extension_len_units as usize + 1) * 8;
    let mut extension = vec![0u8; extension_len];
    extension[0] = IPPROTO_ICMPV6;
    extension[1] = extension_len_units;
    extension.extend_from_slice(&[message_type, 0, 0, 0, 0, 0, 0, 0]);
    let mut packet = ipv6_packet(src, dst, 0, &extension);
    if let Some(length) = pad_to {
        packet.resize(length.max(packet.len()), 0);
        let payload_len = (packet.len() - 14 - 40) as u16;
        packet[18..20].copy_from_slice(&payload_len.to_be_bytes());
    }
    packet
}

fn icmp6_fragment(src: [u8; 16], dst: [u8; 16], fragment_offset: u16) -> Vec<u8> {
    let mut fragment = vec![IPPROTO_ICMPV6, 0, 0, 0, 0, 0, 0, 1];
    fragment[2..4].copy_from_slice(&fragment_offset.to_be_bytes());
    fragment.extend_from_slice(&[137, 0, 0, 0, 0, 0, 0, 0]);
    ipv6_packet(src, dst, 44, &fragment)
}

#[test]
#[ignore = "requires root, bpffs, BPF_PROG_TEST_RUN, and an eBPF object"]
fn ndp_redirect_l2_contract() {
    let fixture = Fixture::load();
    let src6 = [0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let dst6 = [0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];

    // SCHED_CLS test-run is genuinely L2.  A short frame exercises the
    // parser's slow fallback; a long extension frame remains linear in the
    // kernel fixture, so this test does not mislabel it as a forced fallback.
    let conn_before = hash_count::<TuplesKey, ConnState>(&fixture.bpf, "CONN_STATE_MAP");
    assert_eq!(
        fixture
            .run(
                "lan_egress_l2",
                &icmp6(src6, dst6, 137),
                SkbInput::default()
            )
            .return_value,
        TC_ACT_SHOT,
        "local ICMPv6 Redirect is dropped on LAN egress"
    );
    let forwarded = SkbInput {
        ingress_ifindex: 1,
        ..Default::default()
    };
    assert_eq!(
        fixture
            .run("lan_egress_l2", &icmp6(src6, dst6, 137), forwarded)
            .return_value,
        TC_ACT_OK,
        "forwarded ICMPv6 Redirect passes"
    );
    assert_eq!(
        fixture
            .run(
                "lan_egress_l2",
                &icmp6(src6, dst6, 128),
                SkbInput::default()
            )
            .return_value,
        TC_ACT_OK,
        "other ICMPv6 remains untouched"
    );
    assert_eq!(
        fixture
            .run(
                "lan_egress_l2",
                &icmp6_with_hop_extension(src6, dst6, 0, 137, None),
                SkbInput::default(),
            )
            .return_value,
        TC_ACT_SHOT,
        "short extension frame follows the slow parser policy"
    );
    assert_eq!(
        fixture
            .run(
                "lan_egress_l2",
                &icmp6_with_hop_extension(src6, dst6, 30, 137, Some(320)),
                SkbInput::default(),
            )
            .return_value,
        TC_ACT_SHOT,
        "a >256-byte extension frame is still classified from linear data"
    );
    assert_eq!(
        fixture
            .run(
                "lan_egress_l2",
                &icmp6_fragment(src6, dst6, 0),
                SkbInput::default()
            )
            .return_value,
        TC_ACT_SHOT,
        "atomic IPv6 fragment still classifies ICMPv6 Redirect"
    );
    assert_eq!(
        fixture
            .run(
                "lan_egress_l2",
                &icmp6_fragment(src6, dst6, 8),
                SkbInput::default()
            )
            .return_value,
        TC_ACT_OK,
        "non-initial IPv6 fragment passes for kernel reassembly"
    );
    let truncated = ipv6_packet(src6, dst6, IPPROTO_ICMPV6, &[]);
    assert_eq!(
        fixture
            .run("lan_egress_l2", &truncated, SkbInput::default())
            .return_value,
        TC_ACT_SHOT,
        "truncated ICMPv6 follows the malformed/drop policy"
    );
    let too_many_extensions = icmp6_with_hop_extension(src6, dst6, 0, 137, None);
    let mut malformed = ethernet(ETH_P_IPV6);
    malformed.extend_from_slice(&[0x60, 0, 0, 0, 72, 0, 0, 64]);
    malformed.extend_from_slice(&src6);
    malformed.extend_from_slice(&dst6);
    for _ in 0..9 {
        malformed.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    }
    malformed.extend_from_slice(&too_many_extensions[54..]);
    assert_eq!(
        fixture
            .run("lan_egress_l2", &malformed, SkbInput::default())
            .return_value,
        TC_ACT_SHOT,
        "too many IPv6 extensions are malformed"
    );
    assert_eq!(
        hash_count::<TuplesKey, ConnState>(&fixture.bpf, "CONN_STATE_MAP"),
        conn_before,
        "ICMPv6 never creates conntrack state"
    );
}

#[test]
#[ignore = "requires root, bpffs, and BPF_PROG_TEST_RUN"]
fn reply_rx_counters_require_exact_reverse_tuple() {
    let mut fixture = Fixture::load();

    // dae0_ingress must attribute only an exact reverse five-tuple.  The
    // payload makes the byte assertion distinguish packet length from a fixed
    // header size.
    let original = tuple([10, 0, 0, 2], [203, 0, 113, 9], 40000, 443, IPPROTO_TCP);
    put_hash(
        &mut fixture.bpf,
        "REDIRECT_TRACK",
        RedirectTuple::from_tuples(&original),
        RedirectEntry {
            dmac: [0x02, 0, 0, 0, 0, 1],
            smac: [0x02, 0, 0, 0, 0, 2],
            outbound: TEST_OUTBOUND,
            ifindex: 1,
            ..Default::default()
        },
    )
    .expect("seed redirect tracking");
    let reply = tcp_packet([203, 0, 113, 9], [10, 0, 0, 2], 443, 40000, 0x10, 19);
    let rx_before = outbound_stats(&fixture.bpf, TEST_OUTBOUND);
    let reply_run = fixture.run("dae0_ingress", &reply, SkbInput::default());
    assert_eq!(reply_run.return_value, TC_ACT_REDIRECT);
    assert_eq!(reply_run.data_size_out, reply.len() as u32);
    let rx_after = outbound_stats(&fixture.bpf, TEST_OUTBOUND);
    assert_eq!(rx_after.rx_packets - rx_before.rx_packets, 1);
    assert_eq!(rx_after.rx_bytes - rx_before.rx_bytes, reply.len() as u64);
    assert_eq!(outbound_stats(&fixture.bpf, BLOCK_OUTBOUND).rx_packets, 0);

    for wrong_reply in [
        tcp_packet([203, 0, 113, 9], [10, 0, 0, 2], 444, 40000, 0x10, 19),
        udp_packet([203, 0, 113, 9], [10, 0, 0, 2], 443, 40000, 19),
    ] {
        let before = outbound_stats(&fixture.bpf, TEST_OUTBOUND);
        let run = fixture.run("dae0_ingress", &wrong_reply, SkbInput::default());
        assert_eq!(run.return_value, TC_ACT_OK);
        let after = outbound_stats(&fixture.bpf, TEST_OUTBOUND);
        assert_eq!(after.rx_packets, before.rx_packets);
        assert_eq!(after.rx_bytes, before.rx_bytes);
    }
}

#[test]
#[ignore = "requires root, bpffs, and BPF_PROG_TEST_RUN"]
fn cached_route_health_and_pending_marks() {
    let mut fixture = Fixture::load();
    let ready = DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY;
    // Rows cover distinct health exemptions, lifecycle states, and readiness.
    for (index, (protocol, state, alive, flags, verdict)) in [
        (
            IPPROTO_TCP,
            cached_state(0, 0, 0, true, false),
            false,
            0,
            TC_ACT_OK,
        ),
        (
            IPPROTO_TCP,
            cached_state(0, 0, 0, false, true),
            false,
            0,
            TC_ACT_OK,
        ),
        (
            IPPROTO_TCP,
            cached_state(0, 0, 0, false, false),
            false,
            0,
            TC_ACT_REDIRECT,
        ),
        (
            IPPROTO_TCP,
            cached_state(BLOCK_OUTBOUND, 0, 0, false, false),
            false,
            0,
            TC_ACT_REDIRECT,
        ),
        (
            IPPROTO_TCP,
            cached_state(TEST_OUTBOUND, 0, 0, false, false),
            false,
            0,
            TC_ACT_SHOT,
        ),
        (
            IPPROTO_TCP,
            cached_state(TEST_OUTBOUND, 0, 0, false, false),
            true,
            0,
            TC_ACT_REDIRECT,
        ),
        (
            IPPROTO_UDP,
            cached_state(0, UdpDecisionState::Pending as u8, 41, false, false),
            false,
            0,
            TC_ACT_SHOT,
        ),
        (
            IPPROTO_UDP,
            cached_state(0, UdpDecisionState::Pending as u8, 42, false, false),
            false,
            ready,
            TC_ACT_OK,
        ),
        (
            IPPROTO_UDP,
            cached_state(0, UdpDecisionState::DirectArmed as u8, 43, false, false),
            false,
            ready,
            TC_ACT_OK,
        ),
        (
            IPPROTO_UDP,
            cached_state(
                BLOCK_OUTBOUND,
                UdpDecisionState::Block as u8,
                0,
                false,
                false,
            ),
            false,
            0,
            TC_ACT_SHOT,
        ),
        (
            IPPROTO_UDP,
            cached_state(0, 0, 0, false, false),
            false,
            0,
            TC_ACT_SHOT,
        ),
        (
            IPPROTO_UDP,
            cached_state(BLOCK_OUTBOUND, 0, 0, false, false),
            false,
            0,
            TC_ACT_SHOT,
        ),
        (
            IPPROTO_UDP,
            cached_state(TEST_OUTBOUND, 0, 0, false, false),
            false,
            0,
            TC_ACT_SHOT,
        ),
        (
            IPPROTO_UDP,
            cached_state(TEST_OUTBOUND, 0, 0, false, false),
            true,
            0,
            TC_ACT_REDIRECT,
        ),
        (
            IPPROTO_UDP,
            cached_state(
                TEST_OUTBOUND,
                UdpDecisionState::Proxy as u8,
                44,
                false,
                false,
            ),
            false,
            0,
            TC_ACT_REDIRECT,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let sport = 41000 + index as u16;
        let key = tuple([10, 0, 0, 3], [198, 51, 100, 3], sport, 443, protocol);
        put_hash(&mut fixture.bpf, "CONN_STATE_MAP", key, state).unwrap();
        set_health(
            &mut fixture.bpf,
            unsafe { state.meta.data.outbound },
            protocol,
            443,
            alive,
        );
        set_array(&mut fixture.bpf, "DATAPATH_FLAGS_MAP", 0, flags).unwrap();
        let packet = if protocol == IPPROTO_TCP {
            tcp_packet([10, 0, 0, 3], [198, 51, 100, 3], sport, 443, 0x10, 7)
        } else {
            udp_packet([10, 0, 0, 3], [198, 51, 100, 3], sport, 443, 3)
        };
        let run = fixture.run("lan_ingress_l2", &packet, SkbInput::default());
        assert_eq!(run.return_value, verdict, "cached route row {index}");
        if verdict == TC_ACT_OK {
            let expected_mark = if state.decision_token == 0 {
                CLASSIFIED_MARK
            } else {
                pack_nfqueue_mark(state.decision_token).unwrap()
            };
            assert_eq!(run.mark, expected_mark, "cached route row {index}");
        }
    }

    let dns_tcp = tcp_packet([10, 0, 0, 7], [198, 51, 100, 53], 41050, 53, 0x02, 0);
    assert_eq!(
        fixture
            .run("lan_ingress_l2", &dns_tcp, SkbInput::default())
            .return_value,
        TC_ACT_REDIRECT
    );
    let before_dns = hash_count::<TuplesKey, ConnState>(&fixture.bpf, "CONN_STATE_MAP");
    let dns_udp = udp_packet([10, 0, 0, 8], [198, 51, 100, 53], 41051, 53, 3);
    assert_eq!(
        fixture
            .run("lan_ingress_l2", &dns_udp, SkbInput::default())
            .return_value,
        TC_ACT_REDIRECT
    );
    let wan_dns = udp_packet([198, 51, 100, 53], [10, 0, 0, 9], 53, 41052, 3);
    assert_eq!(
        fixture
            .run("wan_ingress_l2", &wan_dns, SkbInput::default())
            .return_value,
        TC_ACT_PIPE
    );
    assert_eq!(
        hash_count::<TuplesKey, ConnState>(&fixture.bpf, "CONN_STATE_MAP"),
        before_dns
    );
}

#[test]
#[ignore = "requires root, bpffs, TUN, iproute2, and an isolated network namespace"]
fn ndp_redirect_l3_on_real_tun() {
    std::thread::spawn(|| {
        use std::io::{Read, Write};
        use std::net::{Ipv6Addr, SocketAddr};
        use std::os::unix::fs::OpenOptionsExt;
        use std::time::{Duration, Instant};

        fn ip(args: &[&str]) {
            let output = std::process::Command::new("ip")
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "ip {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn tun(name: &str, address: &str) -> std::fs::File {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open("/dev/net/tun")
                .unwrap();
            let mut request: libc::ifreq = unsafe { mem::zeroed() };
            for (byte, value) in request.ifr_name.iter_mut().zip(name.bytes()) {
                *byte = value as libc::c_char;
            }
            request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
            assert_eq!(
                unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &request) },
                0
            );
            ip(&["link", "set", "dev", name, "addrgenmode", "none"]);
            ip(&["-6", "addr", "add", address, "dev", name, "nodad"]);
            ip(&["link", "set", "dev", name, "up"]);
            file
        }

        fn received(tun: &mut std::fs::File, destination: Ipv6Addr, message_type: u8) -> bool {
            let deadline = Instant::now() + Duration::from_millis(300);
            let mut packet = [0u8; 2048];
            while Instant::now() < deadline {
                let mut poll = libc::pollfd {
                    fd: tun.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                assert!(unsafe { libc::poll(&mut poll, 1, 25) } >= 0);
                match tun.read(&mut packet) {
                    Ok(length)
                        if length >= 48
                            && packet[24..40] == destination.octets()
                            && packet[40] == message_type =>
                    {
                        return true;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("read TUN packet: {error}"),
                }
            }
            false
        }

        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let mut outgoing = tun("honk-out", "fd42::1/64");
        let mut incoming = tun("honk-in", "fd43::1/64");
        std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").unwrap();
        let mut fixture = Fixture::load();
        aya::programs::tc::qdisc_add_clsact("honk-out").unwrap();
        let program: &mut SchedClassifier = fixture
            .bpf
            .program_mut("lan_egress_l3")
            .unwrap()
            .try_into()
            .unwrap();
        let link = program
            .attach("honk-out", aya::programs::TcAttachType::Egress)
            .unwrap();
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV6),
        )
        .unwrap();
        socket
            .bind(&SocketAddr::new("fd42::1".parse().unwrap(), 0).into())
            .unwrap();
        socket.set_unicast_hops_v6(255).unwrap();
        let destination: Ipv6Addr = "fd42::2".parse().unwrap();
        let mut message = [0u8; 40];
        message[8..24].copy_from_slice(&destination.octets());
        message[24..40].copy_from_slice(&destination.octets());
        for (kind, delivered) in [(128, true), (137, false), (129, true)] {
            message[0] = kind;
            match socket.send_to(&message, &SocketAddr::new(destination.into(), 0).into()) {
                Ok(sent) => assert_eq!(sent, message.len()),
                // A TC drop may propagate NET_XMIT_DROP to the raw sender.
                Err(error) if !delivered => assert_eq!(error.raw_os_error(), Some(libc::ENOBUFS)),
                Err(error) => panic!("send local L3 type {kind}: {error}"),
            }
            assert_eq!(
                received(&mut outgoing, destination, kind),
                delivered,
                "local L3 ICMPv6 type {kind}"
            );
        }
        message[0] = 137;
        let forwarded = ipv6_packet(
            "fd43::2".parse::<Ipv6Addr>().unwrap().octets(),
            destination.octets(),
            IPPROTO_ICMPV6,
            &message,
        );
        incoming.write_all(&forwarded[14..]).unwrap();
        assert!(
            received(&mut outgoing, destination, 137),
            "forwarded L3 Redirect must pass"
        );
        program.detach(link).unwrap();
        socket
            .send_to(&message, &SocketAddr::new(destination.into(), 0).into())
            .unwrap();
        assert!(
            received(&mut outgoing, destination, 137),
            "local Redirect passes without the TC hook"
        );
    })
    .join()
    .unwrap();
}
