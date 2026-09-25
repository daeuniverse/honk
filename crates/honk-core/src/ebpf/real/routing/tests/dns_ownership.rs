use super::{object, outbound_ids, rule};
use crate::control::routing_matcher::RoutingPushPlan;
use crate::ebpf::EbpfBackend;
use crate::ebpf::real::RealEbpfBackend;
use crate::routing::Router;
use aya::Pod;
use aya::maps::{Array, HashMap};
use aya::programs::{ProgramError, SchedClassifier, TcAttachType, TestRun, TestRunOptions};
use aya_ebpf_bindings::bindings::__sk_buff;
use honk_config::routing::RoutingCondition;
use honk_config::types::DialMode;
use honk_ebpf_common::dae_ip::In6Addr;
use honk_ebpf_common::*;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::ptr;
use std::time::Duration;

mod failures;
mod network;

const TC_ACT_OK: u32 = 0;
const TC_ACT_SHOT: u32 = 2;
const TC_ACT_REDIRECT: u32 = 7;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const USER_MARK: u32 = 0x002a_4001;

struct TproxyListeners {
    tcp4: TcpListener,
    tcp6: TcpListener,
    udp4: UdpSocket,
    udp6: UdpSocket,
}

impl TproxyListeners {
    fn new() -> Self {
        Self {
            tcp4: Self::tcp(false),
            tcp6: Self::tcp(true),
            udp4: Self::udp(false),
            udp6: Self::udp(true),
        }
    }

    fn configure(socket: &socket2::Socket, ipv6: bool) {
        if ipv6 {
            socket.set_ip_transparent_v6(true).unwrap();
        } else {
            socket.set_ip_transparent_v4(true).unwrap();
        }
        nix::sys::socket::setsockopt(socket, nix::sys::socket::sockopt::Mark, &DAE_BYPASS_MARK)
            .unwrap();
    }

    fn tcp(ipv6: bool) -> TcpListener {
        let domain = if ipv6 {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None).unwrap();
        socket.set_cloexec(true).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket.set_reuse_address(true).unwrap();
        if ipv6 {
            socket.set_only_v6(true).unwrap();
        }
        Self::configure(&socket, ipv6);
        let address = if ipv6 {
            SocketAddr::from(([0; 16], 0))
        } else {
            SocketAddr::from(([0; 4], 0))
        };
        socket.bind(&address.into()).unwrap();
        socket.listen(128).unwrap();
        socket.into()
    }

    fn udp(ipv6: bool) -> UdpSocket {
        let domain = if ipv6 {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None).unwrap();
        socket.set_cloexec(true).unwrap();
        socket.set_reuse_address(true).unwrap();
        if ipv6 {
            socket.set_only_v6(true).unwrap();
        }
        Self::configure(&socket, ipv6);
        let enabled: libc::c_int = 1;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVMARK,
                    (&enabled as *const libc::c_int).cast(),
                    mem::size_of_val(&enabled) as libc::socklen_t,
                )
            },
            0,
            "SO_RCVMARK: {}",
            std::io::Error::last_os_error()
        );
        let address = if ipv6 {
            SocketAddr::from(([0; 16], 0))
        } else {
            SocketAddr::from(([0; 4], 0))
        };
        socket.bind(&address.into()).unwrap();
        let socket: UdpSocket = socket.into();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
    }

    fn publish(&self, backend: &mut RealEbpfBackend) -> anyhow::Result<()> {
        let udp4 = [self.udp4.as_raw_fd(); 4];
        let udp6 = [self.udp6.as_raw_fd(); 4];
        backend.publish_listener_sockets(self.tcp4.as_raw_fd(), self.tcp6.as_raw_fd(), &udp4, &udp6)
    }
}

#[derive(Clone, Copy, Default)]
struct SkbInput {
    mark: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    cb: [u32; 5],
}

#[derive(Debug)]
struct Run {
    verdict: u32,
    mark: u32,
    cb: [u32; 5],
}

fn isolated(f: impl FnOnce() + Send + 'static) {
    std::thread::spawn(move || {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
            .expect("unshare routing-test network namespace");
        f();
    })
    .join()
    .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

fn fixture_param() -> DaeParam {
    DaeParam {
        tproxy_port: 12345u16.to_be() as u32,
        dae0_ifindex: 1,
        wan_ifindex: 1,
        dae0peer_mac: [0x02, 0, 0, 0, 0, 2],
        dae_socket_mark: DAE_BYPASS_MARK,
        ..Default::default()
    }
}

fn compile(rules: &[honk_config::routing::RoutingRule]) -> RoutingPushPlan {
    let router = Router::new(rules, "direct").unwrap();
    RoutingPushPlan::compile(&router, &outbound_ids(), DialMode::Ip).unwrap()
}

fn publish(
    rules: &[honk_config::routing::RoutingRule],
) -> (RealEbpfBackend, RoutingPushPlan, TproxyListeners) {
    let plan = compile(rules);
    let mut backend =
        RealEbpfBackend::load_routing_test_fixture(&object(), fixture_param()).unwrap();
    backend.publish_routing_plan(&plan, &[]).unwrap();
    let listeners = TproxyListeners::new();
    listeners.publish(&mut backend).unwrap();
    backend.set_datapath_ready(true).unwrap();
    for key in 0..6 {
        set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", key, 1u64);
    }
    for key in 2 * 6..3 * 6 {
        set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", key, 1u64);
    }
    for key in (OutboundIndex::ControlPlaneRouting as u32) * 6
        ..(OutboundIndex::ControlPlaneRouting as u32 + 1) * 6
    {
        set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", key, 1u64);
    }
    (backend, plan, listeners)
}

fn set_array<V: Pod>(backend: &mut RealEbpfBackend, name: &str, index: u32, value: V) {
    let map = backend.bpf_mut().unwrap().map_mut(name).unwrap();
    Array::<_, V>::try_from(map)
        .unwrap()
        .set(index, value, 0)
        .unwrap();
}

fn hash_count<K: Pod, V: Pod>(backend: &RealEbpfBackend, name: &str) -> usize {
    let map = backend.bpf().unwrap().map(name).unwrap();
    HashMap::<_, K, V>::try_from(map)
        .unwrap()
        .keys()
        .map(Result::unwrap)
        .count()
}

fn handoff(backend: &RealEbpfBackend, key: &TuplesKey) -> RoutingHandoffEntry {
    let map = backend.bpf().unwrap().map("ROUTING_HANDOFF_MAP").unwrap();
    HashMap::<_, TuplesKey, RoutingHandoffEntry>::try_from(map)
        .unwrap()
        .get(key, 0)
        .unwrap()
}

fn load_classifier(backend: &mut RealEbpfBackend, name: &str) {
    let program: &mut SchedClassifier = backend
        .bpf_mut()
        .unwrap()
        .program_mut(name)
        .unwrap()
        .try_into()
        .unwrap();
    match program.load() {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
        Err(error) => panic!("load {name}: {error}"),
    }
}

fn run(backend: &RealEbpfBackend, name: &str, packet: &[u8], input: SkbInput) -> Run {
    let program: &SchedClassifier = backend
        .bpf()
        .unwrap()
        .program(name)
        .unwrap()
        .try_into()
        .unwrap();
    let mut context: __sk_buff = unsafe { mem::zeroed() };
    context.mark = input.mark;
    context.ingress_ifindex = input.ingress_ifindex;
    context.ifindex = if input.ifindex == 0 { 1 } else { input.ifindex };
    context.cb = input.cb;
    let context = unsafe {
        std::slice::from_raw_parts(
            (&context as *const __sk_buff).cast::<u8>(),
            mem::size_of::<__sk_buff>(),
        )
    };
    let mut output = vec![0; packet.len() + 64];
    let mut context_out = vec![0; mem::size_of::<__sk_buff>()];
    let result = program
        .test_run(TestRunOptions {
            data_in: Some(packet),
            data_out: Some(&mut output),
            ctx_in: Some(context),
            ctx_out: Some(&mut context_out),
            repeat: 1,
            ..Default::default()
        })
        .unwrap_or_else(|error| panic!("BPF_PROG_TEST_RUN {name}: {error}"));
    let returned: __sk_buff = unsafe { ptr::read_unaligned(context_out.as_ptr().cast()) };
    Run {
        verdict: result.return_value,
        mark: returned.mark,
        cb: returned.cb,
    }
}

fn internet_checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut high = None;
    for chunk in chunks {
        for &byte in *chunk {
            if let Some(high) = high.take() {
                sum += u32::from(u16::from_be_bytes([high, byte]));
            } else {
                high = Some(byte);
            }
        }
    }
    if let Some(high) = high {
        sum += u32::from(high) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn packet(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    source_port: u16,
    destination_port: u16,
    dscp: u8,
    tcp_flags: u8,
) -> Vec<u8> {
    let mut transport = if protocol == IPPROTO_TCP {
        let mut tcp = vec![0u8; 20];
        tcp[..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = tcp_flags;
        tcp
    } else {
        let mut udp = vec![0u8; 9];
        udp[..2].copy_from_slice(&source_port.to_be_bytes());
        udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        let len = udp.len() as u16;
        udp[4..6].copy_from_slice(&len.to_be_bytes());
        udp[8] = 0xa5;
        udp
    };
    let mut bytes = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1];
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            if protocol == IPPROTO_UDP {
                let udp_len = (transport.len() as u16).to_be_bytes();
                let pseudo = [0, protocol, udp_len[0], udp_len[1]];
                let checksum =
                    internet_checksum(&[&src.octets(), &dst.octets(), &pseudo, &transport]);
                transport[6..8].copy_from_slice(
                    &(if checksum == 0 { u16::MAX } else { checksum }).to_be_bytes(),
                );
            }
            bytes.extend_from_slice(&0x0800u16.to_be_bytes());
            let total_len = 20 + transport.len();
            bytes.extend_from_slice(&[
                0x45,
                dscp << 2,
                (total_len >> 8) as u8,
                total_len as u8,
                0,
                0,
                0,
                0,
                64,
                protocol,
                0,
                0,
            ]);
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
            let checksum = internet_checksum(&[&bytes[14..34]]);
            bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            if protocol == IPPROTO_UDP {
                let mut pseudo = [0u8; 8];
                pseudo[..4].copy_from_slice(&(transport.len() as u32).to_be_bytes());
                pseudo[7] = protocol;
                let checksum =
                    internet_checksum(&[&src.octets(), &dst.octets(), &pseudo, &transport]);
                transport[6..8].copy_from_slice(
                    &(if checksum == 0 { u16::MAX } else { checksum }).to_be_bytes(),
                );
            }
            bytes.extend_from_slice(&0x86ddu16.to_be_bytes());
            let traffic_class = dscp << 2;
            bytes.extend_from_slice(&[0x60 | (traffic_class >> 4), traffic_class << 4, 0, 0]);
            bytes.extend_from_slice(&(transport.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&[protocol, 64]);
            bytes.extend_from_slice(&src.octets());
            bytes.extend_from_slice(&dst.octets());
        }
        _ => panic!("mixed address families"),
    }
    bytes.append(&mut transport);
    bytes
}

fn tuple(
    src: IpAddr,
    dst: IpAddr,
    source_port: u16,
    destination_port: u16,
    protocol: u8,
) -> TuplesKey {
    let addr = |ip| match ip {
        IpAddr::V4(ip) => In6Addr::from_ipv4_bytes(ip.octets()),
        IpAddr::V6(ip) => In6Addr::from_ipv6_addr(ip),
    };
    let mut key: TuplesKey = unsafe { mem::zeroed() };
    key.src_ip = addr(src);
    key.dst_ip = addr(dst);
    key.src_port = source_port;
    key.dst_port = destination_port;
    key.l4proto = protocol;
    key
}

fn ip_condition(ip: IpAddr) -> RoutingCondition {
    RoutingCondition {
        ip: vec![ip.to_string()],
        port: vec!["53".into()],
        ..Default::default()
    }
}

fn dns_ordering_rules() -> Vec<honk_config::routing::RoutingRule> {
    vec![
        rule(
            "earlier-nonmust-dns",
            RoutingCondition {
                port: vec!["53".into()],
                dscp: vec!["0".into()],
                ..Default::default()
            },
            "direct",
            0x404,
            false,
        ),
        rule(
            "later-raw-must-dns",
            RoutingCondition {
                port: vec!["53".into()],
                ..Default::default()
            },
            "proxy",
            0x606,
            true,
        ),
    ]
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn dns_direct_must_marks_keep_lan_native_and_reroute_wan_v4_v6_tcp_udp() {
    isolated(|| {
        let destinations = [
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)), 0),
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 54)), USER_MARK),
            ("2001:db8::53".parse().unwrap(), 0),
            ("2001:db8::54".parse().unwrap(), USER_MARK),
        ];
        let rules = destinations
            .iter()
            .enumerate()
            .map(|(index, (destination, mark))| {
                rule(
                    &format!("direct-dns-{index}"),
                    ip_condition(*destination),
                    "direct",
                    *mark,
                    true,
                )
            })
            .collect::<Vec<_>>();
        let (backend, _, _listeners) = publish(&rules);

        for (wan, side) in [(false, "lan_ingress_l2"), (true, "wan_egress_l2")] {
            for (index, (destination, mark)) in destinations.iter().copied().enumerate() {
                let source = match destination {
                    IpAddr::V4(_) => {
                        IpAddr::V4(Ipv4Addr::new(10 + wan as u8, 0, 0, index as u8 + 2))
                    }
                    IpAddr::V6(_) => format!("2001:db9::{:x}", index + 2).parse().unwrap(),
                };
                let redirected = wan && mark != 0;
                let expected_verdict = if redirected {
                    TC_ACT_REDIRECT
                } else {
                    TC_ACT_OK
                };
                let expected_mark = if wan { 0 } else { mark | CLASSIFIED_MARK };
                let before_conn = hash_count::<TuplesKey, ConnState>(&backend, "CONN_STATE_MAP");
                let before_handoff =
                    hash_count::<TuplesKey, RoutingHandoffEntry>(&backend, "ROUTING_HANDOFF_MAP");
                let before_sequence = backend.udp_decision_sequence_status().unwrap();
                let udp = packet(
                    source,
                    destination,
                    IPPROTO_UDP,
                    40000 + index as u16,
                    53,
                    0,
                    0,
                );
                let udp_run = run(&backend, side, &udp, SkbInput::default());
                assert_eq!(
                    udp_run.verdict, expected_verdict,
                    "{side} UDP {destination}"
                );
                assert_eq!(udp_run.mark, expected_mark, "{side} UDP {destination}");
                assert_eq!(
                    hash_count::<TuplesKey, ConnState>(&backend, "CONN_STATE_MAP"),
                    before_conn,
                    "native DNS UDP must not allocate conn state"
                );
                assert_eq!(
                    hash_count::<TuplesKey, RoutingHandoffEntry>(&backend, "ROUTING_HANDOFF_MAP"),
                    before_handoff,
                    "must DNS UDP ownership is per-packet, never a tuple handoff"
                );
                assert_eq!(
                    backend.udp_decision_sequence_status().unwrap(),
                    before_sequence
                );
                if redirected {
                    assert_eq!(
                        UdpDnsRoute::from_mark(udp_run.cb[2]),
                        UdpDnsRoute::direct(0, backend.routing_policy_generation())
                    );
                }

                let source_port = 41000 + index as u16 + (wan as u16) * 100;
                let syn = packet(source, destination, IPPROTO_TCP, source_port, 53, 0, 0x02);
                let following = packet(source, destination, IPPROTO_TCP, source_port, 53, 0, 0x10);
                for (phase, packet) in [("SYN", syn), ("following", following)] {
                    let tcp_run = run(&backend, side, &packet, SkbInput::default());
                    assert_eq!(
                        tcp_run.verdict, expected_verdict,
                        "{side} TCP {phase} {destination}"
                    );
                    assert_eq!(
                        tcp_run.mark, expected_mark,
                        "{side} TCP {phase} {destination}"
                    );
                }
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn dns_block_redirects_nonmust_and_drops_must() {
    isolated(|| {
        for must in [false, true] {
            let rules = [rule(
                "terminal-dns-block",
                RoutingCondition {
                    port: vec!["53".into()],
                    ..Default::default()
                },
                "block",
                0,
                must,
            )];
            let (backend, _, _listeners) = publish(&rules);
            let generation = backend.routing_policy_generation();
            for (wan, side) in [(false, "lan_ingress_l2"), (true, "wan_egress_l2")] {
                for (family, (source, destination)) in [
                    (
                        "IPv4",
                        (
                            IpAddr::V4(Ipv4Addr::new(10 + wan as u8, 1, 0, 2)),
                            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
                        ),
                    ),
                    (
                        "IPv6",
                        (
                            "2001:db9::2".parse().unwrap(),
                            "2001:db8::53".parse().unwrap(),
                        ),
                    ),
                ] {
                    let before_conn =
                        hash_count::<TuplesKey, ConnState>(&backend, "CONN_STATE_MAP");
                    let before_handoff = hash_count::<TuplesKey, RoutingHandoffEntry>(
                        &backend,
                        "ROUTING_HANDOFF_MAP",
                    );
                    let before_sequence = backend.udp_decision_sequence_status().unwrap();
                    let udp_source_port = 42000 + wan as u16;
                    let udp = packet(source, destination, IPPROTO_UDP, udp_source_port, 53, 0, 0);
                    let udp_run = run(&backend, side, &udp, SkbInput::default());
                    if must {
                        assert_eq!(udp_run.verdict, TC_ACT_SHOT, "{side} {family} UDP");
                        assert_eq!(
                            hash_count::<TuplesKey, RoutingHandoffEntry>(
                                &backend,
                                "ROUTING_HANDOFF_MAP"
                            ),
                            before_handoff,
                            "must-block DNS UDP must not publish a handoff"
                        );
                    } else {
                        assert_eq!(udp_run.verdict, TC_ACT_REDIRECT, "{side} {family} UDP");
                        assert_eq!(
                            udp_run.cb[2],
                            UdpDnsRoute::new(OutboundIndex::ControlPlaneRouting as u8, generation,)
                                .unwrap()
                                .to_mark(),
                            "{side} {family} UDP DNS carrier"
                        );
                        let entry = handoff(
                            &backend,
                            &tuple(source, destination, udp_source_port, 53, IPPROTO_UDP),
                        );
                        assert_eq!(
                            entry.result.outbound,
                            OutboundIndex::ControlPlaneRouting as u8
                        );
                        assert_eq!(entry.result.must, 0);
                        assert_eq!(entry.result.mark, 0);
                        assert_eq!(entry.result.decision_token, 0);
                        assert_eq!(entry.routing_generation, 0);
                    }
                    assert_eq!(
                        hash_count::<TuplesKey, ConnState>(&backend, "CONN_STATE_MAP"),
                        before_conn,
                        "DNS UDP must not allocate conn state"
                    );
                    assert_eq!(
                        backend.udp_decision_sequence_status().unwrap(),
                        before_sequence
                    );

                    let source_port = 42100 + wan as u16;
                    let tcp_tuple = tuple(source, destination, source_port, 53, IPPROTO_TCP);
                    let before_tcp_conn =
                        hash_count::<TuplesKey, ConnState>(&backend, "CONN_STATE_MAP");
                    let syn = packet(source, destination, IPPROTO_TCP, source_port, 53, 0, 0x02);
                    let syn_run = run(&backend, side, &syn, SkbInput::default());
                    let expected = if must { TC_ACT_SHOT } else { TC_ACT_REDIRECT };
                    assert_eq!(syn_run.verdict, expected, "{side} {family} TCP SYN");
                    assert_eq!(
                        hash_count::<TuplesKey, ConnState>(&backend, "CONN_STATE_MAP"),
                        before_tcp_conn + 1,
                        "TCP SYN allocates one cached state before its terminal outcome"
                    );
                    if !must {
                        let entry = handoff(&backend, &tcp_tuple);
                        assert_eq!(
                            entry.result.outbound,
                            OutboundIndex::ControlPlaneRouting as u8
                        );
                        assert_eq!(entry.result.must, 0);
                        assert_eq!(entry.result.mark, 0);
                        assert_eq!(entry.result.decision_token, 0);
                        assert_eq!(entry.routing_generation, generation);
                    }
                    let following =
                        packet(source, destination, IPPROTO_TCP, source_port, 53, 0, 0x10);
                    let following_run = run(&backend, side, &following, SkbInput::default());
                    assert_eq!(
                        following_run.verdict, expected,
                        "{side} {family} TCP following"
                    );
                    assert_eq!(
                        hash_count::<TuplesKey, ConnState>(&backend, "CONN_STATE_MAP"),
                        before_tcp_conn + 1,
                        "TCP following packet reuses cached state"
                    );
                    assert_eq!(
                        hash_count::<TuplesKey, RoutingHandoffEntry>(
                            &backend,
                            "ROUTING_HANDOFF_MAP"
                        ),
                        before_handoff + if must { 0 } else { 2 },
                        "TCP handoff accounting follows the terminal outcome"
                    );
                }
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn dns_policy_order_mode_flags_carriers_and_handoff_generation_are_exact() {
    isolated(|| {
        let rules = dns_ordering_rules();
        let (mut backend, plan, _listeners) = publish(&rules);
        load_classifier(&mut backend, "dae0peer_ingress");
        let generation = backend.routing_policy_generation();

        for (index, (source, destination, flags)) in [
            (
                IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
                DATAPATH_FLAG_OFFLOAD_RULE_DIRECT,
            ),
            (
                "2001:db9:2::2".parse().unwrap(),
                "2001:db8:2::53".parse().unwrap(),
                DATAPATH_FLAG_OFFLOAD_ALL,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            backend.set_datapath_flags(flags).unwrap();
            let before = hash_count::<TuplesKey, ConnState>(&backend, "CONN_STATE_MAP");
            let before_handoff =
                hash_count::<TuplesKey, RoutingHandoffEntry>(&backend, "ROUTING_HANDOFF_MAP");
            let initial_sequence = backend.udp_decision_sequence_status().unwrap();
            let source_port = 43000 + index as u16;
            let udp_tuple = tuple(source, destination, source_port, 53, IPPROTO_UDP);
            let raw = packet(source, destination, IPPROTO_UDP, source_port, 53, 46, 0);
            let nonmust = packet(source, destination, IPPROTO_UDP, source_port, 53, 0, 0);
            let raw_route = UdpDnsRoute::new(2, generation).unwrap();
            let nonmust_route =
                UdpDnsRoute::new(OutboundIndex::ControlPlaneRouting as u8, generation).unwrap();

            let raw_run = run(&backend, "lan_ingress_l2", &raw, SkbInput::default());
            assert_eq!(raw_run.verdict, TC_ACT_REDIRECT);
            assert_eq!(raw_run.cb[2], raw_route.to_mark(), "raw {destination}");
            assert_eq!(
                hash_count::<TuplesKey, RoutingHandoffEntry>(&backend, "ROUTING_HANDOFF_MAP"),
                before_handoff,
                "raw UDP DNS must not publish an unused handoff"
            );

            let nonmust_run = run(&backend, "lan_ingress_l2", &nonmust, SkbInput::default());
            assert_eq!(nonmust_run.verdict, TC_ACT_REDIRECT);
            assert_eq!(
                nonmust_run.cb[2],
                nonmust_route.to_mark(),
                "nonmust {destination}"
            );
            assert_ne!(raw_run.cb[2], nonmust_run.cb[2]);
            assert_eq!(
                hash_count::<TuplesKey, RoutingHandoffEntry>(&backend, "ROUTING_HANDOFF_MAP"),
                before_handoff + 1,
                "nonmust UDP DNS publishes its own handoff"
            );
            let nonmust_handoff = handoff(&backend, &udp_tuple);
            assert_eq!(
                nonmust_handoff.result.outbound,
                OutboundIndex::ControlPlaneRouting as u8
            );
            assert_eq!(nonmust_handoff.result.must, 0);
            assert_eq!(nonmust_handoff.result.mark, 0x404);
            assert_eq!(nonmust_handoff.result.dscp, 0);
            assert_eq!(nonmust_handoff.result.decision_token, 0);
            assert_eq!(nonmust_handoff.routing_generation, 0);
            for (label, packet, packet_run, expected) in [
                ("raw", raw.as_slice(), &raw_run, raw_route.to_mark()),
                (
                    "nonmust",
                    nonmust.as_slice(),
                    &nonmust_run,
                    nonmust_route.to_mark(),
                ),
            ] {
                let peer = run(
                    &backend,
                    "dae0peer_ingress",
                    packet,
                    SkbInput {
                        mark: packet_run.mark,
                        cb: packet_run.cb,
                        ..Default::default()
                    },
                );
                assert_eq!(peer.verdict, TC_ACT_OK, "peer {label} {destination}");
                assert_eq!(peer.mark, expected, "peer {label} {destination}");
            }
            assert_eq!(
                hash_count::<TuplesKey, ConnState>(&backend, "CONN_STATE_MAP"),
                before,
                "UDP DNS must not allocate conn state"
            );
            assert_eq!(
                backend.udp_decision_sequence_status().unwrap(),
                initial_sequence
            );

            let udp_control = packet(
                source,
                destination,
                IPPROTO_UDP,
                source_port + 100,
                5353,
                0,
                0,
            );
            let udp_control_run = run(
                &backend,
                "lan_ingress_l2",
                &udp_control,
                SkbInput::default(),
            );
            assert_eq!(udp_control_run.verdict, TC_ACT_OK, "UDP 5353 {destination}");
            assert_eq!(
                udp_control_run.mark, CLASSIFIED_MARK,
                "UDP 5353 {destination}"
            );
            assert_eq!(udp_control_run.cb[2], 0, "5353 is not a DNS carrier");
            let tcp_control = packet(
                source,
                destination,
                IPPROTO_TCP,
                source_port + 101,
                5353,
                0,
                0x02,
            );
            let tcp_control_run = run(
                &backend,
                "lan_ingress_l2",
                &tcp_control,
                SkbInput::default(),
            );
            assert_eq!(tcp_control_run.verdict, TC_ACT_OK, "TCP 5353 {destination}");
            assert_eq!(
                tcp_control_run.mark, CLASSIFIED_MARK,
                "TCP 5353 {destination}"
            );
            assert_eq!(tcp_control_run.cb[2], 0, "5353 is not a DNS carrier");
            let tcp_control_following = packet(
                source,
                destination,
                IPPROTO_TCP,
                source_port + 101,
                5353,
                0,
                0x10,
            );
            let tcp_control_following_run = run(
                &backend,
                "lan_ingress_l2",
                &tcp_control_following,
                SkbInput::default(),
            );
            assert_eq!(
                tcp_control_following_run.verdict, TC_ACT_OK,
                "TCP following 5353 {destination}"
            );
            assert_eq!(
                tcp_control_following_run.mark, CLASSIFIED_MARK,
                "TCP following 5353 {destination}"
            );
            assert_eq!(
                tcp_control_following_run.cb[2], 0,
                "5353 is not a DNS carrier"
            );
            assert_eq!(
                hash_count::<TuplesKey, ConnState>(&backend, "CONN_STATE_MAP"),
                before + 2,
                "5353 follows ordinary TCP/UDP state accounting"
            );

            for (wan, side) in [(false, "lan_ingress_l2"), (true, "wan_egress_l2")] {
                for (must, dscp, expected_outbound, expected_mark) in [
                    (true, 46, 2, 0x606),
                    (false, 0, OutboundIndex::ControlPlaneRouting as u8, 0x404),
                ] {
                    let tcp_port = source_port + 200 + (wan as u16) * 20 + dscp as u16;
                    let syn = packet(source, destination, IPPROTO_TCP, tcp_port, 53, dscp, 0x02);
                    let following =
                        packet(source, destination, IPPROTO_TCP, tcp_port, 53, dscp, 0x10);
                    assert_eq!(
                        run(&backend, side, &syn, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT,
                        "{side} TCP SYN must={must}"
                    );
                    let entry = handoff(
                        &backend,
                        &tuple(source, destination, tcp_port, 53, IPPROTO_TCP),
                    );
                    assert_eq!(entry.result.outbound, expected_outbound);
                    assert_eq!(entry.result.must, must as u8);
                    assert_eq!(entry.result.mark, expected_mark);
                    assert_eq!(entry.result.decision_token, 0);
                    assert_eq!(entry.routing_generation, generation);
                    assert_eq!(
                        run(&backend, side, &following, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT,
                        "{side} TCP following must={must}"
                    );
                }
            }
        }

        backend.publish_routing_plan(&plan, &[]).unwrap();
        let next_generation = backend.routing_policy_generation();
        assert_eq!(next_generation, generation + 1);
        let source = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 9));
        let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53));
        let packet = packet(source, destination, IPPROTO_UDP, 43999, 53, 46, 0);
        let rerouted = run(&backend, "lan_ingress_l2", &packet, SkbInput::default());
        assert_eq!(
            rerouted.cb[2],
            UdpDnsRoute::new(2, next_generation).unwrap().to_mark()
        );
    });
}
