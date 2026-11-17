use super::*;
use crate::topology::{NativeXdpUpdates, Topology};
use std::os::fd::IntoRawFd;

const UPLINK: &str = "hgw_uplink";
const UPLINK_PEER: &str = "hgw_up_peer";

fn fixture() -> GateFixture {
    let fixture = gate_io(GateFixture::with_addresses(true, false));
    gate_io(gate_command(&[
        "link",
        "add",
        UPLINK,
        "type",
        "veth",
        "peer",
        "name",
        UPLINK_PEER,
    ]));
    for device in [UPLINK, UPLINK_PEER] {
        gate_io(gate_command(&[
            "link",
            "set",
            "dev",
            device,
            "addrgenmode",
            "none",
        ]));
        gate_io(gate_command(&["link", "set", "dev", device, "up"]));
    }
    gate_io(gate_command(&[
        "addr",
        "add",
        "198.19.0.2/24",
        "dev",
        UPLINK,
    ]));
    gate_io(gate_command(&[
        "-6",
        "addr",
        "add",
        "2001:db8:b::2/64",
        "dev",
        UPLINK,
        "nodad",
    ]));
    for family in ["-4", "-6"] {
        gate_io(gate_command(&[
            family,
            "rule",
            "add",
            "pref",
            "100",
            "fwmark",
            "128/0xffffffff",
            "table",
            "100",
        ]));
        gate_io(gate_command(&[
            family, "route", "add", "table", "100", "default", "dev", UPLINK,
        ]));
    }
    for family in ["-4", "-6"] {
        let output = gate_io(
            Command::new("ip")
                .args([family, "-o", "addr", "show", "dev", &fixture.device])
                .output(),
        );
        assert!(output.status.success());
        assert!(
            output.stdout.is_empty(),
            "capture must have no address, including link-local"
        );
    }
    let mut topology = gate_io(admit(&fixture, false));
    assert!(!gate_io(topology.check_changed()));
    fixture
}

fn admit(fixture: &GateFixture, attached: bool) -> io::Result<Topology> {
    let capture = [fixture.ifindex];
    if attached {
        Topology::admit_after_xdp_attach(&capture, &capture, 128)
    } else {
        Topology::admit(&capture, &capture, 128)
    }
}

struct Observer(OwnedFd);

impl Observer {
    fn new() -> Self {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        };
        assert!(raw >= 0, "{}", io::Error::last_os_error());
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = 1 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400;
        assert_eq!(
            unsafe {
                libc::bind(
                    raw,
                    (&address as *const libc::sockaddr_nl).cast(),
                    size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
        let group = 19i32;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    raw,
                    270,
                    1,
                    (&group as *const i32).cast(),
                    size_of::<i32>() as u32,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
        Self(fd)
    }

    fn drain(&self) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();
        let mut buffer = vec![0u8; 65_536];
        loop {
            let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut extent = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            let length = unsafe {
                libc::recvfrom(
                    self.0.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                    (&mut source as *mut libc::sockaddr_nl).cast(),
                    &mut extent,
                )
            };
            if length < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::WouldBlock,
                    "observer loss: {error}"
                );
                break;
            }
            assert!(
                length > 0 && length as usize <= buffer.len(),
                "observer truncation"
            );
            assert_eq!(extent as usize, size_of::<libc::sockaddr_nl>());
            assert_eq!(source.nl_pid, 0);
            assert_eq!(source.nl_family, libc::AF_NETLINK as u16);
            let mut bytes = &buffer[..length as usize];
            while !bytes.is_empty() {
                assert!(bytes.len() >= 16);
                let length = word(bytes, 0) as usize;
                assert!(length >= 16 && length <= bytes.len());
                assert_ne!(kind(bytes), 4, "NLMSG_OVERRUN");
                messages.push(bytes[..length].to_vec());
                let advance = (length + 3) & !3;
                assert!(advance <= bytes.len());
                bytes = &bytes[advance..];
            }
            assert!(messages.len() <= 1024, "unexpected notification flood");
        }
        messages
    }

    fn selected(&self, ifindex: u32, program: u32) {
        // veth_xdp_set also notifies the peer when XDP first attaches (netdev_update_features).
        let messages: Vec<_> = self
            .drain()
            .into_iter()
            .filter(|message| {
                kind(message) != 16 || message.len() < 24 || word(message, 20) == ifindex
            })
            .collect();
        assert_eq!(
            messages.len(),
            1,
            "one exact generic message required: {messages:?}"
        );
        let message = &messages[0];
        assert_eq!(kind(message), 16);
        assert_eq!(&message[6..16], &[0; 10]);
        assert_eq!(message[16], 0);
        assert_eq!(message[17], 0);
        assert_eq!(u16::from_ne_bytes(message[18..20].try_into().unwrap()), 1);
        assert_eq!(word(message, 20), ifindex);
        assert_ne!(word(message, 24) & libc::IFF_UP as u32, 0);
        assert_eq!(word(message, 28), 0);
        let mut xdp = None;
        let mut families = Vec::new();
        let mut statistics = 0;
        let mut ipv6_statistics = 0;
        gate_io(gate_bpf::attributes(&message[32..], |attribute, value| {
            match attribute {
                7 => {
                    assert_eq!(value.len(), 96);
                    statistics |= 1;
                }
                23 => {
                    assert_eq!(value.len(), 200);
                    statistics |= 2;
                }
                26 => gate_bpf::attributes(value, |family, nested| {
                    families.push(family);
                    gate_bpf::attributes(nested, |attribute, value| {
                        if family == libc::AF_INET6 as u16 {
                            let schema = match attribute {
                                3 => {
                                    ipv6_statistics |= 1;
                                    Some(38u64)
                                }
                                6 => {
                                    ipv6_statistics |= 2;
                                    Some(7u64)
                                }
                                _ => None,
                            };
                            if let Some(schema) = schema {
                                assert_eq!(value.len(), schema as usize * 8);
                                assert_eq!(
                                    u64::from_ne_bytes(value[..8].try_into().unwrap()),
                                    schema
                                );
                            }
                        }
                        Ok(())
                    })
                })?,
                43 => xdp = Some(gate_bpf::parse_xdp_attributes(value)?),
                _ => {}
            }
            Ok(())
        }));
        assert_eq!(statistics, 3, "generic message omitted link statistics");
        assert_eq!(
            ipv6_statistics, 3,
            "generic message omitted IPv6 statistics schemas"
        );
        assert!(families.contains(&(libc::AF_INET as u16)));
        assert!(families.contains(&(libc::AF_INET6 as u16)));
        gate_io(gate_bpf::require_native(
            xdp.expect("generic XDP nest"),
            program,
        ));
    }

    fn empty(&self) {
        assert!(self.drain().is_empty(), "no SETLINK expected");
    }
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn kind(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes[4..6].try_into().unwrap())
}

fn bind(fixture: &GateFixture, target: &gate_bpf::NativeTarget) -> (Topology, NativeXdpUpdates) {
    let mut topology = gate_io(admit(fixture, true));
    let original_fd = topology.as_raw_fd();
    let budget = honk_netstack::MemoryBudget::new(4 << 20);
    let updates = gate_io(topology.enable_native_xdp_updates(&budget));
    gate_io(target.bind_native_xdp_updates(updates.clone()));
    assert_eq!(
        topology.as_raw_fd(),
        original_fd,
        "binding replaced original watched fd"
    );
    assert_eq!(updates.consumed_operations(), 0);
    assert!(!gate_io(topology.check_changed()));
    (topology, updates)
}

fn closed_traffic(sender: BorrowedFd<'_>, counters: BorrowedFd<'_>, epoch: u64, device: &str) {
    use honk_ebpf_common::xdp::{NativeClosedCounterV1, native_closed_counter_index};
    let index = native_closed_counter_index(epoch, 0).unwrap();
    for ipv6 in [false, true] {
        let before: NativeClosedCounterV1 = gate_io(gate_bpf::map_value(counters, &index));
        gate_io(gate_send(
            sender,
            &gate_frame(ipv6, 41800, b"watch-counter-churn"),
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let after: NativeClosedCounterV1 = gate_io(gate_bpf::map_value(counters, &index));
            assert!(after.is_valid(epoch));
            assert_eq!(after.overflow, 0);
            if after.ordinary_drops == before.ordinary_drops + 1 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "real IPv{family} XDP closed-root traffic missing",
                family = if ipv6 { 6 } else { 4 }
            );
            std::thread::yield_now();
        }
    }
    let ipv6_received = || {
        let counters = gate_io(std::fs::read_to_string(format!(
            "/proc/thread-self/net/dev_snmp6/{device}"
        )));
        counters
            .lines()
            .find_map(|line| {
                let mut words = line.split_whitespace();
                (words.next() == Some("Ip6InReceives"))
                    .then(|| words.next().unwrap().parse::<u64>().unwrap())
            })
            .expect("IPv6 receive statistics")
    };
    let before = ipv6_received();
    let rx_path = format!("/sys/class/net/{device}/statistics/rx_packets");
    let rx_before = gate_io(std::fs::read_to_string(&rx_path))
        .trim()
        .parse::<u64>()
        .unwrap();
    for (source, destination, mac) in [
        ("198.18.0.1:41801", "255.255.255.255:42000", [0xff; 6]),
        (
            "[2001:db8:feed::1]:41801",
            "[ff02::1]:42000",
            [0x33, 0x33, 0, 0, 0, 1],
        ),
    ] {
        gate_io(gate_send(
            sender,
            &packet(
                source.parse().unwrap(),
                destination.parse().unwrap(),
                mac,
                0,
            ),
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let rx_after = gate_io(std::fs::read_to_string(&rx_path))
            .trim()
            .parse::<u64>()
            .unwrap();
        if ipv6_received() > before && rx_after >= rx_before + 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "real link/IPv6 statistics did not change"
        );
        std::thread::yield_now();
    }
}

fn healthy(topology: &mut Topology, updates: &NativeXdpUpdates, consumed: usize) {
    // Read the counter before servicing the owner: success consumed the watched queue synchronously.
    assert_eq!(updates.consumed_operations(), consumed);
    assert!(!gate_io(topology.check_changed()));
    assert!(!gate_io(topology.check_changed()));
}

fn invalidated(topology: &mut Topology) {
    match topology.check_changed() {
        Ok(changed) => assert!(changed, "foreign topology accepted"),
        Err(_) => assert!(gate_io(topology.check_changed())),
    }
    assert!(gate_io(topology.check_changed()), "failure was not sticky");
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_watched_owner_replacements_and_strict_isolation() {
    require_vm();
    let fixture = fixture();
    let mut bootstrap_watch = gate_io(admit(&fixture, false));
    let bootstrap_observer = Observer::new();
    let (programs, attachment) = gate_io(fixture.bootstrap());
    bootstrap_observer.selected(fixture.ifindex, programs.discover_id);
    invalidated(&mut bootstrap_watch);
    let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let target = gate_io(programs.native_target(&gate_io(fixture.capture()), &[], &attachment));
    let maps = gate_io(GateNative::new());
    let first = gate_io(maps.prepare(&target, 2));
    let observer = Observer::new();
    gate_io(first.publish(&target));
    observer.empty();
    gate_io(target.finish_publication());
    gate_io(attachment.replace(&programs));
    observer.selected(fixture.ifindex, first.program_id());
    let (mut topology, updates) = bind(&fixture, &target);
    let mut strict = gate_io(admit(&fixture, true));
    let mut previous = first.program_id();
    for (epoch, count) in [(4, 1), (6, 2)] {
        gate_io(maps.epoch(epoch));
        let next = gate_io(maps.prepare(&target, epoch));
        assert_ne!(previous, next.program_id());
        let sender = gate_io(gate_packet_socket(fixture.peer_ifindex));
        let counters = gate_io(maps.counters.try_clone());
        let device = fixture.device.clone();
        updates.before_next_setter(move || {
            closed_traffic(sender.as_fd(), counters.as_fd(), epoch, &device)
        });
        gate_io(next.publish(&target));
        healthy(&mut topology, &updates, count);
        observer.selected(fixture.ifindex, next.program_id());
        gate_io(gate_bpf::require_native(
            gate_io(gate_bpf::xdp_state(fixture.ifindex)),
            next.program_id(),
        ));
        assert_eq!(
            gate_io(gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)),
            next.tc_program_id()
        );
        gate_singleton(&gate_io(fixture.inventory()), gate.program_id());
        gate_io(target.finish_publication());
        previous = next.program_id();
    }
    invalidated(&mut strict);
    let budget = honk_netstack::MemoryBudget::new(4 << 20);
    assert!(strict.enable_native_xdp_updates(&budget).is_err());
    gate_io(attachment.guard(&programs));
    healthy(&mut topology, &updates, 3);
    observer.selected(fixture.ifindex, programs.discover_id);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_watched_staging_noops_and_recording_withdrawal() {
    require_vm();
    let fixture = fixture();
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let target = gate_io(programs.native_target(&gate_io(fixture.capture()), &[], &attachment));
    let maps = gate_io(GateNative::new());
    let first = gate_io(maps.prepare(&target, 2));
    gate_io(first.publish(&target));
    gate_io(target.finish_publication());
    gate_io(attachment.replace(&programs));
    let (mut topology, updates) = bind(&fixture, &target);
    let observer = Observer::new();
    gate_io(attachment.replace(&programs));
    observer.empty();
    healthy(&mut topology, &updates, 0);
    gate_io(attachment.guard(&programs));
    observer.selected(fixture.ifindex, programs.discover_id);
    healthy(&mut topology, &updates, 1);
    gate_io(attachment.guard(&programs));
    observer.empty();
    healthy(&mut topology, &updates, 1);
    gate_io(maps.epoch(4));
    let next = gate_io(maps.prepare(&target, 4));
    assert_ne!(first.program_id(), next.program_id());
    gate_io(next.publish(&target));
    gate_io(target.finish_publication());
    observer.empty();
    healthy(&mut topology, &updates, 1);
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(fixture.ifindex)),
        programs.discover_id,
    ));
    gate_io(attachment.replace(&programs));
    observer.selected(fixture.ifindex, next.program_id());
    healthy(&mut topology, &updates, 2);
    gate_io(target.withdraw_recording_hooks());
    observer.selected(fixture.ifindex, programs.discover_id);
    healthy(&mut topology, &updates, 3);
    assert_eq!(
        gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    gate_io(target.withdraw_recording_hooks());
    observer.empty();
    healthy(&mut topology, &updates, 3);
    gate_singleton(&gate_io(fixture.inventory()), gate.program_id());
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    Flag,
    Mtu,
    ForeignLinkMtu,
    Address4,
    Address6,
    Route4,
    Route6,
    Rule4,
    Rule6,
    ForeignXdp,
    ReplaceRestore,
    FlagAndXdp,
    MtuAndXdp,
    PinnedReplay,
}

struct MutationContext {
    device: String,
    ifindex: u32,
    old: OwnedFd,
    old_id: u32,
    foreign: OwnedFd,
    foreign_id: u32,
    pinned: OwnedFd,
    pinned_id: u32,
}

impl MutationContext {
    fn new(fixture: &GateFixture, first: &gate_bpf::NativePrograms) -> Self {
        let (foreign, foreign_id) =
            gate_io(gate_program(gate_bpf::BPF_PROG_TYPE_XDP, b"hgw_foreign"));
        let root = gate_io(gate_bpf::private_bpffs(&fixture.pins));
        let pinned = gate_io(gate_open(root.as_fd(), c"guard"));
        let mut info = gate_bpf::ProgInfo::default();
        gate_io(gate_bpf::object_info(pinned.as_fd(), &mut info));
        Self {
            device: fixture.device.clone(),
            ifindex: fixture.ifindex,
            old: gate_io(first.xdp_program.try_clone()),
            old_id: first.program_id(),
            foreign,
            foreign_id,
            pinned,
            pinned_id: info.id,
        }
    }

    fn selected(&self, program: BorrowedFd<'_>, expected: BorrowedFd<'_>) {
        gate_io(
            gate_bpf::set_xdp(
                self.ifindex,
                program.as_raw_fd(),
                Some(expected.as_raw_fd()),
            )
            .map_err(io::Error::from),
        );
    }
}

fn output_contains(args: &[&str], value: &str) {
    let output = gate_io(Command::new("ip").args(args).output());
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(value),
        "{args:?}: {output:?}"
    );
}

fn combined(context: &MutationContext, mtu: bool) {
    let (request, length) = gate_bpf::xdp_update_request(
        context.ifindex,
        context.foreign.as_raw_fd(),
        Some(context.old.as_raw_fd()),
    );
    let mut request = request[..length].to_vec();
    if mtu {
        request.extend_from_slice(&8u16.to_ne_bytes());
        request.extend_from_slice(&4u16.to_ne_bytes());
        request.extend_from_slice(&1400u32.to_ne_bytes());
    } else {
        request[24..28].copy_from_slice(&(libc::IFF_PROMISC as u32).to_ne_bytes());
        request[28..32].copy_from_slice(&(libc::IFF_PROMISC as u32).to_ne_bytes());
    }
    let length = request.len() as u32;
    request[..4].copy_from_slice(&length.to_ne_bytes());
    gate_io(gate_bpf::exchange_netlink(&request, |bytes| {
        gate_bpf::parse_setlink_ack(bytes, 1)
    }));
}

impl Mutation {
    fn foreign_selected(self) -> bool {
        matches!(
            self,
            Self::ForeignXdp | Self::FlagAndXdp | Self::MtuAndXdp | Self::PinnedReplay
        )
    }

    fn apply(self, context: &MutationContext) {
        let device = context.device.as_str();
        match self {
            Self::Flag => gate_io(gate_command(&[
                "link", "set", "dev", device, "promisc", "on",
            ])),
            Self::Mtu => gate_io(gate_command(&["link", "set", "dev", device, "mtu", "1400"])),
            Self::ForeignLinkMtu => {
                gate_io(gate_command(&["link", "set", "dev", UPLINK, "mtu", "1400"]))
            }
            Self::Address4 => gate_io(gate_command(&[
                "-4",
                "addr",
                "add",
                "192.0.2.9/32",
                "dev",
                device,
            ])),
            Self::Address6 => gate_io(gate_command(&[
                "-6",
                "addr",
                "add",
                "2001:db8:c::9/128",
                "dev",
                device,
                "nodad",
            ])),
            Self::Route4 | Self::Route6 => {
                let (family, prefix) = self.route();
                gate_io(gate_command(&[
                    family, "route", "add", prefix, "dev", UPLINK,
                ]));
            }
            Self::Rule4 | Self::Rule6 => {
                gate_io(gate_command(&[
                    self.family(),
                    "rule",
                    "add",
                    "pref",
                    "101",
                    "table",
                    "254",
                ]));
            }
            Self::ForeignXdp | Self::ReplaceRestore => {
                context.selected(context.foreign.as_fd(), context.old.as_fd())
            }
            Self::FlagAndXdp => combined(context, false),
            Self::MtuAndXdp => combined(context, true),
            Self::PinnedReplay => context.selected(context.pinned.as_fd(), context.old.as_fd()),
        }
        match self {
            Self::Flag | Self::FlagAndXdp => {
                let flags = gate_io(std::fs::read_to_string(format!(
                    "/sys/class/net/{device}/flags"
                )));
                let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap();
                assert_ne!(flags & libc::IFF_PROMISC as u32, 0);
            }
            Self::Mtu | Self::MtuAndXdp | Self::ForeignLinkMtu => {
                let device = if matches!(self, Self::ForeignLinkMtu) {
                    UPLINK
                } else {
                    device
                };
                assert_eq!(
                    gate_io(std::fs::read_to_string(format!(
                        "/sys/class/net/{device}/mtu"
                    )))
                    .trim(),
                    "1400"
                );
            }
            Self::Address4 => {
                output_contains(&["-4", "-o", "addr", "show", "dev", device], "192.0.2.9/32")
            }
            Self::Address6 => output_contains(
                &["-6", "-o", "addr", "show", "dev", device],
                "2001:db8:c::9/128",
            ),
            Self::Route4 | Self::Route6 => {
                let (family, prefix) = self.route();
                output_contains(&[family, "route", "show", "exact", prefix], prefix);
            }
            Self::Rule4 | Self::Rule6 => output_contains(&[self.family(), "rule", "show"], "101:"),
            _ => {}
        }
        if self.foreign_selected() || matches!(self, Self::ReplaceRestore) {
            let expected = if matches!(self, Self::PinnedReplay) {
                context.pinned_id
            } else {
                context.foreign_id
            };
            gate_io(gate_bpf::require_native(
                gate_io(gate_bpf::xdp_state(context.ifindex)),
                expected,
            ));
        }
        if matches!(self, Self::ReplaceRestore) {
            context.selected(context.old.as_fd(), context.foreign.as_fd());
            gate_io(gate_bpf::require_native(
                gate_io(gate_bpf::xdp_state(context.ifindex)),
                context.old_id,
            ));
        }
    }

    fn revert(self, context: &MutationContext) {
        let device = context.device.as_str();
        if self.foreign_selected() {
            let expected = if matches!(self, Self::PinnedReplay) {
                context.pinned.as_fd()
            } else {
                context.foreign.as_fd()
            };
            context.selected(context.old.as_fd(), expected);
        }
        match self {
            Self::Flag | Self::FlagAndXdp => gate_io(gate_command(&[
                "link", "set", "dev", device, "promisc", "off",
            ])),
            Self::Mtu | Self::MtuAndXdp => {
                gate_io(gate_command(&["link", "set", "dev", device, "mtu", "1500"]))
            }
            Self::ForeignLinkMtu => {
                gate_io(gate_command(&["link", "set", "dev", UPLINK, "mtu", "1500"]))
            }
            Self::Address4 => gate_io(gate_command(&[
                "-4",
                "addr",
                "del",
                "192.0.2.9/32",
                "dev",
                device,
            ])),
            Self::Address6 => gate_io(gate_command(&[
                "-6",
                "addr",
                "del",
                "2001:db8:c::9/128",
                "dev",
                device,
            ])),
            Self::Route4 | Self::Route6 => {
                let (family, prefix) = self.route();
                gate_io(gate_command(&[
                    family, "route", "del", prefix, "dev", UPLINK,
                ]));
            }
            Self::Rule4 | Self::Rule6 => gate_io(gate_command(&[
                self.family(),
                "rule",
                "del",
                "pref",
                "101",
                "table",
                "254",
            ])),
            _ => {}
        }
    }

    fn family(self) -> &'static str {
        if matches!(self, Self::Route6 | Self::Rule6) {
            "-6"
        } else {
            "-4"
        }
    }

    fn route(self) -> (&'static str, &'static str) {
        if matches!(self, Self::Route6) {
            ("-6", "2001:db8:c::/64")
        } else {
            ("-4", "203.0.113.0/24")
        }
    }

    fn observed(self, context: &MutationContext, messages: &[Vec<u8>]) {
        let (expected_kind, family) = match self {
            Self::Address4 => (20, Some(2)),
            Self::Address6 => (20, Some(10)),
            Self::Route4 => (24, Some(2)),
            Self::Route6 => (24, Some(10)),
            Self::Rule4 => (32, Some(2)),
            Self::Rule6 => (32, Some(10)),
            _ => (16, None),
        };
        let ifindex = if matches!(self, Self::ForeignLinkMtu) {
            gate_io(gate_index(UPLINK))
        } else {
            context.ifindex
        };
        assert!(
            messages.iter().any(|message| {
                if kind(message) != expected_kind
                    || family.is_some_and(|family| message[16] != family)
                {
                    return false;
                }
                if expected_kind != 16 {
                    return true;
                }
                if word(message, 20) != ifindex {
                    return false;
                }
                let flag = word(message, 24) & libc::IFF_PROMISC as u32 != 0;
                let mut mtu = false;
                let mut selected = false;
                gate_io(gate_bpf::attributes(&message[32..], |attribute, value| {
                    if attribute == 4 {
                        mtu = word(value, 0) == 1400;
                    }
                    if attribute == 43 {
                        let state = gate_bpf::parse_xdp_attributes(value)?;
                        let id = if matches!(self, Self::PinnedReplay) {
                            context.pinned_id
                        } else {
                            context.foreign_id
                        };
                        selected = state.prog_id == id && state.drv_prog_id == id;
                    }
                    Ok(())
                }));
                match self {
                    Self::Flag => flag,
                    Self::Mtu | Self::ForeignLinkMtu => mtu,
                    Self::FlagAndXdp => selected && flag,
                    Self::MtuAndXdp => selected && mtu,
                    _ => selected,
                }
            }),
            "{self:?} independent mutation notification missing: {messages:?}"
        );
        if matches!(self, Self::ReplaceRestore) {
            assert!(
                messages.iter().any(|message| {
                    let mut restored = false;
                    if kind(message) == 16 && word(message, 20) == context.ifindex {
                        gate_io(gate_bpf::attributes(&message[32..], |attribute, value| {
                            if attribute == 43 {
                                restored = gate_bpf::parse_xdp_attributes(value)?.prog_id
                                    == context.old_id;
                            }
                            Ok(())
                        }));
                    }
                    restored
                }),
                "foreign restore lacked independent old-ID notification"
            );
        }
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_watched_foreign_mutations_are_sticky() {
    require_vm();
    for mutation in [
        Mutation::Flag,
        Mutation::Mtu,
        Mutation::ForeignLinkMtu,
        Mutation::Address4,
        Mutation::Address6,
        Mutation::Route4,
        Mutation::Route6,
        Mutation::Rule4,
        Mutation::Rule6,
        Mutation::ForeignXdp,
        Mutation::ReplaceRestore,
        Mutation::FlagAndXdp,
        Mutation::MtuAndXdp,
        Mutation::PinnedReplay,
    ] {
        for armed in [false, true] {
            let fixture = fixture();
            let (programs, attachment) = gate_io(fixture.bootstrap());
            let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
            let target =
                gate_io(programs.native_target(&gate_io(fixture.capture()), &[], &attachment));
            let maps = gate_io(GateNative::new());
            let first = gate_io(maps.prepare(&target, 2));
            gate_io(first.publish(&target));
            gate_io(target.finish_publication());
            gate_io(attachment.replace(&programs));
            let context = MutationContext::new(&fixture, &first);
            let (mut topology, updates) = bind(&fixture, &target);
            let observer = Observer::new();
            gate_io(maps.epoch(4));
            let next = gate_io(maps.prepare(&target, 4));
            let tc = gate_io(gate_bpf::map_value::<u32>(target.dispatch_fd(), &1));
            let result = if armed {
                let (start, entered) = std::sync::mpsc::sync_channel(0);
                let (completed, finish) = std::sync::mpsc::sync_channel(0);
                updates.before_next_setter(move || {
                    start.send(()).unwrap();
                    finish
                        .recv_timeout(Duration::from_secs(10))
                        .expect("foreign mutation completion");
                });
                std::thread::scope(|scope| {
                    let context = &context;
                    let worker = scope.spawn(move || {
                        entered
                            .recv_timeout(Duration::from_secs(10))
                            .expect("armed setter frontier");
                        // Always release the setter barrier, including assertion failure.
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                mutation.apply(context)
                            }));
                        completed.send(()).unwrap();
                        if let Err(panic) = outcome {
                            std::panic::resume_unwind(panic);
                        }
                    });
                    let result = next.publish(&target);
                    worker.join().unwrap();
                    result
                })
            } else {
                mutation.apply(&context);
                next.publish(&target)
            };
            assert!(result.is_err(), "{mutation:?}, armed={armed} was accepted");
            mutation.observed(&context, &observer.drain());
            assert_eq!(
                updates.consumed_operations(),
                0,
                "failed operation earned consumption"
            );
            assert_eq!(
                gate_io(gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)),
                tc,
                "failed XDP observation published TC candidate"
            );
            let selected = gate_io(gate_bpf::xdp_state(fixture.ifindex)).prog_id;
            if armed && !mutation.foreign_selected() {
                assert_eq!(
                    selected,
                    next.program_id(),
                    "successful ACK selection was rolled back"
                );
                let inventory = gate_io(fixture.inventory());
                assert!(
                    inventory
                        .pins
                        .iter()
                        .any(|pin| pin.0 == "data" && pin.2 == next.program_id()),
                    "ACK success did not promote actual selected data pin"
                );
            }
            if mutation.foreign_selected() {
                assert!(
                    attachment.guard(&programs).is_err(),
                    "owner overrode foreign selection"
                );
                assert_eq!(
                    gate_io(gate_bpf::xdp_state(fixture.ifindex)).prog_id,
                    selected
                );
            }
            invalidated(&mut topology);
            mutation.revert(&context);
            let mut fresh = gate_io(admit(&fixture, true));
            assert!(
                !gate_io(fresh.check_changed()),
                "fixture did not restore normal topology"
            );
            invalidated(&mut topology);
            assert!(
                next.publish(&target).is_err(),
                "later legitimate update cleared sticky failure"
            );
            assert!(
                attachment.replace(&programs).is_err(),
                "sticky watch reopened activation"
            );
            if !mutation.foreign_selected() {
                assert!(
                    target.withdraw_recording_hooks().is_err(),
                    "terminal cleanup lost topology error"
                );
                gate_io(gate_bpf::require_native(
                    gate_io(gate_bpf::xdp_state(fixture.ifindex)),
                    programs.discover_id,
                ));
                assert_eq!(
                    gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::ENOENT),
                    "sticky guard error prevented recording withdrawal"
                );
            }
            invalidated(&mut topology);
            gate_singleton(&gate_io(fixture.inventory()), gate.program_id());
        }
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_setlink_up_down_and_rejected_ack_cardinality() {
    require_vm();
    for up in [true, false] {
        let fixture = fixture();
        let (programs, _attachment) = gate_io(fixture.bootstrap());
        if !up {
            gate_io(gate_command(&[
                "link",
                "set",
                "dev",
                &fixture.device,
                "down",
            ]));
            assert!(
                admit(&fixture, false).is_err(),
                "DOWN live capture became admissible"
            );
        }
        let observer = Observer::new();
        let (next, id) = gate_io(gate_program(gate_bpf::BPF_PROG_TYPE_XDP, b"hgw_primitive"));
        gate_io(
            gate_bpf::set_xdp(
                fixture.ifindex,
                next.as_raw_fd(),
                Some(programs.discover.as_raw_fd()),
            )
            .map_err(io::Error::from),
        );
        gate_io(gate_bpf::require_native(
            gate_io(gate_bpf::xdp_state(fixture.ifindex)),
            id,
        ));
        if up {
            observer.selected(fixture.ifindex, id);
        } else {
            observer.empty();
        }
        gate_io(
            gate_bpf::set_xdp(fixture.ifindex, next.as_raw_fd(), Some(next.as_raw_fd()))
                .map_err(io::Error::from),
        );
        if up {
            observer.selected(fixture.ifindex, id);
        } else {
            observer.empty();
        }
        let rejected = gate_bpf::set_xdp(
            fixture.ifindex,
            programs.discover.as_raw_fd(),
            Some(programs.discover.as_raw_fd()),
        );
        assert!(
            matches!(rejected, Err(gate_bpf::XdpUpdateError::Rejected(_))),
            "expected-old mismatch did not produce a rejected ACK"
        );
        observer.empty();
        gate_io(gate_bpf::require_native(
            gate_io(gate_bpf::xdp_state(fixture.ifindex)),
            id,
        ));
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_watched_real_receive_loss_is_terminal() {
    require_vm();
    let fixture = fixture();
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let _gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let target = gate_io(programs.native_target(&gate_io(fixture.capture()), &[], &attachment));
    let maps = gate_io(GateNative::new());
    let first = gate_io(maps.prepare(&target, 2));
    gate_io(first.publish(&target));
    gate_io(target.finish_publication());
    gate_io(attachment.replace(&programs));
    let (mut topology, updates) = bind(&fixture, &target);
    let capacity = 4096i32;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                topology.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&capacity as *const i32).cast(),
                size_of::<i32>() as libc::socklen_t,
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
    let observer = Observer::new();
    for index in 0..128 {
        let mtu = if index & 1 == 0 { "1400" } else { "1500" };
        gate_io(gate_command(&[
            "link",
            "set",
            "dev",
            &fixture.device,
            "mtu",
            mtu,
        ]));
        let messages = observer.drain();
        assert!(
            messages
                .iter()
                .any(|message| kind(message) == 16 && word(message, 20) == fixture.ifindex)
        );
    }
    let error = topology
        .check_changed()
        .expect_err("bounded watched socket did not report real receive loss");
    assert_eq!(
        error.raw_os_error(),
        Some(libc::ENOBUFS),
        "loss injection did not reach ENOBUFS"
    );
    invalidated(&mut topology);
    assert_eq!(updates.consumed_operations(), 0);
    gate_io(maps.epoch(4));
    let next = gate_io(maps.prepare(&target, 4));
    assert!(next.publish(&target).is_err());
    assert!(target.withdraw_recording_hooks().is_err());
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
    invalidated(&mut topology);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_watched_guard_errors_preserve_terminal_withdrawal() {
    require_vm();
    for frontier in ["fresh-precheck", "already-invalidated", "after-ack"] {
        let fixture = fixture();
        let (programs, attachment) = gate_io(fixture.bootstrap());
        let gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
        let target = gate_io(programs.native_target(&gate_io(fixture.capture()), &[], &attachment));
        let maps = gate_io(GateNative::new());
        let first = gate_io(maps.prepare(&target, 2));
        gate_io(first.publish(&target));
        gate_io(target.finish_publication());
        gate_io(attachment.replace(&programs));
        let (mut topology, updates) = bind(&fixture, &target);
        let observer = Observer::new();
        gate_io(maps.epoch(4));
        let mutate = {
            let device = fixture.device.clone();
            move || {
                gate_io(gate_command(&[
                    "link", "set", "dev", &device, "mtu", "1400",
                ]))
            }
        };
        if frontier == "after-ack" {
            updates.before_next_setter(mutate);
        } else {
            mutate();
            if frontier == "already-invalidated" {
                invalidated(&mut topology);
            }
        }
        assert!(
            target.withdraw_recording_hooks().is_err(),
            "{frontier} lost topology error"
        );
        assert_eq!(updates.consumed_operations(), 0);
        gate_io(gate_bpf::require_native(
            gate_io(gate_bpf::xdp_state(fixture.ifindex)),
            programs.discover_id,
        ));
        let messages = observer.drain();
        let guards = messages
            .iter()
            .filter(|message| {
                let mut selected = false;
                if kind(message) == 16 && word(message, 20) == fixture.ifindex {
                    gate_io(gate_bpf::attributes(&message[32..], |attribute, value| {
                        if attribute == 43 {
                            selected = gate_bpf::parse_xdp_attributes(value)?.prog_id
                                == programs.discover_id;
                        }
                        Ok(())
                    }));
                }
                selected
            })
            .count();
        assert_eq!(
            guards, 1,
            "terminal guard did not issue exactly one real selection"
        );
        assert_eq!(
            gate_bpf::map_value::<u32>(target.dispatch_fd(), &1)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
        invalidated(&mut topology);
        assert!(target.withdraw_recording_hooks().is_err());
        observer.empty();
        invalidated(&mut topology);
        gate_singleton(&gate_io(fixture.inventory()), gate.program_id());
    }
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_gate_watched_activation_error_retains_actual_selection() {
    require_vm();
    let fixture = fixture();
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let _gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let target = gate_io(programs.native_target(&gate_io(fixture.capture()), &[], &attachment));
    let maps = gate_io(GateNative::new());
    let first = gate_io(maps.prepare(&target, 2));
    gate_io(first.publish(&target));
    gate_io(target.finish_publication());
    gate_io(attachment.replace(&programs));
    let (mut topology, updates) = bind(&fixture, &target);
    let observer = Observer::new();
    gate_io(attachment.guard(&programs));
    observer.selected(fixture.ifindex, programs.discover_id);
    healthy(&mut topology, &updates, 1);
    gate_io(maps.epoch(4));
    let next = gate_io(maps.prepare(&target, 4));
    gate_io(next.publish(&target));
    gate_io(target.finish_publication());
    observer.empty();
    let device = fixture.device.clone();
    updates.before_next_setter(move || {
        gate_io(gate_command(&[
            "link", "set", "dev", &device, "mtu", "1400",
        ]));
    });
    assert!(
        attachment.replace(&programs).is_err(),
        "activation observation error was suppressed"
    );
    assert_eq!(
        updates.consumed_operations(),
        1,
        "failed activation gained notification credit"
    );
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(fixture.ifindex)),
        next.program_id(),
    ));
    let messages = observer.drain();
    assert_eq!(
        messages.len(),
        2,
        "foreign MTU plus actual data selection must both be observed"
    );
    assert!(messages.iter().any(|message| {
        let mut selected = false;
        if kind(message) == 16 && word(message, 20) == fixture.ifindex {
            gate_io(gate_bpf::attributes(&message[32..], |attribute, value| {
                if attribute == 43 {
                    selected = gate_bpf::parse_xdp_attributes(value)?.prog_id == next.program_id();
                }
                Ok(())
            }));
        }
        selected
    }));
    invalidated(&mut topology);
    assert!(target.withdraw_recording_hooks().is_err());
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
    invalidated(&mut topology);
}

fn captured_bound() -> (
    GateFixture,
    Programs,
    GateCaptured,
    Topology,
    NativeXdpUpdates,
) {
    let fixture = fixture();
    let (programs, attachment) = gate_io(fixture.bootstrap());
    let _gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
    let target = gate_io(programs.native_target(&gate_io(fixture.capture()), &[], &attachment));
    let mut maps = gate_io(GateNative::new());
    let captured = gate_io(GateCaptured::new(
        &fixture.directory,
        target.clone(),
        &mut maps,
    ));
    let first = gate_io(maps.prepare_captured(&target, 2, &captured.config()));
    gate_io(first.publish(&target));
    gate_io(target.finish_publication());
    gate_io(attachment.replace(&programs));
    let (topology, updates) = bind(&fixture, &target);
    (fixture, programs, captured, topology, updates)
}

fn captured_id(captured: &GateCaptured, role: &str) -> u32 {
    captured
        .loaded
        .inventory()
        .iter()
        .find(|item| item.role == role)
        .unwrap()
        .id
}

fn close_owned_tap(tap: &mut Option<OwnedFd>) -> io::Result<()> {
    let fd = tap
        .take()
        .expect("TAP callback invoked twice")
        .into_raw_fd();
    if unsafe { libc::close(fd) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_captured_watched_terminal_transitions() {
    require_vm();
    let (fixture, programs, captured, mut topology, updates) = captured_bound();
    let tap_index = captured.loaded.tap_ifindex();
    let guard = captured_id(&captured, "tap-xdp-guard");
    let tc_guard = captured_id(&captured, "tap-tcx-guard-prog");
    let map_identity = (
        captured.loaded.root_map_id(),
        captured.loaded.operation_map_id(),
    );
    let observer = Observer::new();
    gate_io(captured.loaded.seal());
    healthy(&mut topology, &updates, 1);
    observer.selected(tap_index, guard);
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(tap_index)),
        guard,
    ));
    gate_io(gate_bpf::require_gate_tcx(
        &gate_io(gate_bpf::query_tcx(tap_index, gate_bpf::BPF_TCX_INGRESS)),
        &gate_io(gate_bpf::query_tcx(tap_index, gate_bpf::BPF_TCX_EGRESS)),
        tc_guard,
    ));
    gate_io(captured.loaded.seal());
    observer.empty();
    healthy(&mut topology, &updates, 1);
    assert!(gate_io(captured.loaded.finish_close()));
    healthy(&mut topology, &updates, 2);
    let detached = observer.drain();
    assert_eq!(
        detached.len(),
        1,
        "guard detach did not emit one real notification"
    );
    assert_eq!(
        (kind(&detached[0]), word(&detached[0], 20)),
        (16, tap_index)
    );
    assert!(gate_io(gate_bpf::xdp_absent(tap_index)));
    assert!(gate_io(captured.pin_inventory()).is_empty());
    assert!(
        captured
            .loaded
            .inventory()
            .iter()
            .all(|item| item.state != gate_bpf::CapturedResourceState::Installed)
    );
    assert_eq!(
        (
            captured.loaded.root_map_id(),
            captured.loaded.operation_map_id()
        ),
        map_identity
    );
    let loaded = captured.loaded.clone();
    let mut tap = Some(captured._tap);
    let fd = tap.as_ref().unwrap().as_raw_fd();
    gate_io(loaded.close_tap(fd, || close_owned_tap(&mut tap)));
    assert!(tap.is_none(), "authenticated last FD was not consumed");
    healthy(&mut topology, &updates, 3);
    let deleted = observer.drain();
    assert_eq!(
        deleted
            .iter()
            .map(|message| (kind(message), word(message, 20)))
            .collect::<Vec<_>>(),
        [(16, tap_index), (17, tap_index)]
    );
    assert_eq!(
        gate_bpf::xdp_state(tap_index).unwrap_err().raw_os_error(),
        Some(libc::ENODEV)
    );
    let target = &loaded.targets()[0].target;
    gate_io(target.withdraw_recording_hooks());
    healthy(&mut topology, &updates, 4);
    observer.selected(fixture.ifindex, programs.discover_id);
    assert_eq!(gate_candidate_slot(target.dispatch_fd()), None);
    assert!(gate_io(loaded.finish_close()));
    healthy(&mut topology, &updates, 4);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_captured_watched_foreign_close_is_sticky() {
    require_vm();
    for stage in ["seal", "detach", "tap-close"] {
        for during in [false, true] {
            let (fixture, _programs, captured, mut topology, updates) = captured_bound();
            let tap_index = captured.loaded.tap_ifindex();
            let guard = captured_id(&captured, "tap-xdp-guard");
            let tc_guard = captured_id(&captured, "tap-tcx-guard-prog");
            if stage != "seal" {
                gate_io(captured.loaded.seal());
            }
            if stage == "tap-close" {
                assert!(gate_io(captured.loaded.finish_close()));
            }
            let expected = match stage {
                "seal" => 0,
                "detach" => 1,
                _ => 2,
            };
            let before = captured.loaded.inventory();
            let loaded = captured.loaded.clone();
            let mut tap = Some(captured._tap);
            let fd = tap.as_ref().unwrap().as_raw_fd();
            let device = fixture.device.clone();
            let mutate = move || {
                gate_io(gate_command(&[
                    "link", "set", "dev", &device, "mtu", "1400",
                ]))
            };
            if during {
                updates.before_next_setter(mutate);
            } else {
                mutate();
            }
            let result = match stage {
                "seal" => loaded.seal(),
                "detach" => loaded.finish_close().map(|joined| assert!(joined)),
                _ => loaded.close_tap(fd, || close_owned_tap(&mut tap)),
            };
            assert!(
                result.is_err(),
                "foreign change accepted at {stage}, during={during}"
            );
            assert_eq!(updates.consumed_operations(), expected);
            if stage == "seal" || stage == "detach" && !during {
                gate_io(gate_bpf::require_native(
                    gate_io(gate_bpf::xdp_state(tap_index)),
                    guard,
                ));
                gate_io(gate_bpf::require_gate_tcx(
                    &gate_io(gate_bpf::query_tcx(tap_index, gate_bpf::BPF_TCX_INGRESS)),
                    &gate_io(gate_bpf::query_tcx(tap_index, gate_bpf::BPF_TCX_EGRESS)),
                    tc_guard,
                ));
            }
            if stage == "tap-close" && during {
                assert!(
                    tap.is_none(),
                    "actual close mutation was lost after observation failure"
                );
                assert_eq!(
                    gate_bpf::xdp_state(tap_index).unwrap_err().raw_os_error(),
                    Some(libc::ENODEV)
                );
            } else {
                assert!(tap.is_some(), "uninvoked callback consumed the owned TAP");
                assert!(gate_bpf::xdp_state(tap_index).is_ok());
            }
            invalidated(&mut topology);
            assert!(
                loaded.finish_close().is_err(),
                "repeated failed close was rehabilitated"
            );
            let called = std::cell::Cell::new(false);
            assert!(
                loaded
                    .close_tap(fd, || {
                        called.set(true);
                        Ok(())
                    })
                    .is_err()
            );
            assert!(
                !called.get(),
                "failed private close invoked another close callback"
            );
            assert_eq!(updates.consumed_operations(), expected);
            for item in before
                .iter()
                .filter(|item| item.state == gate_bpf::CapturedResourceState::Installed)
            {
                assert!(
                    gate_io(item.pin_path.try_exists()),
                    "failed close removed owned pin {}",
                    item.pin_path.display()
                );
            }
            invalidated(&mut topology);
        }
    }
    let (fixture, programs, captured, mut topology, updates) = captured_bound();
    gate_io(captured.loaded.seal());
    assert!(gate_io(captured.loaded.finish_close()));
    let loaded = captured.loaded.clone();
    let mut tap = Some(captured._tap);
    let fd = tap.as_ref().unwrap().as_raw_fd();
    gate_io(loaded.close_tap(fd, || close_owned_tap(&mut tap)));
    healthy(&mut topology, &updates, 3);
    gate_io(gate_command(&[
        "link",
        "set",
        "dev",
        &fixture.device,
        "mtu",
        "1400",
    ]));
    let target = &loaded.targets()[0].target;
    assert!(
        target.withdraw_recording_hooks().is_err(),
        "post-TAP foreign change was accepted at final withdrawal"
    );
    assert_eq!(gate_candidate_slot(target.dispatch_fd()), None);
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(fixture.ifindex)),
        programs.discover_id,
    ));
    assert_eq!(updates.consumed_operations(), 3);
    assert!(loaded.finish_close().is_err());
    invalidated(&mut topology);
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_captured_watched_tap_close_custody() {
    require_vm();
    let (_fixture, _programs, captured, mut topology, updates) = captured_bound();
    gate_io(captured.loaded.seal());
    assert!(gate_io(captured.loaded.finish_close()));
    let tap_index = captured.loaded.tap_ifindex();
    let loaded = captured.loaded.clone();
    let mut tap = Some(captured._tap);
    let fd = tap.as_ref().unwrap().as_raw_fd();
    let foreign = gate_io(std::fs::File::open("/dev/null"));
    let called = std::cell::Cell::new(0);
    assert!(
        loaded
            .close_tap(foreign.as_raw_fd(), || {
                called.set(called.get() + 1);
                close_owned_tap(&mut tap)
            })
            .is_err()
    );
    assert_eq!(called.get(), 0);
    assert!(tap.is_some());
    assert!(gate_bpf::xdp_state(tap_index).is_ok());
    healthy(&mut topology, &updates, 2);
    let result = loaded.close_tap(fd, || {
        called.set(called.get() + 1);
        close_owned_tap(&mut tap)?;
        Err(io::Error::from_raw_os_error(libc::EIO))
    });
    assert!(
        result.is_err(),
        "consumed error-returning close gained joined success"
    );
    assert_eq!(called.get(), 1);
    assert!(tap.is_none());
    assert_eq!(
        gate_bpf::xdp_state(tap_index).unwrap_err().raw_os_error(),
        Some(libc::ENODEV)
    );
    assert_eq!(updates.consumed_operations(), 2);
    assert!(
        loaded
            .close_tap(fd, || {
                called.set(called.get() + 1);
                Ok(())
            })
            .is_err()
    );
    assert_eq!(called.get(), 1, "consumed FD close was retried");
    assert!(loaded.finish_close().is_err());
    invalidated(&mut topology);
}

fn captured_program(captured: &GateCaptured, role: &str) -> OwnedFd {
    let inventory = captured.loaded.inventory();
    let item = inventory.iter().find(|item| item.role == role).unwrap();
    let root = gate_io(gate_bpf::private_bpffs(item.pin_path.parent().unwrap()));
    let name = CString::new(item.pin_path.file_name().unwrap().as_encoded_bytes()).unwrap();
    let fd = gate_io(gate_open(root.as_fd(), &name));
    let mut info = gate_bpf::ProgInfo::default();
    gate_io(gate_bpf::object_info(fd.as_fd(), &mut info));
    assert_eq!(info.id, item.id);
    fd
}

#[test]
#[ignore = "requires root in a disposable virtme guest private netns"]
fn kernel_native_captured_watched_composition_failure_contains_independently() {
    require_vm();
    for composition in ["duplicate", "partial", "mixed"] {
        let fixture = fixture();
        let (programs, attachment) = gate_io(fixture.bootstrap());
        let _gate = gate_io(programs.attach_native_gate(&attachment, &fixture.pins));
        let target = gate_io(programs.native_target(&gate_io(fixture.capture()), &[], &attachment));
        let other = (composition != "duplicate").then(|| gate_io(fixture.alongside()));
        let (second_owner, second) = if let Some(other) = &other {
            let (programs, attachment) = gate_io(other.bootstrap());
            let _gate = gate_io(programs.attach_native_gate(&attachment, &other.pins));
            let target =
                gate_io(programs.native_target(&gate_io(other.capture()), &[], &attachment));
            (Some((programs, attachment)), target)
        } else {
            (
                None,
                gate_io(programs.native_target(&gate_io(fixture.capture()), &[], &attachment)),
            )
        };
        let targets = [
            gate_bpf::CapturedTarget {
                realm_index: 0,
                logical_ifindex: fixture.ifindex,
                target: target.clone(),
            },
            gate_bpf::CapturedTarget {
                realm_index: 1,
                logical_ifindex: second.capture().authority.ifindex,
                target: second.clone(),
            },
        ];
        let mut maps = gate_io(GateNative::new());
        let captured = gate_io(GateCaptured::new_targets(
            &fixture.directory,
            &targets,
            &mut maps,
        ));
        let first = gate_io(maps.prepare_captured(&target, 2, &captured.config()));
        gate_io(first.publish(&target));
        gate_io(target.finish_publication());
        gate_io(attachment.replace(&programs));
        if let Some((programs, attachment)) = &second_owner {
            let next = gate_io(maps.prepare_captured(&second, 2, &captured.config()));
            gate_io(next.publish(&second));
            gate_io(second.finish_publication());
            gate_io(attachment.replace(programs));
        }
        let physical = if let Some(other) = &other {
            vec![fixture.ifindex, other.ifindex]
        } else {
            vec![fixture.ifindex]
        };
        let mut topology = gate_io(Topology::admit_after_xdp_attach(&physical, &physical, 128));
        let budget = honk_netstack::MemoryBudget::new(4 << 20);
        let updates = gate_io(topology.enable_native_xdp_updates(&budget));
        gate_io(target.bind_native_xdp_updates(updates.clone()));
        let mut mixed = if composition == "mixed" {
            let mut topology = gate_io(Topology::admit_after_xdp_attach(&physical, &physical, 128));
            let updates = gate_io(topology.enable_native_xdp_updates(&budget));
            gate_io(second.bind_native_xdp_updates(updates.clone()));
            Some((topology, updates))
        } else {
            None
        };
        let pins = gate_io(captured.pin_inventory());
        let xdp_guard = captured_id(&captured, "tap-xdp-guard");
        let tcx_guard = captured_id(&captured, "tap-tcx-guard-prog");
        assert!(
            captured.loaded.seal().is_err(),
            "invalid {composition} composition gained shared authority"
        );
        let tap = captured.loaded.tap_ifindex();
        gate_io(gate_bpf::require_native(
            gate_io(gate_bpf::xdp_state(tap)),
            xdp_guard,
        ));
        gate_io(gate_bpf::require_gate_tcx(
            &gate_io(gate_bpf::query_tcx(tap, gate_bpf::BPF_TCX_INGRESS)),
            &gate_io(gate_bpf::query_tcx(tap, gate_bpf::BPF_TCX_EGRESS)),
            tcx_guard,
        ));
        assert_eq!(
            updates.consumed_operations(),
            0,
            "failed composition earned common-watch credit"
        );
        assert!(
            captured.loaded.finish_close().is_err(),
            "repeated {composition} close gained destruction"
        );
        let called = std::cell::Cell::new(false);
        assert!(
            captured
                .loaded
                .close_tap(captured._tap.as_raw_fd(), || {
                    called.set(true);
                    Ok(())
                })
                .is_err()
        );
        assert!(!called.get());
        assert_eq!(gate_io(captured.pin_inventory()), pins);
        invalidated(&mut topology);
        if let Some((topology, updates)) = &mut mixed {
            assert_eq!(updates.consumed_operations(), 0);
            invalidated(topology);
        }
    }
    for foreign_hook in ["xdp", "tcx"] {
        for during in [false, true] {
            let (_fixture, _programs, captured, mut topology, updates) = captured_bound();
            let tap = captured.loaded.tap_ifindex();
            let xdp_guard = captured_id(&captured, "tap-xdp-guard");
            let tcx_guard = captured_id(&captured, "tap-tcx-guard-prog");
            let (foreign, foreign_id) = gate_io(gate_program(
                if foreign_hook == "xdp" {
                    gate_bpf::BPF_PROG_TYPE_XDP
                } else {
                    gate_bpf::BPF_PROG_TYPE_SCHED_CLS
                },
                b"hgr_foreign",
            ));
            let old = captured_program(
                &captured,
                if foreign_hook == "xdp" {
                    "tap-xdp-dispatch"
                } else {
                    "tap-tcx-redirect-prog"
                },
            );
            let mutate = move || {
                if foreign_hook == "xdp" {
                    gate_io(
                        gate_bpf::set_xdp(tap, foreign.as_raw_fd(), Some(old.as_raw_fd()))
                            .map_err(io::Error::from),
                    );
                } else {
                    let ingress = gate_io(gate_bpf::query_tcx(tap, gate_bpf::BPF_TCX_INGRESS));
                    gate_io(gate_bpf::bpf(
                        gate_bpf::BPF_PROG_ATTACH,
                        &mut gate_bpf::TcxAttachAttr {
                            target_ifindex: tap,
                            attach_bpf_fd: foreign.as_raw_fd() as u32,
                            attach_type: gate_bpf::BPF_TCX_INGRESS,
                            attach_flags: gate_bpf::BPF_F_REPLACE,
                            replace_bpf_fd: old.as_raw_fd() as u32,
                            expected_revision: ingress.revision,
                            ..gate_bpf::TcxAttachAttr::default()
                        },
                    ));
                }
            };
            if during {
                updates.before_next_setter(mutate);
            } else {
                mutate();
            }
            let pins = gate_io(captured.pin_inventory());
            assert!(
                captured.loaded.seal().is_err(),
                "foreign {foreign_hook} gained joined seal"
            );
            gate_io(gate_bpf::require_native(
                gate_io(gate_bpf::xdp_state(tap)),
                if foreign_hook == "xdp" {
                    foreign_id
                } else {
                    xdp_guard
                },
            ));
            gate_io(gate_bpf::require_gate_tcx(
                &gate_io(gate_bpf::query_tcx(tap, gate_bpf::BPF_TCX_INGRESS)),
                &gate_io(gate_bpf::query_tcx(tap, gate_bpf::BPF_TCX_EGRESS)),
                if foreign_hook == "tcx" {
                    foreign_id
                } else {
                    tcx_guard
                },
            ));
            assert!(captured.loaded.finish_close().is_err());
            assert_eq!(
                gate_io(captured.pin_inventory()),
                pins,
                "failed containment destroyed owned pin identities"
            );
            let called = std::cell::Cell::new(false);
            assert!(
                captured
                    .loaded
                    .close_tap(captured._tap.as_raw_fd(), || {
                        called.set(true);
                        Ok(())
                    })
                    .is_err()
            );
            assert!(!called.get());
            assert_eq!(
                updates.consumed_operations(),
                usize::from(foreign_hook == "tcx")
            );
            if foreign_hook == "xdp" {
                invalidated(&mut topology);
            }
        }
    }
    let (_fixture, _programs, captured, mut topology, updates) = captured_bound();
    gate_io(captured.loaded.seal());
    assert!(gate_io(captured.loaded.finish_close()));
    let tap = captured.loaded.tap_ifindex();
    let (foreign, foreign_id) = gate_io(gate_program(gate_bpf::BPF_PROG_TYPE_XDP, b"hgr_late_xdp"));
    gate_io(gate_bpf::set_xdp(tap, foreign.as_raw_fd(), None).map_err(io::Error::from));
    let called = std::cell::Cell::new(false);
    assert!(
        captured
            .loaded
            .close_tap(captured._tap.as_raw_fd(), || {
                called.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(
        !called.get(),
        "foreign selected XDP authorized TAP destruction"
    );
    gate_io(gate_bpf::require_native(
        gate_io(gate_bpf::xdp_state(tap)),
        foreign_id,
    ));
    assert_eq!(updates.consumed_operations(), 2);
    invalidated(&mut topology);
}
