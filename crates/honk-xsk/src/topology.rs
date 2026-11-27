//! Read-only capture layout, startup default-route safety and RTNL identity watches.
//!
//! Physical XDP ignores carrier and unrelated device changes. TUN separately proves
//! its owned link, addresses, exact RPDB rules and capture routes.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use honk_netstack::{MemoryBudget, MemoryReservation};

use crate::bpf::{attributes, raw_attributes, wait_netlink};

mod auxiliary;
pub use auxiliary::{AuxLinkInfo, AuxLinkWatch, HostLinkChange};

const IFLA_GSO_IPV4_MAX_SIZE: u16 = 63;
const IFLA_GRO_IPV4_MAX_SIZE: u16 = 64;
const LEGACY_OFFLOAD_MAX_SIZE: u32 = 65_536;
const IFLA_TUN_NUM_QUEUES: u16 = 8;
const IFLA_TUN_NUM_DISABLED_QUEUES: u16 = 9;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = 0x3fff;

const MAX_OBJECTS: usize = 65_536;
const RTNL_BUFFER_BYTES: usize = 65_536;
const DUMP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_DUMP_ATTEMPTS: usize = 8;
const NLM_F_DUMP_INTR: u16 = 0x10;
const DUMP_INTERRUPTED: &str = "topology changed or dump was interrupted during admission";
const RTM_GETNEXTHOP: u16 = 106;
pub(crate) const MAX_BROADCASTS: usize = 64;

const IFA_F_NODAD: u32 = 0x02;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_TENTATIVE: u32 = 0x40;
const IFA_F_PERMANENT: u32 = 0x80;
const IFA_F_NOPREFIXROUTE: u32 = 0x200;
const FIB_RULE_IIF_DETACHED: u32 = 0x08;
const FR_ACT_PROHIBIT: u8 = 8;
const RTN_BLACKHOLE: u8 = 6;
const RTPROT_STATIC: u8 = 4;
const TUN_GUARD_METRIC: u32 = 32760;
// IPv6 stores metric 0 as 1024, and IPv4 deletion treats priority 0 as a wildcard.
const TUN_CAPTURE_METRIC: u32 = 1024;

/// Borrowed TUN configuration plus the process bypass mark capture must route around.
#[derive(Clone, Copy, Debug)]
pub struct TunSpec<'a> {
    pub name: &'a str,
    pub mtu: u32,
    pub queues: u8,
    pub address4: Option<Ipv4Addr>,
    pub address6: Option<Ipv6Addr>,
    pub table: u32,
    pub rule_priority: u32,
    pub bypass_mark: u32,
    pub capture: &'a [(IpAddr, u8)],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunRouteKind {
    Blackhole,
    Unicast { oif: u32 },
}

/// One bare `RTPROT_STATIC` route in the dedicated capture table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunRoute {
    pub table: u32,
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub kind: TunRouteKind,
    pub metric: u32,
}

/// `Fwmark` carries an exact `0xffffffff` mask; `Iif` names the owned TUN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunRuleSelector {
    Fwmark(u32),
    Iif,
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunRuleAction {
    Lookup(u32),
    Prohibit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunRule {
    pub ipv6: bool,
    pub priority: u32,
    pub selector: TunRuleSelector,
    pub action: TunRuleAction,
}

/// `Guarded` holds every rule and blackhole guard but no capture route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunStage {
    Guarded,
    Active,
}

/// Cleanup facts from one dump; `None` marks an object no TUN key represents exactly.
#[derive(Debug)]
pub struct TunReadback {
    /// Some link, of any identity, still has the recorded ifindex.
    pub link: bool,
    /// The recorded ifindex still names the expected TUN link.
    pub owned_tun: bool,
    /// Active queue count. Linux omits both counts for a single-queue TUN.
    pub num_queues: Option<u32>,
    pub num_disabled_queues: Option<u32>,
    pub addresses: Vec<(IpAddr, u8)>,
    /// Every capture-table route as `(table, destination, prefix, metric, key)`.
    pub routes: Vec<(u32, IpAddr, u8, u32, Option<TunRoute>)>,
    /// Every rule of either family in `[P, P+4]` as `(ipv6, priority, key)`.
    pub rules: Vec<(bool, u32, Option<TunRule>)>,
}

impl TunReadback {
    /// Checks the expected active count and requires zero disabled queues.
    /// Single-queue TUN may omit both counts.
    pub fn matches_queues(&self, expected: u8) -> bool {
        self.owned_tun && tun_queues_match(expected, self.num_queues, self.num_disabled_queues)
    }
}

fn tun_queues_match(expected: u8, active: Option<u32>, disabled: Option<u32>) -> bool {
    (expected == 1 && active.is_none() && disabled.is_none())
        || (expected != 0 && active == Some(u32::from(expected)) && disabled == Some(0))
}

impl TunSpec<'_> {
    /// Per enabled family, IPv4 first, in install order `P..=P+4`.
    pub fn rules(&self) -> Vec<TunRule> {
        use TunRuleAction::{Lookup, Prohibit};
        use TunRuleSelector::{All, Fwmark, Iif};
        let mark = Fwmark(self.bypass_mark);
        let shape = [
            (mark, Lookup(254)),
            (mark, Prohibit),
            (Iif, Lookup(254)),
            (Iif, Prohibit),
            (All, Lookup(self.table)),
        ];
        let mut rules = Vec::with_capacity(2 * shape.len());
        for ipv6 in self.families() {
            for (offset, (selector, action)) in (0..).zip(shape) {
                rules.push(TunRule {
                    ipv6,
                    priority: self.rule_priority.saturating_add(offset),
                    selector,
                    action,
                });
            }
        }
        rules
    }

    pub fn guard_routes(&self) -> Vec<TunRoute> {
        self.routes(TunRouteKind::Blackhole, TUN_GUARD_METRIC)
    }

    pub fn capture_routes(&self, oif: u32) -> Vec<TunRoute> {
        self.routes(TunRouteKind::Unicast { oif }, TUN_CAPTURE_METRIC)
    }

    fn routes(&self, kind: TunRouteKind, metric: u32) -> Vec<TunRoute> {
        self.capture
            .iter()
            .map(|&(destination, prefix_len)| TunRoute {
                table: self.table,
                destination,
                prefix_len,
                kind,
                metric,
            })
            .collect()
    }

    fn families(&self) -> impl Iterator<Item = bool> {
        [self.address4.map(|_| false), self.address6.map(|_| true)]
            .into_iter()
            .flatten()
    }

    fn addresses(&self) -> impl Iterator<Item = IpAddr> {
        [self.address4.map(IpAddr::V4), self.address6.map(IpAddr::V6)]
            .into_iter()
            .flatten()
    }

    /// Refuses values that would make derived keys or the reserved range inexact.
    fn validate(&self) -> io::Result<[u8; 16]> {
        let name = self.name.as_bytes();
        let network = |&(destination, prefix): &(IpAddr, u8)| match destination {
            IpAddr::V4(ip) => self.address4.is_some() && network_address(IpAddr::V4(ip), prefix),
            IpAddr::V6(ip) => self.address6.is_some() && network_address(IpAddr::V6(ip), prefix),
        };
        if name.is_empty()
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'-'))
            || matches!(self.name, "lo" | "auto")
            || !(1280..=65535).contains(&self.mtu)
            || self.queues == 0
            || self.address4.is_some_and(|ip| {
                ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_link_local()
            })
            || self.address6.is_some_and(|ip| {
                ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unicast_link_local()
                    || ip.to_ipv4_mapped().is_some()
            })
            || (self.address4.is_none() && self.address6.is_none())
            || self.bypass_mark == 0
            || self.bypass_mark & honk_ebpf_common::CLASSIFIED_MARK != 0
            || matches!(self.table, 0 | 253..=255 | u32::MAX)
            || self.rule_priority == 0
            || self
                .rule_priority
                .checked_add(4)
                .is_none_or(|last| last >= 32766)
            || self.capture.is_empty()
            || self.capture.len() > 64
            || !self.capture.iter().all(network)
            || self
                .capture
                .iter()
                .enumerate()
                .any(|(index, &(address, prefix))| {
                    self.capture[..index].iter().any(|&(other, other_prefix)| {
                        let common = prefix.min(other_prefix);
                        match (address, other) {
                            (IpAddr::V4(a), IpAddr::V4(b)) => {
                                u32::from(a)
                                    .checked_shr(u32::from(32 - common))
                                    .unwrap_or(0)
                                    == u32::from(b)
                                        .checked_shr(u32::from(32 - common))
                                        .unwrap_or(0)
                            }
                            (IpAddr::V6(a), IpAddr::V6(b)) => {
                                u128::from(a)
                                    .checked_shr(u32::from(128 - common))
                                    .unwrap_or(0)
                                    == u128::from(b)
                                        .checked_shr(u32::from(128 - common))
                                        .unwrap_or(0)
                            }
                            _ => false,
                        }
                    })
                })
        {
            return Err(unsupported(
                "invalid TUN name, queues, addresses, mark, table, priority range or capture prefixes",
            ));
        }
        interface_name(name)
    }
}

#[derive(Clone, Debug)]
pub struct CaptureRealm {
    pub realm_id: u32,
    pub name: String,
    pub logical_ifindex: u32,
    pub root_ifindex: u32,
    pub mtu: u32,
    pub mac: [u8; 6],
    pub vlan_count: u32,
    pub tpid: [u16; 2],
    pub vid: [u16; 2],
    pub members: Vec<String>,
}

fn link_name(link: &Link) -> io::Result<String> {
    let name = link
        .name
        .ok_or_else(|| malformed("capture link has no name"))?;
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    std::str::from_utf8(&name[..end])
        .map(str::to_owned)
        .map_err(|_| malformed("invalid capture link name"))
}

pub fn capture_layout(names: &[String]) -> io::Result<Vec<CaptureRealm>> {
    if names.len() > 16 {
        return Err(unsupported("capture exceeds 16 configured roots"));
    }
    if names.is_empty() {
        return Ok(Vec::new());
    }
    with_topology_dump(
        None,
        Instant::now() + DUMP_TIMEOUT,
        &mut [0; RTNL_BUFFER_BYTES],
        |dump| {
            let mut snapshot = dump.snapshot()?;
            dump.append(5, RTM_GETNEXTHOP, 8, &mut snapshot)?;
            snapshot.links.sort_unstable_by_key(|link| link.index);
            capture_layout_snapshot(&snapshot, names)
        },
    )
}

pub fn check_gateway_defaults(captured: &[u32]) -> io::Result<()> {
    with_topology_dump(
        None,
        Instant::now() + DUMP_TIMEOUT,
        &mut [0; RTNL_BUFFER_BYTES],
        |dump| {
            let mut observed = dump.snapshot()?;
            dump.append(5, RTM_GETNEXTHOP, 8, &mut observed)?;
            check_gateway_defaults_snapshot(&observed, captured)
        },
    )
}

fn check_gateway_defaults_snapshot(snapshot: &Snapshot, captured: &[u32]) -> io::Result<()> {
    snapshot.gateway_defaults(captured)
}

pub(crate) fn auxiliary_up(ifindex: u32) -> io::Result<bool> {
    with_topology_dump(
        None,
        Instant::now() + DUMP_TIMEOUT,
        &mut [0; RTNL_BUFFER_BYTES],
        |dump| {
            let mut observed = Snapshot::default();
            dump.append(1, libc::RTM_GETLINK, 16, &mut observed)?;
            observed
                .links
                .iter()
                .find(|link| link.index == ifindex)
                .map(|link| link.flags & libc::IFF_UP as u32 != 0)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))
        },
    )
}

fn capture_layout_snapshot(snapshot: &Snapshot, names: &[String]) -> io::Result<Vec<CaptureRealm>> {
    let veth_kind = interface_name(b"veth")?;
    let mut realms = Vec::new();
    let mut captured = Vec::new();
    for name in names {
        let key = interface_name(name.as_bytes())?;
        let root = snapshot
            .links
            .iter()
            .find(|link| link.name == Some(key))
            .ok_or_else(|| unsupported("configured capture link is absent"))?;
        if root.master != 0 || root.arphrd != 1 {
            return Err(unsupported("capture root is not independent Ethernet"));
        }
        let members: Vec<_> = if root.kind == Some(interface_name(b"bond")?) {
            if root
                .bond
                .is_none_or(|(mode, hash)| mode != 4 || !matches!(hash, 0..=4))
            {
                return Err(unsupported(
                    "bond capture requires 802.3ad and a supported transmit hash policy",
                ));
            }
            snapshot
                .links
                .iter()
                .filter(|link| link.master == root.index)
                .collect()
        } else {
            if root.kind.is_some() && root.kind != Some(interface_name(b"veth")?) {
                return Err(unsupported("unsupported capture root kind"));
            }
            vec![root]
        };
        if members.is_empty() || members.len() > 64 {
            return Err(unsupported(
                "bond has no admitted members or exceeds 64 members",
            ));
        }
        for member in &members {
            if member.arphrd != 1
                || (member.kind.is_some() && member.kind != Some(interface_name(b"veth")?))
            {
                return Err(unsupported("bond member is not physical Ethernet or veth"));
            }
            if captured.contains(&member.index) {
                return Err(unsupported("capture roots overlap"));
            }
            captured.push(member.index);
        }
        if realms.len() == 64 {
            return Err(unsupported("capture exceeds 64 logical realms"));
        }
        let member_names: Vec<_> = members
            .iter()
            .map(|link| link_name(link))
            .collect::<io::Result<_>>()?;
        let start = realms.len();
        realms.push(CaptureRealm {
            realm_id: (realms.len() + 1) as u32,
            name: name.clone(),
            logical_ifindex: root.index,
            root_ifindex: root.index,
            mtu: root.mtu.ok_or_else(|| malformed("missing capture MTU"))?,
            mac: root.mac,
            vlan_count: 0,
            tpid: [0; 2],
            vid: [0; 2],
            members: member_names.clone(),
        });
        let mut cursor = start;
        while cursor < realms.len() {
            let parent = realms[cursor].clone();
            for link in snapshot.links.iter().filter(|link| {
                link.parent == parent.logical_ifindex
                    && link.index != parent.logical_ifindex
                    && link.kind != Some(veth_kind)
            }) {
                if link.master != 0 || parent.vlan_count == 2 || link.vlan.is_none() {
                    return Err(unsupported("unsupported capture upper or VLAN depth"));
                }
                if realms
                    .iter()
                    .any(|realm| realm.logical_ifindex == link.index)
                {
                    return Err(unsupported("cyclic or overlapping capture upper"));
                }
                if realms.len() == 64 {
                    return Err(unsupported("capture exceeds 64 logical realms"));
                }
                let (protocol, id) = link
                    .vlan
                    .ok_or_else(|| unsupported("invalid capture VLAN"))?;
                let mut realm = CaptureRealm {
                    realm_id: (realms.len() + 1) as u32,
                    name: link_name(link)?,
                    logical_ifindex: link.index,
                    root_ifindex: root.index,
                    mtu: parent
                        .mtu
                        .min(link.mtu.ok_or_else(|| malformed("missing VLAN MTU"))?),
                    mac: link.mac,
                    vlan_count: parent.vlan_count + 1,
                    tpid: parent.tpid,
                    vid: parent.vid,
                    members: member_names.clone(),
                };
                realm.tpid[parent.vlan_count as usize] = protocol;
                realm.vid[parent.vlan_count as usize] = id;
                realms.push(realm);
            }
            cursor += 1;
        }
    }
    for link in &snapshot.links {
        if captured.contains(&link.parent)
            && link.index != link.parent
            && link.kind != Some(veth_kind)
            && !realms
                .iter()
                .any(|realm| realm.logical_ifindex == link.index)
        {
            return Err(unsupported(
                "physical capture member has an unadmitted upper",
            ));
        }
    }
    if realms
        .iter()
        .any(|realm| realm.mtu < 1280 || realm.mac == [0; 6] || realm.mac[0] & 1 != 0)
    {
        return Err(unsupported(
            "capture realm requires unicast MAC and MTU >=1280",
        ));
    }
    Ok(realms)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureWatchEvent {
    Quiet,
    AddressDirty,
}

struct CaptureBuffer {
    bytes: Box<[u8]>,
    // Field drop order keeps the charge until the backing storage is freed.
    _memory: MemoryReservation,
}

impl CaptureBuffer {
    fn new(budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let memory = budget.reserve(RTNL_BUFFER_BYTES).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "capture RTNL buffer budget exhausted",
            )
        })?;
        Ok(Self {
            bytes: vec![0; RTNL_BUFFER_BYTES].into_boxed_slice(),
            _memory: memory,
        })
    }
}

pub struct CaptureWatch {
    fd: OwnedFd,
    buffer: CaptureBuffer,
    links: Vec<Link>,
    programs: Vec<(u32, u32)>,
    invalidated: bool,
    ipv4_broadcasts: [Ipv4Addr; MAX_BROADCASTS],
    broadcast_count: usize,
}

impl CaptureWatch {
    pub fn new(indices: &[u32], budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let mut buffer = CaptureBuffer::new(budget)?;
        let deadline = Instant::now() + DUMP_TIMEOUT;
        let fd = route_socket(true)?;
        let current = with_topology_dump(
            Some(netns_cookie(fd.as_fd())?),
            deadline,
            &mut buffer.bytes,
            |dump| dump.snapshot(),
        )?;
        let mut links = Vec::new();
        for index in indices {
            if links.iter().any(|link: &Link| link.index == *index) {
                continue;
            }
            links.push(
                current
                    .links
                    .iter()
                    .find(|link| link.index == *index)
                    .ok_or_else(|| unsupported("captured link disappeared"))?
                    .clone(),
            );
        }
        let (ipv4_broadcasts, broadcast_count) = current.ipv4_broadcasts()?;
        Ok(Self {
            fd,
            buffer,
            links,
            programs: Vec::new(),
            invalidated: false,
            ipv4_broadcasts,
            broadcast_count,
        })
    }

    pub fn ipv4_broadcasts(&self) -> &[Ipv4Addr] {
        &self.ipv4_broadcasts[..self.broadcast_count]
    }

    pub fn expect_program(&mut self, ifindex: u32, program_id: u32) {
        if let Some((_, expected)) = self
            .programs
            .iter_mut()
            .find(|(index, _)| *index == ifindex)
        {
            *expected = program_id;
        } else {
            self.programs.push((ifindex, program_id));
        }
    }

    pub fn check(&mut self) -> io::Result<CaptureWatchEvent> {
        self.check_with(Self::receive)
    }

    fn check_with(
        &mut self,
        receive: impl FnOnce(&mut Self) -> io::Result<CaptureWatchEvent>,
    ) -> io::Result<CaptureWatchEvent> {
        if self.invalidated {
            return Err(unsupported("captured topology lost authority"));
        }
        let result = receive(self);
        if result.is_err() {
            self.invalidated = true;
        }
        result
    }

    fn receive(&mut self) -> io::Result<CaptureWatchEvent> {
        let mut dirty = false;
        for _ in 0..64 {
            let length = match receive_netlink(
                self.fd.as_fd(),
                &mut self.buffer.bytes,
                "invalid capture notification sender or extent",
            ) {
                Ok(length) => length,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(if dirty {
                        CaptureWatchEvent::AddressDirty
                    } else {
                        CaptureWatchEvent::Quiet
                    });
                }
                Err(error) => return Err(error),
            };
            dirty |= self.datagram(&self.buffer.bytes[..length], crate::bpf::xdp_state)?;
        }
        Err(malformed("capture notification drain bound exceeded"))
    }

    fn datagram(
        &self,
        mut bytes: &[u8],
        mut program: impl FnMut(u32) -> io::Result<crate::XdpState>,
    ) -> io::Result<bool> {
        let mut dirty = false;
        let bond_kind = interface_name(b"bond")?;
        while !bytes.is_empty() {
            if bytes.len() < 16 {
                return Err(malformed("short capture notification"));
            }
            let length = u32_at(bytes, 0)? as usize;
            if length < 16 || length > bytes.len() || ((length + 3) & !3) > bytes.len() {
                return Err(malformed("truncated capture notification"));
            }
            if u16::from_ne_bytes([bytes[6], bytes[7]]) & NLM_F_DUMP_INTR != 0 {
                return Err(malformed("interrupted capture notification"));
            }
            let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
            let normalized = match kind {
                16 | 17 => 16,
                20 | 21 => 20,
                24 | 25 => 24,
                32 | 33 => 32,
                _ => return Err(malformed("unexpected capture notification")),
            };
            let mut parsed = Snapshot::default();
            if matches!(normalized, 24 | 32) {
                if length < 28 {
                    return Err(malformed("short route or rule notification"));
                }
                attributes(&bytes[28..length], |_, _| Ok(()))?;
            } else {
                parsed.push(normalized, &bytes[16..length])?;
            }
            if normalized == 20 {
                dirty = true;
            }
            for link in &parsed.links {
                if let Some(old) = self.links.iter().find(|old| old.index == link.index) {
                    if kind == 17 || !same_capture_identity(old, link) {
                        return Err(unsupported("captured link identity changed"));
                    }
                    let expected = self
                        .programs
                        .iter()
                        .find(|(index, _)| *index == link.index)
                        .map_or(0, |(_, id)| *id);
                    let state = program(link.index)?;
                    if state.prog_id != expected
                        || state.drv_prog_id != expected
                        || state.skb_prog_id != 0
                        || state.hw_prog_id != 0
                        || state.attached != u8::from(expected != 0)
                    {
                        return Err(unsupported("captured XDP program changed"));
                    }
                } else if kind == 16
                    && self
                        .links
                        .iter()
                        .any(|old| old.index == link.master && old.kind == Some(bond_kind))
                {
                    return Err(unsupported("captured link identity changed"));
                }
            }
            bytes = &bytes[(length + 3) & !3..];
        }
        Ok(dirty)
    }
}

fn same_capture_identity(a: &Link, b: &Link) -> bool {
    a.index == b.index
        && a.mtu == b.mtu
        && a.master == b.master
        && a.mac == b.mac
        && a.rx_queues == b.rx_queues
        && a.tx_queues == b.tx_queues
        && a.parent == b.parent
        && a.kind == b.kind
        && a.vlan == b.vlan
        && a.bond == b.bond
}

impl AsFd for CaptureWatch {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl AsRawFd for CaptureWatch {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub struct Topology {
    fd: OwnedFd,
    netns_cookie: u64,
    watch: WatchState,
}

enum WatchState {
    Strict {
        invalidated: bool,
    },
    Tun {
        spec: TunWatch,
        owned: (u32, TunStage),
        invalidated: bool,
    },
}

struct TunWatch {
    name: String,
    mtu: u32,
    queues: u8,
    address4: Option<Ipv4Addr>,
    address6: Option<Ipv6Addr>,
    table: u32,
    rule_priority: u32,
    bypass_mark: u32,
    capture: Vec<(IpAddr, u8)>,
}

impl TunWatch {
    fn spec(&self) -> TunSpec<'_> {
        TunSpec {
            name: &self.name,
            mtu: self.mtu,
            queues: self.queues,
            address4: self.address4,
            address6: self.address6,
            table: self.table,
            rule_priority: self.rule_priority,
            bypass_mark: self.bypass_mark,
            capture: &self.capture,
        }
    }
}

impl Topology {
    /// Before creating the TUN: subscribes, then proves the name, addresses, capture
    /// table and `[P, P+4]` are free and each enabled family has an operator uplink.
    pub fn preflight_tun(spec: &TunSpec<'_>) -> io::Result<Self> {
        Self::watch_tun(spec, None)
    }

    /// Completes only the owned IPv6 local-route work before any guards or rules
    /// divert traffic. Foreign topology and malformed observations stay terminal.
    pub fn wait_tun_device(spec: &TunSpec<'_>, ifindex: u32) -> io::Result<()> {
        let name = spec.validate()?;
        let deadline = Instant::now() + DUMP_TIMEOUT;
        let mut watch = route_socket(true)?;
        let cookie = netns_cookie(watch.as_fd())?;
        let mut buffer = [0; RTNL_BUFFER_BYTES];
        loop {
            let ready = with_topology_dump(Some(cookie), deadline, &mut buffer, |dump| {
                dump.snapshot()?.tun_ready(spec, name, Some(ifindex), None)
            })?;
            if ready {
                return Ok(());
            }
            wait_netlink(watch.as_fd(), libc::POLLIN, deadline)?;
            watch = route_socket(true)?;
        }
    }

    /// Proves exactly the owned link, addresses, rules and guards (plus capture routes
    /// when `Active`) beside representable operator routing. Retain and watch it like
    /// [`Self::admit`]; any invalidation requires closing capture admission.
    pub fn admit_tun(spec: &TunSpec<'_>, ifindex: u32, stage: TunStage) -> io::Result<Self> {
        Self::watch_tun(spec, Some((ifindex, stage)))
    }

    fn watch_tun(spec: &TunSpec<'_>, owned: Option<(u32, TunStage)>) -> io::Result<Self> {
        let name = spec.validate()?;
        let deadline = Instant::now() + DUMP_TIMEOUT;
        let fd = route_socket(true)?;
        let netns_cookie = netns_cookie(fd.as_fd())?;
        let mut buffer = [0; RTNL_BUFFER_BYTES];
        with_topology_dump(Some(netns_cookie), deadline, &mut buffer, |dump| {
            dump.snapshot()?.admit_tun(spec, name, owned)
        })?;
        let mut topology = Self {
            fd,
            netns_cookie,
            watch: match owned {
                Some(owned) => WatchState::Tun {
                    spec: TunWatch {
                        name: spec.name.to_owned(),
                        mtu: spec.mtu,
                        queues: spec.queues,
                        address4: spec.address4,
                        address6: spec.address6,
                        table: spec.table,
                        rule_priority: spec.rule_priority,
                        bypass_mark: spec.bypass_mark,
                        capture: spec.capture.to_vec(),
                    },
                    owned,
                    invalidated: false,
                },
                None => WatchState::Strict { invalidated: false },
            },
        };
        let changed = if owned.is_some() {
            topology.check_tun_changed_until(deadline, &mut buffer)?
        } else {
            topology.check_changed()?
        };
        if changed {
            return Err(unsupported("routing topology changed during admission"));
        }
        Ok(topology)
    }

    /// Sticky invalidation on lost authority or an owned TUN object change.
    /// TUN notifications concerning other objects trigger an admission recheck.
    pub fn check_changed(&mut self) -> io::Result<bool> {
        if matches!(self.watch, WatchState::Tun { .. }) {
            return self.check_tun_changed();
        }
        let invalidated = match &mut self.watch {
            WatchState::Strict { invalidated } => invalidated,
            WatchState::Tun { .. } => unreachable!(),
        };
        if *invalidated {
            return Ok(true);
        }
        let mut byte = [0u8; 1];
        loop {
            // SAFETY: byte is writable; MSG_TRUNC discards the entire datagram.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    byte.as_mut_ptr().cast(),
                    1,
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if n >= 0 {
                *invalidated = true;
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::WouldBlock => return Ok(false),
                io::ErrorKind::Interrupted => continue,
                _ => {
                    *invalidated = true;
                    return Err(error);
                }
            }
        }
    }

    /// Classifies notifications and rechecks the admitted TUN dependencies.
    pub fn check_tun_changed(&mut self) -> io::Result<bool> {
        self.check_tun_changed_until(Instant::now() + DUMP_TIMEOUT, &mut [0; RTNL_BUFFER_BYTES])
    }

    fn check_tun_changed_until(
        &mut self,
        deadline: Instant,
        buffer: &mut [u8],
    ) -> io::Result<bool> {
        let WatchState::Tun {
            spec,
            owned,
            invalidated,
        } = &mut self.watch
        else {
            return Err(unsupported("watcher has no admitted TUN custody"));
        };
        if *invalidated {
            return Ok(true);
        }
        let result = (|| {
            let mut changed = false;
            let spec = spec.spec();
            for turn in 0..64 {
                let n = match receive_netlink(
                    self.fd.as_fd(),
                    buffer,
                    "invalid topology notification sender or extent",
                ) {
                    Ok(n) => n,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                };
                if tun_notifications(&buffer[..n], &spec, owned.0)? {
                    return Ok(true);
                }
                changed = true;
                if turn == 63 {
                    return Err(malformed("topology notification drain bound exceeded"));
                }
            }
            if changed {
                let name = spec.validate()?;
                with_topology_dump(Some(self.netns_cookie), deadline, buffer, |dump| {
                    dump.snapshot()?.admit_tun(&spec, name, Some(*owned))
                })?;
            }
            Ok(false)
        })();
        if !matches!(result, Ok(false)) {
            *invalidated = true;
        }
        result
    }
}

fn tun_notifications(mut bytes: &[u8], spec: &TunSpec<'_>, ifindex: u32) -> io::Result<bool> {
    let mut owned_changed = false;
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(malformed("short topology notification"));
        }
        let length = u32_at(bytes, 0)? as usize;
        if length < 16 || length > bytes.len() || ((length + 3) & !3) > bytes.len() {
            return Err(malformed("invalid topology notification length"));
        }
        let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
        if flags & NLM_F_DUMP_INTR != 0 {
            return Err(malformed("interrupted topology notification"));
        }
        let body = &bytes[16..length];
        let normalized = match kind {
            16 | 17 => 16,
            20 | 21 => 20,
            24 | 25 => 24,
            32 | 33 => 32,
            _ => return Err(malformed("unexpected topology notification")),
        };
        let mut parsed = Snapshot::default();
        parsed.push(normalized, body)?;
        owned_changed |= parsed.links.iter().any(|link| link.index == ifindex)
            || parsed
                .addresses
                .iter()
                .any(|address| address.index == ifindex)
            || parsed
                .routes
                .iter()
                .any(|route| route.table == spec.table || route.output == ifindex)
            || parsed.rules.iter().any(|rule| {
                rule.table == spec.table
                    || (spec.rule_priority..=spec.rule_priority + 4).contains(&rule.priority)
            });
        bytes = &bytes[(length + 3) & !3..];
    }
    Ok(owned_changed)
}

impl AsFd for Topology {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Topology {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn malformed(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| malformed("short routing integer"))?
            .try_into()
            .unwrap(),
    ))
}

fn unicast_source(family: u8, bytes: &[u8]) -> io::Result<bool> {
    let address = match (family, bytes.len()) {
        (2, 4) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap())),
        (10, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())),
        _ => return Err(malformed("invalid topology address extent")),
    };
    Ok(!address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(ip) if ip.is_broadcast()))
}

/// Reads cleanup evidence without requiring the topology to remain admissible.
/// Unrepresentable occupants retain their slot and have no deletable key.
pub fn tun_readback(spec: &TunSpec<'_>, ifindex: u32) -> io::Result<TunReadback> {
    spec.validate()?;
    with_topology_dump(
        None,
        Instant::now() + DUMP_TIMEOUT,
        &mut [0; RTNL_BUFFER_BYTES],
        |dump| dump.snapshot()?.tun_readback(spec, ifindex),
    )
}

fn interface_name(bytes: &[u8]) -> io::Result<[u8; 16]> {
    if bytes.is_empty() || bytes.len() >= 16 || bytes.contains(&0) {
        return Err(malformed("invalid topology interface name"));
    }
    let mut name = [0; 16];
    name[..bytes.len()].copy_from_slice(bytes);
    Ok(name)
}

fn netlink_name(bytes: &[u8]) -> io::Result<[u8; 16]> {
    let Some((&0, name)) = bytes.split_last() else {
        return Err(malformed("unterminated topology interface name"));
    };
    interface_name(name)
}

fn ip_address(family: u8, bytes: &[u8]) -> io::Result<IpAddr> {
    match (family, bytes.len()) {
        (2, 4) => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).unwrap(),
        ))),
        (10, 16) => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).unwrap(),
        ))),
        _ => Err(malformed("invalid topology address extent")),
    }
}

fn unspecified(family: u8) -> Option<IpAddr> {
    match family {
        2 => Some(Ipv4Addr::UNSPECIFIED.into()),
        10 => Some(Ipv6Addr::UNSPECIFIED.into()),
        _ => None,
    }
}

fn network_address(address: IpAddr, prefix: u8) -> bool {
    match address {
        IpAddr::V4(ip) => {
            prefix <= 32 && u32::from(ip).checked_shl(prefix.into()).unwrap_or(0) == 0
        }
        IpAddr::V6(ip) => {
            prefix <= 128 && u128::from(ip).checked_shl(prefix.into()).unwrap_or(0) == 0
        }
    }
}

fn exact_u32(bytes: &[u8]) -> io::Result<u32> {
    let value = bytes
        .try_into()
        .map_err(|_| malformed("invalid topology integer extent"))?;
    Ok(u32::from_ne_bytes(value))
}

fn unique_attribute(seen: &mut u64, kind: u16) -> io::Result<()> {
    if kind < 64 {
        let bit = 1u64 << kind;
        if *seen & bit != 0 {
            return Err(malformed("duplicate topology attribute"));
        }
        *seen |= bit;
    }
    Ok(())
}

fn route_socket(watch: bool) -> io::Result<OwnedFd> {
    // SAFETY: socket takes scalar arguments and returns a new owned descriptor.
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
    // SAFETY: successful socket returned this unique descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: zero is valid initialization for sockaddr_nl.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // Subscribe before dumping, including both rule families.
    address.nl_groups = if watch {
        1 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400
    } else {
        0
    };
    // SAFETY: address is complete and alive during bind.
    if unsafe {
        libc::bind(
            raw,
            (&address as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if watch {
        join_route_group(fd.as_fd(), libc::RTNLGRP_IPV6_RULE)?;
    }
    Ok(fd)
}

fn join_route_group(fd: BorrowedFd<'_>, group: libc::c_uint) -> io::Result<()> {
    // SAFETY: the supplied option points to a live group number.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_NETLINK,
            libc::NETLINK_ADD_MEMBERSHIP,
            (&group as *const libc::c_uint).cast(),
            size_of::<libc::c_uint>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn netns_cookie(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let mut value = 0u64;
    let mut length = size_of::<u64>() as libc::socklen_t;
    // SAFETY: value is writable and length names its exact extent.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NETNS_COOKIE,
            (&mut value as *mut u64).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<u64>() || value == 0 {
        return Err(malformed("invalid topology RTNL namespace cookie"));
    }
    Ok(value)
}

fn receive_netlink(
    fd: BorrowedFd<'_>,
    buffer: &mut [u8],
    invalid_sender: &'static str,
) -> io::Result<usize> {
    // SAFETY: recvfrom writes only the provided buffer and sockaddr extent.
    let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    let n = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            (&mut source as *mut libc::sockaddr_nl).cast(),
            &mut length,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0
        || n as usize > buffer.len()
        || length as usize != size_of::<libc::sockaddr_nl>()
        || source.nl_family != libc::AF_NETLINK as libc::sa_family_t
        || source.nl_pid != 0
    {
        return Err(malformed(invalid_sender));
    }
    Ok(n as usize)
}

struct TopologyDump<'a> {
    fd: BorrowedFd<'a>,
    deadline: Instant,
    buffer: &'a mut [u8],
}

impl TopologyDump<'_> {
    fn snapshot(&mut self) -> io::Result<Snapshot> {
        let mut snapshot = Snapshot::default();
        for (sequence, kind, body_len) in [(1, 18, 16), (2, 22, 8), (3, 34, 12), (4, 26, 12)] {
            self.append(sequence, kind, body_len, &mut snapshot)?;
        }
        Ok(snapshot)
    }

    fn append(
        &mut self,
        sequence: u32,
        kind: u16,
        body_len: usize,
        snapshot: &mut Snapshot,
    ) -> io::Result<()> {
        self.request(sequence, kind, &[0; 16][..body_len], |message, body| {
            snapshot.push(message, body)
        })
    }

    fn request(
        &mut self,
        sequence: u32,
        kind: u16,
        body: &[u8],
        receive: impl FnMut(u16, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        dump_request(
            self.fd,
            sequence,
            kind,
            body,
            self.deadline,
            self.buffer,
            receive,
        )
    }
}

fn with_topology_dump<T>(
    expected_cookie: Option<u64>,
    deadline: Instant,
    buffer: &mut [u8],
    run: impl FnMut(&mut TopologyDump<'_>) -> io::Result<T>,
) -> io::Result<T> {
    with_topology_dump_socket(
        expected_cookie,
        deadline,
        buffer,
        || {
            let fd = route_socket(false)?;
            let cookie = netns_cookie(fd.as_fd())?;
            Ok((fd, cookie))
        },
        run,
    )
}

#[derive(Debug)]
struct InterruptedDump;

impl std::fmt::Display for InterruptedDump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(DUMP_INTERRUPTED)
    }
}

impl std::error::Error for InterruptedDump {}

fn with_topology_dump_socket<T>(
    mut expected_cookie: Option<u64>,
    deadline: Instant,
    buffer: &mut [u8],
    mut open: impl FnMut() -> io::Result<(OwnedFd, u64)>,
    mut run: impl FnMut(&mut TopologyDump<'_>) -> io::Result<T>,
) -> io::Result<T> {
    check_dump_deadline(deadline)?;
    for attempt in 0..MAX_DUMP_ATTEMPTS {
        if attempt != 0 && Instant::now() >= deadline {
            break;
        }
        let (fd, cookie) = open()?;
        if *expected_cookie.get_or_insert(cookie) != cookie {
            return Err(malformed("topology dump crossed network namespaces"));
        }
        let result = run(&mut TopologyDump {
            fd: fd.as_fd(),
            deadline,
            buffer,
        });
        // The kernel can still be dumping into an interrupted socket.
        drop(fd);
        match result.and_then(|value| check_dump_deadline(deadline).map(|()| value)) {
            Err(error)
                if error
                    .get_ref()
                    .is_some_and(|cause| cause.is::<InterruptedDump>()) =>
            {
                continue;
            }
            Err(error)
                if attempt != 0
                    && error.kind() == io::ErrorKind::TimedOut
                    && error.raw_os_error().is_none()
                    && Instant::now() >= deadline =>
            {
                break;
            }
            other => return other,
        }
    }
    Err(unsupported(DUMP_INTERRUPTED))
}

fn check_dump_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "topology dump deadline expired",
        ));
    }
    Ok(())
}

fn dump_request(
    fd: BorrowedFd<'_>,
    sequence: u32,
    kind: u16,
    request_body: &[u8],
    deadline: Instant,
    buffer: &mut [u8],
    mut receive: impl FnMut(u16, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut request = [0u8; 36];
    let length = 16 + request_body.len();
    request[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&kind.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    request[16..length].copy_from_slice(request_body);
    // SAFETY: zero is valid initialization for sockaddr_nl.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    loop {
        check_dump_deadline(deadline)?;
        // SAFETY: request and kernel match their supplied lengths.
        let n = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                request.as_ptr().cast(),
                length,
                libc::MSG_DONTWAIT,
                (&kernel as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if n >= 0 {
            if n as usize != length {
                return Err(malformed("short topology dump request"));
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
        wait_netlink(fd, libc::POLLOUT, deadline)?;
    }
    loop {
        check_dump_deadline(deadline)?;
        wait_netlink(fd, libc::POLLIN, deadline)?;
        check_dump_deadline(deadline)?;
        let length = match receive_netlink(fd, buffer, "invalid topology dump sender or extent") {
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if dump_datagram(&buffer[..length], sequence, kind, &mut receive)? {
            return Ok(());
        }
    }
}

fn dump_datagram(
    mut bytes: &[u8],
    sequence: u32,
    kind: u16,
    mut receive: impl FnMut(u16, &[u8]) -> io::Result<()>,
) -> io::Result<bool> {
    let mut done = false;
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(malformed("short topology message"));
        }
        let length = u32_at(bytes, 0)? as usize;
        if length < 16 || length > bytes.len() {
            return Err(malformed("invalid topology message length"));
        }
        let advance = (length + 3) & !3;
        if advance > bytes.len() && length != bytes.len() {
            return Err(malformed("short topology alignment"));
        }
        let message = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
        if u32_at(bytes, 8)? != sequence {
            return Err(unsupported(DUMP_INTERRUPTED));
        }
        let interrupted = flags & NLM_F_DUMP_INTR != 0;
        let body = &bytes[16..length];
        match message {
            2 => {
                let errno = u32_at(body, 0)? as i32;
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(
                        errno
                            .checked_neg()
                            .ok_or_else(|| malformed("invalid topology errno"))?,
                    ));
                }
            }
            3 => {
                if !body.is_empty() {
                    let status = u32_at(body, 0)? as i32;
                    if status != 0 && !(interrupted && status == -libc::EINTR) {
                        return Err(malformed("failed topology dump completion"));
                    }
                }
                done = true;
            }
            4 => return Err(malformed("topology netlink overrun")),
            _ if !done && message == kind - 2 && flags & 2 != 0 => {
                if !interrupted {
                    receive(message, body)?;
                }
            }
            _ => return Err(malformed("unexpected topology dump message")),
        }
        if interrupted {
            return Err(io::Error::new(io::ErrorKind::Interrupted, InterruptedDump));
        }
        bytes = &bytes[advance.min(bytes.len())..];
    }
    Ok(done)
}

#[derive(Default)]
struct Snapshot {
    links: Vec<Link>,
    addresses: Vec<Address>,
    rules: Vec<Rule>,
    routes: Vec<Route>,
    nexthops: Vec<Nexthop>,
}

#[derive(Clone)]
struct Link {
    index: u32,
    loopback: bool,
    name: Option<[u8; 16]>,
    mtu: Option<u32>,
    tx_queue_len: Option<u32>,
    kind: Option<[u8; 16]>,
    flags: u32,
    master: u32,
    arphrd: u16,
    parent: u32,
    foreign_parent: bool,
    mac: [u8; 6],
    rx_queues: u32,
    tx_queues: u32,
    vlan: Option<(u16, u16)>,
    bond: Option<(u8, u8)>,
    tun_queues: Option<u32>,
    tun_disabled_queues: Option<u32>,
    big_tcp: bool,
    has_hardware_address: bool,
}

impl Link {
    fn is_owned_tun(&self, name: [u8; 16], mtu: u32) -> bool {
        // tun_net_initialize sets POINTOPOINT|NOARP|MULTICAST. An attached,
        // administratively up queue also reports RUNNING|LOWER_UP.
        self.name == Some(name)
            && self.mtu == Some(mtu)
            && self.kind == interface_name(b"tun").ok()
            && self.arphrd == libc::ARPHRD_NONE
            && self.flags == 0x110d1
            && self.master == 0
    }
}

#[derive(Clone)]
struct Address {
    family: u8,
    index: u32,
    unicast_source: bool,
    address: IpAddr,
    peer: Option<IpAddr>,
    prefix_len: u8,
    flags: u32,
    scope: u8,
    label: Option<[u8; 16]>,
    unsupported: bool,
    permanent: bool,
    preferred: bool,
}
#[derive(Clone)]
struct Rule {
    family: u8,
    priority: u32,
    table: u32,
    mark: Option<u32>,
    mask: u32,
    action: u8,
    iif: Option<[u8; 16]>,
    oif: Option<[u8; 16]>,
    flags: u32,
    unsupported: bool,
}
#[derive(Clone)]
struct Route {
    family: u8,
    table: u32,
    output: u32,
    input: u32,
    default: bool,
    kind: u8,
    simple: bool,
    native_multicast: bool,
    ipv4_destination: Option<Ipv4Addr>,
    destination: Option<IpAddr>,
    prefix_len: u8,
    metric: u32,
    protocol: u8,
    scope: u8,
    flags: u32,
    gateway: Option<IpAddr>,
    source: Option<IpAddr>,
    preference: u8,
    unsupported: bool,
    outputs: Vec<u32>,
    nexthop: Option<u32>,
    gateway_unsupported: bool,
}

struct Nexthop {
    id: u32,
    output: u32,
    group: Vec<u32>,
    unsupported: bool,
}

impl Snapshot {
    fn gateway_defaults(&self, captured: &[u32]) -> io::Result<()> {
        for family in [2, 10] {
            let enabled = self.addresses.iter().any(|address| {
                address.family == family && address.scope == 0 && address.unicast_source
            });
            let mut found = false;
            for route in self
                .routes
                .iter()
                .filter(|route| route.family == family && route.default)
            {
                if route.gateway_unsupported {
                    return Err(unsupported("unrepresentable default route"));
                }
                if matches!(route.kind, 6..=9) {
                    continue;
                }
                if route.kind != 1 {
                    return Err(unsupported("unsupported default route action"));
                }
                found = true;
                if captured.contains(&route.output)
                    || route.outputs.iter().any(|output| captured.contains(output))
                {
                    return Err(unsupported("default route traverses captured port"));
                }
                if let Some(id) = route.nexthop {
                    self.check_gateway_nexthop(id, captured, &mut Vec::new())?;
                } else if route.output == 0 && route.outputs.is_empty() {
                    return Err(unsupported("default route has no verifiable output"));
                }
            }
            if enabled && !found {
                return Err(unsupported("enabled address family has no default route"));
            }
        }
        Ok(())
    }

    fn check_gateway_nexthop(
        &self,
        id: u32,
        captured: &[u32],
        path: &mut Vec<u32>,
    ) -> io::Result<()> {
        if path.len() == 16 || path.contains(&id) {
            return Err(unsupported("recursive gateway nexthop"));
        }
        let mut matches = self.nexthops.iter().filter(|next| next.id == id);
        let next = matches
            .next()
            .ok_or_else(|| unsupported("missing gateway nexthop"))?;
        if matches.next().is_some() || next.unsupported {
            return Err(unsupported("unrepresentable gateway nexthop"));
        }
        if captured.contains(&next.output) {
            return Err(unsupported("gateway nexthop traverses captured port"));
        }
        path.push(id);
        for child in &next.group {
            self.check_gateway_nexthop(*child, captured, path)?;
        }
        path.pop();
        Ok(())
    }

    fn ipv4_broadcasts(&self) -> io::Result<([Ipv4Addr; MAX_BROADCASTS], usize)> {
        let mut addresses = [Ipv4Addr::UNSPECIFIED; MAX_BROADCASTS];
        let mut count = 0;
        for route in self
            .routes
            .iter()
            .filter(|route| route.family == 2 && route.table == 255 && route.kind == 3)
        {
            let address = route
                .ipv4_destination
                .filter(|_| route.simple)
                .ok_or_else(|| {
                    unsupported("native broadcast requires a simple local-table IPv4 /32")
                })?;
            if self.routes.iter().any(|other| {
                other.family == 2
                    && other.table == 255
                    && other.ipv4_destination == Some(address)
                    && other.kind != 3
            }) {
                return Err(unsupported("ambiguous local broadcast destination"));
            }
            if addresses[..count].contains(&address) {
                continue;
            }
            if count == MAX_BROADCASTS {
                return Err(unsupported(
                    "native broadcast destinations exceed bounded capacity",
                ));
            }
            addresses[count] = address;
            count += 1;
        }
        addresses[..count].sort_unstable();
        Ok((addresses, count))
    }

    fn push(&mut self, kind: u16, body: &[u8]) -> io::Result<()> {
        if self.links.len()
            + self.addresses.len()
            + self.rules.len()
            + self.routes.len()
            + self.nexthops.len()
            >= MAX_OBJECTS
        {
            return Err(unsupported("topology snapshot exceeds bounded capacity"));
        }
        match kind {
            104 => {
                if body.len() < 8 {
                    return Err(malformed("short nexthop"));
                }
                let mut next = Nexthop {
                    id: 0,
                    output: 0,
                    group: Vec::new(),
                    unsupported: false,
                };
                let mut blackhole = false;
                let mut seen = 0;
                attributes(&body[8..], |kind, value| {
                    unique_attribute(&mut seen, kind)?;
                    match kind {
                        1 => next.id = exact_u32(value)?,
                        2 => {
                            if value.is_empty() || !value.len().is_multiple_of(8) {
                                return Err(malformed("invalid nexthop group"));
                            }
                            for child in value.as_chunks::<8>().0 {
                                if child[5..] != [0, 0, 0] {
                                    next.unsupported = true;
                                }
                                next.group.push(u32_at(child, 0)?);
                            }
                        }
                        3 if value.len() == 2 && u16::from_ne_bytes([value[0], value[1]]) == 0 => {}
                        4 if value.is_empty() => blackhole = true,
                        5 => next.output = exact_u32(value)?,
                        6 => {
                            ip_address(body[0], value)?;
                        }
                        _ => next.unsupported = true,
                    }
                    Ok(())
                })?;
                next.unsupported |=
                    next.id == 0 || (!blackhole && next.output == 0 && next.group.is_empty());
                self.nexthops.push(next);
            }
            16 => {
                if body.len() < 16 {
                    return Err(malformed("short topology link"));
                }
                let index = u32_at(body, 4)?;
                let flags = u32_at(body, 8)?;
                let arphrd = u16::from_ne_bytes([body[2], body[3]]);
                let mut link = Link {
                    index,
                    loopback: flags & 8 != 0,
                    name: None,
                    mtu: None,
                    tx_queue_len: None,
                    kind: None,
                    flags,
                    master: 0,
                    arphrd,
                    parent: index,
                    foreign_parent: false,
                    mac: [0; 6],
                    rx_queues: 0,
                    tx_queues: 0,
                    vlan: None,
                    bond: None,
                    tun_queues: None,
                    tun_disabled_queues: None,
                    big_tcp: false,
                    has_hardware_address: false,
                };
                let mut parent = index;
                let mut seen = 0;
                let mut seen_offload = 0;
                let mut info_data = None;
                let mut invalid_tun_info = false;
                raw_attributes(&body[16..], |raw_kind, value| {
                    let kind = raw_kind & NLA_TYPE_MASK;
                    match kind {
                        1 | 3 | 4 | 5 | 10 | libc::IFLA_TXQLEN | 18 | 31 | 32 => {
                            unique_attribute(&mut seen, kind)?
                        }
                        _ => {}
                    }
                    match kind {
                        1 if arphrd == 1 => {
                            if value.len() != 6 {
                                return Err(malformed("invalid link MAC"));
                            }
                            link.mac.copy_from_slice(value);
                        }
                        1 if arphrd == libc::ARPHRD_NONE => {
                            link.has_hardware_address = !value.is_empty();
                        }
                        31 => link.tx_queues = exact_u32(value)?,
                        32 => link.rx_queues = exact_u32(value)?,
                        3 => link.name = Some(netlink_name(value)?),
                        4 => link.mtu = Some(exact_u32(value)?),
                        5 => parent = exact_u32(value)?,
                        libc::IFLA_TXQLEN => link.tx_queue_len = Some(exact_u32(value)?),
                        libc::IFLA_LINK_NETNSID => {
                            exact_u32(value)?;
                            link.foreign_parent = true;
                        }
                        libc::IFLA_GSO_MAX_SIZE
                        | libc::IFLA_GRO_MAX_SIZE
                        | IFLA_GSO_IPV4_MAX_SIZE
                        | IFLA_GRO_IPV4_MAX_SIZE
                            if matches!(arphrd, libc::ARPHRD_NONE | libc::ARPHRD_ETHER) =>
                        {
                            unique_attribute(&mut seen_offload, kind - libc::IFLA_GSO_MAX_SIZE)?;
                            link.big_tcp |= exact_u32(value)? > LEGACY_OFFLOAD_MAX_SIZE;
                        }
                        10 => {
                            link.master = exact_u32(value)?;
                        }
                        18 => {
                            invalid_tun_info |= raw_kind & NLA_F_NET_BYTEORDER != 0;
                            let mut seen_info = 0;
                            raw_attributes(value, |raw_kind, value| {
                                let kind = raw_kind & NLA_TYPE_MASK;
                                match kind {
                                    1 => {
                                        unique_attribute(&mut seen_info, kind)?;
                                        invalid_tun_info |= raw_kind != kind;
                                        link.kind = Some(netlink_name(value)?);
                                    }
                                    2 => {
                                        invalid_tun_info |= info_data.replace(value).is_some()
                                            || raw_kind & NLA_F_NET_BYTEORDER != 0;
                                    }
                                    _ => {}
                                }
                                Ok(())
                            })?;
                        }
                        _ => {}
                    }
                    Ok(())
                })?;
                link.parent = parent;
                if invalid_tun_info && link.kind == Some(interface_name(b"tun")?) {
                    return Err(malformed("invalid TUN link info attributes"));
                }
                if let Some(data) = info_data {
                    if link.kind == Some(interface_name(b"vlan")?) {
                        let mut id = None;
                        let mut protocol = 0x8100;
                        let mut supported = true;
                        attributes(data, |kind, value| {
                            match kind {
                                1 if value.len() == 2 => {
                                    id = Some(u16::from_ne_bytes([value[0], value[1]]))
                                }
                                5 if value.len() == 2 => {
                                    protocol = u16::from_be_bytes([value[0], value[1]])
                                }
                                2 if value.len() == 8 => supported &= u32_at(value, 0)? & !1 == 0,
                                3 | 4 => attributes(value, |_, mapping| {
                                    if mapping.len() != 8 {
                                        return Err(malformed("invalid VLAN QoS mapping"));
                                    }
                                    supported &= u32_at(mapping, 4)? == 0;
                                    Ok(())
                                })?,
                                _ => supported = false,
                            }
                            Ok(())
                        })?;
                        link.vlan = id
                            .filter(|id| {
                                supported && *id < 4095 && matches!(protocol, 0x8100 | 0x88a8)
                            })
                            .map(|id| (protocol, id));
                    } else if link.kind == Some(interface_name(b"bond")?) {
                        let mut mode = None;
                        let mut hash = None;
                        attributes(data, |kind, value| {
                            match kind {
                                1 if value.len() == 1 => mode = Some(value[0]),
                                14 if value.len() == 1 => hash = Some(value[0]),
                                _ => {}
                            }
                            Ok(())
                        })?;
                        link.bond = mode.zip(hash);
                    } else if link.kind == Some(interface_name(b"tun")?) {
                        let mut seen = 0;
                        raw_attributes(data, |kind, value| {
                            let count = match kind & NLA_TYPE_MASK {
                                IFLA_TUN_NUM_QUEUES => &mut link.tun_queues,
                                IFLA_TUN_NUM_DISABLED_QUEUES => &mut link.tun_disabled_queues,
                                _ => return Ok(()),
                            };
                            if kind & !NLA_TYPE_MASK != 0 {
                                return Err(malformed("invalid TUN queue count attribute flags"));
                            }
                            unique_attribute(&mut seen, kind)?;
                            *count = Some(exact_u32(value)?);
                            Ok(())
                        })?;
                    }
                }
                self.links.push(link);
            }
            20 => {
                if body.len() < 8 {
                    return Err(malformed("short topology address"));
                }
                let family = body[0];
                if !matches!(family, 2 | 10) {
                    return Ok(());
                }
                let mut address = None;
                let mut local = None;
                let mut flags = u32::from(body[2]);
                let mut label = None;
                let mut unsupported = false;
                let mut permanent = true;
                let mut preferred = true;
                let mut seen = 0;
                attributes(&body[8..], |kind, value| {
                    unique_attribute(&mut seen, kind)?;
                    match kind {
                        1 => address = Some(ip_address(family, value)?),
                        2 => local = Some(ip_address(family, value)?),
                        3 => label = Some(netlink_name(value)?),
                        6 => {
                            if value.len() != 16 {
                                return Err(malformed("invalid topology address cache info"));
                            }
                            permanent =
                                u32_at(value, 0)? == u32::MAX && u32_at(value, 4)? == u32::MAX;
                            preferred = u32_at(value, 0)? != 0 && u32_at(value, 4)? != 0;
                        }
                        8 => flags = exact_u32(value)?,
                        11 if value.len() == 1 && value[0] == 0 => {}
                        _ => unsupported = true,
                    }
                    Ok(())
                })?;
                let ip = local
                    .or(address)
                    .ok_or_else(|| malformed("missing topology source address"))?;
                let unicast_source = match ip {
                    IpAddr::V4(ip) => unicast_source(family, &ip.octets())?,
                    IpAddr::V6(ip) => unicast_source(family, &ip.octets())?,
                };
                self.addresses.push(Address {
                    family,
                    index: u32_at(body, 4)?,
                    unicast_source,
                    address: ip,
                    peer: address.filter(|peer| *peer != ip),
                    prefix_len: body[1],
                    flags,
                    scope: body[3],
                    label,
                    unsupported,
                    permanent,
                    preferred,
                });
            }
            32 => {
                if body.len() < 12 {
                    return Err(malformed("short topology rule"));
                }
                let flags = u32_at(body, 8)?;
                let mut rule = Rule {
                    family: body[0],
                    priority: 0,
                    table: u32::from(body[4]),
                    mark: None,
                    mask: 0,
                    action: body[7],
                    iif: None,
                    oif: None,
                    flags,
                    unsupported: body[1..4] != [0, 0, 0] || body[5..7] != [0, 0],
                };
                let mut seen = 0;
                attributes(&body[12..], |kind, value| {
                    unique_attribute(&mut seen, kind)?;
                    match kind {
                        3 => {
                            rule.iif = Some(netlink_name(value)?);
                        }
                        6 => rule.priority = exact_u32(value)?,
                        10 => rule.mark = Some(exact_u32(value)?),
                        15 => rule.table = exact_u32(value)?,
                        16 => rule.mask = exact_u32(value)?,
                        17 => {
                            rule.oif = Some(netlink_name(value)?);
                            rule.unsupported = true;
                        }
                        14 if exact_u32(value)? == u32::MAX => {}
                        18 if value.is_empty() => {}
                        21 if value.len() == 1 => {}
                        _ => {
                            rule.unsupported = true;
                        }
                    }
                    Ok(())
                })?;
                self.rules.push(rule);
            }
            24 => {
                if body.len() < 12 {
                    return Err(malformed("short topology route"));
                }
                let mut route = Route {
                    family: body[0],
                    table: u32::from(body[4]),
                    output: 0,
                    input: 0,
                    default: body[1] == 0,
                    kind: body[7],
                    simple: body[2] == 0 && body[3] == 0,
                    native_multicast: body[0] == 10 && body[1] == 8 && body[7] == 5,
                    ipv4_destination: None,
                    destination: unspecified(body[0]),
                    prefix_len: body[1],
                    metric: 0,
                    protocol: body[5],
                    scope: body[6],
                    flags: u32_at(body, 8)?,
                    gateway: None,
                    source: None,
                    preference: 0,
                    unsupported: body[2] != 0 || body[3] != 0,
                    outputs: Vec::new(),
                    nexthop: None,
                    gateway_unsupported: false,
                };
                let mut multicast_destination = None;
                let mut seen = 0;
                attributes(&body[12..], |kind, value| {
                    unique_attribute(&mut seen, kind)?;
                    match kind {
                        1 => {
                            multicast_destination = Some(
                                value.len() == 16
                                    && value[0] == 0xff
                                    && value[1..].iter().all(|&byte| byte == 0),
                            );
                            // XDP historically refuses malformed non-/32 destinations at
                            // admission rather than parsing them as usable multicast.
                            route.destination = ip_address(route.family, value).ok();
                            if body[0] == 2 && body[1] == 32 {
                                route.ipv4_destination = Some(Ipv4Addr::from(
                                    <[u8; 4]>::try_from(value)
                                        .map_err(|_| malformed("invalid IPv4 route destination"))?,
                                ));
                            }
                        }
                        3 => {
                            route.input = exact_u32(value)?;
                            route.simple = false;
                            route.unsupported = true;
                            route.gateway_unsupported = true;
                        }
                        4 => route.output = exact_u32(value)?,
                        9 => {
                            let mut rest = value;
                            while !rest.is_empty() {
                                if rest.len() < 8 {
                                    return Err(malformed("short multipath nexthop"));
                                }
                                let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
                                if len < 8 || len > rest.len() || ((len + 3) & !3) > rest.len() {
                                    return Err(malformed("invalid multipath nexthop"));
                                }
                                let index = u32_at(rest, 4)?;
                                route.gateway_unsupported |= index == 0;
                                attributes(&rest[8..len], |kind, value| {
                                    if kind != 5 {
                                        route.gateway_unsupported = true;
                                        return Ok(());
                                    }
                                    ip_address(route.family, value)?;
                                    Ok(())
                                })?;
                                route.outputs.push(index);
                                rest = &rest[(len + 3) & !3..];
                            }
                            route.simple = false;
                            route.unsupported = true;
                        }
                        30 => {
                            route.nexthop = Some(exact_u32(value)?);
                            route.simple = false;
                            route.unsupported = true;
                        }
                        5 => route.gateway = Some(ip_address(route.family, value)?),
                        6 => route.metric = exact_u32(value)?,
                        7 => route.source = Some(ip_address(route.family, value)?),
                        12 => {
                            if value.len() != 32 {
                                return Err(malformed("invalid topology route cache info"));
                            }
                            route.unsupported |= u32_at(value, 8)? != 0 || u32_at(value, 12)? != 0;
                        }
                        15 => route.table = exact_u32(value)?,
                        20 if value.len() == 1 && matches!(value[0], 0 | 1 | 3) => {
                            route.preference = value[0];
                        }
                        8 | 23 => route.unsupported = true,
                        _ => {
                            route.simple = false;
                            route.unsupported = true;
                            route.gateway_unsupported = true;
                        }
                    }
                    Ok(())
                })?;
                route.unsupported |= route
                    .destination
                    .is_none_or(|ip| !network_address(ip, route.prefix_len))
                    || (route.prefix_len != 0 && multicast_destination.is_none());
                route.native_multicast &= route.simple && multicast_destination == Some(true);
                route.simple &= route.flags == 0;
                route.native_multicast &= route.simple;
                self.routes.push(route);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn admit_tun(
        &self,
        spec: &TunSpec<'_>,
        name: [u8; 16],
        owned: Option<(u32, TunStage)>,
    ) -> io::Result<()> {
        if self.tun_ready(
            spec,
            name,
            owned.map(|(index, _)| index),
            owned.map(|(_, stage)| stage),
        )? {
            Ok(())
        } else {
            Err(unsupported("owned TUN address lacks its exact local route"))
        }
    }

    fn tun_ready(
        &self,
        spec: &TunSpec<'_>,
        name: [u8; 16],
        ifindex: Option<u32>,
        stage: Option<TunStage>,
    ) -> io::Result<bool> {
        let mut indices = HashSet::new();
        let mut names = HashSet::new();
        let vrf = interface_name(b"vrf")?;
        for link in &self.links {
            if link.index == 0
                || !indices.insert(link.index)
                || link.name.is_none_or(|name| !names.insert(name))
                || link.kind == Some(vrf)
            {
                return Err(unsupported("TUN requires unique named links without VRFs"));
            }
        }
        if let Some(index) = ifindex {
            let link = self
                .links
                .iter()
                .find(|link| link.index == index && link.is_owned_tun(name, spec.mtu))
                .ok_or_else(|| unsupported("owned TUN name, MTU, kind, flags or master changed"))?;
            if !tun_queues_match(spec.queues, link.tun_queues, link.tun_disabled_queues) {
                return Err(unsupported(
                    "owned TUN active or disabled queue count changed",
                ));
            }
        } else if self.links.iter().any(|link| link.name == Some(name)) {
            return Err(unsupported("TUN name is already occupied"));
        }
        let expected_addresses: Vec<_> = spec.addresses().collect();
        let mut found_addresses = HashSet::new();
        for address in &self.addresses {
            if Some(address.index) == ifindex {
                let flags = IFA_F_PERMANENT
                    | IFA_F_NOPREFIXROUTE
                    | if address.family == 10 { IFA_F_NODAD } else { 0 };
                if !expected_addresses.contains(&address.address)
                    || !found_addresses.insert(address.address)
                    || address.prefix_len != if address.family == 2 { 32 } else { 128 }
                    || address.flags != flags
                    || address.scope != 0
                    || address.peer.is_some()
                    || address.unsupported
                    || !address.permanent
                    || address.label.is_some_and(|label| label != name)
                {
                    return Err(unsupported(
                        "owned TUN addresses do not match the exact permanent host keys",
                    ));
                }
            } else if expected_addresses.contains(&address.address)
                || address
                    .peer
                    .is_some_and(|peer| expected_addresses.contains(&peer))
            {
                return Err(unsupported(
                    "TUN address is already occupied on another link",
                ));
            }
        }
        if ifindex.is_some() && found_addresses.len() != expected_addresses.len() {
            return Err(unsupported("owned TUN address is missing"));
        }
        let mut ready = true;
        if let Some(index) = ifindex {
            for address in &expected_addresses {
                let family = if address.is_ipv4() { 2 } else { 10 };
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                let mut local = self.routes.iter().filter(|route| {
                    route.family == family
                        && route.table == 255
                        && route.destination == Some(*address)
                        && route.prefix_len == prefix
                });
                match (local.next(), local.next()) {
                    (None, None) if address.is_ipv6() => ready = false,
                    (Some(route), None) if route.kind == 2 && route.output == index => {}
                    _ => {
                        return Err(unsupported(
                            "owned TUN local route is missing, conflicting or duplicated",
                        ));
                    }
                }
            }
        }
        let expected_rules = spec.rules();
        let mut seen_rules = Vec::with_capacity(expected_rules.len());
        for rule in &self.rules {
            let reserved = (spec.rule_priority..=spec.rule_priority + 4).contains(&rule.priority);
            if reserved {
                let key = ifindex.zip(stage).and_then(|(index, _)| {
                    self.tun_rule_key(spec, &expected_rules, rule, index, false)
                });
                if key.is_none() || seen_rules.contains(&key) {
                    return Err(unsupported(
                        "TUN priority range contains a foreign or duplicate rule",
                    ));
                }
                seen_rules.push(key);
            } else if rule.table == spec.table {
                return Err(unsupported("another rule references the TUN capture table"));
            } else if matches!(rule.family, 2 | 10) && !Self::system_tun_rule(rule) {
                return Err(unsupported(
                    "TUN requires only standard local, main and default operator rules",
                ));
            }
        }
        if stage.is_some() && seen_rules.len() != expected_rules.len() {
            return Err(unsupported(
                "TUN requires all five exact rules per enabled family",
            ));
        }
        for ipv6 in spec.families() {
            let family = if ipv6 { 10 } else { 2 };
            for (priority, required) in [(0, true), (32766, true), (32767, false)] {
                let count = self
                    .rules
                    .iter()
                    .filter(|rule| rule.family == family && rule.priority == priority)
                    .count();
                if count > 1 || (required && count != 1) {
                    return Err(unsupported(
                        "TUN requires unique standard local and main rules",
                    ));
                }
            }
        }
        let mut expected_routes = if stage.is_some() {
            spec.guard_routes()
        } else {
            Vec::new()
        };
        if let (Some(index), Some(TunStage::Active)) = (ifindex, stage) {
            expected_routes.extend(spec.capture_routes(index));
        }
        let mut seen_routes = Vec::with_capacity(expected_routes.len());
        for route in &self.routes {
            if route.table == spec.table {
                let key = ifindex
                    .zip(stage)
                    .and_then(|(index, _)| self.tun_route_key(spec, route, index));
                if key.is_none_or(|key| !expected_routes.contains(&key))
                    || seen_routes.contains(&key)
                {
                    return Err(unsupported(
                        "TUN capture table contains a foreign, wrong-stage or duplicate route",
                    ));
                }
                seen_routes.push(key);
            } else if matches!(route.family, 2 | 10) && route.table == 255 {
                let own_local = route.kind == 2
                    && route.prefix_len == if route.family == 2 { 32 } else { 128 }
                    && route
                        .destination
                        .is_some_and(|destination| expected_addresses.contains(&destination));
                if route.unsupported
                    || route.flags != 0
                    || !matches!(route.kind, 2..=5)
                    || (Some(route.output) == ifindex && !own_local && !route.native_multicast)
                {
                    return Err(unsupported(
                        "TUN requires representable local routes without alternate capture paths",
                    ));
                }
            } else if matches!(route.family, 2 | 10) && matches!(route.table, 253 | 254) {
                if !self.operator_tun_route(route, ifindex) {
                    return Err(unsupported(
                        "operator main/default routes must be verifiable and avoid the TUN",
                    ));
                }
            } else if route.output != 0 && Some(route.output) == ifindex {
                return Err(unsupported("another routing table selects the owned TUN"));
            }
        }
        if stage.is_some() && seen_routes.len() != expected_routes.len() {
            return Err(unsupported(
                "TUN capture table is missing an exact guard or active route",
            ));
        }
        for ipv6 in spec.families() {
            let family = if ipv6 { 10 } else { 2 };
            if !self.routes.iter().any(|route| {
                route.family == family && route.table == 254 && route.kind == 1 && route.default
                    && self.addresses.iter().any(|address| {
                        address.family == family && address.index == route.output
                            && address.unicast_source && address.preferred && address.scope == 0
                            && address.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED | 0x20) == 0
                            && (family != 10 || !matches!(address.address, IpAddr::V6(ip) if ip.is_unicast_link_local() || ip.to_ipv4_mapped().is_some()))
                            && route.source.is_none_or(|source| source == address.address)
                    })
            }) {
                return Err(unsupported("each enabled TUN family needs a non-TUN main default and usable uplink source"));
            }
        }
        Ok(ready)
    }

    fn tun_link(&self, spec: &TunSpec<'_>, index: u32) -> bool {
        let Ok(name) = interface_name(spec.name.as_bytes()) else {
            return false;
        };
        self.links
            .iter()
            .any(|link| link.index == index && link.is_owned_tun(name, spec.mtu))
    }

    fn system_tun_rule(rule: &Rule) -> bool {
        !rule.unsupported
            && rule.flags == 0
            && rule.action == 1
            && rule.mark.is_none()
            && rule.mask == 0
            && rule.iif.is_none()
            && matches!(
                (rule.priority, rule.table),
                (0, 255) | (32766, 254) | (32767, 253)
            )
    }

    fn operator_tun_route(&self, route: &Route, owned: Option<u32>) -> bool {
        if route.unsupported
            || route.flags != 0
            || !matches!(route.scope, 0 | 253)
            || !matches!(route.kind, 1 | RTN_BLACKHOLE | 7 | FR_ACT_PROHIBIT | 9)
        {
            return false;
        }
        if route.kind != 1 {
            return (route.output == 0
                || (route.family == 10
                    && self
                        .links
                        .iter()
                        .any(|link| link.index == route.output && link.loopback)))
                && route.gateway.is_none()
                && route.source.is_none();
        }
        Some(route.output) != owned
            && self.links.iter().any(|link| {
                let direct_link = link.kind.is_none()
                    || [
                        b"veth".as_slice(),
                        b"bridge",
                        b"bond",
                        b"vlan",
                        b"macvlan",
                        b"ipvlan",
                        b"team",
                    ]
                    .iter()
                    .any(|kind| interface_name(kind).ok() == link.kind);
                link.index == route.output
                    && link.flags & 1 != 0
                    && !link.loopback
                    && link.master == 0
                    && direct_link
            })
            && route.source.is_none_or(|source| {
                self.addresses.iter().any(|address| {
                    address.index == route.output
                        && address.address == source
                        && address.unicast_source
                        && address.preferred
                        && address.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED | 0x20) == 0
                })
            })
    }

    fn tun_rule_key(
        &self,
        spec: &TunSpec<'_>,
        expected: &[TunRule],
        rule: &Rule,
        ifindex: u32,
        cleanup: bool,
    ) -> Option<TunRule> {
        if rule.unsupported || !matches!(rule.family, 2 | 10) {
            return None;
        }
        let name = interface_name(spec.name.as_bytes()).ok()?;
        let selector = match (rule.mark, rule.mask, rule.iif) {
            (Some(mark), u32::MAX, None) => TunRuleSelector::Fwmark(mark),
            (None, 0, Some(iif)) if iif == name => TunRuleSelector::Iif,
            (None, 0, None) => TunRuleSelector::All,
            _ => return None,
        };
        let detached = cleanup
            && selector == TunRuleSelector::Iif
            && !self
                .links
                .iter()
                .any(|link| link.index == ifindex || link.name == Some(name));
        if rule.flags != if detached { FIB_RULE_IIF_DETACHED } else { 0 } {
            return None;
        }
        if selector == TunRuleSelector::Iif && !detached && !self.tun_link(spec, ifindex) {
            return None;
        }
        let action = match (rule.action, rule.table) {
            (1, table) if table != 0 => TunRuleAction::Lookup(table),
            (FR_ACT_PROHIBIT, 0) => TunRuleAction::Prohibit,
            _ => return None,
        };
        let key = TunRule {
            ipv6: rule.family == 10,
            priority: rule.priority,
            selector,
            action,
        };
        expected.contains(&key).then_some(key)
    }

    fn tun_route_key(&self, spec: &TunSpec<'_>, route: &Route, ifindex: u32) -> Option<TunRoute> {
        if route.unsupported
            || route.protocol != RTPROT_STATIC
            || route.flags != 0
            || route.gateway.is_some()
            || route.source.is_some()
            || route.preference != 0
        {
            return None;
        }
        let kind = match route.kind {
            RTN_BLACKHOLE
                if route.scope == 0
                    && (route.output == 0
                        || (route.family == 10
                            && self
                                .links
                                .iter()
                                .any(|link| link.index == route.output && link.loopback))) =>
            {
                TunRouteKind::Blackhole
            }
            1 if ifindex != 0
                && route.output == ifindex
                && self.tun_link(spec, ifindex)
                && route.scope == if route.family == 2 { 253 } else { 0 } =>
            {
                TunRouteKind::Unicast { oif: ifindex }
            }
            _ => return None,
        };
        let key = TunRoute {
            table: route.table,
            destination: route.destination?,
            prefix_len: route.prefix_len,
            kind,
            metric: route.metric,
        };
        let metric = match kind {
            TunRouteKind::Blackhole => TUN_GUARD_METRIC,
            TunRouteKind::Unicast { .. } => TUN_CAPTURE_METRIC,
        };
        (key.table == spec.table
            && key.metric == metric
            && spec.capture.contains(&(key.destination, key.prefix_len)))
        .then_some(key)
    }

    fn tun_readback(&self, spec: &TunSpec<'_>, ifindex: u32) -> io::Result<TunReadback> {
        let expected_rules = spec.rules();
        let mut links = self.links.iter().filter(|link| link.index == ifindex);
        let link = links.next();
        if links.next().is_some() {
            return Err(malformed("duplicate TUN readback ifindex"));
        }
        let name = interface_name(spec.name.as_bytes())?;
        let kind = interface_name(b"tun")?;
        let tun = link.filter(|link| {
            link.name == Some(name) && link.kind == Some(kind) && link.arphrd == libc::ARPHRD_NONE
        });
        let mut readback = TunReadback {
            link: link.is_some(),
            owned_tun: tun.is_some(),
            num_queues: tun.and_then(|link| link.tun_queues),
            num_disabled_queues: tun.and_then(|link| link.tun_disabled_queues),
            addresses: self
                .addresses
                .iter()
                .filter(|address| address.index == ifindex)
                .map(|address| (address.address, address.prefix_len))
                .collect(),
            routes: Vec::new(),
            rules: Vec::new(),
        };
        for route in self.routes.iter().filter(|route| route.table == spec.table) {
            let destination = route
                .destination
                .ok_or_else(|| malformed("unrepresentable route in TUN cleanup table"))?;
            readback.routes.push((
                route.table,
                destination,
                route.prefix_len,
                route.metric,
                self.tun_route_key(spec, route, ifindex),
            ));
        }
        for rule in self
            .rules
            .iter()
            .filter(|rule| (spec.rule_priority..=spec.rule_priority + 4).contains(&rule.priority))
        {
            if !matches!(rule.family, 2 | 10) {
                return Err(unsupported(
                    "unrepresentable rule family in TUN cleanup priority range",
                ));
            }
            readback.rules.push((
                rule.family == 10,
                rule.priority,
                self.tun_rule_key(spec, &expected_rules, rule, ifindex, true),
            ));
        }
        Ok(readback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod tun;

    pub(super) fn dump_message(sequence: u32, kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = capture_notification(kind, body);
        bytes[6..8].copy_from_slice(&flags.to_ne_bytes());
        bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
        bytes
    }

    #[test]
    fn dump_retry_restarts_full_snapshot_after_interruption() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        for interrupt_on_done in [false, true] {
            let budget = MemoryBudget::new(RTNL_BUFFER_BYTES);
            let mut buffer = CaptureBuffer::new(&budget).unwrap();
            let buffer_address = buffer.bytes.as_ptr();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut previous_peer: Option<UnixStream> = None;
            let mut opened = 0;
            let mut read = 0;
            let snapshot = with_topology_dump_socket(
                Some(42),
                deadline,
                &mut buffer.bytes,
                || {
                    if let Some(mut peer) = previous_peer.take() {
                        assert_eq!(peer.read(&mut [0]).unwrap(), 0, "old dump socket is open");
                    }
                    let (socket, mut peer) = UnixStream::pair()?;
                    peer.set_nonblocking(true)?;
                    opened += 1;
                    peer.write_all(&[opened])?;
                    previous_peer = Some(peer);
                    Ok((socket.into(), 42))
                },
                |dump| {
                    assert_eq!(dump.deadline, deadline);
                    assert_eq!(dump.buffer.as_ptr(), buffer_address);
                    read += 1;
                    let mut marker = [0];
                    UnixStream::from(dump.fd.try_clone_to_owned()?).read_exact(&mut marker)?;
                    assert_eq!(marker, [read]);

                    let index = u32::from(read) + 10;
                    let mut link =
                        dump_message(1, libc::RTM_NEWLINK, 2, &capture_link_body(index, 1500, 1));
                    link.extend(dump_message(1, 3, 2, &[0; 4]));
                    let mut snapshot = Snapshot::default();
                    let mut record = |kind, body: &[u8]| snapshot.push(kind, body);
                    assert!(dump_datagram(&link, 1, libc::RTM_GETLINK, &mut record)?);

                    let mut route = vec![0; 12];
                    route[0] = 2;
                    route[4] = 254;
                    route[7] = 1;
                    attribute(&mut route, 4, &index.to_ne_bytes());
                    let route_flags = if read == 1 && !interrupt_on_done {
                        2 | NLM_F_DUMP_INTR
                    } else {
                        2
                    };
                    let route = dump_message(2, libc::RTM_NEWROUTE, route_flags, &route);
                    assert!(!dump_datagram(&route, 2, libc::RTM_GETROUTE, &mut record)?);
                    let done_flags = if read == 1 && interrupt_on_done {
                        2 | NLM_F_DUMP_INTR
                    } else {
                        2
                    };
                    let done = dump_message(2, 3, done_flags, &[0; 4]);
                    assert!(dump_datagram(&done, 2, libc::RTM_GETROUTE, &mut record)?);
                    Ok(snapshot)
                },
            )
            .unwrap();
            assert_eq!((opened, read), (2, 2));
            assert_eq!(snapshot.links.len(), 1);
            assert_eq!(snapshot.links[0].index, 12);
            assert_eq!(snapshot.routes.len(), 1);
            assert_eq!(snapshot.routes[0].output, 12);
            assert_eq!(budget.used(), RTNL_BUFFER_BYTES);
        }
    }

    #[test]
    fn dump_retry_exhausts_after_eight_socket_attempts() {
        let deadline = Instant::now() + Duration::from_secs(10);
        let done = dump_message(1, 3, 2 | NLM_F_DUMP_INTR, &[0; 4]);
        let mut opened = 0;
        let error = with_topology_dump_socket(
            None,
            deadline,
            &mut [],
            || {
                opened += 1;
                Ok((std::fs::File::open("/dev/null")?.into(), 42))
            },
            |dump| {
                assert_eq!(dump.deadline, deadline);
                dump_datagram(&done, 1, libc::RTM_GETLINK, |_, _| unreachable!())
            },
        )
        .unwrap_err();
        assert_eq!(opened, 8);
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(error.to_string(), DUMP_INTERRUPTED);
    }

    #[test]
    fn dump_retry_preserves_terminal_kernel_timeout() {
        let done = dump_message(1, 3, NLM_F_DUMP_INTR, &(-libc::EINTR).to_ne_bytes());
        let kernel_error = dump_message(1, 2, 0, &(-libc::ETIMEDOUT).to_ne_bytes());
        let mut replies = [done, kernel_error].into_iter();
        let error = with_topology_dump_socket(
            None,
            Instant::now() + Duration::from_secs(10),
            &mut [],
            || Ok((std::fs::File::open("/dev/null")?.into(), 42)),
            |_| {
                dump_datagram(
                    &replies.next().unwrap(),
                    1,
                    libc::RTM_GETLINK,
                    |_, _| unreachable!(),
                )
            },
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ETIMEDOUT));
        assert!(replies.next().is_none());
    }

    #[test]
    fn dump_retry_only_retries_matched_dump_interruptions() {
        use io::ErrorKind::{Interrupted, InvalidData, Unsupported};

        for (message, kind, errno) in [
            (
                dump_message(2, 3, NLM_F_DUMP_INTR, &[0; 4]),
                Unsupported,
                None,
            ),
            (
                dump_message(1, 3, NLM_F_DUMP_INTR, &[0; 2]),
                InvalidData,
                None,
            ),
            (
                dump_message(1, 3, NLM_F_DUMP_INTR, &(-libc::EINVAL).to_ne_bytes()),
                InvalidData,
                None,
            ),
            (
                dump_message(1, 2, 0, &(-libc::EOPNOTSUPP).to_ne_bytes()),
                Unsupported,
                Some(libc::EOPNOTSUPP),
            ),
            (
                dump_message(1, 2, 0, &(-libc::EINTR).to_ne_bytes()),
                Interrupted,
                Some(libc::EINTR),
            ),
            (
                dump_message(1, libc::RTM_NEWLINK, 2, &[0; 16]),
                Unsupported,
                None,
            ),
        ] {
            let mut opened = 0;
            let error = with_topology_dump_socket(
                None,
                Instant::now() + Duration::from_secs(10),
                &mut [],
                || {
                    opened += 1;
                    Ok((std::fs::File::open("/dev/null")?.into(), 42))
                },
                |_| {
                    dump_datagram(&message, 1, libc::RTM_GETLINK, |_, _| {
                        Err(unsupported("test topology policy refusal"))
                    })
                },
            )
            .unwrap_err();
            assert_eq!(opened, 1);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.raw_os_error(), errno);
        }
    }

    #[test]
    fn dump_retry_fences_namespace() {
        let done = dump_message(1, 3, NLM_F_DUMP_INTR, &[0; 4]);
        for (expected_cookie, first_cookie, expected_counts) in [
            (None, 42, (2, 1)),
            (Some(42), 42, (2, 1)),
            (Some(41), 42, (1, 0)),
        ] {
            let mut opened = 0;
            let mut read = 0;
            let error = with_topology_dump_socket(
                expected_cookie,
                Instant::now() + Duration::from_secs(10),
                &mut [],
                || {
                    opened += 1;
                    let cookie = if opened == 1 { first_cookie } else { 43 };
                    Ok((std::fs::File::open("/dev/null")?.into(), cookie))
                },
                |_| {
                    read += 1;
                    dump_datagram(&done, 1, libc::RTM_GETLINK, |_, _| unreachable!())
                },
            )
            .unwrap_err();
            assert_eq!((opened, read), expected_counts);
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    pub(super) fn capture_notification(kind: u16, body: &[u8]) -> Vec<u8> {
        let length = 16 + body.len();
        let mut bytes = vec![0; 16];
        bytes[..4].copy_from_slice(&(length as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(body);
        bytes.resize((length + 3) & !3, 0);
        bytes
    }

    fn capture_link_body(index: u32, mtu: u32, flags: u32) -> Vec<u8> {
        let mut body = vec![0; 16];
        body[2..4].copy_from_slice(&1u16.to_ne_bytes());
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        body[8..12].copy_from_slice(&flags.to_ne_bytes());
        attribute(&mut body, 1, &[2; 6]);
        attribute(&mut body, 4, &mtu.to_ne_bytes());
        attribute(&mut body, 31, &2u32.to_ne_bytes());
        attribute(&mut body, 32, &2u32.to_ne_bytes());
        body
    }

    #[test]
    fn numbered_bond_members_share_logical_vlan_realms() {
        let mut snapshot = topology();
        let mut root = capture_link_body(10, 1500, 1);
        attribute(&mut root, 3, b"bond0\0");
        let mut data = Vec::new();
        attribute(&mut data, 1, &[4]);
        attribute(&mut data, 14, &[2]);
        let mut info = Vec::new();
        attribute(&mut info, 1, b"bond\0");
        attribute(&mut info, 2, &data);
        attribute(&mut root, 18, &info);
        snapshot.push(16, &root).unwrap();
        for (index, name) in [(11, b"member0\0"), (12, b"member1\0")] {
            let mut member = capture_link_body(index, 1500, 1);
            attribute(&mut member, 3, name);
            attribute(&mut member, 10, &10u32.to_ne_bytes());
            snapshot.push(16, &member).unwrap();
        }
        let mut vlan = capture_link_body(13, 1400, 1);
        attribute(&mut vlan, 3, b"bond0.7\0");
        attribute(&mut vlan, 5, &10u32.to_ne_bytes());
        let mut vlan_data = Vec::new();
        attribute(&mut vlan_data, 1, &7u16.to_ne_bytes());
        let mut vlan_info = Vec::new();
        attribute(&mut vlan_info, 1, b"vlan\0");
        attribute(&mut vlan_info, 2, &vlan_data);
        attribute(&mut vlan, 18, &vlan_info);
        snapshot.push(16, &vlan).unwrap();
        snapshot.addresses.push(xdp_address(2, 10));
        let realms = capture_layout_snapshot(&snapshot, &["bond0".into()]).unwrap();
        assert_eq!(realms.len(), 2);
        assert_eq!(realms[0].logical_ifindex, 10);
        assert_eq!(realms[0].root_ifindex, 10);
        assert_eq!(realms[0].members, ["member0", "member1"]);
        assert_eq!(realms[1].members, realms[0].members);
        assert_eq!(realms[1].logical_ifindex, 13);
        assert_eq!(realms[1].root_ifindex, 10);
        assert_eq!(realms[1].vlan_count, 1);
        assert_eq!(realms[1].tpid, [0x8100, 0]);
        assert_eq!(realms[1].vid, [7, 0]);
        snapshot
            .links
            .iter_mut()
            .find(|link| link.index == 10)
            .unwrap()
            .bond = Some((4, 5));
        assert!(capture_layout_snapshot(&snapshot, &["bond0".into()]).is_err());
    }

    #[test]
    fn capture_watch_ignores_carrier_statistics_and_other_devices() {
        let mut snapshot = Snapshot::default();
        snapshot
            .push(16, &capture_link_body(2, 1500, 0x10001))
            .unwrap();
        let watch = CaptureWatch {
            fd: route_socket(false).unwrap(),
            buffer: CaptureBuffer::new(&MemoryBudget::new(RTNL_BUFFER_BYTES)).unwrap(),
            links: snapshot.links,
            programs: Vec::new(),
            invalidated: false,
            ipv4_broadcasts: [Ipv4Addr::UNSPECIFIED; MAX_BROADCASTS],
            broadcast_count: 0,
        };
        let mut carrier = capture_link_body(2, 1500, 1);
        attribute(&mut carrier, 23, &[0; 32]);
        assert!(
            !watch
                .datagram(&capture_notification(16, &carrier), |_| Ok(
                    crate::XdpState::default()
                ))
                .unwrap()
        );
        for kind in [16, 17] {
            let mut other = vec![0; 16];
            other[2..4].copy_from_slice(&512u16.to_ne_bytes());
            other[4..8].copy_from_slice(&9u32.to_ne_bytes());
            attribute(&mut other, 3, b"pppoe0\0");
            assert!(
                !watch
                    .datagram(&capture_notification(kind, &other), |_| panic!(
                        "unrelated program readback"
                    ))
                    .unwrap()
            );
        }
        let address = address_body(10, 9, &[0x20; 16], None);
        assert!(
            watch
                .datagram(&capture_notification(20, &address), |_| panic!(
                    "address program readback"
                ))
                .unwrap()
        );
        for kind in [24, 25, 32, 33] {
            let mut body = vec![0; 12];
            body[0] = 2;
            attribute(&mut body, 99, &[1, 2, 3, 4]);
            assert!(
                !watch
                    .datagram(&capture_notification(kind, &body), |_| panic!(
                        "route or rule program readback"
                    ))
                    .unwrap()
            );
        }
    }

    #[test]
    fn capture_watch_rejects_new_captured_bond_member() {
        let mut snapshot = Snapshot::default();
        let mut bond = capture_link_body(10, 1500, 1);
        let mut info = Vec::new();
        attribute(&mut info, 1, b"bond\0");
        attribute(&mut bond, 18, &info);
        snapshot.push(16, &bond).unwrap();
        let watch = CaptureWatch {
            fd: route_socket(false).unwrap(),
            buffer: CaptureBuffer::new(&MemoryBudget::new(RTNL_BUFFER_BYTES)).unwrap(),
            links: snapshot.links,
            programs: Vec::new(),
            invalidated: false,
            ipv4_broadcasts: [Ipv4Addr::UNSPECIFIED; MAX_BROADCASTS],
            broadcast_count: 0,
        };
        assert!(
            !watch
                .datagram(&capture_notification(16, &bond), |_| Ok(
                    crate::XdpState::default()
                ))
                .unwrap()
        );
        let mut member = capture_link_body(11, 1500, 1);
        attribute(&mut member, 10, &10u32.to_ne_bytes());
        assert!(
            watch
                .datagram(&capture_notification(16, &member), |_| panic!(
                    "unknown program readback"
                ))
                .is_err()
        );
        let mut other = capture_link_body(11, 1500, 1);
        attribute(&mut other, 10, &12u32.to_ne_bytes());
        assert!(
            !watch
                .datagram(&capture_notification(16, &other), |_| panic!(
                    "unknown program readback"
                ))
                .unwrap()
        );
    }

    #[test]
    fn capture_watch_rejects_identity_loss_and_unregistered_programs() {
        let mut snapshot = Snapshot::default();
        let baseline = capture_link_body(2, 1500, 1);
        snapshot.push(16, &baseline).unwrap();
        let mut watch = CaptureWatch {
            fd: route_socket(false).unwrap(),
            buffer: CaptureBuffer::new(&MemoryBudget::new(RTNL_BUFFER_BYTES)).unwrap(),
            links: snapshot.links,
            programs: Vec::new(),
            invalidated: false,
            ipv4_broadcasts: [Ipv4Addr::UNSPECIFIED; MAX_BROADCASTS],
            broadcast_count: 0,
        };
        assert!(
            watch
                .datagram(
                    &capture_notification(16, &capture_link_body(2, 9000, 1)),
                    |_| Ok(crate::XdpState::default())
                )
                .is_err()
        );
        for range in [20..26, 40..44, 48..52] {
            let mut changed = baseline.clone();
            changed[range].fill(7);
            assert!(
                watch
                    .datagram(&capture_notification(16, &changed), |_| Ok(
                        crate::XdpState::default()
                    ))
                    .is_err()
            );
        }
        let mut mastered = baseline.clone();
        attribute(&mut mastered, 10, &9u32.to_ne_bytes());
        assert!(
            watch
                .datagram(&capture_notification(16, &mastered), |_| Ok(
                    crate::XdpState::default()
                ))
                .is_err()
        );
        assert!(
            watch
                .datagram(&capture_notification(17, &baseline), |_| Ok(
                    crate::XdpState::default()
                ))
                .is_err()
        );
        assert!(
            watch
                .datagram(&[0; 7], |_| Ok(crate::XdpState::default()))
                .is_err()
        );
        let owned = crate::XdpState {
            attached: 1,
            prog_id: 17,
            drv_prog_id: 17,
            ..crate::XdpState::default()
        };
        assert!(
            watch
                .datagram(&capture_notification(16, &baseline), |_| Ok(owned))
                .is_err()
        );
        watch.expect_program(2, 17);
        assert!(
            !watch
                .datagram(&capture_notification(16, &baseline), |_| Ok(owned))
                .unwrap()
        );
        let foreign = crate::XdpState {
            prog_id: 18,
            drv_prog_id: 18,
            ..owned
        };
        assert!(
            watch
                .datagram(&capture_notification(16, &baseline), |_| Ok(foreign))
                .is_err()
        );
        assert_eq!(
            watch
                .check_with(|_| Err(io::Error::from_raw_os_error(libc::ENOBUFS)))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOBUFS)
        );
        assert!(
            watch
                .check_with(|_| panic!("lost watch cannot regain authority"))
                .is_err()
        );
    }

    #[test]
    fn capture_watch_buffer_budget_covers_overlap_and_returns_on_drop() {
        let budget = MemoryBudget::new(2 * RTNL_BUFFER_BYTES);
        let occupied = budget.reserve(1).unwrap();
        let first = CaptureBuffer::new(&budget).unwrap();
        assert_eq!(first.bytes.len(), RTNL_BUFFER_BYTES);
        assert_eq!(budget.used(), RTNL_BUFFER_BYTES + 1);

        let error = CaptureBuffer::new(&budget).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(budget.used(), RTNL_BUFFER_BYTES + 1);

        drop(occupied);
        let replacement = CaptureBuffer::new(&budget).unwrap();
        assert_eq!(budget.used(), 2 * RTNL_BUFFER_BYTES);
        drop(first);
        assert_eq!(budget.used(), RTNL_BUFFER_BYTES);
        drop(replacement);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn gateway_checks_defaults_in_every_table_and_nexthop_member() {
        let mut snapshot = topology();
        assert!(check_gateway_defaults_snapshot(&snapshot, &[2]).is_ok());
        snapshot.routes.push(xdp_route(2, 900, 2, true, 1));
        assert!(check_gateway_defaults_snapshot(&snapshot, &[2]).is_err());
        snapshot.routes.pop();
        let mut route = xdp_route(2, 900, 0, true, 1);
        route.nexthop = Some(40);
        snapshot.routes.push(route);
        snapshot.nexthops.push(Nexthop {
            id: 40,
            output: 0,
            group: vec![41, 42],
            unsupported: false,
        });
        snapshot.nexthops.push(Nexthop {
            id: 41,
            output: 3,
            group: Vec::new(),
            unsupported: false,
        });
        snapshot.nexthops.push(Nexthop {
            id: 42,
            output: 2,
            group: Vec::new(),
            unsupported: false,
        });
        assert!(check_gateway_defaults_snapshot(&snapshot, &[2]).is_err());
        snapshot.nexthops[2].output = 3;
        assert!(check_gateway_defaults_snapshot(&snapshot, &[2]).is_ok());
        snapshot.nexthops[2].group.push(40);
        assert!(check_gateway_defaults_snapshot(&snapshot, &[2]).is_err());
    }

    #[test]
    fn tun_notifications_distinguish_unrelated_and_owned_objects() {
        let spec = TunWatch {
            name: "tun0".into(),
            mtu: 1500,
            queues: 1,
            address4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            address6: None,
            table: 100,
            rule_priority: 1000,
            bypass_mark: 128,
            capture: vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)],
        };
        let message = |kind: u16, body: &[u8]| {
            let length = 16 + body.len();
            let mut bytes = vec![0; 16];
            bytes[..4].copy_from_slice(&(length as u32).to_ne_bytes());
            bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
            bytes.extend_from_slice(body);
            bytes.resize((length + 3) & !3, 0);
            bytes
        };
        let other = address_body(2, 3, &[198, 51, 100, 1], None);
        let owned = address_body(2, 9, &[192, 0, 2, 1], None);
        let spec = spec.spec();
        assert!(!tun_notifications(&message(20, &other), &spec, 9).unwrap());
        assert!(tun_notifications(&message(21, &owned), &spec, 9).unwrap());
        assert!(tun_notifications(&[1, 2, 3], &spec, 9).is_err());
    }

    pub(super) fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
        let length = value.len() + 4;
        bytes.extend_from_slice(&(length as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
    }

    fn address_body(family: u8, index: u32, address: &[u8], local: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0; 8];
        body[0] = family;
        body[1] = if family == 2 { 32 } else { 128 };
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        attribute(&mut body, 1, address);
        if let Some(local) = local {
            attribute(&mut body, 2, local);
        }
        body
    }

    fn local_route_body(family: u8, prefix: u8, kind: u8, destination: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0; 12];
        body[0] = family;
        body[1] = prefix;
        body[4] = 255;
        body[5] = 2;
        body[7] = kind;
        if let Some(destination) = destination {
            attribute(&mut body, 1, destination);
        }
        attribute(&mut body, 4, &2u32.to_ne_bytes());
        attribute(&mut body, 6, &256u32.to_ne_bytes());
        body
    }

    #[test]
    fn native_broadcasts_require_unambiguous_local_route_authority() {
        let address = [192, 0, 2, 255];
        for (table, prefix, kind, expected) in
            [(255, 32, 3, true), (254, 32, 3, false), (255, 32, 2, false)]
        {
            let mut snapshot = topology();
            let mut body = local_route_body(2, prefix, kind, Some(&address));
            body[4] = table;
            body[24..28].copy_from_slice(&3u32.to_ne_bytes());
            snapshot.push(24, &body).unwrap();
            let (broadcasts, count) = snapshot.ipv4_broadcasts().unwrap();
            assert_eq!(count, usize::from(expected));
            if expected {
                assert_eq!(broadcasts[0], Ipv4Addr::from(address));
            }
        }
        for mutation in [0, 1, 2, 4] {
            let mut snapshot = topology();
            let mut body = local_route_body(2, 32, 3, Some(&address));
            body[24..28].copy_from_slice(&3u32.to_ne_bytes());
            match mutation {
                0 => body[1] = 24,
                1 => body[3] = 4,
                2 => attribute(&mut body, 99, &0u32.to_ne_bytes()),
                3 => {
                    body[24..28].copy_from_slice(&2u32.to_ne_bytes());
                }
                _ => {
                    let mut conflict = local_route_body(2, 32, 2, Some(&address));
                    conflict[24..28].copy_from_slice(&3u32.to_ne_bytes());
                    snapshot.push(24, &conflict).unwrap();
                }
            }
            snapshot.push(24, &body).unwrap();
            assert!(snapshot.ipv4_broadcasts().is_err());
        }
        let mut canonical = topology();
        for address in [[192, 0, 9, 255], [192, 0, 2, 255], [192, 0, 9, 255]] {
            let mut body = local_route_body(2, 32, 3, Some(&address));
            body[24..28].copy_from_slice(&3u32.to_ne_bytes());
            canonical.push(24, &body).unwrap();
        }
        let (addresses, count) = canonical.ipv4_broadcasts().unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            &addresses[..count],
            &[Ipv4Addr::new(192, 0, 2, 255), Ipv4Addr::new(192, 0, 9, 255)]
        );
        let mut snapshot = topology();
        for index in 0..=MAX_BROADCASTS {
            let mut body = local_route_body(2, 32, 3, Some(&[192, 0, index as u8, 255]));
            body[24..28].copy_from_slice(&3u32.to_ne_bytes());
            snapshot.push(24, &body).unwrap();
            if index < MAX_BROADCASTS {
                assert_eq!(snapshot.ipv4_broadcasts().unwrap().1, index + 1);
            }
        }
        assert!(snapshot.ipv4_broadcasts().is_err());
    }

    #[test]
    fn address_parser_classifies_actual_sources_and_prefers_local_to_peer() {
        for (text, expected) in [
            ("127.0.0.1", false),
            ("127.8.9.10", false),
            ("0.0.0.0", false),
            ("255.255.255.255", false),
            ("224.0.0.1", false),
            ("192.0.2.1", true),
            ("::1", false),
            ("::", false),
            ("ff02::1", false),
            ("2001:db8::1", true),
            ("fe80::1", true),
        ] {
            let (family, address) = match text.parse::<IpAddr>().unwrap() {
                IpAddr::V4(ip) => (2, ip.octets().to_vec()),
                IpAddr::V6(ip) => (10, ip.octets().to_vec()),
            };
            let mut snapshot = Snapshot::default();
            snapshot
                .push(20, &address_body(family, 1, &address, None))
                .unwrap();
            assert_eq!(snapshot.addresses[0].unicast_source, expected, "{text}");
        }
        for (address, local, expected) in [
            ([192, 0, 2, 1], [127, 0, 0, 1], false),
            ([127, 0, 0, 1], [192, 0, 2, 1], true),
        ] {
            let mut snapshot = Snapshot::default();
            snapshot
                .push(20, &address_body(2, 1, &address, Some(&local)))
                .unwrap();
            assert_eq!(snapshot.addresses[0].unicast_source, expected);
        }
        assert!(
            Snapshot::default()
                .push(20, &address_body(10, 1, &[0; 4], None))
                .is_err()
        );
        let mut missing = vec![0; 8];
        missing[0] = 10;
        assert!(Snapshot::default().push(20, &missing).is_err());
        let mut duplicate = address_body(2, 1, &[192, 0, 2, 1], None);
        attribute(&mut duplicate, 1, &[127, 0, 0, 1]);
        assert!(Snapshot::default().push(20, &duplicate).is_err());
    }

    fn xdp_link(index: u32, plain: bool, loopback: bool) -> Link {
        let mut body = vec![0; 16];
        body[2..4].copy_from_slice(&(if plain { 1u16 } else { 0xfffe }).to_ne_bytes());
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        body[8..12].copy_from_slice(&(if loopback { 9u32 } else { 0x10001 }).to_ne_bytes());
        let mut snapshot = Snapshot::default();
        snapshot.push(16, &body).unwrap();
        snapshot.links.pop().unwrap()
    }

    fn xdp_address(family: u8, index: u32) -> Address {
        let ip = if family == 2 {
            vec![192, 0, 2, 1]
        } else {
            "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec()
        };
        let mut snapshot = Snapshot::default();
        snapshot
            .push(20, &address_body(family, index, &ip, None))
            .unwrap();
        snapshot.addresses.pop().unwrap()
    }

    fn xdp_rule(family: u8, priority: u32, table: u32, mark: Option<u32>) -> Rule {
        let mut body = vec![0; 12];
        body[0] = family;
        body[7] = 1;
        attribute(&mut body, 6, &priority.to_ne_bytes());
        attribute(&mut body, 15, &table.to_ne_bytes());
        if let Some(mark) = mark {
            attribute(&mut body, 10, &mark.to_ne_bytes());
            attribute(&mut body, 16, &u32::MAX.to_ne_bytes());
        }
        let mut snapshot = Snapshot::default();
        snapshot.push(32, &body).unwrap();
        snapshot.rules.pop().unwrap()
    }

    fn xdp_route(family: u8, table: u32, output: u32, default: bool, kind: u8) -> Route {
        let mut body = vec![0; 12];
        body[0] = family;
        body[7] = kind;
        if !default {
            body[1] = if family == 2 { 24 } else { 64 };
            let destination = if family == 2 {
                vec![192, 0, 2, 0]
            } else {
                "2001:db8::".parse::<Ipv6Addr>().unwrap().octets().to_vec()
            };
            attribute(&mut body, 1, &destination);
        }
        attribute(&mut body, 15, &table.to_ne_bytes());
        attribute(&mut body, 4, &output.to_ne_bytes());
        let mut snapshot = Snapshot::default();
        snapshot.push(24, &body).unwrap();
        snapshot.routes.pop().unwrap()
    }

    fn topology() -> Snapshot {
        Snapshot {
            links: vec![xdp_link(2, true, false), xdp_link(3, true, false)],
            addresses: vec![xdp_address(2, 3)],
            rules: vec![
                xdp_rule(2, 0, 255, None),
                xdp_rule(2, 100, 100, Some(128)),
                xdp_rule(2, 32766, 254, None),
            ],
            routes: vec![
                xdp_route(2, 100, 3, true, 1),
                xdp_route(2, 254, 2, false, 1),
            ],
            nexthops: Vec::new(),
        }
    }
}
