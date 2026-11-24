use std::sync::Mutex;

use super::*;

const TC_H_INGRESS: u32 = 0xffff_fff1;
const TC_H_CLSACT_INGRESS: u32 = 0xffff_fff2;
const TCM_IFINDEX_MAGIC_BLOCK: u32 = u32::MAX;
const TCA_INGRESS_BLOCK: u16 = 13;
const TCA_KIND: u16 = 1;
const RTM_NEWCHAIN: u16 = 100;
const RTM_DELCHAIN: u16 = 101;
const RTM_NEWNEXTHOP: u16 = 104;
const RTM_DELNEXTHOP: u16 = 105;
const RTM_NEWNEXTHOPBUCKET: u16 = 116;
const RTM_DELNEXTHOPBUCKET: u16 = 117;
const ARPHRD_IP6GRE: u16 = 823;

type InterfaceName = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuxLinkInfo {
    pub ifindex: u32,
    pub mtu: u32,
    pub is_l2: bool,
    pub local_mac: [u8; 6],
    pub up: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostLinkChange {
    Unchanged,
    Refresh(AuxLinkInfo),
    Rebind,
}

impl HostLinkChange {
    fn compare(old: AuxLinkInfo, new: AuxLinkInfo, host: bool, broadcasts_changed: bool) -> Self {
        if old == new && !broadcasts_changed {
            Self::Unchanged
        } else if host && old.same_geometry(new) {
            Self::Refresh(new)
        } else {
            Self::Rebind
        }
    }
}

impl AuxLinkInfo {
    fn from_link(link: &Link) -> io::Result<Self> {
        if link.arphrd == libc::ARPHRD_ETHER {
            return Err(unsupported(
                "configure Ethernet as lan or wan instead of l3_lan",
            ));
        }
        if link.arphrd != libc::ARPHRD_NONE || link.loopback || link.has_hardware_address {
            return Err(unsupported(
                "l3_lan requires an ARPHRD_NONE IP link without a hardware address",
            ));
        }
        let mtu = link
            .mtu
            .ok_or_else(|| malformed("l3_lan link has no MTU"))?;
        if link.index == 0 || link.index > i32::MAX as u32 {
            return Err(malformed("invalid l3_lan ifindex"));
        }
        if !(1280..=u32::from(u16::MAX)).contains(&mtu) {
            return Err(unsupported("l3_lan MTU must be between 1280 and 65535"));
        }
        if link.big_tcp {
            return Err(unsupported("l3_lan does not support BIG TCP GRO/GSO sizes"));
        }
        Ok(Self {
            ifindex: link.index,
            mtu,
            is_l2: false,
            local_mac: link.mac,
            up: link.flags & libc::IFF_UP as u32 != 0,
        })
    }

    fn from_host_link(link: &Link) -> io::Result<Self> {
        let kind = link.kind.unwrap_or_default();
        let kind = std::ffi::CStr::from_bytes_until_nul(&kind)
            .map_err(|_| malformed("invalid Host link kind"))?
            .to_bytes();
        if link.loopback
            || matches!(
                link.arphrd,
                libc::ARPHRD_PPP | libc::ARPHRD_IPGRE | ARPHRD_IP6GRE
            )
            || matches!(
                kind,
                b"ppp" | b"gre" | b"ip6gre" | b"gretap" | b"ip6gretap" | b"erspan" | b"ip6erspan"
            )
        {
            return Err(unsupported("Host egress cannot use loopback, PPP or GRE"));
        }
        let ethernet = matches!(
            kind,
            b"" | b"veth"
                | b"dummy"
                | b"vlan"
                | b"bridge"
                | b"bond"
                | b"team"
                | b"tun"
                | b"macvlan"
                | b"macvtap"
                | b"ipvlan"
        );
        if matches!(kind, b"vlan" | b"macvlan" | b"macvtap" | b"ipvlan")
            && (link.parent == 0 || (!link.foreign_parent && link.parent == link.index))
        {
            return Err(unsupported("Host egress has no verifiable lower device"));
        }
        let is_l2 = match link.arphrd {
            libc::ARPHRD_NONE
                if !link.has_hardware_address
                    && matches!(kind, b"tun" | b"wireguard" | b"ovpn" | b"xfrm") =>
            {
                false
            }
            libc::ARPHRD_ETHER if ethernet && link.mac != [0; 6] && link.mac[0] & 1 == 0 => true,
            _ => {
                return Err(unsupported(
                    "Host egress requires Ethernet with a unicast MAC or bare IP ARPHRD_NONE",
                ));
            }
        };
        let mtu = link
            .mtu
            .ok_or_else(|| malformed("Host egress has no MTU"))?;
        if link.index == 0 || link.index > i32::MAX as u32 {
            return Err(malformed("invalid Host ifindex"));
        }
        if !(1280..=u32::from(u16::MAX)).contains(&mtu) || link.big_tcp {
            return Err(unsupported(
                "Host egress requires MTU 1280..65535 and ordinary GRO/GSO sizes",
            ));
        }
        Ok(Self {
            ifindex: link.index,
            mtu,
            is_l2,
            local_mac: link.mac,
            up: link.flags & libc::IFF_UP as u32 != 0,
        })
    }

    fn same_geometry(self, new: Self) -> bool {
        Self {
            local_mac: new.local_mac,
            ..self
        } == new
    }
}

/// Read-only RTNL authority for one configured auxiliary link.
pub struct AuxLinkWatch {
    fd: OwnedFd,
    netns_cookie: u64,
    state: Mutex<WatchState>,
    host_capture: Option<Arc<HostCaptures>>,
}

struct HostCaptures {
    names: Box<[InterfaceName]>,
    _memory: MemoryReservation,
}

struct WatchState {
    buffer: CaptureBuffer,
    observed: ObservedAuxLink,
    broadcasts: Option<Ipv4Broadcasts>,
    refused_selector: Option<LinkNotificationSelector>,
}

type Ipv4Broadcasts = ([Ipv4Addr; MAX_BROADCASTS], usize);

struct OuterRead {
    selector: LinkNotificationSelector,
    host_lower: Option<HostLower>,
    broadcasts: Option<Ipv4Broadcasts>,
    info: io::Result<Option<AuxLinkInfo>>,
}

impl OuterRead {
    fn refuse(mut self, error: io::Error) -> Self {
        self.info = Err(error);
        self
    }
}

impl WatchState {
    fn record_outer(&mut self, result: io::Result<OuterRead>) -> io::Result<Option<AuxLinkInfo>> {
        let read = result?;
        if read.info.is_ok() {
            self.observed.selector = read.selector;
            self.observed.host_lower = read.host_lower;
            self.broadcasts = read.broadcasts;
            self.refused_selector = None;
        } else {
            self.refused_selector = Some(read.selector);
        }
        read.info
    }

    fn notification_context(
        &self,
        previous: Option<AuxLinkInfo>,
    ) -> (ObservedAuxLink, Option<&Ipv4Broadcasts>) {
        if previous.is_none()
            && let Some(selector) = self.refused_selector
        {
            return (
                ObservedAuxLink {
                    selector,
                    ..self.observed
                },
                None,
            );
        }
        (self.observed, self.broadcasts.as_ref())
    }
}

#[derive(Clone, Copy, Default)]
struct LinkNotificationSelector {
    index: Option<u32>,
    ingress: Option<LegacyIngress>,
    default_refused: bool,
    broadcasts_refused: bool,
}

#[derive(Clone, Copy, Default)]
struct ObservedAuxLink {
    selector: LinkNotificationSelector,
    host: bool,
    host_fifo: Option<(u32, u32)>,
    host_lower: Option<HostLower>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct HostLower {
    parent: u32,
    foreign_parent: bool,
    master: u32,
    kind: Option<InterfaceName>,
    vlan: Option<(u16, u16)>,
}

impl From<&Link> for HostLower {
    fn from(link: &Link) -> Self {
        Self {
            parent: link.parent,
            foreign_parent: link.foreign_parent,
            master: link.master,
            kind: link.kind,
            vlan: link.vlan,
        }
    }
}

impl AuxLinkWatch {
    pub fn new(budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let fd = route_socket(true)?;
        join_route_group(fd.as_fd(), libc::RTNLGRP_TC)?;
        join_route_group(fd.as_fd(), libc::RTNLGRP_NEXTHOP)?;
        Ok(Self {
            netns_cookie: netns_cookie(fd.as_fd())?,
            fd,
            host_capture: None,
            state: Mutex::new(WatchState {
                buffer: CaptureBuffer::new(budget)?,
                observed: ObservedAuxLink::default(),
                broadcasts: None,
                refused_selector: None,
            }),
        })
    }

    /// Capture roots include both physical and auxiliary configured names; their live
    /// lower/upper relationships are resolved anew on each admission.
    pub fn new_host<'a>(
        budget: &Arc<MemoryBudget>,
        capture_interfaces: impl ExactSizeIterator<Item = &'a str>,
    ) -> io::Result<Self> {
        let mut watch = Self::new(budget)?;
        let bytes = capture_interfaces
            .len()
            .checked_mul(size_of::<InterfaceName>())
            .and_then(|bytes| bytes.checked_add(size_of::<HostCaptures>() + 2 * size_of::<usize>()))
            .ok_or_else(|| malformed("Host capture name capacity overflow"))?;
        let memory = budget
            .reserve(bytes)
            .ok_or_else(|| io::Error::other("Host capture name capacity"))?;
        let mut names = Vec::with_capacity(capture_interfaces.len());
        for name in capture_interfaces {
            names.push(interface_name(name.as_bytes())?);
        }
        watch.host_capture = Some(Arc::new(HostCaptures {
            names: names.into_boxed_slice(),
            _memory: memory,
        }));
        watch.state.get_mut().map_err(watch_poisoned)?.observed.host = true;
        Ok(watch)
    }

    pub fn resubscribe(&self, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let mut fresh = Self::new(budget)?;
        if fresh.netns_cookie != self.netns_cookie {
            return Err(unsupported(
                "auxiliary resubscription crossed network namespaces",
            ));
        }
        fresh.host_capture.clone_from(&self.host_capture);
        fresh.state.get_mut().map_err(watch_poisoned)?.observed.host = self.host_capture.is_some();
        Ok(fresh)
    }

    /// A missing name is waiting. A valid administratively down link has `up == false`.
    pub fn read_l3(&self, name: &str) -> io::Result<Option<AuxLinkInfo>> {
        if self.host_capture.is_some() {
            return Err(malformed("Host watch cannot admit an L3 LAN"));
        }
        self.read_outer(name, true)
    }

    pub fn read_host(&self, name: &str) -> io::Result<Option<AuxLinkInfo>> {
        if self.host_capture.is_none() {
            return Err(malformed(
                "Host admission requires the configured capture roots",
            ));
        }
        self.read_outer(name, true)
    }

    pub(crate) fn verify_host_outer(&self, name: &str, expected: AuxLinkInfo) -> io::Result<bool> {
        if self.host_capture.is_none() {
            return Err(malformed("Host verification requires its Host watch"));
        }
        let previous = self
            .state
            .lock()
            .map_err(watch_poisoned)?
            .observed
            .host_lower;
        let actual = self.read_outer(name, false)?;
        let current = self
            .state
            .lock()
            .map_err(watch_poisoned)?
            .observed
            .host_lower;
        Ok(actual == Some(expected) && previous.is_some() && current == previous)
    }
    pub(crate) fn read_outer(
        &self,
        name: &str,
        require_broadcasts: bool,
    ) -> io::Result<Option<AuxLinkInfo>> {
        let name = interface_name(name.as_bytes())?;
        let deadline = Instant::now() + DUMP_TIMEOUT;
        let mut state = self.state.lock().map_err(watch_poisoned)?;
        let attempt = |dump: &mut TopologyDump<'_>| {
            let mut snapshot = Snapshot::default();
            dump.append(1, libc::RTM_GETLINK, 16, &mut snapshot)?;
            let link = snapshot.aux_link(name)?;
            let mut read = OuterRead {
                selector: LinkNotificationSelector {
                    index: link.map(|link| link.index),
                    ..LinkNotificationSelector::default()
                },
                host_lower: None,
                broadcasts: None,
                info: Ok(None),
            };
            let Some(link) = link else {
                return Ok(read);
            };
            let info = if let Some(captures) = &self.host_capture {
                snapshot
                    .check_host_overlap(link.index, &captures.names)
                    .and_then(|()| {
                        read.host_lower = Some(HostLower::from(link));
                        AuxLinkInfo::from_host_link(link)
                    })
            } else {
                AuxLinkInfo::from_link(link)
            };
            let info = match info {
                Ok(info) => info,
                Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                    return Ok(read.refuse(error));
                }
                Err(error) => return Err(error),
            };
            dump.append(2, libc::RTM_GETROUTE, 12, &mut snapshot)?;
            if self.host_capture.is_none() {
                if snapshot
                    .routes
                    .iter()
                    .any(|route| route.is_ip_default() && route.nexthop.is_some())
                {
                    dump.append(3, RTM_GETNEXTHOP, 8, &mut snapshot)?;
                }
                match snapshot.check_aux_defaults(info.ifindex) {
                    Ok(()) => (),
                    Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                        read.selector.default_refused = true;
                        return Ok(read.refuse(error));
                    }
                    Err(error) => return Err(error),
                }
                let (ingress, refusal) = legacy_ingress(dump, info.ifindex)?;
                read.selector.ingress = ingress;
                if let Some(reason) = refusal {
                    return Ok(read.refuse(unsupported(reason)));
                }
            }
            match snapshot.ipv4_broadcasts() {
                Ok(inventory) => read.broadcasts = Some(inventory),
                Err(error) => {
                    read.selector.broadcasts_refused = true;
                    if require_broadcasts {
                        return Ok(read.refuse(error));
                    }
                }
            }
            read.info = Ok(Some(info));
            Ok(read)
        };
        let result = with_topology_dump(
            Some(self.netns_cookie),
            deadline,
            &mut state.buffer.bytes,
            attempt,
        );
        state.record_outer(result)
    }

    /// Return the canonical local-table broadcast destinations from the latest admitted link read.
    pub fn ipv4_broadcasts(&self) -> io::Result<([Ipv4Addr; MAX_BROADCASTS], usize)> {
        self.state
            .lock()
            .map_err(watch_poisoned)?
            .broadcasts
            .ok_or_else(|| unsupported("auxiliary IPv4 broadcasts are not verified"))
    }

    /// Initial readback before the first IFF_UP, while only the owned root pfifo is allowed.
    pub fn verify_host_fifo(&self, name: &str, index: u32, slots: u32) -> io::Result<()> {
        if self.host_capture.is_none() || !(1..=8).contains(&slots) {
            return Err(malformed("invalid Host FIFO admission"));
        }
        let name = interface_name(name.as_bytes())?;
        let tun = interface_name(b"tun")?;
        let deadline = Instant::now() + DUMP_TIMEOUT;
        let mut state = self.state.lock().map_err(watch_poisoned)?;
        with_topology_dump(
            Some(self.netns_cookie),
            deadline,
            &mut state.buffer.bytes,
            |dump| {
                let mut snapshot = Snapshot::default();
                dump.append(1, libc::RTM_GETLINK, 16, &mut snapshot)?;
                if !snapshot.links.iter().any(|l| {
                    l.index == index
                        && l.name == Some(name)
                        && l.kind == Some(tun)
                        && l.arphrd == libc::ARPHRD_NONE
                        && l.master == 0
                        && l.flags & libc::IFF_UP as u32 == 0
                        && l.tx_queue_len == Some(slots)
                }) {
                    return Err(unsupported(
                        "private Host FIFO requires its down TUN and admitted ring size",
                    ));
                }
                private_host_qdiscs(dump, index, slots, true)
            },
        )?;
        state.observed.host_fifo = Some((index, slots));
        Ok(())
    }

    /// Confirm the private TUN still has only the daemon-owned link identity.
    pub fn verify_inner(&self, name: &str, ifindex: u32, mtu: u32) -> io::Result<()> {
        let name_key = interface_name(name.as_bytes())?;
        let deadline = Instant::now() + DUMP_TIMEOUT;
        let mut state = self.state.lock().map_err(watch_poisoned)?;
        let fifo = state.observed.host_fifo;
        let attempt = |dump: &mut TopologyDump<'_>| {
            let mut snapshot = dump.snapshot()?;
            if snapshot.routes.iter().any(|route| route.nexthop.is_some()) {
                dump.append(5, RTM_GETNEXTHOP, 8, &mut snapshot)?;
            }
            if !snapshot
                .links
                .iter()
                .any(|link| link.index == ifindex && link.is_owned_tun(name_key, mtu))
                || snapshot
                    .addresses
                    .iter()
                    .any(|address| address.index == ifindex)
                || snapshot
                    .rules
                    .iter()
                    .any(|rule| rule.names_interface(name_key))
            {
                return Err(unsupported(
                    "private auxiliary TUN identity, addresses or rules changed",
                ));
            }
            for route in &snapshot.routes {
                if route.input == ifindex || snapshot.route_uses(route, ifindex)? {
                    return Err(unsupported("private auxiliary TUN appears in a route"));
                }
            }
            if self.host_capture.is_some() {
                let (index, slots) = fifo
                    .filter(|(i, _)| *i == ifindex)
                    .ok_or_else(|| unsupported("private Host TUN FIFO was not admitted"))?;
                if !snapshot
                    .links
                    .iter()
                    .any(|l| l.index == index && l.tx_queue_len == Some(slots))
                {
                    return Err(unsupported("private Host TUN FIFO length changed"));
                }
                private_host_qdiscs(dump, ifindex, slots, false)?;
            }
            Ok(())
        };
        with_topology_dump(
            Some(self.netns_cookie),
            deadline,
            &mut state.buffer.bytes,
            attempt,
        )
    }

    /// Drain queued notifications, retaining identity loss even across identical recreation.
    /// `inner` is the active private TUN's (name, ifindex, MTU), after its setup notices are drained.
    pub fn changed(
        &mut self,
        name: &str,
        previous: Option<AuxLinkInfo>,
        inner: Option<(&str, u32, u32)>,
    ) -> io::Result<bool> {
        Ok(self.changed_outer(name, previous, inner)? != HostLinkChange::Unchanged)
    }

    pub fn changed_host(
        &mut self,
        name: &str,
        previous: Option<AuxLinkInfo>,
        inner: Option<(&str, u32, u32)>,
    ) -> io::Result<HostLinkChange> {
        if self.host_capture.is_none() {
            return Err(malformed(
                "Host notification requires the configured capture roots",
            ));
        }
        self.changed_outer(name, previous, inner)
    }

    fn changed_outer(
        &mut self,
        name: &str,
        previous: Option<AuxLinkInfo>,
        inner: Option<(&str, u32, u32)>,
    ) -> io::Result<HostLinkChange> {
        let outer_name = interface_name(name.as_bytes())?;
        let inner_key = inner
            .map(|(name, index, mtu)| interface_name(name.as_bytes()).map(|key| (key, index, mtu)))
            .transpose()?;
        let changes = self.drain(outer_name, previous, inner_key)?;
        if changes.invalidated
            || (changes.broadcasts_dirty || (self.host_capture.is_some() && changes.recheck))
                && previous.is_none()
        {
            return Ok(HostLinkChange::Rebind);
        }
        if changes.recheck
            && let Some((name, index, mtu)) = inner
        {
            self.verify_inner(name, index, mtu)?;
        }
        if (changes.recheck || changes.broadcasts_dirty)
            && let Some(old) = previous
        {
            let host = self.host_capture.is_some();
            let before = self.state.get_mut().map_err(watch_poisoned)?;
            let broadcasts = before.broadcasts;
            let lower = before.observed.host_lower;
            let new = match self.read_outer(name, !host) {
                Ok(Some(info)) => info,
                Ok(None) => return Ok(HostLinkChange::Rebind),
                Err(e) if self.host_capture.is_some() && e.kind() == io::ErrorKind::Unsupported => {
                    return Ok(HostLinkChange::Rebind);
                }
                Err(e) => return Err(e),
            };
            let after = self.state.get_mut().map_err(watch_poisoned)?;
            if host && lower != after.observed.host_lower {
                return Ok(HostLinkChange::Rebind);
            }
            return Ok(HostLinkChange::compare(
                old,
                new,
                host,
                after.broadcasts != broadcasts,
            ));
        }
        Ok(HostLinkChange::Unchanged)
    }

    fn drain(
        &mut self,
        name: InterfaceName,
        previous: Option<AuxLinkInfo>,
        inner: Option<(InterfaceName, u32, u32)>,
    ) -> io::Result<Changes> {
        let mut changes = Changes::default();
        let state = self.state.get_mut().map_err(watch_poisoned)?;
        for _ in 0..64 {
            let buffer = &mut state.buffer.bytes;
            let length = match receive_netlink(
                self.fd.as_fd(),
                buffer,
                "invalid auxiliary notification sender or extent",
            ) {
                Ok(length) => length,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(changes),
                Err(error) => return Err(error),
            };
            let (observed, broadcasts) = state.notification_context(previous);
            changes.inspect(
                &state.buffer.bytes[..length],
                name,
                previous,
                inner,
                observed,
                broadcasts,
            )?;
        }
        Err(malformed("auxiliary notification drain bound exceeded"))
    }
}

impl AsFd for AuxLinkWatch {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for AuxLinkWatch {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn watch_poisoned<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("auxiliary topology watch is poisoned")
}

impl Snapshot {
    fn aux_link(&self, name: InterfaceName) -> io::Result<Option<&Link>> {
        let mut named = self.links.iter().filter(|link| link.name == Some(name));
        let Some(link) = named.next() else {
            return Ok(None);
        };
        if named.next().is_some() {
            return Err(malformed("duplicate l3_lan interface name"));
        }
        Ok(Some(link))
    }

    fn check_host_overlap(&self, host: u32, captures: &[InterfaceName]) -> io::Result<()> {
        if captures.is_empty() {
            return Ok(());
        }
        let lower_kinds = [
            interface_name(b"vlan")?,
            interface_name(b"macvlan")?,
            interface_name(b"macvtap")?,
            interface_name(b"ipvlan")?,
        ];
        let mut lowers = std::collections::HashMap::<u32, Vec<u32>>::new();
        let mut roots = Vec::new();
        for link in &self.links {
            if link.name.is_some_and(|name| captures.contains(&name)) {
                roots.push(link.index);
            }
            if link.master != 0 {
                lowers.entry(link.master).or_default().push(link.index);
            }
            if link.kind.is_some_and(|k| lower_kinds.contains(&k))
                && !link.foreign_parent
                && link.parent != link.index
            {
                lowers.entry(link.index).or_default().push(link.parent);
            }
        }
        // A master captures its members; a VLAN traverses its parent. Sibling members
        // of an unrelated master and cross-namespace veth peers need not overlap.
        let descendants = |mut pending: Vec<u32>| {
            let mut seen = HashSet::new();
            while let Some(index) = pending.pop() {
                if seen.insert(index)
                    && let Some(children) = lowers.get(&index)
                {
                    pending.extend_from_slice(children);
                }
            }
            seen
        };
        if !descendants(roots).is_disjoint(&descendants(vec![host])) {
            return Err(unsupported(
                "Host egress overlaps physical or auxiliary capture through a master or VLAN",
            ));
        }
        Ok(())
    }

    fn check_aux_defaults(&self, index: u32) -> io::Result<()> {
        for route in self.routes.iter().filter(|route| route.is_ip_default()) {
            if self.route_uses(route, index)? {
                return Err(unsupported("default route traverses l3_lan"));
            }
        }
        Ok(())
    }

    fn route_uses(&self, route: &Route, index: u32) -> io::Result<bool> {
        if route.uses_output(index) {
            return Ok(true);
        }
        match route.nexthop {
            Some(id) => self.nexthop_uses(id, index, &mut [0; 16], 0),
            None => Ok(false),
        }
    }

    fn nexthop_uses(
        &self,
        id: u32,
        index: u32,
        path: &mut [u32; 16],
        depth: usize,
    ) -> io::Result<bool> {
        if depth == path.len() || path[..depth].contains(&id) {
            return Err(unsupported("recursive auxiliary route nexthop"));
        }
        let mut matching = self.nexthops.iter().filter(|next| next.id == id);
        let next = matching
            .next()
            .ok_or_else(|| unsupported("missing auxiliary route nexthop"))?;
        if matching.next().is_some() {
            return Err(malformed("duplicate auxiliary route nexthop"));
        }
        if next.unsupported && next.output == 0 && next.group.is_empty() {
            return Err(unsupported("unrepresentable auxiliary route nexthop"));
        }
        if next.output == index {
            return Ok(true);
        }
        path[depth] = id;
        for child in &next.group {
            if self.nexthop_uses(*child, index, path, depth + 1)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Route {
    fn is_ip_default(&self) -> bool {
        self.default && matches!(self.family, 2 | 10) && !matches!(self.kind, 6..=9)
    }

    fn uses_output(&self, index: u32) -> bool {
        self.output == index || self.outputs.contains(&index)
    }
}

impl Rule {
    fn names_interface(&self, name: InterfaceName) -> bool {
        self.iif == Some(name) || self.oif == Some(name)
    }
}

struct TcTarget {
    ifindex: u32,
    parent: u32,
}

impl TcTarget {
    fn read(body: &[u8]) -> io::Result<Self> {
        if body.len() < 20 {
            return Err(malformed("short traffic control message"));
        }
        Ok(Self {
            ifindex: u32_at(body, 4)?,
            parent: u32_at(body, 12)?,
        })
    }

    fn body(&self) -> [u8; 20] {
        let mut body = [0; 20];
        body[4..8].copy_from_slice(&self.ifindex.to_ne_bytes());
        body[12..16].copy_from_slice(&self.parent.to_ne_bytes());
        body
    }
}

#[derive(Clone, Copy)]
struct LegacyIngress {
    index: u32,
    parent: u32,
    shared_block: Option<u32>,
}

impl LegacyIngress {
    fn contains(self, target: TcTarget) -> bool {
        if target.ifindex == TCM_IFINDEX_MAGIC_BLOCK {
            return self.shared_block == Some(target.parent);
        }
        target.ifindex == self.index
            && if self.parent == TC_H_INGRESS {
                // The ingress qdisc accepts any minor under its reserved major.
                target.parent & 0xffff_0000 == 0xffff_0000
            } else {
                target.parent == self.parent
            }
    }
}

fn private_host_qdisc(body: &[u8], slots: u32, initial: bool) -> io::Result<()> {
    let target = TcTarget::read(body)?;
    if target.parent != u32::MAX || initial && u32_at(body, 8)? != 0x10000 {
        return Err(unsupported("private Host TUN requires one root queue"));
    }
    let mut kind = None;
    let mut options = None;
    attributes(&body[20..], |field, value| {
        match field {
            TCA_KIND if kind.replace(value).is_some() => {
                return Err(malformed("duplicate Host qdisc kind"));
            }
            2 if options.replace(value).is_some() => {
                return Err(malformed("duplicate Host qdisc options"));
            }
            13 | 14 if exact_u32(value)? != 0 => {
                return Err(unsupported("private Host qdisc has a shared block"));
            }
            _ => (),
        }
        Ok(())
    })?;
    let options = options.ok_or_else(|| malformed("private Host qdisc options missing"))?;
    let limit = match kind {
        Some(b"pfifo\0") => exact_u32(options)?,
        Some(b"netem\0") if !initial && options.len() >= 24 => {
            // The operator's delay-only test queue may hold the same number of the
            // original skbs. Duplication, corruption (including GSO segmentation),
            // child queues and packet/flow transforms cannot inherit that charge.
            if options[8..24].iter().any(|&b| b != 0) {
                return Err(unsupported("private Host netem must be delay-only"));
            }
            attributes(&options[24..], |field, data| {
                match field {
                    10 | 14 if data.len() == 8 => Ok(()), // latency64 and PRNG seed
                    9 if data.is_empty() => Ok(()),       // alignment pad
                    1 | 3 | 4 | 6 | 11 if data.iter().all(|&b| b == 0) => Ok(()),
                    _ => Err(unsupported("private Host netem has unverified options")),
                }
            })?;
            u32_at(options, 4)?
        }
        _ => {
            return Err(unsupported(
                "private Host TUN requires bounded pfifo or a delay-only netem root",
            ));
        }
    };
    if limit == 0 || limit > slots || initial && limit != slots {
        return Err(unsupported(
            "private Host qdisc exceeds its admitted slot count",
        ));
    }
    Ok(())
}

fn private_host_qdiscs(
    dump: &mut TopologyDump<'_>,
    index: u32,
    slots: u32,
    initial: bool,
) -> io::Result<()> {
    let mut found = false;
    dump.request(6, libc::RTM_GETQDISC, &[0; 20], |_, body| {
        if TcTarget::read(body)?.ifindex == index {
            if found {
                return Err(unsupported("additional private Host TUN qdisc"));
            }
            private_host_qdisc(body, slots, initial)?;
            found = true;
        }
        Ok(())
    })?;
    if !found {
        return Err(unsupported("private Host TUN root queue is absent"));
    }
    Ok(())
}

fn legacy_ingress(
    dump: &mut TopologyDump<'_>,
    index: u32,
) -> io::Result<(Option<LegacyIngress>, Option<&'static str>)> {
    let mut qdisc = None;
    dump.request(4, libc::RTM_GETQDISC, &[0; 20], |_, body| {
        let target = TcTarget::read(body)?;
        if target.ifindex != index || target.parent != TC_H_INGRESS {
            return Ok(());
        }
        let mut parent = None;
        let mut shared_block = None;
        let mut seen = 0;
        attributes(&body[20..], |kind, value| {
            match kind {
                TCA_KIND => {
                    unique_attribute(&mut seen, kind)?;
                    parent = Some(match value {
                        b"ingress\0" => Some(TC_H_INGRESS),
                        b"clsact\0" => Some(TC_H_CLSACT_INGRESS),
                        _ => None,
                    });
                }
                TCA_INGRESS_BLOCK => {
                    unique_attribute(&mut seen, kind)?;
                    let block = exact_u32(value)?;
                    if block == 0 {
                        return Err(malformed("invalid l3_lan shared ingress block"));
                    }
                    shared_block = Some(block);
                }
                _ => {}
            }
            Ok(())
        })?;
        let parent = parent.ok_or_else(|| malformed("l3_lan ingress qdisc has no kind"))?;
        if qdisc
            .replace(parent.map(|parent| LegacyIngress {
                index,
                parent,
                shared_block,
            }))
            .is_some()
        {
            return Err(malformed("duplicate l3_lan ingress qdisc"));
        }
        Ok(())
    })?;
    let ingress = match qdisc {
        Some(Some(ingress)) => ingress,
        Some(None) => return Ok((None, Some("unrecognized l3_lan ingress qdisc"))),
        None => return Ok((None, None)),
    };
    let target = match ingress.shared_block {
        Some(block) => TcTarget {
            ifindex: TCM_IFINDEX_MAGIC_BLOCK,
            parent: block,
        },
        None => TcTarget {
            ifindex: index,
            parent: ingress.parent,
        },
    };
    let mut has_filter = false;
    dump.request(5, libc::RTM_GETTFILTER, &target.body(), |_, body| {
        if !ingress.contains(TcTarget::read(body)?) {
            return Err(malformed("unexpected l3_lan ingress filter target"));
        }
        attributes(&body[20..], |_, _| Ok(()))?;
        has_filter = true;
        Ok(())
    })?;
    Ok((
        Some(ingress),
        has_filter.then_some("l3_lan has a conflicting legacy ingress filter"),
    ))
}

#[derive(Default)]
struct Changes {
    invalidated: bool,
    recheck: bool,
    broadcasts_dirty: bool,
}

impl Changes {
    fn inspect(
        &mut self,
        mut bytes: &[u8],
        name: InterfaceName,
        previous: Option<AuxLinkInfo>,
        inner: Option<(InterfaceName, u32, u32)>,
        observed: ObservedAuxLink,
        broadcasts: Option<&Ipv4Broadcasts>,
    ) -> io::Result<()> {
        let outer_index = previous
            .map(|info| info.ifindex)
            .or(observed.selector.index);
        let waiting_for_default = previous.is_none() && observed.selector.default_refused;
        while !bytes.is_empty() {
            if bytes.len() < 16 {
                return Err(malformed("short auxiliary notification"));
            }
            let length = u32_at(bytes, 0)? as usize;
            if length < 16 || length > bytes.len() {
                return Err(malformed("truncated auxiliary notification"));
            }
            let advance = (length + 3) & !3;
            if advance > bytes.len() && length != bytes.len() {
                return Err(malformed("short auxiliary notification alignment"));
            }
            let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
            let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
            if flags & NLM_F_DUMP_INTR != 0 {
                return Err(malformed("interrupted auxiliary notification"));
            }
            let body = &bytes[16..length];
            let mut parsed = Snapshot::default();
            match kind {
                libc::RTM_NEWLINK | libc::RTM_DELLINK => {
                    parsed.push(libc::RTM_NEWLINK, body)?;
                    let link = &parsed.links[0];
                    // Another member joining a master or a new VLAN can make an otherwise
                    // unchanged Host device overlap a capture root.
                    self.recheck |= observed.host;
                    self.invalidated |= match previous {
                        Some(info) if link.index == info.ifindex => {
                            kind == libc::RTM_DELLINK
                                || link.name != Some(name)
                                || if observed.host {
                                    !AuxLinkInfo::from_host_link(link)
                                        .is_ok_and(|new| info.same_geometry(new))
                                        || observed
                                            .host_lower
                                            .is_some_and(|old| old != HostLower::from(link))
                                } else {
                                    AuxLinkInfo::from_link(link).ok() != Some(info)
                                }
                        }
                        _ => match kind {
                            libc::RTM_NEWLINK => link.name == Some(name),
                            _ => outer_index == Some(link.index),
                        },
                    };
                    if let Some((inner_name, index, mtu)) = inner {
                        self.invalidated |= link.index == index
                            && (kind == libc::RTM_DELLINK
                                || !link.is_owned_tun(inner_name, mtu)
                                || observed.host_fifo.is_some_and(|(i, slots)| {
                                    i == index && link.tx_queue_len != Some(slots)
                                }));
                    }
                }
                libc::RTM_NEWROUTE | libc::RTM_DELROUTE => {
                    parsed.push(libc::RTM_NEWROUTE, body)?;
                    let route = &parsed.routes[0];
                    self.broadcasts_dirty |= outer_index.is_some()
                        && (broadcasts.is_some() || observed.selector.broadcasts_refused)
                        && route.may_change_ipv4_broadcasts(broadcasts);
                    if !observed.host && route.is_ip_default() {
                        self.invalidated |= waiting_for_default
                            || outer_index.is_some_and(|index| route.uses_output(index));
                        self.recheck |= route.nexthop.is_some();
                    }
                    if let Some((_, index, _)) = inner {
                        self.invalidated |= route.input == index || route.uses_output(index);
                        self.recheck |= route.nexthop.is_some();
                    }
                }
                RTM_NEWNEXTHOP | RTM_DELNEXTHOP => {
                    parsed.push(RTM_NEWNEXTHOP, body)?;
                    self.invalidated |= waiting_for_default;
                    self.recheck = true;
                }
                libc::RTM_NEWADDR | libc::RTM_DELADDR => {
                    parsed.push(libc::RTM_NEWADDR, body)?;
                    self.invalidated |= inner.is_some_and(|(_, index, _)| {
                        parsed
                            .addresses
                            .iter()
                            .any(|address| address.index == index)
                    });
                }
                libc::RTM_NEWRULE | libc::RTM_DELRULE => {
                    parsed.push(libc::RTM_NEWRULE, body)?;
                    self.invalidated |= inner.is_some_and(|(inner_name, _, _)| {
                        parsed.rules[0].names_interface(inner_name)
                    });
                }
                libc::RTM_NEWQDISC
                | libc::RTM_DELQDISC
                | libc::RTM_NEWTFILTER
                | libc::RTM_DELTFILTER => {
                    let target = TcTarget::read(body)?;
                    attributes(&body[20..], |_, _| Ok(()))?;
                    if observed.host && inner.is_some_and(|(_, index, _)| index == target.ifindex) {
                        self.invalidated |= match kind {
                            libc::RTM_NEWQDISC => observed.host_fifo.is_none_or(|(_, slots)| {
                                private_host_qdisc(body, slots, false).is_err()
                            }),
                            libc::RTM_DELQDISC => {
                                self.recheck = true;
                                false
                            }
                            libc::RTM_NEWTFILTER | libc::RTM_DELTFILTER => true,
                            _ => false,
                        };
                    }
                    self.invalidated |= !observed.host
                        && outer_index.is_some_and(|index| {
                            if matches!(kind, libc::RTM_NEWQDISC | libc::RTM_DELQDISC) {
                                target.ifindex == index && target.parent == TC_H_INGRESS
                            } else {
                                observed.selector.ingress.is_some_and(|ingress| {
                                    ingress.index == index && ingress.contains(target)
                                })
                            }
                        });
                }
                libc::RTM_NEWTCLASS
                | libc::RTM_DELTCLASS
                | RTM_NEWCHAIN
                | RTM_DELCHAIN
                | libc::RTM_NEWACTION
                | libc::RTM_DELACTION
                | RTM_NEWNEXTHOPBUCKET
                | RTM_DELNEXTHOPBUCKET => {}
                _ => return Err(malformed("unexpected auxiliary notification")),
            }
            bytes = &bytes[advance.min(bytes.len())..];
        }
        Ok(())
    }
}

impl Route {
    fn may_change_ipv4_broadcasts(&self, broadcasts: Option<&Ipv4Broadcasts>) -> bool {
        self.family == 2
            && self.table == 255
            && (self.kind == 3
                || self.ipv4_destination.is_some_and(|destination| {
                    broadcasts
                        .is_none_or(|(addresses, count)| addresses[..*count].contains(&destination))
                }))
    }
}

#[cfg(test)]
mod tests;
