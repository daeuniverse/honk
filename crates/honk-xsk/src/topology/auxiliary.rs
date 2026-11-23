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
const RTM_GETNEXTHOP: u16 = 106;
const RTM_NEWNEXTHOPBUCKET: u16 = 116;
const RTM_DELNEXTHOPBUCKET: u16 = 117;

type InterfaceName = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuxLinkInfo {
    pub ifindex: u32,
    pub mtu: u32,
    pub is_l2: bool,
    pub local_mac: [u8; 6],
    pub up: bool,
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
}

/// Read-only RTNL authority for one configured auxiliary link.
pub struct AuxLinkWatch {
    fd: OwnedFd,
    netns_cookie: u64,
    state: Mutex<WatchState>,
}

struct WatchState {
    buffer: CaptureBuffer,
    observed: ObservedAuxLink,
    broadcasts: Option<Ipv4Broadcasts>,
}

type Ipv4Broadcasts = ([Ipv4Addr; MAX_BROADCASTS], usize);

#[derive(Clone, Copy, Default)]
struct ObservedAuxLink {
    index: Option<u32>,
    ingress: Option<LegacyIngress>,
    default_refused: bool,
    broadcasts_refused: bool,
}

impl AuxLinkWatch {
    pub fn new(budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let fd = route_socket(true)?;
        join_route_group(fd.as_fd(), libc::RTNLGRP_TC)?;
        join_route_group(fd.as_fd(), libc::RTNLGRP_NEXTHOP)?;
        Ok(Self {
            netns_cookie: netns_cookie(fd.as_fd())?,
            fd,
            state: Mutex::new(WatchState {
                buffer: CaptureBuffer::new(budget)?,
                observed: ObservedAuxLink::default(),
                broadcasts: None,
            }),
        })
    }

    fn dump_socket(&self) -> io::Result<OwnedFd> {
        let fd = route_socket(false)?;
        if netns_cookie(fd.as_fd())? != self.netns_cookie {
            return Err(unsupported(
                "auxiliary topology dump crossed network namespaces",
            ));
        }
        Ok(fd)
    }

    /// A missing name is waiting. A valid administratively down link has `up == false`.
    pub fn read_l3(&self, name: &str) -> io::Result<Option<AuxLinkInfo>> {
        let name = interface_name(name.as_bytes())?;
        let fd = self.dump_socket()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut state = self.state.lock().map_err(watch_poisoned)?;
        let WatchState {
            buffer,
            observed,
            broadcasts,
        } = &mut *state;
        let buffer = &mut buffer.bytes;
        let mut snapshot = Snapshot::default();
        dump_with_buffer(
            fd.as_fd(),
            1,
            libc::RTM_GETLINK,
            16,
            &mut snapshot,
            deadline,
            buffer,
        )?;
        let link = snapshot.aux_link(name)?;
        let index = link.map(|link| link.index);
        if observed.index != index {
            *observed = ObservedAuxLink {
                index,
                ..ObservedAuxLink::default()
            };
            *broadcasts = None;
        }
        let Some(link) = link else {
            return Ok(None);
        };
        let info = AuxLinkInfo::from_link(link)?;
        dump_with_buffer(
            fd.as_fd(),
            2,
            libc::RTM_GETROUTE,
            12,
            &mut snapshot,
            deadline,
            buffer,
        )?;
        if snapshot
            .routes
            .iter()
            .any(|route| route.is_ip_default() && route.nexthop.is_some())
        {
            dump_with_buffer(
                fd.as_fd(),
                3,
                RTM_GETNEXTHOP,
                8,
                &mut snapshot,
                deadline,
                buffer,
            )?;
        }
        let defaults = snapshot.check_aux_defaults(info.ifindex);
        observed.default_refused = defaults.is_err();
        defaults?;
        let (ingress, has_filter) = legacy_ingress(fd.as_fd(), info.ifindex, deadline, buffer)?;
        observed.ingress = ingress;
        if has_filter {
            return Err(unsupported(
                "l3_lan has a conflicting legacy ingress filter",
            ));
        }
        let verified = snapshot.ipv4_broadcasts();
        observed.broadcasts_refused = verified.is_err();
        *broadcasts = None;
        *broadcasts = Some(verified?);
        Ok(Some(info))
    }

    /// Return the canonical local-table broadcast destinations from the latest admitted link read.
    pub fn ipv4_broadcasts(&self) -> io::Result<([Ipv4Addr; MAX_BROADCASTS], usize)> {
        self.state
            .lock()
            .map_err(watch_poisoned)?
            .broadcasts
            .ok_or_else(|| unsupported("auxiliary IPv4 broadcasts are not verified"))
    }

    /// Confirm the private TUN still has only the daemon-owned link identity.
    pub fn verify_inner(&self, name: &str, ifindex: u32, mtu: u32) -> io::Result<()> {
        let name_key = interface_name(name.as_bytes())?;
        let fd = self.dump_socket()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut state = self.state.lock().map_err(watch_poisoned)?;
        let buffer = &mut state.buffer.bytes;
        let mut snapshot = snapshot_with_buffer(fd.as_fd(), Some(deadline), buffer)?;
        if snapshot.routes.iter().any(|route| route.nexthop.is_some()) {
            dump_with_buffer(
                fd.as_fd(),
                5,
                RTM_GETNEXTHOP,
                8,
                &mut snapshot,
                deadline,
                buffer,
            )?;
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
        Ok(())
    }

    /// Drain queued notifications, retaining identity loss even across identical recreation.
    /// `inner` is the active private TUN's (name, ifindex, MTU), after its setup notices are drained.
    pub fn changed(
        &mut self,
        name: &str,
        previous: Option<AuxLinkInfo>,
        inner: Option<(&str, u32, u32)>,
    ) -> io::Result<bool> {
        let outer_name = interface_name(name.as_bytes())?;
        let inner_key = inner
            .map(|(name, index, mtu)| interface_name(name.as_bytes()).map(|key| (key, index, mtu)))
            .transpose()?;
        let changes = self.drain(outer_name, previous, inner_key)?;
        if changes.invalidated {
            return Ok(true);
        }
        if changes.broadcasts_dirty && previous.is_none() {
            return Ok(true);
        }
        if changes.recheck
            && let Some((name, index, mtu)) = inner
        {
            self.verify_inner(name, index, mtu)?;
        }
        if (changes.recheck || changes.broadcasts_dirty) && previous.is_some() {
            let broadcasts = self.ipv4_broadcasts()?;
            return Ok(self.read_l3(name)? != previous || self.ipv4_broadcasts()? != broadcasts);
        }
        Ok(false)
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
            let length = match receive_notification(self.fd.as_fd(), buffer) {
                Ok(length) => length,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(changes),
                Err(error) => return Err(error),
            };
            changes.inspect(
                &buffer[..length],
                name,
                previous,
                inner,
                state.observed,
                state.broadcasts.as_ref(),
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
        return Err(malformed("invalid auxiliary RTNL namespace cookie"));
    }
    Ok(value)
}

fn receive_notification(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<usize> {
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
        return Err(malformed("invalid auxiliary notification sender or extent"));
    }
    Ok(n as usize)
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

fn legacy_ingress(
    fd: BorrowedFd<'_>,
    index: u32,
    deadline: Instant,
    buffer: &mut [u8],
) -> io::Result<(Option<LegacyIngress>, bool)> {
    let mut ingress = None;
    dump_request(
        fd,
        4,
        libc::RTM_GETQDISC,
        &[0; 20],
        deadline,
        buffer,
        |_, body| {
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
                            b"ingress\0" => TC_H_INGRESS,
                            b"clsact\0" => TC_H_CLSACT_INGRESS,
                            _ => return Err(unsupported("unrecognized l3_lan ingress qdisc")),
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
            if ingress
                .replace(LegacyIngress {
                    index,
                    parent,
                    shared_block,
                })
                .is_some()
            {
                return Err(malformed("duplicate l3_lan ingress qdisc"));
            }
            Ok(())
        },
    )?;
    let Some(ingress) = ingress else {
        return Ok((None, false));
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
    dump_request(
        fd,
        5,
        libc::RTM_GETTFILTER,
        &target.body(),
        deadline,
        buffer,
        |_, body| {
            if !ingress.contains(TcTarget::read(body)?) {
                return Err(malformed("unexpected l3_lan ingress filter target"));
            }
            attributes(&body[20..], |_, _| Ok(()))?;
            has_filter = true;
            Ok(())
        },
    )?;
    Ok((Some(ingress), has_filter))
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
        let outer_index = previous.map(|info| info.ifindex).or(observed.index);
        let waiting_for_default = previous.is_none() && observed.default_refused;
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
            if flags & 0x10 != 0 {
                return Err(malformed("interrupted auxiliary notification"));
            }
            let body = &bytes[16..length];
            let mut parsed = Snapshot::default();
            match kind {
                libc::RTM_NEWLINK | libc::RTM_DELLINK => {
                    parsed.push(libc::RTM_NEWLINK, body)?;
                    let link = &parsed.links[0];
                    self.invalidated |= match previous {
                        Some(info) if link.index == info.ifindex => {
                            kind == libc::RTM_DELLINK
                                || link.name != Some(name)
                                || AuxLinkInfo::from_link(link).ok() != Some(info)
                        }
                        _ => match kind {
                            libc::RTM_NEWLINK => link.name == Some(name),
                            _ => outer_index == Some(link.index),
                        },
                    };
                    if let Some((inner_name, index, mtu)) = inner {
                        self.invalidated |= link.index == index
                            && (kind == libc::RTM_DELLINK || !link.is_owned_tun(inner_name, mtu));
                    }
                }
                libc::RTM_NEWROUTE | libc::RTM_DELROUTE => {
                    parsed.push(libc::RTM_NEWROUTE, body)?;
                    let route = &parsed.routes[0];
                    self.broadcasts_dirty |= outer_index.is_some()
                        && (broadcasts.is_some() || observed.broadcasts_refused)
                        && route.may_change_ipv4_broadcasts(broadcasts);
                    if route.is_ip_default() {
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
                    self.invalidated |= outer_index.is_some_and(|index| {
                        if matches!(kind, libc::RTM_NEWQDISC | libc::RTM_DELQDISC) {
                            target.ifindex == index && target.parent == TC_H_INGRESS
                        } else {
                            observed.ingress.is_some_and(|ingress| {
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
