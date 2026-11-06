//! Read-only admission for preprovisioned own-socket uplink routing.
//!
//! A dedicated exact-bypass-mark RPDB table isolates socket output from captured
//! ports without replacing CoreForward's input FIB. Notifications invalidate
//! this snapshot; they are not an atomic fence against external RTNL writers.
//! Kernel IPv6 ff00::/8 multicast routes remain outside native unicast capture.

use std::collections::HashSet;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::bpf::{attributes, wait_netlink};

const MAX_OBJECTS: usize = 65_536;
pub(crate) const MAX_BROADCASTS: usize = 64;

pub struct Topology {
    fd: OwnedFd,
    invalidated: bool,
    ipv4_broadcasts: [Ipv4Addr; MAX_BROADCASTS],
    broadcast_count: usize,
}

impl Topology {
    /// Requires operator-provisioned mark rules/tables; never writes host routes.
    /// Call before attaching capture, then retain and watch this descriptor for
    /// the whole attachment lifetime. Any invalidation requires closing admission.
    /// Physical roots and every canonical-FIB-proven VLAN descendant belong in
    /// `captured_logical`; discovering a sysfs upper never authorizes it here.
    pub fn admit(
        captured_physical: &[u32],
        captured_logical: &[u32],
        bypass_mark: u32,
    ) -> io::Result<Self> {
        validate_capture_sets(captured_physical, captured_logical, bypass_mark)?;
        let fd = route_socket()?;
        let mut snapshot = Snapshot::default();
        for (sequence, kind, body_len) in [(1, 18, 16), (2, 22, 8), (3, 34, 12), (4, 26, 12)] {
            dump(fd.as_fd(), sequence, kind, body_len, &mut snapshot)?;
        }
        snapshot.admit(captured_physical, captured_logical, bypass_mark)?;
        let (ipv4_broadcasts, broadcast_count) = snapshot.ipv4_broadcasts()?;
        let mut topology = Self {
            fd,
            invalidated: false,
            ipv4_broadcasts,
            broadcast_count,
        };
        if topology.check_changed()? {
            return Err(unsupported("routing topology changed during admission"));
        }
        Ok(topology)
    }

    /// Exact local-table broadcast destinations from this watched namespace.
    pub fn ipv4_broadcasts(&self) -> &[Ipv4Addr] {
        &self.ipv4_broadcasts[..self.broadcast_count]
    }

    /// Sticky fail-closed invalidation, including receive loss and malformed
    /// notifications. No drain/re-admit loop can silently restore old authority.
    pub fn check_changed(&mut self) -> io::Result<bool> {
        if self.invalidated {
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
                self.invalidated = true;
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::WouldBlock => return Ok(false),
                io::ErrorKind::Interrupted => continue,
                _ => {
                    self.invalidated = true;
                    return Err(error);
                }
            }
        }
    }
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

fn validate_capture_sets(
    captured_physical: &[u32],
    captured_logical: &[u32],
    bypass_mark: u32,
) -> io::Result<()> {
    if captured_physical.is_empty()
        || captured_logical.is_empty()
        || bypass_mark == 0
        || bypass_mark & honk_ebpf_common::CLASSIFIED_MARK != 0
        || captured_physical.len() > MAX_OBJECTS
        || captured_logical.len() > MAX_OBJECTS
    {
        return Err(unsupported(
            "invalid physical/logical capture sets or bypass mark",
        ));
    }
    let physical: HashSet<_> = captured_physical.iter().copied().collect();
    let logical: HashSet<_> = captured_logical.iter().copied().collect();
    if physical.len() != captured_physical.len()
        || logical.len() != captured_logical.len()
        || logical.contains(&0)
        || !physical.is_subset(&logical)
    {
        return Err(unsupported(
            "invalid physical/logical capture sets or bypass mark",
        ));
    }
    Ok(())
}

fn route_socket() -> io::Result<OwnedFd> {
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
    address.nl_groups = 1 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400;
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
    let ipv6_rules: libc::c_int = 19;
    // SAFETY: the supplied option is a live integer, for RTNLGRP_IPV6_RULE.
    if unsafe {
        libc::setsockopt(
            raw,
            270,
            1,
            (&ipv6_rules as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn dump(
    fd: BorrowedFd<'_>,
    sequence: u32,
    kind: u16,
    body_len: usize,
    snapshot: &mut Snapshot,
) -> io::Result<()> {
    let mut request = [0u8; 32];
    let length = 16 + body_len;
    request[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&kind.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    // SAFETY: zero is valid initialization for sockaddr_nl.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
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
    let mut buffer = [0u8; 65_536];
    loop {
        wait_netlink(fd, libc::POLLIN, deadline)?;
        let mut source = kernel;
        let mut source_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: receive buffers are writable and correctly sized.
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                (&mut source as *mut libc::sockaddr_nl).cast(),
                &mut source_len,
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
        if n == 0
            || n as usize > buffer.len()
            || source_len as usize != size_of::<libc::sockaddr_nl>()
            || source.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || source.nl_pid != 0
        {
            return Err(malformed("invalid topology dump sender or extent"));
        }
        let mut bytes = &buffer[..n as usize];
        let mut done = false;
        while !bytes.is_empty() {
            if bytes.len() < 16 {
                return Err(malformed("short topology message"));
            }
            let length = u32_at(bytes, 0)? as usize;
            if length < 16 || length > bytes.len() {
                return Err(malformed("invalid topology message length"));
            }
            let message = u16::from_ne_bytes([bytes[4], bytes[5]]);
            let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
            if u32_at(bytes, 8)? != sequence || flags & 0x10 != 0 {
                return Err(unsupported(
                    "topology changed or dump was interrupted during admission",
                ));
            }
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
                    if body.len() >= 4 && u32_at(body, 0)? != 0 {
                        return Err(malformed("failed topology dump completion"));
                    }
                    done = true;
                }
                4 => return Err(malformed("topology netlink overrun")),
                16 | 20 | 24 | 32 if !done && message == kind - 2 && flags & 2 != 0 => {
                    snapshot.push(message, body)?
                }
                _ => return Err(malformed("unexpected topology dump message")),
            }
            let advance = (length + 3) & !3;
            if advance > bytes.len() && length != bytes.len() {
                return Err(malformed("short topology alignment"));
            }
            bytes = &bytes[advance.min(bytes.len())..];
        }
        if done {
            return Ok(());
        }
    }
}

#[derive(Default)]
struct Snapshot {
    links: Vec<Link>,
    addresses: Vec<Address>,
    rules: Vec<Rule>,
    routes: Vec<Route>,
}

struct Link {
    index: u32,
    plain_up_ethernet: bool,
    loopback: bool,
}
struct Address {
    family: u8,
    index: u32,
    unicast_source: bool,
}
struct Rule {
    family: u8,
    priority: u32,
    table: u32,
    mark: Option<u32>,
    mask: u32,
    simple: bool,
}
struct Route {
    family: u8,
    table: u32,
    output: u32,
    default: bool,
    kind: u8,
    simple: bool,
    native_multicast: bool,
    ipv4_destination: Option<Ipv4Addr>,
}

impl Snapshot {
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
        if self.links.len() + self.addresses.len() + self.rules.len() + self.routes.len()
            >= MAX_OBJECTS
        {
            return Err(unsupported("topology snapshot exceeds bounded capacity"));
        }
        match kind {
            16 => {
                if body.len() < 16 {
                    return Err(malformed("short topology link"));
                }
                let index = u32_at(body, 4)?;
                let flags = u32_at(body, 8)?;
                let mut plain =
                    u16::from_ne_bytes([body[2], body[3]]) == 1 && flags & 0x10001 == 0x10001;
                let mut parent = index;
                let mut link_kind = None;
                attributes(&body[16..], |kind, value| {
                    match kind {
                        5 => parent = u32_at(value, 0)?,
                        10 if u32_at(value, 0)? != 0 => plain = false,
                        18 => attributes(value, |kind, name| {
                            if kind == 1 {
                                link_kind = Some(name);
                            }
                            Ok(())
                        })?,
                        _ => {}
                    }
                    Ok(())
                })?;
                plain &= match link_kind {
                    Some(b"veth\0") => true,
                    None => parent == index,
                    _ => false,
                };
                self.links.push(Link {
                    index,
                    plain_up_ethernet: plain,
                    loopback: flags & 8 != 0,
                });
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
                attributes(&body[8..], |kind, value| {
                    let slot = match kind {
                        1 => &mut address,
                        2 => &mut local,
                        _ => return Ok(()),
                    };
                    if slot.replace(unicast_source(family, value)?).is_some() {
                        return Err(malformed("duplicate topology source address"));
                    }
                    Ok(())
                })?;
                self.addresses.push(Address {
                    family,
                    index: u32_at(body, 4)?,
                    unicast_source: local
                        .or(address)
                        .ok_or_else(|| malformed("missing topology source address"))?,
                });
            }
            32 => {
                if body.len() < 12 {
                    return Err(malformed("short topology rule"));
                }
                if !matches!(body[0], 2 | 10) {
                    return Ok(());
                }
                let mut rule = Rule {
                    family: body[0],
                    priority: 0,
                    table: u32::from(body[4]),
                    mark: None,
                    mask: 0,
                    simple: body[1..4] == [0, 0, 0] && body[7] == 1 && u32_at(body, 8)? == 0,
                };
                attributes(&body[12..], |kind, value| {
                    match kind {
                        6 => rule.priority = u32_at(value, 0)?,
                        10 => rule.mark = Some(u32_at(value, 0)?),
                        15 => rule.table = u32_at(value, 0)?,
                        16 => rule.mask = u32_at(value, 0)?,
                        14 if u32_at(value, 0)? == u32::MAX => {}
                        18 | 21 => {}
                        _ => rule.simple = false,
                    }
                    Ok(())
                })?;
                self.rules.push(rule);
            }
            24 => {
                if body.len() < 12 {
                    return Err(malformed("short topology route"));
                }
                if !matches!(body[0], 2 | 10) {
                    return Ok(());
                }
                let mut route = Route {
                    family: body[0],
                    table: u32::from(body[4]),
                    output: 0,
                    default: body[1] == 0,
                    kind: body[7],
                    simple: body[2] == 0 && body[3] == 0 && u32_at(body, 8)? == 0,
                    native_multicast: body[0] == 10 && body[1] == 8 && body[7] == 5,
                    ipv4_destination: None,
                };
                let mut multicast_destination = None;
                attributes(&body[12..], |kind, value| {
                    match kind {
                        1 => {
                            let exact = value.len() == 16
                                && value[0] == 0xff
                                && value[1..].iter().all(|&byte| byte == 0);
                            if multicast_destination.replace(exact).is_some() {
                                return Err(malformed("duplicate topology route destination"));
                            }
                            if body[0] == 2 && body[1] == 32 {
                                route.ipv4_destination = Some(Ipv4Addr::from(
                                    <[u8; 4]>::try_from(value)
                                        .map_err(|_| malformed("invalid IPv4 route destination"))?,
                                ));
                            }
                        }
                        4 => route.output = u32_at(value, 0)?,
                        15 => route.table = u32_at(value, 0)?,
                        5 | 6 | 7 | 8 | 12 | 20 | 23 => {}
                        _ => route.simple = false,
                    }
                    Ok(())
                })?;
                route.native_multicast &= route.simple && multicast_destination == Some(true);
                self.routes.push(route);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn admit(
        &self,
        captured_physical: &[u32],
        captured_logical: &[u32],
        bypass_mark: u32,
    ) -> io::Result<()> {
        for &index in captured_physical {
            if !self
                .links
                .iter()
                .any(|link| link.index == index && link.plain_up_ethernet)
            {
                return Err(unsupported(
                    "capture requires unnumbered, up, standalone Ethernet roots",
                ));
            }
        }
        for &index in captured_logical {
            if !self.links.iter().any(|link| link.index == index)
                || self.addresses.iter().any(|address| address.index == index)
            {
                return Err(unsupported(
                    "logical capture interfaces must exist and remain unnumbered",
                ));
            }
        }
        if self.routes.iter().any(|route| {
            route.table == 255
                && !route.native_multicast
                && (route.kind == 1 || captured_logical.contains(&route.output))
        }) {
            return Err(unsupported(
                "local routing table can select a captured interface",
            ));
        }
        let mut enabled = false;
        for family in [2, 10] {
            let family_enabled = self
                .addresses
                .iter()
                .any(|address| address.family == family && address.unicast_source);
            if !family_enabled {
                continue;
            }
            enabled = true;
            let mut local = 0;
            let mut mark_rule = None;
            for rule in self.rules.iter().filter(|rule| rule.family == family) {
                if !rule.simple {
                    return Err(unsupported(
                        "own-socket uplink proof rejects RPDB selectors, VRFs and rule actions",
                    ));
                }
                match rule.mark {
                    Some(mark)
                        if mark == bypass_mark
                            && rule.mask == u32::MAX
                            && rule.priority > 0
                            && rule.priority < 32766
                            && rule.table != 0
                            && !(253..=255).contains(&rule.table) =>
                    {
                        if mark_rule.replace(rule).is_some() {
                            return Err(unsupported("duplicate bypass mark rules"));
                        }
                    }
                    None if rule.mask == 0 && rule.priority == 0 && rule.table == 255 => local += 1,
                    None if rule.mask == 0
                        && ((rule.priority == 32766 && rule.table == 254)
                            || (rule.priority == 32767 && rule.table == 253)) => {}
                    _ => {
                        return Err(unsupported(
                            "RPDB is not local, exact bypass mark, then main/default",
                        ));
                    }
                }
            }
            if local != 1 {
                return Err(unsupported("missing unique priority-zero local rule"));
            }
            let rule = mark_rule.ok_or_else(|| unsupported("provision an exact bypass-mark rule before main with a dedicated uncaptured uplink table"))?;
            let mut default = false;
            for route in self
                .routes
                .iter()
                .filter(|route| route.family == family && route.table == rule.table)
            {
                if !route.simple
                    || route.kind != 1
                    || captured_logical.contains(&route.output)
                    || !self.links.iter().any(|link| {
                        link.index == route.output && link.plain_up_ethernet && !link.loopback
                    })
                {
                    return Err(unsupported(
                        "bypass table must contain only unicast routes on uncaptured standalone Ethernet uplinks",
                    ));
                }
                default |= route.default;
            }
            if !default {
                return Err(unsupported(
                    "bypass uplink table lacks a covering default for an enabled address family",
                ));
            }
        }
        if !enabled {
            return Err(unsupported("no non-loopback unicast source address family"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
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
            snapshot.admit(&[2], &[2], 128).unwrap();
            let (broadcasts, count) = snapshot.ipv4_broadcasts().unwrap();
            assert_eq!(count, usize::from(expected));
            if expected {
                assert_eq!(broadcasts[0], Ipv4Addr::from(address));
            }
        }
        for mutation in 0..5 {
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
            assert!(
                snapshot
                    .admit(&[2], &[2], 128)
                    .and_then(|()| snapshot.ipv4_broadcasts().map(|_| ()))
                    .is_err()
            );
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
    fn only_exact_simple_ipv6_multicast_routes_bypass_local_capture_refusal() {
        let multicast = Ipv6Addr::from(0xff00u128 << 112).octets();
        let unicast = "2001:db8::".parse::<Ipv6Addr>().unwrap().octets();
        let mut host_bits = multicast;
        host_bits[15] = 1;
        for (family, prefix, kind, destination, allowed) in [
            (10, 8, 5, Some(multicast.as_slice()), true),
            (10, 8, 1, Some(multicast.as_slice()), false),
            (10, 8, 2, Some(multicast.as_slice()), false),
            (10, 8, 5, Some(unicast.as_slice()), false),
            (10, 0, 5, Some(multicast.as_slice()), false),
            (10, 128, 5, Some(multicast.as_slice()), false),
            (2, 8, 5, Some(multicast.as_slice()), false),
            (10, 8, 5, Some(&multicast[..15]), false),
            (10, 8, 5, Some(host_bits.as_slice()), false),
            (10, 8, 5, None, false),
        ] {
            let mut snapshot = topology();
            snapshot
                .push(24, &local_route_body(family, prefix, kind, destination))
                .unwrap();
            assert_eq!(snapshot.routes.last().unwrap().native_multicast, allowed);
            assert_eq!(snapshot.admit(&[2], &[2], 128).is_ok(), allowed);
        }
        for mutation in 0..3 {
            let mut body = local_route_body(10, 8, 5, Some(&multicast));
            match mutation {
                0 => body[2] = 1,
                1 => body[8] = 1,
                _ => attribute(&mut body, 99, &0u32.to_ne_bytes()),
            }
            let mut snapshot = topology();
            snapshot.push(24, &body).unwrap();
            assert!(snapshot.admit(&[2], &[2], 128).is_err());
        }
        let mut duplicate = local_route_body(10, 8, 5, Some(&multicast));
        attribute(&mut duplicate, 1, &unicast);
        assert!(Snapshot::default().push(24, &duplicate).is_err());
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

    #[test]
    fn global_ipv6_host_address_on_loopback_requires_ipv6_bypass_proof() {
        let mut snapshot = topology();
        snapshot.links.push(Link {
            index: 1,
            plain_up_ethernet: false,
            loopback: true,
        });
        snapshot
            .push(20, &address_body(2, 1, &[127, 0, 0, 1], None))
            .unwrap();
        snapshot
            .push(
                20,
                &address_body(10, 1, &Ipv6Addr::LOCALHOST.octets(), None),
            )
            .unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_ok());
        let global = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        snapshot
            .push(20, &address_body(10, 1, &global, None))
            .unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
        let ipv6_rules: Vec<_> = snapshot
            .rules
            .iter()
            .map(|rule| Rule {
                family: 10,
                priority: rule.priority,
                table: rule.table,
                mark: rule.mark,
                mask: rule.mask,
                simple: rule.simple,
            })
            .collect();
        snapshot.rules.extend(ipv6_rules);
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
        let mut default = vec![0; 12];
        default[0] = 10;
        default[4] = 100;
        default[7] = 1;
        attribute(&mut default, 4, &3u32.to_ne_bytes());
        snapshot.push(24, &default).unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_ok());
        snapshot
            .push(
                20,
                &address_body(10, 2, &Ipv6Addr::LOCALHOST.octets(), None),
            )
            .unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
    }

    #[test]
    fn rule_dump_keeps_masks_and_rejects_input_selectors() {
        let mut body = vec![0u8; 12];
        body[0] = 2;
        body[4] = 100;
        body[7] = 1;
        for (kind, value) in [(6u16, 100u32), (10, 128), (16, u32::MAX), (14, u32::MAX)] {
            body.extend_from_slice(&8u16.to_ne_bytes());
            body.extend_from_slice(&kind.to_ne_bytes());
            body.extend_from_slice(&value.to_ne_bytes());
        }
        let mut parsed = Snapshot::default();
        parsed.push(32, &body).unwrap();
        let mut snapshot = topology();
        snapshot.rules[1] = parsed.rules.pop().unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_ok());
        body.extend_from_slice(&8u16.to_ne_bytes());
        body.extend_from_slice(&3u16.to_ne_bytes());
        body.extend_from_slice(b"lo\0\0");
        parsed.push(32, &body).unwrap();
        snapshot.rules[1] = parsed.rules.pop().unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
    }

    fn topology() -> Snapshot {
        Snapshot {
            links: vec![
                Link {
                    index: 2,
                    plain_up_ethernet: true,
                    loopback: false,
                },
                Link {
                    index: 3,
                    plain_up_ethernet: true,
                    loopback: false,
                },
            ],
            addresses: vec![Address {
                family: 2,
                index: 3,
                unicast_source: true,
            }],
            rules: vec![
                Rule {
                    family: 2,
                    priority: 0,
                    table: 255,
                    mark: None,
                    mask: 0,
                    simple: true,
                },
                Rule {
                    family: 2,
                    priority: 100,
                    table: 100,
                    mark: Some(128),
                    mask: u32::MAX,
                    simple: true,
                },
                Rule {
                    family: 2,
                    priority: 32766,
                    table: 254,
                    mark: None,
                    mask: 0,
                    simple: true,
                },
            ],
            routes: vec![
                Route {
                    family: 2,
                    table: 100,
                    output: 3,
                    default: true,
                    kind: 1,
                    simple: true,
                    native_multicast: false,
                    ipv4_destination: None,
                },
                Route {
                    family: 2,
                    table: 254,
                    output: 2,
                    default: false,
                    kind: 1,
                    simple: true,
                    native_multicast: false,
                    ipv4_destination: None,
                },
            ],
        }
    }

    #[test]
    fn marked_uplink_isolation_preserves_core_downstream_routes() {
        let mut snapshot = topology();
        assert!(snapshot.admit(&[2], &[2], 128).is_ok());
        snapshot.routes[0].output = 2;
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
        snapshot.routes[0].output = 3;
        snapshot.addresses.push(Address {
            family: 10,
            index: 2,
            unicast_source: true,
        });
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
        snapshot.addresses.pop();
        snapshot.rules[1].mask = 255;
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
        snapshot.rules[1].mask = u32::MAX;
        snapshot.addresses.push(Address {
            family: 10,
            index: 3,
            unicast_source: true,
        });
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
    }

    #[test]
    fn capture_sets_require_unique_nonzero_roots_inside_logical_realm() {
        assert!(validate_capture_sets(&[2], &[4, 2], 128).is_ok());
        for (physical, logical) in [
            (&[][..], &[2][..]),
            (&[2][..], &[][..]),
            (&[0][..], &[0][..]),
            (&[2][..], &[2, 0][..]),
            (&[2, 2][..], &[2][..]),
            (&[2][..], &[2, 2][..]),
            (&[2][..], &[4][..]),
        ] {
            assert!(validate_capture_sets(physical, logical, 128).is_err());
        }
        assert!(validate_capture_sets(&[2], &[2], 0).is_err());
        assert!(validate_capture_sets(&[2], &[2], honk_ebpf_common::CLASSIFIED_MARK).is_err());
    }

    #[test]
    fn captured_vlan_marked_routes_are_refused_regardless_of_link_shape() {
        for plain_up_ethernet in [false, true] {
            let mut snapshot = topology();
            snapshot.links.push(Link {
                index: 4,
                plain_up_ethernet,
                loopback: false,
            });
            snapshot.routes[0].output = 4;
            assert!(snapshot.admit(&[2], &[2, 4], 128).is_err());
        }
    }

    #[test]
    fn external_uplink_accepts_unnumbered_captured_vlan_downstream() {
        let mut snapshot = topology();
        snapshot.links.push(Link {
            index: 4,
            plain_up_ethernet: false,
            loopback: false,
        });
        snapshot.routes.push(Route {
            family: 2,
            table: 254,
            output: 4,
            default: false,
            kind: 1,
            simple: true,
            native_multicast: false,
            ipv4_destination: None,
        });
        assert!(snapshot.admit(&[2], &[2, 4], 128).is_ok());
        for family in [2, 10] {
            snapshot.addresses.push(Address {
                family,
                index: 4,
                unicast_source: true,
            });
            assert!(snapshot.admit(&[2], &[2, 4], 128).is_err());
            snapshot.addresses.pop();
        }
        snapshot.routes.push(Route {
            family: 2,
            table: 255,
            output: 4,
            default: false,
            kind: 2,
            simple: true,
            native_multicast: false,
            ipv4_destination: None,
        });
        assert!(snapshot.admit(&[2], &[2, 4], 128).is_err());
    }

    #[test]
    fn root_link_parser_distinguishes_veth_peer_from_stacked_parent() {
        for (kind, allowed) in [
            (b"veth\0".as_slice(), true),
            (b"vlan\0".as_slice(), false),
            (b"macvlan\0".as_slice(), false),
        ] {
            let mut body = vec![0; 16];
            body[2..4].copy_from_slice(&1u16.to_ne_bytes());
            body[4..8].copy_from_slice(&2u32.to_ne_bytes());
            body[8..12].copy_from_slice(&0x10001u32.to_ne_bytes());
            attribute(&mut body, 5, &9u32.to_ne_bytes());
            let mut info = Vec::new();
            attribute(&mut info, 1, kind);
            attribute(&mut body, 18, &info);
            let mut parsed = Snapshot::default();
            parsed.push(16, &body).unwrap();
            let mut snapshot = topology();
            snapshot.links[0] = parsed.links.pop().unwrap();
            assert_eq!(snapshot.admit(&[2], &[2], 128).is_ok(), allowed);
        }
    }
}
