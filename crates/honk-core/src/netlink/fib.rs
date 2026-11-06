//! Namespace-bound input FIB queries, not an RPDB replica.
//!
//! One owner serializes dumps, notifications, requests and submission fences on one socket.
//! No result survives a dependency notification or a failed receive/synchronization.
//! NETLINK_PKTINFO distinguishes multicast invalidations from sequence-matched unicast replies.

use super::*;
use honk_datapath::forward::{LinkPath, MarkProvenance, Route, RouteQuery};
use honk_netstack::{MemoryBudget, MemoryReservation};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_MESSAGE: usize = 1 << 20;
const MAX_LINKS: usize = 256;
const MAX_ADDRESSES: usize = 2048;
const MAX_NEIGHBORS: usize = 8192;
const MAX_DUMP_MESSAGES: usize = 65536;
const RTM_GETROUTE: u16 = 26;
const RTM_GETLINK: u16 = 18;
const RTM_GETADDR: u16 = 22;
const RTM_GETNEIGH: u16 = 30;
const RTM_GETRULE: u16 = 34;
const RTM_GETNEXTHOP: u16 = 106;
const FIB_GROUPS: [u32; 11] = [1, 3, 5, 7, 8, 9, 11, 19, 24, 25, 32];
const NLM_F_CAPPED: u16 = 0x100;
const NLM_F_ACK_TLVS: u16 = 0x200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FibState {
    Synchronizing,
    Ready,
    Desynchronized,
}

#[derive(Clone, Copy)]
struct Link {
    index: u32,
    mtu: u32,
    mac: [u8; 6],
    usable: bool,
    parent: u32,
    vlan: Option<(u16, u16)>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LogicalLink {
    pub ifindex: u32,
    pub mtu: u32,
    pub mac: [u8; 6],
    pub path: LinkPath,
}
#[derive(Clone, Copy)]
struct Neighbor {
    index: u32,
    ip: IpAddr,
    mac: [u8; 6],
    usable: bool,
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Address {
    index: u32,
    ip: IpAddr,
}
#[derive(Clone, Copy)]
struct Forwarding {
    index: u32,
    family: u8,
    enabled: bool,
}

pub(crate) enum Resolution {
    Forward(Route),
    LocalInput,
    Drop,
    Error(honk_netstack::transit::TransitError),
    NeighborPending(Route),
}

pub(crate) struct Fib {
    socket: NlSock,
    namespace: u64,
    generation: u64,
    address_generation: u64,
    state: FibState,
    links: Vec<Link>,
    neighbors: Vec<Neighbor>,
    addresses: Vec<Address>,
    previous_addresses: Vec<Address>,
    forwarding: Vec<Forwarding>,
    receive: Vec<u8>,
    synchronized_at: Instant,
    _charge: MemoryReservation,
}

impl Fib {
    /// Must be called synchronously in the capture namespace, before handing this owner
    /// to any asynchronous executor. The socket itself retains that namespace binding.
    pub(crate) fn new(budget: &Arc<MemoryBudget>, namespace: u64) -> io::Result<Self> {
        let socket = NlSock::new()?;
        let observed = namespace_cookie(socket.fd.as_raw_fd())?;
        if namespace == 0 || namespace != observed {
            return Err(invalid("FIB namespace identity mismatch"));
        }
        let packet_info = 1u32;
        // SAFETY: setsockopt reads one initialized u32 for this synchronous call.
        let result = unsafe {
            libc::setsockopt(
                socket.fd.as_raw_fd(),
                libc::SOL_NETLINK,
                libc::NETLINK_PKTINFO,
                (&packet_info as *const u32).cast(),
                size_of::<u32>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        for group in FIB_GROUPS {
            // RTNLGRP_LINK/NEIGH/IPv4+IPv6 IFADDR/RULE/ROUTE/NEXTHOP. Membership
            // precedes every baseline dump, including groups beyond the legacy bitmask.
            // SAFETY: setsockopt reads one initialized u32 for this synchronous call.
            let result = unsafe {
                libc::setsockopt(
                    socket.fd.as_raw_fd(),
                    libc::SOL_NETLINK,
                    libc::NETLINK_ADD_MEMBERSHIP,
                    (&group as *const u32).cast(),
                    size_of::<u32>() as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let bytes = MAX_MESSAGE
            + MAX_LINKS * size_of::<Link>()
            + 2 * MAX_ADDRESSES * size_of::<Address>()
            + MAX_NEIGHBORS * size_of::<Neighbor>()
            + 2 * (MAX_LINKS + 2) * size_of::<Forwarding>()
            + size_of::<Self>();
        let charge = budget
            .reserve(bytes)
            .ok_or_else(|| io::Error::other("FIB memory budget exhausted"))?;
        Ok(Self {
            socket,
            namespace,
            generation: 1,
            address_generation: 1,
            state: FibState::Synchronizing,
            links: Vec::with_capacity(MAX_LINKS),
            neighbors: Vec::with_capacity(MAX_NEIGHBORS),
            forwarding: Vec::with_capacity(2 * (MAX_LINKS + 2)),
            addresses: Vec::with_capacity(MAX_ADDRESSES),
            previous_addresses: Vec::with_capacity(MAX_ADDRESSES),
            receive: vec![0; MAX_MESSAGE],
            synchronized_at: Instant::now(),
            _charge: charge,
        })
    }

    pub(crate) fn state(&self) -> FibState {
        self.state
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn address_generation(&self) -> u64 {
        self.address_generation
    }

    pub(crate) fn logical_links(&self) -> impl Iterator<Item = LogicalLink> + '_ {
        self.links
            .iter()
            .filter_map(|link| logical_link(&self.links, link.index))
    }

    pub(crate) fn validate_capture(&self, physical: &[u32]) -> io::Result<()> {
        if physical.iter().any(|&index| {
            logical_link(&self.links, index)
                .is_none_or(|link| link.path != LinkPath::untagged(index))
        }) {
            return Err(invalid("capture root lacks plain Ethernet authority"));
        }
        for link in &self.links {
            let mut current = link;
            for _ in 0..self.links.len() {
                if physical.contains(&current.index) {
                    if logical_link(&self.links, link.index).is_none() {
                        return Err(invalid("capture has an unsupported VLAN/upper descendant"));
                    }
                    break;
                }
                let Some(parent) = self
                    .links
                    .iter()
                    .find(|parent| parent.index == current.parent)
                else {
                    break;
                };
                current = parent;
            }
        }
        Ok(())
    }

    fn invalidate_address(&mut self) -> io::Result<()> {
        let Some(next) = self.address_generation.checked_add(1) else {
            self.state = FibState::Desynchronized;
            return Err(invalid("FIB address generation exhausted"));
        };
        self.address_generation = next;
        Ok(())
    }

    fn notified(&mut self, kind: u16) -> io::Result<()> {
        if matches!(kind, RTM_NEWLINK | RTM_DELLINK | RTM_NEWADDR | RTM_DELADDR) {
            self.invalidate_address()?;
        }
        self.invalidate()
    }

    fn invalidate(&mut self) -> io::Result<()> {
        self.state = FibState::Synchronizing;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("FIB generation exhausted"))?;
        Ok(())
    }

    fn fail<T>(&mut self, error: io::Error) -> io::Result<T> {
        self.state = FibState::Desynchronized;
        self.generation = self.generation.saturating_add(1);
        Err(error)
    }

    /// A finite receive budget prevents a notification flood from starving closure. Loss,
    /// truncation, malformed messages and unexpected late replies close admission.
    pub(crate) fn poll_changes(&mut self) -> io::Result<bool> {
        if self.state == FibState::Desynchronized {
            return Err(invalid("FIB owner desynchronized"));
        }
        match self.drain_changes() {
            Ok(changed) => Ok(changed),
            Err(error) => self.fail(error),
        }
    }

    fn drain_changes(&mut self) -> io::Result<bool> {
        let before = self.generation;
        for _ in 0..64 {
            let (n, group) = match self.receive_datagram(true) {
                Ok(Some(datagram)) => datagram,
                Ok(None) => return Ok(before != self.generation),
                Err(error) => return Err(error),
            };
            self.drain_datagram(n, group)?;
        }
        Err(invalid("FIB notification drain bound exceeded"))
    }

    fn drain_datagram(&mut self, n: usize, group: u32) -> io::Result<()> {
        let mut at = 0;
        while at < n {
            let (length, kind, flags, _) = header(&self.receive[at..n])?;
            if flags & NLM_F_DUMP_INTR != 0 || !multicast_notification(group, kind)? {
                return Err(invalid("unexpected or late FIB reply"));
            }
            self.notified(kind)?;
            at += align(length);
        }
        Ok(())
    }

    pub(crate) fn synchronize(&mut self) -> io::Result<()> {
        if self.state == FibState::Desynchronized {
            return Err(invalid("FIB owner desynchronized; recreate owner"));
        }
        std::mem::swap(&mut self.addresses, &mut self.previous_addresses);
        for _ in 0..3 {
            self.poll_changes()?;
            self.state = FibState::Synchronizing;
            let generation = self.generation;
            self.links.clear();
            self.neighbors.clear();
            self.addresses.clear();
            self.forwarding.clear();
            let result = (|| {
                for (kind, family, size) in [
                    (RTM_GETLINK, 0, 16),
                    (RTM_GETADDR, 0, 8),
                    (RTM_GETROUTE, AF_INET as u8, 12),
                    (RTM_GETROUTE, AF_INET6 as u8, 12),
                    (RTM_GETRULE, AF_INET as u8, 12),
                    (RTM_GETRULE, AF_INET6 as u8, 12),
                    (82, AF_INET as u8, 4),
                    (82, AF_INET6 as u8, 4),
                    (RTM_GETNEXTHOP, 0, 8),
                    (RTM_GETNEIGH, 0, 12),
                ] {
                    let mut body = [0; 16];
                    body[0] = family;
                    self.exchange(kind, NLM_F_REQUEST | 0x300, &body[..size], &[], true)?;
                }
                self.poll_changes()?;
                Ok(())
            })();
            if let Err(error) = result {
                return self.fail(error);
            }
            if self.generation == generation {
                self.addresses.sort_unstable();
                if self.addresses != self.previous_addresses {
                    self.invalidate_address()?;
                }
                self.state = FibState::Ready;
                self.synchronized_at = Instant::now();
                return Ok(());
            }
        }
        self.fail(invalid("FIB changed throughout bounded synchronization"))
    }

    pub(crate) fn current(&mut self, generation: u64) -> io::Result<bool> {
        if self.state == FibState::Desynchronized {
            return Err(invalid("FIB owner desynchronized"));
        }
        self.poll_changes()?;
        // Some routing dependencies (sysctls, expiring route metrics) have no reliable
        // rtnetlink notification. A lease has a bounded horizon, never indefinite cache use.
        if self.synchronized_at.elapsed() >= Duration::from_secs(1) {
            self.invalidate()?;
        }
        Ok(self.state == FibState::Ready && self.generation == generation)
    }

    pub(crate) fn is_local(&self, address: IpAddr) -> bool {
        self.addresses.iter().any(|entry| entry.ip == address)
    }

    pub(crate) fn lookup(&mut self, query: RouteQuery) -> io::Result<Resolution> {
        self.lookup_context(query, true)
    }

    pub(crate) fn lookup_error(&mut self, original: RouteQuery) -> io::Result<Resolution> {
        let source = if original.source.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let query = RouteQuery {
            source,
            destination: original.source,
            traffic_class: 0,
            protocol: if source.is_ipv4() { 1 } else { 58 },
            ports: None,
            ..original
        };
        let resolution = self.lookup_context(query, false)?;
        if let Resolution::NeighborPending(route) = resolution {
            if self.error_source(route).is_none() {
                return Ok(Resolution::Drop);
            }
            self.request_neighbor(route)?;
        }
        Ok(resolution)
    }

    fn lookup_context(&mut self, query: RouteQuery, input: bool) -> io::Result<Resolution> {
        if input
            && !self.forwarding.iter().any(|state| {
                state.index == query.ingress.ifindex
                    && state.family == family(query.source)
                    && state.enabled
            })
        {
            return Ok(Resolution::Drop);
        }
        let selected = self.select_route(query, input, None)?;
        self.resolve(query, selected)
    }

    fn resolve(&mut self, query: RouteQuery, selected: SelectedRoute) -> io::Result<Resolution> {
        let result = match selected {
            SelectedRoute::Found(result) => result,
            SelectedRoute::Unavailable(libc::EINVAL) => return Ok(Resolution::Drop),
            SelectedRoute::Unavailable(error) => {
                return Ok(Resolution::Error(if error == libc::EACCES {
                    honk_netstack::transit::TransitError::AdminProhibited
                } else {
                    honk_netstack::transit::TransitError::HostUnreachable
                }));
            }
        };
        if result.unsupported {
            return Ok(Resolution::Drop);
        }
        if result.kind == RTN_LOCAL {
            return Ok(Resolution::LocalInput);
        }
        if result.kind != RTN_UNICAST {
            return Ok(Resolution::Drop);
        }
        let Some(link) = logical_link(&self.links, result.ifindex) else {
            return Ok(Resolution::Drop);
        };
        let next_hop = result.gateway.unwrap_or(query.destination);
        let neighbor = self
            .neighbors
            .iter()
            .find(|neighbor| {
                neighbor.index == result.ifindex && neighbor.ip == next_hop && neighbor.usable
            })
            .copied();
        let route = Route {
            generation: self.generation,
            ifindex: link.ifindex,
            l2: link.path,
            mtu: result.mtu.map_or(link.mtu, |mtu| mtu.min(link.mtu)),
            next_hop,
            preferred_source: result
                .preferred_source
                .filter(|source| self.is_local(*source)),
            source_mac: link.mac,
            destination_mac: neighbor.map_or([0; 6], |neighbor| neighbor.mac),
        };
        Ok(if neighbor.is_some() {
            Resolution::Forward(route)
        } else {
            Resolution::NeighborPending(route)
        })
    }

    pub(crate) fn request_neighbor(&mut self, route: Route) -> io::Result<()> {
        if !self.current(route.generation)? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.use_neighbor(route.ifindex, route.next_hop)
    }

    pub(crate) fn error_source(&self, route: Route) -> Option<IpAddr> {
        route.preferred_source.filter(|source| {
            source.is_ipv4() == route.next_hop.is_ipv4()
                && honk_netstack::transit::unicast(*source)
                && self.is_local(*source)
        })
    }

    pub(crate) fn masquerade_source(
        &mut self,
        route: Route,
        query: RouteQuery,
    ) -> io::Result<Option<Ipv4Addr>> {
        if !self.current(route.generation)? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if let Some(IpAddr::V4(address)) = route
            .preferred_source
            .filter(|address| self.is_local(*address))
        {
            return Ok(Some(address));
        }
        if !query.source.is_ipv4() {
            return Ok(None);
        }
        let selected = self.select_route(
            RouteQuery {
                source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                ..query
            },
            false,
            Some(route.ifindex),
        )?;
        Ok(self.masquerade_selection(route, query, selected))
    }

    fn masquerade_selection(
        &self,
        route: Route,
        query: RouteQuery,
        selected: SelectedRoute,
    ) -> Option<Ipv4Addr> {
        let selected = match selected {
            SelectedRoute::Found(selected) => selected,
            SelectedRoute::Unavailable(_) => return None,
        };
        if selected.unsupported
            || selected.kind != RTN_UNICAST
            || selected.ifindex != route.ifindex
            || selected.gateway.unwrap_or(query.destination) != route.next_hop
        {
            return None;
        }
        match selected.preferred_source {
            Some(IpAddr::V4(address))
                if self.is_local(address.into())
                    && honk_netstack::transit::unicast(address.into()) =>
            {
                Some(address)
            }
            _ => None,
        }
    }

    fn select_route(
        &mut self,
        query: RouteQuery,
        input: bool,
        output: Option<u32>,
    ) -> io::Result<SelectedRoute> {
        if query.ingress.namespace != self.namespace
            || query.ingress.ifindex == 0
            || query.source.is_ipv4() != query.destination.is_ipv4()
        {
            return Err(invalid("invalid input-route provenance"));
        }
        let mark = match query.ingress.mark {
            MarkProvenance::Captured(mark) => mark,
            MarkProvenance::BeforeSkb => 0,
            MarkProvenance::Unavailable => return Err(invalid("input-route mark unavailable")),
        };
        if !self.current(self.generation)? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let generation = self.generation;
        let mut body = [0; 12];
        body[0] = family(query.destination);
        body[1] = if query.destination.is_ipv4() { 32 } else { 128 };
        body[2] = if query.source.is_unspecified() {
            0
        } else {
            body[1]
        };
        body[3] = query.traffic_class;
        if query.destination.is_ipv4() {
            body[8..12].copy_from_slice(&0x1000u32.to_ne_bytes());
        }
        let mut attrs = vec![
            (RTA_DST, ip_attr(query.destination)),
            (16, Attr::U32(if input { mark } else { 0 })),
            (27, Attr::Bytes(vec![query.protocol])),
        ];
        if !query.source.is_unspecified() {
            attrs.push((2, ip_attr(query.source)));
        }
        if input {
            attrs.push((3, Attr::U32(query.ingress.ifindex)));
        }
        if let Some(index) = output {
            attrs.push((RTA_OIF, Attr::U32(index)));
        }
        if let Some((source, destination)) = query.ports {
            attrs.push((28, Attr::Bytes(source.to_be_bytes().to_vec())));
            attrs.push((29, Attr::Bytes(destination.to_be_bytes().to_vec())));
        }
        let exchanged = self.exchange(RTM_GETROUTE, NLM_F_REQUEST, &body, &attrs, false);
        self.finish_route(generation, exchanged)
    }

    fn finish_route(
        &mut self,
        generation: u64,
        exchanged: io::Result<Option<SelectedRoute>>,
    ) -> io::Result<SelectedRoute> {
        let resolved = match exchanged {
            Ok(result) => result,
            Err(error) => return self.fail(error),
        };
        if !self.current(generation)? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        match resolved {
            Some(result) => Ok(result),
            None => self.fail(invalid("route query returned no route")),
        }
    }

    fn use_neighbor(&mut self, index: u32, ip: IpAddr) -> io::Result<()> {
        let mut body = [0; 12];
        body[0] = family(ip);
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        body[10] = 1; // NTF_USE: let ARP/ND resolve, never invent a MAC.
        if let Err(error) = self.exchange(
            RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
            &body,
            &[(NDA_DST, ip_attr(ip))],
            false,
        ) {
            return self.fail(error);
        }
        self.invalidate()
    }

    fn receive_datagram(&mut self, nonblocking: bool) -> io::Result<Option<(usize, u32)>> {
        let flags = MsgFlags::MSG_PEEK
            | MsgFlags::MSG_TRUNC
            | if nonblocking {
                MsgFlags::MSG_DONTWAIT
            } else {
                MsgFlags::empty()
            };
        let needed = match recv(self.socket.fd.as_raw_fd(), &mut [0; 1], flags) {
            Ok(n) => n,
            Err(nix::errno::Errno::EAGAIN) if nonblocking => return Ok(None),
            Err(nix::errno::Errno::EAGAIN) => return Err(io::ErrorKind::TimedOut.into()),
            Err(error) => return Err(error.into()),
        };
        if needed == 0 || needed > self.receive.len() {
            return Err(invalid("FIB datagram truncated/oversize"));
        }
        // SAFETY: zero initializes the receive-only address and msghdr; all supplied
        // pointers refer to live, writable buffers for this synchronous recvmsg.
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut control = [0usize; 8];
        let mut vector = libc::iovec {
            iov_base: self.receive.as_mut_ptr().cast(),
            iov_len: self.receive.len(),
        };
        message.msg_name = (&mut source as *mut libc::sockaddr_nl).cast();
        message.msg_namelen = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        // SAFETY: the initialized msghdr borrows the buffers above only for this call.
        let received = unsafe {
            libc::recvmsg(
                self.socket.fd.as_raw_fd(),
                &mut message,
                if nonblocking { libc::MSG_DONTWAIT } else { 0 },
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            return Err(
                if !nonblocking && error.kind() == io::ErrorKind::WouldBlock {
                    io::ErrorKind::TimedOut.into()
                } else {
                    error
                },
            );
        }
        Ok(Some((
            received as usize,
            datagram_group(needed, received as usize, &source, &message, &control)?,
        )))
    }

    fn exchange(
        &mut self,
        kind: u16,
        flags: u16,
        body: &[u8],
        attrs: &[(u16, Attr)],
        dump: bool,
    ) -> io::Result<Option<SelectedRoute>> {
        self.socket.seq = self
            .socket
            .seq
            .checked_add(1)
            .ok_or_else(|| invalid("netlink sequence exhausted"))?;
        let sequence = self.socket.seq;
        let mut request = Vec::with_capacity(256);
        request.extend_from_slice(&[0; 4]);
        request.extend_from_slice(&kind.to_ne_bytes());
        request.extend_from_slice(&flags.to_ne_bytes());
        request.extend_from_slice(&sequence.to_ne_bytes());
        request.extend_from_slice(&0u32.to_ne_bytes());
        request.extend_from_slice(body);
        for (kind, attr) in attrs {
            put_attr(&mut request, *kind, attr);
        }
        let len = request.len() as u32;
        request[..4].copy_from_slice(&len.to_ne_bytes());
        self.socket.send_datagram(&request)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut exchange = Exchange {
            request: &request,
            body_len: body.len(),
            dump,
            messages: 0,
            complete: false,
            error: None,
            route: None,
        };
        while !exchange.complete {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let (n, group) = self
                .receive_datagram(false)?
                .ok_or_else(|| invalid("missing netlink datagram"))?;
            self.exchange_datagram(n, group, &mut exchange)?;
        }
        exchange.finish()
    }

    fn exchange_datagram(
        &mut self,
        n: usize,
        group: u32,
        exchange: &mut Exchange<'_>,
    ) -> io::Result<()> {
        let (_, kind, _, sequence) = header(exchange.request)?;
        let mut at = 0;
        while at < n {
            exchange.messages += 1;
            if exchange.messages > MAX_DUMP_MESSAGES {
                return Err(invalid("FIB dump limit exceeded"));
            }
            let (length, response, response_flags, response_sequence) =
                header(&self.receive[at..n])?;
            if response_flags & NLM_F_DUMP_INTR != 0 {
                return Err(invalid("FIB dump interrupted"));
            }
            if multicast_notification(group, response)? {
                self.notified(response)?;
            } else if response_sequence != sequence || exchange.complete {
                return Err(invalid("late or mismatched FIB reply"));
            } else {
                let payload = &self.receive[at + 16..at + length];
                match response {
                    2 | 3 => {
                        let error = completion_error(
                            response,
                            response_flags,
                            payload,
                            exchange.request,
                            exchange.dump,
                        )?;
                        if error != 0 {
                            if kind == RTM_GETROUTE
                                && !exchange.dump
                                && matches!(
                                    error,
                                    libc::EINVAL
                                        | libc::ENETUNREACH
                                        | libc::EHOSTUNREACH
                                        | libc::EACCES
                                )
                            {
                                exchange.route = Some(SelectedRoute::Unavailable(error));
                            } else {
                                exchange.error = Some(io::Error::from_raw_os_error(error));
                            }
                        }
                        // Consume the remaining headers even after an error; malformed
                        // trailing data must not hide invalidations behind a route miss.
                        exchange.complete = true;
                    }
                    RTM_NEWLINK if exchange.dump && kind == RTM_GETLINK => {
                        if self.links.len() == MAX_LINKS {
                            return Err(invalid("FIB link bound exceeded"));
                        }
                        self.links.push(parse_link(payload)?);
                    }
                    RTM_NEWADDR if exchange.dump && kind == RTM_GETADDR => {
                        if let Some(address) = parse_address(payload)? {
                            if self.addresses.len() == MAX_ADDRESSES {
                                return Err(invalid("FIB address bound exceeded"));
                            }
                            self.addresses.push(address);
                        }
                    }
                    RTM_NEWNEIGH if exchange.dump && kind == RTM_GETNEIGH => {
                        if let Some(neighbor) = parse_neighbor(payload)? {
                            if self.neighbors.len() == MAX_NEIGHBORS {
                                return Err(invalid("FIB neighbor bound exceeded"));
                            }
                            self.neighbors.push(neighbor);
                        }
                    }
                    80 if exchange.dump && kind == 82 => {
                        if self.forwarding.len() == 2 * (MAX_LINKS + 2) {
                            return Err(invalid("FIB netconf bound exceeded"));
                        }
                        self.forwarding.push(parse_forwarding(payload)?);
                    }
                    RTM_NEWROUTE if !exchange.dump && kind == RTM_GETROUTE => {
                        exchange.route = Some(SelectedRoute::Found(parse_route(payload)?));
                        exchange.complete = true;
                    }
                    RTM_NEWROUTE | RTM_NEWRULE | 104 if exchange.dump => {
                        let expected = match kind {
                            RTM_GETROUTE => RTM_NEWROUTE,
                            RTM_GETRULE => RTM_NEWRULE,
                            RTM_GETNEXTHOP => 104,
                            _ => 0,
                        };
                        if response != expected || payload.len() < exchange.body_len {
                            return Err(invalid("unexpected FIB dump data"));
                        }
                        attributes(&payload[exchange.body_len..], |_, _| Ok(()))?;
                    }
                    _ => return Err(invalid("unsupported FIB response")),
                }
            }
            at += align(length);
        }
        Ok(())
    }
}

struct Exchange<'a> {
    request: &'a [u8],
    body_len: usize,
    dump: bool,
    messages: usize,
    complete: bool,
    error: Option<io::Error>,
    route: Option<SelectedRoute>,
}

impl Exchange<'_> {
    fn finish(self) -> io::Result<Option<SelectedRoute>> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.route),
        }
    }
}

fn multicast_notification(group: u32, kind: u16) -> io::Result<bool> {
    if group == 0 {
        return Ok(false);
    }
    if !FIB_GROUPS.contains(&group) || !notification(kind) {
        return Err(invalid("unexpected FIB multicast message"));
    }
    Ok(true)
}

fn control_align(length: usize) -> Option<usize> {
    let alignment = size_of::<usize>();
    length
        .checked_add(alignment - 1)
        .map(|length| length & !(alignment - 1))
}

fn packet_group(mut bytes: &[u8]) -> io::Result<u32> {
    let header_len = control_align(size_of::<libc::cmsghdr>()).unwrap();
    let mut group = None;
    while !bytes.is_empty() {
        if bytes.len() < header_len {
            return Err(invalid("short FIB control header"));
        }
        // SAFETY: the bounded slice contains a cmsghdr; unaligned reads do not
        // depend on the backing control buffer's alignment.
        let header = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::cmsghdr>()) };
        #[cfg(target_env = "musl")]
        let length = header.cmsg_len as usize;
        #[cfg(not(target_env = "musl"))]
        let length = header.cmsg_len;
        if length < header_len || length > bytes.len() {
            return Err(invalid("invalid FIB control length"));
        }
        if header.cmsg_level != libc::SOL_NETLINK
            || header.cmsg_type != libc::NETLINK_PKTINFO
            || length != header_len + size_of::<u32>()
            || group.is_some()
        {
            return Err(invalid("invalid or duplicate FIB packet info"));
        }
        group = Some(u32_attr(&bytes[header_len..length])?);
        let padded = control_align(length).ok_or_else(|| invalid("FIB control length overflow"))?;
        if padded > bytes.len() {
            if length != bytes.len() {
                return Err(invalid("truncated FIB control padding"));
            }
            bytes = &[];
        } else {
            bytes = &bytes[padded..];
        }
    }
    group.ok_or_else(|| invalid("missing FIB packet info"))
}

fn datagram_group(
    needed: usize,
    received: usize,
    source: &libc::sockaddr_nl,
    message: &libc::msghdr,
    control: &[usize],
) -> io::Result<u32> {
    if received != needed
        || message.msg_namelen as usize != size_of::<libc::sockaddr_nl>()
        || source.nl_family != libc::AF_NETLINK as libc::sa_family_t
        || source.nl_pid != 0
    {
        return Err(invalid("FIB datagram source/length mismatch"));
    }
    #[cfg(target_env = "musl")]
    let control_len = message.msg_controllen as usize;
    #[cfg(not(target_env = "musl"))]
    let control_len = message.msg_controllen;
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || control_len > std::mem::size_of_val(control)
    {
        return Err(invalid("FIB datagram/control truncated"));
    }
    // SAFETY: the length is bounded by the initialized stack control buffer.
    let ancillary =
        unsafe { std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), control_len) };
    packet_group(ancillary)
}

fn completion_error(
    kind: u16,
    flags: u16,
    payload: &[u8],
    request: &[u8],
    dump: bool,
) -> io::Result<i32> {
    if payload.len() < 4 {
        return Err(invalid("short netlink completion"));
    }
    let copied = if kind == 2 {
        let copied = if flags & NLM_F_CAPPED != 0 {
            16
        } else {
            request.len()
        };
        if payload.len() < 4 + copied || payload[4..4 + copied] != request[..copied] {
            return Err(invalid("mismatched netlink error request"));
        }
        copied
    } else if kind == 3 && dump {
        0
    } else {
        return Err(invalid("unexpected netlink completion"));
    };
    if flags & NLM_F_ACK_TLVS != 0 {
        attributes(&payload[4 + copied..], |_, _| Ok(()))?;
    } else if payload.len() != 4 + copied {
        return Err(invalid("unexpected netlink completion data"));
    }
    let error = i32::from_ne_bytes(payload[..4].try_into().unwrap());
    if error > 0 || error == i32::MIN {
        return Err(invalid("invalid netlink errno"));
    }
    if error == 0 && dump && kind != 3 {
        return Err(invalid("unexpected netlink dump ack"));
    }
    Ok(-error)
}

fn parse_forwarding(bytes: &[u8]) -> io::Result<Forwarding> {
    if bytes.len() < 4 {
        return Err(invalid("short netconf reply"));
    }
    let mut index = None;
    let mut enabled = false;
    attributes(&bytes[4..], |kind, data| {
        match kind {
            1 => index = Some(u32_attr(data)?),
            2 => enabled = u32_attr(data)? != 0,
            _ => {}
        }
        Ok(())
    })?;
    Ok(Forwarding {
        index: index.ok_or_else(|| invalid("netconf missing ifindex"))?,
        family: bytes[0],
        enabled,
    })
}

fn notification(kind: u16) -> bool {
    matches!(
        kind,
        16 | 17
            | 20
            | 21
            | 24
            | 25
            | 28
            | 29
            | 32
            | 33
            | 80
            | 81
            | 104
            | 105
            | 108
            | 109
            | 116
            | 117
    )
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn family(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        AF_INET as u8
    } else {
        AF_INET6 as u8
    }
}
fn ip_attr(ip: IpAddr) -> Attr {
    Attr::Bytes(match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    })
}
fn u32_attr(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .try_into()
            .map_err(|_| invalid("invalid u32 attribute"))?,
    ))
}
fn ip_address(family: u8, bytes: &[u8]) -> io::Result<IpAddr> {
    match family as i32 {
        AF_INET => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| invalid("invalid IPv4 address"))?,
        ))),
        AF_INET6 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| invalid("invalid IPv6 address"))?,
        ))),
        _ => Err(invalid("unsupported address family")),
    }
}

fn header(bytes: &[u8]) -> io::Result<(usize, u16, u16, u32)> {
    if bytes.len() < 16 {
        return Err(invalid("short netlink header"));
    }
    let length = u32_attr(&bytes[..4])? as usize;
    if length < 16 || length > bytes.len() || align(length) > bytes.len() {
        return Err(invalid("truncated netlink message"));
    }
    Ok((
        length,
        u16::from_ne_bytes(bytes[4..6].try_into().unwrap()),
        u16::from_ne_bytes(bytes[6..8].try_into().unwrap()),
        u32_attr(&bytes[8..12])?,
    ))
}

fn attributes<'a>(
    mut bytes: &'a [u8],
    mut visit: impl FnMut(u16, &'a [u8]) -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid("short route attribute"));
        }
        let length = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap()) & 0x3fff;
        if length < 4 || length > bytes.len() || align(length) > bytes.len() {
            return Err(invalid("truncated route attribute"));
        }
        visit(kind, &bytes[4..length])?;
        bytes = &bytes[align(length)..];
    }
    Ok(())
}

struct Lookup {
    kind: u8,
    unsupported: bool,
    ifindex: u32,
    gateway: Option<IpAddr>,
    mtu: Option<u32>,
    preferred_source: Option<IpAddr>,
}
enum SelectedRoute {
    Found(Lookup),
    Unavailable(i32),
}
fn parse_route(bytes: &[u8]) -> io::Result<Lookup> {
    if bytes.len() < 12 {
        return Err(invalid("short route reply"));
    }
    let mut route = Lookup {
        kind: bytes[7],
        unsupported: false,
        ifindex: 0,
        gateway: None,
        mtu: None,
        preferred_source: None,
    };
    let mut seen = 0u64;
    attributes(&bytes[12..], |kind, data| {
        if kind < 64 {
            let bit = 1u64 << kind;
            if seen & bit != 0 {
                // IPv6 rt6_fill_node can emit the selected source and fib6_prefsrc.
                if kind == 7 && route.preferred_source == Some(ip_address(bytes[0], data)?) {
                    return Ok(());
                }
                return Err(invalid("duplicate route attribute"));
            }
            seen |= bit;
        }
        match kind {
            RTA_OIF => route.ifindex = u32_attr(data)?,
            RTA_GATEWAY => route.gateway = Some(ip_address(bytes[0], data)?),
            7 => route.preferred_source = Some(ip_address(bytes[0], data)?),
            8 => attributes(data, |metric, data| {
                if metric == 2 {
                    if route.mtu.is_some() {
                        return Err(invalid("duplicate route MTU"));
                    }
                    route.mtu = Some(u32_attr(data)?);
                }
                Ok(())
            })?,
            // These are result metadata; the kernel has already executed RPDB selection.
            1 | 2 | 3 | 6 | 11 | 12 | 15 | 16 | 20 | 23 | 24 | 25 | 27 | 28 | 29 | 30 => {}
            _ => route.unsupported = true,
        }
        Ok(())
    })?;
    Ok(route)
}

fn parse_link(bytes: &[u8]) -> io::Result<Link> {
    if bytes.len() < 16 {
        return Err(invalid("short link reply"));
    }
    let flags = u32_attr(&bytes[8..12])?;
    let mut link = Link {
        index: u32_attr(&bytes[4..8])?,
        mtu: 0,
        mac: [0; 6],
        parent: 0,
        vlan: None,
        usable: u16::from_ne_bytes(bytes[2..4].try_into().unwrap()) == ARPHRD_ETHER
            && flags & IFF_UP != 0
            && flags & 8 == 0,
    };
    let mut info = None;
    let mut cross_namespace = false;
    attributes(&bytes[16..], |kind, data| {
        match kind {
            IFLA_ADDRESS if data.len() == 6 => link.mac.copy_from_slice(data),
            4 => link.mtu = u32_attr(data)?,
            5 => link.parent = u32_attr(data)?,
            10 if u32_attr(data)? != 0 => link.usable = false,
            IFLA_LINKINFO => info = Some(data),
            37 => {
                u32_attr(data)?;
                cross_namespace = true;
            }
            _ => {}
        }
        Ok(())
    })?;
    let mut kind = None;
    let mut data = None;
    if let Some(info) = info {
        attributes(info, |attribute, bytes| {
            match attribute {
                IFLA_INFO_KIND => kind = Some(bytes),
                2 => data = Some(bytes),
                _ => {}
            }
            Ok(())
        })?;
    }
    match kind {
        Some(b"vlan\0") => {
            let mut id = None;
            let mut protocol = 0x8100;
            if let Some(data) = data {
                attributes(data, |kind, bytes| {
                    match kind {
                        1 if bytes.len() == 2 => {
                            id = Some(u16::from_ne_bytes(bytes.try_into().unwrap()))
                        }
                        5 if bytes.len() == 2 => {
                            protocol = u16::from_be_bytes(bytes.try_into().unwrap())
                        }
                        2 if bytes.len() == 8 => {
                            if u32_attr(&bytes[..4])? & !1 != 0 {
                                link.usable = false;
                            }
                        }
                        3 | 4 => attributes(bytes, |_, mapping| {
                            if mapping.len() != 8 {
                                return Err(invalid("invalid VLAN QoS mapping"));
                            }
                            if u32_attr(&mapping[4..])? != 0 {
                                link.usable = false;
                            }
                            Ok(())
                        })?,
                        _ => return Err(invalid("unsupported VLAN link attribute")),
                    }
                    Ok(())
                })?;
            }
            link.vlan = id
                .filter(|id| *id < 4095 && matches!(protocol, 0x8100 | 0x88a8))
                .map(|id| (protocol, id));
            link.usable &= link.vlan.is_some() && link.parent != 0 && !cross_namespace;
        }
        Some(b"veth\0") => link.parent = 0,
        None => {
            link.usable &= link.parent == 0 || link.parent == link.index;
            link.parent = 0;
        }
        _ => link.usable = false,
    }
    link.usable &= link.mtu >= 68 && link.mac != [0; 6] && link.mac[0] & 1 == 0;
    Ok(link)
}

fn logical_link(links: &[Link], index: u32) -> Option<LogicalLink> {
    let original = links
        .iter()
        .find(|link| link.index == index && link.usable)?;
    let mut current = original;
    let mut path = LinkPath::untagged(index);
    let mut mtu = original.mtu;
    while let Some((protocol, id)) = current.vlan {
        if path.vlan_count == 2 {
            return None;
        }
        path.vlan_proto[1] = path.vlan_proto[0];
        path.vlan_tci[1] = path.vlan_tci[0];
        path.vlan_proto[0] = protocol;
        path.vlan_tci[0] = id;
        path.vlan_count += 1;
        current = links
            .iter()
            .find(|link| link.index == current.parent && link.usable)?;
        mtu = mtu.min(current.mtu);
    }
    path.physical_ifindex = current.index;
    Some(LogicalLink {
        ifindex: index,
        mtu,
        mac: original.mac,
        path,
    })
}

fn parse_neighbor(bytes: &[u8]) -> io::Result<Option<Neighbor>> {
    if bytes.len() < 12 {
        return Err(invalid("short neighbor reply"));
    }
    if !matches!(bytes[0] as i32, AF_INET | AF_INET6) {
        return Ok(None);
    }
    let mut ip = None;
    let mut mac = [0; 6];
    attributes(&bytes[12..], |kind, data| {
        match kind {
            NDA_DST => ip = Some(ip_address(bytes[0], data)?),
            NDA_LLADDR if data.len() == 6 => mac.copy_from_slice(data),
            _ => {}
        }
        Ok(())
    })?;
    let state = u16::from_ne_bytes(bytes[8..10].try_into().unwrap());
    // STALE must pass through NTF_USE once so native ARP/ND enters DELAY/PROBE;
    // userspace TX itself never updates the kernel neighbor state machine.
    Ok(ip.map(|ip| Neighbor {
        index: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        ip,
        mac,
        usable: state & (2 | 8 | 16 | 64 | 128) != 0
            && bytes[10] & 8 == 0
            && mac != [0; 6]
            && mac[0] & 1 == 0,
    }))
}

fn parse_address(bytes: &[u8]) -> io::Result<Option<Address>> {
    if bytes.len() < 8 {
        return Err(invalid("short address reply"));
    }
    if !matches!(bytes[0] as i32, AF_INET | AF_INET6) {
        return Ok(None);
    }
    let mut ip = None;
    let mut local = None;
    let mut flags = u32::from(bytes[2]);
    attributes(&bytes[8..], |kind, data| {
        match kind {
            IFA_ADDRESS => ip = Some(ip_address(bytes[0], data)?),
            IFA_LOCAL => local = Some(ip_address(bytes[0], data)?),
            8 => flags = u32_attr(data)?,
            _ => {}
        }
        Ok(())
    })?;
    if flags & (8 | 32 | 64) != 0 {
        return Ok(None);
    }
    Ok(local.or(ip).map(|ip| Address {
        index: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        ip,
    }))
}

pub(crate) fn namespace_cookie(fd: std::os::fd::RawFd) -> io::Result<u64> {
    let mut cookie = 0u64;
    let mut length = size_of::<u64>() as libc::socklen_t;
    // SAFETY: getsockopt writes only the supplied live cookie buffer and length.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            71,
            (&mut cookie as *mut u64).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<u64>() || cookie == 0 {
        return Err(invalid("invalid SO_NETNS_COOKIE"));
    }
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_fib() -> Fib {
        let socket = NlSock::new().unwrap();
        let namespace = namespace_cookie(socket.fd.as_raw_fd()).unwrap();
        let mut fib = Fib::new(&MemoryBudget::new(4 << 20), namespace).unwrap();
        fib.state = FibState::Ready;
        fib
    }

    fn message(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = 16 + payload.len();
        let mut bytes = Vec::with_capacity(align(length));
        bytes.extend_from_slice(&(length as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize(align(length), 0);
        bytes
    }

    fn route_request(ipv6: bool, sequence: u32) -> Vec<u8> {
        let mut body = vec![0; 12];
        body[0] = if ipv6 { AF_INET6 as u8 } else { AF_INET as u8 };
        body[1] = if ipv6 { 128 } else { 32 };
        let destination: IpAddr = if ipv6 {
            "2001:db8::2".parse().unwrap()
        } else {
            "198.51.100.2".parse().unwrap()
        };
        put_attr(&mut body, RTA_DST, &ip_attr(destination));
        message(RTM_GETROUTE, NLM_F_REQUEST, sequence, &body)
    }

    fn error_message(request: &[u8], error: i32, capped: bool) -> Vec<u8> {
        let mut payload = (-error).to_ne_bytes().to_vec();
        payload.extend_from_slice(if capped { &request[..16] } else { request });
        message(
            2,
            if capped { NLM_F_CAPPED } else { 0 },
            u32_attr(&request[8..12]).unwrap(),
            &payload,
        )
    }

    fn exchange_state(request: &[u8], body_len: usize, dump: bool) -> Exchange<'_> {
        Exchange {
            request,
            body_len,
            dump,
            messages: 0,
            complete: false,
            error: None,
            route: None,
        }
    }

    fn feed_exchange(
        fib: &mut Fib,
        bytes: &[u8],
        group: u32,
        exchange: &mut Exchange<'_>,
    ) -> io::Result<()> {
        fib.receive[..bytes.len()].copy_from_slice(bytes);
        fib.exchange_datagram(bytes.len(), group, exchange)
    }

    fn query(fib: &Fib, ipv6: bool) -> RouteQuery {
        RouteQuery {
            ingress: honk_datapath::forward::Ingress {
                scope: honk_datapath::ScopeId::HOST,
                namespace: fib.namespace,
                ifindex: 2,
                attachment: 1,
                mark: MarkProvenance::BeforeSkb,
            },
            source: if ipv6 {
                "2001:db8::1".parse().unwrap()
            } else {
                "192.0.2.1".parse().unwrap()
            },
            destination: if ipv6 {
                "2001:db8::2".parse().unwrap()
            } else {
                "198.51.100.2".parse().unwrap()
            },
            traffic_class: 0,
            protocol: 17,
            ports: Some((1234, 4321)),
        }
    }

    fn unicast_reply(ipv6: bool, index: u32) -> Vec<u8> {
        let mut body = vec![0; 12];
        body[0] = if ipv6 { AF_INET6 as u8 } else { AF_INET as u8 };
        body[7] = RTN_UNICAST;
        put_attr(&mut body, RTA_OIF, &Attr::U32(index));
        body
    }

    fn forwarding_fib(ipv6: bool) -> Fib {
        let mut fib = ready_fib();
        fib.links
            .push(parse_link(&link_bytes(9, None, None)).unwrap());
        fib.addresses.push(Address {
            index: 9,
            ip: query(&fib, ipv6).source,
        });
        fib.neighbors.push(Neighbor {
            index: 9,
            ip: query(&fib, ipv6).destination,
            mac: [4; 6],
            usable: true,
        });
        fib
    }

    fn route(fib: &Fib, query: RouteQuery) -> Route {
        Route {
            generation: fib.generation,
            ifindex: 9,
            l2: LinkPath::untagged(9),
            mtu: 1500,
            next_hop: query.destination,
            preferred_source: None,
            source_mac: [2; 6],
            destination_mac: [4; 6],
        }
    }

    fn control_message(group: u32, length: usize, level: i32, kind: i32) -> Vec<u8> {
        let header_len = control_align(size_of::<libc::cmsghdr>()).unwrap();
        let mut bytes = vec![0; control_align(header_len + 4).unwrap()];
        // SAFETY: zero initializes native ABI padding before the header is serialized.
        let mut header: libc::cmsghdr = unsafe { std::mem::zeroed() };
        header.cmsg_len = length as _;
        header.cmsg_level = level;
        header.cmsg_type = kind;
        // SAFETY: the allocated buffer contains an entire native cmsghdr.
        unsafe {
            std::ptr::write_unaligned(bytes.as_mut_ptr().cast::<libc::cmsghdr>(), header);
        }
        bytes[header_len..header_len + 4].copy_from_slice(&group.to_ne_bytes());
        bytes
    }

    fn packet_info(group: u32) -> Vec<u8> {
        control_message(
            group,
            control_align(size_of::<libc::cmsghdr>()).unwrap() + 4,
            libc::SOL_NETLINK,
            libc::NETLINK_PKTINFO,
        )
    }

    #[test]
    fn unresolved_neighbor_retains_route_authority_without_starting_resolution() {
        for ipv6 in [false, true] {
            let mut fib = forwarding_fib(ipv6);
            fib.neighbors.clear();
            let query = query(&fib, ipv6);
            let generation = fib.generation;
            let mut body = unicast_reply(ipv6, 9);
            let mut metrics = Vec::new();
            put_attr(&mut metrics, 2, &Attr::U32(1500));
            put_attr(&mut body, 8, &Attr::Bytes(metrics));
            let selected = SelectedRoute::Found(parse_route(&body).unwrap());
            let Resolution::NeighborPending(route) = fib.resolve(query, selected).unwrap() else {
                panic!("route metadata must survive missing neighbor");
            };
            assert_eq!(route.mtu, 1500);
            assert_eq!(route.ifindex, 9);
            assert_eq!(route.next_hop, query.destination);
            assert_eq!(route.destination_mac, [0; 6]);
            assert_eq!(fib.state, FibState::Ready);
            assert_eq!(fib.generation, generation);
        }
    }

    #[test]
    fn unavailable_egress_refuses_only_the_matching_packet() {
        for ipv6 in [false, true] {
            let mut fib = forwarding_fib(ipv6);
            let query = query(&fib, ipv6);
            let generation = fib.generation;
            let mut unusable = parse_link(&link_bytes(11, None, None)).unwrap();
            unusable.usable = false;
            fib.links.push(unusable);
            for index in [0, 10, 11] {
                let selected =
                    SelectedRoute::Found(parse_route(&unicast_reply(ipv6, index)).unwrap());
                assert!(matches!(
                    fib.resolve(query, selected).unwrap(),
                    Resolution::Drop
                ));
                assert_eq!(fib.state, FibState::Ready);
                assert_eq!(fib.generation, generation);
            }
            let selected = SelectedRoute::Found(parse_route(&unicast_reply(ipv6, 9)).unwrap());
            assert!(matches!(
                fib.resolve(query, selected).unwrap(),
                Resolution::Forward(_)
            ));
        }
    }

    #[test]
    fn unsupported_routes_do_not_desynchronize_dumps_notifications_or_lookups() {
        let mut multipath = 8u16.to_ne_bytes().to_vec();
        multipath.extend_from_slice(&[0, 0]);
        multipath.extend_from_slice(&9u32.to_ne_bytes());
        let mut encap = Vec::new();
        put_attr(
            &mut encap,
            1,
            &Attr::Bytes(0x00010140u32.to_be_bytes().to_vec()),
        );
        let mut via = (AF_INET as u16).to_ne_bytes().to_vec();
        via.extend_from_slice(&[192, 0, 2, 9]);
        for ipv6 in [false, true] {
            for attrs in [
                vec![(9, Attr::Bytes(multipath.clone()))],
                vec![
                    (21, Attr::Bytes(1u16.to_ne_bytes().to_vec())),
                    (22, Attr::Bytes(encap.clone())),
                ],
                vec![(18, Attr::Bytes(via.clone()))],
            ] {
                let mut fib = forwarding_fib(ipv6);
                let query = query(&fib, ipv6);
                let route = route(&fib, query);
                let mut body = unicast_reply(ipv6, 9);
                put_attr(&mut body, 7, &ip_attr(query.source));
                for (kind, attr) in attrs {
                    put_attr(&mut body, kind, &attr);
                }
                let reply = message(RTM_NEWROUTE, 0, 41, &body);
                let mut request = route_request(ipv6, 41);
                request[6..8].copy_from_slice(&(NLM_F_REQUEST | 0x300).to_ne_bytes());
                let mut dump = exchange_state(&request, 12, true);
                feed_exchange(&mut fib, &reply, 0, &mut dump).unwrap();
                feed_exchange(
                    &mut fib,
                    &message(3, 2, 41, &0i32.to_ne_bytes()),
                    0,
                    &mut dump,
                )
                .unwrap();
                assert!(dump.complete);
                assert!(dump.finish().unwrap().is_none());
                assert_eq!(fib.state, FibState::Ready);

                request[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
                let mut exchange = exchange_state(&request, 12, false);
                feed_exchange(&mut fib, &reply, 0, &mut exchange).unwrap();
                let selected = fib
                    .finish_route(route.generation, exchange.finish())
                    .unwrap();
                assert_eq!(fib.masquerade_selection(route, query, selected), None);
                let mut exchange = exchange_state(&request, 12, false);
                feed_exchange(&mut fib, &reply, 0, &mut exchange).unwrap();
                let selected = fib
                    .finish_route(route.generation, exchange.finish())
                    .unwrap();
                assert!(matches!(
                    fib.resolve(query, selected).unwrap(),
                    Resolution::Drop
                ));
                assert_eq!(fib.state, FibState::Ready);
                assert_eq!(fib.generation, route.generation);

                let mut exchange = exchange_state(&request, 12, false);
                feed_exchange(
                    &mut fib,
                    &message(RTM_NEWROUTE, 0, 41, &unicast_reply(ipv6, 9)),
                    0,
                    &mut exchange,
                )
                .unwrap();
                let selected = fib
                    .finish_route(route.generation, exchange.finish())
                    .unwrap();
                assert!(matches!(
                    fib.resolve(query, selected).unwrap(),
                    Resolution::Forward(_)
                ));

                fib.receive[..reply.len()].copy_from_slice(&reply);
                fib.drain_datagram(reply.len(), if ipv6 { 11 } else { 7 })
                    .unwrap();
                assert_eq!(fib.state, FibState::Synchronizing);
                assert_eq!(fib.generation, route.generation + 1);
            }
        }
    }

    #[test]
    fn negative_route_completions_are_packet_local_and_masquerade_source_unavailable() {
        for ipv6 in [false, true] {
            for error in [
                libc::EINVAL,
                libc::ENETUNREACH,
                libc::EHOSTUNREACH,
                libc::EACCES,
            ] {
                for capped in [false, true] {
                    let mut fib = ready_fib();
                    let query = query(&fib, ipv6);
                    let route = route(&fib, query);
                    let request = route_request(ipv6, 41);
                    let mut exchange = exchange_state(&request, 12, false);
                    feed_exchange(
                        &mut fib,
                        &error_message(&request, error, capped),
                        0,
                        &mut exchange,
                    )
                    .unwrap();
                    assert!(exchange.complete);
                    let selected = exchange.finish().unwrap().unwrap();
                    assert!(
                        matches!(selected, SelectedRoute::Unavailable(errno) if errno == error)
                    );
                    assert_eq!(fib.masquerade_selection(route, query, selected), None);
                    let mut exchange = exchange_state(&request, 12, false);
                    feed_exchange(
                        &mut fib,
                        &error_message(&request, error, capped),
                        0,
                        &mut exchange,
                    )
                    .unwrap();
                    let resolution = fib
                        .resolve(query, exchange.finish().unwrap().unwrap())
                        .unwrap();
                    match error {
                        libc::EINVAL => assert!(matches!(resolution, Resolution::Drop)),
                        libc::EACCES => assert!(matches!(
                            resolution,
                            Resolution::Error(
                                honk_netstack::transit::TransitError::AdminProhibited
                            )
                        )),
                        _ => assert!(matches!(
                            resolution,
                            Resolution::Error(
                                honk_netstack::transit::TransitError::HostUnreachable
                            )
                        )),
                    }
                    assert_eq!(fib.state, FibState::Ready);
                    assert_eq!(fib.generation, route.generation);
                }
            }
        }
    }

    #[test]
    fn malformed_negative_completions_and_transport_einval_desynchronize() {
        let request = route_request(false, 41);
        let mut wrong_request = request.clone();
        wrong_request[8] ^= 1;
        let mut wrong_error = error_message(&wrong_request, libc::EINVAL, false);
        wrong_error[8..12].copy_from_slice(&41u32.to_ne_bytes());
        let mut wrong_body = request.clone();
        *wrong_body.last_mut().unwrap() ^= 1;
        let mut short_copy = (-libc::EINVAL).to_ne_bytes().to_vec();
        short_copy.extend_from_slice(&request[..16]);
        let mut positive = libc::EINVAL.to_ne_bytes().to_vec();
        positive.extend_from_slice(&request);
        let mut invalid_errno = i32::MIN.to_ne_bytes().to_vec();
        invalid_errno.extend_from_slice(&request);
        for bytes in [
            message(2, 0, 41, &(-libc::EINVAL).to_ne_bytes()),
            wrong_error,
            error_message(&wrong_body, libc::EINVAL, false),
            message(2, 0, 41, &short_copy),
            message(2, 0, 41, &positive),
            message(2, 0, 41, &invalid_errno),
            message(3, 0, 41, &(-libc::EINVAL).to_ne_bytes()),
        ] {
            let mut fib = ready_fib();
            let generation = fib.generation;
            let mut exchange = exchange_state(&request, 12, false);
            let parsed =
                feed_exchange(&mut fib, &bytes, 0, &mut exchange).and_then(|()| exchange.finish());
            assert!(fib.finish_route(generation, parsed).is_err());
            assert_eq!(fib.state, FibState::Desynchronized);
        }
        for (request, dump) in [
            (message(RTM_GETLINK, NLM_F_REQUEST, 41, &[0; 16]), false),
            (request.clone(), true),
        ] {
            let mut fib = ready_fib();
            let mut exchange = exchange_state(&request, 12, dump);
            feed_exchange(
                &mut fib,
                &error_message(&request, libc::EINVAL, false),
                0,
                &mut exchange,
            )
            .unwrap();
            assert_eq!(
                exchange.finish().err().unwrap().raw_os_error(),
                Some(libc::EINVAL)
            );
        }
        let mut fib = ready_fib();
        assert!(
            fib.finish_route(
                fib.generation,
                Err(io::Error::from_raw_os_error(libc::EINVAL))
            )
            .is_err()
        );
        assert_eq!(fib.state, FibState::Desynchronized);
    }

    #[test]
    fn error_completion_with_unicast_notification_tail_fails_closed() {
        let request = route_request(false, 41);
        for sequence in [0, 41, 42] {
            let mut fib = ready_fib();
            let generation = fib.generation;
            let mut bytes = error_message(&request, libc::EINVAL, false);
            bytes.extend_from_slice(&message(RTM_NEWADDR, 0, sequence, &[0; 8]));
            let mut exchange = exchange_state(&request, 12, false);
            let parsed =
                feed_exchange(&mut fib, &bytes, 0, &mut exchange).and_then(|()| exchange.finish());
            assert!(parsed.is_err());
            fib.notified(RTM_NEWADDR).unwrap();
            let error = fib.finish_route(generation, parsed).err().unwrap();
            assert_ne!(error.kind(), io::ErrorKind::WouldBlock);
            assert_eq!(fib.state, FibState::Desynchronized);
        }
    }

    #[test]
    fn multicast_sequence_collision_never_completes_a_route_query() {
        let request = route_request(false, 41);
        let mut body = vec![0; 12];
        body[0] = AF_INET as u8;
        body[7] = RTN_UNICAST;
        put_attr(&mut body, RTA_OIF, &Attr::U32(9));
        let group = packet_group(&packet_info(7)).unwrap();
        for sequence in [0, 41, 42] {
            let bytes = message(RTM_NEWROUTE, 0, sequence, &body);
            let mut fib = ready_fib();
            let generation = fib.generation;
            let address_generation = fib.address_generation;
            fib.receive[..bytes.len()].copy_from_slice(&bytes);
            fib.drain_datagram(bytes.len(), group).unwrap();
            assert_eq!(fib.generation, generation + 1);
            assert_eq!(fib.address_generation, address_generation);
            assert_eq!(fib.state, FibState::Synchronizing);

            let mut fib = ready_fib();
            let generation = fib.generation;
            let query = query(&fib, false);
            let route = route(&fib, query);
            let mut exchange = exchange_state(&request, 12, false);
            feed_exchange(&mut fib, &bytes, group, &mut exchange).unwrap();
            assert!(!exchange.complete);
            assert!(exchange.route.is_none());
            assert_eq!(fib.generation, generation + 1);
            feed_exchange(
                &mut fib,
                &message(RTM_NEWROUTE, 0, 41, &body),
                0,
                &mut exchange,
            )
            .unwrap();
            assert!(exchange.complete);
            assert!(matches!(exchange.route, Some(SelectedRoute::Found(_))));
            assert_eq!(
                fib.finish_route(generation, exchange.finish())
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(
                fib.masquerade_source(route, query).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(fib.state, FibState::Synchronizing);
        }
    }

    #[test]
    fn inherited_multicast_sequence_revokes_addresses_without_becoming_dump_data() {
        let request = message(RTM_GETLINK, NLM_F_REQUEST | 0x300, 41, &[0; 16]);
        let mut fib = ready_fib();
        let generation = fib.generation;
        let address_generation = fib.address_generation;
        let bytes = message(RTM_NEWLINK, 0, 41, &link_bytes(2, None, None));
        let mut exchange = exchange_state(&request, 16, true);
        feed_exchange(
            &mut fib,
            &bytes,
            packet_group(&packet_info(1)).unwrap(),
            &mut exchange,
        )
        .unwrap();
        assert!(!exchange.complete);
        assert!(fib.links.is_empty());
        assert_eq!(fib.address_generation, address_generation + 1);
        assert_eq!(fib.generation, generation + 1);
        let mut unicast = message(RTM_NEWLINK, 2, 41, &link_bytes(2, None, None));
        unicast.extend_from_slice(&message(3, 2, 41, &0i32.to_ne_bytes()));
        feed_exchange(&mut fib, &unicast, 0, &mut exchange).unwrap();
        assert!(exchange.complete);
        assert_eq!(fib.links.len(), 1);
        assert!(exchange.finish().unwrap().is_none());

        let mut address = vec![0; 8];
        address[0] = AF_INET as u8;
        address[1] = 32;
        address[4..8].copy_from_slice(&2u32.to_ne_bytes());
        put_attr(&mut address, 1, &ip_attr("192.0.2.1".parse().unwrap()));
        let bytes = message(RTM_NEWADDR, 0, 99, &address);
        fib.receive[..bytes.len()].copy_from_slice(&bytes);
        fib.drain_datagram(bytes.len(), packet_group(&packet_info(5)).unwrap())
            .unwrap();
        assert_eq!(fib.address_generation, address_generation + 2);
    }

    #[test]
    fn unicast_late_replies_unknown_multicast_and_dump_loss_are_rejected() {
        let request = route_request(false, 41);
        for (group, kind, flags, sequence) in [
            (0, RTM_NEWROUTE, 0, 0),
            (0, RTM_NEWROUTE, 0, 42),
            (64, RTM_NEWROUTE, 0, 41),
            (7, 42, 0, 41),
            (7, RTM_NEWROUTE, NLM_F_DUMP_INTR, 41),
        ] {
            let mut fib = ready_fib();
            let bytes = message(kind, flags, sequence, &[0; 12]);
            fib.receive[..bytes.len()].copy_from_slice(&bytes);
            assert!(fib.drain_datagram(bytes.len(), group).is_err());
            assert!(
                feed_exchange(
                    &mut fib,
                    &bytes,
                    group,
                    &mut exchange_state(&request, 12, false)
                )
                .is_err()
            );
        }
        let mut fib = ready_fib();
        let bytes = message(RTM_NEWROUTE, 0, 41, &[0; 12]);
        fib.receive[..bytes.len()].copy_from_slice(&bytes);
        assert!(fib.drain_datagram(bytes.len(), 0).is_err());
        let mut exchange = exchange_state(&request, 12, false);
        exchange.messages = MAX_DUMP_MESSAGES;
        assert!(feed_exchange(&mut fib, &bytes, 7, &mut exchange).is_err());
        let mut exchange = exchange_state(&request, 12, false);
        exchange.complete = true;
        assert!(feed_exchange(&mut fib, &bytes, 0, &mut exchange).is_err());
    }

    #[test]
    fn packet_info_rejects_malformed_and_duplicate_control_messages() {
        let header_len = control_align(size_of::<libc::cmsghdr>()).unwrap();
        for group in [0, 7, 32] {
            let bytes = packet_info(group);
            assert_eq!(packet_group(&bytes).unwrap(), group);
            assert_eq!(packet_group(&bytes[..header_len + 4]).unwrap(), group);
        }
        let bytes = packet_info(7);
        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes);
        let mut trailing = bytes.clone();
        trailing.push(0);
        for malformed in [
            vec![],
            bytes[..header_len - 1].to_vec(),
            bytes[..header_len + 3].to_vec(),
            bytes[..bytes.len() - 1].to_vec(),
            duplicate,
            trailing,
            control_message(7, header_len - 1, libc::SOL_NETLINK, libc::NETLINK_PKTINFO),
            control_message(7, bytes.len() + 1, libc::SOL_NETLINK, libc::NETLINK_PKTINFO),
            control_message(7, header_len + 3, libc::SOL_NETLINK, libc::NETLINK_PKTINFO),
            control_message(7, header_len + 4, libc::SOL_SOCKET, libc::NETLINK_PKTINFO),
            control_message(
                7,
                header_len + 4,
                libc::SOL_NETLINK,
                libc::NETLINK_PKTINFO + 1,
            ),
        ] {
            assert!(packet_group(&malformed).is_err());
        }
    }

    #[test]
    fn received_metadata_rejects_non_kernel_senders_lengths_and_truncation() {
        let info = packet_info(7);
        let mut control = [0usize; 8];
        // SAFETY: the byte slice covers exactly the initialized stack control buffer.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                control.as_mut_ptr().cast::<u8>(),
                std::mem::size_of_val(&control),
            )
        };
        bytes[..info.len()].copy_from_slice(&info);
        // SAFETY: these are initialized receive metadata with no dereferenced pointers.
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        source.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        message.msg_namelen = size_of::<libc::sockaddr_nl>() as _;
        message.msg_controllen = info.len() as _;
        assert_eq!(
            datagram_group(32, 32, &source, &message, &control).unwrap(),
            7
        );
        assert!(datagram_group(32, 31, &source, &message, &control).is_err());
        source.nl_pid = 12;
        assert!(datagram_group(32, 32, &source, &message, &control).is_err());
        source.nl_pid = 0;
        source.nl_family = libc::AF_UNIX as _;
        assert!(datagram_group(32, 32, &source, &message, &control).is_err());
        source.nl_family = libc::AF_NETLINK as _;
        message.msg_namelen -= 1;
        assert!(datagram_group(32, 32, &source, &message, &control).is_err());
        message.msg_namelen += 1;
        for flags in [libc::MSG_TRUNC, libc::MSG_CTRUNC] {
            message.msg_flags = flags;
            assert!(datagram_group(32, 32, &source, &message, &control).is_err());
        }
        message.msg_flags = 0;
        message.msg_controllen = (std::mem::size_of_val(&control) + 1) as _;
        assert!(datagram_group(32, 32, &source, &message, &control).is_err());
    }

    #[test]
    fn native_receive_supplies_kernel_unicast_packet_info() {
        let mut fib = ready_fib();
        let mut body = [0; 16];
        body[4..8].copy_from_slice(&1u32.to_ne_bytes());
        fib.socket
            .send_datagram(&message(RTM_GETLINK, NLM_F_REQUEST, 41, &body))
            .unwrap();
        for _ in 0..64 {
            let (length, group) = fib.receive_datagram(false).unwrap().unwrap();
            if group == 0 {
                assert_eq!(header(&fib.receive[..length]).unwrap().3, 41);
                return;
            }
            fib.drain_datagram(length, group).unwrap();
        }
        panic!("kernel unicast reply exceeded the notification receive bound");
    }

    #[test]
    fn duplicate_ipv6_preferred_source_must_agree_and_execution_attributes_stay_unique() {
        let source: IpAddr = "2001:db8::1".parse().unwrap();
        let mut route = vec![0; 12];
        route[0] = AF_INET6 as u8;
        route[7] = RTN_UNICAST;
        put_attr(&mut route, RTA_OIF, &Attr::U32(9));
        put_attr(&mut route, 7, &ip_attr(source));
        let mut identical = route.clone();
        put_attr(&mut identical, 7, &ip_attr(source));
        assert_eq!(
            parse_route(&identical).unwrap().preferred_source,
            Some(source)
        );
        let mut conflicting = route.clone();
        put_attr(
            &mut conflicting,
            7,
            &ip_attr("2001:db8::2".parse().unwrap()),
        );
        assert!(parse_route(&conflicting).is_err());
        let mut malformed = route.clone();
        put_attr(&mut malformed, 7, &Attr::Bytes(vec![0; 4]));
        assert!(parse_route(&malformed).is_err());
        let mut metric = Vec::new();
        put_attr(&mut metric, 2, &Attr::U32(1280));
        for (kind, attr) in [
            (RTA_OIF, Attr::U32(9)),
            (RTA_GATEWAY, ip_attr(source)),
            (8, Attr::Bytes(metric.clone())),
        ] {
            let mut duplicate = vec![0; 12];
            duplicate[0] = AF_INET6 as u8;
            duplicate[7] = RTN_UNICAST;
            put_attr(&mut duplicate, kind, &attr);
            put_attr(&mut duplicate, kind, &attr);
            assert!(parse_route(&duplicate).is_err());
        }
        put_attr(&mut metric, 2, &Attr::U32(1280));
        put_attr(&mut route, 8, &Attr::Bytes(metric));
        assert!(parse_route(&route).is_err());
    }
    #[test]
    fn malformed_route_framing_fails_closed() {
        let mut route = vec![0; 12];
        route[0] = AF_INET as u8;
        route[7] = RTN_UNICAST;
        put_attr(&mut route, RTA_OIF, &Attr::U32(9));
        assert_eq!(parse_route(&route).unwrap().ifindex, 9);
        put_attr(&mut route, 22, &Attr::Bytes(Vec::new()));
        route.extend_from_slice(&[8, 0, 4, 0, 1]);
        assert!(parse_route(&route).is_err());
        assert!(attributes(&[8, 0, 4, 0, 1], |_, _| Ok(())).is_err());
        assert!(header(&[0; 16]).is_err());
    }

    fn link_bytes(index: u32, parent: Option<u32>, vlan: Option<(u16, u16)>) -> Vec<u8> {
        let mut bytes = vec![0; 16];
        bytes[2..4].copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
        bytes[4..8].copy_from_slice(&index.to_ne_bytes());
        bytes[8..12].copy_from_slice(&IFF_UP.to_ne_bytes());
        put_attr(&mut bytes, 4, &Attr::U32(9000));
        put_attr(
            &mut bytes,
            IFLA_ADDRESS,
            &Attr::Bytes(vec![2, 0, 0, 0, 0, index as u8]),
        );
        if let Some(parent) = parent {
            put_attr(&mut bytes, 5, &Attr::U32(parent));
        }
        if let Some((protocol, id)) = vlan {
            let mut data = Vec::new();
            put_attr(&mut data, 1, &Attr::Bytes(id.to_ne_bytes().to_vec()));
            put_attr(&mut data, 5, &Attr::Bytes(protocol.to_be_bytes().to_vec()));
            let mut info = Vec::new();
            put_attr(&mut info, IFLA_INFO_KIND, &Attr::Bytes(b"vlan\0".to_vec()));
            put_attr(&mut info, 2, &Attr::Bytes(data));
            put_attr(&mut bytes, IFLA_LINKINFO, &Attr::Bytes(info));
        }
        bytes
    }

    #[test]
    fn vlan_resolution_preserves_logical_identity_and_outer_to_inner_tags() {
        let mut links = vec![
            parse_link(&link_bytes(2, None, None)).unwrap(),
            parse_link(&link_bytes(3, Some(2), Some((0x88a8, 123)))).unwrap(),
            parse_link(&link_bytes(4, Some(3), Some((0x8100, 456)))).unwrap(),
        ];
        links[1].mtu = 1500;
        let selected = logical_link(&links, 4).unwrap();
        assert_eq!(
            (
                selected.ifindex,
                selected.path.physical_ifindex,
                selected.mtu,
                selected.mac
            ),
            (4, 2, 1500, links[2].mac)
        );
        assert_eq!(selected.path.vlan_proto, [0x88a8, 0x8100]);
        assert_eq!(selected.path.vlan_tci, [123, 456]);
        let header = selected.path.header(selected.mac, [2; 6], false).unwrap();
        assert_eq!(&header[12..], &[0x88, 0xa8, 0, 123, 0x81, 0, 1, 200, 8, 0]);
        links.push(parse_link(&link_bytes(5, Some(4), Some((0x8100, 9)))).unwrap());
        assert!(logical_link(&links, 5).is_none());
        links[0].usable = false;
        assert!(logical_link(&links, 4).is_none());
    }

    #[test]
    fn route_and_neighbor_refresh_do_not_revoke_masquerade_address_identity() {
        let socket = NlSock::new().unwrap();
        let namespace = namespace_cookie(socket.fd.as_raw_fd()).unwrap();
        let mut fib = Fib::new(&MemoryBudget::new(4 << 20), namespace).unwrap();
        let address = fib.address_generation();
        let route = fib.generation();
        for kind in [RTM_NEWROUTE, RTM_NEWRULE, RTM_NEWNEIGH] {
            fib.notified(kind).unwrap();
        }
        fib.invalidate().unwrap();
        assert!(fib.generation() > route);
        assert_eq!(fib.address_generation(), address);
        fib.notified(RTM_NEWADDR).unwrap();
        assert_eq!(fib.address_generation(), address + 1);
        fib.notified(RTM_DELLINK).unwrap();
        assert_eq!(fib.address_generation(), address + 2);
    }
}
