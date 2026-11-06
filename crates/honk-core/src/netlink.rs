//! Minimal synchronous rtnetlink client (NETLINK_ROUTE).
//!
//! Replaces the engine's `ip`/`nsenter` shell-outs: netkit/veth pair creation,
//! link up/down/netns-move, v4/v6 addresses, routes (incl. table 100 +
//! RTN_LOCAL), fwmark rules, and static neighbours. Message headers use
//! the stable kernel ABI layouts directly (the musl libc crate does not
//! export all of them); each request waits for the kernel's
//! NLMSG_ERROR ack.
//!
//! Netlink sockets are namespace-bound at creation: a socket opened
//! inside a scoped `setns` operates on that namespace, which is how the
//! daens-internal setup works without `nsenter`.

use std::io;
#[cfg(feature = "ebpf")]
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};

#[cfg(feature = "ebpf")]
use nix::sys::socket::recvfrom;
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, send,
    setsockopt, socket, sockopt,
};
use nix::sys::time::TimeVal;

pub(crate) mod fib;
#[cfg(feature = "ebpf")]
mod netns_id;

#[cfg(feature = "ebpf")]
pub(crate) fn ipv6_socket_available() -> std::io::Result<bool> {
    match socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    ) {
        Ok(_) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::EAFNOSUPPORT) => Ok(false),
        Err(error) => Err(error),
    }
}

// ---- kernel ABI (stable) --------------------------------------------------

const AF_INET: i32 = libc::AF_INET;
const AF_INET6: i32 = libc::AF_INET6;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
#[cfg(feature = "ebpf")]
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
#[cfg(feature = "ebpf")]
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_DUMP_INTR: u16 = 0x10;
#[cfg(feature = "ebpf")]
const NLM_F_DUMP: u16 = 0x300;

#[cfg(feature = "ebpf")]
const NLMSG_ERROR: u16 = 2;
#[cfg(feature = "ebpf")]
const NLMSG_DONE: u16 = 3;

pub(crate) const RTM_NEWLINK: u16 = 16;
#[cfg(feature = "ebpf")]
const RTM_GETLINK: u16 = 18;
pub(crate) const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
#[cfg(feature = "ebpf")]
const RTM_DELRULE: u16 = 33;
const RTM_NEWRULE: u16 = 32;
const RTM_NEWNEIGH: u16 = 28;

const ARPHRD_ETHER: u16 = 1;
const IFF_UP: u32 = 0x1;

const IFLA_ADDRESS: u16 = 1;
#[cfg(feature = "ebpf")]
const IFLA_IFNAME: u16 = 3;
#[cfg(feature = "ebpf")]
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
#[cfg(feature = "ebpf")]
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_INFO_KIND: u16 = 1;
#[cfg(feature = "ebpf")]
const IFLA_INFO_DATA: u16 = 2;
#[cfg(feature = "ebpf")]
const VETH_INFO_PEER: u16 = 1;
#[cfg(feature = "ebpf")]
const IFLA_NETKIT_PEER_INFO: u16 = 1;
#[cfg(feature = "ebpf")]
const IFLA_NETKIT_MODE: u16 = 5;
#[cfg(feature = "ebpf")]
const NETKIT_L2: u32 = 0;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const RTA_DST: u16 = 1;
const RTA_GATEWAY: u16 = 5;
const RTA_OIF: u16 = 4;
#[cfg(feature = "ebpf")]
const RTA_TABLE: u16 = 15;

const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;

#[cfg(feature = "ebpf")]
const FRA_FWMARK: u16 = 10;
#[cfg(feature = "ebpf")]
const FRA_TABLE: u16 = 15;
#[cfg(feature = "ebpf")]
const FRA_FWMASK: u16 = 16;

#[cfg(feature = "ebpf")]
const NUD_PERMANENT: u16 = 0x80;
const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;
#[cfg(feature = "ebpf")]
const RTPROT_STATIC: u8 = 4;
#[cfg(feature = "ebpf")]
const RT_SCOPE_LINK: u8 = 253;
#[cfg(feature = "ebpf")]
const RT_SCOPE_UNIVERSE: u8 = 0;
#[cfg(feature = "ebpf")]
const RT_SCOPE_HOST: u8 = 254;
#[cfg(feature = "ebpf")]
const FR_ACT_TO_TBL: u8 = 1;

#[cfg(feature = "ebpf")]
#[repr(C)]
#[derive(Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[cfg(feature = "ebpf")]
#[repr(C)]
#[derive(Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[cfg(feature = "ebpf")]
#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[cfg(feature = "ebpf")]
#[repr(C)]
#[derive(Clone, Copy)]
struct NdMsg {
    ndm_family: u8,
    ndm_pad1: u8,
    ndm_pad2: u16,
    ndm_ifindex: i32,
    ndm_state: u16,
    ndm_flags: u8,
    ndm_type: u8,
}

const NLMSG_ALIGNTO: usize = 4;

fn align(len: usize) -> usize {
    len.div_ceil(NLMSG_ALIGNTO) * NLMSG_ALIGNTO
}

#[derive(Clone, Debug)]
enum Attr {
    U32(u32),
    Bytes(Vec<u8>),
    #[cfg(feature = "ebpf")]
    Str(String),
    #[cfg(feature = "ebpf")]
    Nested(Vec<(u16, Attr)>),
}

fn attr_payload(attr: &Attr, out: &mut Vec<u8>) {
    match attr {
        Attr::U32(v) => out.extend_from_slice(&v.to_ne_bytes()),
        Attr::Bytes(b) => out.extend_from_slice(b),
        #[cfg(feature = "ebpf")]
        Attr::Str(s) => {
            out.extend_from_slice(s.as_bytes());
            out.push(0);
        }
        #[cfg(feature = "ebpf")]
        Attr::Nested(children) => {
            for (ty, child) in children {
                put_attr(out, *ty, child);
            }
        }
    }
}

fn put_attr(buf: &mut Vec<u8>, rta_type: u16, attr: &Attr) {
    let mut payload = Vec::new();
    attr_payload(attr, &mut payload);
    let len = (4 + payload.len()) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&rta_type.to_ne_bytes());
    buf.extend_from_slice(&payload);
    while !buf.len().is_multiple_of(NLMSG_ALIGNTO) {
        buf.push(0);
    }
}

#[cfg(feature = "ebpf")]
fn pod_bytes<T>(v: &T) -> &[u8] {
    // SAFETY: used only with #[repr(C)] POD message headers defined above.
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) }
}

#[cfg(feature = "ebpf")]
fn ifinfo(ifindex: i32, flags: u32, change: u32) -> IfInfoMsg {
    IfInfoMsg {
        ifi_family: 0,
        ifi_pad: 0,
        ifi_type: ARPHRD_ETHER,
        ifi_index: ifindex,
        ifi_flags: flags,
        ifi_change: change,
    }
}

#[cfg(feature = "ebpf")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinkPairKind {
    Netkit,
    Veth,
}

#[cfg(feature = "ebpf")]
fn netkit_unavailable(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EOPNOTSUPP)
}

/// One synchronous NETLINK_ROUTE connection.
pub(crate) struct NlSock {
    fd: OwnedFd,
    seq: u32,
}

impl NlSock {
    pub(crate) fn new() -> io::Result<Self> {
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkRoute,
        )
        .map_err(io::Error::from)?;
        setsockopt(&fd, sockopt::ReceiveTimeout, &TimeVal::new(2, 0)).map_err(io::Error::from)?;
        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0)).map_err(io::Error::from)?;
        Ok(Self { fd, seq: 0 })
    }

    #[cfg(feature = "ebpf")]
    /// Receive one datagram. The length is probed with MSG_PEEK|MSG_TRUNC
    /// before consuming: reading an oversize datagram straight away would
    /// silently drop its truncated remainder and make the next datagram
    /// look like the retry. EINTR is retried, oversize is a hard error.
    fn recv_one(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        const MAX_BUF: usize = 1 << 20;
        loop {
            let needed = match recv(
                self.fd.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_PEEK | MsgFlags::MSG_TRUNC,
            ) {
                Ok(needed) => needed,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(io::Error::from(error)),
            };
            if needed > MAX_BUF {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "netlink message exceeds 1 MiB",
                ));
            }
            if needed > buf.len() {
                buf.resize(needed, 0);
            }
            let (received, source) = match recvfrom::<NetlinkAddr>(self.fd.as_raw_fd(), buf) {
                Ok(received) => received,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(io::Error::from(error)),
            };
            if source.is_some_and(|source| source.pid() != 0) {
                continue;
            }
            return Ok(received);
        }
    }

    fn send_datagram(&self, buf: &[u8]) -> io::Result<()> {
        let sent = send(self.fd.as_raw_fd(), buf, MsgFlags::empty()).map_err(io::Error::from)?;
        if sent == buf.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short netlink datagram send",
            ))
        }
    }

    #[cfg(feature = "ebpf")]
    /// Send one request and wait for the kernel ack (NLMSG_ERROR with
    /// error 0).
    fn request(
        &mut self,
        msg_type: u16,
        flags: u16,
        header: &[u8],
        attrs: &[(u16, Attr)],
    ) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&[0u8; 4]); // length, patched below
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
        buf.extend_from_slice(header);
        for (ty, attr) in attrs {
            put_attr(&mut buf, *ty, attr);
        }
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());

        self.send_datagram(&buf)?;

        let mut resp = vec![0u8; 4096];
        loop {
            let n = self.recv_one(&mut resp)?;
            let mut off = 0usize;
            while off + 16 <= n {
                // nlmsghdr: len(4) type(2) flags(2) seq(4) pid(4)
                let hlen = u32::from_ne_bytes(resp[off..off + 4].try_into().unwrap()) as usize;
                let htype = u16::from_ne_bytes(resp[off + 4..off + 6].try_into().unwrap());
                let hseq = u32::from_ne_bytes(resp[off + 8..off + 12].try_into().unwrap());
                if hlen < 16 || off + hlen > n {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed netlink message header",
                    ));
                }
                if hseq == seq && htype == NLMSG_ERROR {
                    if hlen < 20 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "short NLMSG_ERROR",
                        ));
                    }
                    let err = i32::from_ne_bytes(resp[off + 16..off + 20].try_into().unwrap());
                    if err == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(-err));
                }
                off += align(hlen);
            }
        }
    }

    #[cfg(feature = "ebpf")]
    /// Create an L2 netkit pair when supported, otherwise a veth pair.
    pub(crate) fn add_link_pair(&mut self, name: &str, peer: &str) -> io::Result<LinkPairKind> {
        match self.add_netkit_pair(name, peer) {
            Ok(()) => Ok(LinkPairKind::Netkit),
            Err(error) if netkit_unavailable(&error) => {
                self.add_veth_pair(name, peer)?;
                Ok(LinkPairKind::Veth)
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(feature = "ebpf")]
    fn add_netkit_pair(&mut self, name: &str, peer: &str) -> io::Result<()> {
        let header = ifinfo(0, 0, 0);
        let mut peer_payload = pod_bytes(&ifinfo(0, 0, 0)).to_vec();
        put_attr(&mut peer_payload, IFLA_IFNAME, &Attr::Str(peer.to_string()));

        let attrs = [
            (IFLA_IFNAME, Attr::Str(name.to_string())),
            (
                IFLA_LINKINFO,
                Attr::Nested(vec![
                    (IFLA_INFO_KIND, Attr::Str("netkit".to_string())),
                    (
                        IFLA_INFO_DATA,
                        Attr::Nested(vec![
                            (IFLA_NETKIT_MODE, Attr::U32(NETKIT_L2)),
                            (IFLA_NETKIT_PEER_INFO, Attr::Bytes(peer_payload)),
                        ]),
                    ),
                ]),
            ),
        ];
        self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            pod_bytes(&header),
            &attrs,
        )
    }

    #[cfg(feature = "ebpf")]
    /// Create a veth pair (`name` ↔ `peer_name`).
    pub(crate) fn add_veth_pair(&mut self, name: &str, peer: &str) -> io::Result<()> {
        let header = ifinfo(0, 0, 0);
        let mut peer_payload = pod_bytes(&ifinfo(0, 0, 0)).to_vec();
        put_attr(&mut peer_payload, IFLA_IFNAME, &Attr::Str(peer.to_string()));

        let attrs = [
            (IFLA_IFNAME, Attr::Str(name.to_string())),
            (
                IFLA_LINKINFO,
                Attr::Nested(vec![
                    (IFLA_INFO_KIND, Attr::Str("veth".to_string())),
                    (
                        IFLA_INFO_DATA,
                        Attr::Nested(vec![(VETH_INFO_PEER, Attr::Bytes(peer_payload))]),
                    ),
                ]),
            ),
        ];
        self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            pod_bytes(&header),
            &attrs,
        )
    }

    #[cfg(feature = "ebpf")]
    /// Bring a link up (or down).
    pub(crate) fn set_link_up(&mut self, ifindex: u32, up: bool) -> io::Result<()> {
        let header = ifinfo(ifindex as i32, if up { IFF_UP } else { 0 }, IFF_UP);
        self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            pod_bytes(&header),
            &[],
        )
    }

    #[cfg(feature = "ebpf")]
    /// Move a link into the namespace held by `ns_fd`.
    pub(crate) fn set_link_netns_fd(&mut self, ifindex: u32, ns_fd: &OwnedFd) -> io::Result<()> {
        let header = ifinfo(ifindex as i32, 0, 0);
        let fd_no = ns_fd.as_raw_fd() as u32;
        let attrs = [(IFLA_NET_NS_FD, Attr::U32(fd_no))];
        let r = self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            pod_bytes(&header),
            &attrs,
        );
        tracing::debug!(ifindex, fd_no, ok = r.is_ok(), "set_link_netns_fd");
        r
    }

    #[cfg(feature = "ebpf")]
    /// Delete a link by index.
    pub(crate) fn del_link(&mut self, ifindex: u32) -> io::Result<()> {
        let header = ifinfo(ifindex as i32, 0, 0);
        self.request(
            RTM_DELLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            pod_bytes(&header),
            &[],
        )
    }

    #[cfg(feature = "ebpf")]
    /// Add (or remove) an address on an interface.
    pub(crate) fn addr_op(
        &mut self,
        add: bool,
        ifindex: u32,
        family: u8,
        addr: &[u8],
        prefix: u8,
    ) -> io::Result<()> {
        let header = IfAddrMsg {
            ifa_family: family,
            ifa_prefixlen: prefix,
            ifa_flags: 0,
            ifa_scope: RT_SCOPE_UNIVERSE,
            ifa_index: ifindex,
        };
        let attrs = [
            (IFA_LOCAL, Attr::Bytes(addr.to_vec())),
            (IFA_ADDRESS, Attr::Bytes(addr.to_vec())),
        ];
        let (ty, flags) = if add {
            (
                RTM_NEWADDR,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            )
        } else {
            (RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK)
        };
        self.request(ty, flags, pod_bytes(&header), &attrs)
    }

    #[cfg(feature = "ebpf")]
    /// Add a route. `dst` is (network, prefix) or None for default.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_route(
        &mut self,
        family: u8,
        table: u32,
        route_type: u8,
        scope: u8,
        proto: u8,
        dst: Option<(&[u8], u8)>,
        gateway: Option<&[u8]>,
        oif: Option<u32>,
    ) -> io::Result<()> {
        let header = RtMsg {
            rtm_family: family,
            rtm_dst_len: dst.map(|(_, p)| p).unwrap_or(0),
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: if table <= 255 { table as u8 } else { 0 },
            rtm_protocol: proto,
            rtm_scope: scope,
            rtm_type: route_type,
            rtm_flags: 0,
        };
        let mut attrs: Vec<(u16, Attr)> = Vec::new();
        if table > 255 {
            attrs.push((RTA_TABLE, Attr::U32(table)));
        }
        if let Some((net, _)) = dst {
            attrs.push((RTA_DST, Attr::Bytes(net.to_vec())));
        }
        if let Some(gw) = gateway {
            attrs.push((RTA_GATEWAY, Attr::Bytes(gw.to_vec())));
        }
        if let Some(idx) = oif {
            attrs.push((RTA_OIF, Attr::U32(idx)));
        }
        self.request(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            pod_bytes(&header),
            &attrs,
        )
    }

    #[cfg(feature = "ebpf")]
    /// Add/delete a fwmark → table rule.
    fn rule_fwmark(
        &mut self,
        add: bool,
        family: u8,
        fwmark: u32,
        fwmask: u32,
        table: u32,
    ) -> io::Result<()> {
        // fib_rule_hdr: family, dst_len, src_len, tos, table, res1, res2,
        // action, flags(u32)
        let header: [u8; 12] = [
            family,
            0,
            0,
            0,
            if table <= 255 { table as u8 } else { 0 },
            0,
            0,
            FR_ACT_TO_TBL,
            0,
            0,
            0,
            0,
        ];
        let mut attrs: Vec<(u16, Attr)> = vec![
            (FRA_FWMARK, Attr::U32(fwmark)),
            (FRA_FWMASK, Attr::U32(fwmask)),
        ];
        if table > 255 {
            attrs.push((FRA_TABLE, Attr::U32(table)));
        }
        let (ty, flags) = if add {
            (RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)
        } else {
            (RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK)
        };
        self.request(ty, flags, &header, &attrs)
    }

    #[cfg(feature = "ebpf")]
    pub(crate) fn add_rule_fwmark(
        &mut self,
        family: u8,
        fwmark: u32,
        fwmask: u32,
        table: u32,
    ) -> io::Result<()> {
        self.rule_fwmark(true, family, fwmark, fwmask, table)
    }

    #[cfg(feature = "ebpf")]
    pub(crate) fn del_rule_fwmark(
        &mut self,
        family: u8,
        fwmark: u32,
        fwmask: u32,
        table: u32,
    ) -> io::Result<()> {
        self.rule_fwmark(false, family, fwmark, fwmask, table)
    }

    #[cfg(feature = "ebpf")]
    /// Replace a static neighbour entry (IP → MAC, permanent).
    pub(crate) fn neigh_replace(
        &mut self,
        ifindex: u32,
        family: u8,
        ip: &[u8],
        mac: &[u8; 6],
    ) -> io::Result<()> {
        let header = NdMsg {
            ndm_family: family,
            ndm_pad1: 0,
            ndm_pad2: 0,
            ndm_ifindex: ifindex as i32,
            ndm_state: NUD_PERMANENT,
            ndm_flags: 0,
            ndm_type: 0,
        };
        let attrs = [
            (NDA_DST, Attr::Bytes(ip.to_vec())),
            (NDA_LLADDR, Attr::Bytes(mac.to_vec())),
        ];
        self.request(
            RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            pod_bytes(&header),
            &attrs,
        )
    }
}

/// Address families and route enums re-exported for call sites.
#[cfg(feature = "ebpf")]
pub(crate) const FAM_V4: u8 = AF_INET as u8;
#[cfg(feature = "ebpf")]
pub(crate) const FAM_V6: u8 = AF_INET6 as u8;
#[cfg(feature = "ebpf")]
pub(crate) const ROUTE_UNICAST: u8 = RTN_UNICAST;
#[cfg(feature = "ebpf")]
pub(crate) const ROUTE_LOCAL: u8 = RTN_LOCAL;
#[cfg(feature = "ebpf")]
pub(crate) const PROTO_STATIC: u8 = RTPROT_STATIC;
#[cfg(feature = "ebpf")]
pub(crate) const SCOPE_LINK: u8 = RT_SCOPE_LINK;
#[cfg(feature = "ebpf")]
pub(crate) const SCOPE_UNIVERSE: u8 = RT_SCOPE_UNIVERSE;
#[cfg(feature = "ebpf")]
pub(crate) const SCOPE_HOST: u8 = RT_SCOPE_HOST;

#[cfg(feature = "ebpf")]
/// Read an interface's ifindex in the mounted sysfs view, not a scoped setns view.
pub(crate) fn ifindex_of(name: &str) -> io::Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?;
    s.trim()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(feature = "ebpf")]
/// Read an interface's MAC from /sys (namespace-relative).
pub(crate) fn mac_of(name: &str) -> io::Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/address"))?;
    let mut mac = [0u8; 6];
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad MAC"));
    }
    for (i, p) in parts.iter().enumerate() {
        mac[i] =
            u8::from_str_radix(p, 16).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }
    Ok(mac)
}

#[cfg(feature = "ebpf")]
/// One link from an RTM_GETLINK dump. Only the fields interface planning
/// needs; `mac` is optional because L3 devices (tun, wireguard, ppp, sit)
/// have no 6-byte hardware address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkSnapshot {
    pub ifindex: NonZeroU32,
    pub name: String,
    pub arphrd: u16,
    /// `ifi_flags`.
    pub flags: u32,
    /// `IFLA_MASTER`.
    pub master: Option<NonZeroU32>,
    /// `IFLA_LINKINFO` / `IFLA_INFO_KIND`.
    pub kind: Option<String>,
    /// `IFLA_ADDRESS` when it is exactly 6 bytes.
    pub mac: Option<[u8; 6]>,
}

#[cfg(feature = "ebpf")]
fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(feature = "ebpf")]
/// Walk `len/type/payload` attributes. Any attribute that overruns the buffer is
/// `InvalidData`; fewer than four trailing bytes are alignment padding.
fn for_each_attr(
    mut buf: &[u8],
    mut visit: impl FnMut(u16, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    while buf.len() >= 4 {
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let ty = u16::from_ne_bytes([buf[2], buf[3]]) & 0x3fff; // strip NLA_F_NESTED/NET_BYTEORDER
        if len < 4 || len > buf.len() {
            return Err(invalid_data("truncated netlink attribute"));
        }
        visit(ty, &buf[4..len])?;
        buf = &buf[align(len).min(buf.len())..];
    }
    Ok(())
}

#[cfg(feature = "ebpf")]
fn parse_link(msg: &[u8]) -> io::Result<LinkSnapshot> {
    // ifinfomsg: family(1) pad(1) type(2) index(4) flags(4) change(4)
    if msg.len() < 16 {
        return Err(invalid_data("truncated ifinfomsg"));
    }
    let arphrd = u16::from_ne_bytes([msg[2], msg[3]]);
    let ifindex = i32::from_ne_bytes(msg[4..8].try_into().unwrap());
    let flags = u32::from_ne_bytes(msg[8..12].try_into().unwrap());
    let ifindex = u32::try_from(ifindex)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(|| invalid_data("link with zero ifindex"))?;
    let mut name = None;
    let mut master = None;
    let mut kind = None;
    let mut mac = None;
    for_each_attr(&msg[16..], |ty, payload| {
        match ty {
            IFLA_IFNAME => {
                let end = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                name = Some(String::from_utf8_lossy(&payload[..end]).into_owned());
            }
            IFLA_MASTER => {
                let raw: [u8; 4] = payload
                    .try_into()
                    .map_err(|_| invalid_data("bad IFLA_MASTER length"))?;
                master = NonZeroU32::new(u32::from_ne_bytes(raw));
            }
            IFLA_LINKINFO => for_each_attr(payload, |ty, payload| {
                if ty == IFLA_INFO_KIND {
                    let end = payload
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(payload.len());
                    kind = Some(String::from_utf8_lossy(&payload[..end]).into_owned());
                }
                Ok(())
            })?,
            IFLA_ADDRESS if payload.len() == 6 => mac = payload.try_into().ok(),
            _ => {}
        }
        Ok(())
    })?;
    let name = name
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid_data("link without IFLA_IFNAME"))?;
    Ok(LinkSnapshot {
        ifindex,
        name,
        arphrd,
        flags,
        master,
        kind,
        mac,
    })
}

#[cfg(feature = "ebpf")]
/// Fold one datagram of an RTM_GETLINK dump (request `seq`) into `links`.
/// Returns `true` once NLMSG_DONE is seen. Datagrams of an older request
/// (different seq) are ignored.
fn parse_link_datagram(buf: &[u8], seq: u32, links: &mut Vec<LinkSnapshot>) -> io::Result<bool> {
    let mut off = 0usize;
    while off + 16 <= buf.len() {
        let hlen = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        if hlen < 16 || off + hlen > buf.len() {
            return Err(invalid_data("malformed netlink message header"));
        }
        let htype = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
        let hflags = u16::from_ne_bytes(buf[off + 6..off + 8].try_into().unwrap());
        let hseq = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
        if hseq != seq {
            break;
        }
        // The dump raced an interface-table change; its contents are not a
        // consistent snapshot.
        if hflags & NLM_F_DUMP_INTR != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "link dump interrupted by table change",
            ));
        }
        match htype {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                if hlen < 20 {
                    return Err(invalid_data("short NLMSG_ERROR"));
                }
                let err = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                return Err(io::Error::from_raw_os_error(-err));
            }
            RTM_NEWLINK => links.push(parse_link(&buf[off + 16..off + hlen])?),
            _ => {}
        }
        off += align(hlen);
    }
    Ok(false)
}
#[cfg(feature = "ebpf")]
impl NlSock {
    /// Complete RTM_GETLINK dump of the socket's namespace, drained to
    /// NLMSG_DONE (an early return would leave the tail in the socket buffer
    /// and poison the next request's reads). Works in any namespace, unlike
    /// /sys, which shows the host's devices even inside a scoped setns.
    /// `NLM_F_DUMP_INTR` is `ErrorKind::Interrupted`. Callers that retry an
    /// interrupted dump must use a fresh socket: the prior dump may still be active.
    pub(crate) fn dump_links(&mut self) -> io::Result<Vec<LinkSnapshot>> {
        self.seq += 1;
        let seq = self.seq;
        let header = ifinfo(0, 0, 0);
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&RTM_GETLINK.to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(pod_bytes(&header));
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.send_datagram(&buf)?;

        let mut resp = vec![0u8; 8192];
        let mut links = Vec::new();
        loop {
            let n = self.recv_one(&mut resp)?;
            if parse_link_datagram(&resp[..n], seq, &mut links)? {
                return Ok(links);
            }
        }
    }

    /// Look up a link by name with a 6-byte MAC (client-side filter over
    /// [`Self::dump_links`]); L3 links without a MAC read as not found.
    pub(crate) fn get_link(&mut self, name: &str) -> io::Result<(u32, [u8; 6])> {
        self.dump_links()?
            .into_iter()
            .rev()
            .find_map(|link| match link.mac {
                Some(mac) if link.name == name => Some((link.ifindex.get(), mac)),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("link '{name}' not found"))
            })
    }
}

#[cfg(all(test, feature = "ebpf"))]
mod tests;
