use super::*;
use std::num::NonZeroU32;

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

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

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

/// Fold one datagram of an RTM_GETLINK dump (request `seq`) into `links`.
/// Returns `true` once NLMSG_DONE is seen. Datagrams of an older request
/// (different seq) are ignored.
pub(super) fn parse_link_datagram(
    buf: &[u8],
    seq: u32,
    links: &mut Vec<LinkSnapshot>,
) -> io::Result<bool> {
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
}
