//! clsact qdiscs and direct-action BPF filters: interface hooks on kernels
//! before Linux 6.6, which have no TCX links.

use super::*;
use std::os::fd::RawFd;

const RTM_NEWQDISC: u16 = 36;
const RTM_NEWTFILTER: u16 = 44;
const RTM_DELTFILTER: u16 = 45;
const RTM_GETTFILTER: u16 = 46;

const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_BPF_FD: u16 = 6;
const TCA_BPF_NAME: u16 = 7;
const TCA_BPF_FLAGS: u16 = 8;
const TCA_BPF_ID: u16 = 11;
const TCA_BPF_FLAG_ACT_DIRECT: u32 = 1;
const NLA_TYPE_MASK: u16 = 0x3fff;

const TC_H_CLSACT: u32 = 0xffff_fff1;
/// `TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)`.
pub(crate) const TC_PARENT_INGRESS: u32 = 0xffff_fff2;
/// `TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)`.
pub(crate) const TC_PARENT_EGRESS: u32 = 0xffff_fff3;
const ETH_P_ALL: u16 = 0x0003;

#[repr(C)]
#[derive(Clone, Copy)]
struct TcMsg {
    family: u8,
    pad1: u8,
    pad2: u16,
    ifindex: i32,
    handle: u32,
    parent: u32,
    info: u32,
}

fn filter_info(priority: u16) -> u32 {
    (u32::from(priority) << 16) | u32::from(ETH_P_ALL.to_be())
}

/// One filter of a clsact direction, as a dump reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcFilterEntry {
    pub(crate) priority: u16,
    pub(crate) handle: u32,
    /// `None` for a non-BPF classifier.
    pub(crate) program_id: Option<u32>,
}

impl NlSock {
    /// Add the clsact qdisc; one that already exists is kept.
    pub(crate) fn add_clsact(&mut self, ifindex: u32) -> io::Result<()> {
        let header = TcMsg {
            family: libc::AF_UNSPEC as u8,
            pad1: 0,
            pad2: 0,
            ifindex: ifindex as i32,
            handle: 0xffff_0000,
            parent: TC_H_CLSACT,
            info: 0,
        };
        match self.request(
            RTM_NEWQDISC,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            pod_bytes(&header),
            &[(TCA_KIND, Attr::Str("clsact".into()))],
        ) {
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => Ok(()),
            result => result,
        }
    }

    /// Install `program` at `(priority, handle)`. `exclusive` refuses an
    /// existing filter there; otherwise the existing one is changed in place,
    /// which swaps the program without a gap.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn set_bpf_filter(
        &mut self,
        ifindex: u32,
        parent: u32,
        priority: u16,
        handle: u32,
        program: RawFd,
        name: &str,
        exclusive: bool,
    ) -> io::Result<()> {
        let header = TcMsg {
            family: libc::AF_UNSPEC as u8,
            pad1: 0,
            pad2: 0,
            ifindex: ifindex as i32,
            handle,
            parent,
            info: filter_info(priority),
        };
        let flags = NLM_F_REQUEST
            | NLM_F_ACK
            | NLM_F_CREATE
            | if exclusive { NLM_F_EXCL } else { NLM_F_REPLACE };
        self.request(
            RTM_NEWTFILTER,
            flags,
            pod_bytes(&header),
            &[
                (TCA_KIND, Attr::Str("bpf".into())),
                (
                    TCA_OPTIONS,
                    Attr::Nested(vec![
                        (TCA_BPF_FD, Attr::U32(program as u32)),
                        (TCA_BPF_NAME, Attr::Str(name.into())),
                        (TCA_BPF_FLAGS, Attr::U32(TCA_BPF_FLAG_ACT_DIRECT)),
                    ]),
                ),
            ],
        )
    }

    pub(crate) fn del_filter(
        &mut self,
        ifindex: u32,
        parent: u32,
        priority: u16,
        handle: u32,
    ) -> io::Result<()> {
        let header = TcMsg {
            family: libc::AF_UNSPEC as u8,
            pad1: 0,
            pad2: 0,
            ifindex: ifindex as i32,
            handle,
            parent,
            info: filter_info(priority),
        };
        self.request(
            RTM_DELTFILTER,
            NLM_F_REQUEST | NLM_F_ACK,
            pod_bytes(&header),
            &[(TCA_KIND, Attr::Str("bpf".into()))],
        )
    }

    /// Every filter of one clsact direction. A device without clsact, or
    /// without the device, dumps empty.
    pub(crate) fn dump_filters(
        &mut self,
        ifindex: u32,
        parent: u32,
    ) -> io::Result<Vec<TcFilterEntry>> {
        self.seq += 1;
        let seq = self.seq;
        let header = TcMsg {
            family: libc::AF_UNSPEC as u8,
            pad1: 0,
            pad2: 0,
            ifindex: ifindex as i32,
            handle: 0,
            parent,
            info: 0,
        };
        let mut buf = Vec::with_capacity(36);
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&RTM_GETTFILTER.to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(pod_bytes(&header));
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.send_datagram(&buf)?;

        let mut resp = vec![0u8; 8192];
        let mut filters = Vec::new();
        loop {
            let n = self.recv_one(&mut resp)?;
            if parse_filter_datagram(&resp[..n], seq, &mut filters)? {
                return Ok(filters);
            }
        }
    }
}

fn attributes(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if buf.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let kind = u16::from_ne_bytes([buf[2], buf[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > buf.len() {
            return None;
        }
        let payload = &buf[4..len];
        buf = &buf[align(len).min(buf.len())..];
        Some((kind, payload))
    })
}

pub(super) fn parse_filter(body: &[u8]) -> io::Result<TcFilterEntry> {
    let header_len = std::mem::size_of::<TcMsg>();
    if body.len() < header_len {
        return Err(invalid_data("short tcmsg"));
    }
    let handle = u32::from_ne_bytes(body[8..12].try_into().unwrap());
    let info = u32::from_ne_bytes(body[16..20].try_into().unwrap());
    let mut bpf = false;
    let mut program_id = None;
    for (kind, payload) in attributes(&body[header_len..]) {
        match kind {
            TCA_KIND => bpf = payload.starts_with(b"bpf\0"),
            TCA_OPTIONS => {
                for (option, value) in attributes(payload) {
                    if option == TCA_BPF_ID && value.len() >= 4 {
                        program_id = Some(u32::from_ne_bytes(value[..4].try_into().unwrap()));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(TcFilterEntry {
        priority: (info >> 16) as u16,
        handle,
        program_id: program_id.filter(|_| bpf),
    })
}

fn parse_filter_datagram(
    buf: &[u8],
    seq: u32,
    filters: &mut Vec<TcFilterEntry>,
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
        if hflags & NLM_F_DUMP_INTR != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "filter dump interrupted by a change",
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
            RTM_NEWTFILTER => {
                let entry = parse_filter(&buf[off + 16..off + hlen])?;
                // A dump also lists the per-priority chain heads (handle 0).
                if entry.handle != 0 {
                    filters.push(entry);
                }
            }
            _ => {}
        }
        off += align(hlen);
    }
    Ok(false)
}
