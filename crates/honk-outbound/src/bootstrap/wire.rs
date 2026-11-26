//! DNS wire-format encoding and response parsing for bootstrap lookups.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ResolvedRecords;

/// DNS qtype for CNAME alias records (RFC 1035).
const QTYPE_CNAME: u16 = 5;
/// DNS qtype for HTTPS service-binding records (RFC 9460).
pub(super) const QTYPE_HTTPS: u16 = 65;
/// SVCB SvcParam key carrying the ECHConfigList.
const SVCB_KEY_ECH: u16 = 5;
/// Maximum deduplicated answer addresses retained per family.
const MAX_FAMILY_ADDRS: usize = 32;
/// Maximum CNAME alias hops followed within a single response.
const MAX_CNAME_HOPS: usize = 16;
/// Maximum DNS compression pointer jumps per decoded domain name.
const MAX_POINTER_HOPS: usize = 16;
/// Maximum wire-encoded DNS domain name length (RFC 1035 §2.3.4).
const MAX_WIRE_NAME_LEN: usize = 255;

/// Whether `resp` answers `query` (as built by [`build_query`]): same ID, QR
/// set, same opcode and exactly the sent question. Names are case-insensitive
/// in DNS, so only the name ignores ASCII case; type and class must match exactly.
pub(super) fn answers_query(query: &[u8], resp: &[u8]) -> bool {
    let (name, type_class) = query[12..].split_at(query.len() - 16);
    resp.len() >= 12
        && resp[..2] == query[..2]
        && resp[2] & 0x80 != 0
        && (resp[2] ^ query[2]) & 0x78 == 0
        && resp[4..6] == [0, 1]
        && resp
            .get(12..12 + name.len())
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
        && resp.get(12 + name.len()..query.len()) == Some(type_class)
}

/// Build a minimal DNS query (RD set, single question).
pub(super) fn build_query(host: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(host.len() + 18);
    q.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&[0; 6]); // an/ns/ar = 0
    for label in host.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

/// Merge two optional record TTLs, keeping the smaller value when both exist.
pub(super) fn merge_min_ttl(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(t), None) | (None, Some(t)) => Some(t),
        (None, None) => None,
    }
}

/// Extract A/AAAA answer addresses and minimum TTL (including followed CNAME
/// hops) from a DNS response.
pub(super) fn parse_answers(msg: &[u8], qtype: u16) -> io::Result<ResolvedRecords> {
    if msg.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short DNS message",
        ));
    }
    let rcode = msg[3] & 0x0F;
    match rcode {
        0 => {}
        // NXDOMAIN returns empty Ok so /etc/hosts fallback and dual-stack compat stay intact.
        3 => {
            return Ok(ResolvedRecords {
                ips: Vec::new(),
                min_ttl: None,
            });
        }
        _ => {
            return Err(io::Error::other(format!(
                "bootstrap DNS response failed with RCODE {rcode}"
            )));
        }
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    let mut qname = None;
    for idx in 0..qd {
        if idx == 0 {
            let (name, next) = decode_wire_name(msg, pos)?;
            qname = Some(name);
            pos = next;
        } else {
            pos = skip_name(msg, pos)?;
        }
        pos = pos.checked_add(4).ok_or_else(bad)?;
        if pos > msg.len() {
            return Err(bad());
        }
    }
    let mut cnames: Vec<(Vec<u8>, Vec<u8>, u32)> = Vec::new();
    let mut addrs: Vec<(Vec<u8>, IpAddr, u32)> = Vec::new();
    for _ in 0..an {
        let (owner, next) = decode_wire_name(msg, pos)?;
        pos = next;
        if pos + 10 > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated answer",
            ));
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rclass = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated rdata",
            ));
        }
        if rclass == 1 {
            if rtype == QTYPE_CNAME {
                let (target, name_end) = decode_wire_name(msg, pos)?;
                if name_end != pos + rdlen {
                    return Err(bad());
                }
                cnames.push((owner, target, ttl));
            } else if rtype == qtype {
                let ip = match (rtype, rdlen) {
                    (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                        msg[pos],
                        msg[pos + 1],
                        msg[pos + 2],
                        msg[pos + 3],
                    ))),
                    (28, 16) => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&msg[pos..pos + 16]);
                        Some(IpAddr::V6(Ipv6Addr::from(octets)))
                    }
                    _ => None,
                };
                if let Some(ip) = ip {
                    addrs.push((owner, ip, ttl));
                }
            }
        }
        pos += rdlen;
    }

    let Some(mut target_name) = qname else {
        return Ok(ResolvedRecords {
            ips: Vec::new(),
            min_ttl: None,
        });
    };
    let mut visited: Vec<Vec<u8>> = Vec::new();
    let mut cname_min_ttl: Option<u32> = None;
    let mut ips = Vec::new();
    let mut addr_min_ttl: Option<u32> = None;
    loop {
        for (owner, ip, ttl) in &addrs {
            if owner != &target_name {
                continue;
            }
            if ips.contains(ip) {
                addr_min_ttl = merge_min_ttl(addr_min_ttl, Some(*ttl));
            } else if ips.len() < MAX_FAMILY_ADDRS {
                ips.push(*ip);
                addr_min_ttl = merge_min_ttl(addr_min_ttl, Some(*ttl));
            }
        }
        if !ips.is_empty() {
            break;
        }
        let Some((_, next_target, ttl)) = cnames.iter().find(|(owner, _, _)| owner == &target_name)
        else {
            break;
        };
        if next_target == &target_name
            || visited.contains(next_target)
            || visited.len() >= MAX_CNAME_HOPS
        {
            break;
        }
        cname_min_ttl = merge_min_ttl(cname_min_ttl, Some(*ttl));
        visited.push(target_name);
        target_name = next_target.clone();
    }
    let min_ttl = if ips.is_empty() {
        None
    } else {
        merge_min_ttl(cname_min_ttl, addr_min_ttl)
    };
    Ok(ResolvedRecords { ips, min_ttl })
}

/// Extract the ECHConfigList and TTL from the first ServiceMode HTTPS RR in
/// a DNS response. AliasMode records (priority 0) carry no SvcParams and are skipped.
pub(super) fn parse_https_rr_ech(msg: &[u8]) -> Option<(Vec<u8>, u32)> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(msg, pos).ok()?;
        pos = pos.checked_add(4)?;
    }
    for _ in 0..an {
        pos = skip_name(msg, pos).ok()?;
        if pos + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return None;
        }
        if rtype == QTYPE_HTTPS
            && rdlen >= 3
            && let Some(ech) = parse_svcb_ech_param(&msg[pos..pos + rdlen])
        {
            return Some((ech, ttl));
        }
        pos += rdlen;
    }
    None
}

/// Parse SVCB/HTTPS RDATA for the `ech` SvcParam (key 5). Only ServiceMode
/// records (SvcPriority >= 1) carry SvcParams; AliasMode (priority 0) has
/// just a TargetName and is skipped.
fn parse_svcb_ech_param(rdata: &[u8]) -> Option<Vec<u8>> {
    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    if priority == 0 {
        return None;
    }
    let mut pos = skip_name(rdata, 2).ok()?;
    while pos + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + len > rdata.len() {
            return None;
        }
        if key == SVCB_KEY_ECH {
            return Some(rdata[pos..pos + len].to_vec());
        }
        pos += len;
    }
    None
}

fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "bad DNS message")
}

/// Decode a (possibly compressed) domain name into canonical lowercase wire
/// format, returning `(wire_name, next_offset)`.
fn decode_wire_name(msg: &[u8], start: usize) -> io::Result<(Vec<u8>, usize)> {
    let mut cursor = start;
    let mut end = None;
    let mut wire = Vec::new();
    let mut pointer_hops = 0;
    loop {
        let &octet = msg.get(cursor).ok_or_else(bad)?;
        if octet & 0xC0 == 0xC0 {
            let &second = msg.get(cursor + 1).ok_or_else(bad)?;
            let target = usize::from((u16::from(octet & 0x3F) << 8) | u16::from(second));
            pointer_hops += 1;
            if target >= cursor || pointer_hops > MAX_POINTER_HOPS {
                return Err(bad());
            }
            if end.is_none() {
                end = Some(cursor + 2);
            }
            cursor = target;
            continue;
        }
        if octet & 0xC0 != 0 || octet > 63 {
            return Err(bad());
        }
        if wire.len() + 1 > MAX_WIRE_NAME_LEN {
            return Err(bad());
        }
        wire.push(octet);
        cursor += 1;
        if octet == 0 {
            return Ok((wire, end.unwrap_or(cursor)));
        }
        let len = usize::from(octet);
        let label = msg.get(cursor..cursor + len).ok_or_else(bad)?;
        if wire.len() + len >= MAX_WIRE_NAME_LEN {
            return Err(bad());
        }
        wire.extend(label.iter().map(u8::to_ascii_lowercase));
        cursor += len;
    }
}

/// Skip a (possibly compressed) domain name, returning the offset after it.
fn skip_name(msg: &[u8], mut pos: usize) -> io::Result<usize> {
    loop {
        let Some(&len) = msg.get(pos) else {
            return Err(bad());
        };
        if len & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }
        if len == 0 {
            return Ok(pos + 1);
        }
        pos += 1 + len as usize;
        if pos > msg.len() {
            return Err(bad());
        }
    }
}

/// Human-readable qtype name for logs and flow observations.
pub fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        65 => "HTTPS",
        _ => "UNKNOWN",
    }
}
