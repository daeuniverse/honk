use crate::dns::planner::ResponseTraversal;
use crate::dns::wire::skip_dns_name;

#[cfg(test)]
pub(super) fn effective_cache_ttl(configured: u32, answer_min_ttl: u32) -> u32 {
    if configured > 0 {
        configured
    } else {
        answer_min_ttl.max(1)
    }
}

/// TTL advertised on answers served from the serve-stale fallback: small
/// enough that clients retry soon and pick up the recovery.
pub(crate) const SERVE_STALE_TTL_SECS: u32 = 30;

pub(crate) fn traversal_strings(traversal: &ResponseTraversal) -> Vec<String> {
    traversal
        .path()
        .iter()
        .map(|upstream| upstream.as_str().to_owned())
        .collect()
}

pub(super) fn patch_txid(mut response: Vec<u8>, txid: u16) -> Vec<u8> {
    if let Some(bytes) = response.get_mut(0..2) {
        bytes.copy_from_slice(&txid.to_be_bytes());
    }
    response
}
fn normalize_ttl(ttl: u32) -> u32 {
    if ttl & 0x8000_0000 != 0 { 0 } else { ttl }
}

/// RFC 2308 §5 negative-cache TTL: `min(SOA TTL, SOA MINIMUM)` from the
/// authority section, falling back to `default_ttl` when no SOA record is
/// present (or the message is malformed).
pub(crate) fn extract_soa_negative_ttl(data: &[u8], default_ttl: u32) -> u32 {
    if data.len() < 12 {
        return default_ttl;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        if !skip_dns_name(data, &mut pos) {
            return default_ttl;
        }
        pos += 4;
        if pos > data.len() {
            return default_ttl;
        }
    }
    for i in 0..(ancount + nscount) {
        if !skip_dns_name(data, &mut pos) {
            return default_ttl;
        }
        if pos + 10 > data.len() {
            return default_ttl;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ttl = normalize_ttl(u32::from_be_bytes([
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]));
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        if i >= ancount && rtype == 6 && rdlength >= 20 && pos + 10 + rdlength <= data.len() {
            // SOA RDATA: MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE,
            // MINIMUM — the last u32 of RDATA.
            let minimum = normalize_ttl(u32::from_be_bytes([
                data[pos + 10 + rdlength - 4],
                data[pos + 10 + rdlength - 3],
                data[pos + 10 + rdlength - 2],
                data[pos + 10 + rdlength - 1],
            ]));
            return ttl.min(minimum);
        }
        pos += 10 + rdlength;
    }
    default_ttl
}

/// Overwrite TTL fields on answer/authority/additional records with `ttl`,
/// excluding EDNS OPT pseudo-records whose field is an extended control word.
/// Malformed tails are left as-is.
pub(crate) fn rewrite_answer_ttls(data: &mut [u8], ttl: u32) {
    if data.len() < 12 {
        return;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        if !skip_dns_name(data, &mut pos) {
            return;
        }
        pos += 4;
        if pos > data.len() {
            return;
        }
    }

    let ttl_be = ttl.to_be_bytes();
    for _ in 0..(ancount + nscount + arcount) {
        if !skip_dns_name(data, &mut pos) {
            return;
        }
        if pos + 10 > data.len() {
            return;
        }
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        if rtype != 41 {
            data[pos + 4..pos + 8].copy_from_slice(&ttl_be);
        }
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10 + rdlength;
    }
}

/// Extract the minimum positive TTL from DNS records, excluding EDNS OPT
/// pseudo-records. Returns 60 if no TTL is found.
pub(crate) fn extract_min_ttl(data: &[u8]) -> u32 {
    if data.len() < 12 {
        return 60;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut pos = 12;

    for _ in 0..qdcount {
        if !skip_dns_name(data, &mut pos) {
            return 60;
        }
        pos += 4; // QTYPE + QCLASS
        if pos > data.len() {
            return 60;
        }
    }

    let total_records = ancount + nscount + arcount;
    let mut min_ttl = u32::MAX;

    for _ in 0..total_records {
        if pos + 12 > data.len() {
            break;
        }
        if !skip_dns_name(data, &mut pos) {
            break;
        }
        if pos + 10 > data.len() {
            break;
        }

        // Record layout after NAME: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA(n)
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ttl = normalize_ttl(u32::from_be_bytes([
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]));
        if rtype != 41 && ttl < min_ttl {
            min_ttl = ttl;
        }

        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10 + rdlength;
    }

    if min_ttl == u32::MAX { 60 } else { min_ttl }
}
