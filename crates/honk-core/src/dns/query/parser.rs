use std::ops::Range;

use super::{DnsName, EdnsMetadata, HEADER_LEN, OPT_TYPE, QueryError};

const MAX_POINTER_HOPS: usize = 128;

#[derive(Debug)]
pub(super) struct ResourceRecord {
    /// Only OPT validation reads the owner, and only to require the root.
    pub(super) root_owner: bool,
    pub(super) rtype: u16,
    pub(super) class: u16,
    pub(super) ttl: u32,
    pub(super) rdata: Range<usize>,
    pub(super) end: usize,
}

pub(super) fn parse_rr(raw: &[u8], start: usize) -> Result<ResourceRecord, QueryError> {
    let (owner_length, name_end) = parse_name_into(raw, start, &mut [0; 255])?;
    let rtype = read_u16(raw, name_end)?;
    let class = read_u16(raw, name_end + 2)?;
    let ttl = read_u32(raw, name_end + 4)?;
    let rdlength = usize::from(read_u16(raw, name_end + 8)?);
    let rdata_start = name_end + 10;
    let end = rdata_start
        .checked_add(rdlength)
        .filter(|end| *end <= raw.len())
        .ok_or(QueryError::TruncatedField)?;
    Ok(ResourceRecord {
        root_owner: owner_length == 1,
        rtype,
        class,
        ttl,
        rdata: rdata_start..end,
        end,
    })
}

/// Validate an OPT pseudo-RR, passing each option code to `each`.
fn validate_opt(
    raw: &[u8],
    rr: &ResourceRecord,
    mut each: impl FnMut(u16),
) -> Result<(), QueryError> {
    let mut cursor = rr.rdata.start;
    while cursor < rr.rdata.end {
        let code = read_u16(raw, cursor).map_err(|_| QueryError::MalformedEdnsOption)?;
        let len =
            usize::from(read_u16(raw, cursor + 2).map_err(|_| QueryError::MalformedEdnsOption)?);
        cursor = cursor
            .checked_add(4 + len)
            .filter(|end| *end <= rr.rdata.end)
            .ok_or(QueryError::MalformedEdnsOption)?;
        each(code);
    }
    if !rr.root_owner {
        return Err(QueryError::MalformedName);
    }
    Ok(())
}

pub(super) fn parse_edns(raw: &[u8], rr: &ResourceRecord) -> Result<EdnsMetadata, QueryError> {
    let mut option_codes = Vec::new();
    validate_opt(raw, rr, |code| option_codes.push(code))?;
    let flags = u16::try_from(rr.ttl & 0xffff).map_err(|_| QueryError::TruncatedField)?;
    Ok(EdnsMetadata {
        advertised_size: rr.class,
        extended_rcode: u8::try_from(rr.ttl >> 24).map_err(|_| QueryError::TruncatedField)?,
        version: u8::try_from((rr.ttl >> 16) & 0xff).map_err(|_| QueryError::TruncatedField)?,
        dnssec_ok: flags & 0x8000 != 0,
        option_codes,
        flags,
    })
}

/// Allocation-free twin of the walk in `QueryContext::parse_with_profile` for a
/// one-question query: accepts exactly what it accepts and, because UDP ingress
/// needs only that, returns the first OPT's advertised size. The question name
/// must also decode as UTF-8 labels, as `DnsName::to_domain_name` requires.
pub(super) fn scan_single_question_query(raw: &[u8]) -> Result<Option<u16>, QueryError> {
    if raw.len() < HEADER_LEN {
        return Err(QueryError::HeaderTruncated);
    }
    let counts = [read_u16(raw, 6)?, read_u16(raw, 8)?, read_u16(raw, 10)?];
    let mut qname = [0; 255];
    let (length, mut cursor) = parse_name_into(raw, HEADER_LEN, &mut qname)?;
    // Length octets are ASCII, so the wire form is UTF-8 exactly when every label is.
    if std::str::from_utf8(&qname[..length]).is_err() {
        return Err(QueryError::MalformedName);
    }
    read_u16(raw, cursor)?;
    read_u16(raw, cursor + 2)?;
    cursor += 4;
    let mut advertised_size = None;
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let rr = parse_rr(raw, cursor)?;
            cursor = rr.end;
            if section == 2 && rr.rtype == OPT_TYPE {
                validate_opt(raw, &rr, |_| {})?;
                advertised_size.get_or_insert(rr.class);
            }
        }
    }
    if cursor != raw.len() {
        return Err(QueryError::TrailingBytes);
    }
    Ok(advertised_size)
}

pub(crate) fn parse_name(raw: &[u8], start: usize) -> Result<(DnsName, usize), QueryError> {
    let mut wire = [0; 255];
    let (length, end) = parse_name_into(raw, start, &mut wire)?;
    Ok((DnsName(wire[..length].into()), end))
}

/// Pointers jump strictly backward, so a compression loop must cross a
/// non-root label, and each one adds at least two bytes to `wire`. A loop
/// therefore ends at the hop budget or the 255-byte name limit with the same
/// error a visited-offset table would report.
pub(crate) fn parse_name_into(
    raw: &[u8],
    start: usize,
    wire: &mut [u8; 255],
) -> Result<(usize, usize), QueryError> {
    let mut cursor = start;
    let mut end = None;
    let mut length = 0;
    let mut pointer_hops = 0;
    loop {
        let octet = *raw.get(cursor).ok_or(QueryError::MalformedName)?;
        if octet & 0xc0 == 0xc0 {
            let second = *raw.get(cursor + 1).ok_or(QueryError::MalformedName)?;
            let target = usize::from((u16::from(octet & 0x3f) << 8) | u16::from(second));
            pointer_hops += 1;
            if target >= cursor || pointer_hops > MAX_POINTER_HOPS {
                return Err(QueryError::MalformedName);
            }
            if end.is_none() {
                end = Some(cursor + 2);
            }
            cursor = target;
            continue;
        }
        if octet & 0xc0 != 0 || octet > 63 {
            return Err(QueryError::MalformedName);
        }
        *wire.get_mut(length).ok_or(QueryError::MalformedName)? = octet;
        length += 1;
        cursor += 1;
        if octet == 0 {
            return Ok((length, end.unwrap_or(cursor)));
        }
        let label_end = cursor + usize::from(octet);
        let output_end = length + usize::from(octet);
        wire.get_mut(length..output_end)
            .ok_or(QueryError::MalformedName)?
            .copy_from_slice(
                raw.get(cursor..label_end)
                    .ok_or(QueryError::MalformedName)?,
            );
        length = output_end;
        cursor = label_end;
    }
}

pub(super) fn read_u16(raw: &[u8], offset: usize) -> Result<u16, QueryError> {
    let bytes = raw
        .get(offset..offset + 2)
        .ok_or(QueryError::TruncatedField)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(raw: &[u8], offset: usize) -> Result<u32, QueryError> {
    let bytes = raw
        .get(offset..offset + 4)
        .ok_or(QueryError::TruncatedField)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
