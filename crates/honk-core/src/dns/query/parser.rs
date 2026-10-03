use std::ops::Range;

use super::{DnsName, EdnsMetadata, HEADER_LEN, OPT_TYPE, QueryError};

const MAX_POINTER_HOPS: usize = 128;

pub(crate) struct NameParseState {
    visited: Vec<u32>,
    epoch: u32,
    pointer_hops: usize,
}

impl NameParseState {
    pub(crate) fn new(message_len: usize) -> Self {
        Self {
            visited: vec![0; message_len],
            epoch: 0,
            pointer_hops: 0,
        }
    }

    fn begin_name(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            self.visited.fill(0);
            self.epoch = 1;
        }
        self.pointer_hops = 0;
    }

    fn visit_pointer(&mut self, target: usize, cursor: usize) -> Result<(), QueryError> {
        if target >= cursor {
            return Err(QueryError::MalformedName);
        }
        self.pointer_hops += 1;
        if self.pointer_hops > MAX_POINTER_HOPS {
            return Err(QueryError::MalformedName);
        }
        let mark = self
            .visited
            .get_mut(target)
            .ok_or(QueryError::MalformedName)?;
        if *mark == self.epoch {
            return Err(QueryError::MalformedName);
        }
        *mark = self.epoch;
        Ok(())
    }
}

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

pub(super) fn parse_rr(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
) -> Result<ResourceRecord, QueryError> {
    let (owner_length, name_end) = parse_name_into(raw, start, state, &mut [0; 255])?;
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
    let mut state = NameParseState::new(raw.len());
    let mut qname = [0; 255];
    let (length, mut cursor) = parse_name_into(raw, HEADER_LEN, &mut state, &mut qname)?;
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
            let rr = parse_rr(raw, cursor, &mut state)?;
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

pub(crate) fn parse_name(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
) -> Result<(DnsName, usize), QueryError> {
    let mut wire = [0; 255];
    let (length, end) = parse_name_into(raw, start, state, &mut wire)?;
    Ok((DnsName(wire[..length].into()), end))
}

pub(crate) fn parse_name_into(
    raw: &[u8],
    start: usize,
    state: &mut NameParseState,
    wire: &mut [u8; 255],
) -> Result<(usize, usize), QueryError> {
    state.begin_name();
    let mut cursor = start;
    let mut end = None;
    let mut length = 0;
    loop {
        let octet = *raw.get(cursor).ok_or(QueryError::MalformedName)?;
        if octet & 0xc0 == 0xc0 {
            let second = *raw.get(cursor + 1).ok_or(QueryError::MalformedName)?;
            let target = usize::from((u16::from(octet & 0x3f) << 8) | u16::from(second));
            state.visit_pointer(target, cursor)?;
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
