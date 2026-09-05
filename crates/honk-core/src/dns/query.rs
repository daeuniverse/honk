use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use thiserror::Error;

mod parser;

pub(crate) use parser::{NameParseState, parse_name};
use parser::{parse_edns, parse_rr, read_u16};

const HEADER_LEN: usize = 12;
const MIN_QUESTION_WIRE_LEN: usize = 5;
const OPT_TYPE: u16 = 41;
const ALLOWED_QUERY_FLAGS: u16 = 0x0130;
const MIN_UDP_ADVERTISED_SIZE: u16 = 512;
const MAX_UDP_ADVERTISED_SIZE: u16 = 1232;

#[inline]
fn clamp_udp_advertised_size(size: u16) -> u16 {
    size.clamp(MIN_UDP_ADVERTISED_SIZE, MAX_UDP_ADVERTISED_SIZE)
}

/// Unforgeable evidence that an ingress adapter validated the exact query.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ValidatedDnsQuery(IngressProfile);

impl ValidatedDnsQuery {
    pub(crate) const fn ingress(self) -> IngressProfile {
        self.0
    }
}

/// Validate exactly one complete, forwarder-consumable DNS query.
pub(crate) fn validate_exact_dns_query(data: &[u8]) -> Option<ValidatedDnsQuery> {
    if data.len() < HEADER_LEN || data[2] & 0x80 != 0 {
        return None;
    }

    let qdcount = usize::from(u16::from_be_bytes([data[4], data[5]]));
    if qdcount != 1 {
        return None;
    }
    let counts = [
        usize::from(u16::from_be_bytes([data[6], data[7]])),
        usize::from(u16::from_be_bytes([data[8], data[9]])),
        usize::from(u16::from_be_bytes([data[10], data[11]])),
    ];
    let mut pos = HEADER_LEN;
    // Label starts observed while walking question/owner names. Compression
    // pointers may only land on these boundaries (not header/RDATA/interior
    // label bytes). Unparsed RDATA is intentionally not scanned.
    let mut label_boundaries = vec![false; data.len()];

    if !skip_strict_dns_name(data, &mut pos, &mut label_boundaries)
        || pos.checked_add(4).is_none_or(|end| end > data.len())
    {
        return None;
    }
    pos += 4; // QTYPE + QCLASS

    for count in counts {
        for _ in 0..count {
            if !skip_strict_dns_name(data, &mut pos, &mut label_boundaries)
                || pos.checked_add(10).is_none_or(|end| end > data.len())
            {
                return None;
            }
            let rdlength = usize::from(u16::from_be_bytes([data[pos + 8], data[pos + 9]]));
            pos += 10; // TYPE + CLASS + TTL + RDLENGTH
            let rdata_end = pos.checked_add(rdlength)?;
            if rdata_end > data.len() {
                return None;
            }
            pos = rdata_end;
        }
    }

    if pos != data.len() {
        return None;
    }

    let query = QueryContext::parse(data).ok()?;
    query.qname()?.to_domain_name()?;
    let advertised_size = query.edns().map_or(MIN_UDP_ADVERTISED_SIZE, |edns| {
        clamp_udp_advertised_size(edns.advertised_size())
    });
    Some(ValidatedDnsQuery(IngressProfile::Udp { advertised_size }))
}

pub(crate) fn is_exact_dns_query(data: &[u8]) -> bool {
    validate_exact_dns_query(data).is_some()
}

#[cfg(test)]
/// Derive the response-size policy advertised by a UDP DNS query.
pub(crate) fn udp_ingress_profile(data: &[u8]) -> IngressProfile {
    let advertised_size = QueryContext::parse(data)
        .ok()
        .and_then(|query| query.edns().map(|edns| edns.advertised_size()))
        .map_or(MIN_UDP_ADVERTISED_SIZE, clamp_udp_advertised_size);
    IngressProfile::Udp { advertised_size }
}

/// Bounds-safe name walk that enforces the RFC expanded-name limit and
/// restricts compression pointers to previously observed label boundaries.
fn skip_strict_dns_name(data: &[u8], pos: &mut usize, label_boundaries: &mut [bool]) -> bool {
    let mut cursor = *pos;
    let mut expanded = 0usize;
    let mut jumped = false;
    let mut depth = 0usize;

    loop {
        if depth > 128 || cursor >= data.len() || cursor >= label_boundaries.len() {
            return false;
        }

        if jumped {
            if !label_boundaries[cursor] {
                return false;
            }
        } else {
            label_boundaries[cursor] = true;
        }

        let label_len = data[cursor];
        if label_len == 0 {
            if expanded.checked_add(1).is_none_or(|value| value > 255) {
                return false;
            }
            if !jumped {
                *pos = cursor + 1;
            }
            return true;
        }

        if label_len & 0xc0 == 0xc0 {
            let Some(&next) = data.get(cursor + 1) else {
                return false;
            };
            let target = (usize::from(label_len & 0x3f) << 8) | usize::from(next);
            // Pointers name an earlier observed label start only.
            if target >= cursor || target >= label_boundaries.len() || !label_boundaries[target] {
                return false;
            }
            if !jumped {
                *pos = cursor + 2;
            }
            jumped = true;
            cursor = target;
            depth += 1;
            continue;
        }

        if label_len > 63 {
            return false;
        }

        let label_octets = 1 + usize::from(label_len);
        expanded = match expanded.checked_add(label_octets) {
            Some(value) if value <= 255 => value,
            _ => return false,
        };
        let Some(next_pos) = cursor.checked_add(label_octets) else {
            return false;
        };
        if next_pos > data.len() {
            return false;
        }
        cursor = next_pos;
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxId(u16);

impl TxId {
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QType(u16);

impl QType {
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QClass(u16);

impl QClass {
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName(Box<[u8]>);

impl DnsName {
    pub fn as_wire(&self) -> &[u8] {
        &self.0
    }

    /// Decode the canonical wire name as a lowercase dotted UTF-8 domain.
    pub fn to_domain_name(&self) -> Option<String> {
        let mut domain = String::with_capacity(self.0.len());
        let mut cursor = 0usize;
        loop {
            let length = usize::from(*self.0.get(cursor)?);
            cursor += 1;
            if length == 0 {
                if domain.is_empty() || cursor != self.0.len() {
                    return None;
                }
                domain.make_ascii_lowercase();
                return Some(domain);
            }
            let end = cursor.checked_add(length)?;
            let label = std::str::from_utf8(self.0.get(cursor..end)?).ok()?;
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(label);
            cursor = end;
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum IngressProfile {
    Udp {
        advertised_size: u16,
    },
    Tcp,
    Api,
    #[default]
    Internal,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct DnsRequestMeta {
    source_ip: Option<IpAddr>,
    original_dst: Option<SocketAddr>,
}

impl DnsRequestMeta {
    pub const EMPTY: Self = Self {
        source_ip: None,
        original_dst: None,
    };

    pub fn new(source_ip: Option<IpAddr>, original_dst: Option<SocketAddr>) -> Self {
        let source_ip = source_ip.map(|source| match source {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map_or(IpAddr::V6(address), IpAddr::V4),
            source => source,
        });
        Self {
            source_ip,
            original_dst,
        }
    }

    pub const fn source_ip(self) -> Option<IpAddr> {
        self.source_ip
    }

    pub const fn original_dst(self) -> Option<SocketAddr> {
        self.original_dst
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuestionOffsets {
    start: u32,
    end: u32,
}

impl QuestionOffsets {
    pub const fn start(self) -> usize {
        self.start as usize
    }

    pub const fn end(self) -> usize {
        self.end as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsMetadata {
    advertised_size: u16,
    extended_rcode: u8,
    version: u8,
    dnssec_ok: bool,
    option_codes: Vec<u16>,
    flags: u16,
}

impl EdnsMetadata {
    pub const fn advertised_size(&self) -> u16 {
        self.advertised_size
    }

    pub const fn version(&self) -> u8 {
        self.version
    }

    pub const fn extended_rcode(&self) -> u8 {
        self.extended_rcode
    }

    pub const fn dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }

    pub fn option_codes(&self) -> &[u16] {
        &self.option_codes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Question {
    name: DnsName,
    qtype: QType,
    qclass: QClass,
    offsets: QuestionOffsets,
}

#[derive(Debug, Clone)]
pub struct QueryContext {
    txid: TxId,
    flags: u16,
    questions: Vec<Question>,
    edns: Option<EdnsMetadata>,
    ingress: IngressProfile,
    canonical_wire: Arc<[u8]>,
    cacheable: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QueryError {
    #[error("DNS message is shorter than its header")]
    HeaderTruncated,
    #[error("DNS message contains a malformed name")]
    MalformedName,
    #[error("DNS message contains a truncated field")]
    TruncatedField,
    #[error("DNS message contains a malformed EDNS option")]
    MalformedEdnsOption,
    #[error("DNS message has trailing bytes")]
    TrailingBytes,
}

impl QueryContext {
    pub fn parse(raw: &[u8]) -> Result<Self, QueryError> {
        Self::parse_with_profile(raw, IngressProfile::default())
    }

    pub fn parse_with_profile(raw: &[u8], ingress: IngressProfile) -> Result<Self, QueryError> {
        if raw.len() < HEADER_LEN {
            return Err(QueryError::HeaderTruncated);
        }
        let txid = TxId(read_u16(raw, 0)?);
        let flags = read_u16(raw, 2)?;
        let qdcount = read_u16(raw, 4)?;
        let ancount = read_u16(raw, 6)?;
        let nscount = read_u16(raw, 8)?;
        let arcount = read_u16(raw, 10)?;
        let mut cursor = HEADER_LEN;
        if usize::from(qdcount) > (raw.len() - HEADER_LEN) / MIN_QUESTION_WIRE_LEN {
            return Err(QueryError::TruncatedField);
        }
        let mut name_state = NameParseState::new(raw.len());
        let mut questions = Vec::new();
        for _ in 0..qdcount {
            let start = cursor;
            let (name, end) = parse_name(raw, cursor, &mut name_state)?;
            cursor = end;
            let qtype = QType(read_u16(raw, cursor)?);
            let qclass = QClass(read_u16(raw, cursor + 2)?);
            cursor += 4;
            questions.push(Question {
                name,
                qtype,
                qclass,
                offsets: QuestionOffsets {
                    start: u32::try_from(start).map_err(|_| QueryError::TruncatedField)?,
                    end: u32::try_from(cursor).map_err(|_| QueryError::TruncatedField)?,
                },
            });
        }
        for _ in 0..ancount {
            cursor = parse_rr(raw, cursor, &mut name_state)?.end;
        }
        for _ in 0..nscount {
            cursor = parse_rr(raw, cursor, &mut name_state)?.end;
        }
        let mut edns = None;
        let mut opt_count = 0u16;
        for _ in 0..arcount {
            let rr = parse_rr(raw, cursor, &mut name_state)?;
            cursor = rr.end;
            if rr.rtype == OPT_TYPE {
                opt_count = opt_count.saturating_add(1);
                let metadata = parse_edns(raw, &rr)?;
                if edns.is_none() {
                    edns = Some(metadata);
                }
            }
        }
        if cursor != raw.len() {
            return Err(QueryError::TrailingBytes);
        }
        let mut canonical_wire = raw.to_vec();
        if let Some(id) = canonical_wire.get_mut(0..2) {
            id.copy_from_slice(&[0, 0]);
        }
        let cacheable = flags & !ALLOWED_QUERY_FLAGS == 0
            && qdcount == 1
            && ancount == 0
            && nscount == 0
            && arcount == opt_count
            && opt_count <= 1
            && edns.as_ref().is_none_or(|value| {
                value.version == 0
                    && value.option_codes.is_empty()
                    && value.extended_rcode == 0
                    && value.flags & !0x8000 == 0
            });
        Ok(Self {
            txid,
            flags,
            questions,
            edns,
            ingress,
            canonical_wire: canonical_wire.into(),
            cacheable,
        })
    }

    pub const fn txid(&self) -> TxId {
        self.txid
    }

    pub fn qname(&self) -> Option<&DnsName> {
        self.questions.first().map(|question| &question.name)
    }

    pub fn qtype(&self) -> Option<QType> {
        self.questions.first().map(|question| question.qtype)
    }

    pub fn qclass(&self) -> Option<QClass> {
        self.questions.first().map(|question| question.qclass)
    }

    pub fn question_offsets(&self) -> Option<QuestionOffsets> {
        self.questions.first().map(|question| question.offsets)
    }

    pub fn all_question_offsets(&self) -> impl ExactSizeIterator<Item = QuestionOffsets> + '_ {
        self.questions.iter().map(|question| question.offsets)
    }

    pub fn question_wire(&self) -> Option<&[u8]> {
        let offsets = self.question_offsets()?;
        self.canonical_wire.get(offsets.start()..offsets.end())
    }

    pub const fn edns(&self) -> Option<&EdnsMetadata> {
        self.edns.as_ref()
    }

    pub const fn ingress(&self) -> IngressProfile {
        self.ingress
    }

    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
    pub(crate) fn canonical_wire_arc(&self) -> Arc<[u8]> {
        Arc::clone(&self.canonical_wire)
    }

    pub const fn is_cacheable(&self) -> bool {
        self.cacheable
    }

    pub const fn is_coalescable(&self) -> bool {
        self.cacheable
    }

    pub(crate) const fn flags(&self) -> u16 {
        self.flags
    }

    pub(crate) fn questions(&self) -> impl ExactSizeIterator<Item = (&DnsName, QType, QClass)> {
        self.questions
            .iter()
            .map(|question| (&question.name, question.qtype, question.qclass))
    }
}

#[cfg(test)]
mod tests;
