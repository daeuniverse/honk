//! Native DNS presentation over the response validator's record boundaries.

use std::fmt::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;
use thiserror::Error;

use super::{RecordBoundary, ResponseError, Section, read_u16, visit_layout};
use crate::dns::query::{IngressProfile, NameParseState, QueryContext, parse_name_into};

pub(crate) const MAX_JSON_BYTES: usize = 262_144;

#[derive(Debug, Error)]
pub(crate) enum ProjectionError {
    #[error("invalid DNS wire message")]
    Invalid,
    #[error("DNS projection exceeds its byte budget")]
    Budget,
}

impl From<ResponseError> for ProjectionError {
    fn from(_: ResponseError) -> Self {
        Self::Invalid
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DnsQuestion {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub class: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DnsAnswer {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub class: String,
    pub ttl: u32,
    pub data: String,
}

pub(crate) fn context(
    query: &[u8],
    ingress: IngressProfile,
) -> Result<QueryContext, ProjectionError> {
    if query.len() > usize::from(u16::MAX) || query.get(4..6) != Some(&[0, 1]) {
        return Err(ProjectionError::Invalid);
    }
    QueryContext::parse_with_profile(query, ingress).map_err(|_| ProjectionError::Invalid)
}

pub(crate) fn question(
    query: &[u8],
    ingress: IngressProfile,
) -> Result<DnsQuestion, ProjectionError> {
    let query = context(query, ingress)?;
    let mut name = String::new();
    write_name(
        &mut name,
        query.qname().ok_or(ProjectionError::Invalid)?.as_wire(),
    )
    .map_err(|_| ProjectionError::Invalid)?;
    Ok(DnsQuestion {
        name,
        rtype: record_type(query.qtype().ok_or(ProjectionError::Invalid)?.get()),
        class: record_class(query.qclass().ok_or(ProjectionError::Invalid)?.get()),
    })
}

pub(crate) fn project(
    query: &[u8],
    response: &[u8],
    ingress: IngressProfile,
    budget: &mut usize,
) -> Result<Vec<DnsAnswer>, ProjectionError> {
    let query = context(query, ingress)?;
    let charge = measure(&query, response, *budget)?;
    // The complete expansion is charged before allocating any answer strings/vector.
    *budget -= charge;
    let mut answers = Vec::with_capacity(usize::from(read_u16(response, 6)?));
    let mut names = NameParseState::new(response.len());
    let mut result: Result<(), ProjectionError> = Ok(());
    visit_response(&query, response, |record| {
        if record.section != Section::Answer || result.is_err() {
            return;
        }
        result = (|| {
            let mut name = [0; 255];
            let (length, end) = parse_name_into(response, record.wire.start, &mut names, &mut name)
                .map_err(|_| ProjectionError::Invalid)?;
            let rtype = read_u16(response, end)?;
            let mut owner = String::new();
            write_name(&mut owner, &name[..length]).map_err(|_| ProjectionError::Invalid)?;
            let mut data = String::new();
            write_data(
                &mut data,
                response,
                rtype,
                end + 10,
                record.wire.end,
                &mut names,
            )?;
            answers.push(DnsAnswer {
                name: owner,
                rtype: record_type(rtype),
                class: record_class(read_u16(response, end + 2)?),
                ttl: read_u32(response, end + 4)?,
                data,
            });
            Ok(())
        })();
    })?;
    result?;
    Ok(answers)
}

pub(crate) fn measure(
    query: &QueryContext,
    response: &[u8],
    budget: usize,
) -> Result<usize, ProjectionError> {
    if response.len() > usize::from(u16::MAX) {
        return Err(ProjectionError::Invalid);
    }
    let mut charged = 2usize;
    let mut names = NameParseState::new(response.len());
    let mut result = Ok(());
    visit_response(query, response, |record| {
        if result.is_err() {
            return;
        }
        result = (|| {
            let mut name = [0; 255];
            let (length, end) = parse_name_into(response, record.wire.start, &mut names, &mut name)
                .map_err(|_| ProjectionError::Invalid)?;
            let rtype = read_u16(response, end)?;
            let mut size = JsonTextSize(0);
            write_name(&mut size, &name[..length]).map_err(|_| ProjectionError::Invalid)?;
            write_data(
                &mut size,
                response,
                rtype,
                end + 10,
                record.wire.end,
                &mut names,
            )?;
            if record.section == Section::Answer {
                // Object punctuation, type/class, TTL and the vector slot are bounded here.
                charged = charged.saturating_add(size.0 + 128 + size_of::<DnsAnswer>());
                if charged > budget {
                    return Err(ProjectionError::Budget);
                }
            }
            Ok(())
        })();
    })?;
    result?;
    if charged > budget {
        return Err(ProjectionError::Budget);
    }
    Ok(charged)
}

fn visit_response(
    query: &QueryContext,
    response: &[u8],
    visit: impl FnMut(RecordBoundary),
) -> Result<usize, ProjectionError> {
    // The bound listener intentionally returns header-only errors; do not invent an echo.
    if response.len() == 12 && response[3] & 15 != 0 && response[4..12] == [0; 8] {
        let mut header = [0; 12];
        header[2..4].copy_from_slice(&query.flags().to_be_bytes());
        let empty = QueryContext::parse_with_profile(&header, query.ingress())
            .map_err(|_| ProjectionError::Invalid)?;
        return visit_layout(&empty, response, visit).map_err(Into::into);
    }
    visit_layout(query, response, visit).map_err(Into::into)
}

struct JsonTextSize(usize);

impl Write for JsonTextSize {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0 += value
            .bytes()
            .map(|byte| match byte {
                b'"' | b'\\' => 2,
                0..=31 => 6,
                _ => 1,
            })
            .sum::<usize>();
        Ok(())
    }
}

fn write_name(output: &mut impl Write, wire: &[u8]) -> fmt::Result {
    if wire == [0] {
        return output.write_char('.');
    }
    let mut cursor = 0;
    while wire[cursor] != 0 {
        let length = usize::from(wire[cursor]);
        cursor += 1;
        for &byte in &wire[cursor..cursor + length] {
            match byte {
                b'.' | b'\\' => write!(output, "\\{}", char::from(byte))?,
                33..=126 => output.write_char(char::from(byte))?,
                _ => write!(output, "\\{byte:03}")?,
            }
        }
        output.write_char('.')?;
        cursor += length;
    }
    Ok(())
}

fn data_name(
    output: &mut impl Write,
    response: &[u8],
    cursor: &mut usize,
    end: usize,
    names: &mut NameParseState,
) -> Result<(), ProjectionError> {
    let mut wire = [0; 255];
    let (length, next) = parse_name_into(response, *cursor, names, &mut wire)
        .map_err(|_| ProjectionError::Invalid)?;
    if next > end {
        return Err(ProjectionError::Invalid);
    }
    *cursor = next;
    write_name(output, &wire[..length]).map_err(|_| ProjectionError::Invalid)
}

fn read_u32(response: &[u8], offset: usize) -> Result<u32, ProjectionError> {
    let bytes = response
        .get(offset..offset + 4)
        .ok_or(ProjectionError::Invalid)?;
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| ProjectionError::Invalid)?,
    ))
}

fn write_data(
    output: &mut impl Write,
    response: &[u8],
    rtype: u16,
    mut cursor: usize,
    end: usize,
    names: &mut NameParseState,
) -> Result<(), ProjectionError> {
    let data = response.get(cursor..end).ok_or(ProjectionError::Invalid)?;
    fn invalid<T>(_: T) -> ProjectionError {
        ProjectionError::Invalid
    }
    match rtype {
        1 => {
            let bytes: [u8; 4] = data.try_into().map_err(invalid)?;
            write!(output, "{}", Ipv4Addr::from(bytes)).map_err(invalid)?;
        }
        28 => {
            let bytes: [u8; 16] = data.try_into().map_err(invalid)?;
            write!(output, "{}", Ipv6Addr::from(bytes)).map_err(invalid)?;
        }
        2 | 5 | 12 | 39 => {
            data_name(output, response, &mut cursor, end, names)?;
            if cursor != end {
                return Err(ProjectionError::Invalid);
            }
        }
        15 | 33 => {
            let fields = if rtype == 15 { 1 } else { 3 };
            if data.len() < fields * 2 + 1 {
                return Err(ProjectionError::Invalid);
            }
            for _ in 0..fields {
                write!(output, "{} ", read_u16(response, cursor)?).map_err(invalid)?;
                cursor += 2;
            }
            data_name(output, response, &mut cursor, end, names)?;
            if cursor != end {
                return Err(ProjectionError::Invalid);
            }
        }
        6 => {
            data_name(output, response, &mut cursor, end, names)?;
            output.write_char(' ').map_err(invalid)?;
            data_name(output, response, &mut cursor, end, names)?;
            if end - cursor != 20 {
                return Err(ProjectionError::Invalid);
            }
            for _ in 0..5 {
                write!(output, " {}", read_u32(response, cursor)?).map_err(invalid)?;
                cursor += 4;
            }
        }
        16 => {
            let mut first = true;
            while cursor < end {
                let length = usize::from(response[cursor]);
                cursor += 1;
                let text_end = cursor + length;
                if text_end > end {
                    return Err(ProjectionError::Invalid);
                }
                if !first {
                    output.write_char(' ').map_err(invalid)?;
                }
                first = false;
                output.write_char('"').map_err(invalid)?;
                for &byte in &response[cursor..text_end] {
                    match byte {
                        b'"' | b'\\' => write!(output, "\\{}", char::from(byte)),
                        32..=126 => output.write_char(char::from(byte)),
                        _ => write!(output, "\\{byte:03}"),
                    }
                    .map_err(invalid)?;
                }
                output.write_char('"').map_err(invalid)?;
                cursor = text_end;
            }
        }
        _ => {
            // RFC 3597 preserves unknown RDATA instead of inventing or omitting it.
            write!(output, "\\# {} ", data.len()).map_err(invalid)?;
            for byte in data {
                write!(output, "{byte:02X}").map_err(invalid)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn status(response: &[u8]) -> String {
    let Some(low) = response.get(3).map(|flags| u16::from(flags & 15)) else {
        return "INVALID".into();
    };
    if response.len() > usize::from(u16::MAX)
        || response
            .get(4..6)
            .is_none_or(|count| count != [0, 1] && count != [0, 0])
    {
        return "INVALID".into();
    }
    let mut code = low;
    let mut seen_opt = false;
    let mut names = NameParseState::new(response.len());
    let mut invalid = false;
    let parsed = super::visit_message(None, response, |record| {
        let mut name = [0; 255];
        let Ok((length, end)) = parse_name_into(response, record.wire.start, &mut names, &mut name)
        else {
            invalid = true;
            return;
        };
        if read_u16(response, end) == Ok(41) {
            if record.section != Section::Additional || seen_opt || name[..length] != [0] {
                invalid = true;
                return;
            }
            seen_opt = true;
            code |= u16::from(response[end + 4]) << 4;
        }
    });
    if parsed.is_err() || invalid {
        return "INVALID".into();
    }
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        11 => "DSOTYPENI",
        16 => "BADVERS",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => return format!("RCODE{code}"),
    }
    .into()
}

const RECORD_TYPES: &[(u16, &str)] = &[
    (1, "A"),
    (2, "NS"),
    (5, "CNAME"),
    (6, "SOA"),
    (12, "PTR"),
    (15, "MX"),
    (16, "TXT"),
    (28, "AAAA"),
    (33, "SRV"),
    (35, "NAPTR"),
    (39, "DNAME"),
    (41, "OPT"),
    (43, "DS"),
    (44, "SSHFP"),
    (46, "RRSIG"),
    (47, "NSEC"),
    (48, "DNSKEY"),
    (50, "NSEC3"),
    (51, "NSEC3PARAM"),
    (52, "TLSA"),
    (64, "SVCB"),
    (65, "HTTPS"),
    (99, "SPF"),
    (255, "ANY"),
    (257, "CAA"),
];

pub(crate) fn record_type(value: u16) -> String {
    RECORD_TYPES
        .iter()
        .find(|(code, _)| *code == value)
        .map_or_else(|| format!("TYPE{value}"), |(_, name)| (*name).into())
}

pub(crate) fn parse_type(value: &str) -> Option<u16> {
    RECORD_TYPES
        .iter()
        .find(|(_, name)| *name == value)
        .map(|(code, _)| *code)
        .or_else(|| {
            let digits = value.strip_prefix("TYPE").unwrap_or(value);
            (1..=5).contains(&digits.len()).then_some(())?;
            digits
                .bytes()
                .all(|byte| byte.is_ascii_digit())
                .then_some(())?;
            digits.parse().ok()
        })
}

fn record_class(value: u16) -> String {
    match value {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        254 => "NONE",
        255 => "ANY",
        _ => return format!("CLASS{value}"),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(query: &[u8], count: u16) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&count.to_be_bytes());
        response
    }

    #[test]
    fn compressed_expansion_fails_as_a_whole_before_spending_budget() {
        let domain = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        let query = crate::dns::forwarder::build_dns_query(&domain, 5);
        let mut wire = response(&query, 2000);
        for _ in 0..2000 {
            wire.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
        }
        let mut budget = MAX_JSON_BYTES;
        assert!(matches!(
            project(&query, &wire, IngressProfile::Tcp, &mut budget),
            Err(ProjectionError::Budget)
        ));
        assert_eq!(budget, MAX_JSON_BYTES);
        let mut malformed = response(&query, 1);
        let position = malformed.len();
        malformed.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2]);
        let pointer = 0xc000 | (position as u16 + 12);
        malformed.extend_from_slice(&pointer.to_be_bytes());
        assert!(matches!(
            project(&query, &malformed, IngressProfile::Tcp, &mut budget),
            Err(ProjectionError::Invalid)
        ));
    }

    #[test]
    fn unknown_data_and_binary_labels_are_not_clipped_or_lossy() {
        let mut query = crate::dns::forwarder::build_dns_query("x.example", 65000);
        query[13] = 0xff;
        let mut wire = response(&query, 1);
        wire.extend_from_slice(&[
            0xc0, 12, 0xfd, 0xe8, 0, 3, 0xff, 0xff, 0xff, 0xff, 0, 4, 0, 0xff, 0x10, 0x20,
        ]);
        let mut budget = MAX_JSON_BYTES;
        let rows = project(&query, &wire, IngressProfile::Tcp, &mut budget).unwrap();
        assert_eq!(rows[0].name, "\\255.example.");
        assert_eq!(rows[0].rtype, "TYPE65000");
        assert_eq!(rows[0].class, "CH");
        assert_eq!(rows[0].ttl, u32::MAX);
        assert_eq!(rows[0].data, "\\# 4 00FF1020");
    }

    #[test]
    fn extended_status_and_questionless_refusal_use_wire_facts() {
        let query = crate::dns::forwarder::build_dns_query("example.com", 1);
        let mut wire = response(&query, 0);
        wire[10..12].copy_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);
        assert_eq!(status(&wire), "BADVERS");
        wire[3] |= 5;
        assert_eq!(status(&wire), "BADALG");
        let mut refused = [0; 12];
        refused[2..4].copy_from_slice(&0x8185u16.to_be_bytes());
        let mut budget = MAX_JSON_BYTES;
        assert!(
            project(
                &query,
                &refused,
                IngressProfile::Udp {
                    advertised_size: 512
                },
                &mut budget
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(status(&refused), "REFUSED");
        refused[3] &= !15;
        assert!(
            project(
                &query,
                &refused,
                IngressProfile::Udp {
                    advertised_size: 512
                },
                &mut budget
            )
            .is_err()
        );
    }
}
