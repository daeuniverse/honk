use std::ops::Range;
use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

use super::query::{IngressProfile, NameParseState, QueryContext, TxId, parse_name};

const HEADER_LEN: usize = 12;
const QR: u16 = 0x8000;
const TC: u16 = 0x0200;
const OPCODE_MASK: u16 = 0x7800;
const RA: u16 = 0x0080;
const QUERY_ECHO_MASK: u16 = OPCODE_MASK | 0x0110;
pub(crate) fn is_truncated(response: &[u8]) -> bool {
    let Some(flags) = response.get(2..4) else {
        return false;
    };
    u16::from_be_bytes([flags[0], flags[1]]) & TC != 0
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResponseError {
    #[error("DNS response is shorter than its header")]
    HeaderTruncated,
    #[error("DNS response has QR clear")]
    QueryMessage,
    #[error("DNS response opcode does not match the request")]
    OpcodeMismatch,
    #[error("DNS response question does not match the request")]
    QuestionMismatch,
    #[error("DNS response contains a malformed record")]
    MalformedRecord,
    #[error("DNS response has trailing bytes")]
    TrailingBytes,
    #[error("truncated response is incompatible with the request ingress profile")]
    IncompatibleProfile,
    #[error("response template used with a different exact request")]
    RequestIdentityMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional,
}

#[derive(Debug, Clone)]
struct RecordBoundary {
    section: Section,
    wire: Range<usize>,
}

#[derive(Debug, Clone)]
pub struct ResponseTemplate {
    request_identity: Arc<[u8]>,
    wire: Bytes,
    question_end: usize,
    records: Vec<RecordBoundary>,
}

impl ResponseTemplate {
    pub(crate) fn check(request: &QueryContext, response: &[u8]) -> Result<(), ResponseError> {
        validate_layout(request, response).map(|_| ())
    }

    pub fn validate(request: &QueryContext, response: &[u8]) -> Result<Self, ResponseError> {
        let (question_end, records) = validate_layout(request, response)?;
        Ok(Self {
            request_identity: request.canonical_wire_arc(),
            wire: Bytes::copy_from_slice(response),
            question_end,
            records,
        })
    }

    pub(crate) fn validate_owned(
        request: &QueryContext,
        response: Bytes,
    ) -> Result<Self, ResponseError> {
        let (question_end, records) = validate_layout(request, &response)?;
        Ok(Self {
            request_identity: request.canonical_wire_arc(),
            wire: response,
            question_end,
            records,
        })
    }
    pub(crate) fn wire(&self) -> Bytes {
        self.wire.clone()
    }

    pub fn render(&self, caller: &QueryContext) -> Result<Vec<u8>, ResponseError> {
        if caller.canonical_wire() != self.request_identity.as_ref() {
            return Err(ResponseError::RequestIdentityMismatch);
        }
        match caller.ingress() {
            IngressProfile::Udp { advertised_size } => {
                self.render_udp(caller.txid(), usize::from(advertised_size))
            }
            IngressProfile::Tcp | IngressProfile::Api | IngressProfile::Internal => {
                let mut response = self.wire.to_vec();
                set_txid(&mut response, caller.txid())?;
                Ok(response)
            }
        }
    }

    fn render_udp(&self, txid: TxId, limit: usize) -> Result<Vec<u8>, ResponseError> {
        if self.wire.len() <= limit {
            let mut response = self.wire.to_vec();
            set_txid(&mut response, txid)?;
            return Ok(response);
        }
        let prefix = self
            .wire
            .get(..self.question_end)
            .ok_or(ResponseError::MalformedRecord)?;
        let mut response = Vec::with_capacity(limit.max(prefix.len()));
        response.extend_from_slice(prefix);
        let mut counts = [0u16; 3];
        for record in &self.records {
            let record_wire = self
                .wire
                .get(record.wire.clone())
                .ok_or(ResponseError::MalformedRecord)?;
            if response.len().saturating_add(record_wire.len()) > limit {
                break;
            }
            response.extend_from_slice(record_wire);
            let index = match record.section {
                Section::Answer => 0,
                Section::Authority => 1,
                Section::Additional => 2,
            };
            counts[index] = counts[index].saturating_add(1);
        }
        set_txid(&mut response, txid)?;
        let flags = read_u16(&response, 2)? | TC;
        write_u16(&mut response, 2, flags)?;
        write_u16(&mut response, 6, counts[0])?;
        write_u16(&mut response, 8, counts[1])?;
        write_u16(&mut response, 10, counts[2])?;
        Ok(response)
    }
}

fn validate_layout(
    request: &QueryContext,
    response: &[u8],
) -> Result<(usize, Vec<RecordBoundary>), ResponseError> {
    if response.len() < HEADER_LEN {
        return Err(ResponseError::HeaderTruncated);
    }
    let flags = read_u16(response, 2)?;
    if flags & QR == 0 {
        return Err(ResponseError::QueryMessage);
    }
    if flags & OPCODE_MASK != request.flags() & OPCODE_MASK {
        return Err(ResponseError::OpcodeMismatch);
    }
    if flags & TC != 0 && !matches!(request.ingress(), IngressProfile::Udp { .. }) {
        return Err(ResponseError::IncompatibleProfile);
    }
    let qdcount = read_u16(response, 4)?;
    if usize::from(qdcount) != request.questions().len() {
        return Err(ResponseError::QuestionMismatch);
    }
    let mut name_state = NameParseState::new(response.len());
    let mut cursor = HEADER_LEN;
    for (expected_name, expected_type, expected_class) in request.questions() {
        let (name, name_end) = parse_name(response, cursor, &mut name_state)
            .map_err(|_| ResponseError::QuestionMismatch)?;
        let qtype = read_u16(response, name_end)?;
        let qclass = read_u16(response, name_end + 2)?;
        if &name != expected_name || qtype != expected_type.get() || qclass != expected_class.get()
        {
            return Err(ResponseError::QuestionMismatch);
        }
        cursor = name_end + 4;
    }
    let question_end = cursor;
    let sections = [
        (Section::Answer, read_u16(response, 6)?),
        (Section::Authority, read_u16(response, 8)?),
        (Section::Additional, read_u16(response, 10)?),
    ];
    let mut records = Vec::new();
    for (section, count) in sections {
        for _ in 0..count {
            let start = cursor;
            cursor = record_end(response, cursor, &mut name_state)?;
            records.push(RecordBoundary {
                section,
                wire: start..cursor,
            });
        }
    }
    if cursor != response.len() {
        return Err(ResponseError::TrailingBytes);
    }
    Ok((question_end, records))
}

fn record_end(
    response: &[u8],
    start: usize,
    name_state: &mut NameParseState,
) -> Result<usize, ResponseError> {
    let (_, name_end) =
        parse_name(response, start, name_state).map_err(|_| ResponseError::MalformedRecord)?;
    let rdlength = usize::from(read_u16(response, name_end + 8)?);
    (name_end + 10)
        .checked_add(rdlength)
        .filter(|end| *end <= response.len())
        .ok_or(ResponseError::MalformedRecord)
}

fn set_txid(response: &mut [u8], txid: TxId) -> Result<(), ResponseError> {
    write_u16(response, 0, txid.get())
}

fn read_u16(response: &[u8], offset: usize) -> Result<u16, ResponseError> {
    let bytes = response
        .get(offset..offset + 2)
        .ok_or(ResponseError::MalformedRecord)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn write_u16(response: &mut [u8], offset: usize, value: u16) -> Result<(), ResponseError> {
    response
        .get_mut(offset..offset + 2)
        .ok_or(ResponseError::MalformedRecord)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub(crate) fn dns_error_flags(query: &[u8], rcode: u8) -> u16 {
    let request_flags = query
        .get(2..4)
        .map(|flags| u16::from_be_bytes([flags[0], flags[1]]))
        .unwrap_or(0x0100);
    QR | RA | (request_flags & QUERY_ECHO_MASK) | u16::from(rcode & 0x0f)
}

/// Build a minimal DNS error response while preserving the request payload.
pub(crate) fn build_dns_error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    if query.len() < HEADER_LEN {
        return vec![0u8; HEADER_LEN];
    }
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&dns_error_flags(query, rcode).to_be_bytes());
    response
}

pub(crate) fn build_dns_servfail(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 2)
}

pub(crate) fn build_dns_refused(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 5)
}

#[cfg(test)]
mod tests;
