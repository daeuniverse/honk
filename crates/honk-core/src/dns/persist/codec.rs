use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::dns::cache::{CacheKey, OperationKind};
use crate::dns::planner::{RequestScope, UpstreamTag};
use crate::dns::policy::PolicyId;
use crate::dns::query::{IngressProfile, QueryContext};
use crate::dns::response::ResponseTemplate;

mod reader {
    use super::DecodeError;

    const MAX_FIELD_LEN: usize = 1 << 20;

    pub(super) struct Reader<'a> {
        remaining: &'a [u8],
    }

    impl<'a> Reader<'a> {
        pub(super) const fn new(bytes: &'a [u8]) -> Self {
            Self { remaining: bytes }
        }

        pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
            let (value, remaining) = self
                .remaining
                .split_at_checked(len)
                .ok_or(DecodeError::Corrupt)?;
            self.remaining = remaining;
            Ok(value)
        }

        pub(super) fn byte(&mut self) -> Result<u8, DecodeError> {
            Ok(self.take(1)?[0])
        }

        pub(super) fn u16(&mut self) -> Result<u16, DecodeError> {
            let bytes = <[u8; 2]>::try_from(self.take(2)?).map_err(|_| DecodeError::Corrupt)?;
            Ok(u16::from_be_bytes(bytes))
        }

        pub(super) fn u64(&mut self) -> Result<u64, DecodeError> {
            let bytes = <[u8; 8]>::try_from(self.take(8)?).map_err(|_| DecodeError::Corrupt)?;
            Ok(u64::from_be_bytes(bytes))
        }

        pub(super) fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
            let length = usize::try_from(u32::from_be_bytes(
                <[u8; 4]>::try_from(self.take(4)?).map_err(|_| DecodeError::Corrupt)?,
            ))
            .map_err(|_| DecodeError::Corrupt)?;
            if length > MAX_FIELD_LEN {
                return Err(DecodeError::Corrupt);
            }
            self.take(length)
        }

        pub(super) const fn is_empty(&self) -> bool {
            self.remaining.is_empty()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::*;
        use crate::dns::forwarder::build_dns_query;

        #[test]
        fn v2_encoding_matches_golden_bytes() {
            let query_wire = build_dns_query("example.com", 1);
            let query = QueryContext::parse_with_profile(&query_wire, IngressProfile::Internal)
                .expect("query");
            let mut response = query_wire;
            response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            response[6..8].copy_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]);
            let key = CacheKey::new(
                &query,
                None,
                RequestScope::Upstream(UpstreamTag::new("default").expect("tag")),
                OperationKind::Resolve,
            );

            let encoded = encode(&key, &response, 0x0102_0304_0506_0708);
            let payload = encoded
                .bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();

            assert_eq!(
                encoded.suffix,
                "06bd0c8eca602e2c3af0b60abca13d83d19e58c11f887ec14c7109861826ac66"
            );
            assert_eq!(
                payload,
                "48444e53020102030405060708000000300000001d000001000001000000000000076578616d706c6503636f6d00000100010300000000000764656661756c74000000002d000081800001000100000000076578616d706c6503636f6d0000010001c00c000100010000012c0004c0000201"
            );
        }
    }
}

use reader::Reader;

const MAGIC: &[u8; 4] = b"HDNS";
const VERSION: u8 = 2;

pub(super) struct EncodedEntry {
    pub suffix: String,
    pub bytes: Vec<u8>,
}

pub(super) struct DecodedEntry {
    pub key: CacheKey,
    pub response: Vec<u8>,
    pub expire_at_unix: u64,
}

#[derive(Debug, Error)]
pub(super) enum DecodeError {
    #[error("unsupported DNS persistence version {0}")]
    Version(u8),
    #[error("DNS persistence key digest does not match its canonical material")]
    Collision,
    #[error("DNS persistence policy does not match the active policy")]
    PolicyMismatch,
    #[error("malformed DNS persistence entry")]
    Corrupt,
}

pub(super) fn encode(key: &CacheKey, response: &[u8], expire_at_unix: u64) -> EncodedEntry {
    let key_bytes = encode_key(key);
    let suffix = digest_hex(&key_bytes);
    let mut bytes = Vec::with_capacity(17 + key_bytes.len() + response.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&expire_at_unix.to_be_bytes());
    put_bytes(&mut bytes, &key_bytes);
    put_bytes(&mut bytes, response);
    EncodedEntry { suffix, bytes }
}

pub(super) fn decode(
    suffix: &str,
    bytes: &[u8],
    active_policy: Option<&PolicyId>,
) -> Result<DecodedEntry, DecodeError> {
    let mut reader = Reader::new(bytes);
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(DecodeError::Corrupt);
    }
    let version = reader.byte()?;
    if version != VERSION {
        return Err(DecodeError::Version(version));
    }
    let expire_at_unix = reader.u64()?;
    let key_bytes = reader.bytes()?;
    let response = reader.bytes()?.to_vec();
    if !reader.is_empty() || digest_hex(key_bytes) != suffix {
        return Err(DecodeError::Collision);
    }
    let (query, policy, scope, operation) = decode_key(key_bytes, active_policy)?;
    let key = CacheKey::new(&query, policy, scope, operation);
    ResponseTemplate::check(&query, &response).map_err(|_| DecodeError::Corrupt)?;
    Ok(DecodedEntry {
        key,
        response,
        expire_at_unix,
    })
}

fn encode_key(key: &CacheKey) -> Vec<u8> {
    let mut bytes = Vec::new();
    put_bytes(&mut bytes, key.wire_identity());
    match key.ingress() {
        IngressProfile::Udp { advertised_size } => {
            bytes.push(0);
            bytes.extend_from_slice(&advertised_size.to_be_bytes());
        }
        IngressProfile::Tcp => bytes.push(1),
        IngressProfile::Api => bytes.push(2),
        IngressProfile::Internal => bytes.push(3),
    }
    match key.policy_id() {
        None => bytes.push(0),
        Some(policy) => {
            bytes.push(1);
            bytes.extend_from_slice(policy.digest());
            put_bytes(&mut bytes, policy.canonical_bytes());
        }
    }
    match key.scope() {
        RequestScope::Upstream(tag) => {
            bytes.push(0);
            put_bytes(&mut bytes, tag.as_str().as_bytes());
        }
        RequestScope::AsIs(address) => {
            bytes.push(1);
            encode_address(&mut bytes, address);
        }
    }
    bytes.push(match key.operation() {
        OperationKind::Resolve => 0,
        OperationKind::Refresh => 1,
    });
    bytes
}

fn decode_key(
    bytes: &[u8],
    active_policy: Option<&PolicyId>,
) -> Result<(QueryContext, Option<PolicyId>, RequestScope, OperationKind), DecodeError> {
    let mut reader = Reader::new(bytes);
    let wire = reader.bytes()?;
    let ingress = match reader.byte()? {
        0 => IngressProfile::Udp {
            advertised_size: reader.u16()?,
        },
        1 => IngressProfile::Tcp,
        2 => IngressProfile::Api,
        3 => IngressProfile::Internal,
        _ => return Err(DecodeError::Corrupt),
    };
    let policy = decode_policy(&mut reader, active_policy)?;
    let scope = match reader.byte()? {
        0 => {
            let tag = std::str::from_utf8(reader.bytes()?).map_err(|_| DecodeError::Corrupt)?;
            RequestScope::Upstream(UpstreamTag::new(tag).map_err(|_| DecodeError::Corrupt)?)
        }
        1 => RequestScope::AsIs(decode_address(&mut reader)?),
        _ => return Err(DecodeError::Corrupt),
    };
    let operation = match reader.byte()? {
        0 => OperationKind::Resolve,
        1 => OperationKind::Refresh,
        _ => return Err(DecodeError::Corrupt),
    };
    if !reader.is_empty() {
        return Err(DecodeError::Corrupt);
    }
    let query =
        QueryContext::parse_with_profile(wire, ingress).map_err(|_| DecodeError::Corrupt)?;
    Ok((query, policy, scope, operation))
}

fn decode_policy(
    reader: &mut Reader<'_>,
    active: Option<&PolicyId>,
) -> Result<Option<PolicyId>, DecodeError> {
    match reader.byte()? {
        0 if active.is_none() => Ok(None),
        0 => Err(DecodeError::PolicyMismatch),
        1 => {
            let digest = reader.take(32)?;
            let canonical = reader.bytes()?;
            let Some(active) = active else {
                return Err(DecodeError::PolicyMismatch);
            };
            if active.digest().as_slice() != digest || active.canonical_bytes() != canonical {
                return Err(DecodeError::PolicyMismatch);
            }
            Ok(Some(active.clone()))
        }
        _ => Err(DecodeError::Corrupt),
    }
}

fn encode_address(bytes: &mut Vec<u8>, address: &SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            bytes.push(0);
            bytes.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes.extend_from_slice(&address.port().to_be_bytes());
}

fn decode_address(reader: &mut Reader<'_>) -> Result<SocketAddr, DecodeError> {
    let ip = match reader.byte()? {
        0 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(reader.take(4)?).map_err(|_| DecodeError::Corrupt)?,
        )),
        1 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(reader.take(16)?).map_err(|_| DecodeError::Corrupt)?,
        )),
        _ => return Err(DecodeError::Corrupt),
    };
    Ok(SocketAddr::new(ip, reader.u16()?))
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    output.extend_from_slice(value);
}

fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
