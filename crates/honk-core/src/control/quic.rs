//! QUIC Initial packet decryption and SNI extraction (RFC 9000 / RFC 9001).
//!
//! A QUIC connection starts with an Initial packet whose CRYPTO frame carries
//! the TLS 1.3 ClientHello. Initial packets are encrypted with keys derived
//! (via HKDF) from the client-chosen Destination Connection ID, so any
//! on-path observer of the first datagram can decrypt it — including us.
//!
//! The extraction pipeline:
//!
//! 1. [`decrypt_initial_datagram`] parses the long header of each Initial
//!    packet in a (possibly coalesced) UDP datagram, derives the initial
//!    secrets (RFC 9001 §5.2 for QUIC v1, RFC 9369 §3.3 for QUIC v2), removes
//!    header protection (AES-128-ECB mask over a 16-byte sample) and
//!    AEAD-decrypts the payload (AES-128-GCM, nonce = IV XOR packet number).
//! 2. The decrypted payload is walked frame by frame; CRYPTO frame payloads
//!    are collected as `(offset, data)` fragments. Only frame types that are
//!    legal in Initial packets (PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE)
//!    are understood; anything else stops the walk.
//! 3. [`CryptoReassembly`] reassembles the CRYPTO stream across fragments
//!    (and across Initial packets, which may arrive out of order).
//! 4. [`parse_client_hello`] reads the TLS handshake message at CRYPTO
//!    stream offset 0 and extracts the SNI hostname via the shared
//!    ClientHello parser in [`crate::sniffing`].
//!
//! Retry packets, 0-RTT packets and version negotiation are not handled:
//! they carry no ClientHello we can use.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aes::cipher::BlockCipherEncrypt;
use aes_gcm::aes::{Aes128, Block as AesBlock};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use honk_outbound::quic::hkdf_expand_label;
use sha2::Sha256;
use std::collections::BTreeMap;

/// QUIC version 1 (RFC 9000).
pub(crate) const QUIC_VERSION_1: u32 = 0x0000_0001;
/// QUIC version 2 (RFC 9369).
pub(crate) const QUIC_VERSION_2: u32 = 0x6b33_43cf;

/// RFC 9001 §5.2 initial salt (QUIC v1).
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
/// RFC 9369 §3.3 initial salt (QUIC v2).
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Upper bound on the reassembled CRYPTO stream (a ClientHello is < 4 KiB in
/// practice); protects against memory exhaustion by hostile flows.
const MAX_CRYPTO_STREAM: usize = 64 * 1024;
/// AEAD tag size for AES-128-GCM.
const GCM_TAG_LEN: usize = 16;

/// Why a datagram could not be decrypted as a QUIC Initial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicDecryptError {
    /// Not a QUIC long-header Initial packet of a supported version.
    NotInitial,
    /// The packet looked like an Initial but header-protection removal or
    /// AEAD decryption failed (corruption or a non-QUIC flow).
    DecryptFailed,
}

/// AES-128-GCM key/IV and header-protection key derived from the
/// client-chosen Destination Connection ID (RFC 9001 §5.2).
pub(crate) struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

impl InitialKeys {
    /// Derive the secrets protecting *client* Initial packets.
    fn derive_client(dcid: &[u8], version: u32) -> Option<Self> {
        Self::derive(dcid, version, b"client in")
    }

    fn derive(dcid: &[u8], version: u32, secret_label: &[u8]) -> Option<Self> {
        // QUIC v2 uses its own salt *and* its own HKDF labels (RFC 9369 §3.3).
        let (salt, key_label, iv_label, hp_label): (&[u8], &[u8], &[u8], &[u8]) = match version {
            QUIC_VERSION_1 => (&INITIAL_SALT_V1, b"quic key", b"quic iv", b"quic hp"),
            QUIC_VERSION_2 => (&INITIAL_SALT_V2, b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
            _ => return None,
        };
        let extract = Hkdf::<Sha256>::new(Some(salt), dcid);
        let mut secret = [0u8; 32];
        hkdf_expand_label(&extract, secret_label, &mut secret).ok()?;
        let mut keys = Self {
            key: [0; 16],
            iv: [0; 12],
            hp: [0; 16],
        };
        let expand = Hkdf::<Sha256>::from_prk(&secret).ok()?;
        hkdf_expand_label(&expand, key_label, &mut keys.key).ok()?;
        hkdf_expand_label(&expand, iv_label, &mut keys.iv).ok()?;
        hkdf_expand_label(&expand, hp_label, &mut keys.hp).ok()?;
        Some(keys)
    }
}

/// Read a QUIC variable-length integer (RFC 9000 §16).
/// Returns `(value, next position)`.
fn read_varint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let first = *data.get(pos)?;
    let len = 1usize << (first >> 6);
    let bytes = data.get(pos..pos.checked_add(len)?)?;
    let mut value = u64::from(bytes[0] & 0x3f);
    for &b in &bytes[1..] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, pos + len))
}

/// Parsed QUIC long header of an Initial packet.
struct LongHeader<'a> {
    version: u32,
    dcid: &'a [u8],
    /// Offset of the packet number field within the packet.
    pn_offset: usize,
    /// Offset just past this packet (`pn_offset` + Length field value).
    packet_end: usize,
}

/// Parse a long header and check that it belongs to an Initial packet of a
/// supported version. Returns `None` for short headers, version-negotiation
/// packets, unsupported versions, and non-Initial long-header packets.
fn parse_long_header(packet: &[u8]) -> Option<LongHeader<'_>> {
    // Header form (0x80) and fixed bit (0x40) must both be set.
    if packet.len() < 7 || packet[0] & 0xc0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes(packet[1..5].try_into().ok()?);
    // Initial packet type: 0b00 for v1 (RFC 9000 §17.2.2), 0b01 for v2
    // (RFC 9369 §3.1).
    let initial_type = match version {
        QUIC_VERSION_1 => 0,
        QUIC_VERSION_2 => 1,
        _ => return None,
    };
    if (packet[0] >> 4) & 0x03 != initial_type {
        return None;
    }

    let mut pos = 5;
    let dcid_len = usize::from(*packet.get(pos)?);
    if dcid_len > 20 {
        return None;
    }
    pos += 1;
    let dcid = packet.get(pos..pos.checked_add(dcid_len)?)?;
    pos += dcid_len;

    let scid_len = usize::from(*packet.get(pos)?);
    if scid_len > 20 {
        return None;
    }
    pos = pos.checked_add(1 + scid_len)?;

    let (token_len, next) = read_varint(packet, pos)?;
    pos = next.checked_add(token_len as usize)?;
    let (length, next) = read_varint(packet, pos)?;
    let pn_offset = next;
    let packet_end = pn_offset.checked_add(length as usize)?;
    if packet_end > packet.len() {
        return None;
    }
    Some(LongHeader {
        version,
        dcid,
        pn_offset,
        packet_end,
    })
}

/// Remove header protection and AEAD-decrypt one Initial packet.
/// Returns the packet number and the plaintext payload (QUIC frames).
fn decrypt_initial(
    keys: &InitialKeys,
    packet: &[u8],
    hdr: &LongHeader<'_>,
) -> Option<(u64, Vec<u8>)> {
    let pn_offset = hdr.pn_offset;
    // The 16-byte sample starts 4 bytes after the packet number field
    // begins (RFC 9001 §5.4.2).
    let sample: &[u8; 16] = packet
        .get(pn_offset.checked_add(4)?..pn_offset.checked_add(20)?)?
        .try_into()
        .ok()?;

    let hp_cipher = Aes128::new_from_slice(&keys.hp).ok()?;
    let mut mask = AesBlock::from(*sample);
    hp_cipher.encrypt_block(&mut mask);

    // Unprotect: long headers use the low 4 bits of mask[0]; the packet
    // number length is the low 2 bits of the unprotected first byte, + 1.
    let mut header = packet.get(..pn_offset.checked_add(4)?)?.to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(header[0] & 0x03) + 1;
    let mut packet_number = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        packet_number = (packet_number << 8) | u64::from(header[pn_offset + i]);
    }
    header.truncate(pn_offset + pn_len);

    // Nonce: IV XOR packet number, left-padded to 64 bits (RFC 9001 §5.3).
    // The truncated packet number is used as-is; for Initial packets at the
    // start of a connection the full number always fits its encoding, so no
    // RFC 9000 §A.3 reconstruction context is needed.
    let mut nonce = keys.iv;
    for (i, b) in packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }

    let ciphertext = packet.get(pn_offset + pn_len..hdr.packet_end)?;
    if ciphertext.len() < GCM_TAG_LEN {
        return None;
    }
    let aead = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    let payload = aead
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &header,
            },
        )
        .ok()?;
    Some((packet_number, payload))
}

/// Walk the plaintext frames of an Initial packet and collect CRYPTO frame
/// payloads as `(stream offset, data)` fragments.
///
/// Only frame types that may legally appear in Initial packets are
/// understood (RFC 9000 §17.2.2): PADDING, PING, ACK, CRYPTO and
/// CONNECTION_CLOSE. On any other (or malformed) frame the walk stops and
/// the fragments collected so far are kept.
fn collect_crypto_frames(payload: &[u8], out: &mut Vec<(u64, Vec<u8>)>) {
    let mut pos = 0;
    while pos < payload.len() {
        let frame_type = payload[pos];
        pos += 1;
        match frame_type {
            0x00 => {} // PADDING
            0x01 => {} // PING
            0x02 | 0x03 => {
                // ACK (with ECN counts for 0x03)
                let Some(next) = skip_ack_frame(payload, pos, frame_type == 0x03) else {
                    break;
                };
                pos = next;
            }
            0x06 => {
                // CRYPTO
                let Some((offset, next)) = read_varint(payload, pos) else {
                    break;
                };
                let Some((len, next)) = read_varint(payload, next) else {
                    break;
                };
                let Some(end) = next.checked_add(len as usize) else {
                    break;
                };
                let Some(data) = payload.get(next..end) else {
                    break;
                };
                out.push((offset, data.to_vec()));
                pos = end;
            }
            0x1c | 0x1d => {
                // CONNECTION_CLOSE (carries a frame type for 0x1c)
                let Some(next) = skip_connection_close_frame(payload, pos, frame_type == 0x1c)
                else {
                    break;
                };
                pos = next;
            }
            // Any other frame type is a protocol violation in an Initial
            // packet; its length cannot be determined, so stop here.
            _ => break,
        }
    }
}

/// Skip an ACK frame body starting at `pos`; returns the position past it.
fn skip_ack_frame(payload: &[u8], mut pos: usize, has_ecn: bool) -> Option<usize> {
    let (_, next) = read_varint(payload, pos)?; // largest acknowledged
    let (_, next) = read_varint(payload, next)?; // ACK delay
    let (range_count, next) = read_varint(payload, next)?;
    let (_, next) = read_varint(payload, next)?; // first ACK range
    pos = next;
    for _ in 0..range_count {
        let (_, next) = read_varint(payload, pos)?; // gap
        let (_, next) = read_varint(payload, next)?; // ACK range length
        pos = next;
    }
    if has_ecn {
        for _ in 0..3 {
            let (_, next) = read_varint(payload, pos)?; // ECN counts
            pos = next;
        }
    }
    Some(pos)
}

/// Skip a CONNECTION_CLOSE frame body starting at `pos`.
fn skip_connection_close_frame(
    payload: &[u8],
    mut pos: usize,
    has_frame_type: bool,
) -> Option<usize> {
    let (_, next) = read_varint(payload, pos)?; // error code
    pos = next;
    if has_frame_type {
        let (_, next) = read_varint(payload, pos)?; // frame type
        pos = next;
    }
    let (reason_len, next) = read_varint(payload, pos)?;
    next.checked_add(reason_len as usize)
        .filter(|&end| end <= payload.len())
}

/// Decrypt every Initial packet in a (possibly coalesced) UDP datagram and
/// return the CRYPTO fragments it carries, in arrival order.
///
/// Returns `Err(QuicDecryptError::NotInitial)` when the first packet is not
/// a supported Initial, and `Err(QuicDecryptError::DecryptFailed)` when it
/// is but cannot be decrypted. Failures of *trailing* coalesced packets
/// (e.g. 0-RTT or Handshake packets we cannot decrypt) are tolerated: the
/// fragments already collected are returned.
pub(crate) fn decrypt_initial_datagram(
    datagram: &[u8],
) -> Result<Vec<(u64, Vec<u8>)>, QuicDecryptError> {
    let mut fragments = Vec::new();
    let mut rest = datagram;
    loop {
        let Some(hdr) = parse_long_header(rest) else {
            return if fragments.is_empty() {
                Err(QuicDecryptError::NotInitial)
            } else {
                Ok(fragments)
            };
        };
        let keys = InitialKeys::derive_client(hdr.dcid, hdr.version)
            .ok_or(QuicDecryptError::NotInitial)?;
        match decrypt_initial(&keys, rest, &hdr) {
            Some((_, payload)) => collect_crypto_frames(&payload, &mut fragments),
            None => {
                return if fragments.is_empty() {
                    Err(QuicDecryptError::DecryptFailed)
                } else {
                    Ok(fragments)
                };
            }
        }
        rest = &rest[hdr.packet_end..];
        if rest.is_empty() {
            return Ok(fragments);
        }
    }
}

/// Reassembles the CRYPTO stream from out-of-order fragments.
///
/// Bytes become visible through [`CryptoReassembly::assembled`] only once
/// they form a contiguous prefix starting at stream offset 0, which is all
/// the ClientHello parser needs.
#[derive(Default)]
pub(crate) struct CryptoReassembly {
    /// Contiguous stream bytes starting at offset 0.
    assembled: Vec<u8>,
    /// Fragments past the end of `assembled`, keyed by stream offset.
    fragments: BTreeMap<u64, Vec<u8>>,
    /// Total bytes held in `fragments` (DoS guard).
    buffered: usize,
    /// Set once the stream exceeds [`MAX_CRYPTO_STREAM`]; further inserts
    /// are dropped.
    overflowed: bool,
}

impl CryptoReassembly {
    /// Insert a CRYPTO fragment at `offset`. Duplicate or fully-covered
    /// fragments are ignored.
    pub(crate) fn insert(&mut self, mut offset: u64, mut data: Vec<u8>) {
        if self.overflowed {
            return;
        }
        let assembled_len = self.assembled.len() as u64;
        if offset < assembled_len {
            // Trim the part already covered by the assembled prefix.
            let skip = (assembled_len - offset) as usize;
            if skip >= data.len() {
                return;
            }
            data.drain(..skip);
            offset = assembled_len;
        }
        if data.len() > MAX_CRYPTO_STREAM || self.buffered + data.len() > MAX_CRYPTO_STREAM {
            self.overflowed = true;
            self.fragments.clear();
            self.buffered = 0;
            return;
        }
        self.buffered += data.len();
        if let Some(old) = self.fragments.insert(offset, data) {
            self.buffered -= old.len();
        }
        self.drain_contiguous();
    }

    /// Move fragments that extend the assembled prefix into it.
    fn drain_contiguous(&mut self) {
        while let Some(&offset) = self.fragments.keys().next() {
            let assembled_len = self.assembled.len() as u64;
            if offset > assembled_len {
                break;
            }
            let Some((_, mut fragment)) = self.fragments.pop_first() else {
                break;
            };
            self.buffered = self.buffered.saturating_sub(fragment.len());
            let skip = (assembled_len - offset) as usize;
            if skip < fragment.len() {
                fragment.drain(..skip);
                self.assembled.extend_from_slice(&fragment);
            }
        }
        if self.assembled.len() > MAX_CRYPTO_STREAM {
            self.overflowed = true;
            self.fragments.clear();
            self.buffered = 0;
        }
    }

    /// The contiguous stream bytes starting at offset 0 collected so far.
    pub(crate) fn assembled(&self) -> &[u8] {
        &self.assembled
    }

    /// Whether the stream exceeded the safety cap.
    pub(crate) fn is_overflowed(&self) -> bool {
        self.overflowed
    }
}

/// Result of parsing the reassembled CRYPTO stream prefix as a TLS
/// ClientHello handshake message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientHelloParse {
    /// Not enough CRYPTO data yet; wait for more Initial packets.
    Incomplete,
    /// The ClientHello is complete; carries the SNI hostname when present.
    Complete(Option<String>),
    /// The stream does not start with a well-formed ClientHello.
    Invalid,
}

/// Parse the TLS ClientHello at the start of the reassembled CRYPTO stream.
///
/// QUIC carries TLS handshake messages directly in CRYPTO frames (no TLS
/// record header, RFC 9001 §4.1.3), so the stream starts with a 1-byte
/// handshake type and a 3-byte length.
pub(crate) fn parse_client_hello(stream: &[u8]) -> ClientHelloParse {
    if stream.len() < 4 {
        return ClientHelloParse::Incomplete;
    }
    if stream[0] != 0x01 {
        return ClientHelloParse::Invalid; // handshake type: ClientHello
    }
    let hs_len = u32::from_be_bytes([0, stream[1], stream[2], stream[3]]) as usize;
    if hs_len > MAX_CRYPTO_STREAM {
        return ClientHelloParse::Invalid;
    }
    if stream.len() < 4 + hs_len {
        return ClientHelloParse::Incomplete;
    }
    ClientHelloParse::Complete(crate::sniffing::parse_client_hello_body(
        &stream[4..4 + hs_len],
    ))
}

#[cfg(test)]
pub(crate) mod test_utils {
    //! Shared helpers for QUIC sniffer tests: RFC test vectors, a TLS
    //! ClientHello builder, and the encryption-side mirror of the
    //! decryption pipeline for round-trip tests.
    use super::*;

    /// Decode a hex string, ignoring whitespace.
    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert!(digits.len().is_multiple_of(2), "odd-length hex string");
        digits
            .chunks(2)
            .map(|c| {
                let hi = (c[0] as char).to_digit(16).expect("invalid hex") as u8;
                let lo = (c[1] as char).to_digit(16).expect("invalid hex") as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    /// RFC 9001 A.2 protected client Initial packet (DCID 0x8394c8f03e515708,
    /// packet number 2), whose CRYPTO frame carries a ClientHello for
    /// "example.com".
    pub(crate) fn rfc9001_client_initial() -> Vec<u8> {
        unhex(include_str!("quic_testdata/rfc9001_client_initial.hex"))
    }

    /// Build a TLS ClientHello handshake message (type + 3-byte length +
    /// body), optionally carrying an SNI extension.
    pub(crate) fn build_client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(sni) = sni {
            let name = sni.as_bytes();
            extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
            let ext_len = 2 + 1 + 2 + name.len();
            extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());
            extensions.extend_from_slice(&((1 + 2 + name.len()) as u16).to_be_bytes());
            extensions.push(0x00); // name type: host_name
            extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
            extensions.extend_from_slice(name);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version: TLS 1.2
        body.extend_from_slice(&[0x42u8; 32]); // random
        body.push(0); // session id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
        body.push(1); // compression methods length
        body.push(0); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut msg = vec![0x01]; // handshake type: ClientHello
        let len = body.len();
        msg.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        msg.extend_from_slice(&body);
        msg
    }

    /// Encode a QUIC variable-length integer.
    pub(crate) fn encode_varint(value: u64) -> Vec<u8> {
        if value < 1 << 6 {
            vec![value as u8]
        } else if value < 1 << 14 {
            (value as u16 | 0x4000).to_be_bytes().to_vec()
        } else if value < 1 << 30 {
            (value as u32 | 0x8000_0000).to_be_bytes().to_vec()
        } else {
            (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec()
        }
    }

    /// Wrap `data` in a CRYPTO frame at stream `offset`.
    pub(crate) fn wrap_crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x06];
        out.extend_from_slice(&encode_varint(offset));
        out.extend_from_slice(&encode_varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }

    /// Encrypt `plaintext` frames into a protected Initial packet: the
    /// encryption-side mirror of [`decrypt_initial_datagram`], used for
    /// round-trip tests.
    pub(crate) fn protect_initial_packet(
        dcid: &[u8],
        scid: &[u8],
        version: u32,
        pn: u64,
        pn_len: usize,
        plaintext: &[u8],
    ) -> Vec<u8> {
        assert!((1..=4).contains(&pn_len));
        let keys = InitialKeys::derive_client(dcid, version).expect("unsupported version");

        let mut header = Vec::new();
        // Long header | fixed bit | Initial type | pn_len - 1.
        let type_bits = if version == QUIC_VERSION_2 {
            0xd0
        } else {
            0xc0
        };
        header.push(type_bits | (pn_len as u8 - 1));
        header.extend_from_slice(&version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(scid.len() as u8);
        header.extend_from_slice(scid);
        header.push(0); // token length
        header.extend_from_slice(&encode_varint(
            (pn_len + plaintext.len() + GCM_TAG_LEN) as u64,
        ));
        let pn_offset = header.len();
        for i in 0..pn_len {
            header.push((pn >> (8 * (pn_len - 1 - i))) as u8);
        }

        // AEAD-encrypt with the unprotected header as AAD.
        let mut nonce = keys.iv;
        for (i, b) in pn.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        let aead = Aes128Gcm::new_from_slice(&keys.key).expect("bad key length");
        let mut ciphertext = aead
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .expect("AEAD encrypt failed");

        let mut packet = header;
        packet.append(&mut ciphertext);
        assert!(
            packet.len() >= pn_offset + 20,
            "payload too short for header-protection sample"
        );

        // Apply header protection.
        let hp_cipher = Aes128::new_from_slice(&keys.hp).expect("bad hp length");
        let sample: &[u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
        let mut mask = AesBlock::from(*sample);
        hp_cipher.encrypt_block(&mut mask);
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::*;

    /// The client-chosen DCID shared by all RFC 9001/9369 Appendix A samples.
    const RFC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    #[test]
    fn rfc9001_a1_key_derivation() {
        let keys = InitialKeys::derive_client(&RFC_DCID, QUIC_VERSION_1).unwrap();
        assert_eq!(
            keys.key.as_slice(),
            unhex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(keys.iv.as_slice(), unhex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(
            keys.hp.as_slice(),
            unhex("9f50449e04a0e810283a1e9933adedd2")
        );

        let server = InitialKeys::derive(&RFC_DCID, QUIC_VERSION_1, b"server in").unwrap();
        assert_eq!(
            server.key.as_slice(),
            unhex("cf3a5331653c364c88f0f379b6067e37")
        );
        assert_eq!(server.iv.as_slice(), unhex("0ac1493ca1905853b0bba03e"));
        assert_eq!(
            server.hp.as_slice(),
            unhex("c206b8d9b9f0f37644430b490eeaa314")
        );
    }

    #[test]
    fn rfc9369_a1_key_derivation() {
        let keys = InitialKeys::derive_client(&RFC_DCID, QUIC_VERSION_2).unwrap();
        assert_eq!(
            keys.key.as_slice(),
            unhex("8b1a0bc121284290a29e0971b5cd045d")
        );
        assert_eq!(keys.iv.as_slice(), unhex("91f73e2351d8fa91660e909f"));
        assert_eq!(
            keys.hp.as_slice(),
            unhex("45b95e15235d6f45a6b19cbcb0294ba9")
        );

        let server = InitialKeys::derive(&RFC_DCID, QUIC_VERSION_2, b"server in").unwrap();
        assert_eq!(
            server.key.as_slice(),
            unhex("82db637861d55e1d011f19ea71d5d2a7")
        );
        assert_eq!(server.iv.as_slice(), unhex("dd13c276499c0249d3310652"));
        assert_eq!(
            server.hp.as_slice(),
            unhex("edf6d05c83121201b436e16877593c3a")
        );
    }

    /// RFC 9001 A.2: decrypt the sample client Initial and extract the SNI
    /// from its ClientHello ("example.com").
    #[test]
    fn rfc9001_a2_client_initial_decrypt() {
        let packet = rfc9001_client_initial();
        assert_eq!(packet.len(), 1200);

        let hdr = parse_long_header(&packet).unwrap();
        assert_eq!(hdr.version, QUIC_VERSION_1);
        assert_eq!(hdr.dcid, RFC_DCID);
        assert_eq!(hdr.pn_offset, 18);
        assert_eq!(hdr.packet_end, 1200);

        let keys = InitialKeys::derive_client(hdr.dcid, hdr.version).unwrap();
        let (pn, payload) = decrypt_initial(&keys, &packet, &hdr).unwrap();
        assert_eq!(pn, 2);
        assert_eq!(payload.len(), 1162);

        // The plaintext is the RFC's CRYPTO frame followed by PADDING.
        let expected_prefix = unhex(include_str!("quic_testdata/rfc9001_client_payload.hex"));
        assert!(payload.starts_with(&expected_prefix));
        assert!(payload[expected_prefix.len()..].iter().all(|&b| b == 0));

        let mut fragments = Vec::new();
        collect_crypto_frames(&payload, &mut fragments);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].0, 0);
        assert_eq!(fragments[0].1.len(), 241);

        // Full datagram path → ClientHello → SNI.
        let fragments = decrypt_initial_datagram(&packet).unwrap();
        let mut reasm = CryptoReassembly::default();
        for (offset, data) in fragments {
            reasm.insert(offset, data);
        }
        assert_eq!(
            parse_client_hello(reasm.assembled()),
            ClientHelloParse::Complete(Some("example.com".to_string()))
        );
    }

    /// RFC 9001 A.3: the server Initial starts with an ACK frame, which the
    /// frame walker must skip before reaching the CRYPTO frame.
    #[test]
    fn rfc9001_a3_server_initial_decrypt() {
        let packet = unhex(include_str!("quic_testdata/rfc9001_server_initial.hex"));
        let hdr = parse_long_header(&packet).unwrap();
        // Server Initial keys derive from the *client-chosen* DCID, not the
        // DCID of this packet (which is the client's SCID).
        let keys = InitialKeys::derive(&RFC_DCID, QUIC_VERSION_1, b"server in").unwrap();
        let (pn, payload) = decrypt_initial(&keys, &packet, &hdr).unwrap();
        assert_eq!(pn, 1);

        let expected = unhex(include_str!("quic_testdata/rfc9001_server_payload.hex"));
        assert_eq!(payload, expected);

        let mut fragments = Vec::new();
        collect_crypto_frames(&payload, &mut fragments);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].0, 0);
        assert_eq!(fragments[0].1.len(), 90);
    }

    /// RFC 9369 A.2: QUIC v2 client Initial (different salt, HKDF labels,
    /// and packet type mapping), same ClientHello → "example.com".
    #[test]
    fn rfc9369_a2_client_initial_decrypt() {
        let packet = unhex(include_str!("quic_testdata/rfc9369_client_initial.hex"));
        assert_eq!(packet.len(), 1200);

        let hdr = parse_long_header(&packet).unwrap();
        assert_eq!(hdr.version, QUIC_VERSION_2);
        assert_eq!(hdr.dcid, RFC_DCID);

        let keys = InitialKeys::derive_client(hdr.dcid, hdr.version).unwrap();
        let (pn, payload) = decrypt_initial(&keys, &packet, &hdr).unwrap();
        assert_eq!(pn, 2);

        let expected_prefix = unhex(include_str!("quic_testdata/rfc9001_client_payload.hex"));
        assert!(payload.starts_with(&expected_prefix));

        let fragments = decrypt_initial_datagram(&packet).unwrap();
        let mut reasm = CryptoReassembly::default();
        for (offset, data) in fragments {
            reasm.insert(offset, data);
        }
        assert_eq!(
            parse_client_hello(reasm.assembled()),
            ClientHelloParse::Complete(Some("example.com".to_string()))
        );
    }

    /// RFC 9369 A.3: QUIC v2 server Initial (ACK + CRYPTO).
    #[test]
    fn rfc9369_a3_server_initial_decrypt() {
        let packet = unhex(include_str!("quic_testdata/rfc9369_server_initial.hex"));
        let hdr = parse_long_header(&packet).unwrap();
        assert_eq!(hdr.version, QUIC_VERSION_2);
        let keys = InitialKeys::derive(&RFC_DCID, QUIC_VERSION_2, b"server in").unwrap();
        let (pn, payload) = decrypt_initial(&keys, &packet, &hdr).unwrap();
        assert_eq!(pn, 1);
        let expected = unhex(include_str!("quic_testdata/rfc9001_server_payload.hex"));
        assert_eq!(payload, expected);
    }

    #[test]
    fn protect_decrypt_roundtrip() {
        for pn_len in 1..=4 {
            let hello = build_client_hello(Some("roundtrip.test"));
            let frame = wrap_crypto_frame(0, &hello);
            let packet =
                protect_initial_packet(b"01234567", b"abcd", QUIC_VERSION_1, 7, pn_len, &frame);
            let fragments = decrypt_initial_datagram(&packet).unwrap();
            assert_eq!(fragments.len(), 1, "pn_len={pn_len}");
            assert_eq!(fragments[0].1, hello, "pn_len={pn_len}");
        }
        // v2 roundtrip (also exercises the 0b01 Initial type mapping).
        let hello = build_client_hello(Some("v2.roundtrip.test"));
        let frame = wrap_crypto_frame(0, &hello);
        let packet = protect_initial_packet(b"01234567", b"", QUIC_VERSION_2, 0, 1, &frame);
        let fragments = decrypt_initial_datagram(&packet).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].1, hello);
    }

    #[test]
    fn coalesced_datagram_stops_at_non_initial() {
        // An Initial coalesced with a trailing packet that is not an Initial
        // (here: a v1 Handshake packet, type 0b10): its fragments are kept.
        let hello = build_client_hello(Some("coalesced.test"));
        let frame = wrap_crypto_frame(0, &hello);
        let initial = protect_initial_packet(b"01234567", b"", QUIC_VERSION_1, 0, 1, &frame);
        let mut datagram = initial;
        datagram.extend_from_slice(&[0xe0, 0, 0, 0, 1]); // start of a Handshake packet
        let fragments = decrypt_initial_datagram(&datagram).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].1, hello);
    }

    #[test]
    fn reassembly_out_of_order_and_duplicate() {
        let mut reasm = CryptoReassembly::default();
        reasm.insert(10, b"defghij".to_vec());
        assert!(reasm.assembled().is_empty());
        reasm.insert(0, b"abc".to_vec());
        assert_eq!(reasm.assembled(), b"abc");
        reasm.insert(3, b"defgh".to_vec()); // overlaps assembled prefix
        assert_eq!(reasm.assembled(), b"abcdefgh");
        // Duplicate of an already-covered range is ignored.
        reasm.insert(0, b"abc".to_vec());
        assert_eq!(reasm.assembled(), b"abcdefgh");
        // Fragment overlapping both prefix and buffered fragment; the
        // buffered fragment at offset 10 drains right behind it.
        reasm.insert(5, b"fghij".to_vec());
        assert_eq!(reasm.assembled(), b"abcdefghijdefghij");
    }

    #[test]
    fn reassembly_overflow_capped() {
        let mut reasm = CryptoReassembly::default();
        reasm.insert(0, vec![0u8; MAX_CRYPTO_STREAM + 1]);
        assert!(reasm.is_overflowed());
        // After overflow, further inserts are dropped.
        reasm.insert(0, b"abc".to_vec());
        assert!(reasm.assembled().is_empty());
    }

    #[test]
    fn corrupted_tag_fails_aead() {
        let mut packet = rfc9001_client_initial();
        let last = packet.len() - 1;
        packet[last] ^= 0x01; // flip a bit inside the GCM tag
        assert_eq!(
            decrypt_initial_datagram(&packet),
            Err(QuicDecryptError::DecryptFailed)
        );
    }

    #[test]
    fn non_initial_packets_rejected() {
        // Short header.
        assert_eq!(
            decrypt_initial_datagram(&[0x40, 1, 2, 3, 4, 5, 6, 7]),
            Err(QuicDecryptError::NotInitial)
        );
        // Buffer too short.
        assert_eq!(
            decrypt_initial_datagram(&[0xc0]),
            Err(QuicDecryptError::NotInitial)
        );
        // Version negotiation (version 0).
        let mut vn = vec![0xc0, 0, 0, 0, 0];
        vn.extend_from_slice(&[8, 1, 2, 3, 4, 5, 6, 7, 8, 0]);
        assert_eq!(
            decrypt_initial_datagram(&vn),
            Err(QuicDecryptError::NotInitial)
        );
        // Unsupported version.
        let mut uv = vec![0xc0, 0x0a, 0x0a, 0x0a, 0x0a];
        uv.extend_from_slice(&[8, 1, 2, 3, 4, 5, 6, 7, 8, 0]);
        assert_eq!(
            decrypt_initial_datagram(&uv),
            Err(QuicDecryptError::NotInitial)
        );
        // v1 long header, Handshake type (0b10) instead of Initial.
        let mut hs = vec![0xe0, 0, 0, 0, 1];
        hs.extend_from_slice(&[8, 1, 2, 3, 4, 5, 6, 7, 8, 0]);
        assert_eq!(
            decrypt_initial_datagram(&hs),
            Err(QuicDecryptError::NotInitial)
        );
    }

    #[test]
    fn parse_client_hello_states() {
        let hello = build_client_hello(Some("states.test"));
        // Truncated handshake → Incomplete.
        assert_eq!(
            parse_client_hello(&hello[..2]),
            ClientHelloParse::Incomplete
        );
        assert_eq!(
            parse_client_hello(&hello[..hello.len() - 1]),
            ClientHelloParse::Incomplete
        );
        // Full message → SNI.
        assert_eq!(
            parse_client_hello(&hello),
            ClientHelloParse::Complete(Some("states.test".to_string()))
        );
        // Not a ClientHello handshake type → Invalid.
        let mut bad = hello.clone();
        bad[0] = 0x02; // ServerHello
        assert_eq!(parse_client_hello(&bad), ClientHelloParse::Invalid);
        // Absurd handshake length → Invalid.
        let mut huge = hello;
        huge[1] = 0xff;
        huge[2] = 0xff;
        huge[3] = 0xff;
        assert_eq!(parse_client_hello(&huge), ClientHelloParse::Invalid);
    }

    #[test]
    fn varint_encoding() {
        // 1-byte: 0..63
        assert_eq!(read_varint(&[0x00], 0), Some((0, 1)));
        assert_eq!(read_varint(&[0x3f], 0), Some((63, 1)));
        // 2-byte: 64..16383
        assert_eq!(read_varint(&[0x40, 0x7f], 0), Some((127, 2)));
        assert_eq!(read_varint(&[0x7f, 0xff], 0), Some((16383, 2)));
        // 4-byte
        assert_eq!(
            read_varint(&[0x80, 0x01, 0x00, 0x00], 0),
            Some((0x0001_0000, 4))
        );
        // 8-byte
        assert_eq!(
            read_varint(&[0xc0, 0, 0, 0, 0, 0, 0, 0x01], 0),
            Some((1, 8))
        );
        // Truncated
        assert_eq!(read_varint(&[0x40], 0), None);
        assert_eq!(read_varint(&[], 0), None);
        // Roundtrip with the encoder
        for v in [0u64, 63, 64, 16383, 16384, 1 << 30, u64::from(u32::MAX)] {
            let enc = encode_varint(v);
            assert_eq!(read_varint(&enc, 0), Some((v, enc.len())));
        }
    }
}
