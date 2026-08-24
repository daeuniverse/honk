use std::io;

use rand::RngExt;

use crate::quic::recv_read_exact as read_exact;

/// Auth request target: `POST https://hysteria/auth` (`protocol/http.go:8-10`).
pub(super) const URL_HOST: &str = "hysteria";
pub(super) const URL_PATH: &str = "/auth";

pub(super) const HEADER_AUTH: &str = "hysteria-auth";
pub(super) const HEADER_UDP: &str = "hysteria-udp";
pub(super) const HEADER_CC_RX: &str = "hysteria-cc-rx";
pub(super) const HEADER_PADDING: &str = "hysteria-padding";

/// Authentication success status (`protocol/http.go:17`).
pub(super) const STATUS_AUTH_OK: u16 = 233;

/// TCP request frame type on a client bi stream (`protocol/proxy.go:16`).
pub(super) const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// DoS guards mirrored from `protocol/proxy.go:19-24`.
pub(super) const MAX_ADDRESS_LENGTH: u64 = 2048;
pub(super) const MAX_MESSAGE_LENGTH: u64 = 2048;
pub(super) const MAX_PADDING_LENGTH: u64 = 4096;
pub(super) const MAX_UDP_SIZE: usize = 4096;

/// Padding ranges (`protocol/padding.go:26-31`).
pub(super) const AUTH_PADDING_MIN: usize = 256;
pub(super) const AUTH_PADDING_MAX: usize = 2048;
pub(super) const TCP_PADDING_MIN: usize = 64;
pub(super) const TCP_PADDING_MAX: usize = 512;

/// Generous cap for one HEADERS frame payload (the auth response is ~3 KB).
pub(super) const MAX_FIELD_SECTION: u64 = 64 * 1024;

// QUIC varints (RFC 9000 §16) — used by all hysteria2 stream/datagram framing.

pub(super) fn varint_len(value: u64) -> usize {
    if value <= 63 {
        1
    } else if value <= 16383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else {
        8
    }
}

pub(super) fn write_varint(out: &mut Vec<u8>, value: u64) {
    if value <= 63 {
        out.push(value as u8);
    } else if value <= 16383 {
        out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes());
    } else if value <= 1_073_741_823 {
        out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

pub(super) async fn read_varint_stream(recv: &mut quinn::RecvStream) -> io::Result<u64> {
    let mut first = [0u8; 1];
    read_exact(recv, &mut first).await?;
    let len = 1usize << (first[0] >> 6);
    let mut value = (first[0] & 0x3f) as u64;
    for _ in 1..len {
        let mut b = [0u8; 1];
        read_exact(recv, &mut b).await?;
        value = (value << 8) | b[0] as u64;
    }
    Ok(value)
}

pub(super) async fn skip_bytes(recv: &mut quinn::RecvStream, mut n: u64) -> io::Result<()> {
    let mut buf = [0u8; 512];
    while n > 0 {
        let chunk = n.min(buf.len() as u64) as usize;
        read_exact(recv, &mut buf[..chunk]).await?;
        n -= chunk as u64;
    }
    Ok(())
}

/// Random padding string from the padding alphabet
/// (`protocol/padding.go:7-24`), `max` exclusive like sing's range.
pub(super) fn random_padding(min: usize, max: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    let n = rng.random_range(min..max);
    (0..n)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

/// TCP request bytes for one bi stream (`protocol/proxy.go:69-85`): frame
/// type `0x401`, address as a varint-length-prefixed string, random padding.
pub(super) fn encode_tcp_request(addr: &str) -> Vec<u8> {
    let padding = random_padding(TCP_PADDING_MIN, TCP_PADDING_MAX);
    let mut out = Vec::with_capacity(8 + addr.len() + padding.len());
    write_varint(&mut out, FRAME_TYPE_TCP_REQUEST);
    write_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    write_varint(&mut out, padding.len() as u64);
    out.extend_from_slice(padding.as_bytes());
    out
}

/// One inbound UDP message (datagram), see `protocol/proxy.go:162-169`.
/// The address is informational; the relay keys sessions by target.
#[derive(Debug)]
pub(super) struct UdpInbound {
    pub(super) session_id: u32,
    pub(super) packet_id: u16,
    pub(super) frag_id: u8,
    pub(super) frag_total: u8,
    #[cfg(test)]
    pub(super) addr: String,
    pub(super) data: Vec<u8>,
}

/// Decode a UDP message datagram (`protocol/proxy.go:195-221`).
pub(super) fn decode_udp_message(data: &[u8]) -> Option<UdpInbound> {
    if data.len() < 9 {
        return None;
    }
    let session_id = u32::from_be_bytes(data[0..4].try_into().expect("len checked"));
    let packet_id = u16::from_be_bytes(data[4..6].try_into().expect("len checked"));
    let frag_id = data[6];
    let frag_total = data[7];
    if frag_total == 0 || frag_id >= frag_total {
        return None;
    }
    // Address vstring: QUIC varint length + bytes.
    let first = data[8];
    let len_len = 1usize << (first >> 6);
    if data.len() < 8 + len_len {
        return None;
    }
    let mut addr_len = (first & 0x3f) as u64;
    for &b in &data[9..8 + len_len] {
        addr_len = (addr_len << 8) | b as u64;
    }
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        return None;
    }
    let start = 8 + len_len;
    let addr_len = usize::try_from(addr_len).ok()?;
    let end = start.checked_add(addr_len)?;
    // The upstream parser requires at least one payload byte after the address.
    if data.len() <= end {
        return None;
    }
    let _addr = std::str::from_utf8(&data[start..end]).ok()?;
    Some(UdpInbound {
        session_id,
        packet_id,
        frag_id,
        frag_total,
        #[cfg(test)]
        addr: _addr.to_owned(),
        data: data[end..].to_vec(),
    })
}

/// Encode one UDP message datagram (`protocol/proxy.go:180-193`).
pub(super) fn encode_udp_message(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    addr: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + varint_len(addr.len() as u64) + addr.len() + data.len());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(frag_id);
    out.push(frag_total);
    write_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    out.extend_from_slice(data);
    out
}

/// Build the datagram sequence for one UDP payload, fragmenting like sing's
/// `fragUDPMessage` (`packet.go:87-116`): every fragment repeats the full
/// header (address included — the no-address optimization is marked
/// "not work in hysteria" upstream).
pub(super) fn fragment_udp_message(
    session_id: u32,
    packet_id: u16,
    addr: &str,
    data: &[u8],
    max_datagram: usize,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let header = 8 + varint_len(addr.len() as u64) + addr.len();
    if header + data.len() <= max_datagram {
        return Ok(vec![encode_udp_message(
            session_id, packet_id, 0, 1, addr, data,
        )]);
    }
    let chunk = max_datagram.saturating_sub(header);
    if chunk == 0 {
        anyhow::bail!("datagram MTU {max_datagram} too small for the UDP message header");
    }
    let frag_total = data.len().div_ceil(chunk);
    if frag_total > u8::MAX as usize {
        anyhow::bail!("UDP payload {} bytes needs too many fragments", data.len());
    }
    let mut out = Vec::with_capacity(frag_total);
    for (frag_id, piece) in data.chunks(chunk).enumerate() {
        out.push(encode_udp_message(
            session_id,
            packet_id,
            frag_id as u8,
            frag_total as u8,
            addr,
            piece,
        ));
    }
    Ok(out)
}
