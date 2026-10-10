//! Shared DNS wire-format parsing helpers.
//!
//! Bounds-checked walkers over raw DNS messages, used by both the userspace
//! DNS forwarder and the control plane's interception path. All helpers are
//! lenient: they extract what can be parsed and never panic on malformed
//! packets.

use std::net::IpAddr;

/// Advance `pos` past a DNS name (handling label sequences and
/// compression pointers). Returns `false` on malformed data.
pub(crate) fn skip_dns_name(data: &[u8], pos: &mut usize) -> bool {
    loop {
        if *pos >= data.len() {
            return false;
        }
        let len = data[*pos];
        if len == 0 {
            *pos += 1;
            return true;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer — advance past the 2-byte pointer
            if *pos + 2 > data.len() {
                return false;
            }
            *pos += 2;
            return true;
        }
        if len > 63 {
            return false;
        }
        *pos += 1 + len as usize;
        if *pos > data.len() {
            return false;
        }
    }
}

/// Extract A/AAAA answer IPs from a wire-format DNS response.
pub(crate) fn extract_ips_from_dns_response(response: &[u8]) -> Vec<IpAddr> {
    extract_ips_with_ttl(response)
        .into_iter()
        .map(|(ip, _)| ip)
        .collect()
}

/// Extract A/AAAA answer records as `(ip, ttl)` pairs from a wire-format
/// DNS response. Non-address record types are skipped.
pub(crate) fn extract_ips_with_ttl(response: &[u8]) -> Vec<(IpAddr, u32)> {
    extract_ips_with_ttl_bounded(response, usize::MAX)
}

pub(crate) fn extract_ips_with_ttl_bounded(response: &[u8], limit: usize) -> Vec<(IpAddr, u32)> {
    let mut out = Vec::new();
    if response.len() < 12 {
        return out;
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut pos = 12;

    for _ in 0..qdcount {
        if !skip_dns_name(response, &mut pos) {
            return out;
        }
        pos += 4; // QTYPE + QCLASS
        if pos > response.len() {
            return out;
        }
    }

    for _ in 0..ancount {
        if out.len() == limit {
            break;
        }
        if !skip_dns_name(response, &mut pos) {
            break;
        }
        if pos + 10 > response.len() {
            break;
        }
        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > response.len() {
            break;
        }
        match rtype {
            1 if rdlength == 4 => {
                let ip = std::net::Ipv4Addr::new(
                    response[pos],
                    response[pos + 1],
                    response[pos + 2],
                    response[pos + 3],
                );
                out.push((IpAddr::V4(ip), ttl));
            }
            28 if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&response[pos..pos + 16]);
                out.push((IpAddr::V6(std::net::Ipv6Addr::from(octets)), ttl));
            }
            _ => {}
        }
        pos += rdlength;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal response for example.com with one answer record.
    /// The answer NAME is a compression pointer to the question.
    fn make_response(qtype: u16, rdata: &[u8], ttl: u32) -> Vec<u8> {
        let mut v = vec![
            0x00,
            0x00, // ID
            0x81,
            0x80, // Flags: QR=1, RD=1, RA=1
            0x00,
            0x01, // QDCOUNT
            0x00,
            0x01, // ANCOUNT
            0x00,
            0x00, // NSCOUNT
            0x00,
            0x00, // ARCOUNT
            0x07,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            0x03,
            b'c',
            b'o',
            b'm',
            0x00,
            0x00,
            qtype as u8, // QTYPE (fits in low byte for A/AAAA)
            0x00,
            0x01, // QCLASS IN
        ];
        // Answer: NAME = pointer to offset 12, TYPE, CLASS, TTL, RDLENGTH, RDATA
        v.extend_from_slice(&[0xC0, 0x0C]);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(rdata);
        v
    }

    #[test]
    fn test_skip_dns_name_plain() {
        let data = [0x03, b'w', b'w', b'w', 0x00, 0xFF];
        let mut pos = 0;
        assert!(skip_dns_name(&data, &mut pos));
        assert_eq!(pos, 5);
    }

    #[test]
    fn test_skip_dns_name_compression_pointer() {
        let data = [0xC0, 0x0C, 0xFF];
        let mut pos = 0;
        assert!(skip_dns_name(&data, &mut pos));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_skip_dns_name_malformed() {
        // Truncated mid-label
        let data = [0x05, b'a', b'b'];
        let mut pos = 0;
        assert!(!skip_dns_name(&data, &mut pos));
        // Truncated compression pointer
        let data = [0xC0];
        let mut pos = 0;
        assert!(!skip_dns_name(&data, &mut pos));
        // Invalid label length (0x40..0xBF)
        let data = [0x50, 0x00];
        let mut pos = 0;
        assert!(!skip_dns_name(&data, &mut pos));
        // Cursor past end
        let mut pos = 3;
        assert!(!skip_dns_name(&data, &mut pos));
    }

    #[test]
    fn test_extract_ips_a_and_aaaa() {
        let resp = make_response(1, &[1, 2, 3, 4], 60);
        assert_eq!(
            extract_ips_from_dns_response(&resp),
            vec![IpAddr::from([1, 2, 3, 4])]
        );

        let v6 = [0x20u8; 16];
        let resp = make_response(28, &v6, 120);
        let ips = extract_ips_with_ttl(&resp);
        assert_eq!(ips.len(), 1);
        assert!(ips[0].0.is_ipv6());
        assert_eq!(ips[0].1, 120);
    }

    #[test]
    fn test_extract_ips_skips_non_address_records() {
        // TXT answer: must not be collected, but must be walked past.
        let resp = make_response(16, &[0x03, b'f', b'o', b'o'], 60);
        assert!(extract_ips_from_dns_response(&resp).is_empty());
    }

    #[test]
    fn test_extract_ips_malformed() {
        assert!(extract_ips_from_dns_response(&[]).is_empty());
        assert!(extract_ips_from_dns_response(&[0u8; 11]).is_empty());
        // Truncated answer rdata
        let mut resp = make_response(1, &[1, 2, 3, 4], 60);
        resp.truncate(resp.len() - 2);
        assert!(extract_ips_from_dns_response(&resp).is_empty());
    }
}
