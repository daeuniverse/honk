//! SOCKS5-style address codec shared by the proxy handlers.
//!
//! Wire format (RFC 1928 address field):
//!
//! ```text
//! IPv4:   ATYP(0x01) | 4 octets  | port(2)
//! Domain: ATYP(0x03) | len(1)    | domain | port(2)
//! IPv6:   ATYP(0x04) | 16 octets | port(2)
//! ```
//!
//! The trojan, shadowsocks (+2022), AnyTLS, Juicity, and TUIC handlers use
//! this address-then-port layout; TUIC selects different ATYP bytes through
//! [`AtypScheme`]. VMess also reuses that numbering table but writes the port
//! first. VLESS keeps its own encoding and is deliberately not unified here.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::AsyncReadExt;

/// SOCKS5 (RFC 1928) ATYP bytes.
pub(crate) const ATYP_IPV4: u8 = 0x01;
pub(crate) const ATYP_DOMAIN: u8 = 0x03;
pub(crate) const ATYP_IPV6: u8 = 0x04;

/// The ATYP numbering of a protocol variant. The address layout (address
/// bytes followed by a 2-byte big-endian port) is identical across
/// protocols; only the type bytes differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AtypScheme {
    pub(crate) ipv4: u8,
    pub(crate) domain: u8,
    pub(crate) ipv6: u8,
}

/// RFC 1928 / SOCKS5 numbering (trojan, shadowsocks, anytls, juicity, ...).
pub(crate) const ATYP_SOCKS5: AtypScheme = AtypScheme {
    ipv4: ATYP_IPV4,
    domain: ATYP_DOMAIN,
    ipv6: ATYP_IPV6,
};

/// V2Ray numbering used by VMess.
#[cfg(feature = "rprx")]
pub(crate) const ATYP_VMESS: AtypScheme = AtypScheme {
    ipv4: 0x01,
    domain: 0x02,
    ipv6: 0x03,
};

/// sing socksaddr numbering used by TUIC.
pub(crate) const ATYP_SING: AtypScheme = AtypScheme {
    ipv4: 0x01,
    domain: 0x00,
    ipv6: 0x02,
};

/// A target address in SOCKS5-style form: either a socket address or a
/// domain name plus port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SocksAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(String, u16),
}

impl SocksAddr {
    /// A domain override takes precedence over the IP form; the port always
    /// comes from `target`.
    pub(crate) fn new(target: SocketAddr, target_domain: Option<&str>) -> io::Result<Self> {
        if let Some(domain) = target_domain {
            if domain.is_empty() || domain.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "proxy target domain must contain 1..=255 bytes",
                ));
            }
            return Ok(SocksAddr::Domain(domain.to_string(), target.port()));
        }
        Ok(match target {
            SocketAddr::V4(v4) => SocksAddr::V4(v4),
            SocketAddr::V6(v6) => SocksAddr::V6(v6),
        })
    }

    /// Length of the encoded form in bytes (same for every ATYP scheme).
    pub(crate) fn encoded_len(&self) -> usize {
        match self {
            SocksAddr::V4(_) => 1 + 4 + 2,
            SocksAddr::V6(_) => 1 + 16 + 2,
            SocksAddr::Domain(d, _) => 1 + 1 + d.len() + 2,
        }
    }

    /// Append the SOCKS5-ATYP encoding to `out`.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        self.encode_with(out, ATYP_SOCKS5);
    }

    /// Append the encoding under a non-SOCKS5 ATYP numbering (VMess, TUIC).
    pub(crate) fn encode_with(&self, out: &mut Vec<u8>, scheme: AtypScheme) {
        match self {
            SocksAddr::V4(v4) => {
                out.push(scheme.ipv4);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocksAddr::V6(v6) => {
                out.push(scheme.ipv6);
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
            SocksAddr::Domain(domain, port) => {
                assert!(
                    !domain.is_empty() && domain.len() <= u8::MAX as usize,
                    "proxy wire domain must contain 1..=255 bytes"
                );
                out.push(scheme.domain);
                out.push(domain.len() as u8);
                out.extend_from_slice(domain.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// SOCKS5-ATYP encoding as a fresh vector.
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out);
        out
    }

    /// Decode an address under the given ATYP numbering, advancing the
    /// cursor past it.
    pub(crate) fn decode_with(cursor: &mut &[u8], scheme: AtypScheme) -> io::Result<Self> {
        let atyp = take(cursor, 1)?[0];
        Self::decode_body(atyp, cursor, scheme)
    }

    /// Decode the body (everything after the ATYP byte) from `cursor`.
    fn decode_body(atyp: u8, cursor: &mut &[u8], scheme: AtypScheme) -> io::Result<Self> {
        if atyp == scheme.ipv4 {
            let ip: [u8; 4] = take(cursor, 4)?.try_into().expect("slice length checked");
            let port = u16::from_be_bytes(take(cursor, 2)?.try_into().expect("len checked"));
            Ok(SocksAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
        } else if atyp == scheme.ipv6 {
            let ip: [u8; 16] = take(cursor, 16)?.try_into().expect("slice length checked");
            let port = u16::from_be_bytes(take(cursor, 2)?.try_into().expect("len checked"));
            Ok(SocksAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                port,
                0,
                0,
            )))
        } else if atyp == scheme.domain {
            let len = take(cursor, 1)?[0] as usize;
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy wire domain is empty",
                ));
            }
            let domain = take(cursor, len)?;
            let domain = std::str::from_utf8(domain)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .to_string();
            let port = u16::from_be_bytes(take(cursor, 2)?.try_into().expect("len checked"));
            Ok(SocksAddr::Domain(domain, port))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown address type {atyp:#x}"),
            ))
        }
    }

    /// Read the body of an address whose ATYP byte was already consumed,
    /// under the given ATYP numbering.
    pub(crate) async fn read_body<R: AsyncReadExt + Unpin>(
        atyp: u8,
        rd: &mut R,
        scheme: AtypScheme,
    ) -> io::Result<Self> {
        // Read the remaining bytes, then reuse the slice decoder so the
        // bounds checks live in exactly one place.
        let body = if atyp == scheme.ipv4 {
            let mut body = vec![0u8; 4 + 2];
            rd.read_exact(&mut body).await?;
            body
        } else if atyp == scheme.ipv6 {
            let mut body = vec![0u8; 16 + 2];
            rd.read_exact(&mut body).await?;
            body
        } else if atyp == scheme.domain {
            let mut len = [0u8; 1];
            rd.read_exact(&mut len).await?;
            let mut body = vec![0u8; 1 + len[0] as usize + 2];
            body[0] = len[0];
            rd.read_exact(&mut body[1..]).await?;
            body
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown address type {atyp:#x}"),
            ));
        };
        let mut cursor = &body[..];
        Self::decode_body(atyp, &mut cursor, scheme)
    }
}

/// Take `n` bytes off the front of `cursor`.
fn take<'a>(cursor: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    if cursor.len() < n {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short address",
        ));
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Ok(head)
}

/// Encode `target` (+ optional domain override) as SOCKS5-style wire bytes.
pub(crate) fn encode_address(
    target: SocketAddr,
    target_domain: Option<&str>,
) -> io::Result<Vec<u8>> {
    Ok(SocksAddr::new(target, target_domain)?.to_vec())
}

/// The name a shared association may put on the wire for one datagram: only
/// the one it was dialed by. sing-box 1.12.4 fixes its outbound's form by the
/// first destination, and a different name later tears the association down
/// (or black-holes it, for Shadowsocks), so any other name goes out as the
/// numeric `target`.
pub(crate) fn dialed_name<'a>(dialed: Option<&str>, domain: Option<&'a str>) -> Option<&'a str> {
    domain.filter(|name| dialed == Some(*name))
}

/// The real peer a reply naming `domain:port` stands for: `target` when that
/// is the name the association was dialed by, otherwise `None` and the caller
/// drops the frame, since any other name would need DNS. The match is
/// ASCII-case-insensitive, unlike the exact [`dialed_name`] on the send side,
/// because servers may fold the case of a name they echo.
pub(crate) fn dialed_domain_peer(
    dialed: Option<&str>,
    target: SocketAddr,
    domain: impl AsRef<[u8]>,
    port: u16,
) -> Option<SocketAddr> {
    (port == target.port() && dialed?.as_bytes().eq_ignore_ascii_case(domain.as_ref()))
        .then_some(target)
}

#[derive(Debug, thiserror::Error)]
#[error("unknown address type {0:#x}")]
pub(super) struct UnknownReplyAddressType(u8);

/// Read a SOCKS5 reply address without validating a domain before its frame
/// can be drained. Only the captured domain/port projects to `target`; an
/// unknown ATYP stays terminal.
pub(crate) async fn read_reply_source<R: AsyncReadExt + Unpin>(
    rd: &mut R,
    dialed: Option<&str>,
    target: SocketAddr,
) -> io::Result<Option<SocketAddr>> {
    match rd.read_u8().await? {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            rd.read_exact(&mut ip).await?;
            let port = rd.read_u16().await?;
            Ok(Some(SocketAddr::new(Ipv4Addr::from(ip).into(), port)))
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            rd.read_exact(&mut ip).await?;
            let port = rd.read_u16().await?;
            Ok(Some(SocketAddr::new(
                Ipv6Addr::from(ip).to_canonical(),
                port,
            )))
        }
        ATYP_DOMAIN => {
            let len = usize::from(rd.read_u8().await?);
            let mut name = [0u8; u8::MAX as usize];
            rd.read_exact(&mut name[..len]).await?;
            let port = rd.read_u16().await?;
            Ok(dialed_domain_peer(dialed, target, &name[..len], port))
        }
        atyp => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            UnknownReplyAddressType(atyp),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_addr() -> SocksAddr {
        SocksAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 80))
    }

    fn decode_socks5(cursor: &mut &[u8]) -> io::Result<SocksAddr> {
        SocksAddr::decode_with(cursor, ATYP_SOCKS5)
    }

    #[test]
    fn test_encode_ipv4() {
        assert_eq!(
            encode_address("93.184.216.34:80".parse().unwrap(), None).unwrap(),
            vec![0x01, 93, 184, 216, 34, 0x00, 0x50]
        );
    }

    #[test]
    fn test_encode_ipv6() {
        let encoded = encode_address("[2001:db8::1]:8080".parse().unwrap(), None).unwrap();
        assert_eq!(encoded[0], 0x04);
        assert_eq!(
            &encoded[1..17],
            &[
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]
        );
        assert_eq!(&encoded[17..19], &[0x1f, 0x90]);
        assert_eq!(encoded.len(), 19);
    }

    #[test]
    fn test_encode_domain() {
        let encoded =
            encode_address("127.0.0.1:443".parse().unwrap(), Some("example.com")).unwrap();
        assert_eq!(encoded[0], 0x03);
        assert_eq!(encoded[1], 11);
        assert_eq!(&encoded[2..13], b"example.com");
        assert_eq!(&encoded[13..15], &[0x01, 0xbb]);
        assert_eq!(encoded.len(), 15);
    }

    #[test]
    fn test_encode_enforces_domain_length_bounds() {
        let target = "127.0.0.1:443".parse().unwrap();
        let maximum = encode_address(target, Some(&"x".repeat(255))).unwrap();
        assert_eq!(maximum.len(), 259);
        assert_eq!(maximum[1], 255);
        assert!(encode_address(target, Some("")).is_err());
        assert!(encode_address(target, Some(&"x".repeat(256))).is_err());
    }

    #[test]
    #[should_panic(expected = "proxy wire domain must contain 1..=255 bytes")]
    fn test_encode_rejects_directly_constructed_oversized_domain() {
        SocksAddr::Domain("x".repeat(256), 443).to_vec();
    }

    #[test]
    #[cfg(feature = "rprx")]
    fn test_encode_vmess_atyp() {
        // VMess uses the V2Ray ATYP numbering: domain = 0x02, IPv6 = 0x03.
        let domain = SocksAddr::Domain("example.com".to_string(), 443);
        let mut buf = Vec::new();
        domain.encode_with(&mut buf, ATYP_VMESS);
        assert_eq!(buf[0], 0x02);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &[0x01, 0xbb]);

        let v6 = SocksAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            8080,
            0,
            0,
        ));
        let mut buf = Vec::new();
        v6.encode_with(&mut buf, ATYP_VMESS);
        assert_eq!(buf[0], 0x03);
        assert_eq!(buf.len(), 19);

        let mut buf = Vec::new();
        v4_addr().encode_with(&mut buf, ATYP_VMESS);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf.len(), 7);
    }

    #[test]
    fn test_codec_roundtrip() {
        let cases = [
            v4_addr(),
            SocksAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                443,
                0,
                0,
            )),
            SocksAddr::Domain("example.com".to_string(), 8080),
        ];
        for addr in cases {
            let mut buf = Vec::new();
            addr.encode(&mut buf);
            assert_eq!(buf.len(), addr.encoded_len());
            let mut cursor = &buf[..];
            let decoded = decode_socks5(&mut cursor).unwrap();
            assert_eq!(decoded, addr);
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn test_decode_truncated() {
        assert!(decode_socks5(&mut &[0x01, 1][..]).is_err());
        assert!(decode_socks5(&mut &[0x03, 11, 0x65][..]).is_err());
        assert!(decode_socks5(&mut &[0x04, 1, 2][..]).is_err());
        assert!(decode_socks5(&mut &[0x05, 1, 2][..]).is_err());
        assert!(decode_socks5(&mut &[][..]).is_err());
        assert!(decode_socks5(&mut &[0x03, 0, 0, 0][..]).is_err());
    }

    #[tokio::test]
    async fn test_read_body() {
        let addr = SocksAddr::Domain("example.com".to_string(), 443);
        let mut buf = Vec::new();
        addr.encode(&mut buf);
        let mut slice = &buf[1..];
        let read = SocksAddr::read_body(buf[0], &mut slice, ATYP_SOCKS5)
            .await
            .unwrap();
        assert_eq!(read, addr);

        // Truncated stream body fails.
        let mut short = &buf[1..buf.len() - 1];
        assert!(
            SocksAddr::read_body(buf[0], &mut short, ATYP_SOCKS5)
                .await
                .is_err()
        );
        // Unknown ATYP fails.
        let mut bad = &[1u8, 2][..];
        assert!(
            SocksAddr::read_body(0x05, &mut bad, ATYP_SOCKS5)
                .await
                .is_err()
        );
    }

    #[test]
    fn dialed_domain_peer_projects_only_the_dialed_name_and_port() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let project = |dialed, domain: &str, port| dialed_domain_peer(dialed, target, domain, port);
        assert_eq!(
            project(Some("Example.COM"), "example.com", 443),
            Some(target)
        );
        assert_eq!(project(Some("example.com"), "other.example", 443), None);
        assert_eq!(project(Some("example.com"), "example.com", 80), None);
        assert_eq!(project(None, "example.com", 443), None);
        assert_eq!(
            dialed_domain_peer(Some("example.com"), target, b"EXAMPLE.com", 443),
            Some(target)
        );
    }
}
