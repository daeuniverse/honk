//! Traffic sniffing for honk-core.
//!
//! Extracts protocol-level information from the initial bytes of a TCP
//! connection to enable domain-based routing without relying on DNS.
//!
//! ## Supported sniffing
//!
//! - **TLS SNI** (Server Name Indication): Extracts the target hostname
//!   from the TLS ClientHello message. This enables domain-based routing
//!   for HTTPS traffic without needing to decrypt the connection.
//!
//! ## Protocol Format
//!
//! ```text
//! TLS Record Layer (5 bytes):
//!   [0]     Content Type (0x16 = Handshake)
//!   [1..2]  Version
//!   [3..4]  Length (big-endian)
//!
//! Handshake (variable):
//!   [0]     Msg Type (0x01 = ClientHello)
//!   [1..3]  Length
//!   [4..5]  Client Version
//!   [6..37] Random
//!   ...     Session ID, Cipher Suites, Compression, Extensions
//!
//! SNI Extension (inside Extensions):
//!   [0..1]  Type = 0x0000
//!   [2..3]  Length
//!   [4..5]  Server Name List Length
//!   [6]     Name Type = 0x00 (hostname)
//!   [7..8]  Name Length
//!   [9..]   Hostname (ASCII)
//! ```

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::debug;

/// Maximum bytes buffered while sniffing TLS ClientHello or HTTP headers.
/// This is a hard bound: untrusted length fields never grow the buffer.
const MAX_CLIENT_HELLO_SIZE: usize = 4096;

/// Supported traffic types detected by sniffing; the domain lives in
/// [`SniffResult::domain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficType {
    Tls,
    Http,
    Unknown,
}

/// Result of sniffing a connection.
#[derive(Debug, Clone)]
pub struct SniffResult {
    /// Detected traffic type
    pub traffic_type: TrafficType,
    /// Extracted domain (from SNI or HTTP Host)
    pub domain: Option<String>,
    /// Buffered bytes read during sniffing (need to be forwarded)
    pub buffered: Vec<u8>,
}

impl SniffResult {
    /// Create an empty/unknown result.
    pub fn unknown() -> Self {
        Self {
            traffic_type: TrafficType::Unknown,
            domain: None,
            buffered: Vec::new(),
        }
    }

    /// Create a result with a domain extracted from TLS SNI.
    pub fn tls_sni(domain: String, buffered: Vec<u8>) -> Self {
        Self {
            traffic_type: TrafficType::Tls,
            domain: Some(domain),
            buffered,
        }
    }
}

/// Sniff a TCP stream to extract the target domain.
///
/// Reads the initial bytes of a connection and attempts to extract
/// the TLS SNI hostname. Returns both the sniffing result and
/// the buffered bytes that need to be forwarded to the proxy.
///
/// # Arguments
///
/// * `stream` - The TCP stream to sniff
///
/// # Returns
///
/// A `SniffResult` containing the extracted domain (if any) and
/// the buffered initial bytes that must be forwarded.
pub async fn sniff_tcp(stream: &mut (impl AsyncRead + Unpin)) -> SniffResult {
    const SNIFF_DEADLINE: std::time::Duration = std::time::Duration::from_millis(100);
    let deadline = tokio::time::Instant::now() + SNIFF_DEADLINE;
    let mut buf = BytesMut::with_capacity(MAX_CLIENT_HELLO_SIZE);

    loop {
        let required = sniff_required_len(&buf);
        if required <= buf.len() || buf.len() == MAX_CLIENT_HELLO_SIZE {
            break;
        }

        let mut chunk = [0u8; 512];
        let want = (required - buf.len()).min(chunk.len());
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk[..want])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => {
                debug!(bytes = buf.len(), "TCP sniffing timed out");
                break;
            }
            Ok(Err(e)) => {
                debug!(bytes = buf.len(), error = %e, "TCP sniffing read failed");
                break;
            }
        }
    }

    let data = buf.to_vec();
    if let Some(sni) = parse_tls_sni(&data) {
        return SniffResult::tls_sni(sni, data);
    }
    if let Some(host) = parse_http_host(&data) {
        return SniffResult {
            traffic_type: TrafficType::Http,
            domain: Some(host),
            buffered: data,
        };
    }
    SniffResult {
        traffic_type: TrafficType::Unknown,
        domain: None,
        buffered: data,
    }
}

/// Return the prefix length needed to make a bounded sniffing decision.
/// TLS waits for its declared first record and ClientHello handshake; HTTP
/// waits for the complete header terminator.  Unknown protocols get only the
/// initial five-byte classification prefix, avoiding an unnecessary delay.
fn sniff_required_len(data: &[u8]) -> usize {
    if data.is_empty() {
        return 1;
    }
    if data[0] == 0x16 {
        if data.len() < 5 {
            return 5;
        }
        let record_end = 5 + u16::from_be_bytes([data[3], data[4]]) as usize;
        if record_end > MAX_CLIENT_HELLO_SIZE {
            return MAX_CLIENT_HELLO_SIZE;
        }
        if data.len() < 9 {
            return record_end;
        }
        if data[5] != 0x01 {
            return record_end;
        }
        let hello_end = 9 + u24_from_be(&data[6..9]) as usize;
        return record_end.max(hello_end).min(MAX_CLIENT_HELLO_SIZE);
    }
    if is_http_request_prefix(data) {
        return if data.windows(4).any(|window| window == b"\r\n\r\n") {
            data.len()
        } else {
            MAX_CLIENT_HELLO_SIZE
        };
    }
    if data
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b'\r' || *byte == b'\n' || *byte == b'\t')
    {
        return MAX_CLIENT_HELLO_SIZE;
    }
    5
}

/// Whether `data` can still be the start of a supported HTTP request method.
fn is_http_request_prefix(data: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"CONNECT ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
    ];

    METHODS
        .iter()
        .any(|method| method.starts_with(data) || data.starts_with(method))
}

/// Parse TLS ClientHello and extract the SNI hostname.
///
/// Returns `Some(hostname)` if SNI was found, `None` otherwise.
fn parse_tls_sni(data: &[u8]) -> Option<String> {
    let mut pos = 0;

    // TLS Record Layer
    if data.len() < 5 {
        return None;
    }

    let content_type = data[pos];
    pos += 1;

    if content_type != 0x16 {
        // Not a TLS Handshake
        return None;
    }

    let version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Accept TLS 1.0 - 1.3
    if version < 0x0301 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if pos + record_len > data.len() {
        // Record extends beyond our buffer - try with what we have
        // but don't overrun
    }

    let available = (pos + record_len).min(data.len());

    // Handshake
    if pos >= available {
        return None;
    }

    let handshake_type = data[pos];
    pos += 1;

    if handshake_type != 0x01 {
        // Not a ClientHello
        return None;
    }

    if pos + 3 > available {
        return None;
    }

    let handshake_len = u24_from_be(&data[pos..pos + 3]) as usize;
    pos += 3;

    let body_end = pos + handshake_len.min(available - pos);
    parse_client_hello_body(&data[pos..body_end])
}

/// Parse a TLS ClientHello handshake message body (the bytes after the
/// 4-byte handshake type + length header) and extract the SNI hostname.
///
/// Shared with the QUIC sniffer: QUIC carries TLS handshake messages
/// directly in CRYPTO frames without a TLS record header (RFC 9001 §4.1.3).
///
/// Returns `Some(hostname)` if SNI was found, `None` otherwise.
pub(crate) fn parse_client_hello_body(data: &[u8]) -> Option<String> {
    let mut pos = 0;
    let handshake_end = data.len();

    // Client Version (2 bytes)
    if pos + 2 > handshake_end {
        return None;
    }
    let _client_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Random (32 bytes)
    if pos + 32 > handshake_end {
        return None;
    }
    pos += 32;

    // Session ID
    if pos >= handshake_end {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1;
    if pos + session_id_len > handshake_end {
        return None;
    }
    pos += session_id_len;

    // Cipher Suites
    if pos + 2 > handshake_end {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_suites_len > handshake_end {
        return None;
    }
    pos += cipher_suites_len;

    // Compression Methods
    if pos >= handshake_end {
        return None;
    }
    let compression_len = data[pos] as usize;
    pos += 1;
    if pos + compression_len > handshake_end {
        return None;
    }
    pos += compression_len;

    // Extensions
    if pos + 2 > handshake_end {
        return None;
    }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = (pos + extensions_len).min(handshake_end);

    // Search for SNI extension (type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > extensions_end {
            break;
        }

        if ext_type == 0x0000 {
            return parse_sni_extension(&data[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

/// Parse an SNI extension payload and extract the hostname.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    let mut pos = 0;

    // Server Name List Length
    let list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if pos + list_len > data.len() {
        return None;
    }

    let list_end = pos + list_len;

    while pos + 3 <= list_end {
        let name_type = data[pos];
        pos += 1;

        let name_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + name_len > list_end {
            break;
        }

        if name_type == 0x00 {
            // DNS hostname
            let hostname_bytes = &data[pos..pos + name_len];
            if let Ok(hostname) = std::str::from_utf8(hostname_bytes) {
                let hostname = hostname.trim_end_matches('.').to_lowercase();
                if !hostname.is_empty() && is_valid_hostname(&hostname) {
                    return Some(hostname);
                }
            }
        }

        pos += name_len;
    }

    None
}

/// Parse HTTP request and extract the Host header.
fn parse_http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;

    if !text.starts_with("GET ")
        && !text.starts_with("POST ")
        && !text.starts_with("CONNECT ")
        && !text.starts_with("HEAD ")
        && !text.starts_with("PUT ")
        && !text.starts_with("DELETE ")
        && !text.starts_with("OPTIONS ")
    {
        return None;
    }

    for line in text.lines() {
        let lower = line.trim().to_lowercase();
        if lower.starts_with("host:") {
            let host = line.trim()["host:".len()..].trim();
            let host = host.split(':').next().unwrap_or(host);
            if !host.is_empty() && is_valid_hostname(host) {
                return Some(host.to_lowercase());
            }
        }
    }

    None
}

/// Parse a 3-byte big-endian integer.
fn u24_from_be(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
}

/// Validate that a string looks like a valid hostname.
fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Labels must start/end with alphanumeric
        let first = label.chars().next().unwrap_or('\0');
        let last = label.chars().last().unwrap_or('\0');

        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
            return false;
        }

        // Labels can contain alphanumeric and hyphens
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Build a minimal TLS ClientHello with SNI.
    fn build_tls_client_hello(sni: &str) -> Vec<u8> {
        let mut buf = Vec::new();

        // SNI extension
        let sni_bytes = sni.as_bytes();
        let sni_list_data_len = 3 + sni_bytes.len(); // type(1) + name_len(2) + name
        let sni_ext_data_len = 2 + sni_list_data_len; // list_len_field(2) + list_data
        let sni_ext_len = sni_ext_data_len;

        // Extensions
        let mut extensions = Vec::new();
        // SNI extension
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // type
        extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // length
        extensions.extend_from_slice(&(sni_list_data_len as u16).to_be_bytes());
        extensions.push(0x00); // name type: hostname
        extensions.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes()); // name length
        extensions.extend_from_slice(sni_bytes); // hostname

        // Handshake body
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.extend_from_slice(&0u32.to_be_bytes()[1..]); // 3-byte length placeholder
        handshake.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2
        handshake.extend_from_slice(&[0u8; 32]); // random
        handshake.push(0x00); // session ID length = 0
        handshake.extend_from_slice(&0u16.to_be_bytes()); // cipher suites length = 0
        handshake.push(0x00); // compression length = 0
        handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes()); // extensions length
        handshake.extend_from_slice(&extensions);

        // Fix handshake length
        let handshake_body_len = handshake.len() - 4; // minus type + 3-byte length

        handshake[1] = ((handshake_body_len >> 16) & 0xff) as u8;
        handshake[2] = ((handshake_body_len >> 8) & 0xff) as u8;
        handshake[3] = (handshake_body_len & 0xff) as u8;

        // TLS Record
        buf.push(0x16); // Handshake
        buf.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2
        buf.extend_from_slice(&(handshake.len() as u16).to_be_bytes()); // record length
        buf.extend_from_slice(&handshake);

        buf
    }
    #[tokio::test]
    async fn sniff_tcp_reassembles_fragmented_client_hello() {
        let hello = build_tls_client_hello("fragmented.example");
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let producer = tokio::spawn(async move {
            for chunk in hello.chunks(3) {
                writer.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let sniffed = sniff_tcp(&mut reader).await;
        producer.await.unwrap();
        assert_eq!(sniffed.domain.as_deref(), Some("fragmented.example"));
        assert_eq!(
            sniffed.buffered,
            build_tls_client_hello("fragmented.example")
        );
    }

    #[tokio::test]
    async fn sniff_tcp_reassembles_fragmented_http_header() {
        let request = b"GET / HTTP/1.1\r\nHost: fragmented.example\r\n\r\n";
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let producer = tokio::spawn(async move {
            for chunk in request.chunks(2) {
                writer.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let sniffed = sniff_tcp(&mut reader).await;
        producer.await.unwrap();
        assert_eq!(sniffed.domain.as_deref(), Some("fragmented.example"));
        assert_eq!(sniffed.buffered, request);
    }

    #[tokio::test]
    async fn sniff_tcp_timeout_replays_every_consumed_byte() {
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        writer.write_all(&[0x16, 0x03, 0x03, 0x00]).await.unwrap();
        let sniffed = sniff_tcp(&mut reader).await;
        assert_eq!(sniffed.traffic_type, TrafficType::Unknown);
        assert_eq!(sniffed.buffered, [0x16, 0x03, 0x03, 0x00]);
    }

    #[test]
    fn test_parse_tls_sni_basic() {
        let data = build_tls_client_hello("www.google.com");
        let result = parse_tls_sni(&data);
        assert_eq!(result, Some("www.google.com".to_string()));
    }

    #[test]
    fn test_parse_tls_sni_with_subdomain() {
        let data = build_tls_client_hello("api.github.com");
        let result = parse_tls_sni(&data);
        assert_eq!(result, Some("api.github.com".to_string()));
    }

    #[test]
    fn test_parse_tls_sni_non_tls() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let result = parse_tls_sni(&data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_http_host() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: curl\r\n\r\n";
        let result = parse_http_host(data);
        assert_eq!(result, Some("www.example.com".to_string()));
    }

    #[test]
    fn test_parse_http_host_with_port() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let result = parse_http_host(data);
        assert_eq!(result, Some("example.com".to_string()));
    }
    #[tokio::test]
    async fn test_sniff_tcp_detects_fragmented_http_host() {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = tokio::io::duplex(1024);
        let request = b"GET / HTTP/1.1\r\nHost: fragmented.example.com\r\n\r\n";
        let writer = tokio::spawn(async move {
            client.write_all(&request[..20]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            client.write_all(&request[20..]).await.unwrap();
        });

        let result = sniff_tcp(&mut server).await;
        writer.await.unwrap();

        assert_eq!(result.domain.as_deref(), Some("fragmented.example.com"));
        assert_eq!(result.traffic_type, TrafficType::Http);
        assert_eq!(result.buffered, request);
    }

    #[test]
    fn test_is_valid_hostname() {
        assert!(is_valid_hostname("google.com"));
        assert!(is_valid_hostname("www.example.com"));
        assert!(is_valid_hostname("a.co"));
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-bad.com"));
        assert!(!is_valid_hostname("bad-.com"));
        assert!(!is_valid_hostname("invalid_domain.com"));
    }

    #[test]
    fn test_u24_from_be() {
        assert_eq!(u24_from_be(&[0x00, 0x00, 0x01]), 1);
        assert_eq!(u24_from_be(&[0x00, 0x01, 0x00]), 256);
        assert_eq!(u24_from_be(&[0x01, 0x00, 0x00]), 65536);
        assert_eq!(u24_from_be(&[0xFF, 0xFF, 0xFF]), 16777215);
    }
}
