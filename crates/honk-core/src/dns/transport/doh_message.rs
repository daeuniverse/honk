use super::super::endpoint::DnsEndpoint;
use super::failure::DeterministicResponse;

/// `host[:port]` authority string (brackets bare IPv6, elides default 443).
fn authority(host: &str, port: u16) -> String {
    let host_fmt = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        host_fmt
    } else {
        format!("{host_fmt}:{port}")
    }
}

/// Build the DoH/DoH3 POST request for a DNS message. `content_length` is
/// set only on the HTTP/2 path; H3 omits it.
pub(super) fn build_doh_request(
    endpoint: &DnsEndpoint,
    content_length: Option<usize>,
    label: &str,
) -> anyhow::Result<http::Request<()>> {
    let path = if endpoint.path.is_empty() {
        "/dns-query"
    } else {
        endpoint.path.as_str()
    };
    let uri = format!(
        "https://{}{}",
        authority(&endpoint.host, endpoint.port),
        path
    );
    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message");
    if let Some(len) = content_length {
        builder = builder.header("content-length", len.to_string());
    }
    builder
        .body(())
        .map_err(|e| anyhow::anyhow!("{label} request build: {e}"))
}

/// Shared DoH/DoH3 response validation: 2xx status, minimum DNS header size,
/// then restore the original query ID.
/// The status verdict, before the body is read: a 5xx may pass on a fresh
/// session, so it stays a plain error; a 4xx is the peer's settled answer.
pub(super) fn check_doh_status(
    label: &'static str,
    status: http::StatusCode,
) -> anyhow::Result<()> {
    if status.is_success() {
        Ok(())
    } else if status.is_server_error() {
        anyhow::bail!("{label} HTTP status {status}")
    } else {
        Err(DeterministicResponse {
            transport: label,
            reason: format!("HTTP status {status}"),
        }
        .into())
    }
}

pub(super) fn finish_doh_response(
    label: &'static str,
    mut body: Vec<u8>,
    orig_id: u16,
) -> anyhow::Result<Vec<u8>> {
    if body.len() < 12 {
        return Err(DeterministicResponse {
            transport: label,
            reason: format!("response too short ({} bytes)", body.len()),
        }
        .into());
    }
    super::framing::restore_dns_id(&mut body, orig_id);
    Ok(body)
}
