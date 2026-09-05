use super::super::endpoint::DnsEndpoint;

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
/// a zero wire transaction ID, then restore the original query ID.
pub(super) fn finish_doh_response(
    label: &str,
    status: http::StatusCode,
    mut body: Vec<u8>,
    orig_id: u16,
) -> anyhow::Result<Vec<u8>> {
    if !status.is_success() {
        anyhow::bail!("{label} HTTP status {status}");
    }
    if body.len() < 12 {
        anyhow::bail!("{label} response too short ({} bytes)", body.len());
    }
    crate::dns::response::check_transaction_id(0, &body)
        .map_err(|error| anyhow::anyhow!("{label} response transaction ID: {error}"))?;
    super::framing::restore_dns_id(&mut body, orig_id);
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::finish_doh_response;

    #[test]
    fn finish_requires_zero_wire_id_before_restoration() {
        let response = finish_doh_response("DoH", http::StatusCode::OK, vec![0; 12], 0x1234)
            .expect("zero wire ID");
        assert_eq!(&response[..2], &0x1234u16.to_be_bytes());

        let mut wrong_id = vec![0; 12];
        wrong_id[..2].copy_from_slice(&0x4321u16.to_be_bytes());
        assert!(finish_doh_response("DoH", http::StatusCode::OK, wrong_id, 0x1234).is_err());
    }
}
