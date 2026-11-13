//! HTTP/HTTPS proxy inbound sessions: `Proxy-Authorization` Basic
//! authentication, CONNECT tunnels, and absolute-URI request forwarding on
//! top of the shared proxy core in `proxy`.
//!
//! CONNECT carries TLS (and anything after the tunnel) end to end;
//! absolute-form requests (`GET http://host/path HTTP/1.1`) are rewritten to
//! origin-form, stripped of hop-by-hop headers, pinned to
//! `Connection: close`, and forwarded through the routed upstream, so plain
//! HTTP works without any TLS interception. Origin-form request lines carry
//! no routable host and are refused (400), unknown URI schemes get 501, and
//! authentication failures answer 407 with a Basic challenge.

use super::proxy::{ProxyRefusal, ProxyTargetRequest, lookup_user};
use super::*;
use honk_config::inbound::ProxyUser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Bound on the client-driven request head; a client that stalls before
/// completing its request line is dropped instead of holding admission
/// permits.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
/// Request heads above this are refused outright; credential-carrying proxy
/// heads are orders of magnitude smaller in practice.
const MAX_HEAD_BYTES: usize = 64 * 1024;

struct RequestHead {
    method: String,
    uri: String,
    version: String,
    headers: Vec<(String, String)>,
    /// Bytes the client pipelined behind the head (e.g. a body it sent
    /// without waiting for the authentication challenge). They are
    /// re-forwarded after the rewritten request for absolute-form traffic
    /// and prepended to the tunnel for CONNECT.
    overflow: Vec<u8>,
}

impl RequestHead {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

enum HeadRead {
    Request(RequestHead),
    /// Peer closed the connection before sending a request.
    Closed,
    /// The head grew past `MAX_HEAD_BYTES`.
    TooLarge,
    /// The request line or headers are not parseable.
    Malformed,
}

async fn read_request_head(stream: &mut TcpStream) -> std::io::Result<HeadRead> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut scratch = [0u8; 4096];
    loop {
        if let Some(index) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            let overflow = buf[index + 4..].to_vec();
            return Ok(match parse_request_head(&buf[..index]) {
                Some(mut request) => {
                    request.overflow = overflow;
                    HeadRead::Request(request)
                }
                None => HeadRead::Malformed,
            });
        }
        if buf.len() >= MAX_HEAD_BYTES {
            return Ok(HeadRead::TooLarge);
        }
        let read = stream.read(&mut scratch).await?;
        if read == 0 {
            return Ok(HeadRead::Closed);
        }
        buf.extend_from_slice(&scratch[..read]);
    }
}

/// `CR` and `LF` may only appear as the `CRLF` line separator; every other
/// control byte — and a lone `CR` or `LF` — makes the head unparseable.
/// Without this, a bare newline embedded in the request target would be
/// rewritten verbatim into the forwarded request line and could inject
/// header lines into what the upstream sees.
fn head_is_clean(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => index += 2,
            0x00..=0x1f | 0x7f => return false,
            _ => index += 1,
        }
    }
    true
}

fn parse_request_head(head: &[u8]) -> Option<RequestHead> {
    let text = std::str::from_utf8(head).ok()?;
    if !head_is_clean(text) {
        return None;
    }
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?.trim_end();
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_owned();
    let uri = parts.next()?.to_owned();
    let version = parts.next()?.to_owned();
    if method.is_empty() || !version.starts_with("HTTP/1.") {
        return None;
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Obs-fold continuation: append to the previous header value.
            let (_, value) = headers.last_mut()?;
            value.push(' ');
            value.push_str(line.trim());
            continue;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() {
            return None;
        }
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Some(RequestHead {
        method,
        uri,
        version,
        headers,
        overflow: Vec::new(),
    })
}

/// What one parsed request head asks of the proxy.
enum Proxied {
    /// CONNECT authority tunnel.
    Connect { request: ProxyTargetRequest },
    /// Absolute-URI request; `path` is the origin-form target to forward.
    Forward {
        request: ProxyTargetRequest,
        path: String,
    },
}

/// Turn a request line into a routable proxy target or the HTTP answer for
/// an unroutable one.
fn classify(head: &RequestHead) -> Result<Proxied, (u16, &'static str)> {
    if head.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_authority(&head.uri, 443).ok_or((400, "Bad Request"))?;
        return Ok(Proxied::Connect {
            request: target_request(host, port),
        });
    }
    let Some((scheme, rest)) = head.uri.split_once("://") else {
        // Origin-form: a path without scheme or host cannot be routed by a
        // proxy; only absolute-form or CONNECT may reach this inbound.
        return Err((400, "Bad Request"));
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err((501, "Not Implemented"));
    }
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (host, port) = split_authority(&rest[..authority_end], 80).ok_or((400, "Bad Request"))?;
    let path = match &rest[authority_end..] {
        "" => "/".to_owned(),
        path => path.to_owned(),
    };
    Ok(Proxied::Forward {
        request: target_request(host, port),
        path,
    })
}

fn split_authority(authority: &str, default_port: u16) -> Option<(&str, u16)> {
    // Request URIs occasionally embed userinfo; only the host part
    // identifies the upstream target.
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, rest)| rest);
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        if tail.is_empty() {
            return Some((host, default_port));
        }
        let port = tail.strip_prefix(':')?.parse().ok()?;
        if port == 0 {
            return None;
        }
        return Some((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port = port.parse().ok()?;
            if port == 0 {
                return None;
            }
            Some((host, port))
        }
        Some(_) => None,
        // An empty authority (`GET http:// HTTP/1.1`) names no target.
        None if authority.is_empty() => None,
        None => Some((authority, default_port)),
    }
}

fn target_request(host: &str, port: u16) -> ProxyTargetRequest {
    match host.parse::<std::net::IpAddr>() {
        Ok(address) => ProxyTargetRequest::Address(SocketAddr::new(address, port)),
        Err(_) => ProxyTargetRequest::Domain {
            domain: host.to_owned(),
            port,
        },
    }
}

/// The username a request's `Proxy-Authorization: Basic` header proves
/// against this listener's table.
fn authenticate(
    head: &RequestHead,
    users: &[ProxyUser],
    _client_addr: SocketAddr,
) -> Option<String> {
    let credential = head.header("proxy-authorization").and_then(parse_basic)?;
    let user = lookup_user(users, credential.0.as_bytes(), credential.1.as_bytes())?;
    Some(user.username.clone())
}

fn parse_basic(header: &str) -> Option<(String, String)> {
    let (scheme, encoded) = header.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (username, password) = text.split_once(':')?;
    Some((username.to_owned(), password.to_owned()))
}

fn refusal_status(refusal: ProxyRefusal) -> (u16, &'static str) {
    match refusal {
        ProxyRefusal::ResolveFailed | ProxyRefusal::DialFailed => (502, "Bad Gateway"),
        ProxyRefusal::Blocked => (403, "Forbidden"),
        ProxyRefusal::NoCandidates => (503, "Service Unavailable"),
    }
}

async fn respond_status(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    extra: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut response = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n");
    for (name, value) in extra {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    let body = format!("{status} {reason}\n");
    response.push_str(&format!(
        "Content-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        body.len()
    ));
    response.push_str(&body);
    stream.write_all(response.as_bytes()).await
}

/// Rebuild an absolute-form request as an origin-form one for the upstream:
/// rewritten request line, hop-by-hop headers removed (RFC 9110 §7.6.1,
/// including the `Connection` token list), and `Connection: close` pinned
/// so the single-shot relay matches what the server expects.
fn forward_request(head: &RequestHead, path: &str) -> Vec<u8> {
    let mut skip: Vec<String> = [
        "proxy-authorization",
        "proxy-authenticate",
        "proxy-connection",
        "connection",
        "keep-alive",
    ]
    .iter()
    .map(|name| (*name).to_owned())
    .collect();
    for token in head
        .headers
        .iter()
        .filter(|(name, _)| name == "connection")
        .flat_map(|(_, list)| list.split(','))
    {
        let token = token.trim().to_ascii_lowercase();
        if !token.is_empty() {
            skip.push(token);
        }
    }
    let mut out = format!("{} {path} {}\r\n", head.method, head.version);
    for (name, value) in &head.headers {
        if skip.iter().any(|skip| skip == name) {
            continue;
        }
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

impl ControlPlaneHandle {
    /// Serve one accepted HTTP proxy session: one request — a CONNECT
    /// tunnel or an absolute-form forward — then hang up, which every
    /// mainstream client treats as a completed transaction thanks to
    /// `Connection: close`. 4xx/5xx protocol answers complete with
    /// `Ok(())`; `Err` is reserved for transport faults the supervisor
    /// logs.
    pub(in crate::control) async fn serve_http(
        &self,
        mut stream: TcpStream,
        client_addr: SocketAddr,
        users: &[ProxyUser],
    ) -> anyhow::Result<()> {
        let head = match tokio::time::timeout(HEAD_TIMEOUT, read_request_head(&mut stream)).await {
            Err(_) => return Ok(()),
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(HeadRead::Closed)) => return Ok(()),
            Ok(Ok(HeadRead::TooLarge)) => {
                respond_status(&mut stream, 431, "Request Header Fields Too Large", &[]).await?;
                return Ok(());
            }
            Ok(Ok(HeadRead::Malformed)) => {
                respond_status(&mut stream, 400, "Bad Request", &[]).await?;
                return Ok(());
            }
            Ok(Ok(HeadRead::Request(head))) => head,
        };

        let Some(user) = authenticate(&head, users, client_addr) else {
            debug!(%client_addr, "HTTP proxy authentication failed");
            respond_status(
                &mut stream,
                407,
                "Proxy Authentication Required",
                &[("Proxy-Authenticate", "Basic realm=\"honk\"")],
            )
            .await?;
            return Ok(());
        };

        let (request, forward_path) = match classify(&head) {
            Ok(Proxied::Connect { request }) => (request, None),
            Ok(Proxied::Forward { request, path }) => (request, Some(path)),
            Err((status, reason)) => {
                respond_status(&mut stream, status, reason, &[]).await?;
                return Ok(());
            }
        };

        let mut session = match self.proxy_dial(&user, client_addr, request, "HTTP").await? {
            Ok(session) => session,
            Err(refusal) => {
                let (status, reason) = refusal_status(refusal);
                respond_status(&mut stream, status, reason, &[]).await?;
                return Ok(());
            }
        };

        if let Some(path) = forward_path {
            debug!(
                network = "http",
                user = %user,
                method = %head.method,
                outbound = %session.outbound_name,
                dialer = %session.node.name,
                target = %session.target_addr,
                src = %client_addr,
                "HTTP proxy forwarding request"
            );
            // Plain HTTP: the rewritten request is the only thing the
            // upstream expects before the response starts flowing back.
            session
                .stream
                .stream
                .write_all(&forward_request(&head, &path))
                .await?;
        } else {
            debug!(
                network = "http",
                user = %user,
                method = "CONNECT",
                outbound = %session.outbound_name,
                dialer = %session.node.name,
                target = %session.target_addr,
                src = %client_addr,
                "HTTP CONNECT session established"
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        }
        if !head.overflow.is_empty() {
            // Bytes the client pipelined behind the request head belong to
            // the tunnel or the forwarded body, not to the proxy.
            session.stream.stream.write_all(&head.overflow).await?;
        }
        self.proxy_relay(&mut stream, session, client_addr, "HTTP")
            .await
    }
}
