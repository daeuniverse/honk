//! Bootstrap DNS resolution for proxy-server hostnames.
//!
//! Node dials must not depend on the regular DNS path: the system resolver
//! may itself be routed through honk (interception + DNS routing), so right
//! after a restart — before any node is reachable — resolving a proxy
//! server's domain can deadlock against the very nodes it is needed to
//! reach. dae solves this with `bootstrap_resolver`: a plain, direct DNS
//! server that honk queries itself on a bypass-marked socket.
//!
//! [`resolve`] checks the configured bootstrap resolver first, then `/etc/hosts`
//! and the first numeric `/etc/resolv.conf` nameserver. Every DNS socket is
//! bypass-marked; libc NSS/search-suffix resolution is deliberately not used.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::RwLock;
use std::time::Duration;

/// A direct DNS server used to resolve proxy-server hostnames.
#[derive(Debug, Clone, Copy)]
pub struct BootstrapResolver {
    server: SocketAddr,
    use_tcp: bool,
}

impl BootstrapResolver {
    /// Parse `8.8.8.8:53`, `udp://8.8.8.8:53` or `tcp://8.8.8.8:53`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (use_tcp, rest) = match s.split_once("://") {
            Some((scheme, rest)) => (scheme.eq_ignore_ascii_case("tcp"), rest),
            None => (false, s),
        };
        let server: SocketAddr = rest.parse().ok()?;
        Some(Self { server, use_tcp })
    }
}

static GLOBAL: RwLock<Option<BootstrapResolver>> = RwLock::new(None);

/// Install (or clear) the process-wide bootstrap resolver. Called by
/// honk-core at startup and on config reload.
pub fn set_global(resolver: Option<BootstrapResolver>) {
    *GLOBAL.write().unwrap() = resolver;
}

/// Snapshot the process-wide resolver for compatibility callers that do not
/// already own a configuration generation.
pub fn global() -> Option<BootstrapResolver> {
    match GLOBAL.read() {
        Ok(resolver) => *resolver,
        Err(poisoned) => *poisoned.into_inner(),
    }
}

/// The configured bootstrap resolver's server address, if any. Also used
/// as the `direct` node's probe/urltest target: a plain directly-reachable
/// DNS server is exactly what direct-egress latency should be measured
/// against.
pub fn global_server() -> Option<SocketAddr> {
    GLOBAL.read().unwrap().map(|r| r.server)
}

/// Resolve `host`, preferring the configured bootstrap resolver and falling back
/// to `/etc/hosts` and bypass-marked queries to the system nameserver.
pub async fn resolve(host: &str) -> io::Result<Vec<IpAddr>> {
    resolve_with(global(), host).await
}

/// Resolve with an explicit resolver snapshot.
///
/// Generation-owned callers use this path so a later [`set_global`] cannot
/// change the resolver selected by an in-flight or lazily initialized dial.
pub async fn resolve_with(
    resolver: Option<BootstrapResolver>,
    host: &str,
) -> io::Result<Vec<IpAddr>> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if let Some(resolver) = resolver {
        match resolver.query(host).await {
            Ok(ips) if !ips.is_empty() => return Ok(ips),
            Ok(_) => tracing::debug!("bootstrap resolver returned no records for '{}'", host),
            Err(e) => tracing::debug!("bootstrap resolution of '{}' failed: {}", host, e),
        }
    }
    if let Ok(contents) = tokio::fs::read_to_string("/etc/hosts").await {
        let addrs = hosts_addresses(&contents, host);
        if !addrs.is_empty() {
            return Ok(addrs);
        }
    }
    let server = system_nameserver().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no numeric system DNS nameserver")
    })?;
    let resolver = BootstrapResolver {
        server,
        use_tcp: false,
    };
    let addrs = resolver.query(host).await?;
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no DNS addresses"));
    }
    Ok(addrs)
}

fn hosts_addresses(contents: &str, host: &str) -> Vec<IpAddr> {
    let mut addrs = Vec::new();
    let host = host.trim_end_matches('.');
    for line in contents.lines() {
        let mut fields = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_ascii_whitespace();
        let Some(ip) = fields.next().and_then(|ip| ip.parse::<IpAddr>().ok()) else {
            continue;
        };
        if fields.any(|name| name.trim_end_matches('.').eq_ignore_ascii_case(host))
            && !addrs.contains(&ip)
        {
            addrs.push(ip);
        }
    }
    addrs
}

/// Budget for one address family's exchange, connect included.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

impl BootstrapResolver {
    /// Query A and AAAA records for `host` directly from the configured
    /// server over bypass-marked sockets.
    async fn query(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        // Separate budgets: a stalled or failing family must not discard the other's answer.
        match tokio::join!(self.query_family(host, 1), self.query_family(host, 28)) {
            (Err(e), Err(_)) => Err(e),
            (a, aaaa) => Ok([a.unwrap_or_default(), aaaa.unwrap_or_default()].concat()),
        }
    }

    async fn query_family(&self, host: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
        let msg = tokio::time::timeout(QUERY_TIMEOUT, self.query_raw(host, qtype))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "bootstrap DNS query timed out")
            })??;
        parse_answers(&msg, qtype)
    }

    /// Send a single query and return the raw response that answers it.
    async fn query_raw(&self, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
        let query = build_query(host, qtype);
        if !self.use_tcp {
            let response = self.exchange_udp(&query).await?;
            // A truncated answer may omit records; libc's resolver retries it over TCP.
            if response[2] & 0x02 == 0 {
                return Ok(response);
            }
        }
        self.exchange_tcp(&query).await
    }

    async fn exchange_tcp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = crate::util::connect_marked_addr(
            self.server,
            Some(crate::util::bypass_mark()),
            QUERY_TIMEOUT,
        )
        .await?;
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(query).await?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        if !answers_query(query, &buf) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response does not match query",
            ));
        }
        Ok(buf)
    }

    async fn exchange_udp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let bind: SocketAddr = if self.server.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = crate::util::udp_marked_bind(bind).await?;
        socket.connect(self.server).await?;
        socket.send(query).await?;
        let mut buf = [0u8; 1500];
        // Stray and off-path spoofed datagrams are skipped; the caller's deadline bounds the wait.
        loop {
            let n = socket.recv(&mut buf).await?;
            if answers_query(query, &buf[..n]) {
                return Ok(buf[..n].to_vec());
            }
        }
    }
}

/// Whether `resp` answers `query` (as built by [`build_query`]): same ID, QR
/// set, same opcode and exactly the sent question. Names are case-insensitive
/// in DNS, so only the name ignores ASCII case; type and class must match exactly.
fn answers_query(query: &[u8], resp: &[u8]) -> bool {
    let (name, type_class) = query[12..].split_at(query.len() - 16);
    resp.len() >= 12
        && resp[..2] == query[..2]
        && resp[2] & 0x80 != 0
        && (resp[2] ^ query[2]) & 0x78 == 0
        && resp[4..6] == [0, 1]
        && resp
            .get(12..12 + name.len())
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
        && resp.get(12 + name.len()..query.len()) == Some(type_class)
}

/// First nameserver from /etc/resolv.conf (UDP, port 53). Used for record
/// lookups (e.g. ECH discovery) when no `bootstrap_resolver` is configured.
fn system_nameserver() -> Option<SocketAddr> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in contents.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() == Some("nameserver")
            && let Some(ip) = fields.next().and_then(|ip| ip.parse::<IpAddr>().ok())
        {
            return Some(SocketAddr::new(ip, 53));
        }
    }
    None
}

/// DNS qtype for HTTPS service-binding records (RFC 9460).
const QTYPE_HTTPS: u16 = 65;
/// SVCB SvcParam key carrying the ECHConfigList.
const SVCB_KEY_ECH: u16 = 5;

/// Look up the ECHConfigList for `host` via DNS HTTPS records (RFC 9460).
///
/// Queries the configured bootstrap resolver, or the first system nameserver
/// when none is configured. Returns the ECHConfigList and the record TTL, or
/// `None` when no usable HTTPS record exists.
pub async fn query_ech_config(host: &str) -> io::Result<Option<(Vec<u8>, u32)>> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.parse::<IpAddr>().is_ok() {
        return Ok(None);
    }
    let resolver = match global() {
        Some(r) => r,
        None => {
            let Some(server) = system_nameserver() else {
                return Ok(None);
            };
            BootstrapResolver {
                server,
                use_tcp: false,
            }
        }
    };
    let msg = resolver.query_raw(host, QTYPE_HTTPS).await?;
    Ok(parse_https_rr_ech(&msg))
}

/// Extract the ECHConfigList and TTL from the first ServiceMode HTTPS RR in
/// a DNS response. AliasMode records (priority != 0) carry no SvcParams and
/// are skipped.
fn parse_https_rr_ech(msg: &[u8]) -> Option<(Vec<u8>, u32)> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(msg, pos).ok()?;
        pos = pos.checked_add(4)?;
    }
    for _ in 0..an {
        pos = skip_name(msg, pos).ok()?;
        if pos + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return None;
        }
        if rtype == QTYPE_HTTPS
            && rdlen >= 3
            && let Some(ech) = parse_svcb_ech_param(&msg[pos..pos + rdlen])
        {
            return Some((ech, ttl));
        }
        pos += rdlen;
    }
    None
}

/// Parse SVCB/HTTPS RDATA for the `ech` SvcParam (key 5). Only ServiceMode
/// records (SvcPriority >= 1) carry SvcParams; AliasMode (priority 0) has
/// just a TargetName and is skipped.
fn parse_svcb_ech_param(rdata: &[u8]) -> Option<Vec<u8>> {
    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    if priority == 0 {
        return None; // AliasMode has no SvcParams
    }
    let mut pos = skip_name(rdata, 2).ok()?;
    while pos + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + len > rdata.len() {
            return None;
        }
        if key == SVCB_KEY_ECH {
            return Some(rdata[pos..pos + len].to_vec());
        }
        pos += len;
    }
    None
}

/// Build a minimal DNS query (RD set, single question).
fn build_query(host: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(host.len() + 18);
    q.extend_from_slice(&rand::random::<u16>().to_be_bytes()); // id
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&[0; 6]); // an/ns/ar = 0
    for label in host.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

/// Extract A/AAAA answer addresses from a DNS response.
fn parse_answers(msg: &[u8], qtype: u16) -> io::Result<Vec<IpAddr>> {
    if msg.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short DNS message",
        ));
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(msg, pos)?;
        pos = pos.checked_add(4).ok_or_else(bad)?; // qtype + qclass
    }
    let mut ips = Vec::new();
    for _ in 0..an {
        pos = skip_name(msg, pos)?;
        if pos + 10 > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated answer",
            ));
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated rdata",
            ));
        }
        if rtype == qtype {
            match (rtype, rdlen) {
                (1, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(
                    msg[pos],
                    msg[pos + 1],
                    msg[pos + 2],
                    msg[pos + 3],
                ))),
                (28, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&msg[pos..pos + 16]);
                    ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        pos += rdlen;
    }
    Ok(ips)
}

fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "bad DNS message")
}

/// Skip a (possibly compressed) domain name, returning the offset after it.
fn skip_name(msg: &[u8], mut pos: usize) -> io::Result<usize> {
    loop {
        let Some(&len) = msg.get(pos) else {
            return Err(bad());
        };
        if len & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }
        if len == 0 {
            return Ok(pos + 1);
        }
        pos += 1 + len as usize;
        if pos > msg.len() {
            return Err(bad());
        }
    }
}

#[cfg(test)]
pub(crate) static GLOBAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests;
