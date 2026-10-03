//! Parse DNS upstream address strings into host/port/path/SNI.
//!
//! Config stores scheme-stripped fragments:
//! - `8.8.8.8:53`
//! - `dns.google:853`
//! - `dns.google/dns-query`
//! - `1.1.1.1:443/dns-query`

use std::net::{IpAddr, SocketAddr};

use honk_config::dns::DnsStrategy;
use honk_config::types::DnsProtocol;

/// Default DoH / DoH3 request path (RFC 8484).
pub const DEFAULT_DOH_PATH: &str = "/dns-query";

/// Parsed upstream endpoint used by the encrypted DNS transports.
#[derive(Debug, Clone)]
pub struct DnsEndpoint {
    pub host: String,
    pub port: u16,
    /// HTTP path for DoH/DoH3 (always starts with `/`).
    pub path: String,
    /// TLS/QUIC server name (SNI). Falls back to `host` when host is not an IP.
    pub sni: String,
    bootstrap_resolver: Option<honk_outbound::bootstrap::BootstrapResolver>,
    resolved_addr: Option<SocketAddr>,
    strategy: DnsStrategy,
}

impl DnsEndpoint {
    /// Parse `address` for `protocol`, applying default ports/paths and optional
    /// config-level `tls_server_name` override.
    pub fn parse(
        address: &str,
        protocol: DnsProtocol,
        tls_server_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        Self::parse_with_resolver(
            address,
            protocol,
            tls_server_name,
            None,
            DnsStrategy::default(),
        )
    }

    pub(crate) fn parse_with_resolver(
        address: &str,
        protocol: DnsProtocol,
        tls_server_name: Option<&str>,
        bootstrap_resolver: Option<honk_outbound::bootstrap::BootstrapResolver>,
        strategy: DnsStrategy,
    ) -> anyhow::Result<Self> {
        let address = address.trim();
        if address.is_empty() {
            anyhow::bail!("empty DNS upstream address");
        }

        let (hostport, path_raw) = split_hostport_path(address);
        let (host, port_opt) = split_host_port(hostport)?;

        let default_port = default_port(protocol);
        let port = port_opt.unwrap_or(default_port);

        let path = match protocol {
            DnsProtocol::Https | DnsProtocol::H3 => normalize_path(path_raw),
            _ => String::new(),
        };

        let sni = if let Some(sni) = tls_server_name.map(str::trim).filter(|s| !s.is_empty()) {
            sni.to_string()
        } else if host.parse::<IpAddr>().is_ok() {
            // IP literal — SNI still required by rustls; use the IP string.
            host.clone()
        } else {
            host.clone()
        };

        Ok(Self {
            host,
            port,
            path,
            sni,
            bootstrap_resolver,
            resolved_addr: None,
            strategy,
        })
    }
    pub(crate) fn with_resolved_addr(mut self, address: SocketAddr) -> Self {
        self.resolved_addr = Some(address);
        self
    }

    /// Resolve host to every allowed candidate, preferred family first.
    ///
    /// Dialers iterate this list so failure in the preferred family can fall
    /// back to the other family.
    pub async fn resolve_addrs(&self) -> anyhow::Result<Vec<SocketAddr>> {
        self.resolve_addrs_with(self.bootstrap_resolver).await
    }

    async fn resolve_addrs_with(
        &self,
        bootstrap_resolver: Option<honk_outbound::bootstrap::BootstrapResolver>,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        if let Some(address) = self.resolved_addr {
            return Ok(vec![address]);
        }
        let ips = if let Ok(ip) = self.host.parse::<IpAddr>() {
            vec![ip]
        } else {
            let ips = honk_outbound::bootstrap::resolve_with(bootstrap_resolver, &self.host)
                .await
                .map_err(|error| {
                    anyhow::Error::new(error).context(format!("bootstrap resolve '{}'", self.host))
                })?;
            if ips.is_empty() {
                anyhow::bail!("bootstrap resolve '{}' returned no addresses", self.host);
            }
            ips
        };
        let (mut v4, mut v6): (Vec<_>, Vec<_>) = ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.port))
            .partition(SocketAddr::is_ipv4);
        let addresses = match &self.strategy {
            DnsStrategy::PreferIpv6 => {
                v6.extend(v4);
                v6
            }
            DnsStrategy::Ipv4Only => v4,
            DnsStrategy::Ipv6Only => v6,
            DnsStrategy::PreferIpv4 | DnsStrategy::Both => {
                v4.extend(v6);
                v4
            }
        };
        if addresses.is_empty() {
            anyhow::bail!(
                "bootstrap resolve '{}' returned no addresses allowed by {:?}",
                self.host,
                self.strategy
            );
        }
        Ok(addresses)
    }
}

fn default_port(protocol: DnsProtocol) -> u16 {
    match protocol {
        DnsProtocol::Udp | DnsProtocol::Tcp => 53,
        DnsProtocol::Tls | DnsProtocol::Quic => 853,
        DnsProtocol::Https | DnsProtocol::H3 => 443,
    }
}

fn normalize_path(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return DEFAULT_DOH_PATH.to_string();
    }
    if raw.starts_with('/') {
        raw.to_string()
    } else {
        format!("/{raw}")
    }
}

fn split_hostport_path(address: &str) -> (&str, &str) {
    // Prefer splitting on the first `/` that is not inside an IPv6 bracket.
    if let Some(bracket_end) = address.find(']') {
        let after_bracket = &address[bracket_end + 1..];
        if let Some(pos) = after_bracket.find('/') {
            return (&address[..bracket_end + 1 + pos], &after_bracket[pos..]);
        }
        return (address, "");
    }
    if let Some(pos) = address.find('/') {
        (&address[..pos], &address[pos..])
    } else {
        (address, "")
    }
}

fn split_host_port(hostport: &str) -> anyhow::Result<(String, Option<u16>)> {
    let hostport = hostport.trim();
    if let Some(rest) = hostport.strip_prefix('[') {
        // [ipv6] or [ipv6]:port
        let (inside, after) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("unclosed IPv6 bracket in '{hostport}'"))?;
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(
                p.parse::<u16>()
                    .map_err(|e| anyhow::anyhow!("invalid port in '{hostport}': {e}"))?,
            )
        } else if after.is_empty() {
            None
        } else {
            anyhow::bail!("junk after IPv6 address in '{hostport}'");
        };
        return Ok((inside.to_string(), port));
    }

    if hostport.parse::<IpAddr>().is_ok() {
        return Ok((hostport.to_string(), None));
    }

    // host:port — only split when suffix is numeric (so "dns.google" stays intact).
    if let Some((host, port_s)) = hostport.rsplit_once(':')
        && !host.is_empty()
        && port_s.chars().all(|c| c.is_ascii_digit())
        && !port_s.is_empty()
    {
        let port: u16 = port_s
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid port in '{hostport}': {e}"))?;
        return Ok((host.to_string(), Some(port)));
    }
    Ok((hostport.to_string(), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dot_defaults() {
        let ep = DnsEndpoint::parse("dns.google", DnsProtocol::Tls, None).unwrap();
        assert_eq!(ep.host, "dns.google");
        assert_eq!(ep.port, 853);
        assert_eq!(ep.sni, "dns.google");
        assert!(ep.path.is_empty());
    }

    #[test]
    fn parse_doh_path_and_port() {
        let ep =
            DnsEndpoint::parse("cloudflare-dns.com/dns-query", DnsProtocol::Https, None).unwrap();
        assert_eq!(ep.host, "cloudflare-dns.com");
        assert_eq!(ep.port, 443);
        assert_eq!(ep.path, "/dns-query");
        assert_eq!(ep.sni, "cloudflare-dns.com");
    }

    #[test]
    fn parse_ip_with_port() {
        let ep = DnsEndpoint::parse("1.1.1.1:853", DnsProtocol::Tls, Some("cloudflare-dns.com"))
            .unwrap();
        assert_eq!(ep.host, "1.1.1.1");
        assert_eq!(ep.port, 853);
        assert_eq!(ep.sni, "cloudflare-dns.com");
    }

    #[test]
    fn parse_ipv6() {
        let ep = DnsEndpoint::parse("[2606:4700:4700::1111]:853", DnsProtocol::Tls, None).unwrap();
        assert_eq!(ep.host, "2606:4700:4700::1111");
        assert_eq!(ep.port, 853);
    }

    #[test]
    fn parse_h3_default_path() {
        let ep = DnsEndpoint::parse("dns.google", DnsProtocol::H3, None).unwrap();
        assert_eq!(ep.port, 443);
        assert_eq!(ep.path, "/dns-query");
    }

    #[tokio::test]
    async fn resolve_addrs_uses_the_captured_bootstrap_resolver() {
        // Given
        let old = spawn_bootstrap_server([192, 0, 2, 10], None, 2).await;
        let replacement = spawn_bootstrap_server([198, 51, 100, 20], None, 2).await;
        let endpoint = DnsEndpoint::parse("runtime.test:853", DnsProtocol::Tls, None).unwrap();
        let old_resolver =
            honk_outbound::bootstrap::BootstrapResolver::parse(&format!("udp://{old}")).unwrap();
        let replacement_resolver =
            honk_outbound::bootstrap::BootstrapResolver::parse(&format!("udp://{replacement}"))
                .unwrap();

        // When
        let old_addrs = endpoint
            .resolve_addrs_with(Some(old_resolver))
            .await
            .unwrap();
        let replacement_addrs = endpoint
            .resolve_addrs_with(Some(replacement_resolver))
            .await
            .unwrap();

        // Then
        assert_eq!(old_addrs[0].ip(), IpAddr::V4([192, 0, 2, 10].into()));
        assert_eq!(
            replacement_addrs[0].ip(),
            IpAddr::V4([198, 51, 100, 20].into())
        );
    }

    #[tokio::test]
    async fn resolve_addrs_follows_upstream_family_strategy() {
        let ipv4 = [192, 0, 2, 10];
        let ipv6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let server = spawn_bootstrap_server(ipv4, Some(ipv6), 8).await;
        let resolver =
            honk_outbound::bootstrap::BootstrapResolver::parse(&format!("udp://{server}")).unwrap();

        let prefer_v4 = DnsEndpoint::parse_with_resolver(
            "dual.test:853",
            DnsProtocol::Tls,
            None,
            Some(resolver),
            DnsStrategy::PreferIpv4,
        )
        .unwrap()
        .resolve_addrs()
        .await
        .unwrap();
        let prefer_v6 = DnsEndpoint::parse_with_resolver(
            "dual.test:853",
            DnsProtocol::Tls,
            None,
            Some(resolver),
            DnsStrategy::PreferIpv6,
        )
        .unwrap()
        .resolve_addrs()
        .await
        .unwrap();
        let v4_only = DnsEndpoint::parse_with_resolver(
            "dual.test:853",
            DnsProtocol::Tls,
            None,
            Some(resolver),
            DnsStrategy::Ipv4Only,
        )
        .unwrap()
        .resolve_addrs()
        .await
        .unwrap();
        let v6_only = DnsEndpoint::parse_with_resolver(
            "dual.test:853",
            DnsProtocol::Tls,
            None,
            Some(resolver),
            DnsStrategy::Ipv6Only,
        )
        .unwrap()
        .resolve_addrs()
        .await
        .unwrap();

        assert!(prefer_v4[0].is_ipv4());
        assert!(prefer_v4[1].is_ipv6());
        assert!(prefer_v6[0].is_ipv6());
        assert!(prefer_v6[1].is_ipv4());
        assert!(v4_only.iter().all(SocketAddr::is_ipv4));
        assert!(v6_only.iter().all(SocketAddr::is_ipv6));
    }

    async fn spawn_bootstrap_server(
        ipv4: [u8; 4],
        ipv6: Option<[u8; 16]>,
        requests: usize,
    ) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..requests {
                let mut query = [0u8; 512];
                let (length, peer) = socket.recv_from(&mut query).await.unwrap();
                let query = &query[..length];
                let qtype = u16::from_be_bytes([query[length - 4], query[length - 3]]);
                let mut response = query.to_vec();
                response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                let has_answer = qtype == 1 || qtype == 28 && ipv6.is_some();
                response[6..8].copy_from_slice(&u16::from(has_answer).to_be_bytes());
                if qtype == 1 {
                    response.extend_from_slice(&[
                        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
                    ]);
                    response.extend_from_slice(&ipv4);
                } else if qtype == 28
                    && let Some(ipv6) = ipv6
                {
                    response.extend_from_slice(&[
                        0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
                    ]);
                    response.extend_from_slice(&ipv6);
                }
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        address
    }
}
