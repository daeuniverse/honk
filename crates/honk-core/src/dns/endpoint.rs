//! Parse DNS upstream address strings into host/port/path/SNI.
//!
//! Config stores scheme-stripped fragments:
//! - `8.8.8.8:53`
//! - `dns.google:853`
//! - `dns.google/dns-query`
//! - `1.1.1.1:443/dns-query`

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use honk_config::dns::DnsStrategy;
use honk_config::types::DnsProtocol;
use tokio::time::Instant;

use super::transport::DnsSocketBudget;

/// Default DoH / DoH3 request path (RFC 8484).
pub const DEFAULT_DOH_PATH: &str = "/dns-query";
const MAX_RESOLVED_UPSTREAM_ADDRS: usize = 32;

pub(in crate::dns) struct ResolvedEndpointAddrs {
    pub(in crate::dns) addresses: Vec<SocketAddr>,
    pub(in crate::dns) min_ttl: Option<u32>,
}

/// Parsed upstream endpoint used by the encrypted DNS transports.
#[derive(Debug, Clone)]
pub struct DnsEndpoint {
    pub host: String,
    pub port: u16,
    /// HTTP path for DoH/DoH3 (always starts with `/`).
    pub path: String,
    /// TLS/QUIC server name (SNI). Falls back to `host` when host is not an IP.
    pub sni: String,
    literal_ip: Option<IpAddr>,
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

        let literal_ip = host.parse::<IpAddr>().ok();
        let sni = tls_server_name
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map_or_else(|| host.clone(), ToString::to_string);

        Ok(Self {
            host,
            port,
            path,
            sni,
            literal_ip,
            bootstrap_resolver,
            resolved_addr: None,
            strategy,
        })
    }
    pub(crate) fn with_resolved_addr(mut self, address: SocketAddr) -> Self {
        self.resolved_addr = Some(address);
        self
    }

    pub(in crate::dns) fn is_domain(&self) -> bool {
        self.resolved_addr.is_none() && self.literal_ip.is_none()
    }

    pub(in crate::dns) fn try_resolve_static(&self) -> Option<anyhow::Result<SocketAddr>> {
        if let Some(address) = self.resolved_addr {
            return Some(Ok(address));
        }
        let ip = self.literal_ip?;
        let allowed = match self.strategy {
            DnsStrategy::Ipv4Only => ip.is_ipv4(),
            DnsStrategy::Ipv6Only => ip.is_ipv6(),
            DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 | DnsStrategy::Both => true,
        };
        if allowed {
            Some(Ok(SocketAddr::new(ip, self.port)))
        } else {
            Some(Err(anyhow::anyhow!(
                "bootstrap resolve '{}' returned no addresses allowed by {:?}",
                self.host,
                self.strategy
            )))
        }
    }

    /// Resolve host to every allowed candidate, preferred family first.
    ///
    /// Dialers iterate this list so failure in the preferred family can fall
    /// back to the other family.
    pub async fn resolve_addrs(&self) -> anyhow::Result<Vec<SocketAddr>> {
        self.resolve_addrs_budgeted(
            &DnsSocketBudget::default(),
            Instant::now() + Duration::from_secs(10),
        )
        .await
    }

    pub(crate) async fn resolve_addrs_budgeted(
        &self,
        budget: &DnsSocketBudget,
        deadline: Instant,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        self.resolve_records_budgeted(budget, deadline)
            .await
            .map(|resolved| resolved.addresses)
    }

    pub(in crate::dns) async fn resolve_records_budgeted(
        &self,
        budget: &DnsSocketBudget,
        deadline: Instant,
    ) -> anyhow::Result<ResolvedEndpointAddrs> {
        if let Some(static_result) = self.try_resolve_static() {
            return static_result.map(|address| ResolvedEndpointAddrs {
                addresses: vec![address],
                min_ttl: None,
            });
        }
        let (families, credits) = match self.strategy {
            DnsStrategy::Ipv4Only => (honk_outbound::bootstrap::QueryFamilies::Ipv4Only, 1),
            DnsStrategy::Ipv6Only => (honk_outbound::bootstrap::QueryFamilies::Ipv6Only, 1),
            DnsStrategy::PreferIpv6 => (
                honk_outbound::bootstrap::QueryFamilies::Both { prefer_v6: true },
                2,
            ),
            DnsStrategy::PreferIpv4 | DnsStrategy::Both => (
                honk_outbound::bootstrap::QueryFamilies::Both { prefer_v6: false },
                2,
            ),
        };
        let resolved = honk_outbound::bootstrap::resolve_records_with_admission(
            self.bootstrap_resolver,
            &self.host,
            families,
            deadline,
            || async {
                budget
                    .acquire_bootstrap_credits_until(credits, deadline)
                    .await
                    .map_err(|error| std::io::Error::other(error.into_boxed_dyn_error()))
            },
        )
        .await
        .map_err(|error| {
            anyhow::Error::new(error).context(format!("bootstrap resolve '{}'", self.host))
        })?;
        if resolved.ips.is_empty() {
            anyhow::bail!("bootstrap resolve '{}' returned no addresses", self.host);
        }
        let addresses = self.filter_and_cap_ips(resolved.ips)?;
        Ok(ResolvedEndpointAddrs {
            addresses,
            min_ttl: resolved.min_ttl,
        })
    }

    fn filter_and_cap_ips(&self, ips: Vec<IpAddr>) -> anyhow::Result<Vec<SocketAddr>> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for ip in ips {
            let address = SocketAddr::new(ip, self.port);
            let target = if address.is_ipv4() { &mut v4 } else { &mut v6 };
            if !target.contains(&address) {
                target.push(address);
            }
        }
        let addresses = match self.strategy {
            DnsStrategy::PreferIpv6 => cap_dual_stack(v6, v4),
            DnsStrategy::Ipv4Only => {
                v4.truncate(MAX_RESOLVED_UPSTREAM_ADDRS);
                v4
            }
            DnsStrategy::Ipv6Only => {
                v6.truncate(MAX_RESOLVED_UPSTREAM_ADDRS);
                v6
            }
            DnsStrategy::PreferIpv4 | DnsStrategy::Both => cap_dual_stack(v4, v6),
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

/// Cap combined dual-stack candidates while preserving fallback records in the
/// secondary family when the primary family alone fills the cap.
fn cap_dual_stack(mut primary: Vec<SocketAddr>, mut secondary: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let secondary_reserve = secondary.len().min(MAX_RESOLVED_UPSTREAM_ADDRS / 2);
    let primary_keep = primary
        .len()
        .min(MAX_RESOLVED_UPSTREAM_ADDRS - secondary_reserve);
    let secondary_keep = secondary
        .len()
        .min(MAX_RESOLVED_UPSTREAM_ADDRS - primary_keep);
    primary.truncate(primary_keep);
    secondary.truncate(secondary_keep);
    primary.extend(secondary);
    primary
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
        let endpoint = |resolver| {
            DnsEndpoint::parse_with_resolver(
                "runtime.test:853",
                DnsProtocol::Tls,
                None,
                Some(resolver),
                DnsStrategy::default(),
            )
            .unwrap()
        };
        let old_resolver =
            honk_outbound::bootstrap::BootstrapResolver::parse(&format!("udp://{old}")).unwrap();
        let replacement_resolver =
            honk_outbound::bootstrap::BootstrapResolver::parse(&format!("udp://{replacement}"))
                .unwrap();

        // When
        let old_addrs = endpoint(old_resolver).resolve_addrs().await.unwrap();
        let replacement_addrs = endpoint(replacement_resolver)
            .resolve_addrs()
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
        let server = spawn_bootstrap_server(ipv4, Some(ipv6), 6).await;
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

    #[tokio::test]
    async fn bootstrap_burst_holds_two_sockets_until_inline_lookup_cancellation() {
        use honk_outbound::proxy::{PacketRejection, packet_rejection};
        use tokio::net::UdpSocket;

        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = honk_outbound::bootstrap::BootstrapResolver::parse(&format!(
            "udp://{}",
            silent.local_addr().unwrap()
        ))
        .unwrap();
        let budget = DnsSocketBudget::new(2);
        let endpoint = DnsEndpoint::parse_with_resolver(
            "first.invalid:853",
            DnsProtocol::Tls,
            None,
            Some(resolver),
            DnsStrategy::Both,
        )
        .unwrap();
        let mut first = Box::pin(
            endpoint.resolve_addrs_budgeted(&budget, Instant::now() + Duration::from_secs(10)),
        );
        let mut packet = [0; 512];
        let mut peers = Vec::with_capacity(2);
        let mut qtypes = Vec::with_capacity(2);
        for _ in 0..2 {
            let (length, peer) = tokio::select! {
                result = &mut first => panic!("silent bootstrap completed: {result:?}"),
                packet = tokio::time::timeout(
                    Duration::from_secs(1),
                    silent.recv_from(&mut packet),
                ) => packet.unwrap().unwrap(),
            };
            assert_eq!(&packet[12..length - 4], b"\x05first\x07invalid\0");
            qtypes.push(u16::from_be_bytes([packet[length - 4], packet[length - 3]]));
            peers.push(peer);
        }
        qtypes.sort_unstable();
        assert_eq!(qtypes, [1, 28]);
        assert_ne!(peers[0], peers[1]);
        assert_eq!(budget.available_sockets(), 0);
        for peer in &peers {
            let error = UdpSocket::bind(*peer).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        }

        let mut siblings = Vec::with_capacity(8);
        for index in 0..8 {
            let endpoint = DnsEndpoint::parse_with_resolver(
                &format!("blocked-{index}.invalid:853"),
                DnsProtocol::Tls,
                None,
                Some(resolver),
                DnsStrategy::Both,
            )
            .unwrap();
            let budget = budget.clone();
            let mut sibling = Box::pin(async move {
                endpoint
                    .resolve_addrs_budgeted(&budget, Instant::now() + Duration::from_secs(10))
                    .await
            });
            assert!(futures::poll!(sibling.as_mut()).is_pending());
            siblings.push(sibling);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), silent.recv_from(&mut packet))
                .await
                .is_err(),
            "blocked distinct hosts opened extra bootstrap sockets"
        );
        drop(siblings);
        assert_eq!(budget.available_sockets(), 0);

        let waiting = DnsEndpoint::parse_with_resolver(
            "deadline.invalid:853",
            DnsProtocol::Tls,
            None,
            Some(resolver),
            DnsStrategy::Both,
        )
        .unwrap();
        let error = waiting
            .resolve_addrs_budgeted(&budget, Instant::now() + Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(packet_rejection(&error), Some(PacketRejection::Capacity));
        assert_eq!(budget.available_sockets(), 0);
        drop(first);
        assert_eq!(budget.available_sockets(), 2);
        let _first_rebound = UdpSocket::bind(peers[0]).await.unwrap();
        let _second_rebound = UdpSocket::bind(peers[1]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), silent.recv_from(&mut packet))
                .await
                .is_err(),
            "cancelled bootstrap work sent another packet"
        );
    }

    #[tokio::test]
    async fn one_credit_refuses_hostname_bootstrap_but_numeric_and_resolved_endpoints_bypass_it() {
        use honk_outbound::proxy::{PacketRejection, packet_rejection};
        use tokio::net::UdpSocket;

        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = honk_outbound::bootstrap::BootstrapResolver::parse(&format!(
            "udp://{}",
            silent.local_addr().unwrap()
        ))
        .unwrap();
        let budget = DnsSocketBudget::new(1);
        let endpoint = DnsEndpoint::parse_with_resolver(
            "unadmitted.invalid:853",
            DnsProtocol::Tls,
            None,
            Some(resolver),
            DnsStrategy::Both,
        )
        .unwrap();
        let error = tokio::time::timeout(
            Duration::from_millis(100),
            endpoint.resolve_addrs_budgeted(&budget, Instant::now() + Duration::from_secs(1)),
        )
        .await
        .expect("an impossible two-socket reservation must fail immediately")
        .unwrap_err();
        assert_eq!(packet_rejection(&error), Some(PacketRejection::Capacity));
        assert_eq!(budget.available_sockets(), 1);

        let held = budget
            .acquire_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        for address in ["192.0.2.10:853", "[2001:db8::10]:853"] {
            let numeric = DnsEndpoint::parse(address, DnsProtocol::Tls, None).unwrap();
            assert_eq!(
                numeric
                    .resolve_addrs_budgeted(&budget, Instant::now())
                    .await
                    .unwrap(),
                vec![address.parse::<SocketAddr>().unwrap()]
            );
            assert_eq!(budget.available_sockets(), 0);
        }
        let resolved = SocketAddr::from(([192, 0, 2, 11], 853));
        assert_eq!(
            endpoint
                .with_resolved_addr(resolved)
                .resolve_addrs_budgeted(&budget, Instant::now())
                .await
                .unwrap(),
            vec![resolved]
        );
        assert_eq!(budget.available_sockets(), 0);
        drop(held);
        assert_eq!(budget.available_sockets(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), silent.recv_from(&mut [0; 512]))
                .await
                .is_err(),
            "unadmitted or pre-resolved endpoints sent a bootstrap query"
        );
    }

    #[tokio::test]
    async fn single_family_bootstrap_uses_one_credit_and_returns_ttl() {
        let ipv4 = [192, 0, 2, 10];
        let ipv6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let server = spawn_bootstrap_server(ipv4, Some(ipv6), 2).await;
        let resolver =
            honk_outbound::bootstrap::BootstrapResolver::parse(&format!("udp://{server}")).unwrap();
        let budget = DnsSocketBudget::new(1);
        for (strategy, expected) in [
            (DnsStrategy::Ipv4Only, SocketAddr::from((ipv4, 853))),
            (DnsStrategy::Ipv6Only, SocketAddr::from((ipv6, 853))),
        ] {
            let ep = DnsEndpoint::parse_with_resolver(
                "single.test:853",
                DnsProtocol::Tls,
                None,
                Some(resolver),
                strategy,
            )
            .unwrap();
            let res = ep
                .resolve_records_budgeted(&budget, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();
            assert_eq!((res.addresses, res.min_ttl), (vec![expected], Some(60)));
            assert_eq!(budget.available_sockets(), 1);
        }
    }

    #[test]
    fn cap_dual_stack_preserves_secondary_fallback_when_primary_exceeds_half_cap() {
        let v4 = |n| {
            (1..=n)
                .map(|i| SocketAddr::from(([192, 0, 2, i], 443)))
                .collect::<Vec<_>>()
        };
        let v6 = |n| {
            (1..=n)
                .map(|i| {
                    SocketAddr::from((
                        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i],
                        443,
                    ))
                })
                .collect::<Vec<_>>()
        };
        let (p, s) = (v4(28), v6(6));
        let capped = cap_dual_stack(p.clone(), s.clone());
        assert_eq!((&capped[..26], &capped[26..]), (&p[..26], &s[..6]));
        let balanced = cap_dual_stack(p, v6(20));
        assert_eq!(balanced.iter().filter(|a| a.is_ipv4()).count(), 16);
        assert_eq!(balanced.iter().filter(|a| a.is_ipv6()).count(), 16);
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
