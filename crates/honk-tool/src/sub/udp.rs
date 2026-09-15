use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use honk_config::node::Node;
use honk_core::dns::DnsResolver;
use honk_core::proxy::ProxyRegistry;

use super::ProbeFailureKind;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum UdpCheckTarget {
    Literal(SocketAddr),
    Host { host: String, port: u16 },
}

impl UdpCheckTarget {
    pub(super) fn port(&self) -> u16 {
        match self {
            Self::Literal(address) => address.port(),
            Self::Host { port, .. } => *port,
        }
    }
}

pub(super) fn parse_udp_check_target(targets: &[String]) -> anyhow::Result<UdpCheckTarget> {
    for target in targets {
        if let Ok(endpoint) = honk_core::dns::endpoint::DnsEndpoint::parse(
            target.trim(),
            honk_config::types::DnsProtocol::Udp,
            None,
        ) && let Ok(ip) = endpoint.host.parse::<IpAddr>()
        {
            return Ok(UdpCheckTarget::Literal(SocketAddr::new(ip, endpoint.port)));
        }
    }
    let target = targets
        .first()
        .map(String::as_str)
        .context("--udp-check requires at least one target")?
        .trim();
    let endpoint = honk_core::dns::endpoint::DnsEndpoint::parse(
        target,
        honk_config::types::DnsProtocol::Udp,
        None,
    )?;
    Ok(UdpCheckTarget::Host {
        host: endpoint.host,
        port: endpoint.port,
    })
}

// Avoid uncancellable getaddrinfo work and public-resolver fallback.
pub(super) fn system_dns_resolver() -> Option<DnsResolver> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let server = contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "nameserver" {
            return None;
        }
        fields
            .next()?
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })?;
    let mut config = honk_config::dns::DnsConfig {
        upstream: vec![honk_config::dns::DnsUpstream {
            name: "system".into(),
            address: server.to_string(),
            protocol: honk_config::types::DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }],
        ..Default::default()
    };
    config.routing.fallback = "system".into();
    if std::path::Path::new(honk_config::dns::SYSTEM_HOSTS_PATH).is_file() {
        config
            .hosts
            .push(honk_config::dns::SYSTEM_HOSTS_PATH.into());
    }
    DnsResolver::new(&config).ok()
}

async fn resolve_udp_check_target(
    target: &UdpCheckTarget,
    resolver: Option<&DnsResolver>,
) -> Result<SocketAddr, ProbeFailureKind> {
    match target {
        UdpCheckTarget::Literal(address) => Ok(*address),
        UdpCheckTarget::Host { host, port } => {
            let Some(resolver) = resolver else {
                return Err(ProbeFailureKind::Resolve);
            };
            let resolved = resolver
                .resolve_without_fallback(host)
                .await
                .map_err(|_| ProbeFailureKind::Resolve)?;
            resolved
                .ipv4
                .into_iter()
                .chain(resolved.ipv6)
                .next()
                .map(|ip| SocketAddr::new(ip, *port))
                .ok_or(ProbeFailureKind::Resolve)
        }
    }
}

fn next_rand(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn rand_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64 | 1)
        .unwrap_or(0x9e3779b97f4a7c15)
}

pub(super) fn build_dns_probe_query(id: u16) -> Vec<u8> {
    let mut query = honk_core::dns::forwarder::build_dns_query("google.com", 1);
    query[..2].copy_from_slice(&id.to_be_bytes());
    query
}

/// UDP probe: one minimal DNS A query through the node's UDP transport.
/// Proves the node's UDP relay path end to end (mirrors the engine's
/// `probe_node_udp` health check).
pub(super) async fn probe_udp_dns(
    registry: &ProxyRegistry,
    node: &Node,
    target: &UdpCheckTarget,
    resolver: Option<&DnsResolver>,
    timeout: Duration,
) -> Option<Result<Duration, ProbeFailureKind>> {
    let Some(entry) = registry.find(node.protocol()) else {
        return Some(Err(ProbeFailureKind::Handler));
    };
    if !(entry.descriptor.supports_udp)(node) {
        return None;
    }
    if !honk_outbound::descriptor::udp_target_allowed(node, target.port()) {
        return None;
    }
    let packet = entry.packet.as_ref()?;
    let result = tokio::time::timeout(timeout, async {
        let dns_server = resolve_udp_check_target(target, resolver).await?;
        let transport = packet
            .dial_udp_transport(node, dns_server, None, timeout)
            .await
            .map_err(|_| ProbeFailureKind::Exchange)?;

        let mut rng = rand_seed();
        let id = next_rand(&mut rng) as u16;
        let query = build_dns_probe_query(id);

        let start = Instant::now();
        transport
            .send_packet(&query)
            .await
            .map_err(|_| ProbeFailureKind::Exchange)?;
        let mut buf = [0u8; 512];
        match transport.recv_packet(&mut buf).await {
            Ok((n, _)) if n >= 2 && buf[0] == query[0] && buf[1] == query[1] => Ok(start.elapsed()),
            Ok(_) | Err(_) => Err(ProbeFailureKind::Exchange),
        }
    })
    .await;
    Some(match result {
        Ok(result) => result,
        Err(_) => Err(ProbeFailureKind::Timeout),
    })
}

/// UDP probe for QUIC: run a real QUIC handshake through the node's UDP
/// transport and time it.  Unlike a bare Version-Negotiation trigger (which
/// most frontends silently drop), this proves TLS-in-QUIC reachability
/// through the node's UDP path.
pub(super) async fn probe_udp_quic(
    registry: &ProxyRegistry,
    node: &Node,
    url_host: &str,
    url_port: u16,
    timeout: Duration,
) -> Option<Result<Duration, ProbeFailureKind>> {
    let Some(entry) = registry.find(node.protocol()) else {
        return Some(Err(ProbeFailureKind::Handler));
    };
    if !(entry.descriptor.supports_udp)(node) {
        return None;
    }
    if !honk_outbound::descriptor::udp_target_allowed(node, url_port) {
        return None;
    }
    let packet = entry.packet.as_ref()?;
    let addr = match tokio::net::lookup_host((url_host, url_port)).await {
        Ok(mut addrs) => addrs.find(SocketAddr::is_ipv4)?,
        Err(_) => return Some(Err(ProbeFailureKind::Resolve)),
    };
    let transport = match packet.dial_udp_transport(node, addr, None, timeout).await {
        Ok(transport) => transport,
        Err(_) => return Some(Err(ProbeFailureKind::Exchange)),
    };

    let probe_node = Node {
        outbound: honk_config::node::OutboundConfig::Hysteria2(
            honk_config::node::Hysteria2Config {
                quic: honk_config::node::QuicOptions {
                    tls: honk_config::node::TlsOptions {
                        skip_cert_verify: true,
                        sni: Some(url_host.to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let config = match honk_outbound::quic::client_config(
        &probe_node,
        &[b"h3"],
        honk_outbound::quic::QuicClientOptions::default(),
    )
    .await
    {
        Ok(config) => config,
        Err(_) => return Some(Err(ProbeFailureKind::Exchange)),
    };

    Some(
        honk_outbound::quic::quic_handshake_probe(transport, addr, url_host, &config, timeout)
            .await
            .map_err(|_| ProbeFailureKind::Exchange),
    )
}
