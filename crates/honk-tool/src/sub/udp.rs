use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

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

pub(super) fn resolve_udp_probe_target<'a>(
    registry: &'a ProxyRegistry,
    runtimes: Option<&'a honk_outbound::runtime::OutboundRuntimeRegistry>,
    node: &'a Node,
    port: u16,
) -> Result<Option<&'a dyn honk_outbound::proxy::PacketOutbound>, ProbeFailureKind> {
    if let Some(runtimes) = runtimes
        && runtimes.get(&node.id).is_some()
    {
        return match registry.udp_probe_target(runtimes, node) {
            Ok((packet, terminal)) => {
                Ok(honk_outbound::descriptor::udp_target_allowed(terminal, port).then_some(packet))
            }
            Err(error)
                if error
                    .chain()
                    .any(|cause| cause.is::<honk_outbound::proxy::MissingProtocolHandler>()) =>
            {
                Err(ProbeFailureKind::Handler)
            }
            Err(_) => Ok(None),
        };
    }
    if node.chain_hops().is_some() {
        return if registry.find(node.protocol()).is_none() {
            Err(ProbeFailureKind::Handler)
        } else {
            Err(ProbeFailureKind::Admission)
        };
    }
    let Some(entry) = registry.find(node.protocol()) else {
        return Err(ProbeFailureKind::Handler);
    };
    if !honk_outbound::descriptor::carries_udp(honk_outbound::descriptor::UdpPath::Own(node))
        || !honk_outbound::descriptor::udp_target_allowed(node, port)
    {
        return Ok(None);
    }
    Ok(entry.packet.as_deref())
}

async fn dial_probe_udp_transport(
    packet: &dyn honk_outbound::proxy::PacketOutbound,
    runtimes: Option<&honk_outbound::runtime::OutboundRuntimeRegistry>,
    node: &Node,
    target: SocketAddr,
    timeout: Duration,
) -> Result<std::sync::Arc<dyn honk_outbound::proxy::PacketTransport>, ProbeFailureKind> {
    if node.chain_hops().is_some() {
        let runtimes = runtimes.ok_or(ProbeFailureKind::Admission)?;
        let (runtime, guard) = super::acquire_probe_runtime(
            Some(runtimes),
            node,
            honk_outbound::proxy::WarmRequirement::Udp,
        )?;
        let result = runtimes
            .scope_dials(packet.dial_udp_transport_runtime(runtime, target, None, timeout))
            .await
            .map_err(|error| super::classify_probe_dial_error(&error));
        super::close_probe_guard(guard).await;
        return result;
    }
    let dial = packet.dial_udp_transport(node, target, None, timeout);
    let result = match runtimes {
        Some(runtimes) => runtimes.scope_dials(dial).await,
        None => dial.await,
    };
    result.map_err(|error| super::classify_probe_dial_error(&error))
}

/// UDP probe: one minimal DNS A query through the node's UDP transport.
/// Proves the node's UDP relay path end to end (mirrors the engine's
/// `probe_node_udp` health check).
pub(super) async fn probe_udp_dns(
    registry: &ProxyRegistry,
    runtimes: Option<&honk_outbound::runtime::OutboundRuntimeRegistry>,
    node: &Node,
    target: &UdpCheckTarget,
    resolver: Option<&DnsResolver>,
    timeout: Duration,
) -> Option<Result<Duration, ProbeFailureKind>> {
    let packet = match resolve_udp_probe_target(registry, runtimes, node, target.port()) {
        Ok(Some(packet)) => packet,
        Ok(None) => return None,
        Err(failure) => return Some(Err(failure)),
    };
    let result = tokio::time::timeout(timeout, async {
        let dns_server = resolve_udp_check_target(target, resolver).await?;
        let transport =
            dial_probe_udp_transport(packet, runtimes, node, dns_server, timeout).await?;
        honk_core::dns::forwarder::udp_dns_probe(&*transport)
            .await
            .map(|sample| sample.latency)
            .map_err(|_| ProbeFailureKind::Exchange)
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
    runtimes: Option<&honk_outbound::runtime::OutboundRuntimeRegistry>,
    node: &Node,
    url_host: &str,
    url_port: u16,
    timeout: Duration,
) -> Option<Result<Duration, ProbeFailureKind>> {
    let packet = match resolve_udp_probe_target(registry, runtimes, node, url_port) {
        Ok(Some(packet)) => packet,
        Ok(None) => return None,
        Err(failure) => return Some(Err(failure)),
    };
    let addr = match tokio::net::lookup_host((url_host, url_port)).await {
        Ok(mut addrs) => addrs.find(SocketAddr::is_ipv4)?,
        Err(_) => return Some(Err(ProbeFailureKind::Resolve)),
    };
    let transport = match dial_probe_udp_transport(packet, runtimes, node, addr, timeout).await {
        Ok(transport) => transport,
        Err(failure) => return Some(Err(failure)),
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
        honk_outbound::quic::quic_handshake_probe(
            transport,
            addr,
            url_host,
            &config,
            timeout,
            honk_outbound::alive::ProbeCancellation::default(),
        )
        .await
        .map(|measurement| measurement.latency)
        .map_err(|_| ProbeFailureKind::Exchange),
    )
}
