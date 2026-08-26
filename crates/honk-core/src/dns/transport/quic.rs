use std::time::Duration;

use super::dial::{DialContext, dial_candidates};
use crate::dns::endpoint::DnsEndpoint;

/// Shared QUIC client config for DNS transports (15s keep-alive, cubic).
pub(super) async fn dns_quic_config(alpn: &[&[u8]]) -> anyhow::Result<quinn::ClientConfig> {
    honk_outbound::quic::client_config(
        &Default::default(),
        alpn,
        honk_outbound::quic::QuicClientOptions {
            keep_alive: Some(Duration::from_secs(15)),
            ..honk_outbound::quic::QuicClientOptions::with_congestion(Some("cubic"))
        },
    )
    .await
}

/// Lazily-created per-family QUIC client endpoints reused across reconnects.
pub(super) struct SharedQuicEndpoint(tokio::sync::Mutex<[Option<quinn::Endpoint>; 2]>);

impl SharedQuicEndpoint {
    pub(super) fn new() -> Self {
        Self(tokio::sync::Mutex::new([None, None]))
    }

    async fn get(&self, ipv6: bool) -> anyhow::Result<quinn::Endpoint> {
        let mut endpoints = self.0.lock().await;
        let endpoint = &mut endpoints[if ipv6 { 1 } else { 0 }];
        if let Some(endpoint) = endpoint.as_ref() {
            return Ok(endpoint.clone());
        }
        let created = honk_outbound::quic::client_endpoint(ipv6)
            .map_err(|e| anyhow::anyhow!("QUIC client endpoint: {e}"))?;
        *endpoint = Some(created.clone());
        Ok(created)
    }

    pub(super) async fn close(&self, timeout: Duration) {
        let endpoints = {
            let mut endpoints = self.0.lock().await;
            [endpoints[0].take(), endpoints[1].take()]
        };
        for endpoint in endpoints.into_iter().flatten() {
            endpoint.close(0_u32.into(), b"shutdown");
            let _ = tokio::time::timeout(timeout, endpoint.wait_idle()).await;
        }
    }
}

/// Connect `config` to `addr`, using either the shared direct endpoint or an
/// endpoint backed by the selected proxy's PacketTransport. `label` prefixes
/// error messages (`DoQ` / `DoH3 QUIC`).
async fn quic_connect(
    dial: &DialContext,
    direct_endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    addr: std::net::SocketAddr,
    sni: &str,
    label: &str,
    budget: Duration,
) -> anyhow::Result<(
    quinn::Connection,
    Option<honk_outbound::quic::PacketTransportEndpoint>,
)> {
    let deadline = tokio::time::Instant::now() + budget;
    let (connecting, owner) = if dial.proxy.is_some() {
        let transport = dial.dial_packet_transport_until(addr, deadline).await?;
        let owner = honk_outbound::quic::packet_transport_endpoint(transport, addr)
            .map_err(|error| anyhow::anyhow!("{label} packet endpoint: {error}"))?;
        let connecting = owner
            .endpoint()
            .connect_with(config.clone(), addr, sni)
            .map_err(|e| anyhow::anyhow!("{label} connect_with: {e}"))?;
        (connecting, Some(owner))
    } else {
        let endpoint = direct_endpoint.get(addr.is_ipv6()).await?;
        let connecting = endpoint
            .connect_with(config.clone(), addr, sni)
            .map_err(|e| anyhow::anyhow!("{label} connect_with: {e}"))?;
        (connecting, None)
    };
    let connection = tokio::time::timeout_at(deadline, connecting)
        .await
        .map_err(|_| anyhow::anyhow!("{label} handshake timed out"))?
        .map_err(|e| anyhow::anyhow!("{label} handshake: {e}"))?;
    Ok((connection, owner))
}

pub(super) async fn quic_connect_endpoint(
    dial: &DialContext,
    direct_endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    target: &DnsEndpoint,
    deadline: tokio::time::Instant,
    label: &str,
) -> anyhow::Result<(
    quinn::Connection,
    Option<honk_outbound::quic::PacketTransportEndpoint>,
)> {
    let addresses = tokio::time::timeout_at(deadline, target.resolve_addrs())
        .await
        .map_err(|_| anyhow::anyhow!("{label} address resolution timed out"))??;
    dial_candidates(addresses, deadline, label, |address, budget| {
        quic_connect(
            dial,
            direct_endpoint,
            config,
            address,
            &target.sni,
            label,
            budget,
        )
    })
    .await
}
