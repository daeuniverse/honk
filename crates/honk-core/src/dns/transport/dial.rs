use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use super::super::endpoint::DnsEndpoint;
use crate::proxy::ProxyRegistry;
use honk_config::node::Node;

/// Shared dial context for transports that may go direct or via a proxy node.
#[derive(Clone)]
pub struct DialContext {
    pub endpoint: DnsEndpoint,
    pub query_timeout: Duration,
    pub dial_timeout: Duration,
    /// When set, TCP/TLS/QUIC is established through this proxy to `endpoint`.
    pub proxy: Option<ProxyDial>,
}

#[derive(Clone)]
pub struct ProxyDial {
    pub registry: Arc<ProxyRegistry>,
    /// Immutable outbound generation captured by the owning DNS runtime.
    /// Legacy unit-test pools may omit it and use the node path directly.
    pub generation: Option<Arc<honk_outbound::runtime::OutboundRuntimeRegistry>>,
    pub node: Node,
}

/// Try candidates in order, sharing the remaining aggregate time equally
/// among the attempts that have not started yet.
pub(super) async fn dial_candidates<T, F, Fut>(
    addresses: Vec<std::net::SocketAddr>,
    deadline: tokio::time::Instant,
    label: &str,
    mut dial: F,
) -> anyhow::Result<T>
where
    F: FnMut(std::net::SocketAddr, Duration) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let candidate_count = addresses.len();
    let mut last_error = None;
    for (index, address) in addresses.into_iter().enumerate() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let candidates_left = u32::try_from(candidate_count - index).unwrap_or(u32::MAX);
        let budget = remaining / candidates_left;
        let error = match tokio::time::timeout(budget, dial(address, budget)).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(error)) => error,
            Err(_) => anyhow::anyhow!("timed out after {budget:?}"),
        };
        tracing::debug!(
            %address,
            transport = label,
            error = %error,
            "DNS dial failed; trying next address"
        );
        last_error = Some(anyhow::anyhow!("{label} dial to {address}: {error}"));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("{label} resolved to no addresses")))
}

impl DialContext {
    /// Dial a plain TCP stream to the upstream (marked, or via proxy).
    ///
    /// Tries every bootstrap-resolved address in configured family order.
    pub async fn dial_tcp(&self) -> anyhow::Result<tokio::net::TcpStream> {
        if self.proxy.is_some() {
            // Proxy handlers return a boxed stream already connected to the
            // target; for TLS we need a TcpStream-shaped base only on the
            // direct path. Proxy+TLS is handled separately via boxed stream.
            anyhow::bail!("dial_tcp called with proxy set; use dial_tcp_boxed")
        }
        self.dial_tcp_until(tokio::time::Instant::now() + self.dial_timeout)
            .await
    }

    async fn dial_tcp_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<tokio::net::TcpStream> {
        let addresses = tokio::time::timeout_at(deadline, self.endpoint.resolve_addrs())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "DNS TCP address resolution timed out after {:?}",
                    self.dial_timeout
                )
            })??;
        dial_candidates(addresses, deadline, "TCP", |address, budget| async move {
            honk_outbound::util::connect_marked_addr(
                address,
                Some(honk_ebpf_common::DAE_BYPASS_MARK),
                budget,
            )
            .await
            .map_err(anyhow::Error::from)
        })
        .await
    }

    /// Dial through the optional proxy, returning a boxed duplex stream to the
    /// upstream DNS server address.
    pub async fn dial_tcp_boxed(&self) -> anyhow::Result<Box<dyn crate::proxy::AsyncReadWrite>> {
        self.dial_tcp_boxed_until(tokio::time::Instant::now() + self.dial_timeout)
            .await
    }

    pub(super) async fn dial_tcp_boxed_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<Box<dyn crate::proxy::AsyncReadWrite>> {
        if let Some(proxy) = &self.proxy {
            let addresses = tokio::time::timeout_at(deadline, self.endpoint.resolve_addrs())
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "DNS proxy target resolution timed out after {:?}",
                        self.dial_timeout
                    )
                })??;
            let stream = dial_candidates(
                addresses,
                deadline,
                "Proxy DNS",
                |address, budget| async move {
                    if let Some(generation) = &proxy.generation {
                        proxy
                            .registry
                            .dial_runtime(
                                Arc::clone(generation),
                                proxy.node.id,
                                address,
                                None,
                                budget,
                            )
                            .await
                    } else {
                        proxy
                            .registry
                            .dial(&proxy.node, address, None, budget)
                            .await
                    }
                },
            )
            .await?;
            return Ok(stream.stream);
        }
        let stream = self.dial_tcp_until(deadline).await?;
        Ok(Box::new(stream))
    }
    /// Open a proxy packet transport before constructing a QUIC endpoint.
    pub(super) async fn dial_packet_transport_until(
        &self,
        remote: std::net::SocketAddr,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<Arc<dyn honk_outbound::proxy::PacketTransport>> {
        let Some(proxy) = &self.proxy else {
            anyhow::bail!("packet transport requested without proxy")
        };
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("DNS proxy packet setup deadline elapsed")
        }
        let transport = if let Some(generation) = &proxy.generation {
            tokio::time::timeout_at(
                deadline,
                proxy.registry.dial_udp_transport_runtime(
                    Arc::clone(generation),
                    proxy.node.id,
                    remote,
                    None,
                    remaining,
                ),
            )
            .await
            .map_err(|_| anyhow::anyhow!("DNS proxy packet setup timed out"))??
        } else {
            tokio::time::timeout_at(
                deadline,
                proxy
                    .registry
                    .dial_udp_transport(&proxy.node, remote, None, remaining),
            )
            .await
            .map_err(|_| anyhow::anyhow!("DNS proxy packet setup timed out"))??
        };
        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[tokio::test(start_paused = true)]
    async fn silent_first_candidate_leaves_budget_for_fallback() {
        let first = "192.0.2.1:53".parse().unwrap();
        let second = "[2001:db8::1]:53".parse().unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&attempts);
        let start = tokio::time::Instant::now();
        tokio::time::sleep(Duration::from_millis(500)).await;

        let connected = dial_candidates(
            vec![first, second],
            start + Duration::from_secs(3),
            "test",
            move |address, budget| {
                recorded.lock().push((address, budget));
                async move {
                    if address == first {
                        std::future::pending::<()>().await;
                    }
                    Ok(address)
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(connected, second);
        assert_eq!(
            *attempts.lock(),
            vec![
                (first, Duration::from_millis(1250)),
                (second, Duration::from_millis(1250))
            ]
        );
        assert_eq!(start.elapsed(), Duration::from_millis(1750));
    }

    #[tokio::test(start_paused = true)]
    async fn candidate_count_does_not_multiply_deadline() {
        let addresses = vec![
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
            "[2001:db8::1]:53".parse().unwrap(),
        ];
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&attempts);
        let start = tokio::time::Instant::now();

        let error = dial_candidates(
            addresses.clone(),
            start + Duration::from_secs(3),
            "test",
            move |address, _| {
                recorded.lock().push(address);
                async move {
                    std::future::pending::<()>().await;
                    Ok(address)
                }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(*attempts.lock(), addresses);
        assert_eq!(start.elapsed(), Duration::from_secs(3));
        assert!(error.to_string().contains("[2001:db8::1]:53"));
    }
}
