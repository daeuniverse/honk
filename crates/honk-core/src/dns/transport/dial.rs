use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use super::super::endpoint::DnsEndpoint;
use super::budget::DnsSocketBudget;
use crate::proxy::ProxyRegistry;
use honk_config::node::Node;

type DnsTcpStream =
    honk_outbound::proxy::RuntimeOwnedIo<tokio::net::TcpStream, tokio::sync::OwnedSemaphorePermit>;

/// Shared dial context for transports that may go direct or via a proxy node.
#[derive(Clone)]
pub struct DialContext {
    pub endpoint: DnsEndpoint,
    pub query_timeout: Duration,
    pub dial_timeout: Duration,
    pub socket_budget: DnsSocketBudget,
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

pub(super) enum PacketAdmission<'a> {
    Physical(&'a DnsSocketBudget),
    Proxy(&'a DnsSocketBudget),
}

/// Try candidates in order, sharing the remaining aggregate time equally
/// among the attempts that have not started yet.
pub(super) async fn dial_candidates<T, F, Fut>(
    addresses: Vec<std::net::SocketAddr>,
    deadline: tokio::time::Instant,
    label: &str,
    admission: Option<PacketAdmission<'_>>,
    mut dial: F,
) -> anyhow::Result<T>
where
    F: FnMut(std::net::SocketAddr, Duration, Option<tokio::sync::OwnedSemaphorePermit>) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let candidate_count = addresses.len();
    let mut last_error = None;
    for (index, address) in addresses.into_iter().enumerate() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let candidates_left = u32::try_from(candidate_count - index).unwrap_or(u32::MAX);
        let budget = remaining / candidates_left;
        let candidate_deadline = tokio::time::Instant::now() + budget;
        // Keep capacity refusal outside the physical-attempt timeout and address retry.
        let permit = match admission {
            Some(PacketAdmission::Physical(budget)) => {
                Some(budget.acquire_until(candidate_deadline).await?)
            }
            Some(PacketAdmission::Proxy(budget)) => {
                Some(budget.acquire_proxy_until(candidate_deadline).await?)
            }
            None => None,
        };
        let remaining = candidate_deadline.saturating_duration_since(tokio::time::Instant::now());
        let error =
            match tokio::time::timeout_at(candidate_deadline, dial(address, remaining, permit))
                .await
            {
                Ok(Ok(value)) => return Ok(value),
                Ok(Err(error)) => error,
                Err(_) => anyhow::anyhow!("timed out after {budget:?}"),
            };
        if honk_outbound::proxy::is_packet_rejection(&error) {
            return Err(error.context(format!("{label} dial to {address}")));
        }
        tracing::debug!(
            %address,
            transport = label,
            error = %error,
            "DNS dial failed; trying next address"
        );
        last_error = Some(error.context(format!("{label} dial to {address}")));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("{label} resolved to no addresses")))
}

impl DialContext {
    /// Dial a plain TCP stream to the upstream (marked, or via proxy).
    ///
    /// Tries every bootstrap-resolved address in configured family order.
    pub async fn dial_tcp(&self) -> anyhow::Result<DnsTcpStream> {
        if self.proxy.is_some() {
            // Proxy streams already enter outbound physical dial admission.
            anyhow::bail!("dial_tcp called with proxy set; use dial_tcp_boxed")
        }
        self.dial_tcp_until(tokio::time::Instant::now() + self.dial_timeout)
            .await
    }

    async fn dial_tcp_until(&self, deadline: tokio::time::Instant) -> anyhow::Result<DnsTcpStream> {
        let addresses = self
            .endpoint
            .resolve_addrs_budgeted(&self.socket_budget, deadline)
            .await?;
        dial_candidates(
            addresses,
            deadline,
            "TCP",
            Some(PacketAdmission::Physical(&self.socket_budget)),
            |address, budget, permit| async move {
                let stream = honk_outbound::util::connect_marked_addr(
                    address,
                    Some(honk_outbound::util::bypass_mark()),
                    budget,
                )
                .await?;
                Ok(honk_outbound::proxy::RuntimeOwnedIo::new(
                    stream,
                    permit.expect("direct TCP has socket admission"),
                ))
            },
        )
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
            let addresses = self
                .endpoint
                .resolve_addrs_budgeted(&self.socket_budget, deadline)
                .await?;
            let permit = self.socket_budget.acquire_proxy_until(deadline).await?;
            let stream = dial_candidates(
                addresses,
                deadline,
                "Proxy DNS",
                None,
                |address, budget, _| async move {
                    let dial = async {
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
                    };
                    let dial = crate::observe::flows::dns::outbound_dial_scope(&proxy.node, dial);
                    dial.await
                },
            )
            .await?;
            return Ok(Box::new(honk_outbound::proxy::RuntimeOwnedIo::new(
                stream.stream,
                permit,
            )));
        }
        let stream = self.dial_tcp_until(deadline).await?;
        Ok(Box::new(stream))
    }

    pub(super) fn packet_admission(&self) -> Option<PacketAdmission<'_>> {
        match self.proxy.as_ref().map(|proxy| proxy.node.protocol()) {
            None
            | Some(
                honk_config::types::NodeProtocol::Direct
                | honk_config::types::NodeProtocol::SS
                | honk_config::types::NodeProtocol::Socks5,
            ) => Some(PacketAdmission::Physical(&self.socket_budget)),
            Some(_) => Some(PacketAdmission::Proxy(&self.socket_budget)),
        }
    }

    /// Open a proxy packet transport before constructing a QUIC endpoint.
    pub(super) async fn dial_packet_transport_until(
        &self,
        remote: std::net::SocketAddr,
        deadline: tokio::time::Instant,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> anyhow::Result<Arc<dyn honk_outbound::proxy::PacketTransport>> {
        let Some(proxy) = &self.proxy else {
            anyhow::bail!("packet transport requested without proxy")
        };
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("DNS proxy packet setup deadline elapsed")
        }
        let dial = async {
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
            Ok(match permit {
                Some(permit) => {
                    honk_outbound::proxy::packet_transport_with_owner(transport, permit)
                }
                None => transport,
            })
        };
        let dial = crate::observe::flows::dns::outbound_dial_scope(&proxy.node, dial);
        dial.await
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
            None,
            move |address, budget, _| {
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
            None,
            move |address, _, _| {
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

    #[tokio::test]
    async fn packet_rejection_does_not_try_another_address() {
        let first = "192.0.2.1:53".parse().unwrap();
        let second = "192.0.2.2:53".parse().unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&attempts);

        let error = dial_candidates(
            vec![first, second],
            tokio::time::Instant::now() + Duration::from_secs(1),
            "test",
            None,
            move |address, _, _| {
                recorded.lock().push(address);
                async move {
                    Err::<std::net::SocketAddr, _>(
                        honk_outbound::proxy::PacketRejection::Policy.into(),
                    )
                }
            },
        )
        .await
        .unwrap_err();

        assert!(honk_outbound::proxy::is_packet_rejection(&error));
        assert_eq!(*attempts.lock(), vec![first]);
    }

    #[tokio::test(start_paused = true)]
    async fn capacity_refusal_does_not_start_or_retry_an_address() {
        let physical_budget = DnsSocketBudget::new(0);
        let proxy_budget = DnsSocketBudget::new(1);
        let held = proxy_budget
            .acquire_proxy_until(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        for admission in [
            PacketAdmission::Physical(&physical_budget),
            PacketAdmission::Proxy(&proxy_budget),
        ] {
            let attempts = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&attempts);
            let start = tokio::time::Instant::now();
            let error = dial_candidates(
                vec![
                    "192.0.2.1:53".parse().unwrap(),
                    "[2001:db8::1]:53".parse().unwrap(),
                ],
                start + Duration::from_secs(3),
                "test",
                Some(admission),
                move |address, _, _| {
                    recorded.lock().push(address);
                    async move { Ok(address) }
                },
            )
            .await
            .unwrap_err();
            assert_eq!(
                honk_outbound::proxy::packet_rejection(&error),
                Some(honk_outbound::proxy::PacketRejection::Capacity)
            );
            assert!(attempts.lock().is_empty());
            assert_eq!(start.elapsed(), Duration::from_millis(1500));
        }
        drop(held);
    }
}
