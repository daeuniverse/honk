use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;

use honk_config::types::DnsProtocol;
use tracing::debug;

use super::UpstreamPool;
use super::admission::AdmissionPermit;
use super::entries::UpstreamEntry;
use super::routing::DnsDialRoute;
use crate::dns::ecs::EcsQuery;
use crate::dns::forwarder::DnsUpstreamPool;

fn udp_attempt_addresses(
    addresses: &[SocketAddr],
    current: Option<SocketAddr>,
) -> Option<[SocketAddr; 2]> {
    let first = current
        .filter(|address| addresses.contains(address))
        .or_else(|| addresses.first().copied())?;
    let retry = addresses
        .iter()
        .copied()
        .find(|address| address.is_ipv4() != first.is_ipv4())
        .or_else(|| addresses.iter().copied().find(|address| *address != first))
        .unwrap_or(first);
    Some([first, retry])
}

fn retryable_error(error: anyhow::Error) -> anyhow::Result<anyhow::Error> {
    if honk_outbound::proxy::is_packet_rejection(&error) {
        Err(error)
    } else {
        Ok(error)
    }
}

fn admit_score_attempt(
    feedback: Option<&honk_outbound::group::ScoreAttempt>,
    original: &mut Option<honk_outbound::group::ScoreContinuation>,
) -> anyhow::Result<Option<honk_outbound::group::ScoreBusinessGuard>> {
    feedback
        .map(|feedback| {
            let business = feedback.begin()?;
            original.get_or_insert_with(|| business.continuation());
            Ok(business)
        })
        .transpose()
}

impl UpstreamPool {
    pub(super) async fn udp_pool(
        &self,
        entry: &UpstreamEntry,
        address: SocketAddr,
    ) -> anyhow::Result<Arc<crate::dns::transport::UdpPool>> {
        let family = if address.is_ipv6() { 1 } else { 0 };
        if let Some((cached_address, pool)) = entry.udp.lock().pools[family].as_ref()
            && *cached_address == address
            && !pool.is_stopped()
        {
            if let Some(observer) = honk_outbound::runtime::flow_observation::current() {
                observer.publish(
                    honk_outbound::runtime::flow_observation::FlowEvent::TransportAttached {
                        server_addr: Some(address),
                        resolution_location:
                            honk_outbound::runtime::flow_observation::ResolutionLocation::Local,
                    },
                );
            }
            return Ok(Arc::clone(pool));
        }
        let candidate = crate::dns::transport::UdpPool::new_tracked(
            address,
            self.dns_query_timeout,
            Arc::clone(&self.active_transport_tasks),
        );
        let candidate = candidate.await?;
        let (pool, unused) = {
            let mut state = entry.udp.lock();
            if let Some((cached_address, pool)) = state.pools[family].as_ref()
                && *cached_address == address
                && !pool.is_stopped()
            {
                (Arc::clone(pool), Some(candidate))
            } else {
                if state
                    .current
                    .is_some_and(|current| current.is_ipv6() == address.is_ipv6())
                {
                    state.current = None;
                }
                let _ = state.pools[family].replace((address, Arc::clone(&candidate)));
                (candidate, None)
            }
        };
        if let Some(unused) = unused {
            unused.close().await;
            if let Some(observer) = honk_outbound::runtime::flow_observation::current() {
                observer.publish(
                    honk_outbound::runtime::flow_observation::FlowEvent::TransportAttached {
                        server_addr: Some(address),
                        resolution_location:
                            honk_outbound::runtime::flow_observation::ResolutionLocation::Local,
                    },
                );
            }
        }
        Ok(pool)
    }

    async fn admit_query(&self) -> anyhow::Result<AdmissionPermit<'_>> {
        let admission = self
            .admission
            .admit()
            .ok_or_else(|| anyhow::anyhow!("DNS upstream pool is closed"))?;
        #[cfg(test)]
        self.pause_after_admission_for_test().await;
        Ok(admission)
    }

    fn prepare_generated_ecs(&self, raw_query: &[u8]) -> Option<EcsQuery> {
        let subnet = self.client_subnet?;
        match EcsQuery::prepare(raw_query, subnet) {
            Ok(injected) => injected,
            Err(error) => {
                debug!(%error, "DNS query is not eligible for configured ECS injection");
                None
            }
        }
    }

    async fn exchange_direct_udp<'a>(
        &'a self,
        entry: &UpstreamEntry,
        route: &DnsDialRoute,
        raw_query: &[u8],
        admission: AdmissionPermit<'a>,
    ) -> anyhow::Result<(Vec<u8>, AdmissionPermit<'a>, Option<EcsQuery>)> {
        let exchange = async {
            let address = route.target;
            let injected = self.prepare_generated_ecs(raw_query);
            let effective_query = injected.as_ref().map_or(raw_query, EcsQuery::wire);
            crate::observe::flows::dns::transport("udp", "udp");
            let response = {
                let query = async {
                    self.udp_pool(entry, address)
                        .await?
                        .exchange(effective_query, None)
                        .await
                };
                crate::observe::scope_pin!(query);
                let query =
                    crate::observe::flows::dns::transport_exchange_scope(effective_query, query);
                query.await?
            };
            entry.udp.lock().mark_current(address);
            Ok((response, admission, injected))
        };
        crate::observe::scope_pin!(exchange);
        let exchange =
            crate::observe::flows::dns::outbound_scope(route.observation.as_ref(), exchange);
        exchange.await
    }

    pub(super) async fn resolve_udp_addrs(
        entry: &UpstreamEntry,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        entry.endpoint.resolve_addrs().await
    }

    #[cfg(test)]
    pub(super) async fn resolve_udp_addr(entry: &UpstreamEntry) -> anyhow::Result<SocketAddr> {
        Self::resolve_udp_addrs(entry)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses"))
    }
    async fn exchange_routed(
        &self,
        entry: &UpstreamEntry,
        route: &DnsDialRoute,
        raw_query: &[u8],
        business: Option<honk_outbound::group::ScoreBusinessGuard>,
    ) -> anyhow::Result<Vec<u8>> {
        match self
            .get_transport(entry, route.node.as_ref(), route.target)
            .await
        {
            Ok(transport) => transport.exchange(raw_query, business).await,
            Err(error) => {
                if let Some(business) = business {
                    business.finish(honk_outbound::group::ScoreOutcome::from_error(&error));
                }
                Err(error)
            }
        }
    }

    async fn query_udp_via_proxy(
        &self,
        upstream_name: &str,
        entry: &UpstreamEntry,
        route: &DnsDialRoute,
        raw_query: &[u8],
        original: &mut Option<honk_outbound::group::ScoreContinuation>,
    ) -> anyhow::Result<Vec<u8>> {
        let exchange = async {
            let node = route
                .node
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("proxied DNS route has no node"))?;
            let _admission = self.admit_query().await?;
            let business = admit_score_attempt(route.feedback.as_ref(), original)?;
            let response = self
                .exchange_routed(entry, route, raw_query, business)
                .await?;
            let response = if crate::dns::response::is_truncated(&response) {
                crate::observe::flows::dns::tcp_fallback();
                let tcp_feedback = self.tcp_feedback_for_route(entry, route)?;
                let business = admit_score_attempt(tcp_feedback.as_ref(), original)?;
                debug!(
                    "DNS upstream '{}' proxied UDP answer has TC set — retrying over proxied TCP",
                    upstream_name
                );
                self.exchange_routed(entry, route, raw_query, business)
                    .await?
            } else {
                response
            };
            debug!(
                "DNS upstream '{}' (udp via proxy {}) returned {} bytes",
                upstream_name,
                node.name,
                response.len()
            );
            Ok(response)
        };
        crate::observe::scope_pin!(exchange);
        let exchange =
            crate::observe::flows::dns::outbound_scope(route.observation.as_ref(), exchange);
        exchange.await
    }

    async fn finish_direct_udp_query(
        &self,
        upstream_name: &str,
        entry: &UpstreamEntry,
        route: &DnsDialRoute,
        raw_query: &[u8],
        exchange: (Vec<u8>, AdmissionPermit<'_>, Option<EcsQuery>),
    ) -> anyhow::Result<Vec<u8>> {
        let (response, _admission, injected) = exchange;
        let effective_query = injected.as_ref().map_or(raw_query, EcsQuery::wire);
        let response = if crate::dns::response::is_truncated(&response) {
            debug!(
                "DNS upstream '{}' UDP answer has TC set — retrying over TCP",
                upstream_name
            );
            let exchange = async {
                crate::observe::flows::dns::tcp_fallback();
                self.get_transport(entry, None, route.target)
                    .await?
                    .exchange(effective_query, None)
                    .await
            };
            crate::observe::scope_pin!(exchange);
            let exchange =
                crate::observe::flows::dns::outbound_scope(route.observation.as_ref(), exchange);
            exchange.await?
        } else {
            debug!(
                "DNS upstream '{}' (udp) returned {} bytes",
                upstream_name,
                response.len()
            );
            response
        };
        match injected {
            Some(injected) => injected
                .restore_response(response)
                .context("invalid ECS response from DNS upstream"),
            None => Ok(response),
        }
    }
    async fn query_datagram(
        &self,
        upstream_name: &str,
        entry: &UpstreamEntry,
        raw_query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut original_business = None;
        let current = { entry.udp.lock().current_address() };
        let has_traffic_router =
            self.traffic_router_snapshot.read().is_some() || self.traffic_router.read().is_some();
        let initial_route = if current.is_none() && entry.outbound.is_none() && has_traffic_router {
            let resolve = honk_outbound::runtime::flow_observation::observe_resolution(
                Self::resolve_udp_addrs(entry),
            );
            crate::observe::scope_pin!(resolve);
            let (targets, witness) =
                crate::observe::flows::dns::scope_purpose("proxy_server", resolve).await;
            let target = targets?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses"))?;
            if let Some(witness) = witness {
                witness.selected_ip(target.ip());
            }
            Some(
                self.resolve_dial_route_for_address(entry, target, original_business.as_ref())
                    .await?,
            )
        } else {
            None
        };
        let failed = if let Some(address) = current {
            let route = self
                .resolve_dial_route_for_address(entry, address, original_business.as_ref())
                .await?;
            if route.node.is_some() {
                match self
                    .query_udp_via_proxy(
                        upstream_name,
                        entry,
                        &route,
                        raw_query,
                        &mut original_business,
                    )
                    .await
                {
                    Ok(response) => return Ok(response),
                    Err(error) => Some((address, retryable_error(error)?)),
                }
            } else {
                let admission = self.admit_query().await?;
                match self
                    .exchange_direct_udp(entry, &route, raw_query, admission)
                    .await
                {
                    Ok(exchange) => {
                        return self
                            .finish_direct_udp_query(
                                upstream_name,
                                entry,
                                &route,
                                raw_query,
                                exchange,
                            )
                            .await;
                    }
                    Err(error) => Some((address, retryable_error(error)?)),
                }
            }
        } else {
            None
        };

        let resolve = honk_outbound::runtime::flow_observation::observe_resolution(
            Self::resolve_udp_addrs(entry),
        );
        crate::observe::scope_pin!(resolve);
        let (addresses, witness) =
            crate::observe::flows::dns::scope_purpose("proxy_server", resolve).await;
        let addresses = addresses?;
        let (first, first_error, retry) = if let Some((failed_address, first_error)) = failed {
            let [first, retry] = udp_attempt_addresses(&addresses, Some(failed_address))
                .ok_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses"))?;
            let retry = if first == failed_address {
                retry
            } else {
                first
            };
            (failed_address, first_error, retry)
        } else {
            let [first, retry] = udp_attempt_addresses(&addresses, None)
                .ok_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses"))?;
            if let Some(witness) = &witness {
                witness.selected_ip(first.ip());
            }
            let route = match initial_route {
                Some(route) if route.target == first => route,
                _ => {
                    self.resolve_dial_route_for_address(entry, first, original_business.as_ref())
                        .await?
                }
            };
            if route.node.is_some() {
                match self
                    .query_udp_via_proxy(
                        upstream_name,
                        entry,
                        &route,
                        raw_query,
                        &mut original_business,
                    )
                    .await
                {
                    Ok(response) => return Ok(response),
                    Err(first_error) => (first, retryable_error(first_error)?, retry),
                }
            } else {
                let attempt = async {
                    let admission = self.admit_query().await?;
                    self.exchange_direct_udp(entry, &route, raw_query, admission)
                        .await
                }
                .await;
                match attempt {
                    Ok(exchange) => {
                        return self
                            .finish_direct_udp_query(
                                upstream_name,
                                entry,
                                &route,
                                raw_query,
                                exchange,
                            )
                            .await;
                    }
                    Err(first_error) => (first, retryable_error(first_error)?, retry),
                }
            }
        };

        debug!(
            address = %first,
            retry_address = %retry,
            error_kind = "exchange_failed",
            "UDP DNS query candidate failed; retrying"
        );
        if let Some(witness) = &witness {
            witness.selected_ip(retry.ip());
        }
        let route = self
            .resolve_dial_route_for_address(entry, retry, original_business.as_ref())
            .await?;
        if route.node.is_some() {
            return self
                .query_udp_via_proxy(
                    upstream_name,
                    entry,
                    &route,
                    raw_query,
                    &mut original_business,
                )
                .await
                .with_context(|| {
                    format!("UDP DNS failed via {retry} (first {first}: {first_error})")
                });
        }
        let attempt = async {
            let admission = self.admit_query().await?;
            self.exchange_direct_udp(entry, &route, raw_query, admission)
                .await
        }
        .await;
        match attempt {
            Ok(exchange) => {
                self.finish_direct_udp_query(upstream_name, entry, &route, raw_query, exchange)
                    .await
            }
            Err(error) => Err(error).with_context(|| {
                format!("UDP DNS failed via {retry} (first {first}: {first_error})")
            }),
        }
    }
}

impl UpstreamPool {
    async fn query_inner(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        debug!(
            "UpstreamPool::query called for '{}' ({} bytes)",
            upstream_name,
            raw_query.len()
        );
        let entry = self
            .entries
            .get(upstream_name)
            .ok_or_else(|| anyhow::anyhow!("unknown upstream: {upstream_name}"))?;
        if entry.protocol == DnsProtocol::Udp {
            return self.query_datagram(upstream_name, entry, raw_query).await;
        }

        let resolve = honk_outbound::runtime::flow_observation::observe_resolution(
            entry.endpoint.resolve_addrs(),
        );
        crate::observe::scope_pin!(resolve);
        let (targets, witness) =
            crate::observe::flows::dns::scope_purpose("proxy_server", resolve).await;
        let targets = targets?;
        let mut last_error = None;
        let mut first_error = None;
        let mut original_business = None;
        for target in targets {
            let route = self
                .resolve_dial_route_for_address(entry, target, original_business.as_ref())
                .await?;
            let _admission = self.admit_query().await?;
            let business = admit_score_attempt(route.feedback.as_ref(), &mut original_business)?;
            if let Some(witness) = &witness {
                witness.selected_ip(route.target.ip());
            }
            debug!(
                "DNS upstream '{}' dial leaf={:?} (forced={})",
                upstream_name,
                route.node.as_ref().map(|node| node.name.as_str()),
                entry.outbound.is_some()
            );
            let injected = if route.node.is_none() {
                self.prepare_generated_ecs(raw_query)
            } else {
                None
            };
            let effective_query = injected.as_ref().map_or(raw_query, EcsQuery::wire);
            let response = {
                let exchange = self.exchange_routed(entry, &route, effective_query, business);
                crate::observe::scope_pin!(exchange);
                let exchange = crate::observe::flows::dns::outbound_scope(
                    route.observation.as_ref(),
                    exchange,
                );
                exchange.await
            };
            match response {
                Ok(response) => {
                    debug!(
                        "DNS upstream '{}' ({:?} {} via {:?}) returned {} bytes",
                        upstream_name,
                        entry.protocol,
                        entry.endpoint.host,
                        route
                            .node
                            .as_ref()
                            .map(|node| node.name.as_str())
                            .unwrap_or("direct"),
                        response.len()
                    );
                    return match injected {
                        Some(injected) => injected
                            .restore_response(response)
                            .context("invalid ECS response from DNS upstream"),
                        None => Ok(response),
                    };
                }
                Err(error) => {
                    let error = retryable_error(error)?;
                    debug!(
                        target: "honk_core::dns::upstream_pool::failure",
                        upstream = upstream_name,
                        protocol = ?entry.protocol,
                        server = %route.target,
                        leaf = ?route.node.as_ref().map(|node| node.name.as_str()),
                        error = %error,
                        "DNS upstream route failed"
                    );
                    first_error.get_or_insert_with(|| (route.target, error.to_string()));
                    last_error = Some((route.target, error));
                }
            }
        }
        let (target, error) =
            last_error.ok_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses"))?;
        let context = match first_error.filter(|(first, _)| *first != target) {
            Some((first, first_error)) => format!(
                "DNS upstream '{upstream_name}' failed via {target} (first {first}: {first_error})"
            ),
            None => format!("DNS upstream '{upstream_name}' failed via {target}"),
        };
        Err(error).context(context)
    }
}

#[async_trait::async_trait]
impl DnsUpstreamPool for UpstreamPool {
    async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let query = self.query_inner(upstream_name, raw_query);
        crate::observe::scope_pin!(query);
        let query = crate::observe::flows::dns::exchange_scope(raw_query, upstream_name, query);
        query.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_retry_uses_other_family_before_same_family() {
        let ipv6_first = [
            "[2001:db8::1]:53".parse().unwrap(),
            "[2001:db8::2]:53".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
        ];

        assert_eq!(
            udp_attempt_addresses(&ipv6_first, None).unwrap(),
            [ipv6_first[0], ipv6_first[2]]
        );
        assert_eq!(
            udp_attempt_addresses(&ipv6_first, Some(ipv6_first[2])).unwrap(),
            [ipv6_first[2], ipv6_first[0]]
        );
    }
}
