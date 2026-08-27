use std::sync::Arc;
use std::sync::atomic::Ordering;

use honk_config::node::Node;
use honk_config::types::DnsProtocol;
use honk_outbound::group::ScoreFeedback;

use super::UpstreamPool;
use super::entries::UpstreamEntry;
use crate::dns::transport::{
    DialContext, Doh3Client, DohClient, DoqClient, DotPool, LifecycleSlot, ProxyDial, TcpPool,
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct TransportKey {
    resolved_leaf: Option<String>,
    target: std::net::SocketAddr,
}

pub(super) enum PooledTransport {
    Tcp(Arc<TcpPool>),
    Dot(Arc<DotPool>),
    Doh(Arc<DohClient>),
    Doq(Arc<DoqClient>),
    Doh3(Arc<Doh3Client>),
}

impl PooledTransport {
    async fn close(&self) {
        match self {
            Self::Tcp(transport) => transport.close().await,
            Self::Dot(transport) => transport.close().await,
            Self::Doh(transport) => transport.close().await,
            Self::Doq(transport) => transport.close().await,
            Self::Doh3(transport) => transport.close().await,
        }
    }

    pub(super) async fn exchange(
        &self,
        raw_query: &[u8],
        feedback: Option<&ScoreFeedback>,
    ) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Tcp(transport) => transport.exchange(raw_query, feedback).await,
            Self::Dot(transport) => transport.exchange(raw_query, feedback).await,
            Self::Doh(transport) => transport.exchange(raw_query, feedback).await,
            Self::Doq(transport) => transport.exchange(raw_query, feedback).await,
            Self::Doh3(transport) => transport.exchange(raw_query, feedback).await,
        }
    }
}

impl UpstreamPool {
    pub(super) fn dial_context(
        &self,
        entry: &UpstreamEntry,
        proxy_node: Option<&Node>,
        target: std::net::SocketAddr,
    ) -> anyhow::Result<DialContext> {
        let proxy = match (proxy_node, self.proxy_registry.as_ref()) {
            (Some(_), None) => {
                return Err(anyhow::anyhow!(
                    "DNS proxy node selected without a proxy registry"
                ));
            }
            (Some(node), Some(registry)) => Some(ProxyDial {
                registry: Arc::clone(registry),
                generation: self.runtime_generation.get().cloned(),
                node: node.clone(),
            }),
            _ => None,
        };
        Ok(DialContext {
            endpoint: entry.endpoint.clone().with_resolved_addr(target),
            query_timeout: self.dns_query_timeout,
            dial_timeout: self.dns_dial_timeout,
            proxy,
        })
    }

    async fn build_transport(
        &self,
        entry: &UpstreamEntry,
        proxy_node: Option<&Node>,
        target: std::net::SocketAddr,
    ) -> anyhow::Result<PooledTransport> {
        let dial = self.dial_context(entry, proxy_node, target)?;
        Ok(match entry.protocol {
            DnsProtocol::Udp | DnsProtocol::Tcp => PooledTransport::Tcp(TcpPool::new(dial)),
            DnsProtocol::Tls => PooledTransport::Dot(DotPool::new(dial)?),
            DnsProtocol::Https => PooledTransport::Doh(DohClient::new_tracked(
                dial,
                Arc::clone(&self.active_transport_tasks),
            )?),
            DnsProtocol::Quic => PooledTransport::Doq(DoqClient::new(dial).await?),
            DnsProtocol::H3 => PooledTransport::Doh3(
                Doh3Client::new_tracked(dial, Arc::clone(&self.active_transport_tasks)).await?,
            ),
        })
    }

    pub(super) async fn get_transport(
        &self,
        entry: &UpstreamEntry,
        proxy_node: Option<&Node>,
        target: std::net::SocketAddr,
    ) -> anyhow::Result<Arc<PooledTransport>> {
        let key = TransportKey {
            resolved_leaf: proxy_node.map(|node| node.name.clone()),
            target,
        };
        let slot = {
            let mut transports = entry.transports.lock();
            Arc::clone(
                transports
                    .entry(key)
                    .or_insert_with(|| Arc::new(LifecycleSlot::new())),
            )
        };
        slot.acquire(|| self.build_transport(entry, proxy_node, target))
            .await
    }

    pub fn lifecycle_stats(&self) -> super::TransportLifecycleStats {
        let (init_count, close_count) = self
            .entries
            .values()
            .flat_map(|entry| {
                entry
                    .transports
                    .lock()
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .fold((0, 0), |(initializations, closes), slot| {
                (
                    initializations + slot.init_count(),
                    closes + slot.close_count(),
                )
            });
        super::TransportLifecycleStats {
            init_count,
            close_count,
            tasks: self.active_transport_tasks.load(Ordering::SeqCst),
        }
    }

    pub async fn close(&self) {
        let Some(close) = self.admission.acquire_close().await else {
            return;
        };
        self.admission.wait_for_idle().await;
        let slots = self
            .entries
            .values()
            .flat_map(|entry| {
                entry
                    .transports
                    .lock()
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut udp_pools = Vec::new();
        for entry in self.entries.values() {
            let mut state = entry.udp.lock();
            state.current = None;
            udp_pools.extend(
                state
                    .pools
                    .iter_mut()
                    .filter_map(Option::take)
                    .map(|(_, pool)| pool),
            );
        }
        for pool in udp_pools {
            pool.close().await;
        }
        for slot in slots {
            slot.close(|transport| async move {
                transport.close().await;
            })
            .await;
        }
        close.complete();
    }
}
