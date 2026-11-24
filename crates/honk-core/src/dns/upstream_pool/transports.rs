use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use honk_config::types::DnsProtocol;
use honk_outbound::group::{DialKey, ExitCollapse, OwnedTarget, ScoreBusinessGuard};

use super::UpstreamPool;
use super::entries::UpstreamEntry;
use crate::dns::transport::{
    DialContext, Doh3Client, DohClient, DoqClient, DotPool, LifecycleSlot, ProxyDial,
    RouteExchange, TcpPool,
};

impl super::DnsIdleResources {
    pub(crate) fn reclaim_idle(&self) {
        self.reap_idle(true);
    }

    pub(super) fn reap_idle(&self, pressure: bool) -> usize {
        let registered = self.registered.lock();
        if !*registered {
            return 0;
        }
        let Some(_admission) = self.admission.admit() else {
            return 0;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return 0;
        };
        let udp_pools = if pressure {
            self.take_idle_udp_pools()
        } else {
            Vec::new()
        };
        let is_empty: Option<fn(&PooledTransport) -> bool> = if pressure {
            None
        } else {
            Some(PooledTransport::is_empty)
        };
        let mut retiring = self.retiring_transports.lock();
        retiring.udp_pools.extend(udp_pools);
        let mut reclaimed = 0;
        for entry in self.entries.values() {
            let mut transports = entry.transports.lock();
            reclaimed += transports.prune_closed();
            for slot in transports.slots.values() {
                if !pressure && Arc::strong_count(slot) != 1 {
                    continue;
                }
                let failed = Arc::clone(&self.transport_tasks_failed);
                if let Some(teardown) = slot.retire_idle(is_empty, move |transport| async move {
                    transport.close(&failed).await;
                }) {
                    retiring.teardowns.spawn_on(teardown, &runtime);
                }
            }
        }
        retiring.drain(Some(runtime), false, &self.transport_tasks_failed);
        reclaimed
    }

    fn take_idle_udp_pools(&self) -> Vec<Arc<crate::dns::transport::UdpPool>> {
        let now = std::time::Instant::now();
        let mut udp_pools = Vec::new();
        for entry in self.entries.values() {
            let mut state = entry.udp.lock();
            let current = state.current;
            let mut clear_current = false;
            for family in state.pools.iter_mut().flatten() {
                for shard in &mut family.shards {
                    if shard.as_ref().is_some_and(|pool| {
                        Arc::strong_count(pool) == 1 && pool.is_idle(now, std::time::Duration::ZERO)
                    }) {
                        udp_pools.extend(shard.take());
                        crate::stats::record_dns_event(
                            crate::stats::DnsStatEvent::PressureRetiredUdpPool,
                        );
                    }
                }
                clear_current |=
                    current == Some(family.address) && family.shards.iter().all(Option::is_none);
            }
            if clear_current {
                state.current = None;
            }
        }
        udp_pools
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct TransportKey {
    /// A node dialed as itself and as a route's leaf reach the upstream over
    /// different paths.
    dialed: Option<DialKey>,
    /// Collapsed routes use their exit's node key, with route-local session handling.
    collapse: ExitCollapse,
    target: std::net::SocketAddr,
}

#[derive(Default)]
pub(super) struct TransportSlots {
    pub(super) slots: HashMap<TransportKey, Arc<LifecycleSlot<PooledTransport>>>,
    removed_init_count: usize,
    removed_close_count: usize,
}

impl TransportSlots {
    fn prune_closed(&mut self) -> usize {
        let before = self.slots.len();
        self.slots.retain(|_, slot| {
            // A lookup or retirement task can own a closed slot and build into
            // it again. Only the map's sole reference can be unlinked.
            if Arc::strong_count(slot) != 1 || !slot.is_closed() {
                return true;
            }
            self.removed_init_count += slot.init_count();
            self.removed_close_count += slot.close_count();
            false
        });
        let removed = before - self.slots.len();
        if removed != 0 && self.slots.len() <= self.slots.capacity() / 4 {
            self.slots.shrink_to_fit();
        }
        removed
    }

    fn lifecycle_counts(&self) -> (usize, usize) {
        self.slots.values().fold(
            (self.removed_init_count, self.removed_close_count),
            |(init, close), slot| (init + slot.init_count(), close + slot.close_count()),
        )
    }
}

pub(super) enum PooledTransport {
    Tcp(Arc<TcpPool>),
    Dot(Arc<DotPool>),
    Doh(Arc<DohClient>),
    Doq(Arc<DoqClient>),
    Doh3(Arc<Doh3Client>),
}

impl PooledTransport {
    fn is_empty(&self) -> bool {
        match self {
            Self::Tcp(transport) => transport.is_empty(),
            Self::Dot(transport) => transport.is_empty(),
            Self::Doh(transport) => transport.is_empty(),
            Self::Doq(transport) => transport.is_empty(),
            Self::Doh3(transport) => transport.is_empty(),
        }
    }

    async fn close(&self, failed: &AtomicBool) {
        let tasks_failed = match self {
            Self::Tcp(transport) => {
                transport.close().await;
                false
            }
            Self::Dot(transport) => {
                transport.close().await;
                false
            }
            Self::Doh(transport) => {
                transport.close().await;
                false
            }
            Self::Doq(transport) => {
                transport.close().await;
                transport.tasks_failed()
            }
            Self::Doh3(transport) => {
                transport.close().await;
                transport.tasks_failed()
            }
        };
        if tasks_failed {
            failed.store(true, Ordering::Release);
        }
    }

    pub(super) async fn exchange(
        &self,
        raw_query: &[u8],
        feedback: Option<ScoreBusinessGuard>,
        route: Option<RouteExchange<'_>>,
    ) -> anyhow::Result<Vec<u8>> {
        let (upstream, carrier) = match self {
            Self::Tcp(_) => ("tcp", "tcp"),
            Self::Dot(_) => ("dot", "tcp"),
            Self::Doh(_) => ("doh", "tcp"),
            Self::Doq(_) => ("doq", "udp"),
            Self::Doh3(_) => ("doh3", "udp"),
        };
        crate::observe::flows::dns::transport(upstream, carrier);
        match self {
            Self::Tcp(transport) => transport.exchange_routed(raw_query, feedback, route).await,
            Self::Dot(transport) => transport.exchange_routed(raw_query, feedback, route).await,
            Self::Doh(transport) => transport.exchange_routed(raw_query, feedback, route).await,
            Self::Doq(transport) => transport.exchange_routed(raw_query, feedback, route).await,
            Self::Doh3(transport) => transport.exchange_routed(raw_query, feedback, route).await,
        }
    }
}

impl UpstreamPool {
    pub(super) fn dial_context(
        &self,
        entry: &UpstreamEntry,
        proxy_node: Option<&OwnedTarget>,
        target: std::net::SocketAddr,
    ) -> anyhow::Result<DialContext> {
        let proxy = match (proxy_node, self.proxy_registry.as_ref()) {
            (Some(_), None) => {
                return Err(anyhow::anyhow!(
                    "DNS proxy node selected without a proxy registry"
                ));
            }
            (Some(target), Some(registry)) => Some(ProxyDial {
                registry: Arc::clone(registry),
                generation: self.runtime_generation.get().cloned(),
                node: target.node.clone(),
                route: target.route().copied(),
            }),
            _ => None,
        };
        Ok(DialContext {
            endpoint: entry.endpoint.clone().with_resolved_addr(target),
            query_timeout: self.dns_query_timeout,
            dial_timeout: self.dns_dial_timeout,
            socket_budget: self.socket_budget.clone(),
            proxy,
        })
    }

    async fn build_transport(
        &self,
        entry: &UpstreamEntry,
        proxy_node: Option<&OwnedTarget>,
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
        proxy_node: Option<&OwnedTarget>,
        target: std::net::SocketAddr,
    ) -> anyhow::Result<Arc<PooledTransport>> {
        let key = TransportKey {
            dialed: proxy_node.map(OwnedTarget::key),
            collapse: proxy_node.map_or(ExitCollapse::None, |target| target.collapse),
            target,
        };
        let slot = {
            let mut transports = entry.transports.lock();
            Arc::clone(
                transports
                    .slots
                    .entry(key)
                    .or_insert_with(|| Arc::new(LifecycleSlot::new())),
            )
        };
        slot.acquire(|| self.build_transport(entry, proxy_node, target))
            .await
            .map(|(value, _)| value)
    }

    pub fn lifecycle_stats(&self) -> super::TransportLifecycleStats {
        let (init_count, close_count) = self
            .entries
            .values()
            .map(|entry| entry.transports.lock().lifecycle_counts())
            .fold((0, 0), |(init, close), (slot_init, slot_close)| {
                (init + slot_init, close + slot_close)
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
        let mut udp_pools = Vec::new();
        for entry in self.entries.values() {
            let mut state = entry.udp.lock();
            state.current = None;
            udp_pools.extend(
                state
                    .pools
                    .iter_mut()
                    .filter_map(Option::take)
                    .flat_map(|family| family.shards.into_iter().flatten()),
            );
        }
        self.retiring_transports.lock().udp_pools.extend(udp_pools);
        self.drain_retired_transports(true);
        self.join_retired_transports().await;
        for entry in self.entries.values() {
            let slots = entry
                .transports
                .lock()
                .slots
                .values()
                .cloned()
                .collect::<Vec<_>>();
            for slot in slots {
                let failed = Arc::clone(&self.transport_tasks_failed);
                slot.close(move |transport| async move {
                    transport.close(&failed).await;
                })
                .await;
            }
            entry.transports.lock().prune_closed();
        }
        if let Some(generation) = self.runtime_generation.get() {
            generation.shutdown().await;
        }
        close.complete();
    }
}
