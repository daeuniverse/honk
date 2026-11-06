//! Per-upstream DNS query management with connection reuse.

mod admission {
    use parking_lot::Mutex;
    use tokio::sync::Notify;

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum PoolState {
        Open,
        Closing,
        Closed,
    }

    struct AdmissionState {
        phase: PoolState,
        in_flight: usize,
        close_owner: bool,
    }

    pub(super) struct AdmissionGate {
        state: Mutex<AdmissionState>,
        changed: Notify,
    }

    pub(super) struct AdmissionPermit<'a> {
        gate: &'a AdmissionGate,
    }

    pub(super) struct ClosePermit<'a> {
        gate: &'a AdmissionGate,
        armed: bool,
    }

    impl AdmissionGate {
        pub(super) fn new() -> Self {
            Self {
                state: Mutex::new(AdmissionState {
                    phase: PoolState::Open,
                    in_flight: 0,
                    close_owner: false,
                }),
                changed: Notify::new(),
            }
        }

        pub(super) fn admit(&self) -> Option<AdmissionPermit<'_>> {
            let mut state = self.state.lock();
            if state.phase != PoolState::Open {
                return None;
            }
            state.in_flight = state.in_flight.checked_add(1)?;
            Some(AdmissionPermit { gate: self })
        }

        pub(super) async fn acquire_close(&self) -> Option<ClosePermit<'_>> {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let mut state = self.state.lock();
                    match state.phase {
                        PoolState::Open => {
                            state.phase = PoolState::Closing;
                            state.close_owner = true;
                            return Some(ClosePermit::new(self));
                        }
                        PoolState::Closing if !state.close_owner => {
                            state.close_owner = true;
                            return Some(ClosePermit::new(self));
                        }
                        PoolState::Closing => {}
                        PoolState::Closed => return None,
                    };
                }
                changed.await;
            }
        }

        pub(super) async fn wait_for_idle(&self) {
            self.wait_until(|state| state.in_flight == 0).await;
        }

        async fn wait_until(&self, condition: impl Fn(&AdmissionState) -> bool) {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let ready = {
                    let state = self.state.lock();
                    condition(&state)
                };
                if ready {
                    return;
                }
                changed.await;
            }
        }
    }

    impl<'a> ClosePermit<'a> {
        fn new(gate: &'a AdmissionGate) -> Self {
            Self { gate, armed: true }
        }

        pub(super) fn complete(mut self) {
            {
                let mut state = self.gate.state.lock();
                state.phase = PoolState::Closed;
                state.close_owner = false;
            }
            self.armed = false;
            self.gate.changed.notify_waiters();
        }
    }

    impl Drop for ClosePermit<'_> {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            {
                let mut state = self.gate.state.lock();
                state.close_owner = false;
            }
            self.gate.changed.notify_waiters();
        }
    }

    impl Drop for AdmissionPermit<'_> {
        fn drop(&mut self) {
            let became_idle = {
                let mut state = self.gate.state.lock();
                let Some(remaining) = state.in_flight.checked_sub(1) else {
                    return;
                };
                state.in_flight = remaining;
                remaining == 0
            };
            if became_idle {
                self.gate.changed.notify_waiters();
            }
        }
    }
}
mod entries {
    use super::MAX_UDP_SHARDS;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use honk_config::dns::{DnsStrategy, DnsUpstream};

    use super::transports::{PooledTransport, TransportKey};
    use crate::dns::endpoint::DnsEndpoint;
    use crate::dns::transport::{LifecycleSlot, UdpPool};

    pub(super) struct UdpFamily {
        pub(super) address: SocketAddr,
        pub(super) shards: [Option<Arc<UdpPool>>; MAX_UDP_SHARDS],
    }

    #[derive(Default)]
    pub(super) struct UdpState {
        pub(super) current: Option<SocketAddr>,
        pub(super) pools: [Option<UdpFamily>; 2],
    }

    impl UdpState {
        pub(super) fn current_address(&self) -> Option<SocketAddr> {
            let current = self.current?;
            let family = usize::from(current.is_ipv6());
            self.pools[family]
                .as_ref()
                .filter(|pools| {
                    pools.address == current && pools.shards.iter().any(Option::is_some)
                })
                .map(|_| current)
        }

        pub(super) fn mark_current(&mut self, address: SocketAddr) {
            let family = usize::from(address.is_ipv6());
            if self.pools[family].as_ref().is_some_and(|pools| {
                pools.address == address && pools.shards.iter().any(Option::is_some)
            }) {
                self.current = Some(address);
            }
        }
    }

    pub(super) struct UpstreamEntry {
        pub(super) protocol: honk_config::types::DnsProtocol,
        pub(super) endpoint: DnsEndpoint,
        pub(super) outbound: Option<String>,
        pub(super) transports:
            parking_lot::Mutex<HashMap<TransportKey, Arc<LifecycleSlot<PooledTransport>>>>,
        pub(super) udp: parking_lot::Mutex<UdpState>,
        pub(super) udp_creation: [tokio::sync::Mutex<()>; 2],
    }

    pub(super) fn build_entries(
        upstreams: &[DnsUpstream],
        bootstrap_resolver: Option<honk_outbound::bootstrap::BootstrapResolver>,
        strategy: DnsStrategy,
    ) -> anyhow::Result<HashMap<String, UpstreamEntry>> {
        let mut entries = HashMap::new();
        for upstream in upstreams {
            let endpoint = DnsEndpoint::parse_with_resolver(
                &upstream.address,
                upstream.protocol,
                upstream.tls_server_name.as_deref(),
                bootstrap_resolver,
                strategy,
            )
            .map_err(|error| {
                anyhow::anyhow!(
                    "invalid upstream '{}' address '{}': {error}",
                    upstream.name,
                    upstream.address
                )
            })?;
            entries.insert(
                upstream.name.clone(),
                UpstreamEntry {
                    protocol: upstream.protocol,
                    endpoint,
                    outbound: upstream.outbound.clone(),
                    transports: parking_lot::Mutex::new(HashMap::new()),
                    udp: parking_lot::Mutex::new(UdpState::default()),
                    udp_creation: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
                },
            );
        }
        Ok(entries)
    }
}
mod query;
mod routing;
mod transports;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use honk_config::dns::{DnsStrategy, DnsUpstream};
use honk_config::node::{Group, Node};
use honk_outbound::group::{GroupManager, SharedGroupManager};
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::RwLock as AsyncRwLock;

use self::admission::AdmissionGate;
use self::entries::{UpstreamEntry, build_entries};
use crate::dns::routing::DnsRouter;
use crate::proxy::ProxyRegistry;
use crate::routing::Router;

const MAX_UDP_SHARDS: usize = 4;
const UDP_SHARD_EXPANSION_PENDING: usize = 768;
const UDP_SHARD_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportLifecycleStats {
    pub init_count: usize,
    pub close_count: usize,
    pub tasks: usize,
}

#[derive(Default)]
struct RetiredTransports {
    udp_pools: Vec<Arc<crate::dns::transport::UdpPool>>,
    teardowns: tokio::task::JoinSet<()>,
}

impl RetiredTransports {
    fn drain(
        &mut self,
        runtime: Option<tokio::runtime::Handle>,
        force: bool,
        failed: &std::sync::atomic::AtomicBool,
    ) {
        while let Some(result) = self.teardowns.try_join_next() {
            if result.is_err() {
                failed.store(true, std::sync::atomic::Ordering::Release);
            }
        }
        let Some(runtime) = runtime else {
            return;
        };
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.udp_pools)
            .into_iter()
            .partition(|pool| force || pool.is_stopped() || Arc::strong_count(pool) == 1);
        self.udp_pools = waiting;
        for pool in ready {
            self.teardowns
                .spawn_on(async move { pool.close().await }, &runtime);
        }
    }
}

pub(crate) struct DnsIdleResources {
    registered: parking_lot::Mutex<bool>,
    entries: Arc<HashMap<String, UpstreamEntry>>,
    retiring_transports: Arc<parking_lot::Mutex<RetiredTransports>>,
    admission: Arc<AdmissionGate>,
    transport_tasks_failed: Arc<std::sync::atomic::AtomicBool>,
}

pub struct UpstreamPool {
    entries: Arc<HashMap<String, UpstreamEntry>>,
    proxy_registry: Option<Arc<ProxyRegistry>>,
    client_subnet: Option<ipnet::Ipv4Net>,
    /// DNS-only session runtime fork; never the ordinary control-plane registry.
    runtime_generation: std::sync::OnceLock<Arc<honk_outbound::runtime::OutboundRuntimeRegistry>>,
    nodes: Vec<Node>,
    groups: Vec<Group>,
    group_manager: parking_lot::RwLock<Option<SharedGroupManager>>,
    group_manager_snapshot: parking_lot::RwLock<Option<Arc<GroupManager>>>,
    traffic_router: parking_lot::RwLock<Option<Arc<AsyncRwLock<Router>>>>,
    traffic_router_snapshot: parking_lot::RwLock<Option<Arc<Router>>>,
    dns_query_timeout: Duration,
    dns_dial_timeout: Duration,
    socket_budget: crate::dns::transport::DnsSocketBudget,
    retiring_transports: Arc<parking_lot::Mutex<RetiredTransports>>,
    active_transport_tasks: Arc<AtomicUsize>,
    transport_tasks_failed: Arc<std::sync::atomic::AtomicBool>,
    admission: Arc<AdmissionGate>,
    idle_resources: Arc<DnsIdleResources>,
    #[cfg(test)]
    admission_pause: parking_lot::Mutex<Option<AdmissionPause>>,
}

#[cfg(test)]
#[derive(Clone)]
struct AdmissionPause {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

impl UpstreamPool {
    pub fn new(upstreams: &[DnsUpstream], router: Arc<DnsRouter>) -> anyhow::Result<Self> {
        Self::new_with_proxy(upstreams, router, None, Vec::new(), Vec::new())
    }

    pub fn new_with_proxy(
        upstreams: &[DnsUpstream],
        router: Arc<DnsRouter>,
        proxy_registry: Option<Arc<ProxyRegistry>>,
        nodes: Vec<Node>,
        groups: Vec<Group>,
    ) -> anyhow::Result<Self> {
        Self::new_with_proxy_and_bootstrap(
            upstreams,
            router,
            proxy_registry,
            nodes,
            groups,
            honk_outbound::bootstrap::global(),
            DnsStrategy::default(),
        )
    }

    pub(crate) fn new_with_proxy_and_bootstrap(
        upstreams: &[DnsUpstream],
        _router: Arc<DnsRouter>,
        proxy_registry: Option<Arc<ProxyRegistry>>,
        nodes: Vec<Node>,
        groups: Vec<Group>,
        bootstrap_resolver: Option<honk_outbound::bootstrap::BootstrapResolver>,
        strategy: DnsStrategy,
    ) -> anyhow::Result<Self> {
        let entries = Arc::new(build_entries(upstreams, bootstrap_resolver, strategy)?);
        let retiring_transports = Arc::new(parking_lot::Mutex::default());
        let admission = Arc::new(AdmissionGate::new());
        let transport_tasks_failed = Arc::default();
        let idle_resources = Arc::new(DnsIdleResources {
            registered: parking_lot::Mutex::new(true),
            entries: Arc::clone(&entries),
            retiring_transports: Arc::clone(&retiring_transports),
            admission: Arc::clone(&admission),
            transport_tasks_failed: Arc::clone(&transport_tasks_failed),
        });
        let pool = Self {
            entries,
            proxy_registry,
            client_subnet: None,
            runtime_generation: std::sync::OnceLock::new(),
            nodes,
            groups,
            group_manager: parking_lot::RwLock::new(None),
            group_manager_snapshot: parking_lot::RwLock::new(None),
            traffic_router: parking_lot::RwLock::new(None),
            traffic_router_snapshot: parking_lot::RwLock::new(None),
            dns_query_timeout: Duration::from_secs(3),
            dns_dial_timeout: Duration::from_secs(10),
            socket_budget: crate::dns::transport::DnsSocketBudget::default(),
            retiring_transports,
            active_transport_tasks: Arc::new(AtomicUsize::new(0)),
            transport_tasks_failed,
            admission,
            idle_resources,
            #[cfg(test)]
            admission_pause: parking_lot::Mutex::new(None),
        };
        pool.socket_budget.register_idle_owner(&pool.idle_resources);
        Ok(pool)
    }

    pub fn with_socket_budget(mut self, budget: crate::dns::transport::DnsSocketBudget) -> Self {
        *self.idle_resources.registered.lock() = false;
        self.socket_budget
            .unregister_idle_owner(&self.idle_resources);
        self.socket_budget = budget;
        self.idle_resources = Arc::new(DnsIdleResources {
            registered: parking_lot::Mutex::new(true),
            entries: Arc::clone(&self.entries),
            retiring_transports: Arc::clone(&self.retiring_transports),
            admission: Arc::clone(&self.admission),
            transport_tasks_failed: Arc::clone(&self.transport_tasks_failed),
        });
        self.socket_budget.register_idle_owner(&self.idle_resources);
        self
    }

    pub(crate) fn socket_budget(&self) -> &crate::dns::transport::DnsSocketBudget {
        &self.socket_budget
    }

    pub fn with_timeouts(
        mut self,
        dns_query_timeout: Duration,
        dns_dial_timeout: Duration,
    ) -> Self {
        self.dns_query_timeout = dns_query_timeout;
        self.dns_dial_timeout = dns_dial_timeout;
        self
    }

    pub fn with_client_subnet(mut self, client_subnet: Option<ipnet::Ipv4Net>) -> Self {
        self.client_subnet = client_subnet;
        self
    }

    pub fn set_runtime_generation(
        &self,
        generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    ) -> anyhow::Result<()> {
        let dns_generation = Arc::new(generation.fork_for_dns()?);
        self.runtime_generation
            .set(dns_generation)
            .map_err(|_| anyhow::anyhow!("DNS upstream runtime generation is already set"))
    }

    fn reap_udp_shards(&self, now: std::time::Instant) -> usize {
        // Holding admission fences `close`, which waits for idle before its final join.
        let Some(_admission) = self.admission.admit() else {
            return 0;
        };
        let mut retired = Vec::new();
        for entry in self.entries.values() {
            let mut state = entry.udp.lock();
            for family in state.pools.iter_mut().flatten() {
                for shard in &mut family.shards[1..] {
                    if shard.as_ref().is_some_and(|pool| {
                        pool.is_stopped()
                            || (Arc::strong_count(pool) == 1
                                && pool.is_idle(now, UDP_SHARD_IDLE_TIMEOUT))
                    }) {
                        retired.extend(shard.take());
                    }
                }
            }
        }
        let reclaimed = retired.len();
        self.retire_udp_pools(retired);
        reclaimed
    }

    /// Retired pools stay owned here until their receive task has exited; each still
    /// holds a socket credit, so this list is bounded by the DNS socket budget.
    pub(super) fn retire_udp_pools(&self, pools: Vec<Arc<crate::dns::transport::UdpPool>>) {
        self.retiring_transports.lock().udp_pools.extend(pools);
        self.drain_retired_transports(false);
    }

    pub(super) fn drain_retired_transports(&self, force: bool) {
        let mut retired = self.retiring_transports.lock();
        if retired.udp_pools.is_empty() && retired.teardowns.is_empty() {
            return;
        }
        retired.drain(
            tokio::runtime::Handle::try_current().ok(),
            force,
            &self.transport_tasks_failed,
        );
    }

    pub(super) async fn join_retired_transports(&self) {
        while let Some(result) =
            std::future::poll_fn(|cx| self.retiring_transports.lock().teardowns.poll_join_next(cx))
                .await
        {
            if result.is_err() {
                self.transport_tasks_failed
                    .store(true, std::sync::atomic::Ordering::Release);
            }
        }
    }

    pub(crate) fn reap_idle_resources(&self) -> usize {
        self.reap_udp_shards(std::time::Instant::now())
            + self
                .runtime_generation
                .get()
                .map_or(0, |generation| generation.reap_idle_resources())
    }

    pub(crate) fn tasks_failed(&self) -> bool {
        self.transport_tasks_failed
            .load(std::sync::atomic::Ordering::Acquire)
            || self
                .runtime_generation
                .get()
                .is_some_and(|generation| generation.tasks_failed())
    }

    pub fn set_group_manager(&self, group_manager: Option<SharedGroupManager>) {
        *self.group_manager.write() = group_manager;
    }

    pub fn with_group_manager(self, group_manager: SharedGroupManager) -> Self {
        *self.group_manager.write() = Some(group_manager);
        self
    }

    pub fn set_group_manager_snapshot(&self, group_manager: Arc<GroupManager>) {
        *self.group_manager_snapshot.write() = Some(group_manager);
    }

    pub fn with_group_manager_snapshot(self, group_manager: Arc<GroupManager>) -> Self {
        self.set_group_manager_snapshot(group_manager);
        self
    }

    pub fn set_traffic_router(&self, router: Option<Arc<AsyncRwLock<Router>>>) {
        *self.traffic_router.write() = router;
    }

    pub fn with_traffic_router(self, router: Arc<AsyncRwLock<Router>>) -> Self {
        *self.traffic_router.write() = Some(router);
        self
    }

    pub fn set_traffic_router_snapshot(&self, router: Arc<Router>) {
        *self.traffic_router_snapshot.write() = Some(router);
    }

    pub fn with_traffic_router_snapshot(self, router: Arc<Router>) -> Self {
        self.set_traffic_router_snapshot(router);
        self
    }

    pub fn upstream_count(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn arm_admission_pause_for_test(&self) -> AdmissionPause {
        let pause = AdmissionPause {
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        self.admission_pause.lock().replace(pause.clone());
        pause
    }

    #[cfg(test)]
    async fn pause_after_admission_for_test(&self) {
        let pause = self.admission_pause.lock().take();
        if let Some(pause) = pause {
            pause.entered.notify_one();
            pause.release.notified().await;
        }
    }
}
