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
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use honk_config::dns::{DnsStrategy, DnsUpstream};

    use super::transports::{PooledTransport, TransportKey};
    use crate::dns::endpoint::DnsEndpoint;
    use crate::dns::transport::{LifecycleSlot, UdpPool};

    #[derive(Default)]
    pub(super) struct UdpState {
        pub(super) current: Option<SocketAddr>,
        pub(super) pools: [Option<(SocketAddr, Arc<UdpPool>)>; 2],
    }

    impl UdpState {
        pub(super) fn current_pool(&self) -> Option<(SocketAddr, Arc<UdpPool>)> {
            let current = self.current?;
            let family = usize::from(current.is_ipv6());
            self.pools[family]
                .as_ref()
                .filter(|(address, _)| *address == current)
                .map(|(_, pool)| (current, Arc::clone(pool)))
        }

        pub(super) fn mark_current(&mut self, address: SocketAddr) {
            let family = usize::from(address.is_ipv6());
            if self.pools[family]
                .as_ref()
                .is_some_and(|(cached, _)| *cached == address)
            {
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportLifecycleStats {
    pub init_count: usize,
    pub close_count: usize,
    pub tasks: usize,
}

pub struct UpstreamPool {
    entries: HashMap<String, UpstreamEntry>,
    proxy_registry: Option<Arc<ProxyRegistry>>,
    client_subnet: Option<ipnet::Ipv4Net>,
    runtime_generation: std::sync::OnceLock<Arc<honk_outbound::runtime::OutboundRuntimeRegistry>>,
    nodes: Vec<Node>,
    groups: Vec<Group>,
    group_manager: parking_lot::RwLock<Option<SharedGroupManager>>,
    group_manager_snapshot: parking_lot::RwLock<Option<Arc<GroupManager>>>,
    traffic_router: parking_lot::RwLock<Option<Arc<AsyncRwLock<Router>>>>,
    traffic_router_snapshot: parking_lot::RwLock<Option<Arc<Router>>>,
    dns_query_timeout: Duration,
    dns_dial_timeout: Duration,
    active_transport_tasks: Arc<AtomicUsize>,
    admission: AdmissionGate,
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
        Ok(Self {
            entries: build_entries(upstreams, bootstrap_resolver, strategy)?,
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
            active_transport_tasks: Arc::new(AtomicUsize::new(0)),
            admission: AdmissionGate::new(),
            #[cfg(test)]
            admission_pause: parking_lot::Mutex::new(None),
        })
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
        self.runtime_generation
            .set(generation)
            .map_err(|_| anyhow::anyhow!("DNS upstream runtime generation is already set"))
    }

    pub fn with_runtime_generation(
        self,
        generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    ) -> Self {
        self.set_runtime_generation(generation)
            .expect("new DNS upstream pool has no runtime generation");
        self
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
