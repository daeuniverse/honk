//! Explicit routed-only Linux embedding, separate from PacketEndpoints and socket Relay.
//!
//! Drive this owner on a dedicated thread/runtime: FIB cache misses perform bounded
//! synchronous netlink work. Cache hits and submission never wait for a netlink reply.

use super::ControlPlane;
use super::connection::{
    handoff::mode_decision,
    routing::{PacketRoutingSnapshot, RoutingDecision},
};
pub use super::packet_endpoint::EndpointAdmission;
use crate::{
    netlink::fib::{Fib, Resolution},
    routing::PredicateInput,
};
use honk_config::{datapath::InterfaceRole, firewall::FirewallVerdict, routing::RoutingConfig};
use honk_datapath::{
    firewall::{self, Admission, EgressAddress, Facts, Firewall, SourceNat},
    forward::{
        CoreForward, ForwardError, Ingress, MarkProvenance, Packet, Prepared, Route, RouteQuery,
    },
};
use honk_netstack::{MemoryBudget, MemoryReservation, transit::TransitError};
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

mod reassembly;
pub use reassembly::GeneratedError;

pub use crate::netlink::fib::FibState;

/// Deployment requirements are not another policy language. Traffic policy remains dae's
/// canonical Router. Missing/unknown execution selection fails serde admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Execution {
    RoutedOnly,
    MixedEndpoints,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Requirements {
    pub execution: Execution,
    pub nat: bool,
    pub native_continuation: bool,
    pub kernel_firewall: bool,
    pub qdisc: bool,
    pub skb_classification: bool,
}
impl Requirements {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.native_continuation
                && !self.kernel_firewall
                && !self.qdisc
                && !self.skb_classification,
            "CoreForward cannot satisfy native/kernel-firewall/qdisc/skb-classification requirements"
        );
        Ok(())
    }
}

pub(super) fn validate_config(config: &honk_config::Config) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.global.dial_mode == "ip",
        "routed-only CoreForward requires dial_mode ip"
    );
    validate_policy(&config.routing)
}

fn validate_policy(config: &RoutingConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(config.default_outbound.as_str(), "direct" | "block")
            && config.default_mark == 0
            && config
                .rules
                .iter()
                .all(|rule| matches!(rule.outbound.as_str(), "direct" | "block") && rule.mark == 0),
        "routed-only CoreForward requires unmarked direct/block policy; Endpoint/group/native marks are not forwarding actions"
    );
    Ok(())
}

/// Conservative final-Direct profile: reject inputs that require unresolved socket/domain
/// facts rather than silently changing their execution owner to a relay.
pub fn validate_mixed(
    config: &honk_config::Config,
    router: &crate::routing::Router,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.global.dial_mode == "ip"
            && !router.has_direct_marks()
            && !router.uses_process_name()
            && router
                .compiled_routes()
                .iter()
                .all(|route| !route.has_domain_conditions()
                    && route.conditions.iter().all(|condition| !matches!(
                        condition.predicate,
                        crate::routing::CompiledPredicate::Mac(_)
                    ))),
        "mixed Core/Endpoint requires ip mode and no domain/process/MAC/marked routing; select Endpoint for that policy"
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Disposition {
    Core,
    Endpoint,
    Drop,
}

fn route_action<'a>(
    router: &'a crate::routing::Router,
    query: RouteQuery,
    source_mac: Option<&str>,
) -> Option<&'a crate::routing::RouteAction> {
    let protocol = match query.protocol {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmpv6",
        _ => return None,
    };
    Some(router.route_input(PredicateInput {
        domain: None,
        dst_ip: Some(query.destination),
        dst_port: query.ports.map(|ports| ports.1),
        src_ip: Some(query.source),
        src_port: query.ports.map(|ports| ports.0),
        protocol,
        process_name: None,
        mac: source_mac,
        dscp: Some(query.traffic_class >> 2),
    }))
}

fn disposition(
    outbound: &str,
    must: bool,
    marked: bool,
    query: RouteQuery,
    execution: Execution,
    retained: bool,
) -> Disposition {
    if outbound == "block" {
        return Disposition::Drop;
    }
    let dns = query.ports.is_some_and(|ports| ports.1 == 53);
    if outbound == "direct" && !marked && (execution == Execution::RoutedOnly || !dns || must) {
        return Disposition::Core;
    }
    if execution == Execution::MixedEndpoints && matches!(query.protocol, 6 | 17) {
        if retained {
            Disposition::Core
        } else {
            Disposition::Endpoint
        }
    } else {
        Disposition::Drop
    }
}

/// Both traffic policy and transient mode publication must still match at submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyGeneration {
    routing: u64,
    mode: u64,
}

struct Cached {
    query: RouteQuery,
    route: Route,
}

/// LocalInput is deliberately not a forwarding permit or permission to terminate a socket.
/// Adapters without an independently authorized local-input consumer must drop it.
pub enum Decision {
    Forward(Prepared, PolicyGeneration),
    LocalInput,
    Drop,
    Wait(Packet),
    Endpoint(Packet, EndpointAdmission),
}

pub enum CachedDecision<T> {
    Forwarded(T),
    Cold,
    Drop,
}

/// A registration in the existing policy publication owner, obtainable before
/// PacketEndpoints consumes the ControlPlane. Cloning does not create another policy.
#[derive(Clone)]
pub struct RoutingAuthority(Arc<Registration>);

struct Registration {
    router: Arc<tokio::sync::RwLock<crate::routing::Router>>,
    config: Arc<tokio::sync::RwLock<Arc<honk_config::Config>>>,
    diagnostics: crate::config_diagnostics::SharedDiagnostics,
    users: Arc<std::sync::atomic::AtomicUsize>,
    shutdown: Arc<super::ShutdownIntent>,
    healthy: Arc<std::sync::atomic::AtomicBool>,
    execution: Execution,
    mode_state: Option<crate::mode::SharedModeState>,
    group_manager: crate::group::SharedGroupManager,
    runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    #[cfg(feature = "native-api")]
    native: Option<Arc<crate::observe::Observation>>,
}

impl RoutingAuthority {
    fn admitting(&self) -> bool {
        !self.0.shutdown.requested() && self.0.healthy.load(Ordering::Acquire)
    }

    fn generation(&self, mode: Option<&crate::mode::ModeState>) -> PolicyGeneration {
        PolicyGeneration {
            routing: self.0.diagnostics.read().generation,
            mode: mode.map_or(0, crate::mode::ModeState::revision),
        }
    }

    /// Acquire the actual router then config publication readers, in the existing order.
    /// Keep a pending acquisition beside other owner work; drop the guards before awaiting.
    pub async fn read_policy(&self) -> PolicyRead<'_> {
        let router = self.0.router.read().await;
        let config = self.0.config.read().await;
        PolicyRead {
            registration: &self.0,
            router,
            config,
        }
    }
}

/// Held publication readers of one registration. Core rejects another registration's guards;
/// there is no other constructor and no detached generation.
pub struct PolicyRead<'a> {
    registration: &'a Arc<Registration>,
    router: tokio::sync::RwLockReadGuard<'a, crate::routing::Router>,
    config: tokio::sync::RwLockReadGuard<'a, Arc<honk_config::Config>>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.users.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ControlPlane {
    pub async fn core_forward_policy(
        &self,
        execution: Execution,
    ) -> anyhow::Result<RoutingAuthority> {
        let _publication = self.reload_lock.lock().await;
        let router = self.router.read().await;
        let config = self.config.read().await;
        let configured = config
            .datapath
            .as_ref()
            .is_some_and(|datapath| datapath.firewall.is_some());
        anyhow::ensure!(
            configured == router.firewall_policy().is_some()
                && (!configured || router.security_epoch() != 0),
            "firewall policy must be compiled into the accepted Router before capture admission"
        );
        let users = match execution {
            Execution::RoutedOnly => {
                validate_config(&config)?;
                &self.core_forward_users
            }
            Execution::MixedEndpoints => {
                validate_mixed(&config, &router)?;
                &self.core_forward_mixed_users
            }
        };
        users.fetch_add(1, Ordering::AcqRel);
        Ok(RoutingAuthority(Arc::new(Registration {
            router: Arc::clone(&self.router),
            config: Arc::clone(&self.config),
            diagnostics: Arc::clone(&self.diagnostics),
            users: Arc::clone(users),
            execution,
            shutdown: Arc::clone(&self.shutdown_requested),
            healthy: Arc::clone(&self.datapath_healthy),
            mode_state: self.mode_state.clone(),
            group_manager: self.group_manager.clone(),
            runtime_registry: self.runtime_registry.clone(),
            #[cfg(feature = "native-api")]
            native: self.native.clone(),
        })))
    }
}

fn invalidate_address_grants(table: &mut Firewall, known: &mut u64, current: u64) {
    if *known != current {
        table.invalidate_address_generation(current);
        *known = current;
    }
}

fn permits_admin_error(input: &Resolution) -> bool {
    matches!(
        input,
        Resolution::Forward(_)
            | Resolution::NeighborPending(_)
            | Resolution::Error(TransitError::AdminProhibited)
    )
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RefusalCounters {
    pub core_capacity: u64,
    pub nat_capacity: u64,
    pub nat_exhausted: u64,
    pub nat_conflict: u64,
    pub native_history_overflow: u64,
}
impl RefusalCounters {
    fn core(&mut self, error: &ForwardError) {
        if matches!(error, ForwardError::Capacity) {
            self.core_capacity = self.core_capacity.saturating_add(1);
        }
    }
    fn nat(&mut self, error: &firewall::FirewallError) {
        let count = match error {
            firewall::FirewallError::Capacity => &mut self.nat_capacity,
            firewall::FirewallError::Exhausted => &mut self.nat_exhausted,
            firewall::FirewallError::Conflict => &mut self.nat_conflict,
            _ => return,
        };
        *count = count.saturating_add(1);
    }
}

pub struct RoutedCore {
    authority: RoutingAuthority,
    core: CoreForward,
    fib: Fib,
    routes: Vec<Cached>,
    address_generation: u64,
    firewall: Firewall,
    budget: Arc<MemoryBudget>,
    ingress_roles: Vec<(Ingress, InterfaceRole)>,
    reassembly_outputs: Arc<reassembly::Outputs>,
    pending_reassembly_error: Option<reassembly::Pending>,
    reassembly_poll_pending: bool,
    counters: RefusalCounters,
    _role_charge: MemoryReservation,
    _charge: MemoryReservation,
}

impl RoutedCore {
    /// The process/thread must already be in the selected capture namespace. `namespace`
    /// is an actual SO_NETNS_COOKIE obtained from an adapter socket, not a ScopeId/inode.
    pub fn new(
        authority: RoutingAuthority,
        ingresses: &[Ingress],
        requirements: Requirements,
        budget: Arc<MemoryBudget>,
    ) -> anyhow::Result<Self> {
        requirements.validate()?;
        anyhow::ensure!(
            authority.0.execution == requirements.execution,
            "capture execution differs from registered policy consumer"
        );
        anyhow::ensure!(
            ingresses.iter().all(|ingress| matches!(
                ingress.mark,
                MarkProvenance::BeforeSkb | MarkProvenance::Captured(0)
            )),
            "routed-only deployment requires proven pre-skb or captured zero mark"
        );
        if requirements.nat {
            let config = authority
                .0
                .config
                .try_read()
                .map_err(|_| anyhow::anyhow!("configuration publication in progress"))?;
            anyhow::ensure!(config.datapath.as_ref().is_some_and(|datapath| datapath.firewall.is_some() && !datapath.nat.is_empty()), "NAT requirement needs compiled datapath firewall/NAT rules");
        }
        let core = CoreForward::new(ingresses, Arc::clone(&budget), 1024)?;
        let mut fib = Fib::new(&budget, ingresses[0].namespace)?;
        fib.synchronize()?;
        let address_generation = fib.address_generation();
        let charge = budget
            .reserve(1024 * size_of::<Cached>())
            .ok_or_else(|| anyhow::anyhow!("route cache budget exhausted"))?;
        let role_charge = budget
            .reserve(ingresses.len() * size_of::<(Ingress, InterfaceRole)>())
            .ok_or_else(|| anyhow::anyhow!("ingress role budget exhausted"))?;
        let reassembly_outputs = reassembly::Outputs::new(&budget)?;
        let firewall = Firewall::new_history(Arc::clone(&budget), 1024, 0)?;
        Ok(Self {
            authority,
            core,
            fib,
            address_generation,
            routes: Vec::with_capacity(1024),
            firewall,
            budget,
            ingress_roles: Vec::with_capacity(ingresses.len()),
            reassembly_outputs,
            pending_reassembly_error: None,
            reassembly_poll_pending: false,
            counters: RefusalCounters::default(),
            _role_charge: role_charge,
            _charge: charge,
        })
    }

    /// A clone of this core's existing registration, not a second policy consumer.
    pub fn authority(&self) -> RoutingAuthority {
        self.authority.clone()
    }

    fn check_policy(&self, read: &PolicyRead<'_>) -> io::Result<()> {
        if Arc::ptr_eq(read.registration, &self.authority.0) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "policy readers belong to another Core registration",
            ))
        }
    }

    pub fn set_ingress_roles(&mut self, roles: &[(Ingress, InterfaceRole)]) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.ingress_roles.is_empty(),
            "ingress roles are immutable after installation"
        );
        anyhow::ensure!(
            roles.len() == self.core.ingresses().len()
                && roles.iter().enumerate().all(|(index, (identity, _))| self
                    .core
                    .ingresses()
                    .any(|registered| registered == *identity)
                    && roles[..index]
                        .iter()
                        .all(|(previous, _)| previous != identity)),
            "roles must cover every exact registered ingress once"
        );
        self.ingress_roles.extend_from_slice(roles);
        Ok(())
    }

    pub fn state(&self) -> FibState {
        self.fib.state()
    }
    pub fn counters(&self) -> RefusalCounters {
        self.counters
    }
    pub fn receive(
        &mut self,
        ingress: Ingress,
        now: Instant,
        bytes: &[u8],
    ) -> anyhow::Result<Option<Packet>> {
        let packet = self
            .core
            .receive(ingress, now, bytes)
            .inspect_err(|error| self.counters.core(error))?;
        Ok(self.pin_received(packet))
    }

    pub fn receive_segments(
        &mut self,
        ingress: Ingress,
        now: Instant,
        segments: &[&[u8]],
    ) -> anyhow::Result<Option<Packet>> {
        let packet = self
            .core
            .receive_segments(ingress, now, segments)
            .inspect_err(|error| self.counters.core(error))?;
        Ok(self.pin_received(packet))
    }

    fn pin_received(&mut self, packet: Option<Packet>) -> Option<Packet> {
        let packet = packet.and_then(|mut packet| {
            self.firewall.set_fragment_obligations(
                self.core
                    .fragment_obligations()
                    .chain(packet.is_reassembled().then_some(packet.query().into())),
            );
            if (!self.firewall.is_empty() || packet.ip().proto == honk_netstack::wire::PROTO_ICMP)
                && let Ok(facts) = Facts::from_packet(&packet)
            {
                if let Some(quote) = self
                    .firewall
                    .retain_native_quote(packet.query().ingress, &facts)
                {
                    packet.retain_native_quote(quote);
                }
                if !self.firewall.is_empty() {
                    match self
                        .firewall
                        .pin(packet.query().ingress, &facts, packet.received_at())
                    {
                        Ok(Some(binding)) => packet.bind(binding),
                        Ok(None) => {}
                        Err(error) => {
                            self.counters.nat(&error);
                            return None;
                        }
                    }
                }
            }
            Some(packet)
        });
        self.firewall
            .set_fragment_obligations(self.core.fragment_obligations());
        packet
    }

    /// Borrowed RX -> reserved TX, with no whole-packet staging. Cold means retain the
    /// necessary bytes and use decide(); publication contention never invents a decision.
    pub fn forward_cached<'a, T>(
        &mut self,
        ingress: Ingress,
        view: honk_netstack::wire::PacketView<'a>,
        source_mac: Option<&str>,
        now: Instant,
        submit: impl FnOnce(
            Route,
            &mut honk_datapath::forward::ForwardView<'a>,
        ) -> io::Result<Option<T>>,
    ) -> io::Result<CachedDecision<T>> {
        if !self.authority.admitting() {
            return Ok(CachedDecision::Drop);
        }
        let Ok(router) = self.authority.0.router.try_read() else {
            return Ok(CachedDecision::Cold);
        };
        let Ok(_config) = self.authority.0.config.try_read() else {
            return Ok(CachedDecision::Cold);
        };
        let mode = match &self.authority.0.mode_state {
            Some(state) => match state.try_read() {
                Some(mode) => Some(mode),
                None => return Ok(CachedDecision::Cold),
            },
            None => None,
        };
        if router.firewall_policy().is_some() || !self.firewall.is_empty() {
            return Ok(CachedDecision::Cold);
        }
        let input = match self.core.validate_view(ingress, now, view) {
            Ok(input) => input,
            Err(honk_datapath::forward::ForwardError::Packet(
                honk_netstack::wire::ParseError::Fragment,
            )) => return Ok(CachedDecision::Cold),
            Err(_) => return Ok(CachedDecision::Drop),
        };
        let query = input.query();
        let Some(action) = route_action(&router, query, source_mac) else {
            return Ok(CachedDecision::Drop);
        };
        if !action.must
            && action.outbound != "block"
            && mode.as_ref().is_some_and(|mode| mode.is_global())
        {
            return Ok(CachedDecision::Cold);
        }
        let outbound = if !action.must
            && action.outbound != "block"
            && mode.as_ref().is_some_and(|mode| mode.is_direct())
        {
            "direct"
        } else {
            &action.outbound
        };
        match disposition(
            outbound,
            action.must,
            action.mark.is_some(),
            query,
            self.authority.0.execution,
            self.core.retains(query, now),
        ) {
            Disposition::Drop => return Ok(CachedDecision::Drop),
            Disposition::Endpoint => {
                return Ok(if input.permits_new_endpoint() {
                    CachedDecision::Cold
                } else {
                    CachedDecision::Drop
                });
            }
            Disposition::Core => {}
        }
        if query.protocol == honk_netstack::wire::PROTO_ICMP {
            return Ok(CachedDecision::Cold);
        }
        if input.validate_core().is_err() {
            return Ok(CachedDecision::Drop);
        }
        if !self.fib.current(self.fib.generation())? {
            return Ok(CachedDecision::Cold);
        }
        let Some(route) = self
            .routes
            .iter()
            .find(|cached| {
                cached.query == query && cached.route.generation == self.fib.generation()
            })
            .map(|cached| cached.route)
        else {
            return Ok(CachedDecision::Cold);
        };
        let generation = self.authority.0.diagnostics.read().generation;
        let mut output = match self.core.prepare_view(input, route, generation, now) {
            Ok(Some(output)) => output,
            Ok(None) => return Ok(CachedDecision::Cold),
            Err(error) => {
                self.counters.core(&error);
                return Ok(CachedDecision::Drop);
            }
        };
        if !self.fib.current(route.generation)? {
            return Ok(CachedDecision::Cold);
        }
        if let Some((tuple, id)) = output.native_identity()
            && let Some(egress) = self.core.ingress(route.ifindex)
        {
            match self.firewall.observe_plain(ingress, egress, tuple, id, now) {
                Ok(native) => {
                    if !native.is_exact() {
                        self.counters.native_history_overflow =
                            self.counters.native_history_overflow.saturating_add(1);
                    }
                    output.bind_native(native);
                }
                Err(error) => {
                    self.counters.nat(&error);
                    return Ok(CachedDecision::Drop);
                }
            }
        }
        let result = submit(route, &mut output)
            .map(|result| result.map_or(CachedDecision::Drop, CachedDecision::Forwarded));
        drop(mode);
        result
    }

    /// Bounded and synchronous under readers acquired from this core's own registration.
    pub fn decide(
        &mut self,
        read: &PolicyRead<'_>,
        mut packet: Packet,
        source_mac: Option<&str>,
        now: Instant,
    ) -> anyhow::Result<Decision> {
        self.check_policy(read)?;
        let now = now.max(Instant::now());
        if now >= packet.deadline() || !self.authority.admitting() {
            return Ok(Decision::Drop);
        }
        let (generation, epoch, policy, selected, admission) = {
            let router = &*read.router;
            let config = &*read.config;
            let mode_state = self
                .authority
                .0
                .mode_state
                .as_ref()
                .map(|state| state.read());
            #[cfg(feature = "native-api")]
            let native = self.authority.0.native.as_ref().map(|native| {
                (
                    self.authority.0.diagnostics.read().generation,
                    native.catalog.snapshot(),
                )
            });
            let generation = self.authority.generation(mode_state.as_deref());
            let Some(action) = route_action(router, packet.query(), source_mac) else {
                return Ok(Decision::Drop);
            };
            let mode = mode_decision(
                mode_state.as_deref(),
                config,
                #[cfg(feature = "native-api")]
                native.as_ref().map(|(_, catalog)| &**catalog),
                action.outbound.clone(),
                action.must,
            );
            let marked =
                action.outbound == "direct" && mode.name == "direct" && action.mark.is_some();
            let selected = disposition(
                &mode.name,
                action.must,
                marked,
                packet.query(),
                self.authority.0.execution,
                self.core.retains(packet.query(), now),
            );
            let admission = if selected == Disposition::Endpoint && packet.permits_new_endpoint() {
                let (source_port, destination_port) =
                    packet.query().ports.expect("Endpoint transport ports");
                let input = crate::routing::ConnectionInfo {
                    domain: None,
                    dst_ip: packet.query().destination,
                    dst_port: destination_port,
                    src_ip: packet.query().source,
                    src_port: source_port,
                    protocol: if packet.query().protocol == 6 {
                        "tcp"
                    } else {
                        "udp"
                    },
                    process_name: None,
                    mac: source_mac.map(str::to_owned),
                    dscp: Some(packet.query().traffic_class >> 2),
                };
                Some(PacketRoutingSnapshot {
                    decision: RoutingDecision::from_router(
                        router,
                        &input,
                        None,
                        #[cfg(feature = "native-api")]
                        self.authority
                            .0
                            .native
                            .as_deref()
                            .map(|native| (native, generation.routing)),
                    ),
                    mode,
                    mode_state: None,
                    admission_final: true,
                    memory: None,
                    config: Arc::clone(config),
                    group_manager: self.authority.0.group_manager.read().clone(),
                    runtime: self.authority.0.runtime_registry.read().clone(),
                    #[cfg(feature = "native-api")]
                    native,
                })
            } else {
                None
            };
            (
                generation,
                router.security_epoch(),
                router.firewall_policy().cloned(),
                selected,
                admission,
            )
        };
        if selected == Disposition::Drop {
            return Ok(Decision::Drop);
        }
        if self.firewall.epoch() != epoch {
            self.firewall.revoke(epoch);
        }
        self.firewall
            .set_fragment_obligations(self.core.fragment_obligations());
        self.firewall.expire(now);
        let facts = if policy.is_some() || packet.ip().proto == honk_netstack::wire::PROTO_ICMP {
            Facts::from_packet(&packet).ok()
        } else {
            None
        };
        if packet.native_quote().is_none()
            && let Some(facts) = &facts
            && let Some(quote) = self
                .firewall
                .retain_native_quote(packet.query().ingress, facts)
        {
            packet.retain_native_quote(quote);
        }
        let mut binding = packet.binding().cloned();
        if binding
            .as_ref()
            .is_some_and(|binding| !binding.is_current(epoch))
        {
            return Ok(Decision::Drop);
        }
        if binding
            .as_ref()
            .is_none_or(|binding| !binding.is_authorized())
            && policy.is_some()
            && let Some(facts) = &facts
        {
            binding =
                match self
                    .firewall
                    .lookup(packet.query().ingress, facts, packet.received_at())
                {
                    Ok(binding) => binding,
                    Err(error) => {
                        self.counters.nat(&error);
                        return Ok(Decision::Drop);
                    }
                };
            if let Some(binding) = &binding {
                packet.bind(binding.clone());
            }
        }
        if binding.is_none() && selected == Disposition::Endpoint {
            let Some(admission) = admission else {
                return Ok(Decision::Drop);
            };
            let admission = match EndpointAdmission::new(admission, &self.budget) {
                Ok(admission) => admission,
                Err(_) => {
                    self.counters.core_capacity = self.counters.core_capacity.saturating_add(1);
                    return Ok(Decision::Drop);
                }
            };
            return Ok(Decision::Endpoint(packet, admission));
        }
        if packet.validate_core().is_err() {
            return Ok(Decision::Drop);
        }
        let ingress = packet.query().ingress;
        let zone = self
            .ingress_roles
            .iter()
            .find(|(identity, _)| *identity == ingress)
            .map(|(_, role)| *role);
        let mut dnat = None;
        let before = if let Some(binding) = &binding {
            Some(binding.before_route())
        } else if let Some(policy) = &policy {
            let (Some(facts), Some(zone)) = (&facts, zone) else {
                return Ok(Decision::Drop);
            };
            match policy.original(facts.tuple, packet.query().traffic_class, zone) {
                FirewallVerdict::Allow => {}
                FirewallVerdict::Drop => return Ok(Decision::Drop),
                FirewallVerdict::Reject => {
                    return Ok(Decision::Forward(
                        Prepared::Error {
                            packet,
                            error: TransitError::AdminProhibited,
                        },
                        generation,
                    ));
                }
            }
            dnat = policy.dnat(facts.tuple, packet.query().traffic_class);
            match firewall::destination_tuple(facts.tuple, dnat) {
                Ok(tuple) => Some(tuple),
                Err(_) => return Ok(Decision::Drop),
            }
        } else {
            None
        };
        self.fib.poll_changes()?;
        if !self.fib.current(self.fib.generation())? {
            self.routes.clear();
            self.fib.synchronize()?;
        }
        invalidate_address_grants(
            &mut self.firewall,
            &mut self.address_generation,
            self.fib.address_generation(),
        );
        let mut query = packet.query();
        if let Some(tuple) = before {
            query.source = tuple.source;
            query.destination = tuple.destination;
            if query.ports.is_some() {
                query.ports = Some((tuple.source_port, tuple.destination_port));
            }
        }
        packet.set_input_query(query);
        let cached = self
            .routes
            .iter()
            .find(|cached| {
                cached.query == query && cached.route.generation == self.fib.generation()
            })
            .map(|cached| cached.route);
        let (route, neighbor_ready) = match cached {
            Some(route) => (route, true),
            None => match self.fib.lookup(query) {
                Ok(Resolution::Forward(route)) => {
                    if self.routes.len() == 1024 {
                        self.routes.clear();
                    }
                    self.routes.push(Cached { query, route });
                    (route, true)
                }
                Ok(Resolution::LocalInput) => return Ok(Decision::LocalInput),
                Ok(Resolution::Drop) => return Ok(Decision::Drop),
                Ok(Resolution::Error(error)) => {
                    return Ok(Decision::Forward(
                        Prepared::Error { packet, error },
                        generation,
                    ));
                }
                Ok(Resolution::NeighborPending(route)) => (route, false),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(Decision::Wait(packet));
                }
                Err(error) => return Err(error.into()),
            },
        };
        let mut now = Instant::now();
        if now >= packet.deadline() {
            return Ok(Decision::Drop);
        }
        if let Some(existing) = &binding {
            if self.egress_ingress(route)? != Some(existing.egress_ingress()) {
                return Ok(Decision::Drop);
            }
            if let Some(address) = existing.masquerade()
                && (self.fib.address_generation() != address.generation
                    || !self.fib.is_local(address.address.into()))
            {
                self.firewall
                    .invalidate_address(address.ifindex, address.address);
                return Ok(Decision::Drop);
            }
        } else if let Some(policy) = &policy {
            let (Some(_), Some(before), Some(zone)) = (&facts, before, zone) else {
                return Ok(Decision::Drop);
            };
            match policy.forward(before, query.traffic_class, zone) {
                FirewallVerdict::Allow => {}
                FirewallVerdict::Drop => return Ok(Decision::Drop),
                FirewallVerdict::Reject => {
                    return Ok(Decision::Forward(
                        Prepared::Error {
                            packet,
                            error: TransitError::AdminProhibited,
                        },
                        generation,
                    ));
                }
            }
        }
        let early_error = match packet.forwarding_error(route.mtu) {
            Ok(error) => error,
            Err(_) => return Ok(Decision::Drop),
        };
        if let Some(error) = early_error {
            return Ok(Decision::Forward(
                Prepared::Error { packet, error },
                generation,
            ));
        }
        if !neighbor_ready {
            match self.fib.request_neighbor(route) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(Decision::Wait(packet));
        }
        if binding.is_none()
            && let Some(policy) = &policy
        {
            let (Some(facts), Some(before)) = (&facts, before) else {
                return Ok(Decision::Drop);
            };
            let Some(reply_ingress) = self.egress_ingress(route)? else {
                return Ok(Decision::Drop);
            };
            let action = policy.snat(before, query.traffic_class);
            let address = if matches!(action, SourceNat::Masquerade { .. }) {
                match self.fib.masquerade_source(route, query) {
                    Ok(Some(address)) => Some(EgressAddress {
                        ifindex: route.ifindex,
                        address,
                        generation: self.fib.address_generation(),
                    }),
                    Ok(None) => return Ok(Decision::Drop),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(Decision::Wait(packet));
                    }
                    Err(error) => return Err(error.into()),
                }
            } else {
                None
            };
            now = Instant::now();
            if now >= packet.deadline() {
                return Ok(Decision::Drop);
            }
            binding = match self.firewall.admit(Admission {
                ingress,
                reply_ingress,
                facts,
                dnat,
                snat: action,
                egress: address,
                received_at: packet.received_at(),
                now,
            }) {
                Ok(binding) => Some(binding),
                Err(error) => {
                    self.counters.nat(&error);
                    return Ok(Decision::Drop);
                }
            };
        }
        if let Some(binding) = binding {
            if !binding.is_current(epoch) {
                return Ok(Decision::Drop);
            }
            if binding.translation_required() {
                packet.rewrite(|bytes| {
                    binding
                        .rewrite(bytes, false)
                        .map_err(|_| ForwardError::Provenance)
                })?;
            }
            packet.bind(binding);
        }
        if packet.binding().is_none()
            && let Some((tuple, id)) = packet.native_identity()
            && let Some(egress) = self.core.ingress(route.ifindex)
        {
            match self.firewall.observe_plain(ingress, egress, tuple, id, now) {
                Ok(native) => {
                    if !native.is_exact() {
                        self.counters.native_history_overflow =
                            self.counters.native_history_overflow.saturating_add(1);
                    }
                    packet.bind_native(native);
                }
                Err(error) => {
                    self.counters.nat(&error);
                    return Ok(Decision::Drop);
                }
            }
        }
        if let Some(quote) = packet.native_quote().cloned()
            && packet
                .rewrite(|bytes| quote.rewrite(bytes).map_err(|_| ForwardError::Provenance))
                .is_err()
        {
            return Ok(Decision::Drop);
        }
        let prepared = match self.core.prepare(packet, route, generation.routing, now) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.counters.core(&error);
                return Ok(Decision::Drop);
            }
        };
        // Byte translation is deferred until the FIB and both firewall stages succeed.
        // Transit errors quote the original ingress identity, never a DNAT-private tuple.
        let prepared = match (prepared, facts) {
            (Prepared::Error { mut packet, error }, Some(facts)) => {
                if packet
                    .binding()
                    .is_some_and(|binding| binding.translation_required())
                {
                    packet.rewrite(|bytes| {
                        facts.restore(bytes).map_err(|_| ForwardError::Provenance)
                    })?;
                }
                Prepared::Error { packet, error }
            }
            (prepared, _) => prepared,
        };
        Ok(Decision::Forward(prepared, generation))
    }

    /// Run inside the actual policy publication readers AND the provider owner through
    /// descriptor submission. A rejected fence must dispose output, not replay decremented bytes.
    /// The callback rechecks its packet/lease after expiration; `None` disposes stale output.
    pub fn submit<T>(
        &mut self,
        read: &PolicyRead<'_>,
        route: Route,
        generation: PolicyGeneration,
        submit: impl FnOnce() -> io::Result<Option<T>>,
    ) -> io::Result<Option<T>> {
        self.check_policy(read)?;
        let router = &*read.router;
        let mode = self
            .authority
            .0
            .mode_state
            .as_ref()
            .map(|state| state.read());
        if self.firewall.epoch() != router.security_epoch() {
            self.firewall.revoke(router.security_epoch());
        }
        self.firewall
            .set_fragment_obligations(self.core.fragment_obligations());
        self.firewall.expire(Instant::now());
        let current = self.fib.current(route.generation);
        invalidate_address_grants(
            &mut self.firewall,
            &mut self.address_generation,
            self.fib.address_generation(),
        );
        let current_policy = self.authority.generation(mode.as_deref());
        if !self.authority.admitting() || current_policy != generation || !current? {
            return Ok(None);
        }
        let result = submit();
        drop(mode);
        result
    }

    /// The genuine local-output lookup supplies the source, including on unnumbered
    /// capture interfaces. Missing/unassigned preferred source suppresses the error.
    pub fn error(
        &mut self,
        now: Instant,
        packet: &Packet,
        error: TransitError,
        route: Route,
        out: &mut [u8],
    ) -> anyhow::Result<Option<usize>> {
        if !self.fib.current(route.generation)? {
            return Ok(None);
        }
        // Reject still needs input-FIB authority, but a real prohibit route is itself
        // authority to originate the corresponding ICMP error, not a silent blackhole.
        if error == TransitError::AdminProhibited {
            match self.fib.lookup(packet.input_query()) {
                Ok(input) if permits_admin_error(&input) => {}
                Ok(_) => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
        if !self.fib.current(route.generation)? {
            return Ok(None);
        }
        let Some(source) = self.fib.error_source(route) else {
            return Ok(None);
        };
        let limit = out.len().min(route.mtu as usize);
        Ok(self
            .core
            .error(now, error, source, packet, &mut out[..limit])?)
    }

    pub fn retire(&mut self, now: Instant) {
        self.reassembly_poll_pending |= self
            .core
            .poll_reassembly_timeout()
            .is_some_and(|deadline| deadline <= now);
        self.core.retire(now);
        invalidate_address_grants(
            &mut self.firewall,
            &mut self.address_generation,
            self.fib.address_generation(),
        );
        self.firewall
            .set_fragment_obligations(self.core.fragment_obligations());
        self.firewall.expire(now);
    }
    pub fn has_maintenance(&self) -> bool {
        self.core.has_retained_flows() || self.firewall.has_maintenance()
    }

    pub fn fragments_quiescent(&self) -> bool {
        self.core.fragments_quiescent()
            && self.reassembly_outputs.pending() == 0
            && self.pending_reassembly_error.is_none()
    }

    pub fn registered_ingresses(&self) -> impl ExactSizeIterator<Item = Ingress> + '_ {
        self.core.ingresses()
    }
    pub fn egress_ingress(&mut self, route: Route) -> io::Result<Option<Ingress>> {
        Ok(if self.fib.current(route.generation)? {
            self.core.ingress(route.ifindex)
        } else {
            None
        })
    }

    /// Generated ICMP uses a real local-output query with the router's source address;
    /// this output lookup is never used as a transit forwarding oracle.
    pub fn error_route(&mut self, original: &Packet) -> io::Result<Option<Route>> {
        if !self.fib.current(self.fib.generation())? {
            self.routes.clear();
            self.fib.synchronize()?;
        }
        match self.fib.lookup_error(original.query()) {
            Ok(Resolution::Forward(route)) => Ok(Some(route)),
            Ok(_) => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// Read actual socket namespace provenance for a capture adapter before constructing Core.
pub fn socket_namespace(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<u64> {
    use std::os::fd::AsRawFd;
    crate::netlink::fib::namespace_cookie(fd.as_raw_fd())
}

#[cfg(test)]
mod tests;
