//! Control plane: TPROXY accept loop, routing, proxy dial, relay, graceful shutdown.

mod bootstrap;
mod cache;
pub(crate) mod client;
mod connection;
pub mod dns_control;
mod dns_listener;
pub mod drain;
pub mod janitor;
#[cfg(feature = "ebpf")]
pub(crate) mod nfqueue;
#[cfg(feature = "ebpf")]
mod nfqueue_runtime;
#[cfg(all(test, feature = "ebpf"))]
use nfqueue_runtime::{
    NFQUEUE_INGEST_BYTE_BUDGET, NFQUEUE_INGEST_QUEUE_LEN, NfqueueActorQueue, NfqueueRuntimeFatal,
    NfqueueTokenRetryBackoff,
};
#[cfg(feature = "ebpf")]
use nfqueue_runtime::{NfqueueRuntime, NfqueueRuntimeEvent, wait_nfqueue_event};
mod lifecycle;
pub mod packet_sniffer;
mod preconnect;
mod probers;
pub mod quic;
pub(crate) mod reload;
#[cfg(test)]
mod reload_tests;
mod resource_budget;
mod runtime;
mod shutdown;
#[cfg(test)]
mod tests;
#[cfg(test)]
use udp_ingress::{
    UdpLoopState, UdpSlowPathWork, begin_udp_slow_path, dispatch_udp_slow_path,
    reserve_udp_slow_path, try_admit_udp_slow_path, udp_fast_path,
};
pub mod routing_matcher;
mod sockets;
pub mod tcp_sniff;
mod udp_dial;
pub mod udp_endpoint;
mod udp_ingress;
mod udp_removal;
use crate::connection_tracker::ConnectionTracker;
use crate::control::packet_sniffer::PacketSnifferPool;
use crate::control::udp_endpoint::{EndpointReservation, UdpEndpointPool, UdpInitLease};
use crate::dns::DnsResolver;
use crate::dns::query::{ValidatedDnsQuery, validate_exact_dns_query};
use crate::ebpf::EbpfBackend;
use crate::group::{GroupManager, SharedGroupManager};
use crate::pool::ConnectionPool;
use crate::proxy::ProxyRegistry;
use crate::relay;
use crate::routing::{ConnectionInfo, Router};
use crate::sniffing;
use crate::stats::StatsManager;
use bytes::Bytes;
use drain::DrainTracker;
#[cfg(feature = "ebpf")]
use futures::FutureExt;
use honk_config::node::{Group, GroupPolicy};
use honk_config::{
    Config,
    node::Node,
    types::{DialMode, NodeProtocol},
};
use honk_ebpf_common::*;
use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use janitor::BpfJanitor;
use socket2::{Domain, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::Duration;
#[cfg(feature = "ebpf")]
use std::time::Instant;
use tokio::io::Interest;
#[cfg(test)]
use tokio::net::TcpListener;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, trace, warn};

mod commands;

pub use client::ControlClient;
pub(crate) use commands::{ControlCommand, ReloadOutcome, ReloadReply};
use connection::*;
use probers::*;
pub(crate) use reload::LogFiles;
#[cfg(feature = "native-api")]
pub(crate) use reload::restart_required_fields;
use reload::*;
pub(crate) use resource_budget::{MAX_EFFECTIVE_NOFILE, ResourceBudget};
use sockets::*;
#[cfg(all(test, feature = "native-api"))]
pub(crate) use tests::reload_harness::ReloadBehavior;

/// Re-send `NetworkChanged` with bounded backoff after a rejected refresh.
/// Duplicate deliveries after the interface-dependent state converges are
/// cheap no-ops.
fn spawn_network_refresh_retry(tx: mpsc::Sender<ControlCommand>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for delay_secs in [5, 15, 60] {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            if tx.send(ControlCommand::NetworkChanged).await.is_err() {
                return;
            }
        }
        warn!("network-triggered ECS refresh retries exhausted");
    })
}

#[cfg(test)]
type PreDnsPublicationHook = Box<dyn FnOnce(&Arc<GroupManager>) + Send>;

#[cfg(feature = "native-api")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnginePhase {
    Starting,
    Running,
    Draining,
    Failed,
}

/// The main control plane.
pub struct ControlPlane {
    config: Arc<RwLock<Arc<Config>>>,
    diagnostics: crate::config_diagnostics::SharedDiagnostics,
    /// Reuse decisions must observe the generation they eventually replace.
    reload_lock: tokio::sync::Mutex<()>,
    log_files: LogFiles,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    router: Arc<RwLock<Router>>,
    proxy_registry: Arc<ProxyRegistry>,
    dns_resolver: Arc<DnsResolver>,
    dns_controller: Arc<crate::control::dns_control::DnsController>,
    group_manager: SharedGroupManager,
    /// Traffic runtimes; DNS generations own separate session registries.
    runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    stats: Arc<StatsManager>,
    drain_tracker: Arc<DrainTracker>,
    udp_pool: Arc<UdpEndpointPool>,
    sniffer_pool: Arc<PacketSnifferPool>,
    tcp_sniff_neg_cache: Arc<crate::control::tcp_sniff::TcpSniffNegCache>,
    command_tx: mpsc::Sender<ControlCommand>,
    command_rx: Option<mpsc::Receiver<ControlCommand>>,
    /// Backoff retry for rejected interface-dependent runtime refreshes: the
    /// iface watcher consumes each change once, so a transient rejection
    /// would otherwise leave ECS on stale network-derived state.
    network_refresh_retry: Option<tokio::task::JoinHandle<()>>,
    alive_set: Arc<crate::outbound::AliveDialerSet>,
    connection_pool: Arc<ConnectionPool>,
    connection_tracker: Arc<ConnectionTracker>,
    tcp_flow_pins: Arc<TcpFlowPins>,
    /// Persistent cache (selector choices, delay samples); opened by `run()`
    /// via `init_cache_db` unless `experimental.cache_file.enabled` is false.
    cache_db: Option<Arc<crate::state::cache::CacheDb>>,
    /// `cache_db` when `experimental.cache_file` also keeps the Clash mode.
    mode_db: Option<Arc<crate::state::cache::CacheDb>>,
    /// The state database handed to `init_cache_db`.
    state_db: Option<Arc<crate::state::StateDb>>,
    state_tick: cache::StateTick,
    /// Features running reduced; shared with startup and the native API.
    degradations: Arc<crate::degradations::Degradations>,
    /// Built by `configure_health_loop`; a reload updates whether it is needed.
    quic_score_target: Option<Arc<probers::QuicScoreProbeTarget>>,
    /// Node name → eBPF outbound id (push_routing_to_ebpf numbering),
    /// shared with the alive set's outbound resolver; rebuilt on reload.
    outbound_id_map: Arc<parking_lot::RwLock<std::collections::HashMap<uuid::Uuid, u8>>>,
    resource_budget: ResourceBudget,
    concurrency_limit: Arc<tokio::sync::Semaphore>,
    tcp_admission_target: Arc<std::sync::atomic::AtomicUsize>,
    /// Cold non-DNS UDP initialization budget. Ready endpoints bypass it.
    udp_concurrency_limit: Arc<tokio::sync::Semaphore>,
    health_task: Option<tokio::task::JoinHandle<()>>,
    /// Generation-owned UDP warm coordinator, joined before transport retirement.
    udp_warm_task: tokio::sync::Mutex<Option<reload::WarmTask>>,
    /// UDP warm NodeIds survive task replacement so a reload can release
    /// retention that disappeared from the replacement plan.
    udp_warm_ids: Arc<parking_lot::Mutex<std::collections::HashSet<uuid::Uuid>>>,
    /// Generation-owned task that pins every Selector's configured leaf.
    selector_warm_task: tokio::sync::Mutex<Option<reload::WarmTask>>,
    /// Choice changes wake reconciliation immediately; a short periodic pass
    /// repairs sessions lost independently of group changes.
    selector_warm_notify: Arc<tokio::sync::Notify>,
    /// Desired selector NodeIds survive task replacement across reloads so
    /// reused runtimes can release choices that disappeared.
    selector_warm_ids: Arc<parking_lot::Mutex<std::collections::HashSet<uuid::Uuid>>>,
    /// Bare-TCP pins are userspace-pool resources rather than NodeRuntime
    /// state, so their addresses are tracked separately for exact cleanup.
    selector_bare_warm: Arc<parking_lot::Mutex<std::collections::HashMap<uuid::Uuid, String>>>,
    /// Startup mode snapshot shared by routing decisions and serialized flags updates.
    mode_state: Option<crate::mode::SharedModeState>,
    /// Sole writer for mode state and DATAPATH_FLAGS_MAP publication.
    datapath_flags: Option<crate::mode::DatapathFlagsHandle>,
    #[cfg(feature = "ebpf")]
    pending_udp_verdicts: Option<Arc<nfqueue::PendingUdpVerdicts>>,
    datapath_healthy: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(feature = "native-api")]
    phase: Option<tokio::sync::watch::Sender<EnginePhase>>,
    #[cfg(feature = "native-api")]
    configuration: Option<Arc<crate::configuration::AcceptedSources>>,
    native: Option<Arc<crate::observe::Observation>>,
    #[cfg(feature = "native-api")]
    native_owner: Option<Arc<dyn crate::observe::Owner>>,
    #[cfg(feature = "native-api")]
    subscriptions: Option<crate::subscription::SubscriptionSupervisorHandle>,
    shutdown_requested: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(feature = "clash-api")]
    ui_download: Arc<tokio::sync::Mutex<Option<crate::clash_api::ui::UiDownloadTask>>>,
    active_routing_plan: Arc<parking_lot::RwLock<Arc<routing_matcher::RoutingPushPlan>>>,
    #[cfg(feature = "reload-bench-counters")]
    reload_slow_path_entries: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    pre_dns_publication_hook: parking_lot::Mutex<Option<PreDnsPublicationHook>>,
    /// Interface watcher, stopped and joined before `detach_hooks` during
    /// shutdown so it cannot re-attach hooks mid-drain.
    #[cfg(feature = "ebpf")]
    iface_watcher: Option<crate::ebpf::real::IfaceWatcher>,
}

pub(crate) use udp_removal::spawn_udp_removal_worker;

impl ControlPlane {
    #[cfg(feature = "native-api")]
    pub(crate) fn observe_phase(&mut self) -> tokio::sync::watch::Receiver<EnginePhase> {
        self.phase
            .get_or_insert_with(|| tokio::sync::watch::channel(EnginePhase::Starting).0)
            .subscribe()
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn publish_phase(&self, phase: EnginePhase) {
        if let Some(native) = &self.native
            && phase == EnginePhase::Running
        {
            native.started(self.diagnostics.read().generation);
        }
        if let Some(sender) = &self.phase {
            sender.send_replace(phase);
        }
        if let Some(native) = &self.native {
            native
                .events
                .publish("runtime.updated", serde_json::json!({}), None);
        }
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn degradations_handle(&self) -> Arc<crate::degradations::Degradations> {
        Arc::clone(&self.degradations)
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn datapath_health_handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.datapath_healthy)
    }

    /// Install the startup mode snapshot before the flags writer starts.
    pub fn set_mode_state(&mut self, mode_state: crate::mode::SharedModeState) {
        assert!(
            self.datapath_flags.is_none(),
            "mode state cannot be replaced after datapath flags startup"
        );
        self.mode_state = Some(mode_state);
    }

    /// Install the serialized flags writer after cache-backed mode restoration.
    pub fn start_datapath_flags_coordinator(&mut self) -> anyhow::Result<()> {
        if self.datapath_flags.is_some() {
            anyhow::bail!("datapath flags writer already started");
        }
        let mode_state = self
            .mode_state
            .clone()
            .ok_or_else(|| anyhow::anyhow!("mode state is not initialized"))?;
        self.datapath_flags = Some(crate::mode::DatapathFlagsHandle::new(
            Arc::clone(&self.ebpf),
            mode_state,
            self.mode_db.clone(),
        ));
        Ok(())
    }

    pub fn datapath_flags_handle(&self) -> Option<crate::mode::DatapathFlagsHandle> {
        self.datapath_flags.clone()
    }

    async fn initialize_datapath_flags(
        &self,
        nfqueue_enabled: bool,
        nfqueue_ready: bool,
    ) -> anyhow::Result<()> {
        self.datapath_flags
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("datapath flags writer is not running"))?
            .initialize(nfqueue_enabled, nfqueue_ready)
            .await
    }

    pub fn diagnostics_handle(&self) -> crate::config_diagnostics::SharedDiagnostics {
        self.diagnostics.clone()
    }
    pub fn config_handle(&self) -> Arc<RwLock<Arc<Config>>> {
        self.config.clone()
    }
    #[cfg(feature = "native-api")]
    pub(crate) fn log_files(&self) -> LogFiles {
        self.log_files.clone()
    }

    pub(crate) async fn install_startup_diagnostics(
        &self,
        buckets: crate::config_diagnostics::DiagnosticBuckets,
    ) {
        let _config = self.config.write().await;
        self.diagnostics.write().buckets = buckets;
    }

    #[cfg(feature = "reload-bench-counters")]
    pub fn reload_slow_path_entries(&self) -> u64 {
        self.reload_slow_path_entries
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Shared backend cell, used by the interface watcher for dynamic attach.
    pub fn ebpf_handle(&self) -> Arc<RwLock<Box<dyn EbpfBackend>>> {
        self.ebpf.clone()
    }

    /// Hand the interface watcher to the control plane so shutdown can stop
    /// it before detaching hooks.
    #[cfg(feature = "ebpf")]
    pub fn set_iface_watcher(&mut self, watcher: Option<crate::ebpf::real::IfaceWatcher>) {
        self.iface_watcher = watcher;
    }

    pub fn stats_handle(&self) -> Arc<StatsManager> {
        self.stats.clone()
    }

    /// Shared connection pool (bare TCP + ready streams) for the clash
    /// API's pool metrics.
    pub fn connection_pool(&self) -> Arc<ConnectionPool> {
        self.connection_pool.clone()
    }

    pub fn alive_set(&self) -> Arc<crate::outbound::AliveDialerSet> {
        self.alive_set.clone()
    }

    pub fn group_manager(&self) -> SharedGroupManager {
        self.group_manager.clone()
    }

    /// Shared traffic router cell (same handle DNS dial uses for dae-style
    /// "route the DNS server IP" selection).
    pub fn traffic_router(&self) -> Arc<RwLock<Router>> {
        self.router.clone()
    }

    pub fn connection_tracker(&self) -> Arc<ConnectionTracker> {
        self.connection_tracker.clone()
    }

    pub fn proxy_registry(&self) -> Arc<ProxyRegistry> {
        self.proxy_registry.clone()
    }

    /// Shared per-node runtime registry (session-layer ownership).
    pub fn runtime_registry(&self) -> honk_outbound::runtime::SharedRuntimeRegistry {
        self.runtime_registry.clone()
    }

    pub fn dns_service(&self) -> crate::dns::DnsService {
        self.dns_controller.dns_service()
    }

    pub(crate) fn command_sender(&self) -> mpsc::Sender<ControlCommand> {
        self.command_tx.clone()
    }

    pub fn control_client(&self) -> ControlClient {
        ControlClient::new(self.command_sender())
    }

    #[cfg(feature = "clash-api")]
    pub fn ui_download_handle(
        &self,
    ) -> Arc<tokio::sync::Mutex<Option<crate::clash_api::ui::UiDownloadTask>>> {
        Arc::clone(&self.ui_download)
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn attach_subscriptions(
        &mut self,
        subscriptions: crate::subscription::SubscriptionSupervisorHandle,
    ) {
        self.subscriptions = Some(subscriptions);
    }

    pub(crate) fn shutdown_intent(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.shutdown_requested)
    }

    pub fn is_datapath_healthy(&self) -> bool {
        self.datapath_healthy
            .load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(feature = "reload-bench-counters")]
    #[doc(hidden)]
    pub fn reload_benchmark_dns_generation(&self) -> u64 {
        self.dns_controller
            .runtime_provider()
            .current_generation()
            .get()
    }
}

impl ControlPlane {
    pub(crate) fn compile_routing_plan(
        config: &Config,
        router: &Router,
    ) -> anyhow::Result<routing_matcher::RoutingPushPlan> {
        let mut outbound_name_to_id = std::collections::HashMap::new();
        outbound_name_to_id.insert("direct".into(), OutboundIndex::Direct as u8);
        outbound_name_to_id.insert("block".into(), OutboundIndex::Block as u8);
        anyhow::ensure!(
            config.groups.len()
                <= (OutboundIndex::MustRules as usize - OutboundIndex::UserBase as usize),
            "too many routing groups for the outbound index namespace"
        );
        for (i, group) in config.groups.iter().enumerate() {
            let id = OutboundIndex::UserBase as u8 + i as u8;
            outbound_name_to_id.insert(group.name.clone(), id);
        }

        let dial_mode = config
            .global
            .dial_mode
            .parse::<DialMode>()
            .map_err(|_| anyhow::anyhow!("invalid global.dial_mode"))?;
        let mut plan =
            routing_matcher::RoutingPushPlan::compile(router, &outbound_name_to_id, dial_mode)?;
        plan.enable_trace(
            cfg!(feature = "native-api")
                && config.experimental.native_api.enabled
                && config.experimental.native_api.record_flows,
        );
        // Witnesses of a policy without a dictionary could not be decoded.
        #[cfg(feature = "native-api")]
        if plan.trace_enabled()
            && !crate::observe::flows::kernel::KernelTraceDictionary::fits(router, config, &plan)
        {
            tracing::warn!(
                "routing policy too large for its kernel trace dictionary; kernel route tracing is off"
            );
            plan.enable_trace(false);
        }
        Ok(plan)
    }
}

/// direct probe target: the configured `bootstrap_resolver` (scheme
/// stripped), falling back to the built-in default when unset/invalid.
/// The bootstrap resolver is a plain directly-reachable DNS server, which
/// is exactly what a direct-egress health probe should measure.
pub(crate) fn direct_check_addr(bootstrap_resolver: &str) -> String {
    let s = bootstrap_resolver.trim();
    let s = s.split_once("://").map(|(_, rest)| rest).unwrap_or(s);
    if s.parse::<std::net::SocketAddr>().is_ok() {
        s.to_string()
    } else {
        crate::outbound::DEFAULT_DIRECT_CHECK_ADDR.to_string()
    }
}

#[cfg(test)]
use preconnect::preconnect_candidates;
