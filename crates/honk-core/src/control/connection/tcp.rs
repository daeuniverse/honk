use super::handoff::RetireAck;
use super::overall_dial_timeout;
use super::routing::{PacketRoutingSnapshot, build_connection_info, connection_chains};
use crate::control::dns_control::PacketDnsScopeRetired;
use crate::control::netstack::{AuxiliaryWork, FlowIo};
use crate::control::packet_endpoint::run_until_auxiliary_pause;
use crate::control::*;
use crate::group::{OwnedTarget, SelectionNetwork, SelectionPlanMode};

use futures::{
    FutureExt, StreamExt,
    future::{AbortRegistration, Abortable},
};
use std::collections::HashMap;

use crate::connection_tracker::{
    CloseAction, CloseCompletion, CloseSignal, ConnectionOwner, captured_groups,
};

use super::observation::{ConnectionObservation, RouteTraceSlot};

mod dial;
mod direct_relay;
mod input;
mod score;
mod terminal;
#[cfg(target_os = "linux")]
mod worker;

use direct_relay::{DirectRelay, RelayPublication};
use input::{TcpFlow, TcpInput};

use score::{
    tcp_relay_score_outcome, tcp_score_context, timeout_started_score_reporters,
    unpack_tcp_score_plan, wait_for_cold_urltest_release,
};
#[cfg(feature = "native-api")]
use terminal::TcpTerminal;
use terminal::{wait_for_close, write_sniff_prefix};

struct SniffPrefix {
    bytes: Vec<u8>,
    reporter: Option<crate::group::ScoreReporter>,
    #[cfg(feature = "native-api")]
    flow: Option<Arc<crate::observe::flows::FlowGuard>>,
}

enum RelayCompletion {
    Closed,
    PrefixFailed(std::io::Error),
    LocalError(std::io::Error),
    Relayed(anyhow::Result<relay::RelayStats>),
}

#[cfg(feature = "native-api")]
impl RelayCompletion {
    fn terminal(&self) -> TcpTerminal {
        match self {
            Self::Closed => TcpTerminal::IntentionalRetirement,
            Self::PrefixFailed(_) => TcpTerminal::PrefixWriteFailed,
            Self::LocalError(_) => TcpTerminal::ConnectionFailed,
            Self::Relayed(Ok(_)) => TcpTerminal::RelayClosed,
            Self::Relayed(Err(_)) => TcpTerminal::RelayFailed,
        }
    }
}

fn accepted_transfer(
    reporter: Option<&crate::group::ScoreReporter>,
    observation: &ConnectionObservation,
) -> Option<Arc<dyn Fn(u64, u64) + Send + Sync>> {
    let reporter = reporter.cloned();
    let flow = observation.flow().cloned();
    if reporter.is_none() && flow.is_none() {
        return None;
    }
    Some(Arc::new(move |upload, download| {
        if let Some(reporter) = &reporter {
            if upload != 0 {
                reporter.tx(upload);
            }
            if download != 0 {
                reporter.rx(download);
            }
        }
        if upload != 0
            && let Some(flow) = &flow
        {
            flow.accepted_send();
        }
    }))
}

async fn write_prefix(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin + ?Sized),
    prefix: &SniffPrefix,
    progress: &relay::RelayProgress,
    close: Option<&Arc<CloseSignal>>,
) -> Result<(), RelayCompletion> {
    tokio::select! {
        biased;
        _ = wait_for_close(close) => Err(RelayCompletion::Closed),
        result = write_sniff_prefix(stream, &prefix.bytes, |bytes| {
            use std::sync::atomic::Ordering::Relaxed;
            progress.upload.fetch_add(bytes as u64, Relaxed);
            if let Some(outbound) = &progress.outbound {
                outbound.tx_bytes.fetch_add(bytes as u64, Relaxed);
            }
            #[cfg(feature = "native-api")]
            if let Some(flow) = &prefix.flow {
                flow.accepted_send();
            }
            if let Some(reporter) = &prefix.reporter {
                reporter.tx(bytes as u64);
            }
        }) => result.map_err(RelayCompletion::PrefixFailed),
    }
}

/// Block nodes "dial" by failing and the dial path reports no other signal,
/// so a failure where every tried node is a block node is the policy's doing.
pub(super) fn only_block_nodes<'a>(nodes: impl IntoIterator<Item = &'a Node>) -> bool {
    nodes
        .into_iter()
        .all(|node| node.protocol() == honk_config::types::NodeProtocol::Block)
}

/// Whether a successful relay refills the pool for its target. A route's
/// streams come from its hops, so its leaf's pool gains nothing from it.
fn replenishes_pool(outbound_name: &str, target: &OwnedTarget) -> bool {
    !matches!(outbound_name, "direct" | "block") && target.route.is_none()
}

impl ControlPlaneHandle {
    /// Emergency probes to recover a group with no available candidate: its
    /// leaves (sub-group tags carry no probe state) and its exit, whose death
    /// empties the group too.
    pub(super) fn probe_unavailable_group(&self, group: &str) {
        let group_manager = self.group_manager.read().clone();
        for node in group_manager.leaf_nodes_in_group(group) {
            self.alive_set.notify_check_tcp(node.id);
        }
        if let Some(exit) = group_manager.group_exit(group)
            && self.alive_set.is_registered(exit)
        {
            self.alive_set.notify_check_tcp(exit);
        }
    }

    async fn pin_tcp_dns_route(
        &self,
        handoff: &super::handoff::HandoffResult,
        #[cfg(feature = "native-api")] record_route: bool,
    ) -> anyhow::Result<PacketRoutingSnapshot> {
        let config = self.config.read().await;
        let backend = self.ebpf.read().await;
        anyhow::ensure!(
            handoff.routing_generation != 0
                && handoff.routing_generation == backend.routing_policy_generation(),
            "TCP DNS routing generation is stale"
        );
        let outbound = if handoff.outbound == OutboundIndex::Direct as u8 {
            "direct".to_owned()
        } else {
            handoff
                .outbound
                .checked_sub(OutboundIndex::UserBase as u8)
                .filter(|_| handoff.outbound < OutboundIndex::MustRules as u8)
                .and_then(|index| config.groups.get(index as usize))
                .ok_or_else(|| anyhow::anyhow!("invalid terminal TCP DNS outbound"))?
                .name
                .clone()
        };
        let decision = super::routing::RoutingDecision {
            outbound,
            must: true,
            mark: (handoff.mark != 0).then_some(handoff.mark),
            matched_rule: None,
            reroute_by_sniffed_domain: false,
            native_route: RouteTraceSlot::kernel(
                #[cfg(feature = "native-api")]
                record_route,
            ),
        };
        drop(backend);
        Ok(PacketRoutingSnapshot {
            source: None,
            source_mac: None,
            process: None,
            mode: super::handoff::ModeDecision {
                name: decision.outbound.clone(),
                constraint: Default::default(),
                #[cfg(feature = "native-api")]
                group_id: None,
            },
            mode_state: None,
            admission_final: true,
            memory: None,
            decision,
            config: Arc::clone(&config),
            group_manager: self.group_manager.read().clone(),
            runtime: self.runtime_registry.read().clone(),
            #[cfg(feature = "native-api")]
            native: self.native.as_ref().map(|native| {
                (
                    self.diagnostics.read().generation,
                    native.catalog.snapshot(),
                )
            }),
        })
    }

    pub(in crate::control) async fn serve_connection(
        &self,
        stream: TcpStream,
        client_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        debug!("TPROXY TCP connection from {}", client_addr);

        let original_dst = match get_original_dst(&stream) {
            Ok(d) => d,
            Err(e) => {
                // When the eBPF datapath delivers the SYN directly with
                // bpf_sk_assign(), the kernel does not set SO_ORIGINAL_DST.
                // The transparent socket's local address is the original
                // destination, so fall back to that.
                match stream.local_addr() {
                    Ok(d) => {
                        trace!(
                            "SO_ORIGINAL_DST unavailable for {} ({}); using local_addr {}",
                            client_addr, e, d
                        );
                        d
                    }
                    Err(le) => {
                        debug!(
                            "Failed to get original destination for {}: {}; local_addr also failed: {}",
                            client_addr, e, le
                        );
                        return Err(anyhow::anyhow!(
                            "original destination unavailable for {}: {} (local_addr: {})",
                            client_addr,
                            e,
                            le
                        ));
                    }
                }
            }
        };
        debug!("Original destination: {}", original_dst);
        self.serve_tcp_input(
            TcpInput::Kernel(stream),
            client_addr,
            original_dst,
            None,
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .await
    }

    pub(in crate::control) async fn serve_packet_connection(
        &self,
        stream: FlowIo,
    ) -> anyhow::Result<()> {
        let client = stream.peer_addr();
        let destination = stream.local_addr();
        self.serve_tcp_input(
            TcpInput::Packet(stream),
            client,
            destination,
            None,
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .await
    }

    pub(in crate::control) async fn serve_auxiliary_packet_connection(
        &self,
        stream: FlowIo,
        binding: &AuxiliaryWork,
        cancel: AbortRegistration,
    ) -> anyhow::Result<()> {
        if !binding.is_active() {
            return Ok(());
        }
        let client = stream.peer_addr();
        let destination = stream.local_addr();
        self.serve_tcp_input(
            TcpInput::Packet(stream),
            client,
            destination,
            None,
            Some((binding, cancel)),
            #[cfg(target_os = "linux")]
            None,
        )
        .await
    }

    pub(in crate::control) async fn serve_owned_packet_connection(
        &self,
        stream: FlowIo,
        (owner, credit): (
            crate::control::netstack::DirectRelayOwner,
            honk_netstack::MemoryReservation,
        ),
        cancel: AbortRegistration,
    ) -> anyhow::Result<()> {
        let client = stream.peer_addr();
        let destination = stream.local_addr();
        let publication = RelayPublication::default();
        let mut relay = DirectRelay::new(owner.runtime, &publication, &owner.fence);
        let result = std::panic::AssertUnwindSafe(async {
            let mut operation = std::pin::pin!(self.serve_tcp_input(
                TcpInput::Packet(stream),
                client,
                destination,
                Some((&mut relay, credit)),
                None,
                #[cfg(target_os = "linux")]
                None,
            ));
            let mut stop = std::pin::pin!(Abortable::new(std::future::pending::<()>(), cancel));
            let mut stopping = false;
            std::future::poll_fn(|cx| {
                if !stopping && stop.as_mut().poll(cx).is_ready() {
                    stopping = true;
                    if !publication.cancel_active() {
                        return std::task::Poll::Ready(Ok(()));
                    }
                }
                // A completed owner may have won the abort. Let the original caller settle
                // that result before cancelling its next wait (usually exact retirement).
                let result = operation.as_mut().poll(cx);
                if stopping && result.is_pending() && !publication.active() {
                    std::task::Poll::Ready(Ok(()))
                } else {
                    result
                }
            })
            .await
        })
        .catch_unwind()
        .await;
        // Even an unwind or logical abort must join the original remote socket owner.
        relay.cancel_and_join().await;
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    async fn serve_tcp_input(
        &self,
        mut input: TcpInput,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
        direct: Option<(&mut DirectRelay<'_>, honk_netstack::MemoryReservation)>,
        auxiliary: Option<(&AuxiliaryWork, AbortRegistration)>,
        #[cfg(target_os = "linux")] mut worker: Option<&mut worker::WorkerTcp<'_>>,
    ) -> anyhow::Result<()> {
        let (direct, credit) = direct.unzip();
        #[cfg(target_os = "linux")]
        let credit = credit.or_else(|| {
            worker
                .as_deref_mut()
                .and_then(|worker| worker.completion_credit.take())
        });
        let (auxiliary, task_cancel) = auxiliary.unzip();
        let (admitted_route, packet_scope, packet_dscp, gateway_process) = match &mut input {
            TcpInput::Packet(stream) => (
                stream.take_routing(),
                Some(stream.scope()),
                Some(stream.dscp()),
                stream.process(),
            ),
            TcpInput::Kernel(_) => (None, None, None, None),
        };
        let mut observation = ConnectionObservation::begin_in(
            self.native.as_deref(),
            crate::observe::vocab::Network::Tcp,
            client_addr,
            original_dst,
            #[cfg(feature = "native-api")]
            match &input {
                TcpInput::Packet(stream) => Some(stream.memory_budget()),
                TcpInput::Kernel(_) => None,
            },
        )?;
        #[cfg(feature = "native-api")]
        let native_observer = observation.flow().and_then(|flow| {
            flow.observer(self.diagnostics.read().generation, None, "dial_target")
        });
        #[cfg(feature = "native-api")]
        let mut terminal = None;
        let mut close = self
            .connection_tracker
            .is_enabled()
            .then(|| CloseCompletion(CloseSignal::new()));
        let close_signal = close.as_ref().map(|close| Arc::clone(&close.0));
        let result = {
            let operation = async {
                let (mut flow, mut handoff) = match input {
                    TcpInput::Kernel(stream) => {
                        let tuples = build_tuples_key(
                            original_dst.ip(),
                            original_dst.port(),
                            client_addr.ip(),
                            client_addr.port(),
                            6,
                        );
                        let (flow, handoff) = self
                            .adopt_tcp_flow(
                                stream,
                                tuples,
                                #[cfg(feature = "native-api")]
                                &observation,
                            )
                            .await?;
                        (TcpFlow::Kernel(flow), handoff)
                    }
                    TcpInput::Packet(stream) => (
                        TcpFlow::packet(stream, Arc::clone(&self.connection_tracker)),
                        None,
                    ),
                };
                #[cfg(target_os = "linux")]
                if let Some(local) = flow.local() {
                    local.wait_established().await?;
                }
                let packet_input = gateway_process.map(|process| (process, None)).or_else(|| {
                    flow.packet_source()
                        .and_then(|source| source.packet_input())
                });
                if let Some((process, mark)) = packet_input {
                    observation.packet_facts(
                        process,
                        packet_dscp.expect("packet stream carries admitted DSCP"),
                        mark,
                    );
                }
                if flow.is_kernel() {
                    observation.handoff(handoff.as_mut(), true);
                }
                observation.routing_started();

                let pinned_route = if !flow.is_kernel() {
                    Some(match admitted_route {
                        Some(snapshot) => snapshot,
                        None => {
                            self.prepare_packet_routing_snapshot(
                                packet_scope.expect("packet stream carries its scope"),
                                client_addr,
                                original_dst,
                                "tcp",
                                packet_dscp.expect("packet stream carries admitted DSCP"),
                                flow.packet_source(),
                                gateway_process,
                                #[cfg(feature = "native-api")]
                                (observation.is_recording(), flow.packet_memory_budget()),
                            )
                            .await?
                        }
                    })
                } else if original_dst.port() == 53 {
                    let handoff = handoff.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("transparent TCP DNS has no routing handoff")
                    })?;
                    if handoff.outbound != OutboundIndex::Block as u8 && handoff.must != 0 {
                        Some(
                            self.pin_tcp_dns_route(
                                handoff,
                                #[cfg(feature = "native-api")]
                                observation.is_recording(),
                            )
                            .await?,
                        )
                    } else {
                        None
                    }
                } else {
                    None
                };
                if !flow.is_kernel()
                    && let Some(snapshot) = &pinned_route
                {
                    anyhow::ensure!(
                        snapshot.source
                            == flow
                                .packet_source()
                                .and_then(|source| source.optional_context()),
                        "packet TCP routing source changed"
                    );
                }
                if original_dst.port() == 53
                    && !pinned_route
                        .as_ref()
                        .is_some_and(|route| route.decision.must || route.mode.name == "block")
                    && !handoff
                        .as_ref()
                        .is_some_and(|handoff| handoff.outbound == OutboundIndex::Block as u8)
                {
                    #[cfg(target_os = "linux")]
                    if let Some(worker) = worker.as_deref_mut() {
                        worker.release_copy_credit();
                    }
                    flow.serve_dns(&self.dns_controller, client_addr, original_dst)
                        .await?;
                    #[cfg(feature = "native-api")]
                    {
                        terminal = Some(TcpTerminal::DnsInterceptCompleted);
                    }
                    anyhow::ensure!(
                        flow.retire(
                            RetireAck {
                                close: close.take(),
                                outbound: None
                            },
                            credit
                        )
                        .await,
                        "TCP DNS retirement failed"
                    );
                    return Ok(());
                }

                let (dial_mode, connect_timeout, overall_dial_timeout) = {
                    let current_config;
                    let config = if let Some(snapshot) = &pinned_route {
                        &snapshot.config
                    } else {
                        current_config = self.config.read().await;
                        &*current_config
                    };
                    #[cfg(feature = "native-api")]
                    {
                        observation.pin_dial_mode(if let Some(snapshot) = &pinned_route {
                            snapshot.native.as_ref().map(|(generation, _)| *generation)
                        } else {
                            observation
                                .is_recording()
                                .then(|| self.diagnostics.read().generation)
                        });
                    }
                    let connect_timeout = Duration::from_millis(config.global.connect_timeout_ms);
                    (
                        config
                            .global
                            .dial_mode
                            .parse::<DialMode>()
                            .map_err(|_| anyhow::anyhow!("invalid global.dial_mode"))?,
                        connect_timeout,
                        overall_dial_timeout(connect_timeout),
                    )
                };

                // Skip sniffing when the datapath already made a final decision.
                // In ip mode we always dial by original_dst.
                let mut skip_sniff = matches!(dial_mode, DialMode::Ip);
                skip_sniff |= pinned_route
                    .as_ref()
                    .is_some_and(|route| route.final_before_sniff());
                if let Some(ref ho) = handoff {
                    let final_handoff = matches!(
                        ho.outbound,
                        x if x == OutboundIndex::Direct as u8
                            || x == OutboundIndex::Block as u8
                            || x == OutboundIndex::MustRules as u8
                    ) || (ho.must != 0
                        && ho.outbound != OutboundIndex::ControlPlaneRouting as u8);
                    if !skip_sniff && final_handoff {
                        debug!(
                            "Skip TCP sniffing by final eBPF handoff for {} (outbound={})",
                            original_dst, ho.outbound
                        );
                        skip_sniff = true;
                    }
                    let cache_key = (original_dst, ho.outbound);
                    let now = std::time::Instant::now();
                    if !skip_sniff && self.tcp_sniff_neg_cache.should_skip_sniff(&cache_key, now) {
                        debug!("Skip TCP sniffing by negative cache for {}", original_dst);
                        skip_sniff = true;
                    }
                }

                let sniff_result = if skip_sniff {
                    sniffing::SniffResult::unknown()
                } else {
                    flow.sniff().await?
                };
                if auxiliary.is_some_and(|binding| !binding.is_active()) {
                    return Ok(());
                }
                let sniffed_domain = sniff_result.domain.clone();
                if let Some(ref domain) = sniffed_domain {
                    debug!("SNI sniffed domain: {}", domain);
                }
                observation.tcp_sniffed(&sniff_result, handoff.as_ref());
                let (domain, domain_verified, domain_verification) = self
                    .apply_domain_reality_check(
                        dial_mode,
                        sniffed_domain,
                        original_dst.ip(),
                        client_addr,
                    )
                    .await;

                if !skip_sniff && let Some(ref ho) = handoff {
                    let cache_key = (original_dst, ho.outbound);
                    let now = std::time::Instant::now();
                    if domain.is_some() {
                        self.tcp_sniff_neg_cache.clear_sniff_negative(&cache_key);
                    } else {
                        self.tcp_sniff_neg_cache.note_sniff_failure(cache_key, now);
                    }
                }

                let mut conn_info = build_connection_info(
                    domain.clone(),
                    original_dst,
                    client_addr,
                    "tcp",
                    handoff.as_ref(),
                );
                if let Some(dscp) = packet_dscp {
                    conn_info.dscp = Some(dscp);
                }
                #[cfg(feature = "native-api")]
                let mut pinned_native = pinned_route
                    .as_ref()
                    .and_then(|snapshot| snapshot.native.clone());
                let mut admitted_mode = None;
                let mut _routing_memory = None;
                let (mut route, pinned_generation) = if let Some(mut snapshot) = pinned_route {
                    if !flow.is_kernel() {
                        self.route_packet_with_sniffed(
                            &mut snapshot,
                            dial_mode,
                            &conn_info,
                            domain_verified,
                            #[cfg(feature = "native-api")]
                            (observation.is_recording(), flow.packet_memory_budget()),
                        )
                        .await?;
                    }
                    admitted_mode = Some(snapshot.mode);
                    _routing_memory = snapshot.memory;
                    (
                        snapshot.decision,
                        Some((snapshot.config, snapshot.group_manager, snapshot.runtime)),
                    )
                } else {
                    (
                        self.prepare_routing(
                            dial_mode,
                            &conn_info,
                            domain_verified,
                            handoff.as_ref(),
                            None,
                            #[cfg(feature = "native-api")]
                            observation.is_recording(),
                        )
                        .await,
                        None,
                    )
                };
                observation.routed(&mut route);
                let reroute_by_sniffed_domain = route.reroute_by_sniffed_domain;
                let matched_rule = route.matched_rule.take();
                let mode_decision = if let Some(mode) = admitted_mode {
                    route.apply_final_outbound(Some(mode.name.clone()));
                    mode
                } else {
                    self.apply_mode_override(&mut route, OutboundConstraint::Any)
                        .await
                };
                anyhow::ensure!(
                    route
                        .mark
                        .is_none_or(|mark| !honk_ebpf_common::skb_mark_has_reserved_bits(mark)),
                    "direct rule mark uses a reserved datapath bit"
                );
                let outbound_name = mode_decision.name;
                let mode_constraint = mode_decision.constraint;
                observation.mode_applied(&outbound_name);

                // Seed current predicate facts so later flows need not repeat sniffing.
                if flow.is_kernel()
                    && let Some(domain) = &domain
                    && Self::should_write_sniffed_domain_bitmap(
                        handoff.as_ref(),
                        reroute_by_sniffed_domain,
                    )
                {
                    self.push_sniffed_domain_bitmap(domain, original_dst.ip())
                        .await;
                }

                let ipver = if original_dst.is_ipv6() {
                    IpVersion::V6
                } else {
                    IpVersion::V4
                };
                let (generation_config, generation_group_manager, runtime_generation) =
                    if let Some(snapshot) = pinned_generation {
                        snapshot
                    } else {
                        // Config's publication guard pins the group and runtime handles.
                        let config = self.config.read().await;
                        #[cfg(feature = "native-api")]
                        if observation.is_recording()
                            || close.is_some()
                            || mode_decision.group_id.is_some()
                        {
                            pinned_native = self.native.as_ref().map(|native| {
                                (
                                    self.diagnostics.read().generation,
                                    native.catalog.snapshot(),
                                )
                            });
                        }
                        (
                            Arc::clone(&config),
                            self.group_manager.read().clone(),
                            self.runtime_registry.read().clone(),
                        )
                    };
                #[cfg(feature = "native-api")]
                let mode_constraint = if mode_decision.group_id.as_ref().is_some_and(|expected| {
                    pinned_native
                        .as_ref()
                        .and_then(|(_, catalog)| catalog.groups.get(&outbound_name))
                        != Some(expected)
                }) {
                    crate::control::reload::OutboundConstraint::Unavailable
                } else {
                    mode_constraint
                };
                let outbound_kind =
                    crate::stats::OutboundKind::routed(&generation_group_manager, &outbound_name);
                let mut outbound_guard =
                    Some(self.stats.track_connection(&outbound_name, outbound_kind));
                flow.hold_packet_completion(&mut close, &mut outbound_guard, credit)?;
                #[cfg(feature = "native-api")]
                let close_catalog = pinned_native
                    .as_ref()
                    .map(|(_, catalog)| Arc::clone(catalog));
                #[cfg(feature = "native-api")]
                if let Some((generation, catalog)) = &pinned_native {
                    observation.pin_selection(*generation, catalog, &generation_config);
                }
                let selection_observer = observation.selection_observer();
                let (
                    mut candidates,
                    selection_mode,
                    mut score_feedback,
                    mut selection_chains,
                    final_owners,
                    health_ipver,
                    route_revision,
                ) = {
                    let context = tcp_score_context(original_dst, domain.as_deref(), ipver);
                    let select = || {
                        crate::control::reload::resolve_outbound_plan_for_target(
                            &generation_config,
                            &generation_group_manager,
                            &outbound_name,
                            &context,
                            mode_constraint,
                        )
                    };
                    let plan = observation.observe_tcp_plan(selection_observer.as_ref(), select);
                    unpack_tcp_score_plan(plan)
                };
                // Only an unmeasured URLTest group is allowed to speculate. Its
                // candidate set is bounded before spawning so a large group cannot
                // turn one client flow into an unbounded dial storm.
                if selection_mode == SelectionPlanMode::ColdUrlTest {
                    candidates.truncate(3);
                } else {
                    candidates.truncate(1);
                }
                score_feedback
                    .retain(|key, _| candidates.iter().any(|target| target.key() == *key));

                if candidates.is_empty() {
                    observation.tcp_dial_mode(
                        dial_mode,
                        &sniff_result,
                        domain_verification,
                        &candidates,
                        None,
                    );
                    debug!(
                        "No available candidate nodes for outbound '{}' ({})",
                        outbound_name, client_addr
                    );
                    self.probe_unavailable_group(&outbound_name);
                    self.stats.record_error(&outbound_name, outbound_kind);
                    drop(outbound_guard);
                    #[cfg(feature = "native-api")]
                    {
                        terminal = Some(TcpTerminal::NoAvailableNodes);
                    }
                    return Ok(());
                }
                // Domain targets are meaningful only for non-reserved proxy
                // outbounds. Direct and block always use the original IP.
                let target_domain = if matches!(
                    outbound_name.as_str(),
                    "direct" | "block" | "must_rules" | "control_plane_routing"
                ) {
                    None
                } else {
                    domain.clone()
                };
                observation.tcp_dial_mode(
                    dial_mode,
                    &sniff_result,
                    domain_verification,
                    &candidates,
                    target_domain.as_deref(),
                );

                let cold_urltest = selection_mode == SelectionPlanMode::ColdUrlTest;
                let candidate_refs: Vec<&OwnedTarget> = candidates.iter().collect();
                if let Some(flow) = observation.flow() {
                    flow.transition(
                        crate::observe::vocab::ConnectionState::Dialing,
                        "tcp_dial_started",
                        crate::observe::vocab::ConnectionMilestone::Unknown,
                        Some(false),
                    );
                }
                let dial_deadline = tokio::time::Instant::now() + overall_dial_timeout;
                let raced = self
                    .race_candidates(
                        &candidate_refs,
                        original_dst,
                        target_domain.clone(),
                        &outbound_name,
                        outbound_kind,
                        route.mark.and_then(honk_outbound::proxy::DirectMark::new),
                        connect_timeout,
                        dial_deadline,
                        Arc::clone(&runtime_generation),
                        &generation_group_manager,
                        health_ipver,
                        route_revision,
                        &score_feedback,
                        cold_urltest,
                        #[cfg(feature = "native-api")]
                        &selection_chains,
                        #[cfg(feature = "native-api")]
                        &observation,
                    )
                    .await;
                let original = if matches!(&raced, Ok(None))
                    && selection_mode == SelectionPlanMode::Authoritative
                    && candidates.len() == 1
                    && !runtime_generation.is_shutdown()
                {
                    // A deadline can expire before the primary begins any work.
                    score_feedback
                        .get(&candidates[0].key())
                        .and_then(|attempt| attempt.continuation().ok())
                } else {
                    None
                };
                drop(score_feedback);
                let winner = match raced {
                    Ok(Some(pair)) => pair,
                    Err(error) => {
                        drop(outbound_guard);
                        return Err(error);
                    }
                    Ok(None) => {
                        let mut retried = None;
                        if selection_mode == SelectionPlanMode::Authoritative
                            && candidates.len() == 1
                            && matches!(
                                mode_constraint,
                                crate::control::reload::OutboundConstraint::Any
                            )
                            && !runtime_generation.is_shutdown()
                        {
                            // A Score retry excludes the failed route's leaf.
                            let failed_node = candidates[0].node.id;
                            let failed_key = candidates[0].key();
                            let context = tcp_score_context(
                                original_dst,
                                target_domain.as_deref(),
                                health_ipver,
                            );
                            let select = || {
                                crate::control::reload::resolve_urltest_retry_plan_for_target(
                                    &generation_group_manager,
                                    &outbound_name,
                                    &context,
                                    original.as_ref(),
                                )
                            };
                            let mut plan =
                                observation.observe_tcp_plan(selection_observer.as_ref(), select);
                            let urltest_retry = !plan.targets.is_empty();
                            // URLTest retains its existing fresh retry-round budget.
                            let mut retry_deadline =
                                tokio::time::Instant::now() + overall_dial_timeout;
                            if !urltest_retry
                                && let Some(original) = original.as_ref()
                                && tokio::time::Instant::now() < dial_deadline
                            {
                                let select = || {
                                    crate::control::reload::resolve_score_retry_plan_for_target(
                                        &generation_group_manager,
                                        &outbound_name,
                                        &context,
                                        failed_node,
                                        final_owners
                                            .get(&failed_key)
                                            .map(Vec::as_slice)
                                            .unwrap_or_default(),
                                        original,
                                    )
                                };
                                plan = observation
                                    .observe_tcp_plan(selection_observer.as_ref(), select);
                                retry_deadline = dial_deadline;
                            }
                            let (
                                retry_nodes,
                                _,
                                mut retry_feedback,
                                retry_chains,
                                _,
                                retry_health_ipver,
                                retry_route_revision,
                            ) = unpack_tcp_score_plan(plan);
                            if retry_nodes.len() > 1
                                || retry_nodes.first().is_some_and(|target| {
                                    if urltest_retry {
                                        target.key() != failed_key
                                    } else {
                                        target.node.id != failed_node
                                    }
                                })
                            {
                                let nodes: Vec<_> = retry_nodes.iter().take(3).collect();
                                retry_feedback.retain(|key, _| {
                                    nodes.iter().any(|target| target.key() == *key)
                                });
                                retried = match self
                                    .race_candidates(
                                        &nodes,
                                        original_dst,
                                        target_domain.clone(),
                                        &outbound_name,
                                        outbound_kind,
                                        route.mark.and_then(honk_outbound::proxy::DirectMark::new),
                                        connect_timeout,
                                        retry_deadline,
                                        Arc::clone(&runtime_generation),
                                        &generation_group_manager,
                                        retry_health_ipver,
                                        retry_route_revision,
                                        &retry_feedback,
                                        false,
                                        #[cfg(feature = "native-api")]
                                        &retry_chains,
                                        #[cfg(feature = "native-api")]
                                        &observation,
                                    )
                                    .await
                                {
                                    Ok(retry) => retry,
                                    Err(error) => {
                                        drop(outbound_guard);
                                        return Err(error);
                                    }
                                };
                                #[cfg(feature = "native-api")]
                                if retried.is_none()
                                    && only_block_nodes(nodes.iter().map(|target| &target.node))
                                {
                                    terminal = Some(TcpTerminal::PolicyBlock);
                                }
                                if retried.is_some() {
                                    selection_chains = retry_chains;
                                }
                            }
                        }
                        match retried {
                            Some(pair) => pair,
                            None => {
                                drop(outbound_guard);
                                #[cfg(feature = "native-api")]
                                if terminal.is_none() {
                                    terminal = Some(
                                        if outbound_name == "block"
                                            || only_block_nodes(
                                                candidates.iter().map(|target| &target.node),
                                            )
                                        {
                                            TcpTerminal::PolicyBlock
                                        } else {
                                            TcpTerminal::DialFailed
                                        },
                                    );
                                }
                                return Ok(());
                            }
                        }
                    }
                };
                let proxy_stream = winner.stream;
                #[cfg(target_os = "linux")]
                let mut proxy_stream = proxy_stream;
                let target = winner.target;
                let node = &target.node;
                let score_reporter = winner.reporter;
                let route_traffic = winner.route_traffic;
                if node.protocol() != honk_config::types::NodeProtocol::Block {
                    flow.mark_packet_rx_admitted();
                }
                #[cfg(feature = "native-api")]
                let attempt_id = winner.attempt_id;
                #[cfg(feature = "native-api")]
                let winner_observer = winner.observer;
                #[cfg(feature = "native-api")]
                {
                    if let Some(flow) = observation.flow()
                        && let Some(attempt_id) = attempt_id
                    {
                        flow.select_attempt(&attempt_id.to_string());
                    }
                    observation.tcp_connected(
                        selection_chains
                            .get(&target.key())
                            .map(Vec::as_slice)
                            .unwrap_or_default(),
                        &target,
                    );
                    observation.release_selection();
                }

                let dscp_val = handoff.as_ref().map(|ho| ho.dscp);

                let conn_upload = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let conn_download = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let outbound = self.stats.outbound_tracker(&outbound_name, outbound_kind);
                if let Some(close) = &close_signal {
                    let groups = captured_groups(
                        selection_chains
                            .get(&target.key())
                            .map(Vec::as_slice)
                            .unwrap_or_default(),
                        target.selected_member().1,
                        &generation_config,
                        {
                            #[cfg(feature = "native-api")]
                            {
                                close_catalog.as_ref().map(|catalog| &catalog.groups)
                            }
                            #[cfg(not(feature = "native-api"))]
                            {
                                None
                            }
                        },
                    );
                    if let Some(conn_id) = flow.track_if_enabled(
                        |id| {
                            let (rule, rule_payload) = matched_rule
                                .unwrap_or_else(|| ("Fallback".to_string(), String::new()));
                            crate::connection_tracker::ConnectionEntry {
                                id,
                                source: client_addr,
                                destination: original_dst,
                                proxy: node.name.clone(),
                                #[cfg(feature = "native-api")]
                                routed_outbound: self
                                    .connection_tracker
                                    .native_enabled()
                                    .then(|| outbound_name.clone()),
                                #[cfg(feature = "native-api")]
                                native_flow_id: observation.flow().map(|flow| flow.id().to_owned()),
                                rule,
                                rule_payload,
                                chains: connection_chains(
                                    selection_chains.remove(&target.key()).unwrap_or_default(),
                                    node,
                                    target.hop_names(),
                                    target.collapse == crate::group::ExitCollapse::Direct,
                                ),
                                upload: conn_upload.clone(),
                                download: conn_download.clone(),
                                start_time: std::time::Instant::now(),
                                domain: target_domain.clone(),
                                network: "tcp",
                                process: match packet_input {
                                    Some((process, _)) => process.name(),
                                    None => handoff.as_ref().and_then(|ho| ho.process_name()),
                                },
                                process_path: None,
                            }
                        },
                        ConnectionOwner {
                            signal: Arc::clone(close),
                            action: CloseAction::Tcp,
                            groups,
                        },
                    ) {
                        if let Some(native) = observation.flow() {
                            native.attach_connection(
                                conn_id
                                    .as_hyphenated()
                                    .encode_lower(&mut uuid::Uuid::encode_buffer()),
                            );
                        }
                        self.spawn_process_path_enrichment(conn_id, handoff.as_ref());
                    }
                }

                debug!(
                    network = "tcp",
                    outbound = %outbound_name,
                    dialer = %node.name,
                    sniffed = target_domain.as_deref().unwrap_or(""),
                    ip = %original_dst,
                    dscp = ?dscp_val,
                    src = %client_addr,
                    "TCP connection: {} <-> {}", client_addr, original_dst,
                );

                let has_direct_owner = direct.is_some();
                #[cfg(target_os = "linux")]
                let has_direct_owner = has_direct_owner || worker.is_some();
                let handoff_direct = has_direct_owner
                    && self
                        .proxy_registry
                        .can_handoff_packet_direct(&runtime_generation, &target);
                let mut conn_progress = relay::RelayProgress {
                    upload: conn_upload,
                    download: conn_download,
                    outbound: Some(outbound),
                    first_response: None,
                    on_transfer: None,
                };
                #[cfg(target_os = "linux")]
                let mut direct_fallback = None;
                #[cfg(target_os = "linux")]
                if let Some(worker) = worker.as_deref_mut().filter(|_| {
                    handoff_direct && proxy_stream.stream.as_ref().as_any().is::<TcpStream>()
                }) {
                    let local = flow.local().expect("worker Direct requires a local flow");
                    match worker::start_direct(
                        local,
                        proxy_stream,
                        &conn_progress,
                        score_reporter.is_some() || observation.flow().is_some(),
                        close_signal.as_ref(),
                    ) {
                        Ok(worker::DirectStart::Submitted(observer, credit)) => {
                            let job = worker::WorkerDirect {
                                flow,
                                observer,
                                close: close_signal.clone(),
                                score: score_reporter,
                                observation: std::mem::take(&mut observation),
                                #[cfg(feature = "native-api")]
                                relay_observer: winner_observer,
                                stats: Arc::clone(&self.stats),
                                outbound: (outbound_name, outbound_kind),
                                endpoints: (client_addr, original_dst),
                            };
                            return worker.complete_on_worker(job, credit);
                        }
                        Ok(worker::DirectStart::Remote(proxy)) => {
                            proxy_stream = proxy;
                            direct_fallback = Some(input::DirectFallback::new(&self.stats));
                        }
                        Ok(worker::DirectStart::Closed) => {
                            if let Some(score) = &score_reporter {
                                score.finish(crate::group::ScoreOutcome::Cancelled);
                            }
                            anyhow::ensure!(
                                flow.retire(
                                    RetireAck {
                                        close: None,
                                        outbound: None
                                    },
                                    None
                                )
                                .await,
                                "TCP retirement failed"
                            );
                            #[cfg(feature = "native-api")]
                            {
                                terminal = Some(TcpTerminal::IntentionalRetirement);
                            }
                            return Ok(());
                        }
                        Err(error) => {
                            if let Some(score) = &score_reporter {
                                score.finish(crate::group::ScoreOutcome::Rejected);
                            }
                            return Err(
                                anyhow::Error::new(error).context("attaching packet Direct socket")
                            );
                        }
                    }
                }

                let has_prefix = !sniff_result.buffered.is_empty();
                let prefix = SniffPrefix {
                    bytes: sniff_result.buffered,
                    reporter: score_reporter.as_ref().filter(|_| has_prefix).cloned(),
                    #[cfg(feature = "native-api")]
                    flow: observation.flow().filter(|_| has_prefix).cloned(),
                };

                let first_response = if let Some(traffic) =
                    route_traffic.filter(|traffic| !traffic.confirmed)
                {
                    let reporter = score_reporter.clone();
                    let manager = Arc::clone(&generation_group_manager);
                    let generation = Arc::clone(&runtime_generation);
                    let group = outbound_name.clone();
                    let key = target.key();
                    Some(Arc::new(move || {
                        if !generation.is_shutdown() {
                            manager.report_route_response(
                                &group,
                                key,
                                traffic.family,
                                traffic.stamp,
                                traffic.latency,
                            );
                        }
                        if let Some(reporter) = &reporter {
                            reporter.first_response();
                        }
                    }) as Arc<dyn Fn() + Send + Sync>)
                } else {
                    score_reporter.as_ref().map(|reporter| {
                        let reporter = reporter.clone();
                        Arc::new(move || reporter.first_response()) as Arc<dyn Fn() + Send + Sync>
                    })
                };
                conn_progress.first_response = observation.first_response(first_response);
                conn_progress.on_transfer =
                    accepted_transfer(score_reporter.as_ref(), &observation);
                let direct = direct.filter(|_| handoff_direct);
                #[cfg(target_os = "linux")]
                let remote =
                    worker.map(|worker| worker.remote(score_reporter.as_ref(), direct_fallback));
                let Some((flow, relay_result)) = flow
                    .relay_owned(
                        direct,
                        proxy_stream,
                        client_addr,
                        original_dst,
                        conn_progress,
                        prefix,
                        close_signal.as_ref(),
                        #[cfg(target_os = "linux")]
                        remote,
                        #[cfg(feature = "native-api")]
                        winner_observer.as_ref(),
                    )
                    .await
                else {
                    return Ok(());
                };
                // The relay can observe a local stream reset during the cancellation poll.
                if auxiliary.is_some_and(|binding| !binding.is_active()) {
                    return Ok(());
                }
                #[cfg(feature = "native-api")]
                {
                    terminal = Some(relay_result.terminal());
                }
                let relay_succeeded = matches!(&relay_result, RelayCompletion::Relayed(Ok(_)));
                match relay_result {
                    RelayCompletion::Closed => {
                        if let Some(reporter) = &score_reporter {
                            reporter.finish(crate::group::ScoreOutcome::Cancelled);
                        }
                    }
                    RelayCompletion::LocalError(error) => {
                        if let Some(reporter) = &score_reporter {
                            reporter.finish(crate::group::ScoreOutcome::Rejected);
                        }
                        return Err(anyhow::Error::new(error)
                            .context("moving Direct TCP socket between reactors"));
                    }
                    RelayCompletion::PrefixFailed(error) => {
                        debug!(%error, "Failed to write sniffed bytes to proxy");
                        self.stats.record_error(&outbound_name, outbound_kind);
                        if let Some(traffic) = route_traffic
                            && !runtime_generation.is_shutdown()
                        {
                            generation_group_manager.report_route_failure(
                                &outbound_name,
                                &target,
                                traffic.family,
                                traffic.stamp,
                                &error,
                            );
                        }
                        if let Some(reporter) = &score_reporter {
                            reporter.finish(target.score_failure(
                                crate::group::ScoreOutcome::from_io_error(&error),
                                &error,
                            ));
                        }
                    }
                    RelayCompletion::Relayed(Ok(_)) => {
                        if let Some(reporter) = &score_reporter {
                            reporter.finish(crate::group::ScoreOutcome::Success);
                        }
                    }
                    RelayCompletion::Relayed(Err(e)) => {
                        let io_err = e.downcast_ref::<std::io::Error>();
                        if let Some(io_err) = io_err {
                            if relay::is_ignorable_connection_error(io_err) {
                                debug!(
                                    "TCP relay closed for {} -> {}: {}",
                                    client_addr, original_dst, io_err
                                );
                            } else {
                                debug!(
                                    "Relay error for {} -> {}: {}",
                                    client_addr, original_dst, e
                                );
                            }
                        } else {
                            debug!("Relay error for {} -> {}: {}", client_addr, original_dst, e);
                        }
                        self.stats.record_error(&outbound_name, outbound_kind);
                        if let Some(traffic) = route_traffic
                            && !runtime_generation.is_shutdown()
                            && !e.is::<relay::ClientIoError>()
                        {
                            generation_group_manager.report_route_failure(
                                &outbound_name,
                                &target,
                                traffic.family,
                                traffic.stamp,
                                e.as_ref(),
                            );
                        }
                        if let Some(reporter) = &score_reporter {
                            reporter.finish(
                                target.score_failure(tcp_relay_score_outcome(&e), e.as_ref()),
                            );
                        }
                    }
                }
                anyhow::ensure!(
                    flow.retire(
                        RetireAck {
                            close: close.take(),
                            outbound: outbound_guard.take()
                        },
                        None
                    )
                    .await,
                    "TCP retirement failed"
                );

                if relay_succeeded && replenishes_pool(&outbound_name, &target) {
                    self.replenish_tcp_pool(
                        target.node,
                        (original_dst, target_domain),
                        &runtime_generation,
                        connect_timeout,
                        score_reporter,
                        health_ipver,
                    );
                }

                Ok(())
            };
            #[cfg(feature = "native-api")]
            let operation = async {
                let operation = std::pin::pin!(operation);
                match &native_observer {
                    Some(observer) => observer.scope(operation).await,
                    None => operation.await,
                }
            };
            let operation = std::pin::pin!(operation);
            match task_cancel {
                Some(cancel) => {
                    Abortable::new(run_until_auxiliary_pause(auxiliary, operation), cancel)
                        .await
                        .ok()
                        .flatten()
                }
                None => Some(operation.await),
            }
        };
        let result = match result {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) if !error.is::<PacketDnsScopeRetired>() => Err(error),
            Some(Err(_)) | None => {
                #[cfg(feature = "native-api")]
                {
                    terminal = Some(TcpTerminal::IntentionalRetirement);
                }
                Ok(())
            }
        };
        if let Some(close) = &close {
            close.0.finish(result.is_ok());
        }
        #[cfg(feature = "native-api")]
        if let Some(terminal) = if result.is_err() {
            Some(TcpTerminal::ConnectionFailed)
        } else {
            terminal
        } {
            let (state, reason) = terminal.outcome();
            observation.finish(state, reason);
        }
        result
    }
}

#[cfg(test)]
#[path = "tcp_score_tests.rs"]
mod score_tests;

#[cfg(test)]
#[path = "cold_urltest_tests.rs"]
mod cold_urltest_tests;
#[cfg(test)]
#[path = "dial_permit_scope_tests.rs"]
mod dial_permit_scope_tests;

#[cfg(test)]
#[path = "route_chain_tests.rs"]
mod route_chain_tests;

#[cfg(all(test, feature = "native-api"))]
#[path = "tcp_native_flow_tests.rs"]
mod tcp_native_flow_tests;

#[cfg(test)]
#[path = "tcp_native_accounting_tests.rs"]
mod native_accounting_tests;

#[cfg(test)]
#[path = "tcp_packet_tests.rs"]
mod packet_tests;
