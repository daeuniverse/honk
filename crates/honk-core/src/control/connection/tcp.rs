use super::overall_dial_timeout;
use super::routing::{build_connection_info, connection_chains};
use crate::control::*;
use crate::group::{SelectionNetwork, SelectionPlanMode};

use futures::{FutureExt, StreamExt};
use std::collections::{HashMap, HashSet};

use crate::connection_tracker::{
    CloseAction, CloseCompletion, CloseSignal, ConnectionOwner, captured_groups,
};

async fn wait_for_close(close: Option<&CloseCompletion>) {
    match close {
        Some(close) => close.0.cancelled().await,
        None => std::future::pending().await,
    }
}
use super::observation::ConnectionObservation;
#[cfg(feature = "native-api")]
use crate::observe::catalog::CatalogIdentity;

mod dial;

fn tcp_relay_score_outcome(error: &anyhow::Error) -> crate::group::ScoreOutcome {
    if error.is::<relay::ClientIoError>() {
        crate::group::ScoreOutcome::Cancelled
    } else {
        crate::group::ScoreOutcome::from_error(error)
    }
}

async fn write_sniff_prefix(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin + ?Sized),
    mut buffered: &[u8],
    mut on_write: impl FnMut(usize),
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    while !buffered.is_empty() {
        let written = stream.write(buffered).await?;
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        on_write(written);
        buffered = &buffered[written..];
    }
    Ok(())
}

type UnpackedTcpScorePlan = (
    Vec<Node>,
    SelectionPlanMode,
    HashMap<uuid::Uuid, crate::group::ScoreAttempt>,
    HashMap<uuid::Uuid, Vec<String>>,
    HashMap<uuid::Uuid, Vec<String>>,
    IpVersion,
);

struct TcpDnsRoute {
    decision: super::routing::RoutingDecision,
    config: Arc<Config>,
    group_manager: Arc<honk_outbound::group::GroupManager>,
    runtime: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    #[cfg(feature = "native-api")]
    native: Option<(u64, Arc<CatalogIdentity>)>,
}

fn tcp_score_context(
    target: SocketAddr,
    domain: Option<&str>,
    health_family: IpVersion,
) -> crate::group::ScoreSelectionContext {
    let target_family = if target.is_ipv6() {
        IpVersion::V6
    } else {
        IpVersion::V4
    };
    crate::group::ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(target_family),
        health_family,
        target: Some(match domain {
            Some(domain) => crate::group::ScoreTarget::domain(domain, target.port()),
            None => target.into(),
        }),
    }
}

fn unpack_tcp_score_plan(plan: crate::control::reload::ResolvedScorePlan) -> UnpackedTcpScorePlan {
    let mut seen = HashSet::new();
    let mut nodes = Vec::with_capacity(plan.nodes.len());
    let mut feedback = HashMap::new();
    let mut selection_chains = HashMap::new();
    let mut final_owners = HashMap::new();
    for (((node, value), selection_chain), used_final_owners) in plan
        .nodes
        .into_iter()
        .zip(plan.feedback)
        .zip(plan.selection_chains)
        .zip(plan.final_owners)
    {
        if !seen.insert(node.id) {
            continue;
        }
        if let Some(value) = value {
            feedback.insert(node.id, value);
        }
        selection_chains.insert(node.id, selection_chain);
        if !used_final_owners.is_empty() {
            final_owners.insert(node.id, used_final_owners);
        }
        nodes.push(node);
    }
    (
        nodes,
        plan.mode,
        feedback,
        selection_chains,
        final_owners,
        plan.health_family,
    )
}

fn timeout_started_score_reporters(
    reporters: &parking_lot::Mutex<Vec<crate::group::ScoreReporter>>,
) {
    for reporter in reporters.lock().iter() {
        reporter.setup_failed(crate::group::ScoreOutcome::Timeout);
    }
}

#[cfg(test)]
fn started_score_reporter_count(
    reporters: &parking_lot::Mutex<Vec<crate::group::ScoreReporter>>,
) -> usize {
    reporters.lock().len()
}

const COLD_URLTEST_STAGGER: Duration = Duration::from_millis(200);

/// Wait until this candidate's absolute cold-URLTest release offset. The
/// first candidate starts immediately; sleeping candidates have not acquired
/// a dial permit and are dropped with their accepted connection owner.
async fn wait_for_cold_urltest_release(index: usize) {
    if index != 0 {
        tokio::time::sleep(COLD_URLTEST_STAGGER.saturating_mul(index as u32)).await;
    }
}

/// How an observed TCP connection ended.
#[cfg(feature = "native-api")]
#[derive(Clone, Copy)]
enum TcpTerminal {
    DnsInterceptCompleted,
    NoAvailableNodes,
    PolicyBlock,
    DialFailed,
    IntentionalRetirement,
    PrefixWriteFailed,
    RelayClosed,
    RelayFailed,
    ConnectionFailed,
}

#[cfg(feature = "native-api")]
impl TcpTerminal {
    fn outcome(self) -> (crate::observe::vocab::ConnectionState, &'static str) {
        use crate::observe::vocab::ConnectionState::{Blocked, Closed, Failed};
        match self {
            Self::DnsInterceptCompleted => (Closed, "dns_intercept_completed"),
            Self::NoAvailableNodes => (Failed, "no_available_nodes"),
            Self::PolicyBlock => (Blocked, "policy_block"),
            Self::DialFailed => (Failed, "dial_failed"),
            Self::IntentionalRetirement => (Closed, "intentional_retirement"),
            Self::PrefixWriteFailed => (Failed, "prefix_write_failed"),
            Self::RelayClosed => (Closed, "relay_closed"),
            Self::RelayFailed => (Failed, "relay_failed"),
            Self::ConnectionFailed => (Failed, "connection_failed"),
        }
    }
}

/// Block nodes "dial" by failing and the dial path reports no other signal,
/// so a failure where every tried node is a block node is the policy's doing.
pub(super) fn only_block_nodes<'a>(nodes: impl IntoIterator<Item = &'a Node>) -> bool {
    nodes
        .into_iter()
        .all(|node| node.protocol() == honk_config::types::NodeProtocol::Block)
}

impl ControlPlaneHandle {
    async fn pin_tcp_dns_route(
        &self,
        handoff: &super::handoff::HandoffResult,
    ) -> anyhow::Result<TcpDnsRoute> {
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
            mark: honk_outbound::proxy::DirectMark::new(handoff.mark),
            matched_rule: None,
            reroute_by_sniffed_domain: false,
            #[cfg(feature = "native-api")]
            native_route: None,
        };
        drop(backend);
        Ok(TcpDnsRoute {
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
        let mut observation = ConnectionObservation::begin(
            self.native.as_deref(),
            crate::observe::vocab::Network::Tcp,
            client_addr,
            original_dst,
        );
        #[cfg(feature = "native-api")]
        let native_observer = observation.flow().and_then(|flow| {
            flow.observer(self.diagnostics.read().generation, None, "dial_target")
        });
        #[cfg(feature = "native-api")]
        let mut terminal = None;
        let close = self
            .connection_tracker
            .is_enabled()
            .then(|| CloseCompletion(CloseSignal::new()));
        let result = {
            let operation = async {
                let tuples = build_tuples_key(
                    original_dst.ip(),
                    original_dst.port(),
                    client_addr.ip(),
                    client_addr.port(),
                    6, // TCP
                );
                let (mut flow, handoff) = self
                    .adopt_tcp_flow(
                        stream,
                        tuples,
                        #[cfg(feature = "native-api")]
                        &observation,
                    )
                    .await?;
                observation.handoff(handoff.as_ref(), true);
                observation.routing_started();

                let pinned_dns_route = if original_dst.port() == 53 {
                    let handoff = handoff.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("transparent TCP DNS has no routing handoff")
                    })?;
                    if handoff.outbound == OutboundIndex::Block as u8 {
                        None
                    } else if handoff.must != 0 {
                        Some(self.pin_tcp_dns_route(handoff).await?)
                    } else {
                        self.dns_controller
                            .handle_tcp_dns(flow.stream_mut(), client_addr, original_dst)
                            .await?;
                        #[cfg(feature = "native-api")]
                        {
                            terminal = Some(TcpTerminal::DnsInterceptCompleted);
                        }
                        return Ok(());
                    }
                } else {
                    None
                };

                let (dial_mode, connect_timeout, overall_dial_timeout) = {
                    let current_config;
                    let config = if let Some(snapshot) = &pinned_dns_route {
                        &snapshot.config
                    } else {
                        current_config = self.config.read().await;
                        &*current_config
                    };
                    #[cfg(feature = "native-api")]
                    {
                        observation.pin_dial_mode(if let Some(snapshot) = &pinned_dns_route {
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
                    sniffing::sniff_tcp(flow.stream_mut()).await
                };
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

                let conn_info = build_connection_info(
                    domain.clone(),
                    original_dst,
                    client_addr,
                    "tcp",
                    handoff.as_ref(),
                );
                #[cfg(feature = "native-api")]
                let mut pinned_native = pinned_dns_route
                    .as_ref()
                    .and_then(|snapshot| snapshot.native.clone());
                let (mut route, pinned_generation) = if let Some(snapshot) = pinned_dns_route {
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
                let mode_decision = self.apply_mode_override(&mut route).await;
                let outbound_name = mode_decision.name;
                let mode_constraint = mode_decision.constraint;
                observation.mode_applied(&outbound_name);

                // Seed current predicate facts so later flows need not repeat sniffing.
                if let Some(domain) = &domain
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
                let outbound_guard = self.stats.track_connection(&outbound_name, outbound_kind);
                #[cfg(feature = "native-api")]
                let close_catalog = pinned_native
                    .as_ref()
                    .map(|(_, catalog)| Arc::clone(catalog));
                #[cfg(feature = "native-api")]
                if let Some((generation, catalog)) = &pinned_native {
                    observation.pin_selection(*generation, catalog, &generation_config);
                }
                #[cfg(feature = "native-api")]
                let selection_observer = pinned_native.as_ref().and_then(|(generation, _)| {
                    observation.observer(|| *generation, "dial_target")
                });
                let (
                    mut candidates,
                    selection_mode,
                    mut score_feedback,
                    mut selection_chains,
                    final_owners,
                    health_ipver,
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
                    #[cfg(feature = "native-api")]
                    let plan = match &selection_observer {
                        Some(observer) => observer.sync_scope(select),
                        None => select(),
                    };
                    #[cfg(not(feature = "native-api"))]
                    let plan = select();
                    #[cfg(feature = "native-api")]
                    observation.selection_observed(plan.observation.as_ref(), plan.health_family);
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
                score_feedback.retain(|id, _| candidates.iter().any(|node| node.id == *id));

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
                    // Trigger emergency probes to recover dead nodes (leaf
                    // expansion: sub-group tags carry no probe state).
                    let group_manager = self.group_manager.read().clone();
                    for node in group_manager.leaf_nodes_in_group(&outbound_name) {
                        self.alive_set.notify_check_tcp(node.id);
                    }
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
                let candidate_refs: Vec<&Node> = candidates.iter().collect();
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
                        route.mark,
                        connect_timeout,
                        dial_deadline,
                        Arc::clone(&runtime_generation),
                        health_ipver,
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
                        .get(&candidates[0].id)
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
                            let failed_node = candidates[0].id;
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
                            #[cfg(feature = "native-api")]
                            let mut plan = match &selection_observer {
                                Some(observer) => observer.sync_scope(select),
                                None => select(),
                            };
                            #[cfg(not(feature = "native-api"))]
                            let mut plan = select();
                            #[cfg(feature = "native-api")]
                            observation
                                .selection_observed(plan.observation.as_ref(), plan.health_family);
                            // URLTest retains its existing fresh retry-round budget.
                            let mut retry_deadline =
                                tokio::time::Instant::now() + overall_dial_timeout;
                            if plan.nodes.is_empty()
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
                                            .get(&failed_node)
                                            .map(Vec::as_slice)
                                            .unwrap_or_default(),
                                        original,
                                    )
                                };
                                #[cfg(feature = "native-api")]
                                {
                                    plan = match &selection_observer {
                                        Some(observer) => observer.sync_scope(select),
                                        None => select(),
                                    };
                                }
                                #[cfg(not(feature = "native-api"))]
                                {
                                    plan = select();
                                }
                                #[cfg(feature = "native-api")]
                                observation.selection_observed(
                                    plan.observation.as_ref(),
                                    plan.health_family,
                                );
                                retry_deadline = dial_deadline;
                            }
                            let (
                                retry_nodes,
                                _,
                                mut retry_feedback,
                                retry_chains,
                                _,
                                retry_health_ipver,
                            ) = unpack_tcp_score_plan(plan);
                            if retry_nodes.len() > 1
                                || retry_nodes
                                    .first()
                                    .is_some_and(|node| node.id != failed_node)
                            {
                                let nodes: Vec<_> = retry_nodes.iter().take(3).collect();
                                retry_feedback
                                    .retain(|id, _| nodes.iter().any(|node| node.id == *id));
                                retried = match self
                                    .race_candidates(
                                        &nodes,
                                        original_dst,
                                        target_domain.clone(),
                                        &outbound_name,
                                        outbound_kind,
                                        route.mark,
                                        connect_timeout,
                                        retry_deadline,
                                        Arc::clone(&runtime_generation),
                                        retry_health_ipver,
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
                                if retried.is_none() && only_block_nodes(nodes.iter().copied()) {
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
                                        if outbound_name == "block" || only_block_nodes(&candidates)
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
                let mut proxy_stream = winner.stream;
                let node = winner.node;
                let score_reporter = winner.reporter;
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
                            .get(&node.id)
                            .map(Vec::as_slice)
                            .unwrap_or_default(),
                        &node,
                    );
                    observation.release_selection();
                }

                let dscp_val = handoff.as_ref().map(|ho| ho.dscp).unwrap_or(0);

                let conn_upload = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let conn_download = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let (outbound_upload, outbound_download) =
                    self.stats.byte_counters(&outbound_name, outbound_kind);
                if let Some(close) = &close {
                    let groups = captured_groups(
                        selection_chains
                            .get(&node.id)
                            .map(Vec::as_slice)
                            .unwrap_or_default(),
                        &node.name,
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
                        || {
                            let id = uuid::Uuid::new_v4().to_string();
                            let (rule, rule_payload) = matched_rule
                                .unwrap_or_else(|| ("Fallback".to_string(), String::new()));
                            crate::connection_tracker::ConnectionEntry {
                                id,
                                source: client_addr.to_string(),
                                destination: original_dst.to_string(),
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
                                    selection_chains.remove(&node.id).unwrap_or_default(),
                                    &node.name,
                                ),
                                upload: conn_upload.clone(),
                                download: conn_download.clone(),
                                start_time: std::time::Instant::now(),
                                domain: target_domain.clone(),
                                network: "tcp".to_string(),
                                process: handoff.as_ref().and_then(|ho| ho.process_name()),
                                process_path: None,
                            }
                        },
                        ConnectionOwner {
                            signal: Arc::clone(&close.0),
                            action: CloseAction::Tcp,
                            groups,
                        },
                    ) {
                        if let Some(native) = observation.flow() {
                            native.attach_connection(&conn_id);
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
                    dscp = dscp_val,
                    src = %client_addr,
                    "TCP connection: {} <-> {}", client_addr, original_dst,
                );

                let mut intentionally_closed = false;
                let prefix_result = {
                    let operation = async {
                        tokio::select! {
                            biased;
                            _ = wait_for_close(close.as_ref()) => {
                                intentionally_closed = true;
                                Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "connection closed"))
                            }
                            result = write_sniff_prefix(
                                &mut *proxy_stream.stream, &sniff_result.buffered, |bytes| {
                                    conn_upload.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
                                    outbound_upload.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
                                    #[cfg(feature = "native-api")]
                                    if let Some(flow) = observation.flow() {
                                        flow.accepted_send();
                                    }
                                    if let Some(reporter) = &score_reporter {
                                        reporter.tx(bytes as u64);
                                    }
                                },
                            ) => result,
                        }
                    };
                    #[cfg(feature = "native-api")]
                    let operation = async {
                        match &winner_observer {
                            Some(observer) => observer.scope(operation).await,
                            None => operation.await,
                        }
                    };
                    operation.await
                };
                match prefix_result {
                    Ok(()) => {}
                    Err(error) => {
                        #[cfg(feature = "native-api")]
                        {
                            terminal = Some(if intentionally_closed {
                                TcpTerminal::IntentionalRetirement
                            } else {
                                TcpTerminal::PrefixWriteFailed
                            });
                        }
                        if !intentionally_closed {
                            debug!("Failed to write sniffed bytes to proxy: {}", error);
                            self.stats.record_error(&outbound_name, outbound_kind);
                        }
                        drop(outbound_guard);
                        if let Some(reporter) = &score_reporter {
                            reporter.finish(if intentionally_closed {
                                crate::group::ScoreOutcome::Cancelled
                            } else {
                                crate::group::ScoreOutcome::from_io_error(&error)
                            });
                        }
                        drop(proxy_stream);
                        anyhow::ensure!(flow.retire().await, "TCP retirement failed");
                        return Ok(());
                    }
                };

                let first_response = score_reporter.as_ref().map(|reporter| {
                    let reporter = reporter.clone();
                    std::sync::Arc::new(move || reporter.first_response())
                        as std::sync::Arc<dyn Fn() + Send + Sync>
                });
                let first_response = observation.first_response(first_response);
                let on_transfer = score_reporter.as_ref().map(|reporter| {
                    let reporter = reporter.clone();
                    std::sync::Arc::new(move |upload, download| {
                        if upload != 0 {
                            reporter.tx(upload);
                        }
                        if download != 0 {
                            reporter.rx(download);
                        }
                    }) as std::sync::Arc<dyn Fn(u64, u64) + Send + Sync>
                });
                let on_transfer = match observation.flow() {
                    Some(flow) => {
                        let flow = Arc::clone(flow);
                        Some(Arc::new(move |upload, download| {
                            if let Some(callback) = &on_transfer {
                                callback(upload, download);
                            }
                            if upload != 0 {
                                flow.accepted_send();
                            }
                        })
                            as Arc<dyn Fn(u64, u64) + Send + Sync>)
                    }
                    None => on_transfer,
                };
                let conn_progress = relay::RelayProgress {
                    upload: conn_upload.clone(),
                    download: conn_download.clone(),
                    outbound_upload: Some(outbound_upload),
                    outbound_download: Some(outbound_download),
                    first_response,
                    on_transfer,
                };
                let relay_result = {
                    let operation = async {
                        tokio::select! {
                            biased;
                            _ = wait_for_close(close.as_ref()) => None,
                            result = relay::relay_proxy(
                                flow.stream_mut(), proxy_stream, client_addr, original_dst, conn_progress,
                            ) => Some(result),
                        }
                    };
                    #[cfg(feature = "native-api")]
                    let operation = async {
                        match &winner_observer {
                            Some(observer) => observer.scope(operation).await,
                            None => operation.await,
                        }
                    };
                    operation.await
                };
                let Some(relay_result) = relay_result else {
                    if let Some(reporter) = &score_reporter {
                        reporter.finish(crate::group::ScoreOutcome::Cancelled);
                    }
                    #[cfg(feature = "native-api")]
                    {
                        terminal = Some(TcpTerminal::IntentionalRetirement);
                    }
                    anyhow::ensure!(flow.retire().await, "TCP retirement failed");
                    return Ok(());
                };
                #[cfg(feature = "native-api")]
                {
                    terminal = Some(if relay_result.is_ok() {
                        TcpTerminal::RelayClosed
                    } else {
                        TcpTerminal::RelayFailed
                    });
                }
                let relay_succeeded = relay_result.is_ok();
                match relay_result {
                    Ok(_) => {
                        if let Some(reporter) = &score_reporter {
                            reporter.finish(crate::group::ScoreOutcome::Success);
                        }
                    }
                    Err(e) => {
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
                        if let Some(reporter) = &score_reporter {
                            reporter.finish(tcp_relay_score_outcome(&e));
                        }
                    }
                }
                anyhow::ensure!(flow.retire().await, "TCP retirement failed");
                drop(outbound_guard);

                if relay_succeeded && outbound_name != "direct" && outbound_name != "block" {
                    self.replenish_tcp_pool(
                        node,
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
            {
                let operation = std::pin::pin!(operation);
                match &native_observer {
                    Some(observer) => observer.scope(operation).await,
                    None => operation.await,
                }
            }
            #[cfg(not(feature = "native-api"))]
            operation.await
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
mod score_tests {
    use super::*;

    #[tokio::test]
    async fn relay_outcome_is_settled_once_even_when_retirement_fails() -> anyhow::Result<()> {
        use crate::control::tests::support::{canonical_socks5, test_dns_forwarder};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        tokio::time::timeout(Duration::from_secs(10), async {
            for relay_fails in [false, true] {
                for retirement_fails in [false, true] {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                    let destination = listener.local_addr()?;
                    let proxies = [
                        tokio::net::TcpListener::bind("127.0.0.1:0").await?,
                        tokio::net::TcpListener::bind("127.0.0.1:0").await?,
                    ];
                    let nodes = [
                        canonical_socks5(
                            "seed",
                            "127.0.0.1",
                            proxies[0].local_addr()?.port(),
                            None,
                        ),
                        canonical_socks5(
                            "relay",
                            "127.0.0.1",
                            proxies[1].local_addr()?.port(),
                            None,
                        ),
                    ];
                    let mut config = Config::default();
                    config.ensure_builtin_nodes();
                    config.nodes.extend(nodes.iter().cloned());
                    config.groups = vec![Group {
                        name: "score".into(),
                        policy: GroupPolicy::Score,
                        nodes: nodes.iter().map(|node| node.id).collect(),
                        ..Default::default()
                    }];
                    config.routing.default_outbound = "score".into();
                    config.global.dial_mode = "ip".into();
                    let router = Router::from_config(&config.routing)?;
                    let plane = ControlPlane::new(
                        config,
                        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
                        router,
                        Arc::new(ProxyRegistry::default_resolver()?),
                        DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
                        test_dns_forwarder(),
                    )?;
                    let handle = plane.spawn_handle();
                    let manager = handle.group_manager.read().clone();
                    let seed = manager
                        .feedback_for_node(
                            nodes[0].id,
                            crate::group::ScoreSelectionContext::aggregate(
                                SelectionNetwork::Tcp,
                                ProbeDomain::Tcp,
                                IpVersion::V4,
                            ),
                        )
                        .unwrap()
                        .start();
                    seed.setup_succeeded();
                    seed.tx(1);
                    seed.rx(1);
                    seed.finish(crate::group::ScoreOutcome::Success);
                    let mut client = TcpStream::connect(destination).await?;
                    let (accepted, source) = listener.accept().await?;
                    crate::control::tests::store_active_tcp_flow(&handle, destination, source)
                        .await?;
                    let worker = handle.clone();
                    let serving =
                        tokio::spawn(
                            async move { worker.serve_connection(accepted, source).await },
                        );
                    let (mut upstream, _) = tokio::select! {
                        accepted = proxies[0].accept() => accepted?,
                        accepted = proxies[1].accept() => accepted?,
                    };
                    let mut greeting = [0; 3];
                    upstream.read_exact(&mut greeting).await?;
                    upstream.write_all(&[5, 0]).await?;
                    let mut request = [0; 10];
                    upstream.read_exact(&mut request).await?;
                    upstream
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await?;
                    client.write_all(b"q").await?;
                    assert_eq!(upstream.read_u8().await?, b'q');
                    upstream.write_all(b"r").await?;
                    assert_eq!(client.read_u8().await?, b'r');
                    if retirement_fails {
                        let key = handle.tcp_flow_pins.snapshot().into_iter().next().unwrap();
                        assert_eq!(handle.tcp_flow_pins.release_for_test(key), Some(true));
                    }
                    if relay_fails {
                        socket2::SockRef::from(&upstream).set_linger(Some(Duration::ZERO))?;
                        drop(upstream);
                    } else {
                        upstream.shutdown().await?;
                        client.shutdown().await?;
                    }
                    let result = serving.await?;
                    assert_eq!(result.is_err(), retirement_fails);
                    let counters = manager.score_budget_counters("score", SelectionNetwork::Tcp);
                    assert_eq!(counters.spent, 1, "fixture must execute a scored trial");
                    assert_eq!(
                        (
                            counters.trial_success,
                            counters.trial_failure,
                            counters.trial_cancelled
                        ),
                        (u64::from(!relay_fails), u64::from(relay_fails), 0),
                    );
                    assert_eq!(
                        handle.stats.snapshot()["score"].errors,
                        u32::from(relay_fails)
                    );
                    if retirement_fails {
                        assert!(
                            tokio::time::timeout(Duration::from_millis(20), async {
                                tokio::select! {
                                    accepted = proxies[0].accept() => accepted,
                                    accepted = proxies[1].accept() => accepted,
                                }
                            })
                            .await
                            .is_err(),
                            "failed retirement must not replenish the pool"
                        );
                    }
                    let runtime = handle.runtime_registry.read().clone();
                    runtime.shutdown().await;
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    #[test]
    fn pending_warm_refill_refunds_trial_without_starting_business() {
        let nodes = [
            Node::from_share_link("socks5://127.0.0.1:1080#a").unwrap(),
            Node::from_share_link("socks5://127.0.0.1:1081#b").unwrap(),
        ];
        let group = honk_config::group::Group {
            name: "score".into(),
            policy: honk_config::group::GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        };
        let manager = crate::group::GroupManager::new(&[group], &nodes);
        // Trials only serve challengers trailing the selection's completions.
        let seed = manager
            .feedback_for_node(
                nodes[0].id,
                crate::group::ScoreSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .unwrap()
            .start();
        seed.setup_succeeded();
        seed.tx(1);
        seed.rx(1);
        seed.finish(crate::group::ScoreOutcome::Success);
        let context = tcp_score_context("192.0.2.1:443".parse().unwrap(), None, IpVersion::V4);
        let mut plan = manager.selection_plan_for_target("score", &context);
        let attempt = plan.entries[0].feedback.take().unwrap();
        drop(plan);
        assert!(attempt.continuation().is_err());
        assert_eq!(
            manager
                .score_budget_counters("score", SelectionNetwork::Tcp)
                .reserved,
            1
        );
        let warm = attempt.start_warmup(context.clone());
        warm.setup_succeeded();
        warm.tx(1);
        warm.rx(1);
        warm.finish(crate::group::ScoreOutcome::Success);
        let refill = warm.start_warmup(context);
        refill.setup_succeeded();
        refill.finish_setup_only();
        let counters = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(
            (
                counters.business_starts,
                counters.spent,
                counters.reserved,
                counters.refunded
            ),
            (0, 0, 0, 1)
        );
        assert_eq!(counters.cold_available, counters.cold_allowance);
        assert_eq!(manager.score_state().root_business_starts(), 0);
    }

    #[tokio::test]
    async fn client_reset_preserves_score_availability_but_upstream_reset_revokes_target() {
        use crate::group::{ScoreOutcome, ScoreVerificationState};
        use std::sync::atomic::AtomicU64;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn pair() -> (TcpStream, TcpStream) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (client, server) = tokio::join!(
                TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept(),
            );
            (client.unwrap(), server.unwrap().0)
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            for client_reset in [true, false] {
                let node = Node::from_share_link("socks5://127.0.0.1:1080#relay").unwrap();
                let group = honk_config::group::Group {
                    name: "score".into(),
                    policy: honk_config::group::GroupPolicy::Score,
                    nodes: vec![node.id],
                    ..Default::default()
                };
                let manager =
                    crate::group::GroupManager::new(&[group], std::slice::from_ref(&node));
                let address = "127.0.0.1:443".parse().unwrap();
                let context = tcp_score_context(address, None, IpVersion::V4);
                let feedback = manager.feedback_for_node(node.id, context.clone()).unwrap();
                feedback.start().finish(ScoreOutcome::Timeout);
                for _ in 0..4 {
                    let seed = feedback.start();
                    seed.setup_succeeded();
                    seed.tx(1);
                    seed.rx(1);
                    seed.finish(ScoreOutcome::Cancelled);
                }
                let snapshot = || {
                    manager
                        .score_verification_for_network("score", SelectionNetwork::Tcp)
                        .unwrap()
                        .1
                };
                let before = snapshot();
                assert_eq!(before.state, ScoreVerificationState::ObservedUsable);
                drop(manager.selection_plan_for_target("score", &context));
                let before_counts =
                    manager.score_verification_counters("score", SelectionNetwork::Tcp);
                assert_eq!(
                    (
                        before_counts.usable_selections,
                        before_counts.provisional_selections
                    ),
                    (1, 0)
                );
                let reporter = feedback.start();
                reporter.setup_succeeded();
                let progress = relay::RelayProgress {
                    upload: Arc::new(AtomicU64::new(0)),
                    download: Arc::new(AtomicU64::new(0)),
                    outbound_upload: None,
                    outbound_download: None,
                    first_response: Some(Arc::new({
                        let reporter = reporter.clone();
                        move || reporter.first_response()
                    })),
                    on_transfer: Some(Arc::new({
                        let reporter = reporter.clone();
                        move |up, down| {
                            reporter.tx(up);
                            reporter.rx(down);
                        }
                    })),
                };
                let (mut client, relay_client) = pair().await;
                let (relay_upstream, mut upstream) = pair().await;
                let running = tokio::spawn(relay::splice::relay_auto(
                    relay_client,
                    relay_upstream,
                    address,
                    address,
                    Some(progress),
                ));
                client.write_all(b"q").await.unwrap();
                assert_eq!(upstream.read_u8().await.unwrap(), b'q');
                upstream.write_all(b"r").await.unwrap();
                assert_eq!(client.read_u8().await.unwrap(), b'r');
                let reset = if client_reset { client } else { upstream };
                socket2::SockRef::from(&reset)
                    .set_linger(Some(Duration::ZERO))
                    .unwrap();
                drop(reset);
                let error = running.await.unwrap().unwrap_err();
                assert_eq!(
                    error
                        .downcast_ref::<std::io::Error>()
                        .unwrap()
                        .raw_os_error(),
                    Some(libc::ECONNRESET)
                );
                let outcome = tcp_relay_score_outcome(&error);
                assert_eq!(
                    outcome,
                    if client_reset {
                        ScoreOutcome::Cancelled
                    } else {
                        ScoreOutcome::Io(std::io::ErrorKind::ConnectionReset)
                    }
                );
                reporter.finish(outcome);
                let after = snapshot();
                // A target reset cannot erase the node's factual aggregate RX.
                assert_eq!(after.state, ScoreVerificationState::ObservedUsable);
                drop(manager.selection_plan_for_target("score", &context));
                let after_counts =
                    manager.score_verification_counters("score", SelectionNetwork::Tcp);
                assert_eq!(
                    (
                        after_counts.usable_selections - before_counts.usable_selections,
                        after_counts.provisional_selections - before_counts.provisional_selections,
                    ),
                    if client_reset { (1, 0) } else { (0, 1) },
                    "only an upstream reset revokes observed usability for the next target flow"
                );
            }
        })
        .await
        .expect("reset must terminate the relay without waiting for idle cleanup");
    }

    #[tokio::test]
    async fn sniff_prefix_reports_accepted_bytes_before_write_failure() {
        use tokio::io::AsyncReadExt;
        let (mut writer, mut reader) = tokio::io::duplex(3);
        let mut accepted = 0;
        let (result, ()) = tokio::join!(
            write_sniff_prefix(&mut writer, b"prefix", |bytes| accepted += bytes),
            async move {
                let mut prefix = [0; 3];
                reader.read_exact(&mut prefix).await.unwrap();
                assert_eq!(&prefix, b"pre");
                drop(reader);
            },
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(accepted, 3);
    }

    #[test]
    fn tcp_score_context_uses_target_family_not_health_family() {
        let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let context = tcp_score_context(target, Some("example.com"), IpVersion::V6);

        assert_eq!(context.target_family, Some(IpVersion::V4));
        assert_eq!(context.health_family, IpVersion::V6);
        assert_eq!(
            context.target,
            Some(crate::group::ScoreTarget::domain("example.com", 443))
        );
    }

    #[test]
    fn unpack_tcp_score_plan_deduplicates_shared_leaf_metadata() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "shared".into(),
            ..Default::default()
        };
        let plan = crate::control::reload::ResolvedScorePlan {
            mode: SelectionPlanMode::ColdUrlTest,
            nodes: vec![node.clone(), node],
            health_family: IpVersion::V4,
            feedback: vec![None, None],
            selection_chains: vec![
                vec!["outer".into(), "shared".into()],
                vec!["duplicate".into(), "shared".into()],
            ],
            final_owners: vec![Vec::new(), Vec::new()],
            #[cfg(feature = "native-api")]
            observation: None,
        };
        let (nodes, mode, feedback, selection_chains, _, family) = unpack_tcp_score_plan(plan);

        assert_eq!(nodes.len(), 1);
        assert_eq!(mode, SelectionPlanMode::ColdUrlTest);
        assert!(feedback.is_empty());
        assert_eq!(
            selection_chains[&nodes[0].id],
            ["outer".to_owned(), "shared".to_owned()]
        );
        assert_eq!(family, IpVersion::V4);
    }

    #[test]
    fn timeout_helper_finishes_started_reporter_before_abort_drop() {
        let nodes = [
            Node {
                id: uuid::Uuid::new_v4(),
                name: "a".into(),
                ..Default::default()
            },
            Node {
                id: uuid::Uuid::new_v4(),
                name: "b".into(),
                ..Default::default()
            },
        ];
        let group = honk_config::group::Group {
            name: "score".into(),
            policy: honk_config::group::GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        };
        let manager = crate::group::GroupManager::new(&[group], &nodes);
        let context = tcp_score_context("192.0.2.1:443".parse().unwrap(), None, IpVersion::V4);
        let feedback = manager
            .feedback_for_node(nodes[0].id, context.clone())
            .unwrap();
        let reporters = parking_lot::Mutex::new(vec![feedback.start()]);
        assert_eq!(started_score_reporter_count(&reporters), 1);
        timeout_started_score_reporters(&reporters);
        drop(reporters);

        assert_eq!(
            manager.selection_plan_for_target("score", &context).entries[0]
                .node
                .id,
            nodes[1].id
        );
    }
}

#[cfg(test)]
#[path = "cold_urltest_tests.rs"]
mod cold_urltest_tests;
#[cfg(test)]
#[path = "dial_permit_scope_tests.rs"]
mod dial_permit_scope_tests;

#[cfg(all(test, feature = "native-api"))]
#[path = "tcp_native_flow_tests.rs"]
mod tcp_native_flow_tests;

#[cfg(test)]
mod native_accounting_tests {
    use super::write_sniff_prefix;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn native_prefix_partial_failure_keeps_only_written_bytes() {
        let connection = AtomicU64::new(0);
        let outbound = AtomicU64::new(7);
        let (mut writer, mut reader) = tokio::io::duplex(3);
        let (result, received) = tokio::join!(
            write_sniff_prefix(&mut writer, b"abcdef", |bytes| {
                connection.fetch_add(bytes as u64, Ordering::Relaxed);
                outbound.fetch_add(bytes as u64, Ordering::Relaxed);
            }),
            async move {
                let mut received = [0; 3];
                reader.read_exact(&mut received).await.unwrap();
                drop(reader);
                received
            }
        );
        assert_eq!(&received, b"abc");
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(connection.load(Ordering::Relaxed), 3);
        assert_eq!(outbound.load(Ordering::Relaxed), 10);
    }
}
