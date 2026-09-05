use super::routing::{build_connection_info, connection_chains};
use crate::control::*;
use crate::group::{SelectionNetwork, SelectionPlanMode};

use std::collections::{HashMap, HashSet};

type UnpackedTcpScorePlan = (
    Vec<Node>,
    SelectionPlanMode,
    HashMap<uuid::Uuid, crate::group::ScoreFeedback>,
    HashMap<uuid::Uuid, Vec<String>>,
    IpVersion,
);

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
    for ((node, value), selection_chain) in plan
        .nodes
        .into_iter()
        .zip(plan.feedback)
        .zip(plan.selection_chains)
    {
        if !seen.insert(node.id) {
            continue;
        }
        if let Some(value) = value {
            feedback.insert(node.id, value);
        }
        selection_chains.insert(node.id, selection_chain);
        nodes.push(node);
    }
    (
        nodes,
        plan.mode,
        feedback,
        selection_chains,
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
/// a dial permit and are cancelled with their enclosing `JoinSet`.
async fn wait_for_cold_urltest_release(index: usize) {
    if index != 0 {
        tokio::time::sleep(COLD_URLTEST_STAGGER.saturating_mul(index as u32)).await;
    }
}

impl ControlPlaneHandle {
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
                        warn!(
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
        let tuples = build_tuples_key(
            original_dst.ip(),
            original_dst.port(),
            client_addr.ip(),
            client_addr.port(),
            6, // TCP
        );
        let (mut flow, handoff) = self.adopt_tcp_flow(stream, tuples).await?;

        if let Ok(true) = self
            .dns_controller
            .handle_tcp_dns(flow.stream_mut(), client_addr, original_dst)
            .await
        {
            return Ok(());
        }

        let (dial_mode, connect_timeout, overall_dial_timeout) = {
            let config = self.config.read().await;
            let connect_timeout_ms = config.global.connect_timeout_ms;
            (
                config
                    .global
                    .dial_mode
                    .parse::<DialMode>()
                    .map_err(|_| anyhow::anyhow!("invalid global.dial_mode"))?,
                Duration::from_millis(connect_timeout_ms),
                Duration::from_millis((connect_timeout_ms.max(1000) * 4).max(10000)),
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
        let (domain, domain_verified) = self
            .apply_domain_reality_check(
                dial_mode,
                sniffed_domain,
                original_dst.ip(),
                client_addr.ip(),
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
        let route = self
            .prepare_routing(dial_mode, &conn_info, domain_verified, handoff.as_ref())
            .await;
        let reroute_by_sniffed_domain = route.reroute_by_sniffed_domain;
        let matched_rule = route.matched_rule;
        let outbound_name = self.apply_mode_override(route.outbound, route.must).await;

        // For userspace-routed flows with a sniffed domain, write the resolved
        // IP back into eBPF DOMAIN_ROUTING_MAP so the next connection to the
        // same IP can be fast-pathed by eBPF domain rules instead of being
        // sniffed again.
        if let Some(domain) = &domain
            && Self::should_write_sniffed_domain_bitmap(handoff.as_ref(), reroute_by_sniffed_domain)
        {
            self.push_sniffed_domain_bitmap(&conn_info, domain, original_dst.ip())
                .await;
        }

        self.stats.record_connection(&outbound_name);
        // If eBPF already decided this flow should go direct (not just punted
        // it to userspace), skip userspace proxy dial, DNS, and relay entirely.
        // For ControlPlaneRouting handoffs we must relay in userspace even if
        // the final routing decision is direct, because eBPF has not installed
        // the flow state needed to forward the accepted socket.
        let ebpf_offload = outbound_name == "direct"
            && handoff
                .as_ref()
                .map(|ho| {
                    ho.outbound == OutboundIndex::Direct as u8
                        && ho.mark != 0
                        && ho.outbound != OutboundIndex::ControlPlaneRouting as u8
                })
                .unwrap_or(false);
        if ebpf_offload {
            info!(
                network = "tcp",
                outbound = %outbound_name,
                ip = %original_dst,
                src = %client_addr,
                ebpf_offload = true,
                "TCP offloaded to eBPF: {} -> {}",
                client_addr,
                original_dst,
            );
            self.stats.record_close(&outbound_name);
            return Ok(());
        }

        let ipver = if original_dst.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        // Hold the config read guard while cloning the group/runtime handles:
        // reload publishes all three under their write guards, so this is one
        // coherent generation rather than three individually-current values.
        let generation_config_guard = self.config.read().await;
        let generation_config = Arc::clone(&generation_config_guard);
        let generation_group_manager = self.group_manager.read().clone();
        let runtime_generation = self.runtime_registry.read().clone();
        drop(generation_config_guard);
        let (mut candidates, selection_mode, score_feedback, mut selection_chains, health_ipver) = {
            let context = tcp_score_context(original_dst, domain.as_deref(), ipver);
            let plan = crate::control::reload::resolve_outbound_plan_for_target(
                &generation_config,
                &generation_group_manager,
                &outbound_name,
                &context,
            );
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

        if candidates.is_empty() {
            warn!(
                "No available candidate nodes for outbound '{}' ({})",
                outbound_name, client_addr
            );
            // Trigger emergency probes to recover dead nodes (leaf
            // expansion: sub-group tags carry no probe state).
            let group_manager = self.group_manager.read().clone();
            for node in group_manager.leaf_nodes_in_group(&outbound_name) {
                self.alive_set.notify_check_tcp(node.id);
            }
            self.stats.record_error(&outbound_name);
            self.stats.record_close(&outbound_name);
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

        let cold_urltest = selection_mode == SelectionPlanMode::ColdUrlTest;
        let candidate_refs: Vec<&Node> = candidates.iter().collect();
        let raced = self
            .race_candidates(
                &candidate_refs,
                original_dst,
                target_domain.clone(),
                &outbound_name,
                connect_timeout,
                overall_dial_timeout,
                Arc::clone(&runtime_generation),
                health_ipver,
                &score_feedback,
                cold_urltest,
            )
            .await;
        let (mut proxy_stream, node, score_reporter) = match raced {
            Some(pair) => pair,
            None => {
                // Retry once only when a failed authoritative pick can produce
                // a different plan. URLTest may race its alternates; Score
                // re-scores the exact target and retries only a replacement.
                let mut retried: Option<(
                    crate::proxy::ProxyStream,
                    Node,
                    Option<crate::group::ScoreReporter>,
                )> = None;
                if selection_mode == SelectionPlanMode::Authoritative && candidates.len() == 1 {
                    {
                        let group_manager = Arc::clone(&generation_group_manager);
                        let context =
                            tcp_score_context(original_dst, target_domain.as_deref(), health_ipver);
                        let mut plan =
                            crate::control::reload::resolve_urltest_retry_plan_for_target(
                                &group_manager,
                                &outbound_name,
                                &context,
                            );
                        if plan.nodes.is_empty() {
                            plan = crate::control::reload::resolve_outbound_plan_for_target(
                                &generation_config,
                                &group_manager,
                                &outbound_name,
                                &context,
                            );
                        }
                        let (
                            retry_nodes,
                            _,
                            retry_feedback,
                            retry_selection_chains,
                            retry_health_ipver,
                        ) = unpack_tcp_score_plan(plan);
                        if retry_nodes.len() > 1
                            || retry_nodes
                                .first()
                                .is_some_and(|node| node.id != candidates[0].id)
                        {
                            let nodes: Vec<_> = retry_nodes.iter().take(3).collect();
                            let retry = self
                                .race_candidates(
                                    &nodes,
                                    original_dst,
                                    target_domain.clone(),
                                    &outbound_name,
                                    connect_timeout,
                                    overall_dial_timeout,
                                    Arc::clone(&runtime_generation),
                                    retry_health_ipver,
                                    &retry_feedback,
                                    false,
                                )
                                .await;
                            if retry.is_some() {
                                selection_chains = retry_selection_chains;
                            }
                            retried = retry;
                        }
                    }
                }
                match retried {
                    Some(pair) => pair,
                    None => {
                        self.stats.record_close(&outbound_name);
                        return Ok(());
                    }
                }
            }
        };

        let dscp_val = handoff.as_ref().map(|ho| ho.dscp).unwrap_or(0);

        let conn_upload = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let conn_download = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        if let Some(conn_id) = flow.track_if_enabled(|| {
            let id = uuid::Uuid::new_v4().to_string();
            let (rule, rule_payload) =
                matched_rule.unwrap_or_else(|| ("Fallback".to_string(), String::new()));
            crate::connection_tracker::ConnectionEntry {
                id,
                source: client_addr.to_string(),
                destination: original_dst.to_string(),
                proxy: node.name.clone(),
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
        }) {
            self.spawn_process_path_enrichment(conn_id, handoff.as_ref());
        }

        info!(
            network = "tcp",
            outbound = %outbound_name,
            dialer = %node.name,
            sniffed = target_domain.as_deref().unwrap_or(""),
            ip = %original_dst,
            dscp = dscp_val,
            src = %client_addr,
            "TCP connection: {} <-> {}", client_addr, original_dst,
        );

        if !sniff_result.buffered.is_empty() {
            use tokio::io::AsyncWriteExt;
            if let Err(e) = proxy_stream.stream.write_all(&sniff_result.buffered).await {
                warn!("Failed to write sniffed bytes to proxy: {}", e);
                self.stats.record_error(&outbound_name);
                self.stats.record_close(&outbound_name);
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::Io(e.kind()));
                }
                return Ok(());
            }
        }
        if let Some(reporter) = &score_reporter {
            reporter.tx(sniff_result.buffered.len() as u64);
        }

        // Zero-copy fast path: a direct dial yields plain `TcpStream`s on
        // both ends, so relay through `splice(2)` (with automatic lossless
        // fallback to the copy relay when the kernel rejects it). TLS- or
        // protocol-wrapped proxy streams keep the userspace copy relay.
        // Both paths update the connection's live byte counters as data flows.
        let first_response = score_reporter.as_ref().map(|reporter| {
            let reporter = reporter.clone();
            std::sync::Arc::new(move || reporter.first_response())
                as std::sync::Arc<dyn Fn() + Send + Sync>
        });
        let conn_progress = relay::RelayProgress {
            upload: conn_upload.clone(),
            download: conn_download.clone(),
            first_response,
        };
        let relay_result = match proxy_stream.into_tcp_stream() {
            Ok(upstream) => {
                relay::splice::relay_splice(
                    flow.stream_mut(),
                    upstream,
                    client_addr,
                    original_dst,
                    Some(conn_progress.clone()),
                )
                .await
            }
            Err(proxy_stream) => {
                relay::splice::relay_auto(
                    flow.stream_mut(),
                    proxy_stream.stream,
                    client_addr,
                    original_dst,
                    Some(conn_progress),
                )
                .await
            }
        };
        if let Some(reporter) = &score_reporter {
            let upload = conn_upload.load(std::sync::atomic::Ordering::Relaxed);
            let download = conn_download.load(std::sync::atomic::Ordering::Relaxed);
            reporter.tx(upload);
            reporter.rx(download);
            if download > 0 {
                reporter.first_response();
            }
        }
        flow.retire().await;

        match relay_result {
            Ok(relay_stats) => {
                self.stats.record_bytes(
                    &outbound_name,
                    relay_stats.client_to_proxy,
                    relay_stats.proxy_to_client,
                );
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::Success);
                }
                self.stats.record_close(&outbound_name);

                // Deposit a fresh connection for future reuse. Ready-capable
                // handlers get a fully-dialed, target-bound stream (handshake
                // paid here, off the critical path); others get a bare TCP
                // to the proxy server.
                if outbound_name != "direct" && outbound_name != "block" {
                    let node = node.clone();
                    let node_addr = format!("{}:{}", node.host(), node.port);
                    let pool = self.connection_pool.clone();
                    let registry = self.proxy_registry.clone();
                    let target_domain = target_domain.clone();
                    let generation = Arc::clone(&runtime_generation);
                    let pool_feedback = score_reporter
                        .as_ref()
                        .map(|reporter| reporter.feedback().streak_neutral());
                    let pool_health_family = health_ipver;
                    tokio::spawn(async move {
                        let (ready_capable, bare_capable) = registry
                            .find(node.protocol())
                            .map(|entry| {
                                (
                                    (entry.descriptor.pool_ready_streams)(&node),
                                    (entry.descriptor.pool_bare_tcp)(&node),
                                )
                            })
                            .unwrap_or((false, false));
                        if ready_capable {
                            let key = ConnectionPool::ready_key(
                                &node_addr,
                                original_dst,
                                target_domain.as_deref(),
                            );
                            // Only hot targets earn a speculative ready
                            // dial; a one-off flow gets none.
                            if !pool.note_target(&key) {
                                return;
                            }
                            let pool_reporter =
                                pool_feedback.as_ref().map(|feedback| feedback.start());
                            match registry
                                .dial_runtime(
                                    Arc::clone(&generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                            {
                                Ok(stream) => {
                                    if generation.is_shutdown() {
                                        if let Some(reporter) = &pool_reporter {
                                            reporter.finish(crate::group::ScoreOutcome::Shutdown);
                                        }
                                        return;
                                    }
                                    if let Some(reporter) = &pool_reporter {
                                        reporter.setup_succeeded();
                                        reporter.finish_setup_only();
                                    }
                                    pool.deposit_ready(&key, stream).await;
                                }
                                Err(e) => {
                                    if let Some(reporter) = &pool_reporter {
                                        reporter
                                            .setup_failed(score_runtime_outcome(&generation, &e));
                                    }
                                    debug!(
                                        "Pool deposit: ready dial to {} via {} failed: {}",
                                        original_dst, node_addr, e
                                    );
                                }
                            }
                            return;
                        }
                        if !bare_capable {
                            // Multiplexed protocols pool whole sessions
                            // instead; a bare TCP is useless to them.
                            return;
                        }
                        let pool_reporter = pool_feedback.as_ref().map(|feedback| {
                            feedback
                                .clone()
                                .with_context(crate::group::ScoreSelectionContext::aggregate(
                                    SelectionNetwork::Tcp,
                                    ProbeDomain::Tcp,
                                    pool_health_family,
                                ))
                                .start()
                        });
                        match generation
                            .scope_dials(honk_outbound::util::connect_outbound(
                                &node_addr,
                                connect_timeout,
                            ))
                            .await
                        {
                            Ok(stream) => {
                                if generation.is_shutdown() {
                                    if let Some(reporter) = &pool_reporter {
                                        reporter.finish(crate::group::ScoreOutcome::Shutdown);
                                    }
                                    return;
                                }
                                if is_tcp_stream_alive(&stream) {
                                    if let Some(reporter) = &pool_reporter {
                                        reporter.setup_succeeded();
                                        reporter.finish_setup_only();
                                    }
                                    pool.deposit_tcp(&node_addr, stream).await;
                                } else {
                                    if let Some(reporter) = &pool_reporter {
                                        reporter.setup_failed(crate::group::ScoreOutcome::Io(
                                            std::io::ErrorKind::ConnectionReset,
                                        ));
                                    }
                                    debug!("Pool deposit: stream to {} is dead", node_addr);
                                }
                            }
                            Err(e) => {
                                if let Some(reporter) = &pool_reporter {
                                    reporter.setup_failed(if generation.is_shutdown() {
                                        crate::group::ScoreOutcome::Shutdown
                                    } else {
                                        crate::group::ScoreOutcome::Io(e.kind())
                                    });
                                }
                                debug!("Pool deposit: connect to {} failed: {}", node_addr, e);
                            }
                        }
                    });
                }
            }
            Err(e) => {
                // The relay updates these atomics as every read/splice completes.
                // Preserve bytes moved before an I/O failure rather than turning
                // the whole flow into a synthetic zero-byte success.
                self.stats.record_bytes(
                    &outbound_name,
                    conn_upload.load(std::sync::atomic::Ordering::Relaxed),
                    conn_download.load(std::sync::atomic::Ordering::Relaxed),
                );
                let io_err = e.downcast_ref::<std::io::Error>();
                if let Some(io_err) = io_err {
                    if relay::is_ignorable_connection_error(io_err) {
                        debug!(
                            "TCP relay closed for {} -> {}: {}",
                            client_addr, original_dst, io_err
                        );
                    } else {
                        warn!("Relay error for {} -> {}: {}", client_addr, original_dst, e);
                    }
                } else {
                    warn!("Relay error for {} -> {}: {}", client_addr, original_dst, e);
                }
                self.stats.record_error(&outbound_name);
                self.stats.record_close(&outbound_name);
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::from_error(&e));
                }
            }
        }

        if let (Some(ref ho), Some(ref domain)) = (handoff, sniff_result.domain)
            && (ho.outbound >= OutboundIndex::UserBase as u8
                || ho.outbound == OutboundIndex::Direct as u8)
        {
            let mut ebpf = self.ebpf.write().await;
            let ob = if ho.outbound == OutboundIndex::Direct as u8 {
                OutboundIndex::Direct
            } else {
                OutboundIndex::from_user(ho.outbound as u32)
            };
            if let Err(e) = ebpf.add_domain_route(domain, ob) {
                debug!("Failed to add domain route for {}: {}", domain, e);
            }
        }

        Ok(())
    }

    /// Race the candidate dials: the first success wins, losers are
    /// cancelled, and fresh connections for losers are deposited into the
    /// pool (≤2 per race, off the critical path). Failures are reported via
    /// traffic-based thresholds to avoid killing a node from a single
    /// transient failure. Returns the winning stream and its already-owned
    /// node; `None` means every candidate failed (already logged) — close
    /// accounting stays with the caller.
    #[allow(clippy::too_many_arguments)]
    async fn race_candidates(
        &self,
        candidates: &[&Node],
        target: SocketAddr,
        target_domain: Option<String>,
        outbound_name: &str,
        connect_timeout: Duration,
        overall_dial_timeout: Duration,
        runtime_generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
        ipver: IpVersion,
        feedback: &HashMap<uuid::Uuid, crate::group::ScoreFeedback>,
        cold_urltest: bool,
    ) -> Option<(
        crate::proxy::ProxyStream,
        Node,
        Option<crate::group::ScoreReporter>,
    )> {
        let dial_deadline = tokio::time::Instant::now() + overall_dial_timeout;
        let ctx = self.clone();
        let outbound = outbound_name.to_string();
        let feedback = feedback.clone();

        let mut set = tokio::task::JoinSet::new();
        let started_reporters = Arc::new(parking_lot::Mutex::new(Vec::new()));
        for (idx, node) in candidates.iter().enumerate() {
            let ctx = ctx.clone();
            let node = (*node).clone();
            let target_domain = target_domain.clone();
            let generation = Arc::clone(&runtime_generation);
            let feedback = feedback.clone();
            let started_reporters = Arc::clone(&started_reporters);
            set.spawn(async move {
                if cold_urltest {
                    // Absolute releases make only candidate zero immediate;
                    // unreleased work has no dial permit and abort_all()
                    // cancels it before it can start.
                    wait_for_cold_urltest_release(idx).await;
                }
                let reporter = Arc::new(parking_lot::Mutex::new(None));
                let on_start = {
                    let feedback = feedback.get(&node.id).cloned();
                    let reporter = Arc::clone(&reporter);
                    move || {
                        let started = feedback.map(|feedback| feedback.start());
                        if let Some(reporter) = &started {
                            started_reporters.lock().push(reporter.clone());
                        }
                        *reporter.lock() = started;
                    }
                };
                let start = std::time::Instant::now();
                let per_dial_timeout = connect_timeout * 3;
                let result = tokio::time::timeout(
                    per_dial_timeout,
                    Self::dial_pooled(
                        &ctx.proxy_registry,
                        &ctx.connection_pool,
                        &generation,
                        &node,
                        (target, target_domain.as_deref()),
                        connect_timeout,
                        on_start,
                    ),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(anyhow::Error::new(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("dial timed out after {per_dial_timeout:?}"),
                    )))
                });
                let elapsed = start.elapsed();
                let reporter = reporter.lock().clone();
                match &result {
                    Ok(_) => {
                        if let Some(reporter) = &reporter {
                            reporter.setup_succeeded();
                        }
                    }
                    Err(error) => {
                        if let Some(reporter) = &reporter {
                            reporter.setup_failed(score_runtime_outcome(&generation, error));
                        }
                    }
                }
                (result, idx, elapsed, node, reporter)
            });
        }

        let mut last_err: Option<(String, String)> = None;
        let mut first_err: Option<(String, String)> = None;
        let mut timeout_count: usize = 0;
        let mut winner: Option<(
            crate::proxy::ProxyStream,
            usize,
            Node,
            Option<crate::group::ScoreReporter>,
        )> = None;
        let mut remaining = set.len();

        loop {
            if remaining == 0 {
                break;
            }
            remaining -= 1;
            match tokio::time::timeout_at(dial_deadline, set.join_next()).await {
                Ok(Some(task_result)) => match task_result {
                    Ok((Ok((stream, fresh)), idx, elapsed, node, reporter)) => {
                        ctx.alive_set
                            .report_available_traffic(node.id, ProbeDomain::Tcp, ipver);
                        // Real-traffic degradation fast path: a fresh
                        // network dial far above the node's own EMA
                        // counts toward strike demotion (3 in a row);
                        // the emergency probe verifies the suspicion.
                        if fresh
                            && ctx.alive_set.report_dial_latency(
                                node.id,
                                ProbeDomain::Tcp,
                                ipver,
                                elapsed,
                            )
                        {
                            ctx.alive_set.notify_check_tcp(node.id);
                        }
                        winner = Some((stream, idx, node, reporter));
                        set.abort_all();
                        break;
                    }
                    Ok((Err(e), _idx, _elapsed, node, _reporter)) => {
                        debug!("Parallel dial to {} failed: {}", node.name, e);
                        ctx.stats.record_error(&outbound);
                        report_dial_failure_if_current(
                            &runtime_generation,
                            &ctx.alive_set,
                            node.id,
                            ProbeDomain::Tcp,
                            ipver,
                        );
                        let msg = e.to_string();
                        if msg.starts_with("dial timed out after") {
                            timeout_count += 1;
                        }
                        if first_err.is_none() {
                            first_err = Some((msg.clone(), node.name.clone()));
                        }
                        if remaining == 0 {
                            last_err = Some((msg, node.name.clone()));
                        }
                    }
                    Err(_join_err) => {}
                },
                Ok(None) => break,
                Err(_elapsed) => {
                    timeout_started_score_reporters(&started_reporters);
                    set.abort_all();
                    warn!(
                        "Overall dial deadline reached for outbound '{}' ({} candidates, {} remaining)",
                        outbound_name,
                        candidates.len(),
                        remaining
                    );
                    break;
                }
            }
        }

        // Drain any remaining aborted tasks to avoid JoinSet drop panic.
        while (set.join_next().await).is_some() {}

        // so the pool stays warm after a parallel-dial race. Limit to 2 deposits
        // per race to avoid thundering herd on the proxy servers.
        // Ready-capable handlers get a fully-dialed stream (handshake
        // included, paid off the critical path); others get a bare TCP.
        if outbound_name != "direct"
            && outbound_name != "block"
            && let Some((_, winning_idx, ..)) = &winner
        {
            let mut deposit_count = 0u32;
            for (idx, node) in candidates.iter().enumerate() {
                if idx == *winning_idx {
                    continue;
                }
                if deposit_count >= 2 {
                    break;
                }
                let node = (*node).clone();
                let node_addr = format!("{}:{}", node.host(), node.port);
                let pool = ctx.connection_pool.clone();
                let registry = ctx.proxy_registry.clone();
                let target_domain = target_domain.clone();
                let generation = Arc::clone(&runtime_generation);
                let pool_feedback = feedback
                    .get(&node.id)
                    .cloned()
                    .map(|feedback| feedback.streak_neutral());
                let pool_health_family = ipver;
                deposit_count += 1;
                tokio::spawn(async move {
                    let (ready_capable, bare_capable) = registry
                        .find(node.protocol())
                        .map(|entry| {
                            (
                                (entry.descriptor.pool_ready_streams)(&node),
                                (entry.descriptor.pool_bare_tcp)(&node),
                            )
                        })
                        .unwrap_or((false, false));
                    if ready_capable {
                        let key =
                            ConnectionPool::ready_key(&node_addr, target, target_domain.as_deref());
                        // Only hot targets earn a speculative ready
                        // dial; a one-off flow gets none.
                        let Some(_warm_guard) = pool.try_begin_warm(&key) else {
                            return;
                        };
                        let pool_reporter = pool_feedback.as_ref().map(|feedback| feedback.start());
                        match registry
                            .dial_runtime(
                                Arc::clone(&generation),
                                node.id,
                                target,
                                target_domain.as_deref(),
                                connect_timeout,
                            )
                            .await
                        {
                            Ok(stream) => {
                                if generation.is_shutdown() {
                                    if let Some(reporter) = &pool_reporter {
                                        reporter.finish(crate::group::ScoreOutcome::Shutdown);
                                    }
                                    return;
                                }
                                if let Some(reporter) = &pool_reporter {
                                    reporter.setup_succeeded();
                                    reporter.finish_setup_only();
                                }
                                pool.deposit_ready(&key, stream).await;
                            }
                            Err(e) => {
                                if let Some(reporter) = &pool_reporter {
                                    reporter.setup_failed(score_runtime_outcome(&generation, &e));
                                }
                                debug!(
                                    "Post-race pool deposit: ready dial to {} via {} failed: {}",
                                    target, node_addr, e
                                );
                            }
                        }
                        return;
                    }
                    if !bare_capable {
                        // Multiplexed protocols pool whole sessions
                        // instead; a bare TCP is useless to them.
                        return;
                    }
                    let pool_reporter = pool_feedback.as_ref().map(|feedback| {
                        feedback
                            .clone()
                            .with_context(crate::group::ScoreSelectionContext::aggregate(
                                SelectionNetwork::Tcp,
                                ProbeDomain::Tcp,
                                pool_health_family,
                            ))
                            .start()
                    });
                    match generation
                        .scope_dials(honk_outbound::util::connect_outbound(
                            &node_addr,
                            connect_timeout,
                        ))
                        .await
                    {
                        Ok(stream) => {
                            if generation.is_shutdown() {
                                if let Some(reporter) = &pool_reporter {
                                    reporter.finish(crate::group::ScoreOutcome::Shutdown);
                                }
                                return;
                            }
                            if is_tcp_stream_alive(&stream) {
                                if let Some(reporter) = &pool_reporter {
                                    reporter.setup_succeeded();
                                    reporter.finish_setup_only();
                                }
                                pool.deposit_tcp(&node_addr, stream).await;
                            } else {
                                if let Some(reporter) = &pool_reporter {
                                    reporter.setup_failed(crate::group::ScoreOutcome::Io(
                                        std::io::ErrorKind::ConnectionReset,
                                    ));
                                }
                                debug!("Post-race pool deposit: stream to {} is dead", node_addr);
                            }
                        }
                        Err(e) => {
                            if let Some(reporter) = &pool_reporter {
                                reporter.setup_failed(if generation.is_shutdown() {
                                    crate::group::ScoreOutcome::Shutdown
                                } else {
                                    crate::group::ScoreOutcome::Io(e.kind())
                                });
                            }
                            debug!(
                                "Post-race pool deposit: connect to {} failed: {}",
                                node_addr, e
                            );
                        }
                    }
                });
            }
        }

        match winner {
            Some((stream, _, node, reporter)) => Some((stream, node, reporter)),
            None => {
                if let Some((last_msg, last_name)) = last_err {
                    let (first_msg, first_name) =
                        first_err.unwrap_or_else(|| (last_msg.clone(), last_name.clone()));
                    if outbound_name == "direct" || outbound_name == "block" {
                        debug!(
                            "Direct/block dial to {} failed ({}): {}",
                            target, last_name, last_msg
                        );
                    } else {
                        warn!(
                            "All {} candidate(s) failed to dial {} ({} timed out; first error from '{}': {}; last error from '{}': {})",
                            candidates.len(),
                            target,
                            timeout_count,
                            first_name,
                            first_msg,
                            last_name,
                            last_msg
                        );
                    }
                }
                None
            }
        }
    }

    /// Dial through a node using the TCP connection pool.
    ///
    /// Acquisition order:
    /// 1. a pooled *ready* stream (full handshake already completed for
    ///    this exact node+target) — skips both the TCP connect and the
    ///    protocol handshake;
    /// 2. a pooled raw `TcpStream` to the proxy server — skips the TCP
    ///    connect, protocol handshake still runs via `dial_with_tcp()`;
    /// 3. a fresh full `dial()`.
    ///
    /// Set `HONK_POOL_DISABLE=1` to bypass both pools entirely (fresh dial
    /// every time) — an A/B switch for diagnosing pool-related stalls.
    ///
    /// Returns the stream plus `fresh_network`: false ONLY on a ready-pool
    /// acquire (local pool pop, no network round trip); bare-pool
    /// handshakes, warm logical streams, and fresh dials all perform ≥1
    /// round trip through the node and report true.
    async fn dial_pooled(
        registry: &ProxyRegistry,
        pool: &ConnectionPool,
        generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
        node: &Node,
        target: (SocketAddr, Option<&str>),
        connect_timeout: Duration,
        on_start: impl FnOnce() + Send + 'static,
    ) -> anyhow::Result<(crate::proxy::ProxyStream, bool)> {
        let (target, target_domain) = target;
        static POOL_DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let pool_disabled = *POOL_DISABLED.get_or_init(|| {
            std::env::var("HONK_POOL_DISABLE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        });
        let on_start = Arc::new(parking_lot::Mutex::new(Some(on_start)));

        let addr = format!("{}:{}", node.host(), node.port);
        let protocol = node.protocol();
        let entry = registry
            .find(protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;

        if !pool_disabled && (entry.descriptor.pool_ready_streams)(node) {
            let key = ConnectionPool::ready_key(&addr, target, target_domain);
            if let Some(stream) = pool.acquire_ready(&key).await {
                tracing::debug!(
                    "Pooled ready stream via {} acquired for {} (handshake skipped)",
                    addr,
                    target
                );
                if let Some(on_start) = on_start.lock().take() {
                    on_start();
                }
                return Ok((stream, false));
            }
        }

        let dial = async {
            // A raw pooled TCP still needs its protocol handshake. Multiplexed
            // protocols opt out because their node runtime owns the transport.
            if !pool_disabled
                && (entry.descriptor.pool_bare_tcp)(node)
                && let Some(tcp) = pool.acquire_tcp(&addr).await
            {
                if let Some(on_start) = on_start.lock().take() {
                    on_start();
                }
                tracing::debug!("Pooled TCP to {} acquired for {}", addr, target);
                return entry
                    .tcp
                    .dial_with_tcp(node, target, target_domain, tcp, connect_timeout)
                    .await
                    .map(|stream| (stream, true));
            }

            // Pool miss (or pools disabled) — fresh connect through the
            // flow's pinned generation. A candidate absent from the generation
            // (e.g. a hand-built test config without the built-in nodes
            // injected) falls back to the stateless node-based dial.
            tracing::debug!("Fresh TCP connect to {} for {}", addr, target);
            if generation.get(&node.id).is_some() {
                registry
                    .dial_runtime(
                        Arc::clone(generation),
                        node.id,
                        target,
                        target_domain,
                        connect_timeout,
                    )
                    .await
                    .map(|stream| (stream, true))
            } else {
                entry
                    .tcp
                    .dial(node, target, target_domain, connect_timeout)
                    .await
                    .map(|stream| (stream, true))
            }
        };
        let on_start = Arc::clone(&on_start);
        generation
            .scope_dials_with_start(dial, move || {
                if let Some(on_start) = on_start.lock().take() {
                    on_start();
                }
            })
            .await
    }
}

#[cfg(test)]
mod score_tests {
    use super::*;

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
        };
        let (nodes, mode, feedback, selection_chains, family) = unpack_tcp_score_plan(plan);

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
