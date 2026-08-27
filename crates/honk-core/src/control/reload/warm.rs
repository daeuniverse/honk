use super::*;

const SELECTOR_WARM_RECONCILE_INTERVAL: Duration = Duration::from_secs(10);
#[derive(Clone)]
pub(in crate::control) struct SelectorWarmResources {
    pub(in crate::control) generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    pub(in crate::control) proxy_registry: Arc<ProxyRegistry>,
    pub(in crate::control) connection_pool: Arc<ConnectionPool>,
    pub(in crate::control) group_manager: crate::group::SharedGroupManager,
    pub(in crate::control) stats: Arc<StatsManager>,
    pub(in crate::control) selected_ids:
        Arc<parking_lot::Mutex<std::collections::HashSet<uuid::Uuid>>>,
    pub(in crate::control) bare_warm:
        Arc<parking_lot::Mutex<std::collections::HashMap<uuid::Uuid, String>>>,
}

pub(super) struct SelectorWarmCoordinator {
    pub(super) config: Arc<tokio::sync::RwLock<Arc<Config>>>,
    pub(super) group_manager: crate::group::SharedGroupManager,
    pub(super) notify: Arc<tokio::sync::Notify>,
    pub(super) resources: SelectorWarmResources,
}

/// One configured leaf per Selector, preserving config order and deduplicating
/// nodes shared by several groups. The group manager intentionally resolves
/// the configured choice rather than liveness-falling away from it.
pub(in crate::control) fn selector_warm_candidates(
    config: &Config,
    group_manager: &GroupManager,
    generation: &honk_outbound::runtime::OutboundRuntimeRegistry,
) -> Vec<Node> {
    if generation.is_shutdown() {
        return Vec::new();
    }
    let configured: std::collections::HashSet<uuid::Uuid> =
        config.nodes.iter().map(|node| node.id).collect();
    let mut seen = std::collections::HashSet::new();
    config
        .groups
        .iter()
        .filter(|group| group.policy == GroupPolicy::Selector)
        .filter_map(|group| group_manager.selector_warm_node(&group.name))
        .filter(|node| {
            !matches!(node.protocol, NodeProtocol::Direct | NodeProtocol::Block)
                && configured.contains(&node.id)
                && generation.get(&node.id).is_some()
                && seen.insert(node.id)
        })
        .cloned()
        .collect()
}

pub(super) async fn run_selector_warm_coordinator(context: SelectorWarmCoordinator) {
    let SelectorWarmCoordinator {
        config,
        group_manager,
        notify,
        resources,
    } = context;
    loop {
        if resources.generation.is_shutdown() {
            return;
        }
        let (connect_timeout, candidates) = {
            let config = config.read().await;
            let manager = group_manager.read().clone();
            (
                Duration::from_millis(config.global.connect_timeout_ms),
                selector_warm_candidates(&config, &manager, &resources.generation),
            )
        };
        reconcile_selector_warm(candidates, &resources, connect_timeout).await;
        if resources.generation.is_shutdown() {
            return;
        }
        tokio::select! {
            _ = notify.notified() => {}
            _ = tokio::time::sleep(SELECTOR_WARM_RECONCILE_INTERVAL) => {}
        }
    }
}

async fn reconcile_selector_warm(
    candidates: Vec<Node>,
    resources: &SelectorWarmResources,
    connect_timeout: Duration,
) {
    let SelectorWarmResources {
        generation,
        connection_pool,
        stats,
        selected_ids,
        bare_warm,
        ..
    } = resources;
    let desired: std::collections::HashSet<uuid::Uuid> =
        candidates.iter().map(|node| node.id).collect();
    let previous = selected_ids.lock().clone();
    for node_id in previous.difference(&desired) {
        if let Some(runtime) = generation.get(node_id) {
            runtime
                .release_warm(honk_outbound::runtime::WarmRetention::Selector)
                .await;
        }
        stats.clear_warm(*node_id, crate::stats::WarmReason::Selector);
    }
    *selected_ids.lock() = desired.clone();

    let stale_bare: Vec<String> = {
        let mut retained = bare_warm.lock();
        let stale: Vec<uuid::Uuid> = retained
            .keys()
            .filter(|id| !desired.contains(id))
            .copied()
            .collect();
        stale
            .into_iter()
            .filter_map(|id| retained.remove(&id))
            .collect()
    };
    for addr in stale_bare {
        connection_pool.purge_bare(&addr);
    }

    let mut pending = candidates.into_iter();
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        while tasks.len() < 4 {
            let Some(node) = pending.next() else {
                break;
            };
            tasks.spawn(warm_selector_candidate(
                node,
                resources.clone(),
                connect_timeout,
            ));
        }
        if tasks.is_empty() {
            break;
        }
        let _ = tasks.join_next().await;
    }
}

pub(in crate::control) async fn warm_selector_candidate(
    node: Node,
    resources: SelectorWarmResources,
    connect_timeout: Duration,
) {
    let SelectorWarmResources {
        generation,
        proxy_registry,
        connection_pool,
        group_manager,
        stats,
        bare_warm,
        ..
    } = resources;
    // Purge a moved endpoint before redial: failure must not keep the old
    // socket pinned under a stable node ID.
    let descriptor = honk_outbound::descriptor::descriptor(node.protocol);
    let bare_addr =
        (descriptor.pool_bare_tcp)(&node).then(|| format!("{}:{}", node.host(), node.port));
    let stale = {
        let mut retained = bare_warm.lock();
        match (retained.get(&node.id), bare_addr.as_ref()) {
            (Some(old), Some(current)) if old == current => None,
            (Some(_), _) => retained.remove(&node.id),
            (None, _) => None,
        }
    };
    if let Some(stale) = stale {
        connection_pool.purge_bare(&stale);
        stats.clear_warm(node.id, crate::stats::WarmReason::Selector);
    }

    if descriptor.has_generation_runtime(&node) {
        let reporter = group_manager
            .read()
            .feedback_for_node(
                node.id,
                crate::group::ScoreSelectionContext::aggregate(
                    crate::group::SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .map(|feedback| feedback.start());
        match proxy_registry
            .warm_session(Arc::clone(&generation), node.id, connect_timeout)
            .await
        {
            Ok(honk_outbound::proxy::WarmOutcome::Ready) => {
                if let Some(reporter) = &reporter {
                    reporter.setup_succeeded();
                    reporter.finish(crate::group::ScoreOutcome::Success);
                }
                if let Some(addr) = bare_warm.lock().remove(&node.id) {
                    connection_pool.purge_bare(&addr);
                }
                stats.mark_warm(node.id, crate::stats::WarmReason::Selector);
                return;
            }
            Ok(honk_outbound::proxy::WarmOutcome::NotApplicable) => {}
            Err(error) if generation.is_shutdown() => {
                if let Some(reporter) = &reporter {
                    reporter.finish(crate::group::ScoreOutcome::Shutdown);
                }
                debug!(node = %node.name, %error, "Selector warm generation ended");
                return;
            }
            Err(error) => {
                if let Some(reporter) = &reporter {
                    reporter.setup_failed(if error.is::<tokio::time::error::Elapsed>() {
                        crate::group::ScoreOutcome::Timeout
                    } else {
                        crate::group::ScoreOutcome::from_error(&error)
                    });
                }
                debug!(node = %node.name, %error, "Selector warm session failed");
                return;
            }
        }
    }

    let Some(addr) = bare_addr else {
        return;
    };
    if !connection_pool.has_live_bare_entry(&addr) {
        let reporter = group_manager
            .read()
            .feedback_for_node(
                node.id,
                crate::group::ScoreSelectionContext::aggregate(
                    crate::group::SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .map(|feedback| feedback.start());
        let stream = match honk_outbound::util::connect_outbound(&addr, connect_timeout).await {
            Ok(_) if generation.is_shutdown() => {
                if let Some(reporter) = &reporter {
                    reporter.finish(crate::group::ScoreOutcome::Shutdown);
                }
                return;
            }
            Ok(stream) if is_tcp_stream_alive(&stream) => stream,
            Ok(_) => {
                if let Some(reporter) = &reporter {
                    reporter.setup_failed(crate::group::ScoreOutcome::Io(
                        io::ErrorKind::ConnectionAborted,
                    ));
                }
                return;
            }
            Err(error) => {
                if let Some(reporter) = &reporter {
                    reporter.setup_failed(if error.kind() == io::ErrorKind::TimedOut {
                        crate::group::ScoreOutcome::Timeout
                    } else {
                        crate::group::ScoreOutcome::Io(error.kind())
                    });
                }
                debug!(node = %node.name, %error, "Selector warm bare TCP failed");
                return;
            }
        };
        if let Some(reporter) = &reporter {
            reporter.setup_succeeded();
        }
        connection_pool.deposit_tcp(&addr, stream).await;
        if let Some(reporter) = &reporter {
            reporter.finish(crate::group::ScoreOutcome::Success);
        }
    }
    if connection_pool.has_live_bare_entry(&addr) {
        let old = bare_warm.lock().insert(node.id, addr.clone());
        if let Some(old) = old.filter(|old| old != &addr) {
            connection_pool.purge_bare(&old);
        }
        stats.mark_warm(node.id, crate::stats::WarmReason::Selector);
    }
}

/// Select warm candidates: the top `count` UDP leaves (latency order, capped
/// at three) of every configured group, for both IP versions. This replaces
/// winner-only warming: each pass re-evaluates the latency order, so freshly
/// measured fast leaves get reusable session state before they win a
/// selection. Cold URLTest groups contribute their full ranked list. UUIDs
/// are deduplicated across groups; direct/block leaves and nodes without a
/// reusable UDP-capable generation runtime stay out.
///
/// On top of the per-group top-N, a process-wide cap of `4 × count` keeps
/// retained resources bounded as the group count grows. The merged set is
/// re-ranked by global UDP latency and truncated, sacrificing only the
/// slowest leaves.
pub(in crate::control) fn udp_warm_candidates(
    config: &Config,
    group_manager: &GroupManager,
    generation: &honk_outbound::runtime::OutboundRuntimeRegistry,
    count: usize,
) -> Vec<uuid::Uuid> {
    if count == 0 || generation.is_shutdown() {
        return Vec::new();
    }
    let per_group = count.min(3);
    let total_cap = count.saturating_mul(4);
    let configured_ids: std::collections::HashSet<uuid::Uuid> =
        config.nodes.iter().map(|node| node.id).collect();
    let mut selected: Vec<(uuid::Uuid, Duration)> = Vec::new();
    for group in &config.groups {
        for ipver in [IpVersion::V4, IpVersion::V6] {
            let mut leaves = group_manager.ranked_udp_leaves(&group.name, ipver, per_group);
            // `flatten_candidates` covers sub-groups but not a bare `final:`
            // hop — resolve one final hop so final-only groups still warm
            // their terminal leaves.
            if leaves.is_empty()
                && let Some(final_name) = group_manager.get_final_outbound(&group.name)
            {
                leaves = group_manager.ranked_udp_leaves(&final_name, ipver, per_group);
            }
            for node in leaves {
                if matches!(
                    node.protocol,
                    honk_config::types::NodeProtocol::Direct
                        | honk_config::types::NodeProtocol::Block
                ) {
                    continue;
                }
                if !configured_ids.contains(&node.id) {
                    continue;
                }
                let Some(runtime) = generation.get(&node.id) else {
                    continue;
                };
                if !runtime.udp_capable
                    || !honk_outbound::descriptor::descriptor(node.protocol)
                        .has_generation_runtime(node)
                {
                    continue;
                }
                let latency = group_manager.udp_latency(node, ipver);
                match selected.iter_mut().find(|(id, _)| *id == node.id) {
                    Some(entry) => entry.1 = entry.1.min(latency),
                    None => selected.push((node.id, latency)),
                }
            }
        }
    }
    // Stable sort: unmeasured leaves (Duration::MAX) keep their per-group
    // order below every measured one.
    selected.sort_by_key(|(_, latency)| *latency);
    selected.truncate(total_cap);
    selected.into_iter().map(|(id, _)| id).collect()
}

pub(super) async fn reconcile_udp_warm_retention(
    candidates: &[uuid::Uuid],
    generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    stats: &Arc<StatsManager>,
    retained_ids: &Arc<parking_lot::Mutex<std::collections::HashSet<uuid::Uuid>>>,
) {
    let desired: std::collections::HashSet<uuid::Uuid> = candidates.iter().copied().collect();
    let previous = retained_ids.lock().clone();
    for node_id in previous.difference(&desired) {
        if let Some(runtime) = generation.get(node_id) {
            runtime
                .release_warm(honk_outbound::runtime::WarmRetention::Udp)
                .await;
        }
        stats.clear_warm(*node_id, crate::stats::WarmReason::Udp);
    }
    *retained_ids.lock() = desired;
}

/// Periodic warm coordinator: one immediate pass, then another after each
/// completed dispatch batch plus `check_interval` (floored at 10s). Every pass
/// re-ranks the per-group top-N from current probe data; handlers reuse live
/// sessions/clients, so repeat dispatch is cheap. Exits when the count is
/// disabled or the generation turns terminal (reload/shutdown replaces it).
pub(super) async fn run_udp_warm_coordinator<F, Fut>(
    config: Arc<tokio::sync::RwLock<Arc<Config>>>,
    group_manager: crate::group::SharedGroupManager,
    generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    stats: Arc<StatsManager>,
    dispatch: Arc<F>,
    retained_ids: Arc<parking_lot::Mutex<std::collections::HashSet<uuid::Uuid>>>,
) where
    F: Fn(Arc<honk_outbound::runtime::OutboundRuntimeRegistry>, uuid::Uuid) -> Fut
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = anyhow::Result<honk_outbound::proxy::WarmOutcome>> + Send + 'static,
{
    loop {
        if generation.is_shutdown() {
            return;
        }
        let (interval, count, candidates) = {
            let cfg = config.read().await.clone();
            let count = cfg.global.udp_warm_node_count;
            let interval = Duration::from_secs(cfg.global.check_interval_secs.max(10));
            let manager = group_manager.read().clone();
            let candidates = udp_warm_candidates(&cfg, &manager, &generation, count);
            (interval, count, candidates)
        };
        if count == 0 {
            reconcile_udp_warm_retention(&[], &generation, &stats, &retained_ids).await;
            return;
        }
        reconcile_udp_warm_retention(&candidates, &generation, &stats, &retained_ids).await;
        run_udp_warm_dispatches(
            candidates,
            generation.clone(),
            stats.clone(),
            dispatch.clone(),
        )
        .await;
        if generation.is_shutdown() {
            return;
        }
        tokio::time::sleep(interval).await;
    }
}

/// Execute generation-owned warm dispatches with exactly the fixed aggregate
/// metrics contract. Neither cancellation nor a terminal generation mutates
/// outbound health or per-node error state.
pub(in crate::control) async fn run_udp_warm_dispatches<F, Fut>(
    candidates: Vec<uuid::Uuid>,
    generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    stats: Arc<StatsManager>,
    dispatch: Arc<F>,
) where
    F: Fn(Arc<honk_outbound::runtime::OutboundRuntimeRegistry>, uuid::Uuid) -> Fut
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = anyhow::Result<honk_outbound::proxy::WarmOutcome>> + Send + 'static,
{
    if candidates.is_empty() {
        return;
    }
    let mut pending = candidates.into_iter();
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        while tasks.len() < 4 {
            let Some(node_id) = pending.next() else {
                break;
            };
            let generation = Arc::clone(&generation);
            let stats = Arc::clone(&stats);
            let dispatch = Arc::clone(&dispatch);
            tasks.spawn(async move {
                stats.record_udp_warm_attempt();
                match dispatch(generation.clone(), node_id).await {
                    Ok(honk_outbound::proxy::WarmOutcome::Ready) => {
                        stats.record_udp_warm_success();
                        stats.mark_warm(node_id, crate::stats::WarmReason::Udp);
                    }
                    Ok(honk_outbound::proxy::WarmOutcome::NotApplicable) => {}
                    Err(err) if generation.is_shutdown() => {
                        debug!("UDP warm ended with terminal generation: {err}");
                    }
                    Err(err) => {
                        debug!("UDP warm failed: {err}");
                        stats.record_udp_warm_failure();
                    }
                }
            });
        }
        if tasks.is_empty() {
            break;
        }
        if let Some(Err(err)) = tasks.join_next().await
            && err.is_panic()
            && !generation.is_shutdown()
        {
            debug!("UDP warm dispatch panicked: {err}");
            stats.record_udp_warm_failure();
        }
    }
}

impl ControlPlane {
    /// Stop and join the prior generation's warm coordinator. Aborting the
    /// parent drops its JoinSet, so in-flight child dispatches are cancelled
    /// without becoming health or per-outbound error events.
    pub(in crate::control) async fn stop_udp_warm_coordinator(&self) {
        let handle = self.udp_warm_task.lock().await.take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
    }

    /// Start a warm coordinator bound to one immutable runtime generation.
    /// A zero count releases the prior UDP retention set without creating a
    /// task or touching attempt metrics. Positive counts re-rank after every
    /// probe cycle.
    pub(in crate::control) async fn start_udp_warm_coordinator(
        &self,
        generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    ) {
        if generation.is_shutdown() {
            return;
        }
        let count = self.config.read().await.global.udp_warm_node_count;
        if count == 0 {
            reconcile_udp_warm_retention(&[], &generation, &self.stats, &self.udp_warm_ids).await;
            return;
        }
        let connect_timeout = {
            let config = self.config.read().await;
            Duration::from_millis(config.global.connect_timeout_ms)
        };
        let proxy_registry = self.proxy_registry.clone();
        let group_manager = self.group_manager.clone();
        let dispatch = Arc::new(
            move |generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
                  node_id: uuid::Uuid| {
                let proxy_registry = proxy_registry.clone();
                let group_manager = group_manager.clone();
                async move {
                    let reporter = generation
                        .get(&node_id)
                        .filter(|runtime| {
                            runtime.udp_capable
                                && honk_outbound::descriptor::descriptor(runtime.node.protocol)
                                    .has_generation_runtime(&runtime.node)
                        })
                        .and_then(|_| {
                            group_manager.read().feedback_for_node(
                                node_id,
                                crate::group::ScoreSelectionContext::aggregate(
                                    crate::group::SelectionNetwork::Udp,
                                    ProbeDomain::DataUdp,
                                    IpVersion::V4,
                                ),
                            )
                        })
                        .map(|feedback| feedback.start());
                    let result = proxy_registry
                        .warm_udp(generation.clone(), node_id, connect_timeout)
                        .await;
                    match &result {
                        Ok(honk_outbound::proxy::WarmOutcome::Ready) => {
                            if let Some(reporter) = &reporter {
                                reporter.setup_succeeded();
                                reporter.finish(crate::group::ScoreOutcome::Success);
                            }
                        }
                        Ok(honk_outbound::proxy::WarmOutcome::NotApplicable) => {}
                        Err(_) if generation.is_shutdown() => {
                            if let Some(reporter) = &reporter {
                                reporter.finish(crate::group::ScoreOutcome::Shutdown);
                            }
                        }
                        Err(error) => {
                            if let Some(reporter) = &reporter {
                                reporter.setup_failed(
                                    if error.is::<tokio::time::error::Elapsed>() {
                                        crate::group::ScoreOutcome::Timeout
                                    } else {
                                        crate::group::ScoreOutcome::from_error(error)
                                    },
                                );
                            }
                        }
                    }
                    result
                }
            },
        );
        let handle = tokio::spawn(run_udp_warm_coordinator(
            self.config.clone(),
            self.group_manager.clone(),
            generation,
            self.stats.clone(),
            dispatch,
            self.udp_warm_ids.clone(),
        ));
        *self.udp_warm_task.lock().await = Some(handle);
    }

    pub(in crate::control) async fn stop_selector_warm_coordinator(&self) {
        let handle = self.selector_warm_task.lock().await.take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
    }

    /// Pin every configured Selector leaf in this immutable runtime
    /// generation. Choice changes wake the task immediately; the periodic
    /// pass repairs independently lost sessions and consumed bare sockets.
    pub(in crate::control) async fn start_selector_warm_coordinator(
        &self,
        generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    ) {
        if generation.is_shutdown() {
            return;
        }
        let handle = tokio::spawn(run_selector_warm_coordinator(SelectorWarmCoordinator {
            config: self.config.clone(),
            group_manager: self.group_manager.clone(),
            notify: self.selector_warm_notify.clone(),
            resources: SelectorWarmResources {
                generation,
                proxy_registry: self.proxy_registry.clone(),
                connection_pool: self.connection_pool.clone(),
                group_manager: self.group_manager.clone(),
                stats: self.stats.clone(),
                selected_ids: self.selector_warm_ids.clone(),
                bare_warm: self.selector_bare_warm.clone(),
            },
        }));
        *self.selector_warm_task.lock().await = Some(handle);
    }
}
