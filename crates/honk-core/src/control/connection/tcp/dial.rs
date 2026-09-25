use super::*;

impl ControlPlaneHandle {
    /// Race the candidate dials: the first success wins, losers are
    /// cancelled, and fresh connections for losers are deposited into the
    /// pool (≤2 per race, off the critical path). Failures are reported via
    /// traffic-based thresholds to avoid killing a node from a single
    /// transient failure. Returns the winning stream and its already-owned
    /// node; `Ok(None)` means every candidate failed. Local refusal remains
    /// terminal as `Err`; close accounting stays with the caller.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn race_candidates(
        &self,
        candidates: &[&Node],
        target: SocketAddr,
        target_domain: Option<String>,
        outbound_name: &str,
        direct_mark: Option<honk_outbound::proxy::DirectMark>,
        connect_timeout: Duration,
        dial_deadline: tokio::time::Instant,
        runtime_generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
        ipver: IpVersion,
        feedback: &HashMap<uuid::Uuid, crate::group::ScoreAttempt>,
        cold_urltest: bool,
    ) -> anyhow::Result<
        Option<(
            crate::proxy::ProxyStream,
            Node,
            Option<crate::group::ScoreReporter>,
        )>,
    > {
        anyhow::ensure!(
            !runtime_generation.is_shutdown(),
            "outbound runtime generation is shut down"
        );
        if tokio::time::Instant::now() >= dial_deadline {
            return Ok(None);
        }
        let ctx = self.clone();
        let outbound = outbound_name.to_string();

        let mut set = tokio::task::JoinSet::new();
        let started_reporters = Arc::new(parking_lot::Mutex::new(Vec::new()));
        for (idx, node) in candidates.iter().enumerate() {
            let ctx = ctx.clone();
            let node = (*node).clone();
            let target_domain = target_domain.clone();
            let generation = Arc::clone(&runtime_generation);
            let feedback = feedback.get(&node.id).cloned();
            let started_reporters = Arc::clone(&started_reporters);
            set.spawn(async move {
                if cold_urltest {
                    // Absolute releases make only candidate zero immediate;
                    // unreleased work has no dial permit and abort_all()
                    // cancels it before it can start.
                    wait_for_cold_urltest_release(idx).await;
                }
                let business = match feedback
                    .as_ref()
                    .map(crate::group::ScoreAttempt::begin)
                    .transpose()
                {
                    Ok(business) => business,
                    Err(error) => return (Err(error.into()), idx, Duration::ZERO, node, None),
                };
                let score = Arc::new(parking_lot::Mutex::new((business, None)));
                let on_start = {
                    let score = Arc::clone(&score);
                    move || {
                        let mut score = score.lock();
                        let started = score.0.take().map(crate::group::ScoreBusinessGuard::start);
                        if let Some(reporter) = &started {
                            started_reporters.lock().push(reporter.clone());
                        }
                        score.1 = started;
                    }
                };
                let scope = generation.dial_scope(on_start);
                let start = std::time::Instant::now();
                let per_dial_timeout = connect_timeout * 3;
                let result = {
                    let mut dial = std::pin::pin!(Self::dial_pooled(
                        &ctx.proxy_registry,
                        &ctx.connection_pool,
                        &generation,
                        &node,
                        (target, target_domain.as_deref()),
                        connect_timeout,
                        direct_mark,
                        &scope,
                    ));
                    // Poll the dial before the timer, and keep its pending
                    // acquisitions alive until the timeout is classified.
                    tokio::time::timeout(per_dial_timeout, dial.as_mut())
                        .await
                        .unwrap_or_else(|_| {
                            if scope.is_waiting_for_admission() {
                                return Err(honk_outbound::proxy::PacketRejection::Capacity.into());
                            }
                            Err(anyhow::Error::new(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                format!("dial timed out after {per_dial_timeout:?}"),
                            )))
                        })
                };
                let elapsed = start.elapsed();
                let mut score = score.lock();
                let reporter = score.1.clone();
                match &result {
                    Ok(_) => {
                        if let Some(reporter) = &reporter {
                            reporter.setup_succeeded();
                        }
                    }
                    Err(error) => {
                        if let Some(business) = score.0.take() {
                            business.finish(score_runtime_outcome(&generation, error));
                        }
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
        let mut rejection = None;
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
                        if honk_outbound::proxy::is_packet_rejection(&e)
                            || runtime_generation.is_shutdown()
                        {
                            rejection = Some(e);
                            set.abort_all();
                            break;
                        }
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
                    if runtime_generation.is_shutdown() {
                        for reporter in started_reporters.lock().iter() {
                            reporter.finish(crate::group::ScoreOutcome::Shutdown);
                        }
                    } else {
                        timeout_started_score_reporters(&started_reporters);
                    }
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

        while let Some(result) = set.join_next().await {
            if let Ok((Err(error), ..)) = result
                && (honk_outbound::proxy::is_packet_rejection(&error)
                    || runtime_generation.is_shutdown())
            {
                rejection.get_or_insert(error);
            }
        }
        if let Some(error) = rejection {
            return Err(error);
        }

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
                let pool_feedback = feedback.get(&node.id).cloned();
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
                        let key = ConnectionPool::ready_key(
                            generation.generation(),
                            node.id,
                            target,
                            target_domain.as_deref(),
                        );
                        // Only hot targets earn a speculative ready
                        // dial; a one-off flow gets none.
                        let Some(_warm_guard) = pool.try_begin_warm(generation.generation(), &key)
                        else {
                            return;
                        };
                        let pool_reporter = pool_feedback.map(|attempt| {
                            let context = attempt.context().clone();
                            attempt.start_warmup(context)
                        });
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
                                pool.deposit_ready(generation.generation(), &key, stream)
                                    .await;
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
                    let pool_reporter = pool_feedback.map(|attempt| {
                        attempt.start_warmup(crate::group::ScoreSelectionContext::aggregate(
                            SelectionNetwork::Tcp,
                            ProbeDomain::Tcp,
                            pool_health_family,
                        ))
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
                            if pool.deposit_tcp(&node_addr, stream).await {
                                if let Some(reporter) = &pool_reporter {
                                    reporter.setup_succeeded();
                                    reporter.finish_setup_only();
                                }
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
                                    crate::group::ScoreOutcome::from_io_error(&e)
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

        Ok(match winner {
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
        })
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
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn dial_pooled(
        registry: &ProxyRegistry,
        pool: &ConnectionPool,
        generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
        node: &Node,
        target: (SocketAddr, Option<&str>),
        connect_timeout: Duration,
        direct_mark: Option<honk_outbound::proxy::DirectMark>,
        scope: &Arc<honk_outbound::runtime::DialScope>,
    ) -> anyhow::Result<(crate::proxy::ProxyStream, bool)> {
        anyhow::ensure!(
            !generation.is_shutdown(),
            "outbound runtime generation is shut down"
        );
        let (target, target_domain) = target;
        // A marked socket belongs to exactly one flow, so it never touches a pool.
        if let Some(mark) = direct_mark {
            return scope
                .scope(async {
                    registry
                        .dial_runtime_marked(
                            Arc::clone(generation),
                            node.id,
                            target,
                            target_domain,
                            connect_timeout,
                            mark,
                        )
                        .await
                        .map(|stream| (stream, true))
                })
                .await;
        }
        static POOL_DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let pool_disabled = *POOL_DISABLED.get_or_init(|| {
            std::env::var("HONK_POOL_DISABLE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        });

        let addr = format!("{}:{}", node.host(), node.port);
        let protocol = node.protocol();
        let entry = registry
            .find(protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", protocol))?;

        if !pool_disabled && (entry.descriptor.pool_ready_streams)(node) {
            let key =
                ConnectionPool::ready_key(generation.generation(), node.id, target, target_domain);
            if let Some(stream) = pool.acquire_ready(&key).await {
                tracing::debug!(
                    "Pooled ready stream via {} acquired for {} (handshake skipped)",
                    addr,
                    target
                );
                scope.start();
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
                scope.start();
                tracing::debug!("Pooled TCP to {} acquired for {}", addr, target);
                let dial =
                    entry
                        .tcp
                        .dial_with_tcp(node, target, target_domain, tcp, connect_timeout);
                let stream = match generation.get(&node.id) {
                    Some(runtime) => runtime.transport_quality().scope(dial).await,
                    None => dial.await,
                }?;
                return Ok((stream, true));
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
        scope.scope(dial).await
    }
}
