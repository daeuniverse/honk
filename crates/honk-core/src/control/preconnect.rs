use super::*;

/// Pick the nodes the startup preconnect warm-up dials: each group's current
/// selection (selector pick / urltest winner, peek semantics) first, then
/// config order to fill the remaining budget. Eligibility is
/// descriptor-driven — multiplexed (AnyTLS) and QUIC nodes can never consume
/// a pooled bare TCP — and the built-in direct/block markers have no server
/// to dial. `count == 0` disables the warm-up; the
/// [`honk_config::config::PRECONNECT_NODE_COUNT_AUTO`] sentinel caps at
/// `min(nodes, 8)`.
pub(crate) fn preconnect_candidates(
    config: &Config,
    group_manager: &GroupManager,
    count: usize,
) -> Vec<Node> {
    if count == 0 {
        return Vec::new();
    }
    let limit = if count == honk_config::config::PRECONNECT_NODE_COUNT_AUTO {
        config.nodes.len().min(8)
    } else {
        count
    };
    fn eligible(node: &Node) -> bool {
        !matches!(node.protocol(), NodeProtocol::Direct | NodeProtocol::Block)
            && (honk_outbound::descriptor::descriptor(node.protocol()).pool_bare_tcp)(node)
    }
    let mut seen = std::collections::HashSet::new();
    let mut selected: Vec<Node> = Vec::new();
    let push = |node: &Node,
                seen: &mut std::collections::HashSet<uuid::Uuid>,
                selected: &mut Vec<Node>| {
        if selected.len() < limit && eligible(node) && seen.insert(node.id) {
            selected.push(node.clone());
        }
    };
    for group in &config.groups {
        if let Some(node) = group_manager
            .peek_selection_plan_for_domain(&group.name, ProbeDomain::Tcp, IpVersion::V4)
            .nodes
            .first()
        {
            push(node, &mut seen, &mut selected);
        }
    }
    for node in &config.nodes {
        push(node, &mut seen, &mut selected);
    }
    selected
}

impl ControlPlane {
    pub(super) async fn start_preconnect(&self) {
        let config = self.config.read().await;
        let count = config.global.preconnect_node_count;
        let connect_timeout = std::time::Duration::from_millis(config.global.connect_timeout_ms);
        let max_concurrent = if count == honk_config::config::PRECONNECT_NODE_COUNT_AUTO {
            4usize
        } else {
            count.min(8)
        };
        let (nodes, manager) = {
            let manager = self.group_manager.read().clone();
            (preconnect_candidates(&config, &manager, count), manager)
        };
        drop(config);

        if !nodes.is_empty() {
            let node_count = nodes.len();
            let pool = self.connection_pool.clone();
            let stats = self.stats.clone();
            let generation = self.runtime_registry.read().clone();
            let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
            let handle = tokio::spawn(async move {
                let mut set = tokio::task::JoinSet::new();
                for node in nodes {
                    let feedback = manager.feedback_for_node(
                        node.id,
                        crate::group::ScoreSelectionContext::aggregate(
                            crate::group::SelectionNetwork::Tcp,
                            ProbeDomain::Tcp,
                            IpVersion::V4,
                        ),
                    );
                    let addr = format!("{}:{}", node.host(), node.port);
                    let pool = pool.clone();
                    let stats = stats.clone();
                    let generation = Arc::clone(&generation);
                    let sem = semaphore.clone();
                    set.spawn(async move {
                        let _permit = sem.acquire_owned().await;
                        let reporter = feedback.map(|feedback| feedback.start());
                        match generation
                            .scope_dials(honk_outbound::util::connect_outbound(
                                &addr,
                                connect_timeout,
                            ))
                            .await
                        {
                            Ok(stream) if is_tcp_stream_alive(&stream) => {
                                if let Some(reporter) = &reporter {
                                    reporter.setup_succeeded();
                                }
                                pool.deposit_tcp(&addr, stream).await;
                                stats.mark_warm(node.id, crate::stats::WarmReason::Preconnect);
                                if let Some(reporter) = &reporter {
                                    reporter.finish(crate::group::ScoreOutcome::Success);
                                }
                                debug!("Preconnect warmup: deposited connection to {}", addr);
                            }
                            Ok(_) => {
                                if let Some(reporter) = &reporter {
                                    reporter.setup_failed(crate::group::ScoreOutcome::Io(
                                        io::ErrorKind::ConnectionAborted,
                                    ));
                                }
                            }
                            Err(error) => {
                                if let Some(reporter) = &reporter {
                                    reporter.setup_failed(
                                        if error.kind() == io::ErrorKind::TimedOut {
                                            crate::group::ScoreOutcome::Timeout
                                        } else {
                                            crate::group::ScoreOutcome::Io(error.kind())
                                        },
                                    );
                                }
                                debug!("Preconnect warmup to {} failed: {}", addr, error);
                            }
                        }
                    });
                }
                while set.join_next().await.is_some() {}
            });
            self.background_tasks.lock().await.push(handle);
            info!(
                "Preconnect warmup started for {} nodes (max {} concurrent)",
                node_count, max_concurrent
            );
        }
    }
}
