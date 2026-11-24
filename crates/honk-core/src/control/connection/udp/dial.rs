use super::*;
use crate::control::reload::ResolvedScorePlan;
use crate::control::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use crate::control::udp_endpoint::{SourcePath, UdpTrafficEvidence};
use crate::group::SelectionPlanMode;
use honk_outbound::group::OwnedTarget;
use honk_outbound::proxy::{DialRef, PacketRejection, dial_failure_scope};

pub(super) struct PreparedEndpoint {
    pub(super) transport: PreparedEndpointTransport,
    pub(super) reporter: Option<crate::group::ScoreReporter>,
    pub(super) chain: Vec<String>,
    pub(super) evidence: Option<Arc<UdpTrafficEvidence>>,
    #[cfg(feature = "native-api")]
    pub(super) attempt: Option<super::super::observation::ConnectionAttempt>,
}

pub(super) enum PreparedEndpointTransport {
    Flow(honk_outbound::proxy::PreparedUdpTransport),
    Source(crate::control::udp_endpoint::SourcePreparation),
}

pub(super) fn standalone_udp_target(target: &OwnedTarget) -> bool {
    target.node.chain_hops().is_none() && !target.uses_route_evidence()
}

/// The registry decides which protocols share one association per source: a
/// protocol joins by registering a shared-source slot, not by a core list.
pub(super) fn source_path(
    registry: &ProxyRegistry,
    generation: &honk_outbound::runtime::OutboundRuntimeRegistry,
    node: &Node,
    port: u16,
) -> Option<SourcePath> {
    let protocol = node.protocol();
    let shared = || {
        registry
            .has_shared_source(protocol)
            .then_some(SourcePath::Shared)
    };
    match protocol {
        honk_config::types::NodeProtocol::Hysteria2 => Some(SourcePath::Hysteria2),
        honk_config::types::NodeProtocol::Tuic => Some(SourcePath::Tuic),
        #[cfg(feature = "rprx")]
        honk_config::types::NodeProtocol::VLess => {
            use honk_config::node::VlessUdpPath;
            let path = node.vless()?.udp_path(port)?;
            match path {
                VlessUdpPath::Xudp | VlessUdpPath::CoolShared | VlessUdpPath::CoolSeparate => {
                    Some(SourcePath::Vless(path))
                }
                VlessUdpPath::UotV2 | VlessUdpPath::H2 => shared(),
                VlessUdpPath::Native => None,
            }
        }
        honk_config::types::NodeProtocol::Chain => generation
            .get(&node.id)
            .filter(|runtime| registry.has_shared_source_for(runtime))
            .map(|_| SourcePath::Shared),
        _ => {
            let _ = port;
            shared()
        }
    }
}

impl ControlPlaneHandle {
    /// Cold URLTest preparation owns no endpoint state: no lease binding,
    /// reply socket, driver, tracker, or application packet exists until
    /// a single eligible transport winner has been drained and accepted.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn prepare_udp_candidates(
        &self,
        plan: ResolvedScorePlan,
        mark: Option<honk_outbound::proxy::DirectMark>,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
        target_domain: Option<Arc<str>>,
        connect_timeout: Duration,
        transport_deadline: tokio::time::Instant,
        runtime_generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
        selection_manager: &Arc<GroupManager>,
        #[cfg(feature = "native-api")] observation: &ConnectionObservation,
    ) -> anyhow::Result<Option<(OwnedTarget, PreparedEndpoint)>> {
        let ResolvedScorePlan {
            mode: plan_mode,
            targets,
            health_family: scheduler_ipver,
            route_revision,
            feedback: score_feedback,
            selection_chains,
            final_owners,
            ..
        } = plan;
        let mut seen = std::collections::HashSet::new();
        let candidates = targets
            .into_iter()
            .enumerate()
            .filter(|(_, target)| {
                plan_mode != SelectionPlanMode::ColdUrlTest || seen.insert(target.key())
            })
            .collect();
        let target_is_domain = target_domain.is_some();
        // Only a literal direct route keeps a mark, and Cold URLTest is always
        // a group route, so speculative preparation never needs one.
        debug_assert!(plan_mode != SelectionPlanMode::ColdUrlTest || mark.is_none());
        let prepare_generation = Arc::clone(runtime_generation);
        let prepare: UdpPrepare<PreparedEndpoint, (usize, OwnedTarget)> = {
            let registry = self.proxy_registry.clone();
            let stats = self.stats.clone();
            let udp_pool = Arc::clone(&self.udp_pool);
            let alive_set = Arc::clone(&self.alive_set);
            let manager = Arc::clone(selection_manager);
            let target_domain = target_domain.clone();
            #[cfg(feature = "native-api")]
            let native = observation.shared();
            Arc::new(move |_, (index, target)| {
                let registry = registry.clone();
                let stats = stats.clone();
                let runtime_generation = Arc::clone(&prepare_generation);
                let feedback = score_feedback[index].clone();
                let selection_chain = selection_chains[index].clone();
                let final_owners = final_owners[index].clone();
                let manager = Arc::clone(&manager);
                let udp_pool = Arc::clone(&udp_pool);
                let alive_set = Arc::clone(&alive_set);
                let target_domain = target_domain.clone();
                #[cfg(feature = "native-api")]
                let native = native.clone();
                Box::pin(async move {
                    let node = &target.node;
                    let configured_chain = target.route().is_none() && node.chain_hops().is_some();
                    let evidence = if !standalone_udp_target(&target) {
                        Some(
                            UdpTrafficEvidence::capture_route(
                                &manager,
                                &runtime_generation,
                                &target,
                                &selection_chain,
                                &final_owners,
                                route_revision,
                                scheduler_ipver,
                            )
                            .ok_or(PacketRejection::Cancelled)?,
                        )
                    } else {
                        UdpTrafficEvidence::capture_bare(
                            &manager,
                            &runtime_generation,
                            node.id,
                            scheduler_ipver,
                        )
                    }
                    .map(Arc::new);
                    #[cfg(feature = "native-api")]
                    let mut native_attempt = native.as_ref().and_then(|observation| {
                        observation.attempt(&selection_chain, &target, target_domain.as_deref())
                    });
                    let reporter = feedback
                        .as_ref()
                        .map(crate::group::ScoreAttempt::begin)
                        .transpose()
                        .map_err(|error| {
                            let error: anyhow::Error = error.into();
                            #[cfg(feature = "native-api")]
                            if let Some(attempt) = &mut native_attempt {
                                attempt.tcp_finished(Some(&error), node);
                            }
                            error
                        })?
                        .map(crate::group::ScoreBusinessGuard::start);
                    let dial_started_at = std::time::Instant::now();
                    let flow_transport = async {
                        let generation = Arc::clone(&runtime_generation);
                        let domain = target_domain.as_deref();
                        match target.dial_ref() {
                            DialRef::Route(route) => registry
                                .dial_udp_route(
                                    generation,
                                    route,
                                    original_dst,
                                    domain,
                                    connect_timeout,
                                )
                                .await
                                .map(honk_outbound::proxy::PreparedUdpTransport::ready),
                            DialRef::Node(id) if plan_mode == SelectionPlanMode::ColdUrlTest => {
                                registry
                                    .dial_udp_transport_speculative(
                                        generation,
                                        id,
                                        original_dst,
                                        domain,
                                        connect_timeout,
                                    )
                                    .await
                            }
                            DialRef::Node(id) => match mark {
                                Some(mark) => {
                                    registry
                                        .dial_udp_transport_runtime_marked(
                                            generation,
                                            id,
                                            original_dst,
                                            domain,
                                            connect_timeout,
                                            mark,
                                        )
                                        .await
                                }
                                None => {
                                    registry
                                        .dial_udp_transport_runtime(
                                            generation,
                                            id,
                                            original_dst,
                                            domain,
                                            connect_timeout,
                                        )
                                        .await
                                }
                            }
                            .map(honk_outbound::proxy::PreparedUdpTransport::ready),
                        }
                        .map(PreparedEndpointTransport::Flow)
                    };
                    let operation = async {
                        if configured_chain {
                            let framing = registry
                                .udp_framing_node(&runtime_generation, target.dial_ref())?;
                            if !honk_outbound::descriptor::udp_target_allowed(
                                framing,
                                original_dst.port(),
                            ) {
                                return Err(PacketRejection::Policy.into());
                            }
                        }
                        // A route dials over hop runtimes no source is keyed
                        // by, so it never shares one.
                        if let Some(path) = target
                            .route()
                            .is_none()
                            .then(|| {
                                source_path(
                                    &registry,
                                    &runtime_generation,
                                    node,
                                    original_dst.port(),
                                )
                            })
                            .flatten()
                        {
                            let runtime = runtime_generation.get(&node.id).ok_or_else(|| {
                                anyhow::anyhow!(
                                    "node {} is not in the captured runtime generation",
                                    node.id
                                )
                            })?;
                            let creator_evidence =
                                if target.uses_route_evidence() && !configured_chain {
                                    UdpTrafficEvidence::capture_bare(
                                        &manager,
                                        &runtime_generation,
                                        node.id,
                                        scheduler_ipver,
                                    )
                                    .map(Arc::new)
                                } else {
                                    evidence.clone()
                                };
                            udp_pool
                                .prepare_source(
                                    &registry,
                                    Arc::clone(&runtime_generation),
                                    runtime,
                                    client_addr,
                                    path,
                                    target_is_domain.then_some(original_dst),
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                    Arc::clone(&alive_set),
                                    Arc::clone(&stats),
                                    scheduler_ipver,
                                    plan_mode == SelectionPlanMode::ColdUrlTest,
                                )
                                .await
                                .map(|source| {
                                    PreparedEndpointTransport::Source(
                                        source.with_evidence(creator_evidence),
                                    )
                                })
                        } else {
                            flow_transport.await
                        }
                    };
                    #[cfg(feature = "native-api")]
                    let result = match native_attempt
                        .as_ref()
                        .and_then(|attempt| attempt.observer())
                    {
                        Some(observer) => observer.scope(operation).await,
                        None => operation.await,
                    };
                    #[cfg(not(feature = "native-api"))]
                    let result = operation.await;
                    stats.record_udp_dial_latency(dial_started_at.elapsed());
                    match result {
                        Ok(transport) => {
                            #[cfg(feature = "native-api")]
                            if let Some(attempt) = &native_attempt {
                                attempt.udp_prepared();
                            }
                            Ok(PreparedEndpoint {
                                transport,
                                reporter,
                                chain: selection_chain,
                                evidence,
                                #[cfg(feature = "native-api")]
                                attempt: native_attempt,
                            })
                        }
                        Err(error) => {
                            #[cfg(feature = "native-api")]
                            if let Some(attempt) = &mut native_attempt {
                                attempt.tcp_finished(Some(&error), node);
                            }
                            if let Some(reporter) = &reporter {
                                let outcome = score_runtime_outcome(&runtime_generation, &error);
                                let outcome = evidence.as_ref().map_or(outcome, |evidence| {
                                    evidence
                                        .score_failure(outcome, dial_failure_scope(error.as_ref()))
                                });
                                UdpTrafficEvidence::publish_score(
                                    evidence.as_deref(),
                                    reporter,
                                    |r| r.setup_failed(outcome),
                                );
                            }
                            if let Some(evidence) = &evidence {
                                evidence.report_failure(error.as_ref());
                            }
                            Err(error)
                        }
                    }
                })
            })
        };
        let callbacks = UdpStaggerCallbacks {
            allows_target: Arc::new(move |(_, target): &(usize, OwnedTarget)| {
                target.route().is_some()
                    || target.node.chain_hops().is_some()
                    || honk_outbound::descriptor::udp_target_allowed(
                        &target.node,
                        original_dst.port(),
                    )
            }),
            is_eligible: {
                let group_manager = self.group_manager.clone();
                let generation = Arc::clone(runtime_generation);
                Arc::new(move |(_, target): &(usize, OwnedTarget)| {
                    !generation.is_shutdown()
                        && group_manager.read().target_selectable(
                            target,
                            ProbeDomain::DataUdp,
                            scheduler_ipver,
                        )
                })
            },
            on_dial_error: {
                let alive_set = self.alive_set.clone();
                let runtime_generation = Arc::clone(runtime_generation);
                // The stamped path already settled its typed failure above.
                Arc::new(
                    move |(_, target): &(usize, OwnedTarget), error: &anyhow::Error| {
                        if standalone_udp_target(target)
                            && let Some(owner) = target.failure_owner(error)
                        {
                            report_dial_failure_if_current(
                                &runtime_generation,
                                &alive_set,
                                owner,
                                ProbeDomain::DataUdp,
                                scheduler_ipver,
                            );
                        }
                    },
                )
            },
            on_attempt: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_attempt())
            },
            on_winner: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_winner())
            },
            on_cancellation: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_cancellation())
            },
        };
        prepare_udp_plan(
            plan_mode,
            candidates,
            transport_deadline,
            prepare,
            callbacks,
        )
        .await
        .map(|winner| winner.map(|((_, target), prepared)| (target, prepared)))
    }
}
