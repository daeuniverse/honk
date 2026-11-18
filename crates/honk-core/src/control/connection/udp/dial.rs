use super::*;
use crate::control::reload::ResolvedUdpPlan;
use crate::control::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use crate::control::udp_endpoint::SourcePath;
use crate::group::SelectionPlanMode;
use honk_outbound::group::OwnedTarget;

pub(super) struct PreparedEndpoint {
    pub(super) transport: PreparedEndpointTransport,
    pub(super) reporter: Option<crate::group::ScoreReporter>,
    pub(super) chain: Vec<String>,
    #[cfg(feature = "native-api")]
    pub(super) attempt: Option<super::super::observation::ConnectionAttempt>,
}

pub(super) enum PreparedEndpointTransport {
    Flow(honk_outbound::proxy::PreparedUdpTransport),
    Source(crate::control::udp_endpoint::SourcePreparation),
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
        plan: ResolvedUdpPlan,
        mark: Option<honk_outbound::proxy::DirectMark>,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
        target_domain: Option<Arc<str>>,
        connect_timeout: Duration,
        transport_deadline: tokio::time::Instant,
        runtime_generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
        #[cfg(feature = "native-api")] observation: &ConnectionObservation,
    ) -> anyhow::Result<Option<(OwnedTarget, PreparedEndpoint)>> {
        let ResolvedUdpPlan {
            mode: plan_mode,
            targets,
            ipver: scheduler_ipver,
            feedback: score_feedback,
            selection_chains,
            ..
        } = plan;
        let target_is_domain = target_domain.is_some();
        // Only a literal direct route keeps a mark, and Cold URLTest is always
        // a group route, so speculative preparation never needs one.
        debug_assert!(plan_mode != SelectionPlanMode::ColdUrlTest || mark.is_none());
        let prepare_generation = Arc::clone(runtime_generation);
        let prepare: UdpPrepare<PreparedEndpoint, OwnedTarget> = {
            let registry = self.proxy_registry.clone();
            let stats = self.stats.clone();
            let feedback = score_feedback.clone();
            let udp_pool = Arc::clone(&self.udp_pool);
            let alive_set = Arc::clone(&self.alive_set);
            let target_domain = target_domain.clone();
            #[cfg(feature = "native-api")]
            let native = observation.shared();
            Arc::new(move |index: usize, target: OwnedTarget| {
                let registry = registry.clone();
                let stats = stats.clone();
                let runtime_generation = Arc::clone(&prepare_generation);
                let feedback = feedback.get(index).cloned().flatten();
                let selection_chain = selection_chains.get(index).cloned().unwrap_or_default();
                let udp_pool = Arc::clone(&udp_pool);
                let alive_set = Arc::clone(&alive_set);
                let target_domain = target_domain.clone();
                #[cfg(feature = "native-api")]
                let native = native.clone();
                Box::pin(async move {
                    let node = &target.node;
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
                        (if let Some(route) = target.route() {
                            registry
                                .dial_udp_route(
                                    Arc::clone(&runtime_generation),
                                    route,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                        } else if let Some(mark) = mark {
                            registry
                                .dial_udp_transport_runtime_marked(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                    mark,
                                )
                                .await
                        } else {
                            registry
                                .dial_udp_transport_runtime(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                        })
                        .map(honk_outbound::proxy::PreparedUdpTransport::ready)
                        .map(PreparedEndpointTransport::Flow)
                    };
                    let operation = async {
                        // A route dials over hop runtimes no source is keyed
                        // by, so it never shares one.
                        if let Some(path) = target
                            .route
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
                                .map(PreparedEndpointTransport::Source)
                        } else if plan_mode == SelectionPlanMode::ColdUrlTest
                            && target.route.is_none()
                        {
                            registry
                                .dial_udp_transport_speculative(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                                .map(PreparedEndpointTransport::Flow)
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
                            // A route's established stream proves its leaf
                            // and inner exits; the exit's UDP health comes
                            // from the flow it now carries.
                            for proven in target.proven() {
                                alive_set.report_available_traffic(
                                    proven,
                                    ProbeDomain::DataUdp,
                                    scheduler_ipver,
                                );
                            }
                            #[cfg(feature = "native-api")]
                            if let Some(attempt) = &native_attempt {
                                attempt.udp_prepared();
                            }
                            Ok(PreparedEndpoint {
                                transport,
                                reporter,
                                chain: selection_chain,
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
                                reporter.setup_failed(score_runtime_outcome(
                                    &runtime_generation,
                                    &error,
                                ));
                            }
                            Err(error)
                        }
                    }
                })
            })
        };
        let callbacks = UdpStaggerCallbacks {
            // The exit frames a route's UDP, so its policy decides the port.
            allows_target: {
                let generation = Arc::clone(runtime_generation);
                Arc::new(move |target: &OwnedTarget| match target.route() {
                    None => honk_outbound::descriptor::udp_target_allowed(
                        &target.node,
                        original_dst.port(),
                    ),
                    Some(route) => generation.get(&route.exit()).is_some_and(|exit| {
                        honk_outbound::descriptor::udp_target_allowed(
                            &exit.node,
                            original_dst.port(),
                        )
                    }),
                })
            },
            is_eligible: {
                let group_manager = self.group_manager.clone();
                Arc::new(move |target: &OwnedTarget| {
                    group_manager.read().target_selectable(
                        target,
                        ProbeDomain::DataUdp,
                        scheduler_ipver,
                    )
                })
            },
            on_dial_error: {
                let alive_set = self.alive_set.clone();
                let runtime_generation = Arc::clone(runtime_generation);
                // A route's failure counts against the hop that failed; one
                // no hop owns counts against nothing.
                Arc::new(move |target: &OwnedTarget, error: &anyhow::Error| {
                    if let Some(owner) = target.failure_owner(error) {
                        report_dial_failure_if_current(
                            &runtime_generation,
                            &alive_set,
                            owner,
                            ProbeDomain::DataUdp,
                            scheduler_ipver,
                        );
                    }
                })
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
        prepare_udp_plan(plan_mode, targets, transport_deadline, prepare, callbacks).await
    }
}
