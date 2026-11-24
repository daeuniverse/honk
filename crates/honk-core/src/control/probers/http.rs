use super::*;
use honk_outbound::alive::{RouteHttpProber, RouteProbeTicket};
use honk_outbound::group::DialKey;
use honk_outbound::proxy::{DialRef, is_packet_rejection};
use honk_outbound::runtime::OutboundRuntimeRegistry;
use tokio::time::Instant as Deadline;

fn http_probe_context(request: &::http::Request<()>, addr: SocketAddr) -> ScoreSelectionContext {
    let family = target_family(addr);
    let host = request
        .uri()
        .host()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    let port = request.uri().port_u16().unwrap_or_else(|| {
        if request.uri().scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });
    let target = host
        .parse::<std::net::IpAddr>()
        .map_or_else(|_| ScoreTarget::domain(host, port), |_| addr.into());
    ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(family),
        health_family: family,
        target: Some(target),
    }
}

/// Adapts health configuration, generation ownership, and Score feedback
/// to the shared outbound HTTP measurement.
pub(in crate::control) struct ProxyHttpProber {
    pub(super) config: Arc<RwLock<Arc<Config>>>,
    pub(super) proxy_registry: Arc<ProxyRegistry>,
    pub(super) runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    check_method: String,
    group_manager: SharedGroupManager,
    udp_recovery_resolver: Option<crate::outbound::ResolveHook>,
}

impl ProxyHttpProber {
    pub(in crate::control) fn new(
        config: Arc<RwLock<Arc<Config>>>,
        proxy_registry: Arc<ProxyRegistry>,
        runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
        check_method: String,
        group_manager: SharedGroupManager,
    ) -> Self {
        Self {
            config,
            proxy_registry,
            runtime_registry,
            check_method,
            group_manager,
            udp_recovery_resolver: None,
        }
    }

    pub(in crate::control) fn with_udp_recovery_resolver(
        mut self,
        resolver: crate::outbound::ResolveHook,
    ) -> Self {
        self.udp_recovery_resolver = Some(resolver);
        self
    }

    /// Find the exact admitted node; display names need not be unique.
    fn find_node(&self, node_id: uuid::Uuid) -> Option<Node> {
        self.config
            .try_read()
            .ok()?
            .nodes
            .iter()
            .find(|n| n.id == node_id)
            .cloned()
    }
}

impl honk_outbound::alive::HttpProber for ProxyHttpProber {
    fn probe_http(
        &self,
        node_id: uuid::Uuid,
        addr: SocketAddr,
        url: &str,
        timeout: Duration,
        cancel: honk_outbound::alive::ProbeCancellation,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = honk_outbound::alive::HttpProbeOutcome> + Send + 'static>,
    > {
        let node = self.find_node(node_id);
        let registry = self.proxy_registry.clone();
        let generation = self.runtime_registry.read().clone();
        let check_url = url.to_string();
        let check_method = self.check_method.clone();
        let config = self.config.clone();
        let group_manager = self.group_manager.clone();

        Box::pin(async move {
            if cancel.is_cancelled() {
                return honk_outbound::alive::HttpProbeResult::Cancelled.into();
            }
            let Some(node) = node else {
                return honk_outbound::alive::HttpProbeResult::SetupFailure(
                    "node not found".into(),
                )
                .into();
            };
            let protocol = node.protocol();
            let Some(entry) = registry.find(protocol) else {
                return honk_outbound::alive::HttpProbeResult::SetupFailure(format!(
                    "no handler for protocol {:?}",
                    protocol
                ))
                .into();
            };
            let (connect_timeout, default_probe_url, probe_interval) = match config.try_read() {
                Ok(config) => (
                    Duration::from_millis(config.global.connect_timeout_ms),
                    config
                        .global
                        .tcp_check_url
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                    Duration::from_secs(config.global.check_interval_secs),
                ),
                Err(_) => {
                    return honk_outbound::alive::HttpProbeResult::SetupFailure(
                        "config lock busy".to_string(),
                    )
                    .into();
                }
            };

            let request = match honk_outbound::urltest::health_http_probe_request(
                &check_url,
                &check_method,
            ) {
                Ok(request) => request,
                Err(error) => {
                    return honk_outbound::alive::HttpProbeResult::SetupFailure(format!(
                        "invalid HTTP probe request: {error:#}"
                    ))
                    .into();
                }
            };
            let host = request
                .uri()
                .host()
                .unwrap_or_default()
                .trim_matches(['[', ']']);
            let target_domain =
                if protocol == NodeProtocol::Direct || host.parse::<std::net::IpAddr>().is_ok() {
                    None
                } else {
                    Some(host.to_string())
                };
            let (runtime, ephemeral) = match honk_outbound::urltest::try_probe_runtime(
                &generation,
                &node,
                honk_outbound::proxy::WarmRequirement::Session,
            ) {
                Ok(runtime) => runtime,
                Err(_) => {
                    return honk_outbound::alive::HttpProbeResult::SetupFailure(
                        "invalid node for health probe".into(),
                    )
                    .into();
                }
            };
            let warm_feedback = if runtime
                .is_warm_or_stateless_for(honk_outbound::proxy::WarmRequirement::Session)
            {
                None
            } else {
                probe_feedback(
                    &group_manager,
                    node.id,
                    ScoreSelectionContext::aggregate(
                        SelectionNetwork::Tcp,
                        ProbeDomain::Tcp,
                        target_family(addr),
                    ),
                    probe_interval,
                )
                .map(|feedback| feedback.with_source(ScoreSource::Warmup))
            };
            let warm = cancel
                .run(runtime.scope_tasks(generation.scope_dials(
                    honk_outbound::urltest::warm_http_probe(
                        &runtime,
                        entry.warmable.as_deref(),
                        connect_timeout,
                        timeout,
                        warm_feedback,
                    ),
                )))
                .await;
            let Some(warm) = warm else {
                close_ephemeral(ephemeral, &cancel).await;
                return honk_outbound::alive::HttpProbeResult::Cancelled.into();
            };
            if let Err(error) = warm {
                close_ephemeral(ephemeral, &cancel).await;
                if let Some(rejection) = honk_outbound::proxy::packet_rejection(&error) {
                    return honk_outbound::alive::HttpProbeResult::LocalRefusal(rejection).into();
                }
                return honk_outbound::alive::HttpProbeResult::SetupFailure(format!(
                    "warm failed: {error:#}"
                ))
                .into();
            }

            let feedback = group_manager
                .read()
                .feedback_for_http_probe(
                    node.id,
                    http_probe_context(&request, addr),
                    &check_url,
                    &default_probe_url,
                )
                .map(|feedback| feedback.with_probe_interval(probe_interval));
            let result = cancel
                .run(runtime.scope_tasks(generation.scope_dials(
                    honk_outbound::urltest::measure_http_probe(
                        &runtime,
                        entry.tcp.as_ref(),
                        &request,
                        addr,
                        target_domain.as_deref(),
                        connect_timeout,
                        timeout,
                        feedback,
                    ),
                )))
                .await;
            let Some(result) = result else {
                close_ephemeral(ephemeral, &cancel).await;
                return honk_outbound::alive::HttpProbeResult::Cancelled.into();
            };
            let observation = if result
                .as_ref()
                .is_err_and(honk_outbound::proxy::is_packet_rejection)
            {
                None
            } else {
                Some(honk_outbound::alive::HealthObservation::probe(
                    ProbeDomain::Tcp,
                    honk_outbound::alive::HealthMeasurement::HttpHeaders,
                    target_family(addr),
                    result.as_ref().ok().map(|sample| sample.latency),
                    result.as_ref().map_or_else(
                        |_| std::time::SystemTime::now(),
                        |sample| sample.observed_at,
                    ),
                ))
            };
            close_ephemeral(ephemeral, &cancel).await;
            let result = match result {
                Ok(sample) => honk_outbound::alive::HttpProbeResult::WarmSuccess(sample.latency),
                Err(error) => {
                    if let Some(rejection) = honk_outbound::proxy::packet_rejection(&error) {
                        return honk_outbound::alive::HttpProbeResult::LocalRefusal(rejection)
                            .into();
                    }
                    honk_outbound::alive::HttpProbeResult::ExchangeFailure(format!("{error:#}"))
                }
            };
            honk_outbound::alive::HttpProbeOutcome {
                result,
                observation,
            }
        })
    }
}

impl ProxyHttpProber {
    fn route_probe_is_current(
        &self,
        ticket: &RouteProbeTicket,
        generation: &Arc<OutboundRuntimeRegistry>,
    ) -> bool {
        let manager = self.group_manager.read();
        let active = self.runtime_registry.read();
        Arc::ptr_eq(&active, generation)
            && !generation.is_shutdown()
            && ticket.is_current_for(&manager)
    }
}

#[async_trait::async_trait]
impl RouteHttpProber for ProxyHttpProber {
    async fn probe_route_http(
        &self,
        alive: &AliveDialerSet,
        ticket: &RouteProbeTicket,
        deadline: Deadline,
    ) -> anyhow::Result<Option<ProbeMeasurement>> {
        // Capture the registry and HTTP method under the accepted publication
        // order. The ticket already owns the root's effective URL and witness.
        let (generation, config) = {
            let Ok(config) = self.config.try_read() else {
                return Ok(None);
            };
            let manager = self.group_manager.read();
            let generation = self.runtime_registry.read();
            if !ticket.is_current_for(&manager) || generation.is_shutdown() {
                return Ok(None);
            }
            (Arc::clone(&generation), Arc::clone(&config))
        };
        let Ok(request) = honk_outbound::urltest::health_http_probe_request(
            ticket.url(),
            &config.global.tcp_check_http_method,
        ) else {
            return Ok(None);
        };
        let connect_timeout = Duration::from_millis(config.global.connect_timeout_ms);
        if Deadline::now() >= deadline || !self.route_probe_is_current(ticket, &generation) {
            return Ok(None);
        }
        let addrs = alive.route_probe_addrs(ticket).await?;
        let target = ticket.target();
        let dial = match &target {
            DialKey::Node(id) => DialRef::Node(*id),
            DialKey::Route(route) => DialRef::Route(route),
        };
        let mut last_error = None;
        for addr in addrs {
            let remaining = deadline.saturating_duration_since(Deadline::now());
            if remaining.is_zero() || !self.route_probe_is_current(ticket, &generation) {
                return Ok(None);
            }
            // The pinned IP determines the destination family; the request
            // still supplies the configured HTTP Host and verified TLS name.
            let stream = match self
                .proxy_registry
                .dial_ref(
                    Arc::clone(&generation),
                    dial,
                    addr,
                    None,
                    connect_timeout.min(remaining),
                )
                .await
            {
                Ok(stream) => stream,
                Err(error) if is_packet_rejection(&error) => return Err(error),
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let remaining = deadline.saturating_duration_since(Deadline::now());
            if remaining.is_zero() || !self.route_probe_is_current(ticket, &generation) {
                return Ok(None);
            }
            // Once the HTTP exchange starts, never replay the configured method.
            let sample =
                honk_outbound::urltest::validate_routed_http_probe(stream, &request, remaining)
                    .await?;
            return Ok(self
                .route_probe_is_current(ticket, &generation)
                .then_some(sample));
        }
        match last_error {
            Some(error) => Err(error),
            None => Ok(None),
        }
    }

    async fn probe_route_udp(
        &self,
        alive: &AliveDialerSet,
        ticket: &RouteProbeTicket,
        deadline: Deadline,
        cancel: honk_outbound::alive::ProbeCancellation,
    ) -> anyhow::Result<()> {
        let (generation, connect_timeout) = {
            let Ok(config) = self.config.try_read() else {
                return Ok(());
            };
            let manager = self.group_manager.read();
            let generation = self.runtime_registry.read();
            if !ticket.is_current_for(&manager) || generation.is_shutdown() {
                return Ok(());
            }
            (
                Arc::clone(&generation),
                Duration::from_millis(config.global.connect_timeout_ms),
            )
        };
        let current = || {
            !cancel.is_cancelled()
                && Deadline::now() < deadline
                && self.route_probe_is_current(ticket, &generation)
        };
        let exchange = async {
            let key = ticket.target();
            let dial = match &key {
                DialKey::Node(id) => DialRef::Node(*id),
                DialKey::Route(route) => DialRef::Route(route),
            };
            let terminal = self.proxy_registry.udp_framing_node(&generation, dial)?;
            let address = cancel
                .scope_resolution(alive.route_udp_probe_addr(
                    ticket,
                    |port| honk_outbound::descriptor::udp_target_allowed(terminal, port),
                    self.udp_recovery_resolver.as_ref(),
                ))
                .await?;
            let Some(address) = address.filter(|_| current()) else {
                return Ok(None);
            };
            let budget = connect_timeout.min(deadline.saturating_duration_since(Deadline::now()));
            let transport = match dial {
                DialRef::Node(id) => {
                    self.proxy_registry
                        .dial_udp_transport_runtime(
                            Arc::clone(&generation),
                            id,
                            address,
                            None,
                            budget,
                        )
                        .await?
                }
                DialRef::Route(route) => {
                    self.proxy_registry
                        .dial_udp_route(Arc::clone(&generation), route, address, None, budget)
                        .await?
                }
            };
            if !current() {
                return Ok(None);
            }
            use crate::dns::forwarder::{UdpProbeSend, udp_dns_probe_exchange};
            let send = UdpProbeSend::recovery(dial, terminal.id, &current);
            udp_dns_probe_exchange(transport.as_ref(), send).await?;
            Ok::<_, anyhow::Error>(Some(()))
        };
        let result = tokio::time::timeout_at(deadline, exchange)
            .await
            .unwrap_or_else(|error| Err(error.into()));
        let success = match &result {
            Ok(Some(())) => true,
            Ok(None) => return Ok(()),
            Err(error) if udp_probe_local_refusal(error) => return Ok(()),
            Err(_) => false,
        };
        let notifications = {
            let manager = self.group_manager.read();
            let active = self.runtime_registry.read();
            if !Arc::ptr_eq(&active, &generation)
                || generation.is_shutdown()
                || !ticket.is_current_for(&manager)
            {
                return Ok(());
            }
            ticket.settle_udp(success, deadline, &cancel)
        };
        notifications.notify();
        result.map(|_| ())
    }
}
