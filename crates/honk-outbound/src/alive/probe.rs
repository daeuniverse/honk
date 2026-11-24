use super::*;
use crate::group::{
    ScoreOutcome, ScoreReporter, ScoreSelectionContext, ScoreSource, SelectionNetwork,
};
use tokio::time::Instant as Deadline;

/// Verifies a configured HTTP request over the ticket's published route.
/// `None` is neutral. A sample requires a validated response on the routed
/// stream. The health worker owns the absolute deadline and cancellation.
#[async_trait::async_trait]
pub trait RouteHttpProber: Send + Sync {
    async fn probe_route_http(
        &self,
        alive: &AliveDialerSet,
        ticket: &RouteProbeTicket,
        deadline: Deadline,
    ) -> anyhow::Result<Option<ProbeMeasurement>>;

    /// The core publisher commits the result under its active manager and runtime guards.
    async fn probe_route_udp(
        &self,
        alive: &AliveDialerSet,
        ticket: &RouteProbeTicket,
        deadline: Deadline,
        cancel: ProbeCancellation,
    ) -> anyhow::Result<()>;
}

impl AliveDialerSet {
    pub fn set_route_http_probe(&self, prober: Arc<dyn RouteHttpProber>) {
        *self.route_http_prober.write() = Some(prober);
    }

    /// Pin the ticket's configured target to addresses in its failed family.
    pub async fn route_probe_addrs(
        &self,
        ticket: &RouteProbeTicket,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        let target = honk_config::check::decode_health_http_target(ticket.url())?;
        let port = target.port();
        let v4 = ticket.family() == IpVersion::V4;
        let mut addrs = Vec::new();
        let mut push = |ip: std::net::IpAddr| {
            let addr = SocketAddr::new(ip.to_canonical(), port);
            if addrs.len() < 3 && addr.is_ipv4() == v4 && !addrs.contains(&addr) {
                addrs.push(addr);
            }
            addrs.len() == 3
        };
        for addr in Self::parse_check_literals(ticket.url(), port) {
            if push(addr.ip()) {
                break;
            }
        }
        if let Ok(ip) = target.host().parse::<std::net::IpAddr>() {
            push(ip);
            return Ok(addrs);
        }

        // Unlike legacy probes, recovery does not bootstrap around an empty
        // or refused lookup and never bypasses a local policy refusal.
        let resolver = self.resolver.read().clone();
        if let Some(resolve) = resolver {
            let resolved = resolve(target.host().to_owned(), port).await;
            match resolved {
                Ok(resolved) => {
                    for addr in resolved {
                        if push(addr.ip()) {
                            break;
                        }
                    }
                }
                Err(error) if crate::proxy::is_packet_rejection(&error) || addrs.is_empty() => {
                    return Err(error);
                }
                Err(_) => {}
            }
        }
        Ok(addrs)
    }

    /// Prefer configured literals in the claimed family. An accepted resolver is the
    /// only authority for a configured hostname; it cannot redirect the check's port.
    pub async fn route_udp_probe_addr(
        &self,
        ticket: &RouteProbeTicket,
        allowed_port: impl Fn(u16) -> bool,
        resolve: Option<&ResolveHook>,
    ) -> anyhow::Result<Option<SocketAddr>> {
        use honk_config::check::{DnsCheckTarget, decode_dns_check_target};
        let Some(values) = ticket.udp_check_dns() else {
            return Ok(None);
        };
        if !ticket.is_current() {
            return Ok(None);
        }
        let entries = || values.iter().filter(|raw| !raw.trim().is_empty());
        let same_family = |addr: SocketAddr| {
            let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
            (addr.is_ipv4() == (ticket.family() == IpVersion::V4)).then_some(addr)
        };
        for raw in entries() {
            if let DnsCheckTarget::Literal(addr) = decode_dns_check_target(raw)?
                && let Some(addr) = same_family(addr)
            {
                if !allowed_port(addr.port()) {
                    return Err(crate::proxy::PacketRejection::Policy.into());
                }
                return Ok(ticket.is_current().then_some(addr));
            }
        }
        for raw in entries() {
            let DnsCheckTarget::Domain { host, port } = decode_dns_check_target(raw)? else {
                continue;
            };
            if !ticket.is_current() {
                return Ok(None);
            }
            if !allowed_port(port) {
                return Err(crate::proxy::PacketRejection::Policy.into());
            }
            let Some(resolve) = resolve else {
                return Ok(None);
            };
            let result = resolve(host.to_owned(), port).await;
            if !ticket.is_current() {
                return Ok(None);
            }
            match result {
                Ok(addrs) => {
                    if let Some(addr) = addrs
                        .into_iter()
                        .find_map(|addr| same_family(SocketAddr::new(addr.ip(), port)))
                    {
                        return Ok(Some(addr));
                    }
                }
                Err(error) if crate::proxy::is_packet_rejection(&error) => return Err(error),
                Err(_) => (),
            }
        }
        Ok(None)
    }

    pub(super) async fn probe_failed_route(
        &self,
        prober: &dyn RouteHttpProber,
        ticket: RouteProbeTicket,
        deadline: Deadline,
        cancel: ProbeCancellation,
    ) {
        if Deadline::now() >= deadline || !ticket.is_current() {
            return;
        }
        if ticket.domain() != ProbeDomain::Tcp {
            let operation = prober.probe_route_udp(self, &ticket, deadline, cancel.clone());
            // Core owns the absolute I/O timeout as well as the registry it captured.
            // Let it commit that timeout under its current manager/runtime guards.
            if let Some(Err(error)) = cancel.run(operation).await {
                tracing::debug!(%error, family = ?ticket.family(), "Routed UDP recovery probe failed");
            }
            return;
        }
        let result = cancel
            .run(tokio::time::timeout_at(
                deadline,
                prober.probe_route_http(self, &ticket, deadline),
            ))
            .await;
        if cancel.is_cancelled() {
            return;
        }
        let success = match result {
            Some(Ok(Ok(Some(_)))) => Deadline::now() < deadline,
            Some(Ok(Err(error))) if !crate::proxy::is_packet_rejection(&error) => {
                tracing::debug!(%error, domain = ?ticket.domain(), family = ?ticket.family(), "Routed recovery probe failed");
                false
            }
            Some(Err(_)) => false,
            _ => return,
        };
        ticket.finish(success);
    }
}

impl AliveDialerSet {
    fn raw_probe_reporter(&self, node_id: Uuid, ipver: IpVersion) -> Option<ScoreReporter> {
        let factory = self.score_feedback.read().clone();
        factory
            .and_then(|factory| {
                factory(
                    node_id,
                    ScoreSelectionContext::aggregate(
                        SelectionNetwork::Tcp,
                        ProbeDomain::Tcp,
                        ipver,
                    ),
                )
            })
            .map(|feedback| feedback.with_source(ScoreSource::HealthProbe).start())
    }
}

impl AliveDialerSet {
    pub(super) fn same_registration(
        current: Option<&Arc<RegisteredNode>>,
        captured: Option<&Arc<RegisteredNode>>,
    ) -> bool {
        match (current, captured) {
            (Some(current), Some(captured)) => Arc::ptr_eq(current, captured),
            (None, None) => true,
            _ => false,
        }
    }

    fn apply_probe_result(
        &self,
        node_id: Uuid,
        registration: Option<&Arc<RegisteredNode>>,
        domain: ProbeDomain,
        ipver: IpVersion,
        latency: Option<Duration>,
    ) {
        let registered = self.registered.read();
        if !Self::same_registration(registered.nodes.get(&node_id), registration) {
            return;
        }
        let changed = match latency {
            Some(latency) => self.record_probe_latency_state(
                node_id,
                domain,
                ipver,
                latency,
                domain != ProbeDomain::Tcp,
            ),
            None => self.unavailable_change(node_id, domain, ipver, false, false),
        };
        // Removal and result mutation have one order. Notifications run unlocked;
        // a reentrant resolver/callback must not authorize another old update.
        drop(registered);
        self.notify_probe_change(changed, node_id, domain, ipver, latency.is_some(), || {
            Self::same_registration(self.registered.read().nodes.get(&node_id), registration)
        });
    }

    /// Probe a single node's TCP reachability.
    ///
    /// When an HTTP prober is configured (Go: `TcpCheckOption`), this resolves
    /// the check URL's hostname to IPs and sends an HTTP request through the
    /// proxy node, validating the status code.
    /// Falls back to raw TCP connect when no prober is set.
    pub async fn probe_node(&self, node_id: Uuid, timeout: Duration) -> bool {
        let Ok(permit) = self.acquire_health_probe() else {
            return false;
        };
        let cancel = permit.cancellation();
        // block has no liveness to measure.
        if node_id == honk_config::config::BLOCK_NODE_ID {
            return true;
        }
        // direct is measured against the bootstrap resolver (default
        // 223.5.5.5:53) with a raw connect: the proxy check URL is chosen
        // for proxied egress and is commonly unreachable over a direct
        // connection (e.g. google-analytics from CN). The result feeds
        // latency ranking but never the liveness verdict (see
        // mark_unavailable_internal).
        if node_id == honk_config::config::DIRECT_NODE_ID {
            let registration = self.registered.read().nodes.get(&node_id).cloned();
            let target = self.direct_check_addr.read().clone();
            return self
                .probe_node_tcp(
                    node_id,
                    "direct",
                    Some(&target),
                    timeout,
                    registration.as_ref(),
                    &cancel,
                )
                .await;
        }
        let registered = self.registered.read().nodes.get(&node_id).cloned();
        let Some(registered) = registered else {
            return false;
        };

        // Clone the Arc out of the lock before awaiting (parking_lot guard is !Send).
        let prober = self.http_prober.read().clone();
        if let Some(prober) = &prober {
            self.probe_node_http(node_id, &registered, timeout, prober, &cancel)
                .await
        } else {
            self.probe_node_tcp(
                node_id,
                &registered.name,
                registered.raw_probe_address.as_deref(),
                timeout,
                Some(&registered),
                &cancel,
            )
            .await
        }
    }

    /// HTTP-based health check: resolves the check URL hostname, dials through
    /// the proxy node, and validates the HTTP response status code.
    async fn probe_node_http(
        &self,
        node_id: Uuid,
        registered: &Arc<RegisteredNode>,
        timeout: Duration,
        prober: &HttpProberRef,
        cancel: &ProbeCancellation,
    ) -> bool {
        let node_name = registered.name.as_str();
        let check_url = self.check_url.read().clone();
        let Ok(target) = honk_config::check::decode_health_http_target(&check_url) else {
            return self
                .probe_node_tcp(
                    node_id,
                    node_name,
                    registered.raw_probe_address.as_deref(),
                    timeout,
                    Some(registered),
                    cancel,
                )
                .await;
        };
        let hostname = target.host();

        // Use cached IPs from startup (Go: TcpCheckOption.Ip46).
        // Avoids repeated DNS resolution which can fail transiently and
        // cascade into all nodes being marked dead simultaneously.
        // Configured dae-format literal fallbacks remain usable when DNS
        // resolution fails or is locally refused.
        let port = target.port();
        let cached = self.check_url_ips.read().clone();
        let addrs: Vec<SocketAddr> = if cached.is_empty() {
            // Cache miss — one-time resolution via the installed resolver.
            let resolved = self.resolve_host(hostname, port).await.unwrap_or_default();
            let ips = Self::merge_check_addrs(resolved, &check_url, port);
            *self.check_url_ips.write() = ips.clone();
            ips
        } else {
            cached
        };

        if addrs.is_empty() {
            tracing::debug!(
                "Health check found no addresses for '{}' (node '{}')",
                hostname,
                node_name
            );
            return false;
        }

        // Try up to 3 addresses per family, stopping at the first success.
        // This prevents one stale cached address from consuming a failure on
        // every probe cycle when another address in the family still works.
        let mut by_family: [Vec<SocketAddr>; 2] = [Vec::new(), Vec::new()];
        for a in &addrs {
            let idx = if a.is_ipv4() { 0 } else { 1 };
            if by_family[idx].len() < 3 {
                by_family[idx].push(*a);
            }
        }

        let mut any_ok = false;
        for (idx, family_addrs) in by_family.iter().enumerate() {
            let ipver = if idx == 0 {
                IpVersion::V4
            } else {
                IpVersion::V6
            };
            if family_addrs.is_empty() {
                // A check URL with no address in this family yields no
                // evidence either way. Marking the family dead here killed
                // (Tcp, V6) on every cycle for v4-only check URLs, wedging
                // the group's v6 connectivity slot shut (#46).
                continue;
            }

            let mut family_ok = false;
            let mut family_failed = false;
            for a in family_addrs {
                let outcome = prober
                    .probe_http(node_id, *a, &check_url, timeout, cancel.clone())
                    .await;
                if let Some(observation) = outcome.observation {
                    self.record_health_observation(node_id, Some(registered), observation);
                }
                match outcome.result {
                    HttpProbeResult::Cancelled => {
                        if family_failed {
                            self.apply_probe_result(
                                node_id,
                                Some(registered),
                                ProbeDomain::Tcp,
                                ipver,
                                None,
                            );
                        }
                        return any_ok;
                    }
                    HttpProbeResult::WarmSuccess(elapsed) => {
                        tracing::debug!(
                            "HTTP health check succeeded for node '{}' via {} ({}ms)",
                            node_name,
                            a,
                            elapsed.as_millis()
                        );
                        self.apply_probe_result(
                            node_id,
                            Some(registered),
                            ProbeDomain::Tcp,
                            ipver,
                            Some(elapsed),
                        );
                        any_ok = true;
                        family_ok = true;
                        break;
                    }
                    HttpProbeResult::LocalRefusal(error) => {
                        tracing::debug!(%error, "HTTP health probe locally refused");
                        return any_ok;
                    }
                    HttpProbeResult::SetupFailure(error) => {
                        family_failed = true;
                        tracing::debug!(
                            "HTTP health check establishment failed for node '{}' via {}: {}",
                            node_name,
                            a,
                            error
                        );
                    }
                    HttpProbeResult::ExchangeFailure(error) => {
                        family_failed = true;
                        tracing::debug!(
                            "HTTP health check warm exchange failed for node '{}' via {}: {}",
                            node_name,
                            a,
                            error
                        );
                    }
                }
            }
            if !family_ok {
                self.apply_probe_result(node_id, Some(registered), ProbeDomain::Tcp, ipver, None);
            }
        }

        if any_ok {
            tracing::debug!("Node '{}' is alive after HTTP health check", node_name);
        } else {
            tracing::debug!(
                "Node '{}' failed HTTP health check for '{}' through proxy endpoint {}",
                node_name,
                check_url,
                registered.raw_probe_address.as_deref().unwrap_or_default()
            );
        }

        any_ok
    }

    /// Probe a group member against a custom per-group check URL
    /// (sing-box urltest `url` option). `tag` is the member identity the
    /// result is recorded under (a direct member's node name, or a
    /// sub-group's tag); `leaf` is the concrete node actually dialed (for
    /// sub-group member, its current pick). TCP-only HTTP like the global
    /// path: try up to 3 resolved addresses (any family),
    /// first success wins. State is tracked per (tag, url) and never
    /// touches the global six domains.
    pub(super) async fn probe_node_with_url(
        &self,
        tag: &str,
        leaf: Uuid,
        url: &str,
        timeout: Duration,
        native: Option<(GroupProbeContext, Uuid)>,
    ) -> bool {
        let Ok(permit) = self.acquire_health_probe() else {
            return false;
        };
        let cancel = permit.cancellation();
        // direct/block exemption, same rationale as probe_node. The
        // vacuous success still advances the (tag, url) liveness machine:
        // the tag may carry failures earned by a previous non-builtin leaf,
        // and leaving them would filter this member forever.
        if matches!(
            leaf,
            honk_config::config::DIRECT_NODE_ID | honk_config::config::BLOCK_NODE_ID
        ) {
            self.mark_url_probe_succeeded(tag, url);
            return true;
        }
        let registration = self.registered.read().nodes.get(&leaf).cloned();
        let prober_opt = self.http_prober.read().clone();
        let Some(ref prober) = prober_opt else {
            return false;
        };
        let addrs = match self.check_ips_for_url(url).await {
            Ok(addrs) => addrs,
            Err(_) => {
                tracing::debug!("Health check target resolution was locally refused for '{url}'");
                return false;
            }
        };
        if cancel.is_cancelled() {
            return false;
        }
        if addrs.is_empty() {
            tracing::debug!(
                "Health check found no addresses for '{}' (member '{}')",
                url,
                tag
            );
            self.record_url_probe_failure(tag, url);
            return false;
        }

        let mut any_ok = false;
        let mut failed = false;
        for a in addrs.into_iter().take(3) {
            let outcome = prober
                .probe_http(leaf, a, url, timeout, cancel.clone())
                .await;
            if let (Some(observation), Some((context, epoch))) = (outcome.observation, native) {
                self.record_group_health_observation(
                    leaf,
                    registration.as_ref(),
                    context,
                    epoch,
                    observation,
                );
            }
            match outcome.result {
                HttpProbeResult::Cancelled => {
                    if failed {
                        self.record_url_probe_failure(tag, url);
                    }
                    return any_ok;
                }
                HttpProbeResult::WarmSuccess(elapsed) => {
                    tracing::debug!(
                        "HTTP health check succeeded for member '{}' (leaf '{}') via {} ({}ms, url={})",
                        tag,
                        leaf,
                        a,
                        elapsed.as_millis(),
                        url
                    );
                    self.record_url_probe_success(tag, url, elapsed);
                    any_ok = true;
                    break;
                }
                HttpProbeResult::LocalRefusal(error) => {
                    tracing::debug!(%error, "Custom HTTP health probe locally refused");
                    return false;
                }
                HttpProbeResult::SetupFailure(error) => {
                    failed = true;
                    tracing::debug!(
                        "HTTP health check establishment failed for member '{}' (leaf '{}') via {} (url={}): {}",
                        tag,
                        leaf,
                        a,
                        url,
                        error
                    );
                }
                HttpProbeResult::ExchangeFailure(error) => {
                    failed = true;
                    tracing::debug!(
                        "HTTP health check warm exchange failed for member '{}' (leaf '{}') via {} (url={}): {}",
                        tag,
                        leaf,
                        a,
                        url,
                        error
                    );
                }
            }
        }
        if !any_ok {
            tracing::debug!(
                "Member '{}' (leaf '{}') failed HTTP health check against custom URL '{}'",
                tag,
                leaf,
                url
            );
            self.record_url_probe_failure(tag, url);
        }
        any_ok
    }

    /// Raw TCP connect health check when no HTTP prober or check URL is configured.
    async fn probe_node_tcp(
        &self,
        node_id: Uuid,
        node_name: &str,
        node_addr: Option<&str>,
        timeout: Duration,
        registration: Option<&Arc<RegisteredNode>>,
        cancel: &ProbeCancellation,
    ) -> bool {
        // A virtual chain has no endpoint of its own. With no raw target,
        // leave both families' health state alone.
        let Some(addr) = node_addr else {
            return [IpVersion::V4, IpVersion::V6]
                .into_iter()
                .any(|ipver| self.is_alive_for(node_id, ProbeDomain::Tcp, ipver));
        };
        let (host, port) = match addr.rsplit_once(':') {
            Some((host, port)) => port.parse::<u16>().map_or((addr, 80), |port| (host, port)),
            None => (addr, 80),
        };
        let addrs = match self.resolve_host(host, port).await {
            Ok(addrs) if !addrs.is_empty() => addrs,
            Ok(_) => {
                tracing::debug!(
                    "Health check DNS resolution failed for node '{}' ({}): system lookup failed",
                    node_name,
                    addr
                );
                self.apply_probe_result(
                    node_id,
                    registration,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                    None,
                );
                self.apply_probe_result(
                    node_id,
                    registration,
                    ProbeDomain::Tcp,
                    IpVersion::V6,
                    None,
                );
                return false;
            }
            Err(_) => {
                tracing::debug!(
                    "Health check target resolution was locally refused for node '{}' ({})",
                    node_name,
                    addr
                );
                return false;
            }
        };

        let mut probe_addrs: Vec<SocketAddr> = Vec::new();
        let mut any_v4 = false;
        let mut any_v6 = false;
        for a in &addrs {
            if a.is_ipv4() {
                if !any_v4 {
                    any_v4 = true;
                    probe_addrs.push(*a);
                }
            } else if !any_v6 {
                any_v6 = true;
                probe_addrs.push(*a);
            }
            if probe_addrs.len() >= IpVersion::count() {
                break;
            }
        }

        let mut any_ok = false;
        for a in &probe_addrs {
            let ipver = if a.is_ipv4() {
                IpVersion::V4
            } else {
                IpVersion::V6
            };

            let reporter = self.raw_probe_reporter(node_id, ipver);

            let start = Instant::now();
            let Some(result) = cancel
                .run(tokio::time::timeout(
                    timeout,
                    crate::util::connect_marked_addr(
                        *a,
                        Some(self.so_mark.unwrap_or_else(crate::util::bypass_mark)),
                        timeout,
                    ),
                ))
                .await
            else {
                return any_ok;
            };
            let elapsed = start.elapsed();
            self.record_health_observation(
                node_id,
                registration,
                HealthObservation::probe(
                    ProbeDomain::Tcp,
                    HealthMeasurement::TcpConnect,
                    ipver,
                    matches!(&result, Ok(Ok(_))).then_some(elapsed),
                    std::time::SystemTime::now(),
                ),
            );

            match result {
                Ok(Ok(_stream)) => {
                    if let Some(reporter) = &reporter {
                        reporter.setup_succeeded();
                        reporter.probe_latency(elapsed);
                        reporter.finish_setup_only();
                    }
                    tracing::debug!(
                        "Health check probe succeeded for node '{}' via {} ({}ms)",
                        node_name,
                        a,
                        elapsed.as_millis()
                    );
                    self.apply_probe_result(
                        node_id,
                        registration,
                        ProbeDomain::Tcp,
                        ipver,
                        Some(elapsed),
                    );
                    any_ok = true;
                }
                Ok(Err(e)) => {
                    if let Some(reporter) = &reporter {
                        reporter.finish(if e.kind() == std::io::ErrorKind::TimedOut {
                            ScoreOutcome::Timeout
                        } else {
                            ScoreOutcome::Io(e.kind())
                        });
                    }
                    tracing::debug!(
                        "Health check probe failed for node '{}' via {}: {}",
                        node_name,
                        a,
                        e
                    );
                    self.apply_probe_result(node_id, registration, ProbeDomain::Tcp, ipver, None);
                }
                Err(_) => {
                    if let Some(reporter) = &reporter {
                        reporter.finish(ScoreOutcome::Timeout);
                    }
                    tracing::debug!(
                        "Health check probe timed out for node '{}' via {} after {:?}",
                        node_name,
                        a,
                        timeout
                    );
                    self.apply_probe_result(node_id, registration, ProbeDomain::Tcp, ipver, None);
                }
            }
        }

        // A node address that resolves to a single address family says
        // nothing about the other family's reachability through the tunnel —
        // leave it untouched rather than dead-marking it without evidence.
        if any_ok {
            tracing::debug!("Node '{}' is alive after TCP health check", node_name);
        } else {
            tracing::debug!(
                "Node '{}' failed TCP health check against all addresses ({})",
                node_name,
                addr
            );
        }

        any_ok
    }

    /// Probe a single node's UDP data path (Go: UdpCheck) through the
    /// installed [`UdpProber`]: honk-core routes a minimal DNS query through
    /// the proxy handler's `dial_udp_transport` and awaits the answer, then —
    /// for Score group members with an HTTPS check URL — independently runs a
    /// real TLS-in-QUIC handshake against the check target.
    ///
    /// DNS success marks BOTH UDP domains (DataUdp + DnsUdp, v4+v6) alive and
    /// records the round-trip latency for URLTest ranking. When the DNS
    /// target is unreachable but the data-path handshake succeeded, only
    /// DnsUdp records a probe failure and DataUdp is marked alive from the
    /// handshake — a blocked `:53` check target must not condemn a working
    /// UDP path, because excluded nodes receive no traffic that could revive
    /// them. Total failure records one probe failure against each domain
    /// (probe threshold 3, exponential backoff via `mark_unavailable_internal`).
    /// TCP state is never touched. Without an installed prober this is a
    /// no-op returning `false`, and no state is recorded — nodes keep the
    /// legacy TCP-fallback selection semantics (see
    /// [`AliveDialerSet::has_udp_state`]).
    pub async fn probe_node_udp(&self, node_id: Uuid, timeout: Duration) -> bool {
        let registration = self.registered.read().nodes.get(&node_id).cloned();
        self.probe_node_udp_registered(node_id, timeout, registration)
            .await
    }

    pub(super) async fn probe_node_udp_registered(
        &self,
        node_id: Uuid,
        timeout: Duration,
        registration: Option<Arc<RegisteredNode>>,
    ) -> bool {
        let Ok(permit) = self.acquire_health_probe() else {
            return false;
        };
        if !Self::same_registration(
            self.registered.read().nodes.get(&node_id),
            registration.as_ref(),
        ) {
            return false;
        }
        // direct/block UDP liveness carries no verdict: the builtins are
        // never marked dead, and the UDP check target (e.g. 8.8.8.8) is not
        // a reliable direct-egress signal either.
        if matches!(
            node_id,
            honk_config::config::DIRECT_NODE_ID | honk_config::config::BLOCK_NODE_ID
        ) {
            return true;
        }
        // Clone the Arc out of the lock before awaiting (parking_lot guard
        // is !Send).
        let prober = self.udp_prober.read().clone();
        let Some(prober) = &prober else {
            return false;
        };

        let node_name = registration
            .as_ref()
            .map(|node| node.name.clone())
            .unwrap_or_else(|| node_id.to_string());
        const IPVERS: [IpVersion; 2] = [IpVersion::V4, IpVersion::V6];
        let outcome = prober
            .probe_udp(node_id, timeout, permit.cancellation())
            .await;
        for observation in outcome.observations.into_iter().flatten() {
            self.record_health_observation(node_id, registration.as_ref(), observation);
        }
        let measured = |result: Option<anyhow::Result<Duration>>| {
            result.filter(|result| {
                !result
                    .as_ref()
                    .is_err_and(crate::proxy::is_packet_rejection)
            })
        };
        match (measured(outcome.dns), measured(outcome.data_path)) {
            (Some(Ok(elapsed)), _) => {
                tracing::debug!(
                    "UDP health check succeeded for node '{}' ({}ms)",
                    node_name,
                    elapsed.as_millis()
                );
                for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
                    for ipver in IPVERS {
                        self.apply_probe_result(
                            node_id,
                            registration.as_ref(),
                            domain,
                            ipver,
                            Some(elapsed),
                        );
                    }
                }
                true
            }
            (Some(Err(dns_err)), Some(Ok(data_elapsed))) => {
                tracing::debug!(
                    "UDP DNS check failed for node '{}' but the data-path handshake succeeded ({}ms): {}",
                    node_name,
                    data_elapsed.as_millis(),
                    dns_err
                );
                for ipver in IPVERS {
                    self.apply_probe_result(
                        node_id,
                        registration.as_ref(),
                        ProbeDomain::DnsUdp,
                        ipver,
                        None,
                    );
                    self.apply_probe_result(
                        node_id,
                        registration.as_ref(),
                        ProbeDomain::DataUdp,
                        ipver,
                        Some(data_elapsed),
                    );
                }
                true
            }
            (Some(Err(err_msg)), data_path) => {
                match &data_path {
                    Some(Err(data_err)) => tracing::debug!(
                        "UDP health check failed for node '{}': {}; data-path handshake: {}",
                        node_name,
                        err_msg,
                        data_err
                    ),
                    _ => tracing::debug!(
                        "UDP health check failed for node '{}': {}",
                        node_name,
                        err_msg
                    ),
                }
                for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
                    for ipver in IPVERS {
                        self.apply_probe_result(
                            node_id,
                            registration.as_ref(),
                            domain,
                            ipver,
                            None,
                        );
                    }
                }
                false
            }
            (None, Some(Ok(data_elapsed))) => {
                for ipver in IPVERS {
                    self.apply_probe_result(
                        node_id,
                        registration.as_ref(),
                        ProbeDomain::DataUdp,
                        ipver,
                        Some(data_elapsed),
                    );
                }
                true
            }
            (None, Some(Err(_))) => {
                for ipver in IPVERS {
                    self.apply_probe_result(
                        node_id,
                        registration.as_ref(),
                        ProbeDomain::DataUdp,
                        ipver,
                        None,
                    );
                }
                false
            }
            (None, None) => false,
        }
    }

    /// Get recent probe history for a node for API/UI consumption.
    ///
    /// Returns the last `MAX_PROBE_HISTORY` probe records for the given
    /// node, domain, and IP version.  Returns an empty `Vec` if no history
    /// exists.
    pub fn get_probe_history(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Vec<ProbeRecord> {
        let idx = alive_index(domain, ipver);
        let key = (node_id, idx);
        self.probe_history
            .read()
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }
}
