use super::*;
use crate::group::{
    ScoreOutcome, ScoreReporter, ScoreSelectionContext, ScoreSource, SelectionNetwork,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HealthMode {
    Running,
    Stopped,
    Failed,
}

#[derive(Default)]
pub(super) struct HealthControl {
    active: usize,
    loop_running: bool,
    failed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HealthCheckError {
    #[error("health checks are stopped")]
    Stopped,
    #[error("health probe capacity exhausted")]
    Busy,
    #[error("health-check drain timed out")]
    DrainTimeout,
    #[error("health-check worker failed")]
    WorkerFailed,
}

/// A captured health generation. Cancellation drops only the supplied I/O future;
/// callers must finish child/transport cleanup outside `run`.
#[derive(Clone, Default)]
pub struct ProbeCancellation {
    mode: Option<tokio::sync::watch::Sender<HealthMode>>,
    #[cfg(feature = "owned-tasks")]
    resolver_tasks: Option<Arc<crate::runtime::TaskOwner>>,
}

impl ProbeCancellation {
    pub fn is_cancelled(&self) -> bool {
        self.mode
            .as_ref()
            .is_some_and(|mode| *mode.borrow() != HealthMode::Running)
    }
    pub async fn cancelled(&self) {
        let Some(sender) = self.mode.as_ref() else {
            return std::future::pending().await;
        };
        let mut mode = sender.subscribe();
        while *mode.borrow_and_update() == HealthMode::Running {
            if mode.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn report_cleanup_failure(&self) {
        if let Some(mode) = &self.mode {
            mode.send_replace(HealthMode::Failed);
        }
    }

    pub async fn run<F: Future>(&self, future: F) -> Option<F::Output> {
        if self.is_cancelled() {
            return None;
        }
        tokio::select! {
            biased;
            result = future => Some(result),
            _ = self.cancelled() => None,
        }
    }

    /// Keep blocking fallback lookups in the health generation, including when
    /// the measured node itself reuses a warm production runtime.
    pub async fn scope_resolution<T>(
        &self,
        future: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        #[cfg(feature = "owned-tasks")]
        if let Some(owner) = &self.resolver_tasks {
            return owner.scope(future).await;
        }
        future.await
    }
}

/// Retain through network cleanup and synchronous result publication.
pub struct HealthProbePermit<'a> {
    alive: &'a AliveDialerSet,
    cancel: ProbeCancellation,
}

impl HealthProbePermit<'_> {
    pub fn cancellation(&self) -> ProbeCancellation {
        self.cancel.clone()
    }
}

impl Drop for HealthProbePermit<'_> {
    fn drop(&mut self) {
        self.alive.finish_health_probe();
    }
}

struct ExternalProbePermit(Arc<AliveDialerSet>);

impl Drop for ExternalProbePermit {
    fn drop(&mut self) {
        self.0.finish_health_probe();
    }
}

struct HealthLoopGuard {
    alive: Arc<AliveDialerSet>,
    terminal: bool,
}

impl Drop for HealthLoopGuard {
    fn drop(&mut self) {
        let mut control = self.alive.health_control.lock();
        control.loop_running = false;
        if !self.terminal {
            control.failed = true;
            self.alive.health_mode.send_replace(HealthMode::Stopped);
        }
        self.alive.health_changed.notify_waiters();
    }
}

impl AliveDialerSet {
    pub fn acquire_health_probe(&self) -> Result<HealthProbePermit<'_>, HealthCheckError> {
        let cancel = self.admit_health_probe()?;
        Ok(HealthProbePermit {
            alive: self,
            cancel,
        })
    }

    fn admit_health_probe(&self) -> Result<ProbeCancellation, HealthCheckError> {
        let mut control = self.health_control.lock();
        if control.failed {
            return Err(HealthCheckError::WorkerFailed);
        }
        match *self.health_mode.borrow() {
            HealthMode::Running => {}
            HealthMode::Stopped => return Err(HealthCheckError::Stopped),
            HealthMode::Failed => return Err(HealthCheckError::WorkerFailed),
        }
        control.active += 1;
        Ok(ProbeCancellation {
            mode: Some(self.health_mode.clone()),
            #[cfg(feature = "owned-tasks")]
            resolver_tasks: self.health_observations.read().is_some().then(|| {
                Arc::clone(
                    self.health_resolver_tasks
                        .lock()
                        .get_or_insert_with(|| Arc::new(crate::runtime::TaskOwner::production())),
                )
            }),
        })
    }

    fn finish_health_probe(&self) {
        let mut control = self.health_control.lock();
        control.active -= 1;
        control.failed |= std::thread::panicking();
        self.health_changed.notify_waiters();
    }

    /// The closure owns measurement, cleanup and publication. Dropping the
    /// response future does not abandon the registered job.
    pub async fn run_external_probe<T, F>(
        self: &Arc<Self>,
        make: impl FnOnce(ProbeCancellation) -> F + Send + 'static,
    ) -> Result<T, HealthCheckError>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let cancel = self.admit_health_probe()?;
        let permit = ExternalProbePermit(Arc::clone(self));
        let (reply, receive) = tokio::sync::oneshot::channel();
        {
            let mut tasks = self.external_probes.lock();
            while let Some(result) = tasks.try_join_next() {
                if result.is_err() {
                    cancel.report_cleanup_failure();
                }
            }
            if tasks.len() >= 10 {
                return Err(HealthCheckError::Busy);
            }
            tasks.spawn(async move {
                let result = if cancel.is_cancelled() {
                    Err(HealthCheckError::Stopped)
                } else {
                    Ok(make(cancel).await)
                };
                drop(permit);
                let _ = reply.send(result);
            });
        }
        receive.await.map_err(|_| HealthCheckError::WorkerFailed)?
    }

    /// Terminal stop; the caller still joins the retained health-loop handle.
    pub async fn shutdown_health_checks(&self) -> Result<(), HealthCheckError> {
        self.close_health_admission();
        self.wait_health_drained().await
    }

    fn close_health_admission(&self) {
        let _control = self.health_control.lock();
        let closed = self.health_mode.send_if_modified(|mode| {
            if *mode != HealthMode::Running {
                return false;
            }
            *mode = HealthMode::Stopped;
            true
        });
        if closed {
            self.advance_probe_epoch();
        }
    }

    async fn wait_health_drained(&self) -> Result<(), HealthCheckError> {
        let drain = async {
            loop {
                let changed = self.health_changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let drained = {
                    let control = self.health_control.lock();
                    control.active == 0
                        && !control.loop_running
                        && self.external_probes.lock().is_empty()
                };
                if drained {
                    #[cfg(feature = "owned-tasks")]
                    {
                        let owner = self.health_resolver_tasks.lock().clone();
                        if let Some(owner) = owner {
                            owner.close().await;
                            if owner.has_failed() {
                                self.health_worker_failed();
                            }
                        }
                    }
                    let control = self.health_control.lock();
                    return if control.failed || *self.health_mode.borrow() == HealthMode::Failed {
                        Err(HealthCheckError::WorkerFailed)
                    } else {
                        Ok(())
                    };
                }
                tokio::select! {
                    _ = &mut changed => {}
                    result = std::future::poll_fn(|cx| {
                        let mut tasks = self.external_probes.lock();
                        if tasks.is_empty() {
                            std::task::Poll::Pending
                        } else {
                            tasks.poll_join_next(cx)
                        }
                    }) => {
                        if matches!(result, Some(Err(_))) {
                            self.health_worker_failed();
                        }
                    }
                }
            }
        };
        tokio::pin!(drain);
        match tokio::time::timeout(Duration::from_secs(5), &mut drain).await {
            Ok(result) => result,
            Err(_) => {
                // A missed deadline is failure, not permission to detach blocking cleanup.
                drain.await?;
                Err(HealthCheckError::DrainTimeout)
            }
        }
    }

    fn health_worker_failed(&self) {
        self.health_control.lock().failed = true;
        self.health_mode.send_replace(HealthMode::Stopped);
        self.health_changed.notify_waiters();
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
        if !Self::same_registration(registered.get(&node_id), registration) {
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
            None => self.mark_unavailable_state(node_id, domain, ipver, false, false),
        };
        // Removal and result mutation have one order. Notifications run unlocked;
        // a reentrant resolver/callback must not authorize another old update.
        drop(registered);
        if changed {
            self.notify_health_change(node_id, domain, ipver, latency.is_some(), || {
                Self::same_registration(self.registered.read().get(&node_id), registration)
            });
        }
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
            let registration = self.registered.read().get(&node_id).cloned();
            let target = self.direct_check_addr.read().clone();
            return self
                .probe_node_tcp(
                    node_id,
                    "direct",
                    &target,
                    timeout,
                    registration.as_ref(),
                    &cancel,
                )
                .await;
        }
        let registered = self.registered.read().get(&node_id).cloned();
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
                &registered.address,
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
        if check_url.is_empty() {
            return self
                .probe_node_tcp(
                    node_id,
                    node_name,
                    &registered.address,
                    timeout,
                    Some(registered),
                    cancel,
                )
                .await;
        }

        let Ok(target) = honk_config::check::decode_health_http_target(&check_url) else {
            return self
                .probe_node_tcp(
                    node_id,
                    node_name,
                    &registered.address,
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
                registered.address
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
        let registration = self.registered.read().get(&leaf).cloned();
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

    /// Raw TCP connect health check (fallback when no HTTP prober configured).
    async fn probe_node_tcp(
        &self,
        node_id: Uuid,
        node_name: &str,
        node_addr: &str,
        timeout: Duration,
        registration: Option<&Arc<RegisteredNode>>,
        cancel: &ProbeCancellation,
    ) -> bool {
        let addr = node_addr.to_string();
        let (host, port) = match addr.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => (h.to_string(), port),
                Err(_) => (addr.clone(), 80),
            },
            None => (addr.clone(), 80),
        };
        let addrs = match self.resolve_host(&host, port).await {
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
        let registration = self.registered.read().get(&node_id).cloned();
        self.probe_node_udp_registered(node_id, timeout, registration)
            .await
    }

    async fn probe_node_udp_registered(
        &self,
        node_id: Uuid,
        timeout: Duration,
        registration: Option<Arc<RegisteredNode>>,
    ) -> bool {
        let Ok(permit) = self.acquire_health_probe() else {
            return false;
        };
        if !Self::same_registration(self.registered.read().get(&node_id), registration.as_ref()) {
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

    pub async fn run_health_check_cycle(self: &Arc<Self>, timeout: Duration) {
        self.run_health_check_cycle_concurrent(timeout, 1).await;
    }

    /// Probe only dead protocol families whose exponential backoff elapsed.
    /// This runs between full configured health cycles so a long check
    /// interval cannot turn a transient uplink outage into a long lockout.
    pub(super) async fn run_recovery_check_cycle_concurrent(
        self: &Arc<Self>,
        timeout: Duration,
        concurrency: usize,
    ) {
        let Ok(_permit) = self.acquire_health_probe() else {
            return;
        };
        let nodes: Vec<_> = self
            .registered
            .read()
            .iter()
            .map(|(id, node)| (*id, Arc::clone(node)))
            .collect();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
        let mut join_set = tokio::task::JoinSet::new();

        for (id, registration) in nodes {
            if self.is_probe_suspended(id) {
                continue;
            }
            let tcp_due = [IpVersion::V4, IpVersion::V6].into_iter().any(|ipver| {
                !self.is_alive_for(id, ProbeDomain::Tcp, ipver)
                    && self.should_probe(id, ProbeDomain::Tcp, ipver)
            });
            let udp_due = [ProbeDomain::DataUdp, ProbeDomain::DnsUdp]
                .into_iter()
                .any(|domain| {
                    [IpVersion::V4, IpVersion::V6].into_iter().any(|ipver| {
                        !self.is_alive_for(id, domain, ipver)
                            && self.should_probe(id, domain, ipver)
                    })
                });
            if !tcp_due && !udp_due {
                continue;
            }
            let this = self.clone();
            let permit = semaphore.clone();
            join_set.spawn(async move {
                let _permit = permit.acquire().await;
                if tcp_due {
                    this.probe_node(id, timeout).await;
                }
                if udp_due {
                    this.probe_node_udp_registered(id, timeout, Some(registration))
                        .await;
                }
            });
        }

        while let Some(result) = join_set.join_next().await {
            if result.is_err() {
                self.health_worker_failed();
            }
        }
    }

    /// Run health check cycle with concurrent probing.
    ///
    /// Uses a `JoinSet` with a semaphore to limit concurrency (default 10,
    /// matching sing-box). Nodes in backoff are skipped; the recovery runner
    /// revisits due dead nodes between full cycles. Emergency probes triggered
    /// via `trigger_probe` use their own bounded worker set.
    pub async fn run_health_check_cycle_concurrent(
        self: &Arc<Self>,
        timeout: Duration,
        concurrency: usize,
    ) {
        let Ok(permit) = self.acquire_health_probe() else {
            return;
        };
        let cancel = permit.cancellation();
        // Refresh cached check URL IPs at start of each full cycle.
        // Matches Go's TcpCheckOptionRaw.Reset().
        self.refresh_check_ips().await;

        let nodes: Vec<_> = self
            .registered
            .read()
            .iter()
            .map(|(id, node)| (*id, Arc::clone(node)))
            .collect();
        if nodes.is_empty() {
            return;
        }

        let concurrency = concurrency.max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut join_set = tokio::task::JoinSet::new();

        for (id, registration) in nodes {
            // URLTest idle suspension: skip nodes whose groups are all idle
            // (lazy start: never-active groups start suspended).
            if self.is_probe_suspended(id) {
                tracing::trace!("Skipping health check for '{}' (URLTest groups idle)", id);
                continue;
            }
            let idx = alive_index(ProbeDomain::Tcp, IpVersion::V4);
            let state = self.read_state(id, idx);
            // Stopped nodes are probed too — on their slow max_cooldown
            // cadence — so recovery stays reachable (see `should_probe`).
            if Instant::now() < state.cooldown_until {
                continue;
            }
            let this = self.clone();
            let permit = semaphore.clone();
            join_set.spawn(async move {
                let _p = permit.acquire().await;
                this.probe_node(id, timeout).await;
                // UDP data-path probe (Go: UdpCheck) after the TCP probe,
                // gated on the UDP domain's own backoff so a chronically
                // broken UDP path backs off exponentially (and eventually
                // stops) instead of re-probing every cycle. No-op without
                // an installed UdpProber.
                if this.should_probe(id, ProbeDomain::DataUdp, IpVersion::V4) {
                    this.probe_node_udp_registered(id, timeout, Some(registration))
                        .await;
                }
            });
        }

        while let Some(result) = join_set.join_next().await {
            if result.is_err() {
                self.health_worker_failed();
            }
        }
        if cancel.is_cancelled() {
            return;
        }

        // Per-group custom check URLs (sing-box urltest `url` option):
        // probe each group's members against its own target. Members are
        // (tag, leaf) pairs resolved fresh every cycle — for a sub-group
        // member the probe dials its CURRENT pick, and the result is
        // recorded under the sub-group's tag (sing-box RealTag semantics),
        // so nested groups rank correctly even as sub-picks change.
        let native_epoch = self.health_epoch();
        for (group, url) in self.group_check_urls() {
            if self.is_urltest_group_idle(&group) {
                tracing::trace!(
                    "Skipping custom-URL health checks for idle group '{}'",
                    group
                );
                continue;
            }
            for member in self.url_members_for(&group) {
                if !self.should_probe_url(&member.tag, &url) {
                    continue;
                }
                let this = self.clone();
                let url = url.clone();
                let permit = semaphore.clone();
                join_set.spawn(async move {
                    let _p = permit.acquire().await;
                    this.probe_node_with_url(
                        &member.tag,
                        member.leaf,
                        &url,
                        timeout,
                        member.native.zip(native_epoch),
                    )
                    .await;
                });
            }
        }

        while let Some(result) = join_set.join_next().await {
            if result.is_err() {
                self.health_worker_failed();
            }
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

    pub fn spawn_health_check_loop(
        self: &Arc<Self>,
        interval: Duration,
        timeout: Duration,
    ) -> tokio::task::JoinHandle<()> {
        self.spawn_health_check_loop_concurrent(interval, timeout, 10)
    }

    /// Spawn periodic, recovery, and emergency probes through bounded worker
    /// pools. Triggered work is node-deduplicated; full periodic cycles and
    /// dead-node recovery checks remain independently scheduled.
    pub fn spawn_health_check_loop_concurrent(
        self: &Arc<Self>,
        interval: Duration,
        timeout: Duration,
        concurrency: usize,
    ) -> tokio::task::JoinHandle<()> {
        let mut control = self.health_control.lock();
        assert!(!control.loop_running, "health loop already running");
        let mut trigger_rx = self
            .take_trigger_rx()
            .expect("health trigger receiver owned");
        control.loop_running = true;
        let mut mode = self.health_mode.subscribe();
        let mut owner = HealthLoopGuard {
            alive: Arc::clone(self),
            terminal: false,
        };
        drop(control);
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let concurrency = concurrency.max(1);
            let mut emergency_workers = tokio::task::JoinSet::new();
            let stagger_max = std::cmp::min(interval / 4, Duration::from_secs(5));
            let jitter = Duration::from_millis(
                rand::random::<u64>() % stagger_max.as_millis().max(1) as u64,
            );
            let mut ticker =
                tokio::time::interval_at(tokio::time::Instant::now() + jitter, interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let recovery_interval = interval.min(this.base_cooldown).max(Duration::from_secs(1));
            let mut recovery_ticker = tokio::time::interval_at(
                tokio::time::Instant::now() + recovery_interval,
                recovery_interval,
            );
            recovery_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                if *mode.borrow_and_update() != HealthMode::Running {
                    while let Some(result) = emergency_workers.join_next().await {
                        if result.is_err() {
                            this.health_worker_failed();
                        }
                    }
                    owner.terminal = true;
                    drop(owner);
                    return;
                }
                tokio::select! {
                    biased;
                    _ = mode.changed() => {}
                    Some(result) = emergency_workers.join_next(), if !emergency_workers.is_empty() => {
                        if result.is_err() {
                            this.health_worker_failed();
                        }
                    }
                    node = trigger_rx.recv(), if emergency_workers.len() < concurrency => {
                        if let Some(id) = node {
                            {
                                let mut states = this.states.write();
                                if let Some(entry) = states.get_mut(&id) {
                                    for state in entry {
                                        state.cooldown_until = Instant::now();
                                    }
                                }
                            }
                            let this = Arc::clone(&this);
                            emergency_workers.spawn(async move {
                                this.probe_node(id, timeout).await;
                                this.finish_trigger_probe(id);
                            });
                        }
                    }
                    _ = ticker.tick() => {
                        this.run_health_check_cycle_concurrent(timeout, concurrency).await;
                    }
                    _ = recovery_ticker.tick() => {
                        this.run_recovery_check_cycle_concurrent(timeout, concurrency).await;
                    }
                }
            }
        })
    }
}
