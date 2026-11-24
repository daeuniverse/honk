use super::*;

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
        let result = self.wait_health_drained().await;
        let retired_prober = self.route_http_prober.write().take();
        drop(retired_prober);
        result
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
    pub async fn run_health_check_cycle(self: &Arc<Self>, timeout: Duration) {
        self.run_health_check_cycle_concurrent(timeout, 1).await;
    }

    async fn run_probe_batch<F>(
        self: &Arc<Self>,
        nodes: impl Iterator<Item = F> + Send,
        timeout: Duration,
        concurrency: usize,
        cancel: &ProbeCancellation,
    ) where
        F: Future<Output = ()> + Send + 'static,
    {
        let concurrency = concurrency.max(1);
        let route_prober = self.route_http_prober.read().clone();
        // A sweep stays bounded even if earlier misses become due again
        // while the other slots drain.
        let mut route_budget = route_prober.as_ref().map_or(0, |_| concurrency);
        let mut prefer_route = true;
        let mut nodes = nodes.peekable();
        let mut workers = tokio::task::JoinSet::new();
        loop {
            while workers.len() < concurrency && !cancel.is_cancelled() {
                if route_budget > 0 && (prefer_route || nodes.peek().is_none()) {
                    if let Some(prober) = route_prober.as_ref()
                        && let Some(ticket) = self.take_route_probe()
                    {
                        let deadline = tokio::time::Instant::now() + timeout;
                        let this = Arc::clone(self);
                        let prober = Arc::clone(prober);
                        let cancel = cancel.clone();
                        workers.spawn(async move {
                            this.probe_failed_route(prober.as_ref(), ticket, deadline, cancel)
                                .await;
                        });
                        route_budget -= 1;
                        prefer_route = false;
                        continue;
                    }
                    route_budget = 0;
                }
                let Some(node) = nodes.next() else {
                    break;
                };
                workers.spawn(node);
                prefer_route = true;
            }
            match workers.join_next().await {
                Some(Ok(())) => {}
                Some(Err(_)) => self.health_worker_failed(),
                None => break,
            }
        }
    }

    /// Revisit failed routes and dead protocol families between full cycles.
    /// The delay between configured health sweeps need not delay recovery.
    pub(super) async fn run_recovery_check_cycle_concurrent(
        self: &Arc<Self>,
        timeout: Duration,
        concurrency: usize,
    ) {
        let Ok(permit) = self.acquire_health_probe() else {
            return;
        };
        let nodes: Vec<_> = self
            .registered
            .read()
            .nodes
            .iter()
            .map(|(id, node)| (*id, Arc::clone(node)))
            .collect();
        let cancel = permit.cancellation();

        let due = nodes.into_iter().filter_map(|(id, registration)| {
            if self.is_probe_suspended(id) {
                return None;
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
                return None;
            }
            let this = self.clone();
            Some(async move {
                if tcp_due {
                    this.probe_node(id, timeout).await;
                }
                if udp_due {
                    this.probe_node_udp_registered(id, timeout, Some(registration))
                        .await;
                }
            })
        });
        self.run_probe_batch(due, timeout, concurrency, &cancel)
            .await;
    }

    /// Run health check cycle with concurrent probing.
    ///
    /// Node and route work share available slots (default 10). TCP backoff
    /// does not gate the shared UDP probe; emergency TCP probes retain their
    /// own bounded worker set.
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
            .nodes
            .iter()
            .map(|(id, node)| (*id, Arc::clone(node)))
            .collect();
        let has_registered_nodes = !nodes.is_empty();

        let due = nodes.into_iter().filter_map(|(id, registration)| {
            // URLTest idle suspension: skip nodes whose groups are all idle
            // (lazy start: never-active groups start suspended).
            if self.is_probe_suspended(id) {
                tracing::trace!("Skipping health check for '{}' (URLTest groups idle)", id);
                return None;
            }
            // Stopped nodes are probed too — on their slow max_cooldown
            // cadence — so recovery stays reachable (see `should_probe`).
            let tcp_due = self.should_probe(id, ProbeDomain::Tcp, IpVersion::V4);
            if !tcp_due && !self.should_probe(id, ProbeDomain::DataUdp, IpVersion::V4) {
                return None;
            }
            let this = self.clone();
            Some(async move {
                if tcp_due {
                    this.probe_node(id, timeout).await;
                }
                // Keep UDP backoff independent of TCP, including after waiting
                // for the TCP probe. Deep backoff retains its capped cadence.
                if this.should_probe(id, ProbeDomain::DataUdp, IpVersion::V4) {
                    this.probe_node_udp_registered(id, timeout, Some(registration))
                        .await;
                }
            })
        });
        self.run_probe_batch(due, timeout, concurrency, &cancel)
            .await;
        if !has_registered_nodes || cancel.is_cancelled() {
            return;
        }
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
        let mut join_set = tokio::task::JoinSet::new();

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
                                // The emergency probe runs TCP only; UDP
                                // backoff stays with the UDP domains.
                                if let Some(entry) = states.get_mut(&id) {
                                    for ipver in [IpVersion::V4, IpVersion::V6] {
                                        entry[alive_index(ProbeDomain::Tcp, ipver)]
                                            .cooldown_until = Instant::now();
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
