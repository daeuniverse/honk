use super::*;
use crate::group::{ScoreOutcome, ScoreReporter, ScoreSelectionContext, SelectionNetwork};

impl AliveDialerSet {
    fn raw_probe_reporter(&self, node_id: Uuid, ipver: IpVersion) -> Option<ScoreReporter> {
        self.score_feedback
            .read()
            .as_ref()
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
            .map(|feedback| feedback.streak_neutral().start())
    }
}

impl AliveDialerSet {
    /// Probe a single node's TCP reachability.
    ///
    /// When an HTTP prober is configured (Go: `TcpCheckOption`), this resolves
    /// the check URL's hostname to IPs and sends an HTTP request through the
    /// proxy node, validating the status code.
    /// Falls back to raw TCP connect when no prober is set.
    pub async fn probe_node(&self, node_id: Uuid, timeout: Duration) -> bool {
        // block has no liveness to measure.
        if node_id == honk_config::config::BLOCK_NODE_ID {
            return true;
        }
        // direct is measured against the bootstrap resolver (default
        // 223.5.5.5:53) with a raw connect: the proxy check URL is chosen
        // for proxied egress and is commonly unreachable over a direct
        // connection (e.g. google-analytics from CN). The result is a
        // display-only latency signal — failure marks never apply to the
        // direct builtin (see mark_unavailable_internal).
        if node_id == honk_config::config::DIRECT_NODE_ID {
            let target = self.direct_check_addr.read().clone();
            return self
                .probe_node_tcp(node_id, "direct", &target, timeout)
                .await;
        }
        let registered = self.registered.read().get(&node_id).cloned();
        let Some(registered) = registered else {
            return false;
        };

        // Clone the Arc out of the lock before awaiting (parking_lot guard is !Send).
        let prober_opt = self.http_prober.read().clone();
        if let Some(ref prober) = prober_opt {
            return self
                .probe_node_http(node_id, &registered, timeout, prober)
                .await;
        }

        self.probe_node_tcp(node_id, &registered.name, &registered.address, timeout)
            .await
    }

    /// HTTP-based health check: resolves the check URL hostname, dials through
    /// the proxy node, and validates the HTTP response status code.
    async fn probe_node_http(
        &self,
        node_id: Uuid,
        registered: &RegisteredNode,
        timeout: Duration,
        prober: &HttpProberRef,
    ) -> bool {
        let node_name = registered.name.as_str();
        let check_url = self.check_url.read().clone();
        if check_url.is_empty() {
            return self
                .probe_node_tcp(node_id, node_name, &registered.address, timeout)
                .await;
        }

        let Some(hostname) = Self::parse_url_host(&check_url) else {
            return self
                .probe_node_tcp(node_id, node_name, &registered.address, timeout)
                .await;
        };

        // Use cached IPs from startup (Go: TcpCheckOption.Ip46).
        // Avoids repeated DNS resolution which can fail transiently and
        // cascade into all nodes being marked dead simultaneously.
        // dae-format literal fallback IPs are merged in so a DNS failure
        // alone never leaves the probe without targets.
        let port = Self::parse_url_port(&check_url);
        let cached = self.check_url_ips.read().clone();
        let addrs: Vec<SocketAddr> = if cached.is_empty() {
            // Cache miss — one-time resolution via the installed resolver
            // (system lookup is the fallback inside resolve_host).
            let resolved = self.resolve_host(&hostname, port).await;
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
            for a in family_addrs {
                match prober.probe_http(node_name, *a, &check_url, timeout).await {
                    HttpProbeResult::WarmSuccess(elapsed) => {
                        tracing::debug!(
                            "HTTP health check succeeded for node '{}' via {} ({}ms)",
                            node_name,
                            a,
                            elapsed.as_millis()
                        );
                        self.record_probe_latency(node_id, ProbeDomain::Tcp, ipver, elapsed);
                        any_ok = true;
                        family_ok = true;
                        break;
                    }
                    HttpProbeResult::SetupFailure(error) => {
                        tracing::debug!(
                            "HTTP health check establishment failed for node '{}' via {}: {}",
                            node_name,
                            a,
                            error
                        );
                    }
                    HttpProbeResult::ExchangeFailure(error) => {
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
                self.mark_dead_for(node_id, ProbeDomain::Tcp, ipver);
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
    /// a sub-group member, its current pick). TCP-only, plain HTTP like
    /// the global path: try up to 3 resolved addresses (any family),
    /// first success wins. State is tracked per (tag, url) and never
    /// touches the global six domains.
    pub async fn probe_node_with_url(
        &self,
        tag: &str,
        leaf: &str,
        url: &str,
        timeout: Duration,
    ) -> bool {
        // direct/block exemption, same rationale as probe_node.
        if matches!(leaf, "direct" | "block") {
            return true;
        }
        let prober_opt = self.http_prober.read().clone();
        let Some(ref prober) = prober_opt else {
            return false;
        };
        if url.starts_with("https://") {
            // The periodic probe is plain HTTP/1.1 only; an https check URL
            // is downgraded (the request still proves reachability —
            // redirect/4xx responses count as healthy).
            tracing::debug!(
                "check URL '{}' uses https; probing over plain HTTP instead",
                url
            );
        }
        let addrs = self.check_ips_for_url(url).await;
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
        for a in addrs.into_iter().take(3) {
            match prober.probe_http(leaf, a, url, timeout).await {
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
                HttpProbeResult::SetupFailure(error) => {
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
    ) -> bool {
        let addr = node_addr.to_string();
        let (host, port) = match addr.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => (h.to_string(), port),
                Err(_) => (addr.clone(), 80),
            },
            None => (addr.clone(), 80),
        };
        let addrs: Vec<_> = {
            let out = self.resolve_host(&host, port).await;
            if !out.is_empty() {
                out
            } else {
                tracing::debug!(
                    "Health check DNS resolution failed for node '{}' ({}): system lookup failed",
                    node_name,
                    addr
                );
                self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V4);
                self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V6);
                return false;
            }
        };

        if addrs.is_empty() {
            tracing::debug!(
                "Health check found no addresses for node '{}' ({})",
                node_name,
                addr
            );
            self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V4);
            self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V6);
            return false;
        }

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
            let result = tokio::time::timeout(
                timeout,
                crate::util::connect_marked_addr(*a, self.so_mark, timeout),
            )
            .await;
            let elapsed = start.elapsed();

            match result {
                Ok(Ok(_stream)) => {
                    if let Some(reporter) = &reporter {
                        reporter.setup_succeeded();
                        reporter.finish_setup_only();
                    }
                    tracing::debug!(
                        "Health check probe succeeded for node '{}' via {} ({}ms)",
                        node_name,
                        a,
                        elapsed.as_millis()
                    );
                    self.record_probe_latency(node_id, ProbeDomain::Tcp, ipver, elapsed);
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
                    self.mark_dead_for(node_id, ProbeDomain::Tcp, ipver);
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
                    self.mark_dead_for(node_id, ProbeDomain::Tcp, ipver);
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
        let prober_opt = self.udp_prober.read().clone();
        let Some(ref prober) = prober_opt else {
            return false;
        };

        let node_name = self.node_name(node_id);
        const IPVERS: [IpVersion; 2] = [IpVersion::V4, IpVersion::V6];
        let outcome = prober.probe_udp(&node_name, timeout).await;
        match (outcome.dns, outcome.data_path) {
            (Ok(elapsed), _) => {
                tracing::debug!(
                    "UDP health check succeeded for node '{}' ({}ms)",
                    node_name,
                    elapsed.as_millis()
                );
                for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
                    for ipver in IPVERS {
                        self.mark_alive_for_latency(node_id, domain, ipver, elapsed);
                    }
                }
                true
            }
            (Err(dns_err), Some(Ok(data_elapsed))) => {
                tracing::debug!(
                    "UDP DNS check failed for node '{}' but the data-path handshake succeeded ({}ms): {}",
                    node_name,
                    data_elapsed.as_millis(),
                    dns_err
                );
                for ipver in IPVERS {
                    self.mark_dead_for(node_id, ProbeDomain::DnsUdp, ipver);
                    self.mark_alive_for_latency(node_id, ProbeDomain::DataUdp, ipver, data_elapsed);
                }
                true
            }
            (Err(err_msg), data_path) => {
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
                        self.mark_dead_for(node_id, domain, ipver);
                    }
                }
                false
            }
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
        let nodes: Vec<Uuid> = self.registered.read().keys().copied().collect();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
        let mut join_set = tokio::task::JoinSet::new();

        for id in nodes {
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
                    this.probe_node_udp(id, timeout).await;
                }
            });
        }

        while join_set.join_next().await.is_some() {}
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
        // Refresh cached check URL IPs at start of each full cycle.
        // Matches Go's TcpCheckOptionRaw.Reset().
        self.refresh_check_ips().await;

        let nodes: Vec<Uuid> = self.registered.read().keys().copied().collect();
        if nodes.is_empty() {
            return;
        }

        let concurrency = concurrency.max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut join_set = tokio::task::JoinSet::new();

        for id in nodes {
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
                    this.probe_node_udp(id, timeout).await;
                }
            });
        }

        while join_set.join_next().await.is_some() {}

        // Per-group custom check URLs (sing-box urltest `url` option):
        // probe each group's members against its own target. Members are
        // (tag, leaf) pairs resolved fresh every cycle — for a sub-group
        // member the probe dials its CURRENT pick, and the result is
        // recorded under the sub-group's tag (sing-box RealTag semantics),
        // so nested groups rank correctly even as sub-picks change.
        for (group, url) in self.group_check_urls() {
            if self.is_urltest_group_idle(&group) {
                tracing::trace!(
                    "Skipping custom-URL health checks for idle group '{}'",
                    group
                );
                continue;
            }
            for (tag, leaf) in self.url_members_for(&group) {
                if !self.should_probe_url(&tag, &url) {
                    continue;
                }
                let this = self.clone();
                let url = url.clone();
                let permit = semaphore.clone();
                join_set.spawn(async move {
                    let _p = permit.acquire().await;
                    this.probe_node_with_url(&tag, &leaf, &url, timeout).await;
                });
            }
        }

        while join_set.join_next().await.is_some() {}
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
        let this = self.clone();
        let mut trigger_rx = self.take_trigger_rx();
        let concurrency = concurrency.max(1);
        let mut emergency_workers = tokio::task::JoinSet::new();
        tokio::spawn(async move {
            // ── Anti-thundering-herd: stagger the first health check by a
            // random delay within [0, min(5s, interval/4)] to avoid all
            // nodes probing the proxy server simultaneously at startup.
            // Matches Go dae's initialConnectivityCheckJitterWindow logic.
            let stagger_max = std::cmp::min(interval / 4, std::time::Duration::from_secs(5));
            if stagger_max > std::time::Duration::ZERO {
                let jitter_ms =
                    (rand::random::<u64>() % stagger_max.as_millis().max(1) as u64) as u64;
                tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
            }

            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let recovery_interval = std::cmp::max(
                std::cmp::min(interval, this.base_cooldown),
                Duration::from_secs(1),
            );
            let mut recovery_ticker = tokio::time::interval(recovery_interval);
            recovery_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            recovery_ticker.tick().await;
            loop {
                tokio::select! {
                    biased;
                    Some(result) = emergency_workers.join_next(), if !emergency_workers.is_empty() => {
                        if let Err(error) = result {
                            tracing::warn!(?error, "emergency health-check worker panicked");
                        }
                    }
                    node = async {
                        match trigger_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending().await,
                        }
                    }, if emergency_workers.len() < concurrency => {
                        if let Some(id) = node {
                            {
                                let mut states = this.states.write();
                                if let Some(entry) = states.get_mut(&id) {
                                    for e in entry.iter_mut() {
                                        e.cooldown_until = Instant::now();
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
