use super::collection::{SLOW_DIAL_STREAK_MAX, TrafficVerdict};
use super::{
    AliveDialerSet, EMERGENCY_PROBE_COOLDOWN, GRACE_PERIOD, IpVersion, MAX_PROBE_BACKOFF_FAILURES,
    MAX_PROBE_HISTORY, ProbeDomain, ProbeRecord, RECOVERY_SUCCESSES_NEEDED, alive_index,
    probe_backoff, probe_failure_threshold, traffic_failure_threshold,
};
use honk_config::config::{BLOCK_NODE_ID, DIRECT_NODE_ID};
use std::time::{Duration, Instant};
use uuid::Uuid;

impl AliveDialerSet {
    fn push_ebpf(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion, alive: bool) {
        self.notify_health_change(node_id, domain, ipver, alive, || true);
    }

    pub(super) fn notify_health_change(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        alive: bool,
        is_current: impl Fn() -> bool,
    ) {
        let should_notify = || is_current() && self.is_alive_for(node_id, domain, ipver) == alive;
        if !should_notify() {
            return;
        }
        // Callers notify only on a flip, so this logs once per transition.
        let name = self.node_name(node_id);
        if alive {
            tracing::info!(
                "Node '{}' revived (domain={:?}, ipver={:?})",
                name,
                domain,
                ipver
            );
        } else {
            tracing::warn!(
                "Node '{}' marked dead (domain={:?}, ipver={:?})",
                name,
                domain,
                ipver
            );
        }
        let resolver = self.outbound_resolver.read().clone();
        let outbound = resolver.map_or(Some(0), |resolve| resolve(node_id));
        let ebpf_callback = self.ebpf_callback.read().clone();
        if let (Some(outbound), Some(cb)) = (outbound, ebpf_callback)
            && should_notify()
        {
            cb(node_id, outbound, domain as u32, ipver as u32, alive);
        }
        if !alive && should_notify() && !self.udp_sibling_explicitly_alive(node_id, domain) {
            let cb = self.death_callback.read().clone();
            if let Some(cb) = cb
                && should_notify()
            {
                cb(node_id, &name);
            }
        }
    }

    /// Whether any UDP-domain state (DataUdp or DnsUdp, either IP version)
    /// has ever been recorded for this node — i.e. it was UDP-probed or had
    /// UDP traffic reported. Group selection uses this to distinguish
    /// "never UDP-probed" (TCP liveness fallback applies) from "UDP-probed
    /// and dead" (excluded from UDP selection even when TCP is alive).
    pub fn has_udp_state(&self, node_id: Uuid) -> bool {
        let history = self.probe_history.read();
        [ProbeDomain::DataUdp, ProbeDomain::DnsUdp]
            .into_iter()
            .flat_map(|d| {
                [IpVersion::V4, IpVersion::V6]
                    .into_iter()
                    .map(move |v| (d, v))
            })
            .any(|(d, v)| {
                history
                    .get(&(node_id, alive_index(d, v)))
                    .is_some_and(|records| !records.is_empty())
            })
    }

    /// Whether the sibling UDP domain (the one that did not just die) has
    /// recorded, currently-alive state — the node is still carrying UDP
    /// traffic despite this domain's death.
    fn udp_sibling_explicitly_alive(&self, node_id: Uuid, dead: ProbeDomain) -> bool {
        let sibling = match dead {
            ProbeDomain::DataUdp => ProbeDomain::DnsUdp,
            ProbeDomain::DnsUdp => ProbeDomain::DataUdp,
            ProbeDomain::Tcp => return false,
        };
        let history = self.probe_history.read();
        [IpVersion::V4, IpVersion::V6].into_iter().any(|v| {
            self.is_alive_for(node_id, sibling, v)
                && history
                    .get(&(node_id, alive_index(sibling, v)))
                    .is_some_and(|records| !records.is_empty())
        })
    }

    #[cfg(test)]
    pub(super) fn mark_alive_for(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        self.mark_alive_for_latency(node_id, domain, ipver, Duration::ZERO);
    }

    /// Mark a node as alive for a specific domain/IP version, recording the
    /// probe latency so `Latencies10` and `MovingAverage` are updated.
    #[cfg(test)]
    pub(super) fn mark_alive_for_latency(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        latency: Duration,
    ) {
        if self.record_probe_latency_state(node_id, domain, ipver, latency, true) {
            self.push_ebpf(node_id, domain, ipver, true);
        }
    }

    /// Check if a node is within its grace period.
    fn is_in_grace_period(&self, node_id: Uuid) -> bool {
        self.node_registered_at
            .read()
            .get(&node_id)
            .map(|t| t.elapsed() < GRACE_PERIOD)
            .unwrap_or(false)
    }

    /// Append a probe record to history.
    fn record_probe_history(
        &self,
        node_id: Uuid,
        idx: usize,
        success: bool,
        latency: Option<Duration>,
    ) {
        let key = (node_id, idx);
        let mut history = self.probe_history.write();
        let entry = history.entry(key).or_default();
        entry.push(ProbeRecord {
            timestamp: Instant::now(),
            success,
            latency,
        });
        if entry.len() > MAX_PROBE_HISTORY {
            entry.remove(0);
        }
    }

    /// Internal: mark a node as unavailable using either probe or traffic counters.
    ///
    /// Matches Go's `markUnavailableInternal`:
    /// - `force` = true → force-dead immediately
    /// - `is_traffic` = true → use traffic_failure_threshold
    fn mark_unavailable_internal(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        force: bool,
        is_traffic: bool,
    ) {
        if self.mark_unavailable_state(node_id, domain, ipver, force, is_traffic) {
            self.notify_health_change(node_id, domain, ipver, false, || true);
        }
    }

    pub(super) fn mark_unavailable_state(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        force: bool,
        is_traffic: bool,
    ) -> bool {
        let idx = alive_index(domain, ipver);

        // Builtins are the base layer, not candidates: direct failures are
        // local-egress conditions (an unreachable target says nothing about
        // direct itself), and block refusals are policy working. Marking
        // either dead only fail-closes native traffic at TC and makes
        // groups fall back to proxies for traffic that should not be
        // proxied. Only the liveness verdict is suppressed — probes and
        // dial outcomes still feed latency ranking.
        if node_id == DIRECT_NODE_ID || node_id == BLOCK_NODE_ID {
            return false;
        }

        // During the grace period (fresh registrations, e.g. right after a
        // restart) neither probe nor traffic failures count toward death:
        // a startup DNS/warm-up hiccup must not mass-mark every node dead
        // and cause a full proxy outage that then needs minutes of revival
        // cycles to recover from. Forced deaths always bypass grace.
        if !force && self.is_in_grace_period(node_id) {
            self.record_probe_history(node_id, idx, false, None);
            return false;
        }

        let threshold = if is_traffic {
            traffic_failure_threshold(domain)
        } else {
            probe_failure_threshold(domain)
        };

        let changed = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            e.consecutive_successes = 0;
            if force {
                // Forced death: set counters to threshold to match state.
                e.consecutive_failures = threshold;
                e.traffic_failures = threshold;
                e.alive = false;
            } else if is_traffic {
                e.traffic_failures += 1;
                let f = e.traffic_failures;
                if f >= threshold {
                    e.alive = false;
                }
                // Traffic failures don't advance probe backoff cooldown
            } else {
                e.consecutive_failures += 1;
                let f = e.consecutive_failures;
                let backoff = probe_backoff(self.base_cooldown, self.max_cooldown, f);
                e.cooldown_until = Instant::now() + backoff;
                if f >= MAX_PROBE_BACKOFF_FAILURES {
                    e.stopped = true;
                }
                if f >= threshold {
                    e.alive = false;
                }
            }
            was && !e.alive && !force
        });

        if !is_traffic {
            // Probe counters own liveness and cooldown; ranking strikes are
            // reserved for real dial failures.
            self.get_or_create_collection(node_id, idx)
                .mark_probe_unavailable();
        }

        self.record_probe_history(node_id, idx, false, None);
        changed
    }

    pub(super) fn mark_dead_for(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        self.mark_unavailable_internal(node_id, domain, ipver, false, false);
    }

    /// Mark a TCP node as dead (public API for proxy dial failure callers).
    pub fn mark_dead(&self, node_id: Uuid) {
        self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V4);
        self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V6);
    }

    /// Report a node as unavailable due to real traffic failure.
    ///
    /// Uses the per-protocol traffic failure thresholds (TCP=10, UDP Data=50)
    /// so transient glitches don't immediately tear down the node's alive state.
    /// Matches Go's `Dialer.ReportUnavailable`.
    pub fn report_unavailable_traffic(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        // A blocked flow is policy working, not a health signal.
        if node_id == BLOCK_NODE_ID {
            return;
        }
        self.mark_unavailable_internal(node_id, domain, ipver, false, true);
    }

    /// Force-mark a node as dead immediately (used on fatal errors).
    /// Matches Go's `Dialer.ReportUnavailableForced`.
    pub fn report_unavailable_forced(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        if node_id == BLOCK_NODE_ID {
            return;
        }
        self.mark_unavailable_internal(node_id, domain, ipver, true, true);
    }

    /// Report successful traffic through a node, reviving its alive state.
    ///
    /// For DataUDP: a single successful real UDP flow can instantly revive
    /// the data-UDP health domain (Go: `ReportAvailableTraffic`).
    pub fn report_available_traffic(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        let idx = alive_index(domain, ipver);
        // A real dial success breaks the consecutive dial-failure streak —
        // even when the state is clean and nothing else needs updating.
        if let Some(arr) = self.collections.read().get(&node_id) {
            arr[idx].reset_dial_fail_streak();
        }
        if self
            .states
            .read()
            .get(&node_id)
            .is_some_and(|states| states[idx].is_clean_alive())
        {
            return;
        }
        let was_alive = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            e.reset_on_success();
            was
        });
        if !was_alive {
            self.push_ebpf(node_id, domain, ipver, true);
        }
    }

    /// Trigger an emergency TCP health check on this node.
    /// Rate-limited to once per EMERGENCY_PROBE_COOLDOWN to protect the worker pool.
    pub fn notify_check_tcp(&self, node_id: Uuid) {
        let now = Instant::now();
        let mut last = self.last_emergency_tcp.lock();
        if let Some(prev) = last.get(&node_id)
            && now.duration_since(*prev) < EMERGENCY_PROBE_COOLDOWN
        {
            return;
        }
        last.insert(node_id, now);
        drop(last);
        self.trigger_probe(node_id);
    }

    /// Trigger an emergency DNS UDP health check on this node.
    /// Rate-limited to once per EMERGENCY_PROBE_COOLDOWN.
    pub fn notify_check_dns_udp(&self, node_id: Uuid) {
        let now = Instant::now();
        let mut last = self.last_emergency_udp.lock();
        if let Some(prev) = last.get(&node_id)
            && now.duration_since(*prev) < EMERGENCY_PROBE_COOLDOWN
        {
            return;
        }
        last.insert(node_id, now);
        drop(last);
        self.trigger_probe(node_id);
    }

    /// Whether this node is in deep backoff (MAX_PROBE_BACKOFF_FAILURES
    /// consecutive failures). Such nodes still probe on the slow
    /// max_cooldown cadence; the flag is informational (API/diagnostics).
    /// Emergency probes can still be triggered via `notify_check_*`.
    pub fn is_probe_stopped(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) -> bool {
        let idx = alive_index(domain, ipver);
        self.states
            .read()
            .get(&node_id)
            .map(|s| s[idx].stopped)
            .unwrap_or(false)
    }

    /// Record a successful probe latency for a node + domain + IP version.
    /// Applies recovery hysteresis and feeds the selection moving average.
    pub fn record_probe_latency(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        latency: Duration,
    ) {
        if self.record_probe_latency_state(node_id, domain, ipver, latency, false) {
            self.push_ebpf(node_id, domain, ipver, true);
        }
    }

    pub(super) fn record_probe_latency_state(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        latency: Duration,
        immediate: bool,
    ) -> bool {
        let idx = alive_index(domain, ipver);
        let revived = self.with_state(node_id, idx, |e| {
            let was = e.alive;
            if was || immediate {
                e.reset_on_success();
                !was
            } else {
                e.consecutive_successes += 1;
                e.consecutive_failures = 0;
                e.traffic_failures = 0;
                if e.consecutive_successes >= RECOVERY_SUCCESSES_NEEDED {
                    e.alive = true;
                    e.stopped = false;
                    e.cooldown_until = Instant::now();
                    e.consecutive_successes = 0;
                    true
                } else {
                    tracing::debug!(
                        "Node '{}' recovery progress: {}/{} consecutive successes (domain={:?}, ipver={:?})",
                        node_id,
                        e.consecutive_successes,
                        RECOVERY_SUCCESSES_NEEDED,
                        domain,
                        ipver,
                    );
                    false
                }
            }
        });
        if (!immediate || latency > Duration::ZERO)
            && (revived || self.read_state(node_id, idx).alive)
        {
            self.get_or_create_collection(node_id, idx)
                .mark_available(latency);
        }

        self.record_probe_history(node_id, idx, true, Some(latency));
        revived
    }

    /// Read the moving average latency for a node-domain pair.
    ///
    /// Used by `GroupManager`'s `MinLatency` / `MinMovingAverage` policies.
    pub fn get_moving_average(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<Duration> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(&node_id).map(|arr| &arr[idx])?;
        let ma = coll.moving_average_duration();
        if ma > Duration::ZERO { Some(ma) } else { None }
    }

    /// Whether the node carries pending failure strikes in this domain.
    /// Selection demotes such nodes below every non-demoted candidate; the
    /// demotion clears only after max(strikes, 2) consecutive real
    /// successes, so a fast-but-flaky node cannot reclaim rank with one
    /// lucky probe.
    pub fn is_failure_demoted(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) -> bool {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        cols.get(&node_id)
            .is_some_and(|arr| arr[idx].is_failure_demoted())
    }

    /// Read the last probe latency for a node-domain pair.
    pub fn get_last_latency(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<Duration> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(&node_id).map(|arr| &arr[idx])?;
        coll.latencies.last()
    }

    /// Read the most recent REAL (non-synthetic) probe sample and its
    /// measurement time — display semantics for the clash delay history.
    /// Synthetic failure placeholders (10s) are skipped so dashboards never
    /// show them as a measured delay.
    pub fn get_last_real_sample(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<(Duration, std::time::SystemTime)> {
        let idx = alive_index(domain, ipver);
        let cols = self.collections.read();
        let coll = cols.get(&node_id).map(|arr| &arr[idx])?;
        coll.latencies.last_real_sample().map(|s| (s.latency, s.at))
    }

    /// Dial-failure handling: only DIAL_FAILURE_STRIKE_AT consecutive dial
    /// failures append the synthetic timeout sample and one failure strike —
    /// a lone transient failure (the retry race rescues that flow) leaves no
    /// selection state at all. The node's real history and moving average
    /// are retained so URLTest tolerance hysteresis keeps its baseline; the
    /// strike demotes the node in ranking until max(strikes, 2) consecutive
    /// real successes clear it, which is what stops a fast-but-flaky node
    /// from reclaiming the top rank with a single lucky probe.
    pub fn record_dial_failure(&self, node_id: Uuid, domain: ProbeDomain, ipver: IpVersion) {
        // block refusals are policy, and direct failures are local-egress
        // conditions — neither says anything about node quality.
        if node_id == BLOCK_NODE_ID || node_id == DIRECT_NODE_ID {
            return;
        }
        self.get_or_create_collection(node_id, alive_index(domain, ipver))
            .record_dial_failure();
    }

    /// Feed one REAL proxied dial's wall-clock latency (network round trip
    /// only — pool-ready hits are excluded by the caller). Sudden
    /// degradation (3 consecutive dials slower than min(2×ema, ema+500ms),
    /// floored at 250ms so fast nodes under load don't trip it)
    /// appends a synthetic failure strike (strike demotion) and returns
    /// true so the caller fires an emergency probe. Gradual drift stays
    /// owned by the probe cycle. Returns true once per demotion.
    ///
    /// A false positive (target-mix shift, not node decay) self-heals: the
    /// emergency probe succeeds and consecutive probe successes clear the
    /// strike while the replacement node serves traffic meanwhile.
    pub fn report_dial_latency(
        &self,
        node_id: Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
        elapsed: Duration,
    ) -> bool {
        // Local-egress latency is not node quality.
        if node_id == DIRECT_NODE_ID || node_id == BLOCK_NODE_ID {
            return false;
        }
        let coll = self.get_or_create_collection(node_id, alive_index(domain, ipver));
        match coll.record_traffic_latency(elapsed) {
            TrafficVerdict::Slow => {
                if coll.bump_slow_streak() >= SLOW_DIAL_STREAK_MAX {
                    coll.reset_slow_streak();
                    coll.mark_unavailable();
                    true
                } else {
                    false
                }
            }
            TrafficVerdict::Fast | TrafficVerdict::Warmup => {
                coll.reset_slow_streak();
                false
            }
        }
    }

    /// Seed a persisted delay sample into the node's TCP-v4 latency
    /// history (cache.db warm start). Does NOT touch alive state — probes
    /// decide liveness; this only pre-seeds ranking data so URLTest groups
    /// don't start cold after a restart.
    pub fn restore_latency(&self, node_id: Uuid, latency: Duration, at: std::time::SystemTime) {
        let idx = alive_index(ProbeDomain::Tcp, IpVersion::V4);
        let coll = self.get_or_create_collection(node_id, idx);
        coll.restore_sample(latency, at);
    }

    /// Snapshot every node's last real TCP-v4 latency sample for
    /// persistence. Synthetic (failure) samples are excluded.
    pub fn latency_snapshot(&self) -> Vec<(Uuid, Duration, std::time::SystemTime)> {
        let idx = alive_index(ProbeDomain::Tcp, IpVersion::V4);
        let cols = self.collections.read();
        cols.iter()
            .filter_map(|(node, arr)| {
                arr[idx]
                    .latencies
                    .last_real_sample()
                    .map(|s| (*node, s.latency, s.at))
            })
            .collect()
    }
}
