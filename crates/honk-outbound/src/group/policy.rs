//! Per-policy picks over an already-flattened, already-filtered candidate
//! set: Selector precedence, URLTest lowest-latency with tolerance
//! hysteresis and separate TCP/UDP selections, LoadBalance round-robin,
//! Fallback first-alive pinning, plus the latency ranking they share.

use super::*;
use std::sync::atomic::Ordering;

impl GroupManager {
    /// Resolve the configured member before health filtering, so an
    /// unavailable choice cannot redirect traffic to a sibling member.
    pub(super) fn selector_member<'a>(&'a self, group: &'a Group) -> Option<GroupMember<'a>> {
        if group.policy != GroupPolicy::Selector {
            return None;
        }
        let choices = self.selector_choice.read();
        choices
            .get(&group.name)
            .map(String::as_str)
            .into_iter()
            .chain(group.default.as_deref())
            .find_map(|tag| self.members(group).find(|member| member.tag() == tag))
            .or_else(|| self.members(group).next())
    }

    /// Allocation-free selector fast path for a group with direct members
    /// only. It preserves selector precedence and liveness/custom-URL
    /// eligibility while the recursive path retains nested cycle guards.
    pub(super) fn pick_direct_selector<'a>(
        &'a self,
        group: &'a Group,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<&'a Node> {
        let GroupMember::Node(node) = self.selector_member(group)? else {
            return None;
        };
        let selectable = if domain == ProbeDomain::Tcp
            && let Some(url) = group.check_url.as_deref()
            && let Some(alive) = &self.alive_set
        {
            alive.is_alive_for_url(&node.name, url)
        } else {
            self.is_node_selectable_for_domain(node.id, domain, ipver)
        };
        selectable.then_some(node)
    }

    /// Require the configured member's candidate; a nested choice delegates
    /// to that group's own policy without escaping its membership.
    pub(super) fn pick_selector<'a>(
        candidates: &[Candidate<'a>],
        member: GroupMember<'a>,
    ) -> Option<Candidate<'a>> {
        candidates
            .iter()
            .find(|candidate| match (member, candidate.member()) {
                (GroupMember::Node(selected), GroupMember::Node(actual)) => {
                    selected.id == actual.id
                }
                (GroupMember::Group(selected), GroupMember::Group(actual)) => {
                    selected.name == actual.name
                }
                _ => false,
            })
            .cloned()
    }

    /// Rate-limited warning when every candidate was health-filtered and
    /// the sole TCP leaf is served as a last resort: traffic still flows,
    /// but every health signal voted no.
    pub(super) fn warn_selector_last_resort(
        &self,
        group: &Group,
        picked: &str,
        effects: SelectionEffects,
    ) {
        if !effects.applies() {
            return;
        }
        const LOG_COOLDOWN: Duration = Duration::from_secs(60);
        let now = Instant::now();
        let mut last = self.last_resort_log.write();
        if last
            .get(&group.name)
            .is_some_and(|previous| now.duration_since(*previous) < LOG_COOLDOWN)
        {
            return;
        }
        last.insert(group.name.clone(), now);
        drop(last);
        tracing::warn!(
            group = %group.name,
            picked = %picked,
            "no alive member for this network; serving the sole TCP leaf as last resort"
        );
    }

    pub(super) fn pick_score<'a>(
        &self,
        candidates: &[Candidate<'a>],
        group: &Group,
        context: &ScoreSelectionContext,
        effects: SelectionEffects,
    ) -> Candidate<'a> {
        let mut unique = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if !unique
                .iter()
                .any(|existing: &&Candidate<'a>| existing.node.id == candidate.node.id)
            {
                unique.push(candidate);
            }
        }
        let nodes: Vec<_> = unique.iter().map(|candidate| candidate.node).collect();
        let index = if effects.applies() {
            self.score_state
                .rank(&self.score_authority, &group.name, context, &nodes)
        } else {
            self.score_state.peek_rank(&group.name, context, &nodes)
        };
        unique[index].clone()
    }

    /// URLTest policy: lowest-latency alive candidate with tolerance-based
    /// stable selection. TCP and UDP keep independent selections (sing-box
    /// `selectedOutboundTCP` / `selectedOutboundUDP`); TCP ranks by TCP
    /// probes, UDP by DataUDP → DnsUDP → TCP probe latency. A sub-group
    /// candidate ranks by its representative leaf's latency, and selection
    /// identity is the member tag (so a sub-group's internal leaf change
    /// does not by itself switch the parent's selection).
    pub(super) fn pick_urltest<'a>(
        &self,
        candidates: &[Candidate<'a>],
        group: &Group,
        network: SelectionNetwork,
        ipver: IpVersion,
        effects: SelectionEffects,
    ) -> Candidate<'a> {
        let tolerance = Duration::from_millis(group.tolerance.max(1));

        // Without real UDP ranking evidence, keep the TCP-chosen member.
        // Synthetic dial failures alone must not disable this mirror.
        if network == SelectionNetwork::Udp
            && !self.alive_set.as_ref().is_some_and(|alive| {
                candidates.iter().any(|c| {
                    alive.has_real_ranking_evidence(c.node.id, ProbeDomain::DataUdp, ipver)
                        || alive.has_real_ranking_evidence(c.node.id, ProbeDomain::DnsUdp, ipver)
                })
            })
        {
            let tcp_entry = {
                let cache = self.urltest_cache.read();
                cache.get(&group.name).and_then(|sel| sel.tcp.clone())
            };
            if let Some(entry) = tcp_entry
                && let Some(c) = candidates.iter().find(|c| c.tag() == entry.tag)
            {
                if effects.applies()
                    && self.cache_urltest_selection(group, network, c, entry.latency)
                {
                    self.maybe_interrupt(&group.name);
                }
                return c.clone();
            }
            // No usable TCP selection yet — fall through to the normal
            // evaluation (which ranks by the latency fallback chain).
        }

        let best = self.pick_best_by_latency(candidates, group, network, ipver);

        {
            let cache = self.urltest_cache.read();
            if let Some(current) = cache.get(&group.name).and_then(|sel| sel.get(network))
                && let Some(pos) = candidates.iter().position(|c| c.tag() == current.tag)
            {
                let best_latency = self.node_latency(
                    best.node,
                    network,
                    ipver,
                    group.check_url.as_deref(),
                    best.tag(),
                );
                // Hysteresis baseline is the incumbent's *current* measured
                // latency, not the latency recorded when it was selected
                // (sing-box `Select()` / mihomo `fast()` parity): with the
                // stale baseline a degraded incumbent could never be
                // displaced. An incumbent with no current measurement gets
                // no hysteresis; neither does one carrying failure strikes
                // — a just-failed incumbent is replaced immediately.
                let current_latency = self.node_latency(
                    candidates[pos].node,
                    network,
                    ipver,
                    group.check_url.as_deref(),
                    candidates[pos].tag(),
                );
                if current_latency != Duration::MAX
                    && !self.failure_demoted(
                        candidates[pos].node,
                        network,
                        ipver,
                        group.check_url.as_deref(),
                    )
                    && best_latency.saturating_add(tolerance) >= current_latency
                {
                    return candidates[pos].clone();
                }
            }
        }

        let latency = self.node_latency(
            best.node,
            network,
            ipver,
            group.check_url.as_deref(),
            best.tag(),
        );
        if effects.applies() && self.cache_urltest_selection(group, network, &best, latency) {
            self.maybe_interrupt(&group.name);
        }

        best
    }

    /// LoadBalance policy: round-robin over the alive candidates in member
    /// order. Dead members never enter `candidates`, so the rotation skips
    /// them automatically. Each group/network counter is independent
    /// (`lb_counters`), and the pick never fires the interrupt callback:
    /// rotation is per-connection by design, so there is no stable
    /// group-level selection whose change would justify closing every
    /// tracked connection of the group (that would defeat load balancing).
    /// Connections to a node that actually dies are reaped by the alive
    /// set's traffic-failure reporting instead.
    pub(super) fn pick_load_balance<'a>(
        &self,
        candidates: &[Candidate<'a>],
        group: &Group,
        network: SelectionNetwork,
        effects: SelectionEffects,
    ) -> Candidate<'a> {
        let Some(counter) = self
            .lb_counters
            .get(&group.name)
            .map(|counters| &counters[network.slot()])
        else {
            return candidates[0].clone();
        };
        let cursor = if effects.applies() {
            counter.fetch_add(1, Ordering::Relaxed)
        } else {
            counter.load(Ordering::Relaxed)
        };
        candidates[cursor % candidates.len()].clone()
    }

    /// Fallback policy: first alive candidate in member order, pinned.
    ///
    /// The pinned member tag is kept while it remains in the alive
    /// candidate set; only its death triggers re-evaluation (next alive in
    /// member order). A recovered higher-preference member does NOT
    /// immediately win the pin back — deliberate hysteresis: failback
    /// flapping (a marginally-preferred member oscillating alive/dead
    /// would yank every connection twice) costs more than staying on a
    /// working lower-preference member until it actually fails.
    pub(super) fn pick_fallback<'a>(
        &self,
        candidates: &[Candidate<'a>],
        group: &Group,
        network: SelectionNetwork,
        effects: SelectionEffects,
    ) -> Candidate<'a> {
        {
            let cache = self.fallback_cache.read();
            if let Some(pinned) = cache
                .get(&group.name)
                .and_then(|pins| pins[network.slot()].as_deref())
                && let Some(c) = candidates.iter().find(|c| c.tag() == pinned)
            {
                return c.clone();
            }
        }
        let first = candidates[0].clone();
        if effects.applies() && self.cache_fallback_selection(group, network, &first) {
            self.maybe_interrupt(&group.name);
        }
        first
    }

    /// Pick the candidate with the lowest probe latency from alive_set.
    ///
    /// Two tiers: a failure-demoted candidate (recent probe/dial failure,
    /// strikes not yet cleared by consecutive real successes) ranks below
    /// every non-demoted candidate; within a tier the (real-only) moving
    /// average decides.
    pub(super) fn pick_best_by_latency<'a>(
        &self,
        candidates: &[Candidate<'a>],
        group: &Group,
        network: SelectionNetwork,
        ipver: IpVersion,
    ) -> Candidate<'a> {
        candidates
            .iter()
            .min_by_key(|c| {
                (
                    self.failure_demoted(c.node, network, ipver, group.check_url.as_deref()),
                    self.node_latency(c.node, network, ipver, group.check_url.as_deref(), c.tag()),
                )
            })
            .cloned()
            .unwrap_or_else(|| candidates[0].clone())
    }

    /// Whether the node carries pending failure strikes. UDP checks both
    /// UDP domains; the per-(node, url) TCP path tracks no strikes and
    /// always reports not demoted.
    fn failure_demoted(
        &self,
        node: &Node,
        network: SelectionNetwork,
        ipver: IpVersion,
        check_url: Option<&str>,
    ) -> bool {
        let Some(alive) = self.alive_set.as_ref() else {
            return false;
        };
        match network {
            SelectionNetwork::Tcp => {
                check_url.is_none() && alive.is_failure_demoted(node.id, ProbeDomain::Tcp, ipver)
            }
            SelectionNetwork::Udp => {
                alive.is_failure_demoted(node.id, ProbeDomain::DataUdp, ipver)
                    || alive.is_failure_demoted(node.id, ProbeDomain::DnsUdp, ipver)
            }
        }
    }

    /// Effective selection latency for a node on the given network.
    ///
    /// Ranking uses the **halving moving average** (`(prev + sample) / 2`,
    /// dae `min_moving_avg` semantics) over real measurements: recent
    /// samples weigh exponentially more, so a degraded node is displaced
    /// within a few probe cycles while single-sample jitter stays smoothed.
    /// Synthetic failure samples never feed the average — their demotion is
    /// handled by the failure-strike tier in `pick_best_by_latency`.
    /// TCP ranks by the TCP-probe average — or, when the
    /// group has a custom `check_url`, by the per-(node, url) probe average
    /// (sing-box urltest `url` option). UDP ranks by the DataUDP then
    /// DNS-UDP averages only — a node with no UDP measurement ranks
    /// `Duration::MAX` (never its TCP latency), so UDP-proven nodes always
    /// beat UDP-unproven ones; the all-no-UDP-data case is handled
    /// separately by the TCP mirror in [`GroupManager::pick_urltest`].
    pub(super) fn node_latency(
        &self,
        node: &Node,
        network: SelectionNetwork,
        ipver: IpVersion,
        check_url: Option<&str>,
        tag: &str,
    ) -> Duration {
        let latency = match network {
            SelectionNetwork::Tcp => match check_url {
                Some(url) => self
                    .alive_set
                    .as_ref()
                    .and_then(|a| a.get_avg_latency_for_url(tag, url)),
                None => self
                    .alive_set
                    .as_ref()
                    .and_then(|a| a.get_moving_average(node.id, ProbeDomain::Tcp, ipver)),
            },
            SelectionNetwork::Udp => self
                .alive_set
                .as_ref()
                .and_then(|a| a.get_moving_average(node.id, ProbeDomain::DataUdp, ipver))
                .or_else(|| {
                    self.alive_set
                        .as_ref()
                        .and_then(|a| a.get_moving_average(node.id, ProbeDomain::DnsUdp, ipver))
                }),
        };
        latency.unwrap_or(Duration::MAX)
    }

    /// Order candidates by (network-aware) latency, lowest first.
    pub(super) fn order_by_latency<'a>(
        &self,
        mut candidates: Vec<Candidate<'a>>,
        network: SelectionNetwork,
        ipver: IpVersion,
        check_url: Option<&str>,
    ) -> Vec<Candidate<'a>> {
        candidates.sort_by_key(|c| self.node_latency(c.node, network, ipver, check_url, c.tag()));
        candidates
    }
}
