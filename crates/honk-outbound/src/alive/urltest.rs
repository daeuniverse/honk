use super::collection::DialerCollection;
use super::{
    AliveDialerSet, DEFAULT_URLTEST_IDLE_TIMEOUT, ProbeDomain, RECOVERY_SUCCESSES_NEEDED,
    UrlMemberResolver, UrlProbeMember, UrlProbeState, probe_backoff, probe_failure_threshold,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

impl AliveDialerSet {
    /// Register a URLTest group for idle-aware probe suspension.
    ///
    /// `members` are NodeIds; callers should exclude members that also
    /// belong to Selector groups (those are probed unconditionally).
    /// `idle_timeout` defaults to [`DEFAULT_URLTEST_IDLE_TIMEOUT`] when
    /// `None`. Re-callable on config reload.
    pub fn register_urltest_group(
        &self,
        group: &str,
        members: &[Uuid],
        idle_timeout: Option<Duration>,
    ) {
        let timeout = idle_timeout.unwrap_or(DEFAULT_URLTEST_IDLE_TIMEOUT);
        self.urltest_group_timeout
            .write()
            .insert(group.to_string(), timeout);
        self.urltest_group_members
            .write()
            .insert(group.to_string(), members.to_vec());
        let mut node_groups = self.node_urltest_groups.write();
        for member in members {
            node_groups
                .entry(*member)
                .or_default()
                .push(group.to_string());
        }
    }

    /// Replace the whole custom check-URL table (config reload), same
    /// shape as [`AliveDialerSet::sync_urltest_groups`]: `groups` is
    /// `(group name, check_url)` for every group that has a custom
    /// `check_url`. Entries for groups absent from `groups` are dropped;
    /// per-(tag, url) probe state and latency data survive as long as the
    /// URL itself is still in use by some group.
    pub fn sync_group_check_urls(&self, groups: &[(String, String)]) {
        {
            let mut map = self.group_check_urls.write();
            map.clear();
            for (group, url) in groups {
                map.insert(group.clone(), url.clone());
            }
            self.reset_group_health_observations();
        }
        let active_urls: HashSet<String> = self.group_check_urls.read().values().cloned().collect();
        self.url_check_ips
            .write()
            .retain(|url, _| active_urls.contains(url));
        self.url_states
            .write()
            .retain(|(_, url), _| active_urls.contains(url));
        self.url_collections
            .write()
            .retain(|(_, url), _| active_urls.contains(url));
    }

    /// Groups with a custom check URL: `(group name, url)`.
    pub fn group_check_urls(&self) -> Vec<(String, String)> {
        self.group_check_urls
            .read()
            .iter()
            .map(|(g, u)| (g.clone(), u.clone()))
            .collect()
    }

    /// Install the member-tag → leaf resolver used by custom-URL probing
    /// (see the `group_check_urls` field docs).
    pub fn set_url_member_resolver(&self, resolver: Option<UrlMemberResolver>) {
        *self.url_member_resolver.write() = resolver;
    }

    /// Resolve custom-check members with their captured leaf identities.
    /// Empty when no resolver is installed.
    pub fn url_members_for(&self, group: &str) -> Vec<UrlProbeMember> {
        self.url_member_resolver
            .read()
            .as_ref()
            .map(|r| r(group))
            .unwrap_or_default()
    }

    /// Whether the member is alive for a custom check URL. The key is the
    /// member tag; members never probed default to alive.
    pub fn is_alive_for_url(&self, node_id: &str, url: &str) -> bool {
        self.url_states
            .read()
            .get(&(node_id.to_string(), url.to_string()))
            .map(|s| s.alive)
            .unwrap_or(true)
    }

    /// Whether any probe result has been recorded for (member tag, url).
    pub fn has_url_state(&self, node_id: &str, url: &str) -> bool {
        self.url_states
            .read()
            .contains_key(&(node_id.to_string(), url.to_string()))
    }

    /// Moving-average latency for (member tag, check_url) — the ranking
    /// metric for URLTest groups with a custom check URL.
    pub fn get_avg_latency_for_url(&self, node_id: &str, url: &str) -> Option<Duration> {
        let cols = self.url_collections.read();
        let coll = cols.get(&(node_id.to_string(), url.to_string()))?;
        let ma = coll.moving_average_duration();
        if ma > Duration::ZERO { Some(ma) } else { None }
    }

    /// Record a successful custom-URL probe (recovery hysteresis mirrors
    /// the global path: a dead node needs RECOVERY_SUCCESSES_NEEDED
    /// consecutive successes to revive).
    pub(crate) fn record_url_probe_success(&self, node_id: &str, url: &str, latency: Duration) {
        self.mark_url_probe_succeeded(node_id, url);
        let key = (node_id.to_string(), url.to_string());
        let coll = {
            let mut cols = self.url_collections.write();
            cols.entry(key)
                .or_insert_with(|| Arc::new(DialerCollection::new()))
                .clone()
        };
        if self.is_alive_for_url(node_id, url) {
            coll.mark_available(latency);
        }
    }

    /// Advance only the (tag, url) liveness state machine. A builtin leaf
    /// (direct/block) is exempt from URL probing, but a state that died
    /// under a previous non-builtin leaf must still recover once the member
    /// resolves to a builtin, or the tag stays filtered forever.
    pub(crate) fn mark_url_probe_succeeded(&self, node_id: &str, url: &str) {
        let key = (node_id.to_string(), url.to_string());
        let mut states = self.url_states.write();
        let e = states.entry(key).or_insert_with(UrlProbeState::new);
        if e.alive {
            e.consecutive_failures = 0;
            e.consecutive_successes = 0;
            e.cooldown_until = Instant::now();
        } else {
            e.consecutive_successes += 1;
            e.consecutive_failures = 0;
            if e.consecutive_successes >= RECOVERY_SUCCESSES_NEEDED {
                e.alive = true;
                e.consecutive_successes = 0;
                e.cooldown_until = Instant::now();
            }
        }
    }

    /// Record a failed custom-URL probe: TCP-probe parity — three
    /// consecutive failures kill the node for this URL; backoff 5s→300s
    /// with no permanent stop.
    pub(crate) fn record_url_probe_failure(&self, node_id: &str, url: &str) {
        let key = (node_id.to_string(), url.to_string());
        let mut states = self.url_states.write();
        let e = states.entry(key).or_insert_with(UrlProbeState::new);
        e.consecutive_successes = 0;
        e.consecutive_failures += 1;
        let backoff = probe_backoff(
            self.base_cooldown,
            self.max_cooldown,
            e.consecutive_failures,
        );
        e.cooldown_until = Instant::now() + backoff;
        if e.consecutive_failures >= probe_failure_threshold(ProbeDomain::Tcp) {
            e.alive = false;
        }
    }

    /// Whether a (node, url) probe is due (deep backoff still probes on
    /// the slow cadence, matching the global path).
    pub(super) fn should_probe_url(&self, node_id: &str, url: &str) -> bool {
        self.url_states
            .read()
            .get(&(node_id.to_string(), url.to_string()))
            .map(|s| Instant::now() >= s.cooldown_until)
            .unwrap_or(true)
    }

    /// Cached resolved IPs for a custom check URL, resolving on first use
    /// (same caching + literal-fallback semantics as the global check URL).
    pub(super) async fn check_ips_for_url(&self, url: &str) -> anyhow::Result<Vec<SocketAddr>> {
        if let Some(ips) = self.url_check_ips.read().get(url) {
            return Ok(ips.clone());
        }
        let ips = match honk_config::check::decode_health_http_target(url) {
            Ok(target) => {
                let port = target.port();
                match self.resolve_host(target.host(), port).await {
                    Ok(addrs) => Self::merge_check_addrs(addrs, url, port),
                    Err(error) => {
                        let literals = Self::merge_check_addrs(Vec::new(), url, port);
                        if literals.is_empty() {
                            return Err(error);
                        }
                        literals
                    }
                }
            }
            Err(_) => Self::merge_check_addrs(Vec::new(), url, 80),
        };
        self.url_check_ips
            .write()
            .insert(url.to_string(), ips.clone());
        Ok(ips)
    }

    /// Replace the whole URLTest group table (config reload).
    ///
    /// `groups` is `(group name, member NodeIds, idle timeout)` per
    /// URLTest group — the same shape [`register_urltest_group`] takes.
    /// Entries for groups absent from `groups` are dropped, and the
    /// node → groups index is rebuilt from scratch (so stale memberships
    /// and duplicate entries from repeated registration disappear).
    /// `group_last_active` timestamps survive for groups that still exist,
    /// keeping the idle-suspension state across the reload.
    pub fn sync_urltest_groups(&self, groups: &[(String, Vec<Uuid>, Option<Duration>)]) {
        {
            let mut timeouts = self.urltest_group_timeout.write();
            let mut members_map = self.urltest_group_members.write();
            let mut node_groups = self.node_urltest_groups.write();
            timeouts.clear();
            members_map.clear();
            node_groups.clear();
            for (group, members, idle_timeout) in groups {
                timeouts.insert(
                    group.clone(),
                    idle_timeout.unwrap_or(DEFAULT_URLTEST_IDLE_TIMEOUT),
                );
                members_map.insert(group.clone(), members.clone());
                for member in members {
                    node_groups.entry(*member).or_default().push(group.clone());
                }
            }
        }
        let surviving: HashSet<String> =
            self.urltest_group_timeout.read().keys().cloned().collect();
        self.group_last_active
            .write()
            .retain(|group, _| surviving.contains(group));
    }

    /// Record activity for a group (called from group selection paths).
    ///
    /// When a suspended URLTest group becomes active again, health checks
    /// resume and member probes are kicked off immediately so latency data
    /// is fresh for the next selection.
    pub fn mark_group_active(&self, group: &str) {
        let Some(timeout) = self.urltest_group_timeout.read().get(group).copied() else {
            return;
        };
        let was_idle = {
            let mut active = self.group_last_active.write();
            let now = Instant::now();
            let was_idle = active
                .get(group)
                .is_none_or(|last| now.duration_since(*last) >= timeout);
            if let Some(last) = active.get_mut(group) {
                *last = now;
            } else {
                active.insert(group.to_owned(), now);
            }
            was_idle
        };
        if was_idle {
            let members = self
                .urltest_group_members
                .read()
                .get(group)
                .cloned()
                .unwrap_or_default();
            if !members.is_empty() {
                tracing::debug!(
                    "URLTest group '{}' active again — resuming member probes",
                    group
                );
                for member in members {
                    self.trigger_probe(member);
                }
            }
        }
    }

    /// Whether a registered URLTest group has been inactive for longer than
    /// its idle timeout. A never-active group counts as idle (lazy start:
    /// no probes run before the first selection). Unregistered groups are
    /// never idle.
    pub fn is_urltest_group_idle(&self, group: &str) -> bool {
        let timeout = match self.urltest_group_timeout.read().get(group) {
            Some(t) => *t,
            None => return false,
        };
        self.group_last_active
            .read()
            .get(group)
            .map(|t| t.elapsed() >= timeout)
            .unwrap_or(true)
    }

    /// Whether periodic probing of this node is suspended because every
    /// URLTest group it belongs to is idle. Nodes outside URLTest groups
    /// are never suspended.
    pub fn is_probe_suspended(&self, node_id: Uuid) -> bool {
        // Reload takes `urltest_group_timeout` first and this map last, so the
        // names are copied out rather than held across the idle checks.
        let groups = match self.node_urltest_groups.read().get(&node_id) {
            Some(groups) if !groups.is_empty() => groups.clone(),
            _ => return false,
        };
        groups.iter().all(|group| self.is_urltest_group_idle(group))
    }
}
