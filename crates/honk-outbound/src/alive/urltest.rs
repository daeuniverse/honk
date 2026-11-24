use super::collection::DialerCollection;
use super::{
    AliveDialerSet, DEFAULT_GROUP_IDLE_TIMEOUT, ProbeDomain, RECOVERY_SUCCESSES_NEEDED,
    UrlMemberResolver, UrlProbeMember, UrlProbeState, probe_backoff, probe_failure_threshold,
};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAX_ACTIVITY_REFRESH_QUANTUM_NS: u64 = 1_000_000_000;

/// How a group participates in idle probe suspension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleGroupKind {
    /// Automatic policy: wakes its direct members on selection and pauses them
    /// again after `idle_timeout` without traffic.
    Automatic,
    /// Selector policy: always counts as idle so unselected direct members stay
    /// suspended; only explicitly chosen members stay probed via `selected_nodes`.
    Selector,
}

pub(super) struct IdleGroupEntry {
    pub(super) timeout: Duration,
    pub(super) members: Vec<Uuid>,
    pub(super) kind: IdleGroupKind,
    /// Monotonic nanoseconds since `AliveDialerSet::started_at` + 1 (`0` = never active).
    pub(super) last_active_ns: AtomicU64,
}

impl IdleGroupEntry {
    pub(super) fn is_idle(&self, now_ns: u64) -> bool {
        if self.kind == IdleGroupKind::Selector || self.timeout.is_zero() {
            return true;
        }
        let last = self.last_active_ns.load(Ordering::Acquire);
        last == 0 || now_ns.saturating_sub(last) >= duration_to_ns(self.timeout)
    }
}

#[derive(Default)]
pub(super) struct IdleGroups {
    pub(super) groups: HashMap<String, IdleGroupEntry>,
    pub(super) node_groups: HashMap<Uuid, Vec<String>>,
}

impl IdleGroups {
    pub(super) fn remove_node(&mut self, node_id: Uuid) {
        if let Some(groups) = self.node_groups.remove(&node_id) {
            for group in groups {
                if let Some(entry) = self.groups.get_mut(&group) {
                    entry.members.retain(|&id| id != node_id);
                }
            }
        }
    }
}

fn duration_to_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

impl AliveDialerSet {
    pub(super) fn now_ns(&self) -> u64 {
        (self
            .started_at
            .elapsed()
            .as_nanos()
            .min(u64::MAX as u128 - 1) as u64)
            + 1
    }

    /// Register an automatic group for idle-aware probe suspension.
    ///
    /// `members` are the group's direct member NodeIds. `idle_timeout` defaults
    /// to [`DEFAULT_GROUP_IDLE_TIMEOUT`] when `None`. Replaces any prior entry
    /// for `group`; config reload uses [`Self::sync_idle_groups`].
    pub fn register_idle_group(
        &self,
        group: &str,
        members: &[Uuid],
        idle_timeout: Option<Duration>,
    ) {
        let mut idle = self.idle_groups.write();
        let last_active_ns = idle
            .groups
            .get(group)
            .filter(|old| old.kind == IdleGroupKind::Automatic)
            .map(|old| old.last_active_ns.load(Ordering::Relaxed))
            .unwrap_or(0);
        if let Some(old) = idle.groups.remove(group) {
            for member in old.members {
                if let Some(list) = idle.node_groups.get_mut(&member) {
                    list.retain(|name| name != group);
                    if list.is_empty() {
                        idle.node_groups.remove(&member);
                    }
                }
            }
        }
        let mut dedup_members = Vec::with_capacity(members.len());
        for &member in members {
            if !dedup_members.contains(&member) {
                dedup_members.push(member);
                idle.node_groups
                    .entry(member)
                    .or_default()
                    .push(group.to_string());
            }
        }
        idle.groups.insert(
            group.to_string(),
            IdleGroupEntry {
                timeout: idle_timeout.unwrap_or(DEFAULT_GROUP_IDLE_TIMEOUT),
                members: dedup_members,
                kind: IdleGroupKind::Automatic,
                last_active_ns: AtomicU64::new(last_active_ns),
            },
        );
    }

    /// Replace the whole custom check-URL table (config reload), same
    /// shape as [`AliveDialerSet::sync_idle_groups`]: `groups` is
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
                drop(states);
                self.notify_policy_change();
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
        if e.alive && e.consecutive_failures >= probe_failure_threshold(ProbeDomain::Tcp) {
            e.alive = false;
            drop(states);
            self.notify_policy_change();
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

    /// Replace the whole idle-group table atomically.
    ///
    /// Entries for groups absent from `groups` are dropped, duplicate group
    /// names resolve last-definition-wins, and the node → groups index is
    /// rebuilt from the deduplicated entries. Activity timestamps survive for
    /// automatic groups that still exist.
    pub fn sync_idle_groups(&self, groups: &[(String, Vec<Uuid>, Option<Duration>)]) {
        let mut idle = self.idle_groups.write();
        let old_groups = std::mem::take(&mut idle.groups);
        idle.node_groups.clear();
        let mut new_groups = HashMap::with_capacity(groups.len());
        for (group, members, idle_timeout) in groups {
            let last_active_ns = old_groups
                .get(group)
                .filter(|old| old.kind == IdleGroupKind::Automatic)
                .map(|old| old.last_active_ns.load(Ordering::Relaxed))
                .unwrap_or(0);
            let mut dedup_members = Vec::with_capacity(members.len());
            for &member in members {
                if !dedup_members.contains(&member) {
                    dedup_members.push(member);
                }
            }
            new_groups.insert(
                group.clone(),
                IdleGroupEntry {
                    timeout: idle_timeout.unwrap_or(DEFAULT_GROUP_IDLE_TIMEOUT),
                    members: dedup_members,
                    kind: IdleGroupKind::Automatic,
                    last_active_ns: AtomicU64::new(last_active_ns),
                },
            );
        }
        for (name, entry) in &new_groups {
            for &member in &entry.members {
                idle.node_groups
                    .entry(member)
                    .or_default()
                    .push(name.clone());
            }
        }
        idle.groups = new_groups;
    }

    /// Record activity for an automatic group.
    ///
    /// When a suspended automatic group becomes active again, health checks
    /// resume and its direct members are probed immediately. `Selector` groups
    /// and groups with `idle_timeout == 0` stay idle without firing per-selection
    /// wake-up probes.
    pub fn mark_group_active(&self, group: &str) {
        let idle = self.idle_groups.read();
        let Some(entry) = idle.groups.get(group) else {
            return;
        };
        if entry.kind == IdleGroupKind::Selector || entry.timeout.is_zero() {
            return;
        }
        let now_ns = self.now_ns();
        let timeout_ns = duration_to_ns(entry.timeout);
        let refresh_quantum_ns = (timeout_ns / 4).clamp(1, MAX_ACTIVITY_REFRESH_QUANTUM_NS);
        let prev = entry.last_active_ns.load(Ordering::Relaxed);
        if prev != 0 && now_ns.saturating_sub(prev) < refresh_quantum_ns {
            return;
        }
        let prev = entry.last_active_ns.fetch_max(now_ns, Ordering::AcqRel);
        if prev == 0 || now_ns.saturating_sub(prev) >= timeout_ns {
            let members = entry.members.clone();
            drop(idle);
            if !members.is_empty() {
                tracing::debug!("Group '{}' active again — resuming member probes", group);
                for member in members {
                    self.trigger_probe(member);
                }
            }
        }
    }

    /// Whether a registered group is currently idle. Never-active automatic
    /// groups, `Selector` groups, and groups with `idle_timeout == 0` count as
    /// idle. Unregistered groups are never idle.
    pub fn is_group_idle(&self, group: &str) -> bool {
        let idle = self.idle_groups.read();
        let Some(entry) = idle.groups.get(group) else {
            return false;
        };
        entry.is_idle(self.now_ns())
    }

    pub(super) fn is_groups_idle_for_node(&self, node_id: Uuid) -> bool {
        let idle = self.idle_groups.read();
        let Some(groups) = idle.node_groups.get(&node_id) else {
            return false;
        };
        if groups.is_empty() {
            return false;
        }
        let now_ns = self.now_ns();
        groups.iter().all(|group| {
            idle.groups
                .get(group)
                .is_some_and(|entry| entry.is_idle(now_ns))
        })
    }

    /// Whether periodic probing of this node is suspended because every
    /// group it belongs to is idle. Nodes outside any group and nodes a
    /// group holds fixed (see [`Self::set_selected_nodes`]) are never
    /// suspended.
    pub fn is_probe_suspended(&self, node_id: Uuid) -> bool {
        if self.selected_nodes.read().contains(&node_id) {
            return false;
        }
        self.is_groups_idle_for_node(node_id)
    }

    /// Replace the nodes groups hold fixed: a manual selection (Selector
    /// choice, an automatic group's pin) or a node `final`. They keep
    /// periodic probing while idle, so a manually selected dead node can
    /// still recover. Returns the nodes this took out of idle suspension.
    pub fn set_selected_nodes(&self, nodes: HashSet<Uuid>) -> Vec<Uuid> {
        let added: Vec<Uuid> = {
            let current = self.selected_nodes.read();
            nodes
                .iter()
                .filter(|id| !current.contains(id))
                .copied()
                .collect()
        };
        let woken = added
            .into_iter()
            .filter(|id| self.is_probe_suspended(*id))
            .collect();
        *self.selected_nodes.write() = nodes;
        woken
    }
}
