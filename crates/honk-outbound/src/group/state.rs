//! Selection state: the runtime caches behind the policies (URLTest
//! selections per network, Fallback pins, Selector runtime choices, idle
//! timestamps) plus the persist/interrupt callbacks fired when they change.

use super::*;

/// Per-group URLTest selection entry. `tag` is the selected member tag: a
/// direct node name or a sub-group tag. It is the selection identity used
/// for hysteresis and display.
#[derive(Debug, Clone)]
pub(super) struct UrlTestEntry {
    pub(super) tag: String,
    pub(super) latency: Duration,
}

/// Per-group URLTest selections, one per network. The UDP selection is
/// ranked by UDP probe data; when no UDP measurements exist it mirrors
/// the TCP selection (sing-box `Now()` fallback semantics).
#[derive(Debug, Default)]
pub(super) struct UrlTestSelections {
    pub(super) tcp: Option<UrlTestEntry>,
    udp: Option<UrlTestEntry>,
}

impl UrlTestSelections {
    pub(super) fn get(&self, network: SelectionNetwork) -> Option<&UrlTestEntry> {
        match network {
            SelectionNetwork::Tcp => self.tcp.as_ref(),
            SelectionNetwork::Udp => self.udp.as_ref(),
        }
    }

    fn set(&mut self, network: SelectionNetwork, entry: UrlTestEntry) {
        match network {
            SelectionNetwork::Tcp => self.tcp = Some(entry),
            SelectionNetwork::Udp => self.udp = Some(entry),
        }
    }
}

/// Callback invoked when a Selector group's choice changes (group, node).
/// Used by honk-core to persist choices to cache.db.
pub type PersistCallback = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Callback invoked after an effective Selector choice write. The callback
/// is deliberately argument-free: the warm coordinator re-reads the whole
/// deduplicated selector set, which handles shared and nested selections.
pub type SelectorChangeCallback = Arc<dyn Fn() + Send + Sync>;

/// Callback invoked when a group's selected node changes while the group
/// has `interrupt_connections = true`. Argument is the group name;
/// honk-core closes the group's tracked connections.
pub type InterruptCallback = Arc<dyn Fn(&str) + Send + Sync>;

impl GroupManager {
    /// Set the selected node for a Selector group at runtime.
    ///
    /// On an actual change: the persist callback (cache.db persistence) and
    /// — when the group has `interrupt_connections` — the interrupt
    /// callback are invoked.
    pub fn set_selector_choice(&self, group_name: &str, node_name: &str) {
        {
            let mut choices = self.selector_choice.write();
            if choices.get(group_name).map(String::as_str) == Some(node_name) {
                return; // unchanged
            }
            choices.insert(group_name.to_string(), node_name.to_string());
        }
        if let Some(ref cb) = *self.persist_callback.read() {
            cb(group_name, node_name);
        }
        if let Some(ref cb) = *self.selector_change_callback.read() {
            cb();
        }
        self.maybe_interrupt(group_name);
    }

    /// Get the current selected node name for a Selector group.
    pub fn get_selector_choice(&self, group_name: &str) -> Option<String> {
        self.selector_choice.read().get(group_name).cloned()
    }

    /// Install the callback invoked when a Selector group's choice changes
    /// (group_name, node_name). Re-callable; pass `None` to remove.
    pub fn set_persist_callback(&self, cb: Option<PersistCallback>) {
        *self.persist_callback.write() = cb;
    }

    /// Install the callback that wakes Selector warm reconciliation.
    pub fn set_selector_change_callback(&self, cb: Option<SelectorChangeCallback>) {
        *self.selector_change_callback.write() = cb;
    }

    /// Install the callback invoked when a group's selected node changes
    /// and the group has `interrupt_connections = true`. Re-callable;
    /// pass `None` to remove.
    pub fn set_interrupt_callback(&self, cb: Option<InterruptCallback>) {
        *self.interrupt_callback.write() = cb;
    }
    /// Whether any group needs connection tracking for selection changes.
    pub fn has_interrupt_connections(&self) -> bool {
        self.groups
            .values()
            .any(|group| group.interrupt_connections)
    }

    /// Record group activity: updates idle tracking only for groups that
    /// actually configure an idle timeout, then wakes URLTest health checks.
    pub(super) fn mark_used(&self, group_name: &str) {
        if self
            .groups
            .get(group_name)
            .and_then(|group| group.idle_timeout)
            .is_some_and(|timeout| timeout > 0)
        {
            self.last_used
                .write()
                .insert(group_name.to_string(), Instant::now());
        }
        if let Some(alive) = &self.alive_set {
            alive.mark_group_active(group_name);
        }
    }

    /// Fire the interrupt callback when the group opted into connection
    /// interruption on selection changes (`interrupt_connections`).
    pub(super) fn maybe_interrupt(&self, group_name: &str) {
        let interrupt = self
            .groups
            .get(group_name)
            .map(|g| g.interrupt_connections)
            .unwrap_or(false);
        if !interrupt {
            return;
        }
        if let Some(ref cb) = *self.interrupt_callback.read() {
            cb(group_name);
        }
    }

    /// Whether this group has been idle longer than its `idle_timeout`.
    pub fn is_group_idle(&self, group_name: &str) -> bool {
        let group = match self.groups.get(group_name) {
            Some(g) => g,
            None => return false,
        };
        let idle_timeout = match group.idle_timeout {
            Some(t) if t > 0 => Duration::from_secs(t),
            _ => return false,
        };
        self.last_used
            .read()
            .get(group_name)
            .map(|t| t.elapsed() >= idle_timeout)
            .unwrap_or(true)
    }

    /// Get the current URLTest selected node name for TCP.
    ///
    /// This is the pre-split single-network view kept for API
    /// compatibility; new callers should use
    /// [`GroupManager::get_urltest_selection_for_network`].
    pub fn get_urltest_selection(&self, group_name: &str) -> Option<String> {
        self.get_urltest_selection_for_network(group_name, SelectionNetwork::Tcp)
    }

    /// Get the current URLTest selected member tag for the given network
    /// (a direct member's node name, or a sub-group's tag — this is what
    /// the clash `now` field displays).
    pub fn get_urltest_selection_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<String> {
        let cache = self.urltest_cache.read();
        cache
            .get(group_name)
            .and_then(|sel| sel.get(network))
            .map(|entry| entry.tag.clone())
    }

    /// Get the current TCP Fallback pinned member tag (for API/display).
    pub fn get_fallback_selection(&self, group_name: &str) -> Option<String> {
        self.get_fallback_selection_for_network(group_name, SelectionNetwork::Tcp)
    }

    pub fn get_fallback_selection_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<String> {
        self.fallback_cache
            .read()
            .get(group_name)
            .and_then(|pins| pins[network.slot()].clone())
    }

    /// Record `candidate` as the group's URLTest selection for `network`.
    /// Returns true when the selection actually changed (the first-ever
    /// selection is not a change — nothing to interrupt). Change is
    /// detected by member tag: a sub-group swapping its internal leaf
    /// keeps the parent's selection (and its connections) stable.
    pub(super) fn cache_urltest_selection(
        &self,
        group: &Group,
        network: SelectionNetwork,
        candidate: &Candidate,
        latency: Duration,
    ) -> bool {
        let mut cache = self.urltest_cache.write();
        let selections = cache.entry(group.name.clone()).or_default();
        let changed = selections
            .get(network)
            .map(|entry| entry.tag != candidate.tag)
            .unwrap_or(false);
        selections.set(
            network,
            UrlTestEntry {
                tag: candidate.tag.to_string(),
                latency,
            },
        );
        changed
    }

    /// Pin `candidate` as the group's Fallback selection. Returns true
    /// when the pin actually changed (the first-ever pin is not a change).
    /// The pin is by member tag — a sub-group stays pinned while it has
    /// any alive leaf to offer.
    pub(super) fn cache_fallback_selection(
        &self,
        group: &Group,
        network: SelectionNetwork,
        candidate: &Candidate,
    ) -> bool {
        let mut cache = self.fallback_cache.write();
        let pins = cache.entry(group.name.clone()).or_default();
        let pin = &mut pins[network.slot()];
        let changed = pin
            .as_deref()
            .map(|old| old != candidate.tag)
            .unwrap_or(false);
        *pin = Some(candidate.tag.to_owned());
        changed
    }
}
