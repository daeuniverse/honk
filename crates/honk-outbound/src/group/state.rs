//! Runtime selection caches and callbacks fired when they change.

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

/// Exact direct-member identity, also used by the per-network persistence cache.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SelectorMember {
    Node(uuid::Uuid),
    Group(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorNetworks {
    Tcp,
    Udp,
    Both,
}

impl SelectorNetworks {
    pub fn contains(self, network: SelectionNetwork) -> bool {
        matches!(
            (self, network),
            (Self::Both, _)
                | (Self::Tcp, SelectionNetwork::Tcp)
                | (Self::Udp, SelectionNetwork::Udp)
        )
    }
}

impl From<SelectionNetwork> for SelectorNetworks {
    fn from(network: SelectionNetwork) -> Self {
        match network {
            SelectionNetwork::Tcp => Self::Tcp,
            SelectionNetwork::Udp => Self::Udp,
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorChoices {
    pub tcp: Option<SelectorMember>,
    pub udp: Option<SelectorMember>,
    pub revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SelectorError {
    #[error("group not found")]
    GroupNotFound,
    #[error("group is not a selector")]
    NotSelector,
    #[error("group is a selector")]
    IsSelector,
    #[error("choice is not a direct group member")]
    NotMember,
    #[error("selector revision exhausted")]
    RevisionExhausted,
}

#[derive(Default, Clone)]
pub(super) struct SelectorState {
    pub(super) choices: HashMap<String, [Option<SelectorMember>; 2]>,
    /// Runtime pins on automatic groups; never persisted or migrated, so the
    /// next configuration activation drops them.
    pub(super) overrides: HashMap<String, [Option<SelectorMember>; 2]>,
    pub(super) revision: u64,
}

/// Invoked for each network whose explicit runtime choice changed.
pub type PersistCallback = Arc<dyn Fn(&str, SelectionNetwork, &SelectorMember) + Send + Sync>;

/// Callback invoked after an effective Selector choice write. The callback
/// is deliberately argument-free: the warm coordinator re-reads the whole
/// deduplicated selector set, which handles shared and nested selections.
pub type SelectorChangeCallback = Arc<dyn Fn() + Send + Sync>;

/// Invoked for the changed network of a group opting into interruption.
pub type InterruptCallback = Arc<dyn Fn(&str, SelectionNetwork) + Send + Sync>;

/// Committed selection and callbacks deferred until the caller drops its guards.
#[must_use = "run callbacks after releasing the publication guards"]
pub struct SelectorUpdate {
    pub revision: u64,
    pub changed_networks: Vec<SelectionNetwork>,
    persisted_networks: [bool; 2],
    group: String,
    member: Option<SelectorMember>,
    persist: Option<PersistCallback>,
    changed: Option<SelectorChangeCallback>,
    interrupt: Option<InterruptCallback>,
}

impl SelectorUpdate {
    /// The control owner already captured the exact pre-transition close set.
    pub fn run_callbacks_without_interrupt(mut self) {
        self.interrupt = None;
        self.run_callbacks();
    }

    pub fn run_callbacks(self) {
        for (network, stored) in [SelectionNetwork::Tcp, SelectionNetwork::Udp]
            .into_iter()
            .zip(self.persisted_networks)
        {
            if stored
                && let Some(callback) = &self.persist
                && let Some(member) = &self.member
            {
                callback(&self.group, network, member);
            }
        }
        if !self.changed_networks.is_empty()
            && let Some(callback) = self.changed
        {
            callback();
        }
        for network in self.changed_networks {
            if let Some(callback) = &self.interrupt {
                callback(&self.group, network);
            }
        }
    }
}

impl GroupManager {
    /// Name-based callers retain first-declared-member tie breaking.
    pub fn set_selector_choice(
        &self,
        group_name: &str,
        member_name: &str,
        networks: SelectorNetworks,
    ) -> Result<u64, SelectorError> {
        let member = self.selector_member_by_name(group_name, member_name)?;
        let update = self.publish_selector_choice(group_name, &member, networks)?;
        let revision = update.revision;
        update.run_callbacks();
        Ok(revision)
    }

    pub fn selector_member_by_name(
        &self,
        group_name: &str,
        member_name: &str,
    ) -> Result<SelectorMember, SelectorError> {
        let group = self.selector_group(group_name)?;
        self.members(group)
            .find(|member| member.tag() == member_name)
            .map(GroupMember::identity)
            .ok_or(SelectorError::NotMember)
    }

    pub(super) fn selector_group(&self, group_name: &str) -> Result<&Group, SelectorError> {
        let group = self
            .groups
            .get(group_name)
            .ok_or(SelectorError::GroupNotFound)?;
        if group.policy != GroupPolicy::Selector {
            return Err(SelectorError::NotSelector);
        }
        Ok(group)
    }

    /// Validate once and publish both networks atomically. Control-plane callers
    /// serialize this with manager replacement, then run effects outside guards.
    pub fn publish_selector_choice(
        &self,
        group_name: &str,
        member: &SelectorMember,
        networks: SelectorNetworks,
    ) -> Result<SelectorUpdate, SelectorError> {
        let group = self.selector_group(group_name)?;
        let selected = self
            .member_by_identity(group, member)
            .ok_or(SelectorError::NotMember)?;
        let mut state = self.selector_choice.write();
        let changed_networks: Vec<_> = [SelectionNetwork::Tcp, SelectionNetwork::Udp]
            .into_iter()
            .filter(|network| networks.contains(*network))
            .filter(|network| {
                self.selector_member_in(group, *network, &state)
                    .is_none_or(|current| !Self::same_member(current, selected))
            })
            .collect();
        let persisted_networks = [SelectionNetwork::Tcp, SelectionNetwork::Udp].map(|network| {
            networks.contains(network)
                && state
                    .choices
                    .get(group_name)
                    .and_then(|choices| choices[network.slot()].as_ref())
                    != Some(member)
        });
        if persisted_networks.into_iter().any(|stored| stored) {
            let revision = state
                .revision
                .checked_add(1)
                .ok_or(SelectorError::RevisionExhausted)?;
            let choices = state.choices.entry(group_name.to_owned()).or_default();
            for network in [SelectionNetwork::Tcp, SelectionNetwork::Udp] {
                if persisted_networks[network.slot()] {
                    choices[network.slot()] = Some(member.clone());
                }
            }
            state.revision = revision;
        }
        let revision = state.revision;
        drop(state);
        Ok(SelectorUpdate {
            revision,
            changed_networks,
            persisted_networks,
            group: group_name.to_owned(),
            member: Some(member.clone()),
            persist: self.persist_callback.read().clone(),
            changed: self.selector_change_callback.read().clone(),
            interrupt: group
                .interrupt_connections
                .then(|| self.interrupt_callback.read().clone())
                .flatten(),
        })
    }

    /// Pin a member of an automatic group, which then behaves like a Selector
    /// choice until cleared or until the next configuration activation.
    pub fn publish_override(
        &self,
        group_name: &str,
        member: &SelectorMember,
        networks: SelectorNetworks,
    ) -> Result<SelectorUpdate, SelectorError> {
        let group = self.automatic_group(group_name)?;
        self.member_by_identity(group, member)
            .ok_or(SelectorError::NotMember)?;
        self.publish_override_change(group, Some(member), networks)
    }

    /// Return the requested networks of an automatic group to its policy.
    pub fn clear_override(
        &self,
        group_name: &str,
        networks: SelectorNetworks,
    ) -> Result<SelectorUpdate, SelectorError> {
        let group = self.automatic_group(group_name)?;
        self.publish_override_change(group, None, networks)
    }

    pub fn has_override(&self, group_name: &str, network: SelectionNetwork) -> bool {
        self.selector_choice
            .read()
            .overrides
            .get(group_name)
            .is_some_and(|pins| pins[network.slot()].is_some())
    }

    fn automatic_group(&self, group_name: &str) -> Result<&Group, SelectorError> {
        let group = self
            .groups
            .get(group_name)
            .ok_or(SelectorError::GroupNotFound)?;
        if group.policy == GroupPolicy::Selector {
            return Err(SelectorError::IsSelector);
        }
        Ok(group)
    }

    fn publish_override_change(
        &self,
        group: &Group,
        member: Option<&SelectorMember>,
        networks: SelectorNetworks,
    ) -> Result<SelectorUpdate, SelectorError> {
        let mut state = self.selector_choice.write();
        let pins = state
            .overrides
            .get(&group.name)
            .cloned()
            .unwrap_or_default();
        let changed_networks: Vec<_> = [SelectionNetwork::Tcp, SelectionNetwork::Udp]
            .into_iter()
            .filter(|network| {
                networks.contains(*network) && pins[network.slot()].as_ref() != member
            })
            .collect();
        if !changed_networks.is_empty() {
            let revision = state
                .revision
                .checked_add(1)
                .ok_or(SelectorError::RevisionExhausted)?;
            let mut pins = pins;
            for network in &changed_networks {
                pins[network.slot()] = member.cloned();
            }
            if pins.iter().any(Option::is_some) {
                state.overrides.insert(group.name.clone(), pins);
            } else {
                state.overrides.remove(&group.name);
            }
            state.revision = revision;
        }
        let revision = state.revision;
        drop(state);
        Ok(SelectorUpdate {
            revision,
            changed_networks,
            persisted_networks: [false; 2],
            group: group.name.clone(),
            member: member.cloned(),
            persist: None,
            changed: self.selector_change_callback.read().clone(),
            interrupt: group
                .interrupt_connections
                .then(|| self.interrupt_callback.read().clone())
                .flatten(),
        })
    }

    #[cfg(test)]
    /// Both effective identities and their revision from one publication read.
    pub fn selector_choices(&self, group_name: &str) -> Option<SelectorChoices> {
        let group = self.selector_group(group_name).ok()?;
        let state = self.selector_choice.read();
        Some(SelectorChoices {
            tcp: self
                .selector_member_in(group, SelectionNetwork::Tcp, &state)
                .map(GroupMember::identity),
            udp: self
                .selector_member_in(group, SelectionNetwork::Udp, &state)
                .map(GroupMember::identity),
            revision: state.revision,
        })
    }

    #[cfg(test)]
    pub fn selector_member_choice(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<SelectorMember> {
        self.selector_member(self.groups.get(group_name)?, network)
            .map(GroupMember::identity)
    }

    /// Explicit runtime choice, or an automatic group's pin, projected to its
    /// display tag for legacy readers.
    pub fn get_selector_choice(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<String> {
        let group = self.groups.get(group_name)?;
        let state = self.selector_choice.read();
        let choices = if group.policy == GroupPolicy::Selector {
            &state.choices
        } else {
            &state.overrides
        };
        let member = choices.get(group_name)?[network.slot()].as_ref()?;
        self.member_by_identity(group, member)
            .map(|member| member.tag().to_owned())
    }

    /// Install the callback for each changed (group, network, member).
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

    /// Wake URLTest health checks when a group serves traffic.
    pub(super) fn mark_used(&self, group_name: &str) {
        if let Some(alive) = &self.alive_set {
            alive.mark_group_active(group_name);
        }
    }

    /// Fire the interrupt callback when the group opted into connection
    /// interruption on selection changes (`interrupt_connections`).
    pub(super) fn maybe_interrupt(&self, group_name: &str, network: SelectionNetwork) {
        let interrupt = self
            .groups
            .get(group_name)
            .map(|g| g.interrupt_connections)
            .unwrap_or(false);
        if !interrupt {
            return;
        }
        let callback = self.interrupt_callback.read().clone();
        if let Some(callback) = callback {
            callback(group_name, network);
        }
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
            .map(|entry| entry.tag != candidate.tag())
            .unwrap_or(false);
        selections.set(
            network,
            UrlTestEntry {
                tag: candidate.tag().to_string(),
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
            .map(|old| old != candidate.tag())
            .unwrap_or(false);
        *pin = Some(candidate.tag().to_owned());
        changed
    }
}
