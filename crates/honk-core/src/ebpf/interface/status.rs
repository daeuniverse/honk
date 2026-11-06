//! Per-entry binding state, degradation priority and log episodes.

use std::collections::HashMap;
use std::num::NonZeroU32;

use tracing::{debug, error, info, warn};

use super::{Binding, Direction, InterfacePlan, UnboundReason};
use crate::degradations::{Component, Degradations, Issue};

type Key = (NonZeroU32, Direction);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EntryState {
    Bound,
    /// Absent, or `auto` without a default route: appears later on its own.
    Pending,
    /// Refused (type, vrf root, honk's own link): fixed by changing the configuration.
    Unsupported,
    /// TCX create/update/verification failed; retried.
    AttachFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The configured entry as written.
    pub name: String,
    pub state: EntryState,
    pub detail: String,
}

/// A binding that failed to bind or to verify, kept as text so a pass that does
/// not re-verify can carry it forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BindFailure {
    pub key: Key,
    pub program: &'static str,
    pub interface: String,
    pub message: String,
}

impl BindFailure {
    pub(crate) fn new(binding: &Binding, error: &anyhow::Error) -> Self {
        Self {
            key: binding.key(),
            program: binding.program.name(),
            interface: binding.interface.clone(),
            message: format!("{error:#}"),
        }
    }
}

/// State of every configured entry after a pass. `owned` is what the owner
/// holds once the pass committed; `failures` what could not be bound or verified.
pub(crate) fn entry_states(
    plan: &InterfacePlan,
    owned: &[Key],
    failures: &[BindFailure],
) -> Vec<Entry> {
    let mut entries: Vec<Entry> = plan
        .unbound
        .iter()
        .map(|(name, reason)| {
            let (state, detail) = match reason {
                UnboundReason::Absent => (EntryState::Pending, "no such interface".to_string()),
                UnboundReason::AutoUnresolved => (
                    EntryState::Pending,
                    "auto: no IPv4 default route yet".to_string(),
                ),
                UnboundReason::Refused(refused) => (EntryState::Unsupported, refused.to_string()),
            };
            Entry {
                name: name.clone(),
                state,
                detail,
            }
        })
        .collect();
    for (name, derived) in &plan.bound {
        let failure = failures.iter().find(|f| derived.contains(&f.key.0));
        let missing = plan
            .bindings
            .iter()
            .find(|b| derived.contains(&b.ifindex) && !owned.contains(&b.key()));
        let (state, detail) = match (failure, missing) {
            (Some(f), _) => (
                EntryState::AttachFailed,
                format!("{} on {}: {}", f.program, f.interface, f.message),
            ),
            (None, Some(b)) => (
                EntryState::Pending,
                format!("{} on {} is not bound yet", b.program.name(), b.interface),
            ),
            (None, None) => (EntryState::Bound, String::new()),
        };
        entries.push(Entry {
            name: name.clone(),
            state,
            detail,
        });
    }
    entries
}

/// The `interface_binding` reason: `attach_failed` > `unsupported_type` >
/// `pending`; `None` when every configured entry is bound.
pub(crate) fn degradation_reason(entries: &[Entry]) -> Option<EntryState> {
    entries
        .iter()
        .map(|entry| entry.state)
        .filter(|state| *state != EntryState::Bound)
        .max()
}

fn interface_issue(state: EntryState) -> Option<Issue> {
    let reason = match state {
        EntryState::Bound => return None,
        EntryState::Pending => "pending",
        EntryState::Unsupported => "unsupported_type",
        EntryState::AttachFailed => "attach_failed",
    };
    Some(Issue {
        code: "interface_binding_incomplete",
        message: "A configured network interface is not fully bound; traffic interception may be incomplete.",
        reason,
    })
}

pub(crate) fn publish(degradations: &Degradations, state: Option<EntryState>) {
    match state.and_then(interface_issue) {
        Some(issue) => degradations.set(Component::InterfaceBinding, issue),
        None => degradations.clear(Component::InterfaceBinding),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transition {
    /// A new unbound condition for the entry: WARN (ERROR when unsupported).
    Begins,
    /// A bound or partly bound entry disappeared: INFO.
    Lost,
    /// The condition goes on: DEBUG.
    Continues,
    /// Bound after an unbound episode, or first seen bound: INFO.
    Bound,
}

/// One log episode per configured entry, bounded by the configured list.
#[derive(Debug, Default)]
pub(crate) struct Episodes {
    last: HashMap<String, EntryState>,
}

impl Episodes {
    /// Transitions for this pass, in `entries` order; quiet entries are omitted.
    pub(crate) fn observe(&mut self, entries: &[Entry]) -> Vec<(usize, Transition)> {
        let mut transitions = Vec::new();
        for (at, entry) in entries.iter().enumerate() {
            let previous = self.last.insert(entry.name.clone(), entry.state);
            let transition = match (previous, entry.state) {
                (Some(EntryState::Bound), EntryState::Bound) => None,
                (_, EntryState::Bound) => Some(Transition::Bound),
                (Some(before), now) if before == now => Some(Transition::Continues),
                (Some(EntryState::Bound | EntryState::AttachFailed), EntryState::Pending) => {
                    Some(Transition::Lost)
                }
                _ => Some(Transition::Begins),
            };
            transitions.extend(transition.map(|transition| (at, transition)));
        }
        self.last
            .retain(|name, _| entries.iter().any(|entry| &entry.name == name));
        transitions
    }
}

pub(crate) fn log_entry(entry: &Entry, transition: Transition) {
    let (name, detail) = (&entry.name, &entry.detail);
    match (transition, entry.state) {
        (Transition::Bound, _) => info!(interface = %name, "configured interface is bound"),
        (Transition::Lost, _) => {
            info!(interface = %name, "configured interface is no longer bound: {detail}")
        }
        (Transition::Begins, EntryState::Unsupported) => {
            error!(interface = %name, "configured interface is not supported: {detail}")
        }
        (Transition::Begins, EntryState::AttachFailed) => {
            warn!(interface = %name, "configured interface attach failed; retrying: {detail}")
        }
        (Transition::Begins, _) => {
            warn!(interface = %name, "configured interface is not bound yet: {detail}")
        }
        (Transition::Continues, _) => {
            debug!(interface = %name, state = ?entry.state, "configured interface still not bound: {detail}")
        }
    }
}

/// The blocking stage of a reconcile that failed as a whole, which leaves the
/// existing bindings (and the degradation) as they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconcileStep {
    Topology,
    Snapshot,
    Join,
}

impl ReconcileStep {
    pub(crate) fn what(self) -> &'static str {
        match self {
            Self::Topology => "read the network topology",
            Self::Snapshot => "snapshot interface bindings",
            Self::Join => "run the interface reconcile task",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepTransition {
    Begins,
    Continues,
}

/// WARN once per failing step, DEBUG while it persists, INFO on recovery.
#[derive(Debug, Default)]
pub(crate) struct StepEpisode {
    step: Option<ReconcileStep>,
}

impl StepEpisode {
    pub(crate) fn failed(&mut self, step: ReconcileStep) -> StepTransition {
        if self.step.replace(step) == Some(step) {
            StepTransition::Continues
        } else {
            StepTransition::Begins
        }
    }

    pub(crate) fn recovered(&mut self) -> Option<ReconcileStep> {
        self.step.take()
    }
}

#[cfg(test)]
mod tests;
