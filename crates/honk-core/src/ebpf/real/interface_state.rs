//! Reconcile bookkeeping and device sysctls shared by startup and the watcher.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use tracing::{debug, info, warn};

use crate::degradations::Degradations;
use crate::ebpf::interface::status::{
    BindFailure, Episodes, ReconcileStep, StepEpisode, StepTransition, degradation_reason,
    entry_states, log_entry, publish,
};
use crate::ebpf::interface::{Direction, InterfacePlan, Topology};

type Key = (NonZeroU32, Direction);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SysctlKey {
    AcceptRa,
    RpFilter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SysctlWrite {
    pub key: SysctlKey,
    pub ifindex: NonZeroU32,
    pub name: String,
    /// The second, final write of this ifindex; its failure only logs at DEBUG.
    pub reassert: bool,
}

/// A late device's own udev `systemd-sysctl` run lands after our first write
/// (~20 ms on Arch) and puts back the distribution default.
const SYSCTL_REASSERT_AFTER: std::time::Duration = std::time::Duration::from_secs(1);

/// Devices written, by ifindex: once on sight and once more after udev has
/// run, then never again, so an operator's later setting is left alone and a
/// host without IPv6 does not spawn `sysctl -w` every pass. A failed write
/// counts. A recreated device (new ifindex) starts over.
#[derive(Debug, Default)]
pub(crate) struct SysctlTracker {
    /// `Some(first write)` until the second write; `None` once settled.
    attempted: HashMap<(SysctlKey, NonZeroU32), Option<tokio::time::Instant>>,
}

impl SysctlTracker {
    /// The writes owed now: `accept_ra=2` for every WAN-role root and
    /// `rp_filter=0` for the first existing, bindable resolved LAN name.
    pub(crate) fn claim(
        &mut self,
        plan: &InterfacePlan,
        topology: &Topology,
        now: tokio::time::Instant,
    ) -> Vec<SysctlWrite> {
        let present: HashSet<NonZeroU32> = topology.links.iter().map(|l| l.ifindex).collect();
        self.attempted
            .retain(|(_, ifindex), _| present.contains(ifindex));
        let lan = plan
            .lan
            .iter()
            .filter(|name| {
                plan.bound.iter().any(|(entry, _)| {
                    entry == *name
                        || (honk_config::config::is_auto_interface(entry)
                            && topology.default_route.as_ref() == Some(*name))
                })
            })
            .find_map(|name| topology.links.iter().find(|link| &link.name == name))
            .map(|link| (link.ifindex, link.name.clone()));
        for ((key, ifindex), first) in &mut self.attempted {
            let targeted = match key {
                SysctlKey::AcceptRa => plan.wan_roots.iter().any(|(root, _)| root == ifindex),
                SysctlKey::RpFilter => lan.as_ref().is_some_and(|(lan, _)| lan == ifindex),
            };
            if !targeted {
                *first = None;
            }
        }
        let targets = plan
            .wan_roots
            .iter()
            .map(|(ifindex, name)| (SysctlKey::AcceptRa, *ifindex, name.clone()))
            .chain(lan.map(|(ifindex, name)| (SysctlKey::RpFilter, ifindex, name)));
        let mut owed = Vec::new();
        for (key, ifindex, name) in targets {
            let reassert = match self.attempted.get(&(key, ifindex)) {
                None => false,
                Some(Some(first)) if now >= *first + SYSCTL_REASSERT_AFTER => true,
                Some(_) => continue,
            };
            self.attempted
                .insert((key, ifindex), (!reassert).then_some(now));
            owed.push(SysctlWrite {
                key,
                ifindex,
                name,
                reassert,
            });
        }
        owed
    }

    /// When the next second write is due, if any.
    pub(crate) fn due(&self) -> Option<tokio::time::Instant> {
        self.attempted
            .values()
            .flatten()
            .min()
            .map(|first| *first + SYSCTL_REASSERT_AFTER)
    }
}

/// Run the writes; a failed first write is one WARN per ifindex, a failed
/// second write is DEBUG (the first already reported it).
pub(crate) fn perform(
    writes: &[SysctlWrite],
    write: &(dyn Fn(&SysctlWrite) -> anyhow::Result<()> + Send + Sync),
) {
    for owed in writes {
        if let Err(error) = write(owed) {
            if owed.reassert {
                debug!(interface = %owed.name, "failed to set {:?} again: {error:#}", owed.key);
            } else {
                warn!(interface = %owed.name, "failed to set {:?}: {error:#}", owed.key);
            }
        }
    }
}

/// The production writer.
pub(crate) fn write_sysctl(owed: &SysctlWrite) -> anyhow::Result<()> {
    match owed.key {
        SysctlKey::AcceptRa => crate::sysctl::enable_wan_accept_ra(&owed.name),
        SysctlKey::RpFilter => crate::sysctl::disable_rp_filter(&owed.name),
    }
}

/// Everything startup and the watcher share about the configured interfaces.
#[derive(Debug, Default)]
pub(crate) struct InterfaceState {
    episodes: Episodes,
    steps: StepEpisode,
    sysctl: SysctlTracker,
    /// Held bindings whose verification failed until a verifying pass or replacement.
    pub(super) unproven: Vec<BindFailure>,
    pub(super) last_verify: Option<tokio::time::Instant>,
}

impl InterfaceState {
    pub(crate) fn claim_sysctls(
        &mut self,
        plan: &InterfacePlan,
        topology: &Topology,
        now: tokio::time::Instant,
    ) -> Vec<SysctlWrite> {
        self.sysctl.claim(plan, topology, now)
    }

    pub(crate) fn sysctl_due(&self) -> Option<tokio::time::Instant> {
        self.sysctl.due()
    }

    /// After a pass: log each entry's transition and publish the aggregate.
    pub(crate) fn settle(
        &mut self,
        plan: &InterfacePlan,
        owned: &[Key],
        failures: &[BindFailure],
        degradations: &Degradations,
    ) {
        let entries = entry_states(plan, owned, failures);
        for (at, transition) in self.episodes.observe(&entries) {
            log_entry(&entries[at], transition);
        }
        publish(degradations, degradation_reason(&entries));
    }

    /// A stage of the reconcile failed: bindings and degradation stay as they were.
    pub(crate) fn step_failed(&mut self, step: ReconcileStep, error: &anyhow::Error) {
        match self.steps.failed(step) {
            StepTransition::Begins => {
                warn!("failed to {}: {error:#}; retrying", step.what())
            }
            StepTransition::Continues => {
                debug!("still failing to {}: {error:#}", step.what())
            }
        }
    }

    /// A whole pass ran without a failed stage.
    pub(crate) fn step_recovered(&mut self) {
        if let Some(step) = self.steps.recovered() {
            info!(
                "interface reconcile recovered: able to {} again",
                step.what()
            );
        }
    }
}
#[cfg(test)]
mod tests;
