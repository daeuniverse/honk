//! Features running reduced after a failure honk recovered from.
//!
//! Each warn-and-continue site owns one fixed component: it sets the entry
//! when the feature degrades and clears it once the full feature is in effect
//! again. The native API reports the entries on `GET /runtime`.

use std::time::SystemTime;

use parking_lot::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Component {
    Persistence,
    StateCache,
    #[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
    IfaceWatch,
    PnameRouting,
    #[cfg_attr(
        not(all(feature = "native-api", feature = "ebpf", target_os = "linux")),
        allow(dead_code)
    )]
    UdpTrace,
    QuicProbe,
}

impl Component {
    const COUNT: usize = 6;

    #[cfg_attr(not(feature = "native-api"), allow(dead_code))]
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::Persistence => "persistence",
            Self::StateCache => "state_cache",
            Self::IfaceWatch => "iface_watch",
            Self::PnameRouting => "pname_routing",
            Self::UdpTrace => "udp_trace",
            Self::QuicProbe => "quic_probe",
        }
    }
}

/// What is reduced. The message never carries operator-supplied names or
/// values; `reason` is a stable code for the cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Issue {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) reason: &'static str,
}

#[cfg_attr(not(feature = "native-api"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Degradation {
    pub(crate) component: Component,
    pub(crate) issue: Issue,
    /// A stable code for the check that failed, when `reason` names a class.
    pub(crate) rule: Option<&'static str>,
    pub(crate) since: SystemTime,
}

type Notify = Box<dyn Fn() + Send + Sync>;

/// One entry per component, so the list is bounded by `Component::COUNT`.
#[derive(Default)]
pub(crate) struct Degradations {
    entries: Mutex<[Option<Degradation>; Component::COUNT]>,
    notify: Mutex<Option<Notify>>,
}

impl Degradations {
    /// Records `issue`; a component that is already degraded keeps its `since`.
    pub(crate) fn set(&self, component: Component, issue: Issue) {
        self.set_with_rule(component, issue, None);
    }

    /// `set` with the failed check, reported beside `reason`.
    pub(crate) fn set_with_rule(
        &self,
        component: Component,
        issue: Issue,
        rule: Option<&'static str>,
    ) {
        let changed = {
            let mut entries = self.entries.lock();
            let slot = &mut entries[component as usize];
            match slot {
                Some(current) if (current.issue, current.rule) == (issue, rule) => false,
                Some(current) => {
                    (current.issue, current.rule) = (issue, rule);
                    true
                }
                None => {
                    *slot = Some(Degradation {
                        component,
                        issue,
                        rule,
                        since: SystemTime::now(),
                    });
                    true
                }
            }
        };
        if changed {
            self.changed();
        }
    }

    pub(crate) fn clear(&self, component: Component) {
        if self.entries.lock()[component as usize].take().is_some() {
            self.changed();
        }
    }

    #[cfg(test)]
    pub(crate) fn get(&self, component: Component) -> Option<Issue> {
        self.entries.lock()[component as usize]
            .as_ref()
            .map(|entry| entry.issue)
    }

    #[cfg_attr(not(feature = "native-api"), allow(dead_code))]
    pub(crate) fn snapshot(&self) -> Vec<Degradation> {
        self.entries.lock().iter().flatten().cloned().collect()
    }

    /// Runs `notify` after every change; it must not call back into the registry.
    #[cfg_attr(not(feature = "native-api"), allow(dead_code))]
    pub(crate) fn set_notify(&self, notify: Notify) {
        *self.notify.lock() = Some(notify);
    }

    fn changed(&self) {
        if let Some(notify) = self.notify.lock().as_ref() {
            notify();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const LOST: Issue = Issue {
        code: "test_lost",
        message: "Lost.",
        reason: "unavailable",
    };

    #[test]
    fn set_keeps_since_and_notifies_only_on_change() {
        let registry = Degradations::default();
        let notified = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&notified);
        registry.set_notify(Box::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        }));
        registry.set(Component::Persistence, LOST);
        let since = registry.snapshot()[0].since;
        registry.set(Component::Persistence, LOST);
        assert_eq!(notified.load(Ordering::Relaxed), 1);
        let changed = Issue {
            reason: "locked",
            ..LOST
        };
        registry.set(Component::Persistence, changed);
        assert_eq!(notified.load(Ordering::Relaxed), 2);
        let entry = &registry.snapshot()[0];
        assert_eq!((entry.issue, entry.since), (changed, since));
        registry.clear(Component::Persistence);
        registry.clear(Component::Persistence);
        assert_eq!(notified.load(Ordering::Relaxed), 3);
        assert!(registry.snapshot().is_empty());
    }
}
