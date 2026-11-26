//! Flow evidence one UDP endpoint reports, and the terminal outcome it shares
//! with its initializer.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use honk_netstack::MemoryReservation;
use honk_outbound::runtime::flow_observation::FlowObserver;
use parking_lot::Mutex;

use super::{UdpEndpointPool, UdpTerminal};
use crate::control::task_registry::capacity_error;
use crate::observe::flows::FlowGuard;

pub(in crate::control) struct NativeUdpTerminal {
    flow: Arc<FlowGuard>,
    state: Mutex<NativeUdpState>,
}

struct NativeUdpState {
    outcome: Option<UdpTerminal>,
    cleaned: Option<bool>,
    initializer_done: bool,
}

/// The terminal outcome an endpoint shares with its initializer.
pub(in crate::control) type SharedTerminal = Arc<NativeUdpTerminal>;

pub(super) struct InitializerTerminalSlot(OnceLock<SharedTerminal>);

impl InitializerTerminalSlot {
    pub(super) fn new() -> Self {
        Self(OnceLock::new())
    }

    pub(super) fn get(&self) -> Option<&SharedTerminal> {
        self.0.get()
    }

    pub(super) fn get_if(&self, condition: impl FnOnce() -> bool) -> Option<&SharedTerminal> {
        if condition() { self.get() } else { None }
    }

    pub(super) fn get_or_init(&self, flow: &Arc<FlowGuard>) -> SharedTerminal {
        Arc::clone(
            self.0
                .get_or_init(|| NativeUdpTerminal::new(Arc::clone(flow), false)),
        )
    }
}

#[derive(Default)]
pub(super) struct TerminalSlot(Option<SharedTerminal>);

impl TerminalSlot {
    pub(super) fn new(terminal: Option<SharedTerminal>) -> Self {
        Self(terminal)
    }

    pub(super) fn get(&self) -> Option<&SharedTerminal> {
        self.0.as_ref()
    }
}

const _: () = assert!(size_of::<TerminalSlot>() == size_of::<usize>());

pub(in crate::control) struct NativeInitializerGuard {
    terminal: SharedTerminal,
    completed: bool,
}

impl NativeInitializerGuard {
    pub(in crate::control) fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for NativeInitializerGuard {
    fn drop(&mut self) {
        let mut state = self.terminal.state.lock();
        if !self.completed {
            state
                .outcome
                .get_or_insert(UdpTerminal::InitializerCancelled);
        }
        state.initializer_done = true;
        self.terminal.publish(&state);
    }
}

impl NativeUdpTerminal {
    fn new(flow: Arc<FlowGuard>, initializer_done: bool) -> SharedTerminal {
        Arc::new(Self {
            flow,
            state: Mutex::new(NativeUdpState {
                outcome: None,
                cleaned: None,
                initializer_done,
            }),
        })
    }

    pub(in crate::control) fn initializer(self: &Arc<Self>) -> NativeInitializerGuard {
        self.state.lock().initializer_done = false;
        NativeInitializerGuard {
            terminal: Arc::clone(self),
            completed: false,
        }
    }

    pub(super) fn packet_drop(&self, reason: &'static str) {
        self.flow.datapath(
            crate::observe::vocab::Plane::Userspace,
            "drop",
            reason,
            None,
        );
    }

    /// The first outcome wins, except that a cleanup failure overrides any
    /// earlier one: a flow whose teardown failed did not end cleanly.
    pub(in crate::control) fn outcome(&self, outcome: UdpTerminal) {
        let mut terminal = self.state.lock();
        if terminal.outcome.is_none() || outcome == UdpTerminal::CleanupFailed {
            terminal.outcome = Some(outcome);
        }
        self.publish(&terminal);
    }

    pub(super) fn cleaned(&self, success: bool) {
        let mut terminal = self.state.lock();
        terminal.cleaned = Some(terminal.cleaned.unwrap_or(true) && success);
        self.publish(&terminal);
    }

    fn publish(&self, terminal: &NativeUdpState) {
        if !terminal.initializer_done {
            return;
        }
        let outcome = match (terminal.outcome, terminal.cleaned) {
            (_, Some(false)) => UdpTerminal::CleanupFailed,
            (Some(outcome), Some(true)) => outcome,
            _ => return,
        };
        let (state, reason) = outcome.outcome();
        self.flow.finish(state, reason);
    }
}

#[derive(Default)]
pub(in crate::control) struct EndpointObservation {
    inner: Option<Box<ActiveEndpointObservation>>,
}

const _: () = assert!(size_of::<EndpointObservation>() == size_of::<usize>());

#[derive(Default)]
struct ActiveEndpointObservation {
    flow: Option<Arc<FlowGuard>>,
    pool: Weak<UdpEndpointPool>,
    observer: Option<FlowObserver>,
    terminal: TerminalSlot,
    received_reply: AtomicBool,
    memory: Option<MemoryReservation>,
}

pub(super) const ACTIVE_OBSERVATION_BYTES: usize = size_of::<ActiveEndpointObservation>();

impl Drop for EndpointObservation {
    fn drop(&mut self) {
        if let Some(mut active) = self.inner.take() {
            let memory = active.memory.take();
            drop(active);
            drop(memory);
        }
    }
}

impl EndpointObservation {
    pub(in crate::control) fn reserve(pool: &UdpEndpointPool, active: bool) -> io::Result<Self> {
        let mut observation = Self::default();
        if active {
            observation.activate(pool)?;
        }
        Ok(observation)
    }

    fn activate(&mut self, pool: &UdpEndpointPool) -> io::Result<&mut ActiveEndpointObservation> {
        if self.inner.is_none() {
            let memory = match &pool.memory_budget {
                Some(budget) => Some(
                    budget
                        .reserve(ACTIVE_OBSERVATION_BYTES)
                        .ok_or_else(capacity_error)?,
                ),
                None => None,
            };
            self.inner = Some(Box::new(ActiveEndpointObservation {
                memory,
                ..ActiveEndpointObservation::default()
            }));
        }
        Ok(self
            .inner
            .as_deref_mut()
            .expect("active endpoint observation"))
    }

    pub(in crate::control) fn set_flow(
        &mut self,
        flow: Option<Arc<FlowGuard>>,
        pool: &Arc<UdpEndpointPool>,
        terminal: Option<SharedTerminal>,
    ) -> io::Result<()> {
        if self.inner.is_none() && flow.is_none() && terminal.is_none() {
            return Ok(());
        }
        let active = self.activate(pool)?;
        active.terminal = TerminalSlot::new(
            terminal.or_else(|| flow.clone().map(|flow| NativeUdpTerminal::new(flow, true))),
        );
        active.flow = flow;
        active.pool = Arc::downgrade(pool);
        Ok(())
    }

    pub(in crate::control) fn set_observer(
        &mut self,
        observer: Option<FlowObserver>,
        pool: &UdpEndpointPool,
    ) -> io::Result<()> {
        if self.inner.is_some() || observer.is_some() {
            self.activate(pool)?.observer = observer;
        }
        Ok(())
    }

    pub(in crate::control) fn flow(&self) -> Option<&Arc<FlowGuard>> {
        self.inner.as_deref()?.flow.as_ref()
    }

    pub(super) fn observer(&self) -> Option<&FlowObserver> {
        self.inner.as_deref()?.observer.as_ref()
    }

    pub(super) fn terminal(&self) -> Option<&SharedTerminal> {
        self.inner.as_deref()?.terminal.get()
    }

    pub(super) fn received_reply(&self) -> bool {
        self.inner
            .as_deref()
            .is_some_and(|active| active.received_reply.load(Ordering::Relaxed))
    }

    pub(super) fn dropped(&self, reason: &'static str, error: Option<&'static str>) {
        if let Some(flow) = self.flow() {
            flow.datapath(
                crate::observe::vocab::Plane::Userspace,
                "drop",
                reason,
                error,
            );
        }
    }

    pub(super) fn reply_received(&self) {
        if let Some(active) = self.inner.as_deref()
            && let Some(flow) = &active.flow
        {
            active.received_reply.store(true, Ordering::Relaxed);
            if flow.first_reply() {
                flow.transition(
                    crate::observe::vocab::ConnectionState::Active,
                    "reply_received",
                    crate::observe::vocab::ConnectionMilestone::FirstReply,
                    Some(true),
                );
            }
        }
    }

    pub(super) fn finish(&self, outcome: UdpTerminal) {
        if let Some(active) = self.inner.as_deref()
            && let Some(terminal) = active.terminal.get()
        {
            let shutdown = active
                .pool
                .upgrade()
                .is_some_and(|pool| pool.terminal.load(Ordering::Acquire));
            if shutdown {
                terminal.outcome(UdpTerminal::Shutdown);
            } else {
                terminal.outcome(outcome);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::udp_endpoint::SystemUdpReplySocketFactory;
    use honk_netstack::MemoryBudget;

    #[test]
    fn empty_native_udp_observation_setters_do_not_allocate() {
        const CHILD: &str = "HONK_UDP_OBSERVATION_ALLOCATION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "control::udp_endpoint::observation::tests::empty_native_udp_observation_setters_do_not_allocate",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .expect("isolated endpoint allocation test");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("1 passed"),
                "{stdout}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let budget = MemoryBudget::new(4 << 20);
        let pool = Arc::new(
            UdpEndpointPool::with_packet_reply_factory(
                1,
                Arc::new(SystemUdpReplySocketFactory),
                Arc::clone(&budget),
            )
            .unwrap(),
        );
        let hold = budget.reserve(budget.limit() - budget.used()).unwrap();
        let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
        let mut native = EndpointObservation::reserve(&pool, false).unwrap();
        native.set_flow(None, &pool, None).unwrap();
        native.set_observer(None, &pool).unwrap();
        assert_eq!(region.change().allocations, 0);
        assert!(native.inner.is_none());
        assert_eq!(budget.used(), budget.limit());
        drop(hold);
        drop(pool);
        assert_eq!(budget.used(), 0);
    }
}
