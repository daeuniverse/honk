//! Flow evidence one UDP endpoint reports, and the terminal outcome it shares
//! with its initializer.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, Weak};
#[cfg(target_os = "linux")]
use std::time::{Instant, SystemTime};

#[cfg(target_os = "linux")]
use honk_netstack::MemoryBudget;
use honk_netstack::MemoryReservation;
use honk_outbound::runtime::flow_observation::FlowObserver;
use parking_lot::Mutex;
#[cfg(target_os = "linux")]
use tokio::sync::Notify;

use super::{UdpEndpointPool, UdpTerminal};
use crate::control::task_registry::capacity_error;
use crate::observe::flows::FlowGuard;

pub(in crate::control) struct NativeUdpTerminal {
    flow: Arc<FlowGuard>,
    state: Mutex<NativeUdpState>,
    #[cfg(target_os = "linux")]
    packet_drops: PacketDropSink,
}

struct NativeUdpState {
    outcome: Option<UdpTerminal>,
    cleaned: Option<bool>,
    initializer_done: bool,
}

#[cfg(target_os = "linux")]
const PACKET_DROP_CAPACITY: usize = 8;

#[cfg(target_os = "linux")]
struct PacketDrop {
    reason: &'static str,
    at: (Instant, SystemTime),
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct PacketDropBatch {
    entries: [Option<PacketDrop>; PACKET_DROP_CAPACITY],
    len: usize,
}

#[cfg(target_os = "linux")]
struct PacketDropBuffer {
    batch: Mutex<PacketDropBatch>,
    lost: AtomicBool,
    ready: Notify,
    _memory: MemoryReservation,
}

#[cfg(target_os = "linux")]
enum PacketDropSink {
    Inline,
    Deferred(Box<PacketDropBuffer>),
    Unfunded(AtomicBool),
}

#[cfg(target_os = "linux")]
impl PacketDropSink {
    fn new(budget: Option<&Arc<MemoryBudget>>) -> Self {
        let Some(budget) = budget else {
            return Self::Inline;
        };
        let Some(memory) = budget.reserve(size_of::<PacketDropBuffer>()) else {
            return Self::Unfunded(AtomicBool::new(false));
        };
        Self::Deferred(Box::new(PacketDropBuffer {
            batch: Mutex::default(),
            lost: AtomicBool::new(false),
            ready: Notify::new(),
            _memory: memory,
        }))
    }

    fn publish(&self, flow: &FlowGuard) {
        match self {
            Self::Inline => (),
            Self::Deferred(buffer) => buffer.publish(flow),
            Self::Unfunded(lost) => {
                if lost.swap(false, Ordering::AcqRel) {
                    flow.mark_overflow();
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl PacketDropBuffer {
    fn push(&self, reason: &'static str) {
        // The worker may hold UDP admission state. Recorder publication runs on Tokio.
        if let Some(mut batch) = self.batch.try_lock()
            && batch.len < PACKET_DROP_CAPACITY
        {
            let index = batch.len;
            batch.entries[index] = Some(PacketDrop {
                reason,
                at: (Instant::now(), SystemTime::now()),
            });
            batch.len += 1;
        } else {
            self.lost.store(true, Ordering::Release);
        }
        self.ready.notify_one();
    }

    fn publish(&self, flow: &FlowGuard) {
        let batch = std::mem::take(&mut *self.batch.lock());
        for dropped in batch.entries.into_iter().flatten() {
            flow.udp_queue_drop_at(dropped.reason, dropped.at);
        }
        if self.lost.swap(false, Ordering::AcqRel) {
            flow.mark_overflow();
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) async fn observe_packet_drops<T>(
    terminal: Option<&SharedTerminal>,
    mut operation: std::pin::Pin<&mut impl Future<Output = T>>,
) -> T {
    let Some(terminal) = terminal else {
        return operation.await;
    };
    let PacketDropSink::Deferred(drops) = &terminal.packet_drops else {
        return operation.await;
    };
    loop {
        tokio::select! {
            result = &mut operation => {
                drops.publish(&terminal.flow);
                return result;
            }
            () = drops.ready.notified() => drops.publish(&terminal.flow),
        }
    }
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

    pub(super) fn get_or_init(
        &self,
        flow: &Arc<FlowGuard>,
        #[cfg(target_os = "linux")] packet_budget: Option<&Arc<MemoryBudget>>,
    ) -> SharedTerminal {
        Arc::clone(self.0.get_or_init(|| {
            NativeUdpTerminal::new(
                Arc::clone(flow),
                false,
                #[cfg(target_os = "linux")]
                packet_budget,
            )
        }))
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
    fn new(
        flow: Arc<FlowGuard>,
        initializer_done: bool,
        #[cfg(target_os = "linux")] packet_budget: Option<&Arc<MemoryBudget>>,
    ) -> SharedTerminal {
        Arc::new(Self {
            flow,
            #[cfg(target_os = "linux")]
            packet_drops: PacketDropSink::new(packet_budget),
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
        #[cfg(target_os = "linux")]
        match &self.packet_drops {
            PacketDropSink::Inline => (),
            PacketDropSink::Deferred(drops) => return drops.push(reason),
            PacketDropSink::Unfunded(lost) => return lost.store(true, Ordering::Release),
        }
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
        #[cfg(target_os = "linux")]
        self.packet_drops.publish(&self.flow);
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
        active.terminal = TerminalSlot::new(terminal.or_else(|| {
            flow.clone().map(|flow| {
                NativeUdpTerminal::new(
                    flow,
                    true,
                    #[cfg(target_os = "linux")]
                    None,
                )
            })
        }));
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn physical_udp_drop_receipts_keep_origin_and_gap_through_retirement() {
        use crate::observe::vocab::Network;

        let native =
            crate::native_api::observation::NativeObservation::new(&honk_config::Config::default());
        let store = &native.core.flows;
        store.set_recording(true);
        let client = "192.0.2.11:50000".parse().unwrap();
        let destination = "198.51.100.20:443".parse().unwrap();
        let flow = Arc::new(store.begin(Network::Udp, client, destination).unwrap());
        let same_tuple = store.begin(Network::Udp, client, destination).unwrap();
        let budget = MemoryBudget::new(size_of::<PacketDropBuffer>());
        let terminal = NativeUdpTerminal::new(Arc::clone(&flow), true, Some(&budget));
        assert_eq!(budget.used(), budget.limit());

        for _ in 0..=PACKET_DROP_CAPACITY {
            terminal.packet_drop("queue_capacity");
        }
        let expected = {
            let PacketDropSink::Deferred(buffer) = &terminal.packet_drops else {
                panic!("funded receipt buffer");
            };
            let batch = buffer.batch.lock();
            crate::observe::timestamp(batch.entries[0].as_ref().unwrap().at.1)
        };
        assert!(
            store.test_detail(flow.id())["trace"]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .all(|step| step["stage"] != "datapath")
        );

        {
            let operation = std::pin::pin!(std::future::pending::<()>());
            let mut observer = std::pin::pin!(observe_packet_drops(Some(&terminal), operation));
            assert!(futures::poll!(observer.as_mut()).is_pending());
        }
        terminal.packet_drop("queue_closed");
        terminal.outcome(UdpTerminal::Shutdown);
        terminal.cleaned(true);

        let detail = store.test_detail(flow.id());
        let dropped = detail["trace"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|step| step["stage"] == "datapath")
            .collect::<Vec<_>>();
        assert_eq!(dropped.len(), PACKET_DROP_CAPACITY + 1);
        assert_eq!(dropped[0]["observed_at"], expected);
        assert_eq!(dropped[0]["data"]["reason"], "queue_capacity");
        assert_eq!(
            dropped[PACKET_DROP_CAPACITY]["data"]["reason"],
            "queue_closed"
        );
        assert!(
            detail["trace"]["missing"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("buffer_overflow"))
        );
        assert!(
            store.test_detail(same_tuple.id())["trace"]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .all(|step| step["stage"] != "datapath")
        );
        let unfunded = NativeUdpTerminal::new(Arc::new(same_tuple), true, Some(&budget));
        let PacketDropSink::Unfunded(lost) = &unfunded.packet_drops else {
            panic!("a second receipt buffer would exceed the shared budget");
        };
        unfunded.packet_drop("queue_capacity");
        assert!(lost.load(Ordering::Acquire));
        unfunded.outcome(UdpTerminal::Shutdown);
        unfunded.cleaned(true);
        assert!(!lost.load(Ordering::Acquire));

        let retained = Arc::clone(&terminal);
        drop(terminal);
        assert_eq!(budget.used(), budget.limit());
        drop(retained);
        assert_eq!(budget.used(), 0);
    }
}
