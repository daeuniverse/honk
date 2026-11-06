//! Rtnetlink watcher for configured interfaces and `auto` default routes.
//!
//! Link, address, route events and a slow ticker re-read the topology, plan
//! the TCX bindings once and reconcile them against the backend's single
//! owner (`bindings`). Every step that can wait on rtnl (link dump, TCX
//! create/update/query, closing a link FD, sysctl) runs on a blocking thread
//! with no backend lock held; the backend lock is taken only to snapshot
//! (read) and to commit (write). Without a usable event
//! subscription the same loop runs on the ticker alone.

use nix::errno::Errno;
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, socket,
};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::sync::{RwLock, mpsc, watch};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::interface_startup::InterfaceHandoff;
use super::interface_state::{self, InterfaceState, SysctlWrite};
use crate::ebpf::EbpfBackend;
use crate::ebpf::interface::status::{BindFailure, ReconcileStep};
use crate::ebpf::interface::{self, ApplyReport, BindingSnapshot, InterfacePlan, Topology};
use crate::netlink::{RTM_DELLINK, RTM_NEWLINK};

// A captive-portal login may add only a default route to an already-up link.
const RTMGRP_LINK_MASK: u32 = 1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;
const RTMGRP_NETWORK_MASK: u32 = RTMGRP_LINK_MASK
    | RTMGRP_IPV4_IFADDR
    | RTMGRP_IPV4_ROUTE
    | RTMGRP_IPV6_IFADDR
    | RTMGRP_IPV6_ROUTE;
// Events are a wakeup hint only — reconcile re-reads ground truth — but a
// dropped datagram would stall a pending interface forever, so a slow ticker
// backstops the subscription (and is the only trigger without one).
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

type ReadTopology = dyn Fn(bool) -> anyhow::Result<Topology> + Send + Sync;
type ApplyBindings =
    dyn Fn(BindingSnapshot, &InterfacePlan, &Topology, bool) -> ApplyReport + Send + Sync;
type WriteSysctl = dyn Fn(&SysctlWrite) -> anyhow::Result<()> + Send + Sync;

/// The blocking steps of a batch, injectable so watcher logic is tested
/// without a kernel.
#[derive(Clone)]
pub(super) struct Reconciler {
    read_topology: Arc<ReadTopology>,
    apply: Arc<ApplyBindings>,
    sysctl: Arc<WriteSysctl>,
    /// Ticker period; also the shortest gap between two verifications that
    /// only a failed binding asks for.
    interval: Duration,
}

impl Default for Reconciler {
    fn default() -> Self {
        Self {
            read_topology: Arc::new(interface::read_topology),
            apply: Arc::new(super::bindings::apply),
            sysctl: Arc::new(interface_state::write_sysctl),
            interval: RECONCILE_INTERVAL,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkState {
    default_interface: Option<String>,
    local_cidrs: Vec<String>,
}

pub struct IfaceWatcher {
    handle: tokio::task::JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl IfaceWatcher {
    /// Takes over the subscription and the interface state startup built; with
    /// no subscription the watcher reconciles on its ticker alone.
    pub(crate) fn spawn(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        config: Arc<RwLock<Arc<honk_config::Config>>>,
        commands: tokio::sync::mpsc::Sender<crate::control::ControlCommand>,
        degradations: Arc<crate::degradations::Degradations>,
        handoff: InterfaceHandoff,
    ) -> Self {
        let (stop, rx) = watch::channel(false);
        let handle = tokio::spawn(run(
            handoff.subscription,
            ebpf,
            config,
            commands,
            rx,
            degradations,
            handoff.state,
            Reconciler::default(),
        ));
        Self { handle, stop }
    }

    /// Stop between batches and wait for the task. A batch in flight always
    /// finishes: aborting would not stop its blocking thread, which holds dup'd
    /// link FDs that must be closed before `detach_hooks` can detach anything.
    pub async fn shutdown(self, timeout: Duration) {
        let _ = self.stop.send(true);
        let mut handle = self.handle;
        while tokio::time::timeout(timeout, &mut handle).await.is_err() {
            warn!(
                ?timeout,
                "interface watcher is still finishing a blocking step; waiting for it"
            );
        }
    }
}

fn watcher_ticker_only(reason: &'static str) -> crate::degradations::Issue {
    crate::degradations::Issue {
        code: "interface_watcher_disabled",
        message: "The interface watcher reconciles every 60 seconds without event notifications.",
        reason,
    }
}

/// The rtnetlink subscription, opened before the startup dump and handed to
/// the watcher. Its initial reconcile also covers changes during startup.
/// A failure is reported and the watcher runs on its ticker.
pub(super) fn subscribe(degradations: &crate::degradations::Degradations) -> Option<OwnedFd> {
    match subscribe_network_events() {
        Ok(fd) => Some(fd),
        Err(error) => {
            warn!(
                "interface watcher has no event subscription ({error}); reconciling every {}s",
                RECONCILE_INTERVAL.as_secs()
            );
            degradations.set(
                crate::degradations::Component::IfaceWatch,
                watcher_ticker_only("subscribe_failed"),
            );
            None
        }
    }
}

fn subscribe_network_events() -> std::io::Result<OwnedFd> {
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        Some(SockProtocol::NetlinkRoute),
    )
    .map_err(std::io::Error::from)?;
    bind(fd.as_raw_fd(), &NetlinkAddr::new(0, RTMGRP_NETWORK_MASK))
        .map_err(std::io::Error::from)?;
    Ok(fd)
}

/// What one bounded drain of the subscription saw.
#[derive(Debug, Default, PartialEq, Eq)]
struct Drained {
    empty: bool,
    link_event: bool,
    overrun: bool,
}

impl Drained {
    fn verify(&self) -> bool {
        self.link_event || self.overrun
    }
}

/// True when the datagram carries an `RTM_NEWLINK` or `RTM_DELLINK` message.
fn has_link_message(datagram: &[u8]) -> bool {
    let mut offset = 0;
    while let Some(header) = datagram.get(offset..offset + 16) {
        let length = u32::from_ne_bytes(header[0..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(header[4..6].try_into().unwrap());
        if matches!(kind, RTM_NEWLINK | RTM_DELLINK) {
            return true;
        }
        if length < 16 {
            return false;
        }
        offset += (length + 3) & !3;
    }
    false
}

fn drain(fd: RawFd, buf: &mut [u8]) -> std::io::Result<Drained> {
    drain_with(buf, |buffer| recv(fd, buffer, MsgFlags::empty()))
}

fn drain_with(
    buf: &mut [u8],
    mut receive: impl FnMut(&mut [u8]) -> nix::Result<usize>,
) -> std::io::Result<Drained> {
    let mut drained = Drained::default();
    // Bound a burst so stop and the ticker cannot starve behind netlink traffic.
    for _ in 0..64 {
        match receive(buf) {
            Ok(len) => drained.link_event |= has_link_message(&buf[..len.min(buf.len())]),
            Err(Errno::ENOBUFS) => drained.overrun = true,
            Err(Errno::EINTR) => {}
            Err(Errno::EAGAIN) => {
                drained.empty = true;
                return Ok(drained);
            }
            Err(_) if drained.overrun => return Ok(drained),
            Err(errno) => return Err(errno.into()),
        }
    }
    Ok(drained)
}

#[allow(clippy::too_many_arguments)]
async fn run(
    subscription: Option<OwnedFd>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    config: Arc<RwLock<Arc<honk_config::Config>>>,
    commands: tokio::sync::mpsc::Sender<crate::control::ControlCommand>,
    mut stop: watch::Receiver<bool>,
    degradations: Arc<crate::degradations::Degradations>,
    state: InterfaceState,
    reconciler: Reconciler,
) {
    let async_fd = subscription.and_then(|fd| {
        match unsafe { AsyncFd::register_with_interest(fd, tokio::io::Interest::READABLE) } {
            Ok(async_fd) => Some(async_fd),
            Err(error) => {
                warn!(
                    "interface watcher cannot poll its subscription ({error}); reconciling every {}s",
                    reconciler.interval.as_secs()
                );
                degradations.set(
                    crate::degradations::Component::IfaceWatch,
                    watcher_ticker_only("poll_setup_failed"),
                );
                None
            }
        }
    });
    let mut ticker = tokio::time::interval(reconciler.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buf = [0u8; 8192];
    let mut network_state = read_network_state(&config).await;
    let mut netlink_retry_at = tokio::time::Instant::now();
    let notification_queue = commands.clone();
    let mut watch = Watch::new(ebpf, config, commands, reconciler, degradations, state);

    // Interface-dependent state may have changed before the watcher was ready;
    // the control-plane refresh is content-deduplicated.
    watch.reconcile_and_notify(true, true).await;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            permit = notification_queue.reserve(), if watch.pending_notification => {
                match permit {
                    Ok(permit) => { permit.send(crate::control::ControlCommand::NetworkChanged); }
                    Err(_) => debug!("control plane stopped before network-change refresh"),
                }
                watch.pending_notification = false;
            }
            _ = ticker.tick() => {
                let changed = update_network_state(&watch.config, &mut network_state).await;
                watch.reconcile_and_notify(changed, true).await;
            }
            // The second write of a late device's sysctls, after its udev run;
            // without this a quiet host would wait for the ticker.
            _ = sysctl_due(watch.state.sysctl_due()) => {
                watch.reconcile_and_notify(false, false).await;
            }
            guard = readable(async_fd.as_ref(), netlink_retry_at) => {
                // A transient read failure must not kill the watcher: the
                // ticker keeps reconciling regardless.
                let mut guard = match guard {
                    Ok(g) => g,
                    Err(e) => {
                        debug!("interface watcher: netlink wait failed: {}", e);
                        netlink_retry_at = tokio::time::Instant::now() + Duration::from_secs(1);
                        continue;
                    }
                };
                match guard.try_io(|inner| drain(inner.as_raw_fd(), &mut buf)) {
                    Ok(Ok(drained)) => {
                        if drained.empty {
                            guard.clear_ready();
                        }
                        let changed = update_network_state(&watch.config, &mut network_state).await;
                        watch.reconcile_and_notify(changed, drained.verify()).await;
                    }
                    Ok(Err(e)) => {
                        debug!("interface watcher: netlink recv failed: {}", e);
                        netlink_retry_at = tokio::time::Instant::now() + Duration::from_secs(1);
                    }
                    // Spurious readiness; nothing was drained.
                    Err(_) => {}
                }
            }
        }
    }
    debug!("interface watcher stopped");
}

/// Never ready when nothing is owed. A due time that has passed (the last
/// pass failed before claiming) waits a second rather than spinning.
async fn sysctl_due(due: Option<Instant>) {
    match due {
        Some(due) => {
            tokio::time::sleep_until(due.max(Instant::now() + Duration::from_secs(1))).await
        }
        None => std::future::pending().await,
    }
}

/// Readiness of the subscription; never ready without one.
async fn readable<'a>(
    async_fd: Option<&'a AsyncFd<OwnedFd>>,
    retry_at: Instant,
) -> std::io::Result<tokio::io::unix::AsyncFdReadyGuard<'a, OwnedFd>> {
    let Some(async_fd) = async_fd else {
        return std::future::pending().await;
    };
    tokio::time::sleep_until(retry_at).await;
    async_fd.readable().await
}

async fn read_network_state(config: &Arc<RwLock<Arc<honk_config::Config>>>) -> NetworkState {
    let config = config.read().await.clone();
    tokio::task::spawn_blocking(move || NetworkState {
        default_interface: crate::detect_default_interface(),
        local_cidrs: config.local_direct_cidrs(),
    })
    .await
    .expect("network-state task")
}

async fn update_network_state(
    config: &Arc<RwLock<Arc<honk_config::Config>>>,
    current: &mut NetworkState,
) -> bool {
    let next = read_network_state(config).await;
    if *current == next {
        return false;
    }
    *current = next;
    true
}

pub(super) struct Watch {
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    config: Arc<RwLock<Arc<honk_config::Config>>>,
    commands: mpsc::Sender<crate::control::ControlCommand>,
    reconciler: Reconciler,
    degradations: Arc<crate::degradations::Degradations>,
    state: InterfaceState,
    pending_notification: bool,
}

impl Watch {
    pub(super) fn new(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        config: Arc<RwLock<Arc<honk_config::Config>>>,
        commands: mpsc::Sender<crate::control::ControlCommand>,
        reconciler: Reconciler,
        degradations: Arc<crate::degradations::Degradations>,
        state: InterfaceState,
    ) -> Self {
        Self {
            ebpf,
            config,
            commands,
            reconciler,
            degradations,
            state,
            pending_notification: true,
        }
    }

    async fn reconcile_and_notify(&mut self, network_state_changed: bool, verify: bool) {
        self.pending_notification |= network_state_changed;
        // Failures are logged by their episodes; any of them still asks for a refresh.
        match self.reconcile(verify).await {
            Ok(changed) => self.pending_notification |= changed,
            Err(_) => self.pending_notification = true,
        }
        if self.pending_notification {
            match self
                .commands
                .try_send(crate::control::ControlCommand::NetworkChanged)
            {
                Ok(()) => self.pending_notification = false,
                Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.pending_notification = false;
                    debug!("control plane stopped before network-change refresh");
                }
            }
        }
    }

    /// A stage failed as a whole: log its episode and keep what is bound.
    fn step_failed(&mut self, step: ReconcileStep, error: anyhow::Error) -> anyhow::Error {
        self.state.step_failed(step, &error);
        error
    }

    /// One batch: read and plan, snapshot (read lock), apply (no lock), commit
    /// (write lock). Once started it always finishes its commit. `verify`
    /// re-proves retained links against the kernel chain.
    pub(super) async fn reconcile(&mut self, verify: bool) -> anyhow::Result<bool> {
        let (lan, wan) = {
            let config = self.config.read().await;
            (
                config.global.lan_interface.clone(),
                config.global.wan_interface.clone(),
            )
        };

        let mut changed = false;
        let mut last = None;
        // A device that changed under the apply is retried once; the ticker
        // handles anything that keeps moving.
        for round in 0..2 {
            let read = Arc::clone(&self.reconciler.read_topology);
            let (lan, wan) = (lan.clone(), wan.clone());
            let planned = tokio::task::spawn_blocking(move || {
                let topology = read(interface::any_auto(&lan, &wan))?;
                let plan = interface::plan(&lan, &wan, &topology);
                Ok::<_, anyhow::Error>((topology, plan))
            })
            .await;
            let (topology, plan) = match planned {
                Ok(Ok(planned)) => planned,
                Ok(Err(error)) => return Err(self.step_failed(ReconcileStep::Topology, error)),
                Err(error) => return Err(self.step_failed(ReconcileStep::Join, error.into())),
            };

            // On sight: the device is in the dump, whether or not it binds.
            let owed = self.state.claim_sysctls(&plan, &topology, Instant::now());
            if !owed.is_empty() {
                let write = Arc::clone(&self.reconciler.sysctl);
                if let Err(error) =
                    tokio::task::spawn_blocking(move || interface_state::perform(&owed, &*write))
                        .await
                {
                    return Err(self.step_failed(ReconcileStep::Join, error.into()));
                }
            }

            let snapshot = self.ebpf.read().await.interface_binding_snapshot();
            let snapshot = match snapshot {
                Ok(snapshot) => snapshot,
                Err(error) => return Err(self.step_failed(ReconcileStep::Snapshot, error)),
            };
            let held: Vec<_> = snapshot
                .owned
                .iter()
                .map(|(binding, ..)| binding.key())
                .collect();

            let now = Instant::now();
            // A binding that failed its proof is looked at again, but no more
            // often than the ticker, so one stuck binding does not turn every
            // route event into a TCX query per binding.
            let retry_due = !self.state.unproven.is_empty()
                && self
                    .state
                    .last_verify
                    .is_none_or(|at| now.duration_since(at) >= self.reconciler.interval);
            let verify = verify || retry_due || round != 0;
            if verify {
                self.state.last_verify = Some(now);
            }
            let apply = Arc::clone(&self.reconciler.apply);
            let applied = tokio::task::spawn_blocking(move || {
                let report = apply(snapshot, &plan, &topology, verify);
                (report, plan)
            })
            .await;
            let (report, plan) = match applied {
                Ok(applied) => applied,
                Err(error) => return Err(self.step_failed(ReconcileStep::Join, error.into())),
            };
            let ApplyReport {
                commit,
                failed,
                topology_changed,
            } = report;
            let touched: Vec<_> = commit
                .add
                .iter()
                .map(|(binding, ..)| binding.key())
                .chain(
                    commit
                        .reprogram
                        .iter()
                        .map(|(ifindex, direction, _)| (*ifindex, *direction)),
                )
                .collect();
            let owned = commit.keys_after(&held);
            if !commit.is_empty() {
                changed = true;
                log_commit(&commit);
                let closed = self.ebpf.write().await.commit_interface_bindings(commit);
                // The last close of a link takes the rtnl lock.
                if let Err(error) = tokio::task::spawn_blocking(move || drop(closed)).await {
                    return Err(self.step_failed(ReconcileStep::Join, error.into()));
                }
            }
            let mut failures: Vec<BindFailure> = failed
                .iter()
                .map(|(binding, error)| BindFailure::new(binding, error))
                .collect();
            if !verify {
                // Not looked at this pass: still as unproven as before.
                let carried: Vec<_> = self
                    .state
                    .unproven
                    .iter()
                    .filter(|old| {
                        owned.contains(&old.key)
                            && !touched.contains(&old.key)
                            && !failures.iter().any(|f| f.key == old.key)
                    })
                    .cloned()
                    .collect();
                failures.extend(carried);
            }
            self.state
                .settle(&plan, &owned, &failures, &self.degradations);
            self.state.unproven = failures
                .iter()
                .filter(|failure| owned.contains(&failure.key))
                .cloned()
                .collect();
            last = Some(failures);
            if !topology_changed || round == 1 {
                break;
            }
        }
        let failures = last.expect("the first round always runs");
        self.state.step_recovered();
        match failures.first() {
            Some(failure) => Err(anyhow::anyhow!(
                "{} on {}: {}",
                failure.program,
                failure.interface,
                failure.message
            )),
            None => Ok(changed),
        }
    }
}

fn log_commit(commit: &interface::BindingCommit) {
    for (binding, ..) in &commit.add {
        info!(
            interface = %binding.interface,
            ifindex = binding.ifindex.get(),
            direction = ?binding.direction,
            program = binding.program.name(),
            "attached eBPF program to interface"
        );
    }
    for (ifindex, direction, interface) in &commit.rename {
        info!(
            interface = %interface,
            ifindex = ifindex.get(),
            direction = ?direction,
            "interface renamed; binding follows its ifindex"
        );
    }
    for (ifindex, direction, program) in &commit.reprogram {
        info!(
            ifindex = ifindex.get(),
            direction = ?direction,
            program = program.name(),
            "replaced eBPF program on interface"
        );
    }
    for (ifindex, direction) in &commit.remove {
        info!(
            ifindex = ifindex.get(),
            direction = ?direction,
            "released eBPF program from interface"
        );
    }
}

#[cfg(test)]
mod tests;
