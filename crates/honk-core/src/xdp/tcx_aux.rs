//! Each configured L3 LAN keeps its scope, but no packet device or application incarnation crosses a rebind.
mod io;

use self::io::Records;
use super::gateway::GatewayPublisher;
use crate::control::{
    ShutdownIntent,
    netstack::{PacketDriver, PacketOwner, PacketScope, auxiliary_scope},
    packet_endpoint::PacketEndpoints,
};
use crate::tun::{self, TunDevice};
use anyhow::{Context as _, ensure};
use futures::FutureExt as _;
use honk_datapath::ScopeId;
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::{
    AuxDevicePair, AuxReturnLink, AuxTunGuard,
    topology::{AuxLinkInfo, AuxLinkWatch},
};
use std::{
    any::Any,
    future::poll_fn,
    io::ErrorKind,
    os::fd::{AsFd, AsRawFd, RawFd},
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};
use tokio::{io::unix::AsyncFd, sync::oneshot};

const CUSTODY_CHECK: Duration = Duration::from_secs(1);
const PUBLISH_RETRY: Duration = Duration::from_millis(100);
const RESYNC_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, thiserror::Error)]
#[error("auxiliary TUN service panicked: {message}")]
struct ServicePanic {
    message: String,
    // The original panic payload need only be Send. The mutex lets the error own it across join.
    _payload: parking_lot::Mutex<Box<dyn Any + Send>>,
}

impl ServicePanic {
    fn new(payload: Box<dyn Any + Send>) -> Self {
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("non-string panic payload")
            .to_owned();
        Self {
            message,
            _payload: parking_lot::Mutex::new(payload),
        }
    }
}

struct PrivateTun {
    device: TunDevice,
    guard: AuxTunGuard,
    mtu: u32,
    _guard_memory: MemoryReservation,
}

impl AsRawFd for PrivateTun {
    fn as_raw_fd(&self) -> RawFd {
        self.device.as_raw_fd()
    }
}

impl PrivateTun {
    fn new(name: &str, mtu: u32, budget: &Arc<MemoryBudget>) -> anyhow::Result<Self> {
        let device = TunDevice::new_auxiliary(name).context("create exclusive private TUN")?;
        let guard = AuxTunGuard::install(device.ifindex(), device.as_fd(), budget)?;
        let memory = budget
            .reserve(guard.memory_bytes()?)
            .context("L3 LAN terminal guard capacity")?;
        device.configure_auxiliary(name, mtu)?;
        Ok(Self {
            device,
            guard,
            mtu,
            _guard_memory: memory,
        })
    }

    fn verify_fd(&self, name: &str) -> anyhow::Result<()> {
        self.device.verify_auxiliary(name)?;
        ensure!(
            std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"))?.trim()
                == "1",
            "private TUN IPv6 enabled"
        );
        Ok(())
    }

    fn verify(&self, name: &str, watch: &AuxLinkWatch) -> anyhow::Result<()> {
        self.verify_fd(name)?;
        watch.verify_inner(name, self.device.ifindex(), self.mtu)?;
        self.guard.verify()?;
        Ok(())
    }
}

struct Binding {
    outer: AuxLinkInfo,
    io: Option<AsyncFd<PrivateTun>>,
    return_link: Option<(AuxReturnLink, MemoryReservation)>,
    pair: Arc<AuxDevicePair>,
    resumed: bool,
}

impl Binding {
    fn tun(&self) -> &PrivateTun {
        self.io.as_ref().expect("bound private TUN").get_ref()
    }

    fn verify_custody(&self, name: &str) -> anyhow::Result<()> {
        self.tun().verify_fd(name)?;
        self.return_link
            .as_ref()
            .expect("bound return link")
            .0
            .verify()?;
        Ok(())
    }
}

struct Owner {
    driver: PacketDriver,
    endpoints: PacketEndpoints,
    gateway: Arc<GatewayPublisher>,
    admission: Arc<AtomicBool>,
    shutdown: Arc<ShutdownIntent>,
}

impl Owner {
    fn stopping(&self) -> bool {
        self.shutdown.requested() || self.endpoints.is_closing()
    }
    fn open(&self) -> bool {
        self.admission.load(Ordering::Acquire) && !self.stopping()
    }
}

pub(super) struct PreparedAux {
    name: String,
    inner_name: String,
    realm: u32,
    scope: ScopeId,
    budget: Arc<MemoryBudget>,
    watch: Option<AuxLinkWatch>,
    // An absent configured link starts with a virgin guarded TUN. Once used, it is destroyed.
    virgin: Option<PrivateTun>,
    binding: Option<Binding>,
    records: Box<Records>,
    waiting: bool,
}

impl PreparedAux {
    pub(super) fn device_name(index: usize) -> String {
        format!("honk-l3-{index}")
    }
    pub(super) fn scope(&self) -> ScopeId {
        self.scope
    }
    pub(super) fn realm(&self) -> u32 {
        self.realm
    }

    pub(super) fn new(
        name: &str,
        realm: u32,
        index: usize,
        root: &Arc<MemoryBudget>,
    ) -> anyhow::Result<(Self, PacketScope, PacketOwner)> {
        let watch = AuxLinkWatch::new(root)?;
        let link = watch
            .read_l3(name)
            .with_context(|| format!("admit L3 LAN {name}"))?;
        let mtu = link.map_or(1280, |link| link.mtu);
        let (scope, owner) = auxiliary_scope(mtu, root)?;
        let inner_name = Self::device_name(index);
        let records = Records::new(
            scope
                .auxiliary_budget()
                .context("missing auxiliary slice")?,
            inner_name.capacity() + name.len(),
        )?;
        let virgin = PrivateTun::new(&inner_name, mtu, root)?;
        virgin.verify(&inner_name, &watch)?;
        Ok((
            Self {
                name: name.to_owned(),
                inner_name,
                realm,
                scope: scope.scope(),
                budget: Arc::clone(root),
                watch: Some(watch),
                virgin: Some(virgin),
                binding: None,
                records,
                waiting: false,
            },
            scope,
            owner,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run(
        mut self,
        driver: PacketDriver,
        endpoints: PacketEndpoints,
        gateway: Arc<GatewayPublisher>,
        admission: Arc<AtomicBool>,
        shutdown: Arc<ShutdownIntent>,
        activate: oneshot::Receiver<()>,
        ready: oneshot::Sender<anyhow::Result<()>>,
    ) -> anyhow::Result<()> {
        let mut owner = Owner {
            driver,
            endpoints,
            gateway,
            admission,
            shutdown,
        };
        let mut ready = Some(ready);
        // Unwind serving before releasing the owner, which still owes kernel and scope cleanup.
        let serving = AssertUnwindSafe(self.serve(&mut owner, activate, &mut ready))
            .catch_unwind()
            .await;
        let mut failure = match serving {
            Ok(result) => result.err(),
            Err(payload) => Some(
                anyhow::Error::new(ServicePanic::new(payload))
                    .context(format!("L3 LAN {}", self.name)),
            ),
        };
        if let Some(ready) = ready {
            let why = failure.as_ref().map_or_else(
                || "capture closed before activation".into(),
                |error| format!("{error:#}"),
            );
            let _ = ready.send(Err(anyhow::anyhow!("L3 LAN {}: {why}", self.name)));
        }
        if failure.is_some() {
            owner.shutdown.request();
        }
        let withdrawn = self.withdraw(&owner.gateway);
        drop(self.virgin.take());
        let can_unbind = withdrawn.is_ok();
        if !can_unbind {
            owner.shutdown.request();
        }
        super::fold_capture_result(&mut failure, withdrawn);
        // The supervisor owns close. Keep the handed-off driving right until its real return,
        // also on failed startup and while the coordinator is closing the physical capture.
        let timer = None;
        tokio::pin!(timer);
        poll_fn(|cx| {
            let more = owner.driver.service_closing(cx, Instant::now());
            if owner.driver.is_returned() {
                return Poll::Ready(());
            }
            if more || tun::poll_deadline(timer.as_mut(), owner.driver.deadline(), cx).is_ready() {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await;
        let joined = owner.driver.wait_auxiliary_work().await;
        if can_unbind && joined.is_ok() && self.binding.is_some() {
            super::fold_capture_result(
                &mut failure,
                owner
                    .gateway
                    .unbind_auxiliary(self.realm)
                    .map_err(Into::into),
            );
        }
        super::fold_capture_result(&mut failure, joined.map_err(Into::into));
        failure.map_or(Ok(()), Err)
    }

    async fn serve(
        &mut self,
        owner: &mut Owner,
        activate: oneshot::Receiver<()>,
        ready: &mut Option<oneshot::Sender<anyhow::Result<()>>>,
    ) -> anyhow::Result<()> {
        let watch = self.watch.take().expect("prepared auxiliary watcher");
        let mut watch = Self::register_watch(watch)?;
        let shutdown = Arc::clone(&owner.shutdown);
        let timer = None;
        tokio::pin!(timer);
        tokio::select! {
            biased;
            _ = shutdown.wait() => return Ok(()),
            result = activate => result.context("L3 LAN activation cancelled")?,
            _ = poll_fn(|cx| {
                let more = owner.driver.service(cx, Instant::now());
                if owner.endpoints.is_closing() { return Poll::Ready(()); }
                if more || tun::poll_deadline(timer.as_mut(), owner.driver.deadline(), cx).is_ready() { cx.waker().wake_by_ref(); }
                Poll::Pending
            }) => return Ok(()),
        }
        let mut state = State::Scan;
        loop {
            if !owner.open() {
                return Ok(());
            }
            if matches!(state, State::Scan) {
                state = match self.prepare_binding(watch.get_mut(), ready.is_some()) {
                    Ok(state) => state,
                    Err(error) if ready.is_some() && !device_gone(&error) => return Err(error),
                    Err(error) => {
                        self.warn_wait(&format!("{error:#}"));
                        State::Resync
                    }
                };
            }
            if matches!(state, State::Publishing) {
                state = match self.publish(watch.get_mut(), owner) {
                    Ok(state) => state,
                    Err(error) => {
                        self.retire(owner).await?;
                        if !owner.open() {
                            return Ok(());
                        }
                        if ready.is_some() && !device_gone(&error) {
                            return Err(error);
                        }
                        self.warn_wait(&format!("{error:#}"));
                        State::Resync
                    }
                };
            }
            if matches!(state, State::Active | State::Offline(_))
                && let Some(ready) = ready.take()
            {
                ready
                    .send(Ok(()))
                    .map_err(|_| anyhow::anyhow!("L3 LAN readiness receiver dropped"))?;
            }
            let due = state.check_after().map(|delay| Instant::now() + delay);
            let check = None;
            tokio::pin!(check);
            let event = tokio::select! {
                biased;
                _ = shutdown.wait() => return Ok(()),
                event = poll_fn(|cx| {
                    if !owner.open() {
                        return Poll::Ready(Event::Stop);
                    }
                    if !matches!(state, State::Resync) {
                        let identity = match state {
                            State::Offline(link) => link,
                            _ => self.binding.as_ref().map(|b| b.outer),
                        };
                        let inner = self.binding.as_ref().map(|b| (self.inner_name.as_str(), b.tun().device.ifindex(), b.outer.mtu));
                        match tun::poll_topology(&mut watch, cx, |w| w.changed(&self.name, identity, inner)) {
                            Ok(Poll::Ready(true)) => return Poll::Ready(Event::Changed),
                            Ok(Poll::Ready(false)) => cx.waker().wake_by_ref(),
                            Ok(Poll::Pending) => {},
                            Err(e) => return Poll::Ready(Event::Lost(e.into())),
                        }
                    }
                    if tun::poll_deadline(check.as_mut(), due, cx).is_ready() {
                        return Poll::Ready(Event::Check);
                    }
                    let more = if matches!(state, State::Active) {
                        let binding = self.binding.as_ref().expect("active device pair");
                        match self.records.service(binding.io.as_ref().expect("active TUN"), owner, cx) {
                            Ok(more) => more,
                            Err(error) => return Poll::Ready(Event::Lost(error)),
                        }
                    } else { owner.driver.service(cx, Instant::now()) };
                    if more || tun::poll_deadline(timer.as_mut(), owner.driver.deadline(), cx).is_ready() { cx.waker().wake_by_ref(); }
                    Poll::Pending
                }) => event,
            };
            state = match event {
                Event::Stop => return Ok(()),
                Event::Changed => {
                    self.retire(owner).await?;
                    State::Scan
                }
                Event::Lost(error) => {
                    self.retire(owner).await?;
                    self.warn_wait(&format!("{error:#}"));
                    State::Resync
                }
                Event::Check => match state {
                    State::Active => {
                        let result = self.check_active(&owner.gateway);
                        match result {
                            Ok(()) => State::Active,
                            Err(error) => {
                                self.retire(owner).await?;
                                self.warn_wait(&format!("{error:#}"));
                                State::Scan
                            }
                        }
                    }
                    State::Resync => {
                        // A fresh subscription precedes the snapshot after observation loss.
                        match AuxLinkWatch::new(&self.budget).and_then(Self::register_watch) {
                            Ok(replacement) => {
                                watch = replacement;
                                State::Scan
                            }
                            Err(error) if ready.is_some() => return Err(error.into()),
                            Err(_) => State::Resync,
                        }
                    }
                    state => state,
                },
            };
        }
    }

    fn register_watch(watch: AuxLinkWatch) -> std::io::Result<AsyncFd<AuxLinkWatch>> {
        // SAFETY: the subscribed watcher retains its descriptor unchanged until deregistration.
        unsafe { AsyncFd::register(watch) }.map_err(std::io::Error::from)
    }

    fn prepare_binding(
        &mut self,
        watch: &mut AuxLinkWatch,
        startup: bool,
    ) -> anyhow::Result<State> {
        let current = match watch.read_l3(&self.name) {
            Ok(current) => current,
            Err(error) if !startup && error.kind() == ErrorKind::Unsupported => {
                // The watch retains the actual link index and policy selector on refusal.
                self.warn_wait(&error.to_string());
                return Ok(State::Offline(None));
            }
            Err(error) => return Err(error.into()),
        };
        let Some(outer) = current.filter(|link| link.up) else {
            self.warn_wait(if current.is_some() {
                "interface down"
            } else {
                "interface absent"
            });
            return Ok(State::Offline(current));
        };
        let mut tun = match self.virgin.take() {
            Some(tun) => tun,
            None => PrivateTun::new(&self.inner_name, outer.mtu, &self.budget)?,
        };
        if tun.mtu != outer.mtu {
            tun.device
                .configure_auxiliary(&self.inner_name, outer.mtu)?;
            tun.mtu = outer.mtu;
        }
        // Drop our private setup events, then prove the full inner topology before publication.
        if watch.changed(&self.name, Some(outer), None)? {
            return Err(std::io::Error::from_raw_os_error(libc::ENODEV).into());
        }
        tun.verify(&self.inner_name, watch)?;
        let pair = Arc::new(AuxDevicePair::new(
            outer.ifindex,
            tun.device.ifindex(),
            &self.budget,
        )?);
        let return_link = tun.guard.attach_return(&pair)?;
        let return_memory = self
            .budget
            .reserve(return_link.memory_bytes()?)
            .context("L3 LAN return program/link capacity")?;
        // SAFETY: the only TUN descriptor is never changed while registered on this reactor.
        let io = unsafe { AsyncFd::register(tun) }.map_err(std::io::Error::from)?;
        self.binding = Some(Binding {
            outer,
            io: Some(io),
            return_link: Some((return_link, return_memory)),
            pair,
            resumed: false,
        });
        Ok(State::Publishing)
    }

    fn publish(&mut self, watch: &mut AuxLinkWatch, owner: &mut Owner) -> anyhow::Result<State> {
        let b = self.binding.as_mut().expect("prepared device pair");
        b.pair.verify()?;
        b.verify_custody(&self.inner_name)?;
        let outer = b.outer;
        if !b.resumed {
            owner
                .endpoints
                .resume_auxiliary(&mut owner.driver, outer.mtu)?;
            b.resumed = true;
        }
        if !owner.open() {
            return Ok(State::Publishing);
        }
        let inner = Some((
            self.inner_name.as_str(),
            b.tun().device.ifindex(),
            outer.mtu,
        ));
        if watch.changed(&self.name, Some(outer), inner)? {
            return Err(std::io::Error::from_raw_os_error(libc::ENODEV).into());
        }
        let (broadcasts, count) = watch.ipv4_broadcasts()?;
        match owner.gateway.bind_auxiliary(
            self.realm,
            self.scope,
            outer.ifindex,
            Arc::clone(&b.pair),
            &broadcasts[..count],
        ) {
            Ok(()) => {
                self.waiting = false;
                tracing::info!(interface = %self.name, realm = self.realm, ifindex = outer.ifindex, mtu = outer.mtu, "L3 LAN active");
                Ok(State::Active)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(State::Publishing),
            Err(e) => Err(e.into()),
        }
    }

    fn check_active(&self, gateway: &GatewayPublisher) -> anyhow::Result<()> {
        let binding = self.binding.as_ref().expect("active device pair");
        binding.pair.verify_open()?;
        binding.verify_custody(&self.inner_name)?;
        gateway.verify_auxiliary(self.realm, &binding.pair)?;
        Ok(())
    }

    fn warn_wait(&mut self, reason: &str) {
        if !self.waiting {
            tracing::warn!(interface = %self.name, reason, "L3 LAN waiting_link");
            self.waiting = true;
        }
    }

    fn withdraw(&mut self, gateway: &GatewayPublisher) -> anyhow::Result<()> {
        let Some(b) = &mut self.binding else {
            return Ok(());
        };
        let mut failure = b.pair.set_open(false).err().map(Into::into);
        super::fold_capture_result(
            &mut failure,
            gateway.close_auxiliary(self.realm).map_err(Into::into),
        );
        self.records.dispose();
        drop(b.return_link.take());
        // The device-owned SHOT survives loss of the return link. Closing the sole FD
        // destroys the netdevice and its queued skbs, including unconsumed ingress.
        drop(b.io.take());
        let gone = b
            .pair
            .inner_gone()
            .map_err(anyhow::Error::from)
            .and_then(|gone| {
                ensure!(gone, "old private TUN remains registered");
                Ok(())
            });
        super::fold_capture_result(&mut failure, gone);
        failure.map_or(Ok(()), Err)
    }

    async fn retire(&mut self, owner: &mut Owner) -> anyhow::Result<()> {
        if self.binding.is_none() {
            return Ok(());
        }
        self.withdraw(&owner.gateway)?;
        if self.binding.as_ref().is_some_and(|b| b.resumed) {
            let result = owner.endpoints.pause_auxiliary(&mut owner.driver).await;
            if owner.stopping() {
                return Ok(());
            }
            result?;
        }
        owner.gateway.unbind_auxiliary(self.realm)?;
        drop(self.binding.take());
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum State {
    Scan,
    Offline(Option<AuxLinkInfo>),
    Publishing,
    Active,
    Resync,
}

impl State {
    fn check_after(&self) -> Option<Duration> {
        match self {
            Self::Publishing => Some(PUBLISH_RETRY),
            Self::Active => Some(CUSTODY_CHECK),
            Self::Resync => Some(RESYNC_DELAY),
            Self::Scan | Self::Offline(_) => None,
        }
    }
}

enum Event {
    Check,
    Changed,
    Lost(anyhow::Error),
    Stop,
}

fn device_gone(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.raw_os_error() == Some(libc::ENODEV))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_links_have_no_topology_poll_deadline() {
        let down = AuxLinkInfo {
            ifindex: 1,
            mtu: 1280,
            is_l2: false,
            local_mac: [0; 6],
            up: false,
        };
        assert_eq!(State::Offline(None).check_after(), None);
        assert_eq!(State::Offline(Some(down)).check_after(), None);
    }
}
