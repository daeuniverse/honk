//! The auxiliary TUN task keeps each LAN or Host execution scope across device rebinds.
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
    topology::{AuxLinkInfo, AuxLinkWatch, HostLinkChange},
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

fn reserve_host_fifo_budget(auxiliary: &Arc<MemoryBudget>) -> anyhow::Result<Arc<MemoryBudget>> {
    // Two slots and their rings need 1 MiB on 64 KiB pages. The child also charges metadata.
    auxiliary
        .child((1 << 20) + (4 << 10))
        .context("reserve private Host FIFO budget")
}

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
    #[cfg(feature = "packet-ebpf")]
    _host_fifo: Option<honk_xsk::HostFifo>,
}

impl AsRawFd for PrivateTun {
    fn as_raw_fd(&self) -> RawFd {
        self.device.as_raw_fd()
    }
}

impl PrivateTun {
    fn new(
        name: &str,
        mtu: u32,
        budget: &Arc<MemoryBudget>,
        host_budget: Option<&Arc<MemoryBudget>>,
        watch: &AuxLinkWatch,
    ) -> anyhow::Result<Self> {
        #[cfg(feature = "packet-ebpf")]
        let host_fifo = host_budget.map(honk_xsk::HostFifo::reserve).transpose()?;
        #[cfg(not(feature = "packet-ebpf"))]
        let _ = (host_budget, watch);
        let device = TunDevice::new_auxiliary(name).context("create exclusive private TUN")?;
        let guard = AuxTunGuard::install(device.ifindex(), device.as_fd(), budget)?;
        let memory = budget
            .reserve(guard.memory_bytes()?)
            .context("private TUN terminal guard capacity")?;
        #[cfg(feature = "packet-ebpf")]
        if let Some(fifo) = &host_fifo {
            device.prepare_host_fifo(name, fifo.slots())?;
            watch.verify_host_fifo(name, device.ifindex(), fifo.slots())?;
        }
        device.configure_auxiliary(name, mtu)?;
        Ok(Self {
            device,
            guard,
            mtu,
            _guard_memory: memory,
            #[cfg(feature = "packet-ebpf")]
            _host_fifo: host_fifo,
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
    host_binding: Option<u64>,
    resumed: Option<u64>,
}

impl Binding {
    fn tun(&self) -> &PrivateTun {
        self.io.as_ref().expect("bound private TUN").get_ref()
    }

    fn return_link(&self) -> &AuxReturnLink {
        &self.return_link.as_ref().expect("bound return link").0
    }

    fn refresh_outer(
        &mut self,
        watch: &AuxLinkWatch,
        name: &str,
        info: AuxLinkInfo,
    ) -> std::io::Result<()> {
        if self.outer.local_mac != info.local_mac {
            self.return_link().update_host_mac(watch, name, &info)?;
        }
        self.outer = info;
        Ok(())
    }

    fn refresh_broadcasts(&self, watch: &AuxLinkWatch) -> std::io::Result<()> {
        match watch.ipv4_broadcasts() {
            Ok((broadcasts, count)) => self.pair.replace_host_broadcasts(&broadcasts[..count]),
            Err(error) if error.kind() == ErrorKind::Unsupported => {
                // An invalid namespace snapshot cannot grant native broadcast exemptions.
                self.pair.suspend_host_broadcasts()?;
                Err(std::io::Error::new(ErrorKind::WouldBlock, error))
            }
            Err(error) => Err(error),
        }
    }

    fn verify_custody(&self, name: &str) -> anyhow::Result<()> {
        self.tun().verify_fd(name)?;
        if self.host_binding.is_some() {
            self.tun().guard.verify()?;
        }
        self.return_link().verify()?;
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
    host_budget: Option<Arc<MemoryBudget>>,
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
    pub(super) fn host_device_name(index: usize) -> String {
        format!("honk-host-{index}")
    }
    pub(super) fn is_host(&self) -> bool {
        self.host_budget.is_some()
    }
    fn kind(&self) -> &'static str {
        if self.is_host() {
            "Host egress"
        } else {
            "L3 LAN"
        }
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
        Self::prepare(
            name,
            realm,
            Self::device_name(index),
            false,
            AuxLinkWatch::new(root)?,
            root,
        )
    }

    pub(super) fn new_host<'a>(
        name: &str,
        realm: u32,
        index: usize,
        capture_interfaces: impl ExactSizeIterator<Item = &'a str>,
        root: &Arc<MemoryBudget>,
    ) -> anyhow::Result<(Self, PacketScope, PacketOwner)> {
        ensure!(
            cfg!(feature = "packet-ebpf"),
            "Host egress requires the ebpf feature"
        );
        Self::prepare(
            name,
            realm,
            Self::host_device_name(index),
            true,
            AuxLinkWatch::new_host(root, capture_interfaces)?,
            root,
        )
    }

    fn prepare(
        name: &str,
        realm: u32,
        inner_name: String,
        host: bool,
        watch: AuxLinkWatch,
        root: &Arc<MemoryBudget>,
    ) -> anyhow::Result<(Self, PacketScope, PacketOwner)> {
        let link = Self::read_link(&watch, name, host)
            .with_context(|| format!("admit auxiliary interface {name}"))?;
        let mtu = link.map_or(1280, |link| link.mtu);
        let (scope, owner) = auxiliary_scope(mtu, root)?;
        let auxiliary_budget = scope
            .auxiliary_budget()
            .context("missing auxiliary slice")?;
        let records = Records::new(auxiliary_budget, inner_name.capacity() + name.len())?;
        let host_budget = host
            .then(|| reserve_host_fifo_budget(auxiliary_budget))
            .transpose()?;
        let virgin = PrivateTun::new(&inner_name, mtu, root, host_budget.as_ref(), &watch)?;
        virgin.verify(&inner_name, &watch)?;
        Ok((
            Self {
                name: name.to_owned(),
                inner_name,
                realm,
                scope: scope.scope(),
                budget: Arc::clone(root),
                host_budget,
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

    fn read_link(
        watch: &AuxLinkWatch,
        name: &str,
        host: bool,
    ) -> std::io::Result<Option<AuxLinkInfo>> {
        if host {
            watch.read_host(name)
        } else {
            watch.read_l3(name)
        }
    }

    fn link_change(
        watch: &mut AuxLinkWatch,
        name: &str,
        host: bool,
        previous: Option<AuxLinkInfo>,
        inner: Option<(&str, u32, u32)>,
    ) -> std::io::Result<HostLinkChange> {
        if host {
            watch.changed_host(name, previous, inner)
        } else if watch.changed(name, previous, inner)? {
            Ok(HostLinkChange::Rebind)
        } else {
            Ok(HostLinkChange::Unchanged)
        }
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
        let kind = self.kind();
        // Unwind serving before releasing the owner, which still owes kernel and scope cleanup.
        let serving = AssertUnwindSafe(self.serve(&mut owner, activate, &mut ready))
            .catch_unwind()
            .await;
        let mut failure = match serving {
            Ok(result) => result.err(),
            Err(payload) => Some(
                anyhow::Error::new(ServicePanic::new(payload))
                    .context(format!("{kind} {}", self.name)),
            ),
        };
        if let Some(ready) = ready {
            let why = failure.as_ref().map_or_else(
                || "capture closed before activation".into(),
                |error| format!("{error:#}"),
            );
            let _ = ready.send(Err(anyhow::anyhow!("{kind} {}: {why}", self.name)));
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
            super::fold_capture_result(&mut failure, self.unbind(&owner.gateway).await);
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
        let kind = self.kind();
        let host = self.is_host();
        let timer = None;
        tokio::pin!(timer);
        tokio::select! {
            biased;
            _ = shutdown.wait() => return Ok(()),
            result = activate => result.with_context(|| format!("{kind} activation cancelled"))?,
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
                state = match self.prepare_binding(watch.get_mut(), ready.is_some(), &owner.gateway)
                {
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
                    .map_err(|_| anyhow::anyhow!("{kind} readiness receiver dropped"))?;
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
                        let inner = self.binding.as_ref().map(|b| {
                            let tun = b.tun();
                            (self.inner_name.as_str(), tun.device.ifindex(), tun.mtu)
                        });
                        let mut change = HostLinkChange::Unchanged;
                        match tun::poll_topology(&mut watch, cx, |watch| {
                            change = Self::link_change(watch, &self.name, host, identity, inner)?;
                            Ok(change != HostLinkChange::Unchanged)
                        }) {
                            Ok(Poll::Ready(true)) => return Poll::Ready(match change {
                                HostLinkChange::Refresh(info) => Event::Refresh(info),
                                HostLinkChange::Rebind => Event::Changed,
                                HostLinkChange::Unchanged => unreachable!("reported topology change"),
                            }),
                            Ok(Poll::Ready(false)) => cx.waker().wake_by_ref(),
                            Ok(Poll::Pending) => {},
                            Err(e) => return Poll::Ready(Event::Lost(e.into())),
                        }
                    }
                    if tun::poll_deadline(check.as_mut(), due, cx).is_ready() {
                        return Poll::Ready(Event::Check);
                    }
                    let more = if matches!(state, State::Active | State::Refreshing) {
                        let binding = self.binding.as_ref().expect("active device pair");
                        match self.records.service(binding.io.as_ref().expect("active TUN"), owner, cx) {
                            Ok(more) => {
                                #[cfg(feature = "packet-ebpf")]
                                if let Some(cutoff) = self.records.take_drained_cutoff() {
                                    let id = binding.host_binding.expect("Host input drain");
                                    if let Err(e) = owner.gateway.host_input_drained(self.realm, id, cutoff) {
                                        return Poll::Ready(Event::Lost(e.into()));
                                    }
                                }
                                more
                            }
                            Err(error) => return Poll::Ready(Event::Lost(error)),
                        }
                    } else { owner.driver.service(cx, Instant::now()) };
                    if more || tun::poll_deadline(timer.as_mut(), owner.driver.deadline(), cx).is_ready() { cx.waker().wake_by_ref(); }
                    Poll::Pending
                }) => event,
            };
            state = match event {
                Event::Stop => return Ok(()),
                Event::Refresh(info) => {
                    if let Some(binding) = &mut self.binding {
                        match binding.refresh_outer(watch.get_ref(), &self.name, info) {
                            Ok(()) if matches!(state, State::Publishing) => State::Publishing,
                            Ok(()) => self.refresh_broadcasts(owner, watch.get_ref()).await?,
                            Err(error) => {
                                self.retire(owner).await?;
                                self.warn_wait(&error.to_string());
                                State::Resync
                            }
                        }
                    } else {
                        State::Scan
                    }
                }
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
                    State::Active | State::Refreshing => {
                        let result = self.check_active(&owner.gateway);
                        match result {
                            Ok(()) if matches!(state, State::Refreshing) => {
                                self.refresh_broadcasts(owner, watch.get_ref()).await?
                            }
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
                        match watch
                            .get_ref()
                            .resubscribe(&self.budget)
                            .and_then(Self::register_watch)
                        {
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
        gateway: &GatewayPublisher,
    ) -> anyhow::Result<State> {
        #[cfg(not(feature = "packet-ebpf"))]
        let _ = gateway;
        let host = self.is_host();
        let current = match Self::read_link(watch, &self.name, host) {
            Ok(current) => current,
            Err(error) if !startup && error.kind() == ErrorKind::Unsupported => {
                // The watch retains the actual link index and policy selector on refusal.
                self.warn_wait(&error.to_string());
                return Ok(State::Offline(None));
            }
            Err(error) => return Err(error.into()),
        };
        let Some(mut outer) = current.filter(|link| link.up) else {
            self.warn_wait(if current.is_some() {
                "interface down"
            } else {
                "interface absent"
            });
            return Ok(State::Offline(current));
        };
        #[cfg(feature = "packet-ebpf")]
        let private_mtu = if host && outer.is_l2 {
            // SAFETY: sysconf takes only the supported page-size selector.
            let page = u32::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
            ethernet_return_mtu(
                outer.mtu,
                page,
                gateway.host_conntrack()?.skb_shared_info_size(),
            )?
        } else {
            outer.mtu
        };
        #[cfg(not(feature = "packet-ebpf"))]
        let private_mtu = outer.mtu;
        let mut tun = match self.virgin.take() {
            Some(tun) => tun,
            None => PrivateTun::new(
                &self.inner_name,
                private_mtu,
                &self.budget,
                self.host_budget.as_ref(),
                watch,
            )?,
        };
        if tun.mtu != private_mtu {
            tun.device
                .configure_auxiliary(&self.inner_name, private_mtu)?;
            tun.mtu = private_mtu;
        }
        // Drop our private setup events, then prove the full inner topology before publication.
        match Self::link_change(watch, &self.name, host, Some(outer), None)? {
            HostLinkChange::Unchanged => (),
            HostLinkChange::Refresh(info) => outer = info,
            HostLinkChange::Rebind => {
                return Err(std::io::Error::from_raw_os_error(libc::ENODEV).into());
            }
        }
        tun.verify(&self.inner_name, watch)?;
        let inner = tun.device.ifindex();
        let pair = Arc::new(if host {
            AuxDevicePair::new_host(outer.ifindex, inner, &self.budget)?
        } else {
            AuxDevicePair::new(outer.ifindex, inner, &self.budget)?
        });
        let (return_link, host_binding) = if host {
            let binding = ScopeId::allocate().context("Host binding identities exhausted")?;
            #[cfg(feature = "packet-ebpf")]
            {
                tun.guard.install_host_delay_filter(
                    tun.device.as_fd(),
                    &pair,
                    gateway.maps(),
                    &self.budget,
                    gateway.host_conntrack()?,
                )?;
                // A reader that saw the old filter may still be inserting a TUN record.
                gateway.synchronize_host_input()?;
            }
            (
                tun.guard
                    .attach_host_return(&pair, &outer, watch, &self.name)?,
                Some(binding.as_u64()),
            )
        } else {
            (tun.guard.attach_return(&pair)?, None)
        };
        let return_memory = self
            .budget
            .reserve(return_link.memory_bytes()?)
            .context("private TUN return program/link capacity")?;
        // SAFETY: the only TUN descriptor is never changed while registered on this reactor.
        let io = unsafe { AsyncFd::register(tun) }.map_err(std::io::Error::from)?;
        self.binding = Some(Binding {
            outer,
            io: Some(io),
            return_link: Some((return_link, return_memory)),
            pair,
            host_binding,
            resumed: None,
        });
        Ok(State::Publishing)
    }

    fn publish(&mut self, watch: &mut AuxLinkWatch, owner: &mut Owner) -> anyhow::Result<State> {
        let kind = self.kind();
        let b = self.binding.as_mut().expect("prepared device pair");
        b.pair.verify()?;
        b.verify_custody(&self.inner_name)?;
        let private_mtu = b.tun().mtu;
        if b.resumed.is_none() {
            #[cfg(feature = "packet-ebpf")]
            if b.host_binding.is_some()
                && !self.records.discard_before_host_open(b.tun().as_raw_fd())?
            {
                return Ok(State::Publishing);
            }
            owner
                .endpoints
                .resume_auxiliary(&mut owner.driver, private_mtu)?;
            let scope = owner.driver.sole_owner().expect("auxiliary scope");
            let stamp = scope.binding();
            b.resumed = Some(stamp);
            #[cfg(feature = "packet-ebpf")]
            if let Some(binding) = b.host_binding {
                scope.install_host_process_lookup(
                    self.realm,
                    stamp,
                    binding,
                    owner.gateway.host_process_lookup()?,
                )?;
            }
        }
        if !owner.open() {
            return Ok(State::Publishing);
        }
        let inner = Some((
            self.inner_name.as_str(),
            b.tun().device.ifindex(),
            private_mtu,
        ));
        match Self::link_change(
            watch,
            &self.name,
            b.host_binding.is_some(),
            Some(b.outer),
            inner,
        )? {
            HostLinkChange::Unchanged => (),
            HostLinkChange::Refresh(info) => b.refresh_outer(watch, &self.name, info)?,
            HostLinkChange::Rebind => {
                return Err(std::io::Error::from_raw_os_error(libc::ENODEV).into());
            }
        }
        let outer = b.outer;
        let (broadcasts, count) = watch.ipv4_broadcasts()?;
        let result = match b.host_binding {
            #[cfg(feature = "packet-ebpf")]
            Some(binding) => owner.gateway.bind_host(
                self.realm,
                self.scope,
                b.resumed.expect("resumed Host execution"),
                binding,
                outer,
                Arc::clone(&b.pair),
                &broadcasts[..count],
            ),
            #[cfg(not(feature = "packet-ebpf"))]
            Some(_) => anyhow::bail!("Host egress requires the ebpf feature"),
            None => owner.gateway.bind_auxiliary(
                self.realm,
                self.scope,
                outer.ifindex,
                Arc::clone(&b.pair),
                &broadcasts[..count],
            ),
        };
        match result {
            Ok(()) => {
                self.waiting = false;
                tracing::info!(interface = %self.name, realm = self.realm, binding_id = b.host_binding, ifindex = outer.ifindex, mtu = outer.mtu, private_mtu, "{kind} active");
                Ok(State::Active)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(State::Publishing),
            Err(e) => Err(e.into()),
        }
    }

    async fn refresh_broadcasts(
        &mut self,
        owner: &mut Owner,
        watch: &AuxLinkWatch,
    ) -> anyhow::Result<State> {
        let binding = self.binding.as_ref().expect("active Host pair");
        match binding.refresh_broadcasts(watch) {
            Ok(()) => Ok(State::Active),
            // The pair cleared the root slot and verified its identity before returning WouldBlock.
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(State::Refreshing),
            Err(error) => {
                self.retire(owner).await?;
                self.warn_wait(&error.to_string());
                Ok(State::Resync)
            }
        }
    }

    fn check_active(&mut self, gateway: &GatewayPublisher) -> anyhow::Result<()> {
        let binding = self.binding.as_ref().expect("active device pair");
        binding.pair.verify_open()?;
        binding.verify_custody(&self.inner_name)?;
        gateway.verify_auxiliary(self.realm, &binding.pair)?;
        #[cfg(feature = "packet-ebpf")]
        if let Some(id) = binding.host_binding
            && !self.records.draining()
            && let Some(cutoff) = gateway.host_pending_drain(self.realm, id)?
        {
            let passed = binding.tun().guard.admitted_records().ok();
            self.records.request_drain(cutoff, passed);
        }
        Ok(())
    }

    fn warn_wait(&mut self, reason: &str) {
        if !self.waiting {
            let kind = self.kind();
            tracing::warn!(interface = %self.name, reason, "{kind} waiting_link");
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

    async fn unbind(&mut self, gateway: &GatewayPublisher) -> anyhow::Result<()> {
        loop {
            match gateway.unbind_auxiliary(self.realm) {
                Ok(()) => {
                    drop(self.binding.take());
                    return Ok(());
                }
                Err(error) if self.is_host() && error.kind() == ErrorKind::WouldBlock => {
                    // An active sibling can briefly own the cross-realm tuple guard.
                    tokio::time::sleep(PUBLISH_RETRY).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn retire(&mut self, owner: &mut Owner) -> anyhow::Result<()> {
        if self.binding.is_none() {
            return Ok(());
        }
        self.withdraw(&owner.gateway)?;
        if self.binding.as_ref().is_some_and(|b| b.resumed.is_some()) {
            let result = owner.endpoints.pause_auxiliary(&mut owner.driver).await;
            if owner.stopping() {
                return Ok(());
            }
            result?;
        }
        self.unbind(&owner.gateway).await
    }
}

#[derive(Clone, Copy)]
enum State {
    Scan,
    Offline(Option<AuxLinkInfo>),
    Publishing,
    Active,
    Refreshing,
    Resync,
}

impl State {
    fn check_after(&self) -> Option<Duration> {
        match self {
            Self::Publishing | Self::Refreshing => Some(PUBLISH_RETRY),
            Self::Active => Some(CUSTODY_CHECK),
            Self::Resync => Some(RESYNC_DELAY),
            Self::Scan | Self::Offline(_) => None,
        }
    }
}

enum Event {
    Check,
    Changed,
    Refresh(AuxLinkInfo),
    Lost(anyhow::Error),
    Stop,
}

#[cfg(any(feature = "packet-ebpf", test))]
fn ethernet_return_mtu(outer_mtu: u32, page: u32, shared_info_size: usize) -> anyhow::Result<u32> {
    ensure!(
        page.is_power_of_two() && shared_info_size != 0,
        "invalid kernel skb geometry"
    );
    // SKB_MAX_ALLOC uses four pages minus cache-aligned skb_shared_info. Rounding up to
    // a full page covers the kernel cache alignment on both supported architectures.
    let overhead = u32::try_from(shared_info_size)?
        .checked_next_multiple_of(page)
        .context("skb_shared_info alignment overflow")?;
    let limit = page
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_sub(overhead))
        .and_then(|bytes| bytes.checked_sub(14))
        .filter(|&mtu| mtu >= 1280)
        .context("kernel skb change-head limit below the minimum Host Ethernet MTU")?;
    Ok(outer_mtu.min(limit))
}

fn device_gone(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.raw_os_error() == Some(libc::ENODEV))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "packet-ebpf")]
    #[tokio::test]
    async fn host_fifo_leaves_room_for_stack_rebind() -> anyhow::Result<()> {
        use honk_datapath::buffer::TxClass;
        use honk_xsk::HostFifo;

        let root = MemoryBudget::new(32 << 20);
        let (scope, owner) = auxiliary_scope(1500, &root)?;
        let auxiliary = scope.auxiliary_budget().unwrap();
        let _records = Records::new(auxiliary, "honk-host-0".len() + "up".len())?;
        let fifo_budget = reserve_host_fifo_budget(auxiliary)?;
        let mut fifo = HostFifo::reserve(&fifo_budget)?;
        assert!(fifo.slots() >= 2);
        assert_eq!(root.used(), 4 << 20);

        let plane = crate::control::tests::support::control_plane(honk_config::Config::default());
        let scopes = vec![(scope.clone(), owner)];
        let (endpoints, mut supervisor, mut drivers) =
            PacketEndpoints::start_driven(plane, scopes, 1, None, ScopeId::HOST).await?;
        let driver = &mut drivers[0];
        poll_fn(|cx| {
            driver.service(cx, Instant::now());
            supervisor.poll_ready(cx)
        })
        .await?;
        endpoints.resume_auxiliary(driver, 1500)?;

        for mtu in [12_274, 1500, 1400, 1280] {
            let previous = scope.binding();
            drop(fifo);
            endpoints.pause_auxiliary(driver).await?;
            fifo = HostFifo::reserve(&fifo_budget)?;
            endpoints
                .resume_auxiliary(driver, mtu)
                .with_context(|| format!("rebind Host Stack at MTU {mtu}"))?;
            assert!(scope.binding() > previous);
            assert!(fifo.slots() >= 2);
            let headroom = auxiliary.limit() - auxiliary.used();
            assert!(headroom >= 1 << 20, "MTU {mtu}: {headroom} bytes available");
            println!(
                "MTU {mtu}: {} FIFO slots, {headroom} bytes available",
                fifo.slots()
            );

            let client = "192.0.2.2:41000".parse()?;
            let payload = mtu.to_be_bytes();
            let sender = scope.datagram_sender("192.0.2.1:53".parse()?);
            assert_eq!(sender.send_to(&payload, client).await?, payload.len());
            let mut outputs = [None];
            let count =
                poll_fn(|cx| driver.poll_outputs_class(cx, TxClass::Bulk, &mut outputs)).await;
            assert_eq!(count, Some(1));
            let packet = outputs[0].take().unwrap();
            assert!(packet.packet().ends_with(&payload));
            packet.release();
        }
        endpoints.close();
        let (_, joined) = poll_fn(|cx| {
            driver.service(cx, Instant::now());
            supervisor.poll_join_plane(cx)
        })
        .await?;
        joined
    }

    #[test]
    fn host_ethernet_return_budget_leaves_room_for_the_mac_header() {
        assert_eq!(ethernet_return_mtu(1500, 4096, 384).unwrap(), 1500);
        assert_eq!(ethernet_return_mtu(20000, 4096, 384).unwrap(), 12274);
        assert_eq!(ethernet_return_mtu(20000, 4096, 4097).unwrap(), 8178);
        assert_eq!(ethernet_return_mtu(65535, 65536, 384).unwrap(), 65535);
        assert!(ethernet_return_mtu(20000, 4096, 16384).is_err());
        assert!(ethernet_return_mtu(20000, 0, 384).is_err());
        assert!(ethernet_return_mtu(20000, 4096, 0).is_err());
    }

    #[test]
    fn ethernet_private_mtu_accepts_a_jumbo_datagram_and_fragments_its_reply() {
        use honk_netstack::{Config, Mode, Rx, Stack};

        let now = Instant::now();
        let stack = |mtu| {
            let mut cfg = Config::new([17; 32]);
            cfg.mode = Mode::Transparent {
                exclude: Default::default(),
            };
            cfg.mtu = mtu;
            Stack::new(cfg, now)
        };
        let private_mtu = ethernet_return_mtu(20_000, 4096, 384).unwrap() as u16;
        let mut client = stack(20_000);
        let mut host = stack(private_mtu);
        let client_addr = "192.0.2.1:40000".parse().unwrap();
        let host_addr = "198.51.100.2:443".parse().unwrap();
        let bytes = vec![0x7a; 19_000];
        let mut wire = vec![0; 20_000];
        let len = client
            .udp_send_from(client_addr, host_addr, &bytes, &mut wire)
            .unwrap();
        assert!(len > usize::from(private_mtu));
        let Rx::Transparent { payload, .. } = host.receive(now, &wire[..len]) else {
            panic!("oversized ingress datagram did not reach the Host stack");
        };
        assert_eq!(&wire[payload], bytes);
        let first = host
            .udp_send_from(host_addr, client_addr, &bytes, &mut wire)
            .unwrap();
        assert!(first <= usize::from(private_mtu));
        assert_eq!(client.receive(now, &wire[..first]), Rx::Consumed);
        let last = host.poll_transmit(now, &mut wire).unwrap();
        assert!(last <= usize::from(private_mtu));
        let Rx::TransparentOwned {
            packet, payload, ..
        } = client.receive(now, &wire[..last])
        else {
            panic!("fragmented Host reply did not reassemble");
        };
        assert_eq!(&packet[payload], bytes);
    }

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
