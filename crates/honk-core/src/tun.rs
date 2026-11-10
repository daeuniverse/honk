//! Daemon-owned Linux TUN capture into the existing scoped packet Endpoint executor.

mod setup;

use crate::control::{
    ControlPlane,
    netstack::{CAPTURE_MEMORY, OutputLease, PacketDriver, capture_scope},
    packet_endpoint::{PacketEndpointOwner, PacketEndpoints},
};
use anyhow::{Context as _, ensure};
use honk_config::{Config, datapath::Backend};
use honk_datapath::buffer::TxClass;
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::topology::Topology;
use setup::{TunDevice, TunSetup};
use std::{
    future::poll_fn,
    io,
    os::fd::{AsRawFd, RawFd},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::unix::AsyncFd;

const BATCH: usize = 32;
const RX_BYTES: usize = 65_576;
const TURN_BYTES: usize = 1 << 20;
const TURN_TIME: Duration = Duration::from_millis(1);

pub(crate) fn validate_config(config: &Config) -> anyhow::Result<()> {
    let Some(datapath) = config
        .datapath
        .as_ref()
        .filter(|value| value.backend == Backend::Tun)
    else {
        return Ok(());
    };
    datapath.validate()?;
    ensure!(
        !config.global.nfqueue_enable,
        "TUN requires global.nfqueue_enable: false"
    );
    ensure!(
        config.global.lan_interface.is_empty() && config.global.wan_interface.is_empty(),
        "TUN does not accept global LAN/WAN capture interfaces"
    );
    ensure!(
        config.routing.default_mark == 0 && config.routing.rules.iter().all(|rule| rule.mark == 0),
        "TUN Endpoint cannot preserve traffic rule marks"
    );
    let mark = config.global.effective_so_mark();
    ensure!(
        mark != 0 && mark & 0xc800_0000 == 0,
        "TUN requires an exact nonreserved bypass mark"
    );
    for rule in &config.routing.rules {
        let condition = &rule.condition;
        ensure!(
            condition.process_name.is_empty()
                && condition.not.process_name.is_empty()
                && condition.mac.is_empty()
                && condition.not.mac.is_empty(),
            "TUN Endpoint has no process/socket or MAC authority; predicate admission refused"
        );
    }
    Ok(())
}

pub(crate) fn validate_runtime(config: &Config, mock: bool) -> anyhow::Result<()> {
    validate_config(config)?;
    ensure!(
        !mock
            || !config
                .datapath
                .as_ref()
                .is_some_and(|value| value.backend == Backend::Tun),
        "TUN is a real device backend and rejects --mock-ebpf"
    );
    Ok(())
}

struct Runtime {
    io: Option<AsyncFd<TunDevice>>,
    topology: AsyncFd<Topology>,
    setup: Option<TunSetup>,
    driver: Option<PacketDriver>,
    endpoints: PacketEndpoints,
    owner: PacketEndpointOwner,
    admission: Arc<AtomicBool>,
    rx: Box<[u8]>,
    pending: [[Option<OutputLease>; BATCH]; 2],
    first_class: usize,
    closing: bool,
    _memory: MemoryReservation,
}

#[allow(
    clippy::large_enum_variant,
    reason = "Keep the joined ControlPlane on the owner stack without an extra teardown allocation"
)]
enum Turn {
    Joined(anyhow::Result<(ControlPlane, anyhow::Result<()>)>),
    Serviced(anyhow::Result<()>),
}

impl Runtime {
    fn close_capture(&mut self) -> anyhow::Result<()> {
        self.admission.store(false, Ordering::Release);
        let result = self
            .setup
            .as_mut()
            .expect("live TUN setup")
            .close_capture(self.io.as_ref().expect("live TUN FD").get_ref());
        self.closing = true;
        self.endpoints.close();
        self.dispose_pending();
        result
    }

    fn dispose_pending(&mut self) {
        for class in &mut self.pending {
            for output in class {
                drop(output.take());
            }
        }
    }

    fn poll_startup(
        &mut self,
        cx: &mut Context<'_>,
        timer: Pin<&mut Option<tokio::time::Sleep>>,
    ) -> Poll<anyhow::Result<()>> {
        if let Poll::Ready(result) = self.owner.poll_ready(cx) {
            return Poll::Ready(result);
        }
        // A failed startup consumes its supervisor join in poll_ready, but still needs driving.
        self.closing |= self.endpoints.is_closing();
        match self.poll_service(cx, timer, false) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_turn(
        &mut self,
        cx: &mut Context<'_>,
        timer: Pin<&mut Option<tokio::time::Sleep>>,
    ) -> Poll<Turn> {
        if let Poll::Ready(result) = self.owner.poll_join_plane(cx) {
            return Poll::Ready(Turn::Joined(result));
        }
        self.poll_service(cx, timer, true).map(Turn::Serviced)
    }

    fn poll_service(
        &mut self,
        cx: &mut Context<'_>,
        mut timer: Pin<&mut Option<tokio::time::Sleep>>,
        active: bool,
    ) -> Poll<anyhow::Result<()>> {
        let mut topology_more = false;
        if active && !self.closing {
            if self.endpoints.is_closing() || !self.admission.load(Ordering::Acquire) {
                return Poll::Ready(Ok(()));
            }
            match poll_topology(&mut self.topology, cx, Topology::check_changed)? {
                Poll::Ready(true) => {
                    return Poll::Ready(Err(anyhow::anyhow!(
                        "TUN routing topology changed; capture closed and restart required"
                    )));
                }
                Poll::Ready(false) => topology_more = true,
                Poll::Pending => {}
            }
        }
        let now = Instant::now();
        let mut driver = self.driver.take().expect("live packet driver");
        let serviced = service_turn(&mut driver, cx, now, |driver, cx| {
            let mut more = false;
            if active && !self.closing {
                more |= self.read_batch(cx, now, driver.scope())?;
            }
            more |= driver.service(cx, Instant::now());
            if active || self.closing {
                more |= self.outputs(driver, cx)?;
            }
            Ok(more)
        });
        self.driver = Some(driver);
        let more = serviced? || topology_more;
        if more
            || poll_deadline(timer.as_mut(), self.driver.as_ref().unwrap().deadline(), cx)
                .is_ready()
        {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn read_batch(
        &mut self,
        cx: &mut Context<'_>,
        ingress: Instant,
        scope: honk_datapath::ScopeId,
    ) -> anyhow::Result<bool> {
        let io = self.io.as_ref().expect("live TUN FD");
        let mut ready = match io.poll_read_ready(cx) {
            Poll::Ready(result) => result?,
            Poll::Pending => return Ok(false),
        };
        let started = Instant::now();
        let mut bytes = 0;
        for attempt in 0..BATCH {
            if self.endpoints.is_closing() || !self.admission.load(Ordering::Acquire) {
                return Ok(false);
            }
            if turn_limit(attempt, bytes, started, BATCH) {
                return Ok(true);
            }
            let length = match ready
                .try_io(|inner| read_packet(inner.get_ref().as_raw_fd(), &mut self.rx))
            {
                Ok(Ok(length)) => length,
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    return match io.poll_read_ready(cx) {
                        Poll::Ready(Ok(_)) => Ok(true),
                        Poll::Ready(Err(error)) => Err(error.into()),
                        Poll::Pending => Ok(false),
                    };
                }
                Ok(Err(error)) => return Err(error).context("TUN packet read"),
            };
            ensure!(length != 0, "TUN packet reader reached EOF");
            ensure!(
                length < RX_BYTES,
                "TUN record exceeds ordinary IP representation"
            );
            bytes += length;
            let packet = &self.rx[..length];
            if !exact_record(packet) {
                continue;
            }
            admit_packet(&self.endpoints, scope, packet, ingress, |_, _| {
                self.admission.load(Ordering::Acquire) && !self.endpoints.is_closing()
            })?;
        }
        Ok(true)
    }

    fn outputs(&mut self, driver: &mut PacketDriver, cx: &mut Context<'_>) -> anyhow::Result<bool> {
        let started = Instant::now();
        let mut attempts = 0;
        let mut bytes = 0;
        let mut more = false;
        let first = self.first_class;
        self.first_class ^= 1;
        for offset in 0..2 {
            let class = (first + offset) % 2;
            let pending = &mut self.pending[class];
            if pending.iter().all(Option::is_none) {
                match driver.poll_outputs_class(
                    cx,
                    [TxClass::Control, TxClass::Bulk][class],
                    pending,
                ) {
                    Poll::Ready(None) if !self.closing && !self.endpoints.is_closing() => {
                        anyhow::bail!("TUN packet scope ended before endpoint close");
                    }
                    Poll::Ready(Some(count)) => more |= count == BATCH,
                    _ => {}
                }
            }
            if self.closing {
                for output in pending {
                    drop(output.take());
                }
                continue;
            }
            if pending.iter().all(Option::is_none) {
                continue;
            }
            more |= poll_flush(
                self.io.as_ref().expect("live TUN FD"),
                cx,
                pending,
                &mut attempts,
                &mut bytes,
                started,
                || self.admission.load(Ordering::Acquire) && !self.endpoints.is_closing(),
            )?;
        }
        Ok(more)
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.admission.store(false, Ordering::Release);
        self.endpoints.close();
        self.dispose_pending();
        drop(self.driver.take());
        drop(self.io.take());
    }
}

fn admit_packet(
    endpoints: &PacketEndpoints,
    scope: honk_datapath::ScopeId,
    packet: &[u8],
    ingress: Instant,
    on_source: impl FnMut(honk_netstack::ValidatedSource, bool) -> bool,
) -> anyhow::Result<()> {
    match endpoints.receive_with_source(scope, packet, ingress, false, on_source) {
        Ok(_) => Ok(()),
        Err(error)
            if endpoints.is_closing()
                || matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                ) =>
        {
            Ok(())
        }
        Err(error) => Err(error).context("TUN Endpoint admission"),
    }
}

fn poll_topology<T: AsRawFd>(
    io: &mut AsyncFd<T>,
    cx: &mut Context<'_>,
    mut changed: impl FnMut(&mut T) -> io::Result<bool>,
) -> io::Result<Poll<bool>> {
    for _ in 0..2 {
        match io.poll_read_ready(cx) {
            Poll::Ready(Ok(mut ready)) => ready.clear_ready(),
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Pending => return Ok(Poll::Pending),
        }
        // Clear before the receive: a new notification is either read now or wakes the next poll.
        if changed(io.get_mut())? {
            return Ok(Poll::Ready(true));
        }
    }
    Ok(Poll::Ready(false))
}

fn turn_limit(attempts: usize, bytes: usize, started: Instant, maximum: usize) -> bool {
    attempts >= maximum
        || bytes >= TURN_BYTES
        || (attempts != 0 && attempts.is_multiple_of(8) && started.elapsed() >= TURN_TIME)
}

pub(crate) fn service_turn(
    driver: &mut PacketDriver,
    cx: &mut Context<'_>,
    now: Instant,
    io: impl FnOnce(&mut PacketDriver, &mut Context<'_>) -> anyhow::Result<bool>,
) -> anyhow::Result<bool> {
    let more = driver.service(cx, now);
    let result = io(driver, cx);
    // No materialization after the output pass: overdue work retains its next-turn deadline.
    driver.finish_turn(cx, Instant::now());
    result.map(|progress| more || progress)
}

fn exact_record(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
        }
        Some(6) if packet.len() >= 40 => {
            usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len()
        }
        _ => false,
    }
}

fn read_packet(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buffer is a unique writable slice and fd remains owned across this call.
    let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(count as usize)
    }
}

fn write_packet(fd: RawFd, packet: &[u8]) -> io::Result<usize> {
    // SAFETY: packet remains readable and the unique device owner keeps fd live.
    let count = unsafe { libc::write(fd, packet.as_ptr().cast(), packet.len()) };
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(count as usize)
    }
}

fn poll_flush<T: AsRawFd>(
    io: &AsyncFd<T>,
    cx: &mut Context<'_>,
    pending: &mut [Option<OutputLease>; BATCH],
    attempts: &mut usize,
    bytes: &mut usize,
    started: Instant,
    open: impl Fn() -> bool,
) -> io::Result<bool> {
    if !open() {
        return Ok(true);
    }
    let mut ready = match io.poll_write_ready(cx) {
        Poll::Ready(result) => result?,
        Poll::Pending => return Ok(false),
    };
    let accepted_before = *bytes;
    let (blocked, runnable) = flush_pending(pending, attempts, bytes, started, |packet| {
        if !open() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        ready
            .try_io(|inner| write_packet(inner.get_ref().as_raw_fd(), packet))
            .unwrap_or_else(|_| Err(io::ErrorKind::WouldBlock.into()))
    })?;
    if !open() {
        return Ok(true);
    }
    let writable = if blocked {
        // Clear only EAGAIN readiness, then register and recheck the next edge before sleeping.
        match io.poll_write_ready(cx) {
            Poll::Ready(result) => {
                drop(result?);
                true
            }
            Poll::Pending => false,
        }
    } else {
        false
    };
    Ok(runnable || writable || *bytes != accepted_before)
}

fn flush_pending(
    pending: &mut [Option<OutputLease>; BATCH],
    attempts: &mut usize,
    bytes: &mut usize,
    started: Instant,
    mut write: impl FnMut(&[u8]) -> io::Result<usize>,
) -> io::Result<(bool, bool)> {
    for output in pending {
        let Some(lease) = output.as_ref() else {
            continue;
        };
        loop {
            if turn_limit(*attempts, *bytes, started, BATCH * 2) {
                return Ok((false, true));
            }
            *attempts += 1;
            let length = lease.packet().len();
            match write(lease.packet()) {
                Ok(count) if count == length => {
                    *bytes += count;
                    drop(output.take());
                    break;
                }
                Ok(count) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!(
                            "TUN packet boundary violation: accepted {count} of {length} bytes; no replay"
                        ),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok((true, false));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok((false, false))
}

fn poll_deadline(
    mut timer: Pin<&mut Option<tokio::time::Sleep>>,
    deadline: Option<Instant>,
    cx: &mut Context<'_>,
) -> Poll<()> {
    let Some(deadline) = deadline else {
        timer.set(None);
        return Poll::Pending;
    };
    if deadline <= Instant::now() {
        timer.set(None);
        return Poll::Ready(());
    }
    let deadline = tokio::time::Instant::from_std(deadline);
    if let Some(mut sleep) = timer.as_mut().as_pin_mut() {
        sleep.as_mut().reset(deadline);
    } else {
        timer.set(Some(tokio::time::sleep_until(deadline)));
    }
    timer.as_pin_mut().unwrap().poll(cx)
}

pub(crate) async fn run(
    plane: ControlPlane,
    admission: Arc<AtomicBool>,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    let backend = plane.policy_backend_handle();
    let (plane, result) = run_owned(plane, admission).await;
    let result = match (result, backend.write().await.cleanup().await) {
        (Ok(()), cleanup) => cleanup,
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.context(cleanup)),
    };
    if result.is_ok() {
        tracing::info!("TUN datapath stopped");
    }
    (plane, result)
}

fn finish_failed_setup(setup: TunSetup, error: anyhow::Error) -> anyhow::Error {
    match setup.finish(false) {
        Ok(()) => error,
        Err(cleanup) => error.context(cleanup),
    }
}

async fn run_owned(
    plane: ControlPlane,
    admission: Arc<AtomicBool>,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    let config = plane.config_handle().read().await.as_ref().clone();
    let shutdown = plane.shutdown_intent();
    let prepared = (|| -> anyhow::Result<_> {
        validate_config(&config)?;
        let dns = PacketEndpoints::prepare_dns_bind(&config)?;
        let capacity = plane.packet_udp_capacity();
        ensure!(capacity != 0, "TUN requires a funded UDP endpoint capacity");
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let memory = budget
            .reserve(size_of::<Runtime>() + RX_BYTES)
            .context("TUN receive and pending metadata capacity")?;
        let tun = config
            .datapath
            .as_ref()
            .and_then(|value| value.tun.as_ref())
            .context("TUN configuration missing")?;
        let pair = capture_scope(u32::from(tun.mtu), 1, 128, &budget)?;
        let (setup, device, topology) = TunSetup::prepare(&config)?;
        Ok((dns, capacity, memory, pair, setup, device, topology))
    })();
    let (dns, capacity, memory, pair, setup, device, topology) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return (Some(plane), Err(error)),
    };
    // SAFETY: these concrete owners never replace their descriptors while registered.
    let io = match unsafe { AsyncFd::register(device) } {
        Ok(io) => io,
        Err(error) => {
            let (device, error) = error.into_parts();
            drop(device);
            return (Some(plane), Err(finish_failed_setup(setup, error.into())));
        }
    };
    // SAFETY: the subscribed watcher retains its descriptor unchanged while registered.
    let topology = match unsafe { AsyncFd::register(topology) } {
        Ok(topology) => topology,
        Err(error) => {
            let (topology, error) = error.into_parts();
            drop(topology);
            drop(io);
            return (Some(plane), Err(finish_failed_setup(setup, error.into())));
        }
    };
    let (endpoints, owner, mut drivers) =
        match PacketEndpoints::start_driven(plane, vec![pair], capacity, dns) {
            Ok(started) => started,
            Err(error) => {
                drop(io);
                return (None, Err(finish_failed_setup(setup, error)));
            }
        };
    let mut runtime = Runtime {
        io: Some(io),
        topology,
        setup: Some(setup),
        driver: drivers.pop(),
        endpoints,
        owner,
        admission,
        rx: vec![0; RX_BYTES].into_boxed_slice(),
        pending: std::array::from_fn(|_| std::array::from_fn(|_| None)),
        first_class: 0,
        closing: false,
        _memory: memory,
    };
    let timer = None;
    tokio::pin!(timer);
    if let Err(error) = poll_fn(|cx| runtime.poll_startup(cx, timer.as_mut())).await {
        runtime.admission.store(false, Ordering::Release);
        drop(runtime.io.take());
        let error = finish_failed_setup(runtime.setup.take().unwrap(), error);
        return (None, Err(error));
    }
    let activated = (|| -> anyhow::Result<()> {
        let topology = runtime
            .setup
            .as_mut()
            .unwrap()
            .activate(runtime.io.as_ref().unwrap().get_ref())?;
        // SAFETY: the final watcher retains its subscribed descriptor unchanged.
        runtime.topology = unsafe { AsyncFd::register(topology) }.map_err(io::Error::from)?;
        ensure!(
            !runtime.topology.get_mut().check_changed()?,
            "TUN topology changed before publication"
        );
        ensure!(
            !runtime.endpoints.is_closing() && !shutdown.requested(),
            "TUN closed before capture publication"
        );
        runtime.admission.store(true, Ordering::Release);
        runtime.endpoints.capture_ready()?;
        Ok(())
    })();
    let mut failure = activated.err();
    if failure.is_none() {
        tracing::info!("TUN datapath ready");
        if let Err(error) =
            libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready])
        {
            tracing::warn!(%error, "sd_notify readiness failed");
        }
    }
    let joined = loop {
        if !runtime.closing
            && (failure.is_some() || shutdown.requested() || runtime.endpoints.is_closing())
            && let Err(error) = runtime.close_capture()
        {
            failure.get_or_insert(error);
        }
        let turn = tokio::select! {
            turn = poll_fn(|cx| runtime.poll_turn(cx, timer.as_mut())) => Some(turn),
            _ = shutdown.wait(), if !runtime.closing => None,
        };
        match turn {
            Some(Turn::Joined(result)) => break result,
            Some(Turn::Serviced(Err(error))) => {
                if failure.is_none() {
                    tracing::error!(%error, "TUN owner failed closed");
                }
                failure.get_or_insert(error);
            }
            Some(Turn::Serviced(Ok(()))) | None => {}
        }
        tokio::task::yield_now().await;
    };
    if !runtime.closing
        && let Err(error) = runtime.close_capture()
    {
        failure.get_or_insert(error);
    }
    let plane = match joined {
        Ok((plane, result)) => {
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
            Some(plane)
        }
        Err(error) => {
            failure.get_or_insert(error);
            None
        }
    };
    runtime.dispose_pending();
    drop(runtime.driver.take());
    drop(runtime.io.take());
    if let Err(error) = runtime.setup.take().unwrap().finish(failure.is_none()) {
        failure.get_or_insert(error);
    }
    (plane, failure.map_or(Ok(()), Err))
}

#[cfg(test)]
mod tests;
