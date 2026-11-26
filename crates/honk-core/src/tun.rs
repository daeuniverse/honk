//! Daemon-owned Linux TUN capture into the existing scoped packet Endpoint executor.

mod setup;
#[cfg(feature = "ebpf")]
mod source;

use crate::control::{
    ControlPlane,
    netstack::{CAPTURE_MEMORY, OutputLease, PacketDriver, capture_scope_with_output},
    packet_endpoint::{PacketEndpointOwner, PacketEndpoints},
};
use anyhow::{Context as _, ensure};
use honk_config::{Config, datapath::Backend};
use honk_datapath::{ScopeId, buffer::TxClass};
use honk_netstack::{
    Csum, GsoKind, GsoRx, MemoryBudget, MemoryReservation, RxMeta, Transmit, TxCaps, TxCsum, wire,
};
use honk_xsk::topology::Topology;
pub(crate) use setup::TunDevice;
use setup::TunSetup;
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

pub(crate) const BATCH: usize = 32;
const VNET_BYTES: usize = 10;
pub(crate) const MAX_IP_BYTES: usize = 40 + u16::MAX as usize;
pub(crate) const RX_BYTES: usize = VNET_BYTES + MAX_IP_BYTES + 1;
pub(crate) const TX_CAPS: TxCaps = TxCaps {
    tso4: true,
    tso6: true,
    csum4: false,
    csum6: false,
    uso4: false,
    uso6: false,
};
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
        config.routing.default_mark.unwrap_or(0) == 0
            && config
                .routing
                .rules
                .iter()
                .all(|rule| rule.mark.unwrap_or(0) == 0),
        "TUN Endpoint cannot preserve traffic rule marks"
    );
    let mark = config.global.effective_so_mark();
    ensure!(
        mark != 0 && mark & 0xc800_0000 == 0,
        "TUN requires an exact nonreserved bypass mark"
    );
    let host_facts = datapath.tun.as_ref().is_some_and(|tun| tun.host_facts);
    ensure!(
        !host_facts || cfg!(feature = "ebpf"),
        "TUN host_facts requires the built ebpf feature and actual source admission"
    );
    for rule in &config.routing.rules {
        let condition = &rule.condition;
        ensure!(
            (host_facts
                || (condition.process_name.is_empty() && condition.not.process_name.is_empty()))
                && condition.mac.is_empty()
                && condition.not.mac.is_empty(),
            "TUN process predicates require host_facts; MAC predicates are unavailable"
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
    drivers: Vec<PacketDriver>,
    plain_scope: ScopeId,
    host_scope: Option<ScopeId>,
    #[cfg(feature = "ebpf")]
    source: Option<source::Source>,
    pname_support: crate::ebpf::PnameSupportCell,
    endpoints: PacketEndpoints,
    owner: PacketEndpointOwner,
    admission: Arc<AtomicBool>,
    rx: Box<[u8]>,
    pending: [[[Option<OutputLease>; BATCH]; 2]; 2],
    first_group: usize,
    closing: bool,
    malformed_records: u64,
    expired_sources: u64,
    host_capacity_refusals: u64,
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
        *self.pname_support.write() = crate::ebpf::PnameSupport::Unavailable;
        #[cfg(feature = "ebpf")]
        let source_close = self.source.as_mut().map(source::Source::close).transpose();
        self.admission.store(false, Ordering::Release);
        let result = self
            .setup
            .as_mut()
            .expect("live TUN setup")
            .close_capture(self.io.as_ref().expect("live TUN FD").get_ref());
        self.closing = true;
        self.endpoints.close();
        self.dispose_pending();
        #[cfg(feature = "ebpf")]
        if let Err(error) = source_close {
            return match result {
                Ok(()) => Err(error),
                Err(cleanup) => Err(error.context(cleanup)),
            };
        }
        result
    }

    fn dispose_pending(&mut self) {
        for scope in &mut self.pending {
            for class in scope {
                for output in class {
                    drop(output.take());
                }
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
            match poll_topology(&mut self.topology, cx, Topology::check_tun_changed)? {
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
        let mut drivers = std::mem::take(&mut self.drivers);
        let serviced = service_turn(&mut drivers, cx, now, |drivers, cx| {
            let mut more = false;
            if active && !self.closing {
                more |= self.read_batch(cx, now)?;
            }
            for driver in drivers.iter_mut() {
                more |= driver.service(cx, Instant::now());
            }
            if active || self.closing {
                more |= self.outputs(drivers, cx)?;
            }
            Ok(more)
        });
        self.drivers = drivers;
        let more = serviced? || topology_more;
        let deadline = self.drivers.iter().filter_map(PacketDriver::deadline).min();
        if more || poll_deadline(timer.as_mut(), deadline, cx).is_ready() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn read_batch(&mut self, cx: &mut Context<'_>, ingress: Instant) -> anyhow::Result<bool> {
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
            let (length, host): (usize, Option<crate::control::netstack::HostIngress>) = match ready
                .try_io(|inner| {
                    #[cfg(feature = "ebpf")]
                    if let Some(source) = &mut self.source {
                        return source
                            .read(inner.get_ref().as_raw_fd(), &mut self.rx)
                            .map(|read| (read.len, read.host));
                    }
                    read_packet(inner.get_ref().as_raw_fd(), &mut self.rx).map(|len| (len, None))
                }) {
                Ok(Ok(read)) => read,
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                #[cfg(feature = "ebpf")]
                Ok(Err(error)) if source::is_expired(&error) => {
                    self.expired_sources = self.expired_sources.saturating_add(1);
                    continue;
                }
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
                "TUN record exceeds vnet and ordinary IP representation"
            );
            bytes += length;
            let Some((packet, meta)) = decode_record(&self.rx[..length]) else {
                self.malformed_records = self.malformed_records.saturating_add(1);
                continue;
            };
            if let Some(host) = host {
                let scope = self
                    .host_scope
                    .context("Host read without prepared Host scope")?;
                let result = self.endpoints.receive_host_with_source(
                    scope,
                    packet,
                    meta,
                    ingress,
                    &host,
                    None,
                    false,
                    |_, _, _, _| {
                        self.admission.load(Ordering::Acquire) && !self.endpoints.is_closing()
                    },
                );
                match result {
                    Ok(_) => {}
                    Err(error)
                        if error.kind() == io::ErrorKind::TimedOut
                            && Instant::now() >= host.source_horizon =>
                    {
                        self.expired_sources = self.expired_sources.saturating_add(1);
                    }
                    Err(_) if self.endpoints.is_closing() => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                        ) =>
                    {
                        self.host_capacity_refusals = self.host_capacity_refusals.saturating_add(1);
                    }
                    Err(error) => return Err(error).context("TUN Host Endpoint admission"),
                }
            } else {
                admit_packet(
                    &self.endpoints,
                    self.plain_scope,
                    packet,
                    meta,
                    ingress,
                    |_, _| self.admission.load(Ordering::Acquire) && !self.endpoints.is_closing(),
                )?;
            }
        }
        Ok(true)
    }

    fn outputs(
        &mut self,
        drivers: &mut [PacketDriver],
        cx: &mut Context<'_>,
    ) -> anyhow::Result<bool> {
        let started = Instant::now();
        let mut attempts = 0;
        let mut bytes = 0;
        let mut more = false;
        let groups = drivers.len() * 2;
        let first = self.first_group;
        self.first_group = (first + 1) % groups;
        for offset in 0..groups {
            if !self.closing && turn_limit(attempts, bytes, started, BATCH * 2) {
                return Ok(true);
            }
            let group = (first + offset) % groups;
            let scope = group / 2;
            let class = group % 2;
            let driver = &mut drivers[scope];
            let pending = &mut self.pending[scope][class];
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
        *self.pname_support.write() = crate::ebpf::PnameSupport::Unavailable;
        #[cfg(feature = "ebpf")]
        if let Some(source) = &mut self.source {
            let _ = source.close();
        }
        self.endpoints.close();
        self.dispose_pending();
        self.drivers.clear();
        drop(self.io.take());
    }
}

pub(crate) fn admit_packet(
    endpoints: &PacketEndpoints,
    scope: honk_datapath::ScopeId,
    packet: &[u8],
    meta: RxMeta,
    ingress: Instant,
    on_source: impl FnMut(honk_netstack::ValidatedSource, bool) -> bool,
) -> anyhow::Result<()> {
    match endpoints.receive_with_meta_source(scope, packet, meta, ingress, false, on_source) {
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

pub(crate) fn poll_topology<T: AsRawFd>(
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

pub(crate) fn turn_limit(attempts: usize, bytes: usize, started: Instant, maximum: usize) -> bool {
    attempts >= maximum
        || bytes >= TURN_BYTES
        || (attempts != 0 && attempts.is_multiple_of(8) && started.elapsed() >= TURN_TIME)
}

pub(crate) fn service_turn(
    drivers: &mut [PacketDriver],
    cx: &mut Context<'_>,
    now: Instant,
    io: impl FnOnce(&mut [PacketDriver], &mut Context<'_>) -> anyhow::Result<bool>,
) -> anyhow::Result<bool> {
    let mut more = false;
    for driver in drivers.iter_mut() {
        more |= driver.service(cx, now);
    }
    let result = io(drivers, cx);
    // No materialization after the output pass: overdue work retains its next-turn deadline.
    for driver in drivers {
        driver.finish_turn(cx, Instant::now());
    }
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

pub(crate) fn decode_record(record: &[u8]) -> Option<(&[u8], RxMeta)> {
    if record.len() >= RX_BYTES {
        return None;
    }
    let (header, packet) = record.split_at_checked(VNET_BYTES)?;
    if !exact_record(packet) {
        return None;
    }
    Some((packet, vnet_meta(header.try_into().ok()?, packet)?))
}

fn vnet_meta(header: &[u8; VNET_BYTES], packet: &[u8]) -> Option<RxMeta> {
    let field = |offset| u16::from_le_bytes([header[offset], header[offset + 1]]);
    let hdr_len = usize::from(field(2));
    let size = field(4);
    let start = field(6);
    let offset = field(8);
    let csum = match header[0] {
        0 => Csum::Verify,
        1 => Csum::Partial { start, offset },
        2 => Csum::Valid,
        _ => return None,
    };
    if header[0] != 1 && (start != 0 || offset != 0) {
        return None;
    }
    let gso = match header[1] {
        0 if size == 0 && hdr_len == 0 => None,
        1 if packet.first()? >> 4 == 4 && size != 0 && size != u16::MAX => Some(GsoRx {
            kind: GsoKind::Tcp,
            size,
        }),
        4 if packet.first()? >> 4 == 6 && size != 0 && size != u16::MAX => Some(GsoRx {
            kind: GsoKind::Tcp,
            size,
        }),
        _ => return None,
    };
    if header[0] == 1 || gso.is_some() {
        let ip = wire::parse_ip(packet).ok()?;
        let l4 = packet.get(ip.payload.clone())?;
        let (header_end, checksum_offset) = match ip.proto {
            wire::PROTO_TCP => (ip.payload.start + wire::tcp::parse(l4).ok()?.1, 16),
            wire::PROTO_UDP if gso.is_none() => {
                wire::udp::parse(l4).ok()?;
                (ip.payload.start + 8, 6)
            }
            _ => return None,
        };
        if header[0] == 1
            && (usize::from(start) != ip.payload.start
                || offset != checksum_offset
                || usize::from(start) + usize::from(offset) + 2 > header_end)
        {
            return None;
        }
        // Linux reports skb_headlen, which can include linear payload after the headers.
        if gso.is_some() && (hdr_len < header_end || hdr_len > packet.len()) {
            return None;
        }
    }
    Some(RxMeta { csum, gso })
}

fn vnet_header(packet: &[u8], transmit: Transmit) -> io::Result<[u8; VNET_BYTES]> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid TUN transmit metadata");
    if transmit.len != packet.len() {
        return Err(invalid());
    }
    let mut header = [0; VNET_BYTES];
    if let TxCsum::Partial { start, offset } = transmit.csum {
        header[0] = 1;
        header[6..8].copy_from_slice(&start.to_le_bytes());
        header[8..10].copy_from_slice(&offset.to_le_bytes());
    }
    if let Some(gso) = transmit.gso {
        if gso.kind != GsoKind::Tcp || transmit.csum == TxCsum::Full {
            return Err(invalid());
        }
        header[1] = match packet.first().map(|byte| byte >> 4) {
            Some(4) => 1,
            Some(6) => 4,
            _ => return Err(invalid()),
        };
        header[2..4].copy_from_slice(&gso.hdr_len.to_le_bytes());
        header[4..6].copy_from_slice(&gso.size.to_le_bytes());
    }
    vnet_meta(&header, packet).ok_or_else(invalid)?;
    Ok(header)
}

pub(crate) fn read_packet(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buffer is a unique writable slice and fd remains owned across this call.
    let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(count as usize)
    }
}

fn write_packet(fd: RawFd, header: &[u8; VNET_BYTES], packet: &[u8]) -> io::Result<usize> {
    let buffers = [
        libc::iovec {
            iov_base: header.as_ptr().cast_mut().cast(),
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: packet.as_ptr().cast_mut().cast(),
            iov_len: packet.len(),
        },
    ];
    // SAFETY: both slices remain readable and the unique owner keeps fd live during writev.
    let count = unsafe { libc::writev(fd, buffers.as_ptr(), buffers.len() as libc::c_int) };
    if count < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(count as usize)
    }
}

pub(crate) fn poll_flush<T: AsRawFd>(
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
    let (blocked, runnable) =
        flush_pending(pending, attempts, bytes, started, |header, packet| {
            if !open() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            ready
                .try_io(|inner| write_packet(inner.get_ref().as_raw_fd(), header, packet))
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
    mut write: impl FnMut(&[u8; VNET_BYTES], &[u8]) -> io::Result<usize>,
) -> io::Result<(bool, bool)> {
    for output in pending {
        let Some(lease) = output.as_ref() else {
            continue;
        };
        let header = vnet_header(lease.packet(), lease.transmit())?;
        loop {
            if turn_limit(*attempts, *bytes, started, BATCH * 2) {
                return Ok((false, true));
            }
            *attempts += 1;
            let length = VNET_BYTES + lease.packet().len();
            match write(&header, lease.packet()) {
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

pub(crate) fn poll_deadline(
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
    pin_root: &std::path::Path,
    admission: Arc<AtomicBool>,
    pname_support: crate::ebpf::PnameSupportCell,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    let backend = plane.policy_backend_handle();
    let (plane, result) = run_owned(plane, pin_root, admission, pname_support).await;
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

fn finish_startup(
    setup: Option<TunSetup>,
    #[cfg(feature = "ebpf")] source: Option<source::Source>,
    mut error: anyhow::Error,
) -> anyhow::Error {
    #[cfg(feature = "ebpf")]
    if let Some(mut source) = source {
        if let Err(close) = source.close() {
            error = error.context(close);
        }
        if let Err(finish) = source.finish() {
            error = error.context(finish);
        }
    }
    if let Some(setup) = setup {
        error = finish_failed_setup(setup, error);
    }
    error
}

async fn run_owned(
    plane: ControlPlane,
    _pin_root: &std::path::Path,
    admission: Arc<AtomicBool>,
    pname_support: crate::ebpf::PnameSupportCell,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    let config = plane.config_handle().read().await.as_ref().clone();
    let shutdown = plane.shutdown_intent();
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let prepared = (|| -> anyhow::Result<_> {
        validate_config(&config)?;
        let dns = PacketEndpoints::prepare_dns_bind(&config)?;
        let capacity = plane.packet_udp_capacity();
        ensure!(capacity != 0, "TUN requires a funded UDP endpoint capacity");
        let memory = budget
            .reserve(
                size_of::<Runtime>()
                    + RX_BYTES
                    + 4 * size_of::<(
                        crate::control::netstack::PacketScope,
                        crate::control::netstack::PacketOwner,
                    )>(),
            )
            .context("TUN receive and pending metadata capacity")?;
        Ok((dns, capacity, memory))
    })();
    let (dns, capacity, memory) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return (Some(plane), Err(error)),
    };
    let tun = config
        .datapath
        .as_ref()
        .and_then(|value| value.tun.as_ref())
        .unwrap();
    #[cfg(feature = "ebpf")]
    let mut source = if tun.host_facts {
        match source::Source::prepare(&config, &budget, _pin_root) {
            Ok(source) => Some(source),
            Err(error) => return (Some(plane), Err(error)),
        }
    } else {
        None
    };
    let (setup, device, topology) = match TunSetup::prepare(
        &config,
        #[cfg(feature = "ebpf")]
        source.as_mut(),
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return (
                Some(plane),
                Err(finish_startup(
                    None,
                    #[cfg(feature = "ebpf")]
                    source,
                    error,
                )),
            );
        }
    };
    // SAFETY: these concrete owners never replace their descriptors while registered.
    let io = match unsafe { AsyncFd::register(device) } {
        Ok(io) => io,
        Err(error) => {
            let (device, error) = error.into_parts();
            drop(device);
            return (
                Some(plane),
                Err(finish_startup(
                    Some(setup),
                    #[cfg(feature = "ebpf")]
                    source,
                    error.into(),
                )),
            );
        }
    };
    // SAFETY: the subscribed watcher retains its descriptor unchanged while registered.
    let topology = match unsafe { AsyncFd::register(topology) } {
        Ok(topology) => topology,
        Err(error) => {
            let (topology, error) = error.into_parts();
            drop(topology);
            drop(io);
            return (
                Some(plane),
                Err(finish_startup(
                    Some(setup),
                    #[cfg(feature = "ebpf")]
                    source,
                    error.into(),
                )),
            );
        }
    };
    let mut pairs = Vec::with_capacity(1 + usize::from(tun.host_facts));
    let prepared_scopes = (|| -> anyhow::Result<_> {
        let realms = 1 + usize::from(tun.host_facts);
        let pair = capture_scope_with_output(
            u32::from(tun.mtu),
            realms,
            128,
            u16::MAX as usize,
            TX_CAPS,
            &budget,
        )?;
        let plain_scope = pair.0.scope();
        pairs.push(pair);
        let host_scope = if tun.host_facts {
            let pair = capture_scope_with_output(
                u32::from(tun.mtu),
                realms,
                128,
                u16::MAX as usize,
                TX_CAPS,
                &budget,
            )?;
            let scope = pair.0.scope();
            pairs.push(pair);
            pairs.last().unwrap().0.prepare_host()?;
            Some(scope)
        } else {
            None
        };
        Ok((plain_scope, host_scope))
    })();
    let (plain_scope, host_scope) = match prepared_scopes {
        Ok(scopes) => scopes,
        Err(error) => {
            for (scope, _) in &pairs {
                scope.shutdown(true);
            }
            for (_, owner) in pairs {
                owner.run().await;
            }
            drop(io);
            return (
                Some(plane),
                Err(finish_startup(
                    Some(setup),
                    #[cfg(feature = "ebpf")]
                    source,
                    error,
                )),
            );
        }
    };
    let (endpoints, owner, drivers) =
        match PacketEndpoints::start_driven(plane, pairs, capacity, dns, plain_scope).await {
            Ok(started) => started,
            Err(error) => {
                drop(io);
                return (
                    None,
                    Err(finish_startup(
                        Some(setup),
                        #[cfg(feature = "ebpf")]
                        source,
                        error,
                    )),
                );
            }
        };
    let mut runtime = Runtime {
        io: Some(io),
        topology,
        setup: Some(setup),
        drivers,
        plain_scope,
        host_scope,
        #[cfg(feature = "ebpf")]
        source,
        pname_support,
        endpoints,
        owner,
        admission,
        rx: vec![0; RX_BYTES].into_boxed_slice(),
        pending: std::array::from_fn(|_| std::array::from_fn(|_| std::array::from_fn(|_| None))),
        first_group: 0,
        closing: false,
        malformed_records: 0,
        expired_sources: 0,
        host_capacity_refusals: 0,
        _memory: memory,
    };
    let timer = None;
    tokio::pin!(timer);
    if let Err(mut error) = poll_fn(|cx| runtime.poll_startup(cx, timer.as_mut())).await {
        if let Err(close) = runtime.close_capture() {
            error = error.context(close);
        }
        while !runtime.owner.is_joined() {
            match poll_fn(|cx| runtime.poll_turn(cx, timer.as_mut())).await {
                Turn::Joined(result) => {
                    if let Err(cleanup) = result.and_then(|(_, result)| result) {
                        error = error.context(cleanup);
                    }
                }
                Turn::Serviced(Err(cleanup)) => {
                    error = error.context(cleanup);
                }
                Turn::Serviced(Ok(())) => {}
            }
            tokio::task::yield_now().await;
        }
        runtime.drivers.clear();
        drop(runtime.io.take());
        return (
            None,
            Err(finish_startup(
                runtime.setup.take(),
                #[cfg(feature = "ebpf")]
                runtime.source.take(),
                error,
            )),
        );
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
        #[cfg(feature = "ebpf")]
        if let Some(source) = &mut runtime.source {
            source.activate()?;
            *runtime.pname_support.write() = source.pname_support();
        }
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
    runtime.drivers.clear();
    drop(runtime.io.take());
    #[cfg(feature = "ebpf")]
    if let Some(source) = runtime.source.take()
        && let Err(error) = source.finish()
    {
        failure.get_or_insert(error);
    }
    if let Err(error) = runtime.setup.take().unwrap().finish(failure.is_none()) {
        failure.get_or_insert(error);
    }
    (plane, failure.map_or(Ok(()), Err))
}

#[cfg(test)]
mod tests;
