use super::host::{HostCapture, HostPrepare};
use super::*;
use crate::control::netstack::HostIngress;
use honk_ebpf_common::host::HOST_METADATA_LEN;
use std::os::fd::OwnedFd;

const RETURN_HEADER: usize = 54;

pub(super) struct PreparedHost {
    capture: HostCapture,
    queue: Queue,
    watches: [AsyncFd<OwnedFd>; 2],
    scope: ScopeId,
    namespace: u64,
    attachment: u64,
    generated: Option<usize>,
}

impl PreparedHost {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare(
        interfaces: &[String],
        source_xdp: &[(u32, u32)],
        authority: CaptureAuthority,
        mark: u32,
        pin_root: &Path,
        data_dir: &Path,
        realm_count: usize,
        budget: &Arc<MemoryBudget>,
        native: Option<Arc<crate::ebpf::native::NativePublication>>,
    ) -> anyhow::Result<(Self, (PacketScope, crate::control::netstack::PacketOwner))> {
        let capture = HostCapture::prepare_closed(HostPrepare {
            source_interfaces: interfaces,
            source_xdp,
            object: include_bytes!(env!("HONK_HOST_EBPF_OBJECT")),
            authority,
            bypass_mark: mark,
            pin_root,
            data_dir,
            budget: Arc::clone(budget),
            native,
        })?;
        tracing::debug!(used = budget.used(), "Host runtime: after prepare_closed");
        let mtu = capture.output_mtu();
        ensure!(mtu >= 1280, "Host return output MTU must be at least 1280");
        let (config, bulk_frames) = device_sizing(capture.private_device().mtu);
        let mut port = capture.open_port::<Retained>(config)?;
        tracing::debug!(used = budget.used(), "Host runtime: after open_port");
        ensure!(!port.zerocopy(), "Host private queue requires Copy binding");
        let namespace = socket_namespace(port.as_fd())?;
        port.refill()?;
        let observed = port.counters();
        let observed_rings = port.rings();
        // SAFETY: the owned port is deregistered before its socket is closed.
        let io = unsafe { AsyncFd::register(port) }.map_err(io::Error::from)?;
        let [source, child] = capture.watch_fds();
        // SAFETY: these duplicates stay owned and stable until registration drops.
        let source =
            unsafe { AsyncFd::register(source.try_clone_to_owned()?) }.map_err(io::Error::from)?;
        let child =
            unsafe { AsyncFd::register(child.try_clone_to_owned()?) }.map_err(io::Error::from)?;
        let (scope, owner) = capture_scope(mtu, realm_count, bulk_frames, budget)?;
        tracing::debug!(used = budget.used(), "Host runtime: after capture_scope");
        scope.prepare_host()?;
        tracing::debug!(used = budget.used(), "Host runtime: after prepare_host");
        let scope_id = scope.scope();
        let max_length = RETURN_HEADER + mtu as usize;
        Ok((
            Self {
                capture,
                queue: Queue {
                    id: 0,
                    io: QueueIo::Registered(io),
                    observed,
                    observed_rings,
                },
                watches: [source, child],
                scope: scope_id,
                namespace,
                attachment: authority.attachment_generation,
                generated: (max_length <= FRAME_SIZE).then_some(max_length),
            },
            (scope, owner),
        ))
    }
    pub(super) fn finish(mut self) -> anyhow::Result<()> {
        if let Err(error) = self.capture.close_capture() {
            std::mem::forget(self);
            return Err(error);
        }
        let Self {
            mut capture,
            queue,
            watches,
            ..
        } = self;
        let mut port = queue.io.into_inner();
        if !port.close().ready_for_backend_teardown() {
            std::mem::forget((capture, port, watches));
            anyhow::bail!(
                "unpublished Host ledger did not reach terminal ownership; retaining custody"
            );
        }
        port.close_socket();
        drop((port, watches));
        capture.finish_close()
    }

    pub(super) fn observation(&self) -> QueueObservation {
        let config = self.queue.io.get_ref().config();
        QueueObservation {
            namespace: self.namespace,
            attachment: self.attachment,
            ifindex: self.capture.private_device().ifindex,
            queue: 0,
            zero_copy: self.queue.io.get_ref().zerocopy(),
            ring_capacity: config.ring_size,
            rx_frames: config.rx_frames,
            control_frames: config.control_frames,
            bulk_frames: config.bulk_frames,
            sequence: 0,
            attempted_at: None,
            succeeded_at: None,
            socket: None,
            errno: None,
            read_errors: 0,
            rings: None,
        }
    }

    pub(super) fn start(self, drivers: &mut Vec<PacketDriver>) -> HostRuntime {
        let index = drivers
            .iter()
            .position(|driver| driver.scope() == self.scope)
            .expect("start_driven returns the prepared Host scope driver");
        HostRuntime {
            capture: self.capture,
            queue: self.queue,
            watches: self.watches,
            driver: drivers.swap_remove(index),
            generated: self.generated,
            pending: [None, None],
            tx_class: 0,
            metadata_checked: Instant::now(),
        }
    }
}

pub(super) struct HostRuntime {
    pub(super) capture: HostCapture,
    pub(super) queue: Queue,
    watches: [AsyncFd<OwnedFd>; 2],
    pub(super) driver: PacketDriver,
    generated: Option<usize>,
    pub(super) pending: [Option<OutputLease>; 2],
    tx_class: usize,
    pub(super) metadata_checked: Instant,
}

impl HostRuntime {
    pub(super) fn admit(&mut self, support: &crate::ebpf::PnameSupportCell) -> anyhow::Result<()> {
        self.capture.admit(self.queue.io.get_ref().as_fd(), true)?;
        *support.write() = self.capture.pname_support();
        Ok(())
    }

    pub(super) fn native_retirement_drained(&self) -> bool {
        let port = self.queue.io.get_ref();
        let rings = port.rings();
        rings.rx_producer == rings.rx_consumer
            && rings.cq_producer == rings.cq_consumer
            && port.counters().submitted == port.counters().completed
            && port.retained_rx_count() == 0
            && port.rx_completion_count() == 0
            && self.pending.iter().all(Option::is_none)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn poll_io(
        &mut self,
        cx: &mut Context<'_>,
        packet_now: Instant,
        closing: bool,
        endpoints: &PacketEndpoints,
        staging: &mut [u8],
        pressure: &mut PressureCounters,
        qualified: &mut u64,
        unavailable: &mut bool,
    ) -> anyhow::Result<usize> {
        if !closing {
            for watch in &self.watches {
                arm_read(watch, cx)?;
            }
            self.capture.validate_current()?;
            let capture = &self.capture;
            check_metadata(
                &mut self.metadata_checked,
                packet_now,
                &capture.private_device().name,
                || capture.metadata_failures(),
            )?;
            arm_read(&self.queue.io, cx)?;
        }
        if self.generated.is_some() {
            self.driver.begin_turn(packet_now);
        }
        let work = self.service(
            cx,
            packet_now,
            closing,
            endpoints,
            staging,
            pressure,
            qualified,
            unavailable,
        );
        if self.generated.is_some() {
            self.driver.finish_turn(cx, packet_now);
        }
        work
    }

    #[allow(clippy::too_many_arguments)]
    fn service(
        &mut self,
        cx: &mut Context<'_>,
        packet_now: Instant,
        closing: bool,
        endpoints: &PacketEndpoints,
        staging: &mut [u8],
        pressure: &mut PressureCounters,
        qualified: &mut u64,
        unavailable: &mut bool,
    ) -> anyhow::Result<usize> {
        let port = self.queue.io.get_mut();
        let mut progress = port.complete(release_completed)?;
        let capture = &self.capture;
        let driver = &mut self.driver;
        let pending = &mut self.pending;
        let generated = self.generated;
        let tx_class = &mut self.tx_class;
        let (work, kick) = port.transmit_batch(|port| -> anyhow::Result<usize> {
            let mut serviced = 0;
            if !closing {
                let mut failure = None;
                let received = port.receive_segments_with(
                    BATCH,
                    HOST_METADATA_LEN,
                    |segments, metadata, _| {
                        if failure.is_some() {
                            return;
                        }
                        let earlier = Instant::now();
                        let monotonic = match monotonic_ns() {
                            Ok(now) => now,
                            Err(error) => {
                                failure = Some(error);
                                return;
                            }
                        };
                        let Ok(decoded) = capture.decode(segments, metadata, 0, monotonic) else {
                            pressure.capture_rejected = pressure.capture_rejected.saturating_add(1);
                            return;
                        };
                        let Some(remaining) = decoded.receipt.expires_ns.checked_sub(monotonic)
                        else {
                            return;
                        };
                        let Some(source_horizon) =
                            earlier.checked_add(Duration::from_nanos(remaining))
                        else {
                            return;
                        };
                        let mut l3 = [&[][..]; 18];
                        let Some(count) =
                            l3_segments_at(segments, decoded.l3_offset, decoded.l3_len, &mut l3)
                        else {
                            return;
                        };
                        let bytes = if count == 1 {
                            l3[0]
                        } else {
                            if decoded.l3_len > staging.len() {
                                return;
                            }
                            let Ok(view) = PacketView::new(&l3[..count]) else {
                                return;
                            };
                            if view
                                .copy_to(0..decoded.l3_len, &mut staging[..decoded.l3_len])
                                .is_none()
                            {
                                return;
                            }
                            &staging[..decoded.l3_len]
                        };
                        let ingress = HostIngress {
                            facts: decoded.facts,
                            source_horizon,
                        };
                        match endpoints.receive_host_with_source(
                            driver.scope(),
                            bytes,
                            honk_netstack::RxMeta::VERIFY,
                            packet_now,
                            &ingress,
                            None,
                            false,
                            |_, _, _, _| true,
                        ) {
                            Ok(report) if report.qualified_rx => {
                                qualify_packet(qualified, unavailable)
                            }
                            Ok(_) => {}
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
                                ) =>
                            {
                                pressure.endpoint_capacity =
                                    pressure.endpoint_capacity.saturating_add(1);
                                pressure.refused = true;
                            }
                            Err(error) => failure = Some(error.into()),
                        }
                    },
                );
                if let Some(error) = failure {
                    return Err(match received {
                        Ok(_) => error,
                        Err(rx) => error.context(rx).context("Host RX also failed"),
                    });
                }
                serviced += received?;
            }
            if generated.is_none() && driver.service(cx, packet_now) {
                serviced += 1;
            }
            let start_class = *tx_class;
            let mut outputs: [Option<OutputLease>; BATCH] = std::array::from_fn(|_| None);
            for offset in 0..2 {
                let index = (start_class + offset) % 2;
                let class = [TxClass::Control, TxClass::Bulk][index];
                *tx_class = (index + 1) % 2;
                let mut considered = 0;
                while considered < BATCH {
                    let capacity = if closing {
                        BATCH - considered
                    } else {
                        port.tx_packet_capacity(class)?
                    };
                    let selected = if let Some(output) = pending[index].take() {
                        outputs[0] = Some(output);
                        Poll::Ready(Some(1))
                    } else {
                        let count = (BATCH - considered).min(capacity.max(1));
                        driver.poll_outputs_class(cx, class, &mut outputs[..count])
                    };
                    let count = match selected {
                        Poll::Ready(Some(count)) => count,
                        Poll::Ready(None) if !closing && !endpoints.is_closing() => {
                            anyhow::bail!("Host packet scope ended before endpoint close")
                        }
                        _ => {
                            let Some(max_length) = generated.filter(|_| !closing) else {
                                break;
                            };
                            let mut emitted = false;
                            let result = port.transmit_generated(class, max_length, |frame| {
                                let (header, l3) = frame.split_at_mut(RETURN_HEADER);
                                let Some(owner) = driver.materialize_into(packet_now, class, l3)?
                                else {
                                    return Ok(None);
                                };
                                emitted = true;
                                let facts = owner.host_return().ok_or_else(|| {
                                    io::Error::other(
                                        "Host generated output lost original return owner",
                                    )
                                })?;
                                let length = capture
                                    .encode_return(&facts, owner.len(), l3[0] >> 4 == 6, header)
                                    .map_err(io::Error::other)?;
                                if length != RETURN_HEADER {
                                    return Err(io::Error::other(
                                        "Host return header length changed",
                                    ));
                                }
                                Ok(Some((
                                    RETURN_HEADER + owner.len(),
                                    Retained::Endpoint(owner),
                                )))
                            });
                            if emitted {
                                considered += 1;
                                serviced += 1;
                            }
                            match result {
                                Ok(true) => continue,
                                Ok(false) if emitted => continue,
                                Ok(false) => break,
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                    pressure.tx_credit = pressure.tx_credit.saturating_add(1);
                                    pressure.refused = true;
                                    break;
                                }
                                Err(error) => return Err(error.into()),
                            }
                        }
                    };
                    considered += count;
                    let mut blocked = false;
                    for output in &mut outputs[..count] {
                        let output = output.take().expect("selected Host Endpoint output");
                        if closing {
                            serviced += 1;
                            continue;
                        }
                        let length = RETURN_HEADER + output.packet().len();
                        if count == 1 && !port.tx_packet_credit(class, length) {
                            pending[index] = Some(output);
                            pressure.tx_credit = pressure.tx_credit.saturating_add(1);
                            pressure.refused = true;
                            blocked = true;
                            break;
                        }
                        let facts = output.host_return().ok_or_else(|| {
                            io::Error::other("Host CPU output lost original return owner")
                        })?;
                        port.transmit_with(
                            class,
                            length,
                            Retained::Endpoint(output.into_owner()),
                            |owner, target| {
                                let Retained::Endpoint(owner) = owner else {
                                    return Err(io::Error::other("wrong Host TX owner"));
                                };
                                let packet = owner.packet().ok_or_else(|| {
                                    io::Error::other("Host CPU writer has no packet")
                                })?;
                                let (first, rest) = target.split_first_mut().ok_or_else(|| {
                                    io::Error::other("missing Host TX reservation")
                                })?;
                                let (header, payload) =
                                    first.split_at_mut_checked(RETURN_HEADER).ok_or_else(|| {
                                        io::Error::other("short Host TX header reservation")
                                    })?;
                                let encoded = capture
                                    .encode_return(
                                        &facts,
                                        packet.len(),
                                        packet[0] >> 4 == 6,
                                        header,
                                    )
                                    .map_err(io::Error::other)?;
                                if encoded != RETURN_HEADER {
                                    return Err(io::Error::other(
                                        "Host return header length changed",
                                    ));
                                }
                                let prefix = packet.get(..payload.len()).ok_or_else(|| {
                                    io::Error::other("invalid Host TX payload reservation")
                                })?;
                                payload.copy_from_slice(prefix);
                                fill_output(rest, &[], &packet[payload.len()..])
                            },
                        )?;
                        serviced += 1;
                    }
                    if blocked {
                        break;
                    }
                }
            }
            Ok(serviced)
        });
        progress += finish_transmit(work, kick)?;
        Ok(progress)
    }

    pub(super) fn finish(mut self) -> anyhow::Result<()> {
        if let Err(error) = self.capture.close_capture() {
            std::mem::forget(self);
            return Err(error);
        }
        let Self {
            mut capture,
            queue,
            watches,
            driver,
            pending,
            ..
        } = self;
        let mut port = queue.io.into_inner();
        if !port.close().ready_for_backend_teardown() {
            std::mem::forget((capture, port, watches, driver, pending));
            anyhow::bail!("Host ledger did not reach terminal ownership; retaining source custody");
        }
        drop((driver, pending));
        port.close_socket();
        drop((port, watches));
        capture.finish_close()
    }
}

fn monotonic_ns() -> anyhow::Result<u64> {
    let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)?;
    let seconds = u64::try_from(now.tv_sec()).context("invalid Host monotonic seconds")?;
    let nanos = u64::try_from(now.tv_nsec()).context("invalid Host monotonic nanoseconds")?;
    ensure!(nanos < 1_000_000_000, "invalid Host monotonic nanoseconds");
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .context("Host monotonic clock overflow")
}
