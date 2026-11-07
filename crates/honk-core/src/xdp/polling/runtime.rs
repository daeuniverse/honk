use super::{AdaptivePoll, clock, owner_affinity};
use crate::control::{
    ShutdownIntent,
    poll_budget::{BusyInterval, PollSettlement},
};
use crate::xdp::{Runtime, poll_deadline};
use honk_config::datapath::InterfaceRole;
use honk_xsk::{FRAME_SIZE, device::FeatureQuery};
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
use tokio::sync::futures::OwnedNotified;

pub(in crate::xdp) fn polling_segment_stop(
    polling: &AdaptivePoll,
    interval: Option<&BusyInterval>,
    shutdown: &ShutdownIntent,
    deadline: Option<Instant>,
) -> Option<&'static str> {
    let interval = interval?;
    if shutdown.requested() {
        return Some("closing");
    }
    if !polling.segment_current(interval) {
        return Some("polling_revision_changed");
    }
    if deadline.is_some_and(|due| due <= Instant::now()) {
        return Some("real_deadline_due");
    }
    match clock::boottime_ns() {
        Ok(now) if now < interval.end_ns() => None,
        Ok(_) => Some("busy_interval_limit"),
        Err(_) => Some("clock_unavailable"),
    }
}

impl Runtime {
    #[cfg(test)]
    pub(in crate::xdp) fn polling_test_snapshot(&self) -> super::testing::Snapshot {
        let polling = &self.polling;
        super::testing::Snapshot {
            mode: polling.config.mode,
            high: polling.status.high,
            low: polling.status.low,
            rx_high_windows: polling.status.rx_high_windows,
            tx_high_windows: polling.status.tx_high_windows,
            busy_entries: polling.busy_entries,
            probe_rounds: polling.busy_probe_rounds,
            qualified_rx: polling.qualified_rx_total,
            published_tx: polling.published_tx_total,
            local_revision: polling.config.revision,
            process_revision: polling.process_revision,
            reason: polling.reason,
            clock: polling.last_clock,
            clock_error: polling.clock_error,
            executable_sha256: polling
                .budget
                .as_ref()
                .and_then(|budget| budget.executable_sha256().map(str::to_owned)),
            context_sha256: polling.context_sha256.clone(),
            parameter_sha256: polling.parameter_sha256.clone(),
            queues: self
                .devices
                .iter()
                .flat_map(|device| {
                    device
                        .queues
                        .iter()
                        .map(move |queue| super::testing::Queue {
                            device: device.info.name.clone(),
                            id: queue.id,
                            counters: queue.io.get_ref().counters(),
                            rings: queue.io.get_ref().rings(),
                        })
                })
                .collect(),
            cursors: (self.rx_device, self.rx_queue, self.tx_realm, self.tx_class),
            pollable: self.has_pollable_obligation(),
            waiting: self.waiting.len(),
            pending: self.pending.len(),
        }
    }

    #[cfg(test)]
    fn polling_test_pause(&self, point: super::testing::Point) {
        if self.polling.test_control.armed(point) {
            self.polling
                .test_control
                .arrive(point, self.polling_test_snapshot());
        }
    }

    #[cfg(test)]
    fn polling_test_pending(&self, reading: bool, timer: Pin<&Option<tokio::time::Sleep>>) {
        self.polling
            .test_control
            .note_pending(super::testing::PendingWait {
                reading,
                driver_deadline: self
                    .realms
                    .iter()
                    .filter_map(|realm| realm.driver.deadline())
                    .min(),
                armed_deadline: timer.get_ref().as_ref().map(tokio::time::Sleep::deadline),
                idle_ports: self
                    .devices
                    .iter()
                    .flat_map(|device| &device.queues)
                    .all(|queue| {
                        let port = queue.io.get_ref();
                        port.counters().submitted == port.counters().completed
                            && !port.needs_service_retry()
                    }),
                pending_outputs: self
                    .realms
                    .iter()
                    .any(|realm| realm.pending.iter().any(Option::is_some)),
            });
    }

    pub(in crate::xdp) fn refresh_polling_context(&mut self) {
        let context = (|| {
            let mut context = self.polling_prefix.clone()?;
            let affinity = owner_affinity()?;
            context.bytes(&affinity);
            context.number(self.devices.len() as u64);
            context.number(self.realms.len() as u64);
            context.number(u64::from(self.core.is_some()));
            context.number(FRAME_SIZE as u64);
            context.number(crate::xdp::BATCH as u64);
            for device in &self.devices {
                let features = device.features.as_ref().ok_or("context_unavailable")?;
                context.bytes(device.info.name.as_bytes());
                context.bytes(&device.info.mac);
                context.number(u64::from(device.info.mtu));
                context.number(device.info.xdp_features);
                context.number(u64::from(device.info.zerocopy_max_segments));
                context.number(u64::from(device.capture.vlan_metadata));
                context.number(match device.role {
                    InterfaceRole::Lan => 1,
                    InterfaceRole::Wan => 2,
                });
                context.number(device.port_config.rx_frames as u64);
                context.number(device.port_config.control_frames as u64);
                context.number(device.port_config.bulk_frames as u64);
                context.number(u64::from(device.port_config.ring_size));
                context.bytes(features.context());
                context.number(device.queues.len() as u64);
                for queue in &device.queues {
                    context.number(u64::from(queue.id));
                    context.number(u64::from(queue.io.get_ref().zerocopy()));
                }
            }
            for realm in &self.realms {
                context.number(realm.device as u64);
                context.number(u64::from(realm.link.mtu));
                context.bytes(&realm.link.mac);
                context.number(u64::from(realm.link.path.vlan_count));
                for value in realm.link.path.vlan_proto {
                    context.number(u64::from(value));
                }
                for value in realm.link.path.vlan_tci {
                    context.number(u64::from(value));
                }
                context.number(u64::from(realm.generated.is_some()));
            }
            self.polling_affinity = Some(affinity);
            Ok(context.finish())
        })();
        self.polling.context(context);
    }

    pub(in crate::xdp) fn rebuild_polling_context(&mut self) {
        if self.context_recheck {
            self.polling_prefix = super::ContextDigest::platform(&self.polling_budget);
        }
        for device in &mut self.devices {
            device.features = FeatureQuery::new(&device.info, &self.polling_budget).ok();
        }
        self.refresh_polling_context();
        self.context_recheck = false;
        self.context_revision = self.polling.revision();
    }

    pub(in crate::xdp) fn observe_polling_round(&mut self) -> bool {
        let mut transmitted = 0u64;
        let mut progress = false;
        for device in &mut self.devices {
            for queue in &mut device.queues {
                let counters = queue.io.get_ref().counters();
                let rings = queue.io.get_ref().rings();
                match counters
                    .published_packets
                    .checked_sub(queue.observed.published_packets)
                    .and_then(|delta| transmitted.checked_add(delta))
                {
                    Some(value) => transmitted = value,
                    None => self.qualification_unavailable = true,
                }
                self.qualification_unavailable |= counters.publication_count_unavailable;
                progress |= counters.rx != queue.observed.rx
                    || counters.published_packets != queue.observed.published_packets
                    || counters.completed != queue.observed.completed
                    || counters.fill != queue.observed.fill
                    || rings != queue.observed_rings;
                queue.observed = counters;
                queue.observed_rings = rings;
            }
        }
        if self.qualification_unavailable {
            self.polling.counter_unavailable();
        }
        let qualified = std::mem::take(&mut self.qualified_rx);
        let had_clock = self.polling.last_clock.is_some();
        self.polling.boundary(qualified, transmitted);
        if !self.closing && self.polling.clock_requires_policy_recheck(had_clock) {
            self.policy_recheck = true;
            self.context_recheck = true;
        }
        progress
    }

    fn has_pollable_obligation(&self) -> bool {
        !self.closing
            && self.devices.iter().any(|device| {
                device
                    .queues
                    .iter()
                    .any(|queue| queue.io.get_ref().needs_service_retry())
            })
    }

    fn scan_polling_features(
        &mut self,
        interval: &BusyInterval,
        shutdown: &ShutdownIntent,
        reading: bool,
    ) -> Result<(), &'static str> {
        let deadline = self.next_deadline(Instant::now(), !reading);
        if owner_affinity().ok() != self.polling_affinity {
            return Err("calibration_context_mismatch");
        }
        #[cfg(test)]
        let mut pause_snapshot = self
            .polling
            .test_control
            .armed(super::testing::Point::FeatureQuery)
            .then(|| self.polling_test_snapshot());
        for device in &mut self.devices {
            if let Some(reason) =
                polling_segment_stop(&self.polling, Some(interval), shutdown, deadline)
            {
                return Err(reason);
            }
            #[cfg(test)]
            if let Some(snapshot) = pause_snapshot.take() {
                self.polling
                    .test_control
                    .arrive(super::testing::Point::FeatureQuery, snapshot);
            }
            match device
                .features
                .as_mut()
                .ok_or("context_unavailable")?
                .check()
            {
                Ok(true) => {}
                Ok(false) => return Err("calibration_context_mismatch"),
                Err(_error) => {
                    #[cfg(test)]
                    self.polling
                        .test_control
                        .note_query_errno(_error.raw_os_error());
                    device.features = None;
                    return Err("offload_query_failed");
                }
            }
            if let Some(reason) =
                polling_segment_stop(&self.polling, Some(interval), shutdown, deadline)
            {
                return Err(reason);
            }
        }
        Ok(())
    }

    fn log_polling_ledger(&mut self, record: &PollSettlement, reason: &'static str) {
        if !self.polling.report_ledger_due() {
            return;
        }
        let Some(budget) = &self.polling.budget else {
            return;
        };
        let state = budget.snapshot();
        tracing::debug!(reason, elapsed_ns = record.elapsed_ns, charged_ns = record.charged_ns,
            reserved_ns = record.reserved_ns, overrun_ns = record.overrun_ns,
            forfeited_grants = record.forfeited_grants, forfeited_ns = %record.forfeited_ns,
            net_ns = %record.net_ns, "XDP polling interval settled");
        tracing::debug!(desired = ?state.desired_policy, effective = ?state.effective_policy,
            staged = ?state.staged_policy, process_revision = state.process_revision, publisher_closed = state.publisher_closed,
            disabled = state.disabled_reason, net_ns = %state.net_ns, debt_ns = %state.debt_ns,
            capacity_ns = state.capacity_ns, next_refill_ns = ?state.next_refill_ns,
            active_id = ?state.active_id, active_start_ns = ?state.active_start_ns,
            active_policy_revision = ?state.active_policy_revision, reserved_ns = state.reserved_ns,
            charged_ns = %state.charged_ns, overrun_ns = %state.overrun_ns,
            forfeited_grants = state.forfeited_grants, forfeited_ns = %state.forfeited_ns,
            "XDP process polling ledger");
    }

    pub(in crate::xdp) fn poll_service(
        &mut self,
        cx: &mut Context<'_>,
        shutdown: &ShutdownIntent,
        mut timer: Pin<&mut Option<tokio::time::Sleep>>,
        reading: bool,
        notification: Pin<&mut OwnedNotified>,
    ) -> Poll<anyhow::Result<()>> {
        self.polling.poll_change(notification, cx);
        self.polling.synchronize();
        #[cfg(test)]
        self.polling
            .test_control
            .note_serviced_revision(self.polling.revision());
        if !self.closing
            && (self.polling.revision() != self.context_revision || self.context_recheck)
        {
            self.rebuild_polling_context();
        }
        let had_clock = self.polling.last_clock.is_some();
        self.polling.boundary(0, 0);
        if !self.closing && self.polling.clock_requires_policy_recheck(had_clock) {
            self.policy_recheck = true;
            self.context_recheck = true;
            self.service_scopes(cx, Instant::now());
            timer.set(None);
            return Poll::Ready(Ok(()));
        }
        let initial = self.poll_io(cx, None, shutdown, reading);
        self.observe_polling_round();
        let useful_turn = match initial {
            Poll::Ready(Err(error)) => {
                timer.set(None);
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(())) => true,
            Poll::Pending => false,
        };
        if self.closing {
            if useful_turn {
                timer.set(None);
                return Poll::Ready(Ok(()));
            }
            let now = Instant::now();
            let result =
                poll_deadline(timer.as_mut(), self.next_deadline(now, false), now, cx).map(Ok);
            #[cfg(test)]
            if result.is_pending() {
                self.polling_test_pending(false, timer.as_ref());
            }
            return result;
        }
        if shutdown.requested() || self.policy_recheck {
            timer.set(None);
            return Poll::Ready(Ok(()));
        }
        let now = Instant::now();
        let deadline = self.next_deadline(now, !reading);
        let boot = self.polling.last_clock.map(|sample| sample.boot_ns);
        let deadline_ns = match (deadline, boot) {
            (Some(due), Some(boot)) => u64::try_from(due.saturating_duration_since(now).as_nanos())
                .ok()
                .and_then(|remaining| boot.checked_add(remaining)),
            _ => None,
        };
        let pollable = self.has_pollable_obligation();
        #[cfg(test)]
        let idle_high = !pollable && self.polling.status.high;
        let interval = self.polling.begin(pollable, deadline_ns);
        #[cfg(test)]
        if idle_high {
            self.polling.test_control.note_idle_high(interval.is_some());
        }
        if let Some(interval) = interval {
            #[cfg(test)]
            let start_cursors = (self.rx_device, self.rx_queue, self.tx_realm, self.tx_class);
            #[cfg(test)]
            let start_rx = self
                .devices
                .iter()
                .flat_map(|device| &device.queues)
                .map(|queue| queue.io.get_ref().counters().rx)
                .sum();
            #[cfg(test)]
            self.polling_test_pause(super::testing::Point::Reserved);
            let mut failure = None;
            let reason = loop {
                if let Some(reason) =
                    polling_segment_stop(&self.polling, Some(&interval), shutdown, deadline)
                {
                    break reason;
                }
                if let Err(reason) = self.scan_polling_features(&interval, shutdown, reading) {
                    if matches!(
                        reason,
                        "calibration_context_mismatch"
                            | "offload_query_failed"
                            | "context_unavailable"
                    ) {
                        self.context_recheck = true;
                    }
                    break reason;
                }
                self.polling.enter();
                let result = self.poll_io(cx, Some(&interval), shutdown, reading);
                let progressed = self.observe_polling_round();
                if let Poll::Ready(Err(error)) = result {
                    failure = Some(error);
                    break "device_failure";
                }
                if self.policy_recheck {
                    break "resume_or_clock_discontinuity";
                }
                if self.round_cut_short {
                    break "bounded_segment_limit";
                }
                if let Some(reason) = self.polling.probed(progressed) {
                    break reason;
                }
                if !self.has_pollable_obligation() {
                    break "no_pollable_work";
                }
            };
            #[cfg(test)]
            let mut settlement = None;
            let reason = match interval.finish() {
                Ok(record) => {
                    #[cfg(test)]
                    {
                        settlement = Some(record);
                    }
                    self.log_polling_ledger(&record, reason);
                    reason
                }
                Err(_) => {
                    self.polling.counter_unavailable();
                    "accounting_unknown"
                }
            };
            self.polling.leave(reason);
            #[cfg(test)]
            self.polling.test_control.note_exit(super::testing::Exit {
                reason,
                probe_rounds: self.polling.busy_probe_rounds,
                published_packets: self
                    .devices
                    .iter()
                    .flat_map(|device| &device.queues)
                    .map(|queue| queue.io.get_ref().counters().published_packets)
                    .sum(),
                settlement,
                start_cursors,
                cursors: (self.rx_device, self.rx_queue, self.tx_realm, self.tx_class),
                start_rx,
                rx_packets: self
                    .devices
                    .iter()
                    .flat_map(|device| &device.queues)
                    .map(|queue| queue.io.get_ref().counters().rx)
                    .sum(),
            });
            timer.set(None);
            return Poll::Ready(failure.map_or(Ok(()), Err));
        }
        if useful_turn {
            timer.set(None);
            return Poll::Ready(Ok(()));
        }
        let now = Instant::now();
        let result =
            poll_deadline(timer.as_mut(), self.next_deadline(now, !reading), now, cx).map(Ok);
        #[cfg(test)]
        if result.is_pending() {
            self.polling_test_pending(reading, timer.as_ref());
        }
        result
    }
}
