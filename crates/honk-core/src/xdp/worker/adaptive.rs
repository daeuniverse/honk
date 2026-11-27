use super::*;
use sha2::{Digest as _, Sha256};

impl Shared {
    pub(in crate::xdp) fn polling_context(
        &self,
        worker: usize,
        context: Result<String, &'static str>,
    ) {
        let mut contexts = self.contexts.lock();
        if contexts[worker].as_ref() == Some(&context) {
            return;
        }
        contexts[worker] = Some(context);
        drop(contexts);
        for changed in &self.context_changed {
            changed.store(true, Ordering::Release);
        }
        self.wake_worker(1 - worker);
    }

    pub(in crate::xdp) fn combined_polling_context(&self) -> Result<String, &'static str> {
        let contexts = self.contexts.lock();
        let mut hash = Sha256::new();
        hash.update(b"honk-xdp-fixed-owner-v1");
        hash.update([self.workers]);
        for (worker, context) in contexts.iter().take(usize::from(self.workers)).enumerate() {
            let context = context
                .as_ref()
                .ok_or("context_unavailable")?
                .as_ref()
                .map_err(|error| *error)?;
            hash.update((worker as u64).to_le_bytes());
            hash.update(context.as_bytes());
        }
        Ok(crate::configuration::encode_digest(&hash.finalize()))
    }

    pub(in crate::xdp) fn apply_polling_context(&self, worker: usize, polling: &mut AdaptivePoll) {
        if self.context_changed[worker].swap(false, Ordering::AcqRel) {
            polling.context(self.combined_polling_context());
        }
    }
}

impl WorkerRuntime {
    pub(super) fn rebuild_polling_context(&mut self) {
        if self.context_recheck {
            self.polling_prefix = ContextDigest::platform(&self.polling_budget);
        }
        for device in &mut self.devices {
            if self.shared.is_closing() {
                return;
            }
            device.features = FeatureQuery::new(&device.info, &self.polling_budget).ok();
        }
        if self.shared.is_closing() {
            return;
        }
        let context = (|| {
            let mut context = self.polling_prefix.clone()?;
            let affinity = polling::owner_affinity()?;
            context.bytes(&affinity);
            context.number(1);
            context.number(self.devices.len() as u64);
            context.number(self.realms.len() as u64);
            context.number(FRAME_SIZE as u64);
            context.number(BATCH as u64);
            for device in &self.devices {
                let features = device.features.as_ref().ok_or("context_unavailable")?;
                context.number(device.index as u64);
                context.bytes(device.info.name.as_bytes());
                context.bytes(&device.info.mac);
                context.number(u64::from(device.info.mtu));
                context.number(device.info.xdp_features);
                context.number(u64::from(device.info.zerocopy_max_segments));
                context.bytes(features.context());
                for queue in &device.queues {
                    context.number(u64::from(queue.id));
                    context.number(u64::from(queue.io.get_ref().zerocopy()));
                    let config = queue.io.get_ref().config();
                    context.number(config.rx_frames as u64);
                    context.number(config.control_frames as u64);
                    context.number(config.bulk_frames as u64);
                    context.number(u64::from(config.ring_size));
                }
            }
            for realm in &self.realms {
                context.number(realm.device as u64);
                context.number(realm.driver.worker() as u64);
                context.number(u64::from(realm.link.mtu));
                context.bytes(&realm.link.mac);
                context.number(u64::from(realm.link.path.vlan_count));
                for value in realm.link.path.vlan_tci {
                    context.number(u64::from(value));
                }
                for value in realm.link.path.vlan_proto {
                    context.number(u64::from(value));
                }
            }
            self.polling_affinity = Some(affinity);
            Ok(context.finish())
        })();
        self.shared.polling_context(1, context);
        self.polling.context(self.shared.combined_polling_context());
        self.context_revision = self.polling.revision();
        self.context_recheck = false;
    }

    fn observe_round(&mut self) -> bool {
        let mut transmitted = 0u64;
        let mut progressed = false;
        for queue in self
            .devices
            .iter_mut()
            .flat_map(|device| &mut device.queues)
        {
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
            progressed |= counters.rx != queue.observed.rx
                || counters.completed != queue.observed.completed
                || counters.published_packets != queue.observed.published_packets
                || rings != queue.observed_rings;
            queue.observed = counters;
            queue.observed_rings = rings;
        }
        if self.qualification_unavailable {
            self.polling.counter_unavailable();
        }
        let had_clock = self.polling.last_clock.is_some();
        self.polling
            .boundary(std::mem::take(&mut self.qualified_rx), transmitted);
        if self.polling.clock_requires_policy_recheck(had_clock) {
            self.context_recheck = true;
        }
        progressed
    }

    pub(super) fn needs_service_retry(&self) -> bool {
        self.devices
            .iter()
            .flat_map(|device| &device.queues)
            .any(|queue| queue.io.get_ref().needs_service_retry())
    }

    pub(super) fn next_deadline(&self, now: Instant, retry: bool) -> Option<Instant> {
        self.realms
            .iter()
            .filter_map(|realm| realm.driver.deadline())
            .chain(retry.then(|| now + Duration::from_millis(1)))
            .min()
    }

    pub(super) fn poll_service(
        &mut self,
        cx: &mut Context<'_>,
        turns: &mut TurnBudget,
    ) -> anyhow::Result<bool> {
        if self.shared.is_closing() {
            return Ok(false);
        }
        self.polling.synchronize();
        if self.context_revision != self.polling.revision() || self.context_recheck {
            self.rebuild_polling_context();
        }
        self.shared.apply_polling_context(1, &mut self.polling);
        let had_clock = self.polling.last_clock.is_some();
        self.polling.boundary(0, 0);
        if self.polling.clock_requires_policy_recheck(had_clock) {
            self.context_recheck = true;
            return Ok(true);
        }
        let initial = self.poll(cx, None)?;
        if self.shared.is_closing() {
            return Ok(initial);
        }
        self.observe_round();
        if !self.shared.admission.load(Ordering::Acquire)
            || self.shutdown.requested()
            || self.context_recheck
        {
            self.polling.leave("closing_or_clock_change");
            return Ok(initial);
        }
        if turns.poll_due(&self.realms) {
            return Ok(initial);
        }
        let now = Instant::now();
        let pollable = self.needs_service_retry();
        let deadline = self.next_deadline(now, pollable);
        let deadline_ns = deadline
            .zip(self.polling.last_clock)
            .and_then(|(due, clock)| {
                u64::try_from(due.saturating_duration_since(now).as_nanos())
                    .ok()
                    .and_then(|left| clock.boot_ns.checked_add(left))
            });
        let Some(interval) = self.polling.begin(pollable, deadline_ns) else {
            return Ok(initial);
        };
        let mut failure = None;
        let reason = 'busy: loop {
            if self.shared.is_closing() {
                break "closing";
            }
            if let Some(reason) =
                polling_segment_stop(&self.polling, Some(&interval), &self.shutdown, deadline)
            {
                break reason;
            }
            if polling::owner_affinity().ok() != self.polling_affinity {
                self.context_recheck = true;
                break "calibration_context_mismatch";
            }
            let mut changed = None;
            for device in &mut self.devices {
                if self.shared.is_closing() {
                    break 'busy "closing";
                }
                if let Some(reason) =
                    polling_segment_stop(&self.polling, Some(&interval), &self.shutdown, deadline)
                {
                    changed = Some(reason);
                    break;
                }
                match device
                    .features
                    .as_mut()
                    .ok_or("context_unavailable")
                    .and_then(|features| features.check().map_err(|_| "offload_query_failed"))
                {
                    Ok(true) => {}
                    Ok(false) => {
                        changed = Some("calibration_context_mismatch");
                        break;
                    }
                    Err(reason) => {
                        changed = Some(reason);
                        break;
                    }
                }
            }
            if let Some(reason) = changed {
                self.context_recheck = true;
                break reason;
            }
            if self.shared.is_closing() {
                break "closing";
            }
            self.polling.enter();
            turns.charge();
            if let Err(error) = self.poll(cx, Some(&interval)) {
                failure = Some(error);
                break "device_failure";
            }
            if self.shared.is_closing() {
                break "closing";
            }
            let progressed = self.observe_round();
            if self.context_recheck {
                break "resume_or_clock_discontinuity";
            }
            if let Some(reason) = self.polling.probed(progressed) {
                break reason;
            }
            if !self.needs_service_retry() {
                break "no_pollable_work";
            }
            if turns.poll_due(&self.realms) {
                break "bounded_segment_limit";
            }
        };
        match interval.finish() {
            Ok(record) => tracing::debug!(
                worker = 1,
                reason,
                elapsed_ns = record.elapsed_ns,
                charged_ns = record.charged_ns,
                "XDP polling interval settled"
            ),
            Err(_) => self.polling.counter_unavailable(),
        }
        self.polling.leave(reason);
        failure.map_or(Ok(true), Err)
    }
}
