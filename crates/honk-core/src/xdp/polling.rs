//! Optional polling stays with the capture owner; this state grants no packet authority.

pub(crate) mod clock;
pub(super) mod runtime;
#[cfg(test)]
pub(in crate::xdp) mod testing;
mod window;

use crate::control::poll_budget::{BusyInterval, ProcessPollBudget, QuotaPolicy};
use clock::{ClockObservation, SchedulingClock};
use honk_config::{
    Config,
    datapath::{BusyPollConfig, CalibrationStatus, PollMode},
};
use honk_netstack::MemoryBudget;
use sha2::{Digest as _, Sha256};
use std::pin::Pin;
use std::{
    future::Future as _,
    io::Read as _,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::Context,
};
use tokio::sync::{Notify, futures::OwnedNotified};
use window::{ObservationWindows, WindowStatus};

pub(crate) const CALIBRATION_SCHEMA: u16 = 1;
pub(crate) const COUNTING_REVISION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PollingConfig {
    pub revision: u64,
    pub mode: PollMode,
    pub busy: Option<BusyPollConfig>,
    pub publication_error: Option<&'static str>,
}

impl PollingConfig {
    fn from_config(
        config: &Config,
        revision: u64,
        publication_error: Option<&'static str>,
    ) -> Self {
        Self {
            revision,
            mode: config
                .datapath
                .as_ref()
                .map_or(PollMode::Adaptive, |value| value.effective_poll_mode()),
            busy: config
                .datapath
                .as_ref()
                .and_then(|value| value.busy_poll.clone()),
            publication_error,
        }
    }

    pub(crate) fn quota(&self) -> Result<Option<QuotaPolicy>, &'static str> {
        if self.mode == PollMode::Event {
            return Ok(None);
        }
        self.busy.as_ref().map(QuotaPolicy::from_config).transpose()
    }
}

pub(crate) struct PollingPublication {
    revision: AtomicU64,
    config: parking_lot::Mutex<PollingConfig>,
    changed: Arc<Notify>,
}

impl PollingPublication {
    pub(crate) fn new(config: &Config) -> Arc<Self> {
        Arc::new(Self {
            revision: AtomicU64::new(1),
            config: parking_lot::Mutex::new(PollingConfig::from_config(config, 1, None)),
            changed: Arc::new(Notify::new()),
        })
    }

    pub(crate) fn snapshot(&self) -> PollingConfig {
        self.config.lock().clone()
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    pub(crate) fn differs(&self, config: &Config) -> bool {
        let current = self.config.lock();
        current.mode
            != config
                .datapath
                .as_ref()
                .map_or(PollMode::Adaptive, |value| value.effective_poll_mode())
            || current.busy.as_ref()
                != config
                    .datapath
                    .as_ref()
                    .and_then(|value| value.busy_poll.as_ref())
    }

    pub(crate) fn publish(&self, config: &Config, error: Option<&'static str>) {
        let mut current = self.config.lock();
        let next = current.revision.checked_add(1);
        let revision = next.unwrap_or(u64::MAX);
        *current = PollingConfig::from_config(
            config,
            revision,
            error.or(if next.is_none() {
                Some("accounting_unknown")
            } else {
                None
            }),
        );
        self.revision.store(revision, Ordering::Release);
        self.changed.notify_one();
    }

    pub(crate) fn attachment_error(&self, error: Option<&'static str>) {
        let mut current = self.config.lock();
        current.publication_error = error;
    }

    pub(crate) fn notification(&self) -> OwnedNotified {
        Arc::clone(&self.changed).notified_owned()
    }

    pub(crate) fn poll_change(
        &self,
        mut notified: Pin<&mut OwnedNotified>,
        observed: u64,
        cx: &mut Context<'_>,
    ) -> bool {
        notified.as_mut().enable();
        let signaled = notified.as_mut().poll(cx).is_ready();
        if signaled {
            notified.set(self.notification());
            notified.as_mut().enable();
        }
        signaled || self.revision() != observed
    }
}

pub(crate) fn quota_policy(config: &Config) -> Result<Option<QuotaPolicy>, &'static str> {
    let Some(datapath) = &config.datapath else {
        return Ok(None);
    };
    if datapath.effective_poll_mode() == PollMode::Event {
        return Ok(None);
    }
    datapath
        .busy_poll
        .as_ref()
        .map(QuotaPolicy::from_config)
        .transpose()
}

pub(crate) fn parameter_digest(config: &BusyPollConfig) -> String {
    let mut hash = Sha256::new();
    hash.update(b"honk.xdp.poll-parameters.v1\0");
    hash.update(COUNTING_REVISION.to_le_bytes());
    hash.update(config.pps_enter.to_le_bytes());
    hash.update(config.pps_exit.to_le_bytes());
    hash.update(config.observation_window_us.to_le_bytes());
    hash.update(config.enter_windows.to_le_bytes());
    hash.update(config.exit_windows.to_le_bytes());
    hash.update(config.max_busy_us.to_le_bytes());
    hash.update(config.empty_rounds.to_le_bytes());
    hash.update(config.budget_window_us.to_le_bytes());
    hash.update(config.budget_us.to_le_bytes());
    crate::configuration::encode_digest(&hash.finalize())
}

#[derive(Clone)]
pub(crate) struct ContextDigest(Sha256);

impl ContextDigest {
    pub(crate) fn platform(budget: &Arc<MemoryBudget>) -> Result<Self, &'static str> {
        const MAX_CPU_INFO: usize = 1 << 20;
        let charge = budget
            .reserve(MAX_CPU_INFO + 1)
            .ok_or("context_unavailable")?;
        let file = std::fs::File::open("/proc/cpuinfo").map_err(|_| "context_unavailable")?;
        let mut bytes = Vec::with_capacity(MAX_CPU_INFO + 1);
        file.take((MAX_CPU_INFO + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "context_unavailable")?;
        if bytes.len() > MAX_CPU_INFO {
            return Err("context_unavailable");
        }
        let cpu = std::str::from_utf8(&bytes).map_err(|_| "context_unavailable")?;
        let mut result = Self(Sha256::new());
        result.bytes(b"honk.xdp.poll-context.v1\0");
        result.bytes(std::env::consts::ARCH.as_bytes());
        let mut found_model = false;
        for line in cpu.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim();
            if matches!(
                key,
                "vendor_id"
                    | "model name"
                    | "cpu family"
                    | "model"
                    | "stepping"
                    | "microcode"
                    | "CPU implementer"
                    | "CPU architecture"
                    | "CPU variant"
                    | "CPU part"
                    | "CPU revision"
            ) {
                found_model = true;
                result.bytes(key.as_bytes());
                result.bytes(value.trim().as_bytes());
            }
        }
        if !found_model {
            return Err("context_unavailable");
        }
        let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
        // SAFETY: uname initializes the complete supplied utsname on success.
        if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
            return Err("context_unavailable");
        }
        let uts = unsafe { uts.assume_init() };
        for field in [&uts.sysname, &uts.release, &uts.version, &uts.machine] {
            let length = field
                .iter()
                .position(|&value| value == 0)
                .unwrap_or(field.len());
            for &value in &field[..length] {
                result.0.update([value as u8]);
            }
            result.0.update([0]);
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| "context_unavailable")?;
        result.number(runtime.metrics().num_workers() as u64);
        result.number(u64::from(COUNTING_REVISION));
        drop(bytes);
        drop(charge);
        Ok(result)
    }

    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        self.0.update((bytes.len() as u64).to_le_bytes());
        self.0.update(bytes);
    }

    pub(crate) fn number(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }

    pub(crate) fn finish(self) -> String {
        crate::configuration::encode_digest(&self.0.finalize())
    }
}

pub(crate) fn owner_affinity() -> Result<[u8; libc::CPU_SETSIZE as usize / 8], &'static str> {
    let mut set = std::mem::MaybeUninit::<libc::cpu_set_t>::zeroed();
    // SAFETY: the initialized fixed-size cpu_set_t is the exact sched_getaffinity output.
    if unsafe {
        libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), set.as_mut_ptr())
    } != 0
    {
        return Err("context_unavailable");
    }
    let set = unsafe { set.assume_init() };
    let mut bytes = [0; libc::CPU_SETSIZE as usize / 8];
    for cpu in 0..libc::CPU_SETSIZE as usize {
        // SAFETY: cpu is within the fixed cpu_set_t extent.
        if unsafe { libc::CPU_ISSET(cpu, &set) } {
            bytes[cpu / 8] |= 1 << (cpu % 8);
        }
    }
    Ok(bytes)
}

pub(crate) struct AdaptivePoll {
    publication: Arc<PollingPublication>,
    pub(crate) config: PollingConfig,
    pub(crate) budget: Option<ProcessPollBudget>,
    clock: SchedulingClock,
    windows: ObservationWindows,
    status: WindowStatus,
    process_revision: u64,
    pub(crate) last_clock: Option<ClockObservation>,
    context_sha256: Option<String>,
    context_error: Option<&'static str>,
    parameter_sha256: Option<String>,
    quota: Result<Option<QuotaPolicy>, &'static str>,
    counter_failed: bool,
    pub(crate) reason: &'static str,
    busy: bool,
    empty_rounds: u16,
    metadata_dirty: bool,
    busy_entries: u64,
    busy_probe_rounds: u64,
    last_trace_ns: Option<u64>,
    last_ledger_report_ns: Option<u64>,
    clock_error: Option<&'static str>,
    active_local_revision: Option<u64>,
    qualified_rx_total: u64,
    published_tx_total: u64,
    #[cfg(test)]
    test_control: Arc<testing::Control>,
}

impl AdaptivePoll {
    pub(crate) fn new(
        publication: Arc<PollingPublication>,
        budget: Option<ProcessPollBudget>,
    ) -> Self {
        let config = publication.snapshot();
        let parameter_sha256 = config.busy.as_ref().map(parameter_digest);
        let process_revision = budget.as_ref().map_or(0, ProcessPollBudget::revision);
        let quota = config.quota();
        Self {
            publication,
            config,
            budget,
            clock: SchedulingClock::new(),
            windows: ObservationWindows::new(),
            status: WindowStatus::default(),
            process_revision,
            last_clock: None,
            context_sha256: None,
            context_error: Some("context_unavailable"),
            parameter_sha256,
            quota,
            counter_failed: false,
            reason: "pps_dwell_incomplete",
            busy: false,
            empty_rounds: 0,
            metadata_dirty: true,
            busy_entries: 0,
            busy_probe_rounds: 0,
            last_trace_ns: None,
            last_ledger_report_ns: None,
            clock_error: None,
            active_local_revision: None,
            qualified_rx_total: 0,
            published_tx_total: 0,
            #[cfg(test)]
            test_control: Arc::new(testing::Control::default()),
        }
    }

    pub(crate) fn revision(&self) -> u64 {
        self.config.revision
    }

    #[cfg(test)]
    pub(crate) fn notification(&self) -> OwnedNotified {
        self.publication.notification()
    }

    #[cfg(test)]
    pub(in crate::xdp) fn test_control(&self) -> Arc<testing::Control> {
        Arc::clone(&self.test_control)
    }

    pub(crate) fn poll_change(
        &self,
        notification: Pin<&mut OwnedNotified>,
        cx: &mut Context<'_>,
    ) -> bool {
        self.publication
            .poll_change(notification, self.config.revision, cx)
    }

    pub(crate) fn local_current(&self) -> bool {
        self.config.revision != u64::MAX && self.publication.revision() == self.config.revision
    }

    fn reset(&mut self) {
        self.windows.reset();
        self.status = WindowStatus::default();
        self.empty_rounds = 0;
    }

    pub(crate) fn synchronize(&mut self) {
        if self.publication.revision() != self.config.revision {
            self.config = self.publication.snapshot();
            self.parameter_sha256 = self.config.busy.as_ref().map(parameter_digest);
            self.quota = self.config.quota();
            self.metadata_dirty = true;
            self.reset();
        }
        let revision = self.budget.as_ref().map_or(0, ProcessPollBudget::revision);
        if revision != self.process_revision {
            self.process_revision = revision;
            self.reset();
        }
    }

    pub(crate) fn context(&mut self, value: Result<String, &'static str>) {
        match value {
            Ok(value) => {
                if self.context_sha256.as_ref() != Some(&value) || self.context_error.is_some() {
                    self.context_sha256 = Some(value);
                    self.context_error = None;
                    self.metadata_dirty = true;
                    self.reset();
                }
            }
            Err(reason) => {
                self.context_sha256 = None;
                self.context_error = Some(reason);
                self.metadata_dirty = true;
                self.reset();
            }
        }
    }

    pub(crate) fn boundary(&mut self, qualified_rx: u64, published_tx: u64) -> bool {
        self.synchronize();
        let totals = self
            .qualified_rx_total
            .checked_add(qualified_rx)
            .zip(self.published_tx_total.checked_add(published_tx));
        if let Some((rx, tx)) = totals {
            self.qualified_rx_total = rx;
            self.published_tx_total = tx;
        } else {
            self.counter_unavailable();
        }
        let gap = self
            .config
            .busy
            .as_ref()
            .and_then(|config| u64::from(config.observation_window_us).checked_mul(1_000));
        #[cfg(test)]
        {
            self.clock.fault = self.test_control.clock_fault();
        }
        let observation = self.clock.sample(gap);
        let continuous = self.accept_clock_observation(
            observation,
            if self.counter_failed { 0 } else { qualified_rx },
            if self.counter_failed { 0 } else { published_tx },
        );
        if self.counter_failed {
            self.reset();
            return false;
        }
        continuous
    }

    fn accept_clock_observation(
        &mut self,
        observation: Result<ClockObservation, &'static str>,
        qualified_rx: u64,
        published_tx: u64,
    ) -> bool {
        match observation {
            Ok(sample) => {
                #[cfg(test)]
                if sample.discontinuity || sample.offset_changed {
                    self.test_control.note_clock(
                        sample.discontinuity && !sample.offset_changed,
                        sample.offset_changed,
                        false,
                    );
                }
                self.clock_error = None;
                let continuous = sample.continuous;
                if !continuous {
                    self.reset();
                }
                self.last_clock = Some(sample);
                if let Some(config) = &self.config.busy {
                    match self
                        .windows
                        .observe(sample.boot_ns, qualified_rx, published_tx, config)
                    {
                        Ok(status) => self.status = status,
                        Err(reason) => {
                            self.reset();
                            self.transition(false, reason);
                            return false;
                        }
                    }
                }
                if sample.discontinuity {
                    self.transition(false, "resume_or_clock_discontinuity");
                }
                continuous
            }
            Err(reason) => {
                #[cfg(test)]
                if self.clock_error != Some(reason) {
                    self.test_control.note_clock(false, false, true);
                }
                self.clock_error = Some(reason);
                self.last_clock = None;
                self.reset();
                self.transition(false, reason);
                false
            }
        }
    }

    pub(in crate::xdp) fn clock_requires_policy_recheck(&self, previously_available: bool) -> bool {
        previously_available && self.last_clock.is_none_or(|sample| sample.offset_changed)
    }

    fn eligible(&self, pollable: bool) -> Result<QuotaPolicy, &'static str> {
        if self.config.mode == PollMode::Event {
            return Err("explicit_event");
        }
        if !self.local_current() {
            return Err("pps_dwell_incomplete");
        }
        if self.counter_failed {
            return Err("accounting_unknown");
        }
        if let Some(reason) = self.clock_error {
            return Err(reason);
        }
        if let Some(reason) = self.config.publication_error
            && reason != "process_budget_policy_mismatch"
        {
            return Err(reason);
        }
        let config = self.config.busy.as_ref().ok_or("busy_parameters_missing")?;
        let budget = self.budget.as_ref().ok_or("unproven_process_budget")?;
        if budget.publisher_closed() {
            return Err("publisher_closed");
        }
        let quota = self.quota?.ok_or("busy_parameters_missing")?;
        if budget.revision() != self.process_revision || !budget.policy_matches(quota) {
            return Err("process_budget_policy_mismatch");
        }
        let executable = budget
            .executable_sha256()
            .ok_or("executable_identity_unavailable")?;
        if let Some(reason) = self.context_error {
            return Err(reason);
        }
        let context = self
            .context_sha256
            .as_deref()
            .ok_or("context_unavailable")?;
        let calibration = config.calibration.as_ref().ok_or("calibration_missing")?;
        if calibration.schema != CALIBRATION_SCHEMA {
            return Err("calibration_schema_mismatch");
        }
        if calibration.counting_revision != COUNTING_REVISION {
            return Err("calibration_counting_mismatch");
        }
        if calibration.executable_sha256 != executable {
            return Err("calibration_executable_mismatch");
        }
        if calibration.context_sha256 != context {
            return Err("calibration_context_mismatch");
        }
        if Some(calibration.parameter_sha256.as_str()) != self.parameter_sha256.as_deref() {
            return Err("calibration_parameters_mismatch");
        }
        if calibration.status == CalibrationStatus::Candidate && !budget.calibration_experiment() {
            return Err("calibration_candidate_not_enabled");
        }
        if self.last_clock.is_none_or(|sample| !sample.continuous) {
            return Err("pps_dwell_incomplete");
        }
        if !self.status.high {
            return Err("pps_dwell_incomplete");
        }
        if !pollable {
            return Err("no_pollable_work");
        }
        Ok(quota)
    }

    pub(crate) fn begin(
        &mut self,
        pollable: bool,
        deadline_ns: Option<u64>,
    ) -> Option<BusyInterval> {
        let local_revision = self.config.revision;
        let quota = match self.eligible(pollable) {
            Ok(value) => value,
            Err(reason) => {
                self.transition(false, reason);
                return None;
            }
        };
        let config = self.config.busy.as_ref().expect("eligible parameters");
        let max_busy_ns = u64::from(config.max_busy_us).checked_mul(1_000)?;
        let interval = self
            .budget
            .as_ref()
            .expect("eligible process handle")
            .try_reserve(quota, self.process_revision, max_busy_ns, deadline_ns);
        match interval {
            Ok(interval) => {
                self.active_local_revision = Some(local_revision);
                if !self.segment_current(&interval) {
                    let _ = interval.finish();
                    self.active_local_revision = None;
                    return None;
                }
                self.empty_rounds = 0;
                Some(interval)
            }
            Err(reason) => {
                self.transition(false, reason);
                None
            }
        }
    }

    pub(crate) fn segment_current(&self, interval: &BusyInterval) -> bool {
        !self.counter_failed
            && self.clock_error.is_none()
            && self.active_local_revision == Some(self.config.revision)
            && self.local_current()
            && self.budget.as_ref().is_some_and(|budget| {
                !budget.publisher_closed()
                    && budget.revision() == interval.process_revision()
                    && budget.revision() == self.process_revision
            })
    }

    pub(crate) fn probed(&mut self, device_progress: bool) -> Option<&'static str> {
        let Some(rounds) = self.busy_probe_rounds.checked_add(1) else {
            self.counter_unavailable();
            return Some("accounting_unknown");
        };
        self.busy_probe_rounds = rounds;
        if device_progress {
            self.empty_rounds = 0;
        } else {
            self.empty_rounds = self.empty_rounds.saturating_add(1);
        }
        if self.status.low {
            return Some("pps_low_dwell");
        }
        self.config.busy.as_ref().and_then(|config| {
            (self.empty_rounds >= config.empty_rounds).then_some("empty_round_limit")
        })
    }

    pub(crate) fn enter(&mut self) {
        if !self.busy {
            let Some(entries) = self.busy_entries.checked_add(1) else {
                self.counter_unavailable();
                return;
            };
            self.busy_entries = entries;
        }
        self.transition(true, "qualified_busy");
    }

    pub(crate) fn leave(&mut self, reason: &'static str) {
        self.active_local_revision = None;
        self.transition(false, reason);
    }

    pub(crate) fn report_ledger_due(&mut self) -> bool {
        if !tracing::enabled!(tracing::Level::DEBUG) {
            return false;
        }
        let Some(now) = self.last_clock.map(|sample| sample.boot_ns) else {
            return false;
        };
        if self
            .last_ledger_report_ns
            .is_some_and(|previous| now.saturating_sub(previous) < 1_000_000_000)
        {
            return false;
        }
        self.last_ledger_report_ns = Some(now);
        true
    }

    pub(crate) fn counter_unavailable(&mut self) {
        self.counter_failed = true;
        self.reset();
        self.transition(false, "accounting_unknown");
    }

    fn transition(&mut self, busy: bool, reason: &'static str) {
        let changed = self.busy != busy || self.reason != reason;
        self.busy = busy;
        self.reason = reason;
        let trace_due = self.last_clock.map_or(changed, |sample| {
            self.last_trace_ns
                .is_none_or(|previous| sample.boot_ns.saturating_sub(previous) >= 1_000_000_000)
        });
        if trace_due {
            self.last_trace_ns = self.last_clock.map(|sample| sample.boot_ns);
            tracing::debug!(configured = ?self.config.mode, actual = if busy { "busy" } else { "event" }, reason,
                busy_entries = self.busy_entries, busy_probe_rounds = self.busy_probe_rounds,
                qualified_rx_total = self.qualified_rx_total, published_tx_total = self.published_tx_total,
                observed_boottime_ns = ?self.last_clock.map(|sample| sample.boot_ns),
                local_revision = self.config.revision, process_revision = self.process_revision,
                rx_high_windows = self.status.rx_high_windows, tx_high_windows = self.status.tx_high_windows,
                low_windows = self.status.low_windows, clock = ?self.last_clock, "XDP polling state");
        }
        if self.metadata_dirty {
            self.metadata_dirty = false;
            let eligibility_reason = self.eligible(true).err().unwrap_or(reason);
            tracing::info!(schema = CALIBRATION_SCHEMA, counting_revision = COUNTING_REVISION,
                configured = ?self.config.mode, actual = if busy { "busy" } else { "event" }, reason,
                eligibility_reason, qualification_available = !self.counter_failed,
                busy_entries = self.busy_entries, busy_probe_rounds = self.busy_probe_rounds,
                qualified_rx_total = self.qualified_rx_total, published_tx_total = self.published_tx_total,
                observed_boottime_ns = ?self.last_clock.map(|sample| sample.boot_ns),
                executable_sha256 = self.budget.as_ref().and_then(ProcessPollBudget::executable_sha256),
                executable_identity_reason = self.budget.as_ref().map_or(Some("unproven_process_budget"), |budget| budget.executable_sha256().is_none().then_some("executable_identity_unavailable")),
                context_identity_reason = self.context_error,
                parameter_identity_reason = self.config.busy.is_none().then_some("busy_parameters_missing"),
                context_sha256 = self.context_sha256.as_deref(), parameter_sha256 = self.parameter_sha256.as_deref(),
                parameters = ?self.config.busy, clock = ?self.last_clock,
                monotonic_resolution_ns = ?self.last_clock.map(|sample| sample.monotonic_resolution_ns),
                boottime_resolution_ns = ?self.last_clock.map(|sample| sample.boottime_resolution_ns),
                clock_read_duration_ns = ?self.last_clock.map(|sample| sample.read_duration_ns),
                raw_offset_low_ns = ?self.last_clock.map(|sample| sample.raw_offset_low_ns),
                raw_offset_high_ns = ?self.last_clock.map(|sample| sample.raw_offset_high_ns),
                baseline_offset_low_ns = ?self.last_clock.map(|sample| sample.baseline_offset_low_ns),
                baseline_offset_high_ns = ?self.last_clock.map(|sample| sample.baseline_offset_high_ns),
                "XDP polling calibration identity");
        }
    }
}

#[cfg(test)]
mod tests;
