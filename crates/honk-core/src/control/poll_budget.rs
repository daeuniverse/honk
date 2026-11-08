//! Process-owned optional polling time. No packet, DMA or publication authority lives here.

use std::fs::File;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use boring::sha::Sha256;
use honk_config::datapath::BusyPollConfig;
use parking_lot::Mutex;

use crate::xdp::polling::clock::boottime_ns;

const UNKNOWN: &str = "accounting_unknown";
const MISMATCH: &str = "process_budget_policy_mismatch";
static PROCESS: OnceLock<Arc<Shared>> = OnceLock::new();

/// A participant in the one process polling allowance; cloning never grants time.
#[derive(Clone, Debug)]
pub struct ProcessPollBudget(Arc<Shared>);

/// The sole process policy publisher. Dropping it permanently closes Busy admission.
#[derive(Debug)]
pub struct PollBudgetPublisher(ProcessPollBudget);

/// Startup ownership, retained across control-plane runtime replacements.
#[derive(Debug)]
pub enum PollBudgetBinding {
    Publisher(PollBudgetPublisher),
    Participant(ProcessPollBudget),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QuotaPolicy {
    pub(crate) window_ns: u64,
    pub(crate) budget_ns: u64,
}

impl QuotaPolicy {
    pub(crate) fn from_config(config: &BusyPollConfig) -> Result<Self, &'static str> {
        config.validate().map_err(|_| "busy_parameters_invalid")?;
        Ok(Self {
            window_ns: u64::from(config.budget_window_us)
                .checked_mul(1_000)
                .ok_or(UNKNOWN)?,
            budget_ns: u64::from(config.budget_us)
                .checked_mul(1_000)
                .ok_or(UNKNOWN)?,
        })
    }

    fn valid(self) -> bool {
        self.budget_ns > 0 && self.budget_ns < self.window_ns
    }
}

#[derive(Debug)]
struct Shared {
    ledger: Mutex<Ledger>,
    revision: AtomicU64,
    publisher_closed: AtomicBool,
    calibration_experiment: bool,
    executable_sha256: Option<String>,
    #[cfg(test)]
    test_clock: Option<AtomicU64>,
    #[cfg(test)]
    test_clock_failed: AtomicBool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Active {
    id: u64,
    start_ns: u64,
    reserved_ns: u64,
    policy_revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ledger {
    desired: Option<QuotaPolicy>,
    effective: Option<QuotaPolicy>,
    staged: Option<QuotaPolicy>,
    net_ns: i128,
    ceiling_ns: u64,
    next_refill_ns: Option<u64>,
    last_ns: Option<u64>,
    policy_revision: u64,
    reservation_revision: u64,
    active: Option<Active>,
    disabled: Option<&'static str>,
    charged_ns: u128,
    overrun_ns: u128,
    forfeited_grants: u64,
    forfeited_ns: u128,
}

/// A bounded, allocation-free view; reading it neither earns nor spends credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PollBudgetSnapshot {
    pub(crate) desired_policy: Option<QuotaPolicy>,
    pub(crate) effective_policy: Option<QuotaPolicy>,
    pub(crate) staged_policy: Option<QuotaPolicy>,
    pub(crate) process_revision: u64,
    pub(crate) publisher_closed: bool,
    pub(crate) disabled_reason: Option<&'static str>,
    pub(crate) net_ns: i128,
    pub(crate) debt_ns: u128,
    pub(crate) capacity_ns: u64,
    pub(crate) next_refill_ns: Option<u64>,
    pub(crate) active_id: Option<u64>,
    pub(crate) active_start_ns: Option<u64>,
    pub(crate) active_policy_revision: Option<u64>,
    pub(crate) reserved_ns: u64,
    pub(crate) charged_ns: u128,
    pub(crate) overrun_ns: u128,
    pub(crate) forfeited_grants: u64,
    pub(crate) forfeited_ns: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PollSettlement {
    pub(crate) elapsed_ns: u64,
    pub(crate) charged_ns: u64,
    pub(crate) reserved_ns: u64,
    pub(crate) overrun_ns: u64,
    pub(crate) forfeited_grants: u64,
    pub(crate) forfeited_ns: u128,
    pub(crate) net_ns: i128,
}

/// Must end within one synchronous owner turn, before any await or Pending return.
#[derive(Debug)]
pub(crate) struct BusyInterval {
    budget: ProcessPollBudget,
    active: Active,
    end_ns: u64,
    settled: bool,
}

impl ProcessPollBudget {
    /// Initialize exactly once, including after all callers and the publisher drop.
    /// Missing executable/clock identity disables optional polling, not Event I/O.
    pub fn initialize_process(calibration_experiment: bool) -> io::Result<PollBudgetPublisher> {
        initialize_slot(&PROCESS, calibration_experiment)
    }

    #[cfg(test)]
    pub(crate) fn test_publisher(calibration_experiment: bool) -> PollBudgetPublisher {
        let mut shared = Shared::new(calibration_experiment, executable_sha256().ok(), Ok(0));
        shared.test_clock = Some(AtomicU64::new(0));
        PollBudgetPublisher(Self(Arc::new(shared)))
    }

    #[cfg(test)]
    pub(crate) fn set_test_time(&self, now_ns: u64) {
        self.0
            .test_clock
            .as_ref()
            .expect("isolated test clock")
            .store(now_ns, Ordering::Relaxed);
    }

    pub(crate) fn revision(&self) -> u64 {
        self.0.revision.load(Ordering::Acquire)
    }

    pub(crate) fn publisher_closed(&self) -> bool {
        self.0.publisher_closed.load(Ordering::Acquire)
    }

    pub(crate) fn calibration_experiment(&self) -> bool {
        self.0.calibration_experiment
    }

    pub(crate) fn executable_sha256(&self) -> Option<&str> {
        self.0.executable_sha256.as_deref()
    }

    pub(crate) fn policy_matches(&self, policy: QuotaPolicy) -> bool {
        self.0.ledger.lock().desired == Some(policy)
    }

    pub(crate) fn snapshot(&self) -> PollBudgetSnapshot {
        let ledger = self.0.ledger.lock();
        PollBudgetSnapshot {
            desired_policy: ledger.desired,
            effective_policy: ledger.effective,
            staged_policy: ledger.staged,
            process_revision: self.revision(),
            publisher_closed: self.publisher_closed(),
            disabled_reason: ledger.disabled,
            net_ns: ledger.net_ns,
            debt_ns: if ledger.net_ns < 0 {
                ledger.net_ns.unsigned_abs()
            } else {
                0
            },
            capacity_ns: ledger.ceiling_ns,
            next_refill_ns: ledger.next_refill_ns,
            active_id: ledger.active.map(|active| active.id),
            active_start_ns: ledger.active.map(|active| active.start_ns),
            active_policy_revision: ledger.active.map(|active| active.policy_revision),
            reserved_ns: ledger.active.map_or(0, |active| active.reserved_ns),
            charged_ns: ledger.charged_ns,
            overrun_ns: ledger.overrun_ns,
            forfeited_grants: ledger.forfeited_grants,
            forfeited_ns: ledger.forfeited_ns,
        }
    }

    pub(crate) fn try_reserve(
        &self,
        policy: QuotaPolicy,
        expected_process_revision: u64,
        max_busy_ns: u64,
        deadline_ns: Option<u64>,
    ) -> Result<BusyInterval, &'static str> {
        let mut ledger = self.0.ledger.lock();
        self.0.check_open(&ledger)?;
        if ledger.desired != Some(policy) {
            return Err(MISMATCH);
        }
        if ledger.policy_revision != expected_process_revision {
            return Err("process_budget_revision_changed");
        }
        if ledger.active.is_some() {
            return Err("busy_interval_outstanding");
        }
        let mut next = *ledger;
        let now = self.0.read_time(&mut ledger)?;
        if next
            .observe_time(now)
            .and_then(|()| next.advance_to(now, false))
            .is_err()
        {
            return self.0.disable(&mut ledger);
        }
        // Even a denied reservation preserves time earned on the existing schedule.
        *ledger = next;
        if next.net_ns <= 0 {
            return Err("quota_exhausted");
        }
        let Some(frontier) = next.next_refill_ns else {
            return self.0.disable(&mut ledger);
        };
        let end_limit = deadline_ns.map_or(frontier, |deadline| deadline.min(frontier));
        let Some(room) = end_limit.checked_sub(now) else {
            return Err("deadline_due");
        };
        let Ok(credit_ns) = u64::try_from(next.net_ns) else {
            return self.0.disable(&mut ledger);
        };
        let reserved_ns = credit_ns.min(max_busy_ns).min(room);
        if reserved_ns == 0 {
            return Err("deadline_due");
        }
        let Some(id) = next.reservation_revision.checked_add(1) else {
            return self.0.disable(&mut ledger);
        };
        let Some(end_ns) = now.checked_add(reserved_ns) else {
            return self.0.disable(&mut ledger);
        };
        let Some(net_ns) = next.net_ns.checked_sub(i128::from(reserved_ns)) else {
            return self.0.disable(&mut ledger);
        };
        let active = Active {
            id,
            start_ns: now,
            reserved_ns,
            policy_revision: next.policy_revision,
        };
        next.reservation_revision = id;
        next.net_ns = net_ns;
        next.active = Some(active);
        *ledger = next;
        Ok(BusyInterval {
            budget: self.clone(),
            active,
            end_ns,
            settled: false,
        })
    }
}

impl PollBudgetPublisher {
    pub fn participant_handle(&self) -> ProcessPollBudget {
        self.0.clone()
    }
}

impl Drop for PollBudgetPublisher {
    fn drop(&mut self) {
        self.0.0.publisher_closed.store(true, Ordering::Release);
    }
}

impl PollBudgetBinding {
    pub fn participant_handle(&self) -> ProcessPollBudget {
        self.handle().clone()
    }

    fn handle(&self) -> &ProcessPollBudget {
        match self {
            Self::Publisher(publisher) => &publisher.0,
            Self::Participant(participant) => participant,
        }
    }

    pub(crate) fn prepare_policy(&self, policy: Option<QuotaPolicy>) -> Result<u64, &'static str> {
        if policy.is_some_and(|policy| !policy.valid()) {
            return Err("busy_parameters_invalid");
        }
        let handle = self.handle();
        let ledger = handle.0.ledger.lock();
        if matches!(self, Self::Participant(_)) && policy.is_some() && ledger.desired != policy {
            return Err(MISMATCH);
        }
        Ok(handle.revision())
    }

    pub(crate) fn publish_policy(&self, policy: Option<QuotaPolicy>) -> Result<u64, &'static str> {
        if matches!(self, Self::Participant(_)) || policy.is_none() {
            // Independent planes can lose prepare/commit races: the caller commits Event.
            return self.prepare_policy(policy);
        }
        let policy = policy.ok_or("busy_parameters_invalid")?;
        if !policy.valid() {
            return Err("busy_parameters_invalid");
        }
        let handle = self.handle();
        let mut ledger = handle.0.ledger.lock();
        handle.0.check_open(&ledger)?;
        let now = handle.0.read_time(&mut ledger)?;
        let mut next = *ledger;
        if next.publish(policy, now).is_err() {
            return handle.0.disable(&mut ledger);
        }
        *ledger = next;
        handle
            .0
            .revision
            .store(next.policy_revision, Ordering::Release);
        Ok(next.policy_revision)
    }
}

impl BusyInterval {
    pub(crate) fn end_ns(&self) -> u64 {
        self.end_ns
    }

    pub(crate) fn process_revision(&self) -> u64 {
        self.active.policy_revision
    }

    pub(crate) fn finish(mut self) -> Result<PollSettlement, &'static str> {
        self.settled = true;
        self.budget.0.settle(self.active, false)
    }
}

impl Drop for BusyInterval {
    fn drop(&mut self) {
        if !self.settled {
            self.settled = true;
            let _ = self.budget.0.settle(self.active, true);
        }
    }
}

fn initialize_slot(
    slot: &OnceLock<Arc<Shared>>,
    calibration_experiment: bool,
) -> io::Result<PollBudgetPublisher> {
    let mut initialized = false;
    let shared = slot.get_or_init(|| {
        initialized = true;
        Arc::new(Shared::new(
            calibration_experiment,
            executable_sha256().ok(),
            boottime_ns(),
        ))
    });
    if !initialized {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "process polling budget already initialized",
        ));
    }
    Ok(PollBudgetPublisher(ProcessPollBudget(Arc::clone(shared))))
}

fn executable_sha256() -> io::Result<String> {
    let mut file = File::open("/proc/self/exe")?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    loop {
        let count = match file.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(crate::configuration::encode_digest(&hash.finish()))
}

impl Shared {
    fn new(experiment: bool, executable: Option<String>, now: io::Result<u64>) -> Self {
        let disabled = if now.is_err() {
            Some("clock_unavailable")
        } else if executable.is_none() {
            Some("executable_identity_unavailable")
        } else {
            None
        };
        Self {
            ledger: Mutex::new(Ledger {
                desired: None,
                effective: None,
                staged: None,
                net_ns: 0,
                ceiling_ns: 0,
                next_refill_ns: None,
                last_ns: now.ok(),
                policy_revision: 0,
                reservation_revision: 0,
                active: None,
                disabled,
                charged_ns: 0,
                overrun_ns: 0,
                forfeited_grants: 0,
                forfeited_ns: 0,
            }),
            revision: AtomicU64::new(0),
            publisher_closed: AtomicBool::new(false),
            calibration_experiment: experiment,
            executable_sha256: executable,
            #[cfg(test)]
            test_clock: None,
            #[cfg(test)]
            test_clock_failed: AtomicBool::new(false),
        }
    }

    fn check_open(&self, ledger: &Ledger) -> Result<(), &'static str> {
        if self.publisher_closed.load(Ordering::Acquire) {
            Err("publisher_closed")
        } else if let Some(reason) = ledger.disabled {
            Err(reason)
        } else {
            Ok(())
        }
    }

    fn read_time(&self, ledger: &mut Ledger) -> Result<u64, &'static str> {
        #[cfg(test)]
        if let Some(clock) = &self.test_clock {
            return if self.test_clock_failed.load(Ordering::Relaxed) {
                self.disable(ledger)
            } else {
                Ok(clock.load(Ordering::Relaxed))
            };
        }
        boottime_ns().or_else(|_| self.disable(ledger))
    }

    fn disable<T>(&self, ledger: &mut Ledger) -> Result<T, &'static str> {
        ledger.disabled = Some(UNKNOWN);
        // MAX is never an admitted revision; it fences even an already-running interval.
        self.revision.store(u64::MAX, Ordering::Release);
        Err(UNKNOWN)
    }

    fn settle(&self, active: Active, cancelled: bool) -> Result<PollSettlement, &'static str> {
        let mut ledger = self.ledger.lock();
        if ledger.disabled == Some(UNKNOWN) || ledger.active != Some(active) {
            return self.disable(&mut ledger);
        }
        let now = self.read_time(&mut ledger)?;
        let mut next = *ledger;
        match next.settle(active, now, cancelled) {
            Ok(record) => {
                *ledger = next;
                Ok(record)
            }
            Err(_) => self.disable(&mut ledger),
        }
    }
}

impl Ledger {
    fn observe_time(&mut self, now: u64) -> Result<(), &'static str> {
        if self.last_ns.is_some_and(|last| now < last) {
            return Err(UNKNOWN);
        }
        self.last_ns = Some(now);
        Ok(())
    }

    fn publish(&mut self, policy: QuotaPolicy, now: u64) -> Result<(), &'static str> {
        self.observe_time(now)?;
        if self.active.is_none() {
            self.advance_to(now, false)?;
        }
        if self.effective.is_none() {
            self.effective = Some(policy);
            self.ceiling_ns = policy.budget_ns;
            self.next_refill_ns = Some(now.checked_add(policy.window_ns).ok_or(UNKNOWN)?);
        } else {
            self.ceiling_ns = self.ceiling_ns.min(policy.budget_ns);
            let held = self.active.map_or(0, |active| active.reserved_ns);
            let cap = i128::from(self.ceiling_ns)
                .checked_sub(i128::from(held))
                .ok_or(UNKNOWN)?;
            self.net_ns = self.net_ns.min(cap);
            self.staged = Some(policy);
        }
        if self.desired != Some(policy) {
            let revision = self.policy_revision.checked_add(1).ok_or(UNKNOWN)?;
            if revision == u64::MAX {
                return Err(UNKNOWN);
            }
            self.policy_revision = revision;
            self.desired = Some(policy);
        }
        Ok(())
    }

    fn grant(&mut self, count: u64, grant_ns: u64, forfeit: bool) -> Result<(), &'static str> {
        let amount = u128::from(count)
            .checked_mul(u128::from(grant_ns))
            .ok_or(UNKNOWN)?;
        if forfeit {
            self.forfeited_grants = self.forfeited_grants.checked_add(count).ok_or(UNKNOWN)?;
            self.forfeited_ns = self.forfeited_ns.checked_add(amount).ok_or(UNKNOWN)?;
        } else {
            self.net_ns = self
                .net_ns
                .checked_add(i128::try_from(amount).map_err(|_| UNKNOWN)?)
                .ok_or(UNKNOWN)?
                .min(i128::from(self.ceiling_ns));
        }
        Ok(())
    }

    fn advance_to(&mut self, now: u64, forfeit: bool) -> Result<(), &'static str> {
        let Some(mut frontier) = self.next_refill_ns else {
            return Ok(());
        };
        let mut policy = self.effective.ok_or(UNKNOWN)?;
        if frontier > now {
            return Ok(());
        }
        if let Some(staged) = self.staged {
            self.grant(1, policy.budget_ns.min(self.ceiling_ns), forfeit)?;
            policy = staged;
            self.effective = Some(staged);
            self.staged = None;
            self.ceiling_ns = staged.budget_ns;
            self.net_ns = self.net_ns.min(i128::from(self.ceiling_ns));
            frontier = frontier.checked_add(staged.window_ns).ok_or(UNKNOWN)?;
        }
        if frontier <= now {
            let count = now
                .checked_sub(frontier)
                .ok_or(UNKNOWN)?
                .checked_div(policy.window_ns)
                .ok_or(UNKNOWN)?
                .checked_add(1)
                .ok_or(UNKNOWN)?;
            self.grant(count, policy.budget_ns.min(self.ceiling_ns), forfeit)?;
            frontier = frontier
                .checked_add(count.checked_mul(policy.window_ns).ok_or(UNKNOWN)?)
                .ok_or(UNKNOWN)?;
        }
        self.next_refill_ns = Some(frontier);
        Ok(())
    }

    fn settle(
        &mut self,
        active: Active,
        now: u64,
        cancelled: bool,
    ) -> Result<PollSettlement, &'static str> {
        self.observe_time(now)?;
        let elapsed_ns = now.checked_sub(active.start_ns).ok_or(UNKNOWN)?;
        let charged_ns = if cancelled {
            elapsed_ns.max(active.reserved_ns)
        } else {
            elapsed_ns
        };
        let overrun_ns = elapsed_ns.saturating_sub(active.reserved_ns);
        self.net_ns = self
            .net_ns
            .checked_add(i128::from(active.reserved_ns))
            .ok_or(UNKNOWN)?
            .checked_sub(i128::from(charged_ns))
            .ok_or(UNKNOWN)?
            .min(i128::from(self.ceiling_ns));
        self.charged_ns = self
            .charged_ns
            .checked_add(u128::from(charged_ns))
            .ok_or(UNKNOWN)?;
        self.overrun_ns = self
            .overrun_ns
            .checked_add(u128::from(overrun_ns))
            .ok_or(UNKNOWN)?;
        let grants_before = self.forfeited_grants;
        let forfeited_before = self.forfeited_ns;
        // ponytail: one active Busy interval; crossed unresolved frontiers forfeit grants.
        self.advance_to(now, true)?;
        let record = PollSettlement {
            elapsed_ns,
            charged_ns,
            reserved_ns: active.reserved_ns,
            overrun_ns,
            forfeited_grants: self
                .forfeited_grants
                .checked_sub(grants_before)
                .ok_or(UNKNOWN)?,
            forfeited_ns: self
                .forfeited_ns
                .checked_sub(forfeited_before)
                .ok_or(UNKNOWN)?,
            net_ns: self.net_ns,
        };
        self.active = None;
        Ok(record)
    }
}

#[cfg(test)]
mod tests;
