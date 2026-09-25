//! Business-funded optional work. Currency is independent of evidence and target LRUs.
use super::*;
use honk_config::node::Node;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{OnceLock, Weak};

const EARNED_CAP: u64 = 8;
const IN_FLIGHT_TTL: Duration = Duration::from_secs(60);
const PENDING: u8 = 0;
const STARTED: u8 = 1;
const FINISHED: u8 = 2;
const CANCELLED: u8 = 3;
pub(super) fn exploration_target(candidate_count: usize) -> usize {
    if candidate_count <= 4 {
        candidate_count
    } else {
        (((candidate_count as f64).sqrt().ceil() as usize) + 1).min(candidate_count)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScoreBudgetCounters {
    pub business_starts: u64,
    pub trial_starts: u64,
    pub cold_trial_starts: u64,
    pub periodic_trial_starts: u64,
    pub recovery_starts: u64,
    pub reserved: u64,
    pub spent: u64,
    pub budget_blocked: u64,
    pub in_flight_blocked: u64,
    pub refunded: u64,
    pub expired: u64,
    pub cold_allowance: u64,
    pub cold_available: u64,
    pub earned_available: u64,
    pub earning_period: u64,
    pub scopes: u64,
    pub trial_success: u64,
    pub trial_failure: u64,
    pub trial_cancelled: u64,
    pub trial_setup_histogram: [u64; 8],
    pub trial_setup_millis: u64,
    pub trial_elapsed_millis: u64,
}

#[derive(Clone, Copy, Debug)]
enum Token {
    Cold,
    Earned,
}

#[derive(Default)]
pub(in crate::group) struct Opportunity {
    progress: Mutex<OpportunityProgress>,
}

#[derive(Default)]
struct OpportunityProgress {
    begun: bool,
    scopes: Vec<(SelectionCadenceKey, Arc<()>)>,
}

impl std::fmt::Debug for Opportunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opportunity").finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Life {
    status: AtomicU8,
    setup: AtomicBool,
    token: Option<Token>,
    started_at: OnceLock<Instant>,
    answered: AtomicU8,
    source: ScoreTrialSource,
}

impl Life {
    fn elapsed_millis(&self, now: Instant) -> u64 {
        self.started_at.get().map_or(0, |started| {
            u64::try_from(now.saturating_duration_since(*started).as_millis()).unwrap_or(u64::MAX)
        })
    }
}

struct InFlight {
    node: Uuid,
    target: Option<ScoreTarget>,
    life: Weak<Life>,
    expires: Instant,
}

pub(super) struct Scope {
    identity: Arc<()>,
    counters: ScoreBudgetCounters,
    in_flight: Vec<InFlight>,
}

impl Scope {
    fn new(members: usize) -> Self {
        let allowance = exploration_target(members) as u64;
        Self {
            identity: Arc::new(()),
            counters: ScoreBudgetCounters {
                cold_allowance: allowance,
                cold_available: allowance,
                scopes: 1,
                ..Default::default()
            },
            in_flight: Vec::new(),
        }
    }

    fn effective_credit(&self, now: Instant) -> (u64, u64, u64) {
        let c = &self.counters;
        let (mut cold, mut earned, mut reserved) =
            (c.cold_available, c.earned_available, c.reserved);
        // Reads see refundable credit without recording an expiry or refund.
        for entry in &self.in_flight {
            if entry.expires > now {
                continue;
            }
            let Some(life) = entry.life.upgrade() else {
                continue;
            };
            if life.status.load(Ordering::Relaxed) != PENDING {
                continue;
            }
            match life.token {
                Some(Token::Cold) => cold = cold.saturating_add(1).min(c.cold_allowance),
                Some(Token::Earned) => earned = earned.saturating_add(1).min(EARNED_CAP),
                None => continue,
            }
            reserved = reserved.saturating_sub(1);
        }
        (cold, earned, reserved)
    }

    fn available(&self, now: Instant) -> bool {
        let c = &self.counters;
        let (cold, earned, reserved) = self.effective_credit(now);
        c.business_starts < u64::MAX
            && c.spent < u64::MAX
            && reserved < u64::MAX
            && (cold > 0 || earned > 0)
            && c.spent.checked_add(reserved).is_some_and(|used| {
                used < c
                    .cold_allowance
                    .saturating_add(c.business_starts / SCORE_EXPLORATION_PERIOD)
            })
    }

    fn refund(&mut self, token: Token) {
        let c = &mut self.counters;
        c.reserved = c.reserved.saturating_sub(1);
        c.refunded = c.refunded.saturating_add(1);
        match token {
            Token::Cold => {
                c.cold_available = c.cold_available.saturating_add(1).min(c.cold_allowance)
            }
            Token::Earned => {
                c.earned_available = c.earned_available.saturating_add(1).min(EARNED_CAP)
            }
        }
    }

    fn expire(&mut self, now: Instant) {
        let expired = self.drop_in_flight(|entry, _| entry.expires > now);
        self.counters.expired = self.counters.expired.saturating_add(expired);
    }

    /// Drops dead and finished entries plus live ones `keep` rejects, cancelling and refunding
    /// pending work; returns how many live entries were dropped.
    fn drop_in_flight(&mut self, keep: impl Fn(&InFlight, u8) -> bool) -> u64 {
        let (mut dropped, mut cold, mut earned) = (0, 0, 0);
        self.in_flight.retain(|entry| {
            let Some(life) = entry.life.upgrade() else {
                return false;
            };
            let status = life.status.load(Ordering::Relaxed);
            if status >= FINISHED {
                return false;
            }
            if keep(entry, status) {
                return true;
            }
            dropped += 1;
            if status == PENDING {
                life.status.store(CANCELLED, Ordering::Relaxed);
                match life.token {
                    Some(Token::Cold) => cold += 1,
                    Some(Token::Earned) => earned += 1,
                    None => {}
                }
            }
            false
        });
        for _ in 0..cold {
            self.refund(Token::Cold);
        }
        for _ in 0..earned {
            self.refund(Token::Earned);
        }
        dropped
    }

    fn active(
        &self,
        node: Uuid,
        question: ScoreEvidenceQuestion,
        target: Option<&ScoreTarget>,
        now: Instant,
    ) -> usize {
        self.in_flight
            .iter()
            .filter(|entry| {
                entry.node == node
                    && (matches!(
                        question,
                        ScoreEvidenceQuestion::None | ScoreEvidenceQuestion::Qualification
                    ) || target.is_none_or(|target| entry.target.as_ref() == Some(target)))
                    && entry.expires > now
                    && entry.life.upgrade().is_some_and(|life| {
                        life.status.load(Ordering::Relaxed) < FINISHED
                            && life.answered.load(Ordering::Relaxed) & question_mask(question) == 0
                    })
            })
            .count()
    }

    fn track(&mut self, node: Uuid, target: Option<&ScoreTarget>, life: &Arc<Life>, now: Instant) {
        self.expire(now);
        if let Some(entry) = self
            .in_flight
            .iter_mut()
            .find(|entry| entry.life.ptr_eq(&Arc::downgrade(life)))
        {
            entry.expires = now + IN_FLIGHT_TTL;
        } else if self.active(node, ScoreEvidenceQuestion::None, None, now) < 4 {
            self.in_flight.push(InFlight {
                node,
                target: target.cloned(),
                life: Arc::downgrade(life),
                expires: now + IN_FLIGHT_TTL,
            });
        }
    }

    pub(super) fn invalidate_pending(&mut self) {
        self.drop_in_flight(|_, status| status == STARTED);
    }
}

pub(in crate::group) struct Work {
    state: Weak<ScorePolicyState>,
    pub(super) key: SelectionCadenceKey,
    scope: Option<Arc<()>>,
    node: Uuid,
    life: Arc<Life>,
}

impl std::fmt::Debug for Work {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScoreWork").finish_non_exhaustive()
    }
}

impl Work {
    pub(super) fn new(
        state: &Arc<ScorePolicyState>,
        group: &str,
        context: &ScoreSelectionContext,
        node: Uuid,
        source: ScoreTrialSource,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::downgrade(state),
            key: SelectionCadenceKey::new(group, context),
            scope: None,
            node,
            life: Arc::new(Life {
                source,
                ..Default::default()
            }),
        })
    }

    pub(super) fn has_started(&self) -> bool {
        self.life.started_at.get().is_some()
    }

    pub(super) fn is_cold(&self) -> bool {
        self.life.source == ScoreTrialSource::Cold
    }

    fn scope_matches(&self, scope: &Scope) -> bool {
        self.scope
            .as_ref()
            .is_none_or(|identity| Arc::ptr_eq(identity, &scope.identity))
    }

    pub(super) fn cancel_pending(&self, inner: &mut StateInner) {
        if self.life.status.load(Ordering::Relaxed) != PENDING {
            return;
        }
        self.life.status.store(CANCELLED, Ordering::Relaxed);
        if let Some(token) = self.life.token
            && let Some(scope) = inner
                .budgets
                .get_mut(&self.key)
                .filter(|scope| self.scope_matches(scope))
        {
            scope.refund(token);
        }
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            let mut inner = state.inner.lock();
            if self.life.status.load(Ordering::Relaxed) == PENDING {
                self.cancel_pending(&mut inner);
            } else {
                settle(&mut inner, self, ScoreOutcome::Cancelled, Instant::now());
            }
        }
    }
}

fn ensure_scope<'a>(inner: &'a mut StateInner, key: &SelectionCadenceKey) -> &'a mut Scope {
    if !inner.budgets.contains_key(key) {
        let members = inner
            .valid
            .iter()
            .filter(|(group, _)| group == &key.group)
            .count();
        inner.budgets.insert(key.clone(), Scope::new(members));
    }
    inner.budgets.get_mut(key).expect("scope inserted above")
}

/// Ledger scopes behind a read: a targeted context's own, or both target families for an
/// aggregate read, since only targeted work reaches the ledger.
fn read_scopes<'a>(
    inner: &'a StateInner,
    group: &str,
    context: &ScoreSelectionContext,
) -> impl Iterator<Item = Option<&'a Scope>> {
    let aggregate = context.target.is_none() && context.target_family.is_none();
    let families = if aggregate {
        [Some(IpVersion::V4), Some(IpVersion::V6)]
    } else {
        [context.target_family; 2]
    };
    let mut key = SelectionCadenceKey::new(group, context);
    families
        .into_iter()
        .take(1 + usize::from(aggregate))
        .map(move |family| {
            key.family = family;
            inner.budgets.get(&key)
        })
}

/// Reserved or begun work per member that has not finished in the scopes behind this read.
pub(super) fn unfinished(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    nodes: &[&Node],
    now: Instant,
) -> Vec<f64> {
    let mut unfinished = vec![0.0; nodes.len()];
    for scope in read_scopes(inner, group, context).flatten() {
        for (count, node) in unfinished.iter_mut().zip(nodes) {
            *count += scope.active(node.id, ScoreEvidenceQuestion::None, None, now) as f64;
        }
    }
    unfinished
}

pub(super) fn reserve(
    state: &Arc<ScorePolicyState>,
    inner: &mut StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    node: Uuid,
    question: ScoreEvidenceQuestion,
    now: Instant,
) -> Result<Arc<Work>, ScoreWaitReason> {
    let key = SelectionCadenceKey::new(group, context);
    let scope = ensure_scope(inner, &key);
    scope.expire(now);
    // One unanswered trial per question and target: a burst would give a member more evidence
    // than the selection it is compared against before either result is known.
    if scope.active(node, question, context.target.as_ref(), now) > 0
        || scope.active(node, ScoreEvidenceQuestion::None, None, now) >= 4
    {
        scope.counters.in_flight_blocked = scope.counters.in_flight_blocked.saturating_add(1);
        return Err(ScoreWaitReason::InFlight);
    }
    if !scope.available(now) {
        scope.counters.budget_blocked = scope.counters.budget_blocked.saturating_add(1);
        return Err(ScoreWaitReason::Budget);
    }
    let token = if scope.counters.cold_available > 0 {
        scope.counters.cold_available -= 1;
        Token::Cold
    } else {
        scope.counters.earned_available -= 1;
        Token::Earned
    };
    scope.counters.reserved += 1;
    let work = Arc::new(Work {
        state: Arc::downgrade(state),
        key,
        scope: Some(Arc::clone(&scope.identity)),
        node,
        life: Arc::new(Life {
            token: Some(token),
            source: match token {
                Token::Cold => ScoreTrialSource::Cold,
                Token::Earned => ScoreTrialSource::Periodic,
            },
            ..Default::default()
        }),
    });
    scope.track(node, context.target.as_ref(), &work.life, now);
    Ok(work)
}

/// Why the ledger would refuse this member's next trial. An aggregate read waits only while
/// every target family refuses, and on the budget only while every family is exhausted.
pub(super) fn wait_reason(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    node: Uuid,
    question: ScoreEvidenceQuestion,
    now: Instant,
) -> ScoreWaitReason {
    let mut wait = ScoreWaitReason::Budget;
    for scope in read_scopes(inner, group, context) {
        let Some(scope) = scope else {
            return ScoreWaitReason::None;
        };
        if scope.active(node, question, context.target.as_ref(), now) > 0
            || scope.active(node, ScoreEvidenceQuestion::None, None, now) >= 4
        {
            wait = ScoreWaitReason::InFlight;
        } else if scope.available(now) {
            return ScoreWaitReason::None;
        }
    }
    wait
}

pub(super) fn begin_unscored(
    inner: &mut StateInner,
    opportunity: &Opportunity,
    work: &[Arc<Work>],
    now: Instant,
) -> bool {
    if work.iter().any(|item| {
        item.life.token.is_some() || item.life.status.load(Ordering::Relaxed) != PENDING
    }) {
        for item in work {
            item.cancel_pending(inner);
        }
        return false;
    }
    opportunity.progress.lock().begun = true;
    for item in work {
        item.life.status.store(STARTED, Ordering::Relaxed);
        let _ = item.life.started_at.set(now);
    }
    true
}

pub(super) fn begin(
    inner: &mut StateInner,
    authority: &Arc<ScoreAuthority>,
    context: &ScoreSelectionContext,
    attributions: &[ScoreAttribution],
    opportunity: &Opportunity,
    work: &[Arc<Work>],
    now: Instant,
) -> bool {
    if !inner
        .active_authority
        .as_ref()
        .is_some_and(|active| Arc::ptr_eq(active, authority))
        || attributions
            .iter()
            .any(|a| !inner.valid.contains(&(a.group.clone(), a.node_id)))
    {
        for item in work {
            item.cancel_pending(inner);
        }
        return false;
    }
    if work
        .iter()
        .any(|item| item.life.status.load(Ordering::Relaxed) != PENDING)
    {
        return false;
    }
    if context.target.is_none() {
        if work.iter().any(|item| item.life.token.is_some()) {
            for item in work {
                item.cancel_pending(inner);
            }
            return false;
        }
        opportunity.progress.lock().begun = true;
        for item in work {
            item.life.status.store(STARTED, Ordering::Relaxed);
            let _ = item.life.started_at.set(now);
        }
        return true;
    }
    for item in work {
        let scope = ensure_scope(inner, &item.key);
        scope.expire(now);
        if !item.scope_matches(scope) || item.life.status.load(Ordering::Relaxed) == CANCELLED {
            for pending in work {
                pending.cancel_pending(inner);
            }
            return false;
        }
    }
    let mut progress = opportunity.progress.lock();
    if (!progress.begun && inner.root_business_starts == u64::MAX)
        || work.iter().any(|item| {
            item.life.source != ScoreTrialSource::Recovery
                && inner.budgets.get(&item.key).is_some_and(|scope| {
                    !progress.scopes.iter().any(|(key, identity)| {
                        *key == item.key && Arc::ptr_eq(identity, &scope.identity)
                    }) && scope.counters.business_starts == u64::MAX
                })
        })
    {
        for item in work {
            item.cancel_pending(inner);
        }
        return false;
    }
    if !progress.begun {
        inner.root_business_starts += 1;
        progress.begun = true;
    }
    for item in work {
        let scope = ensure_scope(inner, &item.key);
        let counted = item.life.source != ScoreTrialSource::Recovery
            && !progress
                .scopes
                .iter()
                .any(|(key, identity)| *key == item.key && Arc::ptr_eq(identity, &scope.identity));
        if counted {
            scope.counters.business_starts += 1;
            if scope
                .counters
                .business_starts
                .is_multiple_of(SCORE_EXPLORATION_PERIOD)
            {
                scope.counters.earned_available =
                    (scope.counters.earned_available + 1).min(EARNED_CAP);
            }
            progress
                .scopes
                .push((item.key.clone(), Arc::clone(&scope.identity)));
        }
        if item.life.status.load(Ordering::Relaxed) == PENDING {
            item.life.status.store(STARTED, Ordering::Relaxed);
            let _ = item.life.started_at.set(now);
            if item.life.token.is_some() {
                scope.counters.reserved -= 1;
                scope.counters.spent += 1;
                scope.counters.trial_starts = scope.counters.trial_starts.saturating_add(1);
            }
            let counter = match item.life.source {
                ScoreTrialSource::Cold => Some(&mut scope.counters.cold_trial_starts),
                ScoreTrialSource::Periodic => Some(&mut scope.counters.periodic_trial_starts),
                ScoreTrialSource::Recovery => Some(&mut scope.counters.recovery_starts),
                ScoreTrialSource::None => None,
            };
            if let Some(counter) = counter {
                *counter = counter.saturating_add(1);
            }
            scope.track(item.node, context.target.as_ref(), &item.life, now);
        }
        if counted {
            inner
                .evaluation
                .entry(SelectionReasonKey::new(&item.key.group, item.key.network))
                .or_default()
                .record_demand(now);
        }
    }
    true
}

fn question_mask(question: ScoreEvidenceQuestion) -> u8 {
    match question {
        ScoreEvidenceQuestion::Availability | ScoreEvidenceQuestion::Recovery => 1,
        ScoreEvidenceQuestion::Response => 2,
        ScoreEvidenceQuestion::Qualification => 4,
        ScoreEvidenceQuestion::None => 0,
    }
}

pub(super) fn answered(
    inner: &StateInner,
    context: &ScoreSelectionContext,
    attributions: &[ScoreAttribution],
    cells: &[StartedCells],
    work: &[Arc<Work>],
    question: ScoreEvidenceQuestion,
    now: Instant,
) {
    let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) else {
        return;
    };
    for (attribution, cells) in attributions.iter().zip(cells) {
        let key = ExactKey {
            group: attribution.group.clone(),
            network: context.network,
            family,
            target: target.clone(),
            node_id: attribution.node_id,
        };
        let Some(stats) = inner
            .exact
            .peek(&key)
            .filter(|stats| cells.exact == Some(stats.incarnation))
        else {
            continue;
        };
        let accepted = match question {
            ScoreEvidenceQuestion::Availability => {
                cells.credited_exact == Some(stats.availability.epoch)
            }
            ScoreEvidenceQuestion::Response => stats.performance.response.observed_at == Some(now),
            _ => false,
        };
        if accepted && let Some(item) = work.iter().find(|item| item.key.group == attribution.group)
        {
            item.life
                .answered
                .fetch_or(question_mask(question), Ordering::Relaxed);
        }
    }
}

pub(super) fn setup(inner: &mut StateInner, work: &[Arc<Work>], now: Instant) {
    for item in work {
        if item.life.token.is_none()
            || item.life.status.load(Ordering::Relaxed) != STARTED
            || item.life.setup.swap(true, Ordering::Relaxed)
        {
            continue;
        }
        if let Some(scope) = inner
            .budgets
            .get_mut(&item.key)
            .filter(|scope| item.scope_matches(scope))
        {
            let millis = item.life.elapsed_millis(now);
            let bin = millis.max(1).ilog2().min(7) as usize;
            scope.counters.trial_setup_histogram[bin] =
                scope.counters.trial_setup_histogram[bin].saturating_add(1);
            scope.counters.trial_setup_millis =
                scope.counters.trial_setup_millis.saturating_add(millis);
        }
    }
}

fn settle(inner: &mut StateInner, item: &Work, outcome: ScoreOutcome, now: Instant) {
    if item.life.status.load(Ordering::Relaxed) != STARTED {
        return;
    }
    item.life.status.store(FINISHED, Ordering::Relaxed);
    if item.life.token.is_none() {
        return;
    }
    if let Some(scope) = inner
        .budgets
        .get_mut(&item.key)
        .filter(|scope| item.scope_matches(scope))
    {
        let c = &mut scope.counters;
        match outcome {
            ScoreOutcome::Success => c.trial_success = c.trial_success.saturating_add(1),
            ScoreOutcome::Cancelled | ScoreOutcome::Rejected | ScoreOutcome::Shutdown => {
                c.trial_cancelled = c.trial_cancelled.saturating_add(1)
            }
            _ => c.trial_failure = c.trial_failure.saturating_add(1),
        }
        c.trial_elapsed_millis = c
            .trial_elapsed_millis
            .saturating_add(item.life.elapsed_millis(now));
    }
}

pub(super) fn finish(
    state: &ScorePolicyState,
    work: &[Arc<Work>],
    outcome: ScoreOutcome,
    now: Instant,
) {
    let mut inner = state.inner.lock();
    for item in work {
        settle(&mut inner, item, outcome, now);
    }
}

impl ScorePolicyState {
    /// Unique offered businesses, never a sum of nested group counters.
    pub fn root_business_starts(&self) -> u64 {
        self.inner.lock().root_business_starts
    }

    pub(super) fn budget_counters(
        &self,
        group: &str,
        network: SelectionNetwork,
    ) -> ScoreBudgetCounters {
        let inner = self.inner.lock();
        let mut total = ScoreBudgetCounters::default();
        for (_, scope) in inner
            .budgets
            .iter()
            .filter(|(key, _)| key.group == group && key.network == network)
        {
            let c = scope.counters;
            macro_rules! sum { ($($field:ident),*) => { $(total.$field = total.$field.saturating_add(c.$field);)* }; }
            sum!(
                business_starts,
                trial_starts,
                cold_trial_starts,
                periodic_trial_starts,
                recovery_starts,
                reserved,
                spent,
                budget_blocked,
                in_flight_blocked,
                refunded,
                expired,
                cold_allowance,
                cold_available,
                earned_available,
                scopes,
                trial_success,
                trial_failure,
                trial_cancelled,
                trial_setup_millis,
                trial_elapsed_millis
            );
            total.earning_period = SCORE_EXPLORATION_PERIOD;
            for (out, count) in total
                .trial_setup_histogram
                .iter_mut()
                .zip(c.trial_setup_histogram)
            {
                *out = out.saturating_add(count);
            }
        }
        total
    }
}
