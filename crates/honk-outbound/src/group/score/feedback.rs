use super::evidence::Observation;
use super::{
    FlowSample, LIVE_RX_INTERVAL, MAX_THROUGHPUT_DURATION, MIN_THROUGHPUT_BYTES,
    MIN_THROUGHPUT_DURATION, ScoreAttribution, ScoreAuthority, ScoreOutcome, ScorePolicyState,
    ScoreSelectionContext, ScoreSource, StartedCells, budget, comparison,
};
use parking_lot::Mutex;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Immutable attribution and source factory; each start is independent work.
#[derive(Clone)]
pub struct ScoreFeedback {
    state: Arc<ScorePolicyState>,
    authority: Arc<ScoreAuthority>,
    context: ScoreSelectionContext,
    attributions: Arc<[ScoreAttribution]>,
    source: ScoreSource,
    probe_scope: u64,
    probe_interval: Option<Duration>,
}

/// One pending business attempt. Clones retain the same reservation and original identity.
#[derive(Clone, Debug)]
pub struct ScoreAttempt {
    feedback: ScoreFeedback,
    pub(super) opportunity: Arc<budget::Opportunity>,
    work: Arc<[Arc<budget::Work>]>,
}

/// Original business identity, issued only after admission.
#[derive(Clone, Debug)]
pub struct ScoreContinuation {
    pub(super) opportunity: Arc<budget::Opportunity>,
}

/// Owns admitted work until its physical/logical reporter starts.
pub struct ScoreBusinessGuard {
    attempt: Option<ScoreAttempt>,
    admitted: bool,
}

impl ScoreBusinessGuard {
    pub fn continuation(&self) -> ScoreContinuation {
        ScoreContinuation {
            opportunity: Arc::clone(
                &self
                    .attempt
                    .as_ref()
                    .expect("admitted Score attempt")
                    .opportunity,
            ),
        }
    }

    pub fn start(self) -> ScoreReporter {
        self.start_at(Instant::now())
    }

    pub(super) fn start_at(mut self, started: Instant) -> ScoreReporter {
        let attempt = self.attempt.take().expect("admitted Score attempt");
        attempt
            .feedback
            .reporter(attempt.work, started, self.admitted)
    }

    pub fn finish(mut self, outcome: ScoreOutcome) {
        if let Some(attempt) = self.attempt.take() {
            budget::finish(
                &attempt.feedback.state,
                &attempt.work,
                outcome,
                Instant::now(),
            );
        }
    }
}

impl Drop for ScoreBusinessGuard {
    fn drop(&mut self) {
        if let Some(attempt) = &self.attempt {
            budget::finish(
                &attempt.feedback.state,
                &attempt.work,
                ScoreOutcome::Cancelled,
                Instant::now(),
            );
        }
    }
}

impl std::fmt::Debug for ScoreFeedback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScoreFeedback")
            .finish_non_exhaustive()
    }
}

impl ScoreAttempt {
    pub(super) fn planned(
        feedback: ScoreFeedback,
        opportunity: Arc<budget::Opportunity>,
        mut work: Vec<Arc<budget::Work>>,
        source: super::ScoreTrialSource,
    ) -> Self {
        for attribution in feedback.attributions.iter() {
            if !work.iter().any(|item| item.key.group == attribution.group) {
                work.push(budget::Work::new(
                    &feedback.state,
                    &attribution.group,
                    &feedback.context,
                    attribution.node_id,
                    source,
                ));
            }
        }
        Self {
            feedback,
            opportunity,
            work: work.into(),
        }
    }

    /// Admit before node DNS or physical-dial admission waits; stale ordinary work proceeds unscored.
    pub fn begin(&self) -> Result<ScoreBusinessGuard, crate::proxy::PacketRejection> {
        self.begin_at(Instant::now())
    }

    pub(super) fn begin_at(
        &self,
        now: Instant,
    ) -> Result<ScoreBusinessGuard, crate::proxy::PacketRejection> {
        let mut inner = self.feedback.state.inner.lock();
        if !inner
            .active_authority
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &self.feedback.authority))
        {
            return if budget::begin_unscored(&mut inner, &self.opportunity, &self.work, now) {
                Ok(ScoreBusinessGuard {
                    attempt: Some(self.clone()),
                    admitted: false,
                })
            } else {
                Err(crate::proxy::PacketRejection::Cancelled)
            };
        }
        if !budget::begin(
            &mut inner,
            &self.feedback.authority,
            &self.feedback.context,
            &self.feedback.attributions,
            &self.opportunity,
            &self.work,
            now,
        ) {
            return Err(crate::proxy::PacketRejection::Cancelled);
        }
        super::ranking::advance_rotation(
            &mut inner,
            &self.feedback.context,
            &self.feedback.attributions,
        );
        Ok(ScoreBusinessGuard {
            attempt: Some(self.clone()),
            admitted: true,
        })
    }

    pub fn attributions(&self) -> &[ScoreAttribution] {
        self.feedback.attributions()
    }

    pub fn context(&self) -> &ScoreSelectionContext {
        self.feedback.context()
    }

    /// Start unscored refill without admitting or transferring pending business work.
    pub fn start_warmup(self, context: ScoreSelectionContext) -> ScoreReporter {
        self.feedback
            .with_context(context)
            .with_source(ScoreSource::Warmup)
            .start()
    }

    pub fn continuation(&self) -> Result<ScoreContinuation, crate::proxy::PacketRejection> {
        if !self.work.iter().all(|work| work.has_started()) {
            return Err(crate::proxy::PacketRejection::Cancelled);
        }
        Ok(ScoreContinuation {
            opportunity: Arc::clone(&self.opportunity),
        })
    }

    /// A carrier change requires an admitted original, never an unspent reservation.
    pub fn with_context(
        self,
        context: ScoreSelectionContext,
    ) -> Result<Self, crate::proxy::PacketRejection> {
        let original = self.continuation()?;
        Ok(Self::planned(
            self.feedback.with_context(context),
            original.opportunity,
            Vec::new(),
            super::ScoreTrialSource::Recovery,
        ))
    }
}

impl ScoreFeedback {
    pub(in crate::group) fn new(
        state: Arc<ScorePolicyState>,
        authority: Arc<ScoreAuthority>,
        context: ScoreSelectionContext,
        attributions: Vec<ScoreAttribution>,
    ) -> Self {
        Self {
            state,
            authority,
            context,
            attributions: attributions.into(),
            source: ScoreSource::Traffic,
            probe_scope: 0,
            probe_interval: None,
        }
    }

    /// Create one independent business, without changing this factory or any clone.
    pub fn business(&self) -> ScoreAttempt {
        ScoreAttempt::planned(
            self.clone().with_source(ScoreSource::Traffic),
            Arc::new(budget::Opportunity::default()),
            Vec::new(),
            super::ScoreTrialSource::None,
        )
    }

    /// Classify before constructing business work.
    pub fn with_source(mut self, source: ScoreSource) -> Self {
        self.source = source;
        if source == ScoreSource::HealthProbe {
            let mut scope = std::collections::hash_map::DefaultHasher::new();
            self.context.hash(&mut scope);
            self.probe_scope = scope.finish();
        }
        self
    }
    /// Bind configured-probe comparison freshness to its producer's cadence.
    pub fn with_probe_interval(mut self, interval: Duration) -> Self {
        self.probe_interval = Some(interval);
        self
    }

    /// Bind an HTTP health sample to the complete canonical request cohort.
    pub(crate) fn with_probe_identity(mut self, uri: &str, method: &str) -> Self {
        if self.source == ScoreSource::HealthProbe {
            let mut scope = std::collections::hash_map::DefaultHasher::new();
            (&self.context, uri, method).hash(&mut scope);
            self.probe_scope = scope.finish();
        }
        self
    }
    fn probe_scope(&self) -> u64 {
        self.probe_interval.map_or(self.probe_scope, |interval| {
            let mut scope = std::collections::hash_map::DefaultHasher::new();
            (self.probe_scope, interval).hash(&mut scope);
            scope.finish()
        })
    }

    pub fn attributions(&self) -> &[ScoreAttribution] {
        &self.attributions
    }

    pub fn context(&self) -> &ScoreSelectionContext {
        &self.context
    }

    pub fn with_context(mut self, context: ScoreSelectionContext) -> Self {
        self.context = context;
        let source = self.source;
        self.with_source(source)
    }

    /// Start an independent observation; callers with selected business work use its guard.
    pub fn start(&self) -> ScoreReporter {
        self.start_at(Instant::now())
    }

    pub(super) fn start_at(&self, started: Instant) -> ScoreReporter {
        if self.source != ScoreSource::Traffic {
            return self.clone().reporter(Arc::from([]), started, true);
        }
        match self.business().begin_at(started) {
            Ok(guard) => guard.start_at(started),
            // A captured factory cannot publish new observations after authority changes.
            Err(_) => self.clone().reporter(Arc::from([]), started, false),
        }
    }

    fn reporter(
        self,
        work: Arc<[Arc<budget::Work>]>,
        started: Instant,
        admitted: bool,
    ) -> ScoreReporter {
        let cells = if admitted {
            self.state.start_at_with_authority(
                &self.authority,
                &self.context,
                &self.attributions,
                started,
                self.source,
            )
        } else {
            vec![StartedCells::default(); self.attributions.len()]
        };
        ScoreReporter {
            shared: Arc::new(ReporterShared {
                feedback: self,
                work,
                started,
                handles: AtomicUsize::new(1),
                progress: Mutex::new(ReporterProgress {
                    cells,
                    reporter_id: comparison::next_reporter_id(),
                    window_start: started,
                    setup: None,
                    first_response: false,
                    probe: false,
                    finished: false,
                    tx: 0,
                    rx: 0,
                    last_rx_at: None,
                    first_tx_at: None,
                    eligible_rx_at: None,
                    published_rx_at: None,
                    window_tx: 0,
                    window_rx: 0,
                }),
            }),
        }
    }
}

struct ReporterProgress {
    cells: Vec<StartedCells>,
    reporter_id: u64,
    setup: Option<Duration>,
    first_response: bool,
    probe: bool,
    finished: bool,
    tx: u64,
    rx: u64,
    last_rx_at: Option<Instant>,
    first_tx_at: Option<Instant>,
    eligible_rx_at: Option<Instant>,
    published_rx_at: Option<Instant>,
    window_start: Instant,
    window_tx: u64,
    window_rx: u64,
}

struct ReporterShared {
    feedback: ScoreFeedback,
    work: Arc<[Arc<budget::Work>]>,
    started: Instant,
    handles: AtomicUsize,
    progress: Mutex<ReporterProgress>,
}

/// Cloneable exact-once flow reporter. The first terminal call wins; dropping
/// the final unfinished handle reports cancellation.
pub struct ScoreReporter {
    shared: Arc<ReporterShared>,
}

impl Clone for ScoreReporter {
    fn clone(&self) -> Self {
        self.shared.handles.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl ScoreReporter {
    pub fn setup_succeeded(&self) {
        self.setup_succeeded_at(Instant::now());
    }

    pub(super) fn setup_succeeded_at(&self, now: Instant) {
        let mut progress = self.shared.progress.lock();
        if progress.finished || progress.setup.is_some() {
            return;
        }
        let elapsed = now.saturating_duration_since(self.shared.started);
        progress.setup = Some(elapsed);
        progress.window_start = now;
        self.observe(Observation::Setup(elapsed), now, &mut progress);
    }

    pub fn setup_failed(&self, outcome: ScoreOutcome) {
        self.finish(outcome);
    }

    pub fn first_response(&self) {
        self.first_response_at(Instant::now());
    }

    pub(super) fn first_response_at(&self, now: Instant) {
        let mut progress = self.shared.progress.lock();
        if progress.finished || progress.first_response {
            return;
        }
        progress.first_response = true;
        self.observe(
            Observation::Response(now.saturating_duration_since(self.shared.started)),
            now,
            &mut progress,
        );
    }

    /// Publish a genuinely measured configured-probe RTT, never a cached average.
    pub fn probe_latency(&self, latency: Duration) {
        self.probe_latency_at(latency, Instant::now());
    }

    pub(super) fn probe_latency_at(&self, latency: Duration, now: Instant) {
        let mut progress = self.shared.progress.lock();
        let feedback = &self.shared.feedback;
        if progress.finished || progress.probe || feedback.source != ScoreSource::HealthProbe {
            return;
        }
        progress.probe = true;
        let scope = feedback.probe_scope();
        self.observe(
            Observation::Probe {
                latency,
                scope,
                slot: super::evidence::probe_slot(&feedback.context),
                interval: feedback.probe_interval,
            },
            now,
            &mut progress,
        );
    }

    pub fn tx(&self, bytes: u64) {
        self.transfer_at(bytes, 0, Instant::now());
    }

    /// Record a successful send whose receiver can run before its completion callback.
    /// `started_at` must follow core send serialization checks, not source-gate queue entry.
    pub fn tx_completed(&self, bytes: u64, started_at: Instant) {
        self.transfer_with_send_start_at(bytes, 0, Some(started_at), None);
    }

    #[cfg(test)]
    pub(super) fn tx_completed_at(&self, bytes: u64, started_at: Instant, now: Instant) {
        self.transfer_with_send_start_at(bytes, 0, Some(started_at), Some(now));
    }

    pub fn rx(&self, bytes: u64) {
        self.transfer_at(0, bytes, Instant::now());
    }

    pub(super) fn transfer_at(&self, tx: u64, rx: u64, now: Instant) {
        self.transfer_with_send_start_at(tx, rx, None, Some(now));
    }

    fn transfer_with_send_start_at(
        &self,
        tx: u64,
        rx: u64,
        send_started_at: Option<Instant>,
        now: Option<Instant>,
    ) {
        if tx == 0 && rx == 0 {
            return;
        }
        let mut progress = self.shared.progress.lock();
        if progress.finished {
            return;
        }
        // A receive can publish while this completion waits for the reporter lock.
        let now = now.unwrap_or_else(Instant::now);
        let send_started_at = send_started_at.filter(|at| tx > 0 && progress.tx == 0 && *at <= now);
        progress.tx = progress.tx.saturating_add(tx);
        progress.rx = progress.rx.saturating_add(rx);
        if self.shared.feedback.source != ScoreSource::Traffic {
            return;
        }
        if rx > 0 {
            progress.last_rx_at = Some(progress.last_rx_at.map_or(now, |at| at.max(now)));
        }
        if tx > 0 {
            let at = send_started_at.unwrap_or(now);
            progress.first_tx_at = Some(progress.first_tx_at.map_or(at, |seen| seen.min(at)));
        }
        let rx_at = if rx > 0 {
            Some(now)
        } else {
            send_started_at.and_then(|started| {
                progress
                    .last_rx_at
                    .filter(|at| *at >= started && *at <= now)
            })
        };
        if let Some(rx_at) = rx_at
            && progress
                .setup
                .is_some_and(|setup| rx_at >= self.shared.started + setup)
            && progress.first_tx_at.is_some_and(|at| rx_at >= at)
            && self.shared.feedback.context.target.is_some()
        {
            progress.eligible_rx_at =
                Some(progress.eligible_rx_at.map_or(rx_at, |at| at.max(rx_at)));
            if progress
                .published_rx_at
                .is_none_or(|at| now.saturating_duration_since(at) >= LIVE_RX_INTERVAL)
            {
                // A confirmed send can reconcile an already delivered reply; neither callback invents RX time.
                progress.published_rx_at = Some(now);
                self.observe(Observation::BusinessProgress { rx_at }, now, &mut progress);
            }
        }
        if now.saturating_duration_since(progress.window_start) > MAX_THROUGHPUT_DURATION {
            progress.window_start = now;
            progress.window_tx = 0;
            progress.window_rx = 0;
        }
        progress.window_tx = progress.window_tx.saturating_add(tx);
        progress.window_rx = progress.window_rx.saturating_add(rx);
        self.publish_window(&mut progress, now);
    }

    fn publish_window(&self, progress: &mut ReporterProgress, now: Instant) {
        let elapsed = now.saturating_duration_since(progress.window_start);
        if progress.setup.is_none()
            || !progress.first_response
            || progress.tx == 0
            || progress.rx == 0
            || elapsed < MIN_THROUGHPUT_DURATION
            || progress.window_tx.max(progress.window_rx) < MIN_THROUGHPUT_BYTES
        {
            return;
        }
        self.observe(
            Observation::Transfer {
                tx: progress.window_tx,
                rx: progress.window_rx,
                elapsed,
            },
            now,
            progress,
        );
        progress.window_tx = 0;
        progress.window_rx = 0;
        progress.window_start = now;
    }

    fn observe(&self, observation: Observation, now: Instant, progress: &mut ReporterProgress) {
        let feedback = &self.shared.feedback;
        let mut inner = feedback.state.inner.lock();
        if feedback.source == ScoreSource::HealthProbe
            && !inner
                .active_authority
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &feedback.authority))
        {
            return;
        }
        if matches!(&observation, Observation::Setup(_)) {
            budget::setup(&mut inner, &self.shared.work, now);
        }
        comparison::observe(
            &mut inner,
            &feedback.context,
            &feedback.attributions,
            (&progress.cells, progress.reporter_id),
            feedback.source,
            &observation,
            now,
        );
        let answered = match &observation {
            Observation::BusinessProgress { .. } => super::ScoreEvidenceQuestion::Availability,
            Observation::Response(_) => super::ScoreEvidenceQuestion::Response,
            _ => super::ScoreEvidenceQuestion::None,
        };
        ScorePolicyState::observe(
            &mut inner,
            &feedback.context,
            &feedback.attributions,
            &mut progress.cells,
            feedback.source,
            observation,
            now,
        );
        if feedback.source == ScoreSource::Traffic && answered != super::ScoreEvidenceQuestion::None
        {
            budget::answered(
                &inner,
                &feedback.context,
                &feedback.attributions,
                &progress.cells,
                &self.shared.work,
                answered,
                now,
            );
        }
    }

    /// Background refill retains attribution, never the business source or work.
    pub fn start_warmup(&self, context: ScoreSelectionContext) -> ScoreReporter {
        self.shared
            .feedback
            .clone()
            .with_context(context)
            .with_source(ScoreSource::Warmup)
            .start()
    }

    /// Complete a successful preparation that carried no application payload.
    pub fn finish_setup_only(&self) {
        self.finish_at(ScoreOutcome::Success, false, Instant::now());
    }

    pub fn finish(&self, outcome: ScoreOutcome) {
        self.finish_at(outcome, true, Instant::now());
    }

    pub(super) fn finish_at(&self, outcome: ScoreOutcome, count_usefulness: bool, now: Instant) {
        let mut progress = self.shared.progress.lock();
        if progress.finished {
            return;
        }
        progress.finished = true;
        self.publish_window(&mut progress, now);
        let feedback = &self.shared.feedback;
        let sample = FlowSample {
            outcome,
            setup: progress.setup,
            source: feedback.source,
            tx: progress.tx,
            rx: progress.rx,
            eligible_rx_at: progress.eligible_rx_at,
            count_usefulness,
        };
        if feedback.source == ScoreSource::HealthProbe
            && !matches!(
                outcome,
                ScoreOutcome::Success
                    | ScoreOutcome::Rejected
                    | ScoreOutcome::Cancelled
                    | ScoreOutcome::Shutdown
            )
        {
            feedback.state.fail_probe_at(
                &feedback.authority,
                &feedback.context,
                &feedback.attributions,
                &mut progress.cells,
                feedback.probe_scope(),
            );
        }
        feedback.state.finish_at(
            &feedback.context,
            &feedback.attributions,
            &mut progress.cells,
            &sample,
            now,
        );
        budget::finish(&feedback.state, &self.shared.work, outcome, now);
    }
}

impl Drop for ScoreReporter {
    fn drop(&mut self) {
        if self.shared.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.finish_at(ScoreOutcome::Cancelled, false, Instant::now());
        }
    }
}
