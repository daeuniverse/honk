//! Owned flow retirement shared by real and explicit model backends.

use super::{
    EbpfBackend, UdpDecisionCommitResult, UdpDecisionTransition, apply_udp_decision_transition,
    udp_state_is_legacy_userspace_owned, udp_state_is_staged, udp_state_is_userspace_owned,
};
use honk_ebpf_common::conn::{REDIRECT_TRACK_TIMEOUT_NS, ROUTING_HANDOFF_TIMEOUT_NS};
#[cfg(test)]
use honk_ebpf_common::redirect_need::TcpSocketBinding;
use honk_ebpf_common::{ConnState, RedirectEntry, RoutingHandoffEntry, TuplesKey};
use std::sync::atomic::{AtomicU64, Ordering};

pub const RETIRE_BATCH_CAPACITY: usize = 1024;

/// Cumulative conn-state entries physically deleted by userspace retirement,
/// for the janitor's occupancy gauge. eBPF-side inserts/deletes are counted by
/// the `CONN_STATE_OCCUPANCY` map; every backend `retire_batch` adds its own
/// deletes here (including those before a failure) so no caller counts twice.
pub static USERSPACE_CONN_STATE_DELETES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct FlowExpiryHint {
    pub key: TuplesKey,
    pub incarnation: u64,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub enum TcpSocketOwnership {
    Kernel(TcpSocketBinding),
    Model,
}

#[derive(Debug, Clone, Copy)]
pub struct RetireRequest<'a> {
    pub key: TuplesKey,
    pub kind: RetireKind<'a>,
}

impl<'a> RetireRequest<'a> {
    /// An unpublished UDP staging owner (Preparing, Pending or Aborted) under `token`.
    pub fn pending_udp(key: TuplesKey, token: u32, incarnation: Option<u64>) -> Self {
        Self {
            key,
            kind: RetireKind::Udp {
                token,
                incarnation,
                pending_only: true,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RetireKind<'a> {
    Tcp {
        incarnation: u64,
    },
    Udp {
        token: u32,
        incarnation: Option<u64>,
        pending_only: bool,
    },
    ExpiredConn {
        expected: &'a ConnState,
        expired_before_ns: u64,
    },
    ExpiredRedirect {
        expected: &'a RedirectEntry,
        expired_before_ns: u64,
    },
    ExpiredHandoff {
        expected: &'a RoutingHandoffEntry,
        expired_before_ns: u64,
    },
    ExpiryHint {
        incarnation: u64,
        now_ns: u64,
    },
}

/// Owner entries a request's mutation decision reads, so executors fetch only those.
pub(crate) struct OwnerReads {
    pub conn: bool,
    pub handoff: bool,
    pub redirect: bool,
}

impl RetireKind<'_> {
    pub(crate) fn owner_reads(&self) -> OwnerReads {
        match *self {
            Self::ExpiredRedirect { .. } => OwnerReads {
                conn: false,
                handoff: false,
                redirect: true,
            },
            Self::ExpiredHandoff { .. } => OwnerReads {
                conn: false,
                handoff: true,
                redirect: false,
            },
            Self::Tcp { .. }
            | Self::Udp { .. }
            | Self::ExpiredConn { .. }
            | Self::ExpiryHint { .. } => OwnerReads {
                conn: true,
                handoff: true,
                redirect: true,
            },
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetireCounts {
    pub conn: u64,
    pub redirect: u64,
    pub handoff: u64,
}

impl RetireCounts {
    /// Deletes performed after `before` was captured from the same running total.
    pub(crate) fn since(self, before: Self) -> Self {
        Self {
            conn: self.conn - before.conn,
            redirect: self.redirect - before.redirect,
            handoff: self.handoff - before.handoff,
        }
    }
}

impl std::ops::AddAssign for RetireCounts {
    fn add_assign(&mut self, other: Self) {
        self.conn += other.conn;
        self.redirect += other.redirect;
        self.handoff += other.handoff;
    }
}

/// Per-request result of `retire_batch`. `NotRun` is the pre-filled value and
/// survives only where the batch failed first, so it is never settled.
/// `ConnRetired` means this request physically deleted the flow's conn entry;
/// `Done(Applied)` acknowledges only auxiliary retirement, not a conn deletion.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RetireOutcome {
    #[default]
    NotRun,
    ConnRetired,
    Done(UdpDecisionCommitResult),
}

impl RetireOutcome {
    /// The requested owner is gone: removed, already absent, or replaced by a
    /// newer incarnation that retirement must not touch.
    pub fn settled(self) -> bool {
        use UdpDecisionCommitResult::*;
        matches!(
            self,
            Self::ConnRetired | Self::Done(Applied | Missing | Superseded)
        )
    }
}

impl From<UdpDecisionCommitResult> for RetireOutcome {
    fn from(result: UdpDecisionCommitResult) -> Self {
        Self::Done(result)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("flow retirement failed after {counts:?}: {source:#}")]
pub struct RetireError {
    pub counts: RetireCounts,
    #[source]
    pub source: anyhow::Error,
}

#[cfg(feature = "legacy-tc")]
pub(crate) fn tuple_matches(a: &TuplesKey, b: &TuplesKey) -> bool {
    (unsafe { a.src_ip.u6_addr8 == b.src_ip.u6_addr8 && a.dst_ip.u6_addr8 == b.dst_ip.u6_addr8 })
        && a.src_port == b.src_port
        && a.dst_port == b.dst_port
        && a.l4proto == b.l4proto
}

fn conn_matches(a: &ConnState, b: &ConnState, cutoff: u64) -> bool {
    a.last_seen_ns <= cutoff
        && a.last_seen_ns == b.last_seen_ns
        && a.incarnation == b.incarnation
        && a.state == b.state
        && a.decision_token == b.decision_token
        && a.is_wan_ingress_direction == b.is_wan_ingress_direction
        && unsafe { a.meta.raw == b.meta.raw }
        && a.mac == b.mac
        && a.pname == b.pname
        && a.pid == b.pid
        && a.trace_id == b.trace_id
}

fn redirect_matches(a: &RedirectEntry, b: &RedirectEntry, cutoff: u64) -> bool {
    a.last_seen_ns <= cutoff
        && a.last_seen_ns == b.last_seen_ns
        && a.incarnation == b.incarnation
        && a.decision_token == b.decision_token
        && a.dmac == b.dmac
        && a.smac == b.smac
        && a.from_wan == b.from_wan
        && a.outbound == b.outbound
        && a.ifindex == b.ifindex
}

fn handoff_matches(a: &RoutingHandoffEntry, b: &RoutingHandoffEntry, cutoff: u64) -> bool {
    let (x, y) = (&a.result, &b.result);
    a.last_seen_ns <= cutoff
        && a.last_seen_ns == b.last_seen_ns
        && a.incarnation == b.incarnation
        && a.routing_generation == b.routing_generation
        && a.trace_id == b.trace_id
        && x.mark == y.mark
        && x.must == y.must
        && x.mac == y.mac
        && x.outbound == y.outbound
        && x.pname == y.pname
        && x.pid == y.pid
        && x.dscp == y.dscp
        && x.decision_token == y.decision_token
}

pub(crate) fn conn_state_timeout_ns(proto: u8, state: &ConnState) -> u64 {
    use honk_ebpf_common::conn::{
        TCP_CONN_STATE_CLOSING_TIMEOUT_NS, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState,
        UDP_CONN_STATE_TIMEOUT_NS,
    };
    if proto == libc::IPPROTO_UDP as u8 {
        if state.state == honk_ebpf_common::UdpDecisionState::Aborted as u8 {
            0
        } else {
            UDP_CONN_STATE_TIMEOUT_NS
        }
    } else if state.state == TcpState::TcpStateClosing as u8 {
        TCP_CONN_STATE_CLOSING_TIMEOUT_NS
    } else {
        TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
    }
}

pub(crate) fn conn_expired(proto: u8, state: &ConnState, now_ns: u64) -> bool {
    let timeout = conn_state_timeout_ns(proto, state);
    timeout == 0 || now_ns.saturating_sub(state.last_seen_ns) > timeout
}

fn validate_conn_retirement(
    state: &ConnState,
    proto: u8,
    kind: RetireKind<'_>,
) -> Result<(), UdpDecisionCommitResult> {
    use UdpDecisionCommitResult::*;
    match kind {
        RetireKind::Tcp { incarnation } => {
            if state.incarnation != incarnation {
                return Err(Superseded);
            }
        }
        RetireKind::Udp {
            token,
            incarnation,
            pending_only,
        } => {
            if state.decision_token != token
                || incarnation.is_some_and(|id| id != state.incarnation)
            {
                return Err(if pending_only {
                    TokenMismatch
                } else {
                    Superseded
                });
            }
            if pending_only {
                if !udp_state_is_staged(state.state) {
                    return Err(StateMismatch);
                }
            } else if token != 0 {
                if !udp_state_is_userspace_owned(state.state) {
                    return Err(StateMismatch);
                }
            } else if !udp_state_is_legacy_userspace_owned(state)
                && !(state.state == honk_ebpf_common::UdpDecisionState::Aborted as u8
                    && incarnation == Some(state.incarnation))
            {
                return Err(Superseded);
            }
        }
        RetireKind::ExpiredConn {
            expected,
            expired_before_ns,
        } => {
            let cutoff = if proto == libc::IPPROTO_UDP as u8
                && state.state == honk_ebpf_common::UdpDecisionState::Aborted as u8
            {
                u64::MAX
            } else {
                expired_before_ns
            };
            if !conn_matches(state, expected, cutoff) {
                return Err(Superseded);
            }
        }
        RetireKind::ExpiryHint {
            incarnation,
            now_ns,
        } => {
            if state.incarnation != incarnation {
                return Err(Superseded);
            }
            if !conn_expired(proto, state, now_ns) {
                return Err(StateMismatch);
            }
        }
        _ => unreachable!("auxiliary retirement has no conn owner"),
    }
    Ok(())
}

fn auxiliaries_match(
    incarnation: u64,
    token: u32,
    handoff: Option<&RoutingHandoffEntry>,
    track: Option<&RedirectEntry>,
) -> bool {
    handoff.is_none_or(|entry| {
        entry.incarnation == incarnation && entry.result.decision_token == token
    }) && track
        .is_none_or(|entry| entry.incarnation == incarnation && entry.decision_token == token)
}

fn expiry_hint_auxiliary_plan(
    incarnation: u64,
    now_ns: u64,
    owners: &Owners<'_>,
) -> Result<RetirePlan, UdpDecisionCommitResult> {
    use UdpDecisionCommitResult::*;
    let (current, handoff, track) = (owners.conn, owners.handoff, owners.redirect);
    let unchanged = if current.is_none() && handoff.is_none() && track.is_none() {
        Missing
    } else {
        StateMismatch
    };
    let handoff = handoff.filter(|entry| entry.incarnation == incarnation);
    let track = track.filter(|entry| entry.incarnation == incarnation);
    let token = current
        .map(|state| state.decision_token)
        .or_else(|| handoff.map(|entry| entry.result.decision_token))
        .or_else(|| track.map(|entry| entry.decision_token));
    if token.is_some_and(|token| !auxiliaries_match(incarnation, token, handoff, track)) {
        return Err(TokenMismatch);
    }
    Ok(RetirePlan {
        handoff: handoff.is_some_and(|entry| {
            now_ns.saturating_sub(entry.last_seen_ns) > ROUTING_HANDOFF_TIMEOUT_NS
        }),
        redirect: track.is_some_and(|entry| {
            now_ns.saturating_sub(entry.last_seen_ns) > REDIRECT_TRACK_TIMEOUT_NS
        }),
        ..RetirePlan::auxiliary(unchanged)
    })
}

/// Post-grace owner snapshots for one request; only the entries named by
/// `RetireKind::owner_reads` are populated.
pub(crate) struct Owners<'a> {
    pub conn: Option<&'a ConnState>,
    pub handoff: Option<&'a RoutingHandoffEntry>,
    pub redirect: Option<&'a RedirectEntry>,
}

/// Mutation set for an authorized retirement. Executors apply it in field
/// order (auxiliaries, conn) so a failure part-way never leaves a conn whose
/// auxiliaries survive it, and count each delete as it happens.
pub(crate) struct RetirePlan {
    pub handoff: bool,
    pub redirect: bool,
    pub conn: bool,
    /// Outcome when the deciding removal finds its entry already gone.
    unchanged: UdpDecisionCommitResult,
}

impl RetirePlan {
    fn auxiliary(unchanged: UdpDecisionCommitResult) -> Self {
        Self {
            handoff: false,
            redirect: false,
            conn: false,
            unchanged,
        }
    }

    /// `removed` is what the executor just deleted for this request.
    pub(crate) fn outcome(&self, removed: RetireCounts) -> RetireOutcome {
        if self.conn && removed.conn != 0 {
            RetireOutcome::ConnRetired
        } else if !self.conn && removed.handoff + removed.redirect != 0 {
            UdpDecisionCommitResult::Applied.into()
        } else {
            self.unchanged.into()
        }
    }
}

/// Authorize one retirement from post-grace owner snapshots, or refuse with
/// the outcome that leaves every map untouched. Real executes the plan after
/// fence and grace; the model executes it on its own maps.
pub(crate) fn plan_retirement(
    request: &RetireRequest<'_>,
    owners: &Owners<'_>,
) -> Result<RetirePlan, UdpDecisionCommitResult> {
    use UdpDecisionCommitResult::*;
    let proto = request.key.l4proto;
    let conn_plan = |kind| -> Result<RetirePlan, UdpDecisionCommitResult> {
        let state = owners.conn.ok_or(Missing)?;
        validate_conn_retirement(state, proto, kind)?;
        if !auxiliaries_match(
            state.incarnation,
            state.decision_token,
            owners.handoff,
            owners.redirect,
        ) {
            return Err(TokenMismatch);
        }
        Ok(RetirePlan {
            handoff: owners.handoff.is_some(),
            redirect: owners.redirect.is_some(),
            conn: true,
            ..RetirePlan::auxiliary(Missing)
        })
    };
    match request.kind {
        RetireKind::ExpiredRedirect {
            expected,
            expired_before_ns,
        } => match owners.redirect {
            None => Err(Missing),
            Some(current) if redirect_matches(current, expected, expired_before_ns) => {
                Ok(RetirePlan {
                    redirect: true,
                    ..RetirePlan::auxiliary(Applied)
                })
            }
            Some(_) => Err(Superseded),
        },
        RetireKind::ExpiredHandoff {
            expected,
            expired_before_ns,
        } => match owners.handoff {
            None => Err(Missing),
            Some(current) if handoff_matches(current, expected, expired_before_ns) => {
                Ok(RetirePlan {
                    handoff: true,
                    ..RetirePlan::auxiliary(Applied)
                })
            }
            Some(_) => Err(Superseded),
        },
        RetireKind::ExpiryHint {
            incarnation,
            now_ns,
        } => match conn_plan(request.kind) {
            Err(Missing | StateMismatch) => expiry_hint_auxiliary_plan(incarnation, now_ns, owners),
            plan => plan,
        },
        RetireKind::Tcp { .. } | RetireKind::Udp { .. } | RetireKind::ExpiredConn { .. } => {
            conn_plan(request.kind)
        }
    }
}

pub(crate) enum RedirectEffect {
    Remove,
    Rewrite(RedirectEntry),
}

/// Mutation set for one token-bound UDP decision commit.
pub(crate) struct UdpCommitPlan {
    pub state: ConnState,
    pub remove_handoff: bool,
    pub redirect: Option<RedirectEffect>,
}

/// Authorize a UDP decision transition from coherent snapshots whose conn token
/// and incarnation the caller already matched, or refuse.
pub(crate) fn plan_udp_commit(
    mut state: ConnState,
    token: u32,
    transition: UdpDecisionTransition,
    handoff: Option<&RoutingHandoffEntry>,
    track: Option<&RedirectEntry>,
) -> Result<UdpCommitPlan, UdpDecisionCommitResult> {
    apply_udp_decision_transition(&mut state, transition)?;
    if !auxiliaries_match(state.incarnation, token, handoff, track) {
        return Err(UdpDecisionCommitResult::TokenMismatch);
    }
    let initial = !matches!(transition, UdpDecisionTransition::ActivateDirect(_));
    if initial && (handoff.is_none() || track.is_none()) {
        return Err(UdpDecisionCommitResult::Missing);
    }
    // ArmDirect removed both auxiliaries. Activation must never turn an
    // unexpected publication into unfenced map reclamation.
    if !initial && (handoff.is_some() || track.is_some()) {
        return Err(UdpDecisionCommitResult::StateMismatch);
    }
    Ok(UdpCommitPlan {
        state,
        remove_handoff: handoff.is_some(),
        redirect: track.map(|track| match transition {
            UdpDecisionTransition::ActivateProxy(outbound, _) => {
                RedirectEffect::Rewrite(RedirectEntry { outbound, ..*track })
            }
            _ => RedirectEffect::Remove,
        }),
    })
}

/// Retire scanned staged UDP flows, `(key, token, incarnation)`, in
/// capacity-bounded batches through the backend's own fenced executor.
pub(crate) fn retire_staged_udp(
    staged: &[(TuplesKey, u32, u64)],
    mut retire: impl FnMut(
        &[RetireRequest<'_>],
        &mut [RetireOutcome],
    ) -> Result<RetireCounts, RetireError>,
) -> anyhow::Result<()> {
    let capacity = RETIRE_BATCH_CAPACITY.min(staged.len());
    let mut requests = Vec::with_capacity(capacity);
    let mut outcomes = vec![RetireOutcome::NotRun; capacity];
    for chunk in staged.chunks(RETIRE_BATCH_CAPACITY) {
        requests.clear();
        requests.extend(chunk.iter().map(|(key, token, incarnation)| {
            RetireRequest::pending_udp(*key, *token, Some(*incarnation))
        }));
        let outcomes = &mut outcomes[..chunk.len()];
        retire(&requests[..chunk.len()], outcomes)?;
        for (outcome, (_, token, _)) in outcomes.iter().zip(chunk) {
            // A token-zero claim can finish native publication between scan and fence.
            anyhow::ensure!(
                outcome.settled()
                    || (*token == 0
                        && *outcome == RetireOutcome::Done(UdpDecisionCommitResult::StateMismatch)),
                "UDP staging quiescence rejected retirement: {outcome:?}"
            );
        }
    }
    Ok(())
}

/// Retire one unpublished UDP token with exact-owner semantics.
pub fn retire_pending(
    backend: &mut dyn EbpfBackend,
    key: TuplesKey,
    token: u32,
    incarnation: Option<u64>,
) -> Result<RetireOutcome, RetireError> {
    let mut outcome = [RetireOutcome::NotRun];
    backend.retire_batch(
        &[RetireRequest::pending_udp(key, token, incarnation)],
        &mut outcome,
    )?;
    Ok(outcome[0])
}

fn retired_counts(result: &Result<RetireCounts, RetireError>) -> RetireCounts {
    match result {
        Ok(counts) => *counts,
        Err(error) => error.counts,
    }
}

fn conn_deletes(result: &Result<RetireCounts, RetireError>) -> u64 {
    retired_counts(result).conn
}

#[cfg(any(feature = "legacy-tc", test))]
/// Redirect and handoff elements one backend's userspace removed. The datapath
/// only inserts them, so this is what `aux_occupancy` subtracts from its counters.
#[derive(Debug, Default)]
pub(crate) struct AuxDeleteTally {
    pub redirect: u64,
    pub handoff: u64,
}

#[cfg(any(feature = "legacy-tc", test))]
impl AuxDeleteTally {
    /// Count a finished batch, including deletes made before a failure.
    pub(crate) fn record(&mut self, result: &Result<RetireCounts, RetireError>) {
        let counts = retired_counts(result);
        self.redirect += counts.redirect;
        self.handoff += counts.handoff;
    }
}

/// Count a finished batch once, at the backend's execution boundary. Deletes
/// made before a failure are real, so errors contribute their partial counts.
pub(crate) fn account_retirement(result: &Result<RetireCounts, RetireError>) {
    USERSPACE_CONN_STATE_DELETES.fetch_add(conn_deletes(result), Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn retire_fixture(
    backend: &mut dyn EbpfBackend,
    key: TuplesKey,
    kind: RetireKind<'_>,
) -> (RetireCounts, UdpDecisionCommitResult) {
    let mut outcomes = [RetireOutcome::NotRun];
    let counts = backend
        .retire_batch(&[RetireRequest { key, kind }], &mut outcomes)
        .unwrap();
    let result = match outcomes[0] {
        RetireOutcome::ConnRetired => UdpDecisionCommitResult::Applied,
        RetireOutcome::Done(result) => result,
        RetireOutcome::NotRun => panic!("singleton retirement skipped a request"),
    };
    (counts, result)
}

#[cfg(test)]
mod tests;
