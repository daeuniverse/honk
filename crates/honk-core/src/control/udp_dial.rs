//! UDP transport preparation with absolute stagger offsets and an overall deadline.
//!
//! This module deliberately prepares only `PacketTransport`-equivalent values.
//! Lease binding, reply-socket creation, endpoint publication, and the first
//! application send remain in the caller after a winner has been finalized.

use crate::group::SelectionPlanMode;
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// One candidate transport-preparation future. The candidate index preserves
/// path-specific feedback when the same leaf appears through multiple groups.
/// `C` is the candidate: a node, or a dialing target that may be a route.
pub(super) type UdpPrepare<T, C> =
    Arc<dyn Fn(usize, C) -> Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send>> + Send + Sync>;

/// Reports a completed transport failure with its error.
pub(super) type UdpDialError<C> = Arc<dyn Fn(&C, &anyhow::Error) + Send + Sync>;

/// Fixed callbacks let the scheduler keep policy, health, and metric effects
/// at the integration boundary. Completed transport errors trigger
/// `on_dial_error` with the error, which names a chain's failed hop;
/// rejected, aborted and never-started candidates are neutral.
pub(super) struct UdpStaggerCallbacks<C> {
    pub(super) allows_target: Arc<dyn Fn(&C) -> bool + Send + Sync>,
    pub(super) is_eligible: Arc<dyn Fn(&C) -> bool + Send + Sync>,
    pub(super) on_dial_error: UdpDialError<C>,
    pub(super) on_attempt: Arc<dyn Fn() + Send + Sync>,
    pub(super) on_winner: Arc<dyn Fn() + Send + Sync>,
    pub(super) on_cancellation: Arc<dyn Fn() + Send + Sync>,
}

fn stagger_offset(index: usize) -> Duration {
    match index {
        0 => Duration::ZERO,
        1 => Duration::from_millis(30),
        index => Duration::from_millis(80 + 80 * (index as u64 - 2)),
    }
}

/// Start cold URLTest preparations at their absolute offsets, up to three at
/// once, and return the first successful still-eligible result.
///
/// Authoritative plans defensively use only their first node, even if a buggy
/// caller supplied more. A winner or deadline aborts and drains every started
/// loser before this function returns, so speculative transports and dial
/// permits cannot leak into the endpoint/lease lifecycle.
pub(super) async fn prepare_udp_plan<T, C>(
    mode: SelectionPlanMode,
    candidates: Vec<C>,
    deadline: tokio::time::Instant,
    prepare: UdpPrepare<T, C>,
    callbacks: UdpStaggerCallbacks<C>,
) -> anyhow::Result<Option<(C, T)>>
where
    T: Send + 'static,
    C: Clone + Send + 'static,
{
    let records_stagger_metrics = mode == SelectionPlanMode::ColdUrlTest;
    let candidates: Vec<C> = match mode {
        SelectionPlanMode::Authoritative => candidates.into_iter().take(1).collect(),
        SelectionPlanMode::ColdUrlTest => candidates,
    };
    let started_at = tokio::time::Instant::now();
    let mut next = 0;
    let mut tasks = FuturesUnordered::new();
    let mut rejection = None;
    let finalized = Arc::new(AtomicBool::new(false));

    let winner = 'schedule: loop {
        if tokio::time::Instant::now() >= deadline {
            break None;
        }

        // Fill available slots whose absolute deadline has passed. If a
        // completed attempt opened a slot after a deadline, this starts the
        // delayed candidate immediately instead of drifting the schedule.
        while next < candidates.len() && tasks.len() < 3 {
            let node = &candidates[next];
            if !(callbacks.is_eligible)(node) {
                next += 1;
                continue;
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break 'schedule None;
            }
            let due = started_at + stagger_offset(next);
            if now < due {
                break;
            }
            if !(callbacks.allows_target)(node) {
                rejection = Some(honk_outbound::proxy::PacketRejection::Policy.into());
                break 'schedule None;
            }
            let node = node.clone();
            next += 1;
            if records_stagger_metrics {
                (callbacks.on_attempt)();
            }
            let prepare = Arc::clone(&prepare);
            let finalized = Arc::clone(&finalized);
            tasks.push(
                std::panic::AssertUnwindSafe(async move {
                    if finalized.load(Ordering::Relaxed) {
                        return (node, None);
                    }
                    let result = prepare(next - 1, node.clone()).await;
                    (node, Some(result))
                })
                .catch_unwind(),
            );
        }

        if tasks.is_empty() && next == candidates.len() {
            break None;
        }
        let joined = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => break 'schedule None,
            joined = tasks.next(), if !tasks.is_empty() => joined,
            _ = tokio::time::sleep_until(started_at + stagger_offset(next)),
                if next < candidates.len() && tasks.len() < 3 => continue,
        };

        let Some(joined) = joined else {
            continue;
        };
        let Ok((node, Some(result))) = joined else {
            // A task panic/abort has no observed transport result and must not
            // affect health. Continue scheduling the remaining candidates.
            continue;
        };
        match result {
            Ok(value) if (callbacks.is_eligible)(&node) => {
                break Some((node, value));
            }
            Ok(_) => {
                // The node died between launch and completion. Dropping the
                // speculative transport is neutral; it never owned a lease.
            }
            Err(error) => {
                if honk_outbound::proxy::is_packet_rejection(&error) {
                    rejection = Some(error);
                    break 'schedule None;
                }
                (callbacks.on_dial_error)(&node, &error);
            }
        }
    };

    // Draining reports losers that already completed; a preparation first
    // polled after this point is never started.
    finalized.store(true, Ordering::Relaxed);
    let mut cancelled = 0;
    while let Some(Some(joined)) = tasks.next().now_or_never() {
        match joined {
            Ok((node, Some(Err(error)))) => {
                if honk_outbound::proxy::is_packet_rejection(&error) {
                    rejection.get_or_insert(error);
                } else {
                    (callbacks.on_dial_error)(&node, &error);
                }
            }
            Ok((_, None)) => cancelled += 1,
            Ok((_, Some(Ok(_)))) | Err(_) => {}
        }
    }
    if records_stagger_metrics {
        for _ in 0..cancelled + tasks.len() {
            (callbacks.on_cancellation)();
        }
    }
    tasks.clear();
    if let Some(error) = rejection {
        return Err(error);
    }
    if winner.is_some() && tokio::time::Instant::now() < deadline {
        if records_stagger_metrics {
            (callbacks.on_winner)();
        }
        Ok(winner)
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
