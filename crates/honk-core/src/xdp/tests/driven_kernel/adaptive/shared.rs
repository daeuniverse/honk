use super::*;
use crate::xdp::polling::testing::{Exit, PendingWait, Point};

fn published(snapshot: &Snapshot) -> u64 {
    snapshot
        .queues
        .iter()
        .map(|queue| queue.counters.published_packets)
        .sum()
}

fn drained(state: &State) -> bool {
    !state.polling.pollable
        && state.polling.waiting == 0
        && state.polling.pending == 0
        && state.polling.queues.iter().all(|queue| {
            queue.counters.submitted == queue.counters.completed
                && queue.rings.rx_producer == queue.rings.rx_consumer
                && queue.rings.tx_producer == queue.rings.tx_consumer
                && queue.rings.cq_producer == queue.rings.cq_consumer
        })
}

fn queue_rx_advanced(before: &Snapshot, after: &Snapshot) -> bool {
    !before.queues.is_empty()
        && before.queues.len() == after.queues.len()
        && before.queues.iter().all(|old| {
            after.queues.iter().any(|new| {
                (new.device.as_str(), new.id) == (old.device.as_str(), old.id)
                    && new.counters.rx > old.counters.rx
            })
        })
}

fn wire_count(status: &serde_json::Value, actor: &str, counter: &str) -> anyhow::Result<u64> {
    status[actor][counter]
        .as_u64()
        .with_context(|| format!("missing actual {actor}/{counter} wire count: {status}"))
}

async fn sleep_before(deadline: Instant, duration: Duration) -> anyhow::Result<()> {
    let until = Instant::now()
        .checked_add(duration)
        .context("real pause overflow")?;
    ensure!(
        until < deadline,
        "real pause does not fit the unchanged fixture window"
    );
    tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
    Ok(())
}

async fn mode(owner: &mut Owner, requested: PollMode) -> anyhow::Result<State> {
    let mut config = owner.config.clone();
    config.datapath.as_mut().unwrap().poll_mode = Some(requested);
    owner.reload(config).await?;
    owner
        .wait_for(|state| state.polling.mode == requested)
        .await
}

async fn calibrated(
    owner: &mut Owner,
    artifacts: &Path,
    label: &str,
    requested: PollMode,
) -> anyhow::Result<State> {
    let mut config = owner.config.clone();
    let datapath = config.datapath.as_mut().unwrap();
    datapath.poll_mode = Some(requested);
    datapath.busy_poll.as_mut().unwrap().calibration = None;
    let expected = polling::parameter_digest(datapath.busy_poll.as_ref().unwrap());
    owner.reload(config).await?;
    owner
        .wait_for(|state| {
            state.polling.mode == requested
                && state.polling.parameter_sha256.as_deref() == Some(expected.as_str())
        })
        .await?;
    owner.calibrate(artifacts, label).await
}

async fn qualified(owner: &Owner, before: &State) -> anyhow::Result<State> {
    let windows = owner
        .config
        .datapath
        .as_ref()
        .unwrap()
        .busy_poll
        .as_ref()
        .unwrap()
        .enter_windows;
    owner
        .wait_for(|state| {
            state.polling.high
                && (state.polling.rx_high_windows == windows
                    || state.polling.tx_high_windows == windows)
                && state.polling.busy_entries > before.polling.busy_entries
                && state.polling.probe_rounds > before.polling.probe_rounds
                && state.polling.qualified_rx > before.polling.qualified_rx
                && state.polling.published_tx > before.polling.published_tx
        })
        .await
}

async fn parked(owner: &Owner) -> anyhow::Result<(State, PendingWait)> {
    let state = owner.wait_for(drained).await?;
    ensure!(
        state.attempts.started == 0
            && state.attempts.completed == 0
            && state.attempts.canceled == 0,
        "Endpoint-only owner unexpectedly acquired Core policy: {state:?}"
    );
    owner.ready.control.clear_pending();
    // Publication must wake the idle owner before any already-armed driver or
    // maintenance timer can explain service.
    let state = owner.state().await?;
    loop {
        if let Some(wait) = owner.ready.control.pending_wait()
            && !wait.reading
            && wait.idle_ports
            && !wait.pending_outputs
        {
            ensure!(
                wait.driver_deadline.is_none_or(|due| due > Instant::now())
                    && wait
                        .armed_deadline
                        .is_none_or(|due| due.into_std() > Instant::now()),
                "preexisting timer was already due at the actual Pending boundary: {wait:?}"
            );
            return Ok((state, wait));
        }
        ensure!(
            Instant::now() < owner.deadline,
            "Endpoint owner never reached genuine Pending: last={:?}, before={state:?}",
            owner.ready.control.pending_wait()
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn exit_after(
    rig: &Rig,
    control: &Control,
    held: &PollBudgetSnapshot,
    snapshot: &Snapshot,
    reason: &str,
) -> anyhow::Result<Exit> {
    loop {
        let ledger = rig.budget.snapshot();
        if ledger.active_id.is_none()
            && let Some(exit) = control.last_exit()
            && exit.reason == reason
            && exit.probe_rounds == snapshot.probe_rounds
            && exit.settlement.is_some_and(|settlement| {
                ledger.charged_ns.checked_sub(held.charged_ns)
                    == Some(u128::from(settlement.charged_ns))
            })
        {
            ensure!(
                exit.published_packets == published(snapshot)
                    && exit.rx_packets
                        == snapshot
                            .queues
                            .iter()
                            .map(|queue| queue.counters.rx)
                            .sum::<u64>()
                    && exit.cursors == snapshot.cursors,
                "stale device work followed the held segment: {exit:?}, {snapshot:?}"
            );
            let settlement = exit
                .settlement
                .context("real Busy interval was not measured and settled")?;
            ensure!(
                settlement.reserved_ns == held.reserved_ns
                    && settlement.elapsed_ns > 0
                    && settlement.charged_ns == settlement.elapsed_ns,
                "real elapsed interval was not charged in full: {settlement:?}, {held:?}"
            );
            return Ok(exit);
        }
        ensure!(
            Instant::now() < rig.deadline,
            "held real interval did not exit as {reason}"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

fn held_accounting(before: &PollBudgetSnapshot, after: &PollBudgetSnapshot) -> anyhow::Result<()> {
    ensure!(
        before.active_id.is_some()
            && after.active_id == before.active_id
            && after.active_start_ns == before.active_start_ns
            && after.active_policy_revision == before.active_policy_revision
            && after.reserved_ns == before.reserved_ns
            && after.charged_ns == before.charged_ns
            && after.next_refill_ns == before.next_refill_ns
            && after.net_ns <= before.net_ns
            && after.forfeited_grants == before.forfeited_grants
            && after.forfeited_ns == before.forfeited_ns,
        "an outstanding actual reservation was advanced, replaced, or refunded: {before:?}, {after:?}"
    );
    Ok(())
}

fn no_remint(before: &PollBudgetSnapshot, after: &PollBudgetSnapshot) -> anyhow::Result<()> {
    // Both owners are drained Event consumers here; no reserve/publication can earn old-policy time.
    ensure!(
        before.active_id.is_none()
            && after.active_id.is_none()
            && after.net_ns == before.net_ns
            && after.debt_ns == before.debt_ns
            && after.capacity_ns == before.capacity_ns
            && after.next_refill_ns == before.next_refill_ns
            && after.process_revision == before.process_revision
            && after.charged_ns == before.charged_ns
            && after.overrun_ns == before.overrun_ns
            && after.forfeited_grants == before.forfeited_grants
            && after.forfeited_ns == before.forfeited_ns
            && after.disabled_reason.is_none()
            && !after.publisher_closed,
        "participant reconstruction reminted accounting without a time-earning operation: {before:?}, {after:?}"
    );
    Ok(())
}

async fn natural_and_fair(rig: &mut Rig) -> anyhow::Result<()> {
    rig.pump.set("a", true).await?;
    rig.pump.set("b", true).await?;
    let before_a = rig.a().state().await?;
    let before_b = rig.b().state().await?;
    rig.a().ready.fairness.send(true)?;
    rig.b().ready.fairness.send(true)?;
    let a = qualified(rig.a(), &before_a).await?;
    let b = qualified(rig.b(), &before_b).await?;
    ensure!(
        a.fair_turns > before_a.fair_turns
            && a.fair_thread == Some(a.owner_thread)
            && b.fair_turns > before_b.fair_turns
            && b.fair_thread == Some(b.owner_thread),
        "Busy and competitor did not share an actual LocalSet/OS-thread opportunity: {a:?}, {b:?}"
    );
    let a = rig
        .a()
        .wait_for(|state| queue_rx_advanced(&before_a.polling, &state.polling))
        .await?;
    let b = rig
        .b()
        .wait_for(|state| queue_rx_advanced(&before_b.polling, &state.polling))
        .await?;
    for name in ["dut0", "dut1"] {
        ensure!(
            a.polling
                .queues
                .iter()
                .any(|queue| queue.device == name && queue.counters.published_packets > 0),
            "actual multi-device egress was not exercised on {name}: {a:?}"
        );
    }
    ensure!(
        a.polling.queues.iter().any(|queue| queue.id != 0)
            && b.polling.queues.iter().any(|queue| queue.id != 0),
        "owned traffic did not exercise the admitted nonzero queues: {a:?}, {b:?}"
    );
    let status = rig.pump.status().await?;
    for actor in ["a", "b"] {
        for counter in ["sent", "received", "upstream"] {
            ensure!(
                wire_count(&status, actor, counter)? > 0,
                "missing actual {actor}/{counter} UDP wire evidence"
            );
        }
    }
    rig.tcp()
        .step("CONNECT", "shared-fair", "CONNECTED")
        .await?;
    rig.tcp().step("APP", "shared-fair", "APP").await?;
    rig.tcp()
        .step("RETRANSMIT", "shared-fair", "RETRANSMITTED")
        .await?;
    rig.tcp().step("CLOSE", "shared-fair", "CLOSED").await?;
    let after = rig.a().state().await?;
    ensure!(
        after.fair_turns > a.fair_turns
            && after.polling.probe_rounds > a.polling.probe_rounds
            && after.fair_thread == Some(after.owner_thread)
            && published(&after.polling) > published(&a.polling),
        "real control/bulk/close wire progress did not coexist with same-worker Busy fairness: {after:?}"
    );
    loop {
        if let Some(exit) = rig.a().ready.control.last_bounded_cut()
            && exit.reason == "bounded_segment_limit"
            && exit.cursors != exit.start_cursors
            && exit.rx_packets > exit.start_rx
            && exit.rx_packets
                > before_a
                    .polling
                    .queues
                    .iter()
                    .map(|queue| queue.counters.rx)
                    .sum::<u64>()
        {
            ensure!(
                exit.settlement.is_some() && exit.published_packets >= published(&before_a.polling),
                "rotating cursor was not captured at a real work-consuming early cut: {exit:?}"
            );
            break;
        }
        ensure!(
            Instant::now() < rig.deadline,
            "real multi-queue traffic never exposed a rotating bounded early cut"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    rig.a().ready.fairness.send(false)?;
    rig.b().ready.fairness.send(false)?;
    Ok(())
}

async fn idle_and_endpoint_publication(rig: &mut Rig) -> anyhow::Result<()> {
    mode(rig.a_mut(), PollMode::Event).await?;
    let mut config = rig.b().config.clone();
    let busy = config
        .datapath
        .as_mut()
        .unwrap()
        .busy_poll
        .as_mut()
        .unwrap();
    busy.pps_enter = 2;
    busy.pps_exit = 1;
    busy.calibration = None;
    rig.b_mut().reload(config).await?;
    let artifacts = rig.artifacts.clone();
    let initial = calibrated(
        rig.b_mut(),
        &artifacts,
        "shared-low-rate",
        PollMode::Adaptive,
    )
    .await?;
    qualified(rig.b(), &initial).await?;
    let control = Arc::clone(&rig.b().ready.control);
    let idle_before = control.idle_high();
    rig.pump.set("b", false).await?;
    rig.b().wait_for(drained).await?;
    // Valid unmatched RSTs produce actual RX service rounds, but no admitted
    // receive or full TX packet. Idle observation requests are not the stimulus.
    rig.pump.low("b").await?;
    let mut returned_empty = false;
    let low = loop {
        let state = rig.b().state().await?;
        let idle = control.idle_high();
        returned_empty |=
            !state.polling.pollable && idle.0 > idle_before.0 && idle.1 == idle_before.1;
        if drained(&state)
            && state.polling.low
            && !state.polling.high
            && state.polling.rx_high_windows == 0
            && state.polling.tx_high_windows == 0
        {
            break state;
        }
        ensure!(
            Instant::now() < rig.deadline,
            "stopped real traffic never lost directional qualification: {state:?}"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    ensure!(
        returned_empty && low.polling.reason == "pps_dwell_incomplete",
        "traffic stop did not expose an empty/no-pollable Event return followed by actual low dwell: {low:?}"
    );
    ensure!(
        control.idle_high().1 == idle_before.1,
        "a naturally qualified owner reserved Busy time without any pollable device obligation"
    );
    let baseline = low
        .polling
        .clock
        .context("low dwell has no actual clock sample")?
        .boot_ns;
    let window = u64::from(
        rig.b()
            .config
            .datapath
            .as_ref()
            .unwrap()
            .busy_poll
            .as_ref()
            .unwrap()
            .observation_window_us,
    ) * 1_000;
    let unadmitted = rig
        .b()
        .wait_for(|state| {
            state.polling.low
                && state
                    .polling
                    .clock
                    .is_some_and(|clock| clock.boot_ns.saturating_sub(baseline) >= window)
                && state
                    .polling
                    .queues
                    .iter()
                    .map(|queue| queue.counters.rx)
                    .sum::<u64>()
                    > low
                        .polling
                        .queues
                        .iter()
                        .map(|queue| queue.counters.rx)
                        .sum::<u64>()
        })
        .await?;
    ensure!(
        unadmitted.polling.qualified_rx == low.polling.qualified_rx
            && unadmitted.polling.published_tx == low.polling.published_tx,
        "valid unadmitted input fabricated RX/TX qualification: {low:?}, {unadmitted:?}"
    );
    rig.pump.set("b", false).await?;
    rig.b().wait_for(drained).await?;
    let (parked_state, wait) = parked(rig.b()).await?;
    let revision = control.serviced_revision();
    ensure!(
        revision == parked_state.polling.local_revision && parked_state.attempts.started == 0,
        "Endpoint-only baseline was not actually serviced before Pending"
    );
    let mut event = rig.b().config.clone();
    event.datapath.as_mut().unwrap().poll_mode = Some(PollMode::Event);
    rig.b_mut().reload(event).await?;
    // Only the actual reload may notify the owner until this passive service observation succeeds.
    let serviced_at = loop {
        let now = Instant::now();
        if control.serviced_revision() > revision {
            break now;
        }
        ensure!(
            now < rig.deadline,
            "accepted Endpoint-only publication never reached Runtime::poll_service"
        );
        ensure!(
            wait.driver_deadline.is_none_or(|due| now < due),
            "publication did not service before the preexisting driver timer: {wait:?}"
        );
        tokio::time::sleep(Duration::from_micros(100)).await;
    };
    ensure!(
        wait.driver_deadline.is_none_or(|due| serviced_at < due)
            && wait
                .armed_deadline
                .is_none_or(|due| serviced_at < due.into_std()),
        "a preexisting timer could explain Endpoint publication service: {wait:?}"
    );
    let event = rig.b().state().await?;
    ensure!(
        event.polling.mode == PollMode::Event
            && event.polling.local_revision > revision
            && event.attempts.started == 0
            && event.attempts.completed == 0
            && event.attempts.canceled == 0,
        "accepted reload was not consumed by the reader-free Endpoint owner: {event:?}"
    );
    let initial_a = calibrated(
        rig.a_mut(),
        &artifacts,
        "shared-a-after-idle",
        PollMode::Adaptive,
    )
    .await?;
    qualified(rig.a(), &initial_a).await?;
    let initial = calibrated(
        rig.b_mut(),
        &artifacts,
        "shared-after-idle",
        PollMode::Adaptive,
    )
    .await?;
    rig.pump.set("b", true).await?;
    qualified(rig.b(), &initial).await?;
    Ok(())
}

async fn shared_overrun_and_rebuild(rig: &mut Rig) -> anyhow::Result<()> {
    let control = Arc::clone(&rig.b().ready.control);
    let pause = control.arm(Point::Reserved, rig.deadline);
    let snapshot = pause.wait()?;
    let held = rig.budget.snapshot();
    ensure!(
        held.active_id.is_some() && held.reserved_ns > 0 && held.disabled_reason.is_none(),
        "B did not hold one actual process reservation: {held:?}"
    );
    let before = rig.a().state().await?;
    let wire_before = rig.pump.status().await?;
    let competing = rig
        .a()
        .wait_for(|state| {
            state.polling.reason == "busy_interval_outstanding"
                && state.polling.published_tx > before.polling.published_tx
                && state.polling.qualified_rx > before.polling.qualified_rx
        })
        .await?;
    ensure!(
        competing.polling.busy_entries == before.polling.busy_entries
            && competing.polling.probe_rounds == before.polling.probe_rounds,
        "A obtained a second interval while B owned the sole reservation: {competing:?}"
    );
    loop {
        let status = rig.pump.status().await?;
        if wire_count(&status, "a", "received")? > wire_count(&wire_before, "a", "received")?
            && wire_count(&status, "a", "upstream")? > wire_count(&wire_before, "a", "upstream")?
        {
            break;
        }
        ensure!(
            Instant::now() < rig.deadline,
            "competing Event owner did not exchange actual packets"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    held_accounting(&held, &rig.budget.snapshot())?;
    mode(rig.a_mut(), PollMode::Event).await?;
    let mut event = rig.b().config.clone();
    event.datapath.as_mut().unwrap().poll_mode = Some(PollMode::Event);
    rig.b_mut().reload(event).await?;
    rig.pump.set("a", false).await?;
    rig.pump.set("b", false).await?;
    let window = held
        .effective_policy
        .context("held interval lacks actual quota policy")?
        .window_ns;
    let duration = Duration::from_nanos(
        window
            .checked_add(held.reserved_ns)
            .context("real hold overflow")?,
    );
    sleep_before(rig.deadline, duration).await?;
    held_accounting(&held, &rig.budget.snapshot())?;
    pause.release();
    let exit = exit_after(rig, &control, &held, &snapshot, "polling_revision_changed").await?;
    let settlement = exit.settlement.unwrap();
    ensure!(
        settlement.elapsed_ns >= duration.as_nanos() as u64
            && settlement.overrun_ns > 0
            && settlement.net_ns < 0
            && settlement.forfeited_grants > 0
            && settlement.forfeited_ns > 0,
        "real elapsed overrun did not retain debt and forfeit crossed grants: {settlement:?}"
    );
    let after = rig
        .b()
        .wait_for(|state| {
            state.polling.mode == PollMode::Event
                && state.polling.local_revision > snapshot.local_revision
                && drained(state)
        })
        .await?;
    ensure!(
        after.polling.probe_rounds == snapshot.probe_rounds,
        "accepted local publication allowed a stale probe: {after:?}"
    );
    rig.a().wait_for(drained).await?;
    let settled = rig.budget.snapshot();
    ensure!(
        settled.active_id.is_none()
            && settled.net_ns
                == held.net_ns + i128::from(held.reserved_ns) - i128::from(settlement.charged_ns)
            && settled.debt_ns == settled.net_ns.unsigned_abs()
            && settled.charged_ns == held.charged_ns + u128::from(settlement.charged_ns)
            && settled.overrun_ns == held.overrun_ns + u128::from(settlement.overrun_ns),
        "settlement refunded an unresolved grant or lost actual elapsed cost: {held:?}, {settled:?}"
    );
    let (retired, rebuilt) = rig.rebuild_b().await?;
    no_remint(&settled, &retired.ledger)?;
    no_remint(&settled, &rig.budget.snapshot())?;
    ensure!(
        rebuilt.polling.mode == PollMode::Event
            && !rebuilt.polling.high
            && rebuilt.polling.busy_entries == 0
            && rebuilt.polling.probe_rounds == 0
            && rebuilt.attempts.started == 0,
        "rebuilt participant inherited local qualification or a Core reader: {rebuilt:?}"
    );
    drop(retired);
    let artifacts = rig.artifacts.clone();
    let initial = calibrated(
        rig.b_mut(),
        &artifacts,
        "shared-reconstructed",
        PollMode::Adaptive,
    )
    .await?;
    rig.pump.set("b", true).await?;
    qualified(rig.b(), &initial).await?;
    Ok(())
}

async fn independent_process_publication(rig: &mut Rig) -> anyhow::Result<()> {
    let control = Arc::clone(&rig.b().ready.control);
    let pause = control.arm(Point::Reserved, rig.deadline);
    let snapshot = pause.wait()?;
    let held = rig.budget.snapshot();
    let mut publisher = rig.a().config.clone();
    let datapath = publisher.datapath.as_mut().unwrap();
    datapath.poll_mode = Some(PollMode::Adaptive);
    let busy = datapath.busy_poll.as_mut().unwrap();
    busy.budget_us = busy
        .budget_us
        .checked_add(1)
        .context("fixture quota overflow")?;
    busy.budget_window_us = busy
        .budget_window_us
        .checked_add(1)
        .context("fixture window overflow")?;
    busy.calibration = None;
    let quota = (busy.budget_window_us, busy.budget_us);
    rig.a_mut().reload(publisher).await?;
    let changed = rig.budget.snapshot();
    ensure!(
        changed.process_revision > held.process_revision
            && changed.desired_policy != held.desired_policy
            && control.serviced_revision() == snapshot.local_revision,
        "publisher did not change the independent process stamp without B local publication: {held:?}, {changed:?}"
    );
    held_accounting(&held, &changed)?;
    rig.pump.set("b", false).await?;
    let old_policy = held
        .effective_policy
        .context("held interval has no old W/B")?;
    sleep_before(
        rig.deadline,
        Duration::from_nanos(
            old_policy
                .window_ns
                .checked_add(held.reserved_ns)
                .context("old W/B crossing overflow")?,
        ),
    )
    .await?;
    held_accounting(&held, &rig.budget.snapshot())?;
    pause.release();
    let exit = exit_after(rig, &control, &held, &snapshot, "polling_revision_changed").await?;
    let settled = rig.budget.snapshot();
    let desired = changed
        .desired_policy
        .context("new W/B policy was not published")?;
    let old_frontier = held.next_refill_ns.context("old W/B frontier missing")?;
    let new_frontier = settled
        .next_refill_ns
        .context("settled W/B frontier missing")?;
    let distance = new_frontier
        .checked_sub(old_frontier)
        .context("W/B publication moved its frontier backwards")?;
    ensure!(
        settled.effective_policy == Some(desired)
            && settled.staged_policy.is_none()
            && distance > 0
            && distance % desired.window_ns == 0
            && exit
                .settlement
                .is_some_and(|record| record.forfeited_grants > 0 && record.forfeited_ns > 0),
        "held old-W/B interval did not settle on the stable boundary/new-W grid: {held:?}, {changed:?}, {settled:?}"
    );
    let participant = rig
        .b()
        .wait_for(|state| {
            state.polling.process_revision == changed.process_revision
                && state.polling.reason == "process_budget_policy_mismatch"
        })
        .await?;
    ensure!(
        participant.polling.local_revision == snapshot.local_revision
            && participant.polling.probe_rounds == snapshot.probe_rounds
            && control.serviced_revision() == snapshot.local_revision,
        "process-only publication was confused with a B-local notification: {participant:?}"
    );
    let mut participant = rig.b().config.clone();
    let busy = participant
        .datapath
        .as_mut()
        .unwrap()
        .busy_poll
        .as_mut()
        .unwrap();
    busy.budget_window_us = quota.0;
    busy.budget_us = quota.1;
    busy.calibration = None;
    rig.b_mut().reload(participant).await?;
    let artifacts = rig.artifacts.clone();
    calibrated(
        rig.a_mut(),
        &artifacts,
        "shared-process-publisher",
        PollMode::Event,
    )
    .await?;
    let initial = calibrated(
        rig.b_mut(),
        &artifacts,
        "shared-process-participant",
        PollMode::Adaptive,
    )
    .await?;
    rig.pump.set("b", true).await?;
    qualified(rig.b(), &initial).await?;
    Ok(())
}

async fn owned(rig: &Rig, args: &[&str]) -> anyhow::Result<std::process::Output> {
    owned_command(&rig.b_namespace, args).await
}

fn feature<'a>(output: &'a str, name: &str) -> Option<(&'a str, bool)> {
    output.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(':')?;
        (key == name).then(|| {
            (
                value.split_whitespace().next().unwrap_or(""),
                value.contains("[fixed]"),
            )
        })
    })
}

/// Join the topology-failed B, then retire it through the same controller frontier.
async fn topology_retired(rig: &mut Rig) -> anyhow::Result<()> {
    let mut retired = rig
        .b
        .take()
        .unwrap()
        .join()
        .await
        .context("live topology transition did not genuinely close/join B")?;
    ensure!(
        retired
            .state
            .polling
            .queues
            .iter()
            .all(|queue| queue.counters.submitted == queue.counters.completed),
        "topology-failed participant returned before actual CQ drain"
    );
    // PermissionDenied can also come from capture cleanup. The caller's actual
    // feature/name evidence and this join without Shutdown narrow, not uniquely identify, it.
    ensure!(
        Instant::now() < rig.deadline
            && retired
                .failure
                .as_ref()
                .and_then(|error| error.downcast_ref::<io::Error>())
                .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied),
        "changed topology did not autonomously close with the observed permission failure: {:?}",
        retired.failure
    );
    retired.release(&mut rig.pump, None).await
}

async fn restart_b(rig: &mut Rig, config: Config, label: &str) -> anyhow::Result<()> {
    rig.restore_b_link().await?;
    let owner = Owner::start(
        config,
        PollBudgetBinding::Participant(rig.budget.clone()),
        rig.b_namespace.clone(),
        rig.pins.join("b"),
        rig.artifacts.clone(),
        rig.deadline,
    )
    .await?;
    rig.b = Some(owner);
    let artifacts = rig.artifacts.clone();
    let initial = calibrated(rig.b_mut(), &artifacts, label, PollMode::Adaptive).await?;
    rig.pump.set("b", true).await?;
    qualified(rig.b(), &initial).await?;
    Ok(())
}

async fn feature_change(rig: &mut Rig) -> anyhow::Result<()> {
    let original = owned(rig, &["ethtool", "-k", "dut2"]).await?;
    let original_text = std::str::from_utf8(&original.stdout)?;
    let (name, previous) = [
        "rx-gro-list",
        "rx-udp-gro-forwarding",
        "generic-receive-offload",
    ]
    .into_iter()
    .find_map(|name| {
        feature(original_text, name)
            .filter(|(state, fixed)| !fixed && matches!(*state, "on" | "off"))
            .map(|(state, _)| (name, state))
    })
    .context(
        "owned capture device advertises no changeable GRO feature for the real retained-query row",
    )?;
    let requested = if previous == "on" { "off" } else { "on" };
    let config = rig.b().config.clone();
    let control = Arc::clone(&rig.b().ready.control);
    let pause = control.arm(Point::FeatureQuery, rig.deadline);
    let snapshot = pause.wait()?;
    let held = rig.budget.snapshot();
    rig.pump.set("b", false).await?;
    owned(rig, &["ethtool", "-K", "dut2", name, requested]).await?;
    let changed = owned(rig, &["ethtool", "-k", "dut2"]).await?;
    ensure!(
        changed.stdout != original.stdout
            && feature(std::str::from_utf8(&changed.stdout)?, name).map(|value| value.0)
                == Some(requested),
        "ethtool did not actually change the advertised active feature"
    );
    let held_for = Duration::from_nanos(
        held.reserved_ns
            .checked_add(1_000_000)
            .context("query hold overflow")?,
    );
    sleep_before(rig.deadline, held_for).await?;
    held_accounting(&held, &rig.budget.snapshot())?;
    pause.release();
    let exit = exit_after(
        rig,
        &control,
        &held,
        &snapshot,
        "calibration_context_mismatch",
    )
    .await?;
    let settlement = exit.settlement.unwrap();
    ensure!(
        settlement.elapsed_ns >= held_for.as_nanos() as u64 && settlement.overrun_ns > 0,
        "retained live-feature query pause escaped real elapsed accounting: {settlement:?}"
    );
    topology_retired(rig).await?;
    owned(rig, &["ethtool", "-K", "dut2", name, previous]).await?;
    let restored = owned(rig, &["ethtool", "-k", "dut2"]).await?;
    ensure!(
        restored.stdout == original.stdout,
        "owned feature state was not restored after B's true join"
    );
    std::fs::write(
        rig.artifacts.join("adaptive-feature-before.txt"),
        &original.stdout,
    )?;
    std::fs::write(
        rig.artifacts.join("adaptive-feature-changed.txt"),
        &changed.stdout,
    )?;
    std::fs::write(
        rig.artifacts.join("adaptive-feature-restored.txt"),
        &restored.stdout,
    )?;
    restart_b(rig, config, "shared-feature-restored").await
}

async fn feature_query_error(rig: &mut Rig) -> anyhow::Result<()> {
    let original = owned(rig, &["ip", "-j", "link", "show", "dev", "dut2"]).await?;
    let original_link: serde_json::Value = serde_json::from_slice(&original.stdout)?;
    let ifindex = original_link[0]["ifindex"]
        .as_u64()
        .context("owned dut2 has no real ifindex")?;
    ensure!(
        original_link[0]["address"] == "02:00:00:00:00:12",
        "rename target is not the fixture-owned capture device"
    );
    let config = rig.b().config.clone();
    let control = Arc::clone(&rig.b().ready.control);
    let pause = control.arm(Point::FeatureQuery, rig.deadline);
    let snapshot = pause.wait()?;
    let held = rig.budget.snapshot();
    rig.pump.set("b", false).await?;
    owned(
        rig,
        &["ip", "link", "set", "dev", "dut2", "name", "e4-ioctl"],
    )
    .await?;
    let renamed = owned(rig, &["ip", "-j", "link", "show", "dev", "e4-ioctl"]).await?;
    let renamed_link: serde_json::Value = serde_json::from_slice(&renamed.stdout)?;
    ensure!(
        renamed_link[0]["ifindex"].as_u64() == Some(ifindex)
            && renamed_link[0]["address"] == original_link[0]["address"],
        "rename did not retain the exact owned device identity"
    );
    let held_for = Duration::from_nanos(
        held.reserved_ns
            .checked_add(1_000_000)
            .context("query hold overflow")?,
    );
    sleep_before(rig.deadline, held_for).await?;
    pause.release();
    let exit = exit_after(rig, &control, &held, &snapshot, "offload_query_failed").await?;
    let errno = control.last_query_errno();
    ensure!(
        errno == Some(libc::ENODEV),
        "retained old-name ioctl did not actually return ENODEV: {errno:?}"
    );
    ensure!(
        exit.settlement.unwrap().elapsed_ns >= held_for.as_nanos() as u64
            && exit.settlement.unwrap().overrun_ns > 0,
        "failed retained ioctl was not fully charged: {exit:?}"
    );
    topology_retired(rig).await?;
    owned(
        rig,
        &["ip", "link", "set", "dev", "e4-ioctl", "name", "dut2"],
    )
    .await?;
    let restored = owned(rig, &["ip", "-j", "link", "show", "dev", "dut2"]).await?;
    let restored_link: serde_json::Value = serde_json::from_slice(&restored.stdout)?;
    ensure!(
        restored_link[0]["ifindex"].as_u64() == Some(ifindex)
            && restored_link[0]["address"] == original_link[0]["address"],
        "owned name restoration replaced the original interface"
    );
    std::fs::write(
        rig.artifacts.join("adaptive-query-enodev.txt"),
        format!("retained FeatureQuery raw_os_error={errno:?}\n"),
    )?;
    restart_b(rig, config, "shared-query-restored").await
}

async fn publisher_closure(rig: &mut Rig) -> anyhow::Result<()> {
    let control = Arc::clone(&rig.b().ready.control);
    let pause = control.arm(Point::Reserved, rig.deadline);
    let snapshot = pause.wait()?;
    let held = rig.budget.snapshot();
    let tcp = rig
        .tcp
        .take()
        .context("actual TCP peer already joined")?
        .join()
        .await?;
    let mut retired = rig.a.take().unwrap().stop().await?;
    ensure!(
        retired.failure.is_none(),
        "publisher retirement failed: {:?}",
        retired.failure
    );
    retired.release(&mut rig.pump, Some(&tcp)).await?;
    ensure!(
        !rig.budget.snapshot().publisher_closed,
        "stopping A dropped the publisher before its returned ControlPlane was released"
    );
    held_accounting(&held, &rig.budget.snapshot())?;
    drop(retired.plane.take());
    let closed = rig.budget.snapshot();
    ensure!(
        closed.publisher_closed
            && closed.process_revision == held.process_revision
            && control.serviced_revision() == snapshot.local_revision,
        "sole publisher closure rewrote the process stamp or locally notified B: {closed:?}"
    );
    held_accounting(&held, &closed)?;
    pause.release();
    exit_after(rig, &control, &held, &snapshot, "polling_revision_changed").await?;
    let wire_before = rig.pump.status().await?;
    let event = rig
        .b()
        .wait_for(|state| {
            state.polling.reason == "publisher_closed"
                && state.polling.published_tx > snapshot.published_tx
                && state.polling.qualified_rx > snapshot.qualified_rx
        })
        .await?;
    ensure!(
        event.polling.local_revision == snapshot.local_revision
            && event.polling.process_revision == snapshot.process_revision
            && event.polling.busy_entries == snapshot.busy_entries
            && event.polling.probe_rounds == snapshot.probe_rounds,
        "publisher closure admitted another Busy segment or masqueraded as B local publication: {event:?}"
    );
    loop {
        let status = rig.pump.status().await?;
        if wire_count(&status, "b", "received")? > wire_count(&wire_before, "b", "received")?
            && wire_count(&status, "b", "upstream")? > wire_count(&wire_before, "b", "upstream")?
        {
            break;
        }
        ensure!(
            Instant::now() < rig.deadline,
            "publisher-closed B lost ordinary Event wire service"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    rig.pump.set("b", false).await?;
    let drained = rig.b().wait_for(drained).await?;
    ensure!(
        drained.polling.busy_entries == snapshot.busy_entries
            && drained.polling.probe_rounds == snapshot.probe_rounds,
        "publisher-closed Event drain reentered Busy"
    );
    let mut retired = rig.b.take().unwrap().stop().await?;
    ensure!(
        retired.failure.is_none(),
        "participant retirement failed: {:?}",
        retired.failure
    );
    retired.release(&mut rig.pump, None).await?;
    ensure!(
        retired.ledger.publisher_closed
            && retired.ledger.active_id.is_none()
            && retired.ledger.disabled_reason.is_none(),
        "final process accounting lost closure or settlement: {:?}",
        retired.ledger
    );
    Ok(())
}

pub(super) async fn run(rig: &mut Rig) -> anyhow::Result<()> {
    natural_and_fair(rig).await?;
    idle_and_endpoint_publication(rig).await?;
    shared_overrun_and_rebuild(rig).await?;
    independent_process_publication(rig).await?;
    feature_change(rig).await?;
    feature_query_error(rig).await?;
    publisher_closure(rig).await
}
