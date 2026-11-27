use super::*;

#[derive(Clone, Copy)]
enum Interruption {
    Gap,
    Unavailable,
    Offset,
}

fn drained(state: &State) -> bool {
    !state.polling.pollable
        && state.polling.queues.iter().all(|queue| {
            queue.counters.submitted == queue.counters.completed
                && queue.rings.rx_producer == queue.rings.rx_consumer
                && queue.rings.tx_producer == queue.rings.tx_consumer
                && queue.rings.cq_producer == queue.rings.cq_consumer
        })
}

fn queued(state: &State, control: &Control) -> bool {
    state.polling.waiting == 1
        && state.polling.pending == 0
        && state.attempts.started > state.attempts.completed
        && control.pending_wait().is_some_and(|wait| wait.reading)
}

fn retained_reader(state: &State, expected: Attempts, label: &str) -> anyhow::Result<()> {
    ensure!(
        state.polling.waiting == 1 && state.polling.pending == 0,
        "{label}: the original cold Core packet did not remain retained: {state:?}"
    );
    ensure!(
        state.attempts.started == expected.started
            && state.attempts.completed == expected.completed
            && state.attempts.canceled == expected.canceled,
        "{label}: the queued acquisition lost its place: {:?} -> {:?}",
        expected,
        state.attempts
    );
    Ok(())
}

fn completed_output(before: &Snapshot, after: &Snapshot, device: &str) -> bool {
    after.queues.iter().any(|queue| {
        queue.device == device
            && before.queues.iter().any(|old| {
                old.device == queue.device
                    && old.id == queue.id
                    && queue.counters.published_packets > old.counters.published_packets
                    && queue.counters.submitted > old.counters.submitted
                    && queue.counters.completed > old.counters.completed
            })
    })
}

async fn publication_case<T>(
    rig: &mut Rig,
    publication: Arc<tokio::sync::RwLock<T>>,
    label: &str,
    interruption: Interruption,
) -> anyhow::Result<()> {
    let control = Arc::clone(&rig.a().ready.control);
    let (window, enter_windows) = {
        let busy = rig
            .a()
            .config
            .datapath
            .as_ref()
            .unwrap()
            .busy_poll
            .as_ref()
            .unwrap();
        (
            Duration::from_micros(u64::from(busy.observation_window_us)),
            busy.enter_windows,
        )
    };
    rig.pump.set("a", true).await?;
    rig.tcp().step("CONNECT", label, "CONNECTED").await?;
    let before = rig.a().state().await?;
    rig.a()
        .wait_for(|state| {
            state.polling.clock_error.is_none()
                && state.polling.clock.is_some_and(|clock| clock.continuous)
                && state.polling.high
                && (state.polling.rx_high_windows >= enter_windows
                    || state.polling.tx_high_windows >= enter_windows)
                && state.polling.busy_entries > before.polling.busy_entries
                && state.polling.probe_rounds > before.polling.probe_rounds
                && state.polling.waiting == 0
                && state.polling.pending == 0
        })
        .await?;
    rig.pump.set("a", false).await?;
    let stream_start = rig
        .a()
        .wait_for(|state| {
            drained(state) && state.polling.waiting == 0 && state.polling.pending == 0
        })
        .await?;

    let first_writer = Arc::clone(&publication).write_owned().await;
    control.clear_pending();
    rig.tcp().step("COLD", label, "COLD").await?;
    let original = rig
        .a()
        .wait_for(|state| {
            queued(state, &control)
                && drained(state)
                && state.polling.clock.is_some()
                && state.polling.clock_error.is_none()
        })
        .await?;
    let original_clock = original
        .polling
        .clock
        .context("queued reader has no real clock observation")?;

    let later_writer = publication.write_owned();
    tokio::pin!(later_writer);
    match interruption {
        Interruption::Gap => {
            // A replacement during the gap would now queue behind this actual writer.
            ensure!(
                futures::poll!(later_writer.as_mut()).is_pending(),
                "{label}: later writer escaped the first publication writer"
            );
            let pause = window
                .checked_mul(2)
                .context("ordinary service gap overflow")?;
            let started = Instant::now();
            rig.a().gap(pause).await?;
            ensure!(
                started.elapsed() >= pause,
                "{label}: owner pause was not real elapsed time"
            );
            let reset = rig
                .a()
                .wait_for(|state| state.clock_events.gaps > original.clock_events.gaps)
                .await?;
            retained_reader(&reset, original.attempts, label)?;
            ensure!(
                !reset.polling.high
                    && reset.polling.rx_high_windows == 0
                    && reset.polling.tx_high_windows == 0,
                "{label}: ordinary elapsed gap retained old qualification: {reset:?}"
            );
            ensure!(
                reset.clock_events.offsets == original.clock_events.offsets
                    && reset.clock_events.errors == original.clock_events.errors,
                "{label}: elapsed gap was not observed as an ordinary gap: {reset:?}"
            );
        }
        Interruption::Unavailable => control.set_clock_fault(ClockFault::Unavailable),
        Interruption::Offset => {
            // Exceed even a fixture-wide read bracket, without changing ledger/protocol clocks.
            let horizon =
                u64::try_from(WINDOW.as_nanos()).context("clock fixture horizon overflow")?;
            let quantization = original_clock
                .monotonic_resolution_ns
                .checked_add(original_clock.boottime_resolution_ns)
                .context("clock resolution sum overflow")?;
            let offset = horizon
                .checked_add(original_clock.read_duration_ns)
                .and_then(|value| value.checked_add(quantization))
                .and_then(|value| value.checked_add(quantization))
                .context("disjoint clock offset overflow")?;
            original_clock
                .boot_ns
                .checked_add(horizon)
                .and_then(|value| value.checked_add(offset))
                .context("persistent BOOTTIME observation offset exceeds clock range")?;
            control.set_clock_fault(ClockFault::BootOffset(offset));
        }
    }

    control.clear_pending();
    rig.tcp().step("APP", label, "APP").await?;
    let survivor = match interruption {
        Interruption::Gap => {
            let state = rig.a().state().await?;
            retained_reader(&state, original.attempts, label)?;
            state
        }
        Interruption::Unavailable | Interruption::Offset => {
            let state = rig
                .a()
                .wait_for(|state| {
                    queued(state, &control)
                        && drained(state)
                        && state.attempts.started > original.attempts.started
                        && match interruption {
                            Interruption::Unavailable => {
                                state.clock_events.errors > original.clock_events.errors
                            }
                            Interruption::Offset => {
                                state.clock_events.offsets > original.clock_events.offsets
                            }
                            Interruption::Gap => unreachable!(),
                        }
                })
                .await?;
            ensure!(
                state.attempts.started == original.attempts.started + 1
                    && state.attempts.canceled == original.attempts.canceled + 1
                    && state.attempts.completed == original.attempts.completed,
                "{label}: first clock-fault entry must replace exactly one real reader: {:?} -> {:?}",
                original.attempts,
                state.attempts
            );
            ensure!(
                !state.polling.high
                    && state.polling.rx_high_windows == 0
                    && state.polling.tx_high_windows == 0,
                "{label}: clock-fault entry retained old qualification: {state:?}"
            );
            // The intentional cancellation must finish before the FIFO ordering witness queues.
            ensure!(
                futures::poll!(later_writer.as_mut()).is_pending(),
                "{label}: later writer escaped the first publication writer"
            );
            state
        }
    };

    control.clear_pending();
    let timed = rig
        .a()
        .wait_for(|state| {
            queued(state, &control)
                && drained(state)
                && control.pending_wait().is_some_and(|wait| {
                    wait.reading
                        && wait.idle_ports
                        && !wait.pending_outputs
                        && wait.driver_deadline.is_some_and(|due| {
                            due > Instant::now()
                                && wait.armed_deadline == Some(tokio::time::Instant::from_std(due))
                        })
                })
        })
        .await?;
    retained_reader(&timed, survivor.attempts, label)?;
    rig.tcp().step("RETRANSMIT", label, "RETRANSMITTED").await?;
    rig.tcp().step("CLOSE", label, "CLOSED").await?;
    let closed = rig
        .a()
        .wait_for(|state| queued(state, &control) && drained(state))
        .await?;
    retained_reader(&closed, survivor.attempts, label)?;
    ensure!(
        completed_output(&stream_start.polling, &closed.polling, "dut0"),
        "{label}: real Endpoint app/retransmission/close publications did not complete through CQ"
    );
    ensure!(
        closed
            .polling
            .queues
            .iter()
            .any(|queue| queue.device == "dut0"
                && stream_start
                    .polling
                    .queues
                    .iter()
                    .any(|old| old.device == queue.device
                        && old.id == queue.id
                        && queue.counters.rx > old.counters.rx)),
        "{label}: real Endpoint request/ACK/FIN input did not traverse an actual A queue"
    );
    match interruption {
        Interruption::Gap => {
            ensure!(
                closed.clock_events.offsets == original.clock_events.offsets
                    && closed.clock_events.errors == original.clock_events.errors,
                "{label}: ordinary-gap reader encountered an unexpected clock fault: {closed:?}"
            );
        }
        Interruption::Unavailable => {
            ensure!(
                closed.polling.clock.is_none()
                    && closed.polling.clock_error == Some("clock_unavailable")
                    && closed.polling.reason == "clock_unavailable"
                    && closed.clock_events.errors == original.clock_events.errors + 1
                    && closed.clock_events.offsets == original.clock_events.offsets
                    && closed.polling.busy_entries == survivor.polling.busy_entries,
                "{label}: repeated identical unavailability did not remain stable Event service: {closed:?}"
            );
        }
        Interruption::Offset => {
            let clock = closed
                .polling
                .clock
                .context("persistent offset lost the real sample")?;
            ensure!(
                closed.clock_events.offsets == original.clock_events.offsets + 1
                    && closed.clock_events.errors == original.clock_events.errors
                    && closed.polling.clock_error.is_none()
                    && clock.baseline_offset_low_ns > original_clock.baseline_offset_high_ns,
                "{label}: persistent checked offset did not classify/rebase exactly once: {closed:?}"
            );
        }
    }
    ensure!(
        futures::poll!(later_writer.as_mut()).is_pending(),
        "{label}: first writer did not remain held through Endpoint close"
    );

    drop(first_writer);
    let later_guard = later_writer.as_mut().await;
    rig.tcp().step("FORWARDED", label, "FORWARDED").await?;
    // The peer's new ICMP refusal can queue behind the later writer; only the
    // original cold packet's wire/CQ and surviving acquisition are the proof.
    let resolved = rig
        .a()
        .wait_for(|state| state.polling.pending == 0 && drained(state))
        .await?;
    ensure!(
        resolved.attempts.completed == survivor.attempts.started
            && resolved.attempts.canceled == survivor.attempts.canceled,
        "{label}: original cold output did not resolve through the surviving acquisition: {resolved:?}"
    );
    ensure!(
        completed_output(&closed.polling, &resolved.polling, "dut1")
            && resolved.polling.qualified_rx > closed.polling.qualified_rx,
        "{label}: original cold Core output did not publish and complete on actual A egress"
    );
    // Keep the later write guard until the original packet is on the wire and its CQ is drained.
    drop(later_guard);

    if !matches!(interruption, Interruption::Gap) {
        control.set_clock_fault(ClockFault::None);
        rig.pump.set("a", true).await?;
        let restored = rig
            .a()
            .wait_for(|state| {
                state.polling.clock_error.is_none()
                    && state.polling.clock.is_some_and(|clock| clock.continuous)
            })
            .await?;
        if matches!(interruption, Interruption::Offset) {
            ensure!(
                restored.polling.clock.unwrap().baseline_offset_high_ns
                    < closed.polling.clock.unwrap().baseline_offset_low_ns,
                "{label}: restoring the observation producer did not return to the actual clock domain"
            );
        }
        println!(
            "{label}: real app/timer/close/CQ and cold-output FIFO order; clock restore events {:?} -> {:?}",
            resolved.clock_events, restored.clock_events
        );
    } else {
        println!("{label}: real elapsed gap, app/timer/close/CQ and cold-output FIFO order");
    }
    Ok(())
}

pub(super) async fn run(rig: &mut Rig) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::from_std(rig.deadline);
    let control = Arc::clone(&rig.a().ready.control);
    let result = tokio::time::timeout_at(deadline, async {
        let a = rig.a().state().await?;
        let b = rig.b().state().await?;
        for (label, state) in [("a", &a), ("b", &b)] {
            ensure!(state.polling.busy_entries > 0 && state.polling.probe_rounds > 0
                && state.polling.qualified_rx > 0 && state.polling.published_tx > 0,
                "{label}: common prelude did not naturally qualify and service real Busy traffic: {state:?}");
        }
        rig.pump.set("b", false).await?;
        let router = Arc::clone(&rig.a().ready.router);
        let publication = Arc::clone(&rig.a().ready.publication);
        publication_case(rig, Arc::clone(&router), "clock-router-gap", Interruption::Gap).await?;
        publication_case(rig, Arc::clone(&router), "clock-router-unavailable", Interruption::Unavailable).await?;
        publication_case(rig, router, "clock-router-offset", Interruption::Offset).await?;
        publication_case(rig, publication, "clock-config-gap", Interruption::Gap).await?;
        let a_before = rig.a().state().await?;
        let b_before = rig.b().state().await?;
        rig.pump.set("a", true).await?;
        rig.pump.set("b", true).await?;
        rig.a().wait_for(|state| state.polling.high && state.polling.clock_error.is_none()
            && state.polling.busy_entries > a_before.polling.busy_entries
            && state.polling.probe_rounds > a_before.polling.probe_rounds).await?;
        rig.b().wait_for(|state| state.polling.high && state.polling.clock_error.is_none()
            && state.polling.busy_entries > b_before.polling.busy_entries
            && state.polling.probe_rounds > b_before.polling.probe_rounds).await?;
        Ok(())
    }).await;
    control.set_clock_fault(ClockFault::None);
    result.context("clock/queued-reader cases exceeded the shared fixture deadline")?
}
