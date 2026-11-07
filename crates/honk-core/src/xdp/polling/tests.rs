use super::*;
use honk_config::datapath::{Backend, DatapathConfig, DirectProfile, PollCalibration};

fn parameters() -> BusyPollConfig {
    BusyPollConfig {
        pps_enter: 100,
        pps_exit: 10,
        observation_window_us: 10_000,
        enter_windows: 2,
        exit_windows: 2,
        max_busy_us: 100,
        empty_rounds: 3,
        budget_window_us: 10_000,
        budget_us: 1_000,
        calibration: None,
    }
}

fn configuration(mode: PollMode) -> Config {
    Config {
        datapath: Some(DatapathConfig {
            backend: Backend::Xdp,
            direct: Some(DirectProfile::Endpoint),
            poll_mode: Some(mode),
            busy_poll: Some(parameters()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn parameter_identity_has_one_fixed_numeric_encoding_and_no_evidence_cycle() {
    let config = parameters();
    let mut bytes = b"honk.xdp.poll-parameters.v1\0".to_vec();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&100u32.to_le_bytes());
    bytes.extend_from_slice(&10u32.to_le_bytes());
    bytes.extend_from_slice(&10_000u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&100u32.to_le_bytes());
    bytes.extend_from_slice(&3u16.to_le_bytes());
    bytes.extend_from_slice(&10_000u32.to_le_bytes());
    bytes.extend_from_slice(&1_000u32.to_le_bytes());
    let expected = crate::configuration::encode_digest(&Sha256::digest(&bytes));
    assert_eq!(parameter_digest(&config), expected);
    let mut candidate = config.clone();
    candidate.calibration = Some(PollCalibration {
        schema: CALIBRATION_SCHEMA,
        counting_revision: COUNTING_REVISION,
        executable_sha256: "0".repeat(64),
        context_sha256: "1".repeat(64),
        parameter_sha256: expected.clone(),
        status: CalibrationStatus::Candidate,
        evidence_manifest_sha256: "2".repeat(64),
    });
    assert_eq!(parameter_digest(&candidate), expected);
    candidate.calibration.as_mut().unwrap().status = CalibrationStatus::Qualified;
    candidate
        .calibration
        .as_mut()
        .unwrap()
        .evidence_manifest_sha256 = "3".repeat(64);
    assert_eq!(parameter_digest(&candidate), expected);
    let mut variants: [BusyPollConfig; 9] = std::array::from_fn(|_| config.clone());
    variants[0].pps_enter += 1;
    variants[1].pps_exit += 1;
    variants[2].observation_window_us += 1;
    variants[3].enter_windows += 1;
    variants[4].exit_windows += 1;
    variants[5].max_busy_us += 1;
    variants[6].empty_rounds += 1;
    variants[7].budget_window_us += 1;
    variants[8].budget_us += 1;
    for variant in variants {
        assert_ne!(parameter_digest(&variant), expected);
    }
}

#[test]
fn context_encoding_keeps_lengths_and_field_order() {
    let mut first = ContextDigest(Sha256::new());
    first.bytes(b"ab");
    first.bytes(b"c");
    first.number(7);
    let mut second = ContextDigest(Sha256::new());
    second.bytes(b"a");
    second.bytes(b"bc");
    second.number(7);
    assert_ne!(first.finish(), second.finish());
    let mut third = ContextDigest(Sha256::new());
    third.bytes(b"ab");
    third.bytes(b"c");
    third.number(8);
    let mut fourth = ContextDigest(Sha256::new());
    fourth.bytes(b"ab");
    fourth.bytes(b"c");
    fourth.number(7);
    assert_ne!(third.finish(), fourth.finish());
}

#[test]
fn event_and_unproven_embeddings_never_acquire_a_private_allowance() {
    let event = configuration(PollMode::Event);
    let publication = PollingPublication::new(&event);
    let mut state = AdaptivePoll::new(Arc::clone(&publication), None);
    assert!(state.begin(true, None).is_none());
    assert_eq!(state.reason, "explicit_event");
    assert_eq!(
        state.parameter_sha256,
        event
            .datapath
            .as_ref()
            .unwrap()
            .busy_poll
            .as_ref()
            .map(parameter_digest)
    );
    let mut adaptive = event.clone();
    adaptive.datapath.as_mut().unwrap().poll_mode = Some(PollMode::Adaptive);
    publication.publish(&adaptive, None);
    state.synchronize();
    assert!(state.begin(true, None).is_none());
    assert_eq!(state.reason, "unproven_process_budget");
    assert!(state.budget.is_none());
}

#[test]
fn local_revision_and_counter_failure_clear_qualification() {
    let config = configuration(PollMode::Adaptive);
    let publication = PollingPublication::new(&config);
    let mut state = AdaptivePoll::new(Arc::clone(&publication), None);
    state.status.high = true;
    let mut next = config.clone();
    next.datapath
        .as_mut()
        .unwrap()
        .busy_poll
        .as_mut()
        .unwrap()
        .pps_enter += 1;
    publication.publish(&next, None);
    assert!(!state.local_current());
    state.synchronize();
    assert!(!state.status.high);
    assert!(state.local_current());
    state.status.high = true;
    state.counter_unavailable();
    assert!(!state.status.high);
    assert!(state.begin(true, None).is_none());
    assert_eq!(state.reason, "accounting_unknown");
}

fn reserved_consumer() -> (
    crate::control::PollBudgetBinding,
    ProcessPollBudget,
    Arc<PollingPublication>,
    AdaptivePoll,
    BusyInterval,
) {
    let publisher = ProcessPollBudget::test_publisher(true);
    let handle = publisher.participant_handle();
    let binding = crate::control::PollBudgetBinding::Publisher(publisher);
    let mut config = configuration(PollMode::Adaptive);
    let busy = config
        .datapath
        .as_mut()
        .unwrap()
        .busy_poll
        .as_mut()
        .unwrap();
    let parameter_sha256 = parameter_digest(busy);
    busy.calibration = Some(PollCalibration {
        schema: CALIBRATION_SCHEMA,
        counting_revision: COUNTING_REVISION,
        executable_sha256: handle.executable_sha256().unwrap().to_owned(),
        context_sha256: "1".repeat(64),
        parameter_sha256,
        status: CalibrationStatus::Candidate,
        evidence_manifest_sha256: "2".repeat(64),
    });
    let quota = QuotaPolicy::from_config(busy).unwrap();
    binding.publish_policy(Some(quota)).unwrap();
    handle.set_test_time(quota.window_ns);
    let publication = PollingPublication::new(&config);
    let mut consumer = AdaptivePoll::new(Arc::clone(&publication), Some(handle.clone()));
    consumer.context(Ok("1".repeat(64)));
    consumer.last_clock = Some(ClockObservation {
        boot_ns: quota.window_ns,
        continuous: true,
        discontinuity: false,
        offset_changed: false,
        monotonic_resolution_ns: 1,
        boottime_resolution_ns: 1,
        read_duration_ns: 0,
        raw_offset_low_ns: 0,
        raw_offset_high_ns: 0,
        baseline_offset_low_ns: -2,
        baseline_offset_high_ns: 2,
    });
    consumer.status.high = true;
    consumer.status.rx_high_windows = 2;
    let interval = consumer.begin(true, None).unwrap();
    (binding, handle, publication, consumer, interval)
}

#[test]
fn applying_new_local_snapshot_cannot_erase_the_active_event_fence() {
    let (_binding, handle, publication, mut consumer, interval) = reserved_consumer();
    assert!(consumer.segment_current(&interval));
    let mut event = configuration(PollMode::Event);
    event.datapath.as_mut().unwrap().busy_poll = consumer.config.busy.clone();
    publication.publish(&event, None);
    consumer.synchronize();
    assert!(
        consumer.local_current(),
        "the new local snapshot is already applied"
    );
    assert!(
        !consumer.segment_current(&interval),
        "the reservation still owns its original local revision"
    );
    handle.set_test_time(10_000_010);
    interval.finish().unwrap();
    consumer.leave("explicit_event");
    assert!(consumer.begin(true, None).is_none());
    assert_eq!(consumer.reason, "explicit_event");
}

#[test]
fn process_revision_and_publisher_close_fence_segments_without_local_watch_changes() {
    let (binding, handle, publication, mut consumer, interval) = reserved_consumer();
    let local = publication.revision();
    let mut quota = QuotaPolicy::from_config(consumer.config.busy.as_ref().unwrap()).unwrap();
    quota.budget_ns += 1_000;
    binding.publish_policy(Some(quota)).unwrap();
    consumer.synchronize();
    assert_eq!(publication.revision(), local);
    assert!(!consumer.segment_current(&interval));
    handle.set_test_time(10_000_010);
    interval.finish().unwrap();
    consumer.leave("polling_revision_changed");

    let (binding, handle, publication, consumer, interval) = reserved_consumer();
    let local = publication.revision();
    drop(binding);
    assert_eq!(publication.revision(), local);
    assert!(handle.publisher_closed());
    assert!(!consumer.segment_current(&interval));
    handle.set_test_time(10_000_010);
    interval.finish().unwrap();
}

#[test]
fn stable_optional_clock_error_invalidates_a_reader_only_on_error_entry() {
    let config = configuration(PollMode::Adaptive);
    let publication = PollingPublication::new(&config);
    let mut consumer = AdaptivePoll::new(publication, None);
    let good = ClockObservation {
        boot_ns: 100,
        continuous: true,
        discontinuity: false,
        offset_changed: false,
        monotonic_resolution_ns: 1,
        boottime_resolution_ns: 1,
        read_duration_ns: 0,
        raw_offset_low_ns: 0,
        raw_offset_high_ns: 0,
        baseline_offset_low_ns: -2,
        baseline_offset_high_ns: 2,
    };
    consumer.accept_clock_observation(Ok(good), 0, 0);
    let available = consumer.last_clock.is_some();
    consumer.accept_clock_observation(Err("clock_unavailable"), 0, 0);
    assert!(consumer.clock_requires_policy_recheck(available));
    for _ in 0..4 {
        let available = consumer.last_clock.is_some();
        consumer.accept_clock_observation(Err("clock_unavailable"), 0, 0);
        assert!(
            !consumer.clock_requires_policy_recheck(available),
            "stable Event clock failure must preserve the queued reader"
        );
    }
    let available = consumer.last_clock.is_some();
    consumer.accept_clock_observation(
        Ok(ClockObservation {
            continuous: false,
            ..good
        }),
        0,
        0,
    );
    assert!(!consumer.clock_requires_policy_recheck(available));
    let available = consumer.last_clock.is_some();
    consumer.accept_clock_observation(
        Ok(ClockObservation {
            continuous: false,
            discontinuity: true,
            offset_changed: true,
            ..good
        }),
        0,
        0,
    );
    assert!(consumer.clock_requires_policy_recheck(available));
}

#[test]
fn event_totals_need_no_default_pps_window_and_survive_parameter_publication() {
    let mut config = configuration(PollMode::Event);
    config.datapath.as_mut().unwrap().busy_poll = None;
    let publication = PollingPublication::new(&config);
    let mut consumer = AdaptivePoll::new(Arc::clone(&publication), None);
    consumer.boundary(7, 11);
    assert_eq!(
        (consumer.qualified_rx_total, consumer.published_tx_total),
        (7, 11)
    );
    assert!(!consumer.status.high);
    config.datapath.as_mut().unwrap().busy_poll = Some(parameters());
    publication.publish(&config, None);
    consumer.boundary(5, 13);
    assert_eq!(
        (consumer.qualified_rx_total, consumer.published_tx_total),
        (12, 24)
    );
    assert!(consumer.parameter_sha256.is_some());
    consumer.qualified_rx_total = u64::MAX;
    consumer.boundary(1, 0);
    assert!(consumer.counter_failed);
    assert_eq!(consumer.qualified_rx_total, u64::MAX);
    assert!(!consumer.status.high);
}
