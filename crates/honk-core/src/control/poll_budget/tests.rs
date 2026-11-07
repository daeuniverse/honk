use super::*;

fn policy(window_ns: u64, budget_ns: u64) -> QuotaPolicy {
    QuotaPolicy {
        window_ns,
        budget_ns,
    }
}

fn fresh() -> (PollBudgetBinding, ProcessPollBudget) {
    let mut shared = Shared::new(true, Some("0".repeat(64)), Ok(0));
    shared.test_clock = Some(AtomicU64::new(0));
    let publisher = PollBudgetPublisher(ProcessPollBudget(Arc::new(shared)));
    let participant = publisher.participant_handle();
    (PollBudgetBinding::Publisher(publisher), participant)
}

fn clock(handle: &ProcessPollBudget, now: u64) {
    handle
        .0
        .test_clock
        .as_ref()
        .unwrap()
        .store(now, Ordering::Relaxed);
}

fn armed() -> (PollBudgetBinding, ProcessPollBudget, QuotaPolicy) {
    let (binding, handle) = fresh();
    let policy = policy(100, 10);
    assert_eq!(binding.publish_policy(Some(policy)), Ok(1));
    (binding, handle, policy)
}

fn reserve(handle: &ProcessPollBudget, policy: QuotaPolicy, now: u64, max: u64) -> BusyInterval {
    clock(handle, now);
    handle
        .try_reserve(policy, handle.revision(), max, None)
        .unwrap()
}

#[test]
fn process_slot_cannot_remint_after_publisher_and_handles_drop() {
    let slot = OnceLock::new();
    let publisher = initialize_slot(&slot, true).unwrap();
    let participant = publisher.participant_handle();
    assert_eq!(
        initialize_slot(&slot, false).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    drop(publisher);
    assert!(participant.publisher_closed());
    drop(participant);
    assert_eq!(
        initialize_slot(&slot, false).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
}

#[test]
fn executable_hash_is_the_running_image_not_a_config_identity() {
    let expected = Sha256::digest(std::fs::read("/proc/self/exe").unwrap());
    let encoded = executable_sha256().unwrap();
    assert_eq!(encoded.len(), expected.len() * 2);
    for (pair, expected) in encoded.as_bytes().as_chunks::<2>().0.iter().zip(expected) {
        let pair = std::str::from_utf8(pair).unwrap();
        assert_eq!(u8::from_str_radix(pair, 16).unwrap(), expected);
    }
    let unavailable = ProcessPollBudget(Arc::new(Shared::new(false, None, Ok(0))));
    assert_eq!(unavailable.executable_sha256(), None);
    assert_eq!(
        unavailable.snapshot().disabled_reason,
        Some("executable_identity_unavailable")
    );
    let no_clock = ProcessPollBudget(Arc::new(Shared::new(
        false,
        Some("a".repeat(64)),
        Err(io::Error::other("clock")),
    )));
    assert_eq!(
        no_clock.snapshot().disabled_reason,
        Some("clock_unavailable")
    );
}

#[test]
fn zero_initial_credit_exact_boundary_and_reservation_limits() {
    let (_binding, handle, policy) = armed();
    assert_eq!(handle.snapshot().net_ns, 0);
    assert_eq!(handle.snapshot().next_refill_ns, Some(100));
    clock(&handle, 99);
    assert_eq!(
        handle.try_reserve(policy, 1, 10, None).unwrap_err(),
        "quota_exhausted"
    );
    let interval = reserve(&handle, policy, 100, 4);
    assert_eq!(interval.end_ns(), 104);
    assert_eq!(interval.process_revision(), 1);
    clock(&handle, 102);
    let record = interval.finish().unwrap();
    assert_eq!(
        (
            record.elapsed_ns,
            record.charged_ns,
            record.reserved_ns,
            record.net_ns
        ),
        (2, 2, 4, 8)
    );
    clock(&handle, 103);
    let deadline_limited = handle.try_reserve(policy, 1, 10, Some(105)).unwrap();
    assert_eq!(deadline_limited.end_ns(), 105);
    clock(&handle, 105);
    deadline_limited.finish().unwrap();
    assert_eq!(handle.snapshot().net_ns, 6);
    clock(&handle, 199);
    let frontier_limited = handle.try_reserve(policy, 1, 10, None).unwrap();
    assert_eq!(frontier_limited.end_ns(), 200);
    clock(&handle, 199);
    frontier_limited.finish().unwrap();
    assert_eq!(handle.snapshot().net_ns, 6);
    clock(&handle, 200);
    assert_eq!(
        handle.try_reserve(policy, 1, 10, Some(200)).unwrap_err(),
        "deadline_due"
    );
    assert_eq!(handle.snapshot().net_ns, 10);
    let credit_limited = handle.try_reserve(policy, 1, 50, None).unwrap();
    assert_eq!(credit_limited.end_ns(), 210);
    drop(credit_limited);
    assert_eq!(handle.snapshot().net_ns, 0);
}

#[test]
fn one_active_interval_across_clones_and_reconstructed_participants() {
    let (binding, handle, policy) = armed();
    let other = binding.participant_handle();
    let rebuilt = PollBudgetBinding::Participant(other.clone());
    let other = rebuilt.participant_handle();
    let interval = reserve(&handle, policy, 100, 10);
    clock(&other, 500);
    let before = handle.snapshot();
    assert_eq!(
        other.try_reserve(policy, 1, 10, None).unwrap_err(),
        "busy_interval_outstanding"
    );
    assert_eq!(before, other.snapshot());
    let record = interval.finish().unwrap();
    assert_eq!(record.elapsed_ns, 400);
    assert_eq!(record.net_ns, -390);
    assert_eq!(record.overrun_ns, 390);
    assert_eq!((record.forfeited_grants, record.forfeited_ns), (4, 40));
    assert_eq!(other.snapshot().next_refill_ns, Some(600));
    assert_eq!(
        other.try_reserve(policy, 1, 10, None).unwrap_err(),
        "quota_exhausted"
    );
}

#[test]
fn cancellation_never_refunds_and_unwind_charges_full_elapsed() {
    let (_binding, handle, policy) = armed();
    let interval = reserve(&handle, policy, 100, 8);
    clock(&handle, 101);
    drop(interval);
    assert_eq!(
        (handle.snapshot().net_ns, handle.snapshot().charged_ns),
        (2, 8)
    );
    let interval = reserve(&handle, policy, 200, 5);
    clock(&handle, 220);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _interval = interval;
        panic!("abandon synchronous Busy");
    }));
    assert!(result.is_err());
    let snapshot = handle.snapshot();
    assert_eq!(
        (snapshot.net_ns, snapshot.charged_ns, snapshot.overrun_ns),
        (-10, 28, 15)
    );
    assert_eq!(snapshot.active_id, None);
}

#[test]
fn publisher_drop_is_independent_of_process_revision_and_allows_only_settlement() {
    let (binding, handle, policy) = armed();
    let interval = reserve(&handle, policy, 100, 5);
    let revision = handle.revision();
    drop(binding);
    assert!(handle.publisher_closed());
    assert_eq!(handle.revision(), revision);
    clock(&handle, 102);
    assert_eq!(interval.finish().unwrap().net_ns, 8);
    assert_eq!(
        handle.try_reserve(policy, revision, 5, None).unwrap_err(),
        "publisher_closed"
    );
}

#[test]
fn participant_prepare_publish_and_raced_mismatch_never_mutate_ledger() {
    let (binding, handle, old) = armed();
    let participant = PollBudgetBinding::Participant(handle.clone());
    let before = handle.snapshot();
    assert_eq!(participant.prepare_policy(Some(old)), Ok(1));
    assert_eq!(participant.publish_policy(Some(old)), Ok(1));
    assert_eq!(participant.publish_policy(None), Ok(1));
    assert_eq!(handle.snapshot(), before);
    let new = policy(50, 5);
    assert_eq!(participant.prepare_policy(Some(new)), Err(MISMATCH));
    assert_eq!(participant.prepare_policy(Some(old)), Ok(1));
    clock(&handle, 10);
    assert_eq!(binding.publish_policy(Some(new)), Ok(2));
    let after_publisher = handle.snapshot();
    clock(&handle, 1_000);
    assert_eq!(participant.publish_policy(Some(old)), Err(MISMATCH));
    assert_eq!(handle.snapshot(), after_publisher);
    assert_eq!(participant.publish_policy(Some(new)), Ok(2));
    assert_eq!(handle.snapshot(), after_publisher);
    assert!(!handle.policy_matches(old));
    assert!(handle.policy_matches(new));
    assert_eq!(
        handle.try_reserve(new, 1, 5, None).unwrap_err(),
        "process_budget_revision_changed"
    );
    assert_eq!(handle.try_reserve(old, 2, 5, None).unwrap_err(), MISMATCH);
    clock(&handle, 1_000);
    assert_eq!(binding.publish_policy(Some(old)), Ok(3));
    assert_eq!(
        handle.try_reserve(old, 1, 5, None).unwrap_err(),
        "process_budget_revision_changed"
    );
}

#[test]
fn overdue_idle_publication_earns_only_old_schedule_before_new_parameters() {
    let (binding, handle, _) = armed();
    handle.0.ledger.lock().net_ns = -200;
    clock(&handle, 1_000);
    binding.publish_policy(Some(policy(10, 5))).unwrap();
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.net_ns, -100);
    assert_eq!(snapshot.next_refill_ns, Some(1_100));
    assert_eq!(snapshot.effective_policy, Some(policy(100, 10)));
    assert_eq!(snapshot.staged_policy, Some(policy(10, 5)));
}

#[test]
fn overdue_idle_publication_finishes_preexisting_staged_schedule_first() {
    let (binding, handle, _) = armed();
    handle.0.ledger.lock().net_ns = -200;
    clock(&handle, 50);
    binding.publish_policy(Some(policy(200, 5))).unwrap();
    clock(&handle, 1_000);
    binding.publish_policy(Some(policy(10, 5))).unwrap();
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.net_ns, -175);
    assert_eq!(snapshot.next_refill_ns, Some(1_100));
    assert_eq!(snapshot.effective_policy, Some(policy(200, 5)));
    assert_eq!(snapshot.staged_policy, Some(policy(10, 5)));
}

#[test]
fn equality_frontier_belongs_to_old_policy_and_growth_waits_another_frontier() {
    let (binding, handle, _) = armed();
    clock(&handle, 100);
    binding.publish_policy(Some(policy(20, 15))).unwrap();
    assert_eq!(handle.snapshot().net_ns, 10);
    assert_eq!(handle.snapshot().capacity_ns, 10);
    assert_eq!(handle.snapshot().next_refill_ns, Some(200));
    clock(&handle, 200);
    binding.publish_policy(Some(policy(20, 15))).unwrap();
    assert_eq!(handle.snapshot().net_ns, 10);
    assert_eq!(handle.snapshot().capacity_ns, 15);
    assert_eq!(handle.snapshot().next_refill_ns, Some(220));
    clock(&handle, 220);
    binding.publish_policy(Some(policy(20, 15))).unwrap();
    assert_eq!(handle.snapshot().net_ns, 15);
    assert_eq!(handle.snapshot().next_refill_ns, Some(240));
}

#[test]
fn tighten_then_loosen_keeps_burned_capacity_and_stable_frontier() {
    let (binding, handle, original) = armed();
    clock(&handle, 100);
    binding.publish_policy(Some(original)).unwrap();
    clock(&handle, 120);
    binding.publish_policy(Some(policy(30, 4))).unwrap();
    assert_eq!(handle.snapshot().net_ns, 4);
    assert_eq!(handle.snapshot().capacity_ns, 4);
    clock(&handle, 130);
    binding.publish_policy(Some(policy(300, 20))).unwrap();
    assert_eq!(handle.snapshot().net_ns, 4);
    assert_eq!(handle.snapshot().capacity_ns, 4);
    assert_eq!(handle.snapshot().next_refill_ns, Some(200));
    clock(&handle, 200);
    binding.publish_policy(Some(policy(300, 20))).unwrap();
    assert_eq!(handle.snapshot().net_ns, 4);
    assert_eq!(handle.snapshot().capacity_ns, 20);
    assert_eq!(handle.snapshot().next_refill_ns, Some(500));
    clock(&handle, 500);
    binding.publish_policy(Some(policy(300, 20))).unwrap();
    assert_eq!(handle.snapshot().net_ns, 20);
}

#[test]
fn tightening_clamps_net_plus_held_reservation_without_erasing_debt() {
    for reserved in [3, 8] {
        let (binding, handle, old) = armed();
        let interval = reserve(&handle, old, 100, reserved);
        clock(&handle, 101);
        binding.publish_policy(Some(policy(100, 4))).unwrap();
        assert_eq!(handle.snapshot().net_ns, 4 - i128::from(reserved));
        assert_eq!(handle.snapshot().reserved_ns, reserved);
        clock(&handle, 102);
        assert_eq!(interval.finish().unwrap().net_ns, 2);
    }
    let (binding, handle, old) = armed();
    let interval = reserve(&handle, old, 100, 8);
    clock(&handle, 101);
    binding.publish_policy(Some(policy(100, 4))).unwrap();
    binding.publish_policy(Some(policy(100, 20))).unwrap();
    assert_eq!(handle.snapshot().net_ns, -4);
    drop(interval);
    assert_eq!(handle.snapshot().net_ns, -4);
    assert_eq!(handle.snapshot().capacity_ns, 4);
}

#[test]
fn active_reload_never_advances_and_settlement_forfeits_old_and_new_frontiers() {
    let (binding, handle, old) = armed();
    let interval = reserve(&handle, old, 100, 10);
    clock(&handle, 1_000);
    binding.publish_policy(Some(policy(20, 5))).unwrap();
    assert_eq!(handle.snapshot().net_ns, -5);
    assert_eq!(handle.snapshot().next_refill_ns, Some(200));
    assert_eq!(handle.snapshot().forfeited_grants, 0);
    assert_ne!(handle.revision(), interval.process_revision());
    let record = interval.finish().unwrap();
    assert_eq!(record.elapsed_ns, 900);
    assert_eq!(record.net_ns, -895);
    assert_eq!(record.forfeited_grants, 41);
    assert_eq!(record.forfeited_ns, 205);
    assert_eq!(handle.snapshot().next_refill_ns, Some(1_020));
    assert_eq!(handle.snapshot().effective_policy, Some(policy(20, 5)));
    assert_eq!(handle.snapshot().staged_policy, None);
}

#[test]
fn removal_reintroduction_and_identical_reload_do_not_mint_or_reset() {
    let (binding, handle, old) = armed();
    let interval = reserve(&handle, old, 100, 10);
    clock(&handle, 105);
    interval.finish().unwrap();
    let before = handle.snapshot();
    binding.publish_policy(None).unwrap();
    assert_eq!(handle.snapshot(), before);
    binding.publish_policy(Some(old)).unwrap();
    let after = handle.snapshot();
    assert_eq!(after.net_ns, 5);
    assert_eq!(after.process_revision, 1);
    assert_eq!(after.next_refill_ns, Some(200));
    clock(&handle, 150);
    binding.publish_policy(Some(old)).unwrap();
    assert_eq!(handle.snapshot(), after);
    clock(&handle, 200);
    binding.publish_policy(Some(old)).unwrap();
    assert_eq!(handle.snapshot().net_ns, 10);
    assert_eq!(handle.snapshot().next_refill_ns, Some(300));
    assert_eq!(handle.revision(), 1);
}

#[test]
fn long_idle_bulk_advance_repays_debt_without_unbounded_credit() {
    let (binding, handle, old) = armed();
    handle.0.ledger.lock().net_ns = -1_000_000;
    clock(&handle, 1_000_000_000_000);
    binding.publish_policy(Some(old)).unwrap();
    assert_eq!(handle.snapshot().net_ns, 10);
    assert_eq!(handle.snapshot().next_refill_ns, Some(1_000_000_000_100));
    assert_eq!(handle.snapshot().forfeited_grants, 0);
}

#[test]
fn unknown_final_clock_or_backwards_time_retains_active_evidence() {
    for failed in [false, true] {
        let (_binding, handle, old) = armed();
        let interval = reserve(&handle, old, 100, 8);
        let before = handle.snapshot();
        if failed {
            handle.0.test_clock_failed.store(true, Ordering::Relaxed);
        } else {
            clock(&handle, 99);
        }
        assert_eq!(interval.finish(), Err(UNKNOWN));
        let after = handle.snapshot();
        assert_eq!(after.active_id, before.active_id);
        assert_eq!(after.reserved_ns, before.reserved_ns);
        assert_eq!(after.net_ns, before.net_ns);
        assert_eq!(after.next_refill_ns, before.next_refill_ns);
        assert_eq!(after.disabled_reason, Some(UNKNOWN));
        assert_eq!(handle.revision(), u64::MAX);
        clock(&handle, 1_000);
        handle.0.test_clock_failed.store(false, Ordering::Relaxed);
        assert_eq!(
            handle
                .try_reserve(old, handle.revision(), 1, None)
                .unwrap_err(),
            UNKNOWN
        );
        assert_eq!(handle.snapshot(), after);
    }
}

#[test]
fn drop_clock_failure_retains_reservation_and_never_assumes_reserved_elapsed() {
    let (_binding, handle, old) = armed();
    let interval = reserve(&handle, old, 100, 8);
    handle.0.test_clock_failed.store(true, Ordering::Relaxed);
    drop(interval);
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.net_ns, 2);
    assert_eq!(snapshot.reserved_ns, 8);
    assert!(snapshot.active_id.is_some());
    assert_eq!(snapshot.charged_ns, 0);
    assert_eq!(snapshot.disabled_reason, Some(UNKNOWN));
}

#[test]
fn backwards_publication_preserves_active_and_idle_accounting() {
    for active in [false, true] {
        let (binding, handle, old) = armed();
        let interval = if active {
            Some(reserve(&handle, old, 100, 8))
        } else {
            None
        };
        let before = handle.snapshot();
        if active {
            clock(&handle, 99);
        } else {
            clock(&handle, 10);
            binding.publish_policy(Some(old)).unwrap();
            clock(&handle, 9);
        }
        assert_eq!(binding.publish_policy(Some(policy(50, 5))), Err(UNKNOWN));
        let after = handle.snapshot();
        assert_eq!(after.active_id, before.active_id);
        assert_eq!(after.net_ns, before.net_ns);
        assert_eq!(after.desired_policy, before.desired_policy);
        assert_eq!(after.next_refill_ns, before.next_refill_ns);
        drop(interval);
        assert_eq!(handle.snapshot(), after);
    }
}

#[test]
fn stale_and_double_settlement_disable_without_refund() {
    let (_binding, handle, old) = armed();
    let interval = reserve(&handle, old, 100, 8);
    let token = interval.active;
    clock(&handle, 102);
    interval.finish().unwrap();
    let before = handle.snapshot();
    assert_eq!(handle.0.settle(token, false), Err(UNKNOWN));
    assert_eq!(handle.snapshot().net_ns, before.net_ns);
    assert_eq!(handle.snapshot().charged_ns, before.charged_ns);
    let (_binding, handle, old) = armed();
    let interval = reserve(&handle, old, 100, 8);
    let before = handle.snapshot();
    let wrong = Active {
        id: interval.active.id + 1,
        ..interval.active
    };
    assert_eq!(handle.0.settle(wrong, false), Err(UNKNOWN));
    drop(interval);
    assert_eq!(handle.snapshot().active_id, before.active_id);
    assert_eq!(handle.snapshot().net_ns, before.net_ns);
}

#[test]
fn revision_and_reservation_exhaustion_disable_without_wrapping() {
    let (binding, handle, _) = armed();
    handle.0.ledger.lock().policy_revision = u64::MAX - 1;
    handle.0.revision.store(u64::MAX - 1, Ordering::Release);
    assert_eq!(binding.publish_policy(Some(policy(50, 5))), Err(UNKNOWN));
    assert_eq!(handle.revision(), u64::MAX);
    assert_eq!(handle.snapshot().desired_policy, Some(policy(100, 10)));
    let (_binding, handle, old) = armed();
    handle.0.ledger.lock().reservation_revision = u64::MAX;
    clock(&handle, 100);
    assert_eq!(handle.try_reserve(old, 1, 10, None).unwrap_err(), UNKNOWN);
    assert_eq!(handle.snapshot().active_id, None);
    assert_eq!(handle.snapshot().net_ns, 10);
    assert_eq!(handle.0.ledger.lock().reservation_revision, u64::MAX);
}

#[test]
fn arithmetic_overflow_retains_last_proven_accounting_and_disables() {
    let (binding, handle) = fresh();
    clock(&handle, u64::MAX - 1);
    assert_eq!(binding.publish_policy(Some(policy(100, 10))), Err(UNKNOWN));
    assert_eq!(handle.snapshot().next_refill_ns, None);
    assert_eq!(handle.snapshot().net_ns, 0);

    let (binding, handle, old) = armed();
    clock(&handle, u64::MAX);
    let before = handle.snapshot();
    assert_eq!(binding.publish_policy(Some(old)), Err(UNKNOWN));
    assert_eq!(handle.snapshot().net_ns, before.net_ns);
    assert_eq!(handle.snapshot().next_refill_ns, before.next_refill_ns);

    for counter_overflow in [false, true] {
        let (_binding, handle, old) = armed();
        let interval = reserve(&handle, old, 100, 8);
        if counter_overflow {
            handle.0.ledger.lock().charged_ns = u128::MAX;
        } else {
            handle.0.ledger.lock().net_ns = i128::MIN;
        }
        let before = handle.snapshot();
        clock(&handle, 120);
        assert_eq!(interval.finish(), Err(UNKNOWN));
        let after = handle.snapshot();
        assert_eq!(after.active_id, before.active_id);
        assert_eq!(after.net_ns, before.net_ns);
        assert_eq!(after.charged_ns, before.charged_ns);
        assert_eq!(after.debt_ns, before.debt_ns);
    }
}

#[test]
fn cancellation_crossing_staged_frontiers_charges_and_forfeits_without_refund() {
    let (binding, handle, old) = armed();
    let interval = reserve(&handle, old, 100, 8);
    clock(&handle, 150);
    binding.publish_policy(Some(policy(50, 5))).unwrap();
    clock(&handle, 300);
    drop(interval);
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.net_ns, -195);
    assert_eq!(snapshot.charged_ns, 200);
    assert_eq!(snapshot.overrun_ns, 192);
    assert_eq!(snapshot.forfeited_grants, 3);
    assert_eq!(snapshot.forfeited_ns, 15);
    assert_eq!(snapshot.next_refill_ns, Some(350));
    assert_eq!(snapshot.active_id, None);
}

#[test]
fn reservation_clock_failure_and_forfeiture_counter_overflow_disable() {
    let (_binding, handle, old) = armed();
    handle.0.test_clock_failed.store(true, Ordering::Relaxed);
    let before = handle.snapshot();
    assert_eq!(handle.try_reserve(old, 1, 8, None).unwrap_err(), UNKNOWN);
    assert_eq!(handle.snapshot().net_ns, before.net_ns);
    assert_eq!(handle.snapshot().next_refill_ns, before.next_refill_ns);
    assert_eq!(handle.snapshot().active_id, None);

    let (_binding, handle, old) = armed();
    let interval = reserve(&handle, old, 100, 8);
    handle.0.ledger.lock().forfeited_grants = u64::MAX;
    let before = handle.snapshot();
    clock(&handle, 200);
    assert_eq!(interval.finish(), Err(UNKNOWN));
    let after = handle.snapshot();
    assert_eq!(after.active_id, before.active_id);
    assert_eq!(after.net_ns, before.net_ns);
    assert_eq!(after.charged_ns, before.charged_ns);
    assert_eq!(after.forfeited_grants, u64::MAX);
    assert_eq!(after.forfeited_ns, 0);
    assert_eq!(after.next_refill_ns, Some(200));
}

#[test]
fn unarmed_and_invalid_publication_cannot_create_credit() {
    let (binding, handle) = fresh();
    let before = handle.snapshot();
    assert_eq!(binding.publish_policy(None), Ok(0));
    assert_eq!(binding.prepare_policy(None), Ok(0));
    assert_eq!(handle.snapshot(), before);
    for invalid in [
        policy(0, 0),
        policy(100, 0),
        policy(100, 100),
        policy(100, 101),
    ] {
        assert_eq!(
            binding.prepare_policy(Some(invalid)),
            Err("busy_parameters_invalid")
        );
        assert_eq!(
            binding.publish_policy(Some(invalid)),
            Err("busy_parameters_invalid")
        );
        assert_eq!(handle.snapshot(), before);
    }
    clock(&handle, 1_000);
    binding.publish_policy(Some(policy(100, 10))).unwrap();
    assert_eq!(handle.snapshot().net_ns, 0);
    assert_eq!(handle.snapshot().next_refill_ns, Some(1_100));
}

#[test]
fn config_conversion_reuses_numeric_admission_and_checked_nanoseconds() {
    let mut config = BusyPollConfig {
        pps_enter: 1_000,
        pps_exit: 500,
        observation_window_us: 100,
        enter_windows: 2,
        exit_windows: 1,
        max_busy_us: 1,
        empty_rounds: 1,
        budget_window_us: 100,
        budget_us: 10,
        calibration: None,
    };
    assert_eq!(
        QuotaPolicy::from_config(&config),
        Ok(policy(100_000, 10_000))
    );
    config.max_busy_us = 11;
    assert_eq!(
        QuotaPolicy::from_config(&config),
        Err("busy_parameters_invalid")
    );
    config.max_busy_us = 1;
    config.budget_window_us = 0;
    assert_eq!(
        QuotaPolicy::from_config(&config),
        Err("busy_parameters_invalid")
    );
}
