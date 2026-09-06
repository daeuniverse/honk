use super::*;
#[test]
fn overflow_terminal_events_cap_per_stream() {
    let mut overflow = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_HARD_CAP {
        overflow.push_back(1, StreamEvent::Data(InboundPayload::for_test(vec![1])));
    }

    assert!(matches!(
        overflow.admit(1, StreamEvent::Fin),
        OverflowAction::Parked
    ));
    assert!(matches!(
        overflow.admit(1, StreamEvent::Error(Arc::from("x"))),
        OverflowAction::Parked
    ));

    assert!(matches!(
        overflow.admit(1, StreamEvent::Fin),
        OverflowAction::Dropped
    ));
    assert!(matches!(
        overflow.admit(2, StreamEvent::Fin),
        OverflowAction::Parked
    ));
    assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_HARD_CAP);
    assert_eq!(overflow.stream_usage(1).frames, SESSION_OVERFLOW_HARD_CAP);
}

#[test]
fn overflow_state_accounting_tracks_every_queue_operation() {
    let mut overflow = OverflowState::default();
    overflow.push_back(
        1,
        StreamEvent::Data(InboundPayload::for_test(vec![1, 2, 3])),
    );
    overflow.push_back(1, StreamEvent::Fin);
    overflow.push_back(2, StreamEvent::Data(InboundPayload::for_test(vec![0; 5])));
    assert_eq!(
        overflow.usage(),
        OverflowUsage {
            frames: 2,
            bytes: 8
        }
    );

    let event = overflow.pop_front(1).unwrap();
    assert_eq!(
        overflow.usage(),
        OverflowUsage {
            frames: 1,
            bytes: 5
        }
    );
    overflow.push_front(1, event);
    assert_eq!(
        overflow.usage(),
        OverflowUsage {
            frames: 2,
            bytes: 8
        }
    );

    assert_eq!(
        overflow.remove_stream(1),
        OverflowUsage {
            frames: 1,
            bytes: 3
        }
    );
    assert_eq!(
        overflow.usage(),
        OverflowUsage {
            frames: 1,
            bytes: 5
        }
    );
    assert_eq!(
        overflow.clear(),
        OverflowUsage {
            frames: 1,
            bytes: 5
        }
    );
    assert_eq!(overflow.usage(), OverflowUsage::default());
}

#[tokio::test(start_paused = true)]
async fn overflow_full_requeue_preserves_stall_age() {
    let mut overflow = OverflowState::default();
    overflow.push_back(1, StreamEvent::Data(InboundPayload::for_test(vec![1])));
    tokio::time::advance(Duration::from_secs(2)).await;

    let progress = overflow.last_progress_at(1);
    let event = overflow.pop_front(1).unwrap();
    overflow.push_front(1, event);
    overflow.restore_last_progress_at(1, progress);

    assert_eq!(overflow.stalled_for(1), Duration::from_secs(2));
}

#[tokio::test(start_paused = true)]
async fn overflow_flush_progress_resets_stall_age() {
    let mut overflow = OverflowState::default();
    overflow.push_back(1, StreamEvent::Data(InboundPayload::for_test(vec![1])));
    tokio::time::advance(Duration::from_secs(2)).await;
    overflow.note_progress(1);
    tokio::time::advance(Duration::from_secs(2)).await;

    assert_eq!(overflow.stalled_for(1), Duration::from_secs(2));
}

#[tokio::test(start_paused = true)]
async fn overflow_admit_below_hard_caps_never_kills() {
    let mut overflow = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_HARD_CAP - 1 {
        overflow.push_back(1, StreamEvent::Data(InboundPayload::for_test(vec![1])));
    }
    tokio::time::advance(OVERFLOW_STALL_GRACE * 4).await;
    assert!(matches!(
        overflow.admit(2, StreamEvent::Data(InboundPayload::for_test(vec![2]))),
        OverflowAction::Parked
    ));
    assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_HARD_CAP);
}

/// Hard cap with a past-grace stream: the admit reaps the
/// most-stalled stream immediately and hands the event back; the
/// retry parks on the freed space.
#[tokio::test(start_paused = true)]
async fn overflow_admit_hard_cap_reaps_past_grace_stream() {
    let mut overflow = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_HARD_CAP {
        overflow.push_back(1, StreamEvent::Data(InboundPayload::for_test(vec![1; 8])));
    }
    tokio::time::advance(OVERFLOW_STALL_GRACE).await;

    let OverflowAction::Kill(victim, event) =
        overflow.admit(2, StreamEvent::Data(InboundPayload::for_test(vec![9])))
    else {
        panic!("past-grace stream at the hard cap must be reaped")
    };
    assert_eq!(victim.sid, 1);
    assert_eq!(victim.limit, OverflowLimit::SessionFrames);
    assert!(victim.stalled_for >= OVERFLOW_STALL_GRACE);
    assert!(!overflow.has(1));

    assert!(matches!(overflow.admit(2, event), OverflowAction::Parked));
    assert_eq!(overflow.usage().frames, 1);
}

/// Hard cap with every stream inside the grace: the admit asks the
/// caller to wait a bounded round instead of killing or parking past
/// the cap; once a stalled stream crosses the grace, the same admit
/// reaps it.
#[tokio::test(start_paused = true)]
async fn overflow_admit_hard_cap_waits_inside_the_grace() {
    let mut overflow = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_HARD_CAP {
        overflow.push_back(1, StreamEvent::Data(InboundPayload::for_test(vec![1; 8])));
    }
    let wait = match overflow.admit(2, StreamEvent::Data(InboundPayload::for_test(vec![9]))) {
        OverflowAction::Wait(_, wait) => wait,
        _ => panic!("hard cap inside the grace must wait, not kill"),
    };
    assert!(wait <= OVERFLOW_EMERGENCY_WAIT);
    assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_HARD_CAP);
    assert!(overflow.has(1));

    tokio::time::advance(OVERFLOW_STALL_GRACE).await;
    let OverflowAction::Kill(victim, event) =
        overflow.admit(2, StreamEvent::Data(InboundPayload::for_test(vec![9])))
    else {
        panic!("hard cap past the grace must reap")
    };
    assert_eq!(victim.sid, 1);
    assert!(victim.stalled_for >= OVERFLOW_STALL_GRACE);
    assert!(matches!(overflow.admit(2, event), OverflowAction::Parked));
}
