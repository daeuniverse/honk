use super::*;
#[test]
fn overflow_state_enforces_frame_and_byte_caps_independently() {
    let mut frames = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_CAP {
        frames.push_back(1, StreamEvent::Data(InboundPayload::for_test(vec![1])));
    }
    assert_eq!(frames.usage().bytes, SESSION_OVERFLOW_CAP);
    assert_eq!(
        frames.limit_for(2, &StreamEvent::Data(InboundPayload::for_test(vec![1])),),
        Some(OverflowLimit::SessionFrames)
    );

    let mut stream_bytes = OverflowState::default();
    stream_bytes.push_back(
        1,
        StreamEvent::Data(InboundPayload::for_test(vec![0; STREAM_OVERFLOW_BYTES_CAP])),
    );
    assert_eq!(
        stream_bytes.limit_for(1, &StreamEvent::Data(InboundPayload::for_test(vec![1])),),
        Some(OverflowLimit::StreamBytes)
    );

    let mut session_bytes = OverflowState::default();
    for sid in 1..=4 {
        session_bytes.push_back(
            sid,
            StreamEvent::Data(InboundPayload::for_test(vec![0; STREAM_OVERFLOW_BYTES_CAP])),
        );
    }
    assert_eq!(session_bytes.usage().bytes, SESSION_OVERFLOW_BYTES_CAP);
    assert_eq!(
        session_bytes.limit_for(5, &StreamEvent::Data(InboundPayload::for_test(vec![1])),),
        Some(OverflowLimit::SessionBytes)
    );
    assert_eq!(session_bytes.limit_for(5, &StreamEvent::Fin), None);

    let mut competing_limits = OverflowState::default();
    competing_limits.push_back(
        9,
        StreamEvent::Data(InboundPayload::for_test(vec![0; STREAM_OVERFLOW_BYTES_CAP])),
    );
    for _ in 1..SESSION_OVERFLOW_CAP {
        competing_limits.push_back(10, StreamEvent::Data(InboundPayload::for_test(vec![2])));
    }
    assert_eq!(
        competing_limits.limit_for(9, &StreamEvent::Data(InboundPayload::for_test(vec![1])),),
        Some(OverflowLimit::SessionFrames)
    );

    let mut competing_session_limits = OverflowState::default();
    for sid in 1..=4 {
        competing_session_limits.push_back(
            sid,
            StreamEvent::Data(InboundPayload::for_test(vec![0; STREAM_OVERFLOW_BYTES_CAP])),
        );
    }
    for _ in 4..SESSION_OVERFLOW_CAP {
        competing_session_limits
            .push_back(10, StreamEvent::Data(InboundPayload::for_test(vec![3])));
    }
    assert_eq!(
        competing_session_limits
            .limit_for(11, &StreamEvent::Data(InboundPayload::for_test(vec![1])),),
        Some(OverflowLimit::SessionBytes)
    );

    let mut errors = OverflowState::default();
    errors.push_back(1, StreamEvent::Error(Arc::from("remote error")));
    errors.push_back(1, StreamEvent::Fin);
    assert_eq!(errors.usage(), OverflowUsage::default());
    assert_eq!(errors.stream_usage(1).frames, 0);
}

#[test]
fn overflow_terminal_events_cap_per_stream() {
    let mut overflow = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_CAP {
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
    assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_CAP);
    assert_eq!(overflow.stream_usage(1).frames, SESSION_OVERFLOW_CAP);
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

/// Soft caps never kill, no matter how stale the stream: only the
/// watchdog reaps on stall age, only the hard caps reap in admit.
#[tokio::test(start_paused = true)]
async fn overflow_admit_below_hard_caps_never_kills() {
    let mut overflow = OverflowState::default();
    overflow.push_back(
        1,
        StreamEvent::Data(InboundPayload::for_test(vec![0; STREAM_OVERFLOW_BYTES_CAP])),
    );
    tokio::time::advance(OVERFLOW_STALL_GRACE * 4).await;
    assert!(matches!(
        overflow.admit(1, StreamEvent::Data(InboundPayload::for_test(vec![1])),),
        OverflowAction::Parked
    ));
    assert_eq!(
        overflow.stream_usage(1).bytes,
        STREAM_OVERFLOW_BYTES_CAP + 1
    );

    let mut session_soft = OverflowState::default();
    for _ in 0..SESSION_OVERFLOW_CAP {
        session_soft.push_back(1, StreamEvent::Data(InboundPayload::for_test(vec![1])));
    }
    tokio::time::advance(OVERFLOW_STALL_GRACE * 4).await;
    assert!(matches!(
        session_soft.admit(2, StreamEvent::Data(InboundPayload::for_test(vec![2])),),
        OverflowAction::Parked
    ));
    assert_eq!(session_soft.usage().frames, SESSION_OVERFLOW_CAP + 1);
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
