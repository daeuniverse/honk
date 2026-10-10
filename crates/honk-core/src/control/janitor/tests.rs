use super::*;
use crate::ebpf::mock::MockEbpfBackend;
use honk_ebpf_common::{RedirectEntry, RedirectTuple};

#[test]
fn aux_pressure_uses_current_scan_result() {
    let at_watermark = (AUX_MAP_CAPACITY as f64 * CONN_STATE_PRESSURE_WATERMARK) as usize;
    assert!(!aux_scan_is_pressured(at_watermark, true));
    assert!(aux_scan_is_pressured(at_watermark + 1, true));
    assert!(aux_scan_is_pressured(0, false));
}

#[test]
fn scan_tuning_grows_with_pressure() {
    let steady = scan_tuning(0.5);
    let elevated = scan_tuning(CONN_STATE_ELEVATED_WATERMARK);
    let pressure = scan_tuning(CONN_STATE_PRESSURE_WATERMARK);

    assert!(steady.candidates < elevated.candidates);
    assert!(elevated.candidates < pressure.candidates);
    assert!(steady.budget < elevated.budget);
    assert!(elevated.budget < pressure.budget);
}

#[tokio::test]
async fn blocking_scan_keeps_hot_path_readers_available() {
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
        Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
    let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let scan = tokio::spawn(async move {
        janitor
            .run_blocking_read("test", move |_| {
                entered_tx.send(()).expect("test receiver stays alive");
                release_rx.recv().expect("test scan gets released");
            })
            .await
    });

    entered_rx.await.expect("blocking scan started");
    let read_available = tokio::time::timeout(Duration::from_millis(100), backend.read())
        .await
        .is_ok();
    release_tx.send(()).expect("release blocking scan");
    scan.await.expect("scan task joins");

    assert!(
        read_available,
        "bounded janitor scans must not block per-flow eBPF reads"
    );
}

#[tokio::test(start_paused = true)]
async fn supervised_stop_retains_blocking_scan_across_cancelled_join() {
    for panic_in_scan in [false, true] {
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
        let retained_backend = Arc::downgrade(&backend);
        let mut janitor = BpfJanitor::new(backend, Arc::new(TcpFlowPins::default()));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let entered_tx = parking_lot::Mutex::new(Some(entered_tx));
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = parking_lot::Mutex::new(release_rx);
        janitor.blocking_read_hook = Some(Arc::new(move || {
            if let Some(entered_tx) = entered_tx.lock().take() {
                entered_tx.send(()).expect("test receiver stays alive");
                release_rx
                    .lock()
                    .recv()
                    .expect("test releases blocking scan");
                assert!(!panic_in_scan, "injected blocking scan panic");
            }
        }));
        let (stop_tx, stop_rx) = watch::channel(false);
        let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut task = janitor.spawn_supervised(
            super::super::runtime::CriticalTaskExit {
                name: "bpf_janitor",
                fatal_tx,
                expected: false,
            },
            stop_rx,
        );

        entered_rx.await.expect("supervised blocking scan started");
        stop_tx.send(true).expect("janitor owns stop receiver");
        let mut wait = Box::pin(tokio::time::timeout(Duration::from_secs(1), &mut task));
        assert!(futures::poll!(&mut wait).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            wait.await.is_err(),
            "stop must retain the blocked scan join"
        );
        assert!(!task.is_finished());
        assert!(retained_backend.upgrade().is_some());

        release_tx.send(()).expect("release blocking scan");
        let result = task.await;
        if panic_in_scan {
            assert!(
                result
                    .expect_err("scan panic must fail janitor join")
                    .is_panic()
            );
            assert!(
                fatal_rx.try_recv().is_ok(),
                "stop must not hide a prior panic"
            );
        } else {
            result.expect("janitor joins after its blocking scan");
            assert!(
                fatal_rx.try_recv().is_err(),
                "cooperative stop is not fatal"
            );
        }
        assert!(
            retained_backend.upgrade().is_none(),
            "acknowledged stop must leave no owner able to access the backend"
        );
    }
}

#[test]
fn test_pressure_state_enter_on_overflow_delta() {
    let mut state = PressureState::default();
    assert!(!state.active);

    update_pressure_state(&mut state, true, 0.0);
    assert!(state.active);
    assert_eq!(state.quiet_rounds, 0);
}

#[test]
fn test_pressure_state_enter_on_high_watermark() {
    let mut state = PressureState::default();
    assert!(!state.active);

    update_pressure_state(&mut state, false, CONN_STATE_PRESSURE_WATERMARK + 0.01);
    assert!(state.active);
    assert_eq!(state.quiet_rounds, 0);
}

#[test]
fn test_pressure_state_stays_inactive_below_watermark() {
    let mut state = PressureState::default();
    for _ in 0..10 {
        update_pressure_state(&mut state, false, CONN_STATE_PRESSURE_WATERMARK - 0.01);
        assert!(!state.active);
    }
}

#[test]
fn test_pressure_state_exit_after_quiet_rounds() {
    let mut state = PressureState {
        active: true,
        quiet_rounds: 0,
        last_udp_overflow: 0,
        last_tcp_overflow: 0,
    };

    // No overflow and below the watermark for PRESSURE_EXIT_ROUNDS
    // consecutive ticks → exit.
    for _ in 0..PRESSURE_EXIT_ROUNDS {
        assert!(state.active);
        update_pressure_state(&mut state, false, 0.0);
    }
    assert!(!state.active);
}

#[test]
fn test_pressure_state_overflow_resets_quiet_counter() {
    let mut state = PressureState {
        active: true,
        quiet_rounds: 2,
        last_udp_overflow: 0,
        last_tcp_overflow: 0,
    };

    // A new overflow restarts the quiet-period countdown.
    update_pressure_state(&mut state, true, 0.0);
    assert!(state.active);
    assert_eq!(state.quiet_rounds, 0);

    // And it still takes the full run of quiet ticks to exit.
    for _ in 0..PRESSURE_EXIT_ROUNDS - 1 {
        update_pressure_state(&mut state, false, 0.0);
        assert!(state.active);
    }
    update_pressure_state(&mut state, false, 0.0);
    assert!(!state.active);
}

#[test]
fn test_pressure_state_inactive_stays_inactive_without_overflow() {
    let mut state = PressureState::default();
    for _ in 0..10 {
        update_pressure_state(&mut state, false, 0.0);
        assert!(!state.active);
    }
}

#[test]
fn test_occupancy_gauge_estimate_and_calibrate() {
    let mut gauge = OccupancyGauge::default();
    // 100 inserts, 30 datapath deletes, 20 janitor deletes, 10 userspace
    // deletes → 40 live.
    gauge.note_janitor_deletes(20);
    assert_eq!(gauge.estimate(100, 30, 10), 40);

    // A sweep observes 35 entries (5 lost to races) → drift corrects.
    gauge.calibrate(35, 100, 30, 10);
    assert_eq!(gauge.estimate(100, 30, 10), 35);
    // Post-calibration deltas apply on top of the exact count.
    assert_eq!(gauge.estimate(110, 35, 12), 38);
}

#[test]
fn test_occupancy_gauge_never_negative() {
    let gauge = OccupancyGauge::default();
    assert_eq!(gauge.estimate(0, 10, 5), 0);
}

#[test]
fn test_monotonic_now_ns_returns_value() {
    let ns = monotonic_now_ns().expect("monotonic time should be available");
    assert!(ns > 0, "monotonic time should be positive, got {}", ns);
}
fn test_tuple(src_port: u16, l4proto: u8) -> TuplesKey {
    let mut key: TuplesKey = unsafe { std::mem::zeroed() };
    key.src_ip[15] = 1;
    key.dst_ip[15] = 2;
    key.src_port = src_port;
    key.dst_port = 443;
    key.l4proto = l4proto;
    key
}

fn test_state(state: TcpState, last_seen_ns: u64) -> ConnState {
    ConnState {
        state: state as u8,
        last_seen_ns,
        ..Default::default()
    }
}

#[tokio::test]
async fn aux_pressure_detects_bounded_scan_and_recovers() -> anyhow::Result<()> {
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
        Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
    let stale = RedirectEntry::default();
    {
        let mut backend = backend.write().await;
        for port in 0..=(JANITOR_BASE_CANDIDATES as u16) {
            backend
                .redirect_track_store(&RedirectTuple::from_tuples(&test_tuple(port, 17)), &stale)?;
        }
    }

    let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
    let first = janitor
        .cleanup_redirect_track_at(REDIRECT_TRACK_TIMEOUT_NS + 1, scan_tuning(0.0))
        .await;
    assert_eq!(first.deleted, JANITOR_BASE_CANDIDATES as u64);
    assert_eq!(first.scanned, JANITOR_BASE_CANDIDATES);
    assert!(!first.complete);
    assert!(aux_scan_is_pressured(first.scanned, first.complete));

    let second = janitor
        .cleanup_redirect_track_at(
            REDIRECT_TRACK_TIMEOUT_NS + 1,
            scan_tuning(CONN_STATE_PRESSURE_WATERMARK),
        )
        .await;
    assert_eq!(second.deleted, 1);
    assert_eq!(second.scanned, 1);
    assert!(second.complete);
    assert!(!aux_scan_is_pressured(second.scanned, second.complete));

    Ok(())
}

#[tokio::test]
async fn map_health_warnings_rearm_after_pressure_ends() {
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
        Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
    let janitor = BpfJanitor::new(backend, Arc::new(TcpFlowPins::default()));
    let high = (AUX_MAP_CAPACITY as f64 * AUX_MAP_PRESSURE_WATERMARK) as usize + 1;
    let redirect = |scanned, complete| {
        [
            AuxScanResult {
                deleted: 0,
                scanned,
                complete,
            },
            AuxScanResult::default(),
            AuxScanResult::default(),
        ]
    };
    let mut failures = [0; 3];
    let mut aux_warned = [false; 3];
    let mut pressure_warned = [false; 4];
    for (utilization, pressure, scans, aux_expected, occupancy_expected) in [
        (
            CONN_STATE_PRESSURE_WATERMARK,
            true,
            redirect(high, true),
            true,
            true,
        ),
        // A bounded scan below the watermark is only a lower bound.
        (0.0, false, redirect(0, false), true, false),
        (0.0, false, redirect(0, true), false, false),
        (
            CONN_STATE_PRESSURE_WATERMARK,
            true,
            redirect(high, true),
            true,
            true,
        ),
    ] {
        janitor
            .check_map_health(
                utilization,
                pressure,
                scans,
                &mut failures,
                &mut aux_warned,
                &mut pressure_warned,
            )
            .await;
        assert_eq!(aux_warned[0], aux_expected);
        assert_eq!(pressure_warned[3], occupancy_expected);
    }
}

#[tokio::test]
async fn tcp_pin_conn_state_matrix() -> anyhow::Result<()> {
    let pinned_active = test_tuple(10_001, IPPROTO_TCP);
    let pinned_closing = test_tuple(10_002, IPPROTO_TCP);
    let unpinned_active = test_tuple(10_003, IPPROTO_TCP);
    let unpinned_closing = test_tuple(10_004, IPPROTO_TCP);
    let udp = test_tuple(10_005, 17);
    let now_ns = TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + 1;

    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
        Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
    {
        let mut backend = backend.write().await;
        backend.tcp_conn_state_store(&pinned_active, &test_state(TcpState::TcpStateActive, 0))?;
        backend.tcp_conn_state_store(&pinned_closing, &test_state(TcpState::TcpStateClosing, 0))?;
        backend.tcp_conn_state_store(&unpinned_active, &test_state(TcpState::TcpStateActive, 0))?;
        backend
            .tcp_conn_state_store(&unpinned_closing, &test_state(TcpState::TcpStateClosing, 0))?;
        backend.udp_conn_state_store(&udp, &test_state(TcpState::TcpStateActive, 0))?;
    }

    let pins = Arc::new(TcpFlowPins::default());
    pins.retain_for_test(TcpFlowKey::from_tuples(&pinned_active));
    pins.retain_for_test(TcpFlowKey::from_tuples(&pinned_closing));
    let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::clone(&pins));

    assert_eq!(janitor.cleanup_conn_state_for_test(now_ns).await, (3, 5));
    {
        let backend = backend.read().await;
        assert!(backend.tcp_conn_state_lookup(&pinned_active)?.is_some());
        assert!(backend.tcp_conn_state_lookup(&pinned_closing)?.is_some());
        assert!(backend.tcp_conn_state_lookup(&unpinned_active)?.is_none());
        assert!(backend.tcp_conn_state_lookup(&unpinned_closing)?.is_none());
        assert!(backend.udp_conn_state_lookup(&udp)?.is_none());
    }

    assert_eq!(
        pins.release_for_test(TcpFlowKey::from_tuples(&pinned_active)),
        Some(true)
    );
    assert_eq!(
        pins.release_for_test(TcpFlowKey::from_tuples(&pinned_closing)),
        Some(true)
    );
    assert_eq!(janitor.cleanup_conn_state_for_test(now_ns).await, (2, 2));
    let backend = backend.read().await;
    assert!(backend.tcp_conn_state_lookup(&pinned_active)?.is_none());
    assert!(backend.tcp_conn_state_lookup(&pinned_closing)?.is_none());

    anyhow::Ok(())
}

#[tokio::test]
async fn tcp_pin_redirect_matrix() -> anyhow::Result<()> {
    let pinned_key = test_tuple(20_001, IPPROTO_TCP);
    let unpinned_key = test_tuple(20_002, IPPROTO_TCP);
    let udp_key = test_tuple(20_003, 17);
    let pinned = RedirectTuple::from_tuples(&pinned_key);
    let unpinned = RedirectTuple::from_tuples(&unpinned_key);
    let udp = RedirectTuple::from_tuples(&udp_key);
    let stale = RedirectEntry {
        last_seen_ns: 0,
        ..Default::default()
    };
    let now_ns = REDIRECT_TRACK_TIMEOUT_NS + 1;

    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> =
        Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
    {
        let mut backend = backend.write().await;
        backend.redirect_track_store(&pinned, &stale)?;
        backend.redirect_track_store(&unpinned, &stale)?;
        backend.redirect_track_store(&udp, &stale)?;
    }

    let pins = Arc::new(TcpFlowPins::default());
    pins.retain_for_test(TcpFlowKey::from_tuples(&pinned_key));
    let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::clone(&pins));

    assert_eq!(
        janitor.cleanup_redirect_track_for_test(now_ns).await,
        (2, 3)
    );
    {
        let backend = backend.read().await;
        assert!(backend.redirect_track_lookup(&pinned)?.is_some());
        assert!(backend.redirect_track_lookup(&unpinned)?.is_none());
        assert!(backend.redirect_track_lookup(&udp)?.is_none());
    }

    assert_eq!(
        pins.release_for_test(TcpFlowKey::from_tuples(&pinned_key)),
        Some(true)
    );
    assert_eq!(
        janitor.cleanup_redirect_track_for_test(now_ns).await,
        (1, 1)
    );
    assert!(
        backend
            .read()
            .await
            .redirect_track_lookup(&pinned)?
            .is_none()
    );

    Ok(())
}
