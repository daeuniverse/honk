use super::super::connection::TcpFlowKey;
use super::*;
use crate::ebpf::mock::MockEbpfBackend;
use crate::ebpf::{RetireCounts, RetireError};
use honk_ebpf_common::conn::{
    ConnState, REDIRECT_TRACK_TIMEOUT_NS, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState,
    UDP_CONN_STATE_TIMEOUT_NS,
};
use honk_ebpf_common::{RedirectEntry, RedirectTuple, TuplesKey};

mod admission;
mod cadence;
mod cursor;
mod redirect_retention;
mod telemetry;

const IPPROTO_TCP: u8 = 6;

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
    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
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
    assert!(
        scan.await
            .expect("scan task joins")
            .expect("TC capability remains available")
            .is_some()
    );

    assert!(
        read_available,
        "bounded janitor scans must not block per-flow eBPF reads"
    );
}

#[tokio::test(start_paused = true)]
async fn supervised_stop_retains_blocking_scan_across_cancelled_join() {
    for panic_in_scan in [false, true] {
        let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
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

    update_pressure_state(&mut state, true, [0.0; 3]);
    assert!(state.active);
    assert_eq!(state.quiet_rounds, 0);
}

#[test]
fn test_pressure_state_enter_on_high_watermark() {
    let mut state = PressureState::default();
    assert!(!state.active);

    update_pressure_state(
        &mut state,
        false,
        [CONN_STATE_PRESSURE_WATERMARK + 0.01, 0.0, 0.0],
    );
    assert!(state.active);
    assert_eq!(state.quiet_rounds, 0);
}

#[test]
fn test_pressure_state_stays_inactive_below_watermark() {
    let mut state = PressureState::default();
    for _ in 0..10 {
        update_pressure_state(
            &mut state,
            false,
            [CONN_STATE_PRESSURE_WATERMARK - 0.01, 0.0, 0.0],
        );
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
        update_pressure_state(&mut state, false, [0.0; 3]);
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
    update_pressure_state(&mut state, true, [0.0; 3]);
    assert!(state.active);
    assert_eq!(state.quiet_rounds, 0);

    // And it still takes the full run of quiet ticks to exit.
    for _ in 0..PRESSURE_EXIT_ROUNDS - 1 {
        update_pressure_state(&mut state, false, [0.0; 3]);
        assert!(state.active);
    }
    update_pressure_state(&mut state, false, [0.0; 3]);
    assert!(!state.active);
}

#[test]
fn test_pressure_state_inactive_stays_inactive_without_overflow() {
    let mut state = PressureState::default();
    for _ in 0..10 {
        update_pressure_state(&mut state, false, [0.0; 3]);
        assert!(!state.active);
    }
}

#[test]
fn test_occupancy_gauge_estimate_and_calibrate() {
    let mut gauge = OccupancyGauge::default();
    // 100 inserts, 30 datapath deletes, 30 userspace deletes → 40 live.
    assert_eq!(gauge.estimate(100, 30, 30), 40);

    // A sweep observes 35 entries (5 lost to races) → drift corrects.
    gauge.calibrate(35, 100, 30, 30);
    assert_eq!(gauge.estimate(100, 30, 30), 35);
    // Post-calibration deltas apply on top of the exact count.
    assert_eq!(gauge.estimate(110, 35, 32), 38);
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
    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
    let stale = RedirectEntry::default();
    {
        let mut backend = tokio::sync::RwLockWriteGuard::map(backend.write().await, |backend| {
            backend.tc_mut().unwrap()
        });
        for port in 0..=(JANITOR_BASE_CANDIDATES as u16) {
            backend
                .redirect_track_store(&RedirectTuple::from_tuples(&test_tuple(port, 17)), &stale)?;
        }
    }

    let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
    let first = janitor
        .cleanup_redirect_track_at(REDIRECT_TRACK_TIMEOUT_NS + 1, scan_tuning(0.0))
        .await?;
    assert_eq!(first.deleted, JANITOR_BASE_CANDIDATES as u64);
    assert_eq!(first.scanned, JANITOR_BASE_CANDIDATES);
    assert!(!first.complete);
    assert!(aux_scan_is_pressured(first.scanned, first.complete));

    let second = janitor
        .cleanup_redirect_track_at(
            REDIRECT_TRACK_TIMEOUT_NS + 1,
            scan_tuning(CONN_STATE_PRESSURE_WATERMARK),
        )
        .await?;
    assert_eq!(second.deleted, 1);
    assert_eq!(second.scanned, 1);
    assert!(
        !second.complete,
        "a resumed tail is not an exact map cardinality"
    );

    Ok(())
}

#[tokio::test]
async fn map_health_warnings_rearm_after_pressure_ends() {
    let mut model = MockEbpfBackend::new();
    for key in BpfStatsKey::ALL {
        model.bpf_stats.insert(key as u32, 101 + key as u64);
    }
    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(model)));
    let janitor = BpfJanitor::new(backend, Arc::new(TcpFlowPins::default()));
    let high = (AUX_MAP_CAPACITY as f64 * AUX_MAP_PRESSURE_WATERMARK) as usize + 1;
    for map in AuxMap::ALL {
        let scans = |scanned, complete| {
            let mut scans = [AuxScanResult::default(); AuxMap::COUNT];
            scans[map as usize] = AuxScanResult {
                deleted: 0,
                scanned,
                complete,
            };
            scans
        };
        let mut health = HealthLatches::default();
        for (episode, (utilization, pressure, scans, aux_expected, occupancy_expected)) in [
            (
                CONN_STATE_PRESSURE_WATERMARK,
                true,
                scans(high, true),
                true,
                true,
            ),
            // A bounded scan below the watermark is only a lower bound.
            (0.0, false, scans(0, false), true, false),
            (0.0, false, scans(0, true), false, false),
            (
                CONN_STATE_PRESSURE_WATERMARK,
                true,
                scans(high, true),
                true,
                true,
            ),
            (0.1, true, scans(high, true), true, false),
        ]
        .into_iter()
        .enumerate()
        {
            let mut utilizations = [utilization, 0.0, 0.0];
            if pressure {
                utilizations[1 + map as usize] = 0.9;
            }
            janitor
                .check_map_health(utilizations, scans, &mut health)
                .await
                .unwrap();
            assert_eq!(health.aux_pressure_warned[map as usize], aux_expected);
            assert_eq!(health.occupancy_warned, occupancy_expected);
            assert_eq!(
                (
                    health.overflow_warned,
                    health.udp_pressure_warned,
                    health.tcp_pressure_warned
                ),
                (episode == 0, episode == 0, episode == 0),
                "unchanged overflow history must not be promoted during an occupancy episode",
            );
            for key in BpfStatsKey::ALL {
                assert_eq!(health.last_failures[key as usize], 101 + key as u64);
            }
        }
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

    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
    {
        let mut backend = tokio::sync::RwLockWriteGuard::map(backend.write().await, |backend| {
            backend.tc_mut().unwrap()
        });
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
        let backend = tokio::sync::RwLockReadGuard::map(backend.read().await, |backend| {
            backend.tc().unwrap()
        });
        assert!(backend.conn_state_lookup(&pinned_active)?.is_some());
        assert!(backend.conn_state_lookup(&pinned_closing)?.is_some());
        assert!(backend.conn_state_lookup(&unpinned_active)?.is_none());
        assert!(backend.conn_state_lookup(&unpinned_closing)?.is_none());
        assert!(backend.conn_state_lookup(&udp)?.is_none());
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
    let backend =
        tokio::sync::RwLockReadGuard::map(backend.read().await, |backend| backend.tc().unwrap());
    assert!(backend.conn_state_lookup(&pinned_active)?.is_none());
    assert!(backend.conn_state_lookup(&pinned_closing)?.is_none());

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

    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())));
    {
        let mut backend = tokio::sync::RwLockWriteGuard::map(backend.write().await, |backend| {
            backend.tc_mut().unwrap()
        });
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
        let backend = tokio::sync::RwLockReadGuard::map(backend.read().await, |backend| {
            backend.tc().unwrap()
        });
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
            .tc()
            .unwrap()
            .redirect_track_lookup(&pinned)?
            .is_none()
    );

    Ok(())
}

#[tokio::test]
async fn pinned_tcp_prefix_does_not_consume_candidate_budget() -> anyhow::Result<()> {
    use honk_ebpf_common::RoutingHandoffEntry;

    let now_ns = TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + 1;
    for map in ["conn", "redirect", "handoff"] {
        let mut model = MockEbpfBackend::new();
        for port in 1..=(JANITOR_BASE_CANDIDATES as u16 + 2) {
            let key = test_tuple(port, IPPROTO_TCP);
            let mut state = test_state(TcpState::TcpStateActive, 0);
            state.incarnation = u64::from(port);
            model.tcp_conn_state_store(&key, &state)?;
            model.redirect_track_store(
                &RedirectTuple::from_tuples(&key),
                &RedirectEntry {
                    incarnation: state.incarnation,
                    ..Default::default()
                },
            )?;
        }
        for (key, state) in &model.tcp_conn_states {
            model.routing_handoffs.lock().insert(
                *key,
                RoutingHandoffEntry {
                    incarnation: state.incarnation,
                    ..Default::default()
                },
            );
        }

        // Discover this map's stable traversal order, not HashMap's random seed.
        // Replacing values below does not insert/remove keys or reorder buckets.
        let mut order = Vec::new();
        match map {
            "conn" => model.conn_state_for_each_chunk(
                JANITOR_SCAN_CHUNK,
                &mut crate::ebpf::FlowScanCursor::default(),
                &mut |chunk| {
                    order.extend(chunk.iter().map(|(key, _)| *key));
                    true
                },
            )?,
            "redirect" => model.redirect_track_for_each_chunk(
                JANITOR_SCAN_CHUNK,
                &mut crate::ebpf::FlowScanCursor::default(),
                &mut |chunk| {
                    order.extend(
                        chunk
                            .iter()
                            .map(|(key, _)| test_tuple(key.src_port, IPPROTO_TCP)),
                    );
                    true
                },
            )?,
            "handoff" => model.routing_handoff_for_each_chunk(
                JANITOR_SCAN_CHUNK,
                &mut crate::ebpf::FlowScanCursor::default(),
                &mut |chunk| {
                    order.extend(chunk.iter().map(|(key, _)| *key));
                    true
                },
            )?,
            _ => unreachable!(),
        }
        let stale = order[JANITOR_BASE_CANDIDATES];
        let fresh = order[JANITOR_BASE_CANDIDATES + 1];
        let mut fresh_state = test_state(TcpState::TcpStateActive, now_ns);
        fresh_state.incarnation = u64::from(fresh.src_port);
        model.tcp_conn_state_store(&fresh, &fresh_state)?;
        model.redirect_track_store(
            &RedirectTuple::from_tuples(&fresh),
            &RedirectEntry {
                last_seen_ns: now_ns,
                incarnation: fresh_state.incarnation,
                ..Default::default()
            },
        )?;
        model
            .routing_handoffs
            .get_mut()
            .values_mut()
            .find(|entry| entry.incarnation == fresh_state.incarnation)
            .expect("fresh handoff fixture exists")
            .last_seen_ns = now_ns;
        let pins = Arc::new(TcpFlowPins::default());
        for key in &order[..JANITOR_BASE_CANDIDATES] {
            pins.retain_for_test(TcpFlowKey::from_tuples(key));
        }
        let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
            Arc::new(RwLock::new(Box::new(model)));
        let janitor = BpfJanitor::new(Arc::clone(&backend), pins);
        let mut gauge = OccupancyGauge::default();
        let tuning = ScanTuning {
            candidates: JANITOR_BASE_CANDIDATES,
            budget: Duration::from_secs(1),
        };
        match map {
            "conn" => {
                let (deleted, scanned) = janitor
                    .cleanup_conn_state_at(now_ns, &mut gauge, Some(((0, 0), 0)), tuning)
                    .await?;
                assert_eq!((deleted, scanned), (1, order.len()));
                assert_eq!(gauge.estimate(0, 0, 0), order.len() as u64);
            }
            "redirect" | "handoff" => {
                let result = if map == "redirect" {
                    janitor.cleanup_redirect_track_at(now_ns, tuning).await?
                } else {
                    janitor.cleanup_routing_handoff_at(now_ns, tuning).await?
                };
                assert_eq!(result.deleted, 1);
                assert_eq!(result.scanned, order.len());
                assert!(result.complete);
            }
            _ => unreachable!(),
        }
        let backend = tokio::sync::RwLockReadGuard::map(backend.read().await, |backend| {
            backend.tc().unwrap()
        });
        for key in &order {
            let retained = match map {
                "conn" => backend.conn_state_lookup(key)?.is_some(),
                "redirect" => backend
                    .redirect_track_lookup(&RedirectTuple::from_tuples(key))?
                    .is_some(),
                "handoff" => backend.routing_handoff_lookup(key)?.is_some(),
                _ => unreachable!(),
            };
            assert_eq!(
                retained,
                key.src_port != stale.src_port,
                "{map}: port {}",
                key.src_port,
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn tcp_adoption_after_scan_preserves_current_owner() -> anyhow::Result<()> {
    for map in ["conn", "redirect", "handoff"] {
        let key = test_tuple(30_001, IPPROTO_TCP);
        let mut model = MockEbpfBackend::new();
        model.tcp_conn_state_store(&key, &test_state(TcpState::TcpStateActive, 0))?;
        model.redirect_track_store(&RedirectTuple::from_tuples(&key), &RedirectEntry::default())?;
        model.routing_handoffs.get_mut().insert(
            *model
                .tcp_conn_states
                .keys()
                .next()
                .expect("conn fixture exists"),
            honk_ebpf_common::RoutingHandoffEntry::default(),
        );
        let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
            Arc::new(RwLock::new(Box::new(model)));
        let pins = Arc::new(TcpFlowPins::default());
        let mut janitor = BpfJanitor::new(Arc::clone(&backend), Arc::clone(&pins));
        let adopt_backend = Arc::clone(&backend);
        let adopt_pins = Arc::clone(&pins);
        janitor.before_delete_hook = Some(Arc::new(move || {
            // Match admission's continuous backend-read/pin-retain section.
            let _backend = adopt_backend.blocking_read();
            adopt_pins.retain_for_test(TcpFlowKey::from_tuples(&key));
        }));
        let now_ns = TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + 1;
        let result = match map {
            "conn" => janitor.cleanup_conn_state_for_test(now_ns).await,
            "redirect" => janitor.cleanup_redirect_track_for_test(now_ns).await,
            "handoff" => {
                let result = janitor
                    .cleanup_routing_handoff_at(now_ns, scan_tuning(0.0))
                    .await?;
                (result.deleted, result.scanned)
            }
            _ => unreachable!(),
        };
        assert_eq!(result, (0, 1));
        {
            let backend = tokio::sync::RwLockReadGuard::map(backend.read().await, |backend| {
                backend.tc().unwrap()
            });
            assert!(backend.conn_state_lookup(&key)?.is_some());
            assert!(
                backend
                    .redirect_track_lookup(&RedirectTuple::from_tuples(&key))?
                    .is_some()
            );
            assert!(backend.routing_handoff_lookup(&key)?.is_some());
        }
        janitor.before_delete_hook = None;
        assert_eq!(
            pins.release_for_test(TcpFlowKey::from_tuples(&key)),
            Some(true)
        );
        let result = match map {
            "conn" => janitor.cleanup_conn_state_for_test(now_ns).await,
            "redirect" => janitor.cleanup_redirect_track_for_test(now_ns).await,
            "handoff" => {
                let result = janitor
                    .cleanup_routing_handoff_at(now_ns, scan_tuning(0.0))
                    .await?;
                (result.deleted, result.scanned)
            }
            _ => unreachable!(),
        };
        assert_eq!(result, (1, 1));
        let backend = tokio::sync::RwLockReadGuard::map(backend.read().await, |backend| {
            backend.tc().unwrap()
        });
        match map {
            "conn" => assert!(backend.conn_state_lookup(&key)?.is_none()),
            "redirect" => assert!(
                backend
                    .redirect_track_lookup(&RedirectTuple::from_tuples(&key))?
                    .is_none()
            ),
            "handoff" => assert!(backend.routing_handoff_lookup(&key)?.is_none()),
            _ => unreachable!(),
        }
    }
    Ok(())
}

#[tokio::test]
async fn retirement_error_keeps_actual_partial_map_counts() -> anyhow::Result<()> {
    let mut model = MockEbpfBackend::new();
    for port in 0..3 {
        model.udp_conn_state_store(
            &test_tuple(port, 17),
            &test_state(TcpState::TcpStateActive, 0),
        )?;
    }
    model.retire_fault_after = Some(2);
    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(model)));
    let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
    let mut gauge = OccupancyGauge::default();
    let error = janitor
        .cleanup_conn_state_at(
            UDP_CONN_STATE_TIMEOUT_NS + 1,
            &mut gauge,
            Some(((10, 0), 0)),
            scan_tuning(0.0),
        )
        .await
        .expect_err("injected third retirement failure propagates");
    assert_eq!(gauge.estimate(10, 0, 0), 3);
    let error = error
        .downcast_ref::<RetireError>()
        .expect("original partial retirement error retained");
    assert_eq!(
        error.counts,
        RetireCounts {
            conn: 2,
            ..Default::default()
        }
    );
    let mut remaining = 0;
    backend
        .read()
        .await
        .tc()
        .unwrap()
        .conn_state_for_each_chunk(
            JANITOR_SCAN_CHUNK,
            &mut crate::ebpf::FlowScanCursor::default(),
            &mut |chunk| {
                remaining += chunk.len();
                true
            },
        )?;
    assert_eq!(remaining, 1);
    Ok(())
}
