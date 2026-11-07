use super::*;
use crate::ebpf::mock::MockTelemetryFaults;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn failed_telemetry_reads_keep_last_samples_and_still_sweep() -> anyhow::Result<()> {
    for failed_signal in 0..3 {
        let count = if failed_signal == 2 {
            AUX_MAP_CAPACITY * 9 / 10
        } else {
            1
        };
        let mut model = MockEbpfBackend::new();
        for port in 0..count as u16 {
            model.redirect_track_store(
                &RedirectTuple::from_tuples(&test_tuple(port, 17)),
                &RedirectEntry::default(),
            )?;
        }
        if failed_signal == 0 {
            for (key, value) in [
                (BpfStatsKey::UdpConnOverflow, 7),
                (BpfStatsKey::TcpConnOverflow, 11),
            ] {
                model.bpf_stats.insert(key as u32, value);
            }
        }
        let faults = Arc::clone(&model.telemetry_faults);
        let admission = Arc::clone(&model.admission_pressure);
        let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
            Arc::new(RwLock::new(Box::new(model)));
        let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
        let start = tokio::time::Instant::now();
        let mut state = tick::TickState::new(start);
        if failed_signal == 1 {
            state.gauge.calibrate(
                u64::from(MAX_CONN_STATE_NUM) * 9 / 10,
                0,
                0,
                crate::ebpf::USERSPACE_CONN_STATE_DELETES.load(Ordering::Relaxed),
            );
        }
        janitor.tick(&mut state, start, None).await?;
        *faults.lock() = MockTelemetryFaults {
            stats: failed_signal == 0,
            conn_occupancy: failed_signal == 1,
            aux_occupancy: failed_signal == 2,
        };
        if failed_signal == 1 {
            // Failed reads must retain the sampled estimate, not reuse stale
            // counters against a changed gauge or recalibrate without a sample.
            state.gauge.calibrate(
                0,
                0,
                0,
                crate::ebpf::USERSPACE_CONN_STATE_DELETES.load(Ordering::Relaxed),
            );
        }
        let drift = state.gauge.drift;
        for round in 1..=4 {
            janitor
                .tick(
                    &mut state,
                    start + Duration::from_secs(round * 2),
                    Some(REDIRECT_TRACK_TIMEOUT_NS + 1),
                )
                .await?;
            assert!(state.pressure.active, "failed signal {failed_signal}");
            if failed_signal == 0 {
                assert_eq!(
                    (
                        state.pressure.last_udp_overflow,
                        state.pressure.last_tcp_overflow
                    ),
                    (7, 11)
                );
            } else if failed_signal == 1 {
                assert!(admission.load(Ordering::Relaxed));
                assert_eq!(state.gauge.drift, drift);
            }
        }
        *faults.lock() = MockTelemetryFaults::default();
        assert_eq!(
            backend.read().await.tc().unwrap().aux_occupancy()?.0,
            count.saturating_sub(JANITOR_MAX_CANDIDATES * 4) as u64
        );
        for round in 5..=7 {
            janitor
                .tick(&mut state, start + Duration::from_secs(round * 2), None)
                .await?;
        }
        assert!(
            !state.pressure.active,
            "fresh quiet samples release pressure"
        );
        assert!(!admission.load(Ordering::Relaxed));
    }
    Ok(())
}

#[derive(Clone, Default)]
struct LogSink(Arc<parking_lot::Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn telemetry_read_warnings_are_throttled() {
    const CHILD: &str = "HONK_JANITOR_TELEMETRY_LOG_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // The macro's static throttle must not inherit another test's failures.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "control::janitor::tests::telemetry::telemetry_read_warnings_are_throttled",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let sink = LogSink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_target(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        for _ in 0..2 {
            let result = Err(anyhow::anyhow!("injected read fault").context("BPF telemetry"));
            let _ = tick::telemetry_sample::<u64>("test signal", result);
        }
    });
    let logs = String::from_utf8(sink.0.lock().clone()).unwrap();
    assert_eq!(
        logs.lines().filter(|line| line.contains("WARN")).count(),
        1,
        "{logs}"
    );
    assert!(
        logs.contains("BPF telemetry: injected read fault"),
        "{logs}"
    );
}
