use super::*;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn tick_publishes_conn_pressure_without_using_auxiliary_pressure() -> anyhow::Result<()> {
    let mut model = MockEbpfBackend::new();
    for port in 0..((AUX_MAP_CAPACITY as f64 * 0.9) as u16) {
        model.redirect_track_store(
            &RedirectTuple::from_tuples(&test_tuple(port, 17)),
            &RedirectEntry::default(),
        )?;
    }
    let pressure = Arc::clone(&model.admission_pressure);
    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(model)));
    let janitor = BpfJanitor::new(backend, Arc::new(TcpFlowPins::default()));
    let start = tokio::time::Instant::now();
    let mut state = tick::TickState::new(start);
    let enter = (u64::from(MAX_CONN_STATE_NUM) * 7).div_ceil(10);
    let exit = (u64::from(MAX_CONN_STATE_NUM) * 3).div_ceil(5);
    for (occupancy, expected) in [
        (enter - 1, false),
        (enter, true),
        ((enter + exit) / 2, true),
        (exit, true),
        (exit - 1, false),
    ] {
        let deletes = crate::ebpf::USERSPACE_CONN_STATE_DELETES.load(Ordering::Relaxed);
        state.gauge.calibrate(occupancy, 0, 0, deletes);
        janitor.tick(&mut state, start, None).await?;
        assert_eq!(pressure.load(Ordering::Relaxed), expected);
    }
    Ok(())
}
