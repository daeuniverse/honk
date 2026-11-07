use super::*;

#[tokio::test]
async fn bounded_scans_resume_beyond_a_pinned_prefix() -> anyhow::Result<()> {
    let mut model = MockEbpfBackend::new();
    for port in 0..(JANITOR_SCAN_CHUNK * 3) as u16 {
        model.redirect_track_store(
            &RedirectTuple::from_tuples(&test_tuple(port, IPPROTO_TCP)),
            &RedirectEntry::default(),
        )?;
    }
    let mut order = Vec::new();
    model.redirect_track_for_each_chunk(
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
    )?;
    let pins = Arc::new(TcpFlowPins::default());
    for key in &order[..JANITOR_SCAN_CHUNK * 2] {
        pins.retain_for_test(TcpFlowKey::from_tuples(key));
    }
    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(model)));
    let janitor = BpfJanitor::new(Arc::clone(&backend), pins);
    let tuning = ScanTuning {
        candidates: JANITOR_MAX_CANDIDATES,
        budget: Duration::ZERO,
    };
    for expected in [0, 0, JANITOR_SCAN_CHUNK as u64] {
        let result = janitor
            .cleanup_redirect_track_at(REDIRECT_TRACK_TIMEOUT_NS + 1, tuning)
            .await?;
        assert_eq!(result.deleted, expected);
        assert_eq!(result.scanned, JANITOR_SCAN_CHUNK);
    }
    assert_eq!(
        backend.read().await.tc().unwrap().aux_occupancy()?.0,
        (JANITOR_SCAN_CHUNK * 2) as u64
    );
    Ok(())
}
