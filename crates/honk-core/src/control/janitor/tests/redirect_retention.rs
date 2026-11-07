use super::*;

/// The documented reclaim age of unpinned redirects, deliberately not imported:
/// a drifting production value must fail these tests.
const UNPINNED_REDIRECT_RECLAIM_NS: u64 = 30_000_000_000;

#[tokio::test]
async fn short_auxiliary_deadline_preserves_conn_and_other_udp_redirects() -> anyhow::Result<()> {
    let deadline = UNPINNED_REDIRECT_RECLAIM_NS;
    let mut model = MockEbpfBackend::new();
    let pins = Arc::new(TcpFlowPins::default());
    let mut cases = Vec::new();
    for (port, proto, source, dest, token, incarnation, pinned, expired) in [
        (1, 6, 40001, 443, 0, 1, false, true),
        (2, 6, 40002, 443, 0, 2, true, false),
        (3, 17, 40003, 53, 0, 0, false, true),
        (4, 17, 53, 443, 0, 0, false, true),
        (5, 17, 40005, 53, 1, 0, false, false),
        (6, 17, 40006, 53, 0, 6, false, false),
        (7, 17, 40007, 443, 0, 0, false, false),
    ] {
        let mut key = test_tuple(source, proto);
        key.src_ip[15] = port;
        key.dst_port = dest;
        let entry = RedirectEntry {
            decision_token: token,
            incarnation,
            ..Default::default()
        };
        model.redirect_track_store(&RedirectTuple::from_tuples(&key), &entry)?;
        if proto == IPPROTO_TCP {
            model.tcp_conn_state_store(
                &key,
                &ConnState {
                    incarnation,
                    ..Default::default()
                },
            )?;
            if pinned {
                pins.retain_for_test(TcpFlowKey::from_tuples(&key));
            }
        }
        cases.push((key, expired));
    }
    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(model)));
    let janitor = BpfJanitor::new(Arc::clone(&backend), pins);
    assert_eq!(janitor.cleanup_redirect_track_for_test(deadline).await.0, 0);
    assert_eq!(
        janitor
            .cleanup_redirect_track_for_test(deadline + 1)
            .await
            .0,
        3
    );
    let backend =
        tokio::sync::RwLockReadGuard::map(backend.read().await, |backend| backend.tc().unwrap());
    for (key, expired) in cases {
        assert_eq!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))?
                .is_none(),
            expired
        );
        if key.l4proto == IPPROTO_TCP {
            assert!(
                backend.conn_state_lookup(&key)?.is_some(),
                "redirect reclamation must not retire TCP authority"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn redirect_refresh_after_scan_supersedes_short_deadline_candidate() -> anyhow::Result<()> {
    let key = test_tuple(31000, IPPROTO_TCP);
    let now_ns = UNPINNED_REDIRECT_RECLAIM_NS + 1;
    let mut model = MockEbpfBackend::new();
    model.redirect_track_store(&RedirectTuple::from_tuples(&key), &RedirectEntry::default())?;
    let backend: Arc<RwLock<Box<dyn crate::ebpf::PolicyBackend>>> =
        Arc::new(RwLock::new(Box::new(model)));
    let mut janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
    let retained = Arc::clone(&backend);
    janitor.before_delete_hook = Some(Arc::new(move || {
        retained
            .blocking_write()
            .tc_mut()
            .unwrap()
            .redirect_track_store(
                &RedirectTuple::from_tuples(&key),
                &RedirectEntry {
                    last_seen_ns: now_ns,
                    ..Default::default()
                },
            )
            .unwrap();
    }));
    assert_eq!(janitor.cleanup_redirect_track_for_test(now_ns).await.0, 0);
    assert!(
        backend
            .read()
            .await
            .tc()
            .unwrap()
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))?
            .is_some()
    );
    Ok(())
}
