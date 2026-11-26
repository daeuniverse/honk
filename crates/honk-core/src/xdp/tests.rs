use super::*;

mod driven_kernel;
mod retention;

#[test]
fn bond_realm_workers_fit_every_member() {
    assert_eq!(realm_worker_count(2, [1, 2].into_iter()), 1);
}

#[test]
fn direct_relay_requires_matching_physical_owners_and_one_endpoint_member() {
    let endpoint = Some(DirectProfile::Endpoint);
    assert!(direct_relay_eligible(endpoint, 1, 1, 1, true));
    assert!(direct_relay_eligible(endpoint, 2, 2, 1, true));
    for (profile, workers, owners, members, physical) in [
        (endpoint, 1, 1, 1, false),
        (endpoint, 2, 2, 1, false),
        (endpoint, 2, 1, 1, true),
        (endpoint, 3, 3, 1, true),
        (endpoint, 0, 0, 1, true),
        (endpoint, 2, 2, 2, true),
        (endpoint, 1, 1, 0, true),
        (Some(DirectProfile::Core), 2, 2, 1, true),
        (None, 1, 1, 1, true),
    ] {
        assert!(!direct_relay_eligible(
            profile, workers, owners, members, physical
        ));
    }
}

#[test]
fn rx_capacity_preserves_small_budget_and_many_queue_admission() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let sizing = |mtu, queues| queue_sizing(mtu, queues, budget.limit() - budget.used());
    let umem = |mtu, queues| sizing(mtu, queues).0.umem_bytes().unwrap();
    let base = 3 * 1024 * 1024;
    let (wide, scope_bulk) = sizing(1500, 8);
    wide.validate().unwrap();
    assert_eq!(
        (wide.control_frames, wide.bulk_frames, scope_bulk),
        (32, 480, 256)
    );
    assert_eq!(wide.ring_size, 1024);
    assert!(wide.rx_frames > 256 && wide.umem_bytes().unwrap() > base);
    assert_eq!(umem(9000, 1), 2 * 1024 * 1024);
    assert_eq!(umem(1500, 0), base);
    assert_eq!(umem(1500, 9), base);
    for queues in [1, 8] {
        let cutoff = CAPTURE_MEMORY / 2 + queues * 2 * wide.umem_bytes().unwrap();
        assert_eq!(queue_sizing(4074, queues, cutoff - 1).0.rx_frames, 256);
        assert_eq!(
            queue_sizing(4074, queues, cutoff).0.rx_frames,
            wide.rx_frames
        );
        assert_eq!(
            queue_sizing(4074, queues, cutoff + 1).0.rx_frames,
            wide.rx_frames
        );
        assert_eq!(queue_sizing(4075, queues, cutoff + 1).0.ring_size, 256);
    }
    let _other_owners = budget.reserve(CAPTURE_MEMORY - base).unwrap();
    let constrained = sizing(1500, 1).0;
    assert_eq!((constrained.rx_frames, constrained.ring_size), (256, 512));
    assert!(budget.reserve(wide.umem_bytes().unwrap()).is_none());
    let _port = budget.reserve(constrained.umem_bytes().unwrap()).unwrap();
    assert_eq!(budget.used(), budget.limit());
}

#[test]
fn readonly_admission_reports_nonzero_gateway_time_offset() {
    assert!(gateway_time_namespace_issue(Ok(None)).is_none());
    assert!(gateway_time_namespace_issue(Ok(Some(0))).is_none());
    for offset in [-1_000_000_000, 1_000_000_000] {
        let (reason, details) = gateway_time_namespace_issue(Ok(Some(offset))).unwrap();
        let summary = admission_failure(&[(reason, "namespace".into(), details)], 0);
        assert!(summary.contains("reason=time_namespace_offset device=namespace"));
        assert!(summary.contains(&format!("{offset} ns")));
    }
}

#[test]
fn readonly_admission_reports_foreign_xdp_and_mode_failure_together() {
    let info = DeviceInfo {
        name: "eth-test".into(),
        ifindex: 1,
        upper_ifindices: Vec::new(),
        queues: vec![0],
        mtu: 9000,
        mac: [2; 6],
        xdp_features: 3,
        zerocopy_max_segments: 0,
        vlan_metadata: false,
        direct_relay_physical: true,
    };
    let issues: Vec<_> = member_admission_issues(
        &info,
        device_sizing(info.mtu).0,
        Some(BindMode::ZeroCopy),
        METADATA_LEN,
        Ok(false),
    )
    .into_iter()
    .flatten()
    .map(|(reason, details)| (reason, info.name.clone(), details))
    .collect();
    let summary = admission_failure(&issues, 0);
    assert_eq!(issues.len(), 2);
    assert!(summary.contains("reason=xsk_mode device=eth-test"));
    assert!(summary.contains("reason=foreign_xdp device=eth-test"));
}

#[test]
fn readonly_layout_failure_marks_dependent_checks_not_checked() {
    let issues: Vec<_> = layout_admission_issues(&io::Error::other("injected layout failure"))
        .into_iter()
        .map(|(reason, details)| (reason, "capture".into(), details))
        .collect();
    let summary = admission_failure(&issues, 0);
    assert!(summary.contains("reason=capture_layout device=capture: injected layout failure"));
    assert!(summary.contains("reason=NOT_CHECKED device=capture"));
    assert!(summary.contains("depend on capture_layout"));
    assert!(!summary.contains("reason=xsk_mode"));
    assert!(!summary.contains("reason=foreign_xdp"));
}

#[tokio::test(start_paused = true)]
async fn stalled_worker_cannot_extend_the_physical_detach_budget() {
    let deadline = Instant::now() + Duration::from_millis(5);
    let result = drain_before_detach(deadline, || Ok(false), std::future::pending()).await;
    assert!(
        result
            .unwrap_err()
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    );
}

#[tokio::test(start_paused = true)]
async fn pending_tx_cannot_extend_the_worker_deadline() {
    let deadline = Instant::now() + Duration::from_millis(5);
    let result = drain_before_detach(deadline, || Ok(true), std::future::ready(Ok(()))).await;
    assert!(
        result
            .unwrap_err()
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    );
}

#[test]
fn capture_close_folds_later_errors_without_losing_original_cause() {
    let mut failure = None;
    fold_capture_result(
        &mut failure,
        Err(io::Error::from_raw_os_error(libc::EPERM).into()),
    );
    fold_capture_result(&mut failure, Ok(()));
    for stage in ["XSK withdrawal", "private seal", "post-guard grace"] {
        fold_capture_result(&mut failure, Err(anyhow::anyhow!(stage)));
    }
    let error = failure.unwrap();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(libc::EPERM)
    );
    let message = format!("{error:#}");
    for stage in ["XSK withdrawal", "private seal", "post-guard grace"] {
        assert!(message.contains(stage));
    }
}

#[test]
fn pressure_deadline_ends_after_the_recovery_sample() {
    let start = Instant::now();
    let mut pressure = Pressure::new(start);
    assert_eq!(pressure.next_deadline(None), None);
    pressure.counters.capture_rejected = 1;
    assert_eq!(
        pressure.next_deadline(None),
        None,
        "diagnostics do not drive polling"
    );
    pressure.counters.refused = true;
    assert_eq!(
        pressure.next_deadline(None),
        Some(start + Duration::from_secs(1))
    );
    assert!(!pressure.sample(
        start + Duration::from_secs(1) - Duration::from_nanos(1),
        None,
        0,
        0,
        0,
    ));
    assert_eq!(pressure.checked, start);
    assert!(pressure.counters.refused);
    assert!(pressure.sample(start + Duration::from_secs(1), None, 0, 0, 0));
    assert!(!pressure.sample(start + Duration::from_secs(1), None, 0, 0, 0));
    assert!(pressure.active);
    assert_eq!(
        pressure.next_deadline(None),
        Some(start + Duration::from_secs(2))
    );
    assert!(pressure.sample(start + Duration::from_secs(2), None, 0, 0, 0));
    assert!(!pressure.active);
    assert_eq!(pressure.next_deadline(None), None);
    pressure.core.core_capacity = u64::MAX;
    assert!(
        !pressure.refusing(pressure.core),
        "a saturated historic counter is not new work"
    );
}

#[test]
fn qinq_realms_share_capacity_and_release_their_complete_budget() {
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let scopes: Vec<_> = (0..6)
        .map(|_| capture_scope(1500, 6, 256, &budget).unwrap())
        .collect();
    drop(scopes);
    assert_eq!(budget.used(), 0);
}

#[test]
fn sg_l3_and_vlan_output_keep_exact_bytes() {
    let path = ReturnPath {
        realm: 1,
        device: 0,
        mac: [2; 6],
        vlan_tci: [0xa00c, 34],
        vlan_proto: [0x88a8, 0x8100],
        vlan_count: 2,
    };
    let header = return_header(path, [4; 6], 2, true).unwrap();
    let length = header.len();
    assert_eq!(length, 22);
    assert_eq!(
        &header[12..],
        &[0x88, 0xa8, 0xa0, 12, 0x81, 0, 0, 34, 0x86, 0xdd]
    );
    let payload = [7u8; 9000];
    let mut a = [0; 4096];
    let mut b = [0; 4096];
    let mut c = [0; 830];
    fill_output(&mut [&mut a, &mut b, &mut c], &header, &payload).unwrap();
    let packet = DecodedPacket {
        frame_len: length + payload.len(),
        l3_offset: length,
        l3_len: payload.len(),
        source_mac: [4; 6],
        destination_mac: [2; 6],
        ether_type: 0x86dd,
        vlan_tci: path.vlan_tci,
        vlan_proto: path.vlan_proto,
        vlan_count: 2,
        inline_vlan_count: 2,
    };
    let mut slices = [&[][..]; 18];
    let segments = [&a[..], &b[..], &c[..]];
    let count = l3_segments(&segments, packet, &mut slices).unwrap();
    let view = PacketView::new(&slices[..count]).unwrap();
    assert_eq!(view.len(), payload.len());
    view.visit(0..view.len(), |bytes| {
        assert!(bytes.iter().all(|byte| *byte == 7))
    })
    .unwrap();
    assert!(fill_output(&mut [&mut a[..8]], &header, &payload).is_err());
}

#[tokio::test]
async fn cleared_stale_readiness_arms_the_next_wake() {
    let (reader, writer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    writer.set_nonblocking(true).unwrap();
    // SAFETY: the socket keeps its descriptor unchanged until deregistration.
    let reader = unsafe { AsyncFd::register(reader) }
        .map_err(io::Error::from)
        .unwrap();
    assert!(!arm_read(&reader, &mut Context::from_waker(std::task::Waker::noop())).unwrap());
    writer.send(b"drained").unwrap();
    // A previous pass consumed the packet whose event is still cached as Ready.
    reader.readable().await.unwrap().retain_ready();
    assert_eq!(reader.get_ref().recv(&mut [0; 16]).unwrap(), 7);
    let (armed, waiting) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let mut armed = Some(armed);
        poll_fn(|cx| {
            if !arm_read(&reader, cx).unwrap() {
                return Poll::Pending;
            }
            match reader.get_ref().recv(&mut [0; 16]) {
                Ok(_) => Poll::Ready(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if let Some(armed) = armed.take() {
                        let _ = armed.send(());
                    }
                    Poll::Pending
                }
                Err(error) => panic!("unexpected receive failure: {error}"),
            }
        })
        .await;
    });
    waiting.await.unwrap();
    writer.send(b"next").unwrap();
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .expect("the next packet must wake the owner parked after an empty pass")
        .unwrap();
}
