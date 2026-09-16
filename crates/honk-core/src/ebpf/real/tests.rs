use super::*;

/// Number of bpf links this process currently holds open. Every link fd
/// shows a `link_type:` line in its /proc/self/fdinfo entry.
fn held_bpf_link_count() -> usize {
    std::fs::read_dir("/proc/self/fdinfo")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    std::fs::read_to_string(e.path())
                        .map(|c| c.contains("link_type:"))
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

/// Total programs attached to the root cgroup2 across every attach type,
/// via raw BPF_PROG_QUERY (kernel ground truth, no aya state involved).
fn cgroup_attached_prog_count(cgroup_fd: RawFd) -> u32 {
    use aya_obj::generated::bpf_attr;
    use aya_obj::generated::bpf_cmd::*;
    let mut total = 0;
    for attach_type in 0..64u32 {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.query.__bindgen_anon_1.target_fd = cgroup_fd as u32;
        attr.query.attach_type = attach_type;
        if unsafe { syscall::bpf_syscall(BPF_PROG_QUERY as _, &mut attr) }.is_ok() {
            total += unsafe { attr.query.__bindgen_anon_2.prog_cnt };
        }
    }
    total
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn missing_dae0peer_attach_failure_is_propagated() {
    std::thread::spawn(|| {
        // Lazy daens creation may add compatibility mounts; confine them to
        // this thread's disposable mount namespace.
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
            .expect("create test mount namespace");
        nix::mount::mount(
            None::<&str>,
            "/",
            None::<&str>,
            nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .expect("make test mounts private");
        nix::mount::mount(
            Some("tmpfs"),
            "/run",
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        )
        .expect("isolate test runtime directory");

        crate::daens_fd().expect("create test daens namespace");
        let dae0peer_ifindex = || {
            crate::with_daens_netns("inspect test daens", || {
                let mut netlink = crate::netlink::NlSock::new()?;
                netlink.get_link("lo")?;
                match netlink.get_link("dae0peer") {
                    Ok((ifindex, _)) => Ok(Some(ifindex)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(error) => Err(error.into()),
                }
            })
            .expect("inspect test daens namespace")
        };
        assert!(
            dae0peer_ifindex().is_none(),
            "test daens already contains dae0peer; refusing to remove an unowned link"
        );

        let mut backend = RealEbpfBackend::load_routing_test_fixture(
            crate::DEFAULT_BPF_OBJECT,
            DaeParam::default(),
        )
        .expect("load embedded production object");
        let program: &mut aya::programs::SchedClassifier = backend
            .bpf_mut()
            .unwrap()
            .program_mut("dae0peer_ingress")
            .unwrap()
            .try_into()
            .unwrap();
        program
            .load()
            .expect("load valid peer program before attach");
        let caller_netns =
            std::fs::read_link("/proc/thread-self/ns/net").expect("read caller network namespace");
        let links_before = held_bpf_link_count();

        backend
            .attach_dae0peer_ingress()
            .expect_err("missing dae0peer attach must fail");
        assert_eq!(
            std::fs::read_link("/proc/thread-self/ns/net")
                .expect("read restored caller network namespace"),
            caller_netns,
            "failed attach stranded its caller in daens"
        );
        assert_eq!(
            held_bpf_link_count(),
            links_before,
            "failed attach leaked a BPF link"
        );
        assert!(
            dae0peer_ifindex().is_none(),
            "failed attach created or retained dae0peer"
        );
    })
    .join()
    .expect("peer attach regression thread");
}

/// Regression test: every link aya hands us (TC, cgroup sock/sock_addr)
/// stays owned by the backend until its interface is forgotten or global
/// shutdown. Forgetting a startup WAN must release its TCX links so the
/// watcher can bind the same interface again without `EEXIST`.
#[tokio::test]
#[ignore = "requires root; run via just test-netns"]
async fn link_lifecycle_holds_links_and_rebinds_primary_wan() {
    use std::os::fd::AsRawFd;
    let cgroup_path = match detect_cgroup_path() {
        Ok(p) => p,
        Err(_) => return, // cgroup2 unavailable: nothing to attach, nothing to test
    };
    let cgroup_file = std::fs::File::open(&cgroup_path).unwrap();
    let pin_root = Path::new("/sys/fs/bpf").join(format!("honk-link-test-{}", std::process::id()));
    // Other agents (systemd, …) may legitimately hold root-cgroup programs;
    // only the delta belongs to this backend.
    let baseline = cgroup_attached_prog_count(cgroup_file.as_raw_fd());
    let mut backend = RealEbpfBackend::load(
        crate::DEFAULT_BPF_OBJECT,
        &pin_root,
        12345,
        None,
        "lo",
        false,
    )
    .await
    .expect("backend load");
    syscall::reset_udp_decision_sequence_locked(backend.bpf().unwrap(), 2)
        .expect("locked sequence reset");
    assert_eq!(
        backend
            .udp_decision_sequence_status()
            .expect("sequence status after reset"),
        UdpDecisionSequenceStatus {
            next: 0,
            generation: 2,
        }
    );

    let staged_key = TuplesKey::default();
    backend
        .udp_conn_state_store(
            &staged_key,
            &ConnState {
                state: UdpDecisionState::Pending as u8,
                decision_token: 42,
                ..ConnState::default()
            },
        )
        .expect("seed newer staged token");
    assert_eq!(
        backend
            .remove_udp_flow(&staged_key, 41)
            .expect("stale retirement result"),
        UdpDecisionCommitResult::Superseded
    );
    assert_eq!(
        backend
            .udp_conn_state_lookup(&staged_key)
            .expect("newer staged lookup")
            .expect("newer staged state retained")
            .decision_token,
        42,
        "stale cleanup must not overwrite or delete the newer token"
    );
    assert!(
        backend
            .hash_lookup::<_, u32>(UDP_DECISION_RETIRE_FENCE_MAP, &staged_key)
            .expect("retirement fence lookup")
            .is_none(),
        "completed stale cleanup must release its exact fence"
    );
    backend
        .udp_conn_state_remove(&staged_key)
        .expect("remove staged test state");

    // 6 cgroup links + wan_ingress/wan_egress on lo.
    let held = held_bpf_link_count();
    assert!(
        held >= 8,
        "expected >= 8 held bpf links after load, got {held}"
    );
    assert_eq!(
        cgroup_attached_prog_count(cgroup_file.as_raw_fd()),
        baseline + 6,
        "all 6 cgroup programs must stay attached after load"
    );

    let lo_ifindex = std::fs::read_to_string("/sys/class/net/lo/ifindex")
        .expect("lo ifindex")
        .trim()
        .parse()
        .expect("numeric lo ifindex");
    backend.forget_dynamic_interface(lo_ifindex);
    let hooks = backend
        .attach_dynamic_interface("lo", crate::ebpf::IfaceRole::Wan, false)
        .expect("primary WAN rebind");
    assert_eq!(
        hooks,
        crate::ebpf::DynamicHooks {
            ingress: true,
            egress: true,
        }
    );
    assert_eq!(
        held_bpf_link_count(),
        held,
        "rebind must replace, not stack, the two WAN TCX links"
    );

    backend.detach_hooks().expect("detach_hooks");
    assert_eq!(
        held_bpf_link_count(),
        0,
        "detach_hooks must release every link"
    );
    assert_eq!(
        cgroup_attached_prog_count(cgroup_file.as_raw_fd()),
        baseline,
        "detach_hooks must detach the cgroup programs"
    );
    backend.cleanup().await.expect("cleanup");
    for name in [
        UDP_DECISION_SEQUENCE_MAP,
        routing::ROUTING_GENERATION_SEQUENCE_MAP,
    ] {
        assert!(
            pin_root.join(name).exists(),
            "ordinary cleanup must preserve {name}"
        );
        std::fs::remove_file(pin_root.join(name)).expect("remove test allocator pin");
    }
    std::fs::remove_dir(&pin_root).expect("remove test pin root");
}

#[tokio::test]
#[ignore = "requires root; run via just test-netns"]
async fn cleanup_leaves_foreign_pins_under_a_shared_pin_root() {
    let pin_root =
        Path::new("/sys/fs/bpf").join(format!("honk-pin-ownership-test-{}", std::process::id()));
    std::fs::create_dir_all(&pin_root).expect("pin root");
    let foreign = pin_root.join("FOREIGN_MAP");
    aya::maps::Array::<_, u32>::create(1, 0)
        .expect("create foreign map")
        .pin(&foreign)
        .expect("pin foreign map");
    let foreign_id = aya::maps::MapInfo::from_pin(&foreign)
        .expect("foreign map info")
        .id();

    let mut backend = RealEbpfBackend::load(
        crate::DEFAULT_BPF_OBJECT,
        &pin_root,
        12345,
        None,
        "lo",
        false,
    )
    .await
    .expect("backend load");
    backend.detach_hooks().expect("detach hooks");
    backend.cleanup().await.expect("cleanup");

    assert_eq!(
        aya::maps::MapInfo::from_pin(&foreign)
            .expect("cleanup removed a pin this instance did not create")
            .id(),
        foreign_id
    );
    for name in [
        UDP_DECISION_SEQUENCE_MAP,
        routing::ROUTING_GENERATION_SEQUENCE_MAP,
    ] {
        assert!(
            pin_root
                .join(name)
                .try_exists()
                .expect("allocator pin readable"),
            "cleanup removed {name}"
        );
    }

    let _ = std::fs::remove_dir_all(&pin_root);
}

#[tokio::test]
#[ignore = "requires root; run via just test-netns"]
async fn pinned_raw_udp_decision_sequence_survives_reload() {
    let pin_root =
        Path::new("/sys/fs/bpf").join(format!("honk-sequence-reload-test-{}", std::process::id()));
    let mut backend = RealEbpfBackend::load(
        crate::DEFAULT_BPF_OBJECT,
        &pin_root,
        12345,
        None,
        "lo",
        false,
    )
    .await
    .expect("backend load");
    let sequence_map_id = aya::maps::MapInfo::from_pin(pin_root.join(UDP_DECISION_SEQUENCE_MAP))
        .expect("initial sequence map info")
        .id();
    let persisted_next = (1 << UDP_DECISION_GENERATION_SHIFT) | 42;
    syscall::write_udp_decision_sequence_locked(
        backend.bpf().unwrap(),
        &UdpDecisionSequence {
            next: persisted_next,
            ..UdpDecisionSequence::default()
        },
    )
    .expect("seed rollback-compatible persistent allocator value");
    backend.detach_hooks().expect("detach hooks");
    backend.cleanup().await.expect("cleanup");

    let mut reloaded = RealEbpfBackend::load(
        crate::DEFAULT_BPF_OBJECT,
        &pin_root,
        12345,
        None,
        "lo",
        false,
    )
    .await
    .expect("backend reload");
    assert_eq!(
        aya::maps::MapInfo::from_pin(pin_root.join(UDP_DECISION_SEQUENCE_MAP))
            .expect("reloaded sequence map info")
            .id(),
        sequence_map_id,
        "backend reload must reuse the exact pinned allocator map"
    );
    assert_eq!(
        reloaded
            .udp_decision_sequence_status()
            .expect("reloaded sequence status"),
        UdpDecisionSequenceStatus {
            next: 42,
            generation: 1,
        },
        "raw token progress must resume at the same numeric boundary"
    );
    let fence_key = TuplesKey::default();
    let fence_token = udp_decision_token(2, 7).unwrap();
    reloaded
        .hash_insert(UDP_DECISION_RETIRE_FENCE_MAP, &fence_key, &fence_token)
        .expect("seed live retirement fence");
    syscall::write_udp_decision_sequence_locked(
        reloaded.bpf().unwrap(),
        &UdpDecisionSequence {
            next: udp_decision_token(1, UDP_DECISION_SEQUENCE_MASK).unwrap(),
            ..UdpDecisionSequence::default()
        },
    )
    .expect("exhaust sequence before retirement-fence check");
    assert!(
        !reloaded
            .reset_udp_decision_sequence(1)
            .expect("reject rollback-reachable retirement generation"),
        "a higher live generation must block a legacy allocator starting below it"
    );
    assert!(
        !reloaded
            .reset_udp_decision_sequence(2)
            .expect("reject live retirement generation"),
        "a live retirement fence must prevent generation reuse"
    );
    reloaded
        .hash_remove::<TuplesKey, u32>(UDP_DECISION_RETIRE_FENCE_MAP, &fence_key)
        .expect("remove live retirement fence");
    assert!(
        reloaded
            .reset_udp_decision_sequence(2)
            .expect("reset after retirement fence removal")
    );
    let reset = syscall::read_udp_decision_sequence_locked(reloaded.bpf().unwrap())
        .expect("read reset rollback-compatible sequence");
    assert_eq!(reset.next, 2 << UDP_DECISION_GENERATION_SHIFT);
    assert_eq!(reset.exhausted, 0);
    reloaded.detach_hooks().expect("detach hooks after reload");
    reloaded.cleanup().await.expect("reload cleanup");
    for name in [
        UDP_DECISION_SEQUENCE_MAP,
        routing::ROUTING_GENERATION_SEQUENCE_MAP,
    ] {
        std::fs::remove_file(pin_root.join(name)).expect("remove test allocator pin");
    }
    std::fs::remove_dir(&pin_root).expect("remove test pin root");
}

#[tokio::test]
#[ignore = "requires root; run via just test-netns"]
async fn invalid_routing_sequence_pin_is_never_reset() {
    use aya::maps::IterableMap;

    let pin_root = Path::new("/sys/fs/bpf").join(format!(
        "honk-routing-sequence-invalid-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&pin_root).unwrap();
    let pin = pin_root.join(routing::ROUTING_GENERATION_SEQUENCE_MAP);
    for (entries, flags, value) in [
        (2, 0, 17),
        (1, 1 << 7, 17),
        (1, 0, DNS_ROUTE_GENERATION_MAX + 1),
    ] {
        let mut sequence = AyaArray::<_, u64>::create(entries, flags).unwrap();
        sequence.set(0, value, 0).unwrap();
        sequence.map().pin(&pin).unwrap();
        let id = sequence.map().info().unwrap().id();
        assert!(
            RealEbpfBackend::load(
                crate::DEFAULT_BPF_OBJECT,
                &pin_root,
                12345,
                None,
                "lo",
                false
            )
            .await
            .is_err()
        );
        assert_eq!(aya::maps::MapInfo::from_pin(&pin).unwrap().id(), id);
        assert_eq!(sequence.get(&0, 0).unwrap(), value);
        std::fs::remove_file(&pin).unwrap();
    }
    std::fs::remove_dir(pin_root).unwrap();
}

#[tokio::test]
#[ignore = "requires root, cgroup v2, and an eBPF build"]
async fn pname_is_ready_before_first_packet() {
    let mode = process_name::select_capture_mode(crate::DEFAULT_BPF_OBJECT, process_name::detect());
    let pin_root = Path::new("/sys/fs/bpf").join(format!("honk-pname-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&pin_root);
    std::fs::create_dir_all(&pin_root).expect("create test pin root");
    let mut backend = RealEbpfBackend::load(
        crate::DEFAULT_BPF_OBJECT,
        &pin_root,
        12345,
        Some("lo"),
        "lo",
        true,
    )
    .await
    .expect("load backend for pname test");

    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let worker = std::thread::Builder::new()
        .name("worker-thread".into())
        .spawn(move || {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("create worker socket");
            let mut cookie = 0u64;
            let mut cookie_len = std::mem::size_of::<u64>() as libc::socklen_t;
            let status = unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_COOKIE,
                    &mut cookie as *mut _ as *mut libc::c_void,
                    &mut cookie_len,
                )
            };
            assert_eq!(
                status,
                0,
                "read socket cookie: {}",
                std::io::Error::last_os_error()
            );
            ready_tx.send(cookie).expect("publish socket cookie");
            release_rx.recv().expect("release worker socket");
            drop(socket);
        })
        .expect("spawn named worker");
    let cookie = ready_rx.recv().expect("receive socket cookie");

    let entry = backend
        .cookie_pid_lookup(cookie)
        .expect("look up socket cookie")
        .expect("pname map entry must exist before the first packet");
    assert!(
        entry.pname.iter().any(|byte| *byte != 0),
        "pname must never be empty at first-packet lookup"
    );

    let expected = match mode {
        process_name::PnameCaptureMode::Argv0 => {
            let executable = std::env::current_exe().expect("resolve test executable");
            let basename = std::os::unix::ffi::OsStrExt::as_bytes(
                executable.file_name().expect("test executable basename"),
            );
            let mut expected = [0u8; TASK_COMM_LEN];
            let len = basename.len().min(TASK_COMM_LEN - 1);
            expected[..len].copy_from_slice(&basename[..len]);
            expected
        }
        process_name::PnameCaptureMode::Comm => {
            let mut expected = [0u8; TASK_COMM_LEN];
            expected[.."worker-thread".len()].copy_from_slice(b"worker-thread");
            expected
        }
    };
    assert_eq!(entry.pname, expected);

    release_tx.send(()).expect("release worker");
    worker.join().expect("join named worker");
    backend.detach_hooks().expect("detach pname test hooks");
    backend
        .cleanup()
        .await
        .expect("clean up pname test backend");
    for name in [
        UDP_DECISION_SEQUENCE_MAP,
        routing::ROUTING_GENERATION_SEQUENCE_MAP,
    ] {
        std::fs::remove_file(pin_root.join(name)).expect("remove pname test allocator pin");
    }
    std::fs::remove_dir(&pin_root).expect("remove pname test pin root");
}

#[test]
fn test_event_ip() {
    // IPv4-mapped (::ffff:8.8.8.8) in network-order u32 chunks.
    let chunks = [0u32, 0, 0x0000ffffu32.to_be(), 0x08080808u32.to_be()];
    assert_eq!(
        event_ip(&chunks),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))
    );
    // Plain IPv6 (::1).
    let v6 = [0u32, 0, 0, 1u32.to_be()];
    assert_eq!(
        event_ip(&v6),
        std::net::IpAddr::V6("::1".parse::<std::net::Ipv6Addr>().unwrap())
    );
}

#[test]
fn routing_handoff_layout_validation_rejects_legacy_value_size() {
    let key = core::mem::size_of::<TuplesKey>() as u32;
    let current = core::mem::size_of::<RoutingHandoffEntry>() as u32;
    assert!(validate_routing_handoff_sizes(key, current).is_ok());
    assert!(validate_routing_handoff_sizes(key, 48).is_err());
}
