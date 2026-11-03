use super::*;

mod attachment;
mod bindings;
mod btf_source;
mod mandatory_helpers;
mod raw_bpf;
mod retirement;
mod socket_identity;

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

/// Run `test` on a fresh thread in private mount and network namespaces with
/// an isolated `/run`; a panic in `test` is re-raised on the caller.
fn private_netns(test: impl FnOnce() + Send + 'static) {
    std::thread::spawn(move || {
        nix::sched::unshare(
            nix::sched::CloneFlags::CLONE_NEWNS | nix::sched::CloneFlags::CLONE_NEWNET,
        )
        .expect("create private test namespaces");
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
        test();
    })
    .join()
    .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

pub(crate) fn fresh_netns() -> std::os::fd::OwnedFd {
    std::thread::spawn(|| {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        std::fs::File::open("/proc/thread-self/ns/net")
            .map(std::os::fd::OwnedFd::from)
            .unwrap()
    })
    .join()
    .unwrap()
}

pub(crate) fn in_netns<T>(netns: &std::os::fd::OwnedFd, f: impl FnOnce() -> T) -> T {
    let current = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
    nix::sched::setns(netns, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    nix::sched::setns(&current, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Production object loaded against a fresh test dae0 pair. The guard must
/// outlive the backend.
async fn load_bare(pin_root: &Path) -> (crate::daens::Dae0Guard, RealEbpfBackend) {
    let (dae0, setup) = crate::daens::create_test_dae0_pair().expect("dae0 pair");
    let backend = RealEbpfBackend::load(crate::DEFAULT_BPF_OBJECT, pin_root, 12345, &setup, 0)
        .await
        .expect("backend load");
    (dae0, backend)
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

        crate::daens::daens_fd().expect("create test daens namespace");
        let dae0peer_ifindex = || {
            crate::daens::with_daens_netns("inspect test daens", || {
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

/// All configured TCX and cgroup links stay owned until unbind or shutdown.
#[test]
#[ignore = "requires root; run via just test-netns"]
fn link_lifecycle_holds_links_and_rebinds_primary_wan() {
    std::thread::spawn(|| {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        let mut netlink = crate::netlink::NlSock::new().unwrap();
        netlink
            .add_veth_pair("lifecycle-wan", "lifecycle-peer")
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let cgroup_path = detect_cgroup_path().expect("required cgroup2 mount");
            let cgroup_file = std::fs::File::open(&cgroup_path).unwrap();
            let pin_root =
                Path::new("/sys/fs/bpf").join(format!("honk-link-test-{}", std::process::id()));
            // Other agents (systemd, …) may legitimately hold root-cgroup programs;
            // only the delta belongs to this backend.
            let baseline = cgroup_attached_prog_count(cgroup_file.as_raw_fd());
            let (_dae0, mut backend) = load_bare(&pin_root).await;
            backend.bind_test_interfaces(&[], &["lifecycle-wan"]);
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

            let staged_key = TuplesKey {
                l4proto: libc::IPPROTO_UDP as u8,
                ..TuplesKey::default()
            };
            backend
                .udp_conn_state_store(
                    &staged_key,
                    &ConnState {
                        state: UdpDecisionState::Pending as u8,
                        decision_token: 42,
                        incarnation: 42,
                        ..ConnState::default()
                    },
                )
                .expect("seed newer staged token");
            let (_, result) = crate::ebpf::retire_fixture(
                &mut backend,
                staged_key,
                RetireKind::Udp {
                    token: 41,
                    incarnation: Some(41),
                    pending_only: false,
                },
            );
            assert_eq!(result, UdpDecisionCommitResult::Superseded);
            assert_eq!(
                backend
                    .conn_state_lookup(&staged_key)
                    .expect("newer staged lookup")
                    .expect("newer staged state retained")
                    .decision_token,
                42,
                "stale cleanup must not overwrite or delete the newer token"
            );
            assert!(
                backend
                    .hash_lookup::<_, RetirementFence>(RETIRE_FENCE_MAP, &staged_key)
                    .expect("retirement fence lookup")
                    .is_none(),
                "completed stale cleanup must release its exact fence"
            );
            crate::ebpf::retire_fixture(
                &mut backend,
                staged_key,
                RetireKind::Udp {
                    token: 42,
                    incarnation: Some(42),
                    pending_only: false,
                },
            );

            // Five cgroup identity links, sock_ops child proof and the two WAN TCX links.
            let held = held_bpf_link_count();
            assert!(
                held >= 8,
                "expected >= 8 held bpf links after load, got {held}"
            );
            assert_eq!(
                cgroup_attached_prog_count(cgroup_file.as_raw_fd()),
                baseline + 6,
                "all 5 cgroup capture programs and the sock_ops proof must stay attached after load"
            );

            backend.bind_test_interfaces(&[], &[]);
            assert_eq!(held_bpf_link_count(), held - 2);
            backend.bind_test_interfaces(&[], &["lifecycle-wan"]);
            assert_eq!(backend.owned_bindings().count(), 2);
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
        });
    })
    .join()
    .expect("link lifecycle namespace thread");
}

/// Counts tracing links held by this process. Unlike `held_bpf_link_count`, only a vanished
/// fd (ENOENT) is tolerated: any other read failure must not look like "no links".
fn held_tracing_link_count() -> anyhow::Result<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir("/proc/self/fdinfo")? {
        let info = match std::fs::read_to_string(entry?.path()) {
            Ok(info) => info,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        count += usize::from(info.lines().any(|line| {
            line.strip_prefix("link_type:")
                .is_some_and(|kind| kind.trim() == "tracing")
        }));
    }
    Ok(count)
}

/// OpenWrt-class kernels without ftrace cannot create tracing links, so startup must not need
/// one. Routing freplace links appear on policy publication and receive_trace is lazy.
#[tokio::test]
#[ignore = "requires root; run via just test-netns"]
async fn bare_load_holds_no_tracing_links() {
    let pin_root =
        Path::new("/sys/fs/bpf").join(format!("honk-tracing-link-test-{}", std::process::id()));
    assert_eq!(
        held_tracing_link_count().expect("count tracing links before load"),
        0,
        "tracing links already held before load"
    );
    let (_dae0, mut backend) = load_bare(&pin_root).await;
    for program in crate::ebpf::interface::TcProgram::ALL {
        let info = backend
            .bpf()
            .unwrap()
            .program(program.name())
            .unwrap()
            .info()
            .unwrap_or_else(|error| panic!("{} was not preloaded: {error}", program.name()));
        assert_ne!(info.id(), 0);
    }
    assert_eq!(
        backend.owned_bindings().count(),
        0,
        "load must not attach configured interfaces"
    );
    assert_eq!(
        held_tracing_link_count().expect("count tracing links after load"),
        0,
        "bare load attached a tracing link"
    );
    backend.detach_hooks().expect("detach hooks");
    backend.cleanup().await.expect("cleanup");
    for name in [
        UDP_DECISION_SEQUENCE_MAP,
        routing::ROUTING_GENERATION_SEQUENCE_MAP,
    ] {
        std::fs::remove_file(pin_root.join(name)).expect("remove test allocator pin");
    }
    std::fs::remove_dir(&pin_root).expect("remove test pin root");
}

#[cfg(feature = "native-api")]
#[tokio::test]
#[ignore = "requires root; run via just test-netns"]
async fn cleanup_leaves_foreign_pins_under_a_shared_pin_root() {
    use std::os::fd::AsRawFd;

    let links_before = held_bpf_link_count();
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

    let obsolete = [
        "COOKIE_PID_MAP",
        "UDP_DECISION_EPOCH",
        "UDP_DECISION_INFLIGHT",
        "UDP_DECISION_RETIRE_FENCE",
        "TCP_REQUEST_BINDINGS",
        "REQUEST_FENCE",
    ];
    aya::maps::HashMap::<_, u64, [u8; 32]>::create(65536, 1)
        .unwrap()
        .pin(pin_root.join(obsolete[0]))
        .unwrap();
    aya::maps::Array::<_, u32>::create(1, 0)
        .unwrap()
        .pin(pin_root.join(obsolete[1]))
        .unwrap();
    aya::maps::PerCpuArray::<_, u32>::create(2, 0)
        .unwrap()
        .pin(pin_root.join(obsolete[2]))
        .unwrap();
    aya::maps::HashMap::<_, TuplesKey, u32>::create(65536, 1)
        .unwrap()
        .pin(pin_root.join(obsolete[3]))
        .unwrap();
    for name in &obsolete[4..] {
        aya::maps::HashMap::<_, u64, u64>::create(65536, 1)
            .unwrap()
            .pin(pin_root.join(name))
            .unwrap();
    }

    let (_dae0, mut backend) = load_bare(&pin_root).await;
    for name in obsolete {
        assert!(!pin_root.join(name).try_exists().unwrap(), "{name}");
    }
    backend.detach_hooks().expect("detach hooks");
    let trace = backend
        .receive_trace()
        .expect("attach real receive fallback");
    let trace_owner = std::sync::Arc::downgrade(&trace);
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut registration = trace.register(receiver.as_raw_fd()).unwrap();
    assert!(registration.begin(receiver.as_raw_fd()));
    sender
        .send_to(b"trace", receiver.local_addr().unwrap())
        .unwrap();
    let mut bytes = [0u8; 8];
    assert_eq!(receiver.recv(&mut bytes).unwrap(), 5);
    let packets = registration.finish(1).expect("fallback receive evidence");
    assert_eq!(
        packets[0].valid,
        honk_ebpf_common::receive_trace::RECEIVE_TRACE_VALID
    );
    assert_eq!(packets[0].length, 5);
    drop(registration);
    drop(trace);
    backend.cleanup().await.expect("cleanup");
    assert!(
        trace_owner.upgrade().is_none(),
        "cleanup retained receive trace while backend lives"
    );
    assert_eq!(
        held_bpf_link_count(),
        links_before,
        "cleanup retained BPF links"
    );

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
    let (_dae0, dae0_setup) = crate::daens::create_test_dae0_pair().expect("dae0 pair");
    let mut backend =
        RealEbpfBackend::load(crate::DEFAULT_BPF_OBJECT, &pin_root, 12345, &dae0_setup, 0)
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

    let mut reloaded =
        RealEbpfBackend::load(crate::DEFAULT_BPF_OBJECT, &pin_root, 12345, &dae0_setup, 0)
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
        .hash_insert(
            RETIRE_FENCE_MAP,
            &fence_key,
            &RetirementFence {
                owner: u64::MAX,
                decision_token: fence_token,
                padding: 0,
            },
        )
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
    // Fault-injection setup: remove the synthetic live fence, not a flow.
    reloaded
        .hash_remove::<TuplesKey, RetirementFence>(RETIRE_FENCE_MAP, &fence_key)
        .expect("remove synthetic live retirement fence");
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
    let (_dae0, dae0_setup) = crate::daens::create_test_dae0_pair().expect("dae0 pair");
    let pin = pin_root.join(routing::ROUTING_GENERATION_SEQUENCE_MAP);
    for (entries, flags, value) in [
        (2, 0, 17),
        (1, 1 << 7, 17),
        (1, 0, DNS_ROUTE_GENERATION_MAX + 1),
    ] {
        let mut sequence = AyaArray::<_, u64>::create(entries, flags).unwrap();
        sequence.set(0, &value, 0).unwrap();
        sequence.map().pin(&pin).unwrap();
        let id = sequence.map().info().unwrap().id();
        assert!(
            RealEbpfBackend::load(crate::DEFAULT_BPF_OBJECT, &pin_root, 12345, &dae0_setup, 0)
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
    let (data, kernel_btf) = btf::load_kernel().unwrap();
    let mode = process_name::select_capture_mode(
        crate::DEFAULT_BPF_OBJECT,
        &kernel_btf,
        process_name::detect(&data),
    );
    let pin_root = Path::new("/sys/fs/bpf").join(format!("honk-pname-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&pin_root);
    std::fs::create_dir_all(&pin_root).expect("create test pin root");
    let (_dae0, mut backend) = load_bare(&pin_root).await;

    let worker = std::thread::Builder::new()
        .name("worker-thread".into())
        .spawn(|| {
            let mut sockets = Vec::new();
            for domain in [socket2::Domain::IPV4, socket2::Domain::IPV6] {
                for (kind, protocol) in [
                    (socket2::Type::STREAM, socket2::Protocol::TCP),
                    (socket2::Type::DGRAM, socket2::Protocol::UDP),
                ] {
                    sockets.push(socket2::Socket::new(domain, kind, Some(protocol)).unwrap());
                }
            }
            sockets
        })
        .expect("spawn named worker");
    let sockets = worker.join().expect("join named worker");

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
    let storage = aya::maps::SkStorage::<_, SocketIdentity>::try_from(
        backend.bpf().unwrap().map("SOCKET_IDENTITY").unwrap(),
    )
    .expect("socket identity storage");
    for socket in &sockets {
        let entry = storage
            .get(socket, 0)
            .expect("identity before first packet");
        assert_eq!(entry.pid, std::process::id());
        assert_eq!(entry.pname, expected);
    }

    // A duplicate FD owns the same socket even after the creating thread exits
    // and the first FD closes. Connect/send must retain its first identity.
    for (index, socket) in sockets.into_iter().enumerate() {
        if index % 2 == 0 {
            continue;
        }
        let mut retained = SocketIdentity {
            pid: u32::MAX,
            pname: [0; TASK_COMM_LEN],
        };
        retained.pname[..12].copy_from_slice(b"sticky-owner");
        aya::maps::SkStorage::<_, SocketIdentity>::try_from(
            backend
                .bpf_mut()
                .unwrap()
                .map_mut("SOCKET_IDENTITY")
                .unwrap(),
        )
        .unwrap()
        .insert(&socket, &retained, 0)
        .unwrap();
        let duplicate = socket.try_clone().expect("duplicate socket FD");
        drop(socket);
        let receiver =
            std::net::UdpSocket::bind(if index == 1 { "127.0.0.1:0" } else { "[::1]:0" })
                .expect("bind identity-test receiver");
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let destination = socket2::SockAddr::from(receiver.local_addr().unwrap());
        let duplicate = std::thread::Builder::new()
            .name("next-owner".into())
            .spawn(move || {
                duplicate.connect(&destination).unwrap();
                duplicate.send(b"sticky").unwrap();
                duplicate
            })
            .unwrap()
            .join()
            .unwrap();
        let mut bytes = [0; 6];
        assert_eq!(receiver.recv(&mut bytes).unwrap(), bytes.len());
        assert_eq!(&bytes, b"sticky");
        let storage = aya::maps::SkStorage::<_, SocketIdentity>::try_from(
            backend.bpf().unwrap().map("SOCKET_IDENTITY").unwrap(),
        )
        .unwrap();
        assert_eq!(storage.get(&duplicate, 0).unwrap(), retained);
        drop(duplicate);
        let replacement = socket2::Socket::new(
            if index == 1 {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        let fresh = storage.get(&replacement, 0).unwrap();
        assert_eq!(fresh.pid, std::process::id());
        assert_ne!(
            fresh.pname, retained.pname,
            "new sockets must not inherit old storage"
        );
    }

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
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn datapath_observation_crosschecks_program_hook_root_and_admission() {
    use crate::ebpf::{DatapathCheck, DatapathObservationError};
    use aya::maps::{ArrayOfMaps, IterableMap};

    std::thread::spawn(|| {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        let mut netlink = crate::netlink::NlSock::new().unwrap();
        let (loopback, _) = netlink.get_link("lo").unwrap();
        netlink.set_link_up(loopback, true).unwrap();
        netlink
            .add_veth_pair("observe-veth", "observe-peer")
            .unwrap();
        let mut backend = RealEbpfBackend::load_routing_test_fixture(
            crate::DEFAULT_BPF_OBJECT,
            DaeParam::default(),
        )
        .unwrap();
        let before = backend.observe_datapath();
        assert_eq!(before.programs, DatapathCheck::Absent);
        assert_eq!(before.hooks, DatapathCheck::Absent);
        assert_eq!(before.routing, DatapathCheck::Absent);
        assert_eq!(before.admission, Some(false));

        backend.bind_test_interfaces(&["observe-veth"], &[]);
        let router = crate::routing::Router::new(&[], "direct").unwrap();
        let plan = crate::control::routing_matcher::RoutingPushPlan::compile(
            &router,
            &std::collections::HashMap::from([("direct".into(), 0), ("block".into(), 1)]),
            honk_config::types::DialMode::Ip,
        )
        .unwrap();
        backend.publish_routing_plan(&plan, &[]).unwrap();
        let tcp4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp6 = std::net::TcpListener::bind("[::1]:0").unwrap();
        let udp4 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp6 = std::net::UdpSocket::bind("[::1]:0").unwrap();
        backend
            .publish_listener_socket_maps(
                tcp4.as_raw_fd(),
                Some(tcp6.as_raw_fd()),
                &[udp4.as_raw_fd(); 4],
                &[udp6.as_raw_fd(); 4],
            )
            .unwrap();
        backend.set_datapath_ready(true).unwrap();
        let checked = backend.observe_datapath();
        assert_eq!(checked.programs, DatapathCheck::Verified);
        assert!(backend.clear_listener_sockets().is_err());
        assert!(backend.listeners_published);
        assert_eq!(checked.routing, DatapathCheck::Verified);
        assert_eq!(
            checked.routing_generation,
            Some(backend.routing_policy_generation())
        );
        assert_eq!(checked.admission, Some(true));
        assert_eq!(checked.listeners_published, Some(true));
        // Both veth hooks are verified, but the fixture's required dae0 and
        // daens hooks are not, so no attached claim is made.
        assert_eq!(checked.hooks, DatapathCheck::Unknown);
        assert_eq!(checked.attachments.len(), 2);
        assert!(checked.attachments.iter().all(|attachment| {
            attachment.interface == "observe-veth" && attachment.state == DatapathCheck::Verified
        }));
        let capacity = backend
            .hash_map::<TuplesKey, honk_ebpf_common::FlowMapValue<ConnState>>("CONN_STATE_MAP")
            .unwrap()
            .map()
            .info()
            .unwrap()
            .max_entries();
        assert_eq!(checked.conn_state_capacity, Some(capacity));
        assert!(checked.errors.is_empty());

        let root = backend
            .bpf()
            .unwrap()
            .map(ROUTING_POLICY_ROOT_NAME)
            .unwrap();
        let root = ArrayOfMaps::<_, AyaArray<AyaMapData, RoutingPolicyDescriptor>>::try_from(root)
            .unwrap();
        let old_descriptor = root.get(&0, 0).unwrap();
        let mut foreign_descriptor = AyaArray::<_, RoutingPolicyDescriptor>::create(1, 0).unwrap();
        foreign_descriptor
            .set(0, &old_descriptor.get(&0, 0).unwrap(), 0)
            .unwrap();
        let root = backend
            .bpf_mut()
            .unwrap()
            .map_mut(ROUTING_POLICY_ROOT_NAME)
            .unwrap();
        ArrayOfMaps::<_, AyaArray<AyaMapData, RoutingPolicyDescriptor>>::try_from(root)
            .unwrap()
            .set(0, &foreign_descriptor, 0)
            .unwrap();
        let mismatch = backend.observe_datapath();
        assert_eq!(mismatch.routing, DatapathCheck::Error);
        assert_eq!(mismatch.routing_generation, None);
        assert!(mismatch.errors.contains(&DatapathObservationError::Routing));
        assert_eq!(mismatch.admission, Some(true));
        assert_eq!(
            backend.array_get::<u32>("DATAPATH_STATE_MAP", 0).unwrap(),
            Some(1)
        );

        backend.set_datapath_ready(false).unwrap();
        backend.clear_listener_sockets().unwrap();
        assert!(!backend.listeners_published);
        assert!(backend.set_datapath_ready(true).is_err());
        {
            let map = backend
                .bpf_mut()
                .unwrap()
                .map_mut("LISTEN_SOCKET_MAP")
                .unwrap();
            let mut sockets = AyaSockMap::try_from(map).unwrap();
            for key in 0..10 {
                assert!(RealEbpfBackend::sockmap_slot_is_empty(
                    &sockets.clear_index(&key).unwrap_err()
                ));
            }
        }
        backend
            .publish_listener_socket_maps(
                tcp4.as_raw_fd(),
                Some(tcp6.as_raw_fd()),
                &[udp4.as_raw_fd(); 4],
                &[],
            )
            .unwrap();
        {
            let map = backend
                .bpf_mut()
                .unwrap()
                .map_mut("LISTEN_SOCKET_MAP")
                .unwrap();
            let mut sockets = AyaSockMap::try_from(map).unwrap();
            for key in 6..10 {
                assert!(RealEbpfBackend::sockmap_slot_is_empty(
                    &sockets.clear_index(&key).unwrap_err()
                ));
            }
        }
        backend.clear_listener_sockets().unwrap();
        backend.detach_hooks().unwrap();
        let detached = backend.observe_datapath();
        assert_eq!(detached.admission, Some(false));
        assert_eq!(detached.hooks, DatapathCheck::Absent);
        assert!(detached.attachments.is_empty());
    })
    .join()
    .unwrap();
}
