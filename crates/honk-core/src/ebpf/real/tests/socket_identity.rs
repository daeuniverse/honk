use super::raw_bpf::{EXIT, MOV64_IMM, insn, load_program};
use super::*;
use aya::maps::IterableMap as _;
use aya_obj::generated::{
    bpf_attach_type::BPF_CGROUP_SOCK_OPS,
    bpf_attr,
    bpf_cmd::{BPF_PROG_ATTACH, BPF_PROG_DETACH},
    bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS,
};
use honk_ebpf_common::conn::BpfStatsKey;

#[tokio::test]
#[ignore = "requires disposable VM, root, cgroup v2, Linux 6.12+, and an eBPF build"]
async fn allocation_failure_allows_create_connect_and_send_without_identity() {
    let pin_root =
        Path::new("/sys/fs/bpf").join(format!("honk-identity-failure-{}", std::process::id()));
    let (_dae0, mut backend) = load_bare(&pin_root).await;
    let stat = BpfStatsKey::SocketIdentityCaptureFailure as u32;
    let before = backend.get_bpf_stats(stat).unwrap().unwrap_or(0);

    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                // optmem_max is per-netns on the 6.12 floor. No host sysctl or
                // allocator fault injector is changed by this test.
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
                let mut netlink = crate::netlink::NlSock::new().unwrap();
                let (loopback, _) = netlink.get_link("lo").unwrap();
                netlink.set_link_up(loopback, true).unwrap();
                let mut storage = aya::maps::SkStorage::<_, SocketIdentity>::try_from(
                    backend
                        .bpf_mut()
                        .unwrap()
                        .map_mut("SOCKET_IDENTITY")
                        .unwrap(),
                )
                .unwrap();
                let mut cases = Vec::new();
                for (domain, address) in [
                    (socket2::Domain::IPV4, "127.0.0.1:0"),
                    (socket2::Domain::IPV6, "[::1]:0"),
                ] {
                    let listener = std::net::TcpListener::bind(address).unwrap();
                    let receiver = std::net::UdpSocket::bind(address).unwrap();
                    receiver
                        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                        .unwrap();
                    let tcp = socket2::Socket::new(
                        domain,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .unwrap();
                    let udp_connect = socket2::Socket::new(
                        domain,
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::UDP),
                    )
                    .unwrap();
                    let udp_send = socket2::Socket::new(
                        domain,
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::UDP),
                    )
                    .unwrap();
                    for socket in [&tcp, &udp_connect, &udp_send] {
                        assert_eq!(storage.get(socket, 0).unwrap().pid, std::process::id());
                        // Prepare actual missing capture, without replacing storage
                        // or simulating the kernel allocation failure.
                        storage.remove(socket).unwrap();
                    }
                    cases.push((domain, listener, receiver, tcp, udp_connect, udp_send));
                }

                const OPTMEM: &str = "/proc/sys/net/core/optmem_max";
                struct RestoreOptmem(String);
                impl Drop for RestoreOptmem {
                    fn drop(&mut self) {
                        std::fs::write(OPTMEM, &self.0).expect("restore owned netns optmem_max");
                    }
                }
                let restore = RestoreOptmem(std::fs::read_to_string(OPTMEM).unwrap());
                // bpf_sk_storage_charge rejects every positive allocation at zero.
                // All setup sockets and FDs already exist before admission closes.
                std::fs::write(OPTMEM, "0").unwrap();
                for (domain, listener, receiver, tcp, udp_connect, udp_send) in &cases {
                    for (kind, protocol) in [
                        (socket2::Type::STREAM, socket2::Protocol::TCP),
                        (socket2::Type::DGRAM, socket2::Protocol::UDP),
                    ] {
                        let created = socket2::Socket::new(*domain, kind, Some(protocol)).unwrap();
                        assert!(matches!(
                            storage.get(&created, 0),
                            Err(MapError::KeyNotFound)
                        ));
                    }
                    tcp.connect(&socket2::SockAddr::from(listener.local_addr().unwrap()))
                        .unwrap();
                    udp_connect
                        .connect(&socket2::SockAddr::from(receiver.local_addr().unwrap()))
                        .unwrap();
                    udp_send
                        .send_to(
                            b"unnamed",
                            &socket2::SockAddr::from(receiver.local_addr().unwrap()),
                        )
                        .unwrap();
                    let mut bytes = [0; 7];
                    assert_eq!(receiver.recv(&mut bytes).unwrap(), bytes.len());
                    assert_eq!(&bytes, b"unnamed");
                    for socket in [tcp, udp_connect, udp_send] {
                        assert!(matches!(storage.get(socket, 0), Err(MapError::KeyNotFound)));
                    }
                }
                drop(restore);

                // Once the charge is restored, the next hooked operation captures
                // the identity that the failed attempts left missing.
                for (_, _, receiver, _, _, udp_send) in &cases {
                    udp_send
                        .send_to(
                            b"allowed",
                            &socket2::SockAddr::from(receiver.local_addr().unwrap()),
                        )
                        .unwrap();
                    let mut bytes = [0; 7];
                    assert_eq!(receiver.recv(&mut bytes).unwrap(), bytes.len());
                    assert_eq!(&bytes, b"allowed");
                    assert_eq!(storage.get(udp_send, 0).unwrap().pid, std::process::id());
                }
            })
            .join()
            .expect("identity failure test in owned netns");
    });
    assert!(backend.get_bpf_stats(stat).unwrap().unwrap_or(0) >= before + 10);
    backend.detach_hooks().unwrap();
    backend.cleanup().await.unwrap();
    for name in [
        UDP_DECISION_SEQUENCE_MAP,
        routing::ROUTING_GENERATION_SEQUENCE_MAP,
    ] {
        std::fs::remove_file(pin_root.join(name)).unwrap();
    }
    std::fs::remove_dir(pin_root).unwrap();
}

#[test]
#[ignore = "requires disposable VM, root, cgroup v2, Linux 6.12+, and an eBPF build"]
fn unavailable_cgroup_capture_refuses_startup() {
    std::thread::spawn(|| {
        detect_cgroup_path().expect("real cgroup2 mount before isolation");
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
        nix::mount::mount(
            None::<&str>,
            "/",
            None::<&str>,
            nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .unwrap();
        // Remove only this private mount namespace's views, not cgroup hooks
        // or memberships. This formerly allowed startup with capture disabled.
        while let Ok(path) = detect_cgroup_path() {
            nix::mount::umount2(path.as_str(), nix::mount::MntFlags::MNT_DETACH).unwrap();
        }
        let pin_root = Path::new("/sys/fs/bpf")
            .join(format!("honk-identity-unavailable-{}", std::process::id()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (_dae0, dae0_setup) = crate::daens::create_test_dae0_pair().expect("dae0 pair");
        let links_before = held_bpf_link_count();
        let result = runtime.block_on(RealEbpfBackend::load(
            crate::DEFAULT_BPF_OBJECT,
            &pin_root,
            12345,
            &dae0_setup,
            0,
        ));
        assert!(
            result.is_err(),
            "startup allowed missing required cgroup capture"
        );
        assert_eq!(
            held_bpf_link_count(),
            links_before,
            "failed startup retained attachments"
        );
        std::fs::remove_dir_all(pin_root).unwrap();
    })
    .join()
    .expect("startup refusal in private mount namespace");
}

/// A legacy (flags=0, not a link) root-cgroup sock_ops program that is detached on drop.
struct LegacySockOps {
    cgroup: std::fs::File,
    program: std::os::fd::OwnedFd,
}

impl LegacySockOps {
    fn attach(cgroup: std::fs::File) -> std::io::Result<Self> {
        let program = load_program(
            BPF_PROG_TYPE_SOCK_OPS,
            &[insn(MOV64_IMM, 0, 0, 0, 1), insn(EXIT, 0, 0, 0, 0)],
        )?;
        let foreign = Self { cgroup, program };
        foreign.syscall(BPF_PROG_ATTACH as _)?;
        Ok(foreign)
    }

    fn syscall(&self, command: core::ffi::c_long) -> std::io::Result<()> {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.__bindgen_anon_5.__bindgen_anon_1.target_fd = self.cgroup.as_raw_fd() as u32;
        attr.__bindgen_anon_5.attach_bpf_fd = self.program.as_raw_fd() as u32;
        attr.__bindgen_anon_5.attach_type = BPF_CGROUP_SOCK_OPS as u32;
        unsafe { syscall::bpf_syscall(command, &mut attr) }
            .map(|_| ())
            .map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))
    }
}

impl Drop for LegacySockOps {
    fn drop(&mut self) {
        if let Err(error) = self.syscall(BPF_PROG_DETACH as _)
            && !std::thread::panicking()
        {
            panic!("detach foreign sock_ops program: {error}");
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable VM, root, cgroup v2, Linux 6.12+, and an eBPF build"]
async fn occupied_sock_ops_slot_refuses_startup_without_leaving_links() {
    let cgroup = std::fs::File::open(detect_cgroup_path().expect("cgroup2 mount")).unwrap();
    let foreign = LegacySockOps::attach(cgroup).expect("install legacy root sock_ops program");
    let pin_root =
        Path::new("/sys/fs/bpf").join(format!("honk-sock-ops-slot-{}", std::process::id()));
    std::fs::create_dir(&pin_root).unwrap();
    let foreign_pin = pin_root.join("FOREIGN_PIN");
    let foreign_map = AyaArray::<_, u64>::create(1, 0).unwrap();
    foreign_map.map().pin(&foreign_pin).unwrap();
    let foreign_map_id = foreign_map.map().info().unwrap().id();
    drop(foreign_map);
    let routing_pin = pin_root.join(routing::ROUTING_GENERATION_SEQUENCE_MAP);
    let routing_sequence = routing::open_routing_generation_sequence(&routing_pin).unwrap();
    let routing_map_id = routing_sequence.map().info().unwrap().id();
    drop(routing_sequence);
    let (_dae0, dae0_setup) = crate::daens::create_test_dae0_pair().expect("dae0 pair");
    let links_before = held_bpf_link_count();
    let programs_before = cgroup_attached_prog_count(foreign.cgroup.as_raw_fd());

    let result =
        RealEbpfBackend::load(crate::DEFAULT_BPF_OBJECT, &pin_root, 12345, &dae0_setup, 0).await;
    assert!(
        result.is_err(),
        "startup allowed an occupied root sock_ops slot"
    );
    assert_eq!(
        held_bpf_link_count(),
        links_before,
        "failed startup retained attachments"
    );
    assert_eq!(
        cgroup_attached_prog_count(foreign.cgroup.as_raw_fd()),
        programs_before,
        "failed startup retained cgroup programs"
    );
    let retained = [
        UDP_DECISION_SEQUENCE_MAP,
        routing::ROUTING_GENERATION_SEQUENCE_MAP,
        "FOREIGN_PIN",
    ];
    assert_eq!(
        aya::maps::MapInfo::from_pin(&foreign_pin).unwrap().id(),
        foreign_map_id,
        "failed startup replaced a foreign pin"
    );
    assert_eq!(
        aya::maps::MapInfo::from_pin(&routing_pin).unwrap().id(),
        routing_map_id,
        "failed startup replaced the persistent routing sequence"
    );
    for name in retained {
        std::fs::remove_file(pin_root.join(name)).unwrap();
    }
    std::fs::remove_dir(pin_root).unwrap();
}
