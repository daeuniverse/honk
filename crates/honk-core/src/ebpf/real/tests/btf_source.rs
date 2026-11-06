use super::*;

#[test]
#[ignore = "requires disposable VM, root, cgroup v2, Linux 6.12+, and an eBPF build"]
fn kernel_btf_override_controls_startup() {
    const CHILD: &str = "HONK_TEST_KERNEL_BTF";
    let Ok(case) = std::env::var(CHILD) else {
        let directory = tempfile::tempdir().unwrap();
        let valid = directory.path().join("valid.btf");
        let invalid = directory.path().join("invalid.btf");
        let missing = directory.path().join("missing.btf");
        let data = std::fs::read("/sys/kernel/btf/vmlinux").unwrap();
        std::fs::write(&valid, &data).unwrap();
        std::fs::write(&invalid, b"not kernel BTF").unwrap();
        for (case, path) in [("valid", valid), ("missing", missing), ("invalid", invalid)] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "ebpf::real::tests::btf_source::kernel_btf_override_controls_startup",
                    "--nocapture",
                ])
                .env(CHILD, case)
                .env("HONK_VMLINUX_BTF", path)
                .status()
                .unwrap();
            assert!(status.success(), "kernel BTF override case {case} failed");
        }
        return;
    };
    let valid = case == "valid";

    let empty = tempfile::tempdir().unwrap();
    if valid {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
        nix::mount::mount(
            None::<&str>,
            "/",
            None::<&str>,
            nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .unwrap();
        // A matching override must work even without the sysfs BTF mount.
        nix::mount::mount(
            Some(empty.path()),
            "/sys/kernel/btf",
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let pin_root =
                Path::new("/sys/fs/bpf").join(format!("honk-kernel-btf-{}", std::process::id()));
            assert!(!pin_root.exists());
            let (_dae0, dae0_setup) = crate::daens::create_test_dae0_pair().expect("dae0 pair");
            let before = held_bpf_link_count();
            let result =
                RealEbpfBackend::load(crate::DEFAULT_BPF_OBJECT, &pin_root, 12345, &dae0_setup, 0)
                    .await;
            let mut backend = match result {
                Ok(backend) => backend,
                Err(error) => {
                    assert!(!valid, "matching BTF override rejected: {error:#}");
                    assert_eq!(held_bpf_link_count(), before);
                    assert!(!pin_root.exists());
                    return;
                }
            };
            if valid {
                let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                receiver
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let storage = aya::maps::SkStorage::<_, SocketIdentity>::try_from(
                    backend.bpf().unwrap().map("SOCKET_IDENTITY").unwrap(),
                )
                .unwrap();
                assert_eq!(storage.get(&receiver, 0).unwrap().pid, std::process::id());
                #[cfg(feature = "native-api")]
                {
                    let trace = backend.receive_trace().expect("override receive trace");
                    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    let mut registration = trace.register(receiver.as_raw_fd()).unwrap();
                    sender
                        .send_to(b"btf", receiver.local_addr().unwrap())
                        .unwrap();
                    assert!(registration.begin(receiver.as_raw_fd()));
                    let mut buffer = [0; 3];
                    assert_eq!(receiver.recv(&mut buffer).unwrap(), 3);
                    assert_eq!(&buffer, b"btf");
                    let packet = registration.finish(1).expect("traced UDP receive")[0];
                    assert_eq!(
                        packet.valid,
                        honk_ebpf_common::receive_trace::RECEIVE_TRACE_VALID
                    );
                    assert_eq!(packet.length, 3);
                }
                let tcp4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let tcp6 = std::net::TcpListener::bind("[::1]:0").unwrap();
                backend
                    .publish_listener_sockets(tcp4.as_raw_fd(), Some(tcp6.as_raw_fd()), &[], &[])
                    .unwrap();
                backend.set_datapath_ready(true).unwrap();
                backend.set_datapath_ready(false).unwrap();
                backend.clear_listener_sockets().unwrap();
            }
            backend.detach_hooks().unwrap();
            backend.cleanup().await.unwrap();
            std::fs::remove_dir_all(pin_root).unwrap();
            assert!(valid, "invalid BTF override allowed startup");
            assert_eq!(held_bpf_link_count(), before);
        });
}
