use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};

/// Enters private net/mount namespaces with their own sysfs, bpffs and cgroup2.
pub(crate) fn enter_lab_namespaces() -> anyhow::Result<()> {
    let expected_kernel = std::env::var("HONK_CI_EXPECTED_KERNEL").unwrap_or_default();
    anyhow::ensure!(
        std::env::var_os("HONK_CI_VM_LANE").is_some()
            && !expected_kernel.is_empty()
            && std::fs::read_to_string("/proc/sys/kernel/osrelease")?.trim() == expected_kernel,
        "root-cgroup datapath fixtures require the disposable kernel VM gate"
    );
    unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS)?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )?;
    // Mount isolation does not isolate root-cgroup BPF attachments. Only the
    // disposable VM above may remount its hierarchy for real identity capture.
    for line in std::fs::read_to_string("/proc/thread-self/mounts")?.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (_, target, filesystem) = (fields.next(), fields.next(), fields.next());
        if filesystem == Some("cgroup2") {
            umount2(target.expect("cgroup mount target"), MntFlags::MNT_DETACH)?;
        }
    }
    anyhow::ensure!(
        !std::fs::read_to_string("/proc/thread-self/mounts")?
            .lines()
            .any(|line| {
                matches!(
                    line.split_ascii_whitespace().nth(2),
                    Some("cgroup" | "cgroup2")
                )
            }),
        "isolated datapath fixture must not expose a host cgroup filesystem"
    );
    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    // The backend reads interface MACs through sysfs; it must see this netns.
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    mount(
        Some("bpf"),
        "/sys/fs/bpf",
        Some("bpf"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    Ok(())
}

pub(crate) fn enter_with_loopback() -> anyhow::Result<()> {
    enter_lab_namespaces()?;
    crate::netlink::NlSock::new()?.set_tun_link_up(nix::net::if_::if_nametoindex("lo")?)?;
    Ok(())
}
