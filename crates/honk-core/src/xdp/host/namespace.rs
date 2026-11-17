use super::receipt::Receipt;
use crate::netlink::NlSock;
use anyhow::{Context as _, ensure};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;

pub(super) struct PrivatePair {
    pub namespace: OwnedFd,
    pub cookie: u64,
    pub tx: u32,
    pub tx_name: String,
    pub tx_mac: [u8; 6],
    pub device: honk_xsk::device::DeviceInfo,
    mount: PathBuf,
    inode: u64,
    namespace_receipt: usize,
    link_receipt: usize,
}

pub(super) fn in_namespace<T>(
    namespace: &OwnedFd,
    work: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    struct Restore {
        net: File,
        mount: File,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            if unsafe { libc::setns(self.net.as_raw_fd(), libc::CLONE_NEWNET) } != 0
                || unsafe { libc::setns(self.mount.as_raw_fd(), libc::CLONE_NEWNS) } != 0
            {
                std::process::abort();
            }
        }
    }
    let net = File::open("/proc/thread-self/ns/net")?;
    let mount = File::open("/proc/thread-self/ns/mnt")?;
    // Only cold setup calls this scope; a fresh sysfs mount must follow its netns.
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS | nix::sched::CloneFlags::CLONE_FS)?;
    let restore = Restore { net, mount };
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;
    nix::sched::setns(namespace, nix::sched::CloneFlags::CLONE_NEWNET)?;
    nix::mount::mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        nix::mount::MsFlags::MS_RDONLY
            | nix::mount::MsFlags::MS_NOSUID
            | nix::mount::MsFlags::MS_NODEV
            | nix::mount::MsFlags::MS_NOEXEC,
        None::<&str>,
    )?;
    // Fresh sysfs hides the source mount's securityfs submount.
    nix::mount::mount(
        Some("securityfs"),
        "/sys/kernel/security",
        Some("securityfs"),
        nix::mount::MsFlags::MS_RDONLY
            | nix::mount::MsFlags::MS_NOSUID
            | nix::mount::MsFlags::MS_NODEV
            | nix::mount::MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("Host private namespace securityfs mount")?;
    super::kernel::zero_monotonic_namespace()?;
    let result = work();
    drop(restore);
    result
}

fn configure_private_ipv6(name: &str) -> anyhow::Result<()> {
    for (key, value) in [("disable_ipv6", "1"), ("accept_ra", "0"), ("autoconf", "0")] {
        let path = format!("/proc/sys/net/ipv6/conf/{name}/{key}");
        std::fs::write(&path, value)?;
        ensure!(
            std::fs::read_to_string(path)?.trim() == value,
            "Host private sysctl readback"
        );
    }
    Ok(())
}

impl PrivatePair {
    pub fn create(attachment: u64, receipt: &mut Receipt) -> anyhow::Result<Self> {
        let namespace: OwnedFd = std::thread::spawn(|| -> anyhow::Result<OwnedFd> {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)?;
            Ok(File::open("/proc/thread-self/ns/net")?.into())
        })
        .join()
        .map_err(|_| anyhow::anyhow!("Host namespace creator panicked"))??;
        let mount = receipt.path().with_extension("netns");
        let namespace_receipt =
            receipt.intent("network_namespace", serde_json::json!({"mount": mount}))?;
        let target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&mount)?;
        target.sync_all()?;
        File::open(mount.parent().context("Host netns parent")?)?.sync_all()?;
        let source = format!("/proc/self/fd/{}", namespace.as_raw_fd());
        nix::mount::mount(
            Some(source.as_str()),
            &mount,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )?;
        let inode = std::fs::metadata(&mount)?.ino();
        let held: File = namespace.try_clone()?.into();
        ensure!(
            held.metadata()?.ino() == inode,
            "Host namespace mount identity mismatch"
        );
        let cookie = in_namespace(&namespace, || {
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
            Ok(crate::netlink::fib::namespace_cookie(socket.as_raw_fd())?)
        })?;
        receipt.acknowledge(
            namespace_receipt,
            serde_json::json!({"inode":inode,"cookie":cookie}),
        )?;
        let tx_name = format!("hx{:010x}t", attachment);
        let rx_name = format!("hx{:010x}r", attachment);
        ensure!(
            tx_name.len() < libc::IFNAMSIZ,
            "Host attachment exceeds device name domain"
        );
        let link_receipt = receipt.intent(
            "private_veth",
            serde_json::json!({"tx_name":tx_name,"rx_name":rx_name,"child_cookie":cookie}),
        )?;
        let mut nl = NlSock::new()?;
        nl.add_veth_pair(&tx_name, &rx_name)?;
        let (tx, tx_mac) = nl.get_link(&tx_name)?;
        let (rx, _) = nl.get_link(&rx_name)?;
        configure_private_ipv6(&tx_name)?;
        nl.set_link_mtu(tx, 65535)?;
        nl.set_link_mtu(rx, 65535)?;
        nl.set_link_netns_fd(rx, &namespace)?;
        let device = in_namespace(&namespace, || {
            let mut nl = NlSock::new()?;
            let (rx, _) = nl.get_link(&rx_name)?;
            configure_private_ipv6(&rx_name)?;
            nl.set_link_up(rx, true)?;
            let device = honk_xsk::device::DeviceInfo::discover(&rx_name)?;
            ensure!(
                device.queues == [0] && device.mtu == 65535 && device.upper_ifindices.is_empty(),
                "Host private RX shape"
            );
            Ok(device)
        })?;
        nl.set_link_up(tx, true)?;
        receipt.acknowledge(link_receipt,serde_json::json!({"tx":tx,"rx":device.ifindex,"tx_mac":tx_mac,"rx_mac":device.mac,"mtu":device.mtu}))?;
        Ok(Self {
            namespace,
            cookie,
            tx,
            tx_name,
            tx_mac,
            device,
            mount,
            inode,
            namespace_receipt,
            link_receipt,
        })
    }

    pub fn remove(&self, receipt: &mut Receipt) -> anyhow::Result<()> {
        let mut nl = NlSock::new()?;
        ensure!(
            nl.get_link(&self.tx_name)? == (self.tx, self.tx_mac),
            "Host private link replaced"
        );
        ensure!(
            std::fs::metadata(&self.mount)?.ino() == self.inode,
            "Host private namespace mount replaced"
        );
        receipt.begin_removal(self.link_receipt)?;
        nl.del_link(self.tx)?;
        ensure!(
            !nl.dump_links()?
                .iter()
                .any(|link| link.ifindex.get() == self.tx),
            "Host private link remains after delete"
        );
        receipt.removed(self.link_receipt)?;
        receipt.begin_removal(self.namespace_receipt)?;
        nix::mount::umount(&self.mount)?;
        std::fs::remove_file(&self.mount)?;
        File::open(self.mount.parent().context("Host netns parent")?)?.sync_all()?;
        receipt.removed(self.namespace_receipt)
    }
}
