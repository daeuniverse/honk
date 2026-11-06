//! FD-owned daens namespace and host-link setup.

#[cfg(feature = "ebpf")]
use crate::netlink;
#[cfg(feature = "ebpf")]
use crate::sysctl::{require_off, set_sysctl};
#[cfg(feature = "ebpf")]
use tracing::{info, warn};

/// Validated identity of the daemon-owned `dae0`/`dae0peer` pair, read once
/// over netlink right after creation (both ends still in the host namespace).
/// The datapath PARAM is built only from this, so a zero ifindex or MAC never
/// reaches the kernel.
#[cfg(feature = "ebpf")]
#[derive(Debug, Clone)]
pub struct Dae0Setup {
    ifindex: u32,
    peer_ifindex: u32,
    peer_mac: [u8; 6],
}

#[cfg(feature = "ebpf")]
impl Dae0Setup {
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub fn peer_ifindex(&self) -> u32 {
        self.peer_ifindex
    }

    pub fn peer_mac(&self) -> [u8; 6] {
        self.peer_mac
    }

    fn new(ifindex: u32, peer_ifindex: u32, peer_mac: [u8; 6]) -> anyhow::Result<Self> {
        anyhow::ensure!(ifindex != 0, "dae0 has no valid ifindex");
        anyhow::ensure!(peer_ifindex != 0, "dae0peer has no valid ifindex");
        anyhow::ensure!(peer_mac != [0; 6], "dae0peer has an all-zero MAC address");
        Ok(Self {
            ifindex,
            peer_ifindex,
            peer_mac,
        })
    }

    /// Read through the netlink socket's own namespace, never sysfs (whose
    /// view is per-mount and ignores a scoped setns).
    fn read_links(nl: &mut netlink::NlSock, dae0: &str, peer: &str) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let (ifindex, _) = nl.get_link(dae0).with_context(|| format!("read {dae0}"))?;
        let (peer_ifindex, peer_mac) = nl.get_link(peer).with_context(|| format!("read {peer}"))?;
        Self::new(ifindex, peer_ifindex, peer_mac)
    }

    pub(crate) fn read(nl: &mut netlink::NlSock) -> anyhow::Result<Self> {
        Self::read_links(nl, "dae0", "dae0peer")
    }
}

/// Guard that removes the `dae0` link pair and policy routing when it goes out
/// of scope. If setup fails mid-way, drop cleans up whatever was installed.
///
/// Link-local addressing (169.254.0.1/32 on dae0, 169.254.0.11/32 on dae0peer)
/// eliminates the need for iptables MASQUERADE and TCP MSS clamping — the kernel
/// already treats link-local traffic as local.
#[cfg(feature = "ebpf")]
pub(crate) struct Dae0Guard {
    pub ifindex: u32,
}

#[cfg(feature = "ebpf")]
impl Dae0Guard {
    fn new() -> Self {
        Self { ifindex: 0 }
    }
}

#[cfg(feature = "ebpf")]
impl Drop for Dae0Guard {
    fn drop(&mut self) {
        info!("Cleaning up dae0 side effects");
        // The recorded ifindex keeps cleanup pointed at the device THIS
        // instance created, never at a same-named replacement.
        cleanup_dae0_interface((self.ifindex != 0).then_some(self.ifindex));
    }
}

#[cfg(feature = "ebpf")]
pub(crate) fn create_dae0_link() -> anyhow::Result<(Dae0Guard, Dae0Setup)> {
    let mut guard = Dae0Guard::new();

    // Stale-state cleanup (previous run): drop the compat bind-mount (the
    // FD-held namespace dies with its owner process) and any leftover dae0.
    // The singleton lock guarantees no live sibling owns these names.
    if is_mountpoint("/run/netns/daens") {
        let _ = nix::mount::umount2(DAENS_NS_PATH, nix::mount::MntFlags::MNT_DETACH);
    }
    if let Ok(idx) = netlink::ifindex_of("dae0")
        && let Ok(mut nl) = netlink::NlSock::new()
    {
        let _ = nl.del_link(idx);
    }

    // FD-owned namespace (unshare + held FD, compat bind-mount inside).
    create_daens_namespace()?;

    let mut nl = netlink::NlSock::new().map_err(|e| anyhow::anyhow!("netlink: {e}"))?;
    let link_kind = nl
        .add_link_pair("dae0", "dae0peer")
        .map_err(|e| anyhow::anyhow!("failed to add dae0 link pair: {e}"))?;
    info!(kind = ?link_kind, "Created dae0/dae0peer link pair");

    let setup = Dae0Setup::read(&mut nl)?;
    let (dae0_idx, peer_idx) = (setup.ifindex(), setup.peer_ifindex());

    // These are datapath-critical: a "successful" startup without them is
    // worse than a loud failure.
    nl.set_link_up(dae0_idx, true)
        .map_err(|e| anyhow::anyhow!("bring dae0 up: {e}"))?;
    nl.set_link_up(peer_idx, true)
        .map_err(|e| anyhow::anyhow!("bring dae0peer up: {e}"))?;

    for (key, val) in [
        ("net.ipv4.conf.dae0.rp_filter", "0"),
        ("net.ipv4.conf.dae0.accept_local", "1"),
    ] {
        match set_sysctl(key, val) {
            Ok(()) => info!("{} = {}", key, val),
            Err(e) => warn!("failed to set {}={}: {}", key, val, e),
        }
    }

    // Enable IPv6 on dae0 for the daens IPv6 reply path.
    let _ = set_sysctl("net.ipv6.conf.dae0.disable_ipv6", "0");
    let _ = set_sysctl("net.ipv6.conf.dae0.forwarding", "1");

    guard.ifindex = dae0_idx;

    // Assign a link-local /32 address to the host-side dae0.  Link-local
    // addressing eliminates the need for iptables MASQUERADE and TCP MSS
    // clamping — the kernel already treats 169.254.0.0/16 traffic as local.
    let host_v4: std::net::Ipv4Addr = DAENS_HOST_IP.parse().unwrap();
    // Idempotent: delete any stale address left by a previous run first.
    let _ = nl.addr_op(false, dae0_idx, netlink::FAM_V4, &host_v4.octets(), 32);
    nl.addr_op(true, dae0_idx, netlink::FAM_V4, &host_v4.octets(), 32)
        .map_err(|e| anyhow::anyhow!("dae0 IPv4 address {}: {e}", host_v4))?;

    // Assign an IPv6 ULA address to the host-side dae0 so the daens
    // namespace can route IPv6 replies back through this link.
    let host_v6: std::net::Ipv6Addr = DAENS_HOST_IPV6.parse().unwrap();
    let _ = nl.addr_op(false, dae0_idx, netlink::FAM_V6, &host_v6.octets(), 64);
    let _ = nl.addr_op(true, dae0_idx, netlink::FAM_V6, &host_v6.octets(), 64);

    // Enable IPv6 forwarding so daens-originated IPv6 packets reach the LAN.
    let _ = set_sysctl("net.ipv6.conf.all.forwarding", "1");

    Ok((guard, setup))
}

#[cfg(feature = "ebpf")]
pub(crate) fn setup_daens_namespace(tproxy_mark: u32, tproxy_port: u16) -> anyhow::Result<()> {
    let _ = tproxy_port;
    use crate::netlink::{FAM_V4, FAM_V6, NlSock};

    // Host-side dae0 MAC: the L2 next-hop for the daens default route.
    let dae0_mac = netlink::mac_of("dae0").map_err(|e| anyhow::anyhow!("read dae0 MAC: {e}"))?;
    let dae0_idx = netlink::ifindex_of("dae0")?;
    let peer_idx = netlink::ifindex_of("dae0peer")?;

    // Move dae0peer into daens (BPF programs are already attached).
    let mut nl = NlSock::new().map_err(|e| anyhow::anyhow!("netlink: {e}"))?;
    nl.set_link_netns_fd(peer_idx, daens_fd()?)
        .map_err(|e| anyhow::anyhow!("move dae0peer to daens: {e}"))?;
    info!("Moved dae0peer to daens");

    let host_v4: std::net::Ipv4Addr = DAENS_HOST_IP.parse().unwrap();
    let peer_v4: std::net::Ipv4Addr = DAENS_PEER_IP.parse().unwrap();
    let host_v6: std::net::Ipv6Addr = DAENS_HOST_IPV6.parse().unwrap();
    let peer_v6: std::net::Ipv6Addr = DAENS_PEER_IPV6.parse().unwrap();

    // Configure daens in one scoped switch: a netlink socket opened inside
    // operates on the daens namespace, and /proc/sys writes hit the
    // namespace's sysctls.
    let peer_mac = with_daens_netns("configure daens", || {
        use anyhow::Context as _;
        let mut n = NlSock::new().context("daens netlink socket")?;
        // /sys inside a scoped setns still shows the HOST's devices (the
        // view is per-mount, not per-reader) — look links up over netlink,
        // whose socket is bound to the namespace it was created in.
        let (lo, _) = n.get_link("lo").context("lo in daens")?;
        let (peer, peer_mac) = n.get_link("dae0peer").context("dae0peer in daens")?;
        n.set_link_up(lo, true).context("lo up")?;
        n.set_link_up(peer, true).context("dae0peer up")?;
        let ipv6 = netlink::ipv6_socket_available().context("probe IPv6 family in daens")?;

        // fwmark → table 100 with a local default route (v4 + v6 mirror):
        // marked packets are delivered to daens-local sockets.
        n.add_rule_fwmark(
            FAM_V4,
            tproxy_mark,
            !honk_ebpf_common::DNS_ROUTE_MARK_MASK,
            100,
        )?;
        n.add_route(
            FAM_V4,
            100,
            netlink::ROUTE_LOCAL,
            netlink::SCOPE_HOST,
            netlink::PROTO_STATIC,
            None,
            None,
            Some(lo),
        )?;
        if ipv6 {
            n.add_rule_fwmark(
                FAM_V6,
                tproxy_mark,
                !honk_ebpf_common::DNS_ROUTE_MARK_MASK,
                100,
            )?;
            n.add_route(
                FAM_V6,
                100,
                netlink::ROUTE_LOCAL,
                netlink::SCOPE_HOST,
                netlink::PROTO_STATIC,
                None,
                None,
                Some(lo),
            )?;
        }

        // Link-local /32 on dae0peer. The link-scope route tells the kernel
        // that 169.254.0.1 (dae0) is directly reachable at L2; without it,
        // /32 prevents treating 169.254.0.1 as a valid nexthop.
        n.addr_op(true, peer, FAM_V4, &peer_v4.octets(), 32)?;
        n.add_route(
            FAM_V4,
            254,
            netlink::ROUTE_UNICAST,
            netlink::SCOPE_LINK,
            netlink::PROTO_STATIC,
            Some((&host_v4.octets(), 32)),
            None,
            Some(peer),
        )?;
        n.add_route(
            FAM_V4,
            254,
            netlink::ROUTE_UNICAST,
            netlink::SCOPE_UNIVERSE,
            netlink::PROTO_STATIC,
            None,
            Some(&host_v4.octets()),
            Some(peer),
        )?;

        // IPv6 ULA on dae0peer + IPv6 default (non-fatal: v6 path degrades
        // to v4-only rather than aborting startup).
        let _ = n.addr_op(true, peer, FAM_V6, &peer_v6.octets(), 64);
        let _ = n.add_route(
            FAM_V6,
            254,
            netlink::ROUTE_UNICAST,
            netlink::SCOPE_UNIVERSE,
            netlink::PROTO_STATIC,
            None,
            Some(&host_v6.octets()),
            Some(peer),
        );

        // Static neighbours for the host side of the link (v4 + v6).
        n.neigh_replace(peer, FAM_V4, &host_v4.octets(), &dae0_mac)?;
        let _ = n.neigh_replace(peer, FAM_V6, &host_v6.octets(), &dae0_mac);

        // Disable rp_filter, enable accept_local/route_localnet in daens so
        // packets with foreign source/dest addresses can be delivered locally.
        for (key, val) in [
            ("net.ipv4.conf.all.rp_filter", "0"),
            ("net.ipv4.conf.all.accept_local", "1"),
            ("net.ipv4.conf.all.route_localnet", "1"),
            ("net.ipv4.conf.dae0peer.rp_filter", "0"),
            ("net.ipv4.conf.dae0peer.accept_local", "1"),
            ("net.ipv4.conf.dae0peer.route_localnet", "1"),
            ("net.ipv4.conf.lo.accept_local", "1"),
            ("net.ipv4.conf.lo.route_localnet", "1"),
            ("net.ipv6.conf.all.forwarding", "1"),
            ("net.ipv6.conf.dae0peer.forwarding", "1"),
            ("net.ipv6.conf.dae0peer.accept_ra", "0"),
        ] {
            let _ = set_sysctl(key, val);
        }

        // The child proof derives its ISN from `rcv_nxt` at the passive callback, which is only
        // established for ordinary handshakes; keep the other child-creation paths off.
        for (key, optional) in [
            ("net.ipv4.tcp_syncookies", true),
            ("net.ipv4.tcp_migrate_req", false),
            ("net.ipv4.tcp_fastopen", false),
        ] {
            require_off(key, optional)?;
        }
        Ok(peer_mac)
    })?;

    // Install static neighbour entries on the host so replies to
    // daens-bound connections are forwarded to the correct dae0peer MAC.
    nl.neigh_replace(dae0_idx, FAM_V4, &peer_v4.octets(), &peer_mac)
        .map_err(|e| anyhow::anyhow!("host neighbour for daens peer: {e}"))?;
    let _ = nl.neigh_replace(dae0_idx, FAM_V6, &peer_v6.octets(), &peer_mac);

    // Make sure the host forwards traffic between dae0 and the LAN/WAN
    // interfaces; this is required for the SYN-ACK path back to the client.
    set_sysctl("net.ipv4.ip_forward", "1")
        .map_err(|e| anyhow::anyhow!("enable net.ipv4.ip_forward: {e}"))?;

    info!("Configured daens namespace (mark={:#x})", tproxy_mark);
    DAENS_READY.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

/// Path of the daens network-namespace bind-mount, kept for external
/// tooling compatibility (`ip netns exec`, debug shells). The engine
/// itself never depends on it — the namespace is FD-owned (below).
#[cfg(target_os = "linux")]
pub(crate) const DAENS_NS_PATH: &str = "/var/run/netns/daens";

/// Runtime truth for "daens is set up", set by [`setup_daens_namespace`]
/// on success. Socket creation must key on this, never on
/// `DAENS_NS_PATH` existing — a leftover or failed compat mount says
/// nothing about the datapath (a first clean deploy once bound every
/// TPROXY listener into the host namespace because of that confusion).
#[cfg(target_os = "linux")]
pub(crate) static DAENS_READY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether THIS instance created the compat bind-mount at
/// [`DAENS_NS_PATH`]. Cleanup only ever unmounts what it mounted —
/// never a same-named mount belonging to another tool.
#[cfg(feature = "ebpf")]
static COMPAT_MOUNTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Whether THIS instance created the regular file used as the compat
/// bind-mount target. If `/run/netns` belongs to iproute2, unmounting the
/// child does not remove that file, so cleanup must remove its own target.
#[cfg(feature = "ebpf")]
static COMPAT_FILE_CREATED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The engine-owned daens namespace FD, created by
/// [`create_daens_namespace`] at startup. An open namespace FD pins the
/// namespace for the process lifetime — no `ip netns` registry involved.
#[cfg(feature = "ebpf")]
static DAENS_FD: std::sync::OnceLock<std::os::unix::io::OwnedFd> = std::sync::OnceLock::new();

/// Whether THIS instance mounted the tmpfs at /run/netns (the compat
/// bind-mount's parent). Tracked separately from [`COMPAT_MOUNTED`]:
/// cleanup unmounts the parent only when it is ours.
#[cfg(feature = "ebpf")]
static PARENT_TMPFS_MOUNTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Create the daens network namespace without iproute2: a throwaway thread
/// `unshare(CLONE_NEWNET)`s, hands its `/proc/thread-self/ns/net` FD back
/// (the FD pins the namespace after the thread exits), and the FD is stored
/// process-wide. For external tooling compatibility the namespace is also
/// bind-mounted to [`DAENS_NS_PATH`] (best-effort — the engine works fine
/// without the mount).
#[cfg(feature = "ebpf")]
fn create_daens_namespace() -> anyhow::Result<&'static std::os::unix::io::OwnedFd> {
    use std::os::unix::io::OwnedFd;

    if let Some(fd) = DAENS_FD.get() {
        return Ok(fd);
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Err(error) = nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET) {
            let _ = tx.send(Err(std::io::Error::from(error)));
            return;
        }
        // /proc/self/ns/net always shows the main thread's namespace. This
        // thread-local path is the namespace created by unshare above.
        let task_ns = "/proc/thread-self/ns/net";
        // Best-effort compat mount: /var/run/netns/daens (iproute2 shape).
        // The target must be a FILE — namespace handles are files, and a
        // file bind-mount onto a directory fails with ENOTDIR. The parent
        // is made a mountpoint (tmpfs) only if it isn't one already —
        // crucially NOT via a self-MS_BIND, which would stack-duplicate
        // every nsfs mount beneath it (lab ns pins included) on every
        // engine restart.
        let _ = std::fs::create_dir_all("/var/run/netns");
        // /proc/mounts lists the real path (/var/run is a symlink to
        // /run) — check the canonical path or every engine start
        // mounts a fresh tmpfs over the registry, hiding iproute2's
        // namespace files (the lab netns "disappears"). The tmpfs must
        // be mounted BEFORE the target file is created, or the mount
        // hides it and the bind below fails on a first clean deploy.
        if !is_mountpoint("/run/netns") {
            match nix::mount::mount(
                Some("tmpfs"),
                "/var/run/netns",
                Some("tmpfs"),
                nix::mount::MsFlags::empty(),
                None::<&str>,
            ) {
                Ok(()) => {
                    PARENT_TMPFS_MOUNTED.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                Err(error) => warn!("tmpfs mount on /run/netns failed: {error}"),
            }
        }
        let compat_target_ready = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(DAENS_NS_PATH)
        {
            Ok(_) => {
                COMPAT_FILE_CREATED.store(true, std::sync::atomic::Ordering::Relaxed);
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => true,
            Err(error) => {
                warn!("create compat daens target failed: {error}");
                false
            }
        };
        if compat_target_ready {
            // The bind result is reported, never silently ignored — a failed
            // compat mount leaves debug tooling unable to find daens.
            match nix::mount::mount(
                Some(task_ns),
                DAENS_NS_PATH,
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            ) {
                Ok(()) => COMPAT_MOUNTED.store(true, std::sync::atomic::Ordering::Relaxed),
                Err(error) => {
                    warn!("compat bind-mount of daens failed (debug tooling degraded): {error}");
                }
            }
        }
        let result = std::fs::File::open(task_ns).map(OwnedFd::from);
        if result.is_ok() {
            let link = std::fs::read_link(task_ns)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|e| format!("<readlink failed: {e}>"));
            info!("daens FD source: {} -> {}", task_ns, link);
        }
        let _ = tx.send(result);
    });
    let fd = rx
        .recv()
        .map_err(|_| anyhow::anyhow!("daens creator thread died"))?
        .map_err(|e| anyhow::anyhow!("create daens namespace: {e}"))?;
    info!("Created daens network namespace (FD-owned)");
    Ok(DAENS_FD.get_or_init(|| fd))
}

/// The process-wide daens FD (created on demand).
#[cfg(feature = "ebpf")]
pub(crate) fn daens_fd() -> anyhow::Result<&'static std::os::unix::io::OwnedFd> {
    create_daens_namespace()
}

#[cfg(feature = "ebpf")]
pub(crate) fn daens_netns_id() -> anyhow::Result<i32> {
    use std::os::fd::AsFd as _;

    Ok(netlink::NlSock::new()?.ensure_netns_id(daens_fd()?.as_fd())?)
}

/// `SO_NETNS_COOKIE` of the owned daens: the id `bpf_get_netns_cookie` reports for sockets
/// living there, which is how sock_ops tells honk's listeners from every other host socket.
#[cfg(feature = "ebpf")]
pub(crate) fn daens_netns_cookie() -> anyhow::Result<u64> {
    use anyhow::Context as _;
    use std::os::fd::AsRawFd as _;

    with_daens_netns("read daens netns cookie", || {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
            .context("create daens cookie probe socket")?;
        let mut cookie = 0u64;
        let mut length = size_of::<u64>() as libc::socklen_t;
        // SAFETY: `cookie` and `length` outlive the call and describe a u64 option value.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NETNS_COOKIE,
                (&raw mut cookie).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("SO_NETNS_COOKIE (Linux 5.14 or newer required)");
        }
        Ok(cookie)
    })
}

/// Run `f` with the calling thread temporarily switched into the `daens`
/// network namespace, restoring the original namespace on every exit path —
/// including when `f` returns an error or panics (via the drop guard below).
///
/// This mirrors Go dae's `DaeNetns.WithRequired`: the process (all threads)
/// always stays in the host netns; only operations that need the
/// daens-internal view enter it for a scoped, synchronous call:
/// dae0peer TC filter attach, sk_lookup attach, and DNS/UDP reply socket
/// creation (Go "anyfrom" semantics — reply sockets must live in daens so
/// their packets egress dae0peer and take the host dae0_ingress rewrite path
/// back to the LAN).
///
/// `f` must be fully synchronous and must not `.await`: setns(2) is
/// per-thread, so a future parked while inside daens could resume on a
/// different worker thread that never switched, and this thread could
/// restore its namespace while the parked future still assumes daens.  A
/// process-wide mutex serializes the switches; it is not strictly required
/// for correctness (each switch is per-thread) but keeps enter/leave pairs
/// easy to reason about and the logs ordered.
#[cfg(target_os = "linux")]
pub(crate) fn with_daens_netns<R>(
    op: &str,
    f: impl FnOnce() -> anyhow::Result<R>,
) -> anyhow::Result<R> {
    static DAENS_SWITCH: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Restores the saved network namespace on drop, so the original
    /// namespace is regained even when `f` panics. A failed restore
    /// aborts the process — a worker left in the wrong namespace would
    /// silently originate dials from daens forever after.
    struct RestoreNs<'a> {
        fd: std::fs::File,
        op: &'a str,
    }
    impl Drop for RestoreNs<'_> {
        fn drop(&mut self) {
            if let Err(error) = nix::sched::setns(&self.fd, nix::sched::CloneFlags::CLONE_NEWNET) {
                tracing::error!(
                    "failed to restore original netns after '{}': {} — aborting",
                    self.op,
                    error
                );
                std::process::abort();
            }
        }
    }

    // Lock FIRST: the save-and-switch is serialized before any namespace
    // reads, so no other scoped switch can interleave.
    let _switch_guard = DAENS_SWITCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // /proc/thread-self/ns/net is this thread's real namespace;
    // /proc/self/ns/net always resolves to the main thread.
    let orig_ns = std::fs::File::open("/proc/thread-self/ns/net")
        .map_err(|e| anyhow::anyhow!("{}: open /proc/thread-self/ns/net: {}", op, e))?;

    // The FD-owned namespace is the primary handle; the compat bind-mount
    // path is the fallback for tests, mock mode, and non-ebpf builds.
    #[cfg(feature = "ebpf")]
    {
        let daens = daens_fd()
            .map_err(|error| anyhow::anyhow!("{op}: daens namespace unavailable: {error:#}"))?;
        nix::sched::setns(daens, nix::sched::CloneFlags::CLONE_NEWNET)
            .map_err(|error| anyhow::anyhow!("{op}: setns(daens): {error}"))?;
    }
    #[cfg(not(feature = "ebpf"))]
    {
        let daens = std::fs::File::open(DAENS_NS_PATH)
            .map_err(|error| anyhow::anyhow!("{op}: open {DAENS_NS_PATH}: {error}"))?;
        nix::sched::setns(&daens, nix::sched::CloneFlags::CLONE_NEWNET)
            .map_err(|error| anyhow::anyhow!("{op}: setns(daens): {error}"))?;
    }
    let _restore_guard = RestoreNs { fd: orig_ns, op };
    f()
}

#[cfg(feature = "ebpf")]
fn cleanup_dae0_interface(recorded_ifindex: Option<u32>) {
    // Unmount the compat bind-mount only when THIS instance mounted it —
    // a same-named mount from another tool is never ours to tear down.
    if COMPAT_MOUNTED.swap(false, std::sync::atomic::Ordering::Relaxed) {
        let _ = nix::mount::umount2(DAENS_NS_PATH, nix::mount::MntFlags::MNT_DETACH);
    }
    if COMPAT_FILE_CREATED.swap(false, std::sync::atomic::Ordering::Relaxed)
        && let Err(error) = std::fs::remove_file(DAENS_NS_PATH)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!("remove compat daens target failed: {error}");
    }
    // Same ownership rule for the parent tmpfs (child must go first).
    if PARENT_TMPFS_MOUNTED.swap(false, std::sync::atomic::Ordering::Relaxed) {
        let _ = nix::mount::umount2("/run/netns", nix::mount::MntFlags::MNT_DETACH);
    }
    DAENS_READY.store(false, std::sync::atomic::Ordering::Release);
    // The FD-owned namespace dies with the process (dae0peer goes with it).

    let Ok(mut nl) = netlink::NlSock::new() else {
        return;
    };
    // Delete dae0 only when it is still the device this instance created:
    // the recorded ifindex must still match the name — an outsider's
    // same-named recreation is left alone.
    let victim = match recorded_ifindex {
        Some(idx) if netlink::ifindex_of("dae0").ok() == Some(idx) => Some(idx),
        Some(_) => None,
        None => netlink::ifindex_of("dae0").ok(),
    };
    if let Some(idx) = victim {
        let _ = nl.del_link(idx);
    }
    // Policy-routing rules for daens live inside the daens namespace and
    // disappear with it; these are only a safety net for stale
    // host-namespace rules.
    let _ = nl.del_rule_fwmark(
        netlink::FAM_V4,
        honk_ebpf_common::TPROXY_MARK,
        u32::MAX,
        100,
    );
    let _ = nl.del_rule_fwmark(
        netlink::FAM_V6,
        honk_ebpf_common::TPROXY_MARK,
        u32::MAX,
        100,
    );
}

/// Addressing for the dae0/dae0peer link pair between the host namespace and
/// the isolated `daens` namespace.  These strings are the canonical values:
/// the netns setup consumes them (ebpf feature only), while the control
/// plane's internal-traffic filter (`control::is_honk_internal_addr`) and the
/// kernel datapath use the numeric forms `DAE0_IPV6_PREFIX_HI` /
/// `DAE0_IPV4_NET` in `honk-ebpf-common` in every build.  `control` tests
/// assert both forms agree.
///
/// Link-local addresses (169.254.0.0/16) are used instead of a private
/// subnet so that the kernel treats daens-originated traffic as local — no
/// iptables MASQUERADE or TCP MSS clamping is needed.
#[cfg(any(feature = "ebpf", test))]
pub(crate) const DAENS_HOST_IP: &str = "169.254.0.1";
#[cfg(any(feature = "ebpf", test))]
pub(crate) const DAENS_PEER_IP: &str = "169.254.0.11";
/// IPv6 ULA addresses of the dae0/dae0peer link pair (fd00:686f:6e6b::/64).
/// The middle hextets are ASCII "honk" (`68 6f 6e 6b`) so the mnemonic
/// stays readable while remaining a valid IPv6 ULA prefix.
#[cfg(any(feature = "ebpf", test))]
pub(crate) const DAENS_HOST_IPV6: &str = "fd00:686f:6e6b::1";
#[cfg(any(feature = "ebpf", test))]
pub(crate) const DAENS_PEER_IPV6: &str = "fd00:686f:6e6b::2";

/// Whether `path` is a mountpoint (appears in /proc/mounts).
#[cfg(feature = "ebpf")]
fn is_mountpoint(path: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|m| m.lines().any(|l| l.split_whitespace().nth(1) == Some(path)))
        .unwrap_or(false)
}

/// Fixture for production-load tests: a real `dae0`/`dae0peer` pair in the
/// caller's (disposable) network namespace, read through the same validated
/// path as startup. Dropping the guard deletes the pair.
#[cfg(all(test, feature = "ebpf"))]
pub(crate) fn create_test_dae0_pair() -> anyhow::Result<(Dae0Guard, Dae0Setup)> {
    let mut nl = netlink::NlSock::new()?;
    if let Ok((stale, _)) = nl.get_link("dae0") {
        nl.del_link(stale)?;
    }
    nl.add_link_pair("dae0", "dae0peer")?;
    let setup = Dae0Setup::read(&mut nl)?;
    Ok((
        Dae0Guard {
            ifindex: setup.ifindex(),
        },
        setup,
    ))
}

#[cfg(all(test, feature = "ebpf"))]
mod tests {
    use super::*;

    #[test]
    fn setup_rejects_zero_ifindex_and_zero_mac() {
        let mac = [0x02, 0, 0, 0, 0, 1];
        assert!(Dae0Setup::new(1, 2, mac).is_ok());
        assert!(Dae0Setup::new(0, 2, mac).is_err());
        assert!(Dae0Setup::new(1, 0, mac).is_err());
        assert!(Dae0Setup::new(1, 2, [0; 6]).is_err());
    }

    #[test]
    fn read_links_reports_missing_link_and_zero_mac() {
        let mut nl = netlink::NlSock::new().expect("netlink socket");
        let missing = Dae0Setup::read_links(&mut nl, "honk-no-such0", "lo")
            .expect_err("missing dae0 must fail");
        assert!(
            format!("{missing:#}").contains("honk-no-such0"),
            "{missing:#}"
        );
        let missing_peer = Dae0Setup::read_links(&mut nl, "lo", "honk-no-such1")
            .expect_err("missing dae0peer must fail");
        assert!(
            format!("{missing_peer:#}").contains("honk-no-such1"),
            "{missing_peer:#}"
        );
        // `lo` exists with a nonzero ifindex but an all-zero MAC.
        let zero_mac = Dae0Setup::read_links(&mut nl, "lo", "lo").expect_err("zero MAC must fail");
        assert!(format!("{zero_mac:#}").contains("MAC"), "{zero_mac:#}");
    }
}
