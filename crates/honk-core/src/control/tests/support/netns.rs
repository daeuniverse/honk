use super::super::{fresh_test_netns, wait_for_test_address};
use super::udp_test_config;
use aya::maps::{Map, MapData};
use honk_config::node::{Group, Node};
use honk_outbound::proxy::{ProxyStream, TcpOutbound};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use std::mem::size_of;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

/// The only fixture in a transparent TCP lab: a real bypass-marked dial from the
/// router namespace. Ingress, listener, routing and relay stay production.
#[derive(Debug)]
pub(in crate::control::tests) struct KernelTcpDial;

#[async_trait::async_trait]
impl TcpOutbound for KernelTcpDial {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let stream = honk_outbound::util::connect_marked_addr(
            target,
            Some(honk_outbound::util::bypass_mark()),
            connect_timeout,
        )
        .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

/// Process-lifetime state (DAENS_FD) cannot be reset, so each case runs `child` in a
/// fresh process: the parent re-executes `test` once per case with `env` set to it.
pub(in crate::control::tests) fn run_isolated(
    test: &str,
    env: &str,
    cases: impl IntoIterator<Item = impl AsRef<str>>,
    child: fn(&str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if let Some(case) = std::env::var_os(env) {
        let case = case
            .into_string()
            .map_err(|_| anyhow::anyhow!("invalid child case"))?;
        return std::thread::spawn(move || child(&case))
            .join()
            .map_err(|_| anyhow::anyhow!("{test} child panicked"))?;
    }
    for case in cases {
        let case = case.as_ref();
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                test,
                "--ignored",
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(env, case)
            .status()?;
        anyhow::ensure!(status.success(), "{test} {case}: {status}");
    }
    Ok(())
}

/// Enters private net/mount namespaces with their own sysfs, bpffs and cgroup2.
pub(in crate::control::tests) fn enter_lab_namespaces() -> anyhow::Result<()> {
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

/// Enters private net/mount namespaces and wires the LAN and WAN veth edges.
pub(in crate::control::tests) fn build_lab(
    lan_ip: IpAddr,
    wan_ip: IpAddr,
) -> anyhow::Result<(OwnedFd, OwnedFd)> {
    enter_lab_namespaces()?;
    let client_netns = fresh_test_netns();
    let server_netns = fresh_test_netns();
    let mut netlink = crate::netlink::NlSock::new()?;
    let (lo, _) = netlink.get_link("lo")?;
    netlink.set_link_up(lo, true)?;
    for (host, edge, namespace, ip) in [
        ("honk-lan0", "honk-c0", &client_netns, lan_ip),
        ("honk-wan0", "honk-s0", &server_netns, wan_ip),
    ] {
        netlink.add_veth_pair(host, edge)?;
        let (edge_index, _) = netlink.get_link(edge)?;
        netlink.set_link_netns_fd(edge_index, namespace)?;
        let (host_index, _) = netlink.get_link(host)?;
        netlink.set_link_up(host_index, true)?;
        add_address(&mut netlink, host_index, host, ip)?;
    }
    Ok((client_netns, server_netns))
}

/// Real-datapath config whose only route is the group holding `node`.
pub(in crate::control::tests) fn lab_config(node: &honk_config::node::Node) -> honk_config::Config {
    let group = Group {
        name: "fullcone".into(),
        nodes: vec![node.id],
        ..Default::default()
    };
    let mut config = udp_test_config("fullcone", vec![node.clone()], vec![group]);
    config.ensure_builtin_nodes();
    config.global.lan_interface = vec!["honk-lan0".into()];
    config.global.wan_interface = vec!["honk-wan0".into()];
    config.global.dial_mode = "ip".into();
    config.global.nfqueue_enable = false;
    config.global.preconnect_node_count = 0;
    config.global.udp_warm_node_count = 0;
    config.global.store_subscribe = false;
    config.experimental.cache_file.enabled = Some(false);
    config.global.tcp_check_url.clear();
    config.global.udp_check_dns.clear();
    config.dns.bind.clear();
    config
}

pub(in crate::control::tests) fn add_address(
    netlink: &mut crate::netlink::NlSock,
    index: u32,
    name: &str,
    ip: IpAddr,
) -> anyhow::Result<()> {
    match ip {
        IpAddr::V4(ip) => netlink.addr_op(true, index, libc::AF_INET as u8, &ip.octets(), 24)?,
        IpAddr::V6(ip) => {
            std::fs::write("/proc/sys/net/ipv6/conf/all/accept_dad", "0")?;
            std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/accept_dad"), "0")?;
            netlink.addr_op(true, index, libc::AF_INET6 as u8, &ip.octets(), 64)?;
        }
    }
    wait_for_test_address(ip);
    Ok(())
}

pub(in crate::control::tests) fn pinned_map(root: &Path, name: &str) -> anyhow::Result<Map> {
    Ok(Map::from_map_data(MapData::from_pin(root.join(name))?)?)
}

/// The kernel's key for `source -> destination`, as the control plane builds it.
pub(in crate::control::tests) fn tuples_key(
    source: SocketAddr,
    destination: SocketAddr,
    proto: u8,
) -> honk_ebpf_common::TuplesKey {
    crate::control::connection::build_tuples_key(
        destination.ip(),
        destination.port(),
        source.ip(),
        source.port(),
        proto,
    )
}

/// Bucket-protected copies for external readers that cannot exclude userspace tuple
/// retirement. Never fall back to GET_NEXT_KEY plus singleton LOOKUP_ELEM, even for
/// values that look immutable.
pub(in crate::control::tests) fn pinned_hash_snapshot<K: aya::Pod, V: aya::Pod>(
    root: &Path,
    name: &str,
    elem_flags: u64,
) -> anyhow::Result<Vec<(K, V)>> {
    let data = MapData::from_pin(root.join(name))?;
    let info = data.info()?;
    anyhow::ensure!(
        info.map_type()? == aya::maps::MapType::Hash
            && info.key_size() as usize == size_of::<K>()
            && info.value_size() as usize == size_of::<V>(),
        "unexpected pinned hash layout for {name}"
    );
    let mut snapshot = Vec::new();
    crate::ebpf::real::syscall::scan_lookup_batch::<K, V>(
        data.fd().as_fd().as_raw_fd(),
        name,
        elem_flags,
        None,
        &mut None,
        &mut |chunk| {
            snapshot.extend_from_slice(chunk);
            true
        },
    )
    .map_err(|error| {
        error.context(format!(
            "safe pinned snapshot of {name} requires BPF_MAP_LOOKUP_BATCH (elem_flags={elem_flags})"
        ))
    })?;
    Ok(snapshot)
}
