//! Rtnetlink watcher for configured interfaces and `auto` default routes.
//! Link, address, and route events reconcile late/recreated interfaces plus
//! LAN bridge/bond and WAN bond slaves against the process-owned TC links.

use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, socket,
};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc, watch};
use tracing::{debug, info, warn};

use crate::ebpf::{DynamicHooks, EbpfBackend, IfaceRole};

// A captive-portal login may add only a default route to an already-up link.
const RTMGRP_LINK_MASK: u32 = 1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;
const RTMGRP_NETWORK_MASK: u32 = RTMGRP_LINK_MASK
    | RTMGRP_IPV4_IFADDR
    | RTMGRP_IPV4_ROUTE
    | RTMGRP_IPV6_IFADDR
    | RTMGRP_IPV6_ROUTE;
const IFF_UP: u32 = 0x1;
// Events are a wakeup hint only — reconcile re-reads ground truth from
// /sys — but a dropped datagram would stall a pending interface forever,
// so a slow ticker backstops the subscription.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);
/// Attach state per interface name. Program role is part of the identity:
/// LAN ingress and WAN ingress occupy the same direction but are not
/// interchangeable when an `auto` route changes topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachedInterface {
    pub ifindex: u32,
    pub role: IfaceRole,
    pub hooks: DynamicHooks,
}

pub type AttachedMap = HashMap<String, AttachedInterface>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkState {
    default_interface: Option<String>,
    local_cidrs: Vec<String>,
}

pub struct IfaceWatcher {
    handle: tokio::task::JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl IfaceWatcher {
    /// `attached` seeds the names (with ifindex and directions) already
    /// hooked during startup so the first reconcile does not attach twice.
    pub(crate) fn spawn(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        config: Arc<RwLock<Arc<honk_config::Config>>>,
        commands: tokio::sync::mpsc::Sender<crate::control::ControlCommand>,
        attached: AttachedMap,
        degradations: Arc<crate::degradations::Degradations>,
    ) -> Option<Self> {
        let fd = match subscribe_network_events() {
            Ok(fd) => fd,
            Err(e) => {
                warn!(
                    "interface watcher disabled; subscribe network events failed: {}",
                    e
                );
                degradations.set(
                    crate::degradations::Component::IfaceWatch,
                    watcher_disabled("subscribe_failed"),
                );
                return None;
            }
        };
        let (stop, rx) = watch::channel(false);
        let handle = tokio::spawn(run(fd, ebpf, config, commands, attached, rx, degradations));
        Some(Self { handle, stop })
    }

    pub async fn shutdown(self, timeout: Duration) {
        let _ = self.stop.send(true);
        let mut handle = self.handle;
        // A watcher wedged mid-reconcile holds the backend write lock and
        // could re-attach hooks after detach_hooks — abort it rather than
        // drop the handle and leave the task running into teardown.
        if tokio::time::timeout(timeout, &mut handle).await.is_err() {
            handle.abort();
            let _ = (&mut handle).await;
        }
    }
}

fn watcher_disabled(reason: &'static str) -> crate::degradations::Issue {
    crate::degradations::Issue {
        code: "interface_watcher_disabled",
        message: "The interface watcher is not running; interface changes take effect after a restart.",
        reason,
    }
}

fn subscribe_network_events() -> std::io::Result<OwnedFd> {
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        Some(SockProtocol::NetlinkRoute),
    )
    .map_err(std::io::Error::from)?;
    bind(fd.as_raw_fd(), &NetlinkAddr::new(0, RTMGRP_NETWORK_MASK))
        .map_err(std::io::Error::from)?;
    Ok(fd)
}

async fn run(
    fd: OwnedFd,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    config: Arc<RwLock<Arc<honk_config::Config>>>,
    commands: tokio::sync::mpsc::Sender<crate::control::ControlCommand>,
    mut attached: AttachedMap,
    mut stop: watch::Receiver<bool>,
    degradations: Arc<crate::degradations::Degradations>,
) {
    let async_fd = match tokio::io::unix::AsyncFd::with_interest(fd, tokio::io::Interest::READABLE)
    {
        Ok(f) => f,
        Err(e) => {
            warn!("interface watcher disabled: AsyncFd setup failed: {}", e);
            degradations.set(
                crate::degradations::Component::IfaceWatch,
                watcher_disabled("poll_setup_failed"),
            );
            return;
        }
    };
    let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buf = [0u8; 8192];
    let mut network_state = read_network_state(&config).await;
    let mut pending_notification = true;
    let mut netlink_retry_at = tokio::time::Instant::now();

    // Interface-dependent state may have changed before the watcher was ready;
    // the control-plane refresh is content-deduplicated.
    reconcile_and_notify(
        &ebpf,
        &config,
        &commands,
        &mut attached,
        true,
        &mut pending_notification,
    )
    .await;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            permit = commands.reserve(), if pending_notification => {
                match permit {
                    Ok(permit) => { permit.send(crate::control::ControlCommand::NetworkChanged); }
                    Err(_) => debug!("control plane stopped before network-change refresh"),
                }
                pending_notification = false;
            }
            _ = ticker.tick() => {
                let changed = update_network_state(&config, &mut network_state).await;
                reconcile_and_notify(&ebpf, &config, &commands, &mut attached, changed, &mut pending_notification).await;
            }
            guard = async {
                tokio::time::sleep_until(netlink_retry_at).await;
                async_fd.readable().await
            } => {
                // A transient read failure (ENOBUFS after a burst) must not
                // kill the watcher: the ticker keeps reconciling regardless.
                let mut guard = match guard {
                    Ok(g) => g,
                    Err(e) => {
                        warn!("interface watcher: netlink wait failed: {}", e);
                        netlink_retry_at = tokio::time::Instant::now() + Duration::from_secs(1);
                        continue;
                    }
                };
                // Drain pending network events; their contents are irrelevant
                // because reconcile re-derives state from /sys and /proc.
                let drained = guard.try_io(|inner| {
                    // Bound a burst so stop and the ticker cannot starve behind netlink traffic.
                    for _ in 0..64 {
                        match recv(inner.as_raw_fd(), &mut buf, MsgFlags::empty()) {
                            Ok(_) => {}
                            Err(errno) => {
                                let e = std::io::Error::from(errno);
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    return Ok(true);
                                }
                                if e.kind() == std::io::ErrorKind::Interrupted {
                                    continue;
                                }
                                return Err(e);
                            }
                        }
                    }
                    Ok(false)
                });
                match drained {
                    Ok(Ok(drained)) => {
                        if drained {
                            guard.clear_ready();
                        }
                        let changed = update_network_state(&config, &mut network_state).await;
                        reconcile_and_notify(&ebpf, &config, &commands, &mut attached, changed, &mut pending_notification).await;
                    }
                    Ok(Err(e)) => {
                        warn!("interface watcher: netlink recv failed: {}", e);
                        netlink_retry_at = tokio::time::Instant::now() + Duration::from_secs(1);
                    }
                    // Spurious readiness; nothing was drained.
                    Err(_) => {}
                }
            }
        }
    }
    debug!("interface watcher stopped");
}

async fn read_network_state(config: &Arc<RwLock<Arc<honk_config::Config>>>) -> NetworkState {
    let config = config.read().await;
    NetworkState {
        default_interface: crate::detect_default_interface(),
        local_cidrs: config.local_direct_cidrs(),
    }
}

async fn update_network_state(
    config: &Arc<RwLock<Arc<honk_config::Config>>>,
    current: &mut NetworkState,
) -> bool {
    let next = read_network_state(config).await;
    if *current == next {
        return false;
    }
    *current = next;
    true
}

async fn reconcile_and_notify(
    ebpf: &Arc<RwLock<Box<dyn EbpfBackend>>>,
    config: &Arc<RwLock<Arc<honk_config::Config>>>,
    commands: &mpsc::Sender<crate::control::ControlCommand>,
    attached: &mut AttachedMap,
    network_state_changed: bool,
    pending_notification: &mut bool,
) {
    *pending_notification |= network_state_changed;
    match reconcile(ebpf, config, attached).await {
        Ok(changed) => *pending_notification |= changed,
        Err(_) => *pending_notification = true,
    }
    if *pending_notification {
        match commands.try_send(crate::control::ControlCommand::NetworkChanged) {
            Ok(()) => *pending_notification = false,
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                *pending_notification = false;
                debug!("control plane stopped before network-change refresh");
            }
        }
    }
}

async fn reconcile(
    ebpf: &Arc<RwLock<Box<dyn EbpfBackend>>>,
    config: &Arc<RwLock<Arc<honk_config::Config>>>,
    attached: &mut AttachedMap,
) -> anyhow::Result<bool> {
    let (desired, single_homed) = {
        let cfg = config.read().await;
        desired_interfaces(&cfg)
    };
    let wanted = |role: IfaceRole| match role {
        IfaceRole::Lan => DynamicHooks {
            ingress: true,
            egress: !single_homed,
        },
        IfaceRole::LanWan => DynamicHooks {
            ingress: true,
            egress: true,
        },
        IfaceRole::WanBondSlave => DynamicHooks {
            ingress: false,
            egress: true,
        },
        _ => DynamicHooks {
            ingress: true,
            egress: true,
        },
    };
    let mut changed = false;
    let mut attach_error = None;
    let mut backend = ebpf.write().await;
    // Forget tracked entries that vanished, were recreated (their hooks
    // died with the old ifindex), or are no longer wanted (un-enslaved,
    // removed from config).
    let tracked: Vec<(String, u32, IfaceRole)> = attached
        .iter()
        .map(|(name, state)| (name.clone(), state.ifindex, state.role))
        .collect();
    for (name, ifindex, role) in tracked {
        if desired.get(&name) != Some(&role)
            || crate::netlink::ifindex_of(&name).ok() != Some(ifindex)
        {
            backend.forget_dynamic_interface(ifindex);
            attached.remove(&name);
            changed = true;
        }
    }
    for (name, role) in desired {
        let want = wanted(role);
        let have = attached
            .get(&name)
            .map(|state| state.hooks)
            .unwrap_or_default();
        if have == want {
            continue;
        }
        let Ok(ifindex) = crate::netlink::ifindex_of(&name) else {
            continue;
        };
        if !iface_is_up(&name) {
            continue;
        }
        match backend.attach_dynamic_interface(&name, role, single_homed) {
            Ok(hooks) => {
                attached.insert(
                    name.clone(),
                    AttachedInterface {
                        ifindex,
                        role,
                        hooks,
                    },
                );
                if matches!(role, IfaceRole::Wan | IfaceRole::LanWan) {
                    crate::enable_wan_accept_ra(&name);
                }
                info!(interface = %name, role = ?role, "attached eBPF programs to new interface");
                changed = true;
            }
            Err(e) => {
                warn!(interface = %name, role = ?role, "dynamic attach failed: {}", e);
                attach_error
                    .get_or_insert_with(|| e.context(format!("attach {role:?} interface {name}")));
            }
        }
    }
    attach_error.map_or(Ok(changed), Err)
}

/// The configured interface set with roles, mirroring the startup logic in
/// `run()`: a shared LAN/WAN interface receives the single-homed program
/// pair, while an empty LAN list installs no LAN hooks.
fn desired_interfaces(config: &honk_config::Config) -> (HashMap<String, IfaceRole>, bool) {
    let crate::ConfiguredInterfaces {
        lan,
        wan,
        single_homed,
    } = crate::configured_interfaces(config);
    let mut desired = HashMap::new();
    for w in &wan {
        if !lan.contains(w) {
            desired.insert(w.clone(), IfaceRole::Wan);
        }
    }
    for l in &lan {
        let role = if single_homed && wan.contains(l) {
            IfaceRole::LanWan
        } else {
            IfaceRole::Lan
        };
        desired.insert(l.clone(), role);
    }
    // Bridge/bond slaves of configured LAN masters need their own hooks
    // (forwarded traffic bypasses the master's qdiscs); membership is
    // re-read on every reconcile so late-added containers are covered.
    for master in &lan {
        for slave in super::RealEbpfBackend::bridge_slaves(master) {
            desired.entry(slave).or_insert(IfaceRole::LanBridgeSlave);
        }
        for slave in super::RealEbpfBackend::bond_slaves(master) {
            desired.entry(slave).or_insert(IfaceRole::LanBondSlave);
        }
    }
    // A bond may emit host traffic directly on a slave. Re-expand membership
    // so WAN-only mode keeps intercepting slaves added after startup.
    for master in &wan {
        for slave in super::RealEbpfBackend::bond_slaves(master) {
            desired.entry(slave).or_insert(IfaceRole::WanBondSlave);
        }
    }
    (desired, single_homed)
}

fn iface_is_up(name: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|flags| flags & IFF_UP != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn watcher_fixture(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        config: Arc<RwLock<Arc<honk_config::Config>>>,
        commands: mpsc::Sender<crate::control::ControlCommand>,
        attached: AttachedMap,
    ) -> (IfaceWatcher, std::os::unix::net::UnixDatagram) {
        let (events, writer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        events.set_nonblocking(true).unwrap();
        let (stop, rx) = watch::channel(false);
        let handle = tokio::spawn(run(
            events.into(),
            ebpf,
            config,
            commands,
            attached,
            rx,
            Arc::default(),
        ));
        (IfaceWatcher { handle, stop }, writer)
    }

    #[tokio::test]
    async fn a_watcher_that_cannot_poll_is_reported() {
        let degradations = Arc::new(crate::degradations::Degradations::default());
        // epoll refuses regular files.
        let file = tempfile::tempfile().unwrap();
        let ebpf: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(
            crate::ebpf::mock::MockEbpfBackend::new(),
        )));
        let config = Arc::new(RwLock::new(Arc::new(honk_config::Config::default())));
        let (commands, _receiver) = mpsc::channel(1);
        let (_stop, rx) = watch::channel(false);
        run(
            file.into(),
            ebpf,
            config,
            commands,
            AttachedMap::default(),
            rx,
            Arc::clone(&degradations),
        )
        .await;
        assert_eq!(
            degradations
                .get(crate::degradations::Component::IfaceWatch)
                .map(|issue| issue.reason),
            Some("poll_setup_failed")
        );
    }

    #[test]
    fn wan_only_configuration_does_not_synthesize_loopback_lan() {
        let mut config = honk_config::Config::default();
        config.global.wan_interface = vec!["wan0".to_string()];

        let (desired, single_homed) = desired_interfaces(&config);

        assert!(!single_homed);
        assert_eq!(desired.len(), 1);
        assert_eq!(desired.get("wan0"), Some(&IfaceRole::Wan));
        assert!(!desired.contains_key("lo"));
    }

    #[test]
    fn unresolved_auto_is_omitted_without_losing_explicit_interfaces() {
        let configured = vec![
            "auto".to_string(),
            "campus0".to_string(),
            "campus0".to_string(),
        ];

        assert_eq!(
            crate::resolve_configured_interface_names(&configured, None),
            vec!["campus0"]
        );
        assert_eq!(
            crate::resolve_configured_interface_names(&configured, Some("eth0")),
            vec!["eth0", "campus0"]
        );
    }

    #[test]
    fn default_route_parser_waits_for_a_real_default_and_uses_lowest_metric() {
        let header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n";
        let no_default = format!("{header}campus0 0000A8C0 00000000 0001 0 0 10 00FFFFFF 0 0 0\n");
        assert_eq!(
            honk_config::config::default_route_interface_from(&no_default),
            None
        );

        let routes = format!(
            "{header}ethernet0 00000000 00000000 0003 0 0 600 00000000 0 0 0\n\
             wifi0 00000000 00000000 0003 0 0 100 00000000 0 0 0\n"
        );
        assert_eq!(
            honk_config::config::default_route_interface_from(&routes).as_deref(),
            Some("wifi0")
        );
    }

    #[test]
    fn same_interface_uses_single_homed_role() {
        let mut config = honk_config::Config::default();
        config.global.lan_interface = vec!["campus0".to_string()];
        config.global.wan_interface = vec!["campus0".to_string()];

        let (desired, single_homed) = desired_interfaces(&config);

        assert!(single_homed);
        assert_eq!(desired.get("campus0"), Some(&IfaceRole::LanWan));
    }

    #[tokio::test]
    async fn role_change_forgets_incompatible_hooks_before_rebind() {
        let backend = crate::ebpf::mock::MockEbpfBackend::new();
        let attach = backend.dynamic_attach_calls.clone();
        let forget = backend.dynamic_forget_calls.clone();
        let ebpf: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(backend)));
        let mut config = honk_config::Config::default();
        config.global.lan_interface = vec!["lo".to_string()];
        let config = Arc::new(RwLock::new(Arc::new(config)));
        let mut attached = AttachedMap::new();

        assert!(reconcile(&ebpf, &config, &mut attached).await.unwrap());
        let first = attach.load(Ordering::Relaxed);
        {
            let mut config = config.write().await;
            Arc::make_mut(&mut config).global.wan_interface = vec!["lo".to_string()];
        }
        assert!(reconcile(&ebpf, &config, &mut attached).await.unwrap());

        assert_eq!(forget.load(Ordering::Relaxed), 1);
        assert_eq!(attach.load(Ordering::Relaxed), first + 1);
        assert_eq!(
            attached.get("lo").map(|state| state.role),
            Some(IfaceRole::LanWan)
        );
        assert!(!reconcile(&ebpf, &config, &mut attached).await.unwrap());
    }

    #[tokio::test]
    async fn topology_or_network_event_requests_refresh() {
        let backend = crate::ebpf::mock::MockEbpfBackend::new();
        let ebpf: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(backend)));
        let mut config = honk_config::Config::default();
        config.global.lan_interface = vec!["lo".to_string()];
        let config = Arc::new(RwLock::new(Arc::new(config)));
        let mut attached = AttachedMap::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let mut pending_notification = false;
        reconcile_and_notify(
            &ebpf,
            &config,
            &tx,
            &mut attached,
            false,
            &mut pending_notification,
        )
        .await;
        assert!(matches!(
            rx.try_recv(),
            Ok(crate::control::ControlCommand::NetworkChanged)
        ));

        reconcile_and_notify(
            &ebpf,
            &config,
            &tx,
            &mut attached,
            false,
            &mut pending_notification,
        )
        .await;
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        reconcile_and_notify(
            &ebpf,
            &config,
            &tx,
            &mut attached,
            true,
            &mut pending_notification,
        )
        .await;
        assert!(matches!(
            rx.try_recv(),
            Ok(crate::control::ControlCommand::NetworkChanged)
        ));
    }

    #[tokio::test]
    async fn full_control_queue_retains_hint_and_shutdown_joins_the_worker() {
        tokio::time::timeout(Duration::from_secs(1), async {
            let backend = crate::ebpf::mock::MockEbpfBackend::new();
            let ebpf: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(backend)));
            let retained_backend = Arc::downgrade(&ebpf);
            let mut config = honk_config::Config::default();
            config.global.lan_interface = vec!["lo".to_string()];
            let config = Arc::new(RwLock::new(Arc::new(config)));
            let (tx, mut rx) = mpsc::channel(1);
            tx.try_send(crate::control::ControlCommand::NetworkChanged)
                .unwrap();
            let (watcher, _events) = watcher_fixture(ebpf, config, tx, AttachedMap::new());

            // Freeing capacity must deliver the startup hint the full queue held back.
            assert!(matches!(
                rx.recv().await,
                Some(crate::control::ControlCommand::NetworkChanged)
            ));
            assert!(matches!(
                rx.recv().await,
                Some(crate::control::ControlCommand::NetworkChanged)
            ));
            watcher.shutdown(Duration::from_secs(1)).await;
            assert!(
                retained_backend.upgrade().is_none(),
                "shutdown must join the retained worker"
            );
        })
        .await
        .expect("watcher did not deliver the retained hint or join on shutdown");
    }

    #[test]
    #[ignore = "requires root; run via just test-netns"]
    fn route_only_change_wakes_network_subscription() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        std::thread::spawn(|| {
            let rc = unsafe { libc::unshare(libc::CLONE_NEWNET) };
            assert_eq!(rc, 0, "unshare: {}", std::io::Error::last_os_error());

            let mut netlink = crate::netlink::NlSock::new().expect("netlink socket");
            let loopback = crate::netlink::ifindex_of("lo").expect("loopback ifindex");
            netlink
                .set_link_up(loopback, true)
                .expect("bring loopback up");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("tokio runtime");

            runtime.block_on(async move {
                let events = subscribe_network_events().expect("network event subscription");
                let events = tokio::io::unix::AsyncFd::new(events).expect("async netlink socket");
                netlink
                    .add_route(
                        crate::netlink::FAM_V4,
                        254,
                        crate::netlink::ROUTE_UNICAST,
                        crate::netlink::SCOPE_LINK,
                        crate::netlink::PROTO_STATIC,
                        None,
                        None,
                        Some(loopback),
                    )
                    .expect("add default route");

                let _ready = tokio::time::timeout(Duration::from_secs(1), events.readable())
                    .await
                    .expect("route event timeout")
                    .expect("route event readiness");
            });
        })
        .join()
        .expect("network namespace thread");
    }

    /// An unchanged topology keeps the original hooks: the ticker must not
    /// churn working TC links merely because it reconciles periodically.
    #[tokio::test]
    async fn reconcile_reuses_unchanged_hooks() {
        let backend = crate::ebpf::mock::MockEbpfBackend::new();
        let attach = backend.dynamic_attach_calls.clone();
        let detach = backend.detach_calls.clone();
        let ebpf: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(backend)));
        let mut config = honk_config::Config::default();
        config.global.lan_interface = vec!["lo".to_string()];
        let config = Arc::new(RwLock::new(Arc::new(config)));
        let mut attached = AttachedMap::new();

        reconcile(&ebpf, &config, &mut attached).await.unwrap();
        let first = attach.load(Ordering::Relaxed);
        assert!(first >= 1, "first reconcile attaches the configured LAN");
        assert_eq!(detach.load(Ordering::Relaxed), 0);

        reconcile(&ebpf, &config, &mut attached).await.unwrap();
        assert_eq!(
            attach.load(Ordering::Relaxed),
            first,
            "second reconcile must not re-attach"
        );
        assert_eq!(
            detach.load(Ordering::Relaxed),
            0,
            "unchanged reconcile must not detach"
        );
    }
}
