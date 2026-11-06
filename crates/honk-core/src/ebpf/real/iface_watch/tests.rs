use super::*;
use crate::degradations::{Component, Degradations};
use crate::ebpf::interface::{Binding, Direction, TcProgram};
use crate::ebpf::real::interface_state::SysctlKey;
use crate::ebpf::test_support::link;
use crate::netlink::LinkSnapshot;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Fixed topology: no `lo`, no kernel.
fn topology() -> Topology {
    Topology {
        links: vec![link(2, "eth0"), link(3, "eth1")],
        default_route: None,
    }
}

fn fake_fd() -> OwnedFd {
    std::fs::File::open("/dev/null").unwrap().into()
}

/// A kernel-free `apply` with the same contract: diff by `(ifindex,
/// direction)`, reprogram in place, report what could not be bound.
fn model_apply(
    snapshot: BindingSnapshot,
    plan: &InterfacePlan,
    fail_egress: bool,
    topology_changed: bool,
) -> ApplyReport {
    let mut report = ApplyReport {
        topology_changed,
        ..ApplyReport::default()
    };
    for (held, ..) in &snapshot.owned {
        if !plan.bindings.iter().any(|b| b.key() == held.key()) {
            report.commit.remove.push(held.key());
        }
    }
    for binding in &plan.bindings {
        match snapshot
            .owned
            .iter()
            .find(|(held, ..)| held.key() == binding.key())
        {
            None if fail_egress && binding.direction == Direction::Egress => report
                .failed
                .push((binding.clone(), anyhow::anyhow!("injected attach failure"))),
            None => {
                report
                    .commit
                    .add
                    .push((binding.clone(), binding.ifindex.get() * 10, fake_fd()))
            }
            Some((held, ..)) => {
                if held.interface != binding.interface {
                    report.commit.rename.push((
                        binding.ifindex,
                        binding.direction,
                        binding.interface.clone(),
                    ))
                }
                if held.program != binding.program {
                    report.commit.reprogram.push((
                        binding.ifindex,
                        binding.direction,
                        binding.program,
                    ))
                }
            }
        }
    }
    report
}

#[derive(Clone, Default)]
struct Stub {
    fail_egress: Arc<AtomicBool>,
    /// Report `topology_changed` on every apply.
    moving: Arc<AtomicBool>,
    applies: Arc<AtomicU64>,
    fail_topology: Arc<AtomicBool>,
    /// Replaces the fixed topology.
    links: Arc<parking_lot::Mutex<Option<Topology>>>,
    /// What the stub sysctl step was asked to write, in order.
    sysctl: Arc<parking_lot::Mutex<Vec<(SysctlKey, String)>>>,
    /// Sysctl writes that fail (counted as attempted all the same).
    fail_sysctl: Arc<AtomicBool>,
    interval: Option<Duration>,
}

impl Stub {
    fn reconciler(&self) -> Reconciler {
        let (fail, count, moving) = (
            self.fail_egress.clone(),
            self.applies.clone(),
            self.moving.clone(),
        );
        let fail_topology = self.fail_topology.clone();
        let (links, sysctl, fail_sysctl) = (
            self.links.clone(),
            self.sysctl.clone(),
            self.fail_sysctl.clone(),
        );
        Reconciler {
            read_topology: Arc::new(move |_| {
                anyhow::ensure!(
                    !fail_topology.load(Ordering::SeqCst),
                    "injected topology failure"
                );
                Ok(links.lock().clone().unwrap_or_else(topology))
            }),
            apply: Arc::new(move |snapshot, plan, _, _| {
                count.fetch_add(1, Ordering::SeqCst);
                model_apply(
                    snapshot,
                    plan,
                    fail.load(Ordering::SeqCst),
                    moving.load(Ordering::SeqCst),
                )
            }),
            sysctl: Arc::new(move |write| {
                sysctl.lock().push((write.key, write.name.clone()));
                anyhow::ensure!(
                    !fail_sysctl.load(Ordering::SeqCst),
                    "injected sysctl failure"
                );
                Ok(())
            }),
            // Never fires inside a test that does not ask for it.
            interval: self.interval.unwrap_or(Duration::from_secs(3600)),
        }
    }
}

struct Fixture {
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    config: Arc<RwLock<Arc<honk_config::Config>>>,
    commits: Arc<AtomicU64>,
    degradations: Arc<Degradations>,
    stub: Stub,
}

fn fixture(lan: &[&str], wan: &[&str]) -> Fixture {
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let commits = backend.binding_commits.clone();
    let mut config = honk_config::Config::default();
    config.global.lan_interface = lan.iter().map(|name| name.to_string()).collect();
    config.global.wan_interface = wan.iter().map(|name| name.to_string()).collect();
    Fixture {
        ebpf: Arc::new(RwLock::new(Box::new(backend))),
        config: Arc::new(RwLock::new(Arc::new(config))),
        commits,
        degradations: Arc::default(),
        stub: Stub::default(),
    }
}

impl Fixture {
    fn watch(&self) -> (Watch, mpsc::Receiver<crate::control::ControlCommand>) {
        let (tx, rx) = mpsc::channel(4);
        let watch = Watch::new(
            self.ebpf.clone(),
            self.config.clone(),
            tx,
            self.stub.reconciler(),
            self.degradations.clone(),
            InterfaceState::default(),
        );
        (watch, rx)
    }

    /// Every held binding with its link id.
    async fn bindings(&self) -> Vec<(Binding, u32)> {
        self.ebpf
            .read()
            .await
            .interface_binding_snapshot()
            .unwrap()
            .owned
            .into_iter()
            .map(|(b, id, _)| (b, id))
            .collect()
    }

    async fn owned(&self) -> Vec<(u32, Direction, TcProgram)> {
        let mut owned: Vec<_> = (self.bindings().await)
            .into_iter()
            .map(|(b, _)| (b.ifindex.get(), b.direction, b.program))
            .collect();
        owned.sort();
        owned
    }

    async fn set_interfaces(&self, lan: &[&str], wan: &[&str]) {
        let mut config = self.config.write().await;
        let global = &mut Arc::make_mut(&mut config).global;
        global.lan_interface = lan.iter().map(|name| name.to_string()).collect();
        global.wan_interface = wan.iter().map(|name| name.to_string()).collect();
    }
}

#[test]
fn link_messages_are_recognised_inside_a_datagram() {
    let message = |kind: u16, length: u32| {
        let mut bytes = vec![0u8; (length as usize).max(16)];
        bytes[0..4].copy_from_slice(&length.to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes
    };
    // RTM_NEWROUTE (24) then RTM_NEWADDR (20): no link message.
    let mut datagram = message(24, 30);
    datagram.resize(32, 0);
    datagram.extend(message(20, 24));
    assert!(!has_link_message(&datagram));
    // A link message behind a padded route message is still found.
    datagram.extend(message(RTM_DELLINK, 16));
    assert!(has_link_message(&datagram));
    assert!(has_link_message(&message(RTM_NEWLINK, 16)));
    // A malformed length ends the scan instead of looping.
    assert!(!has_link_message(&message(24, 0)));
    assert!(!has_link_message(&[]));
}

#[test]
fn only_link_events_and_overruns_force_verification() {
    assert!(!Drained::default().verify());
    assert!(
        Drained {
            link_event: true,
            ..Drained::default()
        }
        .verify()
    );
    assert!(
        Drained {
            overrun: true,
            ..Drained::default()
        }
        .verify()
    );
}

/// Without a usable subscription (none at all, or one epoll refuses) the watcher
/// still reconciles on its ticker, so a device that appears later is bound.
#[tokio::test]
async fn a_watcher_without_a_working_subscription_keeps_reconciling_on_its_ticker() {
    for epoll_refuses in [false, true] {
        let mut f = fixture(&["eth1"], &[]);
        f.stub.interval = Some(Duration::from_millis(20));
        *f.stub.links.lock() = Some(Topology {
            links: vec![link(2, "eth0")],
            default_route: None,
        });
        // epoll refuses regular files.
        let subscription = epoll_refuses.then(|| tempfile::tempfile().unwrap().into());
        let (commands, _receiver) = mpsc::channel(1);
        let (stop, rx) = watch::channel(false);
        let handle = tokio::spawn(run(
            subscription,
            f.ebpf.clone(),
            f.config.clone(),
            commands,
            rx,
            f.degradations.clone(),
            InterfaceState::default(),
            f.stub.reconciler(),
        ));
        let watcher = IfaceWatcher { handle, stop };

        wait_for(|| {
            f.degradations
                .get(Component::InterfaceBinding)
                .is_some_and(|issue| issue.reason == "pending")
        })
        .await;
        assert!(f.owned().await.is_empty());
        *f.stub.links.lock() = Some(Topology {
            links: vec![link(2, "eth0"), link(3, "eth1")],
            default_route: None,
        });
        wait_for(|| f.degradations.get(Component::InterfaceBinding).is_none()).await;
        assert_eq!(f.owned().await.len(), 2, "bound by the ticker alone");
        assert_eq!(
            f.degradations
                .get(Component::IfaceWatch)
                .map(|issue| issue.reason),
            epoll_refuses.then_some("poll_setup_failed")
        );
        watcher.shutdown(Duration::from_secs(1)).await;
    }
}

async fn wait_for(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("condition not reached");
}

/// A write that fails still counts: an IPv6-disabled host must not respawn
/// `sysctl -w` every tick. A recreated device (new ifindex) is written again,
/// and the write does not wait for the device to bind.
#[tokio::test]
async fn sysctl_is_written_on_sight_attempted_once_and_again_for_a_recreated_device() {
    let f = fixture(&["eth0"], &["eth1"]);
    f.stub.fail_sysctl.store(true, Ordering::SeqCst);
    f.stub.fail_egress.store(true, Ordering::SeqCst);
    let (mut watch, _rx) = f.watch();
    for _ in 0..3 {
        assert!(watch.reconcile(false).await.is_err(), "egress cannot bind");
    }
    assert_eq!(
        *f.stub.sysctl.lock(),
        [
            (SysctlKey::AcceptRa, "eth1".to_string()),
            (SysctlKey::RpFilter, "eth0".to_string()),
        ],
        "attempted once each, although every write failed and no egress bound"
    );

    // eth1 comes back with another ifindex.
    *f.stub.links.lock() = Some(Topology {
        links: vec![link(2, "eth0"), link(9, "eth1")],
        default_route: None,
    });
    let _ = watch.reconcile(false).await;
    assert_eq!(f.stub.sysctl.lock().len(), 3);
    assert_eq!(
        f.stub.sysctl.lock()[2],
        (SysctlKey::AcceptRa, "eth1".to_string())
    );
}

/// A device's own udev run puts the distribution sysctl default back right
/// after our first write: the watcher writes once more about a second later
/// by itself (the 60 s ticker and no event would leave it lost), then stops.
#[tokio::test]
async fn sysctl_is_written_again_after_udev_without_waiting_for_the_ticker() {
    let mut f = fixture(&["eth0"], &["eth1"]);
    f.stub.interval = Some(Duration::from_secs(60));
    let (commands, _receiver) = mpsc::channel(1);
    let (stop, rx) = watch::channel(false);
    let handle = tokio::spawn(run(
        None,
        f.ebpf.clone(),
        f.config.clone(),
        commands,
        rx,
        f.degradations.clone(),
        InterfaceState::default(),
        f.stub.reconciler(),
    ));
    let watcher = IfaceWatcher { handle, stop };
    let writes = |key| {
        f.stub
            .sysctl
            .lock()
            .iter()
            .filter(|(k, _)| *k == key)
            .count()
    };
    wait_for(|| writes(SysctlKey::RpFilter) == 2 && writes(SysctlKey::AcceptRa) == 2).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        (writes(SysctlKey::RpFilter), writes(SysctlKey::AcceptRa)),
        (2, 2),
        "twice per ifindex, then left alone"
    );
    watcher.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn degradation_follows_the_configured_entries() {
    let f = fixture(&["eth0", "gone"], &["lo"]);
    let reason = || {
        f.degradations
            .get(Component::InterfaceBinding)
            .map(|i| i.reason)
    };
    let (mut watch, _rx) = f.watch();
    let with = |links: Vec<LinkSnapshot>| {
        *f.stub.links.lock() = Some(Topology {
            links,
            default_route: None,
        });
    };
    let loopback = || {
        let mut lo = link(1, "lo");
        lo.arphrd = 772;
        lo
    };

    // Absent entries are pending.
    with(vec![link(2, "eth0")]);
    watch.reconcile(false).await.unwrap();
    assert_eq!(reason(), Some("pending"));
    // A refused entry outranks pending.
    with(vec![loopback(), link(2, "eth0")]);
    watch.reconcile(false).await.unwrap();
    assert_eq!(reason(), Some("unsupported_type"));
    // An attach failure outranks both.
    f.stub.fail_egress.store(true, Ordering::SeqCst);
    with(vec![loopback(), link(2, "eth0"), link(3, "gone")]);
    assert!(watch.reconcile(false).await.is_err());
    assert_eq!(reason(), Some("attach_failed"));
    f.stub.fail_egress.store(false, Ordering::SeqCst);
    watch.reconcile(false).await.unwrap();
    assert_eq!(reason(), Some("unsupported_type"));
    // Dropping the refused entry from the configuration clears the degradation.
    f.set_interfaces(&["eth0", "gone"], &[]).await;
    watch.reconcile(false).await.unwrap();
    assert_eq!(reason(), None);
    // The device goes away again: pending, and its links are released.
    with(vec![link(2, "eth0")]);
    watch.reconcile(true).await.unwrap();
    assert_eq!(reason(), Some("pending"));
    assert_eq!(f.owned().await.len(), 2, "only eth0 stays bound");
    // The issue text names nothing the operator configured.
    let issue = f.degradations.get(Component::InterfaceBinding).unwrap();
    assert!(!issue.message.contains("gone") && !issue.message.contains("eth0"));
}

/// A stage that fails as a whole says nothing about the entries: the bindings
/// and the degradation stay as they were, and the failure is retried.
#[tokio::test]
async fn a_failed_stage_leaves_the_degradation_and_bindings_alone() {
    let f = fixture(&["eth0", "gone"], &[]);
    let (mut watch, _rx) = f.watch();
    watch.reconcile(false).await.unwrap();
    let held = f.owned().await;
    let pending = Some("pending");
    let reason = || {
        f.degradations
            .get(Component::InterfaceBinding)
            .map(|i| i.reason)
    };
    assert_eq!(reason(), pending);

    f.stub.fail_topology.store(true, Ordering::SeqCst);
    for _ in 0..2 {
        assert!(watch.reconcile(true).await.is_err());
    }
    assert_eq!((reason(), f.owned().await), (pending, held.clone()));
    f.stub.fail_topology.store(false, Ordering::SeqCst);

    // Unsupported nesting refuses only that entry; the ordinary LAN stays bound.
    let mut a = link(10, "a");
    a.kind = Some("bond".into());
    a.master = NonZeroU32::new(11);
    let mut b = link(11, "b");
    b.kind = Some("bridge".into());
    b.master = NonZeroU32::new(10);
    *f.stub.links.lock() = Some(Topology {
        links: vec![link(2, "eth0"), a, b],
        default_route: None,
    });
    f.set_interfaces(&["eth0", "a"], &[]).await;
    watch.reconcile(true).await.unwrap();
    assert_eq!(
        (reason(), f.owned().await),
        (Some("unsupported_type"), held)
    );
}

#[tokio::test]
async fn a_failed_retry_keeps_the_committed_rounds_degradation() {
    for failing_step in [ReconcileStep::Topology, ReconcileStep::Join] {
        let f = fixture(&["eth0"], &[]);
        f.stub.fail_egress.store(true, Ordering::SeqCst);
        f.stub.moving.store(true, Ordering::SeqCst);
        let (mut watch, _rx) = f.watch();
        let applies = f.stub.applies.clone();
        watch.reconciler.read_topology = Arc::new(move |_| {
            if applies.load(Ordering::SeqCst) == 0 {
                return Ok(topology());
            }
            match failing_step {
                ReconcileStep::Topology => anyhow::bail!("retry dump failed"),
                ReconcileStep::Join => panic!("retry task panicked"),
                ReconcileStep::Snapshot => unreachable!(),
            }
        });

        assert!(watch.reconcile(true).await.is_err());
        assert_eq!(f.stub.applies.load(Ordering::SeqCst), 1);
        assert_eq!(f.commits.load(Ordering::SeqCst), 1);
        assert_eq!(
            f.owned().await,
            [(2, Direction::Ingress, TcProgram::LanIngressL2)]
        );
        assert_eq!(
            f.degradations
                .get(Component::InterfaceBinding)
                .map(|i| i.reason),
            Some("attach_failed"),
            "{failing_step:?} failed only after the partial bind committed"
        );

        watch.reconciler.read_topology = f.stub.reconciler().read_topology;
        f.stub.fail_egress.store(false, Ordering::SeqCst);
        f.stub.moving.store(false, Ordering::SeqCst);
        assert!(watch.reconcile(true).await.unwrap());
        assert!(f.degradations.get(Component::InterfaceBinding).is_none());
    }
}

#[tokio::test]
async fn renamed_port_commit_requests_network_refresh() {
    let f = fixture(&["br0"], &[]);
    let topology_with_port = |port: &str| Topology {
        links: vec![
            LinkSnapshot {
                kind: Some("bridge".into()),
                ..link(10, "br0")
            },
            LinkSnapshot {
                master: NonZeroU32::new(10),
                ..link(11, port)
            },
        ],
        default_route: None,
    };
    *f.stub.links.lock() = Some(topology_with_port("p1"));
    let (mut watch, mut rx) = f.watch();
    watch.reconcile(false).await.unwrap();
    watch.pending_notification = false;
    let commits = f.commits.load(Ordering::Relaxed);

    *f.stub.links.lock() = Some(topology_with_port("p1x"));
    watch.reconcile_and_notify(false, false).await;
    assert!(matches!(
        rx.try_recv(),
        Ok(crate::control::ControlCommand::NetworkChanged)
    ));
    assert_eq!(f.commits.load(Ordering::Relaxed), commits + 1);
    watch.reconcile_and_notify(false, false).await;
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn attach_failure_ends_when_interface_is_no_longer_configured() {
    let f = fixture(&["eth0"], &[]);
    f.stub.fail_egress.store(true, Ordering::SeqCst);
    let (mut watch, _rx) = f.watch();

    assert!(watch.reconcile(false).await.is_err());
    f.set_interfaces(&[], &[]).await;
    watch.reconcile(false).await.unwrap();
    assert!(f.degradations.get(Component::InterfaceBinding).is_none());
    assert!(f.owned().await.is_empty(), "removed from config, released");
}

#[tokio::test]
async fn a_moving_topology_is_retried_once_per_batch() {
    let f = fixture(&["eth0"], &[]);
    f.stub.moving.store(true, Ordering::SeqCst);
    let (mut watch, _rx) = f.watch();
    watch.reconcile(false).await.unwrap();
    assert_eq!(f.stub.applies.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn topology_or_network_event_requests_refresh() {
    let f = fixture(&["eth0"], &[]);
    let (mut watch, mut rx) = f.watch();
    watch.pending_notification = false;

    watch.reconcile_and_notify(false, false).await;
    assert!(matches!(
        rx.try_recv(),
        Ok(crate::control::ControlCommand::NetworkChanged)
    ));

    watch.reconcile_and_notify(false, false).await;
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    watch.reconcile_and_notify(true, false).await;
    assert!(matches!(
        rx.try_recv(),
        Ok(crate::control::ControlCommand::NetworkChanged)
    ));
}

/// An unchanged topology keeps the original hooks: the ticker must not
/// churn working TC links merely because it reconciles periodically.
#[tokio::test]
async fn reconcile_reuses_unchanged_hooks() {
    let f = fixture(&["eth0"], &[]);
    let (mut watch, _rx) = f.watch();

    watch.reconcile(false).await.unwrap();
    let first = f.commits.load(Ordering::Relaxed);
    assert_eq!(first, 1, "first reconcile binds the configured LAN");

    for verify in [false, true] {
        assert!(!watch.reconcile(verify).await.unwrap());
    }
    assert_eq!(
        f.commits.load(Ordering::Relaxed),
        first,
        "unchanged reconcile must not take the write lock"
    );
}

fn watcher_fixture(
    f: &Fixture,
    commands: mpsc::Sender<crate::control::ControlCommand>,
    reconciler: Reconciler,
) -> (IfaceWatcher, std::os::unix::net::UnixDatagram) {
    let (events, writer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    events.set_nonblocking(true).unwrap();
    let (stop, rx) = watch::channel(false);
    let handle = tokio::spawn(run(
        Some(events.into()),
        f.ebpf.clone(),
        f.config.clone(),
        commands,
        rx,
        Arc::default(),
        InterfaceState::default(),
        reconciler,
    ));
    (IfaceWatcher { handle, stop }, writer)
}

#[tokio::test]
async fn full_control_queue_retains_hint_and_shutdown_joins_the_worker() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let f = fixture(&["eth0"], &[]);
        let retained_backend = Arc::downgrade(&f.ebpf);
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(crate::control::ControlCommand::NetworkChanged)
            .unwrap();
        let (watcher, _events) = watcher_fixture(&f, tx, f.stub.reconciler());
        let Fixture { ebpf, .. } = f;
        drop(ebpf);

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

/// Shutdown never aborts a batch whose blocking thread holds link FDs: it
/// keeps waiting (and warning) until the apply returns.
#[tokio::test]
async fn shutdown_waits_for_an_in_flight_apply() {
    let f = fixture(&["eth0"], &[]);
    let entered = Arc::new(AtomicBool::new(false));
    let (release, gate) = std::sync::mpsc::channel::<()>();
    let gate = Arc::new(parking_lot::Mutex::new(gate));
    let reconciler = Reconciler {
        read_topology: Arc::new(|_| Ok(topology())),
        apply: {
            let entered = entered.clone();
            Arc::new(move |snapshot, plan, _, _| {
                entered.store(true, Ordering::SeqCst);
                gate.lock().recv().unwrap();
                model_apply(snapshot, plan, false, false)
            })
        },
        sysctl: Arc::new(|_| Ok(())),
        interval: Duration::from_secs(3600),
    };
    let (tx, _rx) = mpsc::channel(4);
    let (watcher, _events) = watcher_fixture(&f, tx, reconciler);
    while !entered.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    {
        let mut backend = tokio::time::timeout(Duration::from_millis(100), f.ebpf.write())
            .await
            .expect("blocking apply must not hold the backend lock");
        backend.set_datapath_ready(false).unwrap();
    }

    let shutdown = tokio::spawn(watcher.shutdown(Duration::from_millis(50)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !shutdown.is_finished(),
        "shutdown abandoned a running batch"
    );

    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .expect("shutdown must finish once the batch does")
        .unwrap();
    assert_eq!(
        f.owned().await.len(),
        2,
        "the in-flight batch finished its commit before the task ended"
    );
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
        netlink
            .add_veth_pair("route-veth", "route-peer")
            .expect("veth pair");
        let (ifindex, _) = netlink.get_link("route-veth").expect("veth ifindex");
        netlink.set_link_up(ifindex, true).expect("bring veth up");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("tokio runtime");

        runtime.block_on(async move {
            let events = subscribe_network_events().expect("network event subscription");
            let events = unsafe { tokio::io::unix::AsyncFd::register(events) }
                .expect("async netlink socket");
            netlink
                .add_route(
                    crate::netlink::FAM_V4,
                    254,
                    crate::netlink::ROUTE_UNICAST,
                    crate::netlink::SCOPE_LINK,
                    crate::netlink::PROTO_STATIC,
                    None,
                    None,
                    Some(ifindex),
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

/// A binding that failed its proof is looked at again, but not on every route
/// event: at most once per ticker interval. Between those it stays failed.
#[tokio::test]
async fn failed_retained_verification_is_rate_limited_on_route_only_batches() {
    let f = fixture(&["eth0"], &[]);
    let (mut watch, _rx) = f.watch();
    watch.reconcile(false).await.unwrap();
    let held = f.owned().await;
    let commits = f.commits.load(Ordering::Relaxed);
    let verifies = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let failing = Arc::new(AtomicBool::new(true));
    watch.reconciler.apply = {
        let verifies = verifies.clone();
        let failing = failing.clone();
        Arc::new(move |snapshot, plan, _, verify| {
            verifies.lock().push(verify);
            let binding = snapshot.owned[0].0.clone();
            let mut report = model_apply(snapshot, plan, false, false);
            // Only a verifying pass can find (or clear) a proof failure.
            if verify && failing.load(Ordering::SeqCst) {
                report
                    .failed
                    .push((binding, anyhow::anyhow!("query failed")));
            }
            report
        })
    };
    let reason = || {
        f.degradations
            .get(Component::InterfaceBinding)
            .map(|i| i.reason)
    };
    watch.reconciler.interval = Duration::from_secs(3600);
    assert!(watch.reconcile(true).await.is_err());
    for _ in 0..3 {
        assert!(
            watch.reconcile(false).await.is_err(),
            "still failed, not re-verified"
        );
        assert_eq!(reason(), Some("attach_failed"));
    }
    assert_eq!(*verifies.lock(), [true, false, false, false]);

    // Once the interval has passed the next route-only batch proves it again.
    watch.reconciler.interval = Duration::ZERO;
    assert!(watch.reconcile(false).await.is_err());
    failing.store(false, Ordering::SeqCst);
    assert!(!watch.reconcile(false).await.unwrap());
    assert_eq!(reason(), None);
    assert!(!watch.reconcile(false).await.unwrap());
    assert_eq!(
        *verifies.lock(),
        [true, false, false, false, true, true, false]
    );
    assert_eq!(f.owned().await, held);
    assert_eq!(f.commits.load(Ordering::Relaxed), commits);
}

#[test]
fn drain_forces_verification_after_enobufs_and_stops_at_the_message_bound() {
    for terminal in [Errno::EAGAIN, Errno::EIO] {
        let mut outcomes = [Err(Errno::ENOBUFS), Err(terminal)].into_iter();
        let drained = drain_with(&mut [0; 64], |_| outcomes.next().unwrap()).unwrap();
        assert!(drained.verify());
        assert_eq!(drained.empty, terminal == Errno::EAGAIN);
    }
    for (kind, verify) in [(24u16, false), (RTM_NEWLINK, true), (RTM_DELLINK, true)] {
        let mut calls = 0;
        let drained = drain_with(&mut [0; 64], |buffer| {
            calls += 1;
            buffer[0..4].copy_from_slice(&16u32.to_ne_bytes());
            buffer[4..6].copy_from_slice(&kind.to_ne_bytes());
            Ok(16)
        })
        .unwrap();
        assert_eq!(calls, 64);
        assert!(!drained.empty);
        assert_eq!(drained.verify(), verify);
    }
}
