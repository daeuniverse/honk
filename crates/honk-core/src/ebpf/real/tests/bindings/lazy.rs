//! Lazy binding through the shared startup function (`start_interfaces`) and
//! the watcher's own reconcile, on real devices in a private network
//! namespace. Every assertion reads the kernel (TCX chains, link info,
//! `/proc/sys`). No device is brought up: existence is what binds.

use super::watcher::{accept_ra, set_accept_ra};
use super::*;
use crate::control::ControlCommand;
use crate::degradations::{Component, Degradations};
use crate::ebpf::real::iface_watch::{Reconciler, Watch};
use crate::ebpf::real::interface_startup::InterfaceHandoff;
use crate::ebpf::real::{IfaceWatcher, start_interfaces};
use TcProgram::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const IFF_UP: u32 = 1;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| name.to_string()).collect()
}

/// `(ifindex, flags)` of a device, straight from a link dump.
fn link(name: &str) -> (u32, u32) {
    let links = NlSock::new().unwrap().dump_links().unwrap();
    let link = links
        .iter()
        .find(|link| link.name == name)
        .unwrap_or_else(|| panic!("{name} is missing"));
    (link.ifindex.get(), link.flags)
}

/// A veth pair that stays DOWN; the index of `name`.
fn down_veth(name: &str, peer: &str) -> u32 {
    NlSock::new().unwrap().add_veth_pair(name, peer).unwrap();
    let (ifindex, flags) = link(name);
    assert_eq!(flags & IFF_UP, 0, "{name} must stay down");
    ifindex
}

/// What startup returned plus everything a reconcile round needs.
struct Started {
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    programs: BTreeMap<TcProgram, u32>,
    config: Arc<RwLock<Arc<honk_config::Config>>>,
    degradations: Arc<Degradations>,
    handoff: Option<InterfaceHandoff>,
    pin_root: PathBuf,
    _dae0: crate::daens::Dae0Guard,
}

/// The real startup path: `start_interfaces` with the production object. It
/// must succeed whatever the configured interfaces look like.
fn start(rt: &tokio::runtime::Runtime, test: &str, lan: &[&str], wan: &[&str]) -> Started {
    start_with_read(rt, test, lan, wan, crate::ebpf::interface::read_topology)
}

fn start_with_read(
    rt: &tokio::runtime::Runtime,
    test: &str,
    lan: &[&str],
    wan: &[&str],
    read_topology: impl Fn(bool) -> anyhow::Result<Topology>,
) -> Started {
    let degradations = Arc::new(Degradations::default());
    let (dae0, setup) = crate::daens::create_test_dae0_pair().expect("dae0 pair");
    let pin_root =
        Path::new("/sys/fs/bpf").join(format!("honk-lazy-{}-{test}", std::process::id()));
    let (backend, handoff) = rt
        .block_on(start_interfaces(
            crate::DEFAULT_BPF_OBJECT,
            &pin_root,
            12345,
            &setup,
            &names(lan),
            &names(wan),
            &degradations,
            read_topology,
        ))
        .expect("a configured interface never fails startup");
    let mut config = honk_config::Config::default();
    config.global.lan_interface = names(lan);
    config.global.wan_interface = names(wan);
    Started {
        programs: program_ids(&backend),
        ebpf: Arc::new(RwLock::new(Box::new(backend))),
        config: Arc::new(RwLock::new(Arc::new(config))),
        degradations,
        handoff: Some(handoff),
        pin_root,
        _dae0: dae0,
    }
}

impl Started {
    /// The watcher's reconcile, continuing from startup's episode state.
    fn watch(&mut self) -> Watch {
        let (commands, _rx) = mpsc::channel(4);
        Watch::new(
            self.ebpf.clone(),
            self.config.clone(),
            commands,
            Reconciler::default(),
            self.degradations.clone(),
            self.handoff.take().expect("watch once").state,
        )
    }

    fn reason(&self) -> Option<&'static str> {
        self.degradations
            .get(Component::InterfaceBinding)
            .map(|issue| issue.reason)
    }

    /// Release everything this test attached to the shared kernel.
    fn finish(self, rt: &tokio::runtime::Runtime) {
        rt.block_on(async {
            let mut backend = self.ebpf.write().await;
            backend.detach_hooks().expect("detach hooks");
            backend.cleanup().await.expect("cleanup");
        });
        for name in [
            UDP_DECISION_SEQUENCE_MAP,
            routing::ROUTING_GENERATION_SEQUENCE_MAP,
        ] {
            let _ = std::fs::remove_file(self.pin_root.join(name));
        }
        let _ = std::fs::remove_dir(&self.pin_root);
    }
}

type Kernel = BTreeMap<(String, Direction), (TcProgram, u32)>;

/// What the owner holds, each record proven against the kernel.
async fn kernel_bound(started: &Started) -> Kernel {
    kernel_held(&started.ebpf, &started.programs)
        .await
        .into_iter()
        .map(|h| {
            (
                (h.binding.interface, h.binding.direction),
                (h.binding.program, h.id),
            )
        })
        .collect()
}

fn programs(kernel: &Kernel, name: &str) -> [TcProgram; 2] {
    [Direction::Ingress, Direction::Egress]
        .map(|direction| kernel[&(name.to_string(), direction)].0)
}

fn keys(kernel: &Kernel) -> Vec<(&str, Direction)> {
    kernel
        .keys()
        .map(|(name, direction)| (name.as_str(), *direction))
        .collect()
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn startup_refuses_nested_entry_while_binding_the_ordinary_lan() {
    private_netns(|| {
        let rt = runtime();
        down_veth("hbl_lan", "hbl_lanp");
        down_veth("hbl_nested", "hbl_nestedp");
        let mut started = start_with_read(
            &rt,
            "nested",
            &["hbl_lan", "hbl_nested"],
            &[],
            |need_route| {
                let mut topology = read_topology(need_route)?;
                let nested = topology
                    .links
                    .iter_mut()
                    .find(|link| link.name == "hbl_nested")
                    .unwrap();
                let mut master = nested.clone();
                nested.master = std::num::NonZeroU32::new(1_000_000);
                // Inject an unsupported master path while keeping the real LAN topology.
                for (index, name, kind, upper) in [
                    (1_000_000, "hbl_bond", "bond", Some(1_000_001)),
                    (1_000_001, "hbl_br", "bridge", Some(1_000_002)),
                    (1_000_002, "hbl_upper", "bridge", None),
                ] {
                    master.ifindex = std::num::NonZeroU32::new(index).unwrap();
                    master.name = name.into();
                    master.kind = Some(kind.into());
                    master.master = upper.and_then(std::num::NonZeroU32::new);
                    topology.links.push(master.clone());
                }
                Ok(topology)
            },
        );
        rt.block_on(async {
            let bound = kernel_bound(&started).await;
            assert_eq!(
                keys(&bound),
                [
                    ("hbl_lan", Direction::Ingress),
                    ("hbl_lan", Direction::Egress)
                ]
            );
            assert_eq!(started.reason(), Some("unsupported_type"));
        });
        let mut watch = started.watch();
        rt.block_on(async {
            // The first successful plan sees the actual, ordinary veths.
            assert!(watch.reconcile(true).await.unwrap());
            let bound = kernel_bound(&started).await;
            assert_eq!(bound.len(), 4);
            assert_eq!(programs(&bound, "hbl_lan"), [LanIngressL2, LanEgressL2]);
            assert_eq!(programs(&bound, "hbl_nested"), [LanIngressL2, LanEgressL2]);
            assert_eq!(started.reason(), None);
        });
        started.finish(&rt);
    });
}

/// Neither configured interface exists at startup: startup succeeds with no
/// link, `interface_binding` is `pending`, and each device binds when it
/// appears (still down), is released when deleted and rebinds under its new
/// ifindex when recreated.
#[test]
#[ignore = "requires root; run via just test-netns"]
fn absent_interfaces_start_pending_then_bind_release_and_rebind() {
    private_netns(|| {
        let rt = runtime();
        let mut started = start(&rt, "absent", &["hbl_lan"], &["hbl_wan"]);
        let base = held_bpf_link_count();
        let mut watch = started.watch();
        rt.block_on(async {
            assert_eq!(started.reason(), Some("pending"));
            assert!(kernel_bound(&started).await.is_empty());

            let lan = down_veth("hbl_lan", "hbl_lanp");
            assert!(watch.reconcile(true).await.unwrap());
            let bound = kernel_bound(&started).await;
            assert_eq!(keys(&bound).len(), 2);
            assert_eq!(programs(&bound, "hbl_lan"), [LanIngressL2, LanEgressL2]);
            assert_eq!(started.reason(), Some("pending"), "the WAN is still absent");

            down_veth("hbl_wan", "hbl_wanp");
            assert!(watch.reconcile(true).await.unwrap());
            let bound = kernel_bound(&started).await;
            assert_eq!(programs(&bound, "hbl_wan"), [WanIngressL2, WanEgressL2]);
            assert_eq!(started.reason(), None);
            assert_eq!(held_bpf_link_count(), base + 4);
            let old_ids = (
                bound[&("hbl_lan".into(), Direction::Ingress)].1,
                bound[&("hbl_lan".into(), Direction::Egress)].1,
            );

            NlSock::new().unwrap().del_link(lan).unwrap();
            assert!(watch.reconcile(true).await.unwrap());
            let bound = kernel_bound(&started).await;
            assert_eq!(
                keys(&bound),
                [
                    ("hbl_wan", Direction::Ingress),
                    ("hbl_wan", Direction::Egress)
                ]
            );
            assert_eq!(started.reason(), Some("pending"));
            assert_eq!(held_bpf_link_count(), base + 2);

            let again = down_veth("hbl_lan", "hbl_lanp");
            assert_ne!(again, lan, "a new device gets a new ifindex");
            assert!(watch.reconcile(true).await.unwrap());
            let bound = kernel_bound(&started).await;
            let new_ids = (
                bound[&("hbl_lan".into(), Direction::Ingress)].1,
                bound[&("hbl_lan".into(), Direction::Egress)].1,
            );
            assert_ne!(old_ids, new_ids);
            assert_eq!(started.reason(), None);
            assert_eq!(held_bpf_link_count(), base + 4);
        });
        started.finish(&rt);
    });
}

/// Only one configured interface is missing: the DOWN one binds during startup
/// itself and the other binds when it appears.
#[test]
#[ignore = "requires root; run via just test-netns"]
fn only_one_interface_missing_binds_the_down_one_at_startup() {
    for (present, absent, present_programs, absent_programs) in [
        (
            "hbl_lan",
            "hbl_wan",
            [LanIngressL2, LanEgressL2],
            [WanIngressL2, WanEgressL2],
        ),
        (
            "hbl_wan",
            "hbl_lan",
            [WanIngressL2, WanEgressL2],
            [LanIngressL2, LanEgressL2],
        ),
    ] {
        private_netns(move || {
            let rt = runtime();
            down_veth(present, &format!("{present}p"));
            let mut started = start(&rt, "one-missing", &["hbl_lan"], &["hbl_wan"]);
            let mut watch = started.watch();
            rt.block_on(async {
                let bound = kernel_bound(&started).await;
                assert_eq!(programs(&bound, present), present_programs);
                assert_eq!(started.reason(), Some("pending"));
                down_veth(absent, &format!("{absent}p"));
                assert!(watch.reconcile(true).await.unwrap());
                let bound = kernel_bound(&started).await;
                assert_eq!(programs(&bound, absent), absent_programs);
                assert_eq!(started.reason(), None);
            });
            started.finish(&rt);
        });
    }
}

/// A TCX create that fails at startup (the target chain is full: `-ERANGE` at
/// 63 foreign programs) degrades instead of failing startup; freeing a slot
/// recovers without stacking a second link.
#[test]
#[ignore = "requires root; run via just test-netns"]
fn startup_attach_failure_degrades_and_recovers_without_stacking() {
    private_netns(|| {
        let rt = runtime();
        let ifindex = down_veth("hbl_full", "hbl_fullp");
        let mut foreign: Vec<_> = (0..63)
            .map(|_| foreign_link(ifindex, Direction::Ingress).unwrap())
            .collect();
        let mut started = start(&rt, "full", &["hbl_full"], &[]);
        let mut watch = started.watch();
        rt.block_on(async {
            let bound = kernel_bound(&started).await;
            assert_eq!(keys(&bound), [("hbl_full", Direction::Egress)]);
            assert_eq!(started.reason(), Some("attach_failed"));
            assert_eq!(chain(ifindex, Direction::Ingress).len(), 63);

            // Still full: retried, still failed, nothing stacked.
            assert!(watch.reconcile(true).await.is_err());
            assert_eq!(started.reason(), Some("attach_failed"));
            assert_eq!(chain(ifindex, Direction::Ingress).len(), 63);

            drop(foreign.pop());
            assert!(watch.reconcile(true).await.unwrap());
            let bound = kernel_bound(&started).await;
            assert_eq!(programs(&bound, "hbl_full"), [LanIngressL2, LanEgressL2]);
            assert_eq!(started.reason(), None);
            let id = bound[&("hbl_full".into(), Direction::Ingress)].1;
            let on_chain = chain(ifindex, Direction::Ingress);
            assert_eq!(
                (
                    on_chain.len(),
                    on_chain.iter().filter(|c| **c == id).count()
                ),
                (63, 1)
            );
            assert!(
                !watch.reconcile(true).await.unwrap(),
                "settled: nothing to do"
            );
            assert_eq!(chain(ifindex, Direction::Ingress), on_chain);
        });
        started.finish(&rt);
    });
}

/// A configured bridge member binds the bridge and every port; once it
/// leaves the bridge the master and the other ports are released, and a
/// bridge that is deleted and recreated gets its hooks back when re-enslaved.
#[test]
#[ignore = "requires root; run via just test-netns"]
fn bridge_member_leaving_releases_master_links_and_a_recreated_bridge_rebinds() {
    private_netns(|| {
        let rt = runtime();
        ip(&["link", "add", "hbl_br", "type", "bridge"]);
        down_veth("hbl_p", "hbl_pp");
        down_veth("hbl_q", "hbl_qp");
        ip(&["link", "set", "hbl_p", "master", "hbl_br"]);
        ip(&["link", "set", "hbl_q", "master", "hbl_br"]);
        let (old_bridge, _) = link("hbl_br");
        let mut started = start(&rt, "bridge", &["hbl_p"], &[]);
        let mut watch = started.watch();
        let all = [
            ("hbl_br", Direction::Ingress),
            ("hbl_br", Direction::Egress),
            ("hbl_p", Direction::Ingress),
            ("hbl_p", Direction::Egress),
            ("hbl_q", Direction::Ingress),
            ("hbl_q", Direction::Egress),
        ];
        rt.block_on(async {
            assert_eq!(keys(&kernel_bound(&started).await), all);

            ip(&["link", "set", "hbl_p", "nomaster"]);
            assert!(watch.reconcile(true).await.unwrap());
            let bound = kernel_bound(&started).await;
            assert_eq!(
                keys(&bound),
                [("hbl_p", Direction::Ingress), ("hbl_p", Direction::Egress)],
                "master and the other port are released"
            );
            for direction in [Direction::Ingress, Direction::Egress] {
                assert!(chain(old_bridge, direction).is_empty(), "{direction:?}");
                assert!(
                    chain(link("hbl_q").0, direction).is_empty(),
                    "{direction:?}"
                );
            }

            ip(&["link", "set", "hbl_p", "master", "hbl_br"]);
            assert!(watch.reconcile(true).await.unwrap());
            assert_eq!(keys(&kernel_bound(&started).await), all);

            // The bridge is deleted and recreated: the member comes back
            // under a new ifindex and the hooks follow.
            ip(&["link", "del", "hbl_br"]);
            watch.reconcile(true).await.unwrap();
            ip(&["link", "add", "hbl_br", "type", "bridge"]);
            ip(&["link", "set", "hbl_p", "master", "hbl_br"]);
            assert!(watch.reconcile(true).await.unwrap());
            let (new_bridge, _) = link("hbl_br");
            assert_ne!(new_bridge, old_bridge);
            let bound = kernel_bound(&started).await;
            assert_eq!(
                keys(&bound),
                [
                    ("hbl_br", Direction::Ingress),
                    ("hbl_br", Direction::Egress),
                    ("hbl_p", Direction::Ingress),
                    ("hbl_p", Direction::Egress),
                ]
            );
            assert_eq!(started.reason(), None);
            assert_eq!(chain(new_bridge, Direction::Ingress).len(), 1);
        });
        started.finish(&rt);
    });
}

/// `accept_ra=2` is written when the WAN root is first seen, whether at
/// startup or later, for a dotted name too, and again for a recreated device.
/// `rp_filter=0` follows the first resolved LAN that exists.
#[test]
#[ignore = "requires root; run via just test-netns"]
fn accept_ra_and_rp_filter_are_written_on_sight_for_dotted_names() {
    private_netns(|| {
        let rt = runtime();
        down_veth("hbl.100", "hbl_ap");
        down_veth("hbl_lan", "hbl_lanp");
        let rp_filter = |name: &str| {
            std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"))
                .unwrap()
                .trim()
                .to_string()
        };
        set_accept_ra("hbl.100", "0");
        std::fs::write("/proc/sys/net/ipv4/conf/hbl_lan/rp_filter", "1").unwrap();
        let mut started = start(&rt, "sysctl", &["hbl_lan"], &["hbl.100", "hbw.200"]);
        assert_eq!(
            accept_ra("hbl.100"),
            "2",
            "written at startup, dotted name intact"
        );
        assert_eq!(rp_filter("hbl_lan"), "0");
        let mut watch = started.watch();
        rt.block_on(async {
            down_veth("hbw.200", "hbw_bp");
            set_accept_ra("hbw.200", "0");
            watch.reconcile(false).await.unwrap();
            assert_eq!(accept_ra("hbw.200"), "2", "written when first seen");

            // Written once per ifindex: a value changed by someone else sticks.
            set_accept_ra("hbw.200", "1");
            watch.reconcile(true).await.unwrap();
            assert_eq!(accept_ra("hbw.200"), "1");

            // A recreated device has a new ifindex: written again.
            let old = link("hbw.200").0;
            NlSock::new().unwrap().del_link(old).unwrap();
            watch.reconcile(true).await.unwrap();
            down_veth("hbw.200", "hbw_bp");
            assert_ne!(link("hbw.200").0, old);
            watch.reconcile(true).await.unwrap();
            assert_eq!(accept_ra("hbw.200"), "2");
        });
        started.finish(&rt);
    });
}

/// The subscription startup opened is the one the watcher waits on: with the
/// 60 s ticker out of reach, only a netlink event can bind a device that
/// appears after the watcher started.
#[test]
#[ignore = "requires root; run via just test-netns"]
fn watcher_binds_on_an_event_from_the_subscription_startup_opened() {
    private_netns(|| {
        let rt = runtime();
        let mut started = start(&rt, "event", &["hbl_lan"], &[]);
        let handoff = started.handoff.take().unwrap();
        assert!(
            handoff.subscription.is_some(),
            "subscription is opened before the dump"
        );
        let (commands, mut notifications) = mpsc::channel(8);
        rt.block_on(async {
            let watcher = IfaceWatcher::spawn(
                started.ebpf.clone(),
                started.config.clone(),
                commands,
                started.degradations.clone(),
                handoff,
            );
            // The watcher's first pass has run once it announces itself.
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(10), notifications.recv()).await,
                Ok(Some(ControlCommand::NetworkChanged))
            ));
            assert!(kernel_bound(&started).await.is_empty());
            // The interval's immediate first tick is spent; from here only an
            // event can wake the watcher within the test.
            tokio::time::sleep(Duration::from_millis(500)).await;
            down_veth("hbl_lan", "hbl_lanp");
            tokio::time::timeout(Duration::from_secs(10), async {
                while started.reason().is_some() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("an event, not the ticker, must bind the new device");
            let bound = kernel_bound(&started).await;
            assert_eq!(programs(&bound, "hbl_lan"), [LanIngressL2, LanEgressL2]);
            watcher.shutdown(Duration::from_secs(5)).await;
        });
        started.finish(&rt);
    });
}
