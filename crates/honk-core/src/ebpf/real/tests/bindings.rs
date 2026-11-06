//! Real-kernel proofs for the single TCX owner (`real::bindings`): every case
//! runs in a private network namespace on a fixture backend with no daemon
//! pair, drives `apply` the way the watcher does (trait snapshot, blocking
//! apply with `verify`, trait commit, close the returned FDs) and checks the
//! kernel's own chain and link info rather than the owner's records.
//!
//! The private mount namespace deliberately keeps the parent's sysfs, so a
//! veth created here is invisible to `/sys/class/net`.

use super::super::bindings as owner;
use super::*;
use crate::ebpf::EbpfBackend;
use crate::ebpf::interface::{
    Binding, BindingSnapshot, Direction, InterfacePlan, TcProgram, Topology,
    plan as plan_interfaces, read_topology,
};
use crate::netlink::NlSock;
use aya_obj::generated::{BPF_F_AFTER, bpf_attach_type, bpf_attr, bpf_cmd, bpf_prog_type};
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::sync::RwLock;

fn ip(args: &[&str]) {
    let status = std::process::Command::new("ip")
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "ip {}", args.join(" "));
}

fn plan_for(lan: &[&str], wan: &[&str]) -> (InterfacePlan, Topology) {
    let owned = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
    let topology = read_topology(false).unwrap();
    let plan = plan_interfaces(&owned(lan), &owned(wan), &topology);
    (plan, topology)
}

fn attach_type(direction: Direction) -> u32 {
    let kind = match direction {
        Direction::Ingress => bpf_attach_type::BPF_TCX_INGRESS,
        Direction::Egress => bpf_attach_type::BPF_TCX_EGRESS,
    };
    kind as u32
}

/// Link IDs on a chain of the calling thread's namespace, in kernel order.
fn chain(ifindex: u32, direction: Direction) -> Vec<u32> {
    owner::query_chain(ifindex, direction)
        .unwrap_or_else(|error| panic!("query chain of {ifindex} {direction:?}: {error}"))
        .links
}

fn has_errno(error: &anyhow::Error, errno: i32) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io| io.raw_os_error() == Some(errno))
    })
}

/// A TCX link nobody here owns: a fresh `r0 = 0; exit` classifier appended to a
/// chain, the way another tool would.
struct Foreign {
    id: u32,
    _link: OwnedFd,
}

fn foreign_link(ifindex: u32, direction: Direction) -> io::Result<Foreign> {
    let insns: [u8; 16] = [0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    let mut load: bpf_attr = unsafe { core::mem::zeroed() };
    load.__bindgen_anon_3.prog_type = bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS as u32;
    load.__bindgen_anon_3.insn_cnt = 2;
    load.__bindgen_anon_3.insns = insns.as_ptr() as u64;
    load.__bindgen_anon_3.license = c"GPL".as_ptr() as u64;
    let program = unsafe { syscall::bpf_syscall(bpf_cmd::BPF_PROG_LOAD as _, &mut load) }
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
    let program = unsafe { OwnedFd::from_raw_fd(program as i32) };
    let mut create: bpf_attr = unsafe { core::mem::zeroed() };
    create.link_create.__bindgen_anon_1.prog_fd = program.as_raw_fd() as u32;
    create.link_create.__bindgen_anon_2.target_ifindex = ifindex;
    create.link_create.attach_type = attach_type(direction);
    create.link_create.flags = BPF_F_AFTER;
    let link = unsafe { syscall::bpf_syscall(bpf_cmd::BPF_LINK_CREATE as _, &mut create) }
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
    let link = unsafe { OwnedFd::from_raw_fd(link as i32) };
    let id = owner::link_info(link.as_raw_fd())?.id;
    Ok(Foreign { id, _link: link })
}

/// What one reconcile round decided, read before the owner took the commit.
#[derive(Debug)]
struct Round {
    added: Vec<(Binding, u32)>,
    removed: Vec<(u32, Direction)>,
    reprogrammed: Vec<(u32, Direction, TcProgram)>,
    failed: Vec<(Binding, anyhow::Error)>,
    topology_changed: bool,
    /// FDs the owner handed back for closing (replaced or removed links).
    closed: usize,
}

impl Round {
    fn settled(&self) -> bool {
        self.failed.is_empty() && !self.topology_changed
    }

    fn unchanged(&self) -> bool {
        self.settled()
            && self.added.is_empty()
            && self.removed.is_empty()
            && self.reprogrammed.is_empty()
            && self.closed == 0
    }
}

struct Held {
    binding: Binding,
    id: u32,
    link: OwnedFd,
}

struct Lab {
    backend: RealEbpfBackend,
    netlink: NlSock,
}

impl Lab {
    fn new() -> Self {
        let mut backend = RealEbpfBackend::load_routing_test_fixture(
            crate::DEFAULT_BPF_OBJECT,
            DaeParam::default(),
        )
        .expect("load embedded production object");
        // Preloads the eight TC variants and binds nothing.
        backend.bind_test_interfaces(&[], &[]);
        Self {
            backend,
            netlink: NlSock::new().unwrap(),
        }
    }

    fn veth(&mut self, name: &str, peer: &str) -> u32 {
        self.netlink.add_veth_pair(name, peer).unwrap();
        self.netlink.get_link(name).unwrap().0
    }

    /// Snapshot, apply with verification, commit, close: the watcher's order.
    fn reconcile(&mut self, plan: &InterfacePlan, topology: &Topology) -> Round {
        let snapshot = self.snapshot();
        self.reconcile_with(snapshot, plan, topology)
    }

    fn snapshot(&self) -> BindingSnapshot {
        self.backend.interface_binding_snapshot().unwrap()
    }

    /// `reconcile` with a caller-supplied (possibly stale or tampered) snapshot.
    fn reconcile_with(
        &mut self,
        snapshot: BindingSnapshot,
        plan: &InterfacePlan,
        topology: &Topology,
    ) -> Round {
        let mut report = owner::apply(snapshot, plan, topology, true);
        let commit = std::mem::take(&mut report.commit);
        let mut round = Round {
            added: commit
                .add
                .iter()
                .map(|(binding, id, _)| (binding.clone(), *id))
                .collect(),
            removed: commit
                .remove
                .iter()
                .map(|(ifindex, direction)| (ifindex.get(), *direction))
                .collect(),
            reprogrammed: commit
                .reprogram
                .iter()
                .map(|(ifindex, direction, program)| (ifindex.get(), *direction, *program))
                .collect(),
            failed: report.failed,
            topology_changed: report.topology_changed,
            closed: 0,
        };
        let closed = self.backend.commit_interface_bindings(commit);
        round.closed = closed.len();
        drop(closed);
        round
    }

    fn round(&mut self, lan: &[&str], wan: &[&str]) -> Round {
        let (plan, topology) = plan_for(lan, wan);
        self.reconcile(&plan, &topology)
    }

    fn held(&self) -> Vec<Held> {
        held_of(self.snapshot())
    }

    /// `(ifindex, direction)` -> `(program, link id)` as the owner records it.
    fn owned(&self) -> Owned {
        owned_of(&self.held())
    }

    fn program_id(&self, program: TcProgram) -> u32 {
        program_ids(&self.backend)[&program]
    }

    fn assert_truthful(&self) {
        assert_truthful(&self.held(), &program_ids(&self.backend));
    }
}

type Owned = BTreeMap<(u32, Direction), (TcProgram, u32)>;

fn held_of(snapshot: BindingSnapshot) -> Vec<Held> {
    let mut held: Vec<Held> = snapshot
        .owned
        .into_iter()
        .map(|(binding, id, link)| Held { binding, id, link })
        .collect();
    held.sort_by_key(|h| (h.binding.ifindex, h.binding.direction));
    held
}

fn owned_of(held: &[Held]) -> Owned {
    held.iter()
        .map(|h| {
            (
                (h.binding.ifindex.get(), h.binding.direction),
                (h.binding.program, h.id),
            )
        })
        .collect()
}

fn program_ids(backend: &RealEbpfBackend) -> BTreeMap<TcProgram, u32> {
    TcProgram::ALL
        .iter()
        .map(|program| {
            let id = backend
                .bpf()
                .unwrap()
                .program(program.name())
                .unwrap()
                .info()
                .unwrap()
                .id();
            (*program, id)
        })
        .collect()
}

/// Every record matches the kernel: link ID, interface index, attach type,
/// program, and exactly one entry on the namespace-local chain.
fn assert_truthful(held: &[Held], programs: &BTreeMap<TcProgram, u32>) {
    for held in held {
        let Binding {
            ifindex,
            direction,
            program,
            ref interface,
        } = held.binding;
        let info = owner::link_info(held.link.as_raw_fd()).unwrap();
        let what = format!("{interface} ({ifindex}, {direction:?})");
        assert_eq!(info.id, held.id, "{what}: link id");
        assert_eq!(info.ifindex, ifindex.get(), "{what}: link ifindex");
        assert_eq!(
            info.attach_type,
            attach_type(direction),
            "{what}: attach type"
        );
        assert_eq!(
            info.program_id,
            programs[&program],
            "{what}: kernel link runs another program than {}",
            program.name()
        );
        let links = chain(ifindex.get(), direction);
        assert_eq!(
            links.iter().filter(|id| **id == held.id).count(),
            1,
            "{what}: link {} is not exactly once on chain {links:?}",
            held.id
        );
    }
}

/// `held_of` for a backend behind the daemon's lock, proven against the kernel.
async fn kernel_held(
    ebpf: &RwLock<Box<dyn EbpfBackend>>,
    programs: &BTreeMap<TcProgram, u32>,
) -> Vec<Held> {
    let snapshot = ebpf.read().await.interface_binding_snapshot().unwrap();
    let held = held_of(snapshot);
    assert_truthful(&held, programs);
    held
}

mod failure;
mod framing;
mod lazy;
mod watcher;

#[test]
#[ignore = "requires root; run via just test-netns"]
fn private_netns_binding_is_owned_and_detached_by_true_ifindex() {
    private_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hb268", "hb268p");
        let sysfs = crate::netlink::ifindex_of("hb268");
        assert!(
            sysfs.is_err(),
            "mounted sysfs must not show the private-netns veth, got {sysfs:?}"
        );
        let baseline = held_bpf_link_count();

        lab.backend.bind_test_interfaces(&["hb268"], &[]);
        let keys: Vec<_> = lab
            .backend
            .owned_bindings()
            .map(|b| (b.ifindex.get(), b.direction, b.program))
            .collect();
        assert_eq!(keys.len(), 2, "one binding per direction: {keys:?}");
        assert!(keys.iter().all(|(i, ..)| *i == ifindex), "{keys:?}");
        lab.assert_truthful();
        let owned = lab.owned();
        let ingress = owned[&(ifindex, Direction::Ingress)].1;
        let egress = owned[&(ifindex, Direction::Egress)].1;
        assert_eq!(chain(ifindex, Direction::Ingress), [ingress]);
        assert_eq!(chain(ifindex, Direction::Egress), [egress]);
        assert_eq!(held_bpf_link_count(), baseline + 2);

        // The plan no longer wants the device: the owner detaches by true ifindex.
        let round = lab.round(&[], &[]);
        assert!(round.settled(), "{round:?}");
        let mut removed = round.removed.clone();
        removed.sort();
        assert_eq!(
            removed,
            [(ifindex, Direction::Ingress), (ifindex, Direction::Egress)]
        );
        assert_eq!(round.closed, 2);
        assert!(lab.owned().is_empty());
        assert!(chain(ifindex, Direction::Ingress).is_empty());
        assert!(chain(ifindex, Direction::Egress).is_empty());
        assert_eq!(held_bpf_link_count(), baseline);
    });
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn unchanged_plan_keeps_link_ids_and_leaves_foreign_hooks() {
    private_netns(|| {
        let mut lab = Lab::new();
        let lan = lab.veth("hbu_a", "hbu_ap");
        let wan = lab.veth("hbu_b", "hbu_bp");
        let foreign_lan = foreign_link(lan, Direction::Ingress).unwrap();
        let foreign_wan = foreign_link(wan, Direction::Egress).unwrap();
        let baseline = held_bpf_link_count();

        let first = lab.round(&["hbu_a"], &["hbu_b"]);
        assert!(first.settled(), "{first:?}");
        assert_eq!(first.added.len(), 4, "{first:?}");
        let ids = lab.owned();
        assert_eq!(ids.len(), 4);
        lab.assert_truthful();
        // Appended after the foreign link, never before or in place of it.
        assert_eq!(
            chain(lan, Direction::Ingress),
            [foreign_lan.id, ids[&(lan, Direction::Ingress)].1]
        );
        assert_eq!(
            chain(wan, Direction::Egress),
            [foreign_wan.id, ids[&(wan, Direction::Egress)].1]
        );

        let chains = |lab: &Lab| {
            lab.owned()
                .keys()
                .map(|&(ifindex, direction)| ((ifindex, direction), chain(ifindex, direction)))
                .collect::<BTreeMap<_, _>>()
        };
        let before = chains(&lab);
        for _ in 0..3 {
            let round = lab.round(&["hbu_a"], &["hbu_b"]);
            assert!(round.unchanged(), "{round:?}");
            assert_eq!(lab.owned(), ids, "link IDs and programs are stable");
            assert_eq!(chains(&lab), before, "chains are stable");
            assert_eq!(held_bpf_link_count(), baseline + 4);
        }
        lab.assert_truthful();

        let round = lab.round(&[], &[]);
        assert!(round.settled(), "{round:?}");
        assert_eq!(round.removed.len(), 4);
        assert_eq!(chain(lan, Direction::Ingress), [foreign_lan.id]);
        assert_eq!(chain(wan, Direction::Egress), [foreign_wan.id]);
        assert!(chain(lan, Direction::Egress).is_empty());
        assert!(chain(wan, Direction::Ingress).is_empty());
        assert_eq!(held_bpf_link_count(), baseline);
    });
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn role_and_framing_change_updates_links_in_place() {
    use TcProgram::*;
    private_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hbr_a", "hbr_ap");
        let foreign_in = foreign_link(ifindex, Direction::Ingress).unwrap();
        let foreign_out = foreign_link(ifindex, Direction::Egress).unwrap();

        let round = lab.round(&["hbr_a"], &[]);
        assert!(round.settled(), "{round:?}");
        let baseline = held_bpf_link_count();
        let key_in = (ifindex, Direction::Ingress);
        let key_out = (ifindex, Direction::Egress);
        let programs = |lab: &Lab| (lab.owned()[&key_in].0, lab.owned()[&key_out].0);
        assert_eq!(programs(&lab), (LanIngressL2, LanEgressL2));
        let ids = (lab.owned()[&key_in].1, lab.owned()[&key_out].1);

        // After each step: same links, one of ours per chain behind the foreign one.
        let step = |lab: &mut Lab,
                    label: &str,
                    plan: &InterfacePlan,
                    topology: &Topology,
                    expect: &[(Direction, TcProgram)]| {
            let round = lab.reconcile(plan, topology);
            assert!(round.settled(), "{label}: {round:?}");
            assert!(
                round.added.is_empty() && round.removed.is_empty(),
                "{label}: {round:?}"
            );
            assert_eq!(round.closed, 0, "{label}: update must not replace the FD");
            let mut got: Vec<_> = round.reprogrammed.iter().map(|r| (r.1, r.2)).collect();
            got.sort();
            assert_eq!(got, expect, "{label}");
            assert_eq!(
                (lab.owned()[&key_in].1, lab.owned()[&key_out].1),
                ids,
                "{label}: ids"
            );
            assert_eq!(
                chain(ifindex, Direction::Ingress),
                [foreign_in.id, ids.0],
                "{label}"
            );
            assert_eq!(
                chain(ifindex, Direction::Egress),
                [foreign_out.id, ids.1],
                "{label}"
            );
            assert_eq!(held_bpf_link_count(), baseline, "{label}: no new link");
            lab.assert_truthful();
        };

        // LAN -> WAN: both directions switch program on the same links.
        let (plan, topology) = plan_for(&[], &["hbr_a"]);
        step(
            &mut lab,
            "LAN->WAN",
            &plan,
            &topology,
            &[
                (Direction::Ingress, WanIngressL2),
                (Direction::Egress, WanEgressL2),
            ],
        );
        assert_eq!(programs(&lab), (WanIngressL2, WanEgressL2));

        // WAN -> LanWan: only ingress changes (egress is WAN either way).
        let (plan, topology) = plan_for(&["hbr_a"], &["hbr_a"]);
        step(
            &mut lab,
            "WAN->LanWan",
            &plan,
            &topology,
            &[(Direction::Ingress, LanIngressL2)],
        );
        assert_eq!(programs(&lab), (LanIngressL2, WanEgressL2));

        // L2 -> L3 framing at the same ifindex (the device itself stays Ethernet,
        // so the plan is edited instead of the topology).
        let (mut plan, topology) = plan_for(&["hbr_a"], &["hbr_a"]);
        for binding in &mut plan.bindings {
            binding.program = match binding.program {
                LanIngressL2 => LanIngressL3,
                WanEgressL2 => WanEgressL3,
                other => other,
            };
        }
        step(
            &mut lab,
            "L2->L3",
            &plan,
            &topology,
            &[
                (Direction::Ingress, LanIngressL3),
                (Direction::Egress, WanEgressL3),
            ],
        );
        assert_eq!(programs(&lab), (LanIngressL3, WanEgressL3));

        // And back, ending on the planner's own L2 answer.
        let (plan, topology) = plan_for(&["hbr_a"], &["hbr_a"]);
        step(
            &mut lab,
            "L3->L2",
            &plan,
            &topology,
            &[
                (Direction::Ingress, LanIngressL2),
                (Direction::Egress, WanEgressL2),
            ],
        );
        let round = lab.round(&["hbr_a"], &["hbr_a"]);
        assert!(round.unchanged(), "{round:?}");
    });
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn moved_device_recreated_with_same_name_and_index_is_rebound() {
    private_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hbm_a", "hbm_ap");
        let away = fresh_netns();
        let baseline = held_bpf_link_count();
        let round = lab.round(&["hbm_a"], &[]);
        assert!(round.settled() && round.added.len() == 2, "{round:?}");
        let key_in = (ifindex, Direction::Ingress);
        let key_out = (ifindex, Direction::Egress);
        let old = (lab.owned()[&key_in].1, lab.owned()[&key_out].1);

        // The device leaves with its links attached and keeps its index there.
        lab.netlink.set_link_netns_fd(ifindex, &away).unwrap();
        let moved = in_netns(&away, || {
            NlSock::new().unwrap().get_link("hbm_a").unwrap().0
        });
        assert_eq!(
            moved, ifindex,
            "moved device must keep its ifindex for this proof"
        );

        // A different device takes the name and the freed index.
        let index = ifindex.to_string();
        ip(&[
            "link", "add", "name", "hbm_a", "index", &index, "type", "veth", "peer", "name",
            "hbm_c",
        ]);
        let (reborn, _) = lab.netlink.get_link("hbm_a").unwrap();
        assert_eq!(reborn, ifindex, "recreated device must reuse the ifindex");

        // The held link FD still claims this ifindex; only the namespace-local
        // chain tells the two devices apart.
        for held in lab.held() {
            let info = owner::link_info(held.link.as_raw_fd()).unwrap();
            assert_eq!(info.ifindex, ifindex, "link info is ambiguous by design");
        }
        assert!(chain(ifindex, Direction::Ingress).is_empty());
        assert!(chain(ifindex, Direction::Egress).is_empty());
        let away_chains = in_netns(&away, || {
            (
                chain(ifindex, Direction::Ingress),
                chain(ifindex, Direction::Egress),
            )
        });
        assert_eq!(
            away_chains,
            (vec![old.0], vec![old.1]),
            "old links live on the moved device"
        );

        let round = lab.round(&["hbm_a"], &[]);
        assert!(round.settled(), "{round:?}");
        assert!(
            round.removed.is_empty(),
            "same keys are replaced, not removed: {round:?}"
        );
        assert_eq!(round.added.len(), 2, "{round:?}");
        assert_eq!(
            round.closed, 2,
            "the stale links are handed back for closing"
        );
        let new = (lab.owned()[&key_in].1, lab.owned()[&key_out].1);
        assert!(new.0 != old.0 && new.1 != old.1, "old {old:?}, new {new:?}");
        assert_eq!(chain(ifindex, Direction::Ingress), [new.0]);
        assert_eq!(chain(ifindex, Direction::Egress), [new.1]);
        lab.assert_truthful();
        // Closing the stale FDs released the links on the moved device.
        let away_chains = in_netns(&away, || {
            (
                chain(ifindex, Direction::Ingress),
                chain(ifindex, Direction::Egress),
            )
        });
        assert_eq!(
            away_chains,
            (vec![], vec![]),
            "stale links must not stay attached"
        );
        assert_eq!(held_bpf_link_count(), baseline + 2);
    });
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn full_chain_fails_one_direction_and_retry_does_not_stack() {
    private_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hbf_a", "hbf_ap");
        let mut fillers = Vec::new();
        let capacity = loop {
            match foreign_link(ifindex, Direction::Ingress) {
                Ok(link) => fillers.push(link),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(libc::ERANGE), "{error}");
                    break fillers.len();
                }
            }
        };
        assert_eq!(capacity, 63, "mprog capacity (V4.1 P3)");
        let full: Vec<u32> = fillers.iter().map(|f| f.id).collect();
        assert_eq!(chain(ifindex, Direction::Ingress), full);
        let baseline = held_bpf_link_count();

        let expect_partial = |lab: &mut Lab, label: &str| {
            let round = lab.round(&["hbf_a"], &[]);
            assert!(!round.topology_changed, "{label}: {round:?}");
            assert_eq!(round.failed.len(), 1, "{label}: {round:?}");
            let (binding, error) = &round.failed[0];
            assert_eq!(binding.direction, Direction::Ingress, "{label}");
            assert!(has_errno(error, libc::ERANGE), "{label}: {error:#}");
            let owned = lab.owned();
            assert_eq!(
                owned.keys().copied().collect::<Vec<_>>(),
                [(ifindex, Direction::Egress)]
            );
            assert_eq!(
                chain(ifindex, Direction::Ingress),
                full,
                "{label}: ingress untouched"
            );
            assert_eq!(
                chain(ifindex, Direction::Egress),
                [owned[&(ifindex, Direction::Egress)].1],
                "{label}: healthy direction bound once"
            );
            assert_eq!(held_bpf_link_count(), baseline + 1, "{label}");
            lab.assert_truthful();
            (round, owned[&(ifindex, Direction::Egress)].1)
        };
        let (first, egress) = expect_partial(&mut lab, "first attempt");
        assert_eq!(first.added.len(), 1, "{first:?}");
        let (second, same) = expect_partial(&mut lab, "retry while full");
        assert!(second.added.is_empty() && second.closed == 0, "{second:?}");
        assert_eq!(same, egress, "retry keeps the healthy link");
    });
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn observation_follows_add_replace_remove() {
    use crate::ebpf::{DatapathCheck, DatapathObservationError};
    private_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hbo_a", "hbo_ap");
        let seen = |lab: &Lab| {
            let mut found: Vec<_> = lab
                .backend
                .observe_datapath()
                .attachments
                .into_iter()
                .filter(|a| a.interface == "hbo_a")
                .map(|a| (a.egress, a.program, a.state))
                .collect();
            found.sort_by_key(|(egress, program, _)| (*egress, program.clone()));
            found
        };
        let verified = |ingress: &str, egress: &str| {
            vec![
                (false, ingress.to_owned(), DatapathCheck::Verified),
                (true, egress.to_owned(), DatapathCheck::Verified),
            ]
        };
        assert!(seen(&lab).is_empty());

        lab.round(&["hbo_a"], &[]);
        assert_eq!(seen(&lab), verified("lan_ingress_l2", "lan_egress_l2"));

        // Replaced in place: still two attachments, now the WAN programs.
        let round = lab.round(&[], &["hbo_a"]);
        assert!(
            round.settled() && round.reprogrammed.len() == 2,
            "{round:?}"
        );
        assert_eq!(seen(&lab), verified("wan_ingress_l2", "wan_egress_l2"));

        // The device vanishes before any reconcile: the retained FD must not be
        // reported as a verified hook.
        lab.netlink.del_link(ifindex).unwrap();
        let observation = lab.backend.observe_datapath();
        let stale: Vec<_> = observation
            .attachments
            .iter()
            .filter(|attachment| attachment.interface == "hbo_a")
            .collect();
        assert!(
            stale
                .iter()
                .all(|attachment| attachment.state != DatapathCheck::Verified),
            "deleted device still reported verified: {stale:?}"
        );
        assert!(
            observation
                .errors
                .contains(&DatapathObservationError::Hooks),
            "a stale binding must surface as a hook error: {observation:?}"
        );

        let round = lab.round(&[], &[]);
        assert!(round.settled() && round.removed.len() == 2, "{round:?}");
        assert!(seen(&lab).is_empty());
    });
}
