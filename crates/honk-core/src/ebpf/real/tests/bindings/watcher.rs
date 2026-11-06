//! The watcher's own reconcile (`Reconciler::default()`: real topology read,
//! real `apply`, real commit, real close/sysctl step) against a real
//! `RealEbpfBackend` in a private network namespace. Every assertion reads the
//! kernel (TCX chains, link info, `/proc/sys`), not the owner's records.

use super::*;
use crate::ebpf::real::iface_watch::{Reconciler, Watch};
use crate::ebpf::real::interface_state::InterfaceState;
use crate::netlink::{FAM_V4, PROTO_STATIC, ROUTE_UNICAST, SCOPE_LINK};
use std::sync::Arc;
use tokio::sync::mpsc;

const LAN: &str = "hbw_lan";
const PEER: &str = "hbw_lanp";

pub(super) fn accept_ra(device: &str) -> String {
    let path = format!("/proc/sys/net/ipv6/conf/{device}/accept_ra");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
        .trim()
        .to_string()
}

pub(super) fn set_accept_ra(device: &str, value: &str) {
    let path = format!("/proc/sys/net/ipv6/conf/{device}/accept_ra");
    std::fs::write(&path, value).unwrap_or_else(|error| panic!("write {path}: {error}"));
}

/// A veth pair with both ends up (the route needs a live device); the index of `name`.
fn up_pair(netlink: &mut NlSock, name: &str, peer: &str) -> u32 {
    netlink.add_veth_pair(name, peer).unwrap();
    let (ifindex, _) = netlink.get_link(name).unwrap();
    let (peer_index, _) = netlink.get_link(peer).unwrap();
    netlink.set_link_up(ifindex, true).unwrap();
    netlink.set_link_up(peer_index, true).unwrap();
    ifindex
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn watcher_reconcile_binds_reprograms_writes_accept_ra_and_releases() {
    private_netns(|| {
        let lab = Lab::new();
        let programs = program_ids(&lab.backend);
        let Lab {
            backend,
            mut netlink,
        } = lab;
        let ebpf: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(backend)));
        let mut config = honk_config::Config::default();
        config.global.lan_interface = vec![LAN.to_string()];
        config.global.wan_interface = vec!["auto".to_string()];
        let (commands, _commands_rx) = mpsc::channel(4);
        let mut watch = Watch::new(
            ebpf.clone(),
            Arc::new(RwLock::new(Arc::new(config))),
            commands,
            Reconciler::default(),
            Arc::default(),
            InterfaceState::default(),
        );
        let baseline = held_bpf_link_count();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                // The device appears: bound as LAN (`auto` WAN has no route yet).
                let first = up_pair(&mut netlink, LAN, PEER);
                assert!(watch.reconcile(true).await.expect("bind on appearance"));
                let held = owned_of(&kernel_held(&ebpf, &programs).await);
                assert_eq!(
                    held.len(),
                    2,
                    "the watcher's commit must own both directions: {held:?}"
                );
                let bound = Owned::from([
                    (
                        (first, Direction::Ingress),
                        (
                            TcProgram::LanIngressL2,
                            held[&(first, Direction::Ingress)].1,
                        ),
                    ),
                    (
                        (first, Direction::Egress),
                        (TcProgram::LanEgressL2, held[&(first, Direction::Egress)].1),
                    ),
                ]);
                assert_eq!(held, bound);
                assert_eq!(held_bpf_link_count(), baseline + 2);

                // `auto` WAN resolves onto the already-bound LAN root. Something
                // else owns accept_ra first, so only the watcher can make it 2.
                set_accept_ra(LAN, "0");
                assert_eq!(accept_ra(LAN), "0");
                netlink
                    .add_route(
                        FAM_V4,
                        254,
                        ROUTE_UNICAST,
                        SCOPE_LINK,
                        PROTO_STATIC,
                        None,
                        None,
                        Some(first),
                    )
                    .expect("default route on the LAN root");
                let topology = read_topology(true).unwrap();
                assert_eq!(
                    topology.default_route.as_deref(),
                    Some(LAN),
                    "the route table read follows this thread's netns"
                );
                assert!(watch.reconcile(false).await.expect("reprogram in place"));
                let moved = owned_of(&kernel_held(&ebpf, &programs).await);
                assert_eq!(
                    moved,
                    Owned::from([
                        (
                            (first, Direction::Ingress),
                            (
                                TcProgram::LanIngressL2,
                                held[&(first, Direction::Ingress)].1
                            )
                        ),
                        (
                            (first, Direction::Egress),
                            (TcProgram::WanEgressL2, held[&(first, Direction::Egress)].1)
                        ),
                    ]),
                    "LAN ingress kept, egress became WAN egress on the same link ids"
                );
                assert_eq!(
                    held_bpf_link_count(),
                    baseline + 2,
                    "reprogram must not add links"
                );
                assert_eq!(
                    accept_ra(LAN),
                    "2",
                    "the reprogrammed WAN root gets accept_ra=2"
                );

                // The device disappears: every binding is released and closed.
                netlink.del_link(first).unwrap();
                assert!(watch.reconcile(true).await.expect("release on deletion"));
                assert!(kernel_held(&ebpf, &programs).await.is_empty());
                assert_eq!(
                    held_bpf_link_count(),
                    baseline,
                    "closed link FDs must be dropped"
                );
            });
    });
}
