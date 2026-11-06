use super::*;
use crate::ebpf::test_support::{LinkExt, link, planned};

fn write_names(owed: &[SysctlWrite]) -> Vec<(SysctlKey, &str, bool)> {
    owed.iter()
        .map(|w| (w.key, w.name.as_str(), w.reassert))
        .collect()
}

#[test]
fn sysctl_is_written_on_sight_and_once_more_after_udev_then_left_alone() {
    let t0 = tokio::time::Instant::now();
    let after = |ms: u64| t0 + std::time::Duration::from_millis(ms);
    let links = || vec![link(2, "wan.100"), link(3, "br0"), link(4, "eth1")];
    let mut tracker = SysctlTracker::default();
    let topology = Topology {
        links: links(),
        default_route: None,
    };
    let plan = planned(&["br0", "eth1"], &["wan.100"], &topology);
    assert_eq!(
        write_names(&tracker.claim(&plan, &topology, t0)),
        [
            (SysctlKey::AcceptRa, "wan.100", false),
            (SysctlKey::RpFilter, "br0", false)
        ]
    );
    assert_eq!(tracker.due(), Some(after(1000)));
    // Inside udev's window nothing is owed, failed or not.
    assert!(tracker.claim(&plan, &topology, after(999)).is_empty());
    // After it, the second and last write of each.
    assert_eq!(
        write_names(&tracker.claim(&plan, &topology, after(1000))),
        [
            (SysctlKey::AcceptRa, "wan.100", true),
            (SysctlKey::RpFilter, "br0", true)
        ]
    );
    assert_eq!(tracker.due(), None);
    assert!(tracker.claim(&plan, &topology, after(60_000)).is_empty());

    // The WAN device is recreated under a new ifindex: it starts over.
    let mut recreated = links();
    recreated[0].ifindex = NonZeroU32::new(9).unwrap();
    let topology = Topology {
        links: recreated,
        default_route: None,
    };
    let plan = planned(&["br0", "eth1"], &["wan.100"], &topology);
    let owed = tracker.claim(&plan, &topology, after(61_000));
    assert_eq!(
        write_names(&owed),
        [(SysctlKey::AcceptRa, "wan.100", false)]
    );
    assert_eq!(owed[0].ifindex.get(), 9);

    // The first LAN vanishes: rp_filter moves to the first one that exists.
    let topology = Topology {
        links: vec![link(9, "wan.100"), link(4, "eth1")],
        default_route: None,
    };
    let plan = planned(&["br0", "eth1"], &["wan.100"], &topology);
    assert_eq!(
        write_names(&tracker.claim(&plan, &topology, after(61_500))),
        [(SysctlKey::RpFilter, "eth1", false)]
    );
    // Everything gone: the tracker forgets it, so a return is written again.
    let topology = Topology::default();
    let plan = planned(&["br0"], &["wan.100"], &topology);
    assert!(tracker.claim(&plan, &topology, after(62_000)).is_empty());
    assert!(tracker.attempted.is_empty());
    assert_eq!(tracker.due(), None);
}

#[test]
fn moving_sysctl_targets_cancel_the_old_deadlines_while_devices_remain() {
    let t0 = tokio::time::Instant::now();
    let mut topology = Topology {
        links: vec![link(2, "eth1"), link(3, "wan0"), link(4, "wan1")],
        default_route: Some("wan0".into()),
    };
    let mut tracker = SysctlTracker::default();
    let plan = planned(&["br0", "eth1"], &["auto"], &topology);
    assert_eq!(tracker.claim(&plan, &topology, t0).len(), 2);

    topology.links.push(link(5, "br0"));
    topology.default_route = Some("wan1".into());
    let plan = planned(&["br0", "eth1"], &["auto"], &topology);
    let moved = t0 + std::time::Duration::from_millis(500);
    assert_eq!(
        write_names(&tracker.claim(&plan, &topology, moved)),
        [
            (SysctlKey::AcceptRa, "wan1", false),
            (SysctlKey::RpFilter, "br0", false),
        ]
    );
    assert_eq!(tracker.due(), Some(moved + SYSCTL_REASSERT_AFTER));
    assert_eq!(
        tracker
            .claim(&plan, &topology, moved + SYSCTL_REASSERT_AFTER)
            .len(),
        2
    );
    assert_eq!(tracker.due(), None);
}

#[test]
fn rp_filter_skips_refused_lan_entries_including_auto() {
    let topology = Topology {
        links: vec![link(1, "lo").arphrd(libc::ARPHRD_LOOPBACK), link(2, "eth1")],
        default_route: Some("lo".into()),
    };
    for first in ["lo", "auto"] {
        let plan = planned(&[first, "eth1"], &[], &topology);
        let mut tracker = SysctlTracker::default();
        assert_eq!(
            write_names(&tracker.claim(&plan, &topology, tokio::time::Instant::now())),
            [(SysctlKey::RpFilter, "eth1", false)],
            "{first}"
        );
    }
}

#[test]
fn a_wan_that_is_also_lan_gets_accept_ra_once() {
    let topology = Topology {
        links: vec![link(2, "eth0")],
        default_route: None,
    };
    let plan = planned(&["eth0"], &["eth0"], &topology);
    let mut tracker = SysctlTracker::default();
    assert_eq!(
        write_names(&tracker.claim(&plan, &topology, tokio::time::Instant::now())),
        [
            (SysctlKey::AcceptRa, "eth0", false),
            (SysctlKey::RpFilter, "eth0", false)
        ]
    );
}
