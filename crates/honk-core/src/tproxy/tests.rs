use super::*;

fn settings(lan: &[&str], host: HostScope) -> Settings {
    Settings {
        port: 12345,
        tproxy_mark: 0x0800_0000,
        bypass_mark: 0x100,
        lan: lan.iter().map(|name| (*name).to_owned()).collect(),
        host,
    }
}

fn rule_lines(script: &str) -> Vec<&str> {
    script
        .lines()
        .filter(|line| line.starts_with('-'))
        .collect()
}

#[test]
fn honk_marks_return_before_any_diversion() {
    let script = restore_script(
        &settings(&["br-lan"], HostScope::All),
        Family::V4,
        &LocalDestinations::Addrtype,
    );
    let rules = rule_lines(&script);
    for chain in [PREROUTING_CHAIN, OUTPUT_CHAIN] {
        let own: Vec<_> = rules
            .iter()
            .filter(|line| line.starts_with(&format!("-A {chain} ")))
            .collect();
        assert_eq!(
            own[0],
            &format!("-A {chain} -m mark --mark 0x100 -j RETURN")
        );
        assert_eq!(
            own[1],
            &format!("-A {chain} -m mark --mark 0x40000000/0x40000000 -j RETURN")
        );
        let diversion = own
            .iter()
            .position(|line| line.contains("TPROXY") || line.contains("MARK --set-mark"))
            .unwrap();
        assert!(diversion > 1, "{chain}: {own:?}");
    }
}

#[test]
fn lan_dns_is_diverted_before_local_destinations_return() {
    let script = restore_script(
        &settings(&["br-lan"], HostScope::None),
        Family::V4,
        &LocalDestinations::Addrtype,
    );
    let rules = rule_lines(&script);
    let dns = rules
        .iter()
        .position(|line| line.contains("-p udp --dport 53 -j TPROXY"))
        .unwrap();
    let local = rules
        .iter()
        .position(|line| line == &"-A HONK_PREROUTING -m addrtype --dst-type LOCAL -j RETURN")
        .unwrap();
    assert!(dns < local);
    let output_dns = rules
        .iter()
        .any(|line| line.starts_with("-A HONK_OUTPUT") && line.contains("--dport 53"));
    assert!(!output_dns, "host DNS to a local stub stays local");
}

#[test]
fn hooks_follow_the_configured_interfaces() {
    let script = restore_script(
        &settings(
            &["br-lan", "wlan1"],
            HostScope::Interfaces(vec!["eth0".into()]),
        ),
        Family::V6,
        &LocalDestinations::Addrtype,
    );
    let hooks: Vec<_> = rule_lines(&script)
        .into_iter()
        .filter(|line| line.starts_with("-I "))
        .collect();
    assert_eq!(
        hooks,
        [
            "-I PREROUTING -i br-lan -j HONK_PREROUTING",
            "-I PREROUTING -i wlan1 -j HONK_PREROUTING",
            "-I OUTPUT -o eth0 -j HONK_OUTPUT",
            "-I PREROUTING -i lo -m mark --mark 0x8000000/0x8000000 -j HONK_PREROUTING",
        ]
    );
    assert!(script.contains("-A HONK_PREROUTING -d fe80::/10 -j RETURN"));
    assert!(script.contains("-A HONK_OUTPUT -d ff00::/8 -j RETURN"));
    assert!(script.ends_with("COMMIT\n"));
}

#[test]
fn without_addrtype_local_addresses_of_the_family_return() {
    let local = LocalDestinations::Addresses(vec![
        "192.168.1.1".parse().unwrap(),
        "fd00::1".parse().unwrap(),
    ]);
    let script = restore_script(&settings(&["br-lan"], HostScope::All), Family::V4, &local);
    assert!(!script.contains("addrtype"));
    assert!(script.contains("-A HONK_PREROUTING -d 192.168.1.1/32 -j RETURN"));
    assert!(!script.contains("fd00::1"));
    assert!(script.contains("-A HONK_OUTPUT -o lo -j RETURN"));
    assert!(script.contains("-A HONK_PREROUTING -m pkttype --pkt-type broadcast -j RETURN"));
    let v6 = restore_script(&settings(&["br-lan"], HostScope::All), Family::V6, &local);
    assert!(v6.contains("-A HONK_PREROUTING -d fd00::1/128 -j RETURN"));
}

#[test]
fn lan_only_never_loops_host_traffic_back() {
    let script = restore_script(
        &settings(&["br-lan"], HostScope::None),
        Family::V4,
        &LocalDestinations::Addrtype,
    );
    assert!(!script.contains("-I OUTPUT"));
    assert!(!script.contains("-i lo"));
}

#[test]
fn only_honk_jumps_are_deleted() {
    let listing = "-P PREROUTING ACCEPT\n\
                   -A PREROUTING -j bw_mangle_PREROUTING\n\
                   -A PREROUTING -i br-lan -j HONK_PREROUTING\n\
                   -A PREROUTING -i lo -m mark --mark 0x8000000/0x8000000 -j HONK_PREROUTING\n\
                   -A PREROUTING -j HONK_PREROUTING_OTHER\n";
    assert_eq!(
        jump_deletions(listing),
        [
            vec!["-D", "PREROUTING", "-i", "br-lan", "-j", "HONK_PREROUTING"],
            vec![
                "-D",
                "PREROUTING",
                "-i",
                "lo",
                "-m",
                "mark",
                "--mark",
                "0x8000000/0x8000000",
                "-j",
                "HONK_PREROUTING",
            ],
        ]
    );
}

#[test]
fn wan_auto_diverts_every_output_interface() {
    let mut global = honk_config::config::GlobalConfig {
        lan_interface: vec!["br-lan".into(), " br-lan ".into()],
        wan_interface: vec!["eth0".into(), "auto".into()],
        so_mark_from_dae: 0x0040_0000,
        ..Default::default()
    };
    let parsed = Settings::from_config(&global);
    assert_eq!(parsed.lan, ["br-lan"]);
    assert_eq!(parsed.host, HostScope::All);
    assert_eq!(parsed.bypass_mark, 0x0040_0000);

    global.wan_interface = vec!["eth1".into(), "eth0".into()];
    assert_eq!(
        Settings::from_config(&global).host,
        HostScope::Interfaces(vec!["eth0".into(), "eth1".into()])
    );
    global.wan_interface.clear();
    assert_eq!(Settings::from_config(&global).host, HostScope::None);
}

mod process_table {
    use super::super::process::{SocketEntry, find_entry};
    use std::net::SocketAddr;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0 100 0 0 10 0\n\
   1: 0F02000A:C350 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000 10123        0 222 1 0 20 4 30 10 -1\n";
    const UDP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
   7: 00000000000000000000000000000000:D431 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 10050        0 333 2 0 0\n\
   8: 0000000000000000FFFF00000F02000A:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 0 2 0 0\n";

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn connected_tcp_matches_both_ends() {
        let client = address("10.0.2.15:50000");
        let server = address("93.184.216.34:443");
        assert_eq!(
            find_entry(TCP, client, Some(server)),
            Some(SocketEntry {
                uid: 10123,
                inode: 222
            })
        );
        assert_eq!(
            find_entry(TCP, client, Some(address("93.184.216.34:80"))),
            None
        );
    }

    #[test]
    fn wildcard_udp_matches_by_port_and_mapped_addresses_canonicalize() {
        assert_eq!(
            find_entry(UDP6, address("10.0.2.15:54321"), None),
            Some(SocketEntry {
                uid: 10050,
                inode: 333
            })
        );
        assert_eq!(
            find_entry(UDP6, address("10.0.2.15:53"), None),
            None,
            "inode zero has no owner to find"
        );
    }
}
