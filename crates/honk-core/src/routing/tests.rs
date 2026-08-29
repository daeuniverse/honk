use super::*;
use honk_config::routing::{RoutingCondition, RoutingOutbound};

#[test]
fn router_clone_shares_compiled_state() {
    let router = Router::new(&[], "direct").unwrap();
    let clone = router.clone();
    assert!(Arc::ptr_eq(&router.routes, &clone.routes));
    assert!(Arc::ptr_eq(
        &router.default_outbound,
        &clone.default_outbound
    ));
}

#[test]
fn test_trie_empty() {
    let trie = BinaryLpmTrie::from_nets(&[]);
    assert!(!trie.matches(&"1.2.3.4".parse().unwrap()));
    assert!(!trie.matches(&"::1".parse().unwrap()));
}

#[test]
fn test_trie_ipv4_exact() {
    let nets: Vec<ipnet::IpNet> = vec!["10.0.0.1/32".parse().unwrap()];
    let trie = BinaryLpmTrie::from_nets(&nets);
    assert!(trie.matches(&"10.0.0.1".parse().unwrap()));
    assert!(!trie.matches(&"10.0.0.2".parse().unwrap()));
}

#[test]
fn test_trie_ipv4_prefix() {
    let nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let trie = BinaryLpmTrie::from_nets(&nets);
    assert!(trie.matches(&"10.1.2.3".parse().unwrap()));
    assert!(trie.matches(&"10.255.255.255".parse().unwrap()));
    assert!(!trie.matches(&"192.168.1.1".parse().unwrap()));
}

#[test]
fn test_trie_ipv4_multi_prefix() {
    let nets: Vec<ipnet::IpNet> = vec![
        "10.0.0.0/8".parse().unwrap(),
        "192.168.0.0/16".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
    ];
    let trie = BinaryLpmTrie::from_nets(&nets);
    assert!(trie.matches(&"10.1.2.3".parse().unwrap()));
    assert!(trie.matches(&"192.168.1.1".parse().unwrap()));
    assert!(trie.matches(&"172.16.0.1".parse().unwrap()));
    assert!(trie.matches(&"172.31.255.255".parse().unwrap()));
    assert!(!trie.matches(&"8.8.8.8".parse().unwrap()));
    assert!(!trie.matches(&"100.64.0.1".parse().unwrap()));
}

#[test]
fn test_trie_ipv6_exact() {
    let nets: Vec<ipnet::IpNet> = vec!["2001:db8::1/128".parse().unwrap()];
    let trie = BinaryLpmTrie::from_nets(&nets);
    assert!(trie.matches(&"2001:db8::1".parse().unwrap()));
    assert!(!trie.matches(&"2001:db8::2".parse().unwrap()));
}

#[test]
fn test_trie_ipv6_prefix() {
    let nets: Vec<ipnet::IpNet> = vec!["2001:db8::/32".parse().unwrap()];
    let trie = BinaryLpmTrie::from_nets(&nets);
    assert!(trie.matches(&"2001:db8::1".parse().unwrap()));
    assert!(trie.matches(&"2001:db8:ffff::1".parse().unwrap()));
    assert!(!trie.matches(&"2001:db9::1".parse().unwrap()));
}

#[test]
fn test_trie_ipv4_wrong_family_rejected() {
    let trie = BinaryLpmTrie::from_nets(&["10.0.0.0/8".parse().unwrap()]);
    // IPv6 address should not match an IPv4-only trie
    assert!(!trie.matches(&"::ffff:10.0.0.1".parse().unwrap()));
}
#[test]
fn test_trie_mixed_families() {
    let nets: Vec<ipnet::IpNet> = vec![
        "10.0.0.0/8".parse().unwrap(),
        "2001:db8::/32".parse().unwrap(),
    ];
    let trie = BinaryLpmTrie::from_nets(&nets);
    assert!(trie.matches(&"10.1.2.3".parse().unwrap()));
    assert!(trie.matches(&"2001:db8::1".parse().unwrap()));
    assert!(!trie.matches(&"2001:db9::1".parse().unwrap()));
}

#[test]
fn test_empty_router() {
    let router = Router::new(&[], "direct").unwrap();
    assert_eq!(router.route_count(), 0);

    let conn = ConnectionInfo {
        domain: Some("google.com".into()),
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 12345,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };

    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_domain_suffix_route() {
    let rules = vec![RoutingRule {
        name: "google-proxy".into(),
        condition: RoutingCondition {
            domain_suffix: vec!["google.com".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    assert_eq!(router.route_count(), 1);

    let conn = ConnectionInfo {
        domain: Some("www.google.com".into()),
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 12345,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };

    assert_eq!(router.route(&conn), "proxy");
}

#[test]
fn test_sniffed_domain_miss_falls_through_to_ip_rule() {
    let rules = vec![
        RoutingRule {
            name: "known-domain".into(),
            condition: RoutingCondition {
                domain_suffix: vec!["known.example".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("proxy".into()),
            priority: 0,
            must: false,
            mark: 0,
        },
        RoutingRule {
            name: "https-by-port".into(),
            condition: RoutingCondition {
                port: vec!["443".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("direct".into()),
            priority: 1,
            must: false,
            mark: 0,
        },
    ];
    let router = Router::new(&rules, "block").unwrap();
    let conn = ConnectionInfo {
        domain: Some("other.example".into()),
        dst_ip: "203.0.113.10".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.0.2.10".parse().unwrap(),
        src_port: 12345,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };

    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_ip_cidr_route() {
    let rules = vec![RoutingRule {
        name: "private-direct".into(),
        condition: RoutingCondition {
            ip: vec!["10.0.0.0/8".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("direct".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "proxy").unwrap();

    let private_conn = ConnectionInfo {
        domain: None,
        dst_ip: "10.1.2.3".parse().unwrap(),
        dst_port: 80,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 12345,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };

    let public_conn = ConnectionInfo {
        domain: Some("google.com".into()),
        dst_ip: "8.8.8.8".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 12346,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };

    assert_eq!(router.route(&private_conn), "direct");
    assert_eq!(router.route(&public_conn), "proxy");
}

#[test]
fn test_port_route() {
    let rules = vec![RoutingRule {
        name: "web-traffic".into(),
        condition: RoutingCondition {
            port: vec!["80".into(), "443".into(), "8080-8090".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();

    let web_conn = ConnectionInfo {
        domain: None,
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 12345,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };

    let ssh_conn = ConnectionInfo {
        domain: None,
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 22,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 12346,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };

    assert_eq!(router.route(&web_conn), "proxy");
    assert_eq!(router.route(&ssh_conn), "direct");
}

#[test]
fn test_priority_ordering() {
    let rules = vec![
        RoutingRule {
            name: "low-priority".into(),
            condition: RoutingCondition {
                domain_suffix: vec![".com".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("proxy1".into()),
            priority: 100,
            must: false,
            mark: 0,
        },
        RoutingRule {
            name: "high-priority".into(),
            condition: RoutingCondition {
                domain_suffix: vec!["google.com".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("proxy2".into()),
            priority: 0,
            must: false,
            mark: 0,
        },
    ];

    let router = Router::new(&rules, "direct").unwrap();

    let conn = ConnectionInfo {
        domain: Some("www.google.com".into()),
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 12345,
        protocol: "tcp",
        process_name: None,
        mac: None,
        dscp: None,
    };

    // Should match the higher-priority rule (priority 0)
    assert_eq!(router.route(&conn), "proxy2");
}

#[test]
fn test_geosite_cn_route() {
    let rules = vec![RoutingRule {
        name: "geosite-cn-direct".into(),
        condition: RoutingCondition {
            geosite: vec!["cn".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("direct".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "proxy").unwrap();

    for domain in ["www.jd.com", "baidu.com", "www.qq.com", "www.163.com"] {
        let conn = ConnectionInfo {
            domain: Some(domain.into()),
            dst_ip: "1.2.3.4".parse().unwrap(),
            dst_port: 443,
            src_ip: "10.88.0.2".parse().unwrap(),
            src_port: 12345,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        };
        assert_eq!(router.route(&conn), "direct", "failed for {}", domain);
    }
}

#[test]
fn test_glob_to_regex() {
    assert_eq!(glob_to_regex("*.google.com"), r"^.*\.google\.com$");
    assert_eq!(glob_to_regex("test?.com"), r"^test.\.com$");
    assert_eq!(glob_to_regex("exact.com"), r"^exact\.com$");
}

#[test]
fn test_port_range() {
    let r = PortRange {
        start: 8000,
        end: 9000,
    };
    assert!(r.contains(8000));
    assert!(r.contains(8500));
    assert!(r.contains(9000));
    assert!(!r.contains(7999));
    assert!(!r.contains(9001));
}

fn make_conn(process_name: Option<&str>, mac: Option<&str>) -> ConnectionInfo {
    ConnectionInfo {
        domain: None,
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        src_ip: "192.168.1.1".parse().unwrap(),
        src_port: 12345,
        protocol: "tcp",
        process_name: process_name.map(|s| s.to_string()),
        mac: mac.map(|s| s.to_string()),
        dscp: None,
    }
}

#[test]
fn test_mac_route_matching() {
    let rules = vec![RoutingRule {
        name: "mac-proxy".into(),
        condition: RoutingCondition {
            mac: vec!["aa:bb:cc:dd:ee:ff".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();

    assert_eq!(
        router.route(&make_conn(None, Some("aa:bb:cc:dd:ee:ff"))),
        "proxy"
    );
    assert_eq!(
        router.route(&make_conn(None, Some("AA-BB-CC-DD-EE-FF"))),
        "proxy"
    );
    assert_eq!(
        router.route(&make_conn(None, Some("aabb.ccdd.eeff"))),
        "proxy"
    );
    assert_eq!(
        router.route(&make_conn(None, Some("aabbccddeeff"))),
        "proxy"
    );
    assert_eq!(
        router.route(&make_conn(None, Some("00:11:22:33:44:55"))),
        "direct"
    );
    assert_eq!(router.route(&make_conn(None, None)), "direct");
}

#[test]
fn test_process_name_route_matching() {
    let rules = vec![RoutingRule {
        name: "curl-proxy".into(),
        condition: RoutingCondition {
            process_name: vec!["curl".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();

    assert_eq!(
        router.route(&make_conn(Some("/usr/bin/curl"), None)),
        "proxy"
    );
    assert_eq!(router.route(&make_conn(Some("curl"), None)), "proxy");
    assert_eq!(router.route(&make_conn(Some("wget"), None)), "direct");
    assert_eq!(router.route(&make_conn(None, None)), "direct");
}

#[test]
fn test_process_name_route_matching_uses_kernel_comm_limit() {
    let rules = vec![RoutingRule {
        name: "resolved-direct".into(),
        condition: RoutingCondition {
            process_name: vec!["systemd-resolved".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("direct".into()),
        priority: 0,
        must: true,
        mark: 0,
    }];

    let router = Router::new(&rules, "proxy").unwrap();

    assert_eq!(
        router.route(&make_conn(Some("systemd-resolve"), None)),
        "direct"
    );
    assert_eq!(
        router.compiled_routes()[0].process_names,
        vec!["systemd-resolve"]
    );
}

#[test]
fn test_mac_and_process_name_combined() {
    let rules = vec![RoutingRule {
        name: "curl-on-device".into(),
        condition: RoutingCondition {
            process_name: vec!["curl".into()],
            mac: vec!["aa:bb:cc:dd:ee:ff".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();

    assert_eq!(
        router.route(&make_conn(Some("curl"), Some("aa:bb:cc:dd:ee:ff"))),
        "proxy"
    );
    assert_eq!(
        router.route(&make_conn(Some("curl"), Some("00:11:22:33:44:55"))),
        "direct"
    );
    assert_eq!(
        router.route(&make_conn(Some("wget"), Some("aa:bb:cc:dd:ee:ff"))),
        "direct"
    );
    assert_eq!(
        router.route(&make_conn(None, Some("aa:bb:cc:dd:ee:ff"))),
        "direct"
    );
}

#[test]
fn test_normalize_mac() {
    assert_eq!(
        normalize_mac("aa:bb:cc:dd:ee:ff"),
        Some("aa:bb:cc:dd:ee:ff".into())
    );
    assert_eq!(
        normalize_mac("AA-BB-CC-DD-EE-FF"),
        Some("aa:bb:cc:dd:ee:ff".into())
    );
    assert_eq!(
        normalize_mac("aabb.ccdd.eeff"),
        Some("aa:bb:cc:dd:ee:ff".into())
    );
    assert_eq!(
        normalize_mac("aabbccddeeff"),
        Some("aa:bb:cc:dd:ee:ff".into())
    );
    assert_eq!(normalize_mac("aa:bb:cc:dd:ee"), None);
    assert_eq!(normalize_mac("aa:bb:cc:dd:ee:gg"), None);
    assert_eq!(normalize_mac(""), None);
}

#[test]
fn test_domain_exact_route() {
    let rules = vec![RoutingRule {
        name: "exact-google".into(),
        condition: RoutingCondition {
            domain: vec!["google.com".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.domain = Some("google.com".into());
    assert_eq!(router.route(&conn), "proxy");

    conn.domain = Some("www.google.com".into());
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_domain_keyword_route() {
    let rules = vec![RoutingRule {
        name: "keyword-google".into(),
        condition: RoutingCondition {
            domain_keyword: vec!["google".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.domain = Some("www.google.com".into());
    assert_eq!(router.route(&conn), "proxy");

    conn.domain = Some("example.com".into());
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_domain_regex_route() {
    let rules = vec![RoutingRule {
        name: "regex-google".into(),
        condition: RoutingCondition {
            domain_regex: vec![r"^.*\.google\.com$".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.domain = Some("mail.google.com".into());
    assert_eq!(router.route(&conn), "proxy");

    conn.domain = Some("google.com".into());
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_domain_glob_route() {
    let rules = vec![RoutingRule {
        name: "glob-google".into(),
        condition: RoutingCondition {
            domain: vec!["*.google.com".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.domain = Some("www.google.com".into());
    assert_eq!(router.route(&conn), "proxy");

    conn.domain = Some("google.com".into());
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_source_ip_route() {
    let rules = vec![RoutingRule {
        name: "src-lan".into(),
        condition: RoutingCondition {
            source_ip: vec!["192.168.0.0/16".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.src_ip = "192.168.1.1".parse().unwrap();
    assert_eq!(router.route(&conn), "proxy");

    conn.src_ip = "10.0.0.1".parse().unwrap();
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_source_port_route() {
    let rules = vec![RoutingRule {
        name: "src-port".into(),
        condition: RoutingCondition {
            source_port: vec!["12345".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.src_port = 12345;
    assert_eq!(router.route(&conn), "proxy");

    conn.src_port = 54321;
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_protocol_route() {
    let rules = vec![RoutingRule {
        name: "udp-rule".into(),
        condition: RoutingCondition {
            protocol: vec!["udp".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.protocol = "udp";
    assert_eq!(router.route(&conn), "proxy");

    conn.protocol = "tcp";
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_ip_version_route() {
    let rules = vec![RoutingRule {
        name: "ipv6-only".into(),
        condition: RoutingCondition {
            ip_version: vec!["6".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.dst_ip = "2001:db8::1".parse().unwrap();
    assert_eq!(router.route(&conn), "proxy");

    conn.dst_ip = "1.1.1.1".parse().unwrap();
    assert_eq!(router.route(&conn), "direct");
}
#[test]
fn test_mixed_family_ip_route() {
    let rules = vec![RoutingRule {
        name: "mixed-family".into(),
        condition: RoutingCondition {
            ip: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.dst_ip = "10.1.2.3".parse().unwrap();
    assert_eq!(router.route(&conn), "proxy");

    conn.dst_ip = "2001:db8::1".parse().unwrap();
    assert_eq!(router.route(&conn), "proxy");

    conn.dst_ip = "2001:db9::1".parse().unwrap();
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_dscp_route() {
    let rules = vec![RoutingRule {
        name: "dscp-ef".into(),
        condition: RoutingCondition {
            dscp: vec!["46".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.dscp = Some(46);
    assert_eq!(router.route(&conn), "proxy");

    conn.dscp = Some(0);
    assert_eq!(router.route(&conn), "direct");

    conn.dscp = None;
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_geoip_private_route() {
    let rules = vec![RoutingRule {
        name: "private-direct".into(),
        condition: RoutingCondition {
            geo_ip: vec!["private".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("direct".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "proxy").unwrap();
    let mut conn = make_conn(None, None);
    conn.dst_ip = "192.168.1.1".parse().unwrap();
    assert_eq!(router.route(&conn), "direct");

    conn.dst_ip = "10.0.0.1".parse().unwrap();
    assert_eq!(router.route(&conn), "direct");

    conn.dst_ip = "8.8.8.8".parse().unwrap();
    assert_eq!(router.route(&conn), "proxy");
}

#[test]
#[allow(clippy::let_unit_value)]
fn test_geosite_route() {
    // FIXME: Audit that the environment access only happens in single-threaded code.
    let _ = unsafe {
        std::env::set_var(
            "DAE_LOCATION_ASSET",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../.."),
        )
    };

    let rules = vec![RoutingRule {
        name: "geosite-cn".into(),
        condition: RoutingCondition {
            geosite: vec!["cn".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("direct".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "proxy").unwrap();
    let mut conn = make_conn(None, None);
    // baidu.com is in geosite:cn
    conn.domain = Some("www.baidu.com".into());
    assert_eq!(router.route(&conn), "direct");

    conn.domain = Some("www.google.com".into());
    assert_eq!(router.route(&conn), "proxy");
}

#[test]
fn test_must_flag_on_outbound() {
    let rules = vec![RoutingRule {
        name: "must-direct".into(),
        condition: RoutingCondition {
            ip: vec!["10.0.0.0/8".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("direct(must)".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "proxy").unwrap();
    let mut conn = make_conn(None, None);
    conn.dst_ip = "10.0.0.1".parse().unwrap();
    let result = router.route_full(&conn).unwrap();
    assert_eq!(result.outbound_name, "direct");
    assert!(result.must);
}

#[test]
fn test_must_flag_on_rule() {
    let rules = vec![RoutingRule {
        name: "must-rule".into(),
        condition: RoutingCondition {
            ip: vec!["10.0.0.0/8".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("direct".into()),
        priority: 0,
        must: true,
        mark: 0,
    }];

    let router = Router::new(&rules, "proxy").unwrap();
    let mut conn = make_conn(None, None);
    conn.dst_ip = "10.0.0.1".parse().unwrap();
    let result = router.route_full(&conn).unwrap();
    assert_eq!(result.outbound_name, "direct");
    assert!(result.must);
}

#[test]
fn test_route_with_must() {
    let rules = vec![
        RoutingRule {
            name: "must-direct".into(),
            condition: RoutingCondition {
                ip: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("direct(must)".into()),
            priority: 0,
            must: false,
            mark: 0,
        },
        RoutingRule {
            name: "plain-proxy".into(),
            condition: RoutingCondition {
                ip: vec!["192.168.0.0/16".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("proxy".into()),
            priority: 1,
            must: false,
            mark: 0,
        },
    ];
    let router = Router::new(&rules, "proxy").unwrap();
    let mut conn = make_conn(None, None);

    // (must) rule match → flag set.
    conn.dst_ip = "10.0.0.1".parse().unwrap();
    assert_eq!(router.route_with_must(&conn), ("direct", true));

    // Plain rule match → flag clear.
    conn.dst_ip = "192.168.1.1".parse().unwrap();
    assert_eq!(router.route_with_must(&conn), ("proxy", false));

    // Default-outbound fallback never carries must.
    conn.dst_ip = "8.8.8.8".parse().unwrap();
    assert_eq!(router.route_with_must(&conn), ("proxy", false));
}

#[test]
fn test_mark_propagation() {
    let rules = vec![RoutingRule {
        name: "marked-proxy".into(),
        condition: RoutingCondition {
            port: vec!["443".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 42,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.dst_port = 443;
    let result = router.route_full(&conn).unwrap();
    assert_eq!(result.outbound_name, "proxy");
    assert_eq!(result.mark, 42);
}

#[test]
fn test_combined_conditions_and_semantics() {
    let rules = vec![RoutingRule {
        name: "combo".into(),
        condition: RoutingCondition {
            domain_suffix: vec!["google.com".into()],
            port: vec!["443".into()],
            protocol: vec!["tcp".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];

    let router = Router::new(&rules, "direct").unwrap();
    let mut conn = make_conn(None, None);
    conn.domain = Some("www.google.com".into());
    conn.dst_port = 443;
    conn.protocol = "tcp";
    assert_eq!(router.route(&conn), "proxy");

    conn.domain = None;
    assert_eq!(router.route(&conn), "direct");

    conn.domain = Some("www.google.com".into());
    conn.dst_port = 80;
    assert_eq!(router.route(&conn), "direct");

    conn.dst_port = 443;
    conn.protocol = "udp";
    assert_eq!(router.route(&conn), "direct");
}

#[test]
fn test_geosite_matcher_semantics() {
    let domains = vec![
        GeositeDomain::Full("Example.COM".into()),
        GeositeDomain::Domain("google.com".into()),
        GeositeDomain::Keyword("Tube".into()),
        GeositeDomain::Regex(Regex::new(r"^ads\.").unwrap()),
    ];
    let m = GeositeMatcher::build(&domains);

    // Full: case-insensitive exact only
    assert!(m.matches("example.com"));
    assert!(m.matches("EXAMPLE.com"));
    assert!(!m.matches("www.example.com"));

    // Domain: itself + dot-boundary sub-domains, case-insensitive
    assert!(m.matches("google.com"));
    assert!(m.matches("WWW.Google.COM"));
    assert!(m.matches("a.b.google.com"));
    assert!(!m.matches("notgoogle.com"));
    assert!(!m.matches("google.com.evil.org"));

    // Keyword: case-sensitive substring (historical semantics)
    assert!(m.matches("www.YouTube.com"));
    assert!(!m.matches("www.youtube.com"));

    // Regex: matched against the original domain
    assert!(m.matches("ads.example.com"));
    assert!(!m.matches("www.ads.example.com"));

    // Empty matcher never matches
    assert!(!GeositeMatcher::default().matches("example.com"));
}

#[test]
fn test_route_domain_matches_suffix_and_skips_ip_port_only() {
    let rules = vec![
        // Pure IP rule — must NOT match a domain-only probe even if
        // 0.0.0.0 happens to sit inside a broad CIDR.
        RoutingRule {
            name: "ip-private".into(),
            condition: RoutingCondition {
                ip: vec!["0.0.0.0/0".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        },
        // Pure port rule — domain-only probes have port 0, but even if
        // they did match, route_domain skips non-domain rules.
        RoutingRule {
            name: "port-proxy".into(),
            condition: RoutingCondition {
                port: vec!["443".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("proxy".into()),
            priority: 1,
            must: false,
            mark: 0,
        },
        RoutingRule {
            name: "suffix-google".into(),
            condition: RoutingCondition {
                domain_suffix: vec!["google.com".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("google-group".into()),
            priority: 2,
            must: false,
            mark: 0,
        },
    ];

    let router = Router::new(&rules, "final-group").unwrap();

    let m = router.route_domain("www.google.com").expect("suffix match");
    assert_eq!(m.rule_name, "suffix-google");
    assert_eq!(m.outbound_name, "google-group");

    // No domain rule → None (do NOT fall through to default / IP / port).
    assert!(router.route_domain("www.example.com").is_none());
    assert!(router.route_domain("analytics.tiktok.com").is_none());
}

#[test]
fn test_route_domain_does_not_claim_default_as_match() {
    let rules = vec![RoutingRule {
        name: "cn-suffix".into(),
        condition: RoutingCondition {
            domain_suffix: vec![".cn".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("direct".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];
    let router = Router::new(&rules, "🍥 final").unwrap();

    assert_eq!(
        router.route_domain("baidu.cn").map(|m| m.outbound_name),
        Some("direct")
    );
    // Unmatched domain must not pretend to match the default outbound.
    assert!(router.route_domain("example.org").is_none());
    // Real connection-time routing still returns the default via route().
    let mut conn = make_conn(None, None);
    conn.domain = Some("example.org".into());
    conn.dst_ip = "1.2.3.4".parse().unwrap();
    conn.dst_port = 443;
    assert_eq!(router.route(&conn), "🍥 final");
}

mod negation {
    use super::*;
    use honk_config::routing::RoutingNotCondition;

    fn rule(name: &str, not: RoutingNotCondition, outbound: &str) -> RoutingRule {
        RoutingRule {
            name: name.into(),
            condition: RoutingCondition {
                not,
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple(outbound.into()),
            priority: 0,
            must: false,
            mark: 0,
        }
    }

    fn conn() -> ConnectionInfo {
        ConnectionInfo {
            domain: None,
            dst_ip: "1.1.1.1".parse().unwrap(),
            dst_port: 443,
            src_ip: "192.168.1.1".parse().unwrap(),
            src_port: 12345,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        }
    }

    fn not(pairs: &[(&str, &str)]) -> RoutingNotCondition {
        let mut n = RoutingNotCondition::default();
        for (field, value) in pairs {
            let values = vec![value.to_string()];
            match *field {
                "domain" => n.domain = values,
                "domain_suffix" => n.domain_suffix = values,
                "domain_keyword" => n.domain_keyword = values,
                "domain_regex" => n.domain_regex = values,
                "ip" => n.ip = values,
                "source_ip" => n.source_ip = values,
                "port" => n.port = values,
                "source_port" => n.source_port = values,
                "protocol" => n.protocol = values,
                "process_name" => n.process_name = values,
                "mac" => n.mac = values,
                "geo_ip" => n.geo_ip = values,
                "geosite" => n.geosite = values,
                "ip_version" => n.ip_version = values,
                "dscp" => n.dscp = values,
                other => panic!("unknown field {other}"),
            }
        }
        n
    }

    fn check(not_cond: RoutingNotCondition, matching: &ConnectionInfo, vetoed: &ConnectionInfo) {
        let router = Router::new(&[rule("neg", not_cond, "proxy")], "direct").unwrap();
        assert_eq!(router.route(matching), "proxy");
        assert_eq!(router.route(vetoed), "direct");
    }

    #[test]
    fn test_negated_dport() {
        let mut hit = conn();
        hit.dst_port = 80;
        let mut veto = conn();
        veto.dst_port = 53;
        check(not(&[("port", "53")]), &hit, &veto);
    }

    #[test]
    fn test_negated_sport() {
        let mut hit = conn();
        hit.src_port = 8080;
        let mut veto = conn();
        veto.src_port = 53;
        check(not(&[("source_port", "53")]), &hit, &veto);
    }

    #[test]
    fn test_negated_dip() {
        let mut hit = conn();
        hit.dst_ip = "8.8.8.8".parse().unwrap();
        let mut veto = conn();
        veto.dst_ip = "10.1.2.3".parse().unwrap();
        check(not(&[("ip", "10.0.0.0/8")]), &hit, &veto);
    }

    #[test]
    fn test_negated_sip() {
        let mut hit = conn();
        hit.src_ip = "10.0.0.1".parse().unwrap();
        let mut veto = conn();
        veto.src_ip = "192.168.1.5".parse().unwrap();
        check(not(&[("source_ip", "192.168.0.0/16")]), &hit, &veto);
    }

    #[test]
    fn test_negated_l4proto() {
        let mut veto = conn();
        veto.protocol = "udp";
        check(not(&[("protocol", "udp")]), &conn(), &veto);
    }

    #[test]
    fn test_negated_ipversion() {
        let mut veto = conn();
        veto.dst_ip = "2001:db8::1".parse().unwrap();
        check(not(&[("ip_version", "6")]), &conn(), &veto);
    }

    #[test]
    fn test_negated_pname() {
        let mut hit = conn();
        hit.process_name = Some("/usr/bin/curl".into());
        let mut veto = conn();
        veto.process_name = Some("wget".into());
        check(not(&[("process_name", "wget")]), &hit, &veto);
        let mut resolved = conn();
        resolved.process_name = Some("systemd-resolve".into());
        check(
            not(&[("process_name", "systemd-resolved")]),
            &hit,
            &resolved,
        );
    }

    #[test]
    fn test_negated_mac() {
        let mut hit = conn();
        hit.mac = Some("aa:bb:cc:dd:ee:ff".into());
        let mut veto = conn();
        veto.mac = Some("00:11:22:33:44:55".into());
        check(not(&[("mac", "00:11:22:33:44:55")]), &hit, &veto);
    }

    #[test]
    fn test_negated_dscp() {
        let mut hit = conn();
        hit.dscp = Some(0);
        let mut veto = conn();
        veto.dscp = Some(4);
        check(not(&[("dscp", "4")]), &hit, &veto);
    }

    #[test]
    fn test_negated_domain_suffix() {
        let mut hit = conn();
        hit.domain = Some("y.com".into());
        let mut veto = conn();
        veto.domain = Some("www.x.com".into());
        check(not(&[("domain_suffix", "x.com")]), &hit, &veto);

        // Unknown domain cannot prove the negated matcher: treated as "not x".
        let router = Router::new(
            &[rule("neg", not(&[("domain_suffix", "x.com")]), "proxy")],
            "direct",
        )
        .unwrap();
        assert_eq!(router.route(&conn()), "proxy");
    }

    #[test]
    fn test_negated_domain_full_keyword_regex() {
        let mut hit = conn();
        hit.domain = Some("good.com".into());

        let mut veto = conn();
        veto.domain = Some("evil.org".into());
        check(not(&[("domain", "evil.org")]), &hit, &veto);

        let mut veto = conn();
        veto.domain = Some("www.tracker.com".into());
        check(not(&[("domain_keyword", "tracker")]), &hit, &veto);

        let mut veto = conn();
        veto.domain = Some("bad.example.com".into());
        check(not(&[("domain_regex", r"^bad\.")]), &hit, &veto);
    }

    #[test]
    fn test_negated_geoip_private() {
        let mut hit = conn();
        hit.dst_ip = "8.8.8.8".parse().unwrap();
        let mut veto = conn();
        veto.dst_ip = "192.168.1.1".parse().unwrap();
        check(not(&[("geo_ip", "private")]), &hit, &veto);
    }

    #[test]
    fn test_negated_geosite_matcher() {
        // Build the base route without geo assets; then swap in a synthetic
        // negated geosite matcher (the dat-backed positive side is covered
        // by test_geosite_route above).
        let router =
            Router::new(&[rule("neg", not(&[("port", "53")]), "proxy")], "direct").unwrap();
        let route = &router.compiled_routes()[0];
        let domains = vec![GeositeDomain::Domain("x.com".into())];
        let route = CompiledRoute {
            not_ports: Vec::new(),
            not_geosite_domains: domains.clone(),
            not_geosite_matcher: GeositeMatcher::build(&domains),
            ..route.clone()
        };
        let router = Router {
            routes: vec![route].into(),
            default_outbound: "direct".into(),
        };
        let mut veto = conn();
        veto.domain = Some("www.x.com".into());
        assert_eq!(router.route(&veto), "direct");
        let mut hit = conn();
        hit.domain = Some("y.com".into());
        assert_eq!(router.route(&hit), "proxy");
        // Unknown domain never vetoes a negated geosite matcher.
        assert_eq!(router.route(&conn()), "proxy");
    }

    #[test]
    fn test_production_rule_sip_and_not_dport() {
        let rules = vec![
            RoutingRule {
                name: "host24-not-dns".into(),
                condition: RoutingCondition {
                    source_ip: vec!["10.10.10.24/32".into()],
                    not: not(&[("port", "53")]),
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("direct".into()),
                priority: 0,
                must: true,
                mark: 0,
            },
            RoutingRule {
                name: "catch-all".into(),
                condition: RoutingCondition {
                    source_ip: vec!["10.0.0.0/8".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("proxy".into()),
                priority: 1,
                must: false,
                mark: 0,
            },
        ];
        let router = Router::new(&rules, "block").unwrap();

        let mut dns_flow = conn();
        dns_flow.src_ip = "10.10.10.24".parse().unwrap();
        dns_flow.dst_port = 53;
        let m = router.route_full(&dns_flow).unwrap();
        assert_eq!(m.rule_name, "catch-all");

        let mut web_flow = conn();
        web_flow.src_ip = "10.10.10.24".parse().unwrap();
        web_flow.dst_port = 80;
        let m = router.route_full(&web_flow).unwrap();
        assert_eq!(m.rule_name, "host24-not-dns");
        assert!(m.must);
    }

    #[test]
    fn test_negated_only_rule_counts_as_conditioned() {
        // A rule whose only matcher is negated must not degrade to an
        // unconditional match-all bypassing the has_conditions guard.
        let router =
            Router::new(&[rule("neg", not(&[("port", "53")]), "proxy")], "direct").unwrap();
        let mut c = conn();
        c.dst_port = 53;
        assert_eq!(router.route(&c), "direct");
        c.dst_port = 80;
        assert_eq!(router.route(&c), "proxy");
    }
}

/// dae configs write bare IPs in dip/sip; they must parse as host routes
/// rather than silently dropping the matcher.
#[test]
fn bare_ip_in_dip_sip_parses_as_host_route() {
    use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
    let rules = vec![RoutingRule {
        name: "bare".into(),
        condition: RoutingCondition {
            ip: vec!["10.9.9.9".into()],
            source_ip: vec!["192.168.222.2".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("direct".into()),
        priority: 0,
        must: true,
        mark: 0,
    }];
    let router = Router::new(&rules, "proxy").unwrap();
    let hit = |ip: &str, sip: &str| {
        let conn = ConnectionInfo {
            domain: None,
            dst_ip: ip.parse().unwrap(),
            dst_port: 80,
            src_ip: sip.parse().unwrap(),
            src_port: 1000,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        };
        router.route(&conn).to_string()
    };
    assert_eq!(hit("10.9.9.9", "192.168.222.2"), "direct");
    assert_eq!(hit("10.9.9.8", "192.168.222.2"), "proxy");
    assert_eq!(hit("10.9.9.9", "192.168.222.3"), "proxy");
}
