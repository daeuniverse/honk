#[allow(unused_imports)]
use crate::parser::parse_dae_config;
use crate::parser::parse_dae_config_with_diagnostics;

#[cfg(test)]
mod parser_tests {
    use crate::parser::{
        parse_dae_config, parse_dae_config_with_detailed_diagnostics,
        parse_dae_config_with_diagnostics,
    };
    use base64::Engine as _;

    #[test]
    fn test_parse_example_dae() {
        let example = include_str!("../../../../config.dae");
        let result = parse_dae_config(example);
        assert!(
            result.is_ok(),
            "Failed to parse example.dae: {:?}",
            result.err()
        );
        let config = result.unwrap();
        assert!(!config.global.tcp_check_url.is_empty());
        assert!(!config.dns.upstream.is_empty());
    }

    #[test]
    fn test_parse_global_section() {
        let input = r#"
global {
    tproxy_port: 12345
    log_level: info
    log_file: '/var/log/honk/honk.log'
    dial_mode: domain
    nfqueue_enable: false
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.global.tproxy_port, 12345);
        assert_eq!(config.global.log_level, "info");
        assert_eq!(config.global.log_file, "/var/log/honk/honk.log");
        assert_eq!(config.global.dial_mode, "domain");
        assert!(!config.global.nfqueue_enable);
        assert!(parse_dae_config("global {}").unwrap().global.nfqueue_enable);
    }

    #[test]
    fn test_millisecond_durations_keep_the_default_and_return_diagnostics() {
        for (value, expected) in [("50ms", 50), ("0ms", 0), ("0.5s", 500), ("50", 50)] {
            let input = format!(
                "global {{\n    check_tolerance: {value}\n    sniffing_timeout: {value}\n}}"
            );
            let mut diagnostics = Vec::new();
            let config = parse_dae_config_with_diagnostics(&input, &mut diagnostics).unwrap();
            assert_eq!(config.global.check_tolerance_ms, expected, "{value}");
            assert_eq!(config.global.sniffing_timeout_ms, expected, "{value}");
            assert!(diagnostics.is_empty(), "{value}: {diagnostics:?}");
        }

        for value in [
            "1m", "2h", "1min", "abc", "-5ms", "-0.5s", "1.5ms", "inf", "nan", "",
        ] {
            for (setting, key, default) in [
                ("global.check_tolerance", "check_tolerance", 50),
                ("global.sniffing_timeout", "sniffing_timeout", 30),
            ] {
                let input = format!("global {{\n    {key}: {value}\n}}");
                let mut diagnostics = Vec::new();
                let config = parse_dae_config_with_diagnostics(&input, &mut diagnostics).unwrap();
                let observed = match key {
                    "check_tolerance" => config.global.check_tolerance_ms,
                    _ => config.global.sniffing_timeout_ms,
                };
                assert_eq!(observed, default, "{setting} for {value}");
                assert_eq!(diagnostics.len(), 1, "{setting} for {value}");
                assert_eq!(diagnostics[0].setting, setting);
            }
        }
    }

    #[test]
    fn test_timer_diagnostic_survives_later_parse_error() {
        let mut diagnostics = Vec::new();
        let result = parse_dae_config_with_diagnostics(
            "global {\n check_tolerance: abc\n nfqueue_enable: invalid\n}",
            &mut diagnostics,
        );
        assert!(result.is_err());
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].setting, "global.check_tolerance");
    }

    #[test]
    fn test_from_file_preserves_timer_diagnostics() {
        let file = tempfile::Builder::new().suffix(".dae").tempfile().unwrap();
        std::fs::write(file.path(), "global {\n    check_tolerance: abc\n}").unwrap();

        let mut diagnostics = Vec::new();
        let config = crate::Config::from_file_with_diagnostics(
            file.path().to_str().unwrap(),
            &mut diagnostics,
        )
        .unwrap();
        assert_eq!(config.global.check_tolerance_ms, 50);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].setting, "global.check_tolerance");
    }

    #[test]
    fn test_structured_fallback_discards_only_abandoned_dae_diagnostics() {
        let file = tempfile::Builder::new().suffix(".dae").tempfile().unwrap();
        std::fs::write(
            file.path(),
            "ignored: |\n  global {\n    check_tolerance: abc\n    nfqueue_enable: invalid\n  }\n\
             global:\n  check_tolerance_ms: 75\n",
        )
        .unwrap();
        let mut diagnostics = Vec::new();
        parse_dae_config_with_diagnostics("global {\n sniffing_timeout: 2h\n}", &mut diagnostics)
            .unwrap();
        let previous = diagnostics.clone();
        let config = crate::Config::from_file_with_diagnostics(
            file.path().to_str().unwrap(),
            &mut diagnostics,
        )
        .unwrap();
        assert_eq!(config.global.check_tolerance_ms, 75);
        assert_eq!(diagnostics, previous);
    }

    #[test]
    fn test_unrelated_scalar_cannot_hide_dae_semantic_failure() {
        let file = tempfile::Builder::new().suffix(".dae").tempfile().unwrap();
        std::fs::write(
            file.path(),
            include_str!("../../tests/fixtures/invalid_nfqueue_with_scalar.dae"),
        )
        .unwrap();
        let mut diagnostics = Vec::new();
        let error = crate::Config::from_file_with_detailed_diagnostics(
            file.path().to_str().unwrap(),
            &mut diagnostics,
        )
        .unwrap_err();
        assert_eq!(error.category, crate::error::ErrorCategory::Parse);
        assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code == "invalid-structured-config")
        );
    }

    #[test]
    fn test_include_preserves_timer_diagnostics() {
        let dir = tempfile::tempdir().unwrap();
        let entry = dir.path().join("config.dae");
        std::fs::write(&entry, "include {\n    timers.dae\n}").unwrap();
        std::fs::write(
            dir.path().join("timers.dae"),
            "global {\n    sniffing_timeout: 1m\n}",
        )
        .unwrap();

        let mut diagnostics = Vec::new();
        let config =
            crate::Config::from_file_with_diagnostics(entry.to_str().unwrap(), &mut diagnostics)
                .unwrap();
        assert_eq!(config.global.sniffing_timeout_ms, 30);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].setting, "global.sniffing_timeout");
    }

    #[test]
    fn test_parse_store_subscribe() {
        assert!(
            parse_dae_config("global {}")
                .unwrap()
                .global
                .store_subscribe
        );
        assert!(
            !parse_dae_config("global {\n store_subscribe: false\n}")
                .unwrap()
                .global
                .store_subscribe
        );
    }

    #[test]
    fn test_parse_data_dir() {
        let custom = parse_dae_config("global {\n data_dir: '/srv/honk'\n}").unwrap();
        assert_eq!(custom.global.data_dir, "/srv/honk");
        custom.validate().unwrap();
    }

    #[test]
    fn test_parse_wan_only_global() {
        let input = r#"
global {
    wan_interface: ens3
    dial_mode: ip
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert!(config.global.lan_interface.is_empty());
        let explicitly_empty = parse_dae_config("global {\n    lan_interface:\n}").unwrap();
        assert!(explicitly_empty.global.lan_interface.is_empty());
        assert_eq!(config.global.wan_interface, vec!["ens3"]);
    }

    #[test]
    fn test_parse_dns_client_subnet() {
        let config = parse_dae_config("dns {\n    client_subnet: auto(9.9.9.9)\n}").unwrap();
        assert_eq!(config.dns.client_subnet, "auto(9.9.9.9)");
        assert!(config.dns.client_subnet_mode().unwrap().unwrap().is_auto());

        let error = parse_dae_config("dns {\n    client_subnet: auto(example.com)\n}").unwrap_err();
        assert!(error.to_string().contains("dns.client_subnet"));
    }

    #[test]
    fn test_parse_dns_upstream() {
        let input = r#"
dns {
    upstream {
        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google:53'
        cloudflare_dot: 'tls://1.1.1.1:853'
        google_doh: 'https://dns.google/dns-query'
        cf_h3: 'h3://cloudflare-dns.com/dns-query'
        adguard_doq: 'quic://dns.adguard-dns.com'
        proxied: 'tcp://8.8.8.8:53' -> proxy
        google_via: 'https://dns.google/dns-query' -> proxy
        legacy_out: 'tcp://1.1.1.1:53' outbound: oldproxy
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.dns.upstream.len(), 9);
        assert_eq!(config.dns.upstream[0].name, "alidns");
        assert_eq!(config.dns.upstream[1].name, "googledns");

        let dot = &config.dns.upstream[2];
        assert_eq!(dot.protocol, crate::types::DnsProtocol::Tls);
        assert_eq!(dot.address, "1.1.1.1:853");
        // IP literal → no SNI derived from host.
        assert_eq!(dot.tls_server_name, None);

        let doh = &config.dns.upstream[3];
        assert_eq!(doh.protocol, crate::types::DnsProtocol::Https);
        assert_eq!(doh.address, "dns.google/dns-query");
        assert_eq!(doh.tls_server_name.as_deref(), Some("dns.google"));

        let h3 = &config.dns.upstream[4];
        assert_eq!(h3.protocol, crate::types::DnsProtocol::H3);
        assert_eq!(h3.tls_server_name.as_deref(), Some("cloudflare-dns.com"));

        let doq = &config.dns.upstream[5];
        assert_eq!(doq.protocol, crate::types::DnsProtocol::Quic);
        assert_eq!(doq.tls_server_name.as_deref(), Some("dns.adguard-dns.com"));

        let proxied = &config.dns.upstream[6];
        assert_eq!(proxied.outbound.as_deref(), Some("proxy"));

        let google_via = &config.dns.upstream[7];
        assert_eq!(google_via.protocol, crate::types::DnsProtocol::Https);
        assert_eq!(google_via.address, "dns.google/dns-query");
        assert_eq!(google_via.outbound.as_deref(), Some("proxy"));
        assert_eq!(google_via.tls_server_name.as_deref(), Some("dns.google"));

        // Legacy `outbound:` still accepted.
        let legacy = &config.dns.upstream[8];
        assert_eq!(legacy.outbound.as_deref(), Some("oldproxy"));
    }

    #[test]
    fn test_parse_dns_bind_scalar_and_current_dae_bare_udp() {
        let bare = parse_dae_config("dns {\n bind: 127.0.0.1:53\n}").unwrap();
        assert_eq!(bare.dns.bind, "127.0.0.1:53");
        let endpoint = bare.dns.bind_endpoint().unwrap().unwrap();
        assert!(endpoint.udp_enabled());
        assert!(!endpoint.tcp_enabled());
        assert_eq!(endpoint.host(), "127.0.0.1");
        assert_eq!(endpoint.port(), 53);

        let dual = parse_dae_config("dns {\n bind: 'TcP+UdP://[::1]:0'\n}").unwrap();
        assert_eq!(dual.dns.bind, "TcP+UdP://[::1]:0");
        let endpoint = dual.dns.bind_endpoint().unwrap().unwrap();
        assert!(endpoint.udp_enabled());
        assert!(endpoint.tcp_enabled());
        assert_eq!(endpoint.host(), "::1");
        assert_eq!(endpoint.port(), 0);

        let commented =
            parse_dae_config("dns {\n bind: 'udp://localhost:53' # local resolver\n}").unwrap();
        assert_eq!(commented.dns.bind, "udp://localhost:53");
    }

    #[test]
    fn test_parse_dns_bind_rejects_invalid_values_clearly() {
        for value in [
            "localhost:53",
            "udp://localhost",
            "udp://user@localhost:53",
            "udp://localhost:53/path",
            "udp://localhost:53?query",
            "udp://localhost:53#fragment",
            "udp+tcp://localhost:53",
            "udp://[::1:53",
            "udp://localhost:65536",
        ] {
            let input = format!("dns {{\n bind: '{value}'\n}}");
            let error = parse_dae_config(&input).unwrap_err();
            assert!(matches!(error, crate::ConfigError::Parse(_)), "{value}");
            assert!(
                error.to_string().contains("dns.bind"),
                "error must identify dns.bind for {value}: {error}"
            );
        }
    }

    #[test]
    fn test_parse_dns_upstream_tls_server_name() {
        let input = r#"
dns {
    upstream {
        cf_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
        cf_doh: 'https://1.1.1.1/dns-query?tls_server_name=cloudflare-dns.com'
        host_wins: 'tls://one.one.one.one:853?tls_server_name=cloudflare-dns.com'
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.dns.upstream.len(), 3);

        // IP literal + explicit sni: query param stripped from address, sni set.
        let dot = &config.dns.upstream[0];
        assert_eq!(dot.protocol, crate::types::DnsProtocol::Tls);
        assert_eq!(dot.address, "1.1.1.1:853");
        assert_eq!(dot.tls_server_name.as_deref(), Some("cloudflare-dns.com"));

        let doh = &config.dns.upstream[1];
        assert_eq!(doh.protocol, crate::types::DnsProtocol::Https);
        assert_eq!(doh.address, "1.1.1.1/dns-query");
        assert_eq!(doh.tls_server_name.as_deref(), Some("cloudflare-dns.com"));

        // Explicit sni wins over the host-derived one.
        let host_wins = &config.dns.upstream[2];
        assert_eq!(host_wins.address, "one.one.one.one:853");
        assert_eq!(
            host_wins.tls_server_name.as_deref(),
            Some("cloudflare-dns.com")
        );
    }

    #[test]
    fn test_parse_routing_rules() {
        let input = r#"
routing {
    pname(NetworkManager) -> direct
    dip(224.0.0.0/3) -> direct
    domain(geosite:cn) -> direct
    fallback: my_group
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.routing.rules.len(), 3);
        assert_eq!(config.routing.default_outbound, "my_group");
    }

    #[test]
    fn test_parse_nodes() {
        let input = r#"
node {
    'socks5://localhost:1080'
    mylink: 'ss://LINK'
    double_quoted: "socks5://localhost:1081"
    "double_tag": 'socks5://localhost:1082'
    "double_both": "socks5://localhost:1083"
    broken: 'not-a-valid-link'
}
"#;
        let config = parse_dae_config(input).unwrap();
        // `broken` is skipped with a warning; the other five parse.
        assert_eq!(config.nodes.len(), 5);
        let names: Vec<&str> = config.nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"mylink"));
        assert!(names.contains(&"double_quoted"));
        assert!(names.contains(&"double_tag"));
        assert!(names.contains(&"double_both"));
    }

    #[test]
    fn test_parse_tagged_vmess_with_empty_remark() {
        let payload = r#"{"ps":"","add":"vmess.example.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}"#;
        let link = format!(
            "vmess://{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
        );
        let config = parse_dae_config(&format!("node {{\n edge: '{link}'\n}}")).unwrap();
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].name, "edge");
    }

    #[test]
    fn test_parse_vless_mode_link() {
        let config = parse_dae_config(
            "node {\n    xudp: 'vless://00000000-0000-0000-0000-000000000001@example.com:443?vless_mode=xudp#node'\n    cool: 'vless://00000000-0000-0000-0000-000000000001@example.com:443?vless_mode=mux-cool#node'\n}",
        )
        .unwrap();
        assert_eq!(config.nodes.len(), 2);
        assert_eq!(config.nodes[0].name, "xudp");
        assert_eq!(
            config.nodes[0].vless().unwrap().mode,
            crate::node::WireMode::Xudp
        );
        assert_eq!(config.nodes[1].name, "cool");
        assert_eq!(
            config.nodes[1].vless().unwrap().mode,
            crate::node::WireMode::MuxCool
        );
    }

    #[test]
    fn test_node_section_rejects_removed_protocols_and_standalone_mux() {
        for input in [
            "node {\n    'ssr://a'\n}",
            "node {\n    'trojan-go://pw@example.com:443'\n}",
            "node {\n    'http://proxy.example.com:8080'\n}",
        ] {
            let err = parse_dae_config(input).unwrap_err();
            assert!(matches!(err, crate::ConfigError::UnknownProtocol(_)));
        }
        let err = parse_dae_config("node {\n    mux = true\n}").unwrap_err();
        assert!(matches!(err, crate::ConfigError::Parse(_)));
    }

    #[test]
    fn test_parse_groups() {
        let input = r#"
group {
    my_group {
        policy: min_moving_avg
    }
    group2 {
        filter: name(HK_node)
        filter: name(US_node)
        policy: min_avg10
    }
    iris {
        filter: name('iris')
        policy: fixed(0)
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        // Regression: nested group sections must not be emitted twice (the
        // splitter used to clone the accumulated body at close, so each
        // group was pushed again at the next open / at end-of-input).
        assert_eq!(config.groups.len(), 3);
        assert!(config.groups.iter().any(|g| g.name == "my_group"));
        assert!(config.groups.iter().any(|g| g.name == "group2"));
        let iris = config
            .groups
            .iter()
            .find(|g| g.name == "iris")
            .expect("iris group");
        assert_eq!(iris.policy, crate::group::GroupPolicy::Selector);
        let my_group = config
            .groups
            .iter()
            .find(|g| g.name == "my_group")
            .expect("my_group");
        assert_eq!(my_group.policy, crate::group::GroupPolicy::URLTest);
    }

    #[test]
    fn test_parse_unknown_group_policy_remains_selector() {
        let config = parse_dae_config("group {\n proxy {\n policy: future_policy\n }\n}").unwrap();
        assert_eq!(config.groups[0].policy, crate::group::GroupPolicy::Selector);
    }

    #[test]
    fn test_parse_score_group_policy_case_insensitively() {
        for policy in ["score", "ScOrE"] {
            let config =
                parse_dae_config(&format!("group {{\n proxy {{\n policy: {policy}\n }}\n}}"))
                    .unwrap();
            assert_eq!(config.groups[0].policy, crate::group::GroupPolicy::Score);
        }
    }

    #[test]
    fn test_parse_legacy_honk_group_policy_is_actionable() {
        let error = parse_dae_config("group {\n proxy {\n policy: honk\n }\n}").unwrap_err();
        assert!(matches!(error, crate::ConfigError::UnsupportedPolicy(_)));
        assert!(error.to_string().contains("renamed to 'score'"));
    }

    #[test]
    fn test_parse_group_policies_loadbalance_fallback() {
        let input = r#"
group {
    rr {
        policy: roundrobin
    }
    rr2 {
        policy: round_robin
    }
    rr3 {
        policy: loadbalance
    }
    rr4 {
        policy: balance
    }
    fb {
        policy: fallback
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        let policy = |name: &str| {
            config
                .groups
                .iter()
                .find(|g| g.name == name)
                .unwrap_or_else(|| panic!("group '{}' missing", name))
                .policy
        };
        assert_eq!(policy("rr"), crate::group::GroupPolicy::LoadBalance);
        assert_eq!(policy("rr2"), crate::group::GroupPolicy::LoadBalance);
        assert_eq!(policy("rr3"), crate::group::GroupPolicy::LoadBalance);
        assert_eq!(policy("rr4"), crate::group::GroupPolicy::LoadBalance);
        assert_eq!(policy("fb"), crate::group::GroupPolicy::Fallback);
    }

    #[test]
    fn test_parse_group_nested_group_filter() {
        // `filter: group('tag')` names nested sub-groups (sing-box style):
        // it lands in `Group.groups`, not in the node `filters`, and a
        // group whose only membership is sub-groups must NOT swallow every
        // node via the filter-less fallback.
        let input = r#"
node {
    hk1: 'socks5://127.0.0.1:1080'
    us1: 'socks5://127.0.0.1:1081'
}
group {
    hk {
        filter: name(keyword: 'hk')
        policy: urltest
    }
    proxy {
        filter: group('hk')
        policy: select
    }
    multi {
        filter: group('hk', 'proxy')
        filter: name('us1')
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        let group = |name: &str| {
            config
                .groups
                .iter()
                .find(|g| g.name == name)
                .unwrap_or_else(|| panic!("group '{}' missing", name))
        };

        let proxy = group("proxy");
        assert_eq!(proxy.groups, vec!["hk".to_string()]);
        assert!(proxy.filters.is_empty());
        assert!(proxy.nodes.is_empty());
        assert_eq!(proxy.policy, crate::group::GroupPolicy::Selector);

        let multi = group("multi");
        assert_eq!(multi.groups, vec!["hk".to_string(), "proxy".to_string()]);
        assert_eq!(multi.filters, vec!["name('us1')".to_string()]);
        let us1 = config.nodes.iter().find(|n| n.name == "us1").unwrap();
        assert_eq!(multi.nodes, vec![us1.id]);

        let hk1 = config.nodes.iter().find(|n| n.name == "hk1").unwrap();
        assert_eq!(group("hk").nodes, vec![hk1.id]);

        let mut structured: crate::group::Group =
            serde_json::from_str(r#"{"name":"p","filters":["group('hk')"]}"#).unwrap();
        crate::parser::resolve_group_filters(
            std::slice::from_mut(&mut structured),
            &config.nodes,
            &config.subscriptions,
        );
        assert_eq!(
            structured.nodes,
            config.nodes.iter().map(|node| node.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_standalone_group_filter_comments_and_bare_tags() {
        let input = r#"
node {
    edge: 'socks5://127.0.0.1:1080'
}
group {
    proxy {
        filter: group('hk')   # note
    }
    multi {
        filter: group(hk, sg)
    }
}
"#;
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_diagnostics(input, &mut diagnostics).unwrap();

        assert_eq!(config.groups[0].groups, vec!["hk"]);
        assert!(config.groups[0].nodes.is_empty());
        assert_eq!(config.groups[1].groups, vec!["hk", "sg"]);
        assert!(config.groups[1].nodes.is_empty());
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn test_mixed_group_filter_is_reported_and_stays_empty() {
        let input = r#"
node {
    edge: 'socks5://127.0.0.1:1080'
    other: 'socks5://127.0.0.1:1081'
}
group {
    hk {
        filter: name('edge')
    }
    proxy {
        filter: group('hk') && name('edge')
    }
    later {
        filter: name('other')
    }
}
"#;
        let mut diagnostics = Vec::new();
        let mut config = parse_dae_config_with_diagnostics(input, &mut diagnostics).unwrap();

        assert!(config.groups[1].groups.is_empty());
        assert!(config.groups[1].nodes.is_empty());
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].setting, "groups[2].filter");
        assert_eq!(diagnostics[0].value, "1");
        assert_eq!(config.groups[0].nodes, vec![config.nodes[0].id]);
        assert_eq!(config.groups[2].nodes, vec![config.nodes[1].id]);

        config
            .nodes
            .push(crate::node::Node::from_share_link("socks5://127.0.0.1:1082#new").unwrap());
        crate::parser::resolve_group_filters(
            &mut config.groups,
            &config.nodes,
            &config.subscriptions,
        );

        assert!(config.groups[1].groups.is_empty());
        assert!(config.groups[1].nodes.is_empty());
    }

    #[test]
    fn test_nested_call_in_group_filter_is_reported() {
        let input = r#"
node {
    edge: 'socks5://127.0.0.1:1080'
}
group {
    proxy {
        filter: group('hk' && name('edge')
    }
}
"#;
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_diagnostics(input, &mut diagnostics).unwrap();
        let group = |name: &str| {
            config
                .groups
                .iter()
                .find(|g| g.name == name)
                .unwrap_or_else(|| panic!("group '{}' missing", name))
        };

        assert!(group("proxy").groups.is_empty());
        assert!(group("proxy").nodes.is_empty());
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].setting, "groups[1].filter");
        assert_eq!(diagnostics[0].value, "1");
    }

    #[test]
    fn test_entry_node_escaped_quote_tag() {
        let config = parse_dae_config(
            r#"node {
    'a\'b': 'socks5://127.0.0.1:1080'
}"#,
        )
        .unwrap();
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].name, r"a\'b");
    }

    #[test]
    fn test_entry_node_escaped_quote_uri() {
        let config = parse_dae_config(
            r#"node {
    'socks5://127.0.0.1:1080#left\':socks5://127.0.0.2:1081#right'
}"#,
        )
        .unwrap();
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].host, "127.0.0.1");
        assert_eq!(config.nodes[0].port, 1080);
        assert_eq!(
            config.nodes[0].name,
            r"left\':socks5://127.0.0.2:1081#right"
        );
    }

    #[test]
    fn test_entry_comment_tagless_file_subscription() {
        let config = parse_dae_config(
            "subscription {\n 'file://relative/path/to/mysub.sub' # Put subscription content in /etc/dae/relative/path/to/mysub.sub\n}",
        )
        .unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(
            config.subscriptions[0].url,
            "file://relative/path/to/mysub.sub"
        );
        assert_eq!(config.subscriptions[0].name, "relative");
        assert_eq!(config.subscriptions[0].user_agent, None);
    }

    #[test]
    fn test_entry_comment_tagged_subscription() {
        let config = parse_dae_config("subscription {\n tag: 'https://h/p' # c\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "tag");
        assert_eq!(config.subscriptions[0].url, "https://h/p");
        assert_eq!(config.subscriptions[0].user_agent, None);
    }

    #[test]
    fn test_entry_quoted_subscription_glued_url_is_retained_with_hash_warning() {
        let input = "subscription {\n paid: 'http://q'#c\n}";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "paid");
        assert_eq!(config.subscriptions[0].url, "http://q");
        assert_eq!(config.subscriptions[0].user_agent, None);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "legacy-glued-hash");
        assert_eq!(
            diagnostics[0].severity,
            crate::diagnostic::Severity::Warning
        );
        let hash = input.find("#c").unwrap();
        assert_eq!(diagnostics[0].span, Some(hash..hash + 1));
        assert_eq!(diagnostics[0].message, "put whitespace before a comment");
    }

    #[test]
    fn test_entry_literal_hash_in_user_agent() {
        let config = parse_dae_config("subscription {\n tag: 'http://q'(agent#build)\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "tag");
        assert_eq!(config.subscriptions[0].url, "http://q");
        assert_eq!(
            config.subscriptions[0].user_agent.as_deref(),
            Some("agent#build")
        );
    }

    #[test]
    fn test_entry_subscription_empty_user_agent() {
        let config = parse_dae_config("subscription {\n tag: 'http://q'()\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "tag");
        assert_eq!(config.subscriptions[0].url, "http://q");
        assert_eq!(config.subscriptions[0].user_agent.as_deref(), Some(""));
    }

    #[test]
    fn test_entry_subscription_user_agent_trailing_text_skips_entry() {
        let input = "subscription {\n tag: 'http://q'(agent) junk\n}";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        assert!(config.subscriptions.is_empty());
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "legacy-ua-boundary");
        assert_eq!(diagnostics[0].severity, crate::diagnostic::Severity::Error);
        let tail = input.find("junk").unwrap();
        assert_eq!(diagnostics[0].span, Some(tail..tail + 1));
        assert!(diagnostics[0].message.contains("entry is skipped"));
    }

    #[test]
    fn test_entry_quoted_user_agent_protects_delimiters() {
        let config =
            parse_dae_config("subscription {\n tag: 'http://q'('agent)#build')\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "tag");
        assert_eq!(config.subscriptions[0].url, "http://q");
        assert_eq!(
            config.subscriptions[0].user_agent.as_deref(),
            Some("agent)#build")
        );
    }

    #[test]
    fn test_entry_comment_quoted_subscription_nested_parentheses() {
        let config = parse_dae_config(
            "subscription {\n tag: 'http://q'(Mozilla/5.0 (X11; (Linux)#build))\n}",
        )
        .unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "tag");
        assert_eq!(config.subscriptions[0].url, "http://q");
        assert_eq!(
            config.subscriptions[0].user_agent.as_deref(),
            Some("Mozilla/5.0 (X11; (Linux)#build)")
        );
    }

    #[test]
    fn test_entry_comment_bare_node_fragment() {
        let config =
            parse_dae_config("node {\n ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#hk1 # note\n}")
                .unwrap();
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].name, "hk1");
        assert_eq!(config.nodes[0].host, "1.2.3.4");
        assert_eq!(config.nodes[0].port, 8388);
    }

    #[test]
    fn test_entry_comment_tagged_node() {
        let config =
            parse_dae_config("node {\n edge: 'socks5://127.0.0.1:1080' # note\n}").unwrap();
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].name, "edge");
        assert_eq!(config.nodes[0].host, "127.0.0.1");
        assert_eq!(config.nodes[0].port, 1080);
    }

    #[test]
    fn test_entry_comment_quoted_node_trailing_text() {
        let config =
            parse_dae_config("node {\n 'ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#hk1' # note\n}")
                .unwrap();
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].name, "hk1");
        assert_eq!(config.nodes[0].host, "1.2.3.4");
        assert_eq!(config.nodes[0].port, 8388);
    }

    #[test]
    fn test_entry_subscription_tagless_quoted() {
        let config =
            parse_dae_config("subscription {\n 'https://example.com/no_tag_link'\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "example.com");
        assert_eq!(
            config.subscriptions[0].url,
            "https://example.com/no_tag_link"
        );
        assert_eq!(config.subscriptions[0].user_agent, None);
    }

    #[test]
    fn test_entry_subscription_tagless_bare() {
        let config =
            parse_dae_config("subscription {\n https://example.net/sub?x=(1)#frag\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "example.net");
        assert_eq!(
            config.subscriptions[0].url,
            "https://example.net/sub?x=(1)#frag"
        );
        assert_eq!(config.subscriptions[0].user_agent, None);
    }

    #[test]
    fn test_entry_subscription_tagless_user_agent() {
        let config =
            parse_dae_config("subscription {\n 'https://example.org/sub'(provider/2.0)\n}")
                .unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "example.org");
        assert_eq!(config.subscriptions[0].url, "https://example.org/sub");
        assert_eq!(
            config.subscriptions[0].user_agent.as_deref(),
            Some("provider/2.0")
        );
    }

    #[test]
    fn test_entry_subscription_tag_inside_literal() {
        let config =
            parse_dae_config("subscription {\n 'paid:https://example.com/sub'\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "paid");
        assert_eq!(config.subscriptions[0].url, "https://example.com/sub");
        assert_eq!(config.subscriptions[0].user_agent, None);
    }

    #[test]
    fn test_entry_subscription_apostrophe_tag() {
        let config =
            parse_dae_config("subscription {\n edge': https://example.com/sub\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "edge'");
        assert_eq!(config.subscriptions[0].url, "https://example.com/sub");
        assert_eq!(config.subscriptions[0].user_agent, None);
    }

    #[test]
    fn test_entry_subscription_escaped_quote_tag() {
        let config = parse_dae_config(
            r#"subscription {
    "paid\"east": "https://example.com/sub"(provider/2.0)
}"#,
        )
        .unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, r#"paid\"east"#);
        assert_eq!(config.subscriptions[0].url, "https://example.com/sub");
        assert_eq!(
            config.subscriptions[0].user_agent.as_deref(),
            Some("provider/2.0")
        );
    }

    #[test]
    fn test_entry_subscription_colliding_names_select_both_nodes() {
        let mut config = parse_dae_config(
            r#"subscription {
    example.com: 'https://other.example/paid'
    'https://example.com/free'
}
node {
    paid: 'socks5://127.0.0.1:1080'
    free: 'socks5://127.0.0.2:1080'
}
group {
    proxy {
        filter: subtag(example.com)
    }
}"#,
        )
        .unwrap();
        assert_eq!(config.subscriptions.len(), 2);
        assert_eq!(config.nodes.len(), 2);
        config.nodes[0].subscription_id = Some(config.subscriptions[0].id);
        config.nodes[1].subscription_id = Some(config.subscriptions[1].id);
        crate::parser::resolve_group_filters(
            &mut config.groups,
            &config.nodes,
            &config.subscriptions,
        );
        assert_eq!(
            config.groups[0].nodes,
            vec![config.nodes[0].id, config.nodes[1].id]
        );
        assert_eq!(
            config
                .subscriptions
                .iter()
                .map(|sub| (
                    sub.name.as_str(),
                    sub.url.as_str(),
                    sub.user_agent.as_deref()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("example.com", "https://other.example/paid", None),
                ("example.com", "https://example.com/free", None),
            ]
        );
        config.validate().unwrap();
    }

    #[test]
    fn test_entry_subscription_hostless_name() {
        let config = parse_dae_config("subscription {\n 'https://:80/x'\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "");
        assert_eq!(config.subscriptions[0].url, "https://:80/x");
        assert_eq!(config.subscriptions[0].user_agent, None);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_entry_subscription_spaced_tag() {
        let config =
            parse_dae_config("subscription {\n paid : https://example.com/sub\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "paid");
        assert_eq!(config.subscriptions[0].url, "https://example.com/sub");
        assert_eq!(config.subscriptions[0].user_agent, None);
    }

    #[test]
    fn test_entry_subscription_tagged_invalid_url() {
        let config = parse_dae_config("subscription {\n broken: not-a-url\n}").unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "broken");
        assert_eq!(config.subscriptions[0].url, "not-a-url");
        assert_eq!(config.subscriptions[0].user_agent, None);
        assert!(matches!(
            config.validate(),
            Err(crate::ConfigError::Validation(_))
        ));
    }

    #[test]
    fn test_entry_subscription_tagless_garbage() {
        let config = parse_dae_config("subscription {\n foo bar\n}").unwrap();
        assert!(config.subscriptions.is_empty());
    }

    #[test]
    fn test_parse_subscriptions() {
        let input = r#"
subscription {
    my_sub: 'https://www.example.com/subscription/link'
    another_sub: 'https://example.com/another_sub'
    bare: https://example.com/sub?filter=(hk)#token
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.subscriptions.len(), 3);
        assert!(config.subscriptions.iter().all(|sub| sub.enabled));
        assert!(
            config
                .subscriptions
                .iter()
                .all(|sub| sub.update_interval == 86_400 && !sub.id.is_nil())
        );
        assert_ne!(config.subscriptions[0].id, config.subscriptions[1].id);
        assert_eq!(
            config.subscriptions[2].url,
            "https://example.com/sub?filter=(hk)#token"
        );
    }

    #[test]
    fn test_parse_subscription_user_agent_forms() {
        let input = r#"
subscription {
    detailed: {
        url: 'http://example.test/subscription'
        ua: 'provider/2.0'
        interval: '10000s'
    }
    inline: 'http://example.test/sub'(honk/1.0 like)
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.subscriptions.len(), 2);

        let detailed = &config.subscriptions[0];
        assert_eq!(detailed.name, "detailed");
        assert_eq!(detailed.url, "http://example.test/subscription");
        assert_eq!(detailed.user_agent.as_deref(), Some("provider/2.0"));
        assert_eq!(detailed.update_interval, 10_000);

        let inline = &config.subscriptions[1];
        assert_eq!(inline.name, "inline");
        assert_eq!(inline.url, "http://example.test/sub");
        assert_eq!(inline.user_agent.as_deref(), Some("honk/1.0 like"));
        assert_eq!(inline.update_interval, 86_400);
    }

    #[test]
    fn test_parse_full_global() {
        let input = r#"
global {
    tproxy_port: 12345
    tproxy_port_protect: true
    pprof_port: 0
    so_mark_from_dae: 0
    log_level: info
    disable_waiting_network: false
    wan_interface: auto
    auto_config_kernel_parameter: true
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1'
    tcp_check_http_method: HEAD
    udp_check_dns: 'dns.google:53,8.8.8.8'
    check_interval: 30s
    check_tolerance: 50ms
    dial_mode: domain
    allow_insecure: false
    sniffing_timeout: 30ms
    tls_implementation: tls
    utls_imitate: chrome_auto
    tls_fragment: false
    tls_fragment_length: '50-100'
    tls_fragment_interval: '10-20'
    mptcp: false
    fallback_resolver: '8.8.8.8:53'
    bandwidth_max_tx: '200 mbps'
    bandwidth_max_rx: '1 gbps'
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.global.tproxy_port, 12345);
        assert!(config.global.tproxy_port_protect);
        assert_eq!(config.global.check_interval_secs, 30);
        assert_eq!(config.global.check_tolerance_ms, 50);
        assert_eq!(config.global.sniffing_timeout_ms, 30);
    }

    #[test]
    fn test_global_check_tolerance_applies_to_dae_urltest_groups() {
        let config = parse_dae_config(
            r#"
global {
    check_tolerance: 120ms
}
group {
    url {
        policy: urltest
    }
    select {
        policy: select
    }
}
"#,
        )
        .unwrap();

        let group = |name: &str| {
            config
                .groups
                .iter()
                .find(|group| group.name == name)
                .unwrap_or_else(|| panic!("group '{name}' missing"))
        };
        assert_eq!(group("url").tolerance, 120);
        assert_eq!(group("select").tolerance, 50);
    }

    #[test]
    fn test_parse_domain_condition_prefixes() {
        let input = r#"
routing {
    domain(suffix: example.com, keyword: foo, full: bar.org) -> direct
    domain(geosite: cn, geosite: category-ai@cn) -> direct
    domain(geosite: private, suffix: example.net) -> direct
    fallback: direct
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.routing.rules.len(), 3);

        let r0 = &config.routing.rules[0];
        assert_eq!(r0.condition.domain_suffix, vec!["example.com"]);
        assert_eq!(r0.condition.domain_keyword, vec!["foo"]);
        assert_eq!(r0.condition.domain, vec!["bar.org"]);

        let r1 = &config.routing.rules[1];
        assert_eq!(r1.condition.geosite, vec!["cn", "category-ai@cn"]);

        let r2 = &config.routing.rules[2];
        assert_eq!(r2.condition.geosite, vec!["private"]);
        assert_eq!(r2.condition.domain_suffix, vec!["example.net"]);
    }

    #[test]
    fn test_parse_ip_routing_rules() {
        let input = r#"
routing {
    dip(10.0.0.0/8) -> direct
    dip(172.16.0.0/12, 192.168.0.0/16) -> direct
    fallback: proxy
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.routing.rules.len(), 2);
        assert_eq!(config.routing.rules[0].condition.ip, vec!["10.0.0.0/8"]);
        assert_eq!(
            config.routing.rules[1].condition.ip,
            vec!["172.16.0.0/12", "192.168.0.0/16"]
        );
    }

    #[test]
    fn test_parse_multiline_routing_matcher() {
        let input = r#"
routing {
    sip(10.10.10.24/32,
        10.10.10.25/32
    ) -> direct
    dport(443) -> proxy
    fallback: block
}
"#;
        let config = parse_dae_config(input).unwrap();

        assert_eq!(config.routing.rules.len(), 2);
        assert_eq!(
            config.routing.rules[0].condition.source_ip,
            vec!["10.10.10.24/32", "10.10.10.25/32"]
        );
        assert_eq!(
            config.routing.clash_rule_display(&config.routing.rules[0]),
            crate::routing::ClashRuleDisplay::Simple {
                rule_type: "src-ip-cidr",
                payload: "10.10.10.24/32,10.10.10.25/32".to_owned(),
            }
        );
        assert_eq!(config.routing.default_outbound, "block");
    }

    #[test]
    fn test_parse_anytls_node() {
        let input = r#"
node {
    test_node: 'anytls://00000000-0000-0000-0000-000000000000@example.com:443/?sni=example.com&insecure=1#test-node'
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.nodes.len(), 1);
        let node = &config.nodes[0];
        // Named node key is the config name; URL fragment is not the name.
        assert_eq!(node.name, "test_node");
        assert!(matches!(
            node.protocol(),
            crate::types::NodeProtocol::AnyTLS
        ));
        assert_eq!(node.host, "example.com");
        assert_eq!(node.port, 443);
        let anytls = node.anytls().unwrap();
        assert_eq!(
            anytls.password.as_deref(),
            Some("00000000-0000-0000-0000-000000000000")
        );
        assert!(anytls.tls.enabled);
        assert_eq!(anytls.tls.sni.as_deref(), Some("example.com"));
        assert!(anytls.tls.skip_cert_verify);
    }

    #[test]
    fn test_parse_experimental_section() {
        let input = r#"
experimental {
    clash_api {
        external_controller: 0.0.0.0:9999
        external_ui: yacd
        external_ui_download_url: 'https://example.com/ui.zip'
        external_ui_download_detour: proxy
        secret: s3cret
        default_mode: Global
    }
    cache_file {
        enabled: true
        path: cache.db
        cache_id: router1
        store_fakeip: true
        store_dns: true
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(
            config.experimental.clash_api.external_controller,
            "0.0.0.0:9999"
        );
        assert_eq!(config.experimental.clash_api.external_ui, "yacd");
        assert_eq!(
            config.experimental.clash_api.external_ui_download_url,
            "https://example.com/ui.zip"
        );
        assert_eq!(
            config.experimental.clash_api.external_ui_download_detour,
            "proxy"
        );
        assert_eq!(config.experimental.clash_api.secret, "s3cret");
        assert_eq!(config.experimental.clash_api.default_mode, "Global");
        assert!(config.experimental.cache_file.enabled);
        assert_eq!(config.experimental.cache_file.path, "cache.db");
        assert_eq!(config.experimental.cache_file.cache_id, "router1");
        assert!(config.experimental.cache_file.store_fakeip);
        assert!(config.experimental.cache_file.store_dns);
    }

    #[test]
    fn test_legacy_nfqueue_setting_migrates_to_global() {
        for (enabled, expected) in [("true", true), ("false", false), ("", false)] {
            let input = if enabled.is_empty() {
                "experimental {\n    udp_nfqueue {\n    }\n}".to_string()
            } else {
                format!(
                    "experimental {{\n    udp_nfqueue {{\n        enabled: {enabled}\n    }}\n}}"
                )
            };
            let config = parse_dae_config(&input).unwrap();
            assert_eq!(config.global.nfqueue_enable, expected);
        }

        let structured =
            crate::Config::from_json_str(r#"{"experimental":{"udp_nfqueue":{"enabled":true}}}"#)
                .unwrap();
        assert!(structured.global.nfqueue_enable);
        assert!(!structured.to_json_string().unwrap().contains("udp_nfqueue"));
        for (suffix, body) in [
            (".toml", "[experimental.udp_nfqueue]\nenabled = false\n"),
            (
                ".yaml",
                "experimental:\n  udp_nfqueue:\n    enabled: true\n",
            ),
        ] {
            let file = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
            std::fs::write(file.path(), body).unwrap();
            let loaded = crate::Config::from_file(file.path().to_str().unwrap()).unwrap();
            assert_eq!(loaded.global.nfqueue_enable, suffix == ".yaml");
        }

        for input in [
            "experimental {\n    udp_nfqueue {\n        enabled: maybe\n    }\n}",
            "experimental {\n    udp_nfqueue {\n        workers: 4\n    }\n}",
        ] {
            let error =
                parse_dae_config(input).expect_err("invalid legacy NFQUEUE config must fail");
            assert!(matches!(error, crate::ConfigError::Parse(_)), "{error}");
        }

        let error =
            crate::Config::from_json_str(r#"{"experimental":{"udp_nfqueue":{"workers":4}}}"#)
                .expect_err("unknown structured legacy NFQUEUE setting must fail");
        assert!(matches!(error, crate::ConfigError::Parse(_)));

        let config = crate::Config::from_json_str(r#"{"global":{"nfqueue_enable":false}}"#)
            .expect("structured global NFQUEUE setting");
        assert!(!config.global.nfqueue_enable);
    }

    #[test]
    fn test_canonical_nfqueue_setting_wins_over_legacy() {
        let dae = parse_dae_config(
            "global {\n    nfqueue_enable: false\n}\nexperimental {\n    udp_nfqueue {\n        enabled: true\n    }\n}",
        )
        .unwrap();
        assert!(!dae.global.nfqueue_enable);

        let dae = parse_dae_config(
            "global {\n    nfqueue_enable: true\n}\nexperimental {\n    udp_nfqueue {\n        enabled: false\n    }\n}",
        )
        .unwrap();
        assert!(dae.global.nfqueue_enable);

        let json = crate::Config::from_json_str(
            r#"{"global":{"nfqueue_enable":false},"experimental":{"udp_nfqueue":{"enabled":true}}}"#,
        )
        .unwrap();
        assert!(!json.global.nfqueue_enable);

        for (suffix, body, expected) in [
            (
                ".toml",
                "[global]\nnfqueue_enable = false\n[experimental.udp_nfqueue]\nenabled = true\n",
                false,
            ),
            (
                ".yaml",
                "global:\n  nfqueue_enable: true\nexperimental:\n  udp_nfqueue:\n    enabled: false\n",
                true,
            ),
        ] {
            let file = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
            std::fs::write(file.path(), body).unwrap();
            let loaded = crate::Config::from_file(file.path().to_str().unwrap()).unwrap();
            assert_eq!(loaded.global.nfqueue_enable, expected, "{suffix}");
        }
    }
}

#[test]
fn test_parse_group_default_key() {
    let input = r#"
group {
    proxy {
        filter: group('hk')
        filter: name('direct-out')
        policy: select
        default: 'hk'
        final: direct-out
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    let g = config.groups.iter().find(|g| g.name == "proxy").unwrap();
    assert_eq!(g.default.as_deref(), Some("hk"));
    assert_eq!(g.groups, vec!["hk".to_string()]);
    assert_eq!(g.final_outbound.as_deref(), Some("direct-out"));
}

#[test]
fn test_parse_group_check_url() {
    let input = r#"
group {
    ai {
        filter: name(keyword: 'sg')
        policy: urltest
        check_url: 'http://chatgpt.com/cdn-cgi/trace'
        final: direct
    }
    plain {
        filter: name(keyword: 'hk')
        policy: urltest
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    let g = config.groups.iter().find(|g| g.name == "ai").unwrap();
    assert_eq!(
        g.check_url.as_deref(),
        Some("http://chatgpt.com/cdn-cgi/trace")
    );
    assert_eq!(g.final_outbound.as_deref(), Some("direct"));
    let plain = config.groups.iter().find(|g| g.name == "plain").unwrap();
    assert_eq!(plain.check_url, None);
}

#[test]
fn test_group_filter_trailing_comment() {
    let input = r#"
node {
    edge: 'socks5://127.0.0.1:1080'
    other: 'socks5://127.0.0.1:1081'
}
group {
    proxy {
        filter: name('edge') # comment
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    let edge = config
        .nodes
        .iter()
        .find(|node| node.name == "edge")
        .unwrap();
    assert_eq!(config.groups[0].nodes, vec![edge.id]);

    let input = r#"
node {
    'edge#1': 'socks5://127.0.0.1:1080'
}
group {
    proxy {
        filter: name('edge#1')
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.groups[0].nodes.len(), 1, "a quoted `#` is data");
}

#[test]
fn test_group_filter_unterminated_group() {
    let input = r#"
node {
    edge: 'socks5://127.0.0.1:1080'
}
group {
    proxy {
        filter: group('hk'
    }
}
"#;
    let mut config = parse_dae_config(input).unwrap();
    assert!(
        config.groups[0].nodes.is_empty(),
        "unterminated group filter must not select all nodes"
    );
    config
        .nodes
        .push(crate::node::Node::from_share_link("socks5://127.0.0.1:1081#new").unwrap());
    crate::parser::resolve_group_filters(&mut config.groups, &config.nodes, &config.subscriptions);
    assert!(
        config.groups[0].nodes.is_empty(),
        "unterminated group filter must remain empty after adding a node"
    );
}

#[test]
fn test_group_filter_unquoted_hash() {
    let input = r#"
node {
    edge: 'socks5://127.0.0.1:1080'
}
group {
    proxy {
        filter: group(hk#suffix)
    }
}
"#;
    let mut config = parse_dae_config(input).unwrap();
    assert_eq!(config.groups[0].groups, ["hk#suffix"]);
    assert!(config.groups[0].nodes.is_empty());
    config
        .nodes
        .push(crate::node::Node::from_share_link("socks5://127.0.0.1:1081#new").unwrap());
    crate::parser::resolve_group_filters(&mut config.groups, &config.nodes, &config.subscriptions);
    assert_eq!(config.groups[0].groups, ["hk#suffix"]);
    assert!(config.groups[0].nodes.is_empty());
}

#[test]
fn test_group_name_filter_exact_multi_and_regex() {
    // Plain name() params are exact-match, comma-separated values OR-ed;
    // regex: gives a raw pattern (Go dae filter.go parity).
    let input = r#"
node {
    juicity-1: 'juicity://00000000-0000-0000-0000-000000000001:p@1.1.1.1:443'
    juicity-2: 'juicity://00000000-0000-0000-0000-000000000001:p@2.2.2.2:443'
    other: 'juicity://00000000-0000-0000-0000-000000000001:p@3.3.3.3:443'
}
group {
    exact {
        filter: name('juicity-1', 'juicity-2')
        policy: select
    }
    re {
        filter: name(regex: '^juicity-')
        policy: select
    }
    kw {
        filter: name(keyword: 'icity-1')
        policy: select
    }
    nomatch {
        filter: name('juicity')
        policy: select
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    let names = |tag: &str| {
        let g = config.groups.iter().find(|g| g.name == tag).unwrap();
        let mut v: Vec<String> = g
            .nodes
            .iter()
            .map(|id| {
                config
                    .nodes
                    .iter()
                    .find(|n| n.id == *id)
                    .unwrap()
                    .name
                    .clone()
            })
            .collect();
        v.sort();
        v
    };
    assert_eq!(names("exact"), vec!["juicity-1", "juicity-2"]);
    assert_eq!(names("re"), vec!["juicity-1", "juicity-2"]);
    assert_eq!(names("kw"), vec!["juicity-1"]);
    // Exact match on a shared prefix matches NOTHING (the test.dae case).
    assert!(names("nomatch").is_empty());
}

#[test]
fn test_group_subscription_filter_exact_regex_and_compound() {
    let input = r#"
subscription {
    paid: 'https://example.com/paid'
    free: 'https://example.com/free'
}
node {
    paid-hk: 'socks5://10.0.0.1:1080'
    ExpireAt-old: 'socks5://10.0.0.2:1080'
    free-node: 'socks5://10.0.0.3:1080'
    static: 'socks5://10.0.0.4:1080'
}
group {
    only-paid {
        filter: subtag('paid')
    }
    eligible-paid {
        filter: subtag(paid) && !name(keyword: 'ExpireAt-')
    }
    regex-or-exact {
        filter: subtag(regex: '^pa', free)
    }
    keyword {
        filter: subtag(keyword: 'aid')
    }
    separate-lines-or {
        filter: subtag(free)
        filter: name(static)
    }
    missing {
        filter: subtag(unknown)
    }
}
"#;
    let mut config = parse_dae_config(input).unwrap();
    let paid = config
        .subscriptions
        .iter()
        .find(|subscription| subscription.name == "paid")
        .unwrap()
        .id;
    let free = config
        .subscriptions
        .iter()
        .find(|subscription| subscription.name == "free")
        .unwrap()
        .id;
    for node in &mut config.nodes {
        node.subscription_id = match node.name.as_str() {
            "paid-hk" | "ExpireAt-old" => Some(paid),
            "free-node" => Some(free),
            _ => None,
        };
    }
    crate::parser::resolve_group_filters(&mut config.groups, &config.nodes, &config.subscriptions);

    let names = |tag: &str| {
        let group = config
            .groups
            .iter()
            .find(|group| group.name == tag)
            .unwrap();
        let mut names: Vec<_> = group
            .nodes
            .iter()
            .map(|id| {
                config
                    .nodes
                    .iter()
                    .find(|node| node.id == *id)
                    .unwrap()
                    .name
                    .as_str()
            })
            .collect();
        names.sort_unstable();
        names
    };
    assert_eq!(names("only-paid"), vec!["ExpireAt-old", "paid-hk"]);
    assert_eq!(names("eligible-paid"), vec!["paid-hk"]);
    assert_eq!(
        names("regex-or-exact"),
        vec!["ExpireAt-old", "free-node", "paid-hk"]
    );
    assert_eq!(names("keyword"), vec!["ExpireAt-old", "paid-hk"]);
    assert_eq!(names("separate-lines-or"), vec!["free-node", "static"]);
    assert!(names("missing").is_empty());

    config
        .nodes
        .iter_mut()
        .find(|node| node.name == "free-node")
        .unwrap()
        .subscription_id = Some(paid);
    crate::parser::resolve_group_filters(&mut config.groups, &config.nodes, &config.subscriptions);
    let paid_group = config
        .groups
        .iter()
        .find(|group| group.name == "only-paid")
        .unwrap();
    assert_eq!(paid_group.nodes.len(), 3);
}
#[test]
fn test_group_filter_multi_tags_comma_and_pipe() {
    let input = r#"
group {
    proxy {
        filter: group('hk', 'jp')
        filter: group('sg|us')
        filter: group('tw', 'ar|de')
        policy: select
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    let g = config.groups.iter().find(|g| g.name == "proxy").unwrap();
    assert_eq!(
        g.groups,
        vec!["hk", "jp", "sg", "us", "tw", "ar", "de"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_group_tags_serde_string_and_array() {
    let g: crate::group::Group =
        serde_json::from_str(r#"{"name":"p","groups":"hk|jp, sg"}"#).unwrap();
    assert_eq!(
        g.groups,
        vec!["hk".to_string(), "jp".to_string(), "sg".to_string()]
    );
    let g: crate::group::Group =
        serde_json::from_str(r#"{"name":"p","groups":["hk","jp|sg"]}"#).unwrap();
    assert_eq!(
        g.groups,
        vec!["hk".to_string(), "jp".to_string(), "sg".to_string()]
    );
}

// ---------------------------------------------------------------------------
// DNS routing parser tests (new dae-shaped model)
// ---------------------------------------------------------------------------

#[test]
fn test_parse_dns_request_routing_qname() {
    let input = r#"
dns {
    routing {
        request {
            qname(geosite:cn) -> alidns
            fallback: default
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 1);
    let rule = &config.dns.routing.request.rules[0];
    assert_eq!(rule.conditions.len(), 1);
    match &rule.conditions[0] {
        crate::dns::DnsCond::Qname { not, matchers } => {
            assert!(!not);
            assert_eq!(matchers.len(), 1);
        }
        _ => panic!("expected Qname condition"),
    }
    assert_eq!(
        rule.action,
        crate::dns::DnsRequestAction::Upstream("alidns".to_string())
    );
    assert_eq!(config.dns.routing.fallback, "default");
}

#[test]
fn test_dae_dns_rules_are_not_silently_dropped_by_structured_writer() {
    let config = parse_dae_config(
        "dns {\n routing {\n  request {\n   qname(example.com) -> reject\n  }\n }\n}",
    )
    .unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), "original").unwrap();

    let error = config.to_file(file.path().to_str().unwrap()).unwrap_err();

    assert!(matches!(error, crate::ConfigError::Serialization(_)));
    assert!(error.to_string().contains("dns.routing.request"));
    assert_eq!(std::fs::read_to_string(file.path()).unwrap(), "original");
}

#[test]
fn test_dae_writer_rejects_dae_extension_without_touching_source() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.dae");
    let source = "# keep this comment\nglobal {\n    log_level: debug\n}\n";
    let config = parse_dae_config(source).unwrap();
    std::fs::write(&path, source).unwrap();

    let error = config.to_file(path.to_str().unwrap()).unwrap_err();

    assert!(matches!(error, crate::ConfigError::Serialization(_)));
    assert!(error.to_string().contains("refusing to rewrite .dae"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), source);
}

#[test]
fn test_parse_dns_request_routing_qtype() {
    let input = r#"
dns {
    routing {
        request {
            qtype(a, aaaa) -> alidns
            qtype(https) -> reject
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 2);
    match &config.dns.routing.request.rules[0].conditions[0] {
        crate::dns::DnsCond::Qtype { not, types } => {
            assert!(!not);
            assert!(types.contains(&1));
            assert!(types.contains(&28));
        }
        _ => panic!("expected Qtype"),
    }
    match &config.dns.routing.request.rules[1].conditions[0] {
        crate::dns::DnsCond::Qtype { not, types } => {
            assert!(!not);
            assert!(types.contains(&65));
        }
        _ => panic!("expected Qtype"),
    }
    assert_eq!(
        config.dns.routing.request.rules[1].action,
        crate::dns::DnsRequestAction::Reject
    );
}

#[test]
fn test_parse_dns_request_routing_qname_and_qtype() {
    let input = r#"
dns {
    routing {
        request {
            qname(suffix:cn) && qtype(a, aaaa) -> alidns
            qname(full:block.test) -> reject
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 2);
    assert_eq!(config.dns.routing.request.rules[0].conditions.len(), 2);
    assert_eq!(
        config.dns.routing.request.rules[1].action,
        crate::dns::DnsRequestAction::Reject
    );
}

#[test]
fn test_parse_dns_request_routing_sip() {
    let input = r#"
dns {
    routing {
        request {
            sip(192.168.50.1, 100.64.0.0/10, 2001:db8::/32) -> lan_proxy
            !sip(127.0.0.0/8, ::1/128) && qname(suffix: example-isp.cn) -> asis
        }
        response {
            sip(192.168.50.0/24) -> reject
            fallback: accept
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    let rules = &config.dns.routing.request.rules;
    assert_eq!(rules.len(), 2);
    match &rules[0].conditions[0] {
        crate::dns::DnsCond::Sip { not, cidrs } => {
            assert!(!not);
            assert_eq!(cidrs, &["192.168.50.1", "100.64.0.0/10", "2001:db8::/32"]);
        }
        _ => panic!("expected Sip"),
    }
    match &rules[1].conditions[0] {
        crate::dns::DnsCond::Sip { not, cidrs } => {
            assert!(*not);
            assert_eq!(cidrs, &["127.0.0.0/8", "::1/128"]);
        }
        _ => panic!("expected Sip"),
    }
    assert_eq!(rules[1].conditions.len(), 2);
    let response_rules = &config.dns.routing.response.rules;
    assert_eq!(response_rules.len(), 1);
    match &response_rules[0].conditions[0] {
        crate::dns::DnsCond::Sip { not, cidrs } => {
            assert!(!not);
            assert_eq!(cidrs, &["192.168.50.0/24"]);
        }
        _ => panic!("expected response Sip to be rejected by the router"),
    }
}

#[test]
fn test_parse_dns_request_routing_negation() {
    let input = r#"
dns {
    routing {
        request {
            !qname(geosite:cn) -> googledns
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 1);
    match &config.dns.routing.request.rules[0].conditions[0] {
        crate::dns::DnsCond::Qname { not, .. } => {
            assert!(*not);
        }
        _ => panic!("expected Qname"),
    }
}

#[test]
fn test_parse_dns_request_routing_reject_asis() {
    let input = r#"
dns {
    routing {
        request {
            qname(keyword:ads) -> reject
            qname(full:local.test) -> asis
            fallback: default
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 2);
    assert_eq!(
        config.dns.routing.request.rules[0].action,
        crate::dns::DnsRequestAction::Reject
    );
    assert_eq!(
        config.dns.routing.request.rules[1].action,
        crate::dns::DnsRequestAction::AsIs
    );
}

#[test]
fn test_parse_ipversion_prefer_maps_to_prefer_variants() {
    let config = parse_dae_config("dns {\n    ipversion_prefer: 4\n}\n").unwrap();
    assert!(matches!(
        config.dns.strategy,
        crate::dns::DnsStrategy::PreferIpv4
    ));
    let config = parse_dae_config("dns {\n    ipversion_prefer: 6\n}\n").unwrap();
    assert!(matches!(
        config.dns.strategy,
        crate::dns::DnsStrategy::PreferIpv6
    ));
}

#[test]
fn test_parse_dns_response_routing() {
    let input = r#"
dns {
    routing {
        response {
            ip(geoip:private) && !qname(geosite:cn) -> accept
            upstream(googledns) -> reject
            fallback: accept
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.response.rules.len(), 2);
    let rule0 = &config.dns.routing.response.rules[0];
    assert_eq!(rule0.conditions.len(), 2);
    assert_eq!(rule0.action, crate::dns::DnsResponseAction::Accept);
    let rule1 = &config.dns.routing.response.rules[1];
    match &rule1.conditions[0] {
        crate::dns::DnsCond::Upstream { not, names } => {
            assert!(!not);
            assert!(names.contains(&"googledns".to_string()));
        }
        _ => panic!("expected Upstream"),
    }
    assert_eq!(rule1.action, crate::dns::DnsResponseAction::Reject);
}

#[test]
fn test_parse_fixed_domain_ttl() {
    let input = r#"
dns {
    fixed_domain_ttl {
        a.test: 0
        b.test: 300
        c.test: 60
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.fixed_domain_ttl.get("a.test"), Some(&0u32));
    assert_eq!(config.dns.fixed_domain_ttl.get("b.test"), Some(&300u32));
    assert_eq!(config.dns.fixed_domain_ttl.get("c.test"), Some(&60u32));
}

#[test]
fn test_parse_dns_request_ignores_sub() {
    let input = r#"
dns {
    routing {
        request {
            qname(geosite:cn) -> alidns
            sub(whatever) -> reject
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    // sub() rule should be ignored, only the qname rule remains
    assert_eq!(config.dns.routing.request.rules.len(), 1);
    match &config.dns.routing.request.rules[0].conditions[0] {
        crate::dns::DnsCond::Qname { .. } => {}
        _ => panic!("expected Qname"),
    }
}

#[test]
fn test_parse_dns_upstream_aliases_are_equivalent() {
    let input = r#"
dns {
    upstream {
        modern: 'https://dns.example/dns-query' -> proxy
        legacy: 'https://dns.example/dns-query' outbound: proxy
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.upstream.len(), 2);
    let modern = &config.dns.upstream[0];
    let legacy = &config.dns.upstream[1];
    assert_eq!(modern.protocol, legacy.protocol);
    assert_eq!(modern.address, legacy.address);
    assert_eq!(modern.tls_server_name, legacy.tls_server_name);
    assert_eq!(modern.outbound, legacy.outbound);
    assert_eq!(modern.outbound.as_deref(), Some("proxy"));
}

#[test]
fn test_parse_dns_duplicate_sections_preserve_source_order() {
    let input = r#"
dns {
    upstream {
        first: 'udp://1.1.1.1:53'
    }
    upstream {
        second: 'udp://8.8.8.8:53'
    }
    routing {
        request {
            qname(full:example.test) -> first
        }
    }
    routing {
        request {
            qname(full:example.test) -> second
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    let upstream_names = config
        .dns
        .upstream
        .iter()
        .map(|upstream| upstream.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(upstream_names, ["first", "second"]);
    let actions = config
        .dns
        .routing
        .request
        .rules
        .iter()
        .map(|rule| &rule.action)
        .collect::<Vec<_>>();
    assert_eq!(
        actions,
        [
            &crate::dns::DnsRequestAction::Upstream("first".into()),
            &crate::dns::DnsRequestAction::Upstream("second".into()),
        ]
    );
}

#[test]
fn test_parse_dns_request_response_order_is_first_match_relevant() {
    let request_input = r#"
dns {
    routing {
        request {
            qname(full:example.test) -> first
            qname(full:example.test) -> second
            fallback: default
        }
    }
}
"#;
    let request_config = parse_dae_config(request_input).unwrap();
    let request_actions = request_config
        .dns
        .routing
        .request
        .rules
        .iter()
        .map(|rule| &rule.action)
        .collect::<Vec<_>>();
    assert_eq!(
        request_actions,
        [
            &crate::dns::DnsRequestAction::Upstream("first".into()),
            &crate::dns::DnsRequestAction::Upstream("second".into()),
        ]
    );

    let response_input = r#"
dns {
    routing {
        response {
            ip(geoip:private) && !qname(geosite:cn) -> accept
            upstream(googledns) -> reject
            fallback: accept
        }
    }
}
"#;
    let response_config = parse_dae_config(response_input).unwrap();
    let response_actions = response_config
        .dns
        .routing
        .response
        .rules
        .iter()
        .map(|rule| &rule.action)
        .collect::<Vec<_>>();
    assert_eq!(
        response_actions,
        [
            &crate::dns::DnsResponseAction::Accept,
            &crate::dns::DnsResponseAction::Reject,
        ]
    );
}

#[test]
fn test_parse_dns_stale_reply_ttl_invalid_uses_default_and_diagnostic() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "dns {\n    optimistic_stale_reply_ttl: x\n}",
        &mut diagnostics,
    )
    .unwrap();

    assert_eq!(config.dns.cache.stale_reply_ttl, 30);
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].setting, "dns.optimistic_stale_reply_ttl");
}

#[test]
fn test_parse_dns_stale_reply_ttl_numeric_value_has_no_diagnostic() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "dns {\n    optimistic_stale_reply_ttl: 7\n}",
        &mut diagnostics,
    )
    .unwrap();

    assert_eq!(config.dns.cache.stale_reply_ttl, 7);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
}

#[test]
fn test_parse_dns_accepted_invalid_values_keep_fallbacks() {
    let input = r#"
dns {
    ipversion_prefer: 9
    optimistic_cache: maybe
    optimistic_cache_ttl: not-a-duration
    max_cache_size: not-a-number
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert!(matches!(config.dns.strategy, crate::dns::DnsStrategy::Both));
    assert!(!config.dns.cache.enabled);
    assert_eq!(config.dns.cache.ttl, 60);
    assert_eq!(config.dns.cache.max_size, 10000);
}

#[test]
fn test_parse_dns_zero_max_cache_size_is_preserved_for_runtime_clamp() {
    let config = parse_dae_config("dns {\n    max_cache_size: 0\n}\n").unwrap();
    assert_eq!(config.dns.cache.max_size, 0);
}

#[test]
fn hosts_sources_default_off_and_collect_repeated_values() {
    assert!(parse_dae_config("dns {}").unwrap().dns.hosts.is_empty());

    let custom = parse_dae_config(
        "dns {\n    use_host: true\n    use_host: 'rules-one.txt'\n    use_host: false\n    use_host: \"rules-two.txt\"\n    use_host: 'rules-one.txt'\n}",
    )
    .unwrap()
    .dns;
    assert_eq!(
        custom.hosts,
        ["/etc/hosts", "rules-one.txt", "rules-two.txt"]
    );

    assert_eq!(
        parse_dae_config("dns {\n    use_host: on\n}")
            .unwrap()
            .dns
            .hosts,
        ["/etc/hosts"]
    );
    assert!(
        parse_dae_config("dns {\n    use_host: false\n}")
            .unwrap()
            .dns
            .hosts
            .is_empty()
    );
    assert!(parse_dae_config("dns {\n    hosts_file: 'rules.txt'\n}").is_err());
}

#[test]
fn udp_warm_node_count_defaults_to_strictly_disabled() {
    assert_eq!(crate::Config::default().global.udp_warm_node_count, 0);
    assert_eq!(
        parse_dae_config("global {}")
            .unwrap()
            .global
            .udp_warm_node_count,
        0
    );
}

#[test]
fn udp_warm_node_count_parses_zero_and_rejects_invalid_values() {
    let enabled = parse_dae_config("global {\n udp_warm_node_count: 3\n}").unwrap();
    assert_eq!(enabled.global.udp_warm_node_count, 3);

    for invalid in ["nope", "-1", "99999999999999999999999999999999999999"] {
        let err = parse_dae_config(&format!("global {{\n udp_warm_node_count: {invalid}\n}}"))
            .expect_err("invalid udp warm count must reject the dae config");
        assert!(matches!(err, crate::ConfigError::Parse(_)), "{invalid}");
    }
}

#[test]
fn preconnect_node_count_defaults_to_auto_and_zero_disables() {
    assert_eq!(
        crate::Config::default().global.preconnect_node_count,
        crate::config::PRECONNECT_NODE_COUNT_AUTO
    );
    let auto = parse_dae_config("global {\n preconnect_node_count: 'auto'\n}").unwrap();
    assert_eq!(
        auto.global.preconnect_node_count,
        crate::config::PRECONNECT_NODE_COUNT_AUTO
    );
    let disabled = parse_dae_config("global {\n preconnect_node_count: 0\n}").unwrap();
    assert_eq!(disabled.global.preconnect_node_count, 0);
    let explicit = parse_dae_config("global {\n preconnect_node_count: 5\n}").unwrap();
    assert_eq!(explicit.global.preconnect_node_count, 5);
    let err = parse_dae_config("global {\n preconnect_node_count: someday\n}")
        .expect_err("invalid preconnect_node_count must reject the dae config");
    assert!(matches!(err, crate::ConfigError::Parse(_)));
}

#[test]
fn max_concurrent_dials_defaults_and_parses() {
    assert_eq!(crate::Config::default().global.max_concurrent_dials, 64);
    let cfg = parse_dae_config("global {\n max_concurrent_dials: 128\n}").unwrap();
    assert_eq!(cfg.global.max_concurrent_dials, 128);
    let err = parse_dae_config("global {\n max_concurrent_dials: nope\n}")
        .expect_err("invalid max_concurrent_dials must reject the dae config");
    assert!(matches!(err, crate::ConfigError::Parse(_)));
}

#[test]
fn test_parse_route_negation_matrix() {
    let input = r#"
routing {
    pname(curl) && !pname(wget) -> direct
    dip(10.0.0.0/8) && !dip(10.1.0.0/16) -> direct
    sip(192.168.0.0/16) && !sip(192.168.1.0/24) -> direct
    domain(suffix: example.com) && !domain(suffix: ads.example.com, keyword: tracker, full: evil.org, regex: ^bad\.) -> direct
    dport(80) && !dport(53) -> direct
    sport(1000-2000) && !sport(53) -> direct
    l4proto(tcp) && !l4proto(udp) -> direct
    ipversion(4) && !ipversion(6) -> direct
    mac(aa:bb:cc:dd:ee:ff) && !mac(00:11:22:33:44:55) -> direct
    dscp(4) && !dscp(46) -> direct
    dip(geoip:cn) && !dip(geoip:telegram) -> direct
    domain(geosite:cn) && !domain(geosite:category-ads) -> direct
    fallback: proxy
}
"#;
    let config = parse_dae_config(input).unwrap();
    let rules = &config.routing.rules;
    assert_eq!(rules.len(), 12);

    assert_eq!(rules[0].condition.process_name, vec!["curl"]);
    assert_eq!(rules[0].condition.not.process_name, vec!["wget"]);

    assert_eq!(rules[1].condition.ip, vec!["10.0.0.0/8"]);
    assert_eq!(rules[1].condition.not.ip, vec!["10.1.0.0/16"]);

    assert_eq!(rules[2].condition.source_ip, vec!["192.168.0.0/16"]);
    assert_eq!(rules[2].condition.not.source_ip, vec!["192.168.1.0/24"]);

    assert_eq!(rules[3].condition.domain_suffix, vec!["example.com"]);
    assert_eq!(
        rules[3].condition.not.domain_suffix,
        vec!["ads.example.com"]
    );
    assert_eq!(rules[3].condition.not.domain_keyword, vec!["tracker"]);
    assert_eq!(rules[3].condition.not.domain, vec!["evil.org"]);
    assert_eq!(rules[3].condition.not.domain_regex, vec![r"^bad\."]);

    assert_eq!(rules[4].condition.port, vec!["80"]);
    assert_eq!(rules[4].condition.not.port, vec!["53"]);

    assert_eq!(rules[5].condition.source_port, vec!["1000-2000"]);
    assert_eq!(rules[5].condition.not.source_port, vec!["53"]);

    assert_eq!(rules[6].condition.protocol, vec!["tcp"]);
    assert_eq!(rules[6].condition.not.protocol, vec!["udp"]);

    assert_eq!(rules[7].condition.ip_version, vec!["4"]);
    assert_eq!(rules[7].condition.not.ip_version, vec!["6"]);

    assert_eq!(rules[8].condition.mac, vec!["aa:bb:cc:dd:ee:ff"]);
    assert_eq!(rules[8].condition.not.mac, vec!["00:11:22:33:44:55"]);

    assert_eq!(rules[9].condition.dscp, vec!["4"]);
    assert_eq!(rules[9].condition.not.dscp, vec!["46"]);

    assert_eq!(rules[10].condition.geo_ip, vec!["cn"]);
    assert_eq!(rules[10].condition.not.geo_ip, vec!["telegram"]);

    assert_eq!(rules[11].condition.geosite, vec!["cn"]);
    assert_eq!(rules[11].condition.not.geosite, vec!["category-ads"]);

    for rule in rules {
        assert!(
            rule.condition.clash_rule_parts().is_some(),
            "positive side stays the clash display source"
        );
    }
}

#[test]
fn test_parse_route_negation_bare_prefix_forms() {
    let input = r#"
routing {
    !geosite:cn -> proxy
    !geoip:cn -> proxy
    !domain:example.com -> proxy
    !suffix:example.org -> proxy
    !keyword:ads -> proxy
    !full:evil.net -> proxy
    !regex:^bad\. -> proxy
    fallback: direct
}
"#;
    let config = parse_dae_config(input).unwrap();
    let rules = &config.routing.rules;
    assert_eq!(rules.len(), 7);

    assert_eq!(rules[0].condition.not.geosite, vec!["cn"]);
    assert_eq!(rules[1].condition.not.geo_ip, vec!["cn"]);
    assert_eq!(rules[2].condition.not.domain_suffix, vec!["example.com"]);
    assert_eq!(rules[3].condition.not.domain_suffix, vec!["example.org"]);
    assert_eq!(rules[4].condition.not.domain_keyword, vec!["ads"]);
    assert_eq!(rules[5].condition.not.domain, vec!["evil.net"]);
    assert_eq!(rules[6].condition.not.domain_regex, vec![r"^bad\."]);

    for rule in rules {
        let c = &rule.condition;
        assert!(c.domain.is_empty() && c.domain_suffix.is_empty());
        assert!(c.ip.is_empty() && c.port.is_empty() && c.geosite.is_empty());
        assert!(c.geo_ip.is_empty() && c.domain_keyword.is_empty());
    }
}

#[test]
fn test_parse_route_negation_production_rule() {
    let input = r#"
routing {
    sip(10.10.10.24/32) && !dport(53) -> direct(must)
    fallback: proxy
}
"#;
    let config = parse_dae_config(input).unwrap();
    let rule = &config.routing.rules[0];
    assert_eq!(rule.condition.source_ip, vec!["10.10.10.24/32"]);
    assert_eq!(rule.condition.not.port, vec!["53"]);
    assert!(rule.must);
}

#[test]
fn test_routing_condition_not_serde_defaults() {
    let cond: crate::routing::RoutingCondition = toml::from_str("port = ['443']").unwrap();
    assert_eq!(cond.port, vec!["443"]);
    assert!(cond.not.port.is_empty());
    assert!(cond.not.domain.is_empty());

    let cond: crate::routing::RoutingCondition =
        toml::from_str("port = ['443']\n[not]\nport = ['53']").unwrap();
    assert_eq!(cond.not.port, vec!["53"]);
}

#[test]
fn test_unparseable_ports_use_the_fallback_and_return_diagnostics() {
    for (key, value, expected) in [
        ("tproxy_port", "abc", 12345u16),
        ("tproxy_port", "0x3039", 12345u16),
        ("pprof_port", "abc", 0u16),
    ] {
        let input = format!("global {{\n    {key}: {value}\n}}");
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_diagnostics(&input, &mut diagnostics).unwrap();

        assert_eq!(diagnostics.len(), 1, "{key}={value}: {diagnostics:?}");
        assert_eq!(diagnostics[0].setting, format!("global.{key}"));
        let observed = if key == "tproxy_port" {
            config.global.tproxy_port
        } else {
            config.global.pprof_port
        };
        assert_eq!(observed, expected);
    }

    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "global {\n    tproxy_port: 12345\n    pprof_port: 54321\n}",
        &mut diagnostics,
    )
    .unwrap();
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(config.global.tproxy_port, 12345);
    assert_eq!(config.global.pprof_port, 54321);
}

#[test]
fn test_unparseable_so_mark_uses_the_fallback_and_returns_a_diagnostic() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "global {\n    so_mark_from_dae: zz\n}",
        &mut diagnostics,
    )
    .unwrap();

    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].setting, "global.so_mark_from_dae");
    assert_eq!(config.global.so_mark_from_dae, 0);

    for value in ["0x10", "10"] {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_diagnostics(
            &format!("global {{\n    so_mark_from_dae: {value}\n}}"),
            &mut diagnostics,
        )
        .unwrap();
        assert!(diagnostics.is_empty(), "{value}: {diagnostics:?}");
        assert_eq!(config.global.so_mark_from_dae, 16, "{value}");
    }
}

#[test]
fn test_unparseable_second_durations_use_the_fallback_and_return_diagnostics() {
    for value in ["soon", "1.5s"] {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_diagnostics(
            &format!("global {{\n    check_interval: {value}\n}}"),
            &mut diagnostics,
        )
        .unwrap();

        assert_eq!(
            diagnostics.len(),
            1,
            "check_interval={value}: {diagnostics:?}"
        );
        assert_eq!(diagnostics[0].setting, "global.check_interval");
        assert_eq!(config.global.check_interval_secs, 0);
    }

    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "subscription {\n    timed: {\n        url: 'https://example.com/timed'\n        interval: never\n    }\n}",
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].setting, "subscriptions[1].interval");
    assert_eq!(config.subscriptions[0].update_interval, 0);

    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "global {\n    check_interval: 2s\n}\nsubscription {\n    timed: {\n        url: 'https://example.com/timed'\n        interval: 1h\n    }\n}",
        &mut diagnostics,
    )
    .unwrap();
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(config.global.check_interval_secs, 2);
    assert_eq!(config.subscriptions[0].update_interval, 3600);
}

#[test]
fn test_unparseable_ipversion_prefer_uses_the_fallback_and_returns_a_diagnostic() {
    for value in ["ipv4", "0x6"] {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_diagnostics(
            &format!("dns {{\n    ipversion_prefer: {value}\n}}"),
            &mut diagnostics,
        )
        .unwrap();

        assert_eq!(
            diagnostics.len(),
            1,
            "ipversion_prefer={value}: {diagnostics:?}"
        );
        assert_eq!(diagnostics[0].setting, "dns.ipversion_prefer");
        assert!(matches!(config.dns.strategy, crate::dns::DnsStrategy::Both));
    }

    for (value, expected) in [
        ("0", crate::dns::DnsStrategy::Both),
        ("+6", crate::dns::DnsStrategy::PreferIpv6),
        ("06", crate::dns::DnsStrategy::PreferIpv6),
    ] {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_diagnostics(
            &format!("dns {{\n    ipversion_prefer: {value}\n}}"),
            &mut diagnostics,
        )
        .unwrap();
        assert!(diagnostics.is_empty(), "{value}: {diagnostics:?}");
        assert_eq!(config.dns.strategy, expected, "{value}");
    }
}

#[test]
fn test_unparseable_dns_cache_numbers_use_the_fallback_and_return_diagnostics() {
    for (key, value) in [
        ("optimistic_cache_ttl", "x"),
        ("optimistic_cache_ttl", "0x10"),
    ] {
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_diagnostics(
            &format!("dns {{\n    {key}: {value}\n}}"),
            &mut diagnostics,
        )
        .unwrap();

        assert_eq!(diagnostics.len(), 1, "{key}={value}: {diagnostics:?}");
        assert_eq!(diagnostics[0].setting, format!("dns.{key}"));
        assert_eq!(config.dns.cache.ttl, 60);
    }

    let mut diagnostics = Vec::new();
    let config =
        parse_dae_config_with_diagnostics("dns {\n    max_cache_size: x\n}", &mut diagnostics)
            .unwrap();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].setting, "dns.max_cache_size");
    assert_eq!(config.dns.cache.max_size, 10000);

    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "dns {\n    optimistic_cache_ttl: 4294967296\n    max_cache_size: 123\n}",
        &mut diagnostics,
    )
    .unwrap();
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(config.dns.cache.ttl, 4294967296);
    assert_eq!(config.dns.cache.max_size, 123);
}

#[test]
fn test_unparseable_fixed_domain_ttl_is_skipped_and_returns_a_diagnostic() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "dns {\n    fixed_domain_ttl {\n        example.com: 4294967296\n        good.com: 30\n    }\n}",
        &mut diagnostics,
    )
    .unwrap();

    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].setting, "dns.fixed_domain_ttl[1]");
    assert!(!config.dns.fixed_domain_ttl.contains_key("example.com"));
    assert_eq!(config.dns.fixed_domain_ttl.get("good.com"), Some(&30));

    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "dns {\n    fixed_domain_ttl {\n        zero.com: 0\n        max.com: 4294967295\n    }\n}",
        &mut diagnostics,
    )
    .unwrap();
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(config.dns.fixed_domain_ttl.get("zero.com"), Some(&0));
    assert_eq!(
        config.dns.fixed_domain_ttl.get("max.com"),
        Some(&4294967295)
    );
}

#[test]
fn test_unrecognised_booleans_are_false_and_return_diagnostics() {
    let input = r#"
global {
    tproxy_port_protect: flase
    disable_waiting_network: flase
    auto_config_kernel_parameter: flase
    store_subscribe: flase
    allow_insecure: flase
    tls_fragment: flase
    mptcp: flase
}
dns {
    optimistic_cache: flase
}
experimental {
    cache_file {
        enabled: flase
        store_fakeip: flase
        store_dns: flase
    }
}
"#;
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(input, &mut diagnostics).unwrap();

    let expected = [
        "global.tproxy_port_protect",
        "global.disable_waiting_network",
        "global.auto_config_kernel_parameter",
        "global.store_subscribe",
        "global.allow_insecure",
        "global.tls_fragment",
        "global.mptcp",
        "dns.optimistic_cache",
        "experimental.cache_file.enabled",
        "experimental.cache_file.store_fakeip",
        "experimental.cache_file.store_dns",
    ];
    assert_eq!(diagnostics.len(), expected.len(), "{diagnostics:?}");
    for (diagnostic, setting) in diagnostics.iter().zip(expected) {
        assert_eq!(diagnostic.setting, setting);
    }
    assert!(!config.global.tproxy_port_protect);
    assert!(!config.global.disable_waiting_network);
    assert!(!config.global.auto_config_kernel_parameter);
    assert!(!config.global.store_subscribe);
    assert!(!config.global.allow_insecure);
    assert!(!config.global.tls_fragment);
    assert!(!config.global.mptcp);
    assert!(!config.dns.cache.enabled);
    assert!(!config.experimental.cache_file.enabled);
    assert!(!config.experimental.cache_file.store_fakeip);
    assert!(!config.experimental.cache_file.store_dns);

    let valid_input = r#"
global {
    tproxy_port_protect: off
    disable_waiting_network: no
    auto_config_kernel_parameter: 0
    store_subscribe: FALSE
    allow_insecure: f
    tls_fragment: n
    mptcp: t
}
dns {
    optimistic_cache: y
}
experimental {
    cache_file {
        enabled: true
        store_fakeip: yes
        store_dns: on
    }
}
"#;
    let mut diagnostics = Vec::new();
    let config =
        super::parse_dae_config_with_detailed_diagnostics(valid_input, &mut diagnostics).unwrap();
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>(),
        ["legacy-bool-shorthand"; 4]
    );
    assert!(!config.global.tproxy_port_protect);
    assert!(!config.global.disable_waiting_network);
    assert!(!config.global.auto_config_kernel_parameter);
    assert!(!config.global.store_subscribe);
    assert!(!config.global.allow_insecure);
    assert!(!config.global.tls_fragment);
    assert!(!config.global.mptcp);
    assert!(!config.dns.cache.enabled);
    assert!(config.experimental.cache_file.enabled);
    assert!(config.experimental.cache_file.store_fakeip);
    assert!(config.experimental.cache_file.store_dns);
}

#[test]
fn test_unknown_group_policy_returns_a_diagnostic_without_the_text() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "group {\n    odd {\n        policy: mystery('trojan://super-secret@example.com:443')\n    }\n}",
        &mut diagnostics,
    )
    .unwrap();

    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].setting, "groups[1].policy");
    assert_eq!(diagnostics[0].value, "");
    assert!(!diagnostics[0].message.contains("super-secret"));
    assert_eq!(config.groups[0].policy, crate::group::GroupPolicy::Selector);
    assert!(!format!("{config:?}").contains("super-secret"));

    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        "group {\n    odd {\n        policy: select\n    }\n}",
        &mut diagnostics,
    )
    .unwrap();
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(config.groups[0].policy, crate::group::GroupPolicy::Selector);
}

#[test]
fn test_unparseable_group_filter_returns_a_diagnostic() {
    let input = "node {\n    probe: 'socks5://127.0.0.1:1080'\n}\ngroup {\n    proxy {\n        filter: bogus('x')\n    }\n}\n";
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(input, &mut diagnostics).unwrap();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].setting, "groups[1].filter");
    assert_eq!(diagnostics[0].value, "1");
    assert!(config.groups[0].nodes.is_empty());
}

#[test]
fn test_unterminated_group_filter_returns_a_diagnostic() {
    let input = "node {\n    probe: 'socks5://127.0.0.1:1080'\n}\ngroup {\n    proxy {\n        filter: group('hk'\n    }\n}\n";
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(input, &mut diagnostics).unwrap();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].setting, "groups[1].filter");
    assert_eq!(diagnostics[0].value, "1");
    assert!(config.groups[0].nodes.is_empty());
}

#[test]
fn test_group_filter_diagnostics_do_not_echo_the_filter() {
    let input = "node {\n    probe: 'socks5://127.0.0.1:1080'\n}\ngroup {\n    proxy {\n        filter: bogus('trojan://super-secret@example.com:443')\n    }\n}\n";
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(input, &mut diagnostics).unwrap();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].setting, "groups[1].filter");
    assert_eq!(diagnostics[0].value, "1");
    assert!(config.groups[0].nodes.is_empty());
    assert!(!diagnostics[0].setting.contains("super-secret"));
    assert!(!diagnostics[0].value.contains("super-secret"));
    assert!(!diagnostics[0].message.contains("super-secret"));
}

#[test]
fn quoted_conjunction_filter_matches_literal_on_reresolution() {
    let input = "node {\n    'a&&b': 'socks5://127.0.0.1:1080'\n    other: 'socks5://127.0.0.1:1081'\n}\ngroup {\n    proxy {\n        filter: name('a&&b')\n    }\n}\n";
    let mut diagnostics = Vec::new();
    let mut config = parse_dae_config_with_diagnostics(input, &mut diagnostics).unwrap();
    assert_eq!(config.groups[0].nodes, [config.nodes[0].id]);
    assert!(diagnostics.is_empty());

    config.nodes[0].name = "renamed".to_string();
    let replacement = crate::node::Node::from_share_link("socks5://127.0.0.1:1082#a&&b").unwrap();
    let replacement_id = replacement.id;
    config.nodes.push(replacement);
    crate::parser::resolve_group_filters(&mut config.groups, &config.nodes, &config.subscriptions);
    assert_eq!(config.groups[0].nodes, [replacement_id]);
}

#[test]
fn test_filter_ordinal_skips_subgroup_declarations() {
    let input = "node {\n    probe: 'socks5://127.0.0.1:1080'\n}\ngroup {\n    proxy {\n        filter: group('hk')\n        filter: bogus('x')\n    }\n}\n";
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(input, &mut diagnostics).unwrap();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].setting, "groups[1].filter");
    assert_eq!(diagnostics[0].value, "1");
    assert!(config.groups[0].nodes.is_empty());
    assert_eq!(config.groups[0].groups, ["hk"]);
}
