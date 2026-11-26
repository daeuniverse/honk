use honk_config::subscription::dns::SubscriptionDns;

fn parse(text: &str) -> Option<SubscriptionDns> {
    SubscriptionDns::parse(&serde_yaml::from_str(text).unwrap()).unwrap()
}

#[test]
fn subscription_import_is_opt_in_and_strict() {
    for documentation in [
        include_str!("../../../doc/en/reference/subscription.md"),
        include_str!("../../../doc/zh/reference/subscription.md"),
        include_str!("../../../doc/zh-TW/reference/subscription.md"),
    ] {
        let example = documentation
            .split("```dae\n")
            .nth(2)
            .unwrap()
            .split("```")
            .next()
            .unwrap();
        let config = honk_config::parser::parse_dae_config(example).unwrap();
        assert!(config.subscriptions[0].import_dns);
        assert!(!config.subscriptions[1].import_dns);
    }
    let config = honk_config::parser::parse_dae_config(
        "subscription {\n a: 'https://a.invalid/sub' {\n import_dns: yes\n }\n b: 'https://b.invalid/sub'\n}\n",
    )
    .unwrap();
    assert!(config.subscriptions[0].import_dns);
    assert!(!config.subscriptions[1].import_dns);
    let config = honk_config::Config::from_json_str(&config.to_json_string().unwrap()).unwrap();
    assert!(config.subscriptions[0].import_dns);
    assert!(!config.subscriptions[1].import_dns);
    let mut diags = Vec::new();
    let err = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        "subscription {\n a: 'https://a.invalid/sub' {\n import_dns: typo\n }\n}\n",
        &mut diags,
    )
    .unwrap_err();
    assert_eq!(err.diagnostic.code, "invalid-subscription-import-dns");
}

#[test]
fn node_policy_uses_mihomo_static_wildcard_and_suffix_precedence() {
    let dns = parse(
        "nameserver: 192.0.2.1\nnameserver-policy:\n 'a.example.com': [192.0.2.4, 192.0.2.5]\n '*.example.com': 'tcp://192.0.2.3:5353'\n '+.example.com': 192.0.2.2\n '.child.example.com': 192.0.2.6\n",
    )
    .unwrap();
    for (name, address) in [
        ("example.com", "192.0.2.2"),
        ("b.example.com", "192.0.2.3:5353"),
        ("A.EXAMPLE.COM.", "192.0.2.4"),
        ("a.b.example.com", "192.0.2.2"),
        ("a.child.example.com", "192.0.2.6"),
        ("other.test", "192.0.2.1"),
    ] {
        assert_eq!(dns.select(name).unwrap()[0].address, address, "{name}");
    }
    assert_eq!(dns.select("a.example.com").unwrap().len(), 2);
}

#[test]
fn proxy_branch_is_independent_and_policy_requires_default_list() {
    let dns = parse(
        "proxy-server-nameserver: 192.0.2.1\nproxy-server-nameserver-policy:\n '+.example.com': 192.0.2.2\nnameserver: {unsupported: true}\nnameserver-policy: { 'geosite:cn': 192.0.2.3 }\nfallback: [192.0.2.4]\nfallback-filter: { geoip: true }\n",
    )
    .unwrap();
    assert_eq!(dns.select("example.com").unwrap()[0].address, "192.0.2.2");
    assert_eq!(dns.select("other.test").unwrap()[0].address, "192.0.2.1");
    for invalid in [
        "proxy-server-nameserver-policy: { '+.example.com': 192.0.2.2 }",
        "proxy-server-nameserver: []\nproxy-server-nameserver-policy: { '+.example.com': 192.0.2.2 }",
    ] {
        assert!(SubscriptionDns::parse(&serde_yaml::from_str(invalid).unwrap()).is_err());
    }
}

#[test]
fn bootstrap_schemes_and_redacted_diagnostics_reject_unsafe_or_malformed_inputs() {
    let dns = parse(
        "nameserver: [' HTTPS://dns.example:39933/api-query?name=test ', 'h3://dns.example:8443/h3-query?k=1', 'http3://dns.example?k=2', 'QUIC://dns.example:8853', 'TLS://1.1.1.1:853']\ndefault-nameserver: [' 223.5.5.5 ', 'TCP://[2001:db8::53]:5353']\nipv6: false\n",
    )
    .unwrap();
    assert_eq!(
        dns.nameservers[0].address,
        "dns.example:39933/api-query?name=test"
    );
    assert_eq!(
        dns.nameservers[0].protocol,
        honk_config::types::DnsProtocol::Https
    );
    assert_eq!(dns.nameservers[1].address, "dns.example:8443/h3-query?k=1");
    assert_eq!(
        dns.nameservers[1].protocol,
        honk_config::types::DnsProtocol::H3
    );
    assert_eq!(dns.nameservers[2].address, "dns.example/dns-query?k=2");
    assert_eq!(
        dns.nameservers[2].protocol,
        honk_config::types::DnsProtocol::H3
    );
    assert_eq!(
        dns.nameservers[3].protocol,
        honk_config::types::DnsProtocol::Quic
    );
    assert_eq!(
        dns.nameservers[4].protocol,
        honk_config::types::DnsProtocol::Tls
    );
    assert_eq!(dns.default_nameservers.len(), 2);
    assert_eq!(dns.ipv6, Some(false));
    assert_eq!(
        parse("nameserver: ['https://dns.example?token=x/y']")
            .unwrap()
            .nameservers[0]
            .address,
        "dns.example/dns-query?token=x/y"
    );
    assert_eq!(
        parse("nameserver: 192.0.2.1\ndefault-nameserver: ['2001:db8::53']")
            .unwrap()
            .default_nameservers[0]
            .address,
        "2001:db8::53"
    );

    let long_label = format!("{}.example", "a".repeat(64));
    let long_domain = (0..64)
        .map(|i| format!("l{i:02}a"))
        .collect::<Vec<_>>()
        .join(".");
    assert!(long_domain.len() > 253);

    let cases = [
        "nameserver: [123]".to_owned(),
        "nameserver: ['https://dns.example/query?token=secret_token_value#PROXY']".to_owned(),
        "nameserver: ['https://dns.example/dns-query#skip-cert-verify=true']".to_owned(),
        "nameserver: ['https://secret_user:secret_pass@dns.example/dns-query']".to_owned(),
        "nameserver: ['192.0.2.1:0']".to_owned(),
        "nameserver: ['https://dns.example:0/dns-query']".to_owned(),
        "nameserver: ['tcp://[2001:db8::1]:0']".to_owned(),
        "nameserver: ['https://-bad.dns.example/dns-query']".to_owned(),
        "nameserver: ['https://bad-.dns.example/dns-query']".to_owned(),
        "nameserver: ['https://a..dns.example/dns-query']".to_owned(),
        format!("nameserver: ['https://{long_label}/dns-query']"),
        format!("nameserver: ['https://{long_domain}/dns-query']"),
        "nameserver-policy: { '-bad.example': 192.0.2.1 }".to_owned(),
        format!("nameserver-policy: {{ '+.{long_label}': 192.0.2.1 }}"),
        "nameserver: 192.0.2.1\nfallback: [192.0.2.2]".to_owned(),
        "nameserver: 192.0.2.1\nfallback-filter: { geoip: true }".to_owned(),
        "nameserver-policy: { 'geosite:cn': 192.0.2.1 }".to_owned(),
        "nameserver: 192.0.2.1\ndefault-nameserver: ['https://dns.example/query?token=secret_token_value']".to_owned(),
        "nameserver: 192.0.2.1\ndefault-nameserver: ['dns.example:53']".to_owned(),
        "nameserver: 192.0.2.1\ndefault-nameserver: []".to_owned(),
        "respect-rules: true".to_owned(),
        "nameserver: system".to_owned(),
        "nameserver: ['dhcp://eth0']".to_owned(),
    ];
    for text in &cases {
        let value: serde_yaml::Value = serde_yaml::from_str(text).unwrap();
        let error = SubscriptionDns::parse_indexed(2, &value).unwrap_err();
        let setting = error.diagnostic.setting.to_string();
        assert!(
            setting.starts_with("subscriptions[2].dns"),
            "unexpected setting '{setting}' for input: {text}"
        );
        let rendered = format!("{error} {:?}", error.diagnostic);
        for secret in [
            "dns.example",
            "secret_token_value",
            "secret_user",
            "secret_pass",
            "skip-cert-verify",
        ] {
            assert!(
                !rendered.contains(secret),
                "diagnostic leaked '{secret}': {rendered}"
            );
        }
    }
    assert!(parse("{}").is_none());
    assert!(parse("null").is_none());
    let dns = parse("nameserver-policy: { '+.example.com': 192.0.2.1 }").unwrap();
    assert!(dns.select("other.test").is_none());
}

#[test]
fn server_list_policy_and_unique_upstream_bounds_deduplicate_canonical_endpoints() {
    let eight = (1..=8)
        .map(|i| format!("192.0.2.{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    assert!(parse(&format!("nameserver: [{eight}]")).is_some());

    let nine = (1..=9)
        .map(|i| format!("192.0.2.{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let err = SubscriptionDns::parse_indexed(
        1,
        &serde_yaml::from_str(&format!("nameserver: [{nine}]")).unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        err.diagnostic.setting.to_string(),
        "subscriptions[1].dns.nameserver[9]"
    );

    let mut max_policies =
        String::from("nameserver: ['udp://192.0.2.1:53', '192.0.2.1']\nnameserver-policy:\n");
    for i in 0..512 {
        let server = if i % 2 == 0 {
            "192.0.2.1"
        } else {
            "'HTTPS://dns.provider.test:443/dns-query'"
        };
        max_policies.push_str(&format!(
            "  'host-{i}.test': [{server}, 'https://dns.provider.test']\n"
        ));
    }
    let deduplicated = parse(&max_policies).unwrap();
    assert_eq!(
        deduplicated.unique_upstreams().len(),
        2,
        "equivalent upstream spellings across 512 policies must share canonical upstream definitions"
    );

    max_policies.push_str("  'host-512.test': 192.0.2.1\n");
    let err = SubscriptionDns::parse_indexed(3, &serde_yaml::from_str(&max_policies).unwrap())
        .unwrap_err();
    assert_eq!(
        err.diagnostic.setting.to_string(),
        "subscriptions[3].dns.nameserver-policy[513]"
    );

    let mut sixty_four = String::from("nameserver-policy:\n");
    for i in 1..=64 {
        sixty_four.push_str(&format!("  'u-{i}.test': '198.51.100.{i}'\n"));
    }
    let max_unique = parse(&sixty_four).unwrap();
    assert_eq!(max_unique.unique_upstreams().len(), 64);

    sixty_four.push_str("  'u-65.test': '198.51.100.65'\n");
    let err =
        SubscriptionDns::parse_indexed(4, &serde_yaml::from_str(&sixty_four).unwrap()).unwrap_err();
    assert!(
        err.diagnostic
            .setting
            .to_string()
            .starts_with("subscriptions[4].dns")
    );
}

#[test]
fn canonical_authority_and_doh_root_paths_match_runtime_endpoint_grammar() {
    let dns = parse(
        "nameserver:\n  - 'https://doh.pub/'\n  - 'https://doh.pub'\n  - 'HTTPS://DOH.PUB:443/dns-query'\n  - 'h3://dns.alidns.com/'\n  - 'https://doh.pub/?ecs=1'\n  - 'https://[2001:db8::53]/'\n  - 'https://[2001:db8::53]:443/dns-query'\nnameserver-policy:\n  '+.v6.test':\n    - 'udp://[2001:db8::53]:53'\n    - '2001:db8::53'\n",
    )
    .unwrap();
    let addresses = dns
        .nameservers
        .iter()
        .chain(dns.policies.iter().flat_map(|p| &p.upstreams))
        .map(|u| (u.protocol, u.address.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        addresses,
        vec![
            (honk_config::types::DnsProtocol::Https, "doh.pub/dns-query"),
            (
                honk_config::types::DnsProtocol::H3,
                "dns.alidns.com/dns-query"
            ),
            (
                honk_config::types::DnsProtocol::Https,
                "doh.pub/dns-query?ecs=1"
            ),
            (
                honk_config::types::DnsProtocol::Https,
                "[2001:db8::53]/dns-query"
            ),
            (honk_config::types::DnsProtocol::Udp, "2001:db8::53"),
        ]
    );
    assert_eq!(dns.unique_upstreams().len(), 5);

    for bad in [
        "nameserver: ['udp://[2001:db8::1]:']",
        "nameserver: ['1.1.1.1:']",
        "nameserver: ['dns.example:']",
        "nameserver: ['https://dns.example:/dns-query']",
        "nameserver: ['2001:db8:1:2:3:4:5:6:5353']",
        "nameserver: ['udp://2001:db8::1']",
        "nameserver: ['https://2001:db8::1/dns-query']",
        "nameserver: ['127.1']",
        "nameserver: ['127.0.1']",
        "nameserver: ['2130706433']",
        "nameserver: ['0x7f.0.0.1']",
        "nameserver: ['https://127.1/dns-query']",
        "nameserver-policy: { '+.bad.123': 192.0.2.1 }",
    ] {
        let value: serde_yaml::Value = serde_yaml::from_str(bad).unwrap();
        let err = SubscriptionDns::parse_indexed(1, &value).unwrap_err();
        assert!(
            err.diagnostic
                .setting
                .to_string()
                .starts_with("subscriptions[1].dns"),
            "unexpected setting '{}' for {bad}",
            err.diagnostic.setting
        );
    }
}
