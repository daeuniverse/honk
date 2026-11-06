use honk_config::{
    datapath::InterfaceRole,
    firewall::{FirewallVerdict, SourceNat},
    parser::parse_dae_config,
};

fn config(body: &str) -> String {
    format!(
        "datapath {{\n backend: xdp\n direct: core\n interface {{ lan0: lan\n wan0: wan }}\n{body}\n}}"
    )
}

#[test]
fn typed_actions_preserve_stage_zone_and_port_pools() {
    let parsed = parse_dae_config(&config("firewall {\n original {\n lan: sip(10.0.0.0/24) && l4proto(tcp,udp) -> allow\n default: reject\n }\n forward {\n dip(10.0.1.8) -> allow\n }\n}\nnat {\n prerouting {\n dip(198.51.100.1) && dport(8080) -> dnat(10.0.1.8:80)\n }\n postrouting {\n sip(10.0.0.0/24) -> snat(198.51.100.1,40000-40001)\n }\n}")).unwrap();
    let datapath = parsed.datapath.unwrap();
    datapath.validate().unwrap();
    let firewall = datapath.firewall.unwrap();
    assert_eq!(firewall.original.rules[0].ingress, Some(InterfaceRole::Lan));
    assert_eq!(firewall.original.default, FirewallVerdict::Reject);
    assert_eq!(firewall.forward.default, FirewallVerdict::Drop);
    assert_eq!(datapath.nat.prerouting[0].action.port, Some(80));
    assert!(
        matches!(datapath.nat.postrouting[0].action, SourceNat::Snat { ports: Some(pool), .. } if pool.first == 40000 && pool.last == 40001)
    );
}

#[test]
fn invalid_security_compositions_never_become_ignored_rules() {
    for body in [
        "firewall { original { l4proto(tcp) -> direct } }",
        "firewall { unknown { l4proto(tcp) -> allow } }",
        "firewall { original { default: allow\n default: drop } }",
        "nat { prerouting { dip(192.0.2.1) -> dnat([2001:db8::1]:80) } }",
        "nat { postrouting { sip(10.0.0.0/24) -> masquerade(100-10) } }",
    ] {
        assert!(parse_dae_config(&config(body)).is_err(), "accepted {body}");
    }
    assert!(
        parse_dae_config(&config(
            "nat { postrouting { sip(10.0.0.0/24) -> masquerade() } }"
        ))
        .is_err()
    );
    assert!(
        parse_dae_config(&config(
            "firewall { original { !pname(browser) -> allow } }"
        ))
        .is_err()
    );
}

#[test]
fn security_chains_reject_nested_blocks_instead_of_ignoring_them() {
    for (section, chain, statement) in [
        ("firewall", "original", "default: allow"),
        ("firewall", "forward", "default: allow"),
        ("nat", "prerouting", "dip(192.0.2.1) -> dnat(10.0.0.8:80)"),
        ("nat", "postrouting", "sip(10.0.0.0/24) -> masquerade()"),
    ] {
        for nested in ["deny {\n dport(22) -> drop\n }", "deny {}", "deny {\n }"] {
            let firewall = if section == "nat" {
                "firewall {\n original {\n default: allow\n }\n }\n"
            } else {
                ""
            };
            let source = config(&format!(
                "{firewall}{section} {{\n {chain} {{\n {nested}\n {statement}\n }}\n }}"
            ));
            let mut diagnostics = Vec::new();
            let error = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
                &source,
                &mut diagnostics,
            )
            .unwrap_err();
            assert_eq!(error.diagnostic.code, "nested-security-block", "{source}");
            assert_eq!(error.category, honk_config::error::ErrorCategory::Parse);
            assert!(
                !diagnostics
                    .iter()
                    .any(|notice| notice.code == "unknown-block")
            );
        }
    }

    let mut diagnostics = Vec::new();
    honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        "routing {\n ignored {\n sip(10.0.0.1) -> block\n }\n fallback: direct\n }",
        &mut diagnostics,
    )
    .unwrap();
    assert!(
        diagnostics
            .iter()
            .any(|notice| notice.code == "unknown-block")
    );
}

#[test]
fn security_matchers_reject_empty_arguments_without_changing_routing() {
    for condition in [
        "sip()",
        "!pname()",
        "dip( )",
        "sport(,1024)",
        "dport(80,)",
        "l4proto(tcp,,udp)",
        "ipversion('')",
        "mac(\"\")",
        "dscp(, )",
        "domain( ,example.com)",
        "sip(\n # no address\n )",
    ] {
        for (section, chain, action) in [
            ("firewall", "original", "allow"),
            ("firewall", "forward", "drop"),
            ("nat", "prerouting", "dnat(10.0.0.8:80)"),
            ("nat", "postrouting", "masquerade()"),
        ] {
            let firewall = if section == "nat" {
                "firewall {\n original {\n default: allow\n }\n }\n"
            } else {
                ""
            };
            let source = config(&format!(
                "{firewall}{section} {{\n {chain} {{\n {condition} && l4proto(tcp) -> {action}\n }}\n }}"
            ));
            let error = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
                &source,
                &mut Vec::new(),
            )
            .unwrap_err();
            assert_eq!(error.diagnostic.code, "empty-matcher-argument", "{source}");
            assert_eq!(error.category, honk_config::error::ErrorCategory::Parse);
        }
        let routing = parse_dae_config(&format!(
            "routing {{\n {condition} && l4proto(tcp) -> direct\n }}"
        ))
        .unwrap();
        assert!(
            routing.routing.rules[0]
                .condition
                .protocol
                .iter()
                .any(|protocol| protocol == "tcp")
        );
    }
}

#[test]
fn nat_address_admission_matches_transit_unicast_boundaries() {
    use honk_config::firewall::{
        DestinationNat, DnatRule, FirewallConfig, NatConfig, SnatRule, validate,
    };
    let firewall = FirewallConfig::default();
    for (address, allowed) in [
        ("0.0.0.0", false),
        ("0.1.2.3", false),
        ("0.255.255.255", false),
        ("127.0.0.1", false),
        ("224.0.0.1", false),
        ("239.255.255.255", false),
        ("240.0.0.0", false),
        ("255.0.0.1", false),
        ("255.255.255.255", false),
        ("1.0.0.1", true),
        ("10.0.0.2", true),
        ("198.51.100.1", true),
        ("223.255.255.255", true),
    ] {
        let address = address.parse().unwrap();
        let dnat = NatConfig {
            prerouting: vec![DnatRule {
                condition: Default::default(),
                action: DestinationNat {
                    address,
                    port: Some(80),
                },
            }],
            ..Default::default()
        };
        let snat = NatConfig {
            postrouting: vec![SnatRule {
                condition: Default::default(),
                action: SourceNat::Snat {
                    address,
                    ports: None,
                },
            }],
            ..Default::default()
        };
        for nat in [dnat, snat] {
            let decoded: NatConfig =
                serde_json::from_str(&serde_json::to_string(&nat).unwrap()).unwrap();
            assert_eq!(
                validate(Some(&firewall), &decoded).is_ok(),
                allowed,
                "structured NAT address {address}"
            );
        }
        for action in [
            format!("prerouting {{ dip(192.0.2.1) -> dnat({address}:80) }}"),
            format!("postrouting {{ sip(10.0.0.0/24) -> snat({address}) }}"),
        ] {
            let body = format!("firewall {{ original {{ default: allow }} }}\nnat {{ {action} }}");
            assert_eq!(
                parse_dae_config(&config(&body)).is_ok(),
                allowed,
                "dae NAT address {address}"
            );
        }
    }
}

fn encode_structured(value: &serde_json::Value, format: &str) -> String {
    match format {
        "json" => serde_json::to_string(value).unwrap(),
        "toml" => toml::to_string(value).unwrap(),
        "yaml" => serde_yaml::to_string(value).unwrap(),
        _ => unreachable!(),
    }
}

fn decode_structured<T: serde::de::DeserializeOwned>(
    source: &str,
    format: &str,
) -> Result<T, String> {
    match format {
        "json" => serde_json::from_str(source).map_err(|error| error.to_string()),
        "toml" => toml::from_str(source).map_err(|error| error.to_string()),
        "yaml" => serde_yaml::from_str(source).map_err(|error| error.to_string()),
        _ => unreachable!(),
    }
}

fn assert_strict_security_conditions<T: serde::de::DeserializeOwned + serde::Serialize>(
    mut root: serde_json::Value,
    rule_path: &str,
) {
    use honk_config::{Config, routing::RoutingCondition};
    use serde_json::json;

    for (condition, valid) in [
        (
            json!({"source_ip": ["10.0.0.0/24"], "protocol": ["tcp"]}),
            true,
        ),
        (
            json!({
                "source_ip": ["10.0.0.0/24"], "ip": ["198.51.100.1"],
                "source_port": ["1024-65535"], "port": ["80"], "protocol": ["tcp"],
                "ip_version": ["4"], "dscp": ["0"],
                "not": {"source_ip": ["10.0.0.8"], "port": ["22"]}
            }),
            true,
        ),
        (
            json!({"source_ips": ["10.0.0.0/24"], "protocol": ["tcp"]}),
            false,
        ),
        (
            json!({"protocol": ["tcp"], "not": {
                "source_ips": ["10.0.0.8"], "port": ["22"]
            }}),
            false,
        ),
    ] {
        root.pointer_mut(rule_path).unwrap()["condition"] = condition.clone();
        let rule = root.pointer(rule_path).unwrap();
        let canonical = valid.then(|| {
            serde_json::to_value(
                serde_json::from_value::<RoutingCondition>(condition.clone()).unwrap(),
            )
            .unwrap()
        });
        for format in ["json", "toml", "yaml"] {
            let decoded = decode_structured::<T>(&encode_structured(rule, format), format);
            assert_eq!(decoded.is_ok(), valid, "{format} {rule_path}: {condition}");
            if let Ok(decoded) = decoded {
                assert_eq!(
                    serde_json::to_value(decoded).unwrap()["condition"],
                    *canonical.as_ref().unwrap()
                );
            }

            let source = encode_structured(&root, format);
            let decoded = decode_structured::<Config>(&source, format);
            assert_eq!(
                decoded.is_ok(),
                valid,
                "Config serde {format} {rule_path}: {condition}"
            );
            if let Ok(decoded) = decoded {
                decoded.datapath.as_ref().unwrap().validate().unwrap();
                assert_eq!(
                    serde_json::to_value(decoded)
                        .unwrap()
                        .pointer(&format!("{rule_path}/condition")),
                    canonical.as_ref()
                );
            }
            let file = tempfile::Builder::new()
                .suffix(&format!(".{format}"))
                .tempfile()
                .unwrap();
            std::fs::write(file.path(), &source).unwrap();
            let loaded = Config::from_file(file.path().to_str().unwrap());
            assert_eq!(
                loaded.is_ok(),
                valid,
                "Config file {format} {rule_path}: {condition}"
            );
            if let Ok(loaded) = loaded {
                assert_eq!(
                    serde_json::to_value(loaded)
                        .unwrap()
                        .pointer(&format!("{rule_path}/condition")),
                    canonical.as_ref()
                );
            }
            if format == "json" {
                assert_eq!(
                    Config::from_json_str(&source).is_ok(),
                    valid,
                    "Config JSON {rule_path}: {condition}"
                );
            }
        }
    }
}

#[test]
fn structured_security_conditions_reject_unknown_fields_at_every_constructor() {
    use honk_config::firewall::{DnatRule, FirewallRule, SnatRule};
    use serde_json::json;

    let root = json!({"datapath": {
        "backend": "xdp", "direct": "core",
        "interfaces": [{"name": "lan0", "role": "lan"}, {"name": "wan0", "role": "wan"}],
        "firewall": {
            "original": {"rules": [{"condition": {}, "verdict": "allow"}]},
            "forward": {"rules": [{"condition": {}, "verdict": "allow"}]}
        },
        "nat": {
            "prerouting": [{"condition": {}, "action": {"address": "10.0.0.8", "port": 80}}],
            "postrouting": [
                {"condition": {}, "action": {"kind": "snat", "address": "198.51.100.1"}},
                {"condition": {}, "action": {"kind": "masquerade", "ports": {"first": 40000, "last": 40001}}}
            ]
        }
    }});
    assert_strict_security_conditions::<FirewallRule>(
        root.clone(),
        "/datapath/firewall/original/rules/0",
    );
    assert_strict_security_conditions::<FirewallRule>(
        root.clone(),
        "/datapath/firewall/forward/rules/0",
    );
    assert_strict_security_conditions::<DnatRule>(root.clone(), "/datapath/nat/prerouting/0");
    assert_strict_security_conditions::<SnatRule>(root.clone(), "/datapath/nat/postrouting/0");
    assert_strict_security_conditions::<SnatRule>(root, "/datapath/nat/postrouting/1");
}

#[test]
fn strict_security_admission_preserves_legacy_routing_serde() {
    let source = r#"{"source_ips":["10.0.0.0/24"],"protocol":["tcp"],"not":{"source_ips":["10.0.0.8"],"port":["22"]},"outbound":"direct"}"#;
    for format in ["json", "toml", "yaml"] {
        let encoded = encode_structured(&serde_json::from_str(source).unwrap(), format);
        let rule =
            decode_structured::<honk_config::routing::RoutingRule>(&encoded, format).unwrap();
        assert_eq!(rule.condition.protocol, ["tcp"]);
        assert_eq!(rule.condition.not.port, ["22"]);
        assert!(rule.condition.source_ip.is_empty());
        assert!(rule.condition.not.source_ip.is_empty());
    }
}
