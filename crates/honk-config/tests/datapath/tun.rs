use super::{Backend, Config, DirectProfile, dae_fields, polling_parameters};

fn tun_parameters() -> serde_json::Value {
    serde_json::json!({
        "name": "honk0", "address4": "198.18.0.1/32",
        "address6": "fd00:686f:6e6b:100::1/128", "table": 202,
        "rule_priority": 10000, "capture": ["0.0.0.0/0", "::/0"]
    })
}

fn tun_block(value: &serde_json::Value) -> String {
    let mut scalars = value.clone();
    let capture = scalars.as_object_mut().unwrap().remove("capture");
    let mut body = dae_fields(&scalars);
    if let Some(capture) = capture {
        body.push_str("capture {\n");
        for prefix in capture.as_array().unwrap() {
            body.push_str(prefix.as_str().unwrap());
            body.push('\n');
        }
        body.push_str("}\n");
    }
    format!("tun {{\n{body}}}")
}

fn tun_source(value: &serde_json::Value) -> String {
    format!(
        "datapath {{\nbackend: tun\ndirect: endpoint\n{}\n}}",
        tun_block(value)
    )
}

fn tun_json(value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"datapath": {"backend": "tun", "direct": "endpoint", "tun": value}})
}

fn assert_tun_admission(value: &serde_json::Value, accepted: bool) {
    assert_eq!(
        honk_config::parser::parse_dae_config(&tun_source(value)).is_ok(),
        accepted,
        "dae {value}"
    );
    assert_eq!(
        Config::from_json_str(&tun_json(value).to_string())
            .and_then(|config| config.validate())
            .is_ok(),
        accepted,
        "structured {value}"
    );
}

#[test]
fn tun_documented_endpoint_example_survives_both_adapters() {
    let source = r#"
global { nfqueue_enable: false
    so_mark_from_dae: 0x100
    dial_mode: ip }
datapath { backend: tun
    direct: endpoint
    tun { name: honk0
        mtu: 1500
        address4: 198.18.0.1/32
        address6: fd00:686f:6e6b:100::1/128
        table: 202
        rule_priority: 10000
        capture { 0.0.0.0/0
            ::/0 } } }
routing { fallback: direct }
"#;
    let config = honk_config::parser::parse_dae_config(source).unwrap();
    config.validate_detailed().unwrap();
    config.validate_assembled().unwrap();
    let datapath = config.datapath.as_ref().unwrap();
    assert_eq!(datapath.backend, Backend::Tun);
    assert_eq!(datapath.direct, Some(DirectProfile::Endpoint));
    let tun = datapath.tun.as_ref().unwrap();
    assert_eq!(tun.name, "honk0");
    assert_eq!(tun.mtu, 1500);
    assert_eq!(tun.address4, Some("198.18.0.1".parse().unwrap()));
    assert_eq!(tun.address6, Some("fd00:686f:6e6b:100::1".parse().unwrap()));
    assert_eq!((tun.table, tun.rule_priority), (202, 10000));
    let encoded = serde_json::to_value(&config).unwrap();
    assert_eq!(encoded["datapath"]["tun"]["address4"], "198.18.0.1/32");
    assert_eq!(
        encoded["datapath"]["tun"]["address6"],
        "fd00:686f:6e6b:100::1/128"
    );
    let decoded = Config::from_json_str(&encoded.to_string()).unwrap();
    decoded.validate().unwrap();
    assert_eq!(decoded.datapath, config.datapath);
}

#[test]
fn tun_required_fields_unknown_settings_and_duplicate_claims_reject() {
    let mut valid = tun_parameters();
    valid["mtu"] = 1500.into();
    for key in ["name", "table", "rule_priority", "capture"] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert_tun_admission(&missing, false);
    }
    for key in [
        "host_facts",
        "fd",
        "persistent",
        "auto_route",
        "setup_hook",
        "unknown",
    ] {
        let mut unknown = valid.clone();
        unknown[key] = true.into();
        assert_tun_admission(&unknown, false);
    }
    for (key, value) in valid.as_object().unwrap() {
        let duplicate = if key == "capture" {
            "capture { 0.0.0.0/0 }".to_owned()
        } else {
            format!(
                "{key}: {}",
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string())
            )
        };
        let source = tun_source(&valid).replacen("tun {\n", &format!("tun {{\n{duplicate}\n"), 1);
        assert!(
            honk_config::parser::parse_dae_config(&source).is_err(),
            "{source}"
        );
        let json = valid.to_string();
        let duplicate = format!("{},\"{key}\":{value}}}", &json[..json.len() - 1]);
        assert!(serde_json::from_str::<honk_config::datapath::TunConfig>(&duplicate).is_err());
    }
    for extra in ["unknown {}", "name {}"] {
        let source = tun_source(&valid).replacen("tun {\n", &format!("tun {{\n{extra}\n"), 1);
        assert!(
            honk_config::parser::parse_dae_config(&source).is_err(),
            "{source}"
        );
    }
    for capture in [
        "capture {}",
        "capture {\n}",
        "capture { prefix: 0.0.0.0/0 }",
        "capture { nested {} }",
        "capture { ::/0 {} }",
    ] {
        let source = tun_source(&valid).replace("capture {\n0.0.0.0/0\n::/0\n}", capture);
        assert!(
            honk_config::parser::parse_dae_config(&source).is_err(),
            "{source}"
        );
    }
    for backend in ["tc", "xdp", "tun"] {
        assert!(
            Config::from_json_str(&format!(
                r#"{{"datapath":{{"backend":"{backend}","tun":null}}}}"#
            ))
            .is_err()
        );
    }
}

#[test]
fn tun_names_and_host_addresses_are_strict_in_both_adapters() {
    for name in [
        "",
        "lo",
        "auto",
        "a/b",
        "a%b",
        "é",
        "a\0b",
        "1234567890123456",
    ] {
        let mut value = tun_parameters();
        value["name"] = name.into();
        assert_tun_admission(&value, false);
    }
    for name in ["h", "honk_0.x-y", "123456789012345"] {
        let mut value = tun_parameters();
        value["name"] = name.into();
        assert_tun_admission(&value, true);
    }
    for (key, addresses) in [
        (
            "address4",
            vec![
                "198.18.0.1",
                "198.18.0.1/24",
                "::1/32",
                "0.0.0.0/32",
                "224.0.0.1/32",
                "255.255.255.255/32",
                "169.254.0.1/32",
            ],
        ),
        (
            "address6",
            vec![
                "fd00::1",
                "fd00::1/64",
                "198.18.0.1/128",
                "::/128",
                "ff02::1/128",
                "fe80::1/128",
                "::ffff:198.18.0.1/128",
            ],
        ),
    ] {
        for address in addresses {
            let mut value = tun_parameters();
            value[key] = address.into();
            assert_tun_admission(&value, false);
        }
    }
    let mut value = tun_parameters();
    value.as_object_mut().unwrap().remove("address4");
    value.as_object_mut().unwrap().remove("address6");
    assert_tun_admission(&value, false);
}

#[test]
fn tun_capture_prefixes_are_canonical_bounded_and_family_checked() {
    let mut value = tun_parameters();
    value["capture"] =
        serde_json::json!(["2001:db8::/32", "10.1.0.0/16", "10.0.0.0/16", "10.1.0.0/16"]);
    let dae = honk_config::parser::parse_dae_config(&tun_source(&value)).unwrap();
    let json = Config::from_json_str(&tun_json(&value).to_string()).unwrap();
    json.validate().unwrap();
    assert_eq!(dae.datapath, json.datapath);
    let prefixes = &dae.datapath.as_ref().unwrap().tun.as_ref().unwrap().capture;
    assert_eq!(
        prefixes.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["10.0.0.0/16", "10.1.0.0/16", "2001:db8::/32"]
    );
    for prefixes in [
        vec![],
        vec!["10.0.0.1/24"],
        vec!["2001:db8::1/32"],
        vec!["10.0.0.1"],
        vec!["10.1.0.0/16", "10.0.0.0/8"],
        vec!["2001:db8::/32", "2001:db8:1::/48"],
    ] {
        value["capture"] = prefixes.into();
        assert_tun_admission(&value, false);
    }
    for count in [64, 65] {
        value["capture"] = (0..count)
            .map(|index| format!("10.0.0.{index}/32"))
            .collect::<Vec<_>>()
            .into();
        assert_tun_admission(&value, count == 64);
    }
    for (missing, prefix) in [("address4", "::/0"), ("address6", "0.0.0.0/0")] {
        let mut value = tun_parameters();
        value.as_object_mut().unwrap().remove(missing);
        assert_tun_admission(&value, false);
        value["capture"] = serde_json::json!([prefix]);
        assert_tun_admission(&value, true);
    }
}

#[test]
fn tun_device_resources_enforce_checked_numeric_bounds() {
    for (key, numbers) in [
        ("mtu", vec![1280, 1500, 65535]),
        ("table", vec![1, 252, 256, 4294967294_u64]),
        ("rule_priority", vec![1, 32761]),
    ] {
        for number in numbers {
            let mut value = tun_parameters();
            value[key] = number.into();
            assert_tun_admission(&value, true);
        }
    }
    for (key, numbers) in [
        ("mtu", vec![0, 1279, 65536]),
        (
            "table",
            vec![0, 253, 254, 255, 4294967295_u64, 4294967296_u64],
        ),
        (
            "rule_priority",
            vec![0, 32762, 32766, 4294967295_u64, 4294967296_u64],
        ),
    ] {
        for number in numbers {
            let mut value = tun_parameters();
            value[key] = number.into();
            assert_tun_admission(&value, false);
        }
    }
    for key in ["mtu", "table", "rule_priority"] {
        for bad in [
            serde_json::Value::Null,
            serde_json::json!(-1),
            serde_json::json!(1.5),
        ] {
            let mut value = tun_parameters();
            value[key] = bad;
            assert_tun_admission(&value, false);
        }
    }
}

#[test]
fn tun_backend_compositions_preserve_tc_and_xdp_contracts() {
    let value = tun_parameters();
    let source = tun_source(&value);
    for extra in [
        "interface {\n}",
        "interface { dut0: lan }",
        "xsk_mode: copy",
        "poll_mode: event",
        "firewall { original { default: allow } }",
        "nat { postrouting { sip(10.0.0.0/24) -> masquerade() } }",
    ] {
        let source = source.replacen("datapath {\n", &format!("datapath {{\n{extra}\n"), 1);
        assert!(
            honk_config::parser::parse_dae_config(&source).is_err(),
            "{source}"
        );
    }
    for direct in ["core", "native"] {
        assert!(
            honk_config::parser::parse_dae_config(
                &source.replace("direct: endpoint", &format!("direct: {direct}"))
            )
            .is_err()
        );
    }
    assert!(
        honk_config::parser::parse_dae_config(&source.replace("direct: endpoint\n", "")).is_err()
    );
    assert!(
        honk_config::parser::parse_dae_config("datapath { backend: tun\ndirect: endpoint }")
            .is_err()
    );
    for backend in ["tc", "xdp"] {
        assert!(
            honk_config::parser::parse_dae_config(
                &source.replace("backend: tun", &format!("backend: {backend}"))
            )
            .is_err()
        );
        let mut json = tun_json(&value);
        json["datapath"]["backend"] = backend.into();
        json["datapath"]["direct"] = if backend == "tc" {
            serde_json::Value::Null
        } else {
            "endpoint".into()
        };
        json["datapath"]["interfaces"] = if backend == "tc" {
            serde_json::json!([])
        } else {
            serde_json::json!([{"name": "dut0", "role": "lan"}])
        };
        assert!(
            Config::from_json_str(&json.to_string())
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for (key, setting) in [
        ("direct", serde_json::json!("core")),
        (
            "interfaces",
            serde_json::json!([{"name":"dut0","role":"lan"}]),
        ),
        ("xsk_mode", serde_json::json!("copy")),
        ("poll_mode", serde_json::json!("event")),
        ("busy_poll", polling_parameters()),
        ("firewall", serde_json::json!({})),
        (
            "nat",
            serde_json::json!({"postrouting":[{"condition":{},"action":{"kind":"masquerade","ports":{"first":1024,"last":65535}}}]}),
        ),
    ] {
        let mut json = tun_json(&value);
        json["datapath"][key] = setting;
        assert!(
            Config::from_json_str(&json.to_string())
                .and_then(|config| config.validate())
                .is_err(),
            "{json}"
        );
    }
    assert!(
        honk_config::datapath::DatapathConfig::default()
            .same_device_setup(&serde_json::from_str(r#"{"backend":"tc"}"#).unwrap())
    );
}

#[test]
fn tun_merged_sections_and_includes_reject_duplicate_claims() {
    let directory = tempfile::tempdir().unwrap();
    let entry = directory.path().join("main.dae");
    let child = directory.path().join("child.dae");
    let block = tun_block(&tun_parameters());
    let main = "include { child.dae }\ndatapath { backend: tun\ndirect: endpoint }";
    std::fs::write(&entry, main).unwrap();
    std::fs::write(&child, format!("datapath {{\n{block}\n}}")).unwrap();
    let loaded = Config::from_file(entry.to_str().unwrap()).unwrap();
    assert_eq!(
        loaded.datapath,
        honk_config::parser::parse_dae_config(&tun_source(&tun_parameters()))
            .unwrap()
            .datapath
    );
    for extra in [
        "backend: tun".to_owned(),
        "direct: endpoint".to_owned(),
        block.clone(),
    ] {
        let source = format!(
            "{}\ndatapath {{\n{extra}\n}}",
            tun_source(&tun_parameters())
        );
        assert!(honk_config::parser::parse_dae_config(&source).is_err());
        std::fs::write(
            &child,
            format!("datapath {{\n{block}\n}}\ndatapath {{\n{extra}\n}}"),
        )
        .unwrap();
        assert!(Config::from_file(entry.to_str().unwrap()).is_err());
    }
    std::fs::write(&entry, format!("{main}\ndatapath {{\n{block}\n}}")).unwrap();
    std::fs::write(&child, format!("datapath {{\n{block}\n}}")).unwrap();
    assert!(Config::from_file(entry.to_str().unwrap()).is_err());
}

#[test]
fn tun_device_restart_identity_compares_every_setting() {
    let value = tun_parameters();
    let original = honk_config::parser::parse_dae_config(&tun_source(&value))
        .unwrap()
        .datapath
        .unwrap();
    let mut explicit = value.clone();
    explicit["mtu"] = 1500.into();
    explicit["capture"] = serde_json::json!(["::/0", "0.0.0.0/0", "::/0"]);
    let equivalent = honk_config::parser::parse_dae_config(&tun_source(&explicit))
        .unwrap()
        .datapath
        .unwrap();
    assert_eq!(original, equivalent);
    assert!(original.same_device_setup(&equivalent));
    for (key, changed) in [
        ("name", serde_json::json!("honk1")),
        ("mtu", serde_json::json!(9000)),
        ("address4", serde_json::json!("198.18.0.2/32")),
        ("address6", serde_json::json!("fd00:686f:6e6b:100::2/128")),
        ("table", serde_json::json!(203)),
        ("rule_priority", serde_json::json!(10001)),
        ("capture", serde_json::json!(["10.0.0.0/8", "::/0"])),
    ] {
        let mut value = value.clone();
        value[key] = changed;
        let changed = honk_config::parser::parse_dae_config(&tun_source(&value))
            .unwrap()
            .datapath
            .unwrap();
        assert!(!original.same_device_setup(&changed), "{key}");
        assert!(!changed.same_device_setup(&original), "{key}");
    }
    let mut changed = original.clone();
    changed.direct = Some(DirectProfile::Core);
    assert!(!original.same_device_setup(&changed));
    changed = original.clone();
    changed.backend = Backend::Xdp;
    assert!(!original.same_device_setup(&changed));
}

#[test]
fn tun_direct_models_use_shared_canonical_admission() {
    let original = honk_config::parser::parse_dae_config(&tun_source(&tun_parameters())).unwrap();
    for case in 0..13 {
        let mut config = original.clone();
        let tun = config.datapath.as_mut().unwrap().tun.as_mut().unwrap();
        match case {
            0 => tun.name.clear(),
            1 => tun.mtu = 1279,
            2 => tun.address4 = Some(std::net::Ipv4Addr::UNSPECIFIED),
            3 => {
                tun.address4 = None;
                tun.address6 = None;
            }
            4 => tun.table = 0,
            5 => tun.rule_priority = u32::MAX,
            6 => tun.capture = vec!["10.0.0.1/24".parse().unwrap()],
            7 => tun.capture.reverse(),
            8 => tun.capture.push(tun.capture[1]),
            9 => {
                tun.capture = vec![
                    "10.0.0.0/8".parse().unwrap(),
                    "10.1.0.0/16".parse().unwrap(),
                ]
            }
            10 => tun.address6 = None,
            11 => tun.capture = vec!["10.0.0.1/32".parse().unwrap(); 65],
            12 => tun.capture.clear(),
            _ => unreachable!(),
        }
        assert!(tun.validate().is_err(), "case {case}");
        for result in [config.validate_detailed(), config.validate_assembled()] {
            assert_eq!(
                result.unwrap_err().diagnostic.code,
                "invalid-datapath-config",
                "case {case}"
            );
        }
    }
}

#[test]
fn tun_structured_interface_presence_and_parse_only_boundary_are_preserved() {
    for interfaces in [serde_json::json!([]), serde_json::Value::Null] {
        let mut value = tun_json(&tun_parameters());
        value["datapath"]["interfaces"] = interfaces;
        assert!(Config::from_json_str(&value.to_string()).is_err());
    }
    for field in ["xsk_mode", "firewall"] {
        let mut value = tun_json(&tun_parameters());
        value["datapath"][field] = serde_json::Value::Null;
        assert!(
            Config::from_json_str(&value.to_string()).is_err(),
            "accepted {field}"
        );
    }
    let mut value = tun_parameters();
    value["table"] = 0.into();
    let parsed = Config::from_json_str(&tun_json(&value).to_string()).unwrap();
    assert!(parsed.validate().is_err());
    let tc = Config::from_json_str(r#"{"datapath":{"backend":"tc","interfaces":[]}}"#).unwrap();
    tc.validate().unwrap();
    assert_eq!(
        serde_json::to_value(tc).unwrap()["datapath"],
        serde_json::json!({
            "backend":"tc", "direct":null, "xsk_mode":null, "interfaces":[],
            "firewall":null, "nat":{"prerouting":[],"postrouting":[]}
        })
    );
    let xdp = Config::from_json_str(
        r#"{"datapath":{"backend":"xdp","direct":"endpoint","interfaces":[]}}"#,
    )
    .unwrap();
    assert!(xdp.validate().is_err());
}
