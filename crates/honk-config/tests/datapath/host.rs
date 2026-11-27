use super::*;
use honk_config::datapath::{DatapathConfig, HostConfig};
use honk_config::parser::parse_dae_config;
use serde_json::json;

fn source(host: &str) -> String {
    format!("datapath {{\n backend: xdp\n direct: endpoint\n host {{\n {host}\n }}\n}}")
}

fn structured(host: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "backend": "xdp", "direct": "endpoint", "host": host
    })
}

fn admitted(value: serde_json::Value) -> bool {
    serde_json::from_value::<DatapathConfig>(value).is_ok_and(|config| config.validate().is_ok())
}

#[test]
fn host_only_and_mixed_adapters_preserve_physical_xsk_settings() {
    for mode in [
        None,
        Some(("copy", XskMode::Copy)),
        Some(("auto", XskMode::Auto)),
    ] {
        let mut dae = source("interface {\n eth0.100\n wg-wan\n }");
        let mut value = structured(json!({"interfaces": ["eth0.100", "wg-wan"]}));
        if let Some((spelling, _)) = mode {
            dae.push_str(&format!(
                "\ndatapath {{ xsk_mode: {spelling}\n interface {{ lan0: lan }} }}"
            ));
            value["xsk_mode"] = json!(spelling);
            value["interfaces"] = json!([{"name": "lan0", "role": "lan"}]);
        }
        let parsed = honk_config::parser::parse_dae_config(&dae)
            .unwrap()
            .datapath
            .unwrap();
        let decoded: DatapathConfig = serde_json::from_value(value).unwrap();
        decoded.validate().unwrap();
        assert_eq!(parsed, decoded);
        assert_eq!(
            parsed.host,
            Some(HostConfig {
                interfaces: vec!["eth0.100".into(), "wg-wan".into()],
            })
        );
        assert_eq!(parsed.xsk_mode, mode.map(|(_, mode)| mode));
        assert_eq!(
            parsed.effective_xsk_mode(),
            mode.map_or(XskMode::ZeroCopy, |(_, mode)| mode)
        );
        assert_eq!(parsed.interfaces.len(), usize::from(mode.is_some()));
        let serialized = serde_json::to_value(&parsed).unwrap();
        assert_eq!(
            serialized["host"],
            json!({"interfaces": ["eth0.100", "wg-wan"]})
        );
        let roundtrip: DatapathConfig = serde_json::from_value(serialized).unwrap();
        assert_eq!(roundtrip, parsed);
    }
    assert!(
        serde_json::to_value(DatapathConfig::default())
            .unwrap()
            .get("host")
            .is_none()
    );
    assert!(Config::default().datapath.is_none());
}

#[test]
fn host_requires_unique_bounded_explicit_names_in_both_adapters() {
    for body in [
        "",
        "interface { eth0: lan }",
        "interface { eth0 {} }",
        "interface { eth0 { queue: 0 } }",
        "interface { eth0 }\n queue: 0",
        "interface { eth0 }\n include { child.dae }",
        "interface { eth0 }\n interface { eth1 }",
    ] {
        assert!(
            honk_config::parser::parse_dae_config(&source(body)).is_err(),
            "accepted {body}"
        );
    }
    for host in [
        serde_json::Value::Null,
        json!({}),
        json!({"interfaces": null}),
        json!({"interfaces": ["eth0"], "queue": 0}),
    ] {
        let error = serde_json::from_value::<DatapathConfig>(structured(host.clone()));
        assert!(error.is_err(), "accepted {host}");
    }
    for (names, accepted) in [
        (vec![], false),
        (vec!["eth0", "eth0"], false),
        (vec!["auto"], false),
        (vec!["AUTO"], false),
        (vec!["lo"], false),
        (vec!["eth*"], false),
        (vec![""], false),
        (vec![" foo"], false),
        (vec!["."], false),
        (vec![".."], false),
        (vec!["abcdefghijklmno"], true),
        (vec!["abcdefghijklmnop"], false),
        (vec!["eth0", "eth1", "eth2", "eth3"], true),
        (vec!["eth0", "eth1", "eth2", "eth3", "eth4"], false),
    ] {
        let entries = names
            .iter()
            .map(|name| format!("\"{name}\"\n"))
            .collect::<String>();
        let dae = source(&format!("interface {{\n{entries}}}"));
        assert_eq!(parse_dae_config(&dae).is_ok(), accepted, "{names:?}");
        assert_eq!(
            admitted(structured(json!({"interfaces": names}))),
            accepted,
            "{names:?}"
        );
    }
}

#[test]
fn host_backend_direct_and_presence_boundaries_are_strict() {
    let host = json!({"interfaces": ["eth0"]});
    for backend in ["tc", "tun", "xdp"] {
        for direct in [None, Some("core"), Some("endpoint"), Some("native")] {
            let mut value = structured(host.clone());
            value["backend"] = backend.into();
            value["direct"] = serde_json::json!(direct);
            assert_eq!(
                admitted(value),
                backend == "xdp" && direct == Some("endpoint")
            );
            let direct = direct
                .map(|direct| format!("direct: {direct}\n"))
                .unwrap_or_default();
            let dae = format!(
                "datapath {{\n backend: {backend}\n {direct} host {{ interface {{ eth0 }} }}\n}}"
            );
            assert_eq!(
                honk_config::parser::parse_dae_config(&dae).is_ok(),
                backend == "xdp" && direct.as_str() == "direct: endpoint\n"
            );
        }
        let mut value = structured(serde_json::Value::Null);
        value["backend"] = backend.into();
        assert!(!admitted(value));
    }
    assert!(!admitted(
        serde_json::json!({"backend": "xdp", "direct": "endpoint"})
    ));
    for json in [
        r#"{"backend":"xdp","direct":"endpoint","host":{"interfaces":["eth0"],"xsk_mode":"copy","xsk_mode":"copy"}}"#,
        r#"{"backend":"xdp","direct":"endpoint","host":{"interfaces":["eth0"],"interfaces":["eth1"]}}"#,
        r#"{"backend":"xdp","direct":"endpoint","host":{"interfaces":["eth0"]},"host":{"interfaces":["eth1"]}}"#,
    ] {
        assert!(serde_json::from_str::<DatapathConfig>(json).is_err());
    }
}

#[test]
fn host_include_and_merged_sections_reject_repeated_blocks() {
    let directory = tempfile::tempdir().unwrap();
    let entry = directory.path().join("main.dae");
    let child = directory.path().join("child.dae");
    let host = "datapath { host { interface { eth0 } } }";
    std::fs::write(
        &entry,
        "include { child.dae }\ndatapath { backend: xdp\n direct: endpoint }",
    )
    .unwrap();
    std::fs::write(&child, host).unwrap();
    let parsed = Config::from_file(entry.to_str().unwrap()).unwrap();
    assert_eq!(parsed.datapath.unwrap().host.unwrap().interfaces, ["eth0"]);
    std::fs::write(
        &entry,
        format!("include {{ child.dae }}\n{}", source("interface { eth0 }")),
    )
    .unwrap();
    assert!(Config::from_file(entry.to_str().unwrap()).is_err());
    assert!(
        honk_config::parser::parse_dae_config(&format!("{}\n{host}", source("interface { eth0 }")))
            .is_err()
    );
}

#[test]
fn host_exact_identity_is_restart_only_and_independent_of_physical_copy() {
    let initial = honk_config::parser::parse_dae_config(&source("interface {\n eth0\n eth1\n }"))
        .unwrap()
        .datapath
        .unwrap();
    assert!(initial.same_device_setup(&initial.clone()));
    let mut changed = initial.clone();
    changed.host = None;
    assert!(!initial.same_device_setup(&changed));
    changed = initial.clone();
    changed.host.as_mut().unwrap().interfaces.reverse();
    assert!(!initial.same_device_setup(&changed));
    changed = initial.clone();
    changed.host.as_mut().unwrap().interfaces[0] = "eth2".into();
    assert!(!initial.same_device_setup(&changed));
    changed = initial.clone();
    changed.xsk_mode = Some(XskMode::ZeroCopy);
    assert!(initial.same_device_setup(&changed));
    changed.xsk_mode = Some(XskMode::Copy);
    assert!(!initial.same_device_setup(&changed));
    changed = initial.clone();
    changed
        .host
        .as_mut()
        .unwrap()
        .interfaces
        .push("eth0".into());
    assert!(changed.validate().is_err());
}

#[test]
fn host_only_cannot_claim_two_physical_workers() {
    let body = source("interface { eth0 }");
    assert!(
        honk_config::parser::parse_dae_config(&format!("{body}\n datapath {{ workers: 1 }}"))
            .is_ok()
    );
    assert!(
        honk_config::parser::parse_dae_config(&format!("{body}\n datapath {{ workers: 2 }}"))
            .is_err()
    );
    assert!(
        honk_config::parser::parse_dae_config(&format!(
            "{body}\n datapath {{ workers: 2\n interface {{ lan0: lan }} }}"
        ))
        .is_ok()
    );
}

fn assert_migration_pointer(error: &str) {
    for path in [
        "doc/migration/en/gateway-host.md",
        "doc/migration/zh/gateway-host.md",
    ] {
        assert!(error.contains(path), "{error}");
    }
}

#[test]
fn removed_host_xsk_mode_reports_migration_in_each_format() {
    let directory = tempfile::tempdir().unwrap();
    for (extension, content) in [
        ("dae", source("interface { eth0 }\n xsk_mode: copy")),
        ("dae", source("interface { eth0 }\n xsk_mode: null")),
        (
            "json",
            json!({"datapath": structured(json!({"interfaces": ["eth0"], "xsk_mode": "copy"}))}).to_string(),
        ),
        (
            "json",
            json!({"datapath": structured(json!({"interfaces": ["eth0"], "xsk_mode": null}))}).to_string(),
        ),
        (
            "yaml",
            "datapath:\n  backend: xdp\n  direct: endpoint\n  host:\n    interfaces: [eth0]\n    xsk_mode: copy\n".into(),
        ),
        (
            "yml",
            "datapath:\n  backend: xdp\n  direct: endpoint\n  host:\n    interfaces: [eth0]\n    xsk_mode: null\n".into(),
        ),
        (
            "toml",
            "[datapath]\nbackend = 'xdp'\ndirect = 'endpoint'\n[datapath.host]\ninterfaces = ['eth0']\nxsk_mode = 'copy'\n".into(),
        ),
    ] {
        let path = directory.path().join(format!("legacy.{extension}"));
        std::fs::write(&path, &content).unwrap();
        let path = path.to_str().unwrap();
        let error = Config::from_file_with_detailed_diagnostics(path, &mut Vec::new()).unwrap_err();
        assert_eq!(error.diagnostic.code, "removed-host-xsk-mode");
        assert_eq!(error.diagnostic.setting.to_string(), "datapath.host.xsk_mode");
        assert_migration_pointer(&Config::from_file(path).unwrap_err().to_string());
        let error = match extension {
            "dae" => parse_dae_config(&content).unwrap_err().to_string(),
            "json" => {
                assert_migration_pointer(&Config::from_json_str(&content).unwrap_err().to_string());
                serde_json::from_str::<Config>(&content).unwrap_err().to_string()
            }
            "yaml" | "yml" => serde_yaml::from_str::<Config>(&content).unwrap_err().to_string(),
            "toml" => toml::from_str::<Config>(&content).unwrap_err().to_string(),
            _ => unreachable!(),
        };
        assert_migration_pointer(&error);
    }
    let error =
        serde_json::from_value::<HostConfig>(json!({"interfaces": ["eth0"], "xsk_mode": null}))
            .unwrap_err();
    assert_migration_pointer(&error.to_string());
}

#[test]
fn host_bypass_mark_is_checked_by_operator_and_assembled_validation() {
    for (raw, effective) in [
        (None::<u32>, Some(0x100)),
        (Some(0), Some(0x100)),
        (Some(0x200), Some(0x200)),
        (Some(0x37ff_ffff), Some(0x37ff_ffff)),
        (Some(0x0800_0000), None),
        (Some(0x4000_0000), None),
        (Some(0x8000_0000), None),
    ] {
        let mut dae = source("interface { eth0 }");
        let mut json = json!({"datapath": structured(json!({"interfaces": ["eth0"]}))});
        if let Some(raw) = raw {
            dae.push_str(&format!("\nglobal {{ so_mark_from_dae: 0x{raw:x} }}"));
            json["global"] = json!({"so_mark_from_dae": raw});
        }
        for config in [
            parse_dae_config(&dae).unwrap(),
            Config::from_json_str(&json.to_string()).unwrap(),
        ] {
            assert_eq!(config.validate().is_ok(), effective.is_some());
            let detailed = config.validate_detailed();
            let assembled = config.validate_assembled();
            if let Some(mark) = effective {
                detailed.unwrap();
                assembled.unwrap();
                assert_eq!(config.required_socket_mark(), Some(mark));
            } else {
                for error in [detailed.unwrap_err(), assembled.unwrap_err()] {
                    assert_eq!(
                        error.diagnostic.setting.to_string(),
                        "global.so_mark_from_dae"
                    );
                    assert!(error.diagnostic.message.contains("effective bypass mark"));
                }
            }
        }
    }
    assert_eq!(Config::default().required_socket_mark(), None);
    let physical =
        parse_dae_config("datapath { backend: xdp\n direct: endpoint\n interface { eth0: lan } }")
            .unwrap();
    assert_eq!(physical.required_socket_mark(), None);
}

#[test]
fn documented_host_only_configuration_is_admitted() {
    for note in [
        include_str!("../../../../doc/migration/en/gateway-host.md"),
        include_str!("../../../../doc/migration/zh/gateway-host.md"),
    ] {
        let (_, example) = note.split_once("```dae\n").unwrap();
        let (example, _) = example.split_once("```").unwrap();
        let config = parse_dae_config(example).unwrap();
        config.validate().unwrap();
        assert!(!config.global.nfqueue_enable);
        assert_eq!(config.required_socket_mark(), Some(0x100));
        let datapath = config.datapath.unwrap();
        assert!(datapath.interfaces.is_empty());
        assert!(datapath.effective_dns_projection());
        assert_eq!(datapath.host.unwrap().interfaces, ["eth0.100"]);
    }
}
