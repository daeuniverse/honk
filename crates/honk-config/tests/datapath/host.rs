use super::*;
use honk_config::datapath::{DatapathConfig, HostConfig};

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
fn host_only_and_mixed_adapters_preserve_private_copy_and_physical_defaults() {
    for physical in [false, true] {
        for direct in ["endpoint", "native"] {
            let mut dae = source("xsk_mode: copy\n interface {\n eth1\n eth0\n }");
            let mut value = structured(serde_json::json!({
                "interfaces": ["eth1", "eth0"], "xsk_mode": "copy"
            }));
            dae = dae.replace("direct: endpoint", &format!("direct: {direct}"));
            value["direct"] = direct.into();
            if physical {
                dae.push_str("\ndatapath { interface { lan0: lan } }");
                value["interfaces"] = serde_json::json!([{"name": "lan0", "role": "lan"}]);
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
                    interfaces: vec!["eth1".into(), "eth0".into()],
                    xsk_mode: XskMode::Copy,
                })
            );
            assert_eq!(parsed.xsk_mode, None);
            assert_eq!(parsed.effective_xsk_mode(), XskMode::ZeroCopy);
            assert_eq!(parsed.interfaces.len(), usize::from(physical));
            let roundtrip: DatapathConfig =
                serde_json::from_value(serde_json::to_value(&parsed).unwrap()).unwrap();
            assert_eq!(roundtrip, parsed);
        }
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
fn host_requires_explicit_copy_fields_and_unique_bounded_names_in_both_adapters() {
    for body in [
        "",
        "interface { eth0 }",
        "xsk_mode: copy",
        "xsk_mode: zerocopy\n interface { eth0 }",
        "xsk_mode: auto\n interface { eth0 }",
        "xsk_mode: copy\n interface {}",
        "xsk_mode: copy\n interface {\n eth0\n eth0\n }",
        "xsk_mode: copy\n interface { auto }",
        "xsk_mode: copy\n interface { lo }",
        "xsk_mode: copy\n interface { eth* }",
        "xsk_mode: copy\n interface { eth0: lan }",
        "xsk_mode: copy\n interface { eth0 {} }",
        "xsk_mode: copy\n interface { eth0 { queue: 0 } }",
        "xsk_mode: copy\n interface { eth0 }\n queue: 0",
        "xsk_mode: copy\n interface { eth0 }\n include { child.dae }",
        "xsk_mode: copy\n xsk_mode: copy\n interface { eth0 }",
        "xsk_mode: copy\n interface { eth0 }\n interface { eth1 }",
    ] {
        assert!(
            honk_config::parser::parse_dae_config(&source(body)).is_err(),
            "accepted {body}"
        );
    }
    for host in [
        serde_json::Value::Null,
        serde_json::json!({}),
        serde_json::json!({"interfaces": ["eth0"]}),
        serde_json::json!({"xsk_mode": "copy"}),
        serde_json::json!({"interfaces": null, "xsk_mode": "copy"}),
        serde_json::json!({"interfaces": ["eth0"], "xsk_mode": null}),
        serde_json::json!({"interfaces": ["eth0"], "xsk_mode": "zerocopy"}),
        serde_json::json!({"interfaces": ["eth0"], "xsk_mode": "auto"}),
        serde_json::json!({"interfaces": ["eth0"], "xsk_mode": "copy", "queue": 0}),
    ] {
        assert!(!admitted(structured(host.clone())), "accepted {host}");
    }
    for names in [
        vec![],
        vec!["eth0", "eth0"],
        vec!["auto"],
        vec!["lo"],
        vec!["eth*"],
        vec![""],
        vec!["abcdefghijklmnop"],
    ] {
        assert!(!admitted(structured(
            serde_json::json!({"interfaces": names, "xsk_mode": "copy"})
        )));
    }
    for count in [16, 17] {
        let names: Vec<_> = (0..count).map(|index| format!("eth{index}")).collect();
        let dae = source(&format!(
            "xsk_mode: copy\n interface {{\n {}\n }}",
            names.join("\n")
        ));
        assert_eq!(
            honk_config::parser::parse_dae_config(&dae).is_ok(),
            count == 16
        );
        assert_eq!(
            admitted(structured(
                serde_json::json!({"interfaces": names, "xsk_mode": "copy"})
            )),
            count == 16
        );
    }
}

#[test]
fn host_backend_direct_and_presence_boundaries_are_strict() {
    let host = serde_json::json!({"interfaces": ["eth0"], "xsk_mode": "copy"});
    for backend in ["tc", "tun", "xdp"] {
        for direct in [None, Some("core"), Some("endpoint"), Some("native")] {
            let mut value = structured(host.clone());
            value["backend"] = backend.into();
            value["direct"] = serde_json::json!(direct);
            assert_eq!(
                admitted(value),
                backend == "xdp" && matches!(direct, Some("endpoint" | "native"))
            );
            let direct = direct
                .map(|direct| format!("direct: {direct}\n"))
                .unwrap_or_default();
            let dae = format!(
                "datapath {{\n backend: {backend}\n {direct} host {{ xsk_mode: copy\n interface {{ eth0 }} }}\n}}"
            );
            assert_eq!(
                honk_config::parser::parse_dae_config(&dae).is_ok(),
                backend == "xdp"
                    && matches!(direct.as_str(), "direct: endpoint\n" | "direct: native\n")
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
        r#"{"backend":"xdp","direct":"endpoint","host":{"interfaces":["eth0"],"interfaces":["eth1"],"xsk_mode":"copy"}}"#,
        r#"{"backend":"xdp","direct":"endpoint","host":{"interfaces":["eth0"],"xsk_mode":"copy"},"host":{"interfaces":["eth1"],"xsk_mode":"copy"}}"#,
    ] {
        assert!(serde_json::from_str::<DatapathConfig>(json).is_err());
    }
}

#[test]
fn host_include_and_merged_sections_reject_repeated_blocks() {
    let directory = tempfile::tempdir().unwrap();
    let entry = directory.path().join("main.dae");
    let child = directory.path().join("child.dae");
    let host = "datapath { host { xsk_mode: copy\n interface { eth0 } } }";
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
        format!(
            "include {{ child.dae }}\n{}",
            source("xsk_mode: copy\n interface { eth0 }")
        ),
    )
    .unwrap();
    assert!(Config::from_file(entry.to_str().unwrap()).is_err());
    assert!(
        honk_config::parser::parse_dae_config(&format!(
            "{}\n{host}",
            source("xsk_mode: copy\n interface { eth0 }")
        ))
        .is_err()
    );
}

#[test]
fn host_exact_identity_is_restart_only_and_independent_of_physical_copy() {
    let initial = honk_config::parser::parse_dae_config(&source(
        "xsk_mode: copy\n interface {\n eth0\n eth1\n }",
    ))
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
    changed.host.as_mut().unwrap().xsk_mode = XskMode::ZeroCopy;
    assert!(changed.validate().is_err());
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
    for direct in ["endpoint", "native"] {
        let body = source("xsk_mode: copy\n interface { eth0 }")
            .replace("direct: endpoint", &format!("direct: {direct}"));
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
}
