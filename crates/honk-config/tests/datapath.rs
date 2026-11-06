use honk_config::{
    Config,
    datapath::{Backend, DirectProfile, InterfaceRole, XskMode},
};

#[test]
fn explicit_xdp_profile_and_zone_survive_both_adapters() {
    let config = honk_config::parser::parse_dae_config(
        r#"
        datapath {
            backend: xdp
            direct: core
            interface {
                lan0: lan
                wan0: wan
            }
            firewall {
                original { default: allow }
                forward { default: allow }
            }
        }
        routing { fallback: direct }
    "#,
    )
    .unwrap();
    let datapath = config.datapath.as_ref().unwrap();
    assert_eq!(datapath.backend, Backend::Xdp);
    assert_eq!(datapath.direct, Some(DirectProfile::Core));
    assert_eq!(datapath.interfaces[0].role, InterfaceRole::Lan);
    assert_eq!(datapath.interfaces[1].role, InterfaceRole::Wan);
    assert!(datapath.firewall.is_some());
    let decoded: Config = serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
    assert_eq!(decoded.datapath, config.datapath);
    assert!(Config::default().datapath.is_none());
}

#[test]
fn xdp_never_defaults_native_to_another_execution_profile() {
    for body in [
        "backend: xdp\n interface {\n eth0: lan\n }",
        "backend: xdp\n direct: native\n interface {\n eth0: lan\n }",
        "backend: xdp\n direct: core\n interface {\n eth0: lan\n eth0: wan\n }",
        "backend: tc\n direct: core",
        "backend: xdp\n direct: endpoint\n interface {\n eth0: lan\n }\n firewall {\n original {\n default: allow\n }\n }",
        "backend: xdp\n direct: endpoint\n interface {\n auto: lan\n }",
        "backend: xdp\n direct: endpoint\n queue: 0\n interface {\n eth0: lan\n }",
    ] {
        assert!(
            honk_config::parser::parse_dae_config(&format!("datapath {{\n {body}\n }}")).is_err(),
            "accepted {body}"
        );
    }
}

#[test]
fn interface_entries_reject_nested_settings_and_empty_blocks() {
    for entry in [
        "lan0: lan {\n xsk_mode: zerocopy\n }",
        "lan0: lan {}",
        "lan0: lan {\n }",
    ] {
        let source =
            format!("datapath {{\n backend: xdp\n direct: core\n interface {{\n {entry}\n }}\n }}");
        let error = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
            &source,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.diagnostic.code, "nested-interface-block", "{source}");
        assert_eq!(error.category, honk_config::error::ErrorCategory::Parse);
    }
}

#[test]
fn xdp_binding_adapters_preserve_copy_opt_in_and_effective_restart_identity() {
    for direct in ["core", "endpoint"] {
        let source = |setting: &str| {
            format!(
                "datapath {{\n backend: xdp\n direct: {direct}\n {setting}\n interface {{ dut0: lan }}\n}}"
            )
        };
        let omitted = honk_config::parser::parse_dae_config(&source(""))
            .unwrap()
            .datapath
            .unwrap();
        for (mode, expected) in [
            (None, XskMode::ZeroCopy),
            (Some("copy"), XskMode::Copy),
            (Some("zerocopy"), XskMode::ZeroCopy),
        ] {
            let setting = mode
                .map(|mode| format!("xsk_mode: {mode}"))
                .unwrap_or_default();
            let dae = honk_config::parser::parse_dae_config(&source(&setting))
                .unwrap()
                .datapath
                .unwrap();
            let mut value = serde_json::json!({
                "datapath": {
                    "backend": "xdp",
                    "direct": direct,
                    "interfaces": [{"name": "dut0", "role": "lan"}]
                }
            });
            if let Some(mode) = mode {
                value["datapath"]["xsk_mode"] = mode.into();
            }
            let json = Config::from_json_str(&value.to_string()).unwrap();
            json.validate().unwrap();
            let json = json.datapath.unwrap();
            assert_eq!(dae, json);
            assert_eq!(dae.xsk_mode, mode.map(|_| expected));
            assert_eq!(dae.effective_xsk_mode(), expected);
            assert_eq!(
                omitted.same_device_setup(&dae),
                expected == XskMode::ZeroCopy
            );
            assert_eq!(
                dae.same_device_setup(&omitted),
                expected == XskMode::ZeroCopy
            );
            let decoded: honk_config::datapath::DatapathConfig =
                serde_json::from_str(&serde_json::to_string(&dae).unwrap()).unwrap();
            assert_eq!(decoded, dae);
            if mode.is_none() {
                value["datapath"]["xsk_mode"] = serde_json::Value::Null;
                let null = Config::from_json_str(&value.to_string()).unwrap();
                null.validate().unwrap();
                assert_eq!(null.datapath.unwrap(), omitted);
            }
        }
        for setting in ["xsk_mode: auto", "xsk_mode: copy\n xsk_mode: zerocopy"] {
            assert!(honk_config::parser::parse_dae_config(&source(setting)).is_err());
        }
    }
    for mode in ["copy", "zerocopy"] {
        assert!(
            honk_config::parser::parse_dae_config(&format!(
                "datapath {{\n backend: tc\n xsk_mode: {mode}\n}}"
            ))
            .is_err()
        );
        assert!(
            Config::from_json_str(&format!(
                r#"{{"datapath":{{"backend":"tc","xsk_mode":"{mode}"}}}}"#
            ))
            .unwrap()
            .validate()
            .is_err()
        );
    }
}

#[test]
fn included_xsk_mode_preserves_explicit_copy_and_rejects_duplicate_claims() {
    let directory = tempfile::tempdir().unwrap();
    let entry = directory.path().join("main.dae");
    let child = directory.path().join("child.dae");
    let source = "include { child.dae }\ndatapath {\n backend: xdp\n direct: core\n interface { dut0: lan }\n}";
    std::fs::write(&entry, source).unwrap();
    for (setting, expected) in [
        ("", XskMode::ZeroCopy),
        ("xsk_mode: copy", XskMode::Copy),
        ("xsk_mode: zerocopy", XskMode::ZeroCopy),
    ] {
        std::fs::write(&child, format!("datapath {{ {setting} }}")).unwrap();
        let config = Config::from_file(entry.to_str().unwrap()).unwrap();
        let datapath = config.datapath.unwrap();
        assert_eq!(datapath.effective_xsk_mode(), expected);
        assert_eq!(datapath.xsk_mode, (!setting.is_empty()).then_some(expected));
    }
    std::fs::write(&entry, format!("{source}\ndatapath {{ xsk_mode: copy }}")).unwrap();
    assert!(Config::from_file(entry.to_str().unwrap()).is_err());
}
