use honk_config::{
    Config,
    datapath::{Backend, DirectProfile, InterfaceRole},
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
fn xsk_mode_preserves_default_copy_and_requires_restart_for_zero_copy() {
    let source = |setting: &str| {
        format!(
            "datapath {{\n backend: xdp\n direct: core\n {setting}\n interface {{ dut0: lan }}\n}}"
        )
    };
    let omitted = honk_config::parser::parse_dae_config(&source("")).unwrap();
    let copy = honk_config::parser::parse_dae_config(&source("xsk_mode: copy")).unwrap();
    let zero_copy = honk_config::parser::parse_dae_config(&source("xsk_mode: zerocopy")).unwrap();
    let omitted = omitted.datapath.unwrap();
    let copy = copy.datapath.unwrap();
    let zero_copy = zero_copy.datapath.unwrap();
    assert!(omitted.same_device_setup(&copy));
    assert!(!omitted.same_device_setup(&zero_copy));
    assert!(!copy.same_device_setup(&zero_copy));
    let decoded: honk_config::datapath::DatapathConfig =
        serde_json::from_str(&serde_json::to_string(&zero_copy).unwrap()).unwrap();
    assert!(zero_copy.same_device_setup(&decoded));
    assert!(!copy.same_device_setup(&decoded));

    for setting in ["xsk_mode: auto", "xsk_mode: copy\n xsk_mode: zerocopy"] {
        assert!(honk_config::parser::parse_dae_config(&source(setting)).is_err());
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
    Config::from_json_str(r#"{"datapath":{"backend":"tc"}}"#)
        .unwrap()
        .validate()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("child.dae"),
        "datapath { xsk_mode: zerocopy }",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("main.dae"),
        format!("include {{ child.dae }}\n{}", source("xsk_mode: copy")),
    )
    .unwrap();
    assert!(Config::from_file(directory.path().join("main.dae").to_str().unwrap()).is_err());
}
