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

fn polling_parameters() -> serde_json::Value {
    // Test values are not calibrated deployment defaults.
    serde_json::json!({
        "pps_enter": 100, "pps_exit": 50, "observation_window_us": 1000,
        "enter_windows": 2, "exit_windows": 1, "max_busy_us": 10,
        "empty_rounds": 1, "budget_window_us": 1000, "budget_us": 100
    })
}

fn calibration_record() -> serde_json::Value {
    serde_json::json!({
        "schema": 1, "counting_revision": 1, "status": "candidate",
        "executable_sha256": "a".repeat(64), "context_sha256": "b".repeat(64),
        "parameter_sha256": "c".repeat(64), "evidence_manifest_sha256": "d".repeat(64)
    })
}

fn dae_fields(value: &serde_json::Value) -> String {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| {
            if value.is_object() {
                format!("{key} {{\n{}\n}}\n", dae_fields(value))
            } else {
                format!(
                    "{key}: {}\n",
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                )
            }
        })
        .collect()
}

fn polling_source(settings: &str) -> String {
    format!(
        "datapath {{\nbackend: xdp\ndirect: endpoint\ninterface {{ dut0: lan }}\n{settings}\n}}"
    )
}

fn admit_polling_json(busy: &serde_json::Value) -> bool {
    let value = serde_json::json!({"datapath": {
        "backend": "xdp", "direct": "endpoint", "interfaces": [{"name": "dut0", "role": "lan"}],
        "busy_poll": busy
    }});
    Config::from_json_str(&value.to_string())
        .and_then(|config| config.validate())
        .is_ok()
}

fn assert_polling_admission(busy: &serde_json::Value, accepted: bool) {
    let dae = polling_source(&format!("busy_poll {{\n{}\n}}", dae_fields(busy)));
    assert_eq!(
        honk_config::parser::parse_dae_config(&dae).is_ok(),
        accepted,
        "{dae}"
    );
    assert_eq!(admit_polling_json(busy), accepted, "{busy}");
}

#[test]
fn polling_modes_preserve_presence_and_reload_identity() {
    use honk_config::datapath::PollMode;
    let omitted = honk_config::parser::parse_dae_config(&polling_source(""))
        .unwrap()
        .datapath
        .unwrap();
    assert_eq!(omitted.poll_mode, None);
    assert_eq!(omitted.effective_poll_mode(), PollMode::Adaptive);
    for (mode, expected) in [("event", PollMode::Event), ("adaptive", PollMode::Adaptive)] {
        let settings = format!(
            "poll_mode: {mode}\nbusy_poll {{\n{}\n}}",
            dae_fields(&polling_parameters())
        );
        let configured = honk_config::parser::parse_dae_config(&polling_source(&settings))
            .unwrap()
            .datapath
            .unwrap();
        assert_eq!(configured.poll_mode, Some(expected));
        assert_eq!(configured.effective_poll_mode(), expected);
        assert_ne!(configured, omitted);
        assert!(configured.same_device_setup(&omitted));
        assert!(omitted.same_device_setup(&configured));
        let decoded: honk_config::datapath::DatapathConfig =
            serde_json::from_str(&serde_json::to_string(&configured).unwrap()).unwrap();
        assert_eq!(decoded, configured);
        assert!(
            honk_config::parser::parse_dae_config(&format!(
                "datapath {{ backend: tc\npoll_mode: {mode}\n}}"
            ))
            .is_err()
        );
        let typed =
            Config::from_json_str(&format!(r#"{{"datapath":{{"poll_mode":"{mode}"}}}}"#)).unwrap();
        assert!(typed.validate().is_err());
    }
    let encoded = serde_json::to_string(&omitted).unwrap();
    assert_eq!(
        serde_json::from_str::<honk_config::datapath::DatapathConfig>(&encoded).unwrap(),
        omitted
    );
    for key in ["poll_mode", "busy_poll"] {
        assert!(Config::from_json_str(&format!(r#"{{"datapath":{{"{key}":null}}}}"#)).is_err());
    }
    let tc = honk_config::datapath::DatapathConfig {
        busy_poll: Some(serde_json::from_value(polling_parameters()).unwrap()),
        ..Default::default()
    };
    assert!(tc.validate().is_err());
    assert!(
        honk_config::parser::parse_dae_config(&format!(
            "datapath {{ busy_poll {{\n{}\n}} }}",
            dae_fields(&polling_parameters())
        ))
        .is_err()
    );
}

#[test]
fn polling_requires_every_integer_and_enforces_all_bounds_in_both_adapters() {
    let valid = polling_parameters();
    assert_polling_admission(&valid, true);
    for key in valid.as_object().unwrap().keys() {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert_polling_admission(&missing, false);
        for bad in [
            serde_json::Value::Null,
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!(4294967296_u64),
        ] {
            let mut value = valid.clone();
            value[key] = bad;
            assert_polling_admission(&value, false);
        }
        for token in ["+1", "-0", "1.0", "NaN", "Inf", "1us", "1e2"] {
            let fields = dae_fields(&valid);
            let old = format!("{key}: {}\n", valid[key]);
            let fields = fields.replace(&old, &format!("{key}: {token}\n"));
            assert!(
                honk_config::parser::parse_dae_config(&polling_source(&format!(
                    "busy_poll {{\n{fields}\n}}"
                )))
                .is_err(),
                "{key}={token}"
            );
        }
    }
    for (key, bad) in [
        ("pps_enter", 0),
        ("pps_enter", 50),
        ("pps_exit", 100),
        ("observation_window_us", 0),
        ("observation_window_us", 60_000_001),
        ("enter_windows", 0),
        ("enter_windows", 1),
        ("enter_windows", 65536),
        ("exit_windows", 0),
        ("exit_windows", 65536),
        ("empty_rounds", 0),
        ("empty_rounds", 65536),
        ("max_busy_us", 0),
        ("max_busy_us", 101),
        ("max_busy_us", 1001),
        ("budget_window_us", 0),
        ("budget_window_us", 100),
        ("budget_window_us", 60_000_001),
        ("budget_us", 0),
        ("budget_us", 9),
        ("budget_us", 1000),
    ] {
        let mut value = valid.clone();
        value[key] = bad.into();
        assert_polling_admission(&value, false);
    }
    let mut extremes = valid.clone();
    for (key, value) in [
        ("pps_enter", u32::MAX),
        ("pps_exit", u32::MAX - 1),
        ("observation_window_us", 60_000_000),
        ("enter_windows", 65535),
        ("exit_windows", 65535),
        ("empty_rounds", 65535),
        ("max_busy_us", 1000),
        ("budget_window_us", 60_000_000),
        ("budget_us", 59_999_999),
    ] {
        extremes[key] = value.into();
    }
    assert_polling_admission(&extremes, true);
    let mut minimum = valid;
    for (key, value) in [
        ("pps_enter", 1),
        ("pps_exit", 0),
        ("observation_window_us", 1),
        ("max_busy_us", 1),
        ("budget_window_us", 2),
        ("budget_us", 1),
    ] {
        minimum[key] = value.into();
    }
    assert_polling_admission(&minimum, true);
}

#[test]
fn polling_calibration_is_complete_strict_and_not_a_compatibility_claim() {
    let mut valid = polling_parameters();
    valid["calibration"] = calibration_record();
    assert_polling_admission(&valid, true);
    for status in ["candidate", "qualified"] {
        let mut different_revision = valid.clone();
        different_revision["calibration"]["schema"] = 65535.into();
        different_revision["calibration"]["counting_revision"] = u32::MAX.into();
        different_revision["calibration"]["status"] = status.into();
        assert_polling_admission(&different_revision, true);
    }
    for key in calibration_record().as_object().unwrap().keys() {
        let mut missing = valid.clone();
        missing["calibration"].as_object_mut().unwrap().remove(key);
        assert_polling_admission(&missing, false);
        let mut null = valid.clone();
        null["calibration"][key] = serde_json::Value::Null;
        assert_polling_admission(&null, false);
    }
    for key in [
        "executable_sha256",
        "context_sha256",
        "parameter_sha256",
        "evidence_manifest_sha256",
    ] {
        for bad in [
            "".to_owned(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "é".repeat(32),
        ] {
            let mut value = valid.clone();
            value["calibration"][key] = bad.into();
            assert_polling_admission(&value, false);
        }
    }
    for (key, bad) in [
        ("schema", serde_json::json!(0)),
        ("schema", serde_json::json!(65536)),
        ("counting_revision", serde_json::json!(0)),
        ("counting_revision", serde_json::json!(4294967296_u64)),
        ("status", serde_json::json!("unknown")),
        ("extra", serde_json::json!(1)),
    ] {
        let mut value = valid.clone();
        value["calibration"][key] = bad;
        assert_polling_admission(&value, false);
    }
    valid["calibration"] = serde_json::Value::Null;
    assert_polling_admission(&valid, false);
}

#[test]
fn polling_unknown_duplicate_and_misplaced_claims_reject() {
    let busy = polling_parameters();
    let fields = dae_fields(&busy);
    let calibration = dae_fields(&calibration_record());
    for extra in [
        "unknown: 1".to_owned(),
        "unknown {}".to_owned(),
        "pps_enter {}".to_owned(),
        "calibration {}".to_owned(),
    ] {
        assert!(
            honk_config::parser::parse_dae_config(&polling_source(&format!(
                "busy_poll {{\n{fields}\n{extra}\n}}"
            )))
            .is_err()
        );
    }
    for key in busy.as_object().unwrap().keys() {
        let duplicate = format!("busy_poll {{\n{fields}\n{key}: {}\n}}", busy[key]);
        assert!(honk_config::parser::parse_dae_config(&polling_source(&duplicate)).is_err());
        let json = serde_json::to_string(&busy).unwrap();
        let duplicate = format!("{},\"{key}\":{}}}", &json[..json.len() - 1], busy[key]);
        assert!(serde_json::from_str::<honk_config::datapath::BusyPollConfig>(&duplicate).is_err());
    }
    for (key, value) in calibration_record().as_object().unwrap() {
        let duplicate = format!(
            "busy_poll {{\n{fields}\ncalibration {{\n{calibration}\n{key}: {}\n}}\n}}",
            value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string())
        );
        assert!(honk_config::parser::parse_dae_config(&polling_source(&duplicate)).is_err());
        let json = calibration_record().to_string();
        let duplicate = format!("{},\"{key}\":{value}}}", &json[..json.len() - 1]);
        assert!(
            serde_json::from_str::<honk_config::datapath::PollCalibration>(&duplicate).is_err()
        );
    }
    for settings in [
        "poll_mode: busy".to_owned(),
        "poll_mode: null".to_owned(),
        "poll_mode {}".to_owned(),
        "poll_mode: event\npoll_mode: adaptive".to_owned(),
        format!("calibration {{\n{calibration}\n}}"),
        format!("busy_poll {{\n{fields}\ncalibration {{\n{calibration}\nunknown {{}}\n}}\n}}"),
        format!(
            "busy_poll {{\n{fields}\ncalibration {{\n{calibration}\n}}\ncalibration {{\n{calibration}\n}}\n}}"
        ),
    ] {
        assert!(honk_config::parser::parse_dae_config(&polling_source(&settings)).is_err());
    }
    for json in [
        r#"{"poll_mode":"event","poll_mode":"adaptive"}"#.to_owned(),
        format!(
            r#"{{"busy_poll":{busy},"busy_poll":{busy}}}"), format!(r#"{{"calibration":{}}}"#,
            calibration_record()
        ),
    ] {
        assert!(serde_json::from_str::<honk_config::datapath::DatapathConfig>(&json).is_err());
    }
    let mut unknown = busy;
    unknown["unknown"] = 1.into();
    assert_polling_admission(&unknown, false);
}

#[test]
fn polling_include_merges_preserve_one_strict_presence_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let entry = directory.path().join("main.dae");
    let child = directory.path().join("child.dae");
    let mut busy = polling_parameters();
    busy["calibration"] = calibration_record();
    let block = format!("busy_poll {{\n{}\n}}", dae_fields(&busy));
    let main = format!(
        "include {{ child.dae }}\n{}",
        polling_source("poll_mode: event")
    );
    std::fs::write(&entry, &main).unwrap();
    std::fs::write(&child, format!("datapath {{\n{block}\n}}")).unwrap();
    let loaded = Config::from_file(entry.to_str().unwrap()).unwrap();
    assert_eq!(
        loaded.datapath.unwrap().busy_poll.unwrap(),
        serde_json::from_value::<honk_config::datapath::BusyPollConfig>(busy).unwrap()
    );
    for duplicate in [
        "poll_mode: event".to_owned(),
        format!("{block}\n}}\ndatapath {{\n{block}"),
    ] {
        std::fs::write(&child, format!("datapath {{\n{duplicate}\n}}")).unwrap();
        assert!(Config::from_file(entry.to_str().unwrap()).is_err());
    }
    std::fs::write(&entry, format!("{main}\ndatapath {{\n{block}\n}}")).unwrap();
    std::fs::write(&child, format!("datapath {{\n{block}\n}}")).unwrap();
    assert!(Config::from_file(entry.to_str().unwrap()).is_err());
}

#[test]
fn programmatic_polling_admission_and_calibration_identity_match_parser_contract() {
    let source = polling_source(&format!(
        "busy_poll {{\n{}\n}}",
        dae_fields(&polling_parameters())
    ));
    let mut config = honk_config::parser::parse_dae_config(&source).unwrap();
    config.validate().unwrap();
    let original = config.datapath.clone().unwrap();
    let datapath = config.datapath.as_mut().unwrap();
    let busy = datapath.busy_poll.as_mut().unwrap();
    busy.calibration = Some(serde_json::from_value(calibration_record()).unwrap());
    assert_ne!(*datapath, original);
    assert!(datapath.same_device_setup(&original));
    let with_calibration = datapath.clone();
    datapath
        .busy_poll
        .as_mut()
        .unwrap()
        .calibration
        .as_mut()
        .unwrap()
        .status = honk_config::datapath::CalibrationStatus::Qualified;
    assert_ne!(*datapath, with_calibration);
    assert!(datapath.same_device_setup(&with_calibration));
    config.validate().unwrap();
    config
        .datapath
        .as_mut()
        .unwrap()
        .busy_poll
        .as_mut()
        .unwrap()
        .enter_windows = 1;
    assert!(config.validate().is_err());
    let busy = config
        .datapath
        .as_mut()
        .unwrap()
        .busy_poll
        .as_mut()
        .unwrap();
    busy.enter_windows = 2;
    busy.calibration.as_mut().unwrap().context_sha256 = "invalid".into();
    assert!(busy.validate().is_err());
    assert!(config.validate().is_err());
}

#[test]
fn calibration_numbers_and_duplicate_optional_child_are_strict() {
    let mut valid = polling_parameters();
    valid["calibration"] = calibration_record();
    for key in ["schema", "counting_revision"] {
        for bad in [
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("+1"),
            serde_json::json!("NaN"),
            serde_json::json!("Inf"),
        ] {
            let mut value = valid.clone();
            value["calibration"][key] = bad;
            assert_polling_admission(&value, false);
        }
    }
    let json = polling_parameters().to_string();
    let record = calibration_record();
    let duplicate = format!(
        "{},\"calibration\":{record},\"calibration\":{record}}}",
        &json[..json.len() - 1]
    );
    assert!(serde_json::from_str::<honk_config::datapath::BusyPollConfig>(&duplicate).is_err());
}
