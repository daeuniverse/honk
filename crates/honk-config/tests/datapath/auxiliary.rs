use honk_config::{
    datapath::{DatapathConfig, InterfaceRole},
    parser::parse_dae_config,
};
use serde_json::json;

fn admit(
    backend: &str,
    direct: &str,
    interfaces: &[(&str, &str)],
    host: bool,
    workers: u8,
) -> Option<DatapathConfig> {
    let mut text = format!("datapath {{\n backend: {backend}\n direct: {direct}\n");
    let mut structured = json!({"backend": backend, "direct": direct});
    if workers != 1 {
        text.push_str(&format!("workers: {workers}\n"));
        structured["workers"] = json!(workers);
    }
    if host {
        text.push_str("host { xsk_mode: copy\n interface { host0 } }\n");
        structured["host"] = json!({"xsk_mode": "copy", "interfaces": ["host0"]});
    }
    text.push_str("interface {\n");
    for (name, role) in interfaces {
        text.push_str(&format!("{name}: {role}\n"));
    }
    text.push_str("}\n}");
    structured["interfaces"] = json!(
        interfaces
            .iter()
            .map(|(name, role)| json!({"name": name, "role": role}))
            .collect::<Vec<_>>()
    );
    let dae = parse_dae_config(&text)
        .ok()
        .and_then(|config| config.datapath);
    let structured = serde_json::from_value::<DatapathConfig>(structured)
        .ok()
        .filter(|config| config.validate().is_ok());
    assert_eq!(dae, structured, "{text}");
    dae
}

#[test]
fn auxiliary_interface_admission_matches_across_adapters() {
    let physical_and_aux = [("wan0", "wan"), ("wg0", "l3_lan")];
    for (backend, direct, host, workers) in [
        ("tc", "endpoint", false, 1),
        ("tun", "endpoint", false, 1),
        ("xdp", "core", false, 1),
        ("xdp", "endpoint", true, 1),
    ] {
        assert!(admit(backend, direct, &physical_and_aux, host, workers).is_none());
    }
    for (names, workers) in [
        (&[("wg0", "l3_lan")][..], 1),
        (&[("wg0", "l3_lan")][..], 2),
        (&[("wg0", "lan"), ("wg0", "l3_lan")][..], 1),
        (
            &[("wan0", "wan"), ("wg0", "l3_lan"), ("wg0", "l3_lan")][..],
            1,
        ),
        (&[("wan0", "wan"), ("auto", "l3_lan")][..], 1),
    ] {
        assert!(admit("xdp", "endpoint", names, false, workers).is_none());
    }
    let config = admit("xdp", "endpoint", &physical_and_aux, false, 2).unwrap();
    assert_eq!(config.interfaces[1].role, InterfaceRole::L3Lan);
    assert!(config.effective_dns_projection());
    let encoded = serde_json::to_string(&config).unwrap();
    let decoded: DatapathConfig = serde_json::from_str(&encoded).unwrap();
    assert_eq!(config, decoded);
    assert!(config.same_device_setup(&decoded));
    let mut changed = decoded;
    changed.interfaces[1].name = "wg1".into();
    assert!(!config.same_device_setup(&changed));
    changed.interfaces[1].name = "wg0".into();
    changed.interfaces[1].role = InterfaceRole::Lan;
    assert!(!config.same_device_setup(&changed));
}

#[test]
fn auxiliary_limit_is_separate_from_physical_limit() {
    let names: Vec<_> = (0..26).map(|index| format!("dut{index}")).collect();
    for (physical, auxiliary, accepted) in [
        (16, 8, true),
        (16, 9, false),
        (17, 1, false),
        (17, 0, false),
        (1, 9, false),
    ] {
        let interfaces: Vec<_> = names[..physical + auxiliary]
            .iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    name.as_str(),
                    if index < physical { "lan" } else { "l3_lan" },
                )
            })
            .collect();
        assert_eq!(
            admit("xdp", "endpoint", &interfaces, false, 1).is_some(),
            accepted
        );
    }
}

#[test]
fn auxiliary_role_is_refused_in_core_firewall_ingress() {
    let parsed = parse_dae_config(
        "datapath { backend: xdp\n direct: core\n interface { lan0: lan }\n\
         firewall { original { lan: l4proto(tcp) -> allow } }\n }",
    )
    .unwrap();
    let mut datapath = parsed.datapath.unwrap();
    datapath.firewall.as_mut().unwrap().original.rules[0].ingress = Some(InterfaceRole::L3Lan);
    assert!(datapath.validate().is_err());
    assert!(
        serde_json::from_value::<DatapathConfig>(serde_json::to_value(datapath).unwrap()).is_err()
    );
    assert!(
        parse_dae_config(
            "datapath { backend: xdp\n direct: core\n interface { lan0: lan }\n\
         firewall { original { l3_lan: l4proto(tcp) -> allow } }\n }",
        )
        .is_err()
    );
}
