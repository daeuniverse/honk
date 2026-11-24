use super::guard;
use crate::{control::ControlPlane, routing::Router, xdp::gateway::GatewayPolicy};
use anyhow::ensure;
use honk_ebpf_common::{xdp::CaptureAuthority, xdp_gateway::CaptureRealmKey};
use honk_xsk::{
    ConntrackKfuncs, GatewayArbitration, GatewayDnsMaps, GatewayLoad, GatewayMaps, GeneralCapture,
    Programs,
};
use std::{path::PathBuf, process::Command};

// Keep #280's two early address/port conjunctions and long chain before the
// late domain rules. Physical gateway input has no process name, so the
// middle of the chain uses overlapping wire predicates that survive codegen.
const POLICY: &str = r#"
global { dial_mode: ip }
routing {
    sip(198.18.81.2/32) && dip(198.18.80.2/32) && dport(15201) -> block(must)
    sip(198.18.81.2/32) && dip(198.18.80.2/32) && dport(15202) -> direct(must)
    sip(198.18.81.0/24) && l4proto(udp) && dport(53) -> block(must)
    dip(2001:db8:1::/48) && dport(1024-4096) && dscp(8) -> block(must)
    sip(2001:db8:2::/48) && dport(3000-9000) && dscp(16) -> block(must)
    sip(198.18.80.0/24) && dport(2048-4096) && dscp(4) -> block(must)
    dip(198.18.81.0/24) && dport(2000-4000) && dscp(5) -> block(must)
    sip(192.0.2.0/26) && dport(10000-15000) && dscp(6) -> block(must)
    mac(02:00:00:00:00:01, 02:00:00:00:00:02, 02:00:00:00:00:03, 02:00:00:00:00:04) -> block(must)
    mac(02:00:00:00:00:05) -> block(must)
    dscp(4) -> block(must)
    sip(192.0.2.64/26) && dport(7000-11000) && dscp(7) -> block(must)
    sip(192.0.2.128/26) && dport(6500-12000) && dscp(8) -> block(must)
    dip(192.0.2.0/26) && dport(6000-18000) && dscp(9) -> block(must)
    sip(192.0.2.192/26) && dport(5000-16000) && dscp(10) -> block(must)
    dip(192.0.2.64/26) && dport(4000-17000) && dscp(11) -> block(must)
    dip(192.0.2.128/26) && dport(3000-19000) && dscp(12) -> block(must)
    dip(192.0.2.192/26) && dport(2100-20000) && dscp(13) -> block(must)
    dip(2001:db8:3::/48) && dport(3000-4000) && dscp(14) -> block(must)
    sip(2001:db8:4::/48) && dport(2000-8000) && dscp(15) -> block(must)
    mac(02:00:00:00:00:06) -> block(must)
    sip(198.51.100.24/32) && !dport(53) -> block(must)
    dip(10.0.0.0/8, 192.168.0.0/16) -> block(must)
    domain(suffix: example.net, suffix: example.org) -> block
    dport(14588) -> block(must)
    dip(203.0.113.0/24) -> block
    domain(suffix: example.com) -> direct(must)
    dport(22, 80, 443, 8080) -> block
    fallback: direct
}
"#;

#[test]
#[ignore = "requires the disposable kernel VM gate and live native JIT disassembly"]
fn generated_dns_shadow_policy_verifies_and_jits() -> anyhow::Result<()> {
    guard();
    let probe = PathBuf::from(std::env::var_os("HONK_XDP_DNS_PROBE").unwrap());
    let artifacts = PathBuf::from(std::env::var_os("HONK_XDP_ARTIFACT_ROOT").unwrap());
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .without_time()
        .with_ansi(false)
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    // The fixture loads programs without attaching them; guard() already authenticated dut0.
    let ifindex = nix::net::if_::if_nametoindex("dut0")?;
    let config = honk_config::parser::parse_dae_config(POLICY)?;
    let router = Router::from_config(&config.routing)?;
    let plan = ControlPlane::compile_routing_plan(&config, &router)?;
    ensure!(plan.rules.len() >= 28 && plan.has_domain_rules);
    let maps = GatewayMaps::new(
        &[(
            CaptureRealmKey {
                physical_ifindex: ifindex,
                ..Default::default()
            },
            1,
        )],
        &[],
    )?;
    let dns = GatewayDnsMaps::new(2)?;
    let arbitration = GatewayArbitration::new(0)?;
    let conntrack = ConntrackKfuncs::read()?;
    let capture = GeneralCapture {
        authority: CaptureAuthority {
            namespace_cookie: 1,
            attachment_generation: 2,
            scope: 5,
            config_generation: 2,
            ifindex,
            reserved: 0,
        },
        bypass_mark: 0x100,
        vlan_metadata: true,
    };
    for (enabled, mode) in [(false, "static"), (true, "shadow")] {
        let policy = GatewayPolicy::prepare(&plan, enabled, None)?;
        let programs = Programs::load_general_gateway(
            &capture,
            2,
            &[],
            GatewayLoad {
                routing: &policy.bytecode.insns,
                maps: &maps,
                conntrack: Some(&conntrack),
                dns: enabled.then_some(&dns),
                arbitration: enabled.then_some(&arbitration),
            },
        )?;
        for (id, role) in [
            (programs.discover_prog_id(), "boot"),
            (programs.data_prog_id(), "data"),
        ] {
            let status = Command::new("python3")
                .arg(&probe)
                .args(["jit", mode, role, &id.to_string()])
                .arg(&artifacts)
                .status()?;
            ensure!(
                status.success(),
                "JIT evidence failed for {mode}/{role}/{id}"
            );
        }
    }
    Ok(())
}
