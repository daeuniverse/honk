use std::path::{Path, PathBuf};
use std::process::Command;

fn push_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn push_field(tag: u32, wire: u8, out: &mut Vec<u8>) {
    push_varint(((tag as u64) << 3) | wire as u64, out);
}

fn push_len_delim(tag: u32, payload: &[u8], out: &mut Vec<u8>) {
    push_field(tag, 2, out);
    push_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn push_varint_field(tag: u32, v: u64, out: &mut Vec<u8>) {
    push_field(tag, 0, out);
    push_varint(v, out);
}

fn geosite_fixture() -> Vec<u8> {
    let mut domain = Vec::new();
    push_varint_field(1, 2, &mut domain);
    push_len_delim(2, b"pki.goog", &mut domain);

    let mut entry = Vec::new();
    push_len_delim(1, b"PKI", &mut entry);
    push_len_delim(2, &domain, &mut entry);

    let mut dat = Vec::new();
    push_len_delim(1, &entry, &mut dat);
    dat
}

fn geoip_fixture() -> Vec<u8> {
    let mut cidr = Vec::new();
    push_len_delim(1, &[172, 217, 0, 0], &mut cidr);
    push_varint_field(2, 16, &mut cidr);

    let mut entry = Vec::new();
    push_len_delim(1, b"GOOGLE", &mut entry);
    push_len_delim(2, &cidr, &mut entry);

    let mut dat = Vec::new();
    push_len_delim(1, &entry, &mut dat);
    dat
}

fn run_route(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_honk-tool"))
        .env_remove("DAE_LOCATION_ASSET")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn write_config(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("config.dae");
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn traces_issue_524_domain_direct_offload_vs_unknown_domain_indeterminate() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("custom-data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("geosite.dat"), geosite_fixture()).unwrap();
    std::fs::write(data_dir.join("geoip.dat"), geoip_fixture()).unwrap();

    let cfg = write_config(
        dir.path(),
        &format!(
            r#"
global {{
    data_dir: '{}'
    dial_mode: domain
}}
node {{
    n1: 'socks5://127.0.0.1:1080'
}}
group {{
    us {{
        policy: fixed(0)
    }}
}}
routing {{
    domain(geosite:pki) -> direct
    dip(geoip:google) -> us
    fallback: block
}}
"#,
            data_dir.display()
        ),
    );
    let cfg_str = cfg.to_str().unwrap();

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "--config",
        cfg_str,
        "--proto",
        "tcp",
        "--dip",
        "172.217.75.94",
        "--dport",
        "443",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains("decision: indeterminate"), "{stdout}");
    assert!(stdout.contains("missing_inputs: domain"), "{stdout}");
    assert!(
        stdout.contains("[0] indeterminate domain(geosite: pki) -> direct"),
        "{stdout}"
    );
    assert!(
        stdout.contains("[1] matched dip(geoip: google) -> us"),
        "{stdout}"
    );
    assert!(
        stdout.contains("[fallback] skipped fallback: block"),
        "{stdout}"
    );

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "--config",
        cfg_str,
        "--proto",
        "tcp",
        "--domain",
        "crl.pki.goog",
        "--dip",
        "172.217.75.94",
        "--dport",
        "443",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(r#""decision":"determinate""#), "{stdout}");
    assert!(stdout.contains(r#""outbound":"direct""#), "{stdout}");
    assert!(stdout.contains(r#""matched_rule":0"#), "{stdout}");
    assert!(stdout.contains(r#""compilable":true"#), "{stdout}");
    assert!(stdout.contains(r#""domain_final":true"#), "{stdout}");
    assert!(
        stdout.contains(r#""lan_disposition":"native_direct_offload""#),
        "{stdout}"
    );
    assert!(
        stdout.contains(r#""wan_disposition":"native_direct_offload""#),
        "{stdout}"
    );

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "--config",
        cfg_str,
        "--proto",
        "tcp",
        "--domain",
        "crl.pki.goog.",
        "--dip",
        "172.217.75.94",
        "--dport",
        "443",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(r#""decision":"determinate""#), "{stdout}");
    assert!(stdout.contains(r#""outbound":"direct""#), "{stdout}");
    assert!(stdout.contains(r#""matched_rule":0"#), "{stdout}");
    assert!(stdout.contains(r#""domain_final":true"#), "{stdout}");
    assert!(
        stdout.contains(r#""lan_disposition":"native_direct_offload""#),
        "{stdout}"
    );
}

#[test]
fn distinguishes_domain_prefix_punt_from_domain_free_prefix_and_clash_global_mode() {
    let dir = tempfile::tempdir().unwrap();

    let cfg_with_domain_prefix = write_config(
        dir.path(),
        r#"
global {
    dial_mode: domain
}
node {
    n1: 'socks5://127.0.0.1:1080'
}
group {
    us {
        policy: fixed(0)
    }
}
routing {
    domain(suffix: example.com) && dport(8443) -> us
    dip(10.0.0.0/8) -> direct
    fallback: us
}
"#,
    );
    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_with_domain_prefix.to_str().unwrap(),
        "--proto",
        "tcp",
        "--dip",
        "10.1.2.3",
        "--dport",
        "443",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(r#""decision":"determinate""#), "{stdout}");
    assert!(stdout.contains(r#""outbound":"direct""#), "{stdout}");
    assert!(stdout.contains(r#""domain_final":false"#), "{stdout}");
    assert!(
        stdout.contains(r#""lan_disposition":"userspace_control_plane_routing""#),
        "{stdout}"
    );
    assert!(
        stdout.contains(r#""wan_disposition":"userspace_control_plane_routing""#),
        "{stdout}"
    );

    let dir2 = tempfile::tempdir().unwrap();
    let cfg_domain_after = write_config(
        dir2.path(),
        r#"
global {
    dial_mode: domain
}
node {
    n1: 'socks5://127.0.0.1:1080'
}
group {
    us {
        policy: fixed(0)
    }
}
routing {
    dip(10.0.0.0/8) -> direct
    domain(suffix: example.com) && dport(8443) -> us
    fallback: us
}
"#,
    );
    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_domain_after.to_str().unwrap(),
        "--proto",
        "tcp",
        "--dip",
        "10.1.2.3",
        "--dport",
        "443",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(r#""domain_final":true"#), "{stdout}");
    assert!(
        stdout.contains(r#""lan_disposition":"native_direct_offload""#),
        "{stdout}"
    );

    let dir3 = tempfile::tempdir().unwrap();
    let cfg_clash_global = write_config(
        dir3.path(),
        r#"
global {
    dial_mode: domain
}
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        default_mode: global
    }
}
node {
    n1: 'socks5://127.0.0.1:1080'
}
group {
    us {
        policy: fixed(0)
    }
}
routing {
    dip(10.0.0.0/8) -> direct
    domain(suffix: example.com) && dport(8443) -> us
    fallback: us
}
"#,
    );
    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_clash_global.to_str().unwrap(),
        "--proto",
        "tcp",
        "--dip",
        "10.1.2.3",
        "--dport",
        "443",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(r#""domain_final":false"#), "{stdout}");
    assert!(
        stdout.contains(r#""lan_disposition":"userspace_control_plane_routing""#),
        "{stdout}"
    );
}

#[test]
fn enforces_port_53_override_marked_direct_asymmetry_and_domain_plus_plus_punt() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(
        dir.path(),
        r#"
global {
    dial_mode: 'domain++'
}
node {
    n1: 'socks5://127.0.0.1:1080'
}
group {
    us {
        policy: fixed(0)
    }
}
routing {
    sip(192.168.1.10) && sport(53000) && mac('aa-bb-cc-dd-ee-ff') && dscp(0x2e) -> direct(must, mark: 0x200)
    dip(1.1.1.1) && dport(53) -> direct
    dip(4.4.4.4) && dport(53) -> block
    dip(9.9.9.9) && dport(53) -> block(must)
    dport(443) && !pname(curl) -> us
    dport(8443) -> us
    fallback: direct
}
"#,
    );
    let cfg_str = cfg.to_str().unwrap();

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_str,
        "--proto",
        "udp",
        "--sip",
        "192.168.1.10",
        "--sport",
        "53000",
        "--dip",
        "8.8.8.8",
        "--dport",
        "53",
        "--mac",
        "AA:BB:CC:DD:EE:FF",
        "--dscp",
        "46",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(r#""outbound":"direct""#), "{stdout}");
    assert!(stdout.contains(r#""must":true"#), "{stdout}");
    assert!(stdout.contains(r#""mark":512"#), "{stdout}");
    assert!(
        stdout.contains(r#""lan_disposition":"native_direct_offload""#),
        "{stdout}"
    );
    assert!(
        stdout.contains(r#""wan_disposition":"userspace_marked_direct""#),
        "{stdout}"
    );

    let (ok, stdout, stderr) = run_route(&[
        "route", "-c", cfg_str, "--proto", "udp", "--dip", "1.1.1.1", "--dport", "53", "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(r#""decision":"determinate""#), "{stdout}");
    assert!(stdout.contains(r#""outbound":"direct""#), "{stdout}");
    assert!(stdout.contains(r#""must":null"#), "{stdout}");
    assert!(stdout.contains(r#""lan_disposition":null"#), "{stdout}");

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_str,
        "--proto",
        "udp",
        "--sip",
        "192.168.1.20",
        "--dip",
        "1.1.1.1",
        "--dport",
        "53",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(r#""outbound":"direct""#), "{stdout}");
    assert!(stdout.contains(r#""must":false"#), "{stdout}");
    assert!(
        stdout.contains(r#""lan_disposition":"userspace_dns""#),
        "{stdout}"
    );
    assert!(
        stdout.contains(r#""wan_disposition":"userspace_dns""#),
        "{stdout}"
    );

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_str,
        "--proto",
        "udp",
        "--sip",
        "192.168.1.20",
        "--dip",
        "4.4.4.4",
        "--dport",
        "53",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(r#""outbound":"block""#), "{stdout}");
    assert!(stdout.contains(r#""must":false"#), "{stdout}");
    assert!(
        stdout.contains(r#""lan_disposition":"userspace_dns""#),
        "{stdout}"
    );
    assert!(
        stdout.contains(r#""wan_disposition":"userspace_dns""#),
        "{stdout}"
    );

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_str,
        "--proto",
        "udp",
        "--sip",
        "192.168.1.20",
        "--dip",
        "9.9.9.9",
        "--dport",
        "53",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.contains(r#""outbound":"block""#), "{stdout}");
    assert!(stdout.contains(r#""must":true"#), "{stdout}");
    assert!(
        stdout.contains(r#""lan_disposition":"kernel_drop""#),
        "{stdout}"
    );
    assert!(
        stdout.contains(r#""wan_disposition":"kernel_drop""#),
        "{stdout}"
    );

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_str,
        "--proto",
        "tcp",
        "--sip",
        "192.168.1.20",
        "--dip",
        "198.51.100.1",
        "--dport",
        "8443",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(
        stdout.contains(r#""lan_disposition":"userspace_control_plane_routing""#),
        "{stdout}"
    );

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_str,
        "--proto",
        "tcp",
        "--sip",
        "192.168.1.20",
        "--dip",
        "198.51.100.1",
        "--dport",
        "443",
        "--pname",
        "wget\"quoted",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(
        stdout.contains(r#""lan_disposition":"userspace_proxy""#),
        "{stdout}"
    );
}

#[test]
fn rejects_invalid_inputs_and_unvalidated_config_targets() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(
        dir.path(),
        r#"
routing {
    fallback: direct
}
"#,
    );
    let cfg_str = cfg.to_str().unwrap();

    for bad_args in [
        &["route", "-c", cfg_str, "--proto", "tcp"][..],
        &[
            "route", "-c", cfg_str, "--proto", "tcp", "--dip", "1.1.1.1", "--dport", "0",
        ][..],
        &[
            "route", "-c", cfg_str, "--proto", "tcp", "--dip", "1.1.1.1", "--sport", "0",
        ][..],
        &[
            "route", "-c", cfg_str, "--proto", "tcp", "--dip", "1.1.1.1", "--dscp", "64",
        ][..],
        &[
            "route",
            "-c",
            cfg_str,
            "--proto",
            "tcp",
            "--domain",
            "bad..domain",
        ][..],
        &[
            "route",
            "-c",
            cfg_str,
            "--proto",
            "tcp",
            "--dip",
            "1.1.1.1",
            "--mac",
            "not-a-mac",
        ][..],
    ] {
        let (ok, _, _) = run_route(bad_args);
        assert!(!ok, "expected failure for {bad_args:?}");
    }

    let bad_cfg = write_config(
        dir.path(),
        r#"
node {
    raw_node: 'socks5://127.0.0.1:1080'
}
routing {
    dip(1.1.1.1) -> raw_node
    fallback: direct
}
"#,
    );
    let (ok, _, stderr) = run_route(&[
        "route",
        "-c",
        bad_cfg.to_str().unwrap(),
        "--proto",
        "tcp",
        "--dip",
        "1.1.1.1",
    ]);
    assert!(!ok);
    assert!(stderr.contains("group"), "stderr: {stderr}");
}

#[test]
fn handles_omitted_dport_mapped_ipv4_and_clean_json_stdout_on_warnings() {
    let dir = tempfile::tempdir().unwrap();
    let missing_data = dir.path().join("empty-data");
    std::fs::create_dir_all(&missing_data).unwrap();
    let cfg = write_config(
        dir.path(),
        &format!(
            r#"
global {{
    data_dir: '{}'
    dial_mode: ip
}}
node {{
    n1: 'socks5://127.0.0.1:1080'
}}
group {{
    us {{
        policy: fixed(0)
    }}
}}
routing {{
    domain(geosite:missing_cat) -> us
    sip(192.168.1.0/24) && dip(172.217.0.0/16) -> direct(must)
    dip(172.217.0.0/16) -> us
    fallback: direct
}}
"#,
            missing_data.display()
        ),
    );
    let cfg_str = cfg.to_str().unwrap();

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_str,
        "--proto",
        "udp",
        "--domain",
        "example.com",
        "--dip",
        "1.1.1.1",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(
        stdout.starts_with('{') && stdout.trim_end().ends_with('}'),
        "stdout contaminated by warnings: {stdout:?}"
    );
    assert!(
        stderr.contains("geosite.dat"),
        "expected missing geo warning on stderr, got: {stderr:?}"
    );
    assert!(stdout.contains(r#""decision":"determinate""#), "{stdout}");
    assert!(stdout.contains(r#""outbound":"direct""#), "{stdout}");
    assert!(stdout.contains(r#""must":false"#), "{stdout}");
    assert!(
        stdout.contains(r#""domain_final":null"#),
        "omitted --dport on non-must direct cannot settle port-53 vs non-53: {stdout}"
    );
    assert!(
        stdout.contains(r#""lan_disposition":null"#),
        "omitted --dport on non-must direct cannot settle port-53 vs non-53: {stdout}"
    );
    assert!(
        stdout.contains(r#""wan_disposition":null"#),
        "omitted --dport on non-must direct cannot settle port-53 vs non-53: {stdout}"
    );

    let (ok, stdout, stderr) = run_route(&[
        "route",
        "-c",
        cfg_str,
        "--proto",
        "tcp",
        "--domain",
        "example.com",
        "--sip",
        "::ffff:192.168.1.25",
        "--dip",
        "::ffff:172.217.75.94",
        "--json",
    ]);
    assert!(ok, "stderr: {stderr}");
    assert!(stdout.starts_with('{'), "stdout: {stdout:?}");
    assert!(stdout.contains(r#""decision":"determinate""#), "{stdout}");
    assert!(stdout.contains(r#""outbound":"direct""#), "{stdout}");
    assert!(stdout.contains(r#""matched_rule":1"#), "{stdout}");
    assert!(stdout.contains(r#""must":true"#), "{stdout}");
    assert!(
        stdout.contains(r#""lan_disposition":"native_direct_offload""#),
        "direct(must) settles identically on port 53 and non-53: {stdout}"
    );
    assert!(
        stdout.contains(r#""wan_disposition":"native_direct_offload""#),
        "direct(must) settles identically on port 53 and non-53: {stdout}"
    );
}
