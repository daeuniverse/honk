use std::process::Command;

fn run_bpf(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_honk-tool"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[test]
fn bpf_lookup_validates_selectors_and_pin_root() {
    let dir = tempfile::tempdir().unwrap();
    let missing_root = dir.path().join("missing-pins");
    let root_str = missing_root.to_str().unwrap();

    let (ok, _, stderr) = run_bpf(&["bpf", "lookup", "--pin-root", root_str]);
    assert!(!ok);
    assert!(
        stderr.contains("--ip") || stderr.contains("--sip") || stderr.contains("--dip"),
        "stderr: {stderr}"
    );

    let (ok, _, _) = run_bpf(&[
        "bpf",
        "lookup",
        "--ip",
        "172.217.75.94",
        "--dip",
        "172.217.75.94",
        "--pin-root",
        root_str,
    ]);
    assert!(!ok);

    let (ok, _, _) = run_bpf(&[
        "bpf",
        "lookup",
        "--ip",
        "172.217.75.94",
        "--sip",
        "192.168.1.10",
        "--pin-root",
        root_str,
    ]);
    assert!(!ok);

    let (ok, _, stderr) = run_bpf(&[
        "bpf",
        "lookup",
        "--dip",
        "172.217.75.94",
        "--dport",
        "443",
        "--proto",
        "tcp",
        "--pin-root",
        root_str,
    ]);
    assert!(!ok);
    assert!(stderr.contains("CONN_STATE_MAP"), "stderr: {stderr}");
}
