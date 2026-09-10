//! `honk-tool diagnose` — one-shot health check of a running honk engine.
//!
//! Read-only: inspects the process, namespace/veth plumbing, pinned maps,
//! policy routing, and the clash API.  Requires root for the map reads.

use std::{ffi::OsString, io, path::PathBuf};

use clap::Args;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Args)]
pub struct DiagnoseArgs {
    /// BPF pin root.
    #[arg(long, default_value = "/sys/fs/bpf")]
    pub pin_root: PathBuf,
    /// Clash API base URL to probe (empty = skip API checks).
    #[arg(long, default_value = "http://127.0.0.1:9090")]
    pub api: String,
    /// Clash API Bearer token (overrides HONK_API_SECRET).
    #[arg(long, env = "HONK_API_SECRET", hide_env_values = true)]
    pub secret: Option<String>,
    /// Expected TPROXY mark (hex, no 0x).
    #[arg(long, default_value_t = 0x0800_0000)]
    pub tproxy_mark: u32,
}

pub async fn run(args: DiagnoseArgs) -> anyhow::Result<()> {
    let mut issues = 0usize;

    match find_engine() {
        Some((pid, comm)) => println!("[ok] engine running: pid {pid} ({comm})"),
        None => {
            println!("[FAIL] no honk-core/dae process found");
            issues += 1;
        }
    }

    check_path(
        "/var/run/netns/daens",
        "daens network namespace",
        &mut issues,
    );
    check_path("/sys/class/net/dae0", "dae0 veth", &mut issues);

    // 3. Policy routing inside daens: fwmark rule present.
    let rule_out = run_cmd("ip", &["netns", "exec", "daens", "ip", "rule", "list"])?;
    let mark_hex = format!("{:#x}", args.tproxy_mark);
    if rule_out.contains(&format!("fwmark {}", mark_hex)) || rule_out.contains(&mark_hex) {
        println!("[ok] fwmark {mark_hex} rule present in daens");
    } else {
        println!("[FAIL] no fwmark {mark_hex} rule in daens `ip rule list`");
        issues += 1;
    }

    for name in [
        "CONN_STATE_MAP",
        "REDIRECT_TRACK",
        "ROUTING_HANDOFF_MAP",
        "CONN_STATE_OCCUPANCY",
        honk_ebpf_common::ROUTING_POLICY_ROOT_NAME,
    ] {
        check_path(
            &args.pin_root.join(name).display().to_string(),
            name,
            &mut issues,
        );
    }

    // 5. Occupancy + overflow via the bpf stats path.
    match super::bpf::stats(super::bpf::StatsArgs {
        pin_root: args.pin_root.clone(),
    }) {
        Ok(()) => {}
        Err(e) => {
            println!("[FAIL] map stats read: {e}");
            issues += 1;
        }
    }

    if !args.api.is_empty() {
        let url = format!("{}/version", args.api.trim_end_matches('/'));
        match reqwest_get(&url, args.secret.as_deref()).await {
            Ok(body) => println!("[ok] clash API {}: {}", args.api, body.trim()),
            Err(e) => {
                println!("[FAIL] clash API {}: {}", args.api, e);
                issues += 1;
            }
        }
    }

    println!(
        "\n{}",
        if issues == 0 {
            "diagnose: all checks passed".to_string()
        } else {
            format!("diagnose: {issues} issue(s) found")
        }
    );
    anyhow::ensure!(issues == 0, "diagnose: {issues} issue(s) found");
    Ok(())
}

fn find_engine() -> Option<(u32, String)> {
    let entries = std::fs::read_dir("/proc").ok()?;
    find_engine_in(entries.map(|entry| entry.map(|entry| (entry.file_name(), entry.path()))))
}

fn find_engine_in(
    entries: impl Iterator<Item = io::Result<(OsString, PathBuf)>>,
) -> Option<(u32, String)> {
    for entry in entries {
        let Ok((name, path)) = entry else {
            continue;
        };
        let Some(name) = name.to_str() else {
            continue;
        };
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let Ok(comm) = std::fs::read_to_string(path.join("comm")) else {
            continue;
        };
        let comm = comm.trim().to_string();
        if comm == "honk-core" || comm == "honk" || comm == "dae" {
            return Some((pid, comm));
        }
    }
    None
}

fn check_path(path: &str, label: &str, issues: &mut usize) {
    if std::path::Path::new(path).exists() {
        println!("[ok] {label} present ({path})");
    } else {
        println!("[FAIL] {label} missing ({path})");
        *issues += 1;
    }
}

fn run_cmd(cmd: &str, args: &[&str]) -> anyhow::Result<String> {
    let out = std::process::Command::new(cmd).args(args).output()?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Minimal GET helper (avoids pulling reqwest into the tool for one call).
async fn reqwest_get(url: &str, secret: Option<&str>) -> anyhow::Result<String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("only http:// API URLs are supported"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let stream = tokio::net::TcpStream::connect(host).await?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(secret) = secret {
        request.push_str("Authorization: Bearer ");
        request.push_str(secret);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    writer.write_all(request.as_bytes()).await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let mut status = line.split_whitespace();
    anyhow::ensure!(
        matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")),
        "invalid HTTP status line"
    );
    let code = status
        .next()
        .filter(|code| code.len() == 3)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP status code"))?;
    anyhow::ensure!((200..300).contains(&code), "{}", line.trim_end());
    loop {
        line.clear();
        anyhow::ensure!(
            reader.read_line(&mut line).await? != 0,
            "incomplete HTTP response headers"
        );
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    let mut body = String::new();
    reader.read_to_string(&mut body).await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    use super::find_engine_in;

    #[test]
    fn find_engine_skips_unreadable_entries() {
        let dir = tempfile::tempdir().unwrap();
        let missing_comm = dir.path().join("100");
        let engine = dir.path().join("200");
        std::fs::create_dir(&missing_comm).unwrap();
        std::fs::create_dir(&engine).unwrap();
        std::fs::write(engine.join("comm"), "honk-core\n").unwrap();
        let entries = [
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            Ok((OsString::from_vec(vec![0xff]), dir.path().to_path_buf())),
            Ok(("100".into(), missing_comm)),
            Ok(("200".into(), engine)),
        ];

        let found = find_engine_in(entries.into_iter());

        assert_eq!(found, Some((200, "honk-core".to_owned())));
    }
}
