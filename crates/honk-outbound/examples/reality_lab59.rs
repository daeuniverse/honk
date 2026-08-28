//! REALITY interop probe against the lab server at 10.10.10.59:8443
//! (vless+reality+xtls-rprx-vision). Positive case: TLS handshake +
//! REALITY ed25519 server authentication + a minimal VLESS request
//! tunneling an HTTP/1.1 HEAD to the LAN bench server (the lab has no
//! direct internet egress). Negative case: a wrong public key must fail
//! closed at the server-authentication step.
//!
//! Run: cargo run -p honk-outbound --example reality_lab59

use std::time::Duration;

use honk_config::node::Node;
use honk_outbound::reality::{RealityConfig, parse_reality_config, reality_connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADDR: &str = "10.10.10.59:8443";
const UUID: &str = "4a3d42a2-a62d-4454-b2a2-7cbe5ddf4c7a";
const PUBLIC_KEY: &str = "ubLKoDOT4sSoWuztLwduKc9szHmp4lvmKbMk4-1O518";
const SHORT_ID: &str = "a1b2c3d4e5f60718";
const SNI: &str = "dl.google.com";
// LAN bench server: the lab has no direct internet egress, so the probe
// target lives on the probe machine itself.
const TARGET_HOST: &str = "10.10.10.70";
const TARGET_PORT: u16 = 18080;

fn lab_config(addr_host: &str, public_key: &str) -> RealityConfig {
    let node = Node {
        name: "lab59".into(),
        host: addr_host.into(),
        port: 8443,
        outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
            tls: honk_config::node::TlsOptions {
                sni: Some(SNI.into()),
                reality_public_key: Some(public_key.into()),
                reality_short_id: Some(SHORT_ID.into()),
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    parse_reality_config(&node).unwrap().unwrap()
}

/// Minimal VLESS request header (version 0) with the xtls-rprx-vision
/// flow addon: uuid, protobuf-encoded Flow addon, cmd=TCP, domain target.
fn vless_request(uuid: [u8; 16], host: &str, port: u16) -> Vec<u8> {
    const FLOW: &[u8] = b"xtls-rprx-vision";
    let mut buf = Vec::new();
    buf.push(0); // version
    buf.extend_from_slice(&uuid);
    buf.push((2 + FLOW.len()) as u8); // addons length
    buf.push(0x0A); // protobuf field 1 (Flow), length-delimited
    buf.push(FLOW.len() as u8);
    buf.extend_from_slice(FLOW);
    buf.push(1); // command: TCP
    buf.extend_from_slice(&port.to_be_bytes());
    buf.push(2); // address type: domain
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    buf
}

async fn positive(
    addr: &str,
    addr_host: &str,
    public_key: &str,
    chrome: bool,
) -> anyhow::Result<()> {
    let uuid = uuid::Uuid::parse_str(UUID)?.into_bytes();
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut tls = reality_connect(tcp, &lab_config(addr_host, public_key), chrome).await?;
    println!("[+] TLS handshake + REALITY server authentication OK (sni={SNI})");

    tls.write_all(&vless_request(uuid, TARGET_HOST, TARGET_PORT))
        .await?;
    tls.write_all(
        format!("GET /generate_204 HTTP/1.1\r\nHost: {TARGET_HOST}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await?;
    tls.flush().await?;

    // VLESS response header: version + addons_len (+ addons), then payload.
    let mut resp = Vec::new();
    let mut hdr = [0u8; 2];
    tls.read_exact(&mut hdr).await?;
    anyhow::ensure!(hdr[0] == 0, "unexpected VLESS response version {}", hdr[0]);
    if hdr[1] > 0 {
        let mut addons = vec![0u8; hdr[1] as usize];
        tls.read_exact(&mut addons).await?;
    }
    tls.take(8192).read_to_end(&mut resp).await?;
    let payload = vision_unpad(&uuid, &resp);
    let text = String::from_utf8_lossy(&payload);
    let status = text.lines().next().unwrap_or("");
    anyhow::ensure!(status.starts_with("HTTP/"), "unexpected response: {text}");
    println!("[+] VLESS tunnel OK: {status}");
    Ok(())
}

/// Minimal XTLS Vision unpadding for the response direction: the first
/// frame is prefixed with the user UUID, then frames of
/// `[command][contentLen u16][paddingLen u16][content][padding]`; command 1
/// switches to raw passthrough (Xray-core vision.go XtlsWrite/XtlsRead).
fn vision_unpad(uuid: &[u8; 16], data: &[u8]) -> Vec<u8> {
    if data.len() < 21 || data[..16] != uuid[..] {
        return data.to_vec();
    }
    let mut out = Vec::new();
    let mut buf = &data[16..];
    while !buf.is_empty() {
        if buf.len() < 5 {
            break;
        }
        let command = buf[0];
        let content_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let padding_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        buf = &buf[5..];
        if command == 1 {
            out.extend_from_slice(buf);
            break;
        }
        let n = content_len.min(buf.len());
        out.extend_from_slice(&buf[..n]);
        buf = &buf[(n + padding_len).min(buf.len())..];
    }
    out
}

async fn negative(addr: &str, addr_host: &str) -> anyhow::Result<()> {
    // Well-formed but wrong public key: the server cannot decrypt our
    // session_id and relays us to the real dl.google.com, so the leaf
    // certificate is not the ephemeral ed25519 one and authentication
    // must fail closed.
    let wrong_pbk = format!("{}A", &PUBLIC_KEY[..PUBLIC_KEY.len() - 1]);
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    match reality_connect(tcp, &lab_config(addr_host, &wrong_pbk), true).await {
        Ok(_) => anyhow::bail!("wrong public key unexpectedly authenticated"),
        Err(e) => {
            println!("[+] wrong public key rejected as expected: {e:#}");
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let chrome = !std::env::args().any(|a| a == "--no-chrome");
    // Optional overrides for local debugging: reality_lab59 [addr] [pbk]
    let mut args = std::env::args().skip(1).filter(|a| !a.starts_with("--"));
    let addr = args.next().unwrap_or_else(|| ADDR.to_string());
    let addr_host = addr.split(':').next().unwrap_or(&addr).to_string();
    let pbk = args.next().unwrap_or_else(|| PUBLIC_KEY.to_string());
    tokio::time::timeout(
        Duration::from_secs(20),
        positive(&addr, &addr_host, &pbk, chrome),
    )
    .await??;
    tokio::time::timeout(Duration::from_secs(20), negative(&addr, &addr_host)).await??;
    println!("REALITY lab59 interop: PASS");
    Ok(())
}
