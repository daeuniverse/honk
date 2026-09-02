//! VMess AEAD interop probe against the lab server (sing-box vmess
//! inbounds): 10.10.10.70:8446 (bare TCP) and 10.10.10.70:8445
//! (ws+tls, self-signed cert, skip verify). Tunnels an HTTP/1.1 GET through
//! the node and expects a real HTTP reply. The default target is the LAN
//! bench server on the lab machine itself; pass a target to use e.g.
//! www.gstatic.com:80 instead.
//!
//! Run: cargo run -p honk-outbound --features rprx --example vmess_lab59
//!      [8446|8445|all] [host] [target-addr] [target-host] [port]

use std::time::Duration;

use honk_config::node::Node;
use honk_outbound::proxy::TcpOutbound;
use honk_outbound::proxy::vmess::VmessHandler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "10.10.10.70";
const UUID_TCP: &str = "82166345-d1bb-48f8-bd3b-cf0c152a863c";
const UUID_WS: &str = "216b9040-3f89-4103-b4d6-5f013ee0b1c4";

fn node(host: &str, port: u16, uuid: &str, ws_tls: bool) -> Node {
    Node {
        name: format!("lab59-{port}"),
        address: format!("{host}:{port}"),
        host: host.into(),
        port,
        outbound: honk_config::node::OutboundConfig::Vmess(honk_config::node::VmessConfig {
            uuid: Some(uuid.into()),
            transport: honk_config::node::StreamTransportOptions {
                transport: if ws_tls { "ws".into() } else { "tcp".into() },
                ws_path: ws_tls.then(|| "/vmess".into()),
                ..Default::default()
            },
            tls: honk_config::node::TlsOptions {
                enabled: ws_tls,
                sni: ws_tls.then(|| "test.local".into()),
                skip_cert_verify: ws_tls,
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn probe(node: &Node, target: std::net::SocketAddr, target_host: &str) -> anyhow::Result<()> {
    let mut ps = VmessHandler::new()
        .dial(
            node,
            target,
            if target_host.is_empty() {
                None
            } else {
                Some(target_host)
            },
            Duration::from_secs(10),
        )
        .await?;
    println!("[+] dial {} OK (request header sent)", node.name);

    ps.stream
        .write_all(
            format!(
                "GET /generate_204 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                if target_host.is_empty() {
                    "bench"
                } else {
                    target_host
                }
            )
            .as_bytes(),
        )
        .await?;
    ps.stream.flush().await?;
    println!("[+] payload written, reading response");

    let mut resp = Vec::new();
    ps.stream
        .take(8192)
        .read_to_end(&mut resp)
        .await
        .map_err(|e| anyhow::anyhow!("payload relay broken: {e}"))?;
    let text = String::from_utf8_lossy(&resp);
    let status = text.lines().next().unwrap_or("");
    anyhow::ensure!(status.starts_with("HTTP/"), "unexpected response: {text:?}");
    println!("[+] {} tunnel OK: {status}", node.name);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Optional: vmess_lab59 [8446|8445|all] [host] [target-addr] [target-host]
    let mut args = std::env::args().skip(1);
    let which = args.next().unwrap_or_else(|| "all".into());
    let host = args.next().unwrap_or_else(|| HOST.into());
    let target: std::net::SocketAddr = args
        .next()
        .unwrap_or_else(|| "10.10.10.70:18080".into())
        .parse()?;
    let target_host = args.next().unwrap_or_default();
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let timeout = Duration::from_secs(20);
    let port_tcp = if port != 0 { port } else { 8446 };
    let port_ws = if port != 0 { port } else { 8445 };
    if which == "8446" || which == "all" {
        tokio::time::timeout(
            timeout,
            probe(
                &node(&host, port_tcp, UUID_TCP, false),
                target,
                &target_host,
            ),
        )
        .await??;
    }
    if which == "8445" || which == "all" {
        tokio::time::timeout(
            timeout,
            probe(&node(&host, port_ws, UUID_WS, true), target, &target_host),
        )
        .await??;
    }
    println!("VMess lab59 interop: PASS");
    Ok(())
}
