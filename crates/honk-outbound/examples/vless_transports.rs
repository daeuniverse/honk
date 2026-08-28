//! VLESS transport-combination interop probe against the lab server
//! (sing-box vless inbounds on 10.10.10.59): 9560 (ws), 9561 (ws+tls,
//! self-signed cert, skip verify), 9562 (grpc). Tunnels an HTTP/1.1 GET to
//! the LAN bench server through each and expects a real HTTP reply.
//!
//! Run: cargo run -p honk-outbound --features rprx --release \
//!        --example vless_transports [9560|9561|9562|all]

use std::time::Duration;

use honk_config::node::Node;
use honk_outbound::proxy::TcpOutbound;
use honk_outbound::proxy::vless::VLessHandler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "10.10.10.59";
const TARGET: &str = "10.10.10.70:18080";
const UUID_WS: &str = "c95a1e15-e558-4a6b-a9a5-5d8ec836b803";
const UUID_WS_TLS: &str = "2d5652ec-3a89-406f-af69-8e7ea4b3d5a1";
const UUID_GRPC: &str = "80e02391-1835-47b8-8df7-3077554bc2f6";

fn node(host: &str, port: u16, uuid: &str, transport: &str, tls: bool) -> Node {
    Node {
        name: format!("lab59-{port}"),
        address: format!("{host}:{port}"),
        host: host.into(),
        port,
        outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some(uuid.into()),
            transport: honk_config::node::StreamTransportOptions {
                transport: transport.into(),
                ws_path: (transport == "ws").then(|| "/vless-ws".into()),
                grpc_service: (transport == "grpc").then(|| "vless-grpc".into()),
                ..Default::default()
            },
            tls: honk_config::node::TlsOptions {
                enabled: tls,
                sni: tls.then(|| "test.local".into()),
                skip_cert_verify: tls,
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn probe(node: &Node, target: std::net::SocketAddr) -> anyhow::Result<()> {
    let mut ps = VLessHandler::new()
        .dial(node, target, None, Duration::from_secs(10))
        .await?;
    println!("[+] dial {} OK", node.name);

    ps.stream
        .write_all(b"GET /generate_204 HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n")
        .await?;
    ps.stream.flush().await?;

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
    let mut args = std::env::args().skip(1);
    let which = args.next().unwrap_or_else(|| "all".into());
    // Optional "host:port" dials a relay instead of the lab directly
    // (traffic capture); the proxied target is unchanged.
    let connect_addr: Option<String> = args.next();
    let timeout = Duration::from_secs(20);
    let cases = [
        ("9560", node(HOST, 9560, UUID_WS, "ws", false)),
        ("9561", node(HOST, 9561, UUID_WS_TLS, "ws", true)),
        ("9562", node(HOST, 9562, UUID_GRPC, "grpc", false)),
    ];
    for (tag, node) in &cases {
        if which == "all" || which == *tag {
            let mut node = node.clone();
            if let Some(addr) = &connect_addr {
                let (h, p) = addr.rsplit_once(':').unwrap();
                node.host = h.to_string();
                node.port = p.parse()?;
                node.address = addr.clone();
            }
            tokio::time::timeout(timeout, probe(&node, TARGET.parse()?)).await??;
        }
    }
    println!("VLESS transports interop: PASS");
    Ok(())
}
