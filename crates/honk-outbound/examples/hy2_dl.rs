//! Download through the hy2 handler directly (no engine datapath/relay) to
//! isolate QUIC receive performance from honk-core.
//!
//! Usage: hy2_dl <hysteria2 share link> [host:port] [path]

use honk_config::node::Node;
use honk_outbound::proxy::TcpOutbound;
use honk_outbound::proxy::hysteria2::Hysteria2Handler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let link = std::env::args().nth(1).expect("share link");
    let target = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "103.26.8.157:18080".into());
    let path = std::env::args().nth(3).unwrap_or_else(|| "/big.bin".into());
    let node = Node::from_share_link(&link)?;
    let handler = Hysteria2Handler::new();
    let addr: std::net::SocketAddr = target.parse()?;
    let mut stream = handler
        .dial(&node, addr, None, std::time::Duration::from_secs(10))
        .await?;
    stream
        .stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut buf = vec![0u8; 256 * 1024];
    let start = std::time::Instant::now();
    let mut total = 0u64;
    loop {
        let n = stream.stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n as u64;
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "{total} bytes in {elapsed:.1}s = {:.1} MB/s",
        total as f64 / elapsed / 1048576.0
    );
    Ok(())
}
