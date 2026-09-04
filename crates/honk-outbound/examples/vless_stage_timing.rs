//! Stage-level timing for a VLESS dial through a share link.
//! Usage: vless_stage_timing <vless://link> [runs] [target host:port]

use std::time::Instant;

use honk_outbound::reality::{parse_reality_config, reality_connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn vless_request(uuid: [u8; 16], host: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0u8);
    buf.extend_from_slice(&uuid);
    buf.push(0u8);
    buf.push(1u8);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.push(2u8);
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    buf
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let link = std::env::args().nth(1).expect("vless share link");
    let runs: u32 = std::env::args()
        .nth(2)
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let target = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "cp.cloudflare.com:80".into());
    let (target_host, target_port) = target.split_once(':').expect("host:port");
    let target_port: u16 = target_port.parse()?;

    let node = honk_config::node::Node::from_share_link(&link)?;
    let server = format!("{}:{}", node.host(), node.port);
    let uuid = uuid::Uuid::parse_str(node.vless().unwrap().uuid.as_deref().unwrap())?.into_bytes();
    let reality = parse_reality_config(&node)?;

    for run in 1..=runs {
        let t0 = Instant::now();
        let addrs: Vec<_> = tokio::net::lookup_host(&server).await?.collect();
        let t_dns = t0.elapsed();
        let addr = match addrs.first() {
            Some(addr) => *addr,
            None => {
                println!("run {run}: no address");
                continue;
            }
        };

        let t1 = Instant::now();
        let tcp = match tokio::net::TcpStream::connect(addr).await {
            Ok(tcp) => tcp,
            Err(e) => {
                println!("run {run}: tcp connect failed: {e}");
                continue;
            }
        };
        let t_tcp = t1.elapsed();

        let t2 = Instant::now();
        let mut tls = match &reality {
            Some(config) => match reality_connect(tcp, config, false).await {
                Ok(tls) => tls,
                Err(e) => {
                    println!("run {run}: reality failed after {:?}: {e}", t2.elapsed());
                    continue;
                }
            },
            None => {
                println!("run {run}: node has no reality config");
                continue;
            }
        };
        let t_reality = t2.elapsed();

        let t3 = Instant::now();
        let mut req = vless_request(uuid, target_host, target_port);
        req.extend_from_slice(
            format!("HEAD / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        tls.write_all(&req).await?;
        tls.flush().await?;
        let mut one = [0u8; 1];
        let n = tls.read(&mut one).await?;
        let t_exchange = t3.elapsed();

        println!(
            "run {run}: dns={:.1}ms tcp={:.1}ms reality={:.1}ms exchange={:.1}ms ({}B) total={:.1}ms",
            t_dns.as_secs_f64() * 1000.0,
            t_tcp.as_secs_f64() * 1000.0,
            t_reality.as_secs_f64() * 1000.0,
            t_exchange.as_secs_f64() * 1000.0,
            n,
            t0.elapsed().as_secs_f64() * 1000.0,
        );
    }
    Ok(())
}
