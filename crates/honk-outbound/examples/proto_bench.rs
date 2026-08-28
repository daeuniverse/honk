//! Protocol throughput benchmark against a LAN target reachable from the
//! proxy server's outbound. Measures download and upload throughput over
//! the tunnel (median + peak over N runs) plus a coarse CPU usage sample.
//!
//! Usage: proto_bench <share-link> <target-addr> [runs=5] [up_mb=256]
//!   share-link:  any link accepted by `Node::from_share_link` (ss, trojan,
//!                anytls, vmess, vless, hysteria2, tuic, juicity, socks5)
//!   target-addr: host:port of the bench HTTP server (GET /big.bin,
//!                POST /sink), e.g. 10.10.10.70:18080

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use honk_config::node::Node;
use honk_outbound::proxy::ProxyRegistry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn opt(name: &str, default: u64) -> u64 {
    std::env::args()
        .find_map(|a| a.strip_prefix(&format!("{name}=")).map(str::to_string))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Coarse process CPU usage between two samples of /proc/self/stat
/// (utime + stime jiffies), as a percentage of the elapsed wall time.
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // Fields after the comm ")": index 11 = utime, 12 = stime.
    let rest = stat.rsplit_once(')').map(|(_, r)| r).unwrap_or("");
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: u64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
    utime + stime
}

struct Sample {
    mbps: f64,
    cpu_pct: f64,
}

/// Download `Content-Length` bytes through the tunnel; returns MB/s and CPU%.
async fn bench_down(
    tcp: &std::sync::Arc<dyn honk_outbound::proxy::TcpOutbound>,
    node: &Node,
    target: SocketAddr,
) -> anyhow::Result<Sample> {
    let mut s = tcp
        .dial(node, target, None, Duration::from_secs(10))
        .await?;
    s.stream
        .write_all(b"GET /big.bin HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n")
        .await?;
    // Response headers: small; read until CRLFCRLF.
    let mut hdr = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        s.stream.read_exact(&mut b).await?;
        hdr.push(b[0]);
        if hdr.len() >= 4 && &hdr[hdr.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        anyhow::ensure!(hdr.len() < 4096, "response headers too large");
    }
    let ticks0 = cpu_ticks();
    let t0 = Instant::now();
    let verify = std::env::args().any(|a| a == "verify=1");
    let mut hasher = verify.then(|| {
        use sha2::Digest;
        sha2::Sha256::new()
    });
    let mut total = 0u64;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(30), s.stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if let Some(h) = hasher.as_mut() {
                    use sha2::Digest;
                    h.update(&buf[..n]);
                }
                total += n as u64;
            }
            Ok(Err(e)) => anyhow::bail!("read error: {e}"),
            Err(_) => anyhow::bail!("read timeout"),
        }
    }
    if let Some(h) = hasher {
        use sha2::Digest;
        let digest: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        println!("down sha256({total}B): {digest}");
    }
    let secs = t0.elapsed().as_secs_f64();
    let ticks1 = cpu_ticks();
    Ok(Sample {
        mbps: total as f64 / 1e6 / secs,
        cpu_pct: cpu_pct(ticks1 - ticks0, secs),
    })
}

/// Upload `bytes` through the tunnel to POST /sink; returns MB/s and CPU%.
async fn bench_up(
    tcp: &std::sync::Arc<dyn honk_outbound::proxy::TcpOutbound>,
    node: &Node,
    target: SocketAddr,
    bytes: u64,
) -> anyhow::Result<Sample> {
    let mut s = tcp
        .dial(node, target, None, Duration::from_secs(10))
        .await?;
    s.stream
        .write_all(
            format!(
                "POST /sink HTTP/1.1\r\nHost: bench\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let ticks0 = cpu_ticks();
    let t0 = Instant::now();
    let mut sent = 0u64;
    let chunk = vec![0xABu8; 1024 * 1024];
    while sent < bytes {
        let n = (bytes - sent).min(chunk.len() as u64) as usize;
        tokio::time::timeout(Duration::from_secs(60), s.stream.write_all(&chunk[..n]))
            .await
            .map_err(|_| anyhow::anyhow!("write timeout"))??;
        sent += n as u64;
    }
    s.stream.shutdown().await.ok();
    // Drain the 200 response so the server-side cost is included.
    let mut buf = vec![0u8; 8192];
    let _ = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match s.stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    let secs = t0.elapsed().as_secs_f64();
    let ticks1 = cpu_ticks();
    Ok(Sample {
        mbps: sent as f64 / 1e6 / secs,
        cpu_pct: cpu_pct(ticks1 - ticks0, secs),
    })
}

fn cpu_pct(delta_ticks: u64, secs: f64) -> f64 {
    let hz = 100.0; // USER_HZ on Linux
    delta_ticks as f64 / hz / secs * 100.0
}

fn summarize(name: &str, samples: &[Sample]) {
    let mut v: Vec<f64> = samples.iter().map(|s| s.mbps).collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = v[v.len() / 2];
    let peak = v[v.len() - 1];
    let cpu = samples.iter().map(|s| s.cpu_pct).sum::<f64>() / samples.len() as f64;
    println!(
        "{name}: median {median:.1} MB/s, peak {peak:.1} MB/s, avg cpu {cpu:.0}% (runs: {})",
        samples
            .iter()
            .map(|s| format!("{:.1}", s.mbps))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let link = std::env::args().nth(1).expect("share-link");
    let target: SocketAddr = std::env::args().nth(2).expect("target-addr").parse()?;
    let runs = opt("runs", 5) as usize;
    let up_bytes = opt("up_mb", 256) * 1_000_000;

    let node = Node::from_share_link(&link)?;
    let registry = ProxyRegistry::default_resolver()?;
    let tcp = registry
        .find(node.protocol())
        .expect("handler for protocol")
        .tcp
        .clone();

    println!(
        "node: {} ({:?} {}:{})",
        node.name,
        node.protocol(),
        node.host,
        node.port
    );

    let mut downs = Vec::with_capacity(runs);
    let mut ups = Vec::with_capacity(runs);
    for i in 1..=runs {
        match bench_down(&tcp, &node, target).await {
            Ok(s) => {
                println!("down run {i}: {:.1} MB/s (cpu {:.0}%)", s.mbps, s.cpu_pct);
                downs.push(s);
            }
            Err(e) => println!("down run {i}: FAILED: {e:#}"),
        }
    }
    for i in 1..=runs {
        match bench_up(&tcp, &node, target, up_bytes).await {
            Ok(s) => {
                println!("up   run {i}: {:.1} MB/s (cpu {:.0}%)", s.mbps, s.cpu_pct);
                ups.push(s);
            }
            Err(e) => println!("up   run {i}: FAILED: {e:#}"),
        }
    }
    if !downs.is_empty() {
        summarize("DOWN summary", &downs);
    }
    if !ups.is_empty() {
        summarize("UP   summary", &ups);
    }
    Ok(())
}
