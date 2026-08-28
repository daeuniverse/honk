//! VLESS latency, throughput, and CPU benchmark against a reachable HTTP
//! target. The share link selects the mode; generation-owned modes reuse
//! their carrier across runs.
//!
//! Usage: vless_bench <share-link> <target-addr> [runs=5] [up_mb=256]
//!   share-link:  any VLESS link accepted by `Node::from_share_link`
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
    open_ms: f64,
    mbps: f64,
    cpu_pct: f64,
}

/// Download `Content-Length` bytes through the tunnel; returns MB/s and CPU%.
async fn bench_down(
    registry: &ProxyRegistry,
    generation: std::sync::Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    node_id: uuid::Uuid,
    target: SocketAddr,
) -> anyhow::Result<Sample> {
    let open = Instant::now();
    let mut s = registry
        .dial_runtime(generation, node_id, target, None, Duration::from_secs(10))
        .await?;
    let open_ms = open.elapsed().as_secs_f64() * 1000.0;
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
    let mut total = 0u64;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(30), s.stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => total += n as u64,
            Ok(Err(e)) => anyhow::bail!("read error: {e}"),
            Err(_) => anyhow::bail!("read timeout"),
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    let ticks1 = cpu_ticks();
    Ok(Sample {
        open_ms,
        mbps: total as f64 / 1e6 / secs,
        cpu_pct: cpu_pct(ticks1 - ticks0, secs),
    })
}

/// Upload `bytes` through the tunnel to POST /sink; returns MB/s and CPU%.
async fn bench_up(
    registry: &ProxyRegistry,
    generation: std::sync::Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    node_id: uuid::Uuid,
    target: SocketAddr,
    bytes: u64,
) -> anyhow::Result<Sample> {
    let open = Instant::now();
    let mut s = registry
        .dial_runtime(generation, node_id, target, None, Duration::from_secs(10))
        .await?;
    let open_ms = open.elapsed().as_secs_f64() * 1000.0;
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
        open_ms,
        mbps: sent as f64 / 1e6 / secs,
        cpu_pct: cpu_pct(ticks1 - ticks0, secs),
    })
}

fn cpu_pct(delta_ticks: u64, secs: f64) -> f64 {
    let hz = 100.0; // USER_HZ on Linux
    delta_ticks as f64 / hz / secs * 100.0
}

fn summarize(name: &str, samples: &[Sample]) {
    let mut throughput: Vec<f64> = samples.iter().map(|sample| sample.mbps).collect();
    throughput.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut opens: Vec<f64> = samples.iter().map(|sample| sample.open_ms).collect();
    opens.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = throughput[throughput.len() / 2];
    let peak = throughput[throughput.len() - 1];
    let open_p50 = opens[opens.len() / 2];
    let open_p95 = opens[(opens.len() * 95).div_ceil(100).saturating_sub(1)];
    let cpu = samples.iter().map(|sample| sample.cpu_pct).sum::<f64>() / samples.len() as f64;
    println!(
        "{name}: open p50/p95 {open_p50:.3}/{open_p95:.3} ms; median {median:.1} MB/s, peak {peak:.1} MB/s, avg cpu {cpu:.0}% (runs: {})",
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
    let generation = std::sync::Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(
        std::slice::from_ref(&node),
    )?);

    println!(
        "node: {} ({}:{}) flow={:?} reality={}",
        node.name,
        node.host,
        node.port,
        node.vless().and_then(|config| config.flow.as_ref()),
        node.tls()
            .is_some_and(|tls| tls.reality_public_key.is_some())
    );

    let mut downs = Vec::with_capacity(runs);
    let mut ups = Vec::with_capacity(runs);
    for i in 1..=runs {
        match bench_down(
            &registry,
            std::sync::Arc::clone(&generation),
            node.id,
            target,
        )
        .await
        {
            Ok(s) => {
                println!(
                    "down run {i}: open {:.3} ms, {:.1} MB/s (cpu {:.0}%)",
                    s.open_ms, s.mbps, s.cpu_pct
                );
                downs.push(s);
            }
            Err(e) => println!("down run {i}: FAILED: {e:#}"),
        }
    }
    for i in 1..=runs {
        match bench_up(
            &registry,
            std::sync::Arc::clone(&generation),
            node.id,
            target,
            up_bytes,
        )
        .await
        {
            Ok(s) => {
                println!(
                    "up   run {i}: open {:.3} ms, {:.1} MB/s (cpu {:.0}%)",
                    s.open_ms, s.mbps, s.cpu_pct
                );
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
    generation.shutdown().await;
    Ok(())
}
