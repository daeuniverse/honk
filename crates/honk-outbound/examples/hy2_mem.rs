//! hy2 内存分析驱动:N 路并发流,每路模拟慢消费(读 16KiB 后 sleep),
//! 每秒打印 VmRSS 与累计字节。停流后继续采样 RSS 观察回落。
//!
//! Usage: hy2_mem <share-link> <target> [streams=8] [throttle_ms=10] [duration=60]
//!        [stream_win_mib=N] [conn_win_mib=N] [up_mbps=N]
//!   target 由服务端拨出(如 127.0.0.1:18080 指向服务端本机大文件 HTTP)。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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

fn vmrss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let link = std::env::args().nth(1).expect("share-link");
    let target: SocketAddr = std::env::args().nth(2).expect("target").parse()?;
    let streams = opt("streams", 8) as usize;
    let throttle = Duration::from_millis(opt("throttle_ms", 10));
    let duration = Duration::from_secs(opt("duration", 60));

    let mut node = Node::from_share_link(&link)?;
    let sw = opt("stream_win_mib", 0);
    let cw = opt("conn_win_mib", 0);
    let hy2 = node
        .hysteria2_mut()
        .ok_or_else(|| anyhow::anyhow!("share link is not Hysteria2"))?;
    if sw > 0 {
        hy2.init_stream_recv_window = Some(sw << 20);
    }
    if cw > 0 {
        hy2.init_conn_recv_window = Some(cw << 20);
    }
    let up = opt("up_mbps", 0);
    if up > 0 {
        hy2.up_mbps = Some(up as u32);
    }
    node.id = node.derive_id();
    // nodes=K:克隆 K 个节点,用不同 SNI 派生不同 Node.id,
    // 从而拿到 K 条独立 QUIC 连接(验证 conn window × 连接数 模型)。
    let n_nodes = opt("nodes", 1) as usize;
    let mut nodes = vec![node];
    for i in 1..n_nodes {
        let mut c = nodes[0].clone();
        c.name = format!("memtest-{i}");
        c.tls_mut().unwrap().sni = Some(format!("hy2-memtest-{i}"));
        c.id = c.derive_id();
        nodes.push(c);
    }
    let generation = Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(
        &nodes,
    )?);
    let registry = Arc::new(ProxyRegistry::default_resolver()?);

    let total_bytes = Arc::new(AtomicU64::new(0));
    let t0 = Instant::now();
    let mut tasks = Vec::with_capacity(streams);
    for i in 0..streams {
        let node_id = nodes[i % n_nodes].id;
        let generation = Arc::clone(&generation);
        let registry = Arc::clone(&registry);
        let total = Arc::clone(&total_bytes);
        tasks.push(tokio::spawn(async move {
            let mut s = match registry
                .dial_runtime(generation, node_id, target, None, Duration::from_secs(15))
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("stream {i}: dial failed: {e}");
                    return;
                }
            };
            if let Err(e) = s
                .stream
                .write_all(b"GET /bigfile.bin HTTP/1.1\r\nHost: mem\r\n\r\n")
                .await
            {
                eprintln!("stream {i}: write failed: {e}");
                return;
            }
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match s.stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        total.fetch_add(n as u64, Ordering::Relaxed);
                        tokio::time::sleep(throttle).await;
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    // 每秒采样:elapsed, VmRSS MiB, 累计 MB
    let total = Arc::clone(&total_bytes);
    let monitor = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            println!(
                "t={:>4}s rss={:>6} MiB bytes={:>6} MB",
                t0.elapsed().as_secs(),
                vmrss_kib() / 1024,
                total.load(Ordering::Relaxed) >> 20
            );
        }
    });

    tokio::time::sleep(duration).await;
    for t in &tasks {
        t.abort();
    }
    let decay = opt("decay", 1) != 0;
    if decay {
        println!("--- stopped, decay sampling ---");
        for wait in [0u64, 10, 60, 300] {
            if wait > 0 {
                tokio::time::sleep(Duration::from_secs(wait)).await;
            }
            println!("post-stop +{wait:>3}s rss={} MiB", vmrss_kib() / 1024);
        }
    }
    monitor.abort();
    Ok(())
}
