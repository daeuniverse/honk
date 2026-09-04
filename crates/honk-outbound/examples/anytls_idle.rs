//! Idle-corpse probe for AnyTLS warm sessions: hold a pooled session idle
//! past the server's idle-kill window (~30s), then check whether the next
//! stream stalls (silent kill) or works (keepalive prevented the kill, or a
//! clean FIN let the pool redial).

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn probe(
    registry: &honk_outbound::proxy::ProxyRegistry,
    generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    node_id: uuid::Uuid,
    tag: &str,
) {
    let start = Instant::now();
    let target = "1.1.1.1:80".parse().unwrap();
    match registry
        .dial_runtime(
            Arc::clone(generation),
            node_id,
            target,
            None,
            Duration::from_secs(5),
        )
        .await
    {
        Err(e) => println!("{tag}: dial error: {e}"),
        Ok(mut s) => {
            let dial_ms = start.elapsed().as_millis();
            let _ = s.stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
            let mut buf = [0u8; 64];
            match tokio::time::timeout(Duration::from_secs(5), s.stream.read(&mut buf)).await {
                Ok(Ok(n)) => println!(
                    "{tag}: ok dial={}ms total={}ms n={n}",
                    dial_ms,
                    start.elapsed().as_millis()
                ),
                Ok(Err(e)) => println!("{tag}: stream error dial={dial_ms}ms: {e}"),
                Err(_) => println!("{tag}: STALL dial={dial_ms}ms (stream read timed out)"),
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let link = std::env::args().nth(1).expect("share link argument");
    let pause_secs: u64 = std::env::args()
        .nth(2)
        .map(|s| s.parse().unwrap())
        .unwrap_or(45);
    let rounds: u64 = std::env::args()
        .nth(3)
        .map(|s| s.parse().unwrap())
        .unwrap_or(1);
    let node = honk_config::node::Node::from_share_link(&link).expect("parse share link");
    let registry = honk_outbound::proxy::ProxyRegistry::default_resolver()?;
    let generation = Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(
        std::slice::from_ref(&node),
    )?);

    probe(&registry, &generation, node.id, "t+00s").await;
    for round in 1..=rounds {
        tokio::time::sleep(Duration::from_secs(pause_secs)).await;
        probe(
            &registry,
            &generation,
            node.id,
            &format!("round{round} after {pause_secs}s idle"),
        )
        .await;
        probe(
            &registry,
            &generation,
            node.id,
            &format!("round{round} immediate"),
        )
        .await;
    }
    Ok(())
}
