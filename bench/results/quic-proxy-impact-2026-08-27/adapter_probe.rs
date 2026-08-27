use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use honk_config::node::Node;
use honk_outbound::proxy::ProxyRegistry;
use honk_outbound::runtime::OutboundRuntimeRegistry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let node_file = std::env::args().nth(1).expect("node file");
    let target: SocketAddr = std::env::args().nth(2).expect("target").parse()?;
    let samples: usize = std::env::args()
        .nth(3)
        .map_or(Ok(50), |value| value.parse())?;
    let link = std::fs::read_to_string(node_file)?;
    let node = Node::from_share_link(link.trim())?;
    let registry = ProxyRegistry::default_resolver()?;
    let packet = registry
        .find(node.protocol)
        .and_then(|entry| entry.packet.as_ref())
        .ok_or_else(|| anyhow::anyhow!("protocol has no packet handler"))?;
    let runtimes = OutboundRuntimeRegistry::build(std::slice::from_ref(&node))?;
    let runtime = runtimes
        .get(&node.id)
        .ok_or_else(|| anyhow::anyhow!("node runtime missing"))?;
    let timeout = Duration::from_secs(5);
    let config = honk_outbound::quic::client_config(
        &Node {
            sni: Some("inner.test".into()),
            skip_cert_verify: true,
            ..Default::default()
        },
        &[b"h3"],
        Default::default(),
    )
    .await?;

    for round in 0..samples + 5 {
        let transport = packet
            .dial_udp_transport_runtime(Arc::clone(&runtime), target, None, timeout)
            .await?;
        let started = Instant::now();
        let elapsed = honk_outbound::quic::quic_handshake_probe(
            transport,
            target,
            "inner.test",
            &config,
            timeout,
        )
        .await?;
        let total = started.elapsed();
        if round >= 5 {
            println!("{}\t{}", elapsed.as_nanos(), total.as_nanos());
        }
    }
    Ok(())
}
