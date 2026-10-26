//! In-process WireGuard peer tests: each test owns a random key pair, and tests that share a
//! tunnel registry (a plane's generations) build it explicitly, so nothing couples them.

use std::sync::Arc;
use std::time::Duration;

use honk_config::node::Node;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::proxy::{ProxyRegistry, ProxyStream};
use crate::runtime::OutboundRuntimeRegistry;

mod lifecycle;
mod peer;
mod tcp;
mod udp;

use peer::{ECHO, Fixture, PEER_IP, endpoint};

const TIMEOUT: Duration = Duration::from_secs(10);

fn proxies() -> ProxyRegistry {
    ProxyRegistry::default_resolver().unwrap()
}

fn generation(node: &Node) -> Arc<OutboundRuntimeRegistry> {
    Arc::new(OutboundRuntimeRegistry::build(std::slice::from_ref(node)).unwrap())
}

/// The reload successor of `previous`: it inherits the plane's tunnel registry, as production does.
fn successor(previous: &OutboundRuntimeRegistry, node: &Node) -> Arc<OutboundRuntimeRegistry> {
    let (next, _) = OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        std::slice::from_ref(node),
        8,
        8,
        8,
        false,
        Some(previous),
    )
    .unwrap();
    Arc::new(next)
}

async fn dial(
    generation: &Arc<OutboundRuntimeRegistry>,
    node: &Node,
    port: u16,
) -> anyhow::Result<ProxyStream> {
    proxies()
        .dial_runtime(
            Arc::clone(generation),
            node.id,
            endpoint(PEER_IP, port),
            None,
            TIMEOUT,
        )
        .await
}

async fn echo_roundtrip(stream: &mut ProxyStream, payload: &[u8]) {
    stream.stream.write_all(payload).await.unwrap();
    let mut back = vec![0; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.stream.read_exact(&mut back))
        .await
        .expect("echo reply")
        .unwrap();
    assert_eq!(back, payload);
}

#[tokio::test]
async fn tcp_echo_over_a_runtime_dial() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let mut stream = dial(&generation, &fixture.node, ECHO).await.unwrap();
    assert_eq!(stream.target_addr, endpoint(PEER_IP, ECHO));
    echo_roundtrip(&mut stream, b"hello through wireguard").await;
}
