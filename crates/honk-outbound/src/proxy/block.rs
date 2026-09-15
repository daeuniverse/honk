//! Block connection handler.
//!
//! Immediately rejects connections, used for traffic that should be blocked
//! (ads, trackers, malware domains, etc.).

use async_trait::async_trait;
use honk_config::node::Node;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::warn;

use super::{PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound};
use std::sync::Arc;

/// Handler for blocking connections.
#[derive(Default)]
pub struct BlockHandler;

impl BlockHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TcpOutbound for BlockHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        warn!("Blocked connection to {}", target);
        anyhow::bail!("Connection blocked by routing rule");
    }
}

#[async_trait]
impl PacketOutbound for BlockHandler {
    async fn dial_udp_transport(
        &self,
        _node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        warn!("Blocked UDP connection to {}", target);
        anyhow::bail!("UDP connection blocked by routing rule");
    }
}

#[async_trait]
impl ProbeableOutbound for BlockHandler {
    async fn test_connectivity(&self, _node: &Node) -> bool {
        false // Block handler is never "reachable"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_block_rejects() {
        let handler = BlockHandler::new();
        let node = Node::default();
        let target: SocketAddr = "10.0.0.1:80".parse().unwrap();

        let result = handler
            .dial(&node, target, None, Duration::from_secs(3))
            .await;
        assert!(result.is_err());
    }
}
