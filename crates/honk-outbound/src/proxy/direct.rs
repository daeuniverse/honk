//! Bypass handler that connects directly without a proxy.

use async_trait::async_trait;
use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

use super::{
    PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound,
    UdpSocketTransport,
};

pub struct DirectHandler;

impl Default for DirectHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TcpOutbound for DirectHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        debug!("Direct dial to {}", target);
        let stream = crate::runtime::admit_physical_dial(crate::util::connect_marked_addr(
            target,
            Some(honk_ebpf_common::DAE_BYPASS_MARK),
            connect_timeout,
        ))
        .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: None,
        })
    }

    async fn dial_with_tcp(
        &self,
        _node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        tcp: TcpStream,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        debug!("Direct dial (pooled) to {}", target);
        Ok(ProxyStream {
            stream: Box::new(tcp),
            target_addr: target,
            target_domain: None,
        })
    }
}

#[async_trait]
impl PacketOutbound for DirectHandler {
    async fn dial_udp_transport(
        &self,
        _node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        debug!("Direct UDP to {}", target);
        // Bind to the correct address family so the source address matches.
        let bind_addr: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().expect("hardcoded IPv4 bind address")
        } else {
            "[::]:0".parse().expect("hardcoded IPv6 bind address")
        };
        let socket = crate::util::udp_marked_bind(bind_addr).await?;
        Ok(Arc::new(UdpSocketTransport::new(Arc::new(socket), target)))
    }
}

#[async_trait]
impl ProbeableOutbound for DirectHandler {
    async fn test_connectivity(&self, _node: &Node) -> bool {
        // Direct always "works" - connectivity depends on the actual target
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_direct_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                stream.write_all(b"hello").await.ok();
            }
        });

        let handler = DirectHandler::new();
        let node = Node::default();
        let target: SocketAddr = addr;

        let result = handler
            .dial(&node, target, None, Duration::from_secs(3))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn direct_connect_respects_one_physical_dial_permit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                listener.accept().await.unwrap();
            }
        });
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build_reusing(&[], 1, None)
                .unwrap()
                .0,
        );
        let ready = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let first = tokio::spawn({
            let generation = Arc::clone(&generation);
            let ready = Arc::clone(&ready);
            let release = Arc::clone(&release);
            async move {
                generation
                    .scope_dials(async {
                        let _stream = DirectHandler::new()
                            .dial(&Node::default(), addr, None, Duration::from_secs(1))
                            .await
                            .unwrap();
                        ready.notify_one();
                        release.notified().await;
                    })
                    .await;
            }
        });
        ready.notified().await;

        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                generation.scope_dials(DirectHandler::new().dial(
                    &Node::default(),
                    addr,
                    None,
                    Duration::from_secs(1),
                )),
            )
            .await
            .is_err()
        );

        release.notify_one();
        first.await.unwrap();
        generation
            .scope_dials(DirectHandler::new().dial(
                &Node::default(),
                addr,
                None,
                Duration::from_secs(1),
            ))
            .await
            .unwrap();
        server.await.unwrap();
    }
}
