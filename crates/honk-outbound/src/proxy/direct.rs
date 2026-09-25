//! Bypass handler that connects directly without a proxy.

use async_trait::async_trait;
use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use super::{
    PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound,
    UdpSocketTransport,
};

/// A direct rule's nonzero policy-routing mark; an unmarked direct flow uses the global mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DirectMark(std::num::NonZeroU32);

impl DirectMark {
    /// `None` for `0`, the configuration's "no mark" value.
    pub fn new(mark: u32) -> Option<Self> {
        std::num::NonZeroU32::new(mark).map(Self)
    }

    /// The configured low-30-bit policy value.
    pub fn get(self) -> u32 {
        self.0.get()
    }

    /// Socket/skb mark: the rule mark plus the datapath's final-classification flag.
    pub fn socket_mark(self) -> u32 {
        self.get() | honk_ebpf_common::CLASSIFIED_MARK
    }
}

#[derive(Default)]
pub struct DirectHandler;

impl DirectHandler {
    pub fn new() -> Self {
        Self
    }

    /// A routed mark replaces, rather than augments, the global bypass mark.
    pub(crate) async fn dial_marked(
        target: SocketAddr,
        mark: Option<DirectMark>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        debug!("Direct dial to {}", target);
        let mark = mark.map_or_else(crate::util::bypass_mark, DirectMark::socket_mark);
        let stream = crate::runtime::admit_physical_dial(crate::util::connect_marked_addr(
            target,
            Some(mark),
            connect_timeout,
        ))
        .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: None,
        })
    }

    /// Create an unpooled direct UDP flow with its mark set before the first send.
    pub(crate) fn dial_udp_marked(
        target: SocketAddr,
        mark: Option<DirectMark>,
    ) -> anyhow::Result<Arc<UdpSocketTransport>> {
        debug!("Direct UDP to {}", target);
        let bind_addr = SocketAddr::new(
            if target.is_ipv4() {
                std::net::Ipv4Addr::UNSPECIFIED.into()
            } else {
                std::net::Ipv6Addr::UNSPECIFIED.into()
            },
            0,
        );
        let mark = mark.map_or_else(crate::util::bypass_mark, DirectMark::socket_mark);
        let socket = tokio::net::UdpSocket::from_std(crate::util::marked_udp_socket_with_mark(
            bind_addr, mark,
        )?)?;
        Ok(Arc::new(UdpSocketTransport::new(Arc::new(socket), target)))
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
        Self::dial_marked(target, None, connect_timeout).await
    }

    async fn dial_runtime_marked(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        _target_domain: Option<&str>,
        connect_timeout: Duration,
        mark: DirectMark,
    ) -> anyhow::Result<ProxyStream> {
        Self::dial_marked(target, Some(mark), connect_timeout).await
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
        Ok(Self::dial_udp_marked(target, None)?)
    }

    async fn dial_udp_transport_runtime_marked(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
        mark: DirectMark,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Ok(Self::dial_udp_marked(target, Some(mark))?)
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
