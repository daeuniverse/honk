//! Idle pool for plain DNS-over-TCP (RFC 7766).

use std::sync::Arc;

use super::{DialContext, IdlePoolState, close_idle_pool, exchange_with_retry, idle_pool_exchange};
use parking_lot::Mutex;

/// Direct or proxied pooled TCP stream.
type PooledStream = Box<dyn crate::proxy::AsyncReadWrite>;

/// Idle-pool plain-TCP DNS client for one upstream.
pub struct TcpPool {
    dial: DialContext,
    lifecycle: tokio::sync::RwLock<IdlePoolState>,
    idle: Mutex<Vec<PooledStream>>,
}

impl TcpPool {
    pub fn new(dial: DialContext) -> Arc<Self> {
        Arc::new(Self {
            dial,
            lifecycle: tokio::sync::RwLock::new(IdlePoolState::Open),
            idle: Mutex::new(Vec::new()),
        })
    }

    pub async fn exchange(
        self: &Arc<Self>,
        raw_query: &[u8],
        feedback: Option<honk_outbound::group::ScoreBusinessGuard>,
    ) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "TCP DNS",
            raw_query,
            |reporter| async move { self.exchange_once(raw_query, reporter.as_ref()).await },
            |_| async {},
            feedback,
        )
        .await
    }

    async fn exchange_once(
        &self,
        raw_query: &[u8],
        reporter: Option<&honk_outbound::group::ScoreReporter>,
    ) -> anyhow::Result<Vec<u8>> {
        idle_pool_exchange(
            &self.lifecycle,
            &self.idle,
            || self.dial_new(),
            raw_query,
            self.dial.query_timeout,
            reporter,
        )
        .await
    }

    async fn dial_new(&self) -> anyhow::Result<PooledStream> {
        if self.dial.proxy.is_some() {
            self.dial.dial_tcp_boxed().await
        } else {
            Ok(Box::new(self.dial.dial_tcp().await?))
        }
    }

    pub(crate) async fn close(&self) {
        close_idle_pool(&self.lifecycle, &self.idle, self.dial.query_timeout).await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        DnsSocketBudget,
        framing::{read_length_prefixed, write_length_prefixed},
    };
    use super::*;
    use crate::dns::{endpoint::DnsEndpoint, forwarder::build_dns_query};
    use honk_config::types::DnsProtocol;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    async fn serve(listener: Arc<TcpListener>) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut response = read_length_prefixed(&mut stream, Duration::from_secs(2))
            .await
            .unwrap();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        write_length_prefixed(&mut stream, &response).await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn idle_tcp_credit_blocks_cold_transport_and_survives_creator_cancellation() {
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let first_server = tokio::spawn(serve(Arc::clone(&listener)));
        let budget = DnsSocketBudget::new(1);
        let dial = DialContext {
            endpoint: DnsEndpoint::parse(
                &listener.local_addr().unwrap().to_string(),
                DnsProtocol::Tcp,
                None,
            )
            .unwrap(),
            query_timeout: Duration::from_secs(2),
            dial_timeout: Duration::from_secs(2),
            socket_budget: budget.clone(),
            proxy: None,
        };
        let pool = TcpPool::new(dial.clone());
        let cold_pool = TcpPool::new(DialContext {
            dial_timeout: Duration::from_millis(200),
            ..dial
        });
        let query = build_dns_query("example.com", 1);
        let response = pool.exchange(&query, None).await.unwrap();
        assert!(super::super::is_valid_response(&query, &response));
        assert_eq!(
            budget.available_sockets(),
            0,
            "idle TCP released its credit"
        );

        let mut blocked = Box::pin(cold_pool.exchange(&query, None));
        tokio::select! {
            biased;
            result = &mut blocked => panic!("cold transport escaped admission: {result:?}"),
            _ = listener.accept() => panic!("cold transport created an unbudgeted socket"),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
        drop(blocked);
        assert_eq!(
            budget.available_sockets(),
            0,
            "cancellation stole the idle credit"
        );

        let error = tokio::select! {
            result = cold_pool.exchange(&query, None) => result.unwrap_err(),
            _ = listener.accept() => panic!("cold transport created a socket past admission"),
        };
        assert_eq!(
            honk_outbound::proxy::packet_rejection(&error),
            Some(honk_outbound::proxy::PacketRejection::Capacity)
        );
        assert_eq!(budget.available_sockets(), 0);

        pool.close().await;
        assert_eq!(
            budget.available_sockets(),
            1,
            "cancelled creator leaked a credit"
        );
        tokio::time::timeout(Duration::from_secs(2), first_server)
            .await
            .unwrap()
            .unwrap();

        let cold_server = tokio::spawn(serve(listener));
        let response = cold_pool.exchange(&query, None).await.unwrap();
        assert!(super::super::is_valid_response(&query, &response));
        assert_eq!(budget.available_sockets(), 0);
        cold_pool.close().await;
        assert_eq!(budget.available_sockets(), 1);
        tokio::time::timeout(Duration::from_secs(2), cold_server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn idle_proxy_stream_slot_blocks_cold_transport_until_pool_close() {
        use super::super::ProxyDial;

        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let address = listener.local_addr().unwrap();
        let first_server = tokio::spawn(serve(Arc::clone(&listener)));
        let node = honk_config::Config::builtin_direct_node();
        let generation = Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                .unwrap(),
        );
        let budget = DnsSocketBudget::new(1);
        let dial = DialContext {
            endpoint: DnsEndpoint::parse(&address.to_string(), DnsProtocol::Tcp, None).unwrap(),
            query_timeout: Duration::from_secs(2),
            dial_timeout: Duration::from_secs(2),
            socket_budget: budget.clone(),
            proxy: Some(ProxyDial {
                registry: Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
                generation: Some(generation),
                node,
            }),
        };
        let pool = TcpPool::new(dial.clone());
        let cold_pool = TcpPool::new(DialContext {
            dial_timeout: Duration::from_millis(200),
            ..dial
        });
        let query = build_dns_query("example.com", 1);
        let response = pool.exchange(&query, None).await.unwrap();
        assert!(super::super::is_valid_response(&query, &response));
        assert_eq!(budget.available_proxy_streams(), 0);
        assert_eq!(budget.available_sockets(), 1);

        let mut blocked = Box::pin(cold_pool.exchange(&query, None));
        tokio::select! {
            biased;
            result = &mut blocked => panic!("cold proxy escaped admission: {result:?}"),
            _ = listener.accept() => panic!("cold proxy created a socket without a stream slot"),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
        drop(blocked);
        assert_eq!(
            budget.available_proxy_streams(),
            0,
            "cancellation released the idle proxy's stream slot"
        );

        let error = tokio::select! {
            result = cold_pool.exchange(&query, None) => result.unwrap_err(),
            _ = listener.accept() => panic!("cold proxy created a socket past admission"),
        };
        assert_eq!(
            honk_outbound::proxy::packet_rejection(&error),
            Some(honk_outbound::proxy::PacketRejection::Capacity)
        );
        assert_eq!(budget.available_proxy_streams(), 0);

        pool.close().await;
        assert_eq!(budget.available_proxy_streams(), 1);
        tokio::time::timeout(Duration::from_secs(2), first_server)
            .await
            .unwrap()
            .unwrap();

        let cold_server = tokio::spawn(serve(listener));
        let response = cold_pool.exchange(&query, None).await.unwrap();
        assert!(super::super::is_valid_response(&query, &response));
        assert_eq!(budget.available_proxy_streams(), 0);
        cold_pool.close().await;
        assert_eq!(budget.available_proxy_streams(), 1);
        assert_eq!(budget.available_sockets(), 1);
        tokio::time::timeout(Duration::from_secs(2), cold_server)
            .await
            .unwrap()
            .unwrap();
    }
}
