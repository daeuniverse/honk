//! DNS over QUIC (RFC 9250).
//!
//! One long-lived QUIC connection (ALPN `doq`); each query opens a
//! bidirectional stream, writes a length-prefixed message with ID=0,
//! finishes the send side, and reads the length-prefixed response.

use std::sync::Arc;

use quinn::{ClientConfig, Connection};

use super::framing::{
    force_dns_id_zero, read_length_prefixed, restore_dns_id, write_length_prefixed,
};
use super::lifecycle::LifecycleSlot;
use super::{
    DialContext, SharedQuicEndpoint, dns_quic_config, exchange_with_retry, quic_connect_endpoint,
};

/// One physical DoQ connection. Proxied connections retain their packet-backed
/// endpoint here until the pooled connection is explicitly closed.
struct DoqConnection {
    connection: Connection,
    endpoint: Option<honk_outbound::quic::PacketTransportEndpoint>,
    _metrics: honk_outbound::quic::QuicConnectionMonitor,
}

/// DoQ client for one upstream.
pub struct DoqClient {
    dial: DialContext,
    quic_config: ClientConfig,
    quic_ep: SharedQuicEndpoint,
    connection: LifecycleSlot<DoqConnection>,
}

impl DoqClient {
    pub async fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        let quic_config = dns_quic_config(&[b"doq"]).await?;
        Ok(Arc::new(Self {
            dial,
            quic_config,
            quic_ep: SharedQuicEndpoint::new(),
            connection: LifecycleSlot::new(),
        }))
    }

    pub async fn exchange(
        self: &Arc<Self>,
        raw_query: &[u8],
        feedback: Option<&honk_outbound::group::ScoreFeedback>,
    ) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoQ",
            raw_query,
            |reporter| async move { self.exchange_once(raw_query, reporter.as_ref()).await },
            || async { self.close_connection().await },
            feedback,
        )
        .await
    }

    async fn exchange_once(
        &self,
        raw_query: &[u8],
        reporter: Option<&honk_outbound::group::ScoreReporter>,
    ) -> anyhow::Result<Vec<u8>> {
        let conn = self.get_conn().await?;
        if let Some(reporter) = reporter {
            reporter.setup_succeeded();
        }
        tokio::time::timeout(self.dial.query_timeout, async {
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| anyhow::anyhow!("DoQ open_bi: {e}"))?;

            let mut wire = raw_query.to_vec();
            let orig_id = force_dns_id_zero(&mut wire);
            write_length_prefixed(&mut send, &wire).await?;
            send.finish()
                .map_err(|e| anyhow::anyhow!("DoQ finish send: {e}"))?;
            if let Some(reporter) = reporter {
                reporter.tx(raw_query.len() as u64);
            }

            let mut resp = read_length_prefixed(&mut recv, self.dial.query_timeout).await?;
            if let Some(reporter) = reporter
                && super::is_valid_response(raw_query, &resp)
            {
                reporter.first_response();
                reporter.rx(resp.len() as u64);
            }
            restore_dns_id(&mut resp, orig_id);
            Ok::<_, anyhow::Error>(resp)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("DoQ exchange timed out after {:?}", self.dial.query_timeout)
        })?
    }

    async fn get_conn(&self) -> anyhow::Result<Connection> {
        let connection = self.connection.acquire(|| self.dial()).await?;
        if connection.connection.close_reason().is_some() {
            self.close_connection().await;
            return self
                .connection
                .acquire(|| self.dial())
                .await
                .map(|c| c.connection.clone());
        }
        Ok(connection.connection.clone())
    }
    async fn dial(&self) -> anyhow::Result<DoqConnection> {
        let (connection, endpoint) = quic_connect_endpoint(
            &self.dial,
            &self.quic_ep,
            &self.quic_config,
            &self.dial.endpoint,
            tokio::time::Instant::now() + self.dial.dial_timeout,
            "DoQ",
        )
        .await?;
        let metrics = honk_outbound::quic::monitor_quic_connection(&connection);
        Ok(DoqConnection {
            connection,
            endpoint,
            _metrics: metrics,
        })
    }

    async fn close_connection(&self) {
        let timeout = self.dial.query_timeout;
        self.connection
            .close(|connection| async move {
                connection.connection.close(0_u32.into(), b"shutdown");
                let _ = tokio::time::timeout(timeout, connection.connection.closed()).await;
                if let Some(endpoint) = &connection.endpoint {
                    endpoint.close(timeout).await;
                }
            })
            .await;
    }

    pub(crate) async fn close(&self) {
        self.close_connection().await;
        self.quic_ep.close(self.dial.query_timeout).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::types::DnsProtocol;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use crate::dns::forwarder::build_dns_query;
    use crate::dns::transport::tests_proto::{
        ProxiedQuicFixture, insecure_quic_config, proxied_quic_fixture, spawn_doq_server,
    };

    #[tokio::test]
    async fn constructor_keeps_query_and_dial_timeouts_distinct() {
        let dial = DialContext {
            endpoint: crate::dns::endpoint::DnsEndpoint::parse(
                "127.0.0.1",
                DnsProtocol::Quic,
                Some("localhost"),
            )
            .expect("DoQ endpoint"),
            query_timeout: Duration::from_millis(111),
            dial_timeout: Duration::from_millis(222),
            proxy: None,
        };
        let client = DoqClient::new(dial).await.expect("DoQ client");

        assert_eq!(client.dial.query_timeout, Duration::from_millis(111));
        assert_eq!(client.dial.dial_timeout, Duration::from_millis(222));
    }

    #[tokio::test]
    async fn proxied_doq_reuses_and_closes_packet_endpoint() {
        let (address, server) = spawn_doq_server();
        let endpoint = crate::dns::endpoint::DnsEndpoint::parse(
            &format!("127.0.0.1:{}", address.port()),
            DnsProtocol::Quic,
            Some("localhost"),
        )
        .unwrap();
        let ProxiedQuicFixture {
            dial,
            active,
            runtime_dials,
        } = proxied_quic_fixture(endpoint);
        let client = Arc::new(DoqClient {
            dial,
            quic_config: insecure_quic_config(b"doq").await,
            quic_ep: SharedQuicEndpoint::new(),
            connection: LifecycleSlot::new(),
        });
        let query = build_dns_query("example.com", 1);

        for _ in 0..2 {
            let response = client.exchange(&query, None).await.unwrap();
            assert_eq!(&response[..2], &query[..2]);
        }
        assert_eq!(runtime_dials.load(Ordering::SeqCst), 1);
        assert_eq!(active.load(Ordering::SeqCst), 1);

        client.close().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
