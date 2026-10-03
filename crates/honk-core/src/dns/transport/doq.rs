//! DNS over QUIC (RFC 9250).
//!
//! One long-lived QUIC connection (ALPN `doq`); each query opens a
//! bidirectional stream, writes a length-prefixed message with ID=0,
//! finishes the send side, and reads the length-prefixed response.

use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Connection};

use super::framing::{
    force_dns_id_zero, read_length_prefixed, restore_dns_id, write_length_prefixed,
};
use super::lifecycle::{LifecycleSlot, SessionFailure, SessionObservation};
use super::quic::with_packet_cause;
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

impl DoqConnection {
    async fn close(self: Arc<Self>, timeout: Duration) {
        self.connection.close(0_u32.into(), b"shutdown");
        let _ = tokio::time::timeout(timeout, self.connection.closed()).await;
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(timeout).await;
        }
    }
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
        feedback: Option<honk_outbound::group::ScoreBusinessGuard>,
    ) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoQ",
            raw_query,
            |reporter| async move { self.exchange_once(raw_query, reporter.as_ref()).await },
            |error| {
                let connection = SessionFailure::<DoqConnection>::session(error);
                async move {
                    if let Some(connection) = connection {
                        self.retire_connection(&connection).await;
                    }
                }
            },
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
        let io_error = |error| with_packet_cause(conn.endpoint.as_ref(), error);
        tokio::time::timeout(self.dial.query_timeout, async {
            let (mut send, mut recv) = conn.connection.open_bi().await.map_err(|error| {
                with_packet_cause(conn.endpoint.as_ref(), error.into()).context("DoQ open_bi")
            })?;

            let mut wire = raw_query.to_vec();
            let orig_id = force_dns_id_zero(&mut wire);
            write_length_prefixed(&mut send, &wire)
                .await
                .map_err(io_error)?;
            send.finish().map_err(|error| {
                with_packet_cause(conn.endpoint.as_ref(), error.into()).context("DoQ finish send")
            })?;
            if let Some(reporter) = reporter {
                reporter.tx(raw_query.len() as u64);
            }

            let mut resp = read_length_prefixed(&mut recv, self.dial.query_timeout)
                .await
                .map_err(io_error)?;
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
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "DoQ exchange timed out after {:?}",
                self.dial.query_timeout
            ))
        })
        .map_err(|error| SessionFailure::new(conn, error).into())
    }

    async fn get_conn(&self) -> anyhow::Result<Arc<DoqConnection>> {
        let observation = SessionObservation::start();
        let result = async {
            let (connection, reused) = self.connection.acquire(|| self.dial()).await?;
            if connection.connection.close_reason().is_some() {
                observation.record(
                    honk_outbound::runtime::flow_observation::SessionEvent::DnsSessionReadyFailed,
                );
                observation.record(
                    honk_outbound::runtime::flow_observation::SessionEvent::DnsSessionRetryStarted,
                );
                self.retire_connection(&connection).await;
                let (connection, reused) = self.connection.acquire(|| self.dial()).await?;
                if reused {
                    super::lifecycle::attached();
                }
                return Ok(connection);
            }
            if reused {
                super::lifecycle::attached();
            }
            Ok(connection)
        }
        .await;
        observation.finish(
            result,
            honk_outbound::runtime::flow_observation::SessionEvent::DnsSessionAcquired,
        )
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

    async fn retire_connection(&self, connection: &Arc<DoqConnection>) {
        let timeout = self.dial.query_timeout;
        self.connection
            .retire(connection, move |connection| connection.close(timeout))
            .await;
    }

    pub(crate) fn tasks_failed(&self) -> bool {
        self.quic_ep.tasks_failed()
    }

    pub(crate) async fn close(&self) {
        let timeout = self.dial.query_timeout;
        self.connection
            .close(move |connection| connection.close(timeout))
            .await;
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
        #[cfg(feature = "native-api")]
        let store = {
            use crate::native_api::events::EventHub;
            use crate::observe::flows::FlowStore;
            let instance = uuid::Uuid::new_v4().to_string();
            Arc::new(FlowStore::new(
                instance.clone(),
                Arc::new(EventHub::new(instance)),
            ))
        };
        for (index, name) in ["cold.example", "warm.example"].into_iter().enumerate() {
            let query = build_dns_query(name, 1);
            #[cfg(feature = "native-api")]
            let flow = Arc::new(
                store
                    .begin(
                        crate::observe::vocab::Network::Udp,
                        "127.0.0.1:31000".parse().unwrap(),
                        address,
                    )
                    .unwrap(),
            );
            #[cfg(feature = "native-api")]
            let observer = flow.observer(13, None, "intercepted_query").unwrap();
            let exchange = client.exchange(&query, None);
            #[cfg(feature = "native-api")]
            let exchange = observer.scope(exchange);
            let response = exchange.await.unwrap();
            assert!(super::super::is_valid_response(&query, &response));
            assert_eq!(&response[..2], &query[..2]);
            #[cfg(feature = "native-api")]
            {
                let view = store.test_detail(flow.id());
                assert_eq!(view["trace"]["status"], "complete", "{view:#}");
                let steps = view["trace"]["steps"].as_array().unwrap();
                let lookup = steps
                    .iter()
                    .find(|step| step["stage"] == "dns" && step["data"]["status"] == "succeeded")
                    .unwrap();
                let physical: Vec<_> = steps
                    .iter()
                    .filter(|step| {
                        step["stage"] == "outbound" && step["data"]["kind"] == "transport"
                    })
                    .collect();
                assert_eq!(physical.len(), if index == 0 { 2 } else { 0 }, "{view:#}");
                let attached: Vec<_> = steps
                    .iter()
                    .filter(|step| step["data"]["reason"] == "dns_transport_attached")
                    .collect();
                assert_eq!(attached.len(), index, "{view:#}");
                if index == 1 {
                    assert_eq!(
                        attached[0]["data"]["lookup_id"],
                        lookup["data"]["lookup_id"]
                    );
                    assert_eq!(
                        attached[0]["data"]["attempt_id"],
                        lookup["data"]["attempt_id"]
                    );
                    assert_eq!(attached[0]["generation_id"], lookup["generation_id"]);
                }
                assert!(
                    !steps
                        .iter()
                        .any(|step| step["data"]["reason"] == "target_confirmed"
                            || step["data"]["reason"] == "dns_session_retry_started"
                            || step["data"]["milestone"] == "first_reply")
                );
            }
            #[cfg(not(feature = "native-api"))]
            let _ = index;
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
