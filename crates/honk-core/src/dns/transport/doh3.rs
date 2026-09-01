//! DNS over HTTP/3 (DoH3).
//!
//! One long-lived QUIC connection with ALPN `h3`, carrying POST requests of
//! `application/dns-message` to the configured path (default `/dns-query`).

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use h3_quinn::Connection as H3QuinnConnection;
use quinn::ClientConfig;
use tokio::sync::Mutex;
use tracing::debug;

use super::DialContext;
use super::framing::force_dns_id_zero;
use super::lifecycle::LifecycleSlot;
use super::owned_task::OwnedTask;
use super::{
    DnsMessageBody, SharedQuicEndpoint, build_doh_request, dns_quic_config, doh_content_length,
    exchange_with_retry, finish_doh_response, quic_connect_endpoint,
};

type H3Sender = SendRequest<h3_quinn::OpenStreams, Bytes>;

struct H3Session {
    sender: Mutex<Option<H3Sender>>,
    connection: quinn::Connection,
    endpoint: Option<honk_outbound::quic::PacketTransportEndpoint>,
    _metrics: honk_outbound::quic::QuicConnectionMonitor,
    driver: OwnedTask,
}
async fn close_failed_connection(
    connection: &quinn::Connection,
    endpoint: &Option<honk_outbound::quic::PacketTransportEndpoint>,
) {
    connection.close(0_u32.into(), b"DoH3 setup failed");
    if let Some(endpoint) = endpoint {
        endpoint.close(Duration::ZERO).await;
    }
}

/// DoH3 client for one upstream.
pub struct Doh3Client {
    dial: DialContext,
    quic_config: ClientConfig,
    quic_ep: SharedQuicEndpoint,
    session: LifecycleSlot<H3Session>,
    active_tasks: Arc<AtomicUsize>,
}

impl Doh3Client {
    pub async fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        Self::new_tracked(dial, Arc::new(AtomicUsize::new(0))).await
    }

    pub(crate) async fn new_tracked(
        dial: DialContext,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        let quic_config = dns_quic_config(&[b"h3"]).await?;
        Ok(Arc::new(Self {
            dial,
            quic_config,
            quic_ep: SharedQuicEndpoint::new(),
            session: LifecycleSlot::new(),
            active_tasks,
        }))
    }

    pub async fn exchange(
        self: &Arc<Self>,
        raw_query: &[u8],
        feedback: Option<&honk_outbound::group::ScoreFeedback>,
    ) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoH3",
            raw_query,
            |reporter| async move { self.exchange_once(raw_query, reporter.as_ref()).await },
            || async { self.close_session().await },
            feedback,
        )
        .await
    }

    async fn exchange_once(
        &self,
        raw_query: &[u8],
        reporter: Option<&honk_outbound::group::ScoreReporter>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut sender = self.get_sender().await?;
        if let Some(reporter) = reporter {
            reporter.setup_succeeded();
        }

        tokio::time::timeout(self.dial.query_timeout, async {
            let mut wire = raw_query.to_vec();
            let orig_id = force_dns_id_zero(&mut wire);

            let req = build_doh_request(&self.dial.endpoint, None, "DoH3")?;

            let mut stream = sender
                .send_request(req)
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 send_request: {e}"))?;

            stream
                .send_data(Bytes::from(wire))
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 send_data: {e}"))?;
            stream
                .finish()
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 finish: {e}"))?;
            if let Some(reporter) = reporter {
                reporter.tx(raw_query.len() as u64);
            }

            let response = stream
                .recv_response()
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 recv_response: {e}"))?;

            let status = response.status();
            let content_length = doh_content_length("DoH3", response.headers())?;
            let mut buf = DnsMessageBody::new("DoH3", content_length)?;
            while let Some(mut bytes) = stream
                .recv_data()
                .await
                .map_err(|e| anyhow::anyhow!("DoH3 recv_data: {e}"))?
            {
                while bytes.has_remaining() {
                    let chunk = bytes.chunk();
                    let len = chunk.len();
                    buf.push(chunk)?;
                    bytes.advance(len);
                }
            }

            let response = finish_doh_response("DoH3", status, buf.into_bytes(), orig_id)?;
            if let Some(reporter) = reporter
                && super::is_valid_response(raw_query, &response)
            {
                reporter.first_response();
                reporter.rx(response.len() as u64);
            }
            Ok::<_, anyhow::Error>(response)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "DoH3 exchange timed out after {:?}",
                self.dial.query_timeout
            )
        })?
    }

    async fn get_sender(&self) -> anyhow::Result<H3Sender> {
        let session = self.session.acquire(|| self.handshake()).await?;
        session
            .sender
            .lock()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("DoH3 session is closing"))
    }

    async fn handshake(&self) -> anyhow::Result<H3Session> {
        let deadline = tokio::time::Instant::now() + self.dial.dial_timeout;
        let (conn, endpoint) = quic_connect_endpoint(
            &self.dial,
            &self.quic_ep,
            &self.quic_config,
            &self.dial.endpoint,
            deadline,
            "DoH3 QUIC",
        )
        .await?;
        let quinn_conn = H3QuinnConnection::new(conn.clone());
        let h3 = tokio::time::timeout_at(deadline, h3::client::new(quinn_conn)).await;
        let (mut driver, sender) = match h3 {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                close_failed_connection(&conn, &endpoint).await;
                return Err(anyhow::anyhow!("DoH3 h3::client::new: {error}"));
            }
            Err(_) => {
                close_failed_connection(&conn, &endpoint).await;
                return Err(anyhow::anyhow!(
                    "DoH3 dial timed out after {:?}",
                    self.dial.dial_timeout
                ));
            }
        };

        let driver = OwnedTask::spawn(
            async move {
                let error = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
                debug!(
                    error = %error,
                    transport = "doh3",
                    "dns transport driver stopped"
                );
            },
            Arc::clone(&self.active_tasks),
        );
        Ok(H3Session {
            sender: Mutex::new(Some(sender)),
            connection: conn.clone(),
            endpoint,
            _metrics: honk_outbound::quic::monitor_quic_connection(&conn),
            driver,
        })
    }

    async fn close_session(&self) {
        let timeout = self.dial.query_timeout;
        self.session
            .close(|session| async move {
                session.sender.lock().await.take();
                session.connection.close(0_u32.into(), b"shutdown");
                session.driver.shutdown(timeout).await;
                if let Some(endpoint) = &session.endpoint {
                    endpoint.close(timeout).await;
                }
            })
            .await;
    }

    pub(crate) async fn close(&self) {
        self.close_session().await;
        self.quic_ep.close(self.dial.query_timeout).await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DnsMessageBody, DnsMessageTooLarge, MAX_DNS_MESSAGE_SIZE};
    use super::{DialContext, Doh3Client, LifecycleSlot, SharedQuicEndpoint};
    use honk_config::types::DnsProtocol;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::dns::forwarder::build_dns_query;
    use crate::dns::transport::tests_proto::{
        ProxiedQuicFixture, insecure_quic_config, proxied_quic_fixture, spawn_doh3_server,
    };

    #[test]
    fn h3_body_rejects_hostile_multichunk_response_before_append() {
        // Given
        let mut body = DnsMessageBody::new("DoH3", None).expect("body");
        body.push(&vec![0; 40_000]).expect("first chunk");

        // When
        let error = body
            .push(&vec![0; 30_000])
            .expect_err("oversized second chunk");

        // Then
        assert_eq!(body.len(), 40_000);
        assert!(error.downcast_ref::<DnsMessageTooLarge>().is_some());
    }

    #[test]
    fn h3_body_accepts_exact_protocol_boundary() {
        // Given
        let mut body =
            DnsMessageBody::new("DoH3", Some(MAX_DNS_MESSAGE_SIZE)).expect("bounded body");

        // When
        body.push(&vec![0; MAX_DNS_MESSAGE_SIZE])
            .expect("exact boundary");

        // Then
        assert_eq!(body.len(), MAX_DNS_MESSAGE_SIZE);
    }

    #[tokio::test]
    async fn constructor_keeps_query_and_dial_timeouts_distinct() {
        let dial = DialContext {
            endpoint: crate::dns::endpoint::DnsEndpoint::parse(
                "127.0.0.1/dns-query",
                DnsProtocol::H3,
                Some("localhost"),
            )
            .expect("DoH3 endpoint"),
            query_timeout: Duration::from_millis(111),
            dial_timeout: Duration::from_millis(222),
            proxy: None,
        };
        let client = Doh3Client::new(dial).await.expect("DoH3 client");

        assert_eq!(client.dial.query_timeout, Duration::from_millis(111));
        assert_eq!(client.dial.dial_timeout, Duration::from_millis(222));
    }

    #[tokio::test]
    async fn proxied_doh3_reuses_and_closes_packet_endpoint() {
        let (address, server) = spawn_doh3_server();
        let endpoint = crate::dns::endpoint::DnsEndpoint::parse(
            &format!("127.0.0.1:{}/dns-query", address.port()),
            DnsProtocol::H3,
            Some("localhost"),
        )
        .unwrap();
        let ProxiedQuicFixture {
            dial,
            active,
            runtime_dials,
        } = proxied_quic_fixture(endpoint);
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let client = Arc::new(Doh3Client {
            dial,
            quic_config: insecure_quic_config(b"h3").await,
            quic_ep: SharedQuicEndpoint::new(),
            session: LifecycleSlot::new(),
            active_tasks: Arc::clone(&active_tasks),
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
        assert_eq!(active_tasks.load(Ordering::SeqCst), 0);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
