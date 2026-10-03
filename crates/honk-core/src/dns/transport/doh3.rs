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
use super::lifecycle::{LifecycleSlot, SessionFailure, SessionObservation};
use super::owned_task::OwnedTask;
use super::quic::with_packet_cause;
use super::{
    DnsMessageBody, SharedQuicEndpoint, build_doh_request, check_doh_status, dns_quic_config,
    doh_content_length, exchange_with_retry, finish_doh_response, quic_connect_endpoint,
};

type H3Sender = SendRequest<h3_quinn::OpenStreams, Bytes>;

struct H3Session {
    sender: Mutex<Option<H3Sender>>,
    connection: quinn::Connection,
    endpoint: Option<honk_outbound::quic::PacketTransportEndpoint>,
    _metrics: honk_outbound::quic::QuicConnectionMonitor,
    driver: OwnedTask,
}

impl H3Session {
    async fn close(self: Arc<Self>, timeout: Duration) {
        self.sender.lock().await.take();
        self.connection.close(0_u32.into(), b"shutdown");
        self.driver.shutdown(timeout).await;
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(timeout).await;
        }
    }
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
        feedback: Option<honk_outbound::group::ScoreBusinessGuard>,
    ) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoH3",
            raw_query,
            |reporter| async move { self.exchange_once(raw_query, reporter.as_ref()).await },
            |error| {
                let session = SessionFailure::<H3Session>::session(error);
                async move {
                    if let Some(session) = session {
                        self.retire_session(&session).await;
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
        let (session, mut sender) = self.get_sender().await?;
        if let Some(reporter) = reporter {
            reporter.setup_succeeded();
        }

        tokio::time::timeout(self.dial.query_timeout, async {
            let mut wire = raw_query.to_vec();
            let orig_id = force_dns_id_zero(&mut wire);

            let request = build_doh_request(&self.dial.endpoint, None, "DoH3")?;
            let mut stream = sender.send_request(request).await.map_err(|error| {
                with_packet_cause(session.endpoint.as_ref(), error.into())
                    .context("DoH3 send_request")
            })?;

            stream.send_data(Bytes::from(wire)).await.map_err(|error| {
                with_packet_cause(session.endpoint.as_ref(), error.into()).context("DoH3 send_data")
            })?;
            stream.finish().await.map_err(|error| {
                with_packet_cause(session.endpoint.as_ref(), error.into()).context("DoH3 finish")
            })?;
            if let Some(reporter) = reporter {
                reporter.tx(raw_query.len() as u64);
            }

            let response = stream.recv_response().await.map_err(|error| {
                with_packet_cause(session.endpoint.as_ref(), error.into())
                    .context("DoH3 recv_response")
            })?;

            check_doh_status("DoH3", response.status())?;
            let content_length = doh_content_length("DoH3", response.headers())?;
            let mut buf = DnsMessageBody::new("DoH3", content_length)?;
            while let Some(mut bytes) = stream.recv_data().await.map_err(|error| {
                with_packet_cause(session.endpoint.as_ref(), error.into()).context("DoH3 recv_data")
            })? {
                while bytes.has_remaining() {
                    let chunk = bytes.chunk();
                    let len = chunk.len();
                    buf.push(chunk)?;
                    bytes.advance(len);
                }
            }

            let response = finish_doh_response("DoH3", buf.into_bytes(), orig_id)?;
            if let Some(reporter) = reporter
                && super::is_valid_response(raw_query, &response)
            {
                reporter.first_response();
                reporter.rx(response.len() as u64);
            }
            Ok::<_, anyhow::Error>(response)
        })
        .await
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "DoH3 exchange timed out after {:?}",
                self.dial.query_timeout
            ))
        })
        .map_err(|error| SessionFailure::new(session, error).into())
    }

    /// A sender on a live QUIC connection; one that closed between queries
    /// is rebuilt before the query goes out rather than failing it.
    async fn get_sender(&self) -> anyhow::Result<(Arc<H3Session>, H3Sender)> {
        let observation = SessionObservation::start();
        let result = async {
            for attempt in 0..2 {
                let (session, reused) = self.session.acquire(|| self.handshake()).await?;
                match session.connection.close_reason() {
                    None => {
                        let sender = session.sender.lock().await.clone().ok_or_else(|| {
                            SessionFailure::new(
                                Arc::clone(&session),
                                anyhow::anyhow!("DoH3 session is closing"),
                            )
                        })?;
                        if reused {
                            super::lifecycle::attached();
                        }
                        return Ok((session, sender));
                    }
                    Some(reason) if attempt == 0 => {
                        observation.record(honk_outbound::runtime::flow_observation::SessionEvent::DnsSessionReadyFailed);
                        observation.record(honk_outbound::runtime::flow_observation::SessionEvent::DnsSessionRetryStarted);
                        debug!(error = %reason, transport = "doh3", "DoH3 connection is closed; rebuilding");
                        self.retire_session(&session).await;
                    }
                    Some(reason) => {
                        let error = with_packet_cause(session.endpoint.as_ref(), reason.into())
                            .context("DoH3 connection closed");
                        return Err(SessionFailure::new(session, error).into());
                    }
                }
            }
            unreachable!("the loop returns or fails on its second pass")
        }
        .await;
        observation.finish(
            result,
            honk_outbound::runtime::flow_observation::SessionEvent::DnsSessionReadySucceeded,
        )
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
                let error = with_packet_cause(endpoint.as_ref(), error.into())
                    .context("DoH3 h3::client::new");
                close_failed_connection(&conn, &endpoint).await;
                return Err(error);
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

    async fn retire_session(&self, session: &Arc<H3Session>) {
        let timeout = self.dial.query_timeout;
        self.session
            .retire(session, move |session| session.close(timeout))
            .await;
    }

    pub(crate) fn tasks_failed(&self) -> bool {
        self.quic_ep.tasks_failed()
    }

    pub(crate) async fn close(&self) {
        let timeout = self.dial.query_timeout;
        self.session
            .close(move |session| session.close(timeout))
            .await;
        self.quic_ep.close(self.dial.query_timeout).await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        DnsMessageBody, DnsMessageTooLarge, MAX_DNS_MESSAGE_SIZE, exchange_with_retry,
        is_valid_response,
    };
    use super::{Doh3Client, LifecycleSlot, OwnedTask, SharedQuicEndpoint};
    use bytes::{Buf, Bytes};
    use honk_config::types::DnsProtocol;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::dns::forwarder::build_dns_query;
    use crate::dns::transport::tests_proto::{
        ProxiedQuicFixture, insecure_quic_config, proxied_quic_fixture, quic_server_endpoint,
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
    async fn proxied_doh3_reuses_and_closes_packet_endpoint() {
        let (endpoint, address) = quic_server_endpoint(b"h3");
        let mut answer = build_dns_query("example.com", 1);
        answer[..2].fill(0);
        answer[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut h3 = h3::server::builder()
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            for (status, body) in [(400, Vec::new()), (200, vec![0; 3]), (200, answer)] {
                respond_h3(&mut h3, status, body).await;
            }
            connection.closed().await;
        });
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
            let error = client.exchange(&query, None).await.unwrap_err();
            assert!(
                error
                    .chain()
                    .any(|cause| cause.is::<super::super::doh_message::DeterministicResponse>())
            );
        }
        let response = client.exchange(&query, None).await.unwrap();
        assert!(is_valid_response(&query, &response));
        assert_eq!(&response[..2], &query[..2]);
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

    async fn respond_h3(
        h3: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
        status: u16,
        body: Vec<u8>,
    ) -> Vec<u8> {
        let resolver = h3.accept().await.unwrap().unwrap();
        let (_request, mut stream) = resolver.resolve_request().await.unwrap();
        let mut query = Vec::new();
        while let Some(mut data) = stream.recv_data().await.unwrap() {
            query.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        stream
            .send_response(http::Response::builder().status(status).body(()).unwrap())
            .await
            .unwrap();
        if !body.is_empty() {
            stream.send_data(Bytes::from(body)).await.unwrap();
        }
        stream.finish().await.unwrap();
        query
    }

    #[tokio::test]
    async fn final_attempt_goaway_does_not_block_later_query() {
        let (endpoint, address) = quic_server_endpoint(b"h3");
        let (goaway_sent, goaway_received) = tokio::sync::oneshot::channel();
        let mut answer = build_dns_query("example.com", 1);
        answer[..2].fill(0);
        answer[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        let server = tokio::spawn(async move {
            let first = endpoint.accept().await.unwrap().await.unwrap();
            let first_peer = tokio::spawn(async move {
                let mut h3 = h3::server::builder()
                    .build(h3_quinn::Connection::new(first.clone()))
                    .await
                    .unwrap();
                let query = respond_h3(&mut h3, 503, Vec::new()).await;
                first.closed().await;
                query
            });

            let draining = endpoint.accept().await.unwrap().await.unwrap();
            let mut h3 = h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(draining.clone()))
                .await
                .unwrap();
            h3.shutdown(0).await.unwrap();
            goaway_sent.send(()).unwrap();

            let recovered = endpoint.accept().await.unwrap().await.unwrap();
            let mut recovered_h3 = h3::server::builder()
                .build(h3_quinn::Connection::new(recovered.clone()))
                .await
                .unwrap();
            let recovered_query = respond_h3(&mut recovered_h3, 200, answer).await;
            recovered.closed().await;
            draining.closed().await;
            (first_peer.await.unwrap(), recovered_query)
        });

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
        client.session.acquire(|| client.handshake()).await.unwrap();
        let mut final_session = client.handshake().await.unwrap();
        goaway_received.await.unwrap();

        // Wait for the real H3 driver to consume GOAWAY, without sending a DNS body.
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut sender = final_session.sender.lock().await.clone().unwrap();
            loop {
                let request =
                    super::build_doh_request(&client.dial.endpoint, None, "DoH3").unwrap();
                match sender.send_request(request).await {
                    Err(h3::error::StreamError::RemoteClosing) => break,
                    Err(error) => panic!("unexpected H3 setup error: {error}"),
                    Ok(stream) => drop(stream),
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer GOAWAY reached the client");

        // Hold completion of the real driver's teardown beyond the final query deadline.
        let (release_driver, driver_released) = tokio::sync::oneshot::channel();
        let (driver_started, driver_running) = tokio::sync::oneshot::channel();
        let connection = final_session.connection.clone();
        let driver = final_session.driver;
        final_session.driver = OwnedTask::spawn(
            async move {
                driver_started.send(()).unwrap();
                connection.closed().await;
                driver.shutdown(Duration::ZERO).await;
                let _ = driver_released.await;
            },
            Arc::clone(&active_tasks),
        );
        driver_running.await.unwrap();

        let query = build_dns_query("example.com", 1);
        let attempts = AtomicUsize::new(0);
        // The production retry boundary owns reset; only session publication is gated here.
        exchange_with_retry(
            "DoH3",
            &query,
            |_| async {
                if attempts.fetch_add(1, Ordering::SeqCst) == 1 {
                    tokio::time::pause();
                }
                client.exchange_once(&query, None).await
            },
            |error| {
                let session = super::SessionFailure::<super::H3Session>::session(error).unwrap();
                let client = &client;
                async move {
                    client.retire_session(&session).await;
                    client
                        .session
                        .acquire(|| async { Ok(final_session) })
                        .await
                        .unwrap();
                }
            },
            None,
        )
        .await
        .expect_err("503 followed by GOAWAY exhausts the two query attempts");
        tokio::time::resume();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        let _ = release_driver.send(());

        let response = tokio::time::timeout(Duration::from_secs(2), client.exchange(&query, None))
            .await
            .expect("a later query must not wait on an abandoned close")
            .expect("a later query rebuilds the draining session");
        assert!(is_valid_response(&query, &response));
        assert_eq!(&response[..2], &query[..2]);
        assert_eq!(runtime_dials.load(Ordering::SeqCst), 3);

        client.close().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(active_tasks.load(Ordering::SeqCst), 0);
        let (first_query, recovered_query) = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        let mut wire_query = query;
        wire_query[..2].fill(0);
        assert_eq!(first_query, wire_query);
        assert_eq!(recovered_query, wire_query);
    }
}
