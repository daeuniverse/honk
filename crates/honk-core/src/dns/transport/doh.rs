//! DNS over HTTPS (RFC 8484) over HTTP/2.
//!
//! One long-lived H2 session per upstream multiplexes concurrent POSTs of
//! `application/dns-message`. On session death the next query redials once.
//! Query ID is forced to 0 on the wire (cache-friendly) and restored for the
//! intercepted client.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use bytes::Bytes;
use h2::client::{SendRequest, handshake};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use super::framing::force_dns_id_zero;
use super::lifecycle::{LifecycleSlot, SessionFailure, SessionObservation};
use super::owned_task::OwnedTask;
use super::{
    DialContext, DnsMessageBody, build_doh_request, check_doh_status, doh_content_length,
    exchange_with_retry, finish_doh_response,
};
use honk_outbound::tls::TlsConnector;

pub(super) const DOH_ALPN_WIRE: &[u8] = b"\x02h2";

type H2Sender = SendRequest<Bytes>;

struct H2Session {
    sender: Mutex<Option<H2Sender>>,
    driver: OwnedTask,
}

impl H2Session {
    async fn close(self: Arc<Self>, timeout: Duration) {
        self.sender.lock().take();
        self.driver.shutdown(timeout).await;
    }
}

/// Shared DoH (HTTP/2) client for one upstream.
pub struct DohClient {
    dial: DialContext,
    connector: TlsConnector,
    session: LifecycleSlot<H2Session>,
    active_tasks: Arc<AtomicUsize>,
}

impl DohClient {
    pub fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        Self::new_tracked(dial, Arc::new(AtomicUsize::new(0)))
    }

    pub(crate) fn new_tracked(
        dial: DialContext,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        let connector = honk_outbound::tls::build_dns_connector(false, DOH_ALPN_WIRE)?;
        Ok(Arc::new(Self {
            dial,
            connector,
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
            "DoH",
            raw_query,
            |reporter| async move { self.exchange_once(raw_query, reporter.as_ref()).await },
            |error| {
                let session = SessionFailure::<H2Session>::session(error);
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

            let req = build_doh_request(&self.dial.endpoint, Some(wire.len()), "DoH")?;

            let (response_fut, mut send_stream) = sender
                .send_request(req, false)
                .map_err(|e| anyhow::anyhow!("DoH send_request: {e}"))?;

            send_stream
                .send_data(Bytes::from(wire), true)
                .map_err(|e| anyhow::anyhow!("DoH send_data: {e}"))?;
            if let Some(reporter) = reporter {
                reporter.tx(raw_query.len() as u64);
            }

            let response = response_fut
                .await
                .map_err(|e| anyhow::anyhow!("DoH response error: {e}"))?;

            check_doh_status("DoH", response.status())?;
            let content_length = doh_content_length("DoH", response.headers())?;
            let mut body = response.into_body();
            let mut buf = DnsMessageBody::new("DoH", content_length)?;
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|e| anyhow::anyhow!("DoH body read: {e}"))?;
                let n = chunk.len();
                buf.push(&chunk)?;
                let _ = body.flow_control().release_capacity(n);
            }

            let response = finish_doh_response("DoH", buf.into_bytes(), orig_id)?;
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
                "DoH exchange timed out after {:?}",
                self.dial.query_timeout
            ))
        })
        .map_err(|error| SessionFailure::new(session, error).into())
    }

    /// A sender on a live session. The connection driver can stop between
    /// queries (server GOAWAY, idle close), leaving a sender clone that only
    /// fails; `ready` catches that, and the session is rebuilt once before
    /// the query goes out, instead of the query spending its retry on it.
    async fn get_sender(&self) -> anyhow::Result<(Arc<H2Session>, H2Sender)> {
        let observation = SessionObservation::start();
        let result = async {
            for attempt in 0..2 {
                let (session, reused) = self.session.acquire(|| self.handshake()).await?;
                let sender = session.sender.lock().clone().ok_or_else(|| {
                    SessionFailure::new(
                        Arc::clone(&session),
                        anyhow::anyhow!("DoH session is closing"),
                    )
                })?;
                match sender.ready().await {
                    Ok(sender) => {
                        if reused {
                            super::lifecycle::attached();
                        }
                        return Ok((session, sender));
                    }
                    Err(error) if attempt == 0 => {
                        observation.record(honk_outbound::runtime::flow_observation::SessionEvent::DnsSessionReadyFailed);
                        observation.record(honk_outbound::runtime::flow_observation::SessionEvent::DnsSessionRetryStarted);
                        debug!(error = %error, transport = "doh", "DoH session is dead; rebuilding");
                        self.retire_session(&session).await;
                    }
                    Err(error) => {
                        return Err(SessionFailure::new(
                            session,
                            anyhow::anyhow!("DoH session unusable: {error}"),
                        )
                        .into());
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

    async fn handshake(&self) -> anyhow::Result<H2Session> {
        let server_name = self.dial.endpoint.sni.clone();
        let via_proxy = self.dial.proxy.is_some();
        let deadline = tokio::time::Instant::now() + self.dial.dial_timeout;
        let tcp = self.dial.dial_tcp_boxed_until(deadline).await?;
        tokio::time::timeout_at(deadline, async {
            let tls = self
                .connector
                .connect(&server_name, tcp)
                .await
                .map_err(|error| {
                    let route = if via_proxy { " (via proxy)" } else { "" };
                    anyhow::anyhow!("DoH TLS handshake{route}: {error}")
                })?;
            spawn_h2(tls, Arc::clone(&self.active_tasks)).await
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "DoH TCP, TLS, and HTTP/2 setup timed out after {:?}",
                self.dial.dial_timeout
            )
        })?
    }

    async fn retire_session(&self, session: &Arc<H2Session>) {
        let timeout = self.dial.query_timeout;
        self.session
            .retire(session, move |session| session.close(timeout))
            .await;
    }

    pub(crate) async fn close(&self) {
        let timeout = self.dial.query_timeout;
        self.session
            .close(move |session| session.close(timeout))
            .await;
    }
}

async fn spawn_h2<S>(tls: S, active_tasks: Arc<AtomicUsize>) -> anyhow::Result<H2Session>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = handshake(tls)
        .await
        .map_err(|e| anyhow::anyhow!("HTTP/2 handshake: {e}"))?;
    let driver = OwnedTask::spawn(
        async move {
            if let Err(error) = conn.await {
                debug!(
                    error = %error,
                    transport = "doh",
                    "dns transport driver stopped"
                );
            }
        },
        active_tasks,
    );
    Ok(H2Session {
        sender: Mutex::new(Some(sender)),
        driver,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{
        DnsMessageBody, DnsMessageTooLarge, MAX_DNS_MESSAGE_SIZE, doh_content_length,
    };

    #[cfg(feature = "native-api")]
    #[tokio::test]
    async fn native_h2_reuse_and_stale_readiness_keep_inner_retry_evidence() {
        use super::*;
        use crate::dns::{endpoint::DnsEndpoint, forwarder::build_dns_query};
        use crate::native_api::events::EventHub;
        use crate::observe::flows::FlowStore;
        use honk_config::types::DnsProtocol;
        use uuid::Uuid;

        let (mut config, _) = super::super::tests_proto::self_signed_server_config();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for count in [2, 1] {
                let (tcp, _) = listener.accept().await.unwrap();
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut connection = h2::server::handshake(tls).await.unwrap();
                let mut responses = tokio::task::JoinSet::new();
                for _ in 0..count {
                    let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                    responses.spawn(async move {
                        let mut request = request.into_body();
                        let mut answer = Vec::new();
                        while let Some(chunk) = request.data().await {
                            let chunk = chunk.unwrap();
                            answer.extend_from_slice(&chunk);
                            request
                                .flow_control()
                                .release_capacity(chunk.len())
                                .unwrap();
                        }
                        answer[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        respond
                            .send_response(response, false)
                            .unwrap()
                            .send_data(Bytes::from(answer), true)
                            .unwrap();
                    });
                }
                if let Some(Ok(_)) = connection.accept().await {
                    panic!("unexpected query replay");
                }
                while let Some(result) = responses.join_next().await {
                    result.unwrap();
                }
            }
        });
        let mut client = DohClient::new(DialContext {
            endpoint: DnsEndpoint::parse(
                &format!("{address}/dns-query"),
                DnsProtocol::Https,
                Some("localhost"),
            )
            .unwrap(),
            query_timeout: Duration::from_secs(2),
            dial_timeout: Duration::from_secs(2),
            proxy: None,
        })
        .unwrap();
        Arc::get_mut(&mut client).unwrap().connector =
            honk_outbound::tls::build_dns_connector(true, DOH_ALPN_WIRE).unwrap();
        let instance = Uuid::new_v4().to_string();
        let store = Arc::new(FlowStore::new(
            instance.clone(),
            Arc::new(EventHub::new(instance)),
        ));
        for (index, name) in ["cold.example", "warm.example", "recovered.example"]
            .into_iter()
            .enumerate()
        {
            if index == 2 {
                let (session, _) = client
                    .session
                    .acquire(|| async { panic!("warm session") })
                    .await
                    .unwrap();
                session.driver.shutdown(Duration::ZERO).await;
            }
            let flow = Arc::new(
                store
                    .begin(
                        crate::observe::vocab::Network::Udp,
                        "127.0.0.1:31000".parse().unwrap(),
                        address,
                    )
                    .unwrap(),
            );
            let observer = flow.observer(11, None, "intercepted_query").unwrap();
            let query = build_dns_query(name, 1);
            let response = tokio::time::timeout(
                Duration::from_secs(3),
                observer.scope(client.exchange(&query, None)),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(super::super::is_valid_response(&query, &response));
            let view = store.test_detail(flow.id());
            assert_eq!(view["trace"]["status"], "complete", "{view:#}");
            let steps = view["trace"]["steps"].as_array().unwrap();
            let lookup = steps
                .iter()
                .find(|step| step["stage"] == "dns" && step["data"]["status"] == "succeeded")
                .unwrap();
            let physical: Vec<_> = steps
                .iter()
                .filter(|step| step["stage"] == "outbound" && step["data"]["kind"] == "transport")
                .collect();
            assert_eq!(physical.len(), if index == 1 { 0 } else { 2 }, "{view:#}");
            let attached: Vec<_> = steps
                .iter()
                .filter(|step| step["data"]["reason"] == "dns_transport_attached")
                .collect();
            assert_eq!(attached.len(), usize::from(index == 1), "{view:#}");
            let session: Vec<_> = steps
                .iter()
                .filter(|step| {
                    step["data"]["reason"]
                        .as_str()
                        .is_some_and(|reason| reason.starts_with("dns_session_"))
                })
                .collect();
            let reasons: Vec<_> = session
                .iter()
                .map(|step| step["data"]["reason"].as_str().unwrap())
                .collect();
            assert_eq!(
                reasons,
                if index == 2 {
                    vec![
                        "dns_session_ready_failed",
                        "dns_session_retry_started",
                        "dns_session_ready_succeeded",
                    ]
                } else {
                    vec!["dns_session_ready_succeeded"]
                },
                "{view:#}"
            );
            assert!(session.iter().chain(attached.iter()).all(|step| {
                step["data"]["attempt_id"].is_null()
                    && step["data"]["lookup_id"] == lookup["data"]["lookup_id"]
                    && step["generation_id"] == lookup["generation_id"]
            }));
            assert!(
                session
                    .iter()
                    .all(|step| step["data"]["milestone"] == "unknown")
            );
            if index == 2 {
                assert!(session[0]["seq"].as_u64().unwrap() < physical[0]["seq"].as_u64().unwrap());
            }
            assert!(
                !steps
                    .iter()
                    .any(|step| step["data"]["reason"] == "target_confirmed"
                        || step["data"]["milestone"] == "first_reply")
            );
        }
        client.close().await;
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn deterministic_responses_preserve_the_live_session() {
        use super::*;
        use crate::dns::endpoint::DnsEndpoint;
        use crate::dns::forwarder::build_dns_query;
        use honk_config::types::DnsProtocol;
        use std::sync::atomic::Ordering;

        let query = build_dns_query("example.com", 1);
        let mut answer = query.clone();
        answer[..2].fill(0);
        answer[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let mut responses = tokio::task::JoinSet::new();
            for (status, body) in [(400, Vec::new()), (200, vec![0; 3]), (200, answer)] {
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                responses.spawn(async move {
                    let mut request = request.into_body();
                    while let Some(chunk) = request.data().await {
                        let chunk = chunk.unwrap();
                        request
                            .flow_control()
                            .release_capacity(chunk.len())
                            .unwrap();
                    }
                    let response = http::Response::builder().status(status).body(()).unwrap();
                    let mut stream = respond.send_response(response, body.is_empty()).unwrap();
                    if !body.is_empty() {
                        stream.send_data(Bytes::from(body), true).unwrap();
                    }
                });
            }
            assert!(
                connection.accept().await.is_none(),
                "unexpected query replay"
            );
            while let Some(result) = responses.join_next().await {
                result.unwrap();
            }
        });
        let unused_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = unused_listener.local_addr().unwrap();
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let client = DohClient::new_tracked(
            DialContext {
                endpoint: DnsEndpoint::parse(
                    &format!("{address}/dns-query"),
                    DnsProtocol::Https,
                    Some("localhost"),
                )
                .unwrap(),
                query_timeout: Duration::from_secs(1),
                dial_timeout: Duration::from_millis(100),
                proxy: None,
            },
            Arc::clone(&active_tasks),
        )
        .unwrap();
        client
            .session
            .acquire(|| spawn_h2(client_io, Arc::clone(&active_tasks)))
            .await
            .unwrap();
        for _ in 0..2 {
            let error = client.exchange(&query, None).await.unwrap_err();
            assert!(
                error
                    .chain()
                    .any(|cause| cause.is::<super::super::doh_message::DeterministicResponse>())
            );
        }
        let response = client.exchange(&query, None).await.unwrap();
        assert!(super::super::is_valid_response(&query, &response));
        assert_eq!(&response[..2], &query[..2]);
        assert_eq!(client.session.init_count(), 1);
        client.close().await;
        assert_eq!(active_tasks.load(Ordering::SeqCst), 0);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn h2_body_rejects_hostile_multichunk_response_before_append() {
        // Given
        let mut body = DnsMessageBody::new("DoH", None).expect("body");
        body.push(&vec![0; 32_768]).expect("first chunk");

        // When
        let error = body
            .push(&vec![0; 32_768])
            .expect_err("oversized second chunk");

        // Then
        assert_eq!(body.len(), 32_768);
        assert!(error.downcast_ref::<DnsMessageTooLarge>().is_some());
    }

    #[test]
    fn h2_body_accepts_exact_protocol_boundary() {
        // Given
        let mut body =
            DnsMessageBody::new("DoH", Some(MAX_DNS_MESSAGE_SIZE)).expect("bounded body");

        // When
        body.push(&vec![0; MAX_DNS_MESSAGE_SIZE])
            .expect("exact boundary");

        // Then
        assert_eq!(body.len(), MAX_DNS_MESSAGE_SIZE);
    }

    #[test]
    fn h2_body_rejects_oversized_content_length_before_allocation() {
        // Given
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("65536"),
        );

        // When
        let error = doh_content_length("DoH", &headers).expect_err("oversized content length");

        // Then
        assert!(error.downcast_ref::<DnsMessageTooLarge>().is_some());
    }
}
