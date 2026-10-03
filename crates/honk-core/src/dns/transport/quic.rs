use std::time::Duration;

use super::dial::{DialContext, dial_candidates};
use crate::dns::endpoint::DnsEndpoint;

/// Shared QUIC client config for DNS transports (15s keep-alive, cubic).
pub(super) async fn dns_quic_config(alpn: &[&[u8]]) -> anyhow::Result<quinn::ClientConfig> {
    honk_outbound::quic::client_config(
        &honk_config::node::Node {
            outbound: honk_config::node::OutboundConfig::from_protocol(
                honk_config::types::NodeProtocol::Hysteria2,
            ),
            ..Default::default()
        },
        alpn,
        honk_outbound::quic::QuicClientOptions {
            keep_alive: Some(Duration::from_secs(15)),
            ..honk_outbound::quic::QuicClientOptions::with_congestion(Some("cubic"))
        },
    )
    .await
}

/// Lazily-created per-family QUIC client endpoints reused across reconnects.
pub(super) struct SharedQuicEndpoint {
    direct: tokio::sync::Mutex<[Option<quinn::Endpoint>; 2]>,
    tasks: std::sync::Arc<honk_outbound::runtime::TaskOwner>,
}

impl SharedQuicEndpoint {
    pub(super) fn new() -> Self {
        Self {
            direct: tokio::sync::Mutex::new([None, None]),
            tasks: std::sync::Arc::new(honk_outbound::runtime::TaskOwner::production()),
        }
    }

    async fn get(&self, ipv6: bool) -> anyhow::Result<quinn::Endpoint> {
        let mut endpoints = self.direct.lock().await;
        let endpoint = &mut endpoints[if ipv6 { 1 } else { 0 }];
        if let Some(endpoint) = endpoint.as_ref() {
            return Ok(endpoint.clone());
        }
        let created = honk_outbound::quic::client_endpoint(ipv6)
            .map_err(|e| anyhow::anyhow!("QUIC client endpoint: {e}"))?;
        *endpoint = Some(created.clone());
        Ok(created)
    }

    pub(super) async fn close(&self, timeout: Duration) {
        let endpoints = {
            let mut endpoints = self.direct.lock().await;
            [endpoints[0].take(), endpoints[1].take()]
        };
        for endpoint in endpoints.into_iter().flatten() {
            endpoint.close(0_u32.into(), b"shutdown");
            let _ = tokio::time::timeout(timeout, endpoint.wait_idle()).await;
        }
        self.tasks.close().await;
    }

    pub(super) fn tasks_failed(&self) -> bool {
        self.tasks.has_failed()
    }
}

fn endpoint_lost(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if matches!(
            error.downcast_ref::<quinn::ConnectError>(),
            Some(quinn::ConnectError::EndpointStopping)
        ) {
            return true;
        }
        if matches!(
            error.downcast_ref::<quinn::ConnectionError>(),
            Some(quinn::ConnectionError::LocallyClosed)
        ) {
            return true;
        }
        if let Some(quinn::ConnectionError::TransportError(error)) = error.downcast_ref() {
            return error.code == quinn::TransportErrorCode::INTERNAL_ERROR
                && error.frame.is_none();
        }
        if let Some(h3::error::StreamError::ConnectionError(connection, ..)) = error.downcast_ref()
        {
            error = connection;
            continue;
        }
        if let Some(h3::error::ConnectionError::Remote(
            h3::quic::ConnectionErrorIncoming::Undefined(connection),
            ..,
        )) = error.downcast_ref()
        {
            error = connection.as_ref();
            continue;
        }
        let source = error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .map(|source| source as &(dyn std::error::Error + 'static))
            .or_else(|| error.source());
        let Some(source) = source else {
            return false;
        };
        error = source;
    }
}

pub(super) fn with_packet_cause(
    endpoint: Option<&honk_outbound::quic::PacketTransportEndpoint>,
    error: anyhow::Error,
) -> anyhow::Error {
    if honk_outbound::proxy::is_packet_rejection(&error) || !endpoint_lost(error.as_ref()) {
        return error;
    }
    match endpoint.and_then(honk_outbound::quic::PacketTransportEndpoint::terminal_error) {
        Some(cause) => anyhow::Error::new(cause).context(error),
        None => error,
    }
}

/// Connect `config` to `addr`, using either the shared direct endpoint or an
/// endpoint backed by the selected proxy's PacketTransport. `label` prefixes
/// error messages (`DoQ` / `DoH3 QUIC`).
async fn quic_connect(
    dial: &DialContext,
    direct_endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    addr: std::net::SocketAddr,
    sni: &str,
    label: &str,
    budget: Duration,
) -> anyhow::Result<(
    quinn::Connection,
    Option<honk_outbound::quic::PacketTransportEndpoint>,
)> {
    let deadline = tokio::time::Instant::now() + budget;
    let owner = if dial.proxy.is_some() {
        let transport = dial.dial_packet_transport_until(addr, deadline).await?;
        let owner = honk_outbound::quic::packet_transport_endpoint_with_metrics(
            transport,
            addr,
            true,
            Some(&direct_endpoint.tasks),
        )
        .map_err(|error| anyhow::anyhow!("{label} packet endpoint: {error}"))?;
        Some(owner)
    } else {
        None
    };
    let direct;
    let endpoint = if let Some(owner) = &owner {
        owner.endpoint()
    } else {
        direct = direct_endpoint.get(addr.is_ipv6()).await?;
        &direct
    };
    let mut observation = honk_outbound::runtime::flow_observation::TransportAttempt::start(
        Some(addr),
        honk_outbound::runtime::flow_observation::ResolutionLocation::Unknown,
    );
    let handshake = async {
        let connecting = endpoint
            .connect_with(config.clone(), addr, sni)
            .map_err(|error| {
                with_packet_cause(owner.as_ref(), error.into())
                    .context(format!("{label} connect_with"))
            })?;
        tokio::time::timeout_at(deadline, connecting)
            .await
            .map_err(|_| anyhow::anyhow!("{label} handshake timed out"))?
            .map_err(|error| {
                with_packet_cause(owner.as_ref(), error.into())
                    .context(format!("{label} handshake"))
            })
    }
    .await;
    if let Some(observation) = &mut observation {
        observation.finish(
            if handshake.is_ok() {
                honk_outbound::runtime::flow_observation::TransportStatus::Succeeded
            } else {
                honk_outbound::runtime::flow_observation::TransportStatus::Failed
            },
            handshake.as_ref().err().map(|_| {
                honk_outbound::runtime::flow_observation::TransportError::QuicConnectFailed
            }),
        );
    }
    let connection = handshake?;
    Ok((connection, owner))
}

pub(super) async fn quic_connect_endpoint(
    dial: &DialContext,
    direct_endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    target: &DnsEndpoint,
    deadline: tokio::time::Instant,
    label: &str,
) -> anyhow::Result<(
    quinn::Connection,
    Option<honk_outbound::quic::PacketTransportEndpoint>,
)> {
    let addresses = tokio::time::timeout_at(deadline, target.resolve_addrs())
        .await
        .map_err(|_| anyhow::anyhow!("{label} address resolution timed out"))??;
    dial_candidates(addresses, deadline, label, |address, budget| {
        quic_connect(
            dial,
            direct_endpoint,
            config,
            address,
            &target.sni,
            label,
            budget,
        )
    })
    .await
}

#[cfg(all(test, feature = "native-api"))]
mod tests;
#[cfg(test)]
mod packet_cause_tests {
    use super::*;
    use honk_outbound::group::ScoreOutcome;
    use honk_outbound::proxy::{NodeFailure, PacketTransport};
    use std::{io, net::SocketAddr, sync::Arc};

    #[derive(Debug)]
    struct FailedCarrier(SocketAddr);

    #[async_trait::async_trait]
    impl PacketTransport for FailedCarrier {
        fn relay_addr(&self) -> SocketAddr {
            self.0
        }

        async fn send_packet(&self, _data: &[u8]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                NodeFailure(io::Error::from_raw_os_error(libc::ECONNRESET).into()),
            ))
        }

        async fn recv_packet(&self, _data: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn dns_quic_keeps_carrier_causes_through_candidate_failure() {
        let remote = "127.0.0.1:443".parse().unwrap();
        let endpoint = Arc::new(
            honk_outbound::quic::packet_transport_endpoint(Arc::new(FailedCarrier(remote)), remote)
                .unwrap(),
        );
        let config = super::super::tests_proto::insecure_quic_config(b"doq").await;
        let connection_error = Arc::new(parking_lot::Mutex::new(None));
        let error = dial_candidates(
            vec![remote],
            tokio::time::Instant::now() + Duration::from_secs(2),
            "DoQ",
            |address, _| {
                let endpoint = Arc::clone(&endpoint);
                let config = config.clone();
                let observed = Arc::clone(&connection_error);
                async move {
                    let connection = endpoint
                        .endpoint()
                        .connect_with(config, address, "localhost")
                        .map_err(|error| with_packet_cause(Some(&endpoint), error.into()))?;
                    connection.await.map_err(|error| {
                        *observed.lock() = Some(error.clone());
                        with_packet_cause(Some(&endpoint), error.into())
                    })
                }
            },
        )
        .await
        .unwrap_err();
        let endpoint_loss = ScoreOutcome::from_error(&error);
        assert!(
            matches!(endpoint_loss, ScoreOutcome::SharedNodeFailure(_)),
            "{error:#?}; observed={:?}; adapter={:?}",
            connection_error.lock(),
            endpoint.terminal_error()
        );
        let failure: anyhow::Error =
            super::super::lifecycle::SessionFailure::new(Arc::clone(&endpoint), error).into();
        assert!(Arc::ptr_eq(
            &super::super::lifecycle::SessionFailure::session(&failure).unwrap(),
            &endpoint
        ));
        assert_eq!(ScoreOutcome::from_error(&failure), endpoint_loss);
        let h3_loss = h3::error::StreamError::ConnectionError(h3::error::ConnectionError::Remote(
            h3::quic::ConnectionErrorIncoming::Undefined(Arc::new(
                connection_error.lock().take().unwrap(),
            )),
        ));
        assert_eq!(
            ScoreOutcome::from_error(&with_packet_cause(Some(&endpoint), h3_loss.into())),
            endpoint_loss,
            "every query lost with one packet endpoint reports its one terminal episode"
        );
        for error in [
            h3::error::StreamError::StreamError {
                code: h3::error::Code::H3_MESSAGE_ERROR,
                reason: "malformed response headers".into(),
            },
            h3::error::StreamError::RemoteTerminate {
                code: h3::error::Code::H3_REQUEST_CANCELLED,
            },
        ] {
            assert_eq!(
                ScoreOutcome::from_error(&with_packet_cause(Some(&endpoint), error.into())),
                ScoreOutcome::Other
            );
        }

        for error in [
            io::Error::new(
                io::ErrorKind::ConnectionReset,
                quinn::ReadError::Reset(7_u32.into()),
            ),
            io::Error::from(io::ErrorKind::UnexpectedEof),
        ] {
            let kind = error.kind();
            let error = with_packet_cause(Some(&endpoint), error.into());
            assert_eq!(ScoreOutcome::from_error(&error), ScoreOutcome::Io(kind));
        }
        let target_closed = with_packet_cause(
            Some(&endpoint),
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: 7_u32.into(),
                reason: bytes::Bytes::new(),
            })
            .into(),
        );
        assert!(!honk_outbound::proxy::node_failure(&target_closed));
        endpoint.close(Duration::ZERO).await;
    }
}
