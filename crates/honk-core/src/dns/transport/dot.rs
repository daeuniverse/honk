//! DNS over TLS (RFC 7858) with an idle connection pool.

use std::sync::Arc;

use super::dial::CarrierIo;
use super::idle_pool::IdleStream;
use super::retry::exchange_with_route_retry;
use super::{DialContext, IdlePoolState, RouteExchange, close_idle_pool, idle_pool_exchange};
use honk_outbound::tls::{TlsConnector, TlsStream};
use parking_lot::Mutex;

/// TLS stream over either a direct or proxied base connection.
type PooledStream = TlsStream<CarrierIo<Box<dyn crate::proxy::AsyncReadWrite>>>;

/// Idle-pool DoT client for one upstream.
pub struct DotPool {
    dial: DialContext,
    connector: TlsConnector,
    lifecycle: tokio::sync::RwLock<IdlePoolState>,
    idle: Mutex<Vec<IdleStream<PooledStream>>>,
}

impl DotPool {
    pub fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        let connector = honk_outbound::tls::build_dns_connector(false, b"\x03dot")?;
        Ok(Arc::new(Self {
            dial,
            connector,
            lifecycle: tokio::sync::RwLock::new(IdlePoolState::Open),
            idle: Mutex::new(Vec::new()),
        }))
    }

    pub async fn exchange(
        self: &Arc<Self>,
        raw_query: &[u8],
        feedback: Option<honk_outbound::group::ScoreBusinessGuard>,
    ) -> anyhow::Result<Vec<u8>> {
        self.exchange_routed(raw_query, feedback, None).await
    }

    pub(crate) async fn exchange_routed(
        self: &Arc<Self>,
        raw_query: &[u8],
        feedback: Option<honk_outbound::group::ScoreBusinessGuard>,
        route: Option<RouteExchange<'_>>,
    ) -> anyhow::Result<Vec<u8>> {
        let routed = route.is_some();
        exchange_with_route_retry(
            "DoT",
            raw_query,
            |reporter| async move {
                self.exchange_once(raw_query, reporter.as_ref(), routed)
                    .await
            },
            |_| async {},
            feedback,
            route,
        )
        .await
    }

    async fn exchange_once(
        &self,
        raw_query: &[u8],
        reporter: Option<&honk_outbound::group::ScoreReporter>,
        routed: bool,
    ) -> anyhow::Result<Vec<u8>> {
        idle_pool_exchange(
            &self.lifecycle,
            &self.idle,
            || self.dial_tls(routed),
            raw_query,
            self.dial.query_timeout,
            reporter,
            routed,
        )
        .await
    }

    async fn dial_tls(&self, routed: bool) -> anyhow::Result<PooledStream> {
        let server_name = self.dial.endpoint.sni.clone();
        let via_proxy = self.dial.proxy.is_some();
        let deadline = tokio::time::Instant::now() + self.dial.dial_timeout;
        let tcp = self.dial.dial_tcp_boxed_until(deadline).await?;
        let retain = routed
            && self
                .dial
                .proxy
                .as_ref()
                .is_some_and(|proxy| proxy.route.is_none());
        let (tcp, _) = CarrierIo::capture(tcp, retain);
        tokio::time::timeout_at(deadline, self.connector.connect(&server_name, tcp))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "DoT dial and TLS handshake timed out after {:?}",
                    self.dial.dial_timeout
                )
            })?
            .map_err(|error| {
                let route = if via_proxy { " (via proxy)" } else { "" };
                let context = format!("DoT TLS handshake{route}: {error}");
                if routed {
                    error.context(context)
                } else {
                    anyhow::Error::msg(context)
                }
            })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.idle.lock().is_empty()
    }

    pub(crate) async fn close(&self) {
        close_idle_pool(&self.lifecycle, &self.idle, self.dial.query_timeout).await;
    }
}
