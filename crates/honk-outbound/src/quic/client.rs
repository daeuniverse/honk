use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use quinn::{ClientConfig, Connection, Endpoint, VarInt};
use tokio::sync::Mutex;

use crate::transport_quality::TransportQuality;

use super::endpoint::{clamp_quic_payload_size, client_endpoint_with_mtu};
use super::metrics::{QuicClientConnectionMonitor, spawn_quic_client_connection_monitor};
use super::{
    AdaptiveFlowProfiles, QUIC_SAMPLE_INTERVAL, QuicClient, QuicConnState, State, TrackedConnection,
};

impl<C> State<C> {
    fn prune_connections(&mut self) {
        self.connections.retain(|tracked| {
            if tracked.state.upgrade().is_some() {
                return true;
            }
            if tracked.connection.close_reason().is_none() {
                tracked
                    .connection
                    .close(VarInt::from_u32(0), b"state dropped");
            }
            false
        });
    }
}

fn spawn_tracked_connection_cleanup<C: Send + Sync + 'static>(
    state: Weak<Mutex<State<C>>>,
    id: u64,
    connection: Connection,
    owner: Weak<C>,
    monitor: Arc<QuicClientConnectionMonitor>,
) {
    let _ = crate::runtime::spawn_owned(async move {
        let _monitor = monitor;
        let mut removed = false;
        loop {
            if owner.upgrade().is_none() {
                if connection.close_reason().is_none() {
                    connection.close(VarInt::from_u32(0), b"state dropped");
                }
                break;
            }
            tokio::select! {
                _ = connection.closed(), if !removed => {
                    if let Some(state) = state.upgrade() {
                        let mut state = state.lock().await;
                        state.connections.retain(|tracked| tracked.id != id);
                    }
                    removed = true;
                }
                _ = tokio::time::sleep(QUIC_SAMPLE_INTERVAL) => {}
            }
        }
        if !removed && let Some(state) = state.upgrade() {
            let mut state = state.lock().await;
            state.connections.retain(|tracked| tracked.id != id);
        }
    });
}

struct ConnectionCloseGuard(Option<Connection>);

impl ConnectionCloseGuard {
    fn new(conn: Connection) -> Self {
        Self(Some(conn))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ConnectionCloseGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.0.take() {
            conn.close(VarInt::from_u32(0), b"connection setup cancelled");
        }
    }
}

impl<C: Send + Sync + 'static> QuicClient<C> {
    pub fn new(
        server_host: impl Into<String>,
        server_port: u16,
        server_name: impl Into<String>,
        config: ClientConfig,
    ) -> Self {
        Self {
            server_host: server_host.into(),
            server_port,
            server_name: server_name.into(),
            config,
            endpoint_factory: None,
            mtu: 1252,
            flow_control_profiles: Arc::new(AdaptiveFlowProfiles::default()),
            task_scope: crate::runtime::TaskScope::capture(),
            state: Arc::new(Mutex::new(State {
                endpoint: None,
                conn: None,
                connections: Vec::new(),
                next_connection_id: 1,
                quality: None,
                closed: false,
            })),
        }
    }

    pub(crate) fn with_flow_control_profiles(
        mut self,
        profiles: Option<Arc<AdaptiveFlowProfiles>>,
    ) -> Self {
        if let Some(profiles) = profiles {
            self.flow_control_profiles = profiles;
        }
        self
    }

    /// Advertise a larger `max_udp_payload_size` on paths known to carry it
    /// (anything but PMTU-black-holed last miles — see [`super::client_endpoint`]).
    /// Larger datagrams directly lower the per-packet processing cost that
    /// caps single-connection QUIC throughput (~180k pps at 1252B).
    pub fn with_max_udp_payload_size(mut self, mtu: u16) -> Self {
        self.mtu = clamp_quic_payload_size(mtu);
        self
    }

    /// Use a custom endpoint constructor instead of [`super::client_endpoint`] (see
    /// the field docs). The factory is called once per address family and the
    /// resulting endpoint is cached like the default one.
    pub fn with_endpoint_factory(
        mut self,
        factory: impl Fn(bool) -> io::Result<Endpoint> + Send + Sync + 'static,
    ) -> Self {
        self.endpoint_factory = Some(Arc::new(factory));
        self
    }
    pub(crate) async fn enable_metrics(&self, quality: Arc<TransportQuality>)
    where
        C: QuicConnState,
    {
        let mut state = self.state.lock().await;
        state.quality = Some(Arc::clone(&quality));
        for tracked in &state.connections {
            tracked.monitor.enable_metrics(Arc::clone(&quality));
            if let Some(ctx) = tracked.state.upgrade() {
                ctx.enable_telemetry();
            }
        }
    }

    /// Return the shared connection (plus its protocol state), dialing and
    /// running `setup` first when there is no live connection.
    ///
    /// Resolved server addresses are raced until one completes the QUIC
    /// handshake; protocol setup runs exactly once for that winner.
    pub async fn connection_with<F, Fut>(
        &self,
        connect_timeout: Duration,
        setup: F,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = anyhow::Result<C>>,
    {
        self.task_scope
            .scope(self.connection_with_inner(connect_timeout, setup, |_, _| {}))
            .await
    }

    pub(crate) async fn connection_with_metrics<F, Fut>(
        &self,
        connect_timeout: Duration,
        setup: F,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        C: QuicConnState,
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = anyhow::Result<C>>,
    {
        self.task_scope
            .scope(
                self.connection_with_inner(connect_timeout, setup, |ctx, _| {
                    ctx.enable_telemetry();
                }),
            )
            .await
    }

    async fn connection_with_inner<F, Fut, H>(
        &self,
        connect_timeout: Duration,
        setup: F,
        mut on_publish: H,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = anyhow::Result<C>>,
        H: FnMut(&C, &Connection),
    {
        let mut state = self.state.lock().await;
        if state.closed {
            anyhow::bail!("QUIC client is closed");
        }
        state.prune_connections();
        if let Some((conn, ctx)) = &state.conn
            && conn.close_reason().is_none()
        {
            let conn = conn.clone();
            let ctx = Arc::clone(ctx);
            let metrics_enabled = state.quality.is_some();
            drop(state);
            // The QUIC connection is already admitted and reusable; time the
            // logical stream before its protocol open can block or cancel.
            crate::runtime::start_scoped_dial();
            if let Some(observer) = crate::runtime::flow_observation::current() {
                observer.publish(
                    crate::runtime::flow_observation::FlowEvent::TransportAttached {
                        server_addr: Some(conn.remote_address()),
                        resolution_location:
                            crate::runtime::flow_observation::ResolutionLocation::Unknown,
                    },
                );
            }
            if metrics_enabled {
                on_publish(ctx.as_ref(), &conn);
            }
            return Ok((conn, ctx));
        }
        state.conn = None;

        let host = format!("{}:{}", self.server_host, self.server_port);
        let resolution = crate::bootstrap::resolve(&self.server_host);
        let (resolved, selection) =
            crate::runtime::flow_observation::observe_resolution(resolution).await;
        let addrs: Vec<SocketAddr> = resolved
            .with_context(|| format!("resolve {host}"))?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.server_port))
            .collect();
        if addrs.is_empty() {
            anyhow::bail!("resolve {host}: no addresses");
        }

        let cached_endpoint = state
            .endpoint
            .as_ref()
            .map(|(ipv6, endpoint)| (*ipv6, endpoint.clone()));
        let raced = crate::address_race::race_resolved_addrs(&addrs, |server_addr| {
            let ipv6 = server_addr.is_ipv6();
            let dial_config = self.config.clone();
            let endpoint = cached_endpoint
                .as_ref()
                .filter(|(cached_ipv6, _)| *cached_ipv6 == ipv6)
                .map(|(_, endpoint)| endpoint.clone());
            let selection = selection.as_ref();
            async move {
                let endpoint = match endpoint {
                    Some(endpoint) => endpoint,
                    None => {
                        crate::runtime::new_owned_quic_endpoint(|| match &self.endpoint_factory {
                            Some(factory) => factory(ipv6),
                            None => client_endpoint_with_mtu(ipv6, self.mtu),
                        })
                        .with_context(|| format!("create QUIC endpoint (ipv6={ipv6})"))?
                    }
                };
                if let Some(selection) = selection {
                    selection.selected_ip(server_addr.ip());
                }
                let mut last_error = None;
                // Keep retries inside one address job: the shared scheduler
                // races addresses for this node, never protocol attempts or nodes.
                for attempt in 1..=3u8 {
                    let mut observation = crate::runtime::flow_observation::TransportAttempt::start(
                        Some(server_addr), crate::runtime::flow_observation::ResolutionLocation::Unknown);
                    let connecting = match endpoint.connect_with(
                        dial_config.clone(),
                        server_addr,
                        &self.server_name,
                    ) {
                        Ok(connecting) => connecting,
                        Err(error) => {
                            if let Some(observation) = observation.as_mut() {
                                observation.finish(crate::runtime::flow_observation::TransportStatus::Failed, Some(crate::runtime::flow_observation::TransportError::QuicConnectFailed));
                            }
                            return Err(error.into());
                        }
                    };
                    match tokio::time::timeout(connect_timeout, connecting).await {
                        Err(_) => {
                            if let Some(observation) = observation.as_mut() {
                                observation.finish(crate::runtime::flow_observation::TransportStatus::Failed, Some(crate::runtime::flow_observation::TransportError::QuicConnectTimeout));
                            }
                            last_error = Some(anyhow!(
                                "QUIC connect to {server_addr} timed out (attempt {attempt})"
                            ));
                        }
                        Ok(Err(error)) => {
                            if let Some(observation) = observation.as_mut() {
                                observation.finish(crate::runtime::flow_observation::TransportStatus::Failed, Some(crate::runtime::flow_observation::TransportError::QuicConnectFailed));
                            }
                            last_error = Some(
                                crate::proxy::NodeFailure(anyhow::Error::new(error).context(
                                    format!("QUIC connect to {server_addr} (attempt {attempt})"),
                                ))
                                .into(),
                            );
                        }
                        Ok(Ok(connection)) => {
                            if let Some(observation) = observation.as_mut() {
                                observation.finish(crate::runtime::flow_observation::TransportStatus::Succeeded, None);
                            }
                            return Ok((connection, endpoint, ipv6));
                        }
                    }
                }
                Err(last_error.unwrap_or_else(|| anyhow!("QUIC connect to {server_addr} failed")))
            }
        })
        .await;
        let (conn, endpoint, ipv6) = match raced {
            Some(result) => result?,
            None => anyhow::bail!("resolve {host}: no addresses"),
        };
        state.endpoint = Some((ipv6, endpoint.clone()));
        let mut close_guard = ConnectionCloseGuard::new(conn.clone());
        let ctx = match setup(conn.clone()).await {
            Ok(ctx) => ctx,
            Err(error) => {
                close_guard.disarm();
                conn.close(VarInt::from_u32(0), b"setup failed");
                return Err(crate::proxy::quic_carrier_error(error));
            }
        };
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        let ctx = Arc::new(ctx);
        if state.quality.is_some() {
            on_publish(ctx.as_ref(), &conn);
        }
        close_guard.disarm();
        let id = state.next_connection_id;
        state.next_connection_id = state.next_connection_id.wrapping_add(1).max(1);
        let owner = Arc::downgrade(&ctx);
        let monitor = Arc::new(spawn_quic_client_connection_monitor(
            conn.clone(),
            Arc::clone(&self.flow_control_profiles),
            ipv6,
            owner.clone(),
            state.quality.clone(),
        ));
        state.connections.push(TrackedConnection {
            id,
            connection: conn.clone(),
            _endpoint: endpoint.clone(),
            state: owner.clone(),
            monitor: Arc::clone(&monitor),
        });
        spawn_tracked_connection_cleanup(
            Arc::downgrade(&self.state),
            id,
            conn.clone(),
            owner,
            monitor,
        );
        state.conn = Some((conn.clone(), Arc::clone(&ctx)));
        Ok((conn, ctx))
    }

    /// Drop the cached connection if it is `conn`, forcing the next
    /// [`connection_with`](Self::connection_with) call to re-dial. Used when a
    /// stream operation fails on a half-dead connection.
    pub async fn invalidate(&self, conn: &Connection) {
        let mut state = self.state.lock().await;
        if let Some((cached, _)) = &state.conn
            && cached.stable_id() == conn.stable_id()
        {
            state.conn = None;
        }
        state.prune_connections();
    }

    /// Release the reusable holder without closing flows that already own
    /// connection/state clones. A later dial may rebuild this client.
    pub async fn release_cached(&self) {
        let mut state = self.state.lock().await;
        state.conn = None;
        state.endpoint = None;
        state.prune_connections();
    }

    /// Close the cached connection and endpoint, terminating every flow that
    /// still owns a connection clone, and reject future dials. Awaits an
    /// in-flight dial's single-flight section so its late connection is also
    /// closed; a try-lock skip would leak that connection and endpoint driver.
    pub async fn force_close(&self) {
        let endpoint = {
            let mut state = self.state.lock().await;
            state.closed = true;
            state.conn = None;
            for tracked in state.connections.drain(..) {
                tracked
                    .connection
                    .close(VarInt::from_u32(0), b"generation shutdown");
            }
            state.endpoint.take().map(|(_, endpoint)| endpoint)
        };
        if let Some(endpoint) = endpoint {
            endpoint.close(VarInt::from_u32(0), b"generation shutdown");
        }
    }
}
