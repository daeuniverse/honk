//! The outbound a control-plane download leaves through, chosen and dialed
//! the way user traffic is: the external UI archive, geodata updates and
//! subscriptions.
//!
//! A configured detour forces the node or group it names. Otherwise the
//! target follows the routing rules: `direct` and `block` are returned for the
//! caller to handle, and any other result is a node to dial through its tunnel.
//! [`Outbounds::fetch`] makes the whole download that way.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use honk_config::Config;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use honk_outbound::alive::{IpVersion, ProbeDomain};
use honk_outbound::group::{
    ScoreAttempt, ScoreContinuation, ScoreSelectionContext, ScoreTarget, SelectionNetwork,
    SharedGroupManager,
};
use honk_outbound::proxy::{AsyncReadWrite, ProxyRegistry, TcpOutbound};
use honk_outbound::runtime::{
    EphemeralRuntimeGuard, NodeRuntime, OutboundRuntimeRegistry, SharedRuntimeRegistry,
};
use tokio::sync::RwLock;
use tokio::time::{Instant, timeout_at};
use tracing::debug;

use crate::marked_http::{self, Deadline, Reply};
use crate::routing::{ConnectionInfo, Router};

/// What a download needs to be routed like user traffic.
#[derive(Clone, Copy)]
pub(crate) struct Outbounds<'a> {
    pub(crate) router: &'a RwLock<Router>,
    pub(crate) config: &'a RwLock<std::sync::Arc<Config>>,
    pub(crate) group_manager: &'a SharedGroupManager,
    pub(crate) proxy_registry: &'a ProxyRegistry,
    pub(crate) runtime_registry: &'a SharedRuntimeRegistry,
}

/// The owned handles behind [`Outbounds`], for a download that outlives one borrow.
#[derive(Clone)]
pub(crate) struct SharedOutbounds {
    pub(crate) router: std::sync::Arc<RwLock<Router>>,
    pub(crate) config: std::sync::Arc<RwLock<std::sync::Arc<Config>>>,
    pub(crate) group_manager: SharedGroupManager,
    pub(crate) proxy_registry: std::sync::Arc<ProxyRegistry>,
    pub(crate) runtime_registry: SharedRuntimeRegistry,
}

impl SharedOutbounds {
    pub(crate) fn outbounds(&self) -> Outbounds<'_> {
        Outbounds {
            router: &self.router,
            config: &self.config,
            group_manager: &self.group_manager,
            proxy_registry: &self.proxy_registry,
            runtime_registry: &self.runtime_registry,
        }
    }
}

/// The chosen outbound has no node that can carry the download, for example
/// a group whose members a subscription has not delivered yet.
#[derive(Debug, thiserror::Error)]
#[error("outbound '{outbound}' has no available node")]
pub(crate) struct NoUsableNode {
    pub(crate) outbound: String,
}

/// Where the download goes.
pub(crate) enum Route {
    Direct {
        #[cfg_attr(
            not(feature = "clash-api"),
            allow(
                dead_code,
                reason = "only the Clash UI download reports Score feedback"
            )
        )]
        feedback: Option<ScoreAttempt>,
    },
    Block,
    Proxy {
        node: Box<Node>,
        #[cfg_attr(
            not(feature = "clash-api"),
            allow(
                dead_code,
                reason = "only the Clash UI download reports Score feedback"
            )
        )]
        feedback: Option<ScoreAttempt>,
    },
}

/// A download's `download_detour` setting.
pub(crate) enum Detour<'a> {
    /// Straight to the host, outside the routing rules.
    Direct,
    /// The routing rules decide.
    Routing,
    /// Always through the named node or group.
    Group(&'a str),
}

impl<'a> Detour<'a> {
    /// `direct`, `routing` or empty for the rules, and any other name forces that outbound.
    pub(crate) fn parse(setting: &'a str) -> Self {
        match setting {
            "direct" => Self::Direct,
            "" | "routing" => Self::Routing,
            group => Self::Group(group),
        }
    }
}

/// A route, and the group the detour or the routing rules chose, if any.
pub(crate) struct Decision {
    pub(crate) route: Route,
    pub(crate) group: Option<String>,
}

fn parse_host_ip(host: &str) -> Option<IpAddr> {
    host.parse()
        .ok()
        .or_else(|| host.strip_prefix('[')?.strip_suffix(']')?.parse().ok())
}

impl Outbounds<'_> {
    /// Runs `host:port` through `detour`, or through the routing rules when it
    /// is `None`: `Router::route_action` for the outbound name, then the
    /// authoritative group/leaf resolution for the node to dial. `setting`
    /// names the detour's setting in the log, and `purpose` the download in errors.
    pub(crate) async fn decide(
        &self,
        detour: Option<&str>,
        setting: &str,
        purpose: &str,
        (host, port): (&str, u16),
        original: Option<&ScoreContinuation>,
    ) -> anyhow::Result<Decision> {
        let host_ip = parse_host_ip(host);
        let resolved_ip = match host_ip {
            Some(ip) => Some(ip),
            None => honk_outbound::bootstrap::resolve(host)
                .await
                .ok()
                .and_then(|addresses| addresses.into_iter().next()),
        };
        let dst_ip = resolved_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let domain = host_ip.is_none().then(|| host.to_string());
        let info = ConnectionInfo {
            domain: domain.clone(),
            dst_ip,
            dst_port: port,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        };
        let (outbound, rule) = match detour {
            None => {
                let router = self.router.read().await;
                let (action, matched) = router.route_action(&info);
                let rule = matched.map(|m| format!("{}:{}", m.rule_type, m.rule_payload));
                (action.outbound.clone(), rule)
            }
            Some(detour) => (detour.to_owned(), Some(setting.to_owned())),
        };
        let target_ipver = if matches!(dst_ip, IpAddr::V6(_)) {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let score_ipver = resolved_ip.map(|ip| {
            if ip.is_ipv6() {
                IpVersion::V6
            } else {
                IpVersion::V4
            }
        });
        let (node, feedback, group) = {
            let config = self.config.read().await;
            let group_manager = self.group_manager.read().clone();
            // Generic route resolution defaults unknown outputs to direct; an
            // explicitly configured detour must not bypass that operator error.
            if detour.is_some()
                && config.builtin_node(&outbound).is_none()
                && !config.nodes.iter().any(|node| node.name == outbound)
                && !config.groups.iter().any(|group| group.name == outbound)
            {
                anyhow::bail!("{purpose}: detour outbound '{outbound}' not found");
            }
            let group = config
                .groups
                .iter()
                .any(|group| group.name == outbound)
                .then(|| outbound.clone());
            if group.is_some() {
                let context = ScoreSelectionContext {
                    network: SelectionNetwork::Tcp,
                    probe_domain: ProbeDomain::Tcp,
                    target_family: score_ipver,
                    health_family: score_ipver.unwrap_or(target_ipver),
                    target: Some(if domain.is_some() {
                        ScoreTarget::domain(host, port)
                    } else {
                        SocketAddr::new(dst_ip, port).into()
                    }),
                };
                let plan = group_manager
                    .selection_plan_for_target_with_health_fallback(&outbound, &context, original);
                match plan.entries.into_iter().next() {
                    Some(entry) => (Some(entry.node.clone()), entry.feedback, group),
                    None => (None, None, group),
                }
            } else {
                let nodes = crate::control::reload::resolve_outbound_nodes(
                    &config,
                    &group_manager,
                    &outbound,
                    ProbeDomain::Tcp,
                    target_ipver,
                );
                (nodes.into_iter().next(), None, None)
            }
        };
        let Some(node) = node else {
            return Err(anyhow::Error::new(NoUsableNode { outbound }).context(purpose.to_owned()));
        };
        let route = match node.protocol() {
            NodeProtocol::Direct => Route::Direct { feedback },
            NodeProtocol::Block => Route::Block,
            _ => Route::Proxy {
                node: Box::new(node),
                feedback,
            },
        };
        debug!(
            outbound = %outbound,
            rule = rule.as_deref().unwrap_or("fallback"),
            via = match &route {
                Route::Direct { .. } => "direct",
                Route::Block => "block",
                Route::Proxy { node, .. } => node.name.as_str(),
            },
            "{purpose} routed"
        );
        Ok(Decision { route, group })
    }

    /// Prepares a tunnel through `node` to `host:port`. Tunnel handlers dial
    /// by domain, so the node's egress resolves it and local DNS poisoning
    /// does not matter; the address is only a fallback for handlers that need one.
    pub(crate) async fn tunnel(
        &self,
        node: &Node,
        (host, port): (&str, u16),
    ) -> anyhow::Result<Tunnel> {
        let protocol = node.protocol();
        let entry = self
            .proxy_registry
            .find(protocol)
            .ok_or_else(|| anyhow::anyhow!("no handler for protocol {protocol:?}"))?;
        let connect_timeout =
            Duration::from_millis(self.config.read().await.global.connect_timeout_ms);
        let (domain, addr) = match parse_host_ip(host) {
            Some(ip) => (None, SocketAddr::new(ip, port)),
            None => (
                Some(host.to_owned()),
                SocketAddr::from(([0, 0, 0, 0], port)),
            ),
        };
        let generation = self.runtime_registry.read().clone();
        let (runtime, guard) = honk_outbound::urltest::try_probe_runtime(
            &generation,
            node,
            honk_outbound::proxy::WarmRequirement::Session,
        )?;
        Ok(Tunnel {
            generation,
            runtime,
            guard,
            tcp: std::sync::Arc::clone(&entry.tcp),
            connect_timeout,
            addr,
            domain,
        })
    }
}

/// A node's tunnel to one target. The disposable runtime it may own lives
/// until [`Tunnel::close`], after the stream is done.
pub(crate) struct Tunnel {
    generation: std::sync::Arc<OutboundRuntimeRegistry>,
    runtime: std::sync::Arc<NodeRuntime>,
    guard: Option<EphemeralRuntimeGuard>,
    tcp: std::sync::Arc<dyn TcpOutbound>,
    connect_timeout: Duration,
    addr: SocketAddr,
    domain: Option<String>,
}

impl Tunnel {
    pub(crate) async fn dial(&self) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let proxy = self
            .generation
            .scope_dials(self.tcp.dial_runtime(
                std::sync::Arc::clone(&self.runtime),
                self.addr,
                self.domain.as_deref(),
                self.connect_timeout,
            ))
            .await?;
        Ok(proxy.stream)
    }

    pub(crate) async fn close(mut self) -> anyhow::Result<()> {
        if let Some(guard) = self.guard.as_mut() {
            guard.close().await?;
        }
        Ok(())
    }
}

/// One GET a download makes.
pub(crate) struct Request<'a> {
    pub(crate) url: &'a reqwest::Url,
    pub(crate) headers: &'a http::HeaderMap,
    /// Which answers' bodies are read, as in [`marked_http::read`].
    pub(crate) wants_body: fn(http::StatusCode, &http::HeaderMap) -> bool,
    pub(crate) deadline: Deadline,
    pub(crate) max_bytes: usize,
    /// The only resolver a direct host name is resolved with; `None` uses the
    /// process bootstrap resolver and its system fallback.
    pub(crate) bootstrap: Option<&'a str>,
}

/// Why a routed download failed.
pub(crate) enum Failed {
    /// The detour names no outbound, or the chosen one has no usable node.
    Route(anyhow::Error),
    /// The stage that failed.
    Stage(&'static str),
}

impl From<&'static str> for Failed {
    fn from(stage: &'static str) -> Self {
        Self::Stage(stage)
    }
}

impl Outbounds<'_> {
    /// Makes `request` through `detour`: straight to its host, or through the
    /// node the detour or the routing rules choose, whose tunnel is closed
    /// after. Also returns the group the route went through. `setting` and
    /// `purpose` are as in [`Self::decide`]. Setup has to finish by the
    /// deadline's `headers`.
    pub(crate) async fn fetch(
        &self,
        detour: Detour<'_>,
        setting: &str,
        purpose: &str,
        request: &Request<'_>,
    ) -> Result<(Reply, Option<String>), Failed> {
        let detour = match detour {
            Detour::Direct => return Ok((fetch_direct(request).await?, None)),
            Detour::Routing => None,
            Detour::Group(group) => Some(group),
        };
        let host = request.url.host_str().ok_or("invalid_source")?;
        let port = request
            .url
            .port_or_known_default()
            .ok_or("invalid_source")?;
        let by = request.deadline.headers;
        let decision = timeout_at(
            by,
            self.decide(detour, setting, purpose, (host, port), None),
        )
        .await
        .map_err(|_| "download_timeout")?
        .map_err(Failed::Route)?;
        let reply = match decision.route {
            Route::Block => return Err("route_blocked".into()),
            Route::Direct { .. } => fetch_direct(request).await?,
            Route::Proxy { node, .. } => {
                let tunnel = match timeout_at(by, self.tunnel(&node, (host, port))).await {
                    Err(_) => return Err("download_timeout".into()),
                    Ok(Err(error)) => {
                        debug!(%error, node = %node.name, "{purpose} tunnel setup failed");
                        return Err("connection_failed".into());
                    }
                    Ok(Ok(tunnel)) => tunnel,
                };
                let reply = match timeout_at(by, tunnel.dial()).await {
                    Err(_) => Err("download_timeout"),
                    Ok(Err(error)) => {
                        debug!(%error, node = %node.name, "{purpose} tunnel dial failed");
                        Err("connection_failed")
                    }
                    Ok(Ok(stream)) => get(stream, request).await,
                };
                if let Err(error) = tunnel.close().await {
                    debug!(%error, "{purpose} tunnel did not close cleanly");
                }
                reply?
            }
        };
        Ok((reply, decision.group))
    }
}

/// Makes `request` straight to its host over the bypass mark, on the first
/// resolved address that accepts the connection.
pub(crate) async fn fetch_direct(request: &Request<'_>) -> Result<Reply, &'static str> {
    let by = request.deadline.headers;
    let host = request
        .url
        .host_str()
        .ok_or("invalid_source")?
        .trim_matches(['[', ']']);
    let port = request
        .url
        .port_or_known_default()
        .ok_or("invalid_source")?;
    let addresses = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => {
            let resolved = match request.bootstrap {
                Some(bootstrap) => {
                    let resolver = honk_outbound::bootstrap::BootstrapResolver::parse(bootstrap)
                        .ok_or("bootstrap_unavailable")?;
                    timeout_at(by, resolver.query(host)).await
                }
                None => timeout_at(by, honk_outbound::bootstrap::resolve(host)).await,
            };
            resolved
                .map_err(|_| "download_timeout")?
                .map_err(|_| "resolution_failed")?
        }
    };
    for ip in addresses {
        let connected = timeout_at(
            by,
            honk_outbound::util::connect_marked_addr(
                SocketAddr::new(ip, port),
                Some(honk_outbound::util::bypass_mark()),
                by.saturating_duration_since(Instant::now()),
            ),
        )
        .await
        .map_err(|_| "download_timeout")?;
        if let Ok(stream) = connected {
            return get(Box::new(stream), request).await;
        }
    }
    Err("connection_failed")
}

async fn get(
    stream: Box<dyn AsyncReadWrite>,
    request: &Request<'_>,
) -> Result<Reply, &'static str> {
    // Built once, and only for https: plain http must not load the CA store.
    static TLS: std::sync::OnceLock<marked_http::Client> = std::sync::OnceLock::new();
    let plain;
    let client = if request.url.scheme() == "https" {
        match TLS.get() {
            Some(client) => client,
            None => {
                let client = marked_http::Client::new().map_err(|_| "tls_failed")?;
                TLS.get_or_init(|| client)
            }
        }
    } else {
        plain = marked_http::Client::plain();
        &plain
    };
    let prepared = client
        .prepare_over(
            stream,
            request.url,
            request.headers,
            request.deadline.headers,
        )
        .await
        .map_err(|error| error.stage)?;
    let response = timeout_at(request.deadline.headers, marked_http::send(prepared))
        .await
        .map_err(|_| "download_timeout")?
        .map_err(|error| error.stage)?;
    marked_http::read(
        response,
        request.wants_body,
        request.deadline,
        request.max_bytes,
    )
    .await
    .map_err(|error| error.stage)
}
