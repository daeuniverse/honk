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
use honk_config::types::NodeProtocol;
use honk_outbound::alive::{IpVersion, ProbeDomain, RouteHealthRevision, RouteHealthStamp};
use honk_outbound::group::{
    GroupManager, OwnedTarget, ScoreAttempt, ScoreBusinessGuard, ScoreContinuation, ScoreOutcome,
    ScoreSelectionContext, ScoreTarget, SelectionNetwork, SharedGroupManager, Target,
};
use honk_outbound::proxy::{AsyncReadWrite, ProxyRegistry, TcpOutbound};
use honk_outbound::runtime::{
    EphemeralRuntimeGuard, NodeRuntime, OutboundRuntimeRegistry, SharedRuntimeRegistry,
};
use tokio::sync::RwLock;
use tokio::time::{Instant, timeout_at};
use tracing::{debug, warn};

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
        feedback: Option<ScoreAttempt>,
    },
    Block,
    Proxy {
        proxy: Box<DownloadProxy>,
        feedback: Option<ScoreAttempt>,
    },
}

pub(crate) struct DownloadProxy {
    pub(crate) target: OwnedTarget,
    generation: std::sync::Arc<OutboundRuntimeRegistry>,
    connect_timeout: Duration,
    health: Option<DownloadHealthRoute>,
}

struct DownloadHealthRoute {
    manager: std::sync::Arc<GroupManager>,
    group: String,
    family: IpVersion,
    revision: RouteHealthRevision,
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
    /// `strict_resolver`, when set, is the only resolver the host is looked up
    /// with, without the system fallback; unusable, it leaves the address unknown.
    pub(crate) async fn decide(
        &self,
        detour: Option<&str>,
        setting: &str,
        purpose: &str,
        (host, port): (&str, u16),
        original: Option<&ScoreContinuation>,
        strict_resolver: Option<&str>,
    ) -> anyhow::Result<Decision> {
        let host_ip = parse_host_ip(host);
        let resolved = match (host_ip, strict_resolver) {
            (Some(ip), _) => Ok(vec![ip]),
            (None, Some(resolver)) => {
                match honk_outbound::bootstrap::BootstrapResolver::parse(resolver) {
                    Some(resolver) => resolver.query(host).await,
                    None => Err(std::io::ErrorKind::NotFound.into()),
                }
            }
            (None, None) => honk_outbound::bootstrap::resolve(host).await,
        };
        let resolved_ip = resolved
            .ok()
            .and_then(|addresses| addresses.into_iter().next());
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
        // Reload publishes router, config, groups and runtimes under these locks, in this order.
        let router = self.router.read().await;
        let config = self.config.read().await;
        let (outbound, rule) = match detour {
            None => {
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
        let group_manager = self.group_manager.read().clone();
        let (node, feedback, group, health_family, revision) = {
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
                let (plan, revision) =
                    group_manager.dial_plan_for_target(&outbound, &context, original);
                let health_family = plan.health_family;
                match plan.entries.into_iter().next() {
                    Some(entry) => {
                        let mut target = group_manager.own_target(Target {
                            node: entry.node,
                            route: entry.route,
                        });
                        target.collapse = entry.collapse;
                        (Some(target), entry.feedback, group, health_family, revision)
                    }
                    None => (None, None, group, health_family, revision),
                }
            } else {
                let node = config.builtin_node(&outbound).or_else(|| {
                    config
                        .nodes
                        .iter()
                        .find(|node| node.name == outbound)
                        .cloned()
                });
                let node = match node {
                    Some(node) => node,
                    None if detour.is_some() => {
                        anyhow::bail!("{purpose}: detour outbound '{outbound}' not found");
                    }
                    None => {
                        warn!("Outbound '{}' not found, falling back to direct", outbound);
                        Config::builtin_direct_node()
                    }
                };
                (
                    Some(OwnedTarget::node(node)),
                    None,
                    None,
                    target_ipver,
                    RouteHealthRevision::default(),
                )
            }
        };
        let Some(node) = node else {
            return Err(anyhow::Error::new(NoUsableNode { outbound }).context(purpose.to_owned()));
        };
        let route = match node.node.protocol() {
            NodeProtocol::Direct if node.route.is_none() => Route::Direct { feedback },
            NodeProtocol::Block => Route::Block,
            _ => Route::Proxy {
                proxy: Box::new(DownloadProxy {
                    health: group
                        .as_ref()
                        .filter(|_| node.uses_route_evidence())
                        .map(|group| DownloadHealthRoute {
                            manager: group_manager,
                            group: group.clone(),
                            family: health_family,
                            revision,
                        }),
                    target: node,
                    generation: self.runtime_registry.read().clone(),
                    connect_timeout: Duration::from_millis(config.global.connect_timeout_ms),
                }),
                feedback,
            },
        };
        debug!(
            outbound = %outbound,
            rule = rule.as_deref().unwrap_or("fallback"),
            via = match &route {
                Route::Direct { .. } => "direct",
                Route::Block => "block",
                Route::Proxy { proxy, .. } => proxy.target.node.name.as_str(),
            },
            "{purpose} routed"
        );
        Ok(Decision { route, group })
    }
}

impl DownloadProxy {
    pub(crate) fn admit_route_health(&self) -> Option<RouteHealthStamp> {
        self.health.as_ref().map(|route| route.revision.admit())
    }

    pub(crate) fn report_route_outcome(
        &self,
        stamp: Option<RouteHealthStamp>,
        outcome: Result<(), &(dyn std::error::Error + 'static)>,
    ) {
        let (Some(route), Some(stamp)) = (&self.health, stamp) else {
            return;
        };
        if self.generation.is_shutdown() {
            return;
        }
        match outcome {
            Ok(()) => {
                route.manager.report_route_response(
                    &route.group,
                    self.target.key(),
                    route.family,
                    stamp,
                    None,
                );
            }
            Err(error) => {
                route.manager.report_route_failure(
                    &route.group,
                    &self.target,
                    route.family,
                    stamp,
                    error,
                );
            }
        }
    }

    /// Prepares a tunnel through `target` to `host:port`. Tunnel handlers dial
    /// by domain, so the node's egress resolves it and local DNS poisoning
    /// does not matter; the address is only a fallback for handlers that need one.
    pub(crate) fn tunnel<'a>(
        &self,
        registry: &'a ProxyRegistry,
        (host, port): (&str, u16),
    ) -> anyhow::Result<Tunnel<'a>> {
        let (domain, addr) = match parse_host_ip(host) {
            Some(ip) => (None, SocketAddr::new(ip, port)),
            None => (
                Some(host.to_owned()),
                SocketAddr::from(([0, 0, 0, 0], port)),
            ),
        };
        let via = match self.target.route() {
            Some(route) => TunnelVia::Route {
                registry,
                route: *route,
            },
            None => {
                let node = &self.target.node;
                let protocol = node.protocol();
                let entry = registry
                    .find(protocol)
                    .ok_or(honk_outbound::proxy::MissingProtocolHandler(protocol))?;
                let (runtime, guard) = honk_outbound::urltest::try_probe_runtime(
                    &self.generation,
                    node,
                    honk_outbound::proxy::WarmRequirement::Session,
                )?;
                TunnelVia::Node {
                    runtime,
                    guard,
                    tcp: std::sync::Arc::clone(&entry.tcp),
                }
            }
        };
        Ok(Tunnel {
            generation: self.generation.clone(),
            via,
            connect_timeout: self.connect_timeout,
            addr,
            domain,
        })
    }
}

/// A node's or a route's tunnel to one target. The disposable runtime a
/// node's tunnel may own lives until [`Tunnel::close`], after the stream is
/// done.
pub(crate) struct Tunnel<'a> {
    generation: std::sync::Arc<OutboundRuntimeRegistry>,
    via: TunnelVia<'a>,
    connect_timeout: Duration,
    addr: SocketAddr,
    domain: Option<String>,
}

enum TunnelVia<'a> {
    Node {
        runtime: std::sync::Arc<NodeRuntime>,
        guard: Option<EphemeralRuntimeGuard>,
        tcp: std::sync::Arc<dyn TcpOutbound>,
    },
    Route {
        registry: &'a ProxyRegistry,
        route: honk_config::route::Route,
    },
}

impl Tunnel<'_> {
    pub(crate) async fn dial(&self) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let proxy = match &self.via {
            TunnelVia::Node { runtime, tcp, .. } => {
                if self.generation.is_shutdown() {
                    return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
                }
                self.generation
                    .scope_dials(tcp.dial_runtime(
                        std::sync::Arc::clone(runtime),
                        self.addr,
                        self.domain.as_deref(),
                        self.connect_timeout,
                    ))
                    .await
            }
            TunnelVia::Route { registry, route } => {
                registry
                    .dial_ref(
                        std::sync::Arc::clone(&self.generation),
                        honk_outbound::proxy::DialRef::Route(route),
                        self.addr,
                        self.domain.as_deref(),
                        self.connect_timeout,
                    )
                    .await
            }
        };
        if self.generation.is_shutdown() {
            return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
        }
        Ok(proxy?.stream)
    }

    pub(crate) async fn close(mut self) -> anyhow::Result<()> {
        if let TunnelVia::Node {
            guard: Some(guard), ..
        } = &mut self.via
        {
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

/// The stage of a download the server answered with `status`: a 404 is told
/// apart because it is what a removed file or an expired link gives.
pub(crate) fn status_stage(status: http::StatusCode) -> &'static str {
    match status {
        http::StatusCode::NOT_FOUND => "http_not_found",
        _ => "http_status_rejected",
    }
}

/// The outbound a download went through: the node that carried it, and the
/// group that chose the node when one did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Via {
    pub(crate) node: String,
    pub(crate) group: Option<String>,
}

impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node '{}'", self.node)?;
        match &self.group {
            Some(group) => write!(f, " of group '{group}'"),
            None => Ok(()),
        }
    }
}

/// Why a routed download failed.
pub(crate) enum Failed {
    /// The detour names no outbound, or the chosen one has no usable node.
    Route(anyhow::Error),
    /// The stage that failed, and the outbound it went through; `None` before
    /// a node was chosen and for direct downloads.
    Stage(&'static str, Option<Via>),
}

impl From<&'static str> for Failed {
    fn from(stage: &'static str) -> Self {
        Self::Stage(stage, None)
    }
}

impl Outbounds<'_> {
    /// Makes `request` through `detour`: straight to its host, or through the
    /// node the detour or the routing rules choose, whose tunnel is closed
    /// after. Also returns the group and the node the route went through. `setting` and
    /// `purpose` are as in [`Self::decide`]. Setup has to finish by the
    /// deadline's `headers`. `original` is the first admitted Score business of
    /// a redirect chain; later hops of the chain continue it instead of
    /// starting new business.
    pub(crate) async fn fetch(
        &self,
        detour: Detour<'_>,
        setting: &str,
        purpose: &str,
        request: &Request<'_>,
        original: &mut Option<ScoreContinuation>,
    ) -> Result<(Reply, Option<String>, Option<Via>), Failed> {
        let (detour, strict_resolver) = match detour {
            Detour::Direct => return Ok((fetch_direct(request).await?, None, None)),
            Detour::Routing => (None, None),
            Detour::Group(group) => (Some(group), request.bootstrap),
        };
        let host = request.url.host_str().ok_or("invalid_source")?;
        let port = request
            .url
            .port_or_known_default()
            .ok_or("invalid_source")?;
        let by = request.deadline.headers;
        let decision = timeout_at(
            by,
            self.decide(
                detour,
                setting,
                purpose,
                (host, port),
                original.as_ref(),
                strict_resolver,
            ),
        )
        .await
        .map_err(|_| "download_timeout")?
        .map_err(Failed::Route)?;
        let (proxy, feedback) = match decision.route {
            Route::Block => return Err("route_blocked".into()),
            Route::Direct { feedback } => (None, feedback),
            Route::Proxy { proxy, feedback } => (Some(proxy), feedback),
        };
        let business = admit(
            feedback.as_ref(),
            original,
            decision.group.as_deref(),
            purpose,
        )?;
        let via = proxy.as_ref().map(|proxy| Via {
            node: proxy.target.node.name.clone(),
            group: decision.group.clone(),
        });
        let reply = match proxy {
            None => {
                let reply = fetch_direct(request).await;
                if let Some(business) = business {
                    business.finish(settlement(&reply));
                }
                reply
            }
            Some(proxy) => self.fetch_through(&proxy, purpose, request, business).await,
        };
        let reply = match reply {
            Ok(reply) => reply,
            Err(stage) => return Err(Failed::Stage(stage, via)),
        };
        Ok((reply, decision.group, via))
    }

    async fn fetch_through(
        &self,
        proxy: &DownloadProxy,
        purpose: &str,
        request: &Request<'_>,
        business: Option<ScoreBusinessGuard>,
    ) -> Result<Reply, &'static str> {
        let mut stamp = None;
        let reply = async {
            let host = request.url.host_str().ok_or("invalid_source")?;
            let port = request
                .url
                .port_or_known_default()
                .ok_or("invalid_source")?;
            let by = request.deadline.headers;
            let node = &proxy.target.node;
            let tunnel = proxy
                .tunnel(self.proxy_registry, (host, port))
                .map_err(|error| {
                    debug!(%error, node = %node.name, "{purpose} tunnel setup failed");
                    marked_http::Error::caused("connection_failed", error)
                })?;
            stamp = proxy.admit_route_health();
            let reply = match timeout_at(by, tunnel.dial()).await {
                Err(_) => Err("download_timeout".into()),
                Ok(Err(error)) => {
                    debug!(%error, node = %node.name, "{purpose} tunnel dial failed");
                    Err(marked_http::Error::caused("connection_failed", error))
                }
                Ok(Ok(stream)) => get(stream, request).await,
            };
            if let Err(error) = tunnel.close().await {
                debug!(%error, "{purpose} tunnel did not close cleanly");
            }
            reply
        }
        .await;
        if let Some(business) = business {
            let outcome = match &reply {
                Ok(_) => ScoreOutcome::Success,
                Err(_) if stamp.is_none() && proxy.target.uses_route_evidence() => {
                    ScoreOutcome::Rejected
                }
                Err(error) if proxy.target.uses_route_evidence() => {
                    let outcome = error
                        .source
                        .as_ref()
                        .map_or_else(|| failed_settlement(error.stage), ScoreOutcome::from_error);
                    proxy.target.score_failure(outcome, error)
                }
                Err(error) => failed_settlement(error.stage),
            };
            business.finish(outcome);
        }
        proxy.report_route_outcome(
            stamp,
            reply
                .as_ref()
                .map(|_| ())
                .map_err(|error| error as &dyn std::error::Error),
        );
        reply.map_err(|error| error.stage)
    }
}

/// Admits the planned Score business before the download runs. Admission is
/// refused when the selected node left its pool since the plan, so the route
/// has no usable node. The first admitted business of a chain becomes its
/// `original`.
pub(crate) fn admit(
    feedback: Option<&ScoreAttempt>,
    original: &mut Option<ScoreContinuation>,
    group: Option<&str>,
    purpose: &str,
) -> Result<Option<ScoreBusinessGuard>, Failed> {
    let business = feedback.map(ScoreAttempt::begin).transpose().map_err(|_| {
        Failed::Route(
            anyhow::Error::new(NoUsableNode {
                outbound: group.unwrap_or_default().to_owned(),
            })
            .context(purpose.to_owned()),
        )
    })?;
    if let Some(business) = &business {
        original.get_or_insert_with(|| business.continuation());
    }
    Ok(business)
}

/// Score settlement for downloads carrying only the public failure stage.
pub(crate) fn settlement(reply: &Result<Reply, &'static str>) -> ScoreOutcome {
    match reply {
        Ok(_) => ScoreOutcome::Success,
        Err(stage) => failed_settlement(stage),
    }
}

fn failed_settlement(stage: &str) -> ScoreOutcome {
    match stage {
        "download_timeout" => ScoreOutcome::Timeout,
        _ => ScoreOutcome::Other,
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
    let addresses: Vec<_> = addresses
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    let stream = connect_direct(&addresses, by).await?;
    get(Box::new(stream), request)
        .await
        .map_err(|error| error.stage)
}

/// A connection to the first of `addresses` that accepts, racing them like a
/// proxy server's, so a blackholed address does not use up the deadline.
async fn connect_direct(
    addresses: &[SocketAddr],
    by: Instant,
) -> Result<tokio::net::TcpStream, &'static str> {
    timeout_at(
        by,
        honk_outbound::util::connect_marked_resolved(
            addresses,
            Some(honk_outbound::util::bypass_mark()),
            by.saturating_duration_since(Instant::now()),
        ),
    )
    .await
    .map_err(|_| "download_timeout")?
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::TimedOut => "download_timeout",
        _ => "connection_failed",
    })
}

async fn get(
    stream: Box<dyn AsyncReadWrite>,
    request: &Request<'_>,
) -> Result<Reply, marked_http::Error> {
    // Built once, and only for https: plain http must not load the CA store.
    static TLS: std::sync::OnceLock<marked_http::Client> = std::sync::OnceLock::new();
    let plain;
    let client = if request.url.scheme() == "https" {
        match TLS.get() {
            Some(client) => client,
            None => {
                let client = marked_http::Client::new()
                    .map_err(|error| marked_http::Error::caused("tls_failed", error))?;
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
        .await?;
    let response = timeout_at(request.deadline.headers, marked_http::send(prepared))
        .await
        .map_err(|_| "download_timeout")??;
    marked_http::read(
        response,
        request.wants_body,
        request.deadline,
        request.max_bytes,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tokio::time::Instant;

    /// A listener whose accept queue is full, so further connects hang.
    fn blackhole() -> (socket2::Socket, Vec<std::net::TcpStream>) {
        let listener =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        listener
            .bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
            .unwrap();
        listener.listen(0).unwrap();
        let address = listener.local_addr().unwrap().as_socket().unwrap();
        let fillers = (0..4)
            .map(|_| {
                let socket =
                    socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
                        .unwrap();
                socket.set_nonblocking(true).unwrap();
                let _ = socket.connect(&address.into());
                socket.into()
            })
            .collect();
        (listener, fillers)
    }

    #[tokio::test]
    async fn a_blackholed_first_address_does_not_use_up_the_deadline() {
        let (blackhole, _fillers) = blackhole();
        let first = blackhole.local_addr().unwrap().as_socket().unwrap();
        let healthy = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), first.port()))
            .await
            .unwrap();
        let second = healthy.local_addr().unwrap();

        let stream =
            super::connect_direct(&[first, second], Instant::now() + Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), second);
    }
}
