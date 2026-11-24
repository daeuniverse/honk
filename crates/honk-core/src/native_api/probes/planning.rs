use super::*;
use crate::dns::PinnedNameResolver;
use crate::observe::catalog::member_id;
use honk_config::group::GroupPolicy;
use honk_outbound::runtime::PinnedServers;

pub(super) struct Specification {
    pub(super) target: Target,
    pub(super) kind: Kind,
    pub(super) purpose: Purpose,
    pub(super) warmth: Warmth,
}
pub(super) struct Candidate {
    pub(super) node: Node,
    pub(super) ticket: ProbeTicket,
    pub(super) transport: Transport,
    pub(super) family: Family,
    pub(super) rows: Vec<usize>,
}
pub(super) struct Attempt {
    pub(super) candidate: Candidate,
    pub(super) addr: SocketAddr,
    pub(super) servers: PinnedServers,
}
pub(super) struct AddressUnavailable {
    pub(super) rows: Vec<usize>,
    pub(super) observed_at: SystemTime,
}
pub(super) struct Context {
    pub(super) spec: Specification,
    pub(super) config: Arc<Config>,
    pub(super) manager: Arc<GroupManager>,
    pub(super) identity: Arc<CatalogIdentity>,
    pub(super) registry: Arc<OutboundRuntimeRegistry>,
    pub(super) proxy_registry: Arc<honk_outbound::ProxyRegistry>,
    // Retain the DNS generation until every prepared attempt has completed.
    pub(super) dns: PinnedNameResolver,
    pub(super) group: Option<String>,
    pub(super) http: Option<http::Request<()>>,
    destination: Option<(String, u16)>,
}
pub(super) struct Plan {
    pub(super) context: Context,
    pub(super) result: ProbeResult,
    pub(super) candidates: Vec<Candidate>,
}
pub(super) struct PreparedPlan {
    pub(super) context: Context,
    pub(super) result: ProbeResult,
    pub(super) attempts: Vec<Attempt>,
    pub(super) skipped: Vec<AddressUnavailable>,
}

pub(super) fn validate(request: &ProbeRequest) -> Result<(), ApiError> {
    if match &request.target {
        Target::Node { node_id } => node_id.is_empty(),
        Target::Group { group_id } => group_id.is_empty(),
    } {
        return Err(invalid());
    }
    if request.transport.is_empty()
        || request.transport.len() > 2
        || request.transport.len() == 2 && request.transport[0] == request.transport[1]
        || matches!(request.target, Target::Node { .. }) && request.members.is_some()
    {
        return Err(invalid());
    }
    if request.kind != Kind::Dns && request.transport != [Transport::Tcp] {
        return Err(unsupported(
            "This probe kind runs over TCP only",
            json!({"field":"transport","allowed":["tcp"]}),
        ));
    }
    if let Some(Members::Ids(ids)) = &request.members {
        if ids.is_empty()
            || ids.iter().any(String::is_empty)
            || ids.iter().collect::<HashSet<_>>().len() != ids.len()
        {
            return Err(invalid());
        }
        if ids.len() > MAX_MEMBERS {
            return Err(too_large());
        }
    }
    Ok(())
}

pub(super) async fn capture(state: &NativeState, request: ProbeRequest) -> Result<Plan, ApiError> {
    // Publication holds router before config; all later owner snapshots are synchronous.
    let router = state.traffic_router.read().await;
    let config_guard = state.config.read().await;
    let config = Arc::clone(&config_guard);
    let manager = state.group_manager.read().clone();
    let registry = state.runtime_registry.read().clone();
    let identity = state.observation.core.catalog.snapshot();
    let dns = state
        .dns
        .pin_name_resolution(honk_outbound::bootstrap::BootstrapResolver::parse(
            &config.global.bootstrap_resolver,
        ))
        .map_err(|_| state.require_running().err().unwrap_or_else(unavailable))?;
    let result = plan(state, request, config, manager, registry, identity, dns);
    drop(config_guard);
    drop(router);
    result
}

fn plan(
    state: &NativeState,
    request: ProbeRequest,
    config: Arc<Config>,
    manager: Arc<GroupManager>,
    registry: Arc<OutboundRuntimeRegistry>,
    identity: Arc<CatalogIdentity>,
    dns: PinnedNameResolver,
) -> Result<Plan, ApiError> {
    let group = match &request.target {
        Target::Node { .. } => None,
        Target::Group { group_id } => Some(
            identity
                .groups
                .iter()
                .find(|(_, id)| *id == group_id)
                .map(|(name, _)| name.clone())
                .ok_or_else(not_found)?,
        ),
    };
    let members: Vec<_> = if let Some(group) = &group {
        match request.members.as_ref() {
            Some(Members::Scope(MemberScope::Leaves)) => {
                if !manager.probe_plan_within_limit(group, MAX_RESULTS) {
                    return Err(too_large());
                }
                manager
                    .probe_leaves(group, MAX_MEMBERS + 1)
                    .into_iter()
                    .map(GroupMember::Node)
                    .collect()
            }
            _ => {
                let mut members = Vec::new();
                for member in manager.group_members(group) {
                    if let Some(Members::Ids(ids)) = &request.members {
                        let id = member_id(member, &identity).ok_or_else(not_found)?;
                        if !ids.contains(&id) {
                            continue;
                        }
                    }
                    members.push(member);
                    if members.len() > MAX_MEMBERS {
                        break;
                    }
                }
                if let Some(Members::Ids(ids)) = &request.members
                    && members.len() != ids.len()
                {
                    return Err(not_found());
                }
                members
            }
        }
    } else {
        let Target::Node { node_id } = &request.target else {
            unreachable!()
        };
        vec![GroupMember::Node(
            config
                .nodes
                .iter()
                .find(|node| node.id.to_string() == *node_id)
                .ok_or_else(not_found)?,
        )]
    };
    let families: &[Family] = match request.ip_version {
        RequestedFamily::Ipv4 => &[Family::Ipv4],
        RequestedFamily::Ipv6 => &[Family::Ipv6],
        RequestedFamily::Any => &[Family::Ipv4, Family::Ipv6],
    };
    if members.len() > MAX_MEMBERS
        || members
            .len()
            .saturating_mul(families.len())
            .saturating_mul(request.transport.len())
            > MAX_RESULTS
    {
        return Err(too_large());
    }
    if members.iter().any(|member| {
        matches!(member, GroupMember::Group(child)
            if (child.policy != GroupPolicy::Selector
                || !child.groups.is_empty()
                || child.final_outbound.is_some())
                && !manager.probe_plan_within_limit(&child.name, MAX_RESULTS))
    }) {
        return Err(too_large());
    }
    let before = selections(&manager, &identity, group.as_deref());
    let mut rows = Vec::new();
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut unique: HashMap<(Uuid, Transport, Family), usize> = HashMap::new();
    for member in members {
        let member_id = member_id(member, &identity).ok_or_else(not_found)?;
        if let GroupMember::Node(node) = member {
            if request.kind == Kind::TcpConnect && (group.is_none() || !is_chain(node)) {
                tcp_connect_target(node)?;
            }
            if request.transport.contains(&Transport::Udp) && !registry.udp_capable(node) {
                return Err(tcp_only());
            }
        }
        for &transport in &request.transport {
            for &family in families {
                let domain = if transport == Transport::Tcp {
                    ProbeDomain::Tcp
                } else {
                    ProbeDomain::DnsUdp
                };
                // A group row measures its selected leaf's own transport.
                let leaf = manager.probe_leaf(member, domain, family.ip());
                // A chain in a group gets its own row rather than failing the
                // other members' TCP connect probes.
                let unavailable = match leaf {
                    None => Some("no_eligible_leaf"),
                    Some(node) if request.kind == Kind::TcpConnect && is_chain(node) => {
                        Some("no_node_address")
                    }
                    Some(_) => None,
                };
                let index = rows.len();
                rows.push(ResultRow {
                    member_id: member_id.clone(),
                    resolved_leaf_node_id: leaf.map(|node| node.id.to_string()),
                    kind: request.kind,
                    purpose: request.kind.purpose(),
                    transport,
                    ip_version: family,
                    warmth: "unknown",
                    state: if unavailable.is_some() {
                        "unavailable"
                    } else {
                        "unknown"
                    },
                    latency_ms: None,
                    health_updated: false,
                    error: Some(unavailable.unwrap_or("not_started")),
                    observed_at: timestamp(SystemTime::now()),
                });
                if let Some(node) = leaf.filter(|_| unavailable.is_none()) {
                    if request.kind == Kind::TcpConnect {
                        tcp_connect_target(node)?;
                    }
                    if request.kind != Kind::TcpConnect {
                        let entry =
                            state.proxy_registry.find(node.protocol()).ok_or_else(|| {
                                unsupported(
                                    "The probed node protocol has no HTTP or DNS probe path",
                                    json!({"field":"kind","allowed":["tcp_connect"]}),
                                )
                            })?;
                        if transport == Transport::Udp && entry.packet.is_none() {
                            return Err(tcp_only());
                        }
                    }
                    if let Some(&attempt) = unique.get(&(node.id, transport, family)) {
                        candidates[attempt].rows.push(index);
                    } else {
                        unique.insert((node.id, transport, family), candidates.len());
                        candidates.push(Candidate {
                            node: node.clone(),
                            ticket: state.alive_set.probe_ticket(node.id),
                            transport,
                            family,
                            rows: vec![index],
                        });
                    }
                }
            }
        }
    }
    let (http, destination) = match request.kind {
        Kind::TcpConnect => (None, None),
        Kind::Http => {
            const URLS: [&str; 2] = ["check_url", "tcp_check_url"];
            let unusable_url = || configured("The configured HTTP check URL is not usable", &URLS);
            let url = group
                .as_ref()
                .and_then(|name| manager.group(name))
                .and_then(|group| group.check_url.as_deref())
                .or_else(|| config.global.tcp_check_url.first().map(String::as_str))
                .ok_or_else(|| configured("No HTTP check URL is configured", &URLS))?;
            let method = &config.global.tcp_check_http_method;
            let http =
                honk_outbound::urltest::health_http_probe_request(url, method).map_err(|_| {
                    if honk_outbound::urltest::probe_method(method).is_err() {
                        configured(
                            "The configured HTTP check method is not usable",
                            &["tcp_check_http_method"],
                        )
                    } else {
                        unusable_url()
                    }
                })?;
            let host = http
                .uri()
                .host()
                .ok_or_else(unusable_url)?
                .trim_matches(['[', ']'])
                .to_owned();
            let port =
                http.uri()
                    .port_u16()
                    .unwrap_or(if http.uri().scheme_str() == Some("https") {
                        443
                    } else {
                        80
                    });
            (Some(http), Some((host, port)))
        }
        Kind::Dns => {
            let dns_check_target = || {
                configured(
                    "No usable DNS check target is configured",
                    &["udp_check_dns"],
                )
            };
            match honk_config::check::select_dns_check_target(
                config.global.effective_udp_check_dns(),
            )
            .map_err(|_| dns_check_target())?
            .ok_or_else(dns_check_target)?
            {
                honk_config::check::DnsCheckTarget::Literal(addr) => {
                    (None, Some((addr.ip().to_string(), addr.port())))
                }
                honk_config::check::DnsCheckTarget::Domain { host, port } => {
                    (None, Some((host.to_owned(), port)))
                }
            }
        }
    };
    let result = ProbeResult {
        target: request.target.clone(),
        selection_changed: TransportMap {
            tcp: false,
            udp: false,
        },
        selection_before: before.clone(),
        selection_after: before,
        results: rows,
    };
    Ok(Plan {
        context: Context {
            spec: Specification {
                target: request.target,
                kind: request.kind,
                purpose: request.kind.purpose(),
                warmth: request.warmth,
            },
            config,
            manager,
            identity,
            registry,
            proxy_registry: Arc::clone(&state.proxy_registry),
            dns,
            group,
            http,
            destination,
        },
        result,
        candidates,
    })
}

fn direct_or_block() -> ApiError {
    unsupported(
        "TCP connect probes do not apply to direct or block nodes",
        json!({"field":"kind","allowed":["http","dns"]}),
    )
}

fn tcp_connect_target(node: &honk_config::node::Node) -> Result<(), ApiError> {
    match node.protocol() {
        honk_config::types::NodeProtocol::Direct | honk_config::types::NodeProtocol::Block => {
            Err(direct_or_block())
        }
        honk_config::types::NodeProtocol::Chain => Err(unsupported(
            "TCP connect probes need a node address, which chain nodes do not have",
            json!({"field":"kind","allowed":["http","dns"]}),
        )),
        _ => Ok(()),
    }
}

fn is_chain(node: &honk_config::node::Node) -> bool {
    node.protocol() == honk_config::types::NodeProtocol::Chain
}

fn tcp_only() -> ApiError {
    unsupported(
        "The probed node does not carry UDP",
        json!({"field":"transport","allowed":["tcp"]}),
    )
}

/// The requested `kind` needs these settings, which do not yield a target.
fn configured(message: &'static str, settings: &[&str]) -> ApiError {
    unsupported(message, json!({"field":"kind","settings":settings}))
}

pub(super) fn selections(
    manager: &GroupManager,
    identity: &CatalogIdentity,
    group: Option<&str>,
) -> TransportMap<Option<String>> {
    let pick = |network| {
        group
            .and_then(|name| manager.peek_selection(name, network))
            .and_then(|selection| member_id(selection.member, identity))
    };
    TransportMap {
        tcp: pick(SelectionNetwork::Tcp),
        udp: pick(SelectionNetwork::Udp),
    }
}

#[derive(Default)]
struct ResolvedHosts {
    ordinary: HashMap<String, Vec<IpAddr>>,
    physical: HashMap<String, Option<IpAddr>>,
}

pub(super) async fn prepare(plan: Plan) -> Result<PreparedPlan, ApiError> {
    let Plan {
        context,
        result,
        candidates,
    } = plan;
    if let Some((_, port)) = context.destination.as_ref().filter(|(_, port)| *port != 0) {
        for candidate in &candidates {
            if candidate.transport != Transport::Udp {
                continue;
            }
            let (_, terminal) = context
                .proxy_registry
                .udp_probe_target(&context.registry, &candidate.node)
                .map_err(|_| tcp_only())?;
            if !honk_outbound::descriptor::udp_target_allowed(terminal, *port) {
                return Err(unsupported(
                    "The probed node does not carry UDP to the probe port",
                    json!({"field":"transport","allowed":["tcp"]}),
                ));
            }
        }
    }
    let mut resolved = ResolvedHosts::default();
    let mut attempts = Vec::with_capacity(candidates.len());
    let mut skipped = Vec::new();
    for candidate in candidates {
        let (host, port) = context
            .destination
            .as_ref()
            .map(|(host, port)| (host.as_str(), *port))
            .unwrap_or((candidate.node.host(), candidate.node.port));
        if port == 0 {
            return Err(unsupported(
                "The probe destination requires a nonzero port",
                json!({"check":"port"}),
            ));
        }
        let ips = resolve_destination(&context.dns, &mut resolved, host).await?;
        let addr = ips
            .iter()
            .copied()
            .find(|&ip| candidate.family.matches(ip))
            .map(|ip| SocketAddr::new(ip, port));
        // Only the physical entry dials a node server locally. Later hops are
        // reached through their preceding hop, which handles any domain name.
        let needs_server = addr.is_some()
            && context.spec.kind != Kind::TcpConnect
            && candidate.node.protocol() != honk_config::types::NodeProtocol::Direct;
        let servers = if needs_server {
            let chain = if is_chain(&candidate.node) {
                Some(
                    context
                        .registry
                        .get(&candidate.node.id)
                        .ok_or_else(missing_entry)?,
                )
            } else {
                None
            };
            let entry = match &chain {
                Some(chain) => chain.chain_entry_node().ok_or_else(missing_entry)?,
                None => &candidate.node,
            };
            resolve_servers(&context.dns, &mut resolved, entry).await?
        } else {
            Some(PinnedServers::default())
        };
        match (addr, servers) {
            (Some(addr), Some(servers)) => attempts.push(Attempt {
                candidate,
                addr,
                servers,
            }),
            _ => skipped.push(AddressUnavailable {
                rows: candidate.rows,
                observed_at: SystemTime::now(),
            }),
        }
    }
    Ok(PreparedPlan {
        context,
        result,
        attempts,
        skipped,
    })
}

fn missing_entry() -> ApiError {
    unsupported(
        "The probed chain has no admitted entry node",
        json!({"field":"target"}),
    )
}

async fn resolve_servers(
    dns: &PinnedNameResolver,
    resolved: &mut ResolvedHosts,
    entry: &Node,
) -> Result<Option<PinnedServers>, ApiError> {
    let upload = entry.host();
    let upload_ip = resolve_server(dns, resolved, upload).await?;
    let download = entry.xhttp_download().map(|peer| peer.address.as_str());
    // Physical server families are chosen by the resolver, independently of the
    // requested application destination family and of one another.
    let download_pin = match download {
        Some(host)
            if host
                .trim_end_matches('.')
                .eq_ignore_ascii_case(upload.trim_end_matches('.')) =>
        {
            upload_ip.map(|ip| (host, ip))
        }
        Some(host) => {
            let Some(ip) = resolve_server(dns, resolved, host).await? else {
                return Ok(None);
            };
            Some((host, ip))
        }
        None => None,
    };
    Ok(upload_ip.map(|ip| PinnedServers::new((upload, ip), download_pin)))
}

async fn resolve_destination<'a>(
    dns: &PinnedNameResolver,
    resolved: &'a mut ResolvedHosts,
    host: &str,
) -> Result<&'a [IpAddr], ApiError> {
    if !resolved.ordinary.contains_key(host) {
        let addresses = if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            vec![ip]
        } else {
            resolution_result(
                host,
                dns.resolve_node_server(host).await,
                "Resolving the probe destination was refused locally",
            )?
        };
        let mut unique = Vec::with_capacity(addresses.len());
        for ip in addresses.into_iter().map(|ip| ip.to_canonical()) {
            if !unique.contains(&ip) {
                unique.push(ip);
            }
        }
        resolved.ordinary.insert(host.to_owned(), unique);
    }
    Ok(&resolved.ordinary[host])
}

async fn resolve_server(
    dns: &PinnedNameResolver,
    resolved: &mut ResolvedHosts,
    host: &str,
) -> Result<Option<IpAddr>, ApiError> {
    if let Some(&ip) = resolved.physical.get(host) {
        return Ok(ip);
    }
    let destination_ip = resolved
        .ordinary
        .get(host)
        .and_then(|ips| ips.first().copied());
    let ip = resolution_result(
        host,
        dns.resolve_physical_server(host, destination_ip).await,
        "Resolving the probed node's server was refused locally",
    )?;
    resolved.physical.insert(host.to_owned(), ip);
    Ok(ip)
}

fn resolution_result<T: Default>(
    host: &str,
    result: anyhow::Result<T>,
    refused: &'static str,
) -> Result<T, ApiError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) if honk_outbound::proxy::is_packet_rejection(&error) => {
            Err(unsupported(refused, json!({"check":"resolution"})))
        }
        Err(error) => {
            tracing::warn!(host, error = %format_args!("{error:#}"), "probe target resolution failed");
            Ok(T::default())
        }
    }
}
