use super::*;
use crate::dns::PinnedNameResolver;
use crate::observe::catalog::member_id;

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
    pub(super) server: Option<IpAddr>,
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
        .pin_name_resolution()
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
                // Only this scope expands descendants; a child group otherwise probes its one selected leaf.
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
    let before = selections(&manager, &identity, group.as_deref());
    let mut rows = Vec::new();
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut unique: HashMap<(Uuid, Transport, Family), usize> = HashMap::new();
    for member in members {
        let member_id = member_id(member, &identity).ok_or_else(not_found)?;
        if let GroupMember::Node(node) = member {
            if request.kind == Kind::TcpConnect
                && matches!(
                    node.protocol(),
                    honk_config::types::NodeProtocol::Direct
                        | honk_config::types::NodeProtocol::Block
                )
            {
                return Err(direct_or_block());
            }
            if request.transport.contains(&Transport::Udp)
                && !(honk_outbound::descriptor::descriptor(node.protocol()).supports_udp)(node)
            {
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
                let leaf = manager.probe_leaf(member, domain, family.ip());
                let index = rows.len();
                rows.push(ResultRow {
                    member_id: member_id.clone(),
                    resolved_leaf_node_id: leaf.map(|node| node.id.to_string()),
                    kind: request.kind,
                    purpose: request.kind.purpose(),
                    transport,
                    ip_version: family,
                    warmth: "unknown",
                    state: if leaf.is_some() {
                        "unknown"
                    } else {
                        "unavailable"
                    },
                    latency_ms: None,
                    health_updated: false,
                    error: Some(if leaf.is_some() {
                        "not_started"
                    } else {
                        "no_eligible_leaf"
                    }),
                    observed_at: timestamp(SystemTime::now()),
                });
                if let Some(node) = leaf {
                    if request.kind == Kind::TcpConnect
                        && matches!(
                            node.protocol(),
                            honk_config::types::NodeProtocol::Direct
                                | honk_config::types::NodeProtocol::Block
                        )
                    {
                        return Err(direct_or_block());
                    }
                    if request.kind != Kind::TcpConnect {
                        let entry =
                            state.proxy_registry.find(node.protocol()).ok_or_else(|| {
                                unsupported(
                                    "The probed node protocol has no HTTP or DNS probe path",
                                    json!({"field":"kind","allowed":["tcp_connect"]}),
                                )
                            })?;
                        if transport == Transport::Udp
                            && (!(entry.descriptor.supports_udp)(node) || entry.packet.is_none())
                        {
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
            match honk_config::check::select_dns_check_target(&config.global.udp_check_dns)
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

pub(super) async fn prepare(plan: Plan) -> Result<PreparedPlan, ApiError> {
    let Plan {
        context,
        result,
        candidates,
    } = plan;
    let mut resolved = HashMap::new();
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
        let ips = resolve(
            &context.dns,
            &mut resolved,
            host,
            "Resolving the probe destination was refused locally",
        )
        .await?;
        let addr = ips
            .iter()
            .copied()
            .find(|&ip| candidate.family.matches(ip))
            .map(|ip| SocketAddr::new(ip, port));
        let needs_server = context.spec.kind != Kind::TcpConnect
            && candidate.node.protocol() != honk_config::types::NodeProtocol::Direct;
        let server = if needs_server {
            let ips = resolve(
                &context.dns,
                &mut resolved,
                candidate.node.host(),
                "Resolving the probed node's server was refused locally",
            )
            .await?;
            ips.first().copied()
        } else {
            None
        };
        if candidate.transport == Transport::Udp
            && !honk_outbound::descriptor::udp_target_allowed(&candidate.node, port)
        {
            return Err(unsupported(
                "The probed node does not carry UDP to the probe port",
                json!({"field":"transport","allowed":["tcp"]}),
            ));
        }
        match addr {
            Some(addr) if !needs_server || server.is_some() => {
                attempts.push(Attempt {
                    candidate,
                    addr,
                    server,
                });
            }
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

async fn resolve<'a>(
    dns: &PinnedNameResolver,
    resolved: &'a mut HashMap<String, Vec<IpAddr>>,
    host: &str,
    refused: &'static str,
) -> Result<&'a [IpAddr], ApiError> {
    if !resolved.contains_key(host) {
        let addresses = if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            vec![ip]
        } else {
            match dns.resolve(host).await {
                Ok(addresses) => addresses,
                Err(error) if honk_outbound::proxy::is_packet_rejection(&error) => {
                    return Err(unsupported(refused, json!({"check":"resolution"})));
                }
                Err(_) => Vec::new(),
            }
        };
        let mut unique = Vec::with_capacity(addresses.len());
        for ip in addresses.into_iter().map(|ip| ip.to_canonical()) {
            if !unique.contains(&ip) {
                unique.push(ip);
            }
        }
        resolved.insert(host.to_owned(), unique);
    }
    Ok(&resolved[host])
}
