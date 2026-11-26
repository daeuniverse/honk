use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use honk_config::node::Node;
use honk_config::types::{DnsProtocol, NodeProtocol};
use honk_outbound::alive::{IpVersion, ProbeDomain, RouteHealthRevision};
use honk_outbound::group::GroupManager;
use honk_outbound::group::{
    OwnedTarget, ScoreAttempt, ScoreContinuation, ScoreSelectionContext, ScoreTarget,
    SelectionNetwork, Target,
};
use honk_outbound::proxy::PacketRejection;
use tracing::debug;

use super::UpstreamPool;
use super::entries::UpstreamEntry;
use crate::dns::transport::{RouteExchange, RouteFailures, TcpRouteExchange};
use crate::routing::ConnectionInfo;

fn policy_block(reason: &'static str) -> anyhow::Error {
    crate::observe::flows::dns::decision("rejected", Some("policy_block"));
    anyhow::Error::new(PacketRejection::Policy).context(reason)
}

impl UpstreamEntry {
    pub(super) fn check_explicit_block(&self) -> anyhow::Result<()> {
        if self
            .outbound
            .as_deref()
            .is_some_and(|tag| tag.eq_ignore_ascii_case("block"))
        {
            return Err(policy_block(
                "DNS upstream outbound 'block' rejected the dial",
            ));
        }
        Ok(())
    }
}

pub(super) struct DnsDialRoute {
    pub(super) target: SocketAddr,
    /// The selected node or route; `None` dials direct.
    pub(super) node: Option<OwnedTarget>,
    pub(super) feedback: Option<ScoreAttempt>,
    pub(super) observation: Option<crate::observe::flows::record::OutboundAttempt>,
    health: Option<SelectedRouteHealth>,
}

struct SelectedRouteHealth {
    manager: Arc<GroupManager>,
    group: String,
    family: IpVersion,
    revision: RouteHealthRevision,
}

impl DnsDialRoute {
    pub(super) fn route_exchange<'a>(
        &'a self,
        protocol: DnsProtocol,
        reported_failures: &'a mut RouteFailures,
    ) -> Option<RouteExchange<'a>> {
        let target = self.node.as_ref()?;
        let Some(health) = self.health.as_ref() else {
            return (target.uses_route_evidence()
                || matches!(protocol, DnsProtocol::Quic | DnsProtocol::H3)
                    && target.node.resolved_chain_hops().is_some())
            .then_some(RouteExchange::Packet(target));
        };
        Some(RouteExchange::Tcp(TcpRouteExchange {
            manager: &health.manager,
            group: &health.group,
            family: health.family,
            revision: health.revision,
            target,
            reported_failures,
        }))
    }
}

#[derive(Default)]
struct SelectedLeaf {
    node: Option<OwnedTarget>,
    feedback: Option<ScoreAttempt>,
    health: Option<SelectedRouteHealth>,
    path: crate::observe::flows::dns::SelectionPath,
}

impl SelectedLeaf {
    fn explicit(node: &Node) -> anyhow::Result<Self> {
        if node.protocol() == NodeProtocol::Block {
            return Err(policy_block("DNS upstream outbound selected block"));
        }
        Ok(Self {
            node: Some(OwnedTarget::node(node.clone())),
            ..Self::default()
        })
    }
}

pub(super) fn target_context(entry: &UpstreamEntry, target: SocketAddr) -> ScoreSelectionContext {
    // Health gate and score bucket follow the carrier the dial actually
    // exercises: proxied udp:// is pooled TCP-DNS (never real UDP through
    // the node), while DoQ/DoH3 run QUIC over the leaf's PacketTransport.
    // Direct dials never reach this context.
    let (network, probe_domain) = match entry.protocol {
        DnsProtocol::Udp => (SelectionNetwork::Tcp, ProbeDomain::Tcp),
        DnsProtocol::Quic | DnsProtocol::H3 => (SelectionNetwork::Udp, ProbeDomain::DataUdp),
        DnsProtocol::Tcp | DnsProtocol::Tls | DnsProtocol::Https => {
            (SelectionNetwork::Tcp, ProbeDomain::Tcp)
        }
    };
    let family = if target.is_ipv4() {
        IpVersion::V4
    } else {
        IpVersion::V6
    };
    ScoreSelectionContext {
        network,
        probe_domain,
        target_family: Some(family),
        health_family: family,
        target: Some(if entry.endpoint.host.parse::<IpAddr>().is_ok() {
            ScoreTarget::from(target)
        } else {
            ScoreTarget::domain(&entry.endpoint.host, target.port())
        }),
    }
}
pub(super) fn tcp_target_context(
    entry: &UpstreamEntry,
    target: SocketAddr,
) -> ScoreSelectionContext {
    let mut context = target_context(entry, target);
    context.network = SelectionNetwork::Tcp;
    context.probe_domain = ProbeDomain::Tcp;
    context
}

fn select_group_leaf_for_target(
    group_manager: &Arc<GroupManager>,
    outbound: &str,
    entry: &UpstreamEntry,
    target: SocketAddr,
    original: Option<&ScoreContinuation>,
) -> anyhow::Result<Option<SelectedLeaf>> {
    if group_manager.get_group_policy(outbound).is_none() {
        return Ok(None);
    }
    let context = target_context(entry, target);
    let select = || match entry.protocol {
        DnsProtocol::Quic | DnsProtocol::H3 => {
            group_manager.node_packet_dial_plan(outbound, &context, original)
        }
        _ => group_manager.dial_plan_for_target(outbound, &context, original),
    };
    let (plan, revision) = match honk_outbound::runtime::flow_observation::current() {
        Some(observer) => observer.sync_scope(select),
        None => select(),
    };
    let selections = crate::observe::flows::dns::selection_evaluated(plan.observation.as_deref());
    let family = plan.health_family;
    let Some(selected) = plan.entries.into_iter().next() else {
        return Ok(None);
    };
    if selected.node.protocol() == NodeProtocol::Block {
        return Err(policy_block("DNS outbound group selected block"));
    }
    let mut dialed = group_manager.own_target(Target {
        node: selected.node,
        route: selected.route,
    });
    dialed.collapse = selected.collapse;
    Ok(Some(SelectedLeaf {
        path: crate::observe::flows::dns::selection_path(
            &selections,
            &selected.selection_chain,
            &dialed,
            family,
        ),
        health: (context.network == SelectionNetwork::Tcp && dialed.uses_route_evidence()).then(
            || SelectedRouteHealth {
                manager: Arc::clone(group_manager),
                group: outbound.to_owned(),
                family,
                revision,
            },
        ),
        node: Some(dialed),
        feedback: selected.feedback,
    }))
}

impl UpstreamPool {
    fn resolve_outbound_for_target(
        &self,
        outbound: &str,
        entry: &UpstreamEntry,
        target: SocketAddr,
        original: Option<&ScoreContinuation>,
    ) -> anyhow::Result<SelectedLeaf> {
        if outbound.eq_ignore_ascii_case("direct") {
            return Ok(SelectedLeaf::default());
        }

        if let Some(group_manager) = self.group_manager_snapshot.read().as_ref() {
            if let Some(selected) =
                select_group_leaf_for_target(group_manager, outbound, entry, target, original)?
            {
                return Ok(selected);
            }
            if group_manager.get_group_policy(outbound).is_some() {
                return Ok(SelectedLeaf::default());
            }
        } else if let Some(cell) = self.group_manager.read().as_ref() {
            let group_manager = cell.read();
            if group_manager.get_group_policy(outbound).is_some() {
                if let Some(selected) =
                    select_group_leaf_for_target(&group_manager, outbound, entry, target, original)?
                {
                    return Ok(selected);
                }
                debug!(
                    "DNS outbound group '{}' has no available node (GroupManager)",
                    outbound
                );
                return Ok(SelectedLeaf::default());
            }
        }

        if let Some(node) = self.nodes.iter().find(|node| node.name == outbound) {
            return SelectedLeaf::explicit(node);
        }
        // Only a GroupManager routes through an exit, so without one an exit
        // group resolves to no node rather than to its bare first member.
        if self.group_manager.read().is_none()
            && let Some(group) = self.groups.iter().find(|group| group.name == outbound)
            && group.exit.is_none()
            && let Some(node) = group
                .nodes
                .iter()
                .find_map(|id| self.nodes.iter().find(|node| node.id == *id))
        {
            return SelectedLeaf::explicit(node);
        }
        debug!("DNS outbound '{}' resolved to no node", outbound);
        Ok(SelectedLeaf::default())
    }
    pub(super) fn tcp_feedback_for_route(
        &self,
        entry: &UpstreamEntry,
        route: &DnsDialRoute,
    ) -> anyhow::Result<Option<ScoreAttempt>> {
        route
            .feedback
            .clone()
            .map(|feedback| {
                let mut context = tcp_target_context(entry, route.target);
                if let Some(health) = &route.health {
                    context.health_family = health.family;
                }
                feedback.with_context(context)
            })
            .transpose()
            .map_err(Into::into)
    }
    #[cfg(test)]
    pub(super) async fn resolve_dial_route(
        &self,
        entry: &UpstreamEntry,
    ) -> anyhow::Result<DnsDialRoute> {
        let target = self.resolve_upstream_addr(entry).await?;
        self.resolve_dial_route_for_address(entry, target, None)
            .await
    }

    pub(super) async fn resolve_dial_route_for_address(
        &self,
        entry: &UpstreamEntry,
        target: SocketAddr,
        original: Option<&ScoreContinuation>,
    ) -> anyhow::Result<DnsDialRoute> {
        if let Some(tag) = entry.outbound.as_deref() {
            entry.check_explicit_block()?;
            let selected = self.resolve_outbound_for_target(tag, entry, target, original)?;
            if selected.node.is_none() && !tag.eq_ignore_ascii_case("direct") {
                crate::observe::flows::dns::decision("rejected", Some("no_available_outbound"));
                anyhow::bail!("DNS upstream outbound '{tag}' has no available node");
            }
            debug!(
                "DNS dial leaf (forced -> {}): {:?}",
                tag,
                selected
                    .node
                    .as_ref()
                    .map(|target| target.node.name.as_str())
            );
            return Ok(DnsDialRoute {
                observation: crate::observe::flows::dns::outbound_evidence(
                    tag,
                    crate::observe::vocab::RoutingSource::Forced,
                    None,
                    selected.node.as_ref(),
                    target,
                    selected.path,
                ),
                target,
                node: selected.node,
                feedback: selected.feedback,
                health: selected.health,
            });
        }

        let host_is_ip = entry.endpoint.host.parse::<IpAddr>().is_ok();
        let protocol = match entry.protocol {
            DnsProtocol::Udp | DnsProtocol::Quic | DnsProtocol::H3 => "udp",
            DnsProtocol::Tcp | DnsProtocol::Tls | DnsProtocol::Https => "tcp",
        };
        let connection = ConnectionInfo {
            domain: (!host_is_ip).then(|| entry.endpoint.host.clone()),
            dst_ip: target.ip(),
            dst_port: target.port(),
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            protocol,
            process_name: None,
            mac: None,
            dscp: None,
        };
        let (outbound_name, evaluation_id) =
            if let Some(router) = self.traffic_router_snapshot.read().as_ref() {
                crate::observe::flows::dns::route_upstream(router, &connection)
            } else {
                let router_cell = self.traffic_router.read().clone();
                let Some(router) = router_cell else {
                    debug!("DNS dial leaf (no traffic router): direct");
                    return Ok(DnsDialRoute {
                        observation: crate::observe::flows::dns::outbound_evidence(
                            "direct",
                            crate::observe::vocab::RoutingSource::Builtin,
                            None,
                            None,
                            target,
                            Default::default(),
                        ),
                        target,
                        node: None,
                        feedback: None,
                        health: None,
                    });
                };
                let router = router.read().await;
                crate::observe::flows::dns::route_upstream(&router, &connection)
            };
        debug!(
            "DNS dial route: {} {}:{} (host={}) l4={} → outbound '{}'",
            entry.endpoint.host,
            target.ip(),
            target.port(),
            entry.endpoint.host,
            protocol,
            outbound_name
        );
        if outbound_name.eq_ignore_ascii_case("block") {
            return Err(policy_block("DNS dial route selected block"));
        }
        if outbound_name.eq_ignore_ascii_case("direct") {
            return Ok(DnsDialRoute {
                observation: crate::observe::flows::dns::outbound_evidence(
                    &outbound_name,
                    crate::observe::vocab::RoutingSource::Evaluation,
                    evaluation_id,
                    None,
                    target,
                    Default::default(),
                ),
                target,
                node: None,
                feedback: None,
                health: None,
            });
        }
        let selected = self.resolve_outbound_for_target(&outbound_name, entry, target, original)?;
        if selected.node.is_none() {
            crate::observe::flows::dns::decision("rejected", Some("no_available_outbound"));
            anyhow::bail!(
                "DNS dial route selected outbound '{outbound_name}' but no leaf node is available"
            );
        }
        debug!(
            "DNS dial leaf (routed via {}): {:?}",
            outbound_name,
            selected
                .node
                .as_ref()
                .map(|target| target.node.name.as_str())
        );
        Ok(DnsDialRoute {
            observation: crate::observe::flows::dns::outbound_evidence(
                &outbound_name,
                crate::observe::vocab::RoutingSource::Evaluation,
                evaluation_id,
                selected.node.as_ref(),
                target,
                selected.path,
            ),
            target,
            node: selected.node,
            feedback: selected.feedback,
            health: selected.health,
        })
    }

    #[cfg(test)]
    pub(super) async fn resolve_dial_leaf(
        &self,
        entry: &UpstreamEntry,
    ) -> anyhow::Result<Option<Node>> {
        Ok(self
            .resolve_dial_route(entry)
            .await?
            .node
            .map(|target| target.node))
    }

    #[cfg(test)]
    pub(crate) async fn selected_dial_context_for_test(
        &self,
        upstream: &str,
        target: SocketAddr,
    ) -> anyhow::Result<crate::dns::transport::DialContext> {
        let entry = &self.entries[upstream];
        let route = self
            .resolve_dial_route_for_address(entry, target, None)
            .await?;
        self.dial_context(entry, route.node.as_ref(), route.target)
    }
}
