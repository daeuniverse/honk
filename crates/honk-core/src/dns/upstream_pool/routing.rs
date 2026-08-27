use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use honk_config::node::Node;
use honk_config::types::DnsProtocol;
use honk_outbound::alive::{IpVersion, ProbeDomain};
use honk_outbound::group::GroupManager;
use honk_outbound::group::{ScoreFeedback, ScoreSelectionContext, ScoreTarget, SelectionNetwork};
use tracing::{debug, warn};

use super::UpstreamPool;
use super::entries::UpstreamEntry;
use crate::routing::ConnectionInfo;

pub(super) struct DnsDialRoute {
    pub(super) target: SocketAddr,
    pub(super) node: Option<Node>,
    pub(super) feedback: Option<ScoreFeedback>,
}

pub(super) fn target_context(entry: &UpstreamEntry, target: SocketAddr) -> ScoreSelectionContext {
    let (network, probe_domain) = match entry.protocol {
        DnsProtocol::Udp | DnsProtocol::Quic | DnsProtocol::H3 => {
            (SelectionNetwork::Udp, ProbeDomain::DnsUdp)
        }
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
    group_manager: &GroupManager,
    outbound: &str,
    entry: &UpstreamEntry,
    target: SocketAddr,
) -> Option<(Node, Option<ScoreFeedback>)> {
    group_manager.get_group_policy(outbound)?;
    group_manager
        .selection_plan_for_target_with_health_fallback(outbound, &target_context(entry, target))
        .entries
        .into_iter()
        .next()
        .map(|selected| (selected.node.clone(), selected.feedback))
}

impl UpstreamPool {
    fn resolve_outbound_for_target(
        &self,
        outbound: &str,
        entry: &UpstreamEntry,
        target: SocketAddr,
    ) -> (Option<Node>, Option<ScoreFeedback>) {
        if outbound.eq_ignore_ascii_case("direct") {
            return (None, None);
        }

        if let Some(group_manager) = self.group_manager_snapshot.read().as_ref() {
            if let Some((node, feedback)) =
                select_group_leaf_for_target(group_manager, outbound, entry, target)
            {
                return (Some(node), feedback);
            }
            if group_manager.get_group_policy(outbound).is_some() {
                return (None, None);
            }
        } else if let Some(cell) = self.group_manager.read().as_ref() {
            let group_manager = cell.read();
            if group_manager.get_group_policy(outbound).is_some() {
                if let Some((node, feedback)) =
                    select_group_leaf_for_target(&group_manager, outbound, entry, target)
                {
                    return (Some(node), feedback);
                }
                warn!(
                    "DNS outbound group '{}' has no available node (GroupManager)",
                    outbound
                );
                return (None, None);
            }
        }

        if let Some(node) = self.nodes.iter().find(|node| node.name == outbound) {
            return (Some(node.clone()), None);
        }
        if self.group_manager.read().is_none()
            && let Some(group) = self.groups.iter().find(|group| group.name == outbound)
            && let Some(node) = group
                .nodes
                .iter()
                .find_map(|id| self.nodes.iter().find(|node| node.id == *id))
        {
            return (Some(node.clone()), None);
        }
        warn!("DNS outbound '{}' resolved to no node", outbound);
        (None, None)
    }
    pub(super) fn tcp_feedback_for_route(
        &self,
        entry: &UpstreamEntry,
        route: &DnsDialRoute,
    ) -> Option<ScoreFeedback> {
        route
            .feedback
            .clone()
            .map(|feedback| feedback.with_context(tcp_target_context(entry, route.target)))
    }
    #[cfg(test)]
    pub(super) async fn resolve_dial_route(
        &self,
        entry: &UpstreamEntry,
    ) -> anyhow::Result<DnsDialRoute> {
        let target = Self::resolve_udp_addr(entry).await?;
        self.resolve_dial_route_for_address(entry, target).await
    }

    pub(super) async fn resolve_dial_route_for_address(
        &self,
        entry: &UpstreamEntry,
        target: SocketAddr,
    ) -> anyhow::Result<DnsDialRoute> {
        if let Some(tag) = entry.outbound.as_deref() {
            if tag.eq_ignore_ascii_case("block") {
                anyhow::bail!("DNS upstream outbound 'block' rejected the dial");
            }
            let (node, feedback) = self.resolve_outbound_for_target(tag, entry, target);
            if node.is_none() && !tag.eq_ignore_ascii_case("direct") {
                anyhow::bail!("DNS upstream outbound '{tag}' has no available node");
            }
            debug!(
                "DNS dial leaf (forced -> {}): {:?}",
                tag,
                node.as_ref().map(|node| node.name.as_str())
            );
            return Ok(DnsDialRoute {
                target,
                node,
                feedback,
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
        let outbound_name = if let Some(router) = self.traffic_router_snapshot.read().as_ref() {
            router.route(&connection).to_string()
        } else {
            let router_cell = self.traffic_router.read().clone();
            let Some(router) = router_cell else {
                debug!("DNS dial leaf (no traffic router): direct");
                return Ok(DnsDialRoute {
                    target,
                    node: None,
                    feedback: None,
                });
            };
            router.read().await.route(&connection).to_string()
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
            anyhow::bail!("DNS dial route selected block");
        }
        if outbound_name.eq_ignore_ascii_case("direct") {
            return Ok(DnsDialRoute {
                target,
                node: None,
                feedback: None,
            });
        }
        let (node, feedback) = self.resolve_outbound_for_target(&outbound_name, entry, target);
        if node.is_none() {
            anyhow::bail!(
                "DNS dial route selected outbound '{outbound_name}' but no leaf node is available"
            );
        }
        debug!(
            "DNS dial leaf (routed via {}): {:?}",
            outbound_name,
            node.as_ref().map(|node| node.name.as_str())
        );
        Ok(DnsDialRoute {
            target,
            node,
            feedback,
        })
    }

    #[cfg(test)]
    pub(super) async fn resolve_dial_leaf(
        &self,
        entry: &UpstreamEntry,
    ) -> anyhow::Result<Option<Node>> {
        Ok(self.resolve_dial_route(entry).await?.node)
    }
}
