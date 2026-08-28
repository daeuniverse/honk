use honk_config::Config;

fn normalize_reload_metadata(current: &Config, candidate: &mut Config) {
    for (node, current) in candidate.nodes.iter_mut().zip(&current.nodes) {
        node.created_at = current.created_at;
        node.updated_at = current.updated_at;
    }
    for (group, current) in candidate.groups.iter_mut().zip(&current.groups) {
        group.id = current.id;
        group.created_at = current.created_at;
    }
    for (subscription, current) in candidate
        .subscriptions
        .iter_mut()
        .zip(&current.subscriptions)
    {
        subscription.created_at = current.created_at;
        subscription.last_updated = current.last_updated;
        subscription.node_count = current.node_count;
    }
}

pub(in crate::control) fn effective_config_unchanged(
    current: &Config,
    candidate: &mut Config,
) -> bool {
    normalize_reload_metadata(current, candidate);
    current == candidate
}

pub(in crate::control) fn dns_routing_state_reusable(current: &Config, candidate: &Config) -> bool {
    current.dns.routing == candidate.dns.routing
        && current.dns.fixed_domain_ttl == candidate.dns.fixed_domain_ttl
}
/// Whether a fetched subscription would change the effective node set.
/// Parse timestamps are metadata; every other node field participates in the
/// comparison so display, provenance, group filters, and dial tuning changes
/// still trigger a generation rebuild.
pub(in crate::control) fn subscription_nodes_unchanged(
    current: &Config,
    subscription_id: uuid::Uuid,
    candidate: &mut [honk_config::node::Node],
) -> bool {
    let existing = || {
        current
            .nodes
            .iter()
            .filter(|node| node.subscription_id == Some(subscription_id))
    };
    if existing().count() != candidate.len() {
        return false;
    }
    let unchanged = existing()
        .zip(candidate.iter_mut())
        .all(|(previous, node)| {
            let created_at = node.created_at;
            let updated_at = node.updated_at;
            node.created_at = previous.created_at;
            node.updated_at = previous.updated_at;
            let unchanged = previous == node;
            node.created_at = created_at;
            node.updated_at = updated_at;
            unchanged
        });
    if unchanged {
        for (previous, node) in existing().zip(candidate) {
            node.created_at = previous.created_at;
            node.updated_at = previous.updated_at;
        }
    }
    unchanged
}

pub(in crate::control) fn routing_state_reusable(current: &Config, candidate: &Config) -> bool {
    current.routing == candidate.routing
        && current.global.dial_mode == candidate.global.dial_mode
        && current
            .groups
            .iter()
            .map(|group| &group.name)
            .eq(candidate.groups.iter().map(|group| &group.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrelated_fields_reuse_routing_state() {
        let first = Config::default();
        let mut second = first.clone();
        second.global.check_interval_secs += 1;
        assert!(routing_state_reusable(&first, &second));

        second
            .routing
            .rules
            .push(honk_config::routing::RoutingRule {
                name: String::new(),
                condition: honk_config::routing::RoutingCondition {
                    geosite: vec!["cn".into()],
                    ..Default::default()
                },
                outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
                priority: 0,
                must: false,
                mark: 0,
            });
        assert!(!routing_state_reusable(&first, &second));
    }

    #[test]
    fn unrelated_dns_fields_reuse_router_but_fixed_ttl_does_not() {
        let first = Config::default();
        let mut second = first.clone();
        second.dns.cache.ttl += 1;
        assert!(dns_routing_state_reusable(&first, &second));

        second.dns.fixed_domain_ttl.insert("example.com".into(), 60);
        assert!(!dns_routing_state_reusable(&first, &second));
    }

    #[test]
    fn effective_config_ignores_only_runtime_metadata() {
        let mut current = Config::default();
        current.nodes.push(honk_config::node::Node::default());
        current.groups.push(honk_config::node::Group::default());
        current
            .subscriptions
            .push(honk_config::subscription::Subscription::default());
        let mut candidate = current.clone();
        candidate.nodes[0].created_at += chrono::Duration::seconds(1);
        candidate.nodes[0].updated_at += chrono::Duration::seconds(1);
        candidate.groups[0].id = uuid::Uuid::new_v4();
        candidate.groups[0].created_at += chrono::Duration::seconds(1);
        candidate.subscriptions[0].created_at += chrono::Duration::seconds(1);
        candidate.subscriptions[0].last_updated = Some(chrono::Utc::now());
        candidate.subscriptions[0].node_count += 1;
        assert!(effective_config_unchanged(&current, &mut candidate));

        candidate.nodes[0].password = Some("changed".into());
        assert!(!effective_config_unchanged(&current, &mut candidate));
    }
}
