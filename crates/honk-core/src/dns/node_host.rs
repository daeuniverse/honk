//! Node server hosts claimed by `subtag()` DNS request rules.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use honk_config::config::Config;
use honk_config::dns::DnsCond;
use honk_config::node::Node;

use super::DnsService;

/// Lowercase node server host to the tags of every subscription serving it.
pub(crate) type NodeHosts = HashMap<String, Vec<String>>;

/// The node hosts `config`'s `subtag()` rules may claim; empty without one.
pub(crate) fn index(config: &Config) -> NodeHosts {
    let mut hosts = NodeHosts::new();
    if !config.dns.routing.request.rules.iter().any(|rule| {
        rule.conditions
            .iter()
            .any(|condition| matches!(condition, DnsCond::Subtag { .. }))
    }) {
        return hosts;
    }
    for node in &config.nodes {
        let tags: Vec<&String> = config
            .subscriptions
            .iter()
            .filter(|subscription| Some(subscription.id) == node.subscription_id)
            .map(|subscription| &subscription.name)
            .collect();
        if tags.is_empty() {
            continue;
        }
        // An XHTTP download peer dials its own server host.
        let download = node.xhttp_download_view();
        for host in std::iter::once(node.host()).chain(download.as_ref().map(Node::host)) {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            if host.parse::<IpAddr>().is_ok() {
                continue;
            }
            let entry = hosts.entry(host).or_default();
            for tag in &tags {
                if !entry.contains(tag) {
                    entry.push((*tag).clone());
                }
            }
        }
    }
    hosts
}

struct NodeHostRouting(DnsService);

/// The process-wide hook. It claims nothing while the current DNS generation
/// indexes no node host, so configurations without `subtag()` keep bootstrap
/// resolution without a per-dial allocation; otherwise the generation each
/// lookup leases decides the claim.
pub(crate) fn resolver(
    service: &DnsService,
) -> Arc<dyn honk_outbound::bootstrap::NodeHostResolver> {
    Arc::new(NodeHostRouting(service.clone()))
}

impl honk_outbound::bootstrap::NodeHostResolver for NodeHostRouting {
    fn lookup(&self, host: &str) -> Option<honk_outbound::bootstrap::NodeHostLookup> {
        if self.0.forwarder().node_hosts.is_empty() {
            return None;
        }
        let service = self.0.clone();
        let host = host.to_owned();
        Some(Box::pin(async move {
            match service.resolve_node_host(&host).await {
                Ok(Some(addresses)) => Ok(addresses),
                Ok(None) => {
                    honk_outbound::bootstrap::resolve_with(
                        honk_outbound::bootstrap::global(),
                        &host,
                    )
                    .await
                }
                Err(error) => {
                    crate::logging::warn_throttled!(
                        error = %format_args!("{error:#}"),
                        "node host lookup through its subtag() DNS rule failed"
                    );
                    Err(io::Error::other(error))
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_named_hosts_of_subscription_nodes_under_a_subtag_rule() {
        let mut config = honk_config::parser::parse_dae_config(
            "subscription {\n MyAirport: 'https://sub.invalid/'\n Other: 'https://other.invalid/'\n}\ndns {\n upstream {\n  providerdoh: 'udp://192.0.2.53:53' -> direct\n }\n routing {\n  request {\n   subtag(MyAirport) -> providerdoh\n  }\n }\n}\n",
        )
        .unwrap();
        let (airport, other) = (config.subscriptions[0].id, config.subscriptions[1].id);
        for (address, subscription_id) in [
            ("Node.Example.:443", Some(airport)),
            ("node.example:8443", Some(other)),
            ("manual.example:443", None),
            ("192.0.2.1:443", Some(airport)),
        ] {
            config.nodes.push(Node {
                address: address.into(),
                subscription_id,
                ..Default::default()
            });
        }

        let hosts = index(&config);
        assert_eq!(
            hosts.len(),
            1,
            "static nodes and IP literals are not claimable"
        );
        assert_eq!(hosts["node.example"], ["MyAirport", "Other"]);

        config.dns.routing.request.rules.clear();
        assert!(index(&config).is_empty());
    }
}
