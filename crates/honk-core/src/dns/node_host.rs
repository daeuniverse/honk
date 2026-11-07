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

/// The process-wide hook. Hosts the current generation does not claim are
/// declined synchronously, so bootstrap keeps them without a boxed lookup; a claimed lookup
/// is decided again by the generation it leases, and a host a reload stopped
/// claiming in between still resolves through bootstrap.
pub(crate) fn resolver(
    service: &DnsService,
) -> Arc<dyn honk_outbound::bootstrap::NodeHostResolver> {
    Arc::new(NodeHostRouting(service.clone()))
}

impl honk_outbound::bootstrap::NodeHostResolver for NodeHostRouting {
    fn lookup(&self, host: &str) -> Option<honk_outbound::bootstrap::NodeHostLookup> {
        if !self.0.claims_node_host(host) {
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

    #[test]
    fn indexes_the_xhttp_download_host_of_a_subscription_node() {
        let mut config = honk_config::parser::parse_dae_config(
            "subscription {\n MyAirport: 'https://sub.invalid/'\n}\ndns {\n routing {\n  request {\n   subtag(MyAirport) -> providerdoh\n  }\n }\n}\n",
        )
        .unwrap();
        let mut link =
            reqwest::Url::parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@up.example:443")
                .unwrap();
        link.query_pairs_mut()
            .append_pair("type", "xhttp")
            .append_pair("security", "tls")
            .append_pair(
                "extra",
                r#"{"downloadSettings":{"address":"down.example","port":8443,"network":"xhttp","security":"tls","alpn":["h2"]}}"#,
            );
        let mut node = Node::from_share_link(link.as_str()).unwrap();
        node.subscription_id = Some(config.subscriptions[0].id);
        config.nodes.push(node);

        let mut hosts: Vec<_> = index(&config).into_keys().collect();
        hosts.sort();
        assert_eq!(hosts, ["down.example", "up.example"]);
    }

    #[test]
    fn hook_declines_indexed_hosts_no_rule_claims() {
        struct NoPool;

        #[async_trait::async_trait]
        impl crate::dns::forwarder::DnsUpstreamPool for NoPool {
            async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
                anyhow::bail!("declined and unawaited lookups never query")
            }
        }

        let dns = honk_config::parser::parse_dae_config(
            "dns {\n routing {\n  request {\n   subtag(MyAirport) && qname(suffix: private.example) -> providerdoh\n  }\n }\n}\n",
        )
        .unwrap()
        .dns;
        let forwarder = crate::dns::forwarder::DnsForwarder::new(
            Arc::new(NoPool),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(8))),
            Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(&dns).unwrap()),
        )
        .with_node_hosts(
            ["node.private.example", "node.public.example"]
                .map(|host| (host.to_owned(), vec!["MyAirport".to_owned()]))
                .into(),
        );
        let hook = resolver(&DnsService::with_forwarder(Arc::new(forwarder)));

        assert!(hook.lookup("Node.Private.Example.").is_some());
        for unclaimed in ["node.public.example", "unindexed.private.example"] {
            assert!(hook.lookup(unclaimed).is_none(), "{unclaimed}");
        }
    }
}
