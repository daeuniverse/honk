use std::sync::Arc;

use honk_config::dns::DnsConfig;
use honk_config::experimental::CacheFileConfig;

use super::*;
use crate::dns::cache::OperationKind;
use crate::dns::forwarder::build_dns_query;
use crate::dns::planner::{RequestScope, UpstreamTag};
use crate::dns::query::{IngressProfile, QueryContext};

mod actor;
mod restore;

fn test_db(dir: &tempfile::TempDir, cache_id: &str) -> Arc<CacheDb> {
    let config = CacheFileConfig {
        enabled: true,
        path: dir.path().join("cache.db").to_string_lossy().into_owned(),
        cache_id: cache_id.to_string(),
        store_fakeip: false,
        store_dns: true,
    };
    Arc::new(CacheDb::open(&config).expect("cache.db"))
}

fn policy(ttl: u64) -> PolicyId {
    let mut config = DnsConfig::default();
    config.cache.ttl = ttl;
    PolicyId::from_config(&config).expect("policy")
}

fn fixture(
    profile: IngressProfile,
    active_policy: Option<PolicyId>,
    scope: RequestScope,
) -> (CacheKey, Vec<u8>, QueryContext) {
    let query_wire = build_dns_query("example.com", 1);
    let query = QueryContext::parse_with_profile(&query_wire, profile).expect("query");
    let mut response = query_wire;
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]);
    (
        CacheKey::new(&query, active_policy, scope, OperationKind::Resolve),
        response,
        query,
    )
}

fn upstream(name: &str) -> RequestScope {
    RequestScope::Upstream(UpstreamTag::new(name).expect("upstream"))
}

#[test]
fn artifact_aware_policy_round_trips_through_persistence_codec() {
    let config = DnsConfig::default();
    let policy = PolicyId::from_config_with_artifacts(&config, &[1; 32], &[2; 32]).unwrap();
    let (key, response, _) = fixture(
        IngressProfile::Internal,
        Some(policy.clone()),
        upstream("default"),
    );
    let encoded = codec::encode(&key, &response, 123);

    let decoded = codec::decode(&encoded.suffix, &encoded.bytes, Some(&policy)).unwrap();

    assert_eq!(decoded.key.policy_id(), Some(&policy));
}
