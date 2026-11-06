use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_outbound::alive::IpVersion;

use super::state::{DesiredState, family_of};
use super::worker;
use super::{ProjectionObservation, RoutingProjection, RoutingProjectionSnapshot};
use crate::ebpf::maps;
use crate::ebpf::mock::MockEbpfBackend;
use crate::ebpf::{EbpfBackend, ProjectionMapOperation};
use crate::routing::Router;

type SharedBackend = Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>>;
type TestProjection = (
    RoutingProjection,
    tokio::sync::mpsc::Receiver<()>,
    SharedBackend,
);

fn snapshot(generation: u64, a: u32, b: u32) -> Arc<RoutingProjectionSnapshot> {
    let routes = (0..8)
        .map(|bit| {
            let domain = if a & (1 << bit) != 0 {
                "a.test".to_owned()
            } else if b & (1 << bit) != 0 {
                "b.test".to_owned()
            } else {
                format!("unused-{bit}.test")
            };
            RoutingRule {
                name: format!("predicate-{bit}"),
                condition: RoutingCondition {
                    domain: vec![domain],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple("direct".to_owned()),
                priority: bit,
                must: false,
                mark: 0,
            }
        })
        .collect::<Vec<_>>();
    Arc::new(RoutingProjectionSnapshot::new(
        generation,
        Arc::new(Router::new(&routes, "direct").expect("test router")),
    ))
}

fn positive<'a>(
    domain: &'a str,
    ips: &'a [IpAddr],
    expires_at: tokio::time::Instant,
) -> ProjectionObservation<'a> {
    ProjectionObservation::Positive {
        domain,
        family: ips.first().map_or(IpVersion::V4, |ip| family_of(*ip)),
        ips,
        expires_at,
    }
}

fn clear_v4(domain: &str) -> ProjectionObservation<'_> {
    ProjectionObservation::Clear {
        domain,
        family: IpVersion::V4,
    }
}

#[tokio::test(start_paused = true)]
async fn live_domain_without_matching_predicate_projects_present_zero() {
    let now = tokio::time::Instant::now();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(
        positive("unknown.test", &[ip], now + Duration::from_secs(30)),
        now,
    );

    let batch = state.batch(now);
    assert_eq!(batch.sets.len(), 1);
    assert_eq!(batch.sets[0].bitmap.bitmap, [0; 8]);
}
#[tokio::test(start_paused = true)]
async fn shared_ip_clear_and_expiry_recompute_owner_or() {
    let now = tokio::time::Instant::now();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(positive("a.test", &[ip], now + Duration::from_secs(1)), now);
    state.observe(positive("b.test", &[ip], now + Duration::from_secs(5)), now);
    let batch = state.batch(now);
    assert_eq!(batch.sets[0].bitmap.bitmap, [3, 0, 0, 0, 0, 0, 0, 0]);
    assert!(state.commit_success(&batch.sets, &batch.removes));

    state.observe(clear_v4("a.test"), now);
    assert_eq!(
        state.batch(now).sets[0].bitmap.bitmap,
        [2, 0, 0, 0, 0, 0, 0, 0]
    );
    tokio::time::advance(Duration::from_secs(5)).await;
    state.expire(tokio::time::Instant::now());
    assert_eq!(state.batch(tokio::time::Instant::now()).removes[0], ip);
}

#[tokio::test(start_paused = true)]
async fn address_families_are_owned_independently_until_nxdomain() {
    let now = tokio::time::Instant::now();
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(
        positive("a.test", &[v4], now + Duration::from_secs(30)),
        now,
    );
    state.observe(
        positive("a.test", &[v6], now + Duration::from_secs(30)),
        now,
    );
    assert!(state.desired.contains_key(&v4) && state.desired.contains_key(&v6));

    state.observe(
        ProjectionObservation::Clear {
            domain: "a.test",
            family: IpVersion::V6,
        },
        now,
    );
    assert!(state.desired.contains_key(&v4) && !state.desired.contains_key(&v6));

    state.observe(
        positive("a.test", &[v6], now + Duration::from_secs(30)),
        now,
    );
    state.observe(ProjectionObservation::ClearName { domain: "a.test" }, now);
    assert!(state.desired.is_empty());

    // A mapped AAAA answer shares the IPv4 key; clearing AAAA must keep A's fact.
    let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 3).to_ipv6_mapped());
    state.observe(
        positive("a.test", &[v4], now + Duration::from_secs(30)),
        now,
    );
    state.observe(
        positive("a.test", &[mapped], now + Duration::from_secs(30)),
        now,
    );
    state.observe(
        ProjectionObservation::Clear {
            domain: "a.test",
            family: IpVersion::V6,
        },
        now,
    );
    assert!(state.desired.contains_key(&v4));
}

#[tokio::test(start_paused = true)]
async fn address_family_owners_expire_independently() {
    let now = tokio::time::Instant::now();
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 4));
    let blocker = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(
        positive("a.test", &[v4], now + Duration::from_secs(30)),
        now,
    );
    state.observe(
        positive("a.test", &[v6], now + Duration::from_secs(60)),
        now,
    );
    state.observe(
        positive("b.test", &[blocker], now + Duration::from_secs(5)),
        now,
    );
    state.observe(clear_v4("a.test"), now + Duration::from_secs(1));
    state.observe(
        positive(
            "a.test",
            &[v4],
            now + Duration::from_secs(1) + Duration::from_secs(40),
        ),
        now + Duration::from_secs(1),
    );

    state.expire(now + Duration::from_secs(31));
    assert!(state.desired.contains_key(&v4) && state.desired.contains_key(&v6));
    assert!(!state.desired.contains_key(&blocker));

    let later = now + Duration::from_secs(41);
    state.expire(later);
    assert!(!state.desired.contains_key(&v4) && state.desired.contains_key(&v6));

    state.observe(
        positive("a.test", &[v4], later + Duration::from_secs(60)),
        later,
    );
    state.expire(now + Duration::from_secs(61));
    assert!(state.desired.contains_key(&v4) && !state.desired.contains_key(&v6));
    state.expire(now + Duration::from_secs(101));
    assert!(state.owner_domains().is_empty());
}

#[tokio::test(start_paused = true)]
async fn positive_refresh_uses_advertised_ttl_and_retain_keeps_owner() {
    let now = tokio::time::Instant::now();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(
        positive("a.test", &[ip], now + Duration::from_secs(30)),
        now,
    );
    let initial = state.batch(now);
    assert!(state.commit_success(&initial.sets, &initial.removes));
    state.observe(ProjectionObservation::Retain, now + Duration::from_secs(1));
    state.observe(
        ProjectionObservation::Positive {
            domain: "a.test",
            family: IpVersion::V4,
            ips: &[ip],
            expires_at: now + Duration::from_secs(3),
        },
        now + Duration::from_secs(1),
    );
    assert_eq!(state.next_deadline(), Some(now + Duration::from_secs(3)));
    state.expire(now + Duration::from_secs(2));
    assert!(state.desired.contains_key(&ip));
    state.expire(now + Duration::from_secs(3));
    assert_eq!(state.owner_domains(), Vec::<String>::new());
}

#[tokio::test(start_paused = true)]
async fn same_generation_update_after_batch_snapshot_stays_dirty() {
    let now = tokio::time::Instant::now();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(
        positive("a.test", &[ip], now + Duration::from_secs(30)),
        now,
    );
    let stale = state.batch(now);

    state.observe(
        positive("b.test", &[ip], now + Duration::from_secs(30)),
        now,
    );

    assert!(!state.commit_success(&stale.sets, &stale.removes));
    let repaired = state.batch(now);
    assert_eq!(repaired.sets[0].bitmap.bitmap, [3, 0, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn stale_runtime_observation_cannot_downgrade_generation() {
    let now = tokio::time::Instant::now();
    let old = snapshot(1, 1, 2);
    let current = snapshot(2, 4, 8);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4));
    let mut state = DesiredState::new(Arc::clone(&old), 10_000);
    assert!(state.update_snapshot(&current));
    if state.update_snapshot(&old) {
        state.observe(
            positive("a.test", &[ip], now + Duration::from_secs(30)),
            now,
        );
    }
    assert!(state.owner_domains().is_empty());
    state.observe(
        positive("a.test", &[ip], now + Duration::from_secs(30)),
        now,
    );
    let batch = state.batch(now);
    assert_eq!(batch.generation, 2);
    assert_eq!(batch.sets[0].bitmap.bitmap, [4, 0, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn stale_runtime_submission_records_generation_fence_event() {
    let before = crate::stats::dns_snapshot();
    let (projection, _receiver, _ebpf) = projection_for_test(snapshot(2, 4, 8));
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));

    projection.submit(
        snapshot(1, 1, 2),
        positive(
            "a.test",
            &[ip],
            tokio::time::Instant::now() + Duration::from_secs(30),
        ),
    );

    assert!(
        crate::stats::dns_snapshot()
            .delta(before)
            .projection_stale_generation
            >= 1
    );
}

#[tokio::test(start_paused = true)]
async fn deterministic_capacity_evicts_oldest_domain() {
    let now = tokio::time::Instant::now();
    let mut state = DesiredState::new(snapshot(1, 1, 2), 2);
    for (domain, octet) in [("a.test", 1), ("b.test", 2), ("a.test", 3)] {
        state.observe(
            positive(
                domain,
                &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet))],
                now + Duration::from_secs(30),
            ),
            now,
        );
    }
    assert_eq!(
        state.owner_domains(),
        vec!["a.test".to_owned(), "b.test".to_owned()]
    );
    state.observe(
        positive(
            "c.test",
            &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))],
            now + Duration::from_secs(30),
        ),
        now,
    );
    assert_eq!(
        state.owner_domains(),
        vec!["a.test".to_owned(), "c.test".to_owned()]
    );
    state.observe(
        positive(
            "d.test",
            &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))],
            now + Duration::from_secs(30),
        ),
        now,
    );
    assert_eq!(
        state.owner_domains(),
        vec!["c.test".to_owned(), "d.test".to_owned()]
    );
}

#[tokio::test(start_paused = true)]
async fn ten_thousand_and_first_domain_evicts_exact_oldest_owner() {
    let now = tokio::time::Instant::now();
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    for index in 0..=10_000u32 {
        let domain = format!("d{index:05}.test");
        let ip = IpAddr::V4(Ipv4Addr::from(index));
        state.observe(positive(&domain, &[ip], now + Duration::from_secs(30)), now);
    }
    let domains = state.owner_domains();
    assert_eq!(domains.len(), 10_000);
    assert!(!domains.iter().any(|domain| domain == "d00000.test"));
    assert!(domains.iter().any(|domain| domain == "d10000.test"));
}

#[tokio::test(start_paused = true)]
async fn ip_capacity_prefers_matching_facts_and_bounds_reload_projection() {
    use super::state::{IP_CAPACITY, ZERO_IP_CAPACITY};

    let now = tokio::time::Instant::now();
    let current = snapshot(1, 1, 2);
    let mut state = DesiredState::new(Arc::clone(&current), 10_000);
    for index in 0..10_000u32 {
        let ips = (0..7)
            .map(|offset| IpAddr::V4(Ipv4Addr::from(index * 7 + offset)))
            .collect::<Vec<_>>();
        state.observe(
            positive(
                &format!("d{index}.test"),
                &ips,
                now + Duration::from_secs(300),
            ),
            now,
        );
    }
    assert_eq!(state.desired.len(), ZERO_IP_CAPACITY);
    assert_eq!(state.project(&current).len(), ZERO_IP_CAPACITY);
    assert!(
        !state
            .desired
            .contains_key(&IpAddr::V4(Ipv4Addr::from(69_999)))
    );

    let matching = (100_000..100_000 + IP_CAPACITY as u32 + 1)
        .map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
        .collect::<Vec<_>>();
    state.observe(
        positive("a.test", &matching, now + Duration::from_secs(300)),
        now,
    );
    assert_eq!(state.desired.len(), IP_CAPACITY);
    assert!(state.desired.values().all(|entry| entry.bitmap[0] == 1));
    assert!(state.desired.contains_key(&matching[0]));
    assert!(!state.desired.contains_key(matching.last().unwrap()));
    let projected = state.project(&current);
    assert_eq!(
        state
            .desired
            .iter()
            .map(|(ip, value)| (*ip, value.bitmap))
            .collect::<Vec<_>>(),
        projected
            .iter()
            .map(|(ip, value)| (*ip, value.bitmap))
            .collect::<Vec<_>>()
    );
    while !state.dirty_ips.is_empty() {
        let batch = state.batch(now);
        state.commit_success(&batch.sets, &batch.removes);
    }
    let earlier = IpAddr::V4(Ipv4Addr::from(99_999));
    state.observe(
        positive("b.test", &[earlier], now + Duration::from_secs(300)),
        now,
    );
    let eviction = state.batch(now);
    assert!(
        eviction.sets.is_empty(),
        "full projection must free a slot before admitting a new IP"
    );
    assert_eq!(eviction.removes[0], matching[IP_CAPACITY - 1]);
    state.record_failure(eviction.removes[0], now);
    assert!(
        state.batch(now).sets.is_empty(),
        "failed eviction must retain the reservation"
    );
    assert!(
        state.next_deadline().unwrap() > now,
        "blocked admission must not busy-loop"
    );
    state.commit_success(&[], &eviction.removes);
    let admitted = state.batch(now);
    assert_eq!(admitted.sets[0].ip, earlier);
    assert_eq!(admitted.sets[0].bitmap.bitmap[0], 2);
    state.commit_success(&admitted.sets, &[]);
    assert_eq!(state.applied.len(), IP_CAPACITY);
    state.observe(clear_v4("b.test"), now);
    state.observe(
        positive("a.test", &matching, now + Duration::from_secs(300)),
        now,
    );
    assert!(state.desired.contains_key(&matching[IP_CAPACITY - 1]));

    let replacement = snapshot(2, 0, 2);
    let projected = state.project(&replacement);
    state.update_snapshot(&replacement);
    assert_eq!(state.desired.len(), ZERO_IP_CAPACITY);
    assert_eq!(
        state
            .desired
            .iter()
            .map(|(ip, value)| (*ip, value.bitmap))
            .collect::<Vec<_>>(),
        projected
            .iter()
            .map(|(ip, value)| (*ip, value.bitmap))
            .collect::<Vec<_>>()
    );
}

#[tokio::test(start_paused = true)]
async fn capacity_blocked_retry_waits_for_removal_without_spinning() {
    use super::state::IP_CAPACITY;

    let now = tokio::time::Instant::now();
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    let ips = (100_000..100_000 + IP_CAPACITY as u32)
        .map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
        .collect::<Vec<_>>();
    state.observe(
        positive("a.test", &ips, now + Duration::from_secs(300)),
        now,
    );
    loop {
        let mut batch = state.batch(now);
        if batch.sets.is_empty() {
            break;
        }
        if batch.sets.iter().any(|set| set.ip == ips[0]) {
            state.record_failure(ips[0], now);
            batch.sets.retain(|set| set.ip != ips[0]);
        }
        state.commit_success(&batch.sets, &batch.removes);
    }
    assert_eq!(state.applied.len(), IP_CAPACITY - 1);

    let later = now + Duration::from_millis(10);
    state.observe(
        positive(
            "b.test",
            &[Ipv4Addr::from(99_999).into()],
            later + Duration::from_secs(300),
        ),
        later,
    );
    let batch = state.batch(later);
    assert_eq!(batch.removes[0], ips[IP_CAPACITY - 1]);
    state.record_failure(batch.removes[0], later);
    state.commit_success(&batch.sets, &[]);
    assert_eq!(state.applied.len(), IP_CAPACITY);

    tokio::time::advance(Duration::from_millis(100)).await;
    let blocked = state.batch(tokio::time::Instant::now());
    assert!(blocked.sets.is_empty() && blocked.removes.is_empty());
    assert_eq!(
        state.next_deadline(),
        Some(later + Duration::from_millis(100))
    );

    tokio::time::advance(Duration::from_millis(10)).await;
    let removal = state.batch(tokio::time::Instant::now());
    state.commit_success(&[], &removal.removes);
    let resumed = state.batch(tokio::time::Instant::now());
    assert_eq!(resumed.sets[0].ip, ips[0]);
}

#[tokio::test(start_paused = true)]
async fn mapped_ipv6_and_ipv4_share_one_projected_fact() {
    let now = tokio::time::Instant::now();
    let current = snapshot(1, 1, 2);
    let mut state = DesiredState::new(Arc::clone(&current), 10_000);
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    state.observe(
        positive("a.test", &[ip.into()], now + Duration::from_secs(30)),
        now,
    );
    state.observe(
        positive(
            "b.test",
            &[ip.to_ipv6_mapped().into()],
            now + Duration::from_secs(30),
        ),
        now,
    );
    let projected = state.project(&current);
    assert_eq!(projected.len(), 1);
    assert_eq!(projected[&IpAddr::V4(ip)].bitmap[0], 3);
}

#[test]
fn retired_projection_ips_do_not_accumulate_memory() {
    const CHILD: &str = "HONK_PROJECTION_ALLOCATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dns::projection::tests::retired_projection_ips_do_not_accumulate_memory",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("isolated projection allocation test");
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let now = tokio::time::Instant::now();
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
    for index in 1..=10_000_u32 {
        let ip = IpAddr::V4(Ipv4Addr::from(index));
        state.observe(
            positive("a.test", &[ip], now + Duration::from_secs(30)),
            now,
        );
        let batch = state.batch(now);
        assert!(state.commit_success(&batch.sets, &batch.removes));
        state.observe(clear_v4("a.test"), now);
        let batch = state.batch(now);
        assert!(state.commit_success(&batch.sets, &batch.removes));
    }
    let stats = region.change();
    let retained = stats
        .bytes_allocated
        .saturating_sub(stats.bytes_deallocated);
    assert!(
        retained <= 32_768,
        "retired IPs retained {retained} bytes after 10,000 replacements"
    );
}

#[tokio::test(start_paused = true)]
async fn million_hot_owner_refreshes_keep_heaps_bounded() {
    let now = tokio::time::Instant::now();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(
        positive("a.test", &[ip], now + Duration::from_secs(2_000_000)),
        now,
    );

    for update in 1..1_000_000_u64 {
        state.observe(
            positive(
                "a.test",
                &[ip],
                now + Duration::from_secs(2_000_000 - update),
            ),
            now,
        );
    }

    assert_eq!(state.owner_domains().len(), 1);
    assert!(state.expiry_deadlines.len() <= 65);
    assert!(state.eviction_order.len() <= 65);
}

#[tokio::test(start_paused = true)]
async fn refresh_and_ip_replacement_preserve_ttl() {
    let now = tokio::time::Instant::now();
    let old_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 56));
    let new_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 57));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(
        positive("a.test", &[old_ip], now + Duration::from_secs(10)),
        now,
    );
    let initial = state.batch(now);
    assert!(state.commit_success(&initial.sets, &initial.removes));

    state.observe(
        positive("a.test", &[old_ip], now + Duration::from_secs(20)),
        now,
    );
    assert!(state.batch(now).sets.is_empty());
    state.expire(now + Duration::from_secs(11));
    assert_eq!(state.owner_domains(), vec!["a.test".to_owned()]);
    assert_eq!(state.next_deadline(), Some(now + Duration::from_secs(20)));

    state.observe(
        positive("a.test", &[new_ip], now + Duration::from_secs(30)),
        now,
    );
    let replacement = state.batch(now);
    assert_eq!(
        replacement
            .sets
            .iter()
            .map(|set| set.ip)
            .collect::<Vec<_>>(),
        vec![new_ip]
    );
    assert_eq!(replacement.removes, vec![old_ip]);
    assert!(!state.reverse.contains_key(&old_ip));
    assert!(
        state.reverse[&new_ip]
            .members
            .iter()
            .any(|(domain, _)| &**domain == "a.test")
    );
    assert!(state.commit_success(&replacement.sets, &replacement.removes));
    for (observed_at, ttl) in [(11, 5), (12, 20), (13, 5), (14, 20)] {
        state.observe(
            positive(
                "a.test",
                &[new_ip],
                now + Duration::from_secs(observed_at) + Duration::from_secs(ttl),
            ),
            now + Duration::from_secs(observed_at),
        );
    }
    state.expire(now + Duration::from_secs(19));
    assert_eq!(state.next_deadline(), Some(now + Duration::from_secs(34)));
    state.expire(now + Duration::from_secs(33));
    assert_eq!(state.owner_domains(), vec!["a.test".to_owned()]);
    state.expire(now + Duration::from_secs(34));
    assert!(state.owner_domains().is_empty());
}

fn backend_for_test(snapshot: &RoutingProjectionSnapshot) -> MockEbpfBackend {
    let plan = crate::control::routing_matcher::RoutingPushPlan::compile(
        &snapshot.matcher,
        &std::collections::HashMap::from([("direct".to_owned(), 0)]),
        honk_config::types::DialMode::Domain,
    )
    .unwrap();
    let mut backend = MockEbpfBackend::new();
    backend.publish_routing_plan(&plan, &[]).unwrap();
    backend
}

fn owner_expiry(projection: &RoutingProjection, domain: &str) -> Option<tokio::time::Instant> {
    projection
        .state
        .lock()
        .cache_hit_hint(IpVersion::V4 as usize, domain)
        .map(|(_, _, expires_at)| expires_at)
}

#[tokio::test(start_paused = true)]
async fn cache_hit_refresh_is_coalesced_only_inside_its_bounds() {
    let (projection, _receiver, _ebpf) = projection_for_test(snapshot(1, 1, 2));
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 70));
    let submit = |ttl| {
        assert!(projection.try_submit_cache_hit(
            &snapshot(1, 1, 2),
            "a.test",
            IpVersion::V4,
            &[ip],
            tokio::time::Instant::now() + ttl
        ))
    };
    submit(Duration::from_secs(60));
    let first = owner_expiry(&projection, "a.test").unwrap();

    // A hit inside the window that would shorten expiry by less than the
    // window is coalesced: the owner keeps its applied expiry.
    tokio::time::advance(Duration::from_millis(400)).await;
    submit(Duration::from_millis(59_000));
    assert_eq!(owner_expiry(&projection, "a.test"), Some(first));

    // An extension can never be coalesced: skipping it would expire early.
    submit(Duration::from_secs(120));
    assert!(owner_expiry(&projection, "a.test").unwrap() > first);
    let extended = owner_expiry(&projection, "a.test").unwrap();

    // A shortening beyond the window is applied immediately.
    submit(Duration::from_secs(10));
    assert!(owner_expiry(&projection, "a.test").unwrap() < extended);
    let shortened = owner_expiry(&projection, "a.test").unwrap();

    // Once the window elapses, the next hit takes the locked path again.
    tokio::time::advance(Duration::from_millis(1_100)).await;
    submit(Duration::from_millis(8_400));
    assert!(owner_expiry(&projection, "a.test").unwrap() < shortened);

    submit(Duration::from_millis(500));
    submit(Duration::ZERO);
    assert!(
        owner_expiry(&projection, "a.test").is_none(),
        "an expired cache observation must clear instead of coalescing"
    );
}

#[tokio::test(start_paused = true)]
async fn cache_hit_after_owner_change_is_never_coalesced() {
    let (projection, _receiver, _ebpf) = projection_for_test(snapshot(1, 1, 2));
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 71));
    let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 72));
    let hit = |generation, ips: &[IpAddr]| {
        assert!(projection.try_submit_cache_hit(
            &snapshot(generation, 1, 2),
            "a.test",
            IpVersion::V4,
            ips,
            tokio::time::Instant::now() + Duration::from_secs(60),
        ))
    };
    hit(1, &[ip]);
    projection.submit(snapshot(1, 1, 2), clear_v4("a.test"));
    hit(1, &[ip]);
    assert!(
        owner_expiry(&projection, "a.test").is_some(),
        "cleared owner must be restored"
    );

    hit(1, &[other]);
    let state = projection.state.lock();
    assert!(state.desired.contains_key(&other) && !state.desired.contains_key(&ip));
    drop(state);

    projection.update_snapshot(snapshot(2, 1, 2));
    hit(1, &[other]);
    hit(2, &[other]);
    assert_eq!(projection.state.lock().snapshot.generation(), 2);
}

#[tokio::test(start_paused = true)]
async fn ordinary_ttl_change_invalidates_the_cache_hit_hint() {
    let (projection, _receiver, _ebpf) = projection_for_test(snapshot(1, 1, 2));
    let ip = [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 81))];
    let hit = |ttl| {
        assert!(projection.try_submit_cache_hit(
            &snapshot(1, 1, 2),
            "a.test",
            IpVersion::V4,
            &ip,
            tokio::time::Instant::now() + ttl
        ))
    };
    hit(Duration::from_secs(600));
    // Another cache key's upstream answer shortens the same set in place.
    projection.submit(
        snapshot(1, 1, 2),
        positive(
            "a.test",
            &ip,
            tokio::time::Instant::now() + Duration::from_secs(30),
        ),
    );
    tokio::time::advance(Duration::from_millis(500)).await;
    hit(Duration::from_millis(599_000));
    assert!(
        owner_expiry(&projection, "a.test").unwrap()
            > tokio::time::Instant::now() + Duration::from_secs(598),
        "a hit must not coalesce against an expiry the owner no longer has"
    );
}

#[test]
fn address_set_equality_is_exact_for_large_answers() {
    let set = (0..40)
        .map(|host| IpAddr::V4(Ipv4Addr::new(192, 0, 2, host)))
        .collect::<std::collections::BTreeSet<_>>();
    let mut shuffled = set.iter().rev().copied().collect::<Vec<_>>();
    shuffled.swap(3, 17);
    assert!(super::state::same_address_set(set.iter(), &shuffled));
    let mapped = shuffled
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
            v6 => *v6,
        })
        .collect::<Vec<_>>();
    assert!(super::state::same_address_set(set.iter(), &mapped));
    shuffled[0] = shuffled[1];
    assert!(!super::state::same_address_set(set.iter(), &shuffled));
}

#[tokio::test(start_paused = true)]
async fn worker_map_writes_do_not_exclude_same_generation_submissions() {
    let (projection, _receiver, _ebpf) = projection_for_test(snapshot(1, 1, 2));
    let ip = [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 89))];
    let worker_batch = projection.publication_fence.read();
    assert!(
        projection.try_submit(
            &snapshot(1, 1, 2),
            positive(
                "a.test",
                &ip,
                tokio::time::Instant::now() + Duration::from_secs(30)
            )
        ),
        "a worker batch shares the fence with same-generation submissions"
    );
    drop(worker_batch);
    assert!(owner_expiry(&projection, "a.test").is_some());
}

#[tokio::test(start_paused = true)]
async fn held_publication_defers_submission_without_blocking() {
    let (projection, _receiver, _ebpf) = projection_for_test(snapshot(1, 1, 2));
    let ip = [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 90))];
    let next = snapshot(2, 1, 2);
    let publication = projection.prepare_snapshot_publication();
    let expires_at = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut submission = std::pin::pin!(projection.submit_after_publication(|| {
        projection.try_submit(&next, positive("a.test", &ip, expires_at))
    }));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        submission.as_mut().poll(&mut context).is_pending(),
        "a held publication must park the submission, not the thread"
    );
    assert!(owner_expiry(&projection, "a.test").is_none());

    publication.commit(Arc::clone(&next), None);
    tokio::time::timeout(Duration::from_secs(1), submission)
        .await
        .expect("releasing the publication must wake the deferred submission");
    assert_eq!(projection.state.lock().snapshot.generation(), 2);
    assert!(owner_expiry(&projection, "a.test").is_some());
}

fn projection_for_test(snapshot: Arc<RoutingProjectionSnapshot>) -> TestProjection {
    let (wake, receiver) = tokio::sync::mpsc::channel(1);
    let counters = Arc::new(super::ProjectionCounters::default());
    let backend = backend_for_test(&snapshot);
    let state = DesiredState::new(snapshot, 10_000);
    let structure = Arc::clone(&state.structure);
    (
        RoutingProjection {
            state: parking_lot::Mutex::new(state),
            publication_fence: parking_lot::RwLock::new(()),
            wake: parking_lot::Mutex::new(Some(wake)),
            wake_pending: std::sync::atomic::AtomicBool::new(false),
            counters,
            worker: parking_lot::Mutex::new(None),
            lifecycle: {
                let lifecycle = super::ProjectionLifecycle::running();
                lifecycle.finish();
                lifecycle
            },
            hints: Default::default(),
            structure,
            hints_epoch: std::sync::atomic::AtomicU64::new(0),
            publication_released: tokio::sync::Notify::new(),
        },
        receiver,
        Arc::new(tokio::sync::RwLock::new(Box::new(backend))),
    )
}

mod worker_tests;
