use super::*;
use honk_datapath::ScopeId;

#[tokio::test(start_paused = true)]
async fn scoped_owners_share_eviction_and_never_publish_packet_facts_to_host() {
    let now = tokio::time::Instant::now();
    let ip = "192.0.2.90".parse().unwrap();
    let first = ScopeId::allocate().unwrap();
    let second = ScopeId::allocate().unwrap();
    let current = snapshot(1, 1, 2);
    let mut state = DesiredState::new(Arc::clone(&current), 2);
    state.observe(
        ScopeId::HOST,
        positive("a.test", &[ip], now + Duration::from_secs(30)),
        now,
    );
    let host = state.batch(now);
    state.commit_success(&host.sets, &host.removes);
    state.observe(
        first,
        positive("a.test", &[ip], now + Duration::from_secs(30)),
        now,
    );
    state.observe(
        second,
        positive("b.test", &[ip], now + Duration::from_secs(30)),
        now,
    );

    assert_eq!(state.owner_domains().len(), 2);
    assert_eq!(state.desired.len(), 2);
    assert_eq!(state.bitmap(first, ip).unwrap().bitmap[0], 1);
    assert_eq!(state.bitmap(second, ip).unwrap().bitmap[0], 2);
    assert!(state.bitmap(ScopeId::HOST, ip).is_none());
    assert!(state.project(&current).is_empty());
    let withdrawal = state.batch(now);
    assert!(withdrawal.sets.is_empty());
    assert_eq!(withdrawal.removes, [ip]);
    state.commit_success(&withdrawal.sets, &withdrawal.removes);
    assert!(state.dirty_ips.is_empty());
    assert!(state.retries.is_empty());
}

#[tokio::test(start_paused = true)]
async fn scoped_ip_and_zero_fact_capacities_are_global() {
    use super::super::state::{IP_CAPACITY, ZERO_IP_CAPACITY};

    let now = tokio::time::Instant::now();
    let first = ScopeId::allocate().unwrap();
    let second = ScopeId::allocate().unwrap();
    for (name, limit) in [("a.test", IP_CAPACITY), ("unknown.test", ZERO_IP_CAPACITY)] {
        let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
        let ips = (1..=limit as u32 / 2 + 1)
            .map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
            .collect::<Vec<_>>();
        for scope in [first, second] {
            state.observe(
                scope,
                positive(name, &ips, now + Duration::from_secs(30)),
                now,
            );
        }
        assert_eq!(state.desired.len(), limit);
        assert!(state.bitmap(first, ips[0]).is_some());
        assert!(state.bitmap(second, ips[0]).is_some());
        assert!(state.bitmap(first, *ips.last().unwrap()).is_none());
        assert!(state.bitmap(second, *ips.last().unwrap()).is_none());
        assert!(state.project(&snapshot(1, 1, 2)).is_empty());
        assert!(state.batch(now).sets.is_empty());
        assert!(state.dirty_ips.is_empty());
        assert!(state.retries.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn cache_hit_hints_are_scoped_and_packet_answers_ignore_a_kernel_fence() {
    let current = snapshot(1, 1, 2);
    let (projection, _receiver, _ebpf) = projection_for_test(Arc::clone(&current));
    let first = ScopeId::allocate().unwrap();
    let second = ScopeId::allocate().unwrap();
    let ip = "192.0.2.91".parse().unwrap();
    let expires_at = tokio::time::Instant::now() + Duration::from_secs(30);
    assert!(projection.try_submit_cache_hit(
        ScopeId::HOST,
        &current,
        "a.test",
        IpVersion::V4,
        &[ip],
        expires_at,
    ));
    assert!(
        projection
            .packet_bitmap(first, ip, &current.matcher, 1)
            .unwrap()
            .is_none()
    );
    let publication = projection.prepare_snapshot_publication();
    for scope in [first, second] {
        assert!(projection.try_submit_cache_hit(
            scope,
            &current,
            "a.test",
            IpVersion::V4,
            &[ip],
            expires_at,
        ));
        assert_eq!(
            projection
                .packet_bitmap(scope, ip, &current.matcher, 1)
                .unwrap()
                .unwrap()
                .bitmap[0],
            1
        );
    }
    assert_eq!(projection.state.lock().owner_domains().len(), 3);
    assert!(projection.try_submit(first, &current, clear_v4("a.test")));
    assert!(
        projection
            .packet_bitmap(first, ip, &current.matcher, 1)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        projection
            .packet_bitmap(second, ip, &current.matcher, 1)
            .unwrap()
            .unwrap()
            .bitmap[0],
        1
    );
    drop(publication);
}

#[tokio::test(start_paused = true)]
async fn packet_projection_requires_exact_published_generation_and_rebuilds_predicates() {
    let old = snapshot(1, 1, 2);
    let next = snapshot(2, 2, 1);
    let (projection, _receiver, _ebpf) = projection_for_test(Arc::clone(&old));
    let scope = ScopeId::allocate().unwrap();
    let ip = "192.0.2.92".parse().unwrap();
    let late = "192.0.2.93".parse().unwrap();
    let expires_at = tokio::time::Instant::now() + Duration::from_secs(30);
    projection.submit(
        scope,
        Arc::clone(&old),
        positive("a.test", &[ip], expires_at),
    );
    let publication = projection.prepare_snapshot_publication();
    assert!(!projection.try_submit(scope, &next, positive("b.test", &[late], expires_at)));
    assert_eq!(
        projection
            .packet_bitmap(scope, ip, &old.matcher, 1)
            .unwrap()
            .unwrap()
            .bitmap[0],
        1
    );
    assert!(
        projection
            .packet_bitmap(scope, late, &old.matcher, 1)
            .unwrap()
            .is_none()
    );
    assert!(
        projection
            .packet_bitmap(scope, ip, &next.matcher, 2)
            .is_err()
    );
    publication.commit(Arc::clone(&next), None);
    assert_eq!(
        projection
            .packet_bitmap(scope, ip, &next.matcher, 2)
            .unwrap()
            .unwrap()
            .bitmap[0],
        2
    );
    assert!(
        projection
            .packet_bitmap(scope, ip, &old.matcher, 1)
            .is_err()
    );
    assert!(projection.try_submit(scope, &old, positive("a.test", &[late], expires_at)));
    assert!(
        projection
            .packet_bitmap(scope, late, &next.matcher, 2)
            .unwrap()
            .is_none()
    );
    projection.submit(
        scope,
        Arc::clone(&next),
        positive("unknown.test", &[late], expires_at),
    );
    assert_eq!(
        projection
            .packet_bitmap(scope, late, &next.matcher, 2)
            .unwrap()
            .unwrap()
            .bitmap,
        [0; 8]
    );
    assert!(projection.project(&next).is_empty());
}

#[tokio::test(start_paused = true)]
async fn pending_packet_observation_keeps_its_absolute_expiry() {
    let old = snapshot(1, 1, 2);
    let next = snapshot(2, 2, 1);
    let (projection, _receiver, _ebpf) = projection_for_test(Arc::clone(&old));
    let scope = ScopeId::allocate().unwrap();
    let ip = "192.0.2.95".parse().unwrap();
    let now = tokio::time::Instant::now();
    projection.submit(
        scope,
        Arc::clone(&old),
        positive("a.test", &[ip], now + Duration::from_secs(30)),
    );
    let publication = projection.prepare_snapshot_publication();
    let pending = positive(
        "a.test",
        std::slice::from_ref(&ip),
        now + Duration::from_secs(1),
    );
    assert!(!projection.try_submit(scope, &next, pending));
    tokio::time::advance(Duration::from_secs(2)).await;
    publication.commit(Arc::clone(&next), None);
    assert!(projection.try_submit(scope, &next, pending));
    assert!(
        projection
            .packet_bitmap(scope, ip, &next.matcher, 2)
            .unwrap()
            .is_none()
    );
    assert!(projection.state.lock().owner_domains().is_empty());
    assert!(projection.state.lock().dirty_ips.is_empty());
}

#[tokio::test(start_paused = true)]
async fn scoped_families_share_canonical_ips_without_sharing_withdrawal_or_ttl() {
    let now = tokio::time::Instant::now();
    let scope = ScopeId::allocate().unwrap();
    let other = ScopeId::allocate().unwrap();
    let ip = Ipv4Addr::new(192, 0, 2, 94);
    let mapped = IpAddr::V6(ip.to_ipv6_mapped());
    let v6 = "2001:db8::94".parse().unwrap();
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(
        scope,
        positive("a.test", &[ip.into()], now + Duration::from_secs(2)),
        now,
    );
    state.observe(
        scope,
        positive("a.test", &[mapped], now + Duration::from_secs(5)),
        now,
    );
    state.observe(
        other,
        positive("b.test", &[ip.into()], now + Duration::from_secs(10)),
        now,
    );
    state.observe(
        other,
        positive("b.test", &[v6], now + Duration::from_secs(10)),
        now,
    );
    assert_eq!(state.desired.len(), 3);
    assert_eq!(state.bitmap(scope, mapped).unwrap().bitmap[0], 1);
    assert_eq!(state.bitmap(other, mapped).unwrap().bitmap[0], 2);
    state.observe(
        scope,
        ProjectionObservation::Clear {
            domain: "a.test",
            family: IpVersion::V6,
        },
        now,
    );
    assert_eq!(state.bitmap(scope, ip.into()).unwrap().bitmap[0], 1);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(state.bitmap(scope, mapped).is_none());
    assert_eq!(state.bitmap(other, mapped).unwrap().bitmap[0], 2);
    assert_eq!(state.bitmap(other, v6).unwrap().bitmap[0], 2);
    state.observe(
        other,
        ProjectionObservation::ClearName { domain: "b.test" },
        tokio::time::Instant::now(),
    );
    assert!(state.desired.is_empty());
    assert!(state.owner_domains().is_empty());
    assert!(state.dirty_ips.is_empty());
    assert!(state.retries.is_empty());
}
