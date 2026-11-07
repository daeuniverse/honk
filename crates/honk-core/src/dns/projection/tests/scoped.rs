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

fn fact_snapshot(generation: u64) -> Arc<RoutingProjectionSnapshot> {
    let config = honk_config::parser::parse_dae_config(
        "routing { domain(suffix: test) -> block\n fallback: direct }",
    )
    .unwrap();
    Arc::new(RoutingProjectionSnapshot::new(
        generation,
        Arc::new(Router::from_config(&config.routing).unwrap()),
    ))
}

fn registered_projection(
    current: &Arc<RoutingProjectionSnapshot>,
    scopes: &[ScopeId],
) -> TestProjection {
    let result = projection_for_test(Arc::clone(current));
    result
        .0
        .register_packet_scopes(
            scopes.iter().copied(),
            &honk_netstack::MemoryBudget::new(4096),
        )
        .unwrap();
    result
}

fn stamp(
    projection: &RoutingProjection,
    current: &RoutingProjectionSnapshot,
    scope: ScopeId,
    ip: IpAddr,
) -> super::super::FactStamp {
    projection
        .packet_facts()
        .lookup(scope, ip, &current.matcher, current.generation())
        .unwrap()
        .1
}

#[tokio::test(start_paused = true)]
async fn packet_cache_hit_shortening_is_applied_exactly() {
    let current = fact_snapshot(1);
    let (projection, _receiver, _backend) = projection_for_test(Arc::clone(&current));
    let scope = ScopeId::allocate().unwrap();
    let ips = ["192.0.2.1".parse().unwrap()];
    let now = tokio::time::Instant::now();
    for ttl in [Duration::from_secs(2), Duration::from_millis(1500)] {
        assert!(projection.try_submit_cache_hit(
            scope,
            &current,
            "a.test",
            IpVersion::V4,
            &ips,
            now + ttl
        ));
    }
    tokio::time::advance(Duration::from_millis(1600)).await;
    assert!(
        projection
            .packet_bitmap(scope, ips[0], &current.matcher, 1)
            .unwrap()
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn packet_fact_revision_follows_owner_withdrawal_not_bitmap_equality() {
    for mutation in ["clear", "aba", "insert", "replace", "expire"] {
        let current = fact_snapshot(1);
        let scope = ScopeId::allocate().unwrap();
        let (projection, _receiver, _backend) = registered_projection(&current, &[scope]);
        let x = "192.0.2.1".parse().unwrap();
        let y = "192.0.2.2".parse().unwrap();
        let now = tokio::time::Instant::now();
        projection.submit(
            scope,
            Arc::clone(&current),
            positive("a.test", &[x], now + Duration::from_secs(2)),
        );
        projection.submit(
            scope,
            Arc::clone(&current),
            positive("b.test", &[x], now + Duration::from_secs(30)),
        );
        let expected = projection
            .packet_bitmap(scope, x, &current.matcher, 1)
            .unwrap();
        let old = stamp(
            &projection,
            &current,
            scope,
            if mutation == "insert" { y } else { x },
        );
        match mutation {
            "clear" => projection.submit(scope, Arc::clone(&current), clear_v4("a.test")),
            "aba" => {
                projection.submit(scope, Arc::clone(&current), clear_v4("a.test"));
                projection.submit(
                    scope,
                    Arc::clone(&current),
                    positive("a.test", &[x], now + Duration::from_secs(2)),
                );
            }
            "insert" => projection.submit(
                scope,
                Arc::clone(&current),
                positive("c.test", &[y], now + Duration::from_secs(30)),
            ),
            "replace" => projection.submit(
                scope,
                Arc::clone(&current),
                positive("a.test", &[y], now + Duration::from_secs(2)),
            ),
            "expire" => tokio::time::advance(Duration::from_secs(3)).await,
            _ => unreachable!(),
        }
        assert!(!projection.packet_facts().is_current(old), "{mutation}");
        assert_eq!(
            projection
                .packet_bitmap(scope, x, &current.matcher, 1)
                .unwrap(),
            expected,
            "{mutation}"
        );
        let fresh = stamp(&projection, &current, scope, x);
        assert!(projection.packet_facts().is_current(fresh), "{mutation}");
    }
}

#[tokio::test(start_paused = true)]
async fn packet_fact_stamp_keeps_original_expiry() {
    for mutation in ["shorten", "extend", "equal"] {
        let current = fact_snapshot(1);
        let scope = ScopeId::allocate().unwrap();
        let (projection, _receiver, _backend) = registered_projection(&current, &[scope]);
        let ip = "192.0.2.1".parse().unwrap();
        let now = tokio::time::Instant::now();
        let initial = if mutation == "extend" { 2 } else { 30 };
        projection.submit(
            scope,
            Arc::clone(&current),
            positive("a.test", &[ip], now + Duration::from_secs(initial)),
        );
        projection.submit(
            scope,
            Arc::clone(&current),
            positive("b.test", &[ip], now + Duration::from_secs(30)),
        );
        let expected = projection
            .packet_bitmap(scope, ip, &current.matcher, 1)
            .unwrap();
        let old = stamp(&projection, &current, scope, ip);
        let refreshed = if mutation == "shorten" { 20 } else { 30 };
        projection.submit(
            scope,
            Arc::clone(&current),
            positive("a.test", &[ip], now + Duration::from_secs(refreshed)),
        );
        assert_eq!(
            projection.packet_facts().is_current(old),
            mutation != "shorten",
            "{mutation}"
        );
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(
            projection.packet_facts().is_current(old),
            mutation == "equal",
            "{mutation}"
        );
        assert_eq!(
            projection
                .packet_bitmap(scope, ip, &current.matcher, 1)
                .unwrap(),
            expected
        );
    }
}

#[tokio::test(start_paused = true)]
async fn packet_fact_revocation_follows_its_scope_only() {
    use super::super::state::IP_CAPACITY;
    let scopes = std::array::from_fn::<_, 3, _>(|_| ScopeId::allocate().unwrap());
    let [a, b, c] = scopes;
    let current = fact_snapshot(1);
    let now = tokio::time::Instant::now();
    let x = "192.0.2.1".parse().unwrap();
    let y = "192.0.2.2".parse().unwrap();
    let until = now + Duration::from_secs(30);
    let (projection, _receiver, _backend) = registered_projection(&current, &scopes);
    projection.submit(a, Arc::clone(&current), positive("a.test", &[x], until));
    let c_stamp = stamp(&projection, &current, c, x);
    let a_stamp = stamp(&projection, &current, a, x);
    projection.submit(b, Arc::clone(&current), positive("b.test", &[x], until));
    assert!(projection.packet_facts().is_current(a_stamp));
    for observation in [
        positive("a.test", std::slice::from_ref(&y), until),
        clear_v4("a.test"),
    ] {
        let old = stamp(&projection, &current, a, x);
        projection.submit(a, Arc::clone(&current), observation);
        assert!(!projection.packet_facts().is_current(old));
        assert!(projection.packet_facts().is_current(c_stamp));
    }

    let (projection, _receiver, _backend) = registered_projection(&current, &scopes);
    projection.state.lock().capacity = 3;
    projection.submit(a, Arc::clone(&current), positive("a.test", &[x], until));
    projection.submit(a, Arc::clone(&current), positive("b.test", &[x], until));
    projection.submit(c, Arc::clone(&current), positive("c.test", &[x], until));
    let a_stamp = stamp(&projection, &current, a, x);
    let c_stamp = stamp(&projection, &current, c, x);
    let expected = projection.packet_bitmap(a, x, &current.matcher, 1).unwrap();
    projection.submit(b, Arc::clone(&current), positive("d.test", &[x], until));
    assert!(!projection.packet_facts().is_current(a_stamp));
    assert!(projection.packet_facts().is_current(c_stamp));
    assert_eq!(
        projection.packet_bitmap(a, x, &current.matcher, 1).unwrap(),
        expected
    );

    let (projection, _receiver, _backend) = registered_projection(&current, &scopes);
    let highest = IpAddr::V4(Ipv4Addr::from(u32::MAX - 1));
    projection.submit(
        a,
        Arc::clone(&current),
        positive("a.test", &[highest], until),
    );
    let a_stamp = stamp(&projection, &current, a, highest);
    let c_stamp = stamp(&projection, &current, c, x);
    let lower = (1..=IP_CAPACITY as u32)
        .map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
        .collect::<Vec<_>>();
    projection.submit(b, Arc::clone(&current), positive("b.test", &lower, until));
    assert!(
        projection
            .packet_bitmap(a, highest, &current.matcher, 1)
            .unwrap()
            .is_none()
    );
    assert!(!projection.packet_facts().is_current(a_stamp));
    assert!(projection.packet_facts().is_current(c_stamp));
    projection.submit(b, Arc::clone(&current), clear_v4("b.test"));
    let absent = stamp(&projection, &current, a, highest);
    projection.submit(
        a,
        Arc::clone(&current),
        positive("a.test", &[highest], until),
    );
    assert!(!projection.packet_facts().is_current(absent));
    assert!(
        projection
            .packet_bitmap(a, highest, &current.matcher, 1)
            .unwrap()
            .is_some()
    );
    assert!(projection.packet_facts().is_current(c_stamp));
}

#[tokio::test(start_paused = true)]
async fn packet_fact_revision_exhaustion_is_terminal() {
    let scope = ScopeId::allocate().unwrap();
    let current = fact_snapshot(1);
    let (projection, _receiver, _backend) = registered_projection(&current, &[scope]);
    let ip = "192.0.2.1".parse().unwrap();
    projection
        .state
        .lock()
        .set_packet_fact_revision_for_test(scope, u64::MAX - 1);
    let old = stamp(&projection, &current, scope, ip);
    for observation in [
        positive(
            "a.test",
            std::slice::from_ref(&ip),
            tokio::time::Instant::now() + Duration::from_secs(30),
        ),
        clear_v4("a.test"),
    ] {
        projection.submit(scope, Arc::clone(&current), observation);
        assert!(!projection.packet_facts().is_current(old));
        assert!(
            projection
                .packet_facts()
                .lookup(scope, ip, &current.matcher, 1)
                .is_err()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn packet_fact_rebuild_revokes_every_registered_scope() {
    let scopes = [ScopeId::allocate().unwrap(), ScopeId::allocate().unwrap()];
    let current = fact_snapshot(1);
    let (projection, _receiver, _backend) = registered_projection(&current, &scopes);
    let ip = "192.0.2.1".parse().unwrap();
    let stamps = scopes.map(|scope| stamp(&projection, &current, scope, ip));
    let next = fact_snapshot(2);
    projection
        .prepare_snapshot_publication()
        .commit(Arc::clone(&next), None);
    for (scope, old) in scopes.into_iter().zip(stamps) {
        assert!(!projection.packet_facts().is_current(old));
        let fresh = stamp(&projection, &next, scope, ip);
        assert!(projection.packet_facts().is_current(fresh));
    }
}

#[tokio::test]
async fn packet_scope_registration_is_funded_atomic_and_set_once() {
    let current = fact_snapshot(1);
    let scope = ScopeId::allocate().unwrap();
    for invalid in [vec![], vec![ScopeId::HOST], vec![scope, scope]] {
        let (projection, _receiver, _backend) = projection_for_test(Arc::clone(&current));
        let budget = honk_netstack::MemoryBudget::new(4096);
        assert!(
            projection
                .register_packet_scopes(invalid.into_iter(), &budget)
                .is_err()
        );
        assert!(!projection.owns_packet_scope(scope));
        assert_eq!(budget.used(), 0);
    }
    let (projection, _receiver, _backend) = projection_for_test(Arc::clone(&current));
    let budget = honk_netstack::MemoryBudget::new(4096);
    let pressure = budget.reserve(budget.limit()).unwrap();
    assert!(
        projection
            .register_packet_scopes([scope].into_iter(), &budget)
            .is_err()
    );
    assert!(!projection.owns_packet_scope(scope));
    assert_eq!(budget.used(), budget.limit());
    drop(pressure);
    projection
        .register_packet_scopes([scope].into_iter(), &budget)
        .unwrap();
    assert!(projection.owns_packet_scope(scope));
    assert!(budget.used() > 0);
    let registered = budget.used();
    assert!(
        projection
            .register_packet_scopes([scope].into_iter(), &budget)
            .is_err()
    );
    assert_eq!(budget.used(), registered);
    drop(projection);
    assert_eq!(budget.used(), 0);
}
