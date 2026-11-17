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

#[cfg(feature = "ebpf")]
#[tokio::test(start_paused = true)]
async fn native_export_keeps_scoped_revision_and_original_expiry() {
    let current = fact_snapshot(1);
    let scopes = [ScopeId::allocate().unwrap(), ScopeId::allocate().unwrap()];
    let [first, second] = scopes;
    let (projection, _receiver, _backend) = registered_projection(&current, &scopes);
    let now = tokio::time::Instant::now();
    let ip = "192.0.2.1".parse().unwrap();
    for (scope, domain, ttl) in [
        (ScopeId::HOST, "a.test", 1),
        (first, "a.test", 30),
        (first, "b.test", 20),
        (second, "outside.invalid", 40),
    ] {
        projection.submit(
            scope,
            Arc::clone(&current),
            positive(domain, &[ip], now + Duration::from_secs(ttl)),
        );
    }
    let exported = |scope| {
        projection
            .state
            .lock()
            .native_scope_facts(scope)
            .collect::<Vec<_>>()
    };
    let bitmap = current.bitmap_for("a.test").unwrap();
    assert_eq!(
        exported(first),
        [(ip, bitmap, Some(now + Duration::from_secs(20)))]
    );
    assert_eq!(
        exported(second),
        [(
            ip,
            honk_ebpf_common::DomainRouting::default(),
            Some(now + Duration::from_secs(40))
        )]
    );

    let original = stamp(&projection, &current, first, ip);
    assert!(projection.try_submit_cache_hit(
        first,
        &current,
        "b.test",
        IpVersion::V4,
        &[ip],
        now + Duration::from_secs(15),
    ));
    let shortened = stamp(&projection, &current, first, ip);
    assert!(shortened.revision > original.revision);
    assert_eq!(
        exported(first),
        [(ip, bitmap, Some(now + Duration::from_secs(15)))]
    );
    projection.submit(first, Arc::clone(&current), clear_v4("b.test"));
    let cleared = stamp(&projection, &current, first, ip);
    assert!(cleared.revision > shortened.revision);
    assert_eq!(
        exported(first),
        [(ip, bitmap, Some(now + Duration::from_secs(30)))]
    );
    projection.submit(
        first,
        Arc::clone(&current),
        positive("b.test", &[ip], now + Duration::from_secs(15)),
    );
    let reinserted = stamp(&projection, &current, first, ip);
    assert!(reinserted.revision > cleared.revision);
    tokio::time::advance(Duration::from_secs(16)).await;
    let expired = stamp(&projection, &current, first, ip);
    assert!(expired.revision > reinserted.revision);
    assert_eq!(
        exported(first),
        [(ip, bitmap, Some(now + Duration::from_secs(30)))]
    );

    let (projection, _receiver, _backend) = registered_projection(&current, &scopes);
    projection.state.lock().capacity = 1;
    let until = tokio::time::Instant::now() + Duration::from_secs(30);
    projection.submit(
        first,
        Arc::clone(&current),
        positive("a.test", &[ip], until),
    );
    let before_eviction = stamp(&projection, &current, first, ip);
    projection.submit(
        ScopeId::HOST,
        Arc::clone(&current),
        positive("a.test", &[ip], until),
    );
    assert!(stamp(&projection, &current, first, ip).revision > before_eviction.revision);
    assert!(
        projection
            .state
            .lock()
            .native_scope_facts(first)
            .next()
            .is_none()
    );
}

#[cfg(feature = "ebpf")]
#[tokio::test(start_paused = true)]
async fn native_same_revision_extensions_skip_writers_and_keep_the_installed_wake() {
    let current = snapshot(1, 1, 2);
    let scope = ScopeId::allocate().unwrap();
    let (projection, _receiver, _backend) = registered_projection(&current, &[scope]);
    let native = crate::ebpf::native::NativePublication::closed_for_test(
        honk_netstack::MemoryBudget::new(1 << 20),
    )
    .unwrap();
    projection.install_native(Arc::clone(&native)).unwrap();
    let start = tokio::time::Instant::now();
    let ips = ["192.0.2.1".parse().unwrap()];
    projection.submit(
        scope,
        Arc::clone(&current),
        positive("a.test", &ips, start + Duration::from_secs(30)),
    );
    let original = stamp(&projection, &current, scope, ips[0]);
    let writes = native.write_attempts_for_test();
    // Exercise the real scheduler with an installed horizon; the closed fixture
    // cannot create a kernel program and must reject its eventual write attempt.
    let fixed_wake = start + Duration::from_secs(29);
    {
        let mut state = projection.state.lock();
        state
            .native_refresh
            .published(Some(start + Duration::from_secs(30)), start);
        state.native_refresh.defer();
    }
    for _ in 0..280 {
        tokio::time::advance(Duration::from_millis(100)).await;
        let now = tokio::time::Instant::now();
        let observation = positive("a.test", &ips, now + Duration::from_secs(60));
        assert!(
            projection
                .state
                .lock()
                .native_extension_only(scope, observation, now)
        );
        projection.submit(scope, Arc::clone(&current), observation);
        let mut state = projection.state.lock();
        assert_eq!(state.native_refresh.deadline(), Some(fixed_wake));
        assert_eq!(state.next_deadline(), Some(fixed_wake));
        assert_eq!(
            state.native_scope_facts(scope).collect::<Vec<_>>(),
            [(
                ips[0],
                current.bitmap_for("a.test").unwrap(),
                Some(now + Duration::from_secs(60))
            )]
        );
        drop(state);
        assert_eq!(
            stamp(&projection, &current, scope, ips[0]).revision,
            original.revision
        );
        assert_eq!(native.write_attempts_for_test(), writes);
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    projection
        .state
        .lock()
        .try_expire(tokio::time::Instant::now())
        .unwrap();
    assert_eq!(native.write_attempts_for_test(), writes + 1);
    assert_eq!(projection.state.lock().native_refresh.deadline(), None);
    // The old owner-heap wake only retimes the extended owner; it must not fence again.
    tokio::time::advance(Duration::from_secs(1)).await;
    projection
        .state
        .lock()
        .try_expire(tokio::time::Instant::now())
        .unwrap();
    assert_eq!(native.write_attempts_for_test(), writes + 1);
    let now = tokio::time::Instant::now();
    let shortened = positive("a.test", &ips, now + Duration::from_secs(1));
    assert!(
        !projection
            .state
            .lock()
            .native_extension_only(scope, shortened, now)
    );
    projection.submit(scope, Arc::clone(&current), shortened);
    assert_eq!(native.write_attempts_for_test(), writes + 2);
    assert!(stamp(&projection, &current, scope, ips[0]).revision > original.revision);
    let replacement = ["192.0.2.2".parse().unwrap()];
    let changed = positive("a.test", &replacement, now + Duration::from_secs(2));
    assert!(
        !projection
            .state
            .lock()
            .native_extension_only(scope, changed, now)
    );
    projection.submit(scope, Arc::clone(&current), changed);
    assert_eq!(native.write_attempts_for_test(), writes + 3);
    projection.submit(scope, Arc::clone(&current), clear_v4("a.test"));
    assert_eq!(native.write_attempts_for_test(), writes + 4);
    assert!(native.terminal());
}

#[cfg(feature = "ebpf")]
#[test]
fn native_renewal_rate_is_bounded_by_the_fixed_installed_window() {
    use super::super::state::NativeRefresh;
    let start = tokio::time::Instant::now();
    let mut window = NativeRefresh::default();
    let mut published = start;
    for _ in 0..10 {
        window.published(Some(published + Duration::from_secs(2)), published);
        let next = published + Duration::from_secs(1);
        for _ in 0..1000 {
            window.defer();
            assert_eq!(window.deadline(), Some(next));
        }
        published = next;
    }
    assert_eq!(published - start, Duration::from_secs(10));
    for millis in [1000, 500, 100] {
        window.published(Some(start + Duration::from_millis(millis)), start);
        window.defer();
        assert_eq!(
            window.deadline(),
            Some(start + Duration::from_millis(millis / 2))
        );
    }
}

#[cfg(feature = "ebpf")]
#[tokio::test(start_paused = true)]
async fn permanently_closed_native_publication_preserves_all_canonical_dns_mutations() {
    let current = snapshot(1, 1, 2);
    let scope = ScopeId::allocate().unwrap();
    let (baseline, _baseline_receiver, _baseline_backend) =
        registered_projection(&current, &[scope]);
    let (closed, _closed_receiver, _closed_backend) = registered_projection(&current, &[scope]);
    baseline.state.lock().capacity = 1;
    closed.state.lock().capacity = 1;
    let native = crate::ebpf::native::NativePublication::closed_for_test(
        honk_netstack::MemoryBudget::new(1 << 20),
    )
    .unwrap();
    assert!(
        native
            .write(crate::ebpf::native::NativeReason::ScopedDns)
            .is_err()
    );
    closed
        .state
        .lock()
        .install_closed_native_for_test(Arc::clone(&native));
    let compare = || {
        let expected = baseline.state.lock();
        let actual = closed.state.lock();
        assert_eq!(actual.snapshot.generation(), expected.snapshot.generation());
        assert_eq!(actual.owner_domains(), expected.owner_domains());
        assert_eq!(
            actual.native_scope_facts(scope).collect::<Vec<_>>(),
            expected.native_scope_facts(scope).collect::<Vec<_>>()
        );
        assert_eq!(actual.desired, expected.desired);
        assert_eq!(actual.dirty_ips, expected.dirty_ips);
    };
    let now = tokio::time::Instant::now();
    for (domain, ip, ttl, expected_evictions) in [
        ("a.test", "192.0.2.1", 30, 0),
        ("b.test", "192.0.2.2", 20, 1),
    ] {
        let ips = [ip.parse().unwrap()];
        let observation = positive(domain, &ips, now + Duration::from_secs(ttl));
        let expected = baseline.state.lock().observe(scope, observation, now);
        let actual = closed.state.lock().observe(scope, observation, now);
        assert_eq!(expected, expected_evictions);
        assert_eq!(actual, expected);
        compare();
    }
    let newer = snapshot(2, 4, 8);
    assert!(baseline.state.lock().update_snapshot(&newer));
    assert!(closed.state.lock().update_snapshot(&newer));
    compare();
    assert_eq!(
        closed
            .state
            .lock()
            .native_scope_facts(scope)
            .next()
            .unwrap()
            .1
            .bitmap[0],
        8
    );
    let expired = now + Duration::from_secs(21);
    assert!(baseline.state.lock().try_expire(expired).is_ok());
    assert!(closed.state.lock().try_expire(expired).is_ok());
    compare();
    assert!(
        closed
            .state
            .lock()
            .native_scope_facts(scope)
            .next()
            .is_none()
    );
    assert!(native.terminal());
    assert!(
        native
            .write(crate::ebpf::native::NativeReason::ScopedDns)
            .is_err()
    );
}

#[cfg(feature = "ebpf")]
#[tokio::test]
async fn native_export_uses_dns_writer_while_maintenance_is_live() {
    use crate::ebpf::native::{NativePublication, NativeReason};
    use honk_ebpf_common::xdp::NATIVE_EVENT_WRITER_BEGIN;

    let current = snapshot(1, 1, 2);
    let scope = ScopeId::allocate().unwrap();
    let (projection, _receiver, _backend) = registered_projection(&current, &[scope]);
    let native =
        NativePublication::recording_for_test(honk_netstack::MemoryBudget::new(2 << 20)).unwrap();
    let maintenance = native.write(NativeReason::RuntimeMaintenance).unwrap();
    let maintenance_id = maintenance.writer_id_for_test();
    projection.install_native(Arc::clone(&native)).unwrap();
    let events = native.recording_events_for_test();
    assert!(events.len() < 32);
    assert_eq!(events.first().unwrap().seq, 1);
    let dns = events
        .iter()
        .filter(|event| {
            event.kind == NATIVE_EVENT_WRITER_BEGIN
                && event.reason == NativeReason::ScopedDns as u32
        })
        .collect::<Vec<_>>();
    assert_eq!(dns.len(), 2);
    assert_eq!(dns[0].writer_id, dns[1].writer_id);
    assert_ne!(dns[0].writer_id, maintenance_id);
    maintenance.commit();
}
