use std::alloc::System;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};
use futures_util::future::join_all;
use honk_config::dns::{
    DnsCond, DnsConfig, DnsDomainMatcher, DnsRequestAction, DnsRequestRouting, DnsRequestRule,
    DnsRouting, DnsStrategy,
};
use honk_core::dns::DnsResolver;
use honk_core::dns::bench_support::{
    CacheKeyBenchmarkInput, ProjectionBenchmark, RuntimeBenchmark, observability_snapshot_checksum,
    record_observability_event, validate_udp_query_profile,
};
use honk_core::dns::cache::DnsCache;
use honk_core::dns::forwarder::build_dns_query;
use honk_core::dns::routing::DnsRouter;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tokio::runtime::Runtime;
use tokio::sync::Barrier;

#[path = "fixtures.rs"]
mod fixtures;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
const CACHE_OPS_PER_TASK: usize = 256;

pub(super) fn bench_typed_key_build(c: &mut Criterion) {
    let query = build_dns_query("www.example.com", 1);
    let input = CacheKeyBenchmarkInput::parse(&query);
    c.bench_function("dns_typed_key/build", |b| {
        b.iter(|| black_box(input.build()));
    });
}

pub(super) fn bench_warmed_forwarder_hits(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime");
    let positive_pool = Arc::new(fixtures::LoopbackPool::immediate());
    let negative_pool = Arc::new(fixtures::LoopbackPool::nxdomain());
    let positive = fixtures::forwarder(Arc::clone(&positive_pool), true);
    let negative = fixtures::forwarder(Arc::clone(&negative_pool), true);
    let positive_query = build_dns_query("positive.example", 1);
    let negative_query = build_dns_query("negative.example", 1);
    runtime.block_on(async {
        positive
            .resolve_outcome(&positive_query)
            .await
            .expect("warm positive");
        negative
            .resolve_outcome(&negative_query)
            .await
            .expect("warm negative");
    });

    for (label, forwarder, query) in [
        ("POSITIVE", Arc::clone(&positive), positive_query.as_slice()),
        ("NXDOMAIN", Arc::clone(&negative), negative_query.as_slice()),
    ] {
        let region = Region::new(GLOBAL);
        runtime.block_on(async {
            for _ in 0..1_000 {
                black_box(
                    forwarder
                        .resolve_outcome(black_box(query))
                        .await
                        .expect("warmed hit"),
                );
            }
        });
        let allocation = region.change();
        eprintln!(
            "DNS_WARMED_{label}_ALLOCATIONS={} DNS_WARMED_{label}_BYTES={}",
            allocation.allocations, allocation.bytes_allocated
        );
    }

    let mut group = c.benchmark_group("dns_forwarder_warmed");
    group.throughput(Throughput::Elements(1));
    group.bench_function("positive_hit", |b| {
        b.to_async(&runtime).iter(|| async {
            black_box(
                positive
                    .resolve_outcome(black_box(&positive_query))
                    .await
                    .expect("positive hit"),
            );
        });
    });
    group.bench_function("nxdomain_hit", |b| {
        b.to_async(&runtime).iter(|| async {
            black_box(
                negative
                    .resolve_outcome(black_box(&negative_query))
                    .await
                    .expect("negative hit"),
            );
        });
    });
    group.finish();
    assert_eq!(
        positive_pool.calls(),
        1,
        "positive workload must stay cached"
    );
    assert_eq!(
        negative_pool.calls(),
        1,
        "NXDOMAIN workload must stay cached"
    );
}

pub(super) fn bench_dns_udp_validation_profile(c: &mut Criterion) {
    let query = build_dns_query("www.example.com", 1);
    c.bench_function("dns_udp_validation_profile", |b| {
        b.iter(|| black_box(validate_udp_query_profile(black_box(&query))));
    });
}

pub(super) fn bench_projection_replacement(c: &mut Criterion) {
    let mut replacement = ProjectionBenchmark::new();
    c.bench_function("dns_projection/hot_replacement", |b| {
        b.iter(|| black_box(replacement.replace()));
    });
    // 5,000 names refresh in place; 12,000 names churn past the 10,000-owner cap.
    for names in [5_000_usize, 12_000] {
        let mut shared = ProjectionBenchmark::shared_ip(names);
        c.bench_function(&format!("dns_projection/shared_ip/{names}"), |b| {
            b.iter(|| black_box(shared.replace()));
        });
    }
}

pub(super) fn bench_policy_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_policy_evaluation");
    for count in [1_usize, 32, 128] {
        let router = router_with_rules(count);
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| black_box(router.select_request("benchmark.example", 1)));
        });
    }
    group.finish();
}

pub(super) fn bench_cache_concurrency(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime");
    let response = build_dns_query("hot.example", 1);
    let mut group = c.benchmark_group("dns_cache_concurrency");
    for tasks in [1_usize, 16, 64] {
        for scenario in ["same_key", "same_shard", "different_shards", "read_write"] {
            let cache = Arc::new(DnsCache::new(4_096));
            let keys = benchmark_keys(&cache, tasks, scenario);
            for key in &keys {
                cache.benchmark_put(key.clone(), response.clone(), 300);
            }
            group.throughput(Throughput::Elements((tasks * CACHE_OPS_PER_TASK) as u64));
            group.bench_with_input(
                BenchmarkId::new(scenario, tasks),
                &(Arc::clone(&cache), keys, response.clone()),
                |b, (cache, keys, response)| {
                    b.to_async(&runtime).iter(|| {
                        let barrier = Arc::new(Barrier::new(tasks));
                        let operations = (0..tasks).map(move |index| {
                            let cache = Arc::clone(cache);
                            let barrier = Arc::clone(&barrier);
                            let key = keys[index].clone();
                            let response = response.clone();
                            tokio::spawn(async move {
                                barrier.wait().await;
                                let mut hits = 0usize;
                                for _ in 0..CACHE_OPS_PER_TASK {
                                    if scenario == "read_write" && index % 2 == 1 {
                                        cache.benchmark_put(key.clone(), response.clone(), 300);
                                    } else {
                                        hits += usize::from(cache.benchmark_get(&key).is_some());
                                    }
                                }
                                hits
                            })
                        });
                        async move { black_box(join_all(operations).await) }
                    });
                },
            );
        }
    }
    group.finish();
}

fn benchmark_keys(cache: &DnsCache, tasks: usize, scenario: &str) -> Vec<String> {
    let mut by_shard: [Vec<String>; 16] = std::array::from_fn(|_| Vec::new());
    for index in 0..20_000 {
        let key = format!("{scenario}-{index}");
        let shard = cache.benchmark_shard_index(&key);
        if by_shard[shard].len() < tasks {
            by_shard[shard].push(key);
        }
        if by_shard.iter().all(|keys| keys.len() >= tasks) {
            break;
        }
    }
    match scenario {
        "same_key" => vec![by_shard[0][0].clone(); tasks],
        "same_shard" => by_shard[0][..tasks].to_vec(),
        "different_shards" => (0..tasks)
            .map(|index| by_shard[index % by_shard.len()][index / by_shard.len()].clone())
            .collect(),
        "read_write" => by_shard[0][..tasks].to_vec(),
        _ => unreachable!("known cache benchmark scenario"),
    }
}

pub(super) fn bench_singleflight(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime");
    let pool = Arc::new(fixtures::LoopbackPool::immediate());
    let forwarder = fixtures::forwarder(Arc::clone(&pool), true);
    let query = build_dns_query("singleflight.example", 1);
    let mut group = c.benchmark_group("dns_singleflight");
    group.sample_size(10);
    group.throughput(Throughput::Elements(128));
    group.bench_function("128_waiters", |b| {
        b.to_async(&runtime).iter(|| async {
            forwarder.cache().lock().await.clear();
            pool.reset_calls();
            let operations = (0..128).map(|_| forwarder.resolve(&query));
            black_box(join_all(operations).await);
            black_box(pool.calls());
        });
    });
    group.finish();
}

pub(super) fn bench_parallel_families(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime");
    let pool = Arc::new(fixtures::LoopbackPool::delayed());
    let forwarder = fixtures::forwarder(pool, false);
    let mut config = DnsConfig {
        strategy: DnsStrategy::Both,
        ..Default::default()
    };
    config.cache.enabled = false;
    let resolver =
        DnsResolver::with_forwarder(&config, Arc::clone(&forwarder)).expect("benchmark resolver");
    let slower_query = build_dns_query("parallel.example", 28);
    let mut group = c.benchmark_group("dns_parallel_families");
    group.sample_size(20);
    group.bench_function("slower_aaaa_branch", |b| {
        b.to_async(&runtime).iter(|| async {
            black_box(
                forwarder
                    .resolve(black_box(&slower_query))
                    .await
                    .expect("AAAA resolution"),
            );
        });
    });
    group.bench_function("a_and_aaaa", |b| {
        b.to_async(&runtime).iter(|| async {
            black_box(
                resolver
                    .resolve(black_box("parallel.example"))
                    .await
                    .expect("parallel resolution"),
            );
        });
    });
    group.finish();
}

pub(super) fn bench_runtime_access(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime");
    let mut fixture = RuntimeBenchmark::new();
    let mut group = c.benchmark_group("dns_runtime_access");
    group.bench_function("lease_acquire", |b| {
        b.iter(|| black_box(fixture.acquire_generation()));
    });
    group.sample_size(10);
    group.bench_function("publish_swap", |b| {
        b.iter(|| {
            runtime.block_on(async {
                fixture.publish_next();
                black_box(fixture.acquire_generation());
            });
        });
    });
    group.finish();
    runtime.block_on(fixture.shutdown());
}

pub(super) fn bench_observability(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_observability");
    group.bench_function("record_event", |b| {
        b.iter(|| {
            record_observability_event();
        });
    });
    group.bench_function("best_effort_snapshot", |b| {
        b.iter(|| black_box(observability_snapshot_checksum()));
    });
    group.finish();
}

pub(super) fn bench_allocation_harness(c: &mut Criterion) {
    let response = build_dns_query("allocation.example", 1);
    let region = Region::new(GLOBAL);
    let measured_cache = populated_cache(&response);
    let allocated = region.change().bytes_allocated;
    eprintln!("DNS_ALLOC_10K_BYTES={allocated}");
    black_box(measured_cache);

    let mut group = c.benchmark_group("dns_allocation_harness");
    group.sample_size(10);
    group.throughput(Throughput::Elements(10_000));
    group.bench_function("cache_10k_entries", |b| {
        b.iter_batched(
            || Region::new(GLOBAL),
            |region| {
                let cache = populated_cache(&response);
                let allocated = region.change().bytes_allocated;
                black_box((cache, allocated));
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn populated_cache(response: &[u8]) -> DnsCache {
    let mut cache = DnsCache::new(10_000);
    for index in 0..10_000 {
        cache.put(format!("entry-{index}"), response.to_vec(), 300);
    }
    cache
}

fn router_with_rules(count: usize) -> DnsRouter {
    let rules = (0..count)
        .map(|index| DnsRequestRule {
            conditions: vec![DnsCond::Qname {
                not: false,
                matchers: vec![DnsDomainMatcher::Full(if index + 1 == count {
                    "benchmark.example".to_owned()
                } else {
                    format!("never-{index}.example")
                })],
            }],
            action: DnsRequestAction::Upstream("default".to_owned()),
        })
        .collect();
    DnsRouter::new(&DnsRouting {
        request: DnsRequestRouting {
            rules,
            fallback: DnsRequestAction::Reject,
        },
        ..Default::default()
    })
    .expect("benchmark router")
}
