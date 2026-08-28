use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use honk_config::Config;
use honk_config::dns::{DnsLegacyRule, DnsRouting};
use honk_config::node::{Group, GroupPolicy, Node};
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_core::control::ControlPlane;
use honk_core::dns::DnsResolver;
use honk_core::dns::cache::DnsCache;
use honk_core::dns::forwarder::DnsForwarder;
use honk_core::dns::routing::DnsRouter;
use honk_core::dns::upstream_pool::UpstreamPool;
use honk_core::ebpf::mock::MockEbpfBackend;
use honk_core::proxy::ProxyRegistry;
use honk_core::routing::Router;
use tempfile::TempDir;
use tokio::runtime::Runtime;

#[cfg(feature = "reload-alloc-bench")]
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
#[cfg(feature = "reload-alloc-bench")]
use std::alloc::System;
#[cfg(feature = "reload-bench-counters")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "reload-alloc-bench")]
#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[cfg(all(feature = "mimalloc", not(feature = "reload-alloc-bench")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Clone, Copy)]
struct Observation {
    flag_writes: u64,
    #[cfg(feature = "reload-bench-counters")]
    dns_generation: u64,
    #[cfg(feature = "reload-bench-counters")]
    slow_path_entries: u64,
    #[cfg(feature = "reload-bench-counters")]
    routing_writes: u64,
    #[cfg(feature = "reload-bench-counters")]
    connectivity_writes: u64,
}

impl Observation {
    fn since(self, earlier: Self) -> Self {
        Self {
            flag_writes: self.flag_writes.saturating_sub(earlier.flag_writes),
            #[cfg(feature = "reload-bench-counters")]
            dns_generation: self.dns_generation.saturating_sub(earlier.dns_generation),
            #[cfg(feature = "reload-bench-counters")]
            slow_path_entries: self
                .slow_path_entries
                .saturating_sub(earlier.slow_path_entries),
            #[cfg(feature = "reload-bench-counters")]
            routing_writes: self.routing_writes.saturating_sub(earlier.routing_writes),
            #[cfg(feature = "reload-bench-counters")]
            connectivity_writes: self
                .connectivity_writes
                .saturating_sub(earlier.connectivity_writes),
        }
    }

    #[cfg(feature = "reload-bench-counters")]
    fn ebpf_writes(self) -> u64 {
        self.flag_writes + self.routing_writes + self.connectivity_writes
    }
}

struct Fixture {
    _directory: TempDir,
    runtime: Runtime,
    control_plane: ControlPlane,
    config: Config,
    flag_writes: Arc<std::sync::Mutex<Vec<u32>>>,
    #[cfg(feature = "reload-bench-counters")]
    routing_writes: Arc<AtomicU64>,
    #[cfg(feature = "reload-bench-counters")]
    connectivity_writes: Arc<AtomicU64>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("benchmark directory");
        let hosts_path = directory.path().join("hosts.rules");
        let mut hosts = String::with_capacity(800_000);
        for index in 0..20_000 {
            use std::fmt::Write as _;
            writeln!(
                hosts,
                "full:host{index:05}.bench.invalid 192.0.2.{}",
                index % 250 + 1
            )
            .unwrap();
        }
        std::fs::write(&hosts_path, hosts).expect("benchmark hosts");

        let mut config = large_config(hosts_path.to_string_lossy().into_owned());
        let initial_rule = config.routing.rules.pop().expect("routing fixture");
        let initial_router = Router::new(&config.routing.rules, &config.routing.default_outbound)
            .expect("initial router");
        let initial_config = config.clone();
        config.routing.rules.push(initial_rule);

        let dns_router =
            Arc::new(DnsRouter::new_from_dns_config(&config.dns).expect("benchmark DNS router"));
        let upstream_pool = Arc::new(
            UpstreamPool::new(&config.dns.upstream, Arc::clone(&dns_router))
                .expect("benchmark upstream pool"),
        );
        let forwarder = Arc::new(
            DnsForwarder::new(
                upstream_pool,
                Arc::new(tokio::sync::Mutex::new(DnsCache::new(1_024))),
                dns_router,
            )
            .with_policy_from_config(&config.dns)
            .expect("benchmark DNS policy"),
        );

        let backend = MockEbpfBackend::new();
        let flag_writes = Arc::clone(&backend.datapath_flags_writes);
        #[cfg(feature = "reload-bench-counters")]
        let routing_writes = backend.routing_map_write_counter();
        #[cfg(feature = "reload-bench-counters")]
        let connectivity_writes = backend.outbound_alive_write_counter();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("benchmark runtime");
        let control_plane = {
            let _runtime = runtime.enter();
            ControlPlane::new(
                initial_config,
                Box::new(backend),
                initial_router,
                Arc::new(ProxyRegistry::default_resolver().expect("proxy registry")),
                DnsResolver::new(&config.dns).expect("DNS resolver"),
                forwarder,
            )
            .expect("control plane")
        };
        assert!(runtime.block_on(control_plane.reload_runtime_config(config.clone())));
        Self {
            _directory: directory,
            runtime,
            control_plane,
            config,
            flag_writes,
            #[cfg(feature = "reload-bench-counters")]
            routing_writes,
            #[cfg(feature = "reload-bench-counters")]
            connectivity_writes,
        }
    }

    fn reload(&self, config: Config) {
        assert!(
            self.runtime
                .block_on(self.control_plane.reload_runtime_config(config))
        );
    }

    fn observation(&self) -> Observation {
        Observation {
            flag_writes: self.flag_writes.lock().unwrap().len() as u64,
            #[cfg(feature = "reload-bench-counters")]
            dns_generation: self.control_plane.reload_benchmark_dns_generation(),
            #[cfg(feature = "reload-bench-counters")]
            slow_path_entries: self.control_plane.reload_slow_path_entries(),
            #[cfg(feature = "reload-bench-counters")]
            routing_writes: self.routing_writes.load(Ordering::Relaxed),
            #[cfg(feature = "reload-bench-counters")]
            connectivity_writes: self.connectivity_writes.load(Ordering::Relaxed),
        }
    }

    fn verify_contract(&self) {
        let before = self.observation();
        self.reload(self.config.clone());
        let identical = self.observation().since(before);
        let expect_noop = std::env::var("HONK_RELOAD_EXPECT_NOOP").as_deref() != Ok("0");
        if expect_noop {
            assert_eq!(identical.flag_writes, 0, "identical reload wrote flags");
            #[cfg(feature = "reload-bench-counters")]
            {
                assert_eq!(
                    identical.dns_generation, 0,
                    "identical reload published DNS"
                );
                assert_eq!(
                    identical.slow_path_entries, 0,
                    "identical reload rebuilt runtime state"
                );
                assert_eq!(
                    identical.ebpf_writes(),
                    0,
                    "identical reload wrote eBPF maps"
                );
            }
        }

        let mut changed = self.config.clone();
        changed.routing.rules[0].priority += 10_000;
        let before = self.observation();
        self.reload(changed);
        let changed = self.observation().since(before);
        assert!(
            changed.flag_writes > 0,
            "changed reload did not write flags"
        );
        #[cfg(feature = "reload-bench-counters")]
        {
            assert!(
                changed.dns_generation > 0,
                "changed reload did not publish DNS"
            );
            assert!(
                changed.slow_path_entries > 0,
                "changed reload skipped runtime rebuild"
            );
            assert!(
                changed.ebpf_writes() > 0,
                "changed reload did not write eBPF maps"
            );
        }

        self.reload(self.config.clone());
        eprintln!(
            "RELOAD_CONTRACT identical_flag_writes={} changed_flag_writes={}{}",
            identical.flag_writes,
            changed.flag_writes,
            contract_counter_suffix(identical, changed),
        );
    }
}

#[cfg(feature = "reload-bench-counters")]
fn contract_counter_suffix(identical: Observation, changed: Observation) -> String {
    format!(
        " identical_dns_publications={} identical_slow_paths={} identical_ebpf_writes={} changed_dns_publications={} changed_slow_paths={} changed_ebpf_writes={}",
        identical.dns_generation,
        identical.slow_path_entries,
        identical.ebpf_writes(),
        changed.dns_generation,
        changed.slow_path_entries,
        changed.ebpf_writes(),
    )
}

#[cfg(not(feature = "reload-bench-counters"))]
fn contract_counter_suffix(_: Observation, _: Observation) -> String {
    String::new()
}

fn large_config(hosts_path: String) -> Config {
    // CI copies this harness into main, so use the wire shape shared by both revisions.
    let node_template: Node =
        serde_json::from_str(r#"{"name":"","protocol":"socks5","address":"","port":0}"#)
            .expect("reload benchmark node template must deserialize");
    let nodes = (0..512)
        .map(|index| Node {
            id: uuid::Uuid::new_v5(
                &honk_config::node::NODE_ID_NAMESPACE,
                format!("reload-bench-{index}").as_bytes(),
            ),
            name: format!("node-{index:03}"),
            address: format!("192.0.2.{}:{}", index % 250 + 1, 10_000 + index),
            ..node_template.clone()
        })
        .collect::<Vec<_>>();
    let groups = nodes
        .as_slice()
        .as_chunks::<16>()
        .0
        .iter()
        .enumerate()
        .map(|(index, members)| Group {
            name: format!("group-{index:02}"),
            policy: GroupPolicy::LoadBalance,
            nodes: members.iter().map(|node| node.id).collect(),
            ..Default::default()
        })
        .collect();
    let routing_rules = (0..48)
        .map(|index| {
            let condition = match index % 5 {
                0 => RoutingCondition {
                    domain_suffix: vec![format!("route-{index}.bench.invalid")],
                    ..Default::default()
                },
                1 => RoutingCondition {
                    ip: vec![format!("10.{}.{}.0/24", index / 16, index % 16)],
                    ..Default::default()
                },
                2 => RoutingCondition {
                    port: vec![format!("{}-{}", 1_000 + index * 2, 1_001 + index * 2)],
                    protocol: vec!["tcp".into()],
                    ..Default::default()
                },
                3 => RoutingCondition {
                    geosite: vec![["google", "youtube", "geolocation-!cn"][index % 3].into()],
                    ..Default::default()
                },
                _ => RoutingCondition {
                    geo_ip: vec![["private", "cn", "us"][index % 3].into()],
                    ..Default::default()
                },
            };
            RoutingRule {
                name: format!("bench-route-{index:02}"),
                condition,
                outbound: RoutingOutbound::Simple("direct".into()),
                priority: index as u32,
                must: false,
                mark: 0,
            }
        })
        .collect();
    let dns_rules = (0..256)
        .map(|index| DnsLegacyRule {
            domain: format!("regex:^dns-{index:03}\\.bench\\.invalid$"),
            upstream: "default".into(),
        })
        .collect();

    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.global.preconnect_node_count = 0;
    config.global.udp_warm_node_count = 0;
    config.nodes = nodes;
    config.groups = groups;
    config.routing.rules = routing_rules;
    config.routing.default_outbound = "direct".into();
    config.dns.hosts = vec![hosts_path];
    config.dns.routing = DnsRouting {
        rules: dns_rules,
        fallback: "default".into(),
        ..Default::default()
    };
    config
}

fn cpu_time_ns() -> u128 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let usage = unsafe { usage.assume_init() };
    let timeval_ns =
        |value: libc::timeval| value.tv_sec as u128 * 1_000_000_000 + value.tv_usec as u128 * 1_000;
    timeval_ns(usage.ru_utime) + timeval_ns(usage.ru_stime)
}

const METRIC_SAMPLES: usize = 10;

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn bench_reload(c: &mut Criterion) {
    let fixture = Fixture::new();
    fixture.verify_contract();

    let mut wall_ns = [0; METRIC_SAMPLES];
    let mut cpu_ns = [0; METRIC_SAMPLES];
    #[cfg(feature = "reload-bench-counters")]
    let mut dns_publications = [0; METRIC_SAMPLES];
    let mut flag_writes = [0; METRIC_SAMPLES];
    #[cfg(feature = "reload-bench-counters")]
    let mut ebpf_writes = [0; METRIC_SAMPLES];
    #[cfg(feature = "reload-bench-counters")]
    let mut slow_path_entries = [0; METRIC_SAMPLES];
    #[cfg(feature = "reload-alloc-bench")]
    let mut allocations = [0; METRIC_SAMPLES];
    #[cfg(feature = "reload-alloc-bench")]
    let mut bytes_allocated = [0; METRIC_SAMPLES];

    for index in 0..METRIC_SAMPLES {
        let config = black_box(fixture.config.clone());
        let before = fixture.observation();
        #[cfg(feature = "reload-alloc-bench")]
        let region = Region::new(GLOBAL);
        let cpu_start = cpu_time_ns();
        let wall_start = Instant::now();
        fixture.reload(config);
        wall_ns[index] = wall_start.elapsed().as_nanos() as u64;
        cpu_ns[index] = (cpu_time_ns() - cpu_start) as u64;
        let writes = fixture.observation().since(before);
        #[cfg(feature = "reload-bench-counters")]
        {
            dns_publications[index] = writes.dns_generation;
            slow_path_entries[index] = writes.slow_path_entries;
        }
        flag_writes[index] = writes.flag_writes;
        #[cfg(feature = "reload-bench-counters")]
        {
            ebpf_writes[index] = writes.ebpf_writes();
        }
        #[cfg(feature = "reload-alloc-bench")]
        {
            let allocation = region.change();
            allocations[index] = allocation.allocations as u64;
            bytes_allocated[index] = allocation.bytes_allocated as u64;
        }
    }

    let mut metrics = format!(
        "samples={METRIC_SAMPLES} wall_ns={} cpu_ns={} flag_writes={}",
        median(&mut wall_ns),
        median(&mut cpu_ns),
        *flag_writes.iter().max().unwrap(),
    );
    #[cfg(feature = "reload-bench-counters")]
    {
        use std::fmt::Write as _;
        write!(
            metrics,
            " dns_publications={} slow_paths={} ebpf_writes={}",
            *dns_publications.iter().max().unwrap(),
            *slow_path_entries.iter().max().unwrap(),
            *ebpf_writes.iter().max().unwrap(),
        )
        .unwrap();
    }
    #[cfg(feature = "reload-alloc-bench")]
    {
        use std::fmt::Write as _;
        write!(
            metrics,
            " allocations={} bytes_allocated={}",
            median(&mut allocations),
            median(&mut bytes_allocated),
        )
        .unwrap();
    }

    eprintln!("RELOAD_METRICS {metrics}");
    if std::env::var_os("HONK_RELOAD_METRICS_ONLY").is_some() {
        return;
    }

    c.bench_function("reload/identical_effective", |bencher| {
        bencher.to_async(&fixture.runtime).iter_batched(
            || black_box(fixture.config.clone()),
            |config| async {
                assert!(fixture.control_plane.reload_runtime_config(config).await);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_reload);
criterion_main!(benches);
