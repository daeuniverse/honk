mod runtime {
    pub async fn acquire_physical_dial_permit() -> Option<()> {
        None
    }

    pub fn retain_physical_dial_permit(_: Option<()>) {}
}

#[allow(dead_code)]
#[path = "../src/address_race.rs"]
mod address_race;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const SAMPLES: usize = 1_000;
const FAILED_ATTEMPT: Duration = Duration::from_millis(20);
const SUCCESSFUL_ATTEMPT: Duration = Duration::from_micros(200);
const STAGGER: Duration = Duration::from_micros(2_500);
const PRODUCTION_SAMPLES: usize = 100;
const PRODUCTION_SUCCESS: Duration = Duration::from_millis(20);
const PRODUCTION_BASELINE_SAMPLES: usize = 11;
const PRODUCTION_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Default)]
struct Counters {
    active: AtomicUsize,
    peak: AtomicUsize,
    started: AtomicUsize,
    canceled: AtomicUsize,
}

struct AttemptGuard {
    counters: Arc<Counters>,
    completed: bool,
}

impl AttemptGuard {
    fn new(counters: Arc<Counters>) -> Self {
        counters.started.fetch_add(1, Ordering::Relaxed);
        let active = counters.active.fetch_add(1, Ordering::Relaxed) + 1;
        counters.peak.fetch_max(active, Ordering::Relaxed);
        Self {
            counters,
            completed: false,
        }
    }

    fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        self.counters.active.fetch_sub(1, Ordering::Relaxed);
        if !self.completed {
            self.counters.canceled.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn addresses() -> [SocketAddr; 2] {
    [
        (Ipv4Addr::LOCALHOST, 443).into(),
        (Ipv6Addr::LOCALHOST, 443).into(),
    ]
}

async fn sequential(retries: usize) {
    for _ in 0..retries {
        tokio::time::sleep(FAILED_ATTEMPT).await;
    }
    tokio::time::sleep(SUCCESSFUL_ATTEMPT).await;
}

async fn sequential_production(retries: usize) {
    for _ in 0..retries {
        tokio::time::sleep(PRODUCTION_CONNECT_TIMEOUT).await;
    }
    tokio::time::sleep(PRODUCTION_SUCCESS).await;
}

async fn raced(retries: usize, healthy_first: bool, counters: Arc<Counters>) {
    address_race::race_resolved_addrs_with_stagger(&addresses(), STAGGER, move |addr| {
        let guard = AttemptGuard::new(Arc::clone(&counters));
        async move {
            if addr.is_ipv4() && !healthy_first {
                for _ in 0..retries {
                    tokio::time::sleep(FAILED_ATTEMPT).await;
                }
                guard.complete();
                Err::<(), ()>(())
            } else {
                tokio::time::sleep(SUCCESSFUL_ATTEMPT).await;
                guard.complete();
                Ok(())
            }
        }
    })
    .await
    .expect("benchmark addresses are non-empty")
    .expect("fallback must succeed");
}

async fn raced_production(healthy_first: bool, counters: Arc<Counters>) {
    address_race::race_resolved_addrs_with_stagger(
        &addresses(),
        address_race::ADDRESS_RACE_DELAY,
        move |addr| {
            let guard = AttemptGuard::new(Arc::clone(&counters));
            async move {
                if addr.is_ipv4() && !healthy_first {
                    let _guard = guard;
                    std::future::pending::<Result<(), ()>>().await
                } else {
                    tokio::time::sleep(PRODUCTION_SUCCESS).await;
                    guard.complete();
                    Ok(())
                }
            }
        },
    )
    .await
    .expect("benchmark addresses are non-empty")
    .expect("fallback must succeed");
}

async fn measure_sequential(label: &str, retries: usize) {
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        sequential(retries).await;
        samples.push(started.elapsed());
    }
    print_samples(label, samples);
}

async fn measure_production_baseline(label: &str, retries: usize) {
    let mut samples = Vec::with_capacity(PRODUCTION_BASELINE_SAMPLES);
    for _ in 0..PRODUCTION_BASELINE_SAMPLES {
        let started = Instant::now();
        sequential_production(retries).await;
        samples.push(started.elapsed());
    }
    print_samples(label, samples);
}

async fn measure_raced(label: &str, retries: usize, healthy_first: bool) {
    let counters = Arc::new(Counters::default());
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        raced(retries, healthy_first, Arc::clone(&counters)).await;
        samples.push(started.elapsed());
    }
    print_samples(label, samples);
    println!(
        "{label}_started={} {label}_canceled={} {label}_peak={}",
        counters.started.load(Ordering::Relaxed),
        counters.canceled.load(Ordering::Relaxed),
        counters.peak.load(Ordering::Relaxed),
    );
}

async fn measure_production(label: &str, healthy_first: bool) {
    let counters = Arc::new(Counters::default());
    let mut samples = Vec::with_capacity(PRODUCTION_SAMPLES);
    for _ in 0..PRODUCTION_SAMPLES {
        let started = Instant::now();
        raced_production(healthy_first, Arc::clone(&counters)).await;
        samples.push(started.elapsed());
    }
    print_samples(label, samples);
    println!(
        "{label}_started={} {label}_canceled={} {label}_peak={}",
        counters.started.load(Ordering::Relaxed),
        counters.canceled.load(Ordering::Relaxed),
        counters.peak.load(Ordering::Relaxed),
    );
}

fn print_samples(label: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let len = samples.len();
    let p50 = samples[len / 2].as_micros();
    let p95 = samples[len * 95 / 100].as_micros();
    println!("{label}_p50_us={p50} {label}_p95_us={p95}");
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if std::env::args().any(|arg| arg == "production-baseline") {
        measure_production_baseline("tcp_production_sequential", 1).await;
        measure_production_baseline("quic_production_sequential", 3).await;
        return;
    }
    measure_sequential("tcp_sequential", 1).await;
    measure_raced("tcp_raced", 1, false).await;
    measure_sequential("quic_sequential", 3).await;
    measure_raced("quic_raced", 3, false).await;
    measure_sequential("healthy_sequential", 0).await;
    measure_raced("healthy_raced", 1, true).await;
    measure_production("production_fallback", false).await;
    measure_production("production_healthy", true).await;
}
